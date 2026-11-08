use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use crate::process::{ProcessRequest, resolve_executable, run};

const SHELL_FLAVOR: &str = "com.superlogical.terminal.shell";
const OWNED_WINDOW_PREFIX: &str = "rex-projects-ticket-";
const OWNED_SUPERVISOR_WINDOW_PREFIX: &str = "rex-projects-supervisor-";
const OWNED_BLOCK_PREFIX: &str = "rex-projects-run-";
const QUALIFICATION_WINDOW_NAMESPACE: &str = "rex-projects-provider-qualification";
const QUALIFICATION_SESSION_PREFIX: &str = "rex-projects-provider-qualification-";
const MAX_REX_EVENT_FRAME_BYTES: usize = 64 * 1024;
const REX_EVENT_QUEUE_CAPACITY: usize = 128;

/// A scoped Rex event that only requests a fresh authoritative session inventory.
/// It never proves that a process exited.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RexEventSignal {
    BlockClosed {
        session_id: String,
        block_id: String,
    },
    InventoryChanged {
        session_id: String,
    },
    RescanRequired,
}

/// Foreground-owned `rex events` stream. Dropping it terminates and reaps the CLI child.
pub struct RexEventStream {
    child: Child,
    receiver: Receiver<RexEventSignal>,
    overflowed: Arc<AtomicBool>,
    reader_ended: Arc<AtomicBool>,
    reader: Option<JoinHandle<()>>,
}

impl RexEventStream {
    fn spawn(transport: &RexCliTransport) -> Result<Self, RexError> {
        transport.verify_identity()?;
        let mut child = Command::new(&transport.executable)
            .args([
                "-S",
                transport.endpoint.as_str(),
                "events",
                "-s",
                transport.session_id.as_str(),
                "--json",
            ])
            .envs(transport.environment.iter())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| RexError::Process)?;
        let Some(stdout) = child.stdout.take() else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(RexError::Process);
        };
        let (sender, receiver) = mpsc::sync_channel(REX_EVENT_QUEUE_CAPACITY);
        let overflowed = Arc::new(AtomicBool::new(false));
        let reader_ended = Arc::new(AtomicBool::new(false));
        let reader_overflow = Arc::clone(&overflowed);
        let reader_finished = Arc::clone(&reader_ended);
        let reader = match thread::Builder::new()
            .name("rex-events-reader".into())
            .spawn(move || {
                read_rex_events(stdout, sender, reader_overflow);
                reader_finished.store(true, Ordering::Release);
            }) {
            Ok(reader) => reader,
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(RexError::Process);
            }
        };
        Ok(Self {
            child,
            receiver,
            overflowed,
            reader_ended,
            reader: Some(reader),
        })
    }

    /// Drain a bounded batch. Disconnect and queue overflow both require a full rescan.
    pub fn drain(&self, limit: usize) -> Vec<RexEventSignal> {
        let mut signals = Vec::new();
        if self.overflowed.swap(false, Ordering::AcqRel) {
            signals.push(RexEventSignal::RescanRequired);
        }
        for _ in 0..limit {
            match self.receiver.try_recv() {
                Ok(signal) => signals.push(signal),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    signals.push(RexEventSignal::RescanRequired);
                    break;
                }
            }
        }
        signals
    }

    pub fn is_alive(&mut self) -> Result<bool, RexError> {
        if self.reader_ended.load(Ordering::Acquire) {
            return Ok(false);
        }
        self.child
            .try_wait()
            .map(|status| status.is_none())
            .map_err(|_| RexError::Process)
    }
}

impl Drop for RexEventStream {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

fn read_rex_events(
    stdout: impl std::io::Read,
    sender: SyncSender<RexEventSignal>,
    overflowed: Arc<AtomicBool>,
) {
    let mut reader = BufReader::new(stdout);
    let mut frame = Vec::new();
    let mut oversized = false;
    loop {
        let available = match reader.fill_buf() {
            Ok([]) | Err(_) => break,
            Ok(available) => available,
        };
        let newline = available.iter().position(|byte| *byte == b'\n');
        let consumed = newline.map_or(available.len(), |index| index + 1);
        if !oversized {
            if frame.len().saturating_add(consumed) > MAX_REX_EVENT_FRAME_BYTES {
                frame.clear();
                oversized = true;
            } else {
                frame.extend_from_slice(&available[..consumed]);
            }
        }
        reader.consume(consumed);
        if newline.is_some() {
            let signal = if oversized {
                Some(RexEventSignal::RescanRequired)
            } else {
                match parse_rex_event_frame(&frame) {
                    Ok(signal) => signal,
                    Err(()) => Some(RexEventSignal::RescanRequired),
                }
            };
            if signal.is_some_and(|signal| sender.try_send(signal).is_err()) {
                overflowed.store(true, Ordering::Release);
            }
            frame.clear();
            oversized = false;
        }
    }
    if (!frame.is_empty() || oversized) && sender.try_send(RexEventSignal::RescanRequired).is_err()
    {
        overflowed.store(true, Ordering::Release);
    }
}

fn parse_rex_event_frame(frame: &[u8]) -> Result<Option<RexEventSignal>, ()> {
    let value: Value = crate::protocol::parse_unique(frame).map_err(|_| ())?;
    let event_type = value.get("type").and_then(Value::as_str).ok_or(())?;
    match event_type {
        "session_destroyed" => {
            let session_id = value
                .get("payload")
                .and_then(|payload| payload.get("session_id"))
                .and_then(Value::as_str)
                .ok_or(())?;
            Ok(Some(RexEventSignal::InventoryChanged {
                session_id: session_id.to_owned(),
            }))
        }
        "session_event" => {
            let payload = value.get("payload").ok_or(())?;
            let session_id = payload
                .get("session_id")
                .and_then(Value::as_str)
                .ok_or(())?;
            let event = payload.get("event").ok_or(())?;
            match event.get("type").and_then(Value::as_str).ok_or(())? {
                "block_closed" => Ok(Some(RexEventSignal::BlockClosed {
                    session_id: session_id.to_owned(),
                    block_id: event
                        .get("payload")
                        .and_then(|payload| payload.get("block_id"))
                        .and_then(Value::as_str)
                        .ok_or(())?
                        .to_owned(),
                })),
                "window_closed" | "session_view_changed" => {
                    Ok(Some(RexEventSignal::InventoryChanged {
                        session_id: session_id.to_owned(),
                    }))
                }
                _ => Ok(None),
            }
        }
        _ => Ok(None),
    }
}

pub(crate) fn rex_event_requires_inventory(
    signal: &RexEventSignal,
    expected_session: &str,
) -> bool {
    match signal {
        RexEventSignal::BlockClosed { session_id, .. }
        | RexEventSignal::InventoryChanged { session_id } => session_id == expected_session,
        RexEventSignal::RescanRequired => true,
    }
}

#[derive(Clone, Debug)]
pub struct AgentBlockSpec {
    pub run_id: String,
    pub command: PathBuf,
    pub args: Vec<String>,
    pub cwd: PathBuf,
    pub path_prepend: Vec<PathBuf>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RexWindow {
    pub server_instance_id: String,
    pub session_id: String,
    pub window_id: String,
    pub label: String,
    pub initial_block_id: Option<String>,
    pub disposition: CreateDisposition,
}

pub type TicketWindow = RexWindow;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CreateDisposition {
    Created,
    Existing,
    Reconciled,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedBlock {
    pub block_id: String,
    pub label: String,
    pub flavor: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RexContextBlock {
    pub server_instance_id: String,
    pub session_id: String,
    pub window_id: String,
    pub block_id: String,
    pub label: String,
    pub flavor: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowBlock {
    pub block_id: String,
    pub label: String,
    pub flavor: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct RexProcessInfo {
    pub pid: u32,
    pub user_id: u32,
    pub name: String,
    #[serde(default)]
    pub argv0: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub invoked_path: Option<String>,
    #[serde(default)]
    pub script: Option<String>,
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default)]
    pub user: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct RexLastExit {
    pub exit_code: i32,
    #[serde(default)]
    pub error: Option<String>,
}

/// A block-scoped Rex observation. `last_exit: None` is not enough by itself
/// to declare the run alive: callers must also account for missing child and
/// foreground observations and the durable host process manifest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct RexProcessObservation {
    pub last_exit: Option<RexLastExit>,
    #[serde(default)]
    pub child: Option<RexProcessInfo>,
    #[serde(default)]
    pub foreground: Option<RexProcessInfo>,
    #[serde(default)]
    pub ancestors: Option<Vec<RexProcessInfo>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedWindow {
    pub window_id: String,
    pub label: String,
    pub blocks: Vec<OwnedBlock>,
}

/// Host-created, exact Rex identity for a disposable provider qualification session.
/// The wrapper re-observes this session and its sole window/block before it can
/// construct the opaque `RexQualificationFixture` used by run-step.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RexQualificationSessionReceipt {
    endpoint: String,
    instance_id: String,
    session_id: String,
    window_id: String,
    block_id: String,
    operation_id: String,
    session_label: String,
    window_label: String,
}

impl RexQualificationSessionReceipt {
    pub(crate) fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub(crate) fn instance_id(&self) -> &str {
        &self.instance_id
    }

    pub(crate) fn session_id(&self) -> &str {
        &self.session_id
    }

    pub(crate) fn window_id(&self) -> &str {
        &self.window_id
    }

    pub(crate) fn block_id(&self) -> &str {
        &self.block_id
    }

    pub(crate) fn operation_id(&self) -> &str {
        &self.operation_id
    }
}

/// Unforgeable in-crate proof for one isolated provider qualification turn.
/// Production construction is owned by the disposable Rex qualification flow.
pub(crate) struct RexQualificationFixture {
    endpoint: String,
    instance_id: String,
    session_id: String,
    window_id: String,
    block_id: String,
    operation_id: String,
}

impl RexQualificationFixture {
    pub(crate) fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub(crate) fn instance_id(&self) -> &str {
        &self.instance_id
    }

    pub(crate) fn session_id(&self) -> &str {
        &self.session_id
    }

    pub(crate) fn window_id(&self) -> &str {
        &self.window_id
    }

    pub(crate) fn block_id(&self) -> &str {
        &self.block_id
    }

    pub(crate) fn operation_id(&self) -> &str {
        &self.operation_id
    }
}

#[cfg(test)]
pub(crate) fn test_qualification_fixture() -> RexQualificationFixture {
    RexQualificationFixture {
        endpoint: "unix:///tmp/rex-test.sock".into(),
        instance_id: "rex-test-instance".into(),
        session_id: "session-a".into(),
        window_id: "rex-test-window".into(),
        block_id: "block-a".into(),
        operation_id: "run-a".into(),
    }
}

#[derive(Debug)]
pub enum RexError {
    Invalid(String),
    Process,
    Protocol(String),
    Unsupported(String),
    WrongServer,
    Uncertain,
}

impl std::fmt::Display for RexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(message) => write!(f, "invalid Rex request: {message}"),
            Self::Process => f.write_str("Rex CLI operation failed"),
            Self::Protocol(message) => write!(f, "Rex returned an invalid response: {message}"),
            Self::Unsupported(method) => write!(f, "Rex server does not support {method}"),
            Self::WrongServer => {
                f.write_str("Rex endpoint no longer identifies the configured server")
            }
            Self::Uncertain => {
                f.write_str("Rex operation outcome is uncertain and requires reconciliation")
            }
        }
    }
}

impl std::error::Error for RexError {}

#[derive(Clone, Debug)]
pub struct RexCapabilities {
    pub rex_version: String,
    pub server_instance_id: String,
    pub host_id: String,
    pub methods: BTreeSet<String>,
}

/// Authoritative startup identity returned by Rex, pinned for this controller
/// lifetime. The endpoint is never inferred from environment variable names.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RexIdentity {
    pub endpoint: String,
    pub instance_id: String,
    pub session_id: String,
    pub block_id: Option<String>,
}

impl RexIdentity {
    pub fn discover(
        executable: &Path,
        search_path: &[PathBuf],
        environment: &BTreeMap<OsString, OsString>,
        endpoint_override: Option<&str>,
    ) -> Result<Self, RexError> {
        let session_id = environment
            .get(std::ffi::OsStr::new("REX_SESSION"))
            .and_then(|value| value.to_str())
            .filter(|value| !value.is_empty())
            .ok_or_else(|| RexError::Invalid("REX_SESSION is required inside a Rex block".into()))?
            .to_owned();
        if session_id.chars().any(char::is_control) {
            return Err(RexError::Invalid("REX_SESSION is invalid".into()));
        }
        let block_id = environment
            .get(std::ffi::OsStr::new("REX_BLOCK"))
            .and_then(|value| value.to_str())
            .filter(|value| !value.is_empty())
            .map(str::to_owned);
        if block_id
            .as_deref()
            .is_none_or(|block| block.chars().any(char::is_control))
        {
            return Err(RexError::Invalid(
                "REX_BLOCK is required inside a Rex block".into(),
            ));
        }
        if endpoint_override.is_some_and(|endpoint| {
            !(endpoint.starts_with("unix://")
                || endpoint.starts_with("http://")
                || endpoint.starts_with("https://"))
                || endpoint.chars().any(char::is_control)
        }) {
            return Err(RexError::Invalid("Rex server override is invalid".into()));
        }
        let executable = resolve_executable(executable, search_path)
            .ok_or_else(|| RexError::Invalid("Rex CLI executable is unavailable".into()))?;
        let mut args = Vec::<OsString>::new();
        if let Some(endpoint) = endpoint_override {
            args.extend(["--server".into(), endpoint.into()]);
        }
        args.extend([
            "--autostart=false".into(),
            "--timeout".into(),
            "10s".into(),
            "whoami".into(),
            "--json".into(),
        ]);
        let output = run(ProcessRequest {
            executable,
            args,
            stdin: Vec::new(),
            cwd: None,
            clear_environment: false,
            environment: environment.clone(),
            timeout: Duration::from_secs(12),
            shutdown_grace: Duration::from_secs(2),
            stdout_limit: 64 * 1024,
            stderr_tail_limit: 8 * 1024,
        })
        .map_err(|_| RexError::Process)?;
        if output.timed_out
            || !output.cleanup_confirmed
            || !output.status.is_some_and(|status| status.success())
            || output.stdout_truncated
        {
            return Err(RexError::Process);
        }
        let who: WhoAmI = parse(&output.stdout)?;
        if !(who.endpoint.starts_with("unix://")
            || who.endpoint.starts_with("http://")
            || who.endpoint.starts_with("https://"))
            || who.endpoint.chars().any(char::is_control)
            || who.instance_id.is_empty()
            || who.instance_id.chars().any(char::is_control)
            || endpoint_override.is_some_and(|expected| expected != who.endpoint)
        {
            return Err(RexError::WrongServer);
        }
        Ok(Self {
            endpoint: who.endpoint,
            instance_id: who.instance_id,
            session_id,
            block_id,
        })
    }
}

#[derive(Clone)]
pub struct RexCliTransport {
    executable: PathBuf,
    endpoint: String,
    expected_instance_id: String,
    session_id: String,
    environment: BTreeMap<OsString, OsString>,
    timeout: Duration,
    shutdown_grace: Duration,
    capabilities: RexCapabilities,
}

impl RexCliTransport {
    pub fn connect(
        executable: &Path,
        search_path: &[PathBuf],
        endpoint: String,
        expected_instance_id: String,
        session_id: String,
        environment: BTreeMap<OsString, OsString>,
    ) -> Result<Self, RexError> {
        if !(endpoint.starts_with("unix://")
            || endpoint.starts_with("http://")
            || endpoint.starts_with("https://"))
            || expected_instance_id.is_empty()
            || session_id.is_empty()
        {
            return Err(RexError::Invalid(
                "endpoint, instance, and session must be explicit".into(),
            ));
        }
        let executable = resolve_executable(executable, search_path)
            .ok_or_else(|| RexError::Invalid("Rex CLI executable is unavailable".into()))?;
        let timeout = Duration::from_secs(10);
        let shutdown_grace = Duration::from_secs(2);
        let who = raw_cli(
            &executable,
            &endpoint,
            &environment,
            timeout,
            shutdown_grace,
            &["whoami", "--json"],
        )?;
        let identity: WhoAmI = parse(&who.stdout)?;
        if identity.endpoint != endpoint || identity.instance_id != expected_instance_id {
            return Err(RexError::WrongServer);
        }
        let api = raw_cli(
            &executable,
            &endpoint,
            &environment,
            timeout,
            shutdown_grace,
            &["api", "list", "--json"],
        )?;
        let methods = parse_method_names(&api.stdout)?;
        let capabilities = RexCapabilities {
            rex_version: identity.rex_version,
            server_instance_id: identity.instance_id,
            host_id: identity.host_id,
            methods,
        };
        let transport = Self {
            executable,
            endpoint,
            expected_instance_id,
            session_id,
            environment,
            timeout,
            shutdown_grace,
            capabilities,
        };
        for method in [
            "session.view",
            "session.new_window",
            "session.new_split",
            "session.focus_block",
            "session.zoom_block",
            "block.close",
        ] {
            transport.require_method(method)?;
        }
        Ok(transport)
    }

    pub fn capabilities(&self) -> &RexCapabilities {
        &self.capabilities
    }

    /// Start a foreground Rex event reader scoped to this pinned endpoint and session.
    pub fn subscribe_events(&self) -> Result<RexEventStream, RexError> {
        RexEventStream::spawn(self)
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Confirms the active Rex context block exists exactly once in the explicitly bound
    /// server and session.
    pub fn validate_context_block(&self, block_id: &str) -> Result<RexContextBlock, RexError> {
        if block_id.is_empty() || block_id.len() > 512 || block_id.chars().any(char::is_control) {
            return Err(RexError::Invalid(
                "Rex context block ID is malformed".into(),
            ));
        }
        self.verify_identity()?;
        let view = self.session_view()?;
        let blocks = context_blocks(&view, block_id)?;
        self.verify_identity()?;
        if blocks.len() != 1 {
            return Err(RexError::Uncertain);
        }
        let (window_id, label, flavor) = blocks.into_iter().next().expect("one block checked");
        Ok(RexContextBlock {
            server_instance_id: self.capabilities.server_instance_id.clone(),
            session_id: self.session_id.clone(),
            window_id,
            block_id: block_id.to_owned(),
            label,
            flavor,
        })
    }

    pub fn find_or_create_ticket_window(
        &self,
        ticket_namespace: &str,
        ticket_id: &str,
        first_agent: &AgentBlockSpec,
    ) -> Result<TicketWindow, RexError> {
        let label = ticket_window_label(ticket_namespace, ticket_id)?;
        self.find_or_create_window(&label, first_agent)
    }

    pub fn find_or_create_project_window(
        &self,
        project_id: &crate::domain::ids::ProjectId,
        first_agent: &AgentBlockSpec,
    ) -> Result<RexWindow, RexError> {
        self.find_or_create_window(&supervisor_window_label(project_id.as_str()), first_agent)
    }

    fn find_or_create_window(
        &self,
        label: &str,
        first_agent: &AgentBlockSpec,
    ) -> Result<RexWindow, RexError> {
        let view = self.session_view()?;
        let matches = windows_with_label(&view, label)?;
        if matches.len() > 1 {
            return Err(RexError::Uncertain);
        }
        if let Some((window_id, block_id)) = matches.into_iter().next() {
            return Ok(TicketWindow {
                server_instance_id: self.capabilities.server_instance_id.clone(),
                session_id: self.session_id.clone(),
                window_id,
                label: label.to_owned(),
                initial_block_id: block_id,
                disposition: CreateDisposition::Existing,
            });
        }
        let args = json!({
            "session_id": self.session_id,
            "window_label": label,
            "focus": false,
            "layout": {"block": terminal_block(first_agent)?}
        });
        match self.invoke_mutating("session.new_window", args) {
            Ok(result) => {
                let window_id = required_string(&result, "window_id")?.to_owned();
                let block_id = result
                    .get("block_ids")
                    .and_then(Value::as_array)
                    .and_then(|blocks| blocks.first())
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                if block_id.is_none() {
                    return Err(RexError::Uncertain);
                }
                Ok(TicketWindow {
                    server_instance_id: self.capabilities.server_instance_id.clone(),
                    session_id: self.session_id.clone(),
                    window_id,
                    label: label.to_owned(),
                    initial_block_id: block_id,
                    disposition: CreateDisposition::Created,
                })
            }
            Err(_) => self.reconcile_window(label),
        }
    }

    fn reconcile_window(&self, label: &str) -> Result<TicketWindow, RexError> {
        let view = self.session_view().map_err(|_| RexError::Uncertain)?;
        let matches = windows_with_label(&view, label).map_err(|_| RexError::Uncertain)?;
        if matches.len() != 1 {
            return Err(RexError::Uncertain);
        }
        let (window_id, block_id) = matches.into_iter().next().expect("one match checked");
        Ok(TicketWindow {
            server_instance_id: self.capabilities.server_instance_id.clone(),
            session_id: self.session_id.clone(),
            window_id,
            label: label.to_owned(),
            initial_block_id: block_id,
            disposition: CreateDisposition::Reconciled,
        })
    }

    pub fn create_agent_block(
        &self,
        window: &TicketWindow,
        anchor_block_id: &str,
        spec: &AgentBlockSpec,
    ) -> Result<String, RexError> {
        self.check_window(window)?;
        let view = self.session_view()?;
        let matches = windows_with_label(&view, &window.label)?;
        if matches.len() != 1 || !window_contains_block(&view, &window.window_id, anchor_block_id) {
            return Err(RexError::Uncertain);
        }
        let args = json!({
            "session_id": self.session_id,
            "anchor_id": anchor_block_id,
            "direction": "horizontal",
            "side": "after",
            "focus": false,
            "layout": {"block": terminal_block(spec)?}
        });
        match self.invoke_mutating("session.new_split", args) {
            Ok(result) => result
                .get("block_ids")
                .and_then(Value::as_array)
                .and_then(|blocks| blocks.first())
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or(RexError::Uncertain),
            Err(_) => {
                let view = self.session_view().map_err(|_| RexError::Uncertain)?;
                let found = blocks_in_window(
                    &view,
                    &window.window_id,
                    Some(&format!("{OWNED_BLOCK_PREFIX}{}", spec.run_id)),
                )?;
                if found.len() == 1 {
                    Ok(found[0].block_id.clone())
                } else {
                    Err(RexError::Uncertain)
                }
            }
        }
    }

    /// Creates a uniquely labeled disposable Rex session and verifies the
    /// exact resources returned by `rex new` against the same configured server.
    pub(crate) fn create_disposable_qualification_session(
        &self,
        operation_id: &str,
        initial_agent: &AgentBlockSpec,
    ) -> Result<RexQualificationSessionReceipt, RexError> {
        if operation_id.is_empty()
            || operation_id.len() > 180
            || operation_id.chars().any(char::is_control)
            || initial_agent.run_id != operation_id
            || !Path::new(&initial_agent.command).is_absolute()
            || !initial_agent.path_prepend.is_empty()
        {
            return Err(RexError::Invalid(
                "qualification session requires a matching operation ID, absolute command, and no unsupported Rex PATH injection".into(),
            ));
        }
        terminal_block(initial_agent)?;
        let session_label = qualification_session_label(operation_id)?;
        let window_label = ticket_window_label(QUALIFICATION_WINDOW_NAMESPACE, operation_id)?;
        self.verify_identity()?;
        let mut args: Vec<OsString> = vec![
            "new".into(),
            session_label.clone().into(),
            "--cwd".into(),
            initial_agent.cwd.as_os_str().to_owned(),
            "--window".into(),
            window_label.clone().into(),
            "--keep-open".into(),
            "--shell".into(),
            "none".into(),
            "--json".into(),
            "--".into(),
            initial_agent.command.as_os_str().to_owned(),
        ];
        args.extend(initial_agent.args.iter().cloned().map(OsString::from));
        let output = match self.command(&args) {
            Ok(output) => output,
            Err(error) => {
                return self
                    .find_disposable_qualification_session(operation_id)?
                    .ok_or(error);
            }
        };
        self.verify_identity()?;
        let response: Value = parse(&output.stdout)?;
        let session_id = required_string(&response, "session_id")?.to_owned();
        if session_id.is_empty()
            || session_id.len() > 512
            || session_id.chars().any(char::is_control)
        {
            return Err(RexError::Protocol(
                "created qualification session ID is malformed".into(),
            ));
        }
        let windows = response
            .get("initial_windows")
            .and_then(Value::as_array)
            .filter(|windows| windows.len() == 1)
            .ok_or_else(|| {
                RexError::Protocol("rex new returned an unexpected window set".into())
            })?;
        let window = &windows[0];
        let window_id = required_string(window, "window_id")?.to_owned();
        let blocks = window
            .get("block_ids")
            .and_then(Value::as_array)
            .filter(|blocks| blocks.len() == 1)
            .ok_or_else(|| RexError::Protocol("rex new returned an unexpected block set".into()))?;
        let block_id = blocks[0]
            .as_str()
            .filter(|id| !id.is_empty() && !id.chars().any(char::is_control))
            .ok_or_else(|| RexError::Protocol("rex new returned an invalid block ID".into()))?
            .to_owned();
        let receipt = RexQualificationSessionReceipt {
            endpoint: self.endpoint.clone(),
            instance_id: self.expected_instance_id.clone(),
            session_id,
            window_id,
            block_id,
            operation_id: operation_id.to_owned(),
            session_label,
            window_label,
        };
        // Reconnect to the returned session and require an isolated one-window,
        // one-block view before allowing the receipt to leave the host.
        let bound = Self::connect(
            &self.executable,
            &[],
            receipt.endpoint.clone(),
            receipt.instance_id.clone(),
            receipt.session_id.clone(),
            self.environment.clone(),
        )?;
        bound.disposable_qualification_fixture(receipt.clone())?;
        Ok(receipt)
    }

    /// Reconciles an uncertain `rex new` using its unique immutable session label. It never
    /// creates a session and accepts only one exact owned window and block on the pinned server.
    pub(crate) fn find_disposable_qualification_session(
        &self,
        operation_id: &str,
    ) -> Result<Option<RexQualificationSessionReceipt>, RexError> {
        let session_label = qualification_session_label(operation_id)?;
        let window_label = ticket_window_label(QUALIFICATION_WINDOW_NAMESPACE, operation_id)?;
        self.verify_identity()?;
        let output = self.command(&["session".into(), "ls".into(), "--json".into()])?;
        let listed: Value = parse(&output.stdout)?;
        let sessions = listed
            .get("sessions")
            .and_then(Value::as_array)
            .ok_or_else(|| RexError::Protocol("session list has no sessions array".into()))?;
        let matches = sessions
            .iter()
            .filter(|session| session.get("label").and_then(Value::as_str) == Some(&session_label))
            .collect::<Vec<_>>();
        if matches.is_empty() {
            self.verify_identity()?;
            return Ok(None);
        }
        if matches.len() != 1 {
            return Err(RexError::Uncertain);
        }
        let session_id = required_string(matches[0], "session_id")?.to_owned();
        let bound = Self::connect(
            &self.executable,
            &[],
            self.endpoint.clone(),
            self.expected_instance_id.clone(),
            session_id.clone(),
            self.environment.clone(),
        )?;
        let view = bound.session_view()?;
        let windows = view
            .get("windows")
            .and_then(Value::as_array)
            .ok_or_else(|| RexError::Protocol("session view has no windows array".into()))?;
        let matching_windows = windows_with_label(&view, &window_label)?;
        if windows.len() != 1 || matching_windows.len() != 1 {
            return Err(RexError::Uncertain);
        }
        let (window_id, listed_block_id) = matching_windows[0].clone();
        let blocks = all_blocks_in_window(&view, &window_id)?;
        if blocks.len() != 1
            || blocks[0].flavor != SHELL_FLAVOR
            || listed_block_id.as_deref() != Some(blocks[0].block_id.as_str())
        {
            return Err(RexError::Uncertain);
        }
        let block_id = blocks[0].block_id.clone();
        let receipt = RexQualificationSessionReceipt {
            endpoint: self.endpoint.clone(),
            instance_id: self.expected_instance_id.clone(),
            session_id,
            window_id,
            block_id,
            operation_id: operation_id.to_owned(),
            session_label,
            window_label,
        };
        bound.disposable_qualification_fixture(receipt.clone())?;
        self.verify_identity()?;
        Ok(Some(receipt))
    }

    /// Re-observe a serialized host receipt before producing the opaque token
    /// accepted by `run_qualification_turn`.
    pub(crate) fn disposable_qualification_fixture(
        &self,
        receipt: RexQualificationSessionReceipt,
    ) -> Result<RexQualificationFixture, RexError> {
        if receipt.endpoint != self.endpoint
            || receipt.instance_id != self.expected_instance_id
            || receipt.session_id != self.session_id
            || receipt.session_label != qualification_session_label(&receipt.operation_id)?
            || receipt.window_label
                != ticket_window_label(QUALIFICATION_WINDOW_NAMESPACE, &receipt.operation_id)?
        {
            return Err(RexError::Invalid(
                "qualification receipt does not match this Rex transport".into(),
            ));
        }
        self.verify_identity()?;
        let view = self.session_view()?;
        let all_windows = view
            .get("windows")
            .and_then(Value::as_array)
            .ok_or_else(|| RexError::Protocol("session view has no windows array".into()))?;
        let matches = windows_with_label(&view, &receipt.window_label)?;
        let blocks = all_blocks_in_window(&view, &receipt.window_id)?;
        if all_windows.len() != 1
            || matches.len() != 1
            || matches[0].0 != receipt.window_id
            || blocks.len() != 1
            || blocks[0].block_id != receipt.block_id
            || blocks[0].flavor != SHELL_FLAVOR
        {
            return Err(RexError::Uncertain);
        }
        self.verify_identity()?;
        Ok(RexQualificationFixture {
            endpoint: self.endpoint.clone(),
            instance_id: self.expected_instance_id.clone(),
            session_id: self.session_id.clone(),
            window_id: receipt.window_id,
            block_id: receipt.block_id,
            operation_id: receipt.operation_id,
        })
    }

    /// Observe the initial `rex new --shell none` block by its exact host-issued qualification
    /// receipt. This bootstrap block uses Rex's default shell label, so ordinary Agent-label
    /// matching cannot establish its process identity.
    pub(crate) fn observe_qualification_process(
        &self,
        receipt: &RexQualificationSessionReceipt,
    ) -> Result<RexProcessObservation, RexError> {
        self.disposable_qualification_fixture(receipt.clone())?;
        self.verify_identity()?;
        let encoded = serde_json::to_string(&json!({
            "session_id": receipt.session_id,
            "block_id": receipt.block_id
        }))
        .map_err(|_| RexError::Protocol("request encoding failed".into()))?;
        let output = self.command(&[
            "api".into(),
            "call".into(),
            "com.superlogical.terminal.process".into(),
            encoded.into(),
        ])?;
        let observation: RexProcessObservation =
            parse(&output.stdout).map_err(|_| RexError::Uncertain)?;
        self.verify_identity().map_err(|_| RexError::Uncertain)?;
        Ok(observation)
    }

    /// Close only the exact isolated session minted by `rex new`, then verify it is absent
    /// from this explicit Rex server. Call after its provider process tree is confirmed gone.
    pub(crate) fn close_disposable_qualification_session(
        &self,
        receipt: RexQualificationSessionReceipt,
    ) -> Result<(), RexError> {
        self.verify_identity()?;
        let sessions = self.session_list()?;
        let listed = sessions
            .get("sessions")
            .and_then(Value::as_array)
            .ok_or_else(|| RexError::Protocol("session list has no sessions array".into()))?;
        let matches = listed
            .iter()
            .filter(|session| {
                session.get("session_id").and_then(Value::as_str) == Some(&receipt.session_id)
            })
            .collect::<Vec<_>>();
        if matches.is_empty() {
            self.verify_identity()?;
            return Ok(());
        }
        if matches.len() != 1
            || matches[0].get("label").and_then(Value::as_str) != Some(&receipt.session_label)
        {
            return Err(RexError::Uncertain);
        }
        let view = self.session_view()?;
        let windows = view
            .get("windows")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default();
        if !windows.is_empty() {
            self.disposable_qualification_fixture(receipt.clone())?;
        }
        self.command(&["kill".into(), receipt.session_id.clone().into()])?;
        let sessions = self.session_list()?;
        if value_contains_exact_string(&sessions, &receipt.session_id) {
            return Err(RexError::Uncertain);
        }
        self.verify_identity()?;
        Ok(())
    }

    fn session_list(&self) -> Result<Value, RexError> {
        let output = self.command(&["session".into(), "ls".into(), "--json".into()])?;
        let sessions: Value = parse(&output.stdout)?;
        if sessions.get("sessions").and_then(Value::as_array).is_none() {
            return Err(RexError::Protocol(
                "session list has no sessions array".into(),
            ));
        }
        Ok(sessions)
    }

    pub(crate) fn qualification_session_exists(&self, session_id: &str) -> Result<bool, RexError> {
        if session_id.is_empty() || session_id.chars().any(char::is_control) {
            return Err(RexError::Invalid(
                "qualification session ID is malformed".into(),
            ));
        }
        self.verify_identity()?;
        let sessions = self.session_list()?;
        let listed = sessions
            .get("sessions")
            .and_then(Value::as_array)
            .ok_or_else(|| RexError::Protocol("session list has no sessions array".into()))?;
        let matches = listed
            .iter()
            .filter(|session| session.get("session_id").and_then(Value::as_str) == Some(session_id))
            .count();
        self.verify_identity()?;
        match matches {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(RexError::Uncertain),
        }
    }

    /// Returns true when Rex has removed the exact host-created qualification block. The
    /// enclosing session must remain unique and contain no foreign windows or blocks.
    pub(crate) fn qualification_block_finished(
        &self,
        receipt: &RexQualificationSessionReceipt,
    ) -> Result<bool, RexError> {
        if receipt.endpoint != self.endpoint
            || receipt.instance_id != self.expected_instance_id
            || receipt.session_id != self.session_id
        {
            return Err(RexError::Invalid(
                "qualification receipt does not match this Rex transport".into(),
            ));
        }
        self.verify_identity()?;
        let sessions = self.session_list()?;
        let listed = sessions
            .get("sessions")
            .and_then(Value::as_array)
            .ok_or_else(|| RexError::Protocol("session list has no sessions array".into()))?;
        let matches = listed
            .iter()
            .filter(|session| {
                session.get("session_id").and_then(Value::as_str) == Some(&receipt.session_id)
            })
            .collect::<Vec<_>>();
        if matches.is_empty() {
            return Ok(true);
        }
        if matches.len() != 1
            || matches[0].get("label").and_then(Value::as_str) != Some(&receipt.session_label)
        {
            return Err(RexError::Uncertain);
        }
        let view = self.session_view()?;
        if view.get("session_id").and_then(Value::as_str) != Some(&receipt.session_id)
            || view.get("label").and_then(Value::as_str) != Some(&receipt.session_label)
        {
            return Err(RexError::Uncertain);
        }
        let windows = view
            .get("windows")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default();
        if windows.is_empty() {
            return Ok(true);
        }
        if windows.len() != 1
            || windows[0].get("window_id").and_then(Value::as_str) != Some(&receipt.window_id)
            || windows[0].get("label").and_then(Value::as_str) != Some(&receipt.window_label)
        {
            return Err(RexError::Uncertain);
        }
        let blocks = all_blocks_in_window(&view, &receipt.window_id)?;
        if blocks.is_empty() {
            return Ok(true);
        }
        if blocks.len() == 1
            && blocks[0].block_id == receipt.block_id
            && blocks[0].flavor == SHELL_FLAVOR
        {
            return Ok(false);
        }
        Err(RexError::Uncertain)
    }

    pub fn list_owned_windows_and_blocks(&self) -> Result<Vec<OwnedWindow>, RexError> {
        let view = self.session_view()?;
        let windows = view
            .get("windows")
            .and_then(Value::as_array)
            .ok_or_else(|| RexError::Protocol("session view has no windows array".into()))?;
        windows
            .iter()
            .filter_map(|window| {
                let label = window.get("label").and_then(Value::as_str)?;
                (label.starts_with(OWNED_WINDOW_PREFIX)
                    || label.starts_with(OWNED_SUPERVISOR_WINDOW_PREFIX))
                .then(|| {
                    let window_id = window
                        .get("window_id")
                        .and_then(Value::as_str)
                        .ok_or_else(|| RexError::Protocol("owned window has no ID".into()))?
                        .to_owned();
                    let blocks = blocks_in_window(&view, &window_id, None)?;
                    Ok(OwnedWindow {
                        window_id,
                        label: label.to_owned(),
                        blocks,
                    })
                })
            })
            .collect()
    }

    pub fn list_window_blocks(
        &self,
        window: &RexWindow,
        expected_label: &str,
    ) -> Result<Vec<WindowBlock>, RexError> {
        self.check_window(window)?;
        if window.label != expected_label || !is_owned_window_label(expected_label) {
            return Err(RexError::Invalid(
                "Rex window label does not match its owner".into(),
            ));
        }
        let view = self.session_view()?;
        let matches = windows_with_label(&view, expected_label)?;
        if matches.len() != 1 || matches[0].0 != window.window_id {
            return Err(RexError::Uncertain);
        }
        all_blocks_in_window(&view, &window.window_id)
    }

    pub fn window_exists(&self, window: &RexWindow) -> Result<bool, RexError> {
        self.check_window(window)?;
        let view = self.session_view()?;
        let matches = windows_with_label(&view, &window.label)?;
        if matches.len() > 1 {
            return Err(RexError::Uncertain);
        }
        Ok(matches.iter().any(|(id, _)| id == &window.window_id))
    }

    /// Verify that a caller-provided current block belongs to the connected
    /// session. The RPC is a read and must happen before any state write.
    pub fn validate_session_block(&self, block_id: &str) -> Result<(), RexError> {
        if block_id.is_empty() || block_id.chars().any(char::is_control) {
            return Err(RexError::Invalid("Rex block ID is malformed".into()));
        }
        let view = self.session_view()?;
        let windows = view
            .get("windows")
            .and_then(Value::as_array)
            .ok_or_else(|| RexError::Protocol("session view has no windows".into()))?;
        let found = windows
            .iter()
            .flat_map(|window| {
                window
                    .get("layers")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(|layer| layer.get("blocks").and_then(Value::as_array))
                    .flatten()
            })
            .filter(|block| block.get("block_id").and_then(Value::as_str) == Some(block_id))
            .count();
        match found {
            1 => Ok(()),
            0 => Err(RexError::Invalid(
                "current Rex block is absent from the session".into(),
            )),
            _ => Err(RexError::Uncertain),
        }
    }

    pub fn focus_block(&self, block_id: &str) -> Result<(), RexError> {
        self.invoke_mutating(
            "session.focus_block",
            json!({"session_id": self.session_id, "block_id": block_id}),
        )
        .map(|_| ())
    }

    pub fn zoom_block(&self, block_id: &str, zoom: bool) -> Result<(), RexError> {
        self.invoke_mutating(
            "session.zoom_block",
            json!({"session_id": self.session_id, "block_id": block_id, "zoom": zoom}),
        )
        .map(|_| ())
    }

    pub fn close_agent_block(
        &self,
        window: &TicketWindow,
        run_id: &str,
        block_id: &str,
    ) -> Result<(), RexError> {
        self.check_window(window)?;
        let view = self.session_view()?;
        let expected_label = owned_block_label(run_id)?;
        let owned = blocks_in_window(&view, &window.window_id, Some(&expected_label))?
            .iter()
            .any(|block| block.block_id == block_id);
        if !owned {
            return Err(RexError::Invalid(
                "refusing to close a block not owned by this run".into(),
            ));
        }
        self.invoke_mutating(
            "block.close",
            json!({"session_id": self.session_id, "block_id": block_id}),
        )
        .map(|_| ())
    }

    pub fn capture_agent_block(
        &self,
        window: &TicketWindow,
        run_id: &str,
        block_id: &str,
    ) -> Result<String, RexError> {
        self.check_window(window)?;
        let expected_label = owned_block_label(run_id)?;
        let view = self.session_view()?;
        if !blocks_in_window(&view, &window.window_id, Some(&expected_label))?
            .iter()
            .any(|block| block.block_id == block_id)
        {
            return Err(RexError::Uncertain);
        }
        self.verify_identity()?;
        let output = self.command(&[
            "capture".into(),
            "--session".into(),
            self.session_id.clone().into(),
            "--block".into(),
            block_id.into(),
            "--trim".into(),
            "--unwrap".into(),
        ])?;
        self.verify_identity().map_err(|_| RexError::Uncertain)?;
        if output.stdout.len() > 1_048_576 {
            return Err(RexError::Invalid(
                "Rex block archive exceeds the 1 MiB limit".into(),
            ));
        }
        String::from_utf8(output.stdout)
            .map_err(|_| RexError::Protocol("Rex block capture is not UTF-8 text".into()))
    }

    /// Confirm a recorded owned block still has its original terminal command configuration.
    /// A matching label alone is insufficient because users can reuse terminal blocks.
    pub fn agent_block_matches_spec(
        &self,
        window: &TicketWindow,
        spec: &AgentBlockSpec,
        block_id: &str,
    ) -> Result<bool, RexError> {
        self.check_window(window)?;
        let expected = terminal_block(spec)?;
        let expected_label = owned_block_label(&spec.run_id)?;
        let view = self.session_view()?;
        let windows = view
            .get("windows")
            .and_then(Value::as_array)
            .ok_or_else(|| RexError::Protocol("session view has no windows".into()))?;
        let Some(window_value) = windows.iter().find(|value| {
            value.get("window_id").and_then(Value::as_str) == Some(window.window_id.as_str())
        }) else {
            return Ok(false);
        };
        let actual = window_value
            .get("layers")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|layer| layer.get("blocks").and_then(Value::as_array))
            .flatten()
            .find(|block| block.get("block_id").and_then(Value::as_str) == Some(block_id));
        let Some(actual) = actual else {
            return Ok(false);
        };
        if actual.get("label").and_then(Value::as_str) != Some(expected_label.as_str())
            || actual.get("flavor") != expected.get("flavor")
            || actual.get("options") != expected.get("options")
        {
            return Ok(false);
        }
        self.verify_identity()?;
        Ok(true)
    }

    /// Observe the verified block-scoped `terminal.process` action. Rex does
    /// not advertise this dynamic action in the global `api list`, so this
    /// deliberately bypasses the global method-name capability set.
    pub fn observe_process(
        &self,
        window: &TicketWindow,
        run_id: &str,
        block_id: &str,
    ) -> Result<RexProcessObservation, RexError> {
        self.check_window(window)?;
        let view = self.session_view()?;
        let expected_label = owned_block_label(run_id)?;
        if !blocks_in_window(&view, &window.window_id, Some(&expected_label))?
            .iter()
            .any(|block| block.block_id == block_id)
        {
            return Err(RexError::Uncertain);
        }
        self.verify_identity()?;
        let encoded = serde_json::to_string(&json!({
            "session_id": self.session_id,
            "block_id": block_id
        }))
        .map_err(|_| RexError::Protocol("request encoding failed".into()))?;
        let output = self.command(&[
            "api".into(),
            "call".into(),
            "com.superlogical.terminal.process".into(),
            encoded.into(),
        ]);
        let output = output.map_err(|_| RexError::Uncertain)?;
        let observation: RexProcessObservation =
            parse(&output.stdout).map_err(|_| RexError::Uncertain)?;
        self.verify_identity().map_err(|_| RexError::Uncertain)?;
        Ok(observation)
    }

    /// Return whether the exact managed block remains in a successful pinned session inventory.
    /// `false` is authoritative absence; transport or identity errors stay `Err`.
    pub fn agent_block_is_present(
        &self,
        window: &TicketWindow,
        run_id: &str,
        block_id: &str,
    ) -> Result<bool, RexError> {
        self.check_window(window)?;
        let expected_label = owned_block_label(run_id)?;
        let view = self.session_view()?;
        if view.get("session_id").and_then(Value::as_str) != Some(&self.session_id) {
            return Err(RexError::Uncertain);
        }
        let windows = view
            .get("windows")
            .and_then(Value::as_array)
            .ok_or_else(|| RexError::Protocol("session view has no windows array".into()))?;
        let mut present = false;
        for item in windows {
            let Some(window_id) = item.get("window_id").and_then(Value::as_str) else {
                return Err(RexError::Protocol("session view window has no ID".into()));
            };
            for block in blocks_in_window(&view, window_id, None)? {
                if block.block_id == block_id {
                    if block.label != expected_label {
                        return Err(RexError::Uncertain);
                    }
                    present = true;
                }
            }
        }
        self.verify_identity()?;
        Ok(present)
    }

    fn check_window(&self, window: &TicketWindow) -> Result<(), RexError> {
        if window.server_instance_id != self.expected_instance_id
            || window.session_id != self.session_id
        {
            return Err(RexError::WrongServer);
        }
        Ok(())
    }

    fn require_method(&self, method: &str) -> Result<(), RexError> {
        self.capabilities
            .methods
            .contains(method)
            .then_some(())
            .ok_or_else(|| RexError::Unsupported(method.into()))
    }

    fn verify_identity(&self) -> Result<(), RexError> {
        let output = self.command(&["whoami".into(), "--json".into()])?;
        let identity: WhoAmI = parse(&output.stdout)?;
        if identity.endpoint != self.endpoint || identity.instance_id != self.expected_instance_id {
            return Err(RexError::WrongServer);
        }
        Ok(())
    }

    fn session_view(&self) -> Result<Value, RexError> {
        self.call_api(
            "session.view",
            json!({"session_id": self.session_id}),
            false,
        )
    }

    fn invoke_mutating(&self, method: &str, args: Value) -> Result<Value, RexError> {
        self.verify_identity()?;
        self.call_api(method, args, true)
            .map_err(|error| match error {
                RexError::Invalid(_) | RexError::Unsupported(_) | RexError::WrongServer => error,
                _ => RexError::Uncertain,
            })
    }

    fn call_api(&self, method: &str, args: Value, mutation: bool) -> Result<Value, RexError> {
        self.require_method(method)?;
        let encoded = serde_json::to_string(&args)
            .map_err(|_| RexError::Protocol("request encoding failed".into()))?;
        let output = self.command(&["api".into(), "call".into(), method.into(), encoded.into()]);
        let output = match output {
            Ok(output) => output,
            Err(error) if mutation => return Err(error),
            Err(error) => return Err(error),
        };
        let result: Value = parse(&output.stdout)?;
        if mutation {
            self.verify_identity().map_err(|_| RexError::Uncertain)?;
        }
        Ok(result)
    }

    fn command(&self, args: &[OsString]) -> Result<crate::process::ProcessOutput, RexError> {
        let mut full_args = vec![
            "--server".into(),
            self.endpoint.clone().into(),
            "--autostart=false".into(),
            "--timeout".into(),
            format!("{}s", self.timeout.as_secs()).into(),
        ];
        full_args.extend_from_slice(args);
        let output = run(ProcessRequest {
            executable: self.executable.clone(),
            args: full_args,
            stdin: Vec::new(),
            cwd: None,
            clear_environment: false,
            environment: self.environment.clone(),
            timeout: self.timeout + Duration::from_secs(2),
            shutdown_grace: self.shutdown_grace,
            stdout_limit: 4 * 1024 * 1024,
            stderr_tail_limit: 64 * 1024,
        })
        .map_err(|_| RexError::Process)?;
        if output.timed_out
            || !output.cleanup_confirmed
            || !output.status.is_some_and(|status| status.success())
            || output.stdout_truncated
        {
            return Err(RexError::Process);
        }
        Ok(output)
    }
}

#[derive(Deserialize)]
struct WhoAmI {
    endpoint: String,
    instance_id: String,
    host_id: String,
    rex_version: String,
}

fn raw_cli(
    executable: &Path,
    endpoint: &str,
    environment: &BTreeMap<OsString, OsString>,
    timeout: Duration,
    shutdown_grace: Duration,
    args: &[&str],
) -> Result<crate::process::ProcessOutput, RexError> {
    let mut full = vec![
        "--server".into(),
        endpoint.into(),
        "--autostart=false".into(),
        "--timeout".into(),
        format!("{}s", timeout.as_secs()).into(),
    ];
    full.extend(args.iter().map(OsString::from));
    let result = run(ProcessRequest {
        executable: executable.to_path_buf(),
        args: full,
        stdin: Vec::new(),
        cwd: None,
        clear_environment: false,
        environment: environment.clone(),
        timeout: timeout + Duration::from_secs(2),
        shutdown_grace,
        stdout_limit: 4 * 1024 * 1024,
        stderr_tail_limit: 64 * 1024,
    })
    .map_err(|_| RexError::Process)?;
    if result.timed_out
        || !result.cleanup_confirmed
        || !result.status.is_some_and(|status| status.success())
        || result.stdout_truncated
    {
        return Err(RexError::Process);
    }
    Ok(result)
}

fn parse<T: for<'de> Deserialize<'de>>(input: &[u8]) -> Result<T, RexError> {
    crate::protocol::parse_unique(input).map_err(RexError::Protocol)
}

fn value_contains_exact_string(value: &Value, expected: &str) -> bool {
    match value {
        Value::String(value) => value == expected,
        Value::Array(values) => values
            .iter()
            .any(|value| value_contains_exact_string(value, expected)),
        Value::Object(values) => values
            .values()
            .any(|value| value_contains_exact_string(value, expected)),
        _ => false,
    }
}

fn parse_method_names(input: &[u8]) -> Result<BTreeSet<String>, RexError> {
    let value: Value = parse(input)?;
    let names = if let Some(object) = value.get("methods").and_then(Value::as_object) {
        object.keys().cloned().collect()
    } else if let Some(array) = value.get("methods").and_then(Value::as_array) {
        array
            .iter()
            .filter_map(|method| {
                method
                    .get("name")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .collect()
    } else {
        return Err(RexError::Protocol("Rex API list has no methods".into()));
    };
    Ok(names)
}

fn ticket_window_label(namespace: &str, ticket_id: &str) -> Result<String, RexError> {
    if namespace.is_empty()
        || ticket_id.is_empty()
        || namespace.chars().any(char::is_control)
        || ticket_id.chars().any(char::is_control)
    {
        return Err(RexError::Invalid(
            "ticket identity is empty or contains control characters".into(),
        ));
    }
    let mut hasher = Sha256::new();
    hasher.update(namespace.as_bytes());
    hasher.update([0]);
    hasher.update(ticket_id.as_bytes());
    Ok(format!(
        "{OWNED_WINDOW_PREFIX}{}",
        hex_prefix(&hasher.finalize(), 24)
    ))
}

fn qualification_session_label(operation_id: &str) -> Result<String, RexError> {
    if operation_id.is_empty()
        || operation_id.len() > 180
        || operation_id.chars().any(char::is_control)
    {
        return Err(RexError::Invalid(
            "qualification operation ID is invalid".into(),
        ));
    }
    Ok(format!("{QUALIFICATION_SESSION_PREFIX}{operation_id}"))
}

fn supervisor_window_label(project_id: &str) -> String {
    let digest = Sha256::digest(project_id.as_bytes());
    format!(
        "{OWNED_SUPERVISOR_WINDOW_PREFIX}{}",
        hex_prefix(&digest, 24)
    )
}

pub fn owned_ticket_window_label(namespace: &str, ticket_id: &str) -> Result<String, RexError> {
    ticket_window_label(namespace, ticket_id)
}

pub fn owned_supervisor_window_label(project_id: &str) -> String {
    supervisor_window_label(project_id)
}

fn is_owned_window_label(label: &str) -> bool {
    label.starts_with(OWNED_WINDOW_PREFIX) || label.starts_with(OWNED_SUPERVISOR_WINDOW_PREFIX)
}

fn owned_block_label(run_id: &str) -> Result<String, RexError> {
    if run_id.is_empty() || run_id.chars().any(char::is_control) {
        return Err(RexError::Invalid(
            "run ID is empty or contains control characters".into(),
        ));
    }
    let mut hasher = Sha256::new();
    hasher.update(run_id.as_bytes());
    Ok(format!(
        "{OWNED_BLOCK_PREFIX}{}",
        hex_prefix(&hasher.finalize(), 24)
    ))
}

pub fn owned_agent_block_label(run_id: &str) -> Result<String, RexError> {
    owned_block_label(run_id)
}

fn hex_prefix(digest: &[u8], bytes: usize) -> String {
    digest
        .iter()
        .take(bytes / 2)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn terminal_block(spec: &AgentBlockSpec) -> Result<Value, RexError> {
    let label = owned_block_label(&spec.run_id)?;
    if !spec.command.is_absolute()
        || !spec.cwd.is_absolute()
        || spec.path_prepend.iter().any(|path| !path.is_absolute())
        || spec
            .args
            .iter()
            .any(|arg| arg.chars().any(char::is_control))
        || spec
            .path_prepend
            .iter()
            .any(|path| path.to_string_lossy().chars().any(char::is_control))
    {
        return Err(RexError::Invalid(
            "run-step command, working directory, and arguments must be validated".into(),
        ));
    }
    Ok(json!({
        "flavor": SHELL_FLAVOR,
        "label": label,
        "options": {
            "command": std::iter::once(spec.command.display().to_string()).chain(spec.args.iter().cloned()).collect::<Vec<_>>(),
            "cwd": spec.cwd,
            "shell": "none",
            "login": false,
            "path_prepend": spec.path_prepend,
            "exit": {"on_completion": false}
        }
    }))
}

fn windows_with_label(
    view: &Value,
    wanted: &str,
) -> Result<Vec<(String, Option<String>)>, RexError> {
    let windows = view
        .get("windows")
        .and_then(Value::as_array)
        .ok_or_else(|| RexError::Protocol("session view has no windows".into()))?;
    let mut result = Vec::new();
    for window in windows {
        if window.get("label").and_then(Value::as_str) != Some(wanted) {
            continue;
        }
        let id = required_string(window, "window_id")?.to_owned();
        let blocks = blocks_in_window(view, &id, None)?;
        result.push((id, blocks.first().map(|block| block.block_id.clone())));
    }
    Ok(result)
}

fn blocks_in_window(
    view: &Value,
    window_id: &str,
    exact_label: Option<&str>,
) -> Result<Vec<OwnedBlock>, RexError> {
    let windows = view
        .get("windows")
        .and_then(Value::as_array)
        .ok_or_else(|| RexError::Protocol("session view has no windows".into()))?;
    let window = windows
        .iter()
        .find(|window| window.get("window_id").and_then(Value::as_str) == Some(window_id))
        .ok_or_else(|| RexError::Protocol("recorded window is absent from session view".into()))?;
    let layers = window
        .get("layers")
        .and_then(Value::as_array)
        .ok_or_else(|| RexError::Protocol("window has no layers".into()))?;
    let mut result = Vec::new();
    for layer in layers {
        if let Some(blocks) = layer.get("blocks").and_then(Value::as_array) {
            for block in blocks {
                let label = block
                    .get("label")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if !label.starts_with(OWNED_BLOCK_PREFIX)
                    || exact_label.is_some_and(|wanted| label != wanted)
                {
                    continue;
                }
                result.push(OwnedBlock {
                    block_id: required_string(block, "block_id")?.to_owned(),
                    label: label.to_owned(),
                    flavor: block
                        .get("flavor")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                });
            }
        }
    }
    Ok(result)
}

fn context_blocks(view: &Value, wanted: &str) -> Result<Vec<(String, String, String)>, RexError> {
    let windows = view
        .get("windows")
        .and_then(Value::as_array)
        .ok_or_else(|| RexError::Protocol("session view has no windows array".into()))?;
    let mut found = Vec::new();
    for window in windows {
        let window_id = required_string(window, "window_id")?.to_owned();
        let layers = window
            .get("layers")
            .and_then(Value::as_array)
            .ok_or_else(|| RexError::Protocol("window has no layers array".into()))?;
        for layer in layers {
            let Some(blocks) = layer.get("blocks").and_then(Value::as_array) else {
                continue;
            };
            for block in blocks {
                if block.get("block_id").and_then(Value::as_str) == Some(wanted) {
                    found.push((
                        window_id.clone(),
                        required_string(block, "label")?.to_owned(),
                        required_string(block, "flavor")?.to_owned(),
                    ));
                }
            }
        }
    }
    Ok(found)
}

fn all_blocks_in_window(view: &Value, window_id: &str) -> Result<Vec<WindowBlock>, RexError> {
    let windows = view
        .get("windows")
        .and_then(Value::as_array)
        .ok_or_else(|| RexError::Protocol("session view has no windows".into()))?;
    let window = windows
        .iter()
        .find(|window| window.get("window_id").and_then(Value::as_str) == Some(window_id))
        .ok_or_else(|| RexError::Protocol("recorded window is absent from session view".into()))?;
    let layers = window
        .get("layers")
        .and_then(Value::as_array)
        .ok_or_else(|| RexError::Protocol("window has no layers".into()))?;
    let mut result = Vec::new();
    for layer in layers {
        for block in layer
            .get("blocks")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            result.push(WindowBlock {
                block_id: required_string(block, "block_id")?.to_owned(),
                label: block
                    .get("label")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                flavor: block
                    .get("flavor")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
            });
        }
    }
    Ok(result)
}

fn window_contains_block(view: &Value, window_id: &str, block_id: &str) -> bool {
    blocks_in_window(view, window_id, None)
        .is_ok_and(|blocks| blocks.iter().any(|block| block.block_id == block_id))
}

fn required_string<'a>(value: &'a Value, key: &str) -> Result<&'a str, RexError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| RexError::Protocol(format!("response is missing `{key}`")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::path::PathBuf;

    #[test]
    fn ticket_labels_are_stable_and_namespace_scoped() {
        let first = ticket_window_label("tracker/tenant", "T-1").unwrap();
        assert_eq!(first, ticket_window_label("tracker/tenant", "T-1").unwrap());
        assert_ne!(first, ticket_window_label("tracker/other", "T-1").unwrap());
        assert_ne!(first, ticket_window_label("tracker/tenant", "T-2").unwrap());
    }

    #[test]
    fn block_labels_do_not_expose_run_identifiers() {
        let label = owned_block_label("run-secret-name").unwrap();
        assert!(label.starts_with("rex-projects-run-"));
        assert!(!label.contains("run-secret-name"));
    }

    #[test]
    fn rejects_incomplete_agent_launch_descriptor_before_rex_call() {
        let spec = AgentBlockSpec {
            run_id: "r1".into(),
            command: PathBuf::from("relative"),
            args: vec![],
            cwd: PathBuf::from("/tmp"),
            path_prepend: vec![],
        };
        assert!(super::terminal_block(&spec).is_err());
    }

    #[test]
    fn completed_agent_blocks_remain_available_for_host_reconciliation() {
        let dir = tempfile::tempdir().unwrap();
        let spec = AgentBlockSpec {
            run_id: "view-anchor-1".into(),
            command: PathBuf::from("/usr/bin/true"),
            args: vec![],
            cwd: dir.path().to_path_buf(),
            path_prepend: vec![PathBuf::from("/usr/bin")],
        };

        let terminal = super::terminal_block(&spec).unwrap();

        assert_eq!(terminal["options"]["exit"]["on_completion"], false);
    }

    #[test]
    fn parses_block_process_observation_without_exposing_arguments() {
        let observation: super::RexProcessObservation = super::parse(
            br#"{"last_exit":null,"child":{"pid":10,"user_id":501,"name":"codex","path":"/usr/bin/codex"},"foreground":{"pid":11,"user_id":501,"name":"node"},"ancestors":[]}"#,
        )
        .unwrap();
        assert_eq!(observation.last_exit, None);
        assert_eq!(observation.child.unwrap().name, "codex");
    }

    #[cfg(unix)]
    #[test]
    fn discovers_authoritative_rex_endpoint_and_rejects_override_mismatch() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("rex identity fixture");
        std::fs::write(
            &script,
            "#!/bin/sh\nprintf '%s\\n' '{\"endpoint\":\"unix:///tmp/rex-test.sock\",\"instance_id\":\"instance-1\",\"host_id\":\"host-1\",\"rex_version\":\"1.2.3\"}'\n",
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let environment = BTreeMap::from([
            (OsString::from("REX_SESSION"), OsString::from("session-1")),
            (OsString::from("REX_BLOCK"), OsString::from("block-1")),
        ]);
        let identity = RexIdentity::discover(&script, &[], &environment, None).unwrap();
        assert_eq!(identity.endpoint, "unix:///tmp/rex-test.sock");
        assert_eq!(identity.instance_id, "instance-1");
        assert_eq!(identity.session_id, "session-1");
        assert_eq!(identity.block_id.as_deref(), Some("block-1"));
        assert!(
            RexIdentity::discover(&script, &[], &environment, Some("unix:///tmp/other.sock"))
                .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn uses_block_scoped_process_action_even_though_it_is_not_in_global_api_list() {
        let dir = tempfile::tempdir().unwrap();
        let run_id = "run-1";
        let window_label = ticket_window_label("tracker", "T-9").unwrap();
        let block_label = owned_block_label(run_id).unwrap();
        let view = serde_json::json!({"windows":[{"window_id":"window-1","label":window_label,"layers":[{"blocks":[{"block_id":"block-1","label":block_label,"flavor":"com.superlogical.terminal.shell"}]}]}]});
        let whoami = serde_json::json!({"endpoint":"unix:///tmp/rex-test.sock","instance_id":"instance-1","host_id":"host-1","rex_version":"1.2.3"});
        let api = serde_json::json!({"methods":{"session.view":{},"session.new_window":{},"session.new_split":{},"session.focus_block":{},"session.zoom_block":{},"block.close":{}}});
        let process = serde_json::json!({"last_exit":null,"child":{"pid":10,"user_id":501,"name":"codex","path":"/usr/bin/codex"},"foreground":{"pid":11,"user_id":501,"name":"node"},"ancestors":[]});
        let script = dir.path().join("rex fake");
        let body = format!(
            "#!/bin/sh\ncase \"$*\" in\n  *\"whoami --json\"*) printf '%s\\n' '{}' ;;\n  *\"api list --json\"*) printf '%s\\n' '{}' ;;\n  *\"session.view\"*) printf '%s\\n' '{}' ;;\n  *\"terminal.process\"*) printf '%s\\n' '{}' ;;\n  *) exit 3 ;;\nesac\n",
            whoami, api, view, process
        );
        std::fs::write(&script, body).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let transport = RexCliTransport::connect(
            &script,
            &[],
            "unix:///tmp/rex-test.sock".into(),
            "instance-1".into(),
            "session-1".into(),
            BTreeMap::<OsString, OsString>::new(),
        )
        .unwrap();
        transport.validate_session_block("block-1").unwrap();
        assert!(transport.validate_session_block("other-block").is_err());
        let window = TicketWindow {
            server_instance_id: "instance-1".into(),
            session_id: "session-1".into(),
            window_id: "window-1".into(),
            label: window_label,
            initial_block_id: Some("block-1".into()),
            disposition: CreateDisposition::Existing,
        };
        let observation = transport
            .observe_process(&window, run_id, "block-1")
            .unwrap();
        assert_eq!(observation.child.unwrap().name, "codex");
    }

    #[cfg(unix)]
    #[test]
    fn matches_owned_anchor_by_label_and_full_terminal_configuration() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let run_id = "ticket-T-9-view-2";
        let window_label = ticket_window_label("tracker", "T-9").unwrap();
        let spec = AgentBlockSpec {
            run_id: run_id.into(),
            command: PathBuf::from("/usr/bin/env"),
            args: vec!["/tmp/rex-projects".into(), "status".into(), "--json".into()],
            cwd: dir.path().to_path_buf(),
            path_prepend: vec![PathBuf::from("/usr/bin")],
        };
        let terminal = super::terminal_block(&spec).unwrap();
        let view = serde_json::json!({"windows":[{"window_id":"window-1","label":window_label,"layers":[{"blocks":[{
            "block_id":"anchor-1",
            "label":owned_block_label(run_id).unwrap(),
            "flavor":terminal["flavor"],
            "options":terminal["options"]
        }]}]}]});
        let whoami = serde_json::json!({"endpoint":"unix:///tmp/rex-test.sock","instance_id":"instance-1","host_id":"host-1","rex_version":"1.2.3"});
        let api = serde_json::json!({"methods":{"session.view":{},"session.new_window":{},"session.new_split":{},"session.focus_block":{},"session.zoom_block":{},"block.close":{}}});
        let script = dir.path().join("rex fake");
        let body = format!(
            "#!/bin/sh\ncase \"$*\" in\n  *\"whoami --json\"*) printf '%s\\n' '{}' ;;\n  *\"api list --json\"*) printf '%s\\n' '{}' ;;\n  *\"session.view\"*) printf '%s\\n' '{}' ;;\n  *) exit 3 ;;\nesac\n",
            whoami, api, view
        );
        std::fs::write(&script, body).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let transport = RexCliTransport::connect(
            &script,
            &[],
            "unix:///tmp/rex-test.sock".into(),
            "instance-1".into(),
            "session-1".into(),
            BTreeMap::<OsString, OsString>::new(),
        )
        .unwrap();
        let window = TicketWindow {
            server_instance_id: "instance-1".into(),
            session_id: "session-1".into(),
            window_id: "window-1".into(),
            label: window_label,
            initial_block_id: Some("anchor-1".into()),
            disposition: CreateDisposition::Existing,
        };
        assert!(
            transport
                .agent_block_matches_spec(&window, &spec, "anchor-1")
                .unwrap()
        );
        let mut changed = spec;
        changed.cwd = PathBuf::from("/tmp");
        assert!(
            !transport
                .agent_block_matches_spec(&window, &changed, "anchor-1")
                .unwrap()
        );
    }

    #[test]
    fn rex_event_parser_accepts_only_scoped_close_and_inventory_events() {
        assert_eq!(
            parse_rex_event_frame(br#"{"type":"session_event","payload":{"session_id":"session-a","event":{"type":"block_closed","payload":{"block_id":"block-a"}}}}"#),
            Ok(Some(RexEventSignal::BlockClosed {
                session_id: "session-a".into(),
                block_id: "block-a".into(),
            }))
        );
        assert_eq!(
            parse_rex_event_frame(
                br#"{"type":"session_destroyed","payload":{"session_id":"session-a"}}"#
            ),
            Ok(Some(RexEventSignal::InventoryChanged {
                session_id: "session-a".into()
            }))
        );
        assert_eq!(
            parse_rex_event_frame(br#"{"type":"session_event","payload":{"session_id":"session-a","event":{"type":"client_disconnected","payload":{}}}}"#),
            Ok(None)
        );
        assert!(parse_rex_event_frame(b"not json").is_err());
    }

    #[test]
    fn rex_event_reader_bounds_frames_and_requests_rescan_on_overflow() {
        let (sender, receiver) = mpsc::sync_channel(2);
        let overflowed = Arc::new(AtomicBool::new(false));
        let mut input = vec![b'x'; MAX_REX_EVENT_FRAME_BYTES + 1];
        input.push(b'\n');
        for block in ["b", "c", "d"] {
            input.extend_from_slice(
                format!(
                    "{{\"type\":\"session_event\",\"payload\":{{\"session_id\":\"s\",\"event\":{{\"type\":\"block_closed\",\"payload\":{{\"block_id\":\"{block}\"}}}}}}}}\n"
                )
                .as_bytes(),
            );
        }
        read_rex_events(input.as_slice(), sender, Arc::clone(&overflowed));
        assert!(overflowed.load(Ordering::Acquire));
        assert_eq!(receiver.try_recv(), Ok(RexEventSignal::RescanRequired));
        assert_eq!(
            receiver.try_recv(),
            Ok(RexEventSignal::BlockClosed {
                session_id: "s".into(),
                block_id: "b".into()
            })
        );
    }

    #[test]
    fn rex_events_for_other_sessions_do_not_request_inventory() {
        assert!(!rex_event_requires_inventory(
            &RexEventSignal::BlockClosed {
                session_id: "other-session".into(),
                block_id: "block-a".into(),
            },
            "pinned-session"
        ));
        assert!(rex_event_requires_inventory(
            &RexEventSignal::BlockClosed {
                session_id: "pinned-session".into(),
                block_id: "block-a".into(),
            },
            "pinned-session"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn dropping_event_stream_reaps_its_cli_child() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("rex fake");
        let body = r##"#!/bin/sh
case "$*" in
  *"whoami --json"*) printf '%s\n' '{"endpoint":"unix:///tmp/rex-test.sock","instance_id":"instance-1","host_id":"host-1","rex_version":"1.2.3"}' ;;
  *"api list --json"*) printf '%s\n' '{"methods":{"session.view":{},"session.new_window":{},"session.new_split":{},"session.focus_block":{},"session.zoom_block":{},"block.close":{}}}' ;;
  *"events -s session-a --json"*) exec /bin/sleep 30 ;;
  *) exit 3 ;;
esac
"##;
        std::fs::write(&script, body).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let transport = RexCliTransport::connect(
            &script,
            &[],
            "unix:///tmp/rex-test.sock".into(),
            "instance-1".into(),
            "session-a".into(),
            BTreeMap::<OsString, OsString>::new(),
        )
        .unwrap();
        let stream = transport.subscribe_events().unwrap();
        let pid = stream.child.id();
        drop(stream);
        assert!(
            !crate::process::inspect_process_table()
                .unwrap()
                .iter()
                .any(|process| process.pid == pid)
        );
    }

    #[cfg(unix)]
    #[test]
    fn event_stream_eof_requests_reconnect_and_new_stream_receives_events() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("rex fake");
        let body = r##"#!/bin/sh
case "$*" in
  *"whoami --json"*) printf '%s\n' '{"endpoint":"unix:///tmp/rex-test.sock","instance_id":"instance-1","host_id":"host-1","rex_version":"1.2.3"}' ;;
  *"api list --json"*) printf '%s\n' '{"methods":{"session.view":{},"session.new_window":{},"session.new_split":{},"session.focus_block":{},"session.zoom_block":{},"block.close":{}}}' ;;
  *"events -s session-a --json"*) printf '%s\n' '{"type":"session_event","payload":{"session_id":"session-a","event":{"type":"block_closed","payload":{"block_id":"block-a"}}}}' ;;
  *) exit 3 ;;
esac
"##;
        std::fs::write(&script, body).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let transport = RexCliTransport::connect(
            &script,
            &[],
            "unix:///tmp/rex-test.sock".into(),
            "instance-1".into(),
            "session-a".into(),
            BTreeMap::<OsString, OsString>::new(),
        )
        .unwrap();
        for _ in 0..2 {
            let mut stream = transport.subscribe_events().unwrap();
            let mut received = Vec::new();
            for _ in 0..100 {
                received.extend(stream.drain(4));
                if !stream.is_alive().unwrap() && !received.is_empty() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            assert!(received.contains(&RexEventSignal::BlockClosed {
                session_id: "session-a".into(),
                block_id: "block-a".into(),
            }));
            assert!(!stream.is_alive().unwrap());
        }
    }
}
