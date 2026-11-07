use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
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

    pub(crate) fn window_label(&self) -> &str {
        &self.window_label
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
        session_id: "rex-test-session".into(),
        window_id: "rex-test-window".into(),
        block_id: "rex-test-block".into(),
        operation_id: "rex-test-operation".into(),
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
            "path_prepend": spec.path_prepend
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
    use super::{
        AgentBlockSpec, CreateDisposition, RexCliTransport, RexIdentity, TicketWindow,
        owned_block_label, ticket_window_label,
    };
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
}
