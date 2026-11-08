//! Local terminal dashboard. The UI depends on a narrow host port so it never
//! writes SQLite, injects text into a provider terminal, or interprets a key as
//! an authorization decision without an exact human-request binding.

use std::io::{self, IsTerminal, Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock};

use crossterm::cursor;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{self, ClearType};
use serde::{Deserialize, Serialize};

static SHUTDOWN_REQUESTED: LazyLock<Arc<AtomicBool>> =
    LazyLock::new(|| Arc::new(AtomicBool::new(false)));

use crate::adapters::rex::RexCliTransport;
use crate::domain::ids::{
    Digest, HumanRequestId, ProjectId, TicketId, TicketNamespace, TicketRunId,
};
use crate::human_runtime::{HumanDecisionIntent, HumanRequestLifecycle};
use crate::store::{ConfigStore, dashboard_projection};

/// Concrete local backend used by `rex-projects dashboard`. It performs data
/// access and durable human intents outside the terminal rendering loop.
pub struct RuntimeDashboardBackend {
    state_root: std::path::PathBuf,
    rex_binary: std::path::PathBuf,
    rex_endpoint: Option<String>,
}

impl RuntimeDashboardBackend {
    pub fn new(
        state_root: impl Into<std::path::PathBuf>,
        rex_binary: impl Into<std::path::PathBuf>,
    ) -> Self {
        Self {
            state_root: state_root.into(),
            rex_binary: rex_binary.into(),
            rex_endpoint: None,
        }
    }

    pub fn with_endpoint(
        state_root: impl Into<std::path::PathBuf>,
        rex_binary: impl Into<std::path::PathBuf>,
        rex_endpoint: impl Into<String>,
    ) -> Self {
        Self {
            state_root: state_root.into(),
            rex_binary: rex_binary.into(),
            rex_endpoint: Some(rex_endpoint.into()),
        }
    }

    fn owner_generation(&self) -> Result<u64, String> {
        dashboard_projection::active_owner_generation(&self.state_root)?
            .ok_or_else(|| "machine controller is not running".to_owned())
    }

    fn rex_transport(&self, target: &FocusTarget) -> Result<RexCliTransport, String> {
        let pinned = read_owner_rex_binding(&self.state_root)?;
        if pinned.1 != target.rex_server_identity {
            return Err(
                "focus target belongs to a different Rex instance than the active owner".into(),
            );
        }
        let endpoint = self.rex_endpoint.clone().unwrap_or(pinned.0);
        let environment = std::env::vars_os().collect();
        let search_path = std::env::var_os("PATH")
            .map(|path| std::env::split_paths(&path).collect::<Vec<_>>())
            .unwrap_or_default();
        RexCliTransport::connect(
            &self.rex_binary,
            &search_path,
            endpoint,
            target.rex_server_identity.clone(),
            target.session_id.clone(),
            environment,
        )
        .map_err(|error| error.to_string())
    }

    /// Apply a pin update against a caller's snapshot of the active controller generation.
    pub fn set_pin_for_generation(
        &mut self,
        owner_generation: u64,
        ticket_run: &TicketRunId,
        expected_revision: u64,
        expected_view_id: &Digest,
        pinned: bool,
    ) -> Result<(), String> {
        if self.owner_generation()? != owner_generation {
            return Err("controller generation changed; refresh the dashboard".into());
        }
        dashboard_projection::set_ticket_pin(
            &self.state_root,
            owner_generation,
            ticket_run,
            expected_revision,
            expected_view_id,
            pinned,
        )
    }
}

fn read_owner_rex_binding(state_root: &Path) -> Result<(String, String), String> {
    let path = state_root.join("runtime-owner.json");
    let bytes = std::fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    let owner: serde_json::Value = crate::protocol::parse_unique(&bytes)
        .map_err(|_| "runtime owner projection is invalid".to_owned())?;
    let endpoint = owner
        .get("rex_endpoint")
        .and_then(serde_json::Value::as_str)
        .filter(|value| {
            value.starts_with("unix://")
                || value.starts_with("http://")
                || value.starts_with("https://")
        })
        .ok_or_else(|| "runtime owner has no validated Rex endpoint".to_owned())?;
    let instance = owner
        .get("rex_server_identity")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "runtime owner has no validated Rex instance identity".to_owned())?;
    Ok((endpoint.to_owned(), instance.to_owned()))
}

impl DashboardBackend for RuntimeDashboardBackend {
    fn snapshot(&mut self) -> Result<DashboardSnapshot, String> {
        read_projection(&self.state_root)
    }

    fn focus_and_zoom(&mut self, target: &FocusTarget) -> Result<(), String> {
        let transport = self.rex_transport(target)?;
        transport
            .focus_block(&target.block_id)
            .and_then(|_| transport.zoom_block(&target.block_id, true))
            .map_err(|error| error.to_string())
    }

    fn focus_ticket(&mut self, ticket_run: &TicketRunId) -> Result<(), String> {
        let generation = self.owner_generation()?;
        let snapshot = self.snapshot()?;
        let ticket = snapshot
            .tickets
            .iter()
            .find(|ticket| &ticket.ticket_run_id == ticket_run)
            .ok_or_else(|| "TicketRun is no longer in the dashboard snapshot".to_owned())?;
        let expected_revision = ticket.revision;
        let expected_project = ticket.project_id.clone();
        let expected_namespace = ticket.namespace.clone();
        let expected_ticket_id = ticket.ticket_id.clone();
        let expected_view = ticket.rex_view_id.clone();
        let agent = snapshot
            .agents
            .iter()
            .filter(|agent| agent.ticket_run_id.as_ref() == Some(ticket_run))
            .min_by_key(|agent| if agent.role == "coordinator" { 0 } else { 1 })
            .ok_or_else(|| {
                format!(
                    "no active Agent block for {}/{}",
                    ticket.namespace, ticket.ticket_id
                )
            })?;
        let agent_run_id = agent.agent_run_id.clone();
        let target = self
            .focus_target(&agent.agent_run_id)?
            .ok_or_else(|| "Agent has no active Rex block".to_owned())?;
        let fresh = self.snapshot()?;
        let current_ticket = fresh
            .tickets
            .iter()
            .find(|row| &row.ticket_run_id == ticket_run)
            .ok_or_else(|| "TicketRun disappeared before focus".to_owned())?;
        let current_agent = fresh
            .agents
            .iter()
            .find(|row| {
                row.agent_run_id == agent_run_id && row.ticket_run_id.as_ref() == Some(ticket_run)
            })
            .ok_or_else(|| "Agent no longer belongs to this TicketRun".to_owned())?;
        if self.owner_generation()? != generation
            || current_ticket.revision != expected_revision
            || current_ticket.project_id != expected_project
            || current_ticket.namespace != expected_namespace
            || current_ticket.ticket_id != expected_ticket_id
            || current_ticket.rex_view_id != expected_view
            || current_agent.rex_block_id.as_deref() != Some(target.block_id.as_str())
        {
            return Err(
                "TicketRun, Rex view, or controller generation changed; refresh before focusing"
                    .into(),
            );
        }
        let current_target = self
            .focus_target(&agent_run_id)?
            .ok_or_else(|| "Agent block is no longer active".to_owned())?;
        if current_target != target {
            return Err("Rex focus target changed; refresh before focusing".into());
        }
        self.focus_and_zoom(&target)
    }

    fn set_pin(
        &mut self,
        ticket_run: &TicketRunId,
        expected_revision: u64,
        expected_view_id: &Digest,
        pinned: bool,
    ) -> Result<(), String> {
        dashboard_projection::set_ticket_pin(
            &self.state_root,
            self.owner_generation()?,
            ticket_run,
            expected_revision,
            expected_view_id,
            pinned,
        )
    }

    fn instruct_coordinator(
        &mut self,
        ticket_run_id: &TicketRunId,
        expected_revision: u64,
        message: &str,
    ) -> Result<String, String> {
        let snapshot = self.snapshot()?;
        let ticket = snapshot
            .tickets
            .iter()
            .find(|ticket| &ticket.ticket_run_id == ticket_run_id)
            .ok_or_else(|| "TicketRun is no longer in the dashboard snapshot".to_owned())?;
        if ticket.revision != expected_revision {
            return Err("TicketRun revision changed; refresh the dashboard".into());
        }
        let project_id = ProjectId::parse(ticket.project_id.clone())?;
        let namespace = TicketNamespace::parse(ticket.namespace.clone())?;
        let ticket_id = TicketId::parse(ticket.ticket_id.clone())?;
        let request_id = format!(
            "dashboard-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let mut store = ConfigStore::open_control(&self.state_root)?;
        let receipt = store.enqueue_coordinator_instruction(
            self.owner_generation()?,
            &project_id,
            ticket_run_id,
            &namespace,
            &ticket_id,
            expected_revision,
            &request_id,
            message,
            unix_now(),
        )?;
        Ok(format!(
            "queued Coordinator wake {} and Supervisor notification {} for {}/{} at revision {}{}",
            receipt.wake_input_id,
            receipt.supervisor_wake_input_id,
            namespace,
            ticket_id,
            receipt.revision,
            if receipt.replayed { " (replayed)" } else { "" }
        ))
    }

    fn respond(
        &mut self,
        request_id: &HumanRequestId,
        exact_subject_digest: &str,
        exact_expiry: i64,
        choice: &str,
    ) -> Result<String, String> {
        use crate::human_runtime::HumanDecisionChoice;
        let request = ConfigStore::read_human_request(&self.state_root, request_id)?
            .ok_or_else(|| "human request was removed".to_owned())?;
        if !matches!(
            request.lifecycle,
            HumanRequestLifecycle::Pending | HumanRequestLifecycle::Presented
        ) {
            return Err("human request is no longer awaiting a response".into());
        }
        let digest = request.request.subject.digest()?;
        if digest.as_str() != exact_subject_digest
            || request.request.expires_at_unix as i64 != exact_expiry
        {
            return Err("human request subject or expiry changed; refresh the dashboard".into());
        }
        let selected: HumanDecisionChoice =
            serde_json::from_value(serde_json::Value::String(choice.to_owned()))
                .map_err(|_| "choice is not a valid human decision".to_owned())?;
        if !request.request.choices.contains(&selected) {
            return Err("choice is not offered for this request".into());
        }
        let now = unix_now() as u64;
        let response_id = format!(
            "dashboard-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let receipt = ConfigStore::enqueue_human_decision(
            &self.state_root,
            &HumanDecisionIntent {
                response_id,
                request_id: request_id.clone(),
                expected_subject_digest: digest,
                choice: selected,
                explanation: None,
            },
            now,
        )?;
        Ok(format!(
            "queued for controller validation: {}",
            receipt.response_id
        ))
    }

    fn focus_target(&mut self, agent_run_id: &str) -> Result<Option<FocusTarget>, String> {
        let agent_run_id = crate::domain::ids::AgentRunId::parse(agent_run_id.to_owned())?;
        dashboard_projection::read_focus_target(
            &self.state_root,
            self.owner_generation()?,
            &agent_run_id,
        )
        .map(Some)
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .try_into()
        .unwrap_or(i64::MAX)
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct DashboardSnapshot {
    pub observed_at_unix: i64,
    pub projects: Vec<ProjectRow>,
    pub tickets: Vec<TicketRow>,
    pub agents: Vec<AgentRow>,
    pub waits: Vec<WaitRow>,
    pub human_requests: Vec<HumanInboxRow>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ProjectRow {
    pub project_id: String,
    pub mode: String,
    pub lifecycle: String,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct TicketRow {
    pub ticket_run_id: TicketRunId,
    pub project_id: String,
    pub namespace: String,
    pub ticket_id: String,
    pub phase: String,
    pub activity: String,
    pub external_status: String,
    pub revision: u64,
    /// Unknown when the active host adapter has no v7 view-history observation.
    pub pinned: Option<bool>,
    /// The current Rex ticket view, when the host has registered one.
    pub rex_view_id: Option<crate::domain::ids::Digest>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct AgentRow {
    pub agent_run_id: String,
    pub project_id: String,
    pub ticket_run_id: Option<TicketRunId>,
    pub role: String,
    pub state: String,
    pub rex_session_id: Option<String>,
    pub rex_window_id: Option<String>,
    pub rex_block_id: Option<String>,
    pub rex_view_id: Option<crate::domain::ids::Digest>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct WaitRow {
    pub project_id: String,
    pub ticket_run_id: Option<TicketRunId>,
    pub kind: String,
    pub detail: String,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct HumanInboxRow {
    pub request_id: HumanRequestId,
    pub project_id: String,
    pub question: String,
    pub choices: Vec<String>,
    pub subject_digest: String,
    pub expires_at_unix: i64,
    pub lifecycle: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FocusTarget {
    pub view_id: crate::domain::ids::Digest,
    pub rex_server_identity: String,
    pub session_id: String,
    pub window_id: String,
    pub block_id: String,
}

/// Commands cross this host-owned boundary. Implementations persist the
/// request and let the controller validate and apply it; the TUI has no DB API.
pub trait DashboardBackend {
    fn snapshot(&mut self) -> Result<DashboardSnapshot, String>;
    fn focus_and_zoom(&mut self, target: &FocusTarget) -> Result<(), String>;
    fn focus_ticket(&mut self, ticket_run: &TicketRunId) -> Result<(), String>;
    fn set_pin(
        &mut self,
        ticket_run: &TicketRunId,
        expected_revision: u64,
        expected_view_id: &Digest,
        pinned: bool,
    ) -> Result<(), String>;
    fn instruct_coordinator(
        &mut self,
        ticket_run: &TicketRunId,
        expected_revision: u64,
        message: &str,
    ) -> Result<String, String>;
    fn respond(
        &mut self,
        request_id: &HumanRequestId,
        exact_subject_digest: &str,
        exact_expiry: i64,
        choice: &str,
    ) -> Result<String, String>;
    fn focus_target(&mut self, agent_run_id: &str) -> Result<Option<FocusTarget>, String>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DashboardError {
    pub exit_code: i32,
    pub message: String,
}

impl From<String> for DashboardError {
    fn from(message: String) -> Self {
        Self {
            exit_code: 1,
            message,
        }
    }
}
impl From<&str> for DashboardError {
    fn from(message: &str) -> Self {
        Self::from(message.to_owned())
    }
}

impl DashboardError {
    fn denied() -> Self {
        Self {
            exit_code: 77,
            message: "factory Agent context is read-only".into(),
        }
    }
}

/// Marked factory children may inspect/focus but cannot issue human decisions,
/// pin views, or submit instructions. Return the CLI's documented denial code.
pub fn ensure_human_mutation_allowed() -> Result<(), i32> {
    ensure_human_mutation_allowed_for(
        std::env::var_os("REX_PROJECTS_AGENT").is_some(),
        std::env::var_os("REX_PROJECTS_CONTEXT").is_some(),
    )
}

fn ensure_human_mutation_allowed_for(agent: bool, context: bool) -> Result<(), i32> {
    if agent || context { Err(77) } else { Ok(()) }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Selection {
    Ticket(usize),
    Agent(usize),
    Human(usize),
}

/// Run a compact keyboard dashboard. Non-terminal callers should use
/// `snapshot_json`; they never get raw mode or a blocking event loop.
pub fn run<B: DashboardBackend>(backend: &mut B) -> Result<(), DashboardError> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err("dashboard requires a terminal; use --json for a snapshot".into());
    }
    let _signal_guard = ShutdownSignal::install()?;
    let _terminal_guard =
        TerminalGuard::enter().map_err(|e| format!("cannot initialize dashboard terminal: {e}"))?;
    let mut selected = Selection::Ticket(0);
    let mut status_message: Option<String> = None;
    loop {
        let snapshot = backend.snapshot()?;
        render(&snapshot, selected, status_message.as_deref())?;
        if SHUTDOWN_REQUESTED.load(Ordering::Relaxed) {
            break;
        }
        let has_event = match event::poll(std::time::Duration::from_millis(250)) {
            Ok(available) => available,
            Err(_) if SHUTDOWN_REQUESTED.load(Ordering::Relaxed) => break,
            Err(error) => return Err(error.to_string().into()),
        };
        if !has_event {
            continue;
        }
        match event::read().map_err(|e| e.to_string())? {
            Event::Key(key) if key.kind == KeyEventKind::Press => {
                let row_count = match selected {
                    Selection::Ticket(_) => snapshot.tickets.len(),
                    Selection::Agent(_) => snapshot.agents.len(),
                    Selection::Human(_) => snapshot.human_requests.len(),
                };
                match key.code {
                    KeyCode::Char('c') if key.modifiers.contains(event::KeyModifiers::CONTROL) => {
                        break;
                    }
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Tab => selected = next_selection(selected, &snapshot),
                    KeyCode::Down | KeyCode::Char('j') if row_count > 0 => {
                        selected = move_selection(selected, 1, row_count)
                    }
                    KeyCode::Up | KeyCode::Char('k') if row_count > 0 => {
                        selected = move_selection(selected, -1, row_count)
                    }
                    KeyCode::Enter => match selected {
                        Selection::Agent(i) => {
                            if let Some(agent) = snapshot.agents.get(i) {
                                status_message = Some(
                                    match backend
                                        .focus_target(&agent.agent_run_id)
                                        .and_then(|target| {
                                            target.ok_or_else(|| {
                                                "Agent has no active Rex block".to_owned()
                                            })
                                        })
                                        .and_then(|target| backend.focus_and_zoom(&target))
                                    {
                                        Ok(()) => {
                                            format!("Focused and zoomed {}", agent.agent_run_id)
                                        }
                                        Err(error) => format!("Focus blocked: {error}"),
                                    },
                                );
                            }
                        }
                        Selection::Ticket(i) => {
                            if let Some(ticket) = snapshot.tickets.get(i) {
                                status_message =
                                    Some(match backend.focus_ticket(&ticket.ticket_run_id) {
                                        Ok(()) => format!(
                                            "Focused {}/{}",
                                            ticket.namespace, ticket.ticket_id
                                        ),
                                        Err(error) => format!("Focus blocked: {error}"),
                                    });
                            }
                        }
                        Selection::Human(_) => {}
                    },
                    KeyCode::Char('p') => {
                        ensure_human_mutation_allowed().map_err(|_| DashboardError::denied())?;
                        if let Selection::Ticket(i) = selected
                            && let Some(t) = snapshot.tickets.get(i)
                        {
                            status_message = Some(match t.rex_view_id.as_ref() {
                                None => {
                                    "Pin failed: no active Rex ticket view in this snapshot".into()
                                }
                                Some(view_id) => match backend.set_pin(
                                    &t.ticket_run_id,
                                    t.revision,
                                    view_id,
                                    !t.pinned.unwrap_or(false),
                                ) {
                                    Ok(()) => {
                                        if t.pinned == Some(true) {
                                            "Unpinned ticket view".into()
                                        } else {
                                            "Pinned ticket view".into()
                                        }
                                    }
                                    Err(error) => format!("Pin failed: {error}"),
                                },
                            });
                        }
                    }
                    KeyCode::Char('i') => {
                        ensure_human_mutation_allowed().map_err(|_| DashboardError::denied())?;
                        if let Selection::Ticket(i) = selected
                            && let Some(t) = snapshot.tickets.get(i)
                        {
                            let path = prompt_line("Instruction file path (empty cancels): ")?;
                            if !path.is_empty() {
                                let mut bytes = Vec::new();
                                std::fs::File::open(&path)
                                    .and_then(|file| file.take(65_537).read_to_end(&mut bytes))
                                    .map_err(|e| format!("{path}: {e}"))?;
                                if bytes.len() > 65_536 {
                                    return Err("instruction file exceeds 65536 bytes".into());
                                }
                                let msg = String::from_utf8(bytes)
                                    .map_err(|_| "instruction file must be UTF-8")?;
                                if msg.trim().is_empty() {
                                    return Err("instruction file is empty".into());
                                }
                                status_message = Some(
                                    match backend.instruct_coordinator(
                                        &t.ticket_run_id,
                                        t.revision,
                                        &msg,
                                    ) {
                                        Ok(receipt) => receipt,
                                        Err(error) => format!("Instruction not queued: {error}"),
                                    },
                                );
                            }
                        }
                    }
                    KeyCode::Char('h') => {
                        ensure_human_mutation_allowed().map_err(|_| DashboardError::denied())?;
                        if let Selection::Human(i) = selected
                            && let Some(h) = snapshot.human_requests.get(i)
                        {
                            let choice = prompt_line(&format!(
                                "Choice [{}] (empty cancels): ",
                                h.choices.join("/")
                            ))?;
                            if h.choices.iter().any(|c| c == &choice) {
                                status_message = Some(
                                    match backend.respond(
                                        &h.request_id,
                                        &h.subject_digest,
                                        h.expires_at_unix,
                                        &choice,
                                    ) {
                                        Ok(receipt) => receipt,
                                        Err(error) => format!("Response not queued: {error}"),
                                    },
                                );
                            }
                        }
                    }
                    _ => {}
                }
            }
            Event::Resize(_, _) => {}
            _ => {}
        }
    }
    Ok(())
}

pub fn snapshot_json<B: DashboardBackend>(backend: &mut B) -> Result<String, String> {
    serde_json::to_string_pretty(&backend.snapshot()?).map_err(|e| e.to_string())
}

fn next_selection(current: Selection, s: &DashboardSnapshot) -> Selection {
    match current {
        Selection::Ticket(_) if !s.agents.is_empty() => Selection::Agent(0),
        Selection::Ticket(_) if !s.human_requests.is_empty() => Selection::Human(0),
        Selection::Agent(_) if !s.human_requests.is_empty() => Selection::Human(0),
        _ if !s.tickets.is_empty() => Selection::Ticket(0),
        _ if !s.agents.is_empty() => Selection::Agent(0),
        _ => Selection::Human(0),
    }
}
fn move_selection(s: Selection, delta: isize, len: usize) -> Selection {
    let idx = match s {
        Selection::Ticket(i) | Selection::Agent(i) | Selection::Human(i) => i,
    };
    let next = (idx as isize + delta).rem_euclid(len as isize) as usize;
    match s {
        Selection::Ticket(_) => Selection::Ticket(next),
        Selection::Agent(_) => Selection::Agent(next),
        Selection::Human(_) => Selection::Human(next),
    }
}
fn render(
    snapshot: &DashboardSnapshot,
    selected: Selection,
    status_message: Option<&str>,
) -> Result<(), String> {
    let mut out = io::stdout();
    execute!(out, cursor::MoveTo(0, 0), terminal::Clear(ClearType::All))
        .map_err(|e| e.to_string())?;
    writeln!(
        out,
        "rex-projects dashboard  Projects:{} Tickets:{} Agents:{} Waits:{} Human requests:{}",
        snapshot.projects.len(),
        snapshot.tickets.len(),
        snapshot.agents.len(),
        snapshot.waits.len(),
        snapshot.human_requests.len()
    )
    .map_err(|e| e.to_string())?;
    if let Some(message) = status_message {
        writeln!(out, "{message}\n").map_err(|e| e.to_string())?;
    }
    writeln!(
        out,
        "↑/↓ select · Tab section · Enter focus/zoom · p pin · i instruct · h respond · q quit\n"
    )
    .map_err(|e| e.to_string())?;
    for p in &snapshot.projects {
        writeln!(
            out,
            "PROJECT {} [{}] {}",
            terminal_text(&p.project_id),
            terminal_text(&p.mode),
            terminal_text(&p.lifecycle)
        )
        .map_err(|e| e.to_string())?;
        for (ticket_index, t) in snapshot
            .tickets
            .iter()
            .enumerate()
            .filter(|(_, t)| t.project_id == p.project_id)
        {
            marker(selected == Selection::Ticket(ticket_index), &mut out)?;
            writeln!(
                out,
                "{} {}/{} {} · {} · {}",
                match t.pinned {
                    Some(true) => "📌",
                    Some(false) => "  ",
                    None => "? ",
                },
                terminal_text(&t.namespace),
                terminal_text(&t.ticket_id),
                terminal_text(&t.phase),
                terminal_text(&t.activity),
                terminal_text(&t.external_status)
            )
            .map_err(|e| e.to_string())?;
        }
    }
    writeln!(out, "\nAGENTS").map_err(|e| e.to_string())?;
    for (i, a) in snapshot.agents.iter().enumerate() {
        marker(selected == Selection::Agent(i), &mut out)?;
        writeln!(
            out,
            "{} {} [{}] project={} ticket={}",
            terminal_text(&a.role),
            terminal_text(&a.state),
            terminal_text(&a.agent_run_id),
            terminal_text(&a.project_id),
            a.ticket_run_id
                .as_ref()
                .map(|id| terminal_text(&id.to_string()))
                .unwrap_or_else(|| "—".into())
        )
        .map_err(|e| e.to_string())?;
    }
    writeln!(out, "\nWAITS").map_err(|e| e.to_string())?;
    for w in &snapshot.waits {
        writeln!(
            out,
            "{} {} {}",
            terminal_text(&w.project_id),
            terminal_text(&w.kind),
            terminal_text(&w.detail)
        )
        .map_err(|e| e.to_string())?;
    }
    writeln!(out, "\nHUMAN INBOX").map_err(|e| e.to_string())?;
    for (i, h) in snapshot.human_requests.iter().enumerate() {
        marker(selected == Selection::Human(i), &mut out)?;
        writeln!(
            out,
            "{} {} [{}] lifecycle={} choices={:?} expires={} digest={}",
            terminal_text(&h.project_id),
            terminal_text(&h.request_id.to_string()),
            terminal_text(&h.question),
            terminal_text(&h.lifecycle),
            h.choices
                .iter()
                .map(|choice| terminal_text(choice))
                .collect::<Vec<_>>(),
            h.expires_at_unix,
            terminal_text(&h.subject_digest)
        )
        .map_err(|e| e.to_string())?;
    }
    out.flush().map_err(|e| e.to_string())
}
fn marker<W: Write>(selected: bool, out: &mut W) -> Result<(), String> {
    write!(out, "{} ", if selected { ">" } else { " " }).map_err(|e| e.to_string())
}
fn terminal_text(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_control() {
                format!("\\u{{{:04x}}}", ch as u32)
            } else {
                ch.to_string()
            }
        })
        .collect()
}
fn prompt_line(prompt: &str) -> Result<String, String> {
    terminal::disable_raw_mode().map_err(|e| e.to_string())?;
    let mut out = io::stdout();
    write!(out, "\r\n{prompt}")
        .and_then(|_| out.flush())
        .map_err(|e| e.to_string())?;
    let mut value = String::new();
    io::stdin()
        .read_line(&mut value)
        .map_err(|e| e.to_string())?;
    terminal::enable_raw_mode().map_err(|e| e.to_string())?;
    let value = value.trim_end_matches(['\r', '\n']).to_owned();
    if value.len() > 4096 {
        return Err("input exceeds 4096 bytes".into());
    }
    Ok(value)
}
struct TerminalGuard {
    raw_mode_enabled: bool,
}
impl TerminalGuard {
    fn enter() -> io::Result<Self> {
        Self::enter_with(terminal::enable_raw_mode, || {
            execute!(io::stdout(), terminal::EnterAlternateScreen, cursor::Hide).map(|_| ())
        })
    }
    fn enter_with<E, S>(enable_raw: E, enter_screen: S) -> io::Result<Self>
    where
        E: FnOnce() -> io::Result<()>,
        S: FnOnce() -> io::Result<()>,
    {
        // Construct the guard before changing terminal state so even a
        // partially failed setup gets a Drop restoration attempt.
        let mut guard = Self {
            raw_mode_enabled: false,
        };
        enable_raw()?;
        guard.raw_mode_enabled = true;
        enter_screen()?;
        Ok(guard)
    }
}

struct ShutdownSignal(signal_hook::SigId);
impl ShutdownSignal {
    fn install() -> Result<Self, DashboardError> {
        SHUTDOWN_REQUESTED.store(false, Ordering::Relaxed);
        signal_hook::flag::register(
            signal_hook::consts::SIGTERM,
            Arc::clone(&SHUTDOWN_REQUESTED),
        )
        .map(Self)
        .map_err(|error| format!("cannot register dashboard shutdown signal: {error}").into())
    }
}
impl Drop for ShutdownSignal {
    fn drop(&mut self) {
        signal_hook::low_level::unregister(self.0);
        SHUTDOWN_REQUESTED.store(false, Ordering::Relaxed);
    }
}
impl Drop for TerminalGuard {
    fn drop(&mut self) {
        if self.raw_mode_enabled {
            let _ = execute!(io::stdout(), terminal::LeaveAlternateScreen, cursor::Show);
            let _ = terminal::disable_raw_mode();
            self.raw_mode_enabled = false;
        }
    }
}

/// Portable read-only projection from the existing machine database. It does
/// not acquire the controller lock and opens SQLite read-only (no WAL writes).
pub fn read_projection(state_root: &Path) -> Result<DashboardSnapshot, String> {
    crate::store::dashboard_projection::read_projection(state_root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    #[test]
    fn runtime_backend_queues_coordinator_instruction_through_host_api() {
        use crate::config::{AppliedConfig, SourceFile, SourceKind};
        use crate::domain::ids::{
            Digest, ProjectId, Revision, TicketId, TicketNamespace, TicketRunId,
        };
        use crate::launch::{RexView, RexViewKind};
        use crate::store::{ConfigStore, ExpectedRevision, OwnerMetadata, ProjectRecord};
        use std::collections::BTreeMap;

        let temp = tempfile::tempdir().unwrap();
        let mut store = ConfigStore::open_test(temp.path()).unwrap();
        let config: crate::config::Config =
            toml::from_str(include_str!("../examples/fixture/config.toml")).unwrap();
        let config_digest = Digest::parse("a".repeat(64)).unwrap();
        let applied = store
            .apply_snapshot(
                "factory",
                &AppliedConfig {
                    config,
                    profiles: BTreeMap::new(),
                    source_root: temp.path().display().to_string(),
                    source_files: vec![SourceFile {
                        kind: SourceKind::File,
                        path: temp.path().join("factory.toml").display().to_string(),
                        canonical_path: temp.path().join("factory.toml").display().to_string(),
                        sha256: config_digest.clone(),
                        bytes: 0,
                        contents: String::new(),
                    }],
                    digest: config_digest.clone(),
                },
                ExpectedRevision::Bootstrap,
            )
            .unwrap();
        let project_id = ProjectId::parse("goal_project").unwrap();
        store
            .insert_project(&ProjectRecord {
                id: project_id.clone(),
                config_source: "factory".into(),
                config_revision: applied.revision,
                config_digest,
                mode: "goal".into(),
                goal_revision: 1,
                desired_lifecycle: "running".into(),
                state_revision: Revision(0),
            })
            .unwrap();
        let generation = store
            .start_owner(&OwnerMetadata {
                owner_nonce: "dashboard-test-owner".into(),
                state_root: temp.path().display().to_string(),
                config_source: "factory".into(),
                process_start_identity: crate::cli::observed_process_start_identity(
                    std::process::id(),
                )
                .unwrap(),
                executable_path: std::env::current_exe().unwrap().display().to_string(),
                executable_digest: "b".repeat(64),
                rex_endpoint: None,
                rex_server_identity: None,
                rex_session_id: None,
                rex_block_id: None,
            })
            .unwrap();
        store
            .set_project_lifecycle(generation, &project_id, "running")
            .unwrap();
        let namespace = TicketNamespace::parse("github:org/repo").unwrap();
        let ticket_id = TicketId::parse("PAY-1").unwrap();
        let ticket_run_id = TicketRunId::parse("run-dashboard-test").unwrap();
        store
            .create_ticket_run(
                generation,
                &project_id,
                &namespace,
                &ticket_id,
                &ticket_run_id,
                1,
                "queued",
                "ToDo",
            )
            .unwrap();
        let first_view_id = RexView::derive_id(
            &project_id,
            RexViewKind::Ticket,
            Some(namespace.as_str()),
            Some(ticket_id.as_str()),
            1,
        )
        .unwrap();
        store
            .register_rex_view(
                generation,
                &RexView {
                    view_id: first_view_id.clone(),
                    project_id: project_id.clone(),
                    kind: RexViewKind::Ticket,
                    ticket_namespace: Some(namespace.to_string()),
                    ticket_id: Some(ticket_id.to_string()),
                    view_epoch: 1,
                    rex_server_identity: "fixture-instance".into(),
                    rex_session_id: "fixture-session".into(),
                    rex_window_id: "ticket-window-1".into(),
                },
            )
            .unwrap();
        drop(store);

        let mut backend = RuntimeDashboardBackend::new(temp.path(), "rex");
        let old_snapshot = backend.snapshot().unwrap();
        let old_ticket = old_snapshot
            .tickets
            .iter()
            .find(|ticket| ticket.ticket_run_id == ticket_run_id)
            .unwrap();
        let stale_view_id = old_ticket.rex_view_id.clone().unwrap();
        assert_eq!(stale_view_id, first_view_id);
        let receipt = backend
            .instruct_coordinator(&ticket_run_id, 0, "Please clarify the acceptance criteria.")
            .unwrap();
        assert!(receipt.contains("queued Coordinator wake"));

        let db = rusqlite::Connection::open(temp.path().join("state.sqlite3")).unwrap();
        let (source_type, source_revision, payload_json): (String, u64, String) = db
            .query_row(
                "SELECT source_type,source_revision,payload_json FROM role_wake_inputs WHERE project_id=?1 AND role_session_id=?2 ORDER BY wake_input_id DESC LIMIT 1",
                rusqlite::params![project_id.as_str(), format!("ticket_run:{}:coordinator", ticket_run_id.as_str())],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        let payload: serde_json::Value = serde_json::from_str(&payload_json).unwrap();
        assert_eq!(source_type, "human_instruction");
        assert_eq!(source_revision, 0);
        assert_eq!(payload["body"], "Please clarify the acceptance criteria.");
        assert_eq!(payload["ticket_run_id"], ticket_run_id.as_str());
        assert_eq!(payload["expected_revision"], 0);

        db.execute(
            "UPDATE rex_views SET lifecycle='closed',closed_at_unix=1 WHERE view_id=?1",
            [first_view_id.as_str()],
        )
        .unwrap();
        let second_view_id = RexView::derive_id(
            &project_id,
            RexViewKind::Ticket,
            Some(namespace.as_str()),
            Some(ticket_id.as_str()),
            2,
        )
        .unwrap();
        let mut control = ConfigStore::open_control(temp.path()).unwrap();
        control
            .register_rex_view(
                generation,
                &RexView {
                    view_id: second_view_id.clone(),
                    project_id: project_id.clone(),
                    kind: RexViewKind::Ticket,
                    ticket_namespace: Some(namespace.to_string()),
                    ticket_id: Some(ticket_id.to_string()),
                    view_epoch: 2,
                    rex_server_identity: "fixture-instance".into(),
                    rex_session_id: "fixture-session".into(),
                    rex_window_id: "ticket-window-2".into(),
                },
            )
            .unwrap();
        assert!(
            backend
                .set_pin(&ticket_run_id, 0, &stale_view_id, true)
                .unwrap_err()
                .contains("view changed")
        );
        let new_view_pinned: bool = db
            .query_row(
                "SELECT pinned FROM rex_views WHERE view_id=?1",
                [second_view_id.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            !new_view_pinned,
            "a stale snapshot must not pin the replacement view"
        );
    }

    #[test]
    fn selection_wraps_and_moves_within_section() {
        assert_eq!(
            move_selection(Selection::Ticket(0), -1, 3),
            Selection::Ticket(2)
        );
        assert_eq!(
            next_selection(
                Selection::Ticket(0),
                &DashboardSnapshot {
                    observed_at_unix: 0,
                    projects: vec![],
                    tickets: vec![],
                    agents: vec![agent()],
                    waits: vec![],
                    human_requests: vec![]
                }
            ),
            Selection::Agent(0)
        );
    }
    #[test]
    fn marked_factory_context_cannot_mutate() {
        assert_eq!(ensure_human_mutation_allowed_for(false, false), Ok(()));
        assert_eq!(ensure_human_mutation_allowed_for(true, false), Err(77));
        assert_eq!(ensure_human_mutation_allowed_for(false, true), Err(77));
    }
    #[test]
    fn terminal_projection_escapes_control_sequences() {
        assert_eq!(
            terminal_text("safe\u{1b}[31munsafe"),
            "safe\\u{001b}[31munsafe"
        );
    }
    #[test]
    fn noninteractive_json_snapshot_is_complete() {
        let mut backend = FixtureBackend::default();
        let json: serde_json::Value =
            serde_json::from_str(&snapshot_json(&mut backend).unwrap()).unwrap();
        assert_eq!(json["projects"][0]["project_id"], "demo");
        assert_eq!(json["human_requests"][0]["subject_digest"], "a".repeat(64));
    }

    #[cfg(unix)]
    #[test]
    fn runtime_backend_focuses_and_zooms_the_validated_rex_block() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let rex = dir.path().join("rex-fixture");
        let log = dir.path().join("calls.log");
        let script = format!(
            "#!/bin/sh\ncase \"$*\" in\n  *\"whoami --json\"*) printf '%s\\n' '{{\"endpoint\":\"unix:///tmp/rex-fixture.sock\",\"instance_id\":\"rex-fixture\",\"host_id\":\"host\",\"rex_version\":\"1\"}}' ;;\n  *\"api list --json\"*) printf '%s\\n' '{{\"methods\":{{\"session.view\":{{}},\"session.new_window\":{{}},\"session.new_split\":{{}},\"session.focus_block\":{{}},\"session.zoom_block\":{{}},\"block.close\":{{}}}}}}' ;;\n  *\"api call session.focus_block\"*|*\"api call session.zoom_block\"*) printf '%s\\n' \"$*\" >> '{}' ; printf '%s\\n' '{{}}' ;;\n  *) exit 3 ;;\nesac\n",
            log.display()
        );
        std::fs::write(&rex, script).unwrap();
        std::fs::set_permissions(&rex, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut backend = RuntimeDashboardBackend::with_endpoint(
            dir.path(),
            &rex,
            "unix:///tmp/rex-fixture.sock",
        );
        std::fs::write(
            dir.path().join("runtime-owner.json"),
            serde_json::json!({
                "schema_version": 1,
                "rex_endpoint": "unix:///tmp/rex-fixture.sock",
                "rex_server_identity": "rex-fixture"
            })
            .to_string(),
        )
        .unwrap();
        let target = FocusTarget {
            view_id: crate::domain::ids::Digest::parse("a".repeat(64)).unwrap(),
            rex_server_identity: "rex-fixture".into(),
            session_id: "session-9".into(),
            window_id: "window-9".into(),
            block_id: "block-9".into(),
        };
        backend.focus_and_zoom(&target).unwrap();
        let calls = std::fs::read_to_string(log).unwrap();
        assert!(calls.contains("session.focus_block"));
        assert!(calls.contains("block-9"));
        assert!(calls.contains("session.zoom_block"));
    }
    fn agent() -> AgentRow {
        AgentRow {
            agent_run_id: "run".into(),
            project_id: "p".into(),
            ticket_run_id: None,
            role: "worker".into(),
            state: "running".into(),
            rex_session_id: None,
            rex_window_id: None,
            rex_block_id: None,
            rex_view_id: None,
        }
    }

    #[derive(Default)]
    struct FixtureBackend {
        calls: Vec<String>,
    }
    impl DashboardBackend for FixtureBackend {
        fn snapshot(&mut self) -> Result<DashboardSnapshot, String> {
            Ok(fixture_snapshot())
        }
        fn focus_and_zoom(&mut self, target: &FocusTarget) -> Result<(), String> {
            self.calls.push(format!(
                "focus:{}:{}:{}:{}",
                target.rex_server_identity, target.session_id, target.window_id, target.block_id
            ));
            Ok(())
        }
        fn focus_ticket(&mut self, ticket_run: &TicketRunId) -> Result<(), String> {
            self.calls.push(format!("focus-ticket:{ticket_run}"));
            Ok(())
        }
        fn set_pin(
            &mut self,
            id: &TicketRunId,
            revision: u64,
            view_id: &Digest,
            pinned: bool,
        ) -> Result<(), String> {
            self.calls
                .push(format!("pin:{id}:{revision}:{view_id}:{pinned}"));
            Ok(())
        }
        fn instruct_coordinator(
            &mut self,
            id: &TicketRunId,
            revision: u64,
            msg: &str,
        ) -> Result<String, String> {
            self.calls.push(format!("instruct:{id}:{revision}:{msg}"));
            Ok("queued".into())
        }
        fn respond(
            &mut self,
            id: &HumanRequestId,
            digest: &str,
            expiry: i64,
            choice: &str,
        ) -> Result<String, String> {
            self.calls
                .push(format!("respond:{id}:{digest}:{expiry}:{choice}"));
            Ok("queued".into())
        }
        fn focus_target(&mut self, _id: &str) -> Result<Option<FocusTarget>, String> {
            Ok(Some(FocusTarget {
                view_id: crate::domain::ids::Digest::parse("a".repeat(64)).unwrap(),
                rex_server_identity: "rex-fixture".into(),
                session_id: "session-1".into(),
                window_id: "ticket-window".into(),
                block_id: "worker-block".into(),
            }))
        }
    }
    fn fixture_snapshot() -> DashboardSnapshot {
        DashboardSnapshot {
            observed_at_unix: 100,
            projects: vec![ProjectRow {
                project_id: "demo".into(),
                mode: "goal".into(),
                lifecycle: "running".into(),
            }],
            tickets: vec![TicketRow {
                ticket_run_id: TicketRunId::parse("tr-1").unwrap(),
                project_id: "demo".into(),
                namespace: "fixture".into(),
                ticket_id: "T-1".into(),
                phase: "implementing".into(),
                activity: "worker_running".into(),
                external_status: "in_progress".into(),
                revision: 8,
                pinned: Some(false),
                rex_view_id: Some(crate::domain::ids::Digest::parse("a".repeat(64)).unwrap()),
            }],
            agents: vec![AgentRow {
                agent_run_id: "run-1".into(),
                project_id: "demo".into(),
                ticket_run_id: Some(TicketRunId::parse("tr-1").unwrap()),
                role: "worker".into(),
                state: "running".into(),
                rex_session_id: Some("session-1".into()),
                rex_window_id: Some("ticket-window".into()),
                rex_block_id: Some("worker-block".into()),
                rex_view_id: Some(crate::domain::ids::Digest::parse("a".repeat(64)).unwrap()),
            }],
            waits: vec![WaitRow {
                project_id: "demo".into(),
                ticket_run_id: None,
                kind: "check".into(),
                detail: "pending".into(),
            }],
            human_requests: vec![HumanInboxRow {
                request_id: HumanRequestId::parse("human-1").unwrap(),
                project_id: "demo".into(),
                question: "Approve the exact review bundle?".into(),
                choices: vec!["approve".into(), "reject".into()],
                subject_digest: "a".repeat(64),
                expires_at_unix: 500,
                lifecycle: "pending".into(),
            }],
        }
    }

    /// Child entry point used by the PTY fixture below.
    #[test]
    fn pty_child() {
        let Ok(log_path) = std::env::var("REX_PROJECTS_DASHBOARD_PTY_LOG") else {
            return;
        };
        if std::env::var_os("REX_PROJECTS_DASHBOARD_INIT_FAILURE").is_some() {
            let result = TerminalGuard::enter_with(terminal::enable_raw_mode, || {
                Err(io::Error::other("fixture alternate-screen failure"))
            });
            assert!(result.is_err());
            std::fs::write(log_path, "restored").unwrap();
            return;
        }
        let mut backend = FixtureBackend::default();
        let result = run(&mut backend);
        let payload = serde_json::json!({"exit":result.as_ref().err().map(|e|e.exit_code).unwrap_or(0),"calls":backend.calls});
        std::fs::write(log_path, payload.to_string()).unwrap();
        if let Err(e) = result
            && e.exit_code != 77
        {
            std::process::exit(e.exit_code);
        }
    }

    #[test]
    fn pty_keyboard_focuses_and_queues_exact_human_decision() {
        run_pty_fixture(false, false, false);
    }
    #[test]
    fn pty_marked_agent_is_read_only_and_terminal_is_restored() {
        run_pty_fixture(true, false, false);
    }
    #[test]
    fn pty_sigterm_restores_terminal_before_exit() {
        run_pty_fixture(false, true, false);
    }
    #[test]
    fn pty_ctrl_c_restores_terminal_before_exit() {
        run_pty_fixture(false, false, true);
    }
    #[test]
    fn pty_failed_alternate_screen_setup_restores_raw_mode() {
        let mut master_fd = 0;
        let mut slave_fd = 0;
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master_fd,
                    &mut slave_fd,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            },
            0
        );
        let _master = unsafe { File::from_raw_fd(master_fd) };
        let slave = unsafe { File::from_raw_fd(slave_fd) };
        let observer = slave.try_clone().unwrap();
        let mut baseline: libc::termios = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::tcgetattr(observer.as_raw_fd(), &mut baseline) },
            0
        );
        let log = tempfile::NamedTempFile::new().unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "dashboard::tests::pty_child", "--nocapture"])
            .env("REX_PROJECTS_DASHBOARD_PTY_LOG", log.path())
            .env("REX_PROJECTS_DASHBOARD_INIT_FAILURE", "1")
            .stdin(Stdio::from(slave.try_clone().unwrap()))
            .stdout(Stdio::from(slave.try_clone().unwrap()))
            .stderr(Stdio::from(slave))
            .spawn()
            .unwrap();
        let status = child.wait().unwrap();
        assert!(status.success());
        assert_eq!(std::fs::read_to_string(log.path()).unwrap(), "restored");
        let mut after: libc::termios = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::tcgetattr(observer.as_raw_fd(), &mut after) },
            0
        );
        assert_eq!(
            after.c_lflag & (libc::ICANON | libc::ECHO),
            baseline.c_lflag & (libc::ICANON | libc::ECHO)
        );
    }

    fn run_pty_fixture(marked: bool, send_sigterm: bool, send_ctrl_c: bool) {
        let mut master_fd = 0;
        let mut slave_fd = 0;
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master_fd,
                    &mut slave_fd,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            },
            0
        );
        let mut master = unsafe { File::from_raw_fd(master_fd) };
        let slave = unsafe { File::from_raw_fd(slave_fd) };
        let observer = slave.try_clone().unwrap();
        let mut baseline: libc::termios = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::tcgetattr(observer.as_raw_fd(), &mut baseline) },
            0
        );
        unsafe {
            libc::fcntl(master_fd, libc::F_SETFL, libc::O_NONBLOCK);
        }
        let log = tempfile::NamedTempFile::new().unwrap();
        let instruction = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            instruction.path(),
            "Please stop and re-plan before continuing.\n",
        )
        .unwrap();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", "dashboard::tests::pty_child", "--nocapture"])
            .env("REX_PROJECTS_DASHBOARD_PTY_LOG", log.path())
            .stdin(Stdio::from(slave.try_clone().unwrap()))
            .stdout(Stdio::from(slave.try_clone().unwrap()))
            .stderr(Stdio::from(slave));
        if marked {
            command.env("REX_PROJECTS_AGENT", "1");
        }
        let mut child = command.spawn().unwrap();
        let mut captured = Vec::new();
        wait_for_pty_text(
            &mut master,
            &mut captured,
            b"Human requests",
            Duration::from_secs(5),
            log.path(),
        );
        if send_sigterm {
            assert_eq!(
                unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) },
                0
            );
        } else if send_ctrl_c {
            master.write_all(b"\x03").unwrap();
        }
        // Send individual keys as the app acknowledges each selection change.
        if send_sigterm || send_ctrl_c {
            // SIGTERM is translated into a graceful loop exit by the host;
            // no provider block or decision action is executed.
        } else if marked {
            master.write_all(b"\t").unwrap();
            wait_for_pty_text(
                &mut master,
                &mut captured,
                b"> worker running",
                Duration::from_secs(5),
                log.path(),
            );
            master.write_all(b"\t").unwrap();
            wait_for_pty_text(
                &mut master,
                &mut captured,
                b"> demo human-1",
                Duration::from_secs(5),
                log.path(),
            );
            master.write_all(b"h").unwrap();
        } else {
            master.write_all(b"p").unwrap();
            std::thread::sleep(Duration::from_millis(100));
            master.write_all(b"i").unwrap();
            wait_for_pty_text(
                &mut master,
                &mut captured,
                b"Instruction file path",
                Duration::from_secs(5),
                log.path(),
            );
            master
                .write_all(format!("{}\n", instruction.path().display()).as_bytes())
                .unwrap();
            std::thread::sleep(Duration::from_millis(100));
            master.write_all(b"\r").unwrap();
            std::thread::sleep(Duration::from_millis(100));
            master.write_all(b"\t").unwrap();
            wait_for_pty_text(
                &mut master,
                &mut captured,
                b"> worker running",
                Duration::from_secs(5),
                log.path(),
            );
            master.write_all(b"\r").unwrap();
            std::thread::sleep(Duration::from_millis(100));
            master.write_all(b"\t").unwrap();
            wait_for_pty_text(
                &mut master,
                &mut captured,
                b"> demo human-1",
                Duration::from_secs(5),
                log.path(),
            );
            master.write_all(b"h").unwrap();
            wait_for_pty_text(
                &mut master,
                &mut captured,
                b"Choice [approve/reject]",
                Duration::from_secs(5),
                log.path(),
            );
            master.write_all(b"approve\n").unwrap();
            wait_for_pty_text(
                &mut master,
                &mut captured,
                b"approve",
                Duration::from_secs(5),
                log.path(),
            );
            master.write_all(b"q").unwrap();
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while child.try_wait().unwrap().is_none() && Instant::now() < deadline {
            drain(&mut master, &mut captured);
            std::thread::sleep(Duration::from_millis(10));
        }
        let status = child.wait().unwrap();
        assert!(
            status.success(),
            "PTY child failed: {status}; child log={}; output={}",
            std::fs::read_to_string(log.path()).unwrap_or_default(),
            String::from_utf8_lossy(&captured)
        );
        let out: serde_json::Value =
            serde_json::from_slice(&std::fs::read(log.path()).unwrap()).unwrap();
        if send_sigterm || send_ctrl_c {
            assert_eq!(out["exit"], 0);
            assert!(out["calls"].as_array().unwrap().is_empty());
        } else if marked {
            assert_eq!(out["exit"], 77);
            assert!(out["calls"].as_array().unwrap().is_empty());
        } else {
            let calls = out["calls"].as_array().unwrap();
            assert!(calls.iter().any(|c| c == "focus-ticket:tr-1"));
            assert!(
                calls
                    .iter()
                    .any(|c| c == "focus:rex-fixture:session-1:ticket-window:worker-block")
            );
            assert!(
                calls
                    .iter()
                    .any(|c| c == &format!("pin:tr-1:8:{}:true", "a".repeat(64)))
            );
            assert!(
                calls
                    .iter()
                    .any(|c| c == "instruct:tr-1:8:Please stop and re-plan before continuing.\n")
            );
            assert!(
                calls.iter().any(
                    |c| c == format!("respond:human-1:{}:500:approve", "a".repeat(64)).as_str()
                )
            );
        }
        // TerminalGuard must restore the flags altered by crossterm raw mode.
        let mut after: libc::termios = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::tcgetattr(observer.as_raw_fd(), &mut after) },
            0
        );
        assert_eq!(
            after.c_lflag & (libc::ICANON | libc::ECHO),
            baseline.c_lflag & (libc::ICANON | libc::ECHO)
        );
    }
    fn drain(master: &mut File, captured: &mut Vec<u8>) {
        let mut buf = [0u8; 4096];
        loop {
            match master.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => captured.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
    }
    fn wait_for_pty_text(
        master: &mut File,
        captured: &mut Vec<u8>,
        needle: &[u8],
        timeout: Duration,
        log_path: &std::path::Path,
    ) {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            drain(master, captured);
            if captured.windows(needle.len()).any(|w| w == needle) {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!(
            "timed out waiting for {:?}; child log={}; captured={}",
            String::from_utf8_lossy(needle),
            std::fs::read_to_string(log_path).unwrap_or_default(),
            String::from_utf8_lossy(captured)
        );
    }
}
