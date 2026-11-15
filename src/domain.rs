use std::fmt;
use std::str::FromStr;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

/// The eight states Rust tracks for a Ticket (ADR-0004). Phases inside
/// `Running` are free-form Stages reported by the Coordinator.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketState {
    Backlog,
    Ready,
    Running,
    Waiting,
    Verifying,
    Done,
    Abandoned,
    Failed,
}

impl TicketState {
    pub const ALL: [TicketState; 8] = [
        Self::Backlog,
        Self::Ready,
        Self::Running,
        Self::Waiting,
        Self::Verifying,
        Self::Done,
        Self::Abandoned,
        Self::Failed,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Backlog => "backlog",
            Self::Ready => "ready",
            Self::Running => "running",
            Self::Waiting => "waiting",
            Self::Verifying => "verifying",
            Self::Done => "done",
            Self::Abandoned => "abandoned",
            Self::Failed => "failed",
        }
    }

    /// Whether the Ticket has ended and will not run again.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Done | Self::Abandoned | Self::Failed)
    }

    /// Whether a Coordinator is assigned and holds capacity.
    pub fn is_active(self) -> bool {
        matches!(self, Self::Running | Self::Waiting | Self::Verifying)
    }
}

impl fmt::Display for TicketState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for TicketState {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match Self::ALL.iter().find(|state| state.as_str() == s) {
            Some(state) => Ok(*state),
            None => bail!("unknown ticket state {s:?}"),
        }
    }
}

/// How a Coordinator says a Ticket ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Delivered,
    Abandoned,
    Failed,
}

/// A link from a Ticket to an item in an external tracker.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalRef {
    pub tracker: String,
    #[serde(rename = "ref")]
    pub reference: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// Every change to rex-projects state is one of these events (ADR-0008).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Event {
    TicketCreated {
        ticket_id: String,
        project_id: String,
        number: i64,
        title: String,
        body: String,
        priority: i64,
        playbook: Option<String>,
        blocked_by: Vec<String>,
        external_refs: Vec<ExternalRef>,
        ready: bool,
    },
    TicketReadied {
        ticket_id: String,
    },
    TicketDispatched {
        ticket_id: String,
        agent_id: String,
    },
    TicketReported {
        ticket_id: String,
        stage: Option<String>,
        summary: Option<String>,
        progress: Option<u8>,
        next: Option<String>,
        #[serde(default)]
        artifacts: Vec<String>,
    },
    TicketAsked {
        ticket_id: String,
        question: String,
    },
    TicketAnswered {
        ticket_id: String,
        answer: Option<String>,
    },
    TicketCompleted {
        ticket_id: String,
        outcome: Outcome,
        summary: String,
        #[serde(default)]
        artifacts: Vec<String>,
    },
    TicketCancelled {
        ticket_id: String,
        reason: String,
    },
    TicketFailed {
        ticket_id: String,
        reason: String,
    },
    /// A tracker reports that an external ref of an active Ticket was closed
    /// outside rex-projects. It informs the UI and the Coordinator only.
    ExternalChanged {
        ticket_id: String,
        tracker: String,
        reference: String,
        status: String,
    },
    AgentCreated {
        agent_id: String,
        ticket_id: String,
        project_id: String,
        role: String,
        provider: String,
        cwd: String,
    },
    AgentLaunched {
        agent_id: String,
        rex_session_id: String,
        rex_window_id: String,
        rex_block_id: String,
        resume: bool,
    },
    AgentSessionBound {
        agent_id: String,
        harness_session_id: String,
    },
    AgentActivity {
        agent_id: String,
        activity: String,
        message: Option<String>,
    },
    AgentExited {
        agent_id: String,
        reason: String,
    },
}

impl Event {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::TicketCreated { .. } => "ticket_created",
            Self::TicketReadied { .. } => "ticket_readied",
            Self::TicketDispatched { .. } => "ticket_dispatched",
            Self::TicketReported { .. } => "ticket_reported",
            Self::TicketAsked { .. } => "ticket_asked",
            Self::TicketAnswered { .. } => "ticket_answered",
            Self::TicketCompleted { .. } => "ticket_completed",
            Self::TicketCancelled { .. } => "ticket_cancelled",
            Self::TicketFailed { .. } => "ticket_failed",
            Self::ExternalChanged { .. } => "external_changed",
            Self::AgentCreated { .. } => "agent_created",
            Self::AgentLaunched { .. } => "agent_launched",
            Self::AgentSessionBound { .. } => "agent_session_bound",
            Self::AgentActivity { .. } => "agent_activity",
            Self::AgentExited { .. } => "agent_exited",
        }
    }

    pub fn ticket_id(&self) -> Option<&str> {
        match self {
            Self::TicketCreated { ticket_id, .. }
            | Self::TicketReadied { ticket_id }
            | Self::TicketDispatched { ticket_id, .. }
            | Self::TicketReported { ticket_id, .. }
            | Self::TicketAsked { ticket_id, .. }
            | Self::TicketAnswered { ticket_id, .. }
            | Self::TicketCompleted { ticket_id, .. }
            | Self::TicketCancelled { ticket_id, .. }
            | Self::TicketFailed { ticket_id, .. }
            | Self::ExternalChanged { ticket_id, .. }
            | Self::AgentCreated { ticket_id, .. } => Some(ticket_id),
            _ => None,
        }
    }

    pub fn agent_id(&self) -> Option<&str> {
        match self {
            Self::TicketDispatched { agent_id, .. }
            | Self::AgentCreated { agent_id, .. }
            | Self::AgentLaunched { agent_id, .. }
            | Self::AgentSessionBound { agent_id, .. }
            | Self::AgentActivity { agent_id, .. }
            | Self::AgentExited { agent_id, .. } => Some(agent_id),
            _ => None,
        }
    }
}

/// The current view of a Ticket, projected from events.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Ticket {
    pub id: String,
    pub project_id: String,
    pub number: i64,
    pub title: String,
    pub body: String,
    pub state: TicketState,
    pub stage: Option<String>,
    pub summary: Option<String>,
    pub progress: Option<u8>,
    pub next: Option<String>,
    pub question: Option<String>,
    pub priority: i64,
    pub playbook: Option<String>,
    pub blocked_by: Vec<String>,
    pub external_refs: Vec<ExternalRef>,
    pub artifacts: Vec<String>,
    pub outcome: Option<Outcome>,
    pub coordinator_id: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// The current view of an Agent, projected from events.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Agent {
    pub id: String,
    pub ticket_id: String,
    pub project_id: String,
    pub role: String,
    pub provider: String,
    pub cwd: String,
    /// `created`, `running`, or `exited`.
    pub state: String,
    pub harness_session_id: Option<String>,
    pub rex_session_id: Option<String>,
    pub rex_window_id: Option<String>,
    pub rex_block_id: Option<String>,
    pub launches: i64,
    pub activity: Option<String>,
    pub activity_message: Option<String>,
    pub exit_reason: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Builds the id of a Ticket from its Project and number, such as `demo-12`.
pub fn ticket_id(project_id: &str, number: i64) -> String {
    format!("{project_id}-{number}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn states_round_trip_through_strings() {
        for state in TicketState::ALL {
            assert_eq!(state.as_str().parse::<TicketState>().unwrap(), state);
        }
        assert!("nope".parse::<TicketState>().is_err());
    }

    #[test]
    fn events_serialize_with_kind_tag() {
        let event = Event::TicketReadied {
            ticket_id: "demo-1".into(),
        };
        let value = serde_json::to_value(&event).unwrap();
        assert_eq!(value["kind"], "ticket_readied");
        assert_eq!(event.kind(), "ticket_readied");
        let back: Event = serde_json::from_value(value).unwrap();
        assert_eq!(back, event);
    }
}
