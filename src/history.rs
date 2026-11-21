//! A Ticket's history as one line per meaningful event, for `ticket show`
//! and the dashboard. Activity flips and bookkeeping events are left out.

use chrono::{DateTime, Local};

use crate::domain::Event;
use crate::store::StoredEvent;

/// One entry of a Ticket's history.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Local time, as `MM-DD HH:MM`.
    pub at: String,
    pub text: String,
}

/// The history entries of `events`, oldest first.
pub fn entries(events: &[StoredEvent]) -> Vec<Entry> {
    events
        .iter()
        .filter_map(|e| {
            Some(Entry {
                at: local_time(&e.at),
                text: describe(&e.actor, &e.event)?,
            })
        })
        .collect()
}

fn local_time(at: &str) -> String {
    DateTime::parse_from_rfc3339(at)
        .map(|t| t.with_timezone(&Local).format("%m-%d %H:%M").to_string())
        .unwrap_or_else(|_| at.to_owned())
}

/// How history names an Agent: its Ticket has one Coordinator, so that one
/// goes by its role.
fn who(agent_id: &str) -> &str {
    if agent_id.ends_with("-coordinator") {
        "Coordinator"
    } else {
        agent_id
    }
}

fn describe(actor: &str, event: &Event) -> Option<String> {
    Some(match event {
        Event::TicketCreated { ready, .. } => {
            format!("created by {actor}{}", if *ready { ", ready" } else { "" })
        }
        Event::TicketReadied { .. } => format!("readied by {actor}"),
        Event::TicketDispatched { agent_id, .. } => format!("dispatched to {agent_id}"),
        Event::TicketPrepared {
            base_commit,
            playbook,
            ..
        } => match playbook {
            Some(playbook) => format!(
                "prepared {} ({}) at {base_commit}",
                playbook.name,
                playbook.sha256.chars().take(12).collect::<String>()
            ),
            None => format!("prepared at {base_commit}"),
        },
        Event::AgentLaunched {
            agent_id, resume, ..
        } => {
            let verb = if *resume { "resumed" } else { "launched" };
            format!("{} {verb}", who(agent_id))
        }
        Event::AgentExited { agent_id, reason } => {
            format!("{} exited: {reason}", who(agent_id))
        }
        Event::AgentFinished { agent_id, reason } => format!("{agent_id} finished: {reason}"),
        Event::AgentCreated {
            agent_id,
            role,
            provider,
            ..
        } if role != "coordinator" => format!("{actor} spawned {agent_id} ({provider})"),
        Event::TicketReported {
            stage,
            summary,
            progress,
            next,
            artifacts,
            ..
        } => {
            let mut parts = Vec::new();
            if let Some(stage) = stage {
                parts.push(format!("[{stage}]"));
            }
            if let Some(progress) = progress {
                parts.push(format!("{progress}%"));
            }
            if let Some(summary) = summary {
                parts.push(summary.clone());
            }
            if let Some(next) = next {
                parts.push(format!("next: {next}"));
            }
            for artifact in artifacts {
                parts.push(format!("artifact: {artifact}"));
            }
            if parts.is_empty() {
                return None;
            }
            format!("report {}", parts.join("  "))
        }
        Event::TicketAsked { question, .. } => format!("asked: {question}"),
        Event::TicketAnswered { answer, .. } => match answer {
            Some(answer) => format!("answered by {actor}: {answer}"),
            None => format!("answered by {actor}"),
        },
        Event::TicketCompleted {
            outcome,
            summary,
            artifacts,
            ..
        } => {
            let mut text = format!("{outcome}: {summary}");
            for artifact in artifacts {
                text.push_str(&format!("  artifact: {artifact}"));
            }
            text
        }
        Event::TicketCancelled { reason, .. } => format!("cancelled by {actor}: {reason}"),
        Event::TicketFailed { reason, .. } => format!("failed: {reason}"),
        Event::ExternalChanged {
            tracker,
            reference,
            status,
            ..
        } => {
            let verb = if crate::domain::is_closed_status(status) {
                "closed"
            } else {
                "reopened"
            };
            format!("{tracker} {reference} was {verb} outside rex-projects as {status}")
        }
        Event::MessageSent { from, to, body, .. } => {
            let first = body.lines().next().unwrap_or_default();
            let more = if body.lines().nth(1).is_some() {
                " …"
            } else {
                ""
            };
            format!("message {from} -> {to}: {first}{more}")
        }
        Event::AgentCreated { .. }
        | Event::MessagesRead { .. }
        | Event::AgentSessionBound { .. }
        | Event::AgentActivity { .. } => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Outcome;

    fn stored(actor: &str, event: Event) -> StoredEvent {
        StoredEvent {
            seq: 1,
            at: "2026-11-17T14:10:40Z".into(),
            actor: actor.into(),
            project_id: Some("demo".into()),
            ticket_id: Some("demo-1".into()),
            agent_id: None,
            event,
        }
    }

    #[test]
    fn describes_closes_and_reopens() {
        let change = |status: &str| {
            stored(
                "tracker",
                Event::ExternalChanged {
                    ticket_id: "demo-1".into(),
                    tracker: "acme".into(),
                    reference: "A-1".into(),
                    status: status.into(),
                },
            )
        };
        let texts: Vec<String> = entries(&[change("done"), change("open")])
            .into_iter()
            .map(|e| e.text)
            .collect();
        assert_eq!(
            texts,
            [
                "acme A-1 was closed outside rex-projects as done",
                "acme A-1 was reopened outside rex-projects as open",
            ]
        );
    }

    #[test]
    fn describes_reports_questions_and_the_ending() {
        let events = [
            stored(
                "demo-1-coordinator",
                Event::TicketReported {
                    ticket_id: "demo-1".into(),
                    stage: Some("review".into()),
                    summary: Some("PR opened".into()),
                    progress: Some(80),
                    next: Some("Wait for CI".into()),
                    artifacts: vec!["https://example.com/pr/1".into()],
                },
            ),
            stored(
                "demo-1-coordinator",
                Event::AgentActivity {
                    agent_id: "demo-1-coordinator".into(),
                    activity: "working".into(),
                    message: None,
                },
            ),
            stored(
                "demo-1-coordinator",
                Event::TicketAsked {
                    ticket_id: "demo-1".into(),
                    question: "Which API?".into(),
                },
            ),
            stored(
                "human",
                Event::TicketAnswered {
                    ticket_id: "demo-1".into(),
                    answer: Some("v2".into()),
                    question: None,
                },
            ),
            stored(
                "demo-1-coordinator",
                Event::TicketCompleted {
                    ticket_id: "demo-1".into(),
                    outcome: Outcome::Delivered,
                    summary: "Merged".into(),
                    artifacts: Vec::new(),
                },
            ),
        ];
        let texts: Vec<String> = entries(&events).into_iter().map(|e| e.text).collect();
        assert_eq!(
            texts,
            [
                "report [review]  80%  PR opened  next: Wait for CI  artifact: https://example.com/pr/1",
                "asked: Which API?",
                "answered by human: v2",
                "delivered: Merged",
            ]
        );
    }
}
