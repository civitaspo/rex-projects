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

fn describe(actor: &str, event: &Event) -> Option<String> {
    Some(match event {
        Event::TicketCreated { ready, .. } => {
            format!("created by {actor}{}", if *ready { ", ready" } else { "" })
        }
        Event::TicketReadied { .. } => format!("readied by {actor}"),
        Event::TicketDispatched { agent_id, .. } => format!("dispatched to {agent_id}"),
        Event::AgentLaunched { resume, .. } => if *resume {
            "Coordinator resumed"
        } else {
            "Coordinator launched"
        }
        .to_owned(),
        Event::AgentExited { reason, .. } => format!("Coordinator exited: {reason}"),
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
        } => format!("{tracker} {reference} was closed outside rex-projects as {status}"),
        Event::AgentCreated { .. }
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
