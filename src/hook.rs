//! Harness hook handlers (ADR-0002). A hook must never break the harness: it
//! prints nothing to stdout, reports errors on stderr, and always exits 0.

use std::io::Read;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::domain::{Event, TicketState};
use crate::mcp::is_stale;
use crate::paths::Paths;
use crate::store::Store;

/// The longest answer recorded from a human prompt, in characters.
const MAX_ANSWER_CHARS: usize = 2000;

/// The fields rex-projects reads from Claude Code and Codex hook input.
#[derive(Debug, Default, Deserialize)]
struct Payload {
    session_id: Option<String>,
    prompt: Option<String>,
}

/// Runs a hook from the CLI. Does nothing outside an Agent session.
pub fn main(config_dir: Option<PathBuf>, state_dir: Option<PathBuf>, provider: &str, event: &str) {
    // Drain stdin so the harness never sees a broken pipe.
    let mut input = Vec::new();
    let read = std::io::stdin().read_to_end(&mut input);
    let Some(agent_id) = std::env::var("REXP_AGENT_ID")
        .ok()
        .filter(|id| !id.is_empty())
    else {
        return;
    };
    let launch = std::env::var("REXP_AGENT_LAUNCH").ok();
    let result = read.context("failed to read hook input").and_then(|_| {
        let launch = launch
            .map(|l| l.parse::<i64>().context("invalid REXP_AGENT_LAUNCH"))
            .transpose()?;
        let paths = Paths::resolve(config_dir, state_dir)?;
        handle(&paths, &agent_id, launch, provider, event, &input)
    });
    if let Err(err) = result {
        eprintln!("rex-projects hook {provider} {event}: {err:#}");
    }
}

/// Applies one hook `event` from `provider` for `agent_id`.
pub fn handle(
    paths: &Paths,
    agent_id: &str,
    launch: Option<i64>,
    provider: &str,
    event: &str,
    input: &[u8],
) -> Result<()> {
    if !matches!(provider, "claude" | "codex") {
        bail!("unknown provider {provider:?}");
    }
    if !matches!(event, "session-start" | "user-prompt-submit") {
        bail!("unknown hook event {event:?}");
    }
    let payload: Payload = serde_json::from_slice(input).context("invalid hook input")?;
    let mut store = Store::open(&paths.db_file())?;
    let agent = store
        .agent(agent_id)?
        .with_context(|| format!("agent {agent_id} does not exist"))?;
    if is_stale(launch, &agent) {
        return Ok(());
    }
    if event == "session-start" {
        let session_id = payload
            .session_id
            .filter(|id| !id.is_empty())
            .context("hook input has no session_id")?;
        if agent.harness_session_id.as_deref() != Some(session_id.as_str()) {
            store.append(
                agent_id,
                Event::AgentSessionBound {
                    agent_id: agent_id.to_owned(),
                    harness_session_id: session_id,
                },
            )?;
        }
        return Ok(());
    }
    // A human typed into the Coordinator's TUI: that answers a waiting Ticket.
    if agent.role != "coordinator" {
        return Ok(());
    }
    let ticket = store
        .ticket(&agent.ticket_id)?
        .with_context(|| format!("ticket {} does not exist", agent.ticket_id))?;
    if ticket.state == TicketState::Waiting {
        store.append(
            "human",
            Event::TicketAnswered {
                ticket_id: ticket.id,
                answer: payload.prompt.map(|p| truncate(&p)),
            },
        )?;
    }
    Ok(())
}

fn truncate(text: &str) -> String {
    match text.char_indices().nth(MAX_ANSWER_CHARS) {
        Some((end, _)) => format!("{}…", &text[..end]),
        None => text.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::tests::dispatched;

    fn ask(paths: &Paths) {
        Store::open(&paths.db_file())
            .unwrap()
            .append(
                "demo-1-coordinator",
                Event::TicketAsked {
                    ticket_id: "demo-1".into(),
                    question: "Which API?".into(),
                },
            )
            .unwrap();
    }

    fn state(paths: &Paths) -> TicketState {
        let store = Store::open(&paths.db_file()).unwrap();
        store.ticket("demo-1").unwrap().unwrap().state
    }

    fn prompt(paths: &Paths, agent: &str, launch: Option<i64>) -> Result<()> {
        let input =
            br#"{"session_id":"s1","hook_event_name":"UserPromptSubmit","prompt":"Use v2"}"#;
        handle(paths, agent, launch, "claude", "user-prompt-submit", input)
    }

    #[test]
    fn binds_the_session_once() {
        let dir = tempfile::tempdir().unwrap();
        let paths = dispatched(dir.path());
        let input = br#"{"session_id":"s1","transcript_path":"/t.jsonl","hook_event_name":"SessionStart","source":"startup"}"#;
        for _ in 0..2 {
            handle(
                &paths,
                "demo-1-coordinator",
                None,
                "claude",
                "session-start",
                input,
            )
            .unwrap();
        }
        let store = Store::open(&paths.db_file()).unwrap();
        let agent = store.agent("demo-1-coordinator").unwrap().unwrap();
        assert_eq!(agent.harness_session_id.as_deref(), Some("s1"));
        let bound = store
            .events_since(0, 100)
            .unwrap()
            .into_iter()
            .filter(|e| e.event.kind() == "agent_session_bound")
            .count();
        assert_eq!(bound, 1);
    }

    #[test]
    fn a_prompt_answers_a_waiting_ticket() {
        let dir = tempfile::tempdir().unwrap();
        let paths = dispatched(dir.path());
        prompt(&paths, "demo-1-coordinator", None).unwrap();
        assert_eq!(state(&paths), TicketState::Running);

        ask(&paths);
        prompt(&paths, "demo-1-helper", None).unwrap();
        assert_eq!(state(&paths), TicketState::Waiting);
        prompt(&paths, "demo-1-coordinator", None).unwrap();
        assert_eq!(state(&paths), TicketState::Running);
        let events = Store::open(&paths.db_file())
            .unwrap()
            .events_since(0, 100)
            .unwrap();
        let last = events.last().unwrap();
        assert_eq!(last.actor, "human");
        assert_eq!(
            last.event,
            Event::TicketAnswered {
                ticket_id: "demo-1".into(),
                answer: Some("Use v2".into()),
            }
        );
    }

    #[test]
    fn stale_launches_do_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let paths = dispatched(dir.path());
        ask(&paths);
        prompt(&paths, "demo-1-coordinator", Some(3)).unwrap();
        assert_eq!(state(&paths), TicketState::Waiting);
        prompt(&paths, "demo-1-coordinator", Some(0)).unwrap();
        assert_eq!(state(&paths), TicketState::Running);
    }

    #[test]
    fn rejects_unknown_input() {
        let dir = tempfile::tempdir().unwrap();
        let paths = dispatched(dir.path());
        let agent = "demo-1-coordinator";
        assert!(handle(&paths, agent, None, "gemini", "session-start", b"{}").is_err());
        assert!(handle(&paths, agent, None, "claude", "stop", b"{}").is_err());
        assert!(handle(&paths, agent, None, "claude", "session-start", b"{}").is_err());
        assert!(handle(&paths, agent, None, "claude", "session-start", b"nope").is_err());
    }

    #[test]
    fn truncates_long_answers() {
        assert_eq!(truncate("short"), "short");
        let long = "あ".repeat(MAX_ANSWER_CHARS + 5);
        let cut = truncate(&long);
        assert_eq!(cut.chars().count(), MAX_ANSWER_CHARS + 1);
        assert!(cut.ends_with('…'));
    }
}
