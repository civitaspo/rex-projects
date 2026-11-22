//! Harness hook handlers (ADR-0002, ADR-0003). A hook must never break the
//! harness: it prints only hook output JSON to stdout, reports errors on
//! stderr, and always exits 0.

use std::io::Read;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use serde_json::json;

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
    let Some(agent_id) = std::env::var("REX_PROJECTS_AGENT_ID")
        .ok()
        .filter(|id| !id.is_empty())
    else {
        return;
    };
    let launch = std::env::var("REX_PROJECTS_AGENT_LAUNCH").ok();
    let result = read.context("failed to read hook input").and_then(|_| {
        let launch = launch
            .map(|l| {
                l.parse::<i64>()
                    .context("invalid REX_PROJECTS_AGENT_LAUNCH")
            })
            .transpose()?;
        let paths = Paths::resolve(config_dir, state_dir)?;
        handle(&paths, &agent_id, launch, provider, event, &input)
    });
    match result {
        Ok(Some(output)) => println!("{output}"),
        Ok(None) => {}
        Err(err) => eprintln!("rex-projects hook {provider} {event}: {err:#}"),
    }
}

/// Applies one hook `event` from `provider` for `agent_id`, returning what
/// the hook prints for the harness.
pub fn handle(
    paths: &Paths,
    agent_id: &str,
    launch: Option<i64>,
    provider: &str,
    event: &str,
    input: &[u8],
) -> Result<Option<String>> {
    if !matches!(provider, "claude" | "codex") {
        bail!("unknown provider {provider:?}");
    }
    if !matches!(event, "session-start" | "user-prompt-submit" | "stop") {
        bail!("unknown hook event {event:?}");
    }
    let payload: Payload = serde_json::from_slice(input).context("invalid hook input")?;
    let mut store = Store::open(&paths.db_file())?;
    let agent = store
        .agent(agent_id)?
        .with_context(|| format!("agent {agent_id} does not exist"))?;
    if is_stale(launch, &agent) {
        return Ok(None);
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
        return Ok(None);
    }
    if event == "stop" {
        // A Coordinator that asked a human waits for the answer; its messages
        // come with the answer's prompt instead.
        if agent.role == "coordinator"
            && store
                .ticket(&agent.ticket_id)?
                .is_some_and(|t| matches!(t.state, TicketState::Waiting | TicketState::Verifying))
        {
            return Ok(None);
        }
        // Unread messages continue the turn instead of ending it.
        let (messages, remaining) = crate::inbox::take(&mut store, agent_id)?;
        return Ok(crate::inbox::render(&messages, remaining)
            .map(|reason| json!({"decision": "block", "reason": reason}).to_string()));
    }
    // A human typed into the Coordinator's TUI: that answers a waiting Ticket.
    let ticket = store
        .ticket(&agent.ticket_id)?
        .with_context(|| format!("ticket {} does not exist", agent.ticket_id))?;
    // The wake token typed by `serve` is not a human's answer.
    let woken = payload.prompt.as_deref().map(str::trim) == Some(crate::inbox::WAKE_TOKEN);
    if agent.role == "coordinator"
        && ticket.state == TicketState::Waiting
        && ticket.pending_approval.is_none()
        && !woken
    {
        store.append(
            "human",
            Event::TicketAnswered {
                ticket_id: ticket.id,
                answer: payload.prompt.map(|p| truncate(&p)),
                question: ticket.question,
            },
        )?;
    }
    // Unread messages ride along with the human's prompt.
    let (messages, remaining) = crate::inbox::take(&mut store, agent_id)?;
    Ok(crate::inbox::render(&messages, remaining).map(|context| {
        json!({"hookSpecificOutput": {
            "hookEventName": "UserPromptSubmit",
            "additionalContext": context,
        }})
        .to_string()
    }))
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

    fn prompt(paths: &Paths, agent: &str, launch: Option<i64>) -> Result<Option<String>> {
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
                question: Some("Which API?".into()),
            }
        );
    }

    #[test]
    fn typed_prompt_does_not_decide_or_clear_pending_approval() {
        let dir = tempfile::tempdir().unwrap();
        let paths = dispatched(dir.path());
        let mut store = Store::open(&paths.db_file()).unwrap();
        store
            .append(
                "demo-1-coordinator",
                Event::ApprovalRequested {
                    ticket_id: "demo-1".into(),
                    approval_kind: "plan".into(),
                    summary: "Review plan".into(),
                    artifacts: vec![],
                },
            )
            .unwrap();
        prompt(&paths, "demo-1-coordinator", None).unwrap();
        let ticket = Store::open(&paths.db_file())
            .unwrap()
            .ticket("demo-1")
            .unwrap()
            .unwrap();
        assert_eq!(ticket.state, TicketState::Waiting);
        assert_eq!(ticket.pending_approval.unwrap().kind, "plan");
        assert!(
            !Store::open(&paths.db_file())
                .unwrap()
                .ticket_events("demo-1")
                .unwrap()
                .iter()
                .any(|event| matches!(event.event, Event::TicketAnswered { .. }))
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
        assert!(handle(&paths, agent, None, "claude", "pre-tool-use", b"{}").is_err());
        assert!(handle(&paths, agent, None, "claude", "session-start", b"{}").is_err());
        assert!(handle(&paths, agent, None, "claude", "session-start", b"nope").is_err());
    }

    fn send(paths: &Paths, to: &str, body: &str) {
        Store::open(&paths.db_file())
            .unwrap()
            .append(
                "demo-1-helper",
                Event::MessageSent {
                    ticket_id: "demo-1".into(),
                    from: "demo-1-helper".into(),
                    to: to.into(),
                    body: body.into(),
                },
            )
            .unwrap();
    }

    #[test]
    fn stop_continues_the_turn_with_unread_messages() {
        let dir = tempfile::tempdir().unwrap();
        let paths = dispatched(dir.path());
        let input = br#"{"session_id":"s1","hook_event_name":"Stop","stop_hook_active":false}"#;
        let stop = |launch| handle(&paths, "demo-1-coordinator", launch, "codex", "stop", input);
        assert_eq!(stop(None).unwrap(), None);
        send(&paths, "demo-1-coordinator", "Review done: 2 findings.");
        // A superseded process does not take the messages.
        assert_eq!(stop(Some(4)).unwrap(), None);
        let output: serde_json::Value =
            serde_json::from_str(&stop(None).unwrap().unwrap()).unwrap();
        assert_eq!(output["decision"], "block");
        let reason = output["reason"].as_str().unwrap();
        assert!(reason.contains("Review done: 2 findings."), "{reason}");
        assert!(reason.contains("demo-1-helper"), "{reason}");
        assert_eq!(stop(None).unwrap(), None);
    }

    #[test]
    fn a_waiting_coordinator_gets_messages_with_the_answer() {
        let dir = tempfile::tempdir().unwrap();
        let paths = dispatched(dir.path());
        ask(&paths);
        send(&paths, "demo-1-coordinator", "Worker done.");
        let input = br#"{"session_id":"s1","hook_event_name":"Stop","stop_hook_active":false}"#;
        // The turn that asked ends; the message waits for the human.
        let stop = handle(&paths, "demo-1-coordinator", None, "claude", "stop", input).unwrap();
        assert_eq!(stop, None);
        assert_eq!(state(&paths), TicketState::Waiting);
        let output = prompt(&paths, "demo-1-coordinator", None).unwrap().unwrap();
        assert!(output.contains("Worker done."), "{output}");
        assert_eq!(state(&paths), TicketState::Running);
    }

    #[test]
    fn a_prompt_carries_unread_messages() {
        let dir = tempfile::tempdir().unwrap();
        let paths = dispatched(dir.path());
        assert_eq!(prompt(&paths, "demo-1-coordinator", None).unwrap(), None);
        send(&paths, "demo-1-coordinator", "CI is green.");
        let output = prompt(&paths, "demo-1-coordinator", None).unwrap().unwrap();
        let output: serde_json::Value = serde_json::from_str(&output).unwrap();
        let hook = &output["hookSpecificOutput"];
        assert_eq!(hook["hookEventName"], "UserPromptSubmit");
        assert!(
            hook["additionalContext"]
                .as_str()
                .unwrap()
                .contains("CI is green.")
        );
    }

    #[test]
    fn the_wake_token_is_not_an_answer() {
        let dir = tempfile::tempdir().unwrap();
        let paths = dispatched(dir.path());
        ask(&paths);
        let input = serde_json::json!({
            "session_id": "s1",
            "hook_event_name": "UserPromptSubmit",
            "prompt": crate::inbox::WAKE_TOKEN,
        })
        .to_string();
        handle(
            &paths,
            "demo-1-coordinator",
            None,
            "claude",
            "user-prompt-submit",
            input.as_bytes(),
        )
        .unwrap();
        assert_eq!(state(&paths), TicketState::Waiting);
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
