//! Drives `rex-projects mcp` and `rex-projects hook` as a harness would.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use rex_projects::domain::{Event, Outcome, Ticket, TicketState};
use rex_projects::store::{NewTicket, Store};
use serde_json::{Value, json};

const AGENT: &str = "demo-1-coordinator";

struct Env {
    _dir: tempfile::TempDir,
    config: PathBuf,
    state: PathBuf,
}

impl Env {
    /// A Project `demo` with Ticket `demo-1` dispatched to its Coordinator.
    fn dispatched() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config");
        let state = dir.path().join("state");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::write(
            config.join("config.toml"),
            "[[projects]]\nid = \"demo\"\nrepo = \"/tmp/demo\"\ngoal = \"Ship it\"\n",
        )
        .unwrap();
        let mut store = self::store(&state);
        store
            .create_ticket(
                "human",
                NewTicket {
                    project_id: "demo".into(),
                    title: "Add a feature".into(),
                    ready: true,
                    ..Default::default()
                },
            )
            .unwrap();
        store
            .append(
                "serve",
                Event::AgentCreated {
                    agent_id: AGENT.into(),
                    ticket_id: "demo-1".into(),
                    project_id: "demo".into(),
                    role: "coordinator".into(),
                    provider: "claude".into(),
                    cwd: "/tmp".into(),
                },
            )
            .unwrap();
        store
            .append(
                "serve",
                Event::TicketDispatched {
                    ticket_id: "demo-1".into(),
                    agent_id: AGENT.into(),
                },
            )
            .unwrap();
        Self {
            _dir: dir,
            config,
            state,
        }
    }

    fn ticket(&self) -> Ticket {
        store(&self.state).ticket("demo-1").unwrap().unwrap()
    }

    fn run(&self, args: &[&str], agent: Option<&str>, stdin: &str) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_rex-projects"));
        command
            .args(args)
            .env("REXP_CONFIG_DIR", &self.config)
            .env("REXP_STATE_DIR", &self.state)
            .env_remove("REXP_AGENT_ID")
            .env_remove("REXP_AGENT_LAUNCH")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(agent) = agent {
            command.env("REXP_AGENT_ID", agent);
        }
        let mut child = command.spawn().expect("failed to run rex-projects");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    }
}

fn store(state: &Path) -> Store {
    Store::open(&state.join("state.db")).unwrap()
}

fn call(id: i64, tool: &str, arguments: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
           "params": {"name": tool, "arguments": arguments}})
}

#[test]
fn mcp_session_reports_asks_and_completes() {
    let env = Env::dispatched();
    let requests = [
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "test", "version": "0"}}}),
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        call(
            2,
            "report",
            json!({"stage": "implement", "summary": "Halfway", "progress": 50}),
        ),
        call(3, "ask", json!({"question": "Which API?"})),
        call(
            4,
            "complete",
            json!({"outcome": "delivered", "summary": "Shipped", "artifacts": ["https://example.com/pr/1"]}),
        ),
    ];
    let input: String = requests.iter().map(|r| format!("{r}\n")).collect();
    let output = env.run(&["mcp"], Some(AGENT), &input);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let replies: Vec<Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(replies.len(), 4);
    assert_eq!(replies[0]["result"]["protocolVersion"], "2025-06-18");
    for reply in &replies[1..] {
        assert_eq!(reply["result"]["isError"], false, "{reply}");
    }

    let ticket = env.ticket();
    assert_eq!(ticket.state, TicketState::Done);
    assert_eq!(ticket.outcome, Some(Outcome::Delivered));
    assert_eq!(ticket.stage.as_deref(), Some("implement"));
    assert_eq!(ticket.progress, Some(50));
    assert_eq!(ticket.summary.as_deref(), Some("Shipped"));
    assert_eq!(ticket.artifacts, ["https://example.com/pr/1"]);
    let events = store(&env.state).events_since(0, 100).unwrap();
    let asked = events
        .iter()
        .find(|e| e.event.kind() == "ticket_asked")
        .unwrap();
    assert_eq!(asked.actor, AGENT);
}

#[test]
fn prompt_hook_answers_a_waiting_ticket() {
    let env = Env::dispatched();
    store(&env.state)
        .append(
            AGENT,
            Event::TicketAsked {
                ticket_id: "demo-1".into(),
                question: "Which API?".into(),
            },
        )
        .unwrap();
    let input = r#"{"session_id":"s1","transcript_path":"/t.jsonl","cwd":"/tmp","hook_event_name":"UserPromptSubmit","prompt":"Use v2"}"#;
    let args = ["hook", "claude", "user-prompt-submit"];

    // Outside an Agent session the hook leaves the database alone.
    let output = env.run(&args, None, input);
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(env.ticket().state, TicketState::Waiting);

    let output = env.run(&args, Some(AGENT), input);
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(env.ticket().state, TicketState::Running);
    assert_eq!(env.ticket().question, None);
}

#[test]
fn hook_errors_never_fail_the_harness() {
    let env = Env::dispatched();
    let output = env.run(
        &["hook", "claude", "session-start"],
        Some("nobody"),
        r#"{"session_id":"s1"}"#,
    );
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("agent nobody does not exist"));
}

#[test]
fn ticket_answer_resumes_a_waiting_ticket() {
    let env = Env::dispatched();
    store(&env.state)
        .append(
            AGENT,
            Event::TicketAsked {
                ticket_id: "demo-1".into(),
                question: "Which API?".into(),
            },
        )
        .unwrap();
    let output = env.run(&["ticket", "answer", "demo-1", "--text", "v2"], None, "");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(env.ticket().state, TicketState::Running);
    let output = env.run(&["ticket", "answer", "demo-1"], None, "");
    assert!(!output.status.success());
}
