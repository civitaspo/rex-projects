//! The Agent-facing MCP server: newline-delimited JSON-RPC 2.0 over stdio.
//! A Coordinator reports on its Ticket through these tools (ADR-0002).

use std::io::{BufRead, Write};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::config::Config;
use crate::domain::{Agent, Event, Outcome, Ticket};
use crate::paths::Paths;
use crate::store::Store;

/// Handshake-based MCP revisions this server speaks.
const SUPPORTED_VERSIONS: [&str; 4] = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];
const FALLBACK_VERSION: &str = "2025-06-18";

const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;

const WAIT_INSTRUCTION: &str = "Your question is recorded and the Ticket is waiting. Stop working \
     now and wait for the human's reply in this conversation.";

type RpcError = (i64, String);

/// Serves one Agent, identified by `REXP_AGENT_ID`. The store is reopened on
/// every call so that changes made by other processes are seen.
pub struct Server {
    paths: Paths,
    agent_id: String,
    /// The Agent's `launches` count when this session started, if known.
    launch: Option<i64>,
}

impl Server {
    pub fn new(paths: Paths, agent_id: String, launch: Option<i64>) -> Self {
        Self {
            paths,
            agent_id,
            launch,
        }
    }

    /// Answers each request line on `input` with one line on `output` until
    /// the input closes.
    pub fn serve(&self, input: impl BufRead, mut output: impl Write) -> Result<()> {
        for line in input.lines() {
            let line = line.context("failed to read from stdin")?;
            if line.trim().is_empty() {
                continue;
            }
            if let Some(reply) = self.handle_line(&line) {
                serde_json::to_writer(&mut output, &reply)?;
                output.write_all(b"\n")?;
                output.flush()?;
            }
        }
        Ok(())
    }

    fn handle_line(&self, line: &str) -> Option<Value> {
        let message: Value = match serde_json::from_str(line) {
            Ok(message) => message,
            Err(err) => return Some(error_reply(Value::Null, PARSE_ERROR, format!("{err}"))),
        };
        let id = message.get("id").cloned();
        let Some(method) = message.get("method").and_then(Value::as_str) else {
            // A response to a request we never sent needs no reply.
            if message.get("result").is_some() || message.get("error").is_some() {
                return None;
            }
            return Some(error_reply(
                id.unwrap_or(Value::Null),
                INVALID_REQUEST,
                "missing method".into(),
            ));
        };
        // Notifications, including `notifications/initialized`, get no reply.
        let id = id?;
        let params = message.get("params").cloned().unwrap_or(Value::Null);
        Some(match self.dispatch(method, &params) {
            Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
            Err((code, message)) => error_reply(id, code, message),
        })
    }

    fn dispatch(&self, method: &str, params: &Value) -> Result<Value, RpcError> {
        match method {
            "initialize" => {
                let requested = params.get("protocolVersion").and_then(Value::as_str);
                let version = requested
                    .filter(|v| SUPPORTED_VERSIONS.contains(v))
                    .unwrap_or(FALLBACK_VERSION);
                Ok(json!({
                    "protocolVersion": version,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "rex-projects", "version": env!("CARGO_PKG_VERSION")},
                }))
            }
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({"tools": tools()})),
            "tools/call" => {
                let name = params
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or((INVALID_PARAMS, "tools/call requires a tool name".to_owned()))?;
                let args = params.get("arguments").cloned().unwrap_or(json!({}));
                let result = match name {
                    "ticket_get" => self.ticket_get(),
                    "report" => self.report(args),
                    "ask" => self.ask(args),
                    "complete" => self.complete(args),
                    _ => return Err((INVALID_PARAMS, format!("unknown tool {name:?}"))),
                };
                Ok(match result {
                    Ok(value) => tool_result(serde_json::to_string_pretty(&value).unwrap(), false),
                    Err(err) => tool_result(format!("{err:#}"), true),
                })
            }
            _ => Err((METHOD_NOT_FOUND, format!("method {method:?} not found"))),
        }
    }

    fn context(&self) -> Result<(Store, Agent, Ticket)> {
        let store = Store::open(&self.paths.db_file())?;
        let agent = store
            .agent(&self.agent_id)?
            .with_context(|| format!("agent {} does not exist", self.agent_id))?;
        let ticket = store
            .ticket(&agent.ticket_id)?
            .with_context(|| format!("ticket {} does not exist", agent.ticket_id))?;
        Ok((store, agent, ticket))
    }

    /// Like `context`, but refuses when this session is not the Agent's
    /// current launch, so a stale process cannot change state.
    fn write_context(&self) -> Result<(Store, Agent, Ticket)> {
        let context = self.context()?;
        if is_stale(self.launch, &context.1) {
            bail!("this session was superseded by a newer launch of the Agent; stop working");
        }
        Ok(context)
    }

    fn ticket_get(&self) -> Result<Value> {
        let (store, agent, ticket) = self.context()?;
        let goal = Config::load(&self.paths.config_file())
            .ok()
            .and_then(|config| config.project(&ticket.project_id).ok()?.goal.clone());
        let mut blocked_by = Vec::new();
        for blocker in &ticket.blocked_by {
            let state = store.ticket(blocker)?.map(|t| t.state.to_string());
            blocked_by.push(json!({"id": blocker, "state": state}));
        }
        Ok(json!({
            "project": {"id": ticket.project_id, "goal": goal},
            "agent": {"id": agent.id, "role": agent.role},
            "ticket": {
                "id": ticket.id,
                "title": ticket.title,
                "brief": ticket.body,
                "state": ticket.state,
                "stage": ticket.stage,
                "summary": ticket.summary,
                "progress": ticket.progress,
                "next": ticket.next,
                "question": ticket.question,
                "blocked_by": blocked_by,
                "external_refs": ticket.external_refs,
                "artifacts": ticket.artifacts,
            },
        }))
    }

    fn report(&self, args: Value) -> Result<Value> {
        #[derive(Deserialize)]
        struct Args {
            stage: Option<String>,
            summary: Option<String>,
            progress: Option<u8>,
            next: Option<String>,
            #[serde(default)]
            artifacts: Vec<String>,
        }
        let args: Args = parse_args(args)?;
        if args.progress.is_some_and(|p| p > 100) {
            bail!("progress must be between 0 and 100");
        }
        let (mut store, agent, ticket) = self.write_context()?;
        store.append(
            &agent.id,
            Event::TicketReported {
                ticket_id: ticket.id.clone(),
                stage: args.stage,
                summary: args.summary,
                progress: args.progress,
                next: args.next,
                artifacts: args.artifacts,
            },
        )?;
        status(&store, &ticket.id)
    }

    fn ask(&self, args: Value) -> Result<Value> {
        #[derive(Deserialize)]
        struct Args {
            question: String,
        }
        let args: Args = parse_args(args)?;
        if args.question.trim().is_empty() {
            bail!("question must not be empty");
        }
        let (mut store, agent, ticket) = self.write_context()?;
        require_coordinator(&agent, "ask")?;
        store.append(
            &agent.id,
            Event::TicketAsked {
                ticket_id: ticket.id.clone(),
                question: args.question,
            },
        )?;
        let mut value = status(&store, &ticket.id)?;
        value["instruction"] = WAIT_INSTRUCTION.into();
        Ok(value)
    }

    fn complete(&self, args: Value) -> Result<Value> {
        #[derive(Deserialize)]
        struct Args {
            outcome: Outcome,
            summary: String,
            #[serde(default)]
            artifacts: Vec<String>,
        }
        let args: Args = parse_args(args)?;
        if args.summary.trim().is_empty() {
            bail!("summary must not be empty");
        }
        let (mut store, agent, ticket) = self.write_context()?;
        require_coordinator(&agent, "complete")?;
        store.append(
            &agent.id,
            Event::TicketCompleted {
                ticket_id: ticket.id.clone(),
                outcome: args.outcome,
                summary: args.summary,
                artifacts: args.artifacts,
            },
        )?;
        status(&store, &ticket.id)
    }
}

/// Whether a session started at launch `launch` has been superseded. An
/// unknown launch is allowed.
pub fn is_stale(launch: Option<i64>, agent: &Agent) -> bool {
    launch.is_some_and(|launch| launch != agent.launches)
}

fn require_coordinator(agent: &Agent, action: &str) -> Result<()> {
    if agent.role != "coordinator" {
        bail!(
            "only the Coordinator may {action}; agent {} is a {}",
            agent.id,
            agent.role
        );
    }
    Ok(())
}

fn parse_args<T: serde::de::DeserializeOwned>(args: Value) -> Result<T> {
    serde_json::from_value(args).context("invalid arguments")
}

fn status(store: &Store, ticket_id: &str) -> Result<Value> {
    let t = store
        .ticket(ticket_id)?
        .with_context(|| format!("ticket {ticket_id} does not exist"))?;
    Ok(json!({
        "id": t.id,
        "state": t.state,
        "stage": t.stage,
        "summary": t.summary,
        "progress": t.progress,
        "next": t.next,
        "question": t.question,
        "outcome": t.outcome,
        "artifacts": t.artifacts,
    }))
}

fn tool_result(text: String, is_error: bool) -> Value {
    json!({"content": [{"type": "text", "text": text}], "isError": is_error})
}

fn error_reply(id: Value, code: i64, message: String) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

fn tools() -> Value {
    let artifacts = json!({
        "type": "array",
        "items": {"type": "string"},
        "description": "Links or paths produced so far, such as pull request URLs.",
    });
    json!([
        {
            "name": "ticket_get",
            "description": "Read your Ticket: its Brief, state, Stage, latest report, \
                blockers, and the Project's goal.",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": false},
        },
        {
            "name": "report",
            "description": "Report progress on your Ticket. Call it whenever the Stage \
                changes or something notable happens. Omitted fields keep their values.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "stage": {"type": "string", "description": "A free-form phase, such as plan, implement, or review."},
                    "summary": {"type": "string", "description": "What has happened so far."},
                    "progress": {"type": "integer", "minimum": 0, "maximum": 100},
                    "next": {"type": "string", "description": "What you will do next."},
                    "artifacts": artifacts,
                },
                "additionalProperties": false,
            },
        },
        {
            "name": "ask",
            "description": "Coordinator only. Ask the human a question that blocks the \
                Ticket. After calling it, stop and wait for the reply in this conversation.",
            "inputSchema": {
                "type": "object",
                "properties": {"question": {"type": "string"}},
                "required": ["question"],
                "additionalProperties": false,
            },
        },
        {
            "name": "complete",
            "description": "Coordinator only. End the Ticket with an outcome and a summary.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "outcome": {"type": "string", "enum": ["delivered", "abandoned", "failed"]},
                    "summary": {"type": "string"},
                    "artifacts": artifacts,
                },
                "required": ["outcome", "summary"],
                "additionalProperties": false,
            },
        },
    ])
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::domain::TicketState;
    use crate::store::NewTicket;

    /// Creates a config with Project `demo` and a running Ticket `demo-1`
    /// whose Coordinator is `demo-1-coordinator`, plus a helper Agent
    /// `demo-1-helper`.
    pub(crate) fn dispatched(dir: &std::path::Path) -> Paths {
        let paths = Paths {
            config_dir: dir.join("config"),
            state_dir: dir.join("state"),
        };
        std::fs::create_dir_all(&paths.config_dir).unwrap();
        std::fs::write(
            paths.config_file(),
            "[[projects]]\nid = \"demo\"\nrepo = \"/tmp/demo\"\ngoal = \"Ship it\"\n",
        )
        .unwrap();
        let mut store = Store::open(&paths.db_file()).unwrap();
        store
            .create_ticket(
                "human",
                NewTicket {
                    project_id: "demo".into(),
                    title: "Add a feature".into(),
                    body: "The Brief".into(),
                    ready: true,
                    ..Default::default()
                },
            )
            .unwrap();
        for role in ["coordinator", "helper"] {
            store
                .append(
                    "serve",
                    Event::AgentCreated {
                        agent_id: format!("demo-1-{role}"),
                        ticket_id: "demo-1".into(),
                        project_id: "demo".into(),
                        role: role.into(),
                        provider: "claude".into(),
                        cwd: "/tmp".into(),
                    },
                )
                .unwrap();
        }
        store
            .append(
                "serve",
                Event::TicketDispatched {
                    ticket_id: "demo-1".into(),
                    agent_id: "demo-1-coordinator".into(),
                },
            )
            .unwrap();
        paths
    }

    fn rpc(server: &Server, method: &str, params: Value) -> Value {
        let line = json!({"jsonrpc": "2.0", "id": 7, "method": method, "params": params});
        let mut out = Vec::new();
        server
            .serve(format!("{line}\n").as_bytes(), &mut out)
            .unwrap();
        let reply: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(reply["id"], 7);
        reply
    }

    fn call(server: &Server, tool: &str, args: Value) -> (bool, String) {
        let reply = rpc(
            server,
            "tools/call",
            json!({"name": tool, "arguments": args}),
        );
        let result = &reply["result"];
        (
            result["isError"].as_bool().unwrap(),
            result["content"][0]["text"].as_str().unwrap().to_owned(),
        )
    }

    fn setup(agent: &str) -> (tempfile::TempDir, Server) {
        let dir = tempfile::tempdir().unwrap();
        let paths = dispatched(dir.path());
        (dir, Server::new(paths, agent.into(), None))
    }

    fn ticket(server: &Server) -> Ticket {
        Store::open(&server.paths.db_file())
            .unwrap()
            .ticket("demo-1")
            .unwrap()
            .unwrap()
    }

    #[test]
    fn negotiates_the_protocol_version() {
        let (_dir, server) = setup("demo-1-coordinator");
        let reply = rpc(
            &server,
            "initialize",
            json!({"protocolVersion": "2025-03-26"}),
        );
        assert_eq!(reply["result"]["protocolVersion"], "2025-03-26");
        assert_eq!(reply["result"]["capabilities"], json!({"tools": {}}));
        assert_eq!(reply["result"]["serverInfo"]["name"], "rex-projects");
        let reply = rpc(
            &server,
            "initialize",
            json!({"protocolVersion": "1999-01-01"}),
        );
        assert_eq!(reply["result"]["protocolVersion"], FALLBACK_VERSION);
    }

    #[test]
    fn ignores_notifications_and_rejects_unknown_methods() {
        let (_dir, server) = setup("demo-1-coordinator");
        let input = concat!(
            "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n",
            "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/whatever\"}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"resources/list\"}\n",
            "not json\n",
        );
        let mut out = Vec::new();
        server.serve(input.as_bytes(), &mut out).unwrap();
        let replies: Vec<Value> = String::from_utf8(out)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(replies.len(), 3);
        assert_eq!(replies[0], json!({"jsonrpc": "2.0", "id": 1, "result": {}}));
        assert_eq!(replies[1]["error"]["code"], METHOD_NOT_FOUND);
        assert_eq!(replies[2]["error"]["code"], PARSE_ERROR);
    }

    #[test]
    fn lists_tools_and_rejects_unknown_tools() {
        let (_dir, server) = setup("demo-1-coordinator");
        let reply = rpc(&server, "tools/list", json!({}));
        let names: Vec<&str> = reply["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["ticket_get", "report", "ask", "complete"]);
        let reply = rpc(&server, "tools/call", json!({"name": "nope"}));
        assert_eq!(reply["error"]["code"], INVALID_PARAMS);
    }

    #[test]
    fn gets_the_ticket_with_its_project() {
        let (_dir, server) = setup("demo-1-coordinator");
        let (is_error, text) = call(&server, "ticket_get", json!({}));
        assert!(!is_error, "{text}");
        let value: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["project"], json!({"id": "demo", "goal": "Ship it"}));
        assert_eq!(value["ticket"]["brief"], "The Brief");
        assert_eq!(value["ticket"]["state"], "running");
    }

    #[test]
    fn reports_asks_and_completes() {
        let (_dir, server) = setup("demo-1-coordinator");
        let (is_error, text) = call(
            &server,
            "report",
            json!({"stage": "plan", "progress": 10, "artifacts": ["a.md"]}),
        );
        assert!(!is_error, "{text}");
        let t = ticket(&server);
        assert_eq!(t.stage.as_deref(), Some("plan"));
        assert_eq!(t.progress, Some(10));
        assert_eq!(t.artifacts, ["a.md"]);

        let (is_error, text) = call(&server, "ask", json!({"question": "Which API?"}));
        assert!(!is_error, "{text}");
        assert!(text.contains("wait for the human's reply"));
        let t = ticket(&server);
        assert_eq!(t.state, TicketState::Waiting);
        assert_eq!(t.question.as_deref(), Some("Which API?"));

        let (is_error, text) = call(
            &server,
            "complete",
            json!({"outcome": "delivered", "summary": "Done", "artifacts": ["pr"]}),
        );
        assert!(!is_error, "{text}");
        let t = ticket(&server);
        assert_eq!(t.state, TicketState::Done);
        assert_eq!(t.outcome, Some(Outcome::Delivered));

        let (is_error, text) = call(&server, "report", json!({"summary": "more"}));
        assert!(is_error);
        assert!(text.contains("while it is done"), "{text}");
    }

    #[test]
    fn rejects_invalid_arguments() {
        let (_dir, server) = setup("demo-1-coordinator");
        assert!(call(&server, "report", json!({"progress": 101})).0);
        assert!(call(&server, "ask", json!({})).0);
        assert!(
            call(
                &server,
                "complete",
                json!({"outcome": "maybe", "summary": "x"})
            )
            .0
        );
        assert_eq!(ticket(&server).state, TicketState::Running);
    }

    #[test]
    fn only_the_coordinator_asks_and_completes() {
        let (_dir, server) = setup("demo-1-helper");
        let (is_error, text) = call(&server, "ask", json!({"question": "?"}));
        assert!(is_error);
        assert!(text.contains("only the Coordinator"), "{text}");
        assert!(
            call(
                &server,
                "complete",
                json!({"outcome": "failed", "summary": "x"})
            )
            .0
        );
        assert!(!call(&server, "report", json!({"stage": "help"})).0);
    }

    #[test]
    fn unknown_agents_get_an_error_result() {
        let (_dir, server) = setup("nobody");
        let (is_error, text) = call(&server, "ticket_get", json!({}));
        assert!(is_error);
        assert!(text.contains("agent nobody does not exist"));
    }

    #[test]
    fn stale_launches_cannot_write() {
        let dir = tempfile::tempdir().unwrap();
        let paths = dispatched(dir.path());
        // The Agent has never been launched, so its `launches` is 0.
        let stale = Server::new(paths.clone(), "demo-1-coordinator".into(), Some(1));
        let (is_error, text) = call(&stale, "report", json!({"stage": "plan"}));
        assert!(is_error);
        assert!(text.contains("superseded"), "{text}");
        assert!(call(&stale, "ask", json!({"question": "?"})).0);
        assert!(!call(&stale, "ticket_get", json!({})).0);
        assert_eq!(ticket(&stale).stage, None);

        let current = Server::new(paths, "demo-1-coordinator".into(), Some(0));
        assert!(!call(&current, "report", json!({"stage": "plan"})).0);
    }
}
