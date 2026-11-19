//! The Agent-facing MCP server: newline-delimited JSON-RPC 2.0 over stdio.
//! A Coordinator reports on its Ticket through these tools (ADR-0002).

use std::io::{BufRead, Write};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::config::Config;
use crate::domain::{Agent, Event, Outcome, Ticket, TicketState};
use crate::paths::Paths;
use crate::store::Store;

/// Handshake-based MCP revisions this server speaks.
const SUPPORTED_VERSIONS: [&str; 4] = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];
const FALLBACK_VERSION: &str = "2025-11-25";

const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;

const WAIT_INSTRUCTION: &str = "Your question is recorded and the Ticket is waiting. Stop working \
     now and wait for the human's reply in this conversation.";

type RpcError = (i64, String);

/// Serves one Agent, identified by `REX_PROJECTS_AGENT_ID`. The store is reopened on
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
                    "send" => self.send(args),
                    "inbox_read" => self.inbox_read(),
                    "spawn_agent" => self.spawn_agent(args),
                    "agents_list" => self.agents_list(),
                    "agent_stop" => self.agent_stop(args),
                    "done" => self.done(args),
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
            "notice": close_notice(&ticket),
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
        require_coordinator(
            &agent,
            "report; send your progress to the Coordinator instead",
        )?;
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

impl Server {
    fn send(&self, args: Value) -> Result<Value> {
        #[derive(Deserialize)]
        struct Args {
            to: String,
            body: String,
        }
        let args: Args = parse_args(args)?;
        if args.body.chars().count() > crate::inbox::MAX_BODY_CHARS {
            bail!(
                "body is longer than {} characters; put long content in a file and send its path",
                crate::inbox::MAX_BODY_CHARS
            );
        }
        let (mut store, agent, ticket) = self.write_context()?;
        let to = if args.to == "coordinator" {
            ticket
                .coordinator_id
                .clone()
                .context("the Ticket has no Coordinator")?
        } else {
            args.to
        };
        if to == agent.id {
            bail!("you cannot send a message to yourself");
        }
        store.append(
            &agent.id,
            Event::MessageSent {
                ticket_id: ticket.id.clone(),
                from: agent.id.clone(),
                to: to.clone(),
                body: args.body,
            },
        )?;
        Ok(json!({"sent_to": to}))
    }

    fn inbox_read(&self) -> Result<Value> {
        let (mut store, agent, _) = self.write_context()?;
        let (messages, remaining) = crate::inbox::take(&mut store, &agent.id)?;
        Ok(json!({"messages": messages, "remaining": remaining}))
    }

    fn spawn_agent(&self, args: Value) -> Result<Value> {
        #[derive(Deserialize)]
        struct Args {
            role: String,
            task: String,
            provider: Option<String>,
        }
        let args: Args = parse_args(args)?;
        let (mut store, agent, ticket) = self.write_context()?;
        require_coordinator(&agent, "spawn helper Agents")?;
        if !matches!(ticket.state, TicketState::Running | TicketState::Waiting) {
            bail!(
                "ticket {} is {}; helpers run only on a running Ticket",
                ticket.id,
                ticket.state
            );
        }
        crate::config::validate_id(&args.role).context("invalid role")?;
        if args.role == "coordinator" {
            bail!("a Ticket has one Coordinator; spawn a helper Role such as worker or reviewer");
        }
        crate::provider::role_base_text(&self.paths, &args.role)?;
        if args.task.trim().is_empty() {
            bail!("task must not be empty");
        }
        if args.task.chars().count() > crate::inbox::MAX_BODY_CHARS {
            bail!(
                "task is longer than {} characters; put details in a file and pass its path",
                crate::inbox::MAX_BODY_CHARS
            );
        }
        let config = Config::load(&self.paths.config_file())?;
        let project = config.project(&ticket.project_id)?;
        let provider = args
            .provider
            .unwrap_or(project.agent_spec(&args.role).provider);
        config.provider(&provider)?;
        let max = config.limits.max_agents as usize;
        let n = store
            .agents_for_ticket(&ticket.id)?
            .iter()
            .filter(|a| a.role == args.role)
            .count()
            + 1;
        let id = format!("{}-{}-{n}", ticket.id, args.role);
        let admitted = store.append_within_slots(
            &agent.id,
            &[
                Event::AgentCreated {
                    agent_id: id.clone(),
                    ticket_id: ticket.id.clone(),
                    project_id: ticket.project_id.clone(),
                    role: args.role.clone(),
                    provider: provider.clone(),
                    cwd: agent.cwd.clone(),
                },
                Event::MessageSent {
                    ticket_id: ticket.id.clone(),
                    from: agent.id.clone(),
                    to: id.clone(),
                    body: args.task,
                },
            ],
            max,
        )?;
        if !admitted {
            bail!(
                "all {max} Agent slots are in use; wait for a helper to finish, or do the work yourself"
            );
        }
        Ok(json!({
            "agent_id": id,
            "role": args.role,
            "provider": provider,
            "instruction": "rex-projects starts it in a pane beside yours within a few seconds. \
                Its result reaches you as a message when it calls done. If you have nothing \
                else to do meanwhile, end your turn.",
        }))
    }

    fn agents_list(&self) -> Result<Value> {
        let (store, agent, ticket) = self.context()?;
        require_coordinator(&agent, "list helper Agents")?;
        let helpers: Vec<Value> = store
            .agents_for_ticket(&ticket.id)?
            .into_iter()
            .filter(|a| a.id != agent.id)
            .map(|a| {
                json!({
                    "id": a.id,
                    "role": a.role,
                    "provider": a.provider,
                    "state": a.state,
                    "activity": a.activity,
                    "exit_reason": a.exit_reason,
                })
            })
            .collect();
        Ok(json!({"agents": helpers}))
    }

    fn agent_stop(&self, args: Value) -> Result<Value> {
        #[derive(Deserialize)]
        struct Args {
            agent_id: String,
        }
        let args: Args = parse_args(args)?;
        let (mut store, agent, ticket) = self.write_context()?;
        require_coordinator(&agent, "stop helper Agents")?;
        let helper = store
            .agent(&args.agent_id)?
            .filter(|a| a.ticket_id == ticket.id && a.id != agent.id)
            .with_context(|| {
                format!("{} is not a helper on ticket {}", args.agent_id, ticket.id)
            })?;
        store.append(
            &agent.id,
            Event::AgentFinished {
                agent_id: helper.id.clone(),
                reason: "stopped by the Coordinator".into(),
            },
        )?;
        Ok(json!({"stopped": helper.id}))
    }

    fn done(&self, args: Value) -> Result<Value> {
        #[derive(Deserialize)]
        struct Args {
            summary: String,
            #[serde(default)]
            artifacts: Vec<String>,
        }
        let args: Args = parse_args(args)?;
        if args.summary.trim().is_empty() {
            bail!("summary must not be empty");
        }
        let (mut store, agent, ticket) = self.write_context()?;
        if agent.role == "coordinator" {
            bail!("the Coordinator ends its Ticket with `complete`, not `done`");
        }
        let coordinator = ticket
            .coordinator_id
            .clone()
            .context("the Ticket has no Coordinator")?;
        let mut body = format!("{} finished its task.\n\n{}", agent.id, args.summary.trim());
        for artifact in &args.artifacts {
            body.push_str(&format!("\nartifact: {artifact}"));
        }
        if body.chars().count() > crate::inbox::MAX_BODY_CHARS {
            bail!(
                "the summary and artifacts are longer than {} characters; shorten the summary \
                 or put the details in a file and list its path as an artifact",
                crate::inbox::MAX_BODY_CHARS
            );
        }
        store.append_all(
            &agent.id,
            &[
                Event::MessageSent {
                    ticket_id: ticket.id.clone(),
                    from: agent.id.clone(),
                    to: coordinator,
                    body,
                },
                Event::AgentFinished {
                    agent_id: agent.id.clone(),
                    reason: "done".into(),
                },
            ],
        )?;
        Ok(json!({
            "instruction": "Your result is on its way to the Coordinator. Stop now; \
                rex-projects closes this pane.",
        }))
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

/// Asks the Coordinator to check with a human about external closes that no
/// human has answered yet.
fn close_notice(t: &Ticket) -> Option<String> {
    // `ask` only works while the Ticket is running or waiting.
    if !matches!(t.state, TicketState::Running | TicketState::Waiting) {
        return None;
    }
    let closed: Vec<String> = t
        .unacknowledged_closes()
        .map(|r| {
            format!(
                "{} {} is {}",
                r.tracker,
                r.reference,
                r.closed_externally.as_deref().unwrap_or_default()
            )
        })
        .collect();
    (!closed.is_empty()).then(|| {
        format!(
            "Someone closed this Ticket's external item outside rex-projects ({}). Call `ask` to confirm whether to continue.",
            closed.join(", ")
        )
    })
}

fn status(store: &Store, ticket_id: &str) -> Result<Value> {
    let t = store
        .ticket(ticket_id)?
        .with_context(|| format!("ticket {ticket_id} does not exist"))?;
    Ok(json!({
        "notice": close_notice(&t),
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
        {
            "name": "send",
            "description": "Send a message to another Agent on your Ticket. It waits in \
                their inbox and reaches them when their turn ends or they next read it.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "to": {"type": "string", "description": "An Agent id, or `coordinator`."},
                    "body": {"type": "string"},
                },
                "required": ["to", "body"],
                "additionalProperties": false,
            },
        },
        {
            "name": "spawn_agent",
            "description": "Coordinator only. Start a helper Agent in its own pane in your \
                Ticket's worktree, such as a worker to implement or a reviewer to review. \
                Its result reaches you as a message when it calls done.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "role": {"type": "string", "description": "worker, reviewer, or another Role configured for this Project."},
                    "task": {"type": "string", "description": "Everything the helper needs to know: what to do, where, and how you will judge the result."},
                    "provider": {"type": "string", "description": "A configured provider such as claude or codex. Defaults to the Role's provider."},
                },
                "required": ["role", "task"],
                "additionalProperties": false,
            },
        },
        {
            "name": "agents_list",
            "description": "Coordinator only. List your Ticket's helper Agents and their state.",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": false},
        },
        {
            "name": "agent_stop",
            "description": "Coordinator only. Stop a helper Agent and close its pane.",
            "inputSchema": {
                "type": "object",
                "properties": {"agent_id": {"type": "string"}},
                "required": ["agent_id"],
                "additionalProperties": false,
            },
        },
        {
            "name": "done",
            "description": "Helpers only. Finish your task: your summary goes to the \
                Coordinator, and your pane closes.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "summary": {"type": "string", "description": "What you did, how you verified it, and anything left open. A reviewer lists its findings here."},
                    "artifacts": artifacts,
                },
                "required": ["summary"],
                "additionalProperties": false,
            },
        },
        {
            "name": "inbox_read",
            "description": "Read your unread messages and mark them read. Messages also \
                reach you automatically, so call this when told you have unread messages.",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": false},
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
                    external_refs: vec![crate::domain::ExternalRef {
                        tracker: "acme".into(),
                        reference: "A-1".into(),
                        url: None,
                        closed_externally: None,
                        close_acknowledged: false,
                    }],
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
        assert_eq!(
            names,
            [
                "ticket_get",
                "report",
                "ask",
                "complete",
                "send",
                "spawn_agent",
                "agents_list",
                "agent_stop",
                "done",
                "inbox_read"
            ]
        );
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
    fn tells_the_coordinator_about_external_closes() {
        let (_dir, server) = setup("demo-1-coordinator");
        let (_, text) = call(&server, "report", json!({"stage": "plan"}));
        assert!(!text.contains("closed this Ticket"), "{text}");
        Store::open(&server.paths.db_file())
            .unwrap()
            .append(
                "tracker",
                Event::ExternalChanged {
                    ticket_id: "demo-1".into(),
                    tracker: "acme".into(),
                    reference: "A-1".into(),
                    status: "canceled".into(),
                },
            )
            .unwrap();
        let (is_error, text) = call(&server, "report", json!({"stage": "implement"}));
        assert!(!is_error, "{text}");
        assert!(text.contains("acme A-1 is canceled"), "{text}");
        let (_, text) = call(&server, "ticket_get", json!({}));
        assert!(
            text.contains("\"closed_externally\": \"canceled\""),
            "{text}"
        );
        assert!(text.contains("acme A-1 is canceled"), "{text}");

        // Once a human answers, the close stays recorded but stops asking.
        let (_, text) = call(&server, "ask", json!({"question": "Continue?"}));
        assert!(text.contains("acme A-1 is canceled"), "{text}");
        Store::open(&server.paths.db_file())
            .unwrap()
            .append(
                "human",
                Event::TicketAnswered {
                    ticket_id: "demo-1".into(),
                    answer: Some("Yes, continue".into()),
                    question: None,
                },
            )
            .unwrap();
        let (_, text) = call(&server, "report", json!({"stage": "implement"}));
        assert!(!text.contains("acme A-1 is canceled"), "{text}");
        assert!(ticket(&server).unacknowledged_closes().next().is_none());
        assert_eq!(
            ticket(&server).external_refs[0]
                .closed_externally
                .as_deref(),
            Some("canceled")
        );
    }

    #[test]
    fn does_not_ask_an_ended_ticket_to_ask() {
        let (_dir, server) = setup("demo-1-coordinator");
        Store::open(&server.paths.db_file())
            .unwrap()
            .append(
                "tracker",
                Event::ExternalChanged {
                    ticket_id: "demo-1".into(),
                    tracker: "acme".into(),
                    reference: "A-1".into(),
                    status: "done".into(),
                },
            )
            .unwrap();
        let (is_error, text) = call(
            &server,
            "complete",
            json!({"outcome": "delivered", "summary": "Done"}),
        );
        assert!(!is_error, "{text}");
        assert!(!text.contains("Call `ask`"), "{text}");
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
        // Helpers send progress to the Coordinator rather than report it.
        assert!(call(&server, "report", json!({"stage": "help"})).0);
        assert!(
            call(
                &server,
                "spawn_agent",
                json!({"role": "worker", "task": "x"})
            )
            .0
        );
        assert!(call(&server, "agents_list", json!({})).0);
    }

    fn agent(server: &Server, id: &str) -> Agent {
        Store::open(&server.paths.db_file())
            .unwrap()
            .agent(id)
            .unwrap()
            .unwrap()
    }

    #[test]
    fn spawns_lists_stops_and_hears_from_helpers() {
        let (_dir, coordinator) = setup("demo-1-coordinator");
        let (is_error, text) = call(
            &coordinator,
            "spawn_agent",
            json!({"role": "worker", "task": "Add the flag.", "provider": "codex"}),
        );
        assert!(!is_error, "{text}");
        let spawned: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(spawned["agent_id"], "demo-1-worker-1");
        let worker = agent(&coordinator, "demo-1-worker-1");
        assert_eq!(
            (
                worker.role.as_str(),
                worker.provider.as_str(),
                worker.state.as_str()
            ),
            ("worker", "codex", "created")
        );
        let store = Store::open(&coordinator.paths.db_file()).unwrap();
        let task = store.unread("demo-1-worker-1").unwrap();
        assert_eq!(task[0].body, "Add the flag.");

        // A second worker gets the next number and the Role's default provider.
        let (_, text) = call(
            &coordinator,
            "spawn_agent",
            json!({"role": "worker", "task": "Fix the docs."}),
        );
        let spawned: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(spawned["agent_id"], "demo-1-worker-2");
        assert_eq!(spawned["provider"], "claude");

        let (_, text) = call(&coordinator, "agents_list", json!({}));
        let listed: Value = serde_json::from_str(&text).unwrap();
        let ids: Vec<&str> = listed["agents"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, ["demo-1-helper", "demo-1-worker-1", "demo-1-worker-2"]);

        assert!(
            !call(
                &coordinator,
                "agent_stop",
                json!({"agent_id": "demo-1-worker-2"})
            )
            .0
        );
        assert_eq!(agent(&coordinator, "demo-1-worker-2").state, "finished");
        assert!(
            call(
                &coordinator,
                "agent_stop",
                json!({"agent_id": "demo-1-worker-2"})
            )
            .0
        );
        assert!(
            call(
                &coordinator,
                "agent_stop",
                json!({"agent_id": "demo-1-coordinator"})
            )
            .0
        );

        // The worker's done reaches the Coordinator's inbox.
        let worker = Server::new(coordinator.paths.clone(), "demo-1-worker-1".into(), None);
        assert!(call(&worker, "done", json!({"summary": " "})).0);
        // A result too long for one message is refused, and the helper can retry.
        let long = "x".repeat(crate::inbox::MAX_BODY_CHARS);
        let (is_error, text) = call(
            &worker,
            "done",
            json!({"summary": long, "artifacts": ["a"]}),
        );
        assert!(is_error);
        assert!(text.contains("shorten the summary"), "{text}");
        assert_eq!(agent(&coordinator, "demo-1-worker-1").state, "created");
        let (is_error, text) = call(
            &worker,
            "done",
            json!({"summary": "Added --flag; tests pass.", "artifacts": ["src/cli.rs"]}),
        );
        assert!(!is_error, "{text}");
        assert_eq!(agent(&coordinator, "demo-1-worker-1").state, "finished");
        let (_, text) = call(&coordinator, "inbox_read", json!({}));
        let read: Value = serde_json::from_str(&text).unwrap();
        let body = read["messages"][0]["body"].as_str().unwrap();
        assert!(
            body.starts_with("demo-1-worker-1 finished its task."),
            "{body}"
        );
        assert!(body.contains("Added --flag; tests pass."), "{body}");
        assert!(body.contains("artifact: src/cli.rs"), "{body}");
        assert!(call(&worker, "done", json!({"summary": "again"})).0);
        assert!(call(&coordinator, "done", json!({"summary": "x"})).0);
    }

    #[test]
    fn refuses_bad_spawns() {
        let (_dir, coordinator) = setup("demo-1-coordinator");
        for args in [
            json!({"role": "coordinator", "task": "x"}),
            json!({"role": "Bad Role", "task": "x"}),
            json!({"role": "astronaut", "task": "x"}),
            json!({"role": "worker", "task": "  "}),
            json!({"role": "worker", "task": "x", "provider": "gemini"}),
        ] {
            assert!(call(&coordinator, "spawn_agent", args.clone()).0, "{args}");
        }
        // A Role file in the config directory adds a Role.
        let roles = coordinator.paths.config_dir.join("roles");
        std::fs::create_dir_all(&roles).unwrap();
        std::fs::write(roles.join("astronaut.md"), "# Role: Astronaut\n").unwrap();
        assert!(
            !call(
                &coordinator,
                "spawn_agent",
                json!({"role": "astronaut", "task": "x"})
            )
            .0
        );

        // With 4 slots, the Coordinator, the helper, and the astronaut hold
        // three, so one more worker fits and the next does not.
        let config = coordinator.paths.config_file();
        let text = std::fs::read_to_string(&config).unwrap();
        std::fs::write(&config, format!("[limits]\nmax_agents = 4\n{text}")).unwrap();
        assert!(
            !call(
                &coordinator,
                "spawn_agent",
                json!({"role": "worker", "task": "x"})
            )
            .0
        );
        let (is_error, text) = call(
            &coordinator,
            "spawn_agent",
            json!({"role": "worker", "task": "y"}),
        );
        assert!(is_error);
        assert!(text.contains("Agent slots are in use"), "{text}");
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

    #[test]
    fn agents_message_each_other() {
        let (dir, helper) = setup("demo-1-helper");
        let coordinator = Server::new(helper.paths.clone(), "demo-1-coordinator".into(), None);
        let (is_error, text) = call(
            &helper,
            "send",
            json!({"to": "coordinator", "body": "Tests pass."}),
        );
        assert!(!is_error, "{text}");
        assert!(text.contains("demo-1-coordinator"), "{text}");
        let (is_error, text) = call(&coordinator, "inbox_read", json!({}));
        assert!(!is_error, "{text}");
        let read: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(read["messages"][0]["from"], "demo-1-helper");
        assert_eq!(read["messages"][0]["body"], "Tests pass.");
        assert_eq!(read["remaining"], 0);
        let (_, text) = call(&coordinator, "inbox_read", json!({}));
        assert!(text.contains("\"messages\": []"), "{text}");

        for args in [
            json!({"to": "demo-1-helper", "body": "me"}),
            json!({"to": "nobody", "body": "hi"}),
            json!({"to": "coordinator", "body": "  "}),
            json!({"to": "coordinator", "body": "x".repeat(crate::inbox::MAX_BODY_CHARS + 1)}),
        ] {
            assert!(call(&helper, "send", args).0);
        }
        drop(dir);
    }
}
