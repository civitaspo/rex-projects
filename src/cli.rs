use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};

use crate::config::Config;
use crate::domain::{Event, Ticket, TicketState};
use crate::paths::Paths;
use crate::store::{NewTicket, Store};

#[derive(Debug, Parser)]
#[command(
    name = "rex-projects",
    version,
    about = "Run cooperating coding Agents inside Rex"
)]
pub struct Cli {
    /// Directory holding config.toml, Playbooks, and Roles.
    #[arg(long, global = true, env = "REX_PROJECTS_CONFIG_DIR")]
    pub config_dir: Option<PathBuf>,
    /// Directory holding the state database and worktrees.
    #[arg(long, global = true, env = "REX_PROJECTS_STATE_DIR")]
    pub state_dir: Option<PathBuf>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Inspect the configuration.
    #[command(subcommand)]
    Config(ConfigCommand),
    /// Inspect configured Projects.
    #[command(subcommand)]
    Project(ProjectCommand),
    /// Create and manage Tickets.
    #[command(subcommand)]
    Ticket(TicketCommand),
    /// Query external trackers and their write-back jobs.
    #[command(subcommand)]
    Tracker(TrackerCommand),
    /// Print the event log as JSON lines.
    Events(EventsArgs),
    /// Maintain the state database.
    #[command(subcommand)]
    Db(DbCommand),
    /// Serve the Agent-facing MCP server on stdio. Requires REX_PROJECTS_AGENT_ID.
    Mcp,
    /// Handle a harness hook. Reads the hook input from stdin.
    Hook {
        /// `claude` or `codex`.
        provider: String,
        /// `session-start` or `user-prompt-submit`.
        event: String,
    },
    /// Dispatch ready Tickets to Coordinators in Rex and watch them.
    Serve {
        #[arg(long, default_value_t = 2000)]
        interval_ms: u64,
        /// Run one reconcile-and-dispatch pass, then exit.
        #[arg(long)]
        once: bool,
    },
    /// Show the Ticket dashboard.
    Ui {
        /// Quit after jumping to a Ticket, for a floating layer.
        #[arg(long)]
        popup: bool,
    },
    /// Run Agents. Used by the Rex blocks that `serve` opens.
    #[command(subcommand)]
    Agent(AgentCommand),
}

#[derive(Debug, Subcommand)]
pub enum AgentCommand {
    /// Prepare an Agent's files and replace this process with its harness.
    Exec { agent_id: String },
}

#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Load and validate config.toml.
    Check,
}

#[derive(Debug, Subcommand)]
pub enum ProjectCommand {
    /// List configured Projects.
    List {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum TicketCommand {
    /// Create a Ticket.
    New(NewTicketArgs),
    /// List Tickets.
    List {
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        state: Option<TicketState>,
        #[arg(long)]
        json: bool,
    },
    /// Show one Ticket.
    Show {
        id: String,
        #[arg(long)]
        json: bool,
    },
    /// Mark a backlog Ticket ready to run.
    Ready { id: String },
    /// Answer a waiting Ticket's question.
    ///
    /// With `--text`, the answer is typed into the Coordinator's pane and
    /// submitted. Without it, the Ticket is only marked answered, for when you
    /// already replied in the pane and its prompt hook did not record it.
    Answer {
        id: String,
        #[arg(long)]
        text: Option<String>,
    },
    /// Leave a message in an Agent's inbox.
    ///
    /// The message goes to the Ticket's Coordinator, or to `--agent`. It
    /// reaches the Agent when its turn ends or it next reads its inbox,
    /// without interrupting it.
    Message {
        id: String,
        text: String,
        /// The Agent to message, by id. Defaults to the Coordinator.
        #[arg(long)]
        agent: Option<String>,
    },
    /// Create a Ticket from an item in an external tracker.
    Import {
        /// The item's reference in the tracker.
        reference: String,
        #[arg(long)]
        project: String,
        /// Defaults to the Project's tracker.
        #[arg(long)]
        tracker: Option<String>,
        #[arg(long)]
        ready: bool,
        #[arg(long)]
        json: bool,
    },
    /// Stop a Ticket and mark it abandoned.
    Cancel {
        id: String,
        #[arg(long, default_value = "cancelled by a human")]
        reason: String,
    },
    /// Remove the worktree and branch of an ended Ticket.
    Cleanup {
        id: String,
        /// Also delete ignored files, such as `.env` or build output.
        #[arg(long)]
        discard_ignored: bool,
    },
}

#[derive(Debug, Args)]
pub struct NewTicketArgs {
    #[arg(long)]
    pub project: String,
    #[arg(long)]
    pub title: String,
    /// The Brief. Use --body-file - to read it from stdin.
    #[arg(long, conflicts_with = "body_file")]
    pub body: Option<String>,
    #[arg(long)]
    pub body_file: Option<PathBuf>,
    /// Make the Ticket ready to run immediately.
    #[arg(long)]
    pub ready: bool,
    /// Higher runs first.
    #[arg(long, default_value_t = 0)]
    pub priority: i64,
    /// A Ticket that must be done first. Repeatable.
    #[arg(long = "blocked-by")]
    pub blocked_by: Vec<String>,
    #[arg(long)]
    pub playbook: Option<String>,
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Subcommand)]
pub enum TrackerCommand {
    /// List candidate items from a Project's tracker.
    List {
        #[arg(long)]
        project: String,
        #[arg(long, default_value = "")]
        query: String,
        #[arg(long)]
        json: bool,
    },
    /// Show pending and failed write-back jobs.
    Jobs {
        /// Include finished and superseded jobs.
        #[arg(long)]
        all: bool,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Args)]
pub struct EventsArgs {
    /// Print events after this sequence number.
    #[arg(long, default_value_t = 0)]
    pub since: i64,
    /// Keep printing new events as they are recorded.
    #[arg(long)]
    pub follow: bool,
}

#[derive(Debug, Subcommand)]
pub enum DbCommand {
    /// Rebuild the projections from the event log.
    Rebuild,
}

/// Who an operation is attributed to: the calling Agent, or a human.
pub fn actor() -> String {
    std::env::var("REX_PROJECTS_AGENT_ID")
        .ok()
        .filter(|id| !id.is_empty())
        .unwrap_or_else(|| "human".to_owned())
}

pub fn run(cli: Cli) -> Result<()> {
    if let Command::Hook { provider, event } = &cli.command {
        crate::hook::main(cli.config_dir, cli.state_dir, provider, event);
        return Ok(());
    }
    reject_old_env(std::env::vars_os().map(|(name, _)| name))?;
    let paths = Paths::resolve(cli.config_dir, cli.state_dir)?;
    match cli.command {
        Command::Config(ConfigCommand::Check) => {
            let config = Config::load(&paths.config_file())?;
            // `Config::load` already builds the trackers the way `serve` does.
            println!(
                "{}: {} project(s), {} tracker(s)",
                paths.config_file().display(),
                config.projects.len(),
                config.trackers.len()
            );
            Ok(())
        }
        Command::Project(ProjectCommand::List { json }) => {
            let config = Config::load(&paths.config_file())?;
            if json {
                let projects: Vec<_> = config
                    .projects
                    .iter()
                    .map(|p| {
                        serde_json::json!({
                            "id": p.id,
                            "repo": p.repo,
                            "goal": p.goal,
                        })
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&projects)?);
            } else {
                for project in &config.projects {
                    println!("{}\t{}", project.id, project.repo.display());
                }
            }
            Ok(())
        }
        Command::Ticket(command) => ticket(&paths, command),
        Command::Tracker(command) => tracker_command(&paths, command),
        Command::Events(args) => events(&paths, args),
        Command::Mcp => {
            let agent_id = std::env::var("REX_PROJECTS_AGENT_ID")
                .ok()
                .filter(|id| !id.is_empty())
                .context("REX_PROJECTS_AGENT_ID must be set to serve MCP")?;
            let launch = std::env::var("REX_PROJECTS_AGENT_LAUNCH")
                .ok()
                .map(|l| {
                    l.parse::<i64>()
                        .context("invalid REX_PROJECTS_AGENT_LAUNCH")
                })
                .transpose()?;
            crate::mcp::Server::new(paths, agent_id, launch)
                .serve(std::io::stdin().lock(), std::io::stdout().lock())
        }
        Command::Hook { .. } => unreachable!("handled above"),
        Command::Db(DbCommand::Rebuild) => {
            Store::open(&paths.db_file())?.rebuild()?;
            println!("rebuilt projections from the event log");
            Ok(())
        }
        Command::Serve { interval_ms, once } => {
            crate::serve::run(&paths, Duration::from_millis(interval_ms), once)
        }
        Command::Agent(AgentCommand::Exec { agent_id }) => crate::provider::exec(&paths, &agent_id),
        Command::Ui { popup } => crate::ui::run(&paths, popup),
    }
}

fn ticket(paths: &Paths, command: TicketCommand) -> Result<()> {
    let mut store = Store::open(&paths.db_file())?;
    match command {
        TicketCommand::New(args) => {
            let config = Config::load(&paths.config_file())?;
            config.project(&args.project)?;
            for blocker in &args.blocked_by {
                if store.ticket(blocker)?.is_none() {
                    bail!("blocking ticket {blocker} does not exist");
                }
            }
            let body = match (&args.body, &args.body_file) {
                (Some(body), _) => body.clone(),
                (None, Some(path)) if path.as_os_str() == "-" => {
                    let mut body = String::new();
                    std::io::stdin().read_to_string(&mut body)?;
                    body
                }
                (None, Some(path)) => std::fs::read_to_string(path)
                    .with_context(|| format!("failed to read {}", path.display()))?,
                (None, None) => String::new(),
            };
            let ticket = store.create_ticket(
                &actor(),
                NewTicket {
                    project_id: args.project,
                    title: args.title,
                    body,
                    priority: args.priority,
                    playbook: args.playbook,
                    blocked_by: args.blocked_by,
                    external_refs: Vec::new(),
                    ready: args.ready,
                },
            )?;
            if args.json {
                println!("{}", serde_json::to_string_pretty(&ticket)?);
            } else {
                println!("{}", ticket.id);
            }
        }
        TicketCommand::List {
            project,
            state,
            json,
        } => {
            let tickets: Vec<Ticket> = store
                .tickets(project.as_deref())?
                .into_iter()
                .filter(|t| state.is_none_or(|s| t.state == s))
                .collect();
            if json {
                println!("{}", serde_json::to_string_pretty(&tickets)?);
            } else {
                for t in &tickets {
                    println!(
                        "{}\t{}\t{}\t{}",
                        t.id,
                        t.state,
                        t.stage.as_deref().unwrap_or("-"),
                        t.title
                    );
                }
            }
        }
        TicketCommand::Show { id, json } => {
            let ticket = store
                .ticket(&id)?
                .with_context(|| format!("ticket {id} does not exist"))?;
            if json {
                println!("{}", serde_json::to_string_pretty(&ticket)?);
            } else {
                let mut out = std::io::stdout().lock();
                print_ticket(&mut out, &ticket)?;
                let history = crate::history::entries(&store.ticket_events(&id)?);
                if !history.is_empty() {
                    writeln!(out, "\nHistory:")?;
                    for entry in history {
                        writeln!(out, "  {}  {}", entry.at, entry.text)?;
                    }
                }
            }
        }
        TicketCommand::Ready { id } => {
            store.append(
                &actor(),
                Event::TicketReadied {
                    ticket_id: id.clone(),
                },
            )?;
            println!("{id} is ready");
        }
        TicketCommand::Answer { id, text } => {
            answer(
                &mut store,
                &mut crate::rex::RexCli::new(),
                &actor(),
                &id,
                text,
            )?;
            println!("{id} is running");
        }
        TicketCommand::Message { id, text, agent } => {
            let ticket = store
                .ticket(&id)?
                .with_context(|| format!("ticket {id} does not exist"))?;
            let to = agent
                .or(ticket.coordinator_id)
                .with_context(|| format!("ticket {id} has no Coordinator yet"))?;
            if text.chars().count() > crate::inbox::MAX_BODY_CHARS {
                bail!(
                    "the message is longer than {} characters",
                    crate::inbox::MAX_BODY_CHARS
                );
            }
            let from = actor();
            store.append(
                &from,
                Event::MessageSent {
                    ticket_id: id,
                    from: from.clone(),
                    to: to.clone(),
                    body: text,
                },
            )?;
            println!("sent to {to}");
        }
        TicketCommand::Import {
            reference,
            project,
            tracker,
            ready,
            json,
        } => {
            let config = Config::load(&paths.config_file())?;
            let ticket = crate::tracker::import(
                &mut store,
                &config,
                &actor(),
                &project,
                tracker.as_deref(),
                &reference,
                ready,
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&ticket)?);
            } else {
                println!("{}", ticket.id);
            }
        }
        TicketCommand::Cancel { id, reason } => {
            store.append(
                &actor(),
                Event::TicketCancelled {
                    ticket_id: id.clone(),
                    reason,
                },
            )?;
            println!("{id} is abandoned");
        }
        TicketCommand::Cleanup {
            id,
            discard_ignored,
        } => {
            let config = Config::load(&paths.config_file())?;
            crate::worktree::cleanup_ticket(paths, &config, &store, &id, discard_ignored)?;
            println!("removed the worktree of {id}");
        }
    }
    Ok(())
}

fn tracker_command(paths: &Paths, command: TrackerCommand) -> Result<()> {
    match command {
        TrackerCommand::List {
            project,
            query,
            json,
        } => {
            let config = Config::load(&paths.config_file())?;
            let items = crate::tracker::list(&config, &project, &query)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&items)?);
            } else {
                for item in &items {
                    println!(
                        "{}\t{}\t{}",
                        item.reference,
                        item.status.as_str(),
                        item.title
                    );
                }
            }
        }
        TrackerCommand::Jobs { all, json } => {
            let store = Store::open(&paths.db_file())?;
            let jobs = crate::tracker::jobs(&store, all)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&jobs)?);
            } else {
                for job in &jobs {
                    println!(
                        "{}\t{}\t{}\t{} {}\t{}\tattempts={}\t{}",
                        job.id,
                        job.ticket_id,
                        job.state,
                        job.tracker,
                        job.reference,
                        job.action,
                        job.attempts,
                        job.last_error.as_deref().unwrap_or("-")
                    );
                }
            }
        }
    }
    Ok(())
}

fn print_ticket(out: &mut impl Write, t: &Ticket) -> std::io::Result<()> {
    writeln!(out, "{} [{}] {}", t.id, t.state, t.title)?;
    let optional = [
        ("stage", t.stage.as_deref()),
        ("summary", t.summary.as_deref()),
        ("next", t.next.as_deref()),
        ("question", t.question.as_deref()),
        ("playbook", t.playbook.as_deref()),
        ("coordinator", t.coordinator_id.as_deref()),
    ];
    for (label, value) in optional {
        if let Some(value) = value {
            writeln!(out, "{label}: {value}")?;
        }
    }
    if let Some(progress) = t.progress {
        writeln!(out, "progress: {progress}%")?;
    }
    if let Some(outcome) = t.outcome {
        writeln!(out, "outcome: {outcome}")?;
    }
    if !t.blocked_by.is_empty() {
        writeln!(out, "blocked by: {}", t.blocked_by.join(", "))?;
    }
    for r in &t.external_refs {
        write!(out, "external: {} {}", r.tracker, r.reference)?;
        if let Some(url) = &r.url {
            write!(out, " ({url})")?;
        }
        if let Some(status) = &r.closed_externally {
            write!(out, ", closed externally as {status}")?;
        }
        writeln!(out)?;
    }
    for artifact in &t.artifacts {
        writeln!(out, "artifact: {artifact}")?;
    }
    if !t.body.is_empty() {
        writeln!(out, "\n{}", t.body)?;
    }
    Ok(())
}

fn events(paths: &Paths, args: EventsArgs) -> Result<()> {
    let store = Store::open(&paths.db_file())?;
    let mut cursor = args.since;
    let stdout = std::io::stdout();
    loop {
        let batch = store.events_since(cursor, 500)?;
        let mut out = stdout.lock();
        for event in &batch {
            writeln!(out, "{}", serde_json::to_string(event)?)?;
            cursor = event.seq;
        }
        out.flush()?;
        if batch.len() == 500 {
            continue;
        }
        if !args.follow {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// Fails when environment variables use the old `REXP_` prefix, which is
/// ignored now. Ignoring `REXP_STATE_DIR` silently would open a different
/// state database, and an Agent started with `REXP_AGENT_ID` would lose its
/// identity.
fn reject_old_env(names: impl Iterator<Item = std::ffi::OsString>) -> Result<()> {
    let mut old: Vec<String> = names
        .filter_map(|name| name.into_string().ok())
        .filter(|name| name.starts_with("REXP_"))
        .collect();
    if old.is_empty() {
        return Ok(());
    }
    old.sort();
    let renamed: Vec<String> = old
        .iter()
        .map(|name| format!("{name} -> REX_PROJECTS_{}", &name["REXP_".len()..]))
        .collect();
    bail!(
        "the REXP_ environment variables were renamed: {}. Set the new names \
         and unset the old ones; restart Agents that were started before the rename",
        renamed.join(", ")
    );
}

/// Answers a waiting Ticket. A text answer is submitted in the Coordinator's
/// pane first, so the Ticket only leaves `waiting` once the Coordinator has it.
fn answer(
    store: &mut Store,
    rex: &mut impl crate::rex::Rex,
    actor: &str,
    id: &str,
    text: Option<String>,
) -> Result<()> {
    let open_question = |store: &Store| -> Result<Option<String>> {
        let ticket = store
            .ticket(id)?
            .with_context(|| format!("ticket {id} does not exist"))?;
        Ok(ticket
            .question
            .filter(|_| ticket.state == TicketState::Waiting))
    };
    let Some(question) = open_question(store)? else {
        bail!("ticket {id} is not waiting for an answer");
    };
    if let Some(text) = &text {
        let coordinator = store
            .agents_for_ticket(id)?
            .into_iter()
            .find(|a| a.role == "coordinator" && a.state != "exited");
        let (Some(session), Some(block)) = (
            coordinator.as_ref().and_then(|a| a.rex_session_id.clone()),
            coordinator.as_ref().and_then(|a| a.rex_block_id.clone()),
        ) else {
            bail!("ticket {id} has no running Coordinator to answer; start `serve` first");
        };
        // `idle` and `done` both mean the harness is waiting for input.
        let status = rex.program_status(&session, &block)?.map(|s| s.state);
        if !matches!(status.as_deref(), Some("idle" | "done")) {
            bail!(
                "the Coordinator of {id} is {}, not idle; answer in its pane instead",
                status.as_deref().unwrap_or("not reporting a status")
            );
        }
        rex.submit(&session, &block, text)?;
    }
    let sent = text.is_some();
    let answered = store.append(
        actor,
        Event::TicketAnswered {
            ticket_id: id.to_owned(),
            answer: text,
            question: Some(question.clone()),
        },
    );
    match answered {
        Ok(_) => Ok(()),
        // The harness's prompt hook recorded the answer first, and the
        // Coordinator may have asked something new since.
        Err(_) if open_question(store)?.as_ref() != Some(&question) => Ok(()),
        Err(err) if sent => Err(err.context(format!(
            "the answer was sent to the Coordinator, but recording it failed; \
             run `rex-projects ticket answer {id}` without --text to record it \
             without sending it again"
        ))),
        Err(err) => Err(err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rex::fake::{Block, FakeRex};
    use crate::rex::{Rex, Status};

    fn waiting_ticket() -> (Store, FakeRex, String) {
        let mut store = Store::open_in_memory().unwrap();
        store
            .create_ticket(
                "human",
                NewTicket {
                    project_id: "demo".into(),
                    title: "T".into(),
                    ready: true,
                    ..Default::default()
                },
            )
            .unwrap();
        let mut rex = FakeRex::default();
        let session = rex.ensure_session("rex-projects:demo", None).unwrap();
        let window = rex
            .new_window(&session, "demo-1", &[], std::path::Path::new("/"))
            .unwrap();
        for event in [
            Event::AgentCreated {
                agent_id: "demo-1-coordinator".into(),
                ticket_id: "demo-1".into(),
                project_id: "demo".into(),
                role: "coordinator".into(),
                provider: "claude".into(),
                cwd: "/".into(),
            },
            Event::TicketDispatched {
                ticket_id: "demo-1".into(),
                agent_id: "demo-1-coordinator".into(),
            },
            Event::AgentLaunched {
                agent_id: "demo-1-coordinator".into(),
                rex_session_id: session,
                rex_window_id: window.window_id,
                rex_block_id: window.block_id.clone(),
                resume: false,
            },
            Event::TicketAsked {
                ticket_id: "demo-1".into(),
                question: "Which API?".into(),
            },
        ] {
            store.append("serve", event).unwrap();
        }
        (store, rex, window.block_id)
    }

    fn block<'a>(rex: &'a mut FakeRex, id: &str) -> &'a mut Block {
        rex.blocks.get_mut(id).unwrap()
    }

    #[test]
    fn submits_a_text_answer_to_an_idle_coordinator() {
        let (mut store, mut rex, block_id) = waiting_ticket();
        let text = Some("Use v2".to_owned());

        let err = answer(&mut store, &mut rex, "human", "demo-1", text.clone()).unwrap_err();
        assert!(err.to_string().contains("not idle"), "{err}");
        assert_eq!(
            store.ticket("demo-1").unwrap().unwrap().state,
            TicketState::Waiting
        );

        block(&mut rex, &block_id).status = Some(Status {
            state: "idle".into(),
            message: None,
        });
        answer(&mut store, &mut rex, "human", "demo-1", text).unwrap();
        assert_eq!(block(&mut rex, &block_id).input, ["Use v2"]);
        assert_eq!(
            store.ticket("demo-1").unwrap().unwrap().state,
            TicketState::Running
        );

        let err = answer(&mut store, &mut rex, "human", "demo-1", None).unwrap_err();
        assert!(err.to_string().contains("not waiting"), "{err}");
    }

    #[test]
    fn rejects_the_old_environment_variable_prefix() {
        let names = |list: &[&str]| {
            list.iter()
                .map(std::ffi::OsString::from)
                .collect::<Vec<_>>()
                .into_iter()
        };
        reject_old_env(names(&["PATH", "REX_PROJECTS_STATE_DIR"])).unwrap();
        let err = reject_old_env(names(&["REXP_STATE_DIR", "PATH"])).unwrap_err();
        assert!(
            err.to_string()
                .contains("REXP_STATE_DIR -> REX_PROJECTS_STATE_DIR"),
            "{err}"
        );
    }

    #[test]
    fn marks_a_ticket_answered_in_the_pane() {
        let (mut store, mut rex, block_id) = waiting_ticket();
        answer(&mut store, &mut rex, "human", "demo-1", None).unwrap();
        assert!(block(&mut rex, &block_id).input.is_empty());
        assert_eq!(
            store.ticket("demo-1").unwrap().unwrap().state,
            TicketState::Running
        );
    }

    fn shown(ticket: &Ticket) -> String {
        let mut out = Vec::new();
        print_ticket(&mut out, ticket).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn show_prints_progress_outcome_and_external_refs() {
        let (store, _, _) = waiting_ticket();
        let mut ticket = store.ticket("demo-1").unwrap().unwrap();
        let plain = shown(&ticket);
        assert!(!plain.contains("progress:"), "{plain}");
        assert!(!plain.contains("outcome:"), "{plain}");
        assert!(!plain.contains("external:"), "{plain}");

        ticket.progress = Some(40);
        ticket.outcome = Some(crate::domain::Outcome::Delivered);
        ticket.external_refs = vec![
            crate::domain::ExternalRef {
                tracker: "acme".into(),
                reference: "A-1".into(),
                url: Some("https://acme.example/A-1".into()),
                closed_externally: None,
                close_acknowledged: false,
            },
            crate::domain::ExternalRef {
                tracker: "github".into(),
                reference: "7".into(),
                url: None,
                closed_externally: Some("done".into()),
                close_acknowledged: false,
            },
        ];
        let text = shown(&ticket);
        let lines: Vec<&str> = text.lines().collect();
        for expected in [
            "progress: 40%",
            "outcome: delivered",
            "external: acme A-1 (https://acme.example/A-1)",
            "external: github 7, closed externally as done",
        ] {
            assert!(
                lines.contains(&expected),
                "missing {expected:?} in:\n{text}"
            );
        }
    }
}
