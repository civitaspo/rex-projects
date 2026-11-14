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
    #[arg(long, global = true, env = "REXP_CONFIG_DIR")]
    pub config_dir: Option<PathBuf>,
    /// Directory holding the state database and worktrees.
    #[arg(long, global = true, env = "REXP_STATE_DIR")]
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
    /// Print the event log as JSON lines.
    Events(EventsArgs),
    /// Maintain the state database.
    #[command(subcommand)]
    Db(DbCommand),
    /// Serve the Agent-facing MCP server on stdio. Requires REXP_AGENT_ID.
    Mcp,
    /// Handle a harness hook. Reads the hook input from stdin.
    Hook {
        /// `claude` or `codex`.
        provider: String,
        /// `session-start` or `user-prompt-submit`.
        event: String,
    },
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
    /// Mark a waiting Ticket answered so its Coordinator continues.
    Answer {
        id: String,
        #[arg(long)]
        text: Option<String>,
    },
    /// Stop a Ticket and mark it abandoned.
    Cancel {
        id: String,
        #[arg(long, default_value = "cancelled by a human")]
        reason: String,
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
    std::env::var("REXP_AGENT_ID")
        .ok()
        .filter(|id| !id.is_empty())
        .unwrap_or_else(|| "human".to_owned())
}

pub fn run(cli: Cli) -> Result<()> {
    if let Command::Hook { provider, event } = &cli.command {
        crate::hook::main(cli.config_dir, cli.state_dir, provider, event);
        return Ok(());
    }
    let paths = Paths::resolve(cli.config_dir, cli.state_dir)?;
    match cli.command {
        Command::Config(ConfigCommand::Check) => {
            let config = Config::load(&paths.config_file())?;
            println!(
                "{}: {} project(s)",
                paths.config_file().display(),
                config.projects.len()
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
        Command::Events(args) => events(&paths, args),
        Command::Mcp => {
            let agent_id = std::env::var("REXP_AGENT_ID")
                .ok()
                .filter(|id| !id.is_empty())
                .context("REXP_AGENT_ID must be set to serve MCP")?;
            let launch = std::env::var("REXP_AGENT_LAUNCH")
                .ok()
                .map(|l| l.parse::<i64>().context("invalid REXP_AGENT_LAUNCH"))
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
                print_ticket(&ticket);
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
            store.append(
                &actor(),
                Event::TicketAnswered {
                    ticket_id: id.clone(),
                    answer: text,
                },
            )?;
            println!("{id} is running");
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
    }
    Ok(())
}

fn print_ticket(t: &Ticket) {
    println!("{} [{}] {}", t.id, t.state, t.title);
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
            println!("{label}: {value}");
        }
    }
    if !t.blocked_by.is_empty() {
        println!("blocked by: {}", t.blocked_by.join(", "));
    }
    for artifact in &t.artifacts {
        println!("artifact: {artifact}");
    }
    if !t.body.is_empty() {
        println!("\n{}", t.body);
    }
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
