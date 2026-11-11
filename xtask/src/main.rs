use std::ffi::OsString;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand, ValueEnum};
use rex_projects::domain::types::Role;

mod acceptance;
mod fixtures;
mod release;
mod verify;

#[derive(Debug, Parser)]
#[command(
    name = "xtask",
    about = "Development-only rex-projects maintenance tools"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Validate a complete artifact set and render/check the Lua runtime pin.
    Pin {
        #[arg(long)]
        artifact_root: PathBuf,
        #[arg(long, default_value_os_t = default_repository_root().join("lua/rex_projects/runtime_version.lua"))]
        pin_path: PathBuf,
        #[arg(long)]
        protocol: Option<u32>,
        #[arg(long)]
        expected_source_revision: Option<String>,
        #[arg(long, conflicts_with = "write")]
        check: bool,
        #[arg(long)]
        write: bool,
    },
    /// Download the Cargo-version release, verify every csm-ci attestation, and check/write the Lua pin.
    RefreshPin {
        #[arg(long, default_value_os_t = default_repository_root().join("lua/rex_projects/runtime_version.lua"))]
        pin_path: PathBuf,
        #[arg(long, default_value = "gh")]
        gh: PathBuf,
        #[arg(long, conflicts_with = "write")]
        check: bool,
        #[arg(long)]
        write: bool,
    },
    /// Run deterministic external-protocol fixtures for integration tests.
    Fixture {
        #[command(subcommand)]
        fixture: FixtureCommand,
    },
    /// Check explicitly supplied product and Rex binaries before starting acceptance resources.
    Verify {
        #[arg(long)]
        cli: PathBuf,
        #[arg(long)]
        rex: PathBuf,
        #[arg(long)]
        rex_server: String,
        #[arg(long)]
        expected_instance: String,
        #[arg(long)]
        rex_session: String,
        #[arg(long)]
        fixture_root: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum FixtureCommand {
    /// Emulate the operations adapter protocol with durable local state.
    Operations {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long, default_value = "legacy", value_parser = ["legacy", "queued", "running", "awaiting_approval", "succeeded", "failed", "cancelled", "skipped", "missing", "timed_out", "unknown"])]
        observe_status: String,
    },
    /// Emulate the normalized generic ticket protocol with durable SQLite state.
    Ticket {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        namespace: String,
        #[arg(long)]
        drop_create_response_once: Option<String>,
        #[arg(long)]
        mutate_response: Option<String>,
        #[arg(long, default_value_t = 0)]
        index_delay_ms: u64,
        #[arg(long)]
        delay_method: Option<String>,
        #[arg(long, default_value_t = 0)]
        delay_ms: u64,
        #[arg(long, default_value = "record", value_parser = ["record", "edges"])]
        native_shape: String,
    },
    /// Run the local GitHub CLI fixture with the remaining arguments passed to `gh api`.
    #[command(name = "github")]
    GitHub {
        #[arg(long)]
        root: PathBuf,
        #[arg(last = true, required = true)]
        args: Vec<OsString>,
    },
    /// Emit one deterministic, schema-checked Agent message through a provider CLI protocol.
    Agent {
        #[arg(long, value_enum)]
        provider: AgentProvider,
        #[arg(long)]
        role: String,
        #[arg(long)]
        scenario: String,
        #[arg(long)]
        context: PathBuf,
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        runtime_binary: Option<PathBuf>,
        #[arg(last = true)]
        args: Vec<String>,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum AgentProvider {
    Codex,
    Claude,
}

fn default_repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask is directly under the repository root")
        .to_path_buf()
}

fn main() {
    let argv = std::env::args_os().collect::<Vec<_>>();
    if argv
        .first()
        .and_then(|value| Path::new(value).file_name())
        .is_some_and(|name| name == "gh")
    {
        let root = argv
            .first()
            .map(Path::new)
            .and_then(Path::parent)
            .and_then(Path::parent)
            .map(Path::to_path_buf)
            .or_else(|| std::env::var_os("REX_PROJECTS_FIXTURE_ROOT").map(PathBuf::from));
        let result = root
            .ok_or_else(|| "fixture gh cannot resolve its owned fixture root".to_owned())
            .and_then(|root| fixtures::github::run_cli(&root, &argv[1..]));
        if let Err(error) = result {
            eprintln!("fixture gh: {error}");
            std::process::exit(1);
        }
        return;
    }
    let cli = Cli::parse();
    if let Command::Verify {
        cli,
        rex,
        rex_server,
        expected_instance,
        rex_session,
        fixture_root,
    } = cli.command
    {
        match verify::preflight(
            &cli,
            &rex,
            &rex_server,
            &expected_instance,
            &rex_session,
            &fixture_root,
        ) {
            Ok(true) => {
                let result = acceptance::run(acceptance::Request {
                    cli: &cli,
                    rex: &rex,
                    rex_server: &rex_server,
                    expected_instance: &expected_instance,
                    rex_session: &rex_session,
                    fixture_root: &fixture_root,
                });
                if let Err(error) = result {
                    eprintln!("acceptance: {error}");
                    std::process::exit(1);
                }
            }
            Ok(false) => std::process::exit(1),
            Err(error) => {
                eprintln!("preflight: {error}");
                std::process::exit(1);
            }
        }
        return;
    }
    if let Err(error) = run(cli) {
        eprintln!("xtask: {error}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Command::Pin {
            artifact_root,
            pin_path,
            protocol,
            expected_source_revision,
            check: _,
            write,
        } => release::pin_from_artifacts(
            &default_repository_root(),
            &artifact_root,
            &pin_path,
            protocol,
            expected_source_revision.as_deref(),
            write,
        ),
        Command::RefreshPin {
            pin_path,
            gh,
            check: _,
            write,
        } => release::refresh_pin(&default_repository_root(), &pin_path, &gh, write),
        Command::Fixture { fixture } => match fixture {
            FixtureCommand::Operations {
                state_dir,
                observe_status,
            } => fixtures::operations::run(&state_dir, &observe_status),
            FixtureCommand::Ticket {
                database,
                namespace,
                drop_create_response_once,
                mutate_response,
                index_delay_ms,
                delay_method,
                delay_ms,
                native_shape,
            } => fixtures::ticket::run(
                &database,
                &namespace,
                drop_create_response_once.as_deref(),
                mutate_response.as_deref(),
                index_delay_ms,
                delay_method.as_deref().map(|method| (method, delay_ms)),
                &native_shape,
            ),
            FixtureCommand::GitHub { root, args } => fixtures::github::run_cli(&root, &args),
            FixtureCommand::Agent {
                provider,
                role,
                scenario,
                context,
                state_dir,
                runtime_binary,
                args,
            } => {
                let role = match role.as_str() {
                    "supervisor" => Role::Supervisor,
                    "coordinator" => Role::Coordinator,
                    "planner" => Role::Planner,
                    "worker" => Role::Worker,
                    "reviewer" => Role::Reviewer,
                    "merge_decision" => Role::MergeDecision,
                    "operator" => Role::Operator,
                    "postmortem" => Role::Postmortem,
                    _ => return Err("unknown Agent role".to_owned()),
                };
                fixtures::agent::run(
                    match provider {
                        AgentProvider::Codex => fixtures::agent::Provider::Codex,
                        AgentProvider::Claude => fixtures::agent::Provider::Claude,
                    },
                    role,
                    &scenario,
                    &context,
                    &state_dir,
                    runtime_binary.as_deref(),
                    &args,
                )
            }
        },
        Command::Verify { .. } => unreachable!("verify handled before general dispatch"),
    }
}
