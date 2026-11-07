use std::path::PathBuf;

use clap::{Parser, Subcommand};

mod fixtures;
mod release;

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
}

#[derive(Debug, Subcommand)]
enum FixtureCommand {
    /// Emulate the operations adapter protocol with durable local state.
    Operations {
        #[arg(long)]
        state_dir: PathBuf,
    },
}

fn default_repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask is directly under the repository root")
        .to_path_buf()
}

fn main() {
    if let Err(error) = run(Cli::parse()) {
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
            FixtureCommand::Operations { state_dir } => fixtures::operations::run(&state_dir),
        },
    }
}
