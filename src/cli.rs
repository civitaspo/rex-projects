use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};

use crate::adapters::rex::RexCliTransport;
use crate::adapters::tickets::{
    NormalizedTicket, NormalizedTicketStatus, TicketGetRequest, TicketGetResult, TicketListRequest,
    TicketScope,
};
use crate::config::{self, AppliedConfig, Config};
use crate::dashboard::{DashboardBackend, RuntimeDashboardBackend};
use crate::domain::ids::{Digest, HumanRequestId, ProjectId, Revision, TicketRunId};
use crate::process::{
    ProcessRequest, resolve_executable as resolve_process_executable, run as run_process,
};
use crate::protocol::{RequestEnvelope, RequestId, ResponseEnvelope};
use crate::store::{ConfigStore, ControlCommand, ExpectedRevision, OwnerMetadata, ProjectRecord};

#[derive(Debug, Parser)]
#[command(
    name = "rex-projects",
    version,
    about = "Run cooperating Agents for software delivery and recurring operations"
)]
struct Cli {
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,
    #[arg(long, global = true, value_name = "PATH")]
    state_root: Option<PathBuf>,
    #[arg(long, global = true)]
    json: bool,
    #[arg(long, global = true, value_name = "URL")]
    rex_server: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Version {
        #[arg(long)]
        json: bool,
    },
    Schema {
        kind: SchemaKind,
    },
    #[command(subcommand)]
    Config(ConfigCommand),
    #[command(subcommand)]
    Policy(PolicyCommand),
    Doctor {
        #[arg(long)]
        project: Option<String>,
    },
    Runtime {
        #[command(subcommand)]
        command: RuntimeCommand,
    },
    Project {
        #[command(subcommand)]
        command: ProjectCommand,
    },
    Status,
    Dashboard,
    Agent {
        #[command(subcommand)]
        command: AgentCommand,
    },
    Ticket {
        #[command(subcommand)]
        command: TicketCommand,
    },
    Provider {
        #[command(subcommand)]
        command: ProviderCommand,
    },
    Human {
        #[command(subcommand)]
        command: HumanCommand,
    },
    Knowledge {
        #[command(subcommand)]
        command: KnowledgeCommand,
    },
    Learning {
        #[command(subcommand)]
        command: LearningCommand,
    },
}

#[derive(Debug, Subcommand)]
enum LearningCommand {
    Trial {
        #[command(subcommand)]
        command: TrialCommand,
    },
}

#[derive(Debug, Subcommand)]
enum TrialCommand {
    /// Stage one immutable profile-trial matrix for human approval.
    Request {
        #[arg(long)]
        project: String,
        #[arg(long)]
        candidate: String,
        #[arg(long)]
        candidate_digest: String,
        #[arg(long)]
        request_key: String,
        #[arg(long)]
        matrix_file: PathBuf,
    },
}

struct TrialRequestInput {
    project: String,
    candidate: String,
    candidate_digest: String,
    request_key: String,
    matrix_file: PathBuf,
}

#[derive(Debug, Subcommand)]
enum KnowledgeCommand {
    /// List committed postmortem publications for one Project.
    List {
        #[arg(long)]
        project: String,
    },
    /// Show one committed postmortem and its source provenance.
    Show {
        #[arg(long)]
        project: String,
        #[arg(long)]
        ticket_run: String,
    },
    /// Validate published article bytes against their stored request and receipt.
    Validate {
        #[arg(long)]
        project: String,
        #[arg(long)]
        ticket_run: String,
    },
}

#[derive(Debug, Subcommand)]
enum HumanCommand {
    List {
        #[arg(long)]
        project: Option<String>,
    },
    Show {
        request_id: String,
    },
    Respond {
        request_id: String,
        #[arg(long)]
        subject_digest: String,
        #[arg(long, value_enum)]
        choice: HumanChoiceArg,
        #[arg(long)]
        explanation: String,
        #[arg(long)]
        response_id: Option<String>,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum HumanChoiceArg {
    Approve,
    RequestChanges,
    RevisePlan,
    Defer,
    Cancel,
    Refuse,
}

#[derive(Debug, Subcommand)]
enum TicketCommand {
    /// List normalized tickets from the configured ticket CLI adapter.
    List {
        #[arg(long)]
        project: String,
        #[arg(long)]
        status: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: u32,
        #[arg(long)]
        cursor: Option<String>,
    },
    /// Show one normalized ticket from the configured ticket CLI adapter.
    Show {
        #[arg(long)]
        project: String,
        #[arg(long)]
        id: String,
    },
    /// Select a ticket from a bounded list. Use --id for noninteractive selection.
    Select {
        #[arg(long)]
        project: String,
        #[arg(long)]
        status: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: u32,
        #[arg(long)]
        cursor: Option<String>,
        #[arg(long)]
        id: Option<String>,
    },
    /// Focus the current Rex Agent block for a TicketRun.
    Focus { ticket_run: String },
    /// Pin or unpin the current Rex view for a TicketRun.
    View {
        #[command(subcommand)]
        command: TicketViewCommand,
    },
    Instruct {
        #[arg(long)]
        run: String,
        #[arg(long)]
        expected_revision: u64,
        #[arg(long)]
        message_file: PathBuf,
        #[arg(long)]
        request_id: Option<String>,
    },
    /// Show the exact exhausted MergeDecision blocker and digest-bound recovery subject.
    BlockedReason {
        #[arg(long)]
        project: String,
        #[arg(long)]
        run: String,
    },
    /// Queue human intent to resume one exhausted MergeDecision claim.
    ResumeMergeDecision {
        #[arg(long)]
        project: String,
        #[arg(long)]
        run: String,
        #[arg(long)]
        expected_subject_digest: String,
        #[arg(long)]
        request_id: Option<String>,
    },
    /// Show the latest durable state of one MergeDecision recovery request.
    RecoveryStatus {
        #[arg(long)]
        request_id: String,
    },
    ReleaseClaim {
        namespace: String,
        ticket: String,
        ticket_run: String,
        generation: u64,
        expected_revision: u64,
        #[arg(long)]
        reason: String,
        #[arg(long, value_enum)]
        disposition: ClaimDisposition,
        #[arg(long)]
        request_id: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum TicketViewCommand {
    Pin {
        ticket_run: String,
        #[arg(long)]
        expected_revision: u64,
        #[arg(long)]
        view_id: String,
    },
    Unpin {
        ticket_run: String,
        #[arg(long)]
        expected_revision: u64,
        #[arg(long)]
        view_id: String,
    },
}

#[derive(Debug, Subcommand)]
enum ProviderCommand {
    /// Queue an isolated, controller-owned qualification run for the applied role profile.
    Qualify {
        #[arg(long)]
        project: String,
        #[arg(long)]
        role: String,
        #[arg(long)]
        request_id: Option<String>,
    },
    /// Queue an isolated qualification run for one exact proposed candidate revision.
    QualifyCandidate {
        #[arg(long)]
        project: String,
        #[arg(long)]
        candidate: String,
        #[arg(long)]
        candidate_digest: String,
        #[arg(long)]
        request_id: Option<String>,
    },
    /// Read the durable state of a provider qualification request.
    Status {
        #[arg(long)]
        request_id: String,
    },
    /// Queue idempotent reconciliation for one exact unknown qualification request.
    Reconcile {
        #[arg(long)]
        request_id: String,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ClaimDisposition {
    Cancel,
}

#[derive(Debug, Subcommand)]
enum RuntimeCommand {
    Run {
        #[arg(long)]
        once: bool,
        #[arg(long)]
        rex_server: Option<String>,
    },
    Stop {
        #[arg(long)]
        request_id: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum ProjectCommand {
    List,
    Start {
        id: String,
        #[arg(long)]
        request_id: Option<String>,
    },
    Pause {
        id: String,
        #[arg(long)]
        request_id: Option<String>,
    },
    Resume {
        id: String,
        #[arg(long)]
        request_id: Option<String>,
    },
    Stop {
        id: String,
        #[arg(long)]
        request_id: Option<String>,
    },
    Status {
        id: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum AgentCommand {
    /// Internal bounded runner for a controller-owned disposable provider qualification block.
    #[command(hide = true)]
    QualificationRun {
        #[arg(long)]
        package: PathBuf,
    },
    /// Internal tool-shell marker probe for provider qualification.
    #[command(hide = true)]
    QualificationProbe {
        #[arg(long)]
        package: PathBuf,
    },
    RunStep {
        #[arg(long)]
        run: String,
        #[arg(long)]
        package: PathBuf,
        #[arg(long)]
        environment_handoff: PathBuf,
    },
    /// Internal detached finite-turn supervisor bound to one Rex-owned foreground shim.
    #[command(name = "run-step-supervisor", hide = true)]
    RunStepSupervisor {
        #[arg(long)]
        run: String,
        #[arg(long)]
        package: PathBuf,
        #[arg(long)]
        environment_handoff: PathBuf,
        #[arg(long)]
        anchor_pid: u32,
        #[arg(long)]
        anchor_start_identity: String,
    },
    TrialStep {
        #[arg(long)]
        run: String,
        #[arg(long)]
        package: PathBuf,
        #[arg(long)]
        environment_handoff: PathBuf,
    },
    Submit {
        #[arg(long, env = "REX_PROJECTS_CONTROL_DIR")]
        control_dir: PathBuf,
        #[arg(long, env = "REX_PROJECTS_RUN_ID")]
        run_id: String,
        #[arg(long)]
        request_id: String,
        #[arg(long, default_value_t = 5)]
        wait_seconds: u64,
    },
    ArtifactAdd {
        #[arg(long, env = "REX_PROJECTS_CONTROL_DIR")]
        control_dir: PathBuf,
        #[arg(long = "run", env = "REX_PROJECTS_RUN_ID")]
        run_id: String,
        #[arg(long)]
        path: String,
        #[arg(long, value_enum)]
        kind: AgentArtifactKind,
        #[arg(long, default_value_t = 1)]
        schema_version: u32,
        #[arg(long)]
        message_id: String,
        #[arg(long, default_value_t = 60)]
        wait_seconds: u64,
    },
    Repository {
        #[command(subcommand)]
        command: AgentRepositoryCommand,
    },
    Receipt {
        #[arg(long, env = "REX_PROJECTS_CONTROL_DIR")]
        control_dir: PathBuf,
        #[arg(long, env = "REX_PROJECTS_RUN_ID")]
        run_id: String,
        #[arg(long)]
        request_id: String,
    },
    Inbox {
        #[arg(long, env = "REX_PROJECTS_CONTROL_DIR")]
        control_dir: PathBuf,
        #[arg(long = "run", env = "REX_PROJECTS_RUN_ID")]
        run_id: String,
        #[arg(long, default_value_t = 0)]
        after: u64,
    },
}

#[derive(Debug, Subcommand)]
enum AgentRepositoryCommand {
    /// Build and register a Change manifest from this launch's assigned worktree.
    Manifest {
        #[arg(long)]
        paths_file: PathBuf,
        #[arg(long)]
        output: String,
        #[arg(long)]
        message_id: String,
        #[arg(long, default_value_t = 60)]
        wait_seconds: u64,
    },
    /// Ask the host to commit a registered Change manifest and return its durable receipt.
    Commit(AgentRepositoryCommitArgs),
}

#[derive(Debug, Args)]
struct AgentRepositoryCommitArgs {
    #[arg(long)]
    expected_head: String,
    #[arg(long)]
    manifest_reference_file: PathBuf,
    #[arg(long)]
    message_file: PathBuf,
    #[arg(long)]
    message_id: String,
    #[arg(long, default_value_t = 300)]
    wait_seconds: u64,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
#[value(rename_all = "snake_case")]
enum AgentArtifactKind {
    Plan,
    Change,
    TestReceipt,
    Review,
    MergeAssessment,
    OperationReceipt,
    Postmortem,
    Learning,
    General,
}

impl AgentArtifactKind {
    fn role_kind(self) -> crate::engine::orchestration::RoleArtifactKind {
        use crate::engine::orchestration::RoleArtifactKind as Kind;
        match self {
            Self::Plan => Kind::Plan,
            Self::Change => Kind::Change,
            Self::TestReceipt => Kind::TestReceipt,
            Self::Review => Kind::Review,
            Self::MergeAssessment => Kind::MergeAssessment,
            Self::OperationReceipt => Kind::OperationReceipt,
            Self::Postmortem => Kind::Postmortem,
            Self::Learning => Kind::Learning,
            Self::General => Kind::General,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum SchemaKind {
    Config,
    Profile,
    Request,
    Response,
    Version,
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    Validate,
    Apply(ApplyArgs),
    Diff {
        #[arg(long, value_name = "PATH")]
        candidate: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum PolicyCommand {
    Explain {
        #[arg(long)]
        repository: String,
    },
}

#[derive(Debug, Args)]
#[command(group(clap::ArgGroup::new("expectation").required(true).args(["bootstrap", "expected_revision"]).multiple(false)))]
struct ApplyArgs {
    #[arg(long, conflicts_with = "expected_revision")]
    bootstrap: bool,
    #[arg(long, value_name = "REVISION", conflicts_with = "bootstrap")]
    expected_revision: Option<u64>,
}

#[derive(Debug)]
pub struct CliError {
    code: u8,
    message: String,
}

impl CliError {
    fn usage(message: impl Into<String>) -> Self {
        Self {
            code: 2,
            message: message.into(),
        }
    }
    fn unexpected(message: impl Into<String>) -> Self {
        Self {
            code: 1,
            message: message.into(),
        }
    }
    fn conflict(message: impl Into<String>) -> Self {
        Self {
            code: 4,
            message: message.into(),
        }
    }
    fn not_found(message: impl Into<String>) -> Self {
        Self {
            code: 3,
            message: message.into(),
        }
    }
    fn human_only(message: impl Into<String>) -> Self {
        Self {
            code: 77,
            message: message.into(),
        }
    }
    fn unavailable(message: impl Into<String>) -> Self {
        Self {
            code: 5,
            message: message.into(),
        }
    }
    pub fn exit_code(&self) -> i32 {
        i32::from(self.code)
    }
}

fn require_human_context() -> Result<(), CliError> {
    if factory_context_present(
        std::env::var_os("REX_PROJECTS_AGENT").is_some(),
        std::env::var_os("REX_PROJECTS_CONTEXT").is_some(),
    ) {
        return Err(CliError::human_only(
            "this mutation is available only from a human host context; Agent blocks must submit scoped mailbox requests",
        ));
    }
    Ok(())
}

fn factory_context_present(agent_marker: bool, context_marker: bool) -> bool {
    agent_marker || context_marker
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

pub fn run() -> Result<i32, CliError> {
    let args = std::env::args_os().collect::<Vec<_>>();
    if args.len() == 5 && args[1] == "__internal" && args[2] == "env-capture" {
        let output_path = std::path::Path::new(&args[3]);
        let nonce = args[4]
            .to_str()
            .ok_or_else(|| CliError::usage("invalid environment capture request"))?;
        return crate::environment::write_capture_frame(output_path, nonce)
            .map(|()| 0)
            .map_err(|error| CliError::unexpected(error.to_string()));
    }
    let json_requested = args.iter().any(|argument| argument == "--json");
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(error) if error.exit_code() == 0 => {
            print!("{error}");
            return Ok(0);
        }
        Err(error) if error.use_stderr() && !json_requested => {
            return Err(CliError::usage(error.to_string()));
        }
        Err(error) => {
            if json_requested {
                print_json(
                    &serde_json::json!({"error":{"code":"invalid_request","message":error.to_string()}}),
                )?;
            } else {
                print!("{error}");
            }
            return Ok(if error.exit_code() == 0 { 0 } else { 2 });
        }
    };
    let json = cli.json || matches!(&cli.command, Command::Version { json: true });
    let result = match cli.command {
        Command::Version { json: version_json } => version(version_json || json),
        Command::Schema { kind } => schema(kind),
        Command::Config(ConfigCommand::Validate) => validate_config(cli.config.as_deref(), json),
        Command::Config(ConfigCommand::Apply(args)) => {
            apply_config(cli.config.as_deref(), cli.state_root.as_deref(), args, json)
        }
        Command::Config(ConfigCommand::Diff { candidate }) => config_diff(
            cli.config.as_deref(),
            cli.state_root.as_deref(),
            &candidate,
            json,
        ),
        Command::Policy(command) => policy_command(
            cli.config.as_deref(),
            cli.state_root.as_deref(),
            command,
            json,
        ),
        Command::Doctor { project } => doctor(cli.config.as_deref(), project.as_deref(), json),
        Command::Runtime { command } => runtime_command(
            cli.config.as_deref(),
            cli.state_root.as_deref(),
            command,
            cli.rex_server.as_deref(),
            json,
        ),
        Command::Project { command } => project_command(
            cli.config.as_deref(),
            cli.state_root.as_deref(),
            command,
            json,
        ),
        Command::Status => {
            runtime_status(cli.config.as_deref(), cli.state_root.as_deref(), None, json)
        }
        Command::Dashboard => {
            runtime_dashboard(cli.config.as_deref(), cli.state_root.as_deref(), json)
        }
        Command::Agent { command } => agent_command(command, json),
        Command::Ticket { command } => ticket_command(
            cli.config.as_deref(),
            cli.state_root.as_deref(),
            command,
            json,
        ),
        Command::Provider { command } => provider_command(
            cli.config.as_deref(),
            cli.state_root.as_deref(),
            command,
            json,
        ),
        Command::Human { command } => human_command(
            cli.config.as_deref(),
            cli.state_root.as_deref(),
            command,
            json,
        ),
        Command::Knowledge { command } => knowledge_command(
            cli.config.as_deref(),
            cli.state_root.as_deref(),
            command,
            json,
        ),
        Command::Learning { command } => learning_command(
            cli.config.as_deref(),
            cli.state_root.as_deref(),
            command,
            cli.rex_server.as_deref(),
            json,
        ),
    };
    match result {
        Ok(()) => Ok(0),
        Err(error) => {
            if json {
                print_json(
                    &serde_json::json!({"error":{"code":error_code(error.code),"message":error.message}}),
                )?;
            } else {
                eprintln!("{}", error.message);
            }
            Ok(error.exit_code())
        }
    }
}

fn error_code(code: u8) -> &'static str {
    match code {
        2 => "invalid_request",
        3 => "not_found",
        4 => "conflict",
        5 => "unavailable",
        _ => "internal",
    }
}

fn selected_config_path(explicit: Option<&Path>) -> Result<PathBuf, CliError> {
    if let Some(path) = explicit {
        return Ok(path.to_path_buf());
    }
    let config_home = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .ok_or_else(|| CliError::usage("HOME and XDG_CONFIG_HOME are unset; pass --config"))?;
    Ok(config_home.join("rex-projects/config.toml"))
}

fn load_config(path: Option<&Path>) -> Result<(PathBuf, AppliedConfig), CliError> {
    let path = selected_config_path(path)?;
    let loaded = config::load(&path).map_err(CliError::usage)?;
    Ok((path, loaded))
}

fn validate_config(path: Option<&Path>, json: bool) -> Result<(), CliError> {
    let (path, loaded) = load_config(path)?;
    #[derive(Serialize)]
    struct Report<'a> {
        valid: bool,
        config: &'a str,
        digest: String,
        projects: usize,
        repositories: usize,
        profiles: usize,
        source_files: usize,
        source_directories: usize,
    }
    let path_text = path.display().to_string();
    let report = Report {
        valid: true,
        config: &path_text,
        digest: loaded.digest.to_string(),
        projects: loaded.config.projects.len(),
        repositories: loaded.config.repositories.len(),
        profiles: loaded.profiles.len(),
        source_files: loaded
            .source_files
            .iter()
            .filter(|source| matches!(source.kind, config::SourceKind::File))
            .count(),
        source_directories: loaded
            .source_files
            .iter()
            .filter(|source| matches!(source.kind, config::SourceKind::Directory))
            .count(),
    };
    if json {
        print_json(&report)
    } else {
        println!("Valid configuration: {}", path.display());
        println!("Digest: {}", loaded.digest);
        println!(
            "Projects: {}, repositories: {}, profiles: {}, source files: {}, profile directories: {}",
            report.projects,
            report.repositories,
            report.profiles,
            report.source_files,
            report.source_directories
        );
        Ok(())
    }
}

fn project_list(
    config_path: Option<&Path>,
    explicit_state_root: Option<&Path>,
    json: bool,
) -> Result<(), CliError> {
    let (_, configured) = load_config(config_path)?;
    let state_root =
        config::state_root(&configured.config, explicit_state_root).map_err(CliError::usage)?;
    let (effective, snapshot_source, applied_revision) =
        read_effective_snapshot(config_path, explicit_state_root, configured)?;
    let database = state_root.join("state.sqlite3");
    let status = match std::fs::symlink_metadata(&database) {
        Ok(_) => Some(ConfigStore::status(&state_root).map_err(CliError::unavailable)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(CliError::unavailable(error.to_string())),
    };
    #[derive(Serialize)]
    struct ProjectEntry {
        id: String,
        mode: String,
        runtime_observation: &'static str,
        desired_lifecycle: Option<String>,
        observed_lifecycle: Option<String>,
        project_epoch: Option<u64>,
        next_due_at_unix: Option<i64>,
        last_error: Option<String>,
    }
    #[derive(Serialize)]
    struct ProjectListReport {
        schema_version: u32,
        source: &'static str,
        freshness: &'static str,
        applied_revision: Option<u64>,
        observed_at_unix: Option<i64>,
        external_services_queried: bool,
        projects: Vec<ProjectEntry>,
    }
    let report = ProjectListReport {
        schema_version: 1,
        source: snapshot_source,
        freshness: if status.is_some() {
            "local_snapshot"
        } else {
            "configuration_only"
        },
        applied_revision,
        observed_at_unix: status.as_ref().map(|status| status.observed_at_unix),
        external_services_queried: false,
        projects: effective
            .config
            .projects
            .iter()
            .map(|(id, config)| {
                let runtime = status
                    .as_ref()
                    .and_then(|status| status.projects.iter().find(|project| project.id == *id));
                ProjectEntry {
                    id: id.to_string(),
                    mode: match config.mode {
                        crate::domain::types::ProjectMode::Goal => "goal".into(),
                        crate::domain::types::ProjectMode::Operations => "operations".into(),
                    },
                    runtime_observation: if runtime.is_some() {
                        "observed"
                    } else {
                        "not_observed"
                    },
                    desired_lifecycle: runtime.map(|project| project.desired_lifecycle.clone()),
                    observed_lifecycle: runtime.map(|project| project.observed_lifecycle.clone()),
                    project_epoch: runtime.map(|project| project.project_epoch),
                    next_due_at_unix: runtime.map(|project| project.next_due_at_unix),
                    last_error: runtime.and_then(|project| project.last_error.clone()),
                }
            })
            .collect(),
    };
    if json {
        print_json(&report)
    } else {
        println!("Projects (external services not queried):");
        for project in &report.projects {
            println!(
                "{} [{}] runtime={}",
                project.id, project.mode, project.runtime_observation
            );
        }
        Ok(())
    }
}

fn policy_command(
    config_path: Option<&Path>,
    explicit_state_root: Option<&Path>,
    command: PolicyCommand,
    json: bool,
) -> Result<(), CliError> {
    match command {
        PolicyCommand::Explain { repository } => {
            #[derive(Serialize)]
            struct EffectiveRole {
                role: String,
                profile_id: String,
                profile_digest: String,
                instruction_files: Vec<InstructionSource>,
            }
            #[derive(Serialize)]
            struct ProjectRoles {
                project_id: String,
                project_auto_merge: bool,
                effective_roles: Vec<EffectiveRole>,
            }
            #[derive(Serialize)]
            struct MergePolicyReport {
                auto_merge: bool,
                method: Option<crate::domain::types::MergeMethod>,
                executor: Option<crate::domain::types::MergeExecutor>,
                required_checks: Vec<String>,
                required_approvals: u32,
                allowed_check_conclusions: Vec<crate::domain::types::CommitConclusion>,
                minimum_reliability_score: u8,
                hard_gates: [&'static str; 4],
                instructions: Option<String>,
                instructions_sha256: Option<String>,
                instruction_files: Vec<InstructionSource>,
                repository_instruction_files: Vec<InstructionSource>,
            }
            #[derive(Serialize)]
            struct PolicyExplainReport {
                schema_version: u32,
                repository: String,
                snapshot_source: &'static str,
                applied_revision: Option<u64>,
                configuration_digest: String,
                merge_policy: MergePolicyReport,
                projects: Vec<ProjectRoles>,
                capabilities: CapabilityObservation,
                external_services_queried: bool,
            }
            #[derive(Serialize)]
            struct CapabilityObservation {
                status: &'static str,
                reason: &'static str,
            }
            let (_, configured) = load_config(config_path)?;
            let (config, snapshot_source, applied_revision) =
                read_effective_snapshot(config_path, explicit_state_root, configured)?;
            let repository_id =
                crate::domain::ids::RepositoryId::parse(repository).map_err(CliError::usage)?;
            let repo = config
                .config
                .repositories
                .get(&repository_id)
                .ok_or_else(|| {
                    CliError::not_found(format!("Repository `{repository_id}` is not configured"))
                })?;
            let projects = config
                .config
                .projects
                .iter()
                .filter(|(_, project)| project.repositories.contains(&repository_id))
                .map(|(project_id, project)| {
                    let roles =
                        config::effective_project_roles(project_id, &config.config.projects)
                            .map_err(CliError::unexpected)?;
                    let profiles = roles
                        .into_iter()
                        .map(|(role, profile_id)| {
                            let profile = config.profiles.get(&profile_id).ok_or_else(|| {
                                CliError::unexpected(
                                    "effective profile is missing from applied snapshot",
                                )
                            })?;
                            let profile_digest = crate::store::agent_profile_digest(profile)
                                .map_err(CliError::unexpected)?
                                .to_string();
                            let mut instruction_files = profile
                                .instruction_files
                                .iter()
                                .map(|path| instruction_source(&config, path))
                                .collect::<Vec<_>>();
                            if let Some(paths) = repo.role_instruction_files.get(&role) {
                                instruction_files.extend(
                                    paths.iter().map(|path| instruction_source(&config, path)),
                                );
                            }
                            Ok(EffectiveRole {
                                role: format!("{role:?}"),
                                profile_id: profile_id.to_string(),
                                profile_digest,
                                instruction_files,
                            })
                        })
                        .collect::<Result<Vec<_>, CliError>>()?;
                    Ok(ProjectRoles {
                        project_id: project_id.to_string(),
                        project_auto_merge: project.auto_merge,
                        effective_roles: profiles,
                    })
                })
                .collect::<Result<Vec<_>, CliError>>()?;
            let instruction_paths = repo
                .merge
                .instruction_files
                .iter()
                .map(|path| instruction_source(&config, path))
                .collect::<Vec<_>>();
            let repository_instruction_paths = repo
                .instruction_files
                .iter()
                .map(|path| instruction_source(&config, path))
                .collect::<Vec<_>>();
            let inline_digest = repo.merge.instructions.as_deref().map(text_digest);
            let report = PolicyExplainReport {
                schema_version: 1,
                repository: repository_id.to_string(),
                snapshot_source,
                applied_revision,
                configuration_digest: config.digest.to_string(),
                merge_policy: MergePolicyReport {
                    auto_merge: repo.merge.auto_merge,
                    method: repo.merge.method,
                    executor: repo.merge.executor,
                    required_checks: repo.merge.required_checks.clone(),
                    required_approvals: repo.merge.required_approvals,
                    allowed_check_conclusions: repo.merge.allowed_check_conclusions.clone(),
                    minimum_reliability_score: repo.merge.minimum_reliability_score,
                    hard_gates: [
                        "project_and_repository_auto_merge_enabled",
                        "required_checks_succeeded_for_current_revision",
                        "required_approvals_met",
                        "reviewed_revision_matches_merge_revision",
                    ],
                    instructions: repo.merge.instructions.clone(),
                    instructions_sha256: inline_digest,
                    instruction_files: instruction_paths,
                    repository_instruction_files: repository_instruction_paths,
                },
                projects,
                capabilities: CapabilityObservation {
                    status: "not_observed",
                    reason: "policy explain does not contact the forge or inspect a live capability receipt",
                },
                external_services_queried: false,
            };
            if json {
                print_json(&report)
            } else {
                println!(
                    "Repository {} policy from {} snapshot (no external services queried)",
                    repository_id, snapshot_source
                );
                println!(
                    "Automatic merge: {}; method: {:?}; executor: {:?}",
                    repo.merge.auto_merge, repo.merge.method, repo.merge.executor
                );
                println!(
                    "Checks: {:?}; approvals: {}; capabilities: not observed",
                    repo.merge.required_checks, repo.merge.required_approvals
                );
                for source in &report.merge_policy.instruction_files {
                    println!(
                        "Merge instruction: {} ({})",
                        source.path,
                        source.sha256.as_deref().unwrap_or("digest unavailable")
                    );
                }
                for project in &report.projects {
                    for role in &project.effective_roles {
                        println!(
                            "Project {} role {}: profile {} ({})",
                            project.project_id, role.role, role.profile_id, role.profile_digest
                        );
                    }
                }
                Ok(())
            }
        }
    }
}

fn config_diff(
    config_path: Option<&Path>,
    explicit_state_root: Option<&Path>,
    candidate_path: &Path,
    json: bool,
) -> Result<(), CliError> {
    let (source_path, configured) = load_config(config_path)?;
    let (baseline, snapshot_source, applied_revision) =
        read_effective_snapshot(Some(&source_path), explicit_state_root, configured)?;
    let candidate = config::load(candidate_path).map_err(CliError::usage)?;
    #[derive(Serialize)]
    struct SnapshotVersion {
        source: &'static str,
        applied: bool,
        applied_revision: Option<u64>,
        digest: String,
    }
    #[derive(Serialize)]
    struct AssessmentInvalidation {
        status: &'static str,
        reason: &'static str,
    }
    #[derive(Serialize)]
    struct ConfigDiffReport {
        schema_version: u32,
        baseline: SnapshotVersion,
        candidate: SnapshotVersion,
        changes: Vec<ConfigDiffChange>,
        assessment_invalidation: AssessmentInvalidation,
        state_written: bool,
        candidate_applied: bool,
        external_services_queried: bool,
    }
    let mut changes = Vec::<ConfigDiffChange>::new();
    diff_map(
        "project",
        &baseline.config.projects,
        &candidate.config.projects,
        &mut changes,
    )?;
    diff_map(
        "repository",
        &baseline.config.repositories,
        &candidate.config.repositories,
        &mut changes,
    )?;
    diff_map(
        "profile",
        &baseline.profiles,
        &candidate.profiles,
        &mut changes,
    )?;
    diff_map(
        "instruction",
        &instruction_digest_map(&baseline),
        &instruction_digest_map(&candidate),
        &mut changes,
    )?;
    let changes_count = changes.len();
    let report = ConfigDiffReport {
        schema_version: 1,
        baseline: SnapshotVersion {
            source: snapshot_source,
            applied: applied_revision.is_some(),
            applied_revision,
            digest: baseline.digest.to_string(),
        },
        candidate: SnapshotVersion {
            source: "candidate_file",
            applied: false,
            applied_revision: None,
            digest: candidate.digest.to_string(),
        },
        changes,
        assessment_invalidation: AssessmentInvalidation {
            status: "not_established",
            reason: "available read APIs do not expose durable assessment dependencies",
        },
        state_written: false,
        candidate_applied: false,
        external_services_queried: false,
    };
    if json {
        print_json(&report)
    } else {
        println!(
            "Configuration diff: {} changes; baseline={} candidate={}",
            changes_count, snapshot_source, report.candidate.digest
        );
        println!(
            "No configuration or state was changed; assessment invalidation is not established."
        );
        for change in &report.changes {
            println!(
                "{} {}: {} -> {}",
                change.kind,
                change.id,
                change.before_digest.as_deref().unwrap_or("absent"),
                change.candidate_digest.as_deref().unwrap_or("absent")
            );
        }
        Ok(())
    }
}

fn instruction_digest_map(config: &AppliedConfig) -> std::collections::BTreeMap<String, String> {
    let mut paths = std::collections::BTreeSet::new();
    for repository in config.config.repositories.values() {
        paths.extend(repository.instruction_files.iter().cloned());
        paths.extend(repository.merge.instruction_files.iter().cloned());
        for files in repository.role_instruction_files.values() {
            paths.extend(files.iter().cloned());
        }
        if let Some(operations) = &repository.operations {
            paths.extend(operations.instruction_files.iter().cloned());
        }
    }
    for profile in config.profiles.values() {
        paths.extend(profile.instruction_files.iter().cloned());
    }
    paths
        .into_iter()
        .map(|path| {
            let resolved = Path::new(&path);
            let source = config.source_files.iter().find(|source| {
                source.path == path
                    || source.canonical_path == path
                    || source.canonical_path.ends_with(&path)
                    || resolved.is_absolute() && Path::new(&source.canonical_path) == resolved
            });
            let digest = source.map_or_else(
                || "unavailable".to_owned(),
                |source| source.sha256.to_string(),
            );
            (path, digest)
        })
        .collect()
}

fn read_effective_snapshot(
    config_path: Option<&Path>,
    explicit_state_root: Option<&Path>,
    configured: AppliedConfig,
) -> Result<(AppliedConfig, &'static str, Option<u64>), CliError> {
    let source_path = selected_config_path(config_path)?;
    let source_identity = source_path
        .canonicalize()
        .map_err(|error| CliError::usage(error.to_string()))?
        .display()
        .to_string();
    let state_root =
        config::state_root(&configured.config, explicit_state_root).map_err(CliError::usage)?;
    let db = state_root.join("state.sqlite3");
    match std::fs::symlink_metadata(&db) {
        Ok(_) => {
            let snapshot = ConfigStore::open_readonly(&state_root)
                .and_then(|store| store.load_snapshot(&source_identity))
                .map_err(CliError::unavailable)?;
            if let Some(snapshot) = snapshot {
                Ok((
                    snapshot.config,
                    "applied_snapshot",
                    Some(snapshot.revision.0),
                ))
            } else {
                Ok((configured, "configured_snapshot", None))
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok((configured, "configured_snapshot", None))
        }
        Err(error) => Err(CliError::unavailable(error.to_string())),
    }
}

fn serialized_digest<T: Serialize>(value: &T) -> Result<String, CliError> {
    let bytes =
        serde_json::to_vec(value).map_err(|error| CliError::unexpected(error.to_string()))?;
    Ok(text_digest_bytes(&bytes))
}

fn text_digest(text: &str) -> String {
    text_digest_bytes(text.as_bytes())
}

fn text_digest_bytes(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    format!("{:x}", sha2::Sha256::digest(bytes))
}

#[derive(Serialize)]
struct InstructionSource {
    path: String,
    sha256: Option<String>,
    digest_status: &'static str,
}

fn instruction_source(config: &AppliedConfig, path: &str) -> InstructionSource {
    let source = config.source_files.iter().find(|source| {
        source.path == path
            || source.canonical_path == path
            || source.canonical_path.ends_with(path)
    });
    InstructionSource {
        path: path.to_owned(),
        sha256: source.map(|source| source.sha256.to_string()),
        digest_status: if source.is_some() {
            "captured"
        } else {
            "unavailable"
        },
    }
}

#[derive(Serialize)]
struct ConfigDiffChange {
    kind: String,
    id: String,
    before_digest: Option<String>,
    candidate_digest: Option<String>,
}

fn diff_map<K: Ord + std::fmt::Display, T: Serialize>(
    kind: &str,
    before: &std::collections::BTreeMap<K, T>,
    after: &std::collections::BTreeMap<K, T>,
    changes: &mut Vec<ConfigDiffChange>,
) -> Result<(), CliError> {
    let before = before
        .iter()
        .map(|(key, value)| (key.to_string(), value))
        .collect::<std::collections::BTreeMap<_, _>>();
    let after = after
        .iter()
        .map(|(key, value)| (key.to_string(), value))
        .collect::<std::collections::BTreeMap<_, _>>();
    let keys = before
        .keys()
        .chain(after.keys())
        .collect::<std::collections::BTreeSet<_>>();
    for key in keys {
        let old = before.get(key);
        let new = after.get(key);
        let old_digest = old.map(serialized_digest).transpose()?;
        let new_digest = new.map(serialized_digest).transpose()?;
        if old_digest != new_digest {
            changes.push(ConfigDiffChange {
                kind: kind.to_owned(),
                id: key.clone(),
                before_digest: old_digest,
                candidate_digest: new_digest,
            });
        }
    }
    Ok(())
}

fn apply_config(
    config_path: Option<&Path>,
    explicit_state_root: Option<&Path>,
    args: ApplyArgs,
    json: bool,
) -> Result<(), CliError> {
    require_human_context()?;
    let (path, loaded) = load_config(config_path)?;
    let canonical_source = path
        .canonicalize()
        .map_err(|error| CliError::usage(format!("{}: {error}", path.display())))?;
    let identity = canonical_source.display().to_string();
    let state_root =
        config::state_root(&loaded.config, explicit_state_root).map_err(CliError::usage)?;
    let expectation = match (args.bootstrap, args.expected_revision) {
        (true, None) => ExpectedRevision::Bootstrap,
        (false, Some(revision)) => ExpectedRevision::Current(Revision(revision)),
        _ => {
            return Err(CliError::usage(
                "choose exactly one of --bootstrap or --expected-revision",
            ));
        }
    };
    let mut store = match ConfigStore::open(&state_root) {
        Ok(store) => store,
        Err(lock_error) => {
            let status = ConfigStore::status(&state_root).map_err(|_| {
                CliError::unavailable(format!(
                    "cannot acquire controller ownership or validate a live owner: {lock_error}"
                ))
            })?;
            let Some(generation) = status.owner_generation.filter(|_| status.owner_is_live())
            else {
                return Err(CliError::unavailable(format!(
                    "cannot safely submit configuration to an active controller: {lock_error}"
                )));
            };
            let request_id = generated_request_id()?;
            ConfigStore::append_config_apply(
                &state_root,
                &request_id,
                &identity,
                &loaded,
                expectation,
                generation,
            )
            .map_err(CliError::conflict)?;
            let report = serde_json::json!({"accepted":true,"state":"queued","request_id":request_id,"owner_generation":generation,"digest":loaded.digest});
            return if json {
                print_json(&report)
            } else {
                println!(
                    "Queued configuration apply {} for controller generation {}.",
                    request_id, generation
                );
                Ok(())
            };
        }
    };
    let applied = store
        .apply_snapshot(&identity, &loaded, expectation)
        .map_err(CliError::conflict)?;
    #[derive(Serialize)]
    struct Report {
        applied: bool,
        unchanged: bool,
        revision: u64,
        digest: String,
        source_identity: String,
    }
    let report = Report {
        applied: true,
        unchanged: applied.unchanged,
        revision: applied.revision.0,
        digest: applied.digest.to_string(),
        source_identity: identity,
    };
    if json {
        print_json(&report)
    } else {
        println!(
            "Applied configuration revision {} ({})",
            report.revision, report.digest
        );
        Ok(())
    }
}

fn doctor(
    config_path: Option<&Path>,
    selected_project: Option<&str>,
    json: bool,
) -> Result<(), CliError> {
    let (path, loaded) = load_config(config_path)?;
    if let Some(project) = selected_project
        && !loaded
            .config
            .projects
            .keys()
            .any(|key| key.as_str() == project)
    {
        return Err(CliError {
            code: 3,
            message: format!("unknown Project `{project}`"),
        });
    }
    let mut checks = Vec::new();
    checks.push(capability("rex", &loaded.config.runtime.rex_binary));
    checks.push(capability(
        "ticket_adapter",
        &loaded.config.adapters.tickets.command[0],
    ));
    for (name, profile) in &loaded.profiles {
        checks.push(capability(&format!("profile.{name}"), &profile.command[0]));
    }
    for (name, repo) in &loaded.config.repositories {
        for hook in &repo.rex_projects_hooks {
            checks.push(capability(
                &format!("repository.{name}.hook.{}", hook.id),
                &hook.command[0],
            ));
        }
    }
    let report = serde_json::json!({
        "config": path.display().to_string(),
        "project": selected_project,
        "read_only": true,
        "digest": loaded.digest,
        "commands": checks,
        "rex_capabilities": {"status": "not_observed", "message": "doctor does not start Rex; no cached capability receipt is available"},
        "external_calls": 0,
        "state_written": false
    });
    if json {
        print_json(&report)
    } else {
        println!("Configuration: {}", path.display());
        println!("Doctor is read-only; Rex capabilities are not observed in this PR1 build.");
        for command in report["commands"].as_array().into_iter().flatten() {
            println!(
                "{}: {}",
                command["name"].as_str().unwrap_or("command"),
                command["status"].as_str().unwrap_or("unknown")
            );
        }
        Ok(())
    }
}

fn runtime_command(
    config_path: Option<&Path>,
    explicit_state_root: Option<&Path>,
    command: RuntimeCommand,
    rex_server: Option<&str>,
    json: bool,
) -> Result<(), CliError> {
    match command {
        RuntimeCommand::Run {
            once,
            rex_server: command_rex_server,
        } => run_controller(
            config_path,
            explicit_state_root,
            once,
            command_rex_server.as_deref().or(rex_server),
        ),
        RuntimeCommand::Stop { request_id } => {
            let state_root = selected_state_root(config_path, explicit_state_root)?;
            submit_control(
                &state_root,
                request_id.as_deref(),
                ControlCommand {
                    request_id: String::new(),
                    kind: "machine_stop".into(),
                    project_id: None,
                    lifecycle: None,
                    created_at_unix: unix_now_i64()?,
                    applied_config: None,
                },
                json,
            )
        }
    }
}

fn project_command(
    config_path: Option<&Path>,
    explicit_state_root: Option<&Path>,
    command: ProjectCommand,
    json: bool,
) -> Result<(), CliError> {
    match command {
        ProjectCommand::List => project_list(config_path, explicit_state_root, json),
        ProjectCommand::Status { id } => {
            runtime_status(config_path, explicit_state_root, id.as_deref(), json)
        }
        ProjectCommand::Start { id, request_id } => submit_project_lifecycle(
            config_path,
            explicit_state_root,
            &id,
            "running",
            request_id.as_deref(),
            json,
        ),
        ProjectCommand::Pause { id, request_id } => submit_project_lifecycle(
            config_path,
            explicit_state_root,
            &id,
            "paused",
            request_id.as_deref(),
            json,
        ),
        ProjectCommand::Resume { id, request_id } => submit_project_lifecycle(
            config_path,
            explicit_state_root,
            &id,
            "running",
            request_id.as_deref(),
            json,
        ),
        ProjectCommand::Stop { id, request_id } => submit_project_lifecycle(
            config_path,
            explicit_state_root,
            &id,
            "stopped",
            request_id.as_deref(),
            json,
        ),
    }
}

fn ticket_command(
    config_path: Option<&Path>,
    explicit_state_root: Option<&Path>,
    command: TicketCommand,
    json: bool,
) -> Result<(), CliError> {
    match command {
        TicketCommand::List {
            project,
            status,
            limit,
            cursor,
        } => {
            let page = query_ticket_page(
                config_path,
                &project,
                status.as_deref(),
                limit,
                cursor.as_deref(),
            )?;
            if json {
                print_json(&page)
            } else {
                print_ticket_table(&page.tickets);
                if let Some(cursor) = page.next_cursor {
                    println!(
                        "Next page: rex-projects ticket list --project {} --limit {} --cursor {}",
                        project,
                        limit,
                        terminal_safe(&cursor)
                    );
                }
                Ok(())
            }
        }
        TicketCommand::Show { project, id } => {
            let ticket = query_ticket(config_path, &project, &id)?;
            if json {
                print_json(&ticket)
            } else {
                print_ticket_detail(&ticket.ticket);
                for event in ticket.timeline {
                    println!(
                        "{}  {}  {}",
                        terminal_safe(&event.timestamp),
                        terminal_safe(&event.actor),
                        terminal_safe(&event.summary)
                    );
                }
                Ok(())
            }
        }
        TicketCommand::Select {
            project,
            status,
            limit,
            cursor,
            id,
        } => {
            let page = query_ticket_page(
                config_path,
                &project,
                status.as_deref(),
                limit,
                cursor.as_deref(),
            )?;
            if let Some(id) = id {
                let ticket = page
                    .tickets
                    .into_iter()
                    .find(|ticket| ticket.id == id || ticket.key.as_deref() == Some(&id))
                    .ok_or_else(|| {
                        CliError::not_found("selected ticket is not present in this bounded page")
                    })?;
                if json {
                    print_json(&serde_json::json!({"selected": true, "ticket": ticket}))
                } else {
                    print_ticket_identity(&ticket);
                    Ok(())
                }
            } else if json {
                print_json(&ticket_candidates_report(
                    &page.tickets,
                    page.next_cursor.as_deref(),
                ))
            } else if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
                Err(CliError::usage(
                    "ticket select requires a terminal or --id; use --json to list bounded candidates",
                ))
            } else {
                select_ticket_interactively(&page.tickets, page.next_cursor.as_deref())
            }
        }
        TicketCommand::Focus { ticket_run } => {
            require_human_context()?;
            let loaded = load_config(config_path)?.1;
            let state_root =
                config::state_root(&loaded.config, explicit_state_root).map_err(CliError::usage)?;
            let ticket_run = TicketRunId::parse(ticket_run).map_err(CliError::usage)?;
            let mut backend =
                RuntimeDashboardBackend::new(state_root, loaded.config.runtime.rex_binary);
            backend
                .focus_ticket(&ticket_run)
                .map_err(CliError::conflict)?;
            if json {
                print_json(&serde_json::json!({"focused":true,"ticket_run_id":ticket_run}))
            } else {
                println!("Focused {ticket_run}");
                Ok(())
            }
        }
        TicketCommand::View { command } => {
            require_human_context()?;
            let loaded = load_config(config_path)?.1;
            let state_root =
                config::state_root(&loaded.config, explicit_state_root).map_err(CliError::usage)?;
            let mut backend =
                RuntimeDashboardBackend::new(state_root.clone(), loaded.config.runtime.rex_binary);
            let (ticket_run, expected_revision, view_id, pinned) = match command {
                TicketViewCommand::Pin {
                    ticket_run,
                    expected_revision,
                    view_id,
                } => (ticket_run, expected_revision, view_id, true),
                TicketViewCommand::Unpin {
                    ticket_run,
                    expected_revision,
                    view_id,
                } => (ticket_run, expected_revision, view_id, false),
            };
            let ticket_run = TicketRunId::parse(ticket_run).map_err(CliError::usage)?;
            let view_id = Digest::parse(view_id).map_err(CliError::usage)?;
            let owner_generation =
                crate::store::dashboard_projection::active_owner_generation(&state_root)
                    .map_err(CliError::unavailable)?
                    .ok_or_else(|| CliError::unavailable("machine controller is not running"))?;
            let snapshot = backend.snapshot().map_err(CliError::unavailable)?;
            let row = snapshot
                .tickets
                .iter()
                .find(|row| row.ticket_run_id == ticket_run)
                .ok_or_else(|| {
                    CliError::not_found("TicketRun is no longer in the dashboard snapshot")
                })?;
            if row.revision != expected_revision || row.rex_view_id.as_ref() != Some(&view_id) {
                return Err(CliError::conflict(
                    "TicketRun revision or Rex view changed; refresh the dashboard",
                ));
            }
            backend
                .set_pin_for_generation(
                    owner_generation,
                    &ticket_run,
                    expected_revision,
                    &view_id,
                    pinned,
                )
                .map_err(CliError::conflict)?;
            if json {
                print_json(
                    &serde_json::json!({"ticket_run_id":ticket_run,"view_id":view_id,"pinned":pinned}),
                )
            } else {
                println!(
                    "{} Rex view for {ticket_run}",
                    if pinned { "Pinned" } else { "Unpinned" }
                );
                Ok(())
            }
        }
        TicketCommand::Instruct {
            run,
            expected_revision,
            message_file,
            request_id,
        } => {
            require_human_context()?;
            let body = std::fs::read_to_string(&message_file).map_err(|error| {
                CliError::usage(format!("cannot read instruction file: {error}"))
            })?;
            if body.is_empty() || body.len() > 64 * 1024 || body.contains('\0') {
                return Err(CliError::usage(
                    "instruction must be nonempty UTF-8 text no larger than 64 KiB",
                ));
            }
            let state_root = selected_state_root(config_path, explicit_state_root)?;
            let status = ConfigStore::status(&state_root).map_err(CliError::unavailable)?;
            let owner_generation = status.owner_generation.ok_or_else(|| CliError::unavailable("no foreground machine controller is running; start `rex-projects runtime run` first"))?;
            if !status.owner_is_live() {
                return Err(CliError::unavailable(
                    "controller ownership is stale or ambiguous; cannot submit an instruction",
                ));
            }
            let ticket_run_id =
                crate::domain::ids::TicketRunId::parse(run).map_err(CliError::usage)?;
            let request_id = request_id.unwrap_or(generated_request_id()?);
            let mut store =
                ConfigStore::open_control(&state_root).map_err(CliError::unavailable)?;
            let (project_id, namespace, ticket) = store
                .coordinator_instruction_scope(owner_generation, &ticket_run_id)
                .map_err(CliError::usage)?;
            let receipt = store
                .enqueue_coordinator_instruction(
                    owner_generation,
                    &project_id,
                    &ticket_run_id,
                    &namespace,
                    &ticket,
                    expected_revision,
                    &request_id,
                    &body,
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map_err(|error| CliError::unavailable(error.to_string()))?
                        .as_secs() as i64,
                )
                .map_err(CliError::usage)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string(&serde_json::json!({
                        "request_id": request_id,
                        "ticket_run_id": ticket_run_id,
                        "revision": receipt.revision,
                        "coordinator_wake_input_id": receipt.wake_input_id,
                        "supervisor_wake_input_id": receipt.supervisor_wake_input_id,
                        "body_digest": receipt.body_digest,
                        "replayed": receipt.replayed,
                    }))
                    .map_err(|error| CliError::unavailable(error.to_string()))?
                );
            } else {
                println!(
                    "queued Coordinator wake {} and Supervisor notification {} for {}/{} at revision {}{}",
                    receipt.wake_input_id,
                    receipt.supervisor_wake_input_id,
                    namespace,
                    ticket,
                    receipt.revision,
                    if receipt.replayed { " (replayed)" } else { "" }
                );
            }
            Ok(())
        }
        TicketCommand::BlockedReason { project, run } => {
            let state_root = selected_state_root(config_path, explicit_state_root)?;
            let project_id = ProjectId::parse(project).map_err(CliError::usage)?;
            let ticket_run_id = TicketRunId::parse(run).map_err(CliError::usage)?;
            let store = ConfigStore::open_readonly(&state_root).map_err(CliError::unavailable)?;
            let subject = store
                .merge_claim_recovery_subject(&project_id, &ticket_run_id)
                .map_err(CliError::not_found)?;
            let digest = subject.digest().map_err(CliError::unavailable)?;
            let budget_used = store
                .merge_claim_recovery_budget_used(&subject)
                .map_err(CliError::unavailable)?;
            if json {
                print_json(
                    &serde_json::json!({"subject":subject,"subject_digest":digest,"recovery_budget":{"limit":1,"used":budget_used}}),
                )
            } else {
                println!(
                    "Blocked at revision {}: {}",
                    subject.blocked_revision, subject.reason
                );
                println!(
                    "Expected pull request: {}",
                    subject.expected_pull_request_reference
                );
                println!("Recovery subject digest: {digest}");
                println!("Recovery attempt used: {budget_used}");
                Ok(())
            }
        }
        TicketCommand::ResumeMergeDecision {
            project,
            run,
            expected_subject_digest,
            request_id,
        } => {
            require_human_context()?;
            let state_root = selected_state_root(config_path, explicit_state_root)?;
            let project_id = ProjectId::parse(project).map_err(CliError::usage)?;
            let ticket_run_id = TicketRunId::parse(run).map_err(CliError::usage)?;
            let expected_subject_digest =
                Digest::parse(expected_subject_digest).map_err(CliError::usage)?;
            let request_id = request_id.unwrap_or(generated_request_id()?);
            let now_unix = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|error| CliError::unavailable(error.to_string()))?
                .as_secs() as i64;
            let mut store =
                ConfigStore::open_control(&state_root).map_err(CliError::unavailable)?;
            let receipt = store
                .enqueue_merge_claim_recovery(
                    &request_id,
                    &expected_subject_digest,
                    &project_id,
                    &ticket_run_id,
                    now_unix,
                )
                .map_err(CliError::conflict)?;
            if json {
                print_json(
                    &serde_json::json!({"request_id":receipt.request_id,"ticket_run_id":receipt.ticket_run_id,"blocked_revision":receipt.blocked_revision,"subject_digest":receipt.subject_digest,"state":receipt.state,"replayed":receipt.replayed,"message":"queued for controller validation"}),
                )
            } else {
                println!(
                    "Recovery request {}: {}{}",
                    receipt.request_id,
                    if receipt.state == "pending" {
                        "queued for controller validation"
                    } else {
                        receipt.state.as_str()
                    },
                    if receipt.replayed { " (replayed)" } else { "" }
                );
                Ok(())
            }
        }
        TicketCommand::RecoveryStatus { request_id } => {
            let state_root = selected_state_root(config_path, explicit_state_root)?;
            let store = ConfigStore::open_readonly(&state_root).map_err(CliError::unavailable)?;
            let status = store
                .merge_claim_recovery_status(&request_id)
                .map_err(CliError::unavailable)?
                .ok_or_else(|| {
                    CliError::not_found("MergeDecision recovery request was not found")
                })?;
            if json {
                print_json(&status)
            } else {
                println!("Recovery request {}: {}", status.request_id, status.state);
                println!("One-use recovery budget used: {}", status.budget_used);
                if let Some(reason) = status.rejection_reason {
                    println!("Reason: {reason}");
                }
                Ok(())
            }
        }
        TicketCommand::ReleaseClaim {
            namespace,
            ticket,
            ticket_run,
            generation,
            expected_revision,
            reason,
            disposition,
            request_id,
        } => {
            require_human_context()?;
            let state_root = selected_state_root(config_path, explicit_state_root)?;
            let status = ConfigStore::status(&state_root).map_err(CliError::unavailable)?;
            let owner_generation = status.owner_generation.ok_or_else(|| CliError::unavailable("no foreground machine controller is running; start `rex-projects runtime run` first"))?;
            if !status.owner_is_live() {
                return Err(CliError::unavailable(
                    "controller ownership is stale or ambiguous; cannot submit a claim release",
                ));
            }
            let request_id = request_id.unwrap_or(generated_request_id()?);
            let release = crate::store::HumanClaimRelease {
                namespace,
                ticket,
                ticket_run_id: ticket_run,
                generation,
                expected_revision,
                reason,
                disposition: match disposition {
                    ClaimDisposition::Cancel => "cancel".into(),
                },
            };
            ConfigStore::append_human_claim_release(
                &state_root,
                &request_id,
                &release,
                owner_generation,
            )
            .map_err(CliError::conflict)?;
            let report = serde_json::json!({"accepted":true,"request_id":request_id,"state":"queued","owner_generation":owner_generation,"disposition":release.disposition,"ticket_repoll_required":true});
            if json {
                print_json(&report)
            } else {
                println!(
                    "Queued human claim release {} for controller generation {}.",
                    request_id, owner_generation
                );
                println!(
                    "Disposition: cancel the local TicketRun; the controller must repoll the external ticket before claiming it again."
                );
                Ok(())
            }
        }
    }
}

fn ticket_scope_for_project(
    loaded: &AppliedConfig,
    project_text: &str,
) -> Result<(ProjectId, TicketScope), CliError> {
    let project_id = ProjectId::parse(project_text.to_owned()).map_err(CliError::usage)?;
    let project = loaded
        .config
        .projects
        .get(&project_id)
        .ok_or_else(|| CliError::not_found(format!("unknown Project `{project_id}`")))?;
    let values = project
        .ticket_scope
        .iter()
        .map(|(key, value)| {
            value
                .as_str()
                .map(|value| (key.clone(), value.to_owned()))
                .ok_or_else(|| CliError::usage(format!("ticket scope `{key}` must be a string")))
        })
        .collect::<Result<std::collections::BTreeMap<_, _>, _>>()?;
    let scope = TicketScope::new(values).map_err(|error| CliError::usage(error.to_string()))?;
    Ok((project_id, scope))
}

fn query_ticket_page(
    config_path: Option<&Path>,
    project: &str,
    status: Option<&str>,
    limit: u32,
    cursor: Option<&str>,
) -> Result<crate::adapters::tickets::TicketPage, CliError> {
    if !(1..=100).contains(&limit) {
        return Err(CliError::usage(
            "ticket list limit must be between 1 and 100",
        ));
    }
    if cursor.is_some_and(|value| value.len() > 4096 || value.chars().any(char::is_control)) {
        return Err(CliError::usage("ticket cursor is invalid or too long"));
    }
    let (path, loaded) = load_config(config_path)?;
    let (project_id, scope) = ticket_scope_for_project(&loaded, project)?;
    let environment = std::env::vars_os().collect();
    let cwd = path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .canonicalize()
        .map_err(|error| {
            CliError::usage(format!("configuration directory is unavailable: {error}"))
        })?;
    let adapter =
        crate::adapters::tickets::build_ticket_adapter(&loaded.config, &environment, &cwd)
            .map_err(|error| CliError::unavailable(error.to_string()))?;
    let description = adapter
        .describe(ticket_request_id("describe")?)
        .map_err(ticket_adapter_error)?;
    let normalized_status = status.map(parse_normalized_ticket_status).transpose()?;
    adapter
        .list(
            ticket_request_id("list")?,
            Some(project_id),
            TicketListRequest {
                scope,
                status: normalized_status,
                assignee: None,
                project: None,
                milestone: None,
                release: None,
                labels: None,
                query: None,
                cursor: cursor.map(str::to_owned),
                page_size: Some(limit),
                updated_since: None,
            },
        )
        .map_err(ticket_adapter_error)
        .and_then(|page| {
            if page.ticket_namespace != description.ticket_namespace {
                Err(CliError::conflict(
                    "ticket adapter namespace changed during the query",
                ))
            } else {
                Ok(page)
            }
        })
}

fn query_ticket(
    config_path: Option<&Path>,
    project: &str,
    ticket_id: &str,
) -> Result<TicketGetResult, CliError> {
    if ticket_id.is_empty() || ticket_id.len() > 512 || ticket_id.chars().any(char::is_control) {
        return Err(CliError::usage("ticket ID is invalid or too long"));
    }
    let (path, loaded) = load_config(config_path)?;
    let (project_id, scope) = ticket_scope_for_project(&loaded, project)?;
    let environment = std::env::vars_os().collect();
    let cwd = path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .canonicalize()
        .map_err(|error| {
            CliError::usage(format!("configuration directory is unavailable: {error}"))
        })?;
    let adapter =
        crate::adapters::tickets::build_ticket_adapter(&loaded.config, &environment, &cwd)
            .map_err(|error| CliError::unavailable(error.to_string()))?;
    let description = adapter
        .describe(ticket_request_id("describe")?)
        .map_err(ticket_adapter_error)?;
    let result = adapter
        .get(
            ticket_request_id("get")?,
            Some(project_id),
            TicketGetRequest {
                scope,
                ticket_id: ticket_id.to_owned(),
                timeline_limit: Some(20),
            },
        )
        .map_err(ticket_adapter_error)?;
    if result.ticket_namespace != description.ticket_namespace {
        return Err(CliError::conflict(
            "ticket adapter namespace changed during the query",
        ));
    }
    Ok(result)
}

fn ticket_request_id(operation: &str) -> Result<RequestId, CliError> {
    RequestId::new(format!(
        "ticket-cli-{}-{}-{operation}",
        std::process::id(),
        unix_now_i64()?
    ))
    .map_err(CliError::unexpected)
}

fn ticket_adapter_error(error: crate::adapters::tickets::TicketAdapterError) -> CliError {
    match error {
        crate::adapters::tickets::TicketAdapterError::Invalid(message)
        | crate::adapters::tickets::TicketAdapterError::Protocol(message) => {
            CliError::usage(message)
        }
        other => CliError::unavailable(other.to_string()),
    }
}

fn parse_normalized_ticket_status(value: &str) -> Result<NormalizedTicketStatus, CliError> {
    match value {
        "triage" => Ok(NormalizedTicketStatus::Triage),
        "backlog" => Ok(NormalizedTicketStatus::Backlog),
        "ready" | "todo" => Ok(NormalizedTicketStatus::Ready),
        "in-progress" | "in_progress" => Ok(NormalizedTicketStatus::InProgress),
        "in-review" | "in_review" => Ok(NormalizedTicketStatus::InReview),
        "done" => Ok(NormalizedTicketStatus::Done),
        "canceled" | "cancelled" => Ok(NormalizedTicketStatus::Canceled),
        _ => Err(CliError::usage(
            "status must be triage, backlog, ready, in-progress, in-review, done, or canceled",
        )),
    }
}

fn terminal_safe(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() {
                '\u{fffd}'
            } else {
                character
            }
        })
        .collect()
}

fn ticket_label(ticket: &NormalizedTicket) -> String {
    terminal_safe(ticket.key.as_deref().unwrap_or(&ticket.id))
}

fn ticket_status_label(ticket: &NormalizedTicket) -> String {
    terminal_safe(
        ticket
            .status
            .label
            .as_deref()
            .unwrap_or(match ticket.status.value {
                NormalizedTicketStatus::Triage => "Triage",
                NormalizedTicketStatus::Backlog => "Backlog",
                NormalizedTicketStatus::Ready => "ToDo",
                NormalizedTicketStatus::InProgress => "In Progress",
                NormalizedTicketStatus::InReview => "In Review",
                NormalizedTicketStatus::Done => "Done",
                NormalizedTicketStatus::Canceled => "Canceled",
            }),
    )
}

fn ticket_candidates_report(
    tickets: &[NormalizedTicket],
    next_cursor: Option<&str>,
) -> serde_json::Value {
    serde_json::json!({"selected":false,"tickets":tickets,"next_cursor":next_cursor})
}

fn print_ticket_identity(ticket: &NormalizedTicket) {
    println!(
        "{}\t{}\t{}",
        ticket_label(ticket),
        ticket_status_label(ticket),
        terminal_safe(&ticket.title)
    );
}

fn print_ticket_table(tickets: &[NormalizedTicket]) {
    for ticket in tickets {
        print_ticket_identity(ticket);
    }
}

fn print_ticket_detail(ticket: &NormalizedTicket) {
    println!(
        "{} — {}",
        ticket_label(ticket),
        terminal_safe(&ticket.title)
    );
    println!("Status: {}", ticket_status_label(ticket));
    if let Some(url) = &ticket.url {
        println!("URL: {}", terminal_safe(url));
    }
    println!("\n{}", terminal_safe(&ticket.body));
}

fn select_ticket_interactively(
    tickets: &[NormalizedTicket],
    next_cursor: Option<&str>,
) -> Result<(), CliError> {
    if tickets.is_empty() {
        return Err(CliError::not_found("no tickets in this page"));
    }
    print!("{}", render_ticket_selection(tickets));
    if let Some(cursor) = next_cursor {
        println!(
            "More tickets are available; rerun with --cursor {} to view the next page.",
            terminal_safe(cursor)
        );
    }
    print!("Select a numbered choice (1-{}): ", tickets.len());
    io::stdout()
        .flush()
        .map_err(|error| CliError::unavailable(error.to_string()))?;
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|error| CliError::unavailable(error.to_string()))?;
    let index = input
        .trim()
        .parse::<usize>()
        .ok()
        .filter(|index| (1..=tickets.len()).contains(index))
        .ok_or_else(|| CliError::usage("selection must be a listed ticket number"))?;
    let ticket = tickets
        .get(index - 1)
        .ok_or_else(|| CliError::not_found("selection no longer exists"))?;
    print_ticket_identity(ticket);
    Ok(())
}

fn render_ticket_selection(tickets: &[NormalizedTicket]) -> String {
    let mut output = String::new();
    for (index, ticket) in tickets.iter().enumerate() {
        use std::fmt::Write as _;
        let _ = writeln!(
            output,
            "{:>2}) {}\t{}\t{}",
            index + 1,
            ticket_label(ticket),
            ticket_status_label(ticket),
            terminal_safe(&ticket.title)
        );
    }
    output
}

fn provider_command(
    config_path: Option<&Path>,
    explicit_state_root: Option<&Path>,
    command: ProviderCommand,
    json: bool,
) -> Result<(), CliError> {
    require_human_context()?;
    match command {
        ProviderCommand::Status { request_id } => {
            let state_root = selected_state_root(config_path, explicit_state_root)?;
            let store = ConfigStore::open_control(&state_root).map_err(CliError::unavailable)?;
            let job = store
                .provider_qualification_job(&request_id)
                .map_err(CliError::unavailable)?
                .ok_or_else(|| {
                    CliError::not_found(format!(
                        "provider qualification request `{request_id}` was not found"
                    ))
                })?;
            let slot = store
                .provider_qualification_slot(&request_id)
                .map_err(CliError::unavailable)?;
            let (hold_reason, next_safe_action, execution_slot) =
                provider_status_fields(job.status, job.launch_phase, slot.as_ref());
            let report = serde_json::json!({
                "request_id": job.request.request_id,
                "request_digest": job.request_digest,
                "status": job.status,
                "project_id": job.request.project_id,
                "role": job.request.role,
                "profile_id": job.request.profile_id,
                "profile_digest": job.request.profile_digest,
                "config_revision": job.request.config_revision,
                "config_digest": job.request.config_digest,
                "controller_generation": job.controller_generation,
                "qualification_receipt_digest": job.evidence_digest,
                "launch_phase": job.launch_phase.as_str(),
                "hold_reason": hold_reason,
                "environment_snapshot_id": job.environment_snapshot_id,
                "reconcile_pending": job.reconcile_requested_generation == Some(job.controller_generation),
                "execution_slot": execution_slot,
                "next_safe_action": next_safe_action,
                "created_at_unix": job.created_at_unix,
                "updated_at_unix": job.updated_at_unix,
            });
            if json {
                print_json(&report)
            } else {
                println!(
                    "Provider qualification {}: {:?}",
                    job.request.request_id, job.status
                );
                println!(
                    "Project: {}  Role: {:?}",
                    job.request.project_id, job.request.role
                );
                println!(
                    "Profile: {} ({})",
                    job.request.profile_id, job.request.profile_digest
                );
                println!(
                    "Configuration revision: {} ({})",
                    job.request.config_revision, job.request.config_digest
                );
                println!("Launch phase: {:?}", job.launch_phase);
                if let Some(hold_reason) = hold_reason {
                    println!("Held because: {hold_reason}");
                }
                println!("Next safe action: {next_safe_action}");
                if let Some(slot) = slot {
                    println!(
                        "Execution slot: {} / epoch {} / {:?}",
                        slot.slot_index, slot.reservation_epoch, slot.disposition
                    );
                }
                if let Some(digest) = job.evidence_digest {
                    println!("Qualification receipt: {digest}");
                }
                Ok(())
            }
        }
        ProviderCommand::Reconcile { request_id } => {
            let source_path = selected_config_path(config_path)?;
            let state_root = selected_state_root(Some(&source_path), explicit_state_root)?;
            let owner = ConfigStore::status(&state_root).map_err(CliError::unavailable)?;
            let generation = owner.owner_generation.ok_or_else(|| CliError::unavailable(
                "no foreground machine controller is running; start `rex-projects runtime run` first",
            ))?;
            if !owner.owner_is_live() {
                return Err(CliError::unavailable(
                    "controller ownership is stale or ambiguous; cannot queue provider reconciliation",
                ));
            }
            let mut store =
                ConfigStore::open_control(&state_root).map_err(CliError::unavailable)?;
            store
                .queue_provider_qualification_reconcile(generation, &request_id)
                .map_err(CliError::conflict)?;
            let report = serde_json::json!({
                "accepted": true,
                "request_id": request_id,
                "state": "reconcile_queued",
                "controller_generation": generation,
                "effect": "foreground_controller_only",
            });
            if json {
                print_json(&report)
            } else {
                println!("Queued reconciliation for provider qualification {request_id}.");
                println!(
                    "The foreground controller will inspect the saved launch boundary and exact Rex operation label."
                );
                Ok(())
            }
        }
        ProviderCommand::Qualify {
            project,
            role,
            request_id,
        } => {
            let project_id = ProjectId::parse(project).map_err(CliError::usage)?;
            let role = parse_provider_role(&role).ok_or_else(|| {
                CliError::usage("role must be one of supervisor, coordinator, planner, worker, reviewer, merge_decision, operator, or postmortem")
            })?;
            let (source_path, _) = load_config(config_path)?;
            let source_identity = source_path
                .canonicalize()
                .map_err(|error| CliError::usage(format!("{}: {error}", source_path.display())))?
                .display()
                .to_string();
            let state_root = selected_state_root(Some(&source_path), explicit_state_root)?;
            let status = ConfigStore::status(&state_root).map_err(CliError::unavailable)?;
            let owner_generation = status.owner_generation.ok_or_else(|| {
                CliError::unavailable("no foreground machine controller is running; start `rex-projects runtime run` first")
            })?;
            if !status.owner_is_live() {
                return Err(CliError::unavailable(
                    "controller ownership is stale or ambiguous; cannot queue provider qualification",
                ));
            }
            let mut store =
                ConfigStore::open_control(&state_root).map_err(CliError::unavailable)?;
            let current_revision = store
                .current_revision(&source_identity)
                .map_err(CliError::unavailable)?
                .ok_or_else(|| CliError::conflict("configuration has not been applied"))?;
            let snapshot = store
                .load_snapshot(&source_identity)
                .map_err(CliError::unavailable)?
                .ok_or_else(|| CliError::conflict("applied configuration snapshot is missing"))?;
            if snapshot.revision != current_revision {
                return Err(CliError::conflict(
                    "applied configuration revision changed while queuing qualification",
                ));
            }
            let project_config = snapshot
                .config
                .config
                .projects
                .get(&project_id)
                .ok_or_else(|| {
                    CliError::not_found(format!("Project `{project_id}` is not applied"))
                })?;
            let roles = crate::config::effective_project_roles(
                &project_id,
                &snapshot.config.config.projects,
            )
            .map_err(CliError::unexpected)?;
            let profile_id = roles.get(&role).ok_or_else(|| {
                CliError::conflict(format!(
                    "Project `{project_id}` has no effective {role:?} profile"
                ))
            })?;
            let profile = snapshot.config.profiles.get(profile_id).ok_or_else(|| {
                CliError::conflict("effective role profile is missing from applied config")
            })?;
            let profile_digest =
                crate::store::agent_profile_digest(profile).map_err(CliError::unexpected)?;
            if project_config.roles.is_empty() && project_config.role_defaults_from.is_none() {
                return Err(CliError::conflict(
                    "Project has no configured role profiles",
                ));
            }
            let request =
                crate::store::provider_qualification_runtime::ProviderQualificationRequest {
                    request_id: request_id.unwrap_or(generated_request_id()?),
                    project_id: project_id.clone(),
                    role,
                    profile_id: profile_id.clone(),
                    profile_digest,
                    config_revision: snapshot.revision.0,
                    config_digest: snapshot.config.digest.clone(),
                    target: crate::store::provider_qualification_runtime::ProviderQualificationTarget::AppliedProfile,
                };
            let request_digest = store
                .enqueue_provider_qualification(owner_generation, &request)
                .map_err(CliError::conflict)?;
            let report = serde_json::json!({
                "accepted": true,
                "request_id": request.request_id,
                "request_digest": request_digest,
                "project_id": project_id,
                "role": role,
                "profile_id": profile_id,
                "config_revision": snapshot.revision.0,
                "config_digest": snapshot.config.digest,
                "state": "queued",
                "owner_generation": owner_generation,
            });
            if json {
                print_json(&report)
            } else {
                println!(
                    "Queued provider qualification {} for Project {} ({:?}).",
                    request.request_id, project_id, role
                );
                println!(
                    "The foreground Rex controller will run and record the bounded qualification."
                );
                Ok(())
            }
        }
        ProviderCommand::QualifyCandidate {
            project,
            candidate,
            candidate_digest,
            request_id,
        } => {
            use crate::store::provider_qualification_runtime::{
                ProviderQualificationRequest, ProviderQualificationTarget,
            };
            let project_id = ProjectId::parse(project).map_err(CliError::usage)?;
            let candidate_digest =
                crate::domain::ids::Digest::parse(candidate_digest).map_err(CliError::usage)?;
            let (source_path, _) = load_config(config_path)?;
            let source_identity = source_path
                .canonicalize()
                .map_err(|error| CliError::usage(format!("{}: {error}", source_path.display())))?
                .display()
                .to_string();
            let state_root = selected_state_root(Some(&source_path), explicit_state_root)?;
            let status = ConfigStore::status(&state_root).map_err(CliError::unavailable)?;
            let owner_generation = status.owner_generation.ok_or_else(|| CliError::unavailable("no foreground machine controller is running; start `rex-projects runtime run` first"))?;
            if !status.owner_is_live() {
                return Err(CliError::unavailable(
                    "controller ownership is stale or ambiguous; cannot queue provider qualification",
                ));
            }
            let mut store =
                ConfigStore::open_control(&state_root).map_err(CliError::unavailable)?;
            let current_revision = store
                .current_revision(&source_identity)
                .map_err(CliError::unavailable)?
                .ok_or_else(|| CliError::conflict("configuration has not been applied"))?;
            let snapshot = store
                .load_snapshot(&source_identity)
                .map_err(CliError::unavailable)?
                .ok_or_else(|| CliError::conflict("applied configuration snapshot is missing"))?;
            if snapshot.revision != current_revision {
                return Err(CliError::conflict(
                    "applied configuration revision changed while queuing qualification",
                ));
            }
            let package = store
                .learning_candidate_package(&project_id, &candidate, &candidate_digest)
                .map_err(CliError::conflict)?
                .ok_or_else(|| CliError::not_found("exact candidate revision was not found"))?;
            let profile: crate::config::Profile = toml::from_str(
                std::str::from_utf8(
                    package
                        .files
                        .get("config.toml")
                        .ok_or_else(|| CliError::conflict("candidate config.toml is missing"))?,
                )
                .map_err(|error| CliError::conflict(error.to_string()))?,
            )
            .map_err(|error| CliError::conflict(error.to_string()))?;
            let request = ProviderQualificationRequest {
                request_id: request_id.unwrap_or(generated_request_id()?),
                project_id: project_id.clone(),
                role: package.revision.role,
                profile_id: package.profile_id.clone(),
                profile_digest: crate::store::agent_profile_digest(&profile)
                    .map_err(CliError::unexpected)?,
                config_revision: snapshot.revision.0,
                config_digest: snapshot.config.digest.clone(),
                target: ProviderQualificationTarget::Candidate {
                    candidate_id: candidate.clone(),
                    candidate_digest: candidate_digest.clone(),
                },
            };
            let replayed_job = store
                .provider_qualification_job(&request.request_id)
                .map_err(CliError::conflict)?;
            if replayed_job.is_none() {
                store
                    .resolve_provider_qualification_candidate(&request, &snapshot.config)
                    .map_err(CliError::conflict)?;
            }
            let request_digest = store
                .enqueue_provider_qualification(owner_generation, &request)
                .map_err(CliError::conflict)?;
            let state = replayed_job
                .as_ref()
                .map(|job| job.status.as_str())
                .unwrap_or("queued");
            let report = serde_json::json!({
                "accepted": true, "request_id": request.request_id, "request_digest": request_digest,
                "project_id": project_id, "candidate_id": candidate, "candidate_digest": candidate_digest,
                "profile_id": request.profile_id, "profile_digest": request.profile_digest,
                "config_revision": snapshot.revision.0, "config_digest": snapshot.config.digest,
                "state": state, "owner_generation": owner_generation,
            });
            if json {
                print_json(&report)
            } else {
                if replayed_job.is_some() {
                    println!(
                        "Provider qualification {} for candidate {} is {}.",
                        request.request_id, candidate, state
                    );
                } else {
                    println!(
                        "Queued provider qualification {} for candidate {}.",
                        request.request_id, candidate
                    );
                    println!(
                        "The foreground Rex controller will run and record the bounded qualification."
                    );
                }
                Ok(())
            }
        }
    }
}

fn learning_command(
    config_path: Option<&Path>,
    explicit_state_root: Option<&Path>,
    command: LearningCommand,
    rex_server_override: Option<&str>,
    json: bool,
) -> Result<(), CliError> {
    let environment = std::env::vars_os().collect::<std::collections::BTreeMap<_, _>>();
    learning_command_with_environment(
        config_path,
        explicit_state_root,
        command,
        rex_server_override,
        json,
        &environment,
    )
}

fn learning_command_with_environment(
    config_path: Option<&Path>,
    explicit_state_root: Option<&Path>,
    command: LearningCommand,
    rex_server_override: Option<&str>,
    json: bool,
    environment: &std::collections::BTreeMap<std::ffi::OsString, std::ffi::OsString>,
) -> Result<(), CliError> {
    require_human_context()?;
    match command {
        LearningCommand::Trial {
            command:
                TrialCommand::Request {
                    project,
                    candidate,
                    candidate_digest,
                    request_key,
                    matrix_file,
                },
        } => stage_profile_trial_request(
            config_path,
            explicit_state_root,
            TrialRequestInput {
                project,
                candidate,
                candidate_digest,
                request_key,
                matrix_file,
            },
            rex_server_override,
            json,
            environment,
        ),
    }
}

fn stage_profile_trial_request(
    config_path: Option<&Path>,
    explicit_state_root: Option<&Path>,
    request: TrialRequestInput,
    rex_server_override: Option<&str>,
    json: bool,
    environment: &std::collections::BTreeMap<std::ffi::OsString, std::ffi::OsString>,
) -> Result<(), CliError> {
    use crate::launch::RexViewKind;
    use crate::learning_trials::{profile_trial_human_request, profile_trial_review_bundle};
    use std::ffi::OsStr;

    let TrialRequestInput {
        project,
        candidate,
        candidate_digest,
        request_key,
        matrix_file,
    } = request;
    let project_id = ProjectId::parse(project).map_err(CliError::usage)?;
    if candidate.trim().is_empty()
        || candidate.len() > 255
        || candidate.chars().any(char::is_control)
    {
        return Err(CliError::usage("candidate ID is malformed"));
    }
    let requested_digest = Digest::parse(candidate_digest).map_err(CliError::usage)?;
    let matrix_bytes = read_trial_matrix_file(
        &matrix_file,
        crate::learning_trials::INLINE_FIXTURE_MATRIX_MAX_BYTES,
    )
    .map_err(CliError::usage)?;
    let matrix = crate::profile_trial_request::TrialRequestMatrix::parse(&matrix_bytes)
        .map_err(CliError::usage)?;
    let frozen_inputs = matrix.freeze().map_err(CliError::usage)?;
    let (authorization_id, human_request_id) =
        crate::profile_trial_request::stable_ids(&project_id, &request_key)
            .map_err(CliError::usage)?;
    let (source_path, loaded) = load_config(config_path)?;
    let source_identity = source_path
        .canonicalize()
        .map_err(|error| CliError::usage(format!("{}: {error}", source_path.display())))?
        .display()
        .to_string();
    let state_root =
        config::state_root(&loaded.config, explicit_state_root).map_err(CliError::usage)?;
    let owner_status = ConfigStore::status(&state_root).map_err(CliError::unavailable)?;
    let generation = owner_status.owner_generation.ok_or_else(|| {
        CliError::unavailable(
            "no foreground machine controller is running; start `rex-projects runtime run` first",
        )
    })?;
    if !owner_status.owner_is_live() {
        return Err(CliError::unavailable(
            "controller ownership is stale or ambiguous",
        ));
    }
    let search_path = environment
        .get(OsStr::new("PATH"))
        .map(std::env::split_paths)
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    let rex = crate::adapters::rex::RexIdentity::discover(
        Path::new(&loaded.config.runtime.rex_binary),
        &search_path,
        environment,
        rex_server_override,
    )
    .map_err(|error| CliError::unavailable(format!("Rex identity discovery failed: {error}")))?;
    if owner_status.owner_rex_endpoint.as_deref() != Some(rex.endpoint.as_str())
        || owner_status.owner_rex_server_identity.as_deref() != Some(rex.instance_id.as_str())
        || owner_status.owner_rex_session_id.as_deref() != Some(rex.session_id.as_str())
    {
        return Err(CliError::unavailable(
            "current Rex session does not match the foreground controller identity",
        ));
    }
    let mut store = ConfigStore::open_control(&state_root).map_err(CliError::unavailable)?;
    let current_revision = store
        .current_revision(&source_identity)
        .map_err(CliError::unavailable)?
        .ok_or_else(|| CliError::conflict("configuration has not been applied"))?;
    let snapshot = store
        .load_snapshot(&source_identity)
        .map_err(CliError::unavailable)?
        .ok_or_else(|| CliError::conflict("applied configuration snapshot is missing"))?;
    if snapshot.revision != current_revision || snapshot.config.digest != loaded.digest {
        return Err(CliError::conflict(
            "applied configuration changed; apply and retry",
        ));
    }
    let project_config = snapshot
        .config
        .config
        .projects
        .get(&project_id)
        .ok_or_else(|| CliError::not_found(format!("Project `{project_id}` is not applied")))?;
    let package = store
        .learning_candidate_package(&project_id, &candidate, &requested_digest)
        .map_err(CliError::conflict)?
        .ok_or_else(|| CliError::not_found("exact candidate revision was not found"))?;
    if package.revision.digest != requested_digest
        || package.revision.candidate_id != candidate
        || package.revision.project_id != project_id
    {
        return Err(CliError::conflict(
            "candidate package identity does not match the request",
        ));
    }
    let role = package.revision.role;
    let candidate_profile: crate::config::Profile = toml::from_str(
        std::str::from_utf8(
            package
                .files
                .get("config.toml")
                .ok_or_else(|| CliError::conflict("candidate config.toml is missing"))?,
        )
        .map_err(|error| CliError::conflict(error.to_string()))?,
    )
    .map_err(|error| CliError::conflict(error.to_string()))?;
    let metadata: crate::learning::ProfileCandidateMetadata = crate::protocol::parse_unique(
        package
            .files
            .get(crate::learning::PROFILE_CANDIDATE_METADATA_PATH)
            .ok_or_else(|| CliError::conflict("candidate metadata is missing"))?,
    )
    .map_err(CliError::conflict)?;
    if metadata.project_id != project_id
        || metadata.role != role
        || metadata.config_revision != snapshot.revision
        || metadata.config_digest != snapshot.config.digest
    {
        return Err(CliError::conflict(
            "candidate metadata is stale for the applied Project",
        ));
    }
    let base_profile = snapshot
        .config
        .profiles
        .get(&metadata.base_profile_id)
        .ok_or_else(|| CliError::conflict("candidate base profile is missing"))?;
    if !crate::config::effective_project_roles(&project_id, &snapshot.config.config.projects)
        .map_err(CliError::conflict)?
        .get(&role)
        .is_some_and(|id| id == &metadata.base_profile_id)
    {
        let selected_recipe_binding = project_config.operation_matches.iter().any(|matched| {
            snapshot
                .config
                .config
                .operation_recipes
                .get(&matched.recipe)
                .and_then(|recipe| recipe.roles.get(&role))
                == Some(&metadata.base_profile_id)
        });
        if !selected_recipe_binding {
            return Err(CliError::conflict(
                "candidate base profile is not bound to this role by the Project or a selected recipe",
            ));
        }
    }
    let candidate_profile_id = package.profile_id.clone();
    let candidate_profile_digest =
        crate::store::agent_profile_digest(&candidate_profile).map_err(CliError::unexpected)?;
    let qualification_request = crate::store::provider_qualification_runtime::ProviderQualificationRequest {
        request_id: "profile-trial-staging".into(), project_id: project_id.clone(), role,
        profile_id: candidate_profile_id.clone(), profile_digest: candidate_profile_digest.clone(),
        config_revision: snapshot.revision.0, config_digest: snapshot.config.digest.clone(),
        target: crate::store::provider_qualification_runtime::ProviderQualificationTarget::Candidate {
            candidate_id: candidate.clone(), candidate_digest: requested_digest.clone(),
        },
    };
    let candidate_profile = store
        .resolve_profile_trial_candidate(&qualification_request, &snapshot.config)
        .map_err(CliError::conflict)?;
    let base_profile_id = metadata.base_profile_id.clone();
    let baseline = crate::profile_trial_request::profile_snapshot(
        &snapshot.config,
        &base_profile_id,
        &base_profile_id,
        base_profile,
        None,
        None,
    )
    .map_err(CliError::conflict)?;
    let candidate_snapshot = crate::profile_trial_request::profile_snapshot(
        &snapshot.config,
        &candidate_profile_id,
        &base_profile_id,
        &candidate_profile,
        Some(&package.files),
        Some(&metadata.external_sources),
    )
    .map_err(CliError::conflict)?;
    let max_pairs = snapshot
        .config
        .config
        .learning
        .max_trial_pairs_per_revision
        .min(crate::learning::MAX_TRIAL_PAIRS_PER_REVISION);
    let min_inputs = snapshot
        .config
        .config
        .learning
        .min_distinct_trial_inputs
        .max(crate::learning::MIN_DISTINCT_INPUTS);
    let input_digests = frozen_inputs
        .iter()
        .map(|input| (input.input_id.as_str(), &input.input_digest))
        .collect::<std::collections::BTreeMap<_, _>>();
    let distinct_input_digests = matrix
        .pairs
        .iter()
        .filter_map(|pair| input_digests.get(pair.input_id.as_str()).copied())
        .collect::<std::collections::BTreeSet<_>>();
    if matrix.pairs.is_empty()
        || matrix.pairs.len() > max_pairs
        || matrix.pairs.len() > 10
        || distinct_input_digests.len() < min_inputs
    {
        return Err(CliError::conflict(
            "trial matrix exceeds configured pair budget or misses the configured distinct-input digest minimum",
        ));
    }
    if let Some(existing) = store
        .profile_trial_authorization(&authorization_id)
        .map_err(CliError::conflict)?
    {
        if existing.human_request_id != human_request_id
            || existing.project_id != project_id
            || existing.role != role
            || existing.candidate_id != candidate
            || existing.candidate_digest != requested_digest
            || existing.config_revision != snapshot.revision
            || existing.config_digest != snapshot.config.digest
            || existing.inputs != frozen_inputs
            || existing.pairs != matrix.pairs
            || existing.scoped_exception != matrix.scoped_exception
            || existing.baseline != baseline
            || existing.candidate != candidate_snapshot
        {
            return Err(CliError::conflict(
                "request key was reused with different trial content",
            ));
        }
        let old_base_qualification = store
            .provider_qualification(&existing.baseline_qualification_digest)
            .map_err(CliError::conflict)?
            .ok_or_else(|| CliError::conflict("saved baseline qualification receipt is missing"))?;
        let old_candidate_qualification = store
            .provider_qualification(&existing.candidate_qualification_digest)
            .map_err(CliError::conflict)?
            .ok_or_else(|| {
                CliError::conflict("saved candidate qualification receipt is missing")
            })?;
        validate_trial_qualification(
            &store,
            &old_base_qualification,
            &TrialQualificationExpectation {
                project_id: &project_id,
                profile_id: &base_profile_id,
                profile: base_profile,
                profile_digest: &baseline.profile_digest,
                rex_instance: &rex.instance_id,
                candidate_target: None,
            },
        )?;
        validate_trial_qualification(
            &store,
            &old_candidate_qualification,
            &TrialQualificationExpectation {
                project_id: &project_id,
                profile_id: &candidate_profile_id,
                profile: &candidate_profile,
                profile_digest: &candidate_snapshot.profile_digest,
                rex_instance: &rex.instance_id,
                candidate_target: Some((&candidate, &requested_digest)),
            },
        )?;
        let lifecycle = store
            .profile_trial_authorization_lifecycle(&authorization_id)
            .map_err(CliError::conflict)?
            .ok_or_else(|| CliError::conflict("saved profile trial authorization disappeared"))?;
        return if json {
            print_json(
                &serde_json::json!({"accepted":true,"request_id":existing.human_request_id,"authorization_id":existing.authorization_id,"state":lifecycle,"authorization_digest":existing.digest().map_err(CliError::conflict)?}),
            )
        } else {
            println!(
                "Profile trial request {} is already staged ({lifecycle}).",
                existing.human_request_id
            );
            Ok(())
        };
    }
    let baseline_qualification = find_trial_qualification(
        &store,
        &project_id,
        &base_profile_id,
        base_profile,
        &baseline.profile_digest,
        &rex.instance_id,
        None,
    )?;
    let candidate_qualification = find_trial_qualification(
        &store,
        &project_id,
        &candidate_profile_id,
        &candidate_profile,
        &candidate_snapshot.profile_digest,
        &rex.instance_id,
        Some((&candidate, &requested_digest)),
    )?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| CliError::unexpected(error.to_string()))?
        .as_secs();
    let authorization = crate::profile_trial_request::make_authorization(
        crate::profile_trial_request::TrialAuthorizationSeed {
            project_id: project_id.clone(),
            role,
            candidate_id: candidate.clone(),
            candidate_digest: requested_digest.clone(),
            base_profile_id,
            config_revision: snapshot.revision,
            config_digest: snapshot.config.digest.clone(),
            baseline_qualification_digest: baseline_qualification
                .canonical_digest()
                .map_err(CliError::conflict)?,
            candidate_qualification_digest: candidate_qualification
                .canonical_digest()
                .map_err(CliError::conflict)?,
            request_key,
            now_unix: now,
        },
        crate::profile_trial_request::FrozenTrialMatrix {
            baseline,
            candidate: candidate_snapshot,
            inputs: frozen_inputs,
            pairs: matrix.pairs.clone(),
            scoped_exception: matrix.scoped_exception.clone(),
        },
    )
    .map_err(CliError::conflict)?;
    if authorization.authorization_id != authorization_id
        || authorization.human_request_id != human_request_id
    {
        return Err(CliError::unexpected(
            "host request identity derivation changed",
        ));
    }
    {
        let view = store
            .rex_view_history(&project_id)
            .map_err(CliError::conflict)?
            .into_iter()
            .find(|record| {
                record.lifecycle == "active"
                    && record.view.kind == RexViewKind::Supervisor
                    && record.view.rex_server_identity == rex.instance_id
                    && record.view.rex_session_id == rex.session_id
            })
            .map(|record| record.view)
            .ok_or_else(|| {
                CliError::unavailable(
                    "Project has no active Supervisor Rex view in this controller session",
                )
            })?;
        let bundle = profile_trial_review_bundle(&authorization).map_err(CliError::conflict)?;
        let request = profile_trial_human_request(
            human_request_id.clone(),
            &authorization,
            bundle,
            "Review and approve this exact bounded profile trial matrix.".into(),
            authorization.expires_at_unix,
        )
        .map_err(CliError::conflict)?;
        let artifact_root = state_root.join("human-artifacts");
        std::fs::create_dir_all(&artifact_root).map_err(|e| CliError::unexpected(e.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&artifact_root, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| CliError::unexpected(e.to_string()))?;
        }
        let artifact =
            crate::human_runtime::write_runtime_review_artifact(&artifact_root, &request)
                .map_err(|e| CliError::unexpected(e.to_string()))?;
        store
            .prepare_profile_trial_authorization(
                generation,
                &authorization,
                &request,
                &view.view_id,
                &artifact,
                now,
            )
            .map_err(CliError::conflict)?;
        let persisted = store
            .profile_trial_authorization(&authorization_id)
            .map_err(CliError::conflict)?
            .ok_or_else(|| {
                CliError::unexpected("staged profile trial authorization disappeared")
            })?;
        if json {
            print_json(
                &serde_json::json!({"accepted":true,"request_id":human_request_id,"authorization_id":authorization_id,"state":"pending_human_approval","expires_at_unix":persisted.expires_at_unix,"authorization_digest":persisted.digest().map_err(CliError::conflict)?}),
            )
        } else {
            println!(
                "Staged profile trial request {} for human approval.",
                human_request_id
            );
            Ok(())
        }
    }
}

struct TrialQualificationExpectation<'a> {
    project_id: &'a ProjectId,
    profile_id: &'a crate::domain::ids::ProfileId,
    profile: &'a crate::config::Profile,
    profile_digest: &'a Digest,
    rex_instance: &'a str,
    candidate_target: Option<(&'a str, &'a Digest)>,
}

fn find_trial_qualification(
    store: &ConfigStore,
    project_id: &ProjectId,
    profile_id: &crate::domain::ids::ProfileId,
    profile: &crate::config::Profile,
    profile_digest: &Digest,
    rex_instance: &str,
    candidate_target: Option<(&str, &Digest)>,
) -> Result<crate::launch::ProviderQualification, CliError> {
    let receipts = store
        .verified_provider_qualifications(project_id, profile_id, profile_digest, 32)
        .map_err(CliError::conflict)?;
    let expected = TrialQualificationExpectation {
        project_id,
        profile_id,
        profile,
        profile_digest,
        rex_instance,
        candidate_target,
    };
    receipts.into_iter().find(|receipt| validate_trial_qualification(store, receipt, &expected).is_ok())
        .ok_or_else(|| CliError::conflict("no verified qualification matches the exact profile runtime and current Rex instance"))
}

fn validate_trial_qualification(
    store: &ConfigStore,
    receipt: &crate::launch::ProviderQualification,
    expected: &TrialQualificationExpectation<'_>,
) -> Result<(), CliError> {
    let identity = crate::run_step::profile_runtime_identity(expected.profile)
        .map_err(|error| CliError::conflict(error.to_string()))?;
    receipt
        .validate_for_unattended_launch()
        .map_err(CliError::conflict)?;
    if receipt.project_id != *expected.project_id
        || receipt.profile_id != *expected.profile_id
        || receipt.profile_digest != *expected.profile_digest
        || receipt.proof.rex_instance_id != expected.rex_instance
        || receipt.adapter != identity.adapter
        || receipt.executable_path != identity.executable_path.display().to_string()
        || receipt.executable_digest != identity.executable_digest
        || receipt.commit_mode != identity.commit_mode
        || receipt.invocation_options_digest != identity.invocation_options_digest
        || receipt.permission_mode != identity.effective_permission_mode
    {
        return Err(CliError::conflict(
            "qualification receipt does not match the exact trial profile and current Rex instance",
        ));
    }
    if let Some((candidate_id, candidate_digest)) = expected.candidate_target
        && !store
            .provider_qualification_matches_candidate_target(
                &receipt.canonical_digest().map_err(CliError::conflict)?,
                expected.project_id,
                candidate_id,
                candidate_digest,
                expected.profile_id,
                expected.profile_digest,
            )
            .map_err(CliError::conflict)?
    {
        return Err(CliError::conflict(
            "qualification receipt is not bound to the exact candidate revision",
        ));
    }
    Ok(())
}

fn read_trial_matrix_file(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    use std::io::Read;

    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.len() > limit as u64 {
        return Err("trial matrix must be a bounded regular file no larger than 512 KiB".into());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(limit.saturating_add(1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > limit {
        return Err("trial matrix exceeds its byte limit".into());
    }
    Ok(bytes)
}

fn provider_status_fields(
    status: crate::store::provider_qualification_runtime::ProviderQualificationJobStatus,
    phase: crate::store::provider_qualification_runtime::ProviderQualificationLaunchPhase,
    slot: Option<&crate::store::provider_qualification_runtime::ProviderQualificationSlot>,
) -> (
    Option<&'static str>,
    &'static str,
    Option<serde_json::Value>,
) {
    use crate::store::provider_qualification_runtime::{
        ProviderQualificationJobStatus as Status, ProviderQualificationLaunchPhase as Phase,
    };

    let (hold_reason, next_safe_action) = match status {
        Status::Verified => (
            None,
            "no action required; inspect the qualification receipt if details are needed",
        ),
        Status::Failed => (
            None,
            "no retry is available from this terminal request; inspect the failure receipt",
        ),
        Status::Queued => (
            Some("qualification has not been claimed by the controller"),
            "wait for the foreground controller to claim and launch the queued request",
        ),
        Status::Running | Status::Unknown => match phase {
            Phase::LegacyUnknown => (
                Some(
                    "legacy request has no durable evidence proving whether Rex creation was attempted",
                ),
                "keep the existing slot held; inspect retained evidence manually",
            ),
            Phase::NotStarted => (
                Some(
                    "controller stopped before the durable preparation boundary; the prior process may have left ambiguous local preparation",
                ),
                "a human may request reconciliation; the controller will retry only if the deterministic preparation root is absent",
            ),
            Phase::Prepared => (
                Some(
                    "preparation and the original environment handoff are durable; retry is permitted only after exact local validation",
                ),
                "a human may request reconciliation; the controller will validate the saved handoff and retry once",
            ),
            Phase::CreateAttempted => (
                Some(
                    "Rex creation may have happened; retrying creation is forbidden until exact operation-label observation resolves it",
                ),
                "wait for exact-label Rex observation; a second create is forbidden",
            ),
            Phase::Bound => (
                Some(
                    "Rex resource identity is bound, but the qualification result is not terminal",
                ),
                "wait for the bound Rex run and its existing result and cleanup checks",
            ),
        },
    };
    let slot = slot.map(|slot| {
        serde_json::json!({
            "slot_index": slot.slot_index,
            "reservation_epoch": slot.reservation_epoch,
            "controller_generation": slot.controller_generation,
            "disposition": slot.disposition,
        })
    });
    (hold_reason, next_safe_action, slot)
}

fn parse_provider_role(value: &str) -> Option<crate::domain::types::Role> {
    use crate::domain::types::Role;
    match value {
        "supervisor" => Some(Role::Supervisor),
        "coordinator" => Some(Role::Coordinator),
        "planner" => Some(Role::Planner),
        "worker" => Some(Role::Worker),
        "reviewer" => Some(Role::Reviewer),
        "merge_decision" => Some(Role::MergeDecision),
        "operator" => Some(Role::Operator),
        "postmortem" => Some(Role::Postmortem),
        _ => None,
    }
}

fn submit_project_lifecycle(
    config_path: Option<&Path>,
    explicit_state_root: Option<&Path>,
    project: &str,
    lifecycle: &str,
    request_id: Option<&str>,
    json: bool,
) -> Result<(), CliError> {
    require_human_context()?;
    let project_id =
        crate::domain::ids::ProjectId::parse(project.to_owned()).map_err(CliError::usage)?;
    let state_root = selected_state_root(config_path, explicit_state_root)?;
    let status = ConfigStore::status(&state_root).map_err(CliError::unavailable)?;
    if !status.projects.iter().any(|record| record.id == project_id) {
        return Err(CliError::unexpected(format!(
            "Project `{project}` is not registered; start the Rex-owned `runtime run` block after applying configuration"
        )));
    }
    submit_control(
        &state_root,
        request_id,
        ControlCommand {
            request_id: String::new(),
            kind: "project_lifecycle".into(),
            project_id: Some(project_id),
            lifecycle: Some(lifecycle.into()),
            created_at_unix: unix_now_i64()?,
            applied_config: None,
        },
        json,
    )
}

fn submit_control(
    state_root: &Path,
    request_id: Option<&str>,
    command: ControlCommand,
    json: bool,
) -> Result<(), CliError> {
    require_human_context()?;
    let status = ConfigStore::status(state_root).map_err(CliError::unavailable)?;
    let Some(generation) = status.owner_generation else {
        return Err(CliError::unavailable(
            "no foreground machine controller is running; start `rex-projects runtime run` in a Rex-owned block, then retry",
        ));
    };
    if !status.owner_is_live() {
        return Err(CliError::unavailable(
            "controller ownership is stale or ambiguous; do not queue a command until `runtime run` reconciles the owner",
        ));
    }
    let request_id = match request_id {
        Some(value) => value.to_owned(),
        None => generated_request_id()?,
    };
    ConfigStore::append_control(state_root, &request_id, &command, generation)
        .map_err(CliError::conflict)?;
    let report = serde_json::json!({"accepted":true,"request_id":request_id,"owner_generation":generation,"state":"queued"});
    if json {
        print_json(&report)
    } else {
        println!(
            "Queued control request {} for controller generation {}.",
            request_id, generation
        );
        Ok(())
    }
}

fn runtime_status(
    config_path: Option<&Path>,
    explicit_state_root: Option<&Path>,
    project: Option<&str>,
    json: bool,
) -> Result<(), CliError> {
    let state_root = selected_state_root(config_path, explicit_state_root)?;
    let status = ConfigStore::status(&state_root).map_err(CliError::unavailable)?;
    let projects = status.projects.iter().filter(|record| project.is_none_or(|id| record.id.as_str() == id)).map(|record| serde_json::json!({
        "id":record.id.as_str(), "mode":record.mode, "desired_lifecycle":record.desired_lifecycle,
        "observed_lifecycle":record.observed_lifecycle, "project_epoch":record.project_epoch,
        "next_due_at_unix":record.next_due_at_unix, "last_error":record.last_error
    })).collect::<Vec<_>>();
    if let Some(project) = project
        && projects.is_empty()
    {
        return Err(CliError::unexpected(format!(
            "Project `{project}` is not registered"
        )));
    }
    let report = serde_json::json!({
        "schema_version":status.schema_version,
        "observed_at_unix":status.observed_at_unix,
        "freshness":"local_snapshot",
        "owner":{"active":status.owner_is_live(),"generation":status.owner_generation,"pid":status.owner_pid,"started_at_unix":status.owner_started_at_unix,"rex_endpoint":status.owner_rex_endpoint,"rex_server_instance":status.owner_rex_server_identity,"rex_session":status.owner_rex_session_id,"rex_block":status.owner_rex_block_id},
        "projects":projects,
        "pending_commands":status.pending_commands,
        "rejected_commands":status.rejected_commands,
        "pending_effects":status.pending_effects,
        "uncertain_effects":status.uncertain_effects,
        "occupied_slots":status.occupied_slots,
        "machine_shutdown":{"request_id":status.machine_shutdown_request_id,"status":status.machine_shutdown_status,"deadline_unix":status.machine_shutdown_deadline_unix,"error":status.machine_shutdown_error}
    });
    if json {
        print_json(&report)
    } else {
        println!(
            "Controller: {}",
            if status.owner_is_live() {
                "running"
            } else {
                "stopped"
            }
        );
        println!(
            "Snapshot observed at Unix {}. External services are not queried.",
            status.observed_at_unix
        );
        for entry in report["projects"].as_array().into_iter().flatten() {
            println!(
                "{}: desired {}, observed {}",
                entry["id"].as_str().unwrap_or("?"),
                entry["desired_lifecycle"].as_str().unwrap_or("?"),
                entry["observed_lifecycle"].as_str().unwrap_or("?")
            );
        }
        println!(
            "Queued commands: {}; rejected commands: {}; pending effects: {}; uncertain effects: {}; occupied slots: {}",
            status.pending_commands,
            status.rejected_commands,
            status.pending_effects,
            status.uncertain_effects,
            status.occupied_slots
        );
        if let Some(shutdown) = &status.machine_shutdown_status {
            println!(
                "Machine shutdown {}: request {}, deadline {:?}{}",
                shutdown,
                status.machine_shutdown_request_id.as_deref().unwrap_or("?"),
                status.machine_shutdown_deadline_unix,
                status
                    .machine_shutdown_error
                    .as_deref()
                    .map_or_else(String::new, |error| format!("; {error}")),
            );
        }
        Ok(())
    }
}

fn runtime_dashboard(
    config_path: Option<&Path>,
    explicit_state_root: Option<&Path>,
    json: bool,
) -> Result<(), CliError> {
    let (_, loaded) = load_config(config_path)?;
    let state_root =
        config::state_root(&loaded.config, explicit_state_root).map_err(CliError::usage)?;
    let mut backend = RuntimeDashboardBackend::new(state_root, loaded.config.runtime.rex_binary);
    if json {
        let snapshot =
            crate::dashboard::snapshot_json(&mut backend).map_err(CliError::unavailable)?;
        println!("{snapshot}");
        return Ok(());
    }
    crate::dashboard::run(&mut backend).map_err(|error| CliError {
        code: if error.exit_code == 77 { 77 } else { 5 },
        message: error.message,
    })
}

fn selected_state_root(
    config_path: Option<&Path>,
    explicit_state_root: Option<&Path>,
) -> Result<PathBuf, CliError> {
    let (_, loaded) = load_config(config_path)?;
    config::state_root(&loaded.config, explicit_state_root).map_err(CliError::usage)
}

#[derive(Deserialize)]
struct RexWhoAmI {
    endpoint: String,
    instance_id: String,
}

fn discover_rex_binding(
    configured_binary: &str,
    explicit_server: Option<&str>,
) -> Result<(), CliError> {
    let session_id = std::env::var("REX_SESSION").ok();
    let block_id = std::env::var("REX_BLOCK").ok();
    if block_id.is_some() && session_id.is_none() {
        return Err(CliError::conflict(
            "REX_BLOCK is set without REX_SESSION; cannot validate the Rex context",
        ));
    }
    // Direct CLI development outside Rex remains supported. A Rex-owned
    // runtime always carries REX_SESSION; an explicit server also opts in.
    if session_id.is_none() && explicit_server.is_none() {
        return Ok(());
    }
    let search_path = std::env::var_os("PATH")
        .map(|path| std::env::split_paths(&path).collect::<Vec<_>>())
        .unwrap_or_default();
    let rex = resolve_process_executable(Path::new(configured_binary), &search_path)
        .ok_or_else(|| CliError::unavailable("configured Rex CLI executable is unavailable"))?;
    let mut args = Vec::new();
    if let Some(server) = explicit_server {
        if server.is_empty() || server.chars().any(char::is_control) {
            return Err(CliError::usage("--rex-server must be a nonempty URL"));
        }
        args.extend(["--server".into(), server.into()]);
    }
    args.extend(["--autostart=false".into(), "whoami".into(), "--json".into()]);
    let output = run_process(ProcessRequest {
        executable: rex.clone(),
        args,
        stdin: Vec::new(),
        cwd: None,
        clear_environment: false,
        environment: std::env::vars_os().collect(),
        timeout: Duration::from_secs(10),
        shutdown_grace: Duration::from_secs(2),
        stdout_limit: 64 * 1024,
        stderr_tail_limit: 8 * 1024,
    })
    .map_err(|_| CliError::unavailable("Rex whoami could not be started"))?;
    if output.timed_out
        || !output.cleanup_confirmed
        || !output.status.is_some_and(|status| status.success())
        || output.stdout_truncated
    {
        return Err(CliError::unavailable("Rex whoami failed"));
    }
    let who: RexWhoAmI = crate::protocol::parse_unique(&output.stdout)
        .map_err(|_| CliError::unavailable("Rex whoami returned an invalid identity"))?;
    if who.endpoint.trim().is_empty() || who.instance_id.trim().is_empty() {
        return Err(CliError::unavailable(
            "Rex whoami returned an incomplete endpoint or instance ID",
        ));
    }
    if let Some(session_id) = &session_id {
        let transport = RexCliTransport::connect(
            &rex,
            &search_path,
            who.endpoint.clone(),
            who.instance_id.clone(),
            session_id.clone(),
            std::env::vars_os().collect(),
        )
        .map_err(|_| {
            CliError::unavailable("configured Rex server or session could not be verified")
        })?;
        if let Some(block_id) = &block_id {
            transport
                .validate_session_block(block_id)
                .map_err(|_| CliError::unavailable("REX_BLOCK is not present in REX_SESSION"))?;
        }
    }
    Ok(())
}

fn run_controller(
    config_path: Option<&Path>,
    explicit_state_root: Option<&Path>,
    once: bool,
    rex_server_override: Option<&str>,
) -> Result<(), CliError> {
    require_human_context()?;
    let (config_path, loaded) = load_config(config_path)?;
    let canonical_source = config_path
        .canonicalize()
        .map_err(|error| CliError::usage(format!("{}: {error}", config_path.display())))?;
    let config_source = canonical_source.display().to_string();
    let state_root =
        config::state_root(&loaded.config, explicit_state_root).map_err(CliError::usage)?;
    // Resolve and validate Rex before acquiring the machine state lock. The
    // owner projection pins this connection for later dashboard calls.
    discover_rex_binding(&loaded.config.runtime.rex_binary, rex_server_override)?;
    let mut store = ConfigStore::open(&state_root).map_err(CliError::unavailable)?;
    let current = store
        .current_revision(&config_source)
        .map_err(CliError::unexpected)?;
    let Some(revision) = current else {
        return Err(CliError::conflict(
            "configuration is not applied; run `config apply --bootstrap` before starting the foreground controller",
        ));
    };
    let mut snapshot = store
        .load_snapshot(&config_source)
        .map_err(CliError::unexpected)?
        .ok_or_else(|| CliError::conflict("applied configuration snapshot is missing"))?;
    if snapshot.revision != revision || snapshot.config.digest != loaded.digest {
        return Err(CliError::conflict(
            "configuration differs from the applied snapshot; apply the new revision while the controller is stopped",
        ));
    }
    for (project_id, project) in &snapshot.config.config.projects {
        let mode = match project.mode {
            crate::domain::types::ProjectMode::Goal => "goal",
            crate::domain::types::ProjectMode::Operations => "operations",
        };
        let record = ProjectRecord {
            id: project_id.clone(),
            config_source: config_source.clone(),
            config_revision: revision,
            config_digest: snapshot.config.digest.clone(),
            mode: mode.into(),
            goal_revision: project.goal.as_ref().map_or(0, |goal| goal.revision),
            desired_lifecycle: "stopped".into(),
            state_revision: Revision(0),
        };
        store.insert_project(&record).map_err(CliError::conflict)?;
    }
    let process_environment = std::env::vars_os().collect::<std::collections::BTreeMap<_, _>>();
    let search_path = process_environment
        .get(std::ffi::OsStr::new("PATH"))
        .map(std::env::split_paths)
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    let rex_identity = crate::adapters::rex::RexIdentity::discover(
        Path::new(&snapshot.config.config.runtime.rex_binary),
        &search_path,
        &process_environment,
        rex_server_override,
    )
    .map_err(|error| CliError::unavailable(error.to_string()))?;
    let executable_path =
        std::env::current_exe().map_err(|error| CliError::unexpected(error.to_string()))?;
    let executable_bytes =
        std::fs::read(&executable_path).map_err(|error| CliError::unexpected(error.to_string()))?;
    use sha2::{Digest as _, Sha256};
    let executable_digest = format!("{:x}", Sha256::digest(executable_bytes));
    let runtime_executable_digest =
        Digest::parse(executable_digest.clone()).map_err(CliError::usage)?;
    let owner = OwnerMetadata {
        owner_nonce: generated_request_id()?,
        state_root: state_root.display().to_string(),
        config_source: config_source.clone(),
        process_start_identity: process_start_identity()?,
        executable_path: executable_path.display().to_string(),
        executable_digest,
        rex_endpoint: Some(rex_identity.endpoint.clone()),
        rex_server_identity: Some(rex_identity.instance_id.clone()),
        rex_session_id: Some(rex_identity.session_id.clone()),
        rex_block_id: rex_identity.block_id.clone(),
    };
    let mut environment = crate::environment::capture(&snapshot.config.config.runtime.environment)
        .map_err(|error| CliError::unavailable(error.to_string()))?;
    let generation = store.start_owner(&owner).map_err(CliError::unavailable)?;
    let services = crate::runtime_services::RuntimeServices::new(
        &snapshot.config,
        &environment,
        &canonical_source,
        &state_root,
        generation,
        &rex_identity,
        crate::runtime_services::RuntimeExecutable {
            path: &executable_path,
            digest: &runtime_executable_digest,
        },
    );
    let mut services = match services {
        Ok(services) => services,
        Err(error) => {
            let _ = store.stop_owner(generation);
            return Err(CliError::unavailable(error));
        }
    };
    let projection = state_root.join("runtime-owner.json");
    publish_owner_projection(
        &projection,
        generation,
        &owner,
        snapshot.revision.0,
        snapshot.config.digest.as_str(),
    )
    .map_err(CliError::unexpected)?;
    install_stop_signals();
    let mut shutdown = store
        .active_machine_shutdown()
        .map_err(CliError::unavailable)?;
    let mut received_signal = 0;
    loop {
        store
            .heartbeat_owner(generation)
            .map_err(CliError::unavailable)?;
        let signal = STOP_SIGNAL_REQUESTED.swap(0, std::sync::atomic::Ordering::SeqCst);
        if signal != 0 {
            received_signal = signal;
        }
        if !once && signal != 0 && shutdown.is_none() {
            let cause = if signal == libc::SIGINT {
                crate::store::machine_shutdown::MachineShutdownCause::Sigint
            } else {
                crate::store::machine_shutdown::MachineShutdownCause::Sigterm
            };
            shutdown = Some(
                store
                    .begin_signal_shutdown(
                        generation,
                        &generated_request_id()?,
                        cause,
                        unix_now_i64()?,
                        snapshot.config.config.runtime.shutdown_grace_seconds,
                    )
                    .map_err(CliError::unavailable)?,
            );
        }
        if shutdown.is_none() {
            let mut consumed = 0;
            while consumed < 100 {
                if should_defer_controller_work(once) {
                    break;
                }
                let Some(command) = store
                    .process_next_control(
                        generation,
                        snapshot.config.config.runtime.shutdown_grace_seconds,
                    )
                    .map_err(CliError::unexpected)?
                else {
                    break;
                };
                consumed += 1;
                if command.kind == "machine_stop" {
                    shutdown = store
                        .active_machine_shutdown()
                        .map_err(CliError::unavailable)?;
                    break;
                }
                if let Some(applied) = command.applied_config
                    && (applied.revision != snapshot.revision
                        || applied.digest != snapshot.config.digest)
                {
                    snapshot = store.load_snapshot(&config_source).map_err(CliError::unexpected)?
                        .filter(|loaded| loaded.revision == applied.revision && loaded.config.digest == applied.digest)
                        .ok_or_else(|| CliError::unexpected("applied configuration snapshot is missing or does not match its durable receipt"))?;
                    environment =
                        crate::environment::capture(&snapshot.config.config.runtime.environment)
                            .map_err(|error| CliError::unavailable(error.to_string()))?;
                    services = crate::runtime_services::RuntimeServices::new(
                        &snapshot.config,
                        &environment,
                        &canonical_source,
                        &state_root,
                        generation,
                        &rex_identity,
                        crate::runtime_services::RuntimeExecutable {
                            path: &executable_path,
                            digest: &runtime_executable_digest,
                        },
                    )
                    .map_err(CliError::unavailable)?;
                }
            }
        }
        if shutdown.is_none() && should_defer_controller_work(once) {
            // Persist the signal as a machine-stop barrier at the next loop head before
            // another qualifier, effect, or Agent turn can start.
            continue;
        }
        if once && shutdown.is_some() {
            // `--once` is a normal bounded tick. Leave a durable stop barrier for a
            // foreground owner instead of closing parked Agent blocks here.
            break;
        }
        if let Some(intent) = shutdown.as_ref().filter(|_| !once) {
            let now = unix_now_i64()?;
            let issues = services
                .machine_shutdown_tick(&mut store, generation, now, intent.deadline_unix)
                .unwrap_or_else(|error| vec![format!("drain tick: {error}")]);
            let unresolved = store
                .machine_shutdown_unresolved_owners()
                .map_err(CliError::unavailable)?;
            if unresolved == 0 {
                store
                    .set_machine_shutdown_status(
                        generation,
                        &intent.request_id,
                        crate::store::machine_shutdown::MachineShutdownStatus::Stopped,
                        None,
                        now,
                    )
                    .map_err(CliError::unavailable)?;
                shutdown = Some(crate::store::machine_shutdown::MachineShutdown {
                    status: crate::store::machine_shutdown::MachineShutdownStatus::Stopped,
                    last_error: None,
                    ..intent.clone()
                });
                break;
            }
            if now >= intent.deadline_unix {
                let mut details = vec![format!("{unresolved} owned process/slot claim(s) remain")];
                details.extend(issues);
                store
                    .set_machine_shutdown_status(
                        generation,
                        &intent.request_id,
                        crate::store::machine_shutdown::MachineShutdownStatus::Incomplete,
                        Some(&details.join("; ")),
                        now,
                    )
                    .map_err(CliError::unavailable)?;
                shutdown = Some(crate::store::machine_shutdown::MachineShutdown {
                    status: crate::store::machine_shutdown::MachineShutdownStatus::Incomplete,
                    last_error: Some(details.join("; ")),
                    ..intent.clone()
                });
                break;
            }
        }
        if shutdown.is_none() {
            let tick_now = unix_now_i64()?;
            if once {
                crate::engine::factory_runtime::FactoryRuntime::tick_once(
                    &mut store,
                    generation,
                    tick_now,
                    &mut services,
                )
                .map_err(CliError::unavailable)?;
            } else {
                if should_defer_controller_work(once) {
                    continue;
                }
                if let Err(error) = services.tick_provider_qualification_jobs(&mut store, tick_now)
                {
                    eprintln!("rex-projects provider qualification: {error}");
                }
                if should_defer_controller_work(once) {
                    continue;
                }
                let tick = crate::engine::factory_runtime::FactoryRuntime::tick(
                    &mut store,
                    generation,
                    tick_now,
                    &snapshot.config.config,
                    &mut services,
                )
                .map_err(CliError::unavailable)?;
                for error in tick.external_errors {
                    eprintln!("rex-projects runtime: {error}");
                }
            }
        }
        publish_owner_projection(
            &projection,
            generation,
            &owner,
            snapshot.revision.0,
            snapshot.config.digest.as_str(),
        )
        .map_err(CliError::unexpected)?;
        if once && shutdown.is_none() {
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    let stopped = store.stop_owner(generation).map_err(CliError::unavailable);
    if let Err(error) = stopped {
        return Err(CliError::unavailable(error.to_string()));
    }
    let _ = std::fs::remove_file(projection);
    let late_signal = STOP_SIGNAL_REQUESTED.load(std::sync::atomic::Ordering::SeqCst);
    if late_signal != 0 {
        received_signal = late_signal;
    }
    if received_signal == libc::SIGINT {
        return Err(CliError {
            code: 130,
            message: "controller drained after SIGINT".into(),
        });
    }
    if received_signal == libc::SIGTERM {
        return Err(CliError {
            code: 143,
            message: "controller drained after SIGTERM".into(),
        });
    }
    if let Some(intent) = shutdown {
        if intent.status == crate::store::machine_shutdown::MachineShutdownStatus::Incomplete {
            return Err(CliError {
                code: 5,
                message: format!(
                    "controller shutdown incomplete: {}",
                    intent.last_error.as_deref().unwrap_or("owned work remains")
                ),
            });
        }
        println!("Foreground controller drained and stopped.");
        return Ok(());
    }
    if !once {
        println!("Foreground controller stopped after a durable stop request.");
    }
    Ok(())
}

static STOP_SIGNAL_REQUESTED: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

fn should_defer_controller_work(once: bool) -> bool {
    !once && STOP_SIGNAL_REQUESTED.load(std::sync::atomic::Ordering::SeqCst) != 0
}

extern "C" fn request_stop(signal: libc::c_int) {
    STOP_SIGNAL_REQUESTED.store(signal, std::sync::atomic::Ordering::SeqCst);
}

fn install_stop_signals() {
    #[cfg(unix)]
    unsafe {
        libc::signal(
            libc::SIGINT,
            request_stop as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGTERM,
            request_stop as *const () as libc::sighandler_t,
        );
    }
}

fn process_start_identity() -> Result<String, CliError> {
    let value = observed_process_start_identity(std::process::id())
        .ok_or_else(|| CliError::unavailable("cannot observe this process start identity"))?;
    if value.is_empty() {
        return Err(CliError::unavailable("process start identity is empty"));
    }
    Ok(value)
}

impl crate::store::RuntimeStatus {
    pub(crate) fn owner_is_live(&self) -> bool {
        let (Some(pid), Some(expected)) =
            (self.owner_pid, self.owner_process_start_identity.as_deref())
        else {
            return false;
        };
        observed_process_start_identity(pid).as_deref() == Some(expected)
    }
}

pub(crate) fn observed_process_start_identity(pid: u32) -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
        let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
        let found = unsafe {
            libc::proc_pidinfo(
                pid as libc::c_int,
                libc::PROC_PIDTBSDINFO,
                0,
                info.as_mut_ptr().cast(),
                size,
            )
        };
        if found != size {
            return None;
        }
        let info = unsafe { info.assume_init() };
        Some(format!(
            "{}:{}",
            info.pbi_start_tvsec, info.pbi_start_tvusec
        ))
    }
    #[cfg(target_os = "linux")]
    {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let fields = stat.rsplit_once(')')?.1;
        Some(fields.split_whitespace().nth(19)?.to_owned())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = pid;
        None
    }
}

fn publish_owner_projection(
    path: &Path,
    generation: u64,
    owner: &OwnerMetadata,
    config_revision: u64,
    config_digest: &str,
) -> Result<(), String> {
    let updated_at_unix = unix_now_i64().map_err(|error| error.to_string())?;
    let value = serde_json::json!({"schema_version":1,"generation":generation,"pid":std::process::id(),"process_start_identity":owner.process_start_identity,"state_root":owner.state_root,"config_source":owner.config_source,"config_revision":config_revision,"config_digest":config_digest,"executable_path":owner.executable_path,"executable_digest":owner.executable_digest,"rex_endpoint":owner.rex_endpoint,"rex_server_identity":owner.rex_server_identity,"rex_session_id":owner.rex_session_id,"rex_block_id":owner.rex_block_id,"updated_at_unix":updated_at_unix});
    let bytes = serde_json::to_vec(&value).map_err(|error| error.to_string())?;
    let temporary = path.with_extension(format!(
        "json.{}.tmp",
        generated_request_id().map_err(|error| error.message)?
    ));
    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|error| error.to_string())?
    };
    #[cfg(not(unix))]
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|error| error.to_string())?;
    use std::io::Write;
    file.write_all(&bytes).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())?;
    std::fs::rename(&temporary, path).map_err(|error| error.to_string())?;
    Ok(())
}

fn agent_command(command: AgentCommand, json: bool) -> Result<(), CliError> {
    use crate::mailbox::{MailboxCapability, unix_time_now};
    use crate::protocol::RequestEnvelope;
    use serde_json::Value;
    match command {
        AgentCommand::QualificationRun { package } => {
            let result_digest = crate::provider_qualification_run::run_wrapper(&package)
                .map_err(CliError::unavailable)?;
            if json {
                print_json(&serde_json::json!({"result_digest": result_digest}))
            } else {
                println!("Provider qualification turn finished.");
                Ok(())
            }
        }
        AgentCommand::QualificationProbe { package } => {
            crate::provider_qualification_run::run_marker_probe(&package)
                .map_err(CliError::unavailable)?;
            if json {
                print_json(&serde_json::json!({"marker_probe": "complete"}))
            } else {
                println!("Qualification marker probe completed.");
                Ok(())
            }
        }
        AgentCommand::RunStep {
            run,
            package,
            environment_handoff,
        } => {
            let result = crate::run_step_cli::run_step(&run, &package, &environment_handoff)
                .map_err(CliError::unavailable)?;
            if json {
                print_json(&serde_json::json!({
                    "run_id": result.run_id,
                    "result_digest": result.result_digest,
                }))
            } else {
                println!("Completed finite Agent turn {}.", result.run_id);
                Ok(())
            }
        }
        AgentCommand::RunStepSupervisor {
            run,
            package,
            environment_handoff,
            anchor_pid,
            anchor_start_identity,
        } => {
            crate::run_step_cli::run_step_supervisor(
                &run,
                &package,
                &environment_handoff,
                crate::launch::LaunchAnchorIdentity {
                    pid: anchor_pid,
                    start_identity: anchor_start_identity,
                },
            )
            .map_err(CliError::unavailable)?;
            Ok(())
        }
        AgentCommand::TrialStep {
            run,
            package,
            environment_handoff,
        } => {
            let result = crate::trial_step::run_trial_step(&run, &package, &environment_handoff)
                .map_err(CliError::unavailable)?;
            if json {
                print_json(&serde_json::json!({"run_id": run, "result_digest": result}))
            } else {
                println!("Completed profile trial turn {run}.");
                Ok(())
            }
        }
        AgentCommand::Submit {
            control_dir,
            run_id,
            request_id,
            wait_seconds,
        } => {
            if wait_seconds > 5 {
                return Err(CliError::usage(
                    "agent receipt wait is limited to five seconds",
                ));
            }
            let mut bytes = Vec::new();
            let mut input = std::io::stdin();
            let mut input = std::io::Read::take(&mut input, 256 * 1024 + 1);
            std::io::Read::read_to_end(&mut input, &mut bytes)
                .map_err(|error| CliError::unexpected(error.to_string()))?;
            if bytes.len() > 256 * 1024 {
                return Err(CliError::usage("agent request exceeds 256 KiB"));
            }
            let envelope: RequestEnvelope<Value> =
                crate::protocol::parse_unique(&bytes).map_err(CliError::usage)?;
            envelope.validate().map_err(CliError::usage)?;
            if envelope.run_id.as_deref() != Some(run_id.as_str())
                || envelope.request_id.as_str() != request_id
                || envelope.project_id.is_none()
                || envelope.attempt.is_none()
                || envelope.run_epoch.is_none()
                || envelope.expected_subject_revision.is_none()
                || envelope.role.is_none()
                || envelope.request_type.is_none()
            {
                return Err(CliError::usage(
                    "mailbox requests require matching run_id/request_id and complete Project, attempt, epoch, revision, role, and type scope",
                ));
            }
            let capability = MailboxCapability::open_registered_for_run(&run_id, &control_dir)
                .map_err(CliError::unavailable)?;
            let now = unix_time_now().map_err(CliError::unexpected)?;
            let queued = capability
                .queue(&request_id, &bytes, now)
                .map_err(CliError::conflict)?;
            if wait_seconds > 0 {
                let deadline = std::time::Instant::now() + Duration::from_secs(wait_seconds);
                while std::time::Instant::now() < deadline {
                    if let Some(receipt) = capability
                        .read_receipt(&request_id, unix_time_now().map_err(CliError::unexpected)?)
                        .map_err(CliError::unexpected)?
                    {
                        std::io::Write::write_all(&mut std::io::stdout().lock(), &receipt)
                            .map_err(|error| CliError::unexpected(error.to_string()))?;
                        return Ok(());
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
            let report = serde_json::json!({"state":"queued","request_id":request_id,"queue_result":match queued { crate::mailbox::QueueResult::Queued{..} => "queued", crate::mailbox::QueueResult::Duplicate{..} => "duplicate" }});
            if json {
                print_json(&report)
            } else {
                println!(
                    "Request {} is queued; controller receipt is pending.",
                    request_id
                );
                Ok(())
            }
        }
        AgentCommand::ArtifactAdd {
            control_dir,
            run_id,
            path,
            kind,
            schema_version,
            message_id,
            wait_seconds,
        } => agent_artifact_add(
            control_dir,
            run_id,
            path,
            kind,
            schema_version,
            message_id,
            wait_seconds,
            json,
        ),
        AgentCommand::Repository { command } => match command {
            AgentRepositoryCommand::Manifest {
                paths_file,
                output,
                message_id,
                wait_seconds,
            } => agent_repository_manifest(paths_file, output, message_id, wait_seconds, json),
            AgentRepositoryCommand::Commit(args) => {
                agent_repository_commit(control_dir_for_agent()?, run_id_for_agent()?, args, json)
            }
        },
        AgentCommand::Receipt {
            control_dir,
            run_id,
            request_id,
        } => {
            let capability = MailboxCapability::open_registered_for_run(&run_id, &control_dir)
                .map_err(CliError::unavailable)?;
            let receipt = capability
                .read_receipt(&request_id, unix_time_now().map_err(CliError::unexpected)?)
                .map_err(CliError::unexpected)?;
            match receipt {
                Some(bytes) => {
                    std::io::Write::write_all(&mut std::io::stdout().lock(), &bytes)
                        .map_err(|error| CliError::unexpected(error.to_string()))?;
                    Ok(())
                }
                None => Err(CliError::unexpected(
                    "no committed controller receipt exists for this request",
                )),
            }
        }
        AgentCommand::Inbox {
            control_dir,
            run_id,
            after,
        } => {
            let report = agent_inbox_report(
                &control_dir,
                &run_id,
                after,
                std::env::var("REX_PROJECTS_AGENT").as_deref() == Ok("1"),
            )?;
            if json {
                print_json(&report)
            } else {
                println!(
                    "Agent inbox has {} input(s) after {after}.",
                    report["inputs"].as_array().map_or(0, Vec::len)
                );
                Ok(())
            }
        }
    }
}

fn agent_inbox_report(
    control_dir: &Path,
    run_id: &str,
    after: u64,
    factory_agent: bool,
) -> Result<serde_json::Value, CliError> {
    use crate::mailbox::MailboxCapability;

    if !factory_agent {
        return Err(CliError::conflict(
            "agent inbox can only run in a factory Agent context",
        ));
    }
    let capability = MailboxCapability::open_registered_for_run(run_id, control_dir)
        .map_err(CliError::unavailable)?;
    let inputs = crate::agent_api::read_inbox(capability.directory(), run_id, after)
        .map_err(CliError::unavailable)?;
    let next_after = inputs
        .last()
        .map_or(after, |item| after.max(item.wake_input_id));
    Ok(serde_json::json!({
        "run_id": run_id,
        "after": after,
        "next_after": next_after,
        "inputs": inputs,
    }))
}

#[cfg(test)]
pub(crate) fn dispatch_agent_inbox_for_test(args: &[&str]) -> Result<Vec<u8>, String> {
    let cli = Cli::try_parse_from(args.iter().copied()).map_err(|error| error.to_string())?;
    if !cli.json {
        return Err("test inbox dispatch requires --json".into());
    }
    let Command::Agent {
        command:
            AgentCommand::Inbox {
                control_dir,
                run_id,
                after,
            },
    } = cli.command
    else {
        return Err("test inbox dispatch requires `agent inbox`".into());
    };
    let report = agent_inbox_report(&control_dir, &run_id, after, true)
        .map_err(|error| error.to_string())?;
    serde_json::to_vec_pretty(&report).map_err(|error| error.to_string())
}

fn agent_repository_manifest(
    paths_file: PathBuf,
    output: String,
    message_id: String,
    wait_seconds: u64,
    json: bool,
) -> Result<(), CliError> {
    if std::env::var("REX_PROJECTS_AGENT").as_deref() != Ok("1")
        || std::env::var("REX_PROJECTS_ROLE").as_deref() != Ok("worker")
        || std::env::var("REX_PROJECTS_COMMIT_MODE").as_deref() != Ok("host")
    {
        return Err(CliError::conflict(
            "agent repository manifest requires a host-commit Worker launch",
        ));
    }
    let worktree = std::env::var_os("REX_PROJECTS_WORKTREE_PATH")
        .map(PathBuf::from)
        .ok_or_else(|| CliError::conflict("immutable Worker worktree assignment is absent"))?;
    let worktree_id = std::env::var("REX_PROJECTS_WORKTREE_ID")
        .map_err(|_| CliError::conflict("immutable Worker node assignment is absent"))?;
    let request =
        crate::agent_api::RepositoryManifestRequest::from_paths_file(worktree_id, &paths_file)
            .map_err(CliError::usage)?;
    let manifest = request.build(&worktree).map_err(CliError::usage)?;
    crate::agent_api::validate_relative_path(&output).map_err(CliError::usage)?;
    let root = std::env::current_dir()
        .map_err(|error| CliError::unexpected(error.to_string()))?
        .canonicalize()
        .map_err(|error| CliError::unexpected(error.to_string()))?;
    let destination = root.join(&output);
    let parent = destination
        .parent()
        .ok_or_else(|| CliError::usage("manifest output must name a file"))?;
    std::fs::create_dir_all(parent).map_err(|error| CliError::unavailable(error.to_string()))?;
    let canonical_parent = parent
        .canonicalize()
        .map_err(|error| CliError::unavailable(error.to_string()))?;
    if !canonical_parent.starts_with(&root) {
        return Err(CliError::usage(
            "manifest output escapes the Agent workspace",
        ));
    }
    let destination = canonical_parent.join(
        destination
            .file_name()
            .ok_or_else(|| CliError::usage("manifest output must name a file"))?,
    );
    let bytes =
        serde_json::to_vec(&manifest).map_err(|error| CliError::unexpected(error.to_string()))?;
    let control_dir = control_dir_for_agent()?;
    let run_id = run_id_for_agent()?;
    let mailbox =
        crate::mailbox::MailboxCapability::open_registered_for_run(run_id.clone(), &control_dir)
            .map_err(CliError::unavailable)?;
    let created_output = match std::fs::symlink_metadata(&destination) {
        Ok(metadata) => {
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(CliError::conflict(
                    "manifest output already exists and is not a regular file",
                ));
            }
            if std::fs::read(&destination)
                .map_err(|error| CliError::unavailable(error.to_string()))?
                != bytes
            {
                return Err(CliError::conflict(
                    "manifest output already exists with different content",
                ));
            }
            if acknowledged_manifest_receipt(&mailbox, &message_id, &bytes)?.is_none() {
                return Err(CliError::conflict(
                    "manifest output already exists without its matching artifact receipt",
                ));
            }
            false
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&destination)
                .map_err(|error| {
                    CliError::unavailable(format!("create manifest output: {error}"))
                })?;
            std::io::Write::write_all(&mut file, &bytes)
                .map_err(|error| CliError::unavailable(error.to_string()))?;
            true
        }
        Err(error) => return Err(CliError::unavailable(error.to_string())),
    };
    let add_result = agent_artifact_add(
        control_dir.clone(),
        run_id.clone(),
        output,
        AgentArtifactKind::Change,
        1,
        message_id.clone(),
        wait_seconds,
        json,
    );
    if let Ok(()) = add_result
        && acknowledged_manifest_receipt(&mailbox, &message_id, &bytes)?.is_some()
    {
        remove_unchanged_manifest_output(&destination, &bytes)?;
    } else if created_output
        && add_result.is_err()
        && let Ok(now) = crate::mailbox::unix_time_now()
        && matches!(mailbox.has_queued_request(&message_id, now), Ok(false))
    {
        // A failed queue attempt must not strand this invocation's generated output.
        remove_unchanged_manifest_output(&destination, &bytes)?;
    }
    add_result
}

fn remove_unchanged_manifest_output(destination: &Path, bytes: &[u8]) -> Result<(), CliError> {
    match std::fs::symlink_metadata(destination) {
        Ok(metadata)
            if metadata.is_file()
                && !metadata.file_type().is_symlink()
                && std::fs::read(destination)
                    .map_err(|error| CliError::unavailable(error.to_string()))?
                    == bytes =>
        {
            std::fs::remove_file(destination).map_err(|error| {
                CliError::unavailable(format!("remove generated manifest: {error}"))
            })
        }
        Ok(_) => Err(CliError::conflict(
            "manifest output changed during registration; preserved it",
        )),
        Err(error) => Err(CliError::unavailable(error.to_string())),
    }
}

fn acknowledged_manifest_receipt(
    mailbox: &crate::mailbox::MailboxCapability,
    message_id: &str,
    manifest_bytes: &[u8],
) -> Result<Option<Vec<u8>>, CliError> {
    use crate::mailbox::unix_time_now;
    use sha2::Digest as _;

    let Some(receipt) = mailbox
        .read_receipt(message_id, unix_time_now().map_err(CliError::unexpected)?)
        .map_err(CliError::unexpected)?
    else {
        return Ok(None);
    };
    let response: ResponseEnvelope<serde_json::Value> =
        crate::protocol::parse_unique(&receipt).map_err(CliError::unexpected)?;
    response
        .validate_for(&RequestId::new(message_id).map_err(CliError::usage)?)
        .map_err(CliError::unexpected)?;
    let Some(result) = response.result else {
        return Err(CliError::conflict(
            "controller rejected manifest artifact registration",
        ));
    };
    let result: crate::agent_api::ArtifactAddReceipt =
        serde_json::from_value(result).map_err(|error| CliError::unexpected(error.to_string()))?;
    crate::agent_api::validate_relative_path(&result.artifact.path)
        .map_err(CliError::unexpected)?;
    let expected_digest = format!("{:x}", sha2::Sha256::digest(manifest_bytes));
    if result.schema_version != 1
        || result.message_id != message_id
        || result.artifact.kind != crate::engine::orchestration::RoleArtifactKind::Change
        || result.artifact.schema_version != 1
        || result.artifact.digest.as_str() != expected_digest
        || result.artifact.bytes != manifest_bytes.len() as u64
    {
        return Err(CliError::conflict(
            "artifact receipt does not acknowledge this Change manifest",
        ));
    }
    Ok(Some(receipt))
}

fn agent_repository_commit(
    control_dir: PathBuf,
    run_id: String,
    args: AgentRepositoryCommitArgs,
    json: bool,
) -> Result<(), CliError> {
    use crate::mailbox::{MailboxCapability, unix_time_now};
    let AgentRepositoryCommitArgs {
        expected_head,
        manifest_reference_file,
        message_file,
        message_id,
        wait_seconds,
    } = args;
    if wait_seconds > 300 {
        return Err(CliError::usage(
            "repository commit receipt wait is limited to five minutes",
        ));
    }
    let required = |name: &str| {
        std::env::var(name)
            .map_err(|_| CliError::usage(format!("required Agent context `{name}` is absent")))
    };
    if required("REX_PROJECTS_AGENT")? != "1"
        || required("REX_PROJECTS_ROLE")? != "worker"
        || required("REX_PROJECTS_COMMIT_MODE")? != "host"
    {
        return Err(CliError::conflict(
            "agent repository commit requires a host-commit Worker launch",
        ));
    }
    let worktree_id = required("REX_PROJECTS_WORKTREE_ID")?;
    let message =
        std::fs::read(&message_file).map_err(|error| CliError::unavailable(error.to_string()))?;
    if message.len() > 16_000 {
        return Err(CliError::usage("commit message exceeds 16,000 bytes"));
    }
    let commit_message =
        String::from_utf8(message).map_err(|error| CliError::usage(error.to_string()))?;
    let reference_bytes = std::fs::read(&manifest_reference_file)
        .map_err(|error| CliError::unavailable(error.to_string()))?;
    if reference_bytes.len() > 64 * 1024 {
        return Err(CliError::usage("manifest reference exceeds 64 KiB"));
    }
    let manifest: crate::engine::orchestration::RoleArtifactReference =
        crate::protocol::parse_unique(&reference_bytes).map_err(CliError::usage)?;
    let request = crate::agent_api::RepositoryCommitRequest {
        schema_version: 1,
        message_id: message_id.clone(),
        worktree_id,
        expected_head,
        manifest_digest: manifest.digest.clone(),
        manifest,
        commit_message,
    };
    request.validate().map_err(CliError::usage)?;
    let project_id =
        ProjectId::parse(required("REX_PROJECTS_PROJECT_ID")?).map_err(CliError::usage)?;
    let operation_id =
        crate::domain::ids::OperationId::parse(required("REX_PROJECTS_OPERATION_ID")?)
            .map_err(CliError::usage)?;
    let role = serde_json::from_value::<crate::domain::types::Role>(serde_json::Value::String(
        required("REX_PROJECTS_ROLE")?,
    ))
    .map_err(|error| CliError::usage(format!("invalid Agent role context: {error}")))?;
    let attempt = required("REX_PROJECTS_ATTEMPT")?
        .parse::<u32>()
        .map_err(|error| CliError::usage(error.to_string()))?;
    let run_epoch = required("REX_PROJECTS_RUN_EPOCH")?
        .parse::<u64>()
        .map_err(|error| CliError::usage(error.to_string()))?;
    let expected_subject_revision = required("REX_PROJECTS_SUBJECT_REVISION")?
        .parse::<u64>()
        .map_err(|error| CliError::usage(error.to_string()))?;
    let envelope = RequestEnvelope {
        schema_version: crate::protocol::SCHEMA_VERSION,
        request_id: crate::protocol::RequestId::new(message_id.clone()).map_err(CliError::usage)?,
        operation_id: Some(operation_id),
        method: crate::protocol::MethodName::new("repository.commit").map_err(CliError::usage)?,
        project_id: Some(project_id),
        run_id: Some(run_id.clone()),
        attempt: Some(attempt),
        run_epoch: Some(run_epoch),
        expected_subject_revision: Some(expected_subject_revision),
        role: Some(role),
        request_type: Some("repository_commit".into()),
        params: serde_json::to_value(request)
            .map_err(|error| CliError::unexpected(error.to_string()))?,
    };
    let bytes =
        serde_json::to_vec(&envelope).map_err(|error| CliError::unexpected(error.to_string()))?;
    let mailbox = MailboxCapability::open_registered_for_run(run_id, &control_dir)
        .map_err(CliError::unavailable)?;
    mailbox
        .queue(
            &message_id,
            &bytes,
            unix_time_now().map_err(CliError::unexpected)?,
        )
        .map_err(CliError::conflict)?;
    let deadline = std::time::Instant::now() + Duration::from_secs(wait_seconds);
    loop {
        if let Some(receipt) = mailbox
            .read_receipt(&message_id, unix_time_now().map_err(CliError::unexpected)?)
            .map_err(CliError::unexpected)?
        {
            let response: ResponseEnvelope<serde_json::Value> =
                crate::protocol::parse_unique(&receipt).map_err(CliError::unexpected)?;
            response
                .validate_for(
                    &crate::protocol::RequestId::new(message_id.clone())
                        .map_err(CliError::usage)?,
                )
                .map_err(CliError::unexpected)?;
            if let Some(error) = response.error {
                return Err(CliError::conflict(format!(
                    "controller rejected repository.commit: {}",
                    error.message
                )));
            }
            std::io::Write::write_all(&mut std::io::stdout().lock(), &receipt)
                .map_err(|error| CliError::unexpected(error.to_string()))?;
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let pending = serde_json::json!({"state":"queued","request_id":message_id});
    if json {
        print_json(&pending)
    } else {
        println!("Repository commit request is queued; host receipt is pending.");
        Ok(())
    }
}

fn control_dir_for_agent() -> Result<PathBuf, CliError> {
    std::env::var_os("REX_PROJECTS_CONTROL_DIR")
        .map(PathBuf::from)
        .ok_or_else(|| {
            CliError::usage("required Agent context `REX_PROJECTS_CONTROL_DIR` is absent")
        })
}

fn run_id_for_agent() -> Result<String, CliError> {
    std::env::var("REX_PROJECTS_RUN_ID")
        .map_err(|_| CliError::usage("required Agent context `REX_PROJECTS_RUN_ID` is absent"))
}

#[allow(clippy::too_many_arguments)]
fn agent_artifact_add(
    control_dir: PathBuf,
    run_id: String,
    path: String,
    kind: AgentArtifactKind,
    schema_version: u32,
    message_id: String,
    wait_seconds: u64,
    json: bool,
) -> Result<(), CliError> {
    use crate::mailbox::{MailboxCapability, unix_time_now};
    if wait_seconds > 300 {
        return Err(CliError::usage(
            "artifact receipt wait is limited to five minutes",
        ));
    }
    if std::env::var("REX_PROJECTS_AGENT").as_deref() != Ok("1") {
        return Err(CliError::conflict(
            "agent artifact add can only run in a factory Agent context",
        ));
    }
    let required = |name: &str| {
        std::env::var(name)
            .map_err(|_| CliError::usage(format!("required Agent context `{name}` is absent")))
    };
    let project_id =
        ProjectId::parse(required("REX_PROJECTS_PROJECT_ID")?).map_err(CliError::usage)?;
    let operation_id =
        crate::domain::ids::OperationId::parse(required("REX_PROJECTS_OPERATION_ID")?)
            .map_err(CliError::usage)?;
    let role = serde_json::from_value::<crate::domain::types::Role>(serde_json::Value::String(
        required("REX_PROJECTS_ROLE")?,
    ))
    .map_err(|error| CliError::usage(format!("invalid Agent role context: {error}")))?;
    let attempt = required("REX_PROJECTS_ATTEMPT")?
        .parse::<u32>()
        .map_err(|error| CliError::usage(format!("invalid attempt context: {error}")))?;
    let run_epoch = required("REX_PROJECTS_RUN_EPOCH")?
        .parse::<u64>()
        .map_err(|error| CliError::usage(format!("invalid run epoch context: {error}")))?;
    let expected_subject_revision = required("REX_PROJECTS_SUBJECT_REVISION")?
        .parse::<u64>()
        .map_err(|error| CliError::usage(format!("invalid subject revision context: {error}")))?;

    let request = crate::engine::orchestration::ArtifactAddRequest {
        schema_version: 1,
        message_id: message_id.clone(),
        path,
        kind: kind.role_kind(),
        artifact_schema_version: schema_version,
    };
    request.validate().map_err(CliError::usage)?;
    let envelope = RequestEnvelope {
        schema_version: crate::protocol::SCHEMA_VERSION,
        request_id: crate::protocol::RequestId::new(message_id.clone()).map_err(CliError::usage)?,
        operation_id: Some(operation_id),
        method: crate::protocol::MethodName::new("artifact.add").map_err(CliError::usage)?,
        project_id: Some(project_id),
        run_id: Some(run_id.clone()),
        attempt: Some(attempt),
        run_epoch: Some(run_epoch),
        expected_subject_revision: Some(expected_subject_revision),
        role: Some(role),
        request_type: Some("artifact_add".into()),
        params: serde_json::to_value(request)
            .map_err(|error| CliError::unexpected(error.to_string()))?,
    };
    let bytes =
        serde_json::to_vec(&envelope).map_err(|error| CliError::unexpected(error.to_string()))?;
    let mailbox = MailboxCapability::open_registered_for_run(run_id, &control_dir)
        .map_err(CliError::unavailable)?;
    mailbox
        .queue(
            &message_id,
            &bytes,
            unix_time_now().map_err(CliError::unexpected)?,
        )
        .map_err(CliError::conflict)?;
    let deadline = std::time::Instant::now() + Duration::from_secs(wait_seconds);
    loop {
        if let Some(receipt) = mailbox
            .read_receipt(&message_id, unix_time_now().map_err(CliError::unexpected)?)
            .map_err(CliError::unexpected)?
        {
            let response: ResponseEnvelope<serde_json::Value> =
                crate::protocol::parse_unique(&receipt).map_err(CliError::unexpected)?;
            response
                .validate_for(
                    &crate::protocol::RequestId::new(message_id.clone())
                        .map_err(CliError::usage)?,
                )
                .map_err(CliError::unexpected)?;
            if let Some(error) = response.error {
                return Err(CliError::conflict(format!(
                    "controller rejected artifact request: {}",
                    error.message
                )));
            }
            std::io::Write::write_all(&mut std::io::stdout().lock(), &receipt)
                .map_err(|error| CliError::unexpected(error.to_string()))?;
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let pending = serde_json::json!({"state":"queued","request_id":message_id});
    if json {
        print_json(&pending)
    } else {
        println!("Artifact request {message_id} is queued; controller receipt is pending.");
        Ok(())
    }
}

fn human_command(
    config_path: Option<&Path>,
    explicit_state_root: Option<&Path>,
    command: HumanCommand,
    json: bool,
) -> Result<(), CliError> {
    // This is deliberately the first operation: factory-marked Agent blocks cannot inspect the
    // human inbox or enqueue responses, even when invoked with malformed arguments.
    require_human_context()?;
    let state_root = selected_state_root(config_path, explicit_state_root)?;
    match command {
        HumanCommand::List { project } => {
            let project = project
                .map(ProjectId::parse)
                .transpose()
                .map_err(CliError::usage)?;
            let requests = ConfigStore::list_human_requests(&state_root, project.as_ref())
                .map_err(CliError::unavailable)?;
            if json {
                print_json(&serde_json::json!({"requests":requests}))
            } else if requests.is_empty() {
                println!("No human requests.");
                Ok(())
            } else {
                for summary in requests {
                    println!(
                        "{}  {:?}  {:?}  {}",
                        summary.request.request_id,
                        summary.request.purpose,
                        summary.lifecycle,
                        summary.request.subject.subject_id
                    );
                }
                Ok(())
            }
        }
        HumanCommand::Show { request_id } => {
            let request_id = HumanRequestId::parse(request_id).map_err(CliError::usage)?;
            let summary = ConfigStore::read_human_request(&state_root, &request_id)
                .map_err(CliError::unavailable)?
                .ok_or_else(|| CliError::not_found("human request was not found"))?;
            if json {
                print_json(
                    &serde_json::to_value(summary)
                        .map_err(|error| CliError::unexpected(error.to_string()))?,
                )
            } else {
                println!("Request: {}", summary.request.request_id);
                println!(
                    "Purpose: {:?} ({:?})",
                    summary.request.purpose, summary.lifecycle
                );
                println!(
                    "Subject: {} revision {}",
                    summary.request.subject.subject_id, summary.request.subject.revision.0
                );
                println!(
                    "Digest: {}",
                    summary
                        .request
                        .subject
                        .digest()
                        .map_err(CliError::unexpected)?
                );
                println!("Expires: {}", summary.request.expires_at_unix);
                println!("Review artifact: {}", summary.bundle_path);
                if let Some(reference) = summary.presentation_reference {
                    println!("Presenter: {reference}");
                }
                Ok(())
            }
        }
        HumanCommand::Respond {
            request_id,
            subject_digest,
            choice,
            explanation,
            response_id,
        } => {
            let request_id = HumanRequestId::parse(request_id).map_err(CliError::usage)?;
            let expected_subject_digest = Digest::parse(subject_digest).map_err(CliError::usage)?;
            let choice = match choice {
                HumanChoiceArg::Approve => crate::human_runtime::HumanDecisionChoice::Approve,
                HumanChoiceArg::RequestChanges => {
                    crate::human_runtime::HumanDecisionChoice::RequestChanges
                }
                HumanChoiceArg::RevisePlan => crate::human_runtime::HumanDecisionChoice::RevisePlan,
                HumanChoiceArg::Defer => crate::human_runtime::HumanDecisionChoice::Defer,
                HumanChoiceArg::Cancel => crate::human_runtime::HumanDecisionChoice::Cancel,
                HumanChoiceArg::Refuse => crate::human_runtime::HumanDecisionChoice::Refuse,
            };
            let intent = crate::human_runtime::HumanDecisionIntent {
                request_id,
                response_id: response_id.unwrap_or(generated_request_id()?),
                expected_subject_digest,
                choice,
                explanation: Some(explanation),
            };
            let queued = ConfigStore::enqueue_human_decision(
                &state_root,
                &intent,
                unix_now_i64()?.try_into().unwrap_or(u64::MAX),
            )
            .map_err(CliError::conflict)?;
            let report = serde_json::json!({"state":"queued_for_validation","request_id":queued.request_id,"response_id":queued.response_id,"accepted_for_validation":queued.accepted_for_validation,"note":"The controller must re-observe the exact subject before this response becomes authoritative."});
            if json {
                print_json(&report)
            } else {
                println!(
                    "Response {} queued for controller validation.",
                    queued.response_id
                );
                println!(
                    "This is not yet an approval; the controller must verify the current subject."
                );
                Ok(())
            }
        }
    }
}

fn knowledge_command(
    config_path: Option<&Path>,
    explicit_state_root: Option<&Path>,
    command: KnowledgeCommand,
    json: bool,
) -> Result<(), CliError> {
    if std::env::var_os("REX_PROJECTS_AGENT").is_some()
        || std::env::var_os("REX_PROJECTS_CONTEXT").is_some()
    {
        return Err(CliError::human_only(
            "knowledge browsing is available only from a human host context",
        ));
    }
    let (config_path, loaded) = load_config(config_path)?;
    let knowledge = loaded
        .config
        .knowledge
        .as_ref()
        .ok_or_else(|| CliError::usage("knowledge is not configured"))?;
    if knowledge.format != "okf" {
        return Err(CliError::usage(
            "knowledge browse and validate currently support the configured OKF format only",
        ));
    }
    let root = PathBuf::from(knowledge.root.as_str());
    let root = if root.is_absolute() {
        root
    } else {
        let config_path = config_path
            .canonicalize()
            .map_err(|error| CliError::usage(format!("{}: {error}", config_path.display())))?;
        config_path
            .parent()
            .ok_or_else(|| CliError::usage("configuration file has no parent directory"))?
            .join(root)
    };
    let project = match &command {
        KnowledgeCommand::List { project }
        | KnowledgeCommand::Show { project, .. }
        | KnowledgeCommand::Validate { project, .. } => {
            ProjectId::parse(project.clone()).map_err(CliError::usage)?
        }
    };
    let ticket_run = match &command {
        KnowledgeCommand::Show { ticket_run, .. }
        | KnowledgeCommand::Validate { ticket_run, .. } => Some(
            crate::domain::ids::TicketRunId::parse(ticket_run.clone()).map_err(CliError::usage)?,
        ),
        KnowledgeCommand::List { .. } => None,
    };
    let state_root =
        config::state_root(&loaded.config, explicit_state_root).map_err(CliError::usage)?;
    let store = ConfigStore::open_readonly(&state_root).map_err(CliError::unavailable)?;
    let records = store
        .published_knowledge(&project, ticket_run.as_ref(), 100)
        .map_err(CliError::unavailable)?;
    match command {
        KnowledgeCommand::List { .. } => {
            let entries = records
                .iter()
                .map(|record| {
                    serde_json::json!({
                        "project_id": record.manifest.project_id,
                        "ticket_run_id": record.manifest.ticket_run_id,
                        "title": bounded_knowledge_title(&record.input.title),
                        "generated_at": record.input.generated_at,
                        "source_digests": record.manifest.source_digests,
                        "content_sha256": record.manifest.content_sha256,
                        "byte_count": record.manifest.byte_count,
                        "manifest_sha256": record.manifest_digest,
                    })
                })
                .collect::<Vec<_>>();
            if json {
                print_json(&serde_json::json!({"project_id": project, "publications": entries}))
            } else if entries.is_empty() {
                println!("No knowledge publications for Project {}.", project);
                Ok(())
            } else {
                for record in records {
                    println!(
                        "{}  {}  {}  ({} sources)",
                        record.manifest.ticket_run_id,
                        record.input.generated_at,
                        terminal_safe_text(&bounded_knowledge_title(&record.input.title)),
                        record.input.sources.len()
                    );
                }
                Ok(())
            }
        }
        KnowledgeCommand::Show { .. } => {
            let record = records
                .into_iter()
                .next()
                .ok_or_else(|| CliError::not_found("knowledge publication was not found"))?;
            let article = crate::knowledge::validate_publication(
                &root,
                &record.input,
                &record.manifest,
                &record.manifest_digest,
            )
            .map_err(|error| CliError::conflict(error.to_string()))?;
            if json {
                let sources = record
                    .input
                    .sources
                    .iter()
                    .map(|source| {
                        serde_json::json!({
                            "id": source.id,
                            "title": source.title,
                            "resource": source.resource,
                            "digest": source.digest,
                            "trusted": source.trusted,
                        })
                    })
                    .collect::<Vec<_>>();
                print_json(&serde_json::json!({
                    "project_id": project,
                    "ticket_run_id": record.manifest.ticket_run_id,
                    "title": record.input.title,
                    "summary": record.input.summary,
                    "generated_at": record.input.generated_at,
                    "sources": sources,
                    "manifest": record.manifest,
                    "manifest_sha256": record.manifest_digest,
                    "article": article,
                }))
            } else {
                println!(
                    "{} — {}\nGenerated: {}\nSources: {}\nReceipt: {}\n",
                    terminal_safe_text(&record.input.title),
                    record.manifest.ticket_run_id,
                    record.input.generated_at,
                    record.input.sources.len(),
                    record.manifest.content_sha256
                );
                print!("{}", terminal_safe_text(&article));
                Ok(())
            }
        }
        KnowledgeCommand::Validate { .. } => {
            let record = records
                .into_iter()
                .next()
                .ok_or_else(|| CliError::not_found("knowledge publication was not found"))?;
            let article = crate::knowledge::validate_publication(
                &root,
                &record.input,
                &record.manifest,
                &record.manifest_digest,
            )
            .map_err(|error| CliError::conflict(error.to_string()))?;
            let report = serde_json::json!({
                "valid": true,
                "project_id": project,
                "ticket_run_id": record.manifest.ticket_run_id,
                "format": record.manifest.format,
                "content_sha256": record.manifest.content_sha256,
                "byte_count": article.len(),
                "source_count": record.input.sources.len(),
                "manifest_sha256": record.manifest_digest,
            });
            if json {
                print_json(&report)
            } else {
                println!(
                    "Valid {} publication {} ({} bytes, {} sources).",
                    record.manifest.format,
                    record.manifest.ticket_run_id,
                    article.len(),
                    record.input.sources.len()
                );
                Ok(())
            }
        }
    }
}

fn terminal_safe_text(value: &str) -> String {
    let mut safe = String::with_capacity(value.len());
    for character in value.chars() {
        let bidi_control = matches!(
            character,
            '\u{061c}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
        );
        if (character.is_control() && character != '\n') || bidi_control {
            use std::fmt::Write as _;
            write!(safe, "\\u{{{:x}}}", character as u32).expect("writing to String cannot fail");
        } else {
            safe.push(character);
        }
    }
    safe
}

fn bounded_knowledge_title(value: &str) -> String {
    const MAX_CHARS: usize = 256;
    let mut chars = value.chars();
    let mut title = chars.by_ref().take(MAX_CHARS).collect::<String>();
    if chars.next().is_some() {
        title.push('…');
    }
    title
}

fn unix_now_i64() -> Result<i64, CliError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs().try_into().unwrap_or(i64::MAX))
        .map_err(|error| CliError::unexpected(error.to_string()))
}

fn generated_request_id() -> Result<String, CliError> {
    Ok(format!(
        "{}-{}-{}",
        std::process::id(),
        unix_now_i64()?,
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| CliError::unexpected(error.to_string()))?
            .subsec_nanos()
    ))
}

fn capability(name: &str, executable: &str) -> serde_json::Value {
    match resolve_executable(executable) {
        Some(path) => {
            serde_json::json!({"name":name,"executable":executable,"resolved_path":path,"status":"available_not_probed"})
        }
        None => serde_json::json!({"name":name,"executable":executable,"status":"missing"}),
    }
}

fn resolve_executable(value: &str) -> Option<PathBuf> {
    let path = Path::new(value);
    if path.components().count() > 1 || path.is_absolute() {
        return executable_file(path)
            .then(|| path.canonicalize().ok())
            .flatten();
    }
    let search = std::env::var_os("PATH")?;
    std::env::split_paths(&search).find_map(|directory| {
        if directory.as_os_str().is_empty() {
            return None;
        }
        let candidate = directory.join(path);
        executable_file(&candidate)
            .then(|| candidate.canonicalize().ok())
            .flatten()
    })
}

#[cfg(unix)]
fn executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn executable_file(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|metadata| metadata.is_file())
}

#[cfg(test)]
pub(crate) fn dispatch_ticket_command_for_test(args: &[&str]) -> Result<(), CliError> {
    let cli = Cli::try_parse_from(args).map_err(|error| CliError::usage(error.to_string()))?;
    let Command::Ticket { command } = cli.command else {
        return Err(CliError::usage("test command must select `ticket`"));
    };
    ticket_command(
        cli.config.as_deref(),
        cli.state_root.as_deref(),
        command,
        cli.json,
    )
}

#[cfg(test)]
fn dispatch_provider_command_for_test(args: &[&str]) -> Result<(), CliError> {
    let cli = Cli::try_parse_from(args).map_err(|error| CliError::usage(error.to_string()))?;
    let Command::Provider { command } = cli.command else {
        return Err(CliError::usage("test command must select `provider`"));
    };
    provider_command(
        cli.config.as_deref(),
        cli.state_root.as_deref(),
        command,
        cli.json,
    )
}

#[cfg(test)]
fn dispatch_learning_command_with_environment_for_test(
    args: &[&str],
    environment: &std::collections::BTreeMap<std::ffi::OsString, std::ffi::OsString>,
) -> Result<(), CliError> {
    let cli = Cli::try_parse_from(args).map_err(|error| CliError::usage(error.to_string()))?;
    let Command::Learning { command } = cli.command else {
        return Err(CliError::usage("test command must select `learning`"));
    };
    learning_command_with_environment(
        cli.config.as_deref(),
        cli.state_root.as_deref(),
        command,
        cli.rex_server.as_deref(),
        cli.json,
        environment,
    )
}

fn version(json: bool) -> Result<(), CliError> {
    if json {
        let report = VersionInfo {
            name: "rex-projects".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            target: option_env!("REX_PROJECTS_BUILD_TARGET")
                .unwrap_or("unknown")
                .into(),
            cli_protocol: 1,
            database_schema: crate::store::SCHEMA_VERSION as u32,
            source_revision: crate::BUILD_SOURCE_REVISION.map(str::to_owned),
            dirty: option_env!("REX_PROJECTS_BUILD_DIRTY") == Some("true"),
        };
        print_json(&report)
    } else {
        println!("rex-projects {}", env!("CARGO_PKG_VERSION"));
        Ok(())
    }
}

fn schema(kind: SchemaKind) -> Result<(), CliError> {
    let name = match kind {
        SchemaKind::Config => "config",
        SchemaKind::Profile => "profile",
        SchemaKind::Request => "request",
        SchemaKind::Response => "response",
        SchemaKind::Version => "version",
    };
    let value = schema_documents()
        .into_iter()
        .find_map(|(candidate, value)| (candidate == name).then_some(value))
        .expect("selected schema is registered");
    print_json(&value)
}

pub fn schema_documents() -> Vec<(&'static str, serde_json::Value)> {
    vec![
        ("config", config::schema::<Config>()),
        ("profile", config::schema::<config::Profile>()),
        (
            "request",
            config::schema::<RequestEnvelope<serde_json::Value>>(),
        ),
        (
            "response",
            config::schema::<ResponseEnvelope<serde_json::Value>>(),
        ),
        ("version", config::schema::<VersionInfo>()),
    ]
}

#[derive(serde::Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct VersionInfo {
    name: String,
    version: String,
    target: String,
    cli_protocol: u32,
    database_schema: u32,
    source_revision: Option<String>,
    dirty: bool,
}

fn print_json<T: Serialize>(value: &T) -> Result<(), CliError> {
    let text = serde_json::to_string_pretty(value)
        .map_err(|error| CliError::unexpected(error.to_string()))?;
    println!("{text}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::{
        Cli, Command, ProviderCommand, STOP_SIGNAL_REQUESTED, TicketCommand,
        factory_context_present, read_effective_snapshot, read_trial_matrix_file,
        resolve_executable, should_defer_controller_work, terminal_safe,
    };
    use crate::config;
    use crate::store::{ConfigStore, ExpectedRevision};

    #[test]
    fn foreground_signal_defers_new_work_but_once_keeps_its_existing_semantics() {
        STOP_SIGNAL_REQUESTED.store(libc::SIGTERM, std::sync::atomic::Ordering::SeqCst);
        assert!(should_defer_controller_work(false));
        assert!(
            !should_defer_controller_work(true),
            "--once does not adopt the foreground signal-drain behavior"
        );
        STOP_SIGNAL_REQUESTED.store(0, std::sync::atomic::Ordering::SeqCst);
    }

    #[test]
    fn trial_matrix_reader_rejects_symlinks_oversize_and_fifos() {
        let temp = tempfile::tempdir().unwrap();
        let regular = temp.path().join("matrix.json");
        std::fs::write(&regular, b"{}").unwrap();
        assert_eq!(read_trial_matrix_file(&regular, 2).unwrap(), b"{}");
        assert!(read_trial_matrix_file(&regular, 1).is_err());
        let symlink = temp.path().join("matrix-link.json");
        std::os::unix::fs::symlink(&regular, &symlink).unwrap();
        assert!(read_trial_matrix_file(&symlink, 16).is_err());
        let fifo = temp.path().join("matrix.fifo");
        let path = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        assert!(
            read_trial_matrix_file(&fifo, 16)
                .unwrap_err()
                .contains("regular file")
        );
    }

    #[test]
    fn candidate_qualification_cli_requires_exact_target_and_has_no_execution_overrides() {
        let cli = Cli::try_parse_from([
            "rex-projects",
            "provider",
            "qualify-candidate",
            "--project",
            "project-a",
            "--candidate",
            "candidate-a",
            "--candidate-digest",
            &"a".repeat(64),
            "--request-id",
            "request-a",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Provider {
                command: ProviderCommand::QualifyCandidate { .. }
            }
        ));
        assert!(
            Cli::try_parse_from([
                "rex-projects",
                "provider",
                "qualify-candidate",
                "--project",
                "project-a",
                "--candidate",
                "candidate-a",
                "--candidate-digest",
                &"a".repeat(64),
                "--profile",
                "anything",
            ])
            .is_err()
        );
    }

    #[test]
    fn trial_request_cli_stages_exact_pending_review_with_fixture_rex_and_rejects_changed_key_content()
     {
        use crate::domain::ids::{Digest, ProjectId, Revision};
        use crate::domain::types::Role;
        use crate::launch::{RexView, RexViewKind};
        use crate::learning::{CandidateRevision, CandidateStatus, ProfileCandidateMetadata};
        use crate::store::{LearningCandidateRecord, OwnerMetadata, ProjectRecord};
        use sha2::{Digest as _, Sha256};
        use std::collections::{BTreeMap, BTreeSet};
        use std::ffi::{OsStr, OsString};
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let fixture_root =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/fixture");
        let config_root = temp.path().join("config");
        std::fs::create_dir_all(config_root.join("profiles")).unwrap();
        let skill_root_a = config_root.join("external-skills/ops-a");
        let skill_root_b = config_root.join("external-skills/ops-b");
        let skill_root_alias = config_root.join("external-skills/skill-alias");
        std::fs::create_dir_all(skill_root_a.join("references")).unwrap();
        std::fs::create_dir_all(&skill_root_b).unwrap();
        std::os::unix::fs::symlink(&skill_root_a, &skill_root_alias).unwrap();
        std::fs::write(
            skill_root_a.join("SKILL.md"),
            "---\nname: ops-a\ndescription: fixture skill\n---\nFROZEN_SKILL_BODY_MARKER\n",
        )
        .unwrap();
        std::fs::write(
            skill_root_a.join("references/checks.md"),
            "FROZEN_NESTED_REFERENCE\n",
        )
        .unwrap();
        std::fs::write(
            skill_root_b.join("SKILL.md"),
            "---\nname: ops-b\ndescription: second fixture skill\n---\nSecond body.\n",
        )
        .unwrap();
        std::fs::copy(
            fixture_root.join("config.toml"),
            config_root.join("config.toml"),
        )
        .unwrap();
        for profile in ["judgment_claude", "worker_codex"] {
            let source = fixture_root.join("profiles").join(profile);
            let target = config_root.join("profiles").join(profile);
            std::fs::create_dir_all(&target).unwrap();
            for entry in std::fs::read_dir(source).unwrap() {
                let entry = entry.unwrap();
                if entry.file_type().unwrap().is_file() {
                    std::fs::copy(entry.path(), target.join(entry.file_name())).unwrap();
                }
            }
        }
        let judgment_profile = config_root.join("profiles/judgment_claude");
        let real_judgment_profile = config_root.join("profiles/judgment_claude_real");
        std::fs::rename(&judgment_profile, &real_judgment_profile).unwrap();
        std::os::unix::fs::symlink(&real_judgment_profile, &judgment_profile).unwrap();
        let base_profile_config = config_root.join("profiles/judgment_claude/config.toml");
        let original_profile_config = std::fs::read_to_string(&base_profile_config).unwrap();
        let instruction_alias = config_root.join("profiles/judgment_claude/aliases/instruction.md");
        std::fs::create_dir_all(instruction_alias.parent().unwrap()).unwrap();
        let canonical_alias = instruction_alias
            .parent()
            .unwrap()
            .canonicalize()
            .unwrap()
            .join(instruction_alias.file_name().unwrap());
        std::fs::write(
            &base_profile_config,
            original_profile_config.replace(
                "[options]",
                &format!(
                    "instruction_files = [\"aliases/instruction.md\", {:?}]\nskill_paths = [{:?}, {:?}]\n\n[options]",
                    canonical_alias.display().to_string(),
                    skill_root_alias.display().to_string(),
                    skill_root_b.display().to_string(),
                ),
            ),
        )
        .unwrap();
        let alias_target = config_root.join("profiles/judgment_claude/alias-target.md");
        std::fs::write(&alias_target, "Alias-resolved frozen instruction.\n").unwrap();
        std::os::unix::fs::symlink("../alias-target.md", &instruction_alias).unwrap();
        let rex_cli = temp.path().join("fixture-rex");
        std::fs::write(&rex_cli, "#!/bin/sh\nprintf '%s\\n' '{\"endpoint\":\"unix:///tmp/rex-trial-fixture.sock\",\"instance_id\":\"rex-trial-fixture\",\"host_id\":\"fixture-host\",\"rex_version\":\"fixture\",\"methods\":[]}'\n").unwrap();
        std::fs::set_permissions(&rex_cli, std::fs::Permissions::from_mode(0o700)).unwrap();
        let executable = std::env::current_exe().unwrap().canonicalize().unwrap();
        let config_path = config_root.join("config.toml");
        let original = std::fs::read_to_string(&config_path).unwrap();
        let config_text = original.replacen(
            "schema_version = 1",
            &format!(
                "schema_version = 1\n\n[runtime]\nrex_binary = {:?}",
                rex_cli.display().to_string()
            ),
            1,
        );
        std::fs::write(&config_path, config_text).unwrap();
        for profile in ["judgment_claude", "worker_codex"] {
            let profile_path = config_root
                .join("profiles")
                .join(profile)
                .join("config.toml");
            let source = std::fs::read_to_string(&profile_path).unwrap();
            let changed = source
                .replace("/absolute/path/to/claude", executable.to_str().unwrap())
                .replace("/absolute/path/to/codex", executable.to_str().unwrap());
            std::fs::write(profile_path, changed).unwrap();
        }
        let applied = config::load(&config_path).unwrap();
        let state_root = temp.path().join("state");
        let source_identity = config_path.canonicalize().unwrap().display().to_string();
        let mut store = ConfigStore::open_test(&state_root).unwrap();
        store
            .apply_snapshot(&source_identity, &applied, ExpectedRevision::Bootstrap)
            .unwrap();
        for (project_id, project) in &applied.config.projects {
            store
                .insert_project(&ProjectRecord {
                    id: project_id.clone(),
                    config_source: source_identity.clone(),
                    config_revision: Revision(1),
                    config_digest: applied.digest.clone(),
                    mode: match project.mode {
                        crate::domain::types::ProjectMode::Goal => "goal",
                        crate::domain::types::ProjectMode::Operations => "operations",
                    }
                    .into(),
                    goal_revision: project.goal.as_ref().map_or(0, |goal| goal.revision),
                    desired_lifecycle: "stopped".into(),
                    state_revision: Revision(0),
                })
                .unwrap();
        }
        let generation = store
            .start_owner(&OwnerMetadata {
                owner_nonce: "trial-request-fixture-owner".into(),
                state_root: state_root.display().to_string(),
                config_source: source_identity.clone(),
                process_start_identity: super::process_start_identity().unwrap(),
                executable_path: executable.display().to_string(),
                executable_digest: "f".repeat(64),
                rex_endpoint: Some("unix:///tmp/rex-trial-fixture.sock".into()),
                rex_server_identity: Some("rex-trial-fixture".into()),
                rex_session_id: Some("fixture-session".into()),
                rex_block_id: Some("controller-block".into()),
            })
            .unwrap();
        let project_id = ProjectId::parse("goal_project").unwrap();
        let role = Role::Coordinator;
        let base_profile_id =
            crate::config::effective_project_roles(&project_id, &applied.config.projects).unwrap()
                [&role]
                .clone();
        let base = applied.profiles[&base_profile_id].clone();
        let base_digest = crate::store::agent_profile_digest(&base).unwrap();
        let (candidate_id, candidate_profile_id) = crate::learning::candidate_slot_id(
            &project_id,
            role,
            &base_profile_id,
            &crate::topic::TopicKey::parse("trial-fixture").unwrap(),
        );
        let mut candidate = base.clone();
        candidate.description = Some("Fixture trial candidate".into());
        candidate.learned_guidance = Some(crate::config::LearnedGuidance {
            file: "learned/trial.md".into(),
            project_id: project_id.clone(),
            role,
            repository_ids: BTreeSet::new(),
        });
        let mut files = BTreeMap::new();
        let mut external_sources = BTreeMap::new();
        let root = config_root
            .join("profiles")
            .join(base_profile_id.as_str())
            .canonicalize()
            .unwrap();
        for source in &applied.source_files {
            if matches!(source.kind, crate::config::SourceKind::File) {
                let canonical_path = std::path::Path::new(&source.canonical_path);
                let package_path = std::path::Path::new(&source.path);
                if canonical_path.starts_with(&root)
                    && canonical_path
                        .file_name()
                        .is_some_and(|name| name != OsStr::new("config.toml"))
                {
                    let relative = package_path
                        .strip_prefix(&root)
                        .unwrap()
                        .to_string_lossy()
                        .into_owned();
                    files.insert(relative, source.contents.as_bytes().to_vec());
                }
                for skill_root in [&skill_root_a, &skill_root_b] {
                    let canonical_skill_root = skill_root.canonicalize().unwrap();
                    if let Ok(relative) = canonical_path.strip_prefix(&canonical_skill_root) {
                        let relative = relative
                            .to_str()
                            .unwrap()
                            .replace(std::path::MAIN_SEPARATOR, "/");
                        let source_digest = source.sha256.as_str();
                        let package_key = format!("external/{}/{relative}", &source_digest[..16]);
                        external_sources.insert(source.canonical_path.clone(), package_key.clone());
                        files.insert(package_key, source.contents.as_bytes().to_vec());
                    }
                }
            }
        }
        files.insert(
            "learned/trial.md".into(),
            b"Use the narrow tested approach.".to_vec(),
        );
        let captured_skill_text = applied
            .source_files
            .iter()
            .find(|source| {
                source.canonical_path
                    == skill_root_a
                        .join("SKILL.md")
                        .canonicalize()
                        .unwrap()
                        .display()
                        .to_string()
            })
            .unwrap()
            .contents
            .clone();
        let captured_nested_text = applied
            .source_files
            .iter()
            .find(|source| {
                source.canonical_path
                    == skill_root_a
                        .join("references/checks.md")
                        .canonicalize()
                        .unwrap()
                        .display()
                        .to_string()
            })
            .unwrap()
            .contents
            .clone();
        std::fs::write(skill_root_a.join("SKILL.md"), "MUTATED_AFTER_APPLY\n").unwrap();
        let frozen_candidate = crate::profile_trial_request::profile_snapshot(
            &applied,
            &candidate_profile_id,
            &base_profile_id,
            &candidate,
            Some(&files),
            Some(&external_sources),
        )
        .unwrap();
        let skill_a_key =
            crate::learning_trials::trial_skill_root_key(candidate.skill_paths.first().unwrap())
                .unwrap();
        assert_eq!(
            frozen_candidate.skill_trees[&skill_a_key].files["SKILL.md"],
            captured_skill_text
        );
        assert_eq!(
            frozen_candidate.skill_trees[&skill_a_key].files["references/checks.md"],
            captured_nested_text
        );
        assert_eq!(frozen_candidate.skill_trees.len(), 2);
        assert_eq!(
            frozen_candidate.skill_trees[&skill_a_key].directory_name,
            "ops-a"
        );
        let mut uncaptured_relative_root = candidate.clone();
        uncaptured_relative_root.skill_paths = vec!["../../external-skills/ops-a".into()];
        let uncaptured_error = crate::profile_trial_request::profile_snapshot(
            &applied,
            &candidate_profile_id,
            &base_profile_id,
            &uncaptured_relative_root,
            Some(&files),
            Some(&external_sources),
        )
        .unwrap_err();
        assert!(
            uncaptured_error.contains("absent from the captured source manifest"),
            "{uncaptured_error}"
        );
        let mut unsupported_file_root = candidate.clone();
        unsupported_file_root.skill_paths =
            vec![skill_root_a.join("SKILL.md").display().to_string()];
        assert!(
            crate::profile_trial_request::profile_snapshot(
                &applied,
                &candidate_profile_id,
                &base_profile_id,
                &unsupported_file_root,
                Some(&files),
                Some(&external_sources),
            )
            .unwrap_err()
            .contains("not a directory")
        );
        let mut substituted_package = files.clone();
        let skill_source = applied
            .source_files
            .iter()
            .find(|source| source.canonical_path.ends_with("/ops-a/SKILL.md"))
            .unwrap();
        let skill_package_path = external_sources[&skill_source.canonical_path].clone();
        substituted_package.insert(skill_package_path, b"SUBSTITUTED\n".to_vec());
        assert!(
            crate::profile_trial_request::profile_snapshot(
                &applied,
                &candidate_profile_id,
                &base_profile_id,
                &candidate,
                Some(&substituted_package),
                Some(&external_sources),
            )
            .unwrap_err()
            .contains("substituted selected skill")
        );
        let mut incomplete_mapping = external_sources.clone();
        incomplete_mapping.remove(&skill_source.canonical_path);
        assert!(
            crate::profile_trial_request::profile_snapshot(
                &applied,
                &candidate_profile_id,
                &base_profile_id,
                &candidate,
                Some(&files),
                Some(&incomplete_mapping),
            )
            .unwrap_err()
            .contains("no exact mapping")
        );
        std::fs::write(skill_root_a.join("SKILL.md"), &captured_skill_text).unwrap();
        files.insert(
            "learned/trial.md".into(),
            b"Use the narrow tested approach.".to_vec(),
        );
        files.insert(
            "config.toml".into(),
            toml::to_string(&candidate).unwrap().into_bytes(),
        );
        let metadata = ProfileCandidateMetadata {
            schema_version: 1,
            project_id: project_id.clone(),
            candidate_id: candidate_id.clone(),
            profile_id: candidate_profile_id.clone(),
            role,
            base_profile_id: base_profile_id.clone(),
            base_profile_digest: base_digest,
            base_profile_json: serde_json::to_string(&base).unwrap(),
            base_config_toml: toml::to_string(&base).unwrap(),
            base_guidance: None,
            learned_guidance_path: "learned/trial.md".into(),
            config_revision: Revision(1),
            config_digest: applied.digest.clone(),
            topic_key: crate::topic::TopicKey::parse("trial-fixture").unwrap(),
            repository_ids: BTreeSet::new(),
            source_finding_ids: vec![],
            source_ticket_run_ids: BTreeSet::new(),
            expected_prior_digest: None,
            evaluation_criterion: "The exact candidate profile is reviewed.".into(),
            description: "Fixture trial candidate".into(),
            learned_guidance: "Use the narrow tested approach.".into(),
            external_sources: external_sources.clone(),
        };
        files.insert(
            crate::learning::PROFILE_CANDIDATE_METADATA_PATH.into(),
            serde_json::to_vec(&metadata).unwrap(),
        );
        let manifest = crate::learning::manifest_digest(&files).unwrap();
        let rows = files
            .iter()
            .map(|(path, bytes)| {
                (
                    path.clone(),
                    Digest::parse(format!("{:x}", Sha256::digest(bytes))).unwrap(),
                )
            })
            .collect::<Vec<_>>();
        let candidate_digest = crate::learning::candidate_revision_digest(&files).unwrap();
        store
            .register_learning_candidate(
                generation,
                &LearningCandidateRecord {
                    revision: CandidateRevision {
                        candidate_id: candidate_id.clone(),
                        project_id: project_id.clone(),
                        role,
                        digest: candidate_digest.clone(),
                        created_at: "2026-11-13T00:00:00Z".into(),
                        expires_at: "2027-11-13T00:00:00Z".into(),
                        status: CandidateStatus::Proposed,
                    },
                    profile_id: candidate_profile_id.clone(),
                    package_manifest_digest: manifest,
                    package_files_json: serde_json::to_string(&files).unwrap(),
                    package_json: serde_json::to_string(&rows).unwrap(),
                    expected_pairs: 10,
                },
            )
            .unwrap();
        let mut candidate_qualification = None;
        for (profile_id, profile) in [
            (&base_profile_id, &base),
            (&candidate_profile_id, &candidate),
        ] {
            let identity = crate::run_step::profile_runtime_identity(profile).unwrap();
            let markers = [
                "REX_PROJECTS_AGENT",
                "REX_PROJECTS_CONTEXT",
                "REX_PROJECTS_PROJECT_ID",
                "REX_PROJECTS_ROLE",
                "REX_PROJECTS_RUN_ID",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
            let proof = crate::launch::QualificationProof {
                schema_version: 1,
                probe_id: "trial-request-fixture".into(),
                fixture_digest: Digest::parse("a".repeat(64)).unwrap(),
                rex_instance_id: "rex-trial-fixture".into(),
                tool_shell_marker_digest: Digest::parse("b".repeat(64)).unwrap(),
                tool_shell_markers_present: markers.clone(),
                descendant_marker_digest: Digest::parse("c".repeat(64)).unwrap(),
                descendant_markers_present: markers,
                automatic_turn_result_digest: Digest::parse("d".repeat(64)).unwrap(),
                automatic_turn_completed: true,
                structured_result_valid: true,
                observed_permission_mode: identity.effective_permission_mode.into(),
                permission_prompt_count: 0,
                cleanup_process_tree_digest: Digest::parse("e".repeat(64)).unwrap(),
                process_tree_absent: true,
                cleanup_confirmed: true,
            };
            let qualification: crate::launch::ProviderQualification = serde_json::from_value(serde_json::json!({
                "schema_version":1,"project_id":project_id,"profile_id":profile_id,"profile_digest":crate::store::agent_profile_digest(profile).unwrap(),"adapter":identity.adapter,
                "executable_path":identity.executable_path.display().to_string(),"executable_digest":identity.executable_digest,"provider_version":"fixture-1","permission_mode":identity.effective_permission_mode,
                "invocation_options_digest":identity.invocation_options_digest,"commit_mode":identity.commit_mode,"proof":proof,"status":"verified"
            })).unwrap();
            if profile_id == &candidate_profile_id {
                candidate_qualification = Some(qualification);
            } else {
                store
                    .store_provider_qualification(generation, &qualification)
                    .unwrap();
            }
        }
        let supervisor_view = RexView {
            view_id: RexView::derive_id(&project_id, RexViewKind::Supervisor, None, None, 1)
                .unwrap(),
            project_id: project_id.clone(),
            kind: RexViewKind::Supervisor,
            ticket_namespace: None,
            ticket_id: None,
            view_epoch: 1,
            rex_server_identity: "rex-trial-fixture".into(),
            rex_session_id: "fixture-session".into(),
            rex_window_id: "supervisor-window".into(),
        };
        store
            .register_rex_view(generation, &supervisor_view)
            .unwrap();
        drop(store);
        let matrix_path = temp.path().join("trial-matrix.json");
        let matrix = serde_json::json!({
            "inputs": (0..5).map(|index| serde_json::json!({"input_id":format!("case-{index}"),"input":{"case":index},"fixture":{"schema_version":1,"files":{}},"assertions":[]})).collect::<Vec<_>>(),
            "pairs": (0..10).map(|index| serde_json::json!({"pair_index":index,"input_id":format!("case-{}",index/2)})).collect::<Vec<_>>(),
        });
        let env = BTreeMap::from([
            (
                OsString::from("REX_SESSION"),
                OsString::from("fixture-session"),
            ),
            (OsString::from("REX_BLOCK"), OsString::from("human-block")),
            (OsString::from("PATH"), OsString::from("/usr/bin:/bin")),
        ]);
        let args = [
            "rex-projects",
            "--config",
            config_path.to_str().unwrap(),
            "--state-root",
            state_root.to_str().unwrap(),
            "learning",
            "trial",
            "request",
            "--project",
            "goal_project",
            "--candidate",
            candidate_id.as_str(),
            "--candidate-digest",
            candidate_digest.as_str(),
            "--request-key",
            "fixture-request-key",
            "--matrix-file",
            matrix_path.to_str().unwrap(),
        ];
        std::fs::write(&matrix_path, serde_json::to_vec(&matrix).unwrap()).unwrap();
        let mut other_session = env.clone();
        other_session.insert(
            OsString::from("REX_SESSION"),
            OsString::from("other-fixture-session"),
        );
        assert!(
            super::dispatch_learning_command_with_environment_for_test(&args, &other_session)
                .unwrap_err()
                .to_string()
                .contains("does not match the foreground controller identity")
        );
        let initial_error = super::dispatch_learning_command_with_environment_for_test(&args, &env)
            .unwrap_err()
            .to_string();
        assert!(
            initial_error.contains("no verified qualification matches"),
            "{initial_error}"
        );
        let original_config = std::fs::read(&config_path).unwrap();
        let mut changed_config = original_config.clone();
        changed_config.extend_from_slice(b"\n# Not the applied source snapshot.\n");
        std::fs::write(&config_path, changed_config).unwrap();
        let changed_source = crate::config::load(&config_path).unwrap();
        assert_ne!(changed_source.digest, applied.digest);
        assert!(
            super::dispatch_learning_command_with_environment_for_test(&args, &env)
                .unwrap_err()
                .to_string()
                .contains("applied configuration changed")
        );
        std::fs::write(&config_path, original_config).unwrap();
        let db = rusqlite::Connection::open(state_root.join("state.sqlite3")).unwrap();
        for table in ["profile_trial_authorizations", "human_requests"] {
            let count: i64 = db
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, 0, "rejected request wrote to {table}");
        }
        drop(db);
        let mut store = ConfigStore::open_test(&state_root).unwrap();
        let candidate_qualification = candidate_qualification.unwrap();
        let project_record = store.project(&project_id).unwrap().unwrap();
        let qualification_request = crate::store::provider_qualification_runtime::ProviderQualificationRequest {
            request_id: "trial-candidate-qualification".into(),
            project_id: project_id.clone(),
            role,
            profile_id: candidate_profile_id.clone(),
            profile_digest: candidate_qualification.profile_digest.clone(),
            config_revision: project_record.config_revision.0,
            config_digest: project_record.config_digest,
            target: crate::store::provider_qualification_runtime::ProviderQualificationTarget::Candidate {
                candidate_id: candidate_id.clone(),
                candidate_digest: candidate_digest.clone(),
            },
        };
        store
            .enqueue_provider_qualification(generation, &qualification_request)
            .unwrap();
        let crate::store::provider_qualification_runtime::QualificationClaim::Claimed { .. } =
            store
                .claim_provider_qualification(generation, 1, 1)
                .unwrap()
        else {
            panic!("candidate qualification job should be claimable");
        };
        store
            .bind_provider_qualification_rex(
                generation,
                &qualification_request.request_id,
                "fixture-session",
                "qualification-window",
                "qualification-block",
            )
            .unwrap();
        store
            .store_provider_qualification(generation, &candidate_qualification)
            .unwrap();
        let result_json = serde_json::to_string(&candidate_qualification).unwrap();
        let evidence_digest = Digest::parse(format!(
            "{:x}",
            sha2::Sha256::digest(result_json.as_bytes())
        ))
        .unwrap();
        store.finish_provider_qualification_job(
            generation,
            &qualification_request.request_id,
            crate::store::provider_qualification_runtime::ProviderQualificationJobStatus::Verified,
            &result_json,
            &evidence_digest,
            true,
        ).unwrap();
        let candidate_receipt_digest = candidate_qualification.canonical_digest().unwrap();
        assert!(
            store
                .provider_qualification_matches_candidate_target(
                    &candidate_receipt_digest,
                    &project_id,
                    &candidate_id,
                    &candidate_digest,
                    &candidate_profile_id,
                    &candidate_qualification.profile_digest,
                )
                .unwrap()
        );
        assert!(
            !store
                .provider_qualification_matches_candidate_target(
                    &candidate_receipt_digest,
                    &project_id,
                    &candidate_id,
                    &Digest::parse("9".repeat(64)).unwrap(),
                    &candidate_profile_id,
                    &candidate_qualification.profile_digest,
                )
                .unwrap()
        );
        drop(store);
        let mut duplicate_content = matrix.clone();
        for input in duplicate_content["inputs"].as_array_mut().unwrap() {
            input["input"] = serde_json::json!({"same":true});
        }
        std::fs::write(
            &matrix_path,
            serde_json::to_vec(&duplicate_content).unwrap(),
        )
        .unwrap();
        assert!(
            super::dispatch_learning_command_with_environment_for_test(&args, &env)
                .unwrap_err()
                .to_string()
                .contains("distinct-input digest minimum")
        );
        let mut skewed = matrix.clone();
        for pair_index in 0..10 {
            let input_id = if pair_index < 6 {
                "case-0".to_owned()
            } else {
                format!("case-{}", pair_index - 5)
            };
            skewed["pairs"][pair_index]["input_id"] = serde_json::json!(input_id);
        }
        std::fs::write(&matrix_path, serde_json::to_vec(&skewed).unwrap()).unwrap();
        let error =
            super::dispatch_learning_command_with_environment_for_test(&args, &env).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("nonstandard trial pair coverage requires")
        );
        let db = rusqlite::Connection::open(state_root.join("state.sqlite3")).unwrap();
        let auth_count: i64 = db
            .query_row(
                "SELECT count(*) FROM profile_trial_authorizations",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let request_count: i64 = db
            .query_row("SELECT count(*) FROM human_requests", [], |row| row.get(0))
            .unwrap();
        assert_eq!((auth_count, request_count), (0, 0));
        drop(db);
        std::fs::write(&matrix_path, serde_json::to_vec(&matrix).unwrap()).unwrap();
        super::dispatch_learning_command_with_environment_for_test(&args, &env).unwrap();
        let db = rusqlite::Connection::open(state_root.join("state.sqlite3")).unwrap();
        let (lifecycle, request_id, auth_json): (String, String, String) = db.query_row(
            "SELECT lifecycle,human_request_id,authorization_json FROM profile_trial_authorizations WHERE project_id='goal_project'", [], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
        ).unwrap();
        assert_eq!(lifecycle, "pending");
        let auth: crate::learning_trials::ProfileTrialAuthorization =
            serde_json::from_str(&auth_json).unwrap();
        assert_eq!(request_id, auth.human_request_id.as_str());
        let mut empty_skill_base = base.clone();
        empty_skill_base.skill_paths.clear();
        let mut empty_skill_candidate = candidate.clone();
        empty_skill_candidate.skill_paths.clear();
        let mut empty_skill_auth = auth.clone();
        empty_skill_auth.baseline = crate::profile_trial_request::profile_snapshot(
            &applied,
            &base_profile_id,
            &base_profile_id,
            &empty_skill_base,
            None,
            None,
        )
        .unwrap();
        empty_skill_auth.candidate = crate::profile_trial_request::profile_snapshot(
            &applied,
            &candidate_profile_id,
            &base_profile_id,
            &empty_skill_candidate,
            Some(&files),
            Some(&external_sources),
        )
        .unwrap();
        empty_skill_auth.base_profile_digest = empty_skill_auth.baseline.profile_digest.clone();
        assert!(empty_skill_auth.baseline.skill_trees.is_empty());
        assert!(empty_skill_auth.candidate.skill_trees.is_empty());
        empty_skill_auth.validate().unwrap();
        for (profile, required_paths) in [
            (
                &auth.baseline,
                ["instructions.md", "aliases/instruction.md"].as_slice(),
            ),
            (
                &auth.candidate,
                [
                    "instructions.md",
                    "aliases/instruction.md",
                    "learned/trial.md",
                ]
                .as_slice(),
            ),
        ] {
            for path in required_paths {
                assert!(
                    profile.instruction_files.contains_key(*path),
                    "frozen snapshot omitted {path}"
                );
            }
            assert_eq!(
                profile.instruction_files["instructions.md"],
                files["instructions.md"]
            );
            assert_eq!(
                profile.instruction_files["aliases/instruction.md"],
                b"Alias-resolved frozen instruction.\n"
            );
            assert!(profile.instruction_files.values().all(|bytes| {
                !String::from_utf8_lossy(bytes).contains("FROZEN_SKILL_BODY_MARKER")
            }));
        }
        assert_eq!(auth.baseline.skill_trees, auth.candidate.skill_trees);
        assert_eq!(auth.candidate.skill_trees.len(), 2);
        let rendered_role_contract = crate::profile_trial_runtime::render_trial_role_contract(
            role,
            &candidate,
            &auth.candidate,
        )
        .unwrap();
        assert!(!rendered_role_contract.contains("FROZEN_SKILL_BODY_MARKER"));
        assert!(rendered_role_contract.contains("Alias-resolved frozen instruction."));
        let first_input = &auth.inputs[0];
        let derived_seed = crate::learning_trials::trial_workspace_seed(
            &auth.candidate,
            &first_input.fixture_seed,
        )
        .unwrap();
        let workspace_parent = temp.path().join("trial-workspace-parent");
        std::fs::create_dir_all(&workspace_parent).unwrap();
        let workspace = workspace_parent.join("workspace");
        crate::trial_step::materialize_fixture_workspace(
            &derived_seed,
            &derived_seed.digest().unwrap(),
            &workspace,
        )
        .unwrap();
        let provider_root = match candidate.adapter {
            crate::domain::types::AgentAdapter::Codex => ".agents/skills",
            crate::domain::types::AgentAdapter::ClaudeCode => ".claude/skills",
        };
        assert_eq!(
            std::fs::read_to_string(workspace.join(provider_root).join("ops-a").join("SKILL.md"))
                .unwrap(),
            captured_skill_text
        );
        assert_eq!(
            std::fs::read_to_string(
                workspace
                    .join(provider_root)
                    .join("ops-a")
                    .join("references/checks.md")
            )
            .unwrap(),
            captured_nested_text
        );
        assert_eq!(
            auth.candidate.instruction_files["learned/trial.md"],
            b"Use the narrow tested approach."
        );
        assert!(
            auth.human_response_receipt_digest
                .as_str()
                .bytes()
                .all(|byte| byte == b'0')
        );
        let human_count: i64 = db
            .query_row(
                "SELECT count(*) FROM human_requests WHERE request_id=?1",
                [&request_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(human_count, 1);
        for table in [
            "profile_trial_launches",
            "profile_trial_run_receipts",
            "effects",
        ] {
            let count: i64 = db
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, 0, "unexpected rows in {table}");
        }
        let slot_count: i64 = db.query_row("SELECT count(*) FROM execution_slots WHERE owner_kind='profile_trial' AND disposition<>'released'", [], |row| row.get(0)).unwrap();
        assert_eq!(slot_count, 0);
        drop(db);
        // Reopen through the production store before replay; the ID remains bound to the original matrix.
        let reopened = ConfigStore::open_test(&state_root).unwrap();
        assert!(
            reopened
                .profile_trial_authorization(&auth.authorization_id)
                .unwrap()
                .is_some()
        );
        drop(reopened);
        let request_before: (String, String, String, String, i64, i64) =
            rusqlite::Connection::open(state_root.join("state.sqlite3"))
                .unwrap()
                .query_row(
                    "SELECT request_json,artifact_path,bundle_digest,material_digest,created_at_unix,expires_at_unix FROM human_requests WHERE request_id=?1",
                    [&request_id],
                    |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?)),
                )
                .unwrap();
        super::dispatch_learning_command_with_environment_for_test(&args, &env).unwrap();
        let db = rusqlite::Connection::open(state_root.join("state.sqlite3")).unwrap();
        let replay_auth_json: String = db
            .query_row(
                "SELECT authorization_json FROM profile_trial_authorizations WHERE project_id='goal_project'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            replay_auth_json, auth_json,
            "exact retry changed frozen authorization"
        );
        let request_after: (String, String, String, String, i64, i64) = db
            .query_row(
                "SELECT request_json,artifact_path,bundle_digest,material_digest,created_at_unix,expires_at_unix FROM human_requests WHERE request_id=?1",
                [&request_id],
                |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?)),
            )
            .unwrap();
        assert_eq!(
            request_after, request_before,
            "exact retry changed human review binding"
        );
        let retry_auth_count: i64 = db
            .query_row(
                "SELECT count(*) FROM profile_trial_authorizations",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let retry_request_count: i64 = db
            .query_row("SELECT count(*) FROM human_requests", [], |row| row.get(0))
            .unwrap();
        assert_eq!((retry_auth_count, retry_request_count), (1, 1));
        drop(db);
        let mut changed = matrix.clone();
        changed["inputs"][0]["input"]["case"] = serde_json::json!(999);
        std::fs::write(&matrix_path, serde_json::to_vec(&changed).unwrap()).unwrap();
        let error =
            super::dispatch_learning_command_with_environment_for_test(&args, &env).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("request key was reused with different trial content")
        );
        let db = rusqlite::Connection::open(state_root.join("state.sqlite3")).unwrap();
        let auth_count: i64 = db
            .query_row(
                "SELECT count(*) FROM profile_trial_authorizations",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let human_count: i64 = db
            .query_row("SELECT count(*) FROM human_requests", [], |row| row.get(0))
            .unwrap();
        assert_eq!(auth_count, 1);
        assert_eq!(human_count, 1);
        drop(db);

        let request_id = crate::domain::ids::HumanRequestId::parse(request_id).unwrap();
        let request = ConfigStore::read_human_request(&state_root, &request_id)
            .unwrap()
            .unwrap()
            .request;
        let refusal = crate::human_runtime::HumanDecisionIntent {
            request_id: request_id.clone(),
            response_id: "fixture-trial-refusal".into(),
            expected_subject_digest: request.subject.digest().unwrap(),
            choice: crate::human_runtime::HumanDecisionChoice::Refuse,
            explanation: Some("Declined this candidate for the fixture regression.".into()),
        };
        ConfigStore::enqueue_human_decision(&state_root, &refusal, 1_000).unwrap();
        let mut store = ConfigStore::open_test(&state_root).unwrap();
        assert_eq!(
            store
                .process_human_decision(generation, &refusal.response_id, &request.subject, 1_001)
                .unwrap(),
            crate::store::human::HumanDecisionResult::Applied
        );
        assert_eq!(
            store
                .profile_trial_authorization_lifecycle(&auth.authorization_id)
                .unwrap()
                .as_deref(),
            Some("refused"),
        );
        drop(store);

        std::fs::write(&matrix_path, serde_json::to_vec(&matrix).unwrap()).unwrap();
        let mut retry_args = args.to_vec();
        let key_position = retry_args
            .iter()
            .position(|arg| *arg == "--request-key")
            .unwrap();
        retry_args[key_position + 1] = "fixture-request-key-after-refusal";
        super::dispatch_learning_command_with_environment_for_test(&retry_args, &env).unwrap();
        let db = rusqlite::Connection::open(state_root.join("state.sqlite3")).unwrap();
        let lifecycles = db.prepare(
            "SELECT lifecycle FROM profile_trial_authorizations ORDER BY created_at_unix,authorization_id",
        ).unwrap().query_map([], |row| row.get::<_, String>(0)).unwrap()
            .collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(lifecycles, ["refused", "pending"]);
    }

    #[test]
    fn public_candidate_qualification_cli_round_trips_exact_candidate_and_receipt() {
        use crate::domain::ids::{Digest, ProfileId, ProjectId, Revision};
        use crate::domain::types::Role;
        use crate::learning::{CandidateRevision, CandidateStatus, ProfileCandidateMetadata};
        use crate::store::provider_qualification_runtime::{
            ProviderQualificationJobStatus as JobStatus, ProviderQualificationTarget as Target,
            QualificationClaim,
        };
        use crate::store::{ExpectedRevision, LearningCandidateRecord, OwnerMetadata};
        use sha2::{Digest as _, Sha256};
        use std::collections::{BTreeMap, BTreeSet};

        let temp = tempfile::tempdir().unwrap();
        let state_root = temp.path().join("state");
        let config_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("examples/fixture/config.toml")
            .canonicalize()
            .unwrap();
        let source_identity = config_path.display().to_string();
        let applied = config::load(&config_path).unwrap();
        let project_id = ProjectId::parse("goal_project").unwrap();
        let role = Role::Coordinator;
        let base_profile_id =
            crate::config::effective_project_roles(&project_id, &applied.config.projects).unwrap()
                [&role]
                .clone();
        let base_profile = applied.profiles[&base_profile_id].clone();
        let base_profile_digest = crate::store::agent_profile_digest(&base_profile).unwrap();
        let (candidate_id, profile_id) = crate::learning::candidate_slot_id(
            &project_id,
            role,
            &base_profile_id,
            &crate::topic::TopicKey::parse("qualification-fixture").unwrap(),
        );
        let repository_ids = BTreeSet::new();
        let mut candidate_profile = base_profile.clone();
        candidate_profile.description = Some("Fixture candidate description".into());
        candidate_profile.learned_guidance = Some(crate::config::LearnedGuidance {
            file: "learned/guidance.md".into(),
            project_id: project_id.clone(),
            role,
            repository_ids: repository_ids.clone(),
        });
        let mut files = BTreeMap::from([
            (
                "config.toml".to_owned(),
                toml::to_string(&candidate_profile).unwrap().into_bytes(),
            ),
            (
                "learned/guidance.md".to_owned(),
                b"Use focused checks.".to_vec(),
            ),
        ]);
        let metadata = ProfileCandidateMetadata {
            schema_version: 1,
            project_id: project_id.clone(),
            candidate_id: candidate_id.clone(),
            profile_id: profile_id.clone(),
            role,
            base_profile_id: base_profile_id.clone(),
            base_profile_digest,
            base_profile_json: serde_json::to_string(&base_profile).unwrap(),
            base_config_toml: toml::to_string(&base_profile).unwrap(),
            base_guidance: None,
            learned_guidance_path: "learned/guidance.md".into(),
            config_revision: Revision(1),
            config_digest: applied.digest.clone(),
            topic_key: crate::topic::TopicKey::parse("qualification-fixture").unwrap(),
            repository_ids,
            source_finding_ids: Vec::new(),
            source_ticket_run_ids: BTreeSet::new(),
            expected_prior_digest: None,
            evaluation_criterion: "The candidate profile resolves to the exact package.".into(),
            description: "Fixture candidate description".into(),
            learned_guidance: "Use focused checks.".into(),
            external_sources: BTreeMap::new(),
        };
        files.insert(
            crate::learning::PROFILE_CANDIDATE_METADATA_PATH.into(),
            serde_json::to_vec(&metadata).unwrap(),
        );
        let package_manifest_digest = crate::learning::manifest_digest(&files).unwrap();
        let manifest_rows = files
            .iter()
            .map(|(path, bytes)| {
                (
                    path.clone(),
                    Digest::parse(format!("{:x}", Sha256::digest(bytes))).unwrap(),
                )
            })
            .collect::<Vec<_>>();
        let package_json = serde_json::to_string(&manifest_rows).unwrap();
        let package_files_json = serde_json::to_string(&files).unwrap();
        let candidate_digest = crate::learning::candidate_revision_digest(&files).unwrap();
        let record = LearningCandidateRecord {
            revision: CandidateRevision {
                candidate_id: candidate_id.clone(),
                project_id: project_id.clone(),
                role,
                digest: candidate_digest.clone(),
                created_at: "2026-11-12T00:00:00Z".into(),
                expires_at: "2027-11-12T00:00:00Z".into(),
                status: CandidateStatus::Proposed,
            },
            profile_id: profile_id.clone(),
            package_manifest_digest,
            package_files_json,
            package_json,
            expected_pairs: 5,
        };
        let mut store = ConfigStore::open_test(&state_root).unwrap();
        let revision = store
            .apply_snapshot(&source_identity, &applied, ExpectedRevision::Bootstrap)
            .unwrap()
            .revision;
        assert_eq!(revision, Revision(1));
        let generation = store
            .start_owner(&OwnerMetadata {
                owner_nonce: "candidate-qualification-cli-fixture".into(),
                state_root: state_root.display().to_string(),
                config_source: source_identity.clone(),
                process_start_identity: super::process_start_identity().unwrap(),
                executable_path: std::env::current_exe().unwrap().display().to_string(),
                executable_digest: "f".repeat(64),
                rex_endpoint: Some("fixture://rex".into()),
                rex_server_identity: Some("fixture-server".into()),
                rex_session_id: Some("fixture-session".into()),
                rex_block_id: Some("fixture-block".into()),
            })
            .unwrap();
        store
            .register_learning_candidate(generation, &record)
            .unwrap();
        drop(store);

        super::dispatch_provider_command_for_test(&[
            "rex-projects",
            "--config",
            config_path.to_str().unwrap(),
            "--state-root",
            state_root.to_str().unwrap(),
            "--json",
            "provider",
            "qualify-candidate",
            "--project",
            project_id.as_str(),
            "--candidate",
            &candidate_id,
            "--candidate-digest",
            candidate_digest.as_str(),
            "--request-id",
            "candidate-cli-roundtrip",
        ])
        .unwrap();

        let store = ConfigStore::open_test(&state_root).unwrap();
        let job = store
            .provider_qualification_job("candidate-cli-roundtrip")
            .unwrap()
            .unwrap();
        assert_eq!(
            job.request.target,
            Target::Candidate {
                candidate_id: candidate_id.clone(),
                candidate_digest: candidate_digest.clone(),
            }
        );
        assert_eq!(job.request.profile_id, profile_id);
        drop(store);
        let db = rusqlite::Connection::open(state_root.join("state.sqlite3")).unwrap();
        let revision_json: String = db
            .query_row(
                "SELECT revision_json FROM learning_candidates WHERE project_id=?1 AND candidate_id=?2 AND digest=?3",
                rusqlite::params![project_id.as_str(), candidate_id, candidate_digest.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        let mut revision: CandidateRevision = serde_json::from_str(&revision_json).unwrap();
        revision.status = CandidateStatus::Trialing;
        db
            .execute(
                "UPDATE learning_candidates SET status='trialing',revision_json=?4 WHERE project_id=?1 AND candidate_id=?2 AND digest=?3",
                rusqlite::params![project_id.as_str(), candidate_id, candidate_digest.as_str(), serde_json::to_string(&revision).unwrap()],
            )
            .unwrap();
        drop(db);
        super::dispatch_provider_command_for_test(&[
            "rex-projects",
            "--config",
            config_path.to_str().unwrap(),
            "--state-root",
            state_root.to_str().unwrap(),
            "--json",
            "provider",
            "qualify-candidate",
            "--project",
            project_id.as_str(),
            "--candidate",
            &candidate_id,
            "--candidate-digest",
            candidate_digest.as_str(),
            "--request-id",
            "candidate-cli-roundtrip",
        ])
        .unwrap();
        let store = ConfigStore::open_test(&state_root).unwrap();
        let replayed_job = store
            .provider_qualification_job("candidate-cli-roundtrip")
            .unwrap()
            .unwrap();
        assert_eq!(replayed_job, job);
        drop(store);
        let db = rusqlite::Connection::open(state_root.join("state.sqlite3")).unwrap();
        let revision_json: String = db
            .query_row(
                "SELECT revision_json FROM learning_candidates WHERE project_id=?1 AND candidate_id=?2 AND digest=?3",
                rusqlite::params![project_id.as_str(), candidate_id, candidate_digest.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        let mut revision: CandidateRevision = serde_json::from_str(&revision_json).unwrap();
        revision.status = CandidateStatus::Proposed;
        db
            .execute(
                "UPDATE learning_candidates SET status='proposed',revision_json=?4 WHERE project_id=?1 AND candidate_id=?2 AND digest=?3",
                rusqlite::params![project_id.as_str(), candidate_id, candidate_digest.as_str(), serde_json::to_string(&revision).unwrap()],
            )
            .unwrap();
        drop(db);
        let mut store = ConfigStore::open_test(&state_root).unwrap();
        let replay_digest = store
            .enqueue_provider_qualification(generation, &job.request)
            .unwrap();
        assert_eq!(replay_digest, job.request_digest);
        let mut changed_target = job.request.clone();
        changed_target.target = Target::Candidate {
            candidate_id: candidate_id.clone(),
            candidate_digest: Digest::parse("e".repeat(64)).unwrap(),
        };
        assert!(
            store
                .enqueue_provider_qualification(generation, &changed_target)
                .unwrap_err()
                .contains("reused with different content")
        );
        let QualificationClaim::Claimed { job, .. } = store
            .claim_provider_qualification(generation, 4, 4)
            .unwrap()
        else {
            panic!("candidate CLI request must use the normal qualification claim path");
        };
        let resolved = store
            .resolve_provider_qualification_candidate(&job.request, &applied)
            .unwrap();
        assert_eq!(
            crate::store::agent_profile_digest(&resolved).unwrap(),
            job.request.profile_digest
        );

        let proof = crate::launch::QualificationProof {
            schema_version: crate::launch::QUALIFICATION_SCHEMA_VERSION,
            probe_id: "fixture-only-candidate-qualification".into(),
            fixture_digest: Digest::parse("a".repeat(64)).unwrap(),
            rex_instance_id: "fixture-only".into(),
            tool_shell_marker_digest: Digest::parse("b".repeat(64)).unwrap(),
            tool_shell_markers_present: [
                "REX_PROJECTS_AGENT",
                "REX_PROJECTS_CONTEXT",
                "REX_PROJECTS_PROJECT_ID",
                "REX_PROJECTS_ROLE",
                "REX_PROJECTS_RUN_ID",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            descendant_marker_digest: Digest::parse("c".repeat(64)).unwrap(),
            descendant_markers_present: [
                "REX_PROJECTS_AGENT",
                "REX_PROJECTS_CONTEXT",
                "REX_PROJECTS_PROJECT_ID",
                "REX_PROJECTS_ROLE",
                "REX_PROJECTS_RUN_ID",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            automatic_turn_result_digest: Digest::parse("d".repeat(64)).unwrap(),
            automatic_turn_completed: true,
            structured_result_valid: true,
            observed_permission_mode: "fixture-only".into(),
            permission_prompt_count: 0,
            cleanup_process_tree_digest: Digest::parse("e".repeat(64)).unwrap(),
            process_tree_absent: true,
            cleanup_confirmed: true,
        };
        let make_receipt = |receipt_profile_id: ProfileId, receipt_profile_digest: Digest| {
            crate::launch::ProviderQualification {
                schema_version: crate::launch::QUALIFICATION_SCHEMA_VERSION,
                project_id: project_id.clone(),
                profile_id: receipt_profile_id,
                profile_digest: receipt_profile_digest,
                adapter: resolved.adapter,
                executable_path: "/fixture/provider".into(),
                executable_digest: Digest::parse("f".repeat(64)).unwrap(),
                provider_version: "fixture-only".into(),
                permission_mode: "fixture-only".into(),
                invocation_options_digest: Digest::parse("1".repeat(64)).unwrap(),
                commit_mode: resolved.commit_mode,
                proof: proof.clone(),
                status: crate::launch::QualificationStatus::Verified,
            }
        };
        let baseline_digest = crate::store::agent_profile_digest(&base_profile).unwrap();
        let baseline = make_receipt(base_profile_id, baseline_digest);
        store
            .store_provider_qualification(generation, &baseline)
            .unwrap();
        let baseline_json = serde_json::to_string(&baseline).unwrap();
        assert!(
            store
                .finish_provider_qualification_job(
                    generation,
                    &job.request.request_id,
                    JobStatus::Verified,
                    &baseline_json,
                    &Digest::parse(format!("{:x}", Sha256::digest(baseline_json.as_bytes())))
                        .unwrap(),
                    true,
                )
                .is_err()
        );

        let candidate_receipt = make_receipt(
            job.request.profile_id.clone(),
            job.request.profile_digest.clone(),
        );
        let receipt_digest = store
            .store_provider_qualification(generation, &candidate_receipt)
            .unwrap();
        let receipt_json = serde_json::to_string(&candidate_receipt).unwrap();
        store
            .finish_provider_qualification_job(
                generation,
                &job.request.request_id,
                JobStatus::Verified,
                &receipt_json,
                &Digest::parse(format!("{:x}", Sha256::digest(receipt_json.as_bytes()))).unwrap(),
                true,
            )
            .unwrap();
        drop(store);
        let reopened = ConfigStore::open_test(&state_root).unwrap();
        assert_eq!(
            reopened
                .provider_qualification_job(&job.request.request_id)
                .unwrap()
                .unwrap()
                .status,
            JobStatus::Verified,
        );
        assert_eq!(
            reopened
                .provider_qualification(&receipt_digest)
                .unwrap()
                .unwrap(),
            candidate_receipt
        );
    }

    #[test]
    fn doctor_resolves_a_path_with_spaces_without_splitting_it() {
        let temp = tempfile::tempdir().unwrap();
        let executable = temp.path().join("agent with spaces");
        std::fs::write(&executable, "#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let canonical = executable.canonicalize().unwrap();
        assert_eq!(
            resolve_executable(executable.to_str().unwrap()).as_deref(),
            Some(canonical.as_path())
        );
    }

    #[test]
    fn parsed_recovery_status_command_reads_the_generated_state_database() {
        use crate::domain::ids::{ProjectId, TicketRunId};

        let temp = tempfile::tempdir().unwrap();
        let state_root = temp.path().join("state");
        std::fs::create_dir_all(&state_root).unwrap();
        let project_id = ProjectId::parse("project-a").unwrap();
        let ticket_run_id = TicketRunId::parse("ticket-run-a").unwrap();
        let mut store = ConfigStore::open_test(&state_root).unwrap();
        store
            .insert_merge_claim_recovery_status_fixture(
                "recovery-cli-fixture",
                &project_id,
                &ticket_run_id,
                "accepted",
                Some(&"a".repeat(64)),
            )
            .unwrap();
        drop(store);

        let cli = Cli::try_parse_from([
            "rex-projects",
            "--config",
            concat!(env!("CARGO_MANIFEST_DIR"), "/examples/fixture/config.toml"),
            "--state-root",
            state_root.to_str().unwrap(),
            "--json",
            "ticket",
            "recovery-status",
            "--request-id",
            "recovery-cli-fixture",
        ])
        .unwrap();
        let Command::Ticket {
            command: TicketCommand::RecoveryStatus { request_id },
        } = cli.command
        else {
            panic!(
                "public parser must route the recovery-status command to its production handler"
            );
        };
        assert_eq!(request_id, "recovery-cli-fixture");
        super::dispatch_ticket_command_for_test(&[
            "rex-projects",
            "--config",
            concat!(env!("CARGO_MANIFEST_DIR"), "/examples/fixture/config.toml"),
            "--state-root",
            state_root.to_str().unwrap(),
            "--json",
            "ticket",
            "recovery-status",
            "--request-id",
            &request_id,
        ])
        .unwrap();
    }

    #[test]
    fn provider_status_requires_a_request_id_and_parses_as_read_only_command() {
        let cli = Cli::try_parse_from([
            "rex-projects",
            "--json",
            "provider",
            "status",
            "--request-id",
            "qualification-123",
        ])
        .unwrap();
        assert!(cli.json);
        assert!(matches!(
            cli.command,
            Command::Provider {
                command: ProviderCommand::Status { request_id }
            } if request_id == "qualification-123"
        ));
        assert!(Cli::try_parse_from(["rex-projects", "provider", "status"]).is_err());
        let reconcile = Cli::try_parse_from([
            "rex-projects",
            "provider",
            "reconcile",
            "--request-id",
            "qualification-123",
        ])
        .unwrap();
        assert!(matches!(
            reconcile.command,
            Command::Provider {
                command: ProviderCommand::Reconcile { request_id }
            } if request_id == "qualification-123"
        ));
        assert!(Cli::try_parse_from(["rex-projects", "provider", "reconcile"]).is_err());
    }

    #[test]
    fn terminal_provider_status_shows_no_hold_and_preserves_actual_released_slot() {
        use crate::store::provider_qualification_runtime::{
            ProviderQualificationJobStatus as Status, ProviderQualificationLaunchPhase as Phase,
            ProviderQualificationSlot,
        };

        let slot = ProviderQualificationSlot {
            slot_index: 3,
            reservation_epoch: 5,
            controller_generation: 7,
            disposition: "released".into(),
        };
        for status in [Status::Verified, Status::Failed] {
            let (hold_reason, next_safe_action, reported_slot) =
                super::provider_status_fields(status, Phase::Bound, Some(&slot));
            assert_eq!(hold_reason, None);
            assert!(!next_safe_action.contains("held"));
            assert_eq!(
                reported_slot.unwrap()["disposition"],
                serde_json::json!("released")
            );
        }
    }

    #[test]
    fn public_provider_reconcile_handler_persists_only_the_exact_live_request_intent() {
        use crate::domain::ids::{ProfileId, ProjectId};
        use crate::domain::types::Role;
        use crate::store::{ExpectedRevision, OwnerMetadata};

        let temp = tempfile::tempdir().unwrap();
        let state_root = temp.path().join("state");
        let config_path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/fixture/config.toml");
        let applied = config::load(&config_path).unwrap();
        let mut store = ConfigStore::open_test(&state_root).unwrap();
        let revision = store
            .apply_snapshot(
                "provider-reconcile-fixture",
                &applied,
                ExpectedRevision::Bootstrap,
            )
            .unwrap()
            .revision;
        let generation = store
            .start_owner(&OwnerMetadata {
                owner_nonce: "fixture-owner".into(),
                state_root: state_root.display().to_string(),
                config_source: config_path.display().to_string(),
                process_start_identity: super::process_start_identity().unwrap(),
                executable_path: std::env::current_exe().unwrap().display().to_string(),
                executable_digest: "d".repeat(64),
                rex_endpoint: Some("fixture://rex".into()),
                rex_server_identity: Some("fixture-server".into()),
                rex_session_id: Some("fixture-session".into()),
                rex_block_id: Some("fixture-block".into()),
            })
            .unwrap();
        let project_id = ProjectId::parse("goal_project").unwrap();
        let profile_id = ProfileId::parse("judgment_claude").unwrap();
        let profile = applied.profiles.get(&profile_id).unwrap();
        let request = crate::store::provider_qualification_runtime::ProviderQualificationRequest {
            request_id: "qualification-cli-reconcile".into(),
            project_id,
            role: Role::Coordinator,
            profile_id,
            profile_digest: crate::store::agent_profile_digest(profile).unwrap(),
            config_revision: revision.0,
            config_digest: applied.digest.clone(),
            target: crate::store::provider_qualification_runtime::ProviderQualificationTarget::AppliedProfile,
        };
        store
            .enqueue_provider_qualification(generation, &request)
            .unwrap();
        let crate::store::provider_qualification_runtime::QualificationClaim::Claimed { .. } =
            store
                .claim_provider_qualification(generation, 1, 1)
                .unwrap()
        else {
            panic!("fixture qualification should reserve its normal slot");
        };
        store
            .mark_provider_qualification_unknown(generation, &request.request_id)
            .unwrap();
        let held_slot = store
            .provider_qualification_slot(&request.request_id)
            .unwrap()
            .unwrap();
        drop(store);

        super::dispatch_provider_command_for_test(&[
            "rex-projects",
            "--config",
            config_path.to_str().unwrap(),
            "--state-root",
            state_root.to_str().unwrap(),
            "--json",
            "provider",
            "reconcile",
            "--request-id",
            &request.request_id,
        ])
        .unwrap();

        let mut store = ConfigStore::open_test(&state_root).unwrap();
        let persisted = store
            .provider_qualification_job(&request.request_id)
            .unwrap()
            .unwrap();
        assert_eq!(persisted.request, request);
        assert_eq!(persisted.reconcile_requested_generation, Some(generation));
        assert_eq!(
            persisted.status,
            crate::store::provider_qualification_runtime::ProviderQualificationJobStatus::Unknown
        );
        assert_eq!(
            store
                .provider_qualification_slot(&request.request_id)
                .unwrap()
                .unwrap()
                .disposition,
            "unknown"
        );
        let recovered = store
            .claim_provider_qualification_recovery(generation, &request.request_id)
            .unwrap();
        assert_eq!(
            recovered.launch_phase,
            crate::store::provider_qualification_runtime::ProviderQualificationLaunchPhase::NotStarted
        );
        let retried_slot = store
            .provider_qualification_slot(&request.request_id)
            .unwrap()
            .unwrap();
        assert_eq!(retried_slot.slot_index, held_slot.slot_index);
        assert_eq!(retried_slot.reservation_epoch, held_slot.reservation_epoch);
        assert_eq!(retried_slot.disposition, "launch_pending");
    }

    #[test]
    fn role_contract_mailbox_commands_parse_with_the_supported_options() {
        let inbox = Cli::try_parse_from([
            "rex-projects",
            "agent",
            "inbox",
            "--run",
            "agent-test",
            "--control-dir",
            "/tmp/agent-test/control",
            "--json",
        ]);
        assert!(inbox.is_ok());

        let artifact = Cli::try_parse_from([
            "rex-projects",
            "agent",
            "artifact-add",
            "--run",
            "agent-test",
            "--control-dir",
            "/tmp/agent-test/control",
            "--path",
            "evidence.json",
            "--kind",
            "general",
            "--schema-version",
            "1",
            "--message-id",
            "artifact-request",
            "--json",
        ]);
        assert!(artifact.is_ok());

        let receipt = Cli::try_parse_from([
            "rex-projects",
            "agent",
            "receipt",
            "--run-id",
            "agent-test",
            "--control-dir",
            "/tmp/agent-test/control",
            "--request-id",
            "artifact-request",
            "--json",
        ]);
        assert!(receipt.is_ok());
    }

    #[test]
    fn read_projections_accept_the_public_command_shapes() {
        assert!(Cli::try_parse_from(["rex-projects", "project", "list", "--json"]).is_ok());
        assert!(
            Cli::try_parse_from([
                "rex-projects",
                "policy",
                "explain",
                "--repository",
                "repo-a",
                "--json"
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "rex-projects",
                "config",
                "diff",
                "--candidate",
                "candidate.toml",
                "--json"
            ])
            .is_ok()
        );
    }

    #[test]
    fn ticket_cli_contract_requires_project_scope_and_accepts_bounded_pagination() {
        let cli = Cli::try_parse_from([
            "rex-projects",
            "--json",
            "ticket",
            "list",
            "--project",
            "alpha",
            "--status",
            "in-progress",
            "--limit",
            "25",
            "--cursor",
            "page-2",
        ])
        .unwrap();
        assert!(cli.json);
        assert!(Cli::try_parse_from(["rex-projects", "ticket", "list"]).is_err());
        assert!(
            Cli::try_parse_from([
                "rex-projects",
                "ticket",
                "select",
                "--project",
                "alpha",
                "--id",
                "T-1"
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "rex-projects",
                "--json",
                "ticket",
                "blocked-reason",
                "--project",
                "alpha",
                "--run",
                "run-1",
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "rex-projects",
                "--json",
                "ticket",
                "resume-merge-decision",
                "--project",
                "alpha",
                "--run",
                "run-1",
                "--expected-subject-digest",
                &"a".repeat(64),
                "--request-id",
                "human-recovery-1",
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "rex-projects",
                "--json",
                "ticket",
                "recovery-status",
                "--request-id",
                "human-recovery-1",
            ])
            .is_ok()
        );
    }

    fn minimal_config(command: &str) -> String {
        format!(
            "schema_version = 1\n\n[adapters.tickets]\nkind = 'command'\ncommand = ['{command}']\n\n[projects]\n"
        )
    }

    #[test]
    fn projections_use_durable_applied_config_when_local_files_have_moved_on() {
        let temp = tempfile::tempdir().unwrap();
        let canonical_root = temp.path().canonicalize().unwrap();
        let config_file = canonical_root.join("config.toml");
        let state_root = canonical_root.join("state");
        std::fs::write(&config_file, minimal_config("ticket-cli-a")).unwrap();
        let applied = config::load(&config_file).unwrap();
        let source_identity = config_file.canonicalize().unwrap().display().to_string();
        ConfigStore::open_test(&state_root)
            .unwrap()
            .apply_snapshot(&source_identity, &applied, ExpectedRevision::Bootstrap)
            .unwrap();
        let db = state_root.join("state.sqlite3");
        let before_db = std::fs::read(&db).unwrap();
        let before_entries = std::fs::read_dir(&state_root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .filter(|name| name != "state.sqlite3-wal" && name != "state.sqlite3-shm")
            .collect::<std::collections::BTreeSet<_>>();
        ConfigStore::open_readonly(&state_root).unwrap();

        std::fs::write(&config_file, minimal_config("ticket-cli-b")).unwrap();
        let configured_now = config::load(&config_file).unwrap();
        let (effective, source, revision) =
            read_effective_snapshot(Some(&config_file), Some(&state_root), configured_now).unwrap();

        assert_eq!(source, "applied_snapshot");
        assert_eq!(revision, Some(1));
        assert_eq!(effective.config.adapters.tickets.command, ["ticket-cli-a"]);
        assert_eq!(std::fs::read(&db).unwrap(), before_db);
        assert!(!state_root.join("state.sqlite3-journal").exists());
        let after_entries = std::fs::read_dir(&state_root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .filter(|name| name != "state.sqlite3-wal" && name != "state.sqlite3-shm")
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(after_entries, before_entries);
    }

    #[test]
    fn configured_only_projection_does_not_create_state() {
        let temp = tempfile::tempdir().unwrap();
        let config_file = temp.path().join("config.toml");
        let state_root = temp.path().join("state");
        std::fs::write(&config_file, minimal_config("ticket-cli")).unwrap();
        let configured = config::load(&config_file).unwrap();
        let (effective, source, revision) =
            read_effective_snapshot(Some(&config_file), Some(&state_root), configured).unwrap();
        assert_eq!(source, "configured_snapshot");
        assert_eq!(revision, None);
        assert_eq!(effective.config.adapters.tickets.command, ["ticket-cli"]);
        assert!(!state_root.exists());
    }

    #[test]
    fn selection_json_does_not_claim_candidates_were_selected() {
        let report = super::ticket_candidates_report(&[], Some("next"));
        assert_eq!(report["selected"], false);
        assert_eq!(report["next_cursor"], "next");
    }

    #[test]
    fn ticket_terminal_output_replaces_control_characters() {
        assert_eq!(terminal_safe("safe\u{1b}[31m\ntext"), "safe�[31m�text");
    }

    #[test]
    fn ticket_view_mutations_reject_any_factory_marker() {
        assert!(factory_context_present(true, false));
        assert!(factory_context_present(false, true));
        assert!(!factory_context_present(false, false));
    }

    #[test]
    fn interactive_selection_displays_numbered_sanitized_choices() {
        let scope = crate::adapters::tickets::TicketScope::new(
            [("project".to_owned(), "alpha".to_owned())]
                .into_iter()
                .collect(),
        )
        .unwrap();
        let make_ticket =
            |id: &str, key: &str, title: &str| crate::adapters::tickets::NormalizedTicket {
                ticket_namespace: "fixture:repo".into(),
                scope: scope.clone(),
                id: id.into(),
                key: Some(key.into()),
                url: None,
                revision: None,
                title: title.into(),
                body: String::new(),
                status: crate::adapters::tickets::TicketStatusValue {
                    value: crate::adapters::tickets::NormalizedTicketStatus::Ready,
                    native_value: None,
                    provider_id: None,
                    label: None,
                },
                priority: None,
                labels: Vec::new(),
                dependencies: Vec::new(),
                created_at: None,
                updated_at: None,
                extensions: Default::default(),
            };
        let tickets = [
            make_ticket("ticket-1", "T-1", "first\nline"),
            make_ticket("ticket-2", "T-2", "second\u{1b}[31m"),
        ];

        let output = super::render_ticket_selection(&tickets);

        assert_eq!(
            output,
            " 1) T-1\tToDo\tfirst�line\n 2) T-2\tToDo\tsecond�[31m\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn list_queries_the_generic_cli_adapter_and_preserves_its_page_cursor() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let profiles = temp.path().join("profiles");
        for profile in ["judgment_claude", "worker_codex"] {
            let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("examples/fixture/profiles")
                .join(profile);
            let destination = profiles.join(profile);
            std::fs::create_dir_all(&destination).unwrap();
            std::fs::copy(source.join("config.toml"), destination.join("config.toml")).unwrap();
            std::fs::copy(
                source.join("instructions.md"),
                destination.join("instructions.md"),
            )
            .unwrap();
        }
        let adapter = temp.path().join("ticket-adapter");
        let result = r#"{"ticket_namespace":"example:repo","tickets":[{"ticket_namespace":"example:repo","scope":{"project":"example-goal"},"id":"ticket-1","key":"EX-1","title":"Fixture ticket","body":"Body","status":{"value":"ready","label":"Ready"}}],"applied_filters":{},"next_cursor":"cursor-next","observed_at":"2026-11-08T00:00:00Z","scan":{}}"#;
        let description = r#"{"ticket_namespace":"example:repo","identity":{},"supported_schema_versions":[1],"native_value_convention":"exact","status_values":{"triage":"Triage","backlog":"Backlog","ready":"Ready","in_progress":"In Progress","in_review":"In Review","done":"Done","canceled":"Canceled"},"capabilities":{"pagination":true,"filters":[],"revision_support":true,"conditional_revision_mutation":true,"atomic_scope_mutation":true,"remote_idempotency":[],"reconciliation":{},"visibility_grace_seconds":0,"supported_optional_methods":[]}}"#;
        let script = format!(
            "#!/bin/sh\ninput=$(cat)\nrequest_id=$(printf '%s' \"$input\" | sed -n 's/.*\\\"request_id\\\":\\\"//; s/\\\".*//; p')\nmethod=$(printf '%s' \"$input\" | sed -n 's/.*\\\"method\\\":\\\"//; s/\\\".*//; p')\ncase \"$method\" in\n adapter.describe) result='{}' ;;\n ticket.list) result='{}' ;;\n *) exit 9 ;;\nesac\nprintf '{{\"schema_version\":1,\"request_id\":\"%s\",\"result\":%s,\"error\":null}}\\n' \"$request_id\" \"$result\"\n",
            description, result
        );
        std::fs::write(&adapter, script).unwrap();
        std::fs::set_permissions(&adapter, std::fs::Permissions::from_mode(0o755)).unwrap();
        let config = include_str!("../examples/fixture/config.toml").replace(
            "/absolute/path/to/ticket-adapter",
            adapter.to_str().unwrap(),
        );
        let config_path = temp.path().join("config.toml");
        std::fs::write(&config_path, config).unwrap();

        let page = super::query_ticket_page(
            Some(&config_path),
            "goal_project",
            None,
            10,
            Some("cursor-prev"),
        )
        .unwrap();
        assert_eq!(page.tickets[0].key.as_deref(), Some("EX-1"));
        assert_eq!(page.next_cursor.as_deref(), Some("cursor-next"));
    }
}
