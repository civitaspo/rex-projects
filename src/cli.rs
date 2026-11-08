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
    /// Read the durable state of a provider qualification request.
    Status {
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
                if let Some(digest) = job.evidence_digest {
                    println!("Qualification receipt: {digest}");
                }
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
    }
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
        "occupied_slots":status.occupied_slots
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
    let owner = OwnerMetadata {
        owner_nonce: generated_request_id()?,
        state_root: state_root.display().to_string(),
        config_source: config_source.clone(),
        process_start_identity: process_start_identity()?,
        executable_path: executable_path.display().to_string(),
        executable_digest: executable_digest.clone(),
        rex_endpoint: Some(rex_identity.endpoint.clone()),
        rex_server_identity: Some(rex_identity.instance_id.clone()),
        rex_session_id: Some(rex_identity.session_id.clone()),
        rex_block_id: rex_identity.block_id.clone(),
    };
    let mut environment = crate::environment::capture(&snapshot.config.config.runtime.environment)
        .map_err(|error| CliError::unavailable(error.to_string()))?;
    let generation = store.start_owner(&owner).map_err(CliError::unavailable)?;
    let config_dir = canonical_source
        .parent()
        .ok_or_else(|| CliError::usage("configuration file has no parent directory"))?;
    let services = crate::runtime_services::RuntimeServices::new(
        &snapshot.config,
        &environment,
        config_dir,
        &state_root,
        generation,
        &rex_identity,
        &executable_path,
        &Digest::parse(executable_digest.clone()).map_err(CliError::usage)?,
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
    let started = unix_now_i64()?;
    let mut should_stop = false;
    loop {
        let mut consumed = 0;
        while consumed < 100 {
            let Some(command) = store
                .process_next_control(generation)
                .map_err(CliError::unexpected)?
            else {
                break;
            };
            consumed += 1;
            if let Some(applied) = command.applied_config
                && (applied.revision != snapshot.revision
                    || applied.digest != snapshot.config.digest)
            {
                snapshot = store.load_snapshot(&config_source)
                    .map_err(CliError::unexpected)?
                    .filter(|loaded| loaded.revision == applied.revision && loaded.config.digest == applied.digest)
                    .ok_or_else(|| CliError::unexpected("applied configuration snapshot is missing or does not match its durable receipt"))?;
                environment =
                    crate::environment::capture(&snapshot.config.config.runtime.environment)
                        .map_err(|error| CliError::unavailable(error.to_string()))?;
                let rebuilt = crate::runtime_services::RuntimeServices::new(
                    &snapshot.config,
                    &environment,
                    config_dir,
                    &state_root,
                    generation,
                    &rex_identity,
                    &executable_path,
                    &Digest::parse(executable_digest.clone()).map_err(CliError::usage)?,
                );
                services = match rebuilt {
                    Ok(services) => services,
                    Err(error) => {
                        let _ = store.stop_owner(generation);
                        return Err(CliError::unavailable(error));
                    }
                };
            }
            if command.kind == "machine_stop" {
                should_stop = true;
                break;
            }
        }
        store
            .heartbeat_owner(generation)
            .map_err(CliError::unavailable)?;
        if should_stop || STOP_REQUESTED.load(std::sync::atomic::Ordering::SeqCst) {
            break;
        }
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
            if let Err(error) = services.tick_provider_qualification_jobs(&mut store, tick_now) {
                eprintln!("rex-projects provider qualification: {error}");
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
        publish_owner_projection(
            &projection,
            generation,
            &owner,
            snapshot.revision.0,
            snapshot.config.digest.as_str(),
        )
        .map_err(CliError::unexpected)?;
        if once {
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    let stopped = store.stop_owner(generation).map_err(CliError::unavailable);
    if let Err(error) = stopped {
        return Err(CliError::unavailable(error.to_string()));
    }
    let _ = std::fs::remove_file(projection);
    if !once && STOP_REQUESTED.load(std::sync::atomic::Ordering::SeqCst) {
        return Err(CliError::unavailable(format!(
            "controller received a termination signal after {} seconds",
            unix_now_i64()?.saturating_sub(started)
        )));
    }
    if !once {
        println!("Foreground controller stopped after a durable stop request.");
    }
    Ok(())
}

static STOP_REQUESTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

extern "C" fn request_stop(_: libc::c_int) {
    STOP_REQUESTED.store(true, std::sync::atomic::Ordering::SeqCst);
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
    use crate::mailbox::{MailboxCapability, MailboxLimits, unix_time_now};
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
            let capability =
                MailboxCapability::open_registered(run_id, &control_dir, MailboxLimits::default())
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
        AgentCommand::Receipt {
            control_dir,
            run_id,
            request_id,
        } => {
            let capability =
                MailboxCapability::open_registered(run_id, &control_dir, MailboxLimits::default())
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
            if std::env::var("REX_PROJECTS_AGENT").as_deref() != Ok("1") {
                return Err(CliError::conflict(
                    "agent inbox can only run in a factory Agent context",
                ));
            }
            let capability = MailboxCapability::open_registered_for_run(&run_id, &control_dir)
                .map_err(CliError::unavailable)?;
            let inputs = crate::agent_api::read_inbox(capability.directory(), &run_id, after)
                .map_err(CliError::unavailable)?;
            let next_after = inputs
                .last()
                .map_or(after, |item| after.max(item.wake_input_id));
            if json {
                print_json(&serde_json::json!({
                    "run_id": run_id,
                    "after": after,
                    "next_after": next_after,
                    "inputs": inputs,
                }))
            } else {
                println!("Agent inbox has {} input(s) after {after}.", inputs.len());
                Ok(())
            }
        }
    }
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
    use crate::mailbox::{MailboxCapability, MailboxLimits, unix_time_now};
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
    let mailbox =
        MailboxCapability::open_registered(run_id, &control_dir, MailboxLimits::default())
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
            source_revision: option_env!("REX_PROJECTS_SOURCE_REVISION").map(str::to_owned),
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
        Cli, Command, ProviderCommand, factory_context_present, read_effective_snapshot,
        resolve_executable, terminal_safe,
    };
    use crate::config;
    use crate::store::{ConfigStore, ExpectedRevision};

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
