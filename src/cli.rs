use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};

use crate::adapters::rex::RexCliTransport;
use crate::config::{self, AppliedConfig, Config};
use crate::dashboard::RuntimeDashboardBackend;
use crate::domain::ids::{Digest, HumanRequestId, ProjectId, Revision};
use crate::process::{
    ProcessRequest, resolve_executable as resolve_process_executable, run as run_process,
};
use crate::protocol::{RequestEnvelope, ResponseEnvelope};
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
    if std::env::var_os("REX_PROJECTS_AGENT").is_some()
        || std::env::var_os("REX_PROJECTS_CONTEXT").is_some()
    {
        return Err(CliError::human_only(
            "this mutation is available only from a human host context; Agent blocks must submit scoped mailbox requests",
        ));
    }
    Ok(())
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
    require_human_context()?;
    match command {
        TicketCommand::Instruct {
            run,
            expected_revision,
            message_file,
            request_id,
        } => {
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

fn provider_command(
    config_path: Option<&Path>,
    explicit_state_root: Option<&Path>,
    command: ProviderCommand,
    json: bool,
) -> Result<(), CliError> {
    require_human_context()?;
    match command {
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
            let profile_json = serde_json::to_vec(profile)
                .map_err(|error| CliError::unexpected(error.to_string()))?;
            use sha2::{Digest as _, Sha256};
            let profile_digest = Digest::parse(format!("{:x}", Sha256::digest(profile_json)))
                .map_err(CliError::unexpected)?;
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

#[derive(Clone, Debug)]
struct RexConnectionBinding {
    endpoint: String,
    instance_id: String,
    session_id: Option<String>,
    block_id: Option<String>,
}

#[derive(Deserialize)]
struct RexWhoAmI {
    endpoint: String,
    instance_id: String,
}

fn discover_rex_binding(
    configured_binary: &str,
    explicit_server: Option<&str>,
) -> Result<Option<RexConnectionBinding>, CliError> {
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
        return Ok(None);
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
    Ok(Some(RexConnectionBinding {
        endpoint: who.endpoint,
        instance_id: who.instance_id,
        session_id,
        block_id,
    }))
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
    let rex_binding = discover_rex_binding(&loaded.config.runtime.rex_binary, rex_server_override)?;
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
        rex_binding.as_ref(),
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
        let tick_now = unix_now_i64()?;
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
        if !tick.external_errors.is_empty() {
            for error in tick.external_errors {
                eprintln!("rex-projects runtime: {error}");
            }
        }
        publish_owner_projection(
            &projection,
            generation,
            &owner,
            rex_binding.as_ref(),
            snapshot.revision.0,
            snapshot.config.digest.as_str(),
        )
        .map_err(CliError::unexpected)?;
        if should_stop || once || STOP_REQUESTED.load(std::sync::atomic::Ordering::SeqCst) {
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
    _rex_binding: Option<&RexConnectionBinding>,
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
    use super::resolve_executable;

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
}
