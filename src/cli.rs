use std::path::{Path, PathBuf};

use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::Serialize;

use crate::config::{self, AppliedConfig, Config};
use crate::domain::ids::Revision;
use crate::protocol::{RequestEnvelope, ResponseEnvelope};
use crate::store::{ConfigStore, ExpectedRevision};

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

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

pub fn run() -> Result<i32, CliError> {
    let args = std::env::args_os().collect::<Vec<_>>();
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
    let (path, loaded) = load_config(config_path)?;
    let canonical_source = path
        .canonicalize()
        .map_err(|error| CliError::usage(format!("{}: {error}", path.display())))?;
    let identity = canonical_source.display().to_string();
    let state_root =
        config::state_root(&loaded.config, explicit_state_root).map_err(CliError::usage)?;
    let mut store = ConfigStore::open(&state_root).map_err(CliError::unavailable)?;
    let expectation = match (args.bootstrap, args.expected_revision) {
        (true, None) => ExpectedRevision::Bootstrap,
        (false, Some(revision)) => ExpectedRevision::Current(Revision(revision)),
        _ => {
            return Err(CliError::usage(
                "choose exactly one of --bootstrap or --expected-revision",
            ));
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
