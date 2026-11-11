use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::domain::ids::{AdapterId, Digest, ProfileId, ProjectId, RepositoryId};
use crate::domain::types::{
    AgentAdapter, ApprovalMode, CommitConclusion, CommitMode, MergeExecutor, MergeMethod,
    OperationSource, ProjectMode, RecipeStage, Role, TicketStatus,
};

const MAX_SOURCE_FILE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub schema_version: u32,
    #[serde(default)]
    pub state_root: Option<String>,
    #[serde(default)]
    pub runtime: RuntimeConfig,
    pub adapters: AdaptersConfig,
    #[serde(default)]
    pub human: Option<HumanConfig>,
    #[serde(default)]
    pub knowledge: Option<KnowledgeConfig>,
    #[serde(default)]
    pub learning: LearningConfig,
    #[serde(default)]
    pub repositories: BTreeMap<RepositoryId, RepositoryConfig>,
    #[serde(default)]
    pub operation_actions: BTreeMap<String, OperationActionConfig>,
    #[serde(default)]
    pub operation_recipes: BTreeMap<String, OperationRecipe>,
    pub projects: BTreeMap<ProjectId, ProjectConfig>,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfig {
    #[serde(default = "default_rex_binary")]
    pub rex_binary: String,
    #[serde(default = "default_external_poll_seconds")]
    pub external_poll_seconds: u64,
    #[serde(default = "default_max_agent_runs")]
    pub max_agent_runs: usize,
    #[serde(default = "default_max_ticket_runs")]
    pub max_ticket_runs: usize,
    #[serde(default = "default_shutdown_grace_seconds")]
    pub shutdown_grace_seconds: u64,
    #[serde(default = "default_max_blocks_per_tab")]
    pub max_blocks_per_tab: usize,
    #[serde(default = "default_completed_blocks_to_keep")]
    pub completed_blocks_to_keep: usize,
    #[serde(default = "default_max_host_jobs")]
    pub max_host_jobs: usize,
    #[serde(default = "default_tab_retention_hours")]
    pub completed_ticket_tab_retention_hours: u64,
    #[serde(default = "default_max_hooks")]
    pub max_rex_projects_hook_runs: usize,
    #[serde(default)]
    pub environment: EnvironmentConfig,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            rex_binary: default_rex_binary(),
            external_poll_seconds: default_external_poll_seconds(),
            max_agent_runs: default_max_agent_runs(),
            max_ticket_runs: default_max_ticket_runs(),
            shutdown_grace_seconds: default_shutdown_grace_seconds(),
            max_blocks_per_tab: default_max_blocks_per_tab(),
            completed_blocks_to_keep: default_completed_blocks_to_keep(),
            max_host_jobs: default_max_host_jobs(),
            completed_ticket_tab_retention_hours: default_tab_retention_hours(),
            max_rex_projects_hook_runs: default_max_hooks(),
            environment: EnvironmentConfig::default(),
        }
    }
}

fn default_rex_binary() -> String {
    "rex".into()
}
fn default_external_poll_seconds() -> u64 {
    30
}
fn default_max_agent_runs() -> usize {
    8
}
fn default_max_ticket_runs() -> usize {
    3
}
fn default_shutdown_grace_seconds() -> u64 {
    30
}
fn default_max_blocks_per_tab() -> usize {
    8
}
fn default_max_host_jobs() -> usize {
    4
}
fn default_completed_blocks_to_keep() -> usize {
    1
}
fn default_tab_retention_hours() -> u64 {
    24
}
fn default_max_hooks() -> usize {
    2
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentConfig {
    #[serde(default = "default_environment_source")]
    pub source: EnvironmentSource,
    #[serde(default)]
    pub shell: Option<String>,
    #[serde(default = "default_environment_interactive")]
    pub interactive: bool,
    #[serde(default = "default_environment_timeout")]
    pub timeout_seconds: u64,
}

impl Default for EnvironmentConfig {
    fn default() -> Self {
        Self {
            source: default_environment_source(),
            shell: None,
            interactive: default_environment_interactive(),
            timeout_seconds: default_environment_timeout(),
        }
    }
}

fn default_environment_source() -> EnvironmentSource {
    EnvironmentSource::LoginShell
}
fn default_environment_timeout() -> u64 {
    15
}
fn default_environment_interactive() -> bool {
    true
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentSource {
    #[serde(alias = "current")]
    Inherit,
    LoginShell,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdaptersConfig {
    pub tickets: TicketAdapterConfig,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TicketAdapterConfig {
    pub kind: String,
    pub command: Vec<String>,
    #[serde(default)]
    pub environment_allow: Vec<String>,
    #[serde(default = "default_ticket_read_timeout")]
    pub read_timeout_seconds: u64,
    #[serde(default = "default_ticket_write_timeout")]
    pub write_timeout_seconds: u64,
}

fn default_ticket_read_timeout() -> u64 {
    30
}
fn default_ticket_write_timeout() -> u64 {
    120
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanConfig {
    pub kind: String,
    pub command: Vec<String>,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeConfig {
    pub format: String,
    pub root: String,
    pub max_source_bytes: u64,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LearningConfig {
    #[serde(default = "default_candidate_cap")]
    pub max_candidates_per_project: usize,
    #[serde(default = "default_learning_review_hours")]
    pub review_interval_hours: u64,
    #[serde(default = "default_trial_pairs")]
    pub max_trial_pairs_per_revision: usize,
    #[serde(default = "default_distinct_trial_inputs")]
    pub min_distinct_trial_inputs: usize,
}

impl Default for LearningConfig {
    fn default() -> Self {
        Self {
            max_candidates_per_project: 5,
            review_interval_hours: 24,
            max_trial_pairs_per_revision: 10,
            min_distinct_trial_inputs: 5,
        }
    }
}

fn default_candidate_cap() -> usize {
    5
}
fn default_learning_review_hours() -> u64 {
    24
}
fn default_trial_pairs() -> usize {
    10
}
fn default_distinct_trial_inputs() -> usize {
    5
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryConfig {
    pub clone_url: String,
    pub base_branch: String,
    pub forge: String,
    #[serde(default)]
    pub worktree_root: Option<String>,
    #[serde(default)]
    pub instruction_files: Vec<String>,
    #[serde(default)]
    pub role_instruction_files: BTreeMap<Role, Vec<String>>,
    #[serde(default)]
    pub rex_projects_hooks: Vec<HookConfig>,
    #[serde(default)]
    pub merge: MergeConfig,
    #[serde(default)]
    pub operations: Option<RepositoryOperationsConfig>,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HookConfig {
    pub id: String,
    pub command: Vec<String>,
    #[serde(default = "default_hook_timeout")]
    pub timeout_seconds: u64,
}
fn default_hook_timeout() -> u64 {
    900
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MergeConfig {
    #[serde(default)]
    pub auto_merge: bool,
    #[serde(default)]
    pub required_checks: Vec<String>,
    #[serde(default)]
    pub required_approvals: u32,
    #[serde(default = "default_check_conclusions")]
    pub allowed_check_conclusions: Vec<CommitConclusion>,
    #[serde(default)]
    pub minimum_reliability_score: u8,
    #[serde(default)]
    pub method: Option<MergeMethod>,
    #[serde(default)]
    pub executor: Option<MergeExecutor>,
    #[serde(default)]
    pub instructions: Option<String>,
    #[serde(default)]
    pub instruction_files: Vec<String>,
}

impl Default for MergeConfig {
    fn default() -> Self {
        Self {
            auto_merge: false,
            required_checks: Vec::new(),
            required_approvals: 0,
            allowed_check_conclusions: default_check_conclusions(),
            minimum_reliability_score: 85,
            method: None,
            executor: None,
            instructions: None,
            instruction_files: Vec::new(),
        }
    }
}
fn default_check_conclusions() -> Vec<CommitConclusion> {
    vec![CommitConclusion::Success]
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryOperationsConfig {
    pub recipe: String,
    #[serde(default)]
    pub allowed_actions: Vec<String>,
    #[serde(default)]
    pub human_approval_environments: Vec<String>,
    #[serde(default)]
    pub instruction_files: Vec<String>,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum OperationActionConfig {
    ForgeObservation,
    Command { command: Vec<String> },
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationRecipe {
    #[serde(default)]
    pub roles: BTreeMap<Role, ProfileId>,
    #[serde(default)]
    pub required_stages: Vec<RecipeStage>,
    #[serde(default)]
    pub required_evidence: Vec<String>,
    #[serde(default)]
    pub targets: Vec<OperationTarget>,
    #[serde(default)]
    pub not_required_reason: Option<String>,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationTarget {
    pub id: String,
    pub repository: RepositoryId,
    pub environment: String,
    pub action: String,
    #[serde(default)]
    pub depends_on: Vec<String>,
    pub source: OperationSource,
    #[serde(default)]
    pub selector: BTreeMap<String, String>,
    pub success_predicate: SuccessPredicate,
    pub timeout_seconds: u64,
    pub approval: ApprovalMode,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SuccessPredicate {
    TargetSucceeded,
    AllNamedJobsSucceeded {
        jobs: Vec<String>,
    },
    ExplicitNotRequired {
        reason: String,
        evidence: Vec<String>,
    },
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectConfig {
    pub mode: ProjectMode,
    pub ticket_adapter: AdapterId,
    #[serde(default)]
    pub ticket_scope: BTreeMap<String, serde_json::Value>,
    #[serde(default = "default_dispatch_states")]
    pub dispatch_states: Vec<TicketStatus>,
    #[serde(default)]
    pub repositories: Vec<RepositoryId>,
    #[serde(default)]
    pub auto_merge: bool,
    #[serde(default = "default_max_active_tickets")]
    pub max_active_tickets: usize,
    #[serde(default = "default_max_created_tickets")]
    pub max_created_tickets_per_goal_revision: usize,
    #[serde(default = "default_max_review_rounds")]
    pub max_review_rounds: usize,
    #[serde(default = "default_investigation_children")]
    pub max_investigation_children: usize,
    #[serde(default = "default_effect_retries")]
    pub max_effect_retries: usize,
    #[serde(default)]
    pub goal: Option<GoalConfig>,
    #[serde(default)]
    pub roles: BTreeMap<Role, ProfileId>,
    #[serde(default)]
    pub role_defaults_from: Option<ProjectId>,
    #[serde(default)]
    pub operation_matches: Vec<OperationMatch>,
}

fn default_dispatch_states() -> Vec<TicketStatus> {
    vec![TicketStatus::Ready]
}
fn default_max_active_tickets() -> usize {
    1
}
fn default_max_created_tickets() -> usize {
    20
}
fn default_max_review_rounds() -> usize {
    3
}
fn default_investigation_children() -> usize {
    2
}
fn default_effect_retries() -> usize {
    3
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoalConfig {
    pub revision: u64,
    pub statement: String,
    pub acceptance: Vec<String>,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationMatch {
    #[serde(default)]
    pub labels_all: Vec<String>,
    pub recipe: String,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub adapter: AgentAdapter,
    pub command: Vec<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub effort: Option<String>,
    #[serde(default = "default_turn_timeout")]
    pub turn_timeout_seconds: u64,
    #[serde(default)]
    pub instruction_files: Vec<String>,
    #[serde(default)]
    pub skill_paths: Vec<String>,
    #[serde(default)]
    pub commit_mode: CommitMode,
    #[serde(default)]
    pub learned_guidance: Option<LearnedGuidance>,
    #[serde(default)]
    pub options: Option<ProfileOptions>,
}
fn default_turn_timeout() -> u64 {
    1800
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ProfileOptions {
    Codex(CodexOptions),
    ClaudeCode(ClaudeCodeOptions),
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodexOptions {
    #[serde(default = "default_codex_sandbox")]
    pub sandbox: CodexSandbox,
    #[serde(default = "default_codex_approval")]
    pub approval: CodexApproval,
    #[serde(default)]
    pub approve_for_me: bool,
}
impl Default for CodexOptions {
    fn default() -> Self {
        Self {
            sandbox: default_codex_sandbox(),
            approval: default_codex_approval(),
            approve_for_me: false,
        }
    }
}
fn default_codex_sandbox() -> CodexSandbox {
    CodexSandbox::WorkspaceWrite
}
fn default_codex_approval() -> CodexApproval {
    CodexApproval::Never
}

#[derive(Clone, Copy, Debug, JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodexSandbox {
    WorkspaceWrite,
}
#[derive(Clone, Copy, Debug, JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodexApproval {
    Never,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaudeCodeOptions {
    #[serde(default = "default_claude_permission_mode")]
    pub permission_mode: ClaudePermissionMode,
    #[serde(default = "default_claude_prompts")]
    pub permission_prompts: ClaudePermissionPrompts,
}
impl Default for ClaudeCodeOptions {
    fn default() -> Self {
        Self {
            permission_mode: default_claude_permission_mode(),
            permission_prompts: default_claude_prompts(),
        }
    }
}
fn default_claude_permission_mode() -> ClaudePermissionMode {
    ClaudePermissionMode::Auto
}
fn default_claude_prompts() -> ClaudePermissionPrompts {
    ClaudePermissionPrompts::None
}
#[derive(Clone, Copy, Debug, JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaudePermissionMode {
    Auto,
}
#[derive(Clone, Copy, Debug, JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaudePermissionPrompts {
    None,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LearnedGuidance {
    pub file: String,
    pub project_id: ProjectId,
    pub role: Role,
    pub repository_ids: BTreeSet<RepositoryId>,
}

impl Profile {
    fn validate_adapter(&self, profile_name: &str) -> Result<(), String> {
        let matches = matches!(
            (&self.adapter, &self.options),
            (_, None)
                | (AgentAdapter::Codex, Some(ProfileOptions::Codex(_)))
                | (
                    AgentAdapter::ClaudeCode,
                    Some(ProfileOptions::ClaudeCode(_))
                )
        );
        if !matches {
            return Err(format!(
                "profile `{profile_name}` options do not match adapter"
            ));
        }
        if self.command.is_empty() || self.command.iter().any(String::is_empty) {
            return Err(format!(
                "profile `{profile_name}` command must be a nonempty argv"
            ));
        }
        if self.turn_timeout_seconds == 0 {
            return Err(format!(
                "profile `{profile_name}` turn_timeout_seconds must be positive"
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SourceFile {
    pub kind: SourceKind,
    pub path: String,
    pub canonical_path: String,
    pub sha256: Digest,
    pub bytes: u64,
    pub contents: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    File,
    Directory,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppliedConfig {
    pub config: Config,
    pub profiles: BTreeMap<ProfileId, Profile>,
    pub source_root: String,
    pub source_files: Vec<SourceFile>,
    pub digest: Digest,
}

pub fn load(path: &Path) -> Result<AppliedConfig, String> {
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| e.to_string())?
            .join(path)
    };
    let metadata = fs::symlink_metadata(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "configuration path must not be a symlink: {}",
            path.display()
        ));
    }
    let canonical_file = path
        .canonicalize()
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!(
            "configuration path is not a regular file: {}",
            path.display()
        ));
    }
    let root = canonical_file
        .parent()
        .ok_or_else(|| "configuration has no parent directory".to_owned())?
        .to_path_buf();
    let mut source_files = Vec::new();
    let config_text = read_source(&canonical_file, &canonical_file, &mut source_files)?;
    let deserializer = toml::Deserializer::parse(&config_text)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    let config: Config = serde_path_to_error::deserialize(deserializer)
        .map_err(|error| format!("{}: {}", path.display(), error))?;
    let profiles = load_profiles(&root, &mut source_files)?;
    validate_config(&config, &profiles)?;
    validate_file_references(&config, &profiles, &root, &mut source_files)?;
    source_files.sort_by(|a, b| a.path.cmp(&b.path));
    if source_files.len() > 1_024
        || source_files.iter().map(|source| source.bytes).sum::<u64>() > MAX_MANIFEST_BYTES
    {
        return Err("configuration manifest exceeds its 1,024 file or 32 MiB limit".into());
    }
    let first_manifest = digest_manifest(&config, &profiles, &source_files)?;
    let second_files = reread_sources(&source_files)?;
    let second_manifest = digest_manifest(&config, &profiles, &second_files)?;
    if first_manifest != second_manifest {
        return Err(
            "configuration inputs changed while they were being read; retry validation".into(),
        );
    }
    Ok(AppliedConfig {
        config,
        profiles,
        source_root: root.display().to_string(),
        source_files,
        digest: Digest::parse(first_manifest).map_err(|e| e.to_string())?,
    })
}

fn load_profiles(
    root: &Path,
    files: &mut Vec<SourceFile>,
) -> Result<BTreeMap<ProfileId, Profile>, String> {
    let directory = root.join("profiles");
    let entries = match fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(error) => return Err(format!("{}: {error}", directory.display())),
    };
    let mut entries = entries
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    entries.sort_by_key(|entry| entry.file_name());
    let mut profiles = BTreeMap::new();
    for entry in entries {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') {
            continue;
        }
        let id = ProfileId::parse(name.clone())?;
        let path = entry.path();
        if !fs::metadata(&path)
            .map_err(|e| format!("{}: {e}", path.display()))?
            .is_dir()
        {
            return Err(format!("{}: expected a profile directory", path.display()));
        }
        let canonical_dir = path
            .canonicalize()
            .map_err(|e| format!("{}: {e}", path.display()))?;
        record_directory_identity(&path, &canonical_dir, files)?;
        let config_path = canonical_dir.join("config.toml");
        let config_text = read_source(&config_path, &canonical_dir, files)?;
        let deserializer = toml::Deserializer::parse(&config_text)
            .map_err(|error| format!("{}: {error}", config_path.display()))?;
        let profile: Profile = serde_path_to_error::deserialize(deserializer)
            .map_err(|error| format!("{}: {}", config_path.display(), error))?;
        profile.validate_adapter(&name)?;
        if profiles.insert(id.clone(), profile).is_some() {
            return Err(format!("duplicate profile `{id}`"));
        }
    }
    Ok(profiles)
}

fn validate_config(config: &Config, profiles: &BTreeMap<ProfileId, Profile>) -> Result<(), String> {
    if config.schema_version != 1 {
        return Err(format!(
            "schema_version: unsupported version {}",
            config.schema_version
        ));
    }
    if config
        .state_root
        .as_deref()
        .is_some_and(|path| path.trim().is_empty())
    {
        return Err("state_root must be a nonempty path when configured".into());
    }
    let runtime = &config.runtime;
    for (name, value) in [
        (
            "runtime.external_poll_seconds",
            runtime.external_poll_seconds,
        ),
        ("runtime.max_agent_runs", runtime.max_agent_runs as u64),
        ("runtime.max_ticket_runs", runtime.max_ticket_runs as u64),
        ("runtime.max_host_jobs", runtime.max_host_jobs as u64),
        (
            "runtime.shutdown_grace_seconds",
            runtime.shutdown_grace_seconds,
        ),
        (
            "runtime.max_blocks_per_tab",
            runtime.max_blocks_per_tab as u64,
        ),
        (
            "runtime.completed_ticket_tab_retention_hours",
            runtime.completed_ticket_tab_retention_hours,
        ),
        (
            "runtime.max_rex_projects_hook_runs",
            runtime.max_rex_projects_hook_runs as u64,
        ),
        (
            "runtime.environment.timeout_seconds",
            runtime.environment.timeout_seconds,
        ),
    ] {
        if value == 0 {
            return Err(format!("{name} must be positive"));
        }
    }
    if runtime.completed_blocks_to_keep >= runtime.max_blocks_per_tab {
        return Err(
            "runtime.completed_blocks_to_keep must be less than runtime.max_blocks_per_tab".into(),
        );
    }
    if runtime
        .environment
        .shell
        .as_deref()
        .is_some_and(str::is_empty)
    {
        return Err("runtime.environment.shell must not be empty".into());
    }
    if !matches!(config.adapters.tickets.kind.as_str(), "command") {
        return Err("adapters.tickets.kind must be `command`".into());
    }
    validate_argv("adapters.tickets.command", &config.adapters.tickets.command)?;
    if config.adapters.tickets.read_timeout_seconds == 0
        || config.adapters.tickets.write_timeout_seconds == 0
    {
        return Err("ticket adapter timeouts must be positive".into());
    }
    if let Some(human) = &config.human {
        validate_argv("human.command", &human.command)?;
    }
    if let Some(knowledge) = &config.knowledge {
        if knowledge.format != "okf" {
            return Err(
                "knowledge.format must be `okf`; other formats are not supported yet".into(),
            );
        }
        if knowledge.max_source_bytes == 0 {
            return Err("knowledge.max_source_bytes must be positive".into());
        }
    }
    let learning = &config.learning;
    if [
        learning.max_candidates_per_project,
        learning.review_interval_hours as usize,
        learning.max_trial_pairs_per_revision,
        learning.min_distinct_trial_inputs,
    ]
    .contains(&0)
    {
        return Err("learning limits must be positive".into());
    }
    if learning.min_distinct_trial_inputs > learning.max_trial_pairs_per_revision {
        return Err(
            "learning.min_distinct_trial_inputs cannot exceed max_trial_pairs_per_revision".into(),
        );
    }

    for (repo_id, repo) in &config.repositories {
        if repo.clone_url.trim().is_empty() || repo.base_branch.trim().is_empty() {
            return Err(format!(
                "repositories.{repo_id}: clone_url and base_branch must be nonempty"
            ));
        }
        if !matches!(repo.forge.as_str(), "github" | "gitlab" | "forgejo") {
            return Err(format!(
                "repositories.{repo_id}.forge: unsupported forge `{}`",
                repo.forge
            ));
        }
        let mut hooks = BTreeSet::new();
        for hook in &repo.rex_projects_hooks {
            if !valid_key(&hook.id) || !hooks.insert(&hook.id) {
                return Err(format!(
                    "repositories.{repo_id}.rex_projects_hooks: invalid or duplicate id `{}`",
                    hook.id
                ));
            }
            validate_argv(
                &format!(
                    "repositories.{repo_id}.rex_projects_hooks.{}.command",
                    hook.id
                ),
                &hook.command,
            )?;
            if hook.timeout_seconds == 0 {
                return Err(format!(
                    "repositories.{repo_id}.rex_projects_hooks.{}.timeout_seconds must be positive",
                    hook.id
                ));
            }
        }
        if repo.merge.minimum_reliability_score > 100 {
            return Err(format!(
                "repositories.{repo_id}.merge.minimum_reliability_score must be between 0 and 100"
            ));
        }
        if repo.merge.auto_merge && (repo.merge.method.is_none() || repo.merge.executor.is_none()) {
            return Err(format!(
                "repositories.{repo_id}.merge.method and executor are required when auto_merge is enabled"
            ));
        }
        if repo.merge.auto_merge
            && (repo.merge.allowed_check_conclusions.is_empty()
                || repo
                    .merge
                    .required_checks
                    .iter()
                    .collect::<BTreeSet<_>>()
                    .len()
                    != repo.merge.required_checks.len())
        {
            return Err(format!(
                "repositories.{repo_id}.merge requires unique checks and at least one allowed successful conclusion for auto_merge"
            ));
        }
        if repo.merge.executor == Some(MergeExecutor::Request)
            && repo
                .merge
                .instructions
                .as_deref()
                .is_none_or(|instructions| instructions.trim().is_empty())
            && repo.merge.instruction_files.is_empty()
        {
            return Err(format!(
                "repositories.{repo_id}.merge requires instructions when executor is `request`"
            ));
        }
        if let Some(operations) = &repo.operations {
            if !config.operation_recipes.contains_key(&operations.recipe) {
                return Err(format!(
                    "repositories.{repo_id}.operations.recipe: unknown recipe `{}`",
                    operations.recipe
                ));
            }
            for action in &operations.allowed_actions {
                if !config.operation_actions.contains_key(action) {
                    return Err(format!(
                        "repositories.{repo_id}.operations.allowed_actions: unknown action `{action}`"
                    ));
                }
            }
        }
    }
    for (id, action) in &config.operation_actions {
        if !valid_key(id) {
            return Err(format!("operation_actions: invalid action id `{id}`"));
        }
        if let OperationActionConfig::Command { command } = action {
            validate_argv(&format!("operation_actions.{id}.command"), command)?;
        }
    }
    for (id, recipe) in &config.operation_recipes {
        if !valid_key(id) {
            return Err(format!("operation_recipes: invalid recipe id `{id}`"));
        }
        if recipe.targets.is_empty()
            && recipe
                .not_required_reason
                .as_deref()
                .is_none_or(str::is_empty)
        {
            return Err(format!(
                "operation_recipes.{id}: an empty target list requires not_required_reason"
            ));
        }
        if !recipe.targets.is_empty() && recipe.not_required_reason.is_some() {
            return Err(format!(
                "operation_recipes.{id}: not_required_reason is allowed only when targets is empty"
            ));
        }
        let mut target_ids = BTreeSet::new();
        for target in &recipe.targets {
            if !valid_key(&target.id) || !target_ids.insert(&target.id) {
                return Err(format!(
                    "operation_recipes.{id}.targets: invalid or duplicate target id `{}`",
                    target.id
                ));
            }
            let Some(repository) = config.repositories.get(&target.repository) else {
                return Err(format!(
                    "operation_recipes.{id}.targets.{}.repository: unknown repository `{}`",
                    target.id, target.repository
                ));
            };
            if !config.operation_actions.contains_key(&target.action) {
                return Err(format!(
                    "operation_recipes.{id}.targets.{}.action: unknown action `{}`",
                    target.id, target.action
                ));
            }
            let repo_operations = repository.operations.as_ref().ok_or_else(|| {
                format!(
                    "operation_recipes.{id}.targets.{}: repository `{}` has no operations policy",
                    target.id, target.repository
                )
            })?;
            if repo_operations.recipe != *id
                || !repo_operations.allowed_actions.contains(&target.action)
            {
                return Err(format!(
                    "operation_recipes.{id}.targets.{}: repository `{}` does not allow this recipe action",
                    target.id, target.repository
                ));
            }
            if target.timeout_seconds == 0 {
                return Err(format!(
                    "operation_recipes.{id}.targets.{}.timeout_seconds must be positive",
                    target.id
                ));
            }
            validate_selector(&target.id, &target.selector)?;
            if let SuccessPredicate::AllNamedJobsSucceeded { jobs } = &target.success_predicate
                && jobs.is_empty()
            {
                return Err(format!(
                    "operation_recipes.{id}.targets.{}.success_predicate.jobs must not be empty",
                    target.id
                ));
            }
            match (&target.success_predicate, target.approval) {
                (
                    SuccessPredicate::ExplicitNotRequired { reason, evidence },
                    ApprovalMode::NotRequired,
                ) if !reason.trim().is_empty()
                    && !evidence.is_empty()
                    && evidence.iter().all(|item| valid_key(item)) => {}
                (SuccessPredicate::ExplicitNotRequired { .. }, _) => {
                    return Err(format!(
                        "operation_recipes.{id}.targets.{}.explicit_not_required requires approval = `not_required`, a reason, and evidence",
                        target.id
                    ));
                }
                (_, ApprovalMode::NotRequired) => {
                    return Err(format!(
                        "operation_recipes.{id}.targets.{}.approval = `not_required` requires explicit_not_required evidence",
                        target.id
                    ));
                }
                _ => {}
            }
        }
        let known = target_ids.clone();
        for target in &recipe.targets {
            for dep in &target.depends_on {
                if !known.contains(dep) {
                    return Err(format!(
                        "operation_recipes.{id}.targets.{}.depends_on: unknown target `{dep}`",
                        target.id
                    ));
                }
            }
        }
        ensure_acyclic_targets(id, &recipe.targets)?;
        for profile_id in recipe.roles.values() {
            require_profile(
                profiles,
                profile_id,
                &format!("operation_recipes.{id}.roles"),
            )?;
        }
    }
    for (project_id, project) in &config.projects {
        if project.ticket_adapter.as_str() != "tickets" {
            return Err(format!(
                "projects.{project_id}.ticket_adapter: unknown adapter `{}`",
                project.ticket_adapter
            ));
        }
        if project.repositories.is_empty() {
            return Err(format!(
                "projects.{project_id}.repositories must not be empty"
            ));
        }
        if project.repositories.iter().collect::<BTreeSet<_>>().len() != project.repositories.len()
        {
            return Err(format!(
                "projects.{project_id}.repositories must not contain duplicates"
            ));
        }
        for repo in &project.repositories {
            if !config.repositories.contains_key(repo) {
                return Err(format!(
                    "projects.{project_id}.repositories: unknown repository `{repo}`"
                ));
            }
            if project.auto_merge {
                let policy = &config.repositories[repo].merge;
                if !policy.auto_merge || policy.required_checks.is_empty() {
                    return Err(format!(
                        "projects.{project_id}.auto_merge requires every repository to enable auto_merge with at least one required check"
                    ));
                }
            }
        }
        if project.max_active_tickets == 0
            || project.max_review_rounds == 0
            || project.max_investigation_children == 0
            || project.max_effect_retries == 0
            || (project.mode == ProjectMode::Goal
                && project.max_created_tickets_per_goal_revision == 0)
        {
            return Err(format!(
                "projects.{project_id}: execution limits must be positive"
            ));
        }
        match project.mode {
            ProjectMode::Goal => {
                let goal = project.goal.as_ref().ok_or_else(|| {
                    format!("projects.{project_id}.goal is required in goal mode")
                })?;
                if goal.revision == 0
                    || goal.statement.trim().is_empty()
                    || goal.acceptance.is_empty()
                    || goal.acceptance.iter().any(|s| s.trim().is_empty())
                {
                    return Err(format!(
                        "projects.{project_id}.goal requires a positive revision, statement, and nonempty acceptance"
                    ));
                }
                if !project.operation_matches.is_empty() {
                    return Err(format!(
                        "projects.{project_id}.operation_matches is allowed only in operations mode"
                    ));
                }
            }
            ProjectMode::Operations => {
                if project.goal.is_some() {
                    return Err(format!(
                        "projects.{project_id}.goal is not allowed in operations mode"
                    ));
                }
                if project.operation_matches.is_empty() {
                    return Err(format!(
                        "projects.{project_id}.operation_matches must not be empty in operations mode"
                    ));
                }
                for item in &project.operation_matches {
                    if !config.operation_recipes.contains_key(&item.recipe) {
                        return Err(format!(
                            "projects.{project_id}.operation_matches: unknown recipe `{}`",
                            item.recipe
                        ));
                    }
                    let recipe = config
                        .operation_recipes
                        .get(&item.recipe)
                        .expect("checked above");
                    if recipe
                        .targets
                        .iter()
                        .any(|target| !project.repositories.contains(&target.repository))
                    {
                        return Err(format!(
                            "projects.{project_id}.operation_matches: recipe `{}` targets a repository outside this Project",
                            item.recipe
                        ));
                    }
                }
            }
        }
        for status in &project.dispatch_states {
            if matches!(
                status,
                TicketStatus::Done
                    | TicketStatus::Canceled
                    | TicketStatus::InProgress
                    | TicketStatus::InReview
            ) {
                return Err(format!(
                    "projects.{project_id}.dispatch_states cannot include terminal or active state `{status:?}`"
                ));
            }
        }
        if project
            .role_defaults_from
            .as_ref()
            .is_some_and(|parent| !config.projects.contains_key(parent))
        {
            return Err(format!(
                "projects.{project_id}.role_defaults_from references an unknown Project"
            ));
        }
        for profile_id in project.roles.values() {
            require_profile(
                profiles,
                profile_id,
                &format!("projects.{project_id}.roles"),
            )?;
        }
    }
    validate_role_default_graph(&config.projects)?;
    for project_id in config.projects.keys() {
        let resolved = resolve_roles(project_id, &config.projects, &mut BTreeSet::new())?;
        for role in Role::ALL {
            let profile = resolved.get(&role).ok_or_else(|| {
                format!("projects.{project_id}.roles: missing `{role:?}` profile")
            })?;
            require_profile(
                profiles,
                profile,
                &format!("projects.{project_id}.roles.{role:?}"),
            )?;
        }
    }
    for (profile_id, profile) in profiles {
        let Some(learned) = &profile.learned_guidance else {
            continue;
        };
        let project = config.projects.get(&learned.project_id).ok_or_else(|| {
            format!(
                "profiles.{profile_id}.learned_guidance.project_id references an unknown Project"
            )
        })?;
        if learned.repository_ids.is_empty()
            || learned
                .repository_ids
                .iter()
                .any(|id| !project.repositories.contains(id))
        {
            return Err(format!(
                "profiles.{profile_id}.learned_guidance.repository_ids must be a nonempty subset of the Project repositories"
            ));
        }
        let roles = resolve_roles(&learned.project_id, &config.projects, &mut BTreeSet::new())?;
        if roles.get(&learned.role) != Some(profile_id) {
            return Err(format!(
                "profiles.{profile_id}.learned_guidance must match the configured profile for {:?} in Project {}",
                learned.role, learned.project_id
            ));
        }
    }
    Ok(())
}

fn validate_argv(path: &str, argv: &[String]) -> Result<(), String> {
    if argv.is_empty() || argv.iter().any(String::is_empty) {
        return Err(format!(
            "{path} must be a nonempty argv with no empty arguments"
        ));
    }
    Ok(())
}

fn valid_key(value: &str) -> bool {
    let mut chars = value.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

fn require_profile(
    profiles: &BTreeMap<ProfileId, Profile>,
    id: &ProfileId,
    path: &str,
) -> Result<(), String> {
    if !profiles.contains_key(id) {
        return Err(format!("{path}: unknown profile `{id}`"));
    }
    Ok(())
}

fn validate_role_default_graph(
    projects: &BTreeMap<ProjectId, ProjectConfig>,
) -> Result<(), String> {
    for id in projects.keys() {
        resolve_roles(id, projects, &mut BTreeSet::new())?;
    }
    Ok(())
}

fn resolve_roles<'a>(
    id: &'a ProjectId,
    projects: &'a BTreeMap<ProjectId, ProjectConfig>,
    visiting: &mut BTreeSet<ProjectId>,
) -> Result<BTreeMap<Role, ProfileId>, String> {
    if !visiting.insert(id.clone()) {
        return Err(format!("projects.{id}.role_defaults_from: cycle detected"));
    }
    let project = projects
        .get(id)
        .ok_or_else(|| format!("unknown project `{id}`"))?;
    let mut roles = if let Some(parent) = &project.role_defaults_from {
        resolve_roles(parent, projects, visiting)?
    } else {
        BTreeMap::new()
    };
    for (role, profile) in &project.roles {
        roles.insert(*role, profile.clone());
    }
    visiting.remove(id);
    Ok(roles)
}

pub fn effective_project_roles(
    project_id: &ProjectId,
    projects: &BTreeMap<ProjectId, ProjectConfig>,
) -> Result<BTreeMap<Role, ProfileId>, String> {
    resolve_roles(project_id, projects, &mut BTreeSet::new())
}

fn validate_selector(target_id: &str, selector: &BTreeMap<String, String>) -> Result<(), String> {
    const ALLOWED: &[&str] = &[
        "workflow",
        "job",
        "channel",
        "application",
        "environment",
        "ref",
        "branch",
        "tag",
    ];
    for key in selector.keys() {
        if !ALLOWED.contains(&key.as_str()) {
            return Err(format!(
                "operation target `{target_id}` selector has unsupported key `{key}`"
            ));
        }
    }
    Ok(())
}

fn ensure_acyclic_targets(recipe: &str, targets: &[OperationTarget]) -> Result<(), String> {
    fn visit(
        recipe: &str,
        key: &str,
        map: &BTreeMap<&str, &OperationTarget>,
        visiting: &mut BTreeSet<String>,
        done: &mut BTreeSet<String>,
    ) -> Result<(), String> {
        if done.contains(key) {
            return Ok(());
        }
        if !visiting.insert(key.to_owned()) {
            return Err(format!(
                "operation_recipes.{recipe}.targets: dependency cycle through `{key}`"
            ));
        }
        if let Some(node) = map.get(key) {
            for dependency in &node.depends_on {
                visit(recipe, dependency, map, visiting, done)?;
            }
        }
        visiting.remove(key);
        done.insert(key.to_owned());
        Ok(())
    }
    let map = targets
        .iter()
        .map(|target| (target.id.as_str(), target))
        .collect::<BTreeMap<_, _>>();
    let mut visiting = BTreeSet::new();
    let mut done = BTreeSet::new();
    for target in targets {
        visit(recipe, &target.id, &map, &mut visiting, &mut done)?;
    }
    Ok(())
}

fn validate_file_references(
    config: &Config,
    profiles: &BTreeMap<ProfileId, Profile>,
    root: &Path,
    files: &mut Vec<SourceFile>,
) -> Result<(), String> {
    for (id, repository) in &config.repositories {
        let mut relative = repository.instruction_files.clone();
        relative.extend(repository.merge.instruction_files.clone());
        if let Some(operations) = &repository.operations {
            relative.extend(operations.instruction_files.clone());
        }
        for paths in repository.role_instruction_files.values() {
            relative.extend(paths.clone());
        }
        for file in relative {
            read_source(&root.join(&file), root, files)
                .map_err(|e| format!("repositories.{id}: {e}"))?;
        }
    }
    for (id, profile) in profiles {
        let directory = root
            .join("profiles")
            .join(id.as_str())
            .canonicalize()
            .map_err(|e| format!("profiles.{id}: {e}"))?;
        let mut relative = profile.instruction_files.clone();
        for path in relative.drain(..) {
            read_source(&directory.join(&path), &directory, files)
                .map_err(|e| format!("profiles.{id}: {e}"))?;
        }
        let instructions = directory.join("instructions.md");
        if instructions.exists() {
            read_source(&instructions, &directory, files)
                .map_err(|e| format!("profiles.{id}: {e}"))?;
        }
        if let Some(learned) = &profile.learned_guidance {
            read_source(&directory.join(&learned.file), &directory, files)
                .map_err(|e| format!("profiles.{id}.learned_guidance: {e}"))?;
        }
        for skill in &profile.skill_paths {
            let path = PathBuf::from(skill);
            let path = if path.is_absolute() {
                path
            } else {
                directory.join(path)
            };
            collect_skill_files(&path, &directory, files)?;
        }
    }
    Ok(())
}

fn collect_skill_files(
    path: &Path,
    profile_root: &Path,
    files: &mut Vec<SourceFile>,
) -> Result<(), String> {
    let canonical = path
        .canonicalize()
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if !path.is_absolute() && !canonical.starts_with(profile_root) {
        return Err(format!("{} escapes its profile directory", path.display()));
    }
    let metadata = fs::metadata(&canonical).map_err(|e| format!("{}: {e}", canonical.display()))?;
    if metadata.is_file() {
        read_source(
            &canonical,
            if path.is_absolute() {
                &canonical
            } else {
                profile_root
            },
            files,
        )?;
        return Ok(());
    }
    if !metadata.is_dir() {
        return Err(format!(
            "{} is not a regular file or directory",
            canonical.display()
        ));
    }
    let mut entries = fs::read_dir(&canonical)
        .map_err(|e| format!("{}: {e}", canonical.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let child = entry.path();
        if fs::symlink_metadata(&child)
            .map_err(|e| e.to_string())?
            .file_type()
            .is_symlink()
        {
            return Err(format!(
                "skill content must not contain symlinks: {}",
                child.display()
            ));
        }
        collect_skill_files(&child, profile_root, files)?;
    }
    Ok(())
}

fn read_source(
    path: &Path,
    allowed_root: &Path,
    files: &mut Vec<SourceFile>,
) -> Result<String, String> {
    let canonical = path
        .canonicalize()
        .map_err(|e| format!("{}: {e}", path.display()))?;
    let allowed_root = allowed_root
        .canonicalize()
        .map_err(|e| format!("{}: {e}", allowed_root.display()))?;
    if !canonical.starts_with(&allowed_root) {
        return Err(format!(
            "{} escapes {}",
            path.display(),
            allowed_root.display()
        ));
    }
    let metadata = fs::metadata(&canonical).map_err(|e| format!("{}: {e}", canonical.display()))?;
    if !metadata.is_file() {
        return Err(format!("{} is not a regular file", canonical.display()));
    }
    if files
        .iter()
        .any(|file| file.path == path.display().to_string())
    {
        return files
            .iter()
            .find(|file| file.path == path.display().to_string())
            .map(|file| file.contents.clone())
            .ok_or_else(|| "source manifest lookup failed".to_owned());
    }
    if metadata.len() > MAX_SOURCE_FILE_BYTES {
        return Err(format!(
            "{} exceeds {} bytes",
            canonical.display(),
            MAX_SOURCE_FILE_BYTES
        ));
    }
    let bytes = fs::read(&canonical).map_err(|e| format!("{}: {e}", canonical.display()))?;
    let current_bytes = files.iter().map(|source| source.bytes).sum::<u64>();
    if files.len() >= 1_024 || current_bytes.saturating_add(bytes.len() as u64) > MAX_MANIFEST_BYTES
    {
        return Err("configuration source manifest exceeds its 1,024 file or 32 MiB limit".into());
    }
    let contents = String::from_utf8(bytes.clone())
        .map_err(|_| format!("{} must be UTF-8", canonical.display()))?;
    let relative = path.display().to_string();
    let canonical_path = canonical.display().to_string();
    let digest = format!("{:x}", Sha256::digest(&bytes));
    files.push(SourceFile {
        kind: SourceKind::File,
        path: relative,
        canonical_path,
        sha256: Digest::parse(digest)?,
        bytes: bytes.len() as u64,
        contents: contents.clone(),
    });
    Ok(contents)
}

fn record_directory_identity(
    path: &Path,
    canonical: &Path,
    files: &mut Vec<SourceFile>,
) -> Result<(), String> {
    let logical_path = path.display().to_string();
    let canonical_path = canonical.display().to_string();
    let digest = format!("{:x}", Sha256::digest(canonical_path.as_bytes()));
    files.push(SourceFile {
        kind: SourceKind::Directory,
        path: logical_path,
        canonical_path,
        sha256: Digest::parse(digest)?,
        bytes: 0,
        contents: String::new(),
    });
    Ok(())
}

fn reread_sources(sources: &[SourceFile]) -> Result<Vec<SourceFile>, String> {
    sources
        .iter()
        .map(|source| {
            let path = Path::new(&source.path);
            let canonical = path
                .canonicalize()
                .map_err(|e| format!("{}: {e}", path.display()))?;
            if canonical.display().to_string() != source.canonical_path {
                return Err(format!("{} changed its canonical target", path.display()));
            }
            if matches!(source.kind, SourceKind::Directory) {
                let digest = Digest::parse(format!(
                    "{:x}",
                    Sha256::digest(source.canonical_path.as_bytes())
                ))?;
                if digest != source.sha256 {
                    return Err(format!("{} changed its directory identity", path.display()));
                }
                return Ok(source.clone());
            }
            let bytes = fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
            let digest = Digest::parse(format!("{:x}", Sha256::digest(&bytes)))?;
            if digest != source.sha256 || bytes.len() as u64 != source.bytes {
                return Err(format!(
                    "{} changed while configuration was read",
                    path.display()
                ));
            }
            Ok(source.clone())
        })
        .collect()
}

fn digest_manifest(
    config: &Config,
    profiles: &BTreeMap<ProfileId, Profile>,
    files: &[SourceFile],
) -> Result<String, String> {
    let config_json = serde_json::to_value(config).map_err(|e| e.to_string())?;
    let profiles_json = serde_json::to_value(profiles).map_err(|e| e.to_string())?;
    let manifest = serde_json::json!({
        "digest_algorithm": "sha256",
        "representation": "canonical_json_utf8_sorted_keys",
        "config": config_json,
        "profiles": profiles_json,
        "sources": files.iter().map(|source| serde_json::json!({"kind": source.kind, "path": source.path, "canonical_path": source.canonical_path, "sha256": source.sha256, "bytes": source.bytes})).collect::<Vec<_>>(),
    });
    let mut bytes = serde_json::to_vec(&manifest).map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err("configuration source manifest exceeds the 32 MiB limit".into());
    }
    bytes.shrink_to_fit();
    Ok(format!("{:x}", Sha256::digest(&bytes)))
}

pub fn state_root(config: &Config, explicit: Option<&Path>) -> Result<PathBuf, String> {
    let selected = if let Some(explicit) = explicit {
        explicit.to_path_buf()
    } else if let Some(root) = &config.state_root {
        PathBuf::from(root)
    } else if let Some(root) = std::env::var_os("XDG_STATE_HOME") {
        PathBuf::from(root).join("rex-projects")
    } else {
        PathBuf::from(std::env::var_os("HOME").ok_or_else(|| "HOME is not set".to_owned())?)
            .join(".local/state/rex-projects")
    };
    let root = absolute_path(selected)?;
    if let Some(configured) = &config.state_root {
        let configured = absolute_path(PathBuf::from(configured))?;
        if explicit.is_some() && configured != root {
            return Err("--state-root does not match configured state_root".into());
        }
    }
    Ok(root)
}

fn absolute_path(path: PathBuf) -> Result<PathBuf, String> {
    let root = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()
            .map_err(|e| e.to_string())?
            .join(path)
    };
    for component in root.components() {
        if matches!(component, Component::ParentDir) {
            return Err("state root must not contain unresolved parent components".into());
        }
    }
    Ok(root)
}

pub fn schema<T: JsonSchema>() -> serde_json::Value {
    serde_json::to_value(schemars::schema_for!(T)).expect("JsonSchema serialization")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::Path;

    use super::{
        Config, EnvironmentConfig, EnvironmentSource, ProjectConfig, ensure_acyclic_targets,
    };
    use crate::domain::ids::{AdapterId, ProfileId, ProjectId};
    use crate::domain::types::{ProjectMode, Role};

    #[test]
    fn environment_defaults_to_bounded_interactive_login_shell_and_accepts_inherit() {
        let defaults = toml::from_str::<EnvironmentConfig>("").unwrap();
        assert_eq!(defaults.source, EnvironmentSource::LoginShell);
        assert!(defaults.interactive);
        assert_eq!(defaults.timeout_seconds, 15);

        let legacy = toml::from_str::<EnvironmentConfig>("source = 'current'").unwrap();
        assert_eq!(legacy.source, EnvironmentSource::Inherit);
        let explicit = toml::from_str::<EnvironmentConfig>("source = 'inherit'").unwrap();
        assert_eq!(explicit.source, EnvironmentSource::Inherit);
    }

    #[test]
    fn checked_in_goal_and_operations_fixture_is_valid() {
        let config_path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/fixture/config.toml");
        let loaded = super::load(&config_path).unwrap();
        assert_eq!(loaded.config.projects.len(), 2);
        assert_eq!(loaded.profiles.len(), 2);
        assert_eq!(loaded.source_files.len(), 7);
    }

    #[test]
    fn tracker_specific_adapter_kinds_are_rejected() {
        let config_path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/fixture/config.toml");
        let loaded = super::load(&config_path).unwrap();
        let mut config = loaded.config;
        config.adapters.tickets.kind = "tracker_native".into();
        assert!(
            super::validate_config(&config, &loaded.profiles)
                .unwrap_err()
                .contains("adapters.tickets.kind must be `command`")
        );
    }

    #[test]
    fn unsupported_knowledge_format_is_rejected_during_config_validation() {
        let config_path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/fixture/config.toml");
        let loaded = super::load(&config_path).unwrap();
        let mut config = loaded.config;
        config.knowledge = Some(super::KnowledgeConfig {
            format: "llmwiki".into(),
            root: "knowledge".into(),
            max_source_bytes: 1024,
        });
        assert!(
            super::validate_config(&config, &loaded.profiles)
                .unwrap_err()
                .contains("knowledge.format must be `okf`")
        );
    }

    #[test]
    fn explicit_state_root_is_absolute_and_must_match_configured_root() {
        let config_path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/fixture/config.toml");
        let mut config = super::load(&config_path).unwrap().config;
        let relative = super::state_root(&config, Some(Path::new("local-state"))).unwrap();
        assert!(relative.is_absolute());
        config.state_root = Some("/tmp/rex-projects-configured-state".into());
        assert!(super::state_root(&config, Some(Path::new("/tmp/other-state"))).is_err());
        assert_eq!(
            super::state_root(
                &config,
                Some(Path::new("/tmp/rex-projects-configured-state"))
            )
            .unwrap(),
            Path::new("/tmp/rex-projects-configured-state")
        );
    }

    #[test]
    fn automatic_merge_requires_project_and_repository_policy_with_checks() {
        let config_path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/fixture/config.toml");
        let mut loaded = super::load(&config_path).unwrap();
        loaded
            .config
            .projects
            .get_mut(&ProjectId::parse("goal_project").unwrap())
            .unwrap()
            .auto_merge = true;
        assert!(super::validate_config(&loaded.config, &loaded.profiles).is_err());

        let policy = &mut loaded
            .config
            .repositories
            .get_mut(&crate::domain::ids::RepositoryId::parse("example").unwrap())
            .unwrap()
            .merge;
        policy.auto_merge = true;
        policy.required_checks = vec!["test".into()];
        policy.method = Some(crate::domain::types::MergeMethod::Squash);
        policy.executor = Some(crate::domain::types::MergeExecutor::Direct);
        assert!(super::validate_config(&loaded.config, &loaded.profiles).is_ok());
    }

    #[test]
    fn rejects_unknown_fields_with_key_path() {
        let error = toml::from_str::<Config>("schema_version=1\nunknown=true\n[adapters.tickets]\nkind='command'\ncommand=['x']\n[projects.p]\nmode='goal'\nticket_adapter='tickets'\n").unwrap_err().to_string();
        assert!(error.contains("unknown"));
    }

    #[test]
    fn rejects_role_default_cycles() {
        let mut projects = BTreeMap::new();
        projects.insert(
            ProjectId::parse("a").unwrap(),
            ProjectConfig {
                mode: ProjectMode::Operations,
                ticket_adapter: AdapterId::parse("tickets").unwrap(),
                ticket_scope: BTreeMap::new(),
                dispatch_states: vec![],
                repositories: vec![],
                auto_merge: false,
                max_active_tickets: 1,
                max_created_tickets_per_goal_revision: 20,
                max_review_rounds: 3,
                max_investigation_children: 2,
                max_effect_retries: 3,
                goal: None,
                roles: BTreeMap::new(),
                role_defaults_from: Some(ProjectId::parse("b").unwrap()),
                operation_matches: vec![],
            },
        );
        let mut b = projects[&ProjectId::parse("a").unwrap()].clone();
        b.role_defaults_from = Some(ProjectId::parse("a").unwrap());
        projects.insert(ProjectId::parse("b").unwrap(), b);
        assert!(super::validate_role_default_graph(&projects).is_err());
    }

    #[test]
    fn operations_project_role_map_can_be_sparse_before_inheritance() {
        let _role = Role::Worker;
        let _profile = ProfileId::parse("worker_codex").unwrap();
    }

    #[test]
    fn operation_dependencies_reject_cycles() {
        use super::OperationTarget;
        use super::SuccessPredicate;
        use crate::domain::ids::RepositoryId;
        use crate::domain::types::{ApprovalMode, OperationSource};
        let mk = |id: &str, depends_on: Vec<&str>| OperationTarget {
            id: id.into(),
            repository: RepositoryId::parse("repo").unwrap(),
            environment: "test".into(),
            action: "observe".into(),
            depends_on: depends_on.into_iter().map(str::to_owned).collect(),
            source: OperationSource::parse("merge_commit").unwrap(),
            selector: BTreeMap::new(),
            success_predicate: SuccessPredicate::TargetSucceeded,
            timeout_seconds: 1,
            approval: ApprovalMode::RepositoryPolicy,
        };
        assert!(ensure_acyclic_targets("r", &[mk("a", vec!["b"]), mk("b", vec!["a"])]).is_err());
    }
}
