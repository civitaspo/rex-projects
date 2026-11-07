//! Typed operation planning and the external operation-adapter protocol.
//!
//! This module decides which configured rollout targets may run and validates
//! adapter evidence. The controller journals each request before an executor
//! performs it; no network or deployment effects happen inside this module.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::config::{
    AppliedConfig, Config, OperationActionConfig, OperationRecipe, OperationTarget,
    SuccessPredicate,
};
use crate::domain::ids::{
    Digest as ContentDigest, OperationId, ProjectId, RepositoryId, Revision, TicketId, TicketRunId,
};
use crate::domain::types::{ApprovalMode, OperationOutcome, OperationSource};
use crate::protocol::{MethodName, ProtocolError, RequestEnvelope, RequestId, ResponseEnvelope};

pub const OPERATION_PROTOCOL_VERSION: u32 = 1;
pub const MAX_ADAPTER_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_ADAPTER_STDERR_BYTES: usize = 64 * 1024;
pub const MAX_OPERATION_TIMEOUT_SECONDS: u64 = 24 * 60 * 60;

const METHODS: [&str; 4] = [
    "adapter.describe",
    "operation.invoke",
    "operation.observe",
    "operation.find",
];

#[derive(Clone, Debug, Serialize)]
pub struct ValidatedOperationPlan {
    recipe_id: String,
    digest: ContentDigest,
    /// Stable topological order. Independent targets use their configured ID order.
    targets: Vec<OperationTarget>,
    not_required_reason: Option<String>,
}

impl ValidatedOperationPlan {
    pub fn recipe_id(&self) -> &str {
        &self.recipe_id
    }
    pub fn digest(&self) -> &ContentDigest {
        &self.digest
    }
    pub fn targets(&self) -> &[OperationTarget] {
        &self.targets
    }
    pub fn not_required_reason(&self) -> Option<&str> {
        self.not_required_reason.as_deref()
    }
}

/// A ticket resolves to one recipe only when exactly one configured label
/// rule matches. Ambiguity is a human decision, never a first-match choice.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecipeSelection {
    Selected(String),
    NoMatch,
    Ambiguous(Vec<String>),
}

pub fn select_recipe(
    config: &Config,
    project_id: &ProjectId,
    labels: &[String],
) -> Result<RecipeSelection, PlanError> {
    let project = config
        .projects
        .get(project_id)
        .ok_or_else(|| invalid(format!("unknown project `{project_id}`")))?;
    let labels = labels.iter().collect::<BTreeSet<_>>();
    let matches = project
        .operation_matches
        .iter()
        .filter(|rule| rule.labels_all.iter().all(|label| labels.contains(label)))
        .map(|rule| rule.recipe.clone())
        .collect::<BTreeSet<_>>();
    Ok(match matches.len() {
        0 => RecipeSelection::NoMatch,
        1 => RecipeSelection::Selected(matches.into_iter().next().expect("one match")),
        _ => RecipeSelection::Ambiguous(matches.into_iter().collect()),
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlanError {
    Invalid(String),
}

impl std::fmt::Display for PlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(reason) => write!(f, "invalid operation plan: {reason}"),
        }
    }
}

impl std::error::Error for PlanError {}

/// Validates target authority and dependencies against the applied configuration.
pub fn validate_recipe(
    config: &Config,
    recipe_id: &str,
) -> Result<ValidatedOperationPlan, PlanError> {
    let recipe = config.operation_recipes.get(recipe_id).ok_or_else(|| {
        PlanError::Invalid(format!("operation recipe `{recipe_id}` is not configured"))
    })?;
    validate_recipe_value(config, recipe_id, recipe)
}

pub fn validate_recipe_value(
    config: &Config,
    recipe_id: &str,
    recipe: &OperationRecipe,
) -> Result<ValidatedOperationPlan, PlanError> {
    if recipe_id.is_empty() || recipe_id.len() > 255 {
        return Err(invalid("recipe ID must contain 1 to 255 bytes"));
    }
    if recipe.targets.is_empty() {
        let reason = recipe
            .not_required_reason
            .as_deref()
            .filter(|reason| !reason.trim().is_empty())
            .ok_or_else(|| {
                invalid("an empty operations recipe needs a non-empty not_required_reason")
            })?;
        return make_plan(recipe_id, recipe, Vec::new(), Some(reason.to_owned()));
    }
    if recipe.not_required_reason.is_some() {
        return Err(invalid(
            "not_required_reason is only valid for a recipe with no targets",
        ));
    }

    let mut by_id = BTreeMap::new();
    for target in &recipe.targets {
        if !valid_identifier(&target.id) {
            return Err(invalid(format!(
                "invalid operation target ID `{}`",
                target.id
            )));
        }
        if target.timeout_seconds == 0 || target.timeout_seconds > MAX_OPERATION_TIMEOUT_SECONDS {
            return Err(invalid(format!(
                "target `{}` timeout must be between 1 and {MAX_OPERATION_TIMEOUT_SECONDS} seconds",
                target.id
            )));
        }
        if by_id.insert(target.id.as_str(), target).is_some() {
            return Err(invalid(format!(
                "duplicate operation target ID `{}`",
                target.id
            )));
        }
        validate_predicate(target)?;

        let repository = config.repositories.get(&target.repository).ok_or_else(|| {
            invalid(format!(
                "target `{}` references unknown repository `{}`",
                target.id, target.repository
            ))
        })?;
        let operations = repository.operations.as_ref().ok_or_else(|| {
            invalid(format!(
                "repository `{}` has no operations policy for target `{}`",
                target.repository, target.id
            ))
        })?;
        if operations.recipe != recipe_id {
            return Err(invalid(format!(
                "repository `{}` selects recipe `{}` but the Project selected `{recipe_id}`",
                target.repository, operations.recipe
            )));
        }
        if !operations
            .allowed_actions
            .iter()
            .any(|allowed| allowed == &target.action)
        {
            return Err(invalid(format!(
                "action `{}` is not allowed for repository `{}`",
                target.action, target.repository
            )));
        }
        let action = config
            .operation_actions
            .get(&target.action)
            .ok_or_else(|| invalid(format!("action `{}` is not configured", target.action)))?;
        if let OperationActionConfig::Command { command } = action
            && (command.is_empty() || command.iter().any(|argument| argument.contains('\0')))
        {
            return Err(invalid(format!(
                "command action `{}` must contain a non-empty argv without NUL bytes",
                target.action
            )));
        }
    }

    let mut indegree = BTreeMap::<&str, usize>::new();
    let mut dependents = BTreeMap::<&str, Vec<&str>>::new();
    for target in &recipe.targets {
        let mut unique_dependencies = BTreeSet::new();
        for dependency in &target.depends_on {
            if dependency == &target.id || !unique_dependencies.insert(dependency.as_str()) {
                return Err(invalid(format!(
                    "target `{}` has a self or duplicate dependency `{dependency}`",
                    target.id
                )));
            }
            if !by_id.contains_key(dependency.as_str()) {
                return Err(invalid(format!(
                    "target `{}` depends on unknown target `{dependency}`",
                    target.id
                )));
            }
            dependents.entry(dependency).or_default().push(&target.id);
        }
        indegree.insert(&target.id, unique_dependencies.len());
    }

    let mut ready = indegree
        .iter()
        .filter_map(|(id, degree)| (*degree == 0).then_some(*id))
        .collect::<BTreeSet<_>>();
    let mut ordered = Vec::with_capacity(recipe.targets.len());
    while let Some(id) = ready.pop_first() {
        ordered.push((*by_id[id]).clone());
        if let Some(children) = dependents.get(id) {
            for child in children {
                let degree = indegree
                    .get_mut(child)
                    .expect("every dependent is a known target");
                *degree -= 1;
                if *degree == 0 {
                    ready.insert(*child);
                }
            }
        }
    }
    if ordered.len() != recipe.targets.len() {
        return Err(invalid("operation target dependencies contain a cycle"));
    }
    make_plan(recipe_id, recipe, ordered, None)
}

fn validate_predicate(target: &OperationTarget) -> Result<(), PlanError> {
    match &target.success_predicate {
        SuccessPredicate::TargetSucceeded => Ok(()),
        SuccessPredicate::AllNamedJobsSucceeded { jobs } => {
            let unique = jobs.iter().collect::<BTreeSet<_>>();
            if jobs.is_empty()
                || unique.len() != jobs.len()
                || jobs.iter().any(|job| job.trim().is_empty())
            {
                Err(invalid(format!(
                    "target `{}` needs unique non-empty named jobs",
                    target.id
                )))
            } else {
                Ok(())
            }
        }
        SuccessPredicate::ExplicitNotRequired { reason, evidence } => {
            let unique = evidence.iter().collect::<BTreeSet<_>>();
            if reason.trim().is_empty()
                || evidence.is_empty()
                || unique.len() != evidence.len()
                || evidence.iter().any(|item| item.trim().is_empty())
            {
                Err(invalid(format!(
                    "target `{}` explicit not-required predicate needs a reason and unique evidence IDs",
                    target.id
                )))
            } else {
                Ok(())
            }
        }
    }
}

fn make_plan(
    recipe_id: &str,
    source_recipe: &OperationRecipe,
    targets: Vec<OperationTarget>,
    not_required_reason: Option<String>,
) -> Result<ValidatedOperationPlan, PlanError> {
    let canonical = serde_json::to_vec(&(recipe_id, source_recipe))
        .map_err(|error| invalid(format!("cannot encode operation plan: {error}")))?;
    let digest = ContentDigest::parse(format!("{:x}", Sha256::digest(canonical)))
        .map_err(PlanError::Invalid)?;
    Ok(ValidatedOperationPlan {
        recipe_id: recipe_id.to_owned(),
        digest,
        targets,
        not_required_reason,
    })
}

fn invalid(reason: impl Into<String>) -> PlanError {
    PlanError::Invalid(reason.into())
}

fn valid_identifier(value: &str) -> bool {
    let mut chars = value.bytes();
    matches!(chars.next(), Some(first) if first.is_ascii_alphanumeric())
        && chars.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TargetReadiness {
    Ready,
    WaitingFor(Vec<String>),
    BlockedBy(Vec<String>),
    HumanApprovalRequired(String),
    NeedsReconciliation(String),
    RetryRequiresExplicitAuthorization(String),
    AlreadyTerminal,
}

/// Canonical identity of the exact operation a human is authorizing. The
/// digest is persisted with the request and must match at invocation time.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationSubject {
    pub project_id: ProjectId,
    pub ticket_id: TicketId,
    pub ticket_run_id: TicketRunId,
    pub ticket_revision: Revision,
    pub operation_id: OperationId,
    pub recipe_id: String,
    pub plan_digest: ContentDigest,
    pub config_digest: ContentDigest,
    pub target_id: String,
    pub action_id: String,
    pub repository_id: RepositoryId,
    pub environment: String,
    pub source_sha: String,
    pub expected_preconditions: BTreeMap<String, Value>,
}

impl OperationSubject {
    pub fn digest(&self) -> Result<ContentDigest, String> {
        if !valid_git_sha(&self.source_sha) {
            return Err("operation subject must bind a full Git object ID".into());
        }
        let canonical = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        ContentDigest::parse(format!("{:x}", Sha256::digest(canonical)))
    }
}

/// Host-recorded human decision, bound to the complete immutable operation
/// subject. A boolean without this subject digest is not an authorization.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanApprovalReceipt {
    pub request_id: String,
    pub subject_digest: ContentDigest,
    pub approved: bool,
    pub decided_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorizationError {
    Invalid(String),
    ApprovalRequired,
    Rejected,
    StaleApproval,
}

impl std::fmt::Display for AuthorizationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(reason) => write!(f, "invalid operation authorization: {reason}"),
            Self::ApprovalRequired => f.write_str("human approval is required"),
            Self::Rejected => f.write_str("human rejected this operation"),
            Self::StaleApproval => {
                f.write_str("approval is bound to a different operation subject")
            }
        }
    }
}

impl std::error::Error for AuthorizationError {}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CommandExecutionBinding {
    argv: Vec<String>,
    executable_digest: ContentDigest,
    digest: ContentDigest,
}

fn applied_snapshot_fingerprint(applied: &AppliedConfig) -> Result<ContentDigest, String> {
    let canonical = serde_json::to_vec(&(
        &applied.config,
        &applied.profiles,
        &applied.source_files,
        &applied.digest,
    ))
    .map_err(|error| error.to_string())?;
    ContentDigest::parse(format!("{:x}", Sha256::digest(canonical)))
}

fn bind_command_execution(
    action: &OperationActionConfig,
) -> Result<Option<CommandExecutionBinding>, String> {
    let OperationActionConfig::Command { command } = action else {
        return Ok(None);
    };
    let Some((executable, arguments)) = command.split_first() else {
        return Err("configured operation command is empty".into());
    };
    if executable.is_empty()
        || command
            .iter()
            .any(|argument| argument.is_empty() || argument.contains('\0'))
    {
        return Err("configured operation argv contains an empty argument or NUL byte".into());
    }
    let search_path = std::env::var_os("PATH")
        .map(|path| std::env::split_paths(&path).collect::<Vec<_>>())
        .unwrap_or_default();
    let executable = crate::process::resolve_executable(Path::new(executable), &search_path)
        .ok_or_else(|| "configured operation executable is unavailable".to_owned())?;
    let mut file = File::open(&executable)
        .map_err(|_| "configured operation executable cannot be read".to_owned())?;
    let metadata_before = file
        .metadata()
        .map_err(|_| "configured operation executable metadata is unavailable".to_owned())?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| "configured operation executable cannot be hashed".to_owned())?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let metadata_after = file
        .metadata()
        .map_err(|_| "configured operation executable metadata is unavailable".to_owned())?;
    if metadata_before.len() != metadata_after.len()
        || metadata_before.modified().ok() != metadata_after.modified().ok()
    {
        return Err("configured operation executable changed while it was being hashed".into());
    }
    let executable_digest = ContentDigest::parse(format!("{:x}", hasher.finalize()))?;
    let mut argv = Vec::with_capacity(command.len());
    argv.push(executable.display().to_string());
    argv.extend(arguments.iter().cloned());
    let canonical =
        serde_json::to_vec(&(&argv, &executable_digest)).map_err(|error| error.to_string())?;
    let digest = ContentDigest::parse(format!("{:x}", Sha256::digest(canonical)))?;
    Ok(Some(CommandExecutionBinding {
        argv,
        executable_digest,
        digest,
    }))
}

/// Private fields prevent callers from constructing permits from a free
/// `approved` boolean. Obtain one only after checking the current repository
/// policy and exact approval receipt.
#[derive(Clone, Debug)]
pub struct OperationPermit {
    subject: OperationSubject,
    selector: BTreeMap<String, String>,
    approval_digest: Option<ContentDigest>,
    command: Option<CommandExecutionBinding>,
    applied_config_digest: ContentDigest,
    applied_snapshot_fingerprint: ContentDigest,
    authority_digest: ContentDigest,
    timeout_seconds: u64,
}

impl OperationPermit {
    pub fn subject(&self) -> &OperationSubject {
        &self.subject
    }
    pub fn approval_digest(&self) -> Option<&ContentDigest> {
        self.approval_digest.as_ref()
    }

    pub fn stable_correlation_key(&self) -> Result<String, String> {
        Ok(format!(
            "operation:{}:{}:{}",
            self.subject.operation_id,
            self.subject.target_id,
            self.subject.digest()?
        ))
    }

    pub fn invoke_params(&self) -> Result<InvokeParams, String> {
        Ok(InvokeParams {
            action_id: self.subject.action_id.clone(),
            target_id: self.subject.target_id.clone(),
            repository_id: self.subject.repository_id.clone(),
            environment: self.subject.environment.clone(),
            source_sha: self.subject.source_sha.clone(),
            plan_digest: self.subject.plan_digest.clone(),
            correlation_key: self.stable_correlation_key()?,
            selector: self.selector.clone(),
            parameters: BTreeMap::new(),
            expected_preconditions: self.subject.expected_preconditions.clone(),
            approval_digest: self.approval_digest.clone(),
        })
    }

    pub fn invoke_request(
        &self,
        request_id: impl Into<String>,
    ) -> Result<RequestEnvelope<InvokeParams>, String> {
        new_request(
            request_id,
            Some(self.subject.operation_id.clone()),
            Some(self.subject.project_id.clone()),
            "operation.invoke",
            self.invoke_params()?,
        )
    }
}

pub fn authorize_operation(
    applied: &AppliedConfig,
    delivery_facts: &DeliveryFacts,
    plan: &ValidatedOperationPlan,
    target: &OperationTarget,
    subject: OperationSubject,
    approval: Option<&HumanApprovalReceipt>,
) -> Result<OperationPermit, AuthorizationError> {
    let config = &applied.config;
    let applied_config_digest =
        ContentDigest::parse(applied.digest.to_string()).map_err(AuthorizationError::Invalid)?;
    let applied_snapshot_fingerprint =
        applied_snapshot_fingerprint(applied).map_err(AuthorizationError::Invalid)?;
    let authoritative_plan = validate_recipe(config, &plan.recipe_id)
        .map_err(|error| AuthorizationError::Invalid(error.to_string()))?;
    let same_targets = serde_json::to_value(&plan.targets).ok()
        == serde_json::to_value(&authoritative_plan.targets).ok();
    if plan.digest != authoritative_plan.digest
        || plan.not_required_reason != authoritative_plan.not_required_reason
        || !same_targets
    {
        return Err(AuthorizationError::Invalid(
            "operation plan does not match the current applied recipe".into(),
        ));
    }
    let repository = config
        .repositories
        .get(&target.repository)
        .ok_or_else(|| AuthorizationError::Invalid("target repository is not configured".into()))?;
    let policy = repository
        .operations
        .as_ref()
        .ok_or_else(|| AuthorizationError::Invalid("repository has no operations policy".into()))?;
    let action = config
        .operation_actions
        .get(&target.action)
        .ok_or_else(|| AuthorizationError::Invalid("target action is not configured".into()))?;
    let project = config
        .projects
        .get(&subject.project_id)
        .ok_or_else(|| AuthorizationError::Invalid("operation project is not configured".into()))?;
    let resolved_source = resolve_source(&target.source, &target.repository, delivery_facts)
        .map_err(|error| AuthorizationError::Invalid(error.to_string()))?;
    let target_is_planned = plan.targets.iter().any(|candidate| {
        candidate.id == target.id
            && serde_json::to_value(candidate).ok() == serde_json::to_value(target).ok()
    });
    if subject.recipe_id != plan.recipe_id
        || subject.plan_digest != plan.digest
        || subject.config_digest != applied_config_digest
        || subject.target_id != target.id
        || subject.action_id != target.action
        || subject.repository_id != target.repository
        || subject.environment != target.environment
        || subject.source_sha != resolved_source
        || !project.repositories.contains(&target.repository)
        || policy.recipe != plan.recipe_id
        || !policy
            .allowed_actions
            .iter()
            .any(|candidate| candidate == &target.action)
        || !target_is_planned
        || matches!(action, OperationActionConfig::Command { command } if command.is_empty())
    {
        return Err(AuthorizationError::Invalid(
            "operation subject does not match the current plan and repository policy".into(),
        ));
    }
    if !valid_git_sha(&subject.source_sha) {
        return Err(AuthorizationError::Invalid(
            "operation source must be a full Git object ID".into(),
        ));
    }
    let requires_human = matches!(target.approval, ApprovalMode::Always)
        || policy
            .human_approval_environments
            .iter()
            .any(|environment| environment == &target.environment);
    let approval_digest = if requires_human {
        let receipt = approval.ok_or(AuthorizationError::ApprovalRequired)?;
        let subject_digest = subject.digest().map_err(AuthorizationError::Invalid)?;
        if receipt.subject_digest != subject_digest
            || receipt.request_id.trim().is_empty()
            || receipt.decided_at.trim().is_empty()
        {
            return Err(AuthorizationError::StaleApproval);
        }
        if !receipt.approved {
            return Err(AuthorizationError::Rejected);
        }
        Some(receipt.subject_digest.clone())
    } else {
        if approval.is_some() {
            return Err(AuthorizationError::Invalid(
                "unexpected approval receipt for an operation that does not require human approval"
                    .into(),
            ));
        }
        None
    };
    let command = bind_command_execution(action).map_err(AuthorizationError::Invalid)?;
    let authority_digest = operation_authority_digest(
        config,
        &subject.project_id,
        &plan.recipe_id,
        &target.repository,
        &target.action,
    )
    .map_err(AuthorizationError::Invalid)?;
    Ok(OperationPermit {
        subject,
        selector: target.selector.clone(),
        approval_digest,
        command,
        applied_config_digest,
        applied_snapshot_fingerprint,
        authority_digest,
        timeout_seconds: target.timeout_seconds,
    })
}

fn operation_authority_digest(
    config: &Config,
    project_id: &ProjectId,
    recipe_id: &str,
    repository_id: &RepositoryId,
    action_id: &str,
) -> Result<ContentDigest, String> {
    let repository_policy = config
        .repositories
        .get(repository_id)
        .and_then(|repository| repository.operations.as_ref())
        .ok_or_else(|| "repository operation policy is missing".to_owned())?;
    let action = config
        .operation_actions
        .get(action_id)
        .ok_or_else(|| "operation action is missing".to_owned())?;
    let project = config
        .projects
        .get(project_id)
        .ok_or_else(|| "operation project is missing".to_owned())?;
    let recipe = config
        .operation_recipes
        .get(recipe_id)
        .ok_or_else(|| "operation recipe is missing".to_owned())?;
    let canonical = serde_json::to_vec(&(
        recipe_id,
        recipe,
        repository_policy,
        action,
        &project.repositories,
        &project.operation_matches,
    ))
    .map_err(|error| error.to_string())?;
    ContentDigest::parse(format!("{:x}", Sha256::digest(canonical)))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationStatus {
    Queued,
    Running,
    AwaitingApproval,
    Succeeded,
    Failed,
    Cancelled,
    Skipped,
    Missing,
    TimedOut,
    Unknown,
}

/// Returns whether a rollout target may be invoked. `RepositoryPolicy` can be
/// strengthened by the repository's configured human-approval environments.
pub fn target_readiness(
    config: &Config,
    target: &OperationTarget,
    completed: &BTreeMap<String, OperationStatus>,
    current: Option<OperationStatus>,
) -> Result<TargetReadiness, PlanError> {
    match current {
        Some(OperationStatus::Succeeded) => {
            return Ok(TargetReadiness::AlreadyTerminal);
        }
        Some(OperationStatus::Skipped) => {
            return Ok(TargetReadiness::NeedsReconciliation(
                "validate the configured explicit-not-required predicate and evidence before treating a skipped target as complete".into(),
            ));
        }
        Some(
            OperationStatus::Queued | OperationStatus::Running | OperationStatus::AwaitingApproval,
        ) => {
            return Ok(TargetReadiness::NeedsReconciliation(
                "the operation already has a pending external execution".into(),
            ));
        }
        Some(OperationStatus::Unknown) => {
            return Ok(TargetReadiness::NeedsReconciliation(
                "observe or find the existing operation before any retry".into(),
            ));
        }
        Some(
            OperationStatus::Failed
            | OperationStatus::Cancelled
            | OperationStatus::Missing
            | OperationStatus::TimedOut,
        ) => {
            return Ok(TargetReadiness::RetryRequiresExplicitAuthorization(
                "a terminal failed operation requires controller recovery policy and a new authorized attempt".into(),
            ));
        }
        None => {}
    }
    let mut waiting = Vec::new();
    let mut blocked = Vec::new();
    for dependency in &target.depends_on {
        match completed.get(dependency) {
            // A raw external `skipped` status is not dependency success. The
            // controller may persist it as target success only after the
            // configured explicit-not-required predicate and evidence pass.
            Some(OperationStatus::Succeeded) => {}
            Some(
                OperationStatus::Failed
                | OperationStatus::Cancelled
                | OperationStatus::Skipped
                | OperationStatus::Missing
                | OperationStatus::TimedOut,
            ) => {
                blocked.push(dependency.clone());
            }
            Some(
                OperationStatus::Queued
                | OperationStatus::Running
                | OperationStatus::AwaitingApproval
                | OperationStatus::Unknown,
            )
            | None => {
                waiting.push(dependency.clone());
            }
        }
    }
    if !blocked.is_empty() {
        return Ok(TargetReadiness::BlockedBy(blocked));
    }
    if !waiting.is_empty() {
        return Ok(TargetReadiness::WaitingFor(waiting));
    }

    let repository = config.repositories.get(&target.repository).ok_or_else(|| {
        invalid(format!(
            "target `{}` references an unknown repository",
            target.id
        ))
    })?;
    let policy = repository.operations.as_ref().ok_or_else(|| {
        invalid(format!(
            "repository `{}` has no operation policy",
            target.repository
        ))
    })?;
    if !policy
        .allowed_actions
        .iter()
        .any(|action| action == &target.action)
    {
        return Err(invalid(format!(
            "action `{}` is not allowed",
            target.action
        )));
    }
    let environment_requires_human = policy
        .human_approval_environments
        .iter()
        .any(|environment| environment == &target.environment);
    let approval_required =
        environment_requires_human || matches!(target.approval, ApprovalMode::Always);
    if approval_required {
        return Ok(TargetReadiness::HumanApprovalRequired(format!(
            "repository `{}` requires approval for environment `{}`",
            target.repository, target.environment
        )));
    }
    Ok(TargetReadiness::Ready)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryFacts {
    pub merge_commits: BTreeMap<RepositoryId, String>,
    pub planned_revisions: BTreeMap<String, BTreeMap<RepositoryId, String>>,
}

pub fn resolve_source(
    source: &OperationSource,
    repository: &RepositoryId,
    facts: &DeliveryFacts,
) -> Result<String, PlanError> {
    let encoded = serde_json::to_value(source)
        .map_err(|error| invalid(format!("cannot encode operation source: {error}")))?;
    let value = encoded
        .as_str()
        .ok_or_else(|| invalid("operation source is not a string"))?;
    let sha = if value == "merge_commit" {
        facts.merge_commits.get(repository)
    } else if let Some(revision_id) = value.strip_prefix("planned:") {
        facts
            .planned_revisions
            .get(revision_id)
            .and_then(|revisions| revisions.get(repository))
    } else {
        return Err(invalid(
            "operation source is outside the configured source vocabulary",
        ));
    }
    .ok_or_else(|| {
        invalid(format!(
            "source for repository `{repository}` has not been observed"
        ))
    })?;
    if !valid_git_sha(sha) {
        return Err(invalid(format!(
            "resolved source for repository `{repository}` is not a full Git object ID"
        )));
    }
    Ok(sha.clone())
}

fn valid_git_sha(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DescribeParams {
    pub protocol_version: u32,
    pub adapter_kind: String,
}

impl Default for DescribeParams {
    fn default() -> Self {
        Self {
            protocol_version: OPERATION_PROTOCOL_VERSION,
            adapter_kind: "operations".into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvokeParams {
    pub action_id: String,
    pub target_id: String,
    pub repository_id: RepositoryId,
    pub environment: String,
    pub source_sha: String,
    pub plan_digest: ContentDigest,
    pub correlation_key: String,
    #[serde(default)]
    pub selector: BTreeMap<String, String>,
    #[serde(default)]
    pub parameters: BTreeMap<String, Value>,
    #[serde(default)]
    pub expected_preconditions: BTreeMap<String, Value>,
    #[serde(default)]
    pub approval_digest: Option<ContentDigest>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObserveParams {
    pub operation_id: OperationId,
    pub correlation_key: String,
    pub action_id: String,
    pub target_id: String,
    pub repository_id: RepositoryId,
    pub environment: String,
    pub source_sha: String,
    #[serde(default)]
    pub external_reference: Option<String>,
    #[serde(default)]
    pub cursor: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindParams {
    pub operation_id: OperationId,
    pub correlation_key: String,
    pub action_id: String,
    pub target_id: String,
    pub repository_id: RepositoryId,
    pub environment: String,
    pub source_sha: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvokeResult {
    pub outcome: InvokeOutcome,
    #[serde(default)]
    pub external_reference: Option<String>,
    #[serde(default)]
    pub receipt: Option<Value>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvokeOutcome {
    Accepted,
    Completed,
    Rejected,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindResult {
    pub outcome: FindOutcome,
    pub operation_id: OperationId,
    pub correlation_key: String,
    pub action_id: String,
    pub target_id: String,
    pub repository_id: RepositoryId,
    pub environment: String,
    pub source_sha: String,
    #[serde(default)]
    pub observed_at: Option<String>,
    #[serde(default)]
    pub proof_scope: Option<String>,
    #[serde(default)]
    pub external_reference: Option<String>,
    #[serde(default)]
    pub receipt: Option<Value>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindOutcome {
    Found,
    Absent,
    Unknown,
}

impl FindResult {
    pub fn validate(&self) -> Result<(), String> {
        if self.correlation_key.trim().is_empty()
            || self.action_id.trim().is_empty()
            || self.target_id.trim().is_empty()
            || self.environment.trim().is_empty()
            || !valid_git_sha(&self.source_sha)
        {
            return Err(
                "operation.find result is missing a valid requested operation identity".into(),
            );
        }
        match self.outcome {
            FindOutcome::Found if self.external_reference.as_deref().is_none_or(str::is_empty) => {
                Err("found operation result must include an external reference".into())
            }
            FindOutcome::Absent
                if self.observed_at.as_deref().is_none_or(str::is_empty)
                    || self.proof_scope.as_deref().is_none_or(str::is_empty) =>
            {
                Err("absent operation result must include observation time and proof scope".into())
            }
            _ => Ok(()),
        }
    }

    pub fn validate_for(&self, request: &FindParams) -> Result<(), String> {
        self.validate()?;
        if self.operation_id != request.operation_id
            || self.correlation_key != request.correlation_key
            || self.action_id != request.action_id
            || self.target_id != request.target_id
            || self.repository_id != request.repository_id
            || self.environment != request.environment
            || self.source_sha != request.source_sha
        {
            return Err(
                "operation.find result does not match the exact requested operation subject".into(),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationObservation {
    pub provider_instance: String,
    pub external_run_id: String,
    pub operation_id: OperationId,
    pub correlation_key: String,
    pub action_id: String,
    pub target_id: String,
    pub repository_id: RepositoryId,
    pub environment: String,
    pub source_sha: String,
    pub observed_at: String,
    pub status: OperationStatus,
    #[serde(default)]
    pub evidence: Vec<EvidenceReference>,
    #[serde(default)]
    pub jobs: BTreeMap<String, OperationStatus>,
    #[serde(default)]
    pub external_url: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceReference {
    pub id: String,
    pub digest: ContentDigest,
}

impl OperationObservation {
    pub fn validate_for(&self, target: &OperationTarget, source_sha: &str) -> Result<(), String> {
        if self.provider_instance.trim().is_empty()
            || self.external_run_id.trim().is_empty()
            || self.observed_at.trim().is_empty()
        {
            return Err("operation observation is missing provider, run, or time identity".into());
        }
        if self.target_id != target.id
            || self.action_id != target.action
            || self.repository_id != target.repository
            || self.environment != target.environment
            || self.source_sha != source_sha
        {
            return Err("operation observation does not match its target, repository, environment, and source".into());
        }
        if !valid_git_sha(&self.source_sha) {
            return Err("operation observation source must be a full Git object ID".into());
        }
        let mut evidence_ids = BTreeSet::new();
        if self
            .evidence
            .iter()
            .any(|evidence| !valid_identifier(&evidence.id) || !evidence_ids.insert(&evidence.id))
        {
            return Err("operation evidence IDs must be valid and unique".into());
        }
        Ok(())
    }

    pub fn validate_for_request(&self, request: &ObserveParams) -> Result<(), String> {
        if self.operation_id != request.operation_id
            || self.correlation_key != request.correlation_key
        {
            return Err(
                "operation.observe result does not match the exact operation correlation".into(),
            );
        }
        if request
            .external_reference
            .as_deref()
            .is_some_and(|reference| reference != self.external_run_id)
        {
            return Err(
                "operation.observe result does not match the requested external run".into(),
            );
        }
        if request.correlation_key.trim().is_empty() {
            return Err("operation.observe request correlation key is empty".into());
        }
        if self.target_id != request.target_id
            || self.action_id != request.action_id
            || self.repository_id != request.repository_id
            || self.environment != request.environment
            || self.source_sha != request.source_sha
        {
            return Err(
                "operation.observe result does not match the exact requested target and source"
                    .into(),
            );
        }
        self.validate_for_source(&request.source_sha)
    }

    fn validate_for_source(&self, source_sha: &str) -> Result<(), String> {
        if self.provider_instance.trim().is_empty()
            || self.external_run_id.trim().is_empty()
            || self.observed_at.trim().is_empty()
            || !valid_git_sha(&self.source_sha)
            || self.source_sha != source_sha
        {
            return Err(
                "operation observation is missing valid provider, run, source, or time identity"
                    .into(),
            );
        }
        let mut evidence_ids = BTreeSet::new();
        if self
            .evidence
            .iter()
            .any(|evidence| !valid_identifier(&evidence.id) || !evidence_ids.insert(&evidence.id))
        {
            return Err("operation evidence IDs must be valid and unique".into());
        }
        Ok(())
    }

    pub fn satisfies(&self, predicate: &SuccessPredicate) -> PredicateResult {
        match predicate {
            SuccessPredicate::TargetSucceeded => match self.status {
                OperationStatus::Succeeded => PredicateResult::Satisfied,
                OperationStatus::Failed
                | OperationStatus::Cancelled
                | OperationStatus::Missing
                | OperationStatus::TimedOut => PredicateResult::Failed,
                OperationStatus::Queued
                | OperationStatus::Running
                | OperationStatus::AwaitingApproval
                | OperationStatus::Skipped
                | OperationStatus::Unknown => PredicateResult::Pending,
            },
            SuccessPredicate::AllNamedJobsSucceeded { jobs } => {
                match self.status {
                    OperationStatus::Failed
                    | OperationStatus::Cancelled
                    | OperationStatus::Missing
                    | OperationStatus::TimedOut => return PredicateResult::Failed,
                    OperationStatus::Succeeded => {}
                    OperationStatus::Queued
                    | OperationStatus::Running
                    | OperationStatus::AwaitingApproval
                    | OperationStatus::Skipped
                    | OperationStatus::Unknown => return PredicateResult::Pending,
                }
                for job in jobs {
                    match self.jobs.get(job) {
                        Some(OperationStatus::Succeeded) => {}
                        Some(
                            OperationStatus::Failed
                            | OperationStatus::Cancelled
                            | OperationStatus::Missing
                            | OperationStatus::TimedOut,
                        ) => return PredicateResult::Failed,
                        Some(_) | None => return PredicateResult::Pending,
                    }
                }
                PredicateResult::Satisfied
            }
            SuccessPredicate::ExplicitNotRequired { evidence, .. } => {
                if self.status != OperationStatus::Skipped {
                    return match self.status {
                        OperationStatus::Failed
                        | OperationStatus::Cancelled
                        | OperationStatus::Missing
                        | OperationStatus::TimedOut => PredicateResult::Failed,
                        _ => PredicateResult::Pending,
                    };
                }
                let observed = self
                    .evidence
                    .iter()
                    .map(|item| item.id.as_str())
                    .collect::<BTreeSet<_>>();
                if evidence.iter().all(|item| observed.contains(item.as_str())) {
                    PredicateResult::Satisfied
                } else {
                    PredicateResult::Pending
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PredicateResult {
    Satisfied,
    Pending,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterDescription {
    pub protocol_version: u32,
    pub adapter_kind: String,
    pub capabilities: Vec<ActionCapability>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionCapability {
    pub action_id: String,
    pub parameter_schema: Value,
    pub selector_schema: Value,
    pub supports_find: bool,
    pub supports_observe: bool,
    pub idempotency: IdempotencyCapability,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdempotencyCapability {
    RemoteDeduplicates,
    ReconcileByFind,
    NoSafeRetry,
}

impl AdapterDescription {
    pub fn validate(&self) -> Result<(), String> {
        if self.protocol_version != OPERATION_PROTOCOL_VERSION || self.adapter_kind != "operations"
        {
            return Err("operation adapter protocol or kind does not match".into());
        }
        let mut ids = BTreeSet::new();
        if self.capabilities.iter().any(|capability| {
            !valid_identifier(&capability.action_id) || !ids.insert(&capability.action_id)
        }) {
            return Err("adapter action IDs must be valid and unique".into());
        }
        for capability in &self.capabilities {
            if !capability.parameter_schema.is_object() || !capability.selector_schema.is_object() {
                return Err(format!(
                    "action `{}` schemas must be JSON objects",
                    capability.action_id
                ));
            }
            if capability.idempotency == IdempotencyCapability::ReconcileByFind
                && !capability.supports_find
            {
                return Err(format!(
                    "action `{}` claims reconciliation without operation.find",
                    capability.action_id
                ));
            }
        }
        Ok(())
    }
}

/// Confirms that every configured operation action has an explicit adapter
/// contract. Unsupported actions fail before any write-side operation starts.
pub fn validate_operation_capabilities(
    config: &Config,
    description: &AdapterDescription,
) -> Result<(), String> {
    description.validate()?;
    for action_id in config.operation_actions.keys() {
        let capability = description
            .capabilities
            .iter()
            .find(|capability| &capability.action_id == action_id)
            .ok_or_else(|| {
                format!("operation action `{action_id}` is not advertised by the adapter")
            })?;
        if !capability.supports_observe {
            return Err(format!(
                "operation action `{action_id}` does not support observation"
            ));
        }
        if capability.idempotency == IdempotencyCapability::ReconcileByFind
            && !capability.supports_find
        {
            return Err(format!(
                "operation action `{action_id}` cannot reconcile by find"
            ));
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandCompletion {
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub cleanup_confirmed: bool,
    pub stdout: Vec<u8>,
    pub stdout_truncated: bool,
    pub stderr_tail: Vec<u8>,
    pub stderr_truncated: bool,
}

/// Implemented by the bounded host process runner. Implementations must use
/// argv and stdin directly, never a shell, and must redact environment/output.
pub trait BoundedCommandRunner {
    fn run_argv(
        &mut self,
        command: &[String],
        stdin: &[u8],
        timeout: Duration,
        stdout_limit: usize,
        stderr_tail_limit: usize,
    ) -> Result<CommandCompletion, String>;
}

/// Concrete adapter over the shared process owner. It inherits the
/// controller's already-captured environment, never inserts a shell, and
/// delegates process-tree cleanup and bounded pipe handling to `process`.
#[derive(Clone, Copy, Debug)]
pub struct ProcessCommandRunner {
    shutdown_grace: Duration,
}

impl ProcessCommandRunner {
    pub fn new(shutdown_grace: Duration) -> Result<Self, String> {
        if shutdown_grace.is_zero() {
            return Err("process shutdown grace must be non-zero".into());
        }
        Ok(Self { shutdown_grace })
    }
}

impl BoundedCommandRunner for ProcessCommandRunner {
    fn run_argv(
        &mut self,
        command: &[String],
        stdin: &[u8],
        timeout: Duration,
        stdout_limit: usize,
        stderr_tail_limit: usize,
    ) -> Result<CommandCompletion, String> {
        let Some((executable, arguments)) = command.split_first() else {
            return Err("configured command is empty".into());
        };
        if executable.is_empty() || command.iter().any(|value| value.contains('\0')) {
            return Err("configured command contains an empty executable or NUL byte".into());
        }
        let search_path = std::env::var_os("PATH")
            .map(|path| std::env::split_paths(&path).collect::<Vec<_>>())
            .unwrap_or_default();
        let executable = crate::process::resolve_executable(Path::new(executable), &search_path)
            .ok_or_else(|| "configured operation executable is unavailable".to_owned())?;
        let request = crate::process::ProcessRequest {
            executable,
            args: arguments.iter().map(Into::into).collect(),
            stdin: stdin.to_vec(),
            cwd: None,
            clear_environment: false,
            environment: BTreeMap::new(),
            timeout,
            shutdown_grace: self.shutdown_grace,
            stdout_limit,
            stderr_tail_limit,
        };
        let output = crate::process::run(request).map_err(|error| error.to_string())?;
        Ok(CommandCompletion {
            exit_code: output.status.and_then(|status| status.code()),
            timed_out: output.timed_out,
            cleanup_confirmed: output.cleanup_confirmed,
            stdout: output.stdout,
            stdout_truncated: output.stdout_truncated,
            stderr_tail: output.stderr_tail,
            stderr_truncated: output.stderr_truncated,
        })
    }
}

#[derive(Clone, Debug)]
pub enum AdapterCall {
    Response(ResponseEnvelope<Value>),
    Uncertain(String),
}

#[derive(Clone, Debug)]
pub enum AdapterError {
    Invalid(String),
    Execution(String),
    Remote(ProtocolError),
    Uncertain(String),
}

impl std::fmt::Display for AdapterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(reason) => write!(f, "invalid operation adapter response: {reason}"),
            Self::Execution(reason) => write!(f, "operation adapter execution failed: {reason}"),
            Self::Remote(error) => {
                write!(f, "operation adapter rejected request: {}", error.message)
            }
            Self::Uncertain(reason) => write!(f, "operation outcome is uncertain: {reason}"),
        }
    }
}

impl std::error::Error for AdapterError {}

/// Calls one configured command adapter. Any failed or malformed invocation
/// result is `Uncertain`, because the external action may already have happened.
pub fn call_command_adapter<R: BoundedCommandRunner, P: Serialize>(
    runner: &mut R,
    action: &OperationActionConfig,
    request: &RequestEnvelope<P>,
    timeout: Duration,
) -> Result<AdapterCall, AdapterError> {
    request.validate().map_err(AdapterError::Invalid)?;
    let method = serde_json::to_value(&request.method)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or_else(|| AdapterError::Invalid("request method cannot be serialized".into()))?;
    let method = method.as_str();
    if !METHODS.contains(&method) {
        return Err(AdapterError::Invalid(format!(
            "unsupported operation method `{method}`"
        )));
    }
    if timeout.is_zero() || timeout > Duration::from_secs(MAX_OPERATION_TIMEOUT_SECONDS) {
        return Err(AdapterError::Invalid(
            "operation adapter timeout is outside the supported range".into(),
        ));
    }
    let params_value = serde_json::to_value(&request.params)
        .map_err(|error| AdapterError::Invalid(error.to_string()))?;
    validate_request_for(method, request, &params_value).map_err(AdapterError::Invalid)?;
    let command = match action {
        OperationActionConfig::Command { command } if !command.is_empty() => command,
        OperationActionConfig::Command { .. } => {
            return Err(AdapterError::Invalid("configured command is empty".into()));
        }
        OperationActionConfig::ForgeObservation => {
            return Err(AdapterError::Invalid(
                "forge observation action requires its native adapter".into(),
            ));
        }
    };
    let mut stdin =
        serde_json::to_vec(request).map_err(|error| AdapterError::Invalid(error.to_string()))?;
    stdin.push(b'\n');
    let completion = runner
        .run_argv(
            command,
            &stdin,
            timeout,
            MAX_ADAPTER_RESPONSE_BYTES,
            MAX_ADAPTER_STDERR_BYTES,
        )
        .map_err(|error| {
            if method == "operation.invoke" {
                AdapterError::Uncertain(error)
            } else {
                AdapterError::Execution(error)
            }
        })?;
    if !completion.cleanup_confirmed {
        return if method == "operation.invoke" {
            Ok(AdapterCall::Uncertain(
                "adapter process termination is unconfirmed".into(),
            ))
        } else {
            Err(AdapterError::Execution(
                "adapter process termination is unconfirmed".into(),
            ))
        };
    }
    if completion.stdout_truncated || completion.stdout.len() > MAX_ADAPTER_RESPONSE_BYTES {
        return if method == "operation.invoke" {
            Ok(AdapterCall::Uncertain(
                "adapter response exceeded its byte limit".into(),
            ))
        } else {
            Err(AdapterError::Invalid(
                "adapter response exceeded its byte limit".into(),
            ))
        };
    }
    if completion.timed_out || completion.exit_code != Some(0) {
        let reason = if completion.timed_out {
            "adapter timed out".to_owned()
        } else {
            format!("adapter exited with status {:?}", completion.exit_code)
        };
        return if method == "operation.invoke" {
            Ok(AdapterCall::Uncertain(reason))
        } else {
            Err(AdapterError::Execution(reason))
        };
    }
    let response = crate::protocol::parse_unique::<ResponseEnvelope<Value>>(&completion.stdout)
        .map_err(|error| {
            if method == "operation.invoke" {
                AdapterError::Uncertain(format!("adapter reply cannot be reconciled: {error}"))
            } else {
                AdapterError::Invalid(error)
            }
        })?;
    response
        .validate_for(&request.request_id)
        .map_err(|error| {
            if method == "operation.invoke" {
                AdapterError::Uncertain(format!("adapter reply cannot be reconciled: {error}"))
            } else {
                AdapterError::Invalid(error)
            }
        })?;
    if response.error.is_some() {
        return Ok(AdapterCall::Response(response));
    }
    validate_success_payload(
        method,
        response.result.as_ref().expect("validated response result"),
    )
    .map_err(|error| {
        if method == "operation.invoke" {
            AdapterError::Uncertain(format!("adapter reply cannot be reconciled: {error}"))
        } else {
            AdapterError::Invalid(error)
        }
    })?;
    validate_success_for(
        method,
        &params_value,
        response.result.as_ref().expect("validated response result"),
    )
    .map_err(|error| {
        if method == "operation.invoke" {
            AdapterError::Uncertain(format!("adapter reply cannot be reconciled: {error}"))
        } else {
            AdapterError::Invalid(error)
        }
    })?;
    Ok(AdapterCall::Response(response))
}

fn validate_request_for<P>(
    method: &str,
    request: &RequestEnvelope<P>,
    params: &Value,
) -> Result<(), String> {
    match method {
        "operation.invoke" => {
            if request.operation_id.is_none() || request.project_id.is_none() {
                return Err("operation.invoke requires its operation and Project identities in the envelope".into());
            }
            let _: InvokeParams = serde_json::from_value(params.clone())
                .map_err(|error| format!("invalid operation.invoke request params: {error}"))?;
            Ok(())
        }
        "operation.observe" => {
            let params: ObserveParams = serde_json::from_value(params.clone())
                .map_err(|error| format!("invalid operation.observe request params: {error}"))?;
            if request.operation_id.as_ref() != Some(&params.operation_id)
                || request.project_id.is_none()
            {
                return Err(
                    "operation.observe envelope identity does not match its request params".into(),
                );
            }
            Ok(())
        }
        "operation.find" => {
            let params: FindParams = serde_json::from_value(params.clone())
                .map_err(|error| format!("invalid operation.find request params: {error}"))?;
            if request.operation_id.as_ref() != Some(&params.operation_id)
                || request.project_id.is_none()
            {
                return Err(
                    "operation.find envelope identity does not match its request params".into(),
                );
            }
            Ok(())
        }
        "adapter.describe" => Ok(()),
        _ => Err(format!("unsupported operation method `{method}`")),
    }
}

fn validate_success_for(method: &str, params: &Value, result: &Value) -> Result<(), String> {
    match method {
        "operation.find" => {
            let request: FindParams = serde_json::from_value(params.clone())
                .map_err(|error| format!("invalid operation.find request params: {error}"))?;
            let response: FindResult = serde_json::from_value(result.clone())
                .map_err(|error| format!("invalid operation.find result: {error}"))?;
            response.validate_for(&request)
        }
        "operation.observe" => {
            let request: ObserveParams = serde_json::from_value(params.clone())
                .map_err(|error| format!("invalid operation.observe request params: {error}"))?;
            let response: OperationObservation = serde_json::from_value(result.clone())
                .map_err(|error| format!("invalid operation.observe result: {error}"))?;
            response.validate_for_request(&request)
        }
        _ => Ok(()),
    }
}

/// Invocation entry point for a write-side command. The command is selected
/// from trusted applied config using the permit's action ID; callers cannot
/// pass an agent-authored executable or substitute another target.
pub fn invoke_authorized_command<R: BoundedCommandRunner>(
    runner: &mut R,
    applied: &AppliedConfig,
    permit: &OperationPermit,
    request_id: impl Into<String>,
    timeout: Duration,
) -> Result<AdapterCall, AdapterError> {
    let current_config_digest =
        ContentDigest::parse(applied.digest.to_string()).map_err(AdapterError::Invalid)?;
    if current_config_digest != permit.applied_config_digest
        || current_config_digest != permit.subject.config_digest
        || applied_snapshot_fingerprint(applied).map_err(AdapterError::Invalid)?
            != permit.applied_snapshot_fingerprint
    {
        return Err(AdapterError::Invalid(
            "applied configuration changed after operation authorization".into(),
        ));
    }
    let config = &applied.config;
    let plan = validate_recipe(config, &permit.subject.recipe_id)
        .map_err(|error| AdapterError::Invalid(error.to_string()))?;
    if plan.digest != permit.subject.plan_digest {
        return Err(AdapterError::Invalid(
            "operation recipe changed after authorization".into(),
        ));
    }
    let target = plan
        .targets
        .iter()
        .find(|target| target.id == permit.subject.target_id)
        .ok_or_else(|| AdapterError::Invalid("authorized target no longer exists".into()))?;
    if target.action != permit.subject.action_id
        || target.repository != permit.subject.repository_id
        || target.environment != permit.subject.environment
        || target.selector != permit.selector
        || target.timeout_seconds != permit.timeout_seconds
        || timeout.is_zero()
        || timeout > Duration::from_secs(permit.timeout_seconds)
    {
        return Err(AdapterError::Invalid(
            "authorized target or timeout changed after operation authorization".into(),
        ));
    }
    let authority_digest = operation_authority_digest(
        config,
        &permit.subject.project_id,
        &permit.subject.recipe_id,
        &permit.subject.repository_id,
        &permit.subject.action_id,
    )
    .map_err(AdapterError::Invalid)?;
    if authority_digest != permit.authority_digest {
        return Err(AdapterError::Invalid(
            "operation authority policy changed after authorization".into(),
        ));
    }
    let current_action = config
        .operation_actions
        .get(&permit.subject.action_id)
        .ok_or_else(|| AdapterError::Invalid("authorized action is no longer configured".into()))?;
    let current_command = bind_command_execution(current_action).map_err(AdapterError::Invalid)?;
    if current_command != permit.command {
        return Err(AdapterError::Invalid(
            "operation executable or argv changed after authorization".into(),
        ));
    }
    let command = permit.command.as_ref().ok_or_else(|| {
        AdapterError::Invalid("authorized action is not a command adapter".into())
    })?;
    let action = OperationActionConfig::Command {
        command: command.argv.clone(),
    };
    let request = permit
        .invoke_request(request_id)
        .map_err(AdapterError::Invalid)?;
    call_command_adapter(runner, &action, &request, timeout)
}

fn validate_success_payload(method: &str, result: &Value) -> Result<(), String> {
    match method {
        "adapter.describe" => {
            let description: AdapterDescription =
                serde_json::from_value(result.clone()).map_err(|error| error.to_string())?;
            description.validate()
        }
        "operation.invoke" => {
            let result: InvokeResult =
                serde_json::from_value(result.clone()).map_err(|error| error.to_string())?;
            if result.outcome == InvokeOutcome::Accepted
                && result
                    .external_reference
                    .as_deref()
                    .is_none_or(str::is_empty)
            {
                return Err("accepted operation.invoke must include a correlation-capable external reference".into());
            }
            Ok(())
        }
        "operation.observe" => {
            let _: OperationObservation =
                serde_json::from_value(result.clone()).map_err(|error| error.to_string())?;
            Ok(())
        }
        "operation.find" => {
            let result: FindResult =
                serde_json::from_value(result.clone()).map_err(|error| error.to_string())?;
            result.validate()
        }
        _ => Err(format!("unsupported operation method `{method}`")),
    }
}

pub fn classify_invoke(call: &AdapterCall) -> OperationOutcome {
    match call {
        AdapterCall::Uncertain(_) => OperationOutcome::Unknown,
        AdapterCall::Response(response) => match response
            .result
            .as_ref()
            .and_then(|result| serde_json::from_value::<InvokeResult>(result.clone()).ok())
            .map(|result| result.outcome)
        {
            Some(InvokeOutcome::Accepted) => OperationOutcome::Pending,
            Some(InvokeOutcome::Completed) => OperationOutcome::Unknown,
            Some(InvokeOutcome::Rejected) => OperationOutcome::Failed,
            None => OperationOutcome::Unknown,
        },
    }
}

// Keep the generic protocol types close to this module while allowing the
// controller to use the shared Appendix H envelopes directly.
pub fn new_request<P>(
    request_id: impl Into<String>,
    operation_id: Option<OperationId>,
    project_id: Option<ProjectId>,
    method: &str,
    params: P,
) -> Result<RequestEnvelope<P>, String> {
    Ok(RequestEnvelope::host(
        RequestId::new(request_id)?,
        operation_id,
        MethodName::new(method)?,
        project_id,
        params,
    ))
}

fn _duration_is_representable(_: Duration) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{OperationRecipe, RepositoryOperationsConfig};
    use crate::domain::ids::Digest as AppliedDigest;

    const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

    fn fixture_config() -> Config {
        let mut config: Config = toml::from_str(include_str!("../examples/fixture/config.toml"))
            .expect("public fixture config parses");
        config.operation_actions.insert(
            "deploy".into(),
            OperationActionConfig::Command {
                command: vec![
                    "python3".into(),
                    concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/tests/fixtures/operations/adapter.py"
                    )
                    .into(),
                ],
            },
        );
        config
            .repositories
            .get_mut(&RepositoryId::parse("example").unwrap())
            .unwrap()
            .operations = Some(RepositoryOperationsConfig {
            recipe: "rollout".into(),
            allowed_actions: vec!["deploy".into()],
            human_approval_environments: vec!["production".into()],
            instruction_files: vec![],
        });
        config.operation_recipes.insert(
            "rollout".into(),
            recipe(vec![target(
                "deploy_prod",
                vec![],
                ApprovalMode::RepositoryPolicy,
            )]),
        );
        config
    }

    fn applied(config: Config) -> AppliedConfig {
        AppliedConfig {
            config,
            profiles: BTreeMap::new(),
            source_root: "/fixture".into(),
            source_files: vec![],
            digest: AppliedDigest::parse("a".repeat(64)).unwrap(),
        }
    }

    fn target(id: &str, depends_on: Vec<String>, approval: ApprovalMode) -> OperationTarget {
        OperationTarget {
            id: id.into(),
            repository: RepositoryId::parse("example").unwrap(),
            environment: "production".into(),
            action: "deploy".into(),
            depends_on,
            source: OperationSource::parse("merge_commit").unwrap(),
            selector: BTreeMap::new(),
            success_predicate: SuccessPredicate::TargetSucceeded,
            timeout_seconds: 60,
            approval,
        }
    }

    fn recipe(targets: Vec<OperationTarget>) -> OperationRecipe {
        OperationRecipe {
            roles: BTreeMap::new(),
            required_stages: vec![],
            required_evidence: vec![],
            targets,
            not_required_reason: None,
        }
    }

    fn subject(plan: &ValidatedOperationPlan, target: &OperationTarget) -> OperationSubject {
        OperationSubject {
            project_id: ProjectId::parse("operations_project").unwrap(),
            ticket_id: TicketId::parse("PAY-12").unwrap(),
            ticket_run_id: TicketRunId::parse("run-1").unwrap(),
            ticket_revision: Revision(7),
            operation_id: OperationId::parse("op-1").unwrap(),
            recipe_id: plan.recipe_id.clone(),
            plan_digest: plan.digest.clone(),
            config_digest: ContentDigest::parse("a".repeat(64)).unwrap(),
            target_id: target.id.clone(),
            action_id: target.action.clone(),
            repository_id: target.repository.clone(),
            environment: target.environment.clone(),
            source_sha: SHA.into(),
            expected_preconditions: BTreeMap::from([(
                "branch".into(),
                Value::String("main".into()),
            )]),
        }
    }

    fn delivery_facts(target: &OperationTarget) -> DeliveryFacts {
        DeliveryFacts {
            merge_commits: BTreeMap::from([(target.repository.clone(), SHA.into())]),
            planned_revisions: BTreeMap::new(),
        }
    }

    #[test]
    fn plan_is_topologically_sorted_and_cycles_are_rejected() {
        let mut config = fixture_config();
        let mut second = target("second", vec!["first".into()], ApprovalMode::NotRequired);
        second.environment = "test".into();
        let mut first = target("first", vec![], ApprovalMode::NotRequired);
        first.environment = "test".into();
        config.operation_recipes.insert(
            "rollout".into(),
            recipe(vec![second.clone(), first.clone()]),
        );
        let plan = validate_recipe(&config, "rollout").unwrap();
        assert_eq!(
            plan.targets
                .iter()
                .map(|t| t.id.as_str())
                .collect::<Vec<_>>(),
            ["first", "second"]
        );
        first.depends_on = vec!["second".into()];
        config
            .operation_recipes
            .insert("rollout".into(), recipe(vec![first, second]));
        assert!(
            validate_recipe(&config, "rollout")
                .unwrap_err()
                .to_string()
                .contains("cycle")
        );
    }

    #[test]
    fn repository_environment_strengthens_approval_and_binds_exact_subject() {
        let applied = applied(fixture_config());
        let config = &applied.config;
        let plan = validate_recipe(config, "rollout").unwrap();
        let target = &plan.targets[0];
        let facts = delivery_facts(target);
        let base = subject(&plan, target);
        assert_eq!(
            authorize_operation(&applied, &facts, &plan, target, base.clone(), None).unwrap_err(),
            AuthorizationError::ApprovalRequired
        );
        let mut stale = base.clone();
        stale
            .expected_preconditions
            .insert("branch".into(), Value::String("release".into()));
        let receipt = HumanApprovalReceipt {
            request_id: "hr-1".into(),
            subject_digest: base.digest().unwrap(),
            approved: true,
            decided_at: "2026-11-07T00:00:00Z".into(),
        };
        assert_eq!(
            authorize_operation(&applied, &facts, &plan, target, stale, Some(&receipt))
                .unwrap_err(),
            AuthorizationError::StaleApproval
        );
        let permit =
            authorize_operation(&applied, &facts, &plan, target, base, Some(&receipt)).unwrap();
        assert_eq!(
            permit.invoke_params().unwrap().approval_digest,
            Some(receipt.subject_digest)
        );
    }

    #[test]
    fn changed_config_digest_invalidates_authorization() {
        let applied = applied(fixture_config());
        let config = &applied.config;
        let plan = validate_recipe(config, "rollout").unwrap();
        let target = &plan.targets[0];
        let s = subject(&plan, target);
        let facts = delivery_facts(target);
        let mut wrong = applied.clone();
        wrong.digest = AppliedDigest::parse("b".repeat(64)).unwrap();
        assert!(matches!(
            authorize_operation(&wrong, &facts, &plan, target, s, None),
            Err(AuthorizationError::Invalid(_))
        ));
    }

    #[test]
    fn forged_validated_plan_cannot_authorize_a_target_absent_from_config() {
        let mut config = fixture_config();
        let deploy = config.operation_actions["deploy"].clone();
        config
            .operation_actions
            .insert("other_allowed_action".into(), deploy);
        config
            .repositories
            .get_mut(&RepositoryId::parse("example").unwrap())
            .unwrap()
            .operations
            .as_mut()
            .unwrap()
            .allowed_actions
            .push("other_allowed_action".into());
        let applied = applied(config);
        let plan = validate_recipe(&applied.config, "rollout").unwrap();
        let mut forged = plan.clone();
        forged.targets[0].action = "other_allowed_action".into();
        let target = &forged.targets[0];
        let facts = delivery_facts(target);
        let subject = subject(&forged, target);
        assert!(matches!(
            authorize_operation(&applied, &facts, &forged, target, subject, None),
            Err(AuthorizationError::Invalid(reason)) if reason.contains("plan")
        ));
    }

    #[test]
    fn invocation_rejects_changed_command_even_if_caller_reuses_old_config_digest() {
        let applied = applied(fixture_config());
        let plan = validate_recipe(&applied.config, "rollout").unwrap();
        let target = &plan.targets[0];
        let facts = delivery_facts(target);
        let subject = subject(&plan, target);
        let approval = HumanApprovalReceipt {
            request_id: "human-2".into(),
            subject_digest: subject.digest().unwrap(),
            approved: true,
            decided_at: "2026-11-07T00:00:00Z".into(),
        };
        let permit =
            authorize_operation(&applied, &facts, &plan, target, subject, Some(&approval)).unwrap();
        let mut replaced = applied.clone();
        replaced.config.operation_actions.insert(
            "deploy".into(),
            OperationActionConfig::Command {
                command: vec![
                    "python3".into(),
                    "-c".into(),
                    "print('different command')".into(),
                ],
            },
        );
        let mut runner = FakeRunner::default();
        let error = invoke_authorized_command(
            &mut runner,
            &replaced,
            &permit,
            "req-replaced",
            Duration::from_secs(30),
        )
        .unwrap_err();
        assert!(matches!(error, AdapterError::Invalid(_)));
        assert!(
            runner.command.is_empty(),
            "changed executable must not be run"
        );
    }

    #[test]
    fn invocation_rejects_changed_resolved_executable_contents() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("operation-adapter");
        std::fs::write(&executable, b"#!/bin/sh\nexit 0\n").unwrap();
        let mut permissions = std::fs::metadata(&executable).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&executable, permissions).unwrap();
        let mut configured = fixture_config();
        configured.operation_actions.insert(
            "deploy".into(),
            OperationActionConfig::Command {
                command: vec![executable.display().to_string()],
            },
        );
        let applied = applied(configured);
        let plan = validate_recipe(&applied.config, "rollout").unwrap();
        let target = &plan.targets[0];
        let facts = delivery_facts(target);
        let subject = subject(&plan, target);
        let approval = HumanApprovalReceipt {
            request_id: "human-3".into(),
            subject_digest: subject.digest().unwrap(),
            approved: true,
            decided_at: "2026-11-07T00:00:00Z".into(),
        };
        let permit =
            authorize_operation(&applied, &facts, &plan, target, subject, Some(&approval)).unwrap();
        std::fs::write(&executable, b"#!/bin/sh\nexit 42\n").unwrap();
        let mut runner = FakeRunner::default();
        let error = invoke_authorized_command(
            &mut runner,
            &applied,
            &permit,
            "req-mutated-binary",
            Duration::from_secs(30),
        )
        .unwrap_err();
        assert!(matches!(error, AdapterError::Invalid(_)));
        assert!(
            runner.command.is_empty(),
            "modified executable must not be run"
        );
    }

    #[test]
    fn invocation_cannot_exceed_the_configured_target_deadline() {
        let applied = applied(fixture_config());
        let plan = validate_recipe(&applied.config, "rollout").unwrap();
        let target = &plan.targets[0];
        let facts = delivery_facts(target);
        let subject = subject(&plan, target);
        let approval = HumanApprovalReceipt {
            request_id: "human-4".into(),
            subject_digest: subject.digest().unwrap(),
            approved: true,
            decided_at: "2026-11-07T00:00:00Z".into(),
        };
        let permit =
            authorize_operation(&applied, &facts, &plan, target, subject, Some(&approval)).unwrap();
        let mut runner = FakeRunner::default();
        assert!(matches!(
            invoke_authorized_command(
                &mut runner,
                &applied,
                &permit,
                "req-too-long",
                Duration::from_secs(61),
            ),
            Err(AdapterError::Invalid(_))
        ));
        assert!(runner.command.is_empty());
    }

    #[test]
    fn readiness_never_reinvokes_unknown_or_failed_execution_automatically() {
        let config = fixture_config();
        let plan = validate_recipe(&config, "rollout").unwrap();
        let target = &plan.targets[0];
        assert!(matches!(
            target_readiness(
                &config,
                target,
                &BTreeMap::new(),
                Some(OperationStatus::Unknown)
            )
            .unwrap(),
            TargetReadiness::NeedsReconciliation(_)
        ));
        assert!(matches!(
            target_readiness(
                &config,
                target,
                &BTreeMap::new(),
                Some(OperationStatus::TimedOut)
            )
            .unwrap(),
            TargetReadiness::RetryRequiresExplicitAuthorization(_)
        ));
        assert!(matches!(
            target_readiness(
                &config,
                target,
                &BTreeMap::new(),
                Some(OperationStatus::Skipped)
            )
            .unwrap(),
            TargetReadiness::NeedsReconciliation(_)
        ));
    }

    #[test]
    fn source_resolution_requires_exact_full_lowercase_git_object_id() {
        let target = target("deploy", vec![], ApprovalMode::Always);
        let mut facts = DeliveryFacts {
            merge_commits: BTreeMap::from([(target.repository.clone(), SHA.into())]),
            planned_revisions: BTreeMap::new(),
        };
        assert_eq!(
            resolve_source(&target.source, &target.repository, &facts).unwrap(),
            SHA
        );
        facts
            .merge_commits
            .insert(target.repository.clone(), format!("{SHA}00"));
        assert!(resolve_source(&target.source, &target.repository, &facts).is_err());
        facts
            .merge_commits
            .insert(target.repository.clone(), SHA.to_uppercase());
        assert!(resolve_source(&target.source, &target.repository, &facts).is_err());
    }

    #[test]
    fn skipped_observation_must_carry_explicit_not_required_evidence() {
        let target = target("deploy", vec![], ApprovalMode::NotRequired);
        let predicate = SuccessPredicate::ExplicitNotRequired {
            reason: "not applicable".into(),
            evidence: vec!["release_gate".into()],
        };
        let mut observation = OperationObservation {
            provider_instance: "fixture".into(),
            external_run_id: "run-4".into(),
            operation_id: OperationId::parse("op-4").unwrap(),
            correlation_key: "corr-4".into(),
            action_id: target.action.clone(),
            target_id: target.id.clone(),
            repository_id: target.repository.clone(),
            environment: target.environment.clone(),
            source_sha: SHA.into(),
            observed_at: "2026-11-07T00:00:00Z".into(),
            status: OperationStatus::Failed,
            evidence: vec![],
            jobs: BTreeMap::new(),
            external_url: None,
        };
        assert_eq!(observation.satisfies(&predicate), PredicateResult::Failed);
        observation.status = OperationStatus::Skipped;
        assert_eq!(observation.satisfies(&predicate), PredicateResult::Pending);
        observation.evidence.push(EvidenceReference {
            id: "release_gate".into(),
            digest: ContentDigest::parse("c".repeat(64)).unwrap(),
        });
        assert_eq!(
            observation.satisfies(&predicate),
            PredicateResult::Satisfied
        );
    }

    #[test]
    fn observation_must_match_exact_operation_correlation_and_external_run() {
        let target = target("deploy", vec![], ApprovalMode::Always);
        let request = ObserveParams {
            operation_id: OperationId::parse("op-4").unwrap(),
            correlation_key: "corr-4".into(),
            action_id: target.action.clone(),
            target_id: target.id.clone(),
            repository_id: target.repository.clone(),
            environment: target.environment.clone(),
            source_sha: SHA.into(),
            external_reference: Some("run-4".into()),
            cursor: None,
        };
        let observation = OperationObservation {
            provider_instance: "fixture".into(),
            external_run_id: "run-4".into(),
            operation_id: request.operation_id.clone(),
            correlation_key: request.correlation_key.clone(),
            action_id: request.action_id.clone(),
            target_id: request.target_id.clone(),
            repository_id: request.repository_id.clone(),
            environment: request.environment.clone(),
            source_sha: request.source_sha.clone(),
            observed_at: "2026-11-07T00:00:00Z".into(),
            status: OperationStatus::Succeeded,
            evidence: vec![],
            jobs: BTreeMap::new(),
            external_url: None,
        };
        assert!(observation.validate_for_request(&request).is_ok());

        let mut stale = observation.clone();
        stale.operation_id = OperationId::parse("op-other").unwrap();
        assert!(stale.validate_for_request(&request).is_err());

        let mut stale = observation.clone();
        stale.correlation_key = "corr-other".into();
        assert!(stale.validate_for_request(&request).is_err());

        let mut stale = observation;
        stale.external_run_id = "run-other".into();
        assert!(stale.validate_for_request(&request).is_err());
    }

    #[test]
    fn observe_adapter_rejects_stale_operation_and_run_receipts() {
        let operation_id = OperationId::parse("op-current").unwrap();
        let params = ObserveParams {
            operation_id: operation_id.clone(),
            correlation_key: "ticket-run-7:deploy_prod".into(),
            action_id: "deploy".into(),
            target_id: "deploy_prod".into(),
            repository_id: RepositoryId::parse("example").unwrap(),
            environment: "production".into(),
            source_sha: SHA.into(),
            external_reference: Some("run-current".into()),
            cursor: None,
        };
        let request = new_request(
            "observe-request",
            Some(operation_id.clone()),
            Some(ProjectId::parse("operations_project").unwrap()),
            "operation.observe",
            params,
        )
        .unwrap();
        let result = serde_json::json!({
            "provider_instance": "fixture",
            "external_run_id": "run-current",
            "operation_id": operation_id,
            "correlation_key": "ticket-run-7:deploy_prod",
            "action_id": "deploy",
            "target_id": "deploy_prod",
            "repository_id": "example",
            "environment": "production",
            "source_sha": SHA,
            "observed_at": "2026-11-07T00:00:00Z",
            "status": "succeeded",
            "evidence": [],
            "jobs": {}
        });
        let action = OperationActionConfig::Command {
            command: vec!["/opt/adapter".into()],
        };
        let response_bytes = |result: Value| {
            serde_json::to_vec(&serde_json::json!({
                "schema_version": 1,
                "request_id": "observe-request",
                "result": result,
            }))
            .unwrap()
        };
        let mut runner = FakeRunner {
            completion: Some(completed(response_bytes(result.clone()))),
            ..FakeRunner::default()
        };
        assert!(
            call_command_adapter(&mut runner, &action, &request, Duration::from_secs(5)).is_ok()
        );

        for (field, wrong) in [
            ("operation_id", serde_json::json!("op-stale")),
            (
                "correlation_key",
                serde_json::json!("ticket-run-6:deploy_prod"),
            ),
            ("external_run_id", serde_json::json!("run-stale")),
        ] {
            let mut stale = result.clone();
            stale[field] = wrong;
            let mut runner = FakeRunner {
                completion: Some(completed(response_bytes(stale))),
                ..FakeRunner::default()
            };
            assert!(
                call_command_adapter(&mut runner, &action, &request, Duration::from_secs(5))
                    .is_err(),
                "stale {field} must be rejected at the adapter boundary"
            );
        }
    }

    #[test]
    fn duplicate_or_ambiguous_recipe_rules_require_human_resolution() {
        let mut config = fixture_config();
        let project = config
            .projects
            .get_mut(&ProjectId::parse("operations_project").unwrap())
            .unwrap();
        project.operation_matches[0].labels_all = vec!["docs".into()];
        project.operation_matches[0].recipe = "rollout".into();
        project
            .operation_matches
            .push(crate::config::OperationMatch {
                labels_all: vec![],
                recipe: "rollout".into(),
            });
        let labels = vec!["docs".into()];
        assert_eq!(
            select_recipe(
                &config,
                &ProjectId::parse("operations_project").unwrap(),
                &labels
            )
            .unwrap(),
            RecipeSelection::Selected("rollout".into())
        );
        config
            .operation_recipes
            .insert("other".into(), recipe(vec![]));
        config
            .projects
            .get_mut(&ProjectId::parse("operations_project").unwrap())
            .unwrap()
            .operation_matches
            .push(crate::config::OperationMatch {
                labels_all: vec!["docs".into()],
                recipe: "other".into(),
            });
        assert_eq!(
            select_recipe(
                &config,
                &ProjectId::parse("operations_project").unwrap(),
                &labels
            )
            .unwrap(),
            RecipeSelection::Ambiguous(vec!["other".into(), "rollout".into()])
        );
    }

    #[derive(Default)]
    struct FakeRunner {
        command: Vec<String>,
        stdin: Vec<u8>,
        completion: Option<CommandCompletion>,
    }
    impl BoundedCommandRunner for FakeRunner {
        fn run_argv(
            &mut self,
            command: &[String],
            stdin: &[u8],
            _timeout: Duration,
            _stdout_limit: usize,
            _stderr_tail_limit: usize,
        ) -> Result<CommandCompletion, String> {
            self.command = command.to_vec();
            self.stdin = stdin.to_vec();
            Ok(self.completion.take().expect("completion set by test"))
        }
    }

    fn completed(stdout: Vec<u8>) -> CommandCompletion {
        CommandCompletion {
            exit_code: Some(0),
            timed_out: false,
            cleanup_confirmed: true,
            stdout,
            stdout_truncated: false,
            stderr_tail: vec![],
            stderr_truncated: false,
        }
    }

    #[test]
    fn invoke_response_is_pending_until_observation_and_uncertain_is_never_success() {
        let id = RequestId::new("request-1").unwrap();
        let response: ResponseEnvelope<Value> = serde_json::from_value(serde_json::json!({
            "schema_version": 1, "request_id": "request-1", "result": { "outcome": "accepted", "external_reference": "run-9" }
        })).unwrap();
        let call = AdapterCall::Response(response);
        assert_eq!(classify_invoke(&call), OperationOutcome::Pending);
        assert_eq!(
            classify_invoke(&AdapterCall::Uncertain("timeout".into())),
            OperationOutcome::Unknown
        );
        assert_eq!(id.as_str(), "request-1");
    }

    #[test]
    fn command_adapter_sends_json_over_stdin_without_shell_and_uncertain_timeout() {
        let request = new_request(
            "request-1",
            Some(OperationId::parse("op-1").unwrap()),
            Some(ProjectId::parse("operations_project").unwrap()),
            "operation.invoke",
            InvokeParams {
                action_id: "deploy".into(),
                target_id: "deploy_prod".into(),
                repository_id: RepositoryId::parse("example").unwrap(),
                environment: "production".into(),
                source_sha: SHA.into(),
                plan_digest: ContentDigest::parse("d".repeat(64)).unwrap(),
                correlation_key: "correlation".into(),
                selector: BTreeMap::new(),
                parameters: BTreeMap::new(),
                expected_preconditions: BTreeMap::new(),
                approval_digest: None,
            },
        )
        .unwrap();
        let action = OperationActionConfig::Command {
            command: vec!["/opt/adapter".into(), "--mode".into(), "safe".into()],
        };
        let mut runner = FakeRunner { command: vec![], stdin: vec![], completion: Some(completed(br#"{"schema_version":1,"request_id":"request-1","result":{"outcome":"accepted","external_reference":"run-9"}}"#.to_vec())) };
        let call =
            call_command_adapter(&mut runner, &action, &request, Duration::from_secs(10)).unwrap();
        assert_eq!(runner.command, ["/opt/adapter", "--mode", "safe"]);
        assert!(
            std::str::from_utf8(&runner.stdin)
                .unwrap()
                .contains("operation.invoke")
        );
        assert_eq!(classify_invoke(&call), OperationOutcome::Pending);
        runner.completion = Some(CommandCompletion {
            timed_out: true,
            ..completed(vec![])
        });
        assert!(matches!(
            call_command_adapter(&mut runner, &action, &request, Duration::from_secs(10)).unwrap(),
            AdapterCall::Uncertain(_)
        ));
    }

    #[test]
    fn authorized_invocation_uses_only_applied_argv_and_bound_request_fields() {
        let applied = applied(fixture_config());
        let config = &applied.config;
        let plan = validate_recipe(config, "rollout").unwrap();
        let target = &plan.targets[0];
        let facts = delivery_facts(target);
        let subject = subject(&plan, target);
        let approval = HumanApprovalReceipt {
            request_id: "human-1".into(),
            subject_digest: subject.digest().unwrap(),
            approved: true,
            decided_at: "2026-11-07T00:00:00Z".into(),
        };
        let permit =
            authorize_operation(&applied, &facts, &plan, target, subject, Some(&approval)).unwrap();
        let mut runner = FakeRunner {
            command: vec![],
            stdin: vec![],
            completion: Some(completed(br#"{"schema_version":1,"request_id":"req-1","result":{"outcome":"accepted","external_reference":"run-9"}}"#.to_vec())),
        };
        let result = invoke_authorized_command(
            &mut runner,
            &applied,
            &permit,
            "req-1",
            Duration::from_secs(30),
        )
        .unwrap();
        assert_eq!(runner.command.len(), 2);
        assert!(Path::new(&runner.command[0]).is_absolute());
        assert!(runner.command[0].contains("python"));
        let request: RequestEnvelope<InvokeParams> = serde_json::from_slice(&runner.stdin).unwrap();
        assert_eq!(request.operation_id.as_ref().unwrap().as_str(), "op-1");
        assert_eq!(request.params.source_sha, SHA);
        assert_eq!(
            request.params.approval_digest,
            Some(approval.subject_digest)
        );
        assert_eq!(classify_invoke(&result), OperationOutcome::Pending);
    }

    #[test]
    fn public_cli_fixture_exercises_real_json_adapter_process_without_remote_effects() {
        let request = new_request(
            "fixture-request",
            Some(OperationId::parse("fixture-op").unwrap()),
            Some(ProjectId::parse("operations_project").unwrap()),
            "operation.invoke",
            InvokeParams {
                action_id: "fixture_echo".into(),
                target_id: "fixture-target".into(),
                repository_id: RepositoryId::parse("example").unwrap(),
                environment: "test".into(),
                source_sha: SHA.into(),
                plan_digest: ContentDigest::parse("d".repeat(64)).unwrap(),
                correlation_key: "stable-key".into(),
                selector: BTreeMap::new(),
                parameters: BTreeMap::new(),
                expected_preconditions: BTreeMap::new(),
                approval_digest: None,
            },
        )
        .unwrap();
        let action = OperationActionConfig::Command {
            command: vec![
                "python3".into(),
                concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/fixtures/operations/adapter.py"
                )
                .into(),
            ],
        };
        let mut runner = ProcessCommandRunner::new(Duration::from_secs(1)).unwrap();
        let call = call_command_adapter(&mut runner, &action, &request, Duration::from_secs(5))
            .expect("fixture adapter follows the protocol");
        assert_eq!(classify_invoke(&call), OperationOutcome::Pending);
    }

    #[test]
    fn absent_find_requires_observation_proof() {
        let result = FindResult {
            outcome: FindOutcome::Absent,
            operation_id: OperationId::parse("op-1").unwrap(),
            correlation_key: "corr-1".into(),
            action_id: "deploy".into(),
            target_id: "deploy_prod".into(),
            repository_id: RepositoryId::parse("example").unwrap(),
            environment: "production".into(),
            source_sha: SHA.into(),
            observed_at: None,
            proof_scope: None,
            external_reference: None,
            receipt: None,
        };
        assert!(result.validate().is_err());
    }

    #[test]
    fn found_operation_must_match_the_exact_find_subject() {
        let request = FindParams {
            operation_id: OperationId::parse("op-1").unwrap(),
            correlation_key: "stable-correlation".into(),
            action_id: "deploy".into(),
            target_id: "deploy_prod".into(),
            repository_id: RepositoryId::parse("example").unwrap(),
            environment: "production".into(),
            source_sha: SHA.into(),
        };
        let result = FindResult {
            outcome: FindOutcome::Found,
            operation_id: request.operation_id.clone(),
            correlation_key: request.correlation_key.clone(),
            action_id: request.action_id.clone(),
            target_id: request.target_id.clone(),
            repository_id: request.repository_id.clone(),
            environment: request.environment.clone(),
            source_sha: request.source_sha.clone(),
            observed_at: None,
            proof_scope: None,
            external_reference: Some("external-run".into()),
            receipt: None,
        };
        assert!(result.validate_for(&request).is_ok());
        let mut unrelated = result;
        unrelated.operation_id = OperationId::parse("other-operation").unwrap();
        unrelated.source_sha = "f".repeat(40);
        assert!(unrelated.validate_for(&request).is_err());
    }

    #[test]
    fn command_adapter_rejects_found_receipt_for_an_unrelated_operation() {
        let request = new_request(
            "find-request",
            Some(OperationId::parse("op-1").unwrap()),
            Some(ProjectId::parse("operations_project").unwrap()),
            "operation.find",
            FindParams {
                operation_id: OperationId::parse("op-1").unwrap(),
                correlation_key: "stable-correlation".into(),
                action_id: "deploy".into(),
                target_id: "deploy_prod".into(),
                repository_id: RepositoryId::parse("example").unwrap(),
                environment: "production".into(),
                source_sha: SHA.into(),
            },
        )
        .unwrap();
        let result = serde_json::json!({
            "outcome": "found",
            "operation_id": "different-operation",
            "correlation_key": "stable-correlation",
            "action_id": "deploy",
            "target_id": "deploy_prod",
            "repository_id": "example",
            "environment": "production",
            "source_sha": SHA,
            "external_reference": "unrelated-run"
        });
        let response = serde_json::json!({
            "schema_version": 1,
            "request_id": "find-request",
            "result": result
        });
        let mut runner = FakeRunner {
            command: vec![],
            stdin: vec![],
            completion: Some(completed(serde_json::to_vec(&response).unwrap())),
        };
        let action = OperationActionConfig::Command {
            command: vec!["adapter".into()],
        };
        assert!(matches!(
            call_command_adapter(&mut runner, &action, &request, Duration::from_secs(10)),
            Err(AdapterError::Invalid(_))
        ));
    }

    #[test]
    fn find_request_rejects_conflicting_envelope_and_parameter_operation_ids() {
        let request = new_request(
            "find-request-conflict",
            Some(OperationId::parse("op-1").unwrap()),
            Some(ProjectId::parse("operations_project").unwrap()),
            "operation.find",
            FindParams {
                operation_id: OperationId::parse("op-2").unwrap(),
                correlation_key: "stable-correlation".into(),
                action_id: "deploy".into(),
                target_id: "deploy_prod".into(),
                repository_id: RepositoryId::parse("example").unwrap(),
                environment: "production".into(),
                source_sha: SHA.into(),
            },
        )
        .unwrap();
        let mut runner = FakeRunner::default();
        let action = OperationActionConfig::Command {
            command: vec!["adapter".into()],
        };
        assert!(matches!(
            call_command_adapter(&mut runner, &action, &request, Duration::from_secs(10)),
            Err(AdapterError::Invalid(_))
        ));
        assert!(runner.command.is_empty());
    }
}
