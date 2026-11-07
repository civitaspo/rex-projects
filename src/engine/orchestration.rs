use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::config::{Config, OperationRecipe, ProjectConfig, SuccessPredicate};
use crate::domain::ids::{
    AgentRunId, ArtifactId, Digest, OperationId, ProfileId, ProjectId, RepositoryId, Revision,
    TicketId, TicketNamespace, TicketRunId,
};
use crate::domain::types::CommitMode;
use crate::domain::types::{ProjectMode, RecipeStage, Role, TicketStatus};
use crate::engine::reducer::Input;

/// Stable plan-local identity for a task in a TicketRun DAG.
#[derive(Clone, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct WorkNodeId(String);

impl<'de> Deserialize<'de> for WorkNodeId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

impl WorkNodeId {
    pub fn parse(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 80
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            return Err("work node ID must be 1-80 ASCII letters, digits, '.', '_' or '-'".into());
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for WorkNodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExternalTicket {
    pub namespace: TicketNamespace,
    pub id: TicketId,
    pub revision: String,
    pub status: TicketStatus,
    pub labels: BTreeSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DispatchDecision {
    Ignore { reason: DispatchIgnore },
    Dispatch { priority: TicketPriority },
    ReconcileExternalTerminal { status: TicketStatus },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DispatchIgnore {
    NotConfiguredReady,
    ExistingRunOwnsTicket,
    ProjectPausedOrStopped,
    UnsupportedDispatchState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TicketPriority {
    Default,
}

/// Normal dispatch never promotes Triage or Backlog. Their explicit triage or
/// prioritization input must first move them to a configured execution state.
pub fn dispatch_decision(
    project: &ProjectConfig,
    status: TicketStatus,
    has_active_run: bool,
    project_is_runnable: bool,
) -> DispatchDecision {
    if matches!(status, TicketStatus::Done | TicketStatus::Canceled) {
        return DispatchDecision::ReconcileExternalTerminal { status };
    }
    if !project_is_runnable {
        return DispatchDecision::Ignore {
            reason: DispatchIgnore::ProjectPausedOrStopped,
        };
    }
    if has_active_run {
        return DispatchDecision::Ignore {
            reason: DispatchIgnore::ExistingRunOwnsTicket,
        };
    }
    if status != TicketStatus::Ready || !project.dispatch_states.contains(&status) {
        return DispatchDecision::Ignore {
            reason: if status == TicketStatus::Ready {
                DispatchIgnore::NotConfiguredReady
            } else {
                DispatchIgnore::UnsupportedDispatchState
            },
        };
    }
    DispatchDecision::Dispatch {
        priority: TicketPriority::Default,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GoalCreationBudget {
    pub goal_revision: u64,
    pub reserved_attempts: u64,
    pub maximum_attempts: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GoalGap {
    pub key: String,
    pub title: String,
    pub body: String,
    pub acceptance: Vec<String>,
    pub parent: Option<TicketId>,
    pub dependencies: Vec<TicketId>,
    pub priority_rationale: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GoalTicketIntent {
    pub project_id: ProjectId,
    pub goal_revision: u64,
    pub stable_key: String,
    pub gap: GoalGap,
    /// Must be persisted in the same transaction as this intent, before invoke.
    pub reserved_attempt_number: u64,
}

/// Reserves the configured unit before a remote create is called. Callers must
/// atomically persist both the incremented budget and the returned intent.
pub fn reserve_goal_ticket(
    project_id: &ProjectId,
    project: &ProjectConfig,
    budget: &GoalCreationBudget,
    gap: GoalGap,
) -> Result<(GoalCreationBudget, GoalTicketIntent), String> {
    if project.mode != ProjectMode::Goal {
        return Err("operations Projects cannot create goal tickets".into());
    }
    let goal = project
        .goal
        .as_ref()
        .ok_or_else(|| "goal Project has no configured goal".to_owned())?;
    if goal.revision != budget.goal_revision {
        return Err("creation budget is for a stale goal revision".into());
    }
    validate_gap(&gap)?;
    let configured_max = u64::try_from(project.max_created_tickets_per_goal_revision)
        .map_err(|_| "goal ticket limit exceeds supported range".to_owned())?;
    let maximum = budget.maximum_attempts.min(configured_max);
    let attempt = budget
        .reserved_attempts
        .checked_add(1)
        .ok_or_else(|| "goal ticket reservation count exhausted".to_owned())?;
    if attempt > maximum {
        return Err("per-goal-revision ticket creation budget is exhausted".into());
    }
    let next = GoalCreationBudget {
        goal_revision: budget.goal_revision,
        reserved_attempts: attempt,
        maximum_attempts: maximum,
    };
    let intent = GoalTicketIntent {
        project_id: project_id.clone(),
        goal_revision: goal.revision,
        stable_key: goal_ticket_key(project_id, goal.revision, &gap.key),
        gap,
        reserved_attempt_number: attempt,
    };
    Ok((next, intent))
}

fn validate_gap(gap: &GoalGap) -> Result<(), String> {
    if gap.key.trim().is_empty()
        || gap.key.len() > 200
        || gap.key.chars().any(char::is_control)
        || gap.title.trim().is_empty()
        || gap.body.trim().is_empty()
        || gap.acceptance.is_empty()
        || gap.acceptance.iter().any(|item| item.trim().is_empty())
    {
        return Err(
            "goal gap requires a stable key, title, body, and nonempty acceptance items".into(),
        );
    }
    let mut dependencies = BTreeSet::new();
    for dependency in &gap.dependencies {
        if !dependencies.insert(dependency) {
            return Err("goal gap contains a duplicate dependency".into());
        }
    }
    Ok(())
}

fn goal_ticket_key(project_id: &ProjectId, revision: u64, gap_key: &str) -> String {
    let digest = Sha256::digest(gap_key.as_bytes());
    format!("rex-projects:{project_id}:goal:{revision}:gap:{digest:x}")
}

pub const ROLE_RESULT_SCHEMA_VERSION: u32 = 1;
const MAX_ROLE_RESULT_JSON_BYTES: usize = 1_048_576;
const MAX_ROLE_RESULT_ARTIFACTS: usize = 256;
const MAX_ROLE_RESULT_ARTIFACTS_JSON_BYTES: usize = 262_144;

/// Stable identity copied from the host-owned run descriptor and authority row.
/// A submitted result must repeat it exactly before any evidence is accepted.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleResultBinding {
    pub agent_run_id: AgentRunId,
    pub operation_id: OperationId,
    pub project_id: ProjectId,
    pub role_session_id: RoleSessionId,
    pub role: Role,
    pub parent_run_id: Option<AgentRunId>,
    pub parent_role: Option<Role>,
    pub ticket_run_id: Option<TicketRunId>,
    pub ticket_revision: Option<Revision>,
    pub config_revision: Revision,
    pub config_digest: Digest,
    pub profile_digest: Digest,
    pub instruction_digest: Digest,
    pub provider_capability_receipt_digest: Digest,
    pub result_schema_digest: Digest,
    pub controller_generation: u64,
    pub run_epoch: u64,
    pub attempt: u32,
}

impl RoleResultBinding {
    fn validate(&self) -> Result<(), String> {
        RoleSessionId::parse(self.role_session_id.as_str())?;
        if self.config_revision.0 == 0
            || self.controller_generation == 0
            || self.run_epoch == 0
            || self.attempt == 0
        {
            return Err("role result binding has a zero revision or run counter".into());
        }
        if self.parent_run_id.is_some() != self.parent_role.is_some() {
            return Err("parent run ID and parent role must be present together".into());
        }
        let requires_ticket = self.role != Role::Supervisor;
        if self.ticket_run_id.is_some() != requires_ticket
            || self.ticket_revision.is_some() != requires_ticket
        {
            return Err("role result binding has an invalid TicketRun scope".into());
        }
        let valid_parent = match self.role {
            Role::Supervisor => self.parent_role.is_none(),
            Role::Coordinator => self.parent_role == Some(Role::Supervisor),
            Role::Planner
            | Role::Worker
            | Role::Reviewer
            | Role::MergeDecision
            | Role::Operator
            | Role::Postmortem => self.parent_role == Some(Role::Coordinator),
        };
        if !valid_parent {
            return Err("role result binding has an invalid parent role for this run".into());
        }
        Ok(())
    }
}

/// Local logical identity for a durable role session. It is not an Agent
/// supplied destination; validation matches it against the host descriptor.
#[derive(Clone, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct RoleSessionId(String);

impl<'de> Deserialize<'de> for RoleSessionId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

impl RoleSessionId {
    pub fn parse(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 255
            || value.split(':').any(str::is_empty)
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':')
            })
        {
            return Err("invalid role session ID".into());
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoleOutputKind {
    Progress,
    Irregularity,
    HumanRequest,
    TicketProposal,
    DispatchRequest,
    Intervention,
    SpawnRequest,
    InvestigationRequest,
    PrepareWorktrees,
    PlanReady,
    ImplementationReady,
    ReviewReady,
    MergeAssessment,
    MergeIntent,
    OperationAction,
    OperationResult,
    PostmortemReady,
    LearningDecision,
    ProfileTrialResult,
    ProfilePromotionProposal,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "assertion", rename_all = "snake_case", deny_unknown_fields)]
pub enum AgentAssertion {
    Succeeded,
    Blocked { reason: String },
    Failed { reason: String },
    Cancelled { reason: Option<String> },
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoleArtifactKind {
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

impl RoleArtifactKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Plan => "plan",
            Self::Change => "change",
            Self::TestReceipt => "test_receipt",
            Self::Review => "review",
            Self::MergeAssessment => "merge_assessment",
            Self::OperationReceipt => "operation_receipt",
            Self::Postmortem => "postmortem",
            Self::Learning => "learning",
            Self::General => "general",
        }
    }
}

/// Agent request to register one artifact from its run-local writable output
/// root. The host resolves this path relative to the bound AgentRun, copies and
/// verifies the bytes, then returns a registered `RoleArtifactReference`.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactAddRequest {
    /// Artifact-add request envelope version.
    pub schema_version: u32,
    pub message_id: String,
    /// Normalized relative path (at most 1,024 Unicode scalar values and
    /// 4,096 UTF-8 bytes), rooted at the requesting AgentRun output root.
    pub path: String,
    pub kind: RoleArtifactKind,
    /// Schema version of the artifact contents, independent of this request.
    pub artifact_schema_version: u32,
}

impl ArtifactAddRequest {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != ARTIFACT_ADD_REQUEST_SCHEMA_VERSION {
            return Err("unsupported artifact-add request schema version".into());
        }
        if self.message_id.is_empty()
            || self.message_id.len() > 128
            || !self
                .message_id
                .bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_alphanumeric())
            || !self
                .message_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err("artifact-add message ID must be a bounded local identifier".into());
        }
        validate_artifact_relative_path(&self.path)?;
        if self.artifact_schema_version == 0 {
            return Err("artifact schema version must be positive".into());
        }
        Ok(())
    }
}

pub const ARTIFACT_ADD_REQUEST_SCHEMA_VERSION: u32 = 1;
const ARTIFACT_RELATIVE_PATH_PATTERN: &str = r"^(?![A-Za-z]:)(?:[^./\\\p{Cc}][^/\\\p{Cc}]*|\.[^./\\\p{Cc}][^/\\\p{Cc}]*|\.\.[^./\\\p{Cc}][^/\\\p{Cc}]*)((?:/(?:[^./\\\p{Cc}][^/\\\p{Cc}]*|\.[^./\\\p{Cc}][^/\\\p{Cc}]*|\.\.[^/\\\p{Cc}][^/\\\p{Cc}]*))*)$";

pub fn artifact_add_request_schema() -> Value {
    let mut schema = serde_json::to_value(schemars::schema_for!(ArtifactAddRequest))
        .expect("artifact-add request schema serializes to JSON");
    if let Some(properties) = schema.get_mut("properties").and_then(Value::as_object_mut) {
        if let Some(request_version) = properties
            .get_mut("schema_version")
            .and_then(Value::as_object_mut)
        {
            request_version.insert(
                "const".into(),
                Value::from(ARTIFACT_ADD_REQUEST_SCHEMA_VERSION),
            );
        }
        if let Some(artifact_version) = properties
            .get_mut("artifact_schema_version")
            .and_then(Value::as_object_mut)
        {
            artifact_version.insert("minimum".into(), Value::from(1));
        }
        if let Some(message_id) = properties
            .get_mut("message_id")
            .and_then(Value::as_object_mut)
        {
            message_id.insert("minLength".into(), Value::from(1));
            message_id.insert("maxLength".into(), Value::from(128));
            message_id.insert(
                "pattern".into(),
                Value::from(r"^[A-Za-z0-9][A-Za-z0-9._-]*$"),
            );
        }
        if let Some(path) = properties.get_mut("path").and_then(Value::as_object_mut) {
            path.insert("minLength".into(), Value::from(1));
            path.insert("maxLength".into(), Value::from(1024));
            path.insert(
                "pattern".into(),
                Value::from(ARTIFACT_RELATIVE_PATH_PATTERN),
            );
            path.insert("not".into(), serde_json::json!({"pattern": r"^[^/]:"}));
        }
    }
    schema
}

/// A host-registered artifact locator returned after the AgentRun request path
/// has been safely copied and its bytes have been checked. The opaque ID is
/// still only a reference: readers must resolve it in host-owned registration
/// state and verify the immutable receipt before relying on it.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleArtifactReference {
    /// Host-minted stable identity. This identifier alone is not an
    /// acknowledgement; consumers must resolve it in host-owned registration
    /// state before relying on the referenced artifact.
    pub artifact_id: ArtifactId,
    pub kind: RoleArtifactKind,
    pub schema_version: u32,
    /// Normalized relative locator in the host-managed artifact store, at most
    /// 1,024 Unicode scalar values and 4,096 UTF-8 bytes.
    pub path: String,
    pub digest: Digest,
    pub bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct GitCommitId(String);

impl GitCommitId {
    pub fn parse(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        if !matches!(value.len(), 40 | 64)
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err("Git commit ID must be a full lowercase SHA-1 or SHA-256 ID".into());
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for GitCommitId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

macro_rules! role_payload {
    ($name:ident { $($field:ident : $type:ty),* $(,)? }) => {
        #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
        #[serde(deny_unknown_fields)]
        pub struct $name {
            $(pub $field: $type,)*
        }
    };
}

role_payload!(ProgressPayload {
    summary: String,
    completed_node_keys: Vec<WorkNodeId>,
    pending_node_keys: Vec<WorkNodeId>,
    evidence: Vec<RoleArtifactReference>,
    next_observation_at: Option<String>,
});
role_payload!(IrregularityPayload {
    severity: String,
    observed_facts: Vec<String>,
    source_references: Vec<RoleArtifactReference>,
    affected_node_keys: Vec<WorkNodeId>,
    requested_pause_scope: String,
    proposed_options: Vec<String>,
});
role_payload!(HumanRequestPayload {
    kind: String,
    question: String,
    choices: Vec<String>,
    evidence_references: Vec<RoleArtifactReference>,
    subject_digest: Digest,
    requested_continuation: Option<String>,
});
role_payload!(TicketProposalPayload {
    goal_revision: u64,
    gap_key: String,
    title: String,
    body: String,
    acceptance: Vec<String>,
    priority_rationale: String,
    parent: Option<TicketId>,
    dependencies: Vec<TicketId>,
});
role_payload!(DispatchRequestPayload {
    ticket_reference: TicketId,
    expected_ticket_revision: Revision,
    coordinator_profile: ProfileId,
    priority: i32,
    rationale: String,
});
role_payload!(InterventionPayload {
    coordinator_role_session_id: RoleSessionId,
    ticket_run_revision: Revision,
    reason: String,
    evidence: Vec<RoleArtifactReference>,
    proposed_plan_change: String,
});
role_payload!(SpawnRequestPayload {
    work_node: WorkNodeId,
    role: Role,
    profile_id: ProfileId,
    plan_digest: Digest,
    allowed_repositories: Vec<RepositoryId>,
    artifact_inputs: Vec<RoleArtifactReference>,
    parent_run_id: Option<AgentRunId>,
});
role_payload!(InvestigationRequestPayload {
    question: String,
    allowed_repositories: Vec<RepositoryId>,
    required_evidence: Vec<String>,
    parent_run_id: Option<AgentRunId>,
});
role_payload!(PrepareWorktreesPayload {
    accepted_plan_digest: Digest,
    worker_nodes: Vec<WorkNodeId>,
});
role_payload!(PlanReadyPayload {
    plan: WorkPlan,
    unresolved_questions: Vec<String>,
});

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChangeReference {
    pub repository: RepositoryId,
    pub worktree_id: WorkNodeId,
    pub commit_mode: CommitMode,
    pub base_commit: GitCommitId,
    pub previous_head: GitCommitId,
    pub branch_head: GitCommitId,
    pub commit_shas: Vec<GitCommitId>,
}

role_payload!(ImplementationReadyPayload {
    change_references: Vec<ChangeReference>,
    completed_acceptance_items: Vec<String>,
    unresolved_items: Vec<String>,
    irregularity_references: Vec<RoleArtifactReference>,
});
role_payload!(ReviewReadyPayload {
    subject_kind: String,
    subject_digest: Digest,
    findings: Vec<String>,
    evidence_coverage: Vec<String>,
    disposition: String,
    unknowns: Vec<String>,
});
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum MergeConfidence {
    Low,
    Medium,
    High,
}

#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum RiskDimension {
    ChangeImpact,
    Complexity,
    VerificationGaps,
    ReviewUncertainty,
    OperationalExposure,
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateOutcome {
    Pass,
    Fail,
    Unknown,
}

role_payload!(DeterministicGateEvidence {
    gate_id: String,
    outcome: GateOutcome,
    evidence_references: Vec<RoleArtifactReference>,
});

role_payload!(RiskFactorAssessment {
    rating: u8,
    source: String,
    rationale: String,
    evidence_references: Vec<RoleArtifactReference>,
    uncertainty: Option<String>,
});

role_payload!(MergeAssessmentPayload {
    pr_references: Vec<String>,
    subject_digest: Digest,
    deterministic_gate_evidence: Vec<DeterministicGateEvidence>,
    ratings: BTreeMap<RiskDimension, RiskFactorAssessment>,
    confidence: MergeConfidence,
    rationale: String,
    disposition: String,
});

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MergeProcedureStepKind {
    UpdatePullRequestBody,
    RequestMerge,
    DirectMerge,
    VerifyMergeCommit,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MergeProcedureStep {
    pub kind: MergeProcedureStepKind,
    pub instruction_reference: String,
    pub rationale: String,
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PostMergeVerificationKind {
    MergeCommitRecorded,
    TargetBranchContainsCommit,
    RequiredChecksRemainGreen,
    DeploymentObserved,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostMergeVerification {
    pub kind: PostMergeVerificationKind,
    pub instruction_reference: String,
    pub rationale: String,
}

role_payload!(MergeIntentPayload {
    assessment_id: String,
    pr_identities: Vec<String>,
    policy_digest: Digest,
    prepared_body_digest: Digest,
    steps: Vec<MergeProcedureStep>,
    post_merge_verification: Vec<PostMergeVerification>,
});
role_payload!(OperationActionPayload {
    operation_plan_digest: Digest,
    node_key: WorkNodeId,
    action_id: String,
    parameters: BTreeMap<String, String>,
    preconditions: Vec<String>,
    approval_receipt: String,
});
role_payload!(OperationResultPayload {
    node_key: WorkNodeId,
    outcome: String,
    remote_receipt: BTreeMap<String, String>,
    source_commit: GitCommitId,
    environment: String,
    evidence_references: Vec<RoleArtifactReference>,
});
role_payload!(PostmortemReadyPayload {
    candidate_publication_manifest: BTreeMap<String, String>,
    findings: Vec<String>,
    source_references: Vec<RoleArtifactReference>,
    unresolved_provenance: Vec<String>,
});
role_payload!(LearningDecisionPayload {
    batch_id: String,
    batch_digest: Digest,
    config_revision: Revision,
    observations: Vec<String>,
    topic_changes: Vec<String>,
    checkpoint: BTreeMap<String, String>,
    improvements: Vec<String>,
    candidate_change: Option<BTreeMap<String, String>>,
});
role_payload!(ProfileTrialResultPayload {
    candidate_digest: Digest,
    base_digest: Digest,
    authorization_receipt: String,
    run_ids: Vec<AgentRunId>,
    frozen_inputs: Vec<String>,
    evidence_references: Vec<RoleArtifactReference>,
    outcome: String,
});
role_payload!(ProfilePromotionProposalPayload {
    candidate_revision: Revision,
    efficacy_outcome: String,
    evidence_references: Vec<RoleArtifactReference>,
    managed_slot: String,
    profile_diff: BTreeMap<String, String>,
    expected_target_digests: BTreeMap<String, Digest>,
    uncertain_efficacy_exception: Option<BTreeMap<String, String>>,
});

/// Closed role payloads that can cross the durable evidence boundary. These
/// represent Agent assertions only; host observations and effects are stored
/// separately by the controller.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RoleResultPayload {
    Progress(ProgressPayload),
    Irregularity(IrregularityPayload),
    HumanRequest(HumanRequestPayload),
    TicketProposal(TicketProposalPayload),
    DispatchRequest(DispatchRequestPayload),
    Intervention(InterventionPayload),
    SpawnRequest(SpawnRequestPayload),
    InvestigationRequest(InvestigationRequestPayload),
    PrepareWorktrees(PrepareWorktreesPayload),
    PlanReady(PlanReadyPayload),
    ImplementationReady(ImplementationReadyPayload),
    ReviewReady(ReviewReadyPayload),
    MergeAssessment(MergeAssessmentPayload),
    MergeIntent(MergeIntentPayload),
    OperationAction(OperationActionPayload),
    OperationResult(OperationResultPayload),
    PostmortemReady(PostmortemReadyPayload),
    LearningDecision(LearningDecisionPayload),
    ProfileTrialResult(ProfileTrialResultPayload),
    ProfilePromotionProposal(ProfilePromotionProposalPayload),
}

impl RoleResultPayload {
    fn parse(kind: RoleOutputKind, value: Value) -> Result<Self, String> {
        macro_rules! parse_variant {
            ($type:ty, $variant:ident) => {
                serde_json::from_value::<$type>(value)
                    .map(Self::$variant)
                    .map_err(|error| format!("invalid {:?} payload: {error}", kind))
            };
        }
        match kind {
            RoleOutputKind::Progress => parse_variant!(ProgressPayload, Progress),
            RoleOutputKind::Irregularity => parse_variant!(IrregularityPayload, Irregularity),
            RoleOutputKind::HumanRequest => parse_variant!(HumanRequestPayload, HumanRequest),
            RoleOutputKind::TicketProposal => parse_variant!(TicketProposalPayload, TicketProposal),
            RoleOutputKind::DispatchRequest => {
                parse_variant!(DispatchRequestPayload, DispatchRequest)
            }
            RoleOutputKind::Intervention => parse_variant!(InterventionPayload, Intervention),
            RoleOutputKind::SpawnRequest => parse_variant!(SpawnRequestPayload, SpawnRequest),
            RoleOutputKind::InvestigationRequest => {
                parse_variant!(InvestigationRequestPayload, InvestigationRequest)
            }
            RoleOutputKind::PrepareWorktrees => {
                parse_variant!(PrepareWorktreesPayload, PrepareWorktrees)
            }
            RoleOutputKind::PlanReady => parse_variant!(PlanReadyPayload, PlanReady),
            RoleOutputKind::ImplementationReady => {
                parse_variant!(ImplementationReadyPayload, ImplementationReady)
            }
            RoleOutputKind::ReviewReady => parse_variant!(ReviewReadyPayload, ReviewReady),
            RoleOutputKind::MergeAssessment => {
                parse_variant!(MergeAssessmentPayload, MergeAssessment)
            }
            RoleOutputKind::MergeIntent => parse_variant!(MergeIntentPayload, MergeIntent),
            RoleOutputKind::OperationAction => {
                parse_variant!(OperationActionPayload, OperationAction)
            }
            RoleOutputKind::OperationResult => {
                parse_variant!(OperationResultPayload, OperationResult)
            }
            RoleOutputKind::PostmortemReady => {
                parse_variant!(PostmortemReadyPayload, PostmortemReady)
            }
            RoleOutputKind::LearningDecision => {
                parse_variant!(LearningDecisionPayload, LearningDecision)
            }
            RoleOutputKind::ProfileTrialResult => {
                parse_variant!(ProfileTrialResultPayload, ProfileTrialResult)
            }
            RoleOutputKind::ProfilePromotionProposal => {
                parse_variant!(ProfilePromotionProposalPayload, ProfilePromotionProposal)
            }
        }
    }

    pub fn kind(&self) -> RoleOutputKind {
        match self {
            Self::Progress(_) => RoleOutputKind::Progress,
            Self::Irregularity(_) => RoleOutputKind::Irregularity,
            Self::HumanRequest(_) => RoleOutputKind::HumanRequest,
            Self::TicketProposal(_) => RoleOutputKind::TicketProposal,
            Self::DispatchRequest(_) => RoleOutputKind::DispatchRequest,
            Self::Intervention(_) => RoleOutputKind::Intervention,
            Self::SpawnRequest(_) => RoleOutputKind::SpawnRequest,
            Self::InvestigationRequest(_) => RoleOutputKind::InvestigationRequest,
            Self::PrepareWorktrees(_) => RoleOutputKind::PrepareWorktrees,
            Self::PlanReady(_) => RoleOutputKind::PlanReady,
            Self::ImplementationReady(_) => RoleOutputKind::ImplementationReady,
            Self::ReviewReady(_) => RoleOutputKind::ReviewReady,
            Self::MergeAssessment(_) => RoleOutputKind::MergeAssessment,
            Self::MergeIntent(_) => RoleOutputKind::MergeIntent,
            Self::OperationAction(_) => RoleOutputKind::OperationAction,
            Self::OperationResult(_) => RoleOutputKind::OperationResult,
            Self::PostmortemReady(_) => RoleOutputKind::PostmortemReady,
            Self::LearningDecision(_) => RoleOutputKind::LearningDecision,
            Self::ProfileTrialResult(_) => RoleOutputKind::ProfileTrialResult,
            Self::ProfilePromotionProposal(_) => RoleOutputKind::ProfilePromotionProposal,
        }
    }
}

fn validate_role_payload(payload: &RoleResultPayload) -> Result<(), String> {
    match payload {
        RoleResultPayload::ImplementationReady(result) => {
            if result.change_references.is_empty() {
                return Err("implementation-ready result must identify at least one change".into());
            }
            let mut work_nodes = BTreeSet::new();
            for change in &result.change_references {
                if change.commit_shas.is_empty()
                    || change.commit_shas.last() != Some(&change.branch_head)
                    || change.previous_head == change.branch_head
                    || !work_nodes.insert((&change.repository, &change.worktree_id))
                {
                    return Err(
                        "implementation change must identify a unique work node and exact resulting commit chain".into(),
                    );
                }
            }
        }
        RoleResultPayload::MergeAssessment(result)
            if result.pr_references.is_empty()
                || result
                    .pr_references
                    .iter()
                    .any(|reference| reference.trim().is_empty())
                || result.deterministic_gate_evidence.is_empty()
                || result.deterministic_gate_evidence.iter().any(|gate| {
                    gate.gate_id.trim().is_empty() || gate.evidence_references.is_empty()
                })
                || result.rationale.trim().is_empty()
                || result.disposition.trim().is_empty()
                || result.ratings.len() != 5
                || result.ratings.values().any(|factor| {
                    factor.rating > 4
                        || factor.source.trim().is_empty()
                        || factor.rationale.trim().is_empty()
                        || factor.evidence_references.is_empty()
                }) =>
        {
            return Err(
                "merge assessment must provide all five evidenced 0..4 risk factors".into(),
            );
        }
        RoleResultPayload::MergeIntent(result) => {
            let merge_kinds: Vec<_> = result
                .steps
                .iter()
                .filter(|step| {
                    matches!(
                        step.kind,
                        MergeProcedureStepKind::RequestMerge | MergeProcedureStepKind::DirectMerge
                    )
                })
                .collect();
            if result.assessment_id.trim().is_empty()
                || result.pr_identities.is_empty()
                || result
                    .pr_identities
                    .iter()
                    .any(|identity| identity.trim().is_empty())
                || result.steps.is_empty()
                || merge_kinds.len() != 1
                || result
                    .steps
                    .iter()
                    .filter(|step| step.kind == MergeProcedureStepKind::VerifyMergeCommit)
                    .count()
                    != 1
                || result.steps.iter().enumerate().any(|(index, step)| {
                    step.kind == MergeProcedureStepKind::UpdatePullRequestBody
                        && index
                            > result
                                .steps
                                .iter()
                                .position(|candidate| {
                                    matches!(
                                        candidate.kind,
                                        MergeProcedureStepKind::RequestMerge
                                            | MergeProcedureStepKind::DirectMerge
                                    )
                                })
                                .unwrap_or(usize::MAX)
                })
                || result.steps.last().map(|step| step.kind)
                    != Some(MergeProcedureStepKind::VerifyMergeCommit)
                || result.steps.iter().any(|step| {
                    step.instruction_reference.trim().is_empty() || step.rationale.trim().is_empty()
                })
                || result.post_merge_verification.is_empty()
                || result.post_merge_verification.iter().any(|check| {
                    check.instruction_reference.trim().is_empty()
                        || check.rationale.trim().is_empty()
                })
            {
                return Err(
                    "merge intent must name PRs, one merge method, a final merge-commit verification, and evidenced post-merge checks".into(),
                );
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_payload_artifacts(
    payload: &RoleResultPayload,
    role: Role,
    declared_claims: &[RoleArtifactReference],
) -> Result<(), String> {
    let mut references = Vec::new();
    match payload {
        RoleResultPayload::Progress(value) => references.extend(&value.evidence),
        RoleResultPayload::Irregularity(value) => references.extend(&value.source_references),
        RoleResultPayload::HumanRequest(value) => references.extend(&value.evidence_references),
        RoleResultPayload::SpawnRequest(value) => references.extend(&value.artifact_inputs),
        RoleResultPayload::ImplementationReady(value) => {
            references.extend(&value.irregularity_references)
        }
        RoleResultPayload::MergeAssessment(value) => {
            for gate in &value.deterministic_gate_evidence {
                references.extend(&gate.evidence_references);
            }
            for factor in value.ratings.values() {
                references.extend(&factor.evidence_references);
            }
        }
        RoleResultPayload::OperationResult(value) => references.extend(&value.evidence_references),
        RoleResultPayload::PostmortemReady(value) => references.extend(&value.source_references),
        RoleResultPayload::ProfileTrialResult(value) => {
            references.extend(&value.evidence_references)
        }
        RoleResultPayload::ProfilePromotionProposal(value) => {
            references.extend(&value.evidence_references)
        }
        RoleResultPayload::TicketProposal(_)
        | RoleResultPayload::DispatchRequest(_)
        | RoleResultPayload::Intervention(_)
        | RoleResultPayload::InvestigationRequest(_)
        | RoleResultPayload::PrepareWorktrees(_)
        | RoleResultPayload::PlanReady(_)
        | RoleResultPayload::ReviewReady(_)
        | RoleResultPayload::MergeIntent(_)
        | RoleResultPayload::OperationAction(_)
        | RoleResultPayload::LearningDecision(_) => {}
    }
    for reference in references {
        validate_artifact_reference(reference)?;
        if !declared_claims.contains(reference) {
            return Err(
                "nested evidence reference is not declared in the role result artifact claims"
                    .into(),
            );
        }
        if !role_may_submit_artifact(role, reference.kind) {
            return Err(format!(
                "role {role:?} cannot reference artifact kind {:?}",
                reference.kind
            ));
        }
    }
    Ok(())
}

pub fn role_result_payload_schema(kind: RoleOutputKind) -> Value {
    macro_rules! schema_for_kind {
        ($type:ty) => {
            serde_json::to_value(schemars::schema_for!($type))
                .expect("role payload JsonSchema serializes")
        };
    }
    let mut schema = match kind {
        RoleOutputKind::Progress => schema_for_kind!(ProgressPayload),
        RoleOutputKind::Irregularity => schema_for_kind!(IrregularityPayload),
        RoleOutputKind::HumanRequest => schema_for_kind!(HumanRequestPayload),
        RoleOutputKind::TicketProposal => schema_for_kind!(TicketProposalPayload),
        RoleOutputKind::DispatchRequest => schema_for_kind!(DispatchRequestPayload),
        RoleOutputKind::Intervention => schema_for_kind!(InterventionPayload),
        RoleOutputKind::SpawnRequest => schema_for_kind!(SpawnRequestPayload),
        RoleOutputKind::InvestigationRequest => schema_for_kind!(InvestigationRequestPayload),
        RoleOutputKind::PrepareWorktrees => schema_for_kind!(PrepareWorktreesPayload),
        RoleOutputKind::PlanReady => schema_for_kind!(PlanReadyPayload),
        RoleOutputKind::ImplementationReady => schema_for_kind!(ImplementationReadyPayload),
        RoleOutputKind::ReviewReady => schema_for_kind!(ReviewReadyPayload),
        RoleOutputKind::MergeAssessment => schema_for_kind!(MergeAssessmentPayload),
        RoleOutputKind::MergeIntent => schema_for_kind!(MergeIntentPayload),
        RoleOutputKind::OperationAction => schema_for_kind!(OperationActionPayload),
        RoleOutputKind::OperationResult => schema_for_kind!(OperationResultPayload),
        RoleOutputKind::PostmortemReady => schema_for_kind!(PostmortemReadyPayload),
        RoleOutputKind::LearningDecision => schema_for_kind!(LearningDecisionPayload),
        RoleOutputKind::ProfileTrialResult => schema_for_kind!(ProfileTrialResultPayload),
        RoleOutputKind::ProfilePromotionProposal => {
            schema_for_kind!(ProfilePromotionProposalPayload)
        }
    };
    constrain_payload_string_schemas(&mut schema);
    schema
}

// The provider gets the payload's structural constraints. Cross-field rules
// such as commit-chain/head equality and procedure ordering stay authoritative
// in validate_role_payload after typed deserialization.
fn constrain_payload_string_schemas(schema: &mut Value) {
    fn constrain(value: &mut Value, min: usize, max: usize, pattern: &str) {
        if let Some(map) = value.as_object_mut() {
            map.insert("minLength".into(), Value::from(min));
            map.insert("maxLength".into(), Value::from(max));
            map.insert("pattern".into(), Value::from(pattern));
        }
    }
    fn require_non_whitespace(value: &mut Value) {
        if let Some(map) = value.as_object_mut() {
            map.insert("minLength".into(), Value::from(1));
            map.insert("pattern".into(), Value::from(r"\S"));
        }
    }
    fn visit(value: &mut Value) {
        match value {
            Value::Object(map) => {
                if let Some(defs) = map.get_mut("$defs").and_then(Value::as_object_mut) {
                    for (name, definition) in defs {
                        match name.as_str() {
                            "WorkNodeId" => constrain(definition, 1, 80, r"^[A-Za-z0-9._-]+$"),
                            "ProjectId" | "RepositoryId" | "ProfileId" | "AdapterId" => {
                                constrain(definition, 1, 255, r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
                            }
                            "TicketId" | "TicketNamespace" | "TicketRunId" | "AgentRunId"
                            | "HumanRequestId" | "OperationId" | "RexBlockId" => {
                                constrain(definition, 1, 512, r"^[^\p{Cc}]*$")
                            }
                            "Digest" | "ArtifactId" => {
                                constrain(definition, 64, 64, r"^[a-f0-9]{64}$")
                            }
                            "GitCommitId" => {
                                constrain(definition, 40, 64, r"^(?:[a-f0-9]{40}|[a-f0-9]{64})$")
                            }
                            "RoleSessionId" => constrain(
                                definition,
                                1,
                                255,
                                r"^[A-Za-z0-9._-]+(:[A-Za-z0-9._-]+)*$",
                            ),
                            "RoleArtifactReference" => {
                                if let Some(properties) = definition
                                    .get_mut("properties")
                                    .and_then(Value::as_object_mut)
                                {
                                    if let Some(version) = properties
                                        .get_mut("schema_version")
                                        .and_then(Value::as_object_mut)
                                    {
                                        version.insert("minimum".into(), Value::from(1));
                                    }
                                    if let Some(path) =
                                        properties.get_mut("path").and_then(Value::as_object_mut)
                                    {
                                        path.insert("maxLength".into(), Value::from(1024));
                                        path.insert(
                                            "pattern".into(),
                                            Value::from(ARTIFACT_RELATIVE_PATH_PATTERN),
                                        );
                                        path.insert(
                                            "not".into(),
                                            serde_json::json!({"pattern": r"^[^/]:"}),
                                        );
                                    }
                                }
                            }
                            "ChangeReference" => {
                                if let Some(commits) = definition
                                    .get_mut("properties")
                                    .and_then(Value::as_object_mut)
                                    .and_then(|properties| properties.get_mut("commit_shas"))
                                    .and_then(Value::as_object_mut)
                                {
                                    commits.insert("minItems".into(), Value::from(1));
                                }
                            }
                            "RiskFactorAssessment" => {
                                if let Some(properties) = definition
                                    .get_mut("properties")
                                    .and_then(Value::as_object_mut)
                                {
                                    if let Some(rating) =
                                        properties.get_mut("rating").and_then(Value::as_object_mut)
                                    {
                                        rating.insert("maximum".into(), Value::from(4));
                                    }
                                    for field in ["source", "rationale"] {
                                        if let Some(schema) = properties.get_mut(field) {
                                            require_non_whitespace(schema);
                                        }
                                    }
                                    if let Some(evidence) = properties
                                        .get_mut("evidence_references")
                                        .and_then(Value::as_object_mut)
                                    {
                                        evidence.insert("minItems".into(), Value::from(1));
                                    }
                                }
                            }
                            "DeterministicGateEvidence" => {
                                if let Some(properties) = definition
                                    .get_mut("properties")
                                    .and_then(Value::as_object_mut)
                                {
                                    if let Some(gate_id) = properties.get_mut("gate_id") {
                                        require_non_whitespace(gate_id);
                                    }
                                    if let Some(evidence) = properties
                                        .get_mut("evidence_references")
                                        .and_then(Value::as_object_mut)
                                    {
                                        evidence.insert("minItems".into(), Value::from(1));
                                    }
                                }
                            }
                            "MergeProcedureStep" | "PostMergeVerification" => {
                                if let Some(properties) = definition
                                    .get_mut("properties")
                                    .and_then(Value::as_object_mut)
                                {
                                    for field in ["instruction_reference", "rationale"] {
                                        if let Some(text) = properties.get_mut(field) {
                                            require_non_whitespace(text);
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
                if map.get("title").and_then(Value::as_str) == Some("MergeAssessmentPayload")
                    && let Some(properties) =
                        map.get_mut("properties").and_then(Value::as_object_mut)
                {
                    for field in ["pr_references", "deterministic_gate_evidence"] {
                        if let Some(array) =
                            properties.get_mut(field).and_then(Value::as_object_mut)
                        {
                            array.insert("minItems".into(), Value::from(1));
                        }
                    }
                    for field in ["rationale", "disposition"] {
                        if let Some(text) = properties.get_mut(field) {
                            require_non_whitespace(text);
                        }
                    }
                    if let Some(items) = properties
                        .get_mut("pr_references")
                        .and_then(Value::as_object_mut)
                        .and_then(|array| array.get_mut("items"))
                    {
                        require_non_whitespace(items);
                    }
                    if let Some(ratings) =
                        properties.get_mut("ratings").and_then(Value::as_object_mut)
                    {
                        ratings.insert("minProperties".into(), Value::from(5));
                        ratings.insert("maxProperties".into(), Value::from(5));
                        ratings.insert("propertyNames".into(), serde_json::json!({
                                "enum": ["change_impact", "complexity", "verification_gaps", "review_uncertainty", "operational_exposure"]
                            }));
                    }
                }
                if map.get("title").and_then(Value::as_str) == Some("ImplementationReadyPayload")
                    && let Some(changes) = map
                        .get_mut("properties")
                        .and_then(Value::as_object_mut)
                        .and_then(|properties| properties.get_mut("change_references"))
                        .and_then(Value::as_object_mut)
                {
                    changes.insert("minItems".into(), Value::from(1));
                }
                if map.get("title").and_then(Value::as_str) == Some("MergeIntentPayload")
                    && let Some(properties) =
                        map.get_mut("properties").and_then(Value::as_object_mut)
                {
                    for field in ["pr_identities", "steps", "post_merge_verification"] {
                        if let Some(array) =
                            properties.get_mut(field).and_then(Value::as_object_mut)
                        {
                            array.insert("minItems".into(), Value::from(1));
                        }
                    }
                    if let Some(text) = properties.get_mut("assessment_id") {
                        require_non_whitespace(text);
                    }
                    if let Some(items) = properties
                        .get_mut("pr_identities")
                        .and_then(Value::as_object_mut)
                        .and_then(|array| array.get_mut("items"))
                    {
                        require_non_whitespace(items);
                    }
                    for field in ["steps", "post_merge_verification"] {
                        if let Some(item_properties) = properties
                            .get_mut(field)
                            .and_then(Value::as_object_mut)
                            .and_then(|array| array.get_mut("items"))
                            .and_then(Value::as_object_mut)
                            .and_then(|item| item.get_mut("properties"))
                            .and_then(Value::as_object_mut)
                        {
                            for field in ["instruction_reference", "rationale"] {
                                if let Some(text) = item_properties.get_mut(field) {
                                    require_non_whitespace(text);
                                }
                            }
                        }
                    }
                }
                if let Some(properties) = map.get_mut("properties").and_then(Value::as_object_mut) {
                    for (name, property) in properties {
                        match name.as_str() {
                            "digest" => constrain(property, 64, 64, r"^[a-f0-9]{64}$"),
                            name if name.ends_with("_digest") => {
                                constrain(property, 64, 64, r"^[a-f0-9]{64}$")
                            }
                            "base_commit" | "previous_head" | "branch_head" | "source_commit" => {
                                constrain(property, 40, 64, r"^(?:[a-f0-9]{40}|[a-f0-9]{64})$")
                            }
                            "commit_shas" => {
                                if let Some(items) = property.get_mut("items") {
                                    constrain(items, 40, 64, r"^(?:[a-f0-9]{40}|[a-f0-9]{64})$");
                                }
                            }
                            "repository" | "project_id" | "project" | "profile_id"
                            | "adapter_id" => {
                                constrain(property, 1, 255, r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
                            }
                            "coordinator_role_session_id" => {
                                constrain(property, 1, 255, r"^[A-Za-z0-9._-]+(:[A-Za-z0-9._-]+)*$")
                            }
                            "parent" | "ticket_reference" | "ticket_id" | "ticket_namespace"
                            | "ticket_run_id" | "agent_run_id" | "parent_run_id"
                            | "human_request_id" | "operation_id" | "rex_block_id"
                            | "request_id" | "message_id" => {
                                constrain(property, 1, 512, r"^[^\p{Cc}]*$")
                            }
                            "dependencies" => {
                                if let Some(items) = property.get_mut("items") {
                                    constrain(items, 1, 512, r"^[^\p{Cc}]*$");
                                }
                            }
                            "worktree_id" | "work_node" | "node_key" => {
                                constrain(property, 1, 80, r"^[A-Za-z0-9._-]+$")
                            }
                            "affected_node_keys" | "worker_nodes" => {
                                if let Some(items) = property.get_mut("items") {
                                    constrain(items, 1, 80, r"^[A-Za-z0-9._-]+$");
                                }
                            }
                            "path" => {
                                constrain(property, 1, 1024, ARTIFACT_RELATIVE_PATH_PATTERN);
                                if let Some(map) = property.as_object_mut() {
                                    map.insert(
                                        "not".into(),
                                        serde_json::json!({"pattern": r"^[^/]:"}),
                                    );
                                }
                            }
                            _ => {}
                        }
                    }
                }
                for child in map.values_mut() {
                    visit(child);
                }
            }
            Value::Array(items) => items.iter_mut().for_each(visit),
            _ => {}
        }
    }
    visit(schema);
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleResultSubmission {
    pub schema_version: u32,
    pub message_id: String,
    pub binding: RoleResultBinding,
    pub kind: RoleOutputKind,
    pub assertion: AgentAssertion,
    pub structured_result: Value,
    /// SHA-256 of compact serde_json serialization of structured_result.
    pub result_digest: Digest,
    pub artifact_refs: Vec<RoleArtifactReference>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedRoleResult {
    pub binding: RoleResultBinding,
    pub message_id: String,
    pub kind: RoleOutputKind,
    /// This remains an Agent claim and never represents host process success,
    /// hook success, merge completion, or deployment success.
    pub assertion: AgentAssertion,
    pub structured_result: Value,
    pub typed_payload: RoleResultPayload,
    pub result_digest: Digest,
    /// Agent-declared locators only. The host artifact registrar still has to
    /// verify the bytes and persist a receipt before consumers may rely on them.
    pub claimed_artifact_refs: Vec<RoleArtifactReference>,
    /// Derived from the verified parent binding, never from Agent content.
    pub wake_recipients: Vec<WakeSessionKey>,
}

/// Validate a run-local Agent result against host-owned immutable authority.
/// This function creates evidence only; callers must separately persist host
/// process, hook, forge and operation observations and must not reduce directly
/// from the Agent's success assertion.
pub fn validate_role_result(
    expected: &RoleResultBinding,
    submission: RoleResultSubmission,
) -> Result<ValidatedRoleResult, String> {
    expected.validate()?;
    if submission.schema_version != ROLE_RESULT_SCHEMA_VERSION {
        return Err("unsupported role result schema version".into());
    }
    submission.binding.validate()?;
    if &submission.binding != expected {
        return Err("role result binding does not match host-owned run authority".into());
    }
    if submission.message_id.trim().is_empty()
        || submission.message_id.len() > 255
        || submission.message_id.chars().any(char::is_control)
    {
        return Err("invalid role result message ID".into());
    }
    if !role_may_submit_output(submission.binding.role, submission.kind) {
        return Err("role is not allowed to submit this result kind".into());
    }
    validate_assertion(&submission.assertion)?;
    let encoded_result = serde_json::to_vec(&submission.structured_result)
        .map_err(|error| format!("serialize structured role result: {error}"))?;
    if !submission.structured_result.is_object() {
        return Err("structured role result must be a JSON object".into());
    }
    if encoded_result.len() > MAX_ROLE_RESULT_JSON_BYTES {
        return Err("structured role result exceeds its byte limit".into());
    }
    let actual_digest = Digest::parse(format!("{:x}", Sha256::digest(encoded_result)))?;
    if actual_digest != submission.result_digest {
        return Err("structured result digest does not match its content".into());
    }
    let typed_payload =
        RoleResultPayload::parse(submission.kind, submission.structured_result.clone())?;
    validate_role_payload(&typed_payload)?;
    if submission.artifact_refs.len() > MAX_ROLE_RESULT_ARTIFACTS
        || serde_json::to_vec(&submission.artifact_refs)
            .map_err(|error| format!("serialize role result artifact references: {error}"))?
            .len()
            > MAX_ROLE_RESULT_ARTIFACTS_JSON_BYTES
    {
        return Err("role result artifact references exceed their limits".into());
    }
    let mut artifact_paths = BTreeSet::new();
    for artifact in &submission.artifact_refs {
        validate_artifact_reference(artifact)?;
        if !role_may_submit_artifact(submission.binding.role, artifact.kind) {
            return Err("role is not allowed to submit this artifact kind".into());
        }
        if !artifact_paths.insert(&artifact.path) {
            return Err("role result repeats an artifact path".into());
        }
    }
    validate_payload_artifacts(
        &typed_payload,
        submission.binding.role,
        &submission.artifact_refs,
    )?;
    let wake_recipients = result_wake_recipients(&submission.binding, submission.kind);
    Ok(ValidatedRoleResult {
        binding: submission.binding,
        message_id: submission.message_id,
        kind: submission.kind,
        assertion: submission.assertion,
        structured_result: submission.structured_result,
        typed_payload,
        result_digest: submission.result_digest,
        claimed_artifact_refs: submission.artifact_refs,
        wake_recipients,
    })
}

fn validate_assertion(assertion: &AgentAssertion) -> Result<(), String> {
    let reason = match assertion {
        AgentAssertion::Succeeded => return Ok(()),
        AgentAssertion::Blocked { reason } | AgentAssertion::Failed { reason } => Some(reason),
        AgentAssertion::Cancelled { reason } => reason.as_ref(),
    };
    if reason.is_some_and(|value| {
        value.trim().is_empty() || value.len() > 32_000 || value.chars().any(char::is_control)
    }) {
        return Err("Agent assertion reason must be bounded plain text".into());
    }
    Ok(())
}

fn validate_artifact_reference(reference: &RoleArtifactReference) -> Result<(), String> {
    validate_artifact_relative_path(&reference.path)?;
    if reference.schema_version == 0 {
        return Err("artifact schema version must be positive".into());
    }
    Ok(())
}

fn validate_artifact_relative_path(path: &str) -> Result<(), String> {
    if path.is_empty()
        || path.len() > 4096
        || path.chars().count() > 1024
        || path.starts_with('/')
        || path.starts_with('\\')
        || path.contains('\\')
        || path.chars().any(char::is_control)
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || path
            .split('/')
            .next()
            .is_some_and(|part| part.chars().nth(1) == Some(':'))
    {
        return Err("artifact path must be a bounded normalized relative path".into());
    }
    Ok(())
}

pub fn role_may_submit_artifact(role: Role, kind: RoleArtifactKind) -> bool {
    use RoleArtifactKind as K;
    match kind {
        K::Plan => matches!(role, Role::Coordinator | Role::Planner),
        K::Change | K::TestReceipt => role == Role::Worker,
        K::Review => role == Role::Reviewer,
        K::MergeAssessment => role == Role::MergeDecision,
        K::OperationReceipt => role == Role::Operator,
        K::Postmortem => role == Role::Postmortem,
        K::Learning => role == Role::Supervisor,
        K::General => true,
    }
}

fn role_may_submit_output(role: Role, kind: RoleOutputKind) -> bool {
    allowed_role_output_kinds(role).contains(&kind)
}

pub fn allowed_role_output_kinds(role: Role) -> Vec<RoleOutputKind> {
    use RoleOutputKind as K;
    let mut kinds = vec![K::Progress, K::Irregularity, K::HumanRequest];
    kinds.extend(match role {
        Role::Supervisor => vec![
            K::TicketProposal,
            K::DispatchRequest,
            K::Intervention,
            K::LearningDecision,
            K::ProfileTrialResult,
            K::ProfilePromotionProposal,
        ],
        Role::Coordinator => vec![K::SpawnRequest, K::PrepareWorktrees, K::PlanReady],
        Role::Planner => vec![K::PlanReady, K::InvestigationRequest],
        Role::Worker => vec![K::ImplementationReady],
        Role::Reviewer => vec![K::ReviewReady, K::InvestigationRequest],
        Role::MergeDecision => vec![K::MergeAssessment, K::MergeIntent],
        Role::Operator => vec![K::OperationAction, K::OperationResult],
        Role::Postmortem => vec![K::PostmortemReady],
    });
    kinds
}

fn result_wake_recipients(
    binding: &RoleResultBinding,
    kind: RoleOutputKind,
) -> Vec<WakeSessionKey> {
    let mut recipients = BTreeSet::new();
    if let Some(parent_role) = binding.parent_role {
        recipients.insert(WakeSessionKey {
            project_id: binding.project_id.clone(),
            ticket_run_id: if parent_role == Role::Supervisor {
                None
            } else {
                binding.ticket_run_id.clone()
            },
            role: parent_role,
        });
    }
    if kind == RoleOutputKind::Irregularity && binding.role != Role::Supervisor {
        recipients.insert(WakeSessionKey {
            project_id: binding.project_id.clone(),
            ticket_run_id: None,
            role: Role::Supervisor,
        });
    }
    recipients.into_iter().collect()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GoalTicketObservation {
    pub id: TicketId,
    pub created_at_unix_millis: i64,
    pub active_run: bool,
    pub substantive_work: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DuplicateResolution {
    NoDuplicates,
    Canonical {
        ticket_id: TicketId,
        annotate_and_cancel: Vec<TicketId>,
    },
    HumanRequired {
        candidates: Vec<TicketId>,
        reason: String,
    },
}

/// Preserve a previously committed canonical ticket. Without one, select by
/// stable creation time and external ID. Uncertain/in-progress duplicates need
/// human judgment rather than automatic cancellation.
pub fn resolve_goal_duplicates(
    observations: &[GoalTicketObservation],
    previous_canonical: Option<&TicketId>,
) -> DuplicateResolution {
    let mut by_id = BTreeMap::new();
    for item in observations {
        by_id
            .entry(item.id.clone())
            .and_modify(|existing: &mut AggregatedTicketObservation| {
                existing.active_run |= item.active_run;
                existing.substantive_work |= item.substantive_work;
                existing.created_at_conflicts |=
                    existing.created_at_unix_millis != item.created_at_unix_millis;
            })
            .or_insert_with(|| AggregatedTicketObservation {
                created_at_unix_millis: item.created_at_unix_millis,
                active_run: item.active_run,
                substantive_work: item.substantive_work,
                created_at_conflicts: false,
            });
    }
    let candidates: Vec<_> = by_id
        .iter()
        .map(|(id, observation)| GoalTicketObservation {
            id: id.clone(),
            created_at_unix_millis: observation.created_at_unix_millis,
            active_run: observation.active_run,
            substantive_work: observation.substantive_work,
        })
        .collect();
    if candidates.is_empty() && previous_canonical.is_none() {
        return DuplicateResolution::NoDuplicates;
    }
    if by_id
        .values()
        .any(|observation| observation.created_at_conflicts)
    {
        return DuplicateResolution::HumanRequired {
            candidates: candidates.iter().map(|item| item.id.clone()).collect(),
            reason: "one ticket has conflicting creation timestamps".into(),
        };
    }
    let canonical_id = previous_canonical.cloned().or_else(|| {
        candidates
            .iter()
            .min_by(|left, right| {
                left.created_at_unix_millis
                    .cmp(&right.created_at_unix_millis)
                    .then_with(|| left.id.cmp(&right.id))
            })
            .map(|item| item.id.clone())
    });
    let Some(canonical_id) = canonical_id else {
        return DuplicateResolution::HumanRequired {
            candidates: candidates.iter().map(|item| item.id.clone()).collect(),
            reason: "no canonical ticket could be selected".into(),
        };
    };
    let conflicting = candidates
        .iter()
        .any(|item| item.id != canonical_id && (item.active_run || item.substantive_work));
    if conflicting {
        return DuplicateResolution::HumanRequired {
            candidates: candidates.iter().map(|item| item.id.clone()).collect(),
            reason: "a possible duplicate already has an active run or substantive work".into(),
        };
    }
    DuplicateResolution::Canonical {
        ticket_id: canonical_id.clone(),
        annotate_and_cancel: candidates
            .iter()
            .filter(|item| item.id != canonical_id)
            .map(|item| item.id.clone())
            .collect(),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AggregatedTicketObservation {
    created_at_unix_millis: i64,
    active_run: bool,
    substantive_work: bool,
    created_at_conflicts: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecipeSelection {
    pub recipe_id: Option<String>,
    pub decision: RecipeDecision,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecipeDecision {
    Selected,
    HumanRequiredNoMatch,
    HumanRequiredAmbiguous,
    HumanRequiredUnknownRecipe,
    HumanRequiredInvalidRepositoryPolicy,
}

/// Select exactly one declared label rule. A ticket with no rule or multiple
/// matching rules waits for a human; TOML order never silently decides policy.
pub fn select_operation_recipe(
    config: &Config,
    project: &ProjectConfig,
    labels: &BTreeSet<String>,
) -> RecipeSelection {
    let matches: Vec<_> = project
        .operation_matches
        .iter()
        .filter(|rule| rule.labels_all.iter().all(|label| labels.contains(label)))
        .collect();
    if matches.is_empty() {
        return RecipeSelection {
            recipe_id: None,
            decision: RecipeDecision::HumanRequiredNoMatch,
        };
    }
    if matches.len() > 1 {
        return RecipeSelection {
            recipe_id: None,
            decision: RecipeDecision::HumanRequiredAmbiguous,
        };
    }
    let recipe_id = &matches[0].recipe;
    let Some(recipe) = config.operation_recipes.get(recipe_id) else {
        return RecipeSelection {
            recipe_id: Some(recipe_id.clone()),
            decision: RecipeDecision::HumanRequiredUnknownRecipe,
        };
    };
    if !recipe_valid_for_project(config, project, recipe) {
        return RecipeSelection {
            recipe_id: Some(recipe_id.clone()),
            decision: RecipeDecision::HumanRequiredInvalidRepositoryPolicy,
        };
    }
    RecipeSelection {
        recipe_id: Some(recipe_id.clone()),
        decision: RecipeDecision::Selected,
    }
}

fn recipe_valid_for_project(
    config: &Config,
    project: &ProjectConfig,
    recipe: &OperationRecipe,
) -> bool {
    let project_repositories: BTreeSet<_> = project.repositories.iter().collect();
    if recipe.targets.iter().any(|target| {
        !project_repositories.contains(&target.repository)
            || config
                .repositories
                .get(&target.repository)
                .is_none_or(|repository| {
                    repository
                        .operations
                        .as_ref()
                        .is_none_or(|policy| !policy.allowed_actions.contains(&target.action))
                })
            || !config.operation_actions.contains_key(&target.action)
    }) {
        return false;
    }
    if recipe.required_stages.contains(&RecipeStage::Operations)
        && recipe.targets.is_empty()
        && recipe
            .not_required_reason
            .as_deref()
            .is_none_or(str::is_empty)
    {
        return false;
    }
    if recipe.targets.is_empty()
        && recipe
            .not_required_reason
            .as_deref()
            .is_none_or(str::is_empty)
    {
        return false;
    }
    if recipe
        .targets
        .iter()
        .any(|target| match &target.success_predicate {
            SuccessPredicate::ExplicitNotRequired { reason, evidence } => {
                reason.trim().is_empty()
                    || evidence.is_empty()
                    || evidence.iter().any(|item| item.trim().is_empty())
            }
            _ => false,
        })
    {
        return false;
    }
    true
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedWorkNode {
    pub id: WorkNodeId,
    pub repository: RepositoryId,
    pub task: String,
    pub depends_on: Vec<WorkDependency>,
    pub required_evidence: Vec<String>,
    /// True creates a read-only investigation run. Implementation nodes always
    /// execute with the Worker role; Coordinator never gets source-write authority.
    pub investigation: bool,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkDependency {
    pub node: WorkNodeId,
    pub kind: WorkDependencyKind,
    pub affected_evidence: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkDependencyKind {
    GitBase,
    Delivery,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkPlan {
    pub nodes: Vec<PlannedWorkNode>,
    pub requested_investigation_children: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedWorkNode {
    pub id: WorkNodeId,
    pub repository: RepositoryId,
    pub base: WorkBaseSource,
    pub task: String,
    pub depends_on: Vec<WorkDependency>,
    pub required_evidence: Vec<String>,
    pub role: Role,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkBaseSource {
    ControllerObservedCommit {
        commit: String,
    },
    /// Resolve from the predecessor's accepted exact HEAD after it completes;
    /// never substitute the repository's controller-observed trunk base.
    PredecessorWorkNodeHead {
        node: WorkNodeId,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedPlan {
    pub ticket_run_id: TicketRunId,
    pub nodes_in_execution_order: Vec<ValidatedWorkNode>,
    pub spawned_investigation_children: usize,
}

pub fn validate_work_plan(
    ticket_run_id: &TicketRunId,
    project: &ProjectConfig,
    plan: WorkPlan,
    observed_bases: &BTreeMap<RepositoryId, String>,
) -> Result<ValidatedPlan, String> {
    if plan.nodes.is_empty() {
        return Err("a delivery plan must contain at least one work node".into());
    }
    if plan.requested_investigation_children > project.max_investigation_children {
        return Err("plan exceeds the Project investigation-child limit".into());
    }
    let allowed_repositories: BTreeSet<_> = project.repositories.iter().collect();
    let mut nodes = BTreeMap::new();
    for node in plan.nodes {
        if node.task.trim().is_empty() || node.task.len() > 32_000 {
            return Err(format!(
                "work node {} has an empty or oversized task",
                node.id
            ));
        }
        if !allowed_repositories.contains(&node.repository) {
            return Err(format!(
                "work node {} names an unregistered repository",
                node.id
            ));
        }
        if nodes.insert(node.id.clone(), node).is_some() {
            return Err("work plan contains duplicate node IDs".into());
        }
    }
    let mut indegree: BTreeMap<WorkNodeId, usize> =
        nodes.keys().cloned().map(|id| (id, 0)).collect();
    let mut children: BTreeMap<WorkNodeId, BTreeSet<WorkNodeId>> = BTreeMap::new();
    for node in nodes.values() {
        let mut dependencies = BTreeSet::new();
        for dependency in &node.depends_on {
            if dependency.node == node.id {
                return Err(format!("work node {} depends on itself", node.id));
            }
            if !nodes.contains_key(&dependency.node) {
                return Err(format!(
                    "work node {} depends on unknown node {}",
                    node.id, dependency.node
                ));
            }
            let predecessor = nodes.get(&dependency.node).expect("dependency exists");
            if dependency.kind == WorkDependencyKind::GitBase
                && predecessor.repository != node.repository
            {
                return Err(format!(
                    "git-base dependency for work node {} crosses repositories",
                    node.id
                ));
            }
            if dependency.kind == WorkDependencyKind::GitBase && predecessor.investigation {
                return Err(format!(
                    "git-base dependency for work node {} cannot use a read-only investigation",
                    node.id
                ));
            }
            if dependency.affected_evidence.is_empty()
                || dependency
                    .affected_evidence
                    .iter()
                    .any(|evidence| evidence.trim().is_empty())
            {
                return Err(format!(
                    "dependency for work node {} must identify affected evidence",
                    node.id
                ));
            }
            if !dependencies.insert(&dependency.node) {
                return Err(format!("work node {} repeats a dependency", node.id));
            }
            *indegree.get_mut(&node.id).expect("indexed node exists") += 1;
            children
                .entry(dependency.node.clone())
                .or_default()
                .insert(node.id.clone());
        }
    }
    let mut ready: BTreeSet<_> = indegree
        .iter()
        .filter(|(_, count)| **count == 0)
        .map(|(id, _)| id.clone())
        .collect();
    let mut order = Vec::with_capacity(nodes.len());
    while let Some(next) = ready.pop_first() {
        order.push(next.clone());
        if let Some(dependents) = children.get(&next) {
            for child in dependents {
                let count = indegree.get_mut(child).expect("indexed child exists");
                *count -= 1;
                if *count == 0 {
                    ready.insert(child.clone());
                }
            }
        }
    }
    if order.len() != nodes.len() {
        return Err("work plan dependency graph contains a cycle".into());
    }
    let actual_investigations = nodes.values().filter(|node| node.investigation).count();
    if actual_investigations != plan.requested_investigation_children {
        return Err("investigation child count does not match the plan nodes".into());
    }
    if actual_investigations == nodes.len() {
        return Err("a delivery plan requires at least one implementation node".into());
    }
    let mut validated = Vec::with_capacity(order.len());
    for id in order {
        let node = nodes.remove(&id).expect("topological node exists");
        let git_base_dependencies: Vec<_> = node
            .depends_on
            .iter()
            .filter(|dependency| dependency.kind == WorkDependencyKind::GitBase)
            .collect();
        if git_base_dependencies.len() > 1 {
            return Err(format!(
                "work node {} has more than one Git base predecessor",
                node.id
            ));
        }
        let base = if let Some(dependency) = git_base_dependencies.first() {
            WorkBaseSource::PredecessorWorkNodeHead {
                node: dependency.node.clone(),
            }
        } else {
            let commit = observed_bases.get(&node.repository).ok_or_else(|| {
                format!(
                    "no controller-observed base for repository {}",
                    node.repository
                )
            })?;
            validate_git_commit(commit)?;
            WorkBaseSource::ControllerObservedCommit {
                commit: commit.clone(),
            }
        };
        let role = if node.investigation {
            Role::Planner
        } else {
            Role::Worker
        };
        if !node.investigation && node.required_evidence.is_empty() {
            return Err(format!(
                "implementation node {} has no required evidence",
                node.id
            ));
        }
        if node.investigation && !node.required_evidence.is_empty() {
            return Err(format!(
                "read-only investigation node {} cannot require implementation evidence",
                node.id
            ));
        }
        validated.push(ValidatedWorkNode {
            id: node.id,
            repository: node.repository,
            base,
            task: node.task,
            depends_on: node.depends_on,
            required_evidence: node.required_evidence,
            role,
        });
    }
    Ok(ValidatedPlan {
        ticket_run_id: ticket_run_id.clone(),
        nodes_in_execution_order: validated,
        spawned_investigation_children: plan.requested_investigation_children,
    })
}

fn validate_git_commit(value: &str) -> Result<(), String> {
    if matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err("controller-observed base must be a full Git commit ID".into())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReviewProgress {
    pub completed_rounds: usize,
    pub maximum_rounds: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewDisposition {
    StartCorrectionWorker,
    StartMergeDecision,
    HumanRequiredAtRoundLimit,
}

pub fn review_disposition(
    progress: ReviewProgress,
    has_unresolved_findings: bool,
) -> Result<ReviewDisposition, String> {
    if progress.maximum_rounds == 0 {
        return Err("maximum review rounds must be positive".into());
    }
    if has_unresolved_findings {
        if progress.completed_rounds >= progress.maximum_rounds {
            Ok(ReviewDisposition::HumanRequiredAtRoundLimit)
        } else {
            Ok(ReviewDisposition::StartCorrectionWorker)
        }
    } else {
        Ok(ReviewDisposition::StartMergeDecision)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlanComplexity {
    Routine,
    Complex,
    Uncertain,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlannerSelection {
    CoordinatorPlansDirectly,
    LaunchPlanner {
        profile_id: crate::domain::ids::ProfileId,
    },
    HumanClarificationRequired,
}

pub fn select_planner(project: &ProjectConfig, complexity: PlanComplexity) -> PlannerSelection {
    match complexity {
        PlanComplexity::Routine => PlannerSelection::CoordinatorPlansDirectly,
        PlanComplexity::Complex => project
            .roles
            .get(&Role::Planner)
            .cloned()
            .map_or(PlannerSelection::CoordinatorPlansDirectly, |profile_id| {
                PlannerSelection::LaunchPlanner { profile_id }
            }),
        PlanComplexity::Uncertain => PlannerSelection::HumanClarificationRequired,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GoalCompletionEvidence {
    pub satisfied_acceptance: Vec<String>,
    pub incomplete_ticket_ids: Vec<TicketId>,
    pub deferred_risks: Vec<String>,
    pub operation_results: Vec<String>,
    pub subject_digest: crate::domain::ids::Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GoalCompletionDecision {
    NotSatisfied { missing_evidence: Vec<String> },
    RequestHumanConfirmation { evidence: GoalCompletionEvidence },
}

/// Agents can request confirmation; only a human response can complete a goal.
pub fn propose_goal_completion(
    project: &ProjectConfig,
    evidence: GoalCompletionEvidence,
    all_acceptance_ids: &BTreeSet<String>,
    active_ticket_runs: usize,
) -> GoalCompletionDecision {
    if project.mode != ProjectMode::Goal {
        return GoalCompletionDecision::NotSatisfied {
            missing_evidence: vec!["project is not goal-driven".into()],
        };
    }
    let observed: BTreeSet<_> = evidence.satisfied_acceptance.iter().cloned().collect();
    let missing: Vec<_> = all_acceptance_ids.difference(&observed).cloned().collect();
    if !missing.is_empty() || active_ticket_runs > 0 || !evidence.incomplete_ticket_ids.is_empty() {
        return GoalCompletionDecision::NotSatisfied {
            missing_evidence: missing,
        };
    }
    GoalCompletionDecision::RequestHumanConfirmation { evidence }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanIntervention {
    pub project_id: ProjectId,
    pub ticket_run_id: TicketRunId,
    pub expected_revision: u64,
    pub message: String,
    pub fence_active_work: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterventionRoute {
    pub target: Role,
    pub notify: Role,
    pub fence_active_work: bool,
}

pub fn route_human_intervention(
    intervention: &HumanIntervention,
    current_revision: u64,
) -> Result<InterventionRoute, String> {
    if intervention.expected_revision != current_revision {
        return Err("human intervention targets a stale TicketRun revision".into());
    }
    if intervention.message.trim().is_empty() || intervention.message.len() > 32_000 {
        return Err("human intervention must contain a bounded nonempty instruction".into());
    }
    Ok(InterventionRoute {
        target: Role::Coordinator,
        notify: Role::Supervisor,
        fence_active_work: intervention.fence_active_work,
    })
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct WakeSessionKey {
    pub project_id: ProjectId,
    pub ticket_run_id: Option<TicketRunId>,
    pub role: Role,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WakeCause {
    StopOrPolicyFence,
    HumanResponse,
    CoordinatorInstruction,
    ChildResult,
    WorkflowTransition,
    ExternalObservation,
    DueRetry,
    PeriodicSupervisorReview,
}

impl WakeCause {
    fn precedence(self) -> u8 {
        match self {
            Self::StopOrPolicyFence => 0,
            Self::HumanResponse | Self::CoordinatorInstruction => 1,
            Self::ChildResult | Self::WorkflowTransition => 2,
            Self::ExternalObservation => 3,
            Self::DueRetry | Self::PeriodicSupervisorReview => 4,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WakeEvent {
    pub event_id: String,
    pub session: WakeSessionKey,
    pub source_revision: u64,
    pub observed_at_unix_millis: i64,
    pub cause: WakeCause,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoalescedWake {
    pub session: WakeSessionKey,
    pub current_revision: u64,
    pub event_ids_in_precedence_order: Vec<String>,
}

/// Prepare one finite next-turn snapshot. Persist the original wake events
/// separately before scheduling; this function only creates the projection.
pub fn coalesce_wakes(events: &[WakeEvent]) -> Result<Option<CoalescedWake>, String> {
    let Some(first) = events.first() else {
        return Ok(None);
    };
    if events.iter().any(|event| event.session != first.session) {
        return Err("wake batch contains more than one logical role session".into());
    }
    let mut unique = BTreeMap::new();
    for event in events {
        if event.event_id.trim().is_empty() {
            return Err("wake event ID cannot be empty".into());
        }
        match unique.get(&event.event_id) {
            Some(previous) if previous != event => {
                return Err("wake event ID was reused with changed content".into());
            }
            Some(_) => {}
            None => {
                unique.insert(event.event_id.clone(), event.clone());
            }
        }
    }
    let mut unique: Vec<_> = unique.into_values().collect();
    unique.sort_by(|left, right| {
        left.cause
            .precedence()
            .cmp(&right.cause.precedence())
            .then_with(|| right.source_revision.cmp(&left.source_revision))
            .then_with(|| {
                left.observed_at_unix_millis
                    .cmp(&right.observed_at_unix_millis)
            })
            .then_with(|| left.event_id.cmp(&right.event_id))
    });
    let current_revision = unique
        .iter()
        .map(|event| event.source_revision)
        .max()
        .unwrap_or(0);
    Ok(Some(CoalescedWake {
        session: first.session.clone(),
        current_revision,
        event_ids_in_precedence_order: unique.into_iter().map(|event| event.event_id).collect(),
    }))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RoleRequest {
    CoordinatorPlanAccepted,
    CoordinatorAskPlanner,
    CoordinatorPrepareWorktrees,
    CoordinatorStartWorker,
    CoordinatorStartReviewer,
    CoordinatorStartMergeDecision,
    CoordinatorStartOperator,
    CoordinatorStartPostmortem,
    CoordinatorHumanRequest,
    PlannerSubmitPlan,
    PlannerRequestReadOnlyInvestigation,
    WorkerSubmitEvidence,
    WorkerReportIrregularity,
    ReviewerSubmitFindings,
    ReviewerRequestReadOnlyInvestigation,
    MergeDecisionSubmitAssessment,
    MergeDecisionRequestMerge,
    MergeDecisionRequestHuman,
    OperatorRequestDeclaredOperation,
    OperatorSubmitResult,
    PostmortemSubmitPublication,
    SupervisorProposeTicket,
    SupervisorDispatchTicket,
    SupervisorIntervene,
    SupervisorRequestHuman,
    SupervisorProposeGoalComplete,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorizedRequest {
    Transition(Input),
    SpawnRole(Role),
    /// A read-only investigation proposal; the Coordinator decides whether to
    /// consume one of its bounded child slots and launches it on the Agent's
    /// behalf. This request is not itself launch authority.
    RequestCoordinatorInvestigation,
    ReserveGoalTicket,
    QueueHumanRequest,
    RequestDeclaredMerge,
    RequestDeclaredOperation,
    ReportIrregularity,
    PublishKnowledge,
    SubmitPlan,
    SubmitWorkerEvidence,
    SubmitReview,
    SubmitMergeAssessment,
    SubmitOperationEvidence,
}

/// This is the controller's authority check; prompts are explanatory only.
pub fn authorize_role_request(
    role: Role,
    request: RoleRequest,
) -> Result<AuthorizedRequest, String> {
    use AuthorizedRequest as A;
    use RoleRequest as R;
    let authorized = match (role, request.clone()) {
        (Role::Coordinator, R::CoordinatorPlanAccepted) => A::Transition(Input::PlanAccepted),
        (Role::Coordinator, R::CoordinatorAskPlanner) => A::SpawnRole(Role::Planner),
        (Role::Coordinator, R::CoordinatorStartWorker) => A::SpawnRole(Role::Worker),
        (Role::Coordinator, R::CoordinatorStartReviewer) => A::SpawnRole(Role::Reviewer),
        (Role::Coordinator, R::CoordinatorStartMergeDecision) => A::SpawnRole(Role::MergeDecision),
        (Role::Coordinator, R::CoordinatorStartOperator) => A::SpawnRole(Role::Operator),
        (Role::Coordinator, R::CoordinatorStartPostmortem) => A::SpawnRole(Role::Postmortem),
        (Role::Coordinator, R::CoordinatorHumanRequest) => A::QueueHumanRequest,
        (Role::Planner, R::PlannerSubmitPlan) => A::SubmitPlan,
        (Role::Planner, R::PlannerRequestReadOnlyInvestigation) => {
            A::RequestCoordinatorInvestigation
        }
        (Role::Worker, R::WorkerSubmitEvidence) => A::SubmitWorkerEvidence,
        (Role::Worker, R::WorkerReportIrregularity) => A::ReportIrregularity,
        (Role::Reviewer, R::ReviewerSubmitFindings) => A::SubmitReview,
        (Role::Reviewer, R::ReviewerRequestReadOnlyInvestigation) => {
            A::RequestCoordinatorInvestigation
        }
        (Role::MergeDecision, R::MergeDecisionSubmitAssessment) => A::SubmitMergeAssessment,
        (Role::MergeDecision, R::MergeDecisionRequestMerge) => A::RequestDeclaredMerge,
        (Role::MergeDecision, R::MergeDecisionRequestHuman) => A::QueueHumanRequest,
        (Role::Operator, R::OperatorRequestDeclaredOperation) => A::RequestDeclaredOperation,
        (Role::Operator, R::OperatorSubmitResult) => A::SubmitOperationEvidence,
        (Role::Postmortem, R::PostmortemSubmitPublication) => A::PublishKnowledge,
        (Role::Supervisor, R::SupervisorProposeTicket) => A::ReserveGoalTicket,
        (Role::Supervisor, R::SupervisorDispatchTicket) => A::Transition(Input::Dispatch),
        (Role::Supervisor, R::SupervisorIntervene) => A::ReportIrregularity,
        (Role::Supervisor, R::SupervisorRequestHuman) => A::QueueHumanRequest,
        (Role::Supervisor, R::SupervisorProposeGoalComplete) => A::QueueHumanRequest,
        _ => return Err(format!("role {role:?} cannot issue request {request:?}")),
    };
    Ok(authorized)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IrregularitySeverity {
    Recoverable,
    High,
    Critical,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PauseScope {
    WorkNode,
    TicketRun,
    Project,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrregularityDecision {
    pub scope: PauseScope,
    pub fence_current_work: bool,
    pub notify: Vec<Role>,
    pub request_human: bool,
}

pub fn handle_irregularity(
    severity: IrregularitySeverity,
    can_safely_isolate_work_node: bool,
) -> IrregularityDecision {
    match severity {
        IrregularitySeverity::Recoverable if can_safely_isolate_work_node => IrregularityDecision {
            scope: PauseScope::WorkNode,
            fence_current_work: true,
            notify: vec![Role::Coordinator],
            request_human: false,
        },
        IrregularitySeverity::Recoverable => IrregularityDecision {
            scope: PauseScope::TicketRun,
            fence_current_work: true,
            notify: vec![Role::Coordinator],
            request_human: false,
        },
        IrregularitySeverity::High => IrregularityDecision {
            scope: PauseScope::TicketRun,
            fence_current_work: true,
            notify: vec![Role::Coordinator, Role::Supervisor],
            request_human: true,
        },
        IrregularitySeverity::Critical => IrregularityDecision {
            scope: PauseScope::Project,
            fence_current_work: true,
            notify: vec![Role::Coordinator, Role::Supervisor],
            request_human: true,
        },
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use serde_json::json;

    use super::*;
    use crate::config::{GoalConfig, OperationMatch};
    use crate::domain::ids::{AdapterId, TicketId};
    use crate::domain::types::RecipeStage;

    fn test_digest(value: char) -> Digest {
        Digest::parse(value.to_string().repeat(64)).unwrap()
    }

    fn worker_result_binding() -> RoleResultBinding {
        RoleResultBinding {
            agent_run_id: AgentRunId::parse("worker-run-1").unwrap(),
            operation_id: OperationId::parse("launch-1").unwrap(),
            project_id: ProjectId::parse("project-a").unwrap(),
            role_session_id: RoleSessionId::parse("worker-session").unwrap(),
            role: Role::Worker,
            parent_run_id: Some(AgentRunId::parse("coordinator-run-1").unwrap()),
            parent_role: Some(Role::Coordinator),
            ticket_run_id: Some(TicketRunId::parse("ticket-run-1").unwrap()),
            ticket_revision: Some(Revision(4)),
            config_revision: Revision(3),
            config_digest: test_digest('a'),
            profile_digest: test_digest('b'),
            instruction_digest: test_digest('c'),
            provider_capability_receipt_digest: test_digest('d'),
            result_schema_digest: test_digest('e'),
            controller_generation: 2,
            run_epoch: 5,
            attempt: 1,
        }
    }

    fn worker_result_submission(kind: RoleOutputKind, payload: Value) -> RoleResultSubmission {
        let encoded = serde_json::to_vec(&payload).unwrap();
        RoleResultSubmission {
            schema_version: ROLE_RESULT_SCHEMA_VERSION,
            message_id: "result-1".into(),
            binding: worker_result_binding(),
            kind,
            assertion: AgentAssertion::Succeeded,
            result_digest: Digest::parse(format!("{:x}", Sha256::digest(encoded))).unwrap(),
            structured_result: payload,
            artifact_refs: vec![],
        }
    }

    fn worker_implementation_ready_payload() -> Value {
        json!({
            "change_references": [{
                "repository": "repo-a",
                "worktree_id": "node-a",
                "commit_mode": "native",
                "base_commit": "0000000000000000000000000000000000000000",
                "previous_head": "1111111111111111111111111111111111111111",
                "branch_head": "2222222222222222222222222222222222222222",
                "commit_shas": ["2222222222222222222222222222222222222222"]
            }],
            "completed_acceptance_items": [],
            "unresolved_items": [],
            "irregularity_references": []
        })
    }

    fn worker_irregularity_payload() -> Value {
        json!({
            "severity": "high",
            "observed_facts": ["unexpected state"],
            "source_references": [],
            "affected_node_keys": [],
            "requested_pause_scope": "ticket_run",
            "proposed_options": ["pause and ask Coordinator"]
        })
    }

    fn valid_merge_assessment_payload() -> Value {
        let reference = json!({
            "kind": "merge_assessment",
            "artifact_id": "a".repeat(64),
            "schema_version": 1,
            "path": "evidence/gate.json",
            "digest": "a".repeat(64),
            "bytes": 20
        });
        json!({
            "pr_references": ["https://example.invalid/pr/1"],
            "subject_digest": "b".repeat(64),
            "deterministic_gate_evidence": [{
                "gate_id": "required-checks",
                "outcome": "pass",
                "evidence_references": [reference]
            }],
            "ratings": {
                "change_impact": {"rating": 1, "source": "diff", "rationale": "small", "evidence_references": [reference]},
                "complexity": {"rating": 1, "source": "diff", "rationale": "simple", "evidence_references": [reference]},
                "verification_gaps": {"rating": 1, "source": "checks", "rationale": "covered", "evidence_references": [reference]},
                "review_uncertainty": {"rating": 1, "source": "review", "rationale": "clear", "evidence_references": [reference]},
                "operational_exposure": {"rating": 1, "source": "policy", "rationale": "low", "evidence_references": [reference]}
            },
            "confidence": "high",
            "rationale": "all required evidence is present",
            "disposition": "merge"
        })
    }

    fn valid_role_payload_corpus() -> Vec<(RoleOutputKind, Value)> {
        let digest = "a".repeat(64);
        let commit = "1".repeat(40);
        let artifact = json!({
            "kind":"general", "artifact_id": "a".repeat(64), "schema_version":1, "path":"evidence/result.json",
            "digest":digest, "bytes":10
        });
        vec![
            (
                RoleOutputKind::Progress,
                json!({"summary":"working", "completed_node_keys":[], "pending_node_keys":[], "evidence":[], "next_observation_at":null}),
            ),
            (RoleOutputKind::Irregularity, worker_irregularity_payload()),
            (
                RoleOutputKind::HumanRequest,
                json!({"kind":"clarification", "question":"Which option?", "choices":["a"], "evidence_references":[], "subject_digest":digest, "requested_continuation":null}),
            ),
            (
                RoleOutputKind::TicketProposal,
                json!({"goal_revision":1, "gap_key":"gap-1", "title":"A ticket", "body":"Details", "acceptance":["condition"], "priority_rationale":"unblocks work", "parent":null, "dependencies":[]}),
            ),
            (
                RoleOutputKind::DispatchRequest,
                json!({"ticket_reference":"TICKET-1", "expected_ticket_revision":1, "coordinator_profile":"default", "priority":1, "rationale":"unblocks work"}),
            ),
            (
                RoleOutputKind::Intervention,
                json!({"coordinator_role_session_id":"coord-session_1", "ticket_run_revision":1, "reason":"need a decision", "evidence":[], "proposed_plan_change":"pause the node"}),
            ),
            (
                RoleOutputKind::SpawnRequest,
                json!({"work_node":"node-a", "role":"worker", "profile_id":"worker-default", "plan_digest":digest, "allowed_repositories":["repo-a"], "artifact_inputs":[], "parent_run_id":null}),
            ),
            (
                RoleOutputKind::InvestigationRequest,
                json!({"question":"Inspect dependency", "allowed_repositories":["repo-a"], "required_evidence":["read-only findings"], "parent_run_id":null}),
            ),
            (
                RoleOutputKind::PrepareWorktrees,
                json!({"accepted_plan_digest":digest, "worker_nodes":["node-a"]}),
            ),
            (
                RoleOutputKind::PlanReady,
                json!({"plan":{"nodes":[{"id":"node-a", "repository":"repo-a", "task":"implement acceptance", "depends_on":[], "required_evidence":[], "investigation":false}], "requested_investigation_children":0}, "unresolved_questions":[]}),
            ),
            (
                RoleOutputKind::ImplementationReady,
                worker_implementation_ready_payload(),
            ),
            (
                RoleOutputKind::ReviewReady,
                json!({"subject_kind":"patch", "subject_digest":digest, "findings":[], "evidence_coverage":["all acceptance items"], "disposition":"approved", "unknowns":[]}),
            ),
            (
                RoleOutputKind::MergeAssessment,
                valid_merge_assessment_payload(),
            ),
            (
                RoleOutputKind::MergeIntent,
                json!({"assessment_id":"assessment-1", "pr_identities":["repo-a#42"], "policy_digest":digest, "prepared_body_digest":digest, "steps":[{"kind":"direct_merge", "instruction_reference":"merge.instructions#merge", "rationale":"repository policy requires direct merge"}, {"kind":"verify_merge_commit", "instruction_reference":"merge.instructions#verify", "rationale":"confirm resulting commit"}], "post_merge_verification":[{"kind":"merge_commit_recorded", "instruction_reference":"merge.instructions#verify", "rationale":"ensure remote records the merge commit"}]}),
            ),
            (
                RoleOutputKind::OperationAction,
                json!({"operation_plan_digest":digest, "node_key":"node-a", "action_id":"deploy", "parameters":{}, "preconditions":[], "approval_receipt":"approved"}),
            ),
            (
                RoleOutputKind::OperationResult,
                json!({"node_key":"node-a", "outcome":"succeeded", "remote_receipt":{}, "source_commit":commit, "environment":"staging", "evidence_references":[]}),
            ),
            (
                RoleOutputKind::PostmortemReady,
                json!({"candidate_publication_manifest":{}, "findings":["improve test coverage"], "source_references":[artifact], "unresolved_provenance":[]}),
            ),
            (
                RoleOutputKind::LearningDecision,
                json!({"batch_id":"batch-1", "batch_digest":digest, "config_revision":1, "observations":[], "topic_changes":[], "checkpoint":{}, "improvements":[], "candidate_change":null}),
            ),
            (
                RoleOutputKind::ProfileTrialResult,
                json!({"candidate_digest":digest, "base_digest":digest, "authorization_receipt":"authorized", "run_ids":[], "frozen_inputs":[], "evidence_references":[artifact], "outcome":"effective"}),
            ),
            (
                RoleOutputKind::ProfilePromotionProposal,
                json!({"candidate_revision":1, "efficacy_outcome":"effective", "evidence_references":[artifact], "managed_slot":"project/worker", "profile_diff":{}, "expected_target_digests":{}, "uncertain_efficacy_exception":null}),
            ),
        ]
    }

    fn goal_project() -> ProjectConfig {
        ProjectConfig {
            mode: ProjectMode::Goal,
            ticket_adapter: AdapterId::parse("tickets").unwrap(),
            ticket_scope: BTreeMap::new(),
            dispatch_states: vec![TicketStatus::Ready],
            repositories: vec![RepositoryId::parse("repo-a").unwrap()],
            auto_merge: false,
            max_active_tickets: 2,
            max_created_tickets_per_goal_revision: 2,
            max_review_rounds: 2,
            max_investigation_children: 1,
            max_effect_retries: 1,
            goal: Some(GoalConfig {
                revision: 7,
                statement: "deliver".into(),
                acceptance: vec!["works".into()],
            }),
            roles: BTreeMap::new(),
            role_defaults_from: None,
            operation_matches: Vec::new(),
        }
    }

    fn operations_config() -> (Config, ProjectConfig) {
        let project = ProjectConfig {
            mode: ProjectMode::Operations,
            goal: None,
            operation_matches: vec![
                OperationMatch {
                    labels_all: vec!["docs".into()],
                    recipe: "docs_only".into(),
                },
                OperationMatch {
                    labels_all: vec!["service".into()],
                    recipe: "service".into(),
                },
            ],
            ..goal_project()
        };
        let mut config: Config =
            toml::from_str(include_str!("../../examples/fixture/config.toml")).unwrap();
        config.operation_recipes.insert(
            "docs_only".into(),
            OperationRecipe {
                roles: BTreeMap::new(),
                required_stages: vec![RecipeStage::Review],
                required_evidence: vec!["review".into()],
                targets: vec![],
                not_required_reason: Some("docs only".into()),
            },
        );
        config.operation_recipes.insert(
            "service".into(),
            OperationRecipe {
                roles: BTreeMap::new(),
                required_stages: vec![RecipeStage::Operations],
                required_evidence: vec!["deploy".into()],
                targets: vec![],
                not_required_reason: Some("skip explicitly".into()),
            },
        );
        (config, project)
    }

    #[test]
    fn goal_ticket_budget_is_reserved_before_create_and_survives_uncertainty() {
        let project_id = ProjectId::parse("project-a").unwrap();
        let project = goal_project();
        let budget = GoalCreationBudget {
            goal_revision: 7,
            reserved_attempts: 1,
            maximum_attempts: 10,
        };
        let gap = GoalGap {
            key: "api-migration".into(),
            title: "Migrate API".into(),
            body: "Implement the missing interface".into(),
            acceptance: vec!["contract tests pass".into()],
            parent: None,
            dependencies: vec![],
            priority_rationale: "blocks goal".into(),
        };
        let (next, intent) = reserve_goal_ticket(&project_id, &project, &budget, gap).unwrap();
        assert_eq!(next.reserved_attempts, 2);
        assert_eq!(intent.reserved_attempt_number, 2);
        assert_eq!(
            intent.stable_key,
            "rex-projects:project-a:goal:7:gap:9df20b60d1a7fb25b681a2e64af468340d6543741bb200bd64a196ae2dd2132a"
        );
        let exhausted = reserve_goal_ticket(
            &project_id,
            &project,
            &next,
            GoalGap {
                key: "another".into(),
                title: "Another".into(),
                body: "Body".into(),
                acceptance: vec!["done".into()],
                parent: None,
                dependencies: vec![],
                priority_rationale: "".into(),
            },
        );
        assert!(exhausted.is_err());
    }

    #[test]
    fn operations_recipe_ambiguity_and_missing_are_human_gated() {
        let (config, project) = operations_config();
        assert_eq!(
            select_operation_recipe(&config, &project, &BTreeSet::new()).decision,
            RecipeDecision::HumanRequiredNoMatch
        );
        assert_eq!(
            select_operation_recipe(&config, &project, &BTreeSet::from(["docs".into()])).decision,
            RecipeDecision::Selected
        );
        assert_eq!(
            select_operation_recipe(
                &config,
                &project,
                &BTreeSet::from(["docs".into(), "service".into()])
            )
            .decision,
            RecipeDecision::HumanRequiredAmbiguous
        );
    }

    #[test]
    fn duplicate_resolution_is_stable_and_never_discards_active_work() {
        let a = TicketId::parse("external-A").unwrap();
        let b = TicketId::parse("external-B").unwrap();
        let candidates = vec![
            GoalTicketObservation {
                id: a.clone(),
                created_at_unix_millis: 1767225601000,
                active_run: false,
                substantive_work: false,
            },
            GoalTicketObservation {
                id: b.clone(),
                created_at_unix_millis: 1767225602000,
                active_run: false,
                substantive_work: false,
            },
        ];
        assert_eq!(
            resolve_goal_duplicates(&candidates, None),
            DuplicateResolution::Canonical {
                ticket_id: a.clone(),
                annotate_and_cancel: vec![b.clone()]
            }
        );
        assert_eq!(
            resolve_goal_duplicates(&candidates, Some(&b)),
            DuplicateResolution::Canonical {
                ticket_id: b.clone(),
                annotate_and_cancel: vec![a]
            }
        );
        let active = vec![
            candidates[0].clone(),
            GoalTicketObservation {
                id: TicketId::parse("external-C").unwrap(),
                active_run: true,
                ..candidates[1].clone()
            },
        ];
        assert!(matches!(
            resolve_goal_duplicates(&active, None),
            DuplicateResolution::HumanRequired { .. }
        ));
        assert_eq!(
            resolve_goal_duplicates(&[], Some(&b)),
            DuplicateResolution::Canonical {
                ticket_id: b,
                annotate_and_cancel: vec![]
            }
        );
    }

    #[test]
    fn work_plan_deserialization_rejects_invalid_work_node_ids() {
        let template = serde_json::json!({
            "nodes": [{
                "id": "valid-node",
                "repository": "repo-a",
                "task": "implement feature",
                "depends_on": [],
                "required_evidence": ["tests"],
                "investigation": false
            }],
            "requested_investigation_children": 0
        });
        let oversized = "x".repeat(81);
        for invalid in [
            "../outside",
            "folder/node",
            "bad\u{0007}id",
            oversized.as_str(),
        ] {
            let mut value = template.clone();
            value["nodes"][0]["id"] = serde_json::Value::String(invalid.into());
            assert!(
                serde_json::from_value::<WorkPlan>(value).is_err(),
                "accepted invalid work node ID {invalid:?}"
            );
        }
    }

    #[test]
    fn duplicate_observations_merge_conservatively_and_ignore_input_order() {
        let canonical = GoalTicketObservation {
            id: TicketId::parse("canonical").unwrap(),
            created_at_unix_millis: 1,
            active_run: false,
            substantive_work: false,
        };
        let stale_duplicate = GoalTicketObservation {
            id: TicketId::parse("duplicate").unwrap(),
            created_at_unix_millis: 2,
            active_run: false,
            substantive_work: false,
        };
        let current_duplicate = GoalTicketObservation {
            active_run: true,
            substantive_work: true,
            ..stale_duplicate.clone()
        };
        let stale_then_current = vec![
            canonical.clone(),
            stale_duplicate.clone(),
            current_duplicate.clone(),
        ];
        let current_then_stale = vec![canonical, current_duplicate, stale_duplicate];
        let forward = resolve_goal_duplicates(&stale_then_current, None);
        let reverse = resolve_goal_duplicates(&current_then_stale, None);
        assert_eq!(forward, reverse);
        assert!(matches!(
            forward,
            DuplicateResolution::HumanRequired { candidates, .. }
                if candidates == vec![
                    TicketId::parse("canonical").unwrap(),
                    TicketId::parse("duplicate").unwrap()
                ]
        ));
    }

    #[test]
    fn conflicting_creation_timestamps_require_human_without_cancellation() {
        let id = TicketId::parse("duplicate").unwrap();
        let observations = [
            GoalTicketObservation {
                id: id.clone(),
                created_at_unix_millis: 2,
                active_run: false,
                substantive_work: false,
            },
            GoalTicketObservation {
                created_at_unix_millis: 3,
                ..GoalTicketObservation {
                    id: id.clone(),
                    created_at_unix_millis: 2,
                    active_run: false,
                    substantive_work: false,
                }
            },
        ];
        let forward = resolve_goal_duplicates(&observations, None);
        let reverse =
            resolve_goal_duplicates(&observations.into_iter().rev().collect::<Vec<_>>(), None);
        assert_eq!(forward, reverse);
        assert!(matches!(
            forward,
            DuplicateResolution::HumanRequired { candidates, reason }
                if candidates == vec![id] && reason.contains("creation timestamps")
        ));
    }

    #[test]
    fn multi_repository_plan_is_acyclic_and_only_worker_can_implement() {
        let project = goal_project();
        let repo_a = RepositoryId::parse("repo-a").unwrap();
        let repo_b = RepositoryId::parse("repo-b").unwrap();
        let mut project = project;
        project.repositories.push(repo_b.clone());
        let base = "0123456789abcdef0123456789abcdef01234567".to_owned();
        let plan = WorkPlan {
            nodes: vec![
                PlannedWorkNode {
                    id: WorkNodeId::parse("api").unwrap(),
                    repository: repo_a.clone(),
                    task: "update API".into(),
                    depends_on: vec![],
                    required_evidence: vec!["tests".into()],
                    investigation: false,
                },
                PlannedWorkNode {
                    id: WorkNodeId::parse("docs").unwrap(),
                    repository: repo_b.clone(),
                    task: "update docs".into(),
                    depends_on: vec![WorkDependency {
                        node: WorkNodeId::parse("api").unwrap(),
                        kind: WorkDependencyKind::Delivery,
                        affected_evidence: BTreeSet::from(["tests".into(), "review".into()]),
                    }],
                    required_evidence: vec!["docs check".into()],
                    investigation: false,
                },
                PlannedWorkNode {
                    id: WorkNodeId::parse("api-integration").unwrap(),
                    repository: repo_a.clone(),
                    task: "integrate the API branch".into(),
                    depends_on: vec![WorkDependency {
                        node: WorkNodeId::parse("api").unwrap(),
                        kind: WorkDependencyKind::GitBase,
                        affected_evidence: BTreeSet::from(["tests".into(), "review".into()]),
                    }],
                    required_evidence: vec!["integration tests".into()],
                    investigation: false,
                },
            ],
            requested_investigation_children: 0,
        };
        let bases = BTreeMap::from([
            (repo_a.clone(), base.clone()),
            (repo_b.clone(), base.clone()),
        ]);
        let result = validate_work_plan(
            &TicketRunId::parse("run-1").unwrap(),
            &project,
            plan.clone(),
            &bases,
        )
        .unwrap();
        assert_eq!(result.nodes_in_execution_order[0].id.as_str(), "api");
        assert_eq!(result.nodes_in_execution_order[0].role, Role::Worker);
        assert_eq!(
            result.nodes_in_execution_order[1].id.as_str(),
            "api-integration"
        );
        assert_eq!(
            result.nodes_in_execution_order[1].base,
            WorkBaseSource::PredecessorWorkNodeHead {
                node: WorkNodeId::parse("api").unwrap()
            }
        );
        assert_eq!(result.nodes_in_execution_order[2].role, Role::Worker);
        let mut cyclic = plan;
        cyclic.nodes[0].depends_on.push(WorkDependency {
            node: WorkNodeId::parse("docs").unwrap(),
            kind: WorkDependencyKind::Delivery,
            affected_evidence: BTreeSet::from(["integration".into()]),
        });
        assert!(
            validate_work_plan(
                &TicketRunId::parse("run-1").unwrap(),
                &project,
                cyclic,
                &bases
            )
            .is_err()
        );
    }

    #[test]
    fn review_iterations_stop_at_the_configured_bound() {
        assert_eq!(
            review_disposition(
                ReviewProgress {
                    completed_rounds: 0,
                    maximum_rounds: 2
                },
                true
            )
            .unwrap(),
            ReviewDisposition::StartCorrectionWorker
        );
        assert_eq!(
            review_disposition(
                ReviewProgress {
                    completed_rounds: 2,
                    maximum_rounds: 2
                },
                true
            )
            .unwrap(),
            ReviewDisposition::HumanRequiredAtRoundLimit
        );
        assert_eq!(
            review_disposition(
                ReviewProgress {
                    completed_rounds: 2,
                    maximum_rounds: 2
                },
                false
            )
            .unwrap(),
            ReviewDisposition::StartMergeDecision
        );
    }

    #[test]
    fn coordinator_cannot_submit_a_worker_result_and_worker_cannot_publish() {
        assert!(
            authorize_role_request(Role::Coordinator, RoleRequest::WorkerSubmitEvidence).is_err()
        );
        assert!(
            authorize_role_request(Role::Worker, RoleRequest::SupervisorProposeTicket).is_err()
        );
        assert!(
            authorize_role_request(Role::Worker, RoleRequest::MergeDecisionRequestMerge).is_err()
        );
        assert!(
            authorize_role_request(Role::Coordinator, RoleRequest::CoordinatorStartWorker).is_ok()
        );
    }

    #[test]
    fn only_coordinator_can_launch_work_and_investigation_requests_are_proposals() {
        assert_eq!(
            authorize_role_request(Role::Coordinator, RoleRequest::CoordinatorStartWorker).unwrap(),
            AuthorizedRequest::SpawnRole(Role::Worker)
        );
        assert_eq!(
            authorize_role_request(Role::Coordinator, RoleRequest::CoordinatorAskPlanner).unwrap(),
            AuthorizedRequest::SpawnRole(Role::Planner)
        );
        assert_eq!(
            authorize_role_request(
                Role::Planner,
                RoleRequest::PlannerRequestReadOnlyInvestigation
            )
            .unwrap(),
            AuthorizedRequest::RequestCoordinatorInvestigation
        );
        assert_eq!(
            authorize_role_request(
                Role::Reviewer,
                RoleRequest::ReviewerRequestReadOnlyInvestigation
            )
            .unwrap(),
            AuthorizedRequest::RequestCoordinatorInvestigation
        );
        assert!(
            authorize_role_request(Role::Planner, RoleRequest::CoordinatorStartWorker).is_err()
        );
    }

    #[test]
    fn dispatch_only_uses_configured_ready_state_and_deduplicates_by_active_claim() {
        let project = goal_project();
        assert!(matches!(
            dispatch_decision(&project, TicketStatus::Ready, false, true),
            DispatchDecision::Dispatch { .. }
        ));
        assert!(matches!(
            dispatch_decision(&project, TicketStatus::Triage, false, true),
            DispatchDecision::Ignore { .. }
        ));
        assert!(matches!(
            dispatch_decision(&project, TicketStatus::Ready, true, true),
            DispatchDecision::Ignore {
                reason: DispatchIgnore::ExistingRunOwnsTicket
            }
        ));
        assert!(matches!(
            dispatch_decision(&project, TicketStatus::Ready, false, false),
            DispatchDecision::Ignore {
                reason: DispatchIgnore::ProjectPausedOrStopped
            }
        ));
    }

    #[test]
    fn a_previously_selected_canonical_survives_an_incomplete_search_page() {
        let old = TicketId::parse("canonical-old").unwrap();
        let late_duplicate = GoalTicketObservation {
            id: TicketId::parse("duplicate-late").unwrap(),
            created_at_unix_millis: 1767225602000,
            active_run: false,
            substantive_work: false,
        };
        assert_eq!(
            resolve_goal_duplicates(std::slice::from_ref(&late_duplicate), Some(&old)),
            DuplicateResolution::Canonical {
                ticket_id: old,
                annotate_and_cancel: vec![late_duplicate.id],
            }
        );
    }

    #[test]
    fn goal_completion_always_waits_for_human_confirmation() {
        let project = goal_project();
        let evidence = GoalCompletionEvidence {
            satisfied_acceptance: vec!["api".into()],
            incomplete_ticket_ids: vec![],
            deferred_risks: vec![],
            operation_results: vec!["deployed".into()],
            subject_digest: crate::domain::ids::Digest::parse("a".repeat(64)).unwrap(),
        };
        assert!(matches!(
            propose_goal_completion(
                &project,
                evidence.clone(),
                &BTreeSet::from(["api".into()]),
                0
            ),
            GoalCompletionDecision::RequestHumanConfirmation { .. }
        ));
        assert!(matches!(
            propose_goal_completion(&project, evidence, &BTreeSet::from(["api".into()]), 1),
            GoalCompletionDecision::NotSatisfied { .. }
        ));
    }

    #[test]
    fn wake_coalescing_preserves_all_ids_and_orders_stop_before_human_before_observation() {
        let session = WakeSessionKey {
            project_id: ProjectId::parse("project-a").unwrap(),
            ticket_run_id: Some(TicketRunId::parse("run-1").unwrap()),
            role: Role::Coordinator,
        };
        let events = vec![
            WakeEvent {
                event_id: "observation".into(),
                session: session.clone(),
                source_revision: 3,
                observed_at_unix_millis: 30,
                cause: WakeCause::ExternalObservation,
            },
            WakeEvent {
                event_id: "human".into(),
                session: session.clone(),
                source_revision: 2,
                observed_at_unix_millis: 20,
                cause: WakeCause::HumanResponse,
            },
            WakeEvent {
                event_id: "fence".into(),
                session: session.clone(),
                source_revision: 1,
                observed_at_unix_millis: 10,
                cause: WakeCause::StopOrPolicyFence,
            },
            WakeEvent {
                event_id: "human".into(),
                session,
                source_revision: 2,
                observed_at_unix_millis: 20,
                cause: WakeCause::HumanResponse,
            },
        ];
        let coalesced = coalesce_wakes(&events).unwrap().unwrap();
        assert_eq!(coalesced.current_revision, 3);
        assert_eq!(
            coalesced.event_ids_in_precedence_order,
            vec!["fence", "human", "observation"]
        );
    }

    #[test]
    fn intervention_is_revision_bound_and_routes_via_coordinator() {
        let intervention = HumanIntervention {
            project_id: ProjectId::parse("project-a").unwrap(),
            ticket_run_id: TicketRunId::parse("run-1").unwrap(),
            expected_revision: 4,
            message: "Use the narrower migration plan".into(),
            fence_active_work: true,
        };
        assert!(route_human_intervention(&intervention, 3).is_err());
        assert_eq!(
            route_human_intervention(&intervention, 4).unwrap(),
            InterventionRoute {
                target: Role::Coordinator,
                notify: Role::Supervisor,
                fence_active_work: true,
            }
        );
    }

    #[test]
    fn planner_is_optional_for_routine_work_and_required_for_complexity_only_when_configured() {
        let mut project = goal_project();
        assert_eq!(
            select_planner(&project, PlanComplexity::Routine),
            PlannerSelection::CoordinatorPlansDirectly
        );
        assert_eq!(
            select_planner(&project, PlanComplexity::Complex),
            PlannerSelection::CoordinatorPlansDirectly
        );
        project.roles.insert(
            Role::Planner,
            crate::domain::ids::ProfileId::parse("planner").unwrap(),
        );
        assert_eq!(
            select_planner(&project, PlanComplexity::Complex),
            PlannerSelection::LaunchPlanner {
                profile_id: crate::domain::ids::ProfileId::parse("planner").unwrap()
            }
        );
        assert_eq!(
            select_planner(&project, PlanComplexity::Uncertain),
            PlannerSelection::HumanClarificationRequired
        );
    }

    #[test]
    fn role_result_is_bound_to_run_and_routes_only_to_trusted_parent() {
        let binding = worker_result_binding();
        let validated = validate_role_result(
            &binding,
            worker_result_submission(
                RoleOutputKind::ImplementationReady,
                worker_implementation_ready_payload(),
            ),
        )
        .unwrap();
        assert_eq!(validated.binding, binding);
        assert_eq!(validated.assertion, AgentAssertion::Succeeded);
        assert_eq!(
            validated.wake_recipients,
            vec![WakeSessionKey {
                project_id: ProjectId::parse("project-a").unwrap(),
                ticket_run_id: Some(TicketRunId::parse("ticket-run-1").unwrap()),
                role: Role::Coordinator,
            }]
        );

        let mut stale = worker_result_submission(
            RoleOutputKind::ImplementationReady,
            worker_implementation_ready_payload(),
        );
        stale.binding.ticket_revision = Some(Revision(3));
        assert!(validate_role_result(&binding, stale).is_err());
    }

    #[test]
    fn implementation_ready_rejects_empty_and_inconsistent_change_payloads() {
        let binding = worker_result_binding();
        assert!(
            validate_role_result(
                &binding,
                worker_result_submission(RoleOutputKind::ImplementationReady, json!({})),
            )
            .is_err()
        );

        let mut payload = worker_implementation_ready_payload();
        payload["change_references"][0]["branch_head"] =
            json!("3333333333333333333333333333333333333333");
        assert!(
            validate_role_result(
                &binding,
                worker_result_submission(RoleOutputKind::ImplementationReady, payload),
            )
            .is_err()
        );

        let schema = role_result_payload_schema(RoleOutputKind::ImplementationReady);
        assert_eq!(schema["additionalProperties"], json!(false));
        let required: BTreeSet<_> = schema["required"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(required.contains("change_references"));
        assert!(required.contains("completed_acceptance_items"));
        assert!(required.contains("unresolved_items"));
    }

    #[test]
    fn merge_assessment_requires_actual_pr_gate_and_decision_evidence() {
        let digest = "a".repeat(64);
        let reference = json!({
            "kind": "merge_assessment",
            "artifact_id": "a".repeat(64),
            "schema_version": 1,
            "path": "evidence/gate.json",
            "digest": digest,
            "bytes": 20
        });
        let mut valid = json!({
            "pr_references": ["https://example.invalid/pr/1"],
            "subject_digest": "b".repeat(64),
            "deterministic_gate_evidence": [{
                "gate_id": "required-checks",
                "outcome": "pass",
                "evidence_references": [reference]
            }],
            "ratings": {
                "change_impact": {"rating": 1, "source": "diff", "rationale": "small", "evidence_references": [reference]},
                "complexity": {"rating": 1, "source": "diff", "rationale": "simple", "evidence_references": [reference]},
                "verification_gaps": {"rating": 1, "source": "checks", "rationale": "covered", "evidence_references": [reference]},
                "review_uncertainty": {"rating": 1, "source": "review", "rationale": "clear", "evidence_references": [reference]},
                "operational_exposure": {"rating": 1, "source": "policy", "rationale": "low", "evidence_references": [reference]}
            },
            "confidence": "high",
            "rationale": "all required evidence is present",
            "disposition": "merge"
        });
        let payload: MergeAssessmentPayload = serde_json::from_value(valid.clone()).unwrap();
        validate_role_payload(&RoleResultPayload::MergeAssessment(payload)).unwrap();

        for (path, empty) in [
            ("pr_references", json!([])),
            ("deterministic_gate_evidence", json!([])),
            ("rationale", json!("  ")),
            ("disposition", json!("")),
        ] {
            let before = valid[path].clone();
            valid[path] = empty;
            let payload: MergeAssessmentPayload = serde_json::from_value(valid.clone()).unwrap();
            assert!(
                validate_role_payload(&RoleResultPayload::MergeAssessment(payload)).is_err(),
                "{path}"
            );
            valid[path] = before;
        }
    }

    #[test]
    fn merge_intent_is_a_typed_advisory_procedure_with_a_terminal_verification() {
        let valid = json!({
            "assessment_id": "assessment-1",
            "pr_identities": ["repo-a#42"],
            "policy_digest": "a".repeat(64),
            "prepared_body_digest": "b".repeat(64),
            "steps": [
                {"kind":"update_pull_request_body", "instruction_reference":"merge.instructions#body", "rationale":"add required trailer"},
                {"kind":"request_merge", "instruction_reference":"merge.instructions#request", "rationale":"repository requires a merge request"},
                {"kind":"verify_merge_commit", "instruction_reference":"merge.instructions#verify", "rationale":"confirm resulting commit"}
            ],
            "post_merge_verification": [
                {"kind":"merge_commit_recorded", "instruction_reference":"merge.instructions#verify", "rationale":"ensure remote records the merge commit"}
            ]
        });
        let payload: MergeIntentPayload = serde_json::from_value(valid.clone()).unwrap();
        validate_role_payload(&RoleResultPayload::MergeIntent(payload)).unwrap();

        let mut invalid = valid;
        invalid["steps"][1]["kind"] = json!("run_shell_command");
        assert!(serde_json::from_value::<MergeIntentPayload>(invalid).is_err());

        let mut out_of_order: MergeIntentPayload = serde_json::from_value(json!({
            "assessment_id":"assessment-1",
            "pr_identities":["repo-a#42"],
            "policy_digest":"a".repeat(64),
            "prepared_body_digest":"b".repeat(64),
            "steps":[
                {"kind":"direct_merge","instruction_reference":"policy#merge","rationale":"execute"},
                {"kind":"update_pull_request_body","instruction_reference":"policy#body","rationale":"write trailer"},
                {"kind":"verify_merge_commit","instruction_reference":"policy#verify","rationale":"check result"}
            ],
            "post_merge_verification":[{"kind":"merge_commit_recorded","instruction_reference":"policy#verify","rationale":"check record"}]
        })).unwrap();
        assert!(
            validate_role_payload(&RoleResultPayload::MergeIntent(out_of_order.clone())).is_err()
        );
        out_of_order.steps.swap(0, 1);
        validate_role_payload(&RoleResultPayload::MergeIntent(out_of_order)).unwrap();

        let mut missing_final_verify: MergeIntentPayload =
            serde_json::from_value(json!({
                "assessment_id":"assessment-1",
                "pr_identities":["repo-a#42"],
                "policy_digest":"a".repeat(64),
                "prepared_body_digest":"b".repeat(64),
                "steps":[{"kind":"direct_merge","instruction_reference":"policy#merge","rationale":"policy"}],
                "post_merge_verification":[{"kind":"merge_commit_recorded","instruction_reference":"policy#verify","rationale":"check the result"}]
            })).unwrap();
        assert!(
            validate_role_payload(&RoleResultPayload::MergeIntent(
                missing_final_verify.clone()
            ))
            .is_err()
        );

        missing_final_verify.steps.push(MergeProcedureStep {
            kind: MergeProcedureStepKind::VerifyMergeCommit,
            instruction_reference: "policy#verify".into(),
            rationale: "check the resulting commit".into(),
        });
        validate_role_payload(&RoleResultPayload::MergeIntent(missing_final_verify)).unwrap();
    }

    #[test]
    fn nested_artifact_references_must_be_declared_and_remain_unverified_claims() {
        let artifact = RoleArtifactReference {
            artifact_id: ArtifactId::parse("f".repeat(64)).unwrap(),
            kind: RoleArtifactKind::General,
            schema_version: 1,
            path: "evidence/observation.json".into(),
            digest: test_digest('f'),
            bytes: 10,
        };
        let mut payload = worker_implementation_ready_payload();
        payload["irregularity_references"] = json!([artifact]);
        let mut submission = worker_result_submission(RoleOutputKind::ImplementationReady, payload);
        let binding = worker_result_binding();
        assert!(validate_role_result(&binding, submission.clone()).is_err());

        submission.artifact_refs.push(artifact.clone());
        let validated = validate_role_result(&binding, submission).unwrap();
        assert_eq!(validated.claimed_artifact_refs, vec![artifact]);
    }

    #[test]
    fn every_role_output_has_a_bounded_closed_generated_schema() {
        let kinds = [
            RoleOutputKind::Progress,
            RoleOutputKind::Irregularity,
            RoleOutputKind::HumanRequest,
            RoleOutputKind::TicketProposal,
            RoleOutputKind::DispatchRequest,
            RoleOutputKind::Intervention,
            RoleOutputKind::SpawnRequest,
            RoleOutputKind::InvestigationRequest,
            RoleOutputKind::PrepareWorktrees,
            RoleOutputKind::PlanReady,
            RoleOutputKind::ImplementationReady,
            RoleOutputKind::ReviewReady,
            RoleOutputKind::MergeAssessment,
            RoleOutputKind::MergeIntent,
            RoleOutputKind::OperationAction,
            RoleOutputKind::OperationResult,
            RoleOutputKind::PostmortemReady,
            RoleOutputKind::LearningDecision,
            RoleOutputKind::ProfileTrialResult,
            RoleOutputKind::ProfilePromotionProposal,
        ];
        for kind in kinds {
            let schema = role_result_payload_schema(kind);
            assert_eq!(schema["type"], json!("object"), "{kind:?}");
            assert_eq!(schema["additionalProperties"], json!(false), "{kind:?}");
            assert!(
                !schema["required"].as_array().unwrap().is_empty(),
                "{kind:?}"
            );
            assert!(
                serde_json::to_vec(&schema).unwrap().len() < 256 * 1024,
                "{kind:?}"
            );
            jsonschema::options()
                .offline()
                .build(&schema)
                .unwrap_or_else(|error| panic!("{kind:?}: generated schema is invalid: {error}"));
        }
        for role in [
            Role::Supervisor,
            Role::Coordinator,
            Role::Planner,
            Role::Worker,
            Role::Reviewer,
            Role::MergeDecision,
            Role::Operator,
            Role::Postmortem,
        ] {
            for kind in allowed_role_output_kinds(role) {
                jsonschema::options()
                    .offline()
                    .build(&role_result_payload_schema(kind))
                    .unwrap_or_else(|error| panic!("{role:?}/{kind:?}: {error}"));
            }
        }
        for (kind, value) in valid_role_payload_corpus() {
            let schema = role_result_payload_schema(kind);
            let validator = jsonschema::options()
                .offline()
                .build(&schema)
                .unwrap_or_else(|error| panic!("{kind:?}: {error}"));
            assert!(
                validator.is_valid(&value),
                "valid {kind:?} payload: {value}"
            );
            let typed = RoleResultPayload::parse(kind, value).unwrap();
            validate_role_payload(&typed).unwrap();
        }
    }

    #[test]
    fn generated_payload_schema_constrains_domain_string_identifiers() {
        let schema = role_result_payload_schema(RoleOutputKind::ImplementationReady);
        let encoded = schema.to_string();
        assert!(encoded.contains("WorkNodeId"));
        assert!(encoded.contains(r"^[A-Za-z0-9._-]+$"));
        assert!(encoded.contains(r"^(?:[a-f0-9]{40}|[a-f0-9]{64})$"));
        assert!(encoded.contains(r"^[a-f0-9]{64}$"));
    }

    #[test]
    fn generated_role_schemas_reject_parser_invalid_values_offline() {
        fn schema_accepts(kind: RoleOutputKind, value: &Value) -> bool {
            let schema = role_result_payload_schema(kind);
            jsonschema::options()
                .offline()
                .build(&schema)
                .expect("generated role payload schema is valid")
                .is_valid(value)
        }

        let valid_change = worker_implementation_ready_payload();
        assert!(schema_accepts(
            RoleOutputKind::ImplementationReady,
            &valid_change
        ));

        let mut invalid_commit = valid_change.clone();
        invalid_commit["change_references"][0]["branch_head"] = json!("not-a-sha");
        assert!(!schema_accepts(
            RoleOutputKind::ImplementationReady,
            &invalid_commit
        ));
        let mut invalid_node = valid_change.clone();
        invalid_node["change_references"][0]["worktree_id"] = json!("../outside");
        assert!(!schema_accepts(
            RoleOutputKind::ImplementationReady,
            &invalid_node
        ));
        let mut invalid_repository = valid_change.clone();
        invalid_repository["change_references"][0]["repository"] = json!("bad/id");
        assert!(!schema_accepts(
            RoleOutputKind::ImplementationReady,
            &invalid_repository
        ));

        let mut with_artifact = valid_change.clone();
        with_artifact["irregularity_references"] = json!([{
            "kind":"general", "artifact_id":"a".repeat(64), "schema_version":1, "path":"evidence/change.json",
            "digest":"a".repeat(64), "bytes":10
        }]);
        assert!(schema_accepts(
            RoleOutputKind::ImplementationReady,
            &with_artifact
        ));
        for invalid_path in [
            "1:/outside",
            ".:/outside",
            "-:/outside",
            "é:/outside",
            "💥:/outside",
        ] {
            with_artifact["irregularity_references"][0]["path"] = json!(invalid_path);
            assert!(!schema_accepts(
                RoleOutputKind::ImplementationReady,
                &with_artifact
            ));
        }
        with_artifact["irregularity_references"][0]["path"] = json!("🍃".repeat(1100));
        assert!(!schema_accepts(
            RoleOutputKind::ImplementationReady,
            &with_artifact
        ));
        with_artifact["irregularity_references"][0]["path"] = json!("../outside");
        assert!(!schema_accepts(
            RoleOutputKind::ImplementationReady,
            &with_artifact
        ));
        with_artifact["irregularity_references"][0]["path"] = json!("C:/outside");
        assert!(!schema_accepts(
            RoleOutputKind::ImplementationReady,
            &with_artifact
        ));
        with_artifact["irregularity_references"][0]["path"] = json!("evidence/...");
        assert!(schema_accepts(
            RoleOutputKind::ImplementationReady,
            &with_artifact
        ));
        with_artifact["irregularity_references"][0]["schema_version"] = json!(0);
        assert!(!schema_accepts(
            RoleOutputKind::ImplementationReady,
            &with_artifact
        ));
        with_artifact["irregularity_references"][0]["schema_version"] = json!(1);
        with_artifact["irregularity_references"][0]["path"] = json!("evidence/\u{0085}bad");
        assert!(!schema_accepts(
            RoleOutputKind::ImplementationReady,
            &with_artifact
        ));
        with_artifact["irregularity_references"][0]["path"] = json!("evidence/change.json");
        with_artifact["irregularity_references"][0]["artifact_id"] = json!("A".repeat(64));
        assert!(!schema_accepts(
            RoleOutputKind::ImplementationReady,
            &with_artifact
        ));
        with_artifact["irregularity_references"][0]["artifact_id"] = json!("a".repeat(64));
        with_artifact["irregularity_references"][0]
            .as_object_mut()
            .unwrap()
            .remove("artifact_id");
        assert!(!schema_accepts(
            RoleOutputKind::ImplementationReady,
            &with_artifact
        ));
        assert!(
            serde_json::from_value::<RoleArtifactReference>(
                with_artifact["irregularity_references"][0].clone()
            )
            .is_err()
        );

        let mut intervention = json!({
            "coordinator_role_session_id":"coord-session_1",
            "ticket_run_revision":1,
            "reason":"need a decision",
            "evidence":[],
            "proposed_plan_change":"pause the dependent node"
        });
        assert!(schema_accepts(RoleOutputKind::Intervention, &intervention));
        intervention["coordinator_role_session_id"] = json!("../session");
        assert!(!schema_accepts(RoleOutputKind::Intervention, &intervention));

        let mut ticket_proposal = json!({
            "goal_revision":1,
            "gap_key":"gap-1",
            "title":"Complete the requested goal",
            "body":"Details",
            "acceptance":["condition"],
            "priority_rationale":"unblocks work",
            "parent":null,
            "dependencies":[]
        });
        assert!(schema_accepts(
            RoleOutputKind::TicketProposal,
            &ticket_proposal
        ));
        ticket_proposal["parent"] = json!("\u{0085}");
        assert!(!schema_accepts(
            RoleOutputKind::TicketProposal,
            &ticket_proposal
        ));

        let mut merge_assessment = valid_merge_assessment_payload();
        assert!(schema_accepts(
            RoleOutputKind::MergeAssessment,
            &merge_assessment
        ));
        merge_assessment["pr_references"] = json!([]);
        assert!(!schema_accepts(
            RoleOutputKind::MergeAssessment,
            &merge_assessment
        ));
        let mut over_rating = valid_merge_assessment_payload();
        over_rating["ratings"]["complexity"]["rating"] = json!(5);
        assert!(!schema_accepts(
            RoleOutputKind::MergeAssessment,
            &over_rating
        ));
        let mut incomplete_dimensions = valid_merge_assessment_payload();
        incomplete_dimensions["ratings"]
            .as_object_mut()
            .unwrap()
            .remove("complexity");
        assert!(!schema_accepts(
            RoleOutputKind::MergeAssessment,
            &incomplete_dimensions
        ));
        let mut whitespace_pr = valid_merge_assessment_payload();
        whitespace_pr["pr_references"][0] = json!(" \t ");
        assert!(!schema_accepts(
            RoleOutputKind::MergeAssessment,
            &whitespace_pr
        ));
        let typed =
            RoleResultPayload::parse(RoleOutputKind::MergeAssessment, whitespace_pr).unwrap();
        assert!(validate_role_payload(&typed).is_err());

        let mut whitespace_step: Value = valid_role_payload_corpus()
            .into_iter()
            .find_map(|(kind, value)| (kind == RoleOutputKind::MergeIntent).then_some(value))
            .unwrap();
        whitespace_step["steps"][0]["rationale"] = json!("merge\naccording to repository policy");
        assert!(schema_accepts(
            RoleOutputKind::MergeIntent,
            &whitespace_step
        ));
        whitespace_step["steps"][0]["rationale"] = json!(" \n\t ");
        assert!(!schema_accepts(
            RoleOutputKind::MergeIntent,
            &whitespace_step
        ));
        let typed =
            RoleResultPayload::parse(RoleOutputKind::MergeIntent, whitespace_step.clone()).unwrap();
        assert!(validate_role_payload(&typed).is_err());
        whitespace_step["steps"][0]["rationale"] = json!("merge\naccording to repository policy");
        whitespace_step["steps"][0]["instruction_reference"] = json!("   ");
        assert!(!schema_accepts(
            RoleOutputKind::MergeIntent,
            &whitespace_step
        ));
        let typed = RoleResultPayload::parse(RoleOutputKind::MergeIntent, whitespace_step).unwrap();
        assert!(validate_role_payload(&typed).is_err());
    }

    #[test]
    fn worker_result_cannot_bypass_coordinator_through_planner_or_reviewer_parent() {
        for parent_role in [Role::Planner, Role::Reviewer] {
            let mut binding = worker_result_binding();
            binding.parent_role = Some(parent_role);
            let mut submission = worker_result_submission(
                RoleOutputKind::ImplementationReady,
                worker_implementation_ready_payload(),
            );
            submission.binding = binding.clone();
            assert!(validate_role_result(&binding, submission).is_err());
        }
    }

    #[test]
    fn result_assertions_cannot_claim_host_effects_or_choose_a_wake_target() {
        let submission = worker_result_submission(
            RoleOutputKind::ImplementationReady,
            worker_implementation_ready_payload(),
        );
        let mut value = serde_json::to_value(submission).unwrap();
        value["host_exit_succeeded"] = json!(true);
        value["wake_target"] = json!("supervisor");
        assert!(serde_json::from_value::<RoleResultSubmission>(value).is_err());

        let binding = worker_result_binding();
        let merge_claim =
            worker_result_submission(RoleOutputKind::MergeIntent, json!({"method": "squash"}));
        assert!(validate_role_result(&binding, merge_claim).is_err());
    }

    #[test]
    fn irregularity_wakes_bound_parent_and_project_supervisor() {
        let binding = worker_result_binding();
        let result = validate_role_result(
            &binding,
            worker_result_submission(RoleOutputKind::Irregularity, worker_irregularity_payload()),
        )
        .unwrap();
        let recipients: BTreeSet<_> = result.wake_recipients.into_iter().collect();
        assert_eq!(
            recipients,
            BTreeSet::from([
                WakeSessionKey {
                    project_id: ProjectId::parse("project-a").unwrap(),
                    ticket_run_id: None,
                    role: Role::Supervisor,
                },
                WakeSessionKey {
                    project_id: ProjectId::parse("project-a").unwrap(),
                    ticket_run_id: Some(TicketRunId::parse("ticket-run-1").unwrap()),
                    role: Role::Coordinator,
                },
            ])
        );
    }

    #[test]
    fn result_artifact_path_must_be_safe_and_role_owned() {
        let binding = worker_result_binding();
        let oversized_path = "🍃".repeat(1100);
        for path in [
            "1:/outside",
            ".:/outside",
            "-:/outside",
            "é:/outside",
            "💥:/outside",
            oversized_path.as_str(),
        ] {
            let mut invalid_path = worker_result_submission(
                RoleOutputKind::ImplementationReady,
                worker_implementation_ready_payload(),
            );
            invalid_path.artifact_refs.push(RoleArtifactReference {
                artifact_id: ArtifactId::parse("f".repeat(64)).unwrap(),
                kind: RoleArtifactKind::Change,
                schema_version: 1,
                path: path.into(),
                digest: test_digest('f'),
                bytes: 12,
            });
            assert!(
                validate_role_result(&binding, invalid_path).is_err(),
                "{path}"
            );
        }

        let mut submission = worker_result_submission(
            RoleOutputKind::ImplementationReady,
            worker_implementation_ready_payload(),
        );
        submission.artifact_refs.push(RoleArtifactReference {
            artifact_id: ArtifactId::parse("f".repeat(64)).unwrap(),
            kind: RoleArtifactKind::Change,
            schema_version: 1,
            path: "../outside.patch".into(),
            digest: test_digest('f'),
            bytes: 12,
        });
        assert!(validate_role_result(&binding, submission).is_err());

        let mut wrong_role_artifact = worker_result_submission(
            RoleOutputKind::ImplementationReady,
            worker_implementation_ready_payload(),
        );
        wrong_role_artifact
            .artifact_refs
            .push(RoleArtifactReference {
                artifact_id: ArtifactId::parse("1".repeat(64)).unwrap(),
                kind: RoleArtifactKind::OperationReceipt,
                schema_version: 1,
                path: "receipts/deploy.json".into(),
                digest: test_digest('1'),
                bytes: 12,
            });
        assert!(validate_role_result(&binding, wrong_role_artifact).is_err());
    }

    #[test]
    fn artifact_add_request_is_run_local_and_schema_bounded() {
        let valid = ArtifactAddRequest {
            schema_version: ARTIFACT_ADD_REQUEST_SCHEMA_VERSION,
            message_id: "artifact-1".into(),
            path: "output/change.json".into(),
            kind: RoleArtifactKind::Change,
            artifact_schema_version: 1,
        };
        valid.validate().unwrap();

        let schema = artifact_add_request_schema();
        let validator = jsonschema::options()
            .offline()
            .build(&schema)
            .expect("artifact-add request schema is valid");
        let value = serde_json::to_value(&valid).unwrap();
        assert!(validator.is_valid(&value));

        for path in [
            "../outside",
            "/outside",
            "C:/outside",
            "1:/outside",
            ".:/outside",
            "-:/outside",
            "é:/outside",
            "💥:/outside",
            "dir\\file",
            "a//b",
        ] {
            let invalid = ArtifactAddRequest {
                path: path.into(),
                ..valid.clone()
            };
            assert!(invalid.validate().is_err(), "{path}");
            assert!(
                !validator.is_valid(&serde_json::to_value(invalid).unwrap()),
                "{path}"
            );
        }

        let oversized = ArtifactAddRequest {
            path: "🍃".repeat(1100),
            ..valid.clone()
        };
        assert!(oversized.validate().is_err());
        assert!(!validator.is_valid(&serde_json::to_value(oversized).unwrap()));

        let mut invalid = serde_json::to_value(&valid).unwrap();
        invalid["schema_version"] = json!(2);
        assert!(!validator.is_valid(&invalid));
        assert!(
            serde_json::from_value::<ArtifactAddRequest>(invalid)
                .unwrap()
                .validate()
                .is_err()
        );
    }

    #[test]
    fn role_session_id_deserialization_uses_constructor_validation() {
        assert!(RoleSessionId::parse("ticket_run:run-a:coordinator").is_ok());
        for invalid in [
            "../outside",
            "folder/session",
            "bad id",
            "ticket_run::coordinator",
        ] {
            assert!(serde_json::from_str::<RoleSessionId>(&format!("{invalid:?}")).is_err());
        }
    }

    #[test]
    fn intervention_schema_accepts_canonical_coordinator_session() {
        let payload = json!({
            "coordinator_role_session_id": "ticket_run:run-a:coordinator",
            "ticket_run_revision": 1,
            "reason": "Coordinator requests a plan adjustment.",
            "evidence": [],
            "proposed_plan_change": "Split the implementation into smaller nodes."
        });
        let schema = role_result_payload_schema(RoleOutputKind::Intervention);
        let validator = jsonschema::options()
            .offline()
            .build(&schema)
            .expect("Intervention schema is valid");
        assert!(
            validator.is_valid(&payload),
            "{}",
            validator
                .iter_errors(&payload)
                .map(|error| error.to_string())
                .collect::<Vec<_>>()
                .join("; ")
        );
        assert!(RoleResultPayload::parse(RoleOutputKind::Intervention, payload).is_ok());

        let invalid = json!({
            "coordinator_role_session_id": "ticket_run::coordinator",
            "ticket_run_revision": 1,
            "reason": "Coordinator requests a plan adjustment.",
            "evidence": [],
            "proposed_plan_change": "Split the implementation into smaller nodes."
        });
        assert!(!validator.is_valid(&invalid));
        assert!(RoleResultPayload::parse(RoleOutputKind::Intervention, invalid).is_err());
    }
}
