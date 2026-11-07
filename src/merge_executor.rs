//! One-step, freshly validated merge procedure executor.
//!
//! The controller persists the intent and receipt around these calls. This module never owns a
//! database transaction, retries an uncertain effect, or executes repository instruction text.
//! Raw GitHub merge-request comments remain manual because this adapter cannot verify that the
//! comment handler revalidates the approved revision and policy when it acts.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::domain::ids::{Digest, HumanRequestId};
use crate::domain::types::MergeMethod;
use crate::forge::{
    DirectMergeIntent, EffectAcknowledgement, EffectCertainty, Forge, ForgeError, ForgeObservation,
    MergeEffectIntent, Observed, PullRequestRef, Reconciliation, canonical_digest,
    merge_commit_message,
};
use crate::merge_policy::{
    MergeAssessment, MergeDisposition, MergeEvidenceSnapshot, MergePolicy, MergeProcedure,
    MergeProcedureOperation, MergeProcedureStep, build_merge_procedure, digest_merge_evidence,
    evaluate_merge_policy,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TrustedInstructionSource {
    pub key: String,
    pub digest: Digest,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RequestCommentProof {
    pub source_key: String,
    pub source_digest: Digest,
    pub byte_start: usize,
    pub exact_comment: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ResolvedMergeAuthority {
    /// Digest of merge-relevant resolved policy only; unrelated profile/skill updates do not alter it.
    pub policy_digest: Digest,
    pub instruction_digest: Digest,
    pub sources: BTreeMap<String, TrustedInstructionSource>,
    pub request_comment_proofs: Vec<RequestCommentProof>,
    pub execution_time_base_guard: crate::merge_policy::EvidenceState,
    pub base_guard_digest: Option<Digest>,
}

impl ResolvedMergeAuthority {
    fn validate(&self, assessment: &MergeAssessment) -> Result<(), MergeExecutionError> {
        if self.instruction_digest != assessment.subject.instruction_digest
            || self.base_guard_digest != assessment.subject.base_guard_digest
        {
            return Err(MergeExecutionError::Stale(
                "resolved merge policy, instruction, or base-guard digest changed".into(),
            ));
        }
        for (key, source) in &self.sources {
            if key != &source.key || digest_bytes(&source.bytes)? != source.digest {
                return Err(MergeExecutionError::Invalid(
                    "trusted instruction source identity or digest is invalid".into(),
                ));
            }
        }
        for proof in &self.request_comment_proofs {
            let Some(source) = self.sources.get(&proof.source_key) else {
                return Err(MergeExecutionError::Invalid(
                    "merge request command source is not in the trusted snapshot".into(),
                ));
            };
            if source.digest != proof.source_digest
                || !is_single_literal_command(&source.bytes, proof.byte_start, &proof.exact_comment)
            {
                return Err(MergeExecutionError::Invalid(
                    "merge request command does not match a trusted literal instruction span"
                        .into(),
                ));
            }
        }
        Ok(())
    }
}

/// Host-validated, exact-scope approval. It has no public constructor or Serde implementation,
/// so a CLI or Agent payload cannot mint approval by deserializing these fields.
///
/// ```compile_fail
/// let _: rex_projects::merge_executor::HumanMergeApproval =
///     serde_json::from_str(r#"{"approved":true}"#).unwrap();
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanMergeApproval {
    request_id: HumanRequestId,
    subject: crate::merge_policy::MergeSubject,
    configuration_digest: Digest,
    policy_digest: Digest,
    evidence_digest: Digest,
    procedure_digest: Digest,
    response_id: String,
    expires_at_unix: u64,
    /// Exact request bytes separately approved when they were not literal trusted instructions.
    exact_request_comment: Option<String>,
}

/// Implemented only by the host store adapter for the exact-scope approval lookup. This trait is
/// crate-private; protocol types supplied by an Agent cannot provide a receipt to the constructor.
pub(crate) trait HostValidatedHumanApprovalReceipt {
    fn request_id(&self) -> &HumanRequestId;
    fn response_id(&self) -> &str;
    fn subject_digest(&self) -> &Digest;
    fn configuration_digest(&self) -> &Digest;
    fn policy_digest(&self) -> &Digest;
    fn is_explicit_approval(&self) -> bool;
    fn decided_at_unix(&self) -> u64;
    fn expires_at_unix(&self) -> u64;
}

impl HumanMergeApproval {
    /// Mint an approval only from a host store receipt. `expected_subject_digest` must be the
    /// persisted HumanSubjectBinding digest whose material/bundle digests cover this assessment and
    /// exact procedure.
    #[allow(clippy::too_many_arguments)]
    #[allow(dead_code)] // Called by the durable human-approval handler introduced in PR5 runtime.
    pub(crate) fn from_host_validated_receipt(
        receipt: &impl HostValidatedHumanApprovalReceipt,
        expected_request_id: &HumanRequestId,
        expected_subject_digest: &Digest,
        policy: &MergePolicy,
        assessment: &MergeAssessment,
        procedure: &MergeProcedure,
    ) -> Result<Self, MergeExecutionError> {
        let configuration_digest = assessment.subject.config_digest.clone();
        let policy_digest = canonical_digest(policy).map_err(forge_error)?;
        let evidence_digest = assessment.evidence_digest.clone();
        let procedure_digest = canonical_digest(procedure).map_err(forge_error)?;
        let exact_request_comment = procedure.steps.iter().find_map(|step| {
            if let MergeProcedureOperation::RequestMerge { exact_comment } = &step.operation {
                Some(exact_comment.clone())
            } else {
                None
            }
        });
        if receipt.request_id() != expected_request_id
            || receipt.subject_digest() != expected_subject_digest
            || receipt.configuration_digest() != &configuration_digest
            || receipt.policy_digest() != &policy_digest
            || !receipt.is_explicit_approval()
            || receipt.response_id().trim().is_empty()
            || receipt.decided_at_unix() >= receipt.expires_at_unix()
            || current_unix_time()? >= receipt.expires_at_unix()
        {
            return Err(MergeExecutionError::HumanApprovalRequired(
                "host approval receipt is stale, unapproved, or bound to a different request"
                    .into(),
            ));
        }
        Ok(Self {
            request_id: expected_request_id.clone(),
            subject: assessment.subject.clone(),
            configuration_digest,
            policy_digest,
            evidence_digest,
            procedure_digest,
            response_id: receipt.response_id().to_owned(),
            expires_at_unix: receipt.expires_at_unix(),
            exact_request_comment,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MergeStepReceipt {
    pub step_key: String,
    pub operation_key: String,
    pub certainty: EffectCertainty,
    pub request_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StepIntent {
    pub operation_key: String,
    pub authenticated_actor: String,
    /// Exact bytes included in the approved procedure's prepared body digest.
    pub exact_prepared_body: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MergeVerificationReceipt {
    pub merge_commit_sha: String,
    pub included_head_sha: String,
    pub base_parent_sha: String,
    pub merge_method: MergeMethod,
    pub expected_trailers: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StepOutcome {
    Effect(EffectAcknowledgement),
    Verified(MergeVerificationReceipt),
    Pending(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MergeExecutionError {
    Invalid(String),
    Stale(String),
    Blocked(String),
    HumanApprovalRequired(String),
    Forge(String),
    VerificationFailed(String),
}

impl std::fmt::Display for MergeExecutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(value)
            | Self::Stale(value)
            | Self::Blocked(value)
            | Self::HumanApprovalRequired(value)
            | Self::Forge(value)
            | Self::VerificationFailed(value) => f.write_str(value),
        }
    }
}

impl std::error::Error for MergeExecutionError {}

pub struct MergeProcedureExecutor<F> {
    forge: F,
}

impl<F: Forge> MergeProcedureExecutor<F> {
    pub fn new(forge: F) -> Self {
        Self { forge }
    }

    /// Execute only the named next step. The caller persists the immutable intent first and
    /// stores the returned receipt. An `Unknown` acknowledgement must be reconciled, never replayed.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_one(
        &self,
        pull: &PullRequestRef,
        policy: &MergePolicy,
        approved: &MergeAssessment,
        evidence_now: &MergeEvidenceSnapshot,
        approval: Option<&HumanMergeApproval>,
        authority: &ResolvedMergeAuthority,
        procedure: &MergeProcedure,
        step_key: &str,
        intent: &StepIntent,
        prior_receipts: &[MergeStepReceipt],
    ) -> Result<StepOutcome, MergeExecutionError> {
        validate_procedure_policy(policy, procedure, &approved.subject)?;
        authority.validate(approved)?;
        let policy_digest = canonical_digest(policy).map_err(forge_error)?;
        if authority.policy_digest != policy_digest {
            return Err(MergeExecutionError::Stale(
                "resolved merge policy digest differs from the current repository policy".into(),
            ));
        }
        let procedure_digest = canonical_digest(procedure).map_err(forge_error)?;
        let current_assessment =
            evaluate_merge_policy(policy, evidence_now).map_err(MergeExecutionError::Invalid)?;
        if &current_assessment != approved
            || evidence_now.subject != approved.subject
            || digest_merge_evidence(evidence_now).map_err(MergeExecutionError::Invalid)?
                != approved.evidence_digest
        {
            return Err(MergeExecutionError::Stale(
                "current policy evidence or risk assessment differs from approved assessment"
                    .into(),
            ));
        }
        if approved.disposition == MergeDisposition::Blocked {
            return Err(MergeExecutionError::Blocked(
                "a failed invariant or stale assessment blocks all procedure effects".into(),
            ));
        }
        let human_approved = validate_approval(
            approved,
            approval,
            &procedure_digest,
            &policy_digest,
            current_unix_time()?,
        )?;
        if approved.disposition == MergeDisposition::HumanRequired && !human_approved {
            return Err(MergeExecutionError::HumanApprovalRequired(
                "the current assessment requires an exact-scope human approval".into(),
            ));
        }
        if authority.execution_time_base_guard != crate::merge_policy::EvidenceState::Pass
            || authority.base_guard_digest.is_none()
        {
            return Err(MergeExecutionError::Blocked(
                "no verified execution-time base guard is available".into(),
            ));
        }
        let step = find_step(procedure, step_key)?;
        verify_prerequisites(step, procedure, prior_receipts)?;
        if intent.operation_key.is_empty() {
            return Err(MergeExecutionError::Invalid(
                "step operation key must be stable and non-empty".into(),
            ));
        }
        if step.instruction_digest != authority.instruction_digest {
            return Err(MergeExecutionError::Stale(
                "procedure step was resolved from different instructions".into(),
            ));
        }

        let observed = self
            .forge
            .observe(pull)
            .map_err(|error| MergeExecutionError::Forge(error.to_string()))?;
        if matches!(
            step.operation,
            MergeProcedureOperation::VerifyMergeCommit { .. }
        ) {
            observed.verify_subject_identity_core(pull, &approved.subject)
        } else {
            observed.verify_subject_identity(pull, &approved.subject)
        }
        .map_err(|error| MergeExecutionError::Stale(error.to_string()))?;

        match &step.operation {
            MergeProcedureOperation::UpdatePullRequestBody {
                ..
            } => {
                Err(MergeExecutionError::Blocked(
                    "GitHub does not support atomic conditional PR-body updates; perform this step manually, re-observe, and create a new assessment".into(),
                ))
            }
            MergeProcedureOperation::RequestMerge { .. } => {
                Err(MergeExecutionError::Blocked(
                    "plain GitHub merge-request comments have no registered revision-guarded handler; hand off to a human without posting a command".into(),
                ))
            }
            MergeProcedureOperation::ExecuteMerge {
                expected_head_sha,
                base_guard_rule_digest,
            } => {
                if expected_head_sha != &approved.subject.head_sha
                    || Some(base_guard_rule_digest) != authority.base_guard_digest.as_ref()
                {
                    return Err(MergeExecutionError::Stale(
                        "direct merge revisions or base guard differ from approved subject".into(),
                    ));
                }
                ensure_open_same_revisions(&observed, &approved.subject)?;
                let live = complete_pull(&observed)?;
                let bound_body_digest = approved
                    .subject
                    .prepared_body_digest
                    .as_ref()
                    .ok_or_else(|| {
                        MergeExecutionError::Blocked(
                            "merge assessment does not bind the current PR body".into(),
                        )
                    })?;
                let current_body = live.body.as_deref().unwrap_or_default();
                if body_digest(current_body)? != *bound_body_digest {
                    return Err(MergeExecutionError::Stale(
                        "PR body differs from the body digest bound to the merge assessment".into(),
                    ));
                }
                let procedure_body_digest = procedure.steps.iter().find_map(|step| {
                    if let MergeProcedureOperation::UpdatePullRequestBody {
                        approved_body_digest,
                        ..
                    } = &step.operation
                    {
                        Some(approved_body_digest)
                    } else {
                        None
                    }
                });
                if let Some(procedure_body_digest) = procedure_body_digest {
                    let prepared_body = intent.exact_prepared_body.as_ref().ok_or_else(|| {
                        MergeExecutionError::Invalid(
                            "prepared PR body is missing for the approved procedure".into(),
                        )
                    })?;
                    let prepared_digest = digest_bytes(prepared_body.as_bytes())?;
                    if digest_bytes(prepared_body.as_bytes())? != *procedure_body_digest
                        || prepared_digest != body_digest(current_body)?
                    {
                        return Err(MergeExecutionError::Stale(
                            "PR body changed after its reviewed update; refusing merge".into(),
                        ));
                    }
                }
                let expected_trailers = procedure
                    .steps
                    .iter()
                    .find_map(|step| match &step.operation {
                        MergeProcedureOperation::VerifyMergeCommit { expected_trailers } => {
                            Some(expected_trailers.clone())
                        }
                        _ => None,
                    })
                    .unwrap_or_default();
                if procedure.method != MergeMethod::Squash {
                    return Err(MergeExecutionError::Blocked(
                        "GitHub cannot set required trailers for this merge method; use squash or hand off to a human".into(),
                    ));
                }
                let expected_commit_message = merge_commit_message(current_body, &expected_trailers)
                    .map_err(forge_error)?;
                let protection = complete_observation(&observed.branch_protection)?;
                if !protection.supports_execution_base_guard(
                    &policy.required_checks,
                    policy.required_approving_reviews,
                ) {
                    return Err(MergeExecutionError::Blocked(
                        "observed GitHub branch rules do not prove strict execution-time base protection".into(),
                    ));
                }
                let effect = DirectMergeIntent {
                    pull: pull.clone(),
                    operation_key: intent.operation_key.clone(),
                    method: procedure.method,
                    expected_head_sha: expected_head_sha.clone(),
                    expected_base_sha: approved.subject.base_sha.clone(),
                    expected_body: current_body.to_owned(),
                    expected_body_digest: bound_body_digest.clone(),
                    expected_commit_message,
                    approval_expires_at_unix: approval.map(|value| value.expires_at_unix),
                    expected_trailers,
                };
                validate_approval(
                    approved,
                    approval,
                    &procedure_digest,
                    &policy_digest,
                    current_unix_time()?,
                )?;
                let ack = self
                    .forge
                    .execute_merge(&effect)
                    .map_err(|error| MergeExecutionError::Forge(error.to_string()))?;
                Ok(StepOutcome::Effect(ack))
            }
            MergeProcedureOperation::VerifyMergeCommit { expected_trailers } => {
                let result = self.verify_merge(
                    pull,
                    &approved.subject,
                    procedure.method,
                    expected_trailers,
                    &observed,
                )?;
                Ok(result.map_or_else(
                    || StepOutcome::Pending("pull request has not merged yet".into()),
                    StepOutcome::Verified,
                ))
            }
        }
    }

    pub fn reconcile_one(
        &self,
        intent: &MergeEffectIntent,
    ) -> Result<Reconciliation, MergeExecutionError> {
        self.forge
            .reconcile(intent)
            .map_err(|error| MergeExecutionError::Forge(error.to_string()))
    }

    fn verify_merge(
        &self,
        pull: &PullRequestRef,
        subject: &crate::merge_policy::MergeSubject,
        method: MergeMethod,
        expected_trailers: &[String],
        observation: &ForgeObservation,
    ) -> Result<Option<MergeVerificationReceipt>, MergeExecutionError> {
        let pr = complete_observation(&observation.pull_request)?;
        if pr.number.to_string() != subject.pull_request_id
            || pr.node_id != subject.pull_request_node_id
            || pr.repository_id != subject.forge_repository_id
        {
            return Err(MergeExecutionError::VerificationFailed(
                "pull request identity changed before merge verification".into(),
            ));
        }
        if !pr.merged && pr.state == crate::forge::PullRequestState::Open {
            return Ok(None);
        }
        if !pr.merged || pr.head_sha != subject.head_sha {
            return Err(MergeExecutionError::VerificationFailed(
                "pull request did not merge from the approved head".into(),
            ));
        }
        let merge_sha = pr.merge_commit_sha.as_deref().ok_or_else(|| {
            MergeExecutionError::VerificationFailed(
                "merged pull request has no merge commit SHA".into(),
            )
        })?;
        let merge_commit = match self
            .forge
            .observe_commit(&pull.repository, merge_sha)
            .map_err(|error| MergeExecutionError::Forge(error.to_string()))?
        {
            Observed::Complete { value, .. } => value,
            Observed::Unknown { reason } => {
                return Err(MergeExecutionError::VerificationFailed(reason));
            }
        };
        if merge_commit.sha != merge_sha
            || !trailers_match(&merge_commit.message, expected_trailers)
        {
            return Err(MergeExecutionError::VerificationFailed(
                "merge commit identity or required trailers do not match".into(),
            ));
        }
        match method {
            MergeMethod::Merge if !merge_commit.parents.contains(&subject.head_sha) => {
                return Err(MergeExecutionError::VerificationFailed(
                    "merge commit does not have the approved PR head as a parent".into(),
                ));
            }
            _ => (),
        }
        let base_parent = if method == MergeMethod::Merge {
            merge_commit
                .parents
                .iter()
                .find(|parent| *parent != &subject.head_sha)
                .cloned()
        } else {
            merge_commit.parents.first().cloned()
        }
        .ok_or_else(|| {
            MergeExecutionError::VerificationFailed(
                "merge commit has no verifiable base parent".into(),
            )
        })?;
        let comparison = match self
            .forge
            .compare_commits(&pull.repository, &subject.base_sha, &base_parent)
            .map_err(|error| MergeExecutionError::Forge(error.to_string()))?
        {
            Observed::Complete { value, .. } => value,
            Observed::Unknown { reason } => {
                return Err(MergeExecutionError::VerificationFailed(reason));
            }
        };
        if comparison.base_sha != subject.base_sha
            || comparison.head_sha != base_parent
            || comparison.behind_by != 0
        {
            return Err(MergeExecutionError::VerificationFailed(
                "merged target parent does not descend from the assessed base".into(),
            ));
        }
        Ok(Some(MergeVerificationReceipt {
            merge_commit_sha: merge_commit.sha,
            included_head_sha: subject.head_sha.clone(),
            base_parent_sha: base_parent,
            merge_method: method,
            expected_trailers: expected_trailers.to_vec(),
        }))
    }
}

fn current_unix_time() -> Result<u64, MergeExecutionError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| MergeExecutionError::Invalid("system clock is before Unix epoch".into()))
}

fn validate_procedure_policy(
    policy: &MergePolicy,
    procedure: &MergeProcedure,
    subject: &crate::merge_policy::MergeSubject,
) -> Result<(), MergeExecutionError> {
    if policy.method != procedure.method || policy.executor != procedure.executor {
        return Err(MergeExecutionError::Stale(
            "merge procedure method/executor differs from resolved repository policy".into(),
        ));
    }
    build_merge_procedure(
        procedure.method,
        procedure.executor,
        procedure.steps.clone(),
        subject,
    )
    .map_err(|reason| {
        MergeExecutionError::Invalid(format!("merge procedure failed validation: {reason}"))
    })?;
    Ok(())
}

fn validate_approval(
    assessment: &MergeAssessment,
    approval: Option<&HumanMergeApproval>,
    procedure_digest: &Digest,
    policy_digest: &Digest,
    now_unix: u64,
) -> Result<bool, MergeExecutionError> {
    let Some(approval) = approval else {
        return Ok(false);
    };
    if approval.response_id.is_empty()
        || approval.request_id.as_str().trim().is_empty()
        || approval.expires_at_unix <= now_unix
        || approval.subject != assessment.subject
        || approval.configuration_digest != assessment.subject.config_digest
        || &approval.policy_digest != policy_digest
        || approval.evidence_digest != assessment.evidence_digest
        || &approval.procedure_digest != procedure_digest
    {
        return Err(MergeExecutionError::Stale(
            "human approval is expired or scoped to a different subject, evidence, or procedure"
                .into(),
        ));
    }
    Ok(true)
}

fn find_step<'a>(
    procedure: &'a MergeProcedure,
    key: &str,
) -> Result<&'a MergeProcedureStep, MergeExecutionError> {
    procedure
        .steps
        .iter()
        .find(|step| step.key == key)
        .ok_or_else(|| MergeExecutionError::Invalid("merge procedure step key is unknown".into()))
}

fn verify_prerequisites(
    selected: &MergeProcedureStep,
    procedure: &MergeProcedure,
    receipts: &[MergeStepReceipt],
) -> Result<(), MergeExecutionError> {
    let index = procedure
        .steps
        .iter()
        .position(|step| step.key == selected.key)
        .ok_or_else(|| MergeExecutionError::Invalid("selected step is not in procedure".into()))?;
    for prior in &procedure.steps[..index] {
        let receipt = receipts
            .iter()
            .find(|receipt| receipt.step_key == prior.key);
        if !receipt.is_some_and(|receipt| {
            matches!(
                receipt.certainty,
                EffectCertainty::Applied | EffectCertainty::Recovered
            )
        }) {
            return Err(MergeExecutionError::Blocked(format!(
                "earlier procedure step `{}` has no successful durable receipt",
                prior.key
            )));
        }
    }
    for dependency in &selected.prerequisites {
        if !receipts.iter().any(|receipt| {
            receipt.step_key == *dependency
                && matches!(
                    receipt.certainty,
                    EffectCertainty::Applied | EffectCertainty::Recovered
                )
        }) {
            return Err(MergeExecutionError::Blocked(format!(
                "prerequisite step `{dependency}` has no successful durable receipt"
            )));
        }
    }
    Ok(())
}

fn ensure_open_same_revisions(
    observation: &ForgeObservation,
    subject: &crate::merge_policy::MergeSubject,
) -> Result<(), MergeExecutionError> {
    let pr = complete_observation(&observation.pull_request)?;
    if pr.state != crate::forge::PullRequestState::Open
        || pr.merged
        || pr.draft
        || pr.head_sha != subject.head_sha
        || pr.base_sha != subject.base_sha
    {
        return Err(MergeExecutionError::Stale(
            "PR is no longer open at the approved head and base".into(),
        ));
    }
    Ok(())
}

fn complete_observation<T>(observation: &Observed<T>) -> Result<&T, MergeExecutionError> {
    match observation {
        Observed::Complete { value, .. } => Ok(value),
        Observed::Unknown { reason } => Err(MergeExecutionError::Blocked(reason.clone())),
    }
}

fn complete_pull(
    observation: &ForgeObservation,
) -> Result<&crate::forge::PullRequestObservation, MergeExecutionError> {
    complete_observation(&observation.pull_request)
}

fn is_single_literal_command(source: &[u8], start: usize, command: &str) -> bool {
    if command.is_empty()
        || command.len() > 512
        || !command.starts_with('/')
        || command.bytes().any(|byte| byte.is_ascii_control())
    {
        return false;
    }
    let Some(end) = start.checked_add(command.len()) else {
        return false;
    };
    let line_start = start == 0 || source.get(start - 1) == Some(&b'\n');
    let line_end = end == source.len() || source.get(end) == Some(&b'\n');
    line_start && line_end && source.get(start..end) == Some(command.as_bytes())
}

fn trailers_match(message: &str, expected: &[String]) -> bool {
    if expected.is_empty()
        || expected
            .iter()
            .any(|line| !line.starts_with("Co-authored-by: "))
    {
        return false;
    }
    let mut unique = expected.to_vec();
    unique.sort();
    unique.dedup();
    if unique.len() != expected.len() {
        return false;
    }
    let lines = message.trim_end().lines().collect::<Vec<_>>();
    let actual = lines
        .iter()
        .filter(|line| line.starts_with("Co-authored-by: "))
        .copied()
        .collect::<Vec<_>>();
    actual == expected.iter().map(String::as_str).collect::<Vec<_>>()
        && lines.ends_with(&expected.iter().map(String::as_str).collect::<Vec<_>>())
}

fn digest_bytes(bytes: &[u8]) -> Result<Digest, MergeExecutionError> {
    let hash = sha2::Sha256::digest(bytes);
    let value = hash
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Digest::parse(value).map_err(MergeExecutionError::Invalid)
}

fn body_digest(body: &str) -> Result<Digest, MergeExecutionError> {
    digest_bytes(body.as_bytes())
}

fn forge_error(error: ForgeError) -> MergeExecutionError {
    MergeExecutionError::Invalid(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::ids::HumanRequestId;
    use crate::domain::types::{MergeExecutor, MergeMethod};
    use crate::merge_executor::HostValidatedHumanApprovalReceipt;
    use crate::merge_policy::{MergeProcedureOperation, MergeSubject, RiskWeights};

    fn test_digest(letter: char) -> Digest {
        Digest::parse(letter.to_string().repeat(64)).unwrap()
    }

    fn test_subject() -> MergeSubject {
        MergeSubject {
            repository_id: "repo".into(),
            forge: "github".into(),
            forge_host: "github.com".into(),
            forge_repository_id: 10,
            pull_request_id: "1".into(),
            pull_request_node_id: "PR_1".into(),
            head_sha: "head".into(),
            base_ref: "main".into(),
            base_sha: "base".into(),
            config_digest: test_digest('a'),
            instruction_digest: test_digest('b'),
            hooks_digest: test_digest('c'),
            remote_checks_digest: test_digest('d'),
            diff_digest: test_digest('e'),
            merge_comments_digest: test_digest('f'),
            base_guard_digest: Some(test_digest('1')),
            review_digest: test_digest('2'),
            prepared_body_digest: None,
        }
    }

    #[derive(Clone)]
    struct AcceptedReceipt {
        request_id: HumanRequestId,
        response_id: String,
        subject_digest: Digest,
        configuration_digest: Digest,
        policy_digest: Digest,
        approved: bool,
        decided_at_unix: u64,
        expires_at_unix: u64,
    }

    impl HostValidatedHumanApprovalReceipt for AcceptedReceipt {
        fn request_id(&self) -> &HumanRequestId {
            &self.request_id
        }
        fn response_id(&self) -> &str {
            &self.response_id
        }
        fn subject_digest(&self) -> &Digest {
            &self.subject_digest
        }
        fn configuration_digest(&self) -> &Digest {
            &self.configuration_digest
        }
        fn policy_digest(&self) -> &Digest {
            &self.policy_digest
        }
        fn is_explicit_approval(&self) -> bool {
            self.approved
        }
        fn decided_at_unix(&self) -> u64 {
            self.decided_at_unix
        }
        fn expires_at_unix(&self) -> u64 {
            self.expires_at_unix
        }
    }

    fn human_approval_inputs() -> (
        AcceptedReceipt,
        HumanRequestId,
        Digest,
        MergePolicy,
        MergeAssessment,
        MergeProcedure,
    ) {
        let subject = test_subject();
        let policy = MergePolicy {
            auto_merge_enabled: false,
            minimum_reliability_score: 90,
            method: MergeMethod::Squash,
            executor: MergeExecutor::Direct,
            required_checks: vec!["ci".into()],
            required_approving_reviews: None,
            risk_weights: RiskWeights::default(),
        };
        let procedure = MergeProcedure {
            method: MergeMethod::Squash,
            executor: MergeExecutor::Direct,
            steps: vec![
                MergeProcedureStep {
                    key: "merge".into(),
                    prerequisites: vec![],
                    operation: MergeProcedureOperation::ExecuteMerge {
                        expected_head_sha: subject.head_sha.clone(),
                        base_guard_rule_digest: subject.base_guard_digest.clone().unwrap(),
                    },
                    instruction_digest: subject.instruction_digest.clone(),
                },
                MergeProcedureStep {
                    key: "verify".into(),
                    prerequisites: vec!["merge".into()],
                    operation: MergeProcedureOperation::VerifyMergeCommit {
                        expected_trailers: vec!["Co-authored-by: Agent <a@b>".into()],
                    },
                    instruction_digest: subject.instruction_digest.clone(),
                },
            ],
        };
        let assessment = MergeAssessment {
            subject: subject.clone(),
            evidence_digest: test_digest('7'),
            disposition: MergeDisposition::HumanRequired,
            risk_index: Some(0),
            reliability_score: Some(100),
            reasons: vec!["automatic merge disabled".into()],
        };
        let request_id = HumanRequestId::parse("human-approval-7").unwrap();
        let expected_subject_digest = test_digest('8');
        let policy_digest = canonical_digest(&policy).unwrap();
        let receipt = AcceptedReceipt {
            request_id: request_id.clone(),
            response_id: "human-response-7".into(),
            subject_digest: expected_subject_digest.clone(),
            configuration_digest: subject.config_digest.clone(),
            policy_digest,
            approved: true,
            decided_at_unix: 100,
            expires_at_unix: u64::MAX,
        };
        (
            receipt,
            request_id,
            expected_subject_digest,
            policy,
            assessment,
            procedure,
        )
    }

    #[test]
    fn approval_is_minted_only_from_a_current_exact_host_receipt() {
        let (receipt, request_id, subject_digest, policy, assessment, procedure) =
            human_approval_inputs();
        let approval = HumanMergeApproval::from_host_validated_receipt(
            &receipt,
            &request_id,
            &subject_digest,
            &policy,
            &assessment,
            &procedure,
        )
        .unwrap();
        let procedure_digest = canonical_digest(&procedure).unwrap();
        let policy_digest = canonical_digest(&policy).unwrap();
        assert!(
            validate_approval(
                &assessment,
                Some(&approval),
                &procedure_digest,
                &policy_digest,
                150,
            )
            .unwrap()
        );
        let mut cached_after_expiry = approval.clone();
        cached_after_expiry.expires_at_unix = 1;
        assert!(
            validate_approval(
                &assessment,
                Some(&cached_after_expiry),
                &procedure_digest,
                &policy_digest,
                current_unix_time().unwrap(),
            )
            .is_err()
        );
        assert!(
            HumanMergeApproval::from_host_validated_receipt(
                &receipt,
                &HumanRequestId::parse("another-request").unwrap(),
                &subject_digest,
                &policy,
                &assessment,
                &procedure,
            )
            .is_err()
        );
        assert!(
            HumanMergeApproval::from_host_validated_receipt(
                &receipt,
                &request_id,
                &test_digest('9'),
                &policy,
                &assessment,
                &procedure,
            )
            .is_err()
        );
        let mut expired = receipt.clone();
        expired.expires_at_unix = 1;
        assert!(
            HumanMergeApproval::from_host_validated_receipt(
                &expired,
                &request_id,
                &subject_digest,
                &policy,
                &assessment,
                &procedure,
            )
            .is_err()
        );
        let mut denied = receipt;
        denied.approved = false;
        assert!(
            HumanMergeApproval::from_host_validated_receipt(
                &denied,
                &request_id,
                &subject_digest,
                &policy,
                &assessment,
                &procedure,
            )
            .is_err()
        );
    }

    #[test]
    fn instruction_literal_requires_exact_single_line_span() {
        let source = b"Use this command:\n/merge\nthen verify";
        assert!(is_single_literal_command(source, 18, "/merge"));
        assert!(!is_single_literal_command(source, 18, "/merge\nextra"));
        assert!(!is_single_literal_command(source, 0, "gh pr merge"));
        assert!(!is_single_literal_command(
            b"prefix /merge suffix",
            7,
            "/merge"
        ));
    }

    #[test]
    fn trailers_must_be_the_exact_final_block() {
        let expected = vec!["Co-authored-by: Agent <agent@example.com>".to_owned()];
        assert!(trailers_match(
            "Merge change\n\nCo-authored-by: Agent <agent@example.com>\n",
            &expected
        ));
        assert!(!trailers_match(
            "Merge change\nCo-authored-by: Agent <agent@example.com>\ntext",
            &expected
        ));
        assert!(!trailers_match(
            "Merge change\nCo-authored-by: Agent <agent@example.com>\nCo-authored-by: Agent <agent@example.com>",
            &expected
        ));
    }

    #[test]
    fn executor_rejects_a_request_policy_with_a_direct_merge_step() {
        let subject = test_subject();
        let procedure = MergeProcedure {
            method: MergeMethod::Squash,
            executor: MergeExecutor::Request,
            steps: vec![
                MergeProcedureStep {
                    key: "request".into(),
                    prerequisites: vec![],
                    operation: MergeProcedureOperation::ExecuteMerge {
                        expected_head_sha: subject.head_sha.clone(),
                        base_guard_rule_digest: subject.base_guard_digest.clone().unwrap(),
                    },
                    instruction_digest: subject.instruction_digest.clone(),
                },
                MergeProcedureStep {
                    key: "verify".into(),
                    prerequisites: vec!["request".into()],
                    operation: MergeProcedureOperation::VerifyMergeCommit {
                        expected_trailers: vec!["Co-authored-by: Agent <a@b>".into()],
                    },
                    instruction_digest: subject.instruction_digest.clone(),
                },
            ],
        };
        let policy = MergePolicy {
            auto_merge_enabled: true,
            minimum_reliability_score: 80,
            method: MergeMethod::Squash,
            executor: MergeExecutor::Request,
            required_checks: vec!["ci".into()],
            required_approving_reviews: None,
            risk_weights: RiskWeights::default(),
        };
        assert!(matches!(
            validate_procedure_policy(&policy, &procedure, &subject),
            Err(MergeExecutionError::Invalid(_))
        ));
    }
}
