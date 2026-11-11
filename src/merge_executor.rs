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
    BodyUpdateIntent, CommentIntent, DirectMergeIntent, EffectAcknowledgement, EffectCertainty,
    Forge, ForgeError, ForgeObservation, MergeEffectIntent, Observed, PullRequestRef,
    Reconciliation, canonical_digest, merge_commit_message,
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
    /// Exact host-persisted outbox request and acknowledgement, retained so subsequent steps
    /// can allow only the external mutation this approved procedure actually performed.
    pub effect_intent: MergeEffectIntent,
    pub acknowledgement: EffectAcknowledgement,
}

/// Durable outer-effect payload for one step of an approved immutable merge procedure.
/// Prior receipts travel with each next step so the handler can prove its prerequisites without
/// relying on mutable process-local state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MergeStepEffectRequest {
    pub schema_version: u32,
    pub work_id: Digest,
    pub request_id: HumanRequestId,
    pub assessed_revision: crate::domain::ids::Revision,
    pub awaiting_merge_revision: crate::domain::ids::Revision,
    pub step_key: String,
    pub prior_receipts: Vec<MergeStepReceipt>,
}

impl MergeStepReceipt {
    fn certainty_is_success(&self) -> bool {
        matches!(
            self.certainty,
            EffectCertainty::Applied | EffectCertainty::Recovered
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StepIntent {
    pub operation_key: String,
    pub authenticated_actor: String,
    /// Immutable outer outbox creation time, reused to reconstruct the exact inner Forge intent.
    pub attempt_started_unix: u64,
    /// Exact bytes included in the approved procedure's prepared body digest.
    pub exact_prepared_body: Option<String>,
}

/// Rebuild the exact inner Forge mutation from the durable MergeWorkItem plus the outer effect
/// identity. The outer outbox record exists before this value can reach a Forge method.
pub(crate) fn reconciliation_intent(
    item: &crate::store::merge_work::MergeWorkItem,
    step: &MergeProcedureStep,
    pull: &PullRequestRef,
    intent: &StepIntent,
    approval_expires_at_unix: u64,
    attempt_started_unix: u64,
    live_body: &str,
) -> Result<MergeEffectIntent, String> {
    use crate::forge::MergeEffectOperation;
    let (operation, request_digest) = match &step.operation {
        MergeProcedureOperation::UpdatePullRequestBody {
            expected_prior_body_digest,
            approved_body_digest,
        } => {
            let exact_body = intent
                .exact_prepared_body
                .clone()
                .ok_or("approved merge body update has no exact persisted body")?;
            let body = BodyUpdateIntent {
                pull: pull.clone(),
                operation_key: intent.operation_key.clone(),
                expected_head_sha: item.document.assessment.subject.head_sha.clone(),
                expected_prior_body_digest: expected_prior_body_digest.clone(),
                exact_body,
                approved_body_digest: approved_body_digest.clone(),
            };
            (
                MergeEffectOperation::UpdateBody(body.clone()),
                canonical_digest(&body).map_err(|error| error.to_string())?,
            )
        }
        MergeProcedureOperation::RequestMerge { exact_comment } => {
            let comment = CommentIntent {
                pull: pull.clone(),
                operation_key: intent.operation_key.clone(),
                expected_head_sha: item.document.assessment.subject.head_sha.clone(),
                expected_base_sha: item.document.assessment.subject.base_sha.clone(),
                exact_body: exact_comment.clone(),
                authenticated_actor: intent.authenticated_actor.clone(),
                attempt_started_unix,
            };
            (
                MergeEffectOperation::RequestComment(comment.clone()),
                canonical_digest(&comment).map_err(|error| error.to_string())?,
            )
        }
        MergeProcedureOperation::ExecuteMerge {
            expected_head_sha, ..
        } => {
            let expected_trailers = item
                .document
                .procedure
                .steps
                .iter()
                .find_map(|step| {
                    if let MergeProcedureOperation::VerifyMergeCommit { expected_trailers } =
                        &step.operation
                    {
                        Some(expected_trailers.clone())
                    } else {
                        None
                    }
                })
                .unwrap_or_default();
            let expected_body = item
                .document
                .prepared_body
                .as_deref()
                .unwrap_or(live_body)
                .to_owned();
            if item
                .document
                .prepared_body
                .as_ref()
                .is_some_and(|body| body != live_body)
            {
                return Err("live PR body differs from the approved prepared body during merge reconciliation".into());
            }
            if item.document.prepared_body.is_none()
                && item
                    .document
                    .assessment
                    .subject
                    .prepared_body_digest
                    .as_ref()
                    != Some(&body_digest(live_body).map_err(|error| error.to_string())?)
            {
                return Err(
                    "live PR body differs from the assessed body during merge reconciliation"
                        .into(),
                );
            }
            let merge = DirectMergeIntent {
                pull: pull.clone(),
                operation_key: intent.operation_key.clone(),
                method: item.document.procedure.method,
                expected_head_sha: expected_head_sha.clone(),
                expected_base_sha: item.document.assessment.subject.base_sha.clone(),
                expected_body_digest: body_digest(&expected_body)
                    .map_err(|error| error.to_string())?,
                expected_commit_message: merge_commit_message(&expected_body, &expected_trailers)
                    .map_err(|error| error.to_string())?,
                expected_body,
                approval_expires_at_unix: Some(approval_expires_at_unix),
                expected_trailers,
            };
            (
                MergeEffectOperation::DirectMerge(merge.clone()),
                canonical_digest(&merge).map_err(|error| error.to_string())?,
            )
        }
        MergeProcedureOperation::VerifyMergeCommit { .. } => {
            return Err(
                "read-only merge verification does not have a Forge mutation intent".into(),
            );
        }
    };
    Ok(MergeEffectIntent {
        pull: pull.clone(),
        operation_key: intent.operation_key.clone(),
        request_digest,
        operation,
        attempt_started_unix,
    })
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MergeBaseAncestryProof {
    pub comparison_base_sha: String,
    pub comparison_head_sha: String,
    pub behind_by: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum MergeMethodEvidence {
    DirectMergeAcknowledgement {
        operation_key: String,
        request_digest: Digest,
    },
    MergeCommitParents {
        parent_count: usize,
    },
    SingleParentCommit {
        parent_sha: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MergeVerificationReceipt {
    pub merge_commit_sha: String,
    pub included_head_sha: String,
    pub base_parent_sha: String,
    /// The immutable procedure method whose observable merge postconditions were verified.
    /// For requested Squash/Rebase, GitHub exposes the same single-parent shape for a one-commit
    /// PR, so this field does not assert which indistinguishable server route was used.
    pub merge_method: MergeMethod,
    pub method_evidence: MergeMethodEvidence,
    pub base_ancestry: MergeBaseAncestryProof,
    pub expected_trailers: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StepOutcome {
    Effect {
        effect_intent: Box<MergeEffectIntent>,
        acknowledgement: EffectAcknowledgement,
    },
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

    #[cfg(test)]
    pub(crate) fn verify_observed_merge_for_test(
        &self,
        pull: &PullRequestRef,
        subject: &crate::merge_policy::MergeSubject,
        method: MergeMethod,
        expected_trailers: &[String],
        observation: &ForgeObservation,
        prior_receipts: &[MergeStepReceipt],
    ) -> Result<Option<MergeVerificationReceipt>, MergeExecutionError> {
        self.verify_merge(
            pull,
            subject,
            method,
            expected_trailers,
            observation,
            prior_receipts,
        )
    }

    /// Execute only the named next step. The caller persists the immutable intent first and
    /// stores the returned receipt. An `Unknown` acknowledgement must be reconciled, never replayed.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_one(
        &self,
        pull: &PullRequestRef,
        policy: &MergePolicy,
        approved: &MergeAssessment,
        approved_evidence: &MergeEvidenceSnapshot,
        evidence_now: &MergeEvidenceSnapshot,
        approval: Option<&HumanMergeApproval>,
        authority: &ResolvedMergeAuthority,
        procedure: &MergeProcedure,
        baseline_issue_comments: &[crate::forge::IssueComment],
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
        if approved_evidence.subject != approved.subject
            || approved_evidence.current_subject != approved.subject
            || evaluate_merge_policy(policy, approved_evidence)
                .map_err(MergeExecutionError::Invalid)?
                != *approved
            || digest_merge_evidence(approved_evidence).map_err(MergeExecutionError::Invalid)?
                != approved.evidence_digest
        {
            return Err(MergeExecutionError::Stale(
                "persisted policy evidence differs from the approved assessment".into(),
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
        let selected_index = procedure
            .steps
            .iter()
            .position(|candidate| candidate.key == step_key)
            .ok_or_else(|| MergeExecutionError::Invalid("merge step key is unknown".into()))?;
        let terminal_merged_verification = selected_index + 1 == procedure.steps.len()
            && matches!(
                &step.operation,
                MergeProcedureOperation::VerifyMergeCommit { .. }
            )
            && matches!(
                &observed.pull_request,
                Observed::Complete { value, .. }
                    if value.merged && value.state == crate::forge::PullRequestState::Closed
            );
        if terminal_merged_verification {
            let mut identity_observation = observed.clone();
            if let Observed::Complete { value, .. } = &mut identity_observation.pull_request {
                value.base_sha = approved.subject.base_sha.clone();
            }
            identity_observation
                .verify_subject_identity_core(pull, &approved.subject)
                .map_err(|error| MergeExecutionError::Stale(error.to_string()))?;
        } else {
            observed
                .verify_subject_identity_core(pull, &approved.subject)
                .map_err(|error| MergeExecutionError::Stale(error.to_string()))?;
        }
        validate_current_step_evidence(
            policy,
            approved,
            approved_evidence,
            evidence_now,
            &observed,
            pull,
            procedure,
            step_key,
            prior_receipts,
            baseline_issue_comments,
        )?;

        match &step.operation {
            MergeProcedureOperation::UpdatePullRequestBody {
                expected_prior_body_digest,
                approved_body_digest,
            } => {
                if !human_approved {
                    return Err(MergeExecutionError::HumanApprovalRequired(
                        "PR body updates are non-atomic and require approval of these exact body bytes".into(),
                    ));
                }
                ensure_open_same_revisions(&observed, &approved.subject)?;
                let live = complete_pull(&observed)?;
                let current_body = live.body.as_deref().unwrap_or_default();
                if body_digest(current_body)? != *expected_prior_body_digest
                    || approved.subject.prepared_body_digest.as_ref()
                        != Some(expected_prior_body_digest)
                {
                    return Err(MergeExecutionError::Stale(
                        "PR body changed after the exact prior body was reviewed".into(),
                    ));
                }
                let exact_body = intent.exact_prepared_body.as_ref().ok_or_else(|| {
                    MergeExecutionError::Invalid(
                        "exact host-prepared PR body is missing from the step intent".into(),
                    )
                })?;
                if digest_bytes(exact_body.as_bytes())? != *approved_body_digest {
                    return Err(MergeExecutionError::Stale(
                        "host-prepared PR body differs from the human-approved procedure".into(),
                    ));
                }
                let body_intent = BodyUpdateIntent {
                    pull: pull.clone(),
                    operation_key: intent.operation_key.clone(),
                    expected_head_sha: approved.subject.head_sha.clone(),
                    expected_prior_body_digest: expected_prior_body_digest.clone(),
                    exact_body: exact_body.clone(),
                    approved_body_digest: approved_body_digest.clone(),
                };
                let effect_intent = MergeEffectIntent {
                    pull: body_intent.pull.clone(),
                    operation_key: intent.operation_key.clone(),
                    request_digest: canonical_digest(&body_intent).map_err(forge_error)?,
                    operation: crate::forge::MergeEffectOperation::UpdateBody(body_intent.clone()),
                    attempt_started_unix: intent.attempt_started_unix,
                };
                let acknowledgement = self
                    .forge
                    .update_body(&body_intent)
                    .map_err(|error| MergeExecutionError::Forge(error.to_string()))?;
                validate_acknowledgement(
                    &acknowledgement,
                    &intent.operation_key,
                    &canonical_digest(&body_intent).map_err(forge_error)?,
                )?;
                Ok(StepOutcome::Effect {
                    effect_intent: Box::new(effect_intent),
                    acknowledgement,
                })
            }
            MergeProcedureOperation::RequestMerge { exact_comment } => {
                if !human_approved {
                    return Err(MergeExecutionError::HumanApprovalRequired(
                        "the repository merge-request command requires approval of the exact comment".into(),
                    ));
                }
                if approval.and_then(|value| value.exact_request_comment.as_deref())
                    != Some(exact_comment.as_str())
                {
                    return Err(MergeExecutionError::Stale(
                        "merge-request comment differs from the exact approved procedure".into(),
                    ));
                }
                ensure_open_same_revisions(&observed, &approved.subject)?;
                let _live = complete_pull(&observed)?;
                if intent.authenticated_actor.trim().is_empty() {
                    return Err(MergeExecutionError::Invalid(
                        "authenticated merge-request actor is missing".into(),
                    ));
                }
                let comment_intent = CommentIntent {
                    pull: pull.clone(),
                    operation_key: intent.operation_key.clone(),
                    expected_head_sha: approved.subject.head_sha.clone(),
                    expected_base_sha: approved.subject.base_sha.clone(),
                    exact_body: exact_comment.clone(),
                    authenticated_actor: intent.authenticated_actor.clone(),
                    attempt_started_unix: intent.attempt_started_unix,
                };
                let effect_intent = MergeEffectIntent {
                    pull: comment_intent.pull.clone(),
                    operation_key: intent.operation_key.clone(),
                    request_digest: canonical_digest(&comment_intent).map_err(forge_error)?,
                    operation: crate::forge::MergeEffectOperation::RequestComment(
                        comment_intent.clone(),
                    ),
                    attempt_started_unix: comment_intent.attempt_started_unix,
                };
                let acknowledgement = self
                    .forge
                    .post_comment(&comment_intent)
                    .map_err(|error| MergeExecutionError::Forge(error.to_string()))?;
                validate_acknowledgement(
                    &acknowledgement,
                    &intent.operation_key,
                    &canonical_digest(&comment_intent).map_err(forge_error)?,
                )?;
                Ok(StepOutcome::Effect {
                    effect_intent: Box::new(effect_intent),
                    acknowledgement,
                })
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
                let assessed_body_digest = approved
                    .subject
                    .prepared_body_digest
                    .as_ref()
                    .ok_or_else(|| {
                        MergeExecutionError::Blocked(
                            "merge assessment does not bind the current PR body".into(),
                        )
                    })?;
                let current_body = live.body.as_deref().unwrap_or_default();
                let current_body_digest = body_digest(current_body)?;
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
                        || prepared_digest != current_body_digest
                    {
                        return Err(MergeExecutionError::Stale(
                            "PR body changed after its reviewed update; refusing merge".into(),
                        ));
                    }
                } else if current_body_digest != *assessed_body_digest {
                    return Err(MergeExecutionError::Stale(
                        "PR body differs from the body digest bound to the merge assessment".into(),
                    ));
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
                let expected_commit_message =
                    merge_commit_message(current_body, &expected_trailers).map_err(forge_error)?;
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
                    expected_body_digest: current_body_digest,
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
                let effect_intent = MergeEffectIntent {
                    pull: effect.pull.clone(),
                    operation_key: intent.operation_key.clone(),
                    request_digest: canonical_digest(&effect).map_err(forge_error)?,
                    operation: crate::forge::MergeEffectOperation::DirectMerge(effect.clone()),
                    attempt_started_unix: intent.attempt_started_unix,
                };
                let ack = self
                    .forge
                    .execute_merge(&effect)
                    .map_err(|error| MergeExecutionError::Forge(error.to_string()))?;
                Ok(StepOutcome::Effect {
                    effect_intent: Box::new(effect_intent),
                    acknowledgement: ack,
                })
            }
            MergeProcedureOperation::VerifyMergeCommit { expected_trailers } => {
                let result = self.verify_merge(
                    pull,
                    &approved.subject,
                    procedure.method,
                    expected_trailers,
                    &observed,
                    prior_receipts,
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
        prior_receipts: &[MergeStepReceipt],
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
            MergeMethod::Merge
                if merge_commit.parents.len() != 2
                    || !merge_commit.parents.contains(&subject.head_sha) =>
            {
                return Err(MergeExecutionError::VerificationFailed(
                    "merge method does not have exactly the approved head and one base parent"
                        .into(),
                ));
            }
            MergeMethod::Squash | MergeMethod::Rebase if merge_commit.parents.len() != 1 => {
                return Err(MergeExecutionError::VerificationFailed(
                    "single-parent merge method does not have exactly one base parent".into(),
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
        let direct_merge = prior_receipts.iter().find(|receipt| {
            receipt.acknowledgement.resulting_merge_sha.as_deref() == Some(merge_sha)
                && matches!(
                    &receipt.effect_intent.operation,
                    crate::forge::MergeEffectOperation::DirectMerge(intent)
                        if intent.method == method
                )
        });
        let method_evidence = match (method, direct_merge) {
            (_, Some(receipt)) => MergeMethodEvidence::DirectMergeAcknowledgement {
                operation_key: receipt.operation_key.clone(),
                request_digest: receipt.request_digest.clone(),
            },
            (MergeMethod::Merge, None) => {
                if merge_commit.parents.len() < 2 {
                    return Err(MergeExecutionError::VerificationFailed(
                        "merge method cannot be verified from the observed commit parents".into(),
                    ));
                }
                MergeMethodEvidence::MergeCommitParents {
                    parent_count: merge_commit.parents.len(),
                }
            }
            (MergeMethod::Squash | MergeMethod::Rebase, None)
                if merge_commit.parents.len() == 1 =>
            {
                MergeMethodEvidence::SingleParentCommit {
                    parent_sha: base_parent.clone(),
                }
            }
            (_, None) => {
                return Err(MergeExecutionError::VerificationFailed(
                    "the observed merged commit does not satisfy the approved method's parent-shape contract".into(),
                ));
            }
        };
        Ok(Some(MergeVerificationReceipt {
            merge_commit_sha: merge_commit.sha,
            included_head_sha: subject.head_sha.clone(),
            base_parent_sha: base_parent,
            merge_method: method,
            method_evidence,
            base_ancestry: MergeBaseAncestryProof {
                comparison_base_sha: comparison.base_sha,
                comparison_head_sha: comparison.head_sha,
                behind_by: comparison.behind_by,
            },
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

fn validate_acknowledgement(
    acknowledgement: &EffectAcknowledgement,
    operation_key: &str,
    request_digest: &Digest,
) -> Result<(), MergeExecutionError> {
    if acknowledgement.operation_key != operation_key
        || &acknowledgement.request_digest != request_digest
    {
        return Err(MergeExecutionError::Invalid(
            "forge acknowledgement does not match the exact durable merge step intent".into(),
        ));
    }
    Ok(())
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

#[allow(clippy::too_many_arguments)]
fn validate_current_step_evidence(
    policy: &MergePolicy,
    approved: &MergeAssessment,
    approved_evidence: &MergeEvidenceSnapshot,
    evidence_now: &MergeEvidenceSnapshot,
    observation: &ForgeObservation,
    pull: &PullRequestRef,
    procedure: &MergeProcedure,
    step_key: &str,
    prior_receipts: &[MergeStepReceipt],
    baseline_issue_comments: &[crate::forge::IssueComment],
) -> Result<(), MergeExecutionError> {
    let baseline_digest = canonical_digest(&baseline_issue_comments).map_err(forge_error)?;
    if baseline_digest != approved.subject.merge_comments_digest
        || !baseline_issue_comments
            .windows(2)
            .all(|pair| pair[0].id < pair[1].id)
    {
        return Err(MergeExecutionError::Invalid(
            "persisted merge comment baseline is not canonical or does not match its approved digest"
                .into(),
        ));
    }
    let selected_index = procedure
        .steps
        .iter()
        .position(|step| step.key == step_key)
        .ok_or_else(|| MergeExecutionError::Invalid("merge step is not in its procedure".into()))?;
    let mut receipts_by_key = BTreeMap::new();
    for receipt in prior_receipts {
        if receipts_by_key
            .insert(receipt.step_key.as_str(), receipt)
            .is_some()
        {
            return Err(MergeExecutionError::Invalid(
                "duplicate durable merge step receipts were supplied".into(),
            ));
        }
    }
    if receipts_by_key.keys().any(|key| {
        !procedure.steps[..selected_index]
            .iter()
            .any(|step| step.key == **key)
    }) {
        return Err(MergeExecutionError::Invalid(
            "a merge step receipt was supplied for a step that is not a prerequisite".into(),
        ));
    }

    let pr = complete_observation(&observation.pull_request)?;
    let terminal_merged_verification = selected_index + 1 == procedure.steps.len()
        && matches!(
            &procedure.steps[selected_index].operation,
            MergeProcedureOperation::VerifyMergeCommit { .. }
        )
        && pr.merged
        && pr.state == crate::forge::PullRequestState::Closed;
    let current_body = pr.body.as_deref().unwrap_or_default();
    let mut expected_body = None;
    let mut expected_extra_comments = Vec::new();
    for prior_step in &procedure.steps[..selected_index] {
        let receipt = receipts_by_key
            .get(prior_step.key.as_str())
            .ok_or_else(|| {
                MergeExecutionError::Blocked(format!(
                    "prior merge step `{}` has no exact durable effect receipt",
                    prior_step.key
                ))
            })?;
        validate_step_receipt(receipt)?;
        match (&prior_step.operation, &receipt.effect_intent.operation) {
            (
                MergeProcedureOperation::UpdatePullRequestBody {
                    expected_prior_body_digest,
                    approved_body_digest,
                },
                crate::forge::MergeEffectOperation::UpdateBody(body),
            ) if body.expected_prior_body_digest == *expected_prior_body_digest
                && body.approved_body_digest == *approved_body_digest
                && body.pull == *pull
                && body.expected_head_sha == approved.subject.head_sha
                && digest_bytes(body.exact_body.as_bytes())? == *approved_body_digest
                && receipt.certainty_is_success() =>
            {
                if expected_body.replace(body.exact_body.as_str()).is_some() {
                    return Err(MergeExecutionError::Invalid(
                        "merge procedure repeats a PR body update".into(),
                    ));
                }
            }
            (
                MergeProcedureOperation::RequestMerge { exact_comment },
                crate::forge::MergeEffectOperation::RequestComment(comment),
            ) if comment.exact_body == *exact_comment
                && comment.pull == *pull
                && comment.expected_head_sha == approved.subject.head_sha
                && comment.expected_base_sha == approved.subject.base_sha
                && receipt.certainty_is_success() =>
            {
                expected_extra_comments.push((receipt, comment));
            }
            (
                MergeProcedureOperation::ExecuteMerge {
                    expected_head_sha,
                    base_guard_rule_digest,
                },
                crate::forge::MergeEffectOperation::DirectMerge(intent),
            ) if selected_index + 1 == procedure.steps.len()
                && matches!(
                    &procedure.steps[selected_index].operation,
                    MergeProcedureOperation::VerifyMergeCommit { expected_trailers }
                        if intent.expected_trailers == *expected_trailers
                )
                && intent.pull == *pull
                && intent.method == procedure.method
                && intent.expected_head_sha == *expected_head_sha
                && intent.expected_head_sha == approved.subject.head_sha
                && intent.expected_base_sha == approved.subject.base_sha
                && Some(base_guard_rule_digest) == approved.subject.base_guard_digest.as_ref()
                && expected_body.is_none_or(|body| body == intent.expected_body.as_str())
                && (expected_body.is_some()
                    || approved.subject.prepared_body_digest.as_ref()
                        == Some(&intent.expected_body_digest))
                && body_digest(&intent.expected_body)
                    .is_ok_and(|digest| digest == intent.expected_body_digest)
                && receipt.certainty_is_success()
                && receipt.acknowledgement.resulting_head_sha.as_deref()
                    == Some(approved.subject.head_sha.as_str())
                && receipt.acknowledgement.resulting_merge_sha.is_some() => {}
            (
                MergeProcedureOperation::ExecuteMerge { .. },
                crate::forge::MergeEffectOperation::DirectMerge(_),
            ) => {
                return Err(MergeExecutionError::Blocked(
                    "a prior direct merge receipt does not match the approved terminal verification step".into(),
                ));
            }
            _ => {
                return Err(MergeExecutionError::Invalid(
                    "a prior step receipt does not match its exact repository procedure operation"
                        .into(),
                ));
            }
        }
    }

    let expected_body_digest = match expected_body {
        Some(body) => Some(digest_bytes(body.as_bytes())?),
        None => approved.subject.prepared_body_digest.clone(),
    };
    let current_body_digest = digest_bytes(current_body.as_bytes())?;
    if expected_body_digest
        .as_ref()
        .is_some_and(|expected| expected != &current_body_digest)
    {
        return Err(MergeExecutionError::Stale(
            "PR body differs from the exact baseline or approved body-update receipt".into(),
        ));
    }
    if let Some(MergeProcedureStep {
        operation:
            MergeProcedureOperation::UpdatePullRequestBody {
                expected_prior_body_digest,
                ..
            },
        ..
    }) = procedure.steps.get(selected_index)
        && digest_bytes(current_body.as_bytes())? != *expected_prior_body_digest
    {
        return Err(MergeExecutionError::Stale(
            "PR body differs from the exact prior digest for the selected body-update step".into(),
        ));
    }

    let observed_comments = complete_observation(&observation.issue_comments)?;
    let mut sorted_comments = observed_comments.clone();
    sorted_comments.sort_by_key(|comment| comment.id);
    for baseline in baseline_issue_comments {
        if sorted_comments
            .iter()
            .find(|comment| comment.id == baseline.id)
            != Some(baseline)
        {
            return Err(MergeExecutionError::Stale(
                "a baseline PR comment changed or disappeared after approval".into(),
            ));
        }
    }
    let expected_count = baseline_issue_comments
        .len()
        .checked_add(expected_extra_comments.len())
        .ok_or_else(|| MergeExecutionError::Invalid("merge comment count overflow".into()))?;
    if !terminal_merged_verification && sorted_comments.len() != expected_count {
        return Err(MergeExecutionError::Stale(
            "unexpected PR comments appeared after the approved merge procedure began".into(),
        ));
    }
    if terminal_merged_verification && sorted_comments.len() < expected_count {
        return Err(MergeExecutionError::Stale(
            "a recorded merge procedure comment is absent after the pull request was merged".into(),
        ));
    }
    for (receipt, comment_intent) in expected_extra_comments {
        let comment_id = receipt
            .acknowledgement
            .external_id
            .as_deref()
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| {
                MergeExecutionError::Stale(
                    "successful merge-request receipt has no typed comment ID".into(),
                )
            })?;
        let matching = sorted_comments
            .iter()
            .filter(|comment| comment.id == comment_id)
            .collect::<Vec<_>>();
        if !matches!(matching.as_slice(), [comment]
            if comment.body == comment_intent.exact_body
                && comment.user.as_deref() == Some(comment_intent.authenticated_actor.as_str()))
        {
            return Err(MergeExecutionError::Stale(
                "recorded merge-request comment is absent or differs from exact approved content/actor"
                    .into(),
            ));
        }
    }

    let remote_digests = observation.semantic_digests().map_err(forge_error)?;
    if evidence_now.subject != evidence_now.current_subject
        || evidence_now.subject.head_sha != pr.head_sha
        || (!terminal_merged_verification && evidence_now.subject.base_sha != pr.base_sha)
        || evidence_now.subject.diff_digest != remote_digests.diff
        || evidence_now.subject.remote_checks_digest != remote_digests.checks
        || evidence_now.subject.review_digest != remote_digests.reviews
        || evidence_now.subject.merge_comments_digest != remote_digests.merge_comments
        || evidence_now.subject.base_guard_digest.as_ref() != Some(&remote_digests.base_guard)
    {
        return Err(MergeExecutionError::Stale(
            "current merge evidence does not match the fresh complete Forge observation".into(),
        ));
    }
    let mut expected_subject = evidence_now.subject.clone();
    if terminal_merged_verification {
        expected_subject.base_sha = approved.subject.base_sha.clone();
        expected_subject.remote_checks_digest = approved.subject.remote_checks_digest.clone();
    }
    expected_subject.prepared_body_digest = approved.subject.prepared_body_digest.clone();
    expected_subject.merge_comments_digest = approved.subject.merge_comments_digest.clone();
    if expected_subject != approved.subject {
        return Err(MergeExecutionError::Stale(
            "a merge subject field outside the recorded body/comment procedure changed".into(),
        ));
    }
    if let Some(expected_body) = expected_body
        && evidence_now.subject.prepared_body_digest.as_ref()
            != Some(&digest_bytes(expected_body.as_bytes())?)
    {
        return Err(MergeExecutionError::Stale(
            "current PR body digest differs from the recorded approved body".into(),
        ));
    }
    let mut normalized = evidence_now.clone();
    normalized.subject = approved_evidence.subject.clone();
    normalized.current_subject = approved_evidence.current_subject.clone();
    if terminal_merged_verification
        && let Some(gate) = normalized
            .gates
            .iter_mut()
            .find(|gate| gate.key == "pull_request_open")
        && gate.state == crate::merge_policy::EvidenceState::Fail
        && let Some(approved_gate) = approved_evidence
            .gates
            .iter()
            .find(|approved_gate| approved_gate.key == gate.key)
    {
        gate.state = approved_gate.state;
        gate.required = approved_gate.required;
        gate.detail = approved_gate.detail.clone();
    }
    if normalized.gates != approved_evidence.gates
        || normalized.risk != approved_evidence.risk
        || normalized.confidence != approved_evidence.confidence
        || normalized.human_review_required != approved_evidence.human_review_required
        || normalized.execution_time_base_guard != approved_evidence.execution_time_base_guard
        || evaluate_merge_policy(policy, &normalized).map_err(MergeExecutionError::Invalid)?
            != *approved
        || digest_merge_evidence(&normalized).map_err(MergeExecutionError::Invalid)?
            != approved.evidence_digest
    {
        return Err(MergeExecutionError::Stale(
            "checks, reviews, risk inputs, confidence, or execution guard changed after approval"
                .into(),
        ));
    }
    Ok(())
}

fn validate_step_receipt(receipt: &MergeStepReceipt) -> Result<(), MergeExecutionError> {
    let operation_digest = match &receipt.effect_intent.operation {
        crate::forge::MergeEffectOperation::UpdateBody(intent) => {
            if intent.operation_key != receipt.operation_key {
                return Err(MergeExecutionError::Invalid(
                    "PR body effect operation key differs from its outbox identity".into(),
                ));
            }
            canonical_digest(intent).map_err(forge_error)?
        }
        crate::forge::MergeEffectOperation::RequestComment(intent) => {
            if intent.operation_key != receipt.operation_key {
                return Err(MergeExecutionError::Invalid(
                    "merge comment operation key differs from its outbox identity".into(),
                ));
            }
            canonical_digest(intent).map_err(forge_error)?
        }
        crate::forge::MergeEffectOperation::DirectMerge(intent) => {
            if intent.operation_key != receipt.operation_key {
                return Err(MergeExecutionError::Invalid(
                    "direct merge operation key differs from its outbox identity".into(),
                ));
            }
            canonical_digest(intent).map_err(forge_error)?
        }
    };
    if receipt.step_key.trim().is_empty()
        || receipt.operation_key != receipt.effect_intent.operation_key
        || receipt.request_digest != operation_digest
        || receipt.request_digest != receipt.effect_intent.request_digest
        || receipt.request_digest != receipt.acknowledgement.request_digest
        || receipt.operation_key != receipt.acknowledgement.operation_key
        || receipt.certainty != receipt.acknowledgement.certainty
    {
        return Err(MergeExecutionError::Invalid(
            "merge step receipt does not match its exact persisted outbox effect".into(),
        ));
    }
    if !receipt.certainty_is_success() {
        return Err(MergeExecutionError::Blocked(
            "prior merge procedure effect is not confirmed applied".into(),
        ));
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
    fn reconciliation_reconstructs_the_exact_durable_direct_merge_request() {
        let (_receipt, _request_id, _, policy, mut assessment, procedure) = human_approval_inputs();
        let assessed_body = "Reviewed body\n";
        let assessed_digest = body_digest(assessed_body).unwrap();
        assessment.subject.prepared_body_digest = Some(assessed_digest.clone());
        let subject = assessment.subject.clone();
        let item = crate::store::merge_work::MergeWorkItem {
            work_id: test_digest('3'),
            project_id: crate::domain::ids::ProjectId::parse("project-a").unwrap(),
            ticket_run_id: crate::domain::ids::TicketRunId::parse("run-a").unwrap(),
            assessed_revision: crate::domain::ids::Revision(4),
            awaiting_merge_revision: crate::domain::ids::Revision(6),
            configuration_digest: subject.config_digest.clone(),
            accepted_plan_digest: test_digest('4'),
            prepared_receipt_digest: test_digest('5'),
            publication_set_digest: test_digest('6'),
            document: crate::store::merge_work::MergeWorkDocument {
                schema_version: 1,
                assessment_id: "assessment-a".into(),
                assessment_evidence_id: "assessment-evidence".into(),
                assessment_result_digest: test_digest('a'),
                intent_evidence_id: "intent-evidence".into(),
                intent_result_digest: test_digest('b'),
                policy: policy.clone(),
                evidence: MergeEvidenceSnapshot {
                    subject: subject.clone(),
                    current_subject: subject.clone(),
                    gates: vec![],
                    risk: vec![],
                    confidence: crate::merge_policy::Confidence::High,
                    human_review_required: true,
                    execution_time_base_guard: crate::merge_policy::EvidenceState::Pass,
                },
                baseline_issue_comments: vec![],
                assessment: assessment.clone(),
                intent: crate::engine::orchestration::MergeIntentPayload {
                    assessment_id: "assessment-a".into(),
                    pr_identities: vec!["PR_1".into()],
                    policy_digest: canonical_digest(&policy).unwrap(),
                    prepared_body_digest: assessed_digest.clone(),
                    steps: vec![],
                    post_merge_verification: vec![],
                },
                authority: ResolvedMergeAuthority {
                    policy_digest: canonical_digest(&policy).unwrap(),
                    instruction_digest: subject.instruction_digest.clone(),
                    sources: BTreeMap::new(),
                    request_comment_proofs: vec![],
                    execution_time_base_guard: crate::merge_policy::EvidenceState::Pass,
                    base_guard_digest: subject.base_guard_digest.clone(),
                },
                procedure: procedure.clone(),
                prepared_body: None,
            },
        };
        let pull = PullRequestRef {
            repository: crate::forge::RepositoryRef {
                host: "github.com".into(),
                owner: "example".into(),
                name: "repo".into(),
                expected_id: Some(10),
            },
            number: 1,
            expected_node_id: Some("PR_1".into()),
        };
        let step_intent = StepIntent {
            operation_key: "outer:merge".into(),
            authenticated_actor: String::new(),
            attempt_started_unix: 123,
            exact_prepared_body: None,
        };
        let first = reconciliation_intent(
            &item,
            &procedure.steps[0],
            &pull,
            &step_intent,
            999,
            123,
            assessed_body,
        )
        .unwrap();
        let second = reconciliation_intent(
            &item,
            &procedure.steps[0],
            &pull,
            &step_intent,
            999,
            123,
            assessed_body,
        )
        .unwrap();
        assert_eq!(first, second);
        assert_eq!(first.attempt_started_unix, 123);
        assert_eq!(
            first.request_digest,
            match &first.operation {
                crate::forge::MergeEffectOperation::DirectMerge(inner) => {
                    canonical_digest(inner).unwrap()
                }
                _ => panic!("expected direct merge operation"),
            }
        );
        assert!(
            reconciliation_intent(
                &item,
                &procedure.steps[0],
                &pull,
                &step_intent,
                999,
                123,
                "changed body",
            )
            .is_err()
        );

        let mut comment_item = item.clone();
        comment_item.document.procedure.steps[0].operation =
            MergeProcedureOperation::RequestMerge {
                exact_comment: "/merge".into(),
            };
        let comment_step = &comment_item.document.procedure.steps[0];
        let comment_intent = StepIntent {
            operation_key: "outer:request".into(),
            authenticated_actor: "reviewer".into(),
            attempt_started_unix: 456,
            exact_prepared_body: None,
        };
        let comment = reconciliation_intent(
            &comment_item,
            comment_step,
            &pull,
            &comment_intent,
            999,
            456,
            assessed_body,
        )
        .unwrap();
        let crate::forge::MergeEffectOperation::RequestComment(comment_inner) = &comment.operation
        else {
            panic!("expected request comment operation");
        };
        assert_eq!(comment_inner.attempt_started_unix, 456);
        assert_eq!(comment_inner.exact_body, "/merge");
        assert_eq!(comment_inner.authenticated_actor, "reviewer");
        assert_eq!(
            comment.request_digest,
            canonical_digest(comment_inner).unwrap()
        );

        let mut body_item = item;
        let target_body = "Reviewed body\n\nCo-authored-by: Agent <agent@example.com>\n";
        let target_digest = body_digest(target_body).unwrap();
        body_item.document.prepared_body = Some(target_body.into());
        body_item.document.procedure.steps[0].operation =
            MergeProcedureOperation::UpdatePullRequestBody {
                expected_prior_body_digest: body_digest(assessed_body).unwrap(),
                approved_body_digest: target_digest.clone(),
            };
        let body_step = &body_item.document.procedure.steps[0];
        let body_intent = StepIntent {
            operation_key: "outer:body".into(),
            authenticated_actor: String::new(),
            attempt_started_unix: 789,
            exact_prepared_body: Some(target_body.into()),
        };
        let body = reconciliation_intent(
            &body_item,
            body_step,
            &pull,
            &body_intent,
            999,
            789,
            assessed_body,
        )
        .unwrap();
        let crate::forge::MergeEffectOperation::UpdateBody(body_inner) = &body.operation else {
            panic!("expected body update operation");
        };
        assert_eq!(body_inner.exact_body, target_body);
        assert_eq!(body_inner.approved_body_digest, target_digest);
        assert_eq!(body.request_digest, canonical_digest(body_inner).unwrap());
    }

    #[derive(Clone)]
    struct ProcedureForge {
        observation: std::sync::Arc<std::sync::Mutex<ForgeObservation>>,
        commit: crate::forge::CommitObservation,
        add_service_comment_after_merge: bool,
        add_post_merge_check: bool,
    }

    impl Forge for ProcedureForge {
        fn observe(&self, _: &PullRequestRef) -> Result<ForgeObservation, ForgeError> {
            Ok(self.observation.lock().unwrap().clone())
        }

        fn observe_commit(
            &self,
            _: &crate::forge::RepositoryRef,
            sha: &str,
        ) -> Result<Observed<crate::forge::CommitObservation>, ForgeError> {
            if self.commit.sha != sha {
                return Err(ForgeError("unexpected commit SHA".into()));
            }
            Ok(Observed::Complete {
                value: self.commit.clone(),
                pages: 1,
                digest: test_digest('a'),
            })
        }

        fn compare_commits(
            &self,
            _: &crate::forge::RepositoryRef,
            base_sha: &str,
            head_sha: &str,
        ) -> Result<Observed<crate::forge::CommitComparison>, ForgeError> {
            Ok(Observed::Complete {
                value: crate::forge::CommitComparison {
                    base_sha: base_sha.into(),
                    head_sha: head_sha.into(),
                    status: "identical".into(),
                    ahead_by: 0,
                    behind_by: 0,
                },
                pages: 1,
                digest: test_digest('b'),
            })
        }

        fn update_body(
            &self,
            intent: &BodyUpdateIntent,
        ) -> Result<EffectAcknowledgement, ForgeError> {
            let mut observation = self.observation.lock().unwrap();
            let Observed::Complete { value, .. } = &mut observation.pull_request else {
                return Err(ForgeError("PR observation is unknown".into()));
            };
            value.body = Some(intent.exact_body.clone());
            Ok(EffectAcknowledgement {
                operation_key: intent.operation_key.clone(),
                request_digest: canonical_digest(intent)?,
                certainty: EffectCertainty::Applied,
                external_id: None,
                external_url: None,
                resulting_head_sha: Some(value.head_sha.clone()),
                resulting_merge_sha: None,
                reason: None,
            })
        }

        fn post_comment(
            &self,
            intent: &CommentIntent,
        ) -> Result<EffectAcknowledgement, ForgeError> {
            let mut observation = self.observation.lock().unwrap();
            let Observed::Complete {
                value: comments, ..
            } = &mut observation.issue_comments
            else {
                return Err(ForgeError("issue comments are unknown".into()));
            };
            comments.push(crate::forge::IssueComment {
                id: 42,
                user: Some(intent.authenticated_actor.clone()),
                body: intent.exact_body.clone(),
                created_at: "2026-11-09T00:00:00Z".into(),
            });
            let Observed::Complete { value: pull, .. } = &observation.pull_request else {
                return Err(ForgeError("PR observation is unknown".into()));
            };
            Ok(EffectAcknowledgement {
                operation_key: intent.operation_key.clone(),
                request_digest: canonical_digest(intent)?,
                certainty: EffectCertainty::Applied,
                external_id: Some("42".into()),
                external_url: None,
                resulting_head_sha: Some(pull.head_sha.clone()),
                resulting_merge_sha: None,
                reason: None,
            })
        }

        fn execute_merge(
            &self,
            intent: &DirectMergeIntent,
        ) -> Result<EffectAcknowledgement, ForgeError> {
            let mut observation = self.observation.lock().unwrap();
            if self.add_service_comment_after_merge {
                let Observed::Complete {
                    value: comments, ..
                } = &mut observation.issue_comments
                else {
                    return Err(ForgeError("issue comments are unknown".into()));
                };
                comments.push(crate::forge::IssueComment {
                    id: 43,
                    user: Some("csm-ci-server[bot]".into()),
                    body: "csm-ci: Merge accepted".into(),
                    created_at: "2026-11-10T15:16:11Z".into(),
                });
            }
            if self.add_post_merge_check {
                let Observed::Complete { value: checks, .. } = &mut observation.check_runs else {
                    return Err(ForgeError("check-run observation is unknown".into()));
                };
                checks.push(crate::forge::CheckRun {
                    id: 2,
                    name: "release / request".into(),
                    head_sha: intent.expected_head_sha.clone(),
                    status: "completed".into(),
                    conclusion: Some("skipped".into()),
                    app_id: Some(1),
                    app_slug: Some("github-actions".into()),
                    check_suite_id: None,
                    workflow_id: Some(2),
                });
            }
            let Observed::Complete { value: pull, .. } = &mut observation.pull_request else {
                return Err(ForgeError("PR observation is unknown".into()));
            };
            pull.state = crate::forge::PullRequestState::Closed;
            pull.merged = true;
            pull.base_sha = "advanced-base".into();
            pull.merge_commit_sha = Some(self.commit.sha.clone());
            Ok(EffectAcknowledgement {
                operation_key: intent.operation_key.clone(),
                request_digest: canonical_digest(intent)?,
                certainty: EffectCertainty::Applied,
                external_id: None,
                external_url: None,
                resulting_head_sha: Some(pull.head_sha.clone()),
                resulting_merge_sha: Some(self.commit.sha.clone()),
                reason: None,
            })
        }

        fn reconcile(&self, _: &MergeEffectIntent) -> Result<Reconciliation, ForgeError> {
            Ok(Reconciliation::Unknown("fixture does not reconcile".into()))
        }
    }

    fn complete<T>(value: T) -> Observed<T> {
        Observed::Complete {
            value,
            pages: 1,
            digest: test_digest('c'),
        }
    }

    fn procedure_evidence(
        observation: &ForgeObservation,
        subject_seed: &MergeSubject,
    ) -> MergeEvidenceSnapshot {
        use crate::merge_policy::{
            Confidence, EvidenceState, GateEvidence, RiskDimension, RiskRating,
        };
        let remote = observation.semantic_digests().unwrap();
        let pull = match &observation.pull_request {
            Observed::Complete { value, .. } => value,
            Observed::Unknown { .. } => panic!("test fixture observation is complete"),
        };
        let mut subject = subject_seed.clone();
        subject.diff_digest = remote.diff;
        subject.remote_checks_digest = remote.checks;
        subject.review_digest = remote.reviews;
        subject.merge_comments_digest = remote.merge_comments;
        subject.base_guard_digest = Some(remote.base_guard);
        subject.base_sha = pull.base_sha.clone();
        subject.base_ref = pull.base_ref.clone();
        subject.prepared_body_digest = pull.body.as_deref().map(|body| body_digest(body).unwrap());
        MergeEvidenceSnapshot {
            subject: subject.clone(),
            current_subject: subject,
            gates: vec![
                GateEvidence {
                    key: "check:ci".into(),
                    state: EvidenceState::Pass,
                    required: true,
                    detail: "CI is green".into(),
                },
                GateEvidence {
                    key: "pull_request_open".into(),
                    state: if pull.state == crate::forge::PullRequestState::Open
                        && !pull.merged
                        && !pull.draft
                    {
                        EvidenceState::Pass
                    } else {
                        EvidenceState::Fail
                    },
                    required: true,
                    detail: format!("PR {} state from current observation", pull.number),
                },
            ],
            risk: [
                RiskDimension::ChangeImpact,
                RiskDimension::Complexity,
                RiskDimension::VerificationGaps,
                RiskDimension::ReviewUncertainty,
                RiskDimension::OperationalExposure,
            ]
            .into_iter()
            .map(|dimension| RiskRating {
                dimension,
                rating: Some(0),
                rationale: "fixture-reviewed".into(),
            })
            .collect(),
            confidence: Confidence::High,
            human_review_required: true,
            execution_time_base_guard: EvidenceState::Pass,
        }
    }

    #[test]
    fn exact_human_approval_covers_body_update_request_comment_and_verified_merge() {
        run_exact_human_approval_procedure(crate::domain::types::MergeExecutor::Direct);
    }

    #[test]
    fn request_executor_acknowledges_comment_then_waits_for_external_merge() {
        run_exact_human_approval_procedure(crate::domain::types::MergeExecutor::Request);
    }

    fn run_exact_human_approval_procedure(executor_kind: crate::domain::types::MergeExecutor) {
        use crate::domain::types::MergeExecutor;
        use crate::merge_policy::{
            EvidenceState, MergeProcedureOperation, MergeProcedureStep, build_merge_procedure,
        };
        let current_body = "Reviewed implementation\n";
        let prepared_body =
            "Reviewed implementation\n\nCo-authored-by: Agent <agent@example.com>\n";
        let expected_trailers = vec!["Co-authored-by: Agent <agent@example.com>".to_owned()];
        let mut subject = test_subject();
        subject.repository_id = "repo".into();
        subject.forge_repository_id = 10;
        subject.pull_request_id = "1".into();
        subject.pull_request_node_id = "PR_1".into();
        subject.head_sha = "head".into();
        subject.base_sha = "base".into();
        subject.base_ref = "main".into();
        subject.prepared_body_digest = Some(body_digest(current_body).unwrap());
        let protection = crate::forge::BranchProtection {
            strict_required_status_checks: true,
            required_check_contexts: vec!["ci".into()],
            required_approving_review_count: None,
            dismiss_stale_reviews: Some(true),
            enforce_admins: true,
            allow_force_pushes: false,
            allow_deletions: false,
            digest: test_digest('9'),
        };
        let observation = ForgeObservation {
            repository: complete(crate::forge::RepositoryIdentity {
                id: 10,
                full_name: "example/repo".into(),
                default_branch: "main".into(),
                allow_merge_commit: true,
                allow_squash_merge: true,
                allow_rebase_merge: true,
            }),
            pull_request: complete(crate::forge::PullRequestObservation {
                repository_id: 10,
                node_id: "PR_1".into(),
                number: 1,
                state: crate::forge::PullRequestState::Open,
                draft: false,
                merged: false,
                head_sha: "head".into(),
                head_ref: "feature".into(),
                base_sha: "base".into(),
                base_ref: "main".into(),
                body: Some(current_body.into()),
                merge_commit_sha: None,
            }),
            files: complete(vec![]),
            check_runs: complete(vec![crate::forge::CheckRun {
                id: 1,
                name: "ci".into(),
                head_sha: "head".into(),
                status: "completed".into(),
                conclusion: Some("success".into()),
                app_id: Some(1),
                app_slug: None,
                check_suite_id: None,
                workflow_id: None,
            }]),
            statuses: complete(vec![]),
            reviews: complete(vec![]),
            review_comments: complete(vec![]),
            review_threads: complete(vec![]),
            issue_comments: complete(vec![]),
            branch_protection: complete(protection),
            merge_commit: complete(None),
            target_comparison: complete(None),
        };
        let evidence = procedure_evidence(&observation, &subject);
        subject = evidence.subject.clone();
        let evidence = MergeEvidenceSnapshot {
            subject: subject.clone(),
            current_subject: subject.clone(),
            ..evidence
        };
        let policy = MergePolicy {
            auto_merge_enabled: false,
            minimum_reliability_score: 0,
            method: MergeMethod::Squash,
            executor: executor_kind,
            required_checks: vec!["ci".into()],
            required_approving_reviews: None,
            risk_weights: RiskWeights::default(),
        };
        let assessment = evaluate_merge_policy(&policy, &evidence).unwrap();
        assert_eq!(assessment.disposition, MergeDisposition::HumanRequired);
        let procedure = build_merge_procedure(
            policy.method,
            policy.executor,
            vec![
                MergeProcedureStep {
                    key: "body".into(),
                    prerequisites: vec![],
                    operation: MergeProcedureOperation::UpdatePullRequestBody {
                        expected_prior_body_digest: body_digest(current_body).unwrap(),
                        approved_body_digest: body_digest(prepared_body).unwrap(),
                    },
                    instruction_digest: subject.instruction_digest.clone(),
                },
                MergeProcedureStep {
                    key: "merge".into(),
                    prerequisites: vec!["body".into()],
                    operation: match executor_kind {
                        MergeExecutor::Direct => MergeProcedureOperation::ExecuteMerge {
                            expected_head_sha: subject.head_sha.clone(),
                            base_guard_rule_digest: subject.base_guard_digest.clone().unwrap(),
                        },
                        MergeExecutor::Request => MergeProcedureOperation::RequestMerge {
                            exact_comment: "/merge".into(),
                        },
                    },
                    instruction_digest: subject.instruction_digest.clone(),
                },
                MergeProcedureStep {
                    key: "verify".into(),
                    prerequisites: vec!["merge".into()],
                    operation: MergeProcedureOperation::VerifyMergeCommit {
                        expected_trailers: expected_trailers.clone(),
                    },
                    instruction_digest: subject.instruction_digest.clone(),
                },
            ],
            &subject,
        )
        .unwrap();
        let policy_digest = canonical_digest(&policy).unwrap();
        let source_bytes = b"/merge\n".to_vec();
        let source = TrustedInstructionSource {
            key: "inline:merge.instructions".into(),
            digest: digest_bytes(&source_bytes).unwrap(),
            bytes: source_bytes,
        };
        let authority = ResolvedMergeAuthority {
            policy_digest: policy_digest.clone(),
            instruction_digest: subject.instruction_digest.clone(),
            sources: BTreeMap::from([(source.key.clone(), source.clone())]),
            request_comment_proofs: if executor_kind == MergeExecutor::Request {
                vec![RequestCommentProof {
                    source_key: source.key.clone(),
                    source_digest: source.digest.clone(),
                    byte_start: 0,
                    exact_comment: "/merge".into(),
                }]
            } else {
                Vec::new()
            },
            execution_time_base_guard: EvidenceState::Pass,
            base_guard_digest: subject.base_guard_digest.clone(),
        };
        let request_id = HumanRequestId::parse("merge-review-test").unwrap();
        let subject_digest = test_digest('8');
        let host_receipt = AcceptedReceipt {
            request_id: request_id.clone(),
            response_id: "approved-response".into(),
            subject_digest: subject_digest.clone(),
            configuration_digest: subject.config_digest.clone(),
            policy_digest: policy_digest.clone(),
            approved: true,
            decided_at_unix: 100,
            expires_at_unix: u64::MAX,
        };
        let approval = HumanMergeApproval::from_host_validated_receipt(
            &host_receipt,
            &request_id,
            &subject_digest,
            &policy,
            &assessment,
            &procedure,
        )
        .unwrap();
        let commit_message = merge_commit_message(prepared_body, &expected_trailers).unwrap();
        let commit = crate::forge::CommitObservation {
            sha: "merge-sha".into(),
            tree_sha: "tree".into(),
            parents: vec!["advanced-base".into()],
            message: commit_message,
        };
        let forge = ProcedureForge {
            observation: std::sync::Arc::new(std::sync::Mutex::new(observation.clone())),
            commit,
            add_service_comment_after_merge: true,
            add_post_merge_check: true,
        };
        let executor = MergeProcedureExecutor::new(forge.clone());
        let pull = PullRequestRef {
            repository: crate::forge::RepositoryRef {
                host: "github.com".into(),
                owner: "example".into(),
                name: "repo".into(),
                expected_id: Some(10),
            },
            number: 1,
            expected_node_id: Some("PR_1".into()),
        };
        let mut unexpected_before_merge = forge.observe(&pull).unwrap();
        let Observed::Complete {
            value: comments, ..
        } = &mut unexpected_before_merge.issue_comments
        else {
            panic!("fixture issue comments are complete");
        };
        comments.push(crate::forge::IssueComment {
            id: 41,
            user: Some("unexpected-user".into()),
            body: "unreviewed comment".into(),
            created_at: "2026-11-10T15:00:00Z".into(),
        });
        let unexpected_forge = ProcedureForge {
            observation: std::sync::Arc::new(std::sync::Mutex::new(
                unexpected_before_merge.clone(),
            )),
            commit: forge.commit.clone(),
            add_service_comment_after_merge: false,
            add_post_merge_check: false,
        };
        let unexpected_executor = MergeProcedureExecutor::new(unexpected_forge);
        let unexpected_evidence = procedure_evidence(&unexpected_before_merge, &subject);
        let unexpected_result = unexpected_executor.execute_one(
            &pull,
            &policy,
            &assessment,
            &evidence,
            &unexpected_evidence,
            Some(&approval),
            &authority,
            &procedure,
            &[],
            "body",
            &StepIntent {
                operation_key: "outbox:unexpected:body".into(),
                authenticated_actor: String::new(),
                attempt_started_unix: 199,
                exact_prepared_body: Some(prepared_body.into()),
            },
            &[],
        );
        assert!(matches!(
            unexpected_result,
            Err(MergeExecutionError::Stale(_))
        ));

        let mut unexpected_check = observation.clone();
        let Observed::Complete { value: checks, .. } = &mut unexpected_check.check_runs else {
            panic!("fixture check-run observation is complete");
        };
        checks.push(crate::forge::CheckRun {
            id: 2,
            name: "release / request".into(),
            head_sha: subject.head_sha.clone(),
            status: "completed".into(),
            conclusion: Some("skipped".into()),
            app_id: Some(1),
            app_slug: Some("github-actions".into()),
            check_suite_id: None,
            workflow_id: Some(2),
        });
        let unexpected_check_evidence = procedure_evidence(&unexpected_check, &subject);
        let check_only_forge = ProcedureForge {
            observation: std::sync::Arc::new(std::sync::Mutex::new(unexpected_check.clone())),
            commit: forge.commit.clone(),
            add_service_comment_after_merge: false,
            add_post_merge_check: false,
        };
        let check_only_result = MergeProcedureExecutor::new(check_only_forge).execute_one(
            &pull,
            &policy,
            &assessment,
            &evidence,
            &unexpected_check_evidence,
            Some(&approval),
            &authority,
            &procedure,
            &[],
            "body",
            &StepIntent {
                operation_key: "outbox:unexpected:check".into(),
                authenticated_actor: String::new(),
                attempt_started_unix: 199,
                exact_prepared_body: Some(prepared_body.into()),
            },
            &[],
        );
        assert!(matches!(
            check_only_result,
            Err(MergeExecutionError::Stale(reason))
                if reason == "a merge subject field outside the recorded body/comment procedure changed"
        ));

        if executor_kind == MergeExecutor::Request {
            let mut receipts = Vec::new();
            let actor = "reviewer@example.com";
            for (index, key) in ["body", "merge"].into_iter().enumerate() {
                let observation_now = forge.observe(&pull).unwrap();
                let evidence_now = procedure_evidence(&observation_now, &subject);
                let intent = StepIntent {
                    operation_key: format!("outbox:request:{index}:{key}"),
                    authenticated_actor: if key == "merge" {
                        actor.into()
                    } else {
                        String::new()
                    },
                    attempt_started_unix: 300 + index as u64,
                    exact_prepared_body: Some(prepared_body.into()),
                };
                let StepOutcome::Effect {
                    effect_intent,
                    acknowledgement,
                } = executor
                    .execute_one(
                        &pull,
                        &policy,
                        &assessment,
                        &evidence,
                        &evidence_now,
                        Some(&approval),
                        &authority,
                        &procedure,
                        &[],
                        key,
                        &intent,
                        &receipts,
                    )
                    .unwrap()
                else {
                    panic!("body and request steps produce effects")
                };
                if key == "merge" {
                    let crate::forge::MergeEffectOperation::RequestComment(comment) =
                        &effect_intent.operation
                    else {
                        panic!("Request step records a comment intent");
                    };
                    assert_eq!(comment.exact_body, "/merge");
                    assert_eq!(comment.authenticated_actor, actor);
                    assert_eq!(comment.attempt_started_unix, 301);
                    assert_eq!(acknowledgement.external_id.as_deref(), Some("42"));
                    assert_eq!(acknowledgement.resulting_merge_sha, None);
                    let observation_after_comment = forge.observe(&pull).unwrap();
                    let Observed::Complete { value: pr, .. } =
                        observation_after_comment.pull_request
                    else {
                        panic!("fixture PR observation is complete");
                    };
                    assert_eq!(pr.state, crate::forge::PullRequestState::Open);
                    assert!(!pr.merged);
                    assert_eq!(pr.merge_commit_sha, None);
                    let Observed::Complete {
                        value: comments, ..
                    } = observation_after_comment.issue_comments
                    else {
                        panic!("fixture comments observation is complete");
                    };
                    assert!(comments.iter().any(|comment| {
                        comment.id.to_string()
                            == acknowledgement.external_id.as_deref().unwrap_or_default()
                            && comment.user.as_deref() == Some(actor)
                            && comment.body == "/merge"
                    }));
                }
                receipts.push(MergeStepReceipt {
                    step_key: key.into(),
                    operation_key: intent.operation_key,
                    certainty: acknowledgement.certainty,
                    request_digest: effect_intent.request_digest.clone(),
                    effect_intent: *effect_intent,
                    acknowledgement,
                });
            }
            let pending_observation = forge.observe(&pull).unwrap();
            let pending_evidence = procedure_evidence(&pending_observation, &subject);
            assert!(matches!(
                executor
                    .execute_one(
                        &pull,
                        &policy,
                        &assessment,
                        &evidence,
                        &pending_evidence,
                        Some(&approval),
                        &authority,
                        &procedure,
                        &[],
                        "verify",
                        &StepIntent {
                            operation_key: "outbox:request:verify-pending".into(),
                            authenticated_actor: actor.into(),
                            attempt_started_unix: 302,
                            exact_prepared_body: Some(prepared_body.into()),
                        },
                        &receipts,
                    )
                    .unwrap(),
                StepOutcome::Pending(_)
            ));
            {
                let mut observed = forge.observation.lock().unwrap();
                let Observed::Complete { value: pr, .. } = &mut observed.pull_request else {
                    panic!("fixture PR observation is complete");
                };
                pr.state = crate::forge::PullRequestState::Closed;
                pr.merged = true;
                pr.merge_commit_sha = Some(forge.commit.sha.clone());
            }
            let merged_observation = forge.observe(&pull).unwrap();
            let merged_evidence = procedure_evidence(&merged_observation, &subject);
            let outcome = executor
                .execute_one(
                    &pull,
                    &policy,
                    &assessment,
                    &evidence,
                    &merged_evidence,
                    Some(&approval),
                    &authority,
                    &procedure,
                    &[],
                    "verify",
                    &StepIntent {
                        operation_key: "outbox:request:verify-merged".into(),
                        authenticated_actor: actor.into(),
                        attempt_started_unix: 303,
                        exact_prepared_body: Some(prepared_body.into()),
                    },
                    &receipts,
                )
                .unwrap();
            assert!(
                matches!(outcome, StepOutcome::Verified(ref receipt) if receipt.merge_commit_sha == "merge-sha")
            );
            return;
        }

        let mut receipts = Vec::new();
        for (index, key) in ["body", "merge", "verify"].into_iter().enumerate() {
            let observation_now = forge.observe(&pull).unwrap();
            let evidence_now = procedure_evidence(&observation_now, &subject);
            let intent = StepIntent {
                operation_key: format!("outbox:{index}:{key}"),
                authenticated_actor: String::new(),
                attempt_started_unix: 200 + index as u64,
                exact_prepared_body: Some(prepared_body.into()),
            };
            let outcome = executor
                .execute_one(
                    &pull,
                    &policy,
                    &assessment,
                    &evidence,
                    &evidence_now,
                    Some(&approval),
                    &authority,
                    &procedure,
                    &[],
                    key,
                    &intent,
                    &receipts,
                )
                .unwrap();
            match outcome {
                StepOutcome::Effect {
                    effect_intent,
                    acknowledgement,
                } => receipts.push(MergeStepReceipt {
                    step_key: key.into(),
                    operation_key: intent.operation_key,
                    certainty: acknowledgement.certainty,
                    request_digest: effect_intent.request_digest.clone(),
                    effect_intent: *effect_intent,
                    acknowledgement,
                }),
                StepOutcome::Verified(verified) => {
                    assert_eq!(verified.merge_commit_sha, "merge-sha");
                    assert_eq!(verified.included_head_sha, subject.head_sha);
                    assert_eq!(verified.base_parent_sha, "advanced-base");
                    assert_eq!(verified.base_ancestry.comparison_base_sha, subject.base_sha);
                    assert_eq!(verified.base_ancestry.comparison_head_sha, "advanced-base");
                    assert_eq!(verified.base_ancestry.behind_by, 0);
                    assert_eq!(verified.merge_method, MergeMethod::Squash);
                    assert_eq!(verified.expected_trailers, expected_trailers);
                }
                StepOutcome::Pending(reason) => panic!("fixture merge should verify: {reason}"),
            }
        }
        let mut forge_observation = forge.observation.lock().unwrap();
        let Observed::Complete { value: checks, .. } = &mut forge_observation.check_runs else {
            panic!("fixture check-run observation is complete");
        };
        checks.push(crate::forge::CheckRun {
            id: 3,
            name: "ci".into(),
            head_sha: subject.head_sha.clone(),
            status: "completed".into(),
            conclusion: Some("failure".into()),
            app_id: Some(1),
            app_slug: Some("github-actions".into()),
            check_suite_id: None,
            workflow_id: Some(1),
        });
        let merged_observation = forge_observation.clone();
        drop(forge_observation);
        let mut failed_required_gate = procedure_evidence(&merged_observation, &subject);
        failed_required_gate
            .gates
            .iter_mut()
            .find(|gate| gate.key == "check:ci")
            .unwrap()
            .state = crate::merge_policy::EvidenceState::Fail;
        assert!(matches!(
            executor.execute_one(
                &pull,
                &policy,
                &assessment,
                &evidence,
                &failed_required_gate,
                Some(&approval),
                &authority,
                &procedure,
                &[],
                "verify",
                &StepIntent {
                    operation_key: "outbox:failed-required-check".into(),
                    authenticated_actor: String::new(),
                    attempt_started_unix: 203,
                    exact_prepared_body: Some(prepared_body.into()),
                },
                &receipts,
            ),
            Err(MergeExecutionError::Stale(_))
        ));
        assert_eq!(receipts.len(), 2);
        assert!(matches!(
            receipts[0].effect_intent.operation,
            crate::forge::MergeEffectOperation::UpdateBody(_)
        ));
        assert!(matches!(
            receipts[1].effect_intent.operation,
            crate::forge::MergeEffectOperation::DirectMerge(_)
        ));
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
