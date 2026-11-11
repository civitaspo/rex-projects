//! Durable aggregate merge work storage schema.

use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::Digest as _;

use crate::domain::ids::{Digest, ProjectId, Revision, TicketRunId};

type MergeAuthorityRow = (String, String, String, Option<String>, Option<u64>, String);
type MergeWorkItemRow = (
    String,
    String,
    u64,
    u64,
    String,
    String,
    String,
    String,
    String,
    String,
);

/// Host-owned assessment snapshot passed to the next MergeDecision turn. The wake is immutable
/// for the TicketRun revision and includes every input used by the policy evaluation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedMergeBodyProposal {
    pub schema_version: u32,
    pub assessment_id: Digest,
    pub publication_set_digest: Digest,
    pub prior_body_present: bool,
    pub prior_body_digest: Option<Digest>,
    pub exact_target_body: String,
    pub target_body_digest: Digest,
    pub expected_trailers: Vec<String>,
}

impl PreparedMergeBodyProposal {
    fn validate(&self) -> Result<(), String> {
        let target_digest = Digest::parse(format!(
            "{:x}",
            sha2::Sha256::digest(self.exact_target_body.as_bytes())
        ))?;
        let tail = self
            .exact_target_body
            .lines()
            .rev()
            .take(self.expected_trailers.len())
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>();
        if self.schema_version != 1
            || self.expected_trailers.is_empty()
            || self
                .expected_trailers
                .iter()
                .any(|line| line.trim().is_empty())
            || self.prior_body_digest.is_none()
            || (!self.prior_body_present
                && self.prior_body_digest
                    != Some(Digest::parse(format!("{:x}", sha2::Sha256::digest([])))?))
            || self.exact_target_body.len() > 256 * 1024
            || target_digest != self.target_body_digest
            || tail
                .iter()
                .map(|line| (*line).to_owned())
                .collect::<Vec<_>>()
                != self.expected_trailers
        {
            return Err(
                "prepared merge body proposal is malformed or has an invalid digest".into(),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedMergeAssessment {
    pub schema_version: u32,
    pub assessment_id: Digest,
    pub project_id: ProjectId,
    pub ticket_run_id: TicketRunId,
    pub revision: Revision,
    pub configuration_digest: Digest,
    pub source_evidence_id: String,
    pub source_result_digest: Digest,
    pub publication_set_digest: Digest,
    pub pull_request_reference: String,
    pub policy_digest: Digest,
    pub policy: crate::merge_policy::MergePolicy,
    pub evidence: crate::merge_policy::MergeEvidenceSnapshot,
    pub assessment: crate::merge_policy::MergeAssessment,
    pub baseline_issue_comments: Vec<crate::forge::IssueComment>,
    #[serde(default)]
    pub prepared_body_proposal: Option<PreparedMergeBodyProposal>,
}

impl TrustedMergeAssessment {
    pub fn validate(&self) -> Result<(), String> {
        let Some(proposal) = &self.prepared_body_proposal else {
            return Err("trusted MergeAssessment has no host-prepared PR body proposal".into());
        };
        proposal.validate()?;
        if self.schema_version != 1
            || self.source_evidence_id.trim().is_empty()
            || self.pull_request_reference.trim().is_empty()
            || self.evidence.subject != self.evidence.current_subject
            || self.evidence.subject.config_digest != self.configuration_digest
            || self.assessment.subject != self.evidence.subject
            || self.assessment.evidence_digest
                != crate::merge_policy::digest_merge_evidence(&self.evidence)?
            || self.assessment
                != crate::merge_policy::evaluate_merge_policy(&self.policy, &self.evidence)?
            || crate::forge::canonical_digest(&self.policy).map_err(|error| error.to_string())?
                != self.policy_digest
            || proposal.assessment_id != self.assessment_id
            || proposal.publication_set_digest != self.publication_set_digest
            || proposal.prior_body_digest != self.evidence.subject.prepared_body_digest
        {
            return Err(
                "trusted MergeAssessment does not match its host policy/evidence snapshot".into(),
            );
        }
        let mut comments = self.baseline_issue_comments.clone();
        comments.sort_by_key(|comment| comment.id);
        if comments != self.baseline_issue_comments
            || crate::forge::canonical_digest(&comments).map_err(|error| error.to_string())?
                != self.evidence.subject.merge_comments_digest
        {
            return Err(
                "trusted MergeAssessment comments do not match the observed subject".into(),
            );
        }
        Ok(())
    }
}

/// Complete immutable evidence and repository-specific procedure accepted for one merge decision.
/// Agent claims are retained for provenance, while `assessment` and `evidence` are host-derived.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MergeWorkDocument {
    pub schema_version: u32,
    pub assessment_id: String,
    pub assessment_evidence_id: String,
    pub assessment_result_digest: Digest,
    pub intent_evidence_id: String,
    pub intent_result_digest: Digest,
    pub policy: crate::merge_policy::MergePolicy,
    pub evidence: crate::merge_policy::MergeEvidenceSnapshot,
    /// Complete issue-comment baseline used to prove that later merge-command comments are the
    /// only permitted mutation of the reviewed comment surface.
    pub baseline_issue_comments: Vec<crate::forge::IssueComment>,
    pub assessment: crate::merge_policy::MergeAssessment,
    pub intent: crate::engine::orchestration::MergeIntentPayload,
    pub authority: crate::merge_executor::ResolvedMergeAuthority,
    pub procedure: crate::merge_policy::MergeProcedure,
    /// Exact host-constructed PR body presented to a human before any non-atomic body update.
    #[serde(default)]
    pub prepared_body: Option<String>,
}

impl MergeWorkDocument {
    pub fn validate_for(
        &self,
        configuration_digest: &Digest,
        assessment_id: &str,
    ) -> Result<(), String> {
        use crate::merge_policy::{
            MergeProcedureOperation as Operation, digest_merge_evidence, evaluate_merge_policy,
        };

        if self.schema_version != 1
            || self.assessment_id != assessment_id
            || self.assessment_evidence_id.trim().is_empty()
            || self.intent_evidence_id.trim().is_empty()
            || self.intent.assessment_id != assessment_id
            || self.evidence.subject != self.evidence.current_subject
            || self.evidence.subject.config_digest != *configuration_digest
            || self.assessment.subject != self.evidence.subject
            || self.assessment.evidence_digest != digest_merge_evidence(&self.evidence)?
            || evaluate_merge_policy(&self.policy, &self.evidence)? != self.assessment
        {
            return Err(
                "merge work document does not match its trusted evidence and assessment".into(),
            );
        }
        let mut baseline_comments = self.baseline_issue_comments.clone();
        baseline_comments.sort_by_key(|comment| comment.id);
        if baseline_comments != self.baseline_issue_comments
            || crate::forge::canonical_digest(&self.baseline_issue_comments)
                .map_err(|error| error.to_string())?
                != self.evidence.subject.merge_comments_digest
        {
            return Err(
                "merge work comment baseline does not match the reviewed comment digest".into(),
            );
        }
        let policy_digest =
            crate::forge::canonical_digest(&self.policy).map_err(|error| error.to_string())?;
        if self.authority.policy_digest != policy_digest
            || self.intent.policy_digest != policy_digest
            || self.authority.instruction_digest != self.evidence.subject.instruction_digest
            || self.authority.base_guard_digest != self.evidence.subject.base_guard_digest
            || self.procedure.method != self.policy.method
            || self.procedure.executor != self.policy.executor
            || self.procedure.steps.len() != self.intent.steps.len()
            || self.procedure.steps.is_empty()
            || self.intent.post_merge_verification.is_empty()
        {
            return Err(
                "merge work document has stale policy, instructions, or procedure identity".into(),
            );
        }
        let validated_procedure = crate::merge_policy::build_merge_procedure(
            self.procedure.method,
            self.procedure.executor,
            self.procedure.steps.clone(),
            &self.evidence.subject,
        )?;
        if validated_procedure != self.procedure {
            return Err(
                "stored merge procedure is not canonical for its policy and subject".into(),
            );
        }
        let body_step = self.procedure.steps.iter().find_map(|step| {
            if let Operation::UpdatePullRequestBody {
                expected_prior_body_digest,
                approved_body_digest,
            } = &step.operation
            {
                Some((expected_prior_body_digest, approved_body_digest))
            } else {
                None
            }
        });
        match (&self.prepared_body, body_step) {
            (Some(body), Some((prior_digest, approved_digest))) => {
                let observed_prior = self.evidence.subject.prepared_body_digest.as_ref();
                let body_digest =
                    Digest::parse(format!("{:x}", sha2::Sha256::digest(body.as_bytes())))?;
                if observed_prior != Some(prior_digest) || &body_digest != approved_digest {
                    return Err("prepared PR body bytes do not match the exact prior and approved body digests".into());
                }
            }
            (None, None) => {}
            _ => {
                return Err(
                    "merge body-update procedure must carry its exact host-prepared body".into(),
                );
            }
        }
        for (host_step, agent_step) in self.procedure.steps.iter().zip(&self.intent.steps) {
            if host_step.instruction_digest != self.authority.instruction_digest {
                return Err(
                    "merge procedure step is not bound to the trusted instruction snapshot".into(),
                );
            }
            let kind_matches = matches!(
                (&host_step.operation, agent_step.kind),
                (
                    Operation::UpdatePullRequestBody { .. },
                    crate::engine::orchestration::MergeProcedureStepKind::UpdatePullRequestBody
                ) | (
                    Operation::RequestMerge { .. },
                    crate::engine::orchestration::MergeProcedureStepKind::RequestMerge
                ) | (
                    Operation::ExecuteMerge { .. },
                    crate::engine::orchestration::MergeProcedureStepKind::DirectMerge
                ) | (
                    Operation::VerifyMergeCommit { .. },
                    crate::engine::orchestration::MergeProcedureStepKind::VerifyMergeCommit
                )
            );
            if !kind_matches || agent_step.instruction_reference.trim().is_empty() {
                return Err("agent merge steps do not match the host-resolved procedure".into());
            }
            if let Operation::UpdatePullRequestBody {
                approved_body_digest,
                ..
            } = &host_step.operation
                && approved_body_digest != &self.intent.prepared_body_digest
            {
                return Err("prepared PR body differs from the body bound by the procedure".into());
            }
        }
        if !matches!(
            self.procedure.steps.last().map(|step| &step.operation),
            Some(Operation::VerifyMergeCommit { .. })
        ) {
            return Err(
                "merge procedure must end with host verification of the merge commit".into(),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MergeWorkItem {
    pub work_id: Digest,
    pub project_id: ProjectId,
    pub ticket_run_id: TicketRunId,
    pub assessed_revision: Revision,
    pub awaiting_merge_revision: Revision,
    pub configuration_digest: Digest,
    pub accepted_plan_digest: Digest,
    pub prepared_receipt_digest: Digest,
    pub publication_set_digest: Digest,
    pub document: MergeWorkDocument,
}

#[derive(Serialize)]
struct MergeWorkDigestInput<'a> {
    schema_version: u32,
    project_id: &'a ProjectId,
    ticket_run_id: &'a TicketRunId,
    assessed_revision: Revision,
    awaiting_merge_revision: Revision,
    configuration_digest: &'a Digest,
    accepted_plan_digest: &'a Digest,
    prepared_receipt_digest: &'a Digest,
    publication_set_digest: &'a Digest,
    document: &'a MergeWorkDocument,
}

impl MergeWorkItem {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project_id: ProjectId,
        ticket_run_id: TicketRunId,
        assessed_revision: Revision,
        awaiting_merge_revision: Revision,
        configuration_digest: Digest,
        accepted_plan_digest: Digest,
        prepared_receipt_digest: Digest,
        publication_set_digest: Digest,
        document: MergeWorkDocument,
    ) -> Result<Self, String> {
        if document.schema_version != 1
            || assessed_revision.0 == 0
            || awaiting_merge_revision.0 <= assessed_revision.0
            || document.assessment_id.trim().is_empty()
            || document.assessment_evidence_id.trim().is_empty()
            || document.intent_evidence_id.trim().is_empty()
        {
            return Err("merge work item has an invalid schema, identity, or revision".into());
        }
        let work_id = Self::digest_input(
            &project_id,
            &ticket_run_id,
            assessed_revision,
            awaiting_merge_revision,
            &configuration_digest,
            &accepted_plan_digest,
            &prepared_receipt_digest,
            &publication_set_digest,
            &document,
        )?;
        Ok(Self {
            work_id,
            project_id,
            ticket_run_id,
            assessed_revision,
            awaiting_merge_revision,
            configuration_digest,
            accepted_plan_digest,
            prepared_receipt_digest,
            publication_set_digest,
            document,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn digest_input(
        project_id: &ProjectId,
        ticket_run_id: &TicketRunId,
        assessed_revision: Revision,
        awaiting_merge_revision: Revision,
        configuration_digest: &Digest,
        accepted_plan_digest: &Digest,
        prepared_receipt_digest: &Digest,
        publication_set_digest: &Digest,
        document: &MergeWorkDocument,
    ) -> Result<Digest, String> {
        let value = MergeWorkDigestInput {
            schema_version: 1,
            project_id,
            ticket_run_id,
            assessed_revision,
            awaiting_merge_revision,
            configuration_digest,
            accepted_plan_digest,
            prepared_receipt_digest,
            publication_set_digest,
            document,
        };
        let json = crate::store::canonical_json(&value)?;
        Digest::parse(format!("{:x}", sha2::Sha256::digest(json.as_bytes())))
    }

    fn body_json(&self) -> Result<String, String> {
        let input = MergeWorkDigestInput {
            schema_version: 1,
            project_id: &self.project_id,
            ticket_run_id: &self.ticket_run_id,
            assessed_revision: self.assessed_revision,
            awaiting_merge_revision: self.awaiting_merge_revision,
            configuration_digest: &self.configuration_digest,
            accepted_plan_digest: &self.accepted_plan_digest,
            prepared_receipt_digest: &self.prepared_receipt_digest,
            publication_set_digest: &self.publication_set_digest,
            document: &self.document,
        };
        crate::store::canonical_json(&input)
    }

    fn validate(&self) -> Result<String, String> {
        self.document
            .validate_for(&self.configuration_digest, &self.document.assessment_id)?;
        let expected = Self::digest_input(
            &self.project_id,
            &self.ticket_run_id,
            self.assessed_revision,
            self.awaiting_merge_revision,
            &self.configuration_digest,
            &self.accepted_plan_digest,
            &self.prepared_receipt_digest,
            &self.publication_set_digest,
            &self.document,
        )?;
        if expected != self.work_id {
            return Err("merge work item digest does not match its immutable contents".into());
        }
        self.body_json()
    }
}

impl crate::store::ConfigStore {
    /// Reload and validate the immutable host assessment wake that authorized a MergeIntent
    /// turn. The row is selected by the exact TicketRun revision; caller supplied assessment IDs
    /// never select an untrusted free-standing snapshot.
    pub fn trusted_merge_assessment(
        &self,
        project_id: &ProjectId,
        ticket_run_id: &TicketRunId,
        revision: Revision,
    ) -> Result<Option<TrustedMergeAssessment>, String> {
        let session = format!("ticket_run:{ticket_run_id}:merge_decision");
        let row: Option<(String, String)> = self.connection.query_row(
            "SELECT source_id,payload_json FROM role_wake_inputs WHERE project_id=?1 AND role_session_id=?2 AND source_type='host_merge_assessment' AND source_revision=?3 AND lifecycle IN ('pending','claimed','consumed') ORDER BY created_at_unix DESC LIMIT 1",
            params![project_id.as_str(), session, revision.0],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional().map_err(|error| error.to_string())?;
        let Some((source_id, payload)) = row else {
            return Ok(None);
        };
        let value: serde_json::Value = crate::protocol::parse_unique(payload.as_bytes())?;
        if value["schema_version"].as_u64() != Some(1)
            || value["kind"].as_str() != Some("trusted_merge_assessment")
        {
            return Err("stored MergeDecision wake has an invalid envelope".into());
        }
        let assessment: TrustedMergeAssessment =
            serde_json::from_value(value["assessment"].clone())
                .map_err(|error| format!("stored trusted MergeAssessment is invalid: {error}"))?;
        assessment.validate()?;
        if assessment.project_id != *project_id
            || assessment.ticket_run_id != *ticket_run_id
            || assessment.revision != revision
            || assessment.assessment_id.as_str() != source_id
            || crate::store::canonical_json(&serde_json::json!({
                "schema_version": 1,
                "kind": "trusted_merge_assessment",
                "assessment": assessment,
            }))? != payload
        {
            return Err(
                "stored trusted MergeAssessment wake is not bound to its row identity".into(),
            );
        }
        Ok(Some(assessment))
    }

    /// Persist a host-validated assessment as the exact same-revision wake for the MergeDecision
    /// session and acknowledge its source Agent result in one SQLite transaction.
    pub fn persist_trusted_merge_assessment(
        &mut self,
        owner_generation: u64,
        result: &crate::store::agent_results::IngestedAgentResult,
        assessment: &TrustedMergeAssessment,
        now_unix: i64,
    ) -> Result<bool, String> {
        assessment.validate()?;
        let binding = &result.validated.binding;
        let ticket_run_id = binding
            .ticket_run_id
            .as_ref()
            .ok_or("MergeAssessment result has no TicketRun scope")?;
        if binding.role != crate::domain::types::Role::MergeDecision
            || result.validated.kind
                != crate::engine::orchestration::RoleOutputKind::MergeAssessment
            || result.validated.assertion != crate::engine::orchestration::AgentAssertion::Succeeded
            || binding.project_id != assessment.project_id
            || ticket_run_id != &assessment.ticket_run_id
            || binding.ticket_revision != Some(assessment.revision)
            || binding.config_digest != assessment.configuration_digest
            || result.validated.result_digest != assessment.source_result_digest
            || result.receipt.evidence_id() != assessment.source_evidence_id
        {
            return Err("trusted MergeAssessment does not match its validated Agent result".into());
        }

        let wake_session = format!("ticket_run:{}:merge_decision", assessment.ticket_run_id);
        if binding.role_session_id.as_str() != wake_session {
            return Err(
                "MergeAssessment source does not belong to the canonical role session".into(),
            );
        }
        let wake_payload = crate::store::canonical_json(&serde_json::json!({
            "schema_version": 1,
            "kind": "trusted_merge_assessment",
            "assessment": assessment,
        }))?;
        if wake_payload.len() > 512 * 1024 {
            return Err("trusted MergeAssessment wake exceeds its size limit".into());
        }

        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        super::validate_active_generation(&tx, owner_generation)?;
        let current: Option<(String, u64, String, String)> = tx
            .query_row(
                "SELECT internal_phase,revision,config_digest,project_id FROM ticket_runs WHERE ticket_run_id=?1",
                [assessment.ticket_run_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if !matches!(current, Some((ref phase, revision, ref digest, ref project))
            if phase == "assessing"
                && revision == assessment.revision.0
                && digest == assessment.configuration_digest.as_str()
                && project == assessment.project_id.as_str())
        {
            return Err(
                "MergeAssessment is stale or outside the current Assessing revision".into(),
            );
        }
        let authority: Option<MergeAuthorityRow> = tx
            .query_row(
                "SELECT project_id,role,role_session_id,ticket_run_id,ticket_revision,config_digest FROM agent_launch_authority WHERE agent_run_id=?1",
                [binding.agent_run_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if !matches!(authority, Some((ref project, ref role, ref session, Some(ref run), Some(revision), ref digest))
            if project == assessment.project_id.as_str()
                && role == "merge_decision"
                && session == &wake_session
                && run == assessment.ticket_run_id.as_str()
                && revision == assessment.revision.0
                && digest == assessment.configuration_digest.as_str())
        {
            return Err(
                "MergeAssessment source launch authority no longer matches the TicketRun".into(),
            );
        }

        let existing: Option<(String, String)> = tx
            .query_row(
                "SELECT source_id,payload_json FROM role_wake_inputs WHERE project_id=?1 AND role_session_id=?2 AND source_type='host_merge_assessment' AND source_revision=?3 LIMIT 1",
                rusqlite::params![assessment.project_id.as_str(), wake_session, assessment.revision.0],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if let Some((source_id, payload)) = existing.as_ref()
            && (source_id != assessment.assessment_id.as_str() || payload != &wake_payload)
        {
            return Err(
                "a different MergeAssessment already targets this role session revision".into(),
            );
        }
        if existing.is_none() {
            tx.execute(
                "INSERT INTO role_wake_inputs(project_id,role_session_id,source_type,source_id,source_revision,priority,payload_json,lifecycle,created_at_unix) VALUES (?1,?2,'host_merge_assessment',?3,?4,50,?5,'pending',?6)",
                rusqlite::params![assessment.project_id.as_str(), wake_session, assessment.assessment_id.as_str(), assessment.revision.0, wake_payload, now_unix],
            )
            .map_err(|error| error.to_string())?;
        }
        let prior_ack: Option<(u64, String)> = tx
            .query_row(
                "SELECT reducer_revision,disposition FROM agent_result_reducer_ack WHERE evidence_id=?1",
                [assessment.source_evidence_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        match prior_ack {
            Some((revision, disposition))
                if revision == assessment.revision.0 && disposition == "applied" => {}
            Some(_) => {
                return Err(
                    "MergeAssessment source result already has a different acknowledgement".into(),
                );
            }
            None => {
                let changed = tx.execute(
                    "INSERT INTO agent_result_reducer_ack(evidence_id,reducer_revision,disposition,acknowledged_at_unix) SELECT evidence_id,?2,'applied',?3 FROM agent_result_evidence WHERE evidence_id=?1 AND project_id=?4 AND role='merge_decision' AND ticket_run_id=?5",
                    rusqlite::params![assessment.source_evidence_id, assessment.revision.0, now_unix, assessment.project_id.as_str(), assessment.ticket_run_id.as_str()],
                ).map_err(|error| error.to_string())?;
                if changed != 1 {
                    return Err(
                        "cannot atomically acknowledge missing MergeAssessment evidence".into(),
                    );
                }
            }
        }
        tx.execute(
            "DELETE FROM merge_observation_deferrals WHERE source_evidence_id=?1",
            [assessment.source_evidence_id.as_str()],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(existing.is_none())
    }

    /// Insert one fully host-validated work item at the current Assessing revision. An exact
    /// replay is idempotent; a different work item for the same target revision is rejected.
    pub fn persist_merge_work_item(
        &mut self,
        owner_generation: u64,
        item: &MergeWorkItem,
        now_unix: i64,
    ) -> Result<bool, String> {
        let body_json = item.validate()?;
        let work_digest = item.work_id.as_str();
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        super::validate_active_generation(&tx, owner_generation)?;
        let current: Option<(String, u64, String, String)> = tx
            .query_row(
                "SELECT internal_phase,revision,config_digest,project_id FROM ticket_runs WHERE ticket_run_id=?1",
                [item.ticket_run_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if !matches!(current, Some((ref phase, revision, ref digest, ref project))
            if phase == "assessing"
                && revision == item.assessed_revision.0
                && digest == item.configuration_digest.as_str()
                && project == item.project_id.as_str())
        {
            return Err(
                "merge work item is stale or outside the current Assessing revision".into(),
            );
        }
        let accepted_plan: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM accepted_work_plans WHERE project_id=?1 AND ticket_run_id=?2 AND plan_digest=?3 AND configuration_digest=?4)",
                params![item.project_id.as_str(), item.ticket_run_id.as_str(), item.accepted_plan_digest.as_str(), item.configuration_digest.as_str()],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        if !accepted_plan {
            return Err(
                "merge work item does not reference the current Project's accepted plan".into(),
            );
        }
        let existing: Option<(String, String)> = tx
            .query_row(
                "SELECT work_id,work_json FROM merge_work_items WHERE project_id=?1 AND ticket_run_id=?2 AND awaiting_merge_revision=?3",
                params![item.project_id.as_str(), item.ticket_run_id.as_str(), item.awaiting_merge_revision.0],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if let Some((work_id, stored_json)) = existing {
            if work_id != item.work_id.as_str() || stored_json != body_json {
                return Err(
                    "a different immutable merge work item already targets this revision".into(),
                );
            }
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(false);
        }
        tx.execute(
            "INSERT INTO merge_work_items(work_id,project_id,ticket_run_id,assessed_revision,awaiting_merge_revision,configuration_digest,accepted_plan_digest,prepared_receipt_digest,publication_set_digest,work_digest,work_json,created_at_unix) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
            params![
                item.work_id.as_str(),
                item.project_id.as_str(),
                item.ticket_run_id.as_str(),
                item.assessed_revision.0,
                item.awaiting_merge_revision.0,
                item.configuration_digest.as_str(),
                item.accepted_plan_digest.as_str(),
                item.prepared_receipt_digest.as_str(),
                item.publication_set_digest.as_str(),
                work_digest,
                body_json,
                now_unix,
            ],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(true)
    }

    pub fn merge_work_item(
        &self,
        project_id: &ProjectId,
        ticket_run_id: &TicketRunId,
        awaiting_merge_revision: Revision,
    ) -> Result<Option<MergeWorkItem>, String> {
        let row: Option<MergeWorkItemRow> = self.connection
            .query_row(
                "SELECT work_id,work_json,assessed_revision,awaiting_merge_revision,configuration_digest,accepted_plan_digest,prepared_receipt_digest,publication_set_digest,work_digest,project_id FROM merge_work_items WHERE project_id=?1 AND ticket_run_id=?2 AND awaiting_merge_revision=?3",
                params![project_id.as_str(), ticket_run_id.as_str(), awaiting_merge_revision.0],
                |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?,row.get(9)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let Some((
            work_id,
            body_json,
            assessed_revision,
            stored_awaiting_revision,
            configuration_digest,
            accepted_plan_digest,
            prepared_receipt_digest,
            publication_set_digest,
            work_digest,
            stored_project_id,
        )) = row
        else {
            return Ok(None);
        };
        let body: serde_json::Value = crate::protocol::parse_unique(body_json.as_bytes())?;
        let body_digest = format!("{:x}", sha2::Sha256::digest(body_json.as_bytes()));
        if stored_project_id != project_id.as_str()
            || body_digest != work_digest
            || work_id != work_digest
            || body["schema_version"].as_u64() != Some(1)
            || body["project_id"].as_str() != Some(project_id.as_str())
            || body["ticket_run_id"].as_str() != Some(ticket_run_id.as_str())
            || body["assessed_revision"].as_u64() != Some(assessed_revision)
            || body["awaiting_merge_revision"].as_u64() != Some(stored_awaiting_revision)
            || body["configuration_digest"].as_str() != Some(configuration_digest.as_str())
            || body["accepted_plan_digest"].as_str() != Some(accepted_plan_digest.as_str())
            || body["prepared_receipt_digest"].as_str() != Some(prepared_receipt_digest.as_str())
            || body["publication_set_digest"].as_str() != Some(publication_set_digest.as_str())
        {
            return Err(
                "stored immutable merge work item failed its column or digest check".into(),
            );
        }
        let document: MergeWorkDocument = serde_json::from_value(body["document"].clone())
            .map_err(|error| format!("stored merge work document is invalid: {error}"))?;
        let item = MergeWorkItem {
            work_id: Digest::parse(work_id)?,
            project_id: project_id.clone(),
            ticket_run_id: ticket_run_id.clone(),
            assessed_revision: Revision(assessed_revision),
            awaiting_merge_revision: Revision(stored_awaiting_revision),
            configuration_digest: Digest::parse(configuration_digest)?,
            accepted_plan_digest: Digest::parse(accepted_plan_digest)?,
            prepared_receipt_digest: Digest::parse(prepared_receipt_digest)?,
            publication_set_digest: Digest::parse(publication_set_digest)?,
            document,
        };
        if item.validate()? != body_json {
            return Err("stored merge work item is not canonical".into());
        }
        Ok(Some(item))
    }
}

/// Called by the single central v12 migration transaction.
pub fn migrate_v12_merge_work_items(tx: &Transaction<'_>) -> Result<(), String> {
    tx.execute_batch(
        "CREATE TABLE merge_work_items (
            work_id TEXT PRIMARY KEY CHECK(length(work_id)=64),
            project_id TEXT NOT NULL,
            ticket_run_id TEXT NOT NULL,
            assessed_revision INTEGER NOT NULL CHECK(assessed_revision > 0),
            awaiting_merge_revision INTEGER NOT NULL CHECK(awaiting_merge_revision > assessed_revision),
            configuration_digest TEXT NOT NULL CHECK(length(configuration_digest)=64),
            accepted_plan_digest TEXT NOT NULL CHECK(length(accepted_plan_digest)=64),
            prepared_receipt_digest TEXT NOT NULL CHECK(length(prepared_receipt_digest)=64),
            publication_set_digest TEXT NOT NULL CHECK(length(publication_set_digest)=64),
            work_digest TEXT NOT NULL CHECK(length(work_digest)=64),
            work_json TEXT NOT NULL CHECK(length(work_json)<=1048576),
            created_at_unix INTEGER NOT NULL,
            UNIQUE(project_id,ticket_run_id,awaiting_merge_revision)
        );
        CREATE INDEX merge_work_items_run ON merge_work_items(project_id,ticket_run_id,awaiting_merge_revision DESC);",
    )
    .map_err(|error| error.to_string())
}
