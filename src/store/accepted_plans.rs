//! Durable, revision-bound accepted work plans and host-minted Worker inputs.

use std::collections::BTreeMap;

use rusqlite::{OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};

use crate::config::ProjectConfig;
use crate::delivery_runtime::{PrepareWorktreesEffectPayload, PreparedWorktreesEffectReceipt};
use crate::domain::ids::{AgentRunId, Digest, OperationId, ProjectId, RepositoryId, TicketRunId};
use crate::domain::types::CommitMode;
use crate::engine::orchestration::{ValidatedPlan, WorkNodeId, WorkPlan};
use crate::store::{ConfigStore, SucceededEffectReceipt};

const MAX_PLAN_BYTES: usize = 1_048_576;

fn accepted_transition_matches(
    rows: &[(u64, u64, String)],
    revision: u64,
    kind: &str,
    transition: &str,
    source_revision: Option<u64>,
    accepted_revision: Option<u64>,
    publication_revision: Option<u64>,
) -> bool {
    rows.iter().any(|(_, next_revision, evidence)| {
        *next_revision == revision
            && serde_json::from_str::<serde_json::Value>(evidence).is_ok_and(|value| {
                value["kind"] == kind
                    && value["transition"] == transition
                    && source_revision
                        .is_none_or(|revision| value["source_revision"].as_u64() == Some(revision))
                    && accepted_revision.is_none_or(|revision| {
                        value["accepted_revision"].as_u64() == Some(revision)
                    })
                    && publication_revision.is_none_or(|revision| {
                        value["publication_revision"].as_u64() == Some(revision)
                    })
            })
    })
}

type AcceptedPlanRow = (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
);
type AcceptedEffectRow = (
    String,
    String,
    String,
    String,
    Option<u64>,
    String,
    String,
    String,
);
type AcceptedPlanIdentityRow = (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
);

pub(crate) fn coordinator_role_session_id(
    ticket_run_id: &TicketRunId,
) -> Result<crate::engine::orchestration::RoleSessionId, String> {
    crate::engine::orchestration::RoleSessionId::parse(format!(
        "ticket_run:{}:coordinator",
        ticket_run_id.as_str()
    ))
}

#[derive(Clone, Debug)]
pub(crate) struct AcceptedPlanWrite {
    pub configuration_digest: Digest,
    pub plan_digest: Digest,
    pub plan_json: String,
    pub source_evidence_id: String,
    pub source_agent_run_id: AgentRunId,
    pub source_message_id: String,
    pub source_result_digest: Digest,
    pub source_claim_plan_json: String,
    pub coordinator_agent_run_id: AgentRunId,
    pub coordinator_role_session_id: String,
    pub validated_plan: ValidatedPlan,
}

pub(crate) fn prepare_accepted_plan_write(
    ticket_run_id: &TicketRunId,
    plan: &ValidatedPlan,
    configuration_digest: &Digest,
    source: &crate::store::agent_results::IngestedAgentResult,
) -> Result<AcceptedPlanWrite, String> {
    let binding = &source.validated.binding;
    if plan.ticket_run_id != *ticket_run_id
        || plan.nodes_in_execution_order.is_empty()
        || plan.nodes_in_execution_order.len() > 64
        || source.validated.kind != crate::engine::orchestration::RoleOutputKind::PlanReady
        || source.validated.assertion != crate::engine::orchestration::AgentAssertion::Succeeded
        || binding.role != crate::domain::types::Role::Coordinator
        || binding.ticket_run_id.as_ref() != Some(ticket_run_id)
        || binding.config_digest != *configuration_digest
        || binding.role_session_id != coordinator_role_session_id(ticket_run_id)?
        || !matches!(
            source.validated.typed_payload,
            crate::engine::orchestration::RoleResultPayload::PlanReady(_)
        )
    {
        return Err("validated work plan lacks a matching Coordinator result binding".into());
    }
    let crate::engine::orchestration::RoleResultPayload::PlanReady(claim) =
        &source.validated.typed_payload
    else {
        return Err("accepted plan source is not a PlanReady result".into());
    };
    if !validated_plan_matches_claim(plan, &claim.plan) {
        return Err("validated work plan differs from the persisted Coordinator proposal".into());
    }
    let mut node_ids = std::collections::BTreeSet::new();
    if plan.nodes_in_execution_order.iter().any(|node| {
        !node_ids.insert(node.id.as_str().to_owned())
            || node.task.trim().is_empty()
            || node.task.len() > 32_000
            || node.required_evidence.len() > 128
    }) {
        return Err("validated work plan contains duplicate or invalid nodes".into());
    }
    let mut observed_base_shas = BTreeMap::new();
    for node in &plan.nodes_in_execution_order {
        if let crate::engine::orchestration::WorkBaseSource::ControllerObservedCommit { commit } =
            &node.base
            && let Some(previous) =
                observed_base_shas.insert(node.repository.clone(), commit.clone())
            && previous != *commit
        {
            return Err("validated plan has inconsistent observed repository bases".into());
        }
    }
    let persisted = PersistedWorkPlan {
        schema_version: 1,
        proposal: claim.plan.clone(),
        observed_base_shas,
    };
    let persisted_value = serde_json::to_value(&persisted).map_err(|error| error.to_string())?;
    let plan_json = serde_json::to_string(&persisted_value).map_err(|error| error.to_string())?;
    if plan_json.len() > MAX_PLAN_BYTES {
        return Err("validated work plan exceeds storage limit".into());
    }
    Ok(AcceptedPlanWrite {
        configuration_digest: configuration_digest.clone(),
        plan_digest: digest_json(&plan_json),
        plan_json,
        source_evidence_id: source.receipt.evidence_id().to_owned(),
        source_agent_run_id: binding.agent_run_id.clone(),
        source_message_id: source.validated.message_id.clone(),
        source_result_digest: source.validated.result_digest.clone(),
        source_claim_plan_json: serde_json::to_string(&claim.plan)
            .map_err(|error| error.to_string())?,
        coordinator_agent_run_id: binding.agent_run_id.clone(),
        coordinator_role_session_id: binding.role_session_id.as_str().to_owned(),
        validated_plan: plan.clone(),
    })
}

pub(crate) fn validated_plan_matches_claim(
    validated: &ValidatedPlan,
    claim: &crate::engine::orchestration::WorkPlan,
) -> bool {
    if claim.nodes.len() != validated.nodes_in_execution_order.len()
        || claim.requested_investigation_children != validated.spawned_investigation_children
    {
        return false;
    }
    let mut nodes = claim.nodes.iter().collect::<Vec<_>>();
    nodes.sort_by(|left, right| left.id.cmp(&right.id));
    let mut accepted = validated
        .nodes_in_execution_order
        .iter()
        .collect::<Vec<_>>();
    accepted.sort_by(|left, right| left.id.cmp(&right.id));
    nodes.iter().zip(accepted).all(|(claimed, accepted)| {
        claimed.id == accepted.id
            && claimed.repository == accepted.repository
            && claimed.task == accepted.task
            && claimed.depends_on == accepted.depends_on
            && claimed.required_evidence == accepted.required_evidence
            && accepted.role
                == if claimed.investigation {
                    crate::domain::types::Role::Planner
                } else {
                    crate::domain::types::Role::Worker
                }
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedWorkPlanRecord {
    pub project_id: ProjectId,
    pub ticket_run_id: TicketRunId,
    /// Revision of the TicketRun after PlanAccepted committed.
    pub accepted_revision: u64,
    pub configuration_digest: Digest,
    pub plan_digest: Digest,
    pub proposal: WorkPlan,
    pub observed_base_shas: BTreeMap<RepositoryId, String>,
    pub source_evidence_id: String,
    pub source_agent_run_id: AgentRunId,
    pub source_message_id: String,
    pub source_result_digest: Digest,
    pub coordinator_agent_run_id: AgentRunId,
    pub coordinator_role_session_id: String,
    pub coordinator_authority_digest: Digest,
}

#[derive(Clone, Debug)]
pub struct AcceptedImplementationPublicationSnapshot {
    accepted_plan: AcceptedWorkPlanRecord,
    publication_revision: u64,
    prepared_receipt: PreparedWorktreesEffectReceipt,
    publication_receipts: Vec<SucceededEffectReceipt>,
    verification: Option<AcceptedWorkerVerification>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedReviewerCorrection {
    pub evidence_id: String,
    pub result_digest: Digest,
    pub source_revision: u64,
    pub accepted_revision: u64,
    pub publication_revision: u64,
    pub assessment: crate::engine::orchestration::ReviewReadyPayload,
}

/// A Worker check-only completion bound to an already accepted implementation publication.
/// The publication provenance stays at its original revision; this record describes only the
/// later review evidence that was verified against that exact published tree.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AcceptedWorkerVerification {
    pub review_revision: u64,
    pub source_revision: u64,
    pub source_evidence_id: String,
    pub source_agent_run_id: AgentRunId,
    pub source_result_digest: Digest,
    pub publication_revision: u64,
    pub publication_operation_id: OperationId,
    pub published_head: crate::engine::orchestration::GitCommitId,
    pub work_node_id: WorkNodeId,
    pub repository_id: RepositoryId,
    pub test_receipt_artifacts: Vec<crate::engine::orchestration::RoleArtifactReference>,
}

impl AcceptedImplementationPublicationSnapshot {
    pub fn accepted_plan(&self) -> &AcceptedWorkPlanRecord {
        &self.accepted_plan
    }

    pub fn publication_revision(&self) -> u64 {
        self.publication_revision
    }

    pub fn prepared_receipt(&self) -> &PreparedWorktreesEffectReceipt {
        &self.prepared_receipt
    }

    pub fn publication_receipts(&self) -> &[SucceededEffectReceipt] {
        &self.publication_receipts
    }

    pub fn verification(&self) -> Option<&AcceptedWorkerVerification> {
        self.verification.as_ref()
    }
}

impl AcceptedWorkPlanRecord {
    pub fn validate_for(
        &self,
        project: &ProjectConfig,
        configuration_digest: &Digest,
    ) -> Result<ValidatedPlan, String> {
        if self.configuration_digest != *configuration_digest {
            return Err("accepted work plan belongs to a different configuration snapshot".into());
        }
        crate::engine::orchestration::validate_work_plan(
            &self.ticket_run_id,
            project,
            self.proposal.clone(),
            &self.observed_base_shas,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PersistedWorkPlan {
    pub(crate) schema_version: u32,
    pub(crate) proposal: WorkPlan,
    pub(crate) observed_base_shas: BTreeMap<RepositoryId, String>,
}

/// Host-minted node context. Private fields prevent wake JSON from being used
/// as authority to launch a Worker or select a worktree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedWorkerLaunch {
    project_id: ProjectId,
    ticket_run_id: TicketRunId,
    accepted_revision: u64,
    ticket_revision: u64,
    configuration_digest: Digest,
    plan_digest: Digest,
    node_id: WorkNodeId,
    repository_id: RepositoryId,
    commit_mode: CommitMode,
    worktree_path: std::path::PathBuf,
    branch: String,
    base_sha: String,
    expected_head: Option<String>,
    prepare_operation_id: String,
    prepare_receipt_digest: Digest,
    source_evidence_id: String,
    source_agent_run_id: AgentRunId,
    source_message_id: String,
    source_result_digest: Digest,
    coordinator_agent_run_id: AgentRunId,
    coordinator_role_session_id: String,
    coordinator_authority_digest: Digest,
}

impl PreparedWorkerLaunch {
    pub fn reservation_binding(&self) -> crate::launch::WorkerLaunchBinding {
        crate::launch::WorkerLaunchBinding {
            schema_version: 1,
            accepted_revision: self.accepted_revision,
            ticket_revision: self.ticket_revision,
            configuration_digest: self.configuration_digest.clone(),
            plan_digest: self.plan_digest.clone(),
            node_id: self.node_id.clone(),
            repository_id: self.repository_id.clone(),
            commit_mode: self.commit_mode,
            worktree_path: self.worktree_path.clone(),
            branch: self.branch.clone(),
            base_sha: self.base_sha.clone(),
            expected_head: self.expected_head.clone(),
            prepare_operation_id: self.prepare_operation_id.clone(),
            prepare_receipt_digest: self.prepare_receipt_digest.clone(),
            source_evidence_id: self.source_evidence_id.clone(),
            source_agent_run_id: self.source_agent_run_id.clone(),
            source_message_id: self.source_message_id.clone(),
            source_result_digest: self.source_result_digest.clone(),
            coordinator_agent_run_id: self.coordinator_agent_run_id.clone(),
            coordinator_role_session_id: self.coordinator_role_session_id.clone(),
            coordinator_authority_digest: self.coordinator_authority_digest.clone(),
        }
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }
    pub fn ticket_run_id(&self) -> &TicketRunId {
        &self.ticket_run_id
    }
    pub fn accepted_revision(&self) -> u64 {
        self.accepted_revision
    }
    pub fn ticket_revision(&self) -> u64 {
        self.ticket_revision
    }
    pub fn configuration_digest(&self) -> &Digest {
        &self.configuration_digest
    }
    pub fn plan_digest(&self) -> &Digest {
        &self.plan_digest
    }
    pub fn node_id(&self) -> &WorkNodeId {
        &self.node_id
    }
    pub fn repository_id(&self) -> &RepositoryId {
        &self.repository_id
    }
    pub fn commit_mode(&self) -> CommitMode {
        self.commit_mode
    }
    pub fn worktree_path(&self) -> &std::path::Path {
        &self.worktree_path
    }
    pub fn branch(&self) -> &str {
        &self.branch
    }
    pub fn base_sha(&self) -> &str {
        &self.base_sha
    }

    pub fn expected_head(&self) -> &str {
        self.expected_head.as_deref().unwrap_or(&self.base_sha)
    }
    pub fn prepare_operation_id(&self) -> &str {
        &self.prepare_operation_id
    }
    pub fn prepare_receipt_digest(&self) -> &Digest {
        &self.prepare_receipt_digest
    }
    pub fn source_evidence_id(&self) -> &str {
        &self.source_evidence_id
    }
    pub fn source_agent_run_id(&self) -> &AgentRunId {
        &self.source_agent_run_id
    }
    pub fn source_message_id(&self) -> &str {
        &self.source_message_id
    }
    pub fn source_result_digest(&self) -> &Digest {
        &self.source_result_digest
    }
    pub fn coordinator_agent_run_id(&self) -> &AgentRunId {
        &self.coordinator_agent_run_id
    }
    pub fn coordinator_role_session_id(&self) -> &str {
        &self.coordinator_role_session_id
    }
    pub fn coordinator_authority_digest(&self) -> &Digest {
        &self.coordinator_authority_digest
    }
}

/// Recheck the Store-minted Worker authority in the same transaction that
/// reserves the AgentRun. The plan payload remains raw; validation is derived
/// from its captured base observations when the token is minted.
pub(crate) fn revalidate_prepared_worker_launch(
    tx: &Transaction<'_>,
    reservation: &crate::launch::AgentLaunchReservation,
    prepared: &PreparedWorkerLaunch,
) -> Result<(), String> {
    let binding = prepared.reservation_binding();
    if reservation.role != crate::domain::types::Role::Worker
        || reservation.worker_assignment.as_ref() != Some(&binding)
        || reservation.project_id != prepared.project_id
        || reservation.ticket_run_id.as_ref() != Some(&prepared.ticket_run_id)
        || reservation.ticket_revision.map(|revision| revision.0) != Some(prepared.ticket_revision)
        || reservation.config_digest != prepared.configuration_digest
        || reservation.parent_run_id.as_ref() != Some(&prepared.coordinator_agent_run_id)
        || reservation.parent_role != Some(crate::domain::types::Role::Coordinator)
        || reservation.role_session_id
            != format!(
                "ticket:{}:worker:{}",
                prepared.ticket_run_id, prepared.node_id
            )
        || reservation.workspace_path != prepared.worktree_path
        || prepared.accepted_revision == 0
        || prepared.ticket_revision == 0
    {
        return Err("Worker reservation differs from its prepared-plan authority".into());
    }
    let canonical = std::fs::canonicalize(&prepared.worktree_path)
        .map_err(|error| format!("canonicalize prepared Worker worktree: {error}"))?;
    if canonical != prepared.worktree_path {
        return Err("prepared Worker worktree path is no longer canonical".into());
    }

    let ticket: Option<(String, u64, String, String)> = tx
        .query_row(
            "SELECT project_id,revision,internal_phase,config_digest FROM ticket_runs WHERE ticket_run_id=?1",
            [prepared.ticket_run_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    if !matches!(ticket, Some((ref project, revision, ref phase, ref config))
        if project == prepared.project_id.as_str()
            && revision == prepared.ticket_revision
            && phase == "implementing"
            && config == prepared.configuration_digest.as_str())
    {
        return Err("prepared Worker authority is stale for the current TicketRun".into());
    }

    let accepted: Option<AcceptedPlanRow> = tx
        .query_row(
            "SELECT configuration_digest,plan_digest,plan_json,source_evidence_id,source_agent_run_id,source_message_id,source_result_digest,coordinator_agent_run_id,coordinator_role_session_id,coordinator_authority_digest FROM accepted_work_plans WHERE project_id=?1 AND ticket_run_id=?2 AND accepted_revision=?3",
            params![prepared.project_id.as_str(), prepared.ticket_run_id.as_str(), prepared.accepted_revision],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?,row.get(9)?)),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    let Some((
        configuration_digest,
        plan_digest,
        plan_json,
        evidence_id,
        source_run,
        source_message,
        source_result,
        coordinator_run,
        coordinator_session,
        coordinator_authority,
    )) = accepted
    else {
        return Err("accepted Worker plan disappeared before reservation".into());
    };
    if configuration_digest != prepared.configuration_digest.as_str()
        || plan_digest != prepared.plan_digest.as_str()
        || evidence_id != prepared.source_evidence_id
        || source_run != prepared.source_agent_run_id.as_str()
        || source_message != prepared.source_message_id
        || source_result != prepared.source_result_digest.as_str()
        || coordinator_run != prepared.coordinator_agent_run_id.as_str()
        || coordinator_session != prepared.coordinator_role_session_id
        || coordinator_authority != prepared.coordinator_authority_digest.as_str()
        || digest_json(&plan_json) != prepared.plan_digest
    {
        return Err("accepted Worker plan provenance changed before reservation".into());
    }
    let persisted: PersistedWorkPlan = parse_canonical(&plan_json)?;
    if persisted.schema_version != 1 {
        return Err("accepted Worker plan schema is unsupported".into());
    }
    let selected = persisted
        .proposal
        .nodes
        .iter()
        .find(|node| node.id == prepared.node_id)
        .ok_or("prepared Worker node is absent from the accepted raw plan")?;
    if selected.repository != prepared.repository_id || selected.investigation {
        return Err("prepared Worker assignment differs from the accepted raw plan".into());
    }

    let source: Option<(String, String, String, String, String, String, String)> = tx
        .query_row(
            "SELECT agent_run_id,project_id,role,ticket_run_id,message_id,result_digest,outcome FROM agent_result_evidence WHERE evidence_id=?1",
            [&prepared.source_evidence_id],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?)),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    if !matches!(source, Some((ref run,ref project,ref role,ref ticket,ref message,ref digest,ref outcome))
        if run == prepared.coordinator_agent_run_id.as_str()
            && project == prepared.project_id.as_str()
            && role == "coordinator"
            && ticket == prepared.ticket_run_id.as_str()
            && message == &prepared.source_message_id
            && digest == prepared.source_result_digest.as_str()
            && outcome == "completed")
    {
        return Err("accepted Worker plan lacks its exact completed Coordinator result".into());
    }
    let coordinator: Option<(String, String, String, String, String)> = tx
        .query_row(
            "SELECT project_id,role,role_session_id,ticket_run_id,authority_digest FROM agent_launch_authority WHERE agent_run_id=?1",
            [prepared.coordinator_agent_run_id.as_str()],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    if !matches!(coordinator, Some((ref project,ref role,ref session,ref ticket,ref digest))
        if project == prepared.project_id.as_str()
            && role == "coordinator"
            && session == &prepared.coordinator_role_session_id
            && ticket == prepared.ticket_run_id.as_str()
            && digest == prepared.coordinator_authority_digest.as_str())
    {
        return Err("accepted Worker plan Coordinator authority changed".into());
    }

    let effect: Option<AcceptedEffectRow> = tx
        .query_row(
            "SELECT project_id,subject_type,subject_id,kind,expected_revision,request_json,request_digest,receipt_json FROM effects WHERE operation_id=?1 AND status='succeeded'",
            [&prepared.prepare_operation_id],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?)),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    let Some((
        project,
        subject_type,
        subject_id,
        kind,
        expected_revision,
        request_json,
        request_digest,
        receipt_json,
    )) = effect
    else {
        return Err("prepared worktree effect is no longer succeeded".into());
    };
    if project != prepared.project_id.as_str()
        || subject_type != "ticket_run"
        || subject_id != prepared.ticket_run_id.as_str()
        || kind != "prepare_worktrees"
        || expected_revision != Some(prepared.accepted_revision)
        || digest_json(&request_json).as_str() != request_digest
        || digest_json(&receipt_json) != prepared.prepare_receipt_digest
    {
        return Err("prepared worktree effect differs from Worker authority".into());
    }
    let request: PrepareWorktreesEffectPayload = parse_canonical(&request_json)?;
    let receipt: PreparedWorktreesEffectReceipt = parse_canonical(&receipt_json)?;
    let requested = request
        .work_nodes
        .iter()
        .find(|node| node.work_node_id == prepared.node_id)
        .ok_or("prepare request omits the Worker node")?;
    let observed = receipt
        .work_nodes
        .iter()
        .find(|node| node.work_node_id == prepared.node_id)
        .ok_or("prepare receipt omits the Worker node")?;
    if request.ticket_run_id != prepared.ticket_run_id
        || request.source_revision != prepared.accepted_revision
        || request.configuration_digest != prepared.configuration_digest
        || requested.repository_id != prepared.repository_id
        || requested.expected_base_sha != prepared.base_sha
        || requested.commit_mode != prepared.commit_mode
        || receipt.schema_version != 1
        || receipt.ticket_run_id != prepared.ticket_run_id
        || observed.repository_id != prepared.repository_id
        || observed.base_sha != prepared.base_sha
        || observed.branch != prepared.branch
        || observed.worktree_path != prepared.worktree_path
        || observed.commit_mode != prepared.commit_mode
    {
        return Err("prepared worktree receipt differs from the accepted Worker node".into());
    }
    Ok(())
}

/// Called by the single central v12 migration transaction.
pub fn migrate_v12_worker_plan_tables(tx: &Transaction<'_>) -> Result<(), String> {
    tx.execute_batch(
        "CREATE TABLE accepted_work_plans (
            project_id TEXT NOT NULL,
            ticket_run_id TEXT NOT NULL,
            accepted_revision INTEGER NOT NULL CHECK(accepted_revision > 0),
            configuration_digest TEXT NOT NULL CHECK(length(configuration_digest)=64),
            plan_digest TEXT NOT NULL CHECK(length(plan_digest)=64),
            plan_json TEXT NOT NULL,
            source_evidence_id TEXT NOT NULL,
            source_agent_run_id TEXT NOT NULL,
            source_message_id TEXT NOT NULL,
            source_result_digest TEXT NOT NULL CHECK(length(source_result_digest)=64),
            coordinator_agent_run_id TEXT NOT NULL,
            coordinator_role_session_id TEXT NOT NULL,
            coordinator_authority_digest TEXT NOT NULL CHECK(length(coordinator_authority_digest)=64),
            created_at_unix INTEGER NOT NULL,
            PRIMARY KEY(project_id,ticket_run_id,accepted_revision)
        );
        CREATE INDEX accepted_work_plans_latest ON accepted_work_plans(project_id,ticket_run_id,accepted_revision DESC);
        ",
    )
    .map_err(|error| error.to_string())
}

impl ConfigStore {
    pub fn latest_accepted_work_plan(
        &self,
        project_id: &ProjectId,
        ticket_run_id: &TicketRunId,
    ) -> Result<Option<AcceptedWorkPlanRecord>, String> {
        let revision: Option<u64> = self.connection.query_row(
            "SELECT accepted_revision FROM accepted_work_plans WHERE project_id=?1 AND ticket_run_id=?2 ORDER BY accepted_revision DESC LIMIT 1",
            params![project_id.as_str(),ticket_run_id.as_str()],
            |row| row.get(0),
        ).optional().map_err(|error| error.to_string())?;
        match revision {
            Some(revision) => self.accepted_work_plan(project_id, ticket_run_id, revision),
            None => Ok(None),
        }
    }

    pub fn accepted_work_plan(
        &self,
        project_id: &ProjectId,
        ticket_run_id: &TicketRunId,
        accepted_revision: u64,
    ) -> Result<Option<AcceptedWorkPlanRecord>, String> {
        let row: Option<AcceptedPlanIdentityRow> = self.connection.query_row(
            "SELECT configuration_digest,plan_digest,plan_json,source_evidence_id,source_agent_run_id,source_message_id,source_result_digest,coordinator_agent_run_id,coordinator_role_session_id,coordinator_authority_digest FROM accepted_work_plans WHERE project_id=?1 AND ticket_run_id=?2 AND accepted_revision=?3",
            params![project_id.as_str(),ticket_run_id.as_str(),accepted_revision],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?,row.get(9)?)),
        ).optional().map_err(|error| error.to_string())?;
        let Some((
            configuration_digest,
            stored_plan_digest,
            plan_json,
            source_evidence_id,
            source_agent_run_id,
            source_message_id,
            source_result_digest,
            coordinator_agent_run_id,
            coordinator_role_session_id,
            coordinator_authority_digest,
        )) = row
        else {
            return Ok(None);
        };
        let persisted: PersistedWorkPlan = parse_canonical(&plan_json)?;
        if persisted.schema_version != 1 {
            return Err("stored accepted plan schema is unsupported".into());
        }
        if digest_json(&plan_json).as_str() != stored_plan_digest {
            return Err("stored accepted work plan digest is invalid".into());
        }
        Ok(Some(AcceptedWorkPlanRecord {
            project_id: project_id.clone(),
            ticket_run_id: ticket_run_id.clone(),
            accepted_revision,
            configuration_digest: Digest::parse(configuration_digest)?,
            plan_digest: Digest::parse(stored_plan_digest)?,
            proposal: persisted.proposal,
            observed_base_shas: persisted.observed_base_shas,
            source_evidence_id,
            source_agent_run_id: AgentRunId::parse(source_agent_run_id)?,
            source_message_id,
            source_result_digest: Digest::parse(source_result_digest)?,
            coordinator_agent_run_id: AgentRunId::parse(coordinator_agent_run_id)?,
            coordinator_role_session_id,
            coordinator_authority_digest: Digest::parse(coordinator_authority_digest)?,
        }))
    }

    /// Read only the current host-accepted Reviewer corrections that reopened an accepted
    /// implementation plan. The publication snapshot validates the complete correction chain.
    pub fn latest_worker_reviewer_correction(
        &self,
        owner_generation: u64,
        project_id: &ProjectId,
        ticket_run_id: &TicketRunId,
        ticket_revision: u64,
        configuration_digest: &Digest,
        accepted_plan_digest: &Digest,
    ) -> Result<Option<AcceptedReviewerCorrection>, String> {
        let current: Option<(String, u64, String)> = self
            .connection
            .query_row(
                "SELECT project_id,revision,internal_phase FROM ticket_runs WHERE ticket_run_id=?1",
                [ticket_run_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let Some((stored_project, revision, phase)) = current else {
            return Err("Reviewer correction TicketRun is missing".into());
        };
        if stored_project != project_id.as_str() || revision != ticket_revision {
            return Err(
                "Reviewer correction context is stale or belongs to another Project".into(),
            );
        }
        if phase != "implementing" {
            return Ok(None);
        }
        let evidence_json: Option<String> = self
            .connection
            .query_row(
                "SELECT evidence_json FROM transitions WHERE entity_type='ticket_run' AND entity_id=?1 AND project_id=?2 AND new_revision=?3",
                params![ticket_run_id.as_str(), project_id.as_str(), ticket_revision],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let Some(evidence_json) = evidence_json else {
            return Ok(None);
        };
        let evidence: serde_json::Value =
            crate::protocol::parse_unique(evidence_json.as_bytes())
                .map_err(|error| format!("accepted review transition is invalid: {error}"))?;
        if evidence["kind"] != "review_assessment" || evidence["transition"] != "corrections_remain"
        {
            return Ok(None);
        }
        if evidence["schema_version"].as_u64() != Some(1)
            || evidence["accepted_revision"].as_u64() != Some(ticket_revision)
            || evidence["source_revision"].as_u64() != ticket_revision.checked_sub(1)
        {
            return Err("accepted Reviewer correction transition has invalid revisions".into());
        }
        let evidence_id = evidence["evidence_id"]
            .as_str()
            .ok_or("accepted Reviewer correction has no source evidence ID")?
            .to_owned();
        let result_digest = Digest::parse(
            evidence["result_digest"]
                .as_str()
                .ok_or("accepted Reviewer correction has no result digest")?,
        )?;
        let source_revision = evidence["source_revision"].as_u64().unwrap();
        let accepted_revision = evidence["accepted_revision"].as_u64().unwrap();
        let publication_subject: crate::delivery_runtime::ImplementationPublicationSetSubject =
            serde_json::from_value(
                evidence
                    .get("publication_subject")
                    .cloned()
                    .ok_or("accepted Reviewer correction has no publication subject")?,
            )
            .map_err(|error| {
                format!("accepted Reviewer publication subject is invalid: {error}")
            })?;
        let assessment: crate::engine::orchestration::ReviewReadyPayload = serde_json::from_value(
            evidence
                .get("assessment")
                .cloned()
                .ok_or("accepted Reviewer correction has no assessment")?,
        )
        .map_err(|error| format!("accepted Reviewer assessment is invalid: {error}"))?;

        let publication = self.accepted_implementation_publication_snapshot(
            owner_generation,
            project_id,
            ticket_run_id,
            ticket_revision,
        )?;
        if publication.accepted_plan().configuration_digest != *configuration_digest
            || publication.accepted_plan().plan_digest != *accepted_plan_digest
            || publication_subject.ticket_run_id != *ticket_run_id
            || publication_subject.accepted_plan_digest != *accepted_plan_digest
            || publication_subject.publication_revision != publication.publication_revision()
            || publication_subject.publication_revision > source_revision
            || publication_subject.digest()? != assessment.subject_digest
        {
            return Err("accepted Reviewer correction is not bound to the current publication, plan, or configuration".into());
        }

        let source: Option<(String, String, String, String, String, String)> = self
            .connection
            .query_row(
                "SELECT project_id,role,ticket_run_id,result_digest,result_json,outcome FROM agent_result_evidence WHERE evidence_id=?1",
                [&evidence_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let Some((source_project, source_role, source_ticket, source_digest, result_json, outcome)) =
            source
        else {
            return Err("accepted Reviewer correction lost its result evidence".into());
        };
        if source_project != project_id.as_str()
            || source_role != "reviewer"
            || source_ticket != ticket_run_id.as_str()
            || source_digest != result_digest.as_str()
            || outcome != "completed"
        {
            return Err("accepted Reviewer correction source evidence is out of scope".into());
        }
        let submission: crate::engine::orchestration::RoleResultSubmission =
            crate::protocol::parse_unique(result_json.as_bytes()).map_err(|error| {
                format!("accepted Reviewer result evidence is invalid: {error}")
            })?;
        if submission.kind != crate::engine::orchestration::RoleOutputKind::ReviewReady
            || submission.result_digest != result_digest
            || submission.structured_result
                != serde_json::to_value(&assessment).map_err(|error| error.to_string())?
        {
            return Err("accepted Reviewer transition differs from its result evidence".into());
        }
        let acknowledgement: Option<(u64, String)> = self
            .connection
            .query_row(
                "SELECT reducer_revision,disposition FROM agent_result_reducer_ack WHERE evidence_id=?1",
                [&evidence_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if acknowledgement != Some((accepted_revision, "applied".into())) {
            return Err(
                "accepted Reviewer correction has no matching applied result acknowledgement"
                    .into(),
            );
        }
        Ok(Some(AcceptedReviewerCorrection {
            evidence_id,
            result_digest,
            source_revision,
            accepted_revision,
            publication_revision: publication_subject.publication_revision,
            assessment,
        }))
    }

    /// Rebuild the exact host-accepted implementation publication snapshot for Reviewer or MergeIntent.
    pub fn accepted_implementation_publication_snapshot(
        &self,
        owner_generation: u64,
        project_id: &ProjectId,
        ticket_run_id: &TicketRunId,
        consumer_revision: u64,
    ) -> Result<AcceptedImplementationPublicationSnapshot, String> {
        let current: Option<(u64, String, String, String)> = self.connection.query_row(
            "SELECT revision,internal_phase,config_digest,project_id FROM ticket_runs WHERE ticket_run_id=?1",
            [ticket_run_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        ).optional().map_err(|error| error.to_string())?;
        let Some((revision, phase, config_digest, stored_project)) = current else {
            return Err("publication snapshot TicketRun is missing".into());
        };
        if revision != consumer_revision || stored_project != project_id.as_str() {
            return Err("publication snapshot consumer revision or Project is stale".into());
        }
        let active_generation: Option<u64> = self.connection.query_row(
            "SELECT generation FROM controller_owners WHERE singleton=1 AND stopped_at_unix IS NULL",
            [], |row| row.get(0),
        ).optional().map_err(|error| error.to_string())?;
        if active_generation != Some(owner_generation) {
            return Err("publication snapshot requires the active controller generation".into());
        }
        let mut stmt = self.connection.prepare(
            "SELECT old_revision,new_revision,evidence_json FROM transitions WHERE entity_type='ticket_run' AND entity_id=?1 AND project_id=?2 AND new_revision<=?3 ORDER BY new_revision DESC",
        ).map_err(|error| error.to_string())?;
        let rows = stmt
            .query_map(
                params![
                    ticket_run_id.as_str(),
                    project_id.as_str(),
                    consumer_revision
                ],
                |row| {
                    Ok((
                        row.get::<_, u64>(0)?,
                        row.get::<_, u64>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        let Some((source_revision, publication_revision, evidence_json)) = rows
            .iter()
            .find(|(_, _, evidence)| {
                serde_json::from_str::<serde_json::Value>(evidence)
                    .is_ok_and(|value| value["kind"] == "implementation_published")
            })
            .cloned()
        else {
            return Err("TicketRun has no committed implementation publication snapshot".into());
        };
        let evidence: serde_json::Value = crate::protocol::parse_unique(evidence_json.as_bytes())?;
        if source_revision.checked_add(1) != Some(publication_revision)
            || evidence["source_revision"].as_u64() != Some(source_revision)
            || evidence["ticket_run_id"].as_str() != Some(ticket_run_id.as_str())
        {
            return Err("committed implementation publication transition is malformed".into());
        }
        let publication_delta = consumer_revision.checked_sub(publication_revision);
        let transition_chain_matches = |through_offset: u64| {
            (1..=through_offset).all(|offset| {
                let revision = publication_revision + offset;
                if offset % 2 == 1 {
                    accepted_transition_matches(
                        &rows,
                        revision,
                        "review_assessment",
                        "corrections_remain",
                        Some(revision - 1),
                        Some(revision),
                        None,
                    )
                } else {
                    accepted_transition_matches(
                        &rows,
                        revision,
                        "worker_verification_completed",
                        "worker_verification_completed",
                        Some(revision - 1),
                        Some(revision),
                        Some(publication_revision),
                    )
                }
            })
        };
        match (phase.as_str(), publication_delta) {
            ("reviewing", Some(0)) => {}
            ("reviewing", Some(delta)) if delta >= 2 && delta % 2 == 0 => {
                if !transition_chain_matches(delta) {
                    return Err(
                        "publication snapshot is no longer the current review subject".into(),
                    );
                }
            }
            ("assessing", Some(1))
                if rows.iter().any(|(_, next_revision, next_evidence)| {
                    *next_revision == consumer_revision
                        && serde_json::from_str::<serde_json::Value>(next_evidence).is_ok_and(
                            |value| {
                                value["kind"] == "review_assessment"
                                    && value["transition"] == "review_converged"
                            },
                        )
                }) => {}
            ("assessing", Some(delta))
                if delta >= 3
                    && delta % 2 == 1
                    && transition_chain_matches(delta - 1)
                    && rows.iter().any(|(_, next_revision, next_evidence)| {
                        *next_revision == consumer_revision
                            && serde_json::from_str::<serde_json::Value>(next_evidence).is_ok_and(
                                |value| {
                                    value["kind"] == "review_assessment"
                                        && value["transition"] == "review_converged"
                                },
                            )
                    }) => {}
            ("implementing", Some(1))
                if rows.iter().any(|(_, next_revision, next_evidence)| {
                    *next_revision == consumer_revision
                        && serde_json::from_str::<serde_json::Value>(next_evidence).is_ok_and(
                            |value| {
                                value["kind"] == "review_assessment"
                                    && value["transition"] == "corrections_remain"
                            },
                        )
                }) => {}
            ("implementing", Some(delta))
                if delta >= 3
                    && delta % 2 == 1
                    && transition_chain_matches(delta - 1)
                    && accepted_transition_matches(
                        &rows,
                        consumer_revision,
                        "review_assessment",
                        "corrections_remain",
                        Some(consumer_revision - 1),
                        Some(consumer_revision),
                        None,
                    ) => {}
            _ => return Err("publication snapshot is no longer the current review subject".into()),
        }
        let accepted = self
            .latest_accepted_work_plan(project_id, ticket_run_id)?
            .ok_or("publication snapshot has no accepted work plan")?;
        let configuration_digest = Digest::parse(config_digest)?;
        if evidence["plan_digest"].as_str() != Some(accepted.plan_digest.as_str())
            || evidence["configuration_digest"].as_str()
                != Some(accepted.configuration_digest.as_str())
            || accepted.configuration_digest != configuration_digest
        {
            return Err("publication snapshot is bound to a stale plan or configuration".into());
        }
        let prepared_bindings = evidence["prepared_receipts"]
            .as_array()
            .ok_or("publication snapshot has no prepared receipt bindings")?;
        let expected_ids = accepted
            .proposal
            .nodes
            .iter()
            .filter(|node| !node.investigation)
            .map(|node| node.id.as_str().to_owned())
            .collect::<std::collections::BTreeSet<_>>();
        let mut prepared_ids = std::collections::BTreeSet::new();
        let mut prepared_nodes = BTreeMap::new();
        for binding in prepared_bindings {
            let work_node_id = binding["work_node_id"]
                .as_str()
                .ok_or("prepared binding has no node ID")?;
            let operation_id = binding["operation_id"]
                .as_str()
                .ok_or("prepared binding has no operation ID")?;
            let receipt_digest = binding["receipt_digest"]
                .as_str()
                .ok_or("prepared binding has no receipt digest")?;
            if !prepared_ids.insert(work_node_id.to_owned()) {
                return Err("prepared receipt snapshot repeats a work node".into());
            }
            let stored = self
                .succeeded_effect_receipt(operation_id)?
                .ok_or("bound prepared-worktree receipt is no longer succeeded")?;
            if stored.intent().kind
                != crate::engine::reducer::effect_name(
                    &crate::engine::reducer::EffectKind::PrepareWorktrees,
                )
                || stored.intent().project_id != *project_id
                || stored.intent().subject_type != "ticket_run"
                || stored.intent().subject_id != ticket_run_id.as_str()
                || stored
                    .intent()
                    .expected_revision
                    .is_none_or(|source| source > source_revision)
                || sha256(stored.receipt_json().as_bytes()) != receipt_digest
            {
                return Err(
                    "bound prepared-worktree receipt differs from the publication snapshot".into(),
                );
            }
            let prepare_request: crate::delivery_runtime::PrepareWorktreesEffectPayload =
                crate::protocol::parse_unique(stored.intent().request_json.as_bytes())?;
            if prepare_request.ticket_run_id != *ticket_run_id
                || prepare_request.configuration_digest != configuration_digest
            {
                return Err(
                    "prepared receipt request differs from the accepted run or configuration"
                        .into(),
                );
            }
            let (_, prepared) = crate::delivery_runtime::validate_prepared_worktree_stage(&stored)?;
            let node = prepared
                .work_nodes
                .into_iter()
                .find(|node| node.work_node_id.as_str() == work_node_id)
                .ok_or("prepared receipt binding names a node absent from its receipt")?;
            prepared_nodes.insert(work_node_id.to_owned(), node);
        }
        if prepared_ids != expected_ids {
            return Err(
                "prepared receipt snapshot does not cover every accepted implementation node"
                    .into(),
            );
        }
        let prepared_receipt = PreparedWorktreesEffectReceipt {
            schema_version: 1,
            ticket_run_id: ticket_run_id.clone(),
            work_nodes: prepared_nodes.into_values().collect(),
        };
        let bindings = evidence["publication_receipts"]
            .as_array()
            .ok_or("publication snapshot has no receipt bindings")?;
        let mut observed_ids = std::collections::BTreeSet::new();
        let mut publication_receipts = Vec::new();
        for binding in bindings {
            let work_node_id = binding["work_node_id"]
                .as_str()
                .ok_or("publication binding has no node ID")?;
            let operation_id = binding["operation_id"]
                .as_str()
                .ok_or("publication binding has no operation ID")?;
            let receipt_digest = binding["receipt_digest"]
                .as_str()
                .ok_or("publication binding has no receipt digest")?;
            if !observed_ids.insert(work_node_id.to_owned()) {
                return Err("publication snapshot repeats a work node".into());
            }
            let receipt = self
                .succeeded_effect_receipt(operation_id)?
                .ok_or("bound implementation publication receipt is no longer succeeded")?;
            if receipt.intent().kind
                != crate::engine::reducer::effect_name(
                    &crate::engine::reducer::EffectKind::PublishImplementation,
                )
                || receipt.intent().project_id != *project_id
                || receipt.intent().subject_type != "ticket_run"
                || receipt.intent().subject_id != ticket_run_id.as_str()
                || receipt
                    .intent()
                    .expected_revision
                    .is_none_or(|revision| revision > source_revision)
                || sha256(receipt.receipt_json().as_bytes()) != receipt_digest
            {
                return Err(
                    "bound implementation receipt differs from the committed publication snapshot"
                        .into(),
                );
            }
            let request: crate::delivery_runtime::PublishImplementationEffectPayload =
                crate::protocol::parse_unique(receipt.intent().request_json.as_bytes())?;
            if request.work_node_id.as_str() != work_node_id
                || request.ticket_run_id != *ticket_run_id
                || request.configuration_digest != configuration_digest
            {
                return Err("publication receipt request differs from its node, run, or configuration binding".into());
            }
            publication_receipts.push(receipt);
        }
        if observed_ids != expected_ids || publication_receipts.is_empty() {
            return Err(
                "publication snapshot does not cover every accepted implementation node".into(),
            );
        }
        let digest_input = serde_json::to_string(&(&accepted.plan_digest, &bindings))
            .map_err(|error| error.to_string())?;
        if sha256(digest_input.as_bytes())
            != evidence["publication_set_digest"]
                .as_str()
                .unwrap_or_default()
        {
            return Err(
                "publication snapshot digest does not match its committed receipt bindings".into(),
            );
        }
        let verification_revision = match (phase.as_str(), publication_delta) {
            ("reviewing", Some(delta)) if delta >= 2 && delta % 2 == 0 => Some(consumer_revision),
            ("assessing", Some(delta)) if delta >= 3 && delta % 2 == 1 => {
                consumer_revision.checked_sub(1)
            }
            _ => None,
        };
        let verification = if let Some(verification_revision) = verification_revision {
            let (_, _, transition_json) = rows
                .iter()
                .find(|(_, next_revision, _)| *next_revision == verification_revision)
                .ok_or("verification transition is missing from the current review subject")?;
            let transition: serde_json::Value =
                crate::protocol::parse_unique(transition_json.as_bytes())?;
            let value = &transition["verification"];
            let parsed: AcceptedWorkerVerification = serde_json::from_value(serde_json::json!({
                "review_revision": value["review_revision"],
                "source_revision": value["source_revision"],
                "source_evidence_id": value["source_evidence_id"],
                "source_agent_run_id": value["source_agent_run_id"],
                "source_result_digest": value["source_result_digest"],
                "publication_revision": value["publication_revision"],
                "publication_operation_id": value["publication_operation_id"],
                "published_head": value["published_head"],
                "work_node_id": value["work_node_id"],
                "repository_id": value["repository_id"],
                "test_receipt_artifacts": value["test_receipt_artifacts"],
            }))
            .map_err(|error| {
                format!("stored Worker verification transition is invalid: {error}")
            })?;
            if transition["source_revision"].as_u64() != Some(parsed.source_revision)
                || transition["accepted_revision"].as_u64() != Some(parsed.review_revision)
                || transition["evidence_id"].as_str() != Some(parsed.source_evidence_id.as_str())
                || transition["result_digest"].as_str()
                    != Some(parsed.source_result_digest.as_str())
                || transition["kind"] != "worker_verification_completed"
                || transition["transition"] != "worker_verification_completed"
                || parsed.review_revision != verification_revision
                || parsed.source_revision.checked_add(1) != Some(verification_revision)
                || parsed.publication_revision != publication_revision
                || parsed.test_receipt_artifacts.is_empty()
                || parsed
                    .test_receipt_artifacts
                    .iter()
                    .map(|artifact| artifact.artifact_id.as_str())
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    != parsed.test_receipt_artifacts.len()
                || parsed.test_receipt_artifacts.iter().any(|artifact| {
                    artifact.kind != crate::engine::orchestration::RoleArtifactKind::TestReceipt
                })
            {
                return Err(
                    "Worker verification transition is not bound to its accepted review revision"
                        .into(),
                );
            }
            let matching_publication = publication_receipts
                .iter()
                .filter_map(|receipt| {
                    let request: crate::delivery_runtime::PublishImplementationEffectPayload =
                        crate::protocol::parse_unique(receipt.intent().request_json.as_bytes())
                            .ok()?;
                    (request.work_node_id == parsed.work_node_id).then_some((receipt, request))
                })
                .collect::<Vec<_>>();
            if matching_publication.len() != 1 {
                return Err(
                    "Worker verification does not identify exactly one accepted publication".into(),
                );
            }
            let (receipt, request) = &matching_publication[0];
            let published: crate::delivery_runtime::ImplementationPublicationReceipt =
                crate::protocol::parse_unique(receipt.receipt_json().as_bytes())?;
            if receipt.intent().operation_id != parsed.publication_operation_id.as_str()
                || request.repository_id != parsed.repository_id
                || published.commit.head() != parsed.published_head.as_str()
                || published.repository_id != parsed.repository_id
            {
                return Err(
                    "Worker verification differs from the exact accepted publication receipt"
                        .into(),
                );
            }
            Some(parsed)
        } else {
            None
        };
        Ok(AcceptedImplementationPublicationSnapshot {
            accepted_plan: accepted,
            publication_revision,
            prepared_receipt,
            publication_receipts,
            verification,
        })
    }

    /// Return a Worker context only when the supplied success receipt was
    /// re-read from the effects table and exactly covers the current accepted
    /// plan plus prepared worktree receipt.
    pub fn prepared_worker_launch(
        &self,
        owner_generation: u64,
        accepted_revision: u64,
        node_id: &WorkNodeId,
        succeeded: &SucceededEffectReceipt,
        project_config: &ProjectConfig,
        configuration_digest: &Digest,
    ) -> Result<Option<PreparedWorkerLaunch>, String> {
        let active_generation: Option<u64> = self.connection.query_row(
            "SELECT generation FROM controller_owners WHERE singleton=1 AND stopped_at_unix IS NULL",
            [],
            |row| row.get(0),
        ).optional().map_err(|error| error.to_string())?;
        if active_generation != Some(owner_generation) {
            return Err("Worker launch context is fenced to a stale controller generation".into());
        }
        let intent = succeeded.intent();
        if intent.kind != "prepare_worktrees"
            || intent.subject_type != "ticket_run"
            || intent.expected_revision.is_none()
        {
            return Ok(None);
        }
        let project_id = &intent.project_id;
        let ticket_run_id = TicketRunId::parse(intent.subject_id.clone())?;
        let current: Option<(String, u64, String)> = self
            .connection
            .query_row(
                "SELECT project_id,revision,internal_phase FROM ticket_runs WHERE ticket_run_id=?1",
                [ticket_run_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let Some((current_project, current_revision, current_phase)) = current else {
            return Ok(None);
        };
        if current_project != project_id.as_str() || current_phase != "implementing" {
            return Ok(None);
        }
        if intent
            .expected_revision
            .is_none_or(|revision| revision > current_revision)
        {
            return Ok(None);
        }
        let Some(plan) = self.accepted_work_plan(project_id, &ticket_run_id, accepted_revision)?
        else {
            return Ok(None);
        };
        let validated_plan = plan.validate_for(project_config, configuration_digest)?;
        let Some(node) = validated_plan
            .nodes_in_execution_order
            .iter()
            .find(|node| &node.id == node_id)
        else {
            return Ok(None);
        };
        if node.role != crate::domain::types::Role::Worker {
            return Ok(None);
        }
        let coordinator: Option<(String,String,String,String,String)> = self.connection.query_row(
            "SELECT project_id,role,role_session_id,ticket_run_id,authority_digest FROM agent_launch_authority WHERE agent_run_id=?1",
            [plan.coordinator_agent_run_id.as_str()],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)),
        ).optional().map_err(|error| error.to_string())?;
        let Some((
            coordinator_project,
            coordinator_role,
            coordinator_session,
            coordinator_ticket,
            coordinator_authority_digest,
        )) = coordinator
        else {
            return Ok(None);
        };
        if coordinator_project != project_id.as_str()
            || coordinator_role != "coordinator"
            || coordinator_session != plan.coordinator_role_session_id
            || coordinator_ticket != ticket_run_id.as_str()
            || Digest::parse(coordinator_authority_digest)? != plan.coordinator_authority_digest
        {
            return Err(
                "accepted plan Coordinator provenance no longer matches launch authority".into(),
            );
        }
        let payload: PrepareWorktreesEffectPayload = parse_canonical(&intent.request_json)?;
        if digest_json(&intent.request_json).as_str() != intent.request_digest
            || payload.ticket_run_id != ticket_run_id
            || Some(payload.source_revision) != intent.expected_revision
            || payload.configuration_digest != plan.configuration_digest
        {
            return Err("PrepareWorktrees effect does not match accepted plan".into());
        }
        let requested = payload
            .work_nodes
            .iter()
            .find(|entry| entry.work_node_id == *node_id);
        let Some(requested) = requested else {
            return Ok(None);
        };
        if requested.repository_id != node.repository {
            return Err("prepared Worker repository differs from accepted plan".into());
        }
        let receipt: PreparedWorktreesEffectReceipt = parse_unique(succeeded.receipt_json())?;
        if receipt.schema_version != 1 || receipt.ticket_run_id != ticket_run_id {
            return Err("prepared receipt has invalid scope".into());
        }
        let Some(prepared) = receipt
            .work_nodes
            .iter()
            .find(|entry| entry.work_node_id == *node_id)
        else {
            return Ok(None);
        };
        if prepared.repository_id != node.repository
            || prepared.base_sha != requested.expected_base_sha
            || !prepared.worktree_path.is_absolute()
            || prepared.branch.trim().is_empty()
        {
            return Err("prepared worktree does not match accepted Worker node".into());
        }
        let correction_transition: Option<String> = self
            .connection
            .query_row(
                "SELECT evidence_json FROM transitions WHERE entity_type='ticket_run' AND entity_id=?1 AND project_id=?2 AND new_revision=?3",
                params![ticket_run_id.as_str(), project_id.as_str(), current_revision],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let expected_head = match correction_transition {
            Some(evidence_json)
                if serde_json::from_str::<serde_json::Value>(&evidence_json).is_ok_and(
                    |value| {
                        value["kind"] == "review_assessment"
                            && value["transition"] == "corrections_remain"
                    },
                ) =>
            {
                let snapshot = self.accepted_implementation_publication_snapshot(
                    owner_generation,
                    project_id,
                    &ticket_run_id,
                    current_revision,
                )?;
                let matching = snapshot
                    .publication_receipts
                    .iter()
                    .filter_map(|publication| {
                        let request: crate::delivery_runtime::PublishImplementationEffectPayload =
                            crate::protocol::parse_unique(
                                publication.intent().request_json.as_bytes(),
                            )
                            .ok()?;
                        (request.work_node_id == *node_id).then_some((publication, request))
                    })
                    .collect::<Vec<_>>();
                if matching.len() != 1 {
                    return Err("review correction publication does not cover this Worker node exactly once".into());
                }
                let (publication, request) = &matching[0];
                let receipt: crate::delivery_runtime::ImplementationPublicationReceipt =
                    crate::protocol::parse_unique(publication.receipt_json().as_bytes())?;
                if request.ticket_run_id != ticket_run_id
                    || request.repository_id != node.repository
                    || request.configuration_digest != plan.configuration_digest
                    || receipt.ticket_run_id != ticket_run_id
                    || receipt.work_node_id != *node_id
                    || receipt.repository_id != node.repository
                    || receipt.configuration_digest != plan.configuration_digest
                {
                    return Err(
                        "review correction publication differs from the accepted Worker node"
                            .into(),
                    );
                }
                Some(receipt.commit.head().to_owned())
            }
            _ => None,
        };
        Ok(Some(PreparedWorkerLaunch {
            project_id: project_id.clone(),
            ticket_run_id,
            accepted_revision,
            ticket_revision: current_revision,
            configuration_digest: plan.configuration_digest,
            plan_digest: plan.plan_digest,
            node_id: node.id.clone(),
            repository_id: node.repository.clone(),
            commit_mode: requested.commit_mode,
            worktree_path: prepared.worktree_path.clone(),
            branch: prepared.branch.clone(),
            base_sha: prepared.base_sha.clone(),
            expected_head,
            prepare_operation_id: intent.operation_id.clone(),
            prepare_receipt_digest: digest_json(succeeded.receipt_json()),
            source_evidence_id: plan.source_evidence_id,
            source_agent_run_id: plan.source_agent_run_id,
            source_message_id: plan.source_message_id,
            source_result_digest: plan.source_result_digest,
            coordinator_agent_run_id: plan.coordinator_agent_run_id,
            coordinator_role_session_id: plan.coordinator_role_session_id,
            coordinator_authority_digest: plan.coordinator_authority_digest,
        }))
    }
}

fn parse_canonical<T: serde::de::DeserializeOwned>(json: &str) -> Result<T, String> {
    let value: serde_json::Value =
        crate::protocol::parse_unique(json.as_bytes()).map_err(|error| error.to_string())?;
    if serde_json::to_string(&value).map_err(|error| error.to_string())? != json {
        return Err("stored JSON is not canonical".into());
    }
    serde_json::from_value(value).map_err(|error| error.to_string())
}

fn parse_unique<T: serde::de::DeserializeOwned>(json: &str) -> Result<T, String> {
    crate::protocol::parse_unique(json.as_bytes()).map_err(|error| error.to_string())
}

fn digest_json(json: &str) -> Digest {
    use sha2::Digest as _;
    Digest::parse(format!("{:x}", sha2::Sha256::digest(json.as_bytes())))
        .expect("sha256 is valid digest")
}

fn sha256(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    format!("{:x}", sha2::Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::ids::{RepositoryId, TicketRunId};
    use crate::domain::types::Role;
    use crate::engine::orchestration::{
        PlannedWorkNode, ValidatedWorkNode, WorkBaseSource, WorkDependency, WorkPlan,
    };
    use std::collections::BTreeSet;

    fn plan_pair() -> (ValidatedPlan, WorkPlan) {
        let node_id = WorkNodeId::parse("implement").unwrap();
        let repository = RepositoryId::parse("repo-a").unwrap();
        let ticket_run_id = TicketRunId::parse("run-a").unwrap();
        let dependency = WorkDependency {
            node: WorkNodeId::parse("prepare").unwrap(),
            kind: crate::engine::orchestration::WorkDependencyKind::GitBase,
            affected_evidence: BTreeSet::new(),
        };
        let validated = ValidatedPlan {
            ticket_run_id,
            nodes_in_execution_order: vec![ValidatedWorkNode {
                id: node_id.clone(),
                repository: repository.clone(),
                base: WorkBaseSource::ControllerObservedCommit {
                    commit: "a".repeat(40),
                },
                task: "Implement the requested change".into(),
                depends_on: vec![dependency.clone()],
                required_evidence: vec!["tests pass".into()],
                role: Role::Worker,
            }],
            spawned_investigation_children: 0,
        };
        let claim = WorkPlan {
            nodes: vec![PlannedWorkNode {
                id: node_id,
                repository,
                task: "Implement the requested change".into(),
                depends_on: vec![dependency],
                required_evidence: vec!["tests pass".into()],
                investigation: false,
            }],
            requested_investigation_children: 0,
        };
        (validated, claim)
    }

    #[test]
    fn accepted_plan_must_match_every_claimed_node_field() {
        let (validated, claim) = plan_pair();
        assert!(validated_plan_matches_claim(&validated, &claim));

        let mut changed = claim.clone();
        changed.nodes[0].task.push_str(" with unrelated scope");
        assert!(!validated_plan_matches_claim(&validated, &changed));

        let mut wrong_role = claim;
        wrong_role.nodes[0].investigation = true;
        assert!(!validated_plan_matches_claim(&validated, &wrong_role));
    }
}
