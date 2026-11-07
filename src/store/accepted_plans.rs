//! Durable, revision-bound accepted work plans and host-minted Worker inputs.

use std::collections::BTreeMap;

use rusqlite::{OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};

use crate::config::ProjectConfig;
use crate::delivery_runtime::{PrepareWorktreesEffectPayload, PreparedWorktreesEffectReceipt};
use crate::domain::ids::{AgentRunId, Digest, ProjectId, RepositoryId, TicketRunId};
use crate::domain::types::CommitMode;
use crate::engine::orchestration::{ValidatedPlan, WorkNodeId, WorkPlan};
use crate::store::{ConfigStore, SucceededEffectReceipt};

const MAX_PLAN_BYTES: usize = 1_048_576;

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
        {
            if let Some(previous) =
                observed_base_shas.insert(node.repository.clone(), commit.clone())
                && previous != *commit
            {
                return Err("validated plan has inconsistent observed repository bases".into());
            }
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

    let accepted: Option<(String, String, String, String, String, String, String, String, String, String)> = tx
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

    let effect: Option<(String, String, String, String, Option<u64>, String, String, String)> = tx
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
        let row: Option<(String,String,String,String,String,String,String,String,String,String)> = self.connection.query_row(
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
            || intent.expected_revision != Some(accepted_revision)
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
            || payload.source_revision != accepted_revision
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

fn parse_unique<T: serde::de::DeserializeOwned>(json: &str) -> Result<T, String> {
    crate::protocol::parse_unique(json.as_bytes()).map_err(|error| error.to_string())
}

fn digest_json(json: &str) -> Digest {
    use sha2::Digest as _;
    Digest::parse(format!("{:x}", sha2::Sha256::digest(json.as_bytes())))
        .expect("sha256 is valid digest")
}
