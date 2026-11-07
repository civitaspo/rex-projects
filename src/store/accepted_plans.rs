//! Durable, revision-bound accepted work plans and host-minted Worker inputs.

use rusqlite::{OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};

use crate::delivery_runtime::{PrepareWorktreesEffectPayload, PreparedWorktreesEffectReceipt};
use crate::domain::ids::{Digest, ProjectId, RepositoryId, TicketRunId};
use crate::domain::types::CommitMode;
use crate::engine::orchestration::{ValidatedPlan, WorkNodeId};
use crate::store::{ConfigStore, SucceededEffectReceipt};

const MAX_PLAN_BYTES: usize = 1_048_576;

#[derive(Clone, Debug)]
pub(crate) struct AcceptedPlanWrite {
    pub configuration_digest: Digest,
    pub plan_digest: Digest,
    pub plan_json: String,
}

pub(crate) fn prepare_accepted_plan_write(
    ticket_run_id: &TicketRunId,
    plan: &ValidatedPlan,
    configuration_digest: &Digest,
) -> Result<AcceptedPlanWrite, String> {
    if plan.ticket_run_id != *ticket_run_id
        || plan.nodes_in_execution_order.is_empty()
        || plan.nodes_in_execution_order.len() > 64
    {
        return Err("validated work plan has invalid TicketRun binding or node count".into());
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
    let plan_json = serde_json::to_string(plan).map_err(|error| error.to_string())?;
    if plan_json.len() > MAX_PLAN_BYTES {
        return Err("validated work plan exceeds storage limit".into());
    }
    Ok(AcceptedPlanWrite {
        configuration_digest: configuration_digest.clone(),
        plan_digest: digest_json(&plan_json),
        plan_json,
    })
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedWorkPlanRecord {
    pub project_id: ProjectId,
    pub ticket_run_id: TicketRunId,
    /// Revision of the TicketRun after PlanAccepted committed.
    pub accepted_revision: u64,
    pub configuration_digest: Digest,
    pub plan_digest: Digest,
    pub plan: ValidatedPlan,
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
}

impl PreparedWorkerLaunch {
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
        let row: Option<(String,String,String)> = self.connection.query_row(
            "SELECT configuration_digest,plan_digest,plan_json FROM accepted_work_plans WHERE project_id=?1 AND ticket_run_id=?2 AND accepted_revision=?3",
            params![project_id.as_str(),ticket_run_id.as_str(),accepted_revision],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
        ).optional().map_err(|error| error.to_string())?;
        let Some((configuration_digest, stored_plan_digest, plan_json)) = row else {
            return Ok(None);
        };
        let plan: ValidatedPlan = parse_canonical(&plan_json)?;
        if plan.ticket_run_id != *ticket_run_id {
            return Err("stored accepted plan TicketRun binding is invalid".into());
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
            plan,
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
        let Some(node) = plan
            .plan
            .nodes_in_execution_order
            .iter()
            .find(|node| &node.id == node_id)
        else {
            return Ok(None);
        };
        if node.role != crate::domain::types::Role::Worker {
            return Ok(None);
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
