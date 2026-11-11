//! Public, digest-bound recovery requests for an exhausted MergeDecision claim.
//!
//! This module owns the durable request queue. Enqueueing is only human intent;
//! the foreground controller must independently observe and authorize recovery.

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::Digest as _;

use super::ConfigStore;
use crate::domain::ids::{Digest, ProjectId, TicketRunId};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MergeClaimRecoverySubject {
    pub project_id: ProjectId,
    pub ticket_run_id: TicketRunId,
    pub ticket_namespace: String,
    pub ticket_id: String,
    pub blocked_revision: u64,
    pub convergence_revision: u64,
    pub configuration_revision: u64,
    pub configuration_digest: Digest,
    pub accepted_plan_digest: Digest,
    pub source_evidence_id: String,
    pub source_result_digest: Digest,
    pub authority_digest: Digest,
    pub instruction_digest: Digest,
    pub publication_set_digest: Digest,
    pub expected_pull_request_reference: String,
    pub reason: String,
}

impl MergeClaimRecoverySubject {
    pub fn digest(&self) -> Result<Digest, String> {
        let bytes = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        Digest::parse(format!("{:x}", sha2::Sha256::digest(bytes)))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MergeClaimRecoveryReceipt {
    pub request_id: String,
    pub subject_digest: Digest,
    pub project_id: ProjectId,
    pub ticket_run_id: TicketRunId,
    pub blocked_revision: u64,
    pub state: String,
    pub replayed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MergeClaimRecoveryStatus {
    pub request_id: String,
    pub project_id: ProjectId,
    pub ticket_run_id: TicketRunId,
    pub state: String,
    pub rejection_reason: Option<String>,
    pub budget_used: bool,
    pub updated_at_unix: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingMergeClaimRecovery {
    pub request_id: String,
    pub subject: MergeClaimRecoverySubject,
    pub subject_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedMergeClaimRecovery {
    pub request_id: String,
    pub subject: MergeClaimRecoverySubject,
    pub subject_digest: Digest,
    pub authorization_key: Digest,
    pub state: String,
    pub coordinator_evidence_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsumedMergeClaimRecovery {
    pub request_id: String,
    pub subject: MergeClaimRecoverySubject,
    pub subject_digest: Digest,
    pub authorization_key: Digest,
    pub coordinator_evidence_id: String,
}

pub(super) fn authorized_recovery_for_coordinator_run(
    connection: &Connection,
    project_id: &ProjectId,
    ticket_run_id: &TicketRunId,
    agent_run_id: &crate::domain::ids::AgentRunId,
    ticket_revision: u64,
) -> Result<Option<AuthorizedMergeClaimRecovery>, String> {
    let mut statement = connection.prepare(
        "SELECT w.source_type,w.source_id,w.source_revision,w.payload_json,r.subject_json,r.subject_digest,r.authorization_key,r.state,r.coordinator_evidence_id FROM role_wake_inputs w JOIN merge_claim_recovery_requests r ON r.request_id=w.source_id WHERE w.consuming_agent_run_id=?1 AND w.project_id=?2 AND w.role_session_id=?3 AND w.source_revision=?4 AND w.lifecycle IN ('assigned','claimed','consumed') AND json_extract(w.payload_json,'$.ticket_run_id')=?5 AND r.state IN ('authorized','consumed') ORDER BY w.wake_input_id",
    ).map_err(|error| error.to_string())?;
    let rows = statement
        .query_map(
            params![
                agent_run_id.as_str(),
                project_id.as_str(),
                format!("ticket_run:{ticket_run_id}:coordinator"),
                ticket_revision,
                ticket_run_id.as_str()
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, u64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, Option<String>>(8)?,
                ))
            },
        )
        .map_err(|error| error.to_string())?;
    let mut found = None;
    for row in rows {
        let (
            source_type,
            request_id,
            source_revision,
            payload_json,
            subject_json,
            subject_digest,
            authorization_key,
            state,
            coordinator_evidence_id,
        ) = row.map_err(|error| error.to_string())?;
        if source_type != "merge_claim_recovery_authorized" {
            continue;
        }
        let payload: serde_json::Value = crate::protocol::parse_unique(payload_json.as_bytes())?;
        let subject: MergeClaimRecoverySubject =
            crate::protocol::parse_unique(subject_json.as_bytes())?;
        let subject_digest = Digest::parse(subject_digest)?;
        let authorization_key = Digest::parse(authorization_key)?;
        if subject.project_id != *project_id
            || subject.ticket_run_id != *ticket_run_id
            || subject.digest()? != subject_digest
            || payload["request_id"].as_str() != Some(request_id.as_str())
            || payload["subject_digest"].as_str() != Some(subject_digest.as_str())
            || payload["authorization_key"].as_str() != Some(authorization_key.as_str())
            || payload["source_revision"].as_u64() != Some(source_revision)
        {
            return Err("Coordinator recovery input differs from its durable authorization".into());
        }
        let authorization = AuthorizedMergeClaimRecovery {
            request_id,
            subject,
            subject_digest,
            authorization_key,
            state,
            coordinator_evidence_id,
        };
        if found.replace(authorization).is_some() {
            return Err(
                "Coordinator run consumed multiple MergeDecision recovery authorizations".into(),
            );
        }
    }
    Ok(found)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MergeClaimRecoveryObservation {
    Current {
        ticket_namespace: String,
        ticket_id: String,
        ticket_status: crate::adapters::tickets::NormalizedTicketStatus,
        publication_set_digest: Digest,
        pull_request_reference: String,
    },
    Stale(String),
    TemporarilyUnavailable,
}

fn parse_enum<T: DeserializeOwned>(value: &str) -> Result<T, String> {
    serde_json::from_str(&format!("\"{value}\""))
        .map_err(|error| format!("stored workflow value `{value}` is invalid: {error}"))
}

pub(crate) fn migrate_v16(connection: &Connection) -> Result<(), String> {
    let tx = connection
        .unchecked_transaction()
        .map_err(|error| error.to_string())?;
    let version: i64 = tx
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| error.to_string())?;
    if version == 16 {
        tx.commit().map_err(|error| error.to_string())?;
        return Ok(());
    }
    if version != 15 {
        return Err(format!(
            "merge claim recovery migration requires schema 15, found {version}"
        ));
    }
    tx.execute_batch(
        "CREATE TABLE merge_claim_recovery_requests (
            request_id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL,
            ticket_run_id TEXT NOT NULL,
            subject_digest TEXT NOT NULL,
            subject_json TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('pending','authorized','rejected','consumed','accepted','reblocked')),
            authorization_key TEXT,
            rejection_reason TEXT,
            coordinator_evidence_id TEXT,
            resumed_result_evidence_id TEXT,
            created_at_unix INTEGER NOT NULL,
            updated_at_unix INTEGER NOT NULL
         );
         CREATE UNIQUE INDEX merge_claim_recovery_one_per_lineage
            ON merge_claim_recovery_requests(project_id,ticket_run_id,authorization_key)
            WHERE authorization_key IS NOT NULL;
         INSERT INTO schema_migrations(version,applied_at_unix)
            VALUES (16,unixepoch());
         PRAGMA user_version=16;",
    )
    .map_err(|error| error.to_string())?;
    tx.commit().map_err(|error| error.to_string())
}

pub(super) fn validate_v16_schema(connection: &Connection) -> Result<(), String> {
    let recorded: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=16)",
            [],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    if !recorded {
        return Err("schema 16 migration record is missing".into());
    }
    let canonical = Connection::open_in_memory().map_err(|error| error.to_string())?;
    canonical
        .execute_batch(
            "CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY,applied_at_unix INTEGER NOT NULL);
             PRAGMA user_version=15;",
        )
        .map_err(|error| error.to_string())?;
    migrate_v16(&canonical)?;
    super::artifact_registry::validate_table_layout_against(
        connection,
        &canonical,
        "merge_claim_recovery_requests",
    )
}

impl ConfigStore {
    #[cfg(test)]
    pub(crate) fn insert_merge_claim_recovery_status_fixture(
        &mut self,
        request_id: &str,
        project_id: &ProjectId,
        ticket_run_id: &TicketRunId,
        state: &str,
        authorization_key: Option<&str>,
    ) -> Result<(), String> {
        self.connection.execute(
            "INSERT INTO merge_claim_recovery_requests(request_id,project_id,ticket_run_id,subject_digest,subject_json,state,authorization_key,rejection_reason,created_at_unix,updated_at_unix) VALUES (?1,?2,?3,?4,'{}',?5,?6,NULL,1,2)",
            params![request_id, project_id.as_str(), ticket_run_id.as_str(), "0".repeat(64), state, authorization_key],
        ).map_err(|error| error.to_string())?;
        Ok(())
    }

    /// Resolve the immutable recovery subject for a canonical Coordinator child wake.
    /// The caller must already have selected the exact persisted `coordinator_child`
    /// wake; the durable Coordinator evidence ID binds it to the one consumed request.
    pub(crate) fn merge_claim_recovery_subject_for_coordinator_child(
        &self,
        project_id: &ProjectId,
        ticket_run_id: &TicketRunId,
        coordinator_evidence_id: &str,
    ) -> Result<Option<MergeClaimRecoverySubject>, String> {
        let row: Option<(String, String)> = self.connection.query_row(
            "SELECT subject_json,subject_digest FROM merge_claim_recovery_requests WHERE project_id=?1 AND ticket_run_id=?2 AND coordinator_evidence_id=?3 AND state IN ('consumed','accepted','reblocked')",
            params![project_id.as_str(), ticket_run_id.as_str(), coordinator_evidence_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional().map_err(|error| error.to_string())?;
        let Some((subject_json, subject_digest)) = row else {
            return Ok(None);
        };
        let subject: MergeClaimRecoverySubject =
            crate::protocol::parse_unique(subject_json.as_bytes())?;
        if subject.project_id != *project_id
            || subject.ticket_run_id != *ticket_run_id
            || subject.digest()?.as_str() != subject_digest
        {
            return Err(
                "Coordinator child recovery subject no longer matches its durable request".into(),
            );
        }
        Ok(Some(subject))
    }

    pub(crate) fn merge_claim_recovery_subject_for_assessment(
        &self,
        project_id: &ProjectId,
        ticket_run_id: &TicketRunId,
        assessment_evidence_id: &str,
    ) -> Result<Option<MergeClaimRecoverySubject>, String> {
        let row: Option<(String, String)> = self.connection.query_row(
            "SELECT subject_json,subject_digest FROM merge_claim_recovery_requests WHERE project_id=?1 AND ticket_run_id=?2 AND resumed_result_evidence_id=?3 AND state='accepted'",
            params![project_id.as_str(), ticket_run_id.as_str(), assessment_evidence_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional().map_err(|error| error.to_string())?;
        let Some((subject_json, subject_digest)) = row else {
            return Ok(None);
        };
        let subject: MergeClaimRecoverySubject =
            crate::protocol::parse_unique(subject_json.as_bytes())?;
        if subject.project_id != *project_id
            || subject.ticket_run_id != *ticket_run_id
            || subject.digest()?.as_str() != subject_digest
        {
            return Err(
                "trusted assessment recovery subject no longer matches its durable request".into(),
            );
        }
        Ok(Some(subject))
    }

    pub fn merge_claim_recovery_status(
        &self,
        request_id: &str,
    ) -> Result<Option<MergeClaimRecoveryStatus>, String> {
        type RecoveryStatusRow = (
            String,
            String,
            String,
            String,
            Option<String>,
            Option<String>,
            i64,
        );
        let row: Option<RecoveryStatusRow> = self.connection.query_row(
            "SELECT r.request_id,r.project_id,r.ticket_run_id,r.state,r.rejection_reason,r.authorization_key,r.updated_at_unix FROM merge_claim_recovery_requests r WHERE r.request_id=?1",
            [request_id],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?)),
        ).optional().map_err(|error| error.to_string())?;
        let Some((
            request_id,
            project_id,
            ticket_run_id,
            state,
            rejection_reason,
            authorization_key,
            updated_at_unix,
        )) = row
        else {
            return Ok(None);
        };
        Ok(Some(MergeClaimRecoveryStatus {
            request_id,
            project_id: ProjectId::parse(project_id)?,
            ticket_run_id: TicketRunId::parse(ticket_run_id)?,
            budget_used: authorization_key.is_some(),
            state,
            rejection_reason,
            updated_at_unix,
        }))
    }

    pub fn merge_claim_recovery_budget_used(
        &self,
        subject: &MergeClaimRecoverySubject,
    ) -> Result<bool, String> {
        let key = authorization_key(subject)?;
        self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM merge_claim_recovery_requests WHERE project_id=?1 AND ticket_run_id=?2 AND authorization_key=?3)",
            params![subject.project_id.as_str(),subject.ticket_run_id.as_str(),key.as_str()],
            |row| row.get(0),
        ).map_err(|error| error.to_string())
    }

    pub fn recovery_authorization_for_coordinator_result(
        &self,
        result: &crate::store::agent_results::IngestedAgentResult,
    ) -> Result<Option<AuthorizedMergeClaimRecovery>, String> {
        let binding = &result.validated.binding;
        if binding.role != crate::domain::types::Role::Coordinator {
            return Ok(None);
        }
        let Some(ticket_run_id) = &binding.ticket_run_id else {
            return Ok(None);
        };
        let Some(ticket_revision) = binding.ticket_revision else {
            return Ok(None);
        };
        authorized_recovery_for_coordinator_run(
            &self.connection,
            &binding.project_id,
            ticket_run_id,
            &binding.agent_run_id,
            ticket_revision.0,
        )
    }

    pub fn recovery_authorization_for_merge_result(
        &self,
        result: &crate::store::agent_results::IngestedAgentResult,
    ) -> Result<Option<ConsumedMergeClaimRecovery>, String> {
        let binding = &result.validated.binding;
        let Some(ticket_run_id) = &binding.ticket_run_id else {
            return Ok(None);
        };
        if binding.role != crate::domain::types::Role::MergeDecision {
            return Ok(None);
        }
        let authority_json:Option<(String,String)>=self.connection.query_row(
            "SELECT authority_json,authority_digest FROM agent_launch_authority WHERE agent_run_id=?1 AND project_id=?2",
            params![binding.agent_run_id.as_str(),binding.project_id.as_str()],|row|Ok((row.get(0)?,row.get(1)?)),
        ).optional().map_err(|error|error.to_string())?;
        let Some((authority_json, stored_authority_digest)) = authority_json else {
            return Ok(None);
        };
        let authority: crate::launch::AgentLaunchAuthority =
            crate::protocol::parse_unique(authority_json.as_bytes())?;
        if authority.digest()?.as_str() != stored_authority_digest
            || authority.role != crate::domain::types::Role::MergeDecision
            || authority.role_session_id != format!("ticket_run:{ticket_run_id}:merge_decision")
            || authority.ticket_run_id.as_ref() != Some(ticket_run_id)
        {
            return Ok(None);
        }
        let Some(parent_run_id) = authority.parent_run_id.as_ref() else {
            return Ok(None);
        };
        type RecoveryResultRow = (
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            String,
        );
        let row: Option<RecoveryResultRow> = self.connection.query_row(
            "SELECT request_id,subject_json,subject_digest,authorization_key,coordinator_evidence_id,state,project_id,ticket_run_id FROM merge_claim_recovery_requests WHERE project_id=?1 AND ticket_run_id=?2 AND state IN ('consumed','accepted','reblocked') AND coordinator_evidence_id=(SELECT e.evidence_id FROM agent_result_evidence e WHERE e.agent_run_id=?3 AND e.role='coordinator' AND e.outcome='completed') ORDER BY updated_at_unix DESC LIMIT 1",
            params![binding.project_id.as_str(),ticket_run_id.as_str(),parent_run_id.as_str()],
            |row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?)),
        ).optional().map_err(|error|error.to_string())?;
        let Some((
            request_id,
            subject_json,
            subject_digest,
            authorization_key,
            coordinator_evidence_id,
            _state,
            project,
            run,
        )) = row
        else {
            return Ok(None);
        };
        let subject: MergeClaimRecoverySubject = serde_json::from_str(&subject_json)
            .map_err(|error| format!("stored recovery subject is invalid: {error}"))?;
        let subject_digest = Digest::parse(subject_digest)?;
        let authorization_key = Digest::parse(authorization_key)?;
        let current:Option<(u64,String,String,String)>=self.connection.query_row(
            "SELECT revision,internal_phase,activity,config_digest FROM ticket_runs WHERE project_id=?1 AND ticket_run_id=?2",
            params![project.as_str(),run.as_str()],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
        ).optional().map_err(|error|error.to_string())?;
        let Some((revision, phase, activity, config_digest)) = current else {
            return Ok(None);
        };
        if subject.digest()? != subject_digest
            || project != binding.project_id.as_str()
            || run != ticket_run_id.as_str()
            || subject.configuration_digest != binding.config_digest
            || config_digest != binding.config_digest.as_str()
            || revision
                != binding
                    .ticket_revision
                    .map(|value| value.0)
                    .unwrap_or_default()
            || revision != subject.blocked_revision.saturating_add(1)
            || phase != "assessing"
            || activity != "running"
            || authority.config_digest != subject.configuration_digest
            || authority.config_revision.0 != subject.configuration_revision
            || authority.instruction_digest != subject.instruction_digest
            || authority.parent_role != Some(crate::domain::types::Role::Coordinator)
        {
            return Ok(None);
        }
        self.merge_claim_recovery_publication_snapshot(&subject)?;
        Ok(Some(ConsumedMergeClaimRecovery {
            request_id,
            subject,
            subject_digest,
            authorization_key,
            coordinator_evidence_id,
        }))
    }

    pub fn fail_resumed_merge_claim_recovery(
        &mut self,
        owner_generation: u64,
        recovery: &ConsumedMergeClaimRecovery,
        result: &crate::store::agent_results::IngestedAgentResult,
        reason: &str,
        now_unix: i64,
    ) -> Result<(), String> {
        let binding = &result.validated.binding;
        let ticket_run_id = binding
            .ticket_run_id
            .as_ref()
            .ok_or("resumed MergeDecision has no TicketRun")?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        super::validate_active_generation(&tx, owner_generation)?;
        let parent:Option<(String,String,String,String)>=tx.query_row(
            "SELECT parent_run_id,parent_role,role,authority_digest FROM agent_launch_authority WHERE agent_run_id=?1 AND project_id=?2",
            params![binding.agent_run_id.as_str(),binding.project_id.as_str()],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
        ).optional().map_err(|error|error.to_string())?;
        let Some((parent_run, parent_role, role, authority_digest)) = parent else {
            return Err("resumed MergeDecision launch authority is missing".into());
        };
        let authority_json: String = tx.query_row(
            "SELECT authority_json FROM agent_launch_authority WHERE agent_run_id=?1 AND project_id=?2",
            params![binding.agent_run_id.as_str(),binding.project_id.as_str()],
            |row| row.get(0),
        ).map_err(|error| error.to_string())?;
        let authority: crate::launch::AgentLaunchAuthority =
            crate::protocol::parse_unique(authority_json.as_bytes())?;
        if role != "merge_decision"
            || parent_role != "coordinator"
            || parent_run.is_empty()
            || authority.digest()?.as_str() != authority_digest
            || authority.agent_run_id != binding.agent_run_id
            || authority.project_id != binding.project_id
            || authority.role != binding.role
            || authority.role_session_id != binding.role_session_id.as_str()
            || authority.parent_run_id != binding.parent_run_id
            || authority.parent_role != binding.parent_role
            || authority.ticket_run_id != binding.ticket_run_id
            || authority.ticket_revision != binding.ticket_revision
            || authority.config_revision != binding.config_revision
            || authority.config_digest != binding.config_digest
            || authority.instruction_digest != binding.instruction_digest
        {
            return Err(format!(
                "resumed MergeDecision authority differs from its recovery lineage: {reason}"
            ));
        }
        let owner:Option<String>=tx.query_row(
            "SELECT e.agent_run_id FROM agent_result_evidence e WHERE e.evidence_id=?1 AND e.outcome='completed' AND e.role='coordinator'",
            [&recovery.coordinator_evidence_id],|row|row.get(0),
        ).optional().map_err(|error|error.to_string())?;
        if owner.as_deref() != Some(parent_run.as_str()) {
            return Err(
                "resumed MergeDecision parent is not the authorized Coordinator result".into(),
            );
        }
        let stored:Option<(String,String,String,Option<String>)>=tx.query_row(
            "SELECT state,authorization_key,coordinator_evidence_id,resumed_result_evidence_id FROM merge_claim_recovery_requests WHERE request_id=?1 AND project_id=?2 AND ticket_run_id=?3",
            params![recovery.request_id,binding.project_id.as_str(),ticket_run_id.as_str()],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
        ).optional().map_err(|error|error.to_string())?;
        let stored = stored.ok_or("one-use recovery authorization is no longer active")?;
        if !matches!(stored.0.as_str(), "consumed" | "accepted")
            || stored.1 != recovery.authorization_key.as_str()
            || stored.2 != recovery.coordinator_evidence_id
        {
            return Err("one-use recovery authorization is no longer active".into());
        }
        let run:(u64,String,String,String)=tx.query_row("SELECT revision,internal_phase,activity,external_status FROM ticket_runs WHERE project_id=?1 AND ticket_run_id=?2",params![binding.project_id.as_str(),ticket_run_id.as_str()],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?))).map_err(|error|error.to_string())?;
        if binding.ticket_revision.map(|value| value.0) != Some(run.0)
            || run.0 != recovery.subject.blocked_revision.saturating_add(1)
            || parse_enum::<crate::engine::reducer::Phase>(&run.1)?
                != crate::engine::reducer::Phase::Assessing
            || parse_enum::<crate::engine::reducer::Activity>(&run.2)?
                != crate::engine::reducer::Activity::Running
        {
            return Err("resumed MergeDecision result is stale".into());
        }
        if stored.0 == "accepted" {
            let accepted_assessment_json: Option<String> = tx.query_row(
                "SELECT payload_json FROM role_wake_inputs WHERE project_id=?1 AND role_session_id=?2 AND source_type='host_merge_assessment' AND source_revision=?3 ORDER BY created_at_unix DESC LIMIT 1",
                params![binding.project_id.as_str(), binding.role_session_id.as_str(), run.0],
                |row| row.get(0),
            ).optional().map_err(|error| error.to_string())?;
            let Some(payload) = accepted_assessment_json else {
                return Err("accepted recovery request has no trusted MergeAssessment wake".into());
            };
            let value: serde_json::Value = crate::protocol::parse_unique(payload.as_bytes())?;
            if value["kind"].as_str() != Some("trusted_merge_assessment")
                || value["assessment"]["source_evidence_id"].as_str() != stored.3.as_deref()
            {
                return Err(
                    "accepted recovery request is not bound to its trusted MergeAssessment".into(),
                );
            }
        }
        let current = crate::engine::reducer::TicketRun {
            project_id: binding.project_id.clone(),
            ticket_run_id: ticket_run_id.clone(),
            revision: crate::domain::ids::Revision(run.0),
            phase: parse_enum(&run.1)?,
            activity: parse_enum(&run.2)?,
            external_status: super::parse_ticket_status(&run.3)?,
            required_review_revision: None,
        };
        let decision = crate::engine::reducer::reduce(
            &current,
            current.revision,
            crate::engine::reducer::Input::HumanMergeDecisionResumeFailed,
        )?;
        let evidence = serde_json::json!({"kind":"human_merge_claim_recovery_reblocked","request_id":recovery.request_id,"source_evidence_id":result.receipt.evidence_id(),"authorization_key":recovery.authorization_key,"reason":reason,"source_revision":current.revision.0});
        let input_id = format!("merge-claim-recovery-reblocked:{}", recovery.request_id);
        tx.execute("UPDATE ticket_runs SET internal_phase=?3,activity=?4,external_status=?5,revision=?6 WHERE project_id=?1 AND ticket_run_id=?2 AND revision=?7",params![binding.project_id.as_str(),ticket_run_id.as_str(),super::enum_string(&decision.ticket_run.phase)?,super::enum_string(&decision.ticket_run.activity)?,super::enum_string(&decision.ticket_run.external_status)?,decision.ticket_run.revision.0,current.revision.0]).map_err(|error|error.to_string())?;
        if tx.changes() != 1 {
            return Err("TicketRun changed while reblocking failed recovery".into());
        }
        tx.execute("INSERT INTO transitions(project_id,entity_type,entity_id,old_revision,new_revision,input_id,decision_reason,evidence_json,created_at_unix) VALUES (?1,'ticket_run',?2,?3,?4,?5,'resumed MergeDecision recovery failed closed',?6,?7)",params![binding.project_id.as_str(),ticket_run_id.as_str(),current.revision.0,decision.ticket_run.revision.0,input_id,crate::store::canonical_json(&evidence)?,now_unix]).map_err(|error|error.to_string())?;
        let wake = serde_json::json!({"kind":"human_merge_claim_recovery_reblocked","ticket_run_id":ticket_run_id.as_str(),"request_id":recovery.request_id,"reason":reason,"revision":decision.ticket_run.revision.0});
        tx.execute("INSERT INTO role_wake_inputs(project_id,role_session_id,source_type,source_id,source_revision,priority,payload_json,lifecycle,created_at_unix) VALUES (?1,?2,'merge_claim_recovery_reblocked',?3,?4,100,?5,'pending',?6)",params![binding.project_id.as_str(),format!("project:{}:supervisor",binding.project_id.as_str()),recovery.request_id,decision.ticket_run.revision.0,crate::store::canonical_json(&wake)?,now_unix]).map_err(|error|error.to_string())?;
        tx.execute("UPDATE merge_claim_recovery_requests SET state='reblocked',resumed_result_evidence_id=?2,rejection_reason=?3,updated_at_unix=?4 WHERE request_id=?1 AND state IN ('consumed','accepted')",params![recovery.request_id,result.receipt.evidence_id(),reason,now_unix]).map_err(|error|error.to_string())?;
        if tx.changes() != 1 {
            return Err("recovery authorization was already completed".into());
        }
        tx.execute("INSERT INTO agent_result_reducer_ack(evidence_id,reducer_revision,disposition,acknowledged_at_unix) VALUES (?1,?2,'rejected_by_host',?3) ON CONFLICT(evidence_id) DO NOTHING",params![result.receipt.evidence_id(),current.revision.0,now_unix]).map_err(|error|error.to_string())?;
        tx.commit().map_err(|error| error.to_string())
    }

    pub fn fail_merge_claim_recovery_attempt(
        &mut self,
        owner_generation: u64,
        request_id: &str,
        result: &crate::store::agent_results::IngestedAgentResult,
        reason: &str,
        now_unix: i64,
    ) -> Result<(), String> {
        let binding = &result.validated.binding;
        let ticket_run_id = binding
            .ticket_run_id
            .as_ref()
            .ok_or("recovery failure result has no TicketRun")?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        super::validate_active_generation(&tx, owner_generation)?;
        let recovery = authorized_recovery_for_coordinator_run(
            &tx,
            &binding.project_id,
            ticket_run_id,
            &binding.agent_run_id,
            binding
                .ticket_revision
                .ok_or("recovery Coordinator result has no TicketRun revision")?
                .0,
        )?
        .ok_or("result is not bound to the authorized recovery wake")?;
        if recovery.request_id != request_id
            || recovery.subject.configuration_digest != binding.config_digest
        {
            return Err("recovery failure result does not match its authorization".into());
        }
        let run: (u64,String,String,String) = tx.query_row(
            "SELECT revision,internal_phase,activity,external_status FROM ticket_runs WHERE project_id=?1 AND ticket_run_id=?2",
            params![binding.project_id.as_str(),ticket_run_id.as_str()],
            |row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
        ).map_err(|error|error.to_string())?;
        if binding.ticket_revision.map(|revision| revision.0) != Some(run.0)
            || parse_enum::<crate::engine::reducer::Phase>(&run.1)?
                != crate::engine::reducer::Phase::Assessing
            || parse_enum::<crate::engine::reducer::Activity>(&run.2)?
                != crate::engine::reducer::Activity::Running
        {
            return Err("recovery failure result is stale".into());
        }
        let current = crate::engine::reducer::TicketRun {
            project_id: binding.project_id.clone(),
            ticket_run_id: ticket_run_id.clone(),
            revision: crate::domain::ids::Revision(run.0),
            phase: parse_enum(&run.1)?,
            activity: parse_enum(&run.2)?,
            external_status: super::parse_ticket_status(&run.3)?,
            required_review_revision: None,
        };
        let decision = crate::engine::reducer::reduce(
            &current,
            current.revision,
            crate::engine::reducer::Input::HumanMergeDecisionResumeFailed,
        )?;
        let evidence = serde_json::json!({"kind":"human_merge_claim_recovery_reblocked","request_id":request_id,"source_evidence_id":result.receipt.evidence_id(),"authorization_key":recovery.authorization_key,"reason":reason,"source_revision":current.revision.0});
        let evidence_json = crate::store::canonical_json(&evidence)?;
        let message_id = format!("merge-claim-recovery-reblocked:{request_id}");
        tx.execute("UPDATE ticket_runs SET internal_phase=?3,activity=?4,external_status=?5,revision=?6 WHERE project_id=?1 AND ticket_run_id=?2 AND revision=?7",params![binding.project_id.as_str(),ticket_run_id.as_str(),super::enum_string(&decision.ticket_run.phase)?,super::enum_string(&decision.ticket_run.activity)?,super::enum_string(&decision.ticket_run.external_status)?,decision.ticket_run.revision.0,current.revision.0]).map_err(|error|error.to_string())?;
        if tx.changes() != 1 {
            return Err("TicketRun changed while recording failed recovery".into());
        }
        tx.execute("INSERT INTO transitions(project_id,entity_type,entity_id,old_revision,new_revision,input_id,decision_reason,evidence_json,created_at_unix) VALUES (?1,'ticket_run',?2,?3,?4,?5,'human MergeDecision recovery failed closed',?6,?7)",params![binding.project_id.as_str(),ticket_run_id.as_str(),current.revision.0,decision.ticket_run.revision.0,message_id,evidence_json,now_unix]).map_err(|error|error.to_string())?;
        let wake = serde_json::json!({"kind":"human_merge_claim_recovery_reblocked","ticket_run_id":ticket_run_id.as_str(),"request_id":request_id,"reason":reason,"revision":decision.ticket_run.revision.0,"instruction":"The one human-authorized MergeDecision recovery attempt failed. Do not retry automatically; inspect and direct a new plan or human action."});
        tx.execute("INSERT INTO role_wake_inputs(project_id,role_session_id,source_type,source_id,source_revision,priority,payload_json,lifecycle,created_at_unix) VALUES (?1,?2,'merge_claim_recovery_reblocked',?3,?4,100,?5,'pending',?6)",params![binding.project_id.as_str(),format!("project:{}:supervisor",binding.project_id.as_str()),request_id,decision.ticket_run.revision.0,crate::store::canonical_json(&wake)?,now_unix]).map_err(|error|error.to_string())?;
        tx.execute("UPDATE merge_claim_recovery_requests SET state='reblocked',resumed_result_evidence_id=?2,rejection_reason=?3,updated_at_unix=?4 WHERE request_id=?1 AND state IN ('authorized','consumed')",params![request_id,result.receipt.evidence_id(),reason,now_unix]).map_err(|error|error.to_string())?;
        if tx.changes() != 1 {
            return Err("recovery authorization is no longer active".into());
        }
        tx.execute("INSERT INTO agent_result_reducer_ack(evidence_id,reducer_revision,disposition,acknowledged_at_unix) VALUES (?1,?2,'rejected_by_host',?3) ON CONFLICT(evidence_id) DO NOTHING",params![result.receipt.evidence_id(),current.revision.0,now_unix]).map_err(|error|error.to_string())?;
        tx.commit().map_err(|error| error.to_string())
    }

    /// Read the current public recovery subject. This does not change state.
    pub fn merge_claim_recovery_subject(
        &self,
        project_id: &ProjectId,
        ticket_run_id: &TicketRunId,
    ) -> Result<MergeClaimRecoverySubject, String> {
        let subject = subject_on_connection(&self.connection, project_id, ticket_run_id)?;
        self.merge_claim_recovery_publication_snapshot(&subject)?;
        Ok(subject)
    }

    /// Queue human intent only. No owner lease or workflow transition is taken here.
    pub fn enqueue_merge_claim_recovery(
        &mut self,
        request_id: &str,
        subject_digest: &Digest,
        project_id: &ProjectId,
        ticket_run_id: &TicketRunId,
        now_unix: i64,
    ) -> Result<MergeClaimRecoveryReceipt, String> {
        if request_id.is_empty() || request_id.len() > 128 || request_id.contains('\0') {
            return Err("recovery request ID is invalid".into());
        }
        let prior: Option<(String,String,u64,String,String)> = self.connection.query_row(
            "SELECT subject_digest,state,CAST(json_extract(subject_json,'$.blocked_revision') AS INTEGER),project_id,ticket_run_id FROM merge_claim_recovery_requests WHERE request_id=?1",
            [request_id], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)),
        ).optional().map_err(|error| error.to_string())?;
        if let Some((digest, state, revision, prior_project, prior_run)) = prior {
            if digest != subject_digest.as_str()
                || prior_project != project_id.as_str()
                || prior_run != ticket_run_id.as_str()
            {
                return Err("recovery request ID was already used with different contents".into());
            }
            let receipt = MergeClaimRecoveryReceipt {
                request_id: request_id.into(),
                subject_digest: Digest::parse(digest)?,
                project_id: project_id.clone(),
                ticket_run_id: ticket_run_id.clone(),
                blocked_revision: revision,
                state,
                replayed: true,
            };
            return Ok(receipt);
        }
        let shown = self.merge_claim_recovery_subject(project_id, ticket_run_id)?;
        if shown.digest()? != *subject_digest {
            return Err("recovery subject changed; refresh the blocker view".into());
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        // Recheck request identity after the write lock to close a concurrent duplicate race.
        let prior: Option<(String,String,u64,String,String)> = tx.query_row(
            "SELECT subject_digest,state,CAST(json_extract(subject_json,'$.blocked_revision') AS INTEGER),project_id,ticket_run_id FROM merge_claim_recovery_requests WHERE request_id=?1",
            [request_id], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)),
        ).optional().map_err(|error| error.to_string())?;
        if let Some((digest, state, revision, prior_project, prior_run)) = prior {
            if digest != subject_digest.as_str()
                || prior_project != project_id.as_str()
                || prior_run != ticket_run_id.as_str()
            {
                return Err("recovery request ID was already used with different contents".into());
            }
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(MergeClaimRecoveryReceipt {
                request_id: request_id.into(),
                subject_digest: Digest::parse(digest)?,
                project_id: project_id.clone(),
                ticket_run_id: ticket_run_id.clone(),
                blocked_revision: revision,
                state,
                replayed: true,
            });
        }
        let current = subject_on_connection(&tx, project_id, ticket_run_id)?;
        let actual_digest = current.digest()?;
        if actual_digest != *subject_digest {
            return Err("recovery subject changed; refresh the blocker view".into());
        }
        let subject_json = serde_json::to_string(&current).map_err(|error| error.to_string())?;
        tx.execute(
            "INSERT INTO merge_claim_recovery_requests(request_id,project_id,ticket_run_id,subject_digest,subject_json,state,created_at_unix,updated_at_unix) VALUES (?1,?2,?3,?4,?5,'pending',?6,?6)",
            params![request_id,project_id.as_str(),ticket_run_id.as_str(),actual_digest.as_str(),subject_json,now_unix],
        ).map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(MergeClaimRecoveryReceipt {
            request_id: request_id.into(),
            subject_digest: actual_digest,
            project_id: project_id.clone(),
            ticket_run_id: ticket_run_id.clone(),
            blocked_revision: current.blocked_revision,
            state: "pending".into(),
            replayed: false,
        })
    }

    pub fn pending_merge_claim_recoveries(
        &self,
        limit: usize,
    ) -> Result<Vec<PendingMergeClaimRecovery>, String> {
        if !(1..=32).contains(&limit) {
            return Err("MergeDecision recovery request limit must be between 1 and 32".into());
        }
        let mut statement = self.connection.prepare(
            "SELECT request_id,subject_json,subject_digest FROM merge_claim_recovery_requests WHERE state='pending' ORDER BY updated_at_unix,request_id LIMIT ?1",
        ).map_err(|error| error.to_string())?;
        let rows = statement
            .query_map([limit as u64], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(|error| error.to_string())?;
        rows.map(|row| {
            let (request_id, subject_json, subject_digest) =
                row.map_err(|error| error.to_string())?;
            let subject: MergeClaimRecoverySubject = serde_json::from_str(&subject_json)
                .map_err(|error| format!("stored recovery subject is invalid: {error}"))?;
            let subject_digest = Digest::parse(subject_digest)?;
            if subject.digest()? != subject_digest {
                return Err("stored recovery subject digest does not match its content".into());
            }
            Ok(PendingMergeClaimRecovery {
                request_id,
                subject,
                subject_digest,
            })
        })
        .collect()
    }

    /// Atomically consume one verified human request, unblock the TicketRun, and
    /// wake its canonical Coordinator session. External observations happen before this call.
    pub fn authorize_merge_claim_recovery(
        &mut self,
        owner_generation: u64,
        request: &PendingMergeClaimRecovery,
        observation: &MergeClaimRecoveryObservation,
        now_unix: i64,
    ) -> Result<bool, String> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        super::validate_active_generation(&tx, owner_generation)?;
        let run: Option<(u64,String,String,String,String,String)> = tx.query_row(
            "SELECT revision,internal_phase,activity,config_digest,namespace,ticket_id FROM ticket_runs WHERE project_id=?1 AND ticket_run_id=?2",
            params![request.subject.project_id.as_str(),request.subject.ticket_run_id.as_str()],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?)),
        ).optional().map_err(|error| error.to_string())?;
        let still_same_block = run.is_some_and(
            |(revision, phase, activity, config_digest, namespace, ticket_id)| {
                revision == request.subject.blocked_revision
                    && phase == "assessing"
                    && activity == "blocked"
                    && config_digest == request.subject.configuration_digest.as_str()
                    && namespace == request.subject.ticket_namespace
                    && ticket_id == request.subject.ticket_id
            },
        );
        if !still_same_block {
            tx.execute("UPDATE merge_claim_recovery_requests SET state='rejected',rejection_reason='TicketRun or Project configuration changed after the human reviewed the blocker',updated_at_unix=?2 WHERE request_id=?1 AND state='pending'", params![request.request_id,now_unix]).map_err(|error| error.to_string())?;
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(false);
        }
        let current = subject_on_connection(
            &tx,
            &request.subject.project_id,
            &request.subject.ticket_run_id,
        )?;
        if current.digest()? != request.subject_digest {
            tx.execute("UPDATE merge_claim_recovery_requests SET state='rejected',rejection_reason='external ticket or fresh Forge subject changed',updated_at_unix=?2 WHERE request_id=?1 AND state='pending'", params![request.request_id,now_unix]).map_err(|error| error.to_string())?;
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(false);
        }
        let MergeClaimRecoveryObservation::Current {
            ticket_namespace,
            ticket_id,
            ticket_status,
            publication_set_digest,
            pull_request_reference,
        } = observation
        else {
            if let MergeClaimRecoveryObservation::TemporarilyUnavailable = observation {
                tx.execute(
                    "UPDATE merge_claim_recovery_requests SET updated_at_unix=MAX(?2,(SELECT COALESCE(MAX(updated_at_unix),0)+1 FROM merge_claim_recovery_requests)) WHERE request_id=?1 AND state='pending'",
                    params![request.request_id, now_unix],
                ).map_err(|error| error.to_string())?;
                tx.commit().map_err(|error| error.to_string())?;
                return Ok(false);
            }
            let reason = match observation {
                MergeClaimRecoveryObservation::Stale(reason) => reason.as_str(),
                _ => unreachable!("pattern matched Current above"),
            };
            tx.execute("UPDATE merge_claim_recovery_requests SET state='rejected',rejection_reason=?2,updated_at_unix=?3 WHERE request_id=?1 AND state='pending'", params![request.request_id,reason,now_unix]).map_err(|error| error.to_string())?;
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(false);
        };
        if ticket_namespace != &current.ticket_namespace
            || ticket_id != &current.ticket_id
            || *ticket_status != crate::adapters::tickets::NormalizedTicketStatus::InProgress
            || publication_set_digest != &current.publication_set_digest
            || pull_request_reference != &current.expected_pull_request_reference
        {
            tx.execute("UPDATE merge_claim_recovery_requests SET state='rejected',rejection_reason='fresh ticket or Forge observation no longer matches the recovery subject',updated_at_unix=?2 WHERE request_id=?1 AND state='pending'", params![request.request_id,now_unix]).map_err(|error| error.to_string())?;
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(false);
        }
        let authorization_key = authorization_key(&current)?;
        let prior_lineage: Option<String> = tx.query_row(
            "SELECT request_id FROM merge_claim_recovery_requests WHERE project_id=?1 AND ticket_run_id=?2 AND authorization_key=?3 LIMIT 1",
            params![current.project_id.as_str(),current.ticket_run_id.as_str(),authorization_key.as_str()],
            |row| row.get(0),
        ).optional().map_err(|error| error.to_string())?;
        if prior_lineage.is_some() {
            tx.execute("UPDATE merge_claim_recovery_requests SET state='rejected',rejection_reason='one recovery attempt already exists for this unchanged publication lineage',updated_at_unix=?2 WHERE request_id=?1 AND state='pending'", params![request.request_id,now_unix]).map_err(|error| error.to_string())?;
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(false);
        }
        let run: (u64,String,String,String,String,Option<u64>) = tx.query_row(
            "SELECT revision,internal_phase,activity,external_status,config_digest,required_review_revision FROM ticket_runs WHERE project_id=?1 AND ticket_run_id=?2",
            params![current.project_id.as_str(),current.ticket_run_id.as_str()],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?)),
        ).map_err(|error| error.to_string())?;
        let ticket_run = crate::engine::reducer::TicketRun {
            project_id: current.project_id.clone(),
            ticket_run_id: current.ticket_run_id.clone(),
            revision: crate::domain::ids::Revision(run.0),
            phase: parse_enum(&run.1)?,
            activity: parse_enum(&run.2)?,
            external_status: super::parse_ticket_status(&run.3)?,
            required_review_revision: run.5.map(crate::domain::ids::Revision),
        };
        if ticket_run.revision.0 != current.blocked_revision
            || run.4 != current.configuration_digest.as_str()
            || ticket_run.phase != crate::engine::reducer::Phase::Assessing
            || ticket_run.activity != crate::engine::reducer::Activity::Blocked
        {
            tx.execute("UPDATE merge_claim_recovery_requests SET state='rejected',rejection_reason='TicketRun is no longer at the reviewed blocked revision',updated_at_unix=?2 WHERE request_id=?1 AND state='pending'", params![request.request_id,now_unix]).map_err(|error| error.to_string())?;
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(false);
        }
        let decision = crate::engine::reducer::reduce(
            &ticket_run,
            ticket_run.revision,
            crate::engine::reducer::Input::HumanMergeDecisionResume,
        )?;
        let evidence = serde_json::json!({
            "kind":"human_merge_claim_recovery",
            "request_id":request.request_id,
            "subject_digest":request.subject_digest,
            "authorization_key":authorization_key,
            "source_revision":ticket_run.revision.0,
            "ticket_run_id":current.ticket_run_id,
            "project_id":current.project_id,
            "publication_set_digest":current.publication_set_digest,
            "accepted_plan_digest":current.accepted_plan_digest,
        });
        let evidence_json = crate::store::canonical_json(&evidence)?;
        let input_id = format!("merge-claim-recovery:{}", request.request_id);
        tx.execute(
            "UPDATE ticket_runs SET internal_phase=?3,activity=?4,external_status=?5,required_review_revision=NULL,revision=?6 WHERE project_id=?1 AND ticket_run_id=?2 AND revision=?7",
            params![current.project_id.as_str(),current.ticket_run_id.as_str(),super::enum_string(&decision.ticket_run.phase)?,super::enum_string(&decision.ticket_run.activity)?,super::enum_string(&decision.ticket_run.external_status)?,decision.ticket_run.revision.0,ticket_run.revision.0],
        ).map_err(|error| error.to_string())?;
        if tx.changes() != 1 {
            return Err("TicketRun changed while authorizing MergeDecision recovery".into());
        }
        tx.execute(
            "INSERT INTO transitions(project_id,entity_type,entity_id,old_revision,new_revision,input_id,decision_reason,evidence_json,created_at_unix) VALUES (?1,'ticket_run',?2,?3,?4,?5,'human authorized one MergeDecision recovery',?6,?7)",
            params![current.project_id.as_str(),current.ticket_run_id.as_str(),ticket_run.revision.0,decision.ticket_run.revision.0,input_id,evidence_json,now_unix],
        ).map_err(|error| error.to_string())?;
        let coordinator = format!("ticket_run:{}:coordinator", current.ticket_run_id.as_str());
        let wake = serde_json::json!({
            "kind":"human_merge_claim_recovery",
            "ticket_run_id":current.ticket_run_id,
            "request_id":request.request_id,
            "subject_digest":request.subject_digest,
            "authorization_key":authorization_key,
            "source_revision":decision.ticket_run.revision.0,
            "instruction":"Resume only the exhausted MergeDecision claim: request exactly one MergeDecision child for the original accepted merge node. Do not start Workers, re-plan, publish, or merge."
        });
        tx.execute(
            "INSERT INTO role_wake_inputs(project_id,role_session_id,source_type,source_id,source_revision,priority,payload_json,lifecycle,created_at_unix) VALUES (?1,?2,'merge_claim_recovery_authorized',?3,?4,120,?5,'pending',?6)",
            params![current.project_id.as_str(),coordinator,request.request_id,decision.ticket_run.revision.0,crate::store::canonical_json(&wake)?,now_unix],
        ).map_err(|error| error.to_string())?;
        tx.execute(
            "UPDATE merge_claim_recovery_requests SET state='authorized',authorization_key=?2,updated_at_unix=?3 WHERE request_id=?1 AND state='pending'",
            params![request.request_id,authorization_key.as_str(),now_unix],
        ).map_err(|error| error.to_string())?;
        if tx.changes() != 1 {
            return Err("human recovery request is no longer pending".into());
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(true)
    }
}

fn subject_on_connection(
    connection: &Connection,
    project_id: &ProjectId,
    ticket_run_id: &TicketRunId,
) -> Result<MergeClaimRecoverySubject, String> {
    let run: Option<(String,String,u64,u64,String,String,String)> = connection.query_row(
        "SELECT internal_phase,activity,revision,config_revision,config_digest,namespace,ticket_id FROM ticket_runs WHERE ticket_run_id=?1 AND project_id=?2",
        params![ticket_run_id.as_str(),project_id.as_str()],
        |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?)),
    ).optional().map_err(|error| error.to_string())?;
    let Some((
        phase,
        activity,
        blocked_revision,
        configuration_revision,
        configuration_digest,
        ticket_namespace,
        ticket_id,
    )) = run
    else {
        return Err("TicketRun recovery subject was not found in this Project".into());
    };
    if phase != "assessing" || activity != "blocked" {
        return Err("TicketRun has no exhausted MergeDecision claim to resume".into());
    }
    let (source_evidence_id,payload_json):(String,String)=connection.query_row(
        "SELECT source_id,payload_json FROM role_wake_inputs WHERE project_id=?1 AND source_type='merge_assessment_correction_exhausted' AND source_revision=?2 AND json_extract(payload_json,'$.ticket_run_id')=?3 ORDER BY wake_input_id DESC LIMIT 1",
        params![project_id.as_str(),blocked_revision,ticket_run_id.as_str()],|row|Ok((row.get(0)?,row.get(1)?)),
    ).map_err(|error|error.to_string())?;
    let payload: serde_json::Value = crate::protocol::parse_unique(payload_json.as_bytes())?;
    let transition: Option<(u64,String)> = connection.query_row(
        "SELECT old_revision,evidence_json FROM transitions WHERE entity_type='ticket_run' AND entity_id=?1 AND project_id=?2 AND new_revision=?3",
        params![ticket_run_id.as_str(),project_id.as_str(),blocked_revision],|row|Ok((row.get(0)?,row.get(1)?)),
    ).optional().map_err(|error|error.to_string())?;
    let (convergence_revision, transition_json) =
        transition.ok_or("blocked TicketRun exhaustion transition is missing")?;
    if convergence_revision.checked_add(1) != Some(blocked_revision) {
        return Err(
            "exhaustion transition is not the exact predecessor of the blocked revision".into(),
        );
    }
    let transition: serde_json::Value = crate::protocol::parse_unique(transition_json.as_bytes())?;
    if transition["source_evidence_id"].as_str() != Some(source_evidence_id.as_str())
        || transition["publication_set_digest"] != payload["publication_set_digest"]
        || transition["expected_pull_request_reference"]
            != payload["expected_pull_request_reference"]
    {
        return Err("exhaustion wake does not match the exact blocked transition".into());
    }
    type ExhaustedEvidenceRow = (
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
    );
    let evidence: Option<ExhaustedEvidenceRow> = connection.query_row(
        "SELECT e.result_digest,e.agent_run_id,e.role,e.ticket_run_id,a.authority_json,a.authority_digest,a.instruction_digest,a.role_session_id FROM agent_result_evidence e JOIN agent_launch_authority a ON a.agent_run_id=e.agent_run_id WHERE e.evidence_id=?1 AND e.project_id=?2 AND e.outcome='completed'",
        params![source_evidence_id,project_id.as_str()],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?)),
    ).optional().map_err(|error|error.to_string())?;
    let (
        result_digest,
        agent_run_id,
        role,
        evidence_ticket_run,
        authority_json,
        authority_digest,
        instruction_digest,
        role_session,
    ) = evidence
        .ok_or("exhausted MergeDecision evidence or immutable launch authority is missing")?;
    let authority: crate::launch::AgentLaunchAuthority = serde_json::from_str(&authority_json)
        .map_err(|error| format!("stored MergeDecision authority is invalid: {error}"))?;
    let authority_digest = Digest::parse(authority_digest)?;
    authority.validate()?;
    if role != "merge_decision"
        || evidence_ticket_run != ticket_run_id.as_str()
        || authority.agent_run_id.as_str() != agent_run_id
        || authority.role != crate::domain::types::Role::MergeDecision
        || authority.role_session_id != role_session
        || authority.role_session_id != format!("ticket_run:{ticket_run_id}:merge_decision")
        || authority.project_id != *project_id
        || authority.ticket_run_id.as_ref() != Some(ticket_run_id)
        || authority.ticket_revision.map(|revision| revision.0) != Some(convergence_revision)
        || authority.parent_role != Some(crate::domain::types::Role::Coordinator)
        || authority.config_revision.0 != configuration_revision
        || authority.config_digest.as_str() != configuration_digest
        || authority.digest()? != authority_digest
    {
        return Err(
            "exhausted result does not match its immutable MergeDecision launch authority".into(),
        );
    }
    let parent_id = authority
        .parent_run_id
        .as_ref()
        .ok_or("exhausted MergeDecision has no immutable Coordinator parent")?;
    let parent_row:Option<(String,String)>=connection.query_row(
        "SELECT authority_json,authority_digest FROM agent_launch_authority WHERE agent_run_id=?1 AND project_id=?2",
        params![parent_id.as_str(),project_id.as_str()],|row|Ok((row.get(0)?,row.get(1)?)),
    ).optional().map_err(|error|error.to_string())?;
    let (parent_json, parent_digest) =
        parent_row.ok_or("exhausted MergeDecision Coordinator parent authority is missing")?;
    let parent: crate::launch::AgentLaunchAuthority = serde_json::from_str(&parent_json)
        .map_err(|error| format!("stored Coordinator parent authority is invalid: {error}"))?;
    parent.validate()?;
    let parent_completed:bool=connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM agent_result_evidence WHERE agent_run_id=?1 AND project_id=?2 AND ticket_run_id=?3 AND role='coordinator' AND outcome='completed')",
        params![parent_id.as_str(),project_id.as_str(),ticket_run_id.as_str()],|row|row.get(0),
    ).map_err(|error|error.to_string())?;
    if parent.digest()?.as_str() != parent_digest
        || parent.agent_run_id != *parent_id
        || parent.role != crate::domain::types::Role::Coordinator
        || parent.role_session_id != format!("ticket_run:{ticket_run_id}:coordinator")
        || parent.ticket_run_id.as_ref() != Some(ticket_run_id)
        || parent.config_digest.as_str() != configuration_digest
        || !parent_completed
    {
        return Err(
            "exhausted MergeDecision does not have a completed canonical Coordinator parent".into(),
        );
    }
    let plan=connection.query_row("SELECT plan_digest,configuration_digest FROM accepted_work_plans WHERE project_id=?1 AND ticket_run_id=?2 ORDER BY accepted_revision DESC LIMIT 1",params![project_id.as_str(),ticket_run_id.as_str()],|row|Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?))).optional().map_err(|error|error.to_string())?.ok_or("blocked TicketRun has no accepted implementation plan")?;
    let configuration_digest = Digest::parse(configuration_digest)?;
    if plan.1 != configuration_digest.as_str() {
        return Err("accepted plan belongs to a different Project configuration".into());
    }
    Ok(MergeClaimRecoverySubject {
        project_id: project_id.clone(),
        ticket_run_id: ticket_run_id.clone(),
        ticket_namespace,
        ticket_id,
        blocked_revision,
        convergence_revision,
        configuration_revision,
        configuration_digest,
        accepted_plan_digest: Digest::parse(plan.0)?,
        source_evidence_id,
        source_result_digest: Digest::parse(result_digest)?,
        authority_digest,
        instruction_digest: Digest::parse(instruction_digest)?,
        publication_set_digest: Digest::parse(
            payload["publication_set_digest"]
                .as_str()
                .ok_or("exhaustion blocker lacks publication digest")?,
        )?,
        expected_pull_request_reference: payload["expected_pull_request_reference"]
            .as_str()
            .ok_or("exhaustion blocker lacks expected pull request")?
            .to_owned(),
        reason: payload["reason"]
            .as_str()
            .ok_or("exhaustion blocker lacks reason")?
            .to_owned(),
    })
}

fn authorization_key(subject: &MergeClaimRecoverySubject) -> Result<Digest, String> {
    let key_material = serde_json::json!({
        "project_id": subject.project_id,
        "ticket_run_id": subject.ticket_run_id,
        "configuration_revision": subject.configuration_revision,
        "configuration_digest": subject.configuration_digest,
        "accepted_plan_digest": subject.accepted_plan_digest,
        "publication_set_digest": subject.publication_set_digest,
        "convergence_revision": subject.convergence_revision,
    });
    Digest::parse(format!(
        "{:x}",
        sha2::Sha256::digest(crate::store::canonical_json(&key_material)?.as_bytes())
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_recovery_schema_is_rejected_before_wal_without_database_changes() {
        for mutation in [
            "DROP INDEX merge_claim_recovery_one_per_lineage",
            "DELETE FROM schema_migrations WHERE version=16",
            "DROP TABLE merge_claim_recovery_requests",
        ] {
            let temp = tempfile::tempdir().unwrap();
            drop(ConfigStore::open_test(temp.path()).unwrap());
            let path = temp.path().join("state.sqlite3");
            let connection = Connection::open(&path).unwrap();
            connection
                .execute_batch("PRAGMA journal_mode=DELETE;")
                .unwrap();
            connection.execute_batch(mutation).unwrap();
            drop(connection);
            let before = std::fs::read(&path).unwrap();

            let error = ConfigStore::open_test(temp.path()).err().unwrap();
            assert!(
                error.contains("merge_claim_recovery_requests")
                    || error.contains("schema 16 migration record"),
                "{mutation}: {error}"
            );
            assert_eq!(std::fs::read(&path).unwrap(), before, "{mutation}");
        }
    }
}
