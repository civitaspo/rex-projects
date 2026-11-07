//! Durable controller-generation transfers for already-running Agent turns.

use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::domain::ids::{AgentRunId, Digest, OperationId, ProjectId, TicketRunId};
use crate::launch::{AgentLaunchAuthority, ObservedProviderStart, ObservedWrapperIdentity};

use super::{ConfigStore, validate_active_generation};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoverableAgentRun {
    pub agent_run_id: AgentRunId,
    pub current_generation: u64,
    pub previous_generation: u64,
    pub authority: AgentLaunchAuthority,
    pub authority_digest: Digest,
    pub agent_state: String,
    pub started_at_unix: Option<i64>,
    pub launch_state: String,
    pub process_identity_json: Option<String>,
    pub wrapper_identity_json: Option<String>,
    pub provider_tree_json: Option<String>,
    pub pool: String,
    pub slot_index: u32,
    pub reservation_epoch: u64,
    pub slot_disposition: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentAdoptionEvidence {
    pub schema_version: u32,
    pub agent_run_id: AgentRunId,
    pub controller_generation: u64,
    pub previous_controller_generation: u64,
    pub authority_digest: Digest,
    pub descriptor_digest: Digest,
    pub rex_process_observation_digest: Digest,
    pub process_tree_digest: Digest,
    pub provider_start_tree_digest: Digest,
    pub process_tree: Vec<AdoptedProcessIdentity>,
    pub wrapper_pid: u32,
    pub wrapper_start_identity: String,
    pub provider_pid: u32,
    pub provider_start_identity: String,
    pub observed_at_unix: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdoptedProcessIdentity {
    pub pid: u32,
    pub parent_pid: u32,
    pub process_group_id: u32,
    pub start_identity: String,
    pub identity_quality: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StopOwnedRunsEffectPayload {
    pub schema_version: u32,
    pub project_id: ProjectId,
    pub ticket_run_id: TicketRunId,
    pub expected_revision: u64,
}

pub type StopOwnedRunsRequest = StopOwnedRunsEffectPayload;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StopProcessIdentity {
    pub pid: u32,
    pub start_identity: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StopTargetLifecycle {
    NeedsReconciliation,
    IdentityUnknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StopOwnedRunTarget {
    pub agent_run_id: AgentRunId,
    pub attempt: u32,
    pub run_epoch: u64,
    pub reservation_epoch: u64,
    pub authority_digest: Digest,
    pub rex_server_identity: String,
    pub rex_session_id: String,
    pub rex_window_id: String,
    pub rex_block_id: String,
    pub wrapper: Option<StopProcessIdentity>,
    pub provider: Option<StopProcessIdentity>,
    pub lifecycle: StopTargetLifecycle,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StopOwnedRunsIntent {
    pub schema_version: u32,
    pub operation_id: OperationId,
    pub request: StopOwnedRunsRequest,
    pub targets: Vec<StopOwnedRunTarget>,
    pub created_at_unix: i64,
}

impl StopOwnedRunsEffectPayload {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1 || self.expected_revision == 0 {
            return Err("StopOwnedRuns request version is unsupported".into());
        }
        Ok(())
    }

    pub fn from_effect_request(request: &crate::effects::EffectRequest) -> Result<Self, String> {
        if request.intent.kind
            != crate::engine::reducer::effect_name(
                &crate::engine::reducer::EffectKind::StopOwnedRuns,
            )
            || request.intent.subject_type != "ticket_run"
        {
            return Err("effect request is not a ticket-scoped StopOwnedRuns decision".into());
        }
        let value: serde_json::Value =
            crate::protocol::parse_unique(request.intent.request_json.as_bytes())
                .map_err(|error| format!("StopOwnedRuns effect payload is invalid: {error}"))?;
        if value["schema_version"].as_u64() != Some(1)
            || value["project_id"].as_str() != Some(request.intent.project_id.as_str())
            || value["ticket_run_id"].as_str() != Some(request.intent.subject_id.as_str())
        {
            return Err(
                "StopOwnedRuns effect payload does not match its durable effect identity".into(),
            );
        }
        let ticket_run_id = TicketRunId::parse(request.intent.subject_id.clone())?;
        let payload = Self {
            schema_version: 1,
            project_id: request.intent.project_id.clone(),
            ticket_run_id,
            expected_revision: request
                .intent
                .expected_revision
                .ok_or_else(|| "StopOwnedRuns effect has no expected ticket revision".to_owned())?,
        };
        payload.validate()?;
        Ok(payload)
    }
}

impl StopOwnedRunsIntent {
    pub fn validate(&self) -> Result<(), String> {
        self.request.validate()?;
        if self.schema_version != 1 || self.targets.len() > 4096 {
            return Err("StopOwnedRuns intent is incomplete or exceeds its target bound".into());
        }
        let mut previous: Option<&AgentRunId> = None;
        for target in &self.targets {
            if previous.is_some_and(|value| value >= &target.agent_run_id)
                || target.attempt == 0
                || target.run_epoch == 0
                || target.reservation_epoch == 0
                || target.rex_server_identity.trim().is_empty()
                || target.rex_session_id.trim().is_empty()
                || target.rex_window_id.trim().is_empty()
                || target.rex_block_id.trim().is_empty()
                || target.wrapper.as_ref().is_some_and(|process| {
                    process.pid == 0
                        || process.start_identity.trim().is_empty()
                        || process.start_identity.chars().any(char::is_control)
                })
                || target.provider.as_ref().is_some_and(|process| {
                    process.pid == 0
                        || process.start_identity.trim().is_empty()
                        || process.start_identity.chars().any(char::is_control)
                })
                || (target.lifecycle == StopTargetLifecycle::NeedsReconciliation
                    && (target.wrapper.is_none() || target.provider.is_none()))
                || (target.lifecycle == StopTargetLifecycle::IdentityUnknown
                    && target.wrapper.is_some()
                    && target.provider.is_some())
            {
                return Err("StopOwnedRuns targets are invalid or unordered".into());
            }
            previous = Some(&target.agent_run_id);
        }
        Ok(())
    }
}

impl AgentAdoptionEvidence {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1
            || self.controller_generation == 0
            || self.previous_controller_generation == 0
            || self.controller_generation == self.previous_controller_generation
            || self.wrapper_pid == 0
            || self.provider_pid == 0
            || self.process_tree.is_empty()
            || self.process_tree.len() > 1024
            || self.wrapper_start_identity.trim().is_empty()
            || self.provider_start_identity.trim().is_empty()
            || self.wrapper_start_identity.chars().any(char::is_control)
            || self.provider_start_identity.chars().any(char::is_control)
        {
            return Err("Agent adoption evidence is incomplete".into());
        }
        let mut previous_pid = 0;
        for process in &self.process_tree {
            if process.pid == 0
                || process.pid <= previous_pid
                || process.start_identity.trim().is_empty()
                || process.identity_quality != "kernel_birth_token"
            {
                return Err("Agent adoption process tree lacks ordered kernel identities".into());
            }
            previous_pid = process.pid;
        }
        if !self.process_tree.iter().any(|process| {
            process.pid == self.provider_pid
                && process.start_identity == self.provider_start_identity
        }) {
            return Err("Agent adoption process tree omits its provider root".into());
        }
        if !self.process_tree.iter().any(|process| {
            process.pid == self.wrapper_pid && process.start_identity == self.wrapper_start_identity
        }) {
            return Err("Agent adoption process tree omits its Rex wrapper root".into());
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<Digest, String> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        Digest::parse(format!("{:x}", Sha256::digest(bytes)))
    }
}

pub(crate) fn migrate_v12_recovery_tables(tx: &Transaction<'_>) -> Result<(), String> {
    tx
        .execute_batch(
            "CREATE TABLE agent_run_adoptions (
                agent_run_id TEXT NOT NULL REFERENCES agent_runs(agent_run_id),
                controller_generation INTEGER NOT NULL CHECK(controller_generation > 0),
                previous_controller_generation INTEGER NOT NULL CHECK(previous_controller_generation > 0),
                authority_digest TEXT NOT NULL CHECK(length(authority_digest) = 64),
                descriptor_digest TEXT NOT NULL CHECK(length(descriptor_digest) = 64),
                evidence_digest TEXT NOT NULL CHECK(length(evidence_digest) = 64),
                evidence_json TEXT NOT NULL CHECK(length(evidence_json) <= 524288),
                created_at_unix INTEGER NOT NULL,
                PRIMARY KEY(agent_run_id, controller_generation)
            );
            CREATE TRIGGER agent_run_adoptions_immutable_update
            BEFORE UPDATE ON agent_run_adoptions
            BEGIN SELECT RAISE(ABORT, 'Agent adoption evidence is immutable'); END;
            CREATE TRIGGER agent_run_adoptions_immutable_delete
            BEFORE DELETE ON agent_run_adoptions
            BEGIN SELECT RAISE(ABORT, 'Agent adoption evidence is retained'); END;

            CREATE TABLE agent_run_recovery_observations (
                agent_run_id TEXT PRIMARY KEY REFERENCES agent_runs(agent_run_id),
                controller_generation INTEGER NOT NULL CHECK(controller_generation > 0),
                reservation_epoch INTEGER NOT NULL CHECK(reservation_epoch > 0),
                observation_order INTEGER NOT NULL CHECK(observation_order > 0),
                observed_at_unix INTEGER NOT NULL
            );
            CREATE INDEX agent_run_recovery_observations_fairness
                ON agent_run_recovery_observations(controller_generation, observation_order, agent_run_id);

            CREATE TABLE agent_stop_owned_runs_intents (
                operation_id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                ticket_run_id TEXT NOT NULL,
                intent_digest TEXT NOT NULL CHECK(length(intent_digest) = 64),
                intent_json TEXT NOT NULL CHECK(length(intent_json) <= 524288),
                created_at_unix INTEGER NOT NULL
            );
            CREATE TRIGGER agent_stop_owned_runs_intents_immutable_update
            BEFORE UPDATE ON agent_stop_owned_runs_intents
            BEGIN SELECT RAISE(ABORT, 'StopOwnedRuns intent is immutable'); END;
            CREATE TRIGGER agent_stop_owned_runs_intents_immutable_delete
            BEFORE DELETE ON agent_stop_owned_runs_intents
            BEGIN SELECT RAISE(ABORT, 'StopOwnedRuns intent is retained'); END;",
        )
        .map_err(|error| error.to_string())
}

impl ConfigStore {
    /// Freeze the exact runs affected by a durable parent Pause/Cancel effect. A caller must
    /// reobserve each target before signaling; the snapshot itself is never proof of liveness.
    pub fn prepare_stop_owned_runs_intent(
        &mut self,
        owner_generation: u64,
        operation_id: &OperationId,
        request: &StopOwnedRunsRequest,
        now_unix: i64,
    ) -> Result<StopOwnedRunsIntent, String> {
        request.validate()?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let ticket: Option<(String, u64, String, String)> = tx
            .query_row(
                "SELECT project_id,revision,internal_phase,activity FROM ticket_runs WHERE ticket_run_id=?1",
                [request.ticket_run_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let Some((project_id, revision, phase, activity)) = ticket else {
            return Err("StopOwnedRuns TicketRun does not exist".into());
        };
        if project_id != request.project_id.as_str()
            || revision != request.expected_revision
            || (phase != "canceled" && activity != "paused")
        {
            return Err(
                "StopOwnedRuns decision is stale or is not an explicit Pause/Cancel".into(),
            );
        }

        let existing: Option<String> = tx
            .query_row(
                "SELECT intent_json FROM agent_stop_owned_runs_intents WHERE operation_id=?1",
                [operation_id.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if let Some(json) = existing {
            let intent: StopOwnedRunsIntent = crate::protocol::parse_unique(json.as_bytes())
                .map_err(|error| format!("stored StopOwnedRuns intent is invalid: {error}"))?;
            intent.validate()?;
            if intent.operation_id != *operation_id || intent.request != *request {
                return Err("StopOwnedRuns operation was reused for a different request".into());
            }
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(intent);
        }

        let mut statement = tx
            .prepare(
                "SELECT r.agent_run_id,a.authority_json,a.authority_digest,
                        s.reservation_epoch,l.wrapper_process_identity_json,l.provider_process_tree_json
                 FROM agent_runs r
                 JOIN execution_slots s ON s.owner_kind='agent_run' AND s.owner_id=r.agent_run_id
                 JOIN agent_launch_authority a ON a.agent_run_id=r.agent_run_id
                 JOIN agent_launch_state l ON l.agent_run_id=r.agent_run_id
                 WHERE r.project_id=?1 AND r.ticket_run_id=?2 AND r.controller_generation=?3
                   AND r.state IN ('unknown','running','launch_pending')
                   AND s.disposition IN ('unknown','live','launch_pending')
                 ORDER BY r.agent_run_id",
            )
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(
                params![
                    request.project_id.as_str(),
                    request.ticket_run_id.as_str(),
                    owner_generation
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, u64>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, Option<String>>(5)?,
                    ))
                },
            )
            .map_err(|error| error.to_string())?;
        let mut targets = Vec::new();
        for row in rows {
            let (
                raw_id,
                authority_json,
                raw_digest,
                reservation_epoch,
                wrapper_json,
                provider_json,
            ) = row.map_err(|error| error.to_string())?;
            let agent_run_id = AgentRunId::parse(raw_id)?;
            let authority: AgentLaunchAuthority =
                crate::protocol::parse_unique(authority_json.as_bytes()).map_err(|error| {
                    format!("stored Agent launch authority is invalid: {error}")
                })?;
            authority.validate()?;
            let authority_digest = Digest::parse(raw_digest)?;
            if authority.agent_run_id != agent_run_id
                || authority.project_id != request.project_id
                || authority.ticket_run_id.as_ref() != Some(&request.ticket_run_id)
                || authority.digest()? != authority_digest
            {
                return Err(
                    "StopOwnedRuns scope does not match stored Agent launch authority".into(),
                );
            }
            let wrapper = wrapper_json
                .as_deref()
                .and_then(|json| {
                    crate::protocol::parse_unique::<ObservedWrapperIdentity>(json.as_bytes()).ok()
                })
                .filter(|identity| {
                    identity.rex_session_id == authority.rex_session_id
                        && identity.rex_block_id == authority.rex_block_id
                        && identity.runtime_binary_digest == authority.runtime_binary_digest
                })
                .map(|identity| StopProcessIdentity {
                    pid: identity.pid,
                    start_identity: identity.start_identity,
                });
            let provider = provider_json
                .as_deref()
                .and_then(|json| {
                    crate::protocol::parse_unique::<ObservedProviderStart>(json.as_bytes()).ok()
                })
                .filter(|identity| {
                    identity.agent_run_id == agent_run_id && identity.process_tree_confirmed
                })
                .map(|identity| StopProcessIdentity {
                    pid: identity.provider_pid,
                    start_identity: identity.provider_start_identity,
                });
            let lifecycle = if wrapper.is_some() && provider.is_some() {
                StopTargetLifecycle::NeedsReconciliation
            } else {
                StopTargetLifecycle::IdentityUnknown
            };
            targets.push(StopOwnedRunTarget {
                agent_run_id,
                attempt: authority.attempt,
                run_epoch: authority.run_epoch,
                reservation_epoch,
                authority_digest,
                rex_server_identity: authority.rex_server_identity,
                rex_session_id: authority.rex_session_id,
                rex_window_id: authority.rex_window_id,
                rex_block_id: authority.rex_block_id,
                wrapper,
                provider,
                lifecycle,
            });
        }
        drop(statement);
        let intent = StopOwnedRunsIntent {
            schema_version: 1,
            operation_id: operation_id.clone(),
            request: request.clone(),
            targets,
            created_at_unix: now_unix,
        };
        intent.validate()?;
        let intent_json = serde_json::to_string(&intent).map_err(|error| error.to_string())?;
        let digest = format!("{:x}", Sha256::digest(intent_json.as_bytes()));
        tx.execute(
            "INSERT INTO agent_stop_owned_runs_intents(operation_id,project_id,ticket_run_id,intent_digest,intent_json,created_at_unix)
             VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                operation_id.as_str(),
                request.project_id.as_str(),
                request.ticket_run_id.as_str(),
                digest,
                intent_json,
                now_unix
            ],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(intent)
    }

    pub fn stop_owned_runs_intent(
        &self,
        operation_id: &OperationId,
    ) -> Result<Option<StopOwnedRunsIntent>, String> {
        let row: Option<(String, String)> = self
            .connection
            .query_row(
                "SELECT intent_json,intent_digest FROM agent_stop_owned_runs_intents WHERE operation_id=?1",
                [operation_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let Some((json, expected_digest)) = row else {
            return Ok(None);
        };
        let actual_digest = format!("{:x}", Sha256::digest(json.as_bytes()));
        if actual_digest != expected_digest {
            return Err("stored StopOwnedRuns intent digest does not match its payload".into());
        }
        let intent: StopOwnedRunsIntent = crate::protocol::parse_unique(json.as_bytes())
            .map_err(|error| format!("stored StopOwnedRuns intent is invalid: {error}"))?;
        intent.validate()?;
        if intent.operation_id != *operation_id {
            return Err("stored StopOwnedRuns intent operation identity changed".into());
        }
        Ok(Some(intent))
    }

    pub fn recoverable_agent_runs(
        &self,
        owner_generation: u64,
        limit: usize,
    ) -> Result<Vec<RecoverableAgentRun>, String> {
        if limit == 0 || limit > 128 {
            return Err("Agent recovery observation limit must be between 1 and 128".into());
        }
        let owner: Option<u64> = self
            .connection
            .query_row(
                "SELECT generation FROM controller_owners WHERE singleton=1 AND stopped_at_unix IS NULL",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if owner != Some(owner_generation) {
            return Err("Agent recovery read is fenced to a stale controller generation".into());
        }

        let mut statement = self
            .connection
            .prepare(
                "SELECT r.agent_run_id,r.controller_generation,r.state,r.process_identity_json,
                        s.pool,s.slot_index,s.reservation_epoch,s.disposition,r.started_at_unix,
                        a.authority_json,a.authority_digest,l.state,l.wrapper_process_identity_json,
                        l.provider_process_tree_json
                 FROM agent_runs r
                 JOIN execution_slots s ON s.owner_kind='agent_run' AND s.owner_id=r.agent_run_id
                 JOIN agent_launch_authority a ON a.agent_run_id=r.agent_run_id
                 JOIN agent_launch_state l ON l.agent_run_id=r.agent_run_id
                 LEFT JOIN agent_run_recovery_observations o
                   ON o.agent_run_id=r.agent_run_id
                  AND o.controller_generation=r.controller_generation
                  AND o.reservation_epoch=s.reservation_epoch
                 WHERE r.controller_generation=?1 AND r.state IN ('unknown','running','launch_pending')
                   AND s.disposition IN ('unknown','live','launch_pending')
                 ORDER BY COALESCE(o.observation_order,0),r.agent_run_id LIMIT ?2",
            )
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(params![owner_generation, limit], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, u64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, u32>(5)?,
                    row.get::<_, u64>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, Option<i64>>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, Option<String>>(12)?,
                    row.get::<_, Option<String>>(13)?,
                ))
            })
            .map_err(|error| error.to_string())?;
        let mut result = Vec::new();
        for row in rows {
            let (
                id,
                current_generation,
                agent_state,
                process_identity_json,
                pool,
                slot_index,
                reservation_epoch,
                slot_disposition,
                started_at_unix,
                authority_json,
                authority_digest,
                launch_state,
                wrapper_identity_json,
                provider_tree_json,
            ) = row.map_err(|error| error.to_string())?;
            let agent_run_id = AgentRunId::parse(id)?;
            let authority: AgentLaunchAuthority =
                crate::protocol::parse_unique(authority_json.as_bytes()).map_err(|error| {
                    format!("stored Agent launch authority is invalid: {error}")
                })?;
            authority.validate()?;
            let actual_digest = authority.digest()?;
            if authority.agent_run_id != agent_run_id || actual_digest.as_str() != authority_digest
            {
                return Err("stored Agent launch authority changed during recovery".into());
            }
            let adopted_generation: Option<u64> = self
                .connection
                .query_row(
                    "SELECT controller_generation FROM agent_run_adoptions WHERE agent_run_id=?1 ORDER BY controller_generation DESC LIMIT 1",
                    [agent_run_id.as_str()],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|error| error.to_string())?;
            let previous_generation = adopted_generation.unwrap_or(authority.controller_generation);
            result.push(RecoverableAgentRun {
                agent_run_id,
                current_generation,
                previous_generation,
                authority,
                authority_digest: Digest::parse(authority_digest)?,
                agent_state,
                started_at_unix,
                launch_state,
                process_identity_json,
                wrapper_identity_json,
                provider_tree_json,
                pool,
                slot_index,
                reservation_epoch,
                slot_disposition,
            });
        }
        Ok(result)
    }

    /// Persist the last bounded observation so later ticks make progress through all live runs.
    pub fn record_agent_recovery_observation(
        &mut self,
        owner_generation: u64,
        agent_run_id: &AgentRunId,
        expected_reservation_epoch: u64,
        observed_at_unix: i64,
    ) -> Result<(), String> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let observation_order: i64 = tx
            .query_row(
                "SELECT COALESCE(MAX(observation_order),0)+1 FROM agent_run_recovery_observations",
                [],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        let changed = tx.execute(
            "INSERT INTO agent_run_recovery_observations(agent_run_id,controller_generation,reservation_epoch,observation_order,observed_at_unix)
             SELECT r.agent_run_id,r.controller_generation,s.reservation_epoch,?4,?5
             FROM agent_runs r JOIN execution_slots s ON s.owner_kind='agent_run' AND s.owner_id=r.agent_run_id
             WHERE r.agent_run_id=?1 AND r.controller_generation=?2 AND s.reservation_epoch=?3
               AND s.disposition IN ('unknown','live','launch_pending')
             ON CONFLICT(agent_run_id) DO UPDATE SET
               controller_generation=excluded.controller_generation,
               reservation_epoch=excluded.reservation_epoch,
               observation_order=excluded.observation_order,
               observed_at_unix=excluded.observed_at_unix",
            params![agent_run_id.as_str(), owner_generation, expected_reservation_epoch, observation_order, observed_at_unix],
        ).map_err(|error| error.to_string())?;
        if changed != 1 {
            return Err(
                "AgentRun or execution slot changed before recovery observation was recorded"
                    .into(),
            );
        }
        tx.commit().map_err(|error| error.to_string())
    }

    pub fn record_agent_run_adoption(
        &mut self,
        evidence: &AgentAdoptionEvidence,
        expected_reservation_epoch: u64,
    ) -> Result<bool, String> {
        evidence.validate()?;
        let evidence_json = serde_json::to_string(evidence).map_err(|error| error.to_string())?;
        let evidence_digest = evidence.digest()?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, evidence.controller_generation)?;
        let row: Option<(String, u64, u64, String, u64, String, String, String)> = tx
            .query_row(
                "SELECT a.authority_json,r.controller_generation,r.reservation_epoch,r.disposition,
                        r.slot_index,r.pool,r.owner_id,r.owner_kind
                 FROM agent_launch_authority a
                 JOIN agent_runs g ON g.agent_run_id=a.agent_run_id
                 JOIN execution_slots r ON r.owner_kind='agent_run' AND r.owner_id=a.agent_run_id
                 WHERE a.agent_run_id=?1 AND r.pool='agent'",
                [evidence.agent_run_id.as_str()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let Some((
            authority_json,
            current_generation,
            reservation_epoch,
            disposition,
            _slot_index,
            _pool,
            owner_id,
            owner_kind,
        )) = row
        else {
            return Err("AgentRun has no matching owned execution slot".into());
        };
        let authority: AgentLaunchAuthority =
            crate::protocol::parse_unique(authority_json.as_bytes())
                .map_err(|error| format!("stored Agent launch authority is invalid: {error}"))?;
        let last_adopted_generation: Option<u64> = tx
            .query_row(
                "SELECT controller_generation FROM agent_run_adoptions WHERE agent_run_id=?1 ORDER BY controller_generation DESC LIMIT 1",
                [evidence.agent_run_id.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let expected_previous_generation =
            last_adopted_generation.unwrap_or(authority.controller_generation);
        if authority.agent_run_id != evidence.agent_run_id
            || authority.digest()? != evidence.authority_digest
            || authority.descriptor_digest != evidence.descriptor_digest
            || evidence.previous_controller_generation != expected_previous_generation
            || current_generation != evidence.controller_generation
            || reservation_epoch != expected_reservation_epoch
            || owner_kind != "agent_run"
            || owner_id != evidence.agent_run_id.as_str()
            || !matches!(disposition.as_str(), "unknown" | "live")
        {
            return Err("AgentRun or execution-slot identity changed before adoption".into());
        }
        let inserted = tx.execute(
            "INSERT INTO agent_run_adoptions(agent_run_id,controller_generation,previous_controller_generation,authority_digest,descriptor_digest,evidence_digest,evidence_json,created_at_unix)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(agent_run_id,controller_generation) DO NOTHING",
            params![evidence.agent_run_id.as_str(),evidence.controller_generation,evidence.previous_controller_generation,evidence.authority_digest.as_str(),evidence.descriptor_digest.as_str(),evidence_digest.as_str(),evidence_json,super::now_unix()?],
        ).map_err(|error| error.to_string())? == 1;
        if !inserted {
            let existing: (String, String) = tx.query_row(
                "SELECT evidence_digest,evidence_json FROM agent_run_adoptions WHERE agent_run_id=?1 AND controller_generation=?2",
                params![evidence.agent_run_id.as_str(),evidence.controller_generation],
                |row| Ok((row.get(0)?,row.get(1)?)),
            ).map_err(|error| error.to_string())?;
            if existing != (evidence_digest.as_str().to_owned(), evidence_json) {
                return Err(
                    "AgentRun already has different adoption evidence for this generation".into(),
                );
            }
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(false);
        }
        let run_changed = tx.execute(
            "UPDATE agent_runs SET state='running',controller_generation=?2 WHERE agent_run_id=?1 AND controller_generation=?2 AND state='unknown'",
            params![evidence.agent_run_id.as_str(),evidence.controller_generation],
        ).map_err(|error| error.to_string())?;
        let slot_changed = tx.execute(
            "UPDATE execution_slots SET disposition='live',controller_generation=?4,process_identity_json=?5
             WHERE pool='agent' AND owner_kind='agent_run' AND owner_id=?1 AND slot_index=?2
               AND reservation_epoch=?3 AND disposition IN ('unknown','live')",
            params![evidence.agent_run_id.as_str(),_slot_index,expected_reservation_epoch,evidence.controller_generation,serde_json::to_string(&serde_json::json!({"provider_pid":evidence.provider_pid,"provider_start_identity":evidence.provider_start_identity,"process_tree_digest":evidence.process_tree_digest})).map_err(|error| error.to_string())?],
        ).map_err(|error| error.to_string())?;
        if run_changed != 1 || slot_changed != 1 {
            return Err("AgentRun or slot changed while adoption was being recorded".into());
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(true)
    }

    /// Queue one durable parent-role attention input for a run epoch. The unique input identity
    /// coalesces repeat observations and cannot spin an already-running Coordinator.
    pub fn queue_agent_recovery_attention(
        &mut self,
        owner_generation: u64,
        authority: &AgentLaunchAuthority,
        reason: crate::agent_recovery::RecoveryUnknown,
        now_unix: i64,
    ) -> Result<bool, String> {
        let Some(parent_run_id) = &authority.parent_run_id else {
            return Ok(false);
        };
        let parent = self
            .agent_launch_authority(parent_run_id)?
            .ok_or_else(|| "recovery attention parent authority is missing".to_owned())?;
        if parent.project_id != authority.project_id
            || parent.role != authority.parent_role.ok_or("parent role is missing")?
            || !matches!(
                parent.role,
                crate::domain::types::Role::Coordinator | crate::domain::types::Role::Supervisor
            )
        {
            return Err("recovery attention parent is outside the run's role hierarchy".into());
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let payload = serde_json::json!({
            "kind": "agent_recovery_attention",
            "agent_run_id": authority.agent_run_id.as_str(),
            "attempt": authority.attempt,
            "run_epoch": authority.run_epoch,
            "reason": format!("{reason:?}"),
            "instruction": "Inspect the AgentRun and decide whether to stop or resume. Do not start a replacement until process absence is verified."
        });
        let inserted = tx.execute(
            "INSERT INTO role_wake_inputs(project_id,role_session_id,source_type,source_id,source_revision,priority,payload_json,lifecycle,created_at_unix)
             VALUES (?1,?2,'agent_recovery_attention',?3,?4,100,?5,'pending',?6)
             ON CONFLICT(role_session_id,source_type,source_id,source_revision) DO NOTHING",
            params![authority.project_id.as_str(),parent.role_session_id,authority.agent_run_id.as_str(),authority.run_epoch,payload.to_string(),now_unix],
        ).map_err(|error| error.to_string())? == 1;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(inserted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_creates_immutable_adoption_evidence_and_observation_cursor() {
        let mut connection = rusqlite::Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE agent_runs(agent_run_id TEXT PRIMARY KEY);
                 INSERT INTO agent_runs(agent_run_id) VALUES ('run-1');",
            )
            .unwrap();
        let tx = connection.transaction().unwrap();
        migrate_v12_recovery_tables(&tx).unwrap();
        tx.commit().unwrap();

        connection
            .execute(
                "INSERT INTO agent_run_adoptions(agent_run_id,controller_generation,previous_controller_generation,authority_digest,descriptor_digest,evidence_digest,evidence_json,created_at_unix)
                 VALUES ('run-1',2,1,?1,?1,?1,'{}',10)",
                ["a".repeat(64)],
            )
            .unwrap();
        assert!(
            connection
                .execute(
                    "UPDATE agent_run_adoptions SET evidence_json='{}' WHERE agent_run_id='run-1'",
                    [],
                )
                .is_err()
        );
        assert!(
            connection
                .execute(
                    "DELETE FROM agent_run_adoptions WHERE agent_run_id='run-1'",
                    []
                )
                .is_err()
        );
        connection
            .execute(
                "INSERT INTO agent_stop_owned_runs_intents(operation_id,project_id,ticket_run_id,intent_digest,intent_json,created_at_unix)
                 VALUES ('op-1','project-1','ticket-1',?1,'{}',10)",
                ["b".repeat(64)],
            )
            .unwrap();
        assert!(connection
            .execute(
                "UPDATE agent_stop_owned_runs_intents SET intent_json='{}' WHERE operation_id='op-1'",
                [],
            )
            .is_err());
        assert!(
            connection
                .execute(
                    "DELETE FROM agent_stop_owned_runs_intents WHERE operation_id='op-1'",
                    []
                )
                .is_err()
        );

        let observation_table: String = connection
            .query_row(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='agent_run_recovery_observations'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(observation_table, "agent_run_recovery_observations");
    }
}
