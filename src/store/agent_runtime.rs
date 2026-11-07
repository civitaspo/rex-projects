//! Host-side queries and state transitions for finite role Agent turns.

use rusqlite::{OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::domain::ids::{Digest, ProjectId};
use crate::domain::types::Role;
use crate::launch::{AgentLaunchReservation, StartAgentEffectPayload};
use crate::store::{EffectIntent, insert_effect, now_unix, validate_active_generation};

const MAX_WAKE_SNAPSHOT_ITEMS: usize = 256;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PendingRoleWakeInput {
    pub wake_input_id: u64,
    pub source_type: String,
    pub source_id: String,
    pub source_revision: u64,
    pub priority: i32,
    pub payload_json: serde_json::Value,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LaunchPreparationOutcome {
    Prepared { reservation_digest: Digest },
    CapacityUnavailable,
}

impl ConfigStore {
    /// Load the exact host-owned phase-one reservation for a claimed StartAgent effect.
    /// The digest is checked again so a caller cannot substitute a serialized reservation.
    pub fn agent_launch_reservation(
        &self,
        agent_run_id: &crate::domain::ids::AgentRunId,
        expected_digest: &Digest,
    ) -> Result<Option<AgentLaunchReservation>, String> {
        let stored: Option<(String, String)> = self.connection.query_row(
            "SELECT reservation_digest,reservation_json FROM agent_launch_reservations WHERE agent_run_id=?1",
            [agent_run_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional().map_err(|error| error.to_string())?;
        let Some((digest, json)) = stored else {
            return Ok(None);
        };
        if digest != expected_digest.as_str() {
            return Err("StartAgent effect does not match its immutable reservation digest".into());
        }
        let reservation: AgentLaunchReservation = crate::protocol::parse_unique(json.as_bytes())
            .map_err(|error| format!("stored launch reservation is invalid: {error}"))?;
        reservation.validate()?;
        if reservation.agent_run_id != *agent_run_id || reservation.digest()? != *expected_digest {
            return Err("stored launch reservation identity or digest is inconsistent".into());
        }
        Ok(Some(reservation))
    }

    /// Close phase two after host authority and the real Rex block have both been
    /// persisted. This is idempotent and never turns an unknown block into success.
    pub fn finalize_agent_launch_reservation(
        &mut self,
        owner_generation: u64,
        agent_run_id: &crate::domain::ids::AgentRunId,
        reservation_digest: &Digest,
        authority: &crate::launch::AgentLaunchAuthority,
    ) -> Result<(), String> {
        authority.validate()?;
        let authority_digest = authority.digest()?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        if authority.agent_run_id != *agent_run_id
            || authority.controller_generation != owner_generation
        {
            return Err("final launch authority is not bound to this run and controller".into());
        }
        let reservation: Option<(String, String, String)> = tx.query_row(
            "SELECT reservation_digest,reservation_json,lifecycle FROM agent_launch_reservations WHERE agent_run_id=?1",
            [agent_run_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).optional().map_err(|error| error.to_string())?;
        let Some((stored_digest, reservation_json, lifecycle)) = reservation else {
            return Err("AgentRun has no launch reservation".into());
        };
        if stored_digest != reservation_digest.as_str() {
            return Err("launch reservation digest changed before finalization".into());
        }
        let reservation: AgentLaunchReservation =
            crate::protocol::parse_unique(reservation_json.as_bytes())
                .map_err(|error| format!("stored launch reservation is invalid: {error}"))?;
        let expected = reservation.digest()?;
        if expected != *reservation_digest
            || authority.project_id != reservation.project_id
            || authority.role != reservation.role
            || authority.role_session_id != reservation.role_session_id
            || authority.parent_run_id != reservation.parent_run_id
            || authority.parent_role != reservation.parent_role
            || authority.ticket_run_id != reservation.ticket_run_id
            || authority.ticket_revision != reservation.ticket_revision
            || authority.config_revision != reservation.config_revision
            || authority.config_digest != reservation.config_digest
            || authority.operation_id != reservation.operation_id
            || authority.operation_recipe_id != reservation.operation_recipe_id
            || authority.rex_view_id != reservation.rex_view_id
            || authority.runtime_binary_digest != reservation.runtime_binary_digest
            || authority.environment_snapshot_id != reservation.environment_snapshot_id
            || authority.profile_id != reservation.profile_id
            || authority.profile_digest != reservation.profile_digest
            || authority.instruction_digest != reservation.instruction_digest
            || authority.result_schema_digest != reservation.result_schema_digest
            || authority.qualification_receipt_digest != reservation.qualification_receipt_digest
            || authority.descriptor_path != reservation.descriptor_path
            || authority.workspace_path != reservation.workspace_path
            || authority.control_dir != reservation.control_dir
            || authority.mailbox_capability_digest != reservation.mailbox_capability_digest
        {
            return Err("final authority does not preserve the immutable reservation".into());
        }
        let persisted_authority: Option<(String, String)> = tx.query_row(
            "SELECT authority_json,authority_digest FROM agent_launch_authority WHERE agent_run_id=?1",
            [agent_run_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional().map_err(|error| error.to_string())?;
        let authority_json = serde_json::to_string(authority).map_err(|error| error.to_string())?;
        if persisted_authority.as_ref().is_none_or(|(json, digest)| {
            json != &authority_json || digest != authority_digest.as_str()
        }) {
            return Err("final launch authority is not durably registered".into());
        }
        let block: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM rex_view_blocks WHERE view_id=?1 AND block_id=?2 AND agent_run_id=?3 AND ownership='factory' AND lifecycle='active')",
            rusqlite::params![authority.rex_view_id.as_str(), authority.rex_block_id, agent_run_id.as_str()],
            |row| row.get(0),
        ).map_err(|error| error.to_string())?;
        if !block {
            return Err("final launch authority has no matching persisted active Rex block".into());
        }
        let wake_json = crate::store::canonical_json(&reservation.wake_snapshot)?;
        let wake_digest = Digest::parse(format!("{:x}", Sha256::digest(wake_json.as_bytes())))?;
        if wake_digest != authority.wake_snapshot_digest {
            return Err(
                "authority wake snapshot digest does not match the reserved snapshot".into(),
            );
        }
        tx.execute(
            "INSERT INTO agent_wake_context(agent_run_id,snapshot_digest,snapshot_json,created_at_unix) VALUES (?1,?2,?3,?4) ON CONFLICT(agent_run_id) DO NOTHING",
            rusqlite::params![agent_run_id.as_str(), wake_digest.as_str(), wake_json, now_unix()?],
        ).map_err(|error| error.to_string())?;
        let stored_wake: (String, String) = tx.query_row(
            "SELECT snapshot_digest,snapshot_json FROM agent_wake_context WHERE agent_run_id=?1",
            [agent_run_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).map_err(|error| error.to_string())?;
        if stored_wake != (wake_digest.as_str().to_owned(), wake_json) {
            return Err("AgentRun has a different immutable wake snapshot".into());
        }
        if lifecycle == "authorized" {
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(());
        }
        let changed = tx.execute(
            "UPDATE agent_launch_reservations SET lifecycle='authorized',updated_at_unix=?2 WHERE agent_run_id=?1 AND reservation_digest=?3 AND lifecycle IN ('reserved','block_created')",
            rusqlite::params![agent_run_id.as_str(), now_unix()?, reservation_digest.as_str()],
        ).map_err(|error| error.to_string())?;
        if changed != 1 {
            return Err("launch reservation could not transition to finalized".into());
        }
        tx.commit().map_err(|error| error.to_string())
    }

    /// Read an ordered candidate snapshot for a scheduler. This is advisory only: the launch
    /// preparation transaction must recheck and claim these exact IDs before creating a run.
    pub fn pending_role_wake_inputs(
        &self,
        project_id: &ProjectId,
        role_session_id: &str,
        limit: usize,
    ) -> Result<Vec<PendingRoleWakeInput>, String> {
        if role_session_id.trim().is_empty() || role_session_id.chars().any(char::is_control) {
            return Err("role session ID is empty or contains control characters".into());
        }
        if limit == 0 || limit > MAX_WAKE_SNAPSHOT_ITEMS {
            return Err(format!(
                "wake snapshot limit must be between 1 and {MAX_WAKE_SNAPSHOT_ITEMS}"
            ));
        }
        let mut statement = self
            .connection
            .prepare(
                "SELECT wake_input_id,source_type,source_id,source_revision,priority,payload_json \
                 FROM role_wake_inputs WHERE project_id=?1 AND role_session_id=?2 AND lifecycle='pending' \
                 ORDER BY priority DESC,wake_input_id ASC LIMIT ?3",
            )
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(
                rusqlite::params![project_id.as_str(), role_session_id, limit as u64],
                |row| {
                    Ok((
                        row.get::<_, u64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, u64>(3)?,
                        row.get::<_, i32>(4)?,
                        row.get::<_, String>(5)?,
                    ))
                },
            )
            .map_err(|error| error.to_string())?;
        let mut inputs = Vec::new();
        for row in rows {
            let (id, source_type, source_id, revision, priority, payload) =
                row.map_err(|error| error.to_string())?;
            let payload_json = crate::protocol::parse_unique(payload.as_bytes())
                .map_err(|error| format!("stored wake input {id} has invalid JSON: {error}"))?;
            inputs.push(PendingRoleWakeInput {
                wake_input_id: id,
                source_type,
                source_id,
                source_revision: revision,
                priority,
                payload_json,
            });
        }
        Ok(inputs)
    }

    /// Reserve a finite turn and enqueue its first host effect atomically. This phase contains
    /// only the known Rex view identity; the new block ID is observed and bound in phase two.
    pub fn prepare_role_launch(
        &mut self,
        reservation: &AgentLaunchReservation,
    ) -> Result<LaunchPreparationOutcome, String> {
        reservation.validate()?;
        let reservation_digest = reservation.digest()?;
        let control_dir = std::fs::canonicalize(&reservation.control_dir)
            .map_err(|error| format!("canonicalize control directory: {error}"))?;
        let mailbox_dir = std::fs::canonicalize(&reservation.mailbox_directory)
            .map_err(|error| format!("canonicalize mailbox directory: {error}"))?;
        if control_dir != mailbox_dir {
            return Err("mailbox directory must equal the launch control directory".into());
        }
        let reservation_json = crate::store::canonical_json(reservation)?;
        if reservation_json.len() > 1_048_576 {
            return Err("launch reservation exceeds 1 MiB".into());
        }

        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, reservation.controller_generation)?;
        let project: Option<(String, u64, String, String, String, u64, String)> = tx
            .query_row(
                "SELECT p.config_source,p.config_revision,p.config_digest,p.mode,p.desired_lifecycle,r.project_epoch,r.observed_lifecycle FROM projects p JOIN project_runtimes r USING(project_id) WHERE p.project_id=?1",
                [reservation.project_id.as_str()],
                |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let Some((
            config_source,
            config_revision,
            config_digest,
            _mode,
            desired,
            project_epoch,
            observed,
        )) = project
        else {
            return Err("launch reservation references an unknown Project".into());
        };
        if desired != "running"
            || !matches!(observed.as_str(), "running" | "starting")
            || project_epoch != reservation.project_epoch
            || config_revision != reservation.config_revision.0
            || config_digest != reservation.config_digest.as_str()
        {
            return Err("Project lifecycle, epoch, or configuration changed before launch".into());
        }
        let config_json: String = tx
            .query_row(
                "SELECT effective_config_json FROM config_snapshots WHERE source_identity=?1 AND revision=?2 AND digest=?3",
                params![config_source, reservation.config_revision.0, reservation.config_digest.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?
            .ok_or("launch configuration is not the exact current snapshot")?;
        let effective: super::EffectiveConfig =
            crate::protocol::parse_unique(config_json.as_bytes())
                .map_err(|error| format!("applied configuration is invalid: {error}"))?;
        let profile = effective
            .profiles
            .get(&reservation.profile_id)
            .ok_or("launch profile is missing from the applied configuration")?;
        let project_config = effective
            .config
            .projects
            .get(&reservation.project_id)
            .ok_or("launch Project is missing from the applied configuration")?;
        let project_roles = crate::config::effective_project_roles(
            &reservation.project_id,
            &effective.config.projects,
        )?;
        let expected_profile = if let Some(recipe_id) = &reservation.operation_recipe_id {
            let recipe_allowed = project_config
                .operation_matches
                .iter()
                .any(|operation| &operation.recipe == recipe_id);
            if !recipe_allowed {
                return Err("operation recipe is not selected by this Project".into());
            }
            effective
                .config
                .operation_recipes
                .get(recipe_id)
                .ok_or("launch operation recipe is missing from applied configuration")?
                .roles
                .get(&reservation.role)
                .or_else(|| project_roles.get(&reservation.role))
        } else {
            project_roles.get(&reservation.role)
        }
        .ok_or("launch role has no effective profile")?;
        if expected_profile != &reservation.profile_id {
            return Err(
                "launch profile does not match the Project's effective role profile".into(),
            );
        }
        let profile_digest = Digest::parse(format!(
            "{:x}",
            Sha256::digest(crate::store::canonical_json(profile)?.as_bytes())
        ))?;
        if profile_digest != reservation.profile_digest {
            return Err("launch profile digest does not match the applied profile".into());
        }
        let view: Option<(String,String,String,String,String,Option<String>,Option<String>)> = tx
            .query_row(
                "SELECT project_id,view_kind,rex_server_identity,rex_session_id,rex_window_id,ticket_namespace,ticket_id FROM rex_views WHERE view_id=?1 AND lifecycle='active'",
                [reservation.rex_view_id.as_str()],
                |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let Some((
            view_project,
            view_kind,
            _server,
            _session,
            _window,
            view_namespace,
            view_ticket,
        )) = view
        else {
            return Err("launch reservation references no active Rex view".into());
        };
        if view_project != reservation.project_id.as_str()
            || (reservation.role == Role::Supervisor && view_kind != "supervisor")
            || (reservation.role != Role::Supervisor && view_kind != "ticket")
        {
            return Err("Rex view scope does not match launch Project and role".into());
        }
        if let Some(ticket_run_id) = &reservation.ticket_run_id {
            let ticket: Option<(String,String,String,u64)> = tx
                .query_row(
                    "SELECT project_id,namespace,ticket_id,revision FROM ticket_runs WHERE ticket_run_id=?1",
                    [ticket_run_id.as_str()],
                    |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
                )
                .optional()
                .map_err(|error| error.to_string())?;
            let Some((ticket_project, namespace, ticket_id, revision)) = ticket else {
                return Err("launch TicketRun does not exist".into());
            };
            if ticket_project != reservation.project_id.as_str()
                || Some(revision) != reservation.ticket_revision.map(|value| value.0)
                || view_namespace.as_deref() != Some(namespace.as_str())
                || view_ticket.as_deref() != Some(ticket_id.as_str())
            {
                return Err("TicketRun project, revision, or registered Rex view changed".into());
            }
        }

        let qualification_json: Option<String> = tx
            .query_row(
                "SELECT receipt_json FROM provider_qualifications WHERE receipt_digest=?1",
                [reservation.qualification_receipt_digest.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let qualification: crate::launch::ProviderQualification = crate::protocol::parse_unique(
            qualification_json
                .ok_or("provider qualification is not registered")?
                .as_bytes(),
        )
        .map_err(|error| format!("provider qualification is invalid: {error}"))?;
        if qualification.canonical_digest()? != reservation.qualification_receipt_digest
            || qualification.project_id != reservation.project_id
            || qualification.profile_id != reservation.profile_id
            || qualification.profile_digest != reservation.profile_digest
        {
            return Err("provider qualification does not match launch Project/profile".into());
        }
        qualification.validate_for_unattended_launch()?;

        let wakes = load_exact_wake_inputs(&tx, reservation)?;
        if wakes.len() != reservation.wake_snapshot.inputs.len()
            || wakes
                .iter()
                .zip(&reservation.wake_snapshot.inputs)
                .any(|(stored, submitted)| {
                    stored.wake_input_id != submitted.wake_input_id
                        || stored.source_type != submitted.source_type
                        || stored.source_id != submitted.source_id
                        || stored.source_revision != submitted.source_revision
                        || stored.priority != submitted.priority
                        || stored.payload_json != submitted.payload_json
                })
        {
            return Err("wake snapshot differs from the selected current pending inputs".into());
        }

        let prior: Option<(String,String)> = tx
            .query_row(
                "SELECT reservation_digest,reservation_json FROM agent_launch_reservations WHERE agent_run_id=?1",
                [reservation.agent_run_id.as_str()],
                |row| Ok((row.get(0)?,row.get(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if let Some((prior_digest, prior_json)) = prior {
            if prior_digest != reservation_digest.as_str() || prior_json != reservation_json {
                return Err("AgentRun ID was reused with a different immutable reservation".into());
            }
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(LaunchPreparationOutcome::Prepared { reservation_digest });
        }

        let global_used: u32 = tx
            .query_row(
                "SELECT COUNT(*) FROM execution_slots WHERE pool=?1 AND disposition!='released'",
                [&reservation.pool],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        let project_used: u32 = tx
            .query_row(
                "SELECT COUNT(*) FROM execution_slots WHERE project_id=?1 AND disposition!='released'",
                [reservation.project_id.as_str()],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        let slot_occupied: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM execution_slots WHERE pool=?1 AND slot_index=?2 AND disposition!='released')",
                params![reservation.pool,reservation.slot_index],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        if global_used >= reservation.global_capacity
            || project_used >= reservation.project_capacity
            || slot_occupied
            || reservation.slot_index >= reservation.global_capacity
        {
            return Ok(LaunchPreparationOutcome::CapacityUnavailable);
        }
        let active_same_session: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM agent_runs WHERE project_id=?1 AND role_session_id=?2 AND state IN ('launch_pending','running','parked','unknown'))",
                params![reservation.project_id.as_str(),reservation.role_session_id],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        if active_same_session {
            return Ok(LaunchPreparationOutcome::CapacityUnavailable);
        }
        if let Some(parent_id) = &reservation.parent_run_id {
            let parent: Option<(String,String,String)> = tx
                .query_row(
                    "SELECT r.project_id,r.state,a.role FROM agent_runs r JOIN agent_launch_authority a USING(agent_run_id) WHERE r.agent_run_id=?1",
                    [parent_id.as_str()],
                    |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
                )
                .optional()
                .map_err(|error| error.to_string())?;
            let expected_parent_role = reservation
                .parent_role
                .map(|role| {
                    serde_json::to_value(role)
                        .ok()
                        .and_then(|value| value.as_str().map(str::to_owned))
                })
                .flatten();
            if !matches!(parent,Some((ref parent_project,ref state,ref role)) if parent_project==reservation.project_id.as_str() && matches!(state.as_str(),"running"|"parked") && expected_parent_role.as_deref()==Some(role.as_str()))
            {
                return Err(
                    "launch parent is not an active same-Project AgentRun with the expected role"
                        .into(),
                );
            }
        }

        let ticket_run_id = reservation.ticket_run_id.as_ref().map(|id| id.as_str());
        tx.execute(
            "INSERT INTO agent_runs(agent_run_id,project_id,config_source,config_revision,config_digest,role_session_id,logical_owner,finite_turn,launch_operation_id,rex_session_id,rex_window_id,rex_block_id,process_identity_json,state,controller_generation,started_at_unix,finished_at_unix) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,NULL,NULL,NULL,NULL,'launch_pending',?10,NULL,NULL)",
            params![reservation.agent_run_id.as_str(),reservation.project_id.as_str(),config_source,reservation.config_revision.0,reservation.config_digest.as_str(),reservation.role_session_id,format!("role:{}",reservation.role_session_id),reservation.run_epoch,reservation.operation_id.as_str(),reservation.controller_generation],
        ).map_err(|error| error.to_string())?;
        tx.execute(
            "INSERT INTO execution_slots(pool,slot_index,project_id,ticket_run_id,owner_kind,owner_id,reservation_epoch,controller_generation,process_identity_json,disposition) VALUES (?1,?2,?3,?4,'agent_run',?5,?6,?7,NULL,'launch_pending')",
            params![reservation.pool,reservation.slot_index,reservation.project_id.as_str(),ticket_run_id,reservation.agent_run_id.as_str(),reservation.project_epoch,reservation.controller_generation],
        ).map_err(|error| error.to_string())?;
        tx.execute(
            "INSERT INTO agent_mailboxes(agent_run_id,canonical_directory,capability_digest,expires_at_unix,max_request_bytes,max_pending_requests) VALUES (?1,?2,?3,?4,?5,?6)",
            params![reservation.agent_run_id.as_str(),mailbox_dir.to_string_lossy(),reservation.mailbox_capability_digest.as_str(),reservation.mailbox_expires_at_unix,reservation.mailbox_max_request_bytes,reservation.mailbox_max_pending_requests],
        ).map_err(|error| error.to_string())?;
        tx.execute(
            "INSERT INTO agent_launch_reservations(agent_run_id,project_id,operation_id,controller_generation,project_epoch,reservation_digest,reservation_json,lifecycle,created_at_unix,updated_at_unix) VALUES (?1,?2,?3,?4,?5,?6,?7,'reserved',?8,?8)",
            params![reservation.agent_run_id.as_str(),reservation.project_id.as_str(),reservation.operation_id.as_str(),reservation.controller_generation,reservation.project_epoch,reservation_digest.as_str(),reservation_json,now_unix()?],
        ).map_err(|error| error.to_string())?;
        for wake in &reservation.wake_snapshot.inputs {
            let changed = tx.execute(
                "UPDATE role_wake_inputs SET lifecycle='assigned',consuming_agent_run_id=?2 WHERE wake_input_id=?1 AND project_id=?3 AND role_session_id=?4 AND lifecycle='pending'",
                params![wake.wake_input_id,reservation.agent_run_id.as_str(),reservation.project_id.as_str(),reservation.role_session_id],
            ).map_err(|error| error.to_string())?;
            if changed != 1 {
                return Err("wake input was concurrently claimed by another AgentRun".into());
            }
        }
        let effect_payload = StartAgentEffectPayload {
            schema_version: crate::launch::LAUNCH_SCHEMA_VERSION,
            agent_run_id: reservation.agent_run_id.clone(),
            launch_reservation_digest: reservation_digest.clone(),
        };
        let request_json = crate::store::canonical_json(&effect_payload)?;
        let request_digest =
            Digest::parse(format!("{:x}", Sha256::digest(request_json.as_bytes())))?;
        insert_effect(
            &tx,
            &EffectIntent {
                project_id: reservation.project_id.clone(),
                subject_type: "agent_run".into(),
                subject_id: reservation.agent_run_id.as_str().into(),
                operation_id: reservation.operation_id.as_str().into(),
                logical_key: format!("start-agent:{}", reservation.agent_run_id.as_str()),
                kind: "start_agent".into(),
                request_json,
                request_digest: request_digest.as_str().into(),
                expected_revision: None,
            },
            now_unix()?,
        )?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(LaunchPreparationOutcome::Prepared { reservation_digest })
    }
}

use super::ConfigStore;

fn load_exact_wake_inputs(
    tx: &rusqlite::Transaction<'_>,
    reservation: &AgentLaunchReservation,
) -> Result<Vec<PendingRoleWakeInput>, String> {
    if reservation.wake_snapshot.inputs.len() > MAX_WAKE_SNAPSHOT_ITEMS {
        return Err("wake snapshot exceeds the 256 input limit".into());
    }
    let mut inputs = Vec::with_capacity(reservation.wake_snapshot.inputs.len());
    for selected in &reservation.wake_snapshot.inputs {
        let row: Option<(String,String,u64,i32,String)> = tx
            .query_row(
                "SELECT source_type,source_id,source_revision,priority,payload_json FROM role_wake_inputs WHERE wake_input_id=?1 AND project_id=?2 AND role_session_id=?3 AND lifecycle='pending'",
                params![selected.wake_input_id,reservation.project_id.as_str(),reservation.role_session_id],
                |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let Some((source_type, source_id, source_revision, priority, payload)) = row else {
            return Err("selected wake input is missing or no longer pending".into());
        };
        inputs.push(PendingRoleWakeInput {
            wake_input_id: selected.wake_input_id,
            source_type,
            source_id,
            source_revision,
            priority,
            payload_json: crate::protocol::parse_unique(payload.as_bytes())
                .map_err(|error| format!("stored wake input has invalid JSON: {error}"))?,
        });
    }
    Ok(inputs)
}
