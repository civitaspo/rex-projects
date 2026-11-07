//! Durable preparation and finalization for finite Agent launch reservations.

use rusqlite::{OptionalExtension, TransactionBehavior, params};
use sha2::{Digest as _, Sha256};

use crate::domain::ids::{AgentRunId, Digest, ProjectId};
use crate::domain::types::Role;
use crate::launch::{AgentLaunchAuthority, AgentLaunchReservation, StartAgentEffectPayload};
use crate::store::{
    ConfigStore, EffectIntent, canonical_json, insert_effect, now_unix, validate_active_generation,
};

const MAX_WAKE_SNAPSHOT_ITEMS: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LaunchPreparationOutcome {
    Prepared { reservation_digest: Digest },
    CapacityUnavailable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingRoleWakeInput {
    pub wake_input_id: u64,
    pub source_type: String,
    pub source_id: String,
    pub source_revision: u64,
    pub priority: i32,
    pub payload_json: serde_json::Value,
}

impl ConfigStore {
    /// Reserve a finite turn, its execution slot, wake inputs, mailbox, and StartAgent effect
    /// in one SQLite transaction. Worker launches require the later prepared-plan token API.
    pub fn prepare_role_launch(
        &mut self,
        reservation: &AgentLaunchReservation,
    ) -> Result<LaunchPreparationOutcome, String> {
        if reservation.role == Role::Worker || reservation.worker_assignment.is_some() {
            return Err(
                "Worker launches require the opaque accepted-plan and prepared-worktree token"
                    .into(),
            );
        }
        reservation.validate()?;
        let reservation_digest = reservation.digest()?;
        let control_dir = std::fs::canonicalize(&reservation.control_dir)
            .map_err(|error| format!("canonicalize control directory: {error}"))?;
        let mailbox_dir = std::fs::canonicalize(&reservation.mailbox_directory)
            .map_err(|error| format!("canonicalize mailbox directory: {error}"))?;
        if control_dir != mailbox_dir {
            return Err("mailbox directory must equal the launch control directory".into());
        }
        let reservation_json = canonical_json(reservation)?;
        if reservation_json.len() > 1_048_576 {
            return Err("launch reservation exceeds 1 MiB".into());
        }

        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, reservation.controller_generation)?;
        let project: Option<(String, u64, String, String, String, u64, String)> = tx.query_row(
            "SELECT p.config_source,p.config_revision,p.config_digest,p.mode,p.desired_lifecycle,r.project_epoch,r.observed_lifecycle FROM projects p JOIN project_runtimes r USING(project_id) WHERE p.project_id=?1",
            [reservation.project_id.as_str()],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?)),
        ).optional().map_err(|error| error.to_string())?;
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
        let config_json: String = tx.query_row(
            "SELECT effective_config_json FROM config_snapshots WHERE source_identity=?1 AND revision=?2 AND digest=?3",
            params![config_source, reservation.config_revision.0, reservation.config_digest.as_str()],
            |row| row.get(0),
        ).optional().map_err(|error| error.to_string())?
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
            if !project_config
                .operation_matches
                .iter()
                .any(|operation| &operation.recipe == recipe_id)
            {
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
            Sha256::digest(canonical_json(profile)?.as_bytes())
        ))?;
        if profile_digest != reservation.profile_digest {
            return Err("launch profile digest does not match the applied profile".into());
        }

        type ViewScope = (String, String, Option<String>, Option<String>);
        let view: Option<ViewScope> = tx.query_row(
            "SELECT project_id,view_kind,ticket_namespace,ticket_id FROM rex_views WHERE view_id=?1 AND lifecycle='active'",
            [reservation.rex_view_id.as_str()],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
        ).optional().map_err(|error| error.to_string())?;
        let Some((view_project, view_kind, view_namespace, view_ticket)) = view else {
            return Err("launch reservation references no active Rex view".into());
        };
        if view_project != reservation.project_id.as_str()
            || (reservation.role == Role::Supervisor && view_kind != "supervisor")
            || (reservation.role != Role::Supervisor && view_kind != "ticket")
        {
            return Err("Rex view scope does not match launch Project and role".into());
        }
        if let Some(ticket_run_id) = &reservation.ticket_run_id {
            let ticket: Option<(String,String,String,u64)> = tx.query_row(
                "SELECT project_id,namespace,ticket_id,revision FROM ticket_runs WHERE ticket_run_id=?1",
                [ticket_run_id.as_str()],
                |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
            ).optional().map_err(|error| error.to_string())?;
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

        let prior: Option<(String,String)> = tx.query_row(
            "SELECT reservation_digest,reservation_json FROM agent_launch_reservations WHERE agent_run_id=?1",
            [reservation.agent_run_id.as_str()], |row| Ok((row.get(0)?,row.get(1)?)),
        ).optional().map_err(|error| error.to_string())?;
        if let Some((prior_digest, prior_json)) = prior {
            if prior_digest != reservation_digest.as_str() || prior_json != reservation_json {
                return Err("AgentRun ID was reused with a different immutable reservation".into());
            }
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(LaunchPreparationOutcome::Prepared { reservation_digest });
        }
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
                        || !submitted.host_artifacts.is_empty()
                })
        {
            return Err("wake snapshot differs from the selected current pending inputs".into());
        }
        let global_used: u32 = tx
            .query_row(
                "SELECT COUNT(*) FROM execution_slots WHERE pool=?1 AND disposition!='released'",
                [&reservation.pool],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        let project_used: u32 = tx.query_row(
            "SELECT COUNT(*) FROM execution_slots WHERE project_id=?1 AND disposition!='released'",
            [reservation.project_id.as_str()], |row| row.get(0),
        ).map_err(|error| error.to_string())?;
        let slot_occupied: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM execution_slots WHERE pool=?1 AND slot_index=?2 AND disposition!='released')",
            params![reservation.pool,reservation.slot_index], |row| row.get(0),
        ).map_err(|error| error.to_string())?;
        if global_used >= reservation.global_capacity
            || project_used >= reservation.project_capacity
            || slot_occupied
            || reservation.slot_index >= reservation.global_capacity
        {
            return Ok(LaunchPreparationOutcome::CapacityUnavailable);
        }
        let active_same_session: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM agent_runs WHERE project_id=?1 AND role_session_id=?2 AND state IN ('launch_pending','running','parked','unknown'))",
            params![reservation.project_id.as_str(),reservation.role_session_id], |row| row.get(0),
        ).map_err(|error| error.to_string())?;
        if active_same_session {
            return Ok(LaunchPreparationOutcome::CapacityUnavailable);
        }
        if let Some(parent_id) = &reservation.parent_run_id {
            let parent: Option<(String,String,String)> = tx.query_row(
                "SELECT r.project_id,r.state,a.role FROM agent_runs r JOIN agent_launch_authority a USING(agent_run_id) WHERE r.agent_run_id=?1",
                [parent_id.as_str()], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
            ).optional().map_err(|error| error.to_string())?;
            let parent_role = reservation
                .parent_role
                .and_then(|role| serde_json::to_value(role).ok()?.as_str().map(str::to_owned));
            if !matches!(parent,Some((ref p,ref s,ref r)) if p==reservation.project_id.as_str() && matches!(s.as_str(),"running"|"parked") && parent_role.as_deref()==Some(r.as_str()))
            {
                return Err(
                    "launch parent is not an active same-Project AgentRun with the expected role"
                        .into(),
                );
            }
        }

        let role = serde_json::to_value(reservation.role)
            .map_err(|error| error.to_string())?
            .as_str()
            .ok_or("Agent role did not serialize as a string")?
            .to_owned();
        tx.execute(
            "INSERT INTO agent_runs(agent_run_id,project_id,config_source,config_revision,config_digest,role_session_id,role,logical_owner,finite_turn,launch_operation_id,rex_session_id,rex_window_id,rex_block_id,process_identity_json,state,controller_generation,started_at_unix,finished_at_unix) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,NULL,NULL,NULL,NULL,'launch_pending',?11,NULL,NULL)",
            params![reservation.agent_run_id.as_str(),reservation.project_id.as_str(),config_source,reservation.config_revision.0,reservation.config_digest.as_str(),reservation.role_session_id,role,format!("role:{}",reservation.role_session_id),reservation.run_epoch,reservation.operation_id.as_str(),reservation.controller_generation],
        ).map_err(|error| error.to_string())?;
        let slot_changed = tx.execute(
            "INSERT INTO execution_slots(pool,slot_index,project_id,ticket_run_id,owner_kind,owner_id,reservation_epoch,controller_generation,process_identity_json,disposition) VALUES (?1,?2,?3,?4,'agent_run',?5,?6,?7,NULL,'launch_pending') ON CONFLICT(pool,slot_index) DO UPDATE SET project_id=excluded.project_id,ticket_run_id=excluded.ticket_run_id,owner_kind=excluded.owner_kind,owner_id=excluded.owner_id,reservation_epoch=excluded.reservation_epoch,controller_generation=excluded.controller_generation,process_identity_json=NULL,disposition='launch_pending' WHERE execution_slots.disposition='released'",
            params![reservation.pool,reservation.slot_index,reservation.project_id.as_str(),reservation.ticket_run_id.as_ref().map(|id| id.as_str()),reservation.agent_run_id.as_str(),reservation.project_epoch,reservation.controller_generation],
        ).map_err(|error| error.to_string())?;
        if slot_changed != 1 {
            return Err("execution slot is no longer available for this reservation".into());
        }
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
        let payload = StartAgentEffectPayload {
            schema_version: crate::launch::LAUNCH_SCHEMA_VERSION,
            agent_run_id: reservation.agent_run_id.clone(),
            launch_reservation_digest: reservation_digest.clone(),
        };
        let request_json = canonical_json(&payload)?;
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

    /// Read an ordered advisory snapshot; `prepare_role_launch` claims these IDs atomically.
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
        let mut statement = self.connection.prepare(
            "SELECT wake_input_id,source_type,source_id,source_revision,priority,payload_json FROM role_wake_inputs WHERE project_id=?1 AND role_session_id=?2 AND lifecycle='pending' ORDER BY priority DESC,wake_input_id ASC LIMIT ?3",
        ).map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(
                params![project_id.as_str(), role_session_id, limit as u64],
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
        rows.map(|row| {
            let (wake_input_id, source_type, source_id, source_revision, priority, payload) =
                row.map_err(|error| error.to_string())?;
            let payload_json =
                crate::protocol::parse_unique(payload.as_bytes()).map_err(|error| {
                    format!("stored wake input {wake_input_id} has invalid JSON: {error}")
                })?;
            Ok(PendingRoleWakeInput {
                wake_input_id,
                source_type,
                source_id,
                source_revision,
                priority,
                payload_json,
            })
        })
        .collect()
    }

    /// Advisory first-free slot. Reservation transactions recheck capacity and occupancy.
    pub fn available_execution_slot(
        &self,
        project_id: &ProjectId,
        pool: &str,
        global_capacity: u32,
        project_capacity: u32,
    ) -> Result<Option<u32>, String> {
        if pool.trim().is_empty() || global_capacity == 0 || project_capacity == 0 {
            return Err("execution slot query requires positive capacities and a pool".into());
        }
        let global_used: u32 = self
            .connection
            .query_row(
                "SELECT COUNT(*) FROM execution_slots WHERE pool=?1 AND disposition!='released'",
                [pool],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        let project_used: u32 = self.connection.query_row(
            "SELECT COUNT(*) FROM execution_slots WHERE project_id=?1 AND disposition!='released'", [project_id.as_str()], |row| row.get(0),
        ).map_err(|error| error.to_string())?;
        if global_used >= global_capacity || project_used >= project_capacity {
            return Ok(None);
        }
        for slot in 0..global_capacity {
            let occupied: bool = self.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM execution_slots WHERE pool=?1 AND slot_index=?2 AND disposition!='released')",
                params![pool,slot], |row| row.get(0),
            ).map_err(|error| error.to_string())?;
            if !occupied {
                return Ok(Some(slot));
            }
        }
        Ok(None)
    }

    pub fn agent_launch_reservation(
        &self,
        agent_run_id: &AgentRunId,
        expected_digest: &Digest,
    ) -> Result<Option<AgentLaunchReservation>, String> {
        let stored: Option<(String,String)> = self.connection.query_row(
            "SELECT reservation_digest,reservation_json FROM agent_launch_reservations WHERE agent_run_id=?1",
            [agent_run_id.as_str()], |row| Ok((row.get(0)?,row.get(1)?)),
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

    pub fn finalize_agent_launch_reservation(
        &mut self,
        owner_generation: u64,
        agent_run_id: &AgentRunId,
        reservation_digest: &Digest,
        authority: &AgentLaunchAuthority,
    ) -> Result<(), String> {
        authority.validate()?;
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
        let row: Option<(String,String,String)> = tx.query_row(
            "SELECT reservation_digest,reservation_json,lifecycle FROM agent_launch_reservations WHERE agent_run_id=?1",
            [agent_run_id.as_str()], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
        ).optional().map_err(|error| error.to_string())?;
        let Some((stored_digest, json, lifecycle)) = row else {
            return Err("AgentRun has no launch reservation".into());
        };
        if stored_digest != reservation_digest.as_str() {
            return Err("launch reservation digest changed before finalization".into());
        }
        let reservation: AgentLaunchReservation = crate::protocol::parse_unique(json.as_bytes())
            .map_err(|error| format!("stored launch reservation is invalid: {error}"))?;
        if reservation.digest()? != *reservation_digest
            || !authority_matches_reservation(authority, &reservation)
        {
            return Err("final authority does not preserve the immutable reservation".into());
        }
        let persisted: Option<(String,String)> = tx.query_row(
            "SELECT authority_json,authority_digest FROM agent_launch_authority WHERE agent_run_id=?1",
            [agent_run_id.as_str()], |row| Ok((row.get(0)?,row.get(1)?)),
        ).optional().map_err(|error| error.to_string())?;
        let expected_json = authority.storage_json()?;
        let expected_digest = authority.digest()?;
        if persisted.as_ref().is_none_or(|(json, digest)| {
            json != &expected_json || digest != expected_digest.as_str()
        }) {
            return Err("final launch authority is not durably registered".into());
        }
        let block: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM rex_view_blocks WHERE view_id=?1 AND block_id=?2 AND agent_run_id=?3 AND ownership='factory' AND lifecycle='active')",
            params![authority.rex_view_id.as_str(),authority.rex_block_id,agent_run_id.as_str()], |row| row.get(0),
        ).map_err(|error| error.to_string())?;
        if !block {
            return Err("final launch authority has no matching persisted active Rex block".into());
        }
        let wake_json = canonical_json(&reservation.wake_snapshot)?;
        let wake_digest = reservation.wake_snapshot.digest.clone();
        if wake_digest != authority.wake_snapshot_digest {
            return Err(
                "authority wake snapshot digest does not match the reserved snapshot".into(),
            );
        }
        tx.execute("INSERT INTO agent_wake_context(agent_run_id,snapshot_digest,snapshot_json,created_at_unix) VALUES (?1,?2,?3,?4) ON CONFLICT(agent_run_id) DO NOTHING", params![agent_run_id.as_str(),wake_digest.as_str(),wake_json,now_unix()?]).map_err(|error| error.to_string())?;
        let stored_wake: (String,String) = tx.query_row("SELECT snapshot_digest,snapshot_json FROM agent_wake_context WHERE agent_run_id=?1", [agent_run_id.as_str()], |row| Ok((row.get(0)?,row.get(1)?))).map_err(|error| error.to_string())?;
        if stored_wake != (wake_digest.as_str().to_owned(), wake_json) {
            return Err("AgentRun has a different immutable wake snapshot".into());
        }
        if lifecycle != "authorized" {
            let changed = tx.execute("UPDATE agent_launch_reservations SET lifecycle='authorized',updated_at_unix=?2 WHERE agent_run_id=?1 AND reservation_digest=?3 AND lifecycle IN ('reserved','block_created')", params![agent_run_id.as_str(),now_unix()?,reservation_digest.as_str()]).map_err(|error| error.to_string())?;
            if changed != 1 {
                return Err("launch reservation could not transition to finalized".into());
            }
        }
        tx.commit().map_err(|error| error.to_string())
    }
}

fn load_exact_wake_inputs(
    tx: &rusqlite::Transaction<'_>,
    reservation: &AgentLaunchReservation,
) -> Result<Vec<PendingRoleWakeInput>, String> {
    if reservation.wake_snapshot.inputs.len() > MAX_WAKE_SNAPSHOT_ITEMS {
        return Err("wake snapshot exceeds the 256 input limit".into());
    }
    let mut inputs = Vec::with_capacity(reservation.wake_snapshot.inputs.len());
    for selected in &reservation.wake_snapshot.inputs {
        let row: Option<(String,String,u64,i32,String)> = tx.query_row(
            "SELECT source_type,source_id,source_revision,priority,payload_json FROM role_wake_inputs WHERE wake_input_id=?1 AND project_id=?2 AND role_session_id=?3 AND lifecycle='pending'",
            params![selected.wake_input_id,reservation.project_id.as_str(),reservation.role_session_id],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)),
        ).optional().map_err(|error| error.to_string())?;
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

fn authority_matches_reservation(
    authority: &AgentLaunchAuthority,
    reservation: &AgentLaunchReservation,
) -> bool {
    authority.project_id == reservation.project_id
        && authority.role == reservation.role
        && authority.role_session_id == reservation.role_session_id
        && authority.parent_run_id == reservation.parent_run_id
        && authority.parent_role == reservation.parent_role
        && authority.ticket_run_id == reservation.ticket_run_id
        && authority.ticket_revision == reservation.ticket_revision
        && authority.config_revision == reservation.config_revision
        && authority.config_digest == reservation.config_digest
        && authority.attempt == reservation.attempt
        && authority.run_epoch == reservation.run_epoch
        && authority.controller_generation == reservation.controller_generation
        && authority.operation_id == reservation.operation_id
        && authority.operation_recipe_id == reservation.operation_recipe_id
        && authority.wake_snapshot_digest == reservation.wake_snapshot.digest
        && authority.rex_view_id == reservation.rex_view_id
        && authority.runtime_binary_digest == reservation.runtime_binary_digest
        && authority.environment_snapshot_id == reservation.environment_snapshot_id
        && authority.profile_id == reservation.profile_id
        && authority.profile_digest == reservation.profile_digest
        && authority.instruction_digest == reservation.instruction_digest
        && authority.result_schema_digest == reservation.result_schema_digest
        && authority.qualification_receipt_digest == reservation.qualification_receipt_digest
        && authority.descriptor_path == reservation.descriptor_path
        && authority.workspace_path == reservation.workspace_path
        && authority.control_dir == reservation.control_dir
        && authority.mailbox_capability_digest == reservation.mailbox_capability_digest
}

#[cfg(test)]
mod tests {
    use sha2::Digest as _;
    use std::collections::{BTreeMap, BTreeSet};

    use super::{ConfigStore, LaunchPreparationOutcome};
    use crate::config::{AppliedConfig, Profile, SourceFile, SourceKind};
    use crate::domain::ids::{AgentRunId, Digest, OperationId, ProfileId, ProjectId, Revision};
    use crate::domain::types::{AgentAdapter, CommitMode, Role};
    use crate::launch::{
        AgentLaunchAuthority, AgentLaunchReservation, AgentStartRequest, ObservedWrapperIdentity,
        ProviderQualification, QualificationProof, QualificationStatus, RexBlockLifecycle,
        RexBlockOwnership, RexView, RexViewBlock, RexViewKind,
    };
    use crate::store::{ExpectedRevision, OwnerMetadata, ProjectRecord};

    fn digest(ch: char) -> Digest {
        Digest::parse(ch.to_string().repeat(64)).unwrap()
    }

    fn applied() -> AppliedConfig {
        let config = serde_json::from_value(serde_json::json!({
            "schema_version":1,
            "adapters":{"tickets":{"kind":"command","command":["ticket-cli"]}},
            "projects":{"project-a":{"mode":"operations","ticket_adapter":"tickets","roles":{"supervisor":"supervisor","reviewer":"reviewer"}}}
        })).unwrap();
        let profile = serde_json::from_value::<Profile>(serde_json::json!({
            "adapter":"codex","command":["/usr/bin/codex"],"model":"fixture",
            "commit_mode":"native","turn_timeout_seconds":60
        }))
        .unwrap();
        AppliedConfig {
            config,
            profiles: BTreeMap::from([
                (ProfileId::parse("supervisor").unwrap(), profile.clone()),
                (ProfileId::parse("reviewer").unwrap(), profile),
            ]),
            source_root: "/tmp/config".into(),
            source_files: vec![SourceFile {
                kind: SourceKind::File,
                path: "/tmp/config/config.toml".into(),
                canonical_path: "/tmp/config/config.toml".into(),
                sha256: digest('a'),
                bytes: 1,
                contents: "fixture".into(),
            }],
            digest: digest('b'),
        }
    }

    #[test]
    fn reservation_is_durable_idempotent_and_finalizes_only_with_authority_and_active_block() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir(temp.path().join("control")).unwrap();
        std::fs::create_dir(temp.path().join("workspace")).unwrap();
        let mut store = ConfigStore::open_test(temp.path()).unwrap();
        let applied = store
            .apply_snapshot("factory", &applied(), ExpectedRevision::Bootstrap)
            .unwrap();
        let project = ProjectId::parse("project-a").unwrap();
        store
            .insert_project(&ProjectRecord {
                id: project.clone(),
                config_source: "factory".into(),
                config_revision: applied.revision,
                config_digest: digest('b'),
                mode: "operations".into(),
                goal_revision: 0,
                desired_lifecycle: "running".into(),
                state_revision: Revision(0),
            })
            .unwrap();
        let generation = store
            .start_owner(&OwnerMetadata {
                owner_nonce: "owner".into(),
                state_root: temp.path().display().to_string(),
                config_source: "factory".into(),
                process_start_identity: "owner-start".into(),
                executable_path: "/tmp/rex-projects".into(),
                executable_digest: digest('9').as_str().into(),
                rex_server_identity: None,
                rex_session_id: None,
                rex_block_id: None,
            })
            .unwrap();
        store.connection.execute("UPDATE project_runtimes SET desired_lifecycle='running',observed_lifecycle='running',controller_generation=?2 WHERE project_id=?1",rusqlite::params![project.as_str(),generation]).unwrap();
        store
            .connection
            .execute(
                "UPDATE projects SET desired_lifecycle='running' WHERE project_id=?1",
                [project.as_str()],
            )
            .unwrap();

        let view = RexView {
            view_id: RexView::derive_id(&project, RexViewKind::Supervisor, None, None, 1).unwrap(),
            project_id: project.clone(),
            kind: RexViewKind::Supervisor,
            ticket_namespace: None,
            ticket_id: None,
            view_epoch: 1,
            rex_server_identity: "rex-fixture".into(),
            rex_session_id: "session".into(),
            rex_window_id: "window".into(),
        };
        store.register_rex_view(generation, &view).unwrap();
        let markers = [
            "REX_PROJECTS_AGENT",
            "REX_PROJECTS_CONTEXT",
            "REX_PROJECTS_PROJECT_ID",
            "REX_PROJECTS_ROLE",
            "REX_PROJECTS_RUN_ID",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
        let profile_id = ProfileId::parse("supervisor").unwrap();
        let profile_digest = Digest::parse(format!(
            "{:x}",
            sha2::Sha256::digest(
                crate::store::canonical_json(
                    store
                        .load_snapshot("factory")
                        .unwrap()
                        .unwrap()
                        .config
                        .profiles
                        .get(&profile_id)
                        .unwrap()
                )
                .unwrap()
                .as_bytes()
            )
        ))
        .unwrap();
        let qualification = ProviderQualification {
            schema_version: 1,
            project_id: project.clone(),
            profile_id: profile_id.clone(),
            profile_digest: profile_digest.clone(),
            adapter: AgentAdapter::Codex,
            executable_path: "/usr/bin/codex".into(),
            executable_digest: digest('c'),
            provider_version: "fixture-1".into(),
            permission_mode: "workspace_write".into(),
            invocation_options_digest: digest('d'),
            commit_mode: CommitMode::Native,
            proof: QualificationProof {
                schema_version: 1,
                probe_id: "probe-a".into(),
                fixture_digest: digest('e'),
                rex_instance_id: "rex-fixture".into(),
                tool_shell_marker_digest: digest('f'),
                tool_shell_markers_present: markers.clone(),
                descendant_marker_digest: digest('1'),
                descendant_markers_present: markers,
                automatic_turn_result_digest: digest('2'),
                automatic_turn_completed: true,
                structured_result_valid: true,
                observed_permission_mode: "workspace_write".into(),
                permission_prompt_count: 0,
                cleanup_process_tree_digest: digest('3'),
                process_tree_absent: true,
                cleanup_confirmed: true,
            },
            status: QualificationStatus::Verified,
        };
        let qualification_digest = store
            .store_provider_qualification(generation, &qualification)
            .unwrap();
        let run_id = AgentRunId::parse("run-1").unwrap();
        let wake_snapshot = crate::agent_api::AgentWakeSnapshot {
            schema_version: 1,
            project_id: project.clone(),
            role_session_id: "project:project-a:supervisor".into(),
            agent_run_id: run_id.as_str().into(),
            digest: digest('0'),
            inputs: vec![],
        };
        let mut wake_snapshot = wake_snapshot;
        wake_snapshot.digest = wake_snapshot.content_digest().unwrap();
        let reservation = AgentLaunchReservation {
            schema_version: crate::launch::LAUNCH_SCHEMA_VERSION,
            agent_run_id: run_id.clone(),
            project_id: project.clone(),
            role: Role::Supervisor,
            role_session_id: "project:project-a:supervisor".into(),
            parent_run_id: None,
            parent_role: None,
            ticket_run_id: None,
            ticket_revision: None,
            config_revision: applied.revision,
            config_digest: digest('b'),
            attempt: 1,
            run_epoch: 1,
            controller_generation: generation,
            project_epoch: 1,
            operation_id: OperationId::parse("op-run-1").unwrap(),
            operation_recipe_id: None,
            worker_assignment: None,
            rex_view_id: view.view_id.clone(),
            runtime_binary_digest: digest('4'),
            environment_snapshot_id: digest('5'),
            profile_id,
            profile_digest,
            instruction_digest: digest('6'),
            result_schema_digest: digest('7'),
            wake_snapshot,
            qualification_receipt_digest: qualification_digest,
            descriptor_path: temp.path().join("run-1.json"),
            workspace_path: temp.path().join("workspace"),
            control_dir: temp.path().join("control"),
            mailbox_directory: temp.path().join("control"),
            mailbox_capability_digest: digest('8'),
            mailbox_expires_at_unix: (crate::store::now_unix().unwrap() + 86_400) as u64,
            mailbox_max_request_bytes: 1_048_576,
            mailbox_max_pending_requests: 32,
            pool: "agent".into(),
            slot_index: 0,
            global_capacity: 1,
            project_capacity: 1,
        };

        // A real reservation with a database-backed Planner parent must not accept the
        // impossible Reviewer -> Planner edge or leave any durable launch side effects.
        let child_ticket_run_id = crate::domain::ids::TicketRunId::parse("ticket-child").unwrap();
        store.connection.execute(
            "INSERT INTO ticket_runs(ticket_run_id,project_id,config_source,config_revision,config_digest,namespace,ticket_id,generation,internal_phase,activity,external_status,observed_status) VALUES (?1,?2,'factory',?3,?4,'shared','T-2',1,'queued','working','In Progress','In Progress')",
            rusqlite::params![child_ticket_run_id.as_str(), project.as_str(), applied.revision.0, digest('b').as_str()],
        ).unwrap();
        let child_view = RexView {
            view_id: RexView::derive_id(
                &project,
                RexViewKind::Ticket,
                Some("shared"),
                Some("T-2"),
                1,
            )
            .unwrap(),
            project_id: project.clone(),
            kind: RexViewKind::Ticket,
            ticket_namespace: Some("shared".into()),
            ticket_id: Some("T-2".into()),
            view_epoch: 1,
            rex_server_identity: "rex-fixture".into(),
            rex_session_id: "session".into(),
            rex_window_id: "window".into(),
        };
        store.register_rex_view(generation, &child_view).unwrap();
        let reviewer_profile_id = ProfileId::parse("reviewer").unwrap();
        let mut reviewer_qualification = qualification.clone();
        reviewer_qualification.profile_id = reviewer_profile_id.clone();
        let reviewer_qualification_digest = store
            .store_provider_qualification(generation, &reviewer_qualification)
            .unwrap();
        let parent_id = AgentRunId::parse("planner-parent").unwrap();
        let parent_operation = OperationId::parse("op-planner-parent").unwrap();
        store.connection.execute(
            "INSERT INTO agent_runs(agent_run_id,project_id,config_source,config_revision,config_digest,role_session_id,logical_owner,finite_turn,launch_operation_id,state,controller_generation) VALUES (?1,?2,'factory',?3,?4,'planner-parent-session','factory',1,?5,'running',?6)",
            rusqlite::params![parent_id.as_str(), project.as_str(), applied.revision.0, digest('b').as_str(), parent_operation.as_str(), generation],
        ).unwrap();
        store.connection.execute(
            "INSERT INTO agent_launch_authority(agent_run_id,project_id,role,role_session_id,ticket_run_id,ticket_revision,config_revision,config_digest,attempt,run_epoch,controller_generation,launch_operation_id,rex_view_id,descriptor_digest,runtime_binary_digest,descriptor_path,environment_snapshot_id,profile_id,profile_digest,instruction_digest,result_schema_digest,qualification_receipt_digest,rex_server_identity,rex_session_id,rex_window_id,rex_block_id,workspace_path,control_dir,mailbox_capability_digest,authority_json,authority_digest,created_at_unix) VALUES (?1,?2,'planner','planner-parent-session',?3,0,?4,?5,1,1,?6,?7,?8,?9,?10,'/state/parent.json',?11,'reviewer',?12,?13,?14,?15,'rex-fixture','session','window','parent-block','/state/workspace','/state/control',?16,'{}',?17,0)",
            rusqlite::params![parent_id.as_str(), project.as_str(), child_ticket_run_id.as_str(), applied.revision.0, digest('b').as_str(), generation, parent_operation.as_str(), child_view.view_id.as_str(), digest('a').as_str(), digest('4').as_str(), digest('5').as_str(), digest('6').as_str(), digest('7').as_str(), digest('8').as_str(), reviewer_qualification_digest.as_str(), digest('9').as_str(), digest('0').as_str()],
        ).unwrap();
        let child_run_id = AgentRunId::parse("reviewer-child").unwrap();
        let child_operation = OperationId::parse("op-reviewer-child").unwrap();
        let child_session_id = "ticket:project-a:T-2:reviewer";
        store.connection.execute(
            "INSERT INTO role_wake_inputs(project_id,role_session_id,source_type,source_id,source_revision,priority,payload_json,lifecycle,created_at_unix) VALUES (?1,?2,'human','wake-child',1,10,'{}','pending',0)",
            rusqlite::params![project.as_str(), child_session_id],
        ).unwrap();
        let mut impossible_child = reservation.clone();
        impossible_child.agent_run_id = child_run_id.clone();
        impossible_child.role = Role::Reviewer;
        impossible_child.role_session_id = child_session_id.into();
        impossible_child.parent_run_id = Some(parent_id.clone());
        impossible_child.parent_role = Some(Role::Planner);
        impossible_child.ticket_run_id = Some(child_ticket_run_id);
        impossible_child.ticket_revision = Some(Revision(0));
        impossible_child.operation_id = child_operation;
        impossible_child.profile_id = reviewer_profile_id;
        impossible_child.qualification_receipt_digest = reviewer_qualification_digest;
        impossible_child.rex_view_id = child_view.view_id;
        impossible_child.slot_index = 0;
        impossible_child.wake_snapshot.role_session_id = child_session_id.into();
        impossible_child.wake_snapshot.agent_run_id = child_run_id.as_str().into();
        impossible_child.wake_snapshot.inputs = vec![crate::agent_api::AgentWakeItem {
            wake_input_id: store
                .connection
                .query_row(
                    "SELECT wake_input_id FROM role_wake_inputs WHERE source_id='wake-child'",
                    [],
                    |row| row.get(0),
                )
                .unwrap(),
            source_type: "human".into(),
            source_id: "wake-child".into(),
            source_revision: 1,
            priority: 10,
            payload_json: serde_json::json!({}),
            host_artifacts: vec![],
        }];
        impossible_child.wake_snapshot.digest =
            impossible_child.wake_snapshot.content_digest().unwrap();
        let before = store
            .connection
            .query_row(
                "SELECT (SELECT COUNT(*) FROM agent_runs),(SELECT COUNT(*) FROM execution_slots),(SELECT COUNT(*) FROM effects WHERE kind='start_agent'),(SELECT COUNT(*) FROM agent_launch_reservations),(SELECT COUNT(*) FROM agent_mailboxes)",
                [],
                |row| Ok((row.get::<_, u64>(0)?, row.get::<_, u64>(1)?, row.get::<_, u64>(2)?, row.get::<_, u64>(3)?, row.get::<_, u64>(4)?)),
            )
            .unwrap();
        let wake_before: (String, Option<String>, String) = store
            .connection
            .query_row(
                "SELECT lifecycle,consuming_agent_run_id,payload_json FROM role_wake_inputs WHERE source_id='wake-child'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert!(
            store
                .prepare_role_launch(&impossible_child)
                .unwrap_err()
                .contains("parent role")
        );
        let after = store
            .connection
            .query_row(
                "SELECT (SELECT COUNT(*) FROM agent_runs),(SELECT COUNT(*) FROM execution_slots),(SELECT COUNT(*) FROM effects WHERE kind='start_agent'),(SELECT COUNT(*) FROM agent_launch_reservations),(SELECT COUNT(*) FROM agent_mailboxes)",
                [],
                |row| Ok((row.get::<_, u64>(0)?, row.get::<_, u64>(1)?, row.get::<_, u64>(2)?, row.get::<_, u64>(3)?, row.get::<_, u64>(4)?)),
            )
            .unwrap();
        assert_eq!(after, before);
        let wake_after: (String, Option<String>, String) = store
            .connection
            .query_row(
                "SELECT lifecycle,consuming_agent_run_id,payload_json FROM role_wake_inputs WHERE source_id='wake-child'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(wake_after, wake_before);

        let reservation_digest = reservation.digest().unwrap();
        let mut unsupported_worker = reservation.clone();
        unsupported_worker.role = Role::Worker;
        assert!(
            store
                .prepare_role_launch(&unsupported_worker)
                .unwrap_err()
                .contains("opaque accepted-plan")
        );
        assert!(matches!(
            store.prepare_role_launch(&reservation).unwrap(),
            LaunchPreparationOutcome::Prepared { .. }
        ));
        assert!(matches!(
            store.prepare_role_launch(&reservation).unwrap(),
            LaunchPreparationOutcome::Prepared { .. }
        ));
        let effect_count: u64 = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM effects WHERE kind='start_agent'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(effect_count, 1);
        drop(store);
        let mut store = ConfigStore::open_test(temp.path()).unwrap();
        assert_eq!(
            store
                .agent_launch_reservation(&run_id, &reservation_digest)
                .unwrap(),
            Some(reservation.clone())
        );
        let mut substituted_digest = reservation_digest.as_str().to_owned();
        let replacement = if &substituted_digest[..1] == "0" {
            "1"
        } else {
            "0"
        };
        substituted_digest.replace_range(0..1, replacement);
        assert!(
            store
                .agent_launch_reservation(&run_id, &Digest::parse(substituted_digest).unwrap())
                .unwrap_err()
                .contains("does not match")
        );
        assert_eq!(
            store.prepare_role_launch(&reservation).unwrap(),
            LaunchPreparationOutcome::Prepared {
                reservation_digest: reservation_digest.clone()
            }
        );
        let effect_count: u64 = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM effects WHERE kind='start_agent'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(effect_count, 1);

        let authority = AgentLaunchAuthority {
            agent_run_id: run_id.clone(),
            project_id: project,
            role: Role::Supervisor,
            role_session_id: reservation.role_session_id.clone(),
            parent_run_id: None,
            parent_role: None,
            ticket_run_id: None,
            ticket_revision: None,
            config_revision: reservation.config_revision,
            config_digest: reservation.config_digest.clone(),
            attempt: reservation.attempt,
            run_epoch: reservation.run_epoch,
            controller_generation: generation,
            operation_id: reservation.operation_id.clone(),
            operation_recipe_id: None,
            rex_view_id: view.view_id.clone(),
            descriptor_digest: digest('a'),
            runtime_binary_digest: reservation.runtime_binary_digest.clone(),
            descriptor_path: reservation.descriptor_path.clone(),
            environment_snapshot_id: reservation.environment_snapshot_id.clone(),
            profile_id: reservation.profile_id.clone(),
            profile_digest: reservation.profile_digest.clone(),
            instruction_digest: reservation.instruction_digest.clone(),
            result_schema_digest: reservation.result_schema_digest.clone(),
            wake_snapshot_digest: reservation.wake_snapshot.digest.clone(),
            qualification_receipt_digest: reservation.qualification_receipt_digest.clone(),
            rex_server_identity: "rex-fixture".into(),
            rex_session_id: "session".into(),
            rex_window_id: "window".into(),
            rex_block_id: "block-1".into(),
            workspace_path: reservation.workspace_path.clone(),
            control_dir: reservation.control_dir.clone(),
            mailbox_capability_digest: reservation.mailbox_capability_digest.clone(),
        };
        store
            .register_agent_launch_authority(generation, &authority)
            .unwrap();
        let request = AgentStartRequest {
            schema_version: 1,
            operation_id: reservation.operation_id.clone(),
            agent_run_id: run_id.clone(),
            project_id: reservation.project_id.clone(),
            controller_generation: generation,
            descriptor_digest: authority.descriptor_digest.clone(),
            runtime_binary_digest: authority.runtime_binary_digest.clone(),
            environment_snapshot_id: authority.environment_snapshot_id.clone(),
            qualification_receipt_digest: authority.qualification_receipt_digest.clone(),
            wrapper_pid: std::process::id(),
            wrapper_start_identity: "wrapper-start".into(),
            rex_session_id: authority.rex_session_id.clone(),
            rex_block_id: authority.rex_block_id.clone(),
        };
        let observed = ObservedWrapperIdentity {
            pid: request.wrapper_pid,
            start_identity: request.wrapper_start_identity.clone(),
            rex_session_id: request.rex_session_id.clone(),
            rex_block_id: request.rex_block_id.clone(),
            runtime_binary_digest: request.runtime_binary_digest.clone(),
        };
        assert!(
            store
                .authorize_agent_start(generation, &request, &observed)
                .unwrap_err()
                .contains("not been finalized")
        );
        store
            .register_rex_view_block(
                generation,
                &RexViewBlock {
                    view_id: view.view_id.clone(),
                    block_id: "wrong-block".into(),
                    agent_run_id: Some(run_id.clone()),
                    role: Some(Role::Supervisor),
                    ownership: RexBlockOwnership::Factory,
                    lifecycle: RexBlockLifecycle::Active,
                    process_absent_confirmed: false,
                    retained_until_unix: None,
                },
            )
            .unwrap();
        assert!(
            store
                .finalize_agent_launch_reservation(
                    generation,
                    &run_id,
                    &reservation_digest,
                    &authority
                )
                .unwrap_err()
                .contains("no matching persisted active Rex block")
        );
        store
            .register_rex_view_block(
                generation,
                &RexViewBlock {
                    view_id: view.view_id,
                    block_id: "block-1".into(),
                    agent_run_id: Some(run_id.clone()),
                    role: Some(Role::Supervisor),
                    ownership: RexBlockOwnership::Factory,
                    lifecycle: RexBlockLifecycle::Active,
                    process_absent_confirmed: false,
                    retained_until_unix: None,
                },
            )
            .unwrap();
        assert!(
            store
                .authorize_agent_start(generation, &request, &observed)
                .unwrap_err()
                .contains("not been finalized")
        );
        store
            .finalize_agent_launch_reservation(generation, &run_id, &reservation_digest, &authority)
            .unwrap();
        store
            .finalize_agent_launch_reservation(generation, &run_id, &reservation_digest, &authority)
            .unwrap();
        let mut wrong_rex_request = request.clone();
        wrong_rex_request.rex_block_id = "substituted-block".into();
        let wrong_rex_observation = ObservedWrapperIdentity {
            rex_block_id: wrong_rex_request.rex_block_id.clone(),
            ..observed.clone()
        };
        assert!(
            store
                .authorize_agent_start(generation, &wrong_rex_request, &wrong_rex_observation)
                .is_err()
        );
        let wrong_pid_observation = ObservedWrapperIdentity {
            pid: request.wrapper_pid + 1,
            ..observed.clone()
        };
        assert!(
            store
                .authorize_agent_start(generation, &request, &wrong_pid_observation)
                .is_err()
        );
        assert_eq!(
            store
                .authorize_agent_start(generation, &request, &observed)
                .unwrap()
                .decision,
            crate::launch::LaunchDecision::Accepted
        );
        assert_eq!(
            store
                .authorize_agent_start(generation, &request, &observed)
                .unwrap()
                .decision,
            crate::launch::LaunchDecision::Accepted
        );
        let lifecycle: String = store
            .connection
            .query_row(
                "SELECT lifecycle FROM agent_launch_reservations WHERE agent_run_id='run-1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(lifecycle, "authorized");
        let wake_context: String = store
            .connection
            .query_row(
                "SELECT snapshot_json FROM agent_wake_context WHERE agent_run_id='run-1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            wake_context,
            crate::store::canonical_json(&reservation.wake_snapshot).unwrap()
        );
    }

    #[test]
    fn v7_database_migrates_reservation_tables_and_authority_columns() {
        let temp = tempfile::tempdir().unwrap();
        let store = ConfigStore::open_test(temp.path()).unwrap();
        store
            .connection
            .execute_batch(
                "DROP INDEX agent_launch_reservations_project;
             DROP TRIGGER agent_launch_reservation_identity_guard;
             DROP TRIGGER agent_launch_reservation_no_delete;
             DROP TRIGGER agent_wake_context_immutable_update;
             DROP TRIGGER agent_wake_context_immutable_delete;
             DROP TABLE agent_launch_reservations;
             DROP TABLE agent_wake_context;
             ALTER TABLE agent_launch_authority DROP COLUMN operation_recipe_id;
             ALTER TABLE agent_launch_authority DROP COLUMN wake_snapshot_digest;
             DELETE FROM schema_migrations WHERE version=8;
             PRAGMA user_version=7;",
            )
            .unwrap();
        drop(store);

        let store = ConfigStore::open_test(temp.path()).unwrap();
        let version: i64 = store
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, 8);
        let tables: u64 = store.connection.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('agent_launch_reservations','agent_wake_context')",
            [], |row| row.get(0),
        ).unwrap();
        assert_eq!(tables, 2);
        let added_authority_columns: u64 = store.connection.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('agent_launch_authority') WHERE name IN ('operation_recipe_id','wake_snapshot_digest')",
            [], |row| row.get(0),
        ).unwrap();
        assert_eq!(added_authority_columns, 2);
    }
}
