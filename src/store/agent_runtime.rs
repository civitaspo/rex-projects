//! Host-side queries and state transitions for finite role Agent turns.

use rusqlite::{OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::domain::ids::{Digest, ProjectId};
use crate::domain::types::Role;
use crate::launch::{AgentLaunchReservation, StartAgentEffectPayload};
use crate::store::{EffectIntent, insert_effect, now_unix, validate_active_generation};

const MAX_WAKE_SNAPSHOT_ITEMS: usize = 256;
const MAX_PROFILE_QUALIFICATION_CANDIDATES: usize = 32;

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
    /// Suggest the first currently free agent slot without claiming it. The launch
    /// reservation transaction remains authoritative and rechecks the slot atomically.
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
            "SELECT COUNT(*) FROM execution_slots WHERE project_id=?1 AND disposition!='released'",
            [project_id.as_str()],
            |row| row.get(0),
        ).map_err(|error| error.to_string())?;
        if global_used >= global_capacity || project_used >= project_capacity {
            return Ok(None);
        }
        let mut statement = self
            .connection
            .prepare(
                "SELECT slot_index FROM execution_slots WHERE pool=?1 AND disposition!='released'",
            )
            .map_err(|error| error.to_string())?;
        let used = statement
            .query_map([pool], |row| row.get::<_, u32>(0))
            .map_err(|error| error.to_string())?
            .collect::<Result<std::collections::BTreeSet<_>, _>>()
            .map_err(|error| error.to_string())?;
        Ok((0..global_capacity).find(|slot| !used.contains(slot)))
    }

    /// Return bounded verified provider qualifications for one exact applied profile.
    /// Callers must still compare the executable and invocation identity to the live profile.
    pub fn verified_provider_qualifications(
        &self,
        project_id: &ProjectId,
        profile_id: &crate::domain::ids::ProfileId,
        profile_digest: &Digest,
        limit: usize,
    ) -> Result<Vec<crate::launch::ProviderQualification>, String> {
        if limit == 0 || limit > MAX_PROFILE_QUALIFICATION_CANDIDATES {
            return Err(format!(
                "qualification candidate limit must be between 1 and {MAX_PROFILE_QUALIFICATION_CANDIDATES}"
            ));
        }
        let mut statement = self
            .connection
            .prepare(
                "SELECT receipt_digest,receipt_json FROM provider_qualifications \
             WHERE project_id=?1 AND profile_id=?2 AND profile_digest=?3 AND status='verified' \
             ORDER BY created_at_unix DESC,receipt_digest ASC LIMIT ?4",
            )
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(
                rusqlite::params![
                    project_id.as_str(),
                    profile_id.as_str(),
                    profile_digest.as_str(),
                    limit as u64
                ],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .map_err(|error| error.to_string())?;
        let mut qualifications = Vec::new();
        for row in rows {
            let (stored_digest, json) = row.map_err(|error| error.to_string())?;
            let qualification: crate::launch::ProviderQualification =
                crate::protocol::parse_unique(json.as_bytes()).map_err(|error| {
                    format!("stored provider qualification is invalid: {error}")
                })?;
            if qualification.canonical_digest()?.as_str() != stored_digest
                || qualification.project_id != *project_id
                || qualification.profile_id != *profile_id
                || qualification.profile_digest != *profile_digest
                || qualification.status != crate::launch::QualificationStatus::Verified
            {
                return Err(
                    "provider qualification row does not match its exact query scope".into(),
                );
            }
            qualification.validate_for_unattended_launch()?;
            qualifications.push(qualification);
        }
        Ok(qualifications)
    }

    /// Return a previously committed exact start ACK for an identical request. This is the
    /// crash-recovery path after the wrapper consumed its one-use environment and the provider
    /// has already exited; it never authorizes a new request.
    pub fn persisted_start_receipt(
        &self,
        request: &crate::launch::AgentStartRequest,
    ) -> Result<Option<crate::launch::AgentLaunchReceipt>, String> {
        request.validate()?;
        let request_json = serde_json::to_string(request).map_err(|error| error.to_string())?;
        let request_digest =
            Digest::parse(format!("{:x}", Sha256::digest(request_json.as_bytes())))?;
        let stored: Option<(String, String)> = self
            .connection
            .query_row(
                "SELECT start_request_digest,launch_receipt_json FROM agent_launch_state WHERE agent_run_id=?1",
                [request.agent_run_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let Some((stored_digest, receipt_json)) = stored else {
            return Ok(None);
        };
        if stored_digest != request_digest.as_str() {
            return Err("AgentRun already has a different committed start request".into());
        }
        let receipt: crate::launch::AgentLaunchReceipt =
            crate::protocol::parse_unique(receipt_json.as_bytes())
                .map_err(|error| format!("stored Agent launch receipt is invalid: {error}"))?;
        receipt.validate_for(request)?;
        Ok(Some(receipt))
    }

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
            || authority.attempt != reservation.attempt
            || authority.run_epoch != reservation.run_epoch
            || authority.controller_generation != reservation.controller_generation
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
        type ViewScope = (
            String,
            String,
            String,
            String,
            String,
            Option<String>,
            Option<String>,
        );
        let view: Option<ViewScope> = tx
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
            let expected_parent_role = reservation.parent_role.and_then(|role| {
                serde_json::to_value(role)
                    .ok()
                    .and_then(|value| value.as_str().map(str::to_owned))
            });
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
        let slot_changed = tx.execute(
            "INSERT INTO execution_slots(pool,slot_index,project_id,ticket_run_id,owner_kind,owner_id,reservation_epoch,controller_generation,process_identity_json,disposition) VALUES (?1,?2,?3,?4,'agent_run',?5,?6,?7,NULL,'launch_pending') ON CONFLICT(pool,slot_index) DO UPDATE SET project_id=excluded.project_id,ticket_run_id=excluded.ticket_run_id,owner_kind=excluded.owner_kind,owner_id=excluded.owner_id,reservation_epoch=excluded.reservation_epoch,controller_generation=excluded.controller_generation,process_identity_json=NULL,disposition='launch_pending' WHERE execution_slots.disposition='released'",
            params![reservation.pool,reservation.slot_index,reservation.project_id.as_str(),ticket_run_id,reservation.agent_run_id.as_str(),reservation.project_epoch,reservation.controller_generation],
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

#[cfg(test)]
mod tests {
    use sha2::Digest as _;
    use std::collections::{BTreeMap, BTreeSet};

    use super::{ConfigStore, LaunchPreparationOutcome};
    use crate::config::{AppliedConfig, Profile, SourceFile, SourceKind};
    use crate::domain::ids::{AgentRunId, Digest, OperationId, ProfileId, ProjectId, Revision};
    use crate::domain::types::{AgentAdapter, CommitMode, Role};
    use crate::launch::{
        AgentLaunchReservation, LAUNCH_SCHEMA_VERSION, ProviderQualification, QualificationProof,
        QualificationStatus, RexView, RexViewKind,
    };
    use crate::store::{ExpectedRevision, OwnerMetadata, ProjectRecord};

    fn digest(ch: char) -> Digest {
        Digest::parse(ch.to_string().repeat(64)).unwrap()
    }

    fn applied() -> AppliedConfig {
        let config = serde_json::from_value(serde_json::json!({
            "schema_version": 1,
            "adapters": { "tickets": {
                "kind":"command", "command":["ticket-cli"],
                "status_values": {"triage":"Triage","backlog":"Backlog","ready":"Ready","in_progress":"In Progress","in_review":"In Review","done":"Done","canceled":"Canceled"}
            }},
            "projects": { "project-a": {
                "mode":"operations", "ticket_adapter":"tickets",
                "roles":{"supervisor":"supervisor"}
            }}
        })).unwrap();
        let profile: Profile = serde_json::from_value(serde_json::json!({
            "adapter":"codex", "command":["/usr/bin/codex"], "model":"fixture",
            "commit_mode":"native", "turn_timeout_seconds":60
        }))
        .unwrap();
        AppliedConfig {
            config,
            profiles: BTreeMap::from([(ProfileId::parse("supervisor").unwrap(), profile)]),
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

    fn qualification() -> ProviderQualification {
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
        ProviderQualification {
            schema_version: 1,
            project_id: ProjectId::parse("project-a").unwrap(),
            profile_id: ProfileId::parse("supervisor").unwrap(),
            profile_digest: Digest::parse(format!(
                "{:x}",
                sha2::Sha256::digest(
                    crate::store::canonical_json(
                        applied()
                            .profiles
                            .get(&ProfileId::parse("supervisor").unwrap())
                            .unwrap()
                    )
                    .unwrap()
                    .as_bytes()
                )
            ))
            .unwrap(),
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
        }
    }

    #[test]
    fn reserved_start_is_idempotent_after_wakes_are_assigned_and_store_reopens() {
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
            view_id: crate::launch::RexView::derive_id(
                &project,
                RexViewKind::Supervisor,
                None,
                None,
                1,
            )
            .unwrap(),
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
        let qualification = qualification();
        let q_digest = store
            .store_provider_qualification(generation, &qualification)
            .unwrap();
        let qualifications = store
            .verified_provider_qualifications(
                &project,
                &qualification.profile_id,
                &qualification.profile_digest,
                4,
            )
            .unwrap();
        assert_eq!(qualifications, vec![qualification.clone()]);
        assert!(
            store
                .verified_provider_qualifications(
                    &project,
                    &qualification.profile_id,
                    &qualification.profile_digest,
                    MAX_PROFILE_QUALIFICATION_CANDIDATES + 1,
                )
                .is_err()
        );
        store.connection.execute(
            "INSERT INTO role_wake_inputs(project_id,role_session_id,source_type,source_id,source_revision,priority,payload_json,lifecycle,created_at_unix) VALUES (?1,'project:project-a:supervisor','test','event-1',1,10,'{\"kind\":\"start\"}','pending',1)",
            [project.as_str()],
        ).unwrap();
        let run_id = AgentRunId::parse("run-1").unwrap();
        let wake = crate::agent_api::AgentWakeItem {
            wake_input_id: 1,
            source_type: "test".into(),
            source_id: "event-1".into(),
            source_revision: 1,
            priority: 10,
            payload_json: serde_json::json!({"kind":"start"}),
        };
        let mut wake_snapshot = crate::agent_api::AgentWakeSnapshot {
            schema_version: 1,
            project_id: project.clone(),
            role_session_id: "project:project-a:supervisor".into(),
            agent_run_id: run_id.as_str().into(),
            digest: digest('0'),
            inputs: vec![wake],
        };
        wake_snapshot.digest = wake_snapshot.content_digest().unwrap();
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
        let reservation = AgentLaunchReservation {
            schema_version: LAUNCH_SCHEMA_VERSION,
            agent_run_id: run_id,
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
            rex_view_id: view.view_id.clone(),
            runtime_binary_digest: digest('4'),
            environment_snapshot_id: digest('5'),
            profile_id,
            profile_digest,
            instruction_digest: digest('6'),
            result_schema_digest: digest('7'),
            wake_snapshot,
            qualification_receipt_digest: q_digest,
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
        let runtime_state: (String, String, u64, String, u64, String) = store.connection.query_row(
            "SELECT p.desired_lifecycle,r.observed_lifecycle,r.project_epoch,p.config_digest,p.config_revision,p.mode FROM projects p JOIN project_runtimes r USING(project_id) WHERE p.project_id='project-a'",
            [], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?))
        ).unwrap();
        assert_eq!(
            runtime_state,
            (
                "running".into(),
                "running".into(),
                1,
                digest('b').as_str().into(),
                1,
                "operations".into()
            )
        );
        assert!(matches!(
            store.prepare_role_launch(&reservation).unwrap(),
            LaunchPreparationOutcome::Prepared { .. }
        ));
        assert!(matches!(
            store.prepare_role_launch(&reservation).unwrap(),
            LaunchPreparationOutcome::Prepared { .. }
        ));
        drop(store);
        let mut reopened = ConfigStore::open_test(temp.path()).unwrap();
        assert!(matches!(
            reopened.prepare_role_launch(&reservation).unwrap(),
            LaunchPreparationOutcome::Prepared { .. }
        ));
        reopened
            .connection
            .execute(
                "UPDATE execution_slots SET disposition='released' WHERE owner_id='run-1'",
                [],
            )
            .unwrap();
        reopened
            .connection
            .execute(
                "UPDATE agent_runs SET state='completed' WHERE agent_run_id='run-1'",
                [],
            )
            .unwrap();
        reopened.connection.execute(
            "INSERT INTO role_wake_inputs(project_id,role_session_id,source_type,source_id,source_revision,priority,payload_json,lifecycle,created_at_unix) VALUES (?1,'project:project-a:supervisor','test','event-2',1,10,'{\"kind\":\"start\"}','pending',2)",
            [project.as_str()],
        ).unwrap();
        let mut next = reservation.clone();
        next.agent_run_id = AgentRunId::parse("run-2").unwrap();
        next.run_epoch = 2;
        next.operation_id = OperationId::parse("op-run-2").unwrap();
        next.wake_snapshot.agent_run_id = next.agent_run_id.as_str().into();
        next.wake_snapshot.inputs[0].wake_input_id = 2;
        next.wake_snapshot.inputs[0].source_id = "event-2".into();
        next.wake_snapshot.digest = next.wake_snapshot.content_digest().unwrap();
        assert!(matches!(
            reopened.prepare_role_launch(&next).unwrap(),
            LaunchPreparationOutcome::Prepared { .. }
        ));
        let slot_owner: String = reopened
            .connection
            .query_row(
                "SELECT owner_id FROM execution_slots WHERE pool='agent' AND slot_index=0",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(slot_owner, "run-2");
    }
}
