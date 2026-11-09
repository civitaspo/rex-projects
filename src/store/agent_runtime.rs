//! Host-side queries and state transitions for finite role Agent turns.

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::domain::ids::{Digest, ProjectId};
use crate::domain::types::Role;
use crate::launch::{AgentLaunchReservation, StartAgentEffectPayload};
use crate::store::{EffectIntent, insert_effect, now_unix, validate_active_generation};

const MAX_WAKE_SNAPSHOT_ITEMS: usize = 256;
const MAX_WAKE_SNAPSHOT_JSON_BYTES: usize = 1_048_576;
const MAX_WAKE_CONTEXT_MIGRATION_ROWS: usize = 65_536;
const MAX_WAKE_CONTEXT_MIGRATION_BYTES: usize = 64 * 1024 * 1024;
const MAX_PROFILE_QUALIFICATION_CANDIDATES: usize = 32;

type ParentAuthorityScopeRow = (String, String, String, String, Option<String>, u64, String);

pub(crate) fn validate_project_launch_identity(
    connection: &Connection,
    project_id: &ProjectId,
    expected_epoch: u64,
    expected_revision: u64,
    expected_digest: &Digest,
) -> Result<(), String> {
    let current: Option<(u64, String, u64, String, String)> = connection.query_row(
        "SELECT r.project_epoch,p.config_digest,p.config_revision,p.desired_lifecycle,r.observed_lifecycle FROM projects p JOIN project_runtimes r USING(project_id) WHERE p.project_id=?1",
        [project_id.as_str()], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)),
    ).optional().map_err(|error| error.to_string())?;
    let Some((epoch, digest, revision, desired, observed)) = current else {
        return Err("launch Project no longer exists".into());
    };
    if desired != "running"
        || !matches!(observed.as_str(), "running" | "starting")
        || epoch != expected_epoch
    {
        return Err("Project lifecycle or epoch changed".into());
    }
    if revision != expected_revision || digest != expected_digest.as_str() {
        return Err("Project config changed".into());
    }
    Ok(())
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LegacyWakeSnapshot {
    project_id: ProjectId,
    role_session_id: String,
    agent_run_id: String,
    inputs: Vec<LegacyWakeInput>,
    digest: Digest,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LegacyWakeInput {
    wake_input_id: u64,
    source_type: String,
    source_id: String,
    source_revision: u64,
    priority: i64,
    payload_json: String,
}

/// Reconcile the v9 scheduler wake table with the canonical PR3 launch projection.
/// Legacy rows are strictly verified and converted in a bounded buffer before the old
/// table is replaced, so malformed data leaves the transaction's original table intact.
pub(crate) fn migrate_v12_agent_wake_context(tx: &Transaction<'_>) -> Result<(), String> {
    let table_exists: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='agent_wake_context')",
            [],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    if !table_exists {
        create_agent_wake_context_table(tx, "agent_wake_context")?;
        create_agent_wake_context_triggers(tx)?;
        return Ok(());
    }
    let mut statement = tx
        .prepare("SELECT name FROM pragma_table_info('agent_wake_context') ORDER BY cid")
        .map_err(|error| error.to_string())?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    drop(statement);
    if columns
        == [
            "agent_run_id",
            "snapshot_digest",
            "snapshot_json",
            "created_at_unix",
        ]
    {
        return Ok(());
    }
    if columns
        != [
            "agent_run_id",
            "context_json",
            "context_digest",
            "assigned_at_unix",
        ]
    {
        return Err(format!(
            "agent_wake_context has an unsupported v12 migration layout: {columns:?}"
        ));
    }

    let rows = read_legacy_wake_context_rows(tx)?;
    tx.execute_batch("DROP TABLE agent_wake_context;")
        .map_err(|error| error.to_string())?;
    create_agent_wake_context_table(tx, "agent_wake_context")?;
    for (agent_run_id, snapshot_digest, snapshot_json, created_at_unix) in rows {
        tx.execute(
            "INSERT INTO agent_wake_context(agent_run_id,snapshot_digest,snapshot_json,created_at_unix) VALUES (?1,?2,?3,?4)",
            params![agent_run_id,snapshot_digest,snapshot_json,created_at_unix],
        )
        .map_err(|error| error.to_string())?;
    }
    create_agent_wake_context_triggers(tx)
}

fn create_agent_wake_context_table(tx: &Transaction<'_>, table_name: &str) -> Result<(), String> {
    if table_name != "agent_wake_context" {
        return Err("invalid internal wake context table name".into());
    }
    tx.execute_batch(&format!(
        "CREATE TABLE {table_name} (
            agent_run_id TEXT PRIMARY KEY REFERENCES agent_launch_authority(agent_run_id),
            snapshot_digest TEXT NOT NULL CHECK(length(snapshot_digest) = 64),
            snapshot_json TEXT NOT NULL CHECK(length(snapshot_json) <= 1048576),
            created_at_unix INTEGER NOT NULL
        );"
    ))
    .map_err(|error| error.to_string())
}

fn create_agent_wake_context_triggers(tx: &Transaction<'_>) -> Result<(), String> {
    tx.execute_batch(
        "CREATE TRIGGER agent_wake_context_immutable_update
         BEFORE UPDATE ON agent_wake_context
         BEGIN SELECT RAISE(ABORT, 'Agent wake context is immutable'); END;
         CREATE TRIGGER agent_wake_context_immutable_delete
         BEFORE DELETE ON agent_wake_context
         BEGIN SELECT RAISE(ABORT, 'Agent wake context is retained'); END;",
    )
    .map_err(|error| error.to_string())
}

fn read_legacy_wake_context_rows(
    tx: &Transaction<'_>,
) -> Result<Vec<(String, String, String, i64)>, String> {
    let mut statement = tx
        .prepare(
            "SELECT agent_run_id,context_json,context_digest,assigned_at_unix FROM agent_wake_context ORDER BY agent_run_id",
        )
        .map_err(|error| error.to_string())?;
    let mut rows = statement.query([]).map_err(|error| error.to_string())?;
    let mut converted = Vec::new();
    let mut total_bytes = 0usize;
    while let Some(row) = rows.next().map_err(|error| error.to_string())? {
        let agent_run_id: String = row.get(0).map_err(|error| error.to_string())?;
        let context_json: String = row.get(1).map_err(|error| error.to_string())?;
        let context_digest: String = row.get(2).map_err(|error| error.to_string())?;
        let assigned_at_unix: i64 = row.get(3).map_err(|error| error.to_string())?;
        if context_json.len() > MAX_WAKE_SNAPSHOT_JSON_BYTES {
            return Err("legacy Agent wake context exceeds its 1 MiB bound".into());
        }
        total_bytes = total_bytes.saturating_add(context_json.len());
        if converted.len() >= MAX_WAKE_CONTEXT_MIGRATION_ROWS
            || total_bytes > MAX_WAKE_CONTEXT_MIGRATION_BYTES
        {
            return Err("legacy Agent wake contexts exceed the bounded migration limit".into());
        }
        let legacy: LegacyWakeSnapshot = crate::protocol::parse_unique(context_json.as_bytes())
            .map_err(|error| format!("legacy Agent wake snapshot is invalid: {error}"))?;
        if legacy.agent_run_id != agent_run_id
            || legacy.inputs.len() > MAX_WAKE_SNAPSHOT_ITEMS
            || legacy.digest.as_str()
                != legacy_wake_snapshot_digest(
                    &legacy.project_id,
                    &legacy.role_session_id,
                    &legacy.agent_run_id,
                    &legacy.inputs,
                )?
            || crate::store::content_digest(&context_json) != context_digest
        {
            return Err("legacy Agent wake snapshot identity or digest is invalid".into());
        }
        let run_scope: Option<(String, String)> = tx
            .query_row(
                "SELECT project_id,role_session_id FROM agent_runs WHERE agent_run_id=?1",
                [&agent_run_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if run_scope
            .as_ref()
            .is_none_or(|(project_id, role_session_id)| {
                project_id != legacy.project_id.as_str()
                    || role_session_id != &legacy.role_session_id
            })
        {
            return Err("legacy Agent wake snapshot does not match its AgentRun scope".into());
        }
        let has_authority: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM agent_launch_authority WHERE agent_run_id=?1)",
                [&agent_run_id],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        if !has_authority {
            return Err("legacy Agent wake snapshot has no persisted launch authority".into());
        }
        let inputs = legacy
            .inputs
            .into_iter()
            .map(|input| {
                let priority = i32::try_from(input.priority)
                    .map_err(|_| "legacy Agent wake priority is outside the i32 range")?;
                let payload_json = crate::protocol::parse_unique(input.payload_json.as_bytes())
                    .map_err(|error| format!("legacy Agent wake payload is invalid: {error}"))?;
                Ok(crate::agent_api::AgentWakeItem {
                    wake_input_id: input.wake_input_id,
                    source_type: input.source_type,
                    source_id: input.source_id,
                    source_revision: input.source_revision,
                    priority,
                    payload_json,
                    host_artifact_source_evidence_ids: Vec::new(),
                    host_artifacts: Vec::new(),
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let mut snapshot = crate::agent_api::AgentWakeSnapshot {
            schema_version: 1,
            project_id: legacy.project_id,
            role_session_id: legacy.role_session_id,
            agent_run_id: legacy.agent_run_id,
            digest: Digest::parse("0".repeat(64))?,
            inputs,
        };
        snapshot.digest = snapshot.content_digest()?;
        snapshot.validate()?;
        let snapshot_json = crate::store::canonical_json(&snapshot)?;
        if snapshot_json.len() > MAX_WAKE_SNAPSHOT_JSON_BYTES {
            return Err("converted Agent wake snapshot exceeds its 1 MiB bound".into());
        }
        converted.push((
            agent_run_id,
            snapshot.digest.as_str().to_owned(),
            snapshot_json,
            assigned_at_unix,
        ));
    }
    Ok(converted)
}

fn legacy_wake_snapshot_digest(
    project_id: &ProjectId,
    role_session_id: &str,
    agent_run_id: &str,
    inputs: &[LegacyWakeInput],
) -> Result<String, String> {
    let base = serde_json::json!({
        "project_id": project_id.as_str(),
        "role_session_id": role_session_id,
        "agent_run_id": agent_run_id,
        "inputs": inputs,
    });
    let canonical = serde_json::to_string(&base).map_err(|error| error.to_string())?;
    Ok(crate::store::content_digest(&canonical))
}

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

fn ticket_has_active_child(
    connection: &rusqlite::Connection,
    project_id: &crate::domain::ids::ProjectId,
    ticket_run_id: &crate::domain::ids::TicketRunId,
) -> Result<bool, String> {
    connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM agent_runs r JOIN agent_launch_authority a USING(agent_run_id) WHERE r.project_id=?1 AND a.ticket_run_id=?2 AND a.role!='coordinator' AND r.state IN ('launch_pending','running','parked','unknown'))",
        params![project_id.as_str(), ticket_run_id.as_str()],
        |row| row.get(0),
    ).map_err(|error| error.to_string())
}

impl ConfigStore {
    pub fn agent_launch_project_epoch(
        &self,
        agent_run_id: &crate::domain::ids::AgentRunId,
    ) -> Result<Option<u64>, String> {
        self.connection
            .query_row(
                "SELECT project_epoch FROM agent_launch_reservations WHERE agent_run_id=?1",
                [agent_run_id.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())
    }

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

    /// Revalidate the accepted launch before publishing a missing wrapper ACK.
    pub fn validate_agent_launch_replay(
        &self,
        owner_generation: u64,
        expected: &AgentLaunchReservation,
    ) -> Result<(), String> {
        expected.validate()?;
        let active: Option<u64> = self.connection.query_row(
            "SELECT generation FROM controller_owners WHERE singleton=1 AND stopped_at_unix IS NULL",
            [], |row| row.get(0),
        ).optional().map_err(|error| error.to_string())?;
        if active != Some(owner_generation) || expected.controller_generation != owner_generation {
            return Err("controller owner generation is stale".into());
        }
        let stored: Option<(String, String, String)> = self.connection.query_row(
            "SELECT reservation_digest,reservation_json,lifecycle FROM agent_launch_reservations WHERE agent_run_id=?1",
            [expected.agent_run_id.as_str()], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).optional().map_err(|error| error.to_string())?;
        let Some((digest, json, lifecycle)) = stored else {
            return Err("AgentRun has no persisted launch reservation".into());
        };
        let reservation: AgentLaunchReservation = crate::protocol::parse_unique(json.as_bytes())
            .map_err(|error| format!("stored launch reservation is invalid: {error}"))?;
        if lifecycle != "authorized"
            || digest != expected.digest()?.as_str()
            || reservation != *expected
        {
            return Err("persisted launch reservation does not match the accepted launch".into());
        }
        let project: Option<(u64, String, u64, String, String)> = self.connection.query_row(
            "SELECT r.project_epoch,p.config_digest,p.config_revision,p.desired_lifecycle,r.observed_lifecycle FROM projects p JOIN project_runtimes r USING(project_id) WHERE p.project_id=?1",
            [expected.project_id.as_str()], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)),
        ).optional().map_err(|error| error.to_string())?;
        let Some((epoch, config_digest, config_revision, desired, observed)) = project else {
            return Err("launch Project no longer exists".into());
        };
        if desired != "running"
            || !matches!(observed.as_str(), "running" | "starting")
            || epoch != expected.project_epoch
        {
            return Err("Project lifecycle or epoch changed".into());
        }
        if config_revision != expected.config_revision.0
            || config_digest != expected.config_digest.as_str()
        {
            return Err("Project config changed".into());
        }
        Ok(())
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
        let stored: Option<(Option<String>, Option<String>)> = self
            .connection
            .query_row(
                "SELECT start_request_digest,launch_receipt_json FROM agent_launch_state WHERE agent_run_id=?1",
                [request.agent_run_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let Some((stored_digest, receipt_json)) = super::persisted_start_ack(stored)? else {
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

    /// Load the immutable reservation by run identity and verify its stored digest.
    pub fn agent_launch_reservation_for_run(
        &self,
        agent_run_id: &crate::domain::ids::AgentRunId,
    ) -> Result<Option<AgentLaunchReservation>, String> {
        let digest: Option<String> = self
            .connection
            .query_row(
                "SELECT reservation_digest FROM agent_launch_reservations WHERE agent_run_id=?1",
                [agent_run_id.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let Some(digest) = digest else {
            return Ok(None);
        };
        self.agent_launch_reservation(agent_run_id, &Digest::parse(digest)?)
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
        validate_project_launch_identity(
            &tx,
            &reservation.project_id,
            reservation.project_epoch,
            reservation.config_revision.0,
            &reservation.config_digest,
        )?;
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
        let persisted_run: Option<(Option<String>, Option<String>, Option<u64>)> = tx
            .query_row(
                "SELECT role,role_session_id,config_revision FROM agent_runs WHERE agent_run_id=?1",
                [agent_run_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let authority_role = serde_json::to_value(authority.role)
            .map_err(|error| error.to_string())?
            .as_str()
            .ok_or("Agent role did not serialize as a string")?
            .to_owned();
        if !matches!(persisted_run, Some((Some(ref role), Some(ref session), Some(revision)))
            if role == &authority_role
                && session == &authority.role_session_id
                && revision == authority.config_revision.0)
        {
            return Err("AgentRun typed role, role session, or configuration revision does not match launch authority".into());
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
        let wake_digest = reservation.wake_snapshot.content_digest()?;
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
        // SQL selects the highest-priority bounded set. Canonicalize that set by durable ID
        // because AgentWakeSnapshot requires strictly increasing wake_input_id values.
        inputs.sort_by_key(|input| input.wake_input_id);
        Ok(inputs)
    }

    /// Reserve a finite turn and enqueue its first host effect atomically. This phase contains
    /// only the known Rex view identity; the new block ID is observed and bound in phase two.
    pub fn prepare_role_launch(
        &mut self,
        reservation: &AgentLaunchReservation,
    ) -> Result<LaunchPreparationOutcome, String> {
        if reservation.role == Role::Worker {
            return Err(
                "Worker launches require an opaque accepted-plan and prepared-worktree token"
                    .into(),
            );
        }
        if reservation.worker_assignment.is_some() {
            return Err("non-Worker launch cannot carry Worker plan provenance".into());
        }
        self.prepare_role_launch_inner(reservation, None)
    }

    /// Reserve a Worker only with the opaque Store token minted after the accepted
    /// Coordinator plan and its exact prepared-worktree effect have been verified.
    pub fn prepare_worker_role_launch(
        &mut self,
        reservation: &AgentLaunchReservation,
        prepared: &crate::store::accepted_plans::PreparedWorkerLaunch,
    ) -> Result<LaunchPreparationOutcome, String> {
        if reservation.role != Role::Worker {
            return Err("prepared worktree token can only authorize a Worker launch".into());
        }
        if reservation.worker_assignment.as_ref() != Some(&prepared.reservation_binding()) {
            return Err(
                "Worker reservation does not exactly match its host-minted plan token".into(),
            );
        }
        self.prepare_role_launch_inner(reservation, Some(prepared))
    }

    fn prepare_role_launch_inner(
        &mut self,
        reservation: &AgentLaunchReservation,
        prepared_worker: Option<&crate::store::accepted_plans::PreparedWorkerLaunch>,
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
        if let Some(prepared) = prepared_worker {
            crate::store::accepted_plans::revalidate_prepared_worker_launch(
                &tx,
                reservation,
                prepared,
            )?;
        } else if reservation.role == Role::Worker || reservation.worker_assignment.is_some() {
            return Err(
                "Worker launch lacks transactionally verified prepared-worktree authority".into(),
            );
        }
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
        let profile_digest = crate::store::agent_profile_digest(profile)?;
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
        if reservation.role == crate::domain::types::Role::Coordinator
            && let Some(ticket_run_id) = &reservation.ticket_run_id
        {
            let active_child =
                ticket_has_active_child(&tx, &reservation.project_id, ticket_run_id)?;
            if active_child {
                return Ok(LaunchPreparationOutcome::CapacityUnavailable);
            }
        }
        if let Some(parent_id) = &reservation.parent_run_id {
            let parent: Option<ParentAuthorityScopeRow> = tx
                .query_row(
                    "SELECT r.project_id,r.state,a.role,a.role_session_id,a.ticket_run_id,a.config_revision,a.config_digest FROM agent_runs r JOIN agent_launch_authority a USING(agent_run_id) WHERE r.agent_run_id=?1",
                    [parent_id.as_str()],
                    |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?)),
                )
                .optional()
                .map_err(|error| error.to_string())?;
            let expected_parent_role = reservation.parent_role.and_then(|role| {
                serde_json::to_value(role)
                    .ok()
                    .and_then(|value| value.as_str().map(str::to_owned))
            });
            let expected_parent_session = match reservation.parent_role {
                Some(Role::Supervisor) => {
                    Some(format!("project:{}:supervisor", reservation.project_id))
                }
                Some(Role::Coordinator) => reservation
                    .ticket_run_id
                    .as_ref()
                    .map(|id| format!("ticket_run:{id}:coordinator")),
                _ => None,
            };
            let expected_parent_ticket = match reservation.parent_role {
                Some(Role::Supervisor) => None,
                Some(Role::Coordinator) => reservation.ticket_run_id.as_ref().map(|id| id.as_str()),
                _ => None,
            };
            let parent_scope = matches!(parent.as_ref(),Some((parent_project,_,role,session,ticket,config_revision,config))
                if parent_project==reservation.project_id.as_str()
                    && expected_parent_role.as_deref()==Some(role.as_str())
                    && expected_parent_session.as_deref()==Some(session.as_str())
                    && ticket.as_deref()==expected_parent_ticket
                    && *config_revision==reservation.config_revision.0
                    && config==reservation.config_digest.as_str());
            let live_parent = parent_scope
                && matches!(parent.as_ref(),Some((_,state,_,_,_,_,_)) if matches!(state.as_str(),"running"|"parked"));
            let completed_parent = parent_scope
                && matches!(parent.as_ref(),Some((_,state,_,_,_,_,_)) if state=="completed")
                && completed_parent_has_trusted_source(
                    &tx,
                    &ParentSourceScope {
                        project_id: reservation.project_id.as_str(),
                        child_role: reservation.role,
                        role_session_id: &reservation.role_session_id,
                        ticket_run_id: reservation.ticket_run_id.as_ref().map(|id| id.as_str()),
                        parent_role: reservation.parent_role,
                    },
                    parent_id,
                    prepared_worker,
                )?;
            if !live_parent && !completed_parent {
                return Err(
                    "launch parent is not a same-Project AgentRun with the expected role and trusted provenance"
                        .into(),
                );
            }
        }

        let ticket_run_id = reservation.ticket_run_id.as_ref().map(|id| id.as_str());
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

/// Completed finite parents may authorize a child only through the durable source that
/// selected them. The resolver validates the dispatch/result payload before constructing the
/// reservation; this transaction rechecks that the same immutable evidence still anchors it.
struct ParentSourceScope<'a> {
    project_id: &'a str,
    child_role: Role,
    role_session_id: &'a str,
    ticket_run_id: Option<&'a str>,
    parent_role: Option<Role>,
}

fn completed_parent_has_trusted_source(
    tx: &rusqlite::Transaction<'_>,
    scope: &ParentSourceScope<'_>,
    parent_id: &crate::domain::ids::AgentRunId,
    prepared_worker: Option<&crate::store::accepted_plans::PreparedWorkerLaunch>,
) -> Result<bool, String> {
    let evidence_exists: bool = match (scope.child_role, scope.parent_role) {
        (Role::Coordinator, Some(Role::Supervisor)) => {
            let Some(ticket_run_id) = scope.ticket_run_id else {
                return Ok(false);
            };
            if scope.role_session_id != format!("ticket_run:{ticket_run_id}:coordinator") {
                return Ok(false);
            }
            tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM role_wake_inputs w JOIN ticket_runs t ON t.ticket_run_id=?3 AND t.project_id=w.project_id JOIN agent_result_evidence e ON e.evidence_id=json_extract(w.payload_json,'$.supervisor_evidence_id') WHERE w.project_id=?1 AND w.role_session_id=?2 AND w.source_type='ticket_run_dispatch' AND w.source_id=?3 AND e.agent_run_id=?4 AND e.project_id=w.project_id AND e.role='supervisor' AND e.ticket_run_id IS NULL AND e.outcome='completed')",
                rusqlite::params![scope.project_id, format!("ticket_run:{ticket_run_id}:coordinator"), ticket_run_id, parent_id.as_str()],
                |row| row.get(0),
            ).map_err(|error| error.to_string())?
        }
        (Role::Worker, Some(Role::Coordinator)) => prepared_worker.is_some_and(|prepared| {
            prepared.coordinator_agent_run_id() == parent_id
                && prepared.project_id().as_str() == scope.project_id
                && Some(prepared.ticket_run_id().as_str()) == scope.ticket_run_id
                && scope.role_session_id
                    == format!(
                        "ticket:{}:worker:{}",
                        prepared.ticket_run_id(),
                        prepared.node_id()
                    )
                && prepared.coordinator_role_session_id()
                    == format!("ticket_run:{}:coordinator", prepared.ticket_run_id())
        }),
        (
            Role::Planner
            | Role::Reviewer
            | Role::MergeDecision
            | Role::Operator
            | Role::Postmortem,
            Some(Role::Coordinator),
        ) => {
            let Some(ticket_run_id) = scope.ticket_run_id else {
                return Ok(false);
            };
            let role_name = serde_json::to_value(scope.child_role)
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned));
            if role_name.as_deref().is_none_or(|role| {
                scope.role_session_id != format!("ticket_run:{ticket_run_id}:{role}")
            }) {
                return Ok(false);
            }
            tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM role_wake_inputs w JOIN agent_result_evidence e ON e.evidence_id=w.source_id WHERE w.project_id=?1 AND w.role_session_id=?2 AND w.source_type='coordinator_child' AND e.agent_run_id=?3 AND e.project_id=w.project_id AND e.role='coordinator' AND e.ticket_run_id=?4 AND e.outcome='completed')",
                rusqlite::params![scope.project_id, scope.role_session_id, parent_id.as_str(), ticket_run_id],
                |row| row.get(0),
            ).map_err(|error| error.to_string())?
        }
        _ => false,
    };
    Ok(evidence_exists)
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
pub(crate) mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::{
        ConfigStore, LaunchPreparationOutcome, LegacyWakeInput, LegacyWakeSnapshot,
        legacy_wake_snapshot_digest, migrate_v12_agent_wake_context, ticket_has_active_child,
    };
    use crate::config::{AppliedConfig, Profile, SourceFile, SourceKind};
    use crate::domain::ids::{AgentRunId, Digest, OperationId, ProfileId, ProjectId, Revision};
    use crate::domain::types::{AgentAdapter, CommitMode, Role};
    use crate::launch::{
        AgentLaunchReservation, LAUNCH_SCHEMA_VERSION, ObservedProviderStart,
        ProviderProcessIdentity, ProviderQualification, QualificationProof, QualificationStatus,
        RexView, RexViewKind,
    };
    use sha2::Digest as _;

    #[test]
    fn completed_parent_requires_the_role_specific_durable_source() {
        let connection = rusqlite::Connection::open_in_memory().unwrap();
        connection.execute_batch(
            "CREATE TABLE role_wake_inputs(project_id TEXT,role_session_id TEXT,source_type TEXT,source_id TEXT,payload_json TEXT);
             CREATE TABLE ticket_runs(ticket_run_id TEXT,project_id TEXT);
             CREATE TABLE agent_result_evidence(evidence_id TEXT,agent_run_id TEXT,project_id TEXT,role TEXT,ticket_run_id TEXT,outcome TEXT);
             INSERT INTO role_wake_inputs VALUES ('project-a','ticket_run:ticket-1:coordinator','ticket_run_dispatch','ticket-1','{\"supervisor_evidence_id\":\"dispatch-evidence\"}');
             INSERT INTO ticket_runs VALUES ('ticket-1','project-a');
             INSERT INTO agent_result_evidence VALUES ('dispatch-evidence','supervisor-1','project-a','supervisor',NULL,'completed');
             INSERT INTO role_wake_inputs VALUES ('project-a','ticket_run:ticket-1:planner','coordinator_child','child-evidence','{}');
             INSERT INTO agent_result_evidence VALUES ('child-evidence','coordinator-1','project-a','coordinator','ticket-1','completed');"
        ).unwrap();
        let tx = connection.unchecked_transaction().unwrap();
        let coordinator = super::ParentSourceScope {
            project_id: "project-a",
            child_role: Role::Coordinator,
            role_session_id: "ticket_run:ticket-1:coordinator",
            ticket_run_id: Some("ticket-1"),
            parent_role: Some(Role::Supervisor),
        };
        assert!(
            super::completed_parent_has_trusted_source(
                &tx,
                &coordinator,
                &AgentRunId::parse("supervisor-1").unwrap(),
                None,
            )
            .unwrap()
        );
        assert!(
            !super::completed_parent_has_trusted_source(
                &tx,
                &super::ParentSourceScope {
                    role_session_id: "ticket_run:ticket-1:planner",
                    ..coordinator
                },
                &AgentRunId::parse("supervisor-1").unwrap(),
                None,
            )
            .unwrap()
        );
        let planner = super::ParentSourceScope {
            project_id: "project-a",
            child_role: Role::Planner,
            role_session_id: "ticket_run:ticket-1:planner",
            ticket_run_id: Some("ticket-1"),
            parent_role: Some(Role::Coordinator),
        };
        assert!(
            super::completed_parent_has_trusted_source(
                &tx,
                &planner,
                &AgentRunId::parse("coordinator-1").unwrap(),
                None,
            )
            .unwrap()
        );
        assert!(
            !super::completed_parent_has_trusted_source(
                &tx,
                &planner,
                &AgentRunId::parse("wrong-parent").unwrap(),
                None,
            )
            .unwrap()
        );
        assert!(
            !super::completed_parent_has_trusted_source(
                &tx,
                &super::ParentSourceScope {
                    ticket_run_id: Some("other-ticket"),
                    ..planner
                },
                &AgentRunId::parse("coordinator-1").unwrap(),
                None,
            )
            .unwrap()
        );
        assert!(
            !super::completed_parent_has_trusted_source(
                &tx,
                &super::ParentSourceScope {
                    role_session_id: "ticket_run:ticket-1:reviewer",
                    ..planner
                },
                &AgentRunId::parse("coordinator-1").unwrap(),
                None,
            )
            .unwrap()
        );
        assert!(
            !super::completed_parent_has_trusted_source(
                &tx,
                &super::ParentSourceScope {
                    project_id: "other-project",
                    ..planner
                },
                &AgentRunId::parse("coordinator-1").unwrap(),
                None,
            )
            .unwrap()
        );
        assert!(
            !super::completed_parent_has_trusted_source(
                &tx,
                &super::ParentSourceScope {
                    parent_role: Some(Role::Coordinator),
                    ..coordinator
                },
                &AgentRunId::parse("coordinator-1").unwrap(),
                None,
            )
            .unwrap()
        );
        let worker = super::ParentSourceScope {
            child_role: Role::Worker,
            role_session_id: "ticket:ticket-1:worker:node-1",
            parent_role: Some(Role::Coordinator),
            ..planner
        };
        assert!(
            !super::completed_parent_has_trusted_source(
                &tx,
                &worker,
                &AgentRunId::parse("coordinator-1").unwrap(),
                None,
            )
            .unwrap()
        );
    }

    #[test]
    fn coordinator_waits_for_active_or_ambiguous_ticket_agents_to_finish() {
        let connection = rusqlite::Connection::open_in_memory().unwrap();
        connection.execute_batch(
            "CREATE TABLE agent_runs(agent_run_id TEXT PRIMARY KEY,project_id TEXT,state TEXT);
             CREATE TABLE agent_launch_authority(agent_run_id TEXT PRIMARY KEY,role TEXT,ticket_run_id TEXT);
             INSERT INTO agent_runs VALUES ('worker-1','project-a','running');
             INSERT INTO agent_launch_authority VALUES ('worker-1','worker','ticket-1');"
        ).unwrap();
        let project = ProjectId::parse("project-a").unwrap();
        let ticket_run = crate::domain::ids::TicketRunId::parse("ticket-1").unwrap();
        assert!(ticket_has_active_child(&connection, &project, &ticket_run).unwrap());
        connection
            .execute(
                "UPDATE agent_runs SET state='unknown' WHERE agent_run_id='worker-1'",
                [],
            )
            .unwrap();
        assert!(ticket_has_active_child(&connection, &project, &ticket_run).unwrap());
        connection
            .execute(
                "UPDATE agent_runs SET state='completed' WHERE agent_run_id='worker-1'",
                [],
            )
            .unwrap();
        assert!(!ticket_has_active_child(&connection, &project, &ticket_run).unwrap());
        connection
            .execute(
                "INSERT INTO agent_runs VALUES ('other-project-worker','project-b','running')",
                [],
            )
            .unwrap();
        connection.execute("INSERT INTO agent_launch_authority VALUES ('other-project-worker','worker','ticket-1')", []).unwrap();
        assert!(!ticket_has_active_child(&connection, &project, &ticket_run).unwrap());
    }
    use crate::store::{ExpectedRevision, OwnerMetadata, ProjectRecord};

    fn digest(ch: char) -> Digest {
        Digest::parse(ch.to_string().repeat(64)).unwrap()
    }

    #[test]
    fn legacy_wake_context_conversion_rejects_unrepresentable_rows_before_replacement() {
        let mut connection = rusqlite::Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE agent_runs(agent_run_id TEXT PRIMARY KEY,project_id TEXT,role_session_id TEXT);
                 CREATE TABLE agent_launch_authority(agent_run_id TEXT PRIMARY KEY);
                 INSERT INTO agent_runs VALUES ('run1','project1','session1');
                 INSERT INTO agent_launch_authority VALUES ('run1');
                 CREATE TABLE agent_wake_context(
                    agent_run_id TEXT PRIMARY KEY REFERENCES agent_runs(agent_run_id),
                    context_json TEXT NOT NULL,
                    context_digest TEXT NOT NULL,
                    assigned_at_unix INTEGER NOT NULL
                 );",
            )
            .unwrap();
        let project_id = ProjectId::parse("project1").unwrap();
        let input = LegacyWakeInput {
            wake_input_id: 1,
            source_type: "test".into(),
            source_id: "event1".into(),
            source_revision: 1,
            priority: i64::from(i32::MAX) + 1,
            payload_json: "{}".into(),
        };
        let snapshot_digest = legacy_wake_snapshot_digest(
            &project_id,
            "session1",
            "run1",
            std::slice::from_ref(&input),
        )
        .unwrap();
        let context_json = serde_json::to_string(&LegacyWakeSnapshot {
            project_id,
            role_session_id: "session1".into(),
            agent_run_id: "run1".into(),
            inputs: vec![input],
            digest: Digest::parse(snapshot_digest).unwrap(),
        })
        .unwrap();
        let context_digest = crate::store::content_digest(&context_json);
        connection
            .execute(
                "INSERT INTO agent_wake_context VALUES ('run1',?1,?2,1)",
                rusqlite::params![context_json, context_digest],
            )
            .unwrap();

        let tx = connection.transaction().unwrap();
        let error = migrate_v12_agent_wake_context(&tx).unwrap_err();
        assert!(error.contains("i32 range"), "{error}");
        drop(tx);

        let legacy_column_exists: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM pragma_table_info('agent_wake_context') WHERE name='context_json')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            legacy_column_exists,
            "failed conversion leaves the legacy schema intact"
        );
        let row_count: u64 = connection
            .query_row("SELECT COUNT(*) FROM agent_wake_context", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(row_count, 1, "failed conversion preserves the source row");
    }

    pub(crate) fn applied() -> AppliedConfig {
        let config = serde_json::from_value(serde_json::json!({
            "schema_version": 1,
            "adapters": { "tickets": {
                "kind":"command", "command":["ticket-cli"]
            }},
            "projects": { "project-a": {
                "mode":"operations", "ticket_adapter":"tickets",
                "roles":{"supervisor":"supervisor"}
            }}
        }))
        .unwrap();
        let profile: Profile = serde_json::from_value(serde_json::json!({
            "adapter":"codex", "command":["/bin/codex"], "model":"fixture",
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

    pub(crate) fn qualification() -> ProviderQualification {
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
            profile_digest: crate::store::agent_profile_digest(
                applied()
                    .profiles
                    .get(&ProfileId::parse("supervisor").unwrap())
                    .unwrap(),
            )
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

    fn fixture_digest_json<T: serde::Serialize + ?Sized>(value: &T) -> Digest {
        Digest::parse(format!(
            "{:x}",
            sha2::Sha256::digest(serde_json::to_vec(value).unwrap())
        ))
        .unwrap()
    }

    pub(crate) struct CompletedBlockLossFixture {
        pub store: ConfigStore,
        pub generation: u64,
        pub run: crate::store::agent_recovery::RecoverableAgentRun,
        pub wrapper: crate::launch::ObservedWrapperIdentity,
        pub provider: ObservedProviderStart,
        pub slot_owner_id: String,
    }

    pub(crate) fn completed_block_loss_fixture(
        root: &std::path::Path,
        complete_family: bool,
    ) -> CompletedBlockLossFixture {
        use crate::domain::ids::{AgentRunId, OperationId, ProfileId, ProjectId, Revision};
        use crate::domain::types::{AgentAdapter, Role};
        use crate::launch::{
            AgentLaunchAuthority, AgentStartRequest, ObservedWrapperIdentity,
            ProviderProcessIdentity, RexView, RexViewKind,
        };
        use crate::process::ProcessIdentityQuality;
        use crate::run_step::{
            CleanupState, ProviderCapabilityEvidence, ProviderQualificationStatus, RunDescriptor,
            TurnOutcome, TurnResult,
        };
        use crate::run_step_spool::{
            RunFamilyBinding, RunFamilyCoverage, RunFamilyRecord, RunStepSpool,
        };
        use crate::store::{ExpectedRevision, OwnerMetadata, ProjectRecord};
        use sha2::Digest as _;

        let root = std::fs::canonicalize(root).unwrap();
        let state_root = root.join("state");
        let control_dir = root.join("control");
        let workspace = root.join("workspace");
        std::fs::create_dir_all(&state_root).unwrap();
        std::fs::create_dir_all(&control_dir).unwrap();
        std::fs::create_dir_all(&workspace).unwrap();
        let mut store = ConfigStore::open_test(&state_root).unwrap();
        let mut config = applied();
        let profile_id = ProfileId::parse("supervisor").unwrap();
        let profile = config.profiles.get_mut(&profile_id).unwrap();
        profile.command = vec!["/bin/sleep".into()];
        let profile_digest = crate::store::agent_profile_digest(profile).unwrap();
        let applied_snapshot = store
            .apply_snapshot("factory", &config, ExpectedRevision::Bootstrap)
            .unwrap();
        let project_id = ProjectId::parse("project-a").unwrap();
        store
            .insert_project(&ProjectRecord {
                id: project_id.clone(),
                config_source: "factory".into(),
                config_revision: applied_snapshot.revision,
                config_digest: applied_snapshot.digest.clone(),
                mode: "operations".into(),
                goal_revision: 0,
                desired_lifecycle: "running".into(),
                state_revision: Revision(0),
            })
            .unwrap();
        let generation = store
            .start_owner(&OwnerMetadata {
                owner_nonce: "completed-block-loss-test".into(),
                state_root: state_root.display().to_string(),
                config_source: "factory".into(),
                process_start_identity: "owner-start".into(),
                executable_path: "/tmp/rex-projects-fixture".into(),
                executable_digest: "b".repeat(64),
                rex_endpoint: Some("unix:///tmp/rex-test.sock".into()),
                rex_server_identity: Some("rex-instance".into()),
                rex_session_id: Some("session".into()),
                rex_block_id: None,
            })
            .unwrap();
        store
            .connection
            .execute(
                "UPDATE project_runtimes SET desired_lifecycle='running',observed_lifecycle='running',controller_generation=?2 WHERE project_id=?1",
                rusqlite::params![project_id.as_str(), generation],
            )
            .unwrap();
        store
            .connection
            .execute(
                "UPDATE projects SET desired_lifecycle='running' WHERE project_id=?1",
                [project_id.as_str()],
            )
            .unwrap();

        let mut qualification = qualification();
        let executable = std::fs::canonicalize("/bin/sleep").unwrap();
        qualification.project_id = project_id.clone();
        qualification.profile_digest = profile_digest.clone();
        qualification.executable_path = executable.display().to_string();
        qualification.executable_digest = Digest::parse(format!(
            "{:x}",
            sha2::Sha256::digest(std::fs::read(&executable).unwrap())
        ))
        .unwrap();
        let qualification_digest = store
            .store_provider_qualification(generation, &qualification)
            .unwrap();
        let view = RexView {
            view_id: crate::launch::RexView::derive_id(
                &project_id,
                RexViewKind::Supervisor,
                None,
                None,
                1,
            )
            .unwrap(),
            project_id: project_id.clone(),
            kind: RexViewKind::Supervisor,
            ticket_namespace: None,
            ticket_id: None,
            view_epoch: 1,
            rex_server_identity: "rex-instance".into(),
            rex_session_id: "session".into(),
            rex_window_id: "window".into(),
        };
        store.register_rex_view(generation, &view).unwrap();

        let run_id = AgentRunId::parse("run-completed-block-loss-test").unwrap();
        let operation_id = OperationId::parse("operation-completed-block-loss-test").unwrap();
        let wrapper = ObservedWrapperIdentity {
            pid: u32::MAX - 20,
            start_identity: "wrapper-born-test".into(),
            rex_session_id: "session".into(),
            rex_block_id: "block-test".into(),
            runtime_binary_digest: digest('4'),
        };
        let provider_pid = u32::MAX - 19;
        let provider_start_identity = "provider-born-test".to_owned();
        let result_schema = serde_json::json!({"type":"object"});
        let schema_projection = crate::providers::project_result_schema(&result_schema)
            .unwrap()
            .identity;
        let result_schema_digest = schema_projection.source_schema_digest.clone();
        let authority_base = AgentLaunchAuthority {
            agent_run_id: run_id.clone(),
            project_id: project_id.clone(),
            role: Role::Supervisor,
            role_session_id: "project:project-a:supervisor".into(),
            parent_run_id: None,
            parent_role: None,
            ticket_run_id: None,
            ticket_revision: None,
            config_revision: applied_snapshot.revision,
            config_digest: applied_snapshot.digest.clone(),
            attempt: 1,
            run_epoch: 1,
            controller_generation: generation,
            operation_id: operation_id.clone(),
            operation_recipe_id: None,
            rex_view_id: view.view_id.clone(),
            descriptor_digest: digest('0'),
            runtime_binary_digest: wrapper.runtime_binary_digest.clone(),
            descriptor_path: root.join("run-step.package.json"),
            environment_snapshot_id: digest('5'),
            profile_id: profile_id.clone(),
            profile_digest: profile_digest.clone(),
            instruction_digest: digest('6'),
            result_schema_digest: result_schema_digest.clone(),
            wake_snapshot_digest: digest('7'),
            qualification_receipt_digest: qualification_digest.clone(),
            rex_server_identity: "rex-instance".into(),
            rex_session_id: "session".into(),
            rex_window_id: "window".into(),
            rex_block_id: "block-test".into(),
            workspace_path: workspace.clone(),
            control_dir: control_dir.clone(),
            mailbox_capability_digest: digest('8'),
        };
        let result_projection = schema_projection.clone();
        let package = crate::run_step_package::RunStepPackage {
            schema_version: 2,
            execution_slot_epoch: 7,
            descriptor: RunDescriptor {
                schema_version: 1,
                project_id: project_id.clone(),
                run_id: run_id.clone(),
                operation_id: operation_id.clone(),
                role: Role::Supervisor,
                ticket_run_id: None,
                expected_subject_revision: 0,
                attempt: 1,
                run_epoch: 1,
                controller_generation: generation,
                workspace: workspace.clone(),
                control_dir: control_dir.clone(),
                worker_assignment: None,
                rex_session_id: "session".into(),
                rex_block_id: crate::domain::ids::RexBlockId::parse("block-test").unwrap(),
                profile_digest: profile_digest.clone(),
                instruction_digest: authority_base.instruction_digest.clone(),
                plan_digest: None,
                environment_snapshot_id: authority_base.environment_snapshot_id.clone(),
                wake_snapshot_digest: authority_base.wake_snapshot_digest.clone(),
                provider_capability: ProviderCapabilityEvidence {
                    schema_version: 1,
                    adapter: qualification.adapter,
                    profile_digest: profile_digest.clone(),
                    version: qualification.provider_version.clone(),
                    executable_path: executable.clone(),
                    executable_digest: qualification.executable_digest.clone(),
                    permission_mode: qualification.permission_mode.clone(),
                    invocation_options_digest: qualification.invocation_options_digest.clone(),
                    commit_mode: qualification.commit_mode,
                    schema_projection: result_projection,
                    receipt_digest: qualification_digest.clone(),
                    status: ProviderQualificationStatus::Verified,
                },
                result_schema: result_schema.clone(),
            },
            operation_id: operation_id.clone(),
            project_id: project_id.clone(),
            controller_generation: generation,
            runtime_binary_digest: authority_base.runtime_binary_digest.clone(),
            qualification_receipt_digest: qualification_digest.clone(),
            rex_cli_path: "/bin/rex".into(),
            rex_search_path: Vec::new(),
            rex_endpoint: "unix:///tmp/rex-test.sock".into(),
            rex_server_identity: "rex-instance".into(),
            rex_window_id: "window".into(),
            profile: config.profiles[&profile_id].clone(),
            role_contract: "fixture".into(),
            prompt: "fixture".into(),
            continuation: None,
            shutdown_grace_seconds: 30,
            start_ack_timeout_seconds: 30,
        };
        let mut authority = authority_base;
        authority.descriptor_digest = package.publish_once(&authority.descriptor_path).unwrap();
        let authority_digest = authority.digest().unwrap();
        store.connection.execute(
            "INSERT INTO agent_runs(agent_run_id,project_id,config_source,config_revision,config_digest,role_session_id,role,logical_owner,finite_turn,launch_operation_id,state,controller_generation) VALUES (?1,?2,'factory',?3,?4,?5,'supervisor','test',1,?6,'launch_pending',?7)",
            rusqlite::params![run_id.as_str(), project_id.as_str(), authority.config_revision.0, authority.config_digest.as_str(), authority.role_session_id, operation_id.as_str(), generation],
        ).unwrap();
        store.connection.execute(
            "INSERT INTO agent_mailboxes(agent_run_id,canonical_directory,capability_digest,expires_at_unix,max_request_bytes,max_pending_requests) VALUES (?1,?2,?3,4102444800,1048576,32)",
            rusqlite::params![run_id.as_str(), control_dir.display().to_string(), authority.mailbox_capability_digest.as_str()],
        ).unwrap();
        store
            .register_agent_launch_authority(generation, &authority)
            .unwrap();
        store.connection.execute(
            "INSERT INTO execution_slots(pool,slot_index,project_id,owner_kind,owner_id,reservation_epoch,controller_generation,disposition) VALUES ('agent',0,?1,'agent_run',?2,7,0,'unknown')",
            rusqlite::params![project_id.as_str(), run_id.as_str()],
        ).unwrap();
        store.connection.execute(
            "INSERT INTO execution_slots(pool,slot_index,project_id,owner_kind,owner_id,reservation_epoch,controller_generation,disposition) VALUES ('agent',1,?1,'agent_run','unrelated-run',99,0,'unknown')",
            [project_id.as_str()],
        ).unwrap();

        let start_request = AgentStartRequest {
            schema_version: crate::launch::LAUNCH_SCHEMA_VERSION,
            operation_id: operation_id.clone(),
            agent_run_id: run_id.clone(),
            project_id: project_id.clone(),
            controller_generation: generation,
            descriptor_digest: authority.descriptor_digest.clone(),
            runtime_binary_digest: authority.runtime_binary_digest.clone(),
            environment_snapshot_id: authority.environment_snapshot_id.clone(),
            qualification_receipt_digest: qualification_digest.clone(),
            wrapper_pid: wrapper.pid,
            wrapper_start_identity: wrapper.start_identity.clone(),
            rex_session_id: wrapper.rex_session_id.clone(),
            rex_block_id: wrapper.rex_block_id.clone(),
        };
        let start_receipt = crate::launch::authorize_start(
            generation,
            &authority.expectation(&qualification),
            &qualification,
            &start_request,
        )
        .unwrap();
        let request_json = serde_json::to_string(&start_request).unwrap();
        let request_digest = Digest::parse(format!(
            "{:x}",
            sha2::Sha256::digest(request_json.as_bytes())
        ))
        .unwrap();
        store.connection.execute(
            "UPDATE agent_launch_state SET state='awaiting_provider',start_request_id=?2,start_request_digest=?3,wrapper_process_identity_json=?4,launch_receipt_json=?5 WHERE agent_run_id=?1",
            rusqlite::params![run_id.as_str(), operation_id.as_str(), request_digest.as_str(), serde_json::to_string(&wrapper).unwrap(), serde_json::to_string(&start_receipt).unwrap()],
        ).unwrap();
        let spool = RunStepSpool::open(&control_dir).unwrap();
        let start = spool.publish_start_once(start_request.clone()).unwrap();
        spool.publish_start_receipt(&start, start_receipt).unwrap();

        let wrapper_process = crate::process::ProcessIdentity {
            pid: wrapper.pid,
            parent_pid: 1,
            process_group_id: wrapper.pid,
            start_identity: wrapper.start_identity.clone(),
            command: "rex-wrapper-test".into(),
            quality: ProcessIdentityQuality::KernelBirthToken,
        };
        let family_process = crate::process::ProcessIdentity {
            pid: provider_pid,
            parent_pid: wrapper.pid,
            process_group_id: provider_pid,
            start_identity: provider_start_identity.clone(),
            command: executable.display().to_string(),
            quality: ProcessIdentityQuality::KernelBirthToken,
        };
        let binding = RunFamilyBinding {
            schema_version: 1,
            agent_run_id: run_id.clone(),
            reservation_epoch: 7,
            authority_digest: authority_digest.clone(),
            descriptor_digest: authority.descriptor_digest.clone(),
            wrapper_pid: wrapper.pid,
            wrapper_start_identity: wrapper.start_identity.clone(),
        };
        spool.publish_run_family_binding_once(&binding).unwrap();
        let make_family = |coverage| RunFamilyRecord {
            schema_version: 2,
            binding: binding.clone(),
            observed_at_unix: 10,
            coverage,
            wrapper_process: wrapper_process.clone(),
            provider_root: family_process.clone(),
            provider_executable_path: executable.clone(),
            provider_executable_digest: qualification.executable_digest.clone(),
            process_tree_digest: fixture_digest_json(std::slice::from_ref(&family_process)),
            process_tree: vec![family_process.clone()],
        };
        spool
            .write_run_family_record(&make_family(RunFamilyCoverage::Observing))
            .unwrap();
        let family = make_family(RunFamilyCoverage::Complete);
        if complete_family {
            spool.write_run_family_record(&family).unwrap();
        }
        let provider_tree = vec![
            ProviderProcessIdentity {
                pid: wrapper.pid,
                parent_pid: wrapper_process.parent_pid,
                process_group_id: wrapper_process.process_group_id,
                start_identity: wrapper.start_identity.clone(),
                identity_quality: ProcessIdentityQuality::KernelBirthToken,
            },
            ProviderProcessIdentity {
                pid: provider_pid,
                parent_pid: wrapper.pid,
                process_group_id: provider_pid,
                start_identity: provider_start_identity.clone(),
                identity_quality: ProcessIdentityQuality::KernelBirthToken,
            },
        ];
        let provider = ObservedProviderStart {
            agent_run_id: run_id.clone(),
            operation_id,
            provider_pid,
            provider_start_identity,
            executable_digest: qualification.executable_digest.clone(),
            process_tree_digest: fixture_digest_json(&provider_tree),
            process_tree_confirmed: true,
            process_tree: provider_tree,
        };
        provider
            .validate_complete_process_tree(&qualification)
            .unwrap();
        if complete_family {
            let observed_process = crate::run_step::ObservedProcess {
                pid: family_process.pid,
                parent_pid: family_process.parent_pid,
                process_group_id: family_process.process_group_id,
                start_identity: family_process.start_identity.clone(),
                command: family_process.command.clone(),
                identity_quality: "kernel_birth_token".into(),
            };
            let turn = TurnResult {
                receipt: crate::run_step::RunReceipt {
                    run_id: run_id.clone(),
                    attempt: 1,
                    provider: AgentAdapter::Codex,
                    effective_permission_mode: qualification.permission_mode.clone(),
                    conversation_id: None,
                    provider_version: Some(qualification.provider_version.clone()),
                    capability_receipt_digest: Some(qualification_digest),
                    schema_projection,
                    launch_pid_hint: Some(provider.provider_pid),
                    exit_code: None,
                    timed_out: false,
                    cancellation_signal: Some(1),
                    cleanup: CleanupState::Confirmed,
                    cleanup_detail: None,
                    processes: vec![observed_process],
                    result_digest: None,
                    provider_result_failure: None,
                    provider_process_failure: None,
                    outcome: TurnOutcome::Cancelled,
                },
                structured_result: None,
            };
            let terminal = spool.publish_turn_result_once(&start, turn).unwrap();
            assert!(matches!(terminal.receipt.outcome, TurnOutcome::Cancelled));
        }
        let slot_owner_id = run_id.to_string();

        CompletedBlockLossFixture {
            store,
            generation,
            run: crate::store::agent_recovery::RecoverableAgentRun {
                agent_run_id: run_id,
                current_generation: generation,
                previous_generation: 0,
                authority,
                authority_digest,
                agent_state: "launch_pending".into(),
                started_at_unix: None,
                launch_state: "awaiting_provider".into(),
                process_identity_json: None,
                wrapper_identity_json: Some(serde_json::to_string(&wrapper).unwrap()),
                provider_tree_json: None,
                pool: "agent".into(),
                slot_index: 0,
                reservation_epoch: 7,
                slot_disposition: "unknown".into(),
            },
            wrapper,
            provider,
            slot_owner_id,
        }
    }

    pub(crate) fn test_execution_slot_disposition(store: &ConfigStore, owner_id: &str) -> String {
        store
            .connection
            .query_row(
                "SELECT disposition FROM execution_slots WHERE owner_id=?1",
                [owner_id],
                |row| row.get(0),
            )
            .unwrap()
    }

    pub(crate) fn test_insert_unknown_execution_slot(
        store: &mut ConfigStore,
        project_id: &str,
        owner_id: &str,
        slot_index: u32,
        reservation_epoch: u64,
    ) {
        store.connection.execute(
            "INSERT INTO execution_slots(pool,slot_index,project_id,owner_kind,owner_id,reservation_epoch,controller_generation,disposition) VALUES ('agent',?1,?2,'agent_run',?3,?4,0,'unknown')",
            rusqlite::params![slot_index, project_id, owner_id, reservation_epoch],
        ).unwrap();
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
                rex_endpoint: None,
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
                    super::MAX_PROFILE_QUALIFICATION_CANDIDATES + 1,
                )
                .is_err()
        );
        let reviewer_message_id = "review-transition-message";
        let reviewer_payload = serde_json::json!({
            "target": "reviewer",
            "revision": 1,
            "message_id": reviewer_message_id,
        });
        store.connection.execute(
            "INSERT INTO role_wake_inputs(project_id,role_session_id,source_type,source_id,source_revision,priority,payload_json,lifecycle,created_at_unix) VALUES (?1,'project:project-a:supervisor','ticket_run_transition',?2,1,10,?3,'pending',1)",
            rusqlite::params![project.as_str(), reviewer_message_id, reviewer_payload.to_string()],
        ).unwrap();
        let run_id = AgentRunId::parse("run-1").unwrap();
        let source_evidence_id = "e".repeat(64);
        let wake = crate::agent_api::AgentWakeItem {
            wake_input_id: 1,
            source_type: "ticket_run_transition".into(),
            source_id: reviewer_message_id.into(),
            source_revision: 1,
            priority: 10,
            payload_json: reviewer_payload.clone(),
            host_artifact_source_evidence_ids: vec![source_evidence_id.clone()],
            host_artifacts: vec![crate::agent_api::HostArtifactLocator {
                artifact_id: crate::domain::ids::ArtifactId::parse("a".repeat(64)).unwrap(),
                kind: crate::engine::orchestration::RoleArtifactKind::TestReceipt,
                schema_version: 1,
                digest: digest('b'),
                bytes: 12,
                path: format!(".rex-artifacts/sha256/{}/{}", "aa", "a".repeat(64)),
                source_run_id: run_id.as_str().into(),
                source_evidence_id,
                source_authority_digest: digest('c'),
            }],
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
        let profile_digest = crate::store::agent_profile_digest(
            store
                .load_snapshot("factory")
                .unwrap()
                .unwrap()
                .config
                .profiles
                .get(&profile_id)
                .unwrap(),
        )
        .unwrap();
        let result_schema: serde_json::Value = serde_json::from_slice(
            &std::fs::read(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("schemas/agent-results/supervisor-v1.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let result_schema_digest = Digest::parse(format!(
            "{:x}",
            sha2::Sha256::digest(serde_json::to_vec(&result_schema).unwrap())
        ))
        .unwrap();
        let mut reservation = AgentLaunchReservation {
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
            worker_assignment: None,
            rex_view_id: view.view_id.clone(),
            runtime_binary_digest: digest('4'),
            environment_snapshot_id: digest('5'),
            profile_id,
            profile_digest,
            instruction_digest: digest('6'),
            result_schema_digest,
            wake_snapshot,
            qualification_receipt_digest: q_digest,
            descriptor_path: std::fs::canonicalize(temp.path())
                .unwrap()
                .join("run-1.json"),
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
        reservation.mailbox_capability_digest = Digest::parse(
            crate::mailbox::MailboxDescriptor::capability_digest(
                reservation.agent_run_id.as_str(),
                reservation.mailbox_expires_at_unix,
                crate::mailbox::MailboxLimits {
                    max_request_bytes: usize::try_from(reservation.mailbox_max_request_bytes)
                        .unwrap(),
                    max_pending_requests: usize::try_from(reservation.mailbox_max_pending_requests)
                        .unwrap(),
                },
            )
            .unwrap(),
        )
        .unwrap();
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
        store
            .connection
            .execute(
                "UPDATE project_runtimes SET project_epoch=2 WHERE project_id=?1",
                [project.as_str()],
            )
            .unwrap();
        reservation.project_epoch = 2;
        let mut worker_without_provenance = reservation.clone();
        worker_without_provenance.role = Role::Worker;
        worker_without_provenance.ticket_run_id =
            Some(crate::domain::ids::TicketRunId::parse("ticket-run-a").unwrap());
        worker_without_provenance.ticket_revision = Some(Revision(1));
        assert!(
            store
                .prepare_role_launch(&worker_without_provenance)
                .unwrap_err()
                .contains("opaque accepted-plan")
        );
        assert!(matches!(
            store.prepare_role_launch(&reservation).unwrap(),
            LaunchPreparationOutcome::Prepared { .. }
        ));
        crate::start_agent::register_reserved_mailbox(&mut store, generation, &reservation)
            .unwrap();
        let mailbox_descriptor =
            std::fs::read(reservation.mailbox_directory.join("descriptor.json")).unwrap();
        assert_eq!(
            format!("{:x}", sha2::Sha256::digest(&mailbox_descriptor)),
            reservation.mailbox_capability_digest.as_str()
        );
        let registration = store
            .agent_mailbox_registration(reservation.agent_run_id.as_str())
            .unwrap()
            .unwrap();
        assert_eq!(
            registration.capability_digest,
            reservation.mailbox_capability_digest.as_str()
        );
        assert_eq!(
            registration.canonical_directory,
            std::fs::canonicalize(&reservation.mailbox_directory)
                .unwrap()
                .display()
                .to_string()
        );
        crate::start_agent::register_reserved_mailbox(&mut store, generation, &reservation)
            .unwrap();
        assert!(!reservation.descriptor_path.exists());
        assert!(
            crate::start_agent::register_reserved_mailbox(&mut store, generation + 1, &reservation)
                .is_err()
        );
        let mut conflicting_mailbox = reservation.clone();
        conflicting_mailbox.mailbox_max_request_bytes += 1;
        conflicting_mailbox.mailbox_capability_digest = Digest::parse(
            crate::mailbox::MailboxDescriptor::capability_digest(
                conflicting_mailbox.agent_run_id.as_str(),
                conflicting_mailbox.mailbox_expires_at_unix,
                crate::mailbox::MailboxLimits {
                    max_request_bytes: usize::try_from(
                        conflicting_mailbox.mailbox_max_request_bytes,
                    )
                    .unwrap(),
                    max_pending_requests: usize::try_from(
                        conflicting_mailbox.mailbox_max_pending_requests,
                    )
                    .unwrap(),
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert!(
            crate::start_agent::register_reserved_mailbox(
                &mut store,
                generation,
                &conflicting_mailbox
            )
            .is_err()
        );

        // A launch authority binds the semantic wake snapshot digest. The serialized envelope
        // includes that digest field itself, so hashing the JSON would produce a different value.
        let mut authority = crate::launch::AgentLaunchAuthority {
            agent_run_id: reservation.agent_run_id.clone(),
            project_id: reservation.project_id.clone(),
            role: reservation.role,
            role_session_id: reservation.role_session_id.clone(),
            parent_run_id: reservation.parent_run_id.clone(),
            parent_role: reservation.parent_role,
            ticket_run_id: reservation.ticket_run_id.clone(),
            ticket_revision: reservation.ticket_revision,
            config_revision: reservation.config_revision,
            config_digest: reservation.config_digest.clone(),
            attempt: reservation.attempt,
            run_epoch: reservation.run_epoch,
            controller_generation: reservation.controller_generation,
            operation_id: reservation.operation_id.clone(),
            operation_recipe_id: reservation.operation_recipe_id.clone(),
            rex_view_id: reservation.rex_view_id.clone(),
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
            rex_server_identity: view.rex_server_identity.clone(),
            rex_session_id: view.rex_session_id.clone(),
            rex_window_id: view.rex_window_id.clone(),
            rex_block_id: "block-run-1".into(),
            workspace_path: reservation.workspace_path.clone(),
            control_dir: reservation.control_dir.clone(),
            mailbox_capability_digest: reservation.mailbox_capability_digest.clone(),
        };
        let mut package = crate::store::agent_results::tests::reviewer_run_step_package(
            &authority,
            result_schema,
        );
        package.execution_slot_epoch = reservation.project_epoch;
        authority.descriptor_digest = package.publish_once(&reservation.descriptor_path).unwrap();
        store
            .register_agent_launch_authority(generation, &authority)
            .unwrap();
        store
            .register_rex_view_block(
                generation,
                &crate::launch::RexViewBlock {
                    view_id: reservation.rex_view_id.clone(),
                    block_id: authority.rex_block_id.clone(),
                    agent_run_id: Some(reservation.agent_run_id.clone()),
                    role: Some(reservation.role),
                    ownership: crate::launch::RexBlockOwnership::Factory,
                    lifecycle: crate::launch::RexBlockLifecycle::Active,
                    process_absent_confirmed: false,
                    retained_until_unix: None,
                },
            )
            .unwrap();
        store
            .finalize_agent_launch_reservation(
                generation,
                &reservation.agent_run_id,
                &reservation.digest().unwrap(),
                &authority,
            )
            .unwrap();
        let start_request = crate::launch::AgentStartRequest {
            schema_version: LAUNCH_SCHEMA_VERSION,
            operation_id: authority.operation_id.clone(),
            agent_run_id: authority.agent_run_id.clone(),
            project_id: authority.project_id.clone(),
            controller_generation: generation,
            descriptor_digest: authority.descriptor_digest.clone(),
            runtime_binary_digest: authority.runtime_binary_digest.clone(),
            environment_snapshot_id: authority.environment_snapshot_id.clone(),
            qualification_receipt_digest: authority.qualification_receipt_digest.clone(),
            wrapper_pid: 42,
            wrapper_start_identity: "wrapper-start-1".into(),
            rex_session_id: authority.rex_session_id.clone(),
            rex_block_id: authority.rex_block_id.clone(),
        };
        assert_eq!(store.persisted_start_receipt(&start_request).unwrap(), None);
        let receipt = store
            .authorize_agent_start(
                generation,
                &start_request,
                &crate::launch::ObservedWrapperIdentity {
                    pid: start_request.wrapper_pid,
                    start_identity: start_request.wrapper_start_identity.clone(),
                    rex_session_id: start_request.rex_session_id.clone(),
                    rex_block_id: start_request.rex_block_id.clone(),
                    runtime_binary_digest: start_request.runtime_binary_digest.clone(),
                },
            )
            .unwrap();
        assert_eq!(receipt.decision, crate::launch::LaunchDecision::Accepted);
        assert_eq!(
            store.persisted_start_receipt(&start_request).unwrap(),
            Some(receipt.clone())
        );
        let spool = crate::run_step_spool::RunStepSpool::open(&reservation.control_dir).unwrap();
        spool.publish_start_once(start_request.clone()).unwrap();
        let rex_script = temp.path().join("rex-finalize-start-fixture");
        std::fs::write(
            &rex_script,
            "#!/bin/sh\ncase \"$*\" in\n  *\"whoami --json\"*) printf '%s\\n' '{\"endpoint\":\"unix:///tmp/rex-test.sock\",\"instance_id\":\"rex-fixture\",\"host_id\":\"fixture-host\",\"rex_version\":\"1.2.3\"}' ;;\n  *\"api list --json\"*) printf '%s\\n' '{\"methods\":{\"session.view\":{},\"session.new_window\":{},\"session.new_split\":{},\"session.focus_block\":{},\"session.zoom_block\":{},\"block.close\":{}}}' ;;\n  *) exit 3 ;;\nesac\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&rex_script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let rex = crate::adapters::rex::RexCliTransport::connect(
            &rex_script,
            &[],
            "unix:///tmp/rex-test.sock".into(),
            "rex-fixture".into(),
            "session".into(),
            BTreeMap::new(),
        )
        .unwrap();
        let observed_block = crate::adapters::rex::RexContextBlock {
            server_instance_id: "rex-fixture".into(),
            session_id: "session".into(),
            window_id: "window".into(),
            block_id: "block-run-1".into(),
            label: String::new(),
            flavor: String::new(),
        };
        let mut wrong_slot_package = package.clone();
        wrong_slot_package.execution_slot_epoch = reservation.run_epoch;
        assert!(
            crate::run_step_cli::finalize_and_ack_start(
                &mut store,
                generation,
                &reservation,
                &wrong_slot_package,
                &observed_block,
                &rex,
            )
            .is_err()
        );
        crate::run_step_cli::finalize_and_ack_start(
            &mut store,
            generation,
            &reservation,
            &package,
            &observed_block,
            &rex,
        )
        .unwrap();
        let family_binding = spool.read_run_family_binding().unwrap();
        assert_eq!(family_binding.reservation_epoch, 2);
        let wrapper_package: crate::run_step_package::RunStepPackage =
            crate::protocol::parse_unique(&std::fs::read(&reservation.descriptor_path).unwrap())
                .unwrap();
        crate::run_step_cli::validate_run_family_binding(
            &wrapper_package,
            &family_binding,
            &start_request,
            start_request.wrapper_pid,
            &start_request.wrapper_start_identity,
        )
        .unwrap();
        let mut wrong_slot_binding = family_binding;
        wrong_slot_binding.reservation_epoch = reservation.run_epoch;
        assert!(
            crate::run_step_cli::validate_run_family_binding(
                &wrapper_package,
                &wrong_slot_binding,
                &start_request,
                start_request.wrapper_pid,
                &start_request.wrapper_start_identity,
            )
            .is_err()
        );
        store
            .connection
            .execute(
                "UPDATE agent_runs SET state='running' WHERE agent_run_id=?1",
                [reservation.agent_run_id.as_str()],
            )
            .unwrap();
        let artifact_store =
            crate::artifacts::ArtifactStore::open(&temp.path().join("artifacts")).unwrap();
        let mut mailbox_cursor = None;
        store
            .connection
            .execute(
                "UPDATE rex_view_blocks SET lifecycle='unknown' WHERE block_id='block-run-1'",
                [],
            )
            .unwrap();
        assert!(
            !crate::runtime_services::process_one_registered_agent_request(
                &mut store,
                generation,
                crate::store::now_unix().unwrap(),
                &artifact_store,
                &Default::default(),
                &mut mailbox_cursor,
            )
            .unwrap()
        );
        store
            .connection
            .execute(
                "UPDATE rex_view_blocks SET lifecycle='active' WHERE block_id='block-run-1'",
                [],
            )
            .unwrap();
        std::fs::remove_file(reservation.mailbox_directory.join("descriptor.json")).unwrap();
        assert!(
            !crate::runtime_services::process_one_registered_agent_request(
                &mut store,
                generation,
                crate::store::now_unix().unwrap(),
                &artifact_store,
                &Default::default(),
                &mut mailbox_cursor,
            )
            .unwrap()
        );
        assert!(
            crate::runtime_services::process_one_registered_agent_request(
                &mut store,
                generation + 1,
                crate::store::now_unix().unwrap(),
                &artifact_store,
                &Default::default(),
                &mut mailbox_cursor,
            )
            .is_err()
        );
        store
            .connection
            .execute(
                "UPDATE agent_runs SET controller_generation=?2 WHERE agent_run_id=?1",
                rusqlite::params![reservation.agent_run_id.as_str(), generation + 1],
            )
            .unwrap();
        assert!(
            !crate::runtime_services::process_one_registered_agent_request(
                &mut store,
                generation,
                crate::store::now_unix().unwrap(),
                &artifact_store,
                &Default::default(),
                &mut mailbox_cursor,
            )
            .unwrap()
        );
        store
            .connection
            .execute(
                "UPDATE agent_runs SET state='launch_pending',controller_generation=?2 WHERE agent_run_id=?1",
                rusqlite::params![reservation.agent_run_id.as_str(), generation],
            )
            .unwrap();
        let wake_state: (String, Option<String>) = store.connection.query_row(
            "SELECT lifecycle,consuming_agent_run_id FROM role_wake_inputs WHERE wake_input_id=1",
            [], |row| Ok((row.get(0)?, row.get(1)?)),
        ).unwrap();
        assert_eq!(wake_state, ("assigned".into(), Some("run-1".into())));
        let mut unconfirmed = ObservedProviderStart {
            agent_run_id: authority.agent_run_id.clone(),
            operation_id: authority.operation_id.clone(),
            provider_pid: 100,
            provider_start_identity: "provider-start".into(),
            executable_digest: qualification.executable_digest.clone(),
            process_tree_digest: digest('a'),
            process_tree_confirmed: false,
            process_tree: Vec::new(),
        };
        assert!(
            store
                .confirm_provider_started(generation, &unconfirmed)
                .is_err()
        );
        let unchanged: String = store
            .connection
            .query_row(
                "SELECT lifecycle FROM role_wake_inputs WHERE wake_input_id=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(unchanged, "assigned");
        unconfirmed.process_tree_confirmed = true;
        unconfirmed.process_tree = vec![
            ProviderProcessIdentity {
                pid: 42,
                parent_pid: 1,
                process_group_id: 42,
                start_identity: "wrapper-start-1".into(),
                identity_quality: crate::process::ProcessIdentityQuality::KernelBirthToken,
            },
            ProviderProcessIdentity {
                pid: 100,
                parent_pid: 42,
                process_group_id: 100,
                start_identity: "provider-start".into(),
                identity_quality: crate::process::ProcessIdentityQuality::KernelBirthToken,
            },
        ];
        unconfirmed.process_tree_digest = Digest::parse(format!(
            "{:x}",
            sha2::Sha256::digest(serde_json::to_vec(&unconfirmed.process_tree).unwrap())
        ))
        .unwrap();
        store
            .confirm_provider_started(generation, &unconfirmed)
            .unwrap();
        let consumed: String = store
            .connection
            .query_row(
                "SELECT lifecycle FROM role_wake_inputs WHERE wake_input_id=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(consumed, "consumed");

        store
            .connection
            .execute(
                "INSERT INTO execution_slots(pool,slot_index,owner_kind,owner_id,reservation_epoch,controller_generation,disposition)
                 VALUES ('rex_projects_hook',7,'agent_run','unrelated-run',99,?1,'unknown')",
                [generation],
            )
            .unwrap();
        assert_eq!(
            store
                .record_agent_block_close_event(
                    generation,
                    "rex-fixture",
                    "session",
                    "unrelated-block",
                    20,
                )
                .unwrap(),
            None
        );
        assert_eq!(
            store
                .record_agent_block_close_event(
                    generation,
                    "rex-fixture",
                    "session",
                    "block-run-1",
                    21,
                )
                .unwrap(),
            Some(authority.agent_run_id.clone())
        );
        let recoverable = store
            .recoverable_agent_runs(generation, 8)
            .unwrap()
            .into_iter()
            .find(|run| run.agent_run_id == authority.agent_run_id)
            .unwrap();
        let make_cleanup_snapshot = |run: &super::super::agent_recovery::RecoverableAgentRun,
                                     process_tree: Vec<crate::process::ProcessIdentity>,
                                     cleanup_covered: bool,
                                     observed_at_unix: i64| {
            let provider: ObservedProviderStart = crate::protocol::parse_unique(
                run.provider_tree_json.as_deref().unwrap().as_bytes(),
            )
            .unwrap();
            let process_tree_digest = Digest::parse(format!(
                "{:x}",
                sha2::Sha256::digest(serde_json::to_vec(&process_tree).unwrap())
            ))
            .unwrap();
            crate::run_step_spool::BlockLossCleanupSnapshot {
                schema_version: crate::run_step_spool::BLOCK_LOSS_SNAPSHOT_VERSION,
                agent_run_id: run.agent_run_id.clone(),
                reservation_epoch: run.reservation_epoch,
                authority_digest: run.authority_digest.clone(),
                launch_tree_digest: provider.process_tree_digest,
                observed_at_unix,
                cleanup_covered,
                process_tree,
                process_tree_digest,
            }
        };
        let invalid_digest = Digest::parse("f".repeat(64)).unwrap();
        let mut invalid_snapshot = make_cleanup_snapshot(
            &recoverable,
            vec![crate::process::ProcessIdentity {
                pid: 42,
                parent_pid: 1,
                process_group_id: 42,
                start_identity: "wrapper-start-1".into(),
                command: String::new(),
                quality: crate::process::ProcessIdentityQuality::KernelBirthToken,
            }],
            true,
            22,
        );
        invalid_snapshot.process_tree_digest = invalid_digest;
        assert!(
            store
                .reconcile_missing_agent_block(generation, &recoverable, 22, &invalid_snapshot, &[])
                .is_err()
        );
        let mut without_provider = recoverable.clone();
        let mut provider: ObservedProviderStart = crate::protocol::parse_unique(
            without_provider
                .provider_tree_json
                .as_deref()
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        provider.process_tree.retain(|process| process.pid == 42);
        provider.process_tree_digest = Digest::parse(format!(
            "{:x}",
            sha2::Sha256::digest(serde_json::to_vec(&provider.process_tree).unwrap())
        ))
        .unwrap();
        without_provider.provider_tree_json = Some(serde_json::to_string(&provider).unwrap());
        let providerless_snapshot = make_cleanup_snapshot(
            &without_provider,
            vec![crate::process::ProcessIdentity {
                pid: 42,
                parent_pid: 1,
                process_group_id: 42,
                start_identity: "wrapper-start-1".into(),
                command: String::new(),
                quality: crate::process::ProcessIdentityQuality::KernelBirthToken,
            }],
            true,
            22,
        );
        assert!(
            store
                .reconcile_missing_agent_block(
                    generation,
                    &without_provider,
                    22,
                    &providerless_snapshot,
                    &[],
                )
                .is_err()
        );
        let mut without_wrapper = recoverable.clone();
        let mut provider: ObservedProviderStart = crate::protocol::parse_unique(
            without_wrapper
                .provider_tree_json
                .as_deref()
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        provider.process_tree.retain(|process| process.pid == 100);
        provider.process_tree_digest = Digest::parse(format!(
            "{:x}",
            sha2::Sha256::digest(serde_json::to_vec(&provider.process_tree).unwrap())
        ))
        .unwrap();
        without_wrapper.provider_tree_json = Some(serde_json::to_string(&provider).unwrap());
        let wrapperless_snapshot = make_cleanup_snapshot(
            &without_wrapper,
            vec![crate::process::ProcessIdentity {
                pid: 100,
                parent_pid: 42,
                process_group_id: 100,
                start_identity: "provider-start".into(),
                command: String::new(),
                quality: crate::process::ProcessIdentityQuality::KernelBirthToken,
            }],
            true,
            22,
        );
        assert!(
            store
                .reconcile_missing_agent_block(
                    generation,
                    &without_wrapper,
                    22,
                    &wrapperless_snapshot,
                    &[],
                )
                .is_err()
        );
        let state_before_valid_observation: String = store
            .connection
            .query_row(
                "SELECT disposition FROM execution_slots WHERE owner_id=?1",
                [authority.agent_run_id.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(state_before_valid_observation, "launch_pending");
        let surviving_provider = crate::process::ProcessIdentity {
            pid: 100,
            parent_pid: 42,
            process_group_id: 100,
            start_identity: "provider-start".into(),
            command: "/usr/bin/codex".into(),
            quality: crate::process::ProcessIdentityQuality::KernelBirthToken,
        };
        let launch_tree = crate::protocol::parse_unique::<ObservedProviderStart>(
            recoverable
                .provider_tree_json
                .as_deref()
                .unwrap()
                .as_bytes(),
        )
        .unwrap()
        .process_tree
        .iter()
        .map(|process| crate::process::ProcessIdentity {
            pid: process.pid,
            parent_pid: process.parent_pid,
            process_group_id: process.process_group_id,
            start_identity: process.start_identity.clone(),
            command: String::new(),
            quality: process.identity_quality,
        })
        .collect::<Vec<_>>();
        let snapshot_with_survivor = make_cleanup_snapshot(&recoverable, launch_tree, false, 22);
        assert!(
            !store
                .reconcile_missing_agent_block(
                    generation,
                    &recoverable,
                    22,
                    &snapshot_with_survivor,
                    &[surviving_provider],
                )
                .unwrap()
        );
        let retained: String = store
            .connection
            .query_row(
                "SELECT disposition FROM execution_slots WHERE owner_id=?1",
                [authority.agent_run_id.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        let unrelated: String = store
            .connection
            .query_row(
                "SELECT disposition FROM execution_slots WHERE owner_id='unrelated-run'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(retained, "launch_pending");
        assert_eq!(unrelated, "unknown");
        assert_eq!(
            store
                .missing_block_survival_age_seconds(&recoverable, 26)
                .unwrap(),
            4
        );
        assert!(
            store
                .reconcile_missing_agent_block(
                    generation,
                    &recoverable,
                    26,
                    &snapshot_with_survivor,
                    &[],
                )
                .is_err()
        );
        let mut completed_snapshot = snapshot_with_survivor;
        completed_snapshot.cleanup_covered = true;
        let disposition = crate::agent_recovery::observe_after_recovery_marker(
            &mut store,
            generation,
            &recoverable,
            26,
            |store| {
                if store.reconcile_missing_agent_block(
                    generation,
                    &recoverable,
                    26,
                    &completed_snapshot,
                    &[],
                )? {
                    Ok(crate::agent_recovery::AgentRecoveryDisposition::BlockLossTerminal)
                } else {
                    Err("expected terminal block-loss reconciliation".into())
                }
            },
        )
        .unwrap();
        assert_eq!(
            disposition,
            crate::agent_recovery::AgentRecoveryDisposition::BlockLossTerminal
        );
        let observation_epoch: u64 = store
            .connection
            .query_row(
                "SELECT reservation_epoch FROM agent_run_recovery_observations WHERE agent_run_id=?1",
                [authority.agent_run_id.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(observation_epoch, recoverable.reservation_epoch);
        let released: String = store
            .connection
            .query_row(
                "SELECT disposition FROM execution_slots WHERE owner_id=?1",
                [authority.agent_run_id.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        let unrelated: String = store
            .connection
            .query_row(
                "SELECT disposition FROM execution_slots WHERE owner_id='unrelated-run'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(released, "released");
        assert_eq!(unrelated, "unknown");
        let persisted_role: String = store
            .connection
            .query_row(
                "SELECT role FROM agent_runs WHERE agent_run_id='run-1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(persisted_role, "supervisor");
        assert!(matches!(
            store.prepare_role_launch(&reservation).unwrap(),
            LaunchPreparationOutcome::Prepared { .. }
        ));
        drop(store);
        let mut reopened = ConfigStore::open_test(temp.path()).unwrap();
        let (snapshot_digest, snapshot_json): (String, String) = reopened
            .connection
            .query_row(
                "SELECT snapshot_digest,snapshot_json FROM agent_wake_context WHERE agent_run_id='run-1'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let loaded_wake: crate::agent_api::AgentWakeSnapshot =
            crate::protocol::parse_unique(snapshot_json.as_bytes()).unwrap();
        loaded_wake.validate().unwrap();
        assert_eq!(snapshot_digest, reservation.wake_snapshot.digest.as_str());
        assert_eq!(loaded_wake, reservation.wake_snapshot);
        assert_eq!(loaded_wake.inputs[0].payload_json, reviewer_payload);
        assert_eq!(
            reopened.persisted_start_receipt(&start_request).unwrap(),
            Some(receipt)
        );
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
        next.wake_snapshot.inputs[0].source_type = "test".into();
        next.wake_snapshot.inputs[0].source_id = "event-2".into();
        next.wake_snapshot.inputs[0].payload_json = serde_json::json!({"kind":"start"});
        next.wake_snapshot.inputs[0]
            .host_artifact_source_evidence_ids
            .clear();
        next.wake_snapshot.inputs[0].host_artifacts.clear();
        next.wake_snapshot.digest = next.wake_snapshot.content_digest().unwrap();
        let next_preparation = reopened.prepare_role_launch(&next).unwrap();
        assert!(
            matches!(&next_preparation, LaunchPreparationOutcome::Prepared { .. }),
            "unexpected next launch preparation: {next_preparation:?}"
        );
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
