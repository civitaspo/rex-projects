//! Durable, bounded machine-wide controller shutdown.
//!
//! This is intentionally independent of Project and TicketRun desired lifecycle.

use rusqlite::{OptionalExtension, TransactionBehavior, params};
use sha2::{Digest as _, Sha256};

use crate::process::ProcessIdentityQuality;

use super::{ConfigStore, validate_active_generation};

pub const DEFAULT_MACHINE_SHUTDOWN_GRACE_SECONDS: i64 = 30;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MachineShutdownCause {
    Command,
    Sigint,
    Sigterm,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MachineShutdown {
    pub request_id: String,
    pub original_generation: u64,
    pub owner_generation: u64,
    pub cause: MachineShutdownCause,
    pub requested_at_unix: i64,
    pub deadline_unix: i64,
    pub status: MachineShutdownStatus,
    pub last_error: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MachineShutdownStatus {
    Draining,
    Stopped,
    Incomplete,
}

pub(crate) fn migrate_v23(connection: &rusqlite::Connection) -> Result<(), String> {
    let tx = connection
        .unchecked_transaction()
        .map_err(|error| error.to_string())?;
    let version: i64 = tx
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| error.to_string())?;
    if version != 22 {
        return Err(format!(
            "machine shutdown migration requires schema 22, found {version}"
        ));
    }
    tx.execute_batch(
        "CREATE TABLE machine_shutdowns (
            request_id TEXT PRIMARY KEY,
            original_generation INTEGER NOT NULL CHECK(original_generation > 0),
            owner_generation INTEGER NOT NULL CHECK(owner_generation > 0),
            cause TEXT NOT NULL CHECK(cause IN ('command','sigint','sigterm')),
            requested_at_unix INTEGER NOT NULL,
            deadline_unix INTEGER NOT NULL CHECK(deadline_unix > requested_at_unix),
            status TEXT NOT NULL CHECK(status IN ('draining','stopped','incomplete')),
            last_error TEXT,
            updated_at_unix INTEGER NOT NULL
        );
        CREATE UNIQUE INDEX machine_shutdown_one_active
            ON machine_shutdowns(status) WHERE status IN ('draining','incomplete');
        INSERT INTO schema_migrations(version,applied_at_unix) VALUES (23,unixepoch());
        PRAGMA user_version = 23;",
    )
    .map_err(|error| error.to_string())?;
    tx.commit().map_err(|error| error.to_string())
}

pub(crate) fn validate_v23_schema(connection: &rusqlite::Connection) -> Result<(), String> {
    let recorded: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=23)",
            [],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    if !recorded {
        return Err("schema 23 migration record is missing".into());
    }
    let exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='machine_shutdowns')",
        [], |row| row.get(0),
    ).map_err(|error| error.to_string())?;
    if exists {
        Ok(())
    } else {
        Err("schema 23 is missing machine shutdown state".into())
    }
}

impl ConfigStore {
    /// Acknowledge a stop request and establish its fixed deadline in the caller's transaction.
    pub(crate) fn begin_machine_shutdown_in_transaction(
        tx: &rusqlite::Transaction<'_>,
        generation: u64,
        request_id: &str,
        cause: MachineShutdownCause,
        now_unix: i64,
        grace_seconds: u64,
    ) -> Result<(), String> {
        if request_id.trim().is_empty() || !(1..=300).contains(&grace_seconds) {
            return Err("machine shutdown request ID or grace period is invalid".into());
        }
        let active: Option<String> = tx
            .query_row(
                "SELECT request_id FROM machine_shutdowns WHERE status IN ('draining','incomplete')",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if let Some(active) = active {
            if active != request_id {
                return Err("another machine shutdown is already draining".into());
            }
            return Ok(());
        }
        let deadline = now_unix
            .checked_add(grace_seconds as i64)
            .ok_or("machine shutdown deadline overflow")?;
        tx.execute(
            "INSERT INTO machine_shutdowns(request_id,original_generation,owner_generation,cause,requested_at_unix,deadline_unix,status,updated_at_unix)
             VALUES (?1,?2,?2,?3,?4,?5,'draining',?4)",
            params![request_id, generation, cause_name(cause), now_unix, deadline],
        ).map_err(|error| error.to_string())?;
        cancel_unstarted_launches(tx, generation, now_unix)?;
        Ok(())
    }

    /// Signal-driven shutdown has no control command; persist it before entering the drain.
    pub fn begin_signal_shutdown(
        &mut self,
        generation: u64,
        request_id: &str,
        cause: MachineShutdownCause,
        now_unix: i64,
        grace_seconds: u64,
    ) -> Result<MachineShutdown, String> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, generation)?;
        Self::begin_machine_shutdown_in_transaction(
            &tx,
            generation,
            request_id,
            cause,
            now_unix,
            grace_seconds,
        )?;
        let value = read_active(&tx)?.ok_or("machine shutdown barrier was not persisted")?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(value)
    }

    pub fn active_machine_shutdown(&self) -> Result<Option<MachineShutdown>, String> {
        read_active(&self.connection)
    }

    pub fn set_machine_shutdown_status(
        &mut self,
        generation: u64,
        request_id: &str,
        status: MachineShutdownStatus,
        error: Option<&str>,
        now_unix: i64,
    ) -> Result<(), String> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, generation)?;
        let changed = tx
            .execute(
                "UPDATE machine_shutdowns SET status=?3,last_error=?4,updated_at_unix=?5
             WHERE request_id=?1 AND owner_generation=?2 AND status IN ('draining','incomplete')",
                params![request_id, generation, status_name(status), error, now_unix],
            )
            .map_err(|error| error.to_string())?;
        if changed != 1 {
            return Err("machine shutdown is absent or no longer owned by this controller".into());
        }
        tx.commit().map_err(|error| error.to_string())
    }

    /// Count live process owners, not effects with a safely staged process result. Those effects
    /// remain durable and unsettled for ordinary controller replay after shutdown.
    pub fn machine_shutdown_unresolved_owners(&self) -> Result<u64, String> {
        let slots: u64 = self
            .connection
            .query_row(
                "SELECT COUNT(*) FROM execution_slots WHERE disposition!='released'",
                [],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        let total_host: u64 = self
            .connection
            .query_row(
                "SELECT COUNT(*) FROM host_effect_jobs WHERE state IN ('starting','running','unknown')",
                [],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        let host_records = self.host_jobs_in_states(&[
            crate::store::host_jobs::HostJobState::Starting,
            crate::store::host_jobs::HostJobState::Running,
            crate::store::host_jobs::HostJobState::Unknown {
                reason: String::new(),
            },
        ]);
        let drained_host_processes = host_records
            .map(|records| {
                records
                    .iter()
                    .filter(|record| {
                        record.process_receipt.as_ref().is_some_and(|receipt| {
                            receipt.cleanup_confirmed
                                && record.process_identity.as_ref().is_some_and(|identity| {
                                    identity.quality == ProcessIdentityQuality::KernelBirthToken
                                        && identity.pid > 0
                                        && identity.process_group_id == identity.pid
                                        && !identity.start_identity.trim().is_empty()
                                })
                        })
                    })
                    .count() as u64
            })
            .unwrap_or(0);
        let host = total_host.saturating_sub(drained_host_processes);
        let qualifications: u64 = self.connection.query_row(
            "SELECT COUNT(*) FROM provider_qualification_jobs WHERE status IN ('running','unknown')", [], |row| row.get(0),
        ).map_err(|error| error.to_string())?;
        Ok(slots.saturating_add(host).saturating_add(qualifications))
    }
}

/// The shutdown barrier and these cancellations commit together, before drain-only processing.
fn cancel_unstarted_launches(
    tx: &rusqlite::Transaction<'_>,
    generation: u64,
    now_unix: i64,
) -> Result<(), String> {
    let candidates = tx
        .prepare(
            "SELECT reservation_json,reservation_digest FROM agent_launch_reservations
         WHERE controller_generation=?1 AND lifecycle='reserved' AND launch_phase='not_started'",
        )
        .map_err(|error| error.to_string())?
        .query_map([generation], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    for (json, digest) in candidates {
        let Ok(reservation) =
            crate::protocol::parse_unique::<crate::launch::AgentLaunchReservation>(json.as_bytes())
        else {
            continue;
        };
        if reservation.controller_generation != generation
            || super::canonical_json(&reservation).as_deref() != Ok(json.as_str())
            || reservation
                .digest()
                .map(|value| value.as_str().to_owned())
                .as_deref()
                != Ok(digest.as_str())
        {
            continue;
        }
        let request = super::canonical_json(&crate::launch::StartAgentEffectPayload {
            schema_version: crate::launch::LAUNCH_SCHEMA_VERSION,
            agent_run_id: reservation.agent_run_id.clone(),
            launch_reservation_digest: crate::domain::ids::Digest::parse(digest.clone())?,
        })?;
        let request_digest = format!("{:x}", Sha256::digest(request.as_bytes()));
        let run_id = reservation.agent_run_id.as_str();
        let operation_id = reservation.operation_id.as_str();
        let eligible: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM agent_launch_reservations r
             JOIN agent_runs a USING(agent_run_id)
             JOIN effects e ON e.operation_id=r.operation_id
             JOIN execution_slots s ON s.owner_kind='agent_run' AND s.owner_id=r.agent_run_id
             WHERE r.agent_run_id=?1 AND r.project_id=?2 AND r.operation_id=?3
               AND r.controller_generation=?4 AND r.project_epoch=?5
               AND r.reservation_digest=?6 AND r.reservation_json=?7
               AND r.lifecycle='reserved' AND r.launch_phase='not_started'
               AND a.project_id=r.project_id AND a.launch_operation_id=r.operation_id
               AND a.controller_generation=r.controller_generation AND a.state='launch_pending'
               AND a.rex_session_id IS NULL AND a.rex_window_id IS NULL AND a.rex_block_id IS NULL
               AND a.process_identity_json IS NULL AND a.started_at_unix IS NULL AND a.finished_at_unix IS NULL
               AND e.project_id=r.project_id AND e.subject_type='agent_run' AND e.subject_id=r.agent_run_id
               AND e.kind='start_agent' AND e.logical_key='start-agent:'||r.agent_run_id
               AND e.request_json=?8 AND e.request_digest=?9 AND e.expected_revision IS NULL
               AND e.status='pending' AND e.attempt_count=0 AND e.owner_generation IS NULL AND e.receipt_json IS NULL
               AND s.pool=?10 AND s.slot_index=?11 AND s.project_id=r.project_id AND s.ticket_run_id IS ?12
               AND s.reservation_epoch=r.project_epoch AND s.controller_generation=r.controller_generation
               AND s.disposition='launch_pending' AND s.process_identity_json IS NULL
               AND (SELECT COUNT(*) FROM execution_slots WHERE owner_kind='agent_run' AND owner_id=r.agent_run_id)=1
               AND NOT EXISTS(SELECT 1 FROM agent_launch_authority WHERE agent_run_id=r.agent_run_id)
               AND NOT EXISTS(SELECT 1 FROM agent_launch_state WHERE agent_run_id=r.agent_run_id)
               AND NOT EXISTS(SELECT 1 FROM rex_view_blocks WHERE agent_run_id=r.agent_run_id))",
            params![run_id,reservation.project_id.as_str(),operation_id,generation,reservation.project_epoch,
                digest,json,request,request_digest,reservation.pool,reservation.slot_index,
                reservation.ticket_run_id.as_ref().map(|id| id.as_str())],
            |row| row.get(0),
        ).map_err(|error| error.to_string())?;
        if !eligible || !assigned_wakes_match_reservation(tx, &reservation)? {
            continue;
        }
        let effect_changed = tx.execute(
            "UPDATE effects SET status='cancelled',last_error='machine stopped before Agent launch' WHERE operation_id=?1",
            [operation_id],
        ).map_err(|error| error.to_string())?;
        let run_changed = tx
            .execute(
                "UPDATE agent_runs SET state='cancelled',finished_at_unix=?2 WHERE agent_run_id=?1",
                params![run_id, now_unix],
            )
            .map_err(|error| error.to_string())?;
        let reservation_changed = tx.execute(
            "UPDATE agent_launch_reservations SET lifecycle='cancelled',updated_at_unix=?2 WHERE agent_run_id=?1",
            params![run_id,now_unix],
        ).map_err(|error| error.to_string())?;
        let slot_changed = tx.execute(
            "UPDATE execution_slots SET disposition='released' WHERE pool=?1 AND slot_index=?2 AND owner_kind='agent_run' AND owner_id=?3",
            params![reservation.pool,reservation.slot_index,run_id],
        ).map_err(|error| error.to_string())?;
        if [
            effect_changed,
            run_changed,
            reservation_changed,
            slot_changed,
        ] != [1; 4]
        {
            return Err("unstarted launch cancellation did not update its exact owners".into());
        }
        for wake in &reservation.wake_snapshot.inputs {
            let changed = tx
                .execute(
                    "UPDATE role_wake_inputs SET lifecycle='pending',consuming_agent_run_id=NULL
                 WHERE wake_input_id=?1 AND consuming_agent_run_id=?2 AND lifecycle='assigned'",
                    params![wake.wake_input_id, run_id],
                )
                .map_err(|error| error.to_string())?;
            if changed != 1 {
                return Err(
                    "unstarted launch cancellation did not return its exact wake input".into(),
                );
            }
        }
    }
    Ok(())
}

fn assigned_wakes_match_reservation(
    tx: &rusqlite::Transaction<'_>,
    reservation: &crate::launch::AgentLaunchReservation,
) -> Result<bool, String> {
    let count: usize = tx
        .query_row(
            "SELECT COUNT(*) FROM role_wake_inputs WHERE consuming_agent_run_id=?1",
            [reservation.agent_run_id.as_str()],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    if count != reservation.wake_snapshot.inputs.len() {
        return Ok(false);
    }
    for wake in &reservation.wake_snapshot.inputs {
        let payload: Option<String> = tx.query_row(
            "SELECT payload_json FROM role_wake_inputs WHERE wake_input_id=?1
             AND project_id=?2 AND role_session_id=?3 AND consuming_agent_run_id=?4 AND lifecycle='assigned'
             AND source_type=?5 AND source_id=?6 AND source_revision=?7 AND priority=?8",
            params![wake.wake_input_id,reservation.project_id.as_str(),reservation.role_session_id,
                reservation.agent_run_id.as_str(),wake.source_type,wake.source_id,wake.source_revision,wake.priority],
            |row| row.get(0),
        ).optional().map_err(|error| error.to_string())?;
        if payload.and_then(|json| {
            crate::protocol::parse_unique::<serde_json::Value>(json.as_bytes()).ok()
        }) != Some(wake.payload_json.clone())
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn read_active(connection: &rusqlite::Connection) -> Result<Option<MachineShutdown>, String> {
    type ShutdownRow = (String, u64, u64, String, i64, i64, String, Option<String>);
    let row: Option<ShutdownRow> = connection.query_row(
        "SELECT request_id,original_generation,owner_generation,cause,requested_at_unix,deadline_unix,status,last_error
         FROM machine_shutdowns WHERE status IN ('draining','incomplete')", [],
        |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?)),
    ).optional().map_err(|error| error.to_string())?;
    row.map(
        |(
            request_id,
            original_generation,
            owner_generation,
            cause,
            requested_at_unix,
            deadline_unix,
            status,
            last_error,
        )| {
            Ok(MachineShutdown {
                request_id,
                original_generation,
                owner_generation,
                cause: parse_cause(&cause)?,
                requested_at_unix,
                deadline_unix,
                status: parse_status(&status)?,
                last_error,
            })
        },
    )
    .transpose()
}

fn cause_name(cause: MachineShutdownCause) -> &'static str {
    match cause {
        MachineShutdownCause::Command => "command",
        MachineShutdownCause::Sigint => "sigint",
        MachineShutdownCause::Sigterm => "sigterm",
    }
}
fn parse_cause(value: &str) -> Result<MachineShutdownCause, String> {
    match value {
        "command" => Ok(MachineShutdownCause::Command),
        "sigint" => Ok(MachineShutdownCause::Sigint),
        "sigterm" => Ok(MachineShutdownCause::Sigterm),
        _ => Err("stored machine shutdown cause is invalid".into()),
    }
}
fn status_name(status: MachineShutdownStatus) -> &'static str {
    match status {
        MachineShutdownStatus::Draining => "draining",
        MachineShutdownStatus::Stopped => "stopped",
        MachineShutdownStatus::Incomplete => "incomplete",
    }
}
fn parse_status(value: &str) -> Result<MachineShutdownStatus, String> {
    match value {
        "draining" => Ok(MachineShutdownStatus::Draining),
        "stopped" => Ok(MachineShutdownStatus::Stopped),
        "incomplete" => Ok(MachineShutdownStatus::Incomplete),
        _ => Err("stored machine shutdown status is invalid".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::OwnerMetadata;

    #[test]
    fn schema_23_failure_rolls_back_layout_and_migration_record() {
        let connection = rusqlite::Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at_unix INTEGER NOT NULL);
                 PRAGMA user_version=22;
                 CREATE TRIGGER reject_schema_23 BEFORE INSERT ON schema_migrations
                 WHEN NEW.version=23 BEGIN SELECT RAISE(ABORT, 'migration failure fixture'); END;",
            )
            .unwrap();
        assert!(migrate_v23(&connection).is_err());
        assert_eq!(
            connection
                .pragma_query_value::<i64, _>(None, "user_version", |row| row.get(0))
                .unwrap(),
            22
        );
        let new_objects: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE name IN ('machine_shutdowns','machine_shutdown_one_active')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(new_objects, 0);
        assert!(validate_v23_schema(&connection).is_err());

        connection
            .execute_batch("DROP TRIGGER reject_schema_23;")
            .unwrap();
        migrate_v23(&connection).unwrap();
        validate_v23_schema(&connection).unwrap();
        assert_eq!(
            connection
                .query_row::<i64, _, _>(
                    "SELECT COUNT(*) FROM schema_migrations WHERE version=23",
                    [],
                    |row| row.get(0),
                )
                .unwrap(),
            1
        );
    }

    fn owner(root: &std::path::Path, name: &str) -> OwnerMetadata {
        OwnerMetadata {
            owner_nonce: name.into(),
            state_root: root.display().to_string(),
            config_source: "fixture".into(),
            process_start_identity: format!("{name}-start"),
            executable_path: "/tmp/rex-projects-fixture".into(),
            executable_digest: "f".repeat(64),
            rex_endpoint: None,
            rex_server_identity: None,
            rex_session_id: None,
            rex_block_id: None,
        }
    }

    #[test]
    fn shutdown_restart_keeps_original_deadline_and_moves_only_the_drain_owner() {
        let root = tempfile::tempdir().unwrap();
        let mut store = ConfigStore::open_test(root.path()).unwrap();
        let first_generation = store.start_owner(&owner(root.path(), "first")).unwrap();
        let original = store
            .begin_signal_shutdown(
                first_generation,
                "stop-1",
                MachineShutdownCause::Command,
                100,
                7,
            )
            .unwrap();
        assert_eq!(original.deadline_unix, 107);
        store
            .set_machine_shutdown_status(
                first_generation,
                "stop-1",
                MachineShutdownStatus::Incomplete,
                Some("unknown owner retained"),
                106,
            )
            .unwrap();
        store.stop_owner(first_generation).unwrap();

        let second_generation = store.start_owner(&owner(root.path(), "second")).unwrap();
        let resumed = store.active_machine_shutdown().unwrap().unwrap();
        assert_eq!(resumed.original_generation, first_generation);
        assert_eq!(resumed.owner_generation, second_generation);
        assert_eq!(resumed.requested_at_unix, 100);
        assert_eq!(resumed.deadline_unix, original.deadline_unix);
        assert_eq!(resumed.status, MachineShutdownStatus::Incomplete);
        store
            .set_machine_shutdown_status(
                second_generation,
                &resumed.request_id,
                MachineShutdownStatus::Stopped,
                None,
                108,
            )
            .unwrap();
        assert!(store.active_machine_shutdown().unwrap().is_none());
    }

    #[test]
    fn machine_stop_barrier_prevents_pending_project_commands_from_applying() {
        let root = tempfile::tempdir().unwrap();
        let mut store = ConfigStore::open_test(root.path()).unwrap();
        let generation = store
            .start_owner(&owner(root.path(), "controller"))
            .unwrap();
        let now = 100;
        store.connection.execute(
            "INSERT INTO controller_commands(request_id,kind,project_id,lifecycle,payload_json,state,created_at_unix,expected_generation)
             VALUES ('stop-1','machine_stop',NULL,NULL,NULL,'pending',?1,?2),
                    ('later','config_apply',NULL,NULL,'{}','pending',?1,?2)",
            params![now,generation],
        ).unwrap();
        let stop = store.process_next_control(generation, 30).unwrap().unwrap();
        assert_eq!(stop.request_id, "stop-1");
        let barrier = store.active_machine_shutdown().unwrap().unwrap();
        assert_eq!(
            barrier.deadline_unix - barrier.requested_at_unix,
            DEFAULT_MACHINE_SHUTDOWN_GRACE_SECONDS
        );
        assert!(
            store
                .process_next_control(generation, 30)
                .unwrap()
                .is_none()
        );
        let later_state: String = store
            .connection
            .query_row(
                "SELECT state FROM controller_commands WHERE request_id='later'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(later_state, "pending");
    }

    #[test]
    fn launch_pending_and_unsupported_slot_owners_prevent_clean_shutdown() {
        let root = tempfile::tempdir().unwrap();
        let mut store = ConfigStore::open_test(root.path()).unwrap();
        let generation = store
            .start_owner(&owner(root.path(), "controller"))
            .unwrap();
        store.connection.execute(
            "INSERT INTO execution_slots(pool,slot_index,owner_kind,owner_id,reservation_epoch,controller_generation,disposition)
             VALUES ('agent',0,'agent_run','unstarted-agent',1,?1,'launch_pending'),
                    ('rex_projects_hook',0,'host_effect','hook-job',1,?1,'unknown')",
            [generation],
        ).unwrap();
        assert_eq!(store.machine_shutdown_unresolved_owners().unwrap(), 2);
        let slots: Vec<(String, String)> = store
            .connection
            .prepare("SELECT owner_id,disposition FROM execution_slots ORDER BY owner_id")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            slots,
            vec![
                ("hook-job".into(), "unknown".into()),
                ("unstarted-agent".into(), "launch_pending".into()),
            ]
        );
    }

    #[test]
    fn shutdown_counts_only_strictly_deserialized_cleanup_confirmed_process_receipts() {
        let root = tempfile::tempdir().unwrap();
        let mut store = ConfigStore::open_test(root.path()).unwrap();
        let generation = store
            .start_owner(&owner(root.path(), "controller"))
            .unwrap();
        let intent = crate::store::host_jobs::HostJobIntent {
            job_id: "job-complete".into(),
            effect_operation_id: "effect-complete".into(),
            project_id: "project-a".into(),
            subject_id: "ticket-a".into(),
            lane_id: "operation-a".into(),
            kind: crate::store::host_jobs::HostJobKind::OperationAdapter,
            operation_method: Some(crate::store::host_jobs::OperationMethod::Invoke),
            request_digest: "request-a".into(),
            configuration_digest: "config-a".into(),
            environment_snapshot_id: crate::domain::ids::Digest::parse("e".repeat(64)).unwrap(),
            environment_policy_digest: crate::domain::ids::Digest::parse("f".repeat(64)).unwrap(),
            head: "head-a".into(),
            source_digest: "source-a".into(),
            max_attempts: 1,
            retry_when_absent: false,
        };
        store.enqueue_host_job(generation, &intent, 10).unwrap();
        assert!(
            store
                .start_host_job(generation, &intent.job_id, 11)
                .unwrap()
        );
        let identity = crate::process::ProcessIdentity {
            pid: 42,
            parent_pid: 1,
            process_group_id: 42,
            start_identity: "birth-token".into(),
            command: "fixture".into(),
            quality: crate::process::ProcessIdentityQuality::KernelBirthToken,
        };
        assert!(
            store
                .mark_host_job_running(generation, &intent.job_id, &identity, 12)
                .unwrap()
        );
        let receipt = crate::store::host_jobs::HostProcessReceipt {
            status_code: Some(0),
            stdout: b"result".to_vec(),
            stderr_tail: Vec::new(),
            stdout_truncated: false,
            stderr_truncated: false,
            timed_out: false,
            cleanup_confirmed: true,
        };
        assert!(
            store
                .record_host_process_result(generation, &intent, &identity, &receipt, 13)
                .unwrap()
        );
        assert_eq!(store.machine_shutdown_unresolved_owners().unwrap(), 0);

        store
            .connection
            .execute(
                r#"UPDATE host_effect_jobs SET process_receipt_json='{"cleanup_confirmed":true}' WHERE job_id=?1"#,
                [&intent.job_id],
            )
            .unwrap();
        assert_eq!(store.machine_shutdown_unresolved_owners().unwrap(), 1);

        let valid_receipt = serde_json::to_string(&receipt).unwrap();
        store
            .connection
            .execute(
                "UPDATE host_effect_jobs SET process_receipt_json=?1 WHERE job_id=?2",
                rusqlite::params![valid_receipt, intent.job_id],
            )
            .unwrap();
        store
            .connection
            .execute(
                r#"UPDATE host_effect_jobs SET process_identity_json='{"pid":42,"parent_pid":1,"process_group_id":42,"start_identity":"birth-token","command":"fixture"}' WHERE job_id=?1"#,
                [&intent.job_id],
            )
            .unwrap();
        assert_eq!(store.machine_shutdown_unresolved_owners().unwrap(), 1);
    }
}
