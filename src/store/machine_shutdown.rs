//! Durable, bounded machine-wide controller shutdown.
//!
//! This is intentionally independent of Project and TicketRun desired lifecycle.

use rusqlite::{OptionalExtension, TransactionBehavior, params};

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

    /// Count every still-owned execution slot and every independently tracked host/qualification
    /// process. No query limit is used: any remaining owner means bounded-incomplete.
    pub fn machine_shutdown_unresolved_owners(&self) -> Result<u64, String> {
        let slots: u64 = self
            .connection
            .query_row(
                "SELECT COUNT(*) FROM execution_slots WHERE disposition!='released'",
                [],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        let host: u64 = self.connection.query_row(
            "SELECT COUNT(*) FROM host_effect_jobs WHERE state IN ('starting','running','unknown')", [], |row| row.get(0),
        ).map_err(|error| error.to_string())?;
        let qualifications: u64 = self.connection.query_row(
            "SELECT COUNT(*) FROM provider_qualification_jobs WHERE status IN ('running','unknown')", [], |row| row.get(0),
        ).map_err(|error| error.to_string())?;
        Ok(slots.saturating_add(host).saturating_add(qualifications))
    }
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
}
