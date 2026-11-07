use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use fs2::FileExt;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use sha2::{Digest as _, Sha256};

use crate::config::{AppliedConfig, Config, Profile, SourceFile};
use crate::domain::ids::{
    Digest, ProfileId, ProjectId, Revision, TicketId, TicketNamespace, TicketRunId,
};

const SCHEMA_VERSION: i64 = 2;
const INITIAL_SCHEMA_VERSION: i64 = 1;
const MAX_INPUT_BYTES: usize = 1_048_576;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectRecord {
    pub id: ProjectId,
    pub config_source: String,
    pub config_revision: Revision,
    pub config_digest: Digest,
    pub mode: String,
    pub goal_revision: u64,
    pub desired_lifecycle: String,
    pub state_revision: Revision,
}

pub struct DurableInput {
    pub producer_id: String,
    pub message_id: String,
    pub content_digest: String,
    pub recipient: String,
    pub payload: String,
}

pub struct InputReceipt {
    pub receipt: serde_json::Value,
    pub duplicate: bool,
}

pub struct EffectIntent {
    pub operation_id: String,
    pub logical_key: String,
    pub kind: String,
    pub request_json: String,
    pub request_digest: String,
    pub expected_revision: Option<u64>,
}

#[derive(Clone, Copy)]
pub enum EffectOutcome {
    Succeeded,
    Failed,
    Unknown,
}

#[derive(Clone, Debug)]
pub struct OwnerMetadata {
    pub owner_nonce: String,
    pub state_root: String,
    pub config_source: String,
    pub process_start_identity: String,
    pub executable_path: String,
    pub executable_digest: String,
    pub rex_server_identity: Option<String>,
    pub rex_session_id: Option<String>,
    pub rex_block_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadyWork {
    pub work_key: String,
    pub project_id: ProjectId,
    pub subject_id: String,
    pub role: String,
    pub pool: String,
    pub slot_index: u32,
    pub project_epoch: u64,
}

#[derive(Clone, Copy, Debug)]
pub enum ExpectedRevision {
    Bootstrap,
    Current(Revision),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppliedRevision {
    pub revision: Revision,
    pub digest: Digest,
    pub unchanged: bool,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct EffectiveConfig {
    config: Config,
    profiles: std::collections::BTreeMap<ProfileId, Profile>,
    source_root: String,
}

#[derive(Clone, Debug)]
pub struct StoredSnapshot {
    pub revision: Revision,
    pub config: AppliedConfig,
}

pub struct ConfigStore {
    connection: Connection,
    _machine_lock: MachineLock,
}

pub struct MachineLock {
    _file: File,
}

impl MachineLock {
    pub fn acquire(state_root: &Path) -> Result<Self, String> {
        let lock_root = machine_registry_root()?;
        Self::acquire_in_registry(state_root, &lock_root)
    }

    fn acquire_in_registry(state_root: &Path, lock_root: &Path) -> Result<Self, String> {
        fs::create_dir_all(state_root).map_err(|e| format!("{}: {e}", state_root.display()))?;
        if fs::symlink_metadata(state_root)
            .map_err(|e| format!("{}: {e}", state_root.display()))?
            .file_type()
            .is_symlink()
        {
            return Err(format!(
                "state root must not be a symlink: {}",
                state_root.display()
            ));
        }
        restrict_directory_permissions(state_root)?;
        fs::create_dir_all(lock_root).map_err(|e| format!("{}: {e}", lock_root.display()))?;
        if fs::symlink_metadata(lock_root)
            .map_err(|e| format!("{}: {e}", lock_root.display()))?
            .file_type()
            .is_symlink()
        {
            return Err(format!(
                "machine registry must not be a symlink: {}",
                lock_root.display()
            ));
        }
        restrict_directory_permissions(lock_root)?;
        Ok(Self {
            _file: acquire_machine_lock(lock_root)?,
        })
    }
}

impl ConfigStore {
    pub fn open(state_root: &Path) -> Result<Self, String> {
        Self::open_with_lock(state_root, MachineLock::acquire(state_root)?)
    }

    #[cfg(test)]
    fn open_test(state_root: &Path) -> Result<Self, String> {
        let lock_root = state_root.join("machine-registry");
        let machine_lock = MachineLock::acquire_in_registry(state_root, &lock_root)?;
        Self::open_with_lock(state_root, machine_lock)
    }

    fn open_with_lock(state_root: &Path, machine_lock: MachineLock) -> Result<Self, String> {
        let database = state_root.join("state.sqlite3");
        ensure_private_database_file(&database)?;
        let connection =
            Connection::open(&database).map_err(|e| format!("{}: {e}", database.display()))?;
        restrict_file_permissions(&database)?;
        connection
            .busy_timeout(std::time::Duration::from_secs(5))
            .map_err(|e| e.to_string())?;
        let existing_version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(|e| e.to_string())?;
        if existing_version > SCHEMA_VERSION {
            return Err(format!(
                "database schema {existing_version} is newer than supported schema {SCHEMA_VERSION}; refusing to write"
            ));
        }
        connection
            .execute_batch(
                "PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;",
            )
            .map_err(|e| e.to_string())?;
        if existing_version < SCHEMA_VERSION {
            Self::migrate(&connection, existing_version, state_root)?;
        }
        Ok(Self {
            connection,
            _machine_lock: machine_lock,
        })
    }

    fn migrate(connection: &Connection, current: i64, state_root: &Path) -> Result<(), String> {
        if current == 0 {
            let tx = connection
                .unchecked_transaction()
                .map_err(|e| e.to_string())?;
            tx.execute_batch(
                "CREATE TABLE schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at_unix INTEGER NOT NULL
                );
                CREATE TABLE config_snapshots (
                    source_identity TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    digest TEXT NOT NULL,
                    digest_algorithm TEXT NOT NULL CHECK (digest_algorithm = 'sha256'),
                    representation TEXT NOT NULL CHECK (representation = 'canonical_json_utf8_sorted_keys'),
                    effective_config_json TEXT NOT NULL,
                    source_manifest_json TEXT NOT NULL,
                    applied_at_unix INTEGER NOT NULL,
                    PRIMARY KEY (source_identity, revision),
                    UNIQUE (source_identity, digest)
                );
                CREATE TABLE config_current (
                    source_identity TEXT PRIMARY KEY,
                    revision INTEGER NOT NULL,
                    FOREIGN KEY (source_identity, revision) REFERENCES config_snapshots(source_identity, revision)
                );"
            ).map_err(|e| e.to_string())?;
            let now = now_unix()?;
            tx.execute(
                "INSERT INTO schema_migrations(version, applied_at_unix) VALUES (?1, ?2)",
                params![INITIAL_SCHEMA_VERSION, now],
            )
            .map_err(|e| e.to_string())?;
            tx.pragma_update(None, "user_version", INITIAL_SCHEMA_VERSION)
                .map_err(|e| e.to_string())?;
            tx.commit().map_err(|e| e.to_string())?;
        } else if current != INITIAL_SCHEMA_VERSION {
            return Err(format!("no migration path from database schema {current}"));
        }
        backup_before_migration(connection, state_root)?;
        migrate_v2(connection)
    }

    pub fn insert_project(&mut self, project: &ProjectRecord) -> Result<bool, String> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        let snapshot_exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM config_snapshots WHERE source_identity=?1 AND revision=?2 AND digest=?3)",
            params![project.config_source, project.config_revision.0, project.config_digest.as_str()],
            |row| row.get(0),
        ).map_err(|e| e.to_string())?;
        if !snapshot_exists {
            return Err("project must reference an applied config snapshot".into());
        }
        let inserted = tx.execute(
            "INSERT INTO projects(project_id, config_source, config_revision, config_digest, mode, goal_revision, desired_lifecycle, state_revision, created_at_unix) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, ?8) ON CONFLICT(project_id) DO NOTHING",
            params![project.id.as_str(), project.config_source, project.config_revision.0, project.config_digest.as_str(), project.mode, project.goal_revision, project.desired_lifecycle, now_unix()?],
        ).map_err(|e| e.to_string())? != 0;
        if inserted {
            tx.execute("INSERT INTO project_runtimes(project_id, desired_lifecycle, observed_lifecycle, controller_generation, project_epoch, next_due_at_unix) VALUES (?1, ?2, 'stopped', 0, 1, 0)", params![project.id.as_str(), project.desired_lifecycle]).map_err(|e| e.to_string())?;
        } else {
            let existing: (String, u64, String) = tx.query_row("SELECT config_source, config_revision, config_digest FROM projects WHERE project_id=?1", [project.id.as_str()], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))).map_err(|e| e.to_string())?;
            if existing
                != (
                    project.config_source.clone(),
                    project.config_revision.0,
                    project.config_digest.as_str().to_owned(),
                )
            {
                return Err(
                    "project ID already exists with a different applied configuration".into(),
                );
            }
        }
        tx.commit().map_err(|e| e.to_string())?;
        Ok(inserted)
    }

    pub fn project(&self, id: &ProjectId) -> Result<Option<ProjectRecord>, String> {
        self.connection.query_row(
            "SELECT config_source, config_revision, config_digest, mode, goal_revision, desired_lifecycle, state_revision FROM projects WHERE project_id=?1",
            [id.as_str()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?, row.get::<_, u64>(4)?, row.get::<_, String>(5)?, row.get::<_, u64>(6)?)),
        ).optional().map_err(|e| e.to_string())?.map(|(config_source, config_revision, config_digest, mode, goal_revision, desired_lifecycle, state_revision)| {
            Ok(ProjectRecord { id: id.clone(), config_source, config_revision: Revision(config_revision), config_digest: Digest::parse(config_digest)?, mode, goal_revision, desired_lifecycle, state_revision: Revision(state_revision) })
        }).transpose()
    }

    pub fn record_input(
        &mut self,
        owner_generation: u64,
        input: &DurableInput,
    ) -> Result<InputReceipt, String> {
        validate_input(input)?;
        if input.payload.len() > MAX_INPUT_BYTES {
            return Err("input payload exceeds limit".into());
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let previous: Option<(String, String)> = tx.query_row(
            "SELECT content_digest, receipt_json FROM inbox WHERE producer_id=?1 AND message_id=?2",
            params![input.producer_id, input.message_id], |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional().map_err(|e| e.to_string())?;
        if let Some((digest, receipt)) = previous {
            if digest != input.content_digest {
                return Err("message ID was reused with different content".into());
            }
            let receipt = serde_json::from_str(&receipt)
                .map_err(|e| format!("stored receipt is invalid: {e}"))?;
            tx.commit().map_err(|e| e.to_string())?;
            return Ok(InputReceipt {
                receipt,
                duplicate: true,
            });
        }
        let receipt = serde_json::json!({"accepted": true, "message_id": input.message_id, "content_digest": input.content_digest});
        let receipt_json = serde_json::to_string(&receipt).map_err(|e| e.to_string())?;
        tx.execute("INSERT INTO inbox(producer_id, message_id, content_digest, recipient, payload_json, receipt_json, received_at_unix) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)", params![input.producer_id, input.message_id, input.content_digest, input.recipient, input.payload, receipt_json, now_unix()?]).map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(InputReceipt {
            receipt,
            duplicate: false,
        })
    }

    pub fn enqueue_effect(
        &mut self,
        owner_generation: u64,
        effect: &EffectIntent,
    ) -> Result<bool, String> {
        validate_effect(effect)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let inserted = tx.execute("INSERT INTO effects(operation_id, logical_key, kind, request_json, request_digest, expected_revision, status, attempt_count, next_attempt_at_unix, created_at_unix) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending', 0, ?7, ?7) ON CONFLICT(logical_key) DO NOTHING", params![effect.operation_id, effect.logical_key, effect.kind, effect.request_json, effect.request_digest, effect.expected_revision, now_unix()?]).map_err(|e| e.to_string())? != 0;
        if !inserted {
            let (operation, digest): (String, String) = tx
                .query_row(
                    "SELECT operation_id, request_digest FROM effects WHERE logical_key=?1",
                    [&effect.logical_key],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(|e| e.to_string())?;
            if operation != effect.operation_id || digest != effect.request_digest {
                return Err("logical effect key was reused with different intent".into());
            }
        }
        tx.commit().map_err(|e| e.to_string())?;
        Ok(inserted)
    }

    pub fn next_due_effect(
        &mut self,
        owner_generation: u64,
        now: i64,
    ) -> Result<Option<EffectIntent>, String> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        let active_generation: Option<u64> = tx
            .query_row(
                "SELECT generation FROM controller_owners WHERE singleton=1 AND stopped_at_unix IS NULL",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        if active_generation != Some(owner_generation) {
            return Err("controller owner generation is stale".into());
        }
        let row: Option<(String,String,String,String,String,Option<u64>)> = tx.query_row("SELECT operation_id, logical_key, kind, request_json, request_digest, expected_revision FROM effects WHERE status='pending' AND next_attempt_at_unix<=?1 ORDER BY next_attempt_at_unix, created_at_unix LIMIT 1", [now], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?))).optional().map_err(|e| e.to_string())?;
        let Some((
            operation_id,
            logical_key,
            kind,
            request_json,
            request_digest,
            expected_revision,
        )) = row
        else {
            tx.commit().map_err(|e| e.to_string())?;
            return Ok(None);
        };
        let claimed = tx.execute("UPDATE effects SET status='claimed', owner_generation=?2, attempt_count=attempt_count+1 WHERE operation_id=?1 AND status='pending'", params![operation_id, owner_generation]).map_err(|e| e.to_string())?;
        if claimed != 1 {
            return Err("due effect was concurrently claimed".into());
        }
        tx.commit().map_err(|e| e.to_string())?;
        Ok(Some(EffectIntent {
            operation_id,
            logical_key,
            kind,
            request_json,
            request_digest,
            expected_revision,
        }))
    }

    pub fn finish_effect(
        &mut self,
        operation_id: &str,
        owner_generation: u64,
        outcome: EffectOutcome,
        receipt: Option<&str>,
    ) -> Result<(), String> {
        let status = match outcome {
            EffectOutcome::Succeeded => "succeeded",
            EffectOutcome::Failed => "failed",
            EffectOutcome::Unknown => "uncertain",
        };
        let changed = self.connection.execute("UPDATE effects SET status=?3, receipt_json=?4, owner_generation=NULL WHERE operation_id=?1 AND owner_generation=?2 AND status='claimed' AND EXISTS (SELECT 1 FROM controller_owners WHERE singleton=1 AND generation=?2 AND stopped_at_unix IS NULL)", params![operation_id, owner_generation, status, receipt]).map_err(|e| e.to_string())?;
        if changed != 1 {
            return Err("effect claim is stale or no longer active".into());
        }
        Ok(())
    }

    pub fn claim_ticket(
        &mut self,
        owner_generation: u64,
        namespace: &TicketNamespace,
        ticket: &TicketId,
        project: &ProjectId,
        ticket_run: &TicketRunId,
        generation: u64,
    ) -> Result<bool, String> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let matching: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM ticket_runs WHERE ticket_run_id=?1 AND project_id=?2 AND namespace=?3 AND ticket_id=?4 AND generation=?5)", params![ticket_run.as_str(), project.as_str(), namespace.as_str(), ticket.as_str(), generation], |row| row.get(0)).map_err(|e| e.to_string())?;
        if !matching {
            return Err("ticket run does not match claim identity".into());
        }
        let inserted = tx.execute("INSERT INTO ticket_claims(namespace, ticket_id, project_id, ticket_run_id, generation, claimed_at_unix) VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT(namespace, ticket_id) DO NOTHING", params![namespace.as_str(), ticket.as_str(), project.as_str(), ticket_run.as_str(), generation, now_unix()?]).map_err(|e| e.to_string())? == 1;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(inserted)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_ticket_run(
        &mut self,
        owner_generation: u64,
        project: &ProjectId,
        namespace: &TicketNamespace,
        ticket: &TicketId,
        ticket_run: &TicketRunId,
        generation: u64,
        initial_phase: &str,
        external_status: &str,
    ) -> Result<(), String> {
        if generation == 0 || initial_phase.is_empty() || external_status.is_empty() {
            return Err("ticket run identity and initial state are required".into());
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let (config_source, config_revision, config_digest): (String, u64, String) = tx.query_row("SELECT config_source, config_revision, config_digest FROM projects WHERE project_id=?1", [project.as_str()], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))).map_err(|e| e.to_string())?;
        tx.execute("INSERT INTO ticket_runs(ticket_run_id, project_id, config_source, config_revision, config_digest, namespace, ticket_id, generation, internal_phase, activity, external_status, observed_status, revision) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'ready', ?10, ?10, 0)", params![ticket_run.as_str(), project.as_str(), config_source, config_revision, config_digest, namespace.as_str(), ticket.as_str(), generation, initial_phase, external_status]).map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())
    }

    pub fn release_ticket_claim(
        &mut self,
        owner_generation: u64,
        namespace: &TicketNamespace,
        ticket: &TicketId,
        ticket_run: &TicketRunId,
        generation: u64,
    ) -> Result<bool, String> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let removed = tx.execute("DELETE FROM ticket_claims WHERE namespace=?1 AND ticket_id=?2 AND ticket_run_id=?3 AND generation=?4", params![namespace.as_str(), ticket.as_str(), ticket_run.as_str(), generation]).map_err(|e| e.to_string())? == 1;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(removed)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn enqueue_ready(
        &mut self,
        owner_generation: u64,
        project: &ProjectId,
        work_key: &str,
        subject_type: &str,
        subject_id: &str,
        role: &str,
        pool: &str,
        priority: i64,
        ready_at_unix: i64,
        expected_project_epoch: u64,
    ) -> Result<bool, String> {
        if work_key.is_empty()
            || subject_type.is_empty()
            || subject_id.is_empty()
            || role.is_empty()
            || !matches!(pool, "agent" | "rex_projects_hook")
        {
            return Err("ready work identity or pool is invalid".into());
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let epoch: Option<u64> = tx
            .query_row(
                "SELECT project_epoch FROM project_runtimes WHERE project_id=?1",
                [project.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        if epoch != Some(expected_project_epoch) {
            return Err("project epoch changed before queueing work".into());
        }
        let sequence: i64 = tx
            .query_row(
                "SELECT COALESCE(MAX(fair_sequence),0)+1 FROM ready_queue",
                [],
                |row| row.get(0),
            )
            .map_err(|e| e.to_string())?;
        let inserted = tx.execute("INSERT INTO ready_queue(work_key, project_id, subject_type, subject_id, role, pool, priority, ready_at_unix, expected_generation, fair_sequence) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10) ON CONFLICT(work_key) DO NOTHING", params![work_key, project.as_str(), subject_type, subject_id, role, pool, priority, ready_at_unix, expected_project_epoch, sequence]).map_err(|e| e.to_string())? == 1;
        if !inserted {
            let existing: (String, String, String, String, u64) = tx.query_row("SELECT project_id, subject_type, subject_id, role, expected_generation FROM ready_queue WHERE work_key=?1", [work_key], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?))).map_err(|e| e.to_string())?;
            if existing
                != (
                    project.as_str().to_owned(),
                    subject_type.to_owned(),
                    subject_id.to_owned(),
                    role.to_owned(),
                    expected_project_epoch,
                )
            {
                return Err("ready work key was reused with different intent".into());
            }
        }
        tx.commit().map_err(|e| e.to_string())?;
        Ok(inserted)
    }

    pub fn set_project_lifecycle(
        &mut self,
        owner_generation: u64,
        project: &ProjectId,
        lifecycle: &str,
    ) -> Result<u64, String> {
        if !matches!(lifecycle, "running" | "paused" | "stopped") {
            return Err("project lifecycle must be running, paused, or stopped".into());
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let changed = tx
            .execute(
                "UPDATE projects SET desired_lifecycle=?2 WHERE project_id=?1",
                params![project.as_str(), lifecycle],
            )
            .map_err(|e| e.to_string())?;
        if changed != 1 {
            return Err("project not found".into());
        }
        let observed = if lifecycle == "running" {
            "running"
        } else {
            lifecycle
        };
        tx.execute("UPDATE project_runtimes SET desired_lifecycle=?2,observed_lifecycle=?3,controller_generation=?4 WHERE project_id=?1", params![project.as_str(), lifecycle, observed, owner_generation]).map_err(|e| e.to_string())?;
        let epoch: u64 = tx
            .query_row(
                "SELECT project_epoch FROM project_runtimes WHERE project_id=?1",
                [project.as_str()],
                |row| row.get(0),
            )
            .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(epoch)
    }

    pub fn reserve_next_ready(
        &mut self,
        owner_generation: u64,
        now: i64,
        max_agent_slots: u32,
        max_hook_slots: u32,
        max_project_slots: u32,
    ) -> Result<Option<ReadyWork>, String> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let last_project: Option<String> = tx
            .query_row(
                "SELECT last_project_id FROM scheduler_state WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())?
            .flatten();
        let mut candidates = tx.prepare("SELECT q.work_key,q.project_id,q.subject_id,q.role,q.pool,rt.project_epoch FROM ready_queue q JOIN project_runtimes rt USING(project_id) JOIN projects p USING(project_id) WHERE q.ready_at_unix<=?1 AND q.expected_generation=rt.project_epoch AND p.desired_lifecycle='running' AND rt.observed_lifecycle IN ('running','starting') ORDER BY CASE WHEN q.project_id>?2 THEN 0 ELSE 1 END, q.project_id, q.priority DESC, q.fair_sequence").map_err(|e| e.to_string())?;
        let rows = candidates
            .query_map(params![now, last_project.as_deref().unwrap_or("")], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, u64>(5)?,
                ))
            })
            .map_err(|e| e.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        drop(candidates);
        for (work_key, project, subject_id, role, pool, project_epoch) in rows {
            let global_used: u32 = tx.query_row("SELECT COUNT(*) FROM execution_slots WHERE pool=?1 AND disposition!='released'", [&pool], |row| row.get(0)).map_err(|e| e.to_string())?;
            let project_used: u32 = tx.query_row("SELECT COUNT(*) FROM execution_slots WHERE project_id=?1 AND disposition!='released'", [&project], |row| row.get(0)).map_err(|e| e.to_string())?;
            let pool_limit = if pool == "agent" {
                max_agent_slots
            } else {
                max_hook_slots
            };
            if global_used >= pool_limit || project_used >= max_project_slots {
                continue;
            }
            let mut slot_index = None;
            for slot in 0..pool_limit {
                let occupied: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM execution_slots WHERE pool=?1 AND slot_index=?2 AND disposition!='released')", params![pool, slot], |row| row.get(0)).map_err(|e| e.to_string())?;
                if !occupied {
                    slot_index = Some(slot);
                    break;
                }
            }
            let Some(slot_index) = slot_index else {
                continue;
            };
            let claimed = tx
                .execute("DELETE FROM ready_queue WHERE work_key=?1", [&work_key])
                .map_err(|e| e.to_string())?;
            if claimed != 1 {
                return Err("ready work changed during reservation".into());
            }
            tx.execute("INSERT INTO execution_slots(pool, slot_index, project_id, owner_kind, owner_id, reservation_epoch, controller_generation, disposition) VALUES (?1, ?2, ?3, 'ready_work', ?4, ?5, ?6, 'launch_pending')", params![pool, slot_index, project, work_key, project_epoch, owner_generation]).map_err(|e| e.to_string())?;
            tx.execute("INSERT INTO scheduler_state(singleton,last_project_id,revision) VALUES (1,?1,1) ON CONFLICT(singleton) DO UPDATE SET last_project_id=excluded.last_project_id,revision=scheduler_state.revision+1", [&project]).map_err(|e| e.to_string())?;
            tx.commit().map_err(|e| e.to_string())?;
            return Ok(Some(ReadyWork {
                work_key,
                project_id: ProjectId::parse(project)?,
                subject_id,
                role,
                pool,
                slot_index,
                project_epoch,
            }));
        }
        tx.commit().map_err(|e| e.to_string())?;
        Ok(None)
    }

    pub fn release_slot_after_confirmed_exit(
        &mut self,
        owner_generation: u64,
        pool: &str,
        slot_index: u32,
        owner_id: &str,
    ) -> Result<(), String> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let changed = tx.execute("UPDATE execution_slots SET disposition='released',controller_generation=?4 WHERE pool=?1 AND slot_index=?2 AND owner_id=?3 AND disposition IN ('launch_pending','live','parked','unknown')", params![pool, slot_index, owner_id, owner_generation]).map_err(|e| e.to_string())?;
        if changed != 1 {
            return Err("slot could not be released without a matching reservation".into());
        }
        tx.commit().map_err(|e| e.to_string())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn commit_transition(
        &mut self,
        owner_generation: u64,
        project_id: &ProjectId,
        expected_revision: Revision,
        input: &DurableInput,
        reason: &str,
        evidence_json: &str,
        effects: &[EffectIntent],
    ) -> Result<InputReceipt, String> {
        validate_input(input)?;
        if effects.len() > 64
            || reason.is_empty()
            || reason.len() > 1024
            || evidence_json.len() > MAX_INPUT_BYTES
        {
            return Err("transition input exceeds configured limits".into());
        }
        let evidence: serde_json::Value =
            crate::protocol::parse_unique(evidence_json.as_bytes())
                .map_err(|e| format!("invalid transition evidence: {e}"))?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        validate_active_generation(&tx, owner_generation)?;
        let duplicate: Option<(String, String)> = tx.query_row("SELECT content_digest, receipt_json FROM inbox WHERE producer_id=?1 AND message_id=?2", params![input.producer_id, input.message_id], |row| Ok((row.get(0)?, row.get(1)?))).optional().map_err(|e| e.to_string())?;
        if let Some((digest, receipt_json)) = duplicate {
            if digest != input.content_digest {
                return Err("message ID was reused with different content".into());
            }
            tx.commit().map_err(|e| e.to_string())?;
            let receipt = serde_json::from_str(&receipt_json)
                .map_err(|e| format!("stored receipt is invalid: {e}"))?;
            return Ok(InputReceipt {
                receipt,
                duplicate: true,
            });
        }
        let current: u64 = tx
            .query_row(
                "SELECT state_revision FROM projects WHERE project_id=?1",
                [project_id.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "project not found".to_owned())?;
        if current != expected_revision.0 {
            return Err("project revision conflict; no transition or effects were written".into());
        }
        let next = current
            .checked_add(1)
            .ok_or_else(|| "project revision exhausted".to_owned())?;
        let now = now_unix()?;
        tx.execute(
            "UPDATE projects SET state_revision=?2 WHERE project_id=?1 AND state_revision=?3",
            params![project_id.as_str(), next, current],
        )
        .map_err(|e| e.to_string())?;
        tx.execute("INSERT INTO transitions(project_id, entity_type, entity_id, old_revision, new_revision, input_id, decision_reason, evidence_json, created_at_unix) VALUES (?1, 'project', ?1, ?2, ?3, ?4, ?5, ?6, ?7)", params![project_id.as_str(), current, next, input.message_id, reason, serde_json::to_string(&evidence).map_err(|e| e.to_string())?, now]).map_err(|e| e.to_string())?;
        for effect in effects {
            insert_effect(&tx, effect, now)?;
        }
        let receipt = serde_json::json!({"accepted": true, "message_id": input.message_id, "content_digest": input.content_digest, "project_id": project_id, "revision": next, "effects": effects.iter().map(|effect| effect.operation_id.as_str()).collect::<Vec<_>>()});
        tx.execute("INSERT INTO inbox(producer_id, message_id, content_digest, recipient, payload_json, receipt_json, received_at_unix, processed_at_unix) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)", params![input.producer_id, input.message_id, input.content_digest, input.recipient, input.payload, serde_json::to_string(&receipt).map_err(|e| e.to_string())?, now]).map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(InputReceipt {
            receipt,
            duplicate: false,
        })
    }

    pub fn start_owner(&mut self, owner: &OwnerMetadata) -> Result<u64, String> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        let previous: Option<u64> = tx
            .query_row(
                "SELECT generation FROM controller_owners WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        let generation = previous
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| "controller generation exhausted".to_owned())?;
        let now = now_unix()?;
        tx.execute("UPDATE effects SET status='uncertain', owner_generation=NULL, last_error='previous controller stopped before recording an outcome' WHERE status='claimed'", []).map_err(|e| e.to_string())?;
        tx.execute("UPDATE execution_slots SET disposition='unknown' WHERE disposition IN ('launch_pending','live')", []).map_err(|e| e.to_string())?;
        tx.execute("UPDATE agent_runs SET state='unknown', controller_generation=?1 WHERE state IN ('launch_pending','running')", [generation]).map_err(|e| e.to_string())?;
        tx.execute("INSERT INTO controller_owners(singleton, owner_nonce, generation, state_root, config_source, pid, process_start_identity, executable_path, executable_digest, rex_server_identity, rex_session_id, rex_block_id, started_at_unix, heartbeat_at_unix, stopped_at_unix) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?12, NULL) ON CONFLICT(singleton) DO UPDATE SET owner_nonce=excluded.owner_nonce, generation=excluded.generation, state_root=excluded.state_root, config_source=excluded.config_source, pid=excluded.pid, process_start_identity=excluded.process_start_identity, executable_path=excluded.executable_path, executable_digest=excluded.executable_digest, rex_server_identity=excluded.rex_server_identity, rex_session_id=excluded.rex_session_id, rex_block_id=excluded.rex_block_id, started_at_unix=excluded.started_at_unix, heartbeat_at_unix=excluded.heartbeat_at_unix, stopped_at_unix=NULL", params![owner.owner_nonce, generation, owner.state_root, owner.config_source, std::process::id(), owner.process_start_identity, owner.executable_path, owner.executable_digest, owner.rex_server_identity, owner.rex_session_id, owner.rex_block_id, now]).map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(generation)
    }

    pub fn heartbeat_owner(&self, generation: u64) -> Result<(), String> {
        let changed = self.connection.execute("UPDATE controller_owners SET heartbeat_at_unix=?2 WHERE singleton=1 AND generation=?1 AND stopped_at_unix IS NULL", params![generation, now_unix()?]).map_err(|e| e.to_string())?;
        if changed != 1 {
            return Err("controller owner generation is stale".into());
        }
        Ok(())
    }

    pub fn stop_owner(&self, generation: u64) -> Result<(), String> {
        let changed = self.connection.execute("UPDATE controller_owners SET stopped_at_unix=?2 WHERE singleton=1 AND generation=?1 AND stopped_at_unix IS NULL", params![generation, now_unix()?]).map_err(|e| e.to_string())?;
        if changed != 1 {
            return Err("controller owner generation is stale".into());
        }
        Ok(())
    }

    pub fn owner_generation(&self) -> Result<Option<u64>, String> {
        self.connection.query_row("SELECT generation FROM controller_owners WHERE singleton=1 AND stopped_at_unix IS NULL", [], |row| row.get(0)).optional().map_err(|e| e.to_string())
    }
}

fn migrate_v2(connection: &Connection) -> Result<(), String> {
    let tx = connection
        .unchecked_transaction()
        .map_err(|e| e.to_string())?;
    tx.execute_batch(
        "CREATE UNIQUE INDEX config_snapshot_identity_digest ON config_snapshots(source_identity, revision, digest);
        CREATE TABLE projects (
            project_id TEXT PRIMARY KEY,
            config_source TEXT NOT NULL,
            config_revision INTEGER NOT NULL CHECK(config_revision > 0),
            config_digest TEXT NOT NULL CHECK(length(config_digest) = 64),
            mode TEXT NOT NULL CHECK(mode IN ('goal','operations')),
            goal_revision INTEGER NOT NULL DEFAULT 0 CHECK(goal_revision >= 0),
            desired_lifecycle TEXT NOT NULL CHECK(desired_lifecycle IN ('stopped','running','paused')),
            state_revision INTEGER NOT NULL DEFAULT 0 CHECK(state_revision >= 0),
            created_at_unix INTEGER NOT NULL,
            FOREIGN KEY(config_source, config_revision, config_digest) REFERENCES config_snapshots(source_identity, revision, digest)
        );
        CREATE TABLE controller_owners (
            singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
            owner_nonce TEXT NOT NULL,
            generation INTEGER NOT NULL CHECK(generation > 0),
            state_root TEXT NOT NULL,
            config_source TEXT NOT NULL,
            pid INTEGER NOT NULL,
            process_start_identity TEXT NOT NULL,
            executable_path TEXT NOT NULL,
            executable_digest TEXT NOT NULL,
            rex_server_identity TEXT,
            rex_session_id TEXT,
            rex_block_id TEXT,
            started_at_unix INTEGER NOT NULL,
            heartbeat_at_unix INTEGER NOT NULL,
            stopped_at_unix INTEGER
        );
        CREATE TABLE project_runtimes (
            project_id TEXT PRIMARY KEY REFERENCES projects(project_id) ON DELETE CASCADE,
            desired_lifecycle TEXT NOT NULL CHECK(desired_lifecycle IN ('stopped','running','paused')),
            observed_lifecycle TEXT NOT NULL CHECK(observed_lifecycle IN ('stopped','starting','running','paused','reconciling','failed')),
            controller_generation INTEGER NOT NULL DEFAULT 0,
            project_epoch INTEGER NOT NULL DEFAULT 1 CHECK(project_epoch > 0),
            supervisor_session_id TEXT,
            next_due_at_unix INTEGER NOT NULL,
            last_error TEXT
        );
        CREATE TABLE transitions (
            transition_id INTEGER PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(project_id),
            entity_type TEXT NOT NULL,
            entity_id TEXT NOT NULL,
            old_revision INTEGER NOT NULL,
            new_revision INTEGER NOT NULL,
            input_id TEXT NOT NULL,
            decision_reason TEXT NOT NULL,
            evidence_json TEXT NOT NULL,
            created_at_unix INTEGER NOT NULL,
            UNIQUE(project_id, entity_type, entity_id, new_revision)
        );
        CREATE TABLE inbox (
            inbox_id INTEGER PRIMARY KEY,
            producer_id TEXT NOT NULL,
            message_id TEXT NOT NULL,
            content_digest TEXT NOT NULL,
            recipient TEXT NOT NULL,
            payload_json TEXT NOT NULL CHECK(length(payload_json) <= 1048576),
            receipt_json TEXT NOT NULL,
            received_at_unix INTEGER NOT NULL,
            processed_at_unix INTEGER,
            UNIQUE(producer_id, message_id)
        );
        CREATE TABLE effects (
            operation_id TEXT PRIMARY KEY,
            logical_key TEXT NOT NULL UNIQUE,
            kind TEXT NOT NULL,
            request_json TEXT NOT NULL CHECK(length(request_json) <= 1048576),
            request_digest TEXT NOT NULL,
            expected_revision INTEGER,
            status TEXT NOT NULL CHECK(status IN ('pending','claimed','succeeded','failed','uncertain','cancelled')),
            attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count >= 0),
            next_attempt_at_unix INTEGER NOT NULL,
            owner_generation INTEGER,
            receipt_json TEXT,
            last_error TEXT,
            created_at_unix INTEGER NOT NULL
        );
        CREATE INDEX effects_due ON effects(status, next_attempt_at_unix, created_at_unix);
        CREATE TABLE ticket_runs (
            ticket_run_id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(project_id),
            config_source TEXT NOT NULL,
            config_revision INTEGER NOT NULL,
            config_digest TEXT NOT NULL,
            namespace TEXT NOT NULL,
            ticket_id TEXT NOT NULL,
            generation INTEGER NOT NULL CHECK(generation > 0),
            internal_phase TEXT NOT NULL,
            activity TEXT NOT NULL,
            external_status TEXT NOT NULL,
            observed_status TEXT NOT NULL,
            revision INTEGER NOT NULL DEFAULT 0,
            external_revision TEXT,
            UNIQUE(project_id, namespace, ticket_id, generation),
            FOREIGN KEY(config_source, config_revision, config_digest) REFERENCES config_snapshots(source_identity, revision, digest)
        );
        CREATE TABLE ticket_claims (
            namespace TEXT NOT NULL,
            ticket_id TEXT NOT NULL,
            project_id TEXT NOT NULL REFERENCES projects(project_id),
            ticket_run_id TEXT NOT NULL REFERENCES ticket_runs(ticket_run_id),
            generation INTEGER NOT NULL,
            claimed_at_unix INTEGER NOT NULL,
            PRIMARY KEY(namespace, ticket_id)
        );
        CREATE TABLE execution_slots (
            pool TEXT NOT NULL CHECK(pool IN ('agent','rex_projects_hook')),
            slot_index INTEGER NOT NULL CHECK(slot_index >= 0),
            project_id TEXT REFERENCES projects(project_id),
            owner_kind TEXT NOT NULL,
            owner_id TEXT NOT NULL,
            reservation_epoch INTEGER NOT NULL,
            controller_generation INTEGER NOT NULL,
            process_identity_json TEXT,
            disposition TEXT NOT NULL CHECK(disposition IN ('launch_pending','live','parked','unknown','released')),
            PRIMARY KEY(pool, slot_index)
        );
        CREATE UNIQUE INDEX execution_slot_owner_active ON execution_slots(owner_kind,owner_id) WHERE disposition!='released';
        CREATE TABLE scheduler_state (
            singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
            last_project_id TEXT,
            revision INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE agent_runs (
            agent_run_id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(project_id),
            config_source TEXT NOT NULL,
            config_revision INTEGER NOT NULL,
            config_digest TEXT NOT NULL,
            role_session_id TEXT,
            logical_owner TEXT NOT NULL,
            finite_turn INTEGER NOT NULL CHECK(finite_turn > 0),
            launch_operation_id TEXT NOT NULL UNIQUE,
            rex_session_id TEXT,
            rex_window_id TEXT,
            rex_block_id TEXT,
            process_identity_json TEXT,
            state TEXT NOT NULL CHECK(state IN ('launch_pending','running','parked','completed','failed','unknown','cancelled')),
            controller_generation INTEGER NOT NULL,
            started_at_unix INTEGER,
            finished_at_unix INTEGER,
            FOREIGN KEY(config_source, config_revision, config_digest) REFERENCES config_snapshots(source_identity, revision, digest)
        );
        CREATE TABLE role_wake_inputs (
            wake_input_id INTEGER PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(project_id),
            role_session_id TEXT NOT NULL,
            source_type TEXT NOT NULL,
            source_id TEXT NOT NULL,
            source_revision INTEGER NOT NULL,
            priority INTEGER NOT NULL DEFAULT 0,
            payload_json TEXT NOT NULL CHECK(length(payload_json) <= 1048576),
            lifecycle TEXT NOT NULL CHECK(lifecycle IN ('pending','assigned','consumed','superseded')),
            consuming_agent_run_id TEXT REFERENCES agent_runs(agent_run_id),
            created_at_unix INTEGER NOT NULL,
            UNIQUE(role_session_id, source_type, source_id, source_revision)
        );
        CREATE TABLE agent_mailboxes (
            agent_run_id TEXT PRIMARY KEY REFERENCES agent_runs(agent_run_id),
            canonical_directory TEXT NOT NULL,
            capability_digest TEXT NOT NULL,
            expires_at_unix INTEGER NOT NULL,
            request_cursor INTEGER NOT NULL DEFAULT 0,
            reply_cursor INTEGER NOT NULL DEFAULT 0,
            max_request_bytes INTEGER NOT NULL,
            max_pending_requests INTEGER NOT NULL
        );
        CREATE TABLE ready_queue (
            work_key TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(project_id),
            subject_type TEXT NOT NULL,
            subject_id TEXT NOT NULL,
            role TEXT,
            pool TEXT NOT NULL CHECK(pool IN ('agent','rex_projects_hook')),
            priority INTEGER NOT NULL DEFAULT 0,
            ready_at_unix INTEGER NOT NULL,
            expected_generation INTEGER NOT NULL,
            fair_sequence INTEGER NOT NULL UNIQUE
        );
        CREATE INDEX ready_queue_due ON ready_queue(ready_at_unix, priority DESC, fair_sequence);
        CREATE TABLE project_ticket_claim_keys (
            project_id TEXT NOT NULL REFERENCES projects(project_id),
            namespace TEXT NOT NULL,
            ticket_id TEXT NOT NULL,
            PRIMARY KEY(project_id, namespace, ticket_id)
        );
        INSERT INTO schema_migrations(version, applied_at_unix) VALUES (2, unixepoch());
        PRAGMA user_version = 2;"
    ).map_err(|e| e.to_string())?;
    tx.commit().map_err(|e| e.to_string())
}

fn backup_before_migration(connection: &Connection, state_root: &Path) -> Result<(), String> {
    let (busy, _, _) = connection
        .query_row("PRAGMA wal_checkpoint(FULL)", [], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })
        .map_err(|e| e.to_string())?;
    if busy != 0 {
        return Err("database backup postponed because WAL checkpoint is busy".into());
    }
    let source = state_root.join("state.sqlite3");
    let destination = state_root.join(format!("state.sqlite3.pre-v2-{}.bak", now_unix()?));
    let mut input = File::open(&source).map_err(|e| format!("{}: {e}", source.display()))?;
    let mut output = private_create_new(&destination)?;
    std::io::copy(&mut input, &mut output).map_err(|e| e.to_string())?;
    output.sync_all().map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(unix)]
fn private_create_new(path: &Path) -> Result<File, String> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(not(unix))]
fn private_create_new(path: &Path) -> Result<File, String> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))
}

impl ConfigStore {
    pub fn current_revision(&self, source_identity: &str) -> Result<Option<Revision>, String> {
        self.connection
            .query_row(
                "SELECT revision FROM config_current WHERE source_identity = ?1",
                [source_identity],
                |row| row.get::<_, u64>(0),
            )
            .optional()
            .map(|revision| revision.map(Revision))
            .map_err(|e| e.to_string())
    }

    pub fn apply_snapshot(
        &mut self,
        source_identity: &str,
        snapshot: &AppliedConfig,
        expectation: ExpectedRevision,
    ) -> Result<AppliedRevision, String> {
        let effective_config_json = canonical_json(&EffectiveConfig {
            config: snapshot.config.clone(),
            profiles: snapshot.profiles.clone(),
            source_root: snapshot.source_root.clone(),
        })?;
        let source_manifest_json = canonical_json(&snapshot.source_files)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        let current: Option<(u64, String)> = tx.query_row(
            "SELECT current.revision, snapshots.digest FROM config_current current JOIN config_snapshots snapshots USING(source_identity, revision) WHERE current.source_identity = ?1",
            [source_identity],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional().map_err(|e| e.to_string())?;
        if let Some((revision, digest)) = &current
            && digest == snapshot.digest.as_str()
        {
            tx.commit().map_err(|e| e.to_string())?;
            return Ok(AppliedRevision {
                revision: Revision(*revision),
                digest: snapshot.digest.clone(),
                unchanged: true,
            });
        }
        let expectation_matches = match (expectation, current.as_ref()) {
            (ExpectedRevision::Bootstrap, None) => true,
            (ExpectedRevision::Current(expected), Some((actual, _))) => expected.0 == *actual,
            _ => false,
        };
        if !expectation_matches {
            return Err(
                "configuration revision conflict; current snapshot was left unchanged".into(),
            );
        }
        let next_revision = current
            .as_ref()
            .map_or(Some(1), |(revision, _)| revision.checked_add(1))
            .ok_or_else(|| "configuration revision is exhausted".to_owned())?;
        i64::try_from(next_revision).map_err(|_| {
            "configuration revision exceeds SQLite's signed integer range".to_owned()
        })?;
        let applied_at = now_unix()?;
        tx.execute(
            "INSERT INTO config_snapshots(revision, source_identity, digest, digest_algorithm, representation, effective_config_json, source_manifest_json, applied_at_unix) VALUES (?1, ?2, ?3, 'sha256', 'canonical_json_utf8_sorted_keys', ?4, ?5, ?6)",
            params![next_revision, source_identity, snapshot.digest.as_str(), effective_config_json, source_manifest_json, applied_at],
        ).map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT INTO config_current(source_identity, revision) VALUES (?1, ?2) ON CONFLICT(source_identity) DO UPDATE SET revision=excluded.revision",
            params![source_identity, next_revision],
        ).map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(AppliedRevision {
            revision: Revision(next_revision),
            digest: snapshot.digest.clone(),
            unchanged: false,
        })
    }

    pub fn load_snapshot(&self, source_identity: &str) -> Result<Option<StoredSnapshot>, String> {
        let row = self
            .connection
            .query_row(
                "SELECT current.revision, snapshots.digest, snapshots.effective_config_json, snapshots.source_manifest_json FROM config_current current JOIN config_snapshots snapshots USING(source_identity, revision) WHERE current.source_identity = ?1",
                [source_identity],
                |row| {
                    Ok((
                        row.get::<_, u64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| e.to_string())?;
        row.map(|(revision, digest, effective_json, manifest_json)| {
            let effective: EffectiveConfig = serde_json::from_str(&effective_json)
                .map_err(|error| format!("stored effective config is invalid: {error}"))?;
            let source_files: Vec<SourceFile> = serde_json::from_str(&manifest_json)
                .map_err(|error| format!("stored source manifest is invalid: {error}"))?;
            let digest = Digest::parse(digest)?;
            Ok(StoredSnapshot {
                revision: Revision(revision),
                config: AppliedConfig {
                    config: effective.config,
                    profiles: effective.profiles,
                    source_root: effective.source_root,
                    source_files,
                    digest,
                },
            })
        })
        .transpose()
    }
}

fn acquire_machine_lock(state_root: &Path) -> Result<File, String> {
    let path = state_root.join("controller.lock");
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(format!(
                "machine lock must be a regular file: {}",
                path.display()
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("{}: {error}", path.display())),
    }
    let file = private_lock_file(&path)?;
    file.try_lock_exclusive().map_err(|error| {
        if error.kind() == std::io::ErrorKind::WouldBlock {
            format!("machine controller lock is held: {}", path.display())
        } else {
            format!("{}: {error}", path.display())
        }
    })?;
    Ok(file)
}

fn machine_registry_root() -> Result<std::path::PathBuf, String> {
    let root = std::env::var_os("XDG_STATE_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|home| std::path::PathBuf::from(home).join(".local/state"))
        })
        .ok_or_else(|| "HOME and XDG_STATE_HOME are unset".to_owned())?;
    Ok(root.join("rex-projects"))
}

fn validate_input(input: &DurableInput) -> Result<(), String> {
    if input.producer_id.is_empty()
        || input.producer_id.len() > 255
        || input.message_id.is_empty()
        || input.message_id.len() > 255
    {
        return Err("producer and message IDs must contain 1 to 255 bytes".into());
    }
    if input.producer_id.chars().any(char::is_control)
        || input.message_id.chars().any(char::is_control)
        || input.recipient.is_empty()
        || input.recipient.len() > 255
    {
        return Err("invalid inbox identity".into());
    }
    Digest::parse(input.content_digest.clone())?;
    if input.content_digest != content_digest(&input.payload) {
        return Err("input digest does not match payload bytes".into());
    }
    if input.payload.len() > MAX_INPUT_BYTES {
        return Err("input payload exceeds limit".into());
    }
    crate::protocol::parse_unique::<serde_json::Value>(input.payload.as_bytes())
        .map_err(|e| format!("invalid input JSON: {e}"))?;
    Ok(())
}

fn content_digest(bytes: &str) -> String {
    format!("{:x}", Sha256::digest(bytes.as_bytes()))
}

fn insert_effect(
    tx: &rusqlite::Transaction<'_>,
    effect: &EffectIntent,
    now: i64,
) -> Result<(), String> {
    validate_effect(effect)?;
    let inserted = tx.execute("INSERT INTO effects(operation_id, logical_key, kind, request_json, request_digest, expected_revision, status, attempt_count, next_attempt_at_unix, created_at_unix) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending', 0, ?7, ?7) ON CONFLICT(logical_key) DO NOTHING", params![effect.operation_id, effect.logical_key, effect.kind, effect.request_json, effect.request_digest, effect.expected_revision, now]).map_err(|e| e.to_string())?;
    if inserted == 0 {
        let (operation_id, digest, request_json): (String, String, String) = tx.query_row("SELECT operation_id, request_digest, request_json FROM effects WHERE logical_key=?1", [&effect.logical_key], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))).map_err(|e| e.to_string())?;
        if operation_id != effect.operation_id
            || digest != effect.request_digest
            || request_json != effect.request_json
        {
            return Err("logical effect key was reused with different intent".into());
        }
    }
    Ok(())
}

fn validate_effect(effect: &EffectIntent) -> Result<(), String> {
    if effect.operation_id.is_empty() || effect.logical_key.is_empty() || effect.kind.is_empty() {
        return Err("effect operation ID, logical key and kind must not be empty".into());
    }
    if effect.request_json.len() > MAX_INPUT_BYTES {
        return Err("effect request exceeds limit".into());
    }
    let request: serde_json::Value = crate::protocol::parse_unique(effect.request_json.as_bytes())
        .map_err(|e| format!("invalid effect request JSON: {e}"))?;
    let canonical = canonical_json(&request)?;
    if canonical != effect.request_json {
        return Err("effect request must use canonical JSON encoding".into());
    }
    let parsed = Digest::parse(effect.request_digest.clone())?;
    if parsed.as_str() != content_digest(&canonical) {
        return Err("effect request digest does not match canonical request bytes".into());
    }
    Ok(())
}

fn validate_active_generation(tx: &rusqlite::Transaction<'_>, expected: u64) -> Result<(), String> {
    let active: Option<u64> = tx.query_row("SELECT generation FROM controller_owners WHERE singleton=1 AND stopped_at_unix IS NULL", [], |row| row.get(0)).optional().map_err(|e| e.to_string())?;
    if active != Some(expected) {
        return Err("controller owner generation is stale".into());
    }
    Ok(())
}

#[cfg(unix)]
fn private_lock_file(path: &Path) -> Result<File, String> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).mode(0o600);
    let file = options
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(file)
}

#[cfg(not(unix))]
fn private_lock_file(path: &Path) -> Result<File, String> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(unix)]
fn ensure_private_database_file(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(format!(
                "state database must be a regular file: {}",
                path.display()
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true).mode(0o600);
            match options.open(path) {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(format!("{}: {error}", path.display())),
            }
        }
        Err(error) => return Err(format!("{}: {error}", path.display())),
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(not(unix))]
fn ensure_private_database_file(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => Err(format!(
            "state database must be a regular file: {}",
            path.display()
        )),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => fs::File::create(path)
            .map(|_| ())
            .map_err(|e| format!("{}: {e}", path.display())),
        Err(error) => Err(format!("{}: {error}", path.display())),
    }
}

#[cfg(unix)]
fn restrict_directory_permissions(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(not(unix))]
fn restrict_directory_permissions(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn restrict_file_permissions(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(not(unix))]
fn restrict_file_permissions(_path: &Path) -> Result<(), String> {
    Ok(())
}

fn canonical_json<T: serde::Serialize>(value: &T) -> Result<String, String> {
    let value = serde_json::to_value(value).map_err(|e| e.to_string())?;
    serde_json::to_string(&value).map_err(|e| e.to_string())
}

fn now_unix() -> Result<i64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use super::{
        ConfigStore, DurableInput, EffectIntent, EffectOutcome, ExpectedRevision, OwnerMetadata,
        ProjectRecord, content_digest,
    };
    use crate::config::{AppliedConfig, SourceFile, SourceKind};
    use crate::domain::ids::{Digest, ProjectId, Revision, TicketId, TicketNamespace, TicketRunId};

    static STORE_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn snapshot(digest: &str) -> AppliedConfig {
        AppliedConfig {
            config: serde_json::from_value(serde_json::json!({"schema_version":1,"adapters":{"tickets":{"kind":"command","command":["test"],"status_values":{"triage":"Triage","backlog":"Backlog","ready":"Ready","in_progress":"In Progress","in_review":"In Review","done":"Done","canceled":"Canceled"}}},"projects":{}})).unwrap(),
            profiles: BTreeMap::new(), source_root: "/tmp/config".into(), source_files: vec![SourceFile { kind: SourceKind::File, path: "/tmp/config/config.toml".into(), canonical_path: "/tmp/config/config.toml".into(), sha256: Digest::parse("a".repeat(64)).unwrap(), bytes: 1, contents: "x".into() }], digest: Digest::parse(digest).unwrap(),
        }
    }

    #[test]
    fn snapshot_apply_is_compare_and_swap_and_idempotent() {
        let _guard = STORE_TEST_LOCK.lock().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let mut store = ConfigStore::open_test(temp.path()).unwrap();
        assert!(
            std::fs::read_dir(temp.path())
                .unwrap()
                .filter_map(Result::ok)
                .any(|entry| entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("state.sqlite3.pre-v2-")
                    && entry
                        .path()
                        .extension()
                        .is_some_and(|extension| extension == "bak"))
        );
        assert!(ConfigStore::open_test(temp.path()).is_err());
        let first = store
            .apply_snapshot(
                "config",
                &snapshot(&"a".repeat(64)),
                ExpectedRevision::Bootstrap,
            )
            .unwrap();
        assert_eq!(first.revision.0, 1);
        let unchanged = store
            .apply_snapshot(
                "config",
                &snapshot(&"a".repeat(64)),
                ExpectedRevision::Current(first.revision),
            )
            .unwrap();
        assert!(unchanged.unchanged);
        assert!(
            store
                .apply_snapshot(
                    "config",
                    &snapshot(&"b".repeat(64)),
                    ExpectedRevision::Current(crate::domain::ids::Revision(9))
                )
                .is_err()
        );
        assert_eq!(store.current_revision("config").unwrap().unwrap().0, 1);
        let second = store
            .apply_snapshot(
                "config",
                &snapshot(&"b".repeat(64)),
                ExpectedRevision::Current(first.revision),
            )
            .unwrap();
        assert_eq!(second.revision.0, 2);
        let independent = store
            .apply_snapshot(
                "other-config",
                &snapshot(&"a".repeat(64)),
                ExpectedRevision::Bootstrap,
            )
            .unwrap();
        assert_eq!(independent.revision.0, 1);
        let loaded = store.load_snapshot("config").unwrap().unwrap();
        assert_eq!(loaded.revision.0, 2);
        assert_eq!(loaded.config.config.schema_version, 1);
        assert_eq!(loaded.config.digest.as_str(), "b".repeat(64));
    }

    #[test]
    fn transition_commits_inbox_and_effects_atomically_and_deduplicates_retries() {
        let _guard = STORE_TEST_LOCK.lock().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let mut store = ConfigStore::open_test(temp.path()).unwrap();
        let applied = store
            .apply_snapshot(
                "factory",
                &snapshot(&"a".repeat(64)),
                ExpectedRevision::Bootstrap,
            )
            .unwrap();
        let project = ProjectRecord {
            id: ProjectId::parse("payments").unwrap(),
            config_source: "factory".into(),
            config_revision: applied.revision,
            config_digest: Digest::parse("a".repeat(64)).unwrap(),
            mode: "goal".into(),
            goal_revision: 1,
            desired_lifecycle: "running".into(),
            state_revision: Revision(0),
        };
        assert!(store.insert_project(&project).unwrap());
        let generation = store
            .start_owner(&OwnerMetadata {
                owner_nonce: "test-owner".into(),
                state_root: temp.path().to_string_lossy().into_owned(),
                config_source: "factory".into(),
                process_start_identity: "test-process-start".into(),
                executable_path: "/tmp/rex-projects-test".into(),
                executable_digest: "e".repeat(64),
                rex_server_identity: None,
                rex_session_id: None,
                rex_block_id: None,
            })
            .unwrap();
        let epoch = store
            .set_project_lifecycle(generation, &project.id, "running")
            .unwrap();
        let namespace = TicketNamespace::parse("github:org/repo").unwrap();
        let ticket = TicketId::parse("#12").unwrap();
        let ticket_run = TicketRunId::parse("payments-12-g1").unwrap();
        store
            .create_ticket_run(
                generation,
                &project.id,
                &namespace,
                &ticket,
                &ticket_run,
                1,
                "queued",
                "ToDo",
            )
            .unwrap();
        assert!(
            store
                .claim_ticket(generation, &namespace, &ticket, &project.id, &ticket_run, 1)
                .unwrap()
        );
        let wrong_ticket = TicketId::parse("#13").unwrap();
        assert!(
            store
                .claim_ticket(
                    generation,
                    &namespace,
                    &wrong_ticket,
                    &project.id,
                    &ticket_run,
                    1
                )
                .is_err()
        );
        let other_project = ProjectRecord {
            id: ProjectId::parse("other").unwrap(),
            config_source: "factory".into(),
            config_revision: applied.revision,
            config_digest: Digest::parse("a".repeat(64)).unwrap(),
            mode: "operations".into(),
            goal_revision: 0,
            desired_lifecycle: "running".into(),
            state_revision: Revision(0),
        };
        store.insert_project(&other_project).unwrap();
        let other_run = TicketRunId::parse("other-12-g1").unwrap();
        store
            .create_ticket_run(
                generation,
                &other_project.id,
                &namespace,
                &ticket,
                &other_run,
                1,
                "queued",
                "ToDo",
            )
            .unwrap();
        assert!(
            !store
                .claim_ticket(
                    generation,
                    &namespace,
                    &ticket,
                    &other_project.id,
                    &other_run,
                    1
                )
                .unwrap()
        );
        assert!(
            store
                .release_ticket_claim(generation, &namespace, &ticket, &ticket_run, 1)
                .unwrap()
        );
        assert!(
            store
                .claim_ticket(
                    generation,
                    &namespace,
                    &ticket,
                    &other_project.id,
                    &other_run,
                    1
                )
                .unwrap()
        );
        assert!(
            store
                .enqueue_ready(
                    generation,
                    &project.id,
                    "payments:ticket-1:coordinator",
                    "ticket",
                    "ticket-1",
                    "coordinator",
                    "agent",
                    10,
                    1,
                    epoch
                )
                .unwrap()
        );
        let reserved = store
            .reserve_next_ready(generation, 1, 1, 1, 1)
            .unwrap()
            .unwrap();
        assert_eq!(reserved.work_key, "payments:ticket-1:coordinator");
        assert!(
            store
                .reserve_next_ready(generation, 1, 1, 1, 1)
                .unwrap()
                .is_none()
        );
        store
            .release_slot_after_confirmed_exit(
                generation,
                "agent",
                reserved.slot_index,
                &reserved.work_key,
            )
            .unwrap();
        let payload = r#"{"kind":"plan_accepted"}"#;
        let input = DurableInput {
            producer_id: "agent-run-1".into(),
            message_id: "wake-1".into(),
            content_digest: content_digest(payload),
            recipient: "coordinator".into(),
            payload: payload.into(),
        };
        let forged_digest = DurableInput {
            producer_id: "agent-run-forged".into(),
            message_id: "wake-forged".into(),
            content_digest: "f".repeat(64),
            recipient: "coordinator".into(),
            payload: payload.into(),
        };
        assert!(
            store
                .commit_transition(
                    generation,
                    &project.id,
                    Revision(0),
                    &forged_digest,
                    "forged digest",
                    "{}",
                    &[]
                )
                .is_err()
        );
        let effect = EffectIntent {
            operation_id: "op-1".into(),
            logical_key: "payments:ticket-1:start-worker".into(),
            kind: "start_worker".into(),
            request_json: r#"{"ticket_id":"ticket-1"}"#.into(),
            request_digest: content_digest(r#"{"ticket_id":"ticket-1"}"#),
            expected_revision: Some(0),
        };
        let first = store
            .commit_transition(
                generation,
                &project.id,
                Revision(0),
                &input,
                "plan accepted",
                "{}",
                std::slice::from_ref(&effect),
            )
            .unwrap();
        assert!(!first.duplicate);
        assert_eq!(
            store.project(&project.id).unwrap().unwrap().state_revision,
            Revision(1)
        );
        let retried = store
            .commit_transition(
                generation,
                &project.id,
                Revision(0),
                &input,
                "ignored retry",
                "{}",
                &[effect],
            )
            .unwrap();
        assert!(retried.duplicate);
        assert_eq!(retried.receipt, first.receipt);
        assert_eq!(
            store.project(&project.id).unwrap().unwrap().state_revision,
            Revision(1)
        );
        let conflict = DurableInput {
            producer_id: "agent-run-2".into(),
            message_id: "wake-2".into(),
            content_digest: content_digest(r#"{"kind":"reviewed"}"#),
            recipient: "coordinator".into(),
            payload: r#"{"kind":"reviewed"}"#.into(),
        };
        assert!(
            store
                .commit_transition(
                    generation,
                    &project.id,
                    Revision(0),
                    &conflict,
                    "stale",
                    "{}",
                    &[]
                )
                .is_err()
        );
        assert_eq!(
            store.project(&project.id).unwrap().unwrap().state_revision,
            Revision(1)
        );
        let claimed = store
            .next_due_effect(generation, i64::MAX)
            .unwrap()
            .unwrap();
        assert_eq!(claimed.operation_id, "op-1");
        let new_generation = store
            .start_owner(&OwnerMetadata {
                owner_nonce: "restarted-owner".into(),
                state_root: temp.path().to_string_lossy().into_owned(),
                config_source: "factory".into(),
                process_start_identity: "new-process-start".into(),
                executable_path: "/tmp/rex-projects-test".into(),
                executable_digest: "f".repeat(64),
                rex_server_identity: None,
                rex_session_id: None,
                rex_block_id: None,
            })
            .unwrap();
        assert_eq!(new_generation, generation + 1);
        let delayed = DurableInput {
            producer_id: "agent-run-1".into(),
            message_id: "late-result".into(),
            content_digest: content_digest(r#"{"kind":"late"}"#),
            recipient: "coordinator".into(),
            payload: r#"{"kind":"late"}"#.into(),
        };
        assert!(
            store
                .commit_transition(
                    generation,
                    &project.id,
                    Revision(1),
                    &delayed,
                    "stale generation",
                    "{}",
                    &[]
                )
                .is_err()
        );
        assert!(
            store
                .finish_effect("op-1", generation, EffectOutcome::Succeeded, None)
                .is_err()
        );
        assert!(store.next_due_effect(generation, i64::MAX).is_err());
        assert!(
            store
                .next_due_effect(new_generation, i64::MAX)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn newer_database_schema_is_refused_without_changing_database_bytes() {
        let _guard = STORE_TEST_LOCK.lock().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let database = temp.path().join("state.sqlite3");
        {
            let connection = rusqlite::Connection::open(&database).unwrap();
            connection.pragma_update(None, "user_version", 999).unwrap();
        }
        let before = std::fs::read(&database).unwrap();
        let error = match ConfigStore::open_test(temp.path()) {
            Ok(_) => panic!("newer schema must be refused"),
            Err(error) => error,
        };
        assert!(error.contains("newer than supported"));
        assert_eq!(std::fs::read(&database).unwrap(), before);
    }
}
