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
    AgentRunId, Digest, ProfileId, ProjectId, Revision, TicketId, TicketNamespace, TicketRunId,
};
use crate::domain::types::Role;
use crate::engine::reducer::{Input, Phase, TicketRun, WakeTarget, reduce};
use crate::launch::{
    AgentLaunchAuthority, AgentLaunchReceipt, AgentStartRequest, ObservedProviderStart,
    ObservedWrapperIdentity, ProviderQualification, RexBlockLifecycle, RexFocusTarget, RexView,
    RexViewBlock, RexViewCleanupCandidate, RexViewKind, RexViewRecord, authorize_start,
};

pub mod agent_recovery;
#[path = "store/dashboard_projection.rs"]
pub mod dashboard_projection;

pub const SCHEMA_VERSION: i64 = 11;
#[path = "store/accepted_plans.rs"]
pub mod accepted_plans;
pub mod agent_runtime;
pub mod host_jobs;
pub mod human;
#[path = "store/learning.rs"]
mod learning_store;
pub mod merge_work;
pub use learning_store::{
    CandidateRegistration, KnowledgePublicationIntent, KnowledgePublicationReceipt,
    LearningCandidatePackage, LearningCandidateRecord, ProfilePromotionIntent,
    ProjectSupervisorMaintenance, StoredApprovedProfilePackage, StoredTrial,
    SupervisorCandidateEntry, SupervisorKnowledgeEntry, TrialProgress,
};
pub mod operations;
pub mod publication_monitor;
pub mod scheduler;
const INITIAL_SCHEMA_VERSION: i64 = 1;
const MAX_INPUT_BYTES: usize = 1_048_576;
type DueEffectRow = (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    Option<u64>,
);
type ClaimableEffectRow = (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    Option<u64>,
);
type LaunchAgentRunRow = (
    String,
    String,
    u64,
    String,
    String,
    u64,
    String,
    Option<String>,
);
type PendingControlRow = (
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    i64,
);
type RexViewIdentityRow = (
    String,
    String,
    Option<String>,
    Option<String>,
    u64,
    String,
    String,
    String,
);
type LaunchRexViewRow = (
    String,
    String,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
);

type SucceededEffectRow = (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    Option<u64>,
    u32,
    i64,
    Option<String>,
);
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

pub fn durable_input_digest(recipient: &str, payload: &str) -> String {
    let envelope = serde_json::to_vec(&(recipient, payload)).expect("string tuple serializes");
    format!("{:x}", Sha256::digest(envelope))
}

pub struct InputReceipt {
    pub receipt: serde_json::Value,
    pub duplicate: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectIntent {
    pub project_id: ProjectId,
    pub subject_type: String,
    pub subject_id: String,
    pub operation_id: String,
    pub logical_key: String,
    pub kind: String,
    pub request_json: String,
    pub request_digest: String,
    pub expected_revision: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimedEffect {
    pub intent: EffectIntent,
    pub state: EffectClaimState,
    pub attempt_count: u32,
    pub created_at_unix: i64,
}

/// An immutable effect record re-read from SQLite after it reached `succeeded`.
/// Its private fields prevent a caller from turning a transient handler observation into proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SucceededEffectReceipt {
    intent: EffectIntent,
    attempt_count: u32,
    created_at_unix: i64,
    receipt_json: String,
}

impl SucceededEffectReceipt {
    pub fn intent(&self) -> &EffectIntent {
        &self.intent
    }

    pub fn attempt_count(&self) -> u32 {
        self.attempt_count
    }

    pub fn created_at_unix(&self) -> i64 {
        self.created_at_unix
    }

    pub fn receipt_json(&self) -> &str {
        &self.receipt_json
    }

    #[cfg(test)]
    pub(crate) fn for_test(request: &crate::effects::EffectRequest, receipt_json: String) -> Self {
        Self {
            intent: request.intent.clone(),
            attempt_count: request.attempt_count,
            created_at_unix: request.created_at_unix,
            receipt_json,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectClaimState {
    Pending,
    Uncertain,
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
    pub rex_endpoint: Option<String>,
    pub rex_server_identity: Option<String>,
    pub rex_session_id: Option<String>,
    pub rex_block_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectStatus {
    pub id: ProjectId,
    pub mode: String,
    pub desired_lifecycle: String,
    pub observed_lifecycle: String,
    pub project_epoch: u64,
    pub next_due_at_unix: i64,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlCommand {
    pub request_id: String,
    pub kind: String,
    pub project_id: Option<ProjectId>,
    pub lifecycle: Option<String>,
    pub created_at_unix: i64,
    pub applied_config: Option<AppliedRevision>,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct ConfigApplyPayload {
    source_identity: String,
    snapshot: AppliedConfig,
    expectation: ExpectedRevision,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct HumanClaimRelease {
    pub namespace: String,
    pub ticket: String,
    pub ticket_run_id: String,
    pub generation: u64,
    pub expected_revision: u64,
    pub reason: String,
    pub disposition: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeStatus {
    pub schema_version: i64,
    pub owner_generation: Option<u64>,
    pub owner_pid: Option<u32>,
    pub owner_process_start_identity: Option<String>,
    pub owner_started_at_unix: Option<i64>,
    pub owner_rex_endpoint: Option<String>,
    pub owner_rex_server_identity: Option<String>,
    pub owner_rex_session_id: Option<String>,
    pub owner_rex_block_id: Option<String>,
    pub projects: Vec<ProjectStatus>,
    pub pending_commands: u64,
    pub rejected_commands: u64,
    pub pending_effects: u64,
    pub uncertain_effects: u64,
    pub occupied_slots: u64,
    pub observed_at_unix: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentMailboxRegistration {
    pub agent_run_id: String,
    pub canonical_directory: String,
    pub capability_digest: String,
    pub expires_at_unix: u64,
    pub max_request_bytes: usize,
    pub max_pending_requests: usize,
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

#[derive(Clone, Copy, Debug, serde::Deserialize, serde::Serialize)]
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
    _file: Option<File>,
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
            _file: Some(acquire_machine_lock(lock_root)?),
        })
    }
}

impl ConfigStore {
    pub fn open(state_root: &Path) -> Result<Self, String> {
        Self::open_with_lock(state_root, MachineLock::acquire(state_root)?)
    }

    /// Open the state database for a bounded external control request while the foreground
    /// controller owns the machine lock. Mutations remain available only through typed APIs
    /// which fence on the active owner generation.
    pub fn open_control(state_root: &Path) -> Result<Self, String> {
        let database = state_root.join("state.sqlite3");
        let metadata = fs::symlink_metadata(&database)
            .map_err(|error| format!("{}: {error}", database.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err("control database must be an existing regular file".into());
        }
        let connection = Connection::open(&database)
            .map_err(|error| format!("{}: {error}", database.display()))?;
        connection
            .busy_timeout(std::time::Duration::from_secs(2))
            .map_err(|error| error.to_string())?;
        let schema_version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(|error| error.to_string())?;
        if schema_version != SCHEMA_VERSION as i64 {
            return Err(format!(
                "control request requires current schema {SCHEMA_VERSION}, found {schema_version}; run the foreground controller first"
            ));
        }
        connection
            .execute_batch("PRAGMA foreign_keys=ON;")
            .map_err(|error| error.to_string())?;
        Ok(Self {
            connection,
            _machine_lock: MachineLock { _file: None },
        })
    }

    #[cfg(test)]
    pub(crate) fn open_test(state_root: &Path) -> Result<Self, String> {
        let lock_root = state_root.join("machine-registry");
        let machine_lock = MachineLock::acquire_in_registry(state_root, &lock_root)?;
        Self::open_with_lock(state_root, machine_lock)
    }

    fn open_with_lock(state_root: &Path, machine_lock: MachineLock) -> Result<Self, String> {
        let database = state_root.join("state.sqlite3");
        ensure_private_database_file(&database)?;
        let mut connection =
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
        if existing_version == 8 {
            // Validate the hold layout before WAL/journal PRAGMAs can modify an incompatible
            // development database that already claims this schema version.
            Self::validate_human_v8_schema(&connection)?;
        }
        if existing_version == 10 {
            learning_store::validate_v10_schema(&connection)?;
        }
        connection
            .execute_batch(
                "PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;",
            )
            .map_err(|e| e.to_string())?;
        if existing_version < 2 {
            Self::migrate(&connection, existing_version, state_root)?;
        }
        if existing_version < 3 {
            migrate_v3(&connection)?;
        }
        if existing_version < 4 {
            if existing_version > 0 {
                backup_before_migration(&connection, state_root)?;
            }
            migrate_v4(&connection)?;
        }
        if existing_version < 5 {
            if existing_version > 0 {
                backup_before_migration(&connection, state_root)?;
            }
            migrate_v5(&connection)?;
        }
        if existing_version < 6 {
            if existing_version > 0 {
                backup_before_migration(&connection, state_root)?;
            }
            migrate_v6(&connection)?;
        }
        if existing_version < 7 {
            if existing_version > 0 {
                backup_before_migration(&connection, state_root)?;
            }
            crate::launch::migrate_v7(&mut connection)?;
        }
        if existing_version < 8 {
            if existing_version > 0 {
                backup_before_migration(&connection, state_root)?;
            }
            Self::migrate_human_v8(&mut connection)?;
        }
        Self::validate_human_v8_schema(&connection)?;
        if existing_version < 9 {
            if existing_version > 0 {
                backup_before_migration(&connection, state_root)?;
            }
            scheduler::migrate_v9(&connection)?;
        }
        if existing_version < 10 {
            if existing_version > 0 {
                backup_before_migration(&connection, state_root)?;
            }
            learning_store::migrate_v10(&connection)?;
        }
        if existing_version < 11 {
            if existing_version > 0 {
                backup_before_migration(&connection, state_root)?;
            }
            operations::migrate_v11(&connection)?;
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

    pub fn register_rex_view(
        &mut self,
        owner_generation: u64,
        view: &RexView,
    ) -> Result<bool, String> {
        view.validate()?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let inserted = tx.execute(
            "INSERT INTO rex_views(view_id,project_id,view_kind,ticket_namespace,ticket_id,view_epoch,rex_server_identity,rex_session_id,rex_window_id,pinned,lifecycle,created_at_unix,updated_at_unix) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,0,'active',?10,?10) ON CONFLICT(view_id) DO NOTHING",
            params![view.view_id.as_str(),view.project_id.as_str(),serde_json::to_value(view.kind).map_err(|error| error.to_string())?.as_str().unwrap_or_default(),view.ticket_namespace,view.ticket_id,view.view_epoch,view.rex_server_identity,view.rex_session_id,view.rex_window_id,now_unix()?],
        ).map_err(|error| error.to_string())? == 1;
        let stored: Option<RexViewIdentityRow> = tx.query_row(
            "SELECT project_id,view_kind,ticket_namespace,ticket_id,view_epoch,rex_server_identity,rex_session_id,rex_window_id FROM rex_views WHERE view_id=?1",
            [view.view_id.as_str()], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?)),
        ).optional().map_err(|error| error.to_string())?;
        let expected_kind = serde_json::to_value(view.kind)
            .map_err(|error| error.to_string())?
            .as_str()
            .unwrap_or_default()
            .to_owned();
        let expected = (
            view.project_id.as_str().to_owned(),
            expected_kind,
            view.ticket_namespace.clone(),
            view.ticket_id.clone(),
            view.view_epoch,
            view.rex_server_identity.clone(),
            view.rex_session_id.clone(),
            view.rex_window_id.clone(),
        );
        if stored.as_ref() != Some(&expected) {
            return Err("Rex view ID already exists with different identity".into());
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(inserted)
    }

    pub fn observe_rex_view_block(
        &mut self,
        owner_generation: u64,
        view_id: &Digest,
        block_id: &str,
        lifecycle: RexBlockLifecycle,
        process_absent_confirmed: bool,
        retained_until_unix: Option<u64>,
    ) -> Result<(), String> {
        if block_id.trim().is_empty() || block_id.chars().any(char::is_control) {
            return Err("Rex block identity is malformed".into());
        }
        if lifecycle == RexBlockLifecycle::Unknown && process_absent_confirmed {
            return Err("unknown Rex block cannot be marked process-absent confirmed".into());
        }
        if lifecycle == RexBlockLifecycle::Active && process_absent_confirmed {
            return Err("active Rex block cannot be marked process-absent confirmed".into());
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let status = serde_json::to_value(lifecycle).map_err(|error| error.to_string())?;
        let status = status.as_str().ok_or("Rex block lifecycle is invalid")?;
        let changed = tx.execute(
            "UPDATE rex_view_blocks SET lifecycle=?3,process_absent_confirmed=?4,last_observed_at_unix=?5,retained_until_unix=COALESCE(?6,retained_until_unix) WHERE view_id=?1 AND block_id=?2 AND lifecycle!='closed' AND (lifecycle='unknown' OR ?3='unknown' OR (?3='closed' AND process_absent_confirmed=1) OR lifecycle='active')",
            params![view_id.as_str(),block_id,status,process_absent_confirmed,now_unix()?,retained_until_unix],
        ).map_err(|error|error.to_string())?;
        if changed != 1 {
            return Err(
                "Rex view block not found or observation would regress a terminal state".into(),
            );
        }
        tx.commit().map_err(|error| error.to_string())
    }

    pub fn rex_view_history(&self, project_id: &ProjectId) -> Result<Vec<RexViewRecord>, String> {
        let mut statement = self.connection.prepare(
            "SELECT view_id,project_id,view_kind,ticket_namespace,ticket_id,view_epoch,rex_server_identity,rex_session_id,rex_window_id,pinned,lifecycle,created_at_unix,updated_at_unix,closed_at_unix FROM rex_views WHERE project_id=?1 ORDER BY created_at_unix DESC,view_epoch DESC",
        ).map_err(|error| error.to_string())?;
        let rows = statement
            .query_map([project_id.as_str()], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, u64>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, bool>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, u64>(11)?,
                    row.get::<_, u64>(12)?,
                    row.get::<_, Option<u64>>(13)?,
                ))
            })
            .map_err(|error| error.to_string())?;
        rows.map(|row| {
            let (
                id,
                project,
                kind,
                namespace,
                ticket,
                epoch,
                server,
                session,
                window,
                pinned,
                lifecycle,
                created,
                updated,
                closed,
            ) = row.map_err(|error| error.to_string())?;
            let kind = match kind.as_str() {
                "supervisor" => RexViewKind::Supervisor,
                "ticket" => RexViewKind::Ticket,
                _ => return Err("stored Rex view kind is invalid".into()),
            };
            let view = RexView {
                view_id: Digest::parse(id)?,
                project_id: ProjectId::parse(project)?,
                kind,
                ticket_namespace: namespace,
                ticket_id: ticket,
                view_epoch: epoch,
                rex_server_identity: server,
                rex_session_id: session,
                rex_window_id: window,
            };
            view.validate()?;
            Ok(RexViewRecord {
                view,
                pinned,
                lifecycle,
                created_at_unix: created,
                updated_at_unix: updated,
                closed_at_unix: closed,
            })
        })
        .collect()
    }

    pub fn rex_focus_target(
        &self,
        owner_generation: u64,
        view_id: &Digest,
        block_id: &str,
    ) -> Result<RexFocusTarget, String> {
        let active_generation: Option<u64> = self.connection.query_row(
            "SELECT generation FROM controller_owners WHERE singleton=1 AND stopped_at_unix IS NULL",
            [],
            |row| row.get(0),
        ).optional().map_err(|error|error.to_string())?;
        if active_generation != Some(owner_generation) {
            return Err("Rex focus request is fenced to a stale controller generation".into());
        }
        let target: Option<(String,String,String)> = self.connection.query_row(
            "SELECT v.rex_server_identity,v.rex_session_id,v.rex_window_id FROM rex_views v JOIN rex_view_blocks b USING(view_id) WHERE v.view_id=?1 AND b.block_id=?2 AND v.lifecycle='active' AND b.lifecycle!='closed'",
            params![view_id.as_str(),block_id], |row|Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
        ).optional().map_err(|error|error.to_string())?;
        let Some((server, session, window)) = target else {
            return Err("active Rex focus target not found".into());
        };
        Ok(RexFocusTarget {
            view_id: view_id.clone(),
            rex_server_identity: server,
            rex_session_id: session,
            rex_window_id: window,
            rex_block_id: block_id.to_owned(),
        })
    }

    pub fn set_rex_view_pin(
        &mut self,
        owner_generation: u64,
        view_id: &Digest,
        pinned: bool,
    ) -> Result<(), String> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let changed = tx.execute("UPDATE rex_views SET pinned=?2,updated_at_unix=?3 WHERE view_id=?1 AND lifecycle='active'", params![view_id.as_str(),pinned,now_unix()?]).map_err(|error| error.to_string())?;
        if changed != 1 {
            return Err("active Rex view not found".into());
        }
        tx.commit().map_err(|error| error.to_string())
    }

    pub fn rex_view_cleanup_candidates(
        &self,
        now_unix: u64,
        retention_seconds: u64,
    ) -> Result<Vec<RexViewCleanupCandidate>, String> {
        if !self.rex_view_cleanup_schema_ready()? {
            return Ok(Vec::new());
        }
        let cutoff = now_unix.saturating_sub(retention_seconds);
        let mut statement=self.connection.prepare(
            "SELECT v.view_id,v.project_id,v.view_kind,v.ticket_namespace,v.ticket_id,v.view_epoch,v.rex_server_identity,v.rex_session_id,v.rex_window_id,v.updated_at_unix FROM rex_views v WHERE v.lifecycle='active' AND v.pinned=0 AND v.updated_at_unix<=?1 AND EXISTS (SELECT 1 FROM rex_view_blocks b WHERE b.view_id=v.view_id) AND NOT EXISTS (SELECT 1 FROM rex_view_blocks b WHERE b.view_id=v.view_id AND (b.ownership='user' OR b.lifecycle NOT IN ('completed','failed','closed') OR b.process_absent_confirmed=0 OR (b.retained_until_unix IS NOT NULL AND b.retained_until_unix>?2))) AND NOT EXISTS (SELECT 1 FROM human_requests h WHERE h.rex_view_id=v.view_id AND h.lifecycle IN ('pending','presented','response_queued')) ORDER BY v.updated_at_unix",
        ).map_err(|error|error.to_string())?;
        let rows = statement
            .query_map(params![cutoff, now_unix], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, u64>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, u64>(9)?,
                ))
            })
            .map_err(|error| error.to_string())?;
        rows.map(|row| {
            let (id, project, kind, namespace, ticket, epoch, server, session, window, updated) =
                row.map_err(|error| error.to_string())?;
            let kind = match kind.as_str() {
                "supervisor" => RexViewKind::Supervisor,
                "ticket" => RexViewKind::Ticket,
                _ => return Err("stored Rex view kind is invalid".into()),
            };
            let view = RexView {
                view_id: Digest::parse(id)?,
                project_id: ProjectId::parse(project)?,
                kind,
                ticket_namespace: namespace,
                ticket_id: ticket,
                view_epoch: epoch,
                rex_server_identity: server,
                rex_session_id: session,
                rex_window_id: window,
            };
            view.validate()?;
            Ok(RexViewCleanupCandidate {
                view,
                close_after_unix: updated.saturating_add(retention_seconds),
            })
        })
        .collect()
    }

    pub fn begin_rex_view_close(
        &mut self,
        owner_generation: u64,
        candidate: &RexViewCleanupCandidate,
        now_unix: u64,
        retention_seconds: u64,
    ) -> Result<(), String> {
        candidate.view.validate()?;
        if candidate.close_after_unix > now_unix {
            return Err("Rex view retention period has not elapsed".into());
        }
        if !self.rex_view_cleanup_schema_ready()? {
            return Err("human review hold state is unavailable; Rex view cannot be closed".into());
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let cutoff = now_unix.saturating_sub(retention_seconds);
        let changed=tx.execute(
            "UPDATE rex_views SET lifecycle='close_pending',updated_at_unix=?2 WHERE view_id=?1 AND lifecycle='active' AND pinned=0 AND updated_at_unix<=?3 AND EXISTS (SELECT 1 FROM rex_view_blocks b WHERE b.view_id=rex_views.view_id) AND NOT EXISTS (SELECT 1 FROM rex_view_blocks b WHERE b.view_id=rex_views.view_id AND (b.ownership='user' OR b.lifecycle NOT IN ('completed','failed','closed') OR b.process_absent_confirmed=0 OR (b.retained_until_unix IS NOT NULL AND b.retained_until_unix>?2))) AND NOT EXISTS (SELECT 1 FROM human_requests h WHERE h.rex_view_id=rex_views.view_id AND h.lifecycle IN ('pending','presented','response_queued'))",
            params![candidate.view.view_id.as_str(),now_unix,cutoff],
        ).map_err(|error|error.to_string())?;
        if changed != 1 {
            return Err("Rex view is no longer safe to close".into());
        }
        tx.commit().map_err(|error| error.to_string())
    }

    fn rex_view_cleanup_schema_ready(&self) -> Result<bool, String> {
        let table_exists: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='human_requests')",
            [],
            |row| row.get(0),
        ).map_err(|error| error.to_string())?;
        if !table_exists {
            return Ok(false);
        }
        let has_view_binding: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('human_requests') WHERE name='rex_view_id')",
            [],
            |row| row.get(0),
        ).map_err(|error| error.to_string())?;
        Ok(has_view_binding)
    }

    pub fn finish_rex_view_close(
        &mut self,
        owner_generation: u64,
        view_id: &Digest,
        observed_closed: bool,
    ) -> Result<(), String> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let now = now_unix()?;
        let lifecycle = if observed_closed { "closed" } else { "unknown" };
        let changed=tx.execute("UPDATE rex_views SET lifecycle=?2,updated_at_unix=?3,closed_at_unix=CASE WHEN ?2='closed' THEN ?3 ELSE NULL END WHERE view_id=?1 AND lifecycle='close_pending'",params![view_id.as_str(),lifecycle,now]).map_err(|error|error.to_string())?;
        if changed != 1 {
            return Err("Rex view has no matching pending close".into());
        }
        if observed_closed {
            tx.execute("UPDATE rex_view_blocks SET lifecycle='closed',process_absent_confirmed=1,last_observed_at_unix=?2 WHERE view_id=?1",params![view_id.as_str(),now]).map_err(|error|error.to_string())?;
        } else {
            tx.execute("UPDATE rex_view_blocks SET lifecycle='unknown',process_absent_confirmed=0,last_observed_at_unix=?2 WHERE view_id=?1 AND lifecycle!='closed'",params![view_id.as_str(),now]).map_err(|error|error.to_string())?;
        }
        tx.commit().map_err(|error| error.to_string())
    }

    pub fn register_rex_view_block(
        &mut self,
        owner_generation: u64,
        block: &RexViewBlock,
    ) -> Result<bool, String> {
        block.validate()?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let view_state: Option<String> = tx
            .query_row(
                "SELECT lifecycle FROM rex_views WHERE view_id=?1",
                [block.view_id.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if view_state.as_deref() != Some("active") {
            return Err("Rex block can only be recorded in an active view".into());
        }
        if block.ownership == crate::launch::RexBlockOwnership::Factory {
            let run_id = block
                .agent_run_id
                .as_ref()
                .ok_or("factory block requires AgentRun")?;
            let (view, role, block_id): (String, String, String) = tx
                .query_row(
                    "SELECT rex_view_id,role,rex_block_id FROM agent_launch_authority WHERE agent_run_id=?1",
                    [run_id.as_str()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()
                .map_err(|error| error.to_string())?
                .ok_or("factory block requires persisted launch authority")?;
            let role_raw = serde_json::to_value(block.role)
                .map_err(|error| error.to_string())?
                .as_str()
                .unwrap_or_default()
                .to_owned();
            if view != block.view_id.as_str() || role != role_raw || block_id != block.block_id {
                return Err("Rex block identity does not match launch authority".into());
            }
        }
        let ownership = serde_json::to_value(block.ownership).map_err(|error| error.to_string())?;
        let lifecycle = serde_json::to_value(block.lifecycle).map_err(|error| error.to_string())?;
        let role = block.role.map(|role| {
            serde_json::to_value(role)
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned))
        });
        let inserted=tx.execute("INSERT INTO rex_view_blocks(view_id,block_id,agent_run_id,role,ownership,lifecycle,process_absent_confirmed,created_at_unix,last_observed_at_unix,retained_until_unix) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?8,?9) ON CONFLICT(view_id,block_id) DO NOTHING",params![block.view_id.as_str(),block.block_id,block.agent_run_id.as_ref().map(AgentRunId::as_str),role.flatten(),ownership.as_str().unwrap_or_default(),lifecycle.as_str().unwrap_or_default(),block.process_absent_confirmed,now_unix()?,block.retained_until_unix]).map_err(|error|error.to_string())?==1;
        let requested_role = block.role.map(|role| {
            serde_json::to_value(role)
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned))
        });
        let existing: Option<(Option<String>,Option<String>,String)>=tx.query_row(
            "SELECT agent_run_id,role,ownership FROM rex_view_blocks WHERE view_id=?1 AND block_id=?2",
            params![block.view_id.as_str(),block.block_id],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
        ).optional().map_err(|error|error.to_string())?;
        if existing.as_ref().is_none_or(|row| {
            row.0.as_deref() != block.agent_run_id.as_ref().map(AgentRunId::as_str)
                || row.1 != requested_role.flatten()
                || row.2 != ownership.as_str().unwrap_or_default()
        }) {
            return Err("Rex block already exists with different identity".into());
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(inserted)
    }

    /// Persist immutable provider qualification evidence. A caller-supplied digest is never
    /// accepted; the key is recomputed from the full receipt and verified on every read.
    pub fn store_provider_qualification(
        &mut self,
        owner_generation: u64,
        qualification: &ProviderQualification,
    ) -> Result<Digest, String> {
        qualification.validate_for_storage()?;
        let receipt_digest = qualification.canonical_digest()?;
        let receipt_json =
            serde_json::to_string(qualification).map_err(|error| error.to_string())?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        tx.execute(
            "INSERT INTO provider_qualifications(receipt_digest,project_id,profile_id,profile_digest,adapter,executable_path,executable_digest,provider_version,permission_mode,invocation_options_digest,commit_mode,status,receipt_json,created_by_generation,created_at_unix) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15) ON CONFLICT(receipt_digest) DO NOTHING",
            params![receipt_digest.as_str(), qualification.project_id.as_str(), qualification.profile_id.as_str(), qualification.profile_digest.as_str(), serde_json::to_value(qualification.adapter).map_err(|error| error.to_string())?.as_str().unwrap_or_default(), qualification.executable_path, qualification.executable_digest.as_str(), qualification.provider_version, qualification.permission_mode, qualification.invocation_options_digest.as_str(), serde_json::to_value(qualification.commit_mode).map_err(|error| error.to_string())?.as_str().unwrap_or_default(), serde_json::to_value(qualification.status).map_err(|error| error.to_string())?.as_str().unwrap_or_default(), receipt_json, owner_generation, now_unix()?],
        ).map_err(|error| error.to_string())?;
        let stored: String = tx
            .query_row(
                "SELECT receipt_json FROM provider_qualifications WHERE receipt_digest=?1",
                [receipt_digest.as_str()],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        if stored != serde_json::to_string(qualification).map_err(|error| error.to_string())? {
            return Err("qualification digest collides with different stored evidence".into());
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(receipt_digest)
    }

    pub fn provider_qualification(
        &self,
        receipt_digest: &Digest,
    ) -> Result<Option<ProviderQualification>, String> {
        let receipt: Option<String> = self
            .connection
            .query_row(
                "SELECT receipt_json FROM provider_qualifications WHERE receipt_digest=?1",
                [receipt_digest.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        receipt
            .map(|json| {
                let qualification: ProviderQualification =
                    crate::protocol::parse_unique(json.as_bytes()).map_err(|error| {
                        format!("stored provider qualification is invalid: {error}")
                    })?;
                if qualification.canonical_digest()? != *receipt_digest {
                    return Err("stored provider qualification digest mismatch".into());
                }
                Ok(qualification)
            })
            .transpose()
    }

    /// Register the exact immutable run authority only after the Rex block, descriptor,
    /// workspace, and mailbox capability have been prepared by the host.
    pub fn register_agent_launch_authority(
        &mut self,
        owner_generation: u64,
        authority: &AgentLaunchAuthority,
    ) -> Result<bool, String> {
        authority.validate()?;
        let authority_json = serde_json::to_string(authority).map_err(|error| error.to_string())?;
        let authority_digest = authority.digest()?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        if authority.controller_generation != owner_generation {
            return Err(
                "new launch authority must belong to the active controller generation".into(),
            );
        }
        let run: Option<LaunchAgentRunRow> = tx.query_row(
            "SELECT project_id,state,controller_generation,launch_operation_id,config_digest,config_revision,config_source,role_session_id FROM agent_runs WHERE agent_run_id=?1",
            [authority.agent_run_id.as_str()],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?)),
        ).optional().map_err(|error| error.to_string())?;
        let Some((
            project_id,
            state,
            generation,
            operation_id,
            config_digest,
            config_revision,
            config_source,
            role_session_id,
        )) = run
        else {
            return Err("launch authority references an unknown AgentRun".into());
        };
        if project_id != authority.project_id.as_str()
            || state != "launch_pending"
            || generation != owner_generation
            || operation_id != authority.operation_id.as_str()
            || config_digest != authority.config_digest.as_str()
            || config_revision != authority.config_revision.0
            || role_session_id.as_deref() != Some(authority.role_session_id.as_str())
        {
            return Err("AgentRun identity does not match the proposed launch authority".into());
        }
        let snapshot: Option<(String, String)> = tx.query_row(
            "SELECT snapshots.digest,snapshots.effective_config_json FROM config_current current JOIN config_snapshots snapshots USING(source_identity,revision) WHERE current.source_identity=?1 AND current.revision=?2",
            params![config_source,authority.config_revision.0],
            |row| Ok((row.get(0)?,row.get(1)?)),
        ).optional().map_err(|error| error.to_string())?;
        let Some((snapshot_digest, effective_json)) = snapshot else {
            return Err(
                "launch authority config revision is no longer the applied snapshot".into(),
            );
        };
        if snapshot_digest != authority.config_digest.as_str() {
            return Err(
                "launch authority config digest does not match the applied snapshot".into(),
            );
        }
        let effective: EffectiveConfig =
            crate::protocol::parse_unique(effective_json.as_bytes())
                .map_err(|error| format!("applied config snapshot is invalid: {error}"))?;
        let profile = effective
            .profiles
            .get(&authority.profile_id)
            .ok_or("launch profile is missing from the applied config snapshot")?;
        let project_roles = crate::config::effective_project_roles(
            &authority.project_id,
            &effective.config.projects,
        )?;
        let expected_profile = if let Some(recipe_id) = &authority.operation_recipe_id {
            let recipe = effective
                .config
                .operation_recipes
                .get(recipe_id)
                .ok_or("launch operation recipe is missing from the applied config snapshot")?;
            recipe
                .roles
                .get(&authority.role)
                .or_else(|| project_roles.get(&authority.role))
        } else {
            project_roles.get(&authority.role)
        }
        .ok_or("launch role has no effective profile in project or operation recipe")?;
        if expected_profile != &authority.profile_id {
            return Err("launch profile does not match the effective project role profile".into());
        }
        let profile_json = canonical_json(profile)?;
        let profile_digest =
            Digest::parse(format!("{:x}", Sha256::digest(profile_json.as_bytes())))?;
        if profile_digest != authority.profile_digest {
            return Err("launch profile digest does not match the applied config snapshot".into());
        }
        let mailbox: Option<String> = tx
            .query_row(
                "SELECT capability_digest FROM agent_mailboxes WHERE agent_run_id=?1",
                [authority.agent_run_id.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if mailbox.as_deref() != Some(authority.mailbox_capability_digest.as_str()) {
            return Err("launch authority has no matching registered mailbox capability".into());
        }
        let view: Option<LaunchRexViewRow> = tx.query_row(
            "SELECT project_id,rex_server_identity,rex_session_id,rex_window_id,view_kind,ticket_namespace,ticket_id FROM rex_views WHERE view_id=?1 AND lifecycle='active'",
            [authority.rex_view_id.as_str()], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?)),
        ).optional().map_err(|error| error.to_string())?;
        let ticket_scope = if authority.role == Role::Supervisor {
            None
        } else {
            Some(
                tx.query_row(
                    "SELECT project_id,namespace,ticket_id,revision FROM ticket_runs WHERE ticket_run_id=?1",
                    [authority
                        .ticket_run_id
                        .as_ref()
                        .ok_or("ticket AgentRun is missing TicketRun ID")?
                        .as_str()],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, u64>(3)?)),
                )
                .optional()
                .map_err(|error| error.to_string())?
                .ok_or("launch TicketRun does not exist")?,
            )
        };
        let view_ticket_scope_matches =
            view.as_ref()
                .is_some_and(|(_, _, _, _, kind, namespace, ticket)| {
                    if authority.role == Role::Supervisor {
                        kind == "supervisor" && namespace.is_none() && ticket.is_none()
                    } else {
                        kind == "ticket"
                            && ticket_scope.as_ref().is_some_and(
                                |(
                                    ticket_project,
                                    expected_namespace,
                                    expected_ticket,
                                    ticket_revision,
                                )| {
                                    ticket_project == authority.project_id.as_str()
                                        && *ticket_revision
                                            == authority
                                                .ticket_revision
                                                .map(|revision| revision.0)
                                                .unwrap_or_default()
                                        && namespace.as_deref() == Some(expected_namespace.as_str())
                                        && ticket.as_deref() == Some(expected_ticket.as_str())
                                },
                            )
                    }
                });
        if !view_ticket_scope_matches
            || view.as_ref().is_none_or(|row| {
                row.0 != authority.project_id.as_str()
                    || row.1 != authority.rex_server_identity
                    || row.2 != authority.rex_session_id
                    || row.3 != authority.rex_window_id
            })
        {
            return Err("launch authority does not match an active registered Rex view".into());
        }
        let qualification_json: Option<String> = tx
            .query_row(
                "SELECT receipt_json FROM provider_qualifications WHERE receipt_digest=?1",
                [authority.qualification_receipt_digest.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let qualification: ProviderQualification = crate::protocol::parse_unique(
            qualification_json
                .ok_or("launch authority references an unregistered qualification")?
                .as_bytes(),
        )
        .map_err(|error| format!("stored provider qualification is invalid: {error}"))?;
        if qualification.canonical_digest()? != authority.qualification_receipt_digest
            || qualification.project_id != authority.project_id
            || qualification.profile_id != authority.profile_id
            || qualification.profile_digest != authority.profile_digest
        {
            return Err("qualification receipt does not match the immutable launch profile".into());
        }
        qualification.validate_for_unattended_launch()?;
        let authority_inserted = tx.execute(
            "INSERT INTO agent_launch_authority(agent_run_id,project_id,role,role_session_id,parent_run_id,parent_role,ticket_run_id,ticket_revision,config_revision,config_digest,attempt,run_epoch,controller_generation,launch_operation_id,operation_recipe_id,rex_view_id,descriptor_digest,runtime_binary_digest,descriptor_path,environment_snapshot_id,profile_id,profile_digest,instruction_digest,result_schema_digest,qualification_receipt_digest,rex_server_identity,rex_session_id,rex_window_id,rex_block_id,workspace_path,control_dir,mailbox_capability_digest,authority_json,authority_digest,created_at_unix) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25,?26,?27,?28,?29,?30,?31,?32,?33,?34,?35) ON CONFLICT(agent_run_id) DO NOTHING",
            params![authority.agent_run_id.as_str(),authority.project_id.as_str(),serde_json::to_value(authority.role).map_err(|error| error.to_string())?.as_str().unwrap_or_default(),authority.role_session_id,authority.parent_run_id.as_ref().map(AgentRunId::as_str),authority.parent_role.map(|role| serde_json::to_value(role).ok().and_then(|value| value.as_str().map(str::to_owned)).unwrap_or_default()),authority.ticket_run_id.as_ref().map(TicketRunId::as_str),authority.ticket_revision.map(|revision| revision.0),authority.config_revision.0,authority.config_digest.as_str(),authority.attempt,authority.run_epoch,authority.controller_generation,authority.operation_id.as_str(),authority.operation_recipe_id,authority.rex_view_id.as_str(),authority.descriptor_digest.as_str(),authority.runtime_binary_digest.as_str(),authority.descriptor_path.display().to_string(),authority.environment_snapshot_id.as_str(),authority.profile_id.as_str(),authority.profile_digest.as_str(),authority.instruction_digest.as_str(),authority.result_schema_digest.as_str(),authority.qualification_receipt_digest.as_str(),authority.rex_server_identity,authority.rex_session_id,authority.rex_window_id,authority.rex_block_id,authority.workspace_path.display().to_string(),authority.control_dir.display().to_string(),authority.mailbox_capability_digest.as_str(),authority_json,authority_digest.as_str(),now_unix()?],
        ).map_err(|error| error.to_string())?;
        let existing: Option<(String,String)> = tx
            .query_row(
                "SELECT authority_json,authority_digest FROM agent_launch_authority WHERE agent_run_id=?1",
                [authority.agent_run_id.as_str()],
                |row| Ok((row.get(0)?,row.get(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if existing.as_ref().is_none_or(|(json, digest)| {
            json != &authority_json || digest != authority_digest.as_str()
        }) {
            return Err("AgentRun already has a different immutable launch authority".into());
        }
        tx.execute("INSERT INTO agent_launch_state(agent_run_id,state,last_observed_at_unix,updated_at_unix) VALUES (?1,'block_created',?2,?2) ON CONFLICT(agent_run_id) DO NOTHING", params![authority.agent_run_id.as_str(),now_unix()?]).map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(authority_inserted == 1)
    }

    pub fn agent_launch_authority(
        &self,
        agent_run_id: &AgentRunId,
    ) -> Result<Option<AgentLaunchAuthority>, String> {
        let stored: Option<(String,String,String)> = self.connection.query_row(
            "SELECT authority_json,descriptor_digest,authority_digest FROM agent_launch_authority WHERE agent_run_id=?1",
            [agent_run_id.as_str()], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
        ).optional().map_err(|error| error.to_string())?;
        stored
            .map(|(json, descriptor_digest, authority_digest)| {
                let authority: AgentLaunchAuthority =
                    crate::protocol::parse_unique(json.as_bytes()).map_err(|error| {
                        format!("stored Agent launch authority is invalid: {error}")
                    })?;
                authority.validate()?;
                if authority.agent_run_id != *agent_run_id
                    || authority.descriptor_digest.as_str() != descriptor_digest
                    || authority.digest()?.as_str() != authority_digest
                {
                    return Err("stored Agent launch authority digest fields do not match".into());
                }
                Ok(authority)
            })
            .transpose()
    }

    pub fn register_agent_mailbox(
        &mut self,
        owner_generation: u64,
        agent_run_id: &str,
        directory: &Path,
        expires_at_unix: u64,
        limits: crate::mailbox::MailboxLimits,
    ) -> Result<AgentMailboxRegistration, String> {
        let capability = crate::mailbox::MailboxCapability::create(
            agent_run_id,
            directory,
            expires_at_unix,
            limits,
        )?;
        let canonical_directory = capability.directory().display().to_string();
        let descriptor = crate::mailbox::MailboxDescriptor {
            schema_version: 1,
            run_id: agent_run_id.to_owned(),
            expires_at_unix,
            max_request_bytes: limits.max_request_bytes,
            max_pending_requests: limits.max_pending_requests,
        };
        let capability_digest = format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&descriptor).map_err(|error| error.to_string())?)
        );
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let agent_state: Option<(String, u64)> = tx
            .query_row(
                "SELECT state,controller_generation FROM agent_runs WHERE agent_run_id=?1",
                [agent_run_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if !matches!(agent_state, Some((ref state, generation)) if (state == "launch_pending" || state == "running") && generation == owner_generation)
        {
            return Err("mailbox can only be registered for a launch-pending or running AgentRun owned by this controller".into());
        }
        tx.execute(
            "INSERT INTO agent_mailboxes(agent_run_id,canonical_directory,capability_digest,expires_at_unix,max_request_bytes,max_pending_requests) VALUES (?1,?2,?3,?4,?5,?6) ON CONFLICT(agent_run_id) DO NOTHING",
            params![agent_run_id, canonical_directory, capability_digest, expires_at_unix, limits.max_request_bytes, limits.max_pending_requests],
        )
        .map_err(|error| error.to_string())?;
        let existing: (String, String, u64, usize, usize) = tx
            .query_row(
                "SELECT canonical_directory,capability_digest,expires_at_unix,max_request_bytes,max_pending_requests FROM agent_mailboxes WHERE agent_run_id=?1",
                [agent_run_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .map_err(|error| error.to_string())?;
        let expected = (
            canonical_directory.clone(),
            capability_digest.clone(),
            expires_at_unix,
            limits.max_request_bytes,
            limits.max_pending_requests,
        );
        if existing != expected {
            return Err("AgentRun already has a different mailbox capability".into());
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(AgentMailboxRegistration {
            agent_run_id: agent_run_id.to_owned(),
            canonical_directory,
            capability_digest,
            expires_at_unix,
            max_request_bytes: limits.max_request_bytes,
            max_pending_requests: limits.max_pending_requests,
        })
    }

    pub fn agent_mailbox_registration(
        &self,
        agent_run_id: &str,
    ) -> Result<Option<AgentMailboxRegistration>, String> {
        self.connection
            .query_row(
                "SELECT canonical_directory,capability_digest,expires_at_unix,max_request_bytes,max_pending_requests FROM agent_mailboxes WHERE agent_run_id=?1",
                [agent_run_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, u64>(2)?, row.get::<_, usize>(3)?, row.get::<_, usize>(4)?)),
            )
            .optional()
            .map(|row| {
                row.map(|(canonical_directory, capability_digest, expires_at_unix, max_request_bytes, max_pending_requests)| AgentMailboxRegistration {
                    agent_run_id: agent_run_id.to_owned(), canonical_directory, capability_digest, expires_at_unix, max_request_bytes, max_pending_requests
                })
            })
            .map_err(|error| error.to_string())
    }

    pub fn registered_agent_mailboxes(&self) -> Result<Vec<AgentMailboxRegistration>, String> {
        let mut statement = self.connection.prepare(
            "SELECT agent_run_id,canonical_directory,capability_digest,expires_at_unix,max_request_bytes,max_pending_requests FROM agent_mailboxes ORDER BY agent_run_id",
        ).map_err(|error| error.to_string())?;
        statement
            .query_map([], |row| {
                Ok(AgentMailboxRegistration {
                    agent_run_id: row.get(0)?,
                    canonical_directory: row.get(1)?,
                    capability_digest: row.get(2)?,
                    expires_at_unix: row.get(3)?,
                    max_request_bytes: row.get(4)?,
                    max_pending_requests: row.get(5)?,
                })
            })
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())
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
        let inserted = insert_effect(&tx, effect, now_unix()?)?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(inserted)
    }

    pub fn claim_next_due_effect(
        &mut self,
        owner_generation: u64,
        now: i64,
        supported_kinds: &[String],
    ) -> Result<Option<ClaimedEffect>, String> {
        if supported_kinds.is_empty() {
            return Ok(None);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let kind_placeholders = (0..supported_kinds.len())
            .map(|index| format!("?{}", index + 2))
            .collect::<Vec<_>>()
            .join(",");
        let query = format!(
            "SELECT status,project_id,subject_type,subject_id,operation_id,logical_key,kind,request_json,request_digest,expected_revision FROM effects WHERE status IN ('pending','uncertain') AND next_attempt_at_unix<=?1 AND kind IN ({kind_placeholders}) ORDER BY created_at_unix,next_attempt_at_unix,operation_id LIMIT 1"
        );
        let mut values = vec![rusqlite::types::Value::Integer(now)];
        values.extend(
            supported_kinds
                .iter()
                .cloned()
                .map(rusqlite::types::Value::Text),
        );
        let row: Option<ClaimableEffectRow> = tx
            .query_row(&query, rusqlite::params_from_iter(values.iter()), |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                ))
            })
            .optional()
            .map_err(|error| error.to_string())?;
        let Some((
            status,
            project_id,
            subject_type,
            subject_id,
            operation_id,
            logical_key,
            kind,
            request_json,
            request_digest,
            expected_revision,
        )) = row
        else {
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(None);
        };
        let (attempt_count, created_at_unix): (u32, i64) = tx
            .query_row(
                "SELECT attempt_count,created_at_unix FROM effects WHERE operation_id=?1",
                [&operation_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|error| error.to_string())?;
        let increment = i64::from(status == "pending");
        let changed = tx.execute(
            "UPDATE effects SET status='claimed',owner_generation=?2,attempt_count=attempt_count+?3 WHERE operation_id=?1 AND status=?4",
            params![operation_id, owner_generation, increment, status],
        ).map_err(|error| error.to_string())?;
        if changed != 1 {
            return Err("effect claim changed while acquiring the write lock".into());
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(Some(ClaimedEffect {
            intent: EffectIntent {
                project_id: ProjectId::parse(project_id)?,
                subject_type,
                subject_id,
                operation_id,
                logical_key,
                kind,
                request_json,
                request_digest,
                expected_revision,
            },
            state: if status == "pending" {
                EffectClaimState::Pending
            } else {
                EffectClaimState::Uncertain
            },
            attempt_count: attempt_count + u32::from(status == "pending"),
            created_at_unix,
        }))
    }

    pub fn retry_effect_after_absence(
        &self,
        operation_id: &str,
        owner_generation: u64,
        request_digest: &str,
        proof_json: &str,
        next_attempt_at_unix: i64,
    ) -> Result<(), String> {
        let changed = self.connection.execute(
            "UPDATE effects SET status='pending',owner_generation=NULL,next_attempt_at_unix=?5,receipt_json=?4,last_error='authoritative absence confirmed; retry scheduled' WHERE operation_id=?1 AND owner_generation=?2 AND request_digest=?3 AND status='claimed' AND EXISTS (SELECT 1 FROM controller_owners WHERE singleton=1 AND generation=?2 AND stopped_at_unix IS NULL)",
            params![operation_id, owner_generation, request_digest, proof_json, next_attempt_at_unix],
        ).map_err(|error| error.to_string())?;
        if changed != 1 {
            return Err(
                "effect retry claim is stale, digest-mismatched, or no longer active".into(),
            );
        }
        Ok(())
    }

    pub fn defer_effect_reconciliation(
        &self,
        operation_id: &str,
        owner_generation: u64,
        receipt: Option<&str>,
        next_reconciliation_at_unix: i64,
    ) -> Result<(), String> {
        let changed = self.connection.execute(
            "UPDATE effects SET status='uncertain',owner_generation=NULL,next_attempt_at_unix=?4,receipt_json=COALESCE(?3,receipt_json) WHERE operation_id=?1 AND owner_generation=?2 AND status='claimed' AND EXISTS (SELECT 1 FROM controller_owners WHERE singleton=1 AND generation=?2 AND stopped_at_unix IS NULL)",
            params![operation_id, owner_generation, receipt, next_reconciliation_at_unix],
        ).map_err(|error| error.to_string())?;
        if changed != 1 {
            return Err("effect reconciliation claim is stale or no longer active".into());
        }
        Ok(())
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
        let row: Option<DueEffectRow> = tx.query_row("SELECT project_id,subject_type,subject_id,operation_id,logical_key,kind,request_json,request_digest,expected_revision FROM effects WHERE status='pending' AND next_attempt_at_unix<=?1 ORDER BY next_attempt_at_unix, created_at_unix LIMIT 1", [now], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?))).optional().map_err(|e| e.to_string())?;
        let Some((
            project_id,
            subject_type,
            subject_id,
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
            project_id: ProjectId::parse(project_id)?,
            subject_type,
            subject_id,
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

    /// Read handler-owned progress only while this controller still owns the
    /// exact claimed effect request. Progress survives retries and restarts.
    pub fn load_effect_progress(
        &self,
        operation_id: &str,
        owner_generation: u64,
        request_digest: &str,
    ) -> Result<Option<String>, String> {
        Digest::parse(request_digest.to_owned())?;
        self.connection
            .query_row(
                "SELECT p.progress_json FROM effect_progress p JOIN effects e ON e.operation_id=p.operation_id WHERE p.operation_id=?1 AND p.request_digest=?2 AND e.request_digest=?2 AND e.status='claimed' AND e.owner_generation=?3 AND EXISTS (SELECT 1 FROM controller_owners WHERE singleton=1 AND generation=?3 AND stopped_at_unix IS NULL)",
                params![operation_id, request_digest, owner_generation],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())
    }

    /// Persist a bounded canonical JSON checkpoint for the currently claimed
    /// effect. The external operation must be performed outside this transaction.
    pub fn save_effect_progress(
        &mut self,
        operation_id: &str,
        owner_generation: u64,
        request_digest: &str,
        progress_json: &str,
        now_unix: i64,
    ) -> Result<(), String> {
        const MAX_PROGRESS_BYTES: usize = 262_144;
        Digest::parse(request_digest.to_owned())?;
        if progress_json.len() > MAX_PROGRESS_BYTES {
            return Err("effect progress exceeds 262144 bytes".into());
        }
        let value: serde_json::Value = serde_json::from_str(progress_json)
            .map_err(|_| "effect progress must be valid JSON".to_owned())?;
        if serde_json::to_string(&value).map_err(|error| error.to_string())? != progress_json {
            return Err("effect progress JSON must use canonical serialization".into());
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let claimed: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM effects WHERE operation_id=?1 AND request_digest=?2 AND status='claimed' AND owner_generation=?3)",
                params![operation_id, request_digest, owner_generation],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        if !claimed {
            return Err("effect progress claim is stale or request digest mismatched".into());
        }
        tx.execute(
            "INSERT INTO effect_progress(operation_id,request_digest,progress_json,updated_at_unix) VALUES (?1,?2,?3,?4) ON CONFLICT(operation_id) DO UPDATE SET progress_json=excluded.progress_json,updated_at_unix=excluded.updated_at_unix WHERE effect_progress.request_digest=excluded.request_digest",
            params![operation_id, request_digest, progress_json, now_unix],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())
    }

    /// Return a receipt only after SQLite has recorded this effect as succeeded.
    /// Pending, claimed, uncertain, failed, cancelled, or missing effects return `None`.
    pub fn succeeded_effect_receipt(
        &self,
        operation_id: &str,
    ) -> Result<Option<SucceededEffectReceipt>, String> {
        let row: Option<SucceededEffectRow> = self
            .connection
            .query_row(
                "SELECT project_id, subject_type, subject_id, operation_id, logical_key, kind, request_json, request_digest, expected_revision, attempt_count, created_at_unix, receipt_json FROM effects WHERE operation_id=?1 AND status='succeeded'",
                [operation_id],
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
                        row.get(8)?,
                        row.get(9)?,
                        row.get(10)?,
                        row.get(11)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let Some((
            project_id,
            subject_type,
            subject_id,
            operation_id,
            logical_key,
            kind,
            request_json,
            request_digest,
            expected_revision,
            attempt_count,
            created_at_unix,
            receipt_json,
        )) = row
        else {
            return Ok(None);
        };
        let receipt_json =
            receipt_json.ok_or_else(|| "succeeded effect has no persisted receipt".to_owned())?;
        Ok(Some(SucceededEffectReceipt {
            intent: EffectIntent {
                project_id: ProjectId::parse(project_id)?,
                subject_type,
                subject_id,
                operation_id,
                logical_key,
                kind,
                request_json,
                request_digest,
                expected_revision,
            },
            attempt_count,
            created_at_unix,
            receipt_json,
        }))
    }

    /// List a bounded page of durable, succeeded effects for one exact subject.
    /// Callers must still validate each typed receipt against its original request
    /// and the current domain state before producing a transition.
    pub fn list_succeeded_effect_receipts(
        &self,
        owner_generation: u64,
        project_id: &ProjectId,
        subject_type: &str,
        subject_id: &str,
        limit: usize,
    ) -> Result<Vec<SucceededEffectReceipt>, String> {
        if subject_type.is_empty()
            || subject_type.len() > 128
            || subject_id.is_empty()
            || subject_id.len() > 512
        {
            return Err("effect subject identity is invalid".into());
        }
        if limit == 0 || limit > 256 {
            return Err("succeeded effect query limit must be between 1 and 256".into());
        }
        let active_owner: Option<u64> = self
            .connection
            .query_row(
                "SELECT generation FROM controller_owners WHERE singleton=1 AND stopped_at_unix IS NULL",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if active_owner != Some(owner_generation) {
            return Err("controller owner generation is stale".into());
        }
        let mut statement = self.connection.prepare(
            "SELECT operation_id FROM effects WHERE project_id=?1 AND subject_type=?2 AND subject_id=?3 AND status='succeeded' ORDER BY created_at_unix,operation_id LIMIT ?4",
        ).map_err(|error| error.to_string())?;
        let operation_ids = statement
            .query_map(
                params![project_id.as_str(), subject_type, subject_id, limit as u64],
                |row| row.get::<_, String>(0),
            )
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        operation_ids
            .iter()
            .map(|operation_id| {
                self.succeeded_effect_receipt(operation_id)?
                    .ok_or_else(|| "succeeded effect disappeared during read".to_owned())
            })
            .collect()
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
        let reconcile_state: Option<String> = tx.query_row(
            "SELECT state FROM ticket_claim_reconciliations WHERE namespace=?1 AND ticket_id=?2",
            params![namespace.as_str(),ticket.as_str()], |row| row.get(0),
        ).optional().map_err(|e| e.to_string())?;
        if let Some(state) = reconcile_state.as_deref()
            && state != "repolled_open"
        {
            return Err("ticket was relinquished by a human and must be repolled as open before a new local claim".into());
        }
        let matching: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM ticket_runs WHERE ticket_run_id=?1 AND project_id=?2 AND namespace=?3 AND ticket_id=?4 AND generation=?5)", params![ticket_run.as_str(), project.as_str(), namespace.as_str(), ticket.as_str(), generation], |row| row.get(0)).map_err(|e| e.to_string())?;
        if !matching {
            return Err("ticket run does not match claim identity".into());
        }
        let inserted = tx.execute("INSERT INTO ticket_claims(namespace, ticket_id, project_id, ticket_run_id, generation, claimed_at_unix) VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT(namespace, ticket_id) DO NOTHING", params![namespace.as_str(), ticket.as_str(), project.as_str(), ticket_run.as_str(), generation, now_unix()?]).map_err(|e| e.to_string())? == 1;
        if inserted {
            tx.execute("DELETE FROM ticket_claim_reconciliations WHERE namespace=?1 AND ticket_id=?2 AND state='repolled_open'", params![namespace.as_str(),ticket.as_str()]).map_err(|e| e.to_string())?;
        }
        tx.commit().map_err(|e| e.to_string())?;
        Ok(inserted)
    }

    pub fn confirm_ticket_claim_repolled(
        &mut self,
        owner_generation: u64,
        namespace: &TicketNamespace,
        ticket: &TicketId,
        eligible_for_claim: bool,
        observed_status: &str,
        external_revision: Option<&str>,
    ) -> Result<bool, String> {
        if observed_status.is_empty() || observed_status.len() > 255 {
            return Err("repolled external status is required".into());
        }
        let state = if eligible_for_claim {
            "repolled_open"
        } else {
            "repolled_closed"
        };
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let changed = tx.execute(
            "UPDATE ticket_claim_reconciliations SET state=?3,observed_status=?4,external_revision=?5,repolled_by_generation=?6,repolled_at_unix=?7 WHERE namespace=?1 AND ticket_id=?2",
            params![namespace.as_str(),ticket.as_str(),state,observed_status,external_revision,owner_generation,now_unix()?],
        ).map_err(|error| error.to_string())? == 1;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(changed)
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
        let run: Option<(String, String, String)> = tx.query_row(
            "SELECT c.project_id, r.namespace, r.ticket_id FROM ticket_claims c JOIN ticket_runs r USING(ticket_run_id) WHERE c.namespace=?1 AND c.ticket_id=?2 AND c.ticket_run_id=?3 AND c.generation=?4",
            params![namespace.as_str(), ticket.as_str(), ticket_run.as_str(), generation],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).optional().map_err(|e| e.to_string())?;
        if let Some((_, run_namespace, run_ticket)) = &run
            && (run_namespace != namespace.as_str() || run_ticket != ticket.as_str())
        {
            return Err("ticket claim does not match its run identity".into());
        }
        if run.is_none() {
            tx.commit().map_err(|e| e.to_string())?;
            return Ok(false);
        }
        let active_slot: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM execution_slots WHERE ticket_run_id=?1 AND disposition!='released')",
            [ticket_run.as_str()],
            |row| row.get(0),
        ).map_err(|e| e.to_string())?;
        if active_slot {
            return Err(
                "ticket claim cannot be released while a run slot is reserved or uncertain".into(),
            );
        }
        let terminal: bool = tx.query_row("SELECT external_status IN ('Done','Canceled') FROM ticket_runs WHERE ticket_run_id=?1", [ticket_run.as_str()], |row| row.get(0)).map_err(|e| e.to_string())?;
        if !terminal {
            return Err(
                "ticket claim can be released only after Done or Canceled is committed".into(),
            );
        }
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
        let mut candidates = tx.prepare("SELECT q.work_key,q.project_id,q.subject_type,q.subject_id,q.role,q.pool,rt.project_epoch FROM ready_queue q JOIN project_runtimes rt USING(project_id) JOIN projects p USING(project_id) WHERE q.ready_at_unix<=?1 AND q.expected_generation=rt.project_epoch AND p.desired_lifecycle='running' AND rt.observed_lifecycle IN ('running','starting') ORDER BY CASE WHEN q.project_id>?2 THEN 0 ELSE 1 END, q.project_id, q.priority DESC, q.fair_sequence").map_err(|e| e.to_string())?;
        let rows = candidates
            .query_map(params![now, last_project.as_deref().unwrap_or("")], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, u64>(6)?,
                ))
            })
            .map_err(|e| e.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        drop(candidates);
        for (work_key, project, subject_type, subject_id, role, pool, project_epoch) in rows {
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
            let ticket_run_id = (subject_type == "ticket_run").then_some(subject_id.as_str());
            let reserved = tx.execute("INSERT INTO execution_slots(pool, slot_index, project_id, ticket_run_id, owner_kind, owner_id, reservation_epoch, controller_generation, disposition) VALUES (?1, ?2, ?3, ?4, 'ready_work', ?5, ?6, ?7, 'launch_pending') ON CONFLICT(pool,slot_index) DO UPDATE SET project_id=excluded.project_id,ticket_run_id=excluded.ticket_run_id,owner_kind=excluded.owner_kind,owner_id=excluded.owner_id,reservation_epoch=excluded.reservation_epoch,controller_generation=excluded.controller_generation,process_identity_json=NULL,disposition='launch_pending' WHERE execution_slots.disposition='released'", params![pool, slot_index, project, ticket_run_id, work_key, project_epoch, owner_generation]).map_err(|e| e.to_string())?;
            if reserved != 1 {
                return Err("execution slot was concurrently reserved".into());
            }
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
            if effect.project_id != *project_id {
                return Err(
                    "effect Project does not match the authorized transition Project".into(),
                );
            }
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

    #[allow(clippy::too_many_arguments)]
    pub fn commit_ticket_transition(
        &mut self,
        owner_generation: u64,
        ticket_run_id: &TicketRunId,
        expected_revision: Revision,
        input: &DurableInput,
        transition: Input,
        reason: &str,
        evidence_json: &str,
        effects: &[EffectIntent],
    ) -> Result<InputReceipt, String> {
        self.commit_ticket_transition_impl(
            owner_generation,
            ticket_run_id,
            expected_revision,
            input,
            transition,
            reason,
            evidence_json,
            effects,
            None,
            None,
        )
    }

    /// Persist a validated plan and its PlanAccepted transition/effect in one
    /// owner-fenced SQLite transaction.
    #[allow(clippy::too_many_arguments)]
    pub fn commit_validated_work_plan(
        &mut self,
        owner_generation: u64,
        ticket_run_id: &TicketRunId,
        expected_revision: Revision,
        configuration_digest: &Digest,
        plan: &crate::engine::orchestration::ValidatedPlan,
        input: &DurableInput,
        reason: &str,
        evidence_json: &str,
        effects: &[EffectIntent],
    ) -> Result<InputReceipt, String> {
        let write = crate::store::accepted_plans::prepare_accepted_plan_write(
            ticket_run_id,
            plan,
            configuration_digest,
        )?;
        self.commit_ticket_transition_impl(
            owner_generation,
            ticket_run_id,
            expected_revision,
            input,
            Input::PlanAccepted,
            reason,
            evidence_json,
            effects,
            None,
            Some(write),
        )
    }

    /// Commit the final Done transition only with a host proof derived from operation and
    /// Postmortem receipts. The general transition API deliberately cannot accept this event.
    #[allow(clippy::too_many_arguments)]
    pub fn commit_ticket_completion(
        &mut self,
        owner_generation: u64,
        ticket_run_id: &TicketRunId,
        expected_revision: Revision,
        input: &DurableInput,
        reason: &str,
        evidence_json: &str,
        effects: &[EffectIntent],
        proof: &crate::engine::ticket_effects::TicketCompletionProof,
    ) -> Result<InputReceipt, String> {
        self.commit_ticket_transition_impl(
            owner_generation,
            ticket_run_id,
            expected_revision,
            input,
            Input::CompletionObserved,
            reason,
            evidence_json,
            effects,
            Some(proof),
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn commit_ticket_transition_impl(
        &mut self,
        owner_generation: u64,
        ticket_run_id: &TicketRunId,
        expected_revision: Revision,
        input: &DurableInput,
        transition: Input,
        reason: &str,
        evidence_json: &str,
        effects: &[EffectIntent],
        completion_proof: Option<&crate::engine::ticket_effects::TicketCompletionProof>,
        accepted_plan: Option<crate::store::accepted_plans::AcceptedPlanWrite>,
    ) -> Result<InputReceipt, String> {
        validate_input(input)?;
        if matches!(transition, Input::KnowledgePublished) {
            self.ensure_postmortem_published(ticket_run_id)?;
        }
        if reason.is_empty()
            || reason.len() > 1024
            || evidence_json.len() > MAX_INPUT_BYTES
            || effects.len() > 64
        {
            return Err("ticket transition exceeds configured limits".into());
        }
        let evidence: serde_json::Value =
            crate::protocol::parse_unique(evidence_json.as_bytes())
                .map_err(|error| format!("invalid transition evidence: {error}"))?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let duplicate: Option<(String, String)> = tx
            .query_row(
                "SELECT content_digest, receipt_json FROM inbox WHERE producer_id=?1 AND message_id=?2",
                params![input.producer_id, input.message_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if let Some((digest, receipt_json)) = duplicate {
            if digest != input.content_digest {
                return Err("message ID was reused with different content".into());
            }
            let receipt: serde_json::Value = serde_json::from_str(&receipt_json)
                .map_err(|error| format!("stored receipt is invalid: {error}"))?;
            if receipt["ticket_run_id"].as_str() != Some(ticket_run_id.as_str()) {
                return Err("message ID was already committed for another subject".into());
            }
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(InputReceipt {
                receipt,
                duplicate: true,
            });
        }

        let stored: Option<(String, String, String, String, u64, Option<u64>)> = tx
            .query_row(
                "SELECT project_id, internal_phase, activity, external_status, revision, required_review_revision FROM ticket_runs WHERE ticket_run_id=?1",
                [ticket_run_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let Some((project_raw, phase_raw, activity_raw, status_raw, revision, review_revision)) =
            stored
        else {
            return Err("ticket run not found".into());
        };
        let project_id = ProjectId::parse(project_raw)?;
        if revision != expected_revision.0 {
            return Err(
                "ticket run revision conflict; no transition or effects were written".into(),
            );
        }
        let current = TicketRun {
            project_id: project_id.clone(),
            ticket_run_id: ticket_run_id.clone(),
            revision: Revision(revision),
            phase: serde_json::from_str(&format!("\"{phase_raw}\""))
                .map_err(|error| format!("stored ticket phase is invalid: {error}"))?,
            activity: serde_json::from_str(&format!("\"{activity_raw}\""))
                .map_err(|error| format!("stored ticket activity is invalid: {error}"))?,
            external_status: parse_ticket_status(&status_raw)?,
            required_review_revision: review_revision.map(Revision),
        };
        match (&transition, completion_proof) {
            (Input::CompletionObserved, Some(proof)) => {
                if proof.project_id() != &project_id
                    || proof.ticket_run_id() != ticket_run_id
                    || proof.expected_revision() != revision
                {
                    return Err(
                        "completion proof is bound to a different TicketRun revision".into(),
                    );
                }
                let receipt: Option<(String, String, String, String, String, String)> = tx
                    .query_row(
                        "SELECT p.plan_digest,p.state,p.postmortem_receipt_digest,m.receipt_digest,k.operation_id,k.manifest_digest FROM operation_plans p JOIN operation_postmortems m USING(project_id,ticket_run_id) JOIN knowledge_publications k USING(project_id,ticket_run_id) WHERE p.project_id=?1 AND p.ticket_run_id=?2 AND k.state='published'",
                        params![project_id.as_str(), ticket_run_id.as_str()],
                        |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?)),
                    )
                    .optional()
                    .map_err(|error| error.to_string())?;
                let Some((
                    plan_digest,
                    plan_state,
                    plan_postmortem,
                    operation_postmortem,
                    knowledge_operation,
                    knowledge_digest,
                )) = receipt
                else {
                    return Err("completion receipts are incomplete".into());
                };
                if !matches!(plan_state.as_str(), "not_required" | "succeeded")
                    || plan_postmortem != operation_postmortem
                    || Digest::parse(plan_digest)? != *proof.plan_digest()
                    || Digest::parse(operation_postmortem)? != *proof.postmortem_receipt_digest()
                    || knowledge_operation != proof.knowledge_operation_id()
                    || Digest::parse(knowledge_digest)? != *proof.knowledge_manifest_digest()
                {
                    return Err("completion proof no longer matches persisted operation and Postmortem receipts".into());
                }
                let manifest_json: String = tx
                    .query_row(
                        "SELECT manifest_json FROM knowledge_publications WHERE operation_id=?1 AND ticket_run_id=?2 AND state='published'",
                        params![proof.knowledge_operation_id(), ticket_run_id.as_str()],
                        |row| row.get(0),
                    )
                    .map_err(|error| error.to_string())?;
                let manifest: crate::knowledge::PublicationManifest =
                    crate::protocol::parse_unique(manifest_json.as_bytes()).map_err(|error| {
                        format!("stored Postmortem manifest is invalid: {error}")
                    })?;
                if manifest.operation_id.as_str() != proof.knowledge_operation_id()
                    || manifest.project_id.as_str() != project_id.as_str()
                    || manifest.ticket_run_id.as_str() != ticket_run_id.as_str()
                    || serde_json::to_string(&manifest).map_err(|error| error.to_string())?
                        != manifest_json
                    || content_digest(&manifest_json) != proof.knowledge_manifest_digest().as_str()
                {
                    return Err(
                        "completion Postmortem publication receipt failed verification".into(),
                    );
                }
            }
            (Input::CompletionObserved, None) => {
                return Err(
                    "completion requires host-validated operation and Postmortem receipts".into(),
                );
            }
            (_, Some(_)) => {
                return Err("completion proof cannot authorize a different transition".into());
            }
            (_, None) => {}
        }
        let worker_wake = matches!(
            &transition,
            Input::WorktreesPrepared | Input::CorrectionsRemain
        );
        let initial_worktree_wake = matches!(&transition, Input::WorktreesPrepared);
        let is_plan_accepted = matches!(&transition, Input::PlanAccepted);
        if is_plan_accepted != accepted_plan.is_some() {
            return Err("PlanAccepted requires an atomic validated plan payload".into());
        }
        let decision = reduce(&current, expected_revision, transition)?;
        let expected_kinds = decision
            .effects
            .iter()
            .map(|kind| {
                serde_json::to_value(kind)
                    .map_err(|error| error.to_string())?
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| "effect kind did not serialize as a string".to_owned())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut supplied_kinds = effects
            .iter()
            .map(|effect| effect.kind.clone())
            .collect::<Vec<_>>();
        let mut expected_kinds = expected_kinds;
        supplied_kinds.sort();
        expected_kinds.sort();
        if supplied_kinds != expected_kinds
            || effects.iter().any(|effect| {
                effect.project_id != project_id
                    || effect.subject_type != "ticket_run"
                    || effect.subject_id != ticket_run_id.as_str()
                    || effect.expected_revision != Some(decision.ticket_run.revision.0)
            })
        {
            return Err(
                "effect intents do not match the reducer decision and TicketRun revision".into(),
            );
        }

        let decision_run = &decision.ticket_run;
        if let Some(plan) = accepted_plan {
            if decision_run.phase != Phase::Preparing
                || plan.plan_digest.as_str() != content_digest(&plan.plan_json)
            {
                return Err(
                    "validated work plan is not bound to the PlanAccepted transition".into(),
                );
            }
            let source_claim: crate::engine::orchestration::WorkPlan =
                crate::protocol::parse_unique(plan.source_claim_plan_json.as_bytes()).map_err(
                    |error| format!("stored Coordinator plan claim is invalid: {error}"),
                )?;
            let accepted: crate::store::accepted_plans::PersistedWorkPlan =
                crate::protocol::parse_unique(plan.plan_json.as_bytes())
                    .map_err(|error| format!("persisted work plan is invalid: {error}"))?;
            if accepted.schema_version != 1
                || accepted.proposal != source_claim
                || plan.validated_plan.ticket_run_id != *ticket_run_id
                || !crate::store::accepted_plans::validated_plan_matches_claim(
                    &plan.validated_plan,
                    &accepted.proposal,
                )
            {
                return Err("validated work plan differs from Coordinator result evidence".into());
            }
            let source_row: Option<(String,String,String,Option<String>,Option<u64>,String,String,String,String,String)> = tx.query_row(
                "SELECT e.agent_run_id,e.project_id,e.role,e.ticket_run_id,a.ticket_revision,a.role_session_id,a.config_digest,a.authority_digest,a.role,a.parent_role FROM agent_result_evidence e JOIN agent_launch_authority a USING(agent_run_id) WHERE e.evidence_id=?1 AND e.message_id=?2 AND e.result_digest=?3",
                params![plan.source_evidence_id,plan.source_message_id,plan.source_result_digest.as_str()],
                |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?,row.get(9)?)),
            ).optional().map_err(|error| error.to_string())?;
            let Some((
                source_run,
                source_project,
                source_role,
                source_ticket,
                source_ticket_revision,
                source_session,
                source_config,
                authority_digest,
                authority_role,
                parent_role,
            )) = source_row
            else {
                return Err(
                    "accepted plan has no matching persisted Coordinator result evidence".into(),
                );
            };
            if source_run != plan.source_agent_run_id.as_str()
                || source_run != plan.coordinator_agent_run_id.as_str()
                || source_project != project_id.as_str()
                || source_role != "coordinator"
                || authority_role != "coordinator"
                || parent_role != "supervisor"
                || source_ticket.as_deref() != Some(ticket_run_id.as_str())
                || source_ticket_revision != Some(current.revision.0)
                || source_session != plan.coordinator_role_session_id
                || source_config != plan.configuration_digest.as_str()
                || source_session != format!("ticket:{}:coordinator", ticket_run_id.as_str())
            {
                return Err("accepted plan Coordinator provenance is stale or out of scope".into());
            }
            let source_submission: crate::engine::orchestration::RoleResultSubmission = tx
                .query_row(
                    "SELECT result_json FROM agent_result_evidence WHERE evidence_id=?1",
                    [&plan.source_evidence_id],
                    |row| row.get::<_, String>(0),
                )
                .map_err(|error| error.to_string())
                .and_then(|raw| {
                    crate::protocol::parse_unique(raw.as_bytes()).map_err(|error| error.to_string())
                })?;
            let source_binding = source_submission.binding.clone();
            let source_validated = crate::engine::orchestration::validate_role_result(
                &source_binding,
                source_submission,
            )?;
            let source_claim_matches = matches!(
                source_validated.typed_payload,
                crate::engine::orchestration::RoleResultPayload::PlanReady(ref payload)
                    if serde_json::to_string(&payload.plan).is_ok_and(|json| json == plan.source_claim_plan_json)
            );
            if !source_claim_matches {
                return Err(
                    "persisted Coordinator result differs from accepted plan source".into(),
                );
            }
            tx.execute(
                "INSERT INTO accepted_work_plans(project_id,ticket_run_id,accepted_revision,configuration_digest,plan_digest,plan_json,created_at_unix) VALUES (?1,?2,?3,?4,?5,?6,?7)",
                params![project_id.as_str(),ticket_run_id.as_str(),decision_run.revision.0,plan.configuration_digest.as_str(),plan.plan_digest.as_str(),plan.plan_json,now_unix()?],
            ).map_err(|error| error.to_string())?;
        }
        tx.execute(
            "UPDATE ticket_runs SET internal_phase=?2, activity=?3, external_status=?4, required_review_revision=?5, revision=?6 WHERE ticket_run_id=?1 AND revision=?7",
            params![
                ticket_run_id.as_str(),
                enum_string(&decision_run.phase)?,
                enum_string(&decision_run.activity)?,
                enum_string(&decision_run.external_status)?,
                decision_run.required_review_revision.map(|value| value.0),
                decision_run.revision.0,
                current.revision.0
            ],
        )
        .map_err(|error| error.to_string())?;
        tx.execute(
            "INSERT INTO transitions(project_id, entity_type, entity_id, old_revision, new_revision, input_id, decision_reason, evidence_json, created_at_unix) VALUES (?1, 'ticket_run', ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                project_id.as_str(),
                ticket_run_id.as_str(),
                current.revision.0,
                decision_run.revision.0,
                input.message_id,
                reason,
                serde_json::to_string(&evidence).map_err(|error| error.to_string())?,
                now_unix()?
            ],
        )
        .map_err(|error| error.to_string())?;
        let now = now_unix()?;
        for effect in effects {
            insert_effect(&tx, effect, now)?;
        }
        let wake_records = if worker_wake {
            let accepted: Option<(String, String)> = tx
                .query_row(
                    "SELECT plan_digest,plan_json FROM accepted_work_plans WHERE project_id=?1 AND ticket_run_id=?2 ORDER BY accepted_revision DESC LIMIT 1",
                    params![project_id.as_str(), ticket_run_id.as_str()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(|error| error.to_string())?;
            let Some((plan_digest, plan_json)) = accepted else {
                return Err("Worker wake requires a persisted accepted work plan".into());
            };
            if content_digest(&plan_json) != plan_digest {
                return Err("accepted work plan digest is invalid".into());
            }
            let persisted: crate::store::accepted_plans::PersistedWorkPlan =
                crate::protocol::parse_unique(plan_json.as_bytes())
                    .map_err(|error| format!("accepted work plan is invalid: {error}"))?;
            if persisted.schema_version != 1 {
                return Err("accepted work plan is bound to another TicketRun".into());
            }
            persisted.proposal.nodes
                .iter()
                .filter(|node| {
                    !node.investigation
                        && (!initial_worktree_wake || node.depends_on.is_empty())
                })
                .map(|node| {
                    let role_session_id = format!(
                        "ticket:{}:worker:{}",
                        ticket_run_id.as_str(),
                        node.id.as_str()
                    );
                    let payload = serde_json::json!({
                        "schema_version": 1,
                        "kind": "work_node_ready",
                        "ticket_run_id": ticket_run_id.as_str(),
                        "work_node_id": node.id.as_str(),
                        "accepted_plan_digest": plan_digest,
                        "source_message_id": input.message_id,
                        "revision": decision_run.revision.0
                    });
                    let inserted = tx.execute(
                        "INSERT INTO role_wake_inputs(project_id, role_session_id, source_type, source_id, source_revision, priority, payload_json, lifecycle, created_at_unix) VALUES (?1, ?2, 'work_node_ready', ?3, ?4, 0, ?5, 'pending', ?6)",
                        params![project_id.as_str(), role_session_id, input.message_id, decision_run.revision.0, payload.to_string(), now],
                    ).map_err(|error| error.to_string())?;
                    if inserted != 1 { return Err("Worker wake input was not persisted".into()); }
                    Ok(serde_json::json!({"role_session_id":role_session_id,"work_node_id":node.id.as_str(),"revision":decision_run.revision.0}))
                })
                .collect::<Result<Vec<_>, String>>()?
        } else {
            decision
                .wakes
                .iter()
                .map(|target| {
                let (role_session_id, target_name) = match target {
                    WakeTarget::Supervisor => (
                        format!("project:{}:supervisor", project_id.as_str()),
                        "supervisor",
                    ),
                    WakeTarget::TicketRole(role) => (
                        format!(
                            "ticket_run:{}:{}",
                            ticket_run_id.as_str(),
                            crate::engine::factory_runtime::role_name(*role)
                        ),
                        crate::engine::factory_runtime::role_name(*role),
                    ),
                };
                let payload = serde_json::json!({
                    "ticket_run_id": ticket_run_id.as_str(),
                    "target": target_name,
                    "message_id": input.message_id,
                    "revision": decision_run.revision.0
                });
                let inserted = tx.execute(
                    "INSERT INTO role_wake_inputs(project_id, role_session_id, source_type, source_id, source_revision, priority, payload_json, lifecycle, created_at_unix) VALUES (?1, ?2, 'ticket_run_transition', ?3, ?4, 0, ?5, 'pending', ?6)",
                    params![project_id.as_str(), role_session_id, input.message_id, decision_run.revision.0, payload.to_string(), now],
                ).map_err(|error| error.to_string())?;
                if inserted != 1 {
                    return Err("role wake input was not persisted".into());
                }
                Ok(serde_json::json!({"role_session_id":role_session_id,"revision":decision_run.revision.0}))
            })
                .collect::<Result<Vec<_>, String>>()?
        };
        let receipt = serde_json::json!({
            "accepted": true,
            "message_id": input.message_id,
            "content_digest": input.content_digest,
            "project_id": project_id.as_str(),
            "ticket_run_id": ticket_run_id.as_str(),
            "revision": decision_run.revision.0,
            "effects": effects.iter().map(|effect| effect.operation_id.as_str()).collect::<Vec<_>>(),
            "wakes": wake_records
        });
        tx.execute(
            "INSERT INTO inbox(producer_id, message_id, content_digest, recipient, payload_json, receipt_json, received_at_unix, processed_at_unix) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)",
            params![input.producer_id, input.message_id, input.content_digest, input.recipient, input.payload, serde_json::to_string(&receipt).map_err(|error| error.to_string())?, now],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
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
        tx.execute("INSERT INTO controller_owners(singleton, owner_nonce, generation, state_root, config_source, pid, process_start_identity, executable_path, executable_digest, rex_endpoint, rex_server_identity, rex_session_id, rex_block_id, started_at_unix, heartbeat_at_unix, stopped_at_unix) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?13, NULL) ON CONFLICT(singleton) DO UPDATE SET owner_nonce=excluded.owner_nonce, generation=excluded.generation, state_root=excluded.state_root, config_source=excluded.config_source, pid=excluded.pid, process_start_identity=excluded.process_start_identity, executable_path=excluded.executable_path, executable_digest=excluded.executable_digest, rex_endpoint=excluded.rex_endpoint, rex_server_identity=excluded.rex_server_identity, rex_session_id=excluded.rex_session_id, rex_block_id=excluded.rex_block_id, started_at_unix=excluded.started_at_unix, heartbeat_at_unix=excluded.heartbeat_at_unix, stopped_at_unix=NULL", params![owner.owner_nonce, generation, owner.state_root, owner.config_source, std::process::id(), owner.process_start_identity, owner.executable_path, owner.executable_digest, owner.rex_endpoint, owner.rex_server_identity, owner.rex_session_id, owner.rex_block_id, now]).map_err(|e| e.to_string())?;
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

    pub fn process_next_control(
        &mut self,
        owner_generation: u64,
    ) -> Result<Option<ControlCommand>, String> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let row: Option<PendingControlRow> = tx.query_row(
            "SELECT request_id, kind, project_id, lifecycle, payload_json, created_at_unix FROM controller_commands WHERE state='pending' ORDER BY sequence LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
        ).optional().map_err(|e| e.to_string())?;
        let Some((request_id, kind, project, lifecycle, payload_json, created_at_unix)) = row
        else {
            let human: Option<(String, String, u64, i64)> = tx.query_row(
                "SELECT request_id,payload_json,expected_generation,created_at_unix FROM human_claim_release_commands WHERE state='pending' ORDER BY sequence LIMIT 1",
                [],
                |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
            ).optional().map_err(|e| e.to_string())?;
            if let Some((request_id, payload_json, expected_generation, created_at_unix)) = human {
                if expected_generation != owner_generation {
                    tx.execute("UPDATE human_claim_release_commands SET state='rejected',result_json=?2,applied_by_generation=?3,applied_at_unix=?4 WHERE request_id=?1 AND state='pending'", params![request_id, serde_json::json!({"error":"owner generation changed"}).to_string(), owner_generation, now_unix()?]).map_err(|e| e.to_string())?;
                    tx.commit().map_err(|e| e.to_string())?;
                    return Ok(Some(ControlCommand {
                        request_id,
                        kind: "human_claim_release".into(),
                        project_id: None,
                        lifecycle: None,
                        created_at_unix,
                        applied_config: None,
                    }));
                }
                let release: HumanClaimRelease =
                    crate::protocol::parse_unique(payload_json.as_bytes())
                        .map_err(|error| format!("stored claim release is invalid: {error}"))?;
                let outcome =
                    apply_human_claim_release(&tx, owner_generation, &request_id, &release);
                match outcome {
                    Ok(receipt) => {
                        tx.execute("UPDATE human_claim_release_commands SET state='applied',result_json=?2,applied_by_generation=?3,applied_at_unix=?4 WHERE request_id=?1 AND state='pending'", params![request_id, receipt.to_string(), owner_generation, now_unix()?]).map_err(|e| e.to_string())?;
                    }
                    Err(error) => {
                        tx.execute("UPDATE human_claim_release_commands SET state='rejected',result_json=?2,applied_by_generation=?3,applied_at_unix=?4 WHERE request_id=?1 AND state='pending'", params![request_id, serde_json::json!({"error":error}).to_string(), owner_generation, now_unix()?]).map_err(|e| e.to_string())?;
                    }
                }
                tx.commit().map_err(|e| e.to_string())?;
                return Ok(Some(ControlCommand {
                    request_id,
                    kind: "human_claim_release".into(),
                    project_id: None,
                    lifecycle: None,
                    created_at_unix,
                    applied_config: None,
                }));
            }
            tx.commit().map_err(|e| e.to_string())?;
            return Ok(None);
        };
        let mut result = serde_json::json!({"accepted":true});
        let mut applied_config = None;
        match kind.as_str() {
            "machine_stop" => {}
            "config_apply" => {
                let outcome = payload_json
                    .as_deref()
                    .ok_or_else(|| "stored configuration command has no payload".to_owned())
                    .and_then(|value| {
                        crate::protocol::parse_unique::<ConfigApplyPayload>(value.as_bytes())
                            .map_err(|error| {
                                format!("stored configuration command is invalid: {error}")
                            })
                    })
                    .and_then(|payload| {
                        persist_snapshot(
                            &tx,
                            &payload.source_identity,
                            &payload.snapshot,
                            payload.expectation,
                        )
                    });
                match outcome {
                    Ok(applied) => {
                        applied_config = Some(applied.clone());
                        result = serde_json::json!({"accepted":true,"revision":applied.revision.0,"digest":applied.digest,"unchanged":applied.unchanged});
                    }
                    Err(error) => {
                        tx.execute("UPDATE controller_commands SET state='rejected', applied_by_generation=?2, applied_at_unix=?3, result_json=?4 WHERE request_id=?1 AND state='pending'", params![request_id, owner_generation, now_unix()?, serde_json::json!({"error":error}).to_string()]).map_err(|e| e.to_string())?;
                        tx.commit().map_err(|e| e.to_string())?;
                        return Ok(Some(ControlCommand {
                            request_id,
                            kind,
                            project_id: None,
                            lifecycle: None,
                            created_at_unix,
                            applied_config: None,
                        }));
                    }
                }
            }
            "project_lifecycle" => {
                let project = project
                    .as_deref()
                    .ok_or_else(|| "stored Project command has no Project ID".to_owned())?;
                let lifecycle = lifecycle
                    .as_deref()
                    .ok_or_else(|| "stored Project command has no lifecycle".to_owned())?;
                if !matches!(lifecycle, "running" | "paused" | "stopped") {
                    return Err("stored Project command has an invalid lifecycle".into());
                }
                let updated = tx
                    .execute(
                        "UPDATE projects SET desired_lifecycle=?2 WHERE project_id=?1",
                        params![project, lifecycle],
                    )
                    .map_err(|e| e.to_string())?;
                if updated != 1 {
                    tx.execute("UPDATE controller_commands SET state='rejected', result_json=?2 WHERE request_id=?1 AND state='pending'", params![request_id, serde_json::json!({"error":"Project not found"}).to_string()]).map_err(|e| e.to_string())?;
                    tx.commit().map_err(|e| e.to_string())?;
                    return Ok(Some(ControlCommand {
                        request_id,
                        kind,
                        project_id: Some(ProjectId::parse(project)?),
                        lifecycle: Some(lifecycle.to_owned()),
                        created_at_unix,
                        applied_config: None,
                    }));
                }
                let next_epoch: u64 = tx
                    .query_row(
                        "SELECT project_epoch + 1 FROM project_runtimes WHERE project_id=?1",
                        [&project],
                        |row| row.get(0),
                    )
                    .map_err(|e| e.to_string())?;
                let observed = if lifecycle == "running" {
                    "starting"
                } else if lifecycle == "paused" {
                    "paused"
                } else {
                    "stopped"
                };
                tx.execute("UPDATE project_runtimes SET desired_lifecycle=?2, observed_lifecycle=?3, controller_generation=?4, project_epoch=?5 WHERE project_id=?1", params![project, lifecycle, observed, owner_generation, next_epoch]).map_err(|e| e.to_string())?;
            }
            _ => return Err("stored controller command has an unsupported kind".into()),
        }
        tx.execute("UPDATE controller_commands SET state='applied', applied_by_generation=?2, result_json=?3, applied_at_unix=?4 WHERE request_id=?1 AND state='pending'", params![request_id, owner_generation, result.to_string(), now_unix()?]).map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(Some(ControlCommand {
            request_id,
            kind,
            project_id: project.map(ProjectId::parse).transpose()?,
            lifecycle,
            created_at_unix,
            applied_config,
        }))
    }

    pub fn should_stop(&self, owner_generation: u64) -> Result<bool, String> {
        let count: u64 = self.connection.query_row("SELECT COUNT(*) FROM controller_commands WHERE kind='machine_stop' AND state='applied' AND applied_by_generation=?1", [owner_generation], |row| row.get(0)).map_err(|e| e.to_string())?;
        Ok(count > 0)
    }

    pub fn list_projects(&self) -> Result<Vec<ProjectRecord>, String> {
        let mut statement = self.connection.prepare("SELECT project_id, config_source, config_revision, config_digest, mode, goal_revision, desired_lifecycle, state_revision FROM projects ORDER BY project_id").map_err(|e| e.to_string())?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, u64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, u64>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, u64>(7)?,
                ))
            })
            .map_err(|e| e.to_string())?;
        rows.map(|row| {
            let (
                id,
                config_source,
                config_revision,
                config_digest,
                mode,
                goal_revision,
                desired_lifecycle,
                state_revision,
            ) = row.map_err(|e| e.to_string())?;
            Ok(ProjectRecord {
                id: ProjectId::parse(id)?,
                config_source,
                config_revision: Revision(config_revision),
                config_digest: Digest::parse(config_digest)?,
                mode,
                goal_revision,
                desired_lifecycle,
                state_revision: Revision(state_revision),
            })
        })
        .collect()
    }

    pub fn append_control(
        state_root: &Path,
        request_id: &str,
        command: &ControlCommand,
        owner_generation: u64,
    ) -> Result<(), String> {
        if request_id.is_empty()
            || request_id.len() > 255
            || request_id.chars().any(char::is_control)
        {
            return Err("invalid control request ID".into());
        }
        let database = state_root.join("state.sqlite3");
        let connection = Connection::open_with_flags(
            &database,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|e| format!("{}: {e}", database.display()))?;
        connection
            .busy_timeout(std::time::Duration::from_secs(5))
            .map_err(|e| e.to_string())?;
        let tx = connection
            .unchecked_transaction()
            .map_err(|e| e.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let project_id = command.project_id.as_ref().map(ProjectId::as_str);
        tx.execute("INSERT INTO controller_commands(request_id,kind,project_id,lifecycle,state,created_at_unix,expected_generation) VALUES (?1,?2,?3,?4,'pending',?5,?6) ON CONFLICT(request_id) DO NOTHING", params![request_id, command.kind, project_id, command.lifecycle, command.created_at_unix, owner_generation]).map_err(|e| e.to_string())?;
        let existing: (String, Option<String>, Option<String>, u64) = tx.query_row("SELECT kind,project_id,lifecycle,expected_generation FROM controller_commands WHERE request_id=?1", [request_id], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?))).map_err(|e| e.to_string())?;
        if existing
            != (
                command.kind.clone(),
                project_id.map(str::to_owned),
                command.lifecycle.clone(),
                owner_generation,
            )
        {
            return Err("control request ID was reused with different content".into());
        }
        tx.commit().map_err(|e| e.to_string())
    }

    pub fn append_config_apply(
        state_root: &Path,
        request_id: &str,
        source_identity: &str,
        snapshot: &AppliedConfig,
        expectation: ExpectedRevision,
        owner_generation: u64,
    ) -> Result<(), String> {
        if request_id.is_empty()
            || request_id.len() > 255
            || request_id.chars().any(char::is_control)
            || source_identity.is_empty()
            || source_identity.len() > 4096
        {
            return Err("invalid configuration command identity".into());
        }
        let payload = ConfigApplyPayload {
            source_identity: source_identity.into(),
            snapshot: snapshot.clone(),
            expectation,
        };
        let payload_json = canonical_json(&payload)?;
        if payload_json.len() > MAX_INPUT_BYTES {
            return Err("configuration command exceeds the 1 MiB limit".into());
        }
        let database = state_root.join("state.sqlite3");
        let connection = Connection::open_with_flags(
            &database,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|error| format!("{}: {error}", database.display()))?;
        connection
            .busy_timeout(std::time::Duration::from_secs(5))
            .map_err(|error| error.to_string())?;
        let tx = connection
            .unchecked_transaction()
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        tx.execute(
            "INSERT INTO controller_commands(request_id,kind,payload_json,state,created_at_unix,expected_generation) VALUES (?1,'config_apply',?2,'pending',?3,?4) ON CONFLICT(request_id) DO NOTHING",
            params![request_id, payload_json, now_unix()?, owner_generation],
        )
        .map_err(|error| error.to_string())?;
        let existing: (String, Option<String>, u64) = tx
            .query_row(
                "SELECT kind,payload_json,expected_generation FROM controller_commands WHERE request_id=?1",
                [request_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(|error| error.to_string())?;
        if existing != ("config_apply".into(), Some(payload_json), owner_generation) {
            return Err("control request ID was reused with different content".into());
        }
        tx.commit().map_err(|error| error.to_string())
    }

    pub fn append_human_claim_release(
        state_root: &Path,
        request_id: &str,
        release: &HumanClaimRelease,
        owner_generation: u64,
    ) -> Result<(), String> {
        if request_id.is_empty()
            || request_id.len() > 255
            || request_id.chars().any(char::is_control)
        {
            return Err("invalid claim-release request ID".into());
        }
        if release.reason.trim().is_empty()
            || release.reason.len() > 2048
            || release.disposition != "cancel"
        {
            return Err(
                "claim release requires a reason and the explicit `cancel` disposition".into(),
            );
        }
        let payload = canonical_json(release)?;
        let database = state_root.join("state.sqlite3");
        let connection = Connection::open_with_flags(
            &database,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|error| format!("{}: {error}", database.display()))?;
        connection
            .busy_timeout(std::time::Duration::from_secs(5))
            .map_err(|error| error.to_string())?;
        let tx = connection
            .unchecked_transaction()
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        tx.execute("INSERT INTO human_claim_release_commands(request_id,payload_json,state,created_at_unix,expected_generation) VALUES (?1,?2,'pending',?3,?4) ON CONFLICT(request_id) DO NOTHING", params![request_id,payload,now_unix()?,owner_generation]).map_err(|error| error.to_string())?;
        let existing: (String,u64) = tx.query_row("SELECT payload_json,expected_generation FROM human_claim_release_commands WHERE request_id=?1", [request_id], |row| Ok((row.get(0)?,row.get(1)?))).map_err(|error| error.to_string())?;
        if existing != (payload, owner_generation) {
            return Err("claim-release request ID was reused with different content".into());
        }
        tx.commit().map_err(|error| error.to_string())
    }

    pub fn status(state_root: &Path) -> Result<RuntimeStatus, String> {
        let database = state_root.join("state.sqlite3");
        let connection = Connection::open_with_flags(
            &database,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|e| format!("{}: {e}", database.display()))?;
        connection
            .busy_timeout(std::time::Duration::from_secs(2))
            .map_err(|e| e.to_string())?;
        let schema_version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(|e| e.to_string())?;
        if schema_version > SCHEMA_VERSION {
            return Err(format!(
                "database schema {schema_version} is newer than supported schema {SCHEMA_VERSION}; status is unavailable without modifying it"
            ));
        }
        if schema_version < 3 {
            return Err(
                "runtime state is not initialized; start the Rex-owned `runtime run` block".into(),
            );
        }
        let owner: Option<(u64,u32,String,i64)> = connection.query_row("SELECT generation,pid,process_start_identity,started_at_unix FROM controller_owners WHERE singleton=1 AND stopped_at_unix IS NULL", [], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?))).optional().map_err(|e| e.to_string())?;
        let owner_rex = if schema_version >= 10 {
            connection
                .query_row(
                    "SELECT rex_endpoint,rex_server_identity,rex_session_id,rex_block_id FROM controller_owners WHERE singleton=1 AND stopped_at_unix IS NULL",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()
                .map_err(|error| error.to_string())?
                .unwrap_or((None, None, None, None))
        } else {
            (None, None, None, None)
        };
        let mut statement = connection.prepare("SELECT p.project_id,p.mode,p.desired_lifecycle,r.observed_lifecycle,r.project_epoch,r.next_due_at_unix,r.last_error FROM projects p JOIN project_runtimes r USING(project_id) ORDER BY p.project_id").map_err(|e| e.to_string())?;
        let projects = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, u64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Option<String>>(6)?,
                ))
            })
            .map_err(|e| e.to_string())?
            .map(|row| {
                let (
                    id,
                    mode,
                    desired_lifecycle,
                    observed_lifecycle,
                    project_epoch,
                    next_due_at_unix,
                    last_error,
                ) = row.map_err(|e| e.to_string())?;
                Ok(ProjectStatus {
                    id: ProjectId::parse(id)?,
                    mode,
                    desired_lifecycle,
                    observed_lifecycle,
                    project_epoch,
                    next_due_at_unix,
                    last_error,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let count = |query: &str| {
            connection
                .query_row(query, [], |row| row.get::<_, u64>(0))
                .map_err(|e| e.to_string())
        };
        Ok(RuntimeStatus {
            schema_version,
            owner_generation: owner.as_ref().map(|v| v.0),
            owner_pid: owner.as_ref().map(|v| v.1),
            owner_process_start_identity: owner.as_ref().map(|v| v.2.clone()),
            owner_started_at_unix: owner.map(|v| v.3),
            owner_rex_endpoint: owner_rex.0,
            owner_rex_server_identity: owner_rex.1,
            owner_rex_session_id: owner_rex.2,
            owner_rex_block_id: owner_rex.3,
            projects,
            pending_commands: count(
                "SELECT COUNT(*) FROM controller_commands WHERE state='pending'",
            )?,
            rejected_commands: count(
                "SELECT COUNT(*) FROM controller_commands WHERE state='rejected'",
            )?,
            pending_effects: count("SELECT COUNT(*) FROM effects WHERE status='pending'")?,
            uncertain_effects: count("SELECT COUNT(*) FROM effects WHERE status='uncertain'")?,
            occupied_slots: count(
                "SELECT COUNT(*) FROM execution_slots WHERE disposition!='released'",
            )?,
            observed_at_unix: now_unix()?,
        })
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
            project_id TEXT NOT NULL REFERENCES projects(project_id),
            subject_type TEXT NOT NULL,
            subject_id TEXT NOT NULL,
            logical_key TEXT NOT NULL,
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
            created_at_unix INTEGER NOT NULL,
            UNIQUE(project_id, subject_type, subject_id, logical_key)
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
            ticket_run_id TEXT REFERENCES ticket_runs(ticket_run_id),
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

fn persist_snapshot(
    tx: &rusqlite::Transaction<'_>,
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
    let current: Option<(u64, String)> = tx
        .query_row(
            "SELECT current.revision, snapshots.digest FROM config_current current JOIN config_snapshots snapshots USING(source_identity, revision) WHERE current.source_identity = ?1",
            [source_identity],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    if let Some((revision, digest)) = &current
        && digest == snapshot.digest.as_str()
    {
        sync_project_configuration(tx, source_identity, Revision(*revision), snapshot)?;
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
        return Err("configuration revision conflict; current snapshot was left unchanged".into());
    }
    let next_revision = current
        .as_ref()
        .map_or(Some(1), |(revision, _)| revision.checked_add(1))
        .ok_or_else(|| "configuration revision is exhausted".to_owned())?;
    i64::try_from(next_revision)
        .map_err(|_| "configuration revision exceeds SQLite's signed integer range".to_owned())?;
    let applied_at = now_unix()?;
    tx.execute(
        "INSERT INTO config_snapshots(revision, source_identity, digest, digest_algorithm, representation, effective_config_json, source_manifest_json, applied_at_unix) VALUES (?1, ?2, ?3, 'sha256', 'canonical_json_utf8_sorted_keys', ?4, ?5, ?6)",
        params![next_revision, source_identity, snapshot.digest.as_str(), effective_config_json, source_manifest_json, applied_at],
    )
    .map_err(|error| error.to_string())?;
    tx.execute(
        "INSERT INTO config_current(source_identity, revision) VALUES (?1, ?2) ON CONFLICT(source_identity) DO UPDATE SET revision=excluded.revision",
        params![source_identity, next_revision],
    )
    .map_err(|error| error.to_string())?;
    sync_project_configuration(tx, source_identity, Revision(next_revision), snapshot)?;
    Ok(AppliedRevision {
        revision: Revision(next_revision),
        digest: snapshot.digest.clone(),
        unchanged: false,
    })
}

fn sync_project_configuration(
    tx: &rusqlite::Transaction<'_>,
    source_identity: &str,
    revision: Revision,
    snapshot: &AppliedConfig,
) -> Result<(), String> {
    let digest = snapshot.digest.as_str();
    let configured = snapshot
        .config
        .projects
        .keys()
        .map(|project| project.as_str().to_owned())
        .collect::<std::collections::BTreeSet<_>>();
    let mut statement = tx
        .prepare("SELECT project_id FROM projects WHERE config_source=?1")
        .map_err(|error| error.to_string())?;
    let existing = statement
        .query_map([source_identity], |row| row.get::<_, String>(0))
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    drop(statement);
    for project_id in existing {
        if !configured.contains(&project_id) {
            tx.execute(
                "UPDATE projects SET desired_lifecycle='stopped' WHERE project_id=?1",
                [&project_id],
            )
            .map_err(|error| error.to_string())?;
            tx.execute(
                "UPDATE project_runtimes SET desired_lifecycle='stopped',observed_lifecycle='stopped',project_epoch=project_epoch+1 WHERE project_id=?1",
                [&project_id],
            )
            .map_err(|error| error.to_string())?;
        }
    }
    for (id, project) in &snapshot.config.projects {
        let mode = enum_string(&project.mode)?;
        let goal_revision = project.goal.as_ref().map_or(0, |goal| goal.revision);
        let current_owner: Option<String> = tx
            .query_row(
                "SELECT config_source FROM projects WHERE project_id=?1",
                [id.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if let Some(owner) = current_owner
            && owner != source_identity
        {
            return Err(format!(
                "Project `{}` is already owned by another configuration source",
                id.as_str()
            ));
        }
        let inserted = tx.execute(
            "INSERT INTO projects(project_id,config_source,config_revision,config_digest,mode,goal_revision,desired_lifecycle,state_revision,created_at_unix) VALUES (?1,?2,?3,?4,?5,?6,'stopped',0,?7) ON CONFLICT(project_id) DO NOTHING",
            params![id.as_str(), source_identity, revision.0, digest, mode, goal_revision, now_unix()?],
        ).map_err(|error| error.to_string())? == 1;
        if inserted {
            tx.execute(
                "INSERT INTO project_runtimes(project_id,desired_lifecycle,observed_lifecycle,controller_generation,project_epoch,next_due_at_unix) VALUES (?1,'stopped','stopped',0,1,0)",
                [id.as_str()],
            )
            .map_err(|error| error.to_string())?;
        } else {
            tx.execute(
                "UPDATE projects SET config_revision=?2,config_digest=?3,mode=?4,goal_revision=?5 WHERE project_id=?1",
                params![id.as_str(), revision.0, digest, mode, goal_revision],
            )
            .map_err(|error| error.to_string())?;
        }
    }
    Ok(())
}

fn migrate_v3(connection: &Connection) -> Result<(), String> {
    let tx = connection
        .unchecked_transaction()
        .map_err(|e| e.to_string())?;
    tx.execute_batch(
        "CREATE TABLE controller_commands (
            sequence INTEGER PRIMARY KEY,
            request_id TEXT NOT NULL UNIQUE,
            kind TEXT NOT NULL CHECK(kind IN ('machine_stop','project_lifecycle')),
            project_id TEXT REFERENCES projects(project_id),
            lifecycle TEXT CHECK(lifecycle IS NULL OR lifecycle IN ('running','paused','stopped')),
            state TEXT NOT NULL CHECK(state IN ('pending','applied','rejected')),
            created_at_unix INTEGER NOT NULL,
            expected_generation INTEGER NOT NULL,
            applied_by_generation INTEGER,
            applied_at_unix INTEGER,
            result_json TEXT,
            CHECK((kind = 'machine_stop' AND project_id IS NULL AND lifecycle IS NULL) OR (kind = 'project_lifecycle' AND project_id IS NOT NULL AND lifecycle IS NOT NULL))
        );
        CREATE INDEX controller_commands_pending ON controller_commands(state, sequence);
        INSERT INTO schema_migrations(version, applied_at_unix) VALUES (3, unixepoch());
        PRAGMA user_version = 3;",
    )
    .map_err(|e| e.to_string())?;
    tx.commit().map_err(|e| e.to_string())
}

fn migrate_v4(connection: &Connection) -> Result<(), String> {
    let tx = connection
        .unchecked_transaction()
        .map_err(|error| error.to_string())?;
    tx.execute_batch(
        "ALTER TABLE ticket_runs ADD COLUMN required_review_revision INTEGER;
        INSERT INTO schema_migrations(version, applied_at_unix) VALUES (4, unixepoch());
        PRAGMA user_version = 4;",
    )
    .map_err(|error| error.to_string())?;
    tx.commit().map_err(|error| error.to_string())
}

fn migrate_v5(connection: &Connection) -> Result<(), String> {
    let tx = connection
        .unchecked_transaction()
        .map_err(|error| error.to_string())?;
    tx.execute_batch(
        "CREATE TABLE controller_commands_v5 (
            sequence INTEGER PRIMARY KEY,
            request_id TEXT NOT NULL UNIQUE,
            kind TEXT NOT NULL CHECK(kind IN ('machine_stop','project_lifecycle','config_apply')),
            project_id TEXT REFERENCES projects(project_id),
            lifecycle TEXT CHECK(lifecycle IS NULL OR lifecycle IN ('running','paused','stopped')),
            payload_json TEXT CHECK(payload_json IS NULL OR length(payload_json) <= 1048576),
            state TEXT NOT NULL CHECK(state IN ('pending','applied','rejected')),
            created_at_unix INTEGER NOT NULL,
            expected_generation INTEGER NOT NULL,
            applied_by_generation INTEGER,
            applied_at_unix INTEGER,
            result_json TEXT,
            CHECK((kind='machine_stop' AND project_id IS NULL AND lifecycle IS NULL AND payload_json IS NULL) OR (kind='project_lifecycle' AND project_id IS NOT NULL AND lifecycle IS NOT NULL AND payload_json IS NULL) OR (kind='config_apply' AND project_id IS NULL AND lifecycle IS NULL AND payload_json IS NOT NULL))
        );
        INSERT INTO controller_commands_v5(sequence,request_id,kind,project_id,lifecycle,payload_json,state,created_at_unix,expected_generation,applied_by_generation,applied_at_unix,result_json)
            SELECT sequence,request_id,kind,project_id,lifecycle,NULL,state,created_at_unix,expected_generation,applied_by_generation,applied_at_unix,result_json FROM controller_commands;
        DROP INDEX controller_commands_pending;
        DROP TABLE controller_commands;
        ALTER TABLE controller_commands_v5 RENAME TO controller_commands;
        CREATE INDEX controller_commands_pending ON controller_commands(state, sequence);
        INSERT INTO schema_migrations(version, applied_at_unix) VALUES (5, unixepoch());
        PRAGMA user_version = 5;",
    )
    .map_err(|error| error.to_string())?;
    tx.commit().map_err(|error| error.to_string())
}

fn migrate_v6(connection: &Connection) -> Result<(), String> {
    let tx = connection
        .unchecked_transaction()
        .map_err(|error| error.to_string())?;
    tx.execute_batch(
        "CREATE TABLE human_claim_release_commands (
            sequence INTEGER PRIMARY KEY,
            request_id TEXT NOT NULL UNIQUE,
            payload_json TEXT NOT NULL CHECK(length(payload_json) <= 16384),
            state TEXT NOT NULL CHECK(state IN ('pending','applied','rejected')),
            created_at_unix INTEGER NOT NULL,
            expected_generation INTEGER NOT NULL,
            applied_by_generation INTEGER,
            applied_at_unix INTEGER,
            result_json TEXT
        );
        CREATE INDEX human_claim_release_pending ON human_claim_release_commands(state, sequence);
        CREATE TABLE ticket_claim_reconciliations (
            namespace TEXT NOT NULL,
            ticket_id TEXT NOT NULL,
            release_request_id TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('pending','repolled_open','repolled_closed')),
            observed_status TEXT,
            external_revision TEXT,
            repolled_by_generation INTEGER,
            repolled_at_unix INTEGER,
            created_at_unix INTEGER NOT NULL,
            PRIMARY KEY(namespace,ticket_id)
        );
        INSERT INTO schema_migrations(version, applied_at_unix) VALUES (6, unixepoch());
        PRAGMA user_version = 6;",
    )
    .map_err(|error| error.to_string())?;
    tx.commit().map_err(|error| error.to_string())
}

fn apply_human_claim_release(
    tx: &rusqlite::Transaction<'_>,
    owner_generation: u64,
    request_id: &str,
    release: &HumanClaimRelease,
) -> Result<serde_json::Value, String> {
    if release.reason.trim().is_empty()
        || release.reason.len() > 2048
        || release.disposition != "cancel"
    {
        return Err("claim release requires a reason and explicit cancel disposition".into());
    }
    let namespace = TicketNamespace::parse(release.namespace.clone())?;
    let ticket = TicketId::parse(release.ticket.clone())?;
    let ticket_run = TicketRunId::parse(release.ticket_run_id.clone())?;
    let claim: Option<(String, u64, String, u64, String, String, u64)> = tx.query_row(
        "SELECT c.project_id,c.generation,r.namespace,r.generation,r.internal_phase,r.activity,r.revision FROM ticket_claims c JOIN ticket_runs r USING(ticket_run_id) WHERE c.namespace=?1 AND c.ticket_id=?2 AND c.ticket_run_id=?3",
        params![namespace.as_str(), ticket.as_str(), ticket_run.as_str()],
        |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?)),
    ).optional().map_err(|error| error.to_string())?;
    let Some((
        project_id,
        claim_generation,
        run_namespace,
        run_generation,
        phase,
        activity,
        revision,
    )) = claim
    else {
        return Err("ticket claim no longer matches the requested TicketRun".into());
    };
    if claim_generation != release.generation
        || run_generation != release.generation
        || run_namespace != namespace.as_str()
    {
        return Err(
            "ticket claim generation or namespace changed; refresh status before releasing".into(),
        );
    }
    if revision != release.expected_revision {
        return Err("TicketRun revision changed; refresh status before releasing".into());
    }
    let active_slot: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM execution_slots WHERE ticket_run_id=?1 AND disposition!='released')",
        [ticket_run.as_str()], |row| row.get(0),
    ).map_err(|error| error.to_string())?;
    if active_slot {
        return Err(
            "cannot release a claim while its TicketRun has a live or unknown execution slot"
                .into(),
        );
    }
    let next_revision = revision
        .checked_add(1)
        .ok_or_else(|| "TicketRun revision is exhausted".to_owned())?;
    if matches!(phase.as_str(), "done" | "canceled") {
        return Err(
            "TicketRun is already terminal; reconcile its claim through normal terminal cleanup"
                .into(),
        );
    }
    tx.execute(
        "UPDATE ticket_runs SET internal_phase='canceled',activity='failed',revision=?2 WHERE ticket_run_id=?1 AND revision=?3 AND generation=?4",
        params![ticket_run.as_str(),next_revision,revision,release.generation],
    ).map_err(|error| error.to_string())?;
    tx.execute(
        "INSERT INTO transitions(project_id,entity_type,entity_id,old_revision,new_revision,input_id,decision_reason,evidence_json,created_at_unix) VALUES (?1,'ticket_run',?2,?3,?4,?5,'Human relinquished ticket claim',?6,?7)",
        params![project_id,ticket_run.as_str(),revision,next_revision,request_id,serde_json::json!({"actor":"human-cli","reason":release.reason,"disposition":"cancel","prior_phase":phase,"prior_activity":activity,"ticket_run_revision":revision,"owner_generation":owner_generation}).to_string(),now_unix()?],
    ).map_err(|error| error.to_string())?;
    let deleted = tx.execute(
        "DELETE FROM ticket_claims WHERE namespace=?1 AND ticket_id=?2 AND ticket_run_id=?3 AND generation=?4",
        params![namespace.as_str(),ticket.as_str(),ticket_run.as_str(),release.generation],
    ).map_err(|error| error.to_string())?;
    if deleted != 1 {
        return Err("ticket claim changed during release".into());
    }
    tx.execute(
        "INSERT INTO ticket_claim_reconciliations(namespace,ticket_id,release_request_id,state,created_at_unix) VALUES (?1,?2,?3,'pending',?4) ON CONFLICT(namespace,ticket_id) DO UPDATE SET release_request_id=excluded.release_request_id,state='pending',observed_status=NULL,external_revision=NULL,repolled_by_generation=NULL,repolled_at_unix=NULL,created_at_unix=excluded.created_at_unix",
        params![namespace.as_str(),ticket.as_str(),request_id,now_unix()?],
    ).map_err(|error| error.to_string())?;
    Ok(
        serde_json::json!({"released":true,"ticket_run_id":ticket_run.as_str(),"revision":next_revision,"disposition":"cancel","external_ticket_repoll_required":true}),
    )
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
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_nanos();
    let destination = state_root.join(format!("state.sqlite3.pre-v2-{timestamp}.bak"));
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
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        let result = persist_snapshot(&tx, source_identity, snapshot, expectation)?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(result)
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

    /// Persist and return the host launch acknowledgement. Provider execution remains gated
    /// until the wrapper receives this exact durable receipt.
    pub fn authorize_agent_start(
        &mut self,
        current_generation: u64,
        request: &AgentStartRequest,
        observed: &ObservedWrapperIdentity,
    ) -> Result<AgentLaunchReceipt, String> {
        request.validate()?;
        observed.matches_start_request(request)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, current_generation)?;
        let authority_json: String = tx
            .query_row(
                "SELECT authority_json FROM agent_launch_authority WHERE agent_run_id=?1",
                [request.agent_run_id.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?
            .ok_or("Agent start request has no persisted host launch authority")?;
        let authority: AgentLaunchAuthority =
            crate::protocol::parse_unique(authority_json.as_bytes())
                .map_err(|error| format!("stored launch authority is invalid: {error}"))?;
        authority.validate()?;
        let qualification_json: String = tx
            .query_row(
                "SELECT receipt_json FROM provider_qualifications WHERE receipt_digest=?1",
                [authority.qualification_receipt_digest.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?
            .ok_or("launch authority provider qualification is missing")?;
        let qualification: ProviderQualification =
            crate::protocol::parse_unique(qualification_json.as_bytes())
                .map_err(|error| format!("stored provider qualification is invalid: {error}"))?;
        let expected = authority.expectation(&qualification);
        let receipt = authorize_start(current_generation, &expected, &qualification, request)?;
        let run: Option<(String, u64, String)> = tx
            .query_row(
                "SELECT state,controller_generation,launch_operation_id FROM agent_runs WHERE agent_run_id=?1",
                [request.agent_run_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if !matches!(run, Some((ref state, generation, ref operation)) if state == "launch_pending" && generation == current_generation && operation == request.operation_id.as_str())
        {
            return Err(
                "AgentRun is not launch-pending under the active controller generation".into(),
            );
        }
        let stored_ack: Option<(String, String)> = tx
            .query_row(
                "SELECT start_request_digest,launch_receipt_json FROM agent_launch_state WHERE agent_run_id=?1",
                [request.agent_run_id.as_str()],
                |row| Ok((row.get(0)?,row.get(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let request_json = serde_json::to_string(request).map_err(|error| error.to_string())?;
        let request_digest =
            Digest::parse(format!("{:x}", Sha256::digest(request_json.as_bytes())))?;
        let receipt_json = serde_json::to_string(&receipt).map_err(|error| error.to_string())?;
        if let Some((previous_digest, previous_receipt)) = stored_ack {
            if previous_digest != request_digest.as_str() || previous_receipt != receipt_json {
                return Err(
                    "AgentRun already has a different persisted start acknowledgement".into(),
                );
            }
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(receipt);
        }
        let wrapper_json = serde_json::to_string(observed).map_err(|error| error.to_string())?;
        let changed = tx.execute(
            "UPDATE agent_launch_state SET state='awaiting_provider',start_request_id=?2,start_request_digest=?3,wrapper_process_identity_json=?4,launch_receipt_json=?5,last_observed_at_unix=?6,updated_at_unix=?6 WHERE agent_run_id=?1 AND state IN ('block_created','unknown') AND start_request_id IS NULL",
            params![request.agent_run_id.as_str(),request.operation_id.as_str(),request_digest.as_str(),wrapper_json,receipt_json,now_unix()?],
        ).map_err(|error| error.to_string())?;
        if changed != 1 {
            return Err("Agent launch state is not ready for a new start acknowledgement".into());
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(receipt)
    }

    /// Mark a run active only after the host process observer confirms the exact provider
    /// executable and process tree. An unconfirmed observation remains unresolved.
    pub fn confirm_provider_started(
        &mut self,
        current_generation: u64,
        observation: &ObservedProviderStart,
    ) -> Result<(), String> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, current_generation)?;
        let authority_json: String = tx
            .query_row(
                "SELECT authority_json FROM agent_launch_authority WHERE agent_run_id=?1",
                [observation.agent_run_id.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?
            .ok_or("provider start observation references no launch authority")?;
        let authority: AgentLaunchAuthority =
            crate::protocol::parse_unique(authority_json.as_bytes())
                .map_err(|error| format!("stored launch authority is invalid: {error}"))?;
        if authority.controller_generation != current_generation
            || authority.operation_id != observation.operation_id
        {
            return Err(
                "provider start observation does not match the active launch authority".into(),
            );
        }
        let qualification_json: String = tx
            .query_row(
                "SELECT receipt_json FROM provider_qualifications WHERE receipt_digest=?1",
                [authority.qualification_receipt_digest.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?
            .ok_or("provider start qualification receipt is missing")?;
        let qualification: ProviderQualification =
            crate::protocol::parse_unique(qualification_json.as_bytes())
                .map_err(|error| format!("stored provider qualification is invalid: {error}"))?;
        observation.validate(&qualification)?;
        let process_tree_json =
            serde_json::to_string(observation).map_err(|error| error.to_string())?;
        let now = now_unix()?;
        let changed = tx.execute(
            "UPDATE agent_launch_state SET state='running',provider_process_tree_json=?2,last_observed_at_unix=?3,updated_at_unix=?3 WHERE agent_run_id=?1 AND state='awaiting_provider' AND start_request_id=?4",
            params![observation.agent_run_id.as_str(),process_tree_json,now,observation.operation_id.as_str()],
        ).map_err(|error| error.to_string())?;
        if changed != 1 {
            return Err("AgentRun has no matching provider launch awaiting observation".into());
        }
        let process_identity = serde_json::json!({
            "provider_pid": observation.provider_pid,
            "provider_start_identity": observation.provider_start_identity,
            "executable_digest": observation.executable_digest,
            "process_tree_digest": observation.process_tree_digest,
        });
        let run_changed = tx.execute(
            "UPDATE agent_runs SET state='running',process_identity_json=?2,started_at_unix=COALESCE(started_at_unix,?3) WHERE agent_run_id=?1 AND state='launch_pending' AND controller_generation=?4",
            params![observation.agent_run_id.as_str(),serde_json::to_string(&process_identity).map_err(|error| error.to_string())?,now,current_generation],
        ).map_err(|error| error.to_string())?;
        if run_changed != 1 {
            return Err(
                "AgentRun state changed before provider start observation was committed".into(),
            );
        }
        tx.commit().map_err(|error| error.to_string())
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
    if input.content_digest != durable_input_digest(&input.recipient, &input.payload) {
        return Err("input digest does not match recipient and payload bytes".into());
    }
    if input.payload.len() > MAX_INPUT_BYTES {
        return Err("input payload exceeds limit".into());
    }
    crate::protocol::parse_unique::<serde_json::Value>(input.payload.as_bytes())
        .map_err(|e| format!("invalid input JSON: {e}"))?;
    Ok(())
}

fn enum_string(value: &impl serde::Serialize) -> Result<String, String> {
    serde_json::to_value(value)
        .map_err(|error| error.to_string())?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| "typed state did not serialize as a string".into())
}

fn parse_ticket_status(value: &str) -> Result<crate::domain::types::TicketStatus, String> {
    let name = match value {
        "Triage" => "triage",
        "Backlog" => "backlog",
        "ToDo" | "Ready" => "ready",
        "In Progress" => "in_progress",
        "In Review" => "in_review",
        "Done" => "done",
        "Canceled" => "canceled",
        other => other,
    };
    serde_json::from_str(&format!("\"{name}\""))
        .map_err(|error| format!("stored ticket status `{value}` is unsupported: {error}"))
}

fn content_digest(bytes: &str) -> String {
    format!("{:x}", Sha256::digest(bytes.as_bytes()))
}

fn insert_effect(
    tx: &rusqlite::Transaction<'_>,
    effect: &EffectIntent,
    now: i64,
) -> Result<bool, String> {
    validate_effect(effect)?;
    validate_effect_subject(tx, effect)?;
    let inserted = tx.execute("INSERT INTO effects(operation_id, project_id, subject_type, subject_id, logical_key, kind, request_json, request_digest, expected_revision, status, attempt_count, next_attempt_at_unix, created_at_unix) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'pending', 0, ?10, ?10) ON CONFLICT DO NOTHING", params![effect.operation_id, effect.project_id.as_str(), effect.subject_type, effect.subject_id, effect.logical_key, effect.kind, effect.request_json, effect.request_digest, effect.expected_revision, now]).map_err(|e| e.to_string())?;
    if inserted == 1 {
        return Ok(true);
    }
    let existing_by_operation: Option<(String,String,String,String,String,String,String)> = tx.query_row("SELECT project_id,subject_type,subject_id,logical_key,kind,request_json,request_digest FROM effects WHERE operation_id=?1", [&effect.operation_id], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?))).optional().map_err(|e| e.to_string())?;
    let expected = (
        effect.project_id.as_str(),
        effect.subject_type.as_str(),
        effect.subject_id.as_str(),
        effect.logical_key.as_str(),
        effect.kind.as_str(),
        effect.request_json.as_str(),
        effect.request_digest.as_str(),
    );
    if existing_by_operation.as_ref().is_some_and(|row| {
        row.0.as_str() == expected.0
            && row.1 == expected.1
            && row.2 == expected.2
            && row.3 == expected.3
            && row.4 == expected.4
            && row.5 == expected.5
            && row.6 == expected.6
    }) {
        return Ok(false);
    }
    Err("effect operation ID or scoped logical intent was reused with different ownership or content".into())
}

fn validate_effect_subject(
    tx: &rusqlite::Transaction<'_>,
    effect: &EffectIntent,
) -> Result<(), String> {
    let subject_revision: Option<u64> = match effect.subject_type.as_str() {
        "project" if effect.subject_id == effect.project_id.as_str() => tx
            .query_row(
                "SELECT state_revision FROM projects WHERE project_id=?1",
                [effect.project_id.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())?,
        "ticket_run" => tx
            .query_row(
                "SELECT revision FROM ticket_runs WHERE ticket_run_id=?1 AND project_id=?2",
                params![effect.subject_id, effect.project_id.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())?,
        "agent_run" => {
            let exists: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM agent_runs WHERE agent_run_id=?1 AND project_id=?2)",
                params![effect.subject_id, effect.project_id.as_str()],
                |row| row.get(0),
            ).map_err(|e| e.to_string())?;
            if !exists {
                return Err("effect subject does not belong to the declared Project".into());
            }
            if effect.expected_revision.is_some() {
                return Err("agent run effects do not accept a subject revision".into());
            }
            None
        }
        _ => return Err("effect subject type is not supported by this store".into()),
    };
    if subject_revision.is_none() && effect.subject_type != "agent_run" {
        return Err("effect subject does not belong to the declared Project".into());
    }
    if let (Some(expected), Some(actual)) = (effect.expected_revision, subject_revision)
        && expected != actual
    {
        return Err("effect expected subject revision is stale".into());
    }
    Ok(())
}

fn validate_effect(effect: &EffectIntent) -> Result<(), String> {
    if effect.operation_id.is_empty()
        || effect.logical_key.is_empty()
        || effect.kind.is_empty()
        || effect.subject_id.is_empty()
    {
        return Err("effect operation, logical key, kind and subject ID must not be empty".into());
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
        AgentLaunchAuthority, ConfigStore, DurableInput, EffectIntent, EffectOutcome,
        ExpectedRevision, HumanClaimRelease, OwnerMetadata, ProjectRecord, content_digest,
        durable_input_digest,
    };
    use crate::config::{AppliedConfig, SourceFile, SourceKind};
    use crate::domain::ids::{Digest, ProjectId, Revision, TicketId, TicketNamespace, TicketRunId};
    use crate::engine::reducer::Input;
    use crate::launch::{RexBlockLifecycle, RexBlockOwnership, RexView, RexViewBlock, RexViewKind};

    static STORE_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn snapshot(digest: &str) -> AppliedConfig {
        AppliedConfig {
            config: serde_json::from_value(serde_json::json!({"schema_version":1,"adapters":{"tickets":{"kind":"command","command":["test"],"status_values":{"triage":"Triage","backlog":"Backlog","ready":"Ready","in_progress":"In Progress","in_review":"In Review","done":"Done","canceled":"Canceled"}}},"projects":{}})).unwrap(),
            profiles: BTreeMap::new(), source_root: "/tmp/config".into(), source_files: vec![SourceFile { kind: SourceKind::File, path: "/tmp/config/config.toml".into(), canonical_path: "/tmp/config/config.toml".into(), sha256: Digest::parse("a".repeat(64)).unwrap(), bytes: 1, contents: "x".into() }], digest: Digest::parse(digest).unwrap(),
        }
    }

    #[test]
    fn effect_restart_reconciles_same_identity_before_retry() {
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
        let project_id = ProjectId::parse("effects-project").unwrap();
        store
            .insert_project(&ProjectRecord {
                id: project_id.clone(),
                config_source: "factory".into(),
                config_revision: applied.revision,
                config_digest: Digest::parse("a".repeat(64)).unwrap(),
                mode: "goal".into(),
                goal_revision: 1,
                desired_lifecycle: "running".into(),
                state_revision: Revision(0),
            })
            .unwrap();
        let owner = |nonce: &str| OwnerMetadata {
            owner_nonce: nonce.into(),
            state_root: temp.path().to_string_lossy().into_owned(),
            config_source: "factory".into(),
            process_start_identity: nonce.into(),
            executable_path: "/tmp/rex-projects-test".into(),
            executable_digest: "f".repeat(64),
            rex_endpoint: None,
            rex_server_identity: None,
            rex_session_id: None,
            rex_block_id: None,
        };
        let generation = store.start_owner(&owner("first")).unwrap();
        let request = r#"{"value":"same"}"#;
        let intent = EffectIntent {
            project_id: project_id.clone(),
            subject_type: "project".into(),
            subject_id: project_id.as_str().into(),
            operation_id: "stable-operation".into(),
            logical_key: "stable-logical-intent".into(),
            kind: "merge".into(),
            request_json: request.into(),
            request_digest: content_digest(request),
            expected_revision: Some(0),
        };
        store.enqueue_effect(generation, &intent).unwrap();
        let now = super::now_unix().unwrap();
        struct MockHandler {
            actions: Mutex<std::collections::VecDeque<&'static str>>,
            seen: Mutex<Vec<(crate::effects::EffectMode, crate::effects::EffectRequest)>>,
        }
        impl crate::effects::EffectHandler for MockHandler {
            fn kind(&self) -> crate::effects::EffectKind {
                crate::effects::EffectKind::Merge
            }
            fn handle(
                &self,
                mode: crate::effects::EffectMode,
                request: &crate::effects::EffectRequest,
                context: &mut crate::effects::EffectContext<'_>,
            ) -> Result<crate::effects::EffectObservation, String> {
                self.seen.lock().unwrap().push((mode, request.clone()));
                let progress = serde_json::to_string(&serde_json::json!({
                    "attempt": request.attempt_count,
                }))
                .unwrap();
                context.store.save_effect_progress(
                    &request.intent.operation_id,
                    context.owner_generation,
                    &request.intent.request_digest,
                    &progress,
                    context.now_unix,
                )?;
                assert_eq!(
                    context
                        .store
                        .load_effect_progress(
                            &request.intent.operation_id,
                            context.owner_generation,
                            &request.intent.request_digest,
                        )
                        .unwrap()
                        .as_deref(),
                    Some(progress.as_str())
                );
                match self.actions.lock().unwrap().pop_front().unwrap() {
                    "pending" => Ok(crate::effects::EffectObservation::Pending {
                        receipt: "{}".into(),
                    }),
                    "error" => Err("lookup unavailable".into()),
                    "absent" => Ok(crate::effects::EffectObservation::AuthoritativelyAbsent {
                        proof: crate::effects::AbsentProof::from_authoritative_lookup(
                            crate::effects::EffectKind::Merge,
                            request,
                            "fixture lookup",
                            "operation ID was not found",
                        )
                        .unwrap(),
                    }),
                    "applied" => Ok(crate::effects::EffectObservation::Applied {
                        receipt: "{\"merged\":true}".into(),
                    }),
                    other => Err(format!("unexpected test action {other}")),
                }
            }
        }
        let handler = MockHandler {
            actions: Mutex::new(["pending", "error", "error", "absent", "applied"].into()),
            seen: Mutex::new(Vec::new()),
        };
        let handlers: [&dyn crate::effects::EffectHandler; 1] = [&handler];
        let limits = crate::effects::EffectLimits {
            max_attempts: 3,
            max_age: std::time::Duration::from_secs(300),
            retry_base: std::time::Duration::from_secs(20),
            retry_max: std::time::Duration::from_secs(60),
        };
        assert_eq!(
            crate::effects::EffectDispatcher::tick(&mut store, generation, now, &handlers, limits)
                .unwrap(),
            crate::effects::DispatchTick::WaitingForReconciliation {
                operation_id: intent.operation_id.clone()
            }
        );

        let backlog = EffectIntent {
            operation_id: "newer-pending-operation".into(),
            logical_key: "newer-pending-intent".into(),
            ..intent.clone()
        };
        store.enqueue_effect(generation, &backlog).unwrap();
        store.connection.execute(
            "UPDATE effects SET created_at_unix=?2,next_attempt_at_unix=?3 WHERE operation_id=?1",
            rusqlite::params![backlog.operation_id, now + 1, now + 20],
        ).unwrap();

        store.stop_owner(generation).unwrap();
        let next_generation = store.start_owner(&owner("second")).unwrap();
        assert_eq!(
            crate::effects::EffectDispatcher::tick(
                &mut store,
                next_generation,
                now + 20,
                &handlers,
                limits
            )
            .unwrap(),
            crate::effects::DispatchTick::WaitingForReconciliation {
                operation_id: intent.operation_id.clone(),
            }
        );
        assert_eq!(
            handler.seen.lock().unwrap()[1].1.intent.operation_id,
            intent.operation_id
        );
        store
            .connection
            .execute(
                "UPDATE effects SET status='cancelled' WHERE operation_id=?1",
                [&backlog.operation_id],
            )
            .unwrap();
        store.stop_owner(next_generation).unwrap();
        let third_generation = store.start_owner(&owner("third")).unwrap();
        assert_eq!(
            crate::effects::EffectDispatcher::tick(
                &mut store,
                third_generation,
                now + 39,
                &handlers,
                limits
            )
            .unwrap(),
            crate::effects::DispatchTick::Idle
        );
        assert_eq!(
            crate::effects::EffectDispatcher::tick(
                &mut store,
                third_generation,
                now + 40,
                &handlers,
                limits
            )
            .unwrap(),
            crate::effects::DispatchTick::WaitingForReconciliation {
                operation_id: intent.operation_id.clone()
            }
        );
        assert_eq!(
            crate::effects::EffectDispatcher::tick(
                &mut store,
                third_generation,
                now + 79,
                &handlers,
                limits,
            )
            .unwrap(),
            crate::effects::DispatchTick::Idle,
        );
        store.stop_owner(third_generation).unwrap();
        let fourth_generation = store.start_owner(&owner("fourth")).unwrap();
        assert_eq!(
            crate::effects::EffectDispatcher::tick(
                &mut store,
                fourth_generation,
                now + 80,
                &handlers,
                limits
            )
            .unwrap(),
            crate::effects::DispatchTick::RetryScheduled {
                operation_id: intent.operation_id.clone(),
                attempt: 1
            },
        );
        assert_eq!(
            crate::effects::EffectDispatcher::tick(
                &mut store,
                fourth_generation,
                now + 139,
                &handlers,
                limits
            )
            .unwrap(),
            crate::effects::DispatchTick::Idle,
        );
        store.stop_owner(fourth_generation).unwrap();
        let fifth_generation = store.start_owner(&owner("fifth")).unwrap();
        assert_eq!(
            crate::effects::EffectDispatcher::tick(
                &mut store,
                fifth_generation,
                now + 140,
                &handlers,
                limits
            )
            .unwrap(),
            crate::effects::DispatchTick::Completed {
                operation_id: intent.operation_id.clone()
            },
        );
        let seen = handler.seen.lock().unwrap();
        assert_eq!(
            seen.iter().map(|(mode, _)| *mode).collect::<Vec<_>>(),
            [
                crate::effects::EffectMode::Submit,
                crate::effects::EffectMode::Reconcile,
                crate::effects::EffectMode::Reconcile,
                crate::effects::EffectMode::Reconcile,
                crate::effects::EffectMode::Submit,
            ]
        );
        assert!(seen.iter().all(
            |(_, request)| request.intent.operation_id == intent.operation_id
                && request.intent.request_digest == intent.request_digest
        ));
        assert_eq!(
            seen.iter()
                .map(|(_, request)| request.attempt_count)
                .collect::<Vec<_>>(),
            [1, 1, 1, 1, 2]
        );
    }

    #[test]
    fn rex_view_history_pin_and_user_blocks_prevent_automatic_cleanup() {
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
            id: ProjectId::parse("view-project").unwrap(),
            config_source: "factory".into(),
            config_revision: applied.revision,
            config_digest: Digest::parse("a".repeat(64)).unwrap(),
            mode: "operations".into(),
            goal_revision: 0,
            desired_lifecycle: "running".into(),
            state_revision: Revision(0),
        };
        store.insert_project(&project).unwrap();
        let generation = store
            .start_owner(&OwnerMetadata {
                owner_nonce: "view-owner".into(),
                state_root: temp.path().to_string_lossy().into_owned(),
                config_source: "factory".into(),
                process_start_identity: "view-process".into(),
                executable_path: "/tmp/rex-projects-test".into(),
                executable_digest: "e".repeat(64),
                rex_endpoint: None,
                rex_server_identity: None,
                rex_session_id: None,
                rex_block_id: None,
            })
            .unwrap();
        let view_id =
            RexView::derive_id(&project.id, RexViewKind::Supervisor, None, None, 1).unwrap();
        let view = RexView {
            view_id: view_id.clone(),
            project_id: project.id.clone(),
            kind: RexViewKind::Supervisor,
            ticket_namespace: None,
            ticket_id: None,
            view_epoch: 1,
            rex_server_identity: "fixture-instance".into(),
            rex_session_id: "session-1".into(),
            rex_window_id: "window-1".into(),
        };
        assert!(store.register_rex_view(generation, &view).unwrap());
        assert!(!store.register_rex_view(generation, &view).unwrap());
        let ticket_view = |epoch| RexView {
            view_id: RexView::derive_id(
                &project.id,
                RexViewKind::Ticket,
                Some("tracker"),
                Some("T-1"),
                epoch,
            )
            .unwrap(),
            project_id: project.id.clone(),
            kind: RexViewKind::Ticket,
            ticket_namespace: Some("tracker".into()),
            ticket_id: Some("T-1".into()),
            view_epoch: epoch,
            rex_server_identity: "fixture-instance".into(),
            rex_session_id: "session-1".into(),
            rex_window_id: format!("ticket-window-{epoch}"),
        };
        let ticket_view_1 = ticket_view(1);
        assert!(store.register_rex_view(generation, &ticket_view_1).unwrap());
        let ticket_view_2 = ticket_view(2);
        assert!(store.register_rex_view(generation, &ticket_view_2).is_err());
        assert_eq!(store.rex_view_history(&project.id).unwrap().len(), 2);
        store.set_rex_view_pin(generation, &view_id, true).unwrap();
        store.set_rex_view_pin(generation, &view_id, false).unwrap();
        assert!(
            store
                .register_rex_view_block(
                    generation,
                    &RexViewBlock {
                        view_id: view_id.clone(),
                        block_id: "human-block".into(),
                        agent_run_id: None,
                        role: None,
                        ownership: RexBlockOwnership::User,
                        lifecycle: RexBlockLifecycle::Active,
                        process_absent_confirmed: false,
                        retained_until_unix: None,
                    },
                )
                .unwrap()
        );
        let focus = store
            .rex_focus_target(generation, &view_id, "human-block")
            .unwrap();
        assert_eq!(focus.rex_session_id, "session-1");
        assert!(
            store
                .rex_view_cleanup_candidates(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                    1,
                )
                .unwrap()
                .is_empty()
        );
        store
            .connection
            .execute_batch("PRAGMA foreign_keys=OFF;")
            .unwrap();
        store
            .connection
            .execute(
                "DELETE FROM rex_view_blocks WHERE view_id=?1 AND block_id='human-block'",
                [view_id.as_str()],
            )
            .unwrap();
        store.connection.execute(
            "INSERT INTO rex_view_blocks(view_id,block_id,agent_run_id,role,ownership,lifecycle,process_absent_confirmed,created_at_unix,last_observed_at_unix) VALUES (?1,'factory-block','synthetic-run','supervisor','factory','completed',1,1,1)",
            [view_id.as_str()],
        ).unwrap();
        store.connection.execute(
            "INSERT INTO human_requests(request_id,project_id,purpose,subject_kind,subject_id,subject_revision,rex_view_id,subject_digest,material_digest,configuration_digest,policy_digest,bundle_digest,request_json,artifact_path,lifecycle,created_at_unix,expires_at_unix) VALUES ('request-1',?2,'ticket_review','ticket_run','run-1',0,?1,?3,?3,?3,?3,?3,'{}','/tmp/request.html','pending',1,9999999999)",
            rusqlite::params![view_id.as_str(), project.id.as_str(), "a".repeat(64)],
        ).unwrap();
        store
            .connection
            .execute(
                "UPDATE rex_views SET updated_at_unix=0 WHERE view_id=?1",
                [view_id.as_str()],
            )
            .unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(
            store
                .rex_view_cleanup_candidates(now, 0)
                .unwrap()
                .is_empty()
        );
        let candidate = crate::launch::RexViewCleanupCandidate {
            view: view.clone(),
            close_after_unix: now,
        };
        assert!(
            store
                .begin_rex_view_close(generation, &candidate, now, 0)
                .is_err()
        );
        store
            .connection
            .execute(
                "UPDATE human_requests SET lifecycle='decided' WHERE request_id='request-1'",
                [],
            )
            .unwrap();
        assert_eq!(store.rex_view_cleanup_candidates(now, 0).unwrap().len(), 1);
    }

    #[test]
    fn config_apply_queue_survives_a_concurrent_wal_writer() {
        let _guard = STORE_TEST_LOCK.lock().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let mut store = ConfigStore::open_test(temp.path()).unwrap();
        store
            .apply_snapshot(
                "factory",
                &snapshot(&"a".repeat(64)),
                ExpectedRevision::Bootstrap,
            )
            .unwrap();
        let generation = store
            .start_owner(&OwnerMetadata {
                owner_nonce: "queue-writer-test".into(),
                state_root: temp.path().to_string_lossy().into_owned(),
                config_source: "factory".into(),
                process_start_identity: "queue-writer-test".into(),
                executable_path: "/tmp/rex-projects-test".into(),
                executable_digest: "f".repeat(64),
                rex_endpoint: None,
                rex_server_identity: None,
                rex_session_id: None,
                rex_block_id: None,
            })
            .unwrap();
        let mut writer = rusqlite::Connection::open(temp.path().join("state.sqlite3")).unwrap();
        writer
            .busy_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        let writer_tx = writer
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        let state_root = temp.path().to_owned();
        let next_snapshot = snapshot(&"b".repeat(64));
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let append = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            ConfigStore::append_config_apply(
                &state_root,
                "queued-during-controller-write",
                "factory",
                &next_snapshot,
                ExpectedRevision::Current(Revision(1)),
                generation,
            )
        });
        started_rx.recv().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
        writer_tx.commit().unwrap();
        append
            .join()
            .unwrap()
            .expect("config apply should wait for and follow the active WAL writer");
    }

    #[test]
    fn launch_authority_block_binding_rejects_different_rex_block() {
        let _guard = STORE_TEST_LOCK.lock().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let mut store = ConfigStore::open_test(temp.path()).unwrap();
        let project_id = ProjectId::parse("block-binding-project").unwrap();
        let applied = store
            .apply_snapshot(
                "factory",
                &snapshot(&"a".repeat(64)),
                ExpectedRevision::Bootstrap,
            )
            .unwrap();
        store
            .insert_project(&ProjectRecord {
                id: project_id.clone(),
                config_source: "factory".into(),
                config_revision: applied.revision,
                config_digest: Digest::parse("a".repeat(64)).unwrap(),
                mode: "operations".into(),
                goal_revision: 0,
                desired_lifecycle: "running".into(),
                state_revision: Revision(0),
            })
            .unwrap();
        let generation = store
            .start_owner(&OwnerMetadata {
                owner_nonce: "block-owner".into(),
                state_root: temp.path().to_string_lossy().into_owned(),
                config_source: "factory".into(),
                process_start_identity: "block-process".into(),
                executable_path: "/tmp/rex-projects-test".into(),
                executable_digest: "e".repeat(64),
                rex_endpoint: None,
                rex_server_identity: None,
                rex_session_id: None,
                rex_block_id: None,
            })
            .unwrap();
        let view_id =
            RexView::derive_id(&project_id, RexViewKind::Supervisor, None, None, 1).unwrap();
        store
            .register_rex_view(
                generation,
                &RexView {
                    view_id: view_id.clone(),
                    project_id: project_id.clone(),
                    kind: RexViewKind::Supervisor,
                    ticket_namespace: None,
                    ticket_id: None,
                    view_epoch: 1,
                    rex_server_identity: "fixture-instance".into(),
                    rex_session_id: "session-1".into(),
                    rex_window_id: "window-1".into(),
                },
            )
            .unwrap();
        store.connection.execute(
            "INSERT INTO agent_runs(agent_run_id,project_id,config_source,config_revision,config_digest,role_session_id,logical_owner,finite_turn,launch_operation_id,state,controller_generation) VALUES ('run-1',?1,'factory',?2,?3,'role-session','supervisor',1,'op-1','launch_pending',?4)",
            rusqlite::params![project_id.as_str(), applied.revision.0, "a".repeat(64), generation],
        ).unwrap();
        let mismatched_session_authority = AgentLaunchAuthority {
            agent_run_id: crate::domain::ids::AgentRunId::parse("run-1").unwrap(),
            project_id: project_id.clone(),
            role: crate::domain::types::Role::Supervisor,
            role_session_id: "forged-session".into(),
            parent_run_id: None,
            parent_role: None,
            ticket_run_id: None,
            ticket_revision: None,
            config_revision: applied.revision,
            config_digest: Digest::parse("a".repeat(64)).unwrap(),
            attempt: 1,
            run_epoch: 1,
            controller_generation: generation,
            operation_id: crate::domain::ids::OperationId::parse("op-1").unwrap(),
            operation_recipe_id: None,
            rex_view_id: Digest::parse("b".repeat(64)).unwrap(),
            descriptor_digest: Digest::parse("c".repeat(64)).unwrap(),
            runtime_binary_digest: Digest::parse("d".repeat(64)).unwrap(),
            descriptor_path: "/tmp/descriptor.json".into(),
            environment_snapshot_id: Digest::parse("e".repeat(64)).unwrap(),
            profile_id: crate::domain::ids::ProfileId::parse("supervisor").unwrap(),
            profile_digest: Digest::parse("f".repeat(64)).unwrap(),
            instruction_digest: Digest::parse("a".repeat(64)).unwrap(),
            result_schema_digest: Digest::parse("b".repeat(64)).unwrap(),
            wake_snapshot_digest: Digest::parse("c".repeat(64)).unwrap(),
            qualification_receipt_digest: Digest::parse("c".repeat(64)).unwrap(),
            rex_server_identity: "fixture-instance".into(),
            rex_session_id: "session-1".into(),
            rex_window_id: "window-1".into(),
            rex_block_id: "authorized-block".into(),
            workspace_path: "/tmp/workspace".into(),
            control_dir: "/tmp/control".into(),
            mailbox_capability_digest: Digest::parse("d".repeat(64)).unwrap(),
        };
        let mismatch_error = store
            .register_agent_launch_authority(generation, &mismatched_session_authority)
            .unwrap_err();
        assert!(
            mismatch_error.contains("AgentRun identity"),
            "{mismatch_error}"
        );
        store
            .connection
            .execute_batch("PRAGMA foreign_keys=OFF;")
            .unwrap();
        store.connection.execute(
            "INSERT INTO agent_launch_authority(agent_run_id,project_id,role,role_session_id,config_revision,config_digest,attempt,run_epoch,controller_generation,launch_operation_id,rex_view_id,descriptor_digest,runtime_binary_digest,descriptor_path,environment_snapshot_id,profile_id,profile_digest,instruction_digest,result_schema_digest,qualification_receipt_digest,rex_server_identity,rex_session_id,rex_window_id,rex_block_id,workspace_path,control_dir,mailbox_capability_digest,authority_json,authority_digest,created_at_unix) VALUES ('run-1',?1,'supervisor','role-session',1,?2,1,1,?3,'op-1',?4,?5,?5,'/tmp/descriptor',?5,'profile',?5,?5,?5,?5,'fixture-instance','session-1','window-1','authorized-block','/tmp/workspace','/tmp/control',?5,'{}',?5,1)",
            rusqlite::params![project_id.as_str(), "a".repeat(64), generation, view_id.as_str(), "b".repeat(64)],
        ).unwrap();
        let result = store.register_rex_view_block(
            generation,
            &RexViewBlock {
                view_id,
                block_id: "attacker-selected-block".into(),
                agent_run_id: Some(crate::domain::ids::AgentRunId::parse("run-1").unwrap()),
                role: Some(crate::domain::types::Role::Supervisor),
                ownership: RexBlockOwnership::Factory,
                lifecycle: RexBlockLifecycle::Active,
                process_absent_confirmed: false,
                retained_until_unix: None,
            },
        );
        assert!(result.is_err());
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
                rex_endpoint: None,
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
        let transition_payload = r#"{"input":"dispatch"}"#;
        let transition_input = DurableInput {
            producer_id: "agent-run-coordinator-1".into(),
            message_id: "dispatch-message-1".into(),
            content_digest: durable_input_digest("ticket_run", transition_payload),
            recipient: "ticket_run".into(),
            payload: transition_payload.into(),
        };
        let effect = |operation_id: &str, logical_key: &str, kind: &str| EffectIntent {
            project_id: project.id.clone(),
            subject_type: "ticket_run".into(),
            subject_id: ticket_run.as_str().into(),
            operation_id: operation_id.into(),
            logical_key: logical_key.into(),
            kind: kind.into(),
            request_json: "{}".into(),
            request_digest: content_digest("{}"),
            expected_revision: Some(1),
        };
        let effects = [effect(
            "publish-in-progress",
            "publish-in-progress-r1",
            "publish_ticket_status",
        )];
        let receipt = store
            .commit_ticket_transition(
                generation,
                &ticket_run,
                Revision(0),
                &transition_input,
                Input::Dispatch,
                "A ready TicketRun is dispatched.",
                "{}",
                &effects,
            )
            .unwrap();
        assert!(!receipt.duplicate);
        assert_eq!(receipt.receipt["revision"], 1);
        let retry = store
            .commit_ticket_transition(
                generation,
                &ticket_run,
                Revision(0),
                &transition_input,
                Input::Dispatch,
                "A ready TicketRun is dispatched.",
                "{}",
                &effects,
            )
            .unwrap();
        assert!(retry.duplicate);
        let ticket_state: (String, u64) = store
            .connection
            .query_row(
                "SELECT internal_phase, revision FROM ticket_runs WHERE ticket_run_id=?1",
                [ticket_run.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(ticket_state, ("planning".into(), 1));
        let committed: u64 = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM effects WHERE subject_id=?1 AND status='pending'",
                [ticket_run.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(committed, 1);
        let coordinator_wake: u64 = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM role_wake_inputs WHERE project_id=?1 AND role_session_id=?2 AND lifecycle='pending'",
                rusqlite::params![project.id.as_str(),format!("ticket_run:{}:coordinator",ticket_run.as_str())],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(coordinator_wake, 1);
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
                .is_err()
        );
        store
            .connection
            .execute(
                "UPDATE ticket_runs SET external_status='Done' WHERE ticket_run_id=?1",
                [ticket_run.as_str()],
            )
            .unwrap();
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
                    "ticket_run",
                    other_run.as_str(),
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
        let payload = r#"{"kind":"plan_accepted"}"#;
        let input = DurableInput {
            producer_id: "agent-run-1".into(),
            message_id: "wake-1".into(),
            content_digest: durable_input_digest("coordinator", payload),
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
            project_id: project.id.clone(),
            subject_type: "ticket_run".into(),
            subject_id: ticket_run.as_str().to_owned(),
            operation_id: "op-1".into(),
            logical_key: "payments:ticket-1:start-worker".into(),
            kind: "start_worker".into(),
            request_json: r#"{"ticket_id":"ticket-1"}"#.into(),
            request_digest: content_digest(r#"{"ticket_id":"ticket-1"}"#),
            expected_revision: Some(1),
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
        let shared_key_in_other_project = EffectIntent {
            project_id: other_project.id.clone(),
            subject_type: "ticket_run".into(),
            subject_id: other_run.as_str().to_owned(),
            operation_id: "op-other-project".into(),
            logical_key: "payments:ticket-1:start-worker".into(),
            kind: "start_worker".into(),
            request_json: r#"{"ticket_id":"ticket-1"}"#.into(),
            request_digest: content_digest(r#"{"ticket_id":"ticket-1"}"#),
            expected_revision: Some(0),
        };
        assert!(
            store
                .enqueue_effect(generation, &shared_key_in_other_project)
                .unwrap()
        );
        let reused_operation = EffectIntent {
            operation_id: "op-1".into(),
            logical_key: "different-key".into(),
            ..shared_key_in_other_project
        };
        assert!(store.enqueue_effect(generation, &reused_operation).is_err());
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
        let changed_recipient = DurableInput {
            producer_id: input.producer_id.clone(),
            message_id: input.message_id.clone(),
            content_digest: durable_input_digest("supervisor", payload),
            recipient: "supervisor".into(),
            payload: payload.into(),
        };
        assert!(
            store
                .commit_transition(
                    generation,
                    &project.id,
                    Revision(0),
                    &changed_recipient,
                    "changed recipient",
                    "{}",
                    &[]
                )
                .is_err()
        );
        assert_eq!(
            store.project(&project.id).unwrap().unwrap().state_revision,
            Revision(1)
        );
        let conflict = DurableInput {
            producer_id: "agent-run-2".into(),
            message_id: "wake-2".into(),
            content_digest: durable_input_digest("coordinator", r#"{"kind":"reviewed"}"#),
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
        assert_eq!(claimed.operation_id, "publish-in-progress");
        store
            .finish_effect(
                "publish-in-progress",
                generation,
                EffectOutcome::Succeeded,
                Some("{}"),
            )
            .unwrap();
        let project_transition_effect = store
            .next_due_effect(generation, i64::MAX)
            .unwrap()
            .unwrap();
        assert_eq!(project_transition_effect.operation_id, "op-1");
        store
            .finish_effect("op-1", generation, EffectOutcome::Succeeded, Some("{}"))
            .unwrap();
        let other_claim = store
            .next_due_effect(generation, i64::MAX)
            .unwrap()
            .unwrap();
        assert_eq!(other_claim.operation_id, "op-other-project");
        store
            .finish_effect(
                "op-other-project",
                generation,
                EffectOutcome::Succeeded,
                Some("{}"),
            )
            .unwrap();
        let stored_receipt = store
            .succeeded_effect_receipt("op-other-project")
            .unwrap()
            .unwrap();
        assert_eq!(stored_receipt.intent().operation_id, "op-other-project");
        assert_eq!(stored_receipt.receipt_json(), "{}");
        let first_receipt = store.succeeded_effect_receipt("op-1").unwrap().unwrap();
        assert_eq!(first_receipt.intent().operation_id, "op-1");
        assert!(
            store
                .succeeded_effect_receipt("missing-operation")
                .unwrap()
                .is_none()
        );
        let new_generation = store
            .start_owner(&OwnerMetadata {
                owner_nonce: "restarted-owner".into(),
                state_root: temp.path().to_string_lossy().into_owned(),
                config_source: "factory".into(),
                process_start_identity: "new-process-start".into(),
                executable_path: "/tmp/rex-projects-test".into(),
                executable_digest: "f".repeat(64),
                rex_endpoint: None,
                rex_server_identity: None,
                rex_session_id: None,
                rex_block_id: None,
            })
            .unwrap();
        assert_eq!(new_generation, generation + 1);
        assert!(
            store
                .release_ticket_claim(new_generation, &namespace, &ticket, &other_run, 1)
                .is_err()
        );
        store
            .enqueue_ready(
                new_generation,
                &project.id,
                "payments:ticket-2:coordinator",
                "ticket",
                "ticket-2",
                "coordinator",
                "agent",
                10,
                1,
                epoch,
            )
            .unwrap();
        assert!(
            store
                .reserve_next_ready(new_generation, 1, 1, 1, 1)
                .unwrap()
                .is_none()
        );
        store
            .release_slot_after_confirmed_exit(
                new_generation,
                "agent",
                reserved.slot_index,
                &reserved.work_key,
            )
            .unwrap();
        store
            .connection
            .execute(
                "UPDATE ticket_runs SET external_status='Canceled' WHERE ticket_run_id=?1",
                [other_run.as_str()],
            )
            .unwrap();
        assert!(
            store
                .release_ticket_claim(new_generation, &namespace, &ticket, &other_run, 1)
                .unwrap()
        );
        assert!(
            store
                .reserve_next_ready(new_generation, 1, 1, 1, 1)
                .unwrap()
                .is_some()
        );
        let delayed = DurableInput {
            producer_id: "agent-run-1".into(),
            message_id: "late-result".into(),
            content_digest: durable_input_digest("coordinator", r#"{"kind":"late"}"#),
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
    fn human_claim_release_is_audited_cancels_local_run_and_requires_remote_repoll() {
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
            mode: "operations".into(),
            goal_revision: 0,
            desired_lifecycle: "running".into(),
            state_revision: Revision(0),
        };
        store.insert_project(&project).unwrap();
        let generation = store
            .start_owner(&OwnerMetadata {
                owner_nonce: "human-release-owner".into(),
                state_root: temp.path().to_string_lossy().into_owned(),
                config_source: "factory".into(),
                process_start_identity: "test-start".into(),
                executable_path: "/tmp/rex-projects-test".into(),
                executable_digest: "e".repeat(64),
                rex_endpoint: None,
                rex_server_identity: None,
                rex_session_id: None,
                rex_block_id: None,
            })
            .unwrap();
        let namespace = TicketNamespace::parse("github:org/repo").unwrap();
        let ticket = TicketId::parse("#12").unwrap();
        let run = TicketRunId::parse("payments-12-g1").unwrap();
        store
            .create_ticket_run(
                generation,
                &project.id,
                &namespace,
                &ticket,
                &run,
                1,
                "implementing",
                "In Progress",
            )
            .unwrap();
        assert!(
            store
                .claim_ticket(generation, &namespace, &ticket, &project.id, &run, 1)
                .unwrap()
        );
        let release = HumanClaimRelease {
            namespace: namespace.as_str().into(),
            ticket: ticket.as_str().into(),
            ticket_run_id: run.as_str().into(),
            generation: 1,
            expected_revision: 0,
            reason: "Human requested a clean re-triage".into(),
            disposition: "cancel".into(),
        };
        ConfigStore::append_human_claim_release(
            temp.path(),
            "human-release-1",
            &release,
            generation,
        )
        .unwrap();
        let command = store.process_next_control(generation).unwrap().unwrap();
        assert_eq!(command.kind, "human_claim_release");
        let current: (String, u64) = store
            .connection
            .query_row(
                "SELECT internal_phase,revision FROM ticket_runs WHERE ticket_run_id=?1",
                [run.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(current, ("canceled".into(), 1));
        assert!(
            store
                .claim_ticket(generation, &namespace, &ticket, &project.id, &run, 1)
                .is_err()
        );
        assert!(
            store
                .confirm_ticket_claim_repolled(
                    generation,
                    &namespace,
                    &ticket,
                    true,
                    "In Progress",
                    Some("remote-7")
                )
                .unwrap()
        );
        let next_run = TicketRunId::parse("payments-12-g2").unwrap();
        store
            .create_ticket_run(
                generation,
                &project.id,
                &namespace,
                &ticket,
                &next_run,
                2,
                "queued",
                "In Progress",
            )
            .unwrap();
        assert!(
            store
                .claim_ticket(generation, &namespace, &ticket, &project.id, &next_run, 2)
                .unwrap()
        );
        let audit: (String,String) = store.connection.query_row(
            "SELECT input_id,evidence_json FROM transitions WHERE entity_id=?1 AND new_revision=1",[run.as_str()],|row| Ok((row.get(0)?,row.get(1)?)),
        ).unwrap();
        assert_eq!(audit.0, "human-release-1");
        assert!(audit.1.contains("Human requested a clean re-triage"));
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
