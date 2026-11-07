//! Host-owned immutable registry for AgentRun artifacts.
//!
//! Files are copied and synced before the short owner-fenced SQLite transaction. A row is the
//! authority for an artifact; a path, digest, or ID supplied by an Agent is never sufficient.

#[cfg(not(unix))]
use std::fs::File;
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::path::PathBuf;

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use sha2::Digest as _;

use crate::artifacts::{ArtifactStore, VerifiedArtifact as StoredArtifact};
use crate::domain::ids::{ArtifactId, Digest, ProjectId, TicketRunId};
use crate::domain::types::Role;
use crate::engine::orchestration::{RoleArtifactKind, RoleArtifactReference};
use crate::launch::AgentLaunchAuthority;
use crate::mailbox::{MailboxCapability, MailboxRequest, unix_time_now};
use crate::protocol::{RequestId, ResponseEnvelope};

/// A registration receipt whose private fields can only be created after the host has re-read
/// and hashed the immutable object named by a durable registry row.
#[derive(Clone)]
pub struct VerifiedArtifact {
    registration: ArtifactRegistration,
}

impl VerifiedArtifact {
    pub fn reference(&self) -> &RoleArtifactReference {
        &self.registration.reference
    }
    pub fn registration(&self) -> &ArtifactRegistration {
        &self.registration
    }
    pub fn read_bytes(&self, artifact_store: &ArtifactStore) -> Result<Vec<u8>, String> {
        read_registered_object(&self.registration, artifact_store)
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactAddReceipt {
    pub schema_version: u32,
    pub message_id: String,
    pub artifact: RoleArtifactReference,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactRegistration {
    pub artifact_id: ArtifactId,
    pub project_id: ProjectId,
    pub agent_run_id: String,
    pub role: Role,
    pub role_session_id: String,
    pub ticket_run_id: Option<TicketRunId>,
    pub ticket_revision: Option<u64>,
    pub config_revision: u64,
    pub config_digest: Digest,
    pub profile_id: String,
    pub profile_digest: Digest,
    pub workspace_path: PathBuf,
    pub control_dir: PathBuf,
    pub authority_digest: Digest,
    pub message_id: String,
    pub request_digest: Digest,
    pub reference: RoleArtifactReference,
    pub object_path: PathBuf,
}

/// Apply schema v12 only after the immutable v11 operations migration.
pub fn migrate_v12(connection: &Connection) -> Result<(), String> {
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| error.to_string())?;
    if version == 12 {
        validate_v12_schema(connection)?;
        return Ok(());
    }
    if version != 11 {
        return Err(format!(
            "artifact registry migration 12 requires schema 11, found {version}"
        ));
    }
    let foreign_keys_enabled: bool = connection
        .pragma_query_value(None, "foreign_keys", |row| row.get(0))
        .map_err(|error| error.to_string())?;
    connection
        .pragma_update(None, "foreign_keys", "OFF")
        .map_err(|error| error.to_string())?;
    let migration_result = (|| {
        let tx = connection
            .unchecked_transaction()
            .map_err(|error| error.to_string())?;
        crate::launch::migrate_agent_run_role(&tx)?;
        crate::launch::migrate_launch_reservation_tables(&tx)?;
        crate::store::agent_runtime::migrate_v12_agent_wake_context(&tx)?;
        migrate_v12_artifact_tables(&tx)?;
        crate::store::agent_results::migrate_v12_tables(&tx)?;
        crate::store::accepted_plans::migrate_v12_worker_plan_tables(&tx)?;
        crate::store::agent_recovery::migrate_v12_recovery_tables(&tx)?;
        crate::store::rex_view_tables::migrate_v12_view_tables(&tx)?;
        crate::store::provider_qualification::migrate_v12_provider_qualification_jobs(&tx)?;
        crate::store::host_jobs::migrate_v12_host_jobs_tables(&tx)?;
        crate::store::human::migrate_v12_human_tables(&tx)?;
        crate::store::learning_store::migrate_v12_learning_tables(&tx)?;
        crate::store::publication_monitor::migrate_v12_publication_baselines(&tx)?;
        crate::store::merge_work::migrate_v12_merge_work_items(&tx)?;
        let violations = foreign_key_violations(&tx)?;
        if !violations.is_empty() {
            return Err(format!(
                "schema v12 migration produced foreign-key violations: {violations:?}"
            ));
        }
        let now = crate::store::now_unix()?;
        tx.execute(
            "INSERT INTO schema_migrations(version,applied_at_unix) VALUES (12,?1)",
            [now],
        )
        .map_err(|error| error.to_string())?;
        tx.pragma_update(None, "user_version", 12)
            .map_err(|error| error.to_string())?;
        validate_v12_schema(&tx)?;
        tx.commit().map_err(|error| error.to_string())
    })();
    let restore_result = connection
        .pragma_update(
            None,
            "foreign_keys",
            if foreign_keys_enabled { "ON" } else { "OFF" },
        )
        .map_err(|error| error.to_string());
    migration_result?;
    restore_result?;
    validate_v12_schema(connection)
}

fn foreign_key_violations(
    connection: &Connection,
) -> Result<Vec<(String, Option<i64>, String, i64)>, String> {
    let mut statement = connection
        .prepare("PRAGMA foreign_key_check")
        .map_err(|error| error.to_string())?;
    statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())
}

fn migrate_v12_artifact_tables(tx: &Transaction<'_>) -> Result<(), String> {
    tx.execute_batch(
        "CREATE TABLE registered_artifacts (
            artifact_id TEXT PRIMARY KEY CHECK(length(artifact_id)=64),
            project_id TEXT NOT NULL REFERENCES projects(project_id),
            agent_run_id TEXT NOT NULL REFERENCES agent_launch_authority(agent_run_id),
            role TEXT NOT NULL CHECK(role IN ('supervisor','coordinator','planner','worker','reviewer','merge_decision','operator','postmortem')),
            role_session_id TEXT NOT NULL,
            ticket_run_id TEXT REFERENCES ticket_runs(ticket_run_id),
            ticket_revision INTEGER CHECK(ticket_revision IS NULL OR ticket_revision > 0),
            config_revision INTEGER NOT NULL CHECK(config_revision > 0),
            config_digest TEXT NOT NULL CHECK(length(config_digest)=64),
            profile_id TEXT NOT NULL,
            profile_digest TEXT NOT NULL CHECK(length(profile_digest)=64),
            workspace_path TEXT NOT NULL,
            control_dir TEXT NOT NULL,
            authority_digest TEXT NOT NULL CHECK(length(authority_digest)=64),
            message_id TEXT NOT NULL,
            request_digest TEXT NOT NULL CHECK(length(request_digest)=64),
            kind TEXT NOT NULL CHECK(kind IN ('plan','change','test_receipt','review','merge_assessment','operation_receipt','postmortem','learning','general')),
            schema_version INTEGER NOT NULL CHECK(schema_version > 0),
            relative_path TEXT NOT NULL,
            content_digest TEXT NOT NULL CHECK(length(content_digest)=64),
            byte_count INTEGER NOT NULL CHECK(byte_count BETWEEN 0 AND 67108864),
            object_path TEXT NOT NULL,
            created_at_unix INTEGER NOT NULL,
            CHECK((ticket_run_id IS NULL) = (ticket_revision IS NULL))
        );
        CREATE TABLE registered_artifact_messages (
            agent_run_id TEXT NOT NULL REFERENCES agent_launch_authority(agent_run_id),
            message_id TEXT NOT NULL,
            request_digest TEXT NOT NULL CHECK(length(request_digest)=64),
            artifact_id TEXT NOT NULL REFERENCES registered_artifacts(artifact_id),
            created_at_unix INTEGER NOT NULL,
            PRIMARY KEY(agent_run_id,message_id)
        );
        CREATE TRIGGER registered_artifact_messages_immutable_update BEFORE UPDATE ON registered_artifact_messages
            BEGIN SELECT RAISE(ABORT, 'artifact message receipts are immutable'); END;
        CREATE TRIGGER registered_artifact_messages_immutable_delete BEFORE DELETE ON registered_artifact_messages
            BEGIN SELECT RAISE(ABORT, 'artifact message receipts are retained'); END;
        CREATE INDEX registered_artifacts_scope ON registered_artifacts(project_id,agent_run_id,kind,created_at_unix);
        CREATE TRIGGER registered_artifacts_immutable_update BEFORE UPDATE ON registered_artifacts
            BEGIN SELECT RAISE(ABORT, 'registered artifacts are immutable'); END;
        CREATE TRIGGER registered_artifacts_immutable_delete BEFORE DELETE ON registered_artifacts
            BEGIN SELECT RAISE(ABORT, 'registered artifacts are retained'); END;"
    ).map_err(|error| error.to_string())
}

const V12_TABLES: &[&str] = &[
    "registered_artifacts",
    "registered_artifact_messages",
    "agent_launch_reservations",
    "agent_wake_context",
    "agent_result_wakes",
    "agent_terminal_receipts",
    "agent_result_reducer_ack",
    "accepted_work_plans",
    "agent_run_adoptions",
    "agent_run_recovery_observations",
    "agent_stop_owned_runs_intents",
    "agent_stop_owned_runs_progress",
    "agent_stop_owned_runs_process_snapshots",
    "agent_stop_owned_runs_completions",
    "rex_block_archives",
    "provider_qualification_jobs",
    "host_effect_jobs",
    "human_request_authority",
    "human_requests",
    "profile_trial_authorizations",
    "profile_trial_launches",
    "profile_trial_run_receipts",
    "profile_trial_pairs",
    "publication_baselines",
    "merge_work_items",
];

#[derive(Debug, Eq, PartialEq)]
struct ColumnLayout {
    name: String,
    data_type: String,
    not_null: i64,
    default_value: Option<String>,
    primary_key_position: i64,
}

#[derive(Debug, Eq, PartialEq)]
struct ForeignKeyLayout {
    id: i64,
    sequence: i64,
    table: String,
    from: String,
    to: Option<String>,
    on_update: String,
    on_delete: String,
    match_kind: String,
}

#[derive(Debug, Eq, PartialEq)]
struct IndexColumnLayout {
    sequence: i64,
    column_id: i64,
    name: Option<String>,
    descending: i64,
    collation: String,
    is_key: i64,
}

#[derive(Debug, Eq, PartialEq)]
struct IndexLayout {
    name: String,
    unique: i64,
    origin: String,
    partial: i64,
    columns: Vec<IndexColumnLayout>,
    sql: Option<String>,
}

#[derive(Debug, Eq, PartialEq)]
struct TriggerLayout {
    name: String,
    sql: String,
}

#[derive(Debug, Eq, PartialEq)]
struct TableLayout {
    sql: String,
    columns: Vec<ColumnLayout>,
    foreign_keys: Vec<ForeignKeyLayout>,
    indexes: Vec<IndexLayout>,
    triggers: Vec<TriggerLayout>,
}

pub(crate) fn validate_v12_schema(connection: &Connection) -> Result<(), String> {
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| error.to_string())?;
    if version != 12 {
        return Err(format!(
            "artifact registry schema version mismatch: {version}"
        ));
    }
    let migration_recorded: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=12)",
            [],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    if !migration_recorded {
        return Err("schema 12 migration record is missing".into());
    }
    let canonical = canonical_v12_schema()?;
    for table in V12_TABLES {
        let actual = read_table_layout(connection, table)?;
        let expected = read_table_layout(&canonical, table)?;
        if actual != expected {
            return Err(format!(
                "schema 12 table {table} has an incompatible v12 layout"
            ));
        }
    }
    for (table, column) in [("rex_views", "terminal_at_unix"), ("agent_runs", "role")] {
        let actual = read_column_layout(connection, table, column)?;
        let expected = read_column_layout(&canonical, table, column)?;
        if actual != expected {
            return Err(format!(
                "schema 12 column {table}.{column} has an incompatible layout"
            ));
        }
    }
    let actual_agent_runs_sql: String = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='agent_runs'",
            [],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    if !actual_agent_runs_sql.contains(crate::launch::AGENT_RUN_ROLE_CHECK) {
        return Err("schema 12 agent_runs.role has an incompatible role constraint".into());
    }
    let actual_role_trigger: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='trigger' AND name='agent_runs_role_immutable'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    let expected_role_trigger: Option<String> = canonical
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='trigger' AND name='agent_runs_role_immutable'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    if actual_role_trigger.is_none() || actual_role_trigger != expected_role_trigger {
        return Err(
            "schema 12 agent_runs.role immutable trigger is missing or incompatible".into(),
        );
    }
    Ok(())
}

/// Build the expected v12 layout by replaying the same migration helpers into an isolated
/// in-memory database. This keeps startup validation tied to the DDL that creates the schema.
fn canonical_v12_schema() -> Result<Connection, String> {
    let mut canonical = Connection::open_in_memory().map_err(|error| error.to_string())?;
    canonical
        .execute_batch(
            "CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY,applied_at_unix INTEGER NOT NULL);
             CREATE TABLE projects(project_id TEXT PRIMARY KEY);
             CREATE TABLE ticket_runs(ticket_run_id TEXT PRIMARY KEY,project_id TEXT);
             CREATE TABLE agent_launch_authority(agent_run_id TEXT PRIMARY KEY);
             CREATE TABLE agent_runs(agent_run_id TEXT PRIMARY KEY,project_id TEXT,role_session_id TEXT);
             CREATE TABLE rex_views(view_id TEXT PRIMARY KEY);
             CREATE TABLE rex_view_blocks(view_id TEXT NOT NULL,block_id TEXT NOT NULL,PRIMARY KEY(view_id,block_id));
             CREATE TABLE controller_owners(singleton INTEGER PRIMARY KEY);
             CREATE TABLE agent_result_evidence(evidence_id TEXT PRIMARY KEY);
             CREATE TABLE role_wake_inputs(wake_input_id INTEGER PRIMARY KEY);
             CREATE TABLE agent_result_wakes(
                 evidence_id TEXT PRIMARY KEY,
                 recipient_type TEXT NOT NULL,
                 recipient_id TEXT NOT NULL,
                 wake_input_id INTEGER,
                 queued_at_unix INTEGER NOT NULL
             );",
        )
        .map_err(|error| error.to_string())?;
    {
        let tx = canonical.transaction().map_err(|error| error.to_string())?;
        crate::launch::migrate_agent_run_role(&tx)?;
        crate::launch::migrate_launch_reservation_tables(&tx)?;
        crate::store::agent_runtime::migrate_v12_agent_wake_context(&tx)?;
        tx.commit().map_err(|error| error.to_string())?;
    }
    crate::store::human::create_human_requests_table(&canonical, "human_requests", false)?;
    crate::store::human::create_human_request_indexes(&canonical)?;
    let tx = canonical.transaction().map_err(|error| error.to_string())?;
    migrate_v12_artifact_tables(&tx)?;
    crate::store::agent_results::migrate_v12_tables(&tx)?;
    crate::store::accepted_plans::migrate_v12_worker_plan_tables(&tx)?;
    crate::store::agent_recovery::migrate_v12_recovery_tables(&tx)?;
    crate::store::rex_view_tables::migrate_v12_view_tables(&tx)?;
    crate::store::provider_qualification::migrate_v12_provider_qualification_jobs(&tx)?;
    crate::store::host_jobs::migrate_v12_host_jobs_tables(&tx)?;
    crate::store::human::migrate_v12_human_tables(&tx)?;
    crate::store::learning_store::migrate_v12_learning_tables(&tx)?;
    crate::store::publication_monitor::migrate_v12_publication_baselines(&tx)?;
    crate::store::merge_work::migrate_v12_merge_work_items(&tx)?;
    tx.commit().map_err(|error| error.to_string())?;
    Ok(canonical)
}

fn read_column_layout(
    connection: &Connection,
    table: &str,
    column: &str,
) -> Result<Option<ColumnLayout>, String> {
    Ok(read_table_layout(connection, table)?
        .columns
        .into_iter()
        .find(|layout| layout.name == column))
}

fn read_table_layout(connection: &Connection, table: &str) -> Result<TableLayout, String> {
    let sql: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name=?1",
            [table],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    let sql = sql.ok_or_else(|| format!("schema 12 is missing table {table}"))?;

    let mut statement = connection
        .prepare(
            "SELECT name,type,\"notnull\",dflt_value,pk FROM pragma_table_info(?1) ORDER BY cid",
        )
        .map_err(|error| error.to_string())?;
    let columns = statement
        .query_map([table], |row| {
            Ok(ColumnLayout {
                name: row.get(0)?,
                data_type: row.get(1)?,
                not_null: row.get(2)?,
                default_value: row.get(3)?,
                primary_key_position: row.get(4)?,
            })
        })
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;

    let mut statement = connection
        .prepare("SELECT id,seq,\"table\",\"from\",\"to\",on_update,on_delete,\"match\" FROM pragma_foreign_key_list(?1) ORDER BY id,seq")
        .map_err(|error| error.to_string())?;
    let foreign_keys = statement
        .query_map([table], |row| {
            Ok(ForeignKeyLayout {
                id: row.get(0)?,
                sequence: row.get(1)?,
                table: row.get(2)?,
                from: row.get(3)?,
                to: row.get(4)?,
                on_update: row.get(5)?,
                on_delete: row.get(6)?,
                match_kind: row.get(7)?,
            })
        })
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;

    let mut statement = connection
        .prepare("SELECT name,\"unique\",origin,partial FROM pragma_index_list(?1) ORDER BY name")
        .map_err(|error| error.to_string())?;
    let index_rows = statement
        .query_map([table], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    let mut indexes = Vec::with_capacity(index_rows.len());
    for (name, unique, origin, partial) in index_rows {
        let mut index_statement = connection
            .prepare("SELECT seqno,cid,name,\"desc\",coll,\"key\" FROM pragma_index_xinfo(?1) ORDER BY seqno")
            .map_err(|error| error.to_string())?;
        let columns = index_statement
            .query_map([&name], |row| {
                Ok(IndexColumnLayout {
                    sequence: row.get(0)?,
                    column_id: row.get(1)?,
                    name: row.get(2)?,
                    descending: row.get(3)?,
                    collation: row.get(4)?,
                    is_key: row.get(5)?,
                })
            })
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        let index_sql = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='index' AND name=?1",
                [&name],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()
            .map_err(|error| error.to_string())?
            .flatten();
        indexes.push(IndexLayout {
            name,
            unique,
            origin,
            partial,
            columns,
            sql: index_sql,
        });
    }

    let mut statement = connection
        .prepare(
            "SELECT name,sql FROM sqlite_master WHERE type='trigger' AND tbl_name=?1 ORDER BY name",
        )
        .map_err(|error| error.to_string())?;
    let triggers = statement
        .query_map([table], |row| {
            Ok(TriggerLayout {
                name: row.get(0)?,
                sql: row.get(1)?,
            })
        })
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    Ok(TableLayout {
        sql,
        columns,
        foreign_keys,
        indexes,
        triggers,
    })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use rusqlite::Connection;

    use super::lookup_registered_artifact_tx;
    use super::{ArtifactRegistration, migrate_v12, verify_registered_object};
    use crate::artifacts::ArtifactStore;
    use crate::domain::ids::{
        AgentRunId, ArtifactId, Digest, OperationId, ProfileId, ProjectId, Revision, TicketRunId,
    };
    use crate::domain::types::Role;
    use crate::engine::orchestration::RoleArtifactKind;
    use crate::engine::orchestration::RoleArtifactReference;
    use crate::launch::AgentLaunchAuthority;
    use crate::mailbox::{MailboxCapability, unix_time_now};

    #[test]
    fn schema_v12_adds_immutable_artifact_registry_and_message_receipts() {
        let connection = Connection::open_in_memory().unwrap();
        connection.execute_batch(
            "CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY,applied_at_unix INTEGER NOT NULL);
             CREATE TABLE projects(project_id TEXT PRIMARY KEY);
             CREATE TABLE ticket_runs(ticket_run_id TEXT PRIMARY KEY);
             CREATE TABLE agent_runs(agent_run_id TEXT PRIMARY KEY,project_id TEXT,role_session_id TEXT);
             CREATE TABLE rex_views(view_id TEXT PRIMARY KEY);
             CREATE TABLE rex_view_blocks(view_id TEXT NOT NULL,block_id TEXT NOT NULL,PRIMARY KEY(view_id,block_id));
             CREATE TABLE agent_launch_authority(agent_run_id TEXT PRIMARY KEY);
             CREATE TABLE agent_result_evidence(evidence_id TEXT PRIMARY KEY);
             CREATE TABLE role_wake_inputs(wake_input_id INTEGER PRIMARY KEY);
             CREATE TABLE agent_result_wakes(evidence_id TEXT PRIMARY KEY,recipient_type TEXT NOT NULL,recipient_id TEXT NOT NULL,wake_input_id INTEGER,queued_at_unix INTEGER NOT NULL);
             PRAGMA foreign_keys=ON;
             PRAGMA user_version=11;",
        ).unwrap();
        crate::store::human::create_human_requests_table(&connection, "human_requests", false)
            .unwrap();
        crate::store::human::create_human_request_indexes(&connection).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE human_request_history(
                history_id INTEGER PRIMARY KEY,
                request_id TEXT NOT NULL REFERENCES human_requests(request_id)
             );
             INSERT INTO projects(project_id) VALUES ('project1');
             INSERT INTO rex_views(view_id) VALUES ('view1');
             INSERT INTO agent_runs(agent_run_id,project_id,role_session_id) VALUES ('run1','project1','worker-session');
             INSERT INTO agent_launch_authority(agent_run_id) VALUES ('run1');
             INSERT INTO human_requests(
                request_id,project_id,purpose,subject_kind,subject_id,subject_revision,rex_view_id,
                subject_digest,material_digest,configuration_digest,policy_digest,bundle_digest,
                request_json,artifact_path,presentation_reference,lifecycle,created_at_unix,
                expires_at_unix,decided_at_unix
             ) VALUES (
                'request1','project1','release_decision','release','release1',1,'view1',
                'subject','material','configuration','policy','bundle','{}','artifact',NULL,
                'pending',1,2,NULL
             );
             INSERT INTO human_request_history(request_id) VALUES ('request1');",
            )
            .unwrap();
        let legacy_payload = r#"{"kind":"start"}"#;
        let legacy_inputs = serde_json::json!([{
            "wake_input_id": 1,
            "source_type": "test",
            "source_id": "event1",
            "source_revision": 1,
            "priority": 9,
            "payload_json": legacy_payload,
        }]);
        let legacy_digest_material = serde_json::to_string(&serde_json::json!({
            "project_id": "project1",
            "role_session_id": "worker-session",
            "agent_run_id": "run1",
            "inputs": legacy_inputs,
        }))
        .unwrap();
        let legacy_digest = crate::store::content_digest(&legacy_digest_material);
        let legacy_context = serde_json::to_string(&serde_json::json!({
            "project_id": "project1",
            "role_session_id": "worker-session",
            "agent_run_id": "run1",
            "inputs": legacy_inputs,
            "digest": legacy_digest,
        }))
        .unwrap();
        let legacy_context_digest = crate::store::content_digest(&legacy_context);
        connection
            .execute_batch(
                "CREATE TABLE agent_wake_context(
                    agent_run_id TEXT PRIMARY KEY REFERENCES agent_runs(agent_run_id),
                    context_json TEXT NOT NULL CHECK(length(context_json) <= 1048576),
                    context_digest TEXT NOT NULL CHECK(length(context_digest)=64),
                    assigned_at_unix INTEGER NOT NULL
                 );",
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO agent_wake_context(agent_run_id,context_json,context_digest,assigned_at_unix) VALUES ('run1',?1,?2,123)",
                rusqlite::params![legacy_context, legacy_context_digest],
            )
            .unwrap();
        migrate_v12(&connection).unwrap();
        let foreign_keys_enabled: bool = connection
            .pragma_query_value(None, "foreign_keys", |row| row.get(0))
            .unwrap();
        assert!(
            foreign_keys_enabled,
            "migration restores the original FK setting"
        );
        let legacy_role: Option<String> = connection
            .query_row(
                "SELECT role FROM agent_runs WHERE agent_run_id='run1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            legacy_role, None,
            "migration does not infer legacy AgentRun role"
        );
        assert!(
            connection
                .execute(
                    "UPDATE agent_runs SET role='worker' WHERE agent_run_id='run1'",
                    [],
                )
                .is_err(),
            "legacy NULL role remains immutable"
        );
        assert!(
            connection
                .execute(
                    "INSERT INTO agent_runs(agent_run_id,role) VALUES ('invalid-role','unknown_role')",
                    [],
                )
                .is_err(),
            "AgentRun role CHECK accepts only known typed roles"
        );
        let preserved: (String, String, String) = connection
            .query_row(
                "SELECT request_id,purpose,subject_kind FROM human_requests",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            preserved,
            (
                "request1".into(),
                "release_decision".into(),
                "release".into()
            )
        );
        connection
            .execute(
                "INSERT INTO human_requests(
                    request_id,project_id,purpose,subject_kind,subject_id,subject_revision,rex_view_id,
                    subject_digest,material_digest,configuration_digest,policy_digest,bundle_digest,
                    request_json,artifact_path,presentation_reference,lifecycle,created_at_unix,
                    expires_at_unix,decided_at_unix
                 ) VALUES (
                    'publication1','project1','publication_adoption','publication','publication1',1,'view1',
                    'subject','material','configuration','policy','bundle','{}','artifact',NULL,
                    'pending',2,3,NULL
                 )",
                [],
            )
            .unwrap();
        let history_count: u64 = connection
            .query_row("SELECT COUNT(*) FROM human_request_history", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(history_count, 1, "human history rows survive table rebuild");
        let child_fk_preserved: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM pragma_foreign_key_list('human_request_history') WHERE \"table\"='human_requests' AND \"from\"='request_id' AND \"to\"='request_id')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            child_fk_preserved,
            "child foreign key still points at human_requests"
        );
        let index_preserved: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM pragma_index_list('human_requests') WHERE name='human_requests_subject')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(index_preserved, "human request index is recreated");
        let (wake_digest, wake_json, created_at): (String, String, i64) = connection
            .query_row(
                "SELECT snapshot_digest,snapshot_json,created_at_unix FROM agent_wake_context WHERE agent_run_id='run1'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        let wake: crate::agent_api::AgentWakeSnapshot =
            crate::protocol::parse_unique(wake_json.as_bytes()).unwrap();
        wake.validate().unwrap();
        assert_eq!(wake.digest.as_str(), wake_digest);
        assert_eq!(wake.inputs[0].priority, 9);
        assert_eq!(
            wake.inputs[0].payload_json,
            serde_json::json!({"kind":"start"})
        );
        assert_eq!(created_at, 123, "legacy wake assignment time is preserved");
        let version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, 12);
        for table in [
            "registered_artifacts",
            "agent_launch_reservations",
            "agent_wake_context",
            "registered_artifact_messages",
            "agent_terminal_receipts",
            "agent_result_reducer_ack",
            "accepted_work_plans",
            "agent_run_adoptions",
            "agent_run_recovery_observations",
            "agent_stop_owned_runs_intents",
            "agent_stop_owned_runs_progress",
            "agent_stop_owned_runs_process_snapshots",
            "agent_stop_owned_runs_completions",
            "rex_block_archives",
            "provider_qualification_jobs",
            "host_effect_jobs",
            "human_request_authority",
            "profile_trial_authorizations",
            "profile_trial_launches",
            "profile_trial_run_receipts",
            "profile_trial_pairs",
            "publication_baselines",
            "merge_work_items",
        ] {
            let found: bool = connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
                    [table],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(found, "{table} table is missing");
        }
        assert!(
            migrate_v12(&connection).is_ok(),
            "schema 12 migration is idempotent"
        );
        assert!(
            connection
                .query_row(
                    "SELECT 1 FROM pragma_table_info('rex_views') WHERE name='terminal_at_unix'",
                    [],
                    |_| Ok(())
                )
                .is_ok(),
            "Rex view terminal column is missing"
        );
        assert!(
            connection.query_row("SELECT 1 FROM pragma_table_info('agent_result_wakes') WHERE name='wake_input_id'", [], |_| Ok(())).is_ok(),
            "result wake input column is missing"
        );
        let digest = "a".repeat(64);
        connection
            .execute(
                "INSERT INTO provider_qualification_jobs(request_id,project_id,role,profile_id,profile_digest,config_revision,config_digest,request_digest,status,controller_generation,created_at_unix,updated_at_unix) VALUES ('qualification1','project1','worker','worker',?1,1,?1,?1,'running',1,1,1)",
                [&digest],
            )
            .unwrap();
        connection
            .execute(
                "UPDATE provider_qualification_jobs SET status='unknown' WHERE request_id='qualification1'",
                [],
            )
            .unwrap();
        assert!(connection
            .execute(
                "UPDATE provider_qualification_jobs SET status='queued' WHERE request_id='qualification1'",
                [],
            )
            .is_err());
        connection
            .execute(
                "UPDATE provider_qualification_jobs SET status='verified',result_json='{}',evidence_digest=?1 WHERE request_id='qualification1'",
                [&digest],
            )
            .unwrap();
        assert!(connection
            .execute(
                "UPDATE provider_qualification_jobs SET status='failed' WHERE request_id='qualification1'",
                [],
            )
            .is_err());
        connection.execute(
            "INSERT INTO registered_artifacts(artifact_id,project_id,agent_run_id,role,role_session_id,ticket_run_id,ticket_revision,config_revision,config_digest,profile_id,profile_digest,workspace_path,control_dir,authority_digest,message_id,request_digest,kind,schema_version,relative_path,content_digest,byte_count,object_path,created_at_unix) VALUES (?1,'project1','run1','worker','session',NULL,NULL,1,?2,'worker',?2,'/workspace','/control',?2,'message1',?2,'general',1,'sha256/aa/object',?2,0,'/store/object',1)",
            rusqlite::params![digest, digest],
        ).unwrap();
        connection.execute(
            "INSERT INTO registered_artifact_messages(agent_run_id,message_id,request_digest,artifact_id,created_at_unix) VALUES ('run1','message1',?1,?2,1)",
            rusqlite::params![digest, digest],
        ).unwrap();
        assert!(
            connection
                .execute("UPDATE registered_artifacts SET artifact_id='x'", [])
                .is_err()
        );
        assert!(
            connection
                .execute("DELETE FROM registered_artifacts", [])
                .is_err()
        );
        assert!(
            connection
                .execute("UPDATE registered_artifact_messages SET message_id='x'", [])
                .is_err()
        );
        assert!(
            connection
                .execute("DELETE FROM registered_artifact_messages", [])
                .is_err()
        );
    }

    #[test]
    fn schema_v12_rejects_out_of_order_migration_without_mutation() {
        let connection = Connection::open_in_memory().unwrap();
        connection.pragma_update(None, "user_version", 10).unwrap();
        assert!(migrate_v12(&connection).is_err());
        let version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, 10);
    }

    #[test]
    fn fresh_v12_migration_composes_helpers_and_reopens_without_schema_changes() {
        let temp = tempfile::tempdir().unwrap();
        let store = crate::store::ConfigStore::open_test(temp.path()).unwrap();
        let version: i64 = store
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, 12);
        for table in [
            "registered_artifacts",
            "agent_terminal_receipts",
            "accepted_work_plans",
            "agent_run_adoptions",
            "rex_block_archives",
            "provider_qualification_jobs",
            "host_effect_jobs",
            "human_request_authority",
            "profile_trial_authorizations",
            "publication_baselines",
            "merge_work_items",
        ] {
            let found: bool = store
                .connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
                    [table],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(found, "schema v12 is missing {table}");
        }
        drop(store);

        let reopened = crate::store::ConfigStore::open_test(temp.path()).unwrap();
        let version: i64 = reopened
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, 12);
        super::validate_v12_schema(&reopened.connection).unwrap();
    }

    #[test]
    fn claimed_v12_layout_is_rejected_before_database_journal_changes() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("state.sqlite3");
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch("PRAGMA journal_mode=DELETE; PRAGMA user_version=12;")
            .unwrap();
        drop(connection);

        assert!(crate::store::ConfigStore::open_test(temp.path()).is_err());
        let connection = Connection::open(path).unwrap();
        let journal_mode: String = connection
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .unwrap();
        assert_eq!(journal_mode, "delete");
        let version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, 12);
    }

    #[test]
    fn malformed_same_name_v12_table_is_rejected_before_wal() {
        let temp = tempfile::tempdir().unwrap();
        let store = crate::store::ConfigStore::open_test(temp.path()).unwrap();
        drop(store);

        let path = temp.path().join("state.sqlite3");
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "PRAGMA foreign_keys=OFF;
                 PRAGMA journal_mode=DELETE;
                 DROP TABLE publication_baselines;
                 CREATE TABLE publication_baselines(project_id TEXT);",
            )
            .unwrap();
        drop(connection);

        let error = crate::store::ConfigStore::open_test(temp.path())
            .err()
            .expect("malformed schema must be rejected");
        assert!(error.contains("publication_baselines"), "{error}");
        let connection = Connection::open(path).unwrap();
        let journal_mode: String = connection
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .unwrap();
        assert_eq!(journal_mode, "delete");
        let version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, 12);
    }

    #[test]
    fn valid_v10_database_migrates_to_v12_and_reopens() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("state.sqlite3");
        let mut connection = Connection::open(&path).unwrap();
        connection.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
        crate::store::ConfigStore::migrate(&connection, 0, temp.path()).unwrap();
        crate::store::migrate_v3(&connection).unwrap();
        crate::store::migrate_v4(&connection).unwrap();
        crate::store::migrate_v5(&connection).unwrap();
        crate::store::migrate_v6(&connection).unwrap();
        crate::launch::migrate_v7(&mut connection).unwrap();
        crate::store::ConfigStore::migrate_human_v8(&mut connection).unwrap();
        crate::store::scheduler::migrate_v9(&connection).unwrap();
        crate::store::learning_store::migrate_v10(&connection).unwrap();
        let version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, 10);
        crate::store::learning_store::validate_v10_schema(&connection).unwrap();
        drop(connection);

        let store = crate::store::ConfigStore::open_test(temp.path()).unwrap();
        let version: i64 = store
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, 12);
        super::validate_v12_schema(&store.connection).unwrap();
    }

    fn test_authority() -> AgentLaunchAuthority {
        let digest = |byte: char| Digest::parse(byte.to_string().repeat(64)).unwrap();
        AgentLaunchAuthority {
            agent_run_id: AgentRunId::parse("run1").unwrap(),
            project_id: ProjectId::parse("project1").unwrap(),
            role: Role::Worker,
            role_session_id: "worker-session".into(),
            parent_run_id: Some(AgentRunId::parse("coordinator1").unwrap()),
            parent_role: Some(Role::Coordinator),
            ticket_run_id: Some(TicketRunId::parse("ticket1").unwrap()),
            ticket_revision: Some(Revision(2)),
            config_revision: Revision(3),
            config_digest: digest('a'),
            wake_snapshot_digest: digest('5'),
            attempt: 1,
            run_epoch: 2,
            controller_generation: 4,
            operation_id: OperationId::parse("operation1").unwrap(),
            operation_recipe_id: None,
            rex_view_id: digest('b'),
            descriptor_digest: digest('c'),
            runtime_binary_digest: digest('d'),
            descriptor_path: "/state/run1/descriptor.json".into(),
            environment_snapshot_id: digest('e'),
            profile_id: ProfileId::parse("worker").unwrap(),
            profile_digest: digest('f'),
            instruction_digest: digest('1'),
            result_schema_digest: digest('2'),
            qualification_receipt_digest: digest('3'),
            rex_server_identity: "rex1".into(),
            rex_session_id: "session1".into(),
            rex_window_id: "window1".into(),
            rex_block_id: "block1".into(),
            workspace_path: "/state/run1/workspace".into(),
            control_dir: "/state/run1/control".into(),
            mailbox_capability_digest: digest('4'),
        }
    }

    fn lookup_fixture(
        kind: RoleArtifactKind,
    ) -> (Connection, AgentLaunchAuthority, RoleArtifactReference) {
        let connection = Connection::open_in_memory().unwrap();
        connection.execute_batch(
            "CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY,applied_at_unix INTEGER NOT NULL);
             CREATE TABLE projects(project_id TEXT PRIMARY KEY);
             CREATE TABLE ticket_runs(ticket_run_id TEXT PRIMARY KEY);
             CREATE TABLE agent_runs(agent_run_id TEXT PRIMARY KEY);
             CREATE TABLE rex_views(view_id TEXT PRIMARY KEY);
             CREATE TABLE rex_view_blocks(view_id TEXT NOT NULL,block_id TEXT NOT NULL,PRIMARY KEY(view_id,block_id));
             CREATE TABLE agent_launch_authority(agent_run_id TEXT PRIMARY KEY,authority_json TEXT NOT NULL,authority_digest TEXT NOT NULL);
             CREATE TABLE agent_result_evidence(evidence_id TEXT PRIMARY KEY);
             CREATE TABLE role_wake_inputs(wake_input_id INTEGER PRIMARY KEY);
             CREATE TABLE agent_result_wakes(evidence_id TEXT PRIMARY KEY,recipient_type TEXT NOT NULL,recipient_id TEXT NOT NULL,wake_input_id INTEGER,queued_at_unix INTEGER NOT NULL);
             PRAGMA user_version=11;",
        ).unwrap();
        crate::store::human::create_human_requests_table(&connection, "human_requests", false)
            .unwrap();
        crate::store::human::create_human_request_indexes(&connection).unwrap();
        super::migrate_v12(&connection).unwrap();
        let authority = test_authority();
        authority.validate().unwrap();
        let authority_json = serde_json::to_string(&authority).unwrap();
        let authority_digest = authority.digest().unwrap();
        connection.execute(
            "INSERT INTO agent_launch_authority(agent_run_id,authority_json,authority_digest) VALUES (?1,?2,?3)",
            rusqlite::params![authority.agent_run_id.as_str(), authority_json, authority_digest.as_str()],
        ).unwrap();
        connection
            .execute(
                "INSERT INTO projects(project_id) VALUES (?1)",
                [authority.project_id.as_str()],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO ticket_runs(ticket_run_id) VALUES (?1)",
                [authority.ticket_run_id.as_ref().unwrap().as_str()],
            )
            .unwrap();
        let digest = Digest::parse("5".repeat(64)).unwrap();
        let artifact_id = ArtifactId::from_registration_identity(
            &authority.project_id,
            &authority.agent_run_id,
            kind.as_str(),
            1,
            &digest,
        )
        .unwrap();
        let artifact_id_text = artifact_id.to_string();
        let reference = RoleArtifactReference {
            artifact_id,
            kind,
            schema_version: 1,
            path: format!("sha256/{}/{}", &artifact_id_text[..2], artifact_id_text),
            digest: digest.clone(),
            bytes: 5,
        };
        connection.execute(
            "INSERT INTO registered_artifacts(artifact_id,project_id,agent_run_id,role,role_session_id,ticket_run_id,ticket_revision,config_revision,config_digest,profile_id,profile_digest,workspace_path,control_dir,authority_digest,message_id,request_digest,kind,schema_version,relative_path,content_digest,byte_count,object_path,created_at_unix) VALUES (?1,?2,?3,'worker',?4,'ticket1',2,3,?5,'worker',?6,?7,?8,?9,'message1',?10,?11,1,?12,?13,5,'/artifact-store/object',1)",
            rusqlite::params![reference.artifact_id.as_str(), authority.project_id.as_str(), authority.agent_run_id.as_str(), authority.role_session_id, authority.config_digest.as_str(), authority.profile_digest.as_str(), authority.workspace_path.to_string_lossy(), authority.control_dir.to_string_lossy(), authority_digest.as_str(), "6".repeat(64), kind.as_str(), reference.path, digest.as_str()],
        ).unwrap();
        (connection, authority, reference)
    }

    #[test]
    fn registry_transaction_lookup_matches_exact_reference_and_authority_scope() {
        let (mut connection, authority, reference) = lookup_fixture(RoleArtifactKind::Change);
        let tx = connection.transaction().unwrap();
        let found = lookup_registered_artifact_tx(&tx, &authority, &reference)
            .unwrap()
            .unwrap();
        assert_eq!(found.reference, reference);
        assert_eq!(found.workspace_path, authority.workspace_path);
        assert_eq!(found.control_dir, authority.control_dir);
        drop(tx);

        let (mut connection, authority, reference) = lookup_fixture(RoleArtifactKind::Change);
        let mut mismatch = reference.clone();
        mismatch.bytes += 1;
        let tx = connection.transaction().unwrap();
        assert!(lookup_registered_artifact_tx(&tx, &authority, &mismatch).is_err());
        drop(tx);

        let (mut connection, authority, reference) = lookup_fixture(RoleArtifactKind::Change);
        let mut wrong_scope = authority.clone();
        wrong_scope.profile_digest = Digest::parse("0".repeat(64)).unwrap();
        let tx = connection.transaction().unwrap();
        assert!(
            lookup_registered_artifact_tx(&tx, &wrong_scope, &reference)
                .unwrap()
                .is_none()
        );
        drop(tx);
    }

    #[test]
    fn registry_rejects_a_kind_outside_the_agent_role() {
        let (mut connection, authority, reference) = lookup_fixture(RoleArtifactKind::Plan);
        let tx = connection.transaction().unwrap();
        assert!(lookup_registered_artifact_tx(&tx, &authority, &reference).is_err());
    }

    #[test]
    fn artifact_add_ack_waits_for_durable_registry_commit_and_replay_converges() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = temp.path().join("workspace");
        let control_dir = workspace.join(".rex-projects-control");
        fs::create_dir_all(&control_dir).unwrap();
        fs::write(workspace.join("change.diff"), b"verified diff\n").unwrap();
        let mut authority = test_authority();
        authority.workspace_path = fs::canonicalize(&workspace).unwrap();
        authority.control_dir = fs::canonicalize(&control_dir).unwrap();

        let connection = Connection::open_in_memory().unwrap();
        connection.execute_batch(
            "CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY,applied_at_unix INTEGER NOT NULL);
             CREATE TABLE projects(project_id TEXT PRIMARY KEY);
             CREATE TABLE ticket_runs(ticket_run_id TEXT PRIMARY KEY);
             CREATE TABLE agent_runs(agent_run_id TEXT PRIMARY KEY);
             CREATE TABLE rex_views(view_id TEXT PRIMARY KEY);
             CREATE TABLE rex_view_blocks(view_id TEXT NOT NULL,block_id TEXT NOT NULL,PRIMARY KEY(view_id,block_id));
             CREATE TABLE agent_launch_authority(agent_run_id TEXT PRIMARY KEY,authority_json TEXT NOT NULL,authority_digest TEXT NOT NULL);
             CREATE TABLE controller_owners(singleton INTEGER PRIMARY KEY,generation INTEGER NOT NULL,stopped_at_unix INTEGER);
             INSERT INTO controller_owners VALUES (1,4,NULL);
             CREATE TABLE agent_result_evidence(evidence_id TEXT PRIMARY KEY);
             CREATE TABLE role_wake_inputs(wake_input_id INTEGER PRIMARY KEY);
             CREATE TABLE agent_result_wakes(evidence_id TEXT PRIMARY KEY,recipient_type TEXT NOT NULL,recipient_id TEXT NOT NULL,wake_input_id INTEGER,queued_at_unix INTEGER NOT NULL);
             PRAGMA user_version=11;",
        ).unwrap();
        crate::store::human::create_human_requests_table(&connection, "human_requests", false)
            .unwrap();
        crate::store::human::create_human_request_indexes(&connection).unwrap();
        connection
            .execute(
                "INSERT INTO projects(project_id) VALUES (?1)",
                [authority.project_id.as_str()],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO ticket_runs(ticket_run_id) VALUES (?1)",
                [authority.ticket_run_id.as_ref().unwrap().as_str()],
            )
            .unwrap();
        let authority_json = serde_json::to_string(&authority).unwrap();
        let authority_digest = authority.digest().unwrap();
        connection.execute(
            "INSERT INTO agent_launch_authority(agent_run_id,authority_json,authority_digest) VALUES (?1,?2,?3)",
            rusqlite::params![authority.agent_run_id.as_str(), authority_json, authority_digest.as_str()],
        ).unwrap();
        migrate_v12(&connection).unwrap();
        let mut store = crate::store::ConfigStore {
            connection,
            _machine_lock: crate::store::MachineLock { _file: None },
        };

        let now = unix_time_now().unwrap();
        let mailbox_dir = authority.control_dir.join("mailbox");
        let mailbox = MailboxCapability::create(
            authority.agent_run_id.as_str(),
            &mailbox_dir,
            now + 600,
            crate::mailbox::MailboxLimits::default(),
        )
        .unwrap();
        let artifact_store = ArtifactStore::open(&temp.path().join("artifact-store")).unwrap();
        let request = crate::engine::orchestration::ArtifactAddRequest {
            schema_version: 1,
            message_id: "message1".into(),
            path: "change.diff".into(),
            kind: RoleArtifactKind::Change,
            artifact_schema_version: 1,
        };
        let envelope = serde_json::json!({
            "schema_version": 1,
            "request_id": "message1",
            "operation_id": authority.operation_id,
            "method": "artifact.add",
            "project_id": authority.project_id,
            "run_id": authority.agent_run_id,
            "attempt": authority.attempt,
            "run_epoch": authority.run_epoch,
            "role": authority.role,
            "params": request,
        });
        mailbox
            .queue("message1", &serde_json::to_vec(&envelope).unwrap(), now)
            .unwrap();
        let mailbox_request = mailbox.pending(now).unwrap().pop().unwrap();

        assert!(
            store
                .process_artifact_add(
                    5,
                    &authority,
                    &artifact_store,
                    &mailbox,
                    &mailbox_request,
                    &request,
                )
                .is_err()
        );
        assert!(mailbox.read_receipt("message1", now).unwrap().is_none());
        let count: u64 = store
            .connection
            .query_row("SELECT COUNT(*) FROM registered_artifacts", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0);

        let verified = store
            .process_artifact_add(
                4,
                &authority,
                &artifact_store,
                &mailbox,
                &mailbox_request,
                &request,
            )
            .unwrap();
        let replayed = store
            .process_artifact_add(
                4,
                &authority,
                &artifact_store,
                &mailbox,
                &mailbox_request,
                &request,
            )
            .unwrap();
        assert_eq!(replayed.reference(), verified.reference());
        let reopened_artifact_store =
            ArtifactStore::open(&temp.path().join("artifact-store")).unwrap();
        assert_eq!(
            verified.read_bytes(&reopened_artifact_store).unwrap(),
            b"verified diff\n"
        );
        let persisted = store
            .lookup_verified_artifact(&reopened_artifact_store, &authority, verified.reference())
            .unwrap()
            .unwrap();
        assert_eq!(
            persisted.read_bytes(&reopened_artifact_store).unwrap(),
            b"verified diff\n"
        );
        let parent_workspace = temp.path().join("parent-workspace");
        fs::create_dir(&parent_workspace).unwrap();
        let evidence_id = "e".repeat(64);
        let staged = crate::parent_artifacts::stage_verified_parent_artifacts(
            &mut store,
            &reopened_artifact_store,
            &authority,
            &evidence_id,
            &authority.project_id,
            authority.config_revision.0,
            &authority.config_digest,
            &parent_workspace,
            &[verified.reference().clone()],
        )
        .unwrap();
        assert_eq!(staged.len(), 1);
        assert_eq!(
            fs::read(parent_workspace.join(&staged[0].path)).unwrap(),
            b"verified diff\n"
        );
        assert_eq!(
            staged,
            crate::parent_artifacts::stage_verified_parent_artifacts(
                &mut store,
                &reopened_artifact_store,
                &authority,
                &evidence_id,
                &authority.project_id,
                authority.config_revision.0,
                &authority.config_digest,
                &parent_workspace,
                &[verified.reference().clone()],
            )
            .unwrap()
        );
        let staged_file = parent_workspace.join(&staged[0].path);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&staged_file, fs::Permissions::from_mode(0o644)).unwrap();
        }
        fs::write(&staged_file, b"changed diff!\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&staged_file, fs::Permissions::from_mode(0o444)).unwrap();
        }
        let different_content_error = crate::parent_artifacts::stage_verified_parent_artifacts(
            &mut store,
            &reopened_artifact_store,
            &authority,
            &evidence_id,
            &authority.project_id,
            authority.config_revision.0,
            &authority.config_digest,
            &parent_workspace,
            &[verified.reference().clone()],
        )
        .unwrap_err();
        assert!(
            different_content_error.contains("different content"),
            "{different_content_error}"
        );

        let mut wrong_source = authority.clone();
        wrong_source.agent_run_id = AgentRunId::parse("other-run").unwrap();
        assert!(
            crate::parent_artifacts::stage_verified_parent_artifacts(
                &mut store,
                &reopened_artifact_store,
                &wrong_source,
                &evidence_id,
                &authority.project_id,
                authority.config_revision.0,
                &authority.config_digest,
                &parent_workspace,
                &[verified.reference().clone()],
            )
            .is_err()
        );
        assert!(
            crate::parent_artifacts::stage_verified_parent_artifacts(
                &mut store,
                &reopened_artifact_store,
                &authority,
                &evidence_id,
                &authority.project_id,
                authority.config_revision.0 + 1,
                &authority.config_digest,
                &parent_workspace,
                &[verified.reference().clone()],
            )
            .is_err()
        );
        let mut wrong_reference = verified.reference().clone();
        wrong_reference.digest = Digest::parse("0".repeat(64)).unwrap();
        assert!(
            crate::parent_artifacts::stage_verified_parent_artifacts(
                &mut store,
                &reopened_artifact_store,
                &authority,
                &evidence_id,
                &authority.project_id,
                authority.config_revision.0,
                &authority.config_digest,
                &parent_workspace,
                &[wrong_reference],
            )
            .is_err()
        );

        let mut oversized = verified.reference().clone();
        oversized.artifact_id = ArtifactId::parse("f".repeat(64)).unwrap();
        oversized.bytes = 40 * 1024 * 1024;
        let mut oversized_again = oversized.clone();
        oversized_again.artifact_id = ArtifactId::parse("0".repeat(64)).unwrap();
        assert!(
            crate::parent_artifacts::stage_verified_parent_artifacts(
                &mut store,
                &reopened_artifact_store,
                &authority,
                &evidence_id,
                &authority.project_id,
                authority.config_revision.0,
                &authority.config_digest,
                &parent_workspace,
                &[oversized, oversized_again],
            )
            .unwrap_err()
            .contains("64 MiB")
        );

        #[cfg(unix)]
        {
            let linked_workspace = temp.path().join("linked-parent-workspace");
            fs::create_dir(&linked_workspace).unwrap();
            let outside = temp.path().join("outside-artifacts");
            fs::create_dir(&outside).unwrap();
            std::os::unix::fs::symlink(&outside, linked_workspace.join(".rex-artifacts")).unwrap();
            assert!(
                crate::parent_artifacts::stage_verified_parent_artifacts(
                    &mut store,
                    &reopened_artifact_store,
                    &authority,
                    &evidence_id,
                    &authority.project_id,
                    authority.config_revision.0,
                    &authority.config_digest,
                    &linked_workspace,
                    &[verified.reference().clone()],
                )
                .unwrap_err()
                .contains("real directory")
            );
        }
        let receipt = mailbox.read_receipt("message1", now).unwrap().unwrap();
        let receipt: serde_json::Value = serde_json::from_slice(&receipt).unwrap();
        assert_eq!(
            receipt["result"]["artifact"],
            serde_json::to_value(verified.reference()).unwrap()
        );
        assert!(mailbox.pending(now).unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn registry_lookup_proof_rejects_corrupted_object_bytes() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).unwrap();
        let workspace = fs::canonicalize(workspace).unwrap();
        fs::write(workspace.join("result.txt"), b"verified result").unwrap();
        let store = ArtifactStore::open(&temp.path().join("artifact-store")).unwrap();
        let project_id = ProjectId::parse("project1").unwrap();
        let stored = store
            .register(
                &workspace,
                &project_id,
                "run1",
                Role::Worker,
                "result.txt",
                RoleArtifactKind::General,
                1,
            )
            .unwrap();
        let registration = ArtifactRegistration {
            artifact_id: stored.reference.artifact_id.clone(),
            project_id,
            agent_run_id: "run1".into(),
            role: Role::Worker,
            role_session_id: "worker-session".into(),
            ticket_run_id: None,
            ticket_revision: None,
            config_revision: 1,
            config_digest: Digest::parse("a".repeat(64)).unwrap(),
            profile_id: "worker".into(),
            profile_digest: Digest::parse("b".repeat(64)).unwrap(),
            workspace_path: workspace.clone(),
            control_dir: workspace.join("control"),
            authority_digest: Digest::parse("c".repeat(64)).unwrap(),
            message_id: "message1".into(),
            request_digest: Digest::parse("d".repeat(64)).unwrap(),
            reference: stored.reference,
            object_path: stored.object_path.clone(),
        };
        fs::set_permissions(&stored.object_path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&stored.object_path, b"tampered result").unwrap();
        assert!(verify_registered_object(registration, &store).is_err());
    }
}

impl crate::store::ConfigStore {
    /// Process one ArtifactAdd mailbox request. The object is copied and synced before the short
    /// owner-fenced transaction; the mailbox receipt is published only after that transaction
    /// commits and the durable object has been re-read and verified.
    pub fn process_artifact_add(
        &mut self,
        owner_generation: u64,
        authority: &AgentLaunchAuthority,
        artifact_store: &ArtifactStore,
        mailbox: &MailboxCapability,
        mailbox_request: &MailboxRequest,
        request: &crate::engine::orchestration::ArtifactAddRequest,
    ) -> Result<VerifiedArtifact, String> {
        authority.validate()?;
        request.validate()?;
        let envelope = &mailbox_request.envelope;
        let expected_params = serde_json::to_value(request).map_err(|e| e.to_string())?;
        let method = serde_json::to_value(&envelope.method).map_err(|e| e.to_string())?;
        if method.as_str() != Some("artifact.add")
            || envelope.params != expected_params
            || envelope.request_id.as_str() != request.message_id
            || envelope.operation_id.as_ref() != Some(&authority.operation_id)
            || mailbox_request.request_id != request.message_id
            || envelope.run_id.as_deref() != Some(authority.agent_run_id.as_str())
            || envelope.project_id.as_ref() != Some(&authority.project_id)
            || envelope.role != Some(authority.role)
            || envelope.attempt != Some(authority.attempt)
            || envelope.run_epoch != Some(authority.run_epoch)
        {
            return Err(
                "ArtifactAdd mailbox request does not match the immutable launch authority".into(),
            );
        }
        if !crate::engine::orchestration::role_may_submit_artifact(authority.role, request.kind) {
            return Err("Agent role is not authorized to register this artifact kind".into());
        }
        let request_digest = Digest::parse(mailbox_request.digest.clone())?;
        let stored: StoredArtifact = artifact_store.register(
            &authority.workspace_path,
            &authority.project_id,
            authority.agent_run_id.as_str(),
            authority.role,
            &request.path,
            request.kind,
            request.artifact_schema_version,
        )?;
        if stored.project_id != authority.project_id
            || stored.agent_run_id != authority.agent_run_id.as_str()
            || stored.kind != request.kind
            || stored.schema_version != request.artifact_schema_version
            || stored.reference.digest != stored.content_digest
            || stored.reference.bytes != stored.byte_count
        {
            return Err(
                "ArtifactStore returned an artifact outside the requested host scope".into(),
            );
        }
        let registration = persist_registration(
            &mut self.connection,
            owner_generation,
            authority,
            &request.message_id,
            &request_digest,
            &stored.reference,
            &stored.object_path,
        )?;
        let verified = verify_registered_object(registration, artifact_store)?;
        let receipt = ArtifactAddReceipt {
            schema_version: 1,
            message_id: request.message_id.clone(),
            artifact: verified.reference().clone(),
        };
        let ack = ResponseEnvelope {
            schema_version: crate::protocol::SCHEMA_VERSION,
            request_id: RequestId::new(request.message_id.clone())?,
            result: Some(receipt),
            error: None,
            extensions: Default::default(),
        };
        let bytes = serde_json::to_vec(&ack).map_err(|e| e.to_string())?;
        mailbox.publish_receipt(&request.message_id, &bytes, unix_time_now()?)?;
        Ok(verified)
    }

    /// Resolve a host reference to an opaque proof after verifying its immutable object bytes.
    pub fn lookup_verified_artifact(
        &mut self,
        artifact_store: &ArtifactStore,
        authority: &AgentLaunchAuthority,
        reference: &RoleArtifactReference,
    ) -> Result<Option<VerifiedArtifact>, String> {
        let tx = self
            .connection
            .unchecked_transaction()
            .map_err(|e| e.to_string())?;
        let registration = lookup_registered_artifact_tx(&tx, authority, reference)?;
        tx.commit().map_err(|e| e.to_string())?;
        registration
            .map(|registration| verify_registered_object(registration, artifact_store))
            .transpose()
    }
}

fn verify_registered_object(
    registration: ArtifactRegistration,
    artifact_store: &ArtifactStore,
) -> Result<VerifiedArtifact, String> {
    read_registered_object(&registration, artifact_store)?;
    Ok(VerifiedArtifact { registration })
}

fn read_registered_object(
    registration: &ArtifactRegistration,
    artifact_store: &ArtifactStore,
) -> Result<Vec<u8>, String> {
    if !artifact_store.owns_object_path(&registration.reference, &registration.object_path)? {
        return Err("registered artifact path is outside the configured immutable store".into());
    }
    let metadata = fs::symlink_metadata(&registration.object_path)
        .map_err(|e| format!("inspect immutable artifact: {e}"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() != registration.reference.bytes
        || metadata.len() > 64 * 1024 * 1024
    {
        return Err("registered artifact object is missing, linked, or has an invalid size".into());
    }
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(&registration.object_path)
            .map_err(|e| e.to_string())?
    };
    #[cfg(not(unix))]
    let mut file = File::open(&registration.object_path).map_err(|e| e.to_string())?;
    let opened = file.metadata().map_err(|e| e.to_string())?;
    if !opened.is_file() || opened.len() != metadata.len() {
        return Err("registered artifact object changed during verification".into());
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    file.take(64 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    let digest = Digest::parse(format!("{:x}", sha2::Sha256::digest(&bytes)))?;
    if bytes.len() as u64 != registration.reference.bytes || digest != registration.reference.digest
    {
        return Err("registered artifact object bytes do not match the host registry".into());
    }
    Ok(bytes)
}

/// Look up a reference inside a caller-owned transaction. This performs only SQLite work;
/// immutable object bytes are verified outside the transaction with `verify_registered_object`.
pub(crate) fn lookup_registered_artifact_tx(
    tx: &Transaction<'_>,
    authority: &AgentLaunchAuthority,
    reference: &RoleArtifactReference,
) -> Result<Option<ArtifactRegistration>, String> {
    crate::artifacts::validate_relative_path(&reference.path)?;
    let authoritative: Option<(String,String)> = tx.query_row(
        "SELECT authority_json,authority_digest FROM agent_launch_authority WHERE agent_run_id=?1",
        [authority.agent_run_id.as_str()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ).optional().map_err(|error| error.to_string())?;
    let Some((authority_json, authority_digest_stored)) = authoritative else {
        return Ok(None);
    };
    let authority_stored: AgentLaunchAuthority =
        crate::protocol::parse_unique(authority_json.as_bytes())?;
    authority_stored.validate()?;
    if authority_digest_stored != authority_stored.digest()?.as_str() {
        return Err("stored artifact lookup authority digest is invalid".into());
    }
    if authority_stored != *authority {
        return Ok(None);
    }
    let row: Option<(String,String,String,String,String,Option<String>,Option<u64>,u64,String,String,String,String,String,String,String,String,String,i64,String,String,u64,String)> = tx.query_row(
        "SELECT artifact_id,project_id,agent_run_id,role,role_session_id,ticket_run_id,ticket_revision,config_revision,config_digest,profile_id,profile_digest,workspace_path,control_dir,authority_digest,message_id,request_digest,kind,schema_version,relative_path,content_digest,byte_count,object_path FROM registered_artifacts WHERE artifact_id=?1",
        [reference.artifact_id.as_str()],
        |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?,r.get(9)?,r.get(10)?,r.get(11)?,r.get(12)?,r.get(13)?,r.get(14)?,r.get(15)?,r.get(16)?,r.get(17)?,r.get(18)?,r.get(19)?,r.get(20)?,r.get(21)?)),
    ).optional().map_err(|error| error.to_string())?;
    let Some((
        id,
        project_id,
        agent_run_id,
        role,
        session_id,
        ticket_run_id,
        ticket_revision,
        config_revision,
        config_digest,
        profile_id,
        profile_digest,
        workspace_path,
        control_dir,
        authority_digest,
        message_id,
        request_digest,
        kind,
        schema_version,
        relative_path,
        content_digest,
        byte_count,
        object_path,
    )) = row
    else {
        return Ok(None);
    };
    let parsed_project = ProjectId::parse(project_id)?;
    let parsed_id = ArtifactId::parse(id)?;
    let parsed_digest = Digest::parse(config_digest)?;
    let parsed_profile_digest = Digest::parse(profile_digest)?;
    let parsed_authority_digest = Digest::parse(authority_digest)?;
    let parsed_request_digest = Digest::parse(request_digest)?;
    let parsed_content_digest = Digest::parse(content_digest)?;
    let parsed_kind: RoleArtifactKind =
        serde_json::from_str(&format!("\"{}\"", kind)).map_err(|error| error.to_string())?;
    if !crate::engine::orchestration::role_may_submit_artifact(authority.role, parsed_kind) {
        return Err(
            "authoritative Agent role is not authorized for the registered artifact kind".into(),
        );
    }
    let reference_matches = parsed_id == reference.artifact_id
        && parsed_kind == reference.kind
        && u32::try_from(schema_version).ok() == Some(reference.schema_version)
        && relative_path == reference.path
        && parsed_content_digest == reference.digest
        && byte_count == reference.bytes;
    if !reference_matches {
        return Err("artifact reference does not match its host registration".into());
    }
    let authority_digest_expected = authority.digest()?;
    let expected_id = ArtifactId::from_registration_identity(
        &authority.project_id,
        &authority.agent_run_id,
        reference.kind.as_str(),
        reference.schema_version,
        &reference.digest,
    )?;
    if parsed_id != expected_id {
        return Err("registered artifact ID does not match its authority scope".into());
    }
    if parsed_project != authority.project_id
        || agent_run_id != authority.agent_run_id.as_str()
        || role
            != serde_json::to_value(authority.role)
                .map_err(|error| error.to_string())?
                .as_str()
                .unwrap_or_default()
        || session_id != authority.role_session_id
        || ticket_run_id.as_deref() != authority.ticket_run_id.as_ref().map(|value| value.as_str())
        || ticket_revision != authority.ticket_revision.map(|value| value.0)
        || config_revision != authority.config_revision.0
        || parsed_digest != authority.config_digest
        || profile_id != authority.profile_id.as_str()
        || parsed_profile_digest != authority.profile_digest
        || workspace_path != authority.workspace_path.to_string_lossy()
        || control_dir != authority.control_dir.to_string_lossy()
        || parsed_authority_digest != authority_digest_expected
    {
        return Err("registered artifact is outside the authoritative AgentRun scope".into());
    }
    Ok(Some(ArtifactRegistration {
        artifact_id: parsed_id,
        project_id: parsed_project,
        agent_run_id,
        role: authority.role,
        role_session_id: session_id,
        ticket_run_id: authority.ticket_run_id.clone(),
        ticket_revision,
        config_revision,
        config_digest: parsed_digest,
        profile_id,
        profile_digest: parsed_profile_digest,
        workspace_path: PathBuf::from(workspace_path),
        control_dir: PathBuf::from(control_dir),
        authority_digest: parsed_authority_digest,
        message_id,
        request_digest: parsed_request_digest,
        reference: reference.clone(),
        object_path: PathBuf::from(object_path),
    }))
}

pub(crate) fn persist_registration(
    connection: &mut Connection,
    owner_generation: u64,
    authority: &AgentLaunchAuthority,
    message_id: &str,
    request_digest: &Digest,
    reference: &RoleArtifactReference,
    object_path: &std::path::Path,
) -> Result<ArtifactRegistration, String> {
    authority.validate()?;
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|e| e.to_string())?;
    crate::store::validate_active_generation(&tx, owner_generation)?;
    let stored_authority: Option<(String,String)> = tx.query_row(
        "SELECT authority_json,authority_digest FROM agent_launch_authority WHERE agent_run_id=?1",
        [authority.agent_run_id.as_str()], |row| Ok((row.get(0)?,row.get(1)?)),
    ).optional().map_err(|e| e.to_string())?;
    let Some((authority_json, authority_digest)) = stored_authority else {
        return Err("ArtifactAdd references an unknown AgentRun".into());
    };
    let stored: AgentLaunchAuthority = crate::protocol::parse_unique(authority_json.as_bytes())?;
    if stored != *authority
        || authority_digest != authority.digest()?.as_str()
        || authority.controller_generation != owner_generation
    {
        return Err("ArtifactAdd launch authority is stale or does not match the AgentRun".into());
    }
    let expected_id = ArtifactId::from_registration_identity(
        &authority.project_id,
        &authority.agent_run_id,
        reference.kind.as_str(),
        reference.schema_version,
        &reference.digest,
    )?;
    if expected_id != reference.artifact_id {
        return Err("artifact ID does not match host registration identity".into());
    }
    if !crate::engine::orchestration::role_may_submit_artifact(authority.role, reference.kind) {
        return Err("Agent role is not authorized to register this artifact kind".into());
    }
    let role_json = serde_json::to_value(authority.role).map_err(|e| e.to_string())?;
    let role = role_json.as_str().ok_or("role is not a string")?;
    let kind = reference.kind.as_str();
    let ticket_revision = authority.ticket_revision.map(|value| value.0);
    let existing: Option<(String,String)> = tx.query_row(
        "SELECT request_digest,artifact_id FROM registered_artifact_messages WHERE agent_run_id=?1 AND message_id=?2",
        params![authority.agent_run_id.as_str(),message_id], |r| Ok((r.get(0)?,r.get(1)?)),
    ).optional().map_err(|e| e.to_string())?;
    if let Some((old_request, old_id)) = existing {
        if old_request != request_digest.as_str() || old_id != reference.artifact_id.as_str() {
            return Err("ArtifactAdd message ID was replayed with different content".into());
        }
        let existing_artifact = lookup_registered_artifact_tx(&tx, authority, reference)?
            .ok_or("ArtifactAdd replay has no immutable artifact registration")?;
        if existing_artifact.object_path != object_path {
            return Err("ArtifactAdd replay resolved to a different immutable object".into());
        }
    } else {
        if let Some(existing_artifact) = lookup_registered_artifact_tx(&tx, authority, reference)? {
            if existing_artifact.object_path != object_path {
                return Err(
                    "deterministic artifact ID collides with a different object path".into(),
                );
            }
        } else {
            tx.execute("INSERT INTO registered_artifacts(artifact_id,project_id,agent_run_id,role,role_session_id,ticket_run_id,ticket_revision,config_revision,config_digest,profile_id,profile_digest,workspace_path,control_dir,authority_digest,message_id,request_digest,kind,schema_version,relative_path,content_digest,byte_count,object_path,created_at_unix) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23)", params![reference.artifact_id.as_str(),authority.project_id.as_str(),authority.agent_run_id.as_str(),role,authority.role_session_id,authority.ticket_run_id.as_ref().map(|value| value.as_str()),ticket_revision,authority.config_revision.0,authority.config_digest.as_str(),authority.profile_id.as_str(),authority.profile_digest.as_str(),authority.workspace_path.to_string_lossy(),authority.control_dir.to_string_lossy(),authority.digest()?.as_str(),message_id,request_digest.as_str(),kind,reference.schema_version,reference.path,reference.digest.as_str(),reference.bytes,object_path.to_string_lossy(),crate::store::now_unix()?]).map_err(|e| e.to_string())?;
        }
        tx.execute("INSERT INTO registered_artifact_messages(agent_run_id,message_id,request_digest,artifact_id,created_at_unix) VALUES (?1,?2,?3,?4,?5)", params![authority.agent_run_id.as_str(),message_id,request_digest.as_str(),reference.artifact_id.as_str(),crate::store::now_unix()?]).map_err(|e| e.to_string())?;
    }
    let result = ArtifactRegistration {
        artifact_id: reference.artifact_id.clone(),
        project_id: authority.project_id.clone(),
        agent_run_id: authority.agent_run_id.to_string(),
        role: authority.role,
        role_session_id: authority.role_session_id.clone(),
        ticket_run_id: authority.ticket_run_id.clone(),
        ticket_revision,
        config_revision: authority.config_revision.0,
        config_digest: authority.config_digest.clone(),
        profile_id: authority.profile_id.to_string(),
        profile_digest: authority.profile_digest.clone(),
        workspace_path: authority.workspace_path.clone(),
        control_dir: authority.control_dir.clone(),
        authority_digest: authority.digest()?,
        message_id: message_id.to_owned(),
        request_digest: request_digest.clone(),
        reference: reference.clone(),
        object_path: object_path.to_owned(),
    };
    tx.commit().map_err(|e| e.to_string())?;
    Ok(result)
}
