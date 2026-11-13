//! Durable launch boundaries and explicit recovery intent for provider qualification.

use rusqlite::Connection;

const PHASE_TRANSITIONS: &str = "CREATE TRIGGER provider_qualification_launch_phase_transitions
BEFORE UPDATE OF launch_phase ON provider_qualification_jobs
WHEN NOT (OLD.launch_phase=NEW.launch_phase
 OR (OLD.launch_phase='not_started' AND NEW.launch_phase='prepared')
 OR (OLD.launch_phase='prepared' AND NEW.launch_phase='create_attempted')
 OR (OLD.launch_phase='create_attempted' AND NEW.launch_phase='bound'))
BEGIN SELECT RAISE(ABORT, 'provider qualification launch phase transition is invalid'); END;";

const STATUS_TRANSITIONS: &str = "CREATE TRIGGER provider_qualification_status_transitions
BEFORE UPDATE OF status ON provider_qualification_jobs
WHEN NOT (
 OLD.status=NEW.status
 OR (OLD.status='queued' AND NEW.status IN ('running','failed'))
 OR (OLD.status='running' AND NEW.status IN ('unknown','verified','failed'))
 OR (OLD.status='unknown' AND NEW.status IN ('verified','failed'))
 OR (OLD.status='unknown' AND NEW.status='running'
     AND OLD.launch_phase IN ('not_started','prepared')
     AND OLD.reconcile_requested_generation=NEW.controller_generation
     AND OLD.controller_generation=NEW.controller_generation
     AND NEW.reconcile_requested_generation IS NULL
     AND NEW.rex_session_id IS NULL AND NEW.rex_window_id IS NULL AND NEW.rex_block_id IS NULL
     AND EXISTS (SELECT 1 FROM execution_slots s
                 WHERE s.pool='agent' AND s.owner_kind='provider_qualification'
                   AND s.owner_id=OLD.request_id AND s.project_id=OLD.project_id
                   AND s.controller_generation=NEW.controller_generation
                   AND s.disposition='launch_pending'))
)
BEGIN SELECT RAISE(ABORT, 'provider qualification status transition is invalid'); END;";

const SNAPSHOT_IMMUTABLE: &str = "CREATE TRIGGER provider_qualification_environment_snapshot_immutable
BEFORE UPDATE OF environment_snapshot_id ON provider_qualification_jobs
WHEN OLD.environment_snapshot_id IS NOT NULL AND OLD.environment_snapshot_id IS NOT NEW.environment_snapshot_id
BEGIN SELECT RAISE(ABORT, 'provider qualification environment snapshot is immutable'); END;";

pub(crate) fn migrate_v17(connection: &Connection) -> Result<(), String> {
    let tx = connection
        .unchecked_transaction()
        .map_err(|error| error.to_string())?;
    let version: i64 = tx
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| error.to_string())?;
    if version == 17 {
        tx.commit().map_err(|error| error.to_string())?;
        return Ok(());
    }
    if version != 16 {
        return Err(format!(
            "provider qualification recovery migration requires schema 16, found {version}"
        ));
    }
    apply_v17_layout(&tx)?;
    tx.execute_batch(
        "INSERT INTO schema_migrations(version,applied_at_unix) VALUES (17,unixepoch());
         PRAGMA user_version=17;",
    )
    .map_err(|error| error.to_string())?;
    tx.commit().map_err(|error| error.to_string())
}

pub(crate) fn validate_v17_schema(connection: &Connection) -> Result<(), String> {
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| error.to_string())?;
    if !(17..=crate::store::SCHEMA_VERSION).contains(&version) {
        return Err(format!(
            "provider qualification recovery schema version mismatch: {version}"
        ));
    }
    let recorded: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=17)",
            [],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    if !recorded {
        return Err("schema 17 migration record is missing".into());
    }
    let canonical = crate::store::artifact_registry::canonical_v12_schema()?;
    apply_v17_layout(&canonical)?;
    crate::store::artifact_registry::validate_table_layout_against(
        connection,
        &canonical,
        "provider_qualification_jobs",
    )?;
    Ok(())
}

pub(crate) fn apply_v17_layout(connection: &Connection) -> Result<(), String> {
    connection.execute_batch(&format!(
        "ALTER TABLE provider_qualification_jobs ADD COLUMN launch_phase TEXT NOT NULL DEFAULT 'legacy_unknown' CHECK(launch_phase IN ('legacy_unknown','not_started','prepared','create_attempted','bound'));
         ALTER TABLE provider_qualification_jobs ADD COLUMN environment_snapshot_id TEXT CHECK(environment_snapshot_id IS NULL OR length(environment_snapshot_id)=64);
         ALTER TABLE provider_qualification_jobs ADD COLUMN reconcile_requested_generation INTEGER CHECK(reconcile_requested_generation IS NULL OR reconcile_requested_generation>0);
         UPDATE provider_qualification_jobs SET launch_phase='not_started' WHERE status='queued';
         DROP TRIGGER provider_qualification_status_transitions;
         {STATUS_TRANSITIONS}
         {PHASE_TRANSITIONS}
         {SNAPSHOT_IMMUTABLE}"
    ))
    .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_17_layout_is_preserved_by_schema_18_and_validates_exact_launch_columns() {
        let state = tempfile::tempdir().unwrap();
        let store = crate::store::ConfigStore::open_test(state.path()).unwrap();
        assert_eq!(
            store
                .connection
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            crate::store::SCHEMA_VERSION
        );
        validate_v17_schema(&store.connection).unwrap();
        drop(store);

        let reopened = crate::store::ConfigStore::open_test(state.path()).unwrap();
        crate::store::artifact_registry::validate_v12_schema(&reopened.connection).unwrap();
        crate::store::artifact_registry::validate_v13_schema(&reopened.connection).unwrap();
        crate::store::artifact_registry::validate_v14_schema(&reopened.connection).unwrap();
        validate_v17_schema(&reopened.connection).unwrap();
        crate::store::agent_launch_phase::validate_v18_schema(&reopened.connection).unwrap();
        reopened
            .connection
            .execute_batch("DROP TRIGGER provider_qualification_launch_phase_transitions")
            .unwrap();
        assert!(validate_v17_schema(&reopened.connection).is_err());
    }

    #[test]
    fn v16_queued_row_remains_claimable_while_ambiguous_row_stays_legacy_unknown() {
        use crate::domain::ids::{ProfileId, ProjectId};
        use crate::domain::types::Role;
        use crate::store::provider_qualification_runtime::{
            ProviderQualificationLaunchPhase, ProviderQualificationRequest,
        };
        use crate::store::{ExpectedRevision, OwnerMetadata};

        let temp = tempfile::tempdir().unwrap();
        let state_root = temp.path();
        let config_path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/fixture/config.toml");
        let applied = crate::config::load(&config_path).unwrap();
        let mut store = crate::store::ConfigStore::open_test(state_root).unwrap();
        let revision = store
            .apply_snapshot("legacy-provider", &applied, ExpectedRevision::Bootstrap)
            .unwrap()
            .revision;
        let owner_generation = store
            .start_owner(&OwnerMetadata {
                owner_nonce: "v16-legacy-row".into(),
                state_root: state_root.display().to_string(),
                config_source: config_path.display().to_string(),
                process_start_identity: "test-process".into(),
                executable_path: "/test/rex-projects".into(),
                executable_digest: "a".repeat(64),
                rex_endpoint: None,
                rex_server_identity: None,
                rex_session_id: None,
                rex_block_id: None,
            })
            .unwrap();
        let project_id = ProjectId::parse("goal_project").unwrap();
        let profile_id = ProfileId::parse("judgment_claude").unwrap();
        let profile = applied.profiles.get(&profile_id).unwrap();
        let request = ProviderQualificationRequest {
            request_id: "legacy-qualification".into(),
            project_id,
            role: Role::Coordinator,
            profile_id,
            profile_digest: crate::store::agent_profile_digest(profile).unwrap(),
            config_revision: revision.0,
            config_digest: applied.digest,
        };
        store
            .enqueue_provider_qualification(owner_generation, &request)
            .unwrap();
        let crate::store::provider_qualification_runtime::QualificationClaim::Claimed { .. } =
            store
                .claim_provider_qualification(owner_generation, 1, 1)
                .unwrap()
        else {
            panic!("fixture qualification should reserve its original slot");
        };
        store
            .mark_provider_qualification_unknown(owner_generation, &request.request_id)
            .unwrap();
        let queued_request = ProviderQualificationRequest {
            request_id: "legacy-queued-qualification".into(),
            project_id: request.project_id.clone(),
            role: request.role,
            profile_id: request.profile_id.clone(),
            profile_digest: request.profile_digest.clone(),
            config_revision: request.config_revision,
            config_digest: request.config_digest.clone(),
        };
        store
            .enqueue_provider_qualification(owner_generation, &queued_request)
            .unwrap();
        let original_slot = store
            .provider_qualification_slot(&request.request_id)
            .unwrap()
            .unwrap();
        drop(store);

        let database = state_root.join("state.sqlite3");
        let canonical = crate::store::artifact_registry::canonical_v12_schema().unwrap();
        let mut layout_statement = canonical
            .prepare(
                "SELECT sql FROM sqlite_master
                 WHERE tbl_name IN ('provider_qualification_jobs','agent_launch_reservations') AND sql IS NOT NULL
                 ORDER BY CASE type WHEN 'table' THEN 0 WHEN 'index' THEN 1 ELSE 2 END, name",
            )
            .unwrap();
        let v16_layout = layout_statement
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        drop(layout_statement);
        let legacy = Connection::open(&database).unwrap();
        legacy
            .execute_batch(
                "DROP TABLE learning_decisions;
                 DROP TABLE learning_findings;
                 DROP TABLE learning_batches;
                 DROP TABLE supervisor_topic_publications;
                 DELETE FROM schema_migrations WHERE version=21;
                 DELETE FROM schema_migrations WHERE version=20;
                 DELETE FROM schema_migrations WHERE version=19;
                 CREATE TEMP TABLE preserved_provider_qualification_jobs AS
                 SELECT request_id,project_id,role,profile_id,profile_digest,config_revision,
                        config_digest,request_digest,status,controller_generation,rex_session_id,
                        rex_window_id,rex_block_id,result_json,evidence_digest,created_at_unix,
                        updated_at_unix
                 FROM provider_qualification_jobs;
                 CREATE TEMP TABLE preserved_agent_launch_reservations AS
                 SELECT agent_run_id,project_id,operation_id,controller_generation,project_epoch,
                        reservation_digest,reservation_json,lifecycle,created_at_unix,updated_at_unix
                 FROM agent_launch_reservations;
                 DROP TABLE provider_qualification_jobs;
                 DROP TABLE agent_launch_reservations;",
            )
            .unwrap();
        for statement in v16_layout {
            legacy.execute_batch(&statement).unwrap();
        }
        legacy
            .execute_batch(
                "INSERT INTO provider_qualification_jobs(
                    request_id,project_id,role,profile_id,profile_digest,config_revision,
                    config_digest,request_digest,status,controller_generation,rex_session_id,
                    rex_window_id,rex_block_id,result_json,evidence_digest,created_at_unix,
                    updated_at_unix
                 )
                 SELECT request_id,project_id,role,profile_id,profile_digest,config_revision,
                        config_digest,request_digest,status,controller_generation,rex_session_id,
                        rex_window_id,rex_block_id,result_json,evidence_digest,created_at_unix,
                        updated_at_unix
                 FROM preserved_provider_qualification_jobs;
                 DROP TABLE preserved_provider_qualification_jobs;
                 INSERT INTO agent_launch_reservations
                 SELECT agent_run_id,project_id,operation_id,controller_generation,project_epoch,
                        reservation_digest,reservation_json,lifecycle,created_at_unix,updated_at_unix
                 FROM preserved_agent_launch_reservations;
                 DROP TABLE preserved_agent_launch_reservations;
                 DELETE FROM schema_migrations WHERE version>=17;
                 PRAGMA user_version=16;",
            )
            .unwrap();
        drop(legacy);

        let mut migrated = crate::store::ConfigStore::open_test(state_root).unwrap();
        let job = migrated
            .provider_qualification_job(&request.request_id)
            .unwrap()
            .unwrap();
        assert_eq!(
            job.status,
            crate::store::provider_qualification_runtime::ProviderQualificationJobStatus::Unknown
        );
        assert_eq!(
            job.launch_phase,
            ProviderQualificationLaunchPhase::LegacyUnknown
        );
        assert_eq!(job.environment_snapshot_id, None);
        assert_eq!(job.reconcile_requested_generation, None);
        assert_eq!(job.rex_session_id, None);
        let slot = migrated
            .provider_qualification_slot(&request.request_id)
            .unwrap()
            .unwrap();
        assert_eq!(slot.slot_index, original_slot.slot_index);
        assert_eq!(slot.reservation_epoch, original_slot.reservation_epoch);
        assert_eq!(slot.disposition, "unknown");
        assert!(
            migrated
                .claim_provider_qualification_recovery(owner_generation, &request.request_id)
                .is_err()
        );
        assert_eq!(
            migrated
                .provider_qualification_slot(&request.request_id)
                .unwrap()
                .unwrap()
                .disposition,
            "unknown"
        );
        let queued = migrated
            .provider_qualification_job(&queued_request.request_id)
            .unwrap()
            .unwrap();
        assert_eq!(
            queued.status,
            crate::store::provider_qualification_runtime::ProviderQualificationJobStatus::Queued
        );
        assert_eq!(
            queued.launch_phase,
            ProviderQualificationLaunchPhase::NotStarted
        );
        let crate::store::provider_qualification_runtime::QualificationClaim::Claimed {
            job: claimed,
            ..
        } = migrated
            .claim_provider_qualification(owner_generation, 2, 2)
            .unwrap()
        else {
            panic!("migrated queued qualification should be claimable");
        };
        assert_eq!(claimed.request.request_id, queued_request.request_id);
        assert_eq!(
            claimed.launch_phase,
            ProviderQualificationLaunchPhase::NotStarted
        );
        assert_eq!(
            claimed.status,
            crate::store::provider_qualification_runtime::ProviderQualificationJobStatus::Running
        );
        migrated
            .mark_provider_qualification_prepared(
                owner_generation,
                &queued_request.request_id,
                &crate::domain::ids::Digest::parse("b".repeat(64)).unwrap(),
            )
            .unwrap();
        let prepared = migrated
            .provider_qualification_job(&queued_request.request_id)
            .unwrap()
            .unwrap();
        assert_eq!(
            prepared.launch_phase,
            ProviderQualificationLaunchPhase::Prepared
        );
        assert_eq!(
            migrated
                .provider_qualification_slot(&queued_request.request_id)
                .unwrap()
                .unwrap()
                .disposition,
            "launch_pending"
        );
    }

    #[test]
    fn malformed_v17_open_fails_before_wal_changes_database_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let state_root = temp.path();
        drop(crate::store::ConfigStore::open_test(state_root).unwrap());
        let database = state_root.join("state.sqlite3");
        let malformed = Connection::open(&database).unwrap();
        malformed
            .execute_batch("DROP TRIGGER provider_qualification_launch_phase_transitions")
            .unwrap();
        drop(malformed);
        let before = std::fs::read(&database).unwrap();

        assert!(crate::store::ConfigStore::open_test(state_root).is_err());

        let after = std::fs::read(&database).unwrap();
        assert_eq!(
            after, before,
            "schema rejection must happen before WAL mutation"
        );
    }
}
