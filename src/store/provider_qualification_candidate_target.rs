//! Immutable candidate identity attached to a provider qualification request.

use rusqlite::Connection;

const TARGET_LAYOUT: &str = "CREATE TABLE provider_qualification_candidate_targets (
    request_id TEXT PRIMARY KEY REFERENCES provider_qualification_jobs(request_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    candidate_id TEXT NOT NULL CHECK(length(candidate_id) BETWEEN 1 AND 255),
    candidate_digest TEXT NOT NULL CHECK(length(candidate_digest)=64),
    FOREIGN KEY(project_id,candidate_id,candidate_digest)
      REFERENCES learning_candidates(project_id,candidate_id,digest) ON DELETE RESTRICT
);";

const TRIGGERS: &str = "CREATE TRIGGER provider_qualification_candidate_target_insert
BEFORE INSERT ON provider_qualification_candidate_targets
WHEN NOT EXISTS (SELECT 1 FROM provider_qualification_jobs j
                 WHERE j.request_id=NEW.request_id AND j.project_id=NEW.project_id)
BEGIN SELECT RAISE(ABORT, 'provider qualification candidate target project mismatch'); END;
CREATE TRIGGER provider_qualification_candidate_target_immutable_update
BEFORE UPDATE ON provider_qualification_candidate_targets
BEGIN SELECT RAISE(ABORT, 'provider qualification candidate target is immutable'); END;
CREATE TRIGGER provider_qualification_candidate_target_immutable_delete
BEFORE DELETE ON provider_qualification_candidate_targets
BEGIN SELECT RAISE(ABORT, 'provider qualification candidate target is immutable'); END;";

pub(crate) fn migrate_v22(connection: &Connection) -> Result<(), String> {
    let tx = connection
        .unchecked_transaction()
        .map_err(|error| error.to_string())?;
    let version: i64 = tx
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| error.to_string())?;
    if version != 21 {
        return Err(format!(
            "provider qualification candidate target migration requires schema 21, found {version}"
        ));
    }
    apply_v22_layout(&tx)?;
    tx.execute_batch("INSERT INTO schema_migrations(version,applied_at_unix) VALUES (22,unixepoch()); PRAGMA user_version=22;")
        .map_err(|error| error.to_string())?;
    tx.commit().map_err(|error| error.to_string())
}

pub(crate) fn validate_v22_schema(connection: &Connection) -> Result<(), String> {
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| error.to_string())?;
    if !(22..=crate::store::SCHEMA_VERSION).contains(&version) {
        return Err(format!(
            "provider qualification candidate target schema version mismatch: {version}"
        ));
    }
    let recorded: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=22)",
            [],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    if !recorded {
        return Err("schema 22 migration record is missing".into());
    }
    let canonical = crate::store::artifact_registry::canonical_v18_schema()?;
    apply_v22_layout(&canonical)?;
    crate::store::artifact_registry::validate_table_layout_against(
        connection,
        &canonical,
        "provider_qualification_candidate_targets",
    )?;
    Ok(())
}

fn apply_v22_layout(connection: &Connection) -> Result<(), String> {
    connection
        .execute_batch(TARGET_LAYOUT)
        .map_err(|error| error.to_string())?;
    connection
        .execute_batch(TRIGGERS)
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_22_migration_creates_and_validates_target_guards() {
        let state = tempfile::tempdir().unwrap();
        let store = crate::store::ConfigStore::open_test(state.path()).unwrap();
        let version: i64 = store
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, crate::store::SCHEMA_VERSION);
        validate_v22_schema(&store.connection).unwrap();
        let trigger_count: i64 = store.connection.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='trigger' AND name LIKE 'provider_qualification_candidate_target_%'",
            [],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(trigger_count, 3);
    }

    #[test]
    fn schema_validation_rejects_a_same_name_noop_immutability_trigger() {
        let state = tempfile::tempdir().unwrap();
        let store = crate::store::ConfigStore::open_test(state.path()).unwrap();
        store
            .connection
            .execute_batch(
                "DROP TRIGGER provider_qualification_candidate_target_immutable_update;
             CREATE TRIGGER provider_qualification_candidate_target_immutable_update
             BEFORE UPDATE ON provider_qualification_candidate_targets BEGIN SELECT 1; END;",
            )
            .unwrap();
        assert!(validate_v22_schema(&store.connection).is_err());
    }

    #[test]
    fn v21_migration_preserves_legacy_running_request_and_backs_up_database() {
        use crate::domain::ids::{ProfileId, ProjectId};
        use crate::domain::types::Role;
        use crate::store::provider_qualification_runtime::{
            ProviderQualificationLaunchPhase, ProviderQualificationRequest,
            ProviderQualificationTarget, QualificationClaim,
        };
        use crate::store::{ExpectedRevision, OwnerMetadata};

        let state = tempfile::tempdir().unwrap();
        let config_path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/fixture/config.toml");
        let applied = crate::config::load(&config_path).unwrap();
        let mut store = crate::store::ConfigStore::open_test(state.path()).unwrap();
        let revision = store
            .apply_snapshot(
                config_path.to_str().unwrap(),
                &applied,
                ExpectedRevision::Bootstrap,
            )
            .unwrap()
            .revision;
        let generation = store
            .start_owner(&OwnerMetadata {
                owner_nonce: "schema-21-provider-qualification".into(),
                state_root: state.path().display().to_string(),
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
        let request = ProviderQualificationRequest {
            request_id: "v21-applied-profile-job".into(),
            project_id,
            role: Role::Coordinator,
            profile_id: profile_id.clone(),
            profile_digest: crate::store::agent_profile_digest(&applied.profiles[&profile_id])
                .unwrap(),
            config_revision: revision.0,
            config_digest: applied.digest.clone(),
            target: ProviderQualificationTarget::AppliedProfile,
        };
        let request_digest = store
            .enqueue_provider_qualification(generation, &request)
            .unwrap();
        let QualificationClaim::Claimed { .. } = store
            .claim_provider_qualification(generation, 1, 1)
            .unwrap()
        else {
            panic!("legacy applied-profile request should reserve a slot");
        };
        store
            .bind_provider_qualification_rex(
                generation,
                &request.request_id,
                "fixture-session",
                "fixture-window",
                "fixture-block",
            )
            .unwrap();
        let before_job = store
            .provider_qualification_job(&request.request_id)
            .unwrap()
            .unwrap();
        let before_slot = store
            .provider_qualification_slot(&request.request_id)
            .unwrap()
            .unwrap();
        assert_eq!(
            before_job.request.target,
            ProviderQualificationTarget::AppliedProfile
        );
        assert_eq!(
            before_job.launch_phase,
            ProviderQualificationLaunchPhase::NotStarted
        );
        drop(store);

        let database = state.path().join("state.sqlite3");
        let legacy = rusqlite::Connection::open(&database).unwrap();
        legacy
            .execute_batch(
                "DROP TABLE machine_shutdowns;
                 DELETE FROM schema_migrations WHERE version=23;
                 DROP TABLE provider_qualification_candidate_targets;
                 DELETE FROM schema_migrations WHERE version=22;
                 PRAGMA user_version=21;",
            )
            .unwrap();
        legacy
            .query_row("PRAGMA wal_checkpoint(FULL)", [], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .unwrap();
        drop(legacy);
        let pre_migration_database = std::fs::read(&database).unwrap();
        let old_backup_count = std::fs::read_dir(state.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("state.sqlite3.pre-v2-")
            })
            .count();

        let migrated = crate::store::ConfigStore::open_test(state.path()).unwrap();
        assert_eq!(
            migrated
                .connection
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            crate::store::SCHEMA_VERSION
        );
        let after_job = migrated
            .provider_qualification_job(&request.request_id)
            .unwrap()
            .unwrap();
        let after_slot = migrated
            .provider_qualification_slot(&request.request_id)
            .unwrap()
            .unwrap();
        assert_eq!(after_job.request, before_job.request);
        assert_eq!(after_job.request_digest, request_digest);
        assert_eq!(after_job.status, before_job.status);
        assert_eq!(after_job.launch_phase, before_job.launch_phase);
        assert_eq!(after_job.rex_session_id.as_deref(), Some("fixture-session"));
        assert_eq!(after_job.rex_window_id.as_deref(), Some("fixture-window"));
        assert_eq!(after_job.rex_block_id.as_deref(), Some("fixture-block"));
        assert_eq!(after_slot, before_slot);

        let backups = std::fs::read_dir(state.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("state.sqlite3.pre-v2-")
            })
            .collect::<Vec<_>>();
        assert_eq!(backups.len(), old_backup_count + 2);
        assert!(
            backups
                .iter()
                .any(|path| std::fs::read(path).unwrap() == pre_migration_database)
        );
    }
}
