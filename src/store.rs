use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use fs2::FileExt;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::config::{AppliedConfig, Config, Profile, SourceFile};
use crate::domain::ids::{Digest, ProfileId, Revision};

const SCHEMA_VERSION: i64 = 1;

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
        Ok(Self {
            _file: acquire_machine_lock(state_root)?,
        })
    }
}

impl ConfigStore {
    pub fn open(state_root: &Path) -> Result<Self, String> {
        let machine_lock = MachineLock::acquire(state_root)?;
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
            Self::migrate(&connection, existing_version)?;
        }
        Ok(Self {
            connection,
            _machine_lock: machine_lock,
        })
    }

    fn migrate(connection: &Connection, current: i64) -> Result<(), String> {
        if current != 0 {
            return Err(format!("no migration path from database schema {current}"));
        }
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
            );",
        ).map_err(|e| e.to_string())?;
        let now = now_unix()?;
        tx.execute(
            "INSERT INTO schema_migrations(version, applied_at_unix) VALUES (?1, ?2)",
            params![SCHEMA_VERSION, now],
        )
        .map_err(|e| e.to_string())?;
        tx.pragma_update(None, "user_version", SCHEMA_VERSION)
            .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())
    }

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

    use super::{ConfigStore, ExpectedRevision};
    use crate::config::{AppliedConfig, SourceFile, SourceKind};
    use crate::domain::ids::Digest;

    fn snapshot(digest: &str) -> AppliedConfig {
        AppliedConfig {
            config: serde_json::from_value(serde_json::json!({"schema_version":1,"adapters":{"tickets":{"kind":"command","command":["test"],"status_values":{"triage":"Triage","backlog":"Backlog","ready":"Ready","in_progress":"In Progress","in_review":"In Review","done":"Done","canceled":"Canceled"}}},"projects":{}})).unwrap(),
            profiles: BTreeMap::new(), source_root: "/tmp/config".into(), source_files: vec![SourceFile { kind: SourceKind::File, path: "/tmp/config/config.toml".into(), canonical_path: "/tmp/config/config.toml".into(), sha256: Digest::parse("a".repeat(64)).unwrap(), bytes: 1, contents: "x".into() }], digest: Digest::parse(digest).unwrap(),
        }
    }

    #[test]
    fn snapshot_apply_is_compare_and_swap_and_idempotent() {
        let temp = tempfile::tempdir().unwrap();
        let mut store = ConfigStore::open(temp.path()).unwrap();
        assert!(ConfigStore::open(temp.path()).is_err());
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
}
