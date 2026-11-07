use rusqlite::{OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};

use super::ConfigStore;
use crate::process::{ProcessIdentity, ProcessIdentityQuality};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostJobIntent {
    pub job_id: String,
    pub effect_operation_id: String,
    pub project_id: String,
    pub subject_id: String,
    pub worktree_id: String,
    pub kind: String,
    pub request_digest: String,
    pub configuration_digest: String,
    pub head: String,
    pub source_digest: String,
    pub max_attempts: u32,
    pub retry_when_absent: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum HostJobState {
    Pending,
    Starting,
    Running,
    Unknown { reason: String },
    Succeeded,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostJobRecord {
    pub intent: HostJobIntent,
    pub state: HostJobState,
    pub process_identity: Option<ProcessIdentity>,
    pub receipt_json: Option<String>,
    pub attempt_count: u32,
    pub updated_at_unix: i64,
}

pub(crate) fn migrate_v12_host_jobs_tables(tx: &Transaction<'_>) -> Result<(), String> {
    tx.execute_batch(
        "CREATE TABLE IF NOT EXISTS host_effect_jobs (
            job_id TEXT PRIMARY KEY,
            effect_operation_id TEXT NOT NULL UNIQUE,
            project_id TEXT NOT NULL,
            worktree_id TEXT NOT NULL,
            intent_json TEXT NOT NULL,
            state TEXT NOT NULL CHECK (state IN ('pending','starting','running','unknown','succeeded','failed')),
            process_identity_json TEXT,
            unknown_reason TEXT,
            receipt_json TEXT,
            attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
            updated_at_unix INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS host_effect_jobs_state_worktree
            ON host_effect_jobs(state, worktree_id);",
    )
    .map_err(|error| error.to_string())
}

impl ConfigStore {
    pub fn enqueue_host_job(
        &mut self,
        intent: &HostJobIntent,
        now_unix: i64,
    ) -> Result<HostJobRecord, String> {
        validate_intent(intent)?;
        let intent_json = serde_json::to_string(intent).map_err(|error| error.to_string())?;
        let existing = self
            .connection
            .query_row(
                "SELECT job_id, intent_json, state, process_identity_json, unknown_reason, receipt_json, attempt_count, updated_at_unix
                 FROM host_effect_jobs WHERE effect_operation_id = ?1",
                [&intent.effect_operation_id],
                row_to_host_job,
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if let Some(existing) = existing {
            if existing.intent != *intent {
                return Err(
                    "host job operation identity was reused for a different immutable intent"
                        .into(),
                );
            }
            return Ok(existing);
        }
        self.connection
            .execute(
                "INSERT INTO host_effect_jobs(job_id, effect_operation_id, project_id, worktree_id, intent_json, state, attempt_count, updated_at_unix)
                 VALUES (?1, ?2, ?3, ?4, ?5, 'pending', 0, ?6)",
                params![intent.job_id, intent.effect_operation_id, intent.project_id, intent.worktree_id, intent_json, now_unix],
            )
            .map_err(|error| error.to_string())?;
        self.host_job(&intent.job_id)?
            .ok_or_else(|| "inserted host job disappeared".into())
    }

    pub fn host_job(&self, job_id: &str) -> Result<Option<HostJobRecord>, String> {
        self.connection
            .query_row(
                "SELECT job_id, intent_json, state, process_identity_json, unknown_reason, receipt_json, attempt_count, updated_at_unix
                 FROM host_effect_jobs WHERE job_id = ?1",
                [job_id],
                row_to_host_job,
            )
            .optional()
            .map_err(|error| error.to_string())
    }

    pub fn host_jobs_in_states(
        &self,
        states: &[HostJobState],
    ) -> Result<Vec<HostJobRecord>, String> {
        let names = states.iter().map(state_name).collect::<Vec<_>>();
        if names.is_empty() {
            return Ok(Vec::new());
        }
        let placeholders = std::iter::repeat_n("?", names.len())
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "SELECT job_id, intent_json, state, process_identity_json, unknown_reason, receipt_json, attempt_count, updated_at_unix
             FROM host_effect_jobs WHERE state IN ({placeholders}) ORDER BY updated_at_unix, job_id"
        );
        let mut statement = self
            .connection
            .prepare(&sql)
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(rusqlite::params_from_iter(names.iter()), row_to_host_job)
            .map_err(|error| error.to_string())?;
        rows.map(|row| row.map_err(|error| error.to_string()))
            .collect()
    }

    pub fn start_host_job(&mut self, job_id: &str, now_unix: i64) -> Result<bool, String> {
        let changed = self.connection
            .execute(
                "UPDATE host_effect_jobs SET state = 'starting', attempt_count = attempt_count + 1, updated_at_unix = ?2
                 WHERE job_id = ?1 AND state = 'pending' AND attempt_count < json_extract(intent_json, '$.max_attempts')",
                params![job_id, now_unix],
            )
            .map_err(|error| error.to_string())?;
        Ok(changed == 1)
    }

    pub fn revert_host_job_start(&mut self, job_id: &str, now_unix: i64) -> Result<bool, String> {
        let changed = self.connection
            .execute(
                "UPDATE host_effect_jobs SET state = 'pending', attempt_count = attempt_count - 1, updated_at_unix = ?2
                 WHERE job_id = ?1 AND state = 'starting' AND process_identity_json IS NULL AND attempt_count > 0",
                params![job_id, now_unix],
            )
            .map_err(|error| error.to_string())?;
        Ok(changed == 1)
    }

    pub fn mark_host_job_running(
        &mut self,
        job_id: &str,
        identity: &ProcessIdentity,
        now_unix: i64,
    ) -> Result<bool, String> {
        if identity.pid == 0
            || identity.process_group_id != identity.pid
            || identity.start_identity.trim().is_empty()
            || identity.quality != ProcessIdentityQuality::KernelBirthToken
        {
            return Err(
                "host job process identity is not strong enough for restart reconciliation".into(),
            );
        }
        let identity_json = serde_json::to_string(identity).map_err(|error| error.to_string())?;
        let changed = self.connection
            .execute(
                "UPDATE host_effect_jobs SET state = 'running', process_identity_json = ?2, updated_at_unix = ?3
                 WHERE job_id = ?1 AND state = 'starting'",
                params![job_id, identity_json, now_unix],
            )
            .map_err(|error| error.to_string())?;
        if changed == 1 {
            return Ok(true);
        }
        let existing = self.host_job(job_id)?;
        Ok(existing.is_some_and(|record| {
            record.state == super::host_jobs::HostJobState::Running
                && record.process_identity.as_ref() == Some(identity)
        }))
    }

    pub fn mark_host_job_unknown(
        &mut self,
        job_id: &str,
        reason: &str,
        now_unix: i64,
    ) -> Result<bool, String> {
        if reason.trim().is_empty() {
            return Err("unknown host job requires a reason".into());
        }
        let changed = self.connection
            .execute(
                "UPDATE host_effect_jobs SET state = 'unknown', unknown_reason = ?2, updated_at_unix = ?3
                 WHERE job_id = ?1 AND state IN ('starting','running')",
                params![job_id, reason, now_unix],
            )
            .map_err(|error| error.to_string())?;
        Ok(changed == 1)
    }

    pub fn retry_absent_host_job(&mut self, job_id: &str, now_unix: i64) -> Result<bool, String> {
        let changed = self.connection
            .execute(
                "UPDATE host_effect_jobs SET state = 'pending', process_identity_json = NULL, unknown_reason = NULL, receipt_json = NULL, updated_at_unix = ?2
                 WHERE job_id = ?1 AND state = 'unknown'
                   AND json_extract(intent_json, '$.retry_when_absent') = 1
                   AND attempt_count < json_extract(intent_json, '$.max_attempts')",
                params![job_id, now_unix],
            )
            .map_err(|error| error.to_string())?;
        Ok(changed == 1)
    }

    pub fn finish_host_job(
        &mut self,
        job_id: &str,
        succeeded: bool,
        receipt_json: &str,
        now_unix: i64,
    ) -> Result<bool, String> {
        let state = if succeeded { "succeeded" } else { "failed" };
        let changed = self.connection
            .execute(
                "UPDATE host_effect_jobs SET state = ?2, receipt_json = ?3, unknown_reason = NULL, updated_at_unix = ?4
                 WHERE job_id = ?1 AND state IN ('running','starting')",
                params![job_id, state, receipt_json, now_unix],
            )
            .map_err(|error| error.to_string())?;
        Ok(changed == 1)
    }
}

fn validate_intent(intent: &HostJobIntent) -> Result<(), String> {
    for (name, value) in [
        ("job_id", intent.job_id.as_str()),
        ("effect_operation_id", intent.effect_operation_id.as_str()),
        ("project_id", intent.project_id.as_str()),
        ("subject_id", intent.subject_id.as_str()),
        ("worktree_id", intent.worktree_id.as_str()),
        ("kind", intent.kind.as_str()),
        ("request_digest", intent.request_digest.as_str()),
        ("configuration_digest", intent.configuration_digest.as_str()),
        ("head", intent.head.as_str()),
        ("source_digest", intent.source_digest.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(format!("host job {name} must not be empty"));
        }
    }
    if intent.max_attempts == 0 {
        return Err("host job max_attempts must be positive".into());
    }
    Ok(())
}

fn row_to_host_job(row: &rusqlite::Row<'_>) -> rusqlite::Result<HostJobRecord> {
    let job_id: String = row.get(0)?;
    let intent_json: String = row.get(1)?;
    let state_name: String = row.get(2)?;
    let process_identity_json: Option<String> = row.get(3)?;
    let unknown_reason: Option<String> = row.get(4)?;
    let receipt_json: Option<String> = row.get(5)?;
    let attempt_count: u32 = row.get(6)?;
    let updated_at_unix: i64 = row.get(7)?;
    let intent: HostJobIntent =
        serde_json::from_str(&intent_json).map_err(|_| rusqlite::Error::InvalidQuery)?;
    if intent.job_id != job_id {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let state = match state_name.as_str() {
        "pending" => HostJobState::Pending,
        "starting" => HostJobState::Starting,
        "running" => HostJobState::Running,
        "unknown" => HostJobState::Unknown {
            reason: unknown_reason
                .filter(|reason| !reason.trim().is_empty())
                .ok_or(rusqlite::Error::InvalidQuery)?,
        },
        "succeeded" if receipt_json.is_some() => HostJobState::Succeeded,
        "failed" if receipt_json.is_some() => HostJobState::Failed,
        _ => return Err(rusqlite::Error::InvalidQuery),
    };
    let process_identity = process_identity_json
        .map(|json| serde_json::from_str(&json).map_err(|_| rusqlite::Error::InvalidQuery))
        .transpose()?;
    Ok(HostJobRecord {
        intent,
        state,
        process_identity,
        receipt_json,
        attempt_count,
        updated_at_unix,
    })
}

fn state_name(state: &HostJobState) -> &'static str {
    match state {
        HostJobState::Pending => "pending",
        HostJobState::Starting => "starting",
        HostJobState::Running => "running",
        HostJobState::Unknown { .. } => "unknown",
        HostJobState::Succeeded => "succeeded",
        HostJobState::Failed => "failed",
    }
}

#[cfg(test)]
pub(crate) fn in_memory_test_store() -> super::ConfigStore {
    let mut connection = rusqlite::Connection::open_in_memory().unwrap();
    let tx = connection.transaction().unwrap();
    migrate_v12_host_jobs_tables(&tx).unwrap();
    tx.commit().unwrap();
    super::ConfigStore {
        connection,
        _machine_lock: super::MachineLock { _file: None },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::{ProcessIdentity, ProcessIdentityQuality};

    fn intent() -> HostJobIntent {
        HostJobIntent {
            job_id: "job-1".into(),
            effect_operation_id: "effect-1:hook-a".into(),
            project_id: "project-a".into(),
            subject_id: "hook-a".into(),
            worktree_id: "/worktree/a".into(),
            kind: "repository_hook".into(),
            request_digest: "request-digest".into(),
            configuration_digest: "config-digest".into(),
            head: "head-a".into(),
            source_digest: "source-a".into(),
            max_attempts: 2,
            retry_when_absent: true,
        }
    }

    fn identity() -> ProcessIdentity {
        ProcessIdentity {
            pid: 42,
            parent_pid: 1,
            process_group_id: 42,
            start_identity: "kernel-birth-token".into(),
            command: "hook".into(),
            quality: ProcessIdentityQuality::KernelBirthToken,
        }
    }

    #[test]
    fn durable_job_identity_and_uncertain_attempt_budget_are_enforced() {
        let mut store = in_memory_test_store();
        let job = intent();
        assert_eq!(
            store.enqueue_host_job(&job, 10).unwrap().state,
            HostJobState::Pending
        );
        assert_eq!(store.enqueue_host_job(&job, 11).unwrap().attempt_count, 0);
        let mut changed = job.clone();
        changed.head = "different-head".into();
        assert!(store.enqueue_host_job(&changed, 12).is_err());

        assert!(store.start_host_job(&job.job_id, 13).unwrap());
        assert!(
            store
                .mark_host_job_running(&job.job_id, &identity(), 14)
                .unwrap()
        );
        assert!(
            store
                .mark_host_job_unknown(&job.job_id, "controller stopped", 15)
                .unwrap()
        );
        assert!(store.retry_absent_host_job(&job.job_id, 16).unwrap());
        assert_eq!(
            store.host_job(&job.job_id).unwrap().unwrap().attempt_count,
            1
        );

        assert!(store.start_host_job(&job.job_id, 17).unwrap());
        assert!(
            store
                .mark_host_job_running(&job.job_id, &identity(), 18)
                .unwrap()
        );
        assert!(
            store
                .mark_host_job_unknown(&job.job_id, "controller stopped again", 19)
                .unwrap()
        );
        assert!(!store.retry_absent_host_job(&job.job_id, 20).unwrap());
    }

    #[test]
    fn refuses_weak_or_unbound_process_identity() {
        let mut store = in_memory_test_store();
        let job = intent();
        store.enqueue_host_job(&job, 10).unwrap();
        store.start_host_job(&job.job_id, 11).unwrap();
        let mut weak = identity();
        weak.quality = ProcessIdentityQuality::SecondPrecision;
        assert!(store.mark_host_job_running(&job.job_id, &weak, 12).is_err());
        assert!(
            store
                .mark_host_job_running(&job.job_id, &identity(), 12)
                .unwrap()
        );
        assert!(
            store
                .mark_host_job_running(&job.job_id, &identity(), 13)
                .unwrap()
        );
    }
}
