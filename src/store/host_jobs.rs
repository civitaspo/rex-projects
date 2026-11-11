use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};

use super::{ConfigStore, validate_active_generation};
use crate::domain::ids::Digest;
use crate::process::{ProcessIdentity, ProcessIdentityQuality};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostJobKind {
    RepositoryHook,
    OperationAdapter,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationMethod {
    Invoke,
    Find,
    Observe,
}

impl HostJobKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RepositoryHook => "repository_hook",
            Self::OperationAdapter => "operation_adapter",
        }
    }

    pub const fn requires_worktree_lease(self) -> bool {
        matches!(self, Self::RepositoryHook)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostJobIntent {
    pub job_id: String,
    pub effect_operation_id: String,
    pub project_id: String,
    pub subject_id: String,
    /// A repository path for hooks or the operation ID for adapter calls.
    pub lane_id: String,
    pub kind: HostJobKind,
    #[serde(default)]
    pub operation_method: Option<OperationMethod>,
    pub request_digest: String,
    pub configuration_digest: String,
    pub environment_snapshot_id: Digest,
    pub environment_policy_digest: Digest,
    pub head: String,
    pub source_digest: String,
    pub max_attempts: u32,
    pub retry_when_absent: bool,
}

impl HostJobIntent {
    /// Process absence may retry read-only operation calls and repository hooks.
    /// An invoke is never automatically retried, regardless of producer flags.
    pub fn permits_absence_retry(&self) -> bool {
        self.retry_when_absent
            && match self.kind {
                HostJobKind::RepositoryHook => true,
                HostJobKind::OperationAdapter => {
                    matches!(
                        self.operation_method,
                        Some(OperationMethod::Find | OperationMethod::Observe)
                    )
                }
            }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "$host_job_state",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum HostJobSystemReceipt {
    ProcessAbsentNoRetry {
        schema_version: u32,
        intent: HostJobIntent,
        process_identity: ProcessIdentity,
        attempt_count: u32,
    },
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
        owner_generation: u64,
        intent: &HostJobIntent,
        now_unix: i64,
    ) -> Result<HostJobRecord, String> {
        validate_intent(intent)?;
        let intent_json = serde_json::to_string(intent).map_err(|error| error.to_string())?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let existing = tx
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
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(existing);
        }
        tx.execute(
                "INSERT INTO host_effect_jobs(job_id, effect_operation_id, project_id, worktree_id, intent_json, state, attempt_count, updated_at_unix)
                 VALUES (?1, ?2, ?3, ?4, ?5, 'pending', 0, ?6)",
                params![intent.job_id, intent.effect_operation_id, intent.project_id, intent.lane_id, intent_json, now_unix],
            )
            .map_err(|error| error.to_string())?;
        let record = tx.query_row(
                "SELECT job_id, intent_json, state, process_identity_json, unknown_reason, receipt_json, attempt_count, updated_at_unix
                 FROM host_effect_jobs WHERE job_id = ?1",
                [&intent.job_id],
                row_to_host_job,
            )
            .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(record)
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

    pub fn start_host_job(
        &mut self,
        owner_generation: u64,
        job_id: &str,
        now_unix: i64,
    ) -> Result<bool, String> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let changed = tx.execute(
                "UPDATE host_effect_jobs SET state = 'starting', attempt_count = attempt_count + 1, updated_at_unix = ?2
                 WHERE job_id = ?1 AND state = 'pending' AND attempt_count < json_extract(intent_json, '$.max_attempts')",
                params![job_id, now_unix],
            ).map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(changed == 1)
    }

    pub fn revert_host_job_start(
        &mut self,
        owner_generation: u64,
        job_id: &str,
        now_unix: i64,
    ) -> Result<bool, String> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let changed = tx.execute(
                "UPDATE host_effect_jobs SET state = 'pending', attempt_count = attempt_count - 1, updated_at_unix = ?2
                 WHERE job_id = ?1 AND state = 'starting' AND process_identity_json IS NULL AND attempt_count > 0",
                params![job_id, now_unix],
            ).map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(changed == 1)
    }

    pub fn mark_host_job_running(
        &mut self,
        owner_generation: u64,
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
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let changed = tx.execute(
                "UPDATE host_effect_jobs SET state = 'running', process_identity_json = ?2, updated_at_unix = ?3
                 WHERE job_id = ?1 AND state = 'starting'",
                params![job_id, identity_json, now_unix],
            ).map_err(|error| error.to_string())?;
        if changed == 1 {
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(true);
        }
        let existing = tx.query_row(
            "SELECT job_id, intent_json, state, process_identity_json, unknown_reason, receipt_json, attempt_count, updated_at_unix
             FROM host_effect_jobs WHERE job_id = ?1",
            [job_id], row_to_host_job,
        ).optional().map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(existing.is_some_and(|record| {
            record.state == super::host_jobs::HostJobState::Running
                && record.process_identity.as_ref() == Some(identity)
        }))
    }

    pub fn mark_host_job_unknown(
        &mut self,
        owner_generation: u64,
        job_id: &str,
        reason: &str,
        now_unix: i64,
    ) -> Result<bool, String> {
        if reason.trim().is_empty() {
            return Err("unknown host job requires a reason".into());
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let changed = tx.execute(
                "UPDATE host_effect_jobs SET state = 'unknown', unknown_reason = ?2, updated_at_unix = ?3
                 WHERE job_id = ?1 AND state IN ('starting','running')",
                params![job_id, reason, now_unix],
            ).map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(changed == 1)
    }

    pub fn retry_absent_host_job(
        &mut self,
        owner_generation: u64,
        job_id: &str,
        now_unix: i64,
    ) -> Result<bool, String> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let record = tx.query_row(
            "SELECT job_id, intent_json, state, process_identity_json, unknown_reason, receipt_json, attempt_count, updated_at_unix
             FROM host_effect_jobs WHERE job_id = ?1",
            [job_id], row_to_host_job,
        ).optional().map_err(|error| error.to_string())?;
        if !record.is_some_and(|record| record.intent.permits_absence_retry()) {
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(false);
        }
        let changed = tx.execute(
                "UPDATE host_effect_jobs SET state = 'pending', process_identity_json = NULL, unknown_reason = NULL, receipt_json = NULL, updated_at_unix = ?2
                 WHERE job_id = ?1 AND state = 'unknown'
                   AND json_extract(intent_json, '$.retry_when_absent') = 1
                   AND attempt_count < json_extract(intent_json, '$.max_attempts')",
                params![job_id, now_unix],
            ).map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(changed == 1)
    }

    pub fn mark_host_job_process_absent(
        &mut self,
        owner_generation: u64,
        job_id: &str,
        expected_intent: &HostJobIntent,
        expected_identity: &ProcessIdentity,
        now_unix: i64,
    ) -> Result<bool, String> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let record = tx.query_row(
            "SELECT job_id, intent_json, state, process_identity_json, unknown_reason, receipt_json, attempt_count, updated_at_unix
             FROM host_effect_jobs WHERE job_id = ?1",
            [job_id], row_to_host_job,
        ).optional().map_err(|error| error.to_string())?;
        let Some(record) = record else {
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(false);
        };
        if record.intent != *expected_intent
            || record.process_identity.as_ref() != Some(expected_identity)
            || !matches!(record.state, HostJobState::Unknown { .. })
        {
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(false);
        }
        let receipt = HostJobSystemReceipt::ProcessAbsentNoRetry {
            schema_version: 1,
            intent: record.intent,
            process_identity: expected_identity.clone(),
            attempt_count: record.attempt_count,
        };
        let receipt_json = serde_json::to_string(&receipt).map_err(|error| error.to_string())?;
        let changed = tx.execute(
            "UPDATE host_effect_jobs SET state='failed', receipt_json=?2, unknown_reason=NULL, updated_at_unix=?3
             WHERE job_id=?1 AND state='unknown'",
            params![job_id, receipt_json, now_unix],
        ).map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(changed == 1)
    }

    pub fn finish_host_job(
        &mut self,
        owner_generation: u64,
        job_id: &str,
        succeeded: bool,
        receipt_json: &str,
        now_unix: i64,
    ) -> Result<bool, String> {
        let state = if succeeded { "succeeded" } else { "failed" };
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let changed = tx.execute(
                "UPDATE host_effect_jobs SET state = ?2, receipt_json = ?3, unknown_reason = NULL, updated_at_unix = ?4
                 WHERE job_id = ?1 AND state IN ('running','starting')",
                params![job_id, state, receipt_json, now_unix],
            ).map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(changed == 1)
    }
}

fn validate_intent(intent: &HostJobIntent) -> Result<(), String> {
    for (name, value) in [
        ("job_id", intent.job_id.as_str()),
        ("effect_operation_id", intent.effect_operation_id.as_str()),
        ("project_id", intent.project_id.as_str()),
        ("subject_id", intent.subject_id.as_str()),
        ("lane_id", intent.lane_id.as_str()),
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
    match (intent.kind, intent.operation_method) {
        (HostJobKind::RepositoryHook, None) => {}
        (HostJobKind::OperationAdapter, Some(OperationMethod::Invoke)) => {
            if intent.max_attempts != 1 {
                return Err("operation.invoke host jobs must have exactly one host attempt".into());
            }
        }
        (HostJobKind::OperationAdapter, Some(OperationMethod::Find | OperationMethod::Observe)) => {
            if intent.max_attempts > 2 {
                return Err(
                    "read-only operation host jobs may have at most two host attempts".into(),
                );
            }
        }
        _ => return Err("host job kind and operation method do not match".into()),
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
    tx.execute_batch(
        "CREATE TABLE controller_owners (
            singleton INTEGER PRIMARY KEY CHECK(singleton=1),
            generation INTEGER NOT NULL,
            stopped_at_unix INTEGER
         );
         INSERT INTO controller_owners(singleton,generation,stopped_at_unix) VALUES (1,1,NULL);",
    )
    .unwrap();
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
            lane_id: "/worktree/a".into(),
            kind: HostJobKind::RepositoryHook,
            operation_method: None,
            request_digest: "request-digest".into(),
            configuration_digest: "config-digest".into(),
            environment_snapshot_id: Digest::parse("e".repeat(64)).unwrap(),
            environment_policy_digest: Digest::parse("f".repeat(64)).unwrap(),
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
            store.enqueue_host_job(1, &job, 10).unwrap().state,
            HostJobState::Pending
        );
        assert_eq!(
            store.enqueue_host_job(1, &job, 11).unwrap().attempt_count,
            0
        );
        let mut changed = job.clone();
        changed.head = "different-head".into();
        assert!(store.enqueue_host_job(1, &changed, 12).is_err());

        assert!(store.start_host_job(1, &job.job_id, 13).unwrap());
        assert!(
            store
                .mark_host_job_running(1, &job.job_id, &identity(), 14)
                .unwrap()
        );
        assert!(
            store
                .mark_host_job_unknown(1, &job.job_id, "controller stopped", 15)
                .unwrap()
        );
        assert!(store.retry_absent_host_job(1, &job.job_id, 16).unwrap());
        assert_eq!(
            store.host_job(&job.job_id).unwrap().unwrap().attempt_count,
            1
        );

        assert!(store.start_host_job(1, &job.job_id, 17).unwrap());
        assert!(
            store
                .mark_host_job_running(1, &job.job_id, &identity(), 18)
                .unwrap()
        );
        assert!(
            store
                .mark_host_job_unknown(1, &job.job_id, "controller stopped again", 19)
                .unwrap()
        );
        assert!(!store.retry_absent_host_job(1, &job.job_id, 20).unwrap());
    }

    #[test]
    fn refuses_weak_or_unbound_process_identity() {
        let mut store = in_memory_test_store();
        let job = intent();
        store.enqueue_host_job(1, &job, 10).unwrap();
        store.start_host_job(1, &job.job_id, 11).unwrap();
        let mut weak = identity();
        weak.quality = ProcessIdentityQuality::SecondPrecision;
        assert!(
            store
                .mark_host_job_running(1, &job.job_id, &weak, 12)
                .is_err()
        );
        assert!(
            store
                .mark_host_job_running(1, &job.job_id, &identity(), 12)
                .unwrap()
        );
        assert!(
            store
                .mark_host_job_running(1, &job.job_id, &identity(), 13)
                .unwrap()
        );
    }

    #[test]
    fn invoke_cannot_retry_after_process_absence_even_when_retry_flag_is_true() {
        let mut store = in_memory_test_store();
        let mut job = intent();
        job.kind = HostJobKind::OperationAdapter;
        job.operation_method = Some(OperationMethod::Invoke);
        job.max_attempts = 1;
        job.retry_when_absent = true;
        job.lane_id = "operation-1".into();
        job.effect_operation_id = "operation-1:invoke:1".into();
        job.job_id = "invoke-job".into();
        store.enqueue_host_job(1, &job, 10).unwrap();
        store.start_host_job(1, &job.job_id, 11).unwrap();
        store
            .mark_host_job_running(1, &job.job_id, &identity(), 12)
            .unwrap();
        store
            .mark_host_job_unknown(1, &job.job_id, "lost reply", 13)
            .unwrap();

        assert!(!store.retry_absent_host_job(1, &job.job_id, 14).unwrap());
        let record = store.host_job(&job.job_id).unwrap().unwrap();
        assert_eq!(record.attempt_count, 1);
        assert!(matches!(record.state, HostJobState::Unknown { .. }));
    }

    #[test]
    fn read_only_operation_retries_only_within_its_immutable_budget() {
        let mut store = in_memory_test_store();
        let mut job = intent();
        job.kind = HostJobKind::OperationAdapter;
        job.operation_method = Some(OperationMethod::Find);
        job.max_attempts = 2;
        job.retry_when_absent = true;
        job.lane_id = "operation-1".into();
        job.effect_operation_id = "operation-1:find:1".into();
        job.job_id = "find-job".into();
        store.enqueue_host_job(1, &job, 10).unwrap();
        store.start_host_job(1, &job.job_id, 11).unwrap();
        store
            .mark_host_job_running(1, &job.job_id, &identity(), 12)
            .unwrap();
        store
            .mark_host_job_unknown(1, &job.job_id, "lost reply", 13)
            .unwrap();

        assert!(store.retry_absent_host_job(1, &job.job_id, 14).unwrap());
        let record = store.host_job(&job.job_id).unwrap().unwrap();
        assert_eq!(record.attempt_count, 1);
        assert_eq!(record.state, HostJobState::Pending);
        store.start_host_job(1, &job.job_id, 15).unwrap();
        store
            .mark_host_job_running(1, &job.job_id, &identity(), 16)
            .unwrap();
        store
            .mark_host_job_unknown(1, &job.job_id, "second lost reply", 17)
            .unwrap();

        assert!(!store.retry_absent_host_job(1, &job.job_id, 18).unwrap());
        assert_eq!(
            store.host_job(&job.job_id).unwrap().unwrap().attempt_count,
            2
        );
    }

    #[test]
    fn stale_owner_generation_cannot_mutate_host_jobs() {
        let mut store = in_memory_test_store();
        let job = intent();
        store
            .connection
            .execute(
                "UPDATE controller_owners SET generation=2 WHERE singleton=1",
                [],
            )
            .unwrap();

        assert!(store.enqueue_host_job(1, &job, 10).is_err());
        assert!(store.host_job(&job.job_id).unwrap().is_none());
    }
}
