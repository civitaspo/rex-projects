//! Durable requests and controller-owned transitions for provider qualification jobs.

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::domain::ids::{Digest, ProfileId, ProjectId};
use crate::domain::types::Role;
use crate::store::{ConfigStore, now_unix, validate_active_generation};

const MAX_PROVIDER_QUALIFICATION_JOBS: usize = 32;
const MAX_QUALIFICATION_REQUEST_ID_BYTES: usize = 255;
type ProviderQualificationJobRow = (
    String,
    String,
    String,
    String,
    String,
    u64,
    String,
    String,
    String,
    u64,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    i64,
    i64,
);

/// Exact applied-config identity requested by a human. The CLI cannot select an
/// executable, profile body, schema, permission mode, or qualification result.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderQualificationRequest {
    pub request_id: String,
    pub project_id: ProjectId,
    pub role: Role,
    pub profile_id: ProfileId,
    pub profile_digest: Digest,
    pub config_revision: u64,
    pub config_digest: Digest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderQualificationJobStatus {
    Queued,
    Running,
    Unknown,
    Verified,
    Failed,
}

impl ProviderQualificationJobStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Unknown => "unknown",
            Self::Verified => "verified",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderQualificationJob {
    pub request: ProviderQualificationRequest,
    pub request_digest: Digest,
    pub status: ProviderQualificationJobStatus,
    pub controller_generation: u64,
    pub rex_session_id: Option<String>,
    pub rex_window_id: Option<String>,
    pub rex_block_id: Option<String>,
    pub result_json: Option<String>,
    pub evidence_digest: Option<Digest>,
    pub created_at_unix: i64,
    pub updated_at_unix: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QualificationClaim {
    Claimed {
        job: Box<ProviderQualificationJob>,
        slot_index: u32,
    },
    CapacityUnavailable,
    NoQueuedJob,
}

#[derive(Serialize)]
struct RequestIdentity<'a> {
    request_id: &'a str,
    project_id: &'a ProjectId,
    role: Role,
    profile_id: &'a ProfileId,
    profile_digest: &'a Digest,
    config_revision: u64,
    config_digest: &'a Digest,
}

pub fn request_digest(request: &ProviderQualificationRequest) -> Result<Digest, String> {
    let identity = RequestIdentity {
        request_id: &request.request_id,
        project_id: &request.project_id,
        role: request.role,
        profile_id: &request.profile_id,
        profile_digest: &request.profile_digest,
        config_revision: request.config_revision,
        config_digest: &request.config_digest,
    };
    let bytes = serde_json::to_vec(&identity).map_err(|error| error.to_string())?;
    Digest::parse(format!("{:x}", Sha256::digest(bytes)))
}

impl ProviderQualificationRequest {
    pub fn validate(&self) -> Result<(), String> {
        if self.request_id.is_empty()
            || self.request_id.len() > MAX_QUALIFICATION_REQUEST_ID_BYTES
            || self.request_id.chars().any(char::is_control)
            || self.config_revision == 0
        {
            return Err("provider qualification request identity is invalid".into());
        }
        Ok(())
    }
}

impl ConfigStore {
    /// Terminally fail a claimed job only when its deterministic local preflight
    /// failed before any Rex session was created. The slot release and job
    /// receipt are one fenced transaction.
    pub fn fail_provider_qualification_before_launch(
        &mut self,
        owner_generation: u64,
        request_id: &str,
        reason: &str,
    ) -> Result<(), String> {
        if reason.is_empty() || reason.len() > 512 || reason.chars().any(char::is_control) {
            return Err("provider qualification prelaunch failure reason is invalid".into());
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let job = read_job(&tx, request_id)?
            .ok_or("provider qualification prelaunch job does not exist")?;
        if job.status != ProviderQualificationJobStatus::Running
            || job.controller_generation != owner_generation
            || job.rex_session_id.is_some()
            || job.rex_window_id.is_some()
            || job.rex_block_id.is_some()
        {
            return Err("provider qualification prelaunch identity is ambiguous".into());
        }
        let result = serde_json::json!({
            "schema_version": 1,
            "request_id": request_id,
            "outcome": "failed",
            "stage": "prelaunch",
            "reason": reason,
        });
        let bounded_result_json =
            serde_json::to_string(&result).map_err(|error| error.to_string())?;
        let evidence_digest = Digest::parse(format!(
            "{:x}",
            Sha256::digest(bounded_result_json.as_bytes())
        ))?;
        let changed = tx.execute(
            "UPDATE provider_qualification_jobs SET status='failed',result_json=?3,evidence_digest=?4,updated_at_unix=?5 WHERE request_id=?1 AND controller_generation=?2 AND status='running' AND rex_session_id IS NULL AND rex_window_id IS NULL AND rex_block_id IS NULL",
            params![request_id, owner_generation, bounded_result_json, evidence_digest.as_str(), now_unix()?],
        ).map_err(|error| error.to_string())?;
        if changed != 1 {
            return Err("provider qualification changed during prelaunch failure".into());
        }
        let released = tx.execute(
            "UPDATE execution_slots SET disposition='released' WHERE owner_kind='provider_qualification' AND owner_id=?1 AND controller_generation=?2 AND disposition='launch_pending'",
            params![request_id, owner_generation],
        ).map_err(|error| error.to_string())?;
        if released != 1 {
            return Err(
                "provider qualification launch-pending slot is missing or ambiguous".into(),
            );
        }
        tx.commit().map_err(|error| error.to_string())
    }

    /// Queue an exact, idempotent request through the current machine owner.
    /// This is the only external write to the job table; execution and result
    /// transitions remain fenced to the foreground controller generation.
    pub fn enqueue_provider_qualification(
        &mut self,
        owner_generation: u64,
        request: &ProviderQualificationRequest,
    ) -> Result<Digest, String> {
        request.validate()?;
        let digest = request_digest(request)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let project: Option<(u64, String)> = tx
            .query_row(
                "SELECT config_revision,config_digest FROM projects WHERE project_id=?1",
                [request.project_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if project != Some((request.config_revision, request.config_digest.to_string())) {
            return Err(
                "provider qualification request does not match the registered Project config"
                    .into(),
            );
        }
        let now = now_unix()?;
        tx.execute(
            "INSERT INTO provider_qualification_jobs(request_id,project_id,role,profile_id,profile_digest,config_revision,config_digest,request_digest,status,controller_generation,created_at_unix,updated_at_unix) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,'queued',?9,?10,?10) ON CONFLICT(request_id) DO NOTHING",
            params![request.request_id, request.project_id.as_str(), serde_json::to_value(request.role).map_err(|error| error.to_string())?.as_str().unwrap_or_default(), request.profile_id.as_str(), request.profile_digest.as_str(), request.config_revision, request.config_digest.as_str(), digest.as_str(), owner_generation, now],
        )
        .map_err(|error| error.to_string())?;
        let stored = read_job(&tx, &request.request_id)?
            .ok_or("provider qualification request was not stored")?;
        if stored.request != *request || stored.request_digest != digest {
            return Err(
                "provider qualification request ID was reused with different content".into(),
            );
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(digest)
    }

    /// Fence a queued job to the current controller and reserve an ordinary
    /// Agent slot before any Rex or provider side effect is attempted.
    pub fn claim_provider_qualification(
        &mut self,
        owner_generation: u64,
        global_capacity: u32,
        project_capacity: u32,
    ) -> Result<QualificationClaim, String> {
        if global_capacity == 0 || project_capacity == 0 {
            return Err("provider qualification capacity must be positive".into());
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let request_id: Option<String> = tx
            .query_row(
                "SELECT request_id FROM provider_qualification_jobs WHERE status='queued' ORDER BY created_at_unix,request_id LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let Some(request_id) = request_id else {
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(QualificationClaim::NoQueuedJob);
        };
        let job =
            read_job(&tx, &request_id)?.ok_or("queued provider qualification job disappeared")?;
        let global_used: u32 = tx
            .query_row(
                "SELECT COUNT(*) FROM execution_slots WHERE pool='agent' AND disposition!='released'",
                [],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        let project_used: u32 = tx
            .query_row(
                "SELECT COUNT(*) FROM execution_slots WHERE project_id=?1 AND disposition!='released'",
                [job.request.project_id.as_str()],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        if global_used >= global_capacity || project_used >= project_capacity {
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(QualificationClaim::CapacityUnavailable);
        }
        let used = {
            let mut statement = tx
                .prepare("SELECT slot_index FROM execution_slots WHERE pool='agent' AND disposition!='released'")
                .map_err(|error| error.to_string())?;
            statement
                .query_map([], |row| row.get::<_, u32>(0))
                .map_err(|error| error.to_string())?
                .collect::<Result<std::collections::BTreeSet<_>, _>>()
                .map_err(|error| error.to_string())?
        };
        let Some(slot_index) = (0..global_capacity).find(|slot| !used.contains(slot)) else {
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(QualificationClaim::CapacityUnavailable);
        };
        let now = now_unix()?;
        let changed = tx
            .execute(
                "UPDATE provider_qualification_jobs SET status='running',controller_generation=?2,updated_at_unix=?3 WHERE request_id=?1 AND status='queued'",
                params![request_id, owner_generation, now],
            )
            .map_err(|error| error.to_string())?;
        if changed != 1 {
            return Err("provider qualification job changed while being claimed".into());
        }
        let reserved = tx
            .execute(
                "INSERT INTO execution_slots(pool,slot_index,project_id,ticket_run_id,owner_kind,owner_id,reservation_epoch,controller_generation,disposition) VALUES ('agent',?1,?2,NULL,'provider_qualification',?3,1,?4,'launch_pending') ON CONFLICT(pool,slot_index) DO UPDATE SET project_id=excluded.project_id,ticket_run_id=NULL,owner_kind=excluded.owner_kind,owner_id=excluded.owner_id,reservation_epoch=excluded.reservation_epoch,controller_generation=excluded.controller_generation,process_identity_json=NULL,disposition='launch_pending' WHERE execution_slots.disposition='released'",
                params![slot_index, job.request.project_id.as_str(), request_id, owner_generation],
            )
            .map_err(|error| error.to_string())?;
        if reserved != 1 {
            return Err(
                "provider qualification execution slot changed while being reserved".into(),
            );
        }
        let claimed =
            read_job(&tx, &request_id)?.ok_or("claimed provider qualification job disappeared")?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(QualificationClaim::Claimed {
            job: Box::new(claimed),
            slot_index,
        })
    }

    /// On restart, a job already marked running is uncertain. It keeps its
    /// execution slot and must be reconciled from Rex and the private spool;
    /// this method never queues a second provider launch.
    pub fn mark_orphaned_provider_qualification_jobs(
        &mut self,
        owner_generation: u64,
    ) -> Result<usize, String> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let now = now_unix()?;
        let changed = tx
            .execute(
                "UPDATE provider_qualification_jobs SET status='unknown',controller_generation=?1,updated_at_unix=?2 WHERE status IN ('running','unknown') AND controller_generation!=?1",
                params![owner_generation, now],
            )
            .map_err(|error| error.to_string())?;
        tx.execute(
            "UPDATE execution_slots SET disposition='unknown',controller_generation=?1 WHERE owner_kind='provider_qualification' AND controller_generation!=?1 AND disposition IN ('launch_pending','live','parked','unknown')",
            [owner_generation],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(changed)
    }

    pub fn bind_provider_qualification_rex(
        &mut self,
        owner_generation: u64,
        request_id: &str,
        session_id: &str,
        window_id: &str,
        block_id: &str,
    ) -> Result<(), String> {
        if [session_id, window_id, block_id]
            .iter()
            .any(|value| value.is_empty() || value.chars().any(char::is_control))
        {
            return Err("provider qualification Rex binding is invalid".into());
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let existing: Option<(Option<String>, Option<String>, Option<String>)> = tx
            .query_row(
                "SELECT rex_session_id,rex_window_id,rex_block_id FROM provider_qualification_jobs WHERE request_id=?1 AND controller_generation=?2 AND status IN ('running','unknown')",
                params![request_id, owner_generation],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let existing =
            existing.ok_or("provider qualification job is not running under this controller")?;
        let binding = (
            session_id.to_owned(),
            window_id.to_owned(),
            block_id.to_owned(),
        );
        if let (Some(old_session), Some(old_window), Some(old_block)) = &existing {
            if (old_session, old_window, old_block) != (&binding.0, &binding.1, &binding.2) {
                return Err(
                    "provider qualification Rex binding conflicts with its persisted identity"
                        .into(),
                );
            }
        } else if existing != (None, None, None) {
            return Err("provider qualification Rex binding is incomplete and ambiguous".into());
        } else {
            let changed = tx
                .execute(
                    "UPDATE provider_qualification_jobs SET rex_session_id=?3,rex_window_id=?4,rex_block_id=?5,updated_at_unix=?6 WHERE request_id=?1 AND controller_generation=?2 AND status IN ('running','unknown') AND rex_session_id IS NULL AND rex_window_id IS NULL AND rex_block_id IS NULL",
                    params![request_id, owner_generation, session_id, window_id, block_id, now_unix()?],
                )
                .map_err(|error| error.to_string())?;
            if changed != 1 {
                return Err("provider qualification Rex binding changed concurrently".into());
            }
        }
        tx.commit().map_err(|error| error.to_string())
    }

    pub fn mark_provider_qualification_unknown(
        &mut self,
        owner_generation: u64,
        request_id: &str,
    ) -> Result<(), String> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let changed = tx.execute(
            "UPDATE provider_qualification_jobs SET status='unknown',updated_at_unix=?3 WHERE request_id=?1 AND controller_generation=?2 AND status='running'",
            params![request_id, owner_generation, now_unix()?],
        ).map_err(|error| error.to_string())?;
        if changed != 1 {
            return Err("provider qualification job is not running under this controller".into());
        }
        tx.execute(
            "UPDATE execution_slots SET disposition='unknown' WHERE owner_kind='provider_qualification' AND owner_id=?1 AND controller_generation=?2 AND disposition!='released'",
            params![request_id, owner_generation],
        ).map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())
    }

    pub fn finish_provider_qualification_job(
        &mut self,
        owner_generation: u64,
        request_id: &str,
        status: ProviderQualificationJobStatus,
        bounded_result_json: &str,
        evidence_digest: &Digest,
        cleanup_confirmed: bool,
    ) -> Result<(), String> {
        if !matches!(
            status,
            ProviderQualificationJobStatus::Verified | ProviderQualificationJobStatus::Failed
        ) || bounded_result_json.len() > 1_048_576
            || !cleanup_confirmed
        {
            return Err("provider qualification may finish only with a bounded terminal result and confirmed cleanup".into());
        }
        let calculated_evidence = Digest::parse(format!(
            "{:x}",
            Sha256::digest(bounded_result_json.as_bytes())
        ))?;
        if calculated_evidence != *evidence_digest {
            return Err(
                "provider qualification result digest does not match the stored evidence digest"
                    .into(),
            );
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        if status == ProviderQualificationJobStatus::Verified {
            let job =
                read_job(&tx, request_id)?.ok_or("provider qualification job does not exist")?;
            let receipt: crate::launch::ProviderQualification =
                crate::protocol::parse_unique(bounded_result_json.as_bytes()).map_err(|error| {
                    format!("verified qualification result is invalid: {error}")
                })?;
            receipt.validate_for_unattended_launch()?;
            if receipt.project_id != job.request.project_id
                || receipt.profile_id != job.request.profile_id
                || receipt.profile_digest != job.request.profile_digest
            {
                return Err(
                    "verified qualification receipt does not match the job request identity".into(),
                );
            }
            let receipt_digest = receipt.canonical_digest()?;
            let stored: Option<String> = tx
                .query_row(
                    "SELECT receipt_json FROM provider_qualifications WHERE receipt_digest=?1",
                    [receipt_digest.as_str()],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|error| error.to_string())?;
            let stored = stored.ok_or(
                "verified qualification receipt was not persisted before completing its job",
            )?;
            let stored_receipt: crate::launch::ProviderQualification =
                crate::protocol::parse_unique(stored.as_bytes())
                    .map_err(|error| error.to_string())?;
            if stored_receipt != receipt || stored_receipt.canonical_digest()? != receipt_digest {
                return Err(
                    "persisted provider qualification does not match job completion evidence"
                        .into(),
                );
            }
        }
        let changed = tx
            .execute(
                "UPDATE provider_qualification_jobs SET status=?3,result_json=?4,evidence_digest=?5,updated_at_unix=?6 WHERE request_id=?1 AND controller_generation=?2 AND status IN ('queued','running','unknown')",
                params![request_id, owner_generation, status.as_str(), bounded_result_json, evidence_digest.as_str(), now_unix()?],
            )
            .map_err(|error| error.to_string())?;
        if changed != 1 {
            return Err(
                "provider qualification job is not eligible for terminal completion".into(),
            );
        }
        tx.execute(
            "UPDATE execution_slots SET disposition='released',controller_generation=?2 WHERE owner_kind='provider_qualification' AND owner_id=?1 AND disposition!='released'",
            params![request_id, owner_generation],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())
    }

    pub fn provider_qualification_job(
        &self,
        request_id: &str,
    ) -> Result<Option<ProviderQualificationJob>, String> {
        read_job(&self.connection, request_id)
    }

    pub fn provider_qualification_jobs_to_reconcile(
        &self,
        limit: usize,
    ) -> Result<Vec<ProviderQualificationJob>, String> {
        if limit == 0 || limit > MAX_PROVIDER_QUALIFICATION_JOBS {
            return Err("provider qualification reconcile limit is invalid".into());
        }
        let mut statement = self.connection.prepare(
            "SELECT request_id FROM provider_qualification_jobs WHERE status IN ('running','unknown') ORDER BY created_at_unix,request_id LIMIT ?1",
        ).map_err(|error| error.to_string())?;
        let ids = statement
            .query_map([limit as u64], |row| row.get::<_, String>(0))
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        ids.into_iter()
            .map(|id| {
                read_job(&self.connection, &id)?
                    .ok_or_else(|| "provider qualification job disappeared".to_owned())
            })
            .collect()
    }
}

fn read_job(
    connection: &Connection,
    request_id: &str,
) -> Result<Option<ProviderQualificationJob>, String> {
    let row: Option<ProviderQualificationJobRow> = connection.query_row(
        "SELECT request_id,project_id,role,profile_id,profile_digest,config_revision,config_digest,request_digest,status,controller_generation,rex_session_id,rex_window_id,rex_block_id,result_json,evidence_digest,created_at_unix,updated_at_unix FROM provider_qualification_jobs WHERE request_id=?1",
        [request_id],
        |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?,row.get(9)?,row.get(10)?,row.get(11)?,row.get(12)?,row.get(13)?,row.get(14)?,row.get(15)?,row.get(16)?)),
    ).optional().map_err(|error| error.to_string())?;
    row.map(
        |(
            request_id,
            project,
            role,
            profile_id,
            profile_digest,
            config_revision,
            config_digest,
            stored_request_digest,
            status,
            generation,
            session,
            window,
            block,
            result,
            evidence,
            created,
            updated,
        )| {
            let request = ProviderQualificationRequest {
                request_id,
                project_id: ProjectId::parse(project)?,
                role: serde_json::from_value(serde_json::Value::String(role))
                    .map_err(|error| error.to_string())?,
                profile_id: ProfileId::parse(profile_id)?,
                profile_digest: Digest::parse(profile_digest)?,
                config_revision,
                config_digest: Digest::parse(config_digest)?,
            };
            request.validate()?;
            let stored_request_digest = Digest::parse(stored_request_digest)?;
            if request_digest(&request)? != stored_request_digest {
                return Err("provider qualification request digest mismatch".into());
            }
            let status = match status.as_str() {
                "queued" => ProviderQualificationJobStatus::Queued,
                "running" => ProviderQualificationJobStatus::Running,
                "unknown" => ProviderQualificationJobStatus::Unknown,
                "verified" => ProviderQualificationJobStatus::Verified,
                "failed" => ProviderQualificationJobStatus::Failed,
                _ => return Err("provider qualification job has an unknown status".into()),
            };
            Ok(ProviderQualificationJob {
                request,
                request_digest: stored_request_digest,
                status,
                controller_generation: generation,
                rex_session_id: session,
                rex_window_id: window,
                rex_block_id: block,
                result_json: result,
                evidence_digest: evidence.map(Digest::parse).transpose()?,
                created_at_unix: created,
                updated_at_unix: updated,
            })
        },
    )
    .transpose()
}
