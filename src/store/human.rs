//! Durable human review storage and schema v8. The migration is intentionally not wired into
//! `ConfigStore::open` until PR3d's schema v7 migration lands.

use std::fs;
use std::path::Path;

use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::domain::ids::{Digest, HumanRequestId, ProjectId, TicketRunId};
use crate::human_runtime::{
    HumanDecisionChoice, HumanDecisionIntent, HumanPurpose, HumanRequestLifecycle,
    HumanRequestSummary, HumanRuntimeRequest, HumanSubjectBinding, HumanSubjectKind,
    HumanWakeTarget,
};

use super::{ConfigStore, validate_active_generation};

const HUMAN_SCHEMA_VERSION: i64 = 8;
const MAX_PENDING_DECISIONS: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state", content = "detail")]
pub enum HumanDecisionResult {
    Applied,
    Stale { reason: String },
    Expired,
}

/// Opaque authority returned only by `accepted_human_approval` after durable validation.
/// It intentionally cannot be deserialized or constructed outside this module.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanApprovalReceipt {
    request_id: HumanRequestId,
    response_id: String,
    subject_digest: Digest,
    configuration_digest: Digest,
    policy_digest: Digest,
    choice: HumanDecisionChoice,
    approved: bool,
    decided_at_unix: u64,
    request_expires_at_unix: u64,
}

impl HumanApprovalReceipt {
    pub fn request_id(&self) -> &HumanRequestId {
        &self.request_id
    }
    pub fn response_id(&self) -> &str {
        &self.response_id
    }
    pub fn subject_digest(&self) -> &Digest {
        &self.subject_digest
    }
    pub fn configuration_digest(&self) -> &Digest {
        &self.configuration_digest
    }
    pub fn policy_digest(&self) -> &Digest {
        &self.policy_digest
    }
    pub fn choice(&self) -> HumanDecisionChoice {
        self.choice
    }
    pub fn approved(&self) -> bool {
        self.approved
    }
    pub fn decided_at_unix(&self) -> u64 {
        self.decided_at_unix
    }
    pub fn request_expires_at_unix(&self) -> u64 {
        self.request_expires_at_unix
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedApprovalReceipt {
    request_id: HumanRequestId,
    response_id: String,
    subject_digest: Digest,
    configuration_digest: Digest,
    policy_digest: Digest,
    choice: HumanDecisionChoice,
    approved: bool,
    decided_at_unix: u64,
    request_expires_at_unix: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanQueueReceipt {
    pub request_id: HumanRequestId,
    pub response_id: String,
    pub lifecycle: HumanRequestLifecycle,
    /// Queueing is not approval. Only `HumanDecisionResult::Applied` is authoritative.
    pub accepted_for_validation: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueuedHumanDecision {
    pub request: HumanRuntimeRequest,
    pub intent: HumanDecisionIntent,
}

#[derive(Debug)]
enum TicketValidationError {
    Stale(String),
    Storage(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanPresentationReceipt {
    pub request_id: HumanRequestId,
    pub presenter_kind: String,
    pub reference: Option<String>,
    pub location: Option<String>,
    pub outcome: String,
    pub detail: Option<String>,
    pub attempted_at_unix: u64,
}

impl ConfigStore {
    /// Apply v8 after v7. The controller owns migration ordering and updates the shared schema
    /// version only after this transaction succeeds.
    pub fn migrate_human_v8(connection: &mut Connection) -> Result<(), String> {
        let current: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(|error| error.to_string())?;
        if current != HUMAN_SCHEMA_VERSION - 1 {
            return Err(format!(
                "human migration requires schema v7, found {current}"
            ));
        }
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        tx.execute_batch(
            "CREATE TABLE human_requests (
                request_id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL REFERENCES projects(project_id),
                purpose TEXT NOT NULL CHECK(purpose IN ('plan_decision','ticket_review','operation_approval','profile_promotion','goal_change','goal_completion','project_configuration','release_decision')),
                subject_kind TEXT NOT NULL CHECK(subject_kind IN ('ticket_run','plan','operation','profile','goal','project_configuration','release')),
                subject_id TEXT NOT NULL,
                subject_revision INTEGER NOT NULL CHECK(subject_revision >= 0),
                subject_digest TEXT NOT NULL,
                material_digest TEXT NOT NULL,
                configuration_digest TEXT NOT NULL,
                policy_digest TEXT NOT NULL,
                bundle_digest TEXT NOT NULL,
                request_json TEXT NOT NULL CHECK(length(request_json) <= 1048576),
                artifact_path TEXT NOT NULL,
                presentation_reference TEXT,
                lifecycle TEXT NOT NULL CHECK(lifecycle IN ('pending','presented','response_queued','decided','stale','expired','cancelled')),
                created_at_unix INTEGER NOT NULL,
                expires_at_unix INTEGER NOT NULL CHECK(expires_at_unix > created_at_unix),
                decided_at_unix INTEGER,
                UNIQUE(project_id, purpose, subject_kind, subject_id, subject_revision, subject_digest, request_id)
            );
            CREATE INDEX human_requests_project_lifecycle ON human_requests(project_id, lifecycle, created_at_unix);
            CREATE INDEX human_requests_subject ON human_requests(project_id, subject_kind, subject_id, subject_revision, subject_digest);
            CREATE TABLE human_decision_intents (
                response_id TEXT PRIMARY KEY,
                request_id TEXT NOT NULL REFERENCES human_requests(request_id),
                content_digest TEXT NOT NULL,
                intent_json TEXT NOT NULL CHECK(length(intent_json) <= 65536),
                lifecycle TEXT NOT NULL CHECK(lifecycle IN ('queued','applied','stale','expired')),
                result_json TEXT,
                created_at_unix INTEGER NOT NULL,
                processed_at_unix INTEGER
            );
            CREATE UNIQUE INDEX human_one_queued_intent ON human_decision_intents(request_id) WHERE lifecycle='queued';
            CREATE TABLE human_decisions (
                response_id TEXT PRIMARY KEY REFERENCES human_decision_intents(response_id),
                request_id TEXT NOT NULL REFERENCES human_requests(request_id),
                subject_digest TEXT NOT NULL,
                configuration_digest TEXT NOT NULL,
                policy_digest TEXT NOT NULL,
                choice TEXT NOT NULL CHECK(choice IN ('approve','request_changes','revise_plan','defer','cancel','refuse')),
                approved INTEGER NOT NULL CHECK(approved IN (0,1)),
                explanation TEXT,
                decided_at_unix INTEGER NOT NULL,
                receipt_json TEXT NOT NULL CHECK(length(receipt_json) <= 65536),
                UNIQUE(request_id)
            );
            CREATE TABLE human_presentations (
                presentation_id INTEGER PRIMARY KEY,
                request_id TEXT NOT NULL REFERENCES human_requests(request_id),
                presenter_kind TEXT NOT NULL CHECK(presenter_kind IN ('local_html','command')),
                reference TEXT,
                location TEXT,
                outcome TEXT NOT NULL CHECK(outcome IN ('opened','presented','failed')),
                detail TEXT,
                attempted_at_unix INTEGER NOT NULL
            );
            CREATE INDEX human_presentations_request ON human_presentations(request_id, attempted_at_unix);
            INSERT INTO schema_migrations(version, applied_at_unix) VALUES (8, unixepoch());
            PRAGMA user_version=8;",
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())
    }

    pub fn register_human_request(
        &mut self,
        owner_generation: u64,
        request: &HumanRuntimeRequest,
        artifact_path: &Path,
        now: u64,
    ) -> Result<bool, String> {
        request.validate(now)?;
        let artifact_path = validate_artifact_path(artifact_path)?;
        let request_json = serde_json::to_string(request).map_err(|error| error.to_string())?;
        let subject_digest = request.subject.digest()?.to_string();
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let created = tx.execute(
            "INSERT INTO human_requests(request_id,project_id,purpose,subject_kind,subject_id,subject_revision,subject_digest,material_digest,configuration_digest,policy_digest,bundle_digest,request_json,artifact_path,lifecycle,created_at_unix,expires_at_unix) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,'pending',?14,?15) ON CONFLICT(request_id) DO NOTHING",
            params![request.request_id.as_str(), request.subject.project_id.as_str(), purpose_name(request.purpose), subject_kind_name(request.subject.kind), request.subject.subject_id, request.subject.revision.0, subject_digest, request.subject.material_digest.as_str(), request.subject.configuration_digest.as_str(), request.subject.policy_digest.as_str(), request.subject.bundle_digest.as_str(), request_json, artifact_path, now, request.expires_at_unix],
        ).map_err(|error| error.to_string())?;
        if created == 0 {
            let previous: (String, String, String, String) = tx.query_row(
                "SELECT request_json, artifact_path, subject_digest, lifecycle FROM human_requests WHERE request_id=?1",
                [request.request_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            ).map_err(|error| error.to_string())?;
            if previous.0 != request_json
                || previous.1 != artifact_path
                || previous.2 != subject_digest
            {
                return Err("human request ID was reused with different content".into());
            }
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(false);
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(true)
    }

    pub fn record_human_presentation(
        &mut self,
        owner_generation: u64,
        receipt: &HumanPresentationReceipt,
    ) -> Result<(), String> {
        if !matches!(receipt.presenter_kind.as_str(), "local_html" | "command")
            || !matches!(receipt.outcome.as_str(), "opened" | "presented" | "failed")
            || receipt
                .detail
                .as_ref()
                .is_some_and(|value| value.len() > 4096)
        {
            return Err("invalid human presentation receipt".into());
        }
        if let Some(location) = &receipt.location {
            validate_https_location(location)?;
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let affected = tx.execute("UPDATE human_requests SET lifecycle=CASE WHEN lifecycle='pending' AND ?3 IN ('opened','presented') THEN 'presented' ELSE lifecycle END, presentation_reference=CASE WHEN ?3 IN ('opened','presented') THEN COALESCE(?2,presentation_reference) ELSE presentation_reference END WHERE request_id=?1 AND lifecycle IN ('pending','presented')", params![receipt.request_id.as_str(), receipt.reference, receipt.outcome]).map_err(|error| error.to_string())?;
        if affected != 1 {
            return Err("human request is no longer presentable".into());
        }
        tx.execute("INSERT INTO human_presentations(request_id,presenter_kind,reference,location,outcome,detail,attempted_at_unix) VALUES (?1,?2,?3,?4,?5,?6,?7)", params![receipt.request_id.as_str(), receipt.presenter_kind, receipt.reference, receipt.location, receipt.outcome, receipt.detail, receipt.attempted_at_unix]).map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())
    }

    /// Read-only request lookup for `human show`/dashboard clients. This deliberately does not
    /// acquire the singleton controller lock, so a human can inspect a running controller.
    pub fn read_human_request(
        state_root: &Path,
        request_id: &HumanRequestId,
    ) -> Result<Option<HumanRequestSummary>, String> {
        let connection = open_existing_database(state_root, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        load_request(&connection, request_id)
    }

    pub fn list_human_requests(
        state_root: &Path,
        project_id: Option<&ProjectId>,
    ) -> Result<Vec<HumanRequestSummary>, String> {
        let connection = open_existing_database(state_root, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let mut statement = if project_id.is_some() {
            connection.prepare("SELECT request_id FROM human_requests WHERE project_id=?1 ORDER BY created_at_unix,request_id").map_err(|error| error.to_string())?
        } else {
            connection
                .prepare(
                    "SELECT request_id FROM human_requests ORDER BY created_at_unix,request_id",
                )
                .map_err(|error| error.to_string())?
        };
        let ids = if let Some(project_id) = project_id {
            statement
                .query_map([project_id.as_str()], |row| row.get::<_, String>(0))
                .map_err(|error| error.to_string())?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| error.to_string())?
        } else {
            statement
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(|error| error.to_string())?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| error.to_string())?
        };
        ids.into_iter()
            .map(|id| {
                let id = HumanRequestId::parse(id)?;
                load_request(&connection, &id)?
                    .ok_or_else(|| "human request disappeared during read".into())
            })
            .collect()
    }

    /// Queue a human response without acquiring the controller's machine lock. This receipt only
    /// confirms durable enqueue; it never represents approval. The controller re-observes and
    /// validates the full subject before persisting an authoritative decision.
    pub fn enqueue_human_decision(
        state_root: &Path,
        intent: &HumanDecisionIntent,
        now: u64,
    ) -> Result<HumanQueueReceipt, String> {
        intent.validate()?;
        let connection = open_existing_database(state_root, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        let tx = connection
            .unchecked_transaction()
            .map_err(|error| error.to_string())?;
        let request_json: String = tx
            .query_row(
                "SELECT request_json FROM human_requests WHERE request_id=?1",
                [intent.request_id.as_str()],
                |row| row.get(0),
            )
            .map_err(|_| "human request was not found".to_owned())?;
        let request: HumanRuntimeRequest = crate::protocol::parse_unique(request_json.as_bytes())?;
        let lifecycle: String = tx
            .query_row(
                "SELECT lifecycle FROM human_requests WHERE request_id=?1",
                [intent.request_id.as_str()],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        let expected_digest = request.subject.digest()?;
        if intent.expected_subject_digest != expected_digest {
            return Err("human request subject has changed; refresh the review bundle".into());
        }
        if !request.choices.contains(&intent.choice) || !request.purpose.allows(intent.choice) {
            return Err("choice is not offered for this human request".into());
        }
        if now >= request.expires_at_unix {
            return Err("human request has expired".into());
        }
        let payload = serde_json::to_vec(intent).map_err(|error| error.to_string())?;
        let content_digest = format!("{:x}", Sha256::digest(&payload));
        let previous: Option<(String, String)> = tx
            .query_row(
                "SELECT content_digest,lifecycle FROM human_decision_intents WHERE response_id=?1",
                [&intent.response_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if let Some((existing_digest, existing_lifecycle)) = previous {
            if existing_digest != content_digest {
                return Err("response ID was reused with different content".into());
            }
            let receipt = HumanQueueReceipt {
                request_id: intent.request_id.clone(),
                response_id: intent.response_id.clone(),
                lifecycle: parse_lifecycle(&lifecycle)?,
                accepted_for_validation: existing_lifecycle == "queued"
                    || existing_lifecycle == "applied",
            };
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(receipt);
        }
        if !matches!(lifecycle.as_str(), "pending" | "presented") {
            return Err("human request is not awaiting a response".into());
        }
        tx.execute("INSERT INTO human_decision_intents(response_id,request_id,content_digest,intent_json,lifecycle,created_at_unix) VALUES (?1,?2,?3,?4,'queued',?5)", params![intent.response_id,intent.request_id.as_str(),content_digest,String::from_utf8(payload).map_err(|error| error.to_string())?,now]).map_err(|error| error.to_string())?;
        tx.execute("UPDATE human_requests SET lifecycle='response_queued' WHERE request_id=?1 AND lifecycle IN ('pending','presented')", [intent.request_id.as_str()]).map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(HumanQueueReceipt {
            request_id: intent.request_id.clone(),
            response_id: intent.response_id.clone(),
            lifecycle: HumanRequestLifecycle::ResponseQueued,
            accepted_for_validation: true,
        })
    }

    pub fn pending_human_decisions(
        &self,
        owner_generation: u64,
        limit: usize,
    ) -> Result<Vec<QueuedHumanDecision>, String> {
        validate_generation_read(&self.connection, owner_generation)?;
        if limit == 0 || limit > MAX_PENDING_DECISIONS {
            return Err("human decision batch limit is outside the configured range".into());
        }
        let mut statement = self.connection.prepare("SELECT i.intent_json,r.request_json FROM human_decision_intents i JOIN human_requests r USING(request_id) WHERE i.lifecycle='queued' ORDER BY i.created_at_unix,i.response_id LIMIT ?1").map_err(|error| error.to_string())?;
        let rows = statement
            .query_map([limit as i64], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|error| error.to_string())?;
        rows.map(|row| {
            let (intent_json, request_json) = row.map_err(|error| error.to_string())?;
            Ok(QueuedHumanDecision {
                intent: crate::protocol::parse_unique(intent_json.as_bytes())?,
                request: crate::protocol::parse_unique(request_json.as_bytes())?,
            })
        })
        .collect()
    }

    /// Revalidate current subject and ticket revision, then atomically persist the decision and a
    /// role wake. The caller supplies a fresh observation assembled from current provider state.
    pub fn process_human_decision(
        &mut self,
        owner_generation: u64,
        response_id: &str,
        current_subject: &HumanSubjectBinding,
        now: u64,
    ) -> Result<HumanDecisionResult, String> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let row: Option<(String,String,String,Option<String>)> = tx.query_row("SELECT i.intent_json,i.lifecycle,i.request_id,i.result_json FROM human_decision_intents i WHERE i.response_id=?1", [response_id], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?))).optional().map_err(|error| error.to_string())?;
        let Some((intent_json, intent_lifecycle, request_id_raw, result_json)) = row else {
            return Err("queued human response was not found".into());
        };
        if matches!(intent_lifecycle.as_str(), "applied" | "stale" | "expired") {
            let result: HumanDecisionResult = crate::protocol::parse_unique(
                result_json.as_deref().unwrap_or_default().as_bytes(),
            )?;
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(result);
        }
        if intent_lifecycle != "queued" {
            return Err("human response is not queued".into());
        }
        let intent: HumanDecisionIntent = crate::protocol::parse_unique(intent_json.as_bytes())?;
        let request_id = HumanRequestId::parse(request_id_raw)?;
        let request_json: String = tx
            .query_row(
                "SELECT request_json FROM human_requests WHERE request_id=?1",
                [request_id.as_str()],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        let request: HumanRuntimeRequest = crate::protocol::parse_unique(request_json.as_bytes())?;
        if request.subject != *current_subject {
            let result = HumanDecisionResult::Stale { reason: "current subject digest, revision, policy, configuration, or evidence differs from the presented request".into() };
            persist_rejected(&tx, response_id, request_id.as_str(), &result, "stale", now)?;
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(result);
        }
        if current_subject.digest()? != intent.expected_subject_digest
            || intent.expected_subject_digest != request.subject.digest()?
        {
            let result = HumanDecisionResult::Stale {
                reason: "response subject digest does not match the fresh observed subject".into(),
            };
            persist_rejected(&tx, response_id, request_id.as_str(), &result, "stale", now)?;
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(result);
        }
        if now >= request.expires_at_unix {
            let result = HumanDecisionResult::Expired;
            persist_rejected(
                &tx,
                response_id,
                request_id.as_str(),
                &result,
                "expired",
                now,
            )?;
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(result);
        }
        if !request.purpose.allows(intent.choice) || !request.choices.contains(&intent.choice) {
            let result = HumanDecisionResult::Stale {
                reason: "response choice is not permitted by the request".into(),
            };
            persist_rejected(&tx, response_id, request_id.as_str(), &result, "stale", now)?;
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(result);
        }
        match validate_current_ticket(&tx, &request) {
            Ok(()) => {}
            Err(TicketValidationError::Stale(reason)) => {
                let result = HumanDecisionResult::Stale { reason };
                persist_rejected(&tx, response_id, request_id.as_str(), &result, "stale", now)?;
                tx.commit().map_err(|error| error.to_string())?;
                return Ok(result);
            }
            Err(TicketValidationError::Storage(error)) => return Err(error),
        }
        let approved = intent.choice == HumanDecisionChoice::Approve;
        let receipt = PersistedApprovalReceipt {
            request_id: request_id.clone(),
            response_id: intent.response_id.clone(),
            subject_digest: intent.expected_subject_digest.clone(),
            configuration_digest: request.subject.configuration_digest.clone(),
            policy_digest: request.subject.policy_digest.clone(),
            choice: intent.choice,
            approved,
            decided_at_unix: now,
            request_expires_at_unix: request.expires_at_unix,
        };
        let result = HumanDecisionResult::Applied;
        let result_json = serde_json::to_string(&result).map_err(|error| error.to_string())?;
        tx.execute("INSERT INTO human_decisions(response_id,request_id,subject_digest,configuration_digest,policy_digest,choice,approved,explanation,decided_at_unix,receipt_json) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)", params![intent.response_id,request_id.as_str(),receipt.subject_digest.as_str(),receipt.configuration_digest.as_str(),receipt.policy_digest.as_str(),choice_name(intent.choice),approved,intent.explanation,now,serde_json::to_string(&receipt).map_err(|error| error.to_string())?]).map_err(|error| error.to_string())?;
        tx.execute("UPDATE human_requests SET lifecycle='decided',decided_at_unix=?2 WHERE request_id=?1 AND lifecycle='response_queued'", params![request_id.as_str(), now]).map_err(|error| error.to_string())?;
        tx.execute("UPDATE human_decision_intents SET lifecycle='applied',processed_at_unix=?2,result_json=?3 WHERE response_id=?1 AND lifecycle='queued'", params![intent.response_id, now, result_json]).map_err(|error| error.to_string())?;
        insert_role_wake(&tx, &request, &receipt, now)?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(result)
    }

    /// Receipt lookup for operation/profile consumers. Approval is returned only if the exact
    /// request, complete subject, policy, configuration, and non-expired lifecycle match.
    pub fn accepted_human_approval(
        &self,
        request_id: &HumanRequestId,
        subject_digest: &Digest,
        configuration_digest: &Digest,
        policy_digest: &Digest,
        now: u64,
    ) -> Result<Option<HumanApprovalReceipt>, String> {
        let row: Option<(String, String, String, u64)> = self.connection.query_row(
            "SELECT d.receipt_json,r.lifecycle,r.subject_digest,r.expires_at_unix FROM human_decisions d JOIN human_requests r USING(request_id) WHERE d.request_id=?1 AND d.subject_digest=?2 AND d.configuration_digest=?3 AND d.policy_digest=?4",
            params![request_id.as_str(),subject_digest.as_str(),configuration_digest.as_str(),policy_digest.as_str()],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
        ).optional().map_err(|error| error.to_string())?;
        let Some((receipt_json, lifecycle, stored_digest, expires_at)) = row else {
            return Ok(None);
        };
        if lifecycle != "decided" || stored_digest != subject_digest.as_str() || now >= expires_at {
            return Ok(None);
        }
        let receipt: PersistedApprovalReceipt =
            crate::protocol::parse_unique(receipt_json.as_bytes())?;
        if receipt.request_id != *request_id
            || receipt.subject_digest != *subject_digest
            || receipt.configuration_digest != *configuration_digest
            || receipt.policy_digest != *policy_digest
            || !receipt.approved
            || receipt.choice != HumanDecisionChoice::Approve
            || receipt.request_expires_at_unix <= receipt.decided_at_unix
        {
            return Ok(None);
        }
        Ok(Some(HumanApprovalReceipt {
            request_id: receipt.request_id,
            response_id: receipt.response_id,
            subject_digest: receipt.subject_digest,
            configuration_digest: receipt.configuration_digest,
            policy_digest: receipt.policy_digest,
            choice: receipt.choice,
            approved: receipt.approved,
            decided_at_unix: receipt.decided_at_unix,
            request_expires_at_unix: receipt.request_expires_at_unix,
        }))
    }
}

fn validate_current_ticket(
    tx: &rusqlite::Transaction<'_>,
    request: &HumanRuntimeRequest,
) -> Result<(), TicketValidationError> {
    if request.subject.kind != HumanSubjectKind::TicketRun {
        return Ok(());
    }
    let ticket_run = TicketRunId::parse(request.subject.subject_id.clone())
        .map_err(TicketValidationError::Stale)?;
    let observed: Option<(String, u64, String, Option<u64>)> = tx
        .query_row(
            "SELECT project_id,revision,internal_phase,required_review_revision FROM ticket_runs WHERE ticket_run_id=?1",
            [ticket_run.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(|error| TicketValidationError::Storage(error.to_string()))?;
    let Some((project_id, revision, phase, required_review_revision)) = observed else {
        return Err(TicketValidationError::Stale(
            "ticket run no longer exists".into(),
        ));
    };
    if project_id != request.subject.project_id.as_str() || revision != request.subject.revision.0 {
        return Err(TicketValidationError::Stale(
            "ticket run changed after the review request was presented".into(),
        ));
    }
    if request.purpose == HumanPurpose::TicketReview
        && (phase != "waiting_human" || required_review_revision != Some(revision))
    {
        return Err(TicketValidationError::Stale(
            "ticket is no longer waiting for review of this revision".into(),
        ));
    }
    Ok(())
}

fn insert_role_wake(
    tx: &rusqlite::Transaction<'_>,
    request: &HumanRuntimeRequest,
    receipt: &PersistedApprovalReceipt,
    now: u64,
) -> Result<(), String> {
    let (role_session_id, role_name) = match request.wake_target() {
        HumanWakeTarget::Supervisor => (
            format!("project:{}:supervisor", request.subject.project_id),
            "supervisor",
        ),
        HumanWakeTarget::Operator => (
            format!("project:{}:operator", request.subject.project_id),
            "operator",
        ),
        HumanWakeTarget::Coordinator if request.subject.kind == HumanSubjectKind::TicketRun => (
            format!("ticket_run:{}:coordinator", request.subject.subject_id),
            "coordinator",
        ),
        HumanWakeTarget::Coordinator => (
            format!("project:{}:supervisor", request.subject.project_id),
            "supervisor",
        ),
    };
    let payload = serde_json::json!({
        "request_id": receipt.request_id.as_str(),
        "response_id": receipt.response_id,
        "choice": receipt.choice,
        "approved": receipt.approved,
        "subject_digest": receipt.subject_digest,
        "configuration_digest": receipt.configuration_digest,
        "policy_digest": receipt.policy_digest,
        "revision": request.subject.revision.0,
        "target": role_name,
    });
    tx.execute("INSERT INTO role_wake_inputs(project_id,role_session_id,source_type,source_id,source_revision,priority,payload_json,lifecycle,created_at_unix) VALUES (?1,?2,'human_decision',?3,?4,10,?5,'pending',?6)", params![request.subject.project_id.as_str(),role_session_id,receipt.response_id,request.subject.revision.0,payload.to_string(),now]).map_err(|error| error.to_string())?;
    Ok(())
}

fn persist_rejected(
    tx: &rusqlite::Transaction<'_>,
    response_id: &str,
    request_id: &str,
    result: &HumanDecisionResult,
    lifecycle: &str,
    now: u64,
) -> Result<(), String> {
    let result_json = serde_json::to_string(result).map_err(|error| error.to_string())?;
    tx.execute("UPDATE human_decision_intents SET lifecycle=?2,processed_at_unix=?3,result_json=?4 WHERE response_id=?1 AND lifecycle='queued'", params![response_id,lifecycle,now,result_json]).map_err(|error| error.to_string())?;
    tx.execute("UPDATE human_requests SET lifecycle=?2,decided_at_unix=?3 WHERE request_id=?1 AND lifecycle='response_queued'", params![request_id,lifecycle,now]).map_err(|error| error.to_string())?;
    Ok(())
}

fn load_request(
    connection: &Connection,
    request_id: &HumanRequestId,
) -> Result<Option<HumanRequestSummary>, String> {
    let row: Option<(String, String, Option<String>, Option<String>)> = connection.query_row("SELECT request_json,lifecycle,artifact_path,presentation_reference FROM human_requests WHERE request_id=?1", [request_id.as_str()], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?))).optional().map_err(|error| error.to_string())?;
    row.map(|(json, lifecycle, artifact_path, reference)| {
        Ok(HumanRequestSummary {
            request: crate::protocol::parse_unique(json.as_bytes())?,
            lifecycle: parse_lifecycle(&lifecycle)?,
            bundle_path: artifact_path
                .ok_or_else(|| "human review artifact path is missing".to_owned())?,
            presentation_reference: reference,
        })
    })
    .transpose()
}

fn parse_lifecycle(value: &str) -> Result<HumanRequestLifecycle, String> {
    match value {
        "pending" => Ok(HumanRequestLifecycle::Pending),
        "presented" => Ok(HumanRequestLifecycle::Presented),
        "response_queued" => Ok(HumanRequestLifecycle::ResponseQueued),
        "decided" => Ok(HumanRequestLifecycle::Decided),
        "stale" => Ok(HumanRequestLifecycle::Stale),
        "expired" => Ok(HumanRequestLifecycle::Expired),
        "cancelled" => Ok(HumanRequestLifecycle::Cancelled),
        _ => Err(format!("unknown human request lifecycle `{value}`")),
    }
}

fn purpose_name(value: HumanPurpose) -> &'static str {
    match value {
        HumanPurpose::PlanDecision => "plan_decision",
        HumanPurpose::TicketReview => "ticket_review",
        HumanPurpose::OperationApproval => "operation_approval",
        HumanPurpose::ProfilePromotion => "profile_promotion",
        HumanPurpose::GoalChange => "goal_change",
        HumanPurpose::GoalCompletion => "goal_completion",
        HumanPurpose::ProjectConfiguration => "project_configuration",
        HumanPurpose::ReleaseDecision => "release_decision",
    }
}

fn subject_kind_name(value: HumanSubjectKind) -> &'static str {
    match value {
        HumanSubjectKind::TicketRun => "ticket_run",
        HumanSubjectKind::Plan => "plan",
        HumanSubjectKind::Operation => "operation",
        HumanSubjectKind::Profile => "profile",
        HumanSubjectKind::Goal => "goal",
        HumanSubjectKind::ProjectConfiguration => "project_configuration",
        HumanSubjectKind::Release => "release",
    }
}

fn choice_name(value: HumanDecisionChoice) -> &'static str {
    match value {
        HumanDecisionChoice::Approve => "approve",
        HumanDecisionChoice::RequestChanges => "request_changes",
        HumanDecisionChoice::RevisePlan => "revise_plan",
        HumanDecisionChoice::Defer => "defer",
        HumanDecisionChoice::Cancel => "cancel",
        HumanDecisionChoice::Refuse => "refuse",
    }
}

fn validate_artifact_path(path: &Path) -> Result<String, String> {
    if !path.is_absolute() {
        return Err("human review artifact path must be absolute".into());
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("human review artifact must be a regular file".into());
    }
    let canonical = fs::canonicalize(path).map_err(|error| error.to_string())?;
    Ok(canonical.to_string_lossy().into_owned())
}

fn validate_https_location(location: &str) -> Result<(), String> {
    crate::human::validate_safe_url(location)
}

fn open_existing_database(state_root: &Path, flags: OpenFlags) -> Result<Connection, String> {
    let root_metadata = fs::symlink_metadata(state_root).map_err(|error| error.to_string())?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err("state root must be a real directory".into());
    }
    let database = state_root.join("state.sqlite3");
    let metadata = fs::symlink_metadata(&database)
        .map_err(|error| format!("{}: {error}", database.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("state database must be a regular file".into());
    }
    let connection =
        Connection::open_with_flags(&database, flags | OpenFlags::SQLITE_OPEN_NO_MUTEX)
            .map_err(|error| error.to_string())?;
    connection
        .busy_timeout(std::time::Duration::from_secs(5))
        .map_err(|error| error.to_string())?;
    connection
        .execute_batch("PRAGMA foreign_keys=ON;")
        .map_err(|error| error.to_string())?;
    Ok(connection)
}

fn validate_generation_read(connection: &Connection, expected: u64) -> Result<(), String> {
    let active: Option<u64> = connection.query_row("SELECT generation FROM controller_owners WHERE singleton=1 AND stopped_at_unix IS NULL", [], |row| row.get(0)).optional().map_err(|error| error.to_string())?;
    if active != Some(expected) {
        return Err("controller owner generation is stale".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use tempfile::tempdir;

    use crate::domain::ids::Revision;
    use crate::human::{RepositoryReview, ReviewBundle};
    use crate::human_runtime::{
        HumanDecisionChoice, HumanDecisionIntent, HumanPurpose, HumanRuntimeRequest,
        HumanSubjectBinding, HumanSubjectKind, write_runtime_review_artifact,
    };
    use crate::store::{ConfigStore, ExpectedRevision, OwnerMetadata, ProjectRecord};

    fn runtime_fixture() -> (
        tempfile::TempDir,
        ConfigStore,
        u64,
        HumanRuntimeRequest,
        PathBuf,
    ) {
        let temp = tempdir().unwrap();
        let config_path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/fixture/config.toml");
        let loaded = crate::config::load(&config_path).unwrap();
        let mut store = ConfigStore::open_test(temp.path()).unwrap();
        let applied = store
            .apply_snapshot("fixture", &loaded, ExpectedRevision::Bootstrap)
            .unwrap();
        let project = ProjectRecord {
            id: ProjectId::parse("human_project").unwrap(),
            config_source: "fixture".into(),
            config_revision: applied.revision,
            config_digest: loaded.digest.clone(),
            mode: "goal".into(),
            goal_revision: 1,
            desired_lifecycle: "running".into(),
            state_revision: Revision(0),
        };
        store.insert_project(&project).unwrap();
        let generation = store
            .start_owner(&OwnerMetadata {
                owner_nonce: "human-test-owner".into(),
                state_root: temp.path().to_string_lossy().into_owned(),
                config_source: "fixture".into(),
                process_start_identity: "test-process-start".into(),
                executable_path: "/tmp/rex-projects-test".into(),
                executable_digest: "e".repeat(64),
                rex_server_identity: None,
                rex_session_id: None,
                rex_block_id: None,
            })
            .unwrap();
        let bundle = ReviewBundle {
            title: "Review operation".into(),
            summary: "Start one staging operation.".into(),
            risk: None,
            repositories: vec![RepositoryReview {
                repository: "org/repo".into(),
                pull_request: "PR #1".into(),
                url: None,
                base_ref: "main".into(),
                base_sha: "a".repeat(40),
                head_ref: "feature".into(),
                head_sha: "b".repeat(40),
                checks: vec!["tests passed".into()],
                review_receipts: vec![],
                merge_steps: vec!["invoke deploy".into()],
            }],
            evidence: vec![],
            unknowns: vec!["rollout timing".into()],
        };
        let subject = HumanSubjectBinding {
            project_id: project.id,
            kind: HumanSubjectKind::Operation,
            subject_id: "deploy-1".into(),
            revision: Revision(1),
            material_digest: Digest::parse("a".repeat(64)).unwrap(),
            configuration_digest: loaded.digest,
            policy_digest: Digest::parse("c".repeat(64)).unwrap(),
            bundle_digest: crate::human::review_bundle_digest(&bundle).unwrap(),
        };
        let request = HumanRuntimeRequest {
            request_id: HumanRequestId::parse("human-deploy-1").unwrap(),
            purpose: HumanPurpose::OperationApproval,
            subject,
            question: "Start this operation?".into(),
            choices: vec![
                HumanDecisionChoice::Approve,
                HumanDecisionChoice::Refuse,
                HumanDecisionChoice::Defer,
            ],
            expires_at_unix: 100,
            review_bundle: bundle,
        };
        let artifact_root = temp.path().join("human-artifacts");
        fs::create_dir(&artifact_root).unwrap();
        fs::set_permissions(&artifact_root, fs::Permissions::from_mode(0o700)).unwrap();
        let artifact = write_runtime_review_artifact(&artifact_root, &request).unwrap();
        (temp, store, generation, request, artifact)
    }

    #[test]
    fn v8_migration_accepts_a_v7_fixture_and_refuses_direct_v6_migration() {
        let temp = tempdir().unwrap();
        let mut store = ConfigStore::open_test(temp.path()).unwrap();
        assert_eq!(
            store
                .connection
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            HUMAN_SCHEMA_VERSION
        );
        // Start from the real v7 schema produced by the versioned migration chain. Remove only
        // v8's tables and marker so this database can exercise the preceding upgrade boundary.
        store
            .connection
            .execute_batch(
                "DROP TABLE human_presentations;
                 DROP TABLE human_decisions;
                 DROP TABLE human_decision_intents;
                 DROP TABLE human_requests;
                 DELETE FROM schema_migrations WHERE version=8;
                 PRAGMA user_version=7;",
            )
            .unwrap();
        store
            .connection
            .pragma_update(None, "user_version", 6)
            .unwrap();
        assert!(ConfigStore::migrate_human_v8(&mut store.connection).is_err());
        store
            .connection
            .pragma_update(None, "user_version", 7)
            .unwrap();
        drop(store);
        let store = ConfigStore::open_test(temp.path()).unwrap();
        assert_eq!(
            store
                .connection
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            HUMAN_SCHEMA_VERSION
        );
        for table in [
            "human_requests",
            "human_decision_intents",
            "human_decisions",
            "human_presentations",
        ] {
            let exists: bool = store
                .connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
                    [table],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(exists, "missing {table}");
        }
    }

    #[test]
    fn response_and_role_wake_commit_together_and_exact_approval_is_queryable() {
        let (temp, mut store, generation, request, artifact) = runtime_fixture();
        assert!(
            store
                .register_human_request(generation, &request, &artifact, 10)
                .unwrap()
        );
        let listed =
            ConfigStore::list_human_requests(temp.path(), Some(&request.subject.project_id))
                .unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].lifecycle, HumanRequestLifecycle::Pending);
        assert_eq!(listed[0].presentation_reference, None);
        assert_eq!(
            ConfigStore::read_human_request(temp.path(), &request.request_id)
                .unwrap()
                .unwrap()
                .presentation_reference,
            None
        );
        let intent = HumanDecisionIntent {
            request_id: request.request_id.clone(),
            response_id: "response-1".into(),
            expected_subject_digest: request.subject.digest().unwrap(),
            choice: HumanDecisionChoice::Approve,
            explanation: Some("The exact operation is approved.".into()),
        };
        let queued = ConfigStore::enqueue_human_decision(temp.path(), &intent, 11).unwrap();
        assert!(queued.accepted_for_validation);
        assert_eq!(queued.lifecycle, HumanRequestLifecycle::ResponseQueued);
        let decisions_before: u64 = store
            .connection
            .query_row("SELECT COUNT(*) FROM human_decisions", [], |row| row.get(0))
            .unwrap();
        let wakes_before: u64 = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM role_wake_inputs WHERE source_type='human_decision'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!((decisions_before, wakes_before), (0, 0));

        let result = store
            .process_human_decision(generation, &intent.response_id, &request.subject, 12)
            .unwrap();
        let HumanDecisionResult::Applied = result else {
            panic!("fresh approval should be applied: {result:?}");
        };
        let decisions_after: u64 = store
            .connection
            .query_row("SELECT COUNT(*) FROM human_decisions", [], |row| row.get(0))
            .unwrap();
        let wakes_after: u64 = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM role_wake_inputs WHERE source_type='human_decision'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!((decisions_after, wakes_after), (1, 1));
        let wake_target: String = store
            .connection
            .query_row(
                "SELECT role_session_id FROM role_wake_inputs WHERE source_type='human_decision'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(wake_target, "project:human_project:operator");
        let accepted = store
            .accepted_human_approval(
                &request.request_id,
                &request.subject.digest().unwrap(),
                &request.subject.configuration_digest,
                &request.subject.policy_digest,
                13,
            )
            .unwrap();
        assert!(
            accepted
                .as_ref()
                .is_some_and(HumanApprovalReceipt::approved)
        );
        assert!(
            store
                .accepted_human_approval(
                    &request.request_id,
                    &request.subject.digest().unwrap(),
                    &request.subject.configuration_digest,
                    &request.subject.policy_digest,
                    100,
                )
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn stale_subject_is_terminal_and_never_wakes_a_role() {
        let (temp, mut store, generation, request, artifact) = runtime_fixture();
        store
            .register_human_request(generation, &request, &artifact, 10)
            .unwrap();
        let intent = HumanDecisionIntent {
            request_id: request.request_id.clone(),
            response_id: "response-stale".into(),
            expected_subject_digest: request.subject.digest().unwrap(),
            choice: HumanDecisionChoice::Approve,
            explanation: None,
        };
        ConfigStore::enqueue_human_decision(temp.path(), &intent, 11).unwrap();
        let mut changed_subject = request.subject.clone();
        changed_subject.material_digest = Digest::parse("d".repeat(64)).unwrap();
        let result = store
            .process_human_decision(generation, &intent.response_id, &changed_subject, 12)
            .unwrap();
        assert!(matches!(result, HumanDecisionResult::Stale { .. }));
        let decisions: u64 = store
            .connection
            .query_row("SELECT COUNT(*) FROM human_decisions", [], |row| row.get(0))
            .unwrap();
        let wakes: u64 = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM role_wake_inputs WHERE source_type='human_decision'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!((decisions, wakes), (0, 0));
        assert!(
            store
                .accepted_human_approval(
                    &request.request_id,
                    &request.subject.digest().unwrap(),
                    &request.subject.configuration_digest,
                    &request.subject.policy_digest,
                    13,
                )
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn ticket_database_error_rolls_back_processing_so_the_response_can_retry() {
        let (temp, mut store, generation, mut request, _) = runtime_fixture();
        request.request_id = HumanRequestId::parse("human-ticket-1").unwrap();
        request.purpose = HumanPurpose::TicketReview;
        request.subject.kind = HumanSubjectKind::TicketRun;
        request.subject.subject_id = "run-1".into();
        request.choices = vec![
            HumanDecisionChoice::Approve,
            HumanDecisionChoice::RequestChanges,
            HumanDecisionChoice::Defer,
            HumanDecisionChoice::Cancel,
        ];
        store.connection.execute(
            "INSERT INTO ticket_runs(ticket_run_id,project_id,config_source,config_revision,config_digest,namespace,ticket_id,generation,internal_phase,activity,external_status,observed_status,revision,external_revision,required_review_revision) VALUES ('run-1','human_project','fixture',1,?1,'github:org/repo','T-1',1,'waiting_human','blocked','in_progress','in_progress',1,NULL,1)",
            [request.subject.configuration_digest.as_str()],
        ).unwrap();
        let artifact_root = temp.path().join("human-artifacts");
        let artifact = write_runtime_review_artifact(&artifact_root, &request).unwrap();
        store
            .register_human_request(generation, &request, &artifact, 10)
            .unwrap();
        let intent = HumanDecisionIntent {
            request_id: request.request_id.clone(),
            response_id: "response-ticket-1".into(),
            expected_subject_digest: request.subject.digest().unwrap(),
            choice: HumanDecisionChoice::Approve,
            explanation: Some("Review passed.".into()),
        };
        ConfigStore::enqueue_human_decision(temp.path(), &intent, 11).unwrap();

        store
            .connection
            .execute_batch(
                "ALTER TABLE ticket_runs RENAME TO ticket_runs_saved;
                 CREATE TABLE ticket_runs (ticket_run_id TEXT PRIMARY KEY, project_id TEXT, revision INTEGER, internal_phase TEXT);",
            )
            .unwrap();
        assert!(
            store
                .process_human_decision(generation, &intent.response_id, &request.subject, 12)
                .is_err()
        );
        let queued = store.pending_human_decisions(generation, 10).unwrap();
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].intent.response_id, intent.response_id);
        let decisions: u64 = store
            .connection
            .query_row("SELECT COUNT(*) FROM human_decisions", [], |row| row.get(0))
            .unwrap();
        let wakes: u64 = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM role_wake_inputs WHERE source_type='human_decision'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!((decisions, wakes), (0, 0));
    }

    #[test]
    fn failed_presentation_keeps_the_request_pending_until_a_successful_open() {
        let (temp, mut store, generation, request, artifact) = runtime_fixture();
        store
            .register_human_request(generation, &request, &artifact, 10)
            .unwrap();
        store
            .record_human_presentation(
                generation,
                &HumanPresentationReceipt {
                    request_id: request.request_id.clone(),
                    presenter_kind: "command".into(),
                    reference: None,
                    location: None,
                    outcome: "failed".into(),
                    detail: Some("presenter exited nonzero".into()),
                    attempted_at_unix: 11,
                },
            )
            .unwrap();
        let after_failure = ConfigStore::read_human_request(temp.path(), &request.request_id)
            .unwrap()
            .unwrap();
        assert_eq!(after_failure.lifecycle, HumanRequestLifecycle::Pending);
        assert_eq!(after_failure.presentation_reference, None);

        store
            .record_human_presentation(
                generation,
                &HumanPresentationReceipt {
                    request_id: request.request_id.clone(),
                    presenter_kind: "local_html".into(),
                    reference: Some("file-opened".into()),
                    location: None,
                    outcome: "opened".into(),
                    detail: None,
                    attempted_at_unix: 12,
                },
            )
            .unwrap();
        let after_success = ConfigStore::read_human_request(temp.path(), &request.request_id)
            .unwrap()
            .unwrap();
        assert_eq!(after_success.lifecycle, HumanRequestLifecycle::Presented);
        assert_eq!(
            after_success.presentation_reference.as_deref(),
            Some("file-opened")
        );
    }

    #[test]
    fn private_runtime_review_artifact_rejects_overwrite_and_escapes_script_text() {
        use crate::domain::ids::{Digest, HumanRequestId, ProjectId, Revision};
        use crate::human::RepositoryReview;
        use crate::human::ReviewRisk;
        use crate::human::RiskConfidence;
        use crate::human::{ReviewBundle, ReviewEvidence};
        use crate::human_runtime::{
            HumanDecisionChoice, HumanPurpose, HumanRuntimeRequest, HumanSubjectBinding,
            HumanSubjectKind, render_runtime_review_html, write_runtime_review_artifact,
        };
        let bundle = ReviewBundle {
            title: "review <script>alert(1)</script>".into(),
            summary: "<img src=x onerror=1>".into(),
            risk: Some(ReviewRisk {
                rating: 2,
                confidence: RiskConfidence::Medium,
                rationale: "bounded".into(),
                unresolved_gates: vec![],
            }),
            repositories: vec![RepositoryReview {
                repository: "acme/app".into(),
                pull_request: "PR #1".into(),
                url: Some("https://example.test/pull/1".into()),
                base_ref: "main".into(),
                base_sha: "a".repeat(40),
                head_ref: "feature".into(),
                head_sha: "b".repeat(40),
                checks: vec!["pass".into()],
                review_receipts: vec!["looks okay".into()],
                merge_steps: vec!["typed step".into()],
            }],
            evidence: vec![ReviewEvidence {
                title: "diff".into(),
                body: "<script>bad()</script>".into(),
                truncated: false,
            }],
            unknowns: vec![],
        };
        let bundle_digest = crate::human::review_bundle_digest(&bundle).unwrap();
        let mut subject = HumanSubjectBinding {
            project_id: ProjectId::parse("p1").unwrap(),
            kind: HumanSubjectKind::Operation,
            subject_id: "op1".into(),
            revision: Revision(3),
            material_digest: Digest::parse("a".repeat(64)).unwrap(),
            configuration_digest: Digest::parse("b".repeat(64)).unwrap(),
            policy_digest: Digest::parse("c".repeat(64)).unwrap(),
            bundle_digest,
        };
        let request = HumanRuntimeRequest {
            request_id: HumanRequestId::parse("request-1").unwrap(),
            purpose: HumanPurpose::OperationApproval,
            subject: subject.clone(),
            question: "Run the release step?".into(),
            choices: vec![
                HumanDecisionChoice::Approve,
                HumanDecisionChoice::Refuse,
                HumanDecisionChoice::Defer,
            ],
            expires_at_unix: 100,
            review_bundle: bundle,
        };
        let html = render_runtime_review_html(&request).unwrap();
        assert!(html.contains("&lt;script&gt;"));
        assert!(!html.contains("<script>"));
        assert!(!html.contains("<img"));
        let temp = tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let file = write_runtime_review_artifact(temp.path(), &request).unwrap();
        assert!(file.is_file());
        assert_eq!(
            write_runtime_review_artifact(temp.path(), &request).unwrap(),
            file
        );
        let mut changed_request = request.clone();
        changed_request.question.push_str(" Changed");
        assert!(write_runtime_review_artifact(temp.path(), &changed_request).is_err());
        subject.revision = Revision(4);
        assert_ne!(subject.digest().unwrap(), request.subject.digest().unwrap());
    }
}
