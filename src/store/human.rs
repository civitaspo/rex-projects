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
const MAX_AUTHORITY_JSON_BYTES: usize = 4 * 1_048_576;
type HumanViewIdentityRow = (String, String, Option<String>, Option<String>, String);
type HumanRequestSummaryRow = (String, String, String, Option<String>, Option<String>);

/// Additive schema fragment called inside the coordinated v12 migration transaction.
pub(crate) fn migrate_v12_human_tables(tx: &rusqlite::Transaction<'_>) -> Result<(), String> {
    migrate_human_requests_publication_adoption(tx)?;
    tx.execute_batch(
        "CREATE TABLE human_request_authority (
            request_id TEXT PRIMARY KEY REFERENCES human_requests(request_id),
            authority_json TEXT NOT NULL CHECK(length(authority_json) <= 4194304),
            authority_digest TEXT NOT NULL CHECK(length(authority_digest) = 64),
            created_at_unix INTEGER NOT NULL
        );
        CREATE TRIGGER human_request_authority_immutable_update
        BEFORE UPDATE ON human_request_authority
        BEGIN SELECT RAISE(ABORT, 'human request authority is immutable'); END;
        CREATE TRIGGER human_request_authority_immutable_delete
        BEFORE DELETE ON human_request_authority
        BEGIN SELECT RAISE(ABORT, 'human request authority is retained'); END;",
    )
    .map_err(|error| error.to_string())
}

const HUMAN_REQUEST_COLUMNS: &str = "request_id,project_id,purpose,subject_kind,subject_id,subject_revision,rex_view_id,subject_digest,material_digest,configuration_digest,policy_digest,bundle_digest,request_json,artifact_path,presentation_reference,lifecycle,created_at_unix,expires_at_unix,decided_at_unix";

/// Create the canonical human request row shape. The legacy option exists only for the v12
/// canonical-layout builder, which models the v8 table before its v12 rebuild.
pub(crate) fn create_human_requests_table(
    connection: &Connection,
    table_name: &str,
    allow_publication_adoption: bool,
) -> Result<(), String> {
    if !matches!(table_name, "human_requests" | "human_requests_v12") {
        return Err("invalid internal human request table name".into());
    }
    let purposes = if allow_publication_adoption {
        "'plan_decision','coordinator_clarification','ticket_review','operation_approval','profile_promotion','profile_trial','goal_change','goal_completion','project_configuration','release_decision','publication_adoption','merge_preparation'"
    } else {
        "'plan_decision','ticket_review','operation_approval','profile_promotion','profile_trial','goal_change','goal_completion','project_configuration','release_decision','merge_preparation'"
    };
    let subjects = if allow_publication_adoption {
        "'ticket_run','plan','operation','profile','goal','project_configuration','release','publication'"
    } else {
        "'ticket_run','plan','operation','profile','goal','project_configuration','release'"
    };
    connection
        .execute_batch(&format!(
            "CREATE TABLE {table_name} (
                request_id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL REFERENCES projects(project_id),
                purpose TEXT NOT NULL CHECK(purpose IN ({purposes})),
                subject_kind TEXT NOT NULL CHECK(subject_kind IN ({subjects})),
                subject_id TEXT NOT NULL,
                subject_revision INTEGER NOT NULL CHECK(subject_revision >= 0),
                rex_view_id TEXT NOT NULL REFERENCES rex_views(view_id),
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
            );"
        ))
        .map_err(|error| error.to_string())
}

pub(crate) fn create_human_request_indexes(connection: &Connection) -> Result<(), String> {
    connection
        .execute_batch(
            "CREATE INDEX human_requests_project_lifecycle ON human_requests(project_id, lifecycle, created_at_unix);
             CREATE INDEX human_requests_subject ON human_requests(project_id, subject_kind, subject_id, subject_revision, subject_digest);
             CREATE INDEX human_requests_rex_view_lifecycle ON human_requests(rex_view_id,lifecycle);",
        )
        .map_err(|error| error.to_string())
}

fn migrate_human_requests_publication_adoption(
    tx: &rusqlite::Transaction<'_>,
) -> Result<(), String> {
    let sql: Option<String> = tx
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='human_requests'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    let _sql = sql.ok_or("schema 11 is missing human_requests")?;
    create_human_requests_table(tx, "human_requests_v12", true)?;
    tx.execute_batch(&format!(
        "INSERT INTO human_requests_v12({HUMAN_REQUEST_COLUMNS}) SELECT {HUMAN_REQUEST_COLUMNS} FROM human_requests;
         DROP TABLE human_requests;
         ALTER TABLE human_requests_v12 RENAME TO human_requests;"
    ))
    .map_err(|error| error.to_string())?;
    create_human_request_indexes(tx)?;

    // v12's centralized rebuild is the only schema-version bump for these unreleased purposes.
    // Rebuild the decision table too: older v8 databases have a narrower CHECK constraint.
    let decisions_exist: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='human_decisions')",
            [],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    if !decisions_exist {
        // Canonical schema validation builds only the tables needed to validate the layout.
        // The production v8 migration creates this table; the validator fixture does not.
        create_human_decisions_table(tx, "human_decisions")?;
        return Ok(());
    }
    tx.execute_batch(
        "CREATE TABLE human_decisions_v12 (
            response_id TEXT PRIMARY KEY REFERENCES human_decision_intents(response_id),
            request_id TEXT NOT NULL REFERENCES human_requests(request_id),
            subject_digest TEXT NOT NULL,
            configuration_digest TEXT NOT NULL,
            policy_digest TEXT NOT NULL,
            choice TEXT NOT NULL CHECK(choice IN ('approve','answer','request_changes','revise_plan','defer','cancel','refuse','completed')),
            approved INTEGER NOT NULL CHECK(approved IN (0,1)),
            explanation TEXT,
            decided_at_unix INTEGER NOT NULL,
            receipt_json TEXT NOT NULL CHECK(length(receipt_json) <= 65536),
            UNIQUE(request_id)
        );
        INSERT INTO human_decisions_v12(response_id,request_id,subject_digest,configuration_digest,policy_digest,choice,approved,explanation,decided_at_unix,receipt_json)
            SELECT response_id,request_id,subject_digest,configuration_digest,policy_digest,choice,approved,explanation,decided_at_unix,receipt_json FROM human_decisions;
        DROP TABLE human_decisions;
        ALTER TABLE human_decisions_v12 RENAME TO human_decisions;"
    )
    .map_err(|error| format!("could not upgrade human decision choices without data loss: {error}"))
}

fn create_human_decisions_table(connection: &Connection, table_name: &str) -> Result<(), String> {
    if !matches!(table_name, "human_decisions" | "human_decisions_v12") {
        return Err("invalid internal human decisions table name".into());
    }
    connection.execute_batch(&format!(
        "CREATE TABLE {table_name} (
            response_id TEXT PRIMARY KEY REFERENCES human_decision_intents(response_id),
            request_id TEXT NOT NULL REFERENCES human_requests(request_id),
            subject_digest TEXT NOT NULL,
            configuration_digest TEXT NOT NULL,
            policy_digest TEXT NOT NULL,
            choice TEXT NOT NULL CHECK(choice IN ('approve','answer','request_changes','revise_plan','defer','cancel','refuse','completed')),
            approved INTEGER NOT NULL CHECK(approved IN (0,1)),
            explanation TEXT,
            decided_at_unix INTEGER NOT NULL,
            receipt_json TEXT NOT NULL CHECK(length(receipt_json) <= 65536),
            UNIQUE(request_id)
        );"
    )).map_err(|error| error.to_string())
}

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
    explanation: Option<String>,
    decided_at_unix: u64,
    request_expires_at_unix: u64,
}

/// Typed host capability for an approved publication-adoption decision. It can only be minted by
/// the Store after checking the stored request purpose, authority, full subject digest, policy,
/// configuration, and non-expired approval receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedPublicationAdoptionApproval {
    receipt: HumanApprovalReceipt,
    authority: crate::human_runtime::PublicationAdoptionAuthority,
}

impl AcceptedPublicationAdoptionApproval {
    pub fn receipt(&self) -> &HumanApprovalReceipt {
        &self.receipt
    }

    pub fn authority(&self) -> &crate::human_runtime::PublicationAdoptionAuthority {
        &self.authority
    }
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
    pub fn explanation(&self) -> Option<&str> {
        self.explanation.as_deref()
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
    explanation: Option<String>,
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
    /// Read a human request through the controller-owned connection. Unlike the CLI helper,
    /// this does not open a second database connection while the controller holds its lock.
    pub fn current_human_request(
        &self,
        request_id: &HumanRequestId,
    ) -> Result<Option<HumanRequestSummary>, String> {
        load_request(&self.connection, request_id)
    }

    /// Apply v8 after v7. Tests build a v6 fixture, promote only its user_version to 7, and invoke
    /// this function directly so this branch can be reviewed before PR3d is merged.
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
                purpose TEXT NOT NULL CHECK(purpose IN ('plan_decision','ticket_review','operation_approval','profile_promotion','profile_trial','goal_change','goal_completion','publication_adoption','project_configuration','release_decision')),
                subject_kind TEXT NOT NULL CHECK(subject_kind IN ('ticket_run','plan','operation','profile','goal','publication','project_configuration','release')),
                subject_id TEXT NOT NULL,
                subject_revision INTEGER NOT NULL CHECK(subject_revision >= 0),
                rex_view_id TEXT NOT NULL REFERENCES rex_views(view_id),
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
            CREATE INDEX human_requests_rex_view_lifecycle ON human_requests(rex_view_id,lifecycle);
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
                choice TEXT NOT NULL CHECK(choice IN ('approve','answer','request_changes','revise_plan','defer','cancel','refuse','completed')),
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

    pub(crate) fn validate_human_v8_schema(connection: &Connection) -> Result<(), String> {
        let view_column: Option<(String, u64)> = connection
            .query_row(
                "SELECT type,\"notnull\" FROM pragma_table_info('human_requests') WHERE name='rex_view_id'",
                [],
                |row| Ok((row.get(0)?,row.get(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let view_foreign_key: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM pragma_foreign_key_list('human_requests') WHERE \"table\"='rex_views' AND \"from\"='rex_view_id' AND \"to\"='view_id')",
                [],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        let has_view_lifecycle_index: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM pragma_index_list('human_requests') WHERE name='human_requests_rex_view_lifecycle')",
                [],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        let mut index_info = connection
            .prepare("SELECT name FROM pragma_index_info('human_requests_rex_view_lifecycle') ORDER BY seqno")
            .map_err(|error| error.to_string())?;
        let index_columns = index_info
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        if view_column
            .as_ref()
            .is_none_or(|(type_name, not_null)| type_name != "TEXT" || *not_null != 1)
            || !view_foreign_key
            || !has_view_lifecycle_index
            || index_columns != ["rex_view_id", "lifecycle"]
        {
            return Err(
                "database reports schema v8 but is missing the human request Rex view hold layout (human_requests.rex_view_id/index). Preserve and back up this database. This runtime will not alter it; use a binary that supports its layout, or recreate it only if the state is disposable development data from authoritative project configuration and ticket providers.".into(),
            );
        }
        Ok(())
    }

    pub fn register_human_request(
        &mut self,
        owner_generation: u64,
        request: &HumanRuntimeRequest,
        rex_view_id: &Digest,
        artifact_path: &Path,
        now: u64,
    ) -> Result<bool, String> {
        self.register_human_request_inner(
            owner_generation,
            request,
            rex_view_id,
            artifact_path,
            None,
            now,
        )
    }

    pub fn register_human_request_with_authority(
        &mut self,
        owner_generation: u64,
        request: &HumanRuntimeRequest,
        rex_view_id: &Digest,
        artifact_path: &Path,
        authority: &crate::human_runtime::HumanAuthorityMaterial,
        now: u64,
    ) -> Result<bool, String> {
        self.register_human_request_inner(
            owner_generation,
            request,
            rex_view_id,
            artifact_path,
            Some(authority),
            now,
        )
    }

    fn register_human_request_inner(
        &mut self,
        owner_generation: u64,
        request: &HumanRuntimeRequest,
        rex_view_id: &Digest,
        artifact_path: &Path,
        authority: Option<&crate::human_runtime::HumanAuthorityMaterial>,
        now: u64,
    ) -> Result<bool, String> {
        request.validate(now)?;
        if let Some(authority) = authority {
            authority.validate_for(request)?;
            let source = match authority {
                crate::human_runtime::HumanAuthorityMaterial::PlannerClarification {
                    source,
                    ..
                }
                | crate::human_runtime::HumanAuthorityMaterial::CoordinatorClarification {
                    source,
                    ..
                }
                | crate::human_runtime::HumanAuthorityMaterial::GoalCompletion { source, .. } => {
                    Some(source)
                }
                crate::human_runtime::HumanAuthorityMaterial::PublicationAdoption { .. } => None,
            };
            if let Some(source) = source
                && !self.human_role_result_is_current_source(source)?
            {
                return Err(
                    "human request source does not match a completed validated Agent result".into(),
                );
            }
        }
        let artifact_path = validate_artifact_path(artifact_path)?;
        let request_json = serde_json::to_string(request).map_err(|error| error.to_string())?;
        let authority_json = authority
            .map(serde_json::to_string)
            .transpose()
            .map_err(|error| error.to_string())?;
        if authority_json
            .as_ref()
            .is_some_and(|json| json.len() > MAX_AUTHORITY_JSON_BYTES)
        {
            return Err("human request authority exceeds its storage size limit".into());
        }
        let authority_digest = authority_json
            .as_ref()
            .map(|json| format!("{:x}", Sha256::digest(json.as_bytes())));
        let subject_digest = request.subject.digest()?.to_string();
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let previous: Option<(String, String, String, String, String)> = tx
            .query_row(
                "SELECT request_json, artifact_path, subject_digest, lifecycle, rex_view_id FROM human_requests WHERE request_id=?1",
                [request.request_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if let Some(previous) = previous {
            if previous.0 != request_json
                || previous.1 != artifact_path
                || previous.2 != subject_digest
                || previous.4 != rex_view_id.as_str()
            {
                return Err("human request ID was reused with different content".into());
            }
            match (&authority_json, &authority_digest) {
                (Some(json), Some(digest)) => {
                    let existing: Option<(String, String)> = tx
                        .query_row(
                            "SELECT authority_json,authority_digest FROM human_request_authority WHERE request_id=?1",
                            [request.request_id.as_str()],
                            |row| Ok((row.get(0)?, row.get(1)?)),
                        )
                        .optional()
                        .map_err(|error| error.to_string())?;
                    if existing.as_ref() != Some(&(json.clone(), digest.clone())) {
                        return Err(
                            "human request ID was reused with different authority material".into(),
                        );
                    }
                }
                (None, None) => {}
                _ => return Err("invalid human request authority encoding".into()),
            }
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(false);
        }
        validate_active_request_view(&tx, request, rex_view_id)?;
        tx.execute(
            "INSERT INTO human_requests(request_id,project_id,purpose,subject_kind,subject_id,subject_revision,rex_view_id,subject_digest,material_digest,configuration_digest,policy_digest,bundle_digest,request_json,artifact_path,lifecycle,created_at_unix,expires_at_unix) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,'pending',?15,?16)",
            params![request.request_id.as_str(), request.subject.project_id.as_str(), purpose_name(request.purpose), subject_kind_name(request.subject.kind), request.subject.subject_id, request.subject.revision.0, rex_view_id.as_str(), subject_digest, request.subject.material_digest.as_str(), request.subject.configuration_digest.as_str(), request.subject.policy_digest.as_str(), request.subject.bundle_digest.as_str(), request_json, artifact_path, now, request.expires_at_unix],
        ).map_err(|error| error.to_string())?;
        if let (Some(json), Some(digest)) = (authority_json, authority_digest) {
            tx.execute(
                "INSERT INTO human_request_authority(request_id,authority_json,authority_digest,created_at_unix) VALUES (?1,?2,?3,?4)",
                params![request.request_id.as_str(), json, digest, now],
            )
            .map_err(|error| error.to_string())?;
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(true)
    }

    pub fn human_request_authority(
        &self,
        request_id: &HumanRequestId,
    ) -> Result<Option<crate::human_runtime::HumanAuthorityMaterial>, String> {
        let stored: Option<(String, String)> = self
            .connection
            .query_row(
                "SELECT authority_json,authority_digest FROM human_request_authority WHERE request_id=?1",
                [request_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        stored
            .map(|(json, expected_digest)| {
                if json.len() > MAX_AUTHORITY_JSON_BYTES
                    || format!("{:x}", Sha256::digest(json.as_bytes())) != expected_digest
                {
                    return Err("stored human authority digest is invalid".into());
                }
                let authority: crate::human_runtime::HumanAuthorityMaterial =
                    crate::protocol::parse_unique(json.as_bytes())?;
                let canonical =
                    serde_json::to_string(&authority).map_err(|error| error.to_string())?;
                if canonical != json {
                    return Err("stored human authority is not canonical".into());
                }
                Ok(authority)
            })
            .transpose()
    }

    pub(crate) fn human_role_result_is_current_source(
        &self,
        source: &crate::human_runtime::HumanRoleResultSource,
    ) -> Result<bool, String> {
        let binding = &source.binding;
        let Some(authority) = self.agent_launch_authority(&binding.agent_run_id)? else {
            return Ok(false);
        };
        if authority.project_id != binding.project_id
            || authority.role != binding.role
            || authority.ticket_run_id != binding.ticket_run_id
            || authority.ticket_revision != binding.ticket_revision
            || authority.config_revision != binding.config_revision
            || authority.config_digest != binding.config_digest
            || authority.profile_digest != binding.profile_digest
            || authority.instruction_digest != binding.instruction_digest
            || authority.run_epoch != binding.run_epoch
            || authority.attempt != binding.attempt
        {
            return Ok(false);
        }
        let row: Option<(String, String, Option<String>, u32, u64, String, Option<String>, String, String)> = self
            .connection
            .query_row(
                "SELECT project_id,role,ticket_run_id,attempt,run_epoch,message_id,result_digest,result_json,artifact_refs_json FROM agent_result_evidence WHERE agent_run_id=?1 AND message_id=?2 AND outcome='completed'",
                rusqlite::params![binding.agent_run_id.as_str(), source.message_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let Some((
            project_id,
            role,
            ticket_run_id,
            attempt,
            epoch,
            message_id,
            result_digest,
            result_json,
            refs_json,
        )) = row
        else {
            return Ok(false);
        };
        let expected_role = serde_json::to_value(binding.role)
            .map_err(|error| error.to_string())?
            .as_str()
            .ok_or("role serialization was not a string")?
            .to_owned();
        if project_id != binding.project_id.as_str()
            || role != expected_role
            || ticket_run_id.as_deref() != binding.ticket_run_id.as_ref().map(TicketRunId::as_str)
            || attempt != binding.attempt
            || epoch != binding.run_epoch
            || message_id != source.message_id
            || result_digest.as_deref() != Some(source.result_digest.as_str())
        {
            return Ok(false);
        }
        let submission: crate::engine::orchestration::RoleResultSubmission =
            crate::protocol::parse_unique(result_json.as_bytes())?;
        if submission.result_digest != source.result_digest
            || submission.kind != source.result_kind
            || submission.assertion != source.assertion
            || submission.binding != source.binding
            || source.result_kind != crate::engine::orchestration::RoleOutputKind::HumanRequest
            || source.assertion != crate::engine::orchestration::AgentAssertion::Succeeded
        {
            return Ok(false);
        }
        let validated =
            crate::engine::orchestration::validate_role_result(&source.binding, submission)?;
        let crate::engine::orchestration::RoleResultPayload::HumanRequest(stored_request) =
            validated.typed_payload
        else {
            return Ok(false);
        };
        if stored_request != source.human_request {
            return Ok(false);
        }
        let stored_refs: Vec<crate::engine::orchestration::RoleArtifactReference> =
            crate::protocol::parse_unique(refs_json.as_bytes())?;
        Ok(stored_refs == source.claimed_artifact_refs)
    }

    pub(crate) fn current_ticket_human_scope(
        &self,
        ticket_run_id: &TicketRunId,
    ) -> Result<Option<(ProjectId, u64, String, Option<u64>)>, String> {
        self.connection
            .query_row(
                "SELECT project_id,revision,internal_phase,required_review_revision FROM ticket_runs WHERE ticket_run_id=?1",
                [ticket_run_id.as_str()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?, row.get::<_, String>(2)?, row.get::<_, Option<u64>>(3)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?
            .map(|(project, revision, phase, review_revision)| {
                Ok((ProjectId::parse(project)?, revision, phase, review_revision))
            })
            .transpose()
    }

    pub(crate) fn goal_completion_work_is_clear(
        &self,
        project_id: &ProjectId,
    ) -> Result<bool, String> {
        let unfinished_ticket: bool = self
            .connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM ticket_runs WHERE project_id=?1 AND internal_phase NOT IN ('done','canceled'))",
                [project_id.as_str()],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        let unsuccessful_operation: bool = self
            .connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM operation_runs WHERE project_id=?1 AND state NOT IN ('succeeded','skipped'))",
                [project_id.as_str()],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        Ok(!unfinished_ticket && !unsuccessful_operation)
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
        if intent.choice == HumanDecisionChoice::Answer
            && intent
                .explanation
                .as_deref()
                .is_none_or(|answer| answer.trim().is_empty())
        {
            return Err(
                "Coordinator clarification answer must include nonempty answer text".into(),
            );
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

    /// Expire unanswered human requests and release their Rex view holds. The foreground
    /// controller calls this during each poll; queued responses become terminal in the same tx.
    pub fn expire_pending_human_requests(
        &mut self,
        owner_generation: u64,
        now: u64,
    ) -> Result<usize, String> {
        validate_generation_read(&self.connection, owner_generation)?;
        let has_expired: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM human_requests WHERE lifecycle IN ('pending','presented','response_queued') AND expires_at_unix<=?1)",
            [now],
            |row| row.get(0),
        ).map_err(|error| error.to_string())?;
        if !has_expired {
            return Ok(0);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let mut statement = tx.prepare(
            "SELECT request_id,request_json FROM human_requests WHERE lifecycle IN ('pending','presented','response_queued') AND expires_at_unix<=?1 ORDER BY expires_at_unix,request_id",
        ).map_err(|error| error.to_string())?;
        let request_ids = statement
            .query_map([now], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        drop(statement);
        let result_json = serde_json::to_string(&HumanDecisionResult::Expired)
            .map_err(|error| error.to_string())?;
        let mut expired = 0;
        for (request_id, request_json) in request_ids {
            let request: HumanRuntimeRequest =
                crate::protocol::parse_unique(request_json.as_bytes())?;
            let changed = tx.execute(
                "UPDATE human_requests SET lifecycle='expired',decided_at_unix=?2 WHERE request_id=?1 AND lifecycle IN ('pending','presented','response_queued') AND expires_at_unix<=?2",
                params![request_id,now],
            ).map_err(|error| error.to_string())?;
            if changed == 0 {
                continue;
            }
            tx.execute(
                "UPDATE human_decision_intents SET lifecycle='expired',processed_at_unix=?2,result_json=?3 WHERE request_id=?1 AND lifecycle='queued'",
                params![request_id,now,result_json],
            ).map_err(|error| error.to_string())?;
            insert_human_resolution_wake(
                &tx,
                &request,
                &format!("expiry:{}", request_id),
                "expired",
                "human request expired before a decision was applied",
                now,
            )?;
            expired += changed;
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(expired)
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
            persist_rejected(
                &tx,
                response_id,
                request_id.as_str(),
                &request,
                &result,
                "stale",
                now,
            )?;
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(result);
        }
        if current_subject.digest()? != intent.expected_subject_digest
            || intent.expected_subject_digest != request.subject.digest()?
        {
            let result = HumanDecisionResult::Stale {
                reason: "response subject digest does not match the fresh observed subject".into(),
            };
            persist_rejected(
                &tx,
                response_id,
                request_id.as_str(),
                &request,
                &result,
                "stale",
                now,
            )?;
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(result);
        }
        if now >= request.expires_at_unix {
            let result = HumanDecisionResult::Expired;
            persist_rejected(
                &tx,
                response_id,
                request_id.as_str(),
                &request,
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
            persist_rejected(
                &tx,
                response_id,
                request_id.as_str(),
                &request,
                &result,
                "stale",
                now,
            )?;
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(result);
        }
        match validate_current_ticket(&tx, &request) {
            Ok(()) => {}
            Err(TicketValidationError::Stale(reason)) => {
                let result = HumanDecisionResult::Stale { reason };
                persist_rejected(
                    &tx,
                    response_id,
                    request_id.as_str(),
                    &request,
                    &result,
                    "stale",
                    now,
                )?;
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
            explanation: intent.explanation.clone(),
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

    /// Mark a queued decision stale when the authoritative subject has been removed and cannot
    /// produce a replacement binding. Persist the terminal response and wake its owner atomically.
    pub fn reject_human_decision_stale(
        &mut self,
        owner_generation: u64,
        response_id: &str,
        reason: &str,
        now: u64,
    ) -> Result<HumanDecisionResult, String> {
        if reason.trim().is_empty() || reason.len() > 4096 {
            return Err("stale human decision needs a bounded explanation".into());
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let row: Option<(String, String, String, Option<String>)> = tx
            .query_row(
                "SELECT i.intent_json,i.lifecycle,i.request_id,i.result_json FROM human_decision_intents i WHERE i.response_id=?1",
                [response_id],
                |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let Some((intent_json, lifecycle, request_id_raw, result_json)) = row else {
            return Err("queued human response was not found".into());
        };
        if matches!(lifecycle.as_str(), "applied" | "stale" | "expired") {
            let result: HumanDecisionResult = crate::protocol::parse_unique(
                result_json.as_deref().unwrap_or_default().as_bytes(),
            )?;
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(result);
        }
        if lifecycle != "queued" {
            return Err("human response is not queued".into());
        }
        let _intent: HumanDecisionIntent = crate::protocol::parse_unique(intent_json.as_bytes())?;
        let request_id = HumanRequestId::parse(request_id_raw)?;
        let request_json: String = tx
            .query_row(
                "SELECT request_json FROM human_requests WHERE request_id=?1",
                [request_id.as_str()],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        let request: HumanRuntimeRequest = crate::protocol::parse_unique(request_json.as_bytes())?;
        let result = HumanDecisionResult::Stale {
            reason: reason.to_owned(),
        };
        persist_rejected(
            &tx,
            response_id,
            request_id.as_str(),
            &request,
            &result,
            "stale",
            now,
        )?;
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
            explanation: receipt.explanation,
            decided_at_unix: receipt.decided_at_unix,
            request_expires_at_unix: receipt.request_expires_at_unix,
        }))
    }

    pub fn accepted_publication_adoption_approval(
        &self,
        request_id: &HumanRequestId,
        now: u64,
    ) -> Result<Option<AcceptedPublicationAdoptionApproval>, String> {
        let Some(summary) = load_request(&self.connection, request_id)? else {
            return Ok(None);
        };
        if summary.request.purpose != crate::human_runtime::HumanPurpose::PublicationAdoption {
            return Ok(None);
        }
        let Some(crate::human_runtime::HumanAuthorityMaterial::PublicationAdoption { material }) =
            self.human_request_authority(request_id)?
        else {
            return Ok(None);
        };
        if crate::human_runtime::publication_adoption_request(request_id.clone(), material.clone())?
            != summary.request
        {
            return Ok(None);
        }
        let subject_digest = summary.request.subject.digest()?;
        let Some(receipt) = self.accepted_human_approval(
            request_id,
            &subject_digest,
            &summary.request.subject.configuration_digest,
            &summary.request.subject.policy_digest,
            now,
        )?
        else {
            return Ok(None);
        };
        Ok(Some(AcceptedPublicationAdoptionApproval {
            receipt,
            authority: material,
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

fn validate_active_request_view(
    tx: &rusqlite::Transaction<'_>,
    request: &HumanRuntimeRequest,
    view_id: &Digest,
) -> Result<(), String> {
    let observed: Option<HumanViewIdentityRow> = tx
        .query_row(
            "SELECT project_id,view_kind,ticket_namespace,ticket_id,lifecycle FROM rex_views WHERE view_id=?1",
            [view_id.as_str()],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    let Some((project_id, view_kind, namespace, ticket_id, lifecycle)) = observed else {
        return Err("human request Rex view was not found".into());
    };
    if lifecycle != "active" {
        return Err("human request requires an active Rex view".into());
    }
    if project_id != request.subject.project_id.as_str() {
        return Err("human request Rex view belongs to another project".into());
    }
    let expected_kind = match request.purpose {
        HumanPurpose::GoalChange
        | HumanPurpose::GoalCompletion
        | HumanPurpose::ProfilePromotion
        | HumanPurpose::ProfileTrial
        | HumanPurpose::ProjectConfiguration
        | HumanPurpose::ReleaseDecision => "supervisor",
        HumanPurpose::PlanDecision
        | HumanPurpose::CoordinatorClarification
        | HumanPurpose::TicketReview
        | HumanPurpose::OperationApproval
        | HumanPurpose::PublicationAdoption => "ticket",
    };
    if view_kind != expected_kind {
        return Err(format!("human request requires a {expected_kind} Rex view"));
    }
    let ticket_run_id = if request.subject.kind == HumanSubjectKind::TicketRun {
        Some(TicketRunId::parse(request.subject.subject_id.clone())?)
    } else {
        request.subject.ticket_run_id.clone()
    };
    if matches!(
        request.purpose,
        HumanPurpose::OperationApproval | HumanPurpose::PublicationAdoption
    ) && ticket_run_id.is_none()
    {
        return Err(
            "operation and publication-adoption decisions require a ticket-scoped Rex view".into(),
        );
    }
    if let Some(ticket_run) = ticket_run_id {
        let ticket: Option<(String, String)> = tx
            .query_row(
                "SELECT namespace,ticket_id FROM ticket_runs WHERE ticket_run_id=?1 AND project_id=?2",
                params![ticket_run.as_str(), request.subject.project_id.as_str()],
                |row| Ok((row.get(0)?,row.get(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let Some((expected_namespace, expected_ticket_id)) = ticket else {
            return Err("human request ticket run was not found in this project".into());
        };
        if namespace.as_deref() != Some(expected_namespace.as_str())
            || ticket_id.as_deref() != Some(expected_ticket_id.as_str())
        {
            return Err("human request Rex view does not match its ticket run".into());
        }
    }
    Ok(())
}

fn insert_role_wake(
    tx: &rusqlite::Transaction<'_>,
    request: &HumanRuntimeRequest,
    receipt: &PersistedApprovalReceipt,
    now: u64,
) -> Result<(), String> {
    if request.purpose == HumanPurpose::ProfileTrial {
        // Trial approvals are consumed by the controller's typed trial coordinator. They must
        // never wake an Agent role session or become semantic factory input.
        return Ok(());
    }
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
        "explanation": receipt.explanation,
        "target": role_name,
    });
    tx.execute("INSERT INTO role_wake_inputs(project_id,role_session_id,source_type,source_id,source_revision,priority,payload_json,lifecycle,created_at_unix) VALUES (?1,?2,'human_decision',?3,?4,10,?5,'pending',?6)", params![request.subject.project_id.as_str(),role_session_id,receipt.response_id,request.subject.revision.0,payload.to_string(),now]).map_err(|error| error.to_string())?;
    Ok(())
}

fn persist_rejected(
    tx: &rusqlite::Transaction<'_>,
    response_id: &str,
    request_id: &str,
    request: &HumanRuntimeRequest,
    result: &HumanDecisionResult,
    lifecycle: &str,
    now: u64,
) -> Result<(), String> {
    let result_json = serde_json::to_string(result).map_err(|error| error.to_string())?;
    tx.execute("UPDATE human_decision_intents SET lifecycle=?2,processed_at_unix=?3,result_json=?4 WHERE response_id=?1 AND lifecycle='queued'", params![response_id,lifecycle,now,result_json]).map_err(|error| error.to_string())?;
    tx.execute("UPDATE human_requests SET lifecycle=?2,decided_at_unix=?3 WHERE request_id=?1 AND lifecycle='response_queued'", params![request_id,lifecycle,now]).map_err(|error| error.to_string())?;
    insert_human_resolution_wake(tx, request, response_id, lifecycle, &result_json, now)?;
    Ok(())
}

fn insert_human_resolution_wake(
    tx: &rusqlite::Transaction<'_>,
    request: &HumanRuntimeRequest,
    source_id: &str,
    lifecycle: &str,
    detail: &str,
    now: u64,
) -> Result<(), String> {
    let (role_session_id, target) = match request.wake_target() {
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
        "request_id": request.request_id.as_str(),
        "response_id": source_id,
        "outcome": lifecycle,
        "detail": detail,
        "subject_digest": request.subject.digest()?,
        "revision": request.subject.revision.0,
        "target": target,
    });
    tx.execute(
        "INSERT INTO role_wake_inputs(project_id,role_session_id,source_type,source_id,source_revision,priority,payload_json,lifecycle,created_at_unix) VALUES (?1,?2,'human_resolution',?3,?4,10,?5,'pending',?6) ON CONFLICT(role_session_id,source_type,source_id,source_revision) DO NOTHING",
        params![request.subject.project_id.as_str(), role_session_id, source_id, request.subject.revision.0, payload.to_string(), now],
    )
    .map_err(|error| error.to_string())?;
    Ok(())
}

fn load_request(
    connection: &Connection,
    request_id: &HumanRequestId,
) -> Result<Option<HumanRequestSummary>, String> {
    let row: Option<HumanRequestSummaryRow> = connection.query_row("SELECT request_json,lifecycle,rex_view_id,artifact_path,presentation_reference FROM human_requests WHERE request_id=?1", [request_id.as_str()], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?))).optional().map_err(|error| error.to_string())?;
    row.map(|(json, lifecycle, rex_view_id, artifact_path, reference)| {
        Ok(HumanRequestSummary {
            request: crate::protocol::parse_unique(json.as_bytes())?,
            lifecycle: parse_lifecycle(&lifecycle)?,
            rex_view_id: Digest::parse(rex_view_id)?,
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
        HumanPurpose::CoordinatorClarification => "coordinator_clarification",
        HumanPurpose::TicketReview => "ticket_review",
        HumanPurpose::OperationApproval => "operation_approval",
        HumanPurpose::ProfilePromotion => "profile_promotion",
        HumanPurpose::ProfileTrial => "profile_trial",
        HumanPurpose::GoalChange => "goal_change",
        HumanPurpose::GoalCompletion => "goal_completion",
        HumanPurpose::PublicationAdoption => "publication_adoption",
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
        HumanSubjectKind::Publication => "publication",
        HumanSubjectKind::ProjectConfiguration => "project_configuration",
        HumanSubjectKind::Release => "release",
    }
}

fn choice_name(value: HumanDecisionChoice) -> &'static str {
    match value {
        HumanDecisionChoice::Approve => "approve",
        HumanDecisionChoice::Answer => "answer",
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
    use std::ffi::OsString;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use tempfile::tempdir;

    use crate::domain::ids::Revision;
    use crate::human::{RepositoryReview, ReviewBundle};
    use crate::human_runtime::{
        HumanDecisionChoice, HumanDecisionIntent, HumanPresentationEffect,
        HumanPresenterEffectHandler, HumanPurpose, HumanRuntimeRequest, HumanSubjectBinding,
        HumanSubjectKind, HumanSubjectObserver, PublicationAdoptionAuthority,
        SelectedPublicationResource, write_runtime_review_artifact,
    };
    use crate::launch::{RexView, RexViewKind};
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
        store.connection.execute(
            "INSERT INTO ticket_runs(ticket_run_id,project_id,config_source,config_revision,config_digest,namespace,ticket_id,generation,internal_phase,activity,external_status,observed_status,revision,required_review_revision) VALUES ('run-1','human_project','fixture',1,?1,'github:org/repo','T-1',1,'ready','ready','in_progress','in_progress',1,NULL)",
            [loaded.digest.as_str()],
        ).unwrap();
        let generation = store
            .start_owner(&OwnerMetadata {
                owner_nonce: "human-test-owner".into(),
                state_root: temp.path().to_string_lossy().into_owned(),
                config_source: "fixture".into(),
                process_start_identity: "test-process-start".into(),
                executable_path: "/tmp/rex-projects-test".into(),
                executable_digest: "e".repeat(64),
                rex_endpoint: None,
                rex_server_identity: None,
                rex_session_id: None,
                rex_block_id: None,
            })
            .unwrap();
        for (kind, namespace, ticket_id) in [
            (RexViewKind::Supervisor, None, None),
            (RexViewKind::Ticket, Some("github:org/repo"), Some("T-1")),
        ] {
            let view = RexView {
                view_id: RexView::derive_id(&project.id, kind, namespace, ticket_id, 1).unwrap(),
                project_id: project.id.clone(),
                kind,
                ticket_namespace: namespace.map(str::to_owned),
                ticket_id: ticket_id.map(str::to_owned),
                view_epoch: 1,
                rex_server_identity: "test-server".into(),
                rex_session_id: "test-session".into(),
                rex_window_id: if kind == RexViewKind::Supervisor {
                    "supervisor-window".into()
                } else {
                    "ticket-window".into()
                },
            };
            store.register_rex_view(generation, &view).unwrap();
        }
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
            ticket_run_id: Some(TicketRunId::parse("run-1").unwrap()),
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

    fn request_view_id(store: &ConfigStore, request: &HumanRuntimeRequest) -> Digest {
        let view_kind = match request.purpose {
            HumanPurpose::GoalChange
            | HumanPurpose::GoalCompletion
            | HumanPurpose::ProfilePromotion
            | HumanPurpose::ProjectConfiguration => "supervisor",
            _ => "ticket",
        };
        let row: String = if request.subject.kind == HumanSubjectKind::TicketRun {
            store
                .connection
                .query_row(
                    "SELECT v.view_id FROM rex_views v JOIN ticket_runs t ON t.project_id=v.project_id AND t.namespace=v.ticket_namespace AND t.ticket_id=v.ticket_id WHERE t.ticket_run_id=?1 AND v.view_kind=?2 AND v.lifecycle='active'",
                    params![request.subject.subject_id, view_kind],
                    |row| row.get(0),
                )
                .unwrap()
        } else {
            store
                .connection
                .query_row(
                    "SELECT view_id FROM rex_views WHERE project_id=?1 AND view_kind=?2 AND lifecycle='active'",
                    params![request.subject.project_id.as_str(), view_kind],
                    |row| row.get(0),
                )
                .unwrap()
        };
        Digest::parse(row).unwrap()
    }

    fn register_request(
        store: &mut ConfigStore,
        owner_generation: u64,
        request: &HumanRuntimeRequest,
        artifact: &Path,
        now: u64,
    ) -> Result<bool, String> {
        let view_id = request_view_id(store, request);
        store.register_human_request(owner_generation, request, &view_id, artifact, now)
    }

    struct FixedSubjectObserver(HumanSubjectBinding);

    impl HumanSubjectObserver for FixedSubjectObserver {
        fn observe_current_subject(
            &self,
            _store: &ConfigStore,
            _request: &HumanRuntimeRequest,
        ) -> Result<crate::human_runtime::HumanSubjectObservation, String> {
            Ok(crate::human_runtime::HumanSubjectObservation::Current(
                self.0.clone(),
            ))
        }
    }

    #[test]
    fn human_effect_registers_presents_then_consumes_only_a_fresh_human_response() {
        use crate::effects::{
            EffectContext, EffectHandler, EffectMode, EffectObservation, EffectRequest,
        };
        use crate::store::EffectIntent;

        let (temp, mut store, generation, request, artifact) = runtime_fixture();
        let view_id = request_view_id(&store, &request);
        let payload = serde_json::to_string(&HumanPresentationEffect {
            request: request.clone(),
            rex_view_id: view_id,
            authority: None,
        })
        .unwrap();
        let effect = EffectRequest {
            intent: EffectIntent {
                project_id: request.subject.project_id.clone(),
                subject_type: "ticket_run".into(),
                subject_id: if request.purpose == HumanPurpose::OperationApproval {
                    request
                        .subject
                        .ticket_run_id
                        .as_ref()
                        .expect("operation approval fixture binds a TicketRun")
                        .as_str()
                        .to_owned()
                } else {
                    request.subject.subject_id.clone()
                },
                operation_id: "human-effect-1".into(),
                logical_key: "ticket-run-1:1:request_human_review".into(),
                kind: "request_human_review".into(),
                request_json: payload,
                request_digest: "a".repeat(64),
                expected_revision: Some(request.subject.revision.0),
            },
            attempt_count: 1,
            created_at_unix: 50,
        };
        let artifact_root = temp.path().join("human-artifacts");
        // Remove the fixture's existing page so the handler proves it can create its own private,
        // deterministic review bundle while preserving identical manifest/summary files.
        std::fs::remove_file(&artifact).unwrap();
        let handler = HumanPresenterEffectHandler::new(
            "local_html",
            vec!["/usr/bin/true".into()],
            [(OsString::from("PATH"), OsString::from("/usr/bin"))]
                .into_iter()
                .collect(),
            artifact_root,
            std::sync::Arc::new(FixedSubjectObserver(request.subject.clone())),
        )
        .unwrap();
        let mut context = EffectContext {
            store: &mut store,
            owner_generation: generation,
            now_unix: 50,
        };
        let presented = handler
            .handle(EffectMode::Submit, &effect, &mut context)
            .unwrap();
        assert!(matches!(presented, EffectObservation::Pending { .. }));
        assert!(
            context
                .store
                .accepted_human_approval(
                    &request.request_id,
                    &request.subject.digest().unwrap(),
                    &request.subject.configuration_digest,
                    &request.subject.policy_digest,
                    50,
                )
                .unwrap()
                .is_none()
        );

        ConfigStore::enqueue_human_decision(
            temp.path(),
            &HumanDecisionIntent {
                request_id: request.request_id.clone(),
                response_id: "human-response-1".into(),
                expected_subject_digest: request.subject.digest().unwrap(),
                choice: HumanDecisionChoice::Approve,
                explanation: Some("Reviewed the exact head and checks.".into()),
            },
            51,
        )
        .unwrap();
        let reconciled = handler
            .handle(EffectMode::Reconcile, &effect, &mut context)
            .unwrap();
        assert!(matches!(reconciled, EffectObservation::Applied { .. }));
        let approval = context
            .store
            .accepted_human_approval(
                &request.request_id,
                &request.subject.digest().unwrap(),
                &request.subject.configuration_digest,
                &request.subject.policy_digest,
                52,
            )
            .unwrap()
            .unwrap();
        assert!(approval.approved());
        assert_eq!(
            approval.explanation(),
            Some("Reviewed the exact head and checks.")
        );
    }

    #[test]
    fn request_registration_rejects_nonactive_or_wrong_scope_view() {
        let (_temp, mut store, generation, request, artifact) = runtime_fixture();
        let wrong_view: String = store
            .connection
            .query_row(
                "SELECT view_id FROM rex_views WHERE project_id=?1 AND view_kind='supervisor'",
                [request.subject.project_id.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            store
                .register_human_request(
                    generation,
                    &request,
                    &Digest::parse(wrong_view).unwrap(),
                    &artifact,
                    10
                )
                .is_err()
        );

        let view_id = request_view_id(&store, &request);
        store
            .connection
            .execute(
                "UPDATE rex_views SET lifecycle='close_pending' WHERE view_id=?1",
                [view_id.as_str()],
            )
            .unwrap();
        assert!(
            store
                .register_human_request(generation, &request, &view_id, &artifact, 10)
                .is_err()
        );
        let count: u64 = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM human_requests WHERE request_id=?1",
                [request.request_id.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn plan_approval_requires_its_ticket_view_and_release_uses_project_view() {
        let (_temp, mut store, generation, request, artifact) = runtime_fixture();
        let mut plan = request.clone();
        plan.request_id = HumanRequestId::parse("human-plan-1").unwrap();
        plan.purpose = HumanPurpose::PlanDecision;
        plan.subject.kind = HumanSubjectKind::Plan;
        plan.subject.subject_id = "plan-1".into();
        plan.subject.ticket_run_id = Some(TicketRunId::parse("run-1").unwrap());
        plan.choices = vec![HumanDecisionChoice::RevisePlan];
        let artifact = write_runtime_review_artifact(artifact.parent().unwrap(), &plan).unwrap();
        let wrong_view = RexView {
            view_id: RexView::derive_id(
                &plan.subject.project_id,
                RexViewKind::Ticket,
                Some("github:org/repo"),
                Some("T-2"),
                1,
            )
            .unwrap(),
            project_id: plan.subject.project_id.clone(),
            kind: RexViewKind::Ticket,
            ticket_namespace: Some("github:org/repo".into()),
            ticket_id: Some("T-2".into()),
            view_epoch: 1,
            rex_server_identity: "test-server".into(),
            rex_session_id: "test-session".into(),
            rex_window_id: "wrong-ticket-window".into(),
        };
        store.register_rex_view(generation, &wrong_view).unwrap();
        assert!(
            store
                .register_human_request(generation, &plan, &wrong_view.view_id, &artifact, 10)
                .is_err()
        );
        assert!(register_request(&mut store, generation, &plan, &artifact, 10).unwrap());

        let mut release = request;
        release.request_id = HumanRequestId::parse("human-release-1").unwrap();
        release.purpose = HumanPurpose::ReleaseDecision;
        release.subject.kind = HumanSubjectKind::Release;
        release.subject.subject_id = "release-1".into();
        release.subject.ticket_run_id = None;
        release.choices = vec![HumanDecisionChoice::Approve, HumanDecisionChoice::Refuse];
        let artifact = write_runtime_review_artifact(artifact.parent().unwrap(), &release).unwrap();
        let supervisor_view: String = store
            .connection
            .query_row(
                "SELECT view_id FROM rex_views WHERE project_id=?1 AND view_kind='supervisor'",
                [release.subject.project_id.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            store
                .register_human_request(
                    generation,
                    &release,
                    &Digest::parse(supervisor_view).unwrap(),
                    &artifact,
                    10,
                )
                .unwrap()
        );
    }

    #[test]
    fn unanswered_human_request_holds_view_until_expiry_sweep() {
        let (_temp, mut store, generation, request, artifact) = runtime_fixture();
        let view_id = request_view_id(&store, &request);
        store.connection.execute(
            "INSERT INTO agent_runs(agent_run_id,project_id,config_source,config_revision,config_digest,logical_owner,finite_turn,launch_operation_id,state,controller_generation) VALUES ('hold-run','human_project','fixture',1,?1,'test',1,'hold-op','completed',?2)",
            params![request.subject.configuration_digest.as_str(),generation],
        ).unwrap();
        store
            .connection
            .execute(
                "INSERT INTO rex_view_blocks(view_id,block_id,agent_run_id,role,ownership,lifecycle,process_absent_confirmed,created_at_unix,last_observed_at_unix) VALUES (?1,'finished-worker','hold-run','worker','factory','completed',1,1,1)",
                [view_id.as_str()],
            )
            .unwrap();
        store
            .connection
            .execute(
                "UPDATE rex_views SET updated_at_unix=0 WHERE view_id=?1",
                [view_id.as_str()],
            )
            .unwrap();

        // Ticket views become retention candidates only after the durable run is terminal.
        // The pending request below must then keep that otherwise-clean view alive.
        store.connection.execute(
            "UPDATE ticket_runs SET internal_phase='done',activity='done' WHERE ticket_run_id='run-1'",
            [],
        ).unwrap();
        store
            .archive_rex_view_block(generation, &view_id, "finished-worker", "finished output")
            .unwrap();
        assert!(
            store
                .mark_rex_view_terminal(generation, &view_id, 0)
                .unwrap()
        );

        let stale_candidate = store.rex_view_cleanup_candidates(1000, 1).unwrap();
        assert_eq!(stale_candidate.len(), 1);
        register_request(&mut store, generation, &request, &artifact, 10).unwrap();
        assert!(
            store
                .begin_rex_view_close(generation, &stale_candidate[0], 1000, 1)
                .is_err()
        );
        assert!(
            store
                .rex_view_cleanup_candidates(1000, 1)
                .unwrap()
                .is_empty()
        );

        assert_eq!(
            store.expire_pending_human_requests(generation, 99).unwrap(),
            0
        );
        assert_eq!(
            store
                .expire_pending_human_requests(generation, 100)
                .unwrap(),
            1
        );
        let candidates = store.rex_view_cleanup_candidates(1000, 1).unwrap();
        assert_eq!(candidates.len(), 1);
        store
            .begin_rex_view_close(generation, &candidates[0], 1000, 1)
            .unwrap();
    }

    #[test]
    fn expiry_sweep_terminalizes_and_wakes_the_responsible_role() {
        let (temp, mut store, generation, request, artifact) = runtime_fixture();
        register_request(&mut store, generation, &request, &artifact, 10).unwrap();
        let intent = HumanDecisionIntent {
            request_id: request.request_id.clone(),
            response_id: "response-expired".into(),
            expected_subject_digest: request.subject.digest().unwrap(),
            choice: HumanDecisionChoice::Approve,
            explanation: Some("Too late to act".into()),
        };
        ConfigStore::enqueue_human_decision(temp.path(), &intent, 11).unwrap();
        assert_eq!(
            store.pending_human_decisions(generation, 10).unwrap().len(),
            1
        );
        assert_eq!(
            store
                .expire_pending_human_requests(generation, 100)
                .unwrap(),
            1
        );
        assert!(
            store
                .pending_human_decisions(generation, 10)
                .unwrap()
                .is_empty()
        );
        assert!(matches!(
            store
                .process_human_decision(generation, &intent.response_id, &request.subject, 101)
                .unwrap(),
            HumanDecisionResult::Expired
        ));
        let (wake_count, payload): (u64, String) = store
            .connection
            .query_row(
                "SELECT COUNT(*),COALESCE(MAX(payload_json),'') FROM role_wake_inputs WHERE source_type='human_resolution'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(wake_count, 1);
        assert!(payload.contains("expired"));
    }

    #[test]
    fn v8_migration_is_applied_and_includes_the_rex_view_binding() {
        let temp = tempdir().unwrap();
        let store = ConfigStore::open_test(temp.path()).unwrap();
        assert_eq!(
            store
                .connection
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            crate::store::SCHEMA_VERSION
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
        let has_view_binding: bool = store.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('human_requests') WHERE name='rex_view_id')",
            [],
            |row| row.get(0),
        ).unwrap();
        assert!(has_view_binding);
    }

    #[test]
    fn released_v6_database_upgrades_through_v7_v8_and_v9() {
        let temp = tempdir().unwrap();
        let database = temp.path().join("state.sqlite3");
        let connection = Connection::open(&database).unwrap();
        ConfigStore::migrate(&connection, 0, temp.path()).unwrap();
        crate::store::migrate_v3(&connection).unwrap();
        crate::store::migrate_v4(&connection).unwrap();
        crate::store::migrate_v5(&connection).unwrap();
        crate::store::migrate_v6(&connection).unwrap();
        assert_eq!(
            connection
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            6
        );
        drop(connection);

        let store = ConfigStore::open_test(temp.path()).unwrap();
        assert_eq!(
            store
                .connection
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            crate::store::SCHEMA_VERSION
        );
        ConfigStore::validate_human_v8_schema(&store.connection).unwrap();
    }

    #[test]
    fn schema_v8_missing_hold_layout_fails_with_actionable_error_without_repair() {
        let temp = tempdir().unwrap();
        let store = ConfigStore::open_test(temp.path()).unwrap();
        drop(store);
        let database = temp.path().join("state.sqlite3");
        let connection = Connection::open(&database).unwrap();
        connection
            .execute_batch("DROP INDEX human_requests_rex_view_lifecycle")
            .unwrap();
        connection.pragma_update(None, "user_version", 8).unwrap();
        drop(connection);
        let before = fs::read(&database).unwrap();

        let error = match ConfigStore::open_test(temp.path()) {
            Ok(_) => panic!("incomplete v8 layout must be refused"),
            Err(error) => error,
        };
        assert!(error.contains("schema v8 but is missing the human request Rex view hold layout"));
        assert_eq!(fs::read(&database).unwrap(), before);
        let connection = Connection::open(&database).unwrap();
        let index_exists: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM pragma_index_list('human_requests') WHERE name='human_requests_rex_view_lifecycle')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            !index_exists,
            "the failed startup must not alter the database"
        );
    }

    #[test]
    fn response_and_role_wake_commit_together_and_exact_approval_is_queryable() {
        let (temp, mut store, generation, request, artifact) = runtime_fixture();
        assert!(register_request(&mut store, generation, &request, &artifact, 10).unwrap());
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
    fn coordinator_answer_requires_text_and_wakes_its_ticket_coordinator_atomically() {
        let (temp, mut store, generation, base_request, artifact) = runtime_fixture();
        let bundle = base_request.review_bundle.clone();
        let request = HumanRuntimeRequest {
            request_id: HumanRequestId::parse("clarify-1").unwrap(),
            purpose: HumanPurpose::CoordinatorClarification,
            subject: HumanSubjectBinding {
                project_id: ProjectId::parse("human_project").unwrap(),
                kind: HumanSubjectKind::TicketRun,
                subject_id: "run-1".into(),
                ticket_run_id: Some(TicketRunId::parse("run-1").unwrap()),
                revision: Revision(1),
                material_digest: Digest::parse("a".repeat(64)).unwrap(),
                configuration_digest: base_request.subject.configuration_digest.clone(),
                policy_digest: Digest::parse("b".repeat(64)).unwrap(),
                bundle_digest: crate::human::review_bundle_digest(&bundle).unwrap(),
            },
            question: "Which option should we use?".into(),
            choices: vec![
                HumanDecisionChoice::Answer,
                HumanDecisionChoice::Defer,
                HumanDecisionChoice::Cancel,
            ],
            expires_at_unix: 100,
            review_bundle: bundle,
        };
        assert!(register_request(&mut store, generation, &request, &artifact, 10).unwrap());
        let mut intent = HumanDecisionIntent {
            request_id: request.request_id.clone(),
            response_id: "answer-1".into(),
            expected_subject_digest: request.subject.digest().unwrap(),
            choice: HumanDecisionChoice::Answer,
            explanation: None,
        };
        assert!(ConfigStore::enqueue_human_decision(temp.path(), &intent, 11).is_err());
        intent.explanation =
            Some("Use region west-2; it matches the existing deployment target.".into());
        ConfigStore::enqueue_human_decision(temp.path(), &intent, 11).unwrap();
        assert!(matches!(
            store
                .process_human_decision(generation, &intent.response_id, &request.subject, 12)
                .unwrap(),
            HumanDecisionResult::Applied
        ));
        let wake: (String, String) = store.connection.query_row(
            "SELECT role_session_id,payload_json FROM role_wake_inputs WHERE source_type='human_decision' AND source_id='answer-1'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).unwrap();
        assert_eq!(wake.0, "ticket_run:run-1:coordinator");
        let payload: serde_json::Value = serde_json::from_str(&wake.1).unwrap();
        assert_eq!(payload["choice"], "answer");
        assert_eq!(
            payload["explanation"],
            "Use region west-2; it matches the existing deployment target."
        );
    }

    #[test]
    fn v12_human_rebuild_preserves_rows_and_adds_coordinator_answer_constraints() {
        let mut connection = Connection::open_in_memory().unwrap();
        connection.execute_batch(
            "CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at_unix INTEGER NOT NULL);
             CREATE TABLE projects(project_id TEXT PRIMARY KEY);
             CREATE TABLE rex_views(view_id TEXT PRIMARY KEY);
             PRAGMA foreign_keys=OFF;",
        ).unwrap();
        connection
            .execute("INSERT INTO projects VALUES ('p')", [])
            .unwrap();
        connection
            .execute("INSERT INTO rex_views VALUES ('v')", [])
            .unwrap();
        create_human_requests_table(&connection, "human_requests", false).unwrap();
        connection.execute_batch(
            "CREATE TABLE human_decision_intents (
                response_id TEXT PRIMARY KEY,
                request_id TEXT NOT NULL REFERENCES human_requests(request_id),
                content_digest TEXT NOT NULL,
                intent_json TEXT NOT NULL,
                lifecycle TEXT NOT NULL,
                result_json TEXT,
                created_at_unix INTEGER NOT NULL,
                processed_at_unix INTEGER
             );
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
                receipt_json TEXT NOT NULL,
                UNIQUE(request_id)
             );
             INSERT INTO human_requests(request_id,project_id,purpose,subject_kind,subject_id,subject_revision,rex_view_id,subject_digest,material_digest,configuration_digest,policy_digest,bundle_digest,request_json,artifact_path,lifecycle,created_at_unix,expires_at_unix)
             VALUES ('old','p','release_decision','release','r',1,'v','s','m','c','p','b','{}','a','decided',1,2);
             INSERT INTO human_decision_intents(response_id,request_id,content_digest,intent_json,lifecycle,created_at_unix) VALUES ('resp-old','old','d','{}','applied',1);
             INSERT INTO human_decisions(response_id,request_id,subject_digest,configuration_digest,policy_digest,choice,approved,decided_at_unix,receipt_json)
             VALUES ('resp-old','old','s','c','p','approve',1,2,'{}');"
        ).unwrap();
        let tx = connection.transaction().unwrap();
        migrate_v12_human_tables(&tx).unwrap();
        tx.commit().unwrap();

        let preserved: (String, String) = connection
            .query_row(
                "SELECT request_id,purpose FROM human_requests WHERE request_id='old'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(preserved, ("old".into(), "release_decision".into()));
        let preserved_choice: String = connection
            .query_row(
                "SELECT choice FROM human_decisions WHERE response_id='resp-old'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(preserved_choice, "approve");
        connection.execute(
            "INSERT INTO human_requests(request_id,project_id,purpose,subject_kind,subject_id,subject_revision,rex_view_id,subject_digest,material_digest,configuration_digest,policy_digest,bundle_digest,request_json,artifact_path,lifecycle,created_at_unix,expires_at_unix)
             VALUES ('clarify','p','coordinator_clarification','ticket_run','run',1,'v','s2','m2','c','p','b2','{}','a2','decided',3,4)", [],
        ).unwrap();
        connection.execute(
            "INSERT INTO human_decision_intents(response_id,request_id,content_digest,intent_json,lifecycle,created_at_unix) VALUES ('resp-answer','clarify','d2','{}','applied',3)", [],
        ).unwrap();
        connection.execute(
            "INSERT INTO human_decisions(response_id,request_id,subject_digest,configuration_digest,policy_digest,choice,approved,explanation,decided_at_unix,receipt_json)
             VALUES ('resp-answer','clarify','s2','c','p','answer',0,'use option B',4,'{}')", [],
        ).expect("v12 decision constraint accepts Coordinator freeform answers");
    }

    #[test]
    fn stale_subject_is_terminal_and_wakes_its_owner_without_approval() {
        let (temp, mut store, generation, request, artifact) = runtime_fixture();
        register_request(&mut store, generation, &request, &artifact, 10).unwrap();
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
        let (wakes, payload): (u64, String) = store
            .connection
            .query_row(
                "SELECT COUNT(*),COALESCE(MAX(payload_json),'') FROM role_wake_inputs WHERE source_type='human_resolution'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((decisions, wakes), (0, 1));
        assert!(payload.contains("stale"));
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
            "UPDATE ticket_runs SET internal_phase='waiting_human',activity='blocked',revision=1,required_review_revision=1 WHERE ticket_run_id='run-1'",
            [],
        ).unwrap();
        let artifact_root = temp.path().join("human-artifacts");
        let artifact = write_runtime_review_artifact(&artifact_root, &request).unwrap();
        let wrong_view = RexView {
            view_id: RexView::derive_id(
                &request.subject.project_id,
                RexViewKind::Ticket,
                Some("github:org/repo"),
                Some("T-2"),
                1,
            )
            .unwrap(),
            project_id: request.subject.project_id.clone(),
            kind: RexViewKind::Ticket,
            ticket_namespace: Some("github:org/repo".into()),
            ticket_id: Some("T-2".into()),
            view_epoch: 1,
            rex_server_identity: "test-server".into(),
            rex_session_id: "test-session".into(),
            rex_window_id: "wrong-ticket-window".into(),
        };
        store.register_rex_view(generation, &wrong_view).unwrap();
        assert!(
            store
                .register_human_request(generation, &request, &wrong_view.view_id, &artifact, 10)
                .is_err()
        );
        register_request(&mut store, generation, &request, &artifact, 10).unwrap();
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
        register_request(&mut store, generation, &request, &artifact, 10).unwrap();
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
            ticket_run_id: Some(TicketRunId::parse("run-1").unwrap()),
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

    #[test]
    fn approved_publication_adoption_updates_baseline_before_unblocking() {
        let (temp, mut store, generation, _, artifact) = runtime_fixture();
        let project_id = ProjectId::parse("human_project").unwrap();
        let ticket_run_id = TicketRunId::parse("run-1").unwrap();
        let resource = crate::store::publication_monitor::PublicationResource {
            project_id: project_id.clone(),
            ticket_run_id: ticket_run_id.clone(),
            repository_id: crate::domain::ids::RepositoryId::parse("repo-1").unwrap(),
            branch: "rex-projects/test-branch".into(),
        };
        let previous_digest = "a".repeat(64);
        store
            .record_publication_irregularity(
                generation,
                &crate::store::publication_monitor::PublicationIrregularity {
                    resource: resource.clone(),
                    observation_digest: previous_digest.clone(),
                    observed_at_unix: 50,
                    facts: serde_json::json!({"reason":"external branch created"}),
                },
            )
            .unwrap();
        let observation = crate::delivery_runtime::RepositoryPublicationObservation {
            remote_head: Some("head-adopted".into()),
            pull_requests: crate::delivery_forge::ObservationCapability::Known(Vec::new()),
        };
        let unresolved = store
            .latest_unresolved_publication(&resource)
            .unwrap()
            .unwrap();
        let authority = PublicationAdoptionAuthority {
            resource: resource.clone(),
            event_id: unresolved.event_id,
            event_revision: unresolved.revision,
            previous_observation_digest: Digest::parse(previous_digest).unwrap(),
            selected_resource: SelectedPublicationResource::Branch {
                head: "head-adopted".into(),
            },
            current_observation_digest: crate::human_runtime::publication_observation_digest(
                &observation,
            )
            .unwrap(),
            current_observation: observation.clone(),
            configuration_digest: store.project(&project_id).unwrap().unwrap().config_digest,
            policy_digest: Digest::parse("c".repeat(64)).unwrap(),
            expires_at_unix: 200,
        };
        let request_id = HumanRequestId::parse("human-publication-adoption-1").unwrap();
        let request = crate::human_runtime::publication_adoption_request(
            request_id.clone(),
            authority.clone(),
        )
        .unwrap();
        let material = crate::human_runtime::HumanAuthorityMaterial::PublicationAdoption {
            material: authority,
        };
        let view_id = request_view_id(&store, &request);
        store
            .register_human_request_with_authority(
                generation, &request, &view_id, &artifact, &material, 60,
            )
            .unwrap();
        let intent = HumanDecisionIntent {
            request_id: request_id.clone(),
            response_id: "publication-adoption-response-1".into(),
            expected_subject_digest: request.subject.digest().unwrap(),
            choice: HumanDecisionChoice::Approve,
            explanation: Some("Verified the exact current branch head.".into()),
        };
        ConfigStore::enqueue_human_decision(temp.path(), &intent, 61).unwrap();
        assert_eq!(
            store
                .process_human_decision(generation, &intent.response_id, &request.subject, 62)
                .unwrap(),
            HumanDecisionResult::Applied
        );
        let approval = store
            .accepted_publication_adoption_approval(&request_id, 63)
            .unwrap()
            .unwrap();
        let baseline = store
            .adopt_publication_snapshot(
                generation,
                &approval,
                &observation,
                &request.subject.configuration_digest,
                "main",
                64,
            )
            .unwrap();
        assert_eq!(baseline.observation, observation);
        assert!(store.assert_publication_unblocked(&resource).is_ok());
        assert_eq!(
            store
                .classify_publication_observation(
                    &resource,
                    &observation,
                    &crate::publication_monitor::ReconciledHostEffects::default(),
                )
                .unwrap(),
            crate::publication_monitor::PublicationClassification::Unchanged,
            "the next foreground monitor comparison should accept the adopted baseline"
        );
    }
}
