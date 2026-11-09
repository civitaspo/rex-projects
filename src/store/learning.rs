//! Durable learning and knowledge-publication records owned by the machine controller.
//! Migration 10 is intentionally standalone until controller migrations 7–9 are integrated.

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::{ConfigStore, validate_active_generation};
use crate::domain::ids::{Digest, HumanRequestId, OperationId, ProfileId, ProjectId, TicketRunId};
use crate::human_runtime::HumanRuntimeRequest;
use crate::knowledge::{
    DEFAULT_MAX_ARTICLE_BYTES, PostmortemInput, PublicationManifest, validate_postmortem_input,
};
use crate::learning::{
    CandidateLedger, CandidateRevision, CandidateStatus, ProfilePackage, ProfilePublicationReceipt,
    ProfilePublicationStatus, TrialEvidence, TrialObservation, evaluate_trials,
    validated_promotion_claims,
};
use crate::learning_trials::{
    ProfileTrialAuthorization, ProfileTrialLaunchCapsule, ProfileTrialRunReceipt, TrialSide,
    accept_profile_trial_approval, bind_profile_trial_human_request,
};

const MAX_RECORD_BYTES: usize = 4 * 1024 * 1024;
const MAX_TRIALS: usize = 10;
const MAX_SUPERVISOR_KNOWLEDGE_ITEMS: usize = 12;
const MAX_SUPERVISOR_CANDIDATES: usize = 20;
const MAX_SUPERVISOR_CONTEXT_BYTES: usize = 256 * 1024;
type PublicationDbRow = (
    String,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
);
type PromotionDbRow = (
    String,
    String,
    String,
    String,
    String,
    String,
    Option<u64>,
    Option<String>,
    Option<u64>,
    Option<String>,
);
type PromotionIntentRow = (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct KnowledgePublicationIntent {
    pub operation_id: OperationId,
    pub project_id: ProjectId,
    pub ticket_run_id: TicketRunId,
    pub request_digest: Digest,
    pub request_json: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct KnowledgePublicationReceipt {
    pub manifest: PublicationManifest,
    pub manifest_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishedKnowledgeRecord {
    pub input: PostmortemInput,
    pub manifest: PublicationManifest,
    pub manifest_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProfilePromotionIntent {
    pub operation_id: OperationId,
    pub project_id: ProjectId,
    pub candidate_id: String,
    pub profile_id: ProfileId,
    pub role: crate::domain::types::Role,
    pub manifest_digest: Digest,
    pub profile_material_digest: Digest,
    pub expected_config_revision: Digest,
    pub config_source: String,
    pub config_file: String,
    pub human_request_id: HumanRequestId,
    pub approval_subject_digest: Digest,
    pub approval_configuration_digest: Digest,
    pub approval_policy_digest: Digest,
    pub response_receipt_digest: Digest,
    pub package: StoredApprovedProfilePackage,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LearningCandidateRecord {
    pub revision: CandidateRevision,
    pub profile_id: ProfileId,
    pub package_manifest_digest: Digest,
    /// Canonical JSON encoding of the exact UTF-8 file path/content manifest.
    pub package_files_json: String,
    pub package_json: String,
    pub expected_pairs: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LearningCandidatePackage {
    pub revision: CandidateRevision,
    pub profile_id: ProfileId,
    pub manifest_digest: Digest,
    pub files: std::collections::BTreeMap<String, Vec<u8>>,
    pub evidence: Option<TrialEvidence>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StoredTrial {
    pub pair_index: usize,
    pub observation: TrialObservation,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CandidateRegistration {
    Registered,
    AlreadyRegistered,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TrialProgress {
    pub trials: Vec<StoredTrial>,
    pub evidence: TrialEvidence,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SupervisorKnowledgeEntry {
    pub ticket_run_id: TicketRunId,
    pub generated_at: String,
    pub title: String,
    pub summary: String,
    pub findings: Vec<String>,
    pub source_digests: Vec<Digest>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SupervisorCandidateEntry {
    pub revision: CandidateRevision,
    pub profile_id: ProfileId,
    pub package_manifest_digest: Digest,
    pub expected_pairs: usize,
    pub evidence: Option<TrialEvidence>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProjectSupervisorMaintenance {
    pub project_id: ProjectId,
    pub expired_candidates: usize,
    pub knowledge: Vec<SupervisorKnowledgeEntry>,
    pub candidates: Vec<SupervisorCandidateEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProfilePromotionRequest {
    pub operation_id: OperationId,
    pub candidate_id: String,
    pub config_source: String,
    pub config_file: String,
    pub human_request_id: HumanRequestId,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct StoredProfilePublicationReceipt {
    profile_path: String,
    manifest_digest: Digest,
    human_response_receipt_digest: Digest,
    already_published: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StoredApprovedProfilePackage {
    pub project_id: ProjectId,
    pub role: crate::domain::types::Role,
    pub profile_id: ProfileId,
    pub candidate_digest: Digest,
    pub evidence: TrialEvidence,
    pub files: std::collections::BTreeMap<String, Vec<u8>>,
    pub approver: String,
    pub rationale: String,
    pub authorized_at: String,
    pub human_request_id: HumanRequestId,
    pub approval_subject_digest: Digest,
    pub approval_configuration_digest: Digest,
    pub approval_policy_digest: Digest,
    pub response_receipt_digest: Digest,
    pub config_revision: Digest,
    pub profile_material_digest: Digest,
}

/// Install v10 over a v9 database as part of the caller's backed-up migration transaction.
#[allow(dead_code)] // Wired into the ordered v9 migration chain when PR3/4/5 land.
pub(crate) fn migrate_v10(connection: &Connection) -> Result<(), String> {
    let tx = connection
        .unchecked_transaction()
        .map_err(|e| e.to_string())?;
    let version: i64 = tx
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|e| e.to_string())?;
    if version != 9 {
        return Err(format!(
            "learning migration requires schema v9, found v{version}"
        ));
    }
    tx.execute_batch(
        "ALTER TABLE controller_owners ADD COLUMN rex_endpoint TEXT;
        CREATE TABLE knowledge_publications (
            operation_id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(project_id),
            ticket_run_id TEXT NOT NULL UNIQUE REFERENCES ticket_runs(ticket_run_id),
            request_digest TEXT NOT NULL CHECK(length(request_digest)=64),
            request_json TEXT NOT NULL CHECK(length(request_json)<=4194304),
            state TEXT NOT NULL CHECK(state IN ('prepared','published','failed','uncertain')),
            manifest_json TEXT,
            manifest_digest TEXT,
            created_at_unix INTEGER NOT NULL,
            published_at_unix INTEGER,
            CHECK((state='published' AND manifest_json IS NOT NULL AND manifest_digest IS NOT NULL)
               OR (state!='published' AND manifest_json IS NULL AND manifest_digest IS NULL))
        );
        CREATE INDEX knowledge_publication_project ON knowledge_publications(project_id,created_at_unix);
        CREATE TABLE learning_candidates (
            project_id TEXT NOT NULL REFERENCES projects(project_id),
            candidate_id TEXT NOT NULL,
            role TEXT NOT NULL,
            digest TEXT NOT NULL CHECK(length(digest)=64),
            profile_id TEXT NOT NULL,
            revision_json TEXT NOT NULL CHECK(length(revision_json)<=65536),
            package_manifest_digest TEXT NOT NULL CHECK(length(package_manifest_digest)=64),
            package_files_json TEXT NOT NULL CHECK(length(package_files_json)<=4194304),
            package_json TEXT NOT NULL CHECK(length(package_json)<=4194304),
            expected_pairs INTEGER NOT NULL CHECK(expected_pairs BETWEEN 5 AND 10),
            status TEXT NOT NULL CHECK(status IN ('proposed','trialing','awaiting_approval','promoted','superseded','expired','rejected')),
            evidence_json TEXT,
            created_at_unix INTEGER NOT NULL,
            PRIMARY KEY(project_id,candidate_id,digest)
        );
        CREATE INDEX learning_candidates_slots ON learning_candidates(project_id,role,status,created_at_unix);
        CREATE TABLE supervisor_learning_schedule (
            project_id TEXT PRIMARY KEY REFERENCES projects(project_id) ON DELETE CASCADE,
            next_due_at_unix INTEGER NOT NULL,
            last_run_at_unix INTEGER,
            last_snapshot_digest TEXT CHECK(last_snapshot_digest IS NULL OR length(last_snapshot_digest)=64)
        );
        CREATE TABLE learning_trial_pairs (
            project_id TEXT NOT NULL,
            candidate_id TEXT NOT NULL,
            candidate_digest TEXT NOT NULL,
            pair_index INTEGER NOT NULL CHECK(pair_index BETWEEN 0 AND 9),
            input_digest TEXT NOT NULL CHECK(length(input_digest)=64),
            observation_json TEXT NOT NULL CHECK(length(observation_json)<=16384),
            created_at_unix INTEGER NOT NULL,
            PRIMARY KEY(project_id,candidate_id,candidate_digest,pair_index),
            FOREIGN KEY(project_id,candidate_id,candidate_digest)
                REFERENCES learning_candidates(project_id,candidate_id,digest) ON DELETE CASCADE
        );
        CREATE TABLE profile_promotions (
            operation_id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(project_id),
            candidate_id TEXT NOT NULL,
            candidate_digest TEXT NOT NULL CHECK(length(candidate_digest)=64),
            profile_id TEXT NOT NULL,
            role TEXT NOT NULL,
            evidence_digest TEXT NOT NULL CHECK(length(evidence_digest)=64),
            manifest_digest TEXT NOT NULL CHECK(length(manifest_digest)=64),
            config_source TEXT NOT NULL,
            config_file TEXT NOT NULL,
            expected_config_revision TEXT NOT NULL CHECK(length(expected_config_revision)=64),
            human_request_id TEXT NOT NULL,
            human_response_digest TEXT NOT NULL CHECK(length(human_response_digest)=64),
            approval_subject_digest TEXT NOT NULL CHECK(length(approval_subject_digest)=64),
            profile_material_digest TEXT NOT NULL CHECK(length(profile_material_digest)=64),
            approval_configuration_digest TEXT NOT NULL CHECK(length(approval_configuration_digest)=64),
            approval_policy_digest TEXT NOT NULL CHECK(length(approval_policy_digest)=64),
            approved_package_json TEXT NOT NULL CHECK(length(approved_package_json)<=4194304),
            state TEXT NOT NULL CHECK(state IN ('approved','publication_pending','published','activation_pending','active','stale','rejected')),
            publication_receipt_json TEXT,
            activation_from_revision INTEGER,
            activation_to_revision INTEGER,
            activation_config_digest TEXT,
            applied_config_revision INTEGER,
            applied_config_digest TEXT,
            created_at_unix INTEGER NOT NULL,
            UNIQUE(project_id,role,profile_id,candidate_digest)
        );
        CREATE INDEX profile_promotions_pending ON profile_promotions(project_id,state,created_at_unix);
        INSERT INTO schema_migrations(version,applied_at_unix) VALUES (10,unixepoch());
        PRAGMA user_version=10;"
    ).map_err(|e| e.to_string())?;
    tx.commit().map_err(|e| e.to_string())
}

/// Install learning-owned additions in the shared v12 migration transaction.
/// The caller owns the single schema-version bump and invokes this before commit.
pub(crate) fn migrate_v12_learning_tables(tx: &rusqlite::Transaction<'_>) -> Result<(), String> {
    tx.execute_batch(
        "CREATE TABLE IF NOT EXISTS profile_trial_authorizations (
            authorization_id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(project_id),
            candidate_id TEXT NOT NULL,
            candidate_digest TEXT NOT NULL CHECK(length(candidate_digest)=64),
            human_request_id TEXT NOT NULL UNIQUE,
            request_json TEXT NOT NULL CHECK(length(request_json)<=1048576),
            rex_view_id TEXT NOT NULL CHECK(length(rex_view_id)=64),
            artifact_path TEXT NOT NULL CHECK(length(artifact_path)<=4096),
            authorization_digest TEXT NOT NULL CHECK(length(authorization_digest)=64),
            authorization_json TEXT NOT NULL CHECK(length(authorization_json)<=4194304),
            lifecycle TEXT NOT NULL CHECK(lifecycle IN ('pending','authorized','refused','expired','completed')),
            created_at_unix INTEGER NOT NULL,
            authorized_at_unix INTEGER,
            updated_at_unix INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS profile_trial_authorizations_pending
            ON profile_trial_authorizations(project_id,lifecycle,created_at_unix);
        CREATE TABLE IF NOT EXISTS profile_trial_launches (
            authorization_id TEXT NOT NULL REFERENCES profile_trial_authorizations(authorization_id) ON DELETE CASCADE,
            pair_index INTEGER NOT NULL CHECK(pair_index BETWEEN 0 AND 9),
            side TEXT NOT NULL CHECK(side IN ('baseline','candidate')),
            operation_id TEXT NOT NULL UNIQUE,
            run_id TEXT NOT NULL UNIQUE,
            attempt_id TEXT NOT NULL UNIQUE,
            capsule_digest TEXT NOT NULL CHECK(length(capsule_digest)=64),
            capsule_json TEXT NOT NULL CHECK(length(capsule_json)<=2097152),
            lifecycle TEXT NOT NULL CHECK(lifecycle IN ('prepared','running','uncertain','completed','failed')),
            created_at_unix INTEGER NOT NULL,
            completed_at_unix INTEGER,
            PRIMARY KEY(authorization_id,pair_index,side)
        );
        CREATE INDEX IF NOT EXISTS profile_trial_launches_pending
            ON profile_trial_launches(lifecycle,created_at_unix);
        CREATE TABLE IF NOT EXISTS profile_trial_run_receipts (
            authorization_id TEXT NOT NULL,
            pair_index INTEGER NOT NULL,
            side TEXT NOT NULL,
            run_id TEXT NOT NULL,
            attempt_id TEXT NOT NULL,
            receipt_digest TEXT NOT NULL CHECK(length(receipt_digest)=64),
            receipt_json TEXT NOT NULL CHECK(length(receipt_json)<=65536),
            received_at_unix INTEGER NOT NULL,
            PRIMARY KEY(authorization_id,pair_index,side),
            FOREIGN KEY(authorization_id,pair_index,side)
                REFERENCES profile_trial_launches(authorization_id,pair_index,side) ON DELETE CASCADE,
            UNIQUE(run_id)
        );
        CREATE TABLE IF NOT EXISTS profile_trial_pairs (
            authorization_id TEXT NOT NULL REFERENCES profile_trial_authorizations(authorization_id) ON DELETE CASCADE,
            pair_index INTEGER NOT NULL CHECK(pair_index BETWEEN 0 AND 9),
            input_digest TEXT NOT NULL CHECK(length(input_digest)=64),
            observation_json TEXT NOT NULL CHECK(length(observation_json)<=16384),
            created_at_unix INTEGER NOT NULL,
            PRIMARY KEY(authorization_id,pair_index)
        );"
    ).map_err(|e| e.to_string())
}

/// Refuse databases that claim v10 but do not contain this exact unreleased
/// learning layout before WAL or other connection PRAGMAs can mutate them.
pub(crate) fn validate_v10_schema(connection: &Connection) -> Result<(), String> {
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|e| e.to_string())?;
    if version < 10 {
        return Err(format!(
            "learning layout validation requires schema v10 or later, found v{version}"
        ));
    }
    for (table, expected) in [
        (
            "knowledge_publications",
            &["operation_id", "request_json", "manifest_json"][..],
        ),
        (
            "learning_candidates",
            &[
                "package_files_json",
                "package_manifest_digest",
                "evidence_json",
            ][..],
        ),
        (
            "learning_trial_pairs",
            &["pair_index", "observation_json"][..],
        ),
        (
            "profile_promotions",
            &[
                "config_source",
                "config_file",
                "approval_subject_digest",
                "profile_material_digest",
                "approved_package_json",
            ][..],
        ),
        (
            "supervisor_learning_schedule",
            &[
                "next_due_at_unix",
                "last_run_at_unix",
                "last_snapshot_digest",
            ][..],
        ),
    ] {
        let mut statement = connection
            .prepare("SELECT name FROM pragma_table_info(?1)")
            .map_err(|e| e.to_string())?;
        let actual = statement
            .query_map([table], |row| row.get::<_, String>(0))
            .map_err(|e| e.to_string())?
            .collect::<Result<std::collections::BTreeSet<_>, _>>()
            .map_err(|e| e.to_string())?;
        if expected.iter().any(|column| !actual.contains(*column)) {
            let missing = expected
                .iter()
                .filter(|column| !actual.contains(**column))
                .copied()
                .collect::<Vec<_>>()
                .join(", ");
            return Err(format!(
                "database claims schema v10 but {table} is missing required columns: {missing}"
            ));
        }
    }
    Ok(())
}

impl ConfigStore {
    /// Read the committed publications for one Project through the typed store API.
    pub fn published_knowledge(
        &self,
        project: &ProjectId,
        ticket_run: Option<&TicketRunId>,
        limit: usize,
    ) -> Result<Vec<PublishedKnowledgeRecord>, String> {
        const MAX_ITEMS: usize = 100;
        if limit == 0 || limit > MAX_ITEMS {
            return Err(format!(
                "knowledge result limit must be between 1 and {MAX_ITEMS}"
            ));
        }
        let ticket_run_filter = ticket_run.map(TicketRunId::as_str);
        let mut statement = self.connection.prepare(
            "SELECT ticket_run_id,request_digest,request_json,manifest_json,manifest_digest FROM knowledge_publications WHERE project_id=?1 AND state='published' AND (?2 IS NULL OR ticket_run_id=?2) ORDER BY created_at_unix DESC,ticket_run_id DESC LIMIT ?3",
        ).map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(
                params![project.as_str(), ticket_run_filter, limit as i64],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                },
            )
            .map_err(|error| error.to_string())?;
        let mut publications = Vec::new();
        for row in rows {
            let (ticket_run_id, request_digest, request_json, manifest_json, manifest_digest) =
                row.map_err(|error| error.to_string())?;
            verify_digest(&request_json, &Digest::parse(request_digest)?)?;
            let input: PostmortemInput = crate::protocol::parse_unique(request_json.as_bytes())?;
            validate_postmortem_input(&input).map_err(|error| error.to_string())?;
            let manifest: PublicationManifest =
                crate::protocol::parse_unique(manifest_json.as_bytes())?;
            let manifest_digest = Digest::parse(manifest_digest)?;
            let canonical_manifest = serde_json::to_vec(&manifest).map_err(|e| e.to_string())?;
            if input.project_id != *project
                || input.ticket_run_id.as_str() != ticket_run_id
                || manifest.project_id != *project
                || manifest.ticket_run_id.as_str() != ticket_run_id
                || manifest.operation_id != input.operation_id
                || format!("{:x}", Sha256::digest(&canonical_manifest)) != manifest_digest.as_str()
            {
                return Err("stored knowledge publication has invalid provenance".into());
            }
            publications.push(PublishedKnowledgeRecord {
                input,
                manifest,
                manifest_digest,
            });
        }
        Ok(publications)
    }

    /// Resolve the exact immutable profile-trial authorization for a pending human request.
    /// The table is created by the coordinated v12 learning migration.
    /// Persist the exact bounded trial batch before making its human request visible.
    /// A crash between these writes leaves a harmless pending batch that can be retried.
    pub fn prepare_profile_trial_authorization(
        &mut self,
        generation: u64,
        authorization: &ProfileTrialAuthorization,
        request: &HumanRuntimeRequest,
        rex_view_id: &Digest,
        artifact_path: &std::path::Path,
        now_unix: u64,
    ) -> Result<bool, String> {
        let mut bound = authorization.clone();
        bind_profile_trial_human_request(&mut bound, request)?;
        if bound
            .human_response_receipt_digest
            .as_str()
            .bytes()
            .all(|b| b == b'0')
        {
            // Pending requests must not carry an approval receipt supplied by their caller.
            if authorization
                .human_response_receipt_digest
                .as_str()
                .bytes()
                .any(|b| b != b'0')
            {
                return Err("pending profile trial cannot contain an approval receipt".into());
            }
        }
        let digest = bound.digest()?;
        let json = super::canonical_json(&bound)?;
        let request_json = super::canonical_json(request)?;
        let artifact_path_text = artifact_path.to_string_lossy().into_owned();
        if json.len() > 4 * 1024 * 1024
            || request_json.len() > crate::human_runtime::MAX_HUMAN_REQUEST_BYTES
            || artifact_path_text.len() > 4096
        {
            return Err("profile trial authorization exceeds its durable size limit".into());
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        validate_active_generation(&tx, generation)?;
        let candidate: Option<(String, String, String, String, String)> = tx.query_row(
            "SELECT role,profile_id,status,package_manifest_digest,package_files_json FROM learning_candidates WHERE project_id=?1 AND candidate_id=?2 AND digest=?3",
            params![bound.project_id.as_str(),bound.candidate_id,bound.candidate_digest.as_str()],
            |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)),
        ).optional().map_err(|e| e.to_string())?;
        let Some((role, profile_id, status, manifest_raw, files_json)) = candidate else {
            return Err(
                "profile trial candidate is not present in the durable learning ledger".into(),
            );
        };
        let expected_role = serde_json::to_value(bound.role)
            .map_err(|e| e.to_string())?
            .as_str()
            .ok_or("invalid role")?
            .to_owned();
        if role != expected_role
            || profile_id != bound.candidate.profile_id.as_str()
            || !matches!(status.as_str(), "proposed" | "trialing")
        {
            return Err("profile trial candidate scope or lifecycle is stale".into());
        }
        let current_config: Option<(u64, String)> = tx
            .query_row(
                "SELECT config_revision,config_digest FROM projects WHERE project_id=?1",
                [bound.project_id.as_str()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        let Some((revision, config_digest)) = current_config else {
            return Err("profile trial Project no longer exists".into());
        };
        if revision != bound.config_revision.0 || config_digest != bound.config_digest.as_str() {
            return Err("profile trial config snapshot is stale".into());
        }
        let candidate_files: std::collections::BTreeMap<String, Vec<u8>> =
            crate::protocol::parse_unique(files_json.as_bytes())?;
        let manifest = Digest::parse(manifest_raw)?;
        if crate::learning::manifest_digest(&candidate_files).map_err(|e| e.to_string())?
            != manifest
        {
            return Err("durable candidate package manifest is invalid".into());
        }
        let candidate_config: serde_json::Value =
            crate::protocol::parse_unique(bound.candidate.profile_config_json.as_bytes())?;
        let guidance_path = candidate_config
            .get("learned_guidance")
            .and_then(|value| value.get("file"))
            .and_then(serde_json::Value::as_str)
            .ok_or("candidate profile must bind its learned-guidance file")?;
        let stored_guidance = candidate_files
            .get(guidance_path)
            .ok_or("candidate package does not contain its declared learned-guidance file")?;
        let frozen_guidance = bound
            .candidate
            .instruction_files
            .get(guidance_path)
            .ok_or("trial snapshot omits the candidate learned-guidance file")?;
        if stored_guidance != frozen_guidance {
            return Err(
                "trial snapshot learned-guidance bytes differ from the immutable candidate package"
                    .into(),
            );
        }
        let existing: Option<(String,String,String,String,String)> = tx.query_row(
            "SELECT authorization_digest,authorization_json,request_json,rex_view_id,artifact_path FROM profile_trial_authorizations WHERE authorization_id=?1",
            [bound.authorization_id.as_str()], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)),
        ).optional().map_err(|e| e.to_string())?;
        let inserted = if let Some((
            old_digest,
            old_json,
            old_request_json,
            old_view_id,
            old_artifact_path,
        )) = existing
        {
            if old_digest != digest.as_str()
                || old_json != json
                || old_request_json != request_json
                || old_view_id != rex_view_id.as_str()
                || old_artifact_path != artifact_path_text
            {
                return Err(
                    "profile trial authorization ID was reused with different content".into(),
                );
            }
            false
        } else {
            tx.execute(
                "INSERT INTO profile_trial_authorizations(authorization_id,project_id,candidate_id,candidate_digest,human_request_id,request_json,rex_view_id,artifact_path,authorization_digest,authorization_json,lifecycle,created_at_unix,updated_at_unix) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,'pending',?11,?11)",
                params![bound.authorization_id,bound.project_id.as_str(),bound.candidate_id,bound.candidate_digest.as_str(),bound.human_request_id.as_str(),request_json,rex_view_id.as_str(),artifact_path_text,digest.as_str(),json,now_unix],
            ).map_err(|e| e.to_string())?;
            set_candidate_revision_status(
                &tx,
                &bound.project_id,
                &bound.candidate_id,
                &bound.candidate_digest,
                CandidateStatus::Trialing,
            )?;
            true
        };
        tx.commit().map_err(|e| e.to_string())?;
        self.register_human_request(generation, request, rex_view_id, artifact_path, now_unix)?;
        Ok(inserted)
    }

    /// Turn a pending frozen batch into an authorized batch only from the opaque
    /// receipt minted by the durable human decision store.
    pub fn accept_profile_trial_approval(
        &mut self,
        generation: u64,
        authorization_id: &str,
        now_unix: u64,
    ) -> Result<bool, String> {
        let row: Option<(String,String,String)> = self.connection.query_row(
            "SELECT authorization_json,lifecycle,authorization_digest FROM profile_trial_authorizations WHERE authorization_id=?1",
            [authorization_id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)),
        ).optional().map_err(|e| e.to_string())?;
        let Some((json, lifecycle, stored_digest)) = row else {
            return Err("unknown profile trial authorization".into());
        };
        let pending_json = json.clone();
        let mut authorization: ProfileTrialAuthorization =
            crate::protocol::parse_unique(json.as_bytes())?;
        if authorization.digest()?.as_str() != stored_digest {
            return Err("stored profile trial authorization digest is invalid".into());
        }
        if lifecycle == "authorized" {
            return Ok(false);
        }
        if lifecycle != "pending" {
            return Err(format!("profile trial authorization is {lifecycle}"));
        }
        let receipt = self
            .accepted_human_approval(
                &authorization.human_request_id,
                &authorization.human_subject_digest,
                &authorization.human_configuration_digest,
                &authorization.human_policy_digest,
                now_unix,
            )?
            .ok_or("no current accepted human approval exists for this profile trial")?;
        authorization = accept_profile_trial_approval(authorization, &receipt, now_unix)?;
        let json = super::canonical_json(&authorization)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        validate_active_generation(&tx, generation)?;
        let current: Option<(String,String)> = tx.query_row("SELECT authorization_json,lifecycle FROM profile_trial_authorizations WHERE authorization_id=?1",[authorization_id],|r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(|e|e.to_string())?;
        if current
            .as_ref()
            .is_none_or(|(old_json, state)| old_json != &pending_json || state != "pending")
        {
            return Err(
                "profile trial authorization changed while approval was being checked".into(),
            );
        }
        tx.execute("UPDATE profile_trial_authorizations SET authorization_json=?2,lifecycle='authorized',authorized_at_unix=?3,updated_at_unix=?3 WHERE authorization_id=?1 AND lifecycle='pending'",params![authorization_id,json,now_unix]).map_err(|e|e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(true)
    }

    /// Atomically persist the immutable launch capsule and the Rex start effect.
    /// Existing capsules are returned verbatim for reconciliation after restart.
    pub fn next_profile_trial_launch(
        &mut self,
        generation: u64,
        authorization_id: &str,
        now_unix: u64,
        max_agent_slots: u32,
        max_project_slots: u32,
    ) -> Result<Option<ProfileTrialLaunchCapsule>, String> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        validate_active_generation(&tx, generation)?;
        let row: Option<(String,String,String)> = tx.query_row(
            "SELECT authorization_json,lifecycle,authorization_digest FROM profile_trial_authorizations WHERE authorization_id=?1",
            [authorization_id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)),
        ).optional().map_err(|e| e.to_string())?;
        let Some((auth_json, lifecycle, auth_digest)) = row else {
            return Err("unknown profile trial authorization".into());
        };
        if lifecycle != "authorized" {
            return Err("profile trial batch is not human-authorized".into());
        }
        let authorization: ProfileTrialAuthorization =
            crate::protocol::parse_unique(auth_json.as_bytes())?;
        if authorization.digest()?.as_str() != auth_digest {
            return Err("stored profile trial authorization digest is invalid".into());
        }
        let existing: Option<(String,String)> = tx.query_row(
            "SELECT capsule_json,capsule_digest FROM profile_trial_launches WHERE authorization_id=?1 AND lifecycle IN ('prepared','running','uncertain') ORDER BY pair_index,CASE side WHEN 'baseline' THEN 0 ELSE 1 END LIMIT 1",
            [authorization_id], |r| Ok((r.get(0)?,r.get(1)?)),
        ).optional().map_err(|e| e.to_string())?;
        if let Some((json, digest)) = existing {
            if super::content_digest(&json) != digest {
                return Err("stored profile trial capsule digest is invalid".into());
            }
            let capsule: ProfileTrialLaunchCapsule =
                crate::protocol::parse_unique(json.as_bytes())?;
            capsule.validate()?;
            if capsule.authorization_id != authorization_id
                || capsule.authorization_digest != authorization.digest()?
            {
                return Err("stored trial capsule belongs to a different authorization".into());
            }
            tx.commit().map_err(|e| e.to_string())?;
            return Ok(Some(capsule));
        }
        if now_unix >= authorization.expires_at_unix {
            tx.execute("UPDATE profile_trial_authorizations SET lifecycle='expired',updated_at_unix=?2 WHERE authorization_id=?1 AND lifecycle='authorized'",params![authorization_id,now_unix]).map_err(|e|e.to_string())?;
            set_candidate_revision_status(
                &tx,
                &authorization.project_id,
                &authorization.candidate_id,
                &authorization.candidate_digest,
                CandidateStatus::Expired,
            )?;
            tx.commit().map_err(|e| e.to_string())?;
            return Ok(None);
        }
        if max_agent_slots == 0 || max_project_slots == 0 {
            tx.commit().map_err(|e| e.to_string())?;
            return Ok(None);
        }
        for pair in &authorization.pairs {
            let baseline: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM profile_trial_run_receipts WHERE authorization_id=?1 AND pair_index=?2 AND side='baseline')",
                params![authorization_id,pair.pair_index], |r| r.get(0),
            ).map_err(|e| e.to_string())?;
            let candidate: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM profile_trial_run_receipts WHERE authorization_id=?1 AND pair_index=?2 AND side='candidate')",
                params![authorization_id,pair.pair_index], |r| r.get(0),
            ).map_err(|e| e.to_string())?;
            let side = if !baseline {
                TrialSide::Baseline
            } else if !candidate {
                TrialSide::Candidate
            } else {
                continue;
            };
            let capsule = ProfileTrialLaunchCapsule::from_authorized_matrix(
                &authorization,
                pair.pair_index,
                side,
            )?;
            let global_used: u32 = tx.query_row(
                "SELECT COUNT(*) FROM execution_slots WHERE pool='agent' AND disposition!='released'",
                [], |r| r.get(0),
            ).map_err(|e|e.to_string())?;
            let project_used: u32 = tx.query_row(
                "SELECT COUNT(*) FROM execution_slots WHERE project_id=?1 AND disposition!='released'",
                [authorization.project_id.as_str()], |r| r.get(0),
            ).map_err(|e|e.to_string())?;
            if global_used >= max_agent_slots || project_used >= max_project_slots {
                tx.commit().map_err(|e| e.to_string())?;
                return Ok(None);
            }
            let mut slot_index = None;
            for slot in 0..max_agent_slots {
                let occupied: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM execution_slots WHERE pool='agent' AND slot_index=?1 AND disposition!='released')",
                    [slot], |r| r.get(0),
                ).map_err(|e|e.to_string())?;
                if !occupied {
                    slot_index = Some(slot);
                    break;
                }
            }
            let Some(slot_index) = slot_index else {
                tx.commit().map_err(|e| e.to_string())?;
                return Ok(None);
            };
            let project_epoch: u64 = tx
                .query_row(
                    "SELECT project_epoch FROM project_runtimes WHERE project_id=?1",
                    [authorization.project_id.as_str()],
                    |r| r.get(0),
                )
                .optional()
                .map_err(|e| e.to_string())?
                .ok_or("profile trial Project has no runtime epoch")?;
            let reserved = tx.execute(
                "INSERT INTO execution_slots(pool,slot_index,project_id,ticket_run_id,owner_kind,owner_id,reservation_epoch,controller_generation,disposition) VALUES ('agent',?1,?2,NULL,'profile_trial',?3,?4,?5,'launch_pending') ON CONFLICT(pool,slot_index) DO UPDATE SET project_id=excluded.project_id,ticket_run_id=NULL,owner_kind=excluded.owner_kind,owner_id=excluded.owner_id,reservation_epoch=excluded.reservation_epoch,controller_generation=excluded.controller_generation,process_identity_json=NULL,disposition='launch_pending' WHERE execution_slots.disposition='released'",
                params![slot_index,authorization.project_id.as_str(),capsule.operation_id().as_str(),project_epoch,generation],
            ).map_err(|e|e.to_string())?;
            if reserved != 1 {
                return Err("profile trial execution slot was concurrently reserved".into());
            }
            let capsule_json = super::canonical_json(&capsule)?;
            let capsule_digest = super::content_digest(&capsule_json);
            let side_name = if side == TrialSide::Baseline {
                "baseline"
            } else {
                "candidate"
            };
            let request_json = super::canonical_json(
                &serde_json::json!({"authorization_id":authorization_id,"capsule_digest":capsule_digest,"pair_index":pair.pair_index,"run_id":capsule.run_id.as_str(),"side":side_name}),
            )?;
            let effect = super::EffectIntent {
                project_id: authorization.project_id.clone(),
                subject_type: "project".into(),
                subject_id: authorization.project_id.to_string(),
                operation_id: capsule.operation_id.to_string(),
                logical_key: format!(
                    "profile-trial-{}-{}-{side_name}",
                    authorization_id, pair.pair_index
                ),
                kind: "start_profile_trial".into(),
                request_digest: super::content_digest(&request_json),
                request_json,
                expected_revision: None,
            };
            tx.execute("INSERT INTO profile_trial_launches(authorization_id,pair_index,side,operation_id,run_id,attempt_id,capsule_digest,capsule_json,lifecycle,created_at_unix) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,'prepared',?9)",params![authorization_id,pair.pair_index,side_name,capsule.operation_id.as_str(),capsule.run_id.as_str(),capsule.attempt_id,capsule_digest,capsule_json,now_unix]).map_err(|e|e.to_string())?;
            super::insert_effect(&tx, &effect, now_unix as i64)?;
            tx.commit().map_err(|e| e.to_string())?;
            return Ok(Some(capsule));
        }
        tx.execute("UPDATE profile_trial_authorizations SET lifecycle='completed',updated_at_unix=?2 WHERE authorization_id=?1",params![authorization_id,now_unix]).map_err(|e|e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(None)
    }

    /// Accept only host-minted run evidence; pair results become learning evidence
    /// once both sides have durable terminal receipts.
    pub(crate) fn acknowledge_profile_trial_start(
        &mut self,
        generation: u64,
        operation_id: &OperationId,
        process: &crate::process::ProcessIdentity,
        _now_unix: u64,
    ) -> Result<(), String> {
        if process.pid == 0
            || process.start_identity.trim().is_empty()
            || process.command.trim().is_empty()
        {
            return Err("profile trial start requires a pinned host process identity".into());
        }
        let identity_json = serde_json::to_string(&serde_json::json!({
            "pid": process.pid,
            "parent_pid": process.parent_pid,
            "process_group_id": process.process_group_id,
            "start_identity": process.start_identity,
            "command": process.command,
        }))
        .map_err(|e| e.to_string())?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        validate_active_generation(&tx, generation)?;
        let launch: Option<(String, String, String)> = tx.query_row(
            "SELECT l.lifecycle,a.project_id,l.capsule_digest FROM profile_trial_launches l JOIN profile_trial_authorizations a USING(authorization_id) WHERE l.operation_id=?1",
            [operation_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).optional().map_err(|e| e.to_string())?;
        let Some((lifecycle, project_id, _capsule_digest)) = launch else {
            return Err("profile trial start has no durable launch row".into());
        };
        if !matches!(lifecycle.as_str(), "prepared" | "uncertain" | "running") {
            return Err("profile trial launch is not startable".into());
        }
        let slot: Option<(String, String, Option<String>, u64)> = tx.query_row(
            "SELECT project_id,disposition,process_identity_json,controller_generation FROM execution_slots WHERE pool='agent' AND owner_kind='profile_trial' AND owner_id=?1",
            [operation_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        ).optional().map_err(|e| e.to_string())?;
        let Some((slot_project, disposition, previous_identity, slot_generation)) = slot else {
            return Err("profile trial execution slot is missing".into());
        };
        if slot_project != project_id || slot_generation > generation {
            return Err("profile trial execution slot changed ownership".into());
        }
        if lifecycle == "running" {
            if disposition != "running" || previous_identity.as_deref() != Some(&identity_json) {
                return Err("profile trial start retry has a different process identity".into());
            }
            if slot_generation < generation {
                tx.execute(
                    "UPDATE execution_slots SET controller_generation=?3 WHERE pool='agent' AND owner_kind='profile_trial' AND owner_id=?1 AND project_id=?2 AND controller_generation=?4 AND disposition='running'",
                    params![operation_id.as_str(), project_id, generation, slot_generation],
                ).map_err(|e| e.to_string())?;
            }
        } else {
            let changed = tx.execute(
                "UPDATE execution_slots SET process_identity_json=?3,disposition='running',controller_generation=?4 WHERE pool='agent' AND owner_kind='profile_trial' AND owner_id=?1 AND project_id=?2 AND controller_generation=?5 AND disposition!='released'",
                params![operation_id.as_str(), project_id, identity_json, generation, slot_generation],
            ).map_err(|e| e.to_string())?;
            if changed != 1 {
                return Err(
                    "profile trial execution slot changed before start acknowledgement".into(),
                );
            }
            tx.execute(
                "UPDATE profile_trial_launches SET lifecycle='running' WHERE operation_id=?1 AND lifecycle IN ('prepared','uncertain')",
                [operation_id.as_str()],
            ).map_err(|e| e.to_string())?;
        }
        tx.commit().map_err(|e| e.to_string())
    }

    pub(crate) fn record_profile_trial_run_receipt(
        &mut self,
        generation: u64,
        receipt: &ProfileTrialRunReceipt,
        now_unix: u64,
    ) -> Result<TrialProgress, String> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        validate_active_generation(&tx, generation)?;
        let row: Option<(String,String)> = tx.query_row(
            "SELECT authorization_json,lifecycle FROM profile_trial_authorizations WHERE authorization_id=?1",
            [receipt.authorization_id()], |r| Ok((r.get(0)?,r.get(1)?)),
        ).optional().map_err(|e|e.to_string())?;
        let Some((auth_json, lifecycle)) = row else {
            return Err("trial receipt has no durable authorization".into());
        };
        if lifecycle != "authorized" && lifecycle != "completed" {
            return Err("trial receipt authorization is not active".into());
        }
        let authorization: ProfileTrialAuthorization =
            crate::protocol::parse_unique(auth_json.as_bytes())?;
        receipt.validate_against(&authorization)?;
        let side = if receipt.side() == TrialSide::Baseline {
            "baseline"
        } else {
            "candidate"
        };
        let capsule_row: Option<(String,String,String,String)> = tx.query_row(
            "SELECT capsule_json,capsule_digest,run_id,attempt_id FROM profile_trial_launches WHERE authorization_id=?1 AND pair_index=?2 AND side=?3",
            params![receipt.authorization_id(),receipt.pair_index(),side], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)),
        ).optional().map_err(|e|e.to_string())?;
        let Some((capsule_json, capsule_digest, run_id, attempt_id)) = capsule_row else {
            return Err("trial receipt has no prepared durable launch".into());
        };
        if run_id != receipt.run_id().as_str()
            || attempt_id != receipt.attempt_id()
            || super::content_digest(&capsule_json) != capsule_digest
        {
            return Err("trial receipt does not match its persisted launch identity".into());
        }
        let capsule: ProfileTrialLaunchCapsule =
            crate::protocol::parse_unique(capsule_json.as_bytes())?;
        capsule.validate()?;
        if capsule.authorization_id != authorization.authorization_id
            || capsule.authorization_digest != authorization.digest()?
            || capsule.pair_index != receipt.pair_index()
            || capsule.side != receipt.side()
            || capsule.run_id != *receipt.run_id()
            || capsule.attempt_id != receipt.attempt_id()
        {
            return Err("trial receipt differs from the immutable persisted capsule".into());
        }
        let receipt_json = super::canonical_json(receipt)?;
        if receipt_json.len() > 65536 {
            return Err("profile trial receipt exceeds size limit".into());
        }
        let receipt_digest = super::content_digest(&receipt_json);
        let old: Option<(String,String)> = tx.query_row(
            "SELECT receipt_digest,receipt_json FROM profile_trial_run_receipts WHERE authorization_id=?1 AND pair_index=?2 AND side=?3",
            params![receipt.authorization_id(),receipt.pair_index(),side], |r| Ok((r.get(0)?,r.get(1)?)),
        ).optional().map_err(|e|e.to_string())?;
        if let Some((digest, json)) = old {
            if digest != receipt_digest || json != receipt_json {
                return Err("conflicting terminal trial receipt".into());
            }
        } else {
            tx.execute("INSERT INTO profile_trial_run_receipts(authorization_id,pair_index,side,run_id,attempt_id,receipt_digest,receipt_json,received_at_unix) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",params![receipt.authorization_id(),receipt.pair_index(),side,receipt.run_id().as_str(),receipt.attempt_id(),receipt_digest,receipt_json,now_unix]).map_err(|e|e.to_string())?;
            tx.execute("UPDATE profile_trial_launches SET lifecycle='completed',completed_at_unix=?4 WHERE authorization_id=?1 AND pair_index=?2 AND side=?3",params![receipt.authorization_id(),receipt.pair_index(),side,now_unix]).map_err(|e|e.to_string())?;
        }
        let slot: Option<(u32,String)> = tx.query_row(
            "SELECT slot_index,disposition FROM execution_slots WHERE pool='agent' AND owner_kind='profile_trial' AND owner_id=?1",
            [capsule.operation_id().as_str()], |r| Ok((r.get(0)?,r.get(1)?)),
        ).optional().map_err(|e|e.to_string())?;
        let Some((slot_index, disposition)) = slot else {
            return Err("terminal profile trial receipt has no reserved execution slot".into());
        };
        if disposition != "released" {
            tx.execute("UPDATE execution_slots SET disposition='released',controller_generation=?3 WHERE pool='agent' AND slot_index=?1 AND owner_kind='profile_trial' AND owner_id=?2",params![slot_index,capsule.operation_id().as_str(),generation]).map_err(|e|e.to_string())?;
        }
        let baseline_json: Option<String> = tx.query_row("SELECT receipt_json FROM profile_trial_run_receipts WHERE authorization_id=?1 AND pair_index=?2 AND side='baseline'",params![receipt.authorization_id(),receipt.pair_index()],|r|r.get(0)).optional().map_err(|e|e.to_string())?;
        let candidate_json: Option<String> = tx.query_row("SELECT receipt_json FROM profile_trial_run_receipts WHERE authorization_id=?1 AND pair_index=?2 AND side='candidate'",params![receipt.authorization_id(),receipt.pair_index()],|r|r.get(0)).optional().map_err(|e|e.to_string())?;
        if let (Some(baseline_json), Some(candidate_json)) = (baseline_json, candidate_json) {
            let baseline: ProfileTrialRunReceipt =
                crate::protocol::parse_unique(baseline_json.as_bytes())?;
            let candidate: ProfileTrialRunReceipt =
                crate::protocol::parse_unique(candidate_json.as_bytes())?;
            let observation = TrialObservation {
                input_digest: baseline.input_digest().clone(),
                baseline: baseline.status(),
                candidate: candidate.status(),
            };
            let observation_json = super::canonical_json(&observation)?;
            tx.execute("INSERT INTO profile_trial_pairs(authorization_id,pair_index,input_digest,observation_json,created_at_unix) VALUES (?1,?2,?3,?4,?5) ON CONFLICT DO NOTHING",params![authorization.authorization_id,receipt.pair_index(),observation.input_digest.as_str(),observation_json,now_unix]).map_err(|e|e.to_string())?;
        }
        let mut stmt = tx.prepare("SELECT pair_index,observation_json FROM profile_trial_pairs WHERE authorization_id=?1 ORDER BY pair_index").map_err(|e|e.to_string())?;
        let rows = stmt
            .query_map([authorization.authorization_id.as_str()], |r| {
                Ok((r.get::<_, usize>(0)?, r.get::<_, String>(1)?))
            })
            .map_err(|e| e.to_string())?;
        let mut trials = Vec::new();
        for row in rows {
            let (pair_index, json) = row.map_err(|e| e.to_string())?;
            trials.push(StoredTrial {
                pair_index,
                observation: crate::protocol::parse_unique(json.as_bytes())?,
            });
        }
        drop(stmt);
        let evidence = evaluate_trials(
            &trials
                .iter()
                .map(|t| t.observation.clone())
                .collect::<Vec<_>>(),
            authorization.pairs.len(),
        )
        .map_err(|e| e.to_string())?;
        let evidence_json = super::canonical_json(&evidence)?;
        let expected = authorization.pairs.len();
        let new_status = if trials.len() >= expected {
            "awaiting_approval"
        } else {
            "trialing"
        };
        tx.execute("UPDATE learning_candidates SET evidence_json=?4 WHERE project_id=?1 AND candidate_id=?2 AND digest=?3",params![authorization.project_id.as_str(),authorization.candidate_id,authorization.candidate_digest.as_str(),evidence_json]).map_err(|e|e.to_string())?;
        set_candidate_revision_status(
            &tx,
            &authorization.project_id,
            &authorization.candidate_id,
            &authorization.candidate_digest,
            if new_status == "awaiting_approval" {
                CandidateStatus::AwaitingApproval
            } else {
                CandidateStatus::Trialing
            },
        )?;
        if trials.len() >= expected {
            tx.execute("UPDATE profile_trial_authorizations SET lifecycle='completed',updated_at_unix=?2 WHERE authorization_id=?1",params![authorization.authorization_id,now_unix]).map_err(|e|e.to_string())?;
        }
        tx.commit().map_err(|e| e.to_string())?;
        Ok(TrialProgress { trials, evidence })
    }

    pub fn profile_trial_launch_capsule(
        &self,
        authorization_id: &str,
        pair_index: u8,
        side: TrialSide,
    ) -> Result<Option<ProfileTrialLaunchCapsule>, String> {
        let side = if side == TrialSide::Baseline {
            "baseline"
        } else {
            "candidate"
        };
        let row: Option<(String,String)> = self.connection.query_row("SELECT capsule_json,capsule_digest FROM profile_trial_launches WHERE authorization_id=?1 AND pair_index=?2 AND side=?3",params![authorization_id,pair_index,side],|r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(|e|e.to_string())?;
        let Some((json, digest)) = row else {
            return Ok(None);
        };
        if super::content_digest(&json) != digest {
            return Err("stored profile trial capsule digest is invalid".into());
        }
        let capsule: ProfileTrialLaunchCapsule = crate::protocol::parse_unique(json.as_bytes())?;
        capsule.validate()?;
        Ok(Some(capsule))
    }

    pub fn profile_trial_authorization(
        &self,
        authorization_id: &str,
    ) -> Result<Option<ProfileTrialAuthorization>, String> {
        let row: Option<(String,String)> = self.connection.query_row(
            "SELECT authorization_json,authorization_digest FROM profile_trial_authorizations WHERE authorization_id=?1",
            [authorization_id], |r| Ok((r.get(0)?,r.get(1)?)),
        ).optional().map_err(|e|e.to_string())?;
        let Some((json, digest)) = row else {
            return Ok(None);
        };
        let authorization: ProfileTrialAuthorization =
            crate::protocol::parse_unique(json.as_bytes())?;
        if authorization.digest()?.as_str() != digest {
            return Err("stored profile trial authorization digest is invalid".into());
        }
        authorization.validate()?;
        Ok(Some(authorization))
    }

    /// Resolve only a still-pending batch authorization for the persisted
    /// human request. Host observers use this to reconstitute the exact
    /// subject before accepting a response; approved or terminal batches are
    /// not returned by this lookup.
    pub(crate) fn pending_profile_trial_authorization_for_request(
        &self,
        request_id: &HumanRequestId,
    ) -> Result<Option<ProfileTrialAuthorization>, String> {
        let row: Option<(String, String)> = self
            .connection
            .query_row(
                "SELECT authorization_json,authorization_digest FROM profile_trial_authorizations WHERE human_request_id=?1 AND lifecycle='pending'",
                [request_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let Some((json, digest)) = row else {
            return Ok(None);
        };
        let authorization: ProfileTrialAuthorization =
            crate::protocol::parse_unique(json.as_bytes())?;
        if authorization.human_request_id != *request_id
            || authorization.digest()?.as_str() != digest
        {
            return Err("stored pending profile trial authorization is invalid".into());
        }
        authorization.validate()?;
        Ok(Some(authorization))
    }

    /// A dispatcher retry after the Store commit but before outbox acknowledgement
    /// must replay this exact host receipt instead of starting the Agent again.
    pub(crate) fn profile_trial_terminal_receipt(
        &self,
        operation_id: &OperationId,
    ) -> Result<Option<ProfileTrialRunReceipt>, String> {
        let row: Option<(String,u8,String,String)> = self.connection.query_row(
            "SELECT r.receipt_json,r.pair_index,r.side,r.receipt_digest FROM profile_trial_run_receipts r JOIN profile_trial_launches l USING(authorization_id,pair_index,side) WHERE l.operation_id=?1",
            [operation_id.as_str()], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)),
        ).optional().map_err(|e|e.to_string())?;
        let Some((json, pair_index, side, digest)) = row else {
            return Ok(None);
        };
        if super::content_digest(&json) != digest {
            return Err("stored profile trial terminal receipt digest is invalid".into());
        }
        let receipt: ProfileTrialRunReceipt = crate::protocol::parse_unique(json.as_bytes())?;
        let authorization = self
            .profile_trial_authorization(receipt.authorization_id())?
            .ok_or("trial receipt authorization is missing")?;
        receipt.validate_against(&authorization)?;
        let expected_side = if receipt.side() == TrialSide::Baseline {
            "baseline"
        } else {
            "candidate"
        };
        if receipt.pair_index() != pair_index || expected_side != side {
            return Err("stored profile trial receipt has a mismatched launch scope".into());
        }
        Ok(Some(receipt))
    }

    /// Bounded controller cadence: accept at most one newly decided batch and
    /// materialize at most one next side-effect intent in this tick.
    pub fn tick_profile_trials(
        &mut self,
        generation: u64,
        now_unix: u64,
        max_agent_slots: u32,
        max_project_slots: u32,
    ) -> Result<Option<ProfileTrialLaunchCapsule>, String> {
        let pending: Vec<(String, String, String, String, String)> = {
            let mut stmt = self.connection.prepare(
                "SELECT authorization_id,authorization_json,request_json,rex_view_id,artifact_path FROM profile_trial_authorizations WHERE lifecycle='pending' ORDER BY created_at_unix,authorization_id LIMIT 32",
            ).map_err(|e| e.to_string())?;
            let rows = stmt
                .query_map([], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
                })
                .map_err(|e| e.to_string())?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|e| e.to_string())?
        };
        for (id, json, request_json, rex_view_id, artifact_path) in pending {
            let auth: ProfileTrialAuthorization = crate::protocol::parse_unique(json.as_bytes())?;
            if now_unix >= auth.expires_at_unix {
                let tx = self
                    .connection
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .map_err(|e| e.to_string())?;
                validate_active_generation(&tx, generation)?;
                tx.execute("UPDATE profile_trial_authorizations SET lifecycle='expired',updated_at_unix=?2 WHERE authorization_id=?1 AND lifecycle='pending'",params![id,now_unix]).map_err(|e|e.to_string())?;
                set_candidate_revision_status(
                    &tx,
                    &auth.project_id,
                    &auth.candidate_id,
                    &auth.candidate_digest,
                    CandidateStatus::Expired,
                )?;
                tx.commit().map_err(|e| e.to_string())?;
                continue;
            }
            let request_exists: bool = self
                .connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM human_requests WHERE request_id=?1)",
                    [auth.human_request_id.as_str()],
                    |r| r.get(0),
                )
                .map_err(|e| e.to_string())?;
            if !request_exists {
                let request: HumanRuntimeRequest =
                    crate::protocol::parse_unique(request_json.as_bytes())?;
                self.register_human_request(
                    generation,
                    &request,
                    &Digest::parse(rex_view_id)?,
                    std::path::Path::new(&artifact_path),
                    now_unix,
                )?;
            }
            if self
                .accepted_human_approval(
                    &auth.human_request_id,
                    &auth.human_subject_digest,
                    &auth.human_configuration_digest,
                    &auth.human_policy_digest,
                    now_unix,
                )?
                .is_some()
            {
                self.accept_profile_trial_approval(generation, &id, now_unix)?;
                return self.next_profile_trial_launch(
                    generation,
                    &id,
                    now_unix,
                    max_agent_slots,
                    max_project_slots,
                );
            }
        }
        let authorized: Option<String> = self.connection.query_row(
            "SELECT authorization_id FROM profile_trial_authorizations WHERE lifecycle='authorized' ORDER BY authorized_at_unix,authorization_id LIMIT 1",
            [], |r| r.get(0),
        ).optional().map_err(|e|e.to_string())?;
        match authorized {
            Some(id) => self.next_profile_trial_launch(
                generation,
                &id,
                now_unix,
                max_agent_slots,
                max_project_slots,
            ),
            None => Ok(None),
        }
    }

    pub(crate) fn ensure_postmortem_published(
        &self,
        ticket_run_id: &TicketRunId,
    ) -> Result<(), String> {
        let operation: Option<String> = self.connection.query_row(
            "SELECT operation_id FROM knowledge_publications WHERE ticket_run_id=?1 AND state='published'",
            [ticket_run_id.as_str()],
            |row| row.get(0),
        ).optional().map_err(|e| e.to_string())?;
        let Some(operation) = operation else {
            return Err("ticket cannot become Done before durable knowledge publication".into());
        };
        let operation_id = OperationId::parse(operation)?;
        if self.knowledge_publication_receipt(&operation_id)?.is_none() {
            return Err(
                "ticket cannot become Done before a valid knowledge publication receipt".into(),
            );
        }
        Ok(())
    }

    /// Read the immutable package and approval tuple required to replay a profile
    /// publication effect. The caller must still reload the opaque human receipt.
    pub fn profile_promotion_intent(
        &self,
        operation_id: &OperationId,
    ) -> Result<Option<ProfilePromotionIntent>, String> {
        type Row = (
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            String,
        );
        let row: Option<Row> = self.connection.query_row(
            "SELECT project_id,candidate_id,candidate_digest,evidence_digest,profile_id,role,manifest_digest,expected_config_revision,config_source,config_file,human_request_id,approval_subject_digest,profile_material_digest,approval_configuration_digest,approval_policy_digest,human_response_digest,approved_package_json,state FROM profile_promotions WHERE operation_id=?1",
            [operation_id.as_str()],
            |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?,r.get(9)?,r.get(10)?,r.get(11)?,r.get(12)?,r.get(13)?,r.get(14)?,r.get(15)?,r.get(16)?,r.get(17)?)),
        ).optional().map_err(|e| e.to_string())?;
        let Some((
            project_id,
            candidate_id,
            candidate_digest,
            evidence_digest,
            profile_id,
            role,
            manifest,
            config_revision,
            source,
            config_file,
            request_id,
            subject,
            profile_material,
            configuration,
            policy,
            response,
            package_json,
            state,
        )) = row
        else {
            return Ok(None);
        };
        if !matches!(
            state.as_str(),
            "approved" | "publication_pending" | "published" | "activation_pending" | "active"
        ) {
            return Err(format!("profile promotion is terminally {state}"));
        }
        let project_id = ProjectId::parse(project_id)?;
        let candidate_digest = Digest::parse(candidate_digest)?;
        let evidence_digest = Digest::parse(evidence_digest)?;
        let profile_id = ProfileId::parse(profile_id)?;
        let manifest_digest = Digest::parse(manifest)?;
        let expected_config_revision = Digest::parse(config_revision)?;
        let human_request_id = HumanRequestId::parse(request_id)?;
        let approval_subject_digest = Digest::parse(subject)?;
        let profile_material_digest = Digest::parse(profile_material)?;
        let approval_configuration_digest = Digest::parse(configuration)?;
        let approval_policy_digest = Digest::parse(policy)?;
        let response_receipt_digest = Digest::parse(response)?;
        let role: crate::domain::types::Role = serde_json::from_str(&format!("\"{role}\""))
            .map_err(|e| format!("stored profile role is invalid: {e}"))?;
        if package_json.len() > MAX_RECORD_BYTES {
            return Err("stored approved profile package exceeds its limit".into());
        }
        let package: StoredApprovedProfilePackage = serde_json::from_str(&package_json)
            .map_err(|e| format!("stored approved profile package is invalid: {e}"))?;
        if package.project_id != project_id
            || package.profile_id != profile_id
            || package.role != role
            || package.candidate_digest != candidate_digest
            || package.human_request_id != human_request_id
            || package.approval_subject_digest != approval_subject_digest
            || package.profile_material_digest != profile_material_digest
            || package.approval_configuration_digest != approval_configuration_digest
            || package.approval_policy_digest != approval_policy_digest
            || package.response_receipt_digest != response_receipt_digest
            || package.config_revision != expected_config_revision
            || package.candidate_digest.as_str().is_empty()
            || crate::learning::manifest_digest(&package.files).map_err(|e| e.to_string())?
                != manifest_digest
        {
            return Err(
                "stored profile package does not match its immutable promotion identity".into(),
            );
        }
        let subject = crate::learning::profile_approval_subject_digest(
            &project_id,
            role,
            &profile_id,
            &package.candidate_digest,
            &package.files,
            &package.evidence,
            &expected_config_revision,
        )
        .map_err(|e| e.to_string())?;
        if subject != profile_material_digest
            || crate::learning::evidence_digest(&package.evidence).map_err(|e| e.to_string())?
                != evidence_digest
        {
            return Err("stored promotion subject or evidence digest is invalid".into());
        }
        Ok(Some(ProfilePromotionIntent {
            operation_id: operation_id.clone(),
            project_id,
            candidate_id,
            profile_id,
            role,
            manifest_digest,
            profile_material_digest,
            expected_config_revision,
            config_source: source,
            config_file,
            human_request_id,
            approval_subject_digest,
            approval_configuration_digest,
            approval_policy_digest,
            response_receipt_digest,
            package,
        }))
    }

    pub(crate) fn load_approved_profile_package(
        &self,
        intent: &ProfilePromotionIntent,
        now_unix: u64,
    ) -> Result<ProfilePackage, String> {
        let current = self
            .profile_promotion_intent(&intent.operation_id)?
            .ok_or("profile promotion intent disappeared")?;
        if current != *intent {
            return Err("profile promotion intent changed during dispatch".into());
        }
        let request_json: String = self
            .connection
            .query_row(
                "SELECT request_json FROM human_requests WHERE request_id=?1",
                [intent.human_request_id.as_str()],
                |row| row.get(0),
            )
            .map_err(|_| "profile promotion human request is missing".to_owned())?;
        let request: crate::human_runtime::HumanRuntimeRequest =
            crate::protocol::parse_unique(request_json.as_bytes())?;
        if request.purpose != crate::human_runtime::HumanPurpose::ProfilePromotion
            || request.subject.kind != crate::human_runtime::HumanSubjectKind::Profile
            || request.subject.project_id != intent.project_id
            || request.subject.subject_id != intent.candidate_id
            || request.subject.material_digest != intent.profile_material_digest
            || request.subject.configuration_digest != intent.approval_configuration_digest
            || request.subject.policy_digest != intent.approval_policy_digest
            || request.subject.digest().map_err(|e| e.to_string())?
                != intent.approval_subject_digest
        {
            return Err(
                "durable profile approval request no longer matches the approved package".into(),
            );
        }
        let receipt = self
            .accepted_human_approval(
                &intent.human_request_id,
                &intent.approval_subject_digest,
                &intent.approval_configuration_digest,
                &intent.approval_policy_digest,
                now_unix,
            )?
            .ok_or("profile promotion human approval is missing, stale, or expired")?;
        let stored = &intent.package;
        let package = crate::learning::profile_package_from_accepted_approval(
            &receipt,
            stored.project_id.clone(),
            stored.role,
            stored.profile_id.clone(),
            stored.candidate_digest.clone(),
            stored.evidence.clone(),
            stored.files.clone(),
            intent.approval_subject_digest.clone(),
            intent.profile_material_digest.clone(),
            stored.config_revision.clone(),
            stored.approval_configuration_digest.clone(),
            stored.approval_policy_digest.clone(),
            now_unix,
        )
        .map_err(|e| e.to_string())?;
        let claims = validated_promotion_claims(&package).map_err(|e| e.to_string())?;
        if claims.human_request_id != stored.human_request_id
            || claims.approval_subject_digest != stored.approval_subject_digest
            || claims.approval_configuration_digest != stored.approval_configuration_digest
            || claims.approval_policy_digest != stored.approval_policy_digest
            || claims.response_receipt_digest != stored.response_receipt_digest
            || claims.rationale != stored.rationale
            || claims.authorized_at != stored.authorized_at
        {
            return Err("current human receipt differs from the immutable approved package".into());
        }
        Ok(package)
    }

    pub fn profile_publication_receipt(
        &self,
        operation_id: &OperationId,
    ) -> Result<Option<ProfilePublicationReceipt>, String> {
        let row: Option<(String, Option<String>, String)> = self.connection.query_row(
            "SELECT state,publication_receipt_json,manifest_digest FROM profile_promotions WHERE operation_id=?1",
            [operation_id.as_str()],
            |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)),
        ).optional().map_err(|e|e.to_string())?;
        let Some((state, json, expected_manifest)) = row else {
            return Ok(None);
        };
        if !matches!(
            state.as_str(),
            "published" | "activation_pending" | "active"
        ) {
            return Ok(None);
        }
        let stored: StoredProfilePublicationReceipt = serde_json::from_str(
            json.as_deref()
                .ok_or("published profile has no durable receipt")?,
        )
        .map_err(|e| format!("stored profile receipt is invalid: {e}"))?;
        if stored.manifest_digest.as_str() != expected_manifest {
            return Err("stored profile receipt manifest differs from approved intent".into());
        }
        let response: String = self
            .connection
            .query_row(
                "SELECT human_response_digest FROM profile_promotions WHERE operation_id=?1",
                [operation_id.as_str()],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())?;
        if stored.human_response_receipt_digest.as_str() != response {
            return Err("stored profile receipt belongs to a different human response".into());
        }
        Ok(Some(ProfilePublicationReceipt {
            profile_path: std::path::PathBuf::from(stored.profile_path),
            profile_manifest_digest: stored.manifest_digest,
            human_response_receipt_digest: stored.human_response_receipt_digest,
            status: if stored.already_published {
                ProfilePublicationStatus::AlreadyPublished
            } else {
                ProfilePublicationStatus::Published
            },
        }))
    }

    /// Load the exact durable request for an outbox effect. The effect runner
    /// must use this stored input rather than any Agent-supplied replay payload.
    pub fn knowledge_publication_intent(
        &self,
        operation_id: &OperationId,
    ) -> Result<Option<KnowledgePublicationIntent>, String> {
        let row: Option<(String, String, String, String, String)> = self
            .connection
            .query_row(
                "SELECT project_id,ticket_run_id,request_digest,request_json,state FROM knowledge_publications WHERE operation_id=?1",
                [operation_id.as_str()],
                |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let Some((project_id, ticket_run_id, request_digest, request_json, state)) = row else {
            return Ok(None);
        };
        if !matches!(state.as_str(), "prepared" | "published" | "uncertain") {
            return Err(format!("knowledge publication is terminally {state}"));
        }
        let request_digest = Digest::parse(request_digest)?;
        verify_digest(&request_json, &request_digest)?;
        let request: PostmortemInput = serde_json::from_str(&request_json)
            .map_err(|error| format!("stored postmortem request is invalid: {error}"))?;
        let project_id = ProjectId::parse(project_id)?;
        let ticket_run_id = TicketRunId::parse(ticket_run_id)?;
        if request.operation_id != *operation_id
            || request.project_id != project_id
            || request.ticket_run_id != ticket_run_id
        {
            return Err("stored knowledge request does not match its durable identity".into());
        }
        validate_postmortem_input(&request).map_err(|error| error.to_string())?;
        Ok(Some(KnowledgePublicationIntent {
            operation_id: operation_id.clone(),
            project_id,
            ticket_run_id,
            request_digest,
            request_json,
        }))
    }

    /// Return the committed terminal receipt, if publication completed before
    /// the generic dispatcher recorded its outbox receipt.
    pub fn knowledge_publication_receipt(
        &self,
        operation_id: &OperationId,
    ) -> Result<Option<KnowledgePublicationReceipt>, String> {
        let row: Option<(String, Option<String>, Option<String>)> = self
            .connection
            .query_row(
                "SELECT state,manifest_json,manifest_digest FROM knowledge_publications WHERE operation_id=?1",
                [operation_id.as_str()],
                |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let Some((state, manifest_json, manifest_digest)) = row else {
            return Ok(None);
        };
        if state != "published" {
            return Ok(None);
        }
        let manifest: PublicationManifest = serde_json::from_str(
            manifest_json
                .as_deref()
                .ok_or("published knowledge row has no manifest")?,
        )
        .map_err(|error| format!("stored publication manifest is invalid: {error}"))?;
        let manifest_digest =
            Digest::parse(manifest_digest.ok_or("published knowledge row has no digest")?)?;
        let canonical = serde_json::to_vec(&manifest).map_err(|error| error.to_string())?;
        if format!("{:x}", Sha256::digest(&canonical)) != manifest_digest.as_str() {
            return Err("stored publication receipt digest is invalid".into());
        }
        if manifest.operation_id != *operation_id {
            return Err("stored publication receipt has a different operation ID".into());
        }
        Ok(Some(KnowledgePublicationReceipt {
            manifest,
            manifest_digest,
        }))
    }

    /// Persist the immutable postmortem request before filesystem publication.
    pub fn prepare_knowledge_publication(
        &mut self,
        generation: u64,
        intent: &KnowledgePublicationIntent,
    ) -> Result<bool, String> {
        verify_digest(&intent.request_json, &intent.request_digest)?;
        if intent.request_json.len() > MAX_RECORD_BYTES {
            return Err("knowledge request exceeds size limit".into());
        }
        let request: PostmortemInput = serde_json::from_str(&intent.request_json)
            .map_err(|error| format!("invalid postmortem request: {error}"))?;
        validate_postmortem_input(&request).map_err(|error| error.to_string())?;
        if request.operation_id != intent.operation_id
            || request.project_id != intent.project_id
            || request.ticket_run_id != intent.ticket_run_id
        {
            return Err("postmortem request does not match durable operation subject".into());
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        validate_active_generation(&tx, generation)?;
        let old: Option<(String,String)> = tx.query_row("SELECT request_digest,request_json FROM knowledge_publications WHERE operation_id=?1",[intent.operation_id.as_str()],|r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(|e|e.to_string())?;
        if let Some((digest, json)) = old {
            if digest != intent.request_digest.as_str() || json != intent.request_json {
                return Err("knowledge operation ID reused with different content".into());
            }
            tx.commit().map_err(|e| e.to_string())?;
            return Ok(false);
        }
        let current_run: Option<(u64, String)> = tx.query_row(
            "SELECT revision,internal_phase FROM ticket_runs WHERE ticket_run_id=?1 AND project_id=?2",
            params![intent.ticket_run_id.as_str(), intent.project_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional().map_err(|e| e.to_string())?;
        let (revision, phase) = current_run.ok_or("knowledge ticket run no longer exists")?;
        if phase != "postmortem" {
            return Err("knowledge publication can only begin during the Postmortem phase".into());
        }
        tx.execute("INSERT INTO knowledge_publications(operation_id,project_id,ticket_run_id,request_digest,request_json,state,created_at_unix) VALUES (?1,?2,?3,?4,?5,'prepared',?6)",params![intent.operation_id.as_str(),intent.project_id.as_str(),intent.ticket_run_id.as_str(),intent.request_digest.as_str(),intent.request_json,super::now_unix()?]).map_err(|e|e.to_string())?;
        let request_json = super::canonical_json(&serde_json::json!({
            "operation_id": intent.operation_id.as_str(),
            "request_digest": intent.request_digest.as_str(),
        }))?;
        let effect = super::EffectIntent {
            project_id: intent.project_id.clone(),
            subject_type: "ticket_run".into(),
            subject_id: intent.ticket_run_id.to_string(),
            operation_id: intent.operation_id.to_string(),
            logical_key: format!("publish-knowledge-{}", intent.ticket_run_id),
            kind: "publish_knowledge".into(),
            request_digest: super::content_digest(&request_json),
            request_json,
            expected_revision: Some(revision),
        };
        super::insert_effect(&tx, &effect, super::now_unix()?)?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(true)
    }

    /// Persist an immutable publication receipt. Replays must match its exact manifest.
    pub fn record_knowledge_publication(
        &mut self,
        generation: u64,
        operation_id: &OperationId,
        manifest: &PublicationManifest,
        manifest_digest: &Digest,
    ) -> Result<bool, String> {
        let json = serde_json::to_string(manifest).map_err(|e| e.to_string())?;
        verify_digest(&json, manifest_digest)?;
        if manifest.operation_id != *operation_id {
            return Err("publication operation ID mismatch".into());
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        validate_active_generation(&tx, generation)?;
        let row: Option<PublicationDbRow> = tx.query_row("SELECT project_id,ticket_run_id,state,request_json,manifest_json,manifest_digest FROM knowledge_publications WHERE operation_id=?1",[operation_id.as_str()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))).optional().map_err(|e|e.to_string())?;
        let Some((project, run, state, request_json, old_json, old_digest)) = row else {
            return Err("publication receipt has no durable intent".into());
        };
        if project != manifest.project_id.as_str() || run != manifest.ticket_run_id.as_str() {
            return Err("publication receipt subject mismatch".into());
        }
        let request: PostmortemInput = serde_json::from_str(&request_json)
            .map_err(|error| format!("stored postmortem request is invalid: {error}"))?;
        let mut expected_sources = request
            .sources
            .iter()
            .map(|source| source.digest.clone())
            .collect::<Vec<_>>();
        expected_sources.sort();
        let key = format!(
            "{:x}",
            Sha256::digest(request.ticket_run_id.as_str().as_bytes())
        );
        let expected_path = format!(
            "projects/{}/postmortems/{key}.md",
            request.project_id.as_str()
        );
        if manifest.operation_id != request.operation_id
            || manifest.project_id != request.project_id
            || manifest.ticket_run_id != request.ticket_run_id
            || manifest.format != "okf-0.2"
            || manifest.relative_path != expected_path
            || manifest.byte_count > DEFAULT_MAX_ARTICLE_BYTES
            || manifest.source_digests != expected_sources
        {
            return Err(
                "publication manifest does not match the durable postmortem request".into(),
            );
        }
        if state == "published" {
            if old_json.as_deref() == Some(json.as_str())
                && old_digest.as_deref() == Some(manifest_digest.as_str())
            {
                tx.commit().map_err(|e| e.to_string())?;
                return Ok(false);
            }
            return Err("immutable publication receipt conflict".into());
        }
        if state != "prepared" {
            return Err(format!("knowledge operation is {state}, not prepared"));
        }
        tx.execute("UPDATE knowledge_publications SET state='published',manifest_json=?2,manifest_digest=?3,published_at_unix=?4 WHERE operation_id=?1 AND state='prepared'",params![operation_id.as_str(),json,manifest_digest.as_str(),super::now_unix()?]).map_err(|e|e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(true)
    }

    /// Reconstruct exact candidate bytes from the immutable bounded manifest.
    /// The digest is revalidated before host review code can observe them.
    pub fn learning_candidate_package(
        &self,
        project: &ProjectId,
        candidate_id: &str,
        candidate_digest: &Digest,
    ) -> Result<Option<LearningCandidatePackage>, String> {
        let row: Option<(String, String, String, String, Option<String>)> = self.connection.query_row(
            "SELECT revision_json,profile_id,package_manifest_digest,package_files_json,evidence_json FROM learning_candidates WHERE project_id=?1 AND candidate_id=?2 AND digest=?3",
            params![project.as_str(),candidate_id,candidate_digest.as_str()],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)),
        ).optional().map_err(|e|e.to_string())?;
        let Some((revision_json, profile_id, manifest_raw, files_json, evidence_json)) = row else {
            return Ok(None);
        };
        let revision: CandidateRevision = crate::protocol::parse_unique(revision_json.as_bytes())?;
        let profile_id = ProfileId::parse(profile_id)?;
        let manifest_digest = Digest::parse(manifest_raw)?;
        let files: std::collections::BTreeMap<String, Vec<u8>> =
            crate::protocol::parse_unique(files_json.as_bytes())?;
        if revision.project_id != *project
            || revision.candidate_id != candidate_id
            || revision.digest != *candidate_digest
            || serde_json::to_string(&files).map_err(|e| e.to_string())? != files_json
            || crate::learning::manifest_digest(&files).map_err(|e| e.to_string())?
                != manifest_digest
        {
            return Err(
                "stored candidate files do not match the immutable candidate identity".into(),
            );
        }
        let evidence = evidence_json
            .map(|json| crate::protocol::parse_unique(json.as_bytes()))
            .transpose()?;
        Ok(Some(LearningCandidatePackage {
            revision,
            profile_id,
            manifest_digest,
            files,
            evidence,
        }))
    }

    /// Resolve the single currently approval-eligible revision by its stable
    /// candidate ID. Ambiguous IDs fail closed instead of choosing by recency.
    pub fn current_learning_candidate_package(
        &self,
        project: &ProjectId,
        candidate_id: &str,
    ) -> Result<Option<LearningCandidatePackage>, String> {
        let mut statement = self.connection.prepare(
            "SELECT digest FROM learning_candidates WHERE project_id=?1 AND candidate_id=?2 AND status='awaiting_approval' ORDER BY digest",
        ).map_err(|e| e.to_string())?;
        let rows = statement
            .query_map(params![project.as_str(), candidate_id], |row| {
                row.get::<_, String>(0)
            })
            .map_err(|e| e.to_string())?;
        let digests = rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        drop(statement);
        match digests.as_slice() {
            [] => Ok(None),
            [digest] => self.learning_candidate_package(
                project,
                candidate_id,
                &Digest::parse(digest.clone())?,
            ),
            _ => Err("candidate ID has multiple approval-eligible revisions".into()),
        }
    }

    pub fn register_learning_candidate(
        &mut self,
        generation: u64,
        record: &LearningCandidateRecord,
    ) -> Result<CandidateRegistration, String> {
        if !(5..=MAX_TRIALS).contains(&record.expected_pairs)
            || record.package_json.len() > MAX_RECORD_BYTES
            || record.package_files_json.len() > MAX_RECORD_BYTES
            || record.revision.status != CandidateStatus::Proposed
        {
            return Err("candidate package, identity, or trial count exceeds bounds".into());
        }
        verify_digest(&record.package_json, &record.package_manifest_digest)?;
        let files: std::collections::BTreeMap<String, Vec<u8>> =
            crate::protocol::parse_unique(record.package_files_json.as_bytes())?;
        if serde_json::to_string(&files).map_err(|e| e.to_string())? != record.package_files_json
            || crate::learning::manifest_digest(&files).map_err(|e| e.to_string())?
                != record.package_manifest_digest
        {
            return Err("candidate file bytes do not match their immutable manifest".into());
        }
        let revision_json = serde_json::to_string(&record.revision).map_err(|e| e.to_string())?;
        let role = serde_json::to_value(record.revision.role)
            .map_err(|e| e.to_string())?
            .as_str()
            .ok_or("invalid role")?
            .to_owned();
        let status = serde_json::to_value(record.revision.status)
            .map_err(|e| e.to_string())?
            .as_str()
            .ok_or("invalid candidate status")?
            .to_owned();
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        validate_active_generation(&tx, generation)?;
        let prior:Option<(String,String,String,String,usize)>=tx.query_row("SELECT revision_json,package_manifest_digest,package_files_json,package_json,expected_pairs FROM learning_candidates WHERE project_id=?1 AND candidate_id=?2 AND digest=?3",params![record.revision.project_id.as_str(),record.revision.candidate_id,record.revision.digest.as_str()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional().map_err(|e|e.to_string())?;
        if let Some(found) = prior {
            let expected = (
                revision_json,
                record.package_manifest_digest.to_string(),
                record.package_files_json.clone(),
                record.package_json.clone(),
                record.expected_pairs,
            );
            if found != expected {
                return Err("candidate identity has different immutable content".into());
            }
            tx.commit().map_err(|e| e.to_string())?;
            return Ok(CandidateRegistration::AlreadyRegistered);
        }
        let mut ledger = CandidateLedger::default();
        let mut statement = tx
            .prepare("SELECT revision_json FROM learning_candidates WHERE project_id=?1")
            .map_err(|e| e.to_string())?;
        let rows = statement
            .query_map([record.revision.project_id.as_str()], |row| {
                row.get::<_, String>(0)
            })
            .map_err(|e| e.to_string())?;
        for row in rows {
            ledger.revisions.push(
                serde_json::from_str(&row.map_err(|e| e.to_string())?)
                    .map_err(|e| format!("stored candidate revision is invalid: {e}"))?,
            );
        }
        drop(statement);
        let before = ledger.revisions.clone();
        ledger
            .register(record.revision.clone())
            .map_err(|error| error.to_string())?;
        let retained = ledger
            .revisions
            .iter()
            .map(|revision| (revision.candidate_id.clone(), revision.digest.to_string()))
            .collect::<std::collections::BTreeSet<_>>();
        for old in before {
            if !retained.contains(&(old.candidate_id.clone(), old.digest.to_string())) {
                tx.execute(
                    "DELETE FROM learning_candidates WHERE project_id=?1 AND candidate_id=?2 AND digest=?3",
                    params![record.revision.project_id.as_str(), old.candidate_id, old.digest.as_str()],
                )
                .map_err(|e| e.to_string())?;
            }
        }
        tx.execute("INSERT INTO learning_candidates(project_id,candidate_id,role,digest,profile_id,revision_json,package_manifest_digest,package_files_json,package_json,expected_pairs,status,created_at_unix) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",params![record.revision.project_id.as_str(),record.revision.candidate_id,role,record.revision.digest.as_str(),record.profile_id.as_str(),revision_json,record.package_manifest_digest.as_str(),record.package_files_json,record.package_json,record.expected_pairs,status,super::now_unix()?]).map_err(|e|e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(CandidateRegistration::Registered)
    }

    /// One bounded per-project maintenance snapshot for a Supervisor tick.
    /// Expiration is persisted before the snapshot is returned so a crash/retry
    /// sees the same terminal candidate revisions and cannot extend their TTL.
    pub fn maintain_project_supervisor_learning(
        &mut self,
        generation: u64,
        project: &ProjectId,
        now_utc: &str,
        knowledge_limit: usize,
    ) -> Result<ProjectSupervisorMaintenance, String> {
        if knowledge_limit == 0 || knowledge_limit > MAX_SUPERVISOR_KNOWLEDGE_ITEMS {
            return Err("Supervisor knowledge batch size is outside the configured bound".into());
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        validate_active_generation(&tx, generation)?;
        let project_exists: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM projects WHERE project_id=?1)",
                [project.as_str()],
                |row| row.get(0),
            )
            .map_err(|e| e.to_string())?;
        if !project_exists {
            return Err("Supervisor learning tick references an unknown project".into());
        }
        let mut ledger = CandidateLedger::default();
        let mut revisions_stmt = tx.prepare(
            "SELECT revision_json FROM learning_candidates WHERE project_id=?1 ORDER BY created_at_unix,candidate_id,digest",
        ).map_err(|e|e.to_string())?;
        let rows = revisions_stmt
            .query_map([project.as_str()], |row| row.get::<_, String>(0))
            .map_err(|e| e.to_string())?;
        for row in rows {
            ledger.revisions.push(
                serde_json::from_str(&row.map_err(|e| e.to_string())?)
                    .map_err(|e| format!("stored candidate revision is invalid: {e}"))?,
            );
        }
        drop(revisions_stmt);
        let expired_candidates = ledger.expire_due(now_utc).map_err(|e| e.to_string())?;
        for revision in ledger
            .revisions
            .iter()
            .filter(|r| r.status == CandidateStatus::Expired)
        {
            set_candidate_revision_status(
                &tx,
                project,
                &revision.candidate_id,
                &revision.digest,
                CandidateStatus::Expired,
            )?;
        }

        let mut knowledge_stmt = tx.prepare(
            "SELECT ticket_run_id,request_json,manifest_json,manifest_digest FROM knowledge_publications WHERE project_id=?1 AND state='published' ORDER BY created_at_unix DESC,ticket_run_id DESC LIMIT ?2",
        ).map_err(|e|e.to_string())?;
        let knowledge_rows = knowledge_stmt
            .query_map(params![project.as_str(), knowledge_limit as i64], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })
            .map_err(|e| e.to_string())?;
        let mut knowledge = Vec::new();
        for row in knowledge_rows {
            let (run_id, request_json, manifest_json, digest) = row.map_err(|e| e.to_string())?;
            let input: PostmortemInput = crate::protocol::parse_unique(request_json.as_bytes())?;
            validate_postmortem_input(&input).map_err(|e| e.to_string())?;
            let manifest: PublicationManifest =
                crate::protocol::parse_unique(manifest_json.as_bytes())?;
            let manifest_digest = Digest::parse(digest)?;
            if manifest.project_id != *project
                || manifest.ticket_run_id.as_str() != run_id
                || manifest.operation_id != input.operation_id
                || manifest_digest.as_str()
                    != format!(
                        "{:x}",
                        Sha256::digest(serde_json::to_vec(&manifest).map_err(|e| e.to_string())?)
                    )
                    .as_str()
            {
                return Err(
                    "stored Supervisor knowledge publication has invalid provenance".into(),
                );
            }
            knowledge.push(SupervisorKnowledgeEntry {
                ticket_run_id: manifest.ticket_run_id,
                generated_at: input.generated_at,
                title: input.title,
                summary: input.summary,
                findings: input.findings,
                source_digests: manifest.source_digests,
            });
        }
        drop(knowledge_stmt);

        let mut candidates_stmt = tx.prepare(
            "SELECT revision_json,profile_id,package_manifest_digest,expected_pairs,evidence_json FROM learning_candidates WHERE project_id=?1 AND status IN ('proposed','trialing','awaiting_approval') ORDER BY created_at_unix,candidate_id,digest LIMIT ?2",
        ).map_err(|e|e.to_string())?;
        let candidate_rows = candidates_stmt
            .query_map(
                params![project.as_str(), MAX_SUPERVISOR_CANDIDATES as i64],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, usize>(3)?,
                        row.get::<_, Option<String>>(4)?,
                    ))
                },
            )
            .map_err(|e| e.to_string())?;
        let mut candidates = Vec::new();
        for row in candidate_rows {
            let (revision_json, profile_id, manifest_digest, expected_pairs, evidence_json) =
                row.map_err(|e| e.to_string())?;
            let revision: CandidateRevision =
                crate::protocol::parse_unique(revision_json.as_bytes())?;
            let evidence = evidence_json
                .map(|json| crate::protocol::parse_unique(json.as_bytes()))
                .transpose()?;
            candidates.push(SupervisorCandidateEntry {
                revision,
                profile_id: ProfileId::parse(profile_id)?,
                package_manifest_digest: Digest::parse(manifest_digest)?,
                expected_pairs,
                evidence,
            });
        }
        drop(candidates_stmt);
        let snapshot = ProjectSupervisorMaintenance {
            project_id: project.clone(),
            expired_candidates,
            knowledge,
            candidates,
        };
        if serde_json::to_vec(&snapshot)
            .map_err(|e| e.to_string())?
            .len()
            > MAX_SUPERVISOR_CONTEXT_BYTES
        {
            return Err("Supervisor learning context exceeds its aggregate byte limit".into());
        }
        tx.commit().map_err(|e| e.to_string())?;
        Ok(snapshot)
    }

    /// At most one due Project per controller tick gets a bounded learning
    /// snapshot and a durable Supervisor wake. The wake and next due time commit
    /// together; a crash cannot lose a completed maintenance batch.
    pub fn queue_due_supervisor_learning(
        &mut self,
        generation: u64,
        configured_projects: &[ProjectId],
        now_unix: i64,
        interval_seconds: u64,
        knowledge_limit: usize,
    ) -> Result<Option<ProjectId>, String> {
        if now_unix < 0 || interval_seconds == 0 {
            return Err("Supervisor learning schedule requires positive bounded timing".into());
        }
        let now_utc =
            crate::learning::unix_seconds_to_utc(now_unix as u64).map_err(|e| e.to_string())?;
        let mut statement = self.connection.prepare(
            "SELECT p.project_id,COALESCE(s.next_due_at_unix,0) FROM projects p JOIN project_runtimes r USING(project_id) LEFT JOIN supervisor_learning_schedule s USING(project_id) WHERE p.desired_lifecycle='running' AND r.observed_lifecycle='running' AND r.controller_generation=?1 AND COALESCE(s.next_due_at_unix,0)<=?2 ORDER BY COALESCE(s.next_due_at_unix,0),p.project_id",
        ).map_err(|e|e.to_string())?;
        let due_rows = statement
            .query_map(params![generation, now_unix], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })
            .map_err(|e| e.to_string())?;
        let due_rows = due_rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        drop(statement);
        let Some((project_raw, scheduled_due)) = due_rows.into_iter().find(|(id, _)| {
            configured_projects
                .iter()
                .any(|project| project.as_str() == id)
        }) else {
            return Ok(None);
        };
        let project = ProjectId::parse(project_raw)?;
        let snapshot = self.maintain_project_supervisor_learning(
            generation,
            &project,
            &now_utc,
            knowledge_limit,
        )?;
        let payload_json = serde_json::to_string(&serde_json::json!({
            "type": "supervisor_learning_maintenance",
            "maintenance": snapshot,
        }))
        .map_err(|e| e.to_string())?;
        if payload_json.len() > MAX_SUPERVISOR_CONTEXT_BYTES {
            return Err("Supervisor learning wake exceeds its aggregate byte limit".into());
        }
        let digest = Digest::parse(format!("{:x}", Sha256::digest(payload_json.as_bytes())))?;
        let next_due = now_unix
            .checked_add(
                i64::try_from(interval_seconds)
                    .map_err(|_| "learning interval exceeds supported range")?,
            )
            .ok_or("Supervisor learning due time overflow")?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        validate_active_generation(&tx, generation)?;
        let current_due: Option<i64> = tx.query_row(
            "SELECT COALESCE(next_due_at_unix,0) FROM supervisor_learning_schedule WHERE project_id=?1",
            [project.as_str()],
            |row| row.get(0),
        ).optional().map_err(|e|e.to_string())?;
        let current_due = current_due.unwrap_or(0);
        if current_due != scheduled_due {
            return Err("Supervisor learning schedule advanced during snapshot preparation".into());
        }
        let source_id = format!("learning-review:{scheduled_due}");
        tx.execute(
            "INSERT INTO role_wake_inputs(project_id,role_session_id,source_type,source_id,source_revision,priority,payload_json,lifecycle,created_at_unix) VALUES (?1,?2,'learning_maintenance',?3,?4,1,?5,'pending',?6)",
            params![project.as_str(),format!("project:{}:supervisor",project.as_str()),source_id,scheduled_due.max(1),payload_json,now_unix],
        ).map_err(|e|e.to_string())?;
        tx.execute(
            "INSERT INTO supervisor_learning_schedule(project_id,next_due_at_unix,last_run_at_unix,last_snapshot_digest) VALUES (?1,?2,?3,?4) ON CONFLICT(project_id) DO UPDATE SET next_due_at_unix=excluded.next_due_at_unix,last_run_at_unix=excluded.last_run_at_unix,last_snapshot_digest=excluded.last_snapshot_digest",
            params![project.as_str(),next_due,now_unix,digest.as_str()],
        ).map_err(|e|e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(Some(project))
    }

    #[cfg(test)]
    pub(crate) fn record_learning_trial(
        &mut self,
        generation: u64,
        project: &ProjectId,
        candidate_id: &str,
        digest: &Digest,
        pair_index: usize,
        observation: &TrialObservation,
    ) -> Result<TrialProgress, String> {
        if pair_index >= MAX_TRIALS {
            return Err("trial pair index exceeds maximum".into());
        }
        let json = serde_json::to_string(observation).map_err(|e| e.to_string())?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        validate_active_generation(&tx, generation)?;
        let (expected,status):(usize,String)=tx.query_row("SELECT expected_pairs,status FROM learning_candidates WHERE project_id=?1 AND candidate_id=?2 AND digest=?3",params![project.as_str(),candidate_id,digest.as_str()],|r|Ok((r.get(0)?,r.get(1)?))).map_err(|e|e.to_string())?;
        if !matches!(
            status.as_str(),
            "proposed" | "trialing" | "awaiting_approval"
        ) || pair_index >= expected
        {
            return Err("candidate does not accept this trial pair".into());
        }
        let old:Option<String>=tx.query_row("SELECT observation_json FROM learning_trial_pairs WHERE project_id=?1 AND candidate_id=?2 AND candidate_digest=?3 AND pair_index=?4",params![project.as_str(),candidate_id,digest.as_str(),pair_index],|r|r.get(0)).optional().map_err(|e|e.to_string())?;
        if let Some(old) = old {
            if old != json {
                return Err("trial pair retry conflicts with stored observation".into());
            }
        } else {
            if status == "awaiting_approval" {
                return Err("completed candidate cannot accept another trial pair".into());
            }
            tx.execute("INSERT INTO learning_trial_pairs(project_id,candidate_id,candidate_digest,pair_index,input_digest,observation_json,created_at_unix) VALUES (?1,?2,?3,?4,?5,?6,?7)",params![project.as_str(),candidate_id,digest.as_str(),pair_index,observation.input_digest.as_str(),json,super::now_unix()?]).map_err(|e|e.to_string())?;
        }
        let mut stmt=tx.prepare("SELECT pair_index,observation_json FROM learning_trial_pairs WHERE project_id=?1 AND candidate_id=?2 AND candidate_digest=?3 ORDER BY pair_index").map_err(|e|e.to_string())?;
        let rows = stmt
            .query_map(
                params![project.as_str(), candidate_id, digest.as_str()],
                |r| Ok((r.get::<_, usize>(0)?, r.get::<_, String>(1)?)),
            )
            .map_err(|e| e.to_string())?;
        let mut trials = Vec::new();
        for row in rows {
            let (index, json) = row.map_err(|e| e.to_string())?;
            trials.push(StoredTrial {
                pair_index: index,
                observation: serde_json::from_str(&json).map_err(|e| e.to_string())?,
            })
        }
        drop(stmt);
        let observations = trials
            .iter()
            .map(|t| t.observation.clone())
            .collect::<Vec<_>>();
        let evidence = evaluate_trials(&observations, expected).map_err(|e| e.to_string())?;
        let evidence_json = serde_json::to_string(&evidence).map_err(|e| e.to_string())?;
        let new_status = if trials.len() < expected {
            "trialing"
        } else {
            "awaiting_approval"
        };
        let candidate_status = if new_status == "trialing" {
            CandidateStatus::Trialing
        } else {
            CandidateStatus::AwaitingApproval
        };
        set_candidate_revision_status(&tx, project, candidate_id, digest, candidate_status)?;
        tx.execute("UPDATE learning_candidates SET evidence_json=?4 WHERE project_id=?1 AND candidate_id=?2 AND digest=?3",params![project.as_str(),candidate_id,digest.as_str(),evidence_json]).map_err(|e|e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(TrialProgress { trials, evidence })
    }

    /// Record promotion eligibility from a package carrying a crate-private,
    /// controller-validated human receipt. This API is crate-private so CLI or
    /// Agent supplied approver strings can never act as authorization.
    #[allow(dead_code)]
    pub(crate) fn register_profile_promotion(
        &mut self,
        generation: u64,
        request: &ProfilePromotionRequest,
        package: &ProfilePackage,
    ) -> Result<(), String> {
        let claims = validated_promotion_claims(package).map_err(|e| e.to_string())?;
        if claims
            .response_receipt_digest
            .as_str()
            .bytes()
            .all(|byte| byte == b'0')
            || request.config_source.is_empty()
            || request.config_source.chars().any(char::is_control)
            || !std::path::Path::new(&request.config_file).is_absolute()
            || request.human_request_id.as_str().is_empty()
            || request.human_request_id != claims.human_request_id
        {
            return Err(
                "profile promotion needs a validated human response and config source".into(),
            );
        }
        // The human API's receipt digest covers a HumanSubjectBinding envelope. The
        // profile-specific digest lives in that envelope's material_digest; verify
        // both layers against the durable original request before accepting a package.
        let request_json: String = self
            .connection
            .query_row(
                "SELECT request_json FROM human_requests WHERE request_id=?1",
                [claims.human_request_id.as_str()],
                |row| row.get(0),
            )
            .map_err(|_| "profile promotion has no durable human request".to_owned())?;
        let human_request: crate::human_runtime::HumanRuntimeRequest =
            crate::protocol::parse_unique(request_json.as_bytes())?;
        let material_digest = crate::learning::profile_approval_subject_digest(
            &claims.project_id,
            claims.role,
            &claims.profile_id,
            &claims.candidate_digest,
            &package.files,
            &package.evidence,
            &claims.config_revision,
        )
        .map_err(|e| e.to_string())?;
        if human_request.purpose != crate::human_runtime::HumanPurpose::ProfilePromotion
            || human_request.subject.kind != crate::human_runtime::HumanSubjectKind::Profile
            || human_request.subject.project_id != claims.project_id
            || human_request.subject.subject_id != request.candidate_id
            || human_request.subject.material_digest != material_digest
            || human_request.subject.configuration_digest != claims.approval_configuration_digest
            || human_request.subject.policy_digest != claims.approval_policy_digest
            || human_request.subject.digest().map_err(|e| e.to_string())?
                != claims.approval_subject_digest
        {
            return Err(
                "profile approval request does not bind the complete approved package".into(),
            );
        }
        let now_unix: u64 = super::now_unix()?
            .try_into()
            .map_err(|_| "system clock is before the Unix epoch")?;
        let accepted = self
            .accepted_human_approval(
                &claims.human_request_id,
                &claims.approval_subject_digest,
                &claims.approval_configuration_digest,
                &claims.approval_policy_digest,
                now_unix,
            )?
            .ok_or("profile promotion has no current accepted human approval")?;
        let regenerated = crate::learning::profile_package_from_accepted_approval(
            &accepted,
            claims.project_id.clone(),
            claims.role,
            claims.profile_id.clone(),
            claims.candidate_digest.clone(),
            package.evidence.clone(),
            package.files.clone(),
            claims.approval_subject_digest.clone(),
            material_digest.clone(),
            claims.config_revision.clone(),
            claims.approval_configuration_digest.clone(),
            claims.approval_policy_digest.clone(),
            now_unix,
        )
        .map_err(|e| e.to_string())?;
        if validated_promotion_claims(&regenerated).map_err(|e| e.to_string())? != claims {
            return Err("profile package differs from the authoritative human approval".into());
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        validate_active_generation(&tx, generation)?;
        let candidate: Option<(String, String, Option<String>, String, String)> = tx.query_row(
            "SELECT role,status,evidence_json,profile_id,package_manifest_digest FROM learning_candidates WHERE project_id=?1 AND candidate_id=?2 AND digest=?3",
            params![claims.project_id.as_str(), request.candidate_id, claims.candidate_digest.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        ).optional().map_err(|e| e.to_string())?;
        let Some((role, status, evidence_json, candidate_profile_id, candidate_manifest_digest)) =
            candidate
        else {
            return Err("approved profile candidate does not exist".into());
        };
        if role
            != serde_json::to_value(claims.role)
                .map_err(|e| e.to_string())?
                .as_str()
                .ok_or("invalid role")?
            || status != "awaiting_approval"
        {
            return Err("profile candidate is not awaiting approval for the approved role".into());
        }
        if candidate_profile_id != claims.profile_id.as_str()
            || candidate_manifest_digest != claims.manifest_digest.as_str()
        {
            return Err(
                "human approval does not match the candidate's complete profile manifest".into(),
            );
        }
        let evidence_json = evidence_json.ok_or("candidate has no completed trial evidence")?;
        let evidence: TrialEvidence =
            serde_json::from_str(&evidence_json).map_err(|e| e.to_string())?;
        if crate::learning::evidence_digest(&evidence).map_err(|e| e.to_string())?
            != claims.evidence_digest
        {
            return Err("human approval does not match the stored trial evidence".into());
        }
        let role_name = serde_json::to_value(claims.role)
            .map_err(|e| e.to_string())?
            .as_str()
            .ok_or("invalid role")?
            .to_owned();
        let approved_package_json = serde_json::to_string(&StoredApprovedProfilePackage {
            project_id: claims.project_id.clone(),
            role: claims.role,
            profile_id: claims.profile_id.clone(),
            candidate_digest: claims.candidate_digest.clone(),
            evidence: package.evidence.clone(),
            files: package.files.clone(),
            approver: format!("human request {}", claims.human_request_id),
            rationale: claims.rationale.clone(),
            authorized_at: claims.authorized_at.clone(),
            human_request_id: claims.human_request_id.clone(),
            approval_subject_digest: claims.approval_subject_digest.clone(),
            approval_configuration_digest: claims.approval_configuration_digest.clone(),
            approval_policy_digest: claims.approval_policy_digest.clone(),
            response_receipt_digest: claims.response_receipt_digest.clone(),
            config_revision: claims.config_revision.clone(),
            profile_material_digest: material_digest.clone(),
        })
        .map_err(|e| e.to_string())?;
        if approved_package_json.len() > MAX_RECORD_BYTES {
            return Err("approved profile package exceeds the durable intent limit".into());
        }
        let prior: Option<PromotionIntentRow> = tx.query_row(
            "SELECT project_id,candidate_digest,profile_id,role,evidence_digest,manifest_digest,config_source,config_file,expected_config_revision,human_request_id,human_response_digest FROM profile_promotions WHERE operation_id=?1",
            [request.operation_id.as_str()],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?,row.get(9)?,row.get(10)?)),
        ).optional().map_err(|e| e.to_string())?;
        if let Some(existing) = prior {
            let expected = (
                claims.project_id.to_string(),
                claims.candidate_digest.to_string(),
                claims.profile_id.to_string(),
                role_name.clone(),
                claims.evidence_digest.to_string(),
                claims.manifest_digest.to_string(),
                request.config_source.clone(),
                request.config_file.clone(),
                claims.config_revision.to_string(),
                request.human_request_id.to_string(),
                claims.response_receipt_digest.to_string(),
            );
            if existing != expected {
                return Err(
                    "profile promotion operation ID was reused with different approval".into(),
                );
            }
            let prior_package: String = tx
                .query_row(
                    "SELECT approved_package_json FROM profile_promotions WHERE operation_id=?1",
                    [request.operation_id.as_str()],
                    |row| row.get(0),
                )
                .map_err(|e| e.to_string())?;
            if prior_package != approved_package_json {
                return Err(
                    "profile promotion operation was retried with a different package or rationale"
                        .into(),
                );
            }
            tx.commit().map_err(|e| e.to_string())?;
            return Ok(());
        }
        tx.execute(
            "INSERT INTO profile_promotions(operation_id,project_id,candidate_id,candidate_digest,profile_id,role,evidence_digest,manifest_digest,config_source,config_file,expected_config_revision,human_request_id,human_response_digest,approval_subject_digest,profile_material_digest,approval_configuration_digest,approval_policy_digest,approved_package_json,state,created_at_unix) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,'approved',?19)",
            params![request.operation_id.as_str(), claims.project_id.as_str(), request.candidate_id,
                claims.candidate_digest.as_str(), claims.profile_id.as_str(),
                role_name,
                claims.evidence_digest.as_str(), claims.manifest_digest.as_str(), request.config_source, request.config_file,
                claims.config_revision.as_str(), request.human_request_id.as_str(),
                claims.response_receipt_digest.as_str(), claims.approval_subject_digest.as_str(), material_digest.as_str(),
                claims.approval_configuration_digest.as_str(), claims.approval_policy_digest.as_str(),
                approved_package_json, super::now_unix()?],
        ).map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(())
    }

    #[allow(dead_code)]
    pub(crate) fn begin_profile_publication(
        &mut self,
        generation: u64,
        operation_id: &OperationId,
    ) -> Result<bool, String> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        validate_active_generation(&tx, generation)?;
        let promotion: Option<(String, String)> = tx
            .query_row(
                "SELECT project_id,manifest_digest FROM profile_promotions WHERE operation_id=?1",
                [operation_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        let Some((project_id, manifest_digest)) = promotion else {
            return Err("profile promotion does not exist".into());
        };
        let changed = tx.execute(
            "UPDATE profile_promotions SET state='publication_pending' WHERE operation_id=?1 AND state='approved'",
            [operation_id.as_str()],
        ).map_err(|e| e.to_string())? == 1;
        if changed {
            let project_revision: u64 = tx
                .query_row(
                    "SELECT state_revision FROM projects WHERE project_id=?1",
                    [&project_id],
                    |row| row.get(0),
                )
                .map_err(|e| e.to_string())?;
            let request_json = super::canonical_json(&serde_json::json!({
                "operation_id": operation_id.as_str(),
                "manifest_digest": manifest_digest,
            }))?;
            let effect = super::EffectIntent {
                project_id: ProjectId::parse(project_id.clone())?,
                subject_type: "project".into(),
                subject_id: project_id,
                operation_id: operation_id.to_string(),
                logical_key: format!("publish-profile-{}", operation_id),
                kind: "publish_profile".into(),
                request_digest: super::content_digest(&request_json),
                request_json,
                expected_revision: Some(project_revision),
            };
            super::insert_effect(&tx, &effect, super::now_unix()?)?;
        }
        if !changed {
            let state: Option<String> = tx
                .query_row(
                    "SELECT state FROM profile_promotions WHERE operation_id=?1",
                    [operation_id.as_str()],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| e.to_string())?;
            if state.as_deref() != Some("publication_pending")
                && state.as_deref() != Some("published")
                && state.as_deref() != Some("activation_pending")
                && state.as_deref() != Some("active")
            {
                return Err("profile promotion is not approved for publication".into());
            }
        }
        tx.commit().map_err(|e| e.to_string())?;
        Ok(changed)
    }

    #[allow(dead_code)]
    pub(crate) fn record_profile_publication(
        &mut self,
        generation: u64,
        operation_id: &OperationId,
        receipt: &ProfilePublicationReceipt,
    ) -> Result<bool, String> {
        let receipt_json = serde_json::to_string(&StoredProfilePublicationReceipt {
            profile_path: receipt.profile_path.display().to_string(),
            manifest_digest: receipt.profile_manifest_digest.clone(),
            human_response_receipt_digest: receipt.human_response_receipt_digest.clone(),
            already_published: receipt.status == ProfilePublicationStatus::AlreadyPublished,
        })
        .map_err(|e| e.to_string())?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        validate_active_generation(&tx, generation)?;
        let row: Option<(String, String, Option<String>)> = tx.query_row(
            "SELECT state,manifest_digest,publication_receipt_json FROM profile_promotions WHERE operation_id=?1",
            [operation_id.as_str()], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        ).optional().map_err(|e| e.to_string())?;
        let Some((state, expected_manifest, prior)) = row else {
            return Err("profile publication has no approved intent".into());
        };
        if expected_manifest != receipt.profile_manifest_digest.as_str() {
            return Err("profile publication manifest differs from human-approved package".into());
        }
        let expected_response: String = tx
            .query_row(
                "SELECT human_response_digest FROM profile_promotions WHERE operation_id=?1",
                [operation_id.as_str()],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())?;
        if expected_response != receipt.human_response_receipt_digest.as_str() {
            return Err("profile publication receipt is bound to another human response".into());
        }
        if matches!(
            state.as_str(),
            "published" | "activation_pending" | "active"
        ) {
            let old: StoredProfilePublicationReceipt = serde_json::from_str(
                prior
                    .as_deref()
                    .ok_or("published profile is missing its receipt")?,
            )
            .map_err(|e| format!("stored profile receipt is invalid: {e}"))?;
            let new: StoredProfilePublicationReceipt =
                serde_json::from_str(&receipt_json).map_err(|e| e.to_string())?;
            if old.profile_path == new.profile_path
                && old.manifest_digest == new.manifest_digest
                && old.human_response_receipt_digest == new.human_response_receipt_digest
            {
                tx.commit().map_err(|e| e.to_string())?;
                return Ok(false);
            }
            return Err(
                "profile publication receipt conflicts with immutable stored receipt".into(),
            );
        }
        if state != "publication_pending" {
            return Err("profile publication was not prepared".into());
        }
        tx.execute("UPDATE profile_promotions SET state='published',publication_receipt_json=?2 WHERE operation_id=?1", params![operation_id.as_str(), receipt_json]).map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(true)
    }

    /// Mark a candidate active only after ConfigStore has accepted the exact
    /// applied snapshot and it binds this project/role to the approved profile.
    /// The caller writes an activation intent first; if the process stops after
    /// `apply_snapshot`, the same target revision and digest can be reconciled.
    #[allow(dead_code)]
    pub(crate) fn prepare_profile_activation(
        &mut self,
        generation: u64,
        operation_id: &OperationId,
        expected_current_revision: crate::domain::ids::Revision,
        target_config_digest: &Digest,
    ) -> Result<bool, String> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        validate_active_generation(&tx, generation)?;
        let row: Option<(String, String, Option<u64>, Option<String>)> = tx.query_row(
            "SELECT state,config_source,activation_to_revision,activation_config_digest FROM profile_promotions WHERE operation_id=?1",
            [operation_id.as_str()],
            |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)),
        ).optional().map_err(|e|e.to_string())?;
        let Some((state, source, prior_target_revision, prior_target_digest)) = row else {
            return Err("profile activation has no promotion intent".into());
        };
        if state == "active" {
            if prior_target_digest.as_deref() == Some(target_config_digest.as_str()) {
                tx.commit().map_err(|e| e.to_string())?;
                return Ok(false);
            }
            return Err("profile promotion is already active at another config revision".into());
        }
        if state == "activation_pending" {
            if prior_target_digest.as_deref() != Some(target_config_digest.as_str()) {
                return Err("profile activation retry changed its target config digest".into());
            }
            tx.commit().map_err(|e| e.to_string())?;
            return Ok(false);
        }
        if state != "published" {
            return Err("profile package must be published before config activation".into());
        }
        let current: Option<(u64, String)> = tx.query_row(
            "SELECT current.revision,snapshots.digest FROM config_current current JOIN config_snapshots snapshots USING(source_identity,revision) WHERE current.source_identity=?1",
            [&source],
            |r| Ok((r.get(0)?,r.get(1)?)),
        ).optional().map_err(|e|e.to_string())?;
        let Some((current_revision, current_digest)) = current else {
            return Err("profile config source has no applied snapshot".into());
        };
        if current_revision != expected_current_revision.0 {
            return Err("profile config source changed before activation intent".into());
        }
        let target_revision = current_revision
            .checked_add(1)
            .ok_or("profile config revision is exhausted")?;
        tx.execute(
            "UPDATE profile_promotions SET state='activation_pending',activation_from_revision=?2,activation_to_revision=?3,activation_config_digest=?4 WHERE operation_id=?1 AND state='published'",
            params![operation_id.as_str(),current_revision,target_revision,target_config_digest.as_str()],
        ).map_err(|e|e.to_string())?;
        // Make sure a pending target cannot be confused with an already applied revision.
        if current_digest == target_config_digest.as_str() {
            return Err("target profile config is already applied; reconcile it before starting a new activation".into());
        }
        if prior_target_revision.is_some() {
            return Err("published profile unexpectedly has a prior activation target".into());
        }
        tx.commit().map_err(|e| e.to_string())?;
        Ok(true)
    }

    #[allow(dead_code)]
    pub(crate) fn confirm_profile_activation(
        &mut self,
        generation: u64,
        operation_id: &OperationId,
        applied: &super::AppliedRevision,
    ) -> Result<bool, String> {
        let row: Option<PromotionDbRow> = self.connection.query_row(
            "SELECT project_id,profile_id,role,config_source,state,candidate_digest,applied_config_revision,applied_config_digest,activation_to_revision,activation_config_digest FROM profile_promotions WHERE operation_id=?1",
            [operation_id.as_str()], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?,r.get(9)?)),
        ).optional().map_err(|e| e.to_string())?;
        let Some((
            project_id,
            profile_id,
            role,
            source,
            state,
            candidate_digest,
            old_revision,
            old_digest,
            activation_target_revision,
            activation_target_digest,
        )) = row
        else {
            return Err("profile activation has no promotion intent".into());
        };
        if !matches!(state.as_str(), "activation_pending" | "active") {
            return Err("profile package is not durably published".into());
        }
        let snapshot = self
            .load_snapshot(&source)?
            .ok_or("applied declarative config snapshot is missing")?;
        if snapshot.revision != applied.revision || snapshot.config.digest != applied.digest {
            return Err(
                "promotion activation does not match the current ConfigStore CAS snapshot".into(),
            );
        }
        if activation_target_revision != Some(applied.revision.0)
            || activation_target_digest.as_deref() != Some(applied.digest.as_str())
        {
            return Err(
                "applied config snapshot does not match the durable profile activation intent"
                    .into(),
            );
        }
        let project = ProjectId::parse(project_id.clone())?;
        let profile = crate::domain::ids::ProfileId::parse(profile_id.clone())?;
        let role: crate::domain::types::Role = serde_json::from_str(&format!("\"{role}\""))
            .map_err(|e| format!("stored promotion role is invalid: {e}"))?;
        let project_config = snapshot
            .config
            .config
            .projects
            .get(&project)
            .ok_or("applied config does not contain the approved project")?;
        if project_config.roles.get(&role) != Some(&profile)
            || !snapshot.config.profiles.contains_key(&profile)
        {
            return Err(
                "applied config does not bind the approved profile to the approved role".into(),
            );
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        validate_active_generation(&tx, generation)?;
        let current: Option<(u64, String)> = tx.query_row(
            "SELECT current.revision,snapshots.digest FROM config_current current JOIN config_snapshots snapshots USING(source_identity,revision) WHERE current.source_identity=?1",
            [&source], |r| Ok((r.get(0)?,r.get(1)?)),
        ).optional().map_err(|e| e.to_string())?;
        if current != Some((applied.revision.0, applied.digest.to_string())) {
            return Err("config source advanced before profile activation was recorded".into());
        }
        if state == "active" {
            if old_revision != Some(applied.revision.0)
                || old_digest.as_deref() != Some(applied.digest.as_str())
            {
                return Err("profile promotion is active at a different config revision".into());
            }
            tx.commit().map_err(|e| e.to_string())?;
            return Ok(false);
        }
        tx.execute("UPDATE profile_promotions SET state='active',applied_config_revision=?2,applied_config_digest=?3 WHERE operation_id=?1", params![operation_id.as_str(),applied.revision.0,applied.digest.as_str()]).map_err(|e| e.to_string())?;
        let role_name = serde_json::to_value(role)
            .map_err(|e| e.to_string())?
            .as_str()
            .ok_or("invalid role")?
            .to_owned();
        let mut prior_stmt = tx.prepare("SELECT candidate_id,digest FROM learning_candidates WHERE project_id=?1 AND role=?2 AND status='promoted'").map_err(|e|e.to_string())?;
        let prior_rows = prior_stmt
            .query_map(params![project.as_str(), role_name], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|e| e.to_string())?;
        let mut prior_candidates = Vec::new();
        for row in prior_rows {
            prior_candidates.push(row.map_err(|e| e.to_string())?);
        }
        drop(prior_stmt);
        for (old_id, old_digest) in prior_candidates {
            set_candidate_revision_status(
                &tx,
                &project,
                &old_id,
                &Digest::parse(old_digest)?,
                CandidateStatus::Superseded,
            )?;
        }
        let changed = tx.execute("UPDATE learning_candidates SET status='promoted' WHERE project_id=?1 AND digest=?2 AND candidate_id=(SELECT candidate_id FROM profile_promotions WHERE operation_id=?3) AND status='awaiting_approval'", params![project.as_str(),candidate_digest,operation_id.as_str()]).map_err(|e| e.to_string())?;
        if changed != 1 {
            return Err("approved profile candidate disappeared before activation".into());
        }
        let promoted_id: String = tx
            .query_row(
                "SELECT candidate_id FROM profile_promotions WHERE operation_id=?1",
                [operation_id.as_str()],
                |row| row.get(0),
            )
            .map_err(|e| e.to_string())?;
        set_candidate_revision_status(
            &tx,
            &project,
            &promoted_id,
            &Digest::parse(candidate_digest)?,
            CandidateStatus::Promoted,
        )?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(true)
    }
}

fn set_candidate_revision_status(
    tx: &rusqlite::Transaction<'_>,
    project: &ProjectId,
    candidate_id: &str,
    digest: &Digest,
    status: CandidateStatus,
) -> Result<(), String> {
    let revision_json: String = tx.query_row(
        "SELECT revision_json FROM learning_candidates WHERE project_id=?1 AND candidate_id=?2 AND digest=?3",
        params![project.as_str(),candidate_id,digest.as_str()],
        |row| row.get(0),
    ).map_err(|e| e.to_string())?;
    let mut revision: CandidateRevision = serde_json::from_str(&revision_json)
        .map_err(|e| format!("stored candidate revision is invalid: {e}"))?;
    revision.status = status;
    let revision_json = serde_json::to_string(&revision).map_err(|e| e.to_string())?;
    let status = serde_json::to_value(status)
        .map_err(|e| e.to_string())?
        .as_str()
        .ok_or("invalid candidate status")?
        .to_owned();
    tx.execute(
        "UPDATE learning_candidates SET status=?4,revision_json=?5 WHERE project_id=?1 AND candidate_id=?2 AND digest=?3",
        params![project.as_str(),candidate_id,digest.as_str(),status,revision_json],
    ).map_err(|e| e.to_string())?;
    Ok(())
}

fn verify_digest(json: &str, digest: &Digest) -> Result<(), String> {
    let actual = format!("{:x}", Sha256::digest(json.as_bytes()));
    if actual != digest.as_str() {
        Err("serialized value digest mismatch".into())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use rusqlite::Connection;
    use sha2::{Digest as _, Sha256};
    use tempfile::TempDir;

    use super::{
        CandidateRegistration, KnowledgePublicationIntent, LearningCandidateRecord, StoredTrial,
        migrate_v10,
    };
    use crate::config::{AppliedConfig, SourceFile, SourceKind};
    use crate::domain::ids::{
        Digest, OperationId, ProfileId, ProjectId, Revision, TicketId, TicketNamespace, TicketRunId,
    };
    use crate::domain::types::Role;
    use crate::human_runtime::{
        HumanDecisionChoice, HumanDecisionIntent, HumanPurpose, HumanRuntimeRequest,
        HumanSubjectBinding, HumanSubjectKind, write_runtime_review_artifact,
    };
    use crate::knowledge::PostmortemInput;
    use crate::knowledge_effect::KnowledgeEffectHandler;
    use crate::launch::{RexView, RexViewKind};
    use crate::learning::{
        CandidateRevision, CandidateStatus, TrialObservation, TrialOutcome, TrialRunStatus,
    };
    use crate::learning::{ProfilePackage, profile_approval_subject_digest};
    use crate::learning_trials::{
        FrozenTrialInput, HostTrialOutcome, HostTrialRunObservation, ProfileTrialAuthorization,
        TrialPairSpec, TrialProfileSnapshot, TrialSide, profile_trial_human_request,
        profile_trial_review_bundle,
    };
    use crate::store::human::HumanDecisionResult;
    use crate::store::{
        ConfigStore, DurableInput, EffectIntent, ExpectedRevision, OwnerMetadata, ProjectRecord,
        content_digest, durable_input_digest,
    };

    fn digest(byte: char) -> Digest {
        Digest::parse(byte.to_string().repeat(64)).unwrap()
    }

    fn digest_serialized<T: serde::Serialize>(value: &T) -> Digest {
        Digest::parse(format!("{:x}", Sha256::digest(serde_json::to_vec(value).unwrap())).as_str())
            .unwrap()
    }

    fn v9_fixture() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        connection.execute_batch(
            "PRAGMA foreign_keys=ON;
             CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at_unix INTEGER NOT NULL);
             CREATE TABLE projects(project_id TEXT PRIMARY KEY);
             CREATE TABLE ticket_runs(ticket_run_id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(project_id));
             CREATE TABLE controller_owners(singleton INTEGER PRIMARY KEY);
             PRAGMA user_version=9;",
        ).unwrap();
        connection
    }

    #[test]
    fn migration_requires_v9_and_installs_all_durable_ledgers_atomically() {
        let wrong = Connection::open_in_memory().unwrap();
        wrong.pragma_update(None, "user_version", 8).unwrap();
        assert!(migrate_v10(&wrong).is_err());
        let fixture = v9_fixture();
        migrate_v10(&fixture).unwrap();
        let version: i64 = fixture
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, 10);
        let has_rex_endpoint: bool = fixture
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM pragma_table_info('controller_owners') WHERE name='rex_endpoint')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(has_rex_endpoint);
        for table in [
            "knowledge_publications",
            "learning_candidates",
            "learning_trial_pairs",
            "profile_promotions",
            "supervisor_learning_schedule",
        ] {
            let exists: bool = fixture
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
                    [table],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(exists, "missing {table}");
        }
        super::validate_v10_schema(&fixture).unwrap();
    }

    #[test]
    fn v12_learning_trial_tables_install_inside_the_shared_migration_transaction() {
        let mut fixture = v9_fixture();
        migrate_v10(&fixture).unwrap();
        let tx = fixture
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        super::migrate_v12_learning_tables(&tx).unwrap();
        tx.commit().unwrap();
        for table in [
            "profile_trial_authorizations",
            "profile_trial_launches",
            "profile_trial_run_receipts",
            "profile_trial_pairs",
        ] {
            let exists: bool = fixture
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
                    [table],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(exists, "missing {table}");
        }
        let tx = fixture
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        super::migrate_v12_learning_tables(&tx).unwrap();
        tx.commit().unwrap();
    }

    #[test]
    fn approved_profile_trial_persists_capsule_slot_receipt_and_replays_after_restart() {
        let (temp, mut store, project, generation, _) = running_store();
        let project_record = store.project(&project).unwrap().unwrap();
        let tx = store.connection.transaction().unwrap();
        super::migrate_v12_learning_tables(&tx).unwrap();
        tx.commit().unwrap();
        let candidate_id = "worker-learned-v1";
        let candidate_digest = digest('d');
        let profile_id = ProfileId::parse("worker-learned").unwrap();
        let guidance = b"Keep acceptance checks.".to_vec();
        let files = BTreeMap::from([("learned.md".to_owned(), guidance.clone())]);
        let manifest_digest = crate::learning::manifest_digest(&files).unwrap();
        let manifest_rows: Vec<_> = files
            .iter()
            .map(|(path, bytes)| {
                (
                    path,
                    Digest::parse(format!("{:x}", Sha256::digest(bytes)).as_str()).unwrap(),
                )
            })
            .collect();
        let candidate_record = LearningCandidateRecord {
            revision: CandidateRevision {
                candidate_id: candidate_id.into(),
                project_id: project.clone(),
                role: Role::Worker,
                digest: candidate_digest.clone(),
                created_at: "2026-11-07T00:00:00Z".into(),
                expires_at: "2027-11-07T00:00:00Z".into(),
                status: CandidateStatus::Proposed,
            },
            profile_id: profile_id.clone(),
            package_manifest_digest: manifest_digest,
            package_files_json: serde_json::to_string(&files).unwrap(),
            package_json: serde_json::to_string(&manifest_rows).unwrap(),
            expected_pairs: 10,
        };
        store
            .register_learning_candidate(generation, &candidate_record)
            .unwrap();

        let make_snapshot = |learned: bool, description: &str| {
            let mut config = serde_json::json!({"adapter":"codex","command":["agent"],"description":description,"model":"fixture-model","effort":"low","turn_timeout_seconds":30,"instruction_files":[],"skill_paths":[],"commit_mode":"auto","learned_guidance":null,"options":null});
            let snapshot_files = if learned {
                config["learned_guidance"] = serde_json::json!({"file":"learned.md","project_id":project.as_str(),"role":"worker","repository_ids":["repo-a"]});
                files.clone()
            } else {
                BTreeMap::new()
            };
            let profile: crate::config::Profile = serde_json::from_value(config).unwrap();
            let profile_config_json = crate::store::canonical_json(&profile).unwrap();
            TrialProfileSnapshot {
                profile_id: if learned {
                    profile_id.clone()
                } else {
                    ProfileId::parse("worker").unwrap()
                },
                profile_digest: crate::store::agent_profile_digest(&profile).unwrap(),
                instruction_digest: digest_serialized(&snapshot_files),
                profile_config_json,
                instruction_files: snapshot_files,
            }
        };
        let baseline = make_snapshot(false, "base");
        let candidate = make_snapshot(true, "candidate");
        let inputs: Vec<_> = (0..5)
            .map(|i| {
                let input_json = format!("{{\"case\":{i}}}");
                let evaluator = crate::learning_trials::TrialEvaluator::StructuredAssertionsV1 {
                    assertions: vec![],
                };
                let fixture_seed = crate::learning_trials::InlineFixtureV1::empty();
                FrozenTrialInput {
                    input_id: format!("input-{i}"),
                    input_digest: Digest::parse(
                        format!("{:x}", Sha256::digest(input_json.as_bytes())).as_str(),
                    )
                    .unwrap(),
                    input_json,
                    fixture_id: crate::learning_trials::INLINE_FIXTURE_ID.into(),
                    fixture_revision: Digest::parse(format!(
                        "{:x}",
                        Sha256::digest(b"inline_fixture_v1")
                    ))
                    .unwrap(),
                    workspace_seed_digest: fixture_seed.digest().unwrap(),
                    fixture_seed,
                    evaluator_id: evaluator.implementation_id().into(),
                    evaluator_revision: evaluator.digest().unwrap(),
                    evaluator,
                }
            })
            .collect();
        let pairs = (0..10)
            .map(|pair_index| TrialPairSpec {
                pair_index,
                input_id: format!("input-{}", pair_index / 2),
            })
            .collect();
        let authorization = ProfileTrialAuthorization {
            schema_version: 1,
            authorization_id: "profile-trial-1".into(),
            project_id: project.clone(),
            role: Role::Worker,
            candidate_id: candidate_id.into(),
            candidate_digest: candidate_digest.clone(),
            base_profile_id: ProfileId::parse("worker").unwrap(),
            base_profile_digest: baseline.profile_digest.clone(),
            config_revision: project_record.config_revision,
            config_digest: project_record.config_digest.clone(),
            baseline_qualification_digest: digest('1'),
            candidate_qualification_digest: digest('2'),
            trial_policy_digest: digest('3'),
            baseline,
            candidate,
            inputs,
            pairs,
            scoped_exception: None,
            human_request_id: crate::domain::ids::HumanRequestId::parse("human-trial-1").unwrap(),
            human_subject_digest: digest('4'),
            human_configuration_digest: project_record.config_digest,
            human_policy_digest: digest('3'),
            human_response_receipt_digest: digest('0'),
            authorized_at_unix: 10,
            max_attempts_per_side: 1,
            expires_at_unix: 4_102_444_800,
        };
        let bundle = profile_trial_review_bundle(&authorization).unwrap();
        let request = profile_trial_human_request(
            authorization.human_request_id.clone(),
            &authorization,
            bundle,
            "Approve this exact bounded fixture batch?".into(),
            authorization.expires_at_unix,
        )
        .unwrap();
        let view = RexView {
            view_id: RexView::derive_id(&project, RexViewKind::Supervisor, None, None, 1).unwrap(),
            project_id: project.clone(),
            kind: RexViewKind::Supervisor,
            ticket_namespace: None,
            ticket_id: None,
            view_epoch: 1,
            rex_server_identity: "test-server".into(),
            rex_session_id: "test-session".into(),
            rex_window_id: "supervisor-window".into(),
        };
        store.register_rex_view(generation, &view).unwrap();
        let artifact_root = temp.path().join("human-artifacts");
        fs::create_dir_all(&artifact_root).unwrap();
        fs::set_permissions(&artifact_root, fs::Permissions::from_mode(0o700)).unwrap();
        let artifact = write_runtime_review_artifact(&artifact_root, &request).unwrap();
        assert!(
            store
                .prepare_profile_trial_authorization(
                    generation,
                    &authorization,
                    &request,
                    &view.view_id,
                    &artifact,
                    100
                )
                .unwrap()
        );
        assert_eq!(
            store
                .pending_profile_trial_authorization_for_request(&request.request_id)
                .unwrap()
                .unwrap()
                .authorization_id,
            authorization.authorization_id
        );
        // Simulate a crash after the authorization transaction committed but
        // before the human request was registered. The controller cadence
        // must reconstruct the request from its durable authorization row.
        store
            .connection
            .execute(
                "DELETE FROM human_requests WHERE request_id=?1",
                [request.request_id.as_str()],
            )
            .unwrap();
        assert!(
            !store
                .connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM human_requests WHERE request_id=?1)",
                    [request.request_id.as_str()],
                    |row| row.get::<_, bool>(0),
                )
                .unwrap()
        );
        assert!(
            store
                .tick_profile_trials(generation, 100, 2, 1)
                .unwrap()
                .is_none()
        );
        assert!(
            ConfigStore::read_human_request(temp.path(), &request.request_id)
                .unwrap()
                .is_some()
        );
        let now = 101;
        let response = HumanDecisionIntent {
            request_id: request.request_id.clone(),
            response_id: "trial-response-1".into(),
            expected_subject_digest: request.subject.digest().unwrap(),
            choice: HumanDecisionChoice::Approve,
            explanation: Some(
                "Run only the exact isolated fixture matrix for this candidate.".into(),
            ),
        };
        ConfigStore::enqueue_human_decision(temp.path(), &response, now).unwrap();
        assert!(matches!(
            store
                .process_human_decision(generation, &response.response_id, &request.subject, now)
                .unwrap(),
            HumanDecisionResult::Applied
        ));
        assert!(
            store
                .accept_profile_trial_approval(generation, &authorization.authorization_id, now + 1)
                .unwrap()
        );
        assert!(
            store
                .pending_profile_trial_authorization_for_request(&request.request_id)
                .unwrap()
                .is_none()
        );
        let capsule = store
            .next_profile_trial_launch(generation, &authorization.authorization_id, now + 2, 2, 1)
            .unwrap()
            .unwrap();
        assert_eq!(capsule.side, TrialSide::Baseline);
        assert_eq!(
            store
                .next_profile_trial_launch(
                    generation,
                    &authorization.authorization_id,
                    now + 3,
                    2,
                    1
                )
                .unwrap()
                .unwrap(),
            capsule
        );
        let active_slots:usize=store.connection.query_row("SELECT count(*) FROM execution_slots WHERE owner_kind='profile_trial' AND disposition!='released'",[],|r|r.get(0)).unwrap();
        assert_eq!(active_slots, 1);
        let observation = HostTrialRunObservation {
            run_id: capsule.run_id.clone(),
            attempt_id: capsule.attempt_id.clone(),
            qualification_receipt_digest: capsule.provider_qualification_digest.clone(),
            config_revision: capsule.config_revision,
            config_digest: capsule.config_digest.clone(),
            profile_digest: capsule.profile.profile_digest.clone(),
            instruction_digest: capsule.profile.instruction_digest.clone(),
            input_digest: capsule.input_digest.clone(),
            fixture_id: capsule.fixture_id.clone(),
            fixture_revision: capsule.fixture_revision.clone(),
            evaluator_id: capsule.evaluator_id.clone(),
            evaluator_revision: capsule.evaluator_revision.clone(),
            workspace_seed_digest: capsule.workspace_seed_digest.clone(),
            no_effects_receipt_digest: digest('e'),
            outcome: HostTrialOutcome::Equivalent,
            result_receipt_digest: digest('f'),
            completed_at_unix: now + 4,
        };
        let receipt = capsule.mint_terminal_receipt(observation).unwrap();
        store
            .record_profile_trial_run_receipt(generation, &receipt, now + 4)
            .unwrap();
        assert_eq!(
            store
                .profile_trial_terminal_receipt(capsule.operation_id())
                .unwrap(),
            Some(receipt.clone())
        );
        store
            .record_profile_trial_run_receipt(generation, &receipt, now + 5)
            .unwrap();
        let active_slots:usize=store.connection.query_row("SELECT count(*) FROM execution_slots WHERE owner_kind='profile_trial' AND disposition!='released'",[],|r|r.get(0)).unwrap();
        assert_eq!(active_slots, 0);
        let next = store
            .tick_profile_trials(generation, now + 6, 2, 1)
            .unwrap()
            .unwrap();
        assert_eq!(next.pair_index, capsule.pair_index);
        assert_eq!(next.side, TrialSide::Candidate);
        let effect_count: usize = store
            .connection
            .query_row(
                "SELECT count(*) FROM effects WHERE kind='start_profile_trial'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(effect_count, 2);
        drop(store);
        let restored = ConfigStore::open_test(temp.path()).unwrap();
        assert_eq!(
            restored
                .profile_trial_launch_capsule(
                    &authorization.authorization_id,
                    capsule.pair_index,
                    TrialSide::Baseline
                )
                .unwrap(),
            Some(capsule)
        );
    }

    #[test]
    fn startup_refuses_a_v10_database_with_an_incomplete_learning_layout_without_migration() {
        let temp = tempfile::tempdir().unwrap();
        let database = temp.path().join("state.sqlite3");
        let connection = Connection::open(&database).unwrap();
        connection.pragma_update(None, "user_version", 10).unwrap();
        drop(connection);
        let before = fs::read(&database).unwrap();
        let error = match ConfigStore::open_test(temp.path()) {
            Ok(_) => panic!("incomplete schema v10 unexpectedly opened"),
            Err(error) => error,
        };
        assert!(error.contains("database claims schema v10"));
        assert_eq!(fs::read(&database).unwrap(), before);
    }

    fn test_snapshot() -> AppliedConfig {
        AppliedConfig {
            config: serde_json::from_value(serde_json::json!({
                "schema_version": 1,
                "adapters": {"tickets": {"kind":"command","command":["test"]}},
                "projects": {}
            }))
            .unwrap(),
            profiles: BTreeMap::new(),
            source_root: "/tmp/rex-projects-test-config".into(),
            source_files: vec![SourceFile {
                kind: SourceKind::File,
                path: "/tmp/rex-projects-test-config/config.toml".into(),
                canonical_path: "/tmp/rex-projects-test-config/config.toml".into(),
                sha256: Digest::parse("a".repeat(64)).unwrap(),
                bytes: 1,
                contents: "x".into(),
            }],
            digest: Digest::parse("a".repeat(64)).unwrap(),
        }
    }

    fn running_store() -> (TempDir, ConfigStore, ProjectId, u64, TicketRunId) {
        let temp = tempfile::tempdir().unwrap();
        let mut store = ConfigStore::open_test(temp.path()).unwrap();
        let applied = store
            .apply_snapshot("factory", &test_snapshot(), ExpectedRevision::Bootstrap)
            .unwrap();
        let project_id = ProjectId::parse("sample").unwrap();
        store
            .insert_project(&ProjectRecord {
                id: project_id.clone(),
                config_source: "factory".into(),
                config_revision: applied.revision,
                config_digest: applied.digest,
                mode: "goal".into(),
                goal_revision: 1,
                desired_lifecycle: "running".into(),
                state_revision: Revision(0),
            })
            .unwrap();
        let generation = store
            .start_owner(&OwnerMetadata {
                owner_nonce: "test-owner".into(),
                state_root: temp.path().display().to_string(),
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
        let run = TicketRunId::parse("sample-1-g1").unwrap();
        store
            .create_ticket_run(
                generation,
                &project_id,
                &TicketNamespace::parse("github:org/repo").unwrap(),
                &TicketId::parse("1").unwrap(),
                &run,
                1,
                "postmortem",
                "In Progress",
            )
            .unwrap();
        let version: i64 = store
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, crate::store::SCHEMA_VERSION);
        (temp, store, project_id, generation, run)
    }

    #[test]
    fn publication_intent_and_receipt_are_durable_idempotent_and_subject_bound() {
        let (temp, mut store, project, generation, run) = running_store();
        let input = PostmortemInput {
            operation_id: OperationId::parse("postmortem-op-1").unwrap(),
            project_id: project.clone(),
            ticket_run_id: run.clone(),
            title: "Learning".into(),
            summary: "A concise summary.".into(),
            findings: vec![],
            sources: vec![],
            generated_at: "2026-11-07T00:00:00Z".into(),
            max_source_bytes: 1024,
        };
        let request_json = serde_json::to_string(&input).unwrap();
        let request_digest =
            Digest::parse(format!("{:x}", Sha256::digest(request_json.as_bytes()))).unwrap();
        let intent = KnowledgePublicationIntent {
            operation_id: input.operation_id.clone(),
            project_id: project.clone(),
            ticket_run_id: run.clone(),
            request_digest,
            request_json,
        };
        assert!(
            store
                .prepare_knowledge_publication(generation, &intent)
                .unwrap()
        );
        assert_eq!(
            store
                .knowledge_publication_intent(&input.operation_id)
                .unwrap(),
            Some(intent.clone())
        );
        assert!(
            !store
                .prepare_knowledge_publication(generation, &intent)
                .unwrap()
        );
        let effect_count: usize = store
            .connection
            .query_row(
                "SELECT count(*) FROM effects WHERE operation_id=?1 AND kind='publish_knowledge'",
                [input.operation_id.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(effect_count, 1);
        let transition_input = DurableInput {
            producer_id: "postmortem-agent".into(),
            message_id: "knowledge-published-1".into(),
            content_digest: durable_input_digest(
                "ticket_run",
                "{\"input\":\"knowledge_published\"}",
            ),
            recipient: "ticket_run".into(),
            payload: "{\"input\":\"knowledge_published\"}".into(),
        };
        let complete_effect = EffectIntent {
            project_id: project.clone(),
            subject_type: "ticket_run".into(),
            subject_id: run.to_string(),
            operation_id: "complete-ticket-1".into(),
            logical_key: "complete-ticket-r1".into(),
            kind: "complete_ticket".into(),
            request_json: "{}".into(),
            request_digest: content_digest("{}"),
            expected_revision: Some(1),
        };
        assert!(
            store
                .commit_ticket_transition(
                    generation,
                    &run,
                    Revision(0),
                    &transition_input,
                    crate::engine::reducer::Input::KnowledgePublished,
                    "Postmortem receipt is required before completion.",
                    "{}",
                    std::slice::from_ref(&complete_effect),
                )
                .err()
                .unwrap()
                .contains("durable knowledge publication")
        );
        let effect = store
            .next_due_effect(generation, i64::MAX)
            .unwrap()
            .unwrap();
        let knowledge_root = temp.path().join("knowledge");
        let handler = KnowledgeEffectHandler::new(knowledge_root.clone());
        let receipt = handler.execute(&mut store, generation, &effect).unwrap();
        let moved_root = temp.path().join("knowledge-published-before-crash");
        fs::rename(&knowledge_root, &moved_root).unwrap();
        let replay = handler.execute(&mut store, generation, &effect).unwrap();
        assert_eq!(replay, receipt);
        assert!(
            !knowledge_root.exists(),
            "terminal receipt replay reran filesystem publication"
        );
        let transition = store
            .commit_ticket_transition(
                generation,
                &run,
                Revision(0),
                &transition_input,
                crate::engine::reducer::Input::KnowledgePublished,
                "Postmortem receipt is required before completion.",
                "{}",
                std::slice::from_ref(&complete_effect),
            )
            .unwrap();
        assert_eq!(transition.receipt["revision"], 1);
        let state: String = store
            .connection
            .query_row(
                "SELECT state FROM knowledge_publications WHERE operation_id=?1",
                [input.operation_id.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(state, "published");
    }

    #[test]
    fn candidates_and_trial_pairs_survive_database_round_trips_and_reject_conflicts() {
        let (_temp, mut store, project, generation, _) = running_store();
        let candidate_files = BTreeMap::from([(
            "instructions.md".to_owned(),
            b"Keep changes focused.".to_vec(),
        )]);
        let package_files_json = serde_json::to_string(&candidate_files).unwrap();
        let package_digest = crate::learning::manifest_digest(&candidate_files).unwrap();
        let manifest_rows: Vec<_> = candidate_files
            .iter()
            .map(|(path, bytes)| {
                (
                    path,
                    Digest::parse(format!("{:x}", Sha256::digest(bytes))).unwrap(),
                )
            })
            .collect();
        let package_json = serde_json::to_string(&manifest_rows).unwrap();
        let candidate_digest = Digest::parse("b".repeat(64)).unwrap();
        let record = LearningCandidateRecord {
            revision: CandidateRevision {
                candidate_id: "worker-profile-v2".into(),
                project_id: project.clone(),
                role: Role::Worker,
                digest: candidate_digest.clone(),
                created_at: "2026-11-07T00:00:00Z".into(),
                expires_at: "2026-12-07T00:00:00Z".into(),
                status: CandidateStatus::Proposed,
            },
            profile_id: ProfileId::parse("worker-profile").unwrap(),
            package_manifest_digest: package_digest,
            package_files_json,
            package_json,
            expected_pairs: 5,
        };
        assert_eq!(
            store
                .register_learning_candidate(generation, &record)
                .unwrap(),
            CandidateRegistration::Registered
        );
        assert_eq!(
            store
                .register_learning_candidate(generation, &record)
                .unwrap(),
            CandidateRegistration::AlreadyRegistered
        );
        let candidate_package = store
            .learning_candidate_package(&project, &record.revision.candidate_id, &candidate_digest)
            .unwrap()
            .unwrap();
        assert_eq!(candidate_package.files, candidate_files);
        for pair_index in 0usize..5 {
            let observation = TrialObservation {
                input_digest: Digest::parse(format!(
                    "{:x}",
                    Sha256::digest(pair_index.to_be_bytes())
                ))
                .unwrap(),
                baseline: TrialRunStatus::Equivalent,
                candidate: TrialRunStatus::Improved,
            };
            let progress = store
                .record_learning_trial(
                    generation,
                    &project,
                    &record.revision.candidate_id,
                    &candidate_digest,
                    pair_index,
                    &observation,
                )
                .unwrap();
            if pair_index == 4 {
                assert_eq!(progress.evidence.outcome, TrialOutcome::Improved);
            }
            assert_eq!(
                progress.trials.last().unwrap(),
                &StoredTrial {
                    pair_index,
                    observation
                }
            );
        }
        let conflict = TrialObservation {
            input_digest: Digest::parse("c".repeat(64)).unwrap(),
            baseline: TrialRunStatus::Equivalent,
            candidate: TrialRunStatus::Failed,
        };
        assert!(
            store
                .record_learning_trial(
                    generation,
                    &project,
                    &record.revision.candidate_id,
                    &candidate_digest,
                    0,
                    &conflict
                )
                .is_err()
        );
        let count: usize = store
            .connection
            .query_row("SELECT count(*) FROM learning_trial_pairs", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 5);
        let supervisor = store
            .maintain_project_supervisor_learning(generation, &project, "2026-11-08T00:00:00Z", 12)
            .unwrap();
        assert_eq!(supervisor.project_id, project);
        assert_eq!(supervisor.expired_candidates, 0);
        assert_eq!(supervisor.knowledge.len(), 0);
        assert_eq!(supervisor.candidates.len(), 1);
        assert_eq!(
            supervisor.candidates[0].evidence.as_ref().unwrap().outcome,
            TrialOutcome::Improved
        );
        let _ = ProfileId::parse("worker-profile").unwrap();
    }

    #[test]
    fn supervisor_learning_runs_on_durable_per_project_cadence_and_wakes_supervisor() {
        let (_temp, mut store, project, generation, _) = running_store();
        store.connection.execute(
            "UPDATE project_runtimes SET observed_lifecycle='running',controller_generation=?2 WHERE project_id=?1",
            rusqlite::params![project.as_str(),generation],
        ).unwrap();
        assert_eq!(
            store
                .queue_due_supervisor_learning(
                    generation,
                    std::slice::from_ref(&project),
                    100,
                    3600,
                    12
                )
                .unwrap(),
            Some(project.clone())
        );
        assert_eq!(
            store
                .queue_due_supervisor_learning(
                    generation,
                    std::slice::from_ref(&project),
                    101,
                    3600,
                    12
                )
                .unwrap(),
            None
        );
        let supervisor_session = format!("project:{}:supervisor", project.as_str());
        store
            .connection
            .execute(
                "INSERT INTO role_wake_inputs(project_id,role_session_id,source_type,source_id,source_revision,priority,payload_json,lifecycle,created_at_unix) VALUES (?1,?2,'ticket_observation','ticket-1:ready',1,30,'{}','pending',101)",
                rusqlite::params![project.as_str(), supervisor_session],
            )
            .unwrap();
        store
            .connection
            .execute(
                "INSERT INTO role_wake_inputs(project_id,role_session_id,source_type,source_id,source_revision,priority,payload_json,lifecycle,created_at_unix) VALUES (?1,?2,'periodic_supervisor_review','low-priority',1,0,'{}','pending',101)",
                rusqlite::params![project.as_str(), supervisor_session],
            )
            .unwrap();
        let pending = store
            .pending_role_wake_inputs(&project, &supervisor_session, 2)
            .unwrap();
        assert_eq!(
            pending
                .iter()
                .map(|wake| wake.source_type.as_str())
                .collect::<Vec<_>>(),
            vec!["learning_maintenance", "ticket_observation"]
        );
        assert_eq!(
            pending.iter().map(|wake| wake.priority).collect::<Vec<_>>(),
            vec![1, 30]
        );
        assert_eq!(pending[0].source_id, "learning-review:0");
        assert_eq!(pending[0].source_revision, 1);
        assert!(pending.iter().all(|wake| wake.source_revision > 0));
        let mut inbox = crate::agent_api::AgentWakeSnapshot {
            schema_version: 1,
            project_id: project.clone(),
            role_session_id: supervisor_session,
            agent_run_id: "agent-supervisor-test".into(),
            digest: crate::domain::ids::Digest::parse("0".repeat(64)).unwrap(),
            inputs: pending
                .into_iter()
                .map(|wake| crate::agent_api::AgentWakeItem {
                    wake_input_id: wake.wake_input_id,
                    source_type: wake.source_type,
                    source_id: wake.source_id,
                    source_revision: wake.source_revision,
                    priority: wake.priority,
                    payload_json: wake.payload_json,
                    host_artifact_source_evidence_ids: Vec::new(),
                    host_artifacts: Vec::new(),
                })
                .collect(),
        };
        inbox.digest = inbox.content_digest().unwrap();
        inbox.validate().unwrap();
        let wake: (String,String,String) = store.connection.query_row(
            "SELECT role_session_id,source_type,payload_json FROM role_wake_inputs WHERE project_id=?1",
            [project.as_str()],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
        ).unwrap();
        assert_eq!(wake.0, format!("project:{}:supervisor", project.as_str()));
        assert_eq!(wake.1, "learning_maintenance");
        let payload: serde_json::Value = serde_json::from_str(&wake.2).unwrap();
        assert_eq!(payload["type"], "supervisor_learning_maintenance");
        assert_eq!(payload["maintenance"]["project_id"], project.as_str());
        assert_eq!(
            store
                .queue_due_supervisor_learning(
                    generation,
                    std::slice::from_ref(&project),
                    3700,
                    3600,
                    12
                )
                .unwrap(),
            Some(project.clone())
        );
        let wake_count: usize = store.connection.query_row(
            "SELECT count(*) FROM role_wake_inputs WHERE project_id=?1 AND source_type='learning_maintenance'",
            [project.as_str()],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(wake_count, 2);
    }

    #[test]
    fn approved_inconclusive_profile_publishes_replays_and_activates_after_config_cas() {
        let (temp, mut store, project, generation, _) = running_store();
        let profile_id = ProfileId::parse("worker-learned").unwrap();
        let candidate_id = "worker-learned-v1";
        let candidate_digest = Digest::parse("d".repeat(64)).unwrap();
        let files = BTreeMap::from([
            (
                "config.toml".to_owned(),
                b"adapter = \"codex\"\ncommand = [\"codex\"]\n".to_vec(),
            ),
            (
                "instructions.md".to_owned(),
                b"Keep changes small and record test results.".to_vec(),
            ),
        ]);
        let manifest_digest = crate::learning::manifest_digest(&files).unwrap();
        let package_rows: Vec<_> = files
            .iter()
            .map(|(path, bytes)| {
                (
                    path,
                    Digest::parse(format!("{:x}", Sha256::digest(bytes))).unwrap(),
                )
            })
            .collect();
        let package_json = serde_json::to_string(&package_rows).unwrap();
        let candidate = LearningCandidateRecord {
            revision: CandidateRevision {
                candidate_id: candidate_id.into(),
                project_id: project.clone(),
                role: Role::Worker,
                digest: candidate_digest.clone(),
                created_at: "2026-11-07T00:00:00Z".into(),
                expires_at: "2027-11-07T00:00:00Z".into(),
                status: CandidateStatus::Proposed,
            },
            profile_id: profile_id.clone(),
            package_manifest_digest: manifest_digest,
            package_files_json: serde_json::to_string(&files).unwrap(),
            package_json,
            expected_pairs: 5,
        };
        store
            .register_learning_candidate(generation, &candidate)
            .unwrap();
        let mut evidence = None;
        for pair_index in 0usize..5 {
            let observation = TrialObservation {
                input_digest: Digest::parse(format!(
                    "{:x}",
                    Sha256::digest(pair_index.to_be_bytes())
                ))
                .unwrap(),
                baseline: TrialRunStatus::Equivalent,
                candidate: TrialRunStatus::Equivalent,
            };
            evidence = Some(
                store
                    .record_learning_trial(
                        generation,
                        &project,
                        candidate_id,
                        &candidate_digest,
                        pair_index,
                        &observation,
                    )
                    .unwrap()
                    .evidence,
            );
        }
        let evidence = evidence.unwrap();
        assert_eq!(evidence.outcome, TrialOutcome::Inconclusive);
        assert_eq!(evidence.distinct_inputs, 5);
        let candidate_package = store
            .learning_candidate_package(&project, candidate_id, &candidate_digest)
            .unwrap()
            .unwrap();
        assert_eq!(candidate_package.files, files);
        assert_eq!(candidate_package.evidence, Some(evidence.clone()));
        assert_eq!(
            store
                .current_learning_candidate_package(&project, candidate_id)
                .unwrap(),
            Some(candidate_package.clone())
        );

        let declarative_root = temp.path().join("declarative");
        fs::create_dir_all(&declarative_root).unwrap();
        let config_file = declarative_root.join("config.toml");
        fs::write(&config_file, "schema_version = 1\n").unwrap();
        let config_revision =
            crate::learning::config_revision(&config_file, &declarative_root.join("profiles"))
                .unwrap();
        let config_digest = store
            .load_snapshot("factory")
            .unwrap()
            .unwrap()
            .config
            .digest;
        let policy_digest = Digest::parse("e".repeat(64)).unwrap();
        let material_digest = profile_approval_subject_digest(
            &project,
            Role::Worker,
            &profile_id,
            &candidate_digest,
            &files,
            &evidence,
            &config_revision,
        )
        .unwrap();
        let bundle = crate::learning::profile_candidate_review_bundle(&candidate_package).unwrap();
        let request = HumanRuntimeRequest {
            request_id: crate::domain::ids::HumanRequestId::parse("profile-approval-1").unwrap(),
            purpose: HumanPurpose::ProfilePromotion,
            subject: HumanSubjectBinding {
                project_id: project.clone(),
                kind: HumanSubjectKind::Profile,
                subject_id: candidate_id.to_owned(),
                ticket_run_id: None,
                revision: crate::learning::profile_candidate_revision(&candidate_digest).unwrap(),
                material_digest: material_digest.clone(),
                configuration_digest: config_digest.clone(),
                policy_digest: policy_digest.clone(),
                bundle_digest: crate::human::review_bundle_digest(&bundle).unwrap(),
            },
            question: "Approve publishing this profile to the declarative staging directory?"
                .into(),
            choices: vec![HumanDecisionChoice::Approve, HumanDecisionChoice::Refuse],
            expires_at_unix: 4_102_444_800,
            review_bundle: bundle,
        };
        let supervisor_view = RexView {
            view_id: RexView::derive_id(&project, RexViewKind::Supervisor, None, None, 1).unwrap(),
            project_id: project.clone(),
            kind: RexViewKind::Supervisor,
            ticket_namespace: None,
            ticket_id: None,
            view_epoch: 1,
            rex_server_identity: "test-server".into(),
            rex_session_id: "test-session".into(),
            rex_window_id: "supervisor-window".into(),
        };
        store
            .register_rex_view(generation, &supervisor_view)
            .unwrap();
        let artifact_root = temp.path().join("human-artifacts");
        fs::create_dir_all(&artifact_root).unwrap();
        fs::set_permissions(&artifact_root, fs::Permissions::from_mode(0o700)).unwrap();
        let artifact = write_runtime_review_artifact(&artifact_root, &request).unwrap();
        assert!(
            store
                .register_human_request(
                    generation,
                    &request,
                    &supervisor_view.view_id,
                    &artifact,
                    super::super::now_unix().unwrap() as u64,
                )
                .unwrap()
        );
        let now = super::super::now_unix().unwrap() as u64;
        let response = HumanDecisionIntent {
            request_id: request.request_id.clone(),
            response_id: "profile-approval-response-1".into(),
            expected_subject_digest: request.subject.digest().unwrap(),
            choice: HumanDecisionChoice::Approve,
            explanation: Some("Promote only this worker profile for further evaluation; these trials do not establish efficacy.".into()),
        };
        ConfigStore::enqueue_human_decision(temp.path(), &response, now + 1).unwrap();
        assert!(matches!(
            store
                .process_human_decision(
                    generation,
                    &response.response_id,
                    &request.subject,
                    now + 2
                )
                .unwrap(),
            HumanDecisionResult::Applied
        ));
        let receipt = store
            .accepted_human_approval(
                &request.request_id,
                &request.subject.digest().unwrap(),
                &config_digest,
                &policy_digest,
                now + 3,
            )
            .unwrap()
            .unwrap();
        let package: ProfilePackage = crate::learning::profile_package_from_accepted_approval(
            &receipt,
            project.clone(),
            Role::Worker,
            profile_id.clone(),
            candidate_digest.clone(),
            evidence.clone(),
            files.clone(),
            request.subject.digest().unwrap(),
            material_digest.clone(),
            config_revision.clone(),
            config_digest.clone(),
            policy_digest.clone(),
            now + 3,
        )
        .unwrap();
        let operation_id = OperationId::parse("profile-promotion-op-1").unwrap();
        store
            .register_profile_promotion(
                generation,
                &super::ProfilePromotionRequest {
                    operation_id: operation_id.clone(),
                    candidate_id: candidate_id.into(),
                    config_source: "factory".into(),
                    config_file: config_file.display().to_string(),
                    human_request_id: request.request_id.clone(),
                },
                &package,
            )
            .unwrap();
        assert!(
            store
                .begin_profile_publication(generation, &operation_id)
                .unwrap()
        );
        let effect = store
            .next_due_effect(generation, i64::MAX)
            .unwrap()
            .unwrap();
        let handler = crate::profile_effect::ProfileEffectHandler::new(declarative_root.clone());
        let published = handler.execute(&mut store, generation, &effect).unwrap();
        assert!(published.profile_path.is_dir());
        let replay = handler.execute(&mut store, generation, &effect).unwrap();
        assert_eq!(replay, published);

        let current = store.load_snapshot("factory").unwrap().unwrap();
        let mut target = current.config;
        let mut config_value = serde_json::to_value(&target.config).unwrap();
        config_value["projects"][project.as_str()] = serde_json::json!({
            "mode":"goal", "ticket_adapter":"tickets", "roles":{"worker":profile_id.as_str()}
        });
        target.config = serde_json::from_value(config_value).unwrap();
        let profile: crate::config::Profile = serde_json::from_value(serde_json::json!({
            "adapter":"codex", "command":["codex"], "model":"test"
        }))
        .unwrap();
        target.profiles.insert(profile_id, profile);
        target.digest = Digest::parse(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&target.config).unwrap())
        ))
        .unwrap();
        assert!(
            store
                .prepare_profile_activation(
                    generation,
                    &operation_id,
                    current.revision,
                    &target.digest
                )
                .unwrap()
        );
        let applied = store
            .apply_snapshot(
                "factory",
                &target,
                ExpectedRevision::Current(current.revision),
            )
            .unwrap();
        assert!(
            store
                .confirm_profile_activation(generation, &operation_id, &applied)
                .unwrap()
        );
        let status: String = store.connection.query_row(
            "SELECT status FROM learning_candidates WHERE project_id=?1 AND candidate_id=?2 AND digest=?3",
            rusqlite::params![project.as_str(), candidate_id, candidate_digest.as_str()],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(status, "promoted");
        assert!(
            store
                .current_learning_candidate_package(&project, candidate_id)
                .unwrap()
                .is_none()
        );
        store.stop_owner(generation).unwrap();
        drop(store);
        let mut reopened = ConfigStore::open_test(temp.path()).unwrap();
        let recovered_generation = reopened
            .start_owner(&OwnerMetadata {
                owner_nonce: "recovered-profile-owner".into(),
                state_root: temp.path().display().to_string(),
                config_source: "factory".into(),
                process_start_identity: "test-recovered-start".into(),
                executable_path: "/tmp/rex-projects-test".into(),
                executable_digest: "f".repeat(64),
                rex_endpoint: None,
                rex_server_identity: None,
                rex_session_id: None,
                rex_block_id: None,
            })
            .unwrap();
        assert!(
            !reopened
                .confirm_profile_activation(recovered_generation, &operation_id, &applied)
                .unwrap()
        );
        let recovered_state: String = reopened
            .connection
            .query_row(
                "SELECT state FROM profile_promotions WHERE operation_id=?1",
                [operation_id.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(recovered_state, "active");
    }
}
