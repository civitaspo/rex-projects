//! Run-local Agent-facing files and typed mailbox payloads.
//!
//! These helpers never open SQLite. Every value is still an Agent claim until the foreground
//! controller validates it against the immutable launch authority and records host evidence.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::domain::ids::{
    ArtifactId, Digest, HumanRequestId, OperationId, ProjectId, TicketId, TicketRunId,
};
use crate::engine::orchestration::{
    ReviewReadyPayload, RoleArtifactKind, RoleArtifactReference, WorkerRecoveryAuthorization,
};

const MAX_INBOX_BYTES: usize = 1024 * 1024;
const MAX_WAKE_ITEMS: usize = 256;

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentWakeSnapshot {
    pub schema_version: u32,
    pub project_id: ProjectId,
    pub role_session_id: String,
    pub agent_run_id: String,
    pub digest: Digest,
    pub inputs: Vec<AgentWakeItem>,
    /// Host-validated guidance frozen when a Worker launch is reserved. It is contextual input,
    /// not a change to the accepted plan or launch authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_correction_context: Option<WorkerCorrectionContext>,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerCorrectionContext {
    pub schema_version: u32,
    pub project_id: ProjectId,
    pub ticket_run_id: TicketRunId,
    pub ticket_revision: u64,
    pub configuration_digest: Digest,
    pub accepted_plan_digest: Digest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coordinator_instruction: Option<WorkerCoordinatorInstruction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewer_correction: Option<WorkerReviewerCorrection>,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerCoordinatorInstruction {
    pub wake_input_id: u64,
    pub request_id: String,
    pub source_revision: u64,
    pub body_digest: Digest,
    pub body: String,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerReviewerCorrection {
    pub evidence_id: String,
    pub result_digest: Digest,
    pub source_revision: u64,
    pub accepted_revision: u64,
    pub publication_revision: u64,
    pub publication_subject_digest: Digest,
    pub assessment: ReviewReadyPayload,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentWakeItem {
    pub wake_input_id: u64,
    pub source_type: String,
    pub source_id: String,
    pub source_revision: u64,
    pub priority: i32,
    pub payload_json: serde_json::Value,
    /// Host evidence IDs whose artifacts accompany a Reviewer transition. Kept separate from
    /// the durable payload so reservation can compare that payload byte-for-byte.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub host_artifact_source_evidence_ids: Vec<String>,
    /// Host-generated, workspace-relative copies of artifacts named by this wake's
    /// persisted source result. These locators are included in the wake digest.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub host_artifacts: Vec<HostArtifactLocator>,
    /// Immutable completion facts derived by the host for a Postmortem launch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_completion_context: Option<HostCompletionContext>,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostCompletionContext {
    pub schema_version: u32,
    pub scope: HostCompletionScope,
    pub operation_completion: HostOperationCompletion,
    pub implementation_publication: HostImplementationPublication,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub human_decision: Option<HostHumanDecisionEvidence>,
}

/// Historical evidence for a completed merge; this value grants no approval capability.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostHumanDecisionEvidence {
    pub request_id: HumanRequestId,
    pub work_id: Digest,
    pub request_digest: Digest,
    pub receipt_digest: Digest,
    pub receipt: serde_json::Value,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostCompletionScope {
    pub project_id: ProjectId,
    pub ticket_run_id: TicketRunId,
    pub ticket_id: TicketId,
    pub ticket_revision: u64,
    pub configuration_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostOperationCompletion {
    pub plan_digest: Digest,
    pub state: String,
    pub not_required_reason: Option<String>,
    pub receipts: Vec<HostPublicationReceipt>,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostImplementationPublication {
    pub accepted_plan_digest: Digest,
    pub configuration_digest: Digest,
    pub merge_work_id: Digest,
    pub assessed_revision: u64,
    pub awaiting_merge_revision: u64,
    pub prepared_receipt_digest: Digest,
    pub publication_set_digest: Digest,
    pub assessment_id: String,
    pub assessment_evidence_id: String,
    pub assessment_result_digest: Digest,
    pub intent_evidence_id: String,
    pub intent_result_digest: Digest,
    pub assessment: serde_json::Value,
    pub verification: Option<serde_json::Value>,
    pub merge_verification: HostMergeVerification,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostMergeVerification {
    pub work_id: Digest,
    pub configuration_digest: Digest,
    pub accepted_plan_digest: Digest,
    pub assessment_id: String,
    pub source_revision: u64,
    pub merge_commit_sha: String,
    pub included_head_sha: String,
    pub receipt_digest: Digest,
    pub receipt: serde_json::Value,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostPublicationReceipt {
    pub operation_id: String,
    pub kind: String,
    pub request_digest: Digest,
    pub receipt_digest: Digest,
    pub receipt: serde_json::Value,
}

/// A parent-workspace copy of a host-verified artifact. `path` is always relative
/// to the Agent workspace; host store paths are never exposed to the Agent.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostArtifactLocator {
    pub artifact_id: ArtifactId,
    pub kind: RoleArtifactKind,
    pub schema_version: u32,
    pub digest: Digest,
    pub bytes: u64,
    pub path: String,
    pub source_run_id: String,
    pub source_evidence_id: String,
    pub source_authority_digest: Digest,
}

impl HostArtifactLocator {
    pub fn validate(&self) -> Result<(), String> {
        let id = self.artifact_id.as_str();
        if !is_lower_hex_64(id) {
            return Err("host artifact locator has a malformed artifact ID".into());
        }
        let expected = format!(".rex-artifacts/sha256/{}/{}", &id[..2], id);
        if self.schema_version == 0
            || self.bytes == 0
            || self.bytes > 64 * 1024 * 1024
            || self.path != expected
            || !is_lower_hex_64(&self.source_evidence_id)
            || self.source_run_id.trim().is_empty()
            || self.source_run_id.chars().any(char::is_control)
        {
            return Err(
                "host artifact locator is malformed or outside its workspace namespace".into(),
            );
        }
        crate::domain::ids::AgentRunId::parse(self.source_run_id.clone())?;
        Ok(())
    }
}

fn is_lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl AgentWakeSnapshot {
    pub fn worker_recovery_authorization(
        &self,
    ) -> Result<Option<WorkerRecoveryAuthorization>, String> {
        let mut authorization = None;
        for input in &self.inputs {
            if input.source_type != "worker_recovery_authorization" {
                continue;
            }
            let value = input
                .payload_json
                .get("authorization")
                .cloned()
                .ok_or("Worker recovery wake has no host authorization")?;
            let parsed: WorkerRecoveryAuthorization = serde_json::from_value(value)
                .map_err(|error| format!("invalid Worker recovery authorization: {error}"))?;
            parsed.validate()?;
            let expected_session = format!(
                "ticket:{}:worker:{}",
                parsed.ticket_run_id, parsed.work_node_id
            );
            if self.role_session_id != expected_session
                || input.source_id != parsed.prior_worker_result_evidence_id
                || input.source_revision != parsed.ticket_revision
            {
                return Err(
                    "Worker recovery wake differs from its canonical node session or source result"
                        .into(),
                );
            }
            if authorization.replace(parsed).is_some() {
                return Err("Worker wake contains multiple recovery authorizations".into());
            }
        }
        Ok(authorization)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1
            || self.role_session_id.trim().is_empty()
            || self.agent_run_id.trim().is_empty()
        {
            return Err("unsupported or incomplete Agent inbox snapshot".into());
        }
        if let Some(context) = &self.worker_correction_context {
            context.validate_for_snapshot(self)?;
        }
        if self.inputs.len() > MAX_WAKE_ITEMS {
            return Err("Agent inbox snapshot exceeds the 256 item limit".into());
        }
        let mut previous = 0;
        let mut artifact_count = 0usize;
        let mut artifact_bytes = 0u64;
        for item in &self.inputs {
            if item.wake_input_id == 0
                || item.wake_input_id <= previous
                || item.source_revision == 0
                || item.source_type.is_empty()
                || item.source_id.is_empty()
                || item.source_type.chars().any(char::is_control)
                || item.source_id.chars().any(char::is_control)
            {
                return Err(
                    "Agent inbox entries must have ordered IDs and complete source identity".into(),
                );
            }
            previous = item.wake_input_id;
            if let Some(context) = &item.host_completion_context {
                let encoded = serde_json::to_vec(context).map_err(|error| error.to_string())?;
                if encoded.is_empty() || encoded.len() > 256 * 1024 {
                    return Err("Postmortem completion context exceeds the 256 KiB limit".into());
                }
            }
            if let Some(context) = &item.host_completion_context
                && (item.source_type != "ticket_run_transition"
                    || item.payload_json["target"] != "postmortem"
                    || item.payload_json["ticket_run_id"].as_str()
                        != Some(context.scope.ticket_run_id.as_str())
                    || item.payload_json["revision"].as_u64() != Some(item.source_revision)
                    || context.schema_version != 1
                    || context.scope.ticket_revision != item.source_revision
                    || item.payload_json["message_id"].as_str() != Some(item.source_id.as_str())
                    || context.scope.project_id != self.project_id
                    || context.implementation_publication.configuration_digest
                        != context.scope.configuration_digest
                    || self.role_session_id
                        != format!("ticket_run:{}:postmortem", context.scope.ticket_run_id)
                    || !matches!(
                        context.operation_completion.state.as_str(),
                        "succeeded" | "not_required"
                    )
                    || (context.operation_completion.state == "not_required"
                        && context.operation_completion.not_required_reason.is_none())
                    || context
                        .implementation_publication
                        .merge_verification
                        .work_id
                        != context.implementation_publication.merge_work_id
                    || context
                        .implementation_publication
                        .merge_verification
                        .source_revision
                        != context.implementation_publication.awaiting_merge_revision
                    || context
                        .implementation_publication
                        .merge_verification
                        .configuration_digest
                        != context.scope.configuration_digest)
            {
                return Err(
                    "Postmortem completion context is missing or outside its launch scope".into(),
                );
            }
            if item.host_artifacts.len() > 256 {
                return Err("Agent inbox item exceeds the 256 artifact limit".into());
            }
            artifact_count += item.host_artifacts.len();
            let transition_artifact_sources = if item.source_type == "ticket_run_transition"
                && !item.host_artifacts.is_empty()
            {
                if item.payload_json["target"] != "reviewer"
                    || item.payload_json["revision"].as_u64() != Some(item.source_revision)
                    || item.payload_json["message_id"].as_str() != Some(item.source_id.as_str())
                {
                    return Err("host artifacts may accompany only a current Reviewer publication transition".into());
                }
                let sources = item
                    .host_artifact_source_evidence_ids
                    .iter()
                    .map(|source| {
                        Digest::parse(source.to_owned())?;
                        Ok(source.to_owned())
                    })
                    .collect::<Result<std::collections::BTreeSet<_>, String>>()?;
                if sources.is_empty()
                    || sources.len() != item.host_artifact_source_evidence_ids.len()
                {
                    return Err(
                        "Reviewer artifact source evidence IDs must be nonempty and unique".into(),
                    );
                }
                Some(sources)
            } else {
                if !item.host_artifact_source_evidence_ids.is_empty() {
                    return Err("host artifact source evidence IDs may accompany only a Reviewer publication transition".into());
                }
                if !item.host_artifacts.is_empty()
                    && !matches!(
                        item.source_type.as_str(),
                        "agent_result" | "worker_recovery_authorization"
                    )
                {
                    return Err("host artifact locators must accompany a verified result, Worker recovery wake, or Reviewer publication transition".into());
                }
                None
            };
            let mut seen_artifacts = std::collections::BTreeSet::new();
            let mut actual_artifact_sources = std::collections::BTreeSet::new();
            for artifact in &item.host_artifacts {
                artifact.validate()?;
                let source_matches = if let Some(sources) = &transition_artifact_sources {
                    sources.contains(&artifact.source_evidence_id)
                } else {
                    artifact.source_evidence_id == item.source_id
                };
                if !source_matches || !seen_artifacts.insert(artifact.artifact_id.as_str()) {
                    return Err(
                        "host artifact locator source or identity differs from its wake".into(),
                    );
                }
                actual_artifact_sources.insert(artifact.source_evidence_id.clone());
                artifact_bytes = artifact_bytes
                    .checked_add(artifact.bytes)
                    .ok_or("Agent inbox artifact byte count overflow")?;
            }
            if transition_artifact_sources
                .as_ref()
                .is_some_and(|sources| sources != &actual_artifact_sources)
            {
                return Err("Reviewer publication transition source evidence list differs from its host artifacts".into());
            }
        }
        if let Some(ticket_run_id) = self
            .role_session_id
            .strip_prefix("ticket_run:")
            .and_then(|session| session.strip_suffix(":postmortem"))
        {
            let contexts = self
                .inputs
                .iter()
                .filter(|item| item.host_completion_context.is_some())
                .count();
            if contexts != 1
                || self
                    .inputs
                    .iter()
                    .filter_map(|item| item.host_completion_context.as_ref())
                    .any(|context| context.scope.ticket_run_id.as_str() != ticket_run_id)
            {
                return Err(
                    "Postmortem inbox must contain one matching host completion context".into(),
                );
            }
        }
        if artifact_count > 256 || artifact_bytes > 64 * 1024 * 1024 {
            return Err("Agent inbox artifacts exceed their 256 reference or 64 MiB limit".into());
        }
        if self.digest != self.content_digest()? {
            return Err("Agent inbox digest does not match its content".into());
        }
        Ok(())
    }

    pub fn content_digest(&self) -> Result<Digest, String> {
        let bytes = match &self.worker_correction_context {
            Some(context) => serde_json::to_vec(&(
                self.schema_version,
                &self.project_id,
                &self.role_session_id,
                &self.agent_run_id,
                &self.inputs,
                context,
            )),
            None => serde_json::to_vec(&(
                self.schema_version,
                &self.project_id,
                &self.role_session_id,
                &self.agent_run_id,
                &self.inputs,
            )),
        }
        .map_err(|error| error.to_string())?;
        Digest::parse(format!("{:x}", Sha256::digest(bytes)))
    }
}

impl WorkerCorrectionContext {
    pub fn validate_for_snapshot(&self, snapshot: &AgentWakeSnapshot) -> Result<(), String> {
        let session_prefix = format!("ticket:{}:worker:", self.ticket_run_id.as_str());
        let encoded = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        if self.schema_version != 1
            || self.project_id != snapshot.project_id
            || !snapshot.role_session_id.starts_with(&session_prefix)
            || snapshot.role_session_id.len() == session_prefix.len()
            || self.ticket_revision == 0
            || (self.coordinator_instruction.is_none() && self.reviewer_correction.is_none())
            || encoded.len() > 256 * 1024
        {
            return Err(
                "Worker correction context is incomplete, out of scope, or oversized".into(),
            );
        }
        if let Some(instruction) = &self.coordinator_instruction
            && (instruction.wake_input_id == 0
                || instruction.request_id.is_empty()
                || instruction.request_id.len() > 128
                || instruction.source_revision > self.ticket_revision
                || instruction.body.is_empty()
                || instruction.body.len() > 64 * 1024
                || instruction.body.contains('\0')
                || sha256(instruction.body.as_bytes())? != instruction.body_digest)
        {
            return Err("Worker correction context has an invalid Coordinator instruction".into());
        }
        if let Some(review) = &self.reviewer_correction {
            let coverage = review
                .assessment
                .evidence_coverage
                .iter()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>();
            if review.evidence_id.is_empty()
                || review.source_revision.checked_add(1) != Some(review.accepted_revision)
                || review.accepted_revision != self.ticket_revision
                || review.publication_revision > review.source_revision
                || review.publication_subject_digest != review.assessment.subject_digest
                || review.assessment.subject_kind != "implementation_publication_set"
                || coverage.len() != review.assessment.evidence_coverage.len()
                || (review.assessment.findings.is_empty() && review.assessment.unknowns.is_empty())
            {
                return Err(
                    "Worker correction context has an invalid accepted Reviewer result".into(),
                );
            }
        }
        Ok(())
    }

    pub fn validate_for_assignment(
        &self,
        project_id: &ProjectId,
        ticket_run_id: &TicketRunId,
        ticket_revision: u64,
        configuration_digest: &Digest,
        accepted_plan_digest: &Digest,
    ) -> Result<(), String> {
        let snapshot = AgentWakeSnapshot {
            schema_version: 1,
            project_id: project_id.clone(),
            role_session_id: format!("ticket:{}:worker:assigned", ticket_run_id.as_str()),
            agent_run_id: "worker-assignment-validation".into(),
            digest: Digest::parse("0".repeat(64))?,
            inputs: Vec::new(),
            worker_correction_context: Some(self.clone()),
        };
        self.validate_for_snapshot(&snapshot)?;
        if self.project_id != *project_id
            || self.ticket_run_id != *ticket_run_id
            || self.ticket_revision != ticket_revision
            || self.configuration_digest != *configuration_digest
            || self.accepted_plan_digest != *accepted_plan_digest
        {
            return Err("Worker correction context differs from the current assignment".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactAddRequest {
    pub schema_version: u32,
    pub message_id: String,
    /// Normalized relative path under the immutable AgentRun workspace.
    pub path: String,
    pub kind: RoleArtifactKind,
    pub artifact_schema_version: u32,
}

impl ArtifactAddRequest {
    pub fn validate(&self) -> Result<(), String> {
        validate_message_id(&self.message_id)?;
        if self.schema_version != 1 || self.artifact_schema_version == 0 {
            return Err("unsupported artifact request schema".into());
        }
        validate_relative_path(&self.path)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactAddReceipt {
    pub schema_version: u32,
    pub message_id: String,
    pub artifact: RoleArtifactReference,
}

/// Host-mode Worker request to commit the exact Change artifact previously registered for this run.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryCommitRequest {
    pub schema_version: u32,
    pub message_id: String,
    pub worktree_id: String,
    pub expected_head: String,
    pub manifest: RoleArtifactReference,
    pub manifest_digest: Digest,
    pub commit_message: String,
}

impl RepositoryCommitRequest {
    pub fn validate(&self) -> Result<(), String> {
        validate_message_id(&self.message_id)?;
        if self.schema_version != 1
            || self.worktree_id.trim().is_empty()
            || self.worktree_id.chars().any(char::is_control)
            || !matches!(self.expected_head.len(), 40 | 64)
            || !self
                .expected_head
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            || self.manifest.kind != RoleArtifactKind::Change
            || self.manifest.schema_version != 1
            || self.manifest.digest != self.manifest_digest
            || self.commit_message.trim().is_empty()
            || self.commit_message.len() > 16_000
            || self.commit_message.chars().any(|character| {
                character == '\0'
                    || character == '\r'
                    || (character.is_control() && character != '\n' && character != '\t')
            })
        {
            return Err(
                "repository commit request is malformed or does not identify a v1 Change manifest"
                    .into(),
            );
        }
        validate_relative_path(&self.manifest.path)
    }
}

/// Mailbox result returned only after the normal effect journal records a succeeded host commit.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryCommitReceipt {
    pub schema_version: u32,
    pub message_id: String,
    pub commit_operation_id: OperationId,
    pub worktree_id: String,
    pub repository_id: String,
    pub base_sha: String,
    pub manifest_artifact: RoleArtifactReference,
    pub commit: crate::host_commit::HostCommitReceipt,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryManifestRequest {
    pub schema_version: u32,
    pub worktree_id: String,
    pub entries: Vec<ManifestPath>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestPath {
    pub path: String,
    pub operation: ManifestOperation,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestOperation {
    Capture,
    Delete,
}

impl RepositoryManifestRequest {
    pub fn from_paths_file(worktree_id: String, path: &Path) -> Result<Self, String> {
        if worktree_id.trim().is_empty() || worktree_id.chars().any(char::is_control) {
            return Err("invalid worktree ID".into());
        }
        let bytes = read_bounded(path, 1024 * 1024)?;
        let parsed: Self = crate::protocol::parse_unique(&bytes)?;
        if parsed.schema_version != 1 || parsed.worktree_id != worktree_id {
            return Err("manifest file does not match requested worktree".into());
        }
        if parsed.entries.len() > 10_000 {
            return Err("manifest exceeds 10,000 paths".into());
        }
        let mut seen = std::collections::BTreeSet::new();
        for item in &parsed.entries {
            validate_relative_path(&item.path)?;
            if !seen.insert(item.path.clone()) {
                return Err("manifest contains a duplicate path".into());
            }
        }
        Ok(parsed)
    }

    /// Derive a Git manifest from the current Rex block worktree. No Git metadata is touched.
    pub fn build(&self, root: &Path) -> Result<crate::host_commit::ChangeManifest, String> {
        let root =
            fs::canonicalize(root).map_err(|error| format!("canonicalize worktree: {error}"))?;
        let mut items = self.entries.clone();
        items.sort_by(|left, right| left.path.cmp(&right.path));
        let mut entries = Vec::with_capacity(items.len());
        for item in &items {
            let relative = Path::new(&item.path);
            if relative.components().any(|component| {
                let std::path::Component::Normal(part) = component else {
                    return true;
                };
                let part = part.to_string_lossy();
                part.eq_ignore_ascii_case(".git")
                    || part.eq_ignore_ascii_case(".rex-projects")
                    || part.eq_ignore_ascii_case(".rex-projects-mailbox")
                    || part.eq_ignore_ascii_case(".rex-projects-control")
            }) {
                return Err("manifest path names a reserved Git or mailbox location".into());
            }
            let full = root.join(relative);
            match item.operation {
                ManifestOperation::Delete => {
                    entries.push(crate::host_commit::ManifestEntry::Delete {
                        path: item.path.clone(),
                    })
                }
                ManifestOperation::Capture => {
                    let metadata = fs::symlink_metadata(&full)
                        .map_err(|error| format!("inspect {}: {error}", item.path))?;
                    if metadata.file_type().is_symlink() {
                        let parent = full.parent().ok_or("manifest symlink has no parent")?;
                        let resolved_parent = fs::canonicalize(parent)
                            .map_err(|error| format!("resolve manifest parent: {error}"))?;
                        if !resolved_parent.starts_with(&root) {
                            return Err(
                                "manifest path escapes its worktree through a parent symlink"
                                    .into(),
                            );
                        }
                        let target = fs::read_link(&full).map_err(|error| error.to_string())?;
                        let target = target.to_str().ok_or("symlink target is not UTF-8")?;
                        if target.contains('\0') || target.len() > 4096 {
                            return Err("unsupported symlink target".into());
                        }
                        let digest = sha256(target.as_bytes())?;
                        entries.push(crate::host_commit::ManifestEntry::Symlink {
                            path: item.path.clone(),
                            target_sha256: digest,
                            target_byte_count: target.len() as u64,
                        });
                    } else if metadata.is_file() {
                        let resolved = fs::canonicalize(&full)
                            .map_err(|error| format!("resolve {}: {error}", item.path))?;
                        if !resolved.starts_with(&root) {
                            return Err("manifest file escapes its worktree".into());
                        }
                        if metadata.len() > 64 * 1024 * 1024 {
                            return Err("manifest file exceeds 64 MiB".into());
                        }
                        let bytes = read_bounded(&full, 64 * 1024 * 1024)?;
                        let mode = executable_mode(&metadata)?;
                        entries.push(crate::host_commit::ManifestEntry::Write {
                            path: item.path.clone(),
                            mode,
                            sha256: sha256(&bytes)?,
                            byte_count: bytes.len() as u64,
                        });
                    } else {
                        return Err(format!("unsupported manifest entry type: {}", item.path));
                    }
                }
            }
        }
        Ok(crate::host_commit::ChangeManifest {
            schema_version: 1,
            entries,
        })
    }
}

pub fn read_inbox(
    control_dir: &Path,
    run_id: &str,
    after: u64,
) -> Result<Vec<AgentWakeItem>, String> {
    let control_metadata = fs::symlink_metadata(control_dir).map_err(|error| error.to_string())?;
    if !control_metadata.is_dir() || control_metadata.file_type().is_symlink() {
        return Err("Agent control directory must be a real directory".into());
    }
    let control_dir = fs::canonicalize(control_dir).map_err(|error| error.to_string())?;
    let inbox_dir = control_dir.join("inbox");
    let inbox_metadata = fs::symlink_metadata(&inbox_dir).map_err(|error| error.to_string())?;
    if !inbox_metadata.is_dir() || inbox_metadata.file_type().is_symlink() {
        return Err("Agent inbox must be a real directory".into());
    }
    let inbox_dir = fs::canonicalize(&inbox_dir).map_err(|error| error.to_string())?;
    if inbox_dir.parent() != Some(control_dir.as_path()) {
        return Err("Agent inbox directory escaped its control directory".into());
    }
    let path = inbox_dir.join("snapshot.json");
    let bytes = read_bounded(&path, MAX_INBOX_BYTES)?;
    let snapshot: AgentWakeSnapshot = crate::protocol::parse_unique(&bytes)?;
    snapshot.validate()?;
    if snapshot.agent_run_id != run_id {
        return Err("inbox snapshot belongs to another AgentRun".into());
    }
    Ok(snapshot
        .inputs
        .into_iter()
        .filter(|item| item.wake_input_id > after)
        .collect())
}

/// Host-side publication after a durable wake claim. Replaying the same snapshot is idempotent;
/// replacing it with different content is permitted only for a later AgentRun and must be fenced
/// by the host authority before this function is called.
pub fn publish_wake_snapshot(
    control_dir: &Path,
    mut snapshot: AgentWakeSnapshot,
) -> Result<(), String> {
    let directory = control_dir.join("inbox");
    ensure_real_directory(&directory)?;
    snapshot.digest = snapshot.content_digest()?;
    snapshot.validate()?;
    let bytes = serde_json::to_vec(&snapshot).map_err(|error| error.to_string())?;
    if bytes.len() > MAX_INBOX_BYTES {
        return Err("Agent inbox snapshot exceeds 1 MiB".into());
    }
    let path = directory.join("snapshot.json");
    let temporary = directory.join(format!(".snapshot-{}.tmp", std::process::id()));
    write_new_file(&temporary, &bytes)?;
    match fs::rename(&temporary, &path) {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = fs::remove_file(temporary);
            Err(format!("publish Agent inbox snapshot: {error}"))
        }
    }
}

pub fn write_heartbeat(control_dir: &Path, run_id: &str) -> Result<(), String> {
    validate_message_id(run_id)?;
    let directory = control_dir.join("heartbeat");
    ensure_real_directory(&directory)?;
    let epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_secs();
    let body = serde_json::json!({"schema_version":1,"run_id":run_id,"observed_at_unix":epoch});
    atomic_replace(
        &directory.join("heartbeat.json"),
        &serde_json::to_vec(&body).map_err(|error| error.to_string())?,
    )
}

pub fn validate_message_id(value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 255 || value.chars().any(char::is_control) {
        Err("message ID must contain 1 to 255 non-control bytes".into())
    } else {
        Ok(())
    }
}

pub fn validate_relative_path(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 4096
        || value.contains('\\')
        || value.chars().any(char::is_control)
    {
        return Err("path must be a normalized relative path".into());
    }
    let path = Path::new(value);
    if path.is_absolute()
        || path
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err("path must not contain absolute, dot, or parent components".into());
    }
    if value.starts_with(".git/") || value == ".git" || value.starts_with(".rex-projects-control/")
    {
        return Err("path targets reserved repository control data".into());
    }
    Ok(())
}

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut file = options
        .open(path)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.len() > limit as u64 {
        return Err(format!("{} is not a bounded regular file", path.display()));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    std::io::Read::take(&mut file, limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > limit {
        return Err(format!("{} exceeds its byte limit", path.display()));
    }
    Ok(bytes)
}

fn ensure_real_directory(path: &Path) -> Result<(), String> {
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.to_string()),
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("control child must be a real directory".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn atomic_replace(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path.parent().ok_or("heartbeat path has no parent")?;
    let temporary = parent.join(format!(".heartbeat-{}", std::process::id()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .map_err(|error| error.to_string())?;
    file.write_all(bytes).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())?;
    fs::rename(&temporary, path).map_err(|error| error.to_string())?;
    Ok(())
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|error| error.to_string())?;
    file.write_all(bytes).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())?;
    Ok(())
}

fn sha256(bytes: &[u8]) -> Result<Digest, String> {
    Digest::parse(format!("{:x}", Sha256::digest(bytes)))
}

#[cfg(unix)]
fn executable_mode(metadata: &fs::Metadata) -> Result<crate::host_commit::FileMode, String> {
    use std::os::unix::fs::PermissionsExt;
    if metadata.permissions().mode() & 0o111 != 0 {
        Ok(crate::host_commit::FileMode::Executable0755)
    } else {
        Ok(crate::host_commit::FileMode::Regular0644)
    }
}
#[cfg(not(unix))]
fn executable_mode(_: &fs::Metadata) -> Result<crate::host_commit::FileMode, String> {
    Ok(crate::host_commit::FileMode::Regular0644)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn path_validation_rejects_escape_and_control_paths() {
        for invalid in [
            "../secret",
            "/tmp/file",
            "a\\b",
            ".git/config",
            ".rex-projects-control/x",
        ] {
            assert!(validate_relative_path(invalid).is_err(), "{invalid}");
        }
        assert!(validate_relative_path("src/main.rs").is_ok());
    }

    #[test]
    fn host_artifact_locator_is_typed_workspace_relative_and_digest_bound() {
        let locator = HostArtifactLocator {
            artifact_id: ArtifactId::parse("a".repeat(64)).unwrap(),
            kind: RoleArtifactKind::TestReceipt,
            schema_version: 1,
            digest: Digest::parse("b".repeat(64)).unwrap(),
            bytes: 12,
            path: format!(".rex-artifacts/sha256/{}/{}", "aa", "a".repeat(64)),
            source_run_id: "child-run".into(),
            source_evidence_id: "e".repeat(64),
            source_authority_digest: Digest::parse("d".repeat(64)).unwrap(),
        };
        locator.validate().unwrap();
        let mut snapshot = AgentWakeSnapshot {
            schema_version: 1,
            project_id: ProjectId::parse("project-a").unwrap(),
            role_session_id: "coordinator-session".into(),
            agent_run_id: "parent-run".into(),
            digest: Digest::parse("0".repeat(64)).unwrap(),
            inputs: vec![AgentWakeItem {
                wake_input_id: 1,
                source_type: "agent_result".into(),
                source_id: "e".repeat(64),
                source_revision: 1,
                priority: 0,
                payload_json: serde_json::json!({"kind":"validated_agent_result"}),
                host_artifact_source_evidence_ids: Vec::new(),
                host_artifacts: vec![locator],
                host_completion_context: None,
            }],

            worker_correction_context: None,
        };
        snapshot.digest = snapshot.content_digest().unwrap();
        snapshot.validate().unwrap();

        let mut transition = snapshot.clone();
        transition.inputs[0].source_type = "ticket_run_transition".into();
        transition.inputs[0].source_id = "review-transition-message".into();
        transition.inputs[0].payload_json = serde_json::json!({
            "target":"reviewer",
            "revision":1,
            "message_id":"review-transition-message"
        });
        transition.inputs[0].host_artifact_source_evidence_ids = vec!["e".repeat(64)];
        transition.digest = transition.content_digest().unwrap();
        transition.validate().unwrap();

        transition.inputs[0].host_artifact_source_evidence_ids = vec!["f".repeat(64)];
        transition.digest = transition.content_digest().unwrap();
        assert!(transition.validate().is_err());
        transition.inputs[0].host_artifact_source_evidence_ids = vec!["e".repeat(64)];
        transition.digest = transition.content_digest().unwrap();
        transition.inputs[0].payload_json["target"] = serde_json::json!("operator");
        transition.digest = transition.content_digest().unwrap();
        assert!(transition.validate().is_err());
        transition.inputs[0].payload_json["target"] = serde_json::json!("reviewer");
        transition.digest = transition.content_digest().unwrap();
        transition.inputs[0].host_artifacts[0].path = "../../outside".into();
        assert!(transition.validate().is_err());
    }

    #[test]
    fn legacy_wake_digest_stays_stable_and_frozen_correction_context_is_bound() {
        let project_id = ProjectId::parse("project-a").unwrap();
        let role_session_id = "ticket:ticket-run-a:worker:node-a".to_owned();
        let agent_run_id = "worker-run-a".to_owned();
        let legacy_bytes = serde_json::to_vec(&(
            1_u32,
            &project_id,
            &role_session_id,
            &agent_run_id,
            &Vec::<AgentWakeItem>::new(),
        ))
        .unwrap();
        let legacy_digest = sha256(&legacy_bytes).unwrap();
        let legacy_json = serde_json::json!({
            "schema_version":1,
            "project_id":project_id,
            "role_session_id":role_session_id,
            "agent_run_id":agent_run_id,
            "digest":legacy_digest,
            "inputs":[],
        });
        let mut legacy: AgentWakeSnapshot = serde_json::from_value(legacy_json).unwrap();
        legacy.validate().unwrap();
        assert!(legacy.worker_correction_context.is_none());

        legacy.worker_correction_context = Some(WorkerCorrectionContext {
            schema_version: 1,
            project_id: ProjectId::parse("project-a").unwrap(),
            ticket_run_id: TicketRunId::parse("ticket-run-a").unwrap(),
            ticket_revision: 2,
            configuration_digest: Digest::parse("a".repeat(64)).unwrap(),
            accepted_plan_digest: Digest::parse("b".repeat(64)).unwrap(),
            coordinator_instruction: Some(WorkerCoordinatorInstruction {
                wake_input_id: 7,
                request_id: "human-7".into(),
                source_revision: 0,
                body_digest: sha256(b"Keep the plan.").unwrap(),
                body: "Keep the plan.".into(),
            }),
            reviewer_correction: None,
        });
        legacy.digest = legacy.content_digest().unwrap();
        legacy.validate().unwrap();
        legacy
            .worker_correction_context
            .as_mut()
            .unwrap()
            .coordinator_instruction
            .as_mut()
            .unwrap()
            .body = "Change the plan.".into();
        assert!(legacy.validate().is_err());
    }

    #[test]
    fn postmortem_completion_context_is_revision_scoped_to_the_public_wake() {
        let mut snapshot = AgentWakeSnapshot {
            schema_version: 1,
            project_id: crate::domain::ids::ProjectId::parse("project-a").unwrap(),
            role_session_id: "ticket_run:ticket-run-a:postmortem".into(),
            agent_run_id: "agent-postmortem-a".into(),
            digest: Digest::parse("0".repeat(64)).unwrap(),
            inputs: vec![AgentWakeItem {
                wake_input_id: 1,
                source_type: "ticket_run_transition".into(),
                source_id: "transition-message".into(),
                source_revision: 8,
                priority: 10,
                payload_json: serde_json::json!({
                    "target":"postmortem", "ticket_run_id":"ticket-run-a",
                    "revision":8, "message_id":"transition-message"
                }),
                host_artifact_source_evidence_ids: vec![],
                host_artifacts: vec![],
                host_completion_context: Some(serde_json::from_value(serde_json::json!({
                    "schema_version":1,
                    "scope":{"project_id":"project-a", "ticket_run_id":"ticket-run-a", "ticket_id":"ticket-a", "ticket_revision":8, "configuration_digest":"a".repeat(64)},
                    "operation_completion":{"plan_digest":"c".repeat(64), "state":"not_required", "not_required_reason":"no required operations", "receipts":[]},
                    "implementation_publication":{"accepted_plan_digest":"c".repeat(64), "configuration_digest":"a".repeat(64), "merge_work_id":"1".repeat(64), "assessed_revision":6, "awaiting_merge_revision":7, "prepared_receipt_digest":"2".repeat(64), "publication_set_digest":"3".repeat(64), "assessment_id":"assessment-a", "assessment_evidence_id":"e".repeat(64), "assessment_result_digest":"f".repeat(64), "intent_evidence_id":"5".repeat(64), "intent_result_digest":"6".repeat(64), "assessment":{}, "verification":null, "merge_verification":{"work_id":"1".repeat(64), "configuration_digest":"a".repeat(64), "accepted_plan_digest":"c".repeat(64), "assessment_id":"assessment-a", "source_revision":7, "merge_commit_sha":"2".repeat(40), "included_head_sha":"3".repeat(40), "receipt_digest":"4".repeat(64), "receipt":{}}}
                })).unwrap()),
            }],

            worker_correction_context: None,};
        snapshot.digest = snapshot.content_digest().unwrap();
        snapshot.validate().unwrap();
        let directory = tempfile::tempdir().unwrap();
        publish_wake_snapshot(directory.path(), snapshot.clone()).unwrap();
        let received = read_inbox(directory.path(), "agent-postmortem-a", 0).unwrap();
        assert_eq!(received, snapshot.inputs);
        snapshot.inputs[0].source_revision += 1;
        snapshot.digest = snapshot.content_digest().unwrap();
        assert!(snapshot.validate().is_err());
    }

    #[test]
    fn recovery_wake_decodes_only_host_authorized_same_node_input() {
        let authorization = WorkerRecoveryAuthorization {
            schema_version: 1,
            ticket_run_id: crate::domain::ids::TicketRunId::parse("ticket-run-1").unwrap(),
            ticket_revision: 3,
            work_node_id: crate::engine::orchestration::WorkNodeId::parse("worker-1").unwrap(),
            accepted_plan_digest: Digest::parse("a".repeat(64)).unwrap(),
            prior_worker_agent_run_id: crate::domain::ids::AgentRunId::parse("worker-run-1")
                .unwrap(),
            prior_terminal_digest: Digest::parse("b".repeat(64)).unwrap(),
            prior_absence_digest: Digest::parse("c".repeat(64)).unwrap(),
            prior_host_commit_operation_id: None,
            prior_host_commit_receipt_digest: None,
            expected_head: "d".repeat(40),
            source_coordinator_evidence_id: "coordinator-evidence".into(),
            prior_worker_result_evidence_id: "worker-evidence".into(),
            prior_artifact_refs: Vec::new(),
        };
        let mut snapshot = AgentWakeSnapshot {
            schema_version: 1,
            project_id: ProjectId::parse("project-a").unwrap(),
            role_session_id: "ticket:ticket-run-1:worker:worker-1".into(),
            agent_run_id: "worker-run-2".into(),
            digest: Digest::parse("0".repeat(64)).unwrap(),
            inputs: vec![AgentWakeItem {
                wake_input_id: 1,
                source_type: "worker_recovery_authorization".into(),
                source_id: "worker-evidence".into(),
                source_revision: 3,
                priority: 10,
                payload_json: serde_json::json!({"authorization": authorization}),
                host_artifact_source_evidence_ids: Vec::new(),
                host_artifacts: Vec::new(),
                host_completion_context: None,
            }],

            worker_correction_context: None,
        };
        snapshot.digest = snapshot.content_digest().unwrap();
        snapshot.validate().unwrap();
        assert_eq!(
            snapshot
                .worker_recovery_authorization()
                .unwrap()
                .unwrap()
                .expected_head,
            "d".repeat(40)
        );

        snapshot.role_session_id = "ticket:ticket-run-1:worker:worker-2".into();
        assert!(snapshot.worker_recovery_authorization().is_err());
        snapshot.role_session_id = "ticket:ticket-run-1:worker:worker-1".into();
        snapshot.inputs[0].source_revision = 2;
        assert!(snapshot.worker_recovery_authorization().is_err());
    }
}
