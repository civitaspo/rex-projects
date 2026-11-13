//! Typed, immutable Supervisor Topic documents.
//!
//! The durable intent fixes the Project, version, destination, rendered bytes,
//! and source proof; retries can only reconcile those exact bytes.

use std::fmt::Write as FmtWrite;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as IoRead, Write as IoWrite};
use std::path::{Component, Path, PathBuf};

use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::domain::ids::{Digest, ProjectId};

pub const MAX_TOPIC_CHANGES: usize = 5;
pub const MAX_TOPIC_DOCUMENT_BYTES: usize = 64 * 1024;
pub const MAX_TOPIC_BATCH_DOCUMENT_BYTES: usize = MAX_TOPIC_CHANGES * MAX_TOPIC_DOCUMENT_BYTES;
const MAX_SOURCES_PER_TOPIC: usize = 20;
const MAX_FIELD_BYTES: usize = 8 * 1024;

fn nullable_digest_schema(generator: &mut SchemaGenerator) -> Schema {
    Option::<Digest>::json_schema(generator)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TopicChange {
    pub topic_key: String,
    pub title: String,
    pub summary: String,
    pub claims: Vec<String>,
    pub applicability: String,
    pub proposed_check: String,
    pub counterexamples: Vec<String>,
    pub source_finding_ids: Vec<Digest>,
    #[serde(deserialize_with = "Option::<Digest>::deserialize")]
    #[schemars(required, schema_with = "nullable_digest_schema")]
    pub expected_prior_digest: Option<Digest>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct TopicKey(String);

impl TopicKey {
    pub fn parse(value: &str) -> Result<Self, String> {
        if value.is_empty()
            || value.len() > 64
            || value == "index"
            || value == "log"
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            || value.starts_with('-')
            || value.ends_with('-')
            || value.contains("--")
        {
            return Err(
                "Topic key must be a canonical lowercase ASCII slug (index/log are reserved)"
                    .into(),
            );
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for TopicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TopicSourceProof {
    pub finding_id: Digest,
    pub publication_digest: Digest,
    pub ordinal: u32,
    pub ticket_run_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TopicIntent {
    pub operation_id: String,
    pub project_id: ProjectId,
    pub key: TopicKey,
    #[serde(default)]
    pub revision: u64,
    #[serde(default)]
    pub expected_prior_digest: Option<Digest>,
    pub destination_root: PathBuf,
    pub content: String,
    pub content_digest: Digest,
    pub sources: Vec<TopicSourceProof>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TopicManifest {
    pub operation_id: String,
    pub project_id: ProjectId,
    pub topic_key: TopicKey,
    pub relative_path: String,
    pub format: String,
    pub content_sha256: Digest,
    pub source_finding_ids: Vec<Digest>,
    pub source_publication_digests: Vec<Digest>,
    pub byte_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TopicReceipt {
    pub manifest: TopicManifest,
    pub manifest_digest: Digest,
    pub published_at_unix: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TopicPublicationError {
    Conflict(String),
    Failure(String),
}

impl std::fmt::Display for TopicPublicationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Conflict(reason) | Self::Failure(reason) => formatter.write_str(reason),
        }
    }
}

impl From<String> for TopicPublicationError {
    fn from(reason: String) -> Self {
        Self::Failure(reason)
    }
}

impl From<&str> for TopicPublicationError {
    fn from(reason: &str) -> Self {
        Self::Failure(reason.to_owned())
    }
}

pub fn validate_changes(changes: &[TopicChange]) -> Result<(), String> {
    if changes.len() > MAX_TOPIC_CHANGES {
        return Err("Supervisor proposed more than five Topic changes".into());
    }
    let mut keys = std::collections::BTreeSet::new();
    let mut aggregate = 0usize;
    for change in changes {
        let key = TopicKey::parse(&change.topic_key)?;
        if !keys.insert(key) {
            return Err("Supervisor proposed the same Topic key more than once".into());
        }
        if change.title.trim().is_empty()
            || change.summary.trim().is_empty()
            || change.applicability.trim().is_empty()
            || change.proposed_check.trim().is_empty()
            || change.claims.is_empty()
            || change.source_finding_ids.is_empty()
            || change.source_finding_ids.len() > MAX_SOURCES_PER_TOPIC
            || change.counterexamples.len() > MAX_SOURCES_PER_TOPIC
        {
            return Err(
                "Topic proposal is missing required content or exceeds source limits".into(),
            );
        }
        let mut source_ids = std::collections::BTreeSet::new();
        if change
            .source_finding_ids
            .iter()
            .any(|id| !source_ids.insert(id))
        {
            return Err("Topic source Finding IDs must be unique".into());
        }
        for value in std::iter::once(&change.title)
            .chain(std::iter::once(&change.summary))
            .chain(std::iter::once(&change.applicability))
            .chain(std::iter::once(&change.proposed_check))
            .chain(change.claims.iter())
            .chain(change.counterexamples.iter())
        {
            if value.trim().is_empty()
                || value.len() > MAX_FIELD_BYTES
                || contains_unsafe_control(value)
            {
                return Err(
                    "Topic proposal contains an empty, oversized, or unsafe text field".into(),
                );
            }
            aggregate = aggregate
                .checked_add(value.len())
                .ok_or("Topic proposal byte count overflow")?;
        }
    }
    if aggregate > MAX_TOPIC_DOCUMENT_BYTES {
        return Err("Topic proposals exceed the aggregate content limit".into());
    }
    Ok(())
}

pub fn render(
    project_id: &ProjectId,
    change: &TopicChange,
    sources: &[TopicSourceProof],
) -> Result<String, String> {
    validate_changes(std::slice::from_ref(change))?;
    if sources.len() != change.source_finding_ids.len()
        || sources
            .iter()
            .map(|source| &source.finding_id)
            .collect::<std::collections::BTreeSet<_>>()
            != change.source_finding_ids.iter().collect()
    {
        return Err("Topic source proofs do not match the proposal source IDs".into());
    }
    let key = TopicKey::parse(&change.topic_key)?;
    let mut output = String::from("---\ntype: Topic\ntitle: ");
    output.push_str(&yaml_string(&change.title));
    output.push_str("\ndescription: ");
    output.push_str(&yaml_string(&change.summary));
    output.push_str("\nstatus: draft\nrex_projects:\n  project_id: ");
    output.push_str(&yaml_string(project_id.as_str()));
    output.push_str("\n  topic_key: ");
    output.push_str(&yaml_string(key.as_str()));
    if let Some(prior_digest) = &change.expected_prior_digest {
        output.push_str("\n  prior_content_sha256: ");
        output.push_str(&yaml_string(prior_digest.as_str()));
    }
    output.push_str("\n  source_findings:\n");
    let mut sorted_sources = sources.to_vec();
    sorted_sources.sort_by(|left, right| left.finding_id.cmp(&right.finding_id));
    for source in &sorted_sources {
        let run_digest = format!("{:x}", Sha256::digest(source.ticket_run_id.as_bytes()));
        let resource = format!("../postmortems/{run_digest}.md");
        writeln!(
            output,
            "    - id: {}\n      resource: {}\n      publication_sha256: {}\n      ordinal: {}",
            yaml_string(source.finding_id.as_str()),
            yaml_string(&resource),
            yaml_string(source.publication_digest.as_str()),
            source.ordinal
        )
        .unwrap();
    }
    output.push_str("---\n\n# Summary\n\n");
    output.push_str(&change.summary);
    output.push_str("\n\n## Applicability\n\n");
    output.push_str(&change.applicability);
    output.push_str("\n\n## Claims\n");
    for claim in &change.claims {
        output.push_str("\n- ");
        output.push_str(claim);
    }
    output.push_str("\n\n## Proposed check\n\n");
    output.push_str(&change.proposed_check);
    output.push_str("\n\n## Counterexamples\n");
    if change.counterexamples.is_empty() {
        output.push_str("\n- None recorded.");
    } else {
        for counterexample in &change.counterexamples {
            output.push_str("\n- ");
            output.push_str(counterexample);
        }
    }
    output.push_str("\n\n## Sources\n");
    for source in &sorted_sources {
        let run_digest = format!("{:x}", Sha256::digest(source.ticket_run_id.as_bytes()));
        writeln!(output, "\n- Finding `{}` in [published Postmortem](../postmortems/{run_digest}.md) (ordinal {}, publication `{}`).", source.finding_id, source.ordinal, source.publication_digest).unwrap();
    }
    if output.len() > MAX_TOPIC_DOCUMENT_BYTES {
        return Err("rendered Topic exceeds the 64 KiB document limit".into());
    }
    Ok(output)
}

pub fn content_digest(content: &str) -> Digest {
    Digest::parse(format!("{:x}", Sha256::digest(content.as_bytes()))).expect("sha256 is a digest")
}

pub fn publication_relative_path(intent: &TopicIntent) -> Result<String, String> {
    validate_version_identity(intent)?;
    let project = intent.project_id.as_str();
    let filename = if intent.revision == 0 {
        format!("{}.md", intent.key.as_str())
    } else {
        format!("{}.r{}.md", intent.key.as_str(), intent.content_digest)
    };
    Ok(format!("projects/{project}/topics/{filename}"))
}

pub fn validate_version_identity(intent: &TopicIntent) -> Result<(), String> {
    match (intent.revision, intent.expected_prior_digest.as_ref()) {
        (0, None) => Ok(()),
        (0, Some(_)) => Err("genesis Topic intent cannot have a prior digest".into()),
        (_, None) => Err("revised Topic intent must have a prior digest".into()),
        (_, Some(_)) => Ok(()),
    }
}

pub fn expected_operation_id(intent: &TopicIntent) -> Result<String, String> {
    validate_version_identity(intent)?;
    if intent.revision == 0 {
        let mut identity_hash = Sha256::new();
        identity_hash.update(b"rex-supervisor-topic-create-v1\0");
        identity_hash.update(intent.project_id.as_str().as_bytes());
        identity_hash.update(b"\0");
        identity_hash.update(intent.key.as_str().as_bytes());
        return Ok(format!("topic-{:x}", identity_hash.finalize()));
    }
    let mut sources = intent.sources.clone();
    sources.sort_by(|left, right| left.finding_id.cmp(&right.finding_id));
    let source_identity = serde_json::to_vec(&sources).map_err(|error| error.to_string())?;
    let mut identity_hash = Sha256::new();
    identity_hash.update(b"rex-supervisor-topic-revision-v1\0");
    identity_hash.update(intent.project_id.as_str().as_bytes());
    identity_hash.update(b"\0");
    identity_hash.update(intent.key.as_str().as_bytes());
    identity_hash.update(b"\0");
    identity_hash.update(intent.destination_root.to_string_lossy().as_bytes());
    identity_hash.update(b"\0");
    identity_hash.update(intent.revision.to_be_bytes());
    identity_hash.update(b"\0");
    identity_hash.update(
        intent
            .expected_prior_digest
            .as_ref()
            .ok_or("revised Topic intent has no prior digest")?
            .as_str()
            .as_bytes(),
    );
    identity_hash.update(b"\0");
    identity_hash.update(intent.content_digest.as_str().as_bytes());
    identity_hash.update(b"\0");
    identity_hash.update(&source_identity);
    Ok(format!("topic-{:x}", identity_hash.finalize()))
}

pub fn publish_immutable(intent: &TopicIntent) -> Result<TopicReceipt, TopicPublicationError> {
    if !intent.destination_root.is_absolute() {
        return Err("Topic intent destination root must be absolute".into());
    }
    let project = intent.project_id.as_str();
    let root = canonical_root(&intent.destination_root)?;
    let bundle = ensure_child_dir(&root, "projects")?;
    let project_dir = ensure_child_dir(&bundle, project)?;
    let topics_dir = ensure_child_dir(&project_dir, "topics")?;
    validate_version_identity(intent)?;
    let relative_path = publication_relative_path(intent)?;
    let filename = relative_path
        .rsplit('/')
        .next()
        .ok_or("invalid Topic relative path")?;
    let target = topics_dir.join(filename);
    let bytes = intent.content.as_bytes();
    if bytes.len() > MAX_TOPIC_DOCUMENT_BYTES
        || content_digest(&intent.content) != intent.content_digest
    {
        return Err("Topic intent content digest or byte bound is invalid".into());
    }
    let mut source_ids = intent
        .sources
        .iter()
        .map(|source| source.finding_id.clone())
        .collect::<Vec<_>>();
    source_ids.sort();
    let mut publication_digests = intent
        .sources
        .iter()
        .map(|source| source.publication_digest.clone())
        .collect::<Vec<_>>();
    publication_digests.sort();
    let manifest = TopicManifest {
        operation_id: intent.operation_id.clone(),
        project_id: intent.project_id.clone(),
        topic_key: intent.key.clone(),
        relative_path,
        format: "okf-0.2".into(),
        content_sha256: intent.content_digest.clone(),
        source_finding_ids: source_ids,
        source_publication_digests: publication_digests,
        byte_count: bytes.len(),
    };
    let manifest_digest = Digest::parse(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&manifest).map_err(|e| e.to_string())?)
    ))?;
    let staging = topics_dir.join(format!(
        ".{}.{}.tmp",
        intent.key.as_str(),
        intent.operation_id
    ));
    match fs::symlink_metadata(&target) {
        Ok(_) => {
            reconcile_existing(&target, bytes)?;
            if staging.exists() {
                remove_matching_stage(&staging, bytes, true)?;
            }
            return Ok(TopicReceipt {
                manifest,
                manifest_digest,
                published_at_unix: unix_now()?,
            });
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("inspect Topic target: {error}").into()),
    }
    if staging.exists() {
        remove_matching_stage(&staging, bytes, true)?;
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut staged = options
        .open(&staging)
        .map_err(|e| format!("create Topic staging file: {e}"))?;
    staged
        .write_all(bytes)
        .map_err(|e| format!("write Topic staging file: {e}"))?;
    staged
        .sync_all()
        .map_err(|e| format!("sync Topic staging file: {e}"))?;
    drop(staged);
    match fs::hard_link(&staging, &target) {
        Ok(()) => {
            fs::remove_file(&staging).map_err(|e| format!("remove Topic staging file: {e}"))?;
            sync_file_and_parent(&target)?;
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            remove_matching_stage(&staging, bytes, false)?;
            reconcile_existing(&target, bytes)?;
        }
        Err(error) => {
            let _ = fs::remove_file(&staging);
            return Err(format!("publish Topic without replacement: {error}").into());
        }
    }
    Ok(TopicReceipt {
        manifest,
        manifest_digest,
        published_at_unix: unix_now()?,
    })
}

fn canonical_root(root: &Path) -> Result<PathBuf, String> {
    fs::create_dir_all(root).map_err(|e| format!("create Topic root: {e}"))?;
    let canonical = fs::canonicalize(root).map_err(|e| format!("resolve Topic root: {e}"))?;
    if !canonical.is_absolute() {
        return Err("Topic root did not resolve to an absolute path".into());
    }
    let mut directory = canonical.as_path();
    while let Some(parent) = directory.parent() {
        sync_directory(parent).map_err(|e| format!("sync Topic root ancestor: {e}"))?;
        directory = parent;
    }
    Ok(canonical)
}

fn ensure_child_dir(parent: &Path, name: &str) -> Result<PathBuf, TopicPublicationError> {
    if Path::new(name)
        .components()
        .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(TopicPublicationError::Failure(
            "invalid Topic path component".into(),
        ));
    }
    let path = parent.join(name);
    match fs::create_dir(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(TopicPublicationError::Failure(format!(
                "create Topic directory: {error}"
            )));
        }
    }
    let metadata = fs::symlink_metadata(&path)
        .map_err(|e| TopicPublicationError::Failure(format!("inspect Topic directory: {e}")))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(TopicPublicationError::Conflict(
            "Topic path contains a symlink or non-directory".into(),
        ));
    }
    sync_directory(parent)
        .map_err(|e| TopicPublicationError::Failure(format!("sync Topic directory parent: {e}")))?;
    Ok(path)
}

fn reconcile_existing(path: &Path, expected: &[u8]) -> Result<(), TopicPublicationError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|e| TopicPublicationError::Failure(format!("inspect existing Topic: {e}")))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(TopicPublicationError::Conflict(
            "Topic target is not a regular file".into(),
        ));
    }
    if read_bounded(path, expected.len())
        .map_err(|e| TopicPublicationError::Failure(format!("read existing Topic: {e}")))?
        .as_deref()
        != Some(expected)
    {
        return Err(TopicPublicationError::Conflict(
            "Topic target exists with different bytes".into(),
        ));
    }
    sync_file_and_parent(path).map_err(TopicPublicationError::Failure)?;
    Ok(())
}

fn remove_matching_stage(path: &Path, expected: &[u8], allow_partial: bool) -> Result<(), String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|e| format!("inspect Topic staging file: {e}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("Topic staging path contains unexpected data".into());
    }
    let Some(bytes) = read_bounded(path, expected.len()).map_err(|e| e.to_string())? else {
        return Err("Topic staging path contains unexpected data".into());
    };
    let partial = allow_partial && bytes.len() < expected.len() && expected.starts_with(&bytes);
    if bytes != expected && !partial {
        return Err("Topic staging path contains unexpected data".into());
    }
    #[cfg(unix)]
    if partial {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err("Topic staging path contains unexpected data".into());
        }
    }
    fs::remove_file(path).map_err(|e| format!("remove Topic staging file: {e}"))
}

fn read_bounded(path: &Path, maximum: usize) -> io::Result<Option<Vec<u8>>> {
    if fs::symlink_metadata(path)?.len() > maximum as u64 {
        return Ok(None);
    }
    let mut bytes = Vec::with_capacity(maximum.min(4096));
    File::open(path)?
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        Ok(None)
    } else {
        Ok(Some(bytes))
    }
}

fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

fn sync_file_and_parent(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|e| format!("sync Topic file: {e}"))?;
    let parent = path.parent().ok_or("Topic file has no parent directory")?;
    sync_directory(parent).map_err(|e| format!("sync Topic directory: {e}"))
}

fn yaml_string(value: &str) -> String {
    serde_json::to_string(value).expect("string serialization")
}

fn contains_unsafe_control(value: &str) -> bool {
    value
        .chars()
        .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
}

fn unix_now() -> Result<i64, String> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs() as i64)
}

#[cfg(test)]
mod tests {
    use super::{
        TopicChange, TopicKey, TopicSourceProof, content_digest, publish_immutable, render,
        validate_changes,
    };
    use crate::domain::{
        ids::{Digest, ProjectId},
        types::AgentAdapter,
    };
    use crate::engine::orchestration::{RoleOutputKind, RoleResultPayload};
    use crate::{providers, roles};
    use serde_json::json;

    fn change() -> TopicChange {
        TopicChange {
            topic_key: "safe-replay".into(),
            title: "Replay the same publication".into(),
            summary: "Retries must keep the accepted publication bytes.".into(),
            claims: vec!["A retry can reconcile the exact staged document.".into()],
            applicability: "Use for immutable generated Topic files.".into(),
            proposed_check: "Compare the stored content digest before acknowledging.".into(),
            counterexamples: vec!["A different existing file is a conflict.".into()],
            source_finding_ids: vec![Digest::parse("a".repeat(64)).unwrap()],
            expected_prior_digest: None,
        }
    }

    #[test]
    fn provider_result_requires_nullable_prior_digest_field() {
        let digest = "a".repeat(64);
        let topic = json!({
            "topic_key":"required-nullable",
            "title":"A required nullable field",
            "summary":"A creation sends null explicitly.",
            "claims":["Field presence is part of the result contract."],
            "applicability":"Supervisor Topic creation",
            "proposed_check":"The provider parser rejects an omitted field.",
            "counterexamples":[],
            "source_finding_ids":[digest],
            "expected_prior_digest":null
        });
        let supervisor_schema = roles::result_schema(crate::domain::types::Role::Supervisor);
        let schema = json!({
            "$schema":supervisor_schema["$schema"],
            "$defs":supervisor_schema["$defs"],
            "$ref":"#/$defs/TopicChange"
        });
        let parse = |topic: serde_json::Value| {
            let provider_result = json!({
                "result":serde_json::to_string(&topic).unwrap()
            });
            let stdout = [
                json!({
                    "type":"item.completed",
                    "item":{"type":"agent_message","text":provider_result.to_string()}
                })
                .to_string(),
                json!({"type":"turn.completed"}).to_string(),
            ]
            .join("\n");
            providers::parse_result(AgentAdapter::Codex, stdout.as_bytes(), &schema)
                .map(|(_, value)| value)
        };

        let parsed = parse(topic.clone()).unwrap();
        serde_json::from_value::<TopicChange>(parsed).unwrap();

        let decision = json!({
            "batch_id":"batch-1",
            "batch_digest":"a".repeat(64),
            "config_revision":1,
            "observations":["Create a Topic."],
            "topic_changes":[topic.clone()],
            "checkpoint":{},
            "improvements":[],
            "candidate_change":null
        });
        assert!(matches!(
            RoleResultPayload::parse(RoleOutputKind::LearningDecision, decision.clone()).unwrap(),
            RoleResultPayload::LearningDecision(_)
        ));

        let mut missing = topic.clone();
        missing
            .as_object_mut()
            .unwrap()
            .remove("expected_prior_digest");
        let mut missing_decision = decision;
        missing_decision["topic_changes"][0] = missing.clone();
        let error = RoleResultPayload::parse(RoleOutputKind::LearningDecision, missing_decision)
            .unwrap_err();
        assert!(error.contains("expected_prior_digest"), "{error}");
        assert!(parse(missing).is_err());

        let mut malformed = topic.clone();
        malformed["expected_prior_digest"] = json!("not-a-digest");
        assert!(parse(malformed).is_err());

        let mut revision = topic;
        revision["expected_prior_digest"] = json!(digest);
        let parsed = parse(revision).unwrap();
        let decoded = serde_json::from_value::<TopicChange>(parsed).unwrap();
        assert!(validate_changes(&[decoded]).is_ok());
    }

    #[test]
    fn typed_topic_is_validated_rendered_and_created_once_without_replacement() {
        let proposal = change();
        validate_changes(std::slice::from_ref(&proposal)).unwrap();
        assert!(TopicKey::parse("../escape").is_err());
        assert!(TopicKey::parse("index").is_err());
        let source = TopicSourceProof {
            finding_id: proposal.source_finding_ids[0].clone(),
            publication_digest: Digest::parse("b".repeat(64)).unwrap(),
            ordinal: 0,
            ticket_run_id: "run-1".into(),
        };
        let project = ProjectId::parse("sample").unwrap();
        let content = render(&project, &proposal, std::slice::from_ref(&source)).unwrap();
        assert!(content.starts_with("---\ntype: Topic\n"));
        let root = tempfile::tempdir().unwrap();
        let intent = super::TopicIntent {
            operation_id: "topic-create-test".into(),
            project_id: project,
            key: TopicKey::parse(&proposal.topic_key).unwrap(),
            revision: 0,
            expected_prior_digest: None,
            destination_root: root.path().to_path_buf(),
            content_digest: content_digest(&content),
            content,
            sources: vec![source],
        };
        let staging = root
            .path()
            .join("projects/sample/topics/.safe-replay.topic-create-test.tmp");
        std::fs::create_dir_all(staging.parent().unwrap()).unwrap();
        let target = root.path().join("projects/sample/topics/safe-replay.md");
        std::fs::write(&staging, b"unexpected").unwrap();
        assert!(publish_immutable(&intent).is_err());
        assert_eq!(std::fs::read(&staging).unwrap(), b"unexpected");
        std::fs::write(&staging, &intent.content.as_bytes()[..7]).unwrap();
        let partial_alias = staging.with_extension("alias");
        std::fs::hard_link(&staging, &partial_alias).unwrap();
        assert!(publish_immutable(&intent).is_err());
        assert_eq!(
            std::fs::read(&staging).unwrap(),
            &intent.content.as_bytes()[..7]
        );
        assert!(partial_alias.exists());
        std::fs::remove_file(&partial_alias).unwrap();
        std::fs::remove_file(&staging).unwrap();

        std::fs::write(&staging, &intent.content).unwrap();
        std::fs::hard_link(&staging, &target).unwrap();
        publish_immutable(&intent).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), intent.content.as_bytes());
        assert!(!staging.exists());
        std::fs::remove_file(&target).unwrap();
        for partial_len in [0, 7] {
            if target.exists() {
                std::fs::remove_file(&target).unwrap();
            }
            std::fs::write(&staging, &intent.content.as_bytes()[..partial_len]).unwrap();
            publish_immutable(&intent).unwrap();
            assert_eq!(std::fs::read(&target).unwrap(), intent.content.as_bytes());
            assert!(!staging.exists());
        }
        let receipt = publish_immutable(&intent).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), intent.content.as_bytes());
        assert_eq!(receipt.manifest.content_sha256, intent.content_digest);
        assert!(publish_immutable(&intent).unwrap().manifest == receipt.manifest);
        std::fs::write(&target, "human edit").unwrap();
        assert!(publish_immutable(&intent).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"human edit");
        let unexpected = vec![b'x'; super::MAX_TOPIC_DOCUMENT_BYTES * 16];
        std::fs::write(&target, &unexpected).unwrap();
        assert!(publish_immutable(&intent).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), unexpected);
        std::fs::remove_file(&target).unwrap();
        std::os::unix::fs::symlink(root.path().join("missing"), &target).unwrap();
        assert!(matches!(
            publish_immutable(&intent),
            Err(super::TopicPublicationError::Conflict(_))
        ));
        assert!(
            std::fs::symlink_metadata(target)
                .unwrap()
                .file_type()
                .is_symlink()
        );

        let invalid_root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), invalid_root.path().join("projects")).unwrap();
        let mut invalid_parent_intent = intent;
        invalid_parent_intent.destination_root = invalid_root.path().to_path_buf();
        assert!(matches!(
            publish_immutable(&invalid_parent_intent),
            Err(super::TopicPublicationError::Conflict(_))
        ));
        assert!(!outside.path().join("sample/topics/safe-replay.md").exists());
    }
}
