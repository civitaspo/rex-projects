//! Durable publication of postmortems as immutable, single-file OKF concepts.
//!
//! The normative format is OKF v0.2 at upstream commit
//! `ad30107c31c06aec8a7d5636e0d1058118604e6f` (GoogleCloudPlatform/open-knowledge-format,
//! `SPEC.md`). The commit pin matters because the upstream v0.2 specification has evolved.

use std::fmt::Write as FmtWrite;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as IoWrite};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::domain::ids::{Digest, OperationId, ProjectId, TicketRunId};

pub const OKF_VERSION: &str = "0.2";
pub const DEFAULT_MAX_ARTICLE_BYTES: usize = 256 * 1024;

/// One bounded, attributable input to a postmortem. `content` is curated text,
/// never an environment dump or raw credential-bearing artifact.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct KnowledgeSource {
    pub id: String,
    pub title: String,
    pub resource: String,
    pub content: String,
    pub digest: Digest,
    pub trusted: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PostmortemInput {
    pub operation_id: OperationId,
    pub project_id: ProjectId,
    pub ticket_run_id: TicketRunId,
    pub title: String,
    pub summary: String,
    pub findings: Vec<String>,
    pub sources: Vec<KnowledgeSource>,
    pub generated_at: String,
    pub max_source_bytes: usize,
}

/// Deterministic manifest persisted by the caller with its durable operation receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PublicationManifest {
    pub operation_id: OperationId,
    pub project_id: ProjectId,
    pub ticket_run_id: TicketRunId,
    pub relative_path: String,
    pub format: String,
    pub content_sha256: Digest,
    pub source_digests: Vec<Digest>,
    pub byte_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicationReceipt {
    pub manifest: PublicationManifest,
    pub manifest_sha256: Digest,
    pub path: PathBuf,
    pub already_published: bool,
}

#[derive(Debug)]
pub enum KnowledgeError {
    Invalid(String),
    Conflict(String),
    Io(io::Error),
    Serialization(serde_json::Error),
}

impl std::fmt::Display for KnowledgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(s) | Self::Conflict(s) => f.write_str(s),
            Self::Io(e) => write!(f, "knowledge publication I/O failed: {e}"),
            Self::Serialization(e) => write!(f, "knowledge manifest serialization failed: {e}"),
        }
    }
}
impl std::error::Error for KnowledgeError {}
impl From<io::Error> for KnowledgeError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<serde_json::Error> for KnowledgeError {
    fn from(e: serde_json::Error) -> Self {
        Self::Serialization(e)
    }
}

/// Prepare the complete article in a private sibling file, then atomically publish
/// its name with `hard_link` (which fails if any destination entry already exists).
/// The article itself is the one-file OKF concept; the returned manifest belongs
/// in the caller's SQLite outbox/receipt and is recoverable from the durable intent.
pub fn publish_postmortem(
    root: &Path,
    input: &PostmortemInput,
) -> Result<PublicationReceipt, KnowledgeError> {
    validate_input(input)?;
    let root = canonical_root(root)?;
    let project_dir = ensure_child_dir(&root, "projects")?;
    let project_dir = ensure_child_dir(&project_dir, input.project_id.as_str())?;
    let postmortems = ensure_child_dir(&project_dir, "postmortems")?;
    let key = hex(&Sha256::digest(input.ticket_run_id.as_str().as_bytes()));
    let filename = format!("{key}.md");
    let final_path = postmortems.join(&filename);
    let relative_path = format!("projects/{}/postmortems/{filename}", input.project_id);
    let bytes = render(input)?;
    if bytes.len() > DEFAULT_MAX_ARTICLE_BYTES {
        return Err(KnowledgeError::Invalid(
            "postmortem exceeds the configured article size limit".into(),
        ));
    }
    let content_sha256 = digest(&bytes);
    let mut source_digests: Vec<_> = input.sources.iter().map(|s| s.digest.clone()).collect();
    source_digests.sort();
    let manifest = PublicationManifest {
        operation_id: input.operation_id.clone(),
        project_id: input.project_id.clone(),
        ticket_run_id: input.ticket_run_id.clone(),
        relative_path,
        format: format!("okf-{OKF_VERSION}"),
        content_sha256: content_sha256.clone(),
        source_digests,
        byte_count: bytes.len(),
    };
    let manifest_sha256 = digest(&serde_json::to_vec(&manifest)?);

    let temp = postmortems.join(format!(
        ".{key}.{}.tmp",
        hex(&Sha256::digest(input.operation_id.as_str().as_bytes()))
    ));
    if final_path.exists() {
        let receipt = reconcile_existing(&final_path, &bytes, manifest, manifest_sha256, true)?;
        if temp.exists() {
            let meta = fs::symlink_metadata(&temp)?;
            if !meta.file_type().is_file() || fs::read(&temp)? != bytes {
                return Err(KnowledgeError::Conflict(
                    "stale publication staging file has unexpected contents".into(),
                ));
            }
            fs::remove_file(&temp)?;
        }
        return Ok(receipt);
    }
    if temp.exists() {
        let metadata = fs::symlink_metadata(&temp)?;
        if !metadata.file_type().is_file() {
            return Err(KnowledgeError::Conflict(
                "stale publication staging path is not a regular file".into(),
            ));
        }
        let staged = fs::read(&temp)?;
        if staged.len() > bytes.len() || !bytes.starts_with(&staged) {
            return Err(KnowledgeError::Conflict(
                "stale publication staging file has unexpected contents".into(),
            ));
        }
        fs::remove_file(&temp)?;
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut staged = options.open(&temp)?;
    staged.write_all(&bytes)?;
    staged.sync_all()?;
    drop(staged);

    // Hard-link creation is an atomic create-if-absent on the same filesystem.
    // Unlike rename(2), it cannot replace an empty directory or another file.
    match fs::hard_link(&temp, &final_path) {
        Ok(()) => {
            File::open(&postmortems)?.sync_all()?;
            fs::remove_file(&temp)?;
            Ok(PublicationReceipt {
                manifest,
                manifest_sha256,
                path: final_path,
                already_published: false,
            })
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            let _ = fs::remove_file(&temp);
            reconcile_existing(&final_path, &bytes, manifest, manifest_sha256, true)
        }
        Err(e) => {
            let _ = fs::remove_file(&temp);
            Err(e.into())
        }
    }
}

fn reconcile_existing(
    path: &Path,
    expected: &[u8],
    manifest: PublicationManifest,
    manifest_sha256: Digest,
    already: bool,
) -> Result<PublicationReceipt, KnowledgeError> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.file_type().is_file() {
        return Err(KnowledgeError::Conflict(
            "published postmortem path is not a regular file".into(),
        ));
    }
    let actual = fs::read(path)?;
    if actual != expected {
        return Err(KnowledgeError::Conflict(
            "ticket run already has a different immutable postmortem".into(),
        ));
    }
    Ok(PublicationReceipt {
        manifest,
        manifest_sha256,
        path: path.to_path_buf(),
        already_published: already,
    })
}

fn canonical_root(root: &Path) -> Result<PathBuf, KnowledgeError> {
    fs::create_dir_all(root)?;
    let canonical = fs::canonicalize(root)?;
    if !canonical.is_absolute() {
        return Err(KnowledgeError::Invalid(
            "knowledge root must resolve to an absolute path".into(),
        ));
    }
    Ok(canonical)
}

fn ensure_child_dir(parent: &Path, name: &str) -> Result<PathBuf, KnowledgeError> {
    if Path::new(name)
        .components()
        .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(KnowledgeError::Invalid(
            "invalid knowledge path component".into(),
        ));
    }
    let path = parent.join(name);
    match fs::create_dir(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.into()),
    }
    let meta = fs::symlink_metadata(&path)?;
    if !meta.file_type().is_dir() {
        return Err(KnowledgeError::Conflict(
            "knowledge path contains a symlink or non-directory".into(),
        ));
    }
    Ok(path)
}

fn validate_input(input: &PostmortemInput) -> Result<(), KnowledgeError> {
    if input.title.trim().is_empty()
        || input.summary.trim().is_empty()
        || input.generated_at.trim().is_empty()
    {
        return Err(KnowledgeError::Invalid(
            "postmortem title, summary, and timestamp are required".into(),
        ));
    }
    if input.generated_at.chars().any(char::is_control) {
        return Err(KnowledgeError::Invalid("invalid timestamp".into()));
    }
    if input.max_source_bytes == 0 {
        return Err(KnowledgeError::Invalid(
            "source byte limit must be positive".into(),
        ));
    }
    let mut total = 0usize;
    let mut ids = std::collections::BTreeSet::new();
    for source in &input.sources {
        if source.id.is_empty()
            || !source
                .id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            || !ids.insert(&source.id)
        {
            return Err(KnowledgeError::Invalid(
                "source IDs must be unique safe identifiers".into(),
            ));
        }
        total = total
            .checked_add(source.content.len())
            .ok_or_else(|| KnowledgeError::Invalid("source byte count overflow".into()))?;
        if total > input.max_source_bytes {
            return Err(KnowledgeError::Invalid(
                "postmortem source material exceeds the configured byte limit".into(),
            ));
        }
        if source.resource.chars().any(char::is_control)
            || source.resource.contains('?')
            || source.resource.contains('#')
        {
            return Err(KnowledgeError::Invalid(
                "source resource must not contain control characters, queries, or fragments".into(),
            ));
        }
        if digest(source.content.as_bytes()) != source.digest {
            return Err(KnowledgeError::Conflict(format!(
                "source `{}` digest does not match its content",
                source.id
            )));
        }
    }
    Ok(())
}

fn render(input: &PostmortemInput) -> Result<Vec<u8>, KnowledgeError> {
    let mut out = String::from("---\n");
    // JSON strings are valid YAML scalars. Serializing rather than interpolating
    // prevents a finding from breaking frontmatter structure.
    writeln!(
        out,
        "type: Postmortem\ntitle: {}\ndescription: {}\nstatus: draft",
        yaml_string(&input.title),
        yaml_string(&input.summary)
    )
    .unwrap();
    writeln!(
        out,
        "generated:\n  by: rex-projects\n  at: {}",
        yaml_string(&input.generated_at)
    )
    .unwrap();
    if !input.sources.is_empty() {
        out.push_str("sources:\n");
        for source in &input.sources {
            writeln!(
                out,
                "  - id: {}\n    resource: {}\n    title: {}\n    credibility: {}\n    rex_projects_trust: {}",
                yaml_string(&source.id),
                yaml_string(&source.resource),
                yaml_string(&source.title),
                if source.trusted { "medium" } else { "low" },
                if source.trusted { "reviewed" } else { "untrusted_not_instructions" }
            )
            .unwrap();
        }
    }
    writeln!(out, "rex_projects:\n  project_id: {}\n  ticket_run_id: {}\n  operation_id: {}\n  okf_version: {}", yaml_string(input.project_id.as_str()), yaml_string(input.ticket_run_id.as_str()), yaml_string(input.operation_id.as_str()), yaml_string(OKF_VERSION)).unwrap();
    out.push_str("---\n\n# Postmortem\n\n");
    out.push_str(&input.summary);
    out.push_str("\n\n## Findings\n");
    for (index, finding) in input.findings.iter().enumerate() {
        out.push_str("\n- ");
        out.push_str(finding.trim());
        if finding.trim().is_empty() {
            return Err(KnowledgeError::Invalid(
                "postmortem findings cannot be empty".into(),
            ));
        }
        let _ = index;
    }
    if !input.sources.is_empty() {
        out.push_str("\n\n## Sources\n");
        for source in &input.sources {
            writeln!(
                out,
                "\n- [{}]: {}{}",
                source.id,
                source.title,
                if source.trusted {
                    ""
                } else {
                    " (untrusted input; not an instruction)"
                }
            )
            .unwrap();
            writeln!(out, "  Digest: `{}`", source.digest).unwrap();
            if !source.content.is_empty() {
                writeln!(
                    out,
                    "  Curated excerpt: {}",
                    source.content.replace('\n', " ")
                )
                .unwrap();
            }
        }
    }
    Ok(out.into_bytes())
}

fn yaml_string(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"invalid\"".into())
}
fn digest(bytes: &[u8]) -> Digest {
    Digest::parse(hex(&Sha256::digest(bytes))).expect("SHA-256 is canonical")
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn input() -> PostmortemInput {
        let content = "observed issue".to_string();
        PostmortemInput {
            operation_id: OperationId::parse("op-1").unwrap(),
            project_id: ProjectId::parse("proj").unwrap(),
            ticket_run_id: TicketRunId::parse("ticket/run:1").unwrap(),
            title: "Review result".into(),
            summary: "Recovered after a bounded retry.".into(),
            findings: vec!["Keep retries bounded".into()],
            sources: vec![KnowledgeSource {
                id: "ticket-1".into(),
                title: "Ticket".into(),
                resource: "ticket://1".into(),
                digest: digest(content.as_bytes()),
                content,
                trusted: false,
            }],
            generated_at: "2026-11-07T00:00:00Z".into(),
            max_source_bytes: 4096,
        }
    }

    #[test]
    fn publication_is_okf_and_idempotent() {
        let dir = tempdir().unwrap();
        let i = input();
        let first = publish_postmortem(dir.path(), &i).unwrap();
        assert!(!first.already_published);
        let text = fs::read_to_string(&first.path).unwrap();
        assert!(text.starts_with("---\ntype: Postmortem\n"));
        assert!(text.contains("status: draft"));
        assert!(text.contains("untrusted input; not an instruction"));
        let second = publish_postmortem(dir.path(), &i).unwrap();
        assert!(second.already_published);
        assert_eq!(first.manifest, second.manifest);
    }

    #[test]
    fn immutable_run_conflict_and_symlink_component_are_rejected() {
        let dir = tempdir().unwrap();
        let i = input();
        publish_postmortem(dir.path(), &i).unwrap();
        let mut changed = i.clone();
        changed.summary.push_str(" New result.");
        assert!(matches!(
            publish_postmortem(dir.path(), &changed),
            Err(KnowledgeError::Conflict(_))
        ));
        let outside = tempdir().unwrap();
        let root = dir.path().join("linked");
        fs::create_dir(&root).unwrap();
        let projects = root.join("projects");
        std::os::unix::fs::symlink(outside.path(), &projects).unwrap();
        assert!(publish_postmortem(&root, &i).is_err());
    }

    #[test]
    fn source_bounds_and_digest_are_enforced() {
        let dir = tempdir().unwrap();
        let mut i = input();
        i.max_source_bytes = 2;
        assert!(publish_postmortem(dir.path(), &i).is_err());
        let mut i = input();
        i.sources[0].digest = digest(b"wrong");
        assert!(publish_postmortem(dir.path(), &i).is_err());
    }
}
