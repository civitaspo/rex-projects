//! Bounded copies of verified child artifacts for parent Agent workspaces.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use sha2::{Digest as _, Sha256};

use crate::agent_api::HostArtifactLocator;
use crate::artifacts::ArtifactStore;
use crate::domain::ids::{Digest, ProjectId};
use crate::engine::orchestration::RoleArtifactReference;
use crate::launch::AgentLaunchAuthority;
use crate::store::ConfigStore;

const MAX_PARENT_ARTIFACTS: usize = 256;
const MAX_PARENT_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;
static STAGE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// Resolve host-registered references under the source AgentRun authority and stage their exact
/// verified bytes in the destination role workspace. The caller must pass refs from a durable
/// result or host-validated recovery authorization, never Agent-selected references.
#[allow(clippy::too_many_arguments)]
pub fn stage_verified_parent_artifacts(
    store: &mut ConfigStore,
    artifact_store: &ArtifactStore,
    source_authority: &AgentLaunchAuthority,
    source_evidence_id: &str,
    parent_project_id: &ProjectId,
    parent_config_revision: u64,
    parent_config_digest: &Digest,
    parent_workspace: &Path,
    references: &[RoleArtifactReference],
) -> Result<Vec<HostArtifactLocator>, String> {
    source_authority.validate()?;
    if source_evidence_id.len() != 64
        || !source_evidence_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("source evidence ID must be a lowercase SHA-256 identity".into());
    }
    if source_authority.project_id != *parent_project_id
        || source_authority.config_revision.0 != parent_config_revision
        || source_authority.config_digest != *parent_config_digest
    {
        return Err("child artifact source does not match the parent Project configuration".into());
    }
    if references.len() > MAX_PARENT_ARTIFACTS
        || serde_json::to_vec(references)
            .map_err(|error| error.to_string())?
            .len()
            > 262_144
    {
        return Err("parent artifact references exceed their bounded count or size".into());
    }
    let mut total_bytes = 0u64;
    let mut seen = std::collections::BTreeSet::new();
    for reference in references {
        if !seen.insert(reference.artifact_id.as_str()) {
            return Err("parent artifact source repeats an artifact ID".into());
        }
        total_bytes = total_bytes
            .checked_add(reference.bytes)
            .ok_or("parent artifact byte count overflow")?;
    }
    if total_bytes > MAX_PARENT_ARTIFACT_BYTES {
        return Err("parent artifacts exceed the 64 MiB staging limit".into());
    }
    if references.is_empty() {
        return Ok(Vec::new());
    }

    let workspace = canonical_real_directory(parent_workspace, "parent workspace")?;
    let source_authority_digest = source_authority.digest()?;
    let mut staged = Vec::with_capacity(references.len());
    for reference in references {
        let verified = store
            .lookup_verified_artifact(artifact_store, source_authority, reference)?
            .ok_or_else(|| {
                format!(
                    "parent wake source {source_evidence_id} references unregistered artifact {}",
                    reference.artifact_id
                )
            })?;
        if verified.reference() != reference {
            return Err(format!(
                "registered artifact {} does not exactly match the durable source reference",
                reference.artifact_id
            ));
        }
        let registration = verified.registration();
        if registration.project_id != *parent_project_id
            || registration.agent_run_id != source_authority.agent_run_id.as_str()
            || registration.config_revision != parent_config_revision
            || registration.config_digest != *parent_config_digest
            || registration.authority_digest != source_authority_digest
        {
            return Err(format!(
                "registered artifact {} does not match the child launch authority and parent configuration",
                reference.artifact_id
            ));
        }
        let bytes = verified.read_bytes(artifact_store)?;
        if bytes.len() as u64 != reference.bytes
            || format!("{:x}", Sha256::digest(&bytes)) != reference.digest.as_str()
        {
            return Err(format!(
                "registered artifact {} bytes differ from its durable reference",
                reference.artifact_id
            ));
        }
        let relative_path = artifact_relative_path(reference.artifact_id.as_str())?;
        let destination = workspace.join(&relative_path);
        publish_readonly_content(&workspace, &destination, &bytes, reference)?;
        let locator = HostArtifactLocator {
            artifact_id: reference.artifact_id.clone(),
            kind: reference.kind,
            schema_version: reference.schema_version,
            digest: reference.digest.clone(),
            bytes: reference.bytes,
            path: relative_path,
            source_run_id: source_authority.agent_run_id.as_str().to_owned(),
            source_evidence_id: source_evidence_id.to_owned(),
            source_authority_digest: source_authority_digest.clone(),
        };
        locator.validate()?;
        staged.push(locator);
    }
    Ok(staged)
}

fn artifact_relative_path(artifact_id: &str) -> Result<String, String> {
    if artifact_id.len() != 64
        || !artifact_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("artifact ID is not a normalized lowercase SHA-256 identity".into());
    }
    Ok(format!(
        ".rex-artifacts/sha256/{}/{}",
        &artifact_id[..2],
        artifact_id
    ))
}

fn canonical_real_directory(path: &Path, label: &str) -> Result<PathBuf, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| format!("{label}: {error}"))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(format!("{label} must be a real directory"));
    }
    fs::canonicalize(path).map_err(|error| format!("canonicalize {label}: {error}"))
}

fn ensure_private_directory(path: &Path) -> Result<(), String> {
    let created = match fs::create_dir(path) {
        Ok(()) => true,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(error) => return Err(format!("create parent artifact directory: {error}")),
    };
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("parent artifact directory is not a real directory".into());
    }
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("set private artifact directory mode: {error}"))?;
    if created {
        let parent = path
            .parent()
            .ok_or("parent artifact directory has no parent")?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("sync parent artifact directory entry: {error}"))?;
    }
    Ok(())
}

fn publish_readonly_content(
    workspace: &Path,
    destination: &Path,
    bytes: &[u8],
    reference: &RoleArtifactReference,
) -> Result<(), String> {
    let mut current = workspace.to_path_buf();
    for component in [
        ".rex-artifacts",
        "sha256",
        &reference.artifact_id.as_str()[..2],
    ] {
        current.push(component);
        ensure_private_directory(&current)?;
        if !current.starts_with(workspace) {
            return Err("parent artifact directory escaped the workspace".into());
        }
    }
    let parent = destination
        .parent()
        .ok_or("parent artifact destination has no directory")?;
    if parent != current {
        return Err(
            "parent artifact destination is outside its content-addressed directory".into(),
        );
    }

    match fs::symlink_metadata(destination) {
        Ok(metadata) => return verify_existing(destination, metadata, bytes, reference),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("inspect parent artifact destination: {error}")),
    }

    let nonce = STAGE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = parent.join(format!(
        ".stage-{}-{}-{nonce}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "system clock is before Unix epoch")?
            .as_nanos()
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = options
        .open(&temporary)
        .map_err(|error| format!("create parent artifact staging file: {error}"))?;
    let result = (|| {
        file.write_all(bytes)
            .map_err(|error| format!("write parent artifact staging file: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("sync parent artifact staging file: {error}"))?;
        #[cfg(unix)]
        file.set_permissions(fs::Permissions::from_mode(0o444))
            .map_err(|error| format!("make staged parent artifact readonly: {error}"))?;
        drop(file);
        match fs::hard_link(&temporary, destination) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let metadata = fs::symlink_metadata(destination)
                    .map_err(|error| format!("inspect replayed parent artifact: {error}"))?;
                verify_existing(destination, metadata, bytes, reference)?;
            }
            Err(error) => return Err(format!("publish parent artifact atomically: {error}")),
        }
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("sync parent artifact directory: {error}"))?;
        Ok(())
    })();
    let _ = fs::remove_file(&temporary);
    result
}

fn verify_existing(
    path: &Path,
    metadata: fs::Metadata,
    expected: &[u8],
    reference: &RoleArtifactReference,
) -> Result<(), String> {
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() != reference.bytes
    {
        return Err("existing parent artifact is linked or has an invalid size".into());
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o222 != 0 {
        return Err("existing parent artifact is not readonly".into());
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    let file = options.open(path).map_err(|error| {
        format!("open existing parent artifact without following links: {error}")
    })?;
    let opened = file.metadata().map_err(|error| error.to_string())?;
    if !opened.is_file() || opened.len() != reference.bytes {
        return Err("existing parent artifact changed while opening".into());
    }
    let mut actual = Vec::with_capacity(expected.len());
    file.take(reference.bytes.saturating_add(1))
        .read_to_end(&mut actual)
        .map_err(|error| error.to_string())?;
    if actual != expected || format!("{:x}", Sha256::digest(&actual)) != reference.digest.as_str() {
        return Err("existing parent artifact has different content".into());
    }
    Ok(())
}
