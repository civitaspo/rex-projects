//! Host-owned immutable Artifact registration.
//!
//! Agent paths are claims. Registration opens a bounded regular file beneath the launch
//! workspace, copies the opened bytes into content-addressed storage, and returns only after the
//! durable copy has been synced. Callers must persist the returned identity in SQLite before
//! acknowledging the Agent mailbox request.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};

use sha2::{Digest as _, Sha256};

use crate::domain::ids::{Digest, ProjectId};
use crate::domain::types::Role;
use crate::engine::orchestration::{RoleArtifactKind, RoleArtifactReference};

const MAX_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;

fn read_regular_nofollow(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let file = options
        .open(path)
        .map_err(|error| format!("open existing artifact: {error}"))?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err("existing artifact must be a bounded regular file".into());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > limit {
        return Err("existing artifact exceeds its size limit".into());
    }
    Ok(bytes)
}

#[derive(Clone, Debug)]
pub struct VerifiedArtifact {
    pub artifact_id: String,
    pub project_id: ProjectId,
    pub agent_run_id: String,
    pub kind: RoleArtifactKind,
    pub schema_version: u32,
    pub content_digest: Digest,
    pub byte_count: u64,
    pub object_path: PathBuf,
    pub reference: RoleArtifactReference,
}

#[derive(Clone, Debug)]
pub struct ArtifactStore {
    root: PathBuf,
}

impl ArtifactStore {
    pub fn open(root: &Path) -> Result<Self, String> {
        fs::create_dir_all(root).map_err(|error| format!("create artifact root: {error}"))?;
        let metadata = fs::symlink_metadata(root).map_err(|error| error.to_string())?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err("artifact root must be a real directory".into());
        }
        let root = fs::canonicalize(root).map_err(|error| error.to_string())?;
        Ok(Self { root })
    }

    pub fn register(
        &self,
        workspace: &Path,
        project_id: &ProjectId,
        agent_run_id: &str,
        role: Role,
        path: &str,
        kind: RoleArtifactKind,
        schema_version: u32,
    ) -> Result<VerifiedArtifact, String> {
        crate::agent_api::validate_relative_path(path)?;
        if schema_version == 0 || agent_run_id.trim().is_empty() {
            return Err("Artifact request is missing run or schema identity".into());
        }
        if !crate::engine::orchestration::role_may_submit_artifact(role, kind) {
            return Err("Agent role is not authorized to register this artifact kind".into());
        }
        let workspace =
            fs::canonicalize(workspace).map_err(|error| format!("workspace: {error}"))?;
        let bytes = read_workspace_file(&workspace, path)?;
        validate_contents(kind, schema_version, path, &bytes)?;
        let content_digest = Digest::parse(format!("{:x}", Sha256::digest(&bytes)))?;
        let identity = serde_json::to_vec(&(
            "rex-projects-artifact-v1",
            project_id.as_str(),
            agent_run_id,
            kind,
            schema_version,
            content_digest.as_str(),
        ))
        .map_err(|error| error.to_string())?;
        let artifact_id = format!("{:x}", Sha256::digest(identity));
        let relative = format!("sha256/{}/{}", &artifact_id[..2], artifact_id);
        let object_path = self.root.join(&relative);
        let parent = object_path
            .parent()
            .ok_or("artifact object path has no parent")?;
        fs::create_dir_all(parent)
            .map_err(|error| format!("create artifact object directory: {error}"))?;
        let parent_meta = fs::symlink_metadata(parent).map_err(|error| error.to_string())?;
        if !parent_meta.is_dir()
            || parent_meta.file_type().is_symlink()
            || !fs::canonicalize(parent)
                .map_err(|error| error.to_string())?
                .starts_with(&self.root)
        {
            return Err("artifact object directory escaped the immutable store".into());
        }
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&object_path)
        {
            Ok(mut output) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    output
                        .set_permissions(fs::Permissions::from_mode(0o400))
                        .map_err(|error| error.to_string())?;
                }
                output
                    .write_all(&bytes)
                    .map_err(|error| error.to_string())?;
                output.sync_all().map_err(|error| error.to_string())?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing = read_regular_nofollow(&object_path, MAX_ARTIFACT_BYTES)?;
                if existing != bytes {
                    return Err("content-addressed artifact object has conflicting bytes".into());
                }
            }
            Err(error) => return Err(format!("publish immutable artifact object: {error}")),
        }
        let reference = RoleArtifactReference {
            kind,
            schema_version,
            path: relative,
            digest: content_digest.clone(),
            bytes: bytes.len() as u64,
        };
        Ok(VerifiedArtifact {
            artifact_id,
            project_id: project_id.clone(),
            agent_run_id: agent_run_id.to_owned(),
            kind,
            schema_version,
            content_digest,
            byte_count: bytes.len() as u64,
            object_path,
            reference,
        })
    }
}

fn read_workspace_file(workspace: &Path, relative: &str) -> Result<Vec<u8>, String> {
    let path = Path::new(relative);
    if path
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err("Artifact path contains a non-normal component".into());
    }
    #[cfg(unix)]
    {
        use std::os::fd::{AsRawFd, FromRawFd};
        let root = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(workspace)
            .map_err(|error| format!("open workspace root: {error}"))?;
        let mut parent_fd = root.as_raw_fd();
        let mut parents = Vec::<File>::new();
        let components = path.components().collect::<Vec<_>>();
        for component in &components[..components.len() - 1] {
            let Component::Normal(name) = component else {
                return Err("Artifact path is not normalized".into());
            };
            let name = std::ffi::CString::new(name.as_encoded_bytes())
                .map_err(|_| "Artifact path contains NUL")?;
            let fd = unsafe {
                libc::openat(
                    parent_fd,
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(format!(
                    "open Artifact parent: {}",
                    std::io::Error::last_os_error()
                ));
            }
            let opened = unsafe { File::from_raw_fd(fd) };
            parent_fd = opened.as_raw_fd();
            // Retain descriptors until the final open to prevent parent replacement mid-walk.
            parents.push(opened);
        }
        let Component::Normal(name) = components.last().ok_or("Artifact path is empty")? else {
            return Err("Artifact path is not normalized".into());
        };
        let name = std::ffi::CString::new(name.as_encoded_bytes())
            .map_err(|_| "Artifact path contains NUL")?;
        let fd = unsafe {
            libc::openat(
                parent_fd,
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(format!(
                "open Artifact: {}",
                std::io::Error::last_os_error()
            ));
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let metadata = file.metadata().map_err(|error| error.to_string())?;
        if !metadata.is_file() || metadata.len() > MAX_ARTIFACT_BYTES {
            return Err("Artifact must be a bounded regular file".into());
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.take(MAX_ARTIFACT_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| error.to_string())?;
        if bytes.len() as u64 > MAX_ARTIFACT_BYTES {
            return Err("Artifact exceeds 64 MiB".into());
        }
        Ok(bytes)
    }
    #[cfg(not(unix))]
    {
        let full = workspace.join(path);
        let metadata = fs::symlink_metadata(&full).map_err(|error| error.to_string())?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() > MAX_ARTIFACT_BYTES
        {
            return Err("Artifact must be a bounded regular file".into());
        }
        fs::read(full).map_err(|error| error.to_string())
    }
}

fn validate_contents(
    kind: RoleArtifactKind,
    schema_version: u32,
    path: &str,
    bytes: &[u8],
) -> Result<(), String> {
    if path.ends_with(".json") {
        let value: serde_json::Value = crate::protocol::parse_unique(bytes)?;
        if value
            .get("schema_version")
            .and_then(serde_json::Value::as_u64)
            .is_some_and(|value| value != u64::from(schema_version))
        {
            return Err(
                "Artifact JSON schema version does not match its registration request".into(),
            );
        }
    }
    if matches!(
        kind,
        RoleArtifactKind::TestReceipt
            | RoleArtifactKind::Review
            | RoleArtifactKind::MergeAssessment
            | RoleArtifactKind::OperationReceipt
            | RoleArtifactKind::Postmortem
            | RoleArtifactKind::Learning
    ) && bytes.is_empty()
    {
        return Err("evidence Artifact may not be empty".into());
    }
    Ok(())
}
