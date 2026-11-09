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

#[derive(Debug)]
pub(crate) enum ArtifactRegistrationError {
    AgentSource(String),
    Host(String),
}

impl std::fmt::Display for ArtifactRegistrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AgentSource(message) | Self::Host(message) => f.write_str(message),
        }
    }
}

impl From<String> for ArtifactRegistrationError {
    fn from(message: String) -> Self {
        Self::Host(message)
    }
}

impl From<&str> for ArtifactRegistrationError {
    fn from(message: &str) -> Self {
        Self::Host(message.to_owned())
    }
}

fn read_regular_nofollow(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
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

    pub(crate) fn owns_object_path(
        &self,
        reference: &RoleArtifactReference,
        path: &Path,
    ) -> Result<bool, String> {
        validate_relative_path(&reference.path)?;
        let expected = self.root.join(&reference.path);
        if expected != path || !expected.starts_with(&self.root) {
            return Ok(false);
        }
        ensure_real_directory_chain(
            &self.root,
            expected.parent().ok_or("artifact object has no parent")?,
        )?;
        Ok(true)
    }

    #[allow(clippy::too_many_arguments)]
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
        self.register_classified(
            workspace,
            project_id,
            agent_run_id,
            role,
            path,
            kind,
            schema_version,
        )
        .map_err(|error| error.to_string())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn register_for_agent(
        &self,
        workspace: &Path,
        project_id: &ProjectId,
        agent_run_id: &str,
        role: Role,
        path: &str,
        kind: RoleArtifactKind,
        schema_version: u32,
    ) -> Result<VerifiedArtifact, ArtifactRegistrationError> {
        self.register_classified(
            workspace,
            project_id,
            agent_run_id,
            role,
            path,
            kind,
            schema_version,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn register_classified(
        &self,
        workspace: &Path,
        project_id: &ProjectId,
        agent_run_id: &str,
        role: Role,
        path: &str,
        kind: RoleArtifactKind,
        schema_version: u32,
    ) -> Result<VerifiedArtifact, ArtifactRegistrationError> {
        crate::agent_api::validate_relative_path(path)
            .map_err(ArtifactRegistrationError::AgentSource)?;
        if schema_version == 0 || agent_run_id.trim().is_empty() {
            return Err(ArtifactRegistrationError::AgentSource(
                "Artifact request is missing run or schema identity".into(),
            ));
        }
        if !crate::engine::orchestration::role_may_submit_artifact(role, kind) {
            return Err(ArtifactRegistrationError::AgentSource(
                "Agent role is not authorized to register this artifact kind".into(),
            ));
        }
        let workspace = fs::canonicalize(workspace)
            .map_err(|error| ArtifactRegistrationError::Host(format!("workspace: {error}")))?;
        let bytes = read_workspace_file(&workspace, path)?;
        validate_contents(kind, schema_version, path, &bytes)
            .map_err(ArtifactRegistrationError::AgentSource)?;
        let content_digest = Digest::parse(format!("{:x}", Sha256::digest(&bytes)))?;
        let agent_run_id = crate::domain::ids::AgentRunId::parse(agent_run_id.to_owned())?;
        let artifact_id = crate::domain::ids::ArtifactId::from_registration_identity(
            project_id,
            &agent_run_id,
            kind.as_str(),
            schema_version,
            &content_digest,
        )?;
        let artifact_id = artifact_id.as_str();
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
        publish_immutable_object(parent, &object_path, &bytes)?;
        let reference = RoleArtifactReference {
            artifact_id: crate::domain::ids::ArtifactId::parse(artifact_id.to_owned())?,
            kind,
            schema_version,
            path: relative,
            digest: content_digest.clone(),
            bytes: bytes.len() as u64,
        };
        Ok(VerifiedArtifact {
            artifact_id: artifact_id.to_owned(),
            project_id: project_id.clone(),
            agent_run_id: agent_run_id.as_str().to_owned(),
            kind,
            schema_version,
            content_digest,
            byte_count: bytes.len() as u64,
            object_path,
            reference,
        })
    }
}

pub(crate) fn validate_relative_path(path: &str) -> Result<(), String> {
    crate::agent_api::validate_relative_path(path)
}

fn ensure_real_directory_chain(root: &Path, target: &Path) -> Result<(), String> {
    let root = fs::canonicalize(root).map_err(|error| error.to_string())?;
    if !target.starts_with(&root) {
        return Err("Artifact object directory escaped the immutable store".into());
    }
    let mut current = root.as_path().to_path_buf();
    for component in target
        .strip_prefix(&root)
        .map_err(|error| error.to_string())?
        .components()
    {
        if !matches!(component, Component::Normal(_)) {
            return Err("Artifact object path is not normalized".into());
        }
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current).map_err(|error| error.to_string())?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err("Artifact object path contains a non-directory component".into());
        }
    }
    Ok(())
}

fn read_workspace_file(
    workspace: &Path,
    relative: &str,
) -> Result<Vec<u8>, ArtifactRegistrationError> {
    let path = Path::new(relative);
    if path
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(ArtifactRegistrationError::AgentSource(
            "Artifact path contains a non-normal component".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::fd::{AsRawFd, FromRawFd};
        let root = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(workspace)
            .map_err(|error| {
                ArtifactRegistrationError::Host(format!("open workspace root: {error}"))
            })?;
        let mut parent_fd = root.as_raw_fd();
        let mut parents = Vec::<File>::new();
        let components = path.components().collect::<Vec<_>>();
        for component in &components[..components.len() - 1] {
            let Component::Normal(name) = component else {
                return Err(ArtifactRegistrationError::AgentSource(
                    "Artifact path is not normalized".into(),
                ));
            };
            let name = std::ffi::CString::new(name.as_encoded_bytes()).map_err(|_| {
                ArtifactRegistrationError::AgentSource("Artifact path contains NUL".into())
            })?;
            let fd = unsafe {
                libc::openat(
                    parent_fd,
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(classify_source_open_error(
                    "open Artifact parent",
                    std::io::Error::last_os_error(),
                ));
            }
            let opened = unsafe { File::from_raw_fd(fd) };
            parent_fd = opened.as_raw_fd();
            // Retain descriptors until the final open to prevent parent replacement mid-walk.
            parents.push(opened);
        }
        let Component::Normal(name) = components.last().ok_or_else(|| {
            ArtifactRegistrationError::AgentSource("Artifact path is empty".into())
        })?
        else {
            return Err(ArtifactRegistrationError::AgentSource(
                "Artifact path is not normalized".into(),
            ));
        };
        let name = std::ffi::CString::new(name.as_encoded_bytes()).map_err(|_| {
            ArtifactRegistrationError::AgentSource("Artifact path contains NUL".into())
        })?;
        // O_NONBLOCK prevents a malicious FIFO from hanging the host before fstat can reject it.
        let fd = unsafe {
            libc::openat(
                parent_fd,
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            return Err(classify_source_open_error(
                "open Artifact",
                std::io::Error::last_os_error(),
            ));
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let metadata = file
            .metadata()
            .map_err(|error| ArtifactRegistrationError::Host(error.to_string()))?;
        if !metadata.is_file() || metadata.len() > MAX_ARTIFACT_BYTES {
            return Err(ArtifactRegistrationError::AgentSource(
                "Artifact must be a bounded regular file".into(),
            ));
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.take(MAX_ARTIFACT_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| ArtifactRegistrationError::Host(error.to_string()))?;
        if bytes.len() as u64 > MAX_ARTIFACT_BYTES {
            return Err(ArtifactRegistrationError::AgentSource(
                "Artifact exceeds 64 MiB".into(),
            ));
        }
        Ok(bytes)
    }
    #[cfg(not(unix))]
    {
        let full = workspace.join(path);
        let metadata = fs::symlink_metadata(&full)
            .map_err(|error| classify_source_open_error("inspect Artifact source", error))?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() > MAX_ARTIFACT_BYTES
        {
            return Err(ArtifactRegistrationError::AgentSource(
                "Artifact must be a bounded regular file".into(),
            ));
        }
        fs::read(full).map_err(|error| classify_source_open_error("read Artifact", error))
    }
}

fn classify_source_open_error(context: &str, error: std::io::Error) -> ArtifactRegistrationError {
    #[cfg(unix)]
    let is_agent_source_error = matches!(
        error.raw_os_error(),
        Some(
            libc::ENOENT
                | libc::ENOTDIR
                | libc::ELOOP
                | libc::EACCES
                | libc::EPERM
                | libc::ENAMETOOLONG
        )
    );
    #[cfg(not(unix))]
    let is_agent_source_error = matches!(
        error.kind(),
        std::io::ErrorKind::NotFound
            | std::io::ErrorKind::NotADirectory
            | std::io::ErrorKind::PermissionDenied
            | std::io::ErrorKind::InvalidInput
    );
    let message = format!("{context}: {error}");
    if is_agent_source_error {
        ArtifactRegistrationError::AgentSource(message)
    } else {
        ArtifactRegistrationError::Host(message)
    }
}

fn publish_immutable_object(parent: &Path, destination: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock is before Unix epoch")?
        .as_nanos();
    let stage = parent.join(format!(".stage-{}-{nonce:x}", std::process::id()));
    let result = (|| {
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&stage)
            .map_err(|error| format!("create staged Artifact object: {error}"))?;
        output
            .write_all(bytes)
            .map_err(|error| format!("write staged Artifact object: {error}"))?;
        output
            .sync_all()
            .map_err(|error| format!("sync staged Artifact object: {error}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            output
                .set_permissions(fs::Permissions::from_mode(0o400))
                .map_err(|error| format!("make staged Artifact object immutable: {error}"))?;
            output
                .sync_all()
                .map_err(|error| format!("sync immutable Artifact object: {error}"))?;
        }
        drop(output);

        match fs::hard_link(&stage, destination) {
            Ok(()) => sync_directory(parent)?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing = read_regular_nofollow(destination, MAX_ARTIFACT_BYTES)?;
                if existing != bytes {
                    return Err("content-addressed Artifact object has conflicting bytes".into());
                }
            }
            Err(error) => return Err(format!("publish staged Artifact object: {error}")),
        }
        Ok(())
    })();

    match fs::remove_file(&stage) {
        Ok(()) => {
            if result.is_ok() {
                sync_directory(parent)?;
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) if result.is_ok() => {
            return Err(format!("remove staged Artifact object: {error}"));
        }
        Err(_) => {}
    }
    result
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("sync Artifact object directory: {error}"))
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), String> {
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::{
        ArtifactRegistrationError, MAX_ARTIFACT_BYTES, classify_source_open_error,
        publish_immutable_object, read_workspace_file,
    };
    use std::fs;
    use std::io::Read;
    use std::time::{Duration, Instant};

    #[test]
    fn source_open_classifier_keeps_host_resource_failures_fatal() {
        #[cfg(unix)]
        {
            for errno in [
                libc::EMFILE,
                libc::ENFILE,
                libc::ENOMEM,
                libc::EIO,
                libc::EINTR,
            ] {
                assert!(matches!(
                    classify_source_open_error(
                        "open Artifact",
                        std::io::Error::from_raw_os_error(errno)
                    ),
                    ArtifactRegistrationError::Host(_)
                ));
            }
            for errno in [libc::ENOENT, libc::ENOTDIR, libc::ELOOP, libc::EACCES] {
                assert!(matches!(
                    classify_source_open_error(
                        "open Artifact",
                        std::io::Error::from_raw_os_error(errno)
                    ),
                    ArtifactRegistrationError::AgentSource(_)
                ));
            }
        }
        #[cfg(not(unix))]
        {
            assert!(matches!(
                classify_source_open_error(
                    "open Artifact",
                    std::io::Error::from(std::io::ErrorKind::NotFound)
                ),
                ArtifactRegistrationError::AgentSource(_)
            ));
            assert!(matches!(
                classify_source_open_error(
                    "open Artifact",
                    std::io::Error::other("host I/O failure")
                ),
                ArtifactRegistrationError::Host(_)
            ));
        }
    }

    #[test]
    fn retry_after_abandoned_partial_stage_publishes_complete_object() {
        let root = tempfile::tempdir().unwrap();
        let destination = root.path().join("object");
        fs::write(root.path().join(".stage-crashed-partway"), b"partial").unwrap();
        publish_immutable_object(root.path(), &destination, b"complete artifact").unwrap();
        assert_eq!(fs::read(destination).unwrap(), b"complete artifact");
    }

    #[cfg(unix)]
    #[test]
    fn workspace_fifo_is_rejected_without_blocking() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let root = tempfile::tempdir().unwrap();
        let fifo = root.path().join("artifact.fifo");
        let c_path = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        let status = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
        assert_eq!(status, 0);

        let started = Instant::now();
        let result = std::thread::spawn({
            let root = root.path().to_path_buf();
            move || read_workspace_file(&root, "artifact.fifo")
        })
        .join()
        .unwrap();
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn existing_object_must_be_regular_and_within_bound() {
        let root = tempfile::tempdir().unwrap();
        let object = root.path().join("object");
        fs::write(&object, vec![0; MAX_ARTIFACT_BYTES as usize + 1]).unwrap();
        let mut file = fs::File::open(&object).unwrap();
        let mut sample = [0; 1];
        file.read_exact(&mut sample).unwrap();
        assert!(super::read_regular_nofollow(&object, MAX_ARTIFACT_BYTES).is_err());
    }
}
