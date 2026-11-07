//! Immutable Rex-block package for one human-approved profile trial side.
//!
//! Trial runs deliberately carry the profile-trial capsule instead of an
//! `AgentLaunchReservation`. A trial therefore cannot acquire factory wake or
//! mailbox authority by being passed through the ordinary launch path.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::config::Profile;
use crate::domain::ids::{Digest, OperationId, ProjectId};
use crate::learning_trials::{InlineFixtureV1, ProfileTrialLaunchCapsule};
use crate::run_step::{RunDescriptor, TurnRequest, TurnResult};

pub const TRIAL_STEP_PACKAGE_SCHEMA_VERSION: u32 = 1;
const MAX_PACKAGE_BYTES: usize = 8 * 1024 * 1024;
const MAX_TRIAL_RECEIPT_BYTES: usize = 1024 * 1024;

/// Host-generated immutable input for `agent trial-step`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrialRunStepPackage {
    pub schema_version: u32,
    pub capsule: ProfileTrialLaunchCapsule,
    pub capsule_digest: Digest,
    pub environment_handoff_path: PathBuf,
    pub descriptor: RunDescriptor,
    pub operation_id: OperationId,
    pub project_id: ProjectId,
    pub controller_generation: u64,
    pub runtime_binary_digest: Digest,
    pub rex_cli_path: PathBuf,
    pub rex_search_path: Vec<PathBuf>,
    pub rex_endpoint: String,
    pub rex_server_identity: String,
    pub rex_window_id: String,
    pub profile: Profile,
    pub role_contract: String,
    pub prompt: String,
    pub shutdown_grace_seconds: u64,
    pub start_ack_timeout_seconds: u64,
}

/// Wrapper observation that the controller must match against the durable capsule and Rex.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrialStepStartRequest {
    pub schema_version: u32,
    pub capsule_digest: Digest,
    pub operation_id: OperationId,
    pub run_id: crate::domain::ids::AgentRunId,
    pub project_id: ProjectId,
    pub controller_generation: u64,
    pub descriptor_digest: Digest,
    pub runtime_binary_digest: Digest,
    pub qualification_receipt_digest: Digest,
    pub wrapper_pid: u32,
    pub wrapper_start_identity: String,
    pub rex_server_identity: String,
    pub rex_session_id: String,
    pub rex_window_id: String,
    pub rex_block_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrialStepStartReceipt {
    pub schema_version: u32,
    pub request_digest: Digest,
    pub capsule_digest: Digest,
    pub operation_id: OperationId,
    pub run_id: crate::domain::ids::AgentRunId,
    pub controller_generation: u64,
    pub accepted: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrialStepResult {
    pub schema_version: u32,
    pub request_digest: Digest,
    pub receipt: crate::run_step::RunReceipt,
    pub structured_result: Option<serde_json::Value>,
    pub result_digest: Digest,
}

/// Separate filesystem handshake for trial blocks. It has no methods that can mint
/// factory launch authority or publish a role wake.
#[derive(Clone, Debug)]
pub struct TrialStepSpool {
    directory: PathBuf,
}

impl TrialStepSpool {
    pub fn open(control_dir: &std::path::Path) -> Result<Self, String> {
        let metadata = fs::symlink_metadata(control_dir).map_err(|e| e.to_string())?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err("trial control directory must be a real directory".into());
        }
        let parent = fs::canonicalize(control_dir).map_err(|e| e.to_string())?;
        let directory = parent.join("trial-step");
        match fs::create_dir(&directory) {
            Ok(()) => set_private_dir(&directory)?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.to_string()),
        }
        let metadata = fs::symlink_metadata(&directory).map_err(|e| e.to_string())?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err("trial spool must be a real directory".into());
        }
        let canonical = fs::canonicalize(&directory).map_err(|e| e.to_string())?;
        if canonical != directory {
            return Err("trial spool path changed during canonicalization".into());
        }
        Ok(Self { directory })
    }

    pub fn publish_start_once(
        &self,
        request: TrialStepStartRequest,
    ) -> Result<TrialStepStartRequest, String> {
        if request.schema_version != 1
            || request.wrapper_pid == 0
            || request.controller_generation == 0
            || [
                request.wrapper_start_identity.as_str(),
                request.rex_server_identity.as_str(),
                request.rex_session_id.as_str(),
                request.rex_window_id.as_str(),
                request.rex_block_id.as_str(),
            ]
            .iter()
            .any(|value| value.trim().is_empty() || value.chars().any(char::is_control))
        {
            return Err("trial start request is incomplete".into());
        }
        self.publish_once("start.request.json", &request, 32 * 1024)?;
        Ok(request)
    }

    pub fn read_start_request(&self) -> Result<TrialStepStartRequest, String> {
        self.read("start.request.json", 32 * 1024)
    }

    pub fn publish_start_receipt(
        &self,
        request: &TrialStepStartRequest,
        receipt: TrialStepStartReceipt,
    ) -> Result<(), String> {
        let expected = digest_json(request)?;
        if receipt.schema_version != 1
            || receipt.request_digest != expected
            || receipt.capsule_digest != request.capsule_digest
            || receipt.operation_id != request.operation_id
            || receipt.run_id != request.run_id
            || receipt.controller_generation != request.controller_generation
            || !receipt.accepted
        {
            return Err("trial start acknowledgement does not match the request".into());
        }
        self.publish_once("start.receipt.json", &receipt, 32 * 1024)
    }

    pub fn wait_start_receipt(
        &self,
        request: &TrialStepStartRequest,
        timeout: Duration,
    ) -> Result<TrialStepStartReceipt, String> {
        let expected = digest_json(request)?;
        let deadline = std::time::Instant::now()
            .checked_add(timeout)
            .ok_or("trial start deadline overflow")?;
        loop {
            match self.read::<TrialStepStartReceipt>("start.receipt.json", 32 * 1024) {
                Ok(receipt)
                    if receipt.schema_version == 1
                        && receipt.request_digest == expected
                        && receipt.capsule_digest == request.capsule_digest
                        && receipt.operation_id == request.operation_id
                        && receipt.run_id == request.run_id
                        && receipt.controller_generation == request.controller_generation
                        && receipt.accepted =>
                {
                    return Ok(receipt);
                }
                Ok(_) => return Err("trial start acknowledgement is mismatched".into()),
                Err(error) if error == "trial spool file is not present" => {}
                Err(error) => return Err(error),
            }
            if std::time::Instant::now() >= deadline {
                return Err("timed out waiting for trial start acknowledgement".into());
            }
            thread::sleep(Duration::from_millis(50));
        }
    }

    pub fn publish_result_once(&self, result: &TrialStepResult) -> Result<(), String> {
        if result.schema_version != 1
            || result.receipt.run_id.as_str().is_empty()
            || result.result_digest != digest_result_payload(result)?
        {
            return Err("trial result is incomplete or has a mismatched digest".into());
        }
        self.publish_once("turn.result.json", result, MAX_TRIAL_RECEIPT_BYTES)
    }

    pub fn read_result(&self) -> Result<TrialStepResult, String> {
        self.read("turn.result.json", MAX_TRIAL_RECEIPT_BYTES)
    }

    fn publish_once<T: Serialize>(
        &self,
        name: &str,
        value: &T,
        limit: usize,
    ) -> Result<(), String> {
        let bytes = serde_json::to_vec(value).map_err(|e| e.to_string())?;
        if bytes.len() > limit {
            return Err("trial spool record exceeds its byte limit".into());
        }
        let stage = self
            .directory
            .join(format!(".{name}.{}.tmp", std::process::id()));
        let target = self.directory.join(name);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&stage).map_err(|e| e.to_string())?;
        file.write_all(&bytes).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        drop(file);
        match fs::hard_link(&stage, &target) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                if self.read_bytes(name, limit)? != bytes {
                    let _ = fs::remove_file(&stage);
                    return Err("trial spool record already exists with different contents".into());
                }
            }
            Err(error) => {
                let _ = fs::remove_file(&stage);
                return Err(error.to_string());
            }
        }
        fs::remove_file(stage).map_err(|e| e.to_string())
    }

    fn read<T: for<'de> Deserialize<'de>>(&self, name: &str, limit: usize) -> Result<T, String> {
        let bytes = self.read_bytes(name, limit)?;
        crate::protocol::parse_unique(&bytes)
    }

    fn read_bytes(&self, name: &str, limit: usize) -> Result<Vec<u8>, String> {
        let path = self.directory.join(name);
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
        }
        let file = options.open(path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                "trial spool file is not present".to_owned()
            } else {
                error.to_string()
            }
        })?;
        let metadata = file.metadata().map_err(|e| e.to_string())?;
        if !metadata.is_file() || metadata.len() as usize > limit {
            return Err("trial spool file is not a bounded regular file".into());
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.take(limit as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.len() > limit {
            return Err("trial spool file exceeds its byte limit".into());
        }
        Ok(bytes)
    }
}

fn digest_json<T: Serialize>(value: &T) -> Result<Digest, String> {
    let value = serde_json::to_value(value).map_err(|e| e.to_string())?;
    let canonical = serde_json::to_string(&value).map_err(|e| e.to_string())?;
    Digest::parse(format!("{:x}", Sha256::digest(canonical.as_bytes())))
}

fn digest_result_payload(result: &TrialStepResult) -> Result<Digest, String> {
    let payload = (
        &result.schema_version,
        &result.request_digest,
        &result.receipt,
        &result.structured_result,
    );
    digest_json(&payload)
}

fn set_private_dir(path: &std::path::Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Materialize only the approved inline seed into a new private workspace.
/// It never copies from a repository, follows a pre-existing path, or creates links.
pub fn materialize_fixture_workspace(
    seed: &InlineFixtureV1,
    expected_digest: &Digest,
    workspace: &std::path::Path,
) -> Result<(), String> {
    seed.validate()?;
    if seed.digest()? != *expected_digest || !workspace.is_absolute() {
        return Err(
            "trial fixture seed does not match its approved digest or workspace path".into(),
        );
    }
    let parent = workspace.parent().ok_or("trial workspace has no parent")?;
    let parent = fs::canonicalize(parent).map_err(|e| e.to_string())?;
    let parent_metadata = fs::symlink_metadata(&parent).map_err(|e| e.to_string())?;
    if !parent_metadata.is_dir() || parent_metadata.file_type().is_symlink() {
        return Err("trial workspace parent must be a real directory".into());
    }
    let name = workspace
        .file_name()
        .filter(|name| !name.is_empty() && *name != "." && *name != "..")
        .ok_or("trial workspace needs a normal final path component")?;
    let workspace = parent.join(name);
    if let Ok(metadata) = fs::symlink_metadata(&workspace) {
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err("trial workspace must be a real directory".into());
        }
        set_private_dir(&workspace)?;
        let root = fs::canonicalize(&workspace).map_err(|e| e.to_string())?;
        if root != workspace {
            return Err("trial workspace changed during canonicalization".into());
        }
        return verify_existing_fixture_workspace(seed, &root);
    }
    fs::create_dir(&workspace).map_err(|e| e.to_string())?;
    set_private_dir(&workspace)?;
    let root = fs::canonicalize(&workspace).map_err(|e| e.to_string())?;
    if root != workspace {
        return Err("trial workspace changed during canonicalization".into());
    }
    for (relative, contents) in &seed.files {
        let mut cursor = root.clone();
        let parts = relative.split('/').collect::<Vec<_>>();
        for part in &parts[..parts.len() - 1] {
            cursor.push(part);
            match fs::create_dir(&cursor) {
                Ok(()) => set_private_dir(&cursor)?,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.to_string()),
            }
            let metadata = fs::symlink_metadata(&cursor).map_err(|e| e.to_string())?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err("trial seed path traverses a non-directory or symlink".into());
            }
        }
        cursor.push(parts.last().ok_or("trial fixture path is empty")?);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&cursor).map_err(|e| e.to_string())?;
        file.write_all(contents.as_bytes())
            .map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn verify_existing_fixture_workspace(
    seed: &InlineFixtureV1,
    root: &std::path::Path,
) -> Result<(), String> {
    fn visit(
        root: &std::path::Path,
        directory: &std::path::Path,
        expected: &mut BTreeMap<String, String>,
    ) -> Result<(), String> {
        for entry in fs::read_dir(directory).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
            if metadata.file_type().is_symlink() {
                return Err("trial fixture workspace contains a symlink".into());
            }
            let relative = path
                .strip_prefix(root)
                .map_err(|e| e.to_string())?
                .to_str()
                .ok_or("trial workspace path is not UTF-8")?
                .replace(std::path::MAIN_SEPARATOR, "/");
            if relative == ".git" && metadata.is_dir() {
                continue;
            }
            if metadata.is_dir() {
                if !expected
                    .keys()
                    .any(|candidate| candidate.starts_with(&format!("{relative}/")))
                {
                    return Err("trial fixture workspace has an unexpected directory".into());
                }
                visit(root, &path, expected)?;
            } else if metadata.is_file() {
                let Some(contents) = expected.remove(&relative) else {
                    return Err("trial fixture workspace has an unexpected file".into());
                };
                let bytes = read_bounded_file(&path, INLINE_FILE_MAX_BYTES)?;
                if bytes != contents.as_bytes() {
                    return Err(
                        "trial fixture workspace seed content changed before package publication"
                            .into(),
                    );
                }
            } else {
                return Err("trial fixture workspace contains a special file".into());
            }
        }
        Ok(())
    }
    let mut expected = seed.files.clone();
    visit(root, root, &mut expected)?;
    if !expected.is_empty() {
        return Err("trial fixture workspace seed is incomplete".into());
    }
    Ok(())
}

const INLINE_FILE_MAX_BYTES: usize = 1024 * 1024;

impl TrialRunStepPackage {
    pub fn validate(&self) -> Result<(), String> {
        self.capsule.validate()?;
        if self.schema_version != TRIAL_STEP_PACKAGE_SCHEMA_VERSION
            || self.controller_generation == 0
            || self.descriptor.controller_generation != self.controller_generation
            || self.descriptor.project_id != self.project_id
            || self.project_id != self.capsule.project_id
            || self.descriptor.run_id != self.capsule.run_id
            || self.operation_id != *self.capsule.operation_id()
            || self.descriptor.role != self.capsule.role
            || self.descriptor.attempt != u32::from(self.capsule.attempt_ordinal)
            || self.descriptor.run_epoch != 1
            || self.descriptor.profile_digest != self.capsule.profile.profile_digest
            || self.descriptor.instruction_digest != self.capsule.profile.instruction_digest
            || self.descriptor.provider_capability.receipt_digest
                != self.capsule.provider_qualification_digest
            || self.capsule_digest != self.digest_capsule()?
            || self.role_contract.trim().is_empty()
            || self.prompt.trim().is_empty()
            || self.rex_endpoint.trim().is_empty()
            || self.rex_server_identity.trim().is_empty()
            || self.rex_window_id.trim().is_empty()
            || !self.rex_cli_path.is_absolute()
            || !self.environment_handoff_path.is_absolute()
            || self.shutdown_grace_seconds == 0
            || self.shutdown_grace_seconds > 300
            || self.start_ack_timeout_seconds == 0
            || self.start_ack_timeout_seconds > 300
        {
            return Err("trial run-step package is incomplete or not bound to its capsule".into());
        }
        let profile_json = serde_json::to_vec(&self.profile).map_err(|e| e.to_string())?;
        let profile_digest = Digest::parse(format!("{:x}", Sha256::digest(profile_json)))?;
        if profile_digest != self.capsule.profile.profile_digest {
            return Err("trial run-step profile does not match the frozen capsule".into());
        }
        let bytes = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        if bytes.len() > MAX_PACKAGE_BYTES {
            return Err("trial run-step package exceeds its 8 MiB limit".into());
        }
        Ok(())
    }

    pub fn digest_capsule(&self) -> Result<Digest, String> {
        let value = serde_json::to_value(&self.capsule).map_err(|e| e.to_string())?;
        let canonical = serde_json::to_string(&value).map_err(|e| e.to_string())?;
        Digest::parse(format!("{:x}", Sha256::digest(canonical.as_bytes())))
    }

    pub fn digest_package(&self) -> Result<Digest, String> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        Digest::parse(format!("{:x}", Sha256::digest(bytes)))
    }

    /// Publish this package immutably. Retries may observe the same bytes, never replace them.
    pub fn publish_once(&self, path: &std::path::Path) -> Result<Digest, String> {
        self.validate()?;
        let parent = path.parent().ok_or("trial package has no parent")?;
        let metadata = fs::symlink_metadata(parent).map_err(|e| e.to_string())?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err("trial package parent must be a real directory".into());
        }
        let parent = fs::canonicalize(parent).map_err(|e| e.to_string())?;
        if path.parent() != Some(parent.as_path()) {
            return Err("trial package path must use its canonical parent".into());
        }
        let bytes = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        let stage = parent.join(format!(
            ".trial-package-{}-{}.tmp",
            std::process::id(),
            self.capsule.attempt_id
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&stage).map_err(|e| e.to_string())?;
        file.write_all(&bytes).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        drop(file);
        let result = match fs::hard_link(&stage, path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                if read_bounded_file(path, MAX_PACKAGE_BYTES)? == bytes {
                    Ok(())
                } else {
                    Err("trial package already exists with different contents".into())
                }
            }
            Err(error) => Err(error.to_string()),
        };
        let _ = fs::remove_file(stage);
        result?;
        Digest::parse(format!("{:x}", Sha256::digest(bytes)))
    }

    pub fn read(path: &std::path::Path) -> Result<Self, String> {
        let bytes = read_bounded_file(path, MAX_PACKAGE_BYTES)?;
        let package: Self = crate::protocol::parse_unique(&bytes)?;
        package.validate()?;
        Ok(package)
    }

    /// Produce the same finite-turn request used by factory Agents after the
    /// trial wrapper has received the host's exact start acknowledgement.
    pub fn turn_request(
        &self,
        environment: BTreeMap<OsString, OsString>,
    ) -> Result<TurnRequest, String> {
        self.validate()?;
        Ok(TurnRequest {
            descriptor: self.descriptor.clone(),
            profile: self.profile.clone(),
            role_contract: self.role_contract.clone(),
            prompt: self.prompt.clone(),
            environment,
            continuation: None,
            shutdown_grace: Duration::from_secs(self.shutdown_grace_seconds),
        })
    }
}

/// Run the finite provider turn from an immutable trial package. The wrapper
/// confirms its real Rex block and waits for a host acknowledgement before the
/// provider can start. It never opens SQLite or submits factory mailbox effects.
pub fn run_trial_step(
    run_id: &str,
    package_path: &std::path::Path,
    environment_handoff: &std::path::Path,
) -> Result<Digest, String> {
    if std::env::var_os("REX_PROJECTS_CONTEXT").as_deref()
        != Some(std::ffi::OsStr::new("profile_trial"))
        || std::env::var_os("REX_PROJECTS_AGENT").as_deref() != Some(std::ffi::OsStr::new("0"))
    {
        return Err("agent trial-step must run in an isolated profile-trial Rex block".into());
    }
    let package = wait_for_package(package_path)?;
    if package.descriptor.run_id.as_str() != run_id {
        return Err("trial package does not match --run".into());
    }
    if digest_current_exe()? != package.runtime_binary_digest {
        return Err("running rex-projects binary does not match the pinned trial package".into());
    }
    if package.environment_handoff_path != environment_handoff {
        return Err("trial environment handoff path differs from the immutable package".into());
    }
    let session = std::env::var("REX_SESSION").map_err(|_| "Rex block has no session identity")?;
    let block = std::env::var("REX_BLOCK").map_err(|_| "Rex block has no block identity")?;
    if session != package.descriptor.rex_session_id
        || block != package.descriptor.rex_block_id.as_str()
    {
        return Err("Rex trial block differs from the immutable descriptor".into());
    }
    let rex = crate::adapters::rex::RexCliTransport::connect(
        &package.rex_cli_path,
        &package.rex_search_path,
        package.rex_endpoint.clone(),
        package.rex_server_identity.clone(),
        session.clone(),
        std::env::vars_os().collect(),
    )
    .map_err(|error| error.to_string())?;
    let rex_context = rex
        .validate_context_block(&block)
        .map_err(|error| error.to_string())?;
    if rex_context.server_instance_id != package.rex_server_identity
        || rex_context.session_id != session
        || rex_context.window_id != package.rex_window_id
    {
        return Err("Rex trial block is outside the pinned Project Supervisor window".into());
    }

    let spool = TrialStepSpool::open(&package.descriptor.control_dir)?;
    let request = TrialStepStartRequest {
        schema_version: 1,
        capsule_digest: package.capsule_digest.clone(),
        operation_id: package.operation_id.clone(),
        run_id: package.descriptor.run_id.clone(),
        project_id: package.project_id.clone(),
        controller_generation: package.controller_generation,
        descriptor_digest: package.digest_package()?,
        runtime_binary_digest: package.runtime_binary_digest.clone(),
        qualification_receipt_digest: package.capsule.provider_qualification_digest.clone(),
        wrapper_pid: std::process::id(),
        wrapper_start_identity: current_process_start_identity()?,
        rex_server_identity: rex_context.server_instance_id,
        rex_session_id: rex_context.session_id,
        rex_window_id: rex_context.window_id,
        rex_block_id: rex_context.block_id,
    };
    let request = spool.publish_start_once(request)?;
    spool.wait_start_receipt(
        &request,
        Duration::from_secs(package.start_ack_timeout_seconds),
    )?;

    let mut environment = crate::environment::EnvironmentHandoff::consume_file(
        environment_handoff,
        &package.descriptor.environment_snapshot_id,
        package.operation_id.as_str(),
    )
    .map_err(|error| error.to_string())?;
    environment.insert(OsString::from("REX_SESSION"), OsString::from(&session));
    environment.insert(OsString::from("REX_BLOCK"), OsString::from(&block));
    environment.insert(OsString::from("REX_BLOCK_ID"), OsString::from(&block));
    let turn = package.turn_request(environment)?;
    let result =
        crate::run_step::run_profile_trial_turn(&turn, &mut crate::run_step::SystemProcessObserver)
            .map_err(|error| error.to_string())?;
    let result_digest = publish_turn_result(&spool, &request, result)?;
    Ok(result_digest)
}

fn publish_turn_result(
    spool: &TrialStepSpool,
    request: &TrialStepStartRequest,
    result: TurnResult,
) -> Result<Digest, String> {
    let mut envelope = TrialStepResult {
        schema_version: 1,
        request_digest: digest_json(request)?,
        receipt: result.receipt,
        structured_result: result.structured_result,
        result_digest: Digest::parse("0".repeat(64))?,
    };
    envelope.result_digest = digest_result_payload(&envelope)?;
    spool.publish_result_once(&envelope)?;
    Ok(envelope.result_digest)
}

fn wait_for_package(path: &std::path::Path) -> Result<TrialRunStepPackage, String> {
    let deadline = std::time::Instant::now() + Duration::from_secs(300);
    loop {
        match TrialRunStepPackage::read(path) {
            Ok(package) => return Ok(package),
            Err(error) if error.contains("No such file") || error.contains("not found") => {}
            Err(error) => return Err(error),
        }
        if std::time::Instant::now() >= deadline {
            return Err("timed out waiting for immutable trial package".into());
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn digest_current_exe() -> Result<Digest, String> {
    let path = std::env::current_exe().map_err(|e| e.to_string())?;
    let mut file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(|e| e.to_string())?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Digest::parse(format!("{:x}", hasher.finalize()))
}

fn current_process_start_identity() -> Result<String, String> {
    let table = crate::process::inspect_process_table().map_err(|e| e.to_string())?;
    table
        .into_iter()
        .find(|process| process.pid == std::process::id())
        .map(|process| process.start_identity)
        .ok_or_else(|| "cannot observe trial wrapper process birth identity".into())
}

fn read_bounded_file(path: &std::path::Path, limit: usize) -> Result<Vec<u8>, String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(|e| e.to_string())?;
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    if !metadata.is_file() || metadata.len() as usize > limit {
        return Err("trial package must be a bounded regular file".into());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > limit {
        return Err("trial package exceeds its byte limit".into());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::{
        TrialStepResult, TrialStepSpool, TrialStepStartReceipt, TrialStepStartRequest,
        materialize_fixture_workspace,
    };
    use crate::domain::ids::{AgentRunId, Digest, OperationId, ProjectId};
    use crate::domain::types::AgentAdapter;
    use crate::learning_trials::InlineFixtureV1;
    use crate::providers::ProviderSchemaProjectionIdentity;
    use crate::run_step::{CleanupState, RunReceipt, TurnOutcome};
    use std::collections::BTreeMap;
    use std::fs;

    fn digest(byte: char) -> Digest {
        Digest::parse(byte.to_string().repeat(64)).unwrap()
    }

    fn request() -> TrialStepStartRequest {
        TrialStepStartRequest {
            schema_version: 1,
            capsule_digest: digest('a'),
            operation_id: OperationId::parse("trial-operation-1").unwrap(),
            run_id: AgentRunId::parse("trial-run-1").unwrap(),
            project_id: ProjectId::parse("project-a").unwrap(),
            controller_generation: 2,
            descriptor_digest: digest('b'),
            runtime_binary_digest: digest('c'),
            qualification_receipt_digest: digest('d'),
            wrapper_pid: 1234,
            wrapper_start_identity: "birth:1234:7".into(),
            rex_server_identity: "server-1".into(),
            rex_session_id: "session-1".into(),
            rex_window_id: "window-1".into(),
            rex_block_id: "block-1".into(),
        }
    }

    #[test]
    fn fixture_materialization_is_private_exact_and_idempotent() {
        let seed = InlineFixtureV1 {
            schema_version: 1,
            files: BTreeMap::from([
                ("cases/input.json".into(), "{\"value\":1}\n".into()),
                ("src/main.rs".into(), "fn main() {}\n".into()),
            ]),
        };
        let temporary = tempfile::tempdir().unwrap();
        let workspace = temporary.path().join("private-trial");
        let approved_digest = seed.digest().unwrap();

        materialize_fixture_workspace(&seed, &approved_digest, &workspace).unwrap();
        assert_eq!(
            fs::read_to_string(workspace.join("cases/input.json")).unwrap(),
            "{\"value\":1}\n"
        );
        materialize_fixture_workspace(&seed, &approved_digest, &workspace).unwrap();

        fs::write(workspace.join("src/main.rs"), "changed\n").unwrap();
        assert!(materialize_fixture_workspace(&seed, &approved_digest, &workspace).is_err());

        let wrong_digest = digest('f');
        let absent = temporary.path().join("must-not-exist");
        assert!(materialize_fixture_workspace(&seed, &wrong_digest, &absent).is_err());
        assert!(!absent.exists());
    }

    #[test]
    fn trial_spool_replays_identical_start_and_result_but_rejects_conflicts() {
        let temporary = tempfile::tempdir().unwrap();
        let spool = TrialStepSpool::open(temporary.path()).unwrap();
        let start = request();
        spool.publish_start_once(start.clone()).unwrap();
        spool.publish_start_once(start.clone()).unwrap();
        assert_eq!(spool.read_start_request().unwrap().run_id, start.run_id);

        let mut changed_start = start.clone();
        changed_start.rex_block_id = "different-block".into();
        assert!(spool.publish_start_once(changed_start).is_err());

        let receipt = TrialStepStartReceipt {
            schema_version: 1,
            request_digest: super::digest_json(&start).unwrap(),
            capsule_digest: start.capsule_digest.clone(),
            operation_id: start.operation_id.clone(),
            run_id: start.run_id.clone(),
            controller_generation: start.controller_generation,
            accepted: true,
        };
        spool.publish_start_receipt(&start, receipt).unwrap();
        assert!(
            spool
                .wait_start_receipt(&start, std::time::Duration::ZERO)
                .is_ok()
        );

        let mut run_receipt = RunReceipt {
            run_id: start.run_id.clone(),
            attempt: 1,
            provider: AgentAdapter::Codex,
            effective_permission_mode: "read-only".into(),
            conversation_id: None,
            provider_version: Some("fixture".into()),
            capability_receipt_digest: Some(digest('d')),
            schema_projection: ProviderSchemaProjectionIdentity {
                source_schema_digest: digest('e'),
                provider_schema_digest: digest('f'),
                transform_version: "test".into(),
                unsupported_keywords: vec![],
            },
            launch_pid_hint: Some(start.wrapper_pid),
            exit_code: Some(0),
            timed_out: false,
            cancellation_signal: None,
            cleanup: CleanupState::Confirmed,
            cleanup_detail: None,
            processes: vec![],
            result_digest: Some(digest('1')),
            provider_result_failure: None,
            provider_process_failure: None,
            outcome: TurnOutcome::Completed,
        };
        let mut result = TrialStepResult {
            schema_version: 1,
            request_digest: super::digest_json(&start).unwrap(),
            receipt: run_receipt.clone(),
            structured_result: Some(serde_json::json!({"accepted": true})),
            result_digest: digest('0'),
        };
        result.result_digest = super::digest_result_payload(&result).unwrap();
        spool.publish_result_once(&result).unwrap();
        spool.publish_result_once(&result).unwrap();
        let replayed = spool.read_result().unwrap();
        assert_eq!(replayed.result_digest, result.result_digest);
        assert_eq!(replayed.structured_result, result.structured_result);

        run_receipt.exit_code = Some(1);
        let mut conflict = result;
        conflict.receipt = run_receipt;
        conflict.result_digest = super::digest_result_payload(&conflict).unwrap();
        assert!(spool.publish_result_once(&conflict).is_err());
    }
}
