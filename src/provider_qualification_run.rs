//! Finite Rex-block wrapper used only to bootstrap provider qualification.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::adapters::rex::{RexCliTransport, RexQualificationSessionReceipt};
use crate::config::Profile;
use crate::domain::ids::{Digest, ProjectId};
use crate::domain::types::Role;
use crate::environment::EnvironmentHandoff;
use crate::run_step::{
    CleanupState, DisposableQualificationContext, ProviderQualificationStatus, RunDescriptor,
    RunReceipt, SystemProcessObserver, TurnOutcome, TurnRequest, issue_qualification_permit,
    run_qualification_turn,
};

const MAX_PACKAGE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_RESULT_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct QualificationRunPackage {
    pub schema_version: u32,
    pub request_id: String,
    pub project_id: ProjectId,
    pub role: Role,
    pub profile_id: crate::domain::ids::ProfileId,
    pub profile_digest: Digest,
    pub environment_snapshot_id: Digest,
    pub profile: Profile,
    pub descriptor: RunDescriptor,
    pub role_contract: String,
    pub prompt: String,
    pub workspace_root: PathBuf,
    pub environment_handoff: PathBuf,
    pub environment_operation_id: String,
    pub result_path: PathBuf,
    pub rex_cli_path: PathBuf,
    pub rex_search_path: Vec<PathBuf>,
    pub rex_receipt: RexQualificationSessionReceipt,
    pub deadline_seconds: u64,
    pub shutdown_grace_seconds: u64,
}

impl QualificationRunPackage {
    pub(crate) fn publish_once(&self, path: &Path) -> Result<(), String> {
        let parent = path.parent().ok_or("qualification package has no parent")?;
        if !parent.is_dir()
            || fs::canonicalize(parent).map_err(|error| error.to_string())? != parent
        {
            return Err("qualification package parent is not a canonical directory".into());
        }
        let bytes = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        if bytes.len() as u64 > MAX_PACKAGE_BYTES {
            return Err("qualification package exceeds its size limit".into());
        }
        let stage = parent.join(format!(".qualification-{}.tmp", std::process::id()));
        #[cfg(unix)]
        let mut file = {
            use std::os::unix::fs::OpenOptionsExt;
            OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&stage)
                .map_err(|error| error.to_string())?
        };
        #[cfg(not(unix))]
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&stage)
            .map_err(|error| error.to_string())?;
        file.write_all(&bytes).map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
        drop(file);
        let publish = fs::hard_link(&stage, path).map_err(|error| error.to_string());
        let _ = fs::remove_file(stage);
        publish
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct QualificationRunResult {
    pub schema_version: u32,
    pub request_id: String,
    pub receipt: RunReceipt,
    pub structured_result: Option<serde_json::Value>,
    pub result_digest: Digest,
}

pub(crate) fn run_wrapper(package_path: &Path) -> Result<Digest, String> {
    if std::env::var("REX_PROJECTS_AGENT").as_deref() != Ok("1")
        || std::env::var("REX_PROJECTS_CONTEXT").as_deref() != Ok("agent")
    {
        return Err("provider qualification wrapper requires a marked Rex Agent block".into());
    }
    let bytes = read_package_wait(package_path)?;
    let package: QualificationRunPackage = crate::protocol::parse_unique(&bytes)
        .map_err(|error| format!("qualification package is invalid: {error}"))?;
    validate_package(&package, package_path)?;
    let mut environment = EnvironmentHandoff::consume_file(
        &package.environment_handoff,
        &package.environment_snapshot_id,
        &package.environment_operation_id,
    )
    .map_err(|error| error.to_string())?;
    set_agent_markers(&mut environment, &package);
    let rex = RexCliTransport::connect(
        &package.rex_cli_path,
        &package.rex_search_path,
        package.rex_receipt.endpoint().to_owned(),
        package.rex_receipt.instance_id().to_owned(),
        package.rex_receipt.session_id().to_owned(),
        environment.clone(),
    )
    .map_err(|error| error.to_string())?;
    let fixture = rex
        .disposable_qualification_fixture(package.rex_receipt.clone())
        .map_err(|error| error.to_string())?;
    let expected_permission_mode = package
        .descriptor
        .provider_capability
        .permission_mode
        .clone();
    let request = TurnRequest {
        descriptor: package.descriptor,
        profile: package.profile,
        role_contract: package.role_contract,
        prompt: package.prompt,
        environment,
        continuation: None,
        shutdown_grace: Duration::from_secs(package.shutdown_grace_seconds),
    };
    let permit = issue_qualification_permit(
        &request,
        DisposableQualificationContext {
            workspace_root: package.workspace_root.clone(),
            rex_fixture: fixture,
            deadline: Duration::from_secs(package.deadline_seconds),
            expected_permission_mode,
            prompts_denied: true,
        },
    )
    .map_err(|error| error.to_string())?;
    let turn = run_qualification_turn(&request, permit, &mut SystemProcessObserver)
        .map_err(|error| error.to_string())?;
    let result_bytes =
        serde_json::to_vec(&turn.structured_result).map_err(|error| error.to_string())?;
    let result = QualificationRunResult {
        schema_version: 1,
        request_id: package.request_id,
        receipt: turn.receipt,
        structured_result: turn.structured_result,
        result_digest: digest(&result_bytes)?,
    };
    publish_result(&package.result_path, &result)?;
    Ok(result.result_digest)
}

fn read_package_wait(path: &Path) -> Result<Vec<u8>, String> {
    let deadline = std::time::Instant::now() + Duration::from_secs(300);
    loop {
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                if !metadata.is_file()
                    || metadata.file_type().is_symlink()
                    || metadata.len() > MAX_PACKAGE_BYTES
                {
                    return Err("qualification package must be a bounded regular file".into());
                }
                #[cfg(unix)]
                let file = {
                    use std::os::unix::fs::OpenOptionsExt;
                    OpenOptions::new()
                        .read(true)
                        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
                        .open(path)
                        .map_err(|error| error.to_string())?
                };
                #[cfg(not(unix))]
                let mut file = OpenOptions::new()
                    .read(true)
                    .open(path)
                    .map_err(|error| error.to_string())?;
                let mut bytes = Vec::with_capacity(metadata.len() as usize);
                file.take(MAX_PACKAGE_BYTES + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|error| error.to_string())?;
                if bytes.len() as u64 > MAX_PACKAGE_BYTES {
                    return Err("qualification package exceeds its size limit".into());
                }
                return Ok(bytes);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.to_string()),
        }
        if std::time::Instant::now() >= deadline {
            return Err("qualification package was not published before its deadline".into());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn validate_package(package: &QualificationRunPackage, path: &Path) -> Result<(), String> {
    let parent = path.parent().ok_or("qualification package has no parent")?;
    if package.schema_version != 1
        || !parent.is_dir()
        || fs::canonicalize(parent).map_err(|error| error.to_string())? != parent
        || package.request_id.is_empty()
        || package.descriptor.project_id != package.project_id
        || package.descriptor.role != package.role
        || package.descriptor.profile_digest != package.profile_digest
        || package.descriptor.environment_snapshot_id != package.environment_snapshot_id
        || package.descriptor.provider_capability.status != ProviderQualificationStatus::Unknown
        || package.descriptor.rex_session_id != package.rex_receipt.session_id()
        || package.descriptor.rex_block_id.as_str() != package.rex_receipt.block_id()
        || package.result_path.parent() != Some(package.descriptor.control_dir.as_path())
        || package.deadline_seconds == 0
        || package.deadline_seconds > 1800
        || package.shutdown_grace_seconds == 0
        || package.shutdown_grace_seconds > 300
        || !package.rex_cli_path.is_absolute()
    {
        return Err("qualification package identity or bounds are invalid".into());
    }
    let profile_digest =
        digest(&serde_json::to_vec(&package.profile).map_err(|error| error.to_string())?)?;
    if profile_digest != package.profile_digest {
        return Err("qualification package profile digest mismatch".into());
    }
    Ok(())
}

fn set_agent_markers(
    environment: &mut BTreeMap<OsString, OsString>,
    package: &QualificationRunPackage,
) {
    environment.insert("REX_PROJECTS_CONTEXT".into(), "agent".into());
    environment.insert("REX_PROJECTS_AGENT".into(), "1".into());
    environment.insert(
        "REX_PROJECTS_PROJECT_ID".into(),
        package.project_id.as_str().into(),
    );
    environment.insert(
        "REX_PROJECTS_ROLE".into(),
        format!("{:?}", package.role).to_lowercase().into(),
    );
    environment.insert(
        "REX_PROJECTS_RUN_ID".into(),
        package.descriptor.run_id.as_str().into(),
    );
    environment.insert(
        "REX_SESSION".into(),
        package.rex_receipt.session_id().into(),
    );
    environment.insert("REX_BLOCK".into(), package.rex_receipt.block_id().into());
    environment.insert("REX_BLOCK_ID".into(), package.rex_receipt.block_id().into());
}

fn digest(bytes: &[u8]) -> Result<Digest, String> {
    Digest::parse(format!("{:x}", Sha256::digest(bytes)))
}

#[allow(dead_code)]
fn publish_result(path: &Path, result: &QualificationRunResult) -> Result<(), String> {
    let bytes = serde_json::to_vec(result).map_err(|error| error.to_string())?;
    if bytes.len() > MAX_RESULT_BYTES {
        return Err("qualification result exceeds its size limit".into());
    }
    let parent = path.parent().ok_or("qualification result has no parent")?;
    let temporary = parent.join(format!(".qualification-{}.tmp", std::process::id()));
    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|error| error.to_string())?
    };
    #[cfg(not(unix))]
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .map_err(|error| error.to_string())?;
    file.write_all(&bytes).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())?;
    drop(file);
    fs::hard_link(&temporary, path).map_err(|error| error.to_string())?;
    fs::remove_file(temporary).map_err(|error| error.to_string())?;
    Ok(())
}

pub(crate) fn receipt_outcome_succeeded(receipt: &RunReceipt) -> bool {
    matches!(receipt.outcome, TurnOutcome::Completed)
        && matches!(receipt.cleanup, CleanupState::Confirmed)
        && !receipt.processes.is_empty()
        && receipt.provider_version.is_none()
        && receipt.capability_receipt_digest.is_none()
}
