//! Immutable, host-generated input package for the finite Rex-block `agent run-step` wrapper.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use sha2::Digest as _;

use crate::config::Profile;
use crate::domain::ids::{Digest, OperationId, ProjectId};
use crate::domain::types::AgentAdapter;
use crate::run_step::RunDescriptor;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunStepPackage {
    pub schema_version: u32,
    pub descriptor: RunDescriptor,
    pub operation_id: OperationId,
    pub project_id: ProjectId,
    pub controller_generation: u64,
    pub runtime_binary_digest: Digest,
    pub qualification_receipt_digest: Digest,
    pub rex_cli_path: PathBuf,
    pub rex_search_path: Vec<PathBuf>,
    pub rex_endpoint: String,
    pub rex_server_identity: String,
    pub rex_window_id: String,
    pub profile: Profile,
    pub role_contract: String,
    pub prompt: String,
    #[serde(default)]
    pub continuation: Option<RunStepContinuation>,
    pub shutdown_grace_seconds: u64,
    pub start_ack_timeout_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunStepContinuation {
    pub provider: AgentAdapter,
    pub conversation_id: String,
    pub profile_digest: Digest,
    pub instruction_digest: Digest,
    pub workspace: PathBuf,
}

impl RunStepPackage {
    /// Atomically publish a host-built package exactly once. The parked Rex wrapper treats
    /// absence as a wait state; a crash before link leaves only a private staging file.
    pub fn publish_once(&self, path: &std::path::Path) -> Result<Digest, String> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        if bytes.len() > 8 * 1024 * 1024 {
            return Err("run-step package exceeds the 8 MiB limit".into());
        }
        let parent = path
            .parent()
            .ok_or("run-step package has no parent directory")?;
        let metadata = fs::symlink_metadata(parent).map_err(|error| error.to_string())?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err("run-step package parent must be a real directory".into());
        }
        let parent = fs::canonicalize(parent).map_err(|error| error.to_string())?;
        if path.parent() != Some(parent.as_path()) {
            return Err("run-step package path must use its canonical parent".into());
        }
        let nonce = format!(
            "{}-{:x}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| "system clock is before Unix epoch")?
                .as_nanos()
        );
        let stage = parent.join(format!(".run-step-{nonce}.tmp"));
        let _stage_cleanup = StagedFile(stage.clone());
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&stage)
            .map_err(|error| format!("create staged run-step package: {error}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|error| error.to_string())?;
        }
        file.write_all(&bytes).map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
        drop(file);
        let result = match fs::hard_link(&stage, path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                #[cfg(unix)]
                let existing_file = {
                    use std::os::unix::fs::OpenOptionsExt;
                    OpenOptions::new()
                        .read(true)
                        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
                        .open(path)
                        .map_err(|error| format!("read existing run-step package: {error}"))?
                };
                #[cfg(not(unix))]
                let existing_file = OpenOptions::new()
                    .read(true)
                    .open(path)
                    .map_err(|error| format!("read existing run-step package: {error}"))?;
                let metadata = existing_file
                    .metadata()
                    .map_err(|error| error.to_string())?;
                if !metadata.is_file() || metadata.len() > 8 * 1024 * 1024 {
                    return Err("existing run-step package is not a bounded regular file".into());
                }
                let mut existing = Vec::with_capacity(metadata.len() as usize);
                existing_file
                    .take(8 * 1024 * 1024 + 1)
                    .read_to_end(&mut existing)
                    .map_err(|error| error.to_string())?;
                if existing == bytes {
                    Ok(())
                } else {
                    Err("run-step package already exists with different contents".into())
                }
            }
            Err(error) => Err(format!("publish run-step package: {error}")),
        };
        result?;
        fs::remove_file(&stage)
            .map_err(|error| format!("remove staged run-step package: {error}"))?;
        #[cfg(unix)]
        OpenOptions::new()
            .read(true)
            .open(&parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("sync run-step package directory: {error}"))?;
        Digest::parse(format!("{:x}", sha2::Sha256::digest(&bytes)))
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1 || self.controller_generation == 0 {
            return Err("unsupported or incomplete run-step package".into());
        }
        if self.descriptor.run_id.as_str().is_empty()
            || self.descriptor.project_id != self.project_id
            || self.descriptor.controller_generation != self.controller_generation
            || self.descriptor.workspace.as_os_str().is_empty()
            || self.descriptor.control_dir.as_os_str().is_empty()
            || !self.descriptor.workspace.is_absolute()
            || !self.descriptor.control_dir.is_absolute()
            || !self.rex_cli_path.is_absolute()
            || self.rex_endpoint.trim().is_empty()
            || self.rex_server_identity.trim().is_empty()
            || self.rex_window_id.trim().is_empty()
            || self.start_ack_timeout_seconds == 0
            || self.start_ack_timeout_seconds > 300
            || self.shutdown_grace_seconds == 0
            || self.shutdown_grace_seconds > 300
        {
            return Err("run-step package identity or timeout is invalid".into());
        }
        let profile_digest = Digest::parse(format!(
            "{:x}",
            sha2::Sha256::digest(
                serde_json::to_vec(&self.profile).map_err(|error| error.to_string())?
            )
        ))?;
        if profile_digest != self.descriptor.profile_digest {
            return Err("run-step profile does not match the descriptor digest".into());
        }
        Ok(())
    }
}

struct StagedFile(PathBuf);

impl Drop for StagedFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::RunStepPackage;
    use crate::config::Profile;
    use crate::domain::ids::{AgentRunId, Digest, ProjectId, RexBlockId};
    use crate::domain::types::{AgentAdapter, CommitMode, Role};
    use crate::run_step::{ProviderCapabilityEvidence, ProviderQualificationStatus, RunDescriptor};
    use sha2::Digest as _;

    fn digest(ch: char) -> Digest {
        Digest::parse(ch.to_string().repeat(64)).unwrap()
    }

    fn package() -> RunStepPackage {
        let profile: Profile = serde_json::from_value(serde_json::json!({
            "adapter":"codex", "command":["/bin/codex"], "model":"fixture",
            "commit_mode":"native", "turn_timeout_seconds":60
        }))
        .unwrap();
        let profile_digest = Digest::parse(format!(
            "{:x}",
            sha2::Sha256::digest(serde_json::to_vec(&profile).unwrap())
        ))
        .unwrap();
        RunStepPackage {
            schema_version: 1,
            descriptor: RunDescriptor {
                schema_version: 1,
                project_id: ProjectId::parse("project-a").unwrap(),
                run_id: AgentRunId::parse("run-a").unwrap(),
                role: Role::Supervisor,
                ticket_run_id: None,
                attempt: 1,
                run_epoch: 1,
                controller_generation: 1,
                workspace: "/tmp/workspace".into(),
                control_dir: "/tmp/control".into(),
                rex_session_id: "session".into(),
                rex_block_id: RexBlockId::parse("block").unwrap(),
                profile_digest: profile_digest.clone(),
                instruction_digest: digest('a'),
                plan_digest: None,
                environment_snapshot_id: digest('b'),
                wake_snapshot_digest: digest('c'),
                provider_capability: ProviderCapabilityEvidence {
                    schema_version: 1,
                    adapter: AgentAdapter::Codex,
                    profile_digest,
                    version: "fixture-1".into(),
                    executable_path: "/bin/codex".into(),
                    schema_projection: crate::providers::project_result_schema(
                        &serde_json::json!({"type":"object"}),
                    )
                    .unwrap()
                    .identity,
                    executable_digest: digest('d'),
                    permission_mode: "workspace_write".into(),
                    invocation_options_digest: digest('e'),
                    commit_mode: CommitMode::Native,
                    schema_projection: crate::providers::project_result_schema(
                        &serde_json::json!({"type":"object"}),
                    )
                    .unwrap()
                    .identity,
                    receipt_digest: digest('f'),
                    status: ProviderQualificationStatus::Verified,
                },
                result_schema: serde_json::json!({"type":"object"}),
            },
            operation_id: crate::domain::ids::OperationId::parse("operation-a").unwrap(),
            project_id: ProjectId::parse("project-a").unwrap(),
            controller_generation: 1,
            runtime_binary_digest: digest('1'),
            qualification_receipt_digest: digest('f'),
            rex_cli_path: "/bin/rex".into(),
            rex_search_path: vec!["/bin".into()],
            rex_endpoint: "unix:///tmp/rex.sock".into(),
            rex_server_identity: "rex-instance".into(),
            rex_window_id: "window".into(),
            profile,
            role_contract: "contract".into(),
            prompt: "prompt".into(),
            continuation: None,
            shutdown_grace_seconds: 5,
            start_ack_timeout_seconds: 30,
        }
    }

    #[test]
    fn package_is_published_once_and_conflicting_replay_is_rejected() {
        let root = tempfile::tempdir().unwrap();
        let path = std::fs::canonicalize(root.path())
            .unwrap()
            .join("package.json");
        let package = package();
        let first = package.publish_once(&path).unwrap();
        let second = package.publish_once(&path).unwrap();
        assert_eq!(first, second);
        assert_eq!(
            first,
            Digest::parse(format!(
                "{:x}",
                sha2::Sha256::digest(std::fs::read(&path).unwrap())
            ))
            .unwrap()
        );
        std::fs::write(&path, b"tampered").unwrap();
        assert!(package.publish_once(&path).is_err());
    }
}
