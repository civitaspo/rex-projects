//! Immutable, host-generated input package for the finite Rex-block `agent run-step` wrapper.

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
