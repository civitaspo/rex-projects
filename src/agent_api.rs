//! Host-authored Agent wake input snapshot models.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::domain::ids::{ArtifactId, Digest, ProjectId};
use crate::engine::orchestration::RoleArtifactKind;

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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub host_artifacts: Vec<HostArtifactLocator>,
}

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
    fn validate(&self) -> Result<(), String> {
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
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1
            || self.role_session_id.trim().is_empty()
            || self.role_session_id.chars().any(char::is_control)
            || self.agent_run_id.trim().is_empty()
        {
            return Err("unsupported or incomplete Agent inbox snapshot".into());
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
            if item.host_artifacts.len() > 256 {
                return Err("Agent inbox item exceeds the 256 artifact limit".into());
            }
            artifact_count += item.host_artifacts.len();
            if !item.host_artifacts.is_empty() && item.source_type != "agent_result" {
                return Err("host artifact locators must accompany an Agent result wake".into());
            }
            let mut seen_artifacts = std::collections::BTreeSet::new();
            for artifact in &item.host_artifacts {
                artifact.validate()?;
                if artifact.source_evidence_id != item.source_id
                    || !seen_artifacts.insert(artifact.artifact_id.as_str())
                {
                    return Err(
                        "host artifact locator source or identity differs from its wake".into(),
                    );
                }
                artifact_bytes = artifact_bytes
                    .checked_add(artifact.bytes)
                    .ok_or("Agent inbox artifact byte count overflow")?;
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
        let bytes = serde_json::to_vec(&(
            self.schema_version,
            &self.project_id,
            &self.role_session_id,
            &self.agent_run_id,
            &self.inputs,
        ))
        .map_err(|error| error.to_string())?;
        Digest::parse(format!("{:x}", Sha256::digest(bytes)))
    }
}

#[cfg(test)]
mod tests {
    use super::AgentWakeSnapshot;
    use crate::domain::ids::{Digest, ProjectId};

    #[test]
    fn wake_snapshot_rejects_control_characters_in_role_session_id() {
        let snapshot = AgentWakeSnapshot {
            schema_version: 1,
            project_id: ProjectId::parse("project-a").unwrap(),
            role_session_id: "supervisor\n".into(),
            agent_run_id: "run-1".into(),
            digest: Digest::parse("0".repeat(64)).unwrap(),
            inputs: Vec::new(),
        };
        assert!(snapshot.validate().unwrap_err().contains("incomplete"));
    }
}
