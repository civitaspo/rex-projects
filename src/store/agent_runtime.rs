//! Host-side queries and state transitions for finite role Agent turns.

use serde::{Deserialize, Serialize};

use crate::domain::ids::{Digest, ProjectId};

const MAX_WAKE_SNAPSHOT_ITEMS: usize = 256;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PendingRoleWakeInput {
    pub wake_input_id: u64,
    pub source_type: String,
    pub source_id: String,
    pub source_revision: u64,
    pub priority: i32,
    pub payload_json: serde_json::Value,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LaunchPreparationOutcome {
    Prepared { reservation_digest: Digest },
    CapacityUnavailable,
}

impl ConfigStore {
    /// Read an ordered candidate snapshot for a scheduler. This is advisory only: the launch
    /// preparation transaction must recheck and claim these exact IDs before creating a run.
    pub fn pending_role_wake_inputs(
        &self,
        project_id: &ProjectId,
        role_session_id: &str,
        limit: usize,
    ) -> Result<Vec<PendingRoleWakeInput>, String> {
        if role_session_id.trim().is_empty() || role_session_id.chars().any(char::is_control) {
            return Err("role session ID is empty or contains control characters".into());
        }
        if limit == 0 || limit > MAX_WAKE_SNAPSHOT_ITEMS {
            return Err(format!(
                "wake snapshot limit must be between 1 and {MAX_WAKE_SNAPSHOT_ITEMS}"
            ));
        }
        let mut statement = self
            .connection
            .prepare(
                "SELECT wake_input_id,source_type,source_id,source_revision,priority,payload_json \
                 FROM role_wake_inputs WHERE project_id=?1 AND role_session_id=?2 AND lifecycle='pending' \
                 ORDER BY priority DESC,wake_input_id ASC LIMIT ?3",
            )
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(
                rusqlite::params![project_id.as_str(), role_session_id, limit as u64],
                |row| {
                    Ok((
                        row.get::<_, u64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, u64>(3)?,
                        row.get::<_, i32>(4)?,
                        row.get::<_, String>(5)?,
                    ))
                },
            )
            .map_err(|error| error.to_string())?;
        let mut inputs = Vec::new();
        for row in rows {
            let (id, source_type, source_id, revision, priority, payload) =
                row.map_err(|error| error.to_string())?;
            let payload_json = crate::protocol::parse_unique(payload.as_bytes())
                .map_err(|error| format!("stored wake input {id} has invalid JSON: {error}"))?;
            inputs.push(PendingRoleWakeInput {
                wake_input_id: id,
                source_type,
                source_id,
                source_revision: revision,
                priority,
                payload_json,
            });
        }
        Ok(inputs)
    }
}

use super::ConfigStore;
