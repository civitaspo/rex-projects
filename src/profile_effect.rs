//! Durable, replay-safe publication of human-approved profile packages.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::domain::ids::{Digest, OperationId};
use crate::learning::{ProfilePublicationReceipt, publish_approved_profile_package};
use crate::store::{ConfigStore, EffectIntent};

#[derive(Clone, Debug)]
pub struct ProfileEffectHandler {
    declarative_root: PathBuf,
}

#[derive(Deserialize, Serialize)]
struct ProfileEffectPayload {
    operation_id: OperationId,
    manifest_digest: Digest,
}

impl ProfileEffectHandler {
    pub fn new(declarative_root: PathBuf) -> Self {
        Self { declarative_root }
    }

    /// Publish once, then replay the database receipt if the dispatcher retries
    /// after publication completed but before its generic outbox receipt commit.
    pub fn execute(
        &self,
        store: &mut ConfigStore,
        generation: u64,
        effect: &EffectIntent,
    ) -> Result<ProfilePublicationReceipt, String> {
        if effect.kind != "publish_profile" || effect.subject_type != "project" {
            return Err("effect is not a profile publication for a project".into());
        }
        let value: serde_json::Value =
            crate::protocol::parse_unique(effect.request_json.as_bytes())?;
        let canonical = serde_json::to_string(&value).map_err(|e| e.to_string())?;
        let payload: ProfileEffectPayload =
            serde_json::from_value(value).map_err(|e| e.to_string())?;
        let actual_digest = format!("{:x}", Sha256::digest(effect.request_json.as_bytes()));
        if canonical != effect.request_json
            || actual_digest != effect.request_digest
            || payload.operation_id.as_str() != effect.operation_id
        {
            return Err("profile effect payload is not canonical or bound to its operation".into());
        }
        let intent = store
            .profile_promotion_intent(&payload.operation_id)?
            .ok_or("profile effect has no durable promotion intent")?;
        if intent.project_id.as_str() != effect.subject_id
            || intent.project_id != effect.project_id
            || intent.manifest_digest != payload.manifest_digest
        {
            return Err("profile effect does not match its durable promotion subject".into());
        }
        if let Some(receipt) = store.profile_publication_receipt(&payload.operation_id)? {
            return Ok(receipt);
        }
        // The outbox intent is created by this transition. On dispatcher replay
        // the durable promotion is already publication_pending, so false means
        // “prepared earlier”; a missing receipt still requires reconciliation.
        store.begin_profile_publication(generation, &payload.operation_id)?;
        let config_file = PathBuf::from(&intent.config_file);
        if !config_file.is_absolute() {
            return Err("profile configuration source must be an absolute path".into());
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system clock is before the Unix epoch")?
            .as_secs();
        let package = store.load_approved_profile_package(&intent, now)?;
        let receipt = publish_approved_profile_package(
            &self.declarative_root,
            &config_file,
            &intent.expected_config_revision,
            &package,
        )
        .map_err(|e| e.to_string())?;
        store.record_profile_publication(generation, &payload.operation_id, &receipt)?;
        store
            .profile_publication_receipt(&payload.operation_id)?
            .ok_or_else(|| "profile publication receipt was not persisted".into())
    }
}
