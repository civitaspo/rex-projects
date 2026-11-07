//! Host-side adapter for the durable `publish_knowledge` effect.
//!
//! The factory controller constructs this handler with the configured knowledge
//! root. It consumes only the SQLite intent for the claimed operation. If the
//! filesystem publication and durable receipt committed before the outbox receipt,
//! retries replay that exact terminal receipt without rerunning the publication.

use std::path::PathBuf;

use sha2::{Digest as _, Sha256};

use crate::domain::ids::OperationId;
use crate::knowledge::{PostmortemInput, publish_postmortem};
use crate::store::{ConfigStore, EffectIntent, KnowledgePublicationReceipt};

pub struct KnowledgeEffectHandler {
    root: PathBuf,
}

impl KnowledgeEffectHandler {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn execute(
        &self,
        store: &mut ConfigStore,
        owner_generation: u64,
        effect: &EffectIntent,
    ) -> Result<KnowledgePublicationReceipt, String> {
        if effect.kind != "publish_knowledge" || effect.subject_type != "ticket_run" {
            return Err("effect is not a publish_knowledge ticket-run operation".into());
        }
        let operation_id = OperationId::parse(effect.operation_id.clone())?;
        let intent = store
            .knowledge_publication_intent(&operation_id)?
            .ok_or("knowledge publication intent is missing")?;
        if effect.project_id != intent.project_id
            || effect.subject_id != intent.ticket_run_id.as_str()
        {
            return Err("outbox effect does not match the durable knowledge intent".into());
        }
        let expected_payload = serde_json::json!({
            "operation_id": operation_id.as_str(),
            "request_digest": intent.request_digest.as_str(),
        })
        .to_string();
        let expected_digest = format!("{:x}", Sha256::digest(expected_payload.as_bytes()));
        if effect.request_json != expected_payload || effect.request_digest != expected_digest {
            return Err(
                "outbox request payload does not match the durable knowledge intent".into(),
            );
        }
        if let Some(receipt) = store.knowledge_publication_receipt(&operation_id)? {
            return Ok(receipt);
        }
        let input: PostmortemInput = serde_json::from_str(&intent.request_json)
            .map_err(|error| format!("stored postmortem request is invalid: {error}"))?;
        let published =
            publish_postmortem(&self.root, &input).map_err(|error| error.to_string())?;
        store.record_knowledge_publication(
            owner_generation,
            &operation_id,
            &published.manifest,
            &published.manifest_sha256,
        )?;
        store
            .knowledge_publication_receipt(&operation_id)?
            .ok_or("knowledge publisher completed without a durable receipt".into())
    }
}
