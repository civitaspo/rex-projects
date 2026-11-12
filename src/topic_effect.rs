//! Strict handler for the project-scoped Supervisor Topic creation effect.

use std::path::PathBuf;

use sha2::{Digest as _, Sha256};

use crate::domain::ids::OperationId;
use crate::effects::{
    EffectContext, EffectHandler, EffectKind, EffectMode, EffectObservation, EffectRequest,
};
use crate::store::{ConfigStore, EffectIntent};

pub struct TopicEffectHandler {
    root: PathBuf,
}

impl TopicEffectHandler {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn execute(
        &self,
        store: &mut ConfigStore,
        owner_generation: u64,
        effect: &EffectIntent,
    ) -> Result<crate::topic::TopicReceipt, crate::topic::TopicPublicationError> {
        if effect.kind != "publish_topic" || effect.subject_type != "project" {
            return Err("effect is not a project-scoped publish_topic operation".into());
        }
        let operation_id = OperationId::parse(effect.operation_id.clone())?;
        let intent = store
            .supervisor_topic_intent(&operation_id)?
            .ok_or("Topic publication intent is missing")?;
        if effect.project_id != intent.project_id || effect.subject_id != intent.project_id.as_str()
        {
            return Err("outbox effect does not match the durable Topic intent".into());
        }
        let expected_request = serde_json::json!({
            "operation_id": operation_id.as_str(),
            "intent_digest": stored_intent_digest(store, &operation_id)?,
        });
        let expected_json = crate::store::canonical_json(&expected_request)?;
        if effect.request_json != expected_json
            || effect.request_digest != format!("{:x}", Sha256::digest(expected_json.as_bytes()))
        {
            return Err("outbox request differs from the immutable Topic intent".into());
        }
        if let Some(receipt) = store.supervisor_topic_receipt(&operation_id)? {
            return Ok(receipt);
        }
        if !self.root.is_absolute() || intent.destination_root != self.root {
            return Err(crate::topic::TopicPublicationError::Conflict(
                "configured Topic destination changed while a publication was pending".into(),
            ));
        }
        let receipt = crate::topic::publish_create_only(&intent)?;
        store.record_supervisor_topic_publication(owner_generation, &operation_id, &receipt)?;
        store
            .supervisor_topic_receipt(&operation_id)?
            .ok_or("Topic publisher completed without a durable receipt".into())
    }
}

impl EffectHandler for TopicEffectHandler {
    fn kind(&self) -> EffectKind {
        EffectKind::PublishTopic
    }

    fn handle(
        &self,
        _mode: EffectMode,
        request: &EffectRequest,
        context: &mut EffectContext<'_>,
    ) -> Result<EffectObservation, String> {
        match self.execute(context.store, context.owner_generation, &request.intent) {
            Ok(receipt) => Ok(EffectObservation::Applied {
                receipt: serde_json::to_string(&receipt).map_err(|error| error.to_string())?,
            }),
            Err(crate::topic::TopicPublicationError::Conflict(reason)) => {
                let operation_id = OperationId::parse(request.intent.operation_id.clone())?;
                context.store.record_supervisor_topic_conflict(
                    context.owner_generation,
                    &operation_id,
                    &reason,
                )?;
                Ok(EffectObservation::Rejected {
                    receipt: serde_json::json!({
                        "operation_id": operation_id.as_str(),
                        "state": "conflict",
                        "reason": reason,
                    })
                    .to_string(),
                })
            }
            Err(crate::topic::TopicPublicationError::Failure(error)) => Err(error),
        }
    }
}

fn stored_intent_digest(store: &ConfigStore, operation_id: &OperationId) -> Result<String, String> {
    store.supervisor_topic_intent_digest(operation_id)
}
