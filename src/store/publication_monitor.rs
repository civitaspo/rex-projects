//! Durable publication irregularities and exact-resource human resolution.

use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::{ConfigStore, validate_active_generation};
use crate::domain::ids::{ProjectId, RepositoryId, TicketRunId};

/// Install the publication-baseline journal as part of the shared v12 migration.
pub fn migrate_v12_publication_baselines(tx: &Transaction<'_>) -> Result<(), String> {
    tx.execute_batch(
        "CREATE TABLE publication_baselines (
            project_id TEXT NOT NULL,
            ticket_run_id TEXT NOT NULL,
            repository_id TEXT NOT NULL,
            branch TEXT NOT NULL,
            base_branch TEXT NOT NULL,
            configuration_digest TEXT NOT NULL,
            initial_snapshot_json TEXT NOT NULL,
            initial_digest TEXT NOT NULL,
            current_snapshot_json TEXT NOT NULL,
            current_digest TEXT NOT NULL,
            revision INTEGER NOT NULL,
            last_effect_operation_id TEXT,
            updated_at_unix INTEGER NOT NULL,
            PRIMARY KEY(project_id,ticket_run_id,repository_id,branch)
        );
        CREATE INDEX publication_baselines_run ON publication_baselines(project_id,ticket_run_id);",
    )
    .map_err(|error| error.to_string())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationBaseline {
    pub resource: PublicationResource,
    pub base_branch: String,
    pub configuration_digest: crate::domain::ids::Digest,
    pub observation: crate::delivery_runtime::RepositoryPublicationObservation,
    pub revision: u64,
    pub digest: String,
    pub last_effect_operation_id: Option<String>,
}

impl ConfigStore {
    /// A branch is not compared while a matching publication intent is still being reconciled.
    pub fn publication_effect_in_flight(
        &self,
        project_id: &ProjectId,
        ticket_run_id: &TicketRunId,
        repository_id: &RepositoryId,
        _branch: &str,
    ) -> Result<bool, String> {
        let mut statement = self.connection.prepare(
            "SELECT request_json,request_digest FROM effects WHERE project_id=?1 AND subject_type='ticket_run' AND subject_id=?2 AND kind='publish_implementation' AND status IN ('pending','claimed','uncertain') ORDER BY created_at_unix,operation_id LIMIT 64",
        ).map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(
                params![project_id.as_str(), ticket_run_id.as_str()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .map_err(|error| error.to_string())?;
        for row in rows {
            let (json, stored_digest) = row.map_err(|error| error.to_string())?;
            if super::content_digest(&json) != stored_digest {
                return Err("pending publication effect request digest is invalid".into());
            }
            let payload: crate::delivery_runtime::PublishImplementationEffectPayload =
                crate::protocol::parse_unique(json.as_bytes())
                    .map_err(|error| error.to_string())?;
            if payload.repository_id == *repository_id && payload.ticket_run_id == *ticket_run_id {
                // Branch names encode the entire immutable work identity; exact comparison is
                // performed by the caller against the prepared worktree receipt.
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Persist the only acceptable initial baseline: a fresh, complete observation proving the
    /// managed branch and matching pull-request set were absent before worktree preparation.
    pub fn insert_initial_publication_baseline(
        &mut self,
        owner_generation: u64,
        resource: &PublicationResource,
        base_branch: &str,
        configuration_digest: &crate::domain::ids::Digest,
        observation: &crate::delivery_runtime::RepositoryPublicationObservation,
        now_unix: i64,
    ) -> Result<PublicationBaseline, String> {
        if observation.remote_head.is_some()
            || observation.pull_requests
                != crate::delivery_forge::ObservationCapability::Known(Vec::new())
            || base_branch.trim().is_empty()
        {
            return Err(
                "initial publication baseline is not a complete absent-resource observation".into(),
            );
        }
        let snapshot_json = super::canonical_json(observation)?;
        let snapshot_digest = baseline_digest(snapshot_json.as_bytes());
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let run_project: Option<String> = tx
            .query_row(
                "SELECT project_id FROM ticket_runs WHERE ticket_run_id=?1",
                [resource.ticket_run_id.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if run_project.as_deref() != Some(resource.project_id.as_str()) {
            return Err("publication baseline does not match its durable TicketRun".into());
        }
        let inserted = tx.execute(
            "INSERT OR IGNORE INTO publication_baselines(project_id,ticket_run_id,repository_id,branch,base_branch,configuration_digest,initial_snapshot_json,initial_digest,current_snapshot_json,current_digest,revision,last_effect_operation_id,updated_at_unix) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?7,?8,1,NULL,?9)",
            params![resource.project_id.as_str(),resource.ticket_run_id.as_str(),resource.repository_id.as_str(),resource.branch,base_branch,configuration_digest.as_str(),snapshot_json,snapshot_digest,now_unix],
        ).map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        let row = self
            .load_publication_baseline(resource)?
            .ok_or("publication baseline insert disappeared")?;
        if row.base_branch != base_branch
            || row.configuration_digest != *configuration_digest
            || row.digest != snapshot_digest
        {
            return Err(
                "initial publication baseline conflicts with a previously captured observation"
                    .into(),
            );
        }
        let _ = inserted;
        Ok(row)
    }

    pub fn load_publication_baseline(
        &self,
        resource: &PublicationResource,
    ) -> Result<Option<PublicationBaseline>, String> {
        let row: Option<(String,String,String,String,u64,Option<String>)> = self.connection.query_row(
            "SELECT base_branch,configuration_digest,current_snapshot_json,current_digest,revision,last_effect_operation_id FROM publication_baselines WHERE project_id=?1 AND ticket_run_id=?2 AND repository_id=?3 AND branch=?4",
            params![resource.project_id.as_str(),resource.ticket_run_id.as_str(),resource.repository_id.as_str(),resource.branch],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?)),
        ).optional().map_err(|error| error.to_string())?;
        let Some((
            base_branch,
            configuration_digest,
            json,
            digest,
            revision,
            last_effect_operation_id,
        )) = row
        else {
            return Ok(None);
        };
        if baseline_digest(json.as_bytes()) != digest {
            return Err("stored publication baseline digest is invalid".into());
        }
        let observation =
            crate::protocol::parse_unique(json.as_bytes()).map_err(|error| error.to_string())?;
        Ok(Some(PublicationBaseline {
            resource: resource.clone(),
            base_branch,
            configuration_digest: crate::domain::ids::Digest::parse(configuration_digest)?,
            observation,
            revision,
            digest,
            last_effect_operation_id,
        }))
    }

    /// Advance only from a succeeded, exact publication effect whose receipt matches the new
    /// remote snapshot. The caller cannot supply a boolean or an operation ID as proof.
    pub fn advance_publication_baseline(
        &mut self,
        owner_generation: u64,
        expected: &PublicationBaseline,
        next: &crate::delivery_runtime::RepositoryPublicationObservation,
        succeeded: &super::SucceededEffectReceipt,
        now_unix: i64,
    ) -> Result<PublicationBaseline, String> {
        let intent = succeeded.intent();
        if intent.kind != "publish_implementation"
            || intent.project_id != expected.resource.project_id
            || intent.subject_type != "ticket_run"
            || intent.subject_id != expected.resource.ticket_run_id.as_str()
        {
            return Err("publication baseline advance lacks a matching succeeded effect".into());
        }
        let payload: crate::delivery_runtime::PublishImplementationEffectPayload =
            crate::protocol::parse_unique(intent.request_json.as_bytes())
                .map_err(|e| e.to_string())?;
        let receipt: crate::delivery_runtime::ImplementationPublicationReceipt =
            crate::protocol::parse_unique(succeeded.receipt_json().as_bytes())
                .map_err(|e| e.to_string())?;
        if payload.repository_id != expected.resource.repository_id
            || receipt.repository_id != expected.resource.repository_id
            || receipt.effect_operation_id != intent.operation_id
            || payload.ticket_run_id != expected.resource.ticket_run_id
            || receipt.push.branch != expected.resource.branch
            || receipt.pull_request.source_branch != expected.resource.branch
            || next.remote_head.as_deref() != Some(receipt.push.pushed_head.as_str())
        {
            return Err(
                "publication receipt does not authorize the observed baseline update".into(),
            );
        }
        let crate::delivery_forge::ObservationCapability::Known(pulls) = &next.pull_requests else {
            return Err("cannot advance baseline from incomplete PR observation".into());
        };
        let Some(pull) = pulls
            .iter()
            .find(|pull| pull.number == receipt.pull_request.number)
        else {
            return Err("published PR is absent from fresh observation".into());
        };
        if pull.node_id != receipt.pull_request.node_id
            || pull.source_head != receipt.pull_request.source_head
            || pull.source_branch != expected.resource.branch
            || pull.base_branch != expected.base_branch
            || pull.title != receipt.pull_request.title
        {
            return Err("fresh PR observation does not match succeeded publication receipt".into());
        }
        let json = super::canonical_json(next)?;
        let digest = baseline_digest(json.as_bytes());
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let changed = tx.execute("UPDATE publication_baselines SET current_snapshot_json=?5,current_digest=?6,revision=revision+1,last_effect_operation_id=?7,updated_at_unix=?8 WHERE project_id=?1 AND ticket_run_id=?2 AND repository_id=?3 AND branch=?4 AND revision=?9 AND current_digest=?10 AND (last_effect_operation_id IS NULL OR last_effect_operation_id<>?7)", params![expected.resource.project_id.as_str(),expected.resource.ticket_run_id.as_str(),expected.resource.repository_id.as_str(),expected.resource.branch,json,digest,intent.operation_id,now_unix,expected.revision,expected.digest]).map_err(|e| e.to_string())?;
        if changed != 1 {
            return Err("publication baseline changed before compare-and-swap".into());
        }
        tx.commit().map_err(|e| e.to_string())?;
        self.load_publication_baseline(&expected.resource)?
            .ok_or_else(|| "advanced publication baseline disappeared".into())
    }
}

fn baseline_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationResource {
    pub project_id: ProjectId,
    pub ticket_run_id: TicketRunId,
    pub repository_id: RepositoryId,
    pub branch: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationIrregularity {
    pub resource: PublicationResource,
    pub observation_digest: String,
    pub observed_at_unix: i64,
    pub facts: serde_json::Value,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicationIrregularityReceipt {
    pub event_id: String,
    pub revision: u64,
    pub duplicate: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnresolvedPublicationIrregularity {
    pub event_id: String,
    pub revision: u64,
    pub observation_digest: crate::domain::ids::Digest,
    pub facts: serde_json::Value,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicationResolution {
    pub owner_generation: u64,
    pub resource: PublicationResource,
    pub expected_revision: u64,
    pub expected_observation_digest: String,
    pub fresh_observation_digest: String,
    pub selected_resource: serde_json::Value,
    pub human_disposition: String,
    pub now_unix: i64,
}

impl ConfigStore {
    /// Re-read the latest unresolved exact resource before preparing a human adoption request.
    pub fn latest_unresolved_publication(
        &self,
        resource: &PublicationResource,
    ) -> Result<Option<UnresolvedPublicationIrregularity>, String> {
        let entity_id = publication_entity_id(resource)?;
        let row: Option<(u64, String, String)> = self.connection.query_row(
            "SELECT new_revision,input_id,evidence_json FROM transitions WHERE project_id=?1 AND entity_type='external_publication' AND entity_id=?2 ORDER BY new_revision DESC LIMIT 1",
            params![resource.project_id.as_str(),entity_id],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
        ).optional().map_err(|error| error.to_string())?;
        let Some((revision, event_id, evidence_json)) = row else {
            return Ok(None);
        };
        if event_id != format!("{entity_id}:{revision}") {
            return Err("unresolved publication event identity is invalid".into());
        }
        let evidence: serde_json::Value = crate::protocol::parse_unique(evidence_json.as_bytes())
            .map_err(|error| error.to_string())?;
        if evidence["state"] != "unresolved" {
            return Ok(None);
        }
        let observation_digest = crate::domain::ids::Digest::parse(
            evidence["observation_digest"]
                .as_str()
                .ok_or("unresolved publication record has no observation digest")?
                .to_owned(),
        )?;
        let facts = evidence["facts"]["facts"].clone();
        if facts["resource"] != serde_json::to_value(resource).map_err(|error| error.to_string())?
            || facts["observation_digest"] != observation_digest.as_str()
        {
            return Err("unresolved publication record scope is invalid".into());
        }
        Ok(Some(UnresolvedPublicationIrregularity {
            event_id,
            revision,
            observation_digest,
            facts,
        }))
    }

    /// Persist an unexpected remote mutation and its durable Coordinator wake together.
    pub fn record_publication_irregularity(
        &mut self,
        owner_generation: u64,
        irregularity: &PublicationIrregularity,
    ) -> Result<PublicationIrregularityReceipt, String> {
        validate_irregularity(irregularity)?;
        let entity_id = publication_entity_id(&irregularity.resource)?;
        let facts_json = serde_json::to_string(irregularity).map_err(|error| error.to_string())?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let run_project: Option<String> = tx
            .query_row(
                "SELECT project_id FROM ticket_runs WHERE ticket_run_id=?1",
                [irregularity.resource.ticket_run_id.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if run_project.as_deref() != Some(irregularity.resource.project_id.as_str()) {
            return Err("publication irregularity does not match its durable TicketRun".into());
        }
        let latest: Option<(u64, String)> = tx
            .query_row(
                "SELECT new_revision,evidence_json FROM transitions WHERE project_id=?1 AND entity_type='external_publication' AND entity_id=?2 ORDER BY new_revision DESC LIMIT 1",
                params![irregularity.resource.project_id.as_str(), entity_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if let Some((revision, previous_json)) = &latest {
            let previous: serde_json::Value = serde_json::from_str(previous_json)
                .map_err(|error| format!("publication journal is invalid: {error}"))?;
            if previous["state"] == "unresolved"
                && previous["observation_digest"].as_str()
                    == Some(irregularity.observation_digest.as_str())
            {
                tx.commit().map_err(|error| error.to_string())?;
                return Ok(PublicationIrregularityReceipt {
                    event_id: entity_id,
                    revision: *revision,
                    duplicate: true,
                });
            }
        }
        let previous_revision = latest.map_or(0, |(revision, _)| revision);
        let revision = previous_revision
            .checked_add(1)
            .ok_or("publication journal revision overflow")?;
        let event_id = format!("{entity_id}:{revision}");
        let evidence = serde_json::json!({
            "state": "unresolved",
            "observation_digest": irregularity.observation_digest,
            "facts": serde_json::from_str::<serde_json::Value>(&facts_json).map_err(|error| error.to_string())?,
        });
        tx.execute(
            "INSERT INTO transitions(project_id,entity_type,entity_id,old_revision,new_revision,input_id,decision_reason,evidence_json,created_at_unix) VALUES (?1,'external_publication',?2,?3,?4,?5,'unexpected external publication observed',?6,?7)",
            params![
                irregularity.resource.project_id.as_str(), entity_id, previous_revision, revision,
                event_id, evidence.to_string(), irregularity.observed_at_unix
            ],
        )
        .map_err(|error| error.to_string())?;
        let role_session = format!(
            "ticket_run:{}:coordinator",
            irregularity.resource.ticket_run_id.as_str()
        );
        let wake = serde_json::json!({
            "ticket_run_id": irregularity.resource.ticket_run_id.as_str(),
            "target": "coordinator",
            "source": "external_publication",
            "event_id": event_id,
            "revision": revision,
        });
        tx.execute(
            "INSERT INTO role_wake_inputs(project_id,role_session_id,source_type,source_id,source_revision,priority,payload_json,lifecycle,created_at_unix) VALUES (?1,?2,'external_publication',?3,?4,100,?5,'pending',?6)",
            params![
                irregularity.resource.project_id.as_str(), role_session,
                event_id, revision, wake.to_string(), irregularity.observed_at_unix
            ],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(PublicationIrregularityReceipt {
            event_id,
            revision,
            duplicate: false,
        })
    }

    /// Resolve only the exact latest observation a human reviewed. The adopted resource is
    /// recorded as evidence; it does not manufacture a successful push, PR, or merge receipt.
    pub fn resolve_publication_irregularity(
        &mut self,
        resolution: &PublicationResolution,
    ) -> Result<(), String> {
        if !matches!(
            resolution.human_disposition.as_str(),
            "adopt_exact_resource" | "replan"
        ) {
            return Err("unsupported publication irregularity resolution".into());
        }
        let entity_id = publication_entity_id(&resolution.resource)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, resolution.owner_generation)?;
        let latest: Option<(u64, String)> = tx
            .query_row(
                "SELECT new_revision,evidence_json FROM transitions WHERE project_id=?1 AND entity_type='external_publication' AND entity_id=?2 ORDER BY new_revision DESC LIMIT 1",
                params![resolution.resource.project_id.as_str(), entity_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let Some((revision, evidence_json)) = latest else {
            return Err("publication irregularity no longer exists".into());
        };
        let evidence: serde_json::Value = serde_json::from_str(&evidence_json)
            .map_err(|error| format!("publication journal is invalid: {error}"))?;
        let facts = &evidence["facts"]["facts"];
        let selected_is_observed = if resolution.selected_resource["kind"] == "branch" {
            facts["observed_remote_head"] == resolution.selected_resource["head"]
        } else {
            facts["pull_requests"]["value"]
                .as_array()
                .is_some_and(|resources| resources.contains(&resolution.selected_resource))
        };
        if revision != resolution.expected_revision
            || evidence["state"] != "unresolved"
            || evidence["observation_digest"].as_str()
                != Some(resolution.expected_observation_digest.as_str())
            || resolution.fresh_observation_digest != resolution.expected_observation_digest
            || (resolution.human_disposition == "adopt_exact_resource" && !selected_is_observed)
        {
            return Err(
                "publication irregularity or selected resource changed after fresh human review"
                    .into(),
            );
        }
        let next_revision = revision
            .checked_add(1)
            .ok_or("publication journal revision overflow")?;
        let resolution_id = format!("{entity_id}:{next_revision}");
        let resolved = serde_json::json!({
            "state": "resolved",
            "observation_digest": resolution.expected_observation_digest,
            "human_disposition": resolution.human_disposition,
            "resolved_revision": revision,
            "adopted_resource": (resolution.human_disposition == "adopt_exact_resource").then_some(&resolution.selected_resource),
        });
        tx.execute(
            "INSERT INTO transitions(project_id,entity_type,entity_id,old_revision,new_revision,input_id,decision_reason,evidence_json,created_at_unix) VALUES (?1,'external_publication',?2,?3,?4,?5,'human resolved exact external publication observation',?6,?7)",
            params![resolution.resource.project_id.as_str(), entity_id, revision, next_revision, resolution_id, resolved.to_string(), resolution.now_unix],
        )
        .map_err(|error| error.to_string())?;
        let role_session = format!(
            "ticket_run:{}:coordinator",
            resolution.resource.ticket_run_id.as_str()
        );
        let wake = serde_json::json!({
            "ticket_run_id": resolution.resource.ticket_run_id.as_str(),
            "target": "coordinator",
            "source": "publication_resolution",
            "event_id": resolution_id,
            "revision": next_revision,
        });
        tx.execute(
            "INSERT INTO role_wake_inputs(project_id,role_session_id,source_type,source_id,source_revision,priority,payload_json,lifecycle,created_at_unix) VALUES (?1,?2,'external_publication_resolution',?3,?4,50,?5,'pending',?6)",
            params![resolution.resource.project_id.as_str(), role_session, resolution_id, next_revision, wake.to_string(), resolution.now_unix],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())
    }

    /// Check the exact repository branch before any later publication or merge side effect.
    pub fn assert_publication_unblocked(
        &self,
        resource: &PublicationResource,
    ) -> Result<(), String> {
        let entity_id = publication_entity_id(resource)?;
        let evidence: Option<String> = self
            .connection
            .query_row(
                "SELECT evidence_json FROM transitions WHERE project_id=?1 AND entity_type='external_publication' AND entity_id=?2 ORDER BY new_revision DESC LIMIT 1",
                params![resource.project_id.as_str(), entity_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if evidence
            .as_deref()
            .and_then(|json| serde_json::from_str::<serde_json::Value>(json).ok())
            .is_some_and(|evidence| evidence["state"] == "unresolved")
        {
            return Err(
                "publication or merge is paused for an unresolved external mutation".into(),
            );
        }
        Ok(())
    }
}

fn validate_irregularity(irregularity: &PublicationIrregularity) -> Result<(), String> {
    let resource = &irregularity.resource;
    if resource.branch.is_empty()
        || resource.branch.len() > 240
        || resource.branch.starts_with('-')
        || resource.branch.contains("..")
        || !resource
            .branch
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.'))
        || irregularity.observation_digest.len() != 64
        || !irregularity
            .observation_digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("publication irregularity identity or digest is invalid".into());
    }
    Ok(())
}

fn publication_entity_id(resource: &PublicationResource) -> Result<String, String> {
    let canonical = serde_json::to_vec(resource).map_err(|error| error.to_string())?;
    Ok(format!(
        "publication:{}",
        Sha256::digest(canonical)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AppliedConfig, SourceFile, SourceKind};
    use crate::domain::ids::{Digest, Revision};
    use crate::store::{ExpectedRevision, OwnerMetadata, ProjectRecord};
    use std::collections::BTreeMap;

    fn snapshot() -> AppliedConfig {
        AppliedConfig {
            config: serde_json::from_value(serde_json::json!({
                "schema_version": 1,
                "adapters": {"tickets": {"kind":"command","command":["test"]}},
                "projects": {}
            }))
            .unwrap(),
            profiles: BTreeMap::new(),
            source_root: "/tmp/config".into(),
            source_files: vec![SourceFile {
                kind: SourceKind::File,
                path: "/tmp/config/config.toml".into(),
                canonical_path: "/tmp/config/config.toml".into(),
                sha256: Digest::parse("a".repeat(64)).unwrap(),
                bytes: 1,
                contents: "x".into(),
            }],
            digest: Digest::parse("a".repeat(64)).unwrap(),
        }
    }

    fn setup_store(path: &std::path::Path) -> (ConfigStore, u64, PublicationResource) {
        let mut store = ConfigStore::open_test(path).unwrap();
        let applied = store
            .apply_snapshot("factory", &snapshot(), ExpectedRevision::Bootstrap)
            .unwrap();
        let project_id = ProjectId::parse("monitor-project").unwrap();
        let ticket_run_id = TicketRunId::parse("monitor-run").unwrap();
        store
            .insert_project(&ProjectRecord {
                id: project_id.clone(),
                config_source: "factory".into(),
                config_revision: applied.revision,
                config_digest: applied.digest.clone(),
                mode: "goal".into(),
                goal_revision: 1,
                desired_lifecycle: "running".into(),
                state_revision: Revision(0),
            })
            .unwrap();
        store.connection.execute(
            "INSERT INTO ticket_runs(ticket_run_id,project_id,config_source,config_revision,config_digest,namespace,ticket_id,generation,internal_phase,activity,external_status,observed_status,revision) VALUES (?1,?2,'factory',?3,?4,'fixture','T-1',1,'implementing','working','In Progress','In Progress',1)",
            rusqlite::params![ticket_run_id.as_str(), project_id.as_str(), applied.revision.0, applied.digest.as_str()],
        ).unwrap();
        let generation = store
            .start_owner(&OwnerMetadata {
                owner_nonce: "monitor-owner".into(),
                state_root: path.display().to_string(),
                config_source: "factory".into(),
                process_start_identity: "test-process".into(),
                executable_path: "/tmp/rex-projects-test".into(),
                executable_digest: "b".repeat(64),
                rex_endpoint: None,
                rex_server_identity: None,
                rex_session_id: None,
                rex_block_id: None,
            })
            .unwrap();
        (
            store,
            generation,
            PublicationResource {
                project_id,
                ticket_run_id,
                repository_id: RepositoryId::parse("demo").unwrap(),
                branch: "rex-projects/work".into(),
            },
        )
    }

    #[test]
    fn initial_baseline_requires_complete_absence_and_is_immutable() {
        let temp = tempfile::tempdir().unwrap();
        let (mut store, generation, resource) = setup_store(temp.path());
        let absent = crate::delivery_runtime::RepositoryPublicationObservation {
            remote_head: None,
            pull_requests: crate::delivery_forge::ObservationCapability::Known(Vec::new()),
        };
        assert!(
            store
                .insert_initial_publication_baseline(
                    generation,
                    &resource,
                    "main",
                    &Digest::parse("a".repeat(64)).unwrap(),
                    &crate::delivery_runtime::RepositoryPublicationObservation {
                        remote_head: Some("a".repeat(40)),
                        ..absent.clone()
                    },
                    10
                )
                .is_err()
        );
        let saved = store
            .insert_initial_publication_baseline(
                generation,
                &resource,
                "main",
                &Digest::parse("a".repeat(64)).unwrap(),
                &absent,
                11,
            )
            .unwrap();
        assert_eq!(saved.revision, 1);
        assert!(
            store
                .insert_initial_publication_baseline(
                    generation,
                    &resource,
                    "main",
                    &Digest::parse("a".repeat(64)).unwrap(),
                    &crate::delivery_runtime::RepositoryPublicationObservation {
                        remote_head: None,
                        pull_requests: crate::delivery_forge::ObservationCapability::Known(vec![
                            crate::delivery_forge::ObservedPullRequest {
                                number: 1,
                                node_id: "node".into(),
                                url: "https://github.com/acme/demo/pull/1".into(),
                                state: "open".into(),
                                merged: false,
                                merged_at: None,
                                source_branch: resource.branch.clone(),
                                source_head: "a".repeat(40),
                                base_branch: "main".into(),
                                base_sha: "b".repeat(40),
                                title: "change".into(),
                                body: None,
                                timeline: crate::delivery_forge::ObservationCapability::Known(
                                    Vec::new()
                                ),
                            }
                        ]),
                    },
                    12
                )
                .is_err()
        );
        assert_eq!(
            store.load_publication_baseline(&resource).unwrap(),
            Some(saved)
        );
    }

    #[test]
    fn exact_adoption_requires_fresh_matching_revision_and_selected_resource() {
        let temp = tempfile::tempdir().unwrap();
        let (mut store, generation, resource) = setup_store(temp.path());
        let selected = serde_json::json!({"number":7,"source_head":"b".repeat(40)});
        let facts = serde_json::json!({
            "pull_requests": {"status":"known","value":[selected.clone()]},
            "observed_remote_head":"b".repeat(40),
        });
        let digest = format!("{:x}", Sha256::digest(serde_json::to_vec(&facts).unwrap()));
        let receipt = store
            .record_publication_irregularity(
                generation,
                &PublicationIrregularity {
                    resource: resource.clone(),
                    observation_digest: digest.clone(),
                    observed_at_unix: 10,
                    facts,
                },
            )
            .unwrap();
        assert!(store.assert_publication_unblocked(&resource).is_err());
        assert!(
            store
                .resolve_publication_irregularity(&PublicationResolution {
                    owner_generation: generation,
                    resource: resource.clone(),
                    expected_revision: receipt.revision,
                    expected_observation_digest: digest.clone(),
                    fresh_observation_digest: "stale-observation".into(),
                    selected_resource: selected.clone(),
                    human_disposition: "adopt_exact_resource".into(),
                    now_unix: 11,
                },)
                .is_err()
        );
        assert!(store.assert_publication_unblocked(&resource).is_err());
        store
            .resolve_publication_irregularity(&PublicationResolution {
                owner_generation: generation,
                resource: resource.clone(),
                expected_revision: receipt.revision,
                expected_observation_digest: digest.clone(),
                fresh_observation_digest: digest,
                selected_resource: selected,
                human_disposition: "adopt_exact_resource".into(),
                now_unix: 12,
            })
            .unwrap();
        assert!(store.assert_publication_unblocked(&resource).is_ok());
    }
}
