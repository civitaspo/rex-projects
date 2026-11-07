//! Durable publication irregularities and exact-resource human resolution.

use rusqlite::{OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::{ConfigStore, validate_active_generation};
use crate::domain::ids::{ProjectId, RepositoryId, TicketRunId};

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
                "adapters": {"tickets": {"kind":"command","command":["test"],"status_values": {
                    "triage":"Triage","backlog":"Backlog","ready":"Ready","in_progress":"In Progress",
                    "in_review":"In Review","done":"Done","canceled":"Canceled"
                }}},
                "projects": {}
            })).unwrap(),
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
