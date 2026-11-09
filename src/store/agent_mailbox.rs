//! Host-side processing for bounded requests in a run-local Agent mailbox.
//!
//! Agents can only write the mailbox spool. This module checks the spool against the persisted
//! launch reservation and authority, then hands one supported request to its durable host API.

use rusqlite::OptionalExtension;
use sha2::{Digest as _, Sha256};

use crate::artifacts::ArtifactStore;
use crate::domain::ids::{AgentRunId, Digest, OperationId};
use crate::mailbox::{MailboxCapability, MailboxLimits};

type MailboxRunAuthorityStateRow = (
    String,
    u64,
    String,
    u64,
    String,
    Option<String>,
    String,
    String,
);

#[derive(Debug)]
pub enum AgentMailboxProcessingError {
    Authority(String),
    LocalMailbox(String),
}

impl From<String> for AgentMailboxProcessingError {
    fn from(error: String) -> Self {
        Self::Authority(error)
    }
}

impl From<&str> for AgentMailboxProcessingError {
    fn from(error: &str) -> Self {
        Self::Authority(error.to_owned())
    }
}

impl std::fmt::Display for AgentMailboxProcessingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Authority(error) => write!(f, "authority or storage error: {error}"),
            Self::LocalMailbox(error) => write!(f, "local mailbox error: {error}"),
        }
    }
}

impl crate::store::ConfigStore {
    /// Process at most one request for `agent_run_id`. The launch must still be active and all
    /// mailbox scope is resolved from durable host records, never from Agent-selected authority.
    pub fn process_one_agent_mailbox_request(
        &mut self,
        owner_generation: u64,
        agent_run_id: &str,
        now_unix: i64,
        artifact_store: &ArtifactStore,
        profiles: &std::collections::BTreeMap<
            crate::domain::ids::ProfileId,
            crate::config::Profile,
        >,
    ) -> Result<bool, AgentMailboxProcessingError> {
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)
            .map_err(|error| AgentMailboxProcessingError::Authority(error.to_string()))?;
        super::validate_active_generation(&tx, owner_generation)
            .map_err(AgentMailboxProcessingError::Authority)?;
        tx.commit()
            .map_err(|error| AgentMailboxProcessingError::Authority(error.to_string()))?;
        let active: Option<(String, u64)> = self
            .connection
            .query_row(
                "SELECT state,controller_generation FROM agent_runs WHERE agent_run_id=?1",
                [agent_run_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| AgentMailboxProcessingError::Authority(error.to_string()))?;
        match active {
            Some((state, generation)) if state == "running" && generation == owner_generation => {}
            // Recovery must reconcile a previous owner's run before its mailbox is eligible.
            _ => return Ok(false),
        }
        let run_id = AgentRunId::parse(agent_run_id.to_owned())?;
        let Some(authority) = self.agent_launch_authority(&run_id)? else {
            return Err("mailbox run has no persisted launch authority".into());
        };
        if authority.controller_generation != owner_generation {
            return Err("mailbox run is not owned by the active controller generation".into());
        }

        let reservation_row: Option<(String, String, String)> = self
            .connection
            .query_row(
                "SELECT reservation_digest,reservation_json,lifecycle FROM agent_launch_reservations WHERE agent_run_id=?1",
                [agent_run_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let Some((reservation_digest, reservation_json, lifecycle)) = reservation_row else {
            return Err("mailbox run has no persisted launch reservation".into());
        };
        if lifecycle != "authorized" {
            return Err("mailbox run launch reservation is not authorized".into());
        }
        let reservation: crate::launch::AgentLaunchReservation =
            crate::protocol::parse_unique(reservation_json.as_bytes())?;
        let expected_reservation_digest = reservation.digest()?;
        let expected_authority_reservation = [
            authority.project_id == reservation.project_id,
            authority.role == reservation.role,
            authority.role_session_id == reservation.role_session_id,
            authority.parent_run_id == reservation.parent_run_id,
            authority.parent_role == reservation.parent_role,
            authority.ticket_run_id == reservation.ticket_run_id,
            authority.ticket_revision == reservation.ticket_revision,
            authority.config_revision == reservation.config_revision,
            authority.config_digest == reservation.config_digest,
            authority.attempt == reservation.attempt,
            authority.run_epoch == reservation.run_epoch,
            authority.controller_generation == reservation.controller_generation,
            authority.operation_id == reservation.operation_id,
            authority.operation_recipe_id == reservation.operation_recipe_id,
            authority.rex_view_id == reservation.rex_view_id,
            authority.runtime_binary_digest == reservation.runtime_binary_digest,
            authority.environment_snapshot_id == reservation.environment_snapshot_id,
            authority.profile_id == reservation.profile_id,
            authority.profile_digest == reservation.profile_digest,
            authority.instruction_digest == reservation.instruction_digest,
            authority.result_schema_digest == reservation.result_schema_digest,
            authority.qualification_receipt_digest == reservation.qualification_receipt_digest,
            authority.descriptor_path == reservation.descriptor_path,
            authority.workspace_path == reservation.workspace_path,
            authority.control_dir == reservation.control_dir,
            authority.mailbox_capability_digest == reservation.mailbox_capability_digest,
        ]
        .into_iter()
        .all(|matches| matches);
        if expected_reservation_digest.as_str() != reservation_digest
            || reservation.agent_run_id != run_id
            || !expected_authority_reservation
        {
            return Err(
                "mailbox launch reservation differs from immutable launch authority".into(),
            );
        }

        let state: Option<MailboxRunAuthorityStateRow> = self
            .connection
            .query_row(
                "SELECT runs.state,runs.controller_generation,runs.project_id,runs.config_revision,runs.config_digest,runs.role_session_id,runs.launch_operation_id,authority.authority_digest FROM agent_runs runs JOIN agent_launch_authority authority USING(agent_run_id) WHERE runs.agent_run_id=?1",
                [agent_run_id],
                |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let state_matches = match state {
            Some((
                run_state,
                generation,
                project_id,
                config_revision,
                config_digest,
                role_session_id,
                operation_id,
                digest,
            )) => {
                run_state == "running"
                    && generation == owner_generation
                    && project_id == authority.project_id.as_str()
                    && config_revision == authority.config_revision.0
                    && config_digest == authority.config_digest.as_str()
                    && role_session_id.as_deref() == Some(authority.role_session_id.as_str())
                    && operation_id == authority.operation_id.as_str()
                    && digest == authority.digest()?.as_str()
            }
            None => false,
        };
        if !state_matches {
            return Err("mailbox run is not in the exact active persisted launch state".into());
        }
        let active_block: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM rex_view_blocks blocks JOIN rex_views views USING(view_id) WHERE blocks.view_id=?1 AND blocks.block_id=?2 AND blocks.agent_run_id=?3 AND blocks.role=?4 AND blocks.ownership='factory' AND blocks.lifecycle='active' AND views.project_id=?5 AND views.lifecycle='active' AND views.rex_server_identity=?6 AND views.rex_session_id=?7 AND views.rex_window_id=?8)",
            rusqlite::params![authority.rex_view_id.as_str(),authority.rex_block_id,agent_run_id,serde_json::to_value(authority.role).map_err(|error| error.to_string())?.as_str().ok_or("role serialization is not a string")?,authority.project_id.as_str(),authority.rex_server_identity,authority.rex_session_id,authority.rex_window_id],
            |row| row.get(0),
        ).map_err(|error| error.to_string())?;
        if !active_block {
            return Ok(false);
        }
        let wake_context: Option<(String, String)> = self
            .connection
            .query_row(
                "SELECT snapshot_digest,snapshot_json FROM agent_wake_context WHERE agent_run_id=?1",
                [agent_run_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let expected_wake_json = crate::store::canonical_json(&reservation.wake_snapshot)?;
        if !matches!(wake_context, Some((ref digest, ref json)) if digest == authority.wake_snapshot_digest.as_str() && json == &expected_wake_json)
        {
            return Err("mailbox wake snapshot differs from persisted launch context".into());
        }

        let registration = self
            .agent_mailbox_registration(agent_run_id)?
            .ok_or("mailbox run has no registered mailbox capability")?;
        let canonical_mailbox_directory = std::fs::canonicalize(&reservation.mailbox_directory)
            .map_err(|error| {
                AgentMailboxProcessingError::LocalMailbox(format!(
                    "canonicalize registered mailbox directory: {error}"
                ))
            })?;
        if registration.canonical_directory != canonical_mailbox_directory.display().to_string()
            || registration.capability_digest != reservation.mailbox_capability_digest.as_str()
            || authority.control_dir != reservation.control_dir
            || authority.mailbox_capability_digest.as_str() != registration.capability_digest
        {
            return Err("mailbox registration differs from immutable launch authority".into());
        }
        let mailbox = MailboxCapability::open_registered_verified(
            agent_run_id,
            std::path::Path::new(&registration.canonical_directory),
            MailboxLimits {
                max_request_bytes: registration.max_request_bytes,
                max_pending_requests: registration.max_pending_requests,
            },
            &registration.capability_digest,
        )
        .map_err(AgentMailboxProcessingError::LocalMailbox)?;
        let Some(mailbox_request) = mailbox
            .pending(now_unix.max(0) as u64)
            .map_err(AgentMailboxProcessingError::LocalMailbox)?
            .into_iter()
            .next()
        else {
            return Ok(false);
        };

        let method = serde_json::to_value(&mailbox_request.envelope.method)
            .map_err(|error| error.to_string())?;
        if method.as_str() == Some("repository.commit") {
            let request: crate::agent_api::RepositoryCommitRequest = serde_json::from_value(
                mailbox_request.envelope.params.clone(),
            )
            .map_err(|error| {
                AgentMailboxProcessingError::LocalMailbox(format!(
                    "invalid repository.commit params: {error}"
                ))
            })?;
            request
                .validate()
                .map_err(AgentMailboxProcessingError::LocalMailbox)?;
            let profile = profiles
                .get(&authority.profile_id)
                .ok_or("repository.commit Agent profile is no longer configured")?;
            let required_trailer = match profile.adapter {
                crate::domain::types::AgentAdapter::Codex => {
                    "Co-authored-by: Codex <noreply@openai.com>"
                }
                crate::domain::types::AgentAdapter::ClaudeCode => {
                    "Co-authored-by: Claude <noreply@anthropic.com>"
                }
            };
            self.process_repository_commit(
                owner_generation,
                &authority,
                &reservation,
                artifact_store,
                &mailbox,
                &mailbox_request,
                &request,
                required_trailer,
            )?;
            return Ok(true);
        }
        if method.as_str() != Some("artifact.add") {
            let response = crate::protocol::ResponseEnvelope {
                schema_version: crate::protocol::SCHEMA_VERSION,
                request_id: mailbox_request.envelope.request_id.clone(),
                result: None::<serde_json::Value>,
                error: Some(crate::protocol::ProtocolError {
                    code: crate::protocol::ErrorCode::Unsupported,
                    message: "this controller build does not support this Agent request method"
                        .into(),
                    retryable: false,
                    retry_after_ms: None,
                    details: Default::default(),
                }),
                extensions: Default::default(),
            };
            let bytes = serde_json::to_vec(&response).map_err(|error| error.to_string())?;
            mailbox
                .publish_receipt(&mailbox_request.request_id, &bytes, now_unix.max(0) as u64)
                .map_err(AgentMailboxProcessingError::LocalMailbox)?;
            return Ok(true);
        }

        let request: crate::engine::orchestration::ArtifactAddRequest =
            serde_json::from_value(mailbox_request.envelope.params.clone()).map_err(|error| {
                AgentMailboxProcessingError::LocalMailbox(format!(
                    "invalid artifact.add params: {error}"
                ))
            })?;
        let expected_subject_revision = authority.ticket_revision.map(|value| value.0).unwrap_or(0);
        if mailbox_request.envelope.operation_id.as_ref() != Some(&authority.operation_id)
            || mailbox_request.envelope.project_id.as_ref() != Some(&authority.project_id)
            || mailbox_request.envelope.run_id.as_deref() != Some(agent_run_id)
            || mailbox_request.envelope.role != Some(authority.role)
            || mailbox_request.envelope.attempt != Some(authority.attempt)
            || mailbox_request.envelope.run_epoch != Some(authority.run_epoch)
            || mailbox_request.envelope.expected_subject_revision != Some(expected_subject_revision)
        {
            return Err(AgentMailboxProcessingError::LocalMailbox(
                "mailbox request scope differs from immutable launch authority".into(),
            ));
        }
        let digest = Digest::parse(mailbox_request.digest.clone())
            .map_err(AgentMailboxProcessingError::LocalMailbox)?;
        if digest.as_str().is_empty() {
            return Err(AgentMailboxProcessingError::LocalMailbox(
                "mailbox request digest is empty".into(),
            ));
        }
        self.process_artifact_add(
            owner_generation,
            &authority,
            artifact_store,
            &mailbox,
            &mailbox_request,
            &request,
        )?;
        Ok(true)
    }

    #[allow(clippy::too_many_arguments)]
    fn process_repository_commit(
        &mut self,
        owner_generation: u64,
        authority: &crate::launch::AgentLaunchAuthority,
        reservation: &crate::launch::AgentLaunchReservation,
        artifact_store: &ArtifactStore,
        mailbox: &MailboxCapability,
        mailbox_request: &crate::mailbox::MailboxRequest,
        request: &crate::agent_api::RepositoryCommitRequest,
        required_trailer: &str,
    ) -> Result<(), AgentMailboxProcessingError> {
        use crate::delivery_runtime::{
            CommitWorkerManifestEffectPayload, PrepareWorktreesEffectPayload,
            canonical_delivery_payload,
        };
        use crate::engine::reducer::{EffectKind, effect_name};
        use crate::store::EffectIntent;

        let assignment = reservation
            .worker_assignment
            .as_ref()
            .ok_or("repository.commit requires an immutable Worker assignment")?;
        let ticket_run_id = authority
            .ticket_run_id
            .as_ref()
            .ok_or("repository.commit Worker has no TicketRun")?;
        let ticket_revision = authority
            .ticket_revision
            .ok_or("repository.commit Worker has no TicketRun revision")?;
        let envelope = &mailbox_request.envelope;
        if authority.role != crate::domain::types::Role::Worker
            || assignment.commit_mode != crate::domain::types::CommitMode::Host
            || request.worktree_id != assignment.node_id.as_str()
            || envelope.request_id.as_str() != request.message_id
            || mailbox_request.request_id != request.message_id
            || envelope.operation_id.as_ref() != Some(&authority.operation_id)
            || envelope.project_id.as_ref() != Some(&authority.project_id)
            || envelope.run_id.as_deref() != Some(authority.agent_run_id.as_str())
            || envelope.role != Some(authority.role)
            || envelope.attempt != Some(authority.attempt)
            || envelope.run_epoch != Some(authority.run_epoch)
            || envelope.expected_subject_revision != Some(ticket_revision.0)
        {
            return Err(AgentMailboxProcessingError::LocalMailbox(
                "repository.commit request differs from immutable Worker authority".into(),
            ));
        }
        let prepared = self
            .succeeded_effect_receipt(&assignment.prepare_operation_id)?
            .ok_or("repository.commit prepared-worktree effect is not durably succeeded")?;
        if prepared.intent().kind != effect_name(&EffectKind::PrepareWorktrees) {
            return Err("repository.commit preparation reference has the wrong effect kind".into());
        }
        let prepared_payload: PrepareWorktreesEffectPayload =
            crate::protocol::parse_unique(prepared.intent().request_json.as_bytes())?;
        let prepared_node = prepared_payload
            .work_nodes
            .iter()
            .filter(|node| node.work_node_id == assignment.node_id)
            .collect::<Vec<_>>();
        if prepared_payload.ticket_run_id != *ticket_run_id
            || prepared_payload.configuration_digest != authority.config_digest
            || prepared_node.len() != 1
            || prepared_node[0].repository_id != assignment.repository_id
            || prepared_node[0].expected_base_sha != assignment.base_sha
            || prepared_node[0].commit_mode != crate::domain::types::CommitMode::Host
        {
            return Err(
                "repository.commit assignment differs from its succeeded preparation".into(),
            );
        }
        let verified = self
            .lookup_verified_artifact(artifact_store, authority, &request.manifest)?
            .ok_or("repository.commit manifest is not registered to this Worker")?;
        let bytes = verified.read_bytes(artifact_store)?;
        let digest = Digest::parse(format!("{:x}", Sha256::digest(&bytes)))?;
        if digest != request.manifest_digest || digest != request.manifest.digest {
            return Err(
                "repository.commit manifest digest differs from registered artifact bytes".into(),
            );
        }
        let manifest: crate::host_commit::ChangeManifest = crate::protocol::parse_unique(&bytes)?;
        if manifest.schema_version != 1
            || manifest.entries.is_empty()
            || serde_json::to_vec(&manifest).map_err(|error| error.to_string())? != bytes
        {
            return Err("repository.commit manifest is empty or noncanonical".into());
        }
        let message_digest = mailbox_request.digest.as_str();
        let operation_id = OperationId::parse(format!("repo-commit-{message_digest}"))?;
        let payload = CommitWorkerManifestEffectPayload {
            schema_version: 1,
            agent_run_id: authority.agent_run_id.clone(),
            project_id: authority.project_id.clone(),
            message_id: request.message_id.clone(),
            configuration_digest: authority.config_digest.clone(),
            ticket_revision: ticket_revision.0,
            ticket_namespace: prepared_payload.ticket_namespace.clone(),
            ticket_id: prepared_payload.ticket_id.clone(),
            ticket_run_id: ticket_run_id.clone(),
            work_node_id: assignment.node_id.clone(),
            repository_id: assignment.repository_id.clone(),
            worktree_path: assignment.worktree_path.clone(),
            branch: assignment.branch.clone(),
            prepare_operation_id: OperationId::parse(assignment.prepare_operation_id.clone())?,
            expected_base_sha: assignment.base_sha.clone(),
            expected_head: request.expected_head.clone(),
            manifest_artifact: verified.reference().clone(),
            manifest_digest: digest,
            manifest,
            commit_message: request.commit_message.clone(),
            required_trailer: required_trailer.to_owned(),
        };
        let (request_json, request_digest) = canonical_delivery_payload(&payload)?;
        let intent = EffectIntent {
            project_id: authority.project_id.clone(),
            subject_type: "ticket_run".into(),
            subject_id: ticket_run_id.as_str().into(),
            operation_id: operation_id.as_str().to_owned(),
            logical_key: format!(
                "repository.commit:{}:{message_digest}",
                authority.agent_run_id
            ),
            kind: effect_name(&EffectKind::CommitWorkerManifest).into(),
            request_json,
            request_digest,
            expected_revision: Some(ticket_revision.0),
        };
        if let Some(existing) = self.effect_by_logical_key(&intent.logical_key)? {
            if existing != intent {
                return Err(
                    "repository.commit message ID was reused with different request content".into(),
                );
            }
        } else {
            self.enqueue_effect(owner_generation, &intent)?;
        }
        let status: Option<(String, Option<String>)> = self
            .connection
            .query_row(
                "SELECT status,last_error FROM effects WHERE operation_id=?1",
                [&intent.operation_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if let Some((status, last_error)) = status
            && matches!(status.as_str(), "failed" | "cancelled")
        {
            let response = crate::protocol::ResponseEnvelope::<serde_json::Value> {
                schema_version: crate::protocol::SCHEMA_VERSION,
                request_id: mailbox_request.envelope.request_id.clone(),
                result: None,
                error: Some(crate::protocol::ProtocolError {
                    code: crate::protocol::ErrorCode::Unavailable,
                    message: format!(
                        "host repository.commit effect {status}: {}",
                        last_error.unwrap_or_else(|| "effect was cancelled".into())
                    ),
                    retryable: false,
                    retry_after_ms: None,
                    details: Default::default(),
                }),
                extensions: Default::default(),
            };
            let bytes = serde_json::to_vec(&response).map_err(|error| error.to_string())?;
            mailbox
                .publish_receipt(
                    &request.message_id,
                    &bytes,
                    crate::mailbox::unix_time_now()?,
                )
                .map_err(AgentMailboxProcessingError::LocalMailbox)?;
            return Ok(());
        }
        let Some(receipt) = self.succeeded_effect_receipt(&intent.operation_id)? else {
            // Keep the mailbox request pending. The normal dispatcher will execute/reconcile the
            // durable effect; this method will publish the receipt on a later controller pass.
            return Ok(());
        };
        if receipt.intent() != &intent {
            return Err("repository.commit durable receipt has a different intent".into());
        }
        let committed: crate::delivery_runtime::CommitWorkerManifestEffectReceipt =
            crate::protocol::parse_unique(receipt.receipt_json().as_bytes())?;
        let response = crate::protocol::ResponseEnvelope {
            schema_version: crate::protocol::SCHEMA_VERSION,
            request_id: mailbox_request.envelope.request_id.clone(),
            result: Some(crate::agent_api::RepositoryCommitReceipt {
                schema_version: 1,
                message_id: request.message_id.clone(),
                commit_operation_id: operation_id,
                worktree_id: assignment.node_id.to_string(),
                repository_id: assignment.repository_id.to_string(),
                base_sha: assignment.base_sha.clone(),
                manifest_artifact: verified.reference().clone(),
                commit: committed.commit,
            }),
            error: None,
            extensions: Default::default(),
        };
        let response_bytes = serde_json::to_vec(&response).map_err(|error| error.to_string())?;
        mailbox
            .publish_receipt(
                &request.message_id,
                &response_bytes,
                crate::mailbox::unix_time_now()?,
            )
            .map_err(AgentMailboxProcessingError::LocalMailbox)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;

    #[test]
    fn completed_or_foreign_generation_runs_are_not_processed() {
        let root = tempfile::tempdir().unwrap();
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE agent_runs(agent_run_id TEXT PRIMARY KEY,state TEXT NOT NULL,controller_generation INTEGER NOT NULL);
             CREATE TABLE controller_owners(singleton INTEGER PRIMARY KEY,generation INTEGER NOT NULL,stopped_at_unix INTEGER);
             INSERT INTO controller_owners VALUES (1,7,NULL);
                 INSERT INTO agent_runs VALUES ('run-a','completed',7);
                 INSERT INTO agent_runs VALUES ('run-b','running',8);",
            )
            .unwrap();
        let mut store = crate::store::ConfigStore {
            connection,
            _machine_lock: crate::store::MachineLock { _file: None },
        };
        let artifact_store =
            crate::artifacts::ArtifactStore::open(&root.path().join("artifacts")).unwrap();

        assert!(
            !store
                .process_one_agent_mailbox_request(
                    7,
                    "run-a",
                    1,
                    &artifact_store,
                    &Default::default()
                )
                .unwrap()
        );
        assert!(
            !store
                .process_one_agent_mailbox_request(
                    7,
                    "run-b",
                    1,
                    &artifact_store,
                    &Default::default()
                )
                .unwrap()
        );
        assert!(
            store
                .process_one_agent_mailbox_request(
                    8,
                    "run-a",
                    1,
                    &artifact_store,
                    &Default::default()
                )
                .is_err()
        );
    }
}
