//! Host-side processing for bounded requests in a run-local Agent mailbox.
//!
//! Agents can only write the mailbox spool. This module checks the spool against the persisted
//! launch reservation and authority, then hands one supported request to its durable host API.

use rusqlite::OptionalExtension;
use sha2::{Digest as _, Sha256};

use crate::artifacts::ArtifactStore;
use crate::domain::ids::{AgentRunId, Digest, OperationId};
use crate::mailbox::{
    MailboxCapability, MailboxLimits, TerminalCommitReplay, TerminalCommitReplayInspection,
};

pub(crate) struct ValidatedTerminalCommitResponse {
    bytes: Vec<u8>,
}

impl ValidatedTerminalCommitResponse {
    fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MailboxDispatchMode {
    Running,
    TerminalReceiptReplay,
}

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
    /// Process at most one request for `agent_run_id`. Running launches may submit supported
    /// requests; a verified terminal run may only replay an already accepted commit receipt.
    /// All mailbox scope is resolved from durable host records, never Agent-selected authority.
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
        let Some((state, generation)) = active else {
            return Ok(false);
        };
        let active_state = state.clone();
        let mode = match active_state.as_str() {
            "running" if generation == owner_generation => MailboxDispatchMode::Running,
            "running" => {
                // Recovery must reconcile a previous owner's live run before its mailbox is eligible.
                return Ok(false);
            }
            "completed" => {
                crate::store::agent_results::verify_agent_terminal(
                    self,
                    owner_generation,
                    &AgentRunId::parse(agent_run_id.to_owned())?,
                )
                .map_err(AgentMailboxProcessingError::Authority)?;
                MailboxDispatchMode::TerminalReceiptReplay
            }
            _ => return Ok(false),
        };
        let run_id = AgentRunId::parse(agent_run_id.to_owned())?;
        let Some(authority) = self.agent_launch_authority(&run_id)? else {
            return Err("mailbox run has no persisted launch authority".into());
        };
        if mode == MailboxDispatchMode::Running {
            self.validate_mailbox_owner_generation(owner_generation, &authority)?;
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
                persisted_generation,
                project_id,
                config_revision,
                config_digest,
                role_session_id,
                operation_id,
                digest,
            )) => {
                run_state == active_state
                    // The second read must match the mutable owner snapshot observed above.
                    // A completed run can retain its launch or adopted generation after restart;
                    // its immutable terminal receipt, not a current slot lease, proves the end.
                    && persisted_generation == generation
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
            "SELECT EXISTS(SELECT 1 FROM rex_view_blocks blocks JOIN rex_views views USING(view_id) WHERE blocks.view_id=?1 AND blocks.block_id=?2 AND blocks.agent_run_id=?3 AND blocks.role=?4 AND blocks.ownership='factory' AND (?9=1 OR (blocks.lifecycle='active' AND views.lifecycle='active')) AND views.project_id=?5 AND views.rex_server_identity=?6 AND views.rex_session_id=?7 AND views.rex_window_id=?8)",
            rusqlite::params![authority.rex_view_id.as_str(),authority.rex_block_id,agent_run_id,serde_json::to_value(authority.role).map_err(|error| error.to_string())?.as_str().ok_or("role serialization is not a string")?,authority.project_id.as_str(),authority.rex_server_identity,authority.rex_session_id,authority.rex_window_id,mode == MailboxDispatchMode::TerminalReceiptReplay],
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
        let terminal_commit_replay = if now_unix.max(0) as u64 >= registration.expires_at_unix {
            if mode == MailboxDispatchMode::TerminalReceiptReplay {
                let canonical_control_directory = std::fs::canonicalize(&reservation.control_dir)
                    .map_err(|error| {
                    AgentMailboxProcessingError::LocalMailbox(format!(
                        "canonicalize registered control directory: {error}"
                    ))
                })?;
                let shared_control_layout =
                    canonical_mailbox_directory == canonical_control_directory;
                match mailbox.inspect_terminal_commit_replay(shared_control_layout) {
                    TerminalCommitReplayInspection::Drained => return Ok(false),
                    TerminalCommitReplayInspection::Ready(replay) => Some(replay),
                    TerminalCommitReplayInspection::Unresolved {
                        fingerprint,
                        reason,
                    } => {
                        return Err(AgentMailboxProcessingError::LocalMailbox(format!(
                            "expired terminal mailbox remains unresolved ({}; inventory {})",
                            reason.code(),
                            fingerprint
                        )));
                    }
                }
            } else {
                return Err(AgentMailboxProcessingError::LocalMailbox(
                    "mailbox capability has expired".into(),
                ));
            }
        } else {
            None
        };
        let mailbox_request = match terminal_commit_replay.as_ref() {
            Some(replay) => replay.request().clone(),
            None => {
                let Some(mailbox_request) = mailbox
                    .pending(now_unix.max(0) as u64)
                    .map_err(AgentMailboxProcessingError::LocalMailbox)?
                    .into_iter()
                    .next()
                else {
                    return Ok(false);
                };
                mailbox_request
            }
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
            let processed = self.process_repository_commit(
                owner_generation,
                &authority,
                &reservation,
                artifact_store,
                &mailbox,
                &mailbox_request,
                &request,
                required_trailer,
                mode,
                terminal_commit_replay.as_ref(),
            )?;
            if terminal_commit_replay.is_some() && !processed {
                return Err(AgentMailboxProcessingError::LocalMailbox(
                    "expired repository.commit request has no previously accepted terminal outcome"
                        .into(),
                ));
            }
            return Ok(processed);
        }
        if mode == MailboxDispatchMode::TerminalReceiptReplay {
            let response = crate::protocol::ResponseEnvelope {
                schema_version: crate::protocol::SCHEMA_VERSION,
                request_id: mailbox_request.envelope.request_id.clone(),
                result: None::<serde_json::Value>,
                error: Some(crate::protocol::ProtocolError {
                    code: crate::protocol::ErrorCode::Unsupported,
                    message: "terminal Agent runs cannot process new mailbox requests".into(),
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
        match self.process_artifact_add_for_agent(
            owner_generation,
            &authority,
            artifact_store,
            &mailbox,
            &mailbox_request,
            &request,
        ) {
            Ok(_) => Ok(true),
            Err(crate::artifacts::ArtifactRegistrationError::AgentSource(message)) => {
                let response = crate::protocol::ResponseEnvelope {
                    schema_version: crate::protocol::SCHEMA_VERSION,
                    request_id: mailbox_request.envelope.request_id.clone(),
                    result: None::<serde_json::Value>,
                    error: Some(crate::protocol::ProtocolError {
                        code: crate::protocol::ErrorCode::InvalidRequest,
                        message,
                        retryable: false,
                        retry_after_ms: None,
                        details: Default::default(),
                    }),
                    extensions: Default::default(),
                };
                let bytes = serde_json::to_vec(&response).map_err(|error| {
                    AgentMailboxProcessingError::Authority(format!(
                        "serialize ArtifactAdd rejection receipt: {error}"
                    ))
                })?;
                mailbox
                    .publish_receipt(&mailbox_request.request_id, &bytes, now_unix.max(0) as u64)
                    .map_err(|error| {
                        AgentMailboxProcessingError::Authority(format!(
                            "persist ArtifactAdd rejection receipt: {error}"
                        ))
                    })?;
                Ok(true)
            }
            Err(crate::artifacts::ArtifactRegistrationError::Host(error)) => {
                Err(AgentMailboxProcessingError::Authority(error))
            }
        }
    }

    fn validate_mailbox_owner_generation(
        &self,
        owner_generation: u64,
        authority: &crate::launch::AgentLaunchAuthority,
    ) -> Result<(), AgentMailboxProcessingError> {
        crate::store::agent_recovery::validate_agent_run_current_owner(
            &self.connection,
            &authority.agent_run_id,
            authority.controller_generation,
            owner_generation,
            &authority.digest()?,
            &authority.descriptor_digest,
        )
        .map_err(AgentMailboxProcessingError::Authority)
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
        mode: MailboxDispatchMode,
        expired_replay: Option<&TerminalCommitReplay<'_>>,
    ) -> Result<bool, AgentMailboxProcessingError> {
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
        let expected_head = match reservation.wake_snapshot.worker_recovery_authorization()? {
            Some(recovery) => {
                if recovery.ticket_run_id != *ticket_run_id
                    || recovery.ticket_revision != ticket_revision.0
                    || recovery.work_node_id != assignment.node_id
                    || recovery.accepted_plan_digest != assignment.plan_digest
                    || recovery.prior_worker_agent_run_id == authority.agent_run_id
                    || (recovery.prior_host_commit_operation_id.is_none()
                        && recovery.expected_head != assignment.expected_head())
                {
                    return Err(AgentMailboxProcessingError::Authority(
                        "Worker recovery authority differs from the immutable accepted assignment"
                            .into(),
                    ));
                }
                recovery.expected_head
            }
            None => assignment.expected_head().to_owned(),
        };
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
            || request.expected_head != expected_head
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
            manifest_digest: digest.clone(),
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
        } else if mode == MailboxDispatchMode::TerminalReceiptReplay {
            return Ok(false);
        } else {
            self.enqueue_effect(owner_generation, &intent)?;
        }
        let status: Option<(String, Option<String>, Option<String>)> = self
            .connection
            .query_row(
                "SELECT status,last_error,receipt_json FROM effects WHERE operation_id=?1",
                [&intent.operation_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if mode == MailboxDispatchMode::TerminalReceiptReplay {
            match status.as_ref().map(|(status, _, _)| status.as_str()) {
                Some("succeeded") => {
                    let Some(receipt) = self.succeeded_effect_receipt(&intent.operation_id)? else {
                        return Ok(false);
                    };
                    if receipt.intent() != &intent {
                        return Err(
                            "terminal repository.commit receipt has a different intent".into()
                        );
                    }
                }
                Some("failed")
                    if status
                        .as_ref()
                        .and_then(|(status, _, receipt)| {
                            terminal_rejected_commit_reason(status, receipt.as_deref())
                        })
                        .is_some() =>
                {
                    // A completed Worker may replay an already accepted terminal rejection.
                    // The exact immutable intent was checked above; this path never enqueues.
                }
                _ => return Ok(false),
            }
        }
        if let Some((status, last_error, receipt_json)) = status
            && matches!(status.as_str(), "failed" | "cancelled")
        {
            if mode == MailboxDispatchMode::TerminalReceiptReplay
                && terminal_rejected_commit_reason(&status, receipt_json.as_deref()).is_none()
            {
                return Ok(false);
            }
            let reason = persisted_rejection_reason(receipt_json.as_deref())
                .or(last_error)
                .unwrap_or_else(|| "effect was cancelled".into());
            let response = crate::protocol::ResponseEnvelope::<serde_json::Value> {
                schema_version: crate::protocol::SCHEMA_VERSION,
                request_id: mailbox_request.envelope.request_id.clone(),
                result: None,
                error: Some(crate::protocol::ProtocolError {
                    code: crate::protocol::ErrorCode::Unavailable,
                    message: format!("host repository.commit effect {status}: {reason}"),
                    retryable: false,
                    retry_after_ms: None,
                    details: Default::default(),
                }),
                extensions: Default::default(),
            };
            let bytes = serde_json::to_vec(&response).map_err(|error| error.to_string())?;
            if let Some(replay) = expired_replay {
                let validated = ValidatedTerminalCommitResponse::new(bytes);
                replay
                    .publish_response(&validated)
                    .map_err(AgentMailboxProcessingError::LocalMailbox)?;
            } else {
                mailbox
                    .publish_receipt(
                        &request.message_id,
                        &bytes,
                        crate::mailbox::unix_time_now()?,
                    )
                    .map_err(AgentMailboxProcessingError::LocalMailbox)?;
            }
            return Ok(true);
        }
        let Some(receipt) = self.succeeded_effect_receipt(&intent.operation_id)? else {
            // Keep the mailbox request pending. The normal dispatcher will execute/reconcile the
            // durable effect; this method will publish the receipt on a later controller pass.
            return Ok(false);
        };
        if receipt.intent() != &intent {
            return Err("repository.commit durable receipt has a different intent".into());
        }
        let committed: crate::delivery_runtime::CommitWorkerManifestEffectReceipt =
            crate::protocol::parse_unique(receipt.receipt_json().as_bytes())?;
        if committed.schema_version != 1
            || committed.agent_run_id != authority.agent_run_id
            || committed.message_id != request.message_id
            || committed.ticket_run_id != *ticket_run_id
            || committed.work_node_id != assignment.node_id
            || committed.repository_id != assignment.repository_id
            || committed.base_sha != assignment.base_sha
            || committed.manifest_artifact != *verified.reference()
            || committed.commit.operation_id != operation_id
            || committed.commit.repository_id != assignment.repository_id
            || committed.commit.manifest_digest != digest
            || committed.commit.expected_head != request.expected_head
            || committed.commit.observed_head == committed.commit.expected_head
            || !committed.commit.signature_verified
            || !committed.commit.hooks_completed
            || !committed.commit.index_synchronized
            || committed.commit.index_sync_conflict
        {
            return Err(
                "repository.commit durable receipt does not match its exact accepted intent".into(),
            );
        }
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
        if let Some(replay) = expired_replay {
            let validated = ValidatedTerminalCommitResponse::new(response_bytes);
            replay
                .publish_response(&validated)
                .map_err(AgentMailboxProcessingError::LocalMailbox)?;
        } else {
            mailbox
                .publish_receipt(
                    &request.message_id,
                    &response_bytes,
                    crate::mailbox::unix_time_now()?,
                )
                .map_err(AgentMailboxProcessingError::LocalMailbox)?;
        }
        Ok(true)
    }
}

fn persisted_rejection_reason(receipt_json: Option<&str>) -> Option<String> {
    let receipt: serde_json::Value =
        crate::protocol::parse_unique(receipt_json?.as_bytes()).ok()?;
    (receipt["schema_version"].as_u64() == Some(1)
        && receipt["outcome"].as_str() == Some("rejected"))
    .then(|| {
        receipt["reason"]
            .as_str()
            .filter(|reason| !reason.is_empty())
            .map(str::to_owned)
    })
    .flatten()
}

fn terminal_rejected_commit_reason(status: &str, receipt_json: Option<&str>) -> Option<String> {
    (status == "failed")
        .then(|| persisted_rejection_reason(receipt_json))
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    #[test]
    fn terminal_commit_replay_requires_a_persisted_typed_rejection_receipt() {
        let receipt = serde_json::json!({
            "schema_version": 1,
            "outcome": "rejected",
            "reason": "host commit message is missing the required authorship trailer"
        })
        .to_string();
        assert_eq!(
            persisted_rejection_reason(Some(&receipt)).as_deref(),
            Some("host commit message is missing the required authorship trailer")
        );
        assert!(persisted_rejection_reason(None).is_none());
        assert!(persisted_rejection_reason(Some("{} ")).is_none());
        assert!(
            persisted_rejection_reason(Some(
                r#"{"schema_version":1,"outcome":"applied","reason":"ok"}"#
            ))
            .is_none()
        );
        assert!(
            persisted_rejection_reason(Some(
                r#"{"schema_version":1,"outcome":"rejected","reason":""}"#
            ))
            .is_none()
        );
        assert_eq!(
            terminal_rejected_commit_reason("failed", Some(&receipt)).as_deref(),
            Some("host commit message is missing the required authorship trailer")
        );
        assert!(terminal_rejected_commit_reason("cancelled", Some(&receipt)).is_none());
        assert!(terminal_rejected_commit_reason("failed", None).is_none());
    }

    #[test]
    fn terminal_commit_replay_refuses_request_changed_after_inspection() {
        let temp = tempfile::tempdir().unwrap();
        let run_id = "terminal-replay-request-binding";
        let expires_at = crate::mailbox::unix_time_now().unwrap() + 60;
        let mailbox = MailboxCapability::create(
            run_id,
            &temp.path().join("mailbox"),
            expires_at,
            crate::mailbox::MailboxLimits::default(),
        )
        .unwrap();
        let request_id = "registered-commit-request";
        let envelope = crate::protocol::RequestEnvelope {
            schema_version: crate::protocol::SCHEMA_VERSION,
            request_id: crate::protocol::RequestId::new(request_id).unwrap(),
            operation_id: None,
            method: crate::protocol::MethodName::new("repository.commit").unwrap(),
            project_id: None,
            run_id: Some(run_id.into()),
            attempt: None,
            run_epoch: None,
            expected_subject_revision: None,
            role: None,
            request_type: None,
            params: serde_json::json!({"message_id": request_id}),
        };
        let request_bytes = serde_json::to_vec(&envelope).unwrap();
        mailbox
            .queue(
                request_id,
                &request_bytes,
                crate::mailbox::unix_time_now().unwrap(),
            )
            .unwrap();
        let replay = match mailbox.inspect_terminal_commit_replay(false) {
            TerminalCommitReplayInspection::Ready(replay) => replay,
            _ => panic!("expected one inspected repository.commit request"),
        };
        let response = crate::protocol::ResponseEnvelope::<serde_json::Value> {
            schema_version: crate::protocol::SCHEMA_VERSION,
            request_id: crate::protocol::RequestId::new(request_id).unwrap(),
            result: None,
            error: Some(crate::protocol::ProtocolError {
                code: crate::protocol::ErrorCode::Unavailable,
                message: "fixture validated terminal rejection".into(),
                retryable: false,
                retry_after_ms: None,
                details: Default::default(),
            }),
            extensions: Default::default(),
        };
        let proof = ValidatedTerminalCommitResponse::new(serde_json::to_vec(&response).unwrap());
        let mut changed_envelope = envelope;
        changed_envelope.params["message_id"] = serde_json::json!("changed-after-inspection");
        let changed_request = serde_json::to_vec(&changed_envelope).unwrap();
        std::fs::write(
            temp.path().join("mailbox").join(format!(
                "request-{:x}.json",
                Sha256::digest(request_id.as_bytes())
            )),
            changed_request,
        )
        .unwrap();

        assert!(
            replay
                .publish_response(&proof)
                .unwrap_err()
                .contains("request changed before response publication")
        );
        assert!(
            !temp
                .path()
                .join("mailbox")
                .join(format!(
                    "receipt-{:x}.json",
                    Sha256::digest(request_id.as_bytes())
                ))
                .exists()
        );
    }

    fn adopt_fixture_run(
        fixture: &mut crate::store::agent_runtime::tests::CompletedBlockLossFixture,
        root: &std::path::Path,
    ) -> u64 {
        use crate::store::OwnerMetadata;
        use sha2::{Digest as _, Sha256};

        let launch_generation = fixture.generation;
        let reservation = fixture
            .store
            .agent_launch_reservation_for_run(&fixture.run.agent_run_id)
            .unwrap()
            .unwrap();
        let authority = fixture.run.authority.clone();
        let generation = fixture
            .store
            .start_owner(&OwnerMetadata {
                owner_nonce: "artifact-mailbox-test-owner-restart".into(),
                state_root: root.join("state").display().to_string(),
                config_source: "factory".into(),
                process_start_identity: "artifact-mailbox-test-owner".into(),
                executable_path: "/tmp/rex-projects-fixture".into(),
                executable_digest: "b".repeat(64),
                rex_endpoint: Some("unix:///tmp/rex-test.sock".into()),
                rex_server_identity: Some("rex-instance".into()),
                rex_session_id: Some("session".into()),
                rex_block_id: None,
            })
            .unwrap();
        fixture
            .store
            .connection
            .execute(
                "UPDATE agent_runs SET state='unknown',controller_generation=?2 WHERE agent_run_id=?1",
                rusqlite::params![fixture.run.agent_run_id.as_str(), generation],
            )
            .unwrap();
        fixture
            .store
            .connection
            .execute(
                "UPDATE execution_slots SET disposition='unknown' WHERE owner_kind='agent_run' AND owner_id=?1",
                [fixture.run.agent_run_id.as_str()],
            )
            .unwrap();
        fixture
            .store
            .connection
            .execute(
                "UPDATE agent_launch_state SET provider_process_tree_json=?2 WHERE agent_run_id=?1",
                rusqlite::params![
                    fixture.run.agent_run_id.as_str(),
                    serde_json::to_string(&fixture.provider).unwrap(),
                ],
            )
            .unwrap();
        let mut process_tree = fixture
            .provider
            .process_tree
            .iter()
            .map(
                |process| crate::store::agent_recovery::AdoptedProcessIdentity {
                    pid: process.pid,
                    parent_pid: process.parent_pid,
                    process_group_id: process.process_group_id,
                    start_identity: process.start_identity.clone(),
                    identity_quality: serde_json::to_value(process.identity_quality)
                        .unwrap()
                        .as_str()
                        .unwrap()
                        .to_owned(),
                },
            )
            .filter(|process| process.pid != fixture.wrapper.pid)
            .collect::<Vec<_>>();
        process_tree.push(crate::store::agent_recovery::AdoptedProcessIdentity {
            pid: fixture.wrapper.pid,
            parent_pid: 1,
            process_group_id: fixture.wrapper.pid,
            start_identity: fixture.wrapper.start_identity.clone(),
            identity_quality: "kernel_birth_token".into(),
        });
        process_tree.sort_by_key(|process| process.pid);
        let evidence = crate::store::agent_recovery::AgentAdoptionEvidence {
            schema_version: 1,
            agent_run_id: fixture.run.agent_run_id.clone(),
            controller_generation: generation,
            previous_controller_generation: launch_generation,
            authority_digest: authority.digest().unwrap(),
            descriptor_digest: authority.descriptor_digest.clone(),
            rex_process_observation_digest: crate::domain::ids::Digest::parse("c".repeat(64))
                .unwrap(),
            process_tree_digest: crate::domain::ids::Digest::parse(format!(
                "{:x}",
                Sha256::digest(serde_json::to_vec(&process_tree).unwrap())
            ))
            .unwrap(),
            provider_start_tree_digest: fixture.provider.process_tree_digest.clone(),
            process_tree,
            wrapper_pid: fixture.wrapper.pid,
            wrapper_start_identity: fixture.wrapper.start_identity.clone(),
            provider_pid: fixture.provider.provider_pid,
            provider_start_identity: fixture.provider.provider_start_identity.clone(),
            observed_at_unix: 1,
        };
        assert!(
            fixture
                .store
                .record_agent_run_adoption(&evidence, fixture.run.reservation_epoch)
                .unwrap()
        );
        crate::mailbox::MailboxCapability::create(
            fixture.run.agent_run_id.to_string(),
            &reservation.mailbox_directory,
            reservation.mailbox_expires_at_unix,
            crate::mailbox::MailboxLimits {
                max_request_bytes: reservation.mailbox_max_request_bytes as usize,
                max_pending_requests: reservation.mailbox_max_pending_requests as usize,
            },
        )
        .unwrap();
        generation
    }

    fn queue_artifact_request(
        mailbox: &MailboxCapability,
        authority: &crate::launch::AgentLaunchAuthority,
        id: &str,
        path: &str,
    ) {
        queue_artifact_request_kind(
            mailbox,
            authority,
            id,
            path,
            crate::engine::orchestration::RoleArtifactKind::General,
        );
    }

    fn queue_artifact_request_kind(
        mailbox: &MailboxCapability,
        authority: &crate::launch::AgentLaunchAuthority,
        id: &str,
        path: &str,
        kind: crate::engine::orchestration::RoleArtifactKind,
    ) {
        let request = crate::engine::orchestration::ArtifactAddRequest {
            schema_version: 1,
            message_id: id.into(),
            path: path.into(),
            kind,
            artifact_schema_version: 1,
        };
        let envelope = crate::protocol::RequestEnvelope {
            schema_version: crate::protocol::SCHEMA_VERSION,
            request_id: crate::protocol::RequestId::new(id).unwrap(),
            operation_id: Some(authority.operation_id.clone()),
            method: crate::protocol::MethodName::new("artifact.add").unwrap(),
            project_id: Some(authority.project_id.clone()),
            run_id: Some(authority.agent_run_id.to_string()),
            attempt: Some(authority.attempt),
            run_epoch: Some(authority.run_epoch),
            expected_subject_revision: Some(
                authority.ticket_revision.map_or(0, |revision| revision.0),
            ),
            role: Some(authority.role),
            request_type: None,
            params: serde_json::to_value(request).unwrap(),
        };
        mailbox
            .queue(
                id,
                &serde_json::to_vec(&envelope).unwrap(),
                crate::mailbox::unix_time_now().unwrap(),
            )
            .unwrap();
    }

    #[test]
    fn artifact_source_rejection_is_durable_and_next_request_can_register() {
        let temp = tempfile::tempdir().unwrap();
        let mut fixture =
            crate::store::agent_runtime::tests::completed_block_loss_fixture(temp.path(), false);
        let generation = adopt_fixture_run(&mut fixture, temp.path());
        let authority = fixture.run.authority.clone();
        let reservation = fixture
            .store
            .agent_launch_reservation_for_run(&fixture.run.agent_run_id)
            .unwrap()
            .unwrap();
        let mailbox = crate::mailbox::MailboxCapability::open_registered_for_run(
            fixture.run.agent_run_id.to_string(),
            &reservation.mailbox_directory,
        )
        .unwrap();
        let artifact_store = ArtifactStore::open(&temp.path().join("artifacts")).unwrap();
        let control_only_path = "evidence.json";
        std::fs::write(
            authority.control_dir.join(control_only_path),
            br#"{"schema_version":1}"#,
        )
        .unwrap();
        queue_artifact_request(
            &mailbox,
            &authority,
            "missing-workspace-source",
            control_only_path,
        );
        assert!(
            fixture
                .store
                .process_one_agent_mailbox_request(
                    generation,
                    authority.agent_run_id.as_str(),
                    10,
                    &artifact_store,
                    &Default::default(),
                )
                .unwrap()
        );
        let rejected: crate::protocol::ResponseEnvelope<serde_json::Value> =
            crate::protocol::parse_unique(
                &mailbox
                    .read_receipt("missing-workspace-source", 10)
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
        let error = rejected.error.unwrap();
        assert_eq!(
            serde_json::to_value(error.code).unwrap(),
            serde_json::json!("invalid_request")
        );
        assert!(!error.retryable);
        assert_eq!(rejected.request_id.as_str(), "missing-workspace-source");

        std::fs::write(
            authority.workspace_path.join(control_only_path),
            br#"{"schema_version":1}"#,
        )
        .unwrap();
        queue_artifact_request(&mailbox, &authority, "workspace-source", control_only_path);
        assert!(
            fixture
                .store
                .process_one_agent_mailbox_request(
                    generation,
                    authority.agent_run_id.as_str(),
                    11,
                    &artifact_store,
                    &Default::default(),
                )
                .unwrap()
        );
        let registered: crate::protocol::ResponseEnvelope<serde_json::Value> =
            crate::protocol::parse_unique(
                &mailbox
                    .read_receipt("workspace-source", 11)
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
        assert!(registered.error.is_none());
        assert!(registered.result.unwrap()["artifact"]["artifact_id"].is_string());

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            symlink(
                authority.control_dir.join(control_only_path),
                authority.workspace_path.join("linked.json"),
            )
            .unwrap();
            queue_artifact_request(&mailbox, &authority, "symlink-source", "linked.json");
            assert!(
                fixture
                    .store
                    .process_one_agent_mailbox_request(
                        generation,
                        authority.agent_run_id.as_str(),
                        12,
                        &artifact_store,
                        &Default::default(),
                    )
                    .unwrap()
            );
            let symlink_response: crate::protocol::ResponseEnvelope<serde_json::Value> =
                crate::protocol::parse_unique(
                    &mailbox.read_receipt("symlink-source", 12).unwrap().unwrap(),
                )
                .unwrap();
            assert!(symlink_response.error.is_some());
        }

        std::fs::write(authority.workspace_path.join("invalid.json"), b"{invalid").unwrap();
        queue_artifact_request(&mailbox, &authority, "invalid-content", "invalid.json");
        assert!(
            fixture
                .store
                .process_one_agent_mailbox_request(
                    generation,
                    authority.agent_run_id.as_str(),
                    13,
                    &artifact_store,
                    &Default::default(),
                )
                .unwrap()
        );
        let invalid_response: crate::protocol::ResponseEnvelope<serde_json::Value> =
            crate::protocol::parse_unique(
                &mailbox
                    .read_receipt("invalid-content", 13)
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
        assert!(invalid_response.error.is_some());

        queue_artifact_request_kind(
            &mailbox,
            &authority,
            "unauthorized-artifact-kind",
            "valid.json",
            crate::engine::orchestration::RoleArtifactKind::Change,
        );
        assert!(
            fixture
                .store
                .process_one_agent_mailbox_request(
                    generation,
                    authority.agent_run_id.as_str(),
                    14,
                    &artifact_store,
                    &Default::default(),
                )
                .unwrap()
        );
        let unauthorized_response: crate::protocol::ResponseEnvelope<serde_json::Value> =
            crate::protocol::parse_unique(
                &mailbox
                    .read_receipt("unauthorized-artifact-kind", 14)
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
        let unauthorized_error = unauthorized_response.error.unwrap();
        assert_eq!(
            serde_json::to_value(unauthorized_error.code).unwrap(),
            serde_json::json!("invalid_request")
        );
        assert!(!unauthorized_error.retryable);

        std::fs::remove_dir_all(&authority.workspace_path).unwrap();
        queue_artifact_request(&mailbox, &authority, "host-workspace-failure", "valid.json");
        assert!(matches!(
            fixture.store.process_one_agent_mailbox_request(
                generation,
                authority.agent_run_id.as_str(),
                15,
                &artifact_store,
                &Default::default(),
            ),
            Err(AgentMailboxProcessingError::Authority(_))
        ));
        assert!(
            mailbox
                .read_receipt("host-workspace-failure", 15)
                .unwrap()
                .is_none()
        );
    }

    fn adoption_evidence(
        agent_run_id: &AgentRunId,
        controller_generation: u64,
        previous_controller_generation: u64,
        authority_digest: &Digest,
        descriptor_digest: &Digest,
    ) -> crate::store::agent_recovery::AgentAdoptionEvidence {
        use crate::store::agent_recovery::{AdoptedProcessIdentity, AgentAdoptionEvidence};

        AgentAdoptionEvidence {
            schema_version: 1,
            agent_run_id: agent_run_id.clone(),
            controller_generation,
            previous_controller_generation,
            authority_digest: authority_digest.clone(),
            descriptor_digest: descriptor_digest.clone(),
            rex_process_observation_digest: Digest::parse("a".repeat(64)).unwrap(),
            process_tree_digest: Digest::parse("b".repeat(64)).unwrap(),
            provider_start_tree_digest: Digest::parse("c".repeat(64)).unwrap(),
            process_tree: vec![
                AdoptedProcessIdentity {
                    pid: 100,
                    parent_pid: 1,
                    process_group_id: 100,
                    start_identity: "wrapper-start".into(),
                    identity_quality: "kernel_birth_token".into(),
                },
                AdoptedProcessIdentity {
                    pid: 101,
                    parent_pid: 100,
                    process_group_id: 100,
                    start_identity: "provider-start".into(),
                    identity_quality: "kernel_birth_token".into(),
                },
            ],
            wrapper_pid: 100,
            wrapper_start_identity: "wrapper-start".into(),
            provider_pid: 101,
            provider_start_identity: "provider-start".into(),
            observed_at_unix: 1,
        }
    }

    #[test]
    fn adopted_run_owner_requires_the_durable_immutable_authority_chain() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE agent_runs(agent_run_id TEXT PRIMARY KEY,controller_generation INTEGER);
                 INSERT INTO agent_runs VALUES ('worker-run',8);
                 CREATE TABLE agent_run_adoptions(agent_run_id TEXT,controller_generation INTEGER,previous_controller_generation INTEGER,authority_digest TEXT,descriptor_digest TEXT,evidence_digest TEXT,evidence_json TEXT);",
            )
            .unwrap();
        let agent_run_id = AgentRunId::parse("worker-run").unwrap();
        let authority_digest = Digest::parse("1".repeat(64)).unwrap();
        let descriptor_digest = Digest::parse("2".repeat(64)).unwrap();
        let evidence =
            adoption_evidence(&agent_run_id, 8, 7, &authority_digest, &descriptor_digest);
        connection
            .execute(
                "INSERT INTO agent_run_adoptions VALUES (?1,?2,?3,?4,?5,?6,?7)",
                rusqlite::params![
                    agent_run_id.as_str(),
                    evidence.controller_generation,
                    evidence.previous_controller_generation,
                    authority_digest.as_str(),
                    descriptor_digest.as_str(),
                    evidence.digest().unwrap().as_str(),
                    serde_json::to_string(&evidence).unwrap(),
                ],
            )
            .unwrap();

        assert!(
            crate::store::agent_recovery::validate_agent_run_current_owner(
                &connection,
                &agent_run_id,
                7,
                8,
                &authority_digest,
                &descriptor_digest,
            )
            .is_ok()
        );
        assert!(
            crate::store::agent_recovery::validate_agent_run_current_owner(
                &connection,
                &agent_run_id,
                7,
                9,
                &authority_digest,
                &descriptor_digest,
            )
            .is_err()
        );
        assert!(
            crate::store::agent_recovery::validate_agent_run_current_owner(
                &connection,
                &agent_run_id,
                7,
                8,
                &Digest::parse("3".repeat(64)).unwrap(),
                &descriptor_digest,
            )
            .is_err()
        );
    }

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
            store
                .process_one_agent_mailbox_request(
                    7,
                    "run-a",
                    1,
                    &artifact_store,
                    &Default::default()
                )
                .is_err()
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
