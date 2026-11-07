//! Host-verified terminal results from finite Agent runs.
//!
//! The file spool is input, not authority. A terminal capability is minted only after the
//! foreground controller binds a provider receipt to the persisted start request and launch
//! authority, checks the provider's process identities against the live process table, and
//! durably records that observation. Result messages are then validated and persisted atomically
//! with their parent wakes.

use std::fs::{self, OpenOptions};
use std::io::Read;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use sha2::{Digest as _, Sha256};

use crate::domain::ids::{AgentRunId, Digest, ProjectId, TicketRunId};
use crate::domain::types::Role;
use crate::engine::orchestration::{
    RoleResultBinding, RoleResultSubmission, ValidatedRoleResult, WakeSessionKey,
};
use crate::launch::{AgentLaunchAuthority, ProviderQualification};
use crate::roles::RoleResultMessage;
use crate::run_step::{CleanupState, TurnOutcome};
use crate::run_step_spool::{AgentTurnResult, StartRequestEnvelope};
use crate::store::ConfigStore;

const MAX_TERMINAL_BYTES: usize = 2 * 1024 * 1024;

/// An immutable host receipt proving that the persisted provider run completed and its observed
/// process tree is absent. Its private fields prevent callers from manufacturing or deserializing
/// terminal proof.
#[derive(Clone, Debug)]
pub struct VerifiedAgentTerminal {
    agent_run_id: AgentRunId,
    project_id: ProjectId,
    attempt: u32,
    controller_generation: u64,
    authority_digest: Digest,
    start_request_digest: Digest,
    terminal_digest: Digest,
    absence_digest: Digest,
    result: AgentTurnResult,
}

impl VerifiedAgentTerminal {
    pub fn agent_run_id(&self) -> &AgentRunId {
        &self.agent_run_id
    }

    pub fn terminal_digest(&self) -> &Digest {
        &self.terminal_digest
    }
}

/// Durable evidence receipt returned only after evidence and all derived wakes commit together.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredRoleResultReceipt {
    evidence_id: String,
    message_id: String,
    content_digest: Digest,
    terminal_digest: Digest,
    wake_input_ids: Vec<i64>,
}

impl StoredRoleResultReceipt {
    pub fn evidence_id(&self) -> &str {
        &self.evidence_id
    }

    pub fn message_id(&self) -> &str {
        &self.message_id
    }

    pub fn content_digest(&self) -> &Digest {
        &self.content_digest
    }

    pub fn terminal_digest(&self) -> &Digest {
        &self.terminal_digest
    }

    pub fn wake_input_ids(&self) -> &[i64] {
        &self.wake_input_ids
    }
}

#[derive(Clone, Debug)]
pub struct IngestedAgentResult {
    pub validated: ValidatedRoleResult,
    pub receipt: StoredRoleResultReceipt,
    /// Host-verified immutable objects for this exact result binding.
    pub verified_artifacts: Vec<crate::store::artifact_registry::VerifiedArtifact>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResultDisposition {
    Applied,
    RetainedAsClaim,
    RejectedByHost,
}

impl ResultDisposition {
    fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::RetainedAsClaim => "retained_as_claim",
            Self::RejectedByHost => "rejected_by_host",
        }
    }
}

/// Store a provider result only after exact launch matching and a fresh host process-table check.
/// Unknown cleanup, inspection failure, or a surviving process returns an error without releasing
/// execution capacity or making the result available to the reducer.
pub fn record_and_verify_agent_terminal(
    store: &mut ConfigStore,
    owner_generation: u64,
    start: &StartRequestEnvelope,
    result: &AgentTurnResult,
) -> Result<VerifiedAgentTerminal, String> {
    start.validate()?;
    let run_id = &start.request.agent_run_id;
    let authority = store
        .agent_launch_authority(run_id)?
        .ok_or("Agent terminal has no persisted launch authority")?;
    validate_request_authority(&authority, start)?;
    let qualification = load_qualification(&store.connection, &authority)?;
    validate_result_for_start(&authority, start, result, &qualification)?;
    validate_descriptor_and_projection(&authority, result, &qualification)?;
    let receipt_json = serde_json::to_vec(result).map_err(|error| error.to_string())?;
    if receipt_json.len() > MAX_TERMINAL_BYTES {
        return Err("Agent terminal receipt exceeds its storage limit".into());
    }
    let receipt_digest = digest(&receipt_json)?;
    let absence_digest = verify_process_tree_absent(&result.receipt.processes)?;
    let authority_digest = authority.digest()?;
    let now = unix_now()?;

    let tx = store
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| error.to_string())?;
    super::validate_active_generation(&tx, owner_generation)?;
    verify_persisted_authority(&tx, &authority, &authority_digest)?;
    verify_ticket_and_run_snapshot(&tx, &authority, owner_generation)?;
    let prior: Option<(String, String)> = tx
        .query_row(
            "SELECT terminal_digest,receipt_json FROM agent_terminal_receipts WHERE agent_run_id=?1",
            [run_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    let terminal_digest = receipt_digest;
    if let Some((stored_digest, stored_json)) = prior {
        if stored_digest != terminal_digest.as_str()
            || stored_json != String::from_utf8_lossy(&receipt_json)
        {
            return Err("AgentRun already has a different immutable terminal receipt".into());
        }
        tx.commit().map_err(|error| error.to_string())?;
        return verify_agent_terminal(store, owner_generation, run_id);
    }

    let launch_state: Option<(String, Option<String>, Option<String>)> = tx
        .query_row(
            "SELECT state,start_request_digest,provider_process_tree_json FROM agent_launch_state WHERE agent_run_id=?1",
            [run_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    let Some((state, stored_start_digest, process_tree_json)) = launch_state else {
        return Err("AgentRun has no persisted launch state".into());
    };
    if !matches!(state.as_str(), "running" | "unknown")
        || stored_start_digest.as_deref() != Some(start.request_digest.as_str())
    {
        return Err("Agent terminal does not match the persisted active start request".into());
    }
    verify_provider_start_observation(&authority, &process_tree_json, result, &qualification)?;

    tx.execute(
        "INSERT INTO agent_terminal_receipts(agent_run_id,project_id,attempt,controller_generation,authority_digest,start_request_digest,start_request_json,terminal_digest,result_digest,absence_digest,receipt_json,observed_at_unix) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
        params![run_id.as_str(), authority.project_id.as_str(), authority.attempt, authority.controller_generation, authority_digest.as_str(), start.request_digest, serde_json::to_string(start).map_err(|error| error.to_string())?, terminal_digest.as_str(), result.result_digest, absence_digest.as_str(), String::from_utf8_lossy(&receipt_json).as_ref(), now],
    )
    .map_err(|error| error.to_string())?;
    let terminal_request_digest = digest(&receipt_json)?;
    let changed = tx.execute(
        "UPDATE agent_launch_state SET state='completed',terminal_request_id=?2,terminal_request_digest=?3,result_digest=?4,result_receipt_json=?5,last_observed_at_unix=?6,updated_at_unix=?6 WHERE agent_run_id=?1 AND state IN ('running','unknown') AND start_request_digest=?7 AND result_receipt_json IS NULL",
        params![run_id.as_str(), authority.operation_id.as_str(), terminal_request_digest.as_str(), result.result_digest, String::from_utf8_lossy(&receipt_json).as_ref(), now, start.request_digest],
    ).map_err(|error| error.to_string())?;
    if changed != 1 {
        return Err("Agent launch state changed before terminal evidence was recorded".into());
    }
    let run_changed = tx.execute(
        "UPDATE agent_runs SET state='completed',finished_at_unix=COALESCE(finished_at_unix,?2) WHERE agent_run_id=?1 AND state IN ('running','unknown') AND controller_generation=?3",
        params![run_id.as_str(), now, authority.controller_generation],
    ).map_err(|error| error.to_string())?;
    if run_changed != 1 {
        return Err("AgentRun state changed before terminal evidence was recorded".into());
    }
    tx.execute(
        "UPDATE execution_slots SET disposition='released',controller_generation=?2 WHERE owner_id=(SELECT logical_owner FROM agent_runs WHERE agent_run_id=?1) AND project_id=?3 AND controller_generation=?2 AND disposition IN ('launch_pending','live','parked')",
        params![run_id.as_str(), owner_generation, authority.project_id.as_str()],
    )
    .map_err(|error| error.to_string())?;
    tx.commit().map_err(|error| error.to_string())?;

    verify_agent_terminal(store, owner_generation, run_id)
}

/// Re-read immutable terminal evidence and independently confirm that every process identity is
/// still absent. This is the only constructor for `VerifiedAgentTerminal`.
pub fn verify_agent_terminal(
    store: &ConfigStore,
    owner_generation: u64,
    agent_run_id: &AgentRunId,
) -> Result<VerifiedAgentTerminal, String> {
    let row: Option<(String, u32, u64, String, String, String, String, String, String, String)> = store
        .connection
        .query_row(
            "SELECT t.project_id,t.attempt,t.controller_generation,t.authority_digest,t.start_request_digest,t.start_request_json,t.terminal_digest,t.result_digest,t.absence_digest,t.receipt_json FROM agent_terminal_receipts t JOIN agent_launch_state s USING(agent_run_id) JOIN agent_runs r USING(agent_run_id) WHERE t.agent_run_id=?1 AND s.state='completed' AND r.state='completed' AND s.start_request_digest=t.start_request_digest AND s.result_digest=t.result_digest AND s.result_receipt_json=t.receipt_json",
            [agent_run_id.as_str()],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?,row.get(9)?)),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    let Some((
        project,
        attempt,
        generation,
        authority_digest,
        start_digest,
        start_json,
        terminal_digest,
        result_digest,
        absence_digest,
        receipt_json,
    )) = row
    else {
        return Err("AgentRun has no persisted verified terminal receipt".into());
    };
    let active_generation: Option<u64> = store.connection.query_row("SELECT generation FROM controller_owners WHERE singleton=1 AND stopped_at_unix IS NULL", [], |row| row.get(0)).optional().map_err(|error| error.to_string())?;
    if active_generation != Some(owner_generation) {
        return Err("terminal verification requires the active controller generation".into());
    }
    let result: AgentTurnResult = crate::protocol::parse_unique(receipt_json.as_bytes())?;
    if digest(receipt_json.as_bytes())?.as_str() != terminal_digest {
        return Err("stored Agent terminal receipt digest does not match its bytes".into());
    }
    let absent_now = verify_process_tree_absent(&result.receipt.processes)?;
    if absent_now.as_str() != absence_digest {
        return Err(
            "stored terminal process-absence evidence does not match a fresh observation".into(),
        );
    }
    let authority = store
        .agent_launch_authority(agent_run_id)?
        .ok_or("terminal receipt lost its launch authority")?;
    let start: StartRequestEnvelope = crate::protocol::parse_unique(start_json.as_bytes())?;
    start.validate()?;
    validate_request_authority(&authority, &start)?;
    let qualification = load_qualification(&store.connection, &authority)?;
    validate_result_for_start(&authority, &start, &result, &qualification)?;
    validate_descriptor_and_projection(&authority, &result, &qualification)?;
    let process_tree_json: Option<String> = store
        .connection
        .query_row(
            "SELECT provider_process_tree_json FROM agent_launch_state WHERE agent_run_id=?1",
            [agent_run_id.as_str()],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    verify_provider_start_observation(&authority, &process_tree_json, &result, &qualification)?;
    if result.start_request_digest != start.request_digest
        || result.result_digest != result_digest
        || result.receipt.result_digest.as_ref().is_none_or(|value| {
            value.as_str() != result_digest_of_structured(&result).unwrap_or_default()
        })
    {
        return Err(
            "persisted terminal payload result or start digest differs from immutable evidence"
                .into(),
        );
    }
    let expected_authority_digest = authority.digest()?;
    if authority.project_id.as_str() != project
        || authority.attempt != attempt
        || authority.controller_generation != generation
        || expected_authority_digest.as_str() != authority_digest
    {
        return Err("terminal receipt does not match immutable launch authority".into());
    }
    Ok(VerifiedAgentTerminal {
        agent_run_id: agent_run_id.clone(),
        project_id: authority.project_id,
        attempt,
        controller_generation: generation,
        authority_digest: expected_authority_digest,
        start_request_digest: Digest::parse(start_digest)?,
        terminal_digest: Digest::parse(terminal_digest)?,
        absence_digest: Digest::parse(absence_digest)?,
        result,
    })
}

/// Recovery-facing status check: no durable terminal means the run is still unresolved; a
/// persisted but invalid terminal is an error and must retain capacity for human inspection.
pub fn verify_agent_terminal_if_recorded(
    store: &ConfigStore,
    owner_generation: u64,
    agent_run_id: &AgentRunId,
) -> Result<Option<VerifiedAgentTerminal>, String> {
    let exists: bool = store
        .connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM agent_terminal_receipts WHERE agent_run_id=?1)",
            [agent_run_id.as_str()],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    if !exists {
        return Ok(None);
    }
    verify_agent_terminal(store, owner_generation, agent_run_id).map(Some)
}

/// Validate and atomically persist one role message and its derived parent wakes. Replays with
/// identical bytes return the original receipt; a reused message ID with changed content fails.
pub fn ingest_agent_result(
    store: &mut ConfigStore,
    artifact_store: &crate::artifacts::ArtifactStore,
    owner_generation: u64,
    terminal: &VerifiedAgentTerminal,
    message: RoleResultMessage,
) -> Result<IngestedAgentResult, String> {
    let active_generation: Option<u64> = store.connection.query_row("SELECT generation FROM controller_owners WHERE singleton=1 AND stopped_at_unix IS NULL", [], |row| row.get(0)).optional().map_err(|error| error.to_string())?;
    if active_generation != Some(owner_generation) {
        return Err("result ingestion requires the active controller generation".into());
    }
    let authority = store
        .agent_launch_authority(&terminal.agent_run_id)?
        .ok_or("result has no persisted launch authority")?;
    if authority.project_id != terminal.project_id
        || authority.attempt != terminal.attempt
        || authority.digest()? != terminal.authority_digest
    {
        return Err("verified terminal no longer matches launch authority".into());
    }
    let binding = binding_for(&authority)?;
    let validated = message.clone().bind(binding.clone())?;
    let terminal_role_message: RoleResultMessage = serde_json::from_value(
        terminal
            .result
            .structured_result
            .clone()
            .ok_or("completed Agent terminal has no structured result")?,
    )
    .map_err(|error| format!("provider result is not a role result message: {error}"))?;
    if terminal_role_message != message {
        return Err(
            "submitted role result differs from the persisted provider terminal payload".into(),
        );
    }
    let content_bytes = serde_json::to_vec(&(
        "rex-projects-role-result-v1",
        &binding,
        &validated.message_id,
        validated.kind,
        &validated.assertion,
        &validated.structured_result,
        &validated.result_digest,
        &validated.claimed_artifact_refs,
        &terminal.terminal_digest,
    ))
    .map_err(|error| error.to_string())?;
    let content_digest = digest(&content_bytes)?;
    let evidence_id = stable_evidence_id(
        &authority.agent_run_id,
        &validated.message_id,
        &content_digest,
    );
    let verified_artifacts = validated
        .claimed_artifact_refs
        .iter()
        .map(|reference| {
            store
                .lookup_verified_artifact(artifact_store, &authority, reference)?
                .ok_or_else(|| {
                    format!(
                        "artifact {} has no verified host registration",
                        reference.artifact_id
                    )
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let tx = store
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| error.to_string())?;
    super::validate_active_generation(&tx, owner_generation)?;
    verify_persisted_authority(&tx, &authority, &terminal.authority_digest)?;
    verify_terminal_row(&tx, terminal)?;
    verify_ticket_and_run_snapshot(&tx, &authority, owner_generation)?;
    verify_registered_artifacts(
        &tx,
        &authority,
        &validated.claimed_artifact_refs,
        &verified_artifacts,
    )?;
    if let Some((stored_id, stored_digest)) = tx
        .query_row(
            "SELECT evidence_id,content_digest FROM agent_result_evidence WHERE agent_run_id=?1 AND message_id=?2",
            params![authority.agent_run_id.as_str(), validated.message_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(|error| error.to_string())?
    {
        if stored_digest != content_digest.as_str() || stored_id != evidence_id {
            return Err("role result message ID was replayed with different content".into());
        }
        let receipt = load_stored_receipt(&tx, &evidence_id, &content_digest, &terminal.terminal_digest)?;
        tx.commit().map_err(|error| error.to_string())?;
        return Ok(IngestedAgentResult { validated, receipt, verified_artifacts });
    }

    let persisted_submission = RoleResultSubmission {
        schema_version: crate::engine::orchestration::ROLE_RESULT_SCHEMA_VERSION,
        message_id: validated.message_id.clone(),
        binding: validated.binding.clone(),
        kind: validated.kind,
        assertion: validated.assertion.clone(),
        structured_result: validated.structured_result.clone(),
        result_digest: validated.result_digest.clone(),
        artifact_refs: validated.claimed_artifact_refs.clone(),
    };
    let encoded_result =
        serde_json::to_string(&persisted_submission).map_err(|error| error.to_string())?;
    let artifact_refs_json = serde_json::to_string(&validated.claimed_artifact_refs)
        .map_err(|error| error.to_string())?;
    let now = unix_now()?;
    tx.execute(
        "INSERT INTO agent_result_evidence(evidence_id,agent_run_id,project_id,role,ticket_run_id,attempt,run_epoch,message_id,content_digest,outcome,result_digest,result_json,artifact_refs_json,received_at_unix) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,'completed',?10,?11,?12,?13)",
        params![evidence_id, authority.agent_run_id.as_str(), authority.project_id.as_str(), role_name(authority.role), authority.ticket_run_id.as_ref().map(TicketRunId::as_str), authority.attempt, authority.run_epoch, validated.message_id, content_digest.as_str(), validated.result_digest.as_str(), encoded_result, artifact_refs_json, now],
    ).map_err(|error| error.to_string())?;
    let wake_input_ids = insert_derived_wakes(
        &tx,
        &authority,
        &validated,
        &evidence_id,
        &terminal.terminal_digest,
        &terminal.absence_digest,
        now,
    )?;
    let receipt = StoredRoleResultReceipt {
        evidence_id,
        message_id: validated.message_id.clone(),
        content_digest,
        terminal_digest: terminal.terminal_digest.clone(),
        wake_input_ids,
    };
    tx.commit().map_err(|error| error.to_string())?;
    Ok(IngestedAgentResult {
        validated,
        receipt,
        verified_artifacts,
    })
}

/// Replay result evidence that the FactoryRuntime has not acknowledged after its semantic
/// transition. Replaying through the normal validator keeps the reducer input typed and idempotent.
pub fn pending_agent_results(
    store: &mut ConfigStore,
    artifact_store: &crate::artifacts::ArtifactStore,
    owner_generation: u64,
    limit: usize,
) -> Result<Vec<IngestedAgentResult>, String> {
    if limit == 0 || limit > 256 {
        return Err("pending Agent result limit must be between 1 and 256".into());
    }
    let ids = {
        let mut statement = store.connection.prepare(
            "SELECT e.evidence_id,e.agent_run_id,e.message_id FROM agent_result_evidence e LEFT JOIN agent_result_reducer_ack a USING(evidence_id) WHERE a.evidence_id IS NULL ORDER BY e.received_at_unix,e.evidence_id LIMIT ?1",
        ).map_err(|error| error.to_string())?;
        statement
            .query_map([limit as u64], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?
    };
    let mut results = Vec::with_capacity(ids.len());
    for (evidence_id, run_id, message_id) in ids {
        let run_id = AgentRunId::parse(run_id)?;
        let submission: RoleResultSubmission = {
            let json: String = store
                .connection
                .query_row(
                    "SELECT result_json FROM agent_result_evidence WHERE evidence_id=?1",
                    [&evidence_id],
                    |row| row.get(0),
                )
                .map_err(|error| error.to_string())?;
            crate::protocol::parse_unique(json.as_bytes())?
        };
        if submission.message_id != message_id {
            return Err("stored role result message ID differs from evidence key".into());
        }
        let authority = store
            .agent_launch_authority(&run_id)?
            .ok_or("pending evidence has no launch authority")?;
        let terminal = verify_agent_terminal(store, owner_generation, &run_id)?;
        let message = RoleResultMessage {
            schema_version: submission.schema_version,
            message_id: submission.message_id,
            kind: submission.kind,
            assertion: submission.assertion,
            structured_result: submission.structured_result,
            result_digest: submission.result_digest,
            artifact_refs: submission.artifact_refs,
        };
        if binding_for(&authority)? != submission.binding {
            return Err(
                "pending result binding no longer matches immutable launch authority".into(),
            );
        }
        let replayed =
            ingest_agent_result(store, artifact_store, owner_generation, &terminal, message)?;
        if replayed.receipt.evidence_id != evidence_id {
            return Err("pending result replay resolved to a different evidence ID".into());
        }
        results.push(replayed);
    }
    Ok(results)
}

/// Resolve a pending wake to its persisted source result, revalidating the host terminal receipt,
/// immutable launch authority, and every registered artifact before returning typed material.
/// The wake's payload is intentionally not used as authority.
pub fn agent_result_for_wake(
    store: &mut ConfigStore,
    artifact_store: &crate::artifacts::ArtifactStore,
    owner_generation: u64,
    wake_input_id: i64,
) -> Result<Option<IngestedAgentResult>, String> {
    if wake_input_id <= 0 {
        return Err("Agent result wake ID must be positive".into());
    }
    let source = store
        .connection
        .query_row(
            "SELECT e.evidence_id,e.agent_run_id,e.message_id,e.result_json \
         FROM role_wake_inputs w \
         JOIN agent_result_wakes aw ON aw.wake_input_id=w.wake_input_id \
         JOIN agent_result_evidence e ON e.evidence_id=aw.evidence_id \
         WHERE w.wake_input_id=?1 AND w.source_type='agent_result' \
           AND w.lifecycle IN ('pending','assigned')",
            [wake_input_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .optional()
        .map_err(|error| error.to_string())?;
    let Some((evidence_id, run_id, message_id, json)) = source else {
        return Ok(None);
    };
    let run_id = AgentRunId::parse(run_id)?;
    let submission: RoleResultSubmission = crate::protocol::parse_unique(json.as_bytes())?;
    if submission.message_id != message_id {
        return Err("stored role result message ID differs from wake source evidence".into());
    }
    let authority = store
        .agent_launch_authority(&run_id)?
        .ok_or("Agent result wake source has no launch authority")?;
    if authority.controller_generation != owner_generation
        || binding_for(&authority)? != submission.binding
    {
        return Err("Agent result wake source no longer matches its launch authority".into());
    }
    let terminal = verify_agent_terminal(store, owner_generation, &run_id)?;
    let message = RoleResultMessage {
        schema_version: submission.schema_version,
        message_id: submission.message_id,
        kind: submission.kind,
        assertion: submission.assertion,
        structured_result: submission.structured_result,
        result_digest: submission.result_digest,
        artifact_refs: submission.artifact_refs,
    };
    let replayed =
        ingest_agent_result(store, artifact_store, owner_generation, &terminal, message)?;
    if replayed.receipt.evidence_id != evidence_id {
        return Err("Agent result wake resolved to different immutable evidence".into());
    }
    Ok(Some(replayed))
}

/// Poll a bounded set of launched Agent control directories and ingest at most one new result.
/// Existing unacknowledged evidence is replayed first so the semantic consumer can finish after a
/// crash without waiting for the Agent to publish again.
pub fn ingest_next_spooled_agent_result(
    store: &mut ConfigStore,
    artifact_store: &crate::artifacts::ArtifactStore,
    owner_generation: u64,
    candidate_limit: usize,
) -> Result<Option<IngestedAgentResult>, String> {
    if candidate_limit == 0 || candidate_limit > 128 {
        return Err("Agent result candidate limit must be between 1 and 128".into());
    }
    if let Some(existing) = pending_agent_results(store, artifact_store, owner_generation, 1)?
        .into_iter()
        .next()
    {
        return Ok(Some(existing));
    }

    let candidates = {
        let mut statement = store.connection.prepare(
            "SELECT a.agent_run_id,a.control_dir FROM agent_launch_authority a \
             JOIN agent_launch_state s USING(agent_run_id) \
             WHERE a.controller_generation=?1 AND s.state IN ('running','unknown') \
               AND NOT EXISTS(SELECT 1 FROM agent_terminal_receipts t WHERE t.agent_run_id=a.agent_run_id) \
             ORDER BY s.updated_at_unix,a.agent_run_id LIMIT ?2",
        ).map_err(|error| error.to_string())?;
        statement
            .query_map(params![owner_generation, candidate_limit as u64], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?
    };

    for (run_id, control_dir) in candidates {
        let run_id = AgentRunId::parse(run_id)?;
        let spool = crate::run_step_spool::RunStepSpool::open(Path::new(&control_dir))?;
        let start = match spool.read_start_request() {
            Ok(start) => start,
            Err(error) if error == "run-step spool file is not present" => continue,
            Err(error) => return Err(format!("Agent {} start spool: {error}", run_id)),
        };
        if start.request.agent_run_id != run_id {
            return Err("Agent start spool is in a different registered control directory".into());
        }
        let terminal_result = match spool.read_turn_result(&start) {
            Ok(result) => result,
            Err(error) if error == "run-step spool file is not present" => continue,
            Err(error) => return Err(format!("Agent {} result spool: {error}", run_id)),
        };
        let terminal =
            record_and_verify_agent_terminal(store, owner_generation, &start, &terminal_result)?;
        let message: RoleResultMessage = serde_json::from_value(
            terminal_result
                .structured_result
                .clone()
                .ok_or("completed Agent result has no structured role result")?,
        )
        .map_err(|error| format!("Agent {} role result is invalid: {error}", run_id))?;
        return ingest_agent_result(store, artifact_store, owner_generation, &terminal, message)
            .map(Some);
    }
    Ok(None)
}

/// Mark a typed result consumed after the FactoryRuntime has committed its reducer transition.
/// Repeating the same acknowledgement is safe; changing its reducer revision is rejected.
pub fn acknowledge_agent_result(
    store: &mut ConfigStore,
    owner_generation: u64,
    evidence_id: &str,
    reducer_revision: u64,
    disposition: ResultDisposition,
) -> Result<(), String> {
    if reducer_revision == 0 {
        return Err("result reducer revision must be positive".into());
    }
    let tx = store
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| error.to_string())?;
    super::validate_active_generation(&tx, owner_generation)?;
    let existing: Option<(u64,String)> = tx.query_row("SELECT reducer_revision,disposition FROM agent_result_reducer_ack WHERE evidence_id=?1", [evidence_id], |row| Ok((row.get(0)?,row.get(1)?))).optional().map_err(|error| error.to_string())?;
    if let Some((revision, stored_disposition)) = existing {
        if revision != reducer_revision || stored_disposition != disposition.as_str() {
            return Err(
                "Agent result was already acknowledged with a different reducer disposition".into(),
            );
        }
        tx.commit().map_err(|error| error.to_string())?;
        return Ok(());
    }
    let now = unix_now()?;
    let changed = tx.execute("INSERT INTO agent_result_reducer_ack(evidence_id,reducer_revision,disposition,acknowledged_at_unix) SELECT evidence_id,?2,?3,?4 FROM agent_result_evidence WHERE evidence_id=?1", params![evidence_id,reducer_revision,disposition.as_str(),now]).map_err(|error| error.to_string())?;
    if changed != 1 {
        return Err("cannot acknowledge missing role result evidence".into());
    }
    tx.commit().map_err(|error| error.to_string())
}

/// Recover the ACK when a role transition committed but the process stopped before its separate
/// result acknowledgement. The persisted transition inbox and source evidence bind the replay.
pub fn acknowledge_committed_role_result(
    store: &mut ConfigStore,
    owner_generation: u64,
    result_kind: &str,
    evidence_id: &str,
    result_digest: &Digest,
    project_id: &ProjectId,
    ticket_run_id: &TicketRunId,
) -> Result<bool, String> {
    let (message_prefix, role, transitions): (&str, &str, &[&str]) = match result_kind {
        "plan_accepted" => ("plan-ready:", "coordinator", &["plan_accepted"]),
        "worker_implementation_ready" => (
            "implementation-ready:",
            "worker",
            &["worker_implementation_ready"],
        ),
        "review_assessment" => (
            "review-ready:",
            "reviewer",
            &[
                "corrections_remain",
                "review_converged",
                "review_round_limit_reached",
            ],
        ),
        _ => return Err("unsupported committed Agent result transition kind".into()),
    };
    let message_id = format!("{message_prefix}{evidence_id}");
    let tx = store
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| error.to_string())?;
    super::validate_active_generation(&tx, owner_generation)?;
    let committed: Option<(String, String, String)> = tx
        .query_row(
            "SELECT content_digest,payload_json,receipt_json FROM inbox WHERE producer_id='rex-projects-agent-result' AND message_id=?1",
            [&message_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    let Some((content_digest, payload, receipt)) = committed else {
        return Ok(false);
    };
    if crate::store::durable_input_digest("ticket_run", &payload) != content_digest {
        return Err("committed Agent transition has an invalid durable input digest".into());
    }
    let payload_value: serde_json::Value = crate::protocol::parse_unique(payload.as_bytes())?;
    let source_revision = payload_value["source_revision"]
        .as_u64()
        .ok_or("committed Agent transition has no source revision")?;
    let accepted_revision = payload_value["accepted_revision"]
        .as_u64()
        .ok_or("committed Agent transition has no accepted revision")?;
    if payload_value["schema_version"].as_u64() != Some(1)
        || payload_value["kind"].as_str() != Some(result_kind)
        || payload_value["evidence_id"].as_str() != Some(evidence_id)
        || payload_value["result_digest"].as_str() != Some(result_digest.as_str())
        || source_revision.checked_add(1) != Some(accepted_revision)
        || !payload_value["transition"]
            .as_str()
            .is_some_and(|transition| transitions.contains(&transition))
    {
        return Err("committed Agent result transition does not match the pending result".into());
    }
    let receipt_value: serde_json::Value = crate::protocol::parse_unique(receipt.as_bytes())?;
    if receipt_value["project_id"].as_str() != Some(project_id.as_str())
        || receipt_value["ticket_run_id"].as_str() != Some(ticket_run_id.as_str())
        || receipt_value["revision"].as_u64() != Some(accepted_revision)
    {
        return Err(
            "committed Agent result transition receipt has a different subject or revision".into(),
        );
    }
    let source: Option<(String, String, Option<String>, Option<u64>, String)> = tx
        .query_row(
            "SELECT e.project_id,e.role,e.ticket_run_id,a.ticket_revision,e.result_digest FROM agent_result_evidence e JOIN agent_launch_authority a USING(agent_run_id) WHERE e.evidence_id=?1",
            [evidence_id],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    let Some((source_project, source_role, source_ticket, evidence_revision, source_digest)) =
        source
    else {
        return Err("committed Agent result transition has no persisted source evidence".into());
    };
    if source_project != project_id.as_str()
        || source_role != role
        || source_ticket.as_deref() != Some(ticket_run_id.as_str())
        || evidence_revision != Some(source_revision)
        || source_digest != result_digest.as_str()
    {
        return Err(
            "committed Agent result transition differs from its immutable source evidence".into(),
        );
    }
    if result_kind == "plan_accepted" {
        let accepted: Option<String> = tx
            .query_row(
                "SELECT source_evidence_id FROM accepted_work_plans WHERE project_id=?1 AND ticket_run_id=?2 AND accepted_revision=?3",
                params![project_id.as_str(),ticket_run_id.as_str(),accepted_revision],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if accepted.as_deref() != Some(evidence_id) {
            return Err("committed PlanAccepted transition has no matching accepted plan".into());
        }
        let operation_id = format!("prepare-{evidence_id}");
        let effect_exists: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM effects WHERE operation_id=?1 AND project_id=?2 AND subject_type='ticket_run' AND subject_id=?3 AND kind='prepare_worktrees' AND expected_revision=?4)",
                params![operation_id,project_id.as_str(),ticket_run_id.as_str(),accepted_revision],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        if !effect_exists {
            return Err("committed PlanAccepted transition has no matching prepare effect".into());
        }
    } else if result_kind == "worker_implementation_ready" {
        let operation_id = payload_value["publication_operation_id"]
            .as_str()
            .ok_or("committed Worker transition has no publication operation")?;
        let receipt_effects = receipt_value["effects"]
            .as_array()
            .ok_or("committed Worker transition receipt has no effect list")?;
        if !receipt_effects
            .iter()
            .any(|effect| effect.as_str() == Some(operation_id))
        {
            return Err("committed Worker transition receipt omits its publication effect".into());
        }
    }
    let existing: Option<(u64, String)> = tx
        .query_row(
            "SELECT reducer_revision,disposition FROM agent_result_reducer_ack WHERE evidence_id=?1",
            [evidence_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    if let Some((revision, disposition)) = existing {
        if revision != accepted_revision || disposition != "applied" {
            return Err("Agent result already has a different reducer acknowledgement".into());
        }
    } else {
        let changed = tx
            .execute(
                "INSERT INTO agent_result_reducer_ack(evidence_id,reducer_revision,disposition,acknowledged_at_unix) SELECT evidence_id,?2,'applied',?3 FROM agent_result_evidence WHERE evidence_id=?1",
                params![evidence_id, accepted_revision, unix_now()?],
            )
            .map_err(|error| error.to_string())?;
        if changed != 1 {
            return Err("cannot acknowledge missing Reviewer result evidence".into());
        }
    }
    tx.commit().map_err(|error| error.to_string())?;
    Ok(true)
}

pub(crate) fn migrate_v12_tables(tx: &Transaction<'_>) -> Result<(), String> {
    tx.execute_batch(
        "ALTER TABLE agent_result_wakes RENAME TO agent_result_wakes_v7;
        CREATE TABLE agent_result_wakes (
            evidence_id TEXT NOT NULL REFERENCES agent_result_evidence(evidence_id),
            recipient_type TEXT NOT NULL CHECK(recipient_type IN ('coordinator','supervisor')),
            recipient_id TEXT NOT NULL,
            wake_input_id INTEGER REFERENCES role_wake_inputs(wake_input_id),
            queued_at_unix INTEGER NOT NULL,
            PRIMARY KEY(evidence_id,recipient_type,recipient_id)
        );
        INSERT INTO agent_result_wakes(evidence_id,recipient_type,recipient_id,wake_input_id,queued_at_unix)
            SELECT evidence_id,recipient_type,recipient_id,wake_input_id,queued_at_unix FROM agent_result_wakes_v7;
        DROP TABLE agent_result_wakes_v7;
        CREATE TABLE agent_terminal_receipts (
            agent_run_id TEXT PRIMARY KEY REFERENCES agent_launch_authority(agent_run_id),
            project_id TEXT NOT NULL REFERENCES projects(project_id),
            attempt INTEGER NOT NULL CHECK(attempt > 0),
            controller_generation INTEGER NOT NULL CHECK(controller_generation > 0),
            authority_digest TEXT NOT NULL CHECK(length(authority_digest)=64),
            start_request_digest TEXT NOT NULL CHECK(length(start_request_digest)=64),
            start_request_json TEXT NOT NULL CHECK(length(start_request_json)<=32768),
            terminal_digest TEXT NOT NULL CHECK(length(terminal_digest)=64),
            result_digest TEXT NOT NULL CHECK(length(result_digest)=64),
            absence_digest TEXT NOT NULL CHECK(length(absence_digest)=64),
            receipt_json TEXT NOT NULL CHECK(length(receipt_json)<=2097152),
            observed_at_unix INTEGER NOT NULL
        );
        CREATE TRIGGER agent_terminal_receipts_immutable_update BEFORE UPDATE ON agent_terminal_receipts BEGIN SELECT RAISE(ABORT,'Agent terminal receipts are immutable'); END;
        CREATE TRIGGER agent_terminal_receipts_immutable_delete BEFORE DELETE ON agent_terminal_receipts BEGIN SELECT RAISE(ABORT,'Agent terminal receipts are retained'); END;
        CREATE TABLE agent_result_reducer_ack (
            evidence_id TEXT PRIMARY KEY REFERENCES agent_result_evidence(evidence_id),
            reducer_revision INTEGER NOT NULL CHECK(reducer_revision > 0),
            disposition TEXT NOT NULL CHECK(disposition IN ('applied','retained_as_claim','rejected_by_host')),
            acknowledged_at_unix INTEGER NOT NULL
        );",
    )
    .map_err(|error| error.to_string())
}

fn validate_request_authority(
    authority: &AgentLaunchAuthority,
    start: &StartRequestEnvelope,
) -> Result<(), String> {
    let request = &start.request;
    if request.agent_run_id != authority.agent_run_id
        || request.operation_id != authority.operation_id
        || request.project_id != authority.project_id
        || request.controller_generation != authority.controller_generation
        || request.descriptor_digest != authority.descriptor_digest
        || request.runtime_binary_digest != authority.runtime_binary_digest
        || request.environment_snapshot_id != authority.environment_snapshot_id
        || request.qualification_receipt_digest != authority.qualification_receipt_digest
        || request.rex_session_id != authority.rex_session_id
        || request.rex_block_id != authority.rex_block_id
    {
        return Err("start request does not exactly match the immutable launch authority".into());
    }
    Ok(())
}

fn validate_result_for_start(
    authority: &AgentLaunchAuthority,
    start: &StartRequestEnvelope,
    result: &AgentTurnResult,
    qualification: &ProviderQualification,
) -> Result<(), String> {
    result.validate_for(start)?;
    let receipt = &result.receipt;
    let expected_result_digest = result_digest_of_structured(result)?;
    if receipt.run_id != authority.agent_run_id
        || receipt.attempt != authority.attempt
        || receipt.provider != qualification.adapter
        || receipt.capability_receipt_digest.as_ref()
            != Some(&authority.qualification_receipt_digest)
        || !matches!(receipt.outcome, TurnOutcome::Completed)
        || !matches!(receipt.cleanup, CleanupState::Confirmed)
        || receipt.timed_out
        || receipt.exit_code != Some(0)
        || receipt.cancellation_signal.is_some()
        || receipt
            .result_digest
            .as_ref()
            .is_none_or(|value| value.as_str() != expected_result_digest)
    {
        return Err(
            "provider run receipt is not an exact successful terminal for this launch".into(),
        );
    }
    Ok(())
}

fn validate_descriptor_and_projection(
    authority: &AgentLaunchAuthority,
    result: &AgentTurnResult,
    qualification: &ProviderQualification,
) -> Result<(), String> {
    let bytes = read_regular_file(&authority.descriptor_path, 8 * 1024 * 1024)?;
    if digest(&bytes)? != authority.descriptor_digest {
        return Err("persisted run-step package digest does not match launch authority".into());
    }
    let package: crate::run_step_package::RunStepPackage = crate::protocol::parse_unique(&bytes)?;
    package.validate()?;
    let descriptor = &package.descriptor;
    let capability = &descriptor.provider_capability;
    if package.operation_id != authority.operation_id
        || package.project_id != authority.project_id
        || package.controller_generation != authority.controller_generation
        || package.runtime_binary_digest != authority.runtime_binary_digest
        || package.qualification_receipt_digest != authority.qualification_receipt_digest
        || package.rex_server_identity != authority.rex_server_identity
        || package.rex_window_id != authority.rex_window_id
        || package.qualification_receipt_digest != qualification.canonical_digest()?
        || package.profile.adapter != qualification.adapter
        || package.profile.commit_mode != qualification.commit_mode
        || capability.adapter != qualification.adapter
        || capability.executable_path != qualification.executable_path
        || capability.executable_digest != qualification.executable_digest
        || capability.version != qualification.provider_version
        || capability.permission_mode != qualification.permission_mode
        || capability.invocation_options_digest != qualification.invocation_options_digest
        || capability.commit_mode != qualification.commit_mode
        || capability.profile_digest != qualification.profile_digest
        || capability.receipt_digest != authority.qualification_receipt_digest
        || capability.status != crate::run_step::ProviderQualificationStatus::Verified
    {
        return Err("run-step package does not match immutable launch authority".into());
    }
    if descriptor.run_id != authority.agent_run_id
        || descriptor.project_id != authority.project_id
        || descriptor.role != authority.role
        || descriptor.ticket_run_id != authority.ticket_run_id
        || descriptor.attempt != authority.attempt
        || descriptor.run_epoch != authority.run_epoch
        || descriptor.controller_generation != authority.controller_generation
        || descriptor.workspace != authority.workspace_path
        || descriptor.control_dir != authority.control_dir
        || descriptor.wake_snapshot_digest != authority.wake_snapshot_digest
        || descriptor.profile_digest != authority.profile_digest
        || descriptor.instruction_digest != authority.instruction_digest
        || descriptor.environment_snapshot_id != authority.environment_snapshot_id
        || descriptor.rex_session_id != authority.rex_session_id
        || descriptor.rex_block_id.as_str() != authority.rex_block_id
    {
        return Err("run-step package descriptor does not match persisted launch authority".into());
    }
    let expected_projection =
        crate::providers::project_result_schema(&descriptor.result_schema)?.identity;
    if result.receipt.schema_projection != expected_projection
        || expected_projection.source_schema_digest != authority.result_schema_digest
        || descriptor.provider_capability.schema_projection != expected_projection
        || descriptor.provider_capability.receipt_digest != authority.qualification_receipt_digest
    {
        return Err("provider result schema projection does not match launch authority".into());
    }
    Ok(())
}

fn verify_provider_start_observation(
    authority: &AgentLaunchAuthority,
    process_tree_json: &Option<String>,
    result: &AgentTurnResult,
    qualification: &ProviderQualification,
) -> Result<(), String> {
    let json = process_tree_json
        .as_deref()
        .ok_or("launch has no persisted provider process observation")?;
    let observation: crate::launch::ObservedProviderStart =
        crate::protocol::parse_unique(json.as_bytes())?;
    if observation.agent_run_id != authority.agent_run_id
        || observation.operation_id != authority.operation_id
        || observation.executable_digest != qualification.executable_digest
        || !observation.process_tree_confirmed
    {
        return Err("persisted provider process observation does not match terminal run".into());
    }
    if result
        .receipt
        .launch_pid_hint
        .is_some_and(|pid| pid != observation.provider_pid)
    {
        return Err("provider terminal PID does not match observed launch process".into());
    }
    if !process_tree_contains_root(
        &result.receipt.processes,
        observation.provider_pid,
        &observation.provider_start_identity,
    ) {
        return Err(
            "terminal process list omits the host-observed provider process identity".into(),
        );
    }
    Ok(())
}

fn process_tree_contains_root(
    processes: &[crate::run_step::ObservedProcess],
    provider_pid: u32,
    provider_start_identity: &str,
) -> bool {
    processes.iter().any(|process| {
        process.pid == provider_pid
            && process.start_identity == provider_start_identity
            && process.identity_quality == "kernel_birth_token"
    })
}

fn verify_process_tree_absent(
    processes: &[crate::run_step::ObservedProcess],
) -> Result<Digest, String> {
    if processes.is_empty() {
        return Err("terminal receipt has no observed provider process identities".into());
    }
    let mut identities = Vec::with_capacity(processes.len());
    for process in processes {
        if process.pid == 0
            || process.start_identity.trim().is_empty()
            || process.identity_quality != "kernel_birth_token"
        {
            return Err("terminal process cleanup lacks stable kernel identity".into());
        }
        identities.push((process.pid, process.start_identity.as_str()));
    }
    identities.sort_unstable();
    identities.dedup();
    let current = crate::process::inspect_process_table()
        .map_err(|error| format!("inspect process table for terminal cleanup: {error}"))?;
    if current.iter().any(|item| {
        identities
            .iter()
            .any(|(pid, start)| item.pid == *pid && item.start_identity == *start)
    }) {
        return Err(
            "provider process tree is still present; terminal result remains unresolved".into(),
        );
    }
    digest(
        &serde_json::to_vec(&("rex-projects-process-absence-v1", identities))
            .map_err(|error| error.to_string())?,
    )
}

fn binding_for(authority: &AgentLaunchAuthority) -> Result<RoleResultBinding, String> {
    Ok(RoleResultBinding {
        agent_run_id: authority.agent_run_id.clone(),
        operation_id: authority.operation_id.clone(),
        project_id: authority.project_id.clone(),
        role_session_id: crate::engine::orchestration::RoleSessionId::parse(
            authority.role_session_id.clone(),
        )?,
        role: authority.role,
        parent_run_id: authority.parent_run_id.clone(),
        parent_role: authority.parent_role,
        ticket_run_id: authority.ticket_run_id.clone(),
        ticket_revision: authority.ticket_revision,
        config_revision: authority.config_revision,
        config_digest: authority.config_digest.clone(),
        profile_digest: authority.profile_digest.clone(),
        instruction_digest: authority.instruction_digest.clone(),
        provider_capability_receipt_digest: authority.qualification_receipt_digest.clone(),
        result_schema_digest: authority.result_schema_digest.clone(),
        controller_generation: authority.controller_generation,
        run_epoch: authority.run_epoch,
        attempt: authority.attempt,
    })
}

fn verify_persisted_authority(
    tx: &Transaction<'_>,
    authority: &AgentLaunchAuthority,
    expected: &Digest,
) -> Result<(), String> {
    let row: Option<(String, String)> = tx.query_row("SELECT authority_json,authority_digest FROM agent_launch_authority WHERE agent_run_id=?1", [authority.agent_run_id.as_str()], |row| Ok((row.get(0)?,row.get(1)?))).optional().map_err(|error| error.to_string())?;
    let Some((json, digest)) = row else {
        return Err("Agent launch authority disappeared".into());
    };
    if json != serde_json::to_string(authority).map_err(|error| error.to_string())?
        || digest != expected.as_str()
        || authority.digest()? != *expected
    {
        return Err("persisted launch authority bytes or digest changed".into());
    }
    Ok(())
}

fn verify_ticket_and_run_snapshot(
    tx: &Transaction<'_>,
    authority: &AgentLaunchAuthority,
    _generation: u64,
) -> Result<(), String> {
    let run: Option<(String, String, u64, String, u64, String, String)> = tx.query_row("SELECT project_id,config_source,config_revision,config_digest,controller_generation,state,logical_owner FROM agent_runs WHERE agent_run_id=?1", [authority.agent_run_id.as_str()], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?))).optional().map_err(|error| error.to_string())?;
    let Some((project, _source, config_revision, config_digest, run_generation, state, _owner)) =
        run
    else {
        return Err("AgentRun disappeared".into());
    };
    if project != authority.project_id.as_str()
        || config_revision != authority.config_revision.0
        || config_digest != authority.config_digest.as_str()
        || run_generation != authority.controller_generation
        || !matches!(state.as_str(), "running" | "completed")
    {
        return Err(
            "AgentRun project, config, generation, or lifecycle differs from launch authority"
                .into(),
        );
    }
    if let Some(ticket_run) = &authority.ticket_run_id {
        let ticket: Option<(String, u64, String, u64)> = tx.query_row("SELECT project_id,revision,config_digest,config_revision FROM ticket_runs WHERE ticket_run_id=?1", [ticket_run.as_str()], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?))).optional().map_err(|error| error.to_string())?;
        if !matches!(ticket, Some((ref project_id, revision, ref config_digest, config_revision)) if project_id == authority.project_id.as_str() && revision == authority.ticket_revision.map(|value| value.0).unwrap_or_default() && config_digest == authority.config_digest.as_str() && config_revision == authority.config_revision.0)
        {
            return Err(
                "TicketRun revision or config no longer matches Agent launch authority".into(),
            );
        }
    }
    Ok(())
}

fn verify_terminal_row(
    tx: &Transaction<'_>,
    terminal: &VerifiedAgentTerminal,
) -> Result<(), String> {
    let row: Option<(String,String,String,String,u32,u64)> = tx.query_row("SELECT terminal_digest,absence_digest,authority_digest,start_request_digest,attempt,controller_generation FROM agent_terminal_receipts WHERE agent_run_id=?1", [terminal.agent_run_id.as_str()], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?))).optional().map_err(|error| error.to_string())?;
    if !matches!(row, Some((ref digest,ref absence,ref authority,ref start,attempt,generation)) if digest == terminal.terminal_digest.as_str() && absence == terminal.absence_digest.as_str() && authority == terminal.authority_digest.as_str() && start == terminal.start_request_digest.as_str() && attempt == terminal.attempt && generation == terminal.controller_generation)
    {
        return Err("verified terminal capability does not match immutable persisted proof".into());
    }
    Ok(())
}

fn verify_registered_artifacts(
    tx: &Transaction<'_>,
    authority: &AgentLaunchAuthority,
    refs: &[crate::engine::orchestration::RoleArtifactReference],
    verified: &[crate::store::artifact_registry::VerifiedArtifact],
) -> Result<(), String> {
    if refs.len() != verified.len() {
        return Err("artifact verification set does not match claimed references".into());
    }
    for (reference, proof) in refs.iter().zip(verified) {
        if proof.reference() != reference {
            return Err("verified artifact proof differs from the role result reference".into());
        }
        let current = crate::store::artifact_registry::lookup_registered_artifact_tx(
            tx, authority, reference,
        )?
        .ok_or("role result references an unregistered artifact")?;
        if &current != proof.registration() {
            return Err("artifact registration changed after byte verification".into());
        }
    }
    Ok(())
}

fn insert_derived_wakes(
    tx: &Transaction<'_>,
    authority: &AgentLaunchAuthority,
    result: &ValidatedRoleResult,
    evidence_id: &str,
    terminal_digest: &Digest,
    process_absence_digest: &Digest,
    now: i64,
) -> Result<Vec<i64>, String> {
    let mut ids = Vec::new();
    let authority_digest = authority.digest()?;
    let result_envelope = serde_json::json!({
        "schema_version": 1,
        "kind": "validated_agent_result",
        "evidence_id": evidence_id,
        "result_digest": result.result_digest,
        "source": {
            "agent_run_id": authority.agent_run_id,
            "role": authority.role,
            "role_session_id": authority.role_session_id,
            "parent_run_id": authority.parent_run_id,
            "project_id": authority.project_id,
            "ticket_run_id": authority.ticket_run_id,
            "ticket_revision": authority.ticket_revision,
            "config_digest": authority.config_digest,
            "profile_id": authority.profile_id,
            "profile_digest": authority.profile_digest,
            "run_epoch": authority.run_epoch,
            "attempt": authority.attempt,
        },
        "host_observation": {
            "authority_digest": authority_digest,
            "terminal_digest": terminal_digest,
            "process_absence_digest": process_absence_digest,
        },
        "result": {
            "message_id": result.message_id,
            "kind": result.kind,
            "assertion": result.assertion,
            "structured_result": result.structured_result,
            "artifact_refs": result.claimed_artifact_refs,
        },
        "trust_note": "result and artifacts are untrusted Agent observations; host_observation proves process termination only"
    });
    let envelope_bytes = serde_json::to_vec(&result_envelope).map_err(|error| error.to_string())?;
    if envelope_bytes.len() > 512 * 1024 {
        return Err("validated Agent result wake exceeds its 512 KiB snapshot limit".into());
    }
    for recipient in &result.wake_recipients {
        let session = resolve_recipient_session(tx, authority, recipient)?;
        let payload = serde_json::to_string(&result_envelope).map_err(|error| error.to_string())?;
        tx.execute("INSERT INTO role_wake_inputs(project_id,role_session_id,source_type,source_id,source_revision,priority,payload_json,lifecycle,created_at_unix) VALUES (?1,?2,'agent_result',?3,?4,0,?5,'pending',?6) ON CONFLICT(role_session_id,source_type,source_id,source_revision) DO NOTHING", params![authority.project_id.as_str(),session,evidence_id,authority.run_epoch,payload,now]).map_err(|error| error.to_string())?;
        let wake_id: i64 = tx.query_row("SELECT wake_input_id FROM role_wake_inputs WHERE role_session_id=?1 AND source_type='agent_result' AND source_id=?2 AND source_revision=?3", params![session,evidence_id,authority.run_epoch], |row| row.get(0)).map_err(|error| error.to_string())?;
        let recipient_type = if recipient.role == Role::Supervisor {
            "supervisor"
        } else {
            "coordinator"
        };
        tx.execute("INSERT INTO agent_result_wakes(evidence_id,recipient_type,recipient_id,wake_input_id,queued_at_unix) VALUES (?1,?2,?3,?4,?5)", params![evidence_id,recipient_type,session,wake_id,now]).map_err(|error| error.to_string())?;
        ids.push(wake_id);
    }
    Ok(ids)
}

fn resolve_recipient_session(
    tx: &Transaction<'_>,
    authority: &AgentLaunchAuthority,
    key: &WakeSessionKey,
) -> Result<String, String> {
    if key.project_id != authority.project_id {
        return Err("derived result wake crosses its project boundary".into());
    }
    let session: Option<String> = if key.role == Role::Supervisor {
        tx.query_row("SELECT role_session_id FROM agent_launch_authority WHERE project_id=?1 AND role='supervisor' AND ticket_run_id IS NULL ORDER BY created_at_unix DESC LIMIT 1", [key.project_id.as_str()], |row| row.get(0)).optional().map_err(|error| error.to_string())?
    } else if let Some(parent) = &authority.parent_run_id {
        tx.query_row("SELECT role_session_id FROM agent_launch_authority WHERE agent_run_id=?1 AND project_id=?2 AND role=?3", params![parent.as_str(),key.project_id.as_str(),role_name(key.role)], |row| row.get(0)).optional().map_err(|error| error.to_string())?
    } else if let Some(ticket_run) = &key.ticket_run_id {
        tx.query_row("SELECT role_session_id FROM agent_launch_authority WHERE project_id=?1 AND ticket_run_id=?2 AND role=?3 ORDER BY created_at_unix DESC LIMIT 1", params![key.project_id.as_str(),ticket_run.as_str(),role_name(key.role)], |row| row.get(0)).optional().map_err(|error| error.to_string())?
    } else {
        None
    };
    session.ok_or_else(|| "derived role wake has no host-registered recipient session".into())
}

fn load_stored_receipt(
    tx: &Transaction<'_>,
    evidence_id: &str,
    content_digest: &Digest,
    terminal_digest: &Digest,
) -> Result<StoredRoleResultReceipt, String> {
    let mut statement = tx.prepare("SELECT wake_input_id FROM agent_result_wakes WHERE evidence_id=?1 ORDER BY recipient_type,recipient_id").map_err(|error| error.to_string())?;
    let wake_input_ids = statement
        .query_map([evidence_id], |row| row.get::<_, Option<i64>>(0))
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?
        .into_iter()
        .flatten()
        .collect();
    let message_id: String = tx
        .query_row(
            "SELECT message_id FROM agent_result_evidence WHERE evidence_id=?1",
            [evidence_id],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    Ok(StoredRoleResultReceipt {
        evidence_id: evidence_id.to_owned(),
        message_id,
        content_digest: content_digest.clone(),
        terminal_digest: terminal_digest.clone(),
        wake_input_ids,
    })
}

fn load_qualification(
    connection: &rusqlite::Connection,
    authority: &AgentLaunchAuthority,
) -> Result<ProviderQualification, String> {
    let json: String = connection
        .query_row(
            "SELECT receipt_json FROM provider_qualifications WHERE receipt_digest=?1",
            [authority.qualification_receipt_digest.as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| error.to_string())?
        .ok_or("launch qualification receipt is missing")?;
    let qualification: ProviderQualification = crate::protocol::parse_unique(json.as_bytes())?;
    qualification.validate_for_unattended_launch()?;
    if qualification.canonical_digest()? != authority.qualification_receipt_digest
        || qualification.project_id != authority.project_id
        || qualification.profile_id != authority.profile_id
        || qualification.profile_digest != authority.profile_digest
    {
        return Err("provider qualification receipt does not match launch authority".into());
    }
    Ok(qualification)
}

fn result_digest_of_structured(result: &AgentTurnResult) -> Result<String, String> {
    let structured = result
        .structured_result
        .as_ref()
        .ok_or("completed provider receipt has no structured result")?;
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(structured).map_err(|error| error.to_string())?)
    ))
}

fn role_name(role: Role) -> &'static str {
    match role {
        Role::Supervisor => "supervisor",
        Role::Coordinator => "coordinator",
        Role::Planner => "planner",
        Role::Worker => "worker",
        Role::Reviewer => "reviewer",
        Role::MergeDecision => "merge_decision",
        Role::Operator => "operator",
        Role::Postmortem => "postmortem",
    }
}

fn stable_evidence_id(run_id: &AgentRunId, message_id: &str, content_digest: &Digest) -> String {
    let bytes = serde_json::to_vec(&(
        "rex-projects-agent-evidence-v1",
        run_id.as_str(),
        message_id,
        content_digest.as_str(),
    ))
    .expect("tuple serialization is infallible");
    format!("{:x}", Sha256::digest(bytes))
}

fn digest(bytes: &[u8]) -> Result<Digest, String> {
    Digest::parse(format!("{:x}", Sha256::digest(bytes)))
}

fn read_regular_file(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect file {}: {error}", path.display()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() as usize > limit {
        return Err("expected a bounded regular non-symlink file".into());
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options.open(path).map_err(|error| error.to_string())?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > limit {
        return Err("file exceeds its read limit".into());
    }
    Ok(bytes)
}

fn unix_now() -> Result<i64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())
        .and_then(|v| {
            i64::try_from(v.as_secs()).map_err(|_| "timestamp exceeds supported range".into())
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::ids::{OperationId, ProfileId, Revision};
    use crate::domain::types::Role;
    use std::path::PathBuf;

    fn test_authority() -> AgentLaunchAuthority {
        let digest = || Digest::parse("a".repeat(64)).unwrap();
        AgentLaunchAuthority {
            agent_run_id: AgentRunId::parse("worker-run").unwrap(),
            project_id: ProjectId::parse("project-a").unwrap(),
            role: Role::Worker,
            role_session_id: "worker-session".into(),
            parent_run_id: Some(AgentRunId::parse("coordinator-run").unwrap()),
            parent_role: Some(Role::Coordinator),
            ticket_run_id: Some(TicketRunId::parse("ticket-run").unwrap()),
            ticket_revision: Some(Revision(3)),
            config_revision: Revision(2),
            config_digest: digest(),
            wake_snapshot_digest: digest(),
            attempt: 1,
            run_epoch: 1,
            controller_generation: 7,
            operation_id: OperationId::parse("operation-1").unwrap(),
            operation_recipe_id: None,
            rex_view_id: digest(),
            descriptor_digest: digest(),
            runtime_binary_digest: digest(),
            descriptor_path: PathBuf::from("/tmp/descriptor.json"),
            environment_snapshot_id: digest(),
            profile_id: ProfileId::parse("worker").unwrap(),
            profile_digest: digest(),
            instruction_digest: digest(),
            result_schema_digest: digest(),
            qualification_receipt_digest: digest(),
            rex_server_identity: "rex-local".into(),
            rex_session_id: "session-1".into(),
            rex_window_id: "window-1".into(),
            rex_block_id: "block-1".into(),
            workspace_path: PathBuf::from("/tmp/worktree"),
            control_dir: PathBuf::from("/tmp/control"),
            mailbox_capability_digest: digest(),
        }
    }

    fn reviewer_run_step_package(
        authority: &AgentLaunchAuthority,
        result_schema: serde_json::Value,
    ) -> crate::run_step_package::RunStepPackage {
        use crate::config::Profile;
        use crate::domain::types::{AgentAdapter, CommitMode};
        use crate::run_step::{
            ProviderCapabilityEvidence, ProviderQualificationStatus, RunDescriptor,
        };

        let profile: Profile = serde_json::from_value(serde_json::json!({
            "adapter":"codex", "command":["/bin/codex"], "model":"fixture",
            "commit_mode":"native", "turn_timeout_seconds":60
        }))
        .unwrap();
        let profile_digest = digest(&serde_json::to_vec(&profile).unwrap()).unwrap();
        let schema_projection = crate::providers::project_result_schema(&result_schema)
            .unwrap()
            .identity;
        crate::run_step_package::RunStepPackage {
            schema_version: 1,
            descriptor: RunDescriptor {
                schema_version: 1,
                project_id: authority.project_id.clone(),
                run_id: authority.agent_run_id.clone(),
                role: authority.role,
                ticket_run_id: authority.ticket_run_id.clone(),
                operation_id: authority.operation_id.clone(),
                expected_subject_revision: authority
                    .ticket_revision
                    .expect("ticket-scoped result fixture")
                    .0,
                attempt: authority.attempt,
                run_epoch: authority.run_epoch,
                controller_generation: authority.controller_generation,
                workspace: authority.workspace_path.clone(),
                control_dir: authority.control_dir.clone(),
                rex_session_id: authority.rex_session_id.clone(),
                rex_block_id: crate::domain::ids::RexBlockId::parse(authority.rex_block_id.clone())
                    .unwrap(),
                profile_digest: profile_digest.clone(),
                instruction_digest: authority.instruction_digest.clone(),
                plan_digest: None,
                environment_snapshot_id: authority.environment_snapshot_id.clone(),
                wake_snapshot_digest: authority.wake_snapshot_digest.clone(),
                provider_capability: ProviderCapabilityEvidence {
                    schema_version: 1,
                    adapter: AgentAdapter::Codex,
                    profile_digest,
                    version: "fixture-1".into(),
                    executable_path: "/bin/codex".into(),
                    executable_digest: digest(&[b'c'; 1]).unwrap(),
                    permission_mode: "workspace_write".into(),
                    invocation_options_digest: digest(&[b'd'; 1]).unwrap(),
                    commit_mode: CommitMode::Native,
                    schema_projection: schema_projection.clone(),
                    receipt_digest: authority.qualification_receipt_digest.clone(),
                    status: ProviderQualificationStatus::Verified,
                },
                result_schema,
            },
            operation_id: authority.operation_id.clone(),
            project_id: authority.project_id.clone(),
            controller_generation: authority.controller_generation,
            runtime_binary_digest: authority.runtime_binary_digest.clone(),
            qualification_receipt_digest: authority.qualification_receipt_digest.clone(),
            rex_cli_path: "/bin/rex".into(),
            rex_search_path: vec![],
            rex_endpoint: "http://localhost".into(),
            rex_server_identity: authority.rex_server_identity.clone(),
            rex_window_id: authority.rex_window_id.clone(),
            profile,
            role_contract: "reviewer contract".into(),
            prompt: "review this publication".into(),
            continuation: None,
            shutdown_grace_seconds: 5,
            start_ack_timeout_seconds: 5,
        }
    }

    fn reviewer_qualification(authority: &AgentLaunchAuthority) -> ProviderQualification {
        use crate::domain::types::{AgentAdapter, CommitMode};
        use crate::launch::{ProviderQualification, QualificationProof, QualificationStatus};

        let markers = [
            "REX_PROJECTS_AGENT",
            "REX_PROJECTS_CONTEXT",
            "REX_PROJECTS_PROJECT_ID",
            "REX_PROJECTS_ROLE",
            "REX_PROJECTS_RUN_ID",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<std::collections::BTreeSet<_>>();
        ProviderQualification {
            schema_version: 1,
            project_id: authority.project_id.clone(),
            profile_id: authority.profile_id.clone(),
            profile_digest: authority.profile_digest.clone(),
            adapter: AgentAdapter::Codex,
            executable_path: "/bin/codex".into(),
            executable_digest: digest(&[b'c'; 1]).unwrap(),
            provider_version: "fixture-1".into(),
            permission_mode: "workspace_write".into(),
            invocation_options_digest: digest(&[b'd'; 1]).unwrap(),
            commit_mode: CommitMode::Native,
            proof: QualificationProof {
                schema_version: 1,
                probe_id: "probe-a".into(),
                fixture_digest: digest(&[b'e'; 1]).unwrap(),
                rex_instance_id: "rex-fixture".into(),
                tool_shell_marker_digest: digest(&[b'f'; 1]).unwrap(),
                tool_shell_markers_present: markers.clone(),
                descendant_marker_digest: digest(&[b'1'; 1]).unwrap(),
                descendant_markers_present: markers,
                automatic_turn_result_digest: digest(&[b'2'; 1]).unwrap(),
                automatic_turn_completed: true,
                structured_result_valid: true,
                observed_permission_mode: "workspace_write".into(),
                permission_prompt_count: 0,
                cleanup_process_tree_digest: digest(&[b'3'; 1]).unwrap(),
                process_tree_absent: true,
                cleanup_confirmed: true,
            },
            status: QualificationStatus::Verified,
        }
    }

    #[test]
    fn coordinator_result_wake_resolves_only_its_bound_parent_session() {
        let mut connection = rusqlite::Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE agent_launch_authority (
                agent_run_id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                role_session_id TEXT NOT NULL,
                role TEXT NOT NULL
            );
            INSERT INTO agent_launch_authority VALUES
                ('coordinator-run','project-a','coordinator-session','coordinator'),
                ('other-run','project-a','other-session','coordinator');",
            )
            .unwrap();
        let tx = connection.transaction().unwrap();
        let session = resolve_recipient_session(
            &tx,
            &test_authority(),
            &WakeSessionKey {
                project_id: ProjectId::parse("project-a").unwrap(),
                ticket_run_id: Some(TicketRunId::parse("ticket-run").unwrap()),
                role: Role::Coordinator,
            },
        )
        .unwrap();
        assert_eq!(session, "coordinator-session");
    }

    #[test]
    fn process_absence_rejects_unverified_or_missing_process_identity() {
        let unknown = crate::run_step::ObservedProcess {
            pid: 42,
            parent_pid: 1,
            process_group_id: 42,
            start_identity: "pid-only".into(),
            command: "provider".into(),
            identity_quality: "unverified_pid_hint".into(),
        };
        assert!(verify_process_tree_absent(&[unknown]).is_err());
        assert!(verify_process_tree_absent(&[]).is_err());
    }

    #[test]
    fn process_tree_must_include_the_host_observed_provider_identity() {
        let process = crate::run_step::ObservedProcess {
            pid: 42,
            parent_pid: 1,
            process_group_id: 42,
            start_identity: "birth-token".into(),
            command: "provider".into(),
            identity_quality: "kernel_birth_token".into(),
        };
        assert!(process_tree_contains_root(
            &[process.clone()],
            42,
            "birth-token"
        ));
        assert!(!process_tree_contains_root(
            &[process.clone()],
            42,
            "other-token"
        ));
        assert!(!process_tree_contains_root(&[process], 43, "birth-token"));
    }

    #[test]
    fn terminal_descriptor_validation_accepts_published_run_step_package() {
        use crate::domain::types::AgentAdapter;
        use crate::run_step::{CleanupState, RunReceipt, TurnOutcome};

        let temp = tempfile::tempdir().unwrap();
        let temp_path = std::fs::canonicalize(temp.path()).unwrap();
        let mut authority = test_authority();
        authority.role = Role::Reviewer;
        authority.role_session_id = "ticket_run:ticket-run:reviewer".into();
        authority.descriptor_path = temp_path.join("run-step-package.json");
        authority.workspace_path = temp_path.join("workspace");
        authority.control_dir = temp_path.join("control");
        std::fs::create_dir(&authority.workspace_path).unwrap();
        std::fs::create_dir(&authority.control_dir).unwrap();
        let schema: serde_json::Value = crate::protocol::parse_unique(include_bytes!(
            "../../schemas/agent-results/reviewer-v1.json"
        ))
        .unwrap();
        let package = reviewer_run_step_package(&authority, schema.clone());
        authority.result_schema_digest = crate::providers::project_result_schema(&schema)
            .unwrap()
            .identity
            .source_schema_digest;
        authority.profile_digest = package.descriptor.profile_digest.clone();
        let qualification = reviewer_qualification(&authority);
        authority.qualification_receipt_digest = qualification.canonical_digest().unwrap();
        let package = reviewer_run_step_package(&authority, schema.clone());
        authority.descriptor_digest = package.publish_once(&authority.descriptor_path).unwrap();
        let projection = crate::providers::project_result_schema(&schema)
            .unwrap()
            .identity;
        let result = AgentTurnResult {
            schema_version: 1,
            start_request_digest: "a".repeat(64),
            receipt: RunReceipt {
                run_id: authority.agent_run_id.clone(),
                attempt: authority.attempt,
                provider: AgentAdapter::Codex,
                effective_permission_mode: "workspace_write".into(),
                conversation_id: None,
                provider_version: Some("fixture-1".into()),
                provider_process_failure: None,
                provider_result_failure: None,
                capability_receipt_digest: Some(authority.qualification_receipt_digest.clone()),
                schema_projection: projection,
                launch_pid_hint: None,
                exit_code: Some(0),
                timed_out: false,
                cancellation_signal: None,
                cleanup: CleanupState::Confirmed,
                cleanup_detail: None,
                processes: vec![],
                result_digest: None,
                outcome: TurnOutcome::Completed,
            },
            structured_result: Some(serde_json::json!({})),
            result_digest: "b".repeat(64),
        };
        validate_descriptor_and_projection(&authority, &result, &qualification).unwrap();

        let mut wrong_generation = package;
        wrong_generation.runtime_binary_digest = digest(&[b'z'; 1]).unwrap();
        let wrong_path = temp_path.join("wrong-package.json");
        authority.descriptor_path = wrong_path.clone();
        authority.descriptor_digest = wrong_generation.publish_once(&wrong_path).unwrap();
        assert!(
            validate_descriptor_and_projection(&authority, &result, &qualification)
                .unwrap_err()
                .contains("package does not match")
        );

        let mut wrong_revision = reviewer_run_step_package(&authority, schema.clone());
        wrong_revision.descriptor.attempt += 1;
        let wrong_path = temp_path.join("wrong-revision-package.json");
        authority.descriptor_path = wrong_path.clone();
        authority.descriptor_digest = wrong_revision.publish_once(&wrong_path).unwrap();
        assert!(
            validate_descriptor_and_projection(&authority, &result, &qualification)
                .unwrap_err()
                .contains("descriptor does not match")
        );

        authority.descriptor_path = temp_path.join("run-step-package.json");
        authority.descriptor_digest =
            digest(&std::fs::read(&authority.descriptor_path).unwrap()).unwrap();
        let mut wrong_projection = result;
        wrong_projection
            .receipt
            .schema_projection
            .source_schema_digest = digest(&[b'z'; 1]).unwrap();
        assert!(
            validate_descriptor_and_projection(&authority, &wrong_projection, &qualification)
                .unwrap_err()
                .contains("schema projection")
        );
    }

    #[test]
    fn v12_wake_schema_allows_one_result_to_wake_multiple_roles() {
        let mut connection = rusqlite::Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE agent_result_evidence(evidence_id TEXT PRIMARY KEY);
            CREATE TABLE role_wake_inputs(wake_input_id INTEGER PRIMARY KEY);
            CREATE TABLE agent_result_wakes(
                evidence_id TEXT PRIMARY KEY REFERENCES agent_result_evidence(evidence_id),
                recipient_type TEXT NOT NULL,
                recipient_id TEXT NOT NULL,
                wake_input_id INTEGER REFERENCES role_wake_inputs(wake_input_id),
                queued_at_unix INTEGER NOT NULL
            );
            INSERT INTO agent_result_evidence VALUES ('evidence-1');",
            )
            .unwrap();
        let tx = connection.transaction().unwrap();
        migrate_v12_tables(&tx).unwrap();
        tx.commit().unwrap();
        connection.execute(
            "INSERT INTO agent_result_wakes(evidence_id,recipient_type,recipient_id,queued_at_unix) VALUES ('evidence-1','coordinator','coordinator-session',1),('evidence-1','supervisor','supervisor-session',1)",
            [],
        ).unwrap();
        let count: u32 = connection
            .query_row(
                "SELECT COUNT(*) FROM agent_result_wakes WHERE evidence_id='evidence-1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn evidence_identity_is_stable_and_content_sensitive() {
        let run = AgentRunId::parse("run-a").unwrap();
        let first = Digest::parse("a".repeat(64)).unwrap();
        let changed = Digest::parse("b".repeat(64)).unwrap();
        assert_eq!(
            stable_evidence_id(&run, "message-1", &first),
            stable_evidence_id(&run, "message-1", &first)
        );
        assert_ne!(
            stable_evidence_id(&run, "message-1", &first),
            stable_evidence_id(&run, "message-1", &changed)
        );
    }

    #[test]
    fn reviewer_ack_replay_uses_committed_transition_after_ticket_phase_advanced() {
        let temp = tempfile::tempdir().unwrap();
        let mut store = ConfigStore::open_test(temp.path()).unwrap();
        // The fixture models a crash after the transition transaction committed but before
        // the separate result ACK transaction. This call must not depend on current phase.
        store
            .connection
            .execute_batch("PRAGMA foreign_keys=OFF;")
            .unwrap();
        store.connection.execute(
            "INSERT INTO controller_owners(singleton,owner_nonce,generation,state_root,config_source,pid,process_start_identity,executable_path,executable_digest,started_at_unix,heartbeat_at_unix) VALUES (1,'owner',7,'/tmp','factory',1,'owner-start','/tmp/rex','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',1,1)",
            [],
        ).unwrap();
        store.connection.execute(
            "INSERT INTO ticket_runs(ticket_run_id,project_id,config_source,config_revision,config_digest,namespace,ticket_id,generation,internal_phase,activity,external_status,observed_status,revision) VALUES ('ticket-run','project-a','factory',1,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','fixture','T-1',1,'assessing','running','In Progress','In Progress',11)",
            [],
        ).unwrap();

        let evidence_id = "review-evidence-1";
        let result_digest =
            Digest::parse("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
                .unwrap();
        let source_revision = 10;
        let accepted_revision = source_revision + 1;
        store.connection.execute(
            "INSERT INTO agent_launch_authority(agent_run_id,project_id,role,role_session_id,ticket_run_id,ticket_revision,config_revision,config_digest,attempt,run_epoch,controller_generation,launch_operation_id,rex_view_id,descriptor_digest,runtime_binary_digest,descriptor_path,environment_snapshot_id,profile_id,profile_digest,instruction_digest,result_schema_digest,qualification_receipt_digest,rex_server_identity,rex_session_id,rex_window_id,rex_block_id,workspace_path,control_dir,mailbox_capability_digest,authority_json,authority_digest,created_at_unix) VALUES ('reviewer-run','project-a','reviewer','ticket_run:ticket-run:reviewer','ticket-run',?1,1,?2,1,1,7,'review-operation','review-view',?3,?3,'/tmp/package',?3,'reviewer',?3,?3,?3,?3,'fixture','session','window','block','/tmp/workspace','/tmp/control',?3,'{}',?3,1)",
            rusqlite::params![source_revision, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"],
        ).unwrap();
        store.connection.execute(
            "INSERT INTO agent_result_evidence(evidence_id,agent_run_id,project_id,role,ticket_run_id,attempt,run_epoch,message_id,content_digest,outcome,result_digest,result_json,artifact_refs_json,received_at_unix) VALUES (?1,'reviewer-run','project-a','reviewer','ticket-run',1,1,'review-message',?2,'completed',?3,'{}','[]',1)",
            rusqlite::params![evidence_id, "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", result_digest.as_str()],
        ).unwrap();
        let payload = serde_json::json!({
            "schema_version": 1,
            "kind": "review_assessment",
            "evidence_id": evidence_id,
            "result_digest": result_digest.as_str(),
            "source_revision": source_revision,
            "accepted_revision": accepted_revision,
            "transition": "review_converged"
        })
        .to_string();
        let message_id = format!("review-ready:{evidence_id}");
        store.connection.execute(
            "INSERT INTO inbox(producer_id,message_id,content_digest,recipient,payload_json,receipt_json,received_at_unix,processed_at_unix) VALUES ('rex-projects-agent-result',?1,?2,'ticket_run',?3,?4,1,1)",
            rusqlite::params![message_id, crate::store::durable_input_digest("ticket_run", &payload), payload, serde_json::json!({"project_id":"project-a","ticket_run_id":"ticket-run","revision":accepted_revision}).to_string()],
        ).unwrap();

        let project = ProjectId::parse("project-a").unwrap();
        let ticket_run = TicketRunId::parse("ticket-run").unwrap();
        assert!(
            store
                .acknowledge_committed_role_result(
                    7,
                    "review_assessment",
                    evidence_id,
                    &result_digest,
                    &project,
                    &ticket_run,
                )
                .unwrap()
        );
        assert_eq!(store.connection.query_row(
            "SELECT reducer_revision || ':' || disposition FROM agent_result_reducer_ack WHERE evidence_id=?1",
            [evidence_id], |row| row.get::<_, String>(0),
        ).unwrap(), "11:applied");
        assert!(
            store
                .acknowledge_committed_role_result(
                    7,
                    "review_assessment",
                    evidence_id,
                    &result_digest,
                    &project,
                    &ticket_run,
                )
                .unwrap()
        );
        assert!(
            store
                .acknowledge_committed_role_result(
                    7,
                    "review_assessment",
                    evidence_id,
                    &result_digest,
                    &ProjectId::parse("other-project").unwrap(),
                    &ticket_run,
                )
                .is_err()
        );
        assert!(
            store
                .acknowledge_committed_role_result(
                    7,
                    "review_assessment",
                    evidence_id,
                    &result_digest,
                    &project,
                    &TicketRunId::parse("other-ticket").unwrap(),
                )
                .is_err()
        );
        assert!(
            store
                .acknowledge_committed_role_result(
                    7,
                    "review_assessment",
                    evidence_id,
                    &Digest::parse(
                        "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                    )
                    .unwrap(),
                    &project,
                    &ticket_run,
                )
                .is_err()
        );
        let wrong_revision_payload = serde_json::json!({
            "schema_version": 1,
            "kind": "review_assessment",
            "evidence_id": evidence_id,
            "result_digest": result_digest.as_str(),
            "source_revision": source_revision,
            "accepted_revision": accepted_revision + 1,
            "transition": "review_converged"
        })
        .to_string();
        store.connection.execute(
            "UPDATE inbox SET content_digest=?2,payload_json=?3 WHERE producer_id='rex-projects-agent-result' AND message_id=?1",
            rusqlite::params![message_id, crate::store::durable_input_digest("ticket_run", &wrong_revision_payload), wrong_revision_payload],
        ).unwrap();
        assert!(
            store
                .acknowledge_committed_role_result(
                    7,
                    "review_assessment",
                    evidence_id,
                    &result_digest,
                    &project,
                    &ticket_run,
                )
                .is_err()
        );
        store.connection.execute(
            "UPDATE inbox SET content_digest=?2,payload_json=?3 WHERE producer_id='rex-projects-agent-result' AND message_id=?1",
            rusqlite::params![message_id, crate::store::durable_input_digest("ticket_run", &payload), payload],
        ).unwrap();
        let transition_count: u64 = store
            .connection
            .query_row("SELECT COUNT(*) FROM transitions", [], |row| row.get(0))
            .unwrap();
        let effect_count: u64 = store
            .connection
            .query_row("SELECT COUNT(*) FROM effects", [], |row| row.get(0))
            .unwrap();
        assert_eq!((transition_count, effect_count), (0, 0));
        let ack_count: u64 = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM agent_result_reducer_ack WHERE evidence_id=?1",
                [evidence_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(ack_count, 1);

        // Worker replay uses the exact durable payload builder from the production producer.
        let worker_evidence_id = "worker-evidence-1";
        let worker_digest =
            Digest::parse("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .unwrap();
        let worker_payload = crate::engine::factory_runtime::worker_result_transition_payload(
            worker_evidence_id,
            &worker_digest,
            11,
            "publication-operation-1",
            12,
        );
        store.connection.execute(
            "INSERT INTO agent_launch_authority(agent_run_id,project_id,role,role_session_id,ticket_run_id,ticket_revision,config_revision,config_digest,attempt,run_epoch,controller_generation,launch_operation_id,rex_view_id,descriptor_digest,runtime_binary_digest,descriptor_path,environment_snapshot_id,profile_id,profile_digest,instruction_digest,result_schema_digest,qualification_receipt_digest,rex_server_identity,rex_session_id,rex_window_id,rex_block_id,workspace_path,control_dir,mailbox_capability_digest,authority_json,authority_digest,created_at_unix) VALUES ('worker-run','project-a','worker','ticket_run:ticket-run:worker','ticket-run',11,1,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',1,1,7,'worker-operation','worker-view','cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc','cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc','/tmp/package','cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc','worker','cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc','cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc','cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc','cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc','fixture','session','window','block','/tmp/workspace','/tmp/control','cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc','{}','cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',1)",
            [],
        ).unwrap();
        store.connection.execute(
            "INSERT INTO agent_result_evidence(evidence_id,agent_run_id,project_id,role,ticket_run_id,attempt,run_epoch,message_id,content_digest,outcome,result_digest,result_json,artifact_refs_json,received_at_unix) VALUES (?1,'worker-run','project-a','worker','ticket-run',1,1,'worker-message','dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd','completed',?2,'{}','[]',1)",
            rusqlite::params![worker_evidence_id, worker_digest.as_str()],
        ).unwrap();
        let worker_message_id = format!("implementation-ready:{worker_evidence_id}");
        store.connection.execute(
            "INSERT INTO inbox(producer_id,message_id,content_digest,recipient,payload_json,receipt_json,received_at_unix,processed_at_unix) VALUES ('rex-projects-agent-result',?1,?2,'ticket_run',?3,?4,1,1)",
            rusqlite::params![worker_message_id, crate::store::durable_input_digest("ticket_run", &worker_payload), worker_payload, serde_json::json!({"project_id":"project-a","ticket_run_id":"ticket-run","revision":12,"effects":["publication-operation-1"]}).to_string()],
        ).unwrap();
        assert!(
            store
                .acknowledge_committed_role_result(
                    7,
                    "worker_implementation_ready",
                    worker_evidence_id,
                    &worker_digest,
                    &project,
                    &ticket_run,
                )
                .unwrap()
        );
        assert_eq!(store.connection.query_row(
            "SELECT reducer_revision || ':' || disposition FROM agent_result_reducer_ack WHERE evidence_id=?1",
            [worker_evidence_id], |row| row.get::<_, String>(0),
        ).unwrap(), "12:applied");
    }
}

impl ConfigStore {
    pub fn acknowledge_committed_role_result(
        &mut self,
        owner_generation: u64,
        result_kind: &str,
        evidence_id: &str,
        result_digest: &Digest,
        project_id: &ProjectId,
        ticket_run_id: &TicketRunId,
    ) -> Result<bool, String> {
        acknowledge_committed_role_result(
            self,
            owner_generation,
            result_kind,
            evidence_id,
            result_digest,
            project_id,
            ticket_run_id,
        )
    }

    pub fn applied_reviewer_correction_round_count(
        &self,
        project_id: &ProjectId,
        ticket_run_id: &TicketRunId,
    ) -> Result<usize, String> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT i.payload_json FROM agent_result_evidence e JOIN agent_result_reducer_ack a USING(evidence_id) JOIN inbox i ON i.producer_id='rex-projects-agent-result' AND i.message_id='review-ready:' || e.evidence_id WHERE e.project_id=?1 AND e.ticket_run_id=?2 AND e.role='reviewer' AND a.disposition='applied'",
            )
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(
                params![project_id.as_str(), ticket_run_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .map_err(|error| error.to_string())?;
        let mut count = 0;
        for row in rows {
            let payload = row.map_err(|error| error.to_string())?;
            let payload: serde_json::Value = serde_json::from_str(&payload)
                .map_err(|error| format!("stored Reviewer transition is invalid: {error}"))?;
            if payload["transition"] == "corrections_remain" {
                count += 1;
            }
        }
        Ok(count)
    }

    pub fn validated_agent_result_for_wake(
        &mut self,
        artifact_store: &crate::artifacts::ArtifactStore,
        owner_generation: u64,
        wake_input_id: i64,
    ) -> Result<Option<IngestedAgentResult>, String> {
        agent_result_for_wake(self, artifact_store, owner_generation, wake_input_id)
    }

    pub fn ingest_next_spooled_agent_result(
        &mut self,
        artifact_store: &crate::artifacts::ArtifactStore,
        owner_generation: u64,
        candidate_limit: usize,
    ) -> Result<Option<IngestedAgentResult>, String> {
        ingest_next_spooled_agent_result(self, artifact_store, owner_generation, candidate_limit)
    }

    pub fn record_verified_agent_terminal(
        &mut self,
        owner_generation: u64,
        start: &StartRequestEnvelope,
        result: &AgentTurnResult,
    ) -> Result<VerifiedAgentTerminal, String> {
        record_and_verify_agent_terminal(self, owner_generation, start, result)
    }

    pub fn store_validated_agent_result(
        &mut self,
        artifact_store: &crate::artifacts::ArtifactStore,
        owner_generation: u64,
        terminal: &VerifiedAgentTerminal,
        message: RoleResultMessage,
    ) -> Result<IngestedAgentResult, String> {
        ingest_agent_result(self, artifact_store, owner_generation, terminal, message)
    }

    pub fn pending_validated_agent_results(
        &mut self,
        artifact_store: &crate::artifacts::ArtifactStore,
        owner_generation: u64,
        limit: usize,
    ) -> Result<Vec<IngestedAgentResult>, String> {
        pending_agent_results(self, artifact_store, owner_generation, limit)
    }

    pub fn acknowledge_validated_agent_result(
        &mut self,
        owner_generation: u64,
        evidence_id: &str,
        reducer_revision: u64,
        disposition: ResultDisposition,
    ) -> Result<(), String> {
        acknowledge_agent_result(
            self,
            owner_generation,
            evidence_id,
            reducer_revision,
            disposition,
        )
    }
}
