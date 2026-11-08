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
type ObsoleteConfigurationSourceRow = (
    String,
    String,
    String,
    String,
    u32,
    u64,
    String,
    String,
    String,
    u64,
    u64,
    String,
    String,
);
type ValidatedResultParentRow = (
    String,
    u32,
    u64,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
);
type ArtifactSourceRow = (String, String, Option<String>, Option<u64>, String);
type ArtifactSourceWithAuthorityRow = (
    String,
    String,
    Option<String>,
    Option<u64>,
    String,
    u64,
    String,
    String,
    String,
);

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

    #[cfg(test)]
    pub(crate) fn test_receipt(evidence_id: impl Into<String>) -> Self {
        Self {
            evidence_id: evidence_id.into(),
            message_id: "clarification-message".into(),
            content_digest: Digest::parse("a".repeat(64)).expect("test digest"),
            terminal_digest: Digest::parse("b".repeat(64)).expect("test digest"),
            wake_input_ids: Vec::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct IngestedAgentResult {
    pub validated: ValidatedRoleResult,
    pub receipt: StoredRoleResultReceipt,
    /// Host-verified immutable objects for this exact result binding.
    pub verified_artifacts: Vec<crate::store::artifact_registry::VerifiedArtifact>,
}

#[cfg(test)]
pub(crate) fn test_ingested_agent_result(
    submission: RoleResultSubmission,
    evidence_id: String,
) -> IngestedAgentResult {
    let binding = submission.binding.clone();
    let validated =
        crate::engine::orchestration::validate_role_result(&binding, submission).unwrap();
    IngestedAgentResult {
        receipt: StoredRoleResultReceipt {
            evidence_id,
            message_id: validated.message_id.clone(),
            content_digest: Digest::parse("b".repeat(64)).unwrap(),
            terminal_digest: Digest::parse("c".repeat(64)).unwrap(),
            wake_input_ids: Vec::new(),
        },
        validated,
        verified_artifacts: Vec::new(),
    }
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
    verify_agent_run_snapshot(&tx, &authority)?;
    verify_ticket_snapshot(&tx, &authority)?;
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
    let slot: Option<(String, u32, u64)> = tx
        .query_row(
            "SELECT pool,slot_index,reservation_epoch FROM execution_slots WHERE owner_kind='agent_run' AND owner_id=?1 AND project_id=?2 AND controller_generation=?3 AND disposition IN ('launch_pending','live','parked','unknown')",
            params![run_id.as_str(), authority.project_id.as_str(), owner_generation],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    let Some((pool, slot_index, reservation_epoch)) = slot else {
        return Err("Agent terminal has no exact active execution slot to release".into());
    };
    let released = tx
        .execute(
            "UPDATE execution_slots SET disposition='released',controller_generation=?5 WHERE pool=?1 AND slot_index=?2 AND owner_kind='agent_run' AND owner_id=?3 AND reservation_epoch=?4 AND project_id=?6 AND controller_generation=?5 AND disposition IN ('launch_pending','live','parked','unknown')",
            params![pool, slot_index, run_id.as_str(), reservation_epoch, owner_generation, authority.project_id.as_str()],
        )
        .map_err(|error| error.to_string())?;
    if released != 1 {
        return Err("Agent terminal did not release its exact execution slot".into());
    }
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
    let row: Option<ValidatedResultParentRow> = store
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
    let message = message.canonicalized()?;
    let terminal_role_message: RoleResultMessage = serde_json::from_value(
        terminal
            .result
            .structured_result
            .clone()
            .ok_or("completed Agent terminal has no structured result")?,
    )
    .map_err(|error| format!("provider result is not a role result message: {error}"))?;
    let terminal_role_message = terminal_role_message.canonicalized()?;
    if terminal_role_message != message {
        return Err(
            "submitted role result differs from the persisted provider terminal payload".into(),
        );
    }
    let validated = message.clone().bind(binding.clone())?;
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
    verify_agent_run_snapshot(&tx, &authority)?;
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

    // A newly submitted result must still target the current TicketRun revision. An exact
    // evidence replay has already passed this check when first persisted, and can be needed to
    // resolve a durable parent wake after the reducer advances the TicketRun.
    verify_ticket_snapshot(&tx, &authority)?;

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
            result_digest: Some(submission.result_digest),
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
    if binding_for(&authority)? != submission.binding {
        return Err("Agent result wake source no longer matches its launch authority".into());
    }
    let terminal = verify_agent_terminal(store, owner_generation, &run_id)?;
    let message = RoleResultMessage {
        schema_version: submission.schema_version,
        message_id: submission.message_id,
        kind: submission.kind,
        assertion: submission.assertion,
        structured_result: submission.structured_result,
        result_digest: Some(submission.result_digest),
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
        if !matches!(terminal_result.receipt.outcome, TurnOutcome::Completed) {
            // A provider failure is not a role result. Validate that the failure spool still
            // belongs to this immutable launch, then let the regular recovery tick reconcile
            // Rex block loss and process absence without releasing capacity here. Continue
            // scanning this bounded batch so one unresolved run cannot hide later results.
            start.validate()?;
            terminal_result.validate_for(&start)?;
            let authority = store
                .agent_launch_authority(&run_id)?
                .ok_or("Agent terminal has no persisted launch authority")?;
            validate_request_authority(&authority, &start)?;
            let qualification = load_qualification(&store.connection, &authority)?;
            if terminal_result.receipt.attempt != authority.attempt
                || terminal_result.receipt.provider != qualification.adapter
                || terminal_result.receipt.capability_receipt_digest.as_ref()
                    != Some(&authority.qualification_receipt_digest)
            {
                return Err(
                    "provider failure receipt does not match immutable launch authority".into(),
                );
            }
            validate_descriptor_and_projection(&authority, &terminal_result, &qualification)?;
            let launch_state: Option<(String, Option<String>, Option<String>)> = store
                .connection
                .query_row(
                    "SELECT state,start_request_digest,provider_process_tree_json FROM agent_launch_state WHERE agent_run_id=?1",
                    [run_id.as_str()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()
                .map_err(|error| error.to_string())?;
            let Some((state, start_digest, process_tree_json)) = launch_state else {
                return Err("AgentRun has no persisted launch state".into());
            };
            if !matches!(state.as_str(), "running" | "unknown")
                || start_digest.as_deref() != Some(start.request_digest.as_str())
            {
                return Err(
                    "Agent failure receipt does not match the persisted active start request"
                        .into(),
                );
            }
            if let Some(process_tree_json) = process_tree_json {
                verify_provider_start_observation(
                    &authority,
                    &Some(process_tree_json),
                    &terminal_result,
                    &qualification,
                )?;
            }
            continue;
        }
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

/// Acknowledge a host-validated Worker or Reviewer result when its Project configuration has
/// changed, provided the TicketRun is still at the exact revision and phase that launched it.
/// Evidence is retained, and the ACK is scoped to the TicketRun revision so config reloads do not
/// make the same stale result eligible for reduction again.
pub fn acknowledge_obsolete_configuration_result(
    store: &mut ConfigStore,
    owner_generation: u64,
    binding: &RoleResultBinding,
    evidence_id: &str,
    active_config_digest: &Digest,
) -> Result<bool, String> {
    if !matches!(binding.role, Role::Worker | Role::Reviewer) {
        return Err(
            "obsolete configuration disposition only supports Worker and Reviewer results".into(),
        );
    }
    let ticket_run_id = binding
        .ticket_run_id
        .as_ref()
        .ok_or("obsolete configuration result lacks TicketRun scope")?;
    let ticket_revision = binding
        .ticket_revision
        .ok_or("obsolete configuration result lacks TicketRun revision")?;
    let tx = store
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| error.to_string())?;
    super::validate_active_generation(&tx, owner_generation)?;
    let source: Option<ObsoleteConfigurationSourceRow> = tx.query_row(
        "SELECT e.agent_run_id,e.project_id,e.role,e.ticket_run_id,e.attempt,e.run_epoch,a.authority_json,a.authority_digest,p.config_digest,p.config_revision,tr.revision,tr.internal_phase,tr.project_id FROM agent_result_evidence e JOIN agent_terminal_receipts t USING(agent_run_id) JOIN agent_launch_authority a USING(agent_run_id) JOIN projects p ON p.project_id=e.project_id JOIN ticket_runs tr ON tr.ticket_run_id=e.ticket_run_id WHERE e.evidence_id=?1 AND e.outcome='completed'",
        [evidence_id],
        |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?,row.get(9)?,row.get(10)?,row.get(11)?,row.get(12)?)),
    ).optional().map_err(|error| error.to_string())?;
    let Some((
        run_id,
        project_id,
        role,
        ticket_id,
        attempt,
        epoch,
        authority_json,
        authority_digest,
        current_digest,
        current_config_revision,
        ticket_revision_now,
        phase,
        ticket_project,
    )) = source
    else {
        return Err(
            "obsolete configuration disposition requires host-validated result evidence".into(),
        );
    };
    let expected_role = match binding.role {
        Role::Worker => "worker",
        Role::Reviewer => "reviewer",
        _ => unreachable!(),
    };
    let authority: AgentLaunchAuthority = crate::protocol::parse_unique(authority_json.as_bytes())?;
    if authority.digest()?.as_str() != authority_digest
        || binding_for(&authority)? != *binding
        || run_id != binding.agent_run_id.as_str()
        || project_id != binding.project_id.as_str()
        || role != expected_role
        || ticket_id != ticket_run_id.as_str()
        || attempt != binding.attempt
        || epoch != binding.run_epoch
        || ticket_project != binding.project_id.as_str()
        || ticket_revision_now != ticket_revision.0
    {
        return Err(
            "obsolete configuration result does not match its immutable authority and TicketRun"
                .into(),
        );
    }
    let expected_phase = match binding.role {
        Role::Worker => "implementing",
        Role::Reviewer => "reviewing",
        _ => unreachable!(),
    };
    if phase != expected_phase {
        return Err(
            "obsolete configuration result is outside its exact active TicketRun phase".into(),
        );
    }
    if current_digest != active_config_digest.as_str() {
        return Err(
            "Project configuration record differs from the active configuration snapshot".into(),
        );
    }
    if binding.config_digest.as_str() == current_digest
        && binding.config_revision.0 == current_config_revision
    {
        tx.commit().map_err(|error| error.to_string())?;
        return Ok(false);
    }
    if current_config_revision == 0 || ticket_revision_now == 0 {
        return Err("current Project and TicketRun revisions must be positive".into());
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
        if revision != ticket_revision_now || disposition != "rejected_by_host" {
            return Err(
                "obsolete configuration result already has a different reducer acknowledgement"
                    .into(),
            );
        }
    } else {
        let changed = tx.execute("INSERT INTO agent_result_reducer_ack(evidence_id,reducer_revision,disposition,acknowledged_at_unix) SELECT evidence_id,?2,'rejected_by_host',?3 FROM agent_result_evidence WHERE evidence_id=?1", params![evidence_id, ticket_revision_now, unix_now()?]).map_err(|error| error.to_string())?;
        if changed != 1 {
            return Err("cannot acknowledge missing obsolete configuration result evidence".into());
        }
    }
    tx.commit().map_err(|error| error.to_string())?;
    Ok(true)
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
    let source: Option<ArtifactSourceRow> = tx
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

fn verify_agent_run_snapshot(
    tx: &Transaction<'_>,
    authority: &AgentLaunchAuthority,
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
    Ok(())
}

fn verify_ticket_snapshot(
    tx: &Transaction<'_>,
    authority: &AgentLaunchAuthority,
) -> Result<(), String> {
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
    let coordinator_waiting_for_human = authority.role == Role::Coordinator
        && matches!(
            &result.typed_payload,
            crate::engine::orchestration::RoleResultPayload::HumanRequest(request)
                if request.kind == "clarification"
        );
    for recipient in &result.wake_recipients {
        if coordinator_waiting_for_human && recipient.role == Role::Supervisor {
            // A Coordinator clarification is surfaced through the durable human request. The
            // Supervisor must not consume the result as if the ticket could proceed before the
            // human answer arrives; the answer itself wakes this Coordinator session.
            continue;
        }
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
pub(crate) mod tests {
    use super::*;
    use crate::domain::ids::{OperationId, ProfileId, Revision};
    use crate::domain::types::Role;
    use std::path::PathBuf;

    fn coordinator_spawn_result(child_role: Role) -> IngestedAgentResult {
        let digest = || Digest::parse("a".repeat(64)).unwrap();
        let binding = RoleResultBinding {
            agent_run_id: AgentRunId::parse("coordinator-run").unwrap(),
            operation_id: OperationId::parse("coordinator-operation").unwrap(),
            project_id: ProjectId::parse("project-a").unwrap(),
            role_session_id: crate::engine::orchestration::RoleSessionId::parse(
                "ticket_run:ticket-run:coordinator",
            )
            .unwrap(),
            role: Role::Coordinator,
            parent_run_id: Some(AgentRunId::parse("supervisor-run").unwrap()),
            parent_role: Some(Role::Supervisor),
            ticket_run_id: Some(TicketRunId::parse("ticket-run").unwrap()),
            ticket_revision: Some(Revision(3)),
            config_revision: Revision(2),
            config_digest: digest(),
            profile_digest: digest(),
            instruction_digest: digest(),
            provider_capability_receipt_digest: digest(),
            result_schema_digest: digest(),
            controller_generation: 7,
            run_epoch: 3,
            attempt: 1,
        };
        let request = crate::engine::orchestration::SpawnRequestPayload {
            work_node: crate::engine::orchestration::WorkNodeId::parse("plan-node").unwrap(),
            role: child_role,
            profile_id: ProfileId::parse("planner").unwrap(),
            plan_digest: Some(digest()),
            allowed_repositories: Vec::new(),
            artifact_inputs: Vec::new(),
            parent_run_id: Some(AgentRunId::parse("agent-chosen-parent").unwrap()),
        };
        IngestedAgentResult {
            validated: crate::engine::orchestration::ValidatedRoleResult {
                binding,
                message_id: "message-1".into(),
                kind: crate::engine::orchestration::RoleOutputKind::SpawnRequest,
                assertion: crate::engine::orchestration::AgentAssertion::Succeeded,
                structured_result: serde_json::to_value(&request).unwrap(),
                typed_payload: crate::engine::orchestration::RoleResultPayload::SpawnRequest(
                    request,
                ),
                result_digest: digest(),
                claimed_artifact_refs: Vec::new(),
                wake_recipients: Vec::new(),
            },
            receipt: StoredRoleResultReceipt {
                evidence_id: "evidence-spawn".into(),
                message_id: "message-1".into(),
                content_digest: digest(),
                terminal_digest: digest(),
                wake_input_ids: Vec::new(),
            },
            verified_artifacts: Vec::new(),
        }
    }

    fn spawn_test_store() -> ConfigStore {
        let connection = rusqlite::Connection::open_in_memory().unwrap();
        let mut authority = test_authority();
        authority.agent_run_id = AgentRunId::parse("coordinator-run").unwrap();
        authority.role = Role::Coordinator;
        authority.role_session_id = "ticket_run:ticket-run:coordinator".into();
        authority.parent_run_id = Some(AgentRunId::parse("supervisor-run").unwrap());
        authority.parent_role = Some(Role::Supervisor);
        authority.operation_id = OperationId::parse("coordinator-operation").unwrap();
        authority.run_epoch = 3;
        let authority_json = serde_json::to_string(&authority).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE controller_owners(singleton INTEGER, generation INTEGER, stopped_at_unix INTEGER);
                 INSERT INTO controller_owners VALUES (1,7,NULL);
                 CREATE TABLE projects(project_id TEXT, config_revision INTEGER, config_digest TEXT);
                 INSERT INTO projects VALUES ('project-a',2,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
                 CREATE TABLE ticket_runs(ticket_run_id TEXT, project_id TEXT, revision INTEGER, internal_phase TEXT, config_revision INTEGER, config_digest TEXT);
                 INSERT INTO ticket_runs VALUES ('ticket-run','project-a',3,'planning',2,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
                 CREATE TABLE agent_launch_authority(agent_run_id TEXT, authority_json TEXT);
                 CREATE TABLE agent_result_evidence(evidence_id TEXT, agent_run_id TEXT, project_id TEXT, role TEXT, outcome TEXT, ticket_run_id TEXT, run_epoch INTEGER);
                 INSERT INTO agent_result_evidence VALUES ('evidence-spawn','coordinator-run','project-a','coordinator','completed','ticket-run',3);
                 CREATE TABLE role_wake_inputs(wake_input_id INTEGER PRIMARY KEY, project_id TEXT, role_session_id TEXT, source_type TEXT, source_id TEXT, source_revision INTEGER, priority INTEGER, payload_json TEXT, lifecycle TEXT, created_at_unix INTEGER, UNIQUE(role_session_id,source_type,source_id,source_revision));
                 CREATE TABLE agent_result_reducer_ack(evidence_id TEXT PRIMARY KEY, reducer_revision INTEGER, disposition TEXT, acknowledged_at_unix INTEGER);",
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO agent_launch_authority VALUES ('coordinator-run',?1)",
                [&authority_json],
            )
            .unwrap();
        ConfigStore {
            connection,
            _machine_lock: crate::store::MachineLock { _file: None },
        }
    }

    #[test]
    fn coordinator_spawn_wake_is_durable_idempotent_and_rejects_worker_generic_launch() {
        let mut store = spawn_test_store();
        let result = coordinator_spawn_result(Role::Planner);
        let payload = serde_json::json!({"request":result.validated.structured_result});
        store
            .persist_coordinator_child_wake(
                7,
                &result,
                Role::Planner,
                "ticket_run:ticket-run:planner",
                3,
                &payload,
            )
            .unwrap();
        store
            .persist_coordinator_child_wake(
                7,
                &result,
                Role::Planner,
                "ticket_run:ticket-run:planner",
                3,
                &payload,
            )
            .unwrap();
        let wake_count: u32 = store
            .connection
            .query_row("SELECT COUNT(*) FROM role_wake_inputs", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(wake_count, 1);
        let wake: (String, String, String) = store
            .connection
            .query_row(
                "SELECT source_type,source_id,role_session_id FROM role_wake_inputs",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            wake,
            (
                "coordinator_child".into(),
                "evidence-spawn".into(),
                "ticket_run:ticket-run:planner".into()
            )
        );
        let ack: (u64, String) = store
            .connection
            .query_row(
                "SELECT reducer_revision,disposition FROM agent_result_reducer_ack WHERE evidence_id='evidence-spawn'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(ack, (3, "applied".into()));
        let error = store
            .persist_coordinator_child_wake(
                7,
                &coordinator_spawn_result(Role::Worker),
                Role::Worker,
                "ticket_run:ticket-run:worker",
                3,
                &payload,
            )
            .unwrap_err();
        assert!(error.contains("generic ticket role"));
        store
            .connection
            .execute("UPDATE ticket_runs SET revision=4", [])
            .unwrap();
        assert!(
            store
                .persist_coordinator_child_wake(
                    7,
                    &result,
                    Role::Planner,
                    "ticket_run:ticket-run:planner",
                    3,
                    &payload,
                )
                .unwrap_err()
                .contains("stale")
        );
    }

    #[test]
    fn child_parent_resolves_from_source_evidence_and_host_authority() {
        let connection = rusqlite::Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE role_wake_inputs(wake_input_id INTEGER, project_id TEXT, role_session_id TEXT, source_type TEXT, source_id TEXT);
                 INSERT INTO role_wake_inputs VALUES (1,'project-a','ticket_run:ticket-run:planner','coordinator_child','evidence-spawn');
                 CREATE TABLE agent_result_evidence(evidence_id TEXT,agent_run_id TEXT,project_id TEXT,role TEXT,outcome TEXT);
                 INSERT INTO agent_result_evidence VALUES ('evidence-spawn','coordinator-run','project-a','coordinator','completed');
                 CREATE TABLE agent_launch_authority(agent_run_id TEXT,authority_json TEXT,descriptor_digest TEXT,authority_digest TEXT);",
            )
            .unwrap();
        let mut authority = test_authority();
        authority.agent_run_id = AgentRunId::parse("coordinator-run").unwrap();
        authority.role = Role::Coordinator;
        authority.role_session_id = "ticket_run:ticket-run:coordinator".into();
        let authority_json = serde_json::to_string(&authority).unwrap();
        connection
            .execute(
                "INSERT INTO agent_launch_authority VALUES (?1,?2,?3,?4)",
                rusqlite::params![
                    authority.agent_run_id.as_str(),
                    authority_json,
                    authority.descriptor_digest.as_str(),
                    authority.digest().unwrap().as_str(),
                ],
            )
            .unwrap();
        let store = ConfigStore {
            connection,
            _machine_lock: crate::store::MachineLock { _file: None },
        };
        let parent = store
            .coordinator_child_parent(
                &ProjectId::parse("project-a").unwrap(),
                "ticket_run:ticket-run:planner",
            )
            .unwrap();
        assert_eq!(parent.agent_run_id.as_str(), "coordinator-run");
        assert_eq!(parent.role, Role::Coordinator);
    }

    #[test]
    fn coordinator_parent_resolves_the_exact_supervisor_dispatch_evidence() {
        let digest = || Digest::parse("a".repeat(64)).unwrap();
        let mut authority = test_authority();
        authority.agent_run_id = AgentRunId::parse("supervisor-run").unwrap();
        authority.role = Role::Supervisor;
        authority.role_session_id = "project:project-a:supervisor".into();
        authority.parent_run_id = None;
        authority.parent_role = None;
        authority.ticket_run_id = None;
        authority.ticket_revision = None;
        authority.operation_id = OperationId::parse("supervisor-operation").unwrap();
        authority.run_epoch = 1;
        let dispatch = crate::engine::orchestration::DispatchRequestPayload {
            ticket_reference: crate::domain::ids::TicketId::parse("ticket-42").unwrap(),
            expected_ticket_revision: crate::domain::ids::TicketRevision::parse("rev-8").unwrap(),
            coordinator_profile: ProfileId::parse("planner").unwrap(),
            priority: 1,
            rationale: "matches dispatch policy".into(),
        };
        let structured_result = serde_json::to_value(&dispatch).unwrap();
        let submission = crate::engine::orchestration::RoleResultSubmission {
            schema_version: crate::engine::orchestration::ROLE_RESULT_SCHEMA_VERSION,
            message_id: "dispatch-message".into(),
            binding: binding_for(&authority).unwrap(),
            kind: crate::engine::orchestration::RoleOutputKind::DispatchRequest,
            assertion: crate::engine::orchestration::AgentAssertion::Succeeded,
            result_digest: digest(),
            artifact_refs: Vec::new(),
            structured_result,
        };
        let authority_json = serde_json::to_string(&authority).unwrap();
        let submission_json = serde_json::to_string(&submission).unwrap();
        let connection = rusqlite::Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE role_wake_inputs(wake_input_id INTEGER, project_id TEXT, role_session_id TEXT, source_type TEXT, source_id TEXT, payload_json TEXT);
                 INSERT INTO role_wake_inputs VALUES (1,'project-a','ticket_run:ticket-run:coordinator','ticket_run_dispatch','ticket-run','{\"supervisor_evidence_id\":\"dispatch-evidence\"}');
                 CREATE TABLE ticket_runs(ticket_run_id TEXT, project_id TEXT, ticket_id TEXT, external_revision TEXT);
                 INSERT INTO ticket_runs VALUES ('ticket-run','project-a','ticket-42','rev-8');
                 CREATE TABLE agent_result_evidence(evidence_id TEXT, agent_run_id TEXT, project_id TEXT, role TEXT, ticket_run_id TEXT, outcome TEXT, result_json TEXT);
                 CREATE TABLE agent_launch_authority(agent_run_id TEXT, authority_json TEXT, descriptor_digest TEXT, authority_digest TEXT);",
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO agent_result_evidence VALUES ('dispatch-evidence','supervisor-run','project-a','supervisor',NULL,'completed',?1)",
                [&submission_json],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO agent_launch_authority VALUES ('supervisor-run',?1,?2,?3)",
                rusqlite::params![
                    authority_json,
                    authority.descriptor_digest.as_str(),
                    authority.digest().unwrap().as_str(),
                ],
            )
            .unwrap();
        let store = ConfigStore {
            connection,
            _machine_lock: crate::store::MachineLock { _file: None },
        };
        let parent = store
            .supervisor_parent_for_ticket_run(
                &ProjectId::parse("project-a").unwrap(),
                &TicketRunId::parse("ticket-run").unwrap(),
            )
            .unwrap();
        assert_eq!(parent.agent_run_id.as_str(), "supervisor-run");
        assert_eq!(parent.role, Role::Supervisor);
    }

    pub(super) fn test_authority() -> AgentLaunchAuthority {
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

    pub(crate) fn reviewer_run_step_package(
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
        let profile_digest = crate::store::agent_profile_digest(&profile).unwrap();
        let schema_projection = crate::providers::project_result_schema(&result_schema)
            .unwrap()
            .identity;
        crate::run_step_package::RunStepPackage {
            schema_version: 2,
            execution_slot_epoch: 1,
            descriptor: RunDescriptor {
                schema_version: 1,
                project_id: authority.project_id.clone(),
                run_id: authority.agent_run_id.clone(),
                role: authority.role,
                ticket_run_id: authority.ticket_run_id.clone(),
                operation_id: authority.operation_id.clone(),
                expected_subject_revision: authority
                    .ticket_revision
                    .map_or(0, |revision| revision.0),
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

    pub(super) fn reviewer_qualification(
        authority: &AgentLaunchAuthority,
    ) -> ProviderQualification {
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
            std::slice::from_ref(&process),
            42,
            "birth-token"
        ));
        assert!(!process_tree_contains_root(
            std::slice::from_ref(&process),
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
    fn applied_result_wake_replays_after_ticket_revision_and_owner_advance() {
        let payload = serde_json::json!({
            "plan": { "nodes": [], "requested_investigation_children": 0 },
            "unresolved_questions": []
        });
        let message = RoleResultMessage {
            schema_version: crate::engine::orchestration::ROLE_RESULT_SCHEMA_VERSION,
            message_id: "coordinator-plan-ready-replay".into(),
            kind: crate::engine::orchestration::RoleOutputKind::PlanReady,
            assertion: crate::engine::orchestration::AgentAssertion::Succeeded,
            result_digest: Some(digest(&serde_json::to_vec(&payload).unwrap()).unwrap()),
            structured_result: payload,
            artifact_refs: Vec::new(),
        };
        let first_submission = message.clone();
        let mut fixture =
            crate::store::agent_results::host_validation_fixture::host_validated_result(
                Role::Coordinator,
                message,
            )
            .unwrap();
        let source_generation = fixture.owner_generation;
        let evidence_id = fixture.ingested.receipt.evidence_id.clone();
        let wake_id = fixture.ingested.receipt.wake_input_ids[0];
        let ticket_run_id = fixture
            .ingested
            .validated
            .binding
            .ticket_run_id
            .as_ref()
            .unwrap();

        // Model the accepted-plan ACK, subsequent prepare/revision advance, and owner restart.
        fixture
            .store
            .acknowledge_validated_agent_result(
                source_generation,
                &evidence_id,
                4,
                ResultDisposition::Applied,
            )
            .unwrap();
        fixture.store.connection.execute(
            "UPDATE ticket_runs SET revision=5,internal_phase='implementing' WHERE ticket_run_id=?1",
            [ticket_run_id.as_str()],
        ).unwrap();

        let same_owner_replay = agent_result_for_wake(
            &mut fixture.store,
            &fixture.artifacts,
            source_generation,
            i64::try_from(wake_id).unwrap(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(same_owner_replay.receipt.evidence_id, evidence_id);

        fixture.store.stop_owner(source_generation).unwrap();
        let current_generation = fixture
            .store
            .start_owner(&crate::store::OwnerMetadata {
                owner_nonce: "fixture-owner-restarted".into(),
                state_root: fixture._temp.path().display().to_string(),
                config_source: "fixture".into(),
                process_start_identity: "test-owner-restarted".into(),
                executable_path: "/test/fixture".into(),
                executable_digest: "b".repeat(64),
                rex_endpoint: Some("http://fixture".into()),
                rex_server_identity: Some("fixture-rex".into()),
                rex_session_id: Some("fixture-session".into()),
                rex_block_id: Some("fixture-block".into()),
            })
            .unwrap();
        assert_ne!(source_generation, current_generation);

        let replayed = agent_result_for_wake(
            &mut fixture.store,
            &fixture.artifacts,
            current_generation,
            i64::try_from(wake_id).unwrap(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(replayed.receipt.evidence_id, evidence_id);
        assert!(replayed.receipt.wake_input_ids.contains(&wake_id));

        let repeated = agent_result_for_wake(
            &mut fixture.store,
            &fixture.artifacts,
            current_generation,
            i64::try_from(wake_id).unwrap(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(repeated.receipt.evidence_id, evidence_id);
        assert_eq!(
            crate::store::agent_results::host_validation_fixture::result_ack(
                &fixture.store,
                &evidence_id,
            )
            .unwrap()
            .unwrap(),
            (4, "applied".into())
        );

        let terminal = verify_agent_terminal(
            &fixture.store,
            current_generation,
            &replayed.validated.binding.agent_run_id,
        )
        .unwrap();
        assert_eq!(
            terminal.agent_run_id,
            replayed.validated.binding.agent_run_id
        );
        // Even with the old TicketRun revision, the provider terminal still binds the exact
        // persisted message; changing that message cannot turn a replay into new evidence.
        let mut changed_submission = first_submission.clone();
        changed_submission.message_id.push_str("-changed");
        assert!(
            ingest_agent_result(
                &mut fixture.store,
                &fixture.artifacts,
                current_generation,
                &terminal,
                changed_submission,
            )
            .unwrap_err()
            .contains("submitted role result differs from the persisted provider terminal payload")
        );

        let mut stale_fixture =
            crate::store::agent_results::host_validation_fixture::host_validated_terminal_result(
                Role::Coordinator,
                first_submission.clone(),
            )
            .unwrap();
        stale_fixture
            .store
            .connection
            .execute(
                "UPDATE ticket_runs SET revision=5,internal_phase='implementing' WHERE ticket_run_id='fixture-ticket-run'",
                [],
            )
            .unwrap();
        assert!(
            stale_fixture
                .store
                .store_validated_agent_result(
                    &stale_fixture.artifacts,
                    stale_fixture.owner_generation,
                    &stale_fixture.terminal,
                    first_submission,
                )
                .unwrap_err()
                .contains("TicketRun revision or config no longer matches Agent launch authority")
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

    fn spooled_candidate(
        store: &rusqlite::Connection,
        root: &std::path::Path,
        run_id: &str,
        updated_at: i64,
        outcome: TurnOutcome,
        structured_result: Option<serde_json::Value>,
    ) -> AgentRunId {
        use crate::domain::types::AgentAdapter;
        use crate::launch::{
            AgentLaunchReceipt, LaunchDecision, ObservedProviderStart, ProviderProcessIdentity,
        };
        use crate::run_step::{
            CleanupState, ObservedProcess, ProviderResultFailure, RunReceipt, TurnResult,
        };
        use crate::run_step_spool::{RunFamilyBinding, RunFamilyCoverage, RunFamilyRecord};
        use sha2::{Digest as _, Sha256};

        let root = root.join(run_id);
        let control_dir = root.join("control");
        let workspace_path = root.join("workspace");
        std::fs::create_dir_all(&control_dir).unwrap();
        std::fs::create_dir_all(&workspace_path).unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        let mut authority = test_authority();
        authority.agent_run_id = AgentRunId::parse(run_id).unwrap();
        authority.role = Role::Reviewer;
        authority.role_session_id = format!("ticket_run:ticket-run:reviewer:{run_id}");
        authority.control_dir = control_dir;
        authority.workspace_path = workspace_path;
        authority.descriptor_path = root.join("package.json");
        let schema: serde_json::Value = crate::protocol::parse_unique(include_bytes!(
            "../../schemas/agent-results/reviewer-v1.json"
        ))
        .unwrap();
        authority.result_schema_digest = crate::providers::project_result_schema(&schema)
            .unwrap()
            .identity
            .source_schema_digest;
        let package = reviewer_run_step_package(&authority, schema.clone());
        authority.profile_digest = package.descriptor.profile_digest.clone();
        let qualification = reviewer_qualification(&authority);
        authority.qualification_receipt_digest = qualification.canonical_digest().unwrap();
        let package = reviewer_run_step_package(&authority, schema.clone());
        authority.descriptor_digest = package.publish_once(&authority.descriptor_path).unwrap();
        let authority_digest = authority.digest().unwrap();
        authority.validate().unwrap();
        store.execute(
            "INSERT INTO agent_launch_authority(agent_run_id,authority_json,descriptor_digest,authority_digest,controller_generation,control_dir) VALUES (?1,?2,?3,?4,?5,?6)",
            rusqlite::params![
                authority.agent_run_id.as_str(),
                serde_json::to_string(&authority).unwrap(),
                authority.descriptor_digest.as_str(),
                authority_digest.as_str(),
                authority.controller_generation,
                authority.control_dir.display().to_string(),
            ],
        ).unwrap();
        store
            .execute(
                "INSERT INTO provider_qualifications(receipt_digest,receipt_json) VALUES (?1,?2)",
                rusqlite::params![
                    authority.qualification_receipt_digest.as_str(),
                    serde_json::to_string(&qualification).unwrap(),
                ],
            )
            .unwrap();

        let wrapper_pid = 10_000 + updated_at as u32;
        let provider_pid = wrapper_pid + 1;
        let wrapper_start_identity = format!("wrapper-{run_id}");
        let provider_start_identity = format!("provider-{run_id}");
        let spool = crate::run_step_spool::RunStepSpool::open(&authority.control_dir).unwrap();
        let start = spool
            .publish_start_once(crate::launch::AgentStartRequest {
                schema_version: 1,
                operation_id: authority.operation_id.clone(),
                agent_run_id: authority.agent_run_id.clone(),
                project_id: authority.project_id.clone(),
                controller_generation: authority.controller_generation,
                descriptor_digest: authority.descriptor_digest.clone(),
                runtime_binary_digest: authority.runtime_binary_digest.clone(),
                environment_snapshot_id: authority.environment_snapshot_id.clone(),
                qualification_receipt_digest: authority.qualification_receipt_digest.clone(),
                wrapper_pid,
                wrapper_start_identity: wrapper_start_identity.clone(),
                rex_session_id: authority.rex_session_id.clone(),
                rex_block_id: authority.rex_block_id.clone(),
            })
            .unwrap();
        let process = crate::process::ProcessIdentity {
            pid: provider_pid,
            parent_pid: wrapper_pid,
            process_group_id: wrapper_pid,
            start_identity: provider_start_identity.clone(),
            command: "/bin/codex".into(),
            quality: crate::process::ProcessIdentityQuality::KernelBirthToken,
        };
        let process_tree = vec![process.clone()];
        let process_tree_digest = Digest::parse(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&process_tree).unwrap())
        ))
        .unwrap();
        let binding = RunFamilyBinding {
            schema_version: 1,
            agent_run_id: authority.agent_run_id.clone(),
            reservation_epoch: 1,
            authority_digest: authority_digest.clone(),
            descriptor_digest: authority.descriptor_digest.clone(),
            wrapper_pid,
            wrapper_start_identity: wrapper_start_identity.clone(),
        };
        spool.publish_run_family_binding_once(&binding).unwrap();
        let family = |coverage| RunFamilyRecord {
            schema_version: 2,
            binding: binding.clone(),
            observed_at_unix: if coverage == RunFamilyCoverage::Complete {
                2
            } else {
                1
            },
            coverage,
            wrapper_process: crate::process::ProcessIdentity {
                pid: wrapper_pid,
                parent_pid: 1,
                process_group_id: wrapper_pid,
                start_identity: wrapper_start_identity.clone(),
                command: "/usr/local/bin/rex-projects".into(),
                quality: crate::process::ProcessIdentityQuality::KernelBirthToken,
            },
            provider_root: process.clone(),
            provider_executable_path: "/bin/codex".into(),
            provider_executable_digest: qualification.executable_digest.clone(),
            process_tree: process_tree.clone(),
            process_tree_digest: process_tree_digest.clone(),
        };
        spool
            .write_run_family_record(&family(RunFamilyCoverage::Observing))
            .unwrap();
        spool
            .write_run_family_record(&family(RunFamilyCoverage::Complete))
            .unwrap();
        spool
            .publish_start_receipt(
                &start,
                AgentLaunchReceipt {
                    schema_version: 1,
                    operation_id: authority.operation_id.clone(),
                    agent_run_id: authority.agent_run_id.clone(),
                    controller_generation: authority.controller_generation,
                    descriptor_digest: authority.descriptor_digest.clone(),
                    runtime_binary_digest: authority.runtime_binary_digest.clone(),
                    qualification_receipt_digest: authority.qualification_receipt_digest.clone(),
                    decision: LaunchDecision::Accepted,
                    reason: None,
                },
            )
            .unwrap();
        let projection = crate::providers::project_result_schema(&schema)
            .unwrap()
            .identity;
        let result = TurnResult {
            receipt: RunReceipt {
                run_id: authority.agent_run_id.clone(),
                attempt: authority.attempt,
                provider: AgentAdapter::Codex,
                effective_permission_mode: "workspace_write".into(),
                conversation_id: None,
                provider_version: Some("fixture-1".into()),
                capability_receipt_digest: Some(authority.qualification_receipt_digest.clone()),
                schema_projection: projection,
                launch_pid_hint: Some(provider_pid),
                exit_code: Some(0),
                timed_out: false,
                cancellation_signal: None,
                cleanup: if matches!(&outcome, TurnOutcome::Completed) {
                    CleanupState::Confirmed
                } else {
                    CleanupState::Unknown
                },
                cleanup_detail: None,
                processes: vec![ObservedProcess {
                    pid: process.pid,
                    parent_pid: process.parent_pid,
                    process_group_id: process.process_group_id,
                    start_identity: process.start_identity.clone(),
                    command: process.command.clone(),
                    identity_quality: "kernel_birth_token".into(),
                }],
                result_digest: None,
                provider_result_failure: Some(ProviderResultFailure::StructuredOutputMissing),
                provider_process_failure: None,
                outcome,
            },
            structured_result,
        };
        spool.publish_turn_result_once(&start, result).unwrap();

        let observed = ObservedProviderStart {
            agent_run_id: authority.agent_run_id.clone(),
            operation_id: authority.operation_id.clone(),
            provider_pid,
            provider_start_identity,
            executable_digest: qualification.executable_digest,
            process_tree_digest: process_tree_digest.clone(),
            process_tree_confirmed: true,
            process_tree: vec![ProviderProcessIdentity {
                pid: process.pid,
                parent_pid: process.parent_pid,
                process_group_id: process.process_group_id,
                start_identity: process.start_identity,
                identity_quality: process.quality,
            }],
        };
        store.execute(
            "INSERT INTO agent_launch_state(agent_run_id,state,start_request_digest,provider_process_tree_json,updated_at_unix) VALUES (?1,'running',?2,?3,?4)",
            rusqlite::params![
                authority.agent_run_id.as_str(),
                start.request_digest,
                serde_json::to_string(&observed).unwrap(),
                updated_at,
            ],
        ).unwrap();
        store.execute(
            "INSERT INTO execution_slots(owner_kind,owner_id,disposition,reservation_epoch) VALUES ('agent_run',?1,'live',1)",
            [authority.agent_run_id.as_str()],
        ).unwrap();
        authority.agent_run_id
    }

    fn spooled_result_test_store() -> ConfigStore {
        let connection = rusqlite::Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE agent_launch_authority(agent_run_id TEXT,authority_json TEXT,descriptor_digest TEXT,authority_digest TEXT,controller_generation INTEGER,control_dir TEXT);
                 CREATE TABLE agent_launch_state(agent_run_id TEXT,state TEXT,start_request_digest TEXT,provider_process_tree_json TEXT,updated_at_unix INTEGER);
                 CREATE TABLE agent_terminal_receipts(agent_run_id TEXT);
                 CREATE TABLE provider_qualifications(receipt_digest TEXT,receipt_json TEXT);
                 CREATE TABLE agent_result_evidence(evidence_id TEXT,agent_run_id TEXT,message_id TEXT,result_json TEXT,received_at_unix INTEGER);
                 CREATE TABLE agent_result_reducer_ack(evidence_id TEXT);
                 CREATE TABLE execution_slots(owner_kind TEXT,owner_id TEXT,disposition TEXT,reservation_epoch INTEGER);",
            )
            .unwrap();
        ConfigStore {
            connection,
            _machine_lock: crate::store::MachineLock { _file: None },
        }
    }

    #[test]
    fn missing_result_spool_is_deferred_without_releasing_capacity() {
        let temp = tempfile::tempdir().unwrap();
        let mut store = spooled_result_test_store();
        let run_id = spooled_candidate(
            &store.connection,
            temp.path(),
            "missing-result-run",
            1,
            TurnOutcome::MissingResult,
            None,
        );
        let artifacts =
            crate::artifacts::ArtifactStore::open(&temp.path().join("artifacts")).unwrap();

        let result = ingest_next_spooled_agent_result(&mut store, &artifacts, 7, 8).unwrap();

        assert!(result.is_none());
        let disposition: String = store
            .connection
            .query_row(
                "SELECT disposition FROM execution_slots WHERE owner_id=?1",
                [run_id.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(disposition, "live");
        let terminal_count: u64 = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM agent_terminal_receipts WHERE agent_run_id=?1",
                [run_id.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(terminal_count, 0);
    }

    #[test]
    fn missing_result_candidate_does_not_hide_later_completed_candidate() {
        let temp = tempfile::tempdir().unwrap();
        let mut store = spooled_result_test_store();
        spooled_candidate(
            &store.connection,
            temp.path(),
            "missing-result-run",
            1,
            TurnOutcome::MissingResult,
            None,
        );
        spooled_candidate(
            &store.connection,
            temp.path(),
            "completed-without-result-run",
            2,
            TurnOutcome::Completed,
            None,
        );
        let artifacts =
            crate::artifacts::ArtifactStore::open(&temp.path().join("artifacts")).unwrap();

        let error = ingest_next_spooled_agent_result(&mut store, &artifacts, 7, 8).unwrap_err();

        assert!(error.contains("completed provider receipt has no structured result"));
        let missing_result_slot: String = store
            .connection
            .query_row(
                "SELECT disposition FROM execution_slots WHERE owner_id='missing-result-run'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(missing_result_slot, "live");
    }

    #[test]
    fn missing_result_without_provider_observation_defers_to_recovery() {
        let temp = tempfile::tempdir().unwrap();
        let mut store = spooled_result_test_store();
        let run_id = spooled_candidate(
            &store.connection,
            temp.path(),
            "unobserved-missing-result-run",
            1,
            TurnOutcome::MissingResult,
            None,
        );
        store
            .connection
            .execute(
                "UPDATE agent_launch_state SET provider_process_tree_json=NULL WHERE agent_run_id=?1",
                [run_id.as_str()],
            )
            .unwrap();
        let artifacts =
            crate::artifacts::ArtifactStore::open(&temp.path().join("artifacts")).unwrap();

        let result = ingest_next_spooled_agent_result(&mut store, &artifacts, 7, 8).unwrap();

        assert!(result.is_none());
        let disposition: String = store
            .connection
            .query_row(
                "SELECT disposition FROM execution_slots WHERE owner_id=?1",
                [run_id.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(disposition, "live");
    }
}
#[allow(clippy::items_after_test_module)]
impl ConfigStore {
    /// Atomically consumes a host-validated Supervisor intervention and wakes the exact
    /// canonical Coordinator for the still-current TicketRun revision.
    pub fn apply_supervisor_intervention(
        &mut self,
        owner_generation: u64,
        result: &IngestedAgentResult,
    ) -> Result<bool, String> {
        use crate::engine::orchestration::RoleResultPayload;

        let binding = &result.validated.binding;
        let RoleResultPayload::Intervention(intervention) = &result.validated.typed_payload else {
            return Err("Supervisor intervention consumer received another result kind".into());
        };
        let coordinator_session = intervention.coordinator_role_session_id.as_str();
        let ticket_run_raw = coordinator_session
            .strip_prefix("ticket_run:")
            .and_then(|value| value.strip_suffix(":coordinator"))
            .ok_or("Supervisor intervention Coordinator session is not canonical")?;
        let ticket_run_id = TicketRunId::parse(ticket_run_raw.to_owned())?;
        let revision = intervention.ticket_run_revision.0;
        if binding.role != crate::domain::types::Role::Supervisor
            || result.validated.assertion != crate::engine::orchestration::AgentAssertion::Succeeded
            || binding.ticket_run_id.is_some()
            || binding.ticket_revision.is_some()
            || coordinator_session != format!("ticket_run:{}:coordinator", ticket_run_id.as_str())
            || intervention.reason.is_empty()
            || intervention.proposed_plan_change.is_empty()
            || revision == 0
        {
            return Err("Supervisor intervention target is invalid or noncanonical".into());
        }
        let role_session_id = intervention.coordinator_role_session_id.as_str();
        let payload = serde_json::json!({
            "schema_version": 1,
            "kind": "supervisor_intervention",
            "evidence_id": result.receipt.evidence_id(),
            "ticket_run_id": ticket_run_id.as_str(),
            "revision": revision,
            "reason": intervention.reason,
            "proposed_plan_change": intervention.proposed_plan_change,
            "evidence": intervention.evidence,
        });
        let payload_json = serde_json::to_string(&payload).map_err(|error| error.to_string())?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        super::validate_active_generation(&tx, owner_generation)?;

        let source: Option<ArtifactSourceWithAuthorityRow> = tx.query_row(
            "SELECT e.project_id,e.role,e.ticket_run_id,a.ticket_revision,a.role_session_id,a.config_revision,a.config_digest,a.authority_json,a.authority_digest FROM agent_result_evidence e JOIN agent_launch_authority a USING(agent_run_id) WHERE e.evidence_id=?1 AND e.result_digest=?2",
            rusqlite::params![result.receipt.evidence_id(), result.validated.result_digest.as_str()],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?)),
        ).optional().map_err(|error| error.to_string())?;
        let Some((
            source_project,
            source_role,
            source_ticket_run,
            source_revision,
            source_session,
            source_config_revision,
            source_config_digest,
            source_authority_json,
            source_authority_digest,
        )) = source
        else {
            return Err("Supervisor intervention has no matching immutable host evidence".into());
        };
        let source_authority: AgentLaunchAuthority =
            crate::protocol::parse_unique(source_authority_json.as_bytes())?;
        if source_project != binding.project_id.as_str()
            || source_role != "supervisor"
            || source_ticket_run.is_some()
            || source_session != format!("project:{}:supervisor", binding.project_id.as_str())
            || source_revision.is_some()
            || source_config_revision != binding.config_revision.0
            || source_config_digest != binding.config_digest.as_str()
            || source_authority.agent_run_id != binding.agent_run_id
            || source_authority.digest()?.as_str() != source_authority_digest
            || source_authority.role != crate::domain::types::Role::Supervisor
            || source_authority.ticket_run_id.is_some()
            || source_authority.project_id.as_str() != source_project
            || source_authority.role_session_id != source_session
            || source_authority.config_revision.0 != source_config_revision
            || source_authority.config_digest.as_str() != source_config_digest
        {
            return Err(
                "Supervisor intervention provenance is outside its Project authority".into(),
            );
        }
        if let Some((ack_revision, disposition)) = tx
            .query_row(
                "SELECT reducer_revision,disposition FROM agent_result_reducer_ack WHERE evidence_id=?1",
                [result.receipt.evidence_id()],
                |row| Ok((row.get::<_, u64>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?
        {
            if disposition == "rejected_by_host" {
                tx.commit().map_err(|error| error.to_string())?;
                return Ok(true);
            }
            if ack_revision != revision || disposition != "applied" {
                return Err("Supervisor intervention was acknowledged with conflicting semantics".into());
            }
            let wake: Option<String> = tx.query_row(
                "SELECT payload_json FROM role_wake_inputs WHERE project_id=?1 AND role_session_id=?2 AND source_type='supervisor_intervention' AND source_id=?3 AND source_revision=?4",
                rusqlite::params![source_project,role_session_id,result.receipt.evidence_id(),revision],
                |row| row.get(0),
            ).optional().map_err(|error| error.to_string())?;
            if wake.as_deref() != Some(payload_json.as_str()) {
                return Err("acknowledged Supervisor intervention has no matching Coordinator wake".into());
            }
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(true);
        }
        let project_config: Option<(u64, String)> = tx
            .query_row(
                "SELECT config_revision,config_digest FROM projects WHERE project_id=?1",
                [binding.project_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if !matches!(project_config, Some((revision, ref digest)) if revision == binding.config_revision.0 && digest == binding.config_digest.as_str())
        {
            let rejected_revision = project_config
                .as_ref()
                .map(|value| value.0)
                .unwrap_or(binding.config_revision.0)
                .max(1);
            tx.execute(
                "INSERT INTO agent_result_reducer_ack(evidence_id,reducer_revision,disposition,acknowledged_at_unix) VALUES (?1,?2,'rejected_by_host',?3)",
                rusqlite::params![result.receipt.evidence_id(), rejected_revision, unix_now()?],
            ).map_err(|error| error.to_string())?;
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(true);
        }
        let current: Option<(String, u64, String)> = tx
            .query_row(
                "SELECT project_id,revision,internal_phase FROM ticket_runs WHERE ticket_run_id=?1",
                [ticket_run_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let Some((project_id, current_revision, phase)) = current else {
            return Err("Supervisor intervention TicketRun no longer exists".into());
        };
        if project_id != binding.project_id.as_str() {
            return Err("Supervisor intervention TicketRun changed Project ownership".into());
        }
        if current_revision != revision || matches!(phase.as_str(), "done" | "canceled") {
            tx.execute(
                "INSERT INTO agent_result_reducer_ack(evidence_id,reducer_revision,disposition,acknowledged_at_unix) VALUES (?1,?2,'rejected_by_host',?3)",
                rusqlite::params![result.receipt.evidence_id(), current_revision.max(1), unix_now()?],
            ).map_err(|error| error.to_string())?;
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(true);
        }
        tx.execute(
            "INSERT INTO role_wake_inputs(project_id,role_session_id,source_type,source_id,source_revision,priority,payload_json,lifecycle,created_at_unix) VALUES (?1,?2,'supervisor_intervention',?3,?4,90,?5,'pending',?6)",
            rusqlite::params![project_id,role_session_id,result.receipt.evidence_id(),revision,payload_json,unix_now()?],
        ).map_err(|error| error.to_string())?;
        tx.execute(
            "INSERT INTO agent_result_reducer_ack(evidence_id,reducer_revision,disposition,acknowledged_at_unix) VALUES (?1,?2,'applied',?3)",
            rusqlite::params![result.receipt.evidence_id(),revision,unix_now()?],
        ).map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(true)
    }

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

#[cfg(test)]
pub(crate) mod host_validation_fixture {
    use super::*;
    use crate::config::{AppliedConfig, SourceFile, SourceKind};
    use crate::domain::ids::{OperationId, ProfileId, Revision};
    use crate::domain::types::{AgentAdapter, Role};
    use crate::launch::ObservedProviderStart;
    use crate::roles::RoleResultMessage;
    use crate::run_step::{ObservedProcess, RunReceipt};
    use crate::run_step_spool::{AgentTurnResult, StartRequestEnvelope};
    use crate::store::OwnerMetadata;
    use crate::store::{ConfigStore, ExpectedRevision, ProjectRecord};
    use sha2::Sha256;
    use std::process::Command;

    pub(crate) struct TestValidatedResultFixture {
        pub _temp: tempfile::TempDir,
        pub store: ConfigStore,
        pub artifacts: crate::artifacts::ArtifactStore,
        pub owner_generation: u64,
        pub ingested: IngestedAgentResult,
    }

    pub(crate) struct TestTerminalResultFixture {
        pub _temp: tempfile::TempDir,
        pub store: ConfigStore,
        pub artifacts: crate::artifacts::ArtifactStore,
        pub owner_generation: u64,
        pub terminal: VerifiedAgentTerminal,
    }

    pub(crate) struct InPlaceValidatedResultFixture {
        pub artifacts: crate::artifacts::ArtifactStore,
        pub ingested: IngestedAgentResult,
    }

    struct InPlaceTerminalFixture {
        artifacts: crate::artifacts::ArtifactStore,
        terminal: VerifiedAgentTerminal,
        message: RoleResultMessage,
    }

    /// Builds real host terminal and result evidence around test-seeded running launch records.
    /// Qualification, published package, process absence, terminal, and result validators are
    /// production paths; only the earlier controller/Rex prerecords are seeded in the test DB.
    pub(crate) fn host_validated_result(
        role: Role,
        message: RoleResultMessage,
    ) -> Result<TestValidatedResultFixture, String> {
        let mut fixture = host_validated_result_setup(role, message)?;
        let ingested = fixture.store.store_validated_agent_result(
            &fixture.artifacts,
            fixture.owner_generation,
            &fixture.terminal,
            fixture.message,
        )?;
        Ok(TestValidatedResultFixture {
            _temp: fixture.temp,
            store: fixture.store,
            artifacts: fixture.artifacts,
            owner_generation: fixture.owner_generation,
            ingested,
        })
    }

    pub(crate) fn host_validated_terminal_result(
        role: Role,
        message: RoleResultMessage,
    ) -> Result<TestTerminalResultFixture, String> {
        let fixture = host_validated_result_setup(role, message)?;
        Ok(TestTerminalResultFixture {
            _temp: fixture.temp,
            store: fixture.store,
            artifacts: fixture.artifacts,
            owner_generation: fixture.owner_generation,
            terminal: fixture.terminal,
        })
    }

    struct HostValidatedResultSetup {
        temp: tempfile::TempDir,
        store: ConfigStore,
        owner_generation: u64,
        artifacts: crate::artifacts::ArtifactStore,
        terminal: VerifiedAgentTerminal,
        message: RoleResultMessage,
    }

    fn host_validated_result_setup(
        role: Role,
        message: RoleResultMessage,
    ) -> Result<HostValidatedResultSetup, String> {
        let temp = tempfile::tempdir().map_err(|error| error.to_string())?;
        let root = std::fs::canonicalize(temp.path()).map_err(|error| error.to_string())?;
        let mut store = ConfigStore::open_test(&root)?;
        let config_digest = "a".repeat(64);
        let applied = AppliedConfig {
            config: serde_json::from_value(serde_json::json!({"schema_version":1,"adapters":{"tickets":{"kind":"command","command":["test"]}},"projects":{}})).map_err(|error| error.to_string())?,
            profiles: std::collections::BTreeMap::new(),
            source_root: root.display().to_string(),
            source_files: vec![SourceFile { kind: SourceKind::File, path: root.join("config.toml").display().to_string(), canonical_path: root.join("config.toml").display().to_string(), sha256: digest(b"config" )?, bytes: 6, contents: "fixture".into() }],
            digest: Digest::parse(config_digest.clone())?,
        };
        let applied = store.apply_snapshot("fixture", &applied, ExpectedRevision::Bootstrap)?;
        let project_id = ProjectId::parse("fixture-project")?;
        store.insert_project(&ProjectRecord {
            id: project_id.clone(),
            config_source: "fixture".into(),
            config_revision: applied.revision,
            config_digest: Digest::parse(config_digest.clone())?,
            mode: "goal".into(),
            goal_revision: 1,
            desired_lifecycle: "running".into(),
            state_revision: Revision(0),
        })?;
        let owner_generation = store.start_owner(&OwnerMetadata {
            owner_nonce: "fixture-owner".into(),
            state_root: root.display().to_string(),
            config_source: "fixture".into(),
            process_start_identity: "test-owner-identity".into(),
            executable_path: "/test/fixture".into(),
            executable_digest: "b".repeat(64),
            rex_endpoint: Some("http://fixture".into()),
            rex_server_identity: Some("fixture-rex".into()),
            rex_session_id: Some("fixture-session".into()),
            rex_block_id: Some("fixture-block".into()),
        })?;
        let ticket_run_id = TicketRunId::parse("fixture-ticket-run")?;
        let (phase, external_status, ticket_revision) = match role {
            Role::Coordinator => ("planning", "in_progress", 3_u64),
            Role::Postmortem => ("postmortem", "in_progress", 1_u64),
            Role::Worker => ("implementing", "in_progress", 4_u64),
            _ => ("reviewing", "in_review", 1_u64),
        };
        if role != Role::Supervisor {
            store.connection.execute(
            "INSERT INTO ticket_runs(ticket_run_id,project_id,config_source,config_revision,config_digest,namespace,ticket_id,generation,internal_phase,activity,external_status,observed_status,revision) VALUES (?1,?2,'fixture',?3,?4,'fixture','T-1',1,?5,'running',?6,?6,?7)",
            rusqlite::params![ticket_run_id.as_str(), project_id.as_str(), applied.revision.0, config_digest, phase, external_status, ticket_revision],
        ).map_err(|error| error.to_string())?;
            let recipe_id = if role == Role::Worker {
                Some("fixture-recipe")
            } else {
                None
            };
            store.connection.execute(
            "INSERT INTO ticket_run_context(ticket_run_id,project_id,project_epoch,recipe_id,goal_revision,created_at_unix) VALUES (?1,?2,1,?3,1,1)",
            rusqlite::params![ticket_run_id.as_str(), project_id.as_str(), recipe_id],
        ).map_err(|error| error.to_string())?;
        }
        let evidence = if role == Role::Supervisor {
            host_validated_supervisor_terminal_in(
                &mut store,
                &root,
                owner_generation,
                project_id,
                message,
            )?
        } else {
            host_validated_terminal_in(
                &mut store,
                &root,
                owner_generation,
                project_id,
                ticket_run_id,
                role,
                message,
            )?
        };
        Ok(HostValidatedResultSetup {
            temp,
            store,
            owner_generation,
            artifacts: evidence.artifacts,
            terminal: evidence.terminal,
            message: evidence.message,
        })
    }

    /// Adds a real host-validated result to an existing publication/Reviewing database.
    /// Project configuration, owner, and TicketRun state are read from that database so the
    /// launch authority is bound to its current revision and configuration.
    pub(crate) fn host_validated_result_in(
        store: &mut ConfigStore,
        root: &std::path::Path,
        owner_generation: u64,
        project_id: ProjectId,
        ticket_run_id: TicketRunId,
        role: Role,
        message: RoleResultMessage,
    ) -> Result<InPlaceValidatedResultFixture, String> {
        let prepared = host_validated_result_inner(
            store,
            root,
            owner_generation,
            project_id,
            Some(ticket_run_id),
            role,
            message,
        )?;
        let ingested = store.store_validated_agent_result(
            &prepared.artifacts,
            owner_generation,
            &prepared.terminal,
            prepared.message,
        )?;
        Ok(InPlaceValidatedResultFixture {
            artifacts: prepared.artifacts,
            ingested,
        })
    }

    fn host_validated_terminal_in(
        store: &mut ConfigStore,
        root: &std::path::Path,
        owner_generation: u64,
        project_id: ProjectId,
        ticket_run_id: TicketRunId,
        role: Role,
        message: RoleResultMessage,
    ) -> Result<InPlaceTerminalFixture, String> {
        host_validated_result_inner(
            store,
            root,
            owner_generation,
            project_id,
            Some(ticket_run_id),
            role,
            message,
        )
    }

    fn host_validated_supervisor_terminal_in(
        store: &mut ConfigStore,
        root: &std::path::Path,
        owner_generation: u64,
        project_id: ProjectId,
        message: RoleResultMessage,
    ) -> Result<InPlaceTerminalFixture, String> {
        host_validated_result_inner(
            store,
            root,
            owner_generation,
            project_id,
            None,
            Role::Supervisor,
            message,
        )
    }

    fn host_validated_result_inner(
        store: &mut ConfigStore,
        root: &std::path::Path,
        owner_generation: u64,
        project_id: ProjectId,
        ticket_run_id: Option<TicketRunId>,
        role: Role,
        mut message: RoleResultMessage,
    ) -> Result<InPlaceTerminalFixture, String> {
        let project = store
            .project(&project_id)?
            .ok_or("fixture Project is missing")?;
        let config_source = project.config_source.clone();
        let config_revision = project.config_revision;
        let config_digest = project.config_digest.as_str().to_owned();
        let ticket_snapshot: Option<(u64, String, String)> = ticket_run_id.as_ref().map(|ticket_run_id| store.connection
            .query_row(
                "SELECT revision,namespace,ticket_id FROM ticket_runs WHERE ticket_run_id=?1 AND project_id=?2",
                rusqlite::params![ticket_run_id.as_str(), project_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(|error| error.to_string())).transpose()?;
        let (ticket_revision, namespace, ticket_id) =
            ticket_snapshot.unwrap_or((1, "fixture".into(), "T-1".into()));
        let supervisor_suffix = (role == Role::Supervisor)
            .then(|| format!("{:x}", Sha256::digest(message.message_id.as_bytes())));
        let agent_run_id = AgentRunId::parse(supervisor_suffix.as_ref().map_or_else(
            || "fixture-agent-run".to_owned(),
            |suffix| format!("fixture-agent-{}", &suffix[..16]),
        ))?;
        let mut authority = crate::store::agent_results::tests::test_authority();
        authority.agent_run_id = agent_run_id.clone();
        if let Some(suffix) = &supervisor_suffix {
            authority.operation_id = OperationId::parse(format!("fixture-op-{}", &suffix[..16]))?;
        }
        authority.project_id = project_id.clone();
        authority.role = role;
        authority.role_session_id = match role {
            Role::Worker => "ticket:fixture-ticket-run:worker:node-a".into(),
            Role::Coordinator => "ticket_run:fixture-ticket-run:coordinator".into(),
            Role::Supervisor => format!("project:{}:supervisor", project_id.as_str()),
            _ => format!("fixture-{:?}", role).to_lowercase(),
        };
        let parent_run_id = AgentRunId::parse("fixture-parent-run")?;
        let parent_role = if role == Role::Coordinator {
            Role::Supervisor
        } else {
            Role::Coordinator
        };
        let parent_role_session_id = if role == Role::Supervisor {
            None
        } else if parent_role == Role::Supervisor {
            Some(format!("project:{project_id}:supervisor"))
        } else {
            ticket_run_id
                .as_ref()
                .map(|ticket_run_id| format!("ticket_run:{ticket_run_id}:coordinator"))
        };
        if role == Role::Supervisor {
            authority.parent_run_id = None;
            authority.parent_role = None;
            authority.ticket_run_id = None;
            authority.ticket_revision = None;
        } else {
            authority.parent_run_id = Some(parent_run_id.clone());
            authority.parent_role = Some(parent_role);
            authority.ticket_run_id = ticket_run_id.clone();
            authority.ticket_revision = ticket_run_id.as_ref().map(|_| Revision(ticket_revision));
        }
        authority.config_revision = config_revision;
        authority.config_digest = Digest::parse(config_digest.clone())?;
        authority.controller_generation = owner_generation;
        authority.rex_server_identity = "fixture-rex".into();
        authority.rex_session_id = "fixture-session".into();
        authority.rex_window_id = "fixture-window".into();
        authority.rex_block_id = "fixture-block".into();
        authority.descriptor_path = root.join(format!("{}-run-step-package.json", agent_run_id));
        authority.workspace_path = root.join(format!("{}-workspace", agent_run_id));
        authority.control_dir = root.join(format!("{}-control", agent_run_id));
        std::fs::create_dir(&authority.workspace_path).map_err(|error| error.to_string())?;
        std::fs::create_dir(&authority.control_dir).map_err(|error| error.to_string())?;
        let profile: crate::config::Profile = serde_json::from_value(serde_json::json!({
            "adapter":"codex", "command":["/bin/codex"], "model":"fixture", "commit_mode":"native", "turn_timeout_seconds":60
        })).map_err(|error| error.to_string())?;
        authority.profile_id = ProfileId::parse("fixture-profile")?;
        authority.profile_digest = crate::store::agent_profile_digest(&profile)?;
        let schema_name = match role {
            Role::Coordinator => "coordinator-v1.json",
            Role::Supervisor => "supervisor-v1.json",
            Role::Worker => "worker-v1.json",
            Role::Reviewer => "reviewer-v1.json",
            Role::Postmortem => "postmortem-v1.json",
            _ => {
                return Err(
                    "fixture currently supports Supervisor, Worker, Reviewer, and Postmortem roles"
                        .into(),
                );
            }
        };
        let schema_bytes = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("schemas/agent-results")
                .join(schema_name),
        )
        .map_err(|error| error.to_string())?;
        let schema: serde_json::Value = crate::protocol::parse_unique(&schema_bytes)?;
        authority.result_schema_digest = crate::providers::project_result_schema(&schema)?
            .identity
            .source_schema_digest;
        let qualification = crate::store::agent_results::tests::reviewer_qualification(&authority);
        authority.qualification_receipt_digest = qualification.canonical_digest()?;
        store.store_provider_qualification(owner_generation, &qualification)?;
        let run_id_str = agent_run_id.as_str();
        let role_str = serde_json::to_value(role)
            .map_err(|error| error.to_string())?
            .as_str()
            .unwrap()
            .to_owned();
        let now = 1_i64;
        store.connection.execute(
            "INSERT INTO agent_runs(agent_run_id,project_id,config_source,config_revision,config_digest,role_session_id,logical_owner,finite_turn,launch_operation_id,rex_session_id,rex_window_id,rex_block_id,state,controller_generation) VALUES (?1,?2,?3,?4,?5,?6,'fixture-owner',1,?7,?8,?9,?10,'running',?11)",
            rusqlite::params![run_id_str, project_id.as_str(), config_source, config_revision.0, config_digest, authority.role_session_id, authority.operation_id.as_str(), authority.rex_session_id, authority.rex_window_id, authority.rex_block_id, owner_generation],
        ).map_err(|error| error.to_string())?;
        let view_kind = if role == Role::Supervisor {
            crate::launch::RexViewKind::Supervisor
        } else {
            crate::launch::RexViewKind::Ticket
        };
        let view_kind_name = match view_kind {
            crate::launch::RexViewKind::Supervisor => "supervisor",
            crate::launch::RexViewKind::Ticket => "ticket",
        };
        let view_namespace = (role != Role::Supervisor).then_some(namespace.as_str());
        let view_ticket = (role != Role::Supervisor).then_some(ticket_id.as_str());
        let view_id = crate::launch::RexView::derive_id(
            &project_id,
            view_kind,
            view_namespace,
            view_ticket,
            1,
        )?;
        store.connection.execute(
            "INSERT INTO rex_views(view_id,project_id,view_kind,ticket_namespace,ticket_id,view_epoch,rex_server_identity,rex_session_id,rex_window_id,pinned,lifecycle,created_at_unix,updated_at_unix) VALUES (?1,?2,?3,?4,?5,1,'fixture-rex','fixture-session','fixture-window',0,'active',?6,?6) ON CONFLICT(view_id) DO NOTHING",
            rusqlite::params![view_id.as_str(), project_id.as_str(), view_kind_name, view_namespace, view_ticket, now],
        ).map_err(|error| error.to_string())?;
        if parent_role == Role::Supervisor {
            let supervisor_view_id = crate::launch::RexView::derive_id(
                &project_id,
                crate::launch::RexViewKind::Supervisor,
                None,
                None,
                1,
            )?;
            store.connection.execute(
                "INSERT INTO rex_views(view_id,project_id,view_kind,ticket_namespace,ticket_id,view_epoch,rex_server_identity,rex_session_id,rex_window_id,pinned,lifecycle,created_at_unix,updated_at_unix) VALUES (?1,?2,'supervisor',NULL,NULL,1,'fixture-rex','fixture-supervisor-session','fixture-supervisor-window',0,'active',?3,?3)",
                rusqlite::params![supervisor_view_id.as_str(), project_id.as_str(), now],
            ).map_err(|error| error.to_string())?;
        }
        authority.rex_view_id = view_id;
        authority.descriptor_path =
            root.join(format!("{}-run-step-package-final.json", agent_run_id));
        let package = crate::store::agent_results::tests::reviewer_run_step_package(
            &authority,
            schema.clone(),
        );
        authority.descriptor_digest = package.publish_once(&authority.descriptor_path)?;
        if role != Role::Supervisor {
            let parent_run_id_str = parent_run_id.as_str();
            let mut parent_authority = authority.clone();
            parent_authority.agent_run_id = parent_run_id.clone();
            parent_authority.role = parent_role;
            parent_authority.role_session_id = parent_role_session_id.clone().unwrap_or_default();
            parent_authority.parent_run_id = None;
            parent_authority.parent_role = None;
            if parent_role == Role::Supervisor {
                parent_authority.ticket_run_id = None;
                parent_authority.ticket_revision = None;
                parent_authority.rex_view_id = crate::launch::RexView::derive_id(
                    &project_id,
                    crate::launch::RexViewKind::Supervisor,
                    None,
                    None,
                    1,
                )?;
            }
            parent_authority.operation_id = OperationId::parse("fixture-parent-operation")?;
            parent_authority.rex_block_id = "fixture-parent-block".into();
            parent_authority.descriptor_path = root.join("parent-package.json");
            parent_authority.workspace_path = root.join("parent-workspace");
            parent_authority.control_dir = root.join("parent-control");
            parent_authority.validate()?;
            let parent_authority_json =
                serde_json::to_string(&parent_authority).map_err(|error| error.to_string())?;
            let parent_authority_digest = parent_authority.digest()?;
            let parent_role_json = serde_json::to_value(parent_role)
                .map_err(|error| error.to_string())?
                .as_str()
                .unwrap()
                .to_owned();
            store.connection.execute(
                "INSERT INTO agent_runs(agent_run_id,project_id,config_source,config_revision,config_digest,role_session_id,role,logical_owner,finite_turn,launch_operation_id,state,controller_generation) VALUES (?1,?2,?3,?4,?5,?6,?7,'fixture-owner',1,'fixture-parent-operation','completed',?8)",
                rusqlite::params![parent_run_id_str, project_id.as_str(), config_source, config_revision.0, config_digest, parent_role_session_id, parent_role_json, owner_generation],
            ).map_err(|error| error.to_string())?;
            store.connection.execute(
                "INSERT INTO agent_launch_authority(agent_run_id,project_id,role,role_session_id,ticket_run_id,ticket_revision,config_revision,config_digest,attempt,run_epoch,controller_generation,launch_operation_id,rex_view_id,descriptor_digest,runtime_binary_digest,descriptor_path,environment_snapshot_id,profile_id,profile_digest,instruction_digest,result_schema_digest,qualification_receipt_digest,rex_server_identity,rex_session_id,rex_window_id,rex_block_id,workspace_path,control_dir,mailbox_capability_digest,authority_json,authority_digest,created_at_unix) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25,?26,?27,?28,?29,?30,?31,?32)",
            rusqlite::params![parent_authority.agent_run_id.as_str(), parent_authority.project_id.as_str(), parent_role_json, parent_authority.role_session_id, parent_authority.ticket_run_id.as_ref().map(TicketRunId::as_str), parent_authority.ticket_revision.map(|revision| revision.0), parent_authority.config_revision.0, parent_authority.config_digest.as_str(), parent_authority.attempt, parent_authority.run_epoch, parent_authority.controller_generation, parent_authority.operation_id.as_str(), parent_authority.rex_view_id.as_str(), parent_authority.descriptor_digest.as_str(), parent_authority.runtime_binary_digest.as_str(), parent_authority.descriptor_path.display().to_string(), parent_authority.environment_snapshot_id.as_str(), parent_authority.profile_id.as_str(), parent_authority.profile_digest.as_str(), parent_authority.instruction_digest.as_str(), parent_authority.result_schema_digest.as_str(), parent_authority.qualification_receipt_digest.as_str(), parent_authority.rex_server_identity, parent_authority.rex_session_id, parent_authority.rex_window_id, parent_authority.rex_block_id, parent_authority.workspace_path.display().to_string(), parent_authority.control_dir.display().to_string(), parent_authority.mailbox_capability_digest.as_str(), parent_authority_json, parent_authority_digest.as_str(), now],
        ).map_err(|error| error.to_string())?;
        }
        store.connection.execute(
            "INSERT INTO agent_launch_authority(agent_run_id,project_id,role,role_session_id,parent_run_id,parent_role,ticket_run_id,ticket_revision,config_revision,config_digest,attempt,run_epoch,controller_generation,launch_operation_id,rex_view_id,descriptor_digest,runtime_binary_digest,descriptor_path,environment_snapshot_id,profile_id,profile_digest,instruction_digest,result_schema_digest,qualification_receipt_digest,rex_server_identity,rex_session_id,rex_window_id,rex_block_id,workspace_path,control_dir,mailbox_capability_digest,authority_json,authority_digest,created_at_unix) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25,?26,?27,?28,?29,?30,?31,?32,?33,?34)",
            rusqlite::params![run_id_str, project_id.as_str(), role_str, authority.role_session_id, authority.parent_run_id.as_ref().map(AgentRunId::as_str), authority.parent_role.map(|role| serde_json::to_value(role).unwrap().as_str().unwrap().to_owned()), authority.ticket_run_id.as_ref().map(TicketRunId::as_str), authority.ticket_revision.map(|revision| revision.0), authority.config_revision.0, authority.config_digest.as_str(), authority.attempt, authority.run_epoch, owner_generation, authority.operation_id.as_str(), authority.rex_view_id.as_str(), authority.descriptor_digest.as_str(), authority.runtime_binary_digest.as_str(), authority.descriptor_path.display().to_string(), authority.environment_snapshot_id.as_str(), authority.profile_id.as_str(), authority.profile_digest.as_str(), authority.instruction_digest.as_str(), authority.result_schema_digest.as_str(), authority.qualification_receipt_digest.as_str(), authority.rex_server_identity, authority.rex_session_id, authority.rex_window_id, authority.rex_block_id, authority.workspace_path.display().to_string(), authority.control_dir.display().to_string(), authority.mailbox_capability_digest.as_str(), serde_json::to_string(&authority).map_err(|error| error.to_string())?, authority.digest()?.as_str(), now],
        ).map_err(|error| error.to_string())?;
        let project_epoch: u64 = store
            .connection
            .query_row(
                "SELECT project_epoch FROM project_runtimes WHERE project_id=?1",
                [project_id.as_str()],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        let slot_index: u32 = store
            .connection
            .query_row(
                "SELECT COALESCE(MAX(slot_index) + 1, 0) FROM execution_slots WHERE pool='agent'",
                [],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        store.connection.execute(
            "INSERT INTO execution_slots(pool,slot_index,project_id,ticket_run_id,owner_kind,owner_id,reservation_epoch,controller_generation,process_identity_json,disposition) VALUES ('agent',?1,?2,?3,'agent_run',?4,?5,?6,NULL,'live')",
            rusqlite::params![slot_index, project_id.as_str(), ticket_run_id.as_ref().map(TicketRunId::as_str), run_id_str, project_epoch, owner_generation],
        ).map_err(|error| error.to_string())?;
        let child = Command::new("/bin/sleep")
            .arg("0.2")
            .spawn()
            .map_err(|error| error.to_string())?;
        let pid = child.id();
        let process_identity = (0..100)
            .find_map(|_| {
                crate::process::inspect_process_table()
                    .ok()?
                    .into_iter()
                    .find(|item| item.pid == pid)
            })
            .ok_or("test subprocess was not observed in the host process table")?;
        let status = child
            .wait_with_output()
            .map_err(|error| error.to_string())?
            .status;
        if !status.success() {
            return Err("fixture subprocess did not exit successfully".into());
        }
        let process = ObservedProcess {
            pid,
            parent_pid: process_identity.parent_pid,
            process_group_id: process_identity.process_group_id,
            start_identity: process_identity.start_identity.clone(),
            command: process_identity.command.clone(),
            identity_quality: match process_identity.quality {
                crate::process::ProcessIdentityQuality::KernelBirthToken => "kernel_birth_token",
                _ => "second_precision",
            }
            .into(),
        };
        let observed = ObservedProviderStart {
            agent_run_id: agent_run_id.clone(),
            operation_id: authority.operation_id.clone(),
            provider_pid: pid,
            provider_start_identity: process_identity.start_identity,
            executable_digest: qualification.executable_digest.clone(),
            process_tree_digest: digest(b"observed process tree")?,
            process_tree_confirmed: true,
            process_tree: Vec::new(),
        };
        store.connection.execute(
            "INSERT INTO agent_launch_state(agent_run_id,state,start_request_id,start_request_digest,provider_process_tree_json,last_observed_at_unix,updated_at_unix) VALUES (?1,'running',?2,?3,?4,?5,?5)",
            rusqlite::params![run_id_str, authority.operation_id.as_str(), "f".repeat(64), serde_json::to_string(&observed).map_err(|error| error.to_string())?, now],
        ).map_err(|error| error.to_string())?;
        let request = crate::launch::AgentStartRequest {
            schema_version: 1,
            operation_id: authority.operation_id.clone(),
            agent_run_id: agent_run_id.clone(),
            project_id: project_id.clone(),
            controller_generation: owner_generation,
            descriptor_digest: authority.descriptor_digest.clone(),
            runtime_binary_digest: authority.runtime_binary_digest.clone(),
            environment_snapshot_id: authority.environment_snapshot_id.clone(),
            qualification_receipt_digest: authority.qualification_receipt_digest.clone(),
            wrapper_pid: std::process::id(),
            wrapper_start_identity: "fixture-wrapper".into(),
            rex_session_id: authority.rex_session_id.clone(),
            rex_block_id: authority.rex_block_id.clone(),
        };
        let start = StartRequestEnvelope {
            schema_version: 1,
            request_digest: format!(
                "{:x}",
                Sha256::digest(serde_json::to_vec(&request).map_err(|error| error.to_string())?)
            ),
            request,
        };
        let start_json =
            serde_json::to_string(&start.request).map_err(|error| error.to_string())?;
        let actual_start_digest = format!("{:x}", Sha256::digest(start_json.as_bytes()));
        store
            .connection
            .execute(
                "DELETE FROM agent_launch_state WHERE agent_run_id=?1",
                [run_id_str],
            )
            .map_err(|error| error.to_string())?;
        store.connection.execute(
            "INSERT INTO agent_launch_state(agent_run_id,state,start_request_id,start_request_digest,provider_process_tree_json,last_observed_at_unix,updated_at_unix) VALUES (?1,'running',?2,?3,?4,?5,?5)",
            rusqlite::params![run_id_str, authority.operation_id.as_str(), actual_start_digest, serde_json::to_string(&observed).map_err(|error| error.to_string())?, now],
        ).map_err(|error| error.to_string())?;
        let artifacts = crate::artifacts::ArtifactStore::open(&root.join("artifacts"))?;
        if role == Role::Postmortem {
            let source_path = "postmortem/source.md";
            let source_file = authority.workspace_path.join(source_path);
            std::fs::create_dir_all(
                source_file
                    .parent()
                    .ok_or("Postmortem source path has no parent")?,
            )
            .map_err(|error| error.to_string())?;
            std::fs::write(
                &source_file,
                b"# Fixture source\n\nHost-registered Postmortem evidence.\n",
            )
            .map_err(|error| error.to_string())?;
            let artifact = artifacts.register(
                &authority.workspace_path,
                &authority.project_id,
                authority.agent_run_id.as_str(),
                role,
                source_path,
                crate::engine::orchestration::RoleArtifactKind::Postmortem,
                1,
            )?;
            message.artifact_refs = vec![artifact.reference.clone()];
            message.structured_result["source_references"] =
                serde_json::json!([artifact.reference]);
            let request_digest = digest(b"fixture ArtifactAdd request")?;
            crate::store::artifact_registry::persist_registration(
                &mut store.connection,
                owner_generation,
                &authority,
                "fixture-postmortem-artifact",
                &request_digest,
                &artifact.reference,
                &artifact.object_path,
            )?;
            message.result_digest = Some(digest(
                &serde_json::to_vec(&message.structured_result)
                    .map_err(|error| error.to_string())?,
            )?);
        }
        let structured = serde_json::to_value(&message).map_err(|error| error.to_string())?;
        let structured_digest =
            digest(&serde_json::to_vec(&structured).map_err(|error| error.to_string())?)?;
        let projection = crate::providers::project_result_schema(&schema)?.identity;
        let receipt = RunReceipt {
            run_id: agent_run_id.clone(),
            attempt: authority.attempt,
            provider: AgentAdapter::Codex,
            effective_permission_mode: "workspace_write".into(),
            conversation_id: None,
            provider_version: Some("fixture-1".into()),
            provider_process_failure: None,
            provider_result_failure: None,
            capability_receipt_digest: Some(authority.qualification_receipt_digest.clone()),
            schema_projection: projection,
            launch_pid_hint: Some(pid),
            exit_code: Some(0),
            timed_out: false,
            cancellation_signal: None,
            cleanup: CleanupState::Confirmed,
            cleanup_detail: None,
            processes: vec![process],
            result_digest: Some(structured_digest),
            outcome: TurnOutcome::Completed,
        };
        #[derive(serde::Serialize)]
        struct Payload<'a> {
            schema_version: u32,
            start_request_digest: &'a str,
            receipt: &'a RunReceipt,
            structured_result: &'a Option<serde_json::Value>,
        }
        let payload = Payload {
            schema_version: 1,
            start_request_digest: &start.request_digest,
            receipt: &receipt,
            structured_result: &Some(structured.clone()),
        };
        let result_digest = format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&payload).map_err(|error| error.to_string())?)
        );
        let result = AgentTurnResult {
            schema_version: 1,
            start_request_digest: start.request_digest.clone(),
            receipt,
            structured_result: Some(structured),
            result_digest,
        };
        let terminal = store.record_verified_agent_terminal(owner_generation, &start, &result)?;
        let artifacts = crate::artifacts::ArtifactStore::open(&root.join("artifacts"))?;
        Ok(InPlaceTerminalFixture {
            artifacts,
            terminal,
            message,
        })
    }

    pub(crate) fn result_ack(
        store: &ConfigStore,
        evidence_id: &str,
    ) -> Result<Option<(u64, String)>, String> {
        store.connection
            .query_row(
                "SELECT reducer_revision,disposition FROM agent_result_reducer_ack WHERE evidence_id=?1",
                [evidence_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())
    }
}
#[allow(clippy::items_after_test_module)]
impl ConfigStore {
    /// Persist a typed Coordinator child wake and acknowledge its source evidence atomically.
    pub fn persist_coordinator_child_wake(
        &mut self,
        owner_generation: u64,
        result: &IngestedAgentResult,
        child_role: Role,
        role_session_id: &str,
        source_revision: u64,
        payload: &serde_json::Value,
    ) -> Result<(), String> {
        let binding = &result.validated.binding;
        if binding.role != Role::Coordinator
            || result.validated.kind != crate::engine::orchestration::RoleOutputKind::SpawnRequest
            || result.validated.assertion != crate::engine::orchestration::AgentAssertion::Succeeded
            || matches!(
                child_role,
                Role::Worker | Role::Coordinator | Role::Supervisor
            )
            || !matches!(&result.validated.typed_payload, crate::engine::orchestration::RoleResultPayload::SpawnRequest(request) if request.role == child_role)
        {
            return Err("Coordinator child wake requires a succeeded SpawnRequest for a generic ticket role".into());
        }
        let ticket_run_id = binding
            .ticket_run_id
            .as_ref()
            .ok_or("Coordinator child wake requires TicketRun scope")?;
        let evidence_id = result.receipt.evidence_id();
        let payload_json = crate::store::canonical_json(payload)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        super::validate_active_generation(&tx, owner_generation)?;
        let evidence: Option<(String, String, String, String, Option<String>, u64)> = tx
            .query_row(
                "SELECT agent_run_id,project_id,role,outcome,ticket_run_id,run_epoch FROM agent_result_evidence WHERE evidence_id=?1",
                [evidence_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let Some((run_id, project_id, role, outcome, evidence_ticket, evidence_epoch)) = evidence
        else {
            return Err("Coordinator child wake source evidence is missing".into());
        };
        if run_id != binding.agent_run_id.as_str()
            || project_id != binding.project_id.as_str()
            || role != "coordinator"
            || outcome != "completed"
            || evidence_ticket.as_deref() != Some(ticket_run_id.as_str())
            || evidence_epoch != binding.run_epoch
            || result.validated.assertion != crate::engine::orchestration::AgentAssertion::Succeeded
        {
            return Err(
                "Coordinator child wake source is not a succeeded Coordinator result".into(),
            );
        }
        let source_authority_json: String = tx
            .query_row(
                "SELECT authority_json FROM agent_launch_authority WHERE agent_run_id=?1",
                [binding.agent_run_id.as_str()],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        let source_authority: AgentLaunchAuthority =
            crate::protocol::parse_unique(source_authority_json.as_bytes())?;
        if binding_for(&source_authority)? != *binding {
            return Err(
                "Coordinator child source binding differs from registered launch authority".into(),
            );
        }
        let run: Option<(u64, String, u64, String)> = tx
            .query_row(
                "SELECT revision,internal_phase,config_revision,config_digest FROM ticket_runs WHERE ticket_run_id=?1 AND project_id=?2",
                rusqlite::params![ticket_run_id.as_str(), binding.project_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let project_config: Option<(u64, String)> = tx
            .query_row(
                "SELECT config_revision,config_digest FROM projects WHERE project_id=?1",
                [binding.project_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if run.is_none_or(|(revision, _, config_revision, config_digest)| {
            revision != source_revision
                || config_revision != binding.config_revision.0
                || config_digest != binding.config_digest.as_str()
        }) || project_config
            != Some((
                binding.config_revision.0,
                binding.config_digest.as_str().to_owned(),
            ))
            || binding.ticket_revision.map(|revision| revision.0) != Some(source_revision)
            || child_role == Role::Worker
            || child_role == Role::Supervisor
            || child_role == Role::Coordinator
            || role_session_id != format!("ticket_run:{ticket_run_id}:{}", role_name(child_role))
        {
            return Err("Coordinator child wake source is stale or has an invalid session".into());
        }
        let prior_source: Option<(String, String)> = tx
            .query_row(
                "SELECT role_session_id,source_id FROM role_wake_inputs WHERE source_type='coordinator_child' AND source_id=?1 ORDER BY wake_input_id LIMIT 1",
                [evidence_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if prior_source
            .as_ref()
            .is_some_and(|(session, source)| session != role_session_id || source != evidence_id)
        {
            return Err(
                "Coordinator evidence already targets a different child role session".into(),
            );
        }
        let session_source: Option<String> = tx
            .query_row(
                "SELECT source_id FROM role_wake_inputs WHERE role_session_id=?1 AND source_type='coordinator_child' ORDER BY wake_input_id LIMIT 1",
                [role_session_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if session_source
            .as_deref()
            .is_some_and(|source| source != evidence_id)
        {
            return Err(
                "canonical child role session already has a different Coordinator parent".into(),
            );
        }
        let existing: Option<String> = tx
            .query_row(
                "SELECT payload_json FROM role_wake_inputs WHERE role_session_id=?1 AND source_type='coordinator_child' AND source_id=?2 AND source_revision=?3",
                rusqlite::params![role_session_id, evidence_id, source_revision],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if existing
            .as_ref()
            .is_some_and(|stored| stored != &payload_json)
        {
            return Err("Coordinator source evidence already has a different child wake".into());
        }
        if existing.is_none() {
            tx.execute(
                "INSERT INTO role_wake_inputs(project_id,role_session_id,source_type,source_id,source_revision,priority,payload_json,lifecycle,created_at_unix) VALUES (?1,?2,'coordinator_child',?3,?4,10,?5,'pending',?6)",
                rusqlite::params![binding.project_id.as_str(), role_session_id, evidence_id, source_revision, payload_json, super::now_unix()?],
            )
            .map_err(|error| error.to_string())?;
        }
        let prior_ack: Option<(u64, String)> = tx
            .query_row(
                "SELECT reducer_revision,disposition FROM agent_result_reducer_ack WHERE evidence_id=?1",
                [evidence_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if prior_ack.as_ref().is_some_and(|(revision, disposition)| {
            *revision != source_revision || disposition != "applied"
        }) {
            return Err("Coordinator source evidence was acknowledged differently".into());
        }
        if prior_ack.is_none() {
            tx.execute(
                "INSERT INTO agent_result_reducer_ack(evidence_id,reducer_revision,disposition,acknowledged_at_unix) VALUES (?1,?2,'applied',?3)",
                rusqlite::params![evidence_id, source_revision, super::now_unix()?],
            )
            .map_err(|error| error.to_string())?;
        }
        tx.commit().map_err(|error| error.to_string())
    }

    /// Resolve a child wake's parent from immutable host-validated result evidence.
    pub fn coordinator_child_parent(
        &self,
        project_id: &crate::domain::ids::ProjectId,
        role_session_id: &str,
    ) -> Result<crate::launch::AgentLaunchAuthority, String> {
        let evidence_id: String = self
            .connection
            .query_row(
                "SELECT w.source_id FROM role_wake_inputs w JOIN agent_result_evidence e ON e.evidence_id=w.source_id WHERE w.project_id=?1 AND w.role_session_id=?2 AND w.source_type='coordinator_child' ORDER BY w.wake_input_id LIMIT 1",
                rusqlite::params![project_id.as_str(), role_session_id],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        let parent_run: String = self
            .connection
            .query_row(
                "SELECT agent_run_id FROM agent_result_evidence WHERE evidence_id=?1 AND project_id=?2 AND role='coordinator' AND outcome='completed'",
                rusqlite::params![evidence_id, project_id.as_str()],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        let authority = self
            .agent_launch_authority(&crate::domain::ids::AgentRunId::parse(parent_run)?)?
            .ok_or("Coordinator child source has no host launch authority")?;
        if authority.role != crate::domain::types::Role::Coordinator
            || authority.project_id != *project_id
        {
            return Err("Coordinator child source authority has the wrong role or Project".into());
        }
        Ok(authority)
    }

    /// Resolve a TicketRun Coordinator's Supervisor from its immutable dispatch source.
    pub fn supervisor_parent_for_ticket_run(
        &self,
        project_id: &crate::domain::ids::ProjectId,
        ticket_run_id: &crate::domain::ids::TicketRunId,
    ) -> Result<crate::launch::AgentLaunchAuthority, String> {
        let payload: String = self
            .connection
            .query_row(
                "SELECT payload_json FROM role_wake_inputs WHERE project_id=?1 AND role_session_id=?2 AND source_type='ticket_run_dispatch' AND source_id=?3 ORDER BY wake_input_id LIMIT 1",
                rusqlite::params![project_id.as_str(), format!("ticket_run:{ticket_run_id}:coordinator"), ticket_run_id.as_str()],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        let payload: serde_json::Value = crate::protocol::parse_unique(payload.as_bytes())?;
        let evidence_id = payload
            .get("supervisor_evidence_id")
            .and_then(serde_json::Value::as_str)
            .ok_or("TicketRun dispatch has no Supervisor source evidence")?;
        let ticket: (String, Option<String>) = self
            .connection
            .query_row(
                "SELECT ticket_id,external_revision FROM ticket_runs WHERE ticket_run_id=?1 AND project_id=?2",
                rusqlite::params![ticket_run_id.as_str(), project_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|error| error.to_string())?;
        let (run_id, result_json): (String, String) = self
            .connection
            .query_row(
                "SELECT agent_run_id,result_json FROM agent_result_evidence WHERE evidence_id=?1 AND project_id=?2 AND role='supervisor' AND ticket_run_id IS NULL AND outcome='completed'",
                rusqlite::params![evidence_id, project_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|error| error.to_string())?;
        let submission: crate::engine::orchestration::RoleResultSubmission =
            crate::protocol::parse_unique(result_json.as_bytes())?;
        if submission.kind != crate::engine::orchestration::RoleOutputKind::DispatchRequest
            || submission.assertion != crate::engine::orchestration::AgentAssertion::Succeeded
        {
            return Err(
                "TicketRun dispatch source is not a succeeded Supervisor DispatchRequest".into(),
            );
        }
        let authority = self
            .agent_launch_authority(&crate::domain::ids::AgentRunId::parse(run_id)?)?
            .ok_or("TicketRun dispatch Supervisor has no host launch authority")?;
        if binding_for(&authority)? != submission.binding {
            return Err(
                "TicketRun dispatch source differs from Supervisor launch authority".into(),
            );
        }
        let crate::engine::orchestration::RoleResultPayload::DispatchRequest(request) =
            crate::engine::orchestration::RoleResultPayload::parse(
                submission.kind,
                submission.structured_result,
            )?
        else {
            return Err("Supervisor dispatch evidence has a different typed payload".into());
        };
        let expected_revision = request.expected_ticket_revision.as_str();
        if request.ticket_reference.as_str() != ticket.0
            || ticket.1.as_deref() != Some(expected_revision)
        {
            return Err(
                "TicketRun dispatch does not match its Supervisor's exact ticket observation"
                    .into(),
            );
        }
        if authority.role != Role::Supervisor
            || authority.project_id != *project_id
            || authority.ticket_run_id.is_some()
        {
            return Err("TicketRun dispatch source authority is not a Project Supervisor".into());
        }
        Ok(authority)
    }
}
