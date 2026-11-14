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

use crate::domain::ids::{
    AgentRunId, Digest, ProjectId, Revision, TicketId, TicketNamespace, TicketRevision, TicketRunId,
};
use crate::domain::types::Role;
use crate::engine::orchestration::{
    RoleResultBinding, RoleResultSubmission, ValidatedRoleResult, WakeSessionKey,
};
use crate::launch::{AgentLaunchAuthority, ProviderQualification};
use crate::process::{ProcessIdentity, ProcessIdentityQuality};
use crate::roles::RoleResultMessage;
use crate::run_step::{CancellationCause, CleanupState, TurnOutcome};
use crate::run_step_spool::{
    AgentTurnResult, BlockLossCleanupSnapshot, RunFamilyCoverage, RunFamilyRecord,
    StartRequestEnvelope,
};
use crate::store::ConfigStore;
use crate::store::agent_recovery::RecoverableAgentRun;

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
type CancelledCleanupLaunchStateRow = (String, Option<String>, Option<String>, Option<String>);

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

/// Host-only proof that an exact cancelled provider run and its Rex wrapper are absent.
/// It authorizes lifecycle reconciliation only; it is not a successful Agent terminal.
pub(crate) struct VerifiedAgentCleanup {
    agent_run_id: AgentRunId,
    owner_generation: u64,
    reservation_epoch: u64,
    authority_digest: Digest,
    start_request_digest: Digest,
    result_digest: Digest,
    family_digest: Digest,
    snapshot_digest: Digest,
    absence_digest: Digest,
    proof_digest: Digest,
    observed_at_unix: i64,
}

#[cfg(test)]
pub(crate) fn test_verified_agent_cleanup(
    run: &RecoverableAgentRun,
    owner_generation: u64,
    snapshot: &BlockLossCleanupSnapshot,
) -> VerifiedAgentCleanup {
    let start_request_digest = Digest::parse("a".repeat(64)).unwrap();
    let result_digest = Digest::parse("b".repeat(64)).unwrap();
    let family_digest = Digest::parse("c".repeat(64)).unwrap();
    let snapshot_digest = digest(&serde_json::to_vec(snapshot).unwrap()).unwrap();
    let absence_digest = Digest::parse("d".repeat(64)).unwrap();
    let observed_at_unix = 10;
    let proof_digest = digest(
        &serde_json::to_vec(&(
            "rex-projects-cancelled-agent-cleanup-v1",
            &run.agent_run_id,
            owner_generation,
            run.reservation_epoch,
            &run.authority_digest,
            &start_request_digest,
            &result_digest,
            &family_digest,
            &snapshot_digest,
            &absence_digest,
            observed_at_unix,
        ))
        .unwrap(),
    )
    .unwrap();
    VerifiedAgentCleanup {
        agent_run_id: run.agent_run_id.clone(),
        owner_generation,
        reservation_epoch: run.reservation_epoch,
        authority_digest: run.authority_digest.clone(),
        start_request_digest,
        result_digest,
        family_digest,
        snapshot_digest,
        absence_digest,
        proof_digest,
        observed_at_unix,
    }
}

impl VerifiedAgentCleanup {
    pub(crate) fn verify_reconciliation_binding(
        &self,
        run: &RecoverableAgentRun,
        owner_generation: u64,
        snapshot: &BlockLossCleanupSnapshot,
    ) -> Result<(), String> {
        let snapshot_bytes = serde_json::to_vec(snapshot).map_err(|error| error.to_string())?;
        if self.agent_run_id != run.agent_run_id
            || self.owner_generation != owner_generation
            || owner_generation != run.current_generation
            || self.reservation_epoch != run.reservation_epoch
            || self.authority_digest != run.authority_digest
            || self.start_request_digest.as_str().is_empty()
            || self.result_digest.as_str().is_empty()
            || self.family_digest.as_str().is_empty()
            || self.snapshot_digest != digest(&snapshot_bytes)?
            || snapshot.cleanup_covered
            || self.observed_at_unix < snapshot.observed_at_unix
        {
            return Err(
                "cancelled Agent cleanup proof does not match the current recovery snapshot".into(),
            );
        }
        let expected = digest(
            &serde_json::to_vec(&(
                "rex-projects-cancelled-agent-cleanup-v1",
                &self.agent_run_id,
                self.owner_generation,
                self.reservation_epoch,
                &self.authority_digest,
                &self.start_request_digest,
                &self.result_digest,
                &self.family_digest,
                &self.snapshot_digest,
                &self.absence_digest,
                self.observed_at_unix,
            ))
            .map_err(|error| error.to_string())?,
        )?;
        if self.proof_digest != expected {
            return Err("cancelled Agent cleanup proof digest is invalid".into());
        }
        Ok(())
    }

    pub(crate) fn proof_digest(&self) -> &Digest {
        &self.proof_digest
    }

    pub(crate) fn result_digest(&self) -> &Digest {
        &self.result_digest
    }

    pub(crate) fn family_digest(&self) -> &Digest {
        &self.family_digest
    }

    pub(crate) fn absence_digest(&self) -> &Digest {
        &self.absence_digest
    }

    pub(crate) fn snapshot_digest(&self) -> &Digest {
        &self.snapshot_digest
    }

    pub(crate) fn start_request_digest(&self) -> &Digest {
        &self.start_request_digest
    }

    pub(crate) fn observed_at_unix(&self) -> i64 {
        self.observed_at_unix
    }
}

impl VerifiedAgentTerminal {
    pub fn agent_run_id(&self) -> &AgentRunId {
        &self.agent_run_id
    }

    pub(crate) fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub(crate) fn controller_generation(&self) -> u64 {
        self.controller_generation
    }

    pub(crate) fn authority_digest(&self) -> &Digest {
        &self.authority_digest
    }

    pub fn terminal_digest(&self) -> &Digest {
        &self.terminal_digest
    }

    pub fn absence_digest(&self) -> &Digest {
        &self.absence_digest
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MergeClaimRejectionOutcome {
    CoordinatorCorrectionQueued,
    SupervisorEscalationQueued,
    AlreadyRecorded,
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

/// Verify a cancellation-only cleanup receipt for a missing Rex block. The receipt proves no
/// role result and never creates or reuses `VerifiedAgentTerminal`.
pub(crate) fn verify_cancelled_agent_cleanup(
    store: &ConfigStore,
    owner_generation: u64,
    run: &RecoverableAgentRun,
    start: &StartRequestEnvelope,
    result: &AgentTurnResult,
    family: &RunFamilyRecord,
    snapshot: &BlockLossCleanupSnapshot,
) -> Result<VerifiedAgentCleanup, String> {
    start.validate()?;
    result.validate_for(start)?;
    family.validate()?;
    snapshot.validate()?;

    let authority = store
        .agent_launch_authority(&run.agent_run_id)?
        .ok_or("cancelled cleanup has no persisted launch authority")?;
    let authority_digest = authority.digest()?;
    if authority != run.authority
        || authority_digest != run.authority_digest
        || authority.agent_run_id != run.agent_run_id
        || run.current_generation != owner_generation
    {
        return Err(
            "cancelled cleanup does not match the current immutable launch authority".into(),
        );
    }
    validate_request_authority(&authority, start)?;
    verify_accepted_start_receipt(store, start)?;
    let active_generation: Option<u64> = store
        .connection
        .query_row(
            "SELECT generation FROM controller_owners WHERE singleton=1 AND stopped_at_unix IS NULL",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    if active_generation != Some(owner_generation) {
        return Err("cancelled cleanup requires the active controller generation".into());
    }

    let qualification = load_qualification(&store.connection, &authority)?;
    validate_cancelled_result_for_start(&authority, start, result, &qualification)?;
    validate_descriptor_and_projection(&authority, result, &qualification)?;

    let expected_binding = crate::run_step_spool::RunFamilyBinding {
        schema_version: 1,
        agent_run_id: run.agent_run_id.clone(),
        reservation_epoch: run.reservation_epoch,
        authority_digest: run.authority_digest.clone(),
        descriptor_digest: authority.descriptor_digest.clone(),
        wrapper_pid: start.request.wrapper_pid,
        wrapper_start_identity: start.request.wrapper_start_identity.clone(),
        rex_launch_anchor: start.request.rex_launch_anchor.clone(),
    };
    let wrapper: crate::launch::ObservedWrapperIdentity = crate::protocol::parse_unique(
        run.wrapper_identity_json
            .as_deref()
            .ok_or("cancelled cleanup has no saved wrapper identity")?
            .as_bytes(),
    )?;
    wrapper.matches_start_request(&start.request)?;
    if family.binding != expected_binding
        || family.coverage != RunFamilyCoverage::Complete
        || family.provider_executable_path != qualification.executable_path
        || family.provider_executable_digest != qualification.executable_digest
        || family.wrapper_process.pid != wrapper.pid
        || family.wrapper_process.start_identity != wrapper.start_identity
        || family.wrapper_process.quality != ProcessIdentityQuality::KernelBirthToken
        || start
            .request
            .rex_launch_anchor
            .as_ref()
            .is_some_and(|anchor| family.wrapper_process.parent_pid != anchor.pid)
        || family.provider_root.parent_pid != wrapper.pid
        || family.provider_root.quality != ProcessIdentityQuality::KernelBirthToken
    {
        return Err("cancelled cleanup family does not match the exact accepted launch".into());
    }

    let launch_state: Option<CancelledCleanupLaunchStateRow> = store
        .connection
        .query_row(
            "SELECT state,start_request_digest,provider_process_tree_json,wrapper_process_identity_json FROM agent_launch_state WHERE agent_run_id=?1",
            [run.agent_run_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    let Some((state, start_digest, provider_tree_json, wrapper_json)) = launch_state else {
        return Err("cancelled cleanup has no persisted launch state".into());
    };
    if !matches!(state.as_str(), "running" | "unknown")
        || start_digest.as_deref() != Some(start.request_digest.as_str())
        || run.wrapper_identity_json.as_deref() != wrapper_json.as_deref()
        || start.request.wrapper_pid != wrapper.pid
        || start.request.wrapper_start_identity != wrapper.start_identity
        || start.request.rex_session_id != wrapper.rex_session_id
        || start.request.rex_block_id != wrapper.rex_block_id
    {
        return Err("cancelled cleanup start request is no longer active".into());
    }
    let provider_tree_json = provider_tree_json
        .ok_or("cancelled cleanup has no persisted provider-start observation")?;
    let provider: crate::launch::ObservedProviderStart =
        crate::protocol::parse_unique(provider_tree_json.as_bytes())?;
    provider.validate_complete_process_tree(&qualification)?;
    verify_provider_start_observation(
        &authority,
        &Some(provider_tree_json),
        result,
        &qualification,
    )?;
    if provider.provider_pid != family.provider_root.pid
        || provider.provider_start_identity != family.provider_root.start_identity
        || !family
            .process_tree
            .iter()
            .any(|process| same_process_identity(process, &family.provider_root))
        || !provider
            .process_tree
            .iter()
            .any(|process| same_provider_identity(&family.provider_root, process))
    {
        return Err(
            "cancelled cleanup family does not preserve the host-observed provider tree".into(),
        );
    }

    let cumulative_tree = cumulative_provider_family_tree(
        &provider.process_tree,
        &family.process_tree,
        &family.wrapper_process,
    )
    .ok_or("cancelled cleanup process observations have conflicting identities")?;
    if snapshot.cleanup_covered
        || snapshot.agent_run_id != run.agent_run_id
        || snapshot.reservation_epoch != run.reservation_epoch
        || snapshot.authority_digest != run.authority_digest
        || snapshot.launch_tree_digest != provider.process_tree_digest
        || !same_identity_sets(&result.receipt.processes, &family.process_tree)
        || !same_process_identity_sets(&snapshot.process_tree, &cumulative_tree)
    {
        return Err(
            "cancelled cleanup result, family, and cumulative snapshot identities differ".into(),
        );
    }

    let exact_identities = cumulative_tree
        .iter()
        .map(|process| crate::run_step::ObservedProcess {
            pid: process.pid,
            parent_pid: process.parent_pid,
            process_group_id: process.process_group_id,
            start_identity: process.start_identity.clone(),
            command: String::new(),
            identity_quality: match process.quality {
                ProcessIdentityQuality::KernelBirthToken => "kernel_birth_token",
                ProcessIdentityQuality::SecondPrecision => "second_precision",
            }
            .into(),
        })
        .collect::<Vec<_>>();
    let absence_digest = verify_process_tree_absent(&exact_identities)?;
    let family_digest = digest(&serde_json::to_vec(family).map_err(|error| error.to_string())?)?;
    let snapshot_digest =
        digest(&serde_json::to_vec(snapshot).map_err(|error| error.to_string())?)?;
    let result_digest = digest(&serde_json::to_vec(result).map_err(|error| error.to_string())?)?;
    let observed_at_unix = unix_now()?;
    let proof_digest = digest(
        &serde_json::to_vec(&(
            "rex-projects-cancelled-agent-cleanup-v1",
            &run.agent_run_id,
            owner_generation,
            run.reservation_epoch,
            &run.authority_digest,
            &Digest::parse(start.request_digest.clone())?,
            &result_digest,
            &family_digest,
            &snapshot_digest,
            &absence_digest,
            observed_at_unix,
        ))
        .map_err(|error| error.to_string())?,
    )?;
    Ok(VerifiedAgentCleanup {
        agent_run_id: run.agent_run_id.clone(),
        owner_generation,
        reservation_epoch: run.reservation_epoch,
        authority_digest: run.authority_digest.clone(),
        start_request_digest: Digest::parse(start.request_digest.clone())?,
        result_digest,
        family_digest,
        snapshot_digest,
        absence_digest,
        proof_digest,
        observed_at_unix,
    })
}

fn verify_accepted_start_receipt(
    store: &ConfigStore,
    start: &StartRequestEnvelope,
) -> Result<(), String> {
    if store
        .persisted_start_receipt(&start.request)?
        .is_none_or(|receipt| receipt.decision != crate::launch::LaunchDecision::Accepted)
    {
        return Err("cancelled cleanup has no persisted accepted start receipt".into());
    }
    Ok(())
}

fn validate_cancelled_result_for_start(
    authority: &AgentLaunchAuthority,
    start: &StartRequestEnvelope,
    result: &AgentTurnResult,
    qualification: &ProviderQualification,
) -> Result<(), String> {
    let receipt = &result.receipt;
    let signal_cancellation = receipt.cancellation_signal.is_some_and(|signal| signal > 0)
        && receipt.cancellation_cause.is_none();
    let anchor_cancellation = matches!(
        (&receipt.cancellation_cause, start.request.rex_launch_anchor.as_ref()),
        (
            Some(CancellationCause::RexLaunchAnchorClosed {
                pid,
                start_identity,
            }),
            Some(anchor),
        ) if *pid == anchor.pid && start_identity == &anchor.start_identity
    ) && receipt.cancellation_signal.is_none();
    if receipt.run_id != authority.agent_run_id
        || receipt.attempt != authority.attempt
        || receipt.provider != qualification.adapter
        || receipt.capability_receipt_digest.as_ref()
            != Some(&authority.qualification_receipt_digest)
        || !matches!(receipt.outcome, TurnOutcome::Cancelled)
        || !matches!(receipt.cleanup, CleanupState::Confirmed)
        || receipt.timed_out
        || !(signal_cancellation || anchor_cancellation)
        || (receipt.exit_code.is_some() && !anchor_cancellation)
        || receipt.result_digest.is_some()
        || result.structured_result.is_some()
    {
        return Err("provider run receipt is not an exact cleanup-confirmed cancellation".into());
    }
    if result.start_request_digest != start.request_digest {
        return Err("cancelled provider result does not match its start request".into());
    }
    Ok(())
}

fn same_provider_identity(
    family: &ProcessIdentity,
    provider: &crate::launch::ProviderProcessIdentity,
) -> bool {
    family.pid == provider.pid
        && family.parent_pid == provider.parent_pid
        && family.process_group_id == provider.process_group_id
        && family.start_identity == provider.start_identity
        && family.quality == provider.identity_quality
}

fn same_process_identity(left: &ProcessIdentity, right: &ProcessIdentity) -> bool {
    left.pid == right.pid
        && left.parent_pid == right.parent_pid
        && left.process_group_id == right.process_group_id
        && left.start_identity == right.start_identity
        && left.quality == right.quality
}

#[cfg(test)]
mod cancelled_cleanup_tests {
    use super::*;
    use crate::domain::types::AgentAdapter;

    fn start_for(authority: &AgentLaunchAuthority) -> StartRequestEnvelope {
        let request = crate::launch::AgentStartRequest {
            schema_version: 1,
            operation_id: authority.operation_id.clone(),
            agent_run_id: authority.agent_run_id.clone(),
            project_id: authority.project_id.clone(),
            controller_generation: authority.controller_generation,
            descriptor_digest: authority.descriptor_digest.clone(),
            runtime_binary_digest: authority.runtime_binary_digest.clone(),
            environment_snapshot_id: authority.environment_snapshot_id.clone(),
            qualification_receipt_digest: authority.qualification_receipt_digest.clone(),
            wrapper_pid: std::process::id(),
            wrapper_start_identity: "wrapper-birth".into(),
            rex_launch_anchor: None,
            rex_session_id: authority.rex_session_id.clone(),
            rex_block_id: authority.rex_block_id.clone(),
        };
        StartRequestEnvelope {
            schema_version: 1,
            request_digest: format!(
                "{:x}",
                Sha256::digest(serde_json::to_vec(&request).unwrap())
            ),
            request,
        }
    }

    fn start_for_anchor_eof(authority: &AgentLaunchAuthority) -> StartRequestEnvelope {
        let mut start = start_for(authority);
        start.request.rex_launch_anchor = Some(crate::launch::LaunchAnchorIdentity {
            pid: 7001,
            start_identity: "shim-birth".into(),
        });
        start.request_digest = format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&start.request).unwrap())
        );
        start
    }

    fn cancelled_result(
        authority: &AgentLaunchAuthority,
        start: &StartRequestEnvelope,
        cleanup: CleanupState,
    ) -> AgentTurnResult {
        let schema_projection = crate::providers::project_result_schema(&serde_json::json!({
            "type": "object"
        }))
        .unwrap()
        .identity;
        AgentTurnResult {
            schema_version: 1,
            start_request_digest: start.request_digest.clone(),
            receipt: crate::run_step::RunReceipt {
                run_id: authority.agent_run_id.clone(),
                attempt: authority.attempt,
                provider: AgentAdapter::Codex,
                effective_permission_mode: "workspace_write".into(),
                conversation_id: None,
                provider_version: Some("fixture".into()),
                capability_receipt_digest: Some(authority.qualification_receipt_digest.clone()),
                schema_projection,
                launch_pid_hint: None,
                exit_code: None,
                timed_out: false,
                cancellation_signal: Some(1),
                cancellation_cause: None,
                cleanup,
                cleanup_detail: None,
                processes: Vec::new(),
                result_digest: None,
                provider_result_failure: None,
                provider_process_failure: None,
                outcome: TurnOutcome::Cancelled,
            },
            structured_result: None,
            result_digest: "e".repeat(64),
        }
    }

    #[test]
    fn complete_family_keeps_wrapper_separate_from_provider_members() {
        let process = |pid, parent_pid, process_group_id, start_identity: &str| ProcessIdentity {
            pid,
            parent_pid,
            process_group_id,
            start_identity: start_identity.into(),
            command: String::new(),
            quality: ProcessIdentityQuality::KernelBirthToken,
        };
        let provider_identity = |pid, parent_pid, process_group_id, start_identity: &str| {
            crate::launch::ProviderProcessIdentity {
                pid,
                parent_pid,
                process_group_id,
                start_identity: start_identity.into(),
                identity_quality: ProcessIdentityQuality::KernelBirthToken,
            }
        };
        let wrapper = process(84122, 100, 100, "wrapper-birth");
        let provider = process(84201, 84122, 84201, "provider-birth");
        let shell = process(84638, 84201, 84201, "shell-birth");
        let provider_tree = vec![
            provider_identity(84122, 100, 100, "wrapper-birth"),
            provider_identity(84201, 84122, 84201, "provider-birth"),
            provider_identity(84638, 84201, 84201, "shell-birth"),
        ];

        let historical = provider_identity(84500, 84201, 84201, "exited-helper-birth");
        let launch_tree = [provider_tree.as_slice(), std::slice::from_ref(&historical)].concat();
        let union = cumulative_provider_family_tree(
            &launch_tree,
            &[provider.clone(), shell.clone()],
            &wrapper,
        )
        .expect("a launch-only historical process belongs in the cumulative evidence");
        assert_eq!(union.len(), 4);
        assert!(union.iter().any(|identity| {
            identity.pid == historical.pid && identity.start_identity == historical.start_identity
        }));

        let reused_pid = provider_identity(84500, 84201, 84201, "reused-helper-pid");
        let conflicting_launch_tree =
            [launch_tree.as_slice(), std::slice::from_ref(&reused_pid)].concat();
        assert!(
            cumulative_provider_family_tree(&conflicting_launch_tree, &[provider, shell], &wrapper)
                .is_none()
        );
    }

    #[test]
    fn cancelled_result_requires_explicit_confirmed_cleanup_and_no_role_output() {
        let authority = tests::test_authority();
        let start = start_for(&authority);
        let qualification = tests::reviewer_qualification(&authority);
        let result = cancelled_result(&authority, &start, CleanupState::Confirmed);
        assert!(
            validate_cancelled_result_for_start(&authority, &start, &result, &qualification)
                .is_ok()
        );

        let mut signal_exit = result.clone();
        signal_exit.receipt.exit_code = Some(1);
        assert!(
            validate_cancelled_result_for_start(&authority, &start, &signal_exit, &qualification)
                .is_err()
        );

        let unknown_cleanup = cancelled_result(&authority, &start, CleanupState::Unknown);
        assert!(
            validate_cancelled_result_for_start(
                &authority,
                &start,
                &unknown_cleanup,
                &qualification
            )
            .is_err()
        );

        let mut role_output = result;
        role_output.structured_result = Some(serde_json::json!({"assertion":"succeeded"}));
        assert!(
            validate_cancelled_result_for_start(&authority, &start, &role_output, &qualification)
                .is_err()
        );

        let mut wrong_start = start;
        wrong_start.request.descriptor_digest = Digest::parse("f".repeat(64)).unwrap();
        assert!(validate_request_authority(&authority, &wrong_start).is_err());
    }

    #[test]
    fn anchor_eof_cancellation_requires_exact_durable_start_identity() {
        let authority = tests::test_authority();
        let start = start_for_anchor_eof(&authority);
        let qualification = tests::reviewer_qualification(&authority);
        let mut result = cancelled_result(&authority, &start, CleanupState::Confirmed);
        result.receipt.cancellation_signal = None;
        result.receipt.cancellation_cause = Some(CancellationCause::RexLaunchAnchorClosed {
            pid: 7001,
            start_identity: "shim-birth".into(),
        });
        result.receipt.exit_code = Some(1);
        assert!(
            validate_cancelled_result_for_start(&authority, &start, &result, &qualification)
                .is_ok()
        );

        let mut timed_out = result.clone();
        timed_out.receipt.timed_out = true;
        assert!(
            validate_cancelled_result_for_start(&authority, &start, &timed_out, &qualification)
                .is_err()
        );

        let mut unconfirmed_cleanup = result.clone();
        unconfirmed_cleanup.receipt.cleanup = CleanupState::Unknown;
        assert!(
            validate_cancelled_result_for_start(
                &authority,
                &start,
                &unconfirmed_cleanup,
                &qualification
            )
            .is_err()
        );

        let mut structured_output = result.clone();
        structured_output.structured_result = Some(serde_json::json!({"assertion":"success"}));
        assert!(
            validate_cancelled_result_for_start(
                &authority,
                &start,
                &structured_output,
                &qualification
            )
            .is_err()
        );

        result.receipt.cancellation_cause = Some(CancellationCause::RexLaunchAnchorClosed {
            pid: 7001,
            start_identity: "reused-shim-pid".into(),
        });
        assert!(
            validate_cancelled_result_for_start(&authority, &start, &result, &qualification)
                .is_err()
        );

        let legacy_start = start_for(&authority);
        result.start_request_digest = legacy_start.request_digest.clone();
        assert!(
            validate_cancelled_result_for_start(&authority, &legacy_start, &result, &qualification)
                .is_err()
        );
    }

    #[test]
    fn cancelled_cleanup_requires_persisted_accepted_start_ack() {
        let temp = tempfile::tempdir().unwrap();
        let store = ConfigStore::open_test(temp.path()).unwrap();
        let start = start_for(&tests::test_authority());
        assert!(verify_accepted_start_receipt(&store, &start).is_err());
    }

    #[test]
    fn cancelled_cleanup_rejects_extra_snapshot_identity_and_live_survivor() {
        let wrapper = ProcessIdentity {
            pid: 84122,
            parent_pid: 100,
            process_group_id: 100,
            start_identity: "wrapper-birth".into(),
            command: String::new(),
            quality: ProcessIdentityQuality::KernelBirthToken,
        };
        let provider = ProcessIdentity {
            pid: 84201,
            parent_pid: 84122,
            process_group_id: 84201,
            start_identity: "provider-birth".into(),
            command: String::new(),
            quality: ProcessIdentityQuality::KernelBirthToken,
        };
        let family = RunFamilyRecord {
            schema_version: 2,
            binding: crate::run_step_spool::RunFamilyBinding {
                schema_version: 1,
                agent_run_id: AgentRunId::parse("worker-run").unwrap(),
                reservation_epoch: 4,
                authority_digest: Digest::parse("a".repeat(64)).unwrap(),
                descriptor_digest: Digest::parse("b".repeat(64)).unwrap(),
                wrapper_pid: wrapper.pid,
                wrapper_start_identity: wrapper.start_identity.clone(),
                rex_launch_anchor: None,
            },
            observed_at_unix: 1,
            coverage: RunFamilyCoverage::Complete,
            wrapper_process: wrapper.clone(),
            provider_root: provider.clone(),
            provider_executable_path: "/bin/codex".into(),
            provider_executable_digest: Digest::parse("c".repeat(64)).unwrap(),
            process_tree: vec![provider.clone()],
            process_tree_digest: Digest::parse("d".repeat(64)).unwrap(),
        };
        let observed = |identity: &ProcessIdentity| crate::run_step::ObservedProcess {
            pid: identity.pid,
            parent_pid: identity.parent_pid,
            process_group_id: identity.process_group_id,
            start_identity: identity.start_identity.clone(),
            command: String::new(),
            identity_quality: "kernel_birth_token".into(),
        };
        assert!(same_identity_sets(
            &[observed(&provider)],
            &family.process_tree
        ));
        let launch_tree = vec![
            crate::launch::ProviderProcessIdentity {
                pid: provider.pid,
                parent_pid: provider.parent_pid,
                process_group_id: provider.process_group_id,
                start_identity: provider.start_identity.clone(),
                identity_quality: provider.quality,
            },
            crate::launch::ProviderProcessIdentity {
                pid: 84202,
                parent_pid: provider.pid,
                process_group_id: provider.process_group_id,
                start_identity: "historical-launch-only-birth".into(),
                identity_quality: ProcessIdentityQuality::KernelBirthToken,
            },
        ];
        let historical = ProcessIdentity {
            pid: 84202,
            parent_pid: provider.pid,
            process_group_id: provider.process_group_id,
            start_identity: "historical-launch-only-birth".into(),
            command: String::new(),
            quality: ProcessIdentityQuality::KernelBirthToken,
        };
        assert!(same_snapshot_provider_union(
            &BlockLossCleanupSnapshot {
                schema_version: crate::run_step_spool::BLOCK_LOSS_SNAPSHOT_VERSION,
                agent_run_id: family.binding.agent_run_id.clone(),
                reservation_epoch: family.binding.reservation_epoch,
                authority_digest: family.binding.authority_digest.clone(),
                launch_tree_digest: Digest::parse("e".repeat(64)).unwrap(),
                observed_at_unix: 1,
                cleanup_covered: false,
                process_tree: vec![wrapper.clone(), provider.clone(), historical.clone()],
                process_tree_digest: Digest::parse("f".repeat(64)).unwrap(),
            },
            &launch_tree,
            &family,
            &wrapper
        ));
        assert!(!same_snapshot_provider_union(
            &BlockLossCleanupSnapshot {
                schema_version: crate::run_step_spool::BLOCK_LOSS_SNAPSHOT_VERSION,
                agent_run_id: family.binding.agent_run_id.clone(),
                reservation_epoch: family.binding.reservation_epoch,
                authority_digest: family.binding.authority_digest.clone(),
                launch_tree_digest: Digest::parse("e".repeat(64)).unwrap(),
                observed_at_unix: 1,
                cleanup_covered: false,
                process_tree: vec![wrapper.clone(), provider.clone()],
                process_tree_digest: Digest::parse("f".repeat(64)).unwrap(),
            },
            &launch_tree,
            &family,
            &wrapper
        ));
        let extra = ProcessIdentity {
            pid: 84202,
            parent_pid: 84201,
            process_group_id: 84201,
            start_identity: "unexplained-birth".into(),
            command: String::new(),
            quality: ProcessIdentityQuality::KernelBirthToken,
        };
        assert!(!same_identity_sets(
            &[observed(&provider), observed(&extra)],
            &family.process_tree
        ));
        let launch_tree = vec![crate::launch::ProviderProcessIdentity {
            pid: provider.pid,
            parent_pid: provider.parent_pid,
            process_group_id: provider.process_group_id,
            start_identity: provider.start_identity.clone(),
            identity_quality: provider.quality,
        }];
        assert!(!same_snapshot_provider_union(
            &BlockLossCleanupSnapshot {
                schema_version: crate::run_step_spool::BLOCK_LOSS_SNAPSHOT_VERSION,
                agent_run_id: family.binding.agent_run_id.clone(),
                reservation_epoch: family.binding.reservation_epoch,
                authority_digest: family.binding.authority_digest.clone(),
                launch_tree_digest: Digest::parse("e".repeat(64)).unwrap(),
                observed_at_unix: 1,
                cleanup_covered: false,
                process_tree: vec![wrapper, provider, extra],
                process_tree_digest: Digest::parse("f".repeat(64)).unwrap(),
            },
            &launch_tree,
            &family,
            &family.wrapper_process
        ));

        let live = crate::process::inspect_process_table()
            .unwrap()
            .into_iter()
            .find(|process| {
                process.pid == std::process::id()
                    && process.quality == ProcessIdentityQuality::KernelBirthToken
            })
            .unwrap();
        let live_provider_tree = [
            launch_tree.as_slice(),
            &[crate::launch::ProviderProcessIdentity {
                pid: live.pid,
                parent_pid: live.parent_pid,
                process_group_id: live.process_group_id,
                start_identity: live.start_identity.clone(),
                identity_quality: live.quality,
            }],
        ]
        .concat();
        let live_union = cumulative_provider_family_tree(
            &live_provider_tree,
            &family.process_tree,
            &family.wrapper_process,
        )
        .unwrap();
        let observed_live_union = live_union
            .iter()
            .map(|identity| crate::run_step::ObservedProcess {
                pid: identity.pid,
                parent_pid: identity.parent_pid,
                process_group_id: identity.process_group_id,
                start_identity: identity.start_identity.clone(),
                command: String::new(),
                identity_quality: "kernel_birth_token".into(),
            })
            .collect::<Vec<_>>();
        assert!(verify_process_tree_absent(&observed_live_union).is_err());
    }
}

fn same_identity_sets(
    result: &[crate::run_step::ObservedProcess],
    family: &[ProcessIdentity],
) -> bool {
    result.len() == family.len()
        && family.iter().all(|process| {
            result.iter().any(|observed| {
                observed.pid == process.pid
                    && observed.parent_pid == process.parent_pid
                    && observed.process_group_id == process.process_group_id
                    && observed.start_identity == process.start_identity
                    && observed.identity_quality == "kernel_birth_token"
                    && process.quality == ProcessIdentityQuality::KernelBirthToken
            })
        })
}

fn same_process_identity_sets(left: &[ProcessIdentity], right: &[ProcessIdentity]) -> bool {
    left.len() == right.len()
        && right.iter().all(|expected| {
            left.iter()
                .any(|observed| same_process_identity(observed, expected))
        })
}

#[cfg(test)]
fn same_snapshot_provider_union(
    snapshot: &BlockLossCleanupSnapshot,
    provider_tree: &[crate::launch::ProviderProcessIdentity],
    family: &RunFamilyRecord,
    wrapper: &ProcessIdentity,
) -> bool {
    let Some(expected) =
        cumulative_provider_family_tree(provider_tree, &family.process_tree, wrapper)
    else {
        return false;
    };
    same_process_identity_sets(&snapshot.process_tree, &expected)
}

fn cumulative_provider_family_tree(
    provider_tree: &[crate::launch::ProviderProcessIdentity],
    family_tree: &[ProcessIdentity],
    wrapper: &ProcessIdentity,
) -> Option<Vec<ProcessIdentity>> {
    let mut identities = std::collections::BTreeMap::<u32, ProcessIdentity>::new();
    let mut insert = |process: ProcessIdentity| {
        if process.pid == 0
            || process.process_group_id == 0
            || process.start_identity.trim().is_empty()
            || process.quality != ProcessIdentityQuality::KernelBirthToken
        {
            return false;
        }
        match identities.entry(process.pid) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(process);
                true
            }
            std::collections::btree_map::Entry::Occupied(entry) => {
                same_process_identity(entry.get(), &process)
            }
        }
    };
    for process in provider_tree {
        if !insert(ProcessIdentity {
            pid: process.pid,
            parent_pid: process.parent_pid,
            process_group_id: process.process_group_id,
            start_identity: process.start_identity.clone(),
            command: String::new(),
            quality: process.identity_quality,
        }) {
            return None;
        }
    }
    for process in family_tree.iter().chain(std::iter::once(wrapper)) {
        if !insert(process.clone()) {
            return None;
        }
    }
    Some(identities.into_values().collect())
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
    verify_agent_run_snapshot(&tx, &authority, owner_generation)?;
    let launch_reservation = terminal_agent_launch_reservation(&tx, &authority)?;
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
        params![run_id.as_str(), now, owner_generation],
    ).map_err(|error| error.to_string())?;
    if run_changed != 1 {
        return Err("AgentRun state changed before terminal evidence was recorded".into());
    }
    let latest_adoption_generation: Option<u64> = tx
        .query_row(
            "SELECT controller_generation FROM agent_run_adoptions WHERE agent_run_id=?1 ORDER BY controller_generation DESC LIMIT 1",
            [run_id.as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    let prior_slot_generation =
        latest_adoption_generation.unwrap_or(authority.controller_generation);
    let slot: Option<(String, u32, u64, u64)> = tx
        .query_row(
            "SELECT pool,slot_index,reservation_epoch,controller_generation FROM execution_slots
             WHERE owner_kind='agent_run' AND owner_id=?1 AND project_id=?2
               AND controller_generation IN (?3,?4,?5)
               AND (?6 IS NULL OR (pool=?6 AND slot_index=?7 AND ticket_run_id IS ?8 AND reservation_epoch=?9))
               AND disposition IN ('launch_pending','live','parked','unknown')",
            params![
                run_id.as_str(),
                authority.project_id.as_str(),
                authority.controller_generation,
                prior_slot_generation,
                owner_generation,
                launch_reservation.as_ref().map(|reservation| reservation.pool.as_str()),
                launch_reservation.as_ref().map(|reservation| reservation.slot_index),
                launch_reservation.as_ref().and_then(|reservation| reservation.ticket_run_id.as_ref()).map(|ticket| ticket.as_str()),
                launch_reservation.as_ref().map(|reservation| reservation.project_epoch),
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    let Some((pool, slot_index, reservation_epoch, slot_generation)) = slot else {
        return Err("Agent terminal has no exact active execution slot to release".into());
    };
    let released = tx
        .execute(
            "UPDATE execution_slots SET disposition='released',controller_generation=?5 WHERE pool=?1 AND slot_index=?2 AND owner_kind='agent_run' AND owner_id=?3 AND reservation_epoch=?4 AND project_id=?6 AND controller_generation=?7 AND disposition IN ('launch_pending','live','parked','unknown')",
            params![pool, slot_index, run_id.as_str(), reservation_epoch, owner_generation, authority.project_id.as_str(), slot_generation],
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
    verify_agent_run_snapshot(&tx, &authority, owner_generation)?;
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
    pending_agent_results_with_due_at(store, artifact_store, owner_generation, None, limit)
}

pub fn pending_agent_results_at(
    store: &mut ConfigStore,
    artifact_store: &crate::artifacts::ArtifactStore,
    owner_generation: u64,
    now_unix: i64,
    limit: usize,
) -> Result<Vec<IngestedAgentResult>, String> {
    pending_agent_results_with_due_at(
        store,
        artifact_store,
        owner_generation,
        Some(now_unix),
        limit,
    )
}

fn pending_agent_results_with_due_at(
    store: &mut ConfigStore,
    artifact_store: &crate::artifacts::ArtifactStore,
    owner_generation: u64,
    now_unix: Option<i64>,
    limit: usize,
) -> Result<Vec<IngestedAgentResult>, String> {
    if limit == 0 || limit > 256 {
        return Err("pending Agent result limit must be between 1 and 256".into());
    }
    let ids = {
        let sql = if now_unix.is_some() {
            "SELECT e.evidence_id,e.agent_run_id,e.message_id FROM agent_result_evidence e LEFT JOIN agent_result_reducer_ack a USING(evidence_id) WHERE a.evidence_id IS NULL AND NOT EXISTS(SELECT 1 FROM merge_observation_deferrals d WHERE d.source_evidence_id=e.evidence_id AND ((d.state='waiting' AND d.next_attempt_at_unix>?1) OR (d.state IN ('exhausted','permanently_invalid') AND NOT EXISTS(SELECT 1 FROM ticket_runs tr WHERE tr.ticket_run_id=d.ticket_run_id AND tr.project_id=d.project_id AND tr.revision=d.ticket_run_revision AND tr.internal_phase='assessing' AND tr.activity='running')))) ORDER BY e.received_at_unix,e.evidence_id LIMIT ?2"
        } else {
            "SELECT e.evidence_id,e.agent_run_id,e.message_id FROM agent_result_evidence e LEFT JOIN agent_result_reducer_ack a USING(evidence_id) WHERE a.evidence_id IS NULL ORDER BY e.received_at_unix,e.evidence_id LIMIT ?1"
        };
        let mut statement = store
            .connection
            .prepare(sql)
            .map_err(|error| error.to_string())?;
        if let Some(now) = now_unix {
            statement
                .query_map(rusqlite::params![now, limit as u64], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })
                .map_err(|error| error.to_string())?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| error.to_string())?
        } else {
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
        }
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MergeObservationDeferralState {
    Waiting {
        attempt_count: u32,
        next_attempt_at_unix: i64,
    },
    Exhausted {
        attempt_count: u32,
    },
    PermanentlyInvalid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MergeObservationFailureCode {
    ProcessUnavailable,
    TimedOut,
    PermanentlyInvalid,
}

impl MergeObservationFailureCode {
    fn as_str(self) -> &'static str {
        match self {
            Self::ProcessUnavailable => "process_unavailable",
            Self::TimedOut => "timed_out",
            Self::PermanentlyInvalid => "permanent_invalid",
        }
    }

    fn retryable(self) -> bool {
        !matches!(self, Self::PermanentlyInvalid)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MergeObservationDeferralRecord {
    pub source_evidence_id: String,
    pub binding_digest: Digest,
    pub attempt_count: u32,
    pub next_attempt_at_unix: i64,
    pub state: MergeObservationDeferralState,
    pub failure_code: String,
}

pub const MERGE_OBSERVATION_MAX_ATTEMPTS: u32 = 5;

/// Persist an observation failure against the host-validated MergeAssessment identity.
/// Only an allowlisted code is stored; diagnostics and provider output are never persisted.
pub fn record_merge_observation_failure(
    store: &mut ConfigStore,
    owner_generation: u64,
    result: &IngestedAgentResult,
    publication_set_digest: &Digest,
    now_unix: i64,
    failure: MergeObservationFailureCode,
) -> Result<MergeObservationDeferralState, String> {
    let failure_code = failure.as_str();
    let retryable = failure.retryable();
    let binding = &result.validated.binding;
    let ticket_run_id = binding
        .ticket_run_id
        .as_ref()
        .ok_or("MergeAssessment observation binding lacks a TicketRun")?;
    let ticket_revision = binding
        .ticket_revision
        .ok_or("MergeAssessment observation binding lacks a TicketRun revision")?;
    if binding.role != Role::MergeDecision
        || result.validated.kind != crate::engine::orchestration::RoleOutputKind::MergeAssessment
    {
        return Err("observation deferral requires a validated MergeAssessment result".into());
    }
    let binding_json = crate::store::canonical_json(&(
        result.receipt.evidence_id(),
        &result.validated.result_digest,
        &binding.project_id,
        binding.config_revision,
        &binding.config_digest,
        ticket_run_id,
        ticket_revision,
        publication_set_digest,
    ))?;
    let binding_digest = Digest::parse(format!("{:x}", Sha256::digest(binding_json.as_bytes())))?;
    let tx = store
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| error.to_string())?;
    super::validate_active_generation(&tx, owner_generation)?;
    let prior: Option<(String, u32, String)> = tx.query_row(
        "SELECT binding_digest,attempt_count,state FROM merge_observation_deferrals WHERE source_evidence_id=?1",
        [result.receipt.evidence_id()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    ).optional().map_err(|error| error.to_string())?;
    if let Some((prior_digest, prior_attempts, prior_state)) = &prior {
        if prior_state != "waiting" {
            let state = match prior_state.as_str() {
                "exhausted" => MergeObservationDeferralState::Exhausted {
                    attempt_count: *prior_attempts,
                },
                _ => MergeObservationDeferralState::PermanentlyInvalid,
            };
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(state);
        }
        if prior_digest != binding_digest.as_str() {
            tx.execute(
                "UPDATE merge_observation_deferrals SET state='permanently_invalid',failure_code='permanent_invalid',next_attempt_at_unix=?2,updated_at_unix=?2 WHERE source_evidence_id=?1",
                params![result.receipt.evidence_id(), now_unix],
            ).map_err(|error| error.to_string())?;
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(MergeObservationDeferralState::PermanentlyInvalid);
        }
    }
    let attempt_count = if retryable {
        prior
            .as_ref()
            .filter(|(digest, _, _)| digest == binding_digest.as_str())
            .map_or(1, |(_, count, _)| {
                count.saturating_add(1).min(MERGE_OBSERVATION_MAX_ATTEMPTS)
            })
    } else {
        prior
            .as_ref()
            .filter(|(digest, _, _)| digest == binding_digest.as_str())
            .map_or(0, |(_, count, _)| *count)
    };
    let state = if !retryable {
        "permanently_invalid"
    } else if attempt_count >= MERGE_OBSERVATION_MAX_ATTEMPTS {
        "exhausted"
    } else {
        "waiting"
    };
    let delay = match attempt_count {
        0 | 1 => 5_i64,
        2 => 30,
        3 => 120,
        _ => 600,
    };
    let next_attempt = if state == "waiting" {
        now_unix.saturating_add(delay)
    } else {
        now_unix
    };
    tx.execute(
        "INSERT INTO merge_observation_deferrals(source_evidence_id,binding_digest,source_result_digest,project_id,config_revision,config_digest,ticket_run_id,ticket_run_revision,publication_set_digest,attempt_count,next_attempt_at_unix,state,failure_code,created_at_unix,updated_at_unix) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?14) ON CONFLICT(source_evidence_id) DO UPDATE SET binding_digest=excluded.binding_digest,source_result_digest=excluded.source_result_digest,project_id=excluded.project_id,config_revision=excluded.config_revision,config_digest=excluded.config_digest,ticket_run_id=excluded.ticket_run_id,ticket_run_revision=excluded.ticket_run_revision,publication_set_digest=excluded.publication_set_digest,attempt_count=excluded.attempt_count,next_attempt_at_unix=excluded.next_attempt_at_unix,state=excluded.state,failure_code=excluded.failure_code,updated_at_unix=excluded.updated_at_unix",
        params![result.receipt.evidence_id(),binding_digest.as_str(),result.validated.result_digest.as_str(),binding.project_id.as_str(),binding.config_revision.0,binding.config_digest.as_str(),ticket_run_id.as_str(),ticket_revision.0,publication_set_digest.as_str(),attempt_count,next_attempt,state,failure_code,now_unix],
    ).map_err(|error| error.to_string())?;
    tx.commit().map_err(|error| error.to_string())?;
    Ok(match state {
        "waiting" => MergeObservationDeferralState::Waiting {
            attempt_count,
            next_attempt_at_unix: next_attempt,
        },
        "exhausted" => MergeObservationDeferralState::Exhausted { attempt_count },
        _ => MergeObservationDeferralState::PermanentlyInvalid,
    })
}

pub(crate) fn migrate_v15_merge_observation_deferrals(
    connection: &mut rusqlite::Connection,
) -> Result<(), String> {
    let tx = connection
        .transaction()
        .map_err(|error| error.to_string())?;
    tx.execute_batch(
        "CREATE TABLE merge_observation_deferrals(
            source_evidence_id TEXT PRIMARY KEY NOT NULL REFERENCES agent_result_evidence(evidence_id),
            binding_digest TEXT NOT NULL CHECK(length(binding_digest)=64),
            source_result_digest TEXT NOT NULL CHECK(length(source_result_digest)=64),
            project_id TEXT NOT NULL,
            config_revision INTEGER NOT NULL,
            config_digest TEXT NOT NULL CHECK(length(config_digest)=64),
            ticket_run_id TEXT NOT NULL,
            ticket_run_revision INTEGER NOT NULL,
            publication_set_digest TEXT NOT NULL CHECK(length(publication_set_digest)=64),
            attempt_count INTEGER NOT NULL CHECK(attempt_count BETWEEN 0 AND 5),
            next_attempt_at_unix INTEGER NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('waiting','exhausted','permanently_invalid')),
            failure_code TEXT NOT NULL CHECK(failure_code IN ('process_unavailable','timed_out','permanent_invalid')),
            created_at_unix INTEGER NOT NULL,
            updated_at_unix INTEGER NOT NULL
        );
        CREATE INDEX merge_observation_deferrals_due ON merge_observation_deferrals(state,next_attempt_at_unix);
        INSERT INTO schema_migrations(version,applied_at_unix) VALUES (15,unixepoch());
        PRAGMA user_version=15;",
    ).map_err(|error| error.to_string())?;
    tx.commit().map_err(|error| error.to_string())
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
    ingest_next_spooled_agent_result_inner(
        store,
        artifact_store,
        owner_generation,
        candidate_limit,
        None,
        true,
    )
}

pub fn ingest_next_spooled_agent_result_at(
    store: &mut ConfigStore,
    artifact_store: &crate::artifacts::ArtifactStore,
    owner_generation: u64,
    now_unix: i64,
    candidate_limit: usize,
) -> Result<Option<IngestedAgentResult>, String> {
    ingest_next_spooled_agent_result_inner(
        store,
        artifact_store,
        owner_generation,
        candidate_limit,
        Some(now_unix),
        true,
    )
}

/// Shutdown drains newly completed run-step spools without replaying reducer work that was
/// already persisted before shutdown. Such evidence remains unacknowledged for the next normal
/// controller start, while independent terminal spools can still be durably ingested.
pub fn ingest_shutdown_spooled_agent_result_at(
    store: &mut ConfigStore,
    artifact_store: &crate::artifacts::ArtifactStore,
    owner_generation: u64,
    now_unix: i64,
    candidate_limit: usize,
) -> Result<Option<IngestedAgentResult>, String> {
    ingest_next_spooled_agent_result_inner(
        store,
        artifact_store,
        owner_generation,
        candidate_limit,
        Some(now_unix),
        false,
    )
}

fn ingest_next_spooled_agent_result_inner(
    store: &mut ConfigStore,
    artifact_store: &crate::artifacts::ArtifactStore,
    owner_generation: u64,
    candidate_limit: usize,
    now_unix: Option<i64>,
    return_existing_pending_result: bool,
) -> Result<Option<IngestedAgentResult>, String> {
    if candidate_limit == 0 || candidate_limit > 128 {
        return Err("Agent result candidate limit must be between 1 and 128".into());
    }
    if return_existing_pending_result {
        let pending = if let Some(now) = now_unix {
            pending_agent_results_at(store, artifact_store, owner_generation, now, 1)?
        } else {
            pending_agent_results(store, artifact_store, owner_generation, 1)?
        };
        if let Some(existing) = pending.into_iter().next() {
            return Ok(Some(existing));
        }
    }

    if let Some(result) =
        ingest_pending_verified_terminals(store, artifact_store, owner_generation, candidate_limit)?
    {
        return Ok(Some(result));
    }

    let candidates = {
        let mut statement = store.connection.prepare(
            "SELECT a.agent_run_id,a.control_dir FROM agent_launch_authority a \
             JOIN agent_launch_state s USING(agent_run_id) \
             JOIN agent_runs r USING(agent_run_id) \
             WHERE r.controller_generation=?1 AND r.state IN ('running','unknown') \
               AND s.state IN ('running','unknown') \
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
        if let Some(result) =
            ingest_verified_terminal_result(store, artifact_store, owner_generation, &terminal)?
        {
            return Ok(Some(result));
        }
    }
    Ok(None)
}

/// Reconcile the durable terminal-before-result gap. Kept as one production helper so tests and
/// controller ticks exercise the same candidate query and terminal ingestion path.
fn ingest_pending_verified_terminals(
    store: &mut ConfigStore,
    artifact_store: &crate::artifacts::ArtifactStore,
    owner_generation: u64,
    candidate_limit: usize,
) -> Result<Option<IngestedAgentResult>, String> {
    let terminal_ids = {
        let mut statement = store.connection.prepare(
            "SELECT t.agent_run_id FROM agent_terminal_receipts t
             WHERE NOT EXISTS(SELECT 1 FROM agent_result_evidence e WHERE e.agent_run_id=t.agent_run_id)
               AND NOT EXISTS(SELECT 1 FROM role_wake_inputs w WHERE w.source_type='role_result_rejected' AND w.source_id=t.agent_run_id AND json_extract(w.payload_json,'$.terminal_digest')=t.terminal_digest)
             ORDER BY t.observed_at_unix,t.agent_run_id LIMIT ?1",
        ).map_err(|error| error.to_string())?;
        statement
            .query_map([candidate_limit as u64], |row| row.get::<_, String>(0))
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?
    };
    for run_id in terminal_ids {
        let terminal = verify_agent_terminal(store, owner_generation, &AgentRunId::parse(run_id)?)?;
        if let Some(result) =
            ingest_verified_terminal_result(store, artifact_store, owner_generation, &terminal)?
        {
            return Ok(Some(result));
        }
    }
    Ok(None)
}

fn ingest_verified_terminal_result(
    store: &mut ConfigStore,
    artifact_store: &crate::artifacts::ArtifactStore,
    owner_generation: u64,
    terminal: &VerifiedAgentTerminal,
) -> Result<Option<IngestedAgentResult>, String> {
    let authority = store
        .agent_launch_authority(&terminal.agent_run_id)?
        .ok_or("role result lost its immutable launch authority")?;
    let binding = binding_for(&authority)?;
    let value = terminal
        .result
        .structured_result
        .clone()
        .ok_or("completed Agent terminal has no structured result")?;
    let message = serde_json::from_value::<RoleResultMessage>(value);
    let mut valid = match &message {
        Ok(message) => message.clone().bind(binding).is_ok(),
        Err(_) => false,
    };
    if valid {
        for reference in &message
            .as_ref()
            .map_err(|error| error.to_string())?
            .artifact_refs
        {
            // Untrusted references must name this run's exact registration. Byte and storage
            // verification still happens in normal ingestion and its failures remain errors.
            let registered: bool = store.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM registered_artifacts WHERE artifact_id=?1 AND agent_run_id=?2 AND authority_digest=?3 AND kind=?4 AND schema_version=?5 AND relative_path=?6 AND content_digest=?7 AND byte_count=?8)",
                params![reference.artifact_id.as_str(),authority.agent_run_id.as_str(),terminal.authority_digest.as_str(),reference.kind.as_str(),reference.schema_version,reference.path,reference.digest.as_str(),reference.bytes],
                |row| row.get(0),
            ).map_err(|error| error.to_string())?;
            if !registered {
                valid = false;
                break;
            }
        }
    }
    if !valid {
        reblock_rejected_merge_claim_recovery_terminal(
            store,
            owner_generation,
            terminal,
            &authority,
            "the authorized recovery Agent exited with an invalid role result",
        )?;
        record_rejected_role_result(
            store,
            owner_generation,
            terminal,
            &authority,
            "invalid_role_result",
            "The process exited, but its role output failed semantic validation. No child or workflow transition was authorized. Inspect the immutable result and request a corrected turn; inherited artifact locators cannot be forwarded as current-run registrations.",
        )?;
        eprintln!(
            "rex-projects: rejected role output from Agent {}; terminal evidence is retained; inspect the role input and use `ticket instruct` to request a corrected turn",
            authority.agent_run_id
        );
        return Ok(None);
    }
    match ingest_agent_result(
        store,
        artifact_store,
        owner_generation,
        terminal,
        message.map_err(|error| error.to_string())?,
    ) {
        Ok(result) => Ok(Some(result)),
        Err(error)
            if error == "TicketRun revision or config no longer matches Agent launch authority" =>
        {
            reblock_rejected_merge_claim_recovery_terminal(
                store,
                owner_generation,
                terminal,
                &authority,
                "the authorized recovery Agent terminal belongs to a stale launch snapshot",
            )?;
            record_rejected_role_result(
                store,
                owner_generation,
                terminal,
                &authority,
                "stale_launch_snapshot",
                "The TicketRun revision or project configuration advanced after this Agent was launched. The process terminal and absence are verified, but this stale role output authorized no child or workflow transition. Continue from the current Coordinator state.",
            )?;
            eprintln!(
                "rex-projects: retained terminal from stale Agent {}; role output was rejected because its TicketRun or config snapshot advanced",
                authority.agent_run_id
            );
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

/// A verified terminal with malformed role output is not role evidence, but it can prove that an
/// already-authorized one-shot recovery turn has ended. Use only the persisted launch authority,
/// exact consumed recovery wake / parent evidence, and verified terminal receipt to close that
/// recovery attempt; never interpret the malformed payload as authority.
fn reblock_rejected_merge_claim_recovery_terminal(
    store: &mut ConfigStore,
    owner_generation: u64,
    terminal: &VerifiedAgentTerminal,
    authority: &AgentLaunchAuthority,
    reason: &str,
) -> Result<(), String> {
    if !matches!(authority.role, Role::Coordinator | Role::MergeDecision) {
        return Ok(());
    }
    let Some(ticket_run_id) = authority.ticket_run_id.as_ref() else {
        return Ok(());
    };
    let recovery = match authority.role {
        Role::Coordinator => super::merge_claim_recovery::authorized_recovery_for_coordinator_run(
            &store.connection,
            &authority.project_id,
            ticket_run_id,
            &authority.agent_run_id,
            authority
                .ticket_revision
                .map(|revision| revision.0)
                .unwrap_or_default(),
        )?,
        Role::MergeDecision => {
            let Some(parent_run_id) = authority.parent_run_id.as_ref() else {
                return Ok(());
            };
            if authority.parent_role != Some(Role::Coordinator) {
                return Ok(());
            }
            let row: Option<(String, String, String, String)> = store.connection.query_row(
                "SELECT request_id,subject_json,subject_digest,authorization_key FROM merge_claim_recovery_requests WHERE project_id=?1 AND ticket_run_id=?2 AND state IN ('consumed','accepted') AND coordinator_evidence_id=(SELECT e.evidence_id FROM agent_result_evidence e WHERE e.agent_run_id=?3 AND e.role='coordinator' AND e.outcome='completed') ORDER BY updated_at_unix DESC LIMIT 1",
                rusqlite::params![authority.project_id.as_str(), ticket_run_id.as_str(), parent_run_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            ).optional().map_err(|error| error.to_string())?;
            row.map(|(request_id, subject_json, subject_digest, authorization_key)| {
                let subject: super::merge_claim_recovery::MergeClaimRecoverySubject =
                    crate::protocol::parse_unique(subject_json.as_bytes())?;
                let subject_digest = Digest::parse(subject_digest)?;
                let authorization_key = Digest::parse(authorization_key)?;
                if subject.digest()? != subject_digest
                    || subject.project_id != authority.project_id
                    || subject.ticket_run_id != *ticket_run_id
                    || authority.config_digest != subject.configuration_digest
                    || authority.instruction_digest != subject.instruction_digest
                    || authority.ticket_revision.map(|revision| revision.0)
                        != subject.blocked_revision.checked_add(1)
                {
                    return Err("rejected MergeDecision terminal differs from immutable recovery subject".into());
                }
                Ok::<super::merge_claim_recovery::AuthorizedMergeClaimRecovery, String>(super::merge_claim_recovery::AuthorizedMergeClaimRecovery {
                    request_id,
                    subject,
                    subject_digest,
                    authorization_key,
                    state: "consumed".into(),
                    coordinator_evidence_id: None,
                })
            }).transpose()?
        }
        _ => None,
    };
    let Some(recovery) = recovery else {
        return Ok(());
    };
    let tx = store
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| error.to_string())?;
    super::validate_active_generation(&tx, owner_generation)?;
    verify_persisted_authority(&tx, authority, &terminal.authority_digest)?;
    verify_terminal_row(&tx, terminal)?;
    let run: Option<(u64, String, String, String)> = tx.query_row(
        "SELECT revision,internal_phase,activity,external_status FROM ticket_runs WHERE project_id=?1 AND ticket_run_id=?2",
        rusqlite::params![authority.project_id.as_str(), ticket_run_id.as_str()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    ).optional().map_err(|error| error.to_string())?;
    let Some((revision, phase, activity, status)) = run else {
        return Ok(());
    };
    if authority.ticket_revision.map(|value| value.0) != Some(revision)
        || revision != recovery.subject.blocked_revision.saturating_add(1)
        || serde_json::from_str::<crate::engine::reducer::Phase>(&format!("\"{phase}\""))
            .map_err(|error| error.to_string())?
            != crate::engine::reducer::Phase::Assessing
        || serde_json::from_str::<crate::engine::reducer::Activity>(&format!("\"{activity}\""))
            .map_err(|error| error.to_string())?
            != crate::engine::reducer::Activity::Running
    {
        return Ok(());
    }
    let stored: Option<(String, String, String)> = tx.query_row(
        "SELECT state,subject_digest,authorization_key FROM merge_claim_recovery_requests WHERE request_id=?1 AND project_id=?2 AND ticket_run_id=?3",
        rusqlite::params![recovery.request_id, authority.project_id.as_str(), ticket_run_id.as_str()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    ).optional().map_err(|error| error.to_string())?;
    let Some((state, subject_digest, authorization_key)) = stored else {
        return Ok(());
    };
    let allowed_state = match authority.role {
        Role::Coordinator => state == "authorized",
        Role::MergeDecision => matches!(state.as_str(), "consumed" | "accepted"),
        _ => false,
    };
    if !allowed_state
        || subject_digest != recovery.subject_digest.as_str()
        || authorization_key != recovery.authorization_key.as_str()
    {
        return Ok(());
    }
    let current = crate::engine::reducer::TicketRun {
        project_id: authority.project_id.clone(),
        ticket_run_id: ticket_run_id.clone(),
        revision: Revision(revision),
        phase: crate::engine::reducer::Phase::Assessing,
        activity: crate::engine::reducer::Activity::Running,
        external_status: super::parse_ticket_status(&status)?,
        required_review_revision: None,
    };
    let decision = crate::engine::reducer::reduce(
        &current,
        current.revision,
        crate::engine::reducer::Input::HumanMergeDecisionResumeFailed,
    )?;
    let terminal_ref = format!("terminal:{}", terminal.terminal_digest.as_str());
    let evidence = serde_json::json!({"kind":"human_merge_claim_recovery_reblocked","request_id":recovery.request_id,"verified_terminal_digest":terminal.terminal_digest,"authorization_key":recovery.authorization_key,"reason":reason,"source_revision":revision});
    tx.execute(
        "UPDATE ticket_runs SET internal_phase=?3,activity=?4,external_status=?5,revision=?6 WHERE project_id=?1 AND ticket_run_id=?2 AND revision=?7",
        rusqlite::params![authority.project_id.as_str(), ticket_run_id.as_str(), super::enum_string(&decision.ticket_run.phase)?, super::enum_string(&decision.ticket_run.activity)?, super::enum_string(&decision.ticket_run.external_status)?, decision.ticket_run.revision.0, revision],
    ).map_err(|error| error.to_string())?;
    if tx.changes() != 1 {
        return Err("TicketRun changed while reblocking rejected recovery terminal".into());
    }
    tx.execute(
        "INSERT INTO transitions(project_id,entity_type,entity_id,old_revision,new_revision,input_id,decision_reason,evidence_json,created_at_unix) VALUES (?1,'ticket_run',?2,?3,?4,?5,'rejected recovery Agent terminal',?6,?7)",
        rusqlite::params![authority.project_id.as_str(), ticket_run_id.as_str(), revision, decision.ticket_run.revision.0, format!("merge-claim-recovery-reblocked:{}", recovery.request_id), crate::store::canonical_json(&evidence)?, unix_now()?],
    ).map_err(|error| error.to_string())?;
    let wake = serde_json::json!({"kind":"human_merge_claim_recovery_reblocked","ticket_run_id":ticket_run_id.as_str(),"request_id":recovery.request_id,"reason":reason,"revision":decision.ticket_run.revision.0});
    tx.execute(
        "INSERT INTO role_wake_inputs(project_id,role_session_id,source_type,source_id,source_revision,priority,payload_json,lifecycle,created_at_unix) VALUES (?1,?2,'merge_claim_recovery_reblocked',?3,?4,100,?5,'pending',?6)",
        rusqlite::params![authority.project_id.as_str(), format!("project:{}:supervisor", authority.project_id.as_str()), recovery.request_id, decision.ticket_run.revision.0, crate::store::canonical_json(&wake)?, unix_now()?],
    ).map_err(|error| error.to_string())?;
    tx.execute(
        "UPDATE merge_claim_recovery_requests SET state='reblocked',resumed_result_evidence_id=?2,rejection_reason=?3,updated_at_unix=?4 WHERE request_id=?1 AND state=?5",
        rusqlite::params![recovery.request_id, terminal_ref, reason, unix_now()?, state],
    ).map_err(|error| error.to_string())?;
    if tx.changes() != 1 {
        return Err("recovery attempt changed while reblocking rejected terminal".into());
    }
    tx.commit().map_err(|error| error.to_string())
}

fn record_rejected_role_result(
    store: &mut ConfigStore,
    owner_generation: u64,
    terminal: &VerifiedAgentTerminal,
    authority: &AgentLaunchAuthority,
    category: &str,
    instruction: &str,
) -> Result<(), String> {
    let (recipient, lifecycle) = if let Some(parent_id) = &authority.parent_run_id {
        let parent = store
            .agent_launch_authority(parent_id)?
            .ok_or("rejected role result parent authority is missing")?;
        if parent.project_id != authority.project_id
            || Some(parent.role) != authority.parent_role
            || !matches!(parent.role, Role::Coordinator | Role::Supervisor)
        {
            return Err("rejected role result parent is outside its role hierarchy".into());
        }
        (parent.role_session_id, "pending")
    } else {
        // Parentless roles need explicit human direction, not an unbounded self-retry.
        (authority.role_session_id.clone(), "superseded")
    };
    let payload = serde_json::json!({
        "kind":"role_result_rejected", "agent_run_id":authority.agent_run_id,
        "run_epoch":authority.run_epoch, "terminal_digest":terminal.terminal_digest,
        "category":category,
        "instruction":instruction
    })
    .to_string();
    let tx = store
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| error.to_string())?;
    super::validate_active_generation(&tx, owner_generation)?;
    verify_persisted_authority(&tx, authority, &terminal.authority_digest)?;
    verify_terminal_row(&tx, terminal)?;
    let has_evidence: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM agent_result_evidence WHERE agent_run_id=?1)",
            [authority.agent_run_id.as_str()],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    if has_evidence {
        return Err("cannot reject a role result that already has valid evidence".into());
    }
    let existing: Option<String> = tx.query_row(
        "SELECT payload_json FROM role_wake_inputs WHERE role_session_id=?1 AND source_type='role_result_rejected' AND source_id=?2 AND source_revision=?3",
        params![recipient,authority.agent_run_id.as_str(),authority.run_epoch], |row| row.get(0),
    ).optional().map_err(|error| error.to_string())?;
    if let Some(existing) = existing {
        if existing != payload {
            return Err("role rejection marker differs from the verified terminal".into());
        }
    } else {
        tx.execute(
            "INSERT INTO role_wake_inputs(project_id,role_session_id,source_type,source_id,source_revision,priority,payload_json,lifecycle,created_at_unix) VALUES (?1,?2,'role_result_rejected',?3,?4,100,?5,?6,?7)",
            params![authority.project_id.as_str(),recipient,authority.agent_run_id.as_str(),authority.run_epoch,payload,lifecycle,unix_now()?],
        ).map_err(|error| error.to_string())?;
    }
    tx.commit().map_err(|error| error.to_string())
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

/// Acknowledge a host-validated role result when its Project configuration has
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
    if !matches!(
        binding.role,
        Role::Worker | Role::Reviewer | Role::MergeDecision
    ) {
        return Err("obsolete configuration disposition does not support this result role".into());
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
        Role::MergeDecision => "merge_decision",
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
        Role::MergeDecision => "assessing",
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
        "worker_verification_completed" => (
            "worker-verification:",
            "worker",
            &["worker_verification_completed"],
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
    owner_generation: u64,
) -> Result<(), String> {
    let run: Option<(String, String, u64, String, u64, String, String)> = tx.query_row("SELECT project_id,config_source,config_revision,config_digest,controller_generation,state,logical_owner FROM agent_runs WHERE agent_run_id=?1", [authority.agent_run_id.as_str()], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?))).optional().map_err(|error| error.to_string())?;
    let Some((project, _source, config_revision, config_digest, run_generation, state, _owner)) =
        run
    else {
        return Err("AgentRun disappeared".into());
    };
    let generation_matches = if state == "completed" {
        let terminal_exists: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM agent_terminal_receipts WHERE agent_run_id=?1)",
                [authority.agent_run_id.as_str()],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        terminal_exists
            && run_generation >= authority.controller_generation
            && run_generation <= owner_generation
    } else {
        run_generation == owner_generation
    };
    if project != authority.project_id.as_str()
        || config_revision != authority.config_revision.0
        || config_digest != authority.config_digest.as_str()
        || !generation_matches
        || !matches!(state.as_str(), "running" | "unknown" | "completed")
    {
        return Err(
            "AgentRun project, config, generation, or lifecycle differs from launch authority"
                .into(),
        );
    }
    Ok(())
}

fn terminal_agent_launch_reservation(
    tx: &Transaction<'_>,
    authority: &AgentLaunchAuthority,
) -> Result<Option<crate::launch::AgentLaunchReservation>, String> {
    let row: Option<(String, String, String, String, u64, u64, String)> = tx
        .query_row(
            "SELECT reservation_json,lifecycle,project_id,operation_id,controller_generation,project_epoch,reservation_digest
             FROM agent_launch_reservations WHERE agent_run_id=?1",
            [authority.agent_run_id.as_str()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .optional()
        .map_err(|error| error.to_string())?;
    let Some((json, lifecycle, project, operation, generation, epoch, reservation_digest)) = row
    else {
        // A persisted launch may predate immutable reservation records. Its terminal replay
        // remains fenced by the persisted authority and exact active run/project-owned slot.
        return Ok(None);
    };
    if lifecycle != "authorized" {
        return Err("Agent terminal launch reservation is not authorized".into());
    }
    let reservation: crate::launch::AgentLaunchReservation =
        crate::protocol::parse_unique(json.as_bytes())?;
    if reservation.agent_run_id != authority.agent_run_id
        || reservation.project_id.as_str() != project
        || reservation.operation_id.as_str() != operation
        || reservation.controller_generation != generation
        || reservation.project_epoch != epoch
        || reservation.digest()?.as_str() != reservation_digest
        || reservation.project_id != authority.project_id
        || reservation.operation_id != authority.operation_id
        || reservation.role != authority.role
        || reservation.role_session_id != authority.role_session_id
        || reservation.ticket_run_id != authority.ticket_run_id
        || reservation.ticket_revision != authority.ticket_revision
        || reservation.controller_generation != authority.controller_generation
    {
        return Err("Agent terminal launch reservation differs from immutable authority".into());
    }
    Ok(Some(reservation))
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

pub(super) fn load_qualification(
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
        coordinator_spawn_result_at(
            child_role,
            "evidence-spawn",
            "coordinator-run",
            "coordinator-operation",
            3,
            3,
            "ticket_run:ticket-run:coordinator",
        )
    }

    fn coordinator_spawn_result_at(
        child_role: Role,
        evidence_id: &str,
        agent_run_id: &str,
        operation_id: &str,
        ticket_revision: u64,
        run_epoch: u64,
        role_session_id: &str,
    ) -> IngestedAgentResult {
        let digest = || Digest::parse("a".repeat(64)).unwrap();
        let binding = RoleResultBinding {
            agent_run_id: AgentRunId::parse(agent_run_id).unwrap(),
            operation_id: OperationId::parse(operation_id).unwrap(),
            project_id: ProjectId::parse("project-a").unwrap(),
            role_session_id: crate::engine::orchestration::RoleSessionId::parse(role_session_id)
                .unwrap(),
            role: Role::Coordinator,
            parent_run_id: Some(AgentRunId::parse("supervisor-run").unwrap()),
            parent_role: Some(Role::Supervisor),
            ticket_run_id: Some(TicketRunId::parse("ticket-run").unwrap()),
            ticket_revision: Some(Revision(ticket_revision)),
            config_revision: Revision(2),
            config_digest: digest(),
            profile_digest: digest(),
            instruction_digest: digest(),
            provider_capability_receipt_digest: digest(),
            result_schema_digest: digest(),
            controller_generation: 7,
            run_epoch,
            attempt: 1,
        };
        let request = crate::engine::orchestration::SpawnRequestPayload {
            work_node: crate::engine::orchestration::WorkNodeId::parse("plan-node").unwrap(),
            role: child_role,
            profile_id: ProfileId::parse("planner").unwrap(),
            plan_digest: Some(digest()),
            worker_recovery: None,
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
                evidence_id: evidence_id.into(),
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
                 CREATE TABLE agent_launch_authority(agent_run_id TEXT, authority_json TEXT, descriptor_digest TEXT, authority_digest TEXT);
                 CREATE TABLE agent_result_evidence(evidence_id TEXT, agent_run_id TEXT, project_id TEXT, role TEXT, outcome TEXT, ticket_run_id TEXT, run_epoch INTEGER);
                 INSERT INTO agent_result_evidence VALUES ('evidence-spawn','coordinator-run','project-a','coordinator','completed','ticket-run',3);
                 CREATE TABLE role_wake_inputs(wake_input_id INTEGER PRIMARY KEY, project_id TEXT, role_session_id TEXT, source_type TEXT, source_id TEXT, source_revision INTEGER, priority INTEGER, payload_json TEXT, lifecycle TEXT, created_at_unix INTEGER, consuming_agent_run_id TEXT, UNIQUE(role_session_id,source_type,source_id,source_revision));
                 CREATE TABLE agent_result_reducer_ack(evidence_id TEXT PRIMARY KEY, reducer_revision INTEGER, disposition TEXT, acknowledged_at_unix INTEGER);
                 CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY,applied_at_unix INTEGER NOT NULL);
                 PRAGMA user_version=15;",
            )
            .unwrap();
        super::super::merge_claim_recovery::migrate_v16(&connection).unwrap();
        connection
            .execute(
                "INSERT INTO agent_launch_authority VALUES ('coordinator-run',?1,?2,?3)",
                rusqlite::params![
                    authority_json,
                    authority.descriptor_digest.as_str(),
                    authority.digest().unwrap().as_str(),
                ],
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
    fn canonical_child_session_accepts_new_coordinator_turn_but_rejects_other_logical_parent() {
        let mut store = spawn_test_store();
        let first = coordinator_spawn_result(Role::Reviewer);
        let child_session = "ticket_run:ticket-run:reviewer";
        let first_payload = serde_json::json!({"request":"first review"});
        store
            .persist_coordinator_child_wake(
                7,
                &first,
                Role::Reviewer,
                child_session,
                3,
                &first_payload,
            )
            .unwrap();

        let second = coordinator_spawn_result_at(
            Role::Reviewer,
            "evidence-spawn-2",
            "coordinator-run-2",
            "coordinator-operation-2",
            7,
            4,
            "ticket_run:ticket-run:coordinator",
        );
        let mut second_authority = test_authority();
        second_authority.agent_run_id = AgentRunId::parse("coordinator-run-2").unwrap();
        second_authority.role = Role::Coordinator;
        second_authority.role_session_id = "ticket_run:ticket-run:coordinator".into();
        second_authority.parent_run_id = Some(AgentRunId::parse("supervisor-run").unwrap());
        second_authority.parent_role = Some(Role::Supervisor);
        second_authority.ticket_revision = Some(Revision(7));
        second_authority.operation_id = OperationId::parse("coordinator-operation-2").unwrap();
        second_authority.run_epoch = 4;
        store
            .connection
            .execute(
                "INSERT INTO agent_result_evidence VALUES ('evidence-spawn-2','coordinator-run-2','project-a','coordinator','completed','ticket-run',4)",
                [],
            )
            .unwrap();
        store
            .connection
            .execute(
                "INSERT INTO agent_launch_authority VALUES ('coordinator-run-2',?1,?2,?3)",
                rusqlite::params![
                    serde_json::to_string(&second_authority).unwrap(),
                    second_authority.descriptor_digest.as_str(),
                    second_authority.digest().unwrap().as_str(),
                ],
            )
            .unwrap();
        store
            .connection
            .execute("UPDATE ticket_runs SET revision=7", [])
            .unwrap();
        store
            .persist_coordinator_child_wake(
                7,
                &second,
                Role::Reviewer,
                child_session,
                7,
                &serde_json::json!({"request":"re-review after correction"}),
            )
            .unwrap();

        let wake_count: u32 = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM role_wake_inputs WHERE role_session_id=?1 AND source_type='coordinator_child'",
                [child_session],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(wake_count, 2);
        store
            .connection
            .execute(
                "UPDATE role_wake_inputs SET lifecycle='consumed' WHERE source_id='evidence-spawn'",
                [],
            )
            .unwrap();
        let parent = store
            .coordinator_child_parent(&ProjectId::parse("project-a").unwrap(), child_session)
            .unwrap()
            .expect("fresh Reviewer wake resolves its Coordinator turn");
        assert_eq!(parent.agent_run_id.as_str(), "coordinator-run-2");
        assert_eq!(parent.role_session_id, "ticket_run:ticket-run:coordinator");

        let wrong_parent = coordinator_spawn_result_at(
            Role::Reviewer,
            "evidence-spawn-wrong-parent",
            "coordinator-run-wrong-parent",
            "coordinator-operation-wrong-parent",
            7,
            5,
            "ticket_run:ticket-run:coordinator",
        );
        let mut wrong_authority = second_authority.clone();
        wrong_authority.agent_run_id = AgentRunId::parse("coordinator-run-wrong-parent").unwrap();
        wrong_authority.role_session_id = "ticket_run:ticket-run:coordinator".into();
        wrong_authority.operation_id =
            OperationId::parse("coordinator-operation-wrong-parent").unwrap();
        wrong_authority.run_epoch = 5;
        let mut prior_wrong_authority = test_authority();
        prior_wrong_authority.agent_run_id = AgentRunId::parse("coordinator-run").unwrap();
        prior_wrong_authority.role = Role::Coordinator;
        prior_wrong_authority.role_session_id =
            "ticket_run:ticket-run:alternate-coordinator".into();
        prior_wrong_authority.parent_run_id = Some(AgentRunId::parse("supervisor-run").unwrap());
        prior_wrong_authority.parent_role = Some(Role::Supervisor);
        prior_wrong_authority.operation_id = OperationId::parse("coordinator-operation").unwrap();
        prior_wrong_authority.run_epoch = 3;
        store
            .connection
            .execute(
                "UPDATE agent_launch_authority SET authority_json=?1,authority_digest=?2 WHERE agent_run_id='coordinator-run'",
                rusqlite::params![
                    serde_json::to_string(&prior_wrong_authority).unwrap(),
                    prior_wrong_authority.digest().unwrap().as_str(),
                ],
            )
            .unwrap();
        store
            .connection
            .execute(
                "INSERT INTO agent_result_evidence VALUES ('evidence-spawn-wrong-parent','coordinator-run-wrong-parent','project-a','coordinator','completed','ticket-run',5)",
                [],
            )
            .unwrap();
        store
            .connection
            .execute(
                "INSERT INTO agent_launch_authority VALUES ('coordinator-run-wrong-parent',?1,?2,?3)",
                rusqlite::params![
                    serde_json::to_string(&wrong_authority).unwrap(),
                    wrong_authority.descriptor_digest.as_str(),
                    wrong_authority.digest().unwrap().as_str(),
                ],
            )
            .unwrap();
        let error = store
            .persist_coordinator_child_wake(
                7,
                &wrong_parent,
                Role::Reviewer,
                child_session,
                7,
                &serde_json::json!({"request":"must reject"}),
            )
            .unwrap_err();
        assert!(error.contains("different logical Coordinator parent"));
        let bad_ack_count: u32 = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM agent_result_reducer_ack WHERE evidence_id='evidence-spawn-wrong-parent'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(bad_ack_count, 0);

        let mut original_authority = prior_wrong_authority;
        original_authority.role_session_id = "ticket_run:ticket-run:coordinator".into();
        store
            .connection
            .execute(
                "UPDATE agent_launch_authority SET authority_json=?1,authority_digest=?2 WHERE agent_run_id='coordinator-run'",
                rusqlite::params![
                    serde_json::to_string(&original_authority).unwrap(),
                    original_authority.digest().unwrap().as_str(),
                ],
            )
            .unwrap();

        store
            .connection
            .execute(
                "UPDATE agent_launch_authority SET authority_digest='tampered' WHERE agent_run_id='coordinator-run-2'",
                [],
            )
            .unwrap();
        let third = coordinator_spawn_result_at(
            Role::Reviewer,
            "evidence-spawn-3",
            "coordinator-run-3",
            "coordinator-operation-3",
            7,
            6,
            "ticket_run:ticket-run:coordinator",
        );
        let mut third_authority = test_authority();
        third_authority.agent_run_id = AgentRunId::parse("coordinator-run-3").unwrap();
        third_authority.role = Role::Coordinator;
        third_authority.role_session_id = "ticket_run:ticket-run:coordinator".into();
        third_authority.parent_run_id = Some(AgentRunId::parse("supervisor-run").unwrap());
        third_authority.parent_role = Some(Role::Supervisor);
        third_authority.ticket_revision = Some(Revision(7));
        third_authority.operation_id = OperationId::parse("coordinator-operation-3").unwrap();
        third_authority.run_epoch = 6;
        store
            .connection
            .execute(
                "INSERT INTO agent_result_evidence VALUES ('evidence-spawn-3','coordinator-run-3','project-a','coordinator','completed','ticket-run',6)",
                [],
            )
            .unwrap();
        store
            .connection
            .execute(
                "INSERT INTO agent_launch_authority VALUES ('coordinator-run-3',?1,?2,?3)",
                rusqlite::params![
                    serde_json::to_string(&third_authority).unwrap(),
                    third_authority.descriptor_digest.as_str(),
                    third_authority.digest().unwrap().as_str(),
                ],
            )
            .unwrap();
        let authority_error = store
            .persist_coordinator_child_wake(
                7,
                &third,
                Role::Reviewer,
                child_session,
                7,
                &serde_json::json!({"request":"must reject corrupt historical authority"}),
            )
            .unwrap_err();
        assert!(authority_error.contains("authority digest fields do not match"));
        let tampered_ack_count: u32 = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM agent_result_reducer_ack WHERE evidence_id='evidence-spawn-3'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(tampered_ack_count, 0);
    }

    #[test]
    fn child_parent_resolves_from_source_evidence_and_host_authority() {
        let connection = rusqlite::Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE role_wake_inputs(wake_input_id INTEGER, project_id TEXT, role_session_id TEXT, source_type TEXT, source_id TEXT, lifecycle TEXT);
                 INSERT INTO role_wake_inputs VALUES (1,'project-a','ticket_run:ticket-run:planner','coordinator_child','evidence-spawn','pending');
                 CREATE TABLE agent_result_evidence(evidence_id TEXT,agent_run_id TEXT,project_id TEXT,role TEXT,outcome TEXT,ticket_run_id TEXT);
                 INSERT INTO agent_result_evidence VALUES ('evidence-spawn','coordinator-run','project-a','coordinator','completed','ticket-run');
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
            .unwrap()
            .expect("pending Coordinator child wake has parent authority");
        assert_eq!(parent.agent_run_id.as_str(), "coordinator-run");
        assert_eq!(parent.role, Role::Coordinator);
        store
            .connection
            .execute("UPDATE role_wake_inputs SET lifecycle='consumed'", [])
            .unwrap();
        assert!(
            store
                .coordinator_child_parent(
                    &ProjectId::parse("project-a").unwrap(),
                    "ticket_run:ticket-run:planner",
                )
                .unwrap()
                .is_none()
        );
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
                 CREATE TABLE ticket_runs(ticket_run_id TEXT, project_id TEXT, ticket_id TEXT, namespace TEXT, generation INTEGER, external_revision TEXT);
                 INSERT INTO ticket_runs VALUES ('ticket-run','project-a','ticket-42','fixture',1,'rev-9');
                 CREATE TABLE transitions(project_id TEXT, entity_type TEXT, entity_id TEXT, old_revision INTEGER, new_revision INTEGER, input_id TEXT, evidence_json TEXT);
                 INSERT INTO transitions VALUES ('project-a','ticket_run','ticket-run',0,1,'dispatch:fixture:ticket-42','{\"namespace\":\"fixture\",\"ticket_id\":\"ticket-42\",\"generation\":1,\"recipe_id\":null,\"observed_revision\":\"rev-8\"}');
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

        for (input_id, evidence_json) in [
            ("dispatch:fixture:ticket-42", "{"),
            (
                "dispatch:fixture:ticket-42",
                r#"{"namespace":"fixture","ticket_id":"ticket-42","generation":1,"recipe_id":null,"observed_revision":"rev-7"}"#,
            ),
            (
                "dispatch:fixture:ticket-42",
                r#"{"namespace":"fixture","ticket_id":"ticket-42","generation":1,"recipe_id":null}"#,
            ),
            (
                "dispatch:other:ticket-42",
                r#"{"namespace":"other","ticket_id":"ticket-42","generation":1,"recipe_id":null,"observed_revision":"rev-8"}"#,
            ),
            (
                "dispatch:fixture:ticket-43",
                r#"{"namespace":"fixture","ticket_id":"ticket-43","generation":1,"recipe_id":null,"observed_revision":"rev-8"}"#,
            ),
        ] {
            store
                .connection
                .execute(
                    "UPDATE transitions SET input_id=?1,evidence_json=?2 WHERE project_id='project-a' AND entity_type='ticket_run' AND entity_id='ticket-run' AND new_revision=1",
                    rusqlite::params![input_id, evidence_json],
                )
                .unwrap();
            assert!(
                store
                    .supervisor_parent_for_ticket_run(
                        &ProjectId::parse("project-a").unwrap(),
                        &TicketRunId::parse("ticket-run").unwrap(),
                    )
                    .is_err()
            );
        }
        store
            .connection
            .execute(
                "DELETE FROM transitions WHERE project_id='project-a' AND entity_type='ticket_run' AND entity_id='ticket-run' AND new_revision=1",
                [],
            )
            .unwrap();
        assert!(
            store
                .supervisor_parent_for_ticket_run(
                    &ProjectId::parse("project-a").unwrap(),
                    &TicketRunId::parse("ticket-run").unwrap(),
                )
                .is_err()
        );
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
                worker_assignment: None,
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
            supervision_mode: None,
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
                cancellation_cause: None,
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
            wake_id,
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
            wake_id,
        )
        .unwrap()
        .unwrap();
        assert_eq!(replayed.receipt.evidence_id, evidence_id);
        assert!(replayed.receipt.wake_input_ids.contains(&wake_id));

        let repeated = agent_result_for_wake(
            &mut fixture.store,
            &fixture.artifacts,
            current_generation,
            wake_id,
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
        store.execute(
            "INSERT INTO agent_runs(agent_run_id,controller_generation,state) VALUES (?1,?2,'running')",
            rusqlite::params![authority.agent_run_id.as_str(), authority.controller_generation],
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
                rex_launch_anchor: None,
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
            rex_launch_anchor: None,
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
                cancellation_cause: None,
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
                 CREATE TABLE agent_runs(agent_run_id TEXT,controller_generation INTEGER,state TEXT);
                 CREATE TABLE agent_launch_state(agent_run_id TEXT,state TEXT,start_request_digest TEXT,provider_process_tree_json TEXT,updated_at_unix INTEGER);
                 CREATE TABLE agent_terminal_receipts(agent_run_id TEXT,terminal_digest TEXT,observed_at_unix INTEGER);
                 CREATE TABLE provider_qualifications(receipt_digest TEXT,receipt_json TEXT);
                 CREATE TABLE agent_result_evidence(evidence_id TEXT,agent_run_id TEXT,message_id TEXT,result_json TEXT,received_at_unix INTEGER);
                 CREATE TABLE agent_result_reducer_ack(evidence_id TEXT);
                 CREATE TABLE execution_slots(owner_kind TEXT,owner_id TEXT,disposition TEXT,reservation_epoch INTEGER);
                 CREATE TABLE role_wake_inputs(source_type TEXT,source_id TEXT,payload_json TEXT);",
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
    fn shutdown_spool_ingestion_does_not_replay_existing_reducer_backlog() {
        let temp = tempfile::tempdir().unwrap();
        let mut store = spooled_result_test_store();
        store.connection.execute_batch(
            "CREATE TABLE merge_observation_deferrals(source_evidence_id TEXT,state TEXT,next_attempt_at_unix INTEGER,ticket_run_id TEXT,project_id TEXT,ticket_run_revision INTEGER);
             CREATE TABLE ticket_runs(ticket_run_id TEXT,project_id TEXT,revision INTEGER,internal_phase TEXT,activity TEXT);",
        ).unwrap();
        store.connection.execute(
            "INSERT INTO agent_result_evidence(evidence_id,agent_run_id,message_id,result_json,received_at_unix)
             VALUES ('old-evidence','already-finished-run','old-message','not-json',1)",
            [],
        ).unwrap();
        spooled_candidate(
            &store.connection,
            temp.path(),
            "another-run",
            1,
            TurnOutcome::MissingResult,
            None,
        );
        let artifacts =
            crate::artifacts::ArtifactStore::open(&temp.path().join("artifacts")).unwrap();

        assert!(ingest_next_spooled_agent_result_at(&mut store, &artifacts, 7, 10, 8).is_err());

        let ingested =
            ingest_shutdown_spooled_agent_result_at(&mut store, &artifacts, 7, 10, 8).unwrap();

        assert!(ingested.is_none());
        let old_evidence: String = store
            .connection
            .query_row(
                "SELECT result_json FROM agent_result_evidence WHERE evidence_id='old-evidence'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            old_evidence, "not-json",
            "shutdown leaves reducer backlog untouched"
        );
        let slot: String = store
            .connection
            .query_row(
                "SELECT disposition FROM execution_slots WHERE owner_id='another-run'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            slot, "live",
            "an incomplete spool does not release its owner"
        );
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

    #[test]
    fn completed_invalid_spawn_result_is_rejected_durably_without_stopping_ingestion() {
        use crate::engine::orchestration::{AgentAssertion, RoleOutputKind};
        for declare_unregistered_reference in [false, true] {
            let mut message = RoleResultMessage {
                schema_version: 1,
                message_id: "coordinator-review-request".into(),
                kind: RoleOutputKind::SpawnRequest,
                assertion: AgentAssertion::Succeeded,
                structured_result: serde_json::json!({
                    "work_node":"node-a", "role":"reviewer", "profile_id":"fixture-profile",
                    "plan_digest":"a".repeat(64), "allowed_repositories":["repo-a"],
                    "artifact_inputs":[{"artifact_id":"b".repeat(64),"kind":"general",
                        "schema_version":1,"path":"sha256/bb/evidence","digest":"c".repeat(64),"bytes":14}]
                }),
                result_digest: None,
                artifact_refs: Vec::new(),
            };
            if declare_unregistered_reference {
                message.artifact_refs =
                    serde_json::from_value(message.structured_result["artifact_inputs"].clone())
                        .unwrap();
            }
            let mut fixture =
                host_validation_fixture::host_validated_terminal_result(Role::Coordinator, message)
                    .unwrap();
            for _ in 0..2 {
                let result = ingest_next_spooled_agent_result(
                    &mut fixture.store,
                    &fixture.artifacts,
                    fixture.owner_generation,
                    8,
                )
                .unwrap();
                assert!(result.is_none());
            }
            let count: u64 = fixture.store.connection.query_row(
            "SELECT COUNT(*) FROM role_wake_inputs WHERE source_type='role_result_rejected' AND source_id=?1",
            [fixture.terminal.agent_run_id.as_str()], |row| row.get(0),
        ).unwrap();
            assert_eq!(count, 1);
            let evidence: u64 = fixture
                .store
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM agent_result_evidence WHERE agent_run_id=?1",
                    [fixture.terminal.agent_run_id.as_str()],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(
                evidence, 0,
                "an invalid claim must never become verified role evidence"
            );
            verify_agent_terminal(
                &fixture.store,
                fixture.owner_generation,
                fixture.terminal.agent_run_id(),
            )
            .unwrap();
        }
    }

    #[test]
    fn completed_valid_result_is_replayed_after_the_terminal_commit_gap() {
        use crate::engine::orchestration::{AgentAssertion, RoleOutputKind};
        let mut fixture = host_validation_fixture::host_validated_terminal_result(
            Role::Coordinator,
            RoleResultMessage {
                schema_version: 1,
                message_id: "coordinator-progress-after-terminal".into(),
                kind: RoleOutputKind::Progress,
                assertion: AgentAssertion::Blocked {
                    reason: "waiting for review".into(),
                },
                structured_result: serde_json::json!({
                    "summary":"waiting for review", "completed_node_keys":[],
                    "pending_node_keys":["node-a"], "evidence":[], "next_observation_at":null
                }),
                result_digest: None,
                artifact_refs: Vec::new(),
            },
        )
        .unwrap();
        let result = ingest_next_spooled_agent_result(
            &mut fixture.store,
            &fixture.artifacts,
            fixture.owner_generation,
            8,
        )
        .unwrap()
        .expect("a valid terminal must still produce its role result after restart");
        assert_eq!(
            result.validated.message_id,
            "coordinator-progress-after-terminal"
        );
        assert_eq!(
            result.validated.binding.agent_run_id,
            *fixture.terminal.agent_run_id()
        );
        let replay = ingest_next_spooled_agent_result(
            &mut fixture.store,
            &fixture.artifacts,
            fixture.owner_generation,
            8,
        )
        .unwrap()
        .unwrap();
        assert_eq!(replay.receipt.evidence_id(), result.receipt.evidence_id());

        let previous_generation = fixture.owner_generation;
        let owner_generation = fixture
            .store
            .start_owner(&crate::store::OwnerMetadata {
                owner_nonce: "result-replay-after-owner-restart".into(),
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
        assert!(owner_generation > previous_generation);
        let restarted_replay = ingest_next_spooled_agent_result(
            &mut fixture.store,
            &fixture.artifacts,
            owner_generation,
            8,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            restarted_replay.receipt.evidence_id(),
            result.receipt.evidence_id()
        );
        let evidence_count: u64 = fixture
            .store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM agent_result_evidence WHERE agent_run_id=?1",
                [fixture.terminal.agent_run_id().as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(evidence_count, 1);
        let slot_disposition: String = fixture
            .store
            .connection
            .query_row(
                "SELECT disposition FROM execution_slots WHERE owner_id=?1",
                [fixture.terminal.agent_run_id().as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(slot_disposition, "released");
    }

    #[test]
    fn stale_coordinator_terminal_is_rejected_after_ticket_advance_without_child_authority() {
        use crate::engine::orchestration::{AgentAssertion, RoleOutputKind, SpawnRequestPayload};
        let mut fixture = host_validation_fixture::host_validated_terminal_result(
            Role::Coordinator,
            RoleResultMessage {
                schema_version: 1,
                message_id: "coordinator-before-postmortem".into(),
                kind: RoleOutputKind::SpawnRequest,
                assertion: AgentAssertion::Succeeded,
                structured_result: serde_json::to_value(SpawnRequestPayload {
                    work_node: crate::engine::orchestration::WorkNodeId::parse("operator-release")
                        .unwrap(),
                    role: Role::Operator,
                    profile_id: crate::domain::ids::ProfileId::parse("operator-default").unwrap(),
                    plan_digest: None,
                    worker_recovery: None,
                    allowed_repositories: Vec::new(),
                    artifact_inputs: Vec::new(),
                    parent_run_id: None,
                })
                .unwrap(),
                result_digest: None,
                artifact_refs: Vec::new(),
            },
        )
        .unwrap();
        let run_id = fixture.terminal.agent_run_id().as_str();
        fixture
            .store
            .connection
            .execute(
                "UPDATE ticket_runs SET revision=revision+1,internal_phase='postmortem' WHERE ticket_run_id='fixture-ticket-run'",
                [],
            )
            .unwrap();

        // Reconcile the already recorded terminal after the workflow has advanced. The original
        // fixture exercised process absence before this transition; this replay reaches the exact
        // current-revision guard that also ran before first receipt insertion.
        let terminal = record_and_verify_agent_terminal(
            &mut fixture.store,
            fixture.owner_generation,
            &fixture.start,
            &fixture.result,
        )
        .unwrap();
        assert_eq!(terminal.terminal_digest, fixture.terminal.terminal_digest);

        let ingested = ingest_next_spooled_agent_result(
            &mut fixture.store,
            &fixture.artifacts,
            fixture.owner_generation,
            8,
        )
        .unwrap();

        assert!(
            ingested.is_none(),
            "stale role output must not reach the reducer"
        );
        let rejection: Option<String> = fixture
            .store
            .connection
            .query_row(
                "SELECT payload_json FROM role_wake_inputs WHERE source_type='role_result_rejected' AND source_id=?1",
                [run_id],
                |row| row.get(0),
            )
            .optional()
            .unwrap();
        let rejection: serde_json::Value =
            serde_json::from_str(&rejection.expect("stale output must have a durable rejection"))
                .unwrap();
        assert_eq!(rejection["category"], "stale_launch_snapshot");
        assert_eq!(
            rejection["terminal_digest"],
            fixture.terminal.terminal_digest.as_str()
        );

        let evidence_count: u64 = fixture
            .store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM agent_result_evidence WHERE agent_run_id=?1",
                [run_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(evidence_count, 0, "stale evidence cannot authorize a child");
        let child_wake_count: u64 = fixture
            .store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM role_wake_inputs WHERE source_type='agent_result' AND source_id IN (SELECT evidence_id FROM agent_result_evidence WHERE agent_run_id=?1)",
                [run_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(child_wake_count, 0);
        let operator_child_count: u64 = fixture
            .store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM agent_launch_authority WHERE parent_run_id=?1 AND role='operator'",
                [run_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            operator_child_count, 0,
            "stale spawn cannot grant an Operator"
        );
        let slot_disposition: String = fixture
            .store
            .connection
            .query_row(
                "SELECT disposition FROM execution_slots WHERE owner_id=?1",
                [run_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(slot_disposition, "released");
        verify_agent_terminal(
            &fixture.store,
            fixture.owner_generation,
            fixture.terminal.agent_run_id(),
        )
        .expect("verified process absence remains available after the workflow advances");

        // Reprocessing must skip the durable rejection instead of poisoning the controller loop.
        assert!(
            ingest_next_spooled_agent_result(
                &mut fixture.store,
                &fixture.artifacts,
                fixture.owner_generation,
                8,
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn host_validated_blocked_worker_can_receive_one_coordinator_recovery_wake() {
        host_validated_worker_continuation_candidate(
            crate::engine::orchestration::AgentAssertion::Blocked {
                reason: "missing dependency".into(),
            },
            serde_json::json!({
                "summary":"blocked on a missing dependency",
                "completed_node_keys":[], "pending_node_keys":["node-a"],
                "evidence":[], "next_observation_at":null
            }),
            true,
        );
    }

    #[test]
    fn host_validated_worker_with_pending_progress_can_receive_one_coordinator_recovery_wake() {
        host_validated_worker_continuation_candidate(
            crate::engine::orchestration::AgentAssertion::Succeeded,
            serde_json::json!({
                "summary":"investigation is complete; implementation remains",
                "completed_node_keys":[], "pending_node_keys":["node-a"],
                "evidence":[], "next_observation_at":null
            }),
            true,
        );
    }

    #[test]
    fn host_validated_worker_with_nonready_progress_is_not_a_recovery_candidate() {
        for (assertion, progress) in [
            (
                crate::engine::orchestration::AgentAssertion::Succeeded,
                serde_json::json!({
                    "summary":"node is reported complete",
                    "completed_node_keys":["node-a"], "pending_node_keys":[],
                    "evidence":[], "next_observation_at":null
                }),
            ),
            (
                crate::engine::orchestration::AgentAssertion::Succeeded,
                serde_json::json!({
                    "summary":"the assigned node appears in both sets",
                    "completed_node_keys":["node-a"], "pending_node_keys":["node-a"],
                    "evidence":[], "next_observation_at":null
                }),
            ),
            (
                crate::engine::orchestration::AgentAssertion::Succeeded,
                serde_json::json!({
                    "summary":"no node state is reported",
                    "completed_node_keys":[], "pending_node_keys":[],
                    "evidence":[], "next_observation_at":null
                }),
            ),
            (
                crate::engine::orchestration::AgentAssertion::Succeeded,
                serde_json::json!({
                    "summary":"check again later",
                    "completed_node_keys":[], "pending_node_keys":["node-a"],
                    "evidence":[], "next_observation_at":"2099-01-01T00:00:00Z"
                }),
            ),
            (
                crate::engine::orchestration::AgentAssertion::Failed {
                    reason: "the turn reported failure".into(),
                },
                serde_json::json!({
                    "summary":"failed turn with an unfinished node",
                    "completed_node_keys":[], "pending_node_keys":["node-a"],
                    "evidence":[], "next_observation_at":null
                }),
            ),
        ] {
            host_validated_worker_continuation_candidate(assertion, progress, false);
        }
    }

    fn host_validated_worker_continuation_candidate(
        prior_assertion: crate::engine::orchestration::AgentAssertion,
        prior_progress: serde_json::Value,
        expect_candidate: bool,
    ) {
        use crate::config::ProjectConfig;
        use crate::domain::ids::{
            AgentRunId, OperationId, ProfileId, RepositoryId, TicketId, TicketNamespace,
        };
        use crate::domain::types::CommitMode;
        use crate::domain::types::Role;
        use crate::engine::orchestration::{
            AgentAssertion, PlannedWorkNode, RoleOutputKind, WorkPlan, WorkerRecoveryRequest,
        };
        use crate::roles::RoleResultMessage;
        use crate::store::accepted_plans::{AcceptedWorkPlanRecord, PersistedWorkPlan};
        use std::collections::BTreeMap;
        use std::os::unix::fs::PermissionsExt;
        use std::time::Duration;

        let root = tempfile::tempdir().unwrap();
        let git_executable = std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .map(|directory| directory.join("git"))
            .find(|path| path.is_file())
            .expect("git is installed for local repository fixtures");
        let run_git = |args: &[&str]| {
            let output = std::process::Command::new(&git_executable)
                .args(args)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "fixture git command failed: {args:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            String::from_utf8(output.stdout).unwrap().trim().to_owned()
        };
        let bare_remote = root.path().join("origin.git");
        let seed_repository = root.path().join("seed");
        run_git(&["init", "--bare", bare_remote.to_str().unwrap()]);
        run_git(&[
            "init",
            "--initial-branch=main",
            seed_repository.to_str().unwrap(),
        ]);
        run_git(&[
            "-C",
            seed_repository.to_str().unwrap(),
            "config",
            "user.name",
            "Fixture",
        ]);
        run_git(&[
            "-C",
            seed_repository.to_str().unwrap(),
            "config",
            "user.email",
            "fixture@example.invalid",
        ]);
        std::fs::write(seed_repository.join("README.md"), "base\n").unwrap();
        run_git(&["-C", seed_repository.to_str().unwrap(), "add", "README.md"]);
        run_git(&[
            "-C",
            seed_repository.to_str().unwrap(),
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-m",
            "base",
        ]);
        run_git(&[
            "-C",
            seed_repository.to_str().unwrap(),
            "remote",
            "add",
            "origin",
            bare_remote.to_str().unwrap(),
        ]);
        run_git(&[
            "-C",
            seed_repository.to_str().unwrap(),
            "push",
            "origin",
            "main",
        ]);
        let base_commit = run_git(&["-C", seed_repository.to_str().unwrap(), "rev-parse", "HEAD"]);
        let base = base_commit.as_str();
        let bootstrap_worker_id = AgentRunId::parse("fixture-bootstrap-worker").unwrap();
        let worker_id = AgentRunId::parse("fixture-prior-worker").unwrap();
        let blocked = serde_json::json!({
            "summary":"blocked on a missing dependency",
            "completed_node_keys":[], "pending_node_keys":["node-a"],
            "evidence":[], "next_observation_at":null
        });
        let mut worker = host_validation_fixture::host_validated_result_with_agent_run_id(
            Role::Worker,
            RoleResultMessage {
                schema_version: 1,
                message_id: "blocked-worker-result".into(),
                kind: RoleOutputKind::Progress,
                assertion: AgentAssertion::Blocked {
                    reason: "missing dependency".into(),
                },
                result_digest: Some(digest(&serde_json::to_vec(&blocked).unwrap()).unwrap()),
                structured_result: blocked.clone(),
                artifact_refs: Vec::new(),
            },
            Some(bootstrap_worker_id),
        )
        .unwrap();
        let project = ProjectId::parse("fixture-project").unwrap();
        let ticket = TicketRunId::parse("fixture-ticket-run").unwrap();
        let repository = RepositoryId::parse("repo-a").unwrap();
        let node_id = crate::engine::orchestration::WorkNodeId::parse("node-a").unwrap();
        let proposal = WorkPlan {
            nodes: vec![PlannedWorkNode {
                id: node_id.clone(),
                repository: repository.clone(),
                task: "implement the requested change".into(),
                depends_on: Vec::new(),
                required_evidence: vec!["tests pass".into()],
                investigation: false,
            }],
            requested_investigation_children: 0,
        };
        let plan_json = serde_json::to_string(
            &serde_json::to_value(PersistedWorkPlan {
                schema_version: 1,
                proposal: proposal.clone(),
                observed_base_shas: BTreeMap::from([(repository.clone(), base.to_owned())]),
            })
            .unwrap(),
        )
        .unwrap();
        let plan_digest =
            Digest::parse(format!("{:x}", sha2::Sha256::digest(plan_json.as_bytes()))).unwrap();
        let project_config: ProjectConfig = serde_json::from_value(serde_json::json!({
            "mode":"goal", "ticket_adapter":"tickets", "repositories":["repo-a"],
            "goal":{"revision":1,"statement":"fixture goal","acceptance":["tests pass"]}
        }))
        .unwrap();
        let configuration_digest = Digest::parse("a".repeat(64)).unwrap();
        let recovery_request = WorkerRecoveryRequest {
            prior_worker_agent_run_id: worker_id.clone(),
            prior_host_commit_operation_id: None,
        };
        let request = crate::engine::orchestration::SpawnRequestPayload {
            work_node: node_id.clone(),
            role: Role::Worker,
            profile_id: ProfileId::parse("fixture-profile").unwrap(),
            plan_digest: Some(plan_digest.clone()),
            worker_recovery: Some(recovery_request),
            allowed_repositories: Vec::new(),
            artifact_inputs: Vec::new(),
            parent_run_id: None,
        };
        let structured = serde_json::to_value(&request).unwrap();
        let fixture_root = std::fs::canonicalize(worker._temp.path()).unwrap();
        let coordinator = host_validation_fixture::host_validated_result_in_with_agent_run_id(
            &mut worker.store,
            &fixture_root,
            worker.owner_generation,
            project.clone(),
            ticket.clone(),
            Role::Coordinator,
            RoleResultMessage {
                schema_version: 1,
                message_id: "coordinator-recovery-request".into(),
                kind: RoleOutputKind::SpawnRequest,
                assertion: AgentAssertion::Succeeded,
                result_digest: Some(digest(&serde_json::to_vec(&structured).unwrap()).unwrap()),
                structured_result: structured,
                artifact_refs: Vec::new(),
            },
            AgentRunId::parse("fixture-recovery-coordinator").unwrap(),
        )
        .unwrap();
        let coordinator_authority = worker
            .store
            .agent_launch_authority(&AgentRunId::parse("fixture-recovery-coordinator").unwrap())
            .unwrap()
            .unwrap();
        let plan_record = AcceptedWorkPlanRecord {
            project_id: project.clone(),
            ticket_run_id: ticket.clone(),
            accepted_revision: 3,
            configuration_digest: configuration_digest.clone(),
            plan_digest: plan_digest.clone(),
            proposal: proposal.clone(),
            observed_base_shas: BTreeMap::from([(repository.clone(), base.to_owned())]),
            source_evidence_id: coordinator.ingested.receipt.evidence_id().into(),
            source_agent_run_id: coordinator_authority.agent_run_id.clone(),
            source_message_id: coordinator.ingested.receipt.message_id().into(),
            source_result_digest: coordinator.ingested.receipt.content_digest().clone(),
            coordinator_agent_run_id: coordinator_authority.agent_run_id.clone(),
            coordinator_role_session_id: coordinator_authority.role_session_id.clone(),
            coordinator_authority_digest: coordinator_authority.digest().unwrap(),
        };
        worker.store.test_connection().execute(
            "INSERT INTO accepted_work_plans(project_id,ticket_run_id,accepted_revision,configuration_digest,plan_digest,plan_json,source_evidence_id,source_agent_run_id,source_message_id,source_result_digest,coordinator_agent_run_id,coordinator_role_session_id,coordinator_authority_digest,created_at_unix) VALUES (?1,?2,3,?3,?4,?5,?6,?7,?8,?9,?7,?10,?11,1)",
            rusqlite::params![project.as_str(),ticket.as_str(),configuration_digest.as_str(),plan_digest.as_str(),plan_json,plan_record.source_evidence_id,plan_record.source_agent_run_id.as_str(),plan_record.source_message_id,plan_record.source_result_digest.as_str(),plan_record.coordinator_role_session_id,plan_record.coordinator_authority_digest.as_str()],
        ).unwrap();
        let git_options = crate::worktrees::GitOptions {
            executable: git_executable.clone(),
            environment: BTreeMap::new(),
            timeout: Duration::from_secs(20),
        };
        let repository_config = crate::config::RepositoryConfig {
            clone_url: bare_remote.to_string_lossy().into_owned(),
            base_branch: "main".into(),
            forge: "github".into(),
            worktree_root: None,
            instruction_files: Vec::new(),
            role_instruction_files: BTreeMap::new(),
            rex_projects_hooks: Vec::new(),
            merge: crate::config::MergeConfig::default(),
            operations: None,
        };
        let delivery_state = root.path().join("delivery-state");
        let delivery = crate::delivery_runtime::RepositoryDelivery::new(
            &delivery_state,
            git_options.clone(),
            BTreeMap::new(),
            crate::host_jobs::HostJobEnvironmentBinding {
                snapshot_id: Digest::parse("e".repeat(64)).unwrap(),
                policy_digest: Digest::parse("f".repeat(64)).unwrap(),
            },
        )
        .unwrap();
        let prepared_work = delivery
            .prepare_worktree(
                crate::delivery_runtime::WorkNodeIdentity {
                    project_id: project.clone(),
                    repository_id: repository.clone(),
                    ticket_namespace: TicketNamespace::parse("fixture").unwrap(),
                    ticket_id: TicketId::parse("T-1").unwrap(),
                    ticket_run_id: ticket.clone(),
                    work_node_id: node_id.to_string(),
                },
                &repository_config,
                base,
                CommitMode::Host,
            )
            .unwrap();
        let worktree = prepared_work.worktree.path.clone();
        let branch = prepared_work.worktree.branch.clone();
        let source_payload = serde_json::json!({
            "work_node_id":"node-artifact-source",
            "repository":"repo-a",
            "publication_operation_id":"publish-artifact-source",
            "published_head":base,
            "test_receipt_artifact_ids":[]
        });
        let source = host_validation_fixture::host_validated_result_inner(
            &mut worker.store,
            &fixture_root,
            worker.owner_generation,
            project.clone(),
            Some(ticket.clone()),
            Role::Worker,
            RoleResultMessage {
                schema_version: 1,
                message_id: "registered-host-artifact-source".into(),
                kind: RoleOutputKind::VerificationReady,
                assertion: AgentAssertion::Succeeded,
                result_digest: Some(digest(&serde_json::to_vec(&source_payload).unwrap()).unwrap()),
                structured_result: source_payload,
                artifact_refs: Vec::new(),
            },
            Some(AgentRunId::parse("fixture-artifact-source-worker").unwrap()),
            Vec::new(),
            Some("node-artifact-source"),
            None,
            None,
        )
        .unwrap();
        let source_references = source.message.artifact_refs.clone();
        let source_result = worker
            .store
            .store_validated_agent_result(
                &source.artifacts,
                worker.owner_generation,
                &source.terminal,
                source.message,
            )
            .unwrap();
        let source_authority = worker
            .store
            .agent_launch_authority(&AgentRunId::parse("fixture-artifact-source-worker").unwrap())
            .unwrap()
            .unwrap();
        let staged_locators = crate::parent_artifacts::stage_verified_parent_artifacts(
            &mut worker.store,
            &worker.artifacts,
            &source_authority,
            source_result.receipt.evidence_id(),
            &project,
            source_authority.config_revision.0,
            &source_authority.config_digest,
            &worktree,
            &source_references,
        )
        .unwrap();
        assert_eq!(staged_locators.len(), 1);
        let source_evidence_id = source_result.receipt.evidence_id().to_owned();
        let wake_authorization = crate::engine::orchestration::WorkerRecoveryAuthorization {
            schema_version: 1,
            ticket_run_id: ticket.clone(),
            ticket_revision: 4,
            work_node_id: node_id.clone(),
            accepted_plan_digest: plan_digest.clone(),
            prior_worker_agent_run_id: source_authority.agent_run_id.clone(),
            prior_terminal_digest: Digest::parse("b".repeat(64)).unwrap(),
            prior_absence_digest: Digest::parse("c".repeat(64)).unwrap(),
            prior_host_commit_operation_id: None,
            prior_host_commit_receipt_digest: None,
            expected_head: base.into(),
            source_coordinator_evidence_id: source_evidence_id.clone(),
            prior_worker_result_evidence_id: source_evidence_id.clone(),
            prior_artifact_refs: source_references.clone(),
        };
        let role_session = format!("ticket:{ticket}:{role}", role = "worker:node-a");
        let wake_payload = serde_json::json!({"authorization":wake_authorization});
        worker.store.test_connection().execute(
            "INSERT INTO role_wake_inputs(project_id,role_session_id,source_type,source_id,source_revision,priority,payload_json,lifecycle,created_at_unix) VALUES (?1,?2,'worker_recovery_authorization',?3,4,1,?4,'pending',1)",
            rusqlite::params![project.as_str(), role_session, source_evidence_id, crate::store::canonical_json(&wake_payload).unwrap()],
        ).unwrap();
        let wake_input_id: u64 = worker
            .store
            .test_connection()
            .last_insert_rowid()
            .try_into()
            .unwrap();
        let wake_input = crate::agent_api::AgentWakeItem {
            wake_input_id,
            source_type: "worker_recovery_authorization".into(),
            source_id: source_evidence_id,
            source_revision: 4,
            priority: 1,
            payload_json: wake_payload,
            host_artifact_source_evidence_ids: Vec::new(),
            host_artifacts: staged_locators,
            host_completion_context: None,
        };
        let mut wake_snapshot = crate::agent_api::AgentWakeSnapshot {
            schema_version: 1,
            project_id: project.clone(),
            role_session_id: role_session.clone(),
            agent_run_id: worker_id.to_string(),
            digest: Digest::parse("0".repeat(64)).unwrap(),
            inputs: vec![wake_input],
            worker_correction_context: None,
        };
        wake_snapshot.digest = wake_snapshot.content_digest().unwrap();
        let recipient = host_validation_fixture::host_validated_result_inner(
            &mut worker.store,
            &fixture_root,
            worker.owner_generation,
            project.clone(),
            Some(ticket.clone()),
            Role::Worker,
            RoleResultMessage {
                schema_version: 1,
                message_id: "blocked-worker-result-with-artifact".into(),
                kind: RoleOutputKind::Progress,
                assertion: prior_assertion.clone(),
                result_digest: Some(digest(&serde_json::to_vec(&prior_progress).unwrap()).unwrap()),
                structured_result: prior_progress.clone(),
                artifact_refs: Vec::new(),
            },
            Some(worker_id.clone()),
            wake_snapshot.inputs.clone(),
            Some("node-a"),
            None,
            None,
        )
        .unwrap();
        let _recipient_result = worker
            .store
            .store_validated_agent_result(
                &recipient.artifacts,
                worker.owner_generation,
                &recipient.terminal,
                recipient.message,
            )
            .unwrap();
        let prior_authority = worker
            .store
            .agent_launch_authority(&worker_id)
            .unwrap()
            .unwrap();
        let prepare_operation = OperationId::parse("prepare-worker-recovery").unwrap();
        let prepare_request = crate::delivery_runtime::PrepareWorktreesEffectPayload {
            schema_version: 1,
            source_revision: 3,
            configuration_digest: configuration_digest.clone(),
            ticket_namespace: TicketNamespace::parse("fixture").unwrap(),
            ticket_id: TicketId::parse("T-1").unwrap(),
            ticket_run_id: ticket.clone(),
            work_nodes: vec![crate::delivery_runtime::PreparedWorktreeNodeRequest {
                work_node_id: node_id.clone(),
                repository_id: repository.clone(),
                expected_base_sha: base.into(),
                commit_mode: CommitMode::Host,
            }],
        };
        let prepare_receipt = crate::delivery_runtime::PreparedWorktreesEffectReceipt {
            schema_version: 1,
            ticket_run_id: ticket.clone(),
            work_nodes: vec![crate::delivery_runtime::PreparedWorktreeReceiptNode {
                work_node_id: node_id.clone(),
                repository_id: repository.clone(),
                worktree_path: worktree.clone(),
                branch: branch.clone(),
                base_sha: base.into(),
                commit_mode: CommitMode::Host,
                base_refresh: None,
                base_refresh_source: None,
            }],
            base_refreshes: Vec::new(),
        };
        let request_json = crate::store::canonical_json(&prepare_request).unwrap();
        let request_digest = digest(request_json.as_bytes()).unwrap();
        let prepare_receipt_json = crate::store::canonical_json(&prepare_receipt).unwrap();
        let prepare_receipt_digest = digest(prepare_receipt_json.as_bytes()).unwrap();
        worker
            .store
            .test_connection()
            .execute(
                "INSERT INTO effects(operation_id,project_id,subject_type,subject_id,logical_key,kind,request_json,request_digest,expected_revision,status,attempt_count,next_attempt_at_unix,owner_generation,receipt_json,created_at_unix) VALUES (?1,?2,'ticket_run',?3,'prepare-worker-recovery','prepare_worktrees',?4,?5,3,'succeeded',1,0,?6,?7,1)",
                rusqlite::params![
                    prepare_operation.as_str(),
                    project.as_str(),
                    ticket.as_str(),
                    request_json,
                    request_digest.as_str(),
                    worker.owner_generation,
                    prepare_receipt_json
                ],
            )
            .unwrap();
        let assignment = crate::launch::WorkerLaunchBinding {
            schema_version: 1,
            accepted_revision: 3,
            ticket_revision: 4,
            configuration_digest: configuration_digest.clone(),
            plan_digest: plan_digest.clone(),
            node_id: node_id.clone(),
            repository_id: repository.clone(),
            commit_mode: CommitMode::Host,
            worktree_path: worktree.clone(),
            branch: branch.clone(),
            base_sha: base.into(),
            expected_head: None,
            prepare_operation_id: prepare_operation.to_string(),
            prepare_receipt_digest,
            source_evidence_id: plan_record.source_evidence_id.clone(),
            source_agent_run_id: plan_record.source_agent_run_id.clone(),
            source_message_id: plan_record.source_message_id.clone(),
            source_result_digest: plan_record.source_result_digest.clone(),
            coordinator_agent_run_id: coordinator_authority.agent_run_id.clone(),
            coordinator_role_session_id: coordinator_authority.role_session_id.clone(),
            coordinator_authority_digest: coordinator_authority.digest().unwrap(),
        };
        assert_eq!(wake_snapshot.role_session_id, role_session);
        assert_eq!(wake_snapshot.digest, prior_authority.wake_snapshot_digest);
        let previous_mailbox_directory = prior_authority.control_dir.join("mailbox");
        let descriptor_bytes =
            std::fs::read(previous_mailbox_directory.join("descriptor.json")).unwrap();
        let descriptor: crate::mailbox::MailboxDescriptor =
            crate::protocol::parse_unique(&descriptor_bytes).unwrap();
        let expires = descriptor.expires_at_unix;
        let mailbox_max_request_bytes = descriptor.max_request_bytes as u64;
        let mailbox_max_pending_requests = descriptor.max_pending_requests as u32;
        let mailbox_directory = prior_authority.control_dir.clone();
        crate::run_step_spool::RunStepSpool::open(&mailbox_directory).unwrap();
        crate::agent_api::publish_wake_snapshot(&mailbox_directory, wake_snapshot.clone()).unwrap();
        let schema_bytes = serde_json::to_vec(&crate::roles::result_schema(Role::Worker)).unwrap();
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(mailbox_directory.join("result.schema.json"))
        {
            Ok(mut file) => {
                use std::io::Write as _;
                file.write_all(&schema_bytes).unwrap();
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                assert_eq!(
                    std::fs::read(mailbox_directory.join("result.schema.json")).unwrap(),
                    schema_bytes
                );
            }
            Err(error) => panic!("create schema snapshot fixture: {error}"),
        }
        crate::mailbox::MailboxCapability::create(
            worker_id.as_str(),
            &mailbox_directory,
            expires,
            crate::mailbox::MailboxLimits {
                max_request_bytes: descriptor.max_request_bytes,
                max_pending_requests: descriptor.max_pending_requests,
            },
        )
        .unwrap();
        std::fs::remove_dir_all(&previous_mailbox_directory).unwrap();
        let mailbox_digest = Digest::parse(
            crate::mailbox::MailboxDescriptor::capability_digest(
                worker_id.as_str(),
                expires,
                crate::mailbox::MailboxLimits {
                    max_request_bytes: descriptor.max_request_bytes,
                    max_pending_requests: descriptor.max_pending_requests,
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(mailbox_digest, prior_authority.mailbox_capability_digest);
        let reservation = crate::launch::AgentLaunchReservation {
            schema_version: 1,
            agent_run_id: worker_id.clone(),
            project_id: project.clone(),
            role: Role::Worker,
            role_session_id: role_session,
            parent_run_id: prior_authority.parent_run_id.clone(),
            parent_role: prior_authority.parent_role,
            ticket_run_id: Some(ticket.clone()),
            ticket_revision: Some(crate::domain::ids::Revision(4)),
            config_revision: prior_authority.config_revision,
            config_digest: configuration_digest.clone(),
            attempt: prior_authority.attempt,
            run_epoch: prior_authority.run_epoch,
            controller_generation: worker.owner_generation,
            project_epoch: 1,
            operation_id: prior_authority.operation_id.clone(),
            operation_recipe_id: None,
            worker_assignment: Some(assignment),
            rex_view_id: prior_authority.rex_view_id.clone(),
            runtime_binary_digest: prior_authority.runtime_binary_digest.clone(),
            environment_snapshot_id: prior_authority.environment_snapshot_id.clone(),
            profile_id: prior_authority.profile_id.clone(),
            profile_digest: prior_authority.profile_digest.clone(),
            instruction_digest: prior_authority.instruction_digest.clone(),
            result_schema_digest: prior_authority.result_schema_digest.clone(),
            wake_snapshot,
            qualification_receipt_digest: prior_authority.qualification_receipt_digest.clone(),
            descriptor_path: prior_authority.descriptor_path.clone(),
            workspace_path: prior_authority.workspace_path.clone(),
            control_dir: prior_authority.control_dir.clone(),
            mailbox_directory: mailbox_directory.clone(),
            mailbox_capability_digest: mailbox_digest.clone(),
            mailbox_expires_at_unix: expires,
            mailbox_max_request_bytes,
            mailbox_max_pending_requests,
            pool: "agent".into(),
            slot_index: 0,
            global_capacity: 4,
            project_capacity: 4,
        };
        let reservation_json = crate::store::canonical_json(&reservation).unwrap();
        let wake_json = crate::store::canonical_json(&reservation.wake_snapshot).unwrap();
        worker
            .store
            .test_connection()
            .execute(
                "INSERT INTO agent_wake_context(agent_run_id,snapshot_digest,snapshot_json,created_at_unix) VALUES (?1,?2,?3,1)",
                rusqlite::params![worker_id.as_str(),prior_authority.wake_snapshot_digest.as_str(),wake_json],
            )
            .unwrap();
        worker.store.test_connection().execute(
            "INSERT INTO agent_launch_reservations(agent_run_id,project_id,operation_id,controller_generation,project_epoch,reservation_digest,reservation_json,lifecycle,created_at_unix,updated_at_unix) VALUES (?1,?2,?3,?4,1,?5,?6,'authorized',1,1)",
            rusqlite::params![worker_id.as_str(),project.as_str(),reservation.operation_id.as_str(),worker.owner_generation,reservation.digest().unwrap().as_str(),reservation_json],
        ).unwrap();
        worker.store.test_connection().execute(
            "INSERT INTO agent_mailboxes(agent_run_id,canonical_directory,capability_digest,expires_at_unix,max_request_bytes,max_pending_requests) VALUES (?1,?2,?3,?4,?5,?6)",
            rusqlite::params![worker_id.as_str(),mailbox_directory.display().to_string(),mailbox_digest.as_str(),expires,mailbox_max_request_bytes,mailbox_max_pending_requests],
        ).unwrap();
        let current = worker
            .store
            .active_ticket_runs(worker.owner_generation, 8)
            .unwrap()
            .into_iter()
            .find(|run| run.ticket_run_id == ticket)
            .unwrap();
        let prepared_receipt = worker
            .store
            .succeeded_effect_receipt(prepare_operation.as_str())
            .unwrap()
            .unwrap();
        let prepared = worker
            .store
            .prepared_worker_launch(
                worker.owner_generation,
                plan_record.accepted_revision,
                &node_id,
                &prepared_receipt,
                &project_config,
                &configuration_digest,
            )
            .unwrap();
        assert!(
            prepared.is_some(),
            "prepared launch did not validate: {prepared:?}"
        );
        let mut expected_assignment = prepared.as_ref().unwrap().reservation_binding();
        expected_assignment.expected_head = None;
        let stored_assignment = worker
            .store
            .agent_launch_reservation_for_run(&worker_id)
            .unwrap()
            .unwrap()
            .worker_assignment
            .unwrap();
        assert_eq!(expected_assignment, stored_assignment);
        assert_eq!(
            worker
                .store
                .agent_launch_authority(&worker_id)
                .unwrap()
                .unwrap()
                .ticket_revision
                .unwrap()
                .0,
            current.revision
        );
        assert!(
            !worker
                .store
                .connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM role_wake_inputs WHERE project_id=?1 AND source_type='worker_recovery_authorization' AND source_id=(SELECT evidence_id FROM agent_result_evidence WHERE agent_run_id=?2 AND role='worker' AND outcome='completed' ORDER BY received_at_unix DESC LIMIT 1))",
                    rusqlite::params![project.as_str(), worker_id.as_str()],
                    |row| row.get::<_, bool>(0),
                )
                .unwrap()
        );
        let debug_rows: (String, bool, bool) = worker.store.test_connection().query_row(
            "SELECT state,EXISTS(SELECT 1 FROM agent_terminal_receipts WHERE agent_run_id=?1),EXISTS(SELECT 1 FROM agent_result_evidence WHERE agent_run_id=?1 AND role='worker' AND outcome='completed') FROM agent_runs WHERE agent_run_id=?1",
            [worker_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).unwrap();
        assert_eq!(debug_rows, ("completed".into(), true, true));
        let verified = verify_agent_terminal(&worker.store, worker.owner_generation, &worker_id);
        assert!(verified.is_ok(), "terminal rejected: {verified:?}");
        let stored_reservation = worker
            .store
            .agent_launch_reservation_for_run(&worker_id)
            .unwrap()
            .unwrap();
        let stored_assignment = stored_reservation.worker_assignment.as_ref().unwrap();
        assert_eq!(stored_assignment.plan_digest, plan_record.plan_digest);
        assert_eq!(stored_assignment.configuration_digest, configuration_digest);
        assert_eq!(stored_reservation.role, Role::Worker);
        assert_eq!(
            stored_reservation.ticket_revision.unwrap().0,
            current.revision
        );
        let mailbox = crate::mailbox::MailboxCapability::open_registered_for_run(
            worker_id.to_string(),
            &stored_reservation.mailbox_directory,
        )
        .unwrap();
        let artifact_count_before_terminal_rejection: u64 = worker
            .store
            .test_connection()
            .query_row(
                "SELECT COUNT(*) FROM registered_artifacts WHERE agent_run_id=?1",
                [worker_id.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        let artifact_request_id = "completed-worker-artifact-add";
        let artifact_request = crate::engine::orchestration::ArtifactAddRequest {
            schema_version: 1,
            message_id: artifact_request_id.into(),
            path: "change/late-artifact.json".into(),
            kind: crate::engine::orchestration::RoleArtifactKind::Change,
            artifact_schema_version: 1,
        };
        let artifact_envelope = crate::protocol::RequestEnvelope {
            schema_version: crate::protocol::SCHEMA_VERSION,
            request_id: crate::protocol::RequestId::new(artifact_request_id).unwrap(),
            operation_id: Some(stored_reservation.operation_id.clone()),
            method: crate::protocol::MethodName::new("artifact.add").unwrap(),
            project_id: Some(stored_reservation.project_id.clone()),
            run_id: Some(worker_id.to_string()),
            attempt: Some(stored_reservation.attempt),
            run_epoch: Some(stored_reservation.run_epoch),
            expected_subject_revision: Some(current.revision),
            role: Some(Role::Worker),
            request_type: None,
            params: serde_json::to_value(artifact_request).unwrap(),
        };
        mailbox
            .queue(
                artifact_request_id,
                &serde_json::to_vec(&artifact_envelope).unwrap(),
                10,
            )
            .unwrap();
        let pending_before_terminal_dispatch = mailbox.pending(11).unwrap();
        let terminal_run_state: (String, u64) = worker
            .store
            .test_connection()
            .query_row(
                "SELECT state,controller_generation FROM agent_runs WHERE agent_run_id=?1",
                [worker_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert!(!pending_before_terminal_dispatch.is_empty());
        assert_eq!(terminal_run_state.0, "completed");
        let readiness_config: crate::config::Config = serde_json::from_value(serde_json::json!({
            "schema_version": 1,
            "adapters": {"tickets": {"kind": "command", "command": ["test"]}},
            "projects": {"fixture-project": project_config.clone()}
        }))
        .unwrap();
        worker.store.test_connection().execute(
            "UPDATE project_runtimes SET desired_lifecycle='running',observed_lifecycle='running',controller_generation=?2 WHERE project_id=?1",
            rusqlite::params![project.as_str(), worker.owner_generation],
        ).unwrap();
        assert_eq!(
            crate::engine::factory_runtime::queue_ready_worker_recovery_wakes(
                &mut worker.store,
                worker.owner_generation,
                11,
                &readiness_config,
                &configuration_digest,
            )
            .unwrap(),
            0,
            "a pending mailbox request keeps the Worker out of the recovery prompt"
        );
        assert!(
            worker
                .store
                .pending_role_wake_inputs(&project, &format!("ticket_run:{ticket}:coordinator"), 8,)
                .unwrap()
                .iter()
                .all(|wake| wake.source_type != "worker_recovery_ready")
        );
        // Host-validation fixtures omit Rex block observations; seed the completed block needed
        // to exercise the terminal mailbox replay path.
        worker.store.test_connection().execute(
            "INSERT INTO rex_view_blocks(view_id,block_id,agent_run_id,role,ownership,lifecycle,process_absent_confirmed,created_at_unix,last_observed_at_unix) VALUES (?1,?2,?3,'worker','factory','completed',1,1,1)",
            rusqlite::params![prior_authority.rex_view_id.as_str(), prior_authority.rex_block_id, worker_id.as_str()],
        ).unwrap();
        assert!(
            worker
                .store
                .process_one_agent_mailbox_request(
                    worker.owner_generation,
                    worker_id.as_str(),
                    11,
                    &worker.artifacts,
                    &BTreeMap::new(),
                )
                .unwrap()
        );
        let terminal_rejection: crate::protocol::ResponseEnvelope<serde_json::Value> =
            crate::protocol::parse_unique(
                &mailbox
                    .read_receipt(artifact_request_id, 11)
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
        assert!(!terminal_rejection.error.as_ref().unwrap().retryable);
        assert!(mailbox.pending(11).unwrap().is_empty());
        assert_eq!(
            worker
                .store
                .test_connection()
                .query_row(
                    "SELECT COUNT(*) FROM registered_artifacts WHERE agent_run_id=?1",
                    [worker_id.as_str()],
                    |row| row.get::<_, u64>(0),
                )
                .unwrap(),
            artifact_count_before_terminal_rejection
        );
        let candidates = worker
            .store
            .worker_recovery_candidates(
                worker.owner_generation,
                &current,
                &plan_record,
                &project_config,
                &configuration_digest,
            )
            .unwrap();
        if !expect_candidate {
            assert!(candidates.is_empty());
            assert_eq!(
                crate::engine::factory_runtime::queue_ready_worker_recovery_wakes(
                    &mut worker.store,
                    worker.owner_generation,
                    12,
                    &readiness_config,
                    &configuration_digest,
                )
                .unwrap(),
                0
            );
            assert!(
                worker
                    .store
                    .pending_role_wake_inputs(
                        &project,
                        &format!("ticket_run:{ticket}:coordinator"),
                        8,
                    )
                    .unwrap()
                    .iter()
                    .all(|wake| wake.source_type != "worker_recovery_ready")
            );
            return;
        }
        assert_eq!(candidates.len(), 1);
        let recovery_summary =
            crate::runtime_services::verified_worker_recovery_summary(candidates.clone(), |path| {
                let output = std::process::Command::new(&git_executable)
                    .args(["-C", path.to_str().unwrap(), "rev-parse", "HEAD"])
                    .output()
                    .unwrap();
                if !output.status.success() {
                    return Err(String::from_utf8_lossy(&output.stderr).into_owned());
                }
                Ok(String::from_utf8(output.stdout)
                    .map_err(|error| error.to_string())?
                    .trim()
                    .to_owned())
            })
            .unwrap()
            .unwrap();
        assert!(recovery_summary.contains(worker_id.as_str()));
        let evidence_json: String = worker.store.test_connection().query_row(
            "SELECT result_json FROM agent_result_evidence WHERE agent_run_id=?1 AND role='worker' AND outcome='completed'",
            [worker_id.as_str()], |row| row.get(0),
        ).unwrap();
        let evidence_submission: RoleResultSubmission =
            crate::protocol::parse_unique(evidence_json.as_bytes()).unwrap();
        assert_eq!(evidence_submission.assertion, prior_assertion);
        assert!(
            mailbox
                .pending(u64::try_from(super::unix_now().unwrap()).unwrap())
                .unwrap()
                .is_empty()
        );
        let active_worker: bool = worker.store.test_connection().query_row(
            "SELECT EXISTS(SELECT 1 FROM agent_runs WHERE role_session_id=?1 AND state IN ('launch_pending','running','unknown'))",
            [&stored_reservation.role_session_id], |row| row.get(0),
        ).unwrap();
        let leased_worker: bool = worker.store.test_connection().query_row(
            "SELECT EXISTS(SELECT 1 FROM execution_slots WHERE owner_kind='agent_run' AND owner_id=?1 AND disposition!='released')",
            [worker_id.as_str()], |row| row.get(0),
        ).unwrap();
        assert!(!active_worker && !leased_worker);
        assert_eq!(candidates.len(), 1);
        let candidate = &candidates[0];
        assert_eq!(candidate.prior_worker_agent_run_id, worker_id);
        assert_eq!(candidate.expected_head, base);
        assert_eq!(
            crate::engine::factory_runtime::queue_ready_worker_recovery_wakes(
                &mut worker.store,
                worker.owner_generation,
                12,
                &readiness_config,
                &configuration_digest,
            )
            .unwrap(),
            1,
            "the post-receipt scan persists a Coordinator wake after a restart window"
        );
        let coordinator_wakes = worker
            .store
            .pending_role_wake_inputs(&project, &format!("ticket_run:{ticket}:coordinator"), 8)
            .unwrap();
        let readiness_wakes = coordinator_wakes
            .into_iter()
            .filter(|wake| wake.source_type == "worker_recovery_ready")
            .collect::<Vec<_>>();
        assert_eq!(readiness_wakes.len(), 1);
        let wake_items =
            crate::runtime_services::RuntimeServices::wake_items_with_staged_artifacts(
                &worker.artifacts,
                &readiness_config,
                &mut worker.store,
                worker.owner_generation,
                &project,
                stored_reservation.config_revision.0,
                &configuration_digest,
                &fixture_root,
                readiness_wakes,
                None,
            )
            .unwrap();
        assert_eq!(wake_items.len(), 1);
        assert_eq!(wake_items[0].source_type, "worker_recovery_ready");
        assert_eq!(
            wake_items[0].payload_json["prior_worker_result_evidence_id"],
            candidate.prior_worker_result_evidence_id
        );
        let mut wake_snapshot = crate::agent_api::AgentWakeSnapshot {
            schema_version: 1,
            project_id: project.clone(),
            role_session_id: format!("ticket_run:{ticket}:coordinator"),
            agent_run_id: "fixture-coordinator-after-worker-mailbox-drain".into(),
            digest: Digest::parse("0".repeat(64)).unwrap(),
            inputs: wake_items,
            worker_correction_context: None,
        };
        wake_snapshot.digest = wake_snapshot.content_digest().unwrap();
        wake_snapshot.validate().unwrap();
        let coordinator_control = worker._temp.path().join("coordinator-control");
        std::fs::create_dir(&coordinator_control).unwrap();
        crate::agent_api::publish_wake_snapshot(&coordinator_control, wake_snapshot.clone())
            .unwrap();
        let inbox_inputs =
            crate::agent_api::read_inbox(&coordinator_control, &wake_snapshot.agent_run_id, 0)
                .unwrap();
        assert_eq!(inbox_inputs, wake_snapshot.inputs);
        assert_eq!(inbox_inputs[0].source_type, "worker_recovery_ready");
        let applied = crate::config::load(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/fixture/config.toml"),
        )
        .expect("load fixture config for the real Coordinator prompt renderer");
        let rendered = crate::roles::render_role_prompt(
            &applied,
            &crate::roles::PromptContext {
                project_id: ProjectId::parse("goal_project").unwrap(),
                profile_id: None,
                role: Role::Coordinator,
                operation_recipe: None,
                repositories: vec![RepositoryId::parse("example").unwrap()],
                ticket: Some(crate::roles::TicketBrief {
                    ticket_id: TicketId::parse("PAY-12").unwrap(),
                    ticket_revision: current.revision,
                    title: "Recover a blocked worker".into(),
                    body: "Retry the same accepted node after its mailbox is drained.".into(),
                    acceptance: Vec::new(),
                }),
                recovery_summary: Some(recovery_summary),
                accepted_plan: None,
                accepted_plan_digest: None,
                implementation_publication_subject: None,
                completion_context: None,
                previous_decisions: Vec::new(),
                required_evidence: Vec::new(),
                stop_conditions: Vec::new(),
                assigned_commit_mode: None,
            },
            &std::env::current_exe().unwrap(),
        )
        .unwrap();
        let input_file = worker._temp.path().join("coordinator-recovery-prompt.md");
        std::fs::write(&input_file, rendered.text).unwrap();
        let generated_input = std::fs::read_to_string(input_file).unwrap();
        assert!(generated_input.contains(worker_id.as_str()));
        assert!(generated_input.contains(base));
        let coordinator_launch = worker
            .store
            .pending_role_wake_sessions(worker.owner_generation, 16)
            .unwrap()
            .into_iter()
            .find(|candidate| {
                candidate.role_session_id == format!("ticket_run:{ticket}:coordinator")
            })
            .expect("durable readiness wake makes the Coordinator launchable");
        assert_eq!(coordinator_launch.role, Role::Coordinator);
        assert_eq!(
            crate::engine::factory_runtime::queue_ready_worker_recovery_wakes(
                &mut worker.store,
                worker.owner_generation,
                13,
                &readiness_config,
                &configuration_digest,
            )
            .unwrap(),
            0,
            "replaying readiness reconciliation does not enqueue a duplicate wake"
        );
        assert_eq!(
            worker
                .store
                .pending_role_wake_inputs(&project, &format!("ticket_run:{ticket}:coordinator"), 8,)
                .unwrap()
                .into_iter()
                .filter(|wake| wake.source_type == "worker_recovery_ready")
                .count(),
            1
        );
        let authorization = crate::engine::orchestration::WorkerRecoveryAuthorization {
            schema_version: 1,
            ticket_run_id: ticket.clone(),
            ticket_revision: 4,
            work_node_id: node_id.clone(),
            accepted_plan_digest: plan_digest,
            prior_worker_agent_run_id: worker_id.clone(),
            prior_terminal_digest: candidate.prior_terminal_digest.clone(),
            prior_absence_digest: candidate.prior_absence_digest.clone(),
            prior_host_commit_operation_id: None,
            prior_host_commit_receipt_digest: None,
            expected_head: base.into(),
            source_coordinator_evidence_id: coordinator.ingested.receipt.evidence_id().into(),
            prior_worker_result_evidence_id: candidate.prior_worker_result_evidence_id.clone(),
            prior_artifact_refs: Vec::new(),
        };
        let coordinator_result = &coordinator.ingested;
        worker
            .store
            .persist_worker_recovery_wake(
                worker.owner_generation,
                coordinator_result,
                &authorization,
                4,
            )
            .unwrap();
        worker
            .store
            .persist_worker_recovery_wake(
                worker.owner_generation,
                coordinator_result,
                &authorization,
                4,
            )
            .unwrap();
        let wakes = worker
            .store
            .pending_role_wake_inputs(&project, &format!("ticket:{ticket}:worker:{node_id}"), 8)
            .unwrap();
        assert_eq!(wakes.len(), 1);
        assert_eq!(wakes[0].source_type, "worker_recovery_authorization");
        assert!(
            worker
                .store
                .worker_recovery_candidates(
                    worker.owner_generation,
                    &current,
                    &plan_record,
                    &project_config,
                    &configuration_digest,
                )
                .unwrap()
                .is_empty()
        );

        let previous_owner_generation = worker.owner_generation;
        let prior_authority = worker
            .store
            .agent_launch_authority(&worker_id)
            .unwrap()
            .unwrap();
        let manifested_bytes = b"updated tracked fixture\n";
        std::fs::write(worktree.join("README.md"), manifested_bytes).unwrap();
        let manifest = crate::host_commit::ChangeManifest {
            schema_version: 1,
            entries: vec![crate::host_commit::ManifestEntry::Write {
                path: "README.md".into(),
                mode: crate::host_commit::FileMode::Regular0644,
                sha256: digest(manifested_bytes).unwrap(),
                byte_count: manifested_bytes.len() as u64,
            }],
        };
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
        let manifest_path = "change/manifest.json";
        let manifest_file = prior_authority.workspace_path.join(manifest_path);
        std::fs::create_dir_all(manifest_file.parent().unwrap()).unwrap();
        std::fs::write(&manifest_file, &manifest_bytes).unwrap();
        let manifest_artifact = worker
            .artifacts
            .register(
                &prior_authority.workspace_path,
                &prior_authority.project_id,
                worker_id.as_str(),
                Role::Worker,
                manifest_path,
                crate::engine::orchestration::RoleArtifactKind::Change,
                1,
            )
            .unwrap();
        crate::store::artifact_registry::persist_registration(
            &mut worker.store.connection,
            worker.owner_generation,
            &prior_authority,
            "fixture-change-manifest",
            &digest(b"fixture Change ArtifactAdd request").unwrap(),
            &manifest_artifact.reference,
            &manifest_artifact.object_path,
        )
        .unwrap();
        let restarted_generation = worker
            .store
            .start_owner(&crate::store::OwnerMetadata {
                owner_nonce: "completed-worker-mailbox-replay".into(),
                state_root: worker._temp.path().display().to_string(),
                config_source: "fixture".into(),
                process_start_identity: "fixture-owner-restarted".into(),
                executable_path: "/test/fixture".into(),
                executable_digest: "b".repeat(64),
                rex_endpoint: Some("http://fixture".into()),
                rex_server_identity: Some("fixture-rex".into()),
                rex_session_id: Some("fixture-session".into()),
                rex_block_id: Some("fixture-block".into()),
            })
            .unwrap();
        assert!(restarted_generation > previous_owner_generation);
        let block_lifecycle: String = worker
            .store
            .connection
            .query_row(
                "SELECT lifecycle FROM rex_view_blocks WHERE view_id=?1 AND block_id=?2",
                rusqlite::params![
                    prior_authority.rex_view_id.as_str(),
                    prior_authority.rex_block_id
                ],
                |row| row.get(0),
            )
            .unwrap();
        assert!(matches!(block_lifecycle.as_str(), "completed" | "closed"));
        let mailbox = crate::mailbox::MailboxCapability::open_registered_for_run(
            worker_id.to_string(),
            &stored_reservation.mailbox_directory,
        )
        .unwrap();
        let unknown_receipt = worktree.join("correction-test-receipt.txt");
        std::fs::write(&unknown_receipt, "not in the immutable change manifest\n").unwrap();
        let invalid_request_id = "terminal-restart-manifest-path-mismatch";
        let invalid_commit_message =
            "docs: fixture retained commit\n\nCo-authored-by: Codex <noreply@openai.com>";
        let invalid_request = crate::agent_api::RepositoryCommitRequest {
            schema_version: 1,
            message_id: invalid_request_id.into(),
            worktree_id: stored_assignment.node_id.to_string(),
            expected_head: base.into(),
            manifest: manifest_artifact.reference.clone(),
            manifest_digest: manifest_artifact.reference.digest.clone(),
            commit_message: invalid_commit_message.into(),
        };
        let invalid_envelope = crate::protocol::RequestEnvelope {
            schema_version: crate::protocol::SCHEMA_VERSION,
            request_id: crate::protocol::RequestId::new(invalid_request_id).unwrap(),
            operation_id: Some(prior_authority.operation_id.clone()),
            method: crate::protocol::MethodName::new("repository.commit").unwrap(),
            project_id: Some(project.clone()),
            run_id: Some(worker_id.to_string()),
            attempt: Some(prior_authority.attempt),
            run_epoch: Some(prior_authority.run_epoch),
            expected_subject_revision: Some(current.revision),
            role: Some(Role::Worker),
            request_type: None,
            params: serde_json::to_value(&invalid_request).unwrap(),
        };
        mailbox
            .queue(
                invalid_request_id,
                &serde_json::to_vec(&invalid_envelope).unwrap(),
                crate::mailbox::unix_time_now().unwrap(),
            )
            .unwrap();
        let invalid_mailbox_request = mailbox
            .pending(crate::mailbox::unix_time_now().unwrap())
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        let invalid_payload = crate::delivery_runtime::CommitWorkerManifestEffectPayload {
            schema_version: 1,
            agent_run_id: worker_id.clone(),
            project_id: project.clone(),
            message_id: invalid_request.message_id.clone(),
            configuration_digest: prior_authority.config_digest.clone(),
            ticket_revision: current.revision,
            ticket_namespace: TicketNamespace::parse("fixture").unwrap(),
            ticket_id: TicketId::parse("T-1").unwrap(),
            ticket_run_id: ticket.clone(),
            work_node_id: stored_assignment.node_id.clone(),
            repository_id: repository.clone(),
            worktree_path: worktree.clone(),
            branch: branch.clone(),
            prepare_operation_id: prepare_operation.clone(),
            expected_base_sha: base.into(),
            expected_head: invalid_request.expected_head.clone(),
            manifest_artifact: invalid_request.manifest.clone(),
            manifest_digest: invalid_request.manifest_digest.clone(),
            manifest: manifest.clone(),
            commit_message: invalid_request.commit_message.clone(),
            required_trailer: "Co-authored-by: Codex <noreply@openai.com>".into(),
        };
        let (invalid_request_json, invalid_request_digest) =
            crate::delivery_runtime::canonical_delivery_payload(&invalid_payload).unwrap();
        let invalid_operation =
            OperationId::parse(format!("repo-commit-{}", invalid_mailbox_request.digest)).unwrap();
        let invalid_intent = crate::store::EffectIntent {
            project_id: project.clone(),
            subject_type: "ticket_run".into(),
            subject_id: ticket.to_string(),
            operation_id: invalid_operation.to_string(),
            logical_key: format!(
                "repository.commit:{worker_id}:{}",
                invalid_mailbox_request.digest
            ),
            kind: "commit_worker_manifest".into(),
            request_json: invalid_request_json,
            request_digest: invalid_request_digest,
            expected_revision: Some(current.revision),
        };
        worker
            .store
            .enqueue_effect(restarted_generation, &invalid_intent)
            .unwrap();
        let gh_executable = root.path().join("gh-fixture");
        std::fs::write(&gh_executable, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&gh_executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let delivery_effects = crate::delivery_runtime::RepositoryDeliveryEffects::new(
            crate::delivery_runtime::RepositoryDeliveryEffectConfig {
                state_root: delivery_state.clone(),
                git: git_options,
                inherited_environment: BTreeMap::new(),
                environment_binding: crate::host_jobs::HostJobEnvironmentBinding {
                    snapshot_id: Digest::parse("e".repeat(64)).unwrap(),
                    policy_digest: Digest::parse("f".repeat(64)).unwrap(),
                },
                gh_executable,
                gh_environment: BTreeMap::new(),
                timeout: Duration::from_secs(5),
                configuration_digest: configuration_digest.clone(),
                repositories: BTreeMap::from([(repository.clone(), repository_config)]),
                project_repositories: BTreeMap::from([(
                    project.clone(),
                    std::collections::BTreeSet::from([repository.clone()]),
                )]),
                max_hook_attempts: 3,
            },
            std::sync::Arc::new(std::sync::Mutex::new(
                crate::host_jobs::HostJobPool::new(2, 2).unwrap(),
            )),
        )
        .unwrap();
        let commit_handler =
            delivery_effects.commit_worker_manifest_handler(worker.artifacts.clone());
        let limits = crate::effects::EffectLimits {
            max_attempts: 10,
            max_age: Duration::from_secs(900),
            retry_base: Duration::from_secs(1),
            retry_max: Duration::from_secs(10),
        };
        worker
            .store
            .connection
            .execute(
                "UPDATE projects SET desired_lifecycle='stopped' WHERE project_id=?1",
                [project.as_str()],
            )
            .unwrap();
        let stopped_project_tick = crate::effects::EffectDispatcher::tick(
            &mut worker.store,
            restarted_generation,
            crate::store::now_unix().unwrap() + 2,
            &[&commit_handler],
            limits,
        )
        .unwrap();
        assert!(matches!(
            stopped_project_tick,
            crate::effects::DispatchTick::WaitingForReconciliation { .. }
        ));
        worker
            .store
            .connection
            .execute(
                "UPDATE projects SET desired_lifecycle='running' WHERE project_id=?1",
                [project.as_str()],
            )
            .unwrap();
        worker
            .store
            .connection
            .execute(
                "UPDATE ticket_runs SET revision=?2 WHERE ticket_run_id=?1",
                rusqlite::params![ticket.as_str(), current.revision + 1],
            )
            .unwrap();
        let stale_revision_tick = crate::effects::EffectDispatcher::tick(
            &mut worker.store,
            restarted_generation,
            crate::store::now_unix().unwrap() + 4,
            &[&commit_handler],
            limits,
        )
        .unwrap();
        assert!(matches!(
            stale_revision_tick,
            crate::effects::DispatchTick::WaitingForReconciliation { .. }
        ));
        worker
            .store
            .connection
            .execute(
                "UPDATE ticket_runs SET revision=?2 WHERE ticket_run_id=?1",
                rusqlite::params![ticket.as_str(), current.revision],
            )
            .unwrap();
        worker.store.connection.execute(
            "INSERT INTO agent_runs(agent_run_id,project_id,config_source,config_revision,config_digest,role_session_id,logical_owner,finite_turn,launch_operation_id,state,controller_generation) SELECT 'fixture-newer-worker',project_id,config_source,config_revision,config_digest,role_session_id,'fixture-newer-worker',finite_turn,launch_operation_id||'-newer','running',?2 FROM agent_runs WHERE agent_run_id=?1",
            rusqlite::params![worker_id.as_str(), restarted_generation],
        ).unwrap();
        let newer_worker_tick = crate::effects::EffectDispatcher::tick(
            &mut worker.store,
            restarted_generation,
            crate::store::now_unix().unwrap() + 8,
            &[&commit_handler],
            limits,
        )
        .unwrap();
        assert!(
            matches!(
                newer_worker_tick,
                crate::effects::DispatchTick::WaitingForReconciliation { .. }
            ),
            "unexpected newer-worker reconciliation: {newer_worker_tick:?}"
        );
        worker
            .store
            .connection
            .execute(
                "DELETE FROM agent_runs WHERE agent_run_id='fixture-newer-worker'",
                [],
            )
            .unwrap();
        let tick = crate::effects::EffectDispatcher::tick(
            &mut worker.store,
            restarted_generation,
            crate::store::now_unix().unwrap() + 30,
            &[&commit_handler],
            limits,
        )
        .unwrap();
        assert_eq!(
            tick,
            crate::effects::DispatchTick::Completed {
                operation_id: invalid_intent.operation_id.clone()
            }
        );
        let (invalid_status, invalid_receipt): (String, String) = worker
            .store
            .connection
            .query_row(
                "SELECT status,receipt_json FROM effects WHERE operation_id=?1",
                [invalid_intent.operation_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(invalid_status, "failed");
        let invalid_receipt: serde_json::Value =
            crate::protocol::parse_unique(invalid_receipt.as_bytes()).unwrap();
        assert_eq!(invalid_receipt["schema_version"], 1);
        assert_eq!(invalid_receipt["outcome"], "rejected");
        assert!(
            invalid_receipt["reason"]
                .as_str()
                .unwrap()
                .contains("manifest paths")
        );
        let observed_head = delivery.observe_local_head_at(&worktree).unwrap();
        assert_eq!(observed_head, base);
        assert_eq!(
            run_git(&[
                "-C",
                worktree.to_str().unwrap(),
                "diff",
                "--cached",
                "--quiet",
                "HEAD"
            ]),
            ""
        );
        let unchanged_rejection_status =
            run_git(&["-C", worktree.to_str().unwrap(), "status", "--porcelain"]);
        assert!(unchanged_rejection_status.contains("README.md"));
        assert!(unchanged_rejection_status.contains("correction-test-receipt.txt"));
        std::fs::remove_file(&unknown_receipt).unwrap();
        std::fs::write(worktree.join("README.md"), "base\n").unwrap();
        let remaining_status = run_git(&[
            "-C",
            worktree.to_str().unwrap(),
            "status",
            "--porcelain",
            "--untracked-files=all",
        ]);
        assert_eq!(
            remaining_status,
            format!(
                "?? .rex-artifacts/sha256/{}/{}",
                &source_references[0].artifact_id.as_str()[..2],
                source_references[0].artifact_id
            )
        );
        let effect_count_before_invalid_replay: u64 = worker
            .store
            .connection
            .query_row("SELECT COUNT(*) FROM effects", [], |row| row.get(0))
            .unwrap();
        let profiles = BTreeMap::from([(
            prior_authority.profile_id.clone(),
            serde_json::from_value(serde_json::json!({
                "adapter":"codex", "command":["fixture"], "commit_mode":"host"
            }))
            .unwrap(),
        )]);
        assert!(
            worker
                .store
                .process_one_agent_mailbox_request(
                    restarted_generation,
                    worker_id.as_str(),
                    crate::store::now_unix().unwrap(),
                    &worker.artifacts,
                    &profiles,
                )
                .unwrap()
        );
        let invalid_mailbox_receipt: crate::protocol::ResponseEnvelope<serde_json::Value> =
            crate::protocol::parse_unique(
                &mailbox
                    .read_receipt(invalid_request_id, crate::mailbox::unix_time_now().unwrap())
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
        let invalid_error = invalid_mailbox_receipt.error.unwrap();
        assert!(!invalid_error.retryable);
        assert!(invalid_error.message.contains("manifest paths"));
        let effect_count_after_invalid_replay: u64 = worker
            .store
            .connection
            .query_row("SELECT COUNT(*) FROM effects", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            effect_count_after_invalid_replay,
            effect_count_before_invalid_replay
        );

        // The Worker already has a typed terminal rejection for this exact commit intent. If
        // its response disappeared after expiry, the registered Store may republish that exact
        // outcome without re-running the host effect.
        let invalid_receipt_path = mailbox_directory.join(format!(
            "receipt-{:x}.json",
            Sha256::digest(invalid_request_id.as_bytes())
        ));
        let accepted_rejection_bytes = std::fs::read(&invalid_receipt_path).unwrap();
        std::fs::remove_file(&invalid_receipt_path).unwrap();
        let expired_mailbox_time =
            i64::try_from(stored_reservation.mailbox_expires_at_unix + 1).unwrap();
        let changed_adapter_profiles = BTreeMap::from([(
            prior_authority.profile_id.clone(),
            serde_json::from_value(serde_json::json!({
                "adapter":"claude_code", "command":["fixture"], "commit_mode":"host"
            }))
            .unwrap(),
        )]);
        assert!(
            worker
                .store
                .process_one_agent_mailbox_request(
                    restarted_generation,
                    worker_id.as_str(),
                    expired_mailbox_time,
                    &worker.artifacts,
                    &changed_adapter_profiles,
                )
                .unwrap()
        );
        let replayed_rejection: crate::protocol::ResponseEnvelope<serde_json::Value> =
            crate::protocol::parse_unique(
                &mailbox
                    .read_receipt(invalid_request_id, crate::mailbox::unix_time_now().unwrap())
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(
            std::fs::read(&invalid_receipt_path).unwrap(),
            accepted_rejection_bytes
        );
        assert_eq!(replayed_rejection.request_id.as_str(), invalid_request_id);
        assert!(!replayed_rejection.error.unwrap().retryable);
        assert!(
            !worker
                .store
                .process_one_agent_mailbox_request(
                    restarted_generation,
                    worker_id.as_str(),
                    expired_mailbox_time,
                    &worker.artifacts,
                    &profiles,
                )
                .unwrap()
        );
        let effect_count_after_rejection_replay: u64 = worker
            .store
            .connection
            .query_row("SELECT COUNT(*) FROM effects", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            effect_count_after_rejection_replay,
            effect_count_before_invalid_replay
        );

        std::fs::write(worktree.join("README.md"), manifested_bytes).unwrap();
        let prepared_request_id = "terminal-restart-registered-artifact-prepare";
        let prepared_request = crate::agent_api::RepositoryCommitRequest {
            schema_version: 1,
            message_id: prepared_request_id.into(),
            worktree_id: stored_assignment.node_id.to_string(),
            expected_head: base.into(),
            manifest: manifest_artifact.reference.clone(),
            manifest_digest: manifest_artifact.reference.digest.clone(),
            commit_message:
                "docs: prepare with registered host artifact\n\nCo-authored-by: Codex <noreply@openai.com>".into(),
        };
        let prepared_envelope = crate::protocol::RequestEnvelope {
            schema_version: crate::protocol::SCHEMA_VERSION,
            request_id: crate::protocol::RequestId::new(prepared_request_id).unwrap(),
            operation_id: Some(prior_authority.operation_id.clone()),
            method: crate::protocol::MethodName::new("repository.commit").unwrap(),
            project_id: Some(project.clone()),
            run_id: Some(worker_id.to_string()),
            attempt: Some(prior_authority.attempt),
            run_epoch: Some(prior_authority.run_epoch),
            expected_subject_revision: Some(current.revision),
            role: Some(Role::Worker),
            request_type: None,
            params: serde_json::to_value(&prepared_request).unwrap(),
        };
        mailbox
            .queue(
                prepared_request_id,
                &serde_json::to_vec(&prepared_envelope).unwrap(),
                crate::mailbox::unix_time_now().unwrap(),
            )
            .unwrap();
        let prepared_mailbox_request = mailbox
            .pending(crate::mailbox::unix_time_now().unwrap())
            .unwrap()
            .into_iter()
            .find(|request| request.request_id == prepared_request_id)
            .unwrap();
        let prepared_payload = crate::delivery_runtime::CommitWorkerManifestEffectPayload {
            schema_version: 1,
            agent_run_id: worker_id.clone(),
            project_id: project.clone(),
            message_id: prepared_request.message_id.clone(),
            configuration_digest: prior_authority.config_digest.clone(),
            ticket_revision: current.revision,
            ticket_namespace: TicketNamespace::parse("fixture").unwrap(),
            ticket_id: TicketId::parse("T-1").unwrap(),
            ticket_run_id: ticket.clone(),
            work_node_id: stored_assignment.node_id.clone(),
            repository_id: repository.clone(),
            worktree_path: worktree.clone(),
            branch: branch.clone(),
            prepare_operation_id: prepare_operation.clone(),
            expected_base_sha: base.into(),
            expected_head: prepared_request.expected_head.clone(),
            manifest_artifact: prepared_request.manifest.clone(),
            manifest_digest: prepared_request.manifest_digest.clone(),
            manifest: manifest.clone(),
            commit_message: prepared_request.commit_message.clone(),
            required_trailer: "Co-authored-by: Codex <noreply@openai.com>".into(),
        };
        let (prepared_request_json, prepared_request_digest) =
            crate::delivery_runtime::canonical_delivery_payload(&prepared_payload).unwrap();
        let prepared_operation =
            OperationId::parse(format!("repo-commit-{}", prepared_mailbox_request.digest)).unwrap();
        let prepared_intent = crate::store::EffectIntent {
            project_id: project.clone(),
            subject_type: "ticket_run".into(),
            subject_id: ticket.to_string(),
            operation_id: prepared_operation.to_string(),
            logical_key: format!(
                "repository.commit:{worker_id}:{}",
                prepared_mailbox_request.digest
            ),
            kind: "commit_worker_manifest".into(),
            request_json: prepared_request_json,
            request_digest: prepared_request_digest,
            expected_revision: Some(current.revision),
        };
        worker
            .store
            .enqueue_effect(restarted_generation, &prepared_intent)
            .unwrap();
        // Stop at the signing boundary: no unsigned fallback. The HostCommitter fixture tests
        // the successful signed/post-hook path; this dispatcher test proves verified evidence
        // reaches its durable prepared intent through the real registry and effect handler.
        run_git(&[
            "-C",
            worktree.to_str().unwrap(),
            "config",
            "gpg.program",
            "/usr/bin/false",
        ]);
        let prepared_tick = crate::effects::EffectDispatcher::tick(
            &mut worker.store,
            restarted_generation,
            crate::store::now_unix().unwrap() + 40,
            &[&commit_handler],
            limits,
        )
        .unwrap();
        assert!(matches!(
            prepared_tick,
            crate::effects::DispatchTick::WaitingForReconciliation { .. }
        ));
        let prepared_effect_status: String = worker
            .store
            .connection
            .query_row(
                "SELECT status FROM effects WHERE operation_id=?1",
                [prepared_intent.operation_id.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(prepared_effect_status, "uncertain");
        let prepared_host_intent_path = delivery_state
            .join("host-commits")
            .join(prepared_operation.as_str())
            .join("intent.json");
        let prepared_host_intent: crate::host_commit::HostCommitIntent =
            crate::protocol::parse_unique(&std::fs::read(&prepared_host_intent_path).unwrap())
                .unwrap();
        assert_eq!(prepared_host_intent.host_artifact_allowlist.len(), 1);
        assert_eq!(
            prepared_host_intent.host_artifact_allowlist[0].artifact_id,
            source_references[0].artifact_id
        );
        assert_eq!(delivery.observe_local_head_at(&worktree).unwrap(), base);
        let prepared_mailbox_receipt = crate::protocol::ResponseEnvelope {
            schema_version: crate::protocol::SCHEMA_VERSION,
            request_id: crate::protocol::RequestId::new(prepared_request_id).unwrap(),
            result: None::<serde_json::Value>,
            error: Some(crate::protocol::ProtocolError {
                code: crate::protocol::ErrorCode::Unavailable,
                message: "fixture stopped after verifying durable host-commit preparation".into(),
                retryable: true,
                retry_after_ms: None,
                details: BTreeMap::new(),
            }),
            extensions: BTreeMap::new(),
        };
        mailbox
            .publish_receipt(
                prepared_request_id,
                &serde_json::to_vec(&prepared_mailbox_receipt).unwrap(),
                crate::mailbox::unix_time_now().unwrap(),
            )
            .unwrap();
        worker
            .store
            .test_connection()
            .execute(
                "DELETE FROM effects WHERE operation_id=?1",
                [prepared_intent.operation_id.as_str()],
            )
            .unwrap();
        std::fs::remove_dir_all(
            delivery_state
                .join("host-commits")
                .join(prepared_operation.as_str()),
        )
        .unwrap();

        let terminal_request_id = "terminal-restart-replay-scope-check";
        let request = crate::agent_api::RepositoryCommitRequest {
            schema_version: 1,
            message_id: terminal_request_id.into(),
            worktree_id: stored_assignment.node_id.to_string(),
            expected_head: base.into(),
            manifest: manifest_artifact.reference.clone(),
            manifest_digest: manifest_artifact.reference.digest.clone(),
            commit_message:
                "docs: fixture retained commit\n\nCo-authored-by: Codex <noreply@openai.com>".into(),
        };
        let changed_paths = crate::agent_api::RepositoryManifestRequest {
            schema_version: 1,
            worktree_id: request.worktree_id.clone(),
            entries: vec![crate::agent_api::ManifestPath {
                path: "README.md".into(),
                operation: crate::agent_api::ManifestOperation::Capture,
            }],
        };
        std::fs::write(
            mailbox_directory.join("changed-paths.json"),
            serde_json::to_vec(&changed_paths).unwrap(),
        )
        .unwrap();
        std::fs::write(
            mailbox_directory.join("change-reference.json"),
            serde_json::to_vec(&request.manifest).unwrap(),
        )
        .unwrap();
        std::fs::write(
            mailbox_directory.join("commit-message.txt"),
            &request.commit_message,
        )
        .unwrap();
        let terminal_envelope = crate::protocol::RequestEnvelope {
            schema_version: crate::protocol::SCHEMA_VERSION,
            request_id: crate::protocol::RequestId::new(terminal_request_id).unwrap(),
            operation_id: Some(prior_authority.operation_id.clone()),
            method: crate::protocol::MethodName::new("repository.commit").unwrap(),
            project_id: Some(project.clone()),
            run_id: Some(worker_id.to_string()),
            attempt: Some(prior_authority.attempt),
            run_epoch: Some(prior_authority.run_epoch),
            expected_subject_revision: Some(current.revision),
            role: Some(Role::Worker),
            request_type: None,
            params: serde_json::to_value(&request).unwrap(),
        };
        mailbox
            .queue(
                terminal_request_id,
                &serde_json::to_vec(&terminal_envelope).unwrap(),
                crate::mailbox::unix_time_now().unwrap(),
            )
            .unwrap();

        // Fixture-seed an already accepted and succeeded host effect through the public journal
        // API. The mailbox replay below must match this exact intent and durable receipt.
        let mailbox_request = mailbox
            .pending(crate::mailbox::unix_time_now().unwrap())
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        let manifest_digest = request.manifest_digest.clone();
        let payload = crate::delivery_runtime::CommitWorkerManifestEffectPayload {
            schema_version: 1,
            agent_run_id: worker_id.clone(),
            project_id: project.clone(),
            message_id: request.message_id.clone(),
            configuration_digest: prior_authority.config_digest.clone(),
            ticket_revision: current.revision,
            ticket_namespace: TicketNamespace::parse("fixture").unwrap(),
            ticket_id: TicketId::parse("T-1").unwrap(),
            ticket_run_id: ticket.clone(),
            work_node_id: stored_assignment.node_id.clone(),
            repository_id: repository.clone(),
            worktree_path: worktree.clone(),
            branch: branch.clone(),
            prepare_operation_id: prepare_operation.clone(),
            expected_base_sha: base.into(),
            expected_head: request.expected_head.clone(),
            manifest_artifact: request.manifest.clone(),
            manifest_digest: manifest_digest.clone(),
            manifest,
            commit_message: request.commit_message.clone(),
            required_trailer: "Co-authored-by: Codex <noreply@openai.com>".into(),
        };
        let (request_json, request_digest) =
            crate::delivery_runtime::canonical_delivery_payload(&payload).unwrap();
        let effect_operation =
            OperationId::parse(format!("repo-commit-{}", mailbox_request.digest)).unwrap();
        let intent = crate::store::EffectIntent {
            project_id: project.clone(),
            subject_type: "ticket_run".into(),
            subject_id: ticket.to_string(),
            operation_id: effect_operation.to_string(),
            logical_key: format!("repository.commit:{worker_id}:{}", mailbox_request.digest),
            kind: "commit_worker_manifest".into(),
            request_json,
            request_digest,
            expected_revision: Some(current.revision),
        };
        worker
            .store
            .enqueue_effect(restarted_generation, &intent)
            .unwrap();
        let claim = worker
            .store
            .claim_next_due_effect(
                restarted_generation,
                i64::MAX,
                std::slice::from_ref(&intent.kind),
            )
            .unwrap()
            .unwrap();
        assert_eq!(claim.intent, intent);
        let effect_receipt = crate::delivery_runtime::CommitWorkerManifestEffectReceipt {
            schema_version: 1,
            agent_run_id: worker_id.clone(),
            message_id: request.message_id.clone(),
            ticket_run_id: ticket.clone(),
            work_node_id: stored_assignment.node_id.clone(),
            repository_id: repository.clone(),
            base_sha: base.into(),
            manifest_artifact: request.manifest.clone(),
            commit: crate::host_commit::HostCommitReceipt {
                operation_id: effect_operation,
                repository_id: repository.clone(),
                expected_head: request.expected_head.clone(),
                observed_head: "d".repeat(40),
                tree: "e".repeat(40),
                manifest_digest,
                signature_verified: true,
                hooks_completed: true,
                index_synchronized: true,
                index_sync_conflict: false,
            },
        };
        let effect_receipt_json = serde_json::to_string(&effect_receipt).unwrap();
        worker
            .store
            .finish_effect(
                intent.operation_id.as_str(),
                restarted_generation,
                crate::store::EffectOutcome::Succeeded,
                Some(&effect_receipt_json),
            )
            .unwrap();
        let mut committed_recovery = authorization.clone();
        committed_recovery.prior_host_commit_operation_id =
            Some(crate::domain::ids::OperationId::parse(intent.operation_id.clone()).unwrap());
        committed_recovery.prior_host_commit_receipt_digest =
            Some(digest(effect_receipt_json.as_bytes()).unwrap());
        committed_recovery.expected_head = effect_receipt.commit.observed_head.clone();
        committed_recovery
            .prior_artifact_refs
            .push(effect_receipt.manifest_artifact.clone());
        let recovered_prepared = worker
            .store
            .prepared_worker_launch(
                restarted_generation,
                plan_record.accepted_revision,
                &node_id,
                &prepared_receipt,
                &project_config,
                &configuration_digest,
            )
            .unwrap()
            .expect("recovery must retain the genuine accepted prepared token");
        let validated_plan = plan_record
            .validate_for(&project_config, &configuration_digest)
            .unwrap();
        let node = validated_plan
            .nodes_in_execution_order
            .iter()
            .find(|node| node.id == node_id)
            .unwrap();
        let assignment = crate::runtime_services::prepared_worker_assignment_for_test(
            &worker.store,
            restarted_generation,
            &plan_record,
            &validated_plan,
            &recovered_prepared,
            node,
            Some(&committed_recovery),
        )
        .unwrap();
        let assignment_path = worker._temp.path().join("recovered-worker-assignment.json");
        std::fs::write(&assignment_path, assignment).unwrap();
        let assignment: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&assignment_path).unwrap()).unwrap();
        assert_eq!(
            assignment["prepared_worktree"]["expected_head"],
            effect_receipt.commit.observed_head
        );
        assert_eq!(assignment["prepared_worktree"]["verification_only"], false);
        assert_eq!(
            assignment["retained_host_commit"]["commit"]["operation_id"],
            intent.operation_id
        );
        assert_eq!(
            assignment["retained_host_commit"]["manifest_artifact"]["path"],
            effect_receipt.manifest_artifact.path
        );
        assert_eq!(
            assignment["implementation_ready_identity"]["repository"],
            repository.as_str()
        );
        assert_eq!(
            assignment["implementation_ready_identity"]["change_reference_worktree_id"],
            node_id.as_str()
        );
        let prepared_path =
            std::path::PathBuf::from(assignment["prepared_worktree"]["path"].as_str().unwrap());
        let physical_id = prepared_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap();
        let physical_claim: crate::engine::orchestration::ChangeReference =
            serde_json::from_value(serde_json::json!({
                "repository":repository,
                "worktree_id":physical_id,
                "commit_mode":"host",
                "base_commit":base,
                "previous_head":base,
                "branch_head":effect_receipt.commit.observed_head,
                "commit_shas":[effect_receipt.commit.observed_head],
                "host_commit_operation_id":intent.operation_id
            }))
            .unwrap();
        assert_eq!(
            crate::engine::orchestration::change_reference_for_assignment(
                std::slice::from_ref(&physical_claim),
                &repository,
                &node_id,
                &prepared_path,
            )
            .unwrap(),
            &physical_claim
        );

        let mut advanced_no_commit_recovery = authorization.clone();
        advanced_no_commit_recovery.expected_head = "f".repeat(40);
        let advanced_assignment = crate::runtime_services::prepared_worker_assignment_for_test(
            &worker.store,
            restarted_generation,
            &plan_record,
            &validated_plan,
            &recovered_prepared,
            node,
            Some(&advanced_no_commit_recovery),
        )
        .unwrap();
        let advanced_assignment: serde_json::Value =
            serde_json::from_str(&advanced_assignment).unwrap();
        assert_eq!(
            advanced_assignment["prepared_worktree"]["expected_head"],
            advanced_no_commit_recovery.expected_head
        );
        assert_eq!(
            advanced_assignment["prepared_worktree"]["verification_only"],
            false
        );
        assert!(advanced_assignment["retained_host_commit"].is_null());

        let effect_count_before: u64 = worker
            .store
            .connection
            .query_row("SELECT COUNT(*) FROM effects", [], |row| row.get(0))
            .unwrap();
        let mut foreign_receipt = effect_receipt.clone();
        foreign_receipt.agent_run_id = AgentRunId::parse("foreign-worker").unwrap();
        let foreign_receipt_json = serde_json::to_string(&foreign_receipt).unwrap();
        worker
            .store
            .connection
            .execute(
                "UPDATE effects SET receipt_json=?2 WHERE operation_id=?1",
                rusqlite::params![intent.operation_id, foreign_receipt_json],
            )
            .unwrap();
        let rejected = worker.store.process_one_agent_mailbox_request(
            restarted_generation,
            worker_id.as_str(),
            crate::store::now_unix().unwrap(),
            &worker.artifacts,
            &profiles,
        );
        assert!(
            rejected
                .unwrap_err()
                .to_string()
                .contains("durable receipt does not match its exact accepted intent")
        );
        let expired_mismatched_receipt = worker.store.process_one_agent_mailbox_request(
            restarted_generation,
            worker_id.as_str(),
            i64::try_from(stored_reservation.mailbox_expires_at_unix + 1).unwrap(),
            &worker.artifacts,
            &profiles,
        );
        assert!(
            expired_mismatched_receipt
                .unwrap_err()
                .to_string()
                .contains("durable receipt does not match its exact accepted intent")
        );
        assert!(
            mailbox
                .read_receipt(
                    terminal_request_id,
                    crate::mailbox::unix_time_now().unwrap()
                )
                .unwrap()
                .is_none()
        );
        worker
            .store
            .connection
            .execute(
                "UPDATE effects SET receipt_json=?2 WHERE operation_id=?1",
                rusqlite::params![intent.operation_id, effect_receipt_json],
            )
            .unwrap();
        let replay_result = worker.store.process_one_agent_mailbox_request(
            restarted_generation,
            worker_id.as_str(),
            i64::try_from(stored_reservation.mailbox_expires_at_unix + 1).unwrap(),
            &worker.artifacts,
            &BTreeMap::new(),
        );
        assert!(replay_result.unwrap());
        let receipt_bytes = mailbox
            .read_receipt(
                terminal_request_id,
                crate::mailbox::unix_time_now().unwrap(),
            )
            .unwrap()
            .unwrap();
        let response: crate::protocol::ResponseEnvelope<serde_json::Value> =
            crate::protocol::parse_unique(&receipt_bytes).unwrap();
        let response: crate::agent_api::RepositoryCommitReceipt =
            serde_json::from_value(response.result.unwrap()).unwrap();
        assert_eq!(response.message_id, terminal_request_id);
        assert_eq!(response.commit_operation_id.as_str(), intent.operation_id);
        assert_eq!(response.manifest_artifact, request.manifest);
        assert_eq!(response.commit, effect_receipt.commit);
        let effect_count_after: u64 = worker
            .store
            .connection
            .query_row("SELECT COUNT(*) FROM effects", [], |row| row.get(0))
            .unwrap();
        assert_eq!(effect_count_after, effect_count_before);

        let state: String = worker
            .store
            .connection
            .query_row(
                "SELECT state FROM agent_runs WHERE agent_run_id=?1",
                [worker_id.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(state, "completed");
        assert!(
            worker
                .store
                .agent_mailbox_registration(worker_id.as_str())
                .unwrap()
                .is_some()
        );
        let mailbox_registration = worker
            .store
            .agent_mailbox_registration(worker_id.as_str())
            .unwrap()
            .unwrap();
        assert_eq!(
            mailbox_registration.expires_at_unix,
            stored_reservation.mailbox_expires_at_unix
        );
        let slot_disposition_before_expiry: String = worker
            .store
            .connection
            .query_row(
                "SELECT disposition FROM execution_slots WHERE owner_id=?1",
                [worker_id.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            mailbox
                .pending(mailbox_registration.expires_at_unix + 1)
                .unwrap_err()
                .contains("expired")
        );
        let mut mailbox_scan = Default::default();
        let emitted_diagnostics = std::cell::RefCell::new(Vec::new());
        let mut emit_diagnostic = |message| emitted_diagnostics.borrow_mut().push(message);
        macro_rules! scan_mailboxes {
            ($now:expr) => {
                assert!(
                    !crate::runtime_services::process_one_registered_agent_request(
                        &mut worker.store,
                        restarted_generation,
                        $now,
                        &worker.artifacts,
                        &profiles,
                        &mut mailbox_scan,
                        &mut emit_diagnostic,
                    )
                    .unwrap()
                );
            };
        }
        assert!(
            !crate::runtime_services::process_one_registered_agent_request(
                &mut worker.store,
                restarted_generation,
                i64::try_from(mailbox_registration.expires_at_unix).unwrap(),
                &worker.artifacts,
                &profiles,
                &mut mailbox_scan,
                &mut emit_diagnostic,
            )
            .unwrap()
        );
        assert!(emitted_diagnostics.borrow().is_empty());

        let unresolved_id = "terminal-restart-expired-unresolved";
        let unresolved_request = crate::protocol::RequestEnvelope {
            schema_version: crate::protocol::SCHEMA_VERSION,
            request_id: crate::protocol::RequestId::new(unresolved_id).unwrap(),
            operation_id: Some(prior_authority.operation_id.clone()),
            method: crate::protocol::MethodName::new("artifact.add").unwrap(),
            project_id: Some(project.clone()),
            run_id: Some(worker_id.to_string()),
            attempt: Some(prior_authority.attempt),
            run_epoch: Some(prior_authority.run_epoch),
            expected_subject_revision: Some(current.revision),
            role: Some(Role::Worker),
            request_type: None,
            params: serde_json::json!({}),
        };
        let unresolved_request_bytes = serde_json::to_vec(&unresolved_request).unwrap();
        mailbox
            .queue(
                unresolved_id,
                &unresolved_request_bytes,
                crate::mailbox::unix_time_now().unwrap(),
            )
            .unwrap();

        let expired_at = i64::try_from(mailbox_registration.expires_at_unix + 1).unwrap();
        worker
            .store
            .connection
            .execute(
                "INSERT INTO agent_runs(agent_run_id,project_id,config_source,config_revision,config_digest,role_session_id,logical_owner,finite_turn,launch_operation_id,state,controller_generation) SELECT ?1,project_id,config_source,config_revision,config_digest,role_session_id,logical_owner,1,?2,'unknown',controller_generation FROM agent_runs WHERE agent_run_id=?3",
                rusqlite::params![
                    "a-expired-budget-fixture",
                    "expired-budget-fixture-operation",
                    worker_id.as_str()
                ],
            )
            .unwrap();
        worker
            .store
            .connection
            .execute(
                "INSERT INTO agent_mailboxes(agent_run_id,canonical_directory,capability_digest,expires_at_unix,max_request_bytes,max_pending_requests) VALUES (?1,?2,?3,?4,?5,?6)",
                rusqlite::params![
                    "a-expired-budget-fixture",
                    root.path().join("not-opened-expired-mailbox").display().to_string(),
                    "a".repeat(64),
                    mailbox_registration.expires_at_unix,
                    mailbox_registration.max_request_bytes as u64,
                    mailbox_registration.max_pending_requests as u64
                ],
            )
            .unwrap();
        assert!(
            !crate::runtime_services::process_one_registered_agent_request(
                &mut worker.store,
                restarted_generation,
                expired_at,
                &worker.artifacts,
                &profiles,
                &mut mailbox_scan,
                &mut emit_diagnostic,
            )
            .unwrap()
        );
        assert!(emitted_diagnostics.borrow().is_empty());
        scan_mailboxes!(expired_at);
        assert_eq!(emitted_diagnostics.borrow().len(), 1);
        let first_diagnostic = emitted_diagnostics.borrow()[0].clone();

        assert!(
            !crate::runtime_services::process_one_registered_agent_request(
                &mut worker.store,
                restarted_generation,
                expired_at,
                &worker.artifacts,
                &profiles,
                &mut mailbox_scan,
                &mut emit_diagnostic,
            )
            .unwrap()
        );
        assert_eq!(emitted_diagnostics.borrow().len(), 1);
        scan_mailboxes!(expired_at);
        assert_eq!(emitted_diagnostics.borrow().len(), 1);

        let changed_inventory = mailbox_directory.join("unexpected-entry");
        std::fs::write(&changed_inventory, b"visible change").unwrap();
        assert!(
            !crate::runtime_services::process_one_registered_agent_request(
                &mut worker.store,
                restarted_generation,
                expired_at,
                &worker.artifacts,
                &profiles,
                &mut mailbox_scan,
                &mut emit_diagnostic,
            )
            .unwrap()
        );
        assert_eq!(emitted_diagnostics.borrow().len(), 1);
        scan_mailboxes!(expired_at);
        assert_eq!(emitted_diagnostics.borrow().len(), 2);
        assert_ne!(emitted_diagnostics.borrow()[1], first_diagnostic);

        std::fs::remove_file(&changed_inventory).unwrap();
        let unresolved_request_path = mailbox_directory.join(format!(
            "request-{:x}.json",
            Sha256::digest(unresolved_id.as_bytes())
        ));
        std::fs::remove_file(&unresolved_request_path).unwrap();
        assert!(
            !crate::runtime_services::process_one_registered_agent_request(
                &mut worker.store,
                restarted_generation,
                expired_at,
                &worker.artifacts,
                &profiles,
                &mut mailbox_scan,
                &mut emit_diagnostic,
            )
            .unwrap()
        );
        assert_eq!(emitted_diagnostics.borrow().len(), 2);
        scan_mailboxes!(expired_at);
        assert_eq!(emitted_diagnostics.borrow().len(), 2);

        std::fs::write(&unresolved_request_path, &unresolved_request_bytes).unwrap();
        scan_mailboxes!(expired_at);
        assert_eq!(emitted_diagnostics.borrow().len(), 2);
        assert!(
            !crate::runtime_services::process_one_registered_agent_request(
                &mut worker.store,
                restarted_generation,
                expired_at,
                &worker.artifacts,
                &profiles,
                &mut mailbox_scan,
                &mut emit_diagnostic,
            )
            .unwrap()
        );
        assert_eq!(emitted_diagnostics.borrow().len(), 3);
        assert_eq!(emitted_diagnostics.borrow()[2], first_diagnostic);
        assert!(
            !mailbox_directory
                .join(format!(
                    "receipt-{:x}.json",
                    Sha256::digest(unresolved_id.as_bytes())
                ))
                .exists()
        );
        assert_eq!(
            worker
                .store
                .connection
                .query_row("SELECT COUNT(*) FROM effects", [], |row| row
                    .get::<_, u64>(0))
                .unwrap(),
            effect_count_after
        );
        assert_eq!(
            worker
                .store
                .connection
                .query_row(
                    "SELECT disposition FROM execution_slots WHERE owner_id=?1",
                    [worker_id.as_str()],
                    |row| row.get::<_, String>(0)
                )
                .unwrap(),
            slot_disposition_before_expiry
        );

        // A new valid request without a previously accepted effect is not an expired replay
        // authority. Leave it visible and preserve the execution slot for human reconciliation.
        std::fs::remove_file(&unresolved_request_path).unwrap();
        let missing_effect_id = "terminal-restart-missing-accepted-effect";
        let mut missing_effect_request = request.clone();
        missing_effect_request.message_id = missing_effect_id.into();
        let mut missing_effect_envelope = terminal_envelope.clone();
        missing_effect_envelope.request_id =
            crate::protocol::RequestId::new(missing_effect_id).unwrap();
        missing_effect_envelope.params = serde_json::to_value(&missing_effect_request).unwrap();
        mailbox
            .queue(
                missing_effect_id,
                &serde_json::to_vec(&missing_effect_envelope).unwrap(),
                crate::mailbox::unix_time_now().unwrap(),
            )
            .unwrap();
        let effects_before_missing_replay: u64 = worker
            .store
            .connection
            .query_row("SELECT COUNT(*) FROM effects", [], |row| row.get(0))
            .unwrap();
        let missing_effect = worker
            .store
            .process_one_agent_mailbox_request(
                restarted_generation,
                worker_id.as_str(),
                expired_at,
                &worker.artifacts,
                &profiles,
            )
            .unwrap_err()
            .to_string();
        assert!(missing_effect.contains("no previously accepted terminal outcome"));
        assert!(
            !mailbox_directory
                .join(format!(
                    "receipt-{:x}.json",
                    Sha256::digest(missing_effect_id.as_bytes())
                ))
                .exists()
        );
        assert_eq!(
            worker
                .store
                .connection
                .query_row("SELECT COUNT(*) FROM effects", [], |row| row
                    .get::<_, u64>(0))
                .unwrap(),
            effects_before_missing_replay
        );
        assert_eq!(
            worker
                .store
                .connection
                .query_row(
                    "SELECT disposition FROM execution_slots WHERE owner_id=?1",
                    [worker_id.as_str()],
                    |row| row.get::<_, String>(0)
                )
                .unwrap(),
            slot_disposition_before_expiry
        );
        let descriptor_path = mailbox_directory.join("descriptor.json");
        let descriptor_bytes = std::fs::read(&descriptor_path).unwrap();
        let mut stale_descriptor: serde_json::Value =
            crate::protocol::parse_unique(&descriptor_bytes).unwrap();
        stale_descriptor["expires_at_unix"] =
            serde_json::json!(stored_reservation.mailbox_expires_at_unix + 2);
        std::fs::write(
            &descriptor_path,
            serde_json::to_vec(&stale_descriptor).unwrap(),
        )
        .unwrap();
        let stale_registration = worker.store.process_one_agent_mailbox_request(
            restarted_generation,
            worker_id.as_str(),
            expired_at,
            &worker.artifacts,
            &profiles,
        );
        assert!(
            stale_registration
                .unwrap_err()
                .to_string()
                .contains("registered mailbox descriptor digest")
        );
        assert!(
            !mailbox_directory
                .join(format!(
                    "receipt-{:x}.json",
                    Sha256::digest(missing_effect_id.as_bytes())
                ))
                .exists()
        );
        std::fs::write(&descriptor_path, descriptor_bytes).unwrap();
    }

    #[test]
    fn verification_source_replays_real_terminal_and_registered_test_receipt() {
        use crate::domain::ids::{OperationId, RepositoryId};
        use crate::engine::orchestration::{AgentAssertion, RoleOutputKind};

        let head = "2".repeat(40);
        let payload = serde_json::json!({
            "work_node_id":"node-a",
            "repository":"repo-a",
            "publication_operation_id":"publish-worker-1",
            "published_head":head,
            "test_receipt_artifact_ids":[]
        });
        let mut result = host_validation_fixture::host_validated_result(
            Role::Worker,
            RoleResultMessage {
                schema_version: 1,
                message_id: "verification-ready-result".into(),
                kind: RoleOutputKind::VerificationReady,
                assertion: AgentAssertion::Succeeded,
                result_digest: Some(digest(&serde_json::to_vec(&payload).unwrap()).unwrap()),
                structured_result: payload,
                artifact_refs: Vec::new(),
            },
        )
        .unwrap();
        let binding = &result.ingested.validated.binding;
        let ticket_run_id = binding.ticket_run_id.clone().unwrap();
        let source_revision = binding.ticket_revision.unwrap().0;
        let test_receipts = result
            .ingested
            .verified_artifacts
            .iter()
            .map(|artifact| artifact.reference().clone())
            .collect::<Vec<_>>();
        assert_eq!(test_receipts.len(), 1);
        let verification = crate::store::accepted_plans::AcceptedWorkerVerification {
            review_revision: source_revision + 1,
            source_revision,
            source_evidence_id: result.ingested.receipt.evidence_id().to_owned(),
            source_agent_run_id: binding.agent_run_id.clone(),
            source_result_digest: result.ingested.validated.result_digest.clone(),
            publication_revision: source_revision - 1,
            publication_operation_id: OperationId::parse("publish-worker-1").unwrap(),
            published_head: crate::engine::orchestration::GitCommitId::parse(head).unwrap(),
            work_node_id: crate::engine::orchestration::WorkNodeId::parse("node-a").unwrap(),
            repository_id: RepositoryId::parse("repo-a").unwrap(),
            test_receipt_artifacts: test_receipts.clone(),
        };
        let replayed = result
            .store
            .validated_worker_verification_source(
                &result.artifacts,
                result.owner_generation,
                &binding.project_id,
                &ticket_run_id,
                &verification,
            )
            .unwrap();
        assert_eq!(
            replayed.receipt.evidence_id(),
            verification.source_evidence_id
        );
        assert_eq!(
            replayed.verified_artifacts[0].reference(),
            &test_receipts[0]
        );

        let mut stale_receipt = verification;
        stale_receipt.test_receipt_artifacts[0].digest = digest(b"changed receipt").unwrap();
        assert!(
            result
                .store
                .validated_worker_verification_source(
                    &result.artifacts,
                    result.owner_generation,
                    &binding.project_id,
                    &ticket_run_id,
                    &stale_receipt,
                )
                .is_err()
        );
    }
}
fn accepted_correction_publication_head(
    store: &ConfigStore,
    owner_generation: u64,
    binding: &RoleResultBinding,
    authorization: &crate::engine::orchestration::WorkerRecoveryAuthorization,
    assignment: &crate::launch::WorkerLaunchBinding,
    current_revision: u64,
) -> Result<Option<String>, String> {
    let project_id = &binding.project_id;
    let ticket_run_id = &authorization.ticket_run_id;
    let node_id = &authorization.work_node_id;
    let repository_id = &assignment.repository_id;
    let configuration_digest = &binding.config_digest;
    let plan_digest = &authorization.accepted_plan_digest;
    let expected_base_sha = assignment.base_sha.as_str();
    let transition: Option<String> = store
        .connection
        .query_row(
            "SELECT evidence_json FROM transitions WHERE entity_type='ticket_run' AND entity_id=?1 AND project_id=?2 AND new_revision=?3",
            params![ticket_run_id.as_str(), project_id.as_str(), current_revision],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    let Some(transition) = transition else {
        return Ok(None);
    };
    let evidence: serde_json::Value = crate::protocol::parse_unique(transition.as_bytes())?;
    if evidence["kind"] != "review_assessment" || evidence["transition"] != "corrections_remain" {
        return Ok(None);
    }
    let snapshot = store.accepted_implementation_publication_snapshot(
        owner_generation,
        project_id,
        ticket_run_id,
        current_revision,
    )?;
    if snapshot.accepted_plan().plan_digest != *plan_digest
        || snapshot.accepted_plan().configuration_digest != *configuration_digest
    {
        return Err(
            "correction publication belongs to a different accepted plan or configuration".into(),
        );
    }
    let mut heads = Vec::new();
    for publication in snapshot.publication_receipts() {
        let request: crate::delivery_runtime::PublishImplementationEffectPayload =
            crate::protocol::parse_unique(publication.intent().request_json.as_bytes())?;
        if request.work_node_id != *node_id {
            continue;
        }
        let receipt: crate::delivery_runtime::ImplementationPublicationReceipt =
            crate::protocol::parse_unique(publication.receipt_json().as_bytes())?;
        if request.ticket_run_id != *ticket_run_id
            || request.repository_id != *repository_id
            || request.configuration_digest != *configuration_digest
            || request.expected_base_sha != expected_base_sha
            || receipt.ticket_run_id != *ticket_run_id
            || receipt.work_node_id != *node_id
            || receipt.repository_id != *repository_id
            || receipt.configuration_digest != *configuration_digest
            || receipt.source_revision != request.source_revision
        {
            return Err("correction publication does not match its accepted Worker node".into());
        }
        heads.push(receipt.commit.head().to_owned());
    }
    if heads.len() != 1 {
        return Err("correction publication must cover the Worker node exactly once".into());
    }
    Ok(heads.pop())
}

#[allow(clippy::items_after_test_module)]
impl ConfigStore {
    pub fn merge_observation_deferral(
        &self,
        source_evidence_id: &str,
    ) -> Result<Option<MergeObservationDeferralRecord>, String> {
        let stored: Option<(String, u32, i64, String, String)> = self.connection
            .query_row(
                "SELECT binding_digest,attempt_count,next_attempt_at_unix,state,failure_code FROM merge_observation_deferrals WHERE source_evidence_id=?1",
                [source_evidence_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        stored
            .map(|(digest, attempt_count, next, state, failure_code)| {
                let state = match state.as_str() {
                    "waiting" => MergeObservationDeferralState::Waiting {
                        attempt_count,
                        next_attempt_at_unix: next,
                    },
                    "exhausted" => MergeObservationDeferralState::Exhausted { attempt_count },
                    "permanently_invalid" => MergeObservationDeferralState::PermanentlyInvalid,
                    _ => return Err("stored MergeAssessment observation state is invalid".into()),
                };
                Ok(MergeObservationDeferralRecord {
                    source_evidence_id: source_evidence_id.to_owned(),
                    binding_digest: Digest::parse(digest)?,
                    attempt_count,
                    next_attempt_at_unix: next,
                    state,
                    failure_code,
                })
            })
            .transpose()
    }

    pub(crate) fn invalidate_merge_observation_deferral(
        &mut self,
        owner_generation: u64,
        source_evidence_id: &str,
        now_unix: i64,
    ) -> Result<bool, String> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        super::validate_active_generation(&tx, owner_generation)?;
        let changed = tx
            .execute(
                "UPDATE merge_observation_deferrals SET state='permanently_invalid',failure_code='permanent_invalid',next_attempt_at_unix=?2,updated_at_unix=?2 WHERE source_evidence_id=?1 AND state='waiting'",
                params![source_evidence_id, now_unix],
            )
            .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(changed == 1)
    }

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

    /// Revalidate the exact Worker result that produced a host-validated publication for one
    /// accepted work node. The forge receipt supplies `published_head`; neither a Worker claim
    /// nor a raw artifact row is sufficient to identify the source.
    pub fn validated_worker_publication_source_for_node(
        &mut self,
        artifact_store: &crate::artifacts::ArtifactStore,
        owner_generation: u64,
        project_id: &ProjectId,
        ticket_run_id: &TicketRunId,
        publication: &crate::store::SucceededEffectReceipt,
    ) -> Result<IngestedAgentResult, String> {
        let intent = publication.intent();
        let request: crate::delivery_runtime::PublishImplementationEffectPayload =
            crate::protocol::parse_unique(intent.request_json.as_bytes())?;
        let receipt: crate::delivery_runtime::ImplementationPublicationReceipt =
            crate::protocol::parse_unique(publication.receipt_json().as_bytes())?;
        if intent.kind != "publish_implementation"
            || intent.project_id != *project_id
            || intent.subject_type != "ticket_run"
            || intent.subject_id != ticket_run_id.as_str()
            || request.ticket_run_id != *ticket_run_id
            || receipt.ticket_run_id != *ticket_run_id
            || request.work_node_id != receipt.work_node_id
            || request.repository_id != receipt.repository_id
            || request.configuration_digest != receipt.configuration_digest
            || request.source_revision != receipt.source_revision
        {
            return Err("Worker source publication differs from its exact scoped receipt".into());
        }
        if let crate::delivery_runtime::WorkerDeliveryCommit::HostBaseRefresh {
            prior_publication_operation_id,
            prior_publication_receipt_digest,
            ..
        } = &request.commit
        {
            let prior = self
                .succeeded_effect_receipt(prior_publication_operation_id.as_str())?
                .ok_or("base refresh source has no succeeded prior Worker publication")?;
            if digest(prior.receipt_json().as_bytes())? != *prior_publication_receipt_digest {
                return Err("base refresh source prior publication receipt digest differs".into());
            }
            let prior_request: crate::delivery_runtime::PublishImplementationEffectPayload =
                crate::protocol::parse_unique(prior.intent().request_json.as_bytes())?;
            if prior.intent().kind != "publish_implementation"
                || prior.intent().project_id != *project_id
                || prior.intent().subject_type != "ticket_run"
                || prior.intent().subject_id != ticket_run_id.as_str()
                || prior_request.ticket_run_id != request.ticket_run_id
                || prior_request.work_node_id != request.work_node_id
                || prior_request.repository_id != request.repository_id
                || prior_request.configuration_digest != request.configuration_digest
                || prior_request.source_revision >= request.source_revision
            {
                return Err(
                    "base refresh source prior publication differs from its Worker assignment"
                        .into(),
                );
            }
            return self.validated_worker_publication_source_for_node(
                artifact_store,
                owner_generation,
                project_id,
                ticket_run_id,
                &prior,
            );
        }
        let node_id = &request.work_node_id;
        let repository_id = &request.repository_id;
        let publication_revision = request.source_revision;
        let publication_operation_id = intent.operation_id.as_str();
        let published_head = receipt.commit.head();
        if !matches!(published_head.len(), 40 | 64)
            || !published_head.bytes().all(|byte| byte.is_ascii_hexdigit())
            || publication_revision == 0
        {
            return Err(
                "publication source requires a valid commit SHA and positive revision".into(),
            );
        }
        let expected_session = format!("ticket:{ticket_run_id}:worker:{node_id}");
        let transition_json: String = self.connection.query_row(
            "SELECT evidence_json FROM transitions WHERE entity_type='ticket_run' AND entity_id=?1 AND project_id=?2 AND new_revision=?3",
            params![ticket_run_id.as_str(), project_id.as_str(), publication_revision],
            |row| row.get(0),
        ).map_err(|error| error.to_string())?;
        let transition: serde_json::Value =
            crate::protocol::parse_unique(transition_json.as_bytes())?;
        let transition_source_revision = transition["source_revision"]
            .as_u64()
            .ok_or("Worker publication transition lacks its source revision")?;
        let evidence_id = transition["evidence_id"]
            .as_str()
            .ok_or("Worker publication transition lacks its source evidence ID")?;
        let transition_result_digest: Digest =
            serde_json::from_value(transition["result_digest"].clone()).map_err(|error| {
                format!("Worker publication transition result digest is invalid: {error}")
            })?;
        if transition["kind"] != "worker_implementation_ready"
            || transition["transition"] != "worker_implementation_ready"
            || transition["publication_operation_id"].as_str() != Some(publication_operation_id)
            || transition["accepted_revision"].as_u64() != Some(publication_revision)
            || transition_source_revision.checked_add(1) != Some(publication_revision)
        {
            return Err(
                "publication does not bind to the exact host-accepted Worker result transition"
                    .into(),
            );
        }
        let raw_run_id: String = self.connection.query_row(
            "SELECT agent_run_id FROM agent_result_evidence WHERE evidence_id=?1 AND project_id=?2 AND ticket_run_id=?3 AND role='worker' AND outcome='completed'",
            params![evidence_id, project_id.as_str(), ticket_run_id.as_str()],
            |row| row.get(0),
        ).map_err(|error| error.to_string())?;
        let expected_evidence_id = evidence_id.to_owned();
        let agent_run_id = AgentRunId::parse(raw_run_id)?;
        let authority = self
            .agent_launch_authority(&agent_run_id)?
            .ok_or("Worker evidence has no immutable launch authority")?;
        if authority.project_id != *project_id
            || authority.ticket_run_id.as_ref() != Some(ticket_run_id)
            || authority.ticket_revision != Some(Revision(transition_source_revision))
            || authority.role != Role::Worker
            || authority.role_session_id != expected_session
        {
            return Err("published Worker result differs from the exact launch authority".into());
        }
        let reservation = self
            .agent_launch_reservation_for_run(&agent_run_id)?
            .ok_or("published Worker result has no immutable launch reservation")?;
        reservation.validate()?;
        let assignment = reservation
            .worker_assignment
            .as_ref()
            .filter(|assignment| {
                reservation.project_id == *project_id
                    && reservation.ticket_run_id.as_ref() == Some(ticket_run_id)
                    && reservation.role == Role::Worker
                    && assignment.ticket_revision == transition_source_revision
                    && assignment.configuration_digest == authority.config_digest
                    && assignment.node_id == *node_id
                    && assignment.repository_id == *repository_id
            })
            .ok_or("published Worker result has no matching immutable prepared assignment")?;
        let terminal = verify_agent_terminal(self, owner_generation, &agent_run_id)?;
        let structured = terminal
            .result
            .structured_result
            .clone()
            .ok_or("completed Worker terminal has no structured result")?;
        let message: RoleResultMessage = serde_json::from_value(structured)
            .map_err(|error| format!("Worker terminal role result is invalid: {error}"))?;
        let validated = message.clone().bind(binding_for(&authority)?)?;
        if validated.kind != crate::engine::orchestration::RoleOutputKind::ImplementationReady
            || validated.result_digest != transition_result_digest
        {
            return Err(
                "Worker terminal result differs from the accepted publication transition".into(),
            );
        }
        let crate::engine::orchestration::RoleResultPayload::ImplementationReady(payload) =
            validated.typed_payload
        else {
            return Err("ImplementationReady result has an incompatible typed payload".into());
        };
        let node_change = crate::engine::orchestration::change_reference_for_assignment(
            &payload.change_references,
            repository_id,
            node_id,
            &assignment.worktree_path,
        )?;
        if payload.change_references.len() != 1
            || node_change.branch_head.as_str() != published_head
        {
            return Err(
                "Worker result does not uniquely match the published repository head".into(),
            );
        }
        let ingested =
            ingest_agent_result(self, artifact_store, owner_generation, &terminal, message)?;
        if ingested.receipt.evidence_id() != expected_evidence_id {
            return Err(
                "revalidated Worker result resolved to different immutable evidence".into(),
            );
        }
        Ok(ingested)
    }

    /// Revalidate the exact Worker result bound to a durable verification transition. This
    /// reloads the terminal, launch authority, result bytes, and registered artifacts through
    /// the ordinary ingestion path instead of treating transition JSON as artifact authority.
    pub fn validated_worker_verification_source(
        &mut self,
        artifact_store: &crate::artifacts::ArtifactStore,
        owner_generation: u64,
        project_id: &ProjectId,
        ticket_run_id: &TicketRunId,
        verification: &crate::store::accepted_plans::AcceptedWorkerVerification,
    ) -> Result<IngestedAgentResult, String> {
        let (agent_run_raw, result_json, stored_digest): (String, String, String) = self
            .connection
            .query_row(
                "SELECT agent_run_id,result_json,result_digest FROM agent_result_evidence WHERE evidence_id=?1 AND project_id=?2 AND ticket_run_id=?3 AND role='worker' AND outcome='completed'",
                params![
                    verification.source_evidence_id,
                    project_id.as_str(),
                    ticket_run_id.as_str()
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(|error| format!("Worker verification source evidence is missing: {error}"))?;
        let agent_run_id = AgentRunId::parse(agent_run_raw)?;
        let submission: RoleResultSubmission =
            crate::protocol::parse_unique(result_json.as_bytes())?;
        if submission.binding.project_id != *project_id
            || submission.binding.ticket_run_id.as_ref() != Some(ticket_run_id)
            || submission.binding.ticket_revision != Some(Revision(verification.source_revision))
            || submission.binding.role != Role::Worker
            || submission.binding.agent_run_id != agent_run_id
            || submission.result_digest != verification.source_result_digest
            || stored_digest != verification.source_result_digest.as_str()
        {
            return Err(
                "Worker verification source differs from its immutable evidence binding".into(),
            );
        }
        let expected_session = format!(
            "ticket:{ticket_run_id}:worker:{}",
            verification.work_node_id
        );
        let authority = self
            .agent_launch_authority(&agent_run_id)?
            .ok_or("Worker verification source has no immutable launch authority")?;
        if authority.project_id != *project_id
            || authority.ticket_run_id.as_ref() != Some(ticket_run_id)
            || authority.ticket_revision != Some(Revision(verification.source_revision))
            || authority.role != Role::Worker
            || authority.role_session_id != expected_session
            || binding_for(&authority)? != submission.binding
        {
            return Err("Worker verification source no longer matches its launch authority".into());
        }
        let terminal = verify_agent_terminal(self, owner_generation, &agent_run_id)?;
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
            ingest_agent_result(self, artifact_store, owner_generation, &terminal, message)?;
        if replayed.receipt.evidence_id() != verification.source_evidence_id {
            return Err("Worker verification source replay resolved to different evidence".into());
        }
        let crate::engine::orchestration::RoleResultPayload::VerificationReady(claim) =
            &replayed.validated.typed_payload
        else {
            return Err("Worker verification source has another result kind".into());
        };
        let actual_receipts = replayed
            .verified_artifacts
            .iter()
            .filter(|artifact| {
                artifact.reference().kind
                    == crate::engine::orchestration::RoleArtifactKind::TestReceipt
            })
            .map(|artifact| artifact.reference().clone())
            .collect::<Vec<_>>();
        let actual_ids = actual_receipts
            .iter()
            .map(|artifact| artifact.artifact_id.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        let claimed_ids = claim
            .test_receipt_artifact_ids
            .iter()
            .map(|artifact_id| artifact_id.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        if claim.work_node_id != verification.work_node_id
            || claim.repository != verification.repository_id
            || claim.publication_operation_id != verification.publication_operation_id
            || claim.published_head != verification.published_head
            || actual_receipts.len() != claim.test_receipt_artifact_ids.len()
            || actual_ids != claimed_ids
            || actual_receipts != verification.test_receipt_artifacts
        {
            return Err("Worker verification result differs from its accepted publication or TestReceipt set".into());
        }
        Ok(replayed)
    }

    pub fn ingest_next_spooled_agent_result(
        &mut self,
        artifact_store: &crate::artifacts::ArtifactStore,
        owner_generation: u64,
        candidate_limit: usize,
    ) -> Result<Option<IngestedAgentResult>, String> {
        ingest_next_spooled_agent_result(self, artifact_store, owner_generation, candidate_limit)
    }

    pub fn ingest_next_spooled_agent_result_at(
        &mut self,
        artifact_store: &crate::artifacts::ArtifactStore,
        owner_generation: u64,
        now_unix: i64,
        candidate_limit: usize,
    ) -> Result<Option<IngestedAgentResult>, String> {
        ingest_next_spooled_agent_result_at(
            self,
            artifact_store,
            owner_generation,
            now_unix,
            candidate_limit,
        )
    }

    pub fn ingest_shutdown_spooled_agent_result_at(
        &mut self,
        artifact_store: &crate::artifacts::ArtifactStore,
        owner_generation: u64,
        now_unix: i64,
        candidate_limit: usize,
    ) -> Result<Option<IngestedAgentResult>, String> {
        ingest_shutdown_spooled_agent_result_at(
            self,
            artifact_store,
            owner_generation,
            now_unix,
            candidate_limit,
        )
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

    pub fn runnable_validated_agent_results(
        &mut self,
        artifact_store: &crate::artifacts::ArtifactStore,
        owner_generation: u64,
        now_unix: i64,
        limit: usize,
    ) -> Result<Vec<IngestedAgentResult>, String> {
        pending_agent_results_at(self, artifact_store, owner_generation, now_unix, limit)
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

    pub fn record_merge_observation_failure(
        &mut self,
        owner_generation: u64,
        result: &IngestedAgentResult,
        publication_set_digest: &Digest,
        now_unix: i64,
        failure: MergeObservationFailureCode,
    ) -> Result<MergeObservationDeferralState, String> {
        record_merge_observation_failure(
            self,
            owner_generation,
            result,
            publication_set_digest,
            now_unix,
            failure,
        )
    }

    pub fn validated_agent_result_ack(
        &self,
        evidence_id: &str,
    ) -> Result<Option<(u64, String)>, String> {
        self.connection
            .query_row(
                "SELECT reducer_revision,disposition FROM agent_result_reducer_ack WHERE evidence_id=?1",
                [evidence_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())
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
        pub start: StartRequestEnvelope,
        pub result: AgentTurnResult,
    }

    pub(crate) struct InPlaceValidatedResultFixture {
        pub artifacts: crate::artifacts::ArtifactStore,
        pub ingested: IngestedAgentResult,
    }

    pub(crate) struct InPlaceTerminalFixture {
        pub(crate) artifacts: crate::artifacts::ArtifactStore,
        pub(crate) terminal: VerifiedAgentTerminal,
        pub(crate) message: RoleResultMessage,
        pub(crate) start: StartRequestEnvelope,
        pub(crate) result: AgentTurnResult,
    }

    /// Builds real host terminal and result evidence around test-seeded running launch records.
    /// Qualification, published package, process absence, terminal, and result validators are
    /// production paths; only the earlier controller/Rex prerecords are seeded in the test DB.
    pub(crate) fn host_validated_result(
        role: Role,
        message: RoleResultMessage,
    ) -> Result<TestValidatedResultFixture, String> {
        host_validated_result_with_agent_run_id(role, message, None)
    }

    pub(crate) fn host_validated_result_with_config(
        role: Role,
        message: RoleResultMessage,
        config: crate::config::Config,
    ) -> Result<TestValidatedResultFixture, String> {
        let mut fixture = host_validated_result_setup(role, message, None, Some(config))?;
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

    pub(crate) fn host_validated_result_with_agent_run_id(
        role: Role,
        message: RoleResultMessage,
        agent_run_id: Option<AgentRunId>,
    ) -> Result<TestValidatedResultFixture, String> {
        let mut fixture = host_validated_result_setup(role, message, agent_run_id, None)?;
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
        let fixture = host_validated_result_setup(role, message, None, None)?;
        Ok(TestTerminalResultFixture {
            _temp: fixture.temp,
            store: fixture.store,
            artifacts: fixture.artifacts,
            owner_generation: fixture.owner_generation,
            terminal: fixture.terminal,
            start: fixture.start,
            result: fixture.result,
        })
    }

    struct HostValidatedResultSetup {
        temp: tempfile::TempDir,
        store: ConfigStore,
        owner_generation: u64,
        artifacts: crate::artifacts::ArtifactStore,
        terminal: VerifiedAgentTerminal,
        message: RoleResultMessage,
        start: StartRequestEnvelope,
        result: AgentTurnResult,
    }

    fn host_validated_result_setup(
        role: Role,
        message: RoleResultMessage,
        agent_run_id_override: Option<AgentRunId>,
        config_override: Option<crate::config::Config>,
    ) -> Result<HostValidatedResultSetup, String> {
        let temp = tempfile::tempdir().map_err(|error| error.to_string())?;
        let root = std::fs::canonicalize(temp.path()).map_err(|error| error.to_string())?;
        let mut store = ConfigStore::open_test(&root)?;
        let snapshot = if let Some(config) = config_override {
            let fixture_config = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("examples/fixture/config.toml");
            let mut snapshot = crate::config::load(&fixture_config)?;
            let source = snapshot
                .source_files
                .iter_mut()
                .find(|source| {
                    matches!(source.kind, SourceKind::File)
                        && std::path::Path::new(&source.path) == fixture_config
                })
                .ok_or("fixture config source is missing")?;
            source.contents = toml::to_string(&config).map_err(|error| error.to_string())?;
            source.bytes = source.contents.len() as u64;
            source.sha256 = digest(source.contents.as_bytes())?;
            snapshot.config = config;
            snapshot.digest = Digest::parse(crate::config::digest_manifest(
                &snapshot.config,
                &snapshot.profiles,
                &snapshot.source_files,
            )?)?;
            snapshot
        } else {
            AppliedConfig {
                config: serde_json::from_value(serde_json::json!({"schema_version":1,"adapters":{"tickets":{"kind":"command","command":["test"]}},"projects":{}})).map_err(|error| error.to_string())?,
                profiles: std::collections::BTreeMap::new(),
                source_root: root.display().to_string(),
                source_files: vec![SourceFile { kind: SourceKind::File, path: root.join("config.toml").display().to_string(), canonical_path: root.join("config.toml").display().to_string(), sha256: digest(b"config")?, bytes: 6, contents: "fixture".into() }],
                digest: Digest::parse("a".repeat(64))?,
            }
        };
        let config_digest = snapshot.digest.to_string();
        let applied = store.apply_snapshot("fixture", &snapshot, ExpectedRevision::Bootstrap)?;
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
            Role::MergeDecision => ("assessing", "in_progress", 1_u64),
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
                agent_run_id_override,
            )?
        };
        Ok(HostValidatedResultSetup {
            temp,
            store,
            owner_generation,
            artifacts: evidence.artifacts,
            terminal: evidence.terminal,
            message: evidence.message,
            start: evidence.start,
            result: evidence.result,
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
        host_validated_result_in_with_agent_run_id(
            store,
            root,
            owner_generation,
            project_id,
            ticket_run_id,
            role,
            message,
            AgentRunId::parse("fixture-agent-run")?,
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "Test fixtures bind explicit launch and result identities"
    )]
    pub(crate) fn host_validated_result_in_with_agent_run_id(
        store: &mut ConfigStore,
        root: &std::path::Path,
        owner_generation: u64,
        project_id: ProjectId,
        ticket_run_id: TicketRunId,
        role: Role,
        message: RoleResultMessage,
        agent_run_id: AgentRunId,
    ) -> Result<InPlaceValidatedResultFixture, String> {
        host_validated_result_in_with_wake_inputs(
            store,
            root,
            owner_generation,
            project_id,
            ticket_run_id,
            role,
            message,
            agent_run_id,
            Vec::new(),
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "Test fixtures bind explicit launch and result identities"
    )]
    pub(crate) fn host_validated_result_in_with_wake_inputs(
        store: &mut ConfigStore,
        root: &std::path::Path,
        owner_generation: u64,
        project_id: ProjectId,
        ticket_run_id: TicketRunId,
        role: Role,
        message: RoleResultMessage,
        agent_run_id: AgentRunId,
        wake_inputs: Vec<crate::agent_api::AgentWakeItem>,
    ) -> Result<InPlaceValidatedResultFixture, String> {
        host_validated_result_in_with_wake_inputs_and_parent(
            store,
            root,
            owner_generation,
            project_id,
            ticket_run_id,
            role,
            message,
            agent_run_id,
            wake_inputs,
            None,
            None,
        )
    }

    /// Builds and ingests a host-validated Supervisor result bound to its durable wake inputs.
    pub(crate) fn host_validated_supervisor_result_in_with_wake_inputs(
        store: &mut ConfigStore,
        root: &std::path::Path,
        owner_generation: u64,
        project_id: ProjectId,
        message: RoleResultMessage,
        agent_run_id: AgentRunId,
        wake_inputs: Vec<crate::agent_api::AgentWakeItem>,
    ) -> Result<InPlaceValidatedResultFixture, String> {
        let prepared = host_validated_result_inner(
            store,
            root,
            owner_generation,
            project_id,
            None,
            Role::Supervisor,
            message,
            Some(agent_run_id),
            wake_inputs,
            None,
            None,
            None,
        )
        .map_err(|error| format!("host validated Supervisor fixture setup: {error}"))?;
        let ingested = store
            .store_validated_agent_result(
                &prepared.artifacts,
                owner_generation,
                &prepared.terminal,
                prepared.message,
            )
            .map_err(|error| format!("host validated Supervisor result ingestion: {error}"))?;
        Ok(InPlaceValidatedResultFixture {
            artifacts: prepared.artifacts,
            ingested,
        })
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "Test fixture binds explicit wake and Coordinator parent identities"
    )]
    pub(crate) fn host_validated_result_in_with_wake_inputs_and_parent(
        store: &mut ConfigStore,
        root: &std::path::Path,
        owner_generation: u64,
        project_id: ProjectId,
        ticket_run_id: TicketRunId,
        role: Role,
        message: RoleResultMessage,
        agent_run_id: AgentRunId,
        wake_inputs: Vec<crate::agent_api::AgentWakeItem>,
        parent_run_id: Option<AgentRunId>,
        instruction_digest: Option<Digest>,
    ) -> Result<InPlaceValidatedResultFixture, String> {
        let prepared = host_validated_result_inner(
            store,
            root,
            owner_generation,
            project_id,
            Some(ticket_run_id),
            role,
            message,
            Some(agent_run_id),
            wake_inputs,
            None,
            parent_run_id,
            instruction_digest,
        )
        .map_err(|error| format!("host validated result fixture setup: {error}"))?;
        let ingested = store
            .store_validated_agent_result(
                &prepared.artifacts,
                owner_generation,
                &prepared.terminal,
                prepared.message,
            )
            .map_err(|error| format!("host validated result ingestion: {error}"))?;
        Ok(InPlaceValidatedResultFixture {
            artifacts: prepared.artifacts,
            ingested,
        })
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "Fixture supplies exact launch and recovery wake lineage for a crash-cut test"
    )]
    pub(crate) fn host_validated_terminal_in_with_wake_inputs_and_parent(
        store: &mut ConfigStore,
        root: &std::path::Path,
        owner_generation: u64,
        project_id: ProjectId,
        ticket_run_id: TicketRunId,
        role: Role,
        message: RoleResultMessage,
        agent_run_id: AgentRunId,
        wake_inputs: Vec<crate::agent_api::AgentWakeItem>,
        parent_run_id: Option<AgentRunId>,
        instruction_digest: Option<Digest>,
    ) -> Result<InPlaceTerminalFixture, String> {
        host_validated_result_inner(
            store,
            root,
            owner_generation,
            project_id,
            Some(ticket_run_id),
            role,
            message,
            Some(agent_run_id),
            wake_inputs,
            None,
            parent_run_id,
            instruction_digest,
        )
        .map_err(|error| format!("host terminal fixture setup: {error}"))
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "Fixture binds a Worker terminal to its accepted node and Coordinator"
    )]
    pub(crate) fn host_validated_worker_terminal_in(
        store: &mut ConfigStore,
        root: &std::path::Path,
        owner_generation: u64,
        project_id: ProjectId,
        ticket_run_id: TicketRunId,
        message: RoleResultMessage,
        agent_run_id: AgentRunId,
        worker_node_id: &str,
        coordinator_run_id: AgentRunId,
    ) -> Result<InPlaceTerminalFixture, String> {
        host_validated_result_inner(
            store,
            root,
            owner_generation,
            project_id,
            Some(ticket_run_id),
            Role::Worker,
            message,
            Some(agent_run_id),
            Vec::new(),
            Some(worker_node_id),
            Some(coordinator_run_id),
            None,
        )
        .map_err(|error| format!("host Worker terminal fixture setup: {error}"))
    }

    pub(crate) fn close_recovery_terminal_for_test(
        store: &mut ConfigStore,
        owner_generation: u64,
        terminal: &VerifiedAgentTerminal,
        reason: &str,
    ) -> Result<(), String> {
        let authority = store
            .agent_launch_authority(terminal.agent_run_id())?
            .ok_or("fixture terminal has no launch authority")?;
        super::reblock_rejected_merge_claim_recovery_terminal(
            store,
            owner_generation,
            terminal,
            &authority,
            reason,
        )
    }

    pub(crate) fn reconcile_pending_terminals_for_test(
        store: &mut ConfigStore,
        artifacts: &crate::artifacts::ArtifactStore,
        owner_generation: u64,
    ) -> Result<Option<IngestedAgentResult>, String> {
        ingest_pending_verified_terminals(store, artifacts, owner_generation, 128)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "Test fixtures bind explicit launch and result identities"
    )]
    fn host_validated_terminal_in(
        store: &mut ConfigStore,
        root: &std::path::Path,
        owner_generation: u64,
        project_id: ProjectId,
        ticket_run_id: TicketRunId,
        role: Role,
        message: RoleResultMessage,
        agent_run_id_override: Option<AgentRunId>,
    ) -> Result<InPlaceTerminalFixture, String> {
        host_validated_result_inner(
            store,
            root,
            owner_generation,
            project_id,
            Some(ticket_run_id),
            role,
            message,
            agent_run_id_override,
            Vec::new(),
            None,
            None,
            None,
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
            None,
            Vec::new(),
            None,
            None,
            None,
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "Test fixtures bind explicit launch and result identities"
    )]
    pub(super) fn host_validated_result_inner(
        store: &mut ConfigStore,
        root: &std::path::Path,
        owner_generation: u64,
        project_id: ProjectId,
        ticket_run_id: Option<TicketRunId>,
        role: Role,
        mut message: RoleResultMessage,
        agent_run_id_override: Option<AgentRunId>,
        wake_inputs: Vec<crate::agent_api::AgentWakeItem>,
        worker_node_id: Option<&str>,
        parent_run_id_override: Option<AgentRunId>,
        instruction_digest_override: Option<Digest>,
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
        let has_run_id_override = agent_run_id_override.is_some();
        let agent_run_id = match agent_run_id_override {
            Some(agent_run_id) => agent_run_id,
            None => AgentRunId::parse(supervisor_suffix.as_ref().map_or_else(
                || "fixture-agent-run".to_owned(),
                |suffix| format!("fixture-agent-{}", &suffix[..16]),
            ))?,
        };
        let mut authority = crate::store::agent_results::tests::test_authority();
        authority.agent_run_id = agent_run_id.clone();
        if has_run_id_override {
            authority.operation_id = OperationId::parse(format!("{agent_run_id}-operation"))?;
        }
        if let Some(suffix) = &supervisor_suffix {
            authority.operation_id = OperationId::parse(format!("fixture-op-{}", &suffix[..16]))?;
        }
        authority.project_id = project_id.clone();
        authority.role = role;
        authority.role_session_id = match role {
            Role::Worker => format!(
                "ticket:{}:worker:{}",
                ticket_run_id
                    .as_ref()
                    .map_or("fixture-ticket-run", TicketRunId::as_str),
                worker_node_id.unwrap_or("node-a")
            ),
            Role::Coordinator => format!(
                "ticket_run:{}:coordinator",
                ticket_run_id
                    .as_ref()
                    .map_or("fixture-ticket-run", TicketRunId::as_str)
            ),
            Role::MergeDecision => format!(
                "ticket_run:{}:merge_decision",
                ticket_run_id
                    .as_ref()
                    .map_or("fixture-ticket-run", TicketRunId::as_str)
            ),
            Role::Supervisor => format!("project:{}:supervisor", project_id.as_str()),
            _ => format!("fixture-{:?}", role).to_lowercase(),
        };
        if let Some(instruction_digest) = instruction_digest_override {
            authority.instruction_digest = instruction_digest;
        }
        let mut wake_snapshot = crate::agent_api::AgentWakeSnapshot {
            schema_version: 1,
            project_id: project_id.clone(),
            role_session_id: authority.role_session_id.clone(),
            agent_run_id: agent_run_id.to_string(),
            digest: Digest::parse("0".repeat(64))?,
            inputs: wake_inputs,
            worker_correction_context: None,
        };
        wake_snapshot.digest = wake_snapshot.content_digest()?;
        authority.wake_snapshot_digest = wake_snapshot.digest.clone();
        let parent_run_id = if let Some(parent_run_id) = parent_run_id_override {
            parent_run_id
        } else {
            AgentRunId::parse(if has_run_id_override {
                format!("{agent_run_id}-parent")
            } else {
                "fixture-parent-run".to_owned()
            })?
        };
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
        let mailbox_limits = crate::mailbox::MailboxLimits::default();
        let mailbox_now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_secs();
        let mailbox_expires_at = mailbox_now.saturating_add(600);
        authority.mailbox_capability_digest =
            Digest::parse(crate::mailbox::MailboxDescriptor::capability_digest(
                agent_run_id.as_str(),
                mailbox_expires_at,
                mailbox_limits,
            )?)?;
        let mailbox = crate::mailbox::MailboxCapability::create(
            agent_run_id.as_str(),
            &authority.control_dir.join("mailbox"),
            mailbox_expires_at,
            mailbox_limits,
        )?;
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
            Role::MergeDecision => "merge_decision-v1.json",
            Role::Postmortem => "postmortem-v1.json",
            _ => {
                return Err(
                    "fixture currently supports Supervisor, Worker, Reviewer, MergeDecision, and Postmortem roles"
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
            "INSERT INTO agent_runs(agent_run_id,project_id,config_source,config_revision,config_digest,role_session_id,role,logical_owner,finite_turn,launch_operation_id,rex_session_id,rex_window_id,rex_block_id,state,controller_generation) VALUES (?1,?2,?3,?4,?5,?6,?7,'fixture-owner',1,?8,?9,?10,?11,'running',?12)",
            rusqlite::params![run_id_str, project_id.as_str(), config_source, config_revision.0, config_digest, authority.role_session_id, role_str, authority.operation_id.as_str(), authority.rex_session_id, authority.rex_window_id, authority.rex_block_id, owner_generation],
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
            let existing_parent: Option<(String, String)> = store
                .connection
                .query_row(
                    "SELECT authority_json,authority_digest FROM agent_launch_authority WHERE agent_run_id=?1 AND project_id=?2",
                    rusqlite::params![parent_run_id_str, project_id.as_str()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(|error| error.to_string())?;
            if let Some((authority_json, authority_digest)) = &existing_parent {
                let existing: crate::launch::AgentLaunchAuthority =
                    crate::protocol::parse_unique(authority_json.as_bytes())?;
                existing.validate()?;
                let completed: bool = store.connection.query_row(
                    "SELECT EXISTS(SELECT 1 FROM agent_result_evidence WHERE agent_run_id=?1 AND project_id=?2 AND role='coordinator' AND outcome='completed')",
                    rusqlite::params![parent_run_id_str, project_id.as_str()],
                    |row| row.get(0),
                ).map_err(|error| error.to_string())?;
                if existing.digest()?.as_str() != authority_digest
                    || existing.role != parent_role
                    || existing.role_session_id
                        != parent_role_session_id.as_deref().unwrap_or_default()
                    || existing.ticket_run_id != ticket_run_id
                    || !completed
                {
                    return Err(
                        "existing fixture parent is not a completed canonical Coordinator".into(),
                    );
                }
            }
            if existing_parent.is_none() {
                let mut parent_authority = authority.clone();
                parent_authority.agent_run_id = parent_run_id.clone();
                parent_authority.role = parent_role;
                parent_authority.role_session_id =
                    parent_role_session_id.clone().unwrap_or_default();
                parent_authority.parent_run_id = None;
                parent_authority.parent_role = None;
                if parent_role == Role::Supervisor {
                    parent_authority.ticket_run_id = None;
                    parent_authority.ticket_revision = None;
                    let existing_view: Option<(String, String, String, String)> = store.connection.query_row(
                    "SELECT view_id,rex_server_identity,rex_session_id,rex_window_id FROM rex_views WHERE project_id=?1 AND view_kind='supervisor' AND lifecycle='active' LIMIT 1",
                    [project_id.as_str()],
                    |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
                ).optional().map_err(|error| error.to_string())?;
                    let (supervisor_view_id, server_identity, session_id, window_id) = if let Some(
                        existing,
                    ) =
                        existing_view
                    {
                        existing
                    } else {
                        let view_id = crate::launch::RexView::derive_id(
                            &project_id,
                            crate::launch::RexViewKind::Supervisor,
                            None,
                            None,
                            mailbox_now,
                        )?;
                        store.connection.execute(
                            "INSERT INTO rex_views(view_id,project_id,view_kind,ticket_namespace,ticket_id,view_epoch,rex_server_identity,rex_session_id,rex_window_id,pinned,lifecycle,created_at_unix,updated_at_unix) VALUES (?1,?2,'supervisor',NULL,NULL,?3,'fixture-rex','fixture-supervisor-session','fixture-supervisor-window',0,'active',?4,?4)",
                            rusqlite::params![view_id.as_str(), project_id.as_str(), mailbox_now, now],
                        ).map_err(|error| error.to_string())?;
                        (
                            view_id.as_str().to_owned(),
                            "fixture-rex".into(),
                            "fixture-supervisor-session".into(),
                            "fixture-supervisor-window".into(),
                        )
                    };
                    parent_authority.rex_view_id = Digest::parse(supervisor_view_id)?;
                    parent_authority.rex_server_identity = server_identity;
                    parent_authority.rex_session_id = session_id;
                    parent_authority.rex_window_id = window_id;
                }
                parent_authority.operation_id = OperationId::parse(if has_run_id_override {
                    format!("{agent_run_id}-parent-op")
                } else {
                    "fixture-parent-operation".to_owned()
                })?;
                parent_authority.rex_block_id = "fixture-parent-block".into();
                parent_authority.descriptor_path = root.join("parent-package.json");
                parent_authority.workspace_path = root.join("parent-workspace");
                parent_authority.control_dir = root.join("parent-control");
                parent_authority.mailbox_capability_digest =
                    Digest::parse(crate::mailbox::MailboxDescriptor::capability_digest(
                        parent_run_id_str,
                        mailbox_expires_at,
                        mailbox_limits,
                    )?)?;
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
                "INSERT INTO agent_runs(agent_run_id,project_id,config_source,config_revision,config_digest,role_session_id,role,logical_owner,finite_turn,launch_operation_id,state,controller_generation) VALUES (?1,?2,?3,?4,?5,?6,?7,'fixture-owner',1,?8,'completed',?9)",
                rusqlite::params![parent_run_id_str, project_id.as_str(), config_source, config_revision.0, config_digest, parent_role_session_id, parent_role_json, parent_authority.operation_id.as_str(), owner_generation],
            ).map_err(|error| error.to_string())?;
                store.connection.execute(
                "INSERT INTO agent_launch_authority(agent_run_id,project_id,role,role_session_id,ticket_run_id,ticket_revision,config_revision,config_digest,attempt,run_epoch,controller_generation,launch_operation_id,rex_view_id,descriptor_digest,runtime_binary_digest,descriptor_path,environment_snapshot_id,profile_id,profile_digest,instruction_digest,result_schema_digest,qualification_receipt_digest,rex_server_identity,rex_session_id,rex_window_id,rex_block_id,workspace_path,control_dir,mailbox_capability_digest,authority_json,authority_digest,created_at_unix) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25,?26,?27,?28,?29,?30,?31,?32)",
            rusqlite::params![parent_authority.agent_run_id.as_str(), parent_authority.project_id.as_str(), parent_role_json, parent_authority.role_session_id, parent_authority.ticket_run_id.as_ref().map(TicketRunId::as_str), parent_authority.ticket_revision.map(|revision| revision.0), parent_authority.config_revision.0, parent_authority.config_digest.as_str(), parent_authority.attempt, parent_authority.run_epoch, parent_authority.controller_generation, parent_authority.operation_id.as_str(), parent_authority.rex_view_id.as_str(), parent_authority.descriptor_digest.as_str(), parent_authority.runtime_binary_digest.as_str(), parent_authority.descriptor_path.display().to_string(), parent_authority.environment_snapshot_id.as_str(), parent_authority.profile_id.as_str(), parent_authority.profile_digest.as_str(), parent_authority.instruction_digest.as_str(), parent_authority.result_schema_digest.as_str(), parent_authority.qualification_receipt_digest.as_str(), parent_authority.rex_server_identity, parent_authority.rex_session_id, parent_authority.rex_window_id, parent_authority.rex_block_id, parent_authority.workspace_path.display().to_string(), parent_authority.control_dir.display().to_string(), parent_authority.mailbox_capability_digest.as_str(), parent_authority_json, parent_authority_digest.as_str(), now],
        ).map_err(|error| error.to_string())?;
            }
        }
        store.connection.execute(
            "INSERT INTO agent_launch_authority(agent_run_id,project_id,role,role_session_id,parent_run_id,parent_role,ticket_run_id,ticket_revision,config_revision,config_digest,attempt,run_epoch,controller_generation,launch_operation_id,rex_view_id,descriptor_digest,runtime_binary_digest,descriptor_path,environment_snapshot_id,profile_id,profile_digest,instruction_digest,result_schema_digest,qualification_receipt_digest,rex_server_identity,rex_session_id,rex_window_id,rex_block_id,workspace_path,control_dir,mailbox_capability_digest,authority_json,authority_digest,created_at_unix) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25,?26,?27,?28,?29,?30,?31,?32,?33,?34)",
            rusqlite::params![run_id_str, project_id.as_str(), role_str, authority.role_session_id, authority.parent_run_id.as_ref().map(AgentRunId::as_str), authority.parent_role.map(|role| serde_json::to_value(role).unwrap().as_str().unwrap().to_owned()), authority.ticket_run_id.as_ref().map(TicketRunId::as_str), authority.ticket_revision.map(|revision| revision.0), authority.config_revision.0, authority.config_digest.as_str(), authority.attempt, authority.run_epoch, owner_generation, authority.operation_id.as_str(), authority.rex_view_id.as_str(), authority.descriptor_digest.as_str(), authority.runtime_binary_digest.as_str(), authority.descriptor_path.display().to_string(), authority.environment_snapshot_id.as_str(), authority.profile_id.as_str(), authority.profile_digest.as_str(), authority.instruction_digest.as_str(), authority.result_schema_digest.as_str(), authority.qualification_receipt_digest.as_str(), authority.rex_server_identity, authority.rex_session_id, authority.rex_window_id, authority.rex_block_id, authority.workspace_path.display().to_string(), authority.control_dir.display().to_string(), authority.mailbox_capability_digest.as_str(), serde_json::to_string(&authority).map_err(|error| error.to_string())?, authority.digest()?.as_str(), now],
        ).map_err(|error| error.to_string())?;
        for wake in &wake_snapshot.inputs {
            let changed = store.connection.execute(
                "UPDATE role_wake_inputs SET lifecycle='assigned',consuming_agent_run_id=?2 WHERE wake_input_id=?1 AND project_id=?3 AND role_session_id=?4 AND lifecycle='pending'",
                rusqlite::params![wake.wake_input_id, run_id_str, project_id.as_str(), authority.role_session_id],
            ).map_err(|error| error.to_string())?;
            if changed != 1 {
                return Err(
                    "fixture launch wake input was not pending for the exact role session".into(),
                );
            }
        }
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
        if role == Role::Supervisor && !wake_snapshot.inputs.is_empty() {
            let reservation = crate::launch::AgentLaunchReservation {
                schema_version: crate::launch::LAUNCH_SCHEMA_VERSION,
                agent_run_id: agent_run_id.clone(),
                project_id: project_id.clone(),
                role,
                role_session_id: authority.role_session_id.clone(),
                parent_run_id: authority.parent_run_id.clone(),
                parent_role: authority.parent_role,
                ticket_run_id: ticket_run_id.clone(),
                ticket_revision: authority.ticket_revision,
                config_revision: authority.config_revision,
                config_digest: authority.config_digest.clone(),
                attempt: authority.attempt,
                run_epoch: authority.run_epoch,
                controller_generation: owner_generation,
                project_epoch,
                operation_id: authority.operation_id.clone(),
                operation_recipe_id: None,
                worker_assignment: None,
                rex_view_id: authority.rex_view_id.clone(),
                runtime_binary_digest: authority.runtime_binary_digest.clone(),
                environment_snapshot_id: authority.environment_snapshot_id.clone(),
                profile_id: authority.profile_id.clone(),
                profile_digest: authority.profile_digest.clone(),
                instruction_digest: authority.instruction_digest.clone(),
                result_schema_digest: authority.result_schema_digest.clone(),
                wake_snapshot: wake_snapshot.clone(),
                qualification_receipt_digest: authority.qualification_receipt_digest.clone(),
                descriptor_path: authority.descriptor_path.clone(),
                workspace_path: authority.workspace_path.clone(),
                control_dir: authority.control_dir.clone(),
                mailbox_directory: authority.control_dir.join("mailbox"),
                mailbox_capability_digest: authority.mailbox_capability_digest.clone(),
                mailbox_expires_at_unix: mailbox_expires_at,
                mailbox_max_request_bytes: mailbox_limits.max_request_bytes as u64,
                mailbox_max_pending_requests: mailbox_limits.max_pending_requests as u32,
                pool: "agent".into(),
                slot_index,
                global_capacity: 1,
                project_capacity: 1,
            };
            if role == Role::Supervisor && !reservation.wake_snapshot.inputs.is_empty() {
                crate::agent_api::publish_wake_snapshot(
                    &authority.control_dir,
                    reservation.wake_snapshot.clone(),
                )?;
                let inbox = crate::agent_api::read_inbox(&authority.control_dir, run_id_str, 0)?;
                if inbox != reservation.wake_snapshot.inputs {
                    return Err(
                        "fixture Agent inbox differs from its immutable wake reservation".into(),
                    );
                }
            }
            let reservation_json = crate::store::canonical_json(&reservation)?;
            let wake_json = crate::store::canonical_json(&wake_snapshot)?;
            store.connection.execute(
            "INSERT INTO agent_wake_context(agent_run_id,snapshot_digest,snapshot_json,created_at_unix) VALUES (?1,?2,?3,?4)",
            rusqlite::params![run_id_str, wake_snapshot.digest.as_str(), wake_json, now],
        ).map_err(|error| error.to_string())?;
            store.connection.execute(
            "INSERT INTO agent_launch_reservations(agent_run_id,project_id,operation_id,controller_generation,project_epoch,reservation_digest,reservation_json,lifecycle,created_at_unix,updated_at_unix) VALUES (?1,?2,?3,?4,?5,?6,?7,'authorized',?8,?8)",
            rusqlite::params![run_id_str, project_id.as_str(), authority.operation_id.as_str(), owner_generation, project_epoch, reservation.digest()?.as_str(), reservation_json, now],
        ).map_err(|error| error.to_string())?;
            store.connection.execute(
            "INSERT INTO agent_mailboxes(agent_run_id,canonical_directory,capability_digest,expires_at_unix,max_request_bytes,max_pending_requests) VALUES (?1,?2,?3,?4,?5,?6)",
                        rusqlite::params![run_id_str, authority.control_dir.join("mailbox").display().to_string(), authority.mailbox_capability_digest.as_str(), mailbox_expires_at, mailbox_limits.max_request_bytes, mailbox_limits.max_pending_requests],
        ).map_err(|error| error.to_string())?;
        }
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
            rex_launch_anchor: None,
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
            let request: crate::engine::orchestration::ArtifactAddRequest =
                serde_json::from_value(serde_json::json!({
                    "schema_version": 1,
                    "message_id": "fixture-postmortem-artifact",
                    "path": source_path,
                    "kind": "postmortem",
                    "artifact_schema_version": 1
                }))
                .map_err(|error| format!("parse public ArtifactAdd request: {error}"))?;
            request.validate()?;
            let envelope = serde_json::json!({
                "schema_version": crate::protocol::SCHEMA_VERSION,
                "request_id": request.message_id,
                "operation_id": authority.operation_id,
                "method": "artifact.add",
                "project_id": authority.project_id,
                "run_id": authority.agent_run_id,
                "attempt": authority.attempt,
                "run_epoch": authority.run_epoch,
                "role": authority.role,
                "params": request,
            });
            mailbox.queue(
                "fixture-postmortem-artifact",
                &serde_json::to_vec(&envelope).map_err(|error| error.to_string())?,
                mailbox_now,
            )?;
            let mailbox_request = mailbox
                .pending(mailbox_now)?
                .into_iter()
                .find(|pending| pending.request_id == "fixture-postmortem-artifact")
                .ok_or("public ArtifactAdd request was not available in the mailbox")?;
            let artifact = store.process_artifact_add(
                owner_generation,
                &authority,
                &artifacts,
                &mailbox,
                &mailbox_request,
                &request,
            )?;
            let receipt_bytes = mailbox
                .read_receipt("fixture-postmortem-artifact", mailbox_now)?
                .ok_or("public ArtifactAdd receipt was not written")?;
            let receipt: serde_json::Value = crate::protocol::parse_unique(&receipt_bytes)?;
            if receipt["result"]["artifact"]
                != serde_json::to_value(artifact.reference()).map_err(|error| error.to_string())?
            {
                return Err(
                    "public ArtifactAdd receipt differs from its registered artifact".into(),
                );
            }
            message.artifact_refs = vec![artifact.reference().clone()];
            message.structured_result["source_references"] =
                serde_json::json!([artifact.reference()]);
            message.result_digest = Some(digest(
                &serde_json::to_vec(&message.structured_result)
                    .map_err(|error| error.to_string())?,
            )?);
        } else if role == Role::MergeDecision
            && message.kind == crate::engine::orchestration::RoleOutputKind::MergeAssessment
        {
            let source_path = "evidence/merge-assessment.md";
            let source_file = authority.workspace_path.join(source_path);
            std::fs::create_dir_all(
                source_file
                    .parent()
                    .ok_or("MergeAssessment evidence path has no parent")?,
            )
            .map_err(|error| error.to_string())?;
            std::fs::write(
                &source_file,
                b"# Merge assessment evidence\n\nHost fixture evidence for the exact accepted publication subject.\n",
            )
            .map_err(|error| error.to_string())?;
            let artifact = artifacts.register(
                &authority.workspace_path,
                &authority.project_id,
                authority.agent_run_id.as_str(),
                role,
                source_path,
                crate::engine::orchestration::RoleArtifactKind::MergeAssessment,
                1,
            )?;
            let reference =
                serde_json::to_value(&artifact.reference).map_err(|error| error.to_string())?;
            let gates = message.structured_result["deterministic_gate_evidence"]
                .as_array_mut()
                .ok_or("MergeAssessment fixture has no deterministic gate list")?;
            for gate in gates {
                gate["evidence_references"] = serde_json::json!([reference]);
            }
            let ratings = message.structured_result["ratings"]
                .as_object_mut()
                .ok_or("MergeAssessment fixture has no risk ratings")?;
            for rating in ratings.values_mut() {
                rating["evidence_references"] = serde_json::json!([reference]);
            }
            message.artifact_refs = vec![artifact.reference.clone()];
            let request_digest = digest(b"fixture MergeAssessment ArtifactAdd request")?;
            crate::store::artifact_registry::persist_registration(
                &mut store.connection,
                owner_generation,
                &authority,
                "fixture-merge-assessment-artifact",
                &request_digest,
                &artifact.reference,
                &artifact.object_path,
            )?;
            message.result_digest = Some(digest(
                &serde_json::to_vec(&message.structured_result)
                    .map_err(|error| error.to_string())?,
            )?);
        } else if role == Role::Worker
            && message.kind == crate::engine::orchestration::RoleOutputKind::VerificationReady
        {
            let source_path = "checks/test-receipt.md";
            let source_file = authority.workspace_path.join(source_path);
            std::fs::create_dir_all(
                source_file
                    .parent()
                    .ok_or("Worker TestReceipt path has no parent")?,
            )
            .map_err(|error| error.to_string())?;
            std::fs::write(
                &source_file,
                b"# Test receipt\n\nAll configured checks passed.\n",
            )
            .map_err(|error| error.to_string())?;
            let artifact = artifacts.register(
                &authority.workspace_path,
                &authority.project_id,
                authority.agent_run_id.as_str(),
                role,
                source_path,
                crate::engine::orchestration::RoleArtifactKind::TestReceipt,
                1,
            )?;
            message.artifact_refs = vec![artifact.reference.clone()];
            message.structured_result["test_receipt_artifact_ids"] =
                serde_json::json!([artifact.reference.artifact_id]);
            let request_digest = digest(b"fixture Worker TestReceipt ArtifactAdd request")?;
            crate::store::artifact_registry::persist_registration(
                &mut store.connection,
                owner_generation,
                &authority,
                "fixture-worker-test-receipt-artifact",
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
            cancellation_cause: None,
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
            start,
            result,
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
    /// Return host-verified, same-node retry opportunities for the Coordinator prompt.
    /// Candidates are informational only; a retry request is revalidated before its wake is saved.
    pub fn worker_recovery_candidates(
        &self,
        owner_generation: u64,
        run: &crate::store::scheduler::ActiveTicketRun,
        plan: &crate::store::accepted_plans::AcceptedWorkPlanRecord,
        project_config: &crate::config::ProjectConfig,
        configuration_digest: &Digest,
    ) -> Result<Vec<crate::engine::orchestration::WorkerRecoveryCandidate>, String> {
        use crate::delivery_runtime::{
            CommitWorkerManifestEffectPayload, CommitWorkerManifestEffectReceipt,
        };
        use crate::engine::orchestration::{
            AgentAssertion, RoleOutputKind, RoleResultPayload, WorkerRecoveryCandidate,
        };
        use crate::engine::reducer::Phase;

        if run.phase != Phase::Implementing
            || plan.ticket_run_id != run.ticket_run_id
            || plan.project_id != run.project_id
        {
            return Ok(Vec::new());
        }
        let validated = plan.validate_for(project_config, configuration_digest)?;
        let ids = {
            let mut statement = self.connection.prepare(
                "SELECT agent_run_id FROM agent_runs WHERE project_id=?1 AND role='worker' AND state='completed' ORDER BY agent_run_id",
            ).map_err(|error| error.to_string())?;
            let rows = statement
                .query_map([run.project_id.as_str()], |row| row.get::<_, String>(0))
                .map_err(|error| error.to_string())?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|error| error.to_string())?
        };
        let mut candidates = Vec::new();
        for raw_id in ids {
            let prior_id = AgentRunId::parse(raw_id)?;
            let Ok(terminal) = verify_agent_terminal(self, owner_generation, &prior_id) else {
                continue;
            };
            let Some(authority) = self.agent_launch_authority(&prior_id)? else {
                continue;
            };
            let Some(ticket) = authority.ticket_run_id.as_ref() else {
                continue;
            };
            let Some(reservation) = self.agent_launch_reservation_for_run(&prior_id)? else {
                continue;
            };
            let Some(assignment) = reservation.worker_assignment.as_ref() else {
                continue;
            };
            if authority.role != Role::Worker
                || authority.project_id != run.project_id
                || ticket != &run.ticket_run_id
                || authority.ticket_revision.map(|revision| revision.0) != Some(run.revision)
                || authority.config_digest != *configuration_digest
                || authority.role_session_id
                    != format!("ticket:{}:worker:{}", run.ticket_run_id, assignment.node_id)
                || assignment.configuration_digest != *configuration_digest
                || assignment.plan_digest != plan.plan_digest
            {
                continue;
            }
            let Some(node) = validated
                .nodes_in_execution_order
                .iter()
                .find(|node| node.id == assignment.node_id && node.role == Role::Worker)
            else {
                continue;
            };
            if node.repository != assignment.repository_id {
                continue;
            }
            let Some(preparation) =
                self.succeeded_effect_receipt(&assignment.prepare_operation_id)?
            else {
                continue;
            };
            let Some(prepared) = self.prepared_worker_launch(
                owner_generation,
                plan.accepted_revision,
                &assignment.node_id,
                &preparation,
                project_config,
                configuration_digest,
            )?
            else {
                continue;
            };
            let derived_assignment = prepared.reservation_binding();
            if (assignment.expected_head.is_some()
                && assignment.expected_head.as_deref() != Some(prepared.expected_head()))
                || {
                    let mut expected_prior = derived_assignment;
                    expected_prior.expected_head = assignment.expected_head.clone();
                    &expected_prior != assignment
                }
            {
                continue;
            }
            let prepared_expected_head = prepared.expected_head().to_owned();
            let active: bool = self.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM agent_runs WHERE role_session_id=?1 AND state IN ('launch_pending','running','unknown'))",
                [&authority.role_session_id], |row| row.get(0),
            ).map_err(|error| error.to_string())?;
            let leased: bool = self.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM execution_slots WHERE owner_kind='agent_run' AND owner_id=?1 AND disposition!='released')",
                [prior_id.as_str()], |row| row.get(0),
            ).map_err(|error| error.to_string())?;
            if active || leased {
                continue;
            }
            let Some(registration) = self.agent_mailbox_registration(prior_id.as_str())? else {
                continue;
            };
            let Ok(mailbox) = crate::mailbox::MailboxCapability::open_registered_for_run(
                prior_id.to_string(),
                Path::new(&registration.canonical_directory),
            ) else {
                continue;
            };
            let now = u64::try_from(super::now_unix()?)
                .map_err(|_| "controller clock is before the Unix epoch")?;
            let Ok(pending_requests) = mailbox.pending(now) else {
                continue;
            };
            // A terminal Worker can still have an unacknowledged repository.commit request if
            // the bounded one-request-per-tick pump had not drained its mailbox.
            if !pending_requests.is_empty() {
                continue;
            }
            let evidence: Option<(String, String)> = self.connection.query_row(
                "SELECT evidence_id,result_json FROM agent_result_evidence WHERE agent_run_id=?1 AND project_id=?2 AND role='worker' AND ticket_run_id=?3 AND outcome='completed' ORDER BY received_at_unix DESC,evidence_id DESC LIMIT 1",
                rusqlite::params![prior_id.as_str(), run.project_id.as_str(), run.ticket_run_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            ).optional().map_err(|error| error.to_string())?;
            let Some((evidence_id, result_json)) = evidence else {
                continue;
            };
            let already_retried: bool = self.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM role_wake_inputs WHERE project_id=?1 AND source_type='worker_recovery_authorization' AND source_id=?2)",
                rusqlite::params![run.project_id.as_str(), evidence_id],
                |row| row.get(0),
            ).map_err(|error| error.to_string())?;
            if already_retried {
                continue;
            }
            let submission: RoleResultSubmission =
                crate::protocol::parse_unique(result_json.as_bytes())?;
            let resumable_result = match submission.assertion {
                AgentAssertion::Blocked { .. } => true,
                AgentAssertion::Succeeded if submission.kind == RoleOutputKind::Progress => {
                    match RoleResultPayload::parse(submission.kind, submission.structured_result)? {
                        RoleResultPayload::Progress(progress) => {
                            progress.pending_node_keys.contains(&assignment.node_id)
                                && !progress.completed_node_keys.contains(&assignment.node_id)
                                && progress.next_observation_at.is_none()
                        }
                        _ => false,
                    }
                }
                AgentAssertion::Succeeded
                | AgentAssertion::Failed { .. }
                | AgentAssertion::Cancelled { .. } => false,
            };
            if submission.binding.agent_run_id != prior_id
                || submission.binding.role != Role::Worker
                || submission
                    .binding
                    .ticket_revision
                    .map(|revision| revision.0)
                    != Some(run.revision)
                || !resumable_result
            {
                continue;
            }
            let effects = {
                let mut statement = self.connection.prepare(
                    "SELECT operation_id,status,request_json,receipt_json FROM effects WHERE kind='commit_worker_manifest' AND json_extract(request_json,'$.agent_run_id')=?1 AND project_id=?2 AND subject_type='ticket_run' AND subject_id=?3 ORDER BY operation_id",
                ).map_err(|error| error.to_string())?;
                let rows = statement
                    .query_map(
                        rusqlite::params![
                            prior_id.as_str(),
                            run.project_id.as_str(),
                            run.ticket_run_id.as_str()
                        ],
                        |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, String>(2)?,
                                row.get::<_, Option<String>>(3)?,
                            ))
                        },
                    )
                    .map_err(|error| error.to_string())?;
                rows.collect::<Result<Vec<_>, _>>()
                    .map_err(|error| error.to_string())?
            };
            let mut commit: Option<(crate::domain::ids::OperationId, Digest, String)> = None;
            let mut commit_manifest_artifact: Option<
                crate::engine::orchestration::RoleArtifactReference,
            > = None;
            let mut uncertain = false;
            for (operation_id, status, request_json, receipt_json) in effects {
                match status.as_str() {
                    "pending" | "claimed" | "uncertain" => uncertain = true,
                    "succeeded" => {
                        let Some(succeeded) = self.succeeded_effect_receipt(&operation_id)? else {
                            uncertain = true;
                            continue;
                        };
                        if succeeded.intent().kind
                            != crate::engine::reducer::effect_name(
                                &crate::engine::reducer::EffectKind::CommitWorkerManifest,
                            )
                            || succeeded.intent().request_json != request_json
                            || succeeded.receipt_json()
                                != receipt_json.as_deref().unwrap_or_default()
                        {
                            return Err(
                                "succeeded Worker commit differs from its durable effect receipt"
                                    .into(),
                            );
                        }
                        let payload: CommitWorkerManifestEffectPayload =
                            crate::protocol::parse_unique(request_json.as_bytes())?;
                        let Some(receipt_json) = receipt_json else {
                            uncertain = true;
                            continue;
                        };
                        let receipt: CommitWorkerManifestEffectReceipt =
                            crate::protocol::parse_unique(receipt_json.as_bytes())?;
                        if payload.agent_run_id != prior_id
                            || payload.ticket_run_id != run.ticket_run_id
                            || payload.work_node_id != assignment.node_id
                            || payload.repository_id != assignment.repository_id
                            || payload.expected_base_sha != assignment.base_sha
                            || payload.prepare_operation_id.as_str()
                                != assignment.prepare_operation_id
                            || receipt.agent_run_id != prior_id
                            || receipt.ticket_run_id != run.ticket_run_id
                            || receipt.work_node_id != assignment.node_id
                            || receipt.repository_id != assignment.repository_id
                            || receipt.base_sha != assignment.base_sha
                            || receipt.commit.operation_id.as_str() != operation_id
                            || receipt.commit.expected_head != payload.expected_head
                            || receipt.commit.observed_head == receipt.commit.expected_head
                            || !receipt.commit.signature_verified
                            || !receipt.commit.hooks_completed
                            || !receipt.commit.index_synchronized
                            || receipt.commit.index_sync_conflict
                            || receipt.manifest_artifact != payload.manifest_artifact
                        {
                            return Err(
                                "host Worker commit receipt does not match the prior accepted node"
                                    .into(),
                            );
                        }
                        if commit
                            .replace((
                                receipt.commit.operation_id.clone(),
                                digest(receipt_json.as_bytes())?,
                                receipt.commit.observed_head,
                            ))
                            .is_some()
                        {
                            return Err("prior Worker has multiple succeeded host commits".into());
                        }
                        commit_manifest_artifact = Some(receipt.manifest_artifact);
                    }
                    "failed" | "cancelled" => {}
                    _ => uncertain = true,
                }
            }
            if uncertain {
                continue;
            }
            let (prior_host_commit_operation_id, prior_host_commit_receipt_digest, expected_head) =
                match commit {
                    Some((operation, receipt_digest, head)) => {
                        (Some(operation), Some(receipt_digest), head)
                    }
                    None => (None, None, prepared_expected_head),
                };
            let mut prior_artifact_refs = submission.artifact_refs;
            if let Some(manifest) = commit_manifest_artifact
                && !prior_artifact_refs.contains(&manifest)
            {
                prior_artifact_refs.push(manifest);
            }
            candidates.push(WorkerRecoveryCandidate {
                work_node_id: assignment.node_id.clone(),
                ticket_revision: run.revision,
                worktree_path: assignment.worktree_path.clone(),
                accepted_plan_digest: plan.plan_digest.clone(),
                prior_worker_agent_run_id: prior_id,
                prior_host_commit_operation_id,
                expected_head,
                prior_terminal_digest: terminal.terminal_digest().clone(),
                prior_absence_digest: terminal.absence_digest().clone(),
                prior_host_commit_receipt_digest,
                prior_worker_result_evidence_id: evidence_id,
                prior_artifact_refs,
            });
        }
        Ok(candidates)
    }

    /// Persist a Coordinator-only nudge when a terminal Worker becomes eligible for
    /// same-node continuation. This contains no Worker authorization;
    /// a later Coordinator result must still request and pass the normal recovery
    /// candidate validation before a replacement can launch.
    pub fn queue_worker_recovery_ready_wake(
        &mut self,
        owner_generation: u64,
        run: &crate::store::scheduler::ActiveTicketRun,
        plan: &crate::store::accepted_plans::AcceptedWorkPlanRecord,
        configuration_digest: &Digest,
        candidate: &crate::engine::orchestration::WorkerRecoveryCandidate,
        now_unix: i64,
    ) -> Result<bool, String> {
        use crate::engine::reducer::Phase;

        if run.phase != Phase::Implementing
            || candidate.ticket_revision != run.revision
            || candidate.accepted_plan_digest != plan.plan_digest
            || plan.ticket_run_id != run.ticket_run_id
            || plan.project_id != run.project_id
            || plan.configuration_digest != *configuration_digest
        {
            return Err(
                "Worker recovery readiness does not match the current TicketRun and plan".into(),
            );
        }
        let role_session_id = format!("ticket_run:{}:coordinator", run.ticket_run_id);
        let identity = serde_json::to_vec(&(
            "rex-projects-worker-recovery-ready-v1",
            run.project_id.as_str(),
            run.ticket_run_id.as_str(),
            run.revision,
            configuration_digest.as_str(),
            plan.plan_digest.as_str(),
            candidate.prior_worker_result_evidence_id.as_str(),
        ))
        .map_err(|error| error.to_string())?;
        let source_id = digest(&identity)?.to_string();
        let payload = serde_json::json!({
            "kind": "worker_recovery_ready",
            "ticket_run_id": run.ticket_run_id.as_str(),
            "ticket_revision": run.revision,
            "prior_worker_result_evidence_id": candidate.prior_worker_result_evidence_id,
            "instruction": "Re-evaluate host-verified Worker recovery candidates for this TicketRun. Do not start a Worker directly; any recovery requires a typed Coordinator SpawnRequest and fresh host authorization."
        });
        let payload_json = serde_json::to_string(&payload).map_err(|error| error.to_string())?;

        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        super::validate_active_generation(&tx, owner_generation)?;
        let current: Option<(u64, String, u64)> = tx
            .query_row(
                "SELECT t.revision,t.internal_phase,c.project_epoch FROM ticket_runs t JOIN ticket_run_context c USING(project_id,ticket_run_id) JOIN projects p USING(project_id) JOIN project_runtimes r USING(project_id) WHERE t.project_id=?1 AND t.ticket_run_id=?2 AND p.desired_lifecycle='running' AND r.observed_lifecycle='running' AND r.controller_generation=?3",
                rusqlite::params![run.project_id.as_str(), run.ticket_run_id.as_str(), owner_generation],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if current != Some((run.revision, "implementing".into(), run.project_epoch)) {
            return Err(
                "Worker recovery readiness became stale before its Coordinator wake was persisted"
                    .into(),
            );
        }
        let persisted_plan: Option<(String, String)> = tx
            .query_row(
                "SELECT plan_digest,configuration_digest FROM accepted_work_plans WHERE project_id=?1 AND ticket_run_id=?2 AND accepted_revision=?3",
                rusqlite::params![run.project_id.as_str(), run.ticket_run_id.as_str(), plan.accepted_revision],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if persisted_plan
            != Some((
                plan.plan_digest.to_string(),
                configuration_digest.to_string(),
            ))
        {
            return Err("Worker recovery readiness plan is no longer the accepted plan".into());
        }
        let existing: Option<String> = tx
            .query_row(
                "SELECT payload_json FROM role_wake_inputs WHERE project_id=?1 AND role_session_id=?2 AND source_type='worker_recovery_ready' AND source_id=?3 AND source_revision=?4",
                rusqlite::params![run.project_id.as_str(), role_session_id, source_id, run.revision],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if existing
            .as_ref()
            .is_some_and(|stored| stored != &payload_json)
        {
            return Err(
                "Worker recovery readiness key already has a different Coordinator wake".into(),
            );
        }
        let inserted = if existing.is_none() {
            tx.execute(
                "INSERT INTO role_wake_inputs(project_id,role_session_id,source_type,source_id,source_revision,priority,payload_json,lifecycle,created_at_unix) VALUES (?1,?2,'worker_recovery_ready',?3,?4,20,?5,'pending',?6)",
                rusqlite::params![run.project_id.as_str(), role_session_id, source_id, run.revision, payload_json, now_unix],
            )
            .map_err(|error| error.to_string())?
                == 1
        } else {
            false
        };
        tx.commit().map_err(|error| error.to_string())?;
        Ok(inserted)
    }

    /// Persist a Coordinator-requested Worker retry only after its candidate has been
    /// revalidated by the host. The prior Worker run is the idempotency key.
    pub fn persist_worker_recovery_wake(
        &mut self,
        owner_generation: u64,
        result: &IngestedAgentResult,
        authorization: &crate::engine::orchestration::WorkerRecoveryAuthorization,
        source_revision: u64,
    ) -> Result<(), String> {
        use crate::engine::orchestration::{AgentAssertion, RoleResultPayload};
        authorization.validate()?;
        let binding = &result.validated.binding;
        let RoleResultPayload::SpawnRequest(request) = &result.validated.typed_payload else {
            return Err(
                "Worker recovery authorization requires a typed Coordinator SpawnRequest".into(),
            );
        };
        if binding.role != Role::Coordinator
            || result.validated.kind != crate::engine::orchestration::RoleOutputKind::SpawnRequest
            || result.validated.assertion != AgentAssertion::Succeeded
            || request.role != Role::Worker
            || request.worker_recovery.is_none()
            || request.work_node != authorization.work_node_id
            || request.plan_digest.as_ref() != Some(&authorization.accepted_plan_digest)
            || request.worker_recovery.as_ref().is_none_or(|recovery| {
                recovery.prior_worker_agent_run_id != authorization.prior_worker_agent_run_id
                    || recovery.prior_host_commit_operation_id
                        != authorization.prior_host_commit_operation_id
            })
            || binding.ticket_revision.map(|revision| revision.0) != Some(source_revision)
            || authorization.ticket_revision != source_revision
            || binding.ticket_run_id.as_ref() != Some(&authorization.ticket_run_id)
            || authorization.source_coordinator_evidence_id != result.receipt.evidence_id()
        {
            return Err("Worker recovery request differs from its host authorization".into());
        }
        let role_session_id = format!(
            "ticket:{}:worker:{}",
            authorization.ticket_run_id, authorization.work_node_id
        );
        let observed_prior_reservation_json: String = self
            .connection
            .query_row(
                "SELECT reservation_json FROM agent_launch_reservations WHERE agent_run_id=?1",
                [authorization.prior_worker_agent_run_id.as_str()],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        let prior_reservation: crate::launch::AgentLaunchReservation =
            crate::protocol::parse_unique(observed_prior_reservation_json.as_bytes())?;
        let prior_assignment = prior_reservation
            .worker_assignment
            .as_ref()
            .ok_or("prior Worker reservation has no prepared assignment")?;
        let accepted_publication_head = accepted_correction_publication_head(
            self,
            owner_generation,
            binding,
            authorization,
            prior_assignment,
            source_revision,
        )?;
        let precommit_expected_head = accepted_publication_head
            .unwrap_or_else(|| prior_assignment.expected_head().to_owned());
        let payload = serde_json::json!({
            "schema_version":1,
            "kind":"worker_recovery_authorization",
            "authorization":authorization,
        });
        let payload_json = crate::store::canonical_json(&payload)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        super::validate_active_generation(&tx, owner_generation)?;
        let run: Option<(String,u64,String,String,u64)> = tx.query_row(
            "SELECT internal_phase,revision,config_digest,project_id,config_revision FROM ticket_runs WHERE ticket_run_id=?1",
            [authorization.ticket_run_id.as_str()], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)),
        ).optional().map_err(|error| error.to_string())?;
        let Some((phase, revision, config_digest, project_id, config_revision)) = run else {
            return Err("Worker recovery TicketRun is missing".into());
        };
        if phase != "implementing"
            || revision != source_revision
            || project_id != binding.project_id.as_str()
            || config_digest != binding.config_digest.as_str()
            || config_revision != binding.config_revision.0
        {
            return Err("Worker recovery request is stale or outside Implementing".into());
        }
        let accepted_plan: Option<String> = tx.query_row(
            "SELECT plan_digest FROM accepted_work_plans WHERE project_id=?1 AND ticket_run_id=?2 ORDER BY accepted_revision DESC LIMIT 1",
            rusqlite::params![binding.project_id.as_str(),authorization.ticket_run_id.as_str()], |row| row.get(0),
        ).optional().map_err(|error| error.to_string())?;
        if accepted_plan.as_deref() != Some(authorization.accepted_plan_digest.as_str()) {
            return Err("Worker recovery accepted plan changed before persistence".into());
        }
        let evidence: Option<(String,String,String,String,Option<String>,u64)> = tx.query_row(
            "SELECT agent_run_id,project_id,role,outcome,ticket_run_id,run_epoch FROM agent_result_evidence WHERE evidence_id=?1",
            [result.receipt.evidence_id()], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?)),
        ).optional().map_err(|error| error.to_string())?;
        if !matches!(evidence, Some((ref agent,ref project,ref role,ref outcome,Some(ref ticket),epoch)) if agent == binding.agent_run_id.as_str() && project == binding.project_id.as_str() && role == "coordinator" && outcome == "completed" && ticket == authorization.ticket_run_id.as_str() && epoch == binding.run_epoch)
        {
            return Err("Worker recovery source is not a persisted Coordinator result".into());
        }
        let prior_authority_json: Option<String> = tx
            .query_row(
                "SELECT authority_json FROM agent_launch_authority WHERE agent_run_id=?1",
                [authorization.prior_worker_agent_run_id.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let Some(prior_authority_json) = prior_authority_json else {
            return Err("prior Worker launch authority is missing".into());
        };
        let prior_authority: crate::launch::AgentLaunchAuthority =
            crate::protocol::parse_unique(prior_authority_json.as_bytes())?;
        let prior_reservation_json: Option<String> = tx
            .query_row(
                "SELECT reservation_json FROM agent_launch_reservations WHERE agent_run_id=?1",
                [authorization.prior_worker_agent_run_id.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let Some(prior_reservation_json) = prior_reservation_json else {
            return Err("prior Worker reservation is missing".into());
        };
        if prior_reservation_json != observed_prior_reservation_json {
            return Err(
                "prior Worker reservation changed while recovery authority was derived".into(),
            );
        }
        let prior_reservation: crate::launch::AgentLaunchReservation =
            crate::protocol::parse_unique(prior_reservation_json.as_bytes())?;
        let prior_assignment = prior_reservation
            .worker_assignment
            .as_ref()
            .ok_or("prior Worker reservation has no prepared assignment")?;
        if prior_authority.role != Role::Worker
            || prior_authority.project_id != binding.project_id
            || prior_authority.ticket_run_id.as_ref() != Some(&authorization.ticket_run_id)
            || prior_authority.ticket_revision.map(|value| value.0) != Some(source_revision)
            || prior_reservation.ticket_revision.map(|value| value.0)
                != Some(authorization.ticket_revision)
            || prior_authority.role_session_id != role_session_id
            || prior_assignment.node_id != authorization.work_node_id
            || prior_assignment.plan_digest != authorization.accepted_plan_digest
            || prior_assignment.configuration_digest != binding.config_digest
        {
            return Err("prior Worker authority differs from the requested accepted node".into());
        }
        let terminal: Option<(String,String)> = tx.query_row(
            "SELECT terminal_digest,absence_digest FROM agent_terminal_receipts WHERE agent_run_id=?1",
            [authorization.prior_worker_agent_run_id.as_str()], |row| Ok((row.get(0)?,row.get(1)?)),
        ).optional().map_err(|error| error.to_string())?;
        if !matches!(terminal, Some((ref terminal,ref absence)) if terminal == authorization.prior_terminal_digest.as_str() && absence == authorization.prior_absence_digest.as_str())
        {
            return Err("prior Worker terminal or process-absence proof changed".into());
        }
        let active: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM agent_runs WHERE role_session_id=?1 AND state IN ('launch_pending','running','unknown'))",
            [&role_session_id], |row| row.get(0),
        ).map_err(|error| error.to_string())?;
        let leased: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM execution_slots WHERE owner_kind='agent_run' AND owner_id=?1 AND disposition!='released')",
            [authorization.prior_worker_agent_run_id.as_str()], |row| row.get(0),
        ).map_err(|error| error.to_string())?;
        if active || leased {
            return Err("prior Worker still owns an active process or execution lease".into());
        }
        let commit_rows: Vec<(String, String, Option<String>)> = {
            let mut statement = tx.prepare(
                "SELECT operation_id,status,receipt_json FROM effects WHERE kind='commit_worker_manifest' AND json_extract(request_json,'$.agent_run_id')=?1 AND project_id=?2 AND subject_type='ticket_run' AND subject_id=?3 ORDER BY operation_id",
            ).map_err(|error| error.to_string())?;
            let rows = statement
                .query_map(
                    rusqlite::params![
                        authorization.prior_worker_agent_run_id.as_str(),
                        binding.project_id.as_str(),
                        authorization.ticket_run_id.as_str()
                    ],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .map_err(|error| error.to_string())?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|error| error.to_string())?
        };
        match authorization.prior_host_commit_operation_id.as_ref() {
            None => {
                if commit_rows.iter().any(|(_, status, _)| {
                    matches!(
                        status.as_str(),
                        "pending" | "claimed" | "uncertain" | "succeeded"
                    )
                }) || authorization.prior_host_commit_receipt_digest.is_some()
                    || authorization.expected_head != precommit_expected_head
                {
                    return Err("pre-commit Worker recovery has a pending, uncertain, or completed host commit".into());
                }
            }
            Some(operation_id) => {
                if commit_rows.iter().any(|(_, status, _)| {
                    matches!(status.as_str(), "pending" | "claimed" | "uncertain")
                }) || commit_rows
                    .iter()
                    .filter(|(_, status, _)| status == "succeeded")
                    .count()
                    != 1
                {
                    return Err("post-commit Worker recovery has another pending, uncertain, or succeeded host commit".into());
                }
                let row = commit_rows
                    .iter()
                    .find(|(operation, status, receipt)| {
                        operation == operation_id.as_str()
                            && status == "succeeded"
                            && receipt.is_some()
                    })
                    .ok_or("post-commit Worker recovery lacks its exact succeeded host receipt")?;
                let receipt_json = row
                    .2
                    .as_deref()
                    .ok_or("succeeded host commit has no receipt")?;
                let receipt_digest = digest(receipt_json.as_bytes())?;
                if authorization.prior_host_commit_receipt_digest.as_ref() != Some(&receipt_digest)
                {
                    return Err("post-commit Worker recovery receipt digest changed".into());
                }
                let receipt: crate::delivery_runtime::CommitWorkerManifestEffectReceipt =
                    crate::protocol::parse_unique(receipt_json.as_bytes())?;
                if receipt.agent_run_id != authorization.prior_worker_agent_run_id
                    || receipt.ticket_run_id != authorization.ticket_run_id
                    || receipt.work_node_id != authorization.work_node_id
                    || receipt.repository_id != prior_assignment.repository_id
                    || receipt.base_sha != prior_assignment.base_sha
                    || receipt.commit.operation_id != *operation_id
                    || receipt.commit.observed_head != authorization.expected_head
                    || !receipt.commit.signature_verified
                    || !receipt.commit.hooks_completed
                    || !receipt.commit.index_synchronized
                    || receipt.commit.index_sync_conflict
                {
                    return Err("post-commit Worker recovery receipt does not match its accepted assignment".into());
                }
            }
        }
        let existing: Option<String> = tx.query_row(
            "SELECT payload_json FROM role_wake_inputs WHERE project_id=?1 AND role_session_id=?2 AND source_type='worker_recovery_authorization' AND source_id=?3",
            rusqlite::params![binding.project_id.as_str(),role_session_id,authorization.prior_worker_result_evidence_id], |row| row.get(0),
        ).optional().map_err(|error| error.to_string())?;
        if existing
            .as_ref()
            .is_some_and(|stored| stored != &payload_json)
        {
            return Err("prior Worker run already has a different recovery authorization".into());
        }
        if existing.is_none() {
            tx.execute(
                "INSERT INTO role_wake_inputs(project_id,role_session_id,source_type,source_id,source_revision,priority,payload_json,lifecycle,created_at_unix) VALUES (?1,?2,'worker_recovery_authorization',?3,?4,10,?5,'pending',?6)",
                rusqlite::params![binding.project_id.as_str(),role_session_id,authorization.prior_worker_result_evidence_id,source_revision,payload_json,super::now_unix()?],
            ).map_err(|error| error.to_string())?;
        }
        let prior_ack: Option<(u64,String)> = tx.query_row(
            "SELECT reducer_revision,disposition FROM agent_result_reducer_ack WHERE evidence_id=?1",
            [result.receipt.evidence_id()], |row| Ok((row.get(0)?,row.get(1)?)),
        ).optional().map_err(|error| error.to_string())?;
        if prior_ack.as_ref().is_some_and(|(revision, disposition)| {
            *revision != source_revision || disposition != "applied"
        }) {
            return Err("Coordinator recovery request was acknowledged differently".into());
        }
        if prior_ack.is_none() {
            tx.execute("INSERT INTO agent_result_reducer_ack(evidence_id,reducer_revision,disposition,acknowledged_at_unix) VALUES (?1,?2,'applied',?3)",rusqlite::params![result.receipt.evidence_id(),source_revision,super::now_unix()?]).map_err(|error| error.to_string())?;
        }
        tx.commit().map_err(|error| error.to_string())
    }

    /// Reject a structurally valid MergeDecision claim that disagrees with the host's
    /// accepted publication identity. The first mismatch gets one exact Coordinator
    /// correction; a second mismatch for that same publication/revision blocks the
    /// TicketRun and notifies its Supervisor. The result ACK and wake/transition share
    /// one SQLite transaction.
    pub fn reject_merge_assessment_claim(
        &mut self,
        owner_generation: u64,
        result: &IngestedAgentResult,
        publication_set_digest: &str,
        expected_pull_request_reference: &str,
        reason: &str,
    ) -> Result<MergeClaimRejectionOutcome, String> {
        let binding = &result.validated.binding;
        let ticket_run_id = binding
            .ticket_run_id
            .as_ref()
            .ok_or("MergeDecision claim rejection requires TicketRun scope")?;
        let source_revision = binding
            .ticket_revision
            .ok_or("MergeDecision claim rejection lacks TicketRun revision")?;
        if binding.role != Role::MergeDecision
            || result.validated.kind
                != crate::engine::orchestration::RoleOutputKind::MergeAssessment
            || result.validated.assertion != crate::engine::orchestration::AgentAssertion::Succeeded
        {
            return Err("claim rejection requires a succeeded MergeAssessment result".into());
        }
        if reason.is_empty() || reason.len() > 512 || expected_pull_request_reference.is_empty() {
            return Err("claim rejection correction context is invalid".into());
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        super::validate_active_generation(&tx, owner_generation)?;
        let prior_ack: Option<(u64, String)> = tx.query_row(
            "SELECT reducer_revision,disposition FROM agent_result_reducer_ack WHERE evidence_id=?1",
            [result.receipt.evidence_id()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional().map_err(|error| error.to_string())?;
        if let Some((_revision, disposition)) = prior_ack {
            if disposition != "rejected_by_host" {
                return Err(
                    "MergeDecision evidence was already acknowledged with a different disposition"
                        .into(),
                );
            }
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(MergeClaimRejectionOutcome::AlreadyRecorded);
        }

        let evidence: Option<(String, String, String, Option<String>, String, String)> = tx.query_row(
            "SELECT agent_run_id,project_id,role,ticket_run_id,outcome,result_digest FROM agent_result_evidence WHERE evidence_id=?1",
            [result.receipt.evidence_id()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
        ).optional().map_err(|error| error.to_string())?;
        let Some((agent_run_id, project_id, role, evidence_ticket, outcome, result_digest)) =
            evidence
        else {
            return Err("MergeDecision claim rejection source evidence is missing".into());
        };
        if agent_run_id != binding.agent_run_id.as_str()
            || project_id != binding.project_id.as_str()
            || role != "merge_decision"
            || evidence_ticket.as_deref() != Some(ticket_run_id.as_str())
            || outcome != "completed"
            || result_digest != result.validated.result_digest.as_str()
        {
            return Err(
                "MergeDecision claim rejection source evidence is not authoritative".into(),
            );
        }
        let (authority_json, authority_digest): (String, String) = tx.query_row(
            "SELECT authority_json,authority_digest FROM agent_launch_authority WHERE agent_run_id=?1",
            [binding.agent_run_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).map_err(|error| error.to_string())?;
        let authority: AgentLaunchAuthority =
            crate::protocol::parse_unique(authority_json.as_bytes())?;
        authority.validate()?;
        if authority.digest()?.as_str() != authority_digest
            || binding_for(&authority)? != *binding
            || authority.ticket_run_id.as_ref() != Some(ticket_run_id)
            || authority.ticket_revision != Some(source_revision)
        {
            return Err(
                "MergeDecision claim rejection differs from immutable launch authority".into(),
            );
        }
        let parent_id = authority
            .parent_run_id
            .as_ref()
            .ok_or("MergeDecision launch authority has no Coordinator parent")?;
        let (parent_json, parent_digest): (String, String) = tx
            .query_row(
                "SELECT authority_json,authority_digest FROM agent_launch_authority WHERE agent_run_id=?1",
                [parent_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|error| error.to_string())?;
        let parent: AgentLaunchAuthority = crate::protocol::parse_unique(parent_json.as_bytes())?;
        parent.validate()?;
        if parent.digest()?.as_str() != parent_digest
            || parent.agent_run_id != *parent_id
            || parent.role != Role::Coordinator
            || parent.role_session_id != format!("ticket_run:{ticket_run_id}:coordinator")
            || parent.project_id != authority.project_id
            || parent.ticket_run_id != authority.ticket_run_id
            || Some(parent.role) != authority.parent_role
            || authority.role_session_id != format!("ticket_run:{}:merge_decision", ticket_run_id)
        {
            return Err("MergeDecision claim rejection parent lineage is invalid".into());
        }
        let current: Option<(String, String, String, u64, String)> = tx.query_row(
            "SELECT internal_phase,activity,external_status,revision,project_id FROM ticket_runs WHERE ticket_run_id=?1",
            [ticket_run_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        ).optional().map_err(|error| error.to_string())?;
        let Some((phase, activity, external_status, revision, ticket_project)) = current else {
            return Err("MergeDecision claim rejection TicketRun is missing".into());
        };
        if phase != "assessing"
            || activity != "running"
            || revision != source_revision.0
            || ticket_project != binding.project_id.as_str()
        {
            return Err(
                "MergeDecision claim rejection TicketRun is stale or not actively assessing".into(),
            );
        }
        let trusted_assessment_exists: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM role_wake_inputs WHERE project_id=?1 AND role_session_id=?2 AND source_type='host_merge_assessment' AND source_revision=?3 AND lifecycle IN ('pending','claimed','consumed'))",
                rusqlite::params![binding.project_id.as_str(), authority.role_session_id, source_revision.0],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        if trusted_assessment_exists {
            tx.execute(
                "INSERT INTO agent_result_reducer_ack(evidence_id,reducer_revision,disposition,acknowledged_at_unix) VALUES (?1,?2,'rejected_by_host',?3)",
                rusqlite::params![result.receipt.evidence_id(),source_revision.0,super::now_unix()?],
            )
            .map_err(|error| error.to_string())?;
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(MergeClaimRejectionOutcome::AlreadyRecorded);
        }
        let prior_count: u64 = tx.query_row(
            "SELECT count(*) FROM role_wake_inputs WHERE project_id=?1 AND source_revision=?2 AND json_extract(payload_json,'$.ticket_run_id')=?3 AND json_extract(payload_json,'$.publication_set_digest')=?4 AND json_extract(payload_json,'$.kind')='merge_assessment_claim_rejected'",
            rusqlite::params![binding.project_id.as_str(), source_revision.0, ticket_run_id.as_str(), publication_set_digest],
            |row| row.get(0),
        ).map_err(|error| error.to_string())?;
        let now = super::now_unix()?;
        let (outcome, ack_revision) = if prior_count == 0 {
            let payload = serde_json::json!({
                "kind":"merge_assessment_claim_rejected",
                "source_evidence_id":result.receipt.evidence_id(),
                "ticket_run_id":ticket_run_id.as_str(),
                "publication_set_digest":publication_set_digest,
                "expected_pull_request_reference":expected_pull_request_reference,
                "reason":reason,
                "instruction":"You are the Coordinator. Do not write or revise the MergeAssessment yourself. Inspect this rejected claim and issue one explicit SpawnRequest for a new MergeDecision turn, using the configured MergeDecision profile and an accepted work node. The new MergeDecision turn will receive the host-validated publication subject and must put the expected pull request reference exactly as shown, without annotations or extra text, in pr_references. Do not request another correction after this one."
            });
            tx.execute(
                "INSERT INTO role_wake_inputs(project_id,role_session_id,source_type,source_id,source_revision,priority,payload_json,lifecycle,created_at_unix) VALUES (?1,?2,'merge_assessment_claim_rejected',?3,?4,100,?5,'pending',?6)",
                rusqlite::params![binding.project_id.as_str(),parent.role_session_id,result.receipt.evidence_id(),source_revision.0,payload.to_string(),now],
            ).map_err(|error| error.to_string())?;
            (
                MergeClaimRejectionOutcome::CoordinatorCorrectionQueued,
                source_revision.0,
            )
        } else {
            let current_run = crate::engine::reducer::TicketRun {
                project_id: binding.project_id.clone(),
                ticket_run_id: ticket_run_id.clone(),
                revision: source_revision,
                phase: crate::engine::reducer::Phase::Assessing,
                activity: crate::engine::reducer::Activity::Running,
                external_status: super::parse_ticket_status(&external_status)?,
                required_review_revision: None,
            };
            let decision = crate::engine::reducer::reduce(
                &current_run,
                source_revision,
                crate::engine::reducer::Input::MergeAssessmentCorrectionExhausted,
            )?;
            tx.execute(
                "UPDATE ticket_runs SET internal_phase=?2,activity=?3,external_status=?4,required_review_revision=?5,revision=?6 WHERE ticket_run_id=?1 AND revision=?7",
                rusqlite::params![ticket_run_id.as_str(),super::enum_string(&decision.ticket_run.phase)?,super::enum_string(&decision.ticket_run.activity)?,super::enum_string(&decision.ticket_run.external_status)?,decision.ticket_run.required_review_revision.map(|value| value.0),decision.ticket_run.revision.0,source_revision.0],
            ).map_err(|error| error.to_string())?;
            let message_id = format!(
                "merge-assessment-correction-exhausted:{}",
                result.receipt.evidence_id()
            );
            let payload = serde_json::json!({"source_evidence_id":result.receipt.evidence_id(),"publication_set_digest":publication_set_digest,"reason":reason,"expected_pull_request_reference":expected_pull_request_reference});
            let payload_json = crate::store::canonical_json(&payload)?;
            let input = crate::store::DurableInput {
                producer_id: "rex-projects-agent-result".into(),
                message_id: message_id.clone(),
                content_digest: crate::store::durable_input_digest("ticket_run", &payload_json),
                recipient: "ticket_run".into(),
                payload: payload_json.clone(),
            };
            tx.execute(
                "INSERT INTO transitions(project_id,entity_type,entity_id,old_revision,new_revision,input_id,decision_reason,evidence_json,created_at_unix) VALUES (?1,'ticket_run',?2,?3,?4,?5,'MergeDecision claim correction exhausted',?6,?7)",
                rusqlite::params![binding.project_id.as_str(),ticket_run_id.as_str(),source_revision.0,decision.ticket_run.revision.0,message_id,payload_json,now],
            ).map_err(|error| error.to_string())?;
            let supervisor_payload = serde_json::json!({
                "kind":"merge_assessment_correction_exhausted",
                "ticket_run_id":ticket_run_id.as_str(),
                "source_evidence_id":result.receipt.evidence_id(),
                "publication_set_digest":publication_set_digest,
                "expected_pull_request_reference":expected_pull_request_reference,
                "reason":reason,
                "revision":decision.ticket_run.revision.0,
                "instruction":"The one automatic MergeDecision correction still did not identify the accepted pull request exactly. This TicketRun is blocked; inspect and provide human direction before resuming."
            });
            tx.execute(
                "INSERT INTO role_wake_inputs(project_id,role_session_id,source_type,source_id,source_revision,priority,payload_json,lifecycle,created_at_unix) VALUES (?1,?2,'merge_assessment_correction_exhausted',?3,?4,100,?5,'pending',?6)",
                rusqlite::params![binding.project_id.as_str(),format!("project:{}:supervisor",binding.project_id.as_str()),result.receipt.evidence_id(),decision.ticket_run.revision.0,supervisor_payload.to_string(),now],
            ).map_err(|error| error.to_string())?;
            let receipt = serde_json::json!({"accepted":true,"ticket_run_id":ticket_run_id.as_str(),"revision":decision.ticket_run.revision.0,"blocked":true});
            tx.execute(
                "INSERT INTO inbox(producer_id,message_id,content_digest,recipient,payload_json,receipt_json,received_at_unix,processed_at_unix) VALUES (?1,?2,?3,?4,?5,?6,?7,?7)",
                rusqlite::params![input.producer_id,input.message_id,input.content_digest,input.recipient,input.payload,receipt.to_string(),now],
            ).map_err(|error| error.to_string())?;
            (
                MergeClaimRejectionOutcome::SupervisorEscalationQueued,
                decision.ticket_run.revision.0,
            )
        };
        tx.execute(
            "INSERT INTO agent_result_reducer_ack(evidence_id,reducer_revision,disposition,acknowledged_at_unix) VALUES (?1,?2,'rejected_by_host',?3)",
            rusqlite::params![result.receipt.evidence_id(),ack_revision,now],
        ).map_err(|error| error.to_string())?;
        tx.execute(
            "DELETE FROM merge_observation_deferrals WHERE source_evidence_id=?1",
            [result.receipt.evidence_id()],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(outcome)
    }

    /// Reject a phase-ineligible child request and wake its canonical Coordinator atomically.
    pub fn reject_coordinator_child_wake(
        &mut self,
        owner_generation: u64,
        result: &IngestedAgentResult,
        observed_phase: crate::engine::reducer::Phase,
        payload: &serde_json::Value,
    ) -> Result<(), String> {
        let binding = &result.validated.binding;
        let crate::engine::orchestration::RoleResultPayload::SpawnRequest(request) =
            &result.validated.typed_payload
        else {
            return Err("Coordinator spawn rejection requires a typed SpawnRequest".into());
        };
        let child_role = request.role;
        if binding.role != Role::Coordinator
            || result.validated.kind != crate::engine::orchestration::RoleOutputKind::SpawnRequest
            || result.validated.assertion != crate::engine::orchestration::AgentAssertion::Succeeded
            || child_role == Role::Worker
            || child_role == Role::Coordinator
            || child_role == Role::Supervisor
        {
            return Err(
                "Coordinator spawn rejection requires a succeeded generic-role SpawnRequest".into(),
            );
        }
        let ticket_run_id = binding
            .ticket_run_id
            .as_ref()
            .ok_or("Coordinator spawn rejection requires TicketRun scope")?;
        let expected_session = format!("ticket_run:{ticket_run_id}:coordinator");
        let source_revision = binding
            .ticket_revision
            .map(|revision| revision.0)
            .ok_or("Coordinator spawn rejection lacks TicketRun revision")?;
        let role_session_id = expected_session.as_str();
        if binding.role_session_id.as_str() != expected_session
            || crate::runtime_services::role_allowed_in_phase(child_role, observed_phase)
        {
            return Err("Coordinator spawn rejection scope or phase is invalid".into());
        }
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
            return Err("Coordinator spawn rejection source evidence is missing".into());
        };
        if run_id != binding.agent_run_id.as_str()
            || project_id != binding.project_id.as_str()
            || role != "coordinator"
            || outcome != "completed"
            || evidence_ticket.as_deref() != Some(ticket_run_id.as_str())
            || evidence_epoch != binding.run_epoch
        {
            return Err("Coordinator spawn rejection source evidence is not authoritative".into());
        }
        let (authority_json, authority_digest): (String, String) = tx
            .query_row(
                "SELECT authority_json,authority_digest FROM agent_launch_authority WHERE agent_run_id=?1",
                [binding.agent_run_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|error| error.to_string())?;
        let authority: AgentLaunchAuthority =
            crate::protocol::parse_unique(authority_json.as_bytes())?;
        authority.validate()?;
        if authority.agent_run_id != binding.agent_run_id
            || authority.digest()?.as_str() != authority_digest
            || binding_for(&authority)? != *binding
            || authority.role_session_id != expected_session
        {
            return Err(
                "Coordinator spawn rejection differs from immutable launch authority".into(),
            );
        }
        let ticket: Option<(u64, String, u64, String, String)> = tx
            .query_row(
                "SELECT revision,internal_phase,config_revision,config_digest,project_id FROM ticket_runs WHERE ticket_run_id=?1",
                [ticket_run_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let Some((revision, phase, config_revision, config_digest, ticket_project)) = ticket else {
            return Err("Coordinator spawn rejection TicketRun is missing".into());
        };
        let project: Option<(u64, String)> = tx
            .query_row(
                "SELECT config_revision,config_digest FROM projects WHERE project_id=?1",
                [binding.project_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let expected_phase = serde_json::to_value(observed_phase)
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned))
            .ok_or("TicketRun phase is not serializable")?;
        if revision != source_revision
            || phase != expected_phase
            || ticket_project != binding.project_id.as_str()
            || config_revision != binding.config_revision.0
            || config_digest != binding.config_digest.as_str()
            || project
                != Some((
                    binding.config_revision.0,
                    binding.config_digest.as_str().to_owned(),
                ))
        {
            return Err("Coordinator spawn rejection TicketRun or Project is stale".into());
        }
        let existing: Option<String> = tx
            .query_row(
                "SELECT payload_json FROM role_wake_inputs WHERE role_session_id=?1 AND source_type='coordinator_spawn_rejected' AND source_id=?2 AND source_revision=?3",
                rusqlite::params![role_session_id, evidence_id, source_revision],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if existing
            .as_ref()
            .is_some_and(|stored| stored != &payload_json)
        {
            return Err("Coordinator spawn rejection already has a different wake".into());
        }
        if existing.is_none() {
            tx.execute(
                "INSERT INTO role_wake_inputs(project_id,role_session_id,source_type,source_id,source_revision,priority,payload_json,lifecycle,created_at_unix) VALUES (?1,?2,'coordinator_spawn_rejected',?3,?4,100,?5,'pending',?6)",
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
            *revision != source_revision || disposition != "rejected_by_host"
        }) {
            return Err("Coordinator spawn rejection evidence was acknowledged differently".into());
        }
        if prior_ack.is_none() {
            tx.execute(
                "INSERT INTO agent_result_reducer_ack(evidence_id,reducer_revision,disposition,acknowledged_at_unix) VALUES (?1,?2,'rejected_by_host',?3)",
                rusqlite::params![evidence_id, source_revision, super::now_unix()?],
            )
            .map_err(|error| error.to_string())?;
        }
        tx.commit().map_err(|error| error.to_string())
    }

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
        if source_authority.role_session_id != format!("ticket_run:{ticket_run_id}:coordinator") {
            return Err(
                "Coordinator child source has a noncanonical Coordinator role session".into(),
            );
        }
        let recovery_authorization = if let Some(revision) = binding.ticket_revision {
            super::merge_claim_recovery::authorized_recovery_for_coordinator_run(
                &tx,
                &binding.project_id,
                ticket_run_id,
                &binding.agent_run_id,
                revision.0,
            )?
        } else {
            None
        };
        if recovery_authorization.is_some() && child_role != Role::MergeDecision {
            return Err(
                "a human MergeDecision recovery Coordinator may request only one MergeDecision child"
                    .into(),
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
        let prior_parents = {
            let mut statement = tx
                .prepare(
                    "SELECT w.source_id,e.agent_run_id,e.project_id,e.role,e.outcome,e.ticket_run_id FROM role_wake_inputs w LEFT JOIN agent_result_evidence e ON e.evidence_id=w.source_id WHERE w.project_id=?1 AND w.role_session_id=?2 AND w.source_type='coordinator_child' ORDER BY w.wake_input_id",
                )
                .map_err(|error| error.to_string())?;
            let rows = statement
                .query_map(
                    rusqlite::params![binding.project_id.as_str(), role_session_id],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, Option<String>>(1)?,
                            row.get::<_, Option<String>>(2)?,
                            row.get::<_, Option<String>>(3)?,
                            row.get::<_, Option<String>>(4)?,
                            row.get::<_, Option<String>>(5)?,
                        ))
                    },
                )
                .map_err(|error| error.to_string())?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|error| error.to_string())?
        };
        for (prior_evidence, prior_run, prior_project, prior_role, prior_outcome, prior_ticket) in
            prior_parents
        {
            if prior_evidence == evidence_id {
                continue;
            }
            let Some(prior_run) = prior_run else {
                return Err(
                    "canonical child role session has missing Coordinator source evidence".into(),
                );
            };
            if prior_project.as_deref() != Some(binding.project_id.as_str())
                || prior_role.as_deref() != Some("coordinator")
                || prior_outcome.as_deref() != Some("completed")
                || prior_ticket.as_deref() != Some(ticket_run_id.as_str())
            {
                return Err(
                    "canonical child role session has an invalid prior Coordinator source".into(),
                );
            }
            let (prior_authority_json, prior_descriptor_digest, prior_authority_digest): (
                String,
                String,
                String,
            ) = tx
                .query_row(
                    "SELECT authority_json,descriptor_digest,authority_digest FROM agent_launch_authority WHERE agent_run_id=?1",
                    [&prior_run],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .map_err(|error| error.to_string())?;
            let prior_authority: AgentLaunchAuthority =
                crate::protocol::parse_unique(prior_authority_json.as_bytes())?;
            prior_authority.validate()?;
            if prior_authority.agent_run_id.as_str() != prior_run
                || prior_authority.descriptor_digest.as_str() != prior_descriptor_digest
                || prior_authority.digest()?.as_str() != prior_authority_digest
            {
                return Err("stored Agent launch authority digest fields do not match".into());
            }
            if prior_authority.role != Role::Coordinator
                || prior_authority.project_id != binding.project_id
                || prior_authority.ticket_run_id.as_ref() != Some(ticket_run_id)
                || prior_authority.role_session_id != source_authority.role_session_id
            {
                return Err(
                    "canonical child role session has a different logical Coordinator parent"
                        .into(),
                );
            }
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
        if let Some(recovery) = recovery_authorization {
            if recovery.subject.configuration_digest != binding.config_digest
                || recovery.subject.blocked_revision.checked_add(1) != Some(source_revision)
            {
                return Err("Coordinator result is outside the exact authorized MergeDecision recovery revision".into());
            }
            match recovery.state.as_str() {
                "authorized" => {
                    tx.execute(
                        "UPDATE merge_claim_recovery_requests SET state='consumed',coordinator_evidence_id=?2,updated_at_unix=?3 WHERE request_id=?1 AND state='authorized' AND authorization_key=?4 AND coordinator_evidence_id IS NULL",
                        rusqlite::params![recovery.request_id,evidence_id,super::now_unix()?,recovery.authorization_key.as_str()],
                    ).map_err(|error| error.to_string())?;
                    if tx.changes() != 1 {
                        return Err("MergeDecision recovery authorization was already consumed or changed".into());
                    }
                }
                "consumed" if recovery.coordinator_evidence_id.as_deref()==Some(evidence_id) => {}
                _ => return Err("MergeDecision recovery authorization was already consumed by another Coordinator result".into()),
            }
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

    /// Resolve a pending child wake's parent from host-validated result evidence.
    pub fn coordinator_child_parent(
        &self,
        project_id: &crate::domain::ids::ProjectId,
        role_session_id: &str,
    ) -> Result<Option<crate::launch::AgentLaunchAuthority>, String> {
        let evidence_id: Option<String> = self
            .connection
            .query_row(
                "SELECT w.source_id FROM role_wake_inputs w JOIN agent_result_evidence e ON e.evidence_id=w.source_id WHERE w.project_id=?1 AND w.role_session_id=?2 AND w.source_type='coordinator_child' AND w.lifecycle='pending' ORDER BY w.wake_input_id LIMIT 1",
                rusqlite::params![project_id.as_str(), role_session_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let Some(evidence_id) = evidence_id else {
            return Ok(None);
        };
        self.coordinator_child_parent_for_evidence(project_id, role_session_id, &evidence_id)
    }

    /// Resolve the parent for one exact pending Coordinator child source.
    /// Callers that already have the consumed wake snapshot must not substitute
    /// the oldest pending child for a different evidence item.
    pub fn coordinator_child_parent_for_evidence(
        &self,
        project_id: &crate::domain::ids::ProjectId,
        role_session_id: &str,
        evidence_id: &str,
    ) -> Result<Option<crate::launch::AgentLaunchAuthority>, String> {
        let pending: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM role_wake_inputs WHERE project_id=?1 AND role_session_id=?2 AND source_type='coordinator_child' AND source_id=?3 AND lifecycle='pending')",
            rusqlite::params![project_id.as_str(), role_session_id, evidence_id],
            |row| row.get(0),
        ).map_err(|error| error.to_string())?;
        if !pending {
            return Ok(None);
        }
        let (parent_run, ticket_run_id): (String, String) = self
            .connection
            .query_row(
                "SELECT agent_run_id,ticket_run_id FROM agent_result_evidence WHERE evidence_id=?1 AND project_id=?2 AND role='coordinator' AND outcome='completed' AND ticket_run_id IS NOT NULL",
                rusqlite::params![evidence_id, project_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|error| error.to_string())?;
        let authority = self
            .agent_launch_authority(&crate::domain::ids::AgentRunId::parse(parent_run)?)?
            .ok_or("Coordinator child source has no host launch authority")?;
        if authority.role != crate::domain::types::Role::Coordinator
            || authority.project_id != *project_id
            || authority
                .ticket_run_id
                .as_ref()
                .map(|ticket| ticket.as_str())
                != Some(ticket_run_id.as_str())
            || authority.role_session_id != format!("ticket_run:{ticket_run_id}:coordinator")
        {
            return Err(
                "Coordinator child source authority has the wrong role, Project, or TicketRun"
                    .into(),
            );
        }
        Ok(Some(authority))
    }

    /// Resolve the Coordinator authority for a later MergeDecision turn from its
    /// exact host-validated assessment. A consumed child wake is not reusable;
    /// the assessment's immutable result authority preserves the parent link.
    pub fn coordinator_parent_for_merge_assessment(
        &self,
        project_id: &crate::domain::ids::ProjectId,
        ticket_run_id: &crate::domain::ids::TicketRunId,
        revision: crate::domain::ids::Revision,
    ) -> Result<Option<crate::launch::AgentLaunchAuthority>, String> {
        let Some(assessment) =
            self.trusted_merge_assessment(project_id, ticket_run_id, revision)?
        else {
            return Ok(None);
        };
        let (run_id, role, outcome, evidence_ticket): (String, String, String, Option<String>) = self.connection
            .query_row(
                "SELECT agent_run_id,role,outcome,ticket_run_id FROM agent_result_evidence WHERE evidence_id=?1 AND project_id=?2",
                rusqlite::params![assessment.source_evidence_id, project_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .map_err(|error| error.to_string())?;
        if role != "merge_decision"
            || outcome != "completed"
            || evidence_ticket.as_deref() != Some(ticket_run_id.as_str())
        {
            return Err(
                "trusted MergeAssessment source is not a completed result for this TicketRun"
                    .into(),
            );
        }
        let merge_authority = self
            .agent_launch_authority(&crate::domain::ids::AgentRunId::parse(run_id)?)?
            .ok_or("trusted MergeAssessment source has no immutable launch authority")?;
        let parent_id = merge_authority
            .parent_run_id
            .as_ref()
            .ok_or("MergeDecision authority has no Coordinator parent")?;
        if merge_authority.role != crate::domain::types::Role::MergeDecision
            || merge_authority.project_id != *project_id
            || merge_authority.ticket_run_id.as_ref() != Some(ticket_run_id)
            || merge_authority.ticket_revision != Some(revision)
            || merge_authority.config_digest != assessment.configuration_digest
            || merge_authority.parent_role != Some(crate::domain::types::Role::Coordinator)
            || merge_authority.role_session_id
                != format!("ticket_run:{ticket_run_id}:merge_decision")
        {
            return Err(
                "trusted MergeAssessment source authority differs from its exact launch scope"
                    .into(),
            );
        }
        let parent = self
            .agent_launch_authority(parent_id)?
            .ok_or("MergeDecision Coordinator parent has no immutable launch authority")?;
        let parent_completed: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM agent_result_evidence WHERE agent_run_id=?1 AND project_id=?2 AND role='coordinator' AND outcome='completed' AND ticket_run_id=?3)",
            rusqlite::params![parent_id.as_str(), project_id.as_str(), ticket_run_id.as_str()],
            |row| row.get(0),
        ).map_err(|error| error.to_string())?;
        if !parent_completed
            || parent.agent_run_id != *parent_id
            || parent.role != crate::domain::types::Role::Coordinator
            || parent.project_id != *project_id
            || parent.ticket_run_id.as_ref() != Some(ticket_run_id)
            || parent.role_session_id != format!("ticket_run:{ticket_run_id}:coordinator")
            || parent.config_revision != merge_authority.config_revision
            || parent.config_digest != assessment.configuration_digest
            || parent.ticket_revision != Some(revision)
        {
            return Err(
                "MergeDecision parent is not the exact completed Coordinator for this assessment"
                    .into(),
            );
        }
        Ok(Some(parent))
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
        let ticket: (String, String, u64) = self
            .connection
            .query_row(
                "SELECT ticket_id,namespace,generation FROM ticket_runs WHERE ticket_run_id=?1 AND project_id=?2",
                rusqlite::params![ticket_run_id.as_str(), project_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
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
        #[derive(serde::Deserialize)]
        struct InitialDispatchEvidence {
            namespace: TicketNamespace,
            ticket_id: TicketId,
            generation: u64,
            observed_revision: Option<TicketRevision>,
        }

        let (old_revision, new_revision, input_id, evidence_json): (i64, i64, String, String) = self
            .connection
            .query_row(
                "SELECT old_revision,new_revision,input_id,evidence_json FROM transitions WHERE project_id=?1 AND entity_type='ticket_run' AND entity_id=?2 AND new_revision=1",
                rusqlite::params![project_id.as_str(), ticket_run_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .map_err(|error| format!("TicketRun has no immutable initial dispatch provenance: {error}"))?;
        if old_revision != 0 || new_revision != 1 {
            return Err(
                "TicketRun initial dispatch provenance has an invalid transition revision".into(),
            );
        }
        let provenance: InitialDispatchEvidence =
            crate::protocol::parse_unique(evidence_json.as_bytes())?;
        let expected_input_id =
            format!("dispatch:{}:{}", provenance.namespace, provenance.ticket_id);
        let expected_revision = request.expected_ticket_revision.as_str();
        let observed_revision = provenance
            .observed_revision
            .as_ref()
            .ok_or("TicketRun initial dispatch provenance has no observed external revision")?;
        if input_id != expected_input_id
            || provenance.ticket_id.as_str() != ticket.0
            || provenance.namespace.as_str() != ticket.1
            || provenance.generation != ticket.2
            || request.ticket_reference.as_str() != ticket.0
            || observed_revision.as_str() != expected_revision
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
