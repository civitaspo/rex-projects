//! Reconcile live finite Agent turns after the machine controller changes owner.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde::Deserialize;
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::adapters::rex::{
    CreateDisposition, RexCliTransport, RexProcessObservation, TicketWindow,
};
use crate::domain::ids::{AgentRunId, Digest, ProfileId};
use crate::launch::{ObservedProviderStart, ObservedWrapperIdentity};
use crate::process::{
    ProcessIdentity, ProcessIdentityQuality, ProcessSignal, capture_process_tree,
    inspect_process_table, signal_process_group_if_observed,
};
use crate::run_step_spool::{BlockLossCleanupSnapshot, RunStepSpool};
use crate::store::ConfigStore;
use crate::store::agent_recovery::{
    AdoptedProcessIdentity, AgentAdoptionEvidence, RecoverableAgentRun,
};

const MAX_HEARTBEAT_BYTES: u64 = 1024;

#[derive(Clone, Debug)]
pub struct RecoveryPolicy {
    /// Rex session selected by the controller's verified runtime identity.
    pub rex_session_id: String,
    /// Profiles are pinned from the applied configuration, keyed by immutable ProfileId.
    pub turn_timeout_seconds: BTreeMap<ProfileId, u64>,
    pub heartbeat_stale_after_seconds: u64,
    pub max_observations_per_tick: usize,
    pub now_unix: i64,
}

impl RecoveryPolicy {
    pub fn validate(&self) -> Result<(), String> {
        if self.rex_session_id.trim().is_empty()
            || self.rex_session_id.chars().any(char::is_control)
            || self.heartbeat_stale_after_seconds == 0
            || self.heartbeat_stale_after_seconds > i64::MAX as u64
            || self.max_observations_per_tick == 0
            || self.max_observations_per_tick > 8
            || self
                .turn_timeout_seconds
                .values()
                .any(|seconds| *seconds == 0 || *seconds > i64::MAX as u64)
        {
            return Err(
                "Agent recovery policy is incomplete or exceeds its observation bound".into(),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentRecoveryDisposition {
    Adopted,
    AdoptedWithAttention,
    AlreadyAdopted,
    ProviderStarted,
    BlockLossStopping,
    BlockLossTerminal,
    Unresolved { reason: RecoveryUnknown },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryUnknown {
    WrongRexIdentity,
    RexObservationUnavailable,
    RexBlockExited,
    WrapperIdentityMismatch,
    ProviderIdentityMismatch,
    ProcessInspectionUnavailable,
    HeartbeatMissingOrInvalid,
    HeartbeatStale,
    RunTimeoutExceeded,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentRecoveryObservation {
    pub agent_run_id: AgentRunId,
    pub disposition: AgentRecoveryDisposition,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentRecoveryReport {
    pub examined: usize,
    pub observations: Vec<AgentRecoveryObservation>,
    pub more_pending: bool,
}

pub struct AgentRecoveryRuntime;

impl AgentRecoveryRuntime {
    /// Observe a finite, ordered subset of unknown/live runs. A failed or ambiguous observation
    /// never releases a slot and never authorizes a replacement turn.
    pub fn tick(
        store: &mut ConfigStore,
        owner_generation: u64,
        pinned_rex: &RexCliTransport,
        policy: &RecoveryPolicy,
    ) -> Result<AgentRecoveryReport, String> {
        policy.validate()?;
        let runs =
            store.recoverable_agent_runs(owner_generation, policy.max_observations_per_tick + 1)?;
        let more_pending = runs.len() > policy.max_observations_per_tick;
        let runs = runs
            .into_iter()
            .take(policy.max_observations_per_tick)
            .collect::<Vec<_>>();
        if runs.is_empty() {
            return Ok(AgentRecoveryReport {
                examined: 0,
                observations: Vec::new(),
                more_pending: false,
            });
        }
        let process_table = inspect_process_table().ok();
        let rex_instance = pinned_rex.capabilities().server_instance_id.as_str();
        let mut observations = Vec::with_capacity(runs.len());
        for run in runs {
            let disposition = if let Some(processes) = &process_table {
                Self::observe_one(
                    store,
                    owner_generation,
                    pinned_rex,
                    policy,
                    &run,
                    rex_instance,
                    processes,
                )?
            } else {
                AgentRecoveryDisposition::Unresolved {
                    reason: RecoveryUnknown::ProcessInspectionUnavailable,
                }
            };
            store.record_agent_recovery_observation(
                owner_generation,
                &run.agent_run_id,
                run.reservation_epoch,
                policy.now_unix,
            )?;
            observations.push(AgentRecoveryObservation {
                agent_run_id: run.agent_run_id,
                disposition,
            });
        }
        Ok(AgentRecoveryReport {
            examined: observations.len(),
            observations,
            more_pending,
        })
    }

    fn observe_one(
        store: &mut ConfigStore,
        owner_generation: u64,
        pinned_rex: &RexCliTransport,
        policy: &RecoveryPolicy,
        run: &RecoverableAgentRun,
        rex_instance: &str,
        process_table: &[ProcessIdentity],
    ) -> Result<AgentRecoveryDisposition, String> {
        let authority = &run.authority;
        if authority.rex_server_identity != rex_instance
            || authority.rex_session_id != policy.rex_session_id
        {
            return Ok(AgentRecoveryDisposition::Unresolved {
                reason: RecoveryUnknown::WrongRexIdentity,
            });
        }
        let wrapper: ObservedWrapperIdentity = match run.wrapper_identity_json.as_deref() {
            Some(json) => crate::protocol::parse_unique(json.as_bytes())
                .map_err(|error| format!("stored wrapper identity is invalid: {error}"))?,
            None => {
                return Ok(AgentRecoveryDisposition::Unresolved {
                    reason: RecoveryUnknown::WrapperIdentityMismatch,
                });
            }
        };
        if run.launch_state == "awaiting_provider" && run.provider_tree_json.is_none() {
            return observe_provider_start(
                store,
                owner_generation,
                pinned_rex,
                run,
                &wrapper,
                rex_instance,
                process_table,
            );
        }
        let provider: ObservedProviderStart = match run.provider_tree_json.as_deref() {
            Some(json) => crate::protocol::parse_unique(json.as_bytes())
                .map_err(|error| format!("stored provider start receipt is invalid: {error}"))?,
            None => {
                return Ok(AgentRecoveryDisposition::Unresolved {
                    reason: RecoveryUnknown::ProviderIdentityMismatch,
                });
            }
        };
        if wrapper.rex_session_id != authority.rex_session_id
            || wrapper.rex_block_id != authority.rex_block_id
            || wrapper.runtime_binary_digest != authority.runtime_binary_digest
            || provider.agent_run_id != authority.agent_run_id
            || !provider.process_tree_confirmed
        {
            return Ok(AgentRecoveryDisposition::Unresolved {
                reason: RecoveryUnknown::WrapperIdentityMismatch,
            });
        }
        if run.launch_state != "running" {
            return Ok(AgentRecoveryDisposition::Unresolved {
                reason: RecoveryUnknown::ProviderIdentityMismatch,
            });
        }
        let stored_process: StoredProviderIdentity = match run.process_identity_json.as_deref() {
            Some(json) => crate::protocol::parse_unique(json.as_bytes())
                .map_err(|error| format!("stored provider process identity is invalid: {error}"))?,
            None => {
                return Ok(AgentRecoveryDisposition::Unresolved {
                    reason: RecoveryUnknown::ProviderIdentityMismatch,
                });
            }
        };
        if stored_process.provider_pid != provider.provider_pid
            || stored_process.provider_start_identity != provider.provider_start_identity
            || stored_process.executable_digest != provider.executable_digest
            || stored_process.process_tree_digest != provider.process_tree_digest
            || stored_process.process_tree != provider.process_tree
        {
            return Ok(AgentRecoveryDisposition::Unresolved {
                reason: RecoveryUnknown::ProviderIdentityMismatch,
            });
        }
        let qualification = store
            .provider_qualification(&authority.qualification_receipt_digest)?
            .ok_or_else(|| "Agent recovery qualification receipt is missing".to_owned())?;
        if provider
            .validate_complete_process_tree(&qualification)
            .is_err()
        {
            return Ok(AgentRecoveryDisposition::Unresolved {
                reason: RecoveryUnknown::ProviderIdentityMismatch,
            });
        }
        if !provider_tree_contains_wrapper(&provider, &wrapper) {
            return Ok(AgentRecoveryDisposition::Unresolved {
                reason: RecoveryUnknown::WrapperIdentityMismatch,
            });
        }
        let window = TicketWindow {
            server_instance_id: rex_instance.to_owned(),
            session_id: authority.rex_session_id.clone(),
            window_id: authority.rex_window_id.clone(),
            label: String::new(),
            initial_block_id: Some(authority.rex_block_id.clone()),
            disposition: CreateDisposition::Existing,
        };
        match pinned_rex.agent_block_is_present(
            &window,
            authority.agent_run_id.as_str(),
            &authority.rex_block_id,
        ) {
            Ok(false) => {
                return reconcile_missing_block(
                    store,
                    owner_generation,
                    run,
                    &provider,
                    &wrapper,
                    &qualification,
                    policy,
                    process_table,
                );
            }
            Ok(true) => {}
            Err(_) => {
                return Ok(AgentRecoveryDisposition::Unresolved {
                    reason: RecoveryUnknown::RexObservationUnavailable,
                });
            }
        }
        let observation = match pinned_rex.observe_process(
            &window,
            authority.agent_run_id.as_str(),
            &authority.rex_block_id,
        ) {
            Ok(observation) => observation,
            Err(_) => {
                return Ok(AgentRecoveryDisposition::Unresolved {
                    reason: RecoveryUnknown::RexObservationUnavailable,
                });
            }
        };
        if !rex_processes_match(&observation, &wrapper, &provider) {
            return Ok(AgentRecoveryDisposition::Unresolved {
                reason: if observation.last_exit.is_some() {
                    RecoveryUnknown::RexBlockExited
                } else {
                    RecoveryUnknown::ProviderIdentityMismatch
                },
            });
        }
        let Some(wrapper_process) =
            kernel_identity(process_table, wrapper.pid, &wrapper.start_identity)
        else {
            return Ok(AgentRecoveryDisposition::Unresolved {
                reason: RecoveryUnknown::WrapperIdentityMismatch,
            });
        };
        let Some(provider_process) = kernel_identity(
            process_table,
            provider.provider_pid,
            &provider.provider_start_identity,
        ) else {
            return Ok(AgentRecoveryDisposition::Unresolved {
                reason: RecoveryUnknown::ProviderIdentityMismatch,
            });
        };
        if wrapper_process.quality != ProcessIdentityQuality::KernelBirthToken
            || provider_process.quality != ProcessIdentityQuality::KernelBirthToken
        {
            return Ok(AgentRecoveryDisposition::Unresolved {
                reason: RecoveryUnknown::ProcessInspectionUnavailable,
            });
        }
        // Rex owns the wrapper root. Capture from there so adoption evidence covers the
        // complete run tree, including the provider and any later descendants.
        let process_tree = capture_process_tree(wrapper.pid, process_table);
        if process_tree.is_empty()
            || process_tree
                .iter()
                .any(|process| process.quality != ProcessIdentityQuality::KernelBirthToken)
            || !process_tree.iter().any(|process| {
                process.pid == provider_process.pid
                    && process.start_identity == provider_process.start_identity
            })
        {
            return Ok(AgentRecoveryDisposition::Unresolved {
                reason: RecoveryUnknown::ProcessInspectionUnavailable,
            });
        }
        let process_tree = process_tree
            .iter()
            .map(|process| AdoptedProcessIdentity {
                pid: process.pid,
                parent_pid: process.parent_pid,
                process_group_id: process.process_group_id,
                start_identity: process.start_identity.clone(),
                identity_quality: "kernel_birth_token".into(),
            })
            .collect::<Vec<_>>();
        let heartbeat = read_heartbeat(
            &authority.control_dir,
            authority.agent_run_id.as_str(),
            policy.now_unix,
            policy.heartbeat_stale_after_seconds,
        );
        let profile_timeout = policy
            .turn_timeout_seconds
            .get(&authority.profile_id)
            .copied();
        let timeout_exceeded = profile_timeout.is_some_and(|timeout| {
            run.started_at_unix
                .is_some_and(|started| policy.now_unix.saturating_sub(started) > timeout as i64)
        });
        let (attention, reason) = match heartbeat {
            HeartbeatStatus::Fresh => (false, None),
            HeartbeatStatus::Stale => (true, Some(RecoveryUnknown::HeartbeatStale)),
            HeartbeatStatus::MissingOrInvalid => {
                (true, Some(RecoveryUnknown::HeartbeatMissingOrInvalid))
            }
        };
        let reason = if timeout_exceeded {
            Some(RecoveryUnknown::RunTimeoutExceeded)
        } else {
            reason
        };
        let rex_digest = digest_rex_observation(&observation)?;
        let evidence = AgentAdoptionEvidence {
            schema_version: 1,
            agent_run_id: authority.agent_run_id.clone(),
            controller_generation: owner_generation,
            previous_controller_generation: run.previous_generation,
            authority_digest: run.authority_digest.clone(),
            descriptor_digest: authority.descriptor_digest.clone(),
            rex_process_observation_digest: rex_digest,
            process_tree_digest: digest_json(&process_tree)?,
            provider_start_tree_digest: provider.process_tree_digest.clone(),
            process_tree,
            wrapper_pid: wrapper_process.pid,
            wrapper_start_identity: wrapper_process.start_identity.clone(),
            provider_pid: provider_process.pid,
            provider_start_identity: provider_process.start_identity.clone(),
            observed_at_unix: policy.now_unix,
        };
        let inserted =
            if run.agent_state == "unknown" && run.previous_generation != owner_generation {
                store.record_agent_run_adoption(&evidence, run.reservation_epoch)?
            } else {
                false
            };
        if attention || timeout_exceeded {
            store.queue_agent_recovery_attention(
                owner_generation,
                authority,
                reason.unwrap_or(RecoveryUnknown::HeartbeatMissingOrInvalid),
                policy.now_unix,
            )?;
        }
        Ok(if attention || timeout_exceeded {
            AgentRecoveryDisposition::AdoptedWithAttention
        } else if !inserted {
            AgentRecoveryDisposition::AlreadyAdopted
        } else {
            AgentRecoveryDisposition::Adopted
        })
    }
}

fn reconcile_missing_block(
    store: &mut ConfigStore,
    owner_generation: u64,
    run: &RecoverableAgentRun,
    provider: &ObservedProviderStart,
    wrapper: &ObservedWrapperIdentity,
    qualification: &crate::launch::ProviderQualification,
    policy: &RecoveryPolicy,
    current: &[ProcessIdentity],
) -> Result<AgentRecoveryDisposition, String> {
    if provider
        .validate_complete_process_tree(qualification)
        .is_err()
        || !provider_tree_contains_wrapper(provider, wrapper)
    {
        return Ok(AgentRecoveryDisposition::Unresolved {
            reason: RecoveryUnknown::ProviderIdentityMismatch,
        });
    }
    let launch_tree = provider
        .process_tree
        .iter()
        .map(|identity| ProcessIdentity {
            pid: identity.pid,
            parent_pid: identity.parent_pid,
            process_group_id: identity.process_group_id,
            start_identity: identity.start_identity.clone(),
            command: String::new(),
            quality: identity.identity_quality,
        })
        .collect::<Vec<_>>();
    if launch_tree.is_empty() {
        return Ok(AgentRecoveryDisposition::Unresolved {
            reason: RecoveryUnknown::ProcessInspectionUnavailable,
        });
    }
    let launch_groups = launch_tree
        .iter()
        .map(|process| process.process_group_id)
        .collect::<BTreeSet<_>>();
    if launch_groups.contains(&0)
        || launch_tree.iter().any(|process| {
            process.quality != ProcessIdentityQuality::KernelBirthToken
                || process.start_identity.trim().is_empty()
        })
    {
        return Ok(AgentRecoveryDisposition::Unresolved {
            reason: RecoveryUnknown::ProcessInspectionUnavailable,
        });
    }
    let spool = match RunStepSpool::open(&run.authority.control_dir) {
        Ok(spool) => spool,
        Err(_) => {
            return Ok(AgentRecoveryDisposition::Unresolved {
                reason: RecoveryUnknown::ProcessInspectionUnavailable,
            });
        }
    };
    let existing_snapshot = match spool.read_block_loss_cleanup_snapshot() {
        Ok(snapshot) => snapshot,
        Err(_) => {
            return Ok(AgentRecoveryDisposition::Unresolved {
                reason: RecoveryUnknown::ProcessInspectionUnavailable,
            });
        }
    };
    let mut snapshot = match existing_snapshot {
        Some(snapshot) => {
            if snapshot.agent_run_id != run.agent_run_id
                || snapshot.reservation_epoch != run.reservation_epoch
                || snapshot.authority_digest != run.authority_digest
                || snapshot.launch_tree_digest != provider.process_tree_digest
                || !contains_process_identities(&snapshot.process_tree, &launch_tree)
            {
                return Ok(AgentRecoveryDisposition::Unresolved {
                    reason: RecoveryUnknown::ProcessInspectionUnavailable,
                });
            }
            snapshot
        }
        None => {
            // The launch-time tree cannot prove that no later child escaped to a new PGID. A
            // fresh capture is permitted only while the exact provider birth identity is live.
            let Some(identities) = initial_cleanup_tree(
                provider.provider_pid,
                &provider.provider_start_identity,
                &launch_tree,
                current,
            ) else {
                return Ok(AgentRecoveryDisposition::Unresolved {
                    reason: RecoveryUnknown::ProviderIdentityMismatch,
                });
            };
            match make_block_loss_snapshot(run, provider, identities, policy.now_unix, false) {
                Ok(snapshot) => snapshot,
                Err(_) => {
                    return Ok(AgentRecoveryDisposition::Unresolved {
                        reason: RecoveryUnknown::ProcessInspectionUnavailable,
                    });
                }
            }
        }
    };
    let before_extend = snapshot.process_tree.len();
    let Some(extended) = (match extend_process_tree(&snapshot.process_tree, current) {
        Ok(extended) => extended,
        Err(_) => None,
    }) else {
        return Ok(AgentRecoveryDisposition::Unresolved {
            reason: RecoveryUnknown::ProcessInspectionUnavailable,
        });
    };
    if extended.len() > 1024 {
        return Ok(AgentRecoveryDisposition::Unresolved {
            reason: RecoveryUnknown::ProcessInspectionUnavailable,
        });
    }
    snapshot.process_tree = extended;
    if snapshot.process_tree.len() > before_extend {
        snapshot.cleanup_covered = false;
    }
    snapshot.observed_at_unix = policy.now_unix;
    snapshot.process_tree_digest = match digest_process_tree(&snapshot.process_tree) {
        Ok(digest) => digest,
        Err(_) => {
            return Ok(AgentRecoveryDisposition::Unresolved {
                reason: RecoveryUnknown::ProcessInspectionUnavailable,
            });
        }
    };
    if snapshot.validate().is_err() {
        return Ok(AgentRecoveryDisposition::Unresolved {
            reason: RecoveryUnknown::ProcessInspectionUnavailable,
        });
    }
    // Persist the cumulative identities before any signal can be sent.
    if spool.write_block_loss_cleanup_snapshot(&snapshot).is_err() {
        return Ok(AgentRecoveryDisposition::Unresolved {
            reason: RecoveryUnknown::ProcessInspectionUnavailable,
        });
    }
    let survivors = crate::process::matching_processes(&snapshot.process_tree, current);
    if cleanup_absence_confirmed(&snapshot, current) {
        let released = store.reconcile_missing_agent_block(
            owner_generation,
            run,
            policy.now_unix,
            &snapshot,
            &survivors,
        )?;
        if released {
            return Ok(AgentRecoveryDisposition::BlockLossTerminal);
        }
    }
    if survivors.is_empty() {
        return Ok(AgentRecoveryDisposition::Unresolved {
            reason: RecoveryUnknown::ProcessInspectionUnavailable,
        });
    }
    let groups = snapshot
        .process_tree
        .iter()
        .map(|process| process.process_group_id)
        .collect::<BTreeSet<_>>();
    let signal = if store.missing_block_survival_age_seconds(run, policy.now_unix)? >= 3 {
        ProcessSignal::Kill
    } else {
        ProcessSignal::Terminate
    };
    let mut signalled = false;
    for group_id in groups {
        signalled |=
            signal_process_group_if_observed(group_id, &snapshot.process_tree, current, signal)
                .map_err(|error| error.to_string())?;
    }
    if !signalled {
        return Ok(AgentRecoveryDisposition::Unresolved {
            reason: RecoveryUnknown::ProcessInspectionUnavailable,
        });
    }
    snapshot.cleanup_covered = true;
    snapshot.observed_at_unix = policy.now_unix;
    if spool.write_block_loss_cleanup_snapshot(&snapshot).is_err() {
        return Ok(AgentRecoveryDisposition::Unresolved {
            reason: RecoveryUnknown::ProcessInspectionUnavailable,
        });
    }
    store.reconcile_missing_agent_block(
        owner_generation,
        run,
        policy.now_unix,
        &snapshot,
        &survivors,
    )?;
    Ok(AgentRecoveryDisposition::BlockLossStopping)
}

fn make_block_loss_snapshot(
    run: &RecoverableAgentRun,
    provider: &ObservedProviderStart,
    process_tree: Vec<ProcessIdentity>,
    observed_at_unix: i64,
    cleanup_covered: bool,
) -> Result<BlockLossCleanupSnapshot, String> {
    let snapshot = BlockLossCleanupSnapshot {
        schema_version: 1,
        agent_run_id: run.agent_run_id.clone(),
        reservation_epoch: run.reservation_epoch,
        authority_digest: run.authority_digest.clone(),
        launch_tree_digest: provider.process_tree_digest.clone(),
        observed_at_unix,
        cleanup_covered,
        process_tree_digest: digest_process_tree(&process_tree)?,
        process_tree,
    };
    snapshot.validate()?;
    Ok(snapshot)
}

fn digest_process_tree(process_tree: &[ProcessIdentity]) -> Result<Digest, String> {
    let bytes = serde_json::to_vec(process_tree).map_err(|error| error.to_string())?;
    Digest::parse(format!("{:x}", Sha256::digest(bytes)))
}

fn initial_cleanup_tree(
    provider_pid: u32,
    provider_start_identity: &str,
    launch_tree: &[ProcessIdentity],
    current: &[ProcessIdentity],
) -> Option<Vec<ProcessIdentity>> {
    let live_provider = kernel_identity(current, provider_pid, provider_start_identity)?;
    let captured = capture_process_tree(live_provider.pid, current);
    if captured.is_empty()
        || captured.iter().any(|process| {
            process.quality != ProcessIdentityQuality::KernelBirthToken
                || process.start_identity.trim().is_empty()
                || process.process_group_id == 0
        })
    {
        return None;
    }
    let mut identities = launch_tree.to_vec();
    merge_process_tree(&mut identities, &captured);
    (identities.len() <= 1024).then_some(identities)
}

fn cleanup_absence_confirmed(
    snapshot: &BlockLossCleanupSnapshot,
    current: &[ProcessIdentity],
) -> bool {
    snapshot.cleanup_covered
        && crate::process::matching_processes(&snapshot.process_tree, current).is_empty()
}

fn contains_process_identities(tree: &[ProcessIdentity], required: &[ProcessIdentity]) -> bool {
    required.iter().all(|expected| {
        tree.iter().any(|actual| {
            actual.pid == expected.pid
                && actual.start_identity == expected.start_identity
                && actual.quality == expected.quality
        })
    })
}

fn merge_process_tree(target: &mut Vec<ProcessIdentity>, observed: &[ProcessIdentity]) {
    for process in observed {
        if let Some(existing) = target.iter_mut().find(|existing| {
            existing.pid == process.pid && existing.start_identity == process.start_identity
        }) {
            *existing = process.clone();
        } else {
            target.push(process.clone());
        }
    }
    target.sort_by(|left, right| {
        (left.pid, &left.start_identity).cmp(&(right.pid, &right.start_identity))
    });
}

fn extend_process_tree(
    cumulative: &[ProcessIdentity],
    current: &[ProcessIdentity],
) -> Result<Option<Vec<ProcessIdentity>>, String> {
    let mut extended = cumulative.to_vec();
    let mut known = cumulative
        .iter()
        .map(|process| (process.pid, process.start_identity.clone()))
        .collect::<BTreeSet<_>>();
    let historical_groups = cumulative
        .iter()
        .map(|process| process.process_group_id)
        .collect::<BTreeSet<_>>();
    let mut observed_groups = historical_groups.clone();
    loop {
        let before = extended.len();
        let live_roots = crate::process::matching_processes(&extended, current);
        if extended.iter().any(|expected| {
            current.iter().any(|actual| {
                actual.pid == expected.pid
                    && actual.start_identity == expected.start_identity
                    && actual.quality != ProcessIdentityQuality::KernelBirthToken
            })
        }) {
            return Ok(None);
        }
        let mut anchored_groups = BTreeSet::new();
        for root in &live_roots {
            if root.quality != ProcessIdentityQuality::KernelBirthToken {
                return Ok(None);
            }
            anchored_groups.insert(root.process_group_id);
            observed_groups.insert(root.process_group_id);
            merge_process_tree(&mut extended, &[root.clone()]);
            let captured = capture_process_tree(root.pid, current);
            if captured.iter().any(|process| {
                process.quality != ProcessIdentityQuality::KernelBirthToken
                    || process.start_identity.trim().is_empty()
                    || process.process_group_id == 0
            }) {
                return Ok(None);
            }
            for process in captured {
                observed_groups.insert(process.process_group_id);
                known.insert((process.pid, process.start_identity.clone()));
                merge_process_tree(&mut extended, &[process]);
            }
        }
        for process in current.iter().filter(|process| {
            historical_groups.contains(&process.process_group_id)
                || observed_groups.contains(&process.process_group_id)
        }) {
            let identity = (process.pid, process.start_identity.clone());
            if !known.contains(&identity) && !anchored_groups.contains(&process.process_group_id) {
                // A numeric PGID can be recycled. Without a live exact tracked member anchoring
                // the group, its occupants are ambiguous: retain ownership and never adopt/signal.
                return Ok(None);
            }
        }
        if extended.len() > 1024 {
            return Ok(None);
        }
        if extended.len() == before {
            break;
        }
    }
    Ok(Some(extended))
}

fn provider_tree_contains_wrapper(
    provider: &ObservedProviderStart,
    wrapper: &ObservedWrapperIdentity,
) -> bool {
    provider.process_tree.iter().any(|process| {
        process.pid == wrapper.pid && process.start_identity == wrapper.start_identity
    })
}

fn observe_provider_start(
    store: &mut ConfigStore,
    owner_generation: u64,
    pinned_rex: &RexCliTransport,
    run: &RecoverableAgentRun,
    wrapper: &ObservedWrapperIdentity,
    rex_instance: &str,
    process_table: &[ProcessIdentity],
) -> Result<AgentRecoveryDisposition, String> {
    let authority = &run.authority;
    if wrapper.rex_session_id != authority.rex_session_id
        || wrapper.rex_block_id != authority.rex_block_id
        || wrapper.runtime_binary_digest != authority.runtime_binary_digest
    {
        return Ok(AgentRecoveryDisposition::Unresolved {
            reason: RecoveryUnknown::WrapperIdentityMismatch,
        });
    }
    let qualification = store
        .provider_qualification(&authority.qualification_receipt_digest)?
        .ok_or_else(|| "Agent start qualification receipt is missing".to_owned())?;
    let window = TicketWindow {
        server_instance_id: rex_instance.to_owned(),
        session_id: authority.rex_session_id.clone(),
        window_id: authority.rex_window_id.clone(),
        label: String::new(),
        initial_block_id: Some(authority.rex_block_id.clone()),
        disposition: CreateDisposition::Existing,
    };
    let rex_observation = match pinned_rex.observe_process(
        &window,
        authority.agent_run_id.as_str(),
        &authority.rex_block_id,
    ) {
        Ok(observation) => observation,
        Err(_) => {
            return Ok(AgentRecoveryDisposition::Unresolved {
                reason: RecoveryUnknown::RexObservationUnavailable,
            });
        }
    };
    let Some(rex_wrapper) = rex_observation.child.as_ref() else {
        return Ok(AgentRecoveryDisposition::Unresolved {
            reason: RecoveryUnknown::WrapperIdentityMismatch,
        });
    };
    let Some(rex_provider) = rex_observation.foreground.as_ref() else {
        return Ok(AgentRecoveryDisposition::Unresolved {
            reason: RecoveryUnknown::ProviderIdentityMismatch,
        });
    };
    let expected_executable = std::fs::canonicalize(&qualification.executable_path).ok();
    if rex_observation.last_exit.is_some()
        || rex_wrapper.pid != wrapper.pid
        || rex_provider.pid == wrapper.pid
        || expected_executable.as_ref().is_none_or(|expected| {
            rex_provider
                .path
                .as_deref()
                .and_then(|path| std::fs::canonicalize(path).ok())
                .as_ref()
                != Some(expected)
        })
    {
        return Ok(AgentRecoveryDisposition::Unresolved {
            reason: RecoveryUnknown::ProviderIdentityMismatch,
        });
    }
    let Some(wrapper_process) =
        kernel_identity(process_table, wrapper.pid, &wrapper.start_identity)
    else {
        return Ok(AgentRecoveryDisposition::Unresolved {
            reason: RecoveryUnknown::WrapperIdentityMismatch,
        });
    };
    let Some(provider_process) = process_table.iter().find(|process| {
        process.pid == rex_provider.pid
            && process.quality == ProcessIdentityQuality::KernelBirthToken
            && std::fs::canonicalize(&process.command).ok() == expected_executable
    }) else {
        return Ok(AgentRecoveryDisposition::Unresolved {
            reason: RecoveryUnknown::ProviderIdentityMismatch,
        });
    };
    let tree = capture_process_tree(wrapper_process.pid, process_table);
    if tree.is_empty()
        || tree.iter().any(|process| {
            process.quality != ProcessIdentityQuality::KernelBirthToken
                || process.process_group_id == 0
        })
        || !tree.iter().any(|process| {
            process.pid == provider_process.pid
                && process.start_identity == provider_process.start_identity
        })
    {
        return Ok(AgentRecoveryDisposition::Unresolved {
            reason: RecoveryUnknown::ProcessInspectionUnavailable,
        });
    }
    let process_tree = tree
        .iter()
        .map(|process| crate::launch::ProviderProcessIdentity {
            pid: process.pid,
            parent_pid: process.parent_pid,
            process_group_id: process.process_group_id,
            start_identity: process.start_identity.clone(),
            identity_quality: process.quality,
        })
        .collect::<Vec<_>>();
    let observation = ObservedProviderStart {
        agent_run_id: authority.agent_run_id.clone(),
        operation_id: authority.operation_id.clone(),
        provider_pid: provider_process.pid,
        provider_start_identity: provider_process.start_identity.clone(),
        executable_digest: qualification.executable_digest.clone(),
        process_tree_digest: digest_json(&process_tree)?,
        process_tree_confirmed: true,
        process_tree,
    };
    observation.validate_complete_process_tree(&qualification)?;
    store.confirm_provider_started(owner_generation, &observation)?;
    Ok(AgentRecoveryDisposition::ProviderStarted)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HeartbeatStatus {
    Fresh,
    Stale,
    MissingOrInvalid,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Heartbeat {
    schema_version: u32,
    run_id: String,
    observed_at_unix: u64,
}

fn read_heartbeat(
    control_dir: &Path,
    expected_run: &str,
    now_unix: i64,
    stale_after_seconds: u64,
) -> HeartbeatStatus {
    let path = control_dir.join("heartbeat/heartbeat.json");
    let Ok(metadata) = fs::symlink_metadata(&path) else {
        return HeartbeatStatus::MissingOrInvalid;
    };
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_HEARTBEAT_BYTES
    {
        return HeartbeatStatus::MissingOrInvalid;
    }
    let Ok(bytes) = fs::read(path) else {
        return HeartbeatStatus::MissingOrInvalid;
    };
    let Ok(heartbeat) = crate::protocol::parse_unique::<Heartbeat>(&bytes) else {
        return HeartbeatStatus::MissingOrInvalid;
    };
    if heartbeat.schema_version != 1
        || heartbeat.run_id != expected_run
        || heartbeat.observed_at_unix > now_unix.max(0) as u64
    {
        return HeartbeatStatus::MissingOrInvalid;
    }
    if now_unix.saturating_sub(heartbeat.observed_at_unix as i64) <= stale_after_seconds as i64 {
        HeartbeatStatus::Fresh
    } else {
        HeartbeatStatus::Stale
    }
}

fn kernel_identity<'a>(
    process_table: &'a [ProcessIdentity],
    pid: u32,
    start_identity: &str,
) -> Option<&'a ProcessIdentity> {
    process_table.iter().find(|process| {
        process.pid == pid
            && process.start_identity == start_identity
            && process.quality == ProcessIdentityQuality::KernelBirthToken
    })
}

fn rex_processes_match(
    observation: &RexProcessObservation,
    wrapper: &ObservedWrapperIdentity,
    provider: &ObservedProviderStart,
) -> bool {
    observation.last_exit.is_none()
        && observation
            .child
            .as_ref()
            .is_some_and(|process| process.pid == wrapper.pid)
        && observation
            .foreground
            .as_ref()
            .is_some_and(|process| process.pid == provider.provider_pid)
}

fn digest_json(value: &impl serde::Serialize) -> Result<Digest, String> {
    let bytes = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    Digest::parse(format!("{:x}", Sha256::digest(bytes)))
}

fn digest_rex_observation(observation: &RexProcessObservation) -> Result<Digest, String> {
    let process = |process: &crate::adapters::rex::RexProcessInfo| {
        serde_json::json!({
            "pid": process.pid,
            "user_id": process.user_id,
            "name": process.name,
            "argv0": process.argv0,
            "path": process.path,
            "invoked_path": process.invoked_path,
            "script": process.script,
            "cwd": process.cwd,
            "user": process.user,
        })
    };
    let value = serde_json::json!({
        "last_exit": observation.last_exit.as_ref().map(|exit| serde_json::json!({
            "exit_code": exit.exit_code,
            "error": exit.error,
        })),
        "child": observation.child.as_ref().map(process),
        "foreground": observation.foreground.as_ref().map(process),
        "ancestors": observation.ancestors.as_ref().map(|items| items.iter().map(process).collect::<Vec<_>>()),
    });
    digest_json(&value)
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredProviderIdentity {
    provider_pid: u32,
    provider_start_identity: String,
    executable_digest: Digest,
    process_tree_digest: Digest,
    #[serde(default)]
    process_tree: Vec<crate::launch::ProviderProcessIdentity>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Child, Command};
    use std::time::{Duration, Instant};

    #[test]
    fn provider_tree_must_include_the_exact_wrapper_birth_identity() {
        let provider = ObservedProviderStart {
            agent_run_id: AgentRunId::parse("run-1").unwrap(),
            operation_id: crate::domain::ids::OperationId::parse("op-1").unwrap(),
            provider_pid: 22,
            provider_start_identity: "provider-born".into(),
            executable_digest: Digest::parse("a".repeat(64)).unwrap(),
            process_tree_digest: Digest::parse("b".repeat(64)).unwrap(),
            process_tree_confirmed: true,
            process_tree: vec![crate::launch::ProviderProcessIdentity {
                pid: 11,
                parent_pid: 1,
                process_group_id: 11,
                start_identity: "wrapper-born".into(),
                identity_quality: ProcessIdentityQuality::KernelBirthToken,
            }],
        };
        let wrapper = ObservedWrapperIdentity {
            pid: 11,
            start_identity: "wrapper-born".into(),
            rex_session_id: "session".into(),
            rex_block_id: "block".into(),
            runtime_binary_digest: Digest::parse("c".repeat(64)).unwrap(),
        };
        assert!(provider_tree_contains_wrapper(&provider, &wrapper));
        let reused_pid = ObservedWrapperIdentity {
            start_identity: "different-birth".into(),
            ..wrapper.clone()
        };
        assert!(!provider_tree_contains_wrapper(&provider, &reused_pid));
        let omitted_wrapper = ObservedWrapperIdentity { pid: 12, ..wrapper };
        assert!(!provider_tree_contains_wrapper(&provider, &omitted_wrapper));
    }

    fn policy() -> RecoveryPolicy {
        RecoveryPolicy {
            rex_session_id: "factory-session".into(),
            turn_timeout_seconds: BTreeMap::new(),
            heartbeat_stale_after_seconds: 30,
            max_observations_per_tick: 8,
            now_unix: 1_000,
        }
    }

    #[test]
    fn recovery_policy_enforces_a_hard_eight_run_bound() {
        assert!(policy().validate().is_ok());

        let mut too_many = policy();
        too_many.max_observations_per_tick = 9;
        assert!(too_many.validate().is_err());
    }

    #[test]
    fn recovery_policy_requires_pinned_session_and_positive_timeouts() {
        let mut unpinned = policy();
        unpinned.rex_session_id.clear();
        assert!(unpinned.validate().is_err());

        let mut invalid_timeout = policy();
        invalid_timeout
            .turn_timeout_seconds
            .insert(ProfileId::parse("worker").unwrap(), 0);
        assert!(invalid_timeout.validate().is_err());
    }

    #[test]
    fn heartbeat_is_unknown_when_missing_and_only_fresh_for_its_run() {
        let root = tempfile::tempdir().unwrap();
        let control_dir = root.path().join("control");
        fs::create_dir_all(control_dir.join("heartbeat")).unwrap();
        assert_eq!(
            read_heartbeat(&control_dir, "run-1", 1_000, 30),
            HeartbeatStatus::MissingOrInvalid
        );

        fs::write(
            control_dir.join("heartbeat/heartbeat.json"),
            r#"{"schema_version":1,"run_id":"other-run","observed_at_unix":990}"#,
        )
        .unwrap();
        assert_eq!(
            read_heartbeat(&control_dir, "run-1", 1_000, 30),
            HeartbeatStatus::MissingOrInvalid
        );

        fs::write(
            control_dir.join("heartbeat/heartbeat.json"),
            r#"{"schema_version":1,"run_id":"run-1","observed_at_unix":900}"#,
        )
        .unwrap();
        assert_eq!(
            read_heartbeat(&control_dir, "run-1", 1_000, 30),
            HeartbeatStatus::Stale
        );

        fs::write(
            control_dir.join("heartbeat/heartbeat.json"),
            r#"{"schema_version":1,"run_id":"run-1","observed_at_unix":990}"#,
        )
        .unwrap();
        assert_eq!(
            read_heartbeat(&control_dir, "run-1", 1_000, 30),
            HeartbeatStatus::Fresh
        );
    }

    #[cfg(unix)]
    #[test]
    fn block_loss_cleanup_tracks_late_new_group_child_and_leaves_unrelated_process_alone() {
        use std::os::unix::process::CommandExt;

        let root = tempfile::tempdir().unwrap();
        let marker = root.path().join("start-child");
        let child_pid_path = root.path().join("child.pid");
        let mut provider = spawn_late_child_provider(&marker, &child_pid_path);
        let provider_identity = wait_for_identity(provider.id());
        let launch_tree = vec![provider_identity.clone()];
        let initial = initial_cleanup_tree(
            provider.id(),
            &provider_identity.start_identity,
            &launch_tree,
            &inspect_process_table().unwrap(),
        )
        .unwrap();
        std::fs::write(&marker, b"go").unwrap();
        let child_pid = wait_for_pid_file(&child_pid_path);
        let child_identity = wait_for_identity(child_pid);
        assert_ne!(
            child_identity.process_group_id,
            provider_identity.process_group_id
        );

        let mut unrelated = Command::new("/bin/sleep")
            .arg("300")
            .process_group(0)
            .spawn()
            .unwrap();
        let unrelated_identity = wait_for_identity(unrelated.id());
        let current = inspect_process_table().unwrap();
        let cumulative = extend_process_tree(&initial, &current).unwrap().unwrap();
        assert!(contains_process_identities(
            &cumulative,
            &[child_identity.clone()]
        ));
        let snapshot = make_test_snapshot(cumulative.clone(), false);
        assert!(!cleanup_absence_confirmed(&snapshot, &current));

        for group_id in cumulative
            .iter()
            .map(|process| process.process_group_id)
            .collect::<BTreeSet<_>>()
        {
            signal_process_group_if_observed(
                group_id,
                &cumulative,
                &current,
                ProcessSignal::Terminate,
            )
            .unwrap();
        }
        let stopped = wait_until_processes_absent(&cumulative);
        assert!(stopped);
        let current = inspect_process_table().unwrap();
        let mut covered = snapshot;
        covered.cleanup_covered = true;
        assert!(cleanup_absence_confirmed(&covered, &current));
        assert!(
            !crate::process::matching_processes(
                std::slice::from_ref(&unrelated_identity),
                &current
            )
            .is_empty()
        );
        let _ = unrelated.kill();
        let _ = unrelated.wait();
        let _ = provider.wait();
    }

    #[cfg(unix)]
    #[test]
    fn block_loss_without_live_provider_capture_keeps_late_child_unknown() {
        let root = tempfile::tempdir().unwrap();
        let marker = root.path().join("start-child");
        let child_pid_path = root.path().join("child.pid");
        let mut provider = spawn_late_child_provider(&marker, &child_pid_path);
        let provider_identity = wait_for_identity(provider.id());
        let launch_tree = vec![provider_identity.clone()];
        let _initial_launch_capture = initial_cleanup_tree(
            provider.id(),
            &provider_identity.start_identity,
            &launch_tree,
            &inspect_process_table().unwrap(),
        )
        .unwrap();
        std::fs::write(&marker, b"go").unwrap();
        let child_pid = wait_for_pid_file(&child_pid_path);
        let child_identity = wait_for_identity(child_pid);
        signal_process_group_if_observed(
            provider_identity.process_group_id,
            std::slice::from_ref(&provider_identity),
            &inspect_process_table().unwrap(),
            ProcessSignal::Terminate,
        )
        .unwrap();
        assert!(wait_until_processes_absent(std::slice::from_ref(
            &provider_identity
        )));
        let current = inspect_process_table().unwrap();
        assert!(
            crate::process::matching_processes(std::slice::from_ref(&child_identity), &current)
                .len()
                == 1
        );
        assert!(
            initial_cleanup_tree(
                provider.id(),
                &provider_identity.start_identity,
                &launch_tree,
                &current,
            )
            .is_none()
        );
        // The fixture owns this deliberately unresolved child; explicitly clean it up.
        signal_process_group_if_observed(
            child_identity.process_group_id,
            std::slice::from_ref(&child_identity),
            &current,
            ProcessSignal::Kill,
        )
        .unwrap();
        assert!(wait_until_processes_absent(std::slice::from_ref(
            &child_identity
        )));
        let _ = provider.wait();
    }

    #[cfg(unix)]
    #[test]
    fn block_loss_snapshot_can_miss_child_forked_before_cleanup_signal() {
        let root = tempfile::tempdir().unwrap();
        let marker = root.path().join("start-child");
        let child_pid_path = root.path().join("child.pid");
        let spool_dir = root.path().join("control");
        std::fs::create_dir(&spool_dir).unwrap();
        let spool = RunStepSpool::open(&spool_dir).unwrap();
        let mut provider = TrackedChild::new(spawn_late_child_provider(&marker, &child_pid_path));
        let provider_identity = wait_for_identity(provider.id());
        let launch_tree = vec![provider_identity.clone()];
        let sampled_process_table = inspect_process_table().unwrap();
        let sampled_tree = initial_cleanup_tree(
            provider.id(),
            &provider_identity.start_identity,
            &launch_tree,
            &sampled_process_table,
        )
        .unwrap();
        let mut snapshot = make_test_snapshot(sampled_tree, false);
        spool.write_block_loss_cleanup_snapshot(&snapshot).unwrap();

        // This creates the descendant strictly after the production capture, but before its
        // signal operation. Job control puts the child in a different process group.
        std::fs::write(&marker, b"go").unwrap();
        let child_identity =
            TrackedProcess::new(wait_for_identity(wait_for_pid_file(&child_pid_path)));
        let distinct_group =
            child_identity.identity.process_group_id != provider_identity.process_group_id;

        // Match the production ordering: use the earlier process-table sample to signal only
        // identities visible when the snapshot was taken.
        let signal_observed = signal_process_group_if_observed(
            provider_identity.process_group_id,
            &snapshot.process_tree,
            &sampled_process_table,
            ProcessSignal::Terminate,
        )
        .unwrap();
        let provider_gone = wait_until_processes_absent(std::slice::from_ref(&provider_identity));
        let child_survives = !crate::process::matching_processes(
            std::slice::from_ref(&child_identity.identity),
            &inspect_process_table().unwrap(),
        )
        .is_empty();
        snapshot.cleanup_covered = signal_observed;
        snapshot.observed_at_unix += 1;
        spool.write_block_loss_cleanup_snapshot(&snapshot).unwrap();

        // Match the next production observation: extend from a fresh process table and apply
        // the same release predicate.
        let stored = spool.read_block_loss_cleanup_snapshot().unwrap().unwrap();
        let next_process_table = inspect_process_table().unwrap();
        let next_tree = extend_process_tree(&stored.process_tree, &next_process_table)
            .unwrap()
            .unwrap();
        let mut next_snapshot = stored;
        next_snapshot.process_tree = next_tree;
        next_snapshot.process_tree_digest =
            digest_process_tree(&next_snapshot.process_tree).unwrap();
        let cleanup_would_release = cleanup_absence_confirmed(&next_snapshot, &next_process_table);

        // The test owns this child, including the deliberately uncovered race case.
        signal_process_group_if_observed(
            child_identity.identity.process_group_id,
            std::slice::from_ref(&child_identity.identity),
            &inspect_process_table().unwrap(),
            ProcessSignal::Kill,
        )
        .unwrap();
        let child_cleaned =
            wait_until_processes_absent(std::slice::from_ref(&child_identity.identity));
        let _ = provider.wait();

        assert!(
            distinct_group,
            "child must be outside the sampled process group"
        );
        assert!(
            signal_observed,
            "sampled provider group should receive cleanup signal"
        );
        assert!(
            provider_gone,
            "the tracked provider should exit after the signal"
        );
        assert!(
            child_survives,
            "the new-group child should survive the stale-sample signal"
        );
        assert!(child_cleaned, "the test must explicitly clean up its child");
        assert!(
            !cleanup_would_release,
            "cleanup must not release while the untracked child survives"
        );
    }

    #[cfg(unix)]
    struct TrackedChild(Child);

    #[cfg(unix)]
    impl TrackedChild {
        fn new(child: Child) -> Self {
            Self(child)
        }

        fn id(&self) -> u32 {
            self.0.id()
        }

        fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
            self.0.wait()
        }
    }

    #[cfg(unix)]
    impl Drop for TrackedChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[cfg(unix)]
    struct TrackedProcess {
        identity: ProcessIdentity,
    }

    #[cfg(unix)]
    impl TrackedProcess {
        fn new(identity: ProcessIdentity) -> Self {
            Self { identity }
        }
    }

    #[cfg(unix)]
    impl Drop for TrackedProcess {
        fn drop(&mut self) {
            if let Ok(current) = inspect_process_table() {
                let _ = signal_process_group_if_observed(
                    self.identity.process_group_id,
                    std::slice::from_ref(&self.identity),
                    &current,
                    ProcessSignal::Kill,
                );
            }
        }
    }

    #[cfg(unix)]
    fn spawn_late_child_provider(marker: &std::path::Path, child_pid: &std::path::Path) -> Child {
        use std::os::unix::process::CommandExt;

        let script = format!(
            "while [ ! -f '{}' ]; do :; done; set -m; /bin/sleep 300 & echo $! > '{}'; wait",
            marker.display(),
            child_pid.display(),
        );
        Command::new("/bin/sh")
            .arg("-c")
            .arg(script)
            .process_group(0)
            .spawn()
            .unwrap()
    }

    #[cfg(unix)]
    fn wait_for_identity(pid: u32) -> ProcessIdentity {
        wait_until(|| {
            inspect_process_table().ok()?.into_iter().find(|process| {
                process.pid == pid && process.quality == ProcessIdentityQuality::KernelBirthToken
            })
        })
        .expect("process identity should become observable")
    }

    #[cfg(unix)]
    fn wait_for_pid_file(path: &std::path::Path) -> u32 {
        wait_until(|| std::fs::read_to_string(path).ok()?.trim().parse().ok())
            .expect("child PID should be published")
    }

    #[cfg(unix)]
    fn wait_until<T>(mut observe: impl FnMut() -> Option<T>) -> Option<T> {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if let Some(value) = observe() {
                return Some(value);
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[cfg(unix)]
    fn wait_until_processes_absent(processes: &[ProcessIdentity]) -> bool {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let Ok(current) = inspect_process_table() else {
                return false;
            };
            if crate::process::matching_processes(processes, &current).is_empty() {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn make_test_snapshot(
        process_tree: Vec<ProcessIdentity>,
        cleanup_covered: bool,
    ) -> BlockLossCleanupSnapshot {
        let process_tree_digest = digest_process_tree(&process_tree).unwrap();
        BlockLossCleanupSnapshot {
            schema_version: 1,
            agent_run_id: AgentRunId::parse("run-test").unwrap(),
            reservation_epoch: 1,
            authority_digest: Digest::parse("a".repeat(64)).unwrap(),
            launch_tree_digest: Digest::parse("b".repeat(64)).unwrap(),
            observed_at_unix: 1,
            cleanup_covered,
            process_tree,
            process_tree_digest,
        }
    }
}
