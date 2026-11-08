//! Reconcile live finite Agent turns after the machine controller changes owner.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
#[cfg(target_os = "macos")]
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};

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
    executable_path_for_identity, inspect_process_table, signal_process_group_if_observed,
};
use crate::run_step_spool::{BlockLossCleanupSnapshot, RunFamilyCoverage, RunStepSpool};
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

pub(crate) fn observe_after_recovery_marker(
    store: &mut ConfigStore,
    owner_generation: u64,
    run: &RecoverableAgentRun,
    observed_at_unix: i64,
    observe: impl FnOnce(&mut ConfigStore) -> Result<AgentRecoveryDisposition, String>,
) -> Result<AgentRecoveryDisposition, String> {
    store.record_agent_recovery_observation(
        owner_generation,
        &run.agent_run_id,
        run.reservation_epoch,
        observed_at_unix,
    )?;
    observe(store)
}

const MAX_FORK_WATCH_RUNS: usize = 64;
const MAX_FORK_WATCH_IDENTITIES: usize = 1024;

#[derive(Default)]
pub struct AgentRecoveryRuntime {
    fork_watches: BTreeMap<AgentRunId, RunForkWatch>,
}

struct RunForkWatch {
    authority_digest: Digest,
    reservation_epoch: u64,
    launch_tree_digest: Digest,
    watched: BTreeMap<(u32, String), ProcessIdentity>,
    invalidated: bool,
    #[cfg(target_os = "macos")]
    queue_fd: Option<RawFd>,
}

impl RunForkWatch {
    fn new(authority_digest: &Digest, reservation_epoch: u64, launch_tree_digest: &Digest) -> Self {
        #[cfg(target_os = "macos")]
        let queue_fd = unsafe {
            let fd = libc::kqueue();
            if fd < 0 || libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) < 0 {
                if fd >= 0 {
                    libc::close(fd);
                }
                None
            } else {
                Some(fd)
            }
        };
        #[cfg(not(target_os = "macos"))]
        let invalidated = true;
        #[cfg(target_os = "macos")]
        let invalidated = queue_fd.is_none();
        Self {
            authority_digest: authority_digest.clone(),
            reservation_epoch,
            launch_tree_digest: launch_tree_digest.clone(),
            watched: BTreeMap::new(),
            invalidated,
            #[cfg(target_os = "macos")]
            queue_fd,
        }
    }

    fn matches(
        &self,
        authority_digest: &Digest,
        reservation_epoch: u64,
        launch_tree_digest: &Digest,
    ) -> bool {
        self.authority_digest == *authority_digest
            && self.reservation_epoch == reservation_epoch
            && self.launch_tree_digest == *launch_tree_digest
    }

    fn unavailable(
        authority_digest: &Digest,
        reservation_epoch: u64,
        launch_tree_digest: &Digest,
    ) -> Self {
        Self {
            authority_digest: authority_digest.clone(),
            reservation_epoch,
            launch_tree_digest: launch_tree_digest.clone(),
            watched: BTreeMap::new(),
            invalidated: true,
            #[cfg(target_os = "macos")]
            queue_fd: None,
        }
    }

    fn covers_sample(
        &self,
        provider_pid: u32,
        provider_birth: &str,
        tracked: &[ProcessIdentity],
        current: &[ProcessIdentity],
    ) -> bool {
        !self.invalidated
            && (self
                .watched
                .contains_key(&(provider_pid, provider_birth.to_owned()))
                || crate::process::matching_processes(tracked, current).is_empty())
    }

    fn arm(&mut self, processes: &[ProcessIdentity], current: &[ProcessIdentity]) -> bool {
        if self.invalidated || processes.len() > MAX_FORK_WATCH_IDENTITIES {
            return false;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (processes, current);
            self.invalidated = true;
            return false;
        }
        #[cfg(target_os = "macos")]
        {
            let Some(queue_fd) = self.queue_fd else {
                self.invalidated = true;
                return false;
            };
            let mut newly_watched = Vec::new();
            for process in processes {
                if process.quality != ProcessIdentityQuality::KernelBirthToken
                    || process.start_identity.trim().is_empty()
                {
                    self.invalidated = true;
                    continue;
                }
                let key = (process.pid, process.start_identity.clone());
                if self.watched.contains_key(&key) {
                    continue;
                }
                if self.watched.keys().any(|(pid, _)| *pid == process.pid) {
                    self.invalidated = true;
                    continue;
                }
                let Some(actual) = kernel_identity(current, process.pid, &process.start_identity)
                else {
                    // Exited identities cannot fork; live identities are rechecked after registration.
                    continue;
                };
                let mut event: libc::kevent = unsafe { std::mem::zeroed() };
                event.ident = actual.pid as libc::uintptr_t;
                event.filter = libc::EVFILT_PROC;
                event.flags = libc::EV_ADD | libc::EV_CLEAR;
                event.fflags = libc::NOTE_FORK | libc::NOTE_EXIT;
                let result = unsafe {
                    libc::kevent(
                        queue_fd,
                        &event,
                        1,
                        std::ptr::null_mut(),
                        0,
                        std::ptr::null(),
                    )
                };
                if result < 0 {
                    self.invalidated = true;
                    continue;
                }
                self.watched.insert(key.clone(), actual.clone());
                newly_watched.push(key);
            }
            if !newly_watched.is_empty() {
                match inspect_process_table() {
                    Ok(after_register) => {
                        for (pid, birth) in newly_watched {
                            if kernel_identity(&after_register, pid, &birth).is_none() {
                                self.invalidated = true;
                            }
                        }
                    }
                    Err(_) => self.invalidated = true,
                }
            }
            self.drain_events() && !self.invalidated
        }
    }

    fn drain_events(&mut self) -> bool {
        if self.invalidated {
            return false;
        }
        #[cfg(not(target_os = "macos"))]
        {
            self.invalidated = true;
            false
        }
        #[cfg(target_os = "macos")]
        {
            let Some(queue_fd) = self.queue_fd else {
                self.invalidated = true;
                return false;
            };
            let mut events = [unsafe { std::mem::zeroed::<libc::kevent>() }; 64];
            let timeout = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            loop {
                let count = unsafe {
                    libc::kevent(
                        queue_fd,
                        std::ptr::null(),
                        0,
                        events.as_mut_ptr(),
                        events.len() as libc::c_int,
                        &timeout,
                    )
                };
                if count < 0 {
                    self.invalidated = true;
                    return false;
                }
                if count == 0 {
                    break;
                }
                for event in events.iter().take(count as usize) {
                    let flags = unsafe { std::ptr::addr_of!(event.flags).read_unaligned() };
                    let fflags = unsafe { std::ptr::addr_of!(event.fflags).read_unaligned() };
                    if flags & libc::EV_ERROR != 0
                        || fflags & libc::NOTE_FORK != 0
                        || fflags & !(libc::NOTE_EXIT) != 0
                    {
                        self.invalidated = true;
                    }
                }
                if self.invalidated || count < events.len() as libc::c_int {
                    break;
                }
            }
            !self.invalidated
        }
    }

    fn seal_cleanup_if_absent(
        &mut self,
        snapshot: &mut BlockLossCleanupSnapshot,
        fresh_process_table: &[ProcessIdentity],
    ) -> bool {
        if !self.drain_events()
            || self.invalidated
            || !crate::process::matching_processes(&snapshot.process_tree, fresh_process_table)
                .is_empty()
        {
            return false;
        }
        snapshot.cleanup_covered = true;
        true
    }
}

#[cfg(target_os = "macos")]
impl Drop for RunForkWatch {
    fn drop(&mut self) {
        if let Some(queue_fd) = self.queue_fd.take() {
            unsafe { libc::close(queue_fd) };
        }
    }
}

impl AgentRecoveryRuntime {
    fn run_fork_watch(
        &mut self,
        run: &RecoverableAgentRun,
        launch_tree_digest: &Digest,
        snapshot_exists: bool,
    ) -> Option<&mut RunForkWatch> {
        if !self.fork_watches.contains_key(&run.agent_run_id) {
            if self.fork_watches.len() >= MAX_FORK_WATCH_RUNS {
                return None;
            }
            let watch = if snapshot_exists {
                RunForkWatch::unavailable(
                    &run.authority_digest,
                    run.reservation_epoch,
                    launch_tree_digest,
                )
            } else {
                RunForkWatch::new(
                    &run.authority_digest,
                    run.reservation_epoch,
                    launch_tree_digest,
                )
            };
            self.fork_watches.insert(run.agent_run_id.clone(), watch);
        }
        let watch = self.fork_watches.get_mut(&run.agent_run_id)?;
        if !watch.matches(
            &run.authority_digest,
            run.reservation_epoch,
            launch_tree_digest,
        ) {
            watch.invalidated = true;
        }
        Some(watch)
    }

    fn watch_live_run_tree(
        &mut self,
        run: &RecoverableAgentRun,
        provider: &ObservedProviderStart,
        process_tree: &[ProcessIdentity],
        current: &[ProcessIdentity],
    ) -> bool {
        // A controller restart cannot prove continuous coverage across a cleanup snapshot.
        // Existing in-memory watches remain valid: they are the proof that preceded it.
        let snapshot_exists = RunStepSpool::open(&run.authority.control_dir)
            .and_then(|spool| spool.read_block_loss_cleanup_snapshot())
            .map(|snapshot| snapshot.is_some())
            .unwrap_or(true);
        let Some(watch) = self.run_fork_watch(run, &provider.process_tree_digest, snapshot_exists)
        else {
            return false;
        };
        if watch.invalidated || !watch.arm(process_tree, current) {
            watch.invalidated = true;
            return false;
        }
        let mut tracked = process_tree.to_vec();
        for _ in 0..16 {
            let fresh = match inspect_process_table() {
                Ok(processes) => processes,
                Err(_) => {
                    watch.invalidated = true;
                    return false;
                }
            };
            let Some(extended) = extend_process_tree(&tracked, &fresh).unwrap_or_default() else {
                watch.invalidated = true;
                return false;
            };
            if extended.len() > MAX_FORK_WATCH_IDENTITIES
                || !watch.arm(&extended, &fresh)
                || !watch.drain_events()
            {
                watch.invalidated = true;
                return false;
            }
            tracked = extended;
            let after = match inspect_process_table() {
                Ok(processes) => processes,
                Err(_) => {
                    watch.invalidated = true;
                    return false;
                }
            };
            let Some(after_tree) = extend_process_tree(&tracked, &after).unwrap_or_default() else {
                watch.invalidated = true;
                return false;
            };
            if after_tree.len() > MAX_FORK_WATCH_IDENTITIES {
                watch.invalidated = true;
                return false;
            }
            let all_live_identities_watched = after_tree.iter().all(|process| {
                kernel_identity(&after, process.pid, &process.start_identity).is_none()
                    || watch
                        .watched
                        .contains_key(&(process.pid, process.start_identity.clone()))
            });
            let provider_watched = watch.watched.contains_key(&(
                provider.provider_pid,
                provider.provider_start_identity.clone(),
            ));
            if after_tree.len() == tracked.len()
                && all_live_identities_watched
                && provider_watched
                && watch.drain_events()
                && watch.covers_sample(
                    provider.provider_pid,
                    &provider.provider_start_identity,
                    &tracked,
                    &after,
                )
            {
                return true;
            }
            tracked = after_tree;
        }
        watch.invalidated = true;
        false
    }

    /// Observe a finite, ordered subset of unknown/live runs. A failed or ambiguous observation
    /// never releases a slot and never authorizes a replacement turn.
    pub fn tick(
        &mut self,
        store: &mut ConfigStore,
        owner_generation: u64,
        pinned_rex: &RexCliTransport,
        policy: &RecoveryPolicy,
    ) -> Result<AgentRecoveryReport, String> {
        policy.validate()?;
        let runs =
            store.recoverable_agent_runs(owner_generation, policy.max_observations_per_tick + 1)?;
        let active_runs = store.recoverable_agent_runs(owner_generation, 128)?;
        if active_runs.len() < 128 {
            let active_ids = active_runs
                .iter()
                .map(|run| run.agent_run_id.clone())
                .collect::<BTreeSet<_>>();
            self.fork_watches
                .retain(|agent_run_id, _| active_ids.contains(agent_run_id));
        }
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
            let disposition = observe_after_recovery_marker(
                store,
                owner_generation,
                &run,
                policy.now_unix,
                |store| {
                    if let Some(processes) = &process_table {
                        self.observe_one(
                            store,
                            owner_generation,
                            pinned_rex,
                            policy,
                            &run,
                            rex_instance,
                            processes,
                        )
                    } else {
                        Ok(AgentRecoveryDisposition::Unresolved {
                            reason: RecoveryUnknown::ProcessInspectionUnavailable,
                        })
                    }
                },
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

    #[allow(clippy::too_many_arguments)]
    fn observe_one(
        &mut self,
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
                    self,
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
                process.pid == wrapper_process.pid
                    && process.start_identity == wrapper_process.start_identity
            })
            || !process_tree.iter().any(|process| {
                process.pid == provider_process.pid
                    && process.start_identity == provider_process.start_identity
            })
        {
            return Ok(AgentRecoveryDisposition::Unresolved {
                reason: RecoveryUnknown::ProcessInspectionUnavailable,
            });
        }
        // Establish continuous fork/exit observation while Rex still confirms the block and
        // every identity is present. A missing, malformed, or already-existing cleanup snapshot
        // prevents a newly created watch from being treated as continuous proof.
        self.watch_live_run_tree(run, &provider, &process_tree, process_table);
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

#[allow(clippy::too_many_arguments)]
fn reconcile_missing_block(
    runtime: &mut AgentRecoveryRuntime,
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
    let family = spool
        .read_run_family_record()
        .ok()
        .flatten()
        .filter(|family| {
            family.binding.agent_run_id == run.agent_run_id
                && family.binding.reservation_epoch == run.reservation_epoch
                && family.binding.authority_digest == run.authority_digest
                && family.binding.descriptor_digest == run.authority.descriptor_digest
                && family.binding.wrapper_pid == wrapper.pid
                && family.binding.wrapper_start_identity == wrapper.start_identity
                && family.provider_root.pid == provider.provider_pid
                && family.provider_root.start_identity == provider.provider_start_identity
                && family.provider_root.quality == ProcessIdentityQuality::KernelBirthToken
                && launch_tree.iter().any(|process| {
                    process.pid == family.provider_root.pid
                        && process.start_identity == family.provider_root.start_identity
                        && process.process_group_id == family.provider_root.process_group_id
                        && process.quality == family.provider_root.quality
                })
        });
    let producer_complete = family
        .as_ref()
        .is_some_and(|family| family.coverage == RunFamilyCoverage::Complete);
    let snapshot_exists = existing_snapshot.is_some();
    let mut snapshot = match existing_snapshot {
        Some(mut snapshot) => {
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
            let family_was_already_recorded = family.as_ref().is_none_or(|family| {
                contains_process_identities(&snapshot.process_tree, &family.process_tree)
            });
            if let Some(family) = &family {
                merge_process_tree(&mut snapshot.process_tree, &family.process_tree);
            }
            if snapshot.process_tree.len() > MAX_FORK_WATCH_IDENTITIES {
                return Ok(AgentRecoveryDisposition::Unresolved {
                    reason: RecoveryUnknown::ProcessInspectionUnavailable,
                });
            }
            snapshot.observed_at_unix = snapshot.observed_at_unix.max(policy.now_unix);
            snapshot.process_tree_digest = match digest_process_tree(&snapshot.process_tree) {
                Ok(digest) => digest,
                Err(_) => {
                    return Ok(AgentRecoveryDisposition::Unresolved {
                        reason: RecoveryUnknown::ProcessInspectionUnavailable,
                    });
                }
            };
            if !producer_complete || !family_was_already_recorded {
                snapshot.cleanup_covered = false;
            }
            if snapshot.cleanup_covered {
                let Some(fresh) = inspect_process_table().ok() else {
                    return Ok(AgentRecoveryDisposition::Unresolved {
                        reason: RecoveryUnknown::ProcessInspectionUnavailable,
                    });
                };
                if cleanup_absence_confirmed(&snapshot, &fresh) {
                    let released = store.reconcile_missing_agent_block(
                        owner_generation,
                        run,
                        policy.now_unix,
                        &snapshot,
                        &[],
                    )?;
                    if released {
                        runtime.fork_watches.remove(&run.agent_run_id);
                        return Ok(AgentRecoveryDisposition::BlockLossTerminal);
                    }
                }
                return Ok(AgentRecoveryDisposition::Unresolved {
                    reason: RecoveryUnknown::ProcessInspectionUnavailable,
                });
            }
            snapshot
        }
        None => {
            let mut process_tree = launch_tree.clone();
            if let Some(family) = &family {
                merge_process_tree(&mut process_tree, &family.process_tree);
            }
            make_block_loss_snapshot(run, provider, process_tree, policy.now_unix, false)?
        }
    };
    if !producer_complete {
        return stop_known_processes_without_watch(
            store,
            run,
            owner_generation,
            policy,
            &spool,
            snapshot,
            current,
            RecoveryUnknown::ProcessInspectionUnavailable,
        );
    }
    if runtime
        .run_fork_watch(run, &provider.process_tree_digest, snapshot_exists)
        .is_none()
    {
        return stop_known_processes_without_watch(
            store,
            run,
            owner_generation,
            policy,
            &spool,
            snapshot,
            current,
            RecoveryUnknown::ProcessInspectionUnavailable,
        );
    }
    let mut watch_healthy = !runtime
        .fork_watches
        .get(&run.agent_run_id)
        .is_some_and(|watch| watch.invalidated);
    let registration_table = inspect_process_table().unwrap_or_else(|_| current.to_vec());
    let watch_seed = if snapshot_exists {
        snapshot.process_tree.as_slice()
    } else {
        launch_tree.as_slice()
    };
    {
        let watch = runtime.fork_watches.get_mut(&run.agent_run_id).unwrap();
        watch_healthy &= watch.arm(watch_seed, &registration_table);
    }
    let fresh = match inspect_process_table() {
        Ok(processes) => processes,
        Err(_) => {
            runtime
                .fork_watches
                .get_mut(&run.agent_run_id)
                .unwrap()
                .invalidated = true;
            return stop_known_processes_without_watch(
                store,
                run,
                owner_generation,
                policy,
                &spool,
                snapshot,
                current,
                RecoveryUnknown::ProcessInspectionUnavailable,
            );
        }
    };
    {
        let watch = runtime.fork_watches.get_mut(&run.agent_run_id).unwrap();
        watch_healthy &= watch.arm(watch_seed, &fresh);
        watch_healthy &= watch.drain_events();
        if !watch.covers_sample(
            provider.provider_pid,
            &provider.provider_start_identity,
            &snapshot.process_tree,
            &fresh,
        ) {
            watch_healthy = false;
        }
    }
    let Some(extended) = extend_process_tree(&snapshot.process_tree, &fresh).unwrap_or_default()
    else {
        if let Some(watch) = runtime.fork_watches.get_mut(&run.agent_run_id) {
            watch.invalidated = true;
        }
        return stop_known_processes_without_watch(
            store,
            run,
            owner_generation,
            policy,
            &spool,
            snapshot,
            &fresh,
            RecoveryUnknown::ProcessInspectionUnavailable,
        );
    };
    if extended.len() > MAX_FORK_WATCH_IDENTITIES {
        if let Some(watch) = runtime.fork_watches.get_mut(&run.agent_run_id) {
            watch.invalidated = true;
        }
        return Ok(AgentRecoveryDisposition::Unresolved {
            reason: RecoveryUnknown::ProcessInspectionUnavailable,
        });
    }
    snapshot.process_tree = extended;
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
    // Watch every live identity discovered by this sample before persisting it or signalling.
    if let Some(watch) = runtime.fork_watches.get_mut(&run.agent_run_id) {
        watch_healthy &= watch.arm(&snapshot.process_tree, &fresh);
        watch_healthy &= watch.drain_events();
    } else {
        watch_healthy = false;
    }
    snapshot.cleanup_covered = false;
    if spool.write_block_loss_cleanup_snapshot(&snapshot).is_err() {
        return Ok(AgentRecoveryDisposition::Unresolved {
            reason: RecoveryUnknown::ProcessInspectionUnavailable,
        });
    }
    let mut survivors = crate::process::matching_processes(&snapshot.process_tree, &fresh);
    if !survivors.is_empty() {
        // Persist the observed survivor before signalling: a fast TERM exit must still leave
        // the process-survived fact and the original escalation clock in the store.
        store.reconcile_missing_agent_block(
            owner_generation,
            run,
            policy.now_unix,
            &snapshot,
            &survivors,
        )?;
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
        for group_id in groups {
            if signal_process_group_if_observed(group_id, &snapshot.process_tree, &fresh, signal)
                .is_err()
            {
                watch_healthy = false;
            }
        }
    }
    if let Some(watch) = runtime.fork_watches.get_mut(&run.agent_run_id) {
        watch_healthy &= watch.drain_events();
    } else {
        watch_healthy = false;
    }
    let final_table = match inspect_process_table() {
        Ok(processes) => processes,
        Err(_) => {
            return store_survival_or_unresolved(
                store,
                owner_generation,
                run,
                policy.now_unix,
                &snapshot,
                &survivors,
            );
        }
    };
    let Some(final_tree) =
        extend_process_tree(&snapshot.process_tree, &final_table).unwrap_or_default()
    else {
        if let Some(watch) = runtime.fork_watches.get_mut(&run.agent_run_id) {
            watch.invalidated = true;
        }
        return store_survival_or_unresolved(
            store,
            owner_generation,
            run,
            policy.now_unix,
            &snapshot,
            &survivors,
        );
    };
    if final_tree.len() > MAX_FORK_WATCH_IDENTITIES {
        return store_survival_or_unresolved(
            store,
            owner_generation,
            run,
            policy.now_unix,
            &snapshot,
            &survivors,
        );
    }
    snapshot.process_tree = final_tree;
    survivors = crate::process::matching_processes(&snapshot.process_tree, &final_table);
    if let Some(watch) = runtime.fork_watches.get_mut(&run.agent_run_id) {
        watch_healthy &= watch.arm(&snapshot.process_tree, &final_table);
        watch_healthy &= watch.drain_events();
        watch_healthy &= !watch.invalidated;
    } else {
        watch_healthy = false;
    }
    if !survivors.is_empty() {
        snapshot.process_tree_digest = match digest_process_tree(&snapshot.process_tree) {
            Ok(digest) => digest,
            Err(_) => {
                return Ok(AgentRecoveryDisposition::Unresolved {
                    reason: RecoveryUnknown::ProcessInspectionUnavailable,
                });
            }
        };
        snapshot.observed_at_unix = policy.now_unix;
        if spool.write_block_loss_cleanup_snapshot(&snapshot).is_err() {
            return Ok(AgentRecoveryDisposition::Unresolved {
                reason: RecoveryUnknown::ProcessInspectionUnavailable,
            });
        }
        return store_survival_or_unresolved(
            store,
            owner_generation,
            run,
            policy.now_unix,
            &snapshot,
            &survivors,
        );
    }
    let sealed = runtime
        .fork_watches
        .get_mut(&run.agent_run_id)
        .is_some_and(|watch| {
            watch_healthy && watch.seal_cleanup_if_absent(&mut snapshot, &final_table)
        });
    if !sealed {
        snapshot.process_tree_digest = match digest_process_tree(&snapshot.process_tree) {
            Ok(digest) => digest,
            Err(_) => {
                return Ok(AgentRecoveryDisposition::Unresolved {
                    reason: RecoveryUnknown::ProcessInspectionUnavailable,
                });
            }
        };
        snapshot.observed_at_unix = policy.now_unix;
        let _ = spool.write_block_loss_cleanup_snapshot(&snapshot);
        return Ok(AgentRecoveryDisposition::Unresolved {
            reason: RecoveryUnknown::ProcessInspectionUnavailable,
        });
    }
    snapshot.process_tree_digest = match digest_process_tree(&snapshot.process_tree) {
        Ok(digest) => digest,
        Err(_) => {
            return Ok(AgentRecoveryDisposition::Unresolved {
                reason: RecoveryUnknown::ProcessInspectionUnavailable,
            });
        }
    };
    snapshot.observed_at_unix = policy.now_unix;
    if spool.write_block_loss_cleanup_snapshot(&snapshot).is_err() {
        return Ok(AgentRecoveryDisposition::Unresolved {
            reason: RecoveryUnknown::ProcessInspectionUnavailable,
        });
    }
    let released = store.reconcile_missing_agent_block(
        owner_generation,
        run,
        policy.now_unix,
        &snapshot,
        &[],
    )?;
    if released {
        runtime.fork_watches.remove(&run.agent_run_id);
        return Ok(AgentRecoveryDisposition::BlockLossTerminal);
    }
    Ok(AgentRecoveryDisposition::BlockLossStopping)
}

#[allow(clippy::too_many_arguments)]
fn stop_known_processes_without_watch(
    store: &mut ConfigStore,
    run: &RecoverableAgentRun,
    owner_generation: u64,
    policy: &RecoveryPolicy,
    spool: &RunStepSpool,
    mut snapshot: BlockLossCleanupSnapshot,
    current: &[ProcessIdentity],
    reason: RecoveryUnknown,
) -> Result<AgentRecoveryDisposition, String> {
    snapshot.cleanup_covered = false;
    let _ = spool.write_block_loss_cleanup_snapshot(&snapshot);
    let survivors = crate::process::matching_processes(&snapshot.process_tree, current);
    if !survivors.is_empty() {
        let signal = if store.missing_block_survival_age_seconds(run, policy.now_unix)? >= 3 {
            ProcessSignal::Kill
        } else {
            ProcessSignal::Terminate
        };
        for group_id in snapshot
            .process_tree
            .iter()
            .map(|process| process.process_group_id)
            .collect::<BTreeSet<_>>()
        {
            let _ =
                signal_process_group_if_observed(group_id, &snapshot.process_tree, current, signal);
        }
        return store_survival_or_unresolved(
            store,
            owner_generation,
            run,
            policy.now_unix,
            &snapshot,
            &survivors,
        );
    }
    Ok(AgentRecoveryDisposition::Unresolved { reason })
}

fn store_survival_or_unresolved(
    store: &mut ConfigStore,
    owner_generation: u64,
    run: &RecoverableAgentRun,
    observed_at_unix: i64,
    snapshot: &BlockLossCleanupSnapshot,
    survivors: &[ProcessIdentity],
) -> Result<AgentRecoveryDisposition, String> {
    if !survivors.is_empty() {
        store.reconcile_missing_agent_block(
            owner_generation,
            run,
            observed_at_unix,
            snapshot,
            survivors,
        )?;
        return Ok(AgentRecoveryDisposition::BlockLossStopping);
    }
    Ok(AgentRecoveryDisposition::Unresolved {
        reason: RecoveryUnknown::ProcessInspectionUnavailable,
    })
}

fn make_block_loss_snapshot(
    run: &RecoverableAgentRun,
    provider: &ObservedProviderStart,
    process_tree: Vec<ProcessIdentity>,
    observed_at_unix: i64,
    cleanup_covered: bool,
) -> Result<BlockLossCleanupSnapshot, String> {
    let snapshot = BlockLossCleanupSnapshot {
        schema_version: crate::run_step_spool::BLOCK_LOSS_SNAPSHOT_VERSION,
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

#[cfg(test)]
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
            merge_process_tree(&mut extended, std::slice::from_ref(root));
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
    let Some(expected_executable) = verified_qualification_executable(&qualification) else {
        return Ok(AgentRecoveryDisposition::Unresolved {
            reason: RecoveryUnknown::ProviderIdentityMismatch,
        });
    };
    if rex_observation.last_exit.is_some() {
        if rex_observation
            .child
            .as_ref()
            .is_some_and(|rex_wrapper| rex_wrapper.pid != wrapper.pid)
        {
            return Ok(AgentRecoveryDisposition::Unresolved {
                reason: RecoveryUnknown::WrapperIdentityMismatch,
            });
        }
        return observe_completed_provider_start_from_family(
            store,
            owner_generation,
            run,
            wrapper,
            &qualification,
            &expected_executable,
        );
    }
    let Some(rex_wrapper) = rex_observation.child.as_ref() else {
        return Ok(AgentRecoveryDisposition::Unresolved {
            reason: RecoveryUnknown::WrapperIdentityMismatch,
        });
    };
    if rex_wrapper.pid != wrapper.pid {
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
    let tree = capture_process_tree(wrapper_process.pid, process_table);
    if tree
        .iter()
        .find(|process| process.pid == wrapper_process.pid)
        .is_none_or(|process| process.start_identity != wrapper_process.start_identity)
    {
        return Ok(AgentRecoveryDisposition::Unresolved {
            reason: RecoveryUnknown::ProcessInspectionUnavailable,
        });
    }
    let provider_process = match discover_provider_process(
        wrapper_process.pid,
        rex_observation
            .foreground
            .as_ref()
            .map(|process| process.pid),
        Some(expected_executable.as_path()),
        &tree,
        |process| executable_path_for_identity(process).map_err(|_| ()),
    ) {
        Ok(Some(provider_process)) => provider_process,
        Ok(None) => {
            return Ok(AgentRecoveryDisposition::Unresolved {
                reason: RecoveryUnknown::ProviderIdentityMismatch,
            });
        }
        Err(()) => {
            return Ok(AgentRecoveryDisposition::Unresolved {
                reason: RecoveryUnknown::ProcessInspectionUnavailable,
            });
        }
    };
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

/// Promote a provider whose Rex block finished before the controller's first live-process poll.
/// Only the provider runner's complete, immutable run-family observation can bridge this race;
/// terminal result verification and slot release remain on their existing separate path.
fn observe_completed_provider_start_from_family(
    store: &mut ConfigStore,
    owner_generation: u64,
    run: &RecoverableAgentRun,
    wrapper: &ObservedWrapperIdentity,
    qualification: &crate::launch::ProviderQualification,
    expected_executable: &Path,
) -> Result<AgentRecoveryDisposition, String> {
    let unresolved = || AgentRecoveryDisposition::Unresolved {
        reason: RecoveryUnknown::ProviderIdentityMismatch,
    };
    let spool = match RunStepSpool::open(&run.authority.control_dir) {
        Ok(spool) => spool,
        Err(_) => return Ok(unresolved()),
    };
    let start = match spool.read_start_request() {
        Ok(start) => start,
        Err(_) => return Ok(unresolved()),
    };
    let request = &start.request;
    if request.agent_run_id != run.agent_run_id
        || request.operation_id != run.authority.operation_id
        || request.controller_generation != owner_generation
        || request.descriptor_digest != run.authority.descriptor_digest
        || request.runtime_binary_digest != run.authority.runtime_binary_digest
        || request.qualification_receipt_digest != run.authority.qualification_receipt_digest
        || request.rex_session_id != run.authority.rex_session_id
        || request.rex_block_id != run.authority.rex_block_id
        || request.wrapper_pid != wrapper.pid
        || request.wrapper_start_identity != wrapper.start_identity
    {
        return Ok(unresolved());
    }
    let published_receipt = match spool.read_start_receipt(&start) {
        Ok(Some(receipt)) if receipt.decision == crate::launch::LaunchDecision::Accepted => receipt,
        _ => return Ok(unresolved()),
    };
    if store.persisted_start_receipt(request)?.as_ref() != Some(&published_receipt) {
        return Ok(unresolved());
    }
    let family = match spool.read_run_family_record() {
        Ok(Some(family)) => family,
        Ok(None) | Err(_) => return Ok(unresolved()),
    };
    let expected_binding = crate::run_step_spool::RunFamilyBinding {
        schema_version: 1,
        agent_run_id: run.agent_run_id.clone(),
        reservation_epoch: run.reservation_epoch,
        authority_digest: run.authority_digest.clone(),
        descriptor_digest: run.authority.descriptor_digest.clone(),
        wrapper_pid: wrapper.pid,
        wrapper_start_identity: wrapper.start_identity.clone(),
    };
    if family.binding != expected_binding
        || family.coverage != RunFamilyCoverage::Complete
        || family.provider_executable_path != expected_executable
        || family.provider_executable_digest != qualification.executable_digest
        || family.wrapper_process.pid != wrapper.pid
        || family.wrapper_process.start_identity != wrapper.start_identity
        || family.provider_root.parent_pid != wrapper.pid
        || !family.process_tree.iter().any(|process| {
            process.pid == family.provider_root.pid
                && process.start_identity == family.provider_root.start_identity
                && process.quality == ProcessIdentityQuality::KernelBirthToken
        })
    {
        return Ok(unresolved());
    }

    let mut exact_tree = Vec::with_capacity(family.process_tree.len() + 1);
    exact_tree.push(family.wrapper_process.clone());
    exact_tree.extend(family.process_tree.iter().cloned());
    let current = match inspect_process_table() {
        Ok(current) => current,
        Err(_) => {
            return Ok(AgentRecoveryDisposition::Unresolved {
                reason: RecoveryUnknown::ProcessInspectionUnavailable,
            });
        }
    };
    if !crate::process::matching_processes(&exact_tree, &current).is_empty() {
        return Ok(unresolved());
    }
    let process_tree = exact_tree
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
        agent_run_id: run.authority.agent_run_id.clone(),
        operation_id: run.authority.operation_id.clone(),
        provider_pid: family.provider_root.pid,
        provider_start_identity: family.provider_root.start_identity.clone(),
        executable_digest: qualification.executable_digest.clone(),
        process_tree_digest: digest_json(&process_tree)?,
        process_tree_confirmed: true,
        process_tree,
    };
    observation.validate_complete_process_tree(qualification)?;
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

fn process_is_descendant_of(
    candidate: &ProcessIdentity,
    root_pid: u32,
    process_tree: &[ProcessIdentity],
) -> bool {
    let mut parent_pid = candidate.parent_pid;
    let mut visited = BTreeSet::new();
    while parent_pid != 0 && visited.insert(parent_pid) {
        if parent_pid == root_pid {
            return true;
        }
        let Some(parent) = process_tree
            .iter()
            .find(|process| process.pid == parent_pid)
        else {
            return false;
        };
        parent_pid = parent.parent_pid;
    }
    false
}

fn discover_provider_process<'a>(
    wrapper_pid: u32,
    rex_foreground_pid: Option<u32>,
    expected_executable: Option<&Path>,
    process_tree: &'a [ProcessIdentity],
    mut executable_path: impl FnMut(&ProcessIdentity) -> Result<Option<PathBuf>, ()>,
) -> Result<Option<&'a ProcessIdentity>, ()> {
    let Some(expected_executable) = expected_executable else {
        return Ok(None);
    };
    let mut candidates = Vec::new();
    for process in process_tree.iter().filter(|process| {
        process.quality == ProcessIdentityQuality::KernelBirthToken
            && process.pid != wrapper_pid
            && process_is_descendant_of(process, wrapper_pid, process_tree)
    }) {
        if executable_path(process)?.as_deref() == Some(expected_executable) {
            candidates.push(process);
        }
    }
    if candidates.len() != 1 {
        return Ok(None);
    }
    let provider = candidates[0];
    if rex_foreground_pid.is_some_and(|pid| pid != wrapper_pid && pid != provider.pid) {
        return Ok(None);
    }
    Ok(Some(provider))
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
        && observation.foreground.as_ref().is_some_and(|process| {
            process.pid == provider.provider_pid || process.pid == wrapper.pid
        })
}

fn verified_qualification_executable(
    qualification: &crate::launch::ProviderQualification,
) -> Option<PathBuf> {
    let path = Path::new(&qualification.executable_path);
    if !path.is_absolute() {
        return None;
    }
    let metadata = fs::symlink_metadata(path).ok()?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > 1024 * 1024 * 1024
    {
        return None;
    }
    let canonical = fs::canonicalize(path).ok()?;
    let mut file = fs::File::open(&canonical).ok()?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).ok()?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let digest = Digest::parse(format!("{:x}", hasher.finalize())).ok()?;
    (digest == qualification.executable_digest).then_some(canonical)
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

    #[test]
    fn provider_discovery_uses_unique_qualified_descendant_when_rex_foreground_is_wrapper() {
        let mut native_provider = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let actual = wait_for_identity(native_provider.id());
        let wrapper = ProcessIdentity {
            pid: u32::MAX - 1,
            parent_pid: 1,
            process_group_id: u32::MAX - 1,
            start_identity: "wrapper-born".into(),
            command: "/path/to/rex-wrapper".into(),
            quality: ProcessIdentityQuality::KernelBirthToken,
        };
        let provider = ProcessIdentity {
            pid: actual.pid,
            parent_pid: wrapper.pid,
            ..actual.clone()
        };
        let tree = vec![wrapper.clone(), provider.clone()];
        let executable = Path::new("/bin/sleep").canonicalize().unwrap();

        let discovered = discover_provider_process(
            wrapper.pid,
            Some(wrapper.pid),
            Some(&executable),
            &tree,
            |process| executable_path_for_identity(process).map_err(|_| ()),
        );
        assert_eq!(discovered, Ok(Some(&provider)));

        let unrelated_foreground =
            discover_provider_process(wrapper.pid, Some(99), Some(&executable), &tree, |process| {
                executable_path_for_identity(process).map_err(|_| ())
            });
        assert_eq!(unrelated_foreground, Ok(None));

        let unrelated = ProcessIdentity {
            pid: actual.pid,
            parent_pid: 1,
            ..actual.clone()
        };
        assert_eq!(
            discover_provider_process(
                wrapper.pid,
                Some(wrapper.pid),
                Some(&executable),
                &[wrapper.clone(), unrelated],
                |_| Ok(None),
            ),
            Ok(None)
        );

        let mut second_provider = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let second_actual = wait_for_identity(second_provider.id());
        let ambiguous = ProcessIdentity {
            pid: second_actual.pid,
            parent_pid: wrapper.pid,
            ..second_actual
        };
        assert_eq!(
            discover_provider_process(
                wrapper.pid,
                Some(wrapper.pid),
                Some(&executable),
                &[wrapper.clone(), provider.clone(), ambiguous.clone()],
                |process| executable_path_for_identity(process).map_err(|_| ()),
            ),
            Ok(None)
        );

        let wrapper_pid = wrapper.pid;
        let unreadable_candidate_tree = [wrapper, provider.clone(), ambiguous];
        let inspection_failed = discover_provider_process(
            wrapper_pid,
            Some(wrapper_pid),
            Some(&executable),
            &unreadable_candidate_tree,
            |process| {
                if process.pid == provider.pid {
                    Ok(Some(executable.clone()))
                } else {
                    Err(())
                }
            },
        );
        assert_eq!(inspection_failed, Err(()));
        native_provider.kill().unwrap();
        native_provider.wait().unwrap();
        second_provider.kill().unwrap();
        second_provider.wait().unwrap();
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

    #[cfg(target_os = "macos")]
    #[test]
    fn live_run_observation_arms_watch_before_block_loss() {
        use std::os::unix::process::CommandExt;

        let root = tempfile::tempdir().unwrap();
        let control_dir = root.path().join("control");
        fs::create_dir_all(&control_dir).unwrap();
        let spool = RunStepSpool::open(&control_dir).unwrap();
        let mut child = Command::new("/bin/sleep")
            .arg("30")
            .process_group(0)
            .spawn()
            .unwrap();
        let identity = wait_for_identity(child.id());
        let (run, provider) = watch_test_run(&control_dir, &identity);
        let current = inspect_process_table().unwrap();
        let mut runtime = AgentRecoveryRuntime::default();

        assert!(runtime.watch_live_run_tree(
            &run,
            &provider,
            std::slice::from_ref(&identity),
            &current,
        ));
        let watch = runtime.fork_watches.get(&run.agent_run_id).unwrap();
        assert!(!watch.invalidated);
        assert!(
            watch
                .watched
                .contains_key(&(identity.pid, identity.start_identity.clone()))
        );

        let mut snapshot = make_test_snapshot(vec![identity.clone()], false);
        snapshot.agent_run_id = run.agent_run_id.clone();
        snapshot.reservation_epoch = run.reservation_epoch;
        snapshot.authority_digest = run.authority_digest.clone();
        snapshot.launch_tree_digest = provider.process_tree_digest.clone();
        spool.write_block_loss_cleanup_snapshot(&snapshot).unwrap();
        assert!(runtime.watch_live_run_tree(
            &run,
            &provider,
            std::slice::from_ref(&identity),
            &inspect_process_table().unwrap(),
        ));
        assert!(!runtime.fork_watches[&run.agent_run_id].invalidated);

        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn live_run_observation_does_not_recreate_watch_after_cleanup_snapshot() {
        use std::os::unix::process::CommandExt;

        let root = tempfile::tempdir().unwrap();
        let control_dir = root.path().join("control");
        fs::create_dir_all(&control_dir).unwrap();
        let spool = RunStepSpool::open(&control_dir).unwrap();
        let mut child = Command::new("/bin/sleep")
            .arg("30")
            .process_group(0)
            .spawn()
            .unwrap();
        let identity = wait_for_identity(child.id());
        let (run, provider) = watch_test_run(&control_dir, &identity);
        let mut snapshot = make_test_snapshot(vec![identity.clone()], false);
        snapshot.agent_run_id = run.agent_run_id.clone();
        snapshot.reservation_epoch = run.reservation_epoch;
        snapshot.authority_digest = run.authority_digest.clone();
        snapshot.launch_tree_digest = provider.process_tree_digest.clone();
        spool.write_block_loss_cleanup_snapshot(&snapshot).unwrap();
        let current = inspect_process_table().unwrap();
        let mut runtime = AgentRecoveryRuntime::default();

        assert!(!runtime.watch_live_run_tree(
            &run,
            &provider,
            std::slice::from_ref(&identity),
            &current,
        ));
        assert!(runtime.fork_watches[&run.agent_run_id].invalidated);

        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[cfg(target_os = "macos")]
    fn watch_test_run(
        control_dir: &Path,
        identity: &ProcessIdentity,
    ) -> (RecoverableAgentRun, ObservedProviderStart) {
        use crate::domain::ids::{OperationId, ProjectId, Revision};
        use crate::domain::types::Role;

        let run_id = AgentRunId::parse("run-watch-test").unwrap();
        let digest = Digest::parse("a".repeat(64)).unwrap();
        let authority = crate::launch::AgentLaunchAuthority {
            agent_run_id: run_id.clone(),
            project_id: ProjectId::parse("project-watch-test").unwrap(),
            role: Role::Supervisor,
            role_session_id: "role-session".into(),
            parent_run_id: None,
            parent_role: None,
            ticket_run_id: None,
            ticket_revision: None,
            config_revision: Revision(1),
            config_digest: digest.clone(),
            attempt: 1,
            run_epoch: 1,
            controller_generation: 1,
            operation_id: OperationId::parse("operation-watch-test").unwrap(),
            operation_recipe_id: None,
            rex_view_id: digest.clone(),
            descriptor_digest: digest.clone(),
            runtime_binary_digest: digest.clone(),
            descriptor_path: control_dir.join("descriptor.json"),
            environment_snapshot_id: digest.clone(),
            profile_id: ProfileId::parse("profile-watch-test").unwrap(),
            profile_digest: digest.clone(),
            instruction_digest: digest.clone(),
            result_schema_digest: digest.clone(),
            wake_snapshot_digest: digest.clone(),
            qualification_receipt_digest: digest.clone(),
            rex_server_identity: "rex-instance".into(),
            rex_session_id: "session".into(),
            rex_window_id: "window".into(),
            rex_block_id: "block".into(),
            workspace_path: control_dir.to_path_buf(),
            control_dir: control_dir.to_path_buf(),
            mailbox_capability_digest: digest.clone(),
        };
        let process = crate::launch::ProviderProcessIdentity {
            pid: identity.pid,
            parent_pid: identity.parent_pid,
            process_group_id: identity.process_group_id,
            start_identity: identity.start_identity.clone(),
            identity_quality: identity.quality,
        };
        let provider = ObservedProviderStart {
            agent_run_id: run_id.clone(),
            operation_id: authority.operation_id.clone(),
            provider_pid: identity.pid,
            provider_start_identity: identity.start_identity.clone(),
            executable_digest: digest.clone(),
            process_tree_digest: digest.clone(),
            process_tree_confirmed: true,
            process_tree: vec![process],
        };
        (
            RecoverableAgentRun {
                agent_run_id: run_id,
                current_generation: 1,
                previous_generation: 0,
                authority,
                authority_digest: digest,
                agent_state: "unknown".into(),
                started_at_unix: Some(1),
                launch_state: "running".into(),
                process_identity_json: None,
                wrapper_identity_json: None,
                provider_tree_json: None,
                pool: "agent".into(),
                slot_index: 0,
                reservation_epoch: 1,
                slot_disposition: "live".into(),
            },
            provider,
        )
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
            std::slice::from_ref(&child_identity)
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

    #[cfg(target_os = "macos")]
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
        let mut watch = RunForkWatch::new(
            &snapshot.authority_digest,
            snapshot.reservation_epoch,
            &snapshot.launch_tree_digest,
        );
        assert!(watch.arm(&snapshot.process_tree, &sampled_process_table));

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
        let fork_invalidated_watch = !watch.drain_events();
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
        assert!(
            fork_invalidated_watch,
            "NOTE_FORK must invalidate the proof"
        );
        assert!(
            !watch.seal_cleanup_if_absent(&mut next_snapshot, &next_process_table),
            "a forked run must not seal even if the old sample appears absent"
        );
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

    #[cfg(target_os = "macos")]
    #[test]
    fn already_exited_family_can_be_confirmed_without_watching_a_dead_provider() {
        use std::os::unix::process::CommandExt;

        let mut provider = TrackedChild::new(
            Command::new("/bin/sleep")
                .arg("300")
                .process_group(0)
                .spawn()
                .unwrap(),
        );
        let identity = wait_for_identity(provider.id());
        let mut snapshot = make_test_snapshot(vec![identity.clone()], false);
        let mut watch = RunForkWatch::new(
            &snapshot.authority_digest,
            snapshot.reservation_epoch,
            &snapshot.launch_tree_digest,
        );
        let live = inspect_process_table().unwrap();
        assert!(!watch.covers_sample(
            identity.pid,
            &identity.start_identity,
            &snapshot.process_tree,
            &live,
        ));
        provider.0.kill().unwrap();
        provider.wait().unwrap();
        assert!(wait_until_processes_absent(std::slice::from_ref(&identity)));
        let absent = inspect_process_table().unwrap();
        snapshot.process_tree = extend_process_tree(&snapshot.process_tree, &absent)
            .unwrap()
            .unwrap();
        assert!(watch.arm(&snapshot.process_tree, &absent));
        assert!(watch.covers_sample(
            identity.pid,
            &identity.start_identity,
            &snapshot.process_tree,
            &absent,
        ));
        assert!(watch.seal_cleanup_if_absent(&mut snapshot, &absent));
        assert!(cleanup_absence_confirmed(&snapshot, &absent));

        let ambiguous_group_member = ProcessIdentity {
            pid: u32::MAX - 2,
            start_identity: "unknown-group-member".into(),
            ..identity.clone()
        };
        let mut ambiguous = absent;
        ambiguous.push(ambiguous_group_member);
        assert!(
            extend_process_tree(&snapshot.process_tree, &ambiguous)
                .unwrap()
                .is_none()
        );
        watch.invalidated = true;
        assert!(!watch.covers_sample(
            identity.pid,
            &identity.start_identity,
            &snapshot.process_tree,
            &[],
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn fork_watch_seals_only_fresh_absence_and_restart_cannot_rearm() {
        use std::os::unix::process::CommandExt;

        let mut provider = TrackedChild::new(
            Command::new("/bin/sleep")
                .arg("300")
                .process_group(0)
                .spawn()
                .unwrap(),
        );
        let identity = wait_for_identity(provider.id());
        let mut snapshot = make_test_snapshot(vec![identity.clone()], false);
        let mut watch = RunForkWatch::new(
            &snapshot.authority_digest,
            snapshot.reservation_epoch,
            &snapshot.launch_tree_digest,
        );
        assert!(watch.arm(&snapshot.process_tree, &inspect_process_table().unwrap()));
        let before_stop = inspect_process_table().unwrap();
        assert!(
            signal_process_group_if_observed(
                identity.process_group_id,
                std::slice::from_ref(&identity),
                &before_stop,
                ProcessSignal::Terminate,
            )
            .unwrap()
        );
        assert!(wait_until_processes_absent(std::slice::from_ref(&identity)));
        let after_stop = inspect_process_table().unwrap();
        assert!(watch.seal_cleanup_if_absent(&mut snapshot, &after_stop));
        assert!(cleanup_absence_confirmed(&snapshot, &after_stop));

        let mut recovered = RunForkWatch::unavailable(
            &snapshot.authority_digest,
            snapshot.reservation_epoch,
            &snapshot.launch_tree_digest,
        );
        snapshot.cleanup_covered = false;
        assert!(!recovered.arm(&snapshot.process_tree, &after_stop));
        assert!(!recovered.seal_cleanup_if_absent(&mut snapshot, &after_stop));
        assert!(!cleanup_absence_confirmed(&snapshot, &after_stop));
        let _ = provider.wait();
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn unsupported_fork_watch_platform_fails_closed() {
        let process = ProcessIdentity {
            pid: 42,
            parent_pid: 1,
            process_group_id: 42,
            start_identity: "birth-42".into(),
            command: String::new(),
            quality: ProcessIdentityQuality::KernelBirthToken,
        };
        let mut snapshot = make_test_snapshot(vec![process.clone()], false);
        let mut watch = RunForkWatch::new(
            &snapshot.authority_digest,
            snapshot.reservation_epoch,
            &snapshot.launch_tree_digest,
        );
        assert!(!watch.arm(&snapshot.process_tree, std::slice::from_ref(&process)));
        assert!(!watch.seal_cleanup_if_absent(&mut snapshot, &[]));
        assert!(!cleanup_absence_confirmed(&snapshot, &[]));
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
            schema_version: crate::run_step_spool::BLOCK_LOSS_SNAPSHOT_VERSION,
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
