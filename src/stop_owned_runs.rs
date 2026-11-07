//! Host-owned cancellation of the exact AgentRuns named by a durable Pause/Cancel effect.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::adapters::rex::{CreateDisposition, RexCliTransport, TicketWindow};
use crate::agent_recovery::RecoveryUnknown;
use crate::domain::ids::Digest as ContentDigest;
use crate::effects::{EffectContext, EffectHandler, EffectMode, EffectObservation, EffectRequest};
use crate::launch::AgentLaunchAuthority;
use crate::process::{
    ProcessIdentityQuality, ProcessSignal, capture_process_tree, inspect_process_table,
    signal_process_group_if_observed,
};
use crate::store::agent_recovery::{
    StopOwnedRunTarget, StopOwnedRunsEffectPayload, StopTargetLifecycle, VerifiedStopCancellation,
};
use crate::store::agent_results::verify_agent_terminal_if_recorded;

const MAX_TARGETS_PER_TICK: usize = 8;
const MAX_TREE_IDENTITIES: usize = 1024;
const MAX_EXECUTABLE_BYTES: u64 = 512 * 1024 * 1024;

pub struct StopOwnedRunsHandler {
    rex: Arc<RexCliTransport>,
    runtime_binary: PathBuf,
    runtime_binary_digest: ContentDigest,
    shutdown_grace: Duration,
}

impl StopOwnedRunsHandler {
    pub fn new(
        rex: Arc<RexCliTransport>,
        runtime_binary: PathBuf,
        runtime_binary_digest: ContentDigest,
        shutdown_grace: Duration,
    ) -> Result<Self, String> {
        if !runtime_binary.is_absolute() || shutdown_grace.is_zero() {
            return Err(
                "StopOwnedRuns requires an absolute runtime binary and positive grace".into(),
            );
        }
        Ok(Self {
            rex,
            runtime_binary,
            runtime_binary_digest,
            shutdown_grace,
        })
    }

    fn reconcile(
        &self,
        request: &EffectRequest,
        context: &mut EffectContext<'_>,
    ) -> Result<EffectObservation, String> {
        let payload = StopOwnedRunsEffectPayload::from_effect_request(request)?;
        let operation_id =
            crate::domain::ids::OperationId::parse(request.intent.operation_id.clone())?;
        let intent = context.store.prepare_stop_owned_runs_intent(
            context.owner_generation,
            &operation_id,
            &payload,
            context.now_unix,
        )?;
        if intent.targets.is_empty() {
            return Ok(EffectObservation::Applied {
                receipt: stop_receipt(&intent, 0, 0, 0)?,
            });
        }

        let (mut cursor, _) = context.store.stop_owned_runs_progress(&operation_id)?;
        if cursor as usize >= intent.targets.len() {
            return Err("stored StopOwnedRuns cursor exceeds its immutable target list".into());
        }
        let turns = intent.targets.len().min(MAX_TARGETS_PER_TICK);
        let mut examined = 0;
        let mut signalled = 0;
        let mut needs_attention = 0;
        for _ in 0..turns {
            let target = &intent.targets[cursor as usize];
            let result =
                self.reconcile_target(&operation_id, request.attempt_count, target, context);
            examined += 1;
            match result {
                TargetReconcile::Terminal => {}
                TargetReconcile::Signalled => signalled += 1,
                TargetReconcile::Unknown => needs_attention += 1,
            }
            (cursor, _) = context.store.advance_stop_owned_runs_progress(
                context.owner_generation,
                &operation_id,
                cursor,
                intent.targets.len() as u32,
                context.now_unix,
            )?;
        }

        let mut all_terminal = true;
        for target in &intent.targets {
            let cancelled = context
                .store
                .stop_cancellation_complete(&operation_id, &target.agent_run_id)?;
            let terminal = verify_agent_terminal_if_recorded(
                context.store,
                context.owner_generation,
                &target.agent_run_id,
            )?
            .is_some();
            if !cancelled && !terminal {
                all_terminal = false;
                break;
            }
        }
        let receipt = stop_receipt(&intent, examined, signalled, needs_attention)?;
        if all_terminal {
            Ok(EffectObservation::Applied { receipt })
        } else {
            Ok(EffectObservation::Pending { receipt })
        }
    }

    fn reconcile_target(
        &self,
        operation_id: &crate::domain::ids::OperationId,
        attempt_count: u32,
        target: &StopOwnedRunTarget,
        context: &mut EffectContext<'_>,
    ) -> TargetReconcile {
        let authority = match context.store.agent_launch_authority(&target.agent_run_id) {
            Ok(Some(authority)) if target_matches_authority(target, &authority) => authority,
            Ok(Some(authority)) => return self.mark_unknown(target, &authority, context),
            _ => {
                let _ = context.store.retain_agent_run_unknown(
                    context.owner_generation,
                    &target.agent_run_id,
                    target.reservation_epoch,
                );
                return TargetReconcile::Unknown;
            }
        };
        if context
            .store
            .stop_cancellation_complete(operation_id, &target.agent_run_id)
            .unwrap_or(false)
        {
            return TargetReconcile::Terminal;
        }
        match verify_agent_terminal_if_recorded(
            context.store,
            context.owner_generation,
            &target.agent_run_id,
        ) {
            Ok(Some(_)) => return TargetReconcile::Terminal,
            Err(_) => return self.mark_unknown(target, &authority, context),
            Ok(None) => {}
        }
        if context
            .store
            .retain_agent_run_unknown(
                context.owner_generation,
                &target.agent_run_id,
                target.reservation_epoch,
            )
            .is_err()
        {
            return self.mark_unknown(target, &authority, context);
        }
        if target.lifecycle != StopTargetLifecycle::NeedsReconciliation {
            return self.mark_unknown(target, &authority, context);
        }
        if self.rex.capabilities().server_instance_id != target.rex_server_identity
            || self.rex.session_id() != target.rex_session_id
            || authority.rex_window_id != target.rex_window_id
            || authority.rex_block_id != target.rex_block_id
            || authority.runtime_binary_digest != self.runtime_binary_digest
            || hash_file(&self.runtime_binary).ok().as_ref() != Some(&self.runtime_binary_digest)
        {
            return self.mark_unknown(target, &authority, context);
        }
        let Some(wrapper_target) = target.wrapper.as_ref() else {
            return self.mark_unknown(target, &authority, context);
        };
        let Some(provider_target) = target.provider.as_ref() else {
            return self.mark_unknown(target, &authority, context);
        };
        let Some(qualification) = context
            .store
            .provider_qualification(&authority.qualification_receipt_digest)
            .ok()
            .flatten()
        else {
            return self.mark_unknown(target, &authority, context);
        };
        if hash_file(Path::new(&qualification.executable_path))
            .ok()
            .as_ref()
            != Some(&qualification.executable_digest)
        {
            return self.mark_unknown(target, &authority, context);
        }
        let window = TicketWindow {
            server_instance_id: target.rex_server_identity.clone(),
            session_id: target.rex_session_id.clone(),
            window_id: target.rex_window_id.clone(),
            label: String::new(),
            initial_block_id: Some(target.rex_block_id.clone()),
            disposition: CreateDisposition::Existing,
        };
        let observation = match self.rex.observe_process(
            &window,
            target.agent_run_id.as_str(),
            &target.rex_block_id,
        ) {
            Ok(observation) => observation,
            Err(_) => return self.mark_unknown(target, &authority, context),
        };
        let current = match inspect_process_table() {
            Ok(current) => current,
            Err(_) => return self.mark_unknown(target, &authority, context),
        };
        if observation.last_exit.is_some()
            && observation.child.is_none()
            && observation.foreground.is_none()
        {
            let Some((snapshot_digest, snapshot)) = context
                .store
                .stop_process_snapshot(operation_id, &target.agent_run_id)
                .ok()
                .flatten()
            else {
                return self.mark_unknown(target, &authority, context);
            };
            if !owned_process_tree_is_absent(&snapshot, &current) {
                return self.mark_unknown(target, &authority, context);
            }
            let rex_digest = match rex_observation_digest(&observation)
                .map(|bytes| ContentDigest::parse(format!("{:x}", Sha256::digest(bytes))))
            {
                Ok(Ok(digest)) => digest,
                _ => return self.mark_unknown(target, &authority, context),
            };
            let proof = VerifiedStopCancellation::after_verified_absence(
                operation_id,
                target,
                &snapshot_digest,
                &rex_digest,
                context.now_unix,
            );
            if context
                .store
                .complete_cancelled_agent_run(
                    context.owner_generation,
                    operation_id,
                    target,
                    &proof,
                )
                .is_err()
            {
                return self.mark_unknown(target, &authority, context);
            }
            return TargetReconcile::Terminal;
        }
        let (Some(child), Some(foreground)) =
            (observation.child.as_ref(), observation.foreground.as_ref())
        else {
            return self.mark_unknown(target, &authority, context);
        };
        if observation.last_exit.is_some()
            || child.pid != wrapper_target.pid
            || foreground.pid != provider_target.pid
            || !rex_command_matches(child, &self.runtime_binary)
            || !rex_command_matches(foreground, Path::new(&qualification.executable_path))
        {
            return self.mark_unknown(target, &authority, context);
        }
        let tree = capture_process_tree(wrapper_target.pid, &current);
        if tree.is_empty()
            || tree.len() > MAX_TREE_IDENTITIES
            || tree.iter().any(|identity| {
                identity.quality != ProcessIdentityQuality::KernelBirthToken
                    || identity.command.is_empty()
                    || identity.command.chars().any(char::is_control)
            })
        {
            return self.mark_unknown(target, &authority, context);
        }
        let wrapper = tree.iter().find(|process| {
            process.pid == wrapper_target.pid
                && process.start_identity == wrapper_target.start_identity
        });
        let provider = tree.iter().find(|process| {
            process.pid == provider_target.pid
                && process.start_identity == provider_target.start_identity
        });
        let (Some(wrapper), Some(provider)) = (wrapper, provider) else {
            return self.mark_unknown(target, &authority, context);
        };
        if wrapper.pid != wrapper.process_group_id
            || tree
                .iter()
                .any(|process| process.process_group_id != wrapper.process_group_id)
            || provider.process_group_id != wrapper.process_group_id
        {
            return self.mark_unknown(target, &authority, context);
        }
        let snapshot_digest = match context.store.record_stop_process_snapshot(
            context.owner_generation,
            operation_id,
            target,
            &tree,
            context.now_unix,
        ) {
            Ok(digest) => digest,
            Err(_) => return self.mark_unknown(target, &authority, context),
        };
        let Some((_, original_tree)) = context
            .store
            .stop_process_snapshot(operation_id, &target.agent_run_id)
            .ok()
            .flatten()
        else {
            return self.mark_unknown(target, &authority, context);
        };
        if original_tree != tree {
            let _ = snapshot_digest;
            return self.mark_unknown(target, &authority, context);
        }
        let signal = signal_for_attempt(attempt_count, self.shutdown_grace);
        match signal_process_group_if_observed(wrapper.process_group_id, &tree, &current, signal) {
            Ok(_) if signal == ProcessSignal::Kill => {
                self.mark_unknown(target, &authority, context)
            }
            Ok(_) => TargetReconcile::Signalled,
            Err(_) => self.mark_unknown(target, &authority, context),
        }
    }

    fn mark_unknown(
        &self,
        target: &StopOwnedRunTarget,
        authority: &AgentLaunchAuthority,
        context: &mut EffectContext<'_>,
    ) -> TargetReconcile {
        let _ = context.store.retain_agent_run_unknown(
            context.owner_generation,
            &target.agent_run_id,
            target.reservation_epoch,
        );
        let _ = context.store.queue_agent_recovery_attention(
            context.owner_generation,
            authority,
            RecoveryUnknown::ProcessInspectionUnavailable,
            context.now_unix,
        );
        TargetReconcile::Unknown
    }
}

fn rex_observation_digest(
    observation: &crate::adapters::rex::RexProcessObservation,
) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(&serde_json::json!({
        "last_exit": observation.last_exit.as_ref().map(|exit| (exit.exit_code, exit.error.as_deref())),
        "child": observation.child.as_ref().map(|process| (process.pid, process.user_id, process.name.as_str(), process.argv0.as_deref(), process.path.as_deref(), process.invoked_path.as_deref(), process.script.as_deref(), process.cwd.as_deref(), process.user.as_deref())),
        "foreground": observation.foreground.as_ref().map(|process| (process.pid, process.user_id, process.name.as_str(), process.argv0.as_deref(), process.path.as_deref(), process.invoked_path.as_deref(), process.script.as_deref(), process.cwd.as_deref(), process.user.as_deref())),
        "ancestors": observation.ancestors.as_ref().map(|processes| processes.iter().map(|process| (process.pid, process.user_id, process.name.as_str(), process.argv0.as_deref(), process.path.as_deref(), process.invoked_path.as_deref(), process.script.as_deref(), process.cwd.as_deref(), process.user.as_deref())).collect::<Vec<_>>()),
    }))
}

pub(crate) fn owned_process_tree_is_absent(
    snapshot: &[crate::process::ProcessIdentity],
    current: &[crate::process::ProcessIdentity],
) -> bool {
    let Some(group_id) = snapshot.first().map(|identity| identity.process_group_id) else {
        return false;
    };
    group_id > 0
        && snapshot.iter().all(|identity| {
            identity.quality == ProcessIdentityQuality::KernelBirthToken
                && identity.start_identity.trim() != ""
                && identity.process_group_id == group_id
        })
        && snapshot.iter().all(|expected| {
            !current.iter().any(|actual| {
                actual.pid == expected.pid && actual.start_identity == expected.start_identity
            })
        })
        && current
            .iter()
            .all(|actual| actual.process_group_id != group_id)
}

impl EffectHandler for StopOwnedRunsHandler {
    fn kind(&self) -> crate::engine::reducer::EffectKind {
        crate::engine::reducer::EffectKind::StopOwnedRuns
    }

    fn handle(
        &self,
        _mode: EffectMode,
        request: &EffectRequest,
        context: &mut EffectContext<'_>,
    ) -> Result<EffectObservation, String> {
        self.reconcile(request, context)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TargetReconcile {
    Terminal,
    Signalled,
    Unknown,
}

#[derive(Serialize)]
struct StopReceipt<'a> {
    schema_version: u32,
    operation_id: &'a str,
    target_count: usize,
    examined_this_tick: usize,
    signalled_this_tick: usize,
    unknown_this_tick: usize,
    disposition: &'static str,
}

fn stop_receipt(
    intent: &crate::store::agent_recovery::StopOwnedRunsIntent,
    examined: usize,
    signalled: usize,
    unknown: usize,
) -> Result<String, String> {
    serde_json::to_string(&StopReceipt {
        schema_version: 1,
        operation_id: intent.operation_id.as_str(),
        target_count: intent.targets.len(),
        examined_this_tick: examined,
        signalled_this_tick: signalled,
        unknown_this_tick: unknown,
        disposition: if intent.targets.is_empty() {
            "no_targets"
        } else {
            "reconciled"
        },
    })
    .map_err(|error| error.to_string())
}

fn target_matches_authority(target: &StopOwnedRunTarget, authority: &AgentLaunchAuthority) -> bool {
    authority.digest().is_ok_and(|digest| {
        target.agent_run_id == authority.agent_run_id
            && target.attempt == authority.attempt
            && target.run_epoch == authority.run_epoch
            && target.authority_digest == digest
            && target.rex_server_identity == authority.rex_server_identity
            && target.rex_session_id == authority.rex_session_id
            && target.rex_window_id == authority.rex_window_id
            && target.rex_block_id == authority.rex_block_id
    })
}

fn rex_command_matches(process: &crate::adapters::rex::RexProcessInfo, expected: &Path) -> bool {
    let Ok(expected) = expected.canonicalize() else {
        return false;
    };
    [
        process.path.as_deref(),
        process.invoked_path.as_deref(),
        process.argv0.as_deref(),
        process.script.as_deref(),
    ]
    .into_iter()
    .flatten()
    .any(|candidate| {
        Path::new(candidate)
            .canonicalize()
            .is_ok_and(|actual| actual == expected)
    })
}

fn hash_file(path: &Path) -> Result<ContentDigest, String> {
    let canonical = path
        .canonicalize()
        .map_err(|error| format!("canonicalize executable: {error}"))?;
    let metadata =
        std::fs::symlink_metadata(path).map_err(|error| format!("inspect executable: {error}"))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_EXECUTABLE_BYTES
    {
        return Err("executable is not a bounded regular file".into());
    }
    let mut file =
        std::fs::File::open(canonical).map_err(|error| format!("open executable: {error}"))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("read executable: {error}"))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    ContentDigest::parse(format!("{:x}", digest.finalize()))
}

fn signal_for_attempt(attempt: u32, grace: Duration) -> ProcessSignal {
    let grace_attempts = grace.as_secs().div_ceil(2).clamp(1, 3) as u32;
    if attempt <= grace_attempts {
        ProcessSignal::Interrupt
    } else if attempt <= grace_attempts.saturating_mul(2) {
        ProcessSignal::Terminate
    } else {
        ProcessSignal::Kill
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stop_escalation_is_bounded_and_monotonic() {
        let grace = Duration::from_secs(5);
        assert_eq!(signal_for_attempt(1, grace), ProcessSignal::Interrupt);
        assert_eq!(signal_for_attempt(3, grace), ProcessSignal::Interrupt);
        assert_eq!(signal_for_attempt(4, grace), ProcessSignal::Terminate);
        assert_eq!(signal_for_attempt(6, grace), ProcessSignal::Terminate);
        assert_eq!(signal_for_attempt(7, grace), ProcessSignal::Kill);
        assert_eq!(signal_for_attempt(u32::MAX, grace), ProcessSignal::Kill);
    }

    #[test]
    fn rex_command_must_resolve_to_the_immutable_executable_path() {
        let temp = tempfile::tempdir().unwrap();
        let executable = temp.path().join("provider");
        std::fs::write(&executable, b"provider").unwrap();
        let expected = executable.canonicalize().unwrap();
        let info = crate::adapters::rex::RexProcessInfo {
            pid: 42,
            user_id: 1000,
            name: "provider".into(),
            argv0: None,
            path: Some(expected.display().to_string()),
            invoked_path: None,
            script: None,
            cwd: None,
            user: None,
        };
        assert!(rex_command_matches(&info, &expected));

        let wrong = temp.path().join("other-provider");
        std::fs::write(&wrong, b"other").unwrap();
        assert!(!rex_command_matches(&info, &wrong));
    }

    #[test]
    fn hard_killed_run_without_agent_terminal_waits_for_full_process_group_absence() {
        use std::os::unix::process::CommandExt;
        use std::process::{Command, Stdio};
        use std::thread;

        let mut child = Command::new("/bin/sh")
            .args(["-c", "sleep 60 & wait"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .unwrap();
        let root_pid = child.id();
        let mut snapshot = Vec::new();
        for _ in 0..40 {
            let current = inspect_process_table().unwrap();
            snapshot = capture_process_tree(root_pid, &current);
            if snapshot.len() >= 2 {
                break;
            }
            thread::sleep(Duration::from_millis(25));
        }
        assert!(snapshot.len() >= 2, "fixture child was not observed");
        let group_id = snapshot[0].process_group_id;
        child.kill().unwrap();
        let _ = child.wait();

        let after_parent_death = inspect_process_table().unwrap();
        assert!(
            after_parent_death
                .iter()
                .any(|process| process.process_group_id == group_id)
        );
        assert!(!owned_process_tree_is_absent(
            &snapshot,
            &after_parent_death
        ));

        let child_pid = snapshot
            .iter()
            .find(|process| process.pid != root_pid)
            .unwrap()
            .pid;
        assert!(
            Command::new("/bin/kill")
                .args(["-KILL", &child_pid.to_string()])
                .status()
                .unwrap()
                .success()
        );
        let mut absent = false;
        for _ in 0..80 {
            let current = inspect_process_table().unwrap();
            if owned_process_tree_is_absent(&snapshot, &current) {
                absent = true;
                break;
            }
            thread::sleep(Duration::from_millis(25));
        }
        assert!(absent, "owned process group remained after confirmed kill");
    }

    #[test]
    fn unknown_process_identity_keeps_cancellation_unresolved() {
        let unknown = vec![crate::process::ProcessIdentity {
            pid: 123,
            parent_pid: 1,
            process_group_id: 123,
            start_identity: "second-precision:123".into(),
            command: "agent".into(),
            quality: ProcessIdentityQuality::SecondPrecision,
        }];
        assert!(!owned_process_tree_is_absent(&unknown, &[]));
    }
}
