//! Reconcile live finite Agent turns after the machine controller changes owner.

use std::collections::BTreeMap;
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
    ProcessIdentity, ProcessIdentityQuality, capture_process_tree, inspect_process_table,
};
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
        {
            return Ok(AgentRecoveryDisposition::Unresolved {
                reason: RecoveryUnknown::ProviderIdentityMismatch,
            });
        }
        let qualification = store
            .provider_qualification(&authority.qualification_receipt_digest)?
            .ok_or_else(|| "Agent recovery qualification receipt is missing".to_owned())?;
        provider.validate(&qualification)?;
        let window = TicketWindow {
            server_instance_id: rex_instance.to_owned(),
            session_id: authority.rex_session_id.clone(),
            window_id: authority.rex_window_id.clone(),
            label: String::new(),
            initial_block_id: Some(authority.rex_block_id.clone()),
            disposition: CreateDisposition::Existing,
        };
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
