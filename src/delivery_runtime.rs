//! Host-owned repository delivery steps for one accepted implementation handoff.
//!
//! This module never opens a user's ordinary checkout. Every Git mutation is scoped to the
//! configured managed clone and the stable worktree returned by `WorktreeManager`.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::config::RepositoryConfig;
use crate::delivery_forge::{
    PublicationError, PublishedPullRequest, PullRequestPublicationIntent, PullRequestPublisher,
};
use crate::domain::ids::{
    Digest, OperationId, ProjectId, RepositoryId, TicketId, TicketNamespace, TicketRunId,
};
use crate::domain::types::CommitMode;
use crate::effects::{
    AbsentProof, EffectContext, EffectHandler, EffectMode, EffectObservation, EffectRequest,
};
use crate::engine::orchestration::{WorkNodeId, WorkPlan};
use crate::engine::reducer::EffectKind;
use crate::hooks::{HookReceipt, HookRunContext, HookRunner};
use crate::host_commit::{
    ChangeManifest, HostCommitError, HostCommitOptions, HostCommitReceipt, HostCommitter,
    PreparedHostCommit,
};
use crate::host_jobs::{HostJobEnvironmentBinding, HostJobPool};
use crate::process::{self, ProcessOutput, ProcessRequest};
use crate::worktrees::{
    GitOptions, ManagedRepository, ManagedWorktree, NativeCommitReceipt, TicketKey, WorktreeError,
    WorktreeManager,
};

const DELIVERY_OUTPUT_LIMIT: usize = 1024 * 1024;
const DELIVERY_STDERR_LIMIT: usize = 16 * 1024;
const DELIVERY_SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkNodeIdentity {
    pub project_id: ProjectId,
    pub repository_id: RepositoryId,
    pub ticket_namespace: TicketNamespace,
    pub ticket_id: TicketId,
    pub ticket_run_id: TicketRunId,
    pub work_node_id: String,
}

impl WorkNodeIdentity {
    /// The stable branch identity used by the managed worktree layer, without creating or
    /// fetching a worktree. Used to capture the external-resource baseline before mutation.
    pub fn branch_name(&self) -> Result<String, DeliveryError> {
        let key = self.ticket_key()?;
        let mut digest = Sha256::new();
        digest.update(key.namespace.as_str());
        digest.update([0]);
        digest.update(key.ticket_id.as_str());
        Ok(format!(
            "rex-projects/{}",
            hex_lower(&digest.finalize()[..16])
        ))
    }

    fn ticket_key(&self) -> Result<TicketKey, DeliveryError> {
        if self.work_node_id.is_empty()
            || self.work_node_id.len() > 255
            || !self
                .work_node_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(DeliveryError::Invalid("work node ID is invalid".into()));
        }
        let mut digest = Sha256::new();
        for value in [
            self.project_id.as_str(),
            self.ticket_namespace.as_str(),
            self.ticket_id.as_str(),
            self.ticket_run_id.as_str(),
            self.work_node_id.as_str(),
        ] {
            digest.update(value.as_bytes());
            digest.update([0]);
        }
        let composite_ticket_id = digest
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        Ok(TicketKey {
            namespace: self.ticket_namespace.clone(),
            ticket_id: TicketId::parse(composite_ticket_id).map_err(DeliveryError::Invalid)?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedRepositoryWork {
    pub identity: WorkNodeIdentity,
    pub repository: ManagedRepository,
    pub worktree: ManagedWorktree,
    pub expected_base_sha: String,
    pub commit_mode: CommitMode,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkerCommitSubmission {
    Native {
        previous_accepted_head: String,
        worker_reported_head: String,
        required_trailer: String,
    },
    HostManifest {
        operation_id: OperationId,
        expected_head: String,
        manifest: ChangeManifest,
        manifest_root: PathBuf,
        message: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum VerifiedCommit {
    Native { receipt: NativeCommitReceipt },
    Host { receipt: HostCommitReceipt },
}

impl VerifiedCommit {
    pub fn head(&self) -> &str {
        match self {
            Self::Native { receipt } => &receipt.head,
            Self::Host { receipt } => &receipt.observed_head,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HookGateReceipt {
    pub repository_id: RepositoryId,
    pub head: String,
    pub configuration_digest: Digest,
    pub hook_receipts: Vec<HookReceipt>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushReceipt {
    pub repository_id: RepositoryId,
    pub branch: String,
    pub expected_remote_head: Option<String>,
    pub observed_remote_head: String,
    pub pushed_head: String,
    pub force_with_lease: bool,
}

/// Inputs captured from an authoritative forge observation before repairing a stacked branch.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StackRepairRequest {
    pub repository_id: RepositoryId,
    pub worktree_path: PathBuf,
    pub branch: String,
    pub recorded_base_sha: String,
    pub old_parent_sha: String,
    pub new_parent_sha: String,
    pub expected_child_head: String,
    pub expected_remote_child_head: String,
    pub default_branch: String,
    pub observed_protected_branches: Vec<String>,
    pub protection_observation_complete: bool,
    pub protection_observed_at_unix: u64,
    pub protection_observation_digest: Digest,
    pub required_trailer: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StackRepairReceipt {
    pub repository_id: RepositoryId,
    pub branch: String,
    pub old_parent_sha: String,
    pub new_parent_sha: String,
    pub old_child_head: String,
    pub new_child_head: String,
    pub verified_commits: Vec<String>,
    pub hook_gate: HookGateReceipt,
    pub protection_observation_digest: Digest,
}

pub struct PullRequestPublication<'a> {
    pub repository_config: &'a RepositoryConfig,
    pub configuration_digest: &'a Digest,
    pub expected_head: &'a str,
    pub hook_gate: &'a HookGateReceipt,
    pub intent: &'a PullRequestPublicationIntent,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryPublicationObservation {
    pub remote_head: Option<String>,
    pub pull_requests: crate::delivery_forge::ObservationCapability<
        Vec<crate::delivery_forge::ObservedPullRequest>,
    >,
}

#[derive(Debug)]
pub enum DeliveryError {
    Invalid(String),
    Conflict(String),
    Unknown(String),
    Git(String),
    Worktree(WorktreeError),
    HostCommit(HostCommitError),
    Hook(String),
}

impl std::fmt::Display for DeliveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(message)
            | Self::Conflict(message)
            | Self::Unknown(message)
            | Self::Git(message)
            | Self::Hook(message) => f.write_str(message),
            Self::Worktree(error) => write!(f, "{error}"),
            Self::HostCommit(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for DeliveryError {}

pub struct RepositoryDelivery {
    state_root: PathBuf,
    git: GitOptions,
    worktrees: WorktreeManager,
    commits: HostCommitter,
    hooks: HookRunner,
}

impl RepositoryDelivery {
    pub fn new(
        state_root: &Path,
        git: GitOptions,
        inherited_environment: BTreeMap<OsString, OsString>,
        environment_binding: HostJobEnvironmentBinding,
    ) -> Result<Self, DeliveryError> {
        let worktrees =
            WorktreeManager::new(state_root, git.clone()).map_err(DeliveryError::Worktree)?;
        let commits = HostCommitter::new(HostCommitOptions {
            git_executable: git.executable.clone(),
            git_environment: git.environment.clone(),
            state_root: state_root.to_owned(),
            timeout: git.timeout,
        })
        .map_err(DeliveryError::HostCommit)?;
        let hooks = HookRunner::new(git.clone(), inherited_environment, environment_binding);
        Ok(Self {
            state_root: state_root.to_owned(),
            git,
            worktrees,
            commits,
            hooks,
        })
    }

    /// Initialize/fetch the managed clone and create or reuse the stable TicketRun/work-node branch.
    pub fn prepare_worktree(
        &self,
        identity: WorkNodeIdentity,
        repository_config: &RepositoryConfig,
        expected_base_sha: &str,
        commit_mode: CommitMode,
    ) -> Result<PreparedRepositoryWork, DeliveryError> {
        if commit_mode == CommitMode::Auto {
            return Err(DeliveryError::Invalid(
                "resolve automatic commit mode to native or host before preparing delivery".into(),
            ));
        }
        validate_git_sha(expected_base_sha)?;
        let repository = self
            .worktrees
            .ensure_repository(&identity.repository_id, &repository_config.clone_url)
            .map_err(DeliveryError::Worktree)?;
        let worktree = self
            .worktrees
            .prepare_worktree(
                &repository,
                &repository_config.base_branch,
                &identity.ticket_key()?,
            )
            .map_err(DeliveryError::Worktree)?;
        if worktree.base_sha != expected_base_sha {
            return Err(DeliveryError::Conflict(
                "fetched base differs from the accepted work plan; refusing to retarget the branch"
                    .into(),
            ));
        }
        Ok(PreparedRepositoryWork {
            identity,
            repository,
            worktree,
            expected_base_sha: expected_base_sha.to_owned(),
            commit_mode,
        })
    }

    /// Read one exact remote branch without initializing the managed clone.
    pub fn observe_configured_remote_branch(
        &self,
        repository_config: &RepositoryConfig,
        branch: &str,
    ) -> Result<Option<String>, DeliveryError> {
        let reference = format!("refs/heads/{branch}");
        let output = process::run(ProcessRequest {
            executable: self.git.executable.clone(),
            args: vec![
                "ls-remote".into(),
                "--heads".into(),
                repository_config.clone_url.clone().into(),
                reference.clone().into(),
            ],
            stdin: Vec::new(),
            cwd: None,
            clear_environment: true,
            environment: self.git.environment.clone(),
            timeout: self.git.timeout,
            shutdown_grace: DELIVERY_SHUTDOWN_GRACE,
            stdout_limit: 64 * 1024,
            stderr_tail_limit: DELIVERY_STDERR_LIMIT,
        })
        .map_err(|_| {
            DeliveryError::Unknown("could not observe the configured remote branch".into())
        })?;
        if !output.status.is_some_and(|status| status.success())
            || output.timed_out
            || !output.cleanup_confirmed
            || output.stdout_truncated
        {
            return Err(DeliveryError::Unknown(
                "could not establish the configured remote branch state".into(),
            ));
        }
        let text = std::str::from_utf8(&output.stdout)
            .map_err(|_| DeliveryError::Unknown("remote branch response is not UTF-8".into()))?;
        let mut rows = text.lines();
        let Some(row) = rows.next() else {
            return Ok(None);
        };
        if rows.next().is_some() {
            return Err(DeliveryError::Unknown(
                "remote returned multiple rows for an exact branch ref".into(),
            ));
        }
        let (sha, refname) = row.split_once('\t').ok_or_else(|| {
            DeliveryError::Unknown("remote returned a malformed branch ref".into())
        })?;
        validate_git_sha(sha)?;
        if refname != reference {
            return Err(DeliveryError::Unknown(
                "remote returned a different branch ref".into(),
            ));
        }
        Ok(Some(sha.to_owned()))
    }

    /// Inspect actual refs and objects for native commits, or execute/reconcile the host manifest.
    pub fn verify_worker_commit(
        &self,
        work: &PreparedRepositoryWork,
        submission: WorkerCommitSubmission,
    ) -> Result<VerifiedCommit, DeliveryError> {
        match submission {
            WorkerCommitSubmission::Native {
                previous_accepted_head,
                worker_reported_head,
                required_trailer,
            } => {
                if work.commit_mode != CommitMode::Native {
                    return Err(DeliveryError::Invalid(
                        "native commit submission does not match the selected commit mode".into(),
                    ));
                }
                validate_git_sha(&previous_accepted_head)?;
                validate_git_sha(&worker_reported_head)?;
                let mut verification_base = work.worktree.clone();
                verification_base.base_sha = previous_accepted_head;
                let _lease = self
                    .worktrees
                    .acquire_writer_lease(work.worktree.clone())
                    .map_err(DeliveryError::Worktree)?;
                let receipt = self
                    .worktrees
                    .verify_native_commits(&verification_base, &required_trailer)
                    .map_err(DeliveryError::Worktree)?;
                if receipt.head != worker_reported_head {
                    return Err(DeliveryError::Conflict(
                        "Worker-reported HEAD differs from the host-observed branch HEAD".into(),
                    ));
                }
                Ok(VerifiedCommit::Native { receipt })
            }
            WorkerCommitSubmission::HostManifest {
                operation_id,
                expected_head,
                manifest,
                manifest_root,
                message,
            } => {
                if work.commit_mode != CommitMode::Host {
                    return Err(DeliveryError::Invalid(
                        "host manifest submission does not match the selected commit mode".into(),
                    ));
                }
                validate_git_sha(&expected_head)?;
                let actual_head =
                    self.git_text(&work.worktree.path, ["rev-parse", "--verify", "HEAD"])?;
                if actual_head.trim() != expected_head {
                    return Err(DeliveryError::Conflict(
                        "host manifest expected HEAD differs from the current worktree".into(),
                    ));
                }
                let _lease = self
                    .worktrees
                    .acquire_writer_lease(work.worktree.clone())
                    .map_err(DeliveryError::Worktree)?;
                let prepared = self
                    .commits
                    .prepare(
                        &work.worktree,
                        operation_id,
                        manifest,
                        &manifest_root,
                        message,
                    )
                    .map_err(DeliveryError::HostCommit)?;
                if prepared.intent.expected_head != expected_head {
                    return Err(DeliveryError::Conflict(
                        "host commit manifest is bound to a different expected HEAD".into(),
                    ));
                }
                let receipt = match self
                    .commits
                    .execute(&work.worktree, &prepared)
                    .map_err(DeliveryError::HostCommit)
                {
                    Ok(receipt) => receipt,
                    Err(error) => {
                        // Keep the immutable prepared intent for the durable effect's next reconcile.
                        return Err(error);
                    }
                };
                Ok(VerifiedCommit::Host { receipt })
            }
        }
    }

    /// Durable effect phase: prepare a host commit intent without executing it.
    pub fn prepare_host_manifest(
        &self,
        work: &PreparedRepositoryWork,
        operation_id: OperationId,
        expected_head: &str,
        manifest: ChangeManifest,
        manifest_root: &Path,
        message: String,
    ) -> Result<PreparedHostCommit, DeliveryError> {
        if work.commit_mode != CommitMode::Host {
            return Err(DeliveryError::Invalid(
                "host manifest does not match the selected commit mode".into(),
            ));
        }
        validate_git_sha(expected_head)?;
        let _lease = self
            .worktrees
            .acquire_writer_lease(work.worktree.clone())
            .map_err(DeliveryError::Worktree)?;
        let actual_head = self.git_text(&work.worktree.path, ["rev-parse", "--verify", "HEAD"])?;
        if actual_head.trim() != expected_head {
            return Err(DeliveryError::Conflict(
                "host manifest expected HEAD differs from the current worktree".into(),
            ));
        }
        let mut commit_worktree = work.worktree.clone();
        commit_worktree.base_sha = expected_head.to_owned();
        self.commits
            .prepare(
                &commit_worktree,
                operation_id,
                manifest,
                manifest_root,
                message,
            )
            .map_err(DeliveryError::HostCommit)
    }

    pub fn load_prepared_host_manifest(
        &self,
        work: &PreparedRepositoryWork,
        operation_id: &OperationId,
        expected_head: &str,
        manifest: &ChangeManifest,
        manifest_root: &Path,
        message: &str,
    ) -> Result<Option<PreparedHostCommit>, DeliveryError> {
        if work.commit_mode != CommitMode::Host {
            return Err(DeliveryError::Invalid(
                "host manifest recovery does not match the selected commit mode".into(),
            ));
        }
        validate_git_sha(expected_head)?;
        let _lease = self
            .worktrees
            .acquire_writer_lease(work.worktree.clone())
            .map_err(DeliveryError::Worktree)?;
        let mut commit_worktree = work.worktree.clone();
        commit_worktree.base_sha = expected_head.to_owned();
        self.commits
            .load_prepared(
                &commit_worktree,
                operation_id,
                manifest,
                manifest_root,
                message,
            )
            .map_err(DeliveryError::HostCommit)
    }

    pub fn validate_required_commit_trailer(
        &self,
        work: &PreparedRepositoryWork,
        message: &str,
        required_trailer: &str,
    ) -> Result<(), DeliveryError> {
        if work.commit_mode != CommitMode::Host {
            return Err(DeliveryError::Invalid(
                "host commit trailer validation requires host commit mode".into(),
            ));
        }
        self.commits
            .validate_required_trailer(&work.worktree, message, required_trailer)
            .map_err(DeliveryError::HostCommit)
    }

    /// Durable effect phase: execute a previously persisted host commit intent.
    pub fn execute_host_commit(
        &self,
        work: &PreparedRepositoryWork,
        prepared: &PreparedHostCommit,
    ) -> Result<HostCommitReceipt, DeliveryError> {
        let _lease = self
            .worktrees
            .acquire_writer_lease(work.worktree.clone())
            .map_err(DeliveryError::Worktree)?;
        let mut commit_worktree = work.worktree.clone();
        commit_worktree.base_sha = prepared.intent.expected_head.clone();
        self.commits
            .execute(&commit_worktree, prepared)
            .map_err(DeliveryError::HostCommit)
    }

    /// Durable effect phase: reconcile an interrupted host commit without committing twice.
    pub fn reconcile_host_commit(
        &self,
        work: &PreparedRepositoryWork,
        prepared: &PreparedHostCommit,
    ) -> Result<Option<HostCommitReceipt>, DeliveryError> {
        let _lease = self
            .worktrees
            .acquire_writer_lease(work.worktree.clone())
            .map_err(DeliveryError::Worktree)?;
        let mut commit_worktree = work.worktree.clone();
        commit_worktree.base_sha = prepared.intent.expected_head.clone();
        self.commits
            .reconcile(&commit_worktree, prepared)
            .map_err(DeliveryError::HostCommit)
    }

    /// Execute repository-declared checks against the immutable accepted commit head.
    pub fn run_required_hooks(
        &self,
        work: &PreparedRepositoryWork,
        repository_config: &RepositoryConfig,
        configuration_digest: &Digest,
        verified_commit: &VerifiedCommit,
    ) -> Result<HookGateReceipt, DeliveryError> {
        let accepted_head = verified_commit.head();
        validate_git_sha(accepted_head)?;
        let _lease = self
            .worktrees
            .acquire_writer_lease(work.worktree.clone())
            .map_err(DeliveryError::Worktree)?;
        let hook_receipts = self
            .hooks
            .run_required(
                &repository_config.rex_projects_hooks,
                HookRunContext {
                    repository_id: &work.identity.repository_id,
                    worktree: &work.worktree.path,
                    expected_head: accepted_head,
                    project_id: &work.identity.project_id,
                    ticket_run_id: &work.identity.ticket_run_id,
                    configuration_digest,
                    state_root: &self.state_root,
                },
            )
            .map_err(|error| DeliveryError::Hook(error.to_string()))?;
        Ok(HookGateReceipt {
            repository_id: work.identity.repository_id.clone(),
            head: accepted_head.to_owned(),
            configuration_digest: configuration_digest.clone(),
            hook_receipts,
        })
    }

    pub fn run_required_hooks_managed(
        &self,
        work: &PreparedRepositoryWork,
        repository_config: &RepositoryConfig,
        configuration_digest: &Digest,
        verified_commit: &VerifiedCommit,
        execution: crate::hooks::ManagedHookExecution<'_>,
    ) -> Result<Option<HookGateReceipt>, DeliveryError> {
        let accepted_head = verified_commit.head();
        validate_git_sha(accepted_head)?;
        let receipts = self
            .hooks
            .run_required_managed(
                &repository_config.rex_projects_hooks,
                HookRunContext {
                    repository_id: &work.identity.repository_id,
                    worktree: &work.worktree.path,
                    expected_head: accepted_head,
                    project_id: &work.identity.project_id,
                    ticket_run_id: &work.identity.ticket_run_id,
                    configuration_digest,
                    state_root: &self.state_root,
                },
                execution,
                || {
                    self.worktrees
                        .acquire_writer_lease(work.worktree.clone())
                        .map_err(|error| error.to_string())
                },
            )
            .map_err(|error| DeliveryError::Hook(error.to_string()))?;
        Ok(receipts.map(|hook_receipts| HookGateReceipt {
            repository_id: work.identity.repository_id.clone(),
            head: accepted_head.to_owned(),
            configuration_digest: configuration_digest.clone(),
            hook_receipts,
        }))
    }

    /// Push the exact owned head as a non-forced, explicit refspec. A remote already at this SHA
    /// is an idempotent success; any different observed remote SHA is a reconciliation conflict.
    pub fn push_owned_branch(
        &self,
        work: &PreparedRepositoryWork,
        repository_config: &RepositoryConfig,
        configuration_digest: &Digest,
        expected_head: &str,
        expected_remote_head: Option<&str>,
        hook_gate: &HookGateReceipt,
    ) -> Result<PushReceipt, DeliveryError> {
        validate_git_sha(expected_head)?;
        validate_hook_gate(
            work,
            repository_config,
            configuration_digest,
            expected_head,
            hook_gate,
        )?;
        let _lease = self
            .worktrees
            .acquire_writer_lease(work.worktree.clone())
            .map_err(DeliveryError::Worktree)?;
        if work.worktree.repository_id != work.identity.repository_id {
            return Err(DeliveryError::Invalid(
                "worktree repository does not match its immutable work identity".into(),
            ));
        }
        let local_head = self.git_text(&work.worktree.path, ["rev-parse", "--verify", "HEAD"])?;
        if local_head.trim() != expected_head {
            return Err(DeliveryError::Conflict(
                "local branch HEAD changed before publication".into(),
            ));
        }
        let branch = self.git_text(
            &work.worktree.path,
            ["symbolic-ref", "--quiet", "--short", "HEAD"],
        )?;
        if branch.trim() != work.worktree.branch {
            return Err(DeliveryError::Conflict(
                "worktree is no longer on its owned delivery branch".into(),
            ));
        }
        let observed_remote =
            self.remote_branch_head(&work.worktree.path, &work.worktree.branch)?;
        if observed_remote.as_deref() == Some(expected_head) {
            return Ok(PushReceipt {
                repository_id: work.identity.repository_id.clone(),
                branch: work.worktree.branch.clone(),
                expected_remote_head: expected_remote_head.map(str::to_owned),
                observed_remote_head: expected_head.to_owned(),
                pushed_head: expected_head.to_owned(),
                force_with_lease: false,
            });
        }
        if observed_remote.as_deref() != expected_remote_head {
            return Err(DeliveryError::Conflict(
                "remote branch differs from the publication intent's expected head".into(),
            ));
        }
        let refspec = format!("{expected_head}:refs/heads/{}", work.worktree.branch);
        let result = self.git_run(&work.worktree.path, ["push", "origin", &refspec]);
        match result {
            Ok(output)
                if output.status.is_some_and(|status| status.success())
                    && !output.timed_out
                    && output.cleanup_confirmed => {}
            _ => {
                let observed_after =
                    self.remote_branch_head(&work.worktree.path, &work.worktree.branch)?;
                if observed_after.as_deref() == Some(expected_head) {
                    return Ok(PushReceipt {
                        repository_id: work.identity.repository_id.clone(),
                        branch: work.worktree.branch.clone(),
                        expected_remote_head: expected_remote_head.map(str::to_owned),
                        observed_remote_head: expected_head.to_owned(),
                        pushed_head: expected_head.to_owned(),
                        force_with_lease: false,
                    });
                }
                return Err(DeliveryError::Unknown(
                    "push outcome is uncertain; inspect the exact remote branch before retrying"
                        .into(),
                ));
            }
        }
        let observed_after = self.remote_branch_head(&work.worktree.path, &work.worktree.branch)?;
        if observed_after.as_deref() != Some(expected_head) {
            return Err(DeliveryError::Unknown(
                "push completed without verifying the exact remote head".into(),
            ));
        }
        Ok(PushReceipt {
            repository_id: work.identity.repository_id.clone(),
            branch: work.worktree.branch.clone(),
            expected_remote_head: expected_remote_head.map(str::to_owned),
            observed_remote_head: expected_head.to_owned(),
            pushed_head: expected_head.to_owned(),
            force_with_lease: false,
        })
    }

    /// Read-only publication reconciliation; does not update a remote ref.
    pub fn reconcile_owned_branch(
        &self,
        work: &PreparedRepositoryWork,
        repository_config: &RepositoryConfig,
        configuration_digest: &Digest,
        expected_head: &str,
        expected_prior_remote_head: Option<&str>,
        hook_gate: &HookGateReceipt,
    ) -> Result<Option<PushReceipt>, DeliveryError> {
        validate_git_sha(expected_head)?;
        validate_hook_gate(
            work,
            repository_config,
            configuration_digest,
            expected_head,
            hook_gate,
        )?;
        let local_head = self.git_text(&work.worktree.path, ["rev-parse", "--verify", "HEAD"])?;
        if local_head.trim() != expected_head {
            return Err(DeliveryError::Conflict(
                "local branch differs from the persisted publication intent".into(),
            ));
        }
        let observed = self.remote_branch_head(&work.worktree.path, &work.worktree.branch)?;
        if observed.as_deref() == Some(expected_head) {
            return Ok(Some(PushReceipt {
                repository_id: work.identity.repository_id.clone(),
                branch: work.worktree.branch.clone(),
                expected_remote_head: expected_prior_remote_head.map(str::to_owned),
                observed_remote_head: expected_head.to_owned(),
                pushed_head: expected_head.to_owned(),
                force_with_lease: false,
            }));
        }
        if observed.as_deref() == expected_prior_remote_head {
            return Ok(None);
        }
        Err(DeliveryError::Conflict(
            "remote branch matches neither the previous nor intended head".into(),
        ))
    }

    pub fn observe_local_head(
        &self,
        work: &PreparedRepositoryWork,
    ) -> Result<String, DeliveryError> {
        self.observe_local_head_at(&work.worktree.path)
    }

    /// Observe one host-persisted worktree path using the configured bounded Git executor.
    pub fn observe_local_head_at(&self, path: &Path) -> Result<String, DeliveryError> {
        let head = self.git_text(path, ["rev-parse", "--verify", "HEAD"])?;
        let head = head.trim().to_owned();
        validate_git_sha(&head)?;
        Ok(head)
    }

    /// Read the subject of one exact, currently checked-out Worker commit through the bounded
    /// Git executor. Publication callers must already have validated the commit authority.
    pub fn observe_commit_subject_at(
        &self,
        path: &Path,
        expected_head: &str,
    ) -> Result<String, DeliveryError> {
        validate_git_sha(expected_head)?;
        let actual_head = self.observe_local_head_at(path)?;
        if actual_head != expected_head {
            return Err(DeliveryError::Conflict(
                "pull request title source differs from the observed worktree HEAD".into(),
            ));
        }
        let subject = self.git_text(path, ["show", "-s", "--format=%s", expected_head])?;
        let subject = subject.trim().to_owned();
        if subject.is_empty() || subject.contains(['\n', '\r']) {
            return Err(DeliveryError::Invalid(
                "observed Worker commit has an invalid pull request title".into(),
            ));
        }
        Ok(subject)
    }

    /// Observe the exact owned branch and matching PR timeline through the configured Git and
    /// `gh` CLI identities. A failed branch read is an error; forge capability gaps stay typed.
    pub fn observe_publication(
        &self,
        publisher: &impl PullRequestPublisher,
        work: &PreparedRepositoryWork,
        intent: &PullRequestPublicationIntent,
    ) -> Result<RepositoryPublicationObservation, DeliveryError> {
        if work.identity.repository_id != intent.repository_id
            || work.worktree.branch != intent.source_branch
        {
            return Err(DeliveryError::Conflict(
                "publication observation does not match the owned worktree".into(),
            ));
        }
        let remote_head = self.remote_branch_head(&work.worktree.path, &work.worktree.branch)?;
        let forge = publisher
            .observe(intent)
            .map_err(|error| DeliveryError::Unknown(error.to_string()))?;
        Ok(RepositoryPublicationObservation {
            remote_head,
            pull_requests: forge.pull_requests,
        })
    }

    /// Validate publication identity and gate evidence before delegating to the forge adapter.
    pub fn publish_pull_request(
        &self,
        publisher: &impl PullRequestPublisher,
        work: &PreparedRepositoryWork,
        publication: PullRequestPublication<'_>,
    ) -> Result<PublishedPullRequest, DeliveryError> {
        let PullRequestPublication {
            repository_config,
            configuration_digest,
            expected_head,
            hook_gate,
            intent,
        } = publication;
        if repository_config.forge != "github"
            || work.identity.repository_id != intent.repository_id
            || work.repository.clone_url != intent.clone_url
            || work.worktree.branch != intent.source_branch
            || repository_config.base_branch != intent.base_branch
            || intent.source_head != expected_head
        {
            return Err(DeliveryError::Conflict(
                "pull request intent differs from the configured repository delivery".into(),
            ));
        }
        validate_hook_gate(
            work,
            repository_config,
            configuration_digest,
            expected_head,
            hook_gate,
        )?;
        let local_head = self.git_text(&work.worktree.path, ["rev-parse", "--verify", "HEAD"])?;
        if local_head.trim() != expected_head {
            return Err(DeliveryError::Conflict(
                "local delivery branch changed before PR publication".into(),
            ));
        }
        publisher
            .publish(intent)
            .map_err(|error: PublicationError| DeliveryError::Unknown(error.to_string()))
    }

    /// Rebase a dependent branch after its parent was squash-merged. Force is limited to an
    /// explicitly owned, non-default, observed-unprotected branch and carries an exact lease.
    pub fn repair_stacked_branch(
        &self,
        prepared_work: &PreparedRepositoryWork,
        repository_config: &RepositoryConfig,
        configuration_digest: &Digest,
        request: &StackRepairRequest,
    ) -> Result<StackRepairReceipt, DeliveryError> {
        for sha in [
            request.old_parent_sha.as_str(),
            request.new_parent_sha.as_str(),
            request.expected_child_head.as_str(),
            request.expected_remote_child_head.as_str(),
        ] {
            validate_git_sha(sha)?;
        }
        validate_branch_name(&request.branch)?;
        validate_branch_name(&request.default_branch)?;
        validate_git_sha(&request.recorded_base_sha)?;
        if !request.protection_observation_complete
            || request.repository_id != prepared_work.identity.repository_id
            || request.worktree_path != prepared_work.worktree.path
            || request.branch != prepared_work.worktree.branch
            || request.recorded_base_sha != prepared_work.worktree.base_sha
            || request.protection_observation_digest.as_str().len() != 64
            || request.branch == request.default_branch
            || request
                .observed_protected_branches
                .iter()
                .any(|branch| branch == &request.branch)
        {
            return Err(DeliveryError::Invalid(
                "stack repair requires a non-default branch with observed unprotected status"
                    .into(),
            ));
        }
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now_unix.saturating_sub(request.protection_observed_at_unix) > 300
            || request.protection_observed_at_unix > now_unix.saturating_add(30)
        {
            return Err(DeliveryError::Conflict(
                "stack repair branch-protection observation is stale".into(),
            ));
        }
        let worktree = ManagedWorktree {
            repository_id: request.repository_id.clone(),
            path: request.worktree_path.clone(),
            branch: request.branch.clone(),
            base_sha: request.recorded_base_sha.clone(),
        };
        let _lease = self
            .worktrees
            .acquire_writer_lease(worktree.clone())
            .map_err(DeliveryError::Worktree)?;
        let local_branch = self.git_text(
            &worktree.path,
            ["symbolic-ref", "--quiet", "--short", "HEAD"],
        )?;
        if local_branch.trim() != worktree.branch {
            return Err(DeliveryError::Conflict(
                "worktree is no longer on its owned stack child branch".into(),
            ));
        }
        let remote_before = self.remote_branch_head(&worktree.path, &worktree.branch)?;
        let local_head = self
            .git_text(&worktree.path, ["rev-parse", "--verify", "HEAD"])?
            .trim()
            .to_owned();
        let is_original_head = local_head == request.expected_child_head;
        if is_original_head
            && (request.expected_child_head != request.expected_remote_child_head
                || remote_before.as_deref() != Some(&request.expected_remote_child_head))
        {
            return Err(DeliveryError::Conflict(
                "remote child branch changed before stack repair".into(),
            ));
        }
        let original_patch = self.git_bytes(
            &worktree.path,
            [
                "diff",
                "--binary",
                "--no-ext-diff",
                request.old_parent_sha.as_str(),
                request.expected_child_head.as_str(),
            ],
        )?;
        let old_patch_digest = Sha256::digest(&original_patch);
        if is_original_head {
            self.git_status_ok(
                &worktree.path,
                [
                    "merge-base",
                    "--is-ancestor",
                    request.old_parent_sha.as_str(),
                    request.expected_child_head.as_str(),
                ],
            )?;
            let merges = self.git_text(
                &worktree.path,
                [
                    "rev-list",
                    "--merges",
                    &format!(
                        "{}..{}",
                        request.old_parent_sha, request.expected_child_head
                    ),
                ],
            )?;
            if !merges.trim().is_empty() {
                return Err(DeliveryError::Conflict(
                    "stack repair only supports a linear child commit series".into(),
                ));
            }
            self.git_checked(
                &worktree.path,
                [
                    "rebase",
                    "--onto",
                    request.new_parent_sha.as_str(),
                    request.old_parent_sha.as_str(),
                ],
            )?;
        } else {
            let status = self.git_text(
                &worktree.path,
                ["status", "--porcelain=v2", "--untracked-files=all"],
            )?;
            if !status.is_empty() {
                return Err(DeliveryError::Conflict(
                    "interrupted stack rebase left a dirty worktree; manual reconciliation is required".into(),
                ));
            }
            let current_patch = self.git_bytes(
                &worktree.path,
                [
                    "diff",
                    "--binary",
                    "--no-ext-diff",
                    request.new_parent_sha.as_str(),
                    local_head.as_str(),
                ],
            )?;
            if Sha256::digest(&current_patch) != old_patch_digest {
                return Err(DeliveryError::Conflict(
                    "local child differs from both the original and intended rebased history"
                        .into(),
                ));
            }
            if remote_before.as_deref() != Some(&request.expected_remote_child_head)
                && remote_before.as_deref() != Some(&local_head)
            {
                return Err(DeliveryError::Conflict(
                    "remote child branch changed during stack repair".into(),
                ));
            }
        }
        let rebased_head = self
            .git_text(&worktree.path, ["rev-parse", "--verify", "HEAD"])?
            .trim()
            .to_owned();
        validate_git_sha(&rebased_head)?;
        let mut rebased_worktree = worktree.clone();
        rebased_worktree.base_sha = request.new_parent_sha.clone();
        let verified = self
            .worktrees
            .verify_native_commits(&rebased_worktree, &request.required_trailer)
            .map_err(DeliveryError::Worktree)?;
        if verified.head != rebased_head || verified.base_sha != request.new_parent_sha {
            return Err(DeliveryError::Conflict(
                "rebased branch did not verify against its new parent".into(),
            ));
        }
        let mut rebased_prepared_work = prepared_work.clone();
        rebased_prepared_work.worktree = rebased_worktree;
        rebased_prepared_work.expected_base_sha = request.new_parent_sha.clone();
        let hook_gate = self.run_required_hooks(
            &rebased_prepared_work,
            repository_config,
            configuration_digest,
            &VerifiedCommit::Native {
                receipt: verified.clone(),
            },
        )?;
        let refspec = format!("{rebased_head}:refs/heads/{}", worktree.branch);
        let lease = format!(
            "--force-with-lease=refs/heads/{}:{}",
            worktree.branch, request.expected_remote_child_head
        );
        if remote_before.as_deref() != Some(&rebased_head) {
            let result = self.git_run(&worktree.path, ["push", &lease, "origin", &refspec]);
            if !matches!(result, Ok(ref output) if output.status.is_some_and(|status| status.success()) && !output.timed_out && output.cleanup_confirmed)
                && self
                    .remote_branch_head(&worktree.path, &worktree.branch)?
                    .as_deref()
                    != Some(&rebased_head)
            {
                return Err(DeliveryError::Unknown(
                    "stack repair push outcome is uncertain; reconcile the exact remote ref".into(),
                ));
            }
        }
        let remote_after = self.remote_branch_head(&worktree.path, &worktree.branch)?;
        if remote_after.as_deref() != Some(&rebased_head) {
            return Err(DeliveryError::Unknown(
                "stack repair did not verify the exact remote head".into(),
            ));
        }
        Ok(StackRepairReceipt {
            repository_id: request.repository_id.clone(),
            branch: worktree.branch.clone(),
            old_parent_sha: request.old_parent_sha.clone(),
            new_parent_sha: request.new_parent_sha.clone(),
            old_child_head: request.expected_child_head.clone(),
            new_child_head: rebased_head,
            verified_commits: verified.commits,
            hook_gate,
            protection_observation_digest: request.protection_observation_digest.clone(),
        })
    }

    fn remote_branch_head(
        &self,
        cwd: &Path,
        branch: &str,
    ) -> Result<Option<String>, DeliveryError> {
        let reference = format!("refs/heads/{branch}");
        let output = self.git_run(cwd, ["ls-remote", "--heads", "origin", &reference])?;
        if !output.status.is_some_and(|status| status.success())
            || output.timed_out
            || !output.cleanup_confirmed
            || output.stdout_truncated
        {
            return Err(DeliveryError::Unknown(
                "cannot establish the current remote branch head".into(),
            ));
        }
        let text = String::from_utf8(output.stdout)
            .map_err(|_| DeliveryError::Unknown("remote branch response is not UTF-8".into()))?;
        let mut rows = text.lines();
        let Some(row) = rows.next() else {
            return Ok(None);
        };
        if rows.next().is_some() {
            return Err(DeliveryError::Unknown(
                "remote returned multiple rows for an exact branch ref".into(),
            ));
        }
        let (sha, refname) = row.split_once('\t').ok_or_else(|| {
            DeliveryError::Unknown("remote returned an invalid ref observation".into())
        })?;
        validate_git_sha(sha)?;
        if refname != reference {
            return Err(DeliveryError::Unknown(
                "remote returned a different branch ref".into(),
            ));
        }
        Ok(Some(sha.to_owned()))
    }

    fn git_text<const N: usize>(
        &self,
        cwd: &Path,
        args: [&str; N],
    ) -> Result<String, DeliveryError> {
        let output = self.git_run(cwd, args)?;
        if !output.status.is_some_and(|status| status.success())
            || output.timed_out
            || !output.cleanup_confirmed
            || output.stdout_truncated
        {
            return Err(DeliveryError::Git(
                "Git command failed or had an uncertain outcome".into(),
            ));
        }
        String::from_utf8(output.stdout)
            .map_err(|_| DeliveryError::Git("Git output is not UTF-8".into()))
    }

    fn git_bytes<const N: usize>(
        &self,
        cwd: &Path,
        args: [&str; N],
    ) -> Result<Vec<u8>, DeliveryError> {
        let output = self.git_run(cwd, args)?;
        if !output.status.is_some_and(|status| status.success())
            || output.timed_out
            || !output.cleanup_confirmed
            || output.stdout_truncated
        {
            return Err(DeliveryError::Git(
                "Git command failed or had an uncertain outcome".into(),
            ));
        }
        Ok(output.stdout)
    }

    fn git_checked<const N: usize>(
        &self,
        cwd: &Path,
        args: [&str; N],
    ) -> Result<(), DeliveryError> {
        let output = self.git_run(cwd, args)?;
        if output.status.is_some_and(|status| status.success())
            && !output.timed_out
            && output.cleanup_confirmed
        {
            Ok(())
        } else {
            Err(DeliveryError::Conflict(
                "stack rebase failed; inspect the managed worktree before retrying".into(),
            ))
        }
    }

    fn git_status_ok<const N: usize>(
        &self,
        cwd: &Path,
        args: [&str; N],
    ) -> Result<(), DeliveryError> {
        let output = self.git_run(cwd, args)?;
        if output.status.is_some_and(|status| status.success())
            && !output.timed_out
            && output.cleanup_confirmed
        {
            Ok(())
        } else {
            Err(DeliveryError::Conflict(
                "Git ancestry precondition is not satisfied".into(),
            ))
        }
    }

    fn git_run<const N: usize>(
        &self,
        cwd: &Path,
        args: [&str; N],
    ) -> Result<ProcessOutput, DeliveryError> {
        let mut environment = self.git.environment.clone();
        process::clear_git_repository_environment(&mut environment);
        environment.insert("GIT_TERMINAL_PROMPT".into(), "0".into());
        process::run(ProcessRequest {
            executable: self.git.executable.clone(),
            args: args.into_iter().map(OsString::from).collect(),
            stdin: Vec::new(),
            cwd: Some(cwd.to_owned()),
            clear_environment: true,
            environment,
            timeout: self.git.timeout,
            shutdown_grace: DELIVERY_SHUTDOWN_GRACE,
            stdout_limit: DELIVERY_OUTPUT_LIMIT,
            stderr_tail_limit: DELIVERY_STDERR_LIMIT,
        })
        .map_err(|_| DeliveryError::Unknown("Git process did not produce a reliable result".into()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareWorktreesEffectPayload {
    pub schema_version: u32,
    pub source_revision: u64,
    pub configuration_digest: Digest,
    pub ticket_namespace: TicketNamespace,
    pub ticket_id: TicketId,
    pub ticket_run_id: TicketRunId,
    pub work_nodes: Vec<PreparedWorktreeNodeRequest>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedWorktreeNodeRequest {
    pub work_node_id: WorkNodeId,
    pub repository_id: RepositoryId,
    pub expected_base_sha: String,
    pub commit_mode: CommitMode,
}

/// A host-owned, run-scoped request to commit a Worker manifest before its final result is accepted.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitWorkerManifestEffectPayload {
    pub schema_version: u32,
    pub agent_run_id: crate::domain::ids::AgentRunId,
    pub project_id: ProjectId,
    pub message_id: String,
    pub configuration_digest: Digest,
    pub ticket_revision: u64,
    pub ticket_namespace: TicketNamespace,
    pub ticket_id: TicketId,
    pub ticket_run_id: TicketRunId,
    pub work_node_id: WorkNodeId,
    pub repository_id: RepositoryId,
    pub worktree_path: PathBuf,
    pub branch: String,
    pub prepare_operation_id: OperationId,
    pub expected_base_sha: String,
    pub expected_head: String,
    pub manifest_artifact: crate::engine::orchestration::RoleArtifactReference,
    pub manifest_digest: Digest,
    pub manifest: crate::host_commit::ChangeManifest,
    pub commit_message: String,
    pub required_trailer: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitWorkerManifestEffectReceipt {
    pub schema_version: u32,
    pub agent_run_id: crate::domain::ids::AgentRunId,
    pub message_id: String,
    pub ticket_run_id: TicketRunId,
    pub work_node_id: WorkNodeId,
    pub repository_id: RepositoryId,
    pub base_sha: String,
    pub manifest_artifact: crate::engine::orchestration::RoleArtifactReference,
    pub commit: crate::host_commit::HostCommitReceipt,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkerDeliveryCommit {
    Native {
        previous_accepted_head: String,
        worker_reported_head: String,
        required_trailer: String,
    },
    HostReceipt {
        operation_id: OperationId,
        expected_head: String,
        worker_reported_head: String,
        receipt: Box<CommitWorkerManifestEffectReceipt>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishImplementationEffectPayload {
    pub schema_version: u32,
    pub source_revision: u64,
    pub configuration_digest: Digest,
    pub ticket_namespace: TicketNamespace,
    pub ticket_id: TicketId,
    pub ticket_run_id: TicketRunId,
    pub work_node_id: WorkNodeId,
    pub repository_id: RepositoryId,
    pub expected_base_sha: String,
    pub base_branch: String,
    pub commit_mode: CommitMode,
    pub commit: WorkerDeliveryCommit,
    pub expected_remote_head: Option<String>,
    pub pull_request: PullRequestContent,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PullRequestContent {
    pub title: String,
    pub body: String,
    pub update_target: Option<crate::delivery_forge::PullRequestTarget>,
}

/// Canonical wire encoding for durable delivery effect requests.
pub fn canonical_delivery_payload<T: Serialize>(payload: &T) -> Result<(String, String), String> {
    let value = serde_json::to_value(payload).map_err(|error| error.to_string())?;
    let json = serde_json::to_string(&value).map_err(|error| error.to_string())?;
    let digest = sha256_hex(json.as_bytes());
    Ok((json, digest))
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedWorktreesEffectReceipt {
    pub schema_version: u32,
    pub ticket_run_id: TicketRunId,
    pub work_nodes: Vec<PreparedWorktreeReceiptNode>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedWorktreeReceiptNode {
    pub work_node_id: WorkNodeId,
    pub repository_id: RepositoryId,
    pub worktree_path: PathBuf,
    pub branch: String,
    pub base_sha: String,
    pub commit_mode: CommitMode,
}

/// Validate that a persisted worktree receipt covers exactly its request.
pub fn validate_prepared_receipt(
    request: &PrepareWorktreesEffectPayload,
    receipt: &PreparedWorktreesEffectReceipt,
) -> Result<(), String> {
    if receipt.schema_version != 1 || receipt.ticket_run_id != request.ticket_run_id {
        return Err("prepared worktree receipt has a mismatched schema or TicketRun".into());
    }
    if request.work_nodes.is_empty() || request.work_nodes.len() > 64 {
        return Err("prepare worktree request node count is outside limits".into());
    }
    if receipt.work_nodes.len() != request.work_nodes.len() {
        return Err("prepared worktree receipt does not cover the requested nodes".into());
    }
    let mut expected = request.work_nodes.iter().collect::<Vec<_>>();
    expected.sort_by(|left, right| left.work_node_id.cmp(&right.work_node_id));
    let mut actual = receipt.work_nodes.iter().collect::<Vec<_>>();
    actual.sort_by(|left, right| left.work_node_id.cmp(&right.work_node_id));
    let mut previous: Option<&str> = None;
    for (wanted, got) in expected.iter().zip(actual) {
        if previous == Some(wanted.work_node_id.as_str())
            || wanted.work_node_id != got.work_node_id
            || wanted.repository_id != got.repository_id
            || wanted.expected_base_sha != got.base_sha
            || wanted.commit_mode != got.commit_mode
            || !got.worktree_path.is_absolute()
            || got.branch.trim().is_empty()
        {
            return Err("prepared worktree node does not match its effect request".into());
        }
        previous = Some(wanted.work_node_id.as_str());
    }
    Ok(())
}

/// Settings and adapters shared by the two repository-delivery effect handlers.
pub struct RepositoryDeliveryEffects {
    delivery: RepositoryDelivery,
    publisher: crate::delivery_forge::GitHubPullRequestPublisher,
    configuration_digest: Digest,
    repositories: BTreeMap<RepositoryId, RepositoryConfig>,
    project_repositories: BTreeMap<ProjectId, BTreeSet<RepositoryId>>,
    host_jobs: Arc<Mutex<HostJobPool>>,
    max_hook_attempts: u32,
}

pub struct RepositoryDeliveryEffectConfig {
    pub state_root: PathBuf,
    pub git: GitOptions,
    pub inherited_environment: BTreeMap<OsString, OsString>,
    pub environment_binding: HostJobEnvironmentBinding,
    pub gh_executable: PathBuf,
    pub gh_environment: BTreeMap<OsString, OsString>,
    pub timeout: Duration,
    pub configuration_digest: Digest,
    pub repositories: BTreeMap<RepositoryId, RepositoryConfig>,
    pub project_repositories: BTreeMap<ProjectId, BTreeSet<RepositoryId>>,
    pub max_hook_attempts: u32,
}

impl RepositoryDeliveryEffects {
    pub fn new(
        config: RepositoryDeliveryEffectConfig,
        host_jobs: Arc<Mutex<HostJobPool>>,
    ) -> Result<Arc<Self>, String> {
        if config.max_hook_attempts == 0 {
            return Err("maximum hook attempts must be positive".into());
        }
        let delivery = RepositoryDelivery::new(
            &config.state_root,
            config.git,
            config.inherited_environment,
            config.environment_binding,
        )
        .map_err(|error| error.to_string())?;
        let publisher = crate::delivery_forge::GitHubPullRequestPublisher::new(
            config.gh_executable,
            config.gh_environment,
            config.timeout,
        )
        .map_err(|error| error.to_string())?;
        for (project, repositories) in &config.project_repositories {
            if repositories
                .iter()
                .any(|repository| !config.repositories.contains_key(repository))
            {
                return Err(format!(
                    "Project `{project}` references an unknown repository in delivery registry"
                ));
            }
        }
        Ok(Arc::new(Self {
            delivery,
            publisher,
            configuration_digest: config.configuration_digest,
            repositories: config.repositories,
            project_repositories: config.project_repositories,
            host_jobs,
            max_hook_attempts: config.max_hook_attempts,
        }))
    }

    pub fn host_jobs(&self) -> Arc<Mutex<HostJobPool>> {
        Arc::clone(&self.host_jobs)
    }

    pub fn observe_local_head_at(&self, path: &Path) -> Result<String, String> {
        self.delivery
            .observe_local_head_at(path)
            .map_err(|error| error.to_string())
    }

    pub fn observe_commit_subject_at(
        &self,
        path: &Path,
        expected_head: &str,
    ) -> Result<String, String> {
        self.delivery
            .observe_commit_subject_at(path, expected_head)
            .map_err(|error| error.to_string())
    }

    pub fn prepare_worktrees_handler(self: &Arc<Self>) -> PrepareWorktreesEffectHandler {
        PrepareWorktreesEffectHandler {
            effects: Arc::clone(self),
        }
    }

    pub fn publish_implementation_handler(self: &Arc<Self>) -> PublishImplementationEffectHandler {
        PublishImplementationEffectHandler {
            effects: Arc::clone(self),
        }
    }

    pub fn commit_worker_manifest_handler(
        self: &Arc<Self>,
        artifacts: crate::artifacts::ArtifactStore,
    ) -> CommitWorkerManifestEffectHandler {
        CommitWorkerManifestEffectHandler {
            effects: Arc::clone(self),
            artifacts,
        }
    }

    /// Resolve one durable publication receipt to its fresh configured PR observation. The
    /// supplied receipt must be read from the succeeded effects journal by its caller.
    pub fn resolve_current_pull_request(
        &self,
        receipt: &ImplementationPublicationReceipt,
    ) -> Result<crate::delivery_forge::ObservedPullRequest, String> {
        let repository = self.repository(&receipt.repository_id)?;
        if repository.forge != "github"
            || receipt.pull_request.repository_id != receipt.repository_id
            || receipt.push.repository_id != receipt.repository_id
            || receipt.hook_gate.repository_id != receipt.repository_id
            || receipt.pull_request.source_branch != receipt.push.branch
            || receipt.pull_request.source_head != receipt.push.pushed_head
            || receipt.pull_request.source_head != receipt.commit.head()
            || receipt.pull_request.base_branch != repository.base_branch
        {
            return Err(
                "persisted publication receipt does not match current repository policy".into(),
            );
        }
        let observation = self
            .publisher
            .observe_matching(
                &repository.clone_url,
                &receipt.pull_request.source_branch,
                &repository.base_branch,
            )
            .map_err(|error| error.to_string())?;
        let crate::delivery_forge::ObservationCapability::Known(pull_requests) =
            observation.pull_requests
        else {
            return Err("current pull-request observation capability is unknown".into());
        };
        let matching = pull_requests
            .into_iter()
            .filter(|pull| pull.number == receipt.pull_request.number)
            .collect::<Vec<_>>();
        let [pull] = matching.as_slice() else {
            return Err(
                "persisted pull request is missing or ambiguous in current observation".into(),
            );
        };
        let body_digest = pull.body.as_deref().map(|body| sha256_hex(body.as_bytes()));
        if pull.node_id != receipt.pull_request.node_id
            || pull.source_branch != receipt.pull_request.source_branch
            || pull.source_head != receipt.pull_request.source_head
            || pull.base_branch != receipt.pull_request.base_branch
            || pull.title != receipt.pull_request.title
            || body_digest.as_deref() != Some(receipt.pull_request.body_digest.as_str())
        {
            return Err(
                "current pull request differs from its succeeded publication receipt".into(),
            );
        }
        Ok(pull.clone())
    }

    /// Resolve a durable publication receipt and fetch the human-readable diff, checks, and
    /// reviews for the same PR. The receipt is checked before any detail is returned.
    pub fn resolve_current_pull_request_review(
        &self,
        receipt: &ImplementationPublicationReceipt,
    ) -> Result<
        (
            crate::delivery_forge::ObservedPullRequest,
            crate::delivery_forge::PullRequestReviewMaterial,
        ),
        String,
    > {
        let pull = self.resolve_current_pull_request(receipt)?;
        let repository = self.repository(&receipt.repository_id)?;
        let material = self
            .publisher
            .review_material(
                &repository.clone_url,
                receipt.pull_request.number,
                receipt.commit.head(),
            )
            .map_err(|error| error.to_string())?;
        Ok((pull, material))
    }

    /// Fresh, paginated view used by human review and publication reconciliation.
    pub fn observe_current_pull_requests(
        &self,
        repository_id: &RepositoryId,
        source_branch: &str,
    ) -> Result<crate::delivery_forge::GitHubPublicationObservation, String> {
        let repository = self.repository(repository_id)?;
        if repository.forge != "github" {
            return Err("fresh pull-request observation is supported only for GitHub".into());
        }
        self.publisher
            .observe_matching(
                &repository.clone_url,
                source_branch,
                &repository.base_branch,
            )
            .map_err(|error| error.to_string())
    }

    pub fn observe_remote_branch(
        &self,
        repository_id: &RepositoryId,
        branch: &str,
    ) -> Result<Option<String>, String> {
        self.delivery
            .observe_configured_remote_branch(self.repository(repository_id)?, branch)
            .map_err(|error| error.to_string())
    }

    fn ensure_initial_publication_baseline(
        &self,
        store: &mut crate::store::ConfigStore,
        owner_generation: u64,
        request: &EffectRequest,
        payload: &PrepareWorktreesEffectPayload,
        node: &PreparedWorktreeNodeRequest,
        now_unix: i64,
    ) -> Result<(), String> {
        let identity = WorkNodeIdentity {
            project_id: request.intent.project_id.clone(),
            repository_id: node.repository_id.clone(),
            ticket_namespace: payload.ticket_namespace.clone(),
            ticket_id: payload.ticket_id.clone(),
            ticket_run_id: payload.ticket_run_id.clone(),
            work_node_id: node.work_node_id.to_string(),
        };
        let branch = identity.branch_name().map_err(|error| error.to_string())?;
        let resource = crate::store::publication_monitor::PublicationResource {
            project_id: request.intent.project_id.clone(),
            ticket_run_id: payload.ticket_run_id.clone(),
            repository_id: node.repository_id.clone(),
            branch: branch.clone(),
        };
        if let Some(baseline) = store.load_publication_baseline(&resource)? {
            if baseline.base_branch != self.repository(&node.repository_id)?.base_branch {
                return Err(
                    "stored publication baseline does not match current repository base branch"
                        .into(),
                );
            }
            return Ok(());
        }
        let repository = self.repository(&node.repository_id)?;
        let remote_head = self
            .delivery
            .observe_configured_remote_branch(repository, &branch)
            .map_err(|error| error.to_string())?;
        let observed = self.observe_current_pull_requests(&node.repository_id, &branch)?;
        let observation = RepositoryPublicationObservation {
            remote_head,
            pull_requests: observed.pull_requests,
        };
        if observation.remote_head.is_some()
            || observation.pull_requests
                != crate::delivery_forge::ObservationCapability::Known(Vec::new())
        {
            return Err("managed branch or pull request already exists without a trusted initial baseline; human reconciliation is required".into());
        }
        store.insert_initial_publication_baseline(
            owner_generation,
            &resource,
            &repository.base_branch,
            &payload.configuration_digest,
            &observation,
            now_unix,
        )?;
        Ok(())
    }

    fn prepare_worktrees(
        &self,
        request: &EffectRequest,
    ) -> Result<PreparedWorktreesEffectReceipt, String> {
        let payload: PrepareWorktreesEffectPayload = decode_effect_payload(request)?;
        self.validate_prepare_payload(request, &payload)?;
        let mut receipts = Vec::with_capacity(payload.work_nodes.len());
        for node in payload.work_nodes {
            let identity = WorkNodeIdentity {
                project_id: request.intent.project_id.clone(),
                repository_id: node.repository_id.clone(),
                ticket_namespace: payload.ticket_namespace.clone(),
                ticket_id: payload.ticket_id.clone(),
                ticket_run_id: payload.ticket_run_id.clone(),
                work_node_id: node.work_node_id.to_string(),
            };
            let repository_config = self.repository(&node.repository_id)?;
            let prepared = self
                .delivery
                .prepare_worktree(
                    identity,
                    repository_config,
                    &node.expected_base_sha,
                    node.commit_mode,
                )
                .map_err(|error| error.to_string())?;
            receipts.push(PreparedWorktreeReceiptNode {
                work_node_id: node.work_node_id,
                repository_id: node.repository_id,
                worktree_path: prepared.worktree.path,
                branch: prepared.worktree.branch,
                base_sha: prepared.worktree.base_sha,
                commit_mode: prepared.commit_mode,
            });
        }
        Ok(PreparedWorktreesEffectReceipt {
            schema_version: 1,
            ticket_run_id: payload.ticket_run_id,
            work_nodes: receipts,
        })
    }

    fn commit_worker_manifest(
        &self,
        mode: EffectMode,
        request: &EffectRequest,
        store: &mut crate::store::ConfigStore,
        owner_generation: u64,
        artifacts: &crate::artifacts::ArtifactStore,
    ) -> Result<EffectObservation, String> {
        validate_effect_kind(request, EffectKind::CommitWorkerManifest)?;
        let payload: CommitWorkerManifestEffectPayload = decode_effect_payload(request)?;
        if payload.schema_version != 1
            || request.intent.subject_type != "ticket_run"
            || request.intent.subject_id != payload.ticket_run_id.as_str()
            || request.intent.project_id != payload.project_id
            || request.intent.expected_revision != Some(payload.ticket_revision)
            || payload.manifest_artifact.kind
                != crate::engine::orchestration::RoleArtifactKind::Change
            || payload.manifest_artifact.schema_version != 1
            || payload.manifest_artifact.digest != payload.manifest_digest
            || payload.commit_message.trim().is_empty()
            || payload.commit_message.contains('\0')
        {
            return Err("Worker commit effect does not match its immutable mailbox scope".into());
        }
        validate_git_sha(&payload.expected_base_sha).map_err(|error| error.to_string())?;
        validate_git_sha(&payload.expected_head).map_err(|error| error.to_string())?;

        let authority = store
            .agent_launch_authority(&payload.agent_run_id)?
            .ok_or("repository.commit launch authority is missing")?;
        let reservation = store
            .agent_launch_reservation_for_run(&payload.agent_run_id)?
            .ok_or("repository.commit launch reservation is missing")?;
        if authority.controller_generation != owner_generation
            || authority.project_id != payload.project_id
            || authority.role != crate::domain::types::Role::Worker
            || authority.ticket_run_id.as_ref() != Some(&payload.ticket_run_id)
            || authority.ticket_revision.map(|value| value.0) != Some(payload.ticket_revision)
            || authority.config_digest != payload.configuration_digest
            || reservation.controller_generation != owner_generation
            || reservation.agent_run_id != payload.agent_run_id
            || reservation.project_id != authority.project_id
            || reservation.role != authority.role
            || reservation.ticket_run_id.as_ref() != Some(&payload.ticket_run_id)
            || reservation.ticket_revision.map(|value| value.0) != Some(payload.ticket_revision)
            || reservation.config_digest != payload.configuration_digest
        {
            return Err(
                "repository.commit effect no longer matches the active Worker authority".into(),
            );
        }
        let assignment = reservation
            .worker_assignment
            .as_ref()
            .ok_or("repository.commit Worker has no prepared-worktree assignment")?;
        if assignment.commit_mode != CommitMode::Host
            || assignment.node_id != payload.work_node_id
            || assignment.repository_id != payload.repository_id
            || assignment.worktree_path != payload.worktree_path
            || assignment.branch != payload.branch
            || assignment.base_sha != payload.expected_base_sha
            || assignment.prepare_operation_id != payload.prepare_operation_id.as_str()
        {
            return Err(
                "repository.commit effect differs from the immutable Worker assignment".into(),
            );
        }

        let prior_publications = store.list_succeeded_effect_receipts(
            owner_generation,
            &authority.project_id,
            "ticket_run",
            payload.ticket_run_id.as_str(),
            256,
        )?;
        let mut latest_published_head = None;
        for publication in &prior_publications {
            if publication.intent().kind
                != crate::engine::reducer::effect_name(&EffectKind::PublishImplementation)
            {
                continue;
            }
            let published: ImplementationPublicationReceipt =
                serde_json::from_str(publication.receipt_json())
                    .map_err(|error| format!("stored publication receipt is invalid: {error}"))?;
            if published.work_node_id == payload.work_node_id
                && published.repository_id == payload.repository_id
                && published.ticket_run_id == payload.ticket_run_id
            {
                latest_published_head = Some(published.commit.head().to_owned());
            }
        }
        let recovery_authorization = reservation.wake_snapshot.worker_recovery_authorization()?;
        let recovery_head = if let Some(recovery) = &recovery_authorization {
            if recovery.ticket_run_id != payload.ticket_run_id
                || recovery.ticket_revision != payload.ticket_revision
                || recovery.work_node_id != payload.work_node_id
                || recovery.accepted_plan_digest != assignment.plan_digest
                || recovery.prior_worker_agent_run_id == payload.agent_run_id
                || recovery.expected_head != payload.expected_head
            {
                return Err("repository.commit Worker recovery authorization differs from this accepted node".into());
            }
            match recovery.prior_host_commit_operation_id.as_ref() {
                Some(prior_operation_id) => {
                    let prior = store
                        .succeeded_effect_receipt(prior_operation_id.as_str())?
                        .ok_or("Worker recovery prior host commit is no longer succeeded")?;
                    if prior.intent().kind
                        != crate::engine::reducer::effect_name(&EffectKind::CommitWorkerManifest)
                    {
                        return Err(
                            "Worker recovery prior operation is not a host Worker commit".into(),
                        );
                    }
                    let prior_payload: CommitWorkerManifestEffectPayload =
                        serde_json::from_str(&prior.intent().request_json).map_err(|error| {
                            format!("stored prior Worker commit request is invalid: {error}")
                        })?;
                    let prior_receipt: CommitWorkerManifestEffectReceipt =
                        serde_json::from_str(prior.receipt_json()).map_err(|error| {
                            format!("stored prior Worker commit receipt is invalid: {error}")
                        })?;
                    let receipt_digest =
                        Digest::parse(sha256_hex(prior.receipt_json().as_bytes()))?;
                    if recovery.prior_host_commit_receipt_digest.as_ref() != Some(&receipt_digest)
                        || prior.intent().project_id != authority.project_id
                        || prior.intent().subject_type != "ticket_run"
                        || prior.intent().subject_id != payload.ticket_run_id.as_str()
                        || prior.intent().expected_revision != Some(payload.ticket_revision)
                        || prior_payload.agent_run_id != recovery.prior_worker_agent_run_id
                        || prior_payload.project_id != authority.project_id
                        || prior_payload.configuration_digest != authority.config_digest
                        || prior_payload.ticket_revision != payload.ticket_revision
                        || prior_payload.ticket_run_id != payload.ticket_run_id
                        || prior_payload.work_node_id != payload.work_node_id
                        || prior_payload.repository_id != payload.repository_id
                        || prior_payload.expected_base_sha != assignment.base_sha
                        || prior_payload.prepare_operation_id.as_str()
                            != assignment.prepare_operation_id
                        || prior_receipt.agent_run_id != recovery.prior_worker_agent_run_id
                        || prior_receipt.message_id != prior_payload.message_id
                        || prior_receipt.ticket_run_id != payload.ticket_run_id
                        || prior_receipt.work_node_id != payload.work_node_id
                        || prior_receipt.repository_id != payload.repository_id
                        || prior_receipt.base_sha != assignment.base_sha
                        || prior_receipt.manifest_artifact != prior_payload.manifest_artifact
                        || prior_receipt.commit.operation_id != *prior_operation_id
                        || prior_receipt.commit.expected_head != prior_payload.expected_head
                        || prior_receipt.commit.observed_head != recovery.expected_head
                        || prior_receipt.commit.observed_head == prior_receipt.commit.expected_head
                        || !prior_receipt.commit.signature_verified
                        || !prior_receipt.commit.hooks_completed
                        || !prior_receipt.commit.index_synchronized
                        || prior_receipt.commit.index_sync_conflict
                    {
                        return Err("Worker recovery prior host commit receipt does not prove the authorized HEAD".into());
                    }
                    Some(prior_receipt.commit.observed_head)
                }
                None => {
                    if recovery.expected_head != assignment.base_sha {
                        return Err(
                            "pre-commit Worker recovery does not start at the prepared base".into(),
                        );
                    }
                    None
                }
            }
        } else {
            None
        };
        let trusted_previous_head = recovery_head
            .as_deref()
            .or(latest_published_head.as_deref())
            .unwrap_or(payload.expected_base_sha.as_str());
        if payload.expected_head != trusted_previous_head {
            return Err(
                "repository.commit expected HEAD is not the current host-accepted work-node head"
                    .into(),
            );
        }
        for prior in &prior_publications {
            if prior.intent().kind
                != crate::engine::reducer::effect_name(&EffectKind::CommitWorkerManifest)
            {
                continue;
            }
            let previous: CommitWorkerManifestEffectReceipt =
                serde_json::from_str(prior.receipt_json())
                    .map_err(|error| format!("stored Worker commit receipt is invalid: {error}"))?;
            if previous.agent_run_id == payload.agent_run_id
                && previous.work_node_id == payload.work_node_id
                && prior.intent().operation_id != request.intent.operation_id
            {
                return Err("Worker already submitted a repository.commit request for this run and work node".into());
            }
        }

        let prepared_effect = store
            .succeeded_effect_receipt(payload.prepare_operation_id.as_str())?
            .ok_or("repository.commit prepared-worktree effect is no longer succeeded")?;
        let (validated_prepared, prepared_receipt) =
            validate_prepared_worktree_stage(&prepared_effect)?;
        let prepare_request: PrepareWorktreesEffectPayload =
            serde_json::from_str(&prepared_effect.intent().request_json)
                .map_err(|error| format!("prepared-worktree request is invalid: {error}"))?;
        let prepared_node = prepared_receipt
            .work_nodes
            .iter()
            .find(|node| node.work_node_id == payload.work_node_id)
            .ok_or("prepared-worktree receipt omits the Worker node")?;
        if validated_prepared.project_id != authority.project_id
            || validated_prepared.ticket_run_id != payload.ticket_run_id
            || prepare_request.ticket_namespace != payload.ticket_namespace
            || prepare_request.ticket_id != payload.ticket_id
            || prepare_request.configuration_digest != payload.configuration_digest
            || prepare_request
                .work_nodes
                .iter()
                .filter(|node| {
                    node.work_node_id == payload.work_node_id
                        && node.repository_id == payload.repository_id
                        && node.expected_base_sha == payload.expected_base_sha
                        && node.commit_mode == CommitMode::Host
                })
                .count()
                != 1
            || prepared_node.repository_id != payload.repository_id
            || prepared_node.worktree_path != payload.worktree_path
            || prepared_node.branch != payload.branch
            || prepared_node.base_sha != payload.expected_base_sha
            || prepared_node.commit_mode != CommitMode::Host
        {
            return Err(
                "repository.commit effect differs from its succeeded worktree preparation".into(),
            );
        }
        let verified_artifact = store
            .lookup_verified_artifact(artifacts, &authority, &payload.manifest_artifact)?
            .ok_or("repository.commit manifest is not registered to the Worker run")?;
        let manifest_bytes = verified_artifact.read_bytes(artifacts)?;
        let manifest_digest = Digest::parse(format!("{:x}", Sha256::digest(&manifest_bytes)))?;
        if manifest_digest != payload.manifest_digest {
            return Err(
                "repository.commit manifest bytes differ from the registered digest".into(),
            );
        }
        let manifest: ChangeManifest = crate::protocol::parse_unique(&manifest_bytes)?;
        if manifest.schema_version != 1
            || manifest.entries.is_empty()
            || serde_json::to_vec(&manifest).map_err(|error| error.to_string())? != manifest_bytes
            || manifest != payload.manifest
        {
            return Err(
                "repository.commit manifest is not the registered canonical manifest".into(),
            );
        }

        let identity = WorkNodeIdentity {
            project_id: authority.project_id.clone(),
            repository_id: payload.repository_id.clone(),
            ticket_namespace: payload.ticket_namespace.clone(),
            ticket_id: payload.ticket_id.clone(),
            ticket_run_id: payload.ticket_run_id.clone(),
            work_node_id: payload.work_node_id.to_string(),
        };
        let repository_config = self.repository(&payload.repository_id)?;
        let work = self
            .delivery
            .prepare_worktree(
                identity,
                repository_config,
                &payload.expected_base_sha,
                CommitMode::Host,
            )
            .map_err(|error| error.to_string())?;
        if work.worktree.path != payload.worktree_path || work.worktree.branch != payload.branch {
            return Err(
                "prepared Worker worktree identity changed before repository.commit".into(),
            );
        }
        self.delivery
            .validate_required_commit_trailer(
                &work,
                &payload.commit_message,
                &payload.required_trailer,
            )
            .map_err(|error| error.to_string())?;
        let operation_id = OperationId::parse(request.intent.operation_id.clone())?;
        let commit = match mode {
            EffectMode::Submit => {
                let prepared = self
                    .delivery
                    .prepare_host_manifest(
                        &work,
                        operation_id.clone(),
                        &payload.expected_head,
                        payload.manifest.clone(),
                        &work.worktree.path,
                        payload.commit_message.clone(),
                    )
                    .map_err(|error| error.to_string())?;
                self.delivery
                    .execute_host_commit(&work, &prepared)
                    .map_err(|error| error.to_string())?
            }
            EffectMode::Reconcile => {
                let Some(prepared) = self
                    .delivery
                    .load_prepared_host_manifest(
                        &work,
                        &operation_id,
                        &payload.expected_head,
                        &payload.manifest,
                        &work.worktree.path,
                        &payload.commit_message,
                    )
                    .map_err(|error| error.to_string())?
                else {
                    return absent_effect(
                        EffectKind::CommitWorkerManifest,
                        request,
                        "managed_host_commit_intent",
                        "no prepared host commit exists yet for this durable operation".into(),
                    );
                };
                match self
                    .delivery
                    .reconcile_host_commit(&work, &prepared)
                    .map_err(|error| error.to_string())?
                {
                    Some(receipt) => receipt,
                    None => {
                        return absent_effect(
                            EffectKind::CommitWorkerManifest,
                            request,
                            "managed_git_worktree_head",
                            format!(
                                "the owned branch remains at expected head {}",
                                payload.expected_head
                            ),
                        );
                    }
                }
            }
        };
        if commit.operation_id != operation_id
            || commit.repository_id != payload.repository_id
            || commit.expected_head != payload.expected_head
            || commit.observed_head == payload.expected_head
            || !commit.signature_verified
            || !commit.hooks_completed
            || !commit.index_synchronized
            || commit.index_sync_conflict
        {
            return Err(
                "host commit receipt does not prove the requested signed repository change".into(),
            );
        }
        let receipt = CommitWorkerManifestEffectReceipt {
            schema_version: 1,
            agent_run_id: payload.agent_run_id,
            message_id: payload.message_id,
            ticket_run_id: payload.ticket_run_id,
            work_node_id: payload.work_node_id,
            repository_id: payload.repository_id,
            base_sha: payload.expected_base_sha,
            manifest_artifact: payload.manifest_artifact,
            commit,
        };
        Ok(EffectObservation::Applied {
            receipt: serde_json::to_string(&receipt).map_err(|error| error.to_string())?,
        })
    }

    fn validate_prepare_payload(
        &self,
        request: &EffectRequest,
        payload: &PrepareWorktreesEffectPayload,
    ) -> Result<(), String> {
        self.validate_scope(
            request,
            &payload.ticket_run_id,
            &payload.configuration_digest,
        )?;
        validate_effect_kind(request, EffectKind::PrepareWorktrees)?;
        validate_source_revision(request, payload.source_revision)?;
        if payload.schema_version != 1 || payload.work_nodes.is_empty() {
            return Err("prepare_worktrees payload is empty or uses an unsupported schema".into());
        }
        let mut previous_id: Option<String> = None;
        for node in &payload.work_nodes {
            let node_id = node.work_node_id.to_string();
            if previous_id
                .as_ref()
                .is_some_and(|previous| previous >= &node_id)
            {
                return Err("work_nodes must be unique and sorted by work_node_id".into());
            }
            previous_id = Some(node_id);
            self.require_repository(&request.intent.project_id, &node.repository_id)?;
            if node.commit_mode == CommitMode::Auto {
                return Err(
                    "commit_mode must resolve to native or host before worktree prep".into(),
                );
            }
            validate_git_sha(&node.expected_base_sha).map_err(|error| error.to_string())?;
        }
        Ok(())
    }

    fn validate_publish_payload(
        &self,
        request: &EffectRequest,
        payload: &PublishImplementationEffectPayload,
    ) -> Result<(), String> {
        self.validate_scope(
            request,
            &payload.ticket_run_id,
            &payload.configuration_digest,
        )?;
        validate_effect_kind(request, EffectKind::PublishImplementation)?;
        validate_source_revision(request, payload.source_revision)?;
        if payload.schema_version != 1 {
            return Err("publish_implementation uses an unsupported schema".into());
        }
        self.require_repository(&request.intent.project_id, &payload.repository_id)?;
        if payload.commit_mode == CommitMode::Auto {
            return Err("commit_mode must resolve to native or host before publishing".into());
        }
        validate_git_sha(&payload.expected_base_sha).map_err(|error| error.to_string())?;
        if let Some(expected) = &payload.expected_remote_head {
            validate_git_sha(expected).map_err(|error| error.to_string())?;
        }
        let repository_config = self.repository(&payload.repository_id)?;
        if payload.base_branch != repository_config.base_branch {
            return Err("pull request base branch differs from repository configuration".into());
        }
        crate::delivery_forge::validate_github_clone_url(&repository_config.clone_url)
            .map_err(|error| error.to_string())?;
        if payload.pull_request.title.trim().is_empty()
            || payload.pull_request.title.contains(['\n', '\r'])
        {
            return Err("pull request title must be one nonempty line".into());
        }
        match (&payload.commit, payload.commit_mode) {
            (
                WorkerDeliveryCommit::Native {
                    previous_accepted_head,
                    worker_reported_head,
                    required_trailer,
                },
                CommitMode::Native,
            ) => {
                validate_git_sha(previous_accepted_head).map_err(|error| error.to_string())?;
                validate_git_sha(worker_reported_head).map_err(|error| error.to_string())?;
                if required_trailer.trim().is_empty() || required_trailer.contains(['\n', '\r']) {
                    return Err("required commit trailer must be a nonempty single line".into());
                }
            }
            (
                WorkerDeliveryCommit::HostReceipt {
                    expected_head,
                    worker_reported_head,
                    receipt,
                    ..
                },
                CommitMode::Host,
            ) => {
                validate_git_sha(expected_head).map_err(|error| error.to_string())?;
                validate_git_sha(worker_reported_head).map_err(|error| error.to_string())?;
                if receipt.schema_version != 1
                    || receipt.commit.expected_head != *expected_head
                    || receipt.commit.observed_head != *worker_reported_head
                    || !receipt.commit.signature_verified
                    || !receipt.commit.hooks_completed
                    || receipt.commit.expected_head == receipt.commit.observed_head
                {
                    return Err("host receipt does not identify one verified host commit".into());
                }
            }
            _ => return Err("commit payload does not match the configured commit mode".into()),
        }
        Ok(())
    }

    fn publish_implementation(
        &self,
        mode: EffectMode,
        request: &EffectRequest,
        store: &mut crate::store::ConfigStore,
        owner_generation: u64,
        now_unix: i64,
    ) -> Result<EffectObservation, String> {
        let payload: PublishImplementationEffectPayload = decode_effect_payload(request)?;
        self.validate_publish_payload(request, &payload)?;
        let repository_config = self.repository(&payload.repository_id)?;
        let identity = WorkNodeIdentity {
            project_id: request.intent.project_id.clone(),
            repository_id: payload.repository_id.clone(),
            ticket_namespace: payload.ticket_namespace.clone(),
            ticket_id: payload.ticket_id.clone(),
            ticket_run_id: payload.ticket_run_id.clone(),
            work_node_id: payload.work_node_id.to_string(),
        };
        let work = self
            .delivery
            .prepare_worktree(
                identity,
                repository_config,
                &payload.expected_base_sha,
                payload.commit_mode,
            )
            .map_err(|error| error.to_string())?;
        store.assert_publication_unblocked(
            &crate::store::publication_monitor::PublicationResource {
                project_id: request.intent.project_id.clone(),
                ticket_run_id: payload.ticket_run_id.clone(),
                repository_id: payload.repository_id.clone(),
                branch: work.worktree.branch.clone(),
            },
        )?;
        let commit = match (&payload.commit, payload.commit_mode, mode) {
            (
                WorkerDeliveryCommit::Native {
                    previous_accepted_head,
                    worker_reported_head,
                    required_trailer,
                },
                CommitMode::Native,
                EffectMode::Submit,
            ) => self
                .delivery
                .verify_worker_commit(
                    &work,
                    WorkerCommitSubmission::Native {
                        previous_accepted_head: previous_accepted_head.clone(),
                        worker_reported_head: worker_reported_head.clone(),
                        required_trailer: required_trailer.clone(),
                    },
                )
                .map_err(|error| error.to_string())?,
            (
                WorkerDeliveryCommit::Native {
                    previous_accepted_head,
                    worker_reported_head,
                    required_trailer,
                },
                CommitMode::Native,
                EffectMode::Reconcile,
            ) => {
                if self
                    .delivery
                    .observe_local_head(&work)
                    .map_err(|error| error.to_string())?
                    .as_str()
                    == previous_accepted_head
                {
                    return absent_effect(
                        EffectKind::PublishImplementation,
                        request,
                        "managed_git_worktree_head",
                        format!(
                            "the owned branch remains at accepted head {previous_accepted_head}"
                        ),
                    );
                }
                self.delivery
                    .verify_worker_commit(
                        &work,
                        WorkerCommitSubmission::Native {
                            previous_accepted_head: previous_accepted_head.clone(),
                            worker_reported_head: worker_reported_head.clone(),
                            required_trailer: required_trailer.clone(),
                        },
                    )
                    .map_err(|error| error.to_string())?
            }
            (
                WorkerDeliveryCommit::HostReceipt {
                    operation_id,
                    expected_head,
                    worker_reported_head,
                    receipt,
                },
                CommitMode::Host,
                _,
            ) => {
                let stored = store
                    .succeeded_effect_receipt(operation_id.as_str())?
                    .ok_or("Worker host commit receipt is not durably succeeded")?;
                if stored.intent().kind
                    != crate::engine::reducer::effect_name(&EffectKind::CommitWorkerManifest)
                    || stored.intent().project_id != request.intent.project_id
                    || stored.intent().subject_id != payload.ticket_run_id.as_str()
                {
                    return Err(
                        "Worker host commit effect receipt has the wrong durable scope".into(),
                    );
                }
                let persisted_receipt: CommitWorkerManifestEffectReceipt =
                    serde_json::from_str(stored.receipt_json()).map_err(|error| {
                        format!("stored Worker commit receipt is invalid: {error}")
                    })?;
                if &persisted_receipt != receipt.as_ref()
                    || receipt.commit.operation_id != *operation_id
                    || receipt.ticket_run_id != payload.ticket_run_id
                    || receipt.work_node_id != payload.work_node_id
                    || receipt.repository_id != payload.repository_id
                    || receipt.base_sha != payload.expected_base_sha
                    || receipt.commit.expected_head != *expected_head
                    || receipt.commit.observed_head != *worker_reported_head
                    || receipt.commit.observed_head == *expected_head
                {
                    return Err(
                        "Worker result does not match the durable host commit receipt".into(),
                    );
                }
                VerifiedCommit::Host {
                    receipt: receipt.commit.clone(),
                }
            }
            _ => return Err("commit payload does not match the configured commit mode".into()),
        };
        let mut host_jobs = self
            .host_jobs
            .lock()
            .map_err(|_| "host job pool lock is poisoned".to_owned())?;
        host_jobs.poll(store, owner_generation, now_unix)?;
        let Some(hook_gate) = self
            .delivery
            .run_required_hooks_managed(
                &work,
                repository_config,
                &self.configuration_digest,
                &commit,
                crate::hooks::ManagedHookExecution {
                    store,
                    pool: &mut host_jobs,
                    owner_generation,
                    effect_operation_id: &request.intent.operation_id,
                    max_attempts: self.max_hook_attempts,
                    now_unix,
                },
            )
            .map_err(|error| error.to_string())?
        else {
            return Ok(EffectObservation::Pending {
                receipt: serde_json::json!({
                    "schema_version": 1,
                    "state": "repository_hooks_pending",
                    "effect_operation_id": request.intent.operation_id,
                    "head": commit.head(),
                })
                .to_string(),
            });
        };
        let pr_operation = derived_operation_id(
            &request.intent.operation_id,
            &payload.repository_id,
            payload.work_node_id.as_str(),
            "pull-request",
        )?;
        let publication_intent = PullRequestPublicationIntent {
            operation_id: pr_operation,
            repository_id: payload.repository_id.clone(),
            clone_url: repository_config.clone_url.clone(),
            source_branch: work.worktree.branch.clone(),
            source_head: commit.head().to_owned(),
            base_branch: repository_config.base_branch.clone(),
            title: payload.pull_request.title.clone(),
            body: payload.pull_request.body.clone(),
            update_target: payload.pull_request.update_target.clone(),
        };
        let before_publication = self
            .delivery
            .observe_publication(&self.publisher, &work, &publication_intent)
            .map_err(|error| error.to_string())?;
        let expected_remote = if mode == EffectMode::Reconcile {
            Some(commit.head())
        } else {
            payload.expected_remote_head.as_deref()
        };
        let remote_is_reconciled = before_publication.remote_head.as_deref() == expected_remote
            || (mode == EffectMode::Reconcile
                && before_publication.remote_head.as_deref()
                    == payload.expected_remote_head.as_deref());
        let pull_requests_are_reconciled = match &before_publication.pull_requests {
            crate::delivery_forge::ObservationCapability::Unknown => {
                return Err("GitHub PR and timeline observation capability is unknown".into());
            }
            crate::delivery_forge::ObservationCapability::Known(pull_requests) => {
                if mode == EffectMode::Reconcile {
                    pull_requests.len() <= 1
                        && pull_requests.first().is_none_or(|pull| {
                            !pull.merged
                                && pull.state == "open"
                                && pull.body.as_deref().is_some_and(|body| {
                                    body.contains(&format!(
                                        "<!-- rex-projects-operation:{} -->",
                                        publication_intent.operation_id
                                    ))
                                })
                                && pull.source_branch == publication_intent.source_branch
                                && pull.source_head == publication_intent.source_head
                                && pull.base_branch == publication_intent.base_branch
                                && pull.title == publication_intent.title
                                && pull.body.as_deref()
                                    == Some(marked_body_for_monitor(&publication_intent).as_str())
                                && matches!(
                                    &pull.timeline,
                                    crate::delivery_forge::ObservationCapability::Known(entries)
                                        if entries.is_empty()
                                )
                        })
                } else if let Some(target) = &publication_intent.update_target {
                    pull_requests.len() == 1
                        && pull_requests[0].number == target.number
                        && !pull_requests[0].merged
                        && pull_requests[0].state == "open"
                        && pull_requests[0].source_head == target.expected_head
                        && pull_requests[0].source_branch == publication_intent.source_branch
                        && pull_requests[0].base_branch == publication_intent.base_branch
                } else {
                    pull_requests.is_empty()
                }
            }
        };
        if !remote_is_reconciled || !pull_requests_are_reconciled {
            let facts = serde_json::json!({
                "observed_remote_head": before_publication.remote_head,
                "expected_remote_head": expected_remote,
                "pull_requests": before_publication.pull_requests,
                "host_effect_operation_id": request.intent.operation_id,
                "publication_operation_id": publication_intent.operation_id,
                "work_node_id": payload.work_node_id,
            });
            let facts_json = serde_json::to_vec(&facts).map_err(|error| error.to_string())?;
            store
                .record_publication_irregularity(
                    owner_generation,
                    &crate::store::publication_monitor::PublicationIrregularity {
                        resource: crate::store::publication_monitor::PublicationResource {
                            project_id: request.intent.project_id.clone(),
                            ticket_run_id: payload.ticket_run_id.clone(),
                            repository_id: payload.repository_id.clone(),
                            branch: work.worktree.branch.clone(),
                        },
                        observation_digest: sha256_hex(&facts_json),
                        observed_at_unix: now_unix,
                        facts,
                    },
                )
                .map_err(|error| error.to_string())?;
            return Err("unexpected external publication mutation paused this work node".into());
        }
        if mode == EffectMode::Reconcile {
            let push = self
                .delivery
                .reconcile_owned_branch(
                    &work,
                    repository_config,
                    &self.configuration_digest,
                    commit.head(),
                    payload.expected_remote_head.as_deref(),
                    &hook_gate,
                )
                .map_err(|error| error.to_string())?;
            let Some(push) = push else {
                return absent_effect(
                    EffectKind::PublishImplementation,
                    request,
                    "git_remote_ref",
                    format!(
                        "{} is still at its prior expected head {:?}",
                        work.worktree.branch, payload.expected_remote_head
                    ),
                );
            };
            if let Some(pull_request) = self
                .publisher
                .reconcile(&publication_intent)
                .map_err(|error| error.to_string())?
            {
                return Ok(EffectObservation::Applied {
                    receipt: serde_json::to_string(&ImplementationPublicationReceipt {
                        schema_version: 1,
                        effect_operation_id: request.intent.operation_id.clone(),
                        source_revision: payload.source_revision,
                        configuration_digest: payload.configuration_digest.clone(),
                        ticket_run_id: payload.ticket_run_id.clone(),
                        repository_id: payload.repository_id,
                        work_node_id: payload.work_node_id,
                        commit,
                        hook_gate,
                        push,
                        pull_request,
                    })
                    .map_err(|error| error.to_string())?,
                });
            }
            return absent_effect(
                EffectKind::PublishImplementation,
                request,
                "github_pull_request_search",
                format!(
                    "no PR with operation marker {} for {}/{}",
                    publication_intent.operation_id,
                    publication_intent.source_branch,
                    publication_intent.base_branch
                ),
            );
        }
        let push = self
            .delivery
            .push_owned_branch(
                &work,
                repository_config,
                &self.configuration_digest,
                commit.head(),
                payload.expected_remote_head.as_deref(),
                &hook_gate,
            )
            .map_err(|error| error.to_string())?;
        let pull_request = self
            .delivery
            .publish_pull_request(
                &self.publisher,
                &work,
                PullRequestPublication {
                    repository_config,
                    configuration_digest: &self.configuration_digest,
                    expected_head: commit.head(),
                    hook_gate: &hook_gate,
                    intent: &publication_intent,
                },
            )
            .map_err(|error| error.to_string())?;
        Ok(EffectObservation::Applied {
            receipt: serde_json::to_string(&ImplementationPublicationReceipt {
                schema_version: 1,
                effect_operation_id: request.intent.operation_id.clone(),
                source_revision: payload.source_revision,
                configuration_digest: payload.configuration_digest.clone(),
                ticket_run_id: payload.ticket_run_id.clone(),
                repository_id: payload.repository_id,
                work_node_id: payload.work_node_id,
                commit,
                hook_gate,
                push,
                pull_request,
            })
            .map_err(|error| error.to_string())?,
        })
    }

    fn validate_scope(
        &self,
        request: &EffectRequest,
        ticket_run_id: &TicketRunId,
        configuration_digest: &Digest,
    ) -> Result<(), String> {
        if request.intent.subject_type != "ticket_run"
            || request.intent.subject_id != ticket_run_id.as_str()
            || request.intent.expected_revision.is_none()
            || configuration_digest != &self.configuration_digest
        {
            return Err("effect scope, revision, or configuration digest does not match".into());
        }
        Ok(())
    }

    fn require_repository(
        &self,
        project_id: &ProjectId,
        repository_id: &RepositoryId,
    ) -> Result<(), String> {
        if !self
            .project_repositories
            .get(project_id)
            .is_some_and(|repositories| repositories.contains(repository_id))
            || !self.repositories.contains_key(repository_id)
        {
            return Err("repository is not configured for this Project".into());
        }
        Ok(())
    }

    fn repository(&self, repository_id: &RepositoryId) -> Result<&RepositoryConfig, String> {
        self.repositories
            .get(repository_id)
            .ok_or_else(|| "repository is missing from the active configuration".into())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImplementationPublicationReceipt {
    pub schema_version: u32,
    pub effect_operation_id: String,
    pub source_revision: u64,
    pub configuration_digest: Digest,
    pub ticket_run_id: TicketRunId,
    pub repository_id: RepositoryId,
    pub work_node_id: WorkNodeId,
    pub commit: VerifiedCommit,
    pub hook_gate: HookGateReceipt,
    pub push: PushReceipt,
    pub pull_request: PublishedPullRequest,
}

/// Host-derived identity and coverage for the exact implementation publications under review.
/// The revision and coverage are prompt metadata; `digest()` intentionally hashes only the
/// historical three-field subject JSON consumed by ReviewReady validation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImplementationPublicationSetSubject {
    pub ticket_run_id: TicketRunId,
    pub accepted_plan_digest: Digest,
    pub publications: Vec<ImplementationPublicationSubjectFact>,
    pub coverage: Vec<WorkNodeId>,
    pub publication_revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImplementationPublicationSubjectFact {
    pub work_node_id: WorkNodeId,
    pub repository_id: RepositoryId,
    pub pull_request_number: u64,
    pub pull_request_node_id: String,
    pub pull_request_head: String,
    pub published_head: String,
    pub receipt_digest: String,
}

impl ImplementationPublicationSetSubject {
    /// This is deliberately the exact JSON value and field set historically accepted by the
    /// ReviewReady consumer. Do not add revision or coverage to this digest.
    pub fn digest(&self) -> Result<Digest, String> {
        let mut publications = self
            .publications
            .iter()
            .map(|publication| {
                serde_json::json!({
                    "work_node_id": publication.work_node_id,
                    "repository_id": publication.repository_id,
                    "pull_request_number": publication.pull_request_number,
                    "pull_request_node_id": publication.pull_request_node_id,
                    "pull_request_head": publication.pull_request_head,
                    "published_head": publication.published_head,
                    "receipt_digest": publication.receipt_digest,
                })
            })
            .collect::<Vec<_>>();
        publications
            .sort_by_key(|fact| fact["work_node_id"].as_str().unwrap_or_default().to_owned());
        let subject = serde_json::json!({
            "ticket_run_id": self.ticket_run_id,
            "accepted_plan_digest": self.accepted_plan_digest,
            "publications": publications,
        });
        let bytes = serde_json::to_vec(&subject).map_err(|error| error.to_string())?;
        Digest::parse(sha256_hex(&bytes))
    }
}

/// Opaque proof that the dispatcher’s durable Applied output matches its typed request.
/// Only this module can mint the capability; callers cannot fabricate a reviewer wake.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedImplementationPublication {
    project_id: ProjectId,
    ticket_run_id: TicketRunId,
    source_revision: u64,
    work_node_ids: Vec<WorkNodeId>,
    receipt_bindings: Vec<(WorkNodeId, String)>,
    publication_set_digest: String,
}

/// Opaque proof for one stage of an accepted implementation plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedWorkNodePublication {
    project_id: ProjectId,
    ticket_run_id: TicketRunId,
    source_revision: u64,
    configuration_digest: Digest,
    work_node_id: WorkNodeId,
    head: String,
    receipt_digest: String,
}

/// Opaque proof that a persisted preparation receipt covers these exact nodes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedPreparedWorktrees {
    project_id: ProjectId,
    ticket_run_id: TicketRunId,
    source_revision: u64,
    configuration_digest: Digest,
    work_node_ids: Vec<WorkNodeId>,
    receipt_digest: String,
}

impl ValidatedPreparedWorktrees {
    pub(crate) fn matches(&self, run: &crate::engine::reducer::TicketRun) -> bool {
        self.project_id == run.project_id
            && self.ticket_run_id == run.ticket_run_id
            && self.source_revision == run.revision.0
            && !self.work_node_ids.is_empty()
            && !self.receipt_digest.is_empty()
    }

    pub(crate) fn work_node_ids(&self) -> &[WorkNodeId] {
        &self.work_node_ids
    }

    pub(crate) fn configuration_digest(&self) -> &Digest {
        &self.configuration_digest
    }
}

pub fn validate_prepared_worktree_stage(
    stored: &crate::store::SucceededEffectReceipt,
) -> Result<(ValidatedPreparedWorktrees, PreparedWorktreesEffectReceipt), String> {
    let request = effect_request_from_persisted(stored);
    validate_effect_kind(&request, EffectKind::PrepareWorktrees)?;
    let payload: PrepareWorktreesEffectPayload = decode_effect_payload(&request)?;
    validate_source_revision(&request, payload.source_revision)?;
    if request.intent.subject_type != "ticket_run"
        || request.intent.subject_id != payload.ticket_run_id.as_str()
    {
        return Err("prepared receipt does not match its TicketRun subject".into());
    }
    let receipt: PreparedWorktreesEffectReceipt =
        serde_json::from_str(stored.receipt_json()).map_err(|error| error.to_string())?;
    validate_prepared_receipt(&payload, &receipt)?;
    Ok((
        ValidatedPreparedWorktrees {
            project_id: request.intent.project_id,
            ticket_run_id: payload.ticket_run_id,
            source_revision: payload.source_revision,
            configuration_digest: payload.configuration_digest,
            work_node_ids: payload
                .work_nodes
                .into_iter()
                .map(|node| node.work_node_id)
                .collect(),
            receipt_digest: sha256_hex(stored.receipt_json().as_bytes()),
        },
        receipt,
    ))
}

impl ValidatedWorkNodePublication {
    pub(crate) fn matches(&self, run: &crate::engine::reducer::TicketRun) -> bool {
        self.project_id == run.project_id
            && self.ticket_run_id == run.ticket_run_id
            && self.source_revision == run.revision.0
            && !self.head.is_empty()
            && !self.receipt_digest.is_empty()
    }

    pub fn work_node_id(&self) -> &WorkNodeId {
        &self.work_node_id
    }

    pub fn head(&self) -> &str {
        &self.head
    }

    pub(crate) fn configuration_digest(&self) -> &Digest {
        &self.configuration_digest
    }
}

impl ValidatedImplementationPublication {
    pub(crate) fn matches(&self, run: &crate::engine::reducer::TicketRun) -> bool {
        self.project_id == run.project_id
            && self.ticket_run_id == run.ticket_run_id
            && self.source_revision == run.revision.0
            && !self.work_node_ids.is_empty()
            && self
                .receipt_bindings
                .iter()
                .map(|(node_id, _)| node_id.clone())
                .eq(self.work_node_ids.iter().cloned())
            && digest_json(&(&self.work_node_ids, &self.receipt_bindings))
                .is_ok_and(|digest| digest == self.publication_set_digest)
    }
}

/// Build the Reviewer subject only from a validated complete publication capability.
/// The capability and persisted receipt set must still agree exactly at the call site.
pub fn implementation_publication_set_subject(
    accepted_plan_digest: &Digest,
    work_plan: &WorkPlan,
    validated: &ValidatedImplementationPublication,
    publications: &[crate::store::SucceededEffectReceipt],
    publication_revision: u64,
) -> Result<ImplementationPublicationSetSubject, String> {
    let expected = work_plan
        .nodes
        .iter()
        .filter(|node| !node.investigation)
        .map(|node| node.id.clone())
        .collect::<BTreeSet<_>>();
    let bindings = validated
        .receipt_bindings
        .iter()
        .cloned()
        .collect::<BTreeMap<_, _>>();
    if expected.is_empty()
        || expected.iter().cloned().collect::<Vec<_>>() != validated.work_node_ids
        || bindings.len() != validated.receipt_bindings.len()
        || bindings.keys().cloned().collect::<BTreeSet<_>>() != expected
        || publications.len() != bindings.len()
    {
        return Err(
            "validated publication capability differs from the accepted implementation plan".into(),
        );
    }
    let mut facts = Vec::with_capacity(publications.len());
    let mut seen_work_node_ids = BTreeSet::new();
    for publication in publications {
        let receipt: ImplementationPublicationReceipt =
            serde_json::from_str(publication.receipt_json())
                .map_err(|error| format!("invalid implementation publication receipt: {error}"))?;
        let receipt_digest = sha256_hex(publication.receipt_json().as_bytes());
        if bindings.get(&receipt.work_node_id) != Some(&receipt_digest)
            || !seen_work_node_ids.insert(receipt.work_node_id.clone())
            || receipt.ticket_run_id != validated.ticket_run_id
        {
            return Err(
                "publication receipt differs from the validated publication capability".into(),
            );
        }
        facts.push(ImplementationPublicationSubjectFact {
            work_node_id: receipt.work_node_id,
            repository_id: receipt.repository_id,
            pull_request_number: receipt.pull_request.number,
            pull_request_node_id: receipt.pull_request.node_id,
            pull_request_head: receipt.pull_request.source_head,
            published_head: receipt.push.pushed_head,
            receipt_digest,
        });
    }
    if seen_work_node_ids != expected {
        return Err(
            "publication receipts do not cover each validated work node exactly once".into(),
        );
    }
    facts.sort_by(|left, right| left.work_node_id.cmp(&right.work_node_id));
    let coverage = expected.into_iter().collect::<Vec<_>>();
    Ok(ImplementationPublicationSetSubject {
        ticket_run_id: validated.ticket_run_id.clone(),
        accepted_plan_digest: accepted_plan_digest.clone(),
        publications: facts,
        coverage,
        publication_revision,
    })
}

/// Validate the complete planned work-node set against prepared nodes and durable Applied receipts.
/// A partial or duplicate set never produces the capability required to start Reviewer.
pub fn validate_implementation_publication_receipt(
    work_plan: &WorkPlan,
    prepared_worktrees: &PreparedWorktreesEffectReceipt,
    project_id: &ProjectId,
    repositories: &BTreeMap<RepositoryId, RepositoryConfig>,
    publications: &[crate::store::SucceededEffectReceipt],
) -> Result<ValidatedImplementationPublication, String> {
    let planned_nodes = work_plan
        .nodes
        .iter()
        .map(|node| {
            (
                node.id.clone(),
                (node.repository.clone(), node.investigation),
            )
        })
        .collect::<BTreeMap<_, _>>();
    if planned_nodes.len() != work_plan.nodes.len() {
        return Err("work plan contains duplicate work node identities".into());
    }
    let implementation_nodes = planned_nodes
        .iter()
        .filter(|(_, (_, investigation))| !investigation)
        .map(|(id, (repository, _))| (id.clone(), repository.clone()))
        .collect::<BTreeMap<_, _>>();
    let expected_work_node_ids = implementation_nodes.keys().cloned().collect::<Vec<_>>();
    if expected_work_node_ids.is_empty() || publications.len() != expected_work_node_ids.len() {
        return Err("publication receipts do not cover every planned work node".into());
    }
    let mut expected_ids = expected_work_node_ids.to_vec();
    expected_ids.sort();
    expected_ids.dedup();
    if expected_ids.len() != expected_work_node_ids.len() {
        return Err("planned work node identities must be unique".into());
    }
    let mut prepared = prepared_worktrees.work_nodes.clone();
    prepared.sort_by(|left, right| left.work_node_id.cmp(&right.work_node_id));
    let prepared_ids = prepared
        .iter()
        .map(|node| node.work_node_id.clone())
        .collect::<BTreeSet<_>>();
    if prepared_ids.len() != prepared.len()
        || prepared.iter().any(|node| {
            planned_nodes
                .get(&node.work_node_id)
                .is_none_or(|(repository, _)| repository != &node.repository_id)
        })
        || expected_ids
            .iter()
            .any(|node_id| !prepared_ids.contains(node_id))
    {
        return Err(
            "prepared worktrees do not cover the complete planned implementation set".into(),
        );
    }
    let mut requests = BTreeMap::new();
    for publication in publications {
        let request = effect_request_from_persisted(publication);
        let payload: PublishImplementationEffectPayload = decode_effect_payload(&request)?;
        if requests
            .insert(payload.work_node_id.clone(), (request, publication))
            .is_some()
        {
            return Err("multiple publication receipts target the same work node".into());
        }
    }
    if requests.len() != expected_ids.len()
        || requests.keys().cloned().ne(expected_ids.iter().cloned())
    {
        return Err("publication receipts do not match the complete planned work-node set".into());
    }
    if prepared_worktrees.schema_version != 1
        || prepared_worktrees.ticket_run_id.as_str().is_empty()
    {
        return Err(
            "prepared worktree receipt is unsupported or has no ticket-run identity".into(),
        );
    }
    let mut run_identity: Option<(TicketRunId, Digest)> = None;
    let mut source_revision = 0;
    for prepared_node in prepared
        .iter()
        .filter(|node| implementation_nodes.contains_key(&node.work_node_id))
    {
        let publication = requests
            .get(&prepared_node.work_node_id)
            .expect("receipt set was checked against planned node set");
        let (request, stored) = publication;
        let payload: PublishImplementationEffectPayload = decode_effect_payload(request)?;
        if payload.ticket_run_id != prepared_worktrees.ticket_run_id {
            return Err("publication receipt belongs to a different ticket run".into());
        }
        let identity = (
            payload.ticket_run_id.clone(),
            payload.configuration_digest.clone(),
        );
        if run_identity
            .as_ref()
            .is_some_and(|expected| expected != &identity)
        {
            return Err(
                "publication effects do not share one run revision and configuration".into(),
            );
        }
        run_identity = Some(identity);
        source_revision = source_revision.max(payload.source_revision);
        let repository_config = repositories
            .get(&prepared_node.repository_id)
            .ok_or_else(|| "repository config is missing for a planned work node".to_owned())?;
        validate_one_implementation_publication_receipt(
            request,
            prepared_node,
            project_id,
            repository_config,
            stored.receipt_json(),
        )?;
    }
    let (ticket_run_id, _) =
        run_identity.ok_or_else(|| "publication receipt set is empty".to_owned())?;
    let receipt_bindings = expected_ids
        .iter()
        .map(|work_node_id| {
            let publication = requests
                .get(work_node_id)
                .expect("receipt set was checked against planned node set");
            (
                work_node_id.clone(),
                sha256_hex(publication.1.receipt_json().as_bytes()),
            )
        })
        .collect::<Vec<_>>();
    let publication_set_digest = digest_json(&(&expected_ids, &receipt_bindings))?;
    Ok(ValidatedImplementationPublication {
        project_id: project_id.clone(),
        ticket_run_id,
        source_revision,
        work_node_ids: expected_ids,
        receipt_bindings,
        publication_set_digest,
    })
}

/// Validate one stage receipt before it can advance the work graph.
pub fn validate_work_node_publication_receipt(
    work_plan: &WorkPlan,
    prepared_worktree: &PreparedWorktreeReceiptNode,
    project_id: &ProjectId,
    repositories: &BTreeMap<RepositoryId, RepositoryConfig>,
    publication: &crate::store::SucceededEffectReceipt,
    expected_revision: u64,
) -> Result<ValidatedWorkNodePublication, String> {
    let request = effect_request_from_persisted(publication);
    let payload: PublishImplementationEffectPayload = decode_effect_payload(&request)?;
    let node = work_plan
        .nodes
        .iter()
        .find(|node| node.id == payload.work_node_id)
        .ok_or("publication receipt names a node outside the accepted plan")?;
    if node.investigation
        || node.repository != payload.repository_id
        || request.intent.expected_revision != Some(expected_revision)
        || payload.source_revision != expected_revision
        || prepared_worktree.work_node_id != payload.work_node_id
        || prepared_worktree.repository_id != payload.repository_id
    {
        return Err("publication receipt does not match the current planned stage".into());
    }
    let repository = repositories
        .get(&node.repository)
        .ok_or("repository config is missing for a planned work node")?;
    let receipt = validate_one_implementation_publication_receipt(
        &request,
        prepared_worktree,
        project_id,
        repository,
        publication.receipt_json(),
    )?;
    Ok(ValidatedWorkNodePublication {
        project_id: project_id.clone(),
        ticket_run_id: payload.ticket_run_id,
        source_revision: expected_revision,
        configuration_digest: payload.configuration_digest,
        work_node_id: payload.work_node_id,
        head: receipt.commit.head().to_owned(),
        receipt_digest: sha256_hex(publication.receipt_json().as_bytes()),
    })
}

fn effect_request_from_persisted(stored: &crate::store::SucceededEffectReceipt) -> EffectRequest {
    EffectRequest {
        intent: stored.intent().clone(),
        attempt_count: stored.attempt_count(),
        created_at_unix: stored.created_at_unix(),
    }
}

/// Validate one persisted Applied receipt against its request and prepared worktree.
fn validate_one_implementation_publication_receipt(
    request: &EffectRequest,
    prepared_worktree: &PreparedWorktreeReceiptNode,
    project_id: &ProjectId,
    repository_config: &RepositoryConfig,
    receipt_json: &str,
) -> Result<ImplementationPublicationReceipt, String> {
    let payload: PublishImplementationEffectPayload = decode_effect_payload(request)?;
    validate_effect_kind(request, EffectKind::PublishImplementation)?;
    validate_source_revision(request, payload.source_revision)?;
    if request.intent.project_id != *project_id
        || request.intent.subject_type != "ticket_run"
        || request.intent.subject_id != payload.ticket_run_id.as_str()
        || payload.repository_id.as_str().is_empty()
    {
        return Err(
            "implementation receipt effect subject does not match its project and run".into(),
        );
    }
    let receipt: ImplementationPublicationReceipt = serde_json::from_str(receipt_json)
        .map_err(|error| format!("invalid implementation receipt JSON: {error}"))?;
    if receipt.schema_version != 1
        || receipt.effect_operation_id != request.intent.operation_id
        || receipt.source_revision != payload.source_revision
        || receipt.configuration_digest != payload.configuration_digest
        || receipt.ticket_run_id != payload.ticket_run_id
        || receipt.repository_id != payload.repository_id
        || receipt.work_node_id != payload.work_node_id
        || prepared_worktree.repository_id != payload.repository_id
        || prepared_worktree.work_node_id != payload.work_node_id
        || prepared_worktree.commit_mode != payload.commit_mode
        || prepared_worktree.base_sha != payload.expected_base_sha
        || repository_config.base_branch != payload.base_branch
    {
        return Err(
            "implementation receipt does not match its effect and worktree identities".into(),
        );
    }
    let head = receipt.commit.head();
    match (&receipt.commit, &payload.commit) {
        (
            VerifiedCommit::Native { receipt: commit },
            WorkerDeliveryCommit::Native {
                previous_accepted_head,
                worker_reported_head,
                ..
            },
        ) if payload.commit_mode == CommitMode::Native
            && commit.base_sha == *previous_accepted_head
            && commit.head == *worker_reported_head
            && commit.commits.last().is_some_and(|last| last == head) => {}
        (
            VerifiedCommit::Host { receipt: commit },
            WorkerDeliveryCommit::HostReceipt {
                operation_id,
                expected_head,
                worker_reported_head,
                receipt: commit_receipt,
            },
        ) if payload.commit_mode == CommitMode::Host
            && commit.operation_id == *operation_id
            && commit_receipt.commit.operation_id == *operation_id
            && commit_receipt.commit.repository_id == payload.repository_id
            && commit.repository_id == payload.repository_id
            && commit.expected_head == *expected_head
            && commit.observed_head == *worker_reported_head
            && commit.observed_head == *head
            && commit_receipt.commit.manifest_digest == commit_receipt.manifest_artifact.digest
            && commit.signature_verified
            && commit.hooks_completed
            && commit.index_synchronized
            && !commit.index_sync_conflict => {}
        _ => {
            return Err("implementation receipt commit does not match the requested commit".into());
        }
    }
    if receipt.hook_gate.repository_id != payload.repository_id
        || receipt.hook_gate.head != head
        || receipt.hook_gate.configuration_digest != payload.configuration_digest
        || receipt.hook_gate.hook_receipts.len() != repository_config.rex_projects_hooks.len()
        || repository_config.rex_projects_hooks.iter().any(|expected| {
            receipt
                .hook_gate
                .hook_receipts
                .iter()
                .filter(|observed| observed.hook_id == expected.id)
                .count()
                != 1
        })
        || receipt.hook_gate.hook_receipts.iter().any(|hook| {
            !hook.succeeded
                || hook.timed_out
                || !hook.cleanup_confirmed
                || hook.source_before != hook.source_after
                || hook.head != head
                || hook.repository_id != payload.repository_id
                || hook.ticket_run_id != payload.ticket_run_id
                || hook.configuration_digest != payload.configuration_digest
        })
    {
        return Err("implementation receipt hook gate is incomplete or mismatched".into());
    }
    if receipt.push.repository_id != payload.repository_id
        || receipt.push.branch != prepared_worktree.branch
        || receipt.push.pushed_head != head
        || receipt.push.observed_remote_head != head
        || receipt.push.expected_remote_head != payload.expected_remote_head
        || receipt.push.force_with_lease
    {
        return Err("implementation receipt does not prove the exact expected remote head".into());
    }
    let expected_pr_operation = derived_operation_id(
        &request.intent.operation_id,
        &payload.repository_id,
        payload.work_node_id.as_str(),
        "pull-request",
    )?;
    let expected_body = format!(
        "{}\n\n<!-- rex-projects-operation:{} -->",
        payload.pull_request.body.trim_end(),
        expected_pr_operation.as_str()
    );
    if receipt.pull_request.repository_id != payload.repository_id
        || receipt.pull_request.operation_id != expected_pr_operation
        || receipt.pull_request.source_branch != prepared_worktree.branch
        || receipt.pull_request.source_head != head
        || receipt.pull_request.base_branch != payload.base_branch
        || receipt.pull_request.title != payload.pull_request.title
        || receipt.pull_request.body_digest != sha256_hex(expected_body.as_bytes())
        || receipt.pull_request.state != "open"
        || receipt.pull_request.url.is_empty()
        || receipt.pull_request.node_id.is_empty()
    {
        return Err(
            "implementation receipt pull request does not match the delivery intent".into(),
        );
    }
    Ok(receipt)
}

fn digest_json<T: Serialize>(value: &T) -> Result<String, String> {
    let bytes = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    Ok(sha256_hex(&bytes))
}

fn marked_body_for_monitor(intent: &PullRequestPublicationIntent) -> String {
    format!(
        "{}\n\n<!-- rex-projects-operation:{} -->",
        intent.body.trim_end(),
        intent.operation_id.as_str()
    )
}

pub struct PrepareWorktreesEffectHandler {
    effects: Arc<RepositoryDeliveryEffects>,
}

impl EffectHandler for PrepareWorktreesEffectHandler {
    fn kind(&self) -> EffectKind {
        EffectKind::PrepareWorktrees
    }

    fn handle(
        &self,
        _mode: EffectMode,
        request: &EffectRequest,
        context: &mut EffectContext<'_>,
    ) -> Result<EffectObservation, String> {
        let payload: PrepareWorktreesEffectPayload = match decode_effect_payload(request) {
            Ok(payload) => payload,
            Err(error) => return Ok(rejected_delivery_effect(error)),
        };
        if let Err(error) = self.effects.validate_prepare_payload(request, &payload) {
            return Ok(rejected_delivery_effect(error));
        }
        for node in &payload.work_nodes {
            if let Err(error) = self.effects.ensure_initial_publication_baseline(
                context.store,
                context.owner_generation,
                request,
                &payload,
                node,
                context.now_unix,
            ) {
                return Ok(rejected_delivery_effect(error));
            }
        }
        let receipt = self.effects.prepare_worktrees(request)?;
        Ok(EffectObservation::Applied {
            receipt: crate::store::canonical_json(&receipt)?,
        })
    }
}

pub struct PublishImplementationEffectHandler {
    effects: Arc<RepositoryDeliveryEffects>,
}

pub struct CommitWorkerManifestEffectHandler {
    effects: Arc<RepositoryDeliveryEffects>,
    artifacts: crate::artifacts::ArtifactStore,
}

impl EffectHandler for CommitWorkerManifestEffectHandler {
    fn kind(&self) -> EffectKind {
        EffectKind::CommitWorkerManifest
    }

    fn handle(
        &self,
        mode: EffectMode,
        request: &EffectRequest,
        context: &mut EffectContext<'_>,
    ) -> Result<EffectObservation, String> {
        self.effects.commit_worker_manifest(
            mode,
            request,
            context.store,
            context.owner_generation,
            &self.artifacts,
        )
    }
}

impl EffectHandler for PublishImplementationEffectHandler {
    fn kind(&self) -> EffectKind {
        EffectKind::PublishImplementation
    }

    fn handle(
        &self,
        mode: EffectMode,
        request: &EffectRequest,
        context: &mut EffectContext<'_>,
    ) -> Result<EffectObservation, String> {
        let payload: PublishImplementationEffectPayload = match decode_effect_payload(request) {
            Ok(payload) => payload,
            Err(error) => return Ok(rejected_delivery_effect(error)),
        };
        if let Err(error) = self.effects.validate_publish_payload(request, &payload) {
            return Ok(rejected_delivery_effect(error));
        }
        self.effects.publish_implementation(
            mode,
            request,
            context.store,
            context.owner_generation,
            context.now_unix,
        )
    }
}

fn rejected_delivery_effect(error: String) -> EffectObservation {
    EffectObservation::Rejected {
        receipt: serde_json::json!({
            "schema_version": 1,
            "outcome": "rejected",
            "reason": error,
        })
        .to_string(),
    }
}

fn decode_effect_payload<T>(request: &EffectRequest) -> Result<T, String>
where
    T: serde::de::DeserializeOwned,
{
    let parsed: serde_json::Value = serde_json::from_str(&request.intent.request_json)
        .map_err(|error| format!("invalid effect JSON: {error}"))?;
    let canonical = serde_json::to_string(&parsed).map_err(|error| error.to_string())?;
    if canonical != request.intent.request_json {
        return Err("effect request JSON is not canonical".into());
    }
    if sha256_hex(request.intent.request_json.as_bytes()) != request.intent.request_digest {
        return Err("effect request digest does not match its payload".into());
    }
    serde_json::from_value(parsed).map_err(|error| format!("invalid typed effect payload: {error}"))
}

fn validate_effect_kind(request: &EffectRequest, expected: EffectKind) -> Result<(), String> {
    if request.intent.kind != crate::engine::reducer::effect_name(&expected) {
        return Err("effect kind does not match its typed delivery handler".into());
    }
    Ok(())
}

fn validate_source_revision(request: &EffectRequest, source_revision: u64) -> Result<(), String> {
    if request.intent.expected_revision != Some(source_revision) {
        return Err(
            "effect payload revision does not match the persisted expected revision".into(),
        );
    }
    Ok(())
}

fn absent_effect(
    kind: EffectKind,
    request: &EffectRequest,
    authority: &str,
    evidence: String,
) -> Result<EffectObservation, String> {
    Ok(EffectObservation::AuthoritativelyAbsent {
        proof: AbsentProof::from_authoritative_lookup(kind, request, authority, evidence)?,
    })
}

fn derived_operation_id(
    parent: &str,
    repository_id: &RepositoryId,
    node_id: &str,
    stage: &str,
) -> Result<OperationId, String> {
    let bytes = [parent, repository_id.as_str(), node_id, stage].join("\0");
    OperationId::parse(format!("rp-{}", sha256_hex(bytes.as_bytes())))
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn hex_lower(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(TABLE[(byte >> 4) as usize]));
        output.push(char::from(TABLE[(byte & 0x0f) as usize]));
    }
    output
}

fn validate_git_sha(value: &str) -> Result<(), DeliveryError> {
    if !matches!(value.len(), 40 | 64) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(DeliveryError::Invalid(
            "Git object ID is not canonical".into(),
        ));
    }
    Ok(())
}

fn validate_branch_name(value: &str) -> Result<(), DeliveryError> {
    if value.is_empty()
        || value.len() > 240
        || value.starts_with('-')
        || value.contains("..")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.'))
    {
        return Err(DeliveryError::Invalid(
            "managed branch name is invalid".into(),
        ));
    }
    Ok(())
}

fn validate_hook_gate(
    work: &PreparedRepositoryWork,
    repository_config: &RepositoryConfig,
    expected_configuration_digest: &Digest,
    expected_head: &str,
    receipt: &HookGateReceipt,
) -> Result<(), DeliveryError> {
    let mut expected_ids = repository_config
        .rex_projects_hooks
        .iter()
        .map(|hook| hook.id.as_str())
        .collect::<Vec<_>>();
    expected_ids.sort_unstable();
    let mut actual_ids = receipt
        .hook_receipts
        .iter()
        .map(|hook| hook.hook_id.as_str())
        .collect::<Vec<_>>();
    actual_ids.sort_unstable();
    if receipt.repository_id != work.identity.repository_id
        || receipt.head != expected_head
        || &receipt.configuration_digest != expected_configuration_digest
        || expected_ids != actual_ids
        || receipt.hook_receipts.iter().any(|hook| {
            hook.repository_id != work.identity.repository_id
                || hook.project_id != work.identity.project_id
                || hook.ticket_run_id != work.identity.ticket_run_id
                || hook.head != expected_head
                || &hook.configuration_digest != expected_configuration_digest
                || !hook.succeeded
        })
    {
        return Err(DeliveryError::Conflict(
            "repository hook evidence is missing, failed, or bound to a different subject".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publication_subject_digest_keeps_the_existing_three_field_contract() {
        let subject = ImplementationPublicationSetSubject {
            ticket_run_id: TicketRunId::parse("run-1").unwrap(),
            accepted_plan_digest: Digest::parse("a".repeat(64)).unwrap(),
            publications: vec![ImplementationPublicationSubjectFact {
                work_node_id: WorkNodeId::parse("node-1").unwrap(),
                repository_id: RepositoryId::parse("repo-1").unwrap(),
                pull_request_number: 9,
                pull_request_node_id: "PR_node_9".into(),
                pull_request_head: "b".repeat(40),
                published_head: "c".repeat(40),
                receipt_digest: "d".repeat(64),
            }],
            coverage: vec![WorkNodeId::parse("node-1").unwrap()],
            publication_revision: 5,
        };
        let legacy_value = serde_json::json!({
            "ticket_run_id": "run-1",
            "accepted_plan_digest": "a".repeat(64),
            "publications": [{
                "work_node_id": "node-1",
                "repository_id": "repo-1",
                "pull_request_number": 9,
                "pull_request_node_id": "PR_node_9",
                "pull_request_head": "b".repeat(40),
                "published_head": "c".repeat(40),
                "receipt_digest": "d".repeat(64),
            }]
        });
        let legacy_digest =
            Digest::parse(sha256_hex(&serde_json::to_vec(&legacy_value).unwrap())).unwrap();
        assert_eq!(subject.digest().unwrap(), legacy_digest);

        let mut metadata_changed = subject;
        metadata_changed.publication_revision += 1;
        metadata_changed
            .coverage
            .push(WorkNodeId::parse("extra-node").unwrap());
        assert_eq!(metadata_changed.digest().unwrap(), legacy_digest);
    }
    use crate::config::MergeConfig;
    use crate::process::ProcessRequest;
    use std::ffi::OsString;
    use std::os::unix::fs::PermissionsExt;
    use std::time::Duration;

    fn git_path() -> PathBuf {
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .map(|directory| directory.join("git"))
            .find(|path| path.is_file())
            .expect("git is installed for local repository fixtures")
    }

    fn git(executable: &Path, cwd: &Path, args: &[&str]) {
        let output = process::run(ProcessRequest {
            executable: executable.to_owned(),
            args: args.iter().map(OsString::from).collect(),
            stdin: Vec::new(),
            cwd: Some(cwd.to_owned()),
            clear_environment: true,
            environment: BTreeMap::new(),
            timeout: Duration::from_secs(20),
            shutdown_grace: Duration::from_secs(2),
            stdout_limit: 1024 * 1024,
            stderr_tail_limit: 8192,
        })
        .unwrap();
        assert!(
            output.status.is_some_and(|status| status.success()),
            "fixture git command failed: {args:?}"
        );
    }

    #[test]
    fn bounded_local_head_observation_ignores_inherited_git_repository_selectors() {
        let temp = tempfile::tempdir().unwrap();
        let executable = git_path();
        let target = temp.path().join("target");
        let unrelated = temp.path().join("unrelated");
        for (path, file, content) in [
            (&target, "target.txt", "target"),
            (&unrelated, "unrelated.txt", "unrelated"),
        ] {
            std::fs::create_dir(path).unwrap();
            git(&executable, path, &["init", "--initial-branch=main"]);
            git(&executable, path, &["config", "user.name", "Fixture"]);
            git(
                &executable,
                path,
                &["config", "user.email", "fixture@example.test"],
            );
            std::fs::write(path.join(file), content).unwrap();
            git(&executable, path, &["add", file]);
            git(
                &executable,
                path,
                &["-c", "commit.gpgsign=false", "commit", "-m", "fixture"],
            );
        }
        let head = |path: &Path| {
            let output = process::run(ProcessRequest {
                executable: executable.clone(),
                args: ["rev-parse", "--verify", "HEAD"]
                    .into_iter()
                    .map(OsString::from)
                    .collect(),
                stdin: Vec::new(),
                cwd: Some(path.to_owned()),
                clear_environment: true,
                environment: BTreeMap::new(),
                timeout: Duration::from_secs(3),
                shutdown_grace: Duration::from_secs(2),
                stdout_limit: 4096,
                stderr_tail_limit: 4096,
            })
            .unwrap();
            assert!(output.status.is_some_and(|status| status.success()));
            String::from_utf8(output.stdout).unwrap().trim().to_owned()
        };
        let expected = head(&target);
        assert_ne!(expected, head(&unrelated));

        let delivery = RepositoryDelivery::new(
            &temp.path().join("state"),
            GitOptions {
                executable,
                environment: BTreeMap::from([(
                    OsString::from("GIT_DIR"),
                    unrelated.join(".git").into_os_string(),
                )]),
                timeout: Duration::from_secs(3),
            },
            BTreeMap::new(),
            HostJobEnvironmentBinding {
                snapshot_id: Digest::parse("e".repeat(64)).unwrap(),
                policy_digest: Digest::parse("f".repeat(64)).unwrap(),
            },
        )
        .unwrap();
        assert_eq!(delivery.observe_local_head_at(&target).unwrap(), expected);
    }

    #[test]
    fn bounded_commit_subject_observation_uses_the_exact_current_head() {
        let temp = tempfile::tempdir().unwrap();
        let executable = git_path();
        let repository = temp.path().join("repository");
        std::fs::create_dir(&repository).unwrap();
        git(&executable, &repository, &["init", "--initial-branch=main"]);
        git(
            &executable,
            &repository,
            &["config", "user.name", "Fixture"],
        );
        git(
            &executable,
            &repository,
            &["config", "user.email", "fixture@example.test"],
        );
        std::fs::write(repository.join("README.md"), "fixture\n").unwrap();
        git(&executable, &repository, &["add", "README.md"]);
        let subject = "docs: handle long accepted work descriptions";
        git(
            &executable,
            &repository,
            &["-c", "commit.gpgsign=false", "commit", "-m", subject],
        );
        let head = process::run(ProcessRequest {
            executable: executable.clone(),
            args: ["rev-parse", "--verify", "HEAD"]
                .into_iter()
                .map(OsString::from)
                .collect(),
            stdin: Vec::new(),
            cwd: Some(repository.clone()),
            clear_environment: true,
            environment: BTreeMap::new(),
            timeout: Duration::from_secs(3),
            shutdown_grace: Duration::from_secs(2),
            stdout_limit: 4096,
            stderr_tail_limit: 4096,
        })
        .unwrap();
        assert!(head.status.is_some_and(|status| status.success()));
        let head = String::from_utf8(head.stdout).unwrap().trim().to_owned();

        let delivery = RepositoryDelivery::new(
            &temp.path().join("state"),
            GitOptions {
                executable,
                environment: BTreeMap::new(),
                timeout: Duration::from_secs(3),
            },
            BTreeMap::new(),
            HostJobEnvironmentBinding {
                snapshot_id: Digest::parse("e".repeat(64)).unwrap(),
                policy_digest: Digest::parse("f".repeat(64)).unwrap(),
            },
        )
        .unwrap();
        assert_eq!(
            delivery
                .observe_commit_subject_at(&repository, &head)
                .unwrap(),
            subject
        );
        assert!(
            delivery
                .observe_commit_subject_at(&repository, &"0".repeat(40))
                .is_err()
        );
    }

    fn seed_local_remote(root: &Path, executable: &Path) -> (PathBuf, String) {
        let bare = root.join("origin.git");
        let seed = root.join("seed");
        std::fs::create_dir_all(&seed).unwrap();
        git(
            executable,
            root,
            &["init", "--bare", bare.to_str().unwrap()],
        );
        git(
            executable,
            root,
            &["init", "-b", "main", seed.to_str().unwrap()],
        );
        std::fs::write(seed.join("README.md"), "base\n").unwrap();
        git(executable, &seed, &["add", "README.md"]);
        git(
            executable,
            &seed,
            &[
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-m",
                "base",
            ],
        );
        git(
            executable,
            &seed,
            &["remote", "add", "origin", bare.to_str().unwrap()],
        );
        git(executable, &seed, &["push", "origin", "main"]);
        let head = std::process::Command::new(executable)
            .current_dir(&seed)
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap();
        (
            bare,
            String::from_utf8(head.stdout).unwrap().trim().to_owned(),
        )
    }

    fn fixture_repository_config(clone_url: String) -> RepositoryConfig {
        RepositoryConfig {
            clone_url,
            base_branch: "main".into(),
            forge: "github".into(),
            worktree_root: None,
            instruction_files: Vec::new(),
            role_instruction_files: BTreeMap::new(),
            rex_projects_hooks: Vec::new(),
            merge: MergeConfig::default(),
            operations: None,
        }
    }

    #[test]
    fn work_node_branch_key_is_stable_but_distinguishes_nodes_and_ticket_runs() {
        let first = WorkNodeIdentity {
            project_id: ProjectId::parse("project").unwrap(),
            repository_id: RepositoryId::parse("repo").unwrap(),
            ticket_namespace: TicketNamespace::parse("tickets/acme").unwrap(),
            ticket_id: TicketId::parse("T-42").unwrap(),
            ticket_run_id: TicketRunId::parse("run-1").unwrap(),
            work_node_id: "service-change".into(),
        };
        assert_eq!(first.ticket_key().unwrap(), first.ticket_key().unwrap());
        let mut second = first.clone();
        second.work_node_id = "docs-change".into();
        assert_ne!(first.ticket_key().unwrap(), second.ticket_key().unwrap());
    }

    #[test]
    fn pushes_only_owned_managed_branch_and_reconciles_exact_remote_head() {
        let temp = tempfile::tempdir().unwrap();
        let executable = git_path();
        let bare = temp.path().join("origin.git");
        let seed = temp.path().join("seed");
        std::fs::create_dir_all(&seed).unwrap();
        git(
            &executable,
            temp.path(),
            &["init", "--bare", bare.to_str().unwrap()],
        );
        git(
            &executable,
            temp.path(),
            &["init", "-b", "main", seed.to_str().unwrap()],
        );
        std::fs::write(seed.join("README.md"), "base\n").unwrap();
        git(&executable, &seed, &["add", "README.md"]);
        git(
            &executable,
            &seed,
            &[
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-m",
                "base",
            ],
        );
        git(
            &executable,
            &seed,
            &["remote", "add", "origin", bare.to_str().unwrap()],
        );
        git(&executable, &seed, &["push", "origin", "main"]);
        let base = String::from_utf8(
            std::process::Command::new(&executable)
                .current_dir(&seed)
                .args(["rev-parse", "HEAD"])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_owned();
        let repo_id = RepositoryId::parse("demo").unwrap();
        let project_id = ProjectId::parse("project").unwrap();
        let identity = WorkNodeIdentity {
            project_id,
            repository_id: repo_id,
            ticket_namespace: TicketNamespace::parse("fixture").unwrap(),
            ticket_id: TicketId::parse("T-10").unwrap(),
            ticket_run_id: TicketRunId::parse("run-1").unwrap(),
            work_node_id: "api".into(),
        };
        let git_options = GitOptions {
            executable: executable.clone(),
            environment: BTreeMap::new(),
            timeout: Duration::from_secs(20),
        };
        let delivery = RepositoryDelivery::new(
            &temp.path().join("state"),
            git_options,
            BTreeMap::new(),
            HostJobEnvironmentBinding {
                snapshot_id: Digest::parse("e".repeat(64)).unwrap(),
                policy_digest: Digest::parse("f".repeat(64)).unwrap(),
            },
        )
        .unwrap();
        let config = RepositoryConfig {
            clone_url: bare.to_string_lossy().into_owned(),
            base_branch: "main".into(),
            forge: "github".into(),
            worktree_root: None,
            instruction_files: Vec::new(),
            role_instruction_files: BTreeMap::new(),
            rex_projects_hooks: Vec::new(),
            merge: MergeConfig::default(),
            operations: None,
        };
        let work = delivery
            .prepare_worktree(identity, &config, &base, CommitMode::Native)
            .unwrap();
        std::fs::write(work.worktree.path.join("change.txt"), "feature\n").unwrap();
        git(&executable, &work.worktree.path, &["add", "change.txt"]);
        git(
            &executable,
            &work.worktree.path,
            &[
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-m",
                "feature",
            ],
        );
        let head = std::process::Command::new(&executable)
            .current_dir(&work.worktree.path)
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap();
        let head = String::from_utf8(head.stdout).unwrap().trim().to_owned();
        let digest = Digest::parse("a".repeat(64)).unwrap();
        let gate = HookGateReceipt {
            repository_id: work.identity.repository_id.clone(),
            head: head.clone(),
            configuration_digest: digest.clone(),
            hook_receipts: Vec::new(),
        };
        let first = delivery
            .push_owned_branch(&work, &config, &digest, &head, None, &gate)
            .unwrap();
        let second = delivery
            .push_owned_branch(&work, &config, &digest, &head, None, &gate)
            .unwrap();
        assert_eq!(first, second);
        assert_eq!(first.pushed_head, head);
        assert!(!first.force_with_lease);
    }

    #[test]
    fn prepare_worktrees_effect_is_canonical_scoped_and_replayable() {
        let temp = tempfile::tempdir().unwrap();
        let executable = git_path();
        let (bare, base_sha) = seed_local_remote(temp.path(), &executable);
        let repository_id = RepositoryId::parse("demo").unwrap();
        let project_id = ProjectId::parse("project").unwrap();
        let gh_executable = temp.path().join("gh-fixture");
        std::fs::write(&gh_executable, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&gh_executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let configuration_digest = Digest::parse("c".repeat(64)).unwrap();
        let host_jobs = Arc::new(Mutex::new(HostJobPool::new(2, 2).unwrap()));
        let effects = RepositoryDeliveryEffects::new(
            RepositoryDeliveryEffectConfig {
                state_root: temp.path().join("state"),
                git: GitOptions {
                    executable,
                    environment: BTreeMap::new(),
                    timeout: Duration::from_secs(20),
                },
                inherited_environment: BTreeMap::new(),
                environment_binding: HostJobEnvironmentBinding {
                    snapshot_id: Digest::parse("e".repeat(64)).unwrap(),
                    policy_digest: Digest::parse("f".repeat(64)).unwrap(),
                },
                gh_executable,
                gh_environment: BTreeMap::new(),
                timeout: Duration::from_secs(5),
                configuration_digest: configuration_digest.clone(),
                repositories: BTreeMap::from([(
                    repository_id.clone(),
                    fixture_repository_config(bare.to_string_lossy().into_owned()),
                )]),
                project_repositories: BTreeMap::from([(
                    project_id.clone(),
                    BTreeSet::from([repository_id.clone()]),
                )]),
                max_hook_attempts: 3,
            },
            host_jobs,
        )
        .unwrap();
        let payload = PrepareWorktreesEffectPayload {
            schema_version: 1,
            source_revision: 1,
            configuration_digest,
            ticket_namespace: TicketNamespace::parse("fixture").unwrap(),
            ticket_id: TicketId::parse("T-3").unwrap(),
            ticket_run_id: TicketRunId::parse("run-1").unwrap(),
            work_nodes: vec![PreparedWorktreeNodeRequest {
                work_node_id: WorkNodeId::parse("api").unwrap(),
                repository_id,
                expected_base_sha: base_sha.clone(),
                commit_mode: CommitMode::Native,
            }],
        };
        let mut invalid_payload = payload.clone();
        invalid_payload
            .work_nodes
            .push(PreparedWorktreeNodeRequest {
                work_node_id: WorkNodeId::parse("zeta").unwrap(),
                repository_id: RepositoryId::parse("demo").unwrap(),
                expected_base_sha: base_sha.clone(),
                commit_mode: CommitMode::Auto,
            });
        let (invalid_json, invalid_digest) = canonical_delivery_payload(&invalid_payload).unwrap();
        let invalid_request = EffectRequest {
            intent: crate::store::EffectIntent {
                project_id: ProjectId::parse("project").unwrap(),
                subject_type: "ticket_run".into(),
                subject_id: "run-1".into(),
                operation_id: "prepare-invalid".into(),
                logical_key: "run-1:revision-1:prepare-invalid".into(),
                kind: "prepare_worktrees".into(),
                request_json: invalid_json,
                request_digest: invalid_digest,
                expected_revision: Some(1),
            },
            attempt_count: 0,
            created_at_unix: 1,
        };
        let handler = effects.prepare_worktrees_handler();
        let mut store =
            crate::store::ConfigStore::open_test(&temp.path().join("controller")).unwrap();
        let applied = store
            .apply_snapshot(
                "factory",
                &crate::config::AppliedConfig {
                    config: serde_json::from_value(serde_json::json!({
                        "schema_version": 1,
                        "adapters": {"tickets": {"kind":"command","command":["test"]}},
                        "projects": {}
                    }))
                    .unwrap(),
                    profiles: BTreeMap::new(),
                    source_root: temp.path().display().to_string(),
                    source_files: Vec::new(),
                    digest: Digest::parse("a".repeat(64)).unwrap(),
                },
                crate::store::ExpectedRevision::Bootstrap,
            )
            .unwrap();
        store
            .insert_project(&crate::store::ProjectRecord {
                id: project_id.clone(),
                config_source: "factory".into(),
                config_revision: applied.revision,
                config_digest: applied.digest.clone(),
                mode: "goal".into(),
                goal_revision: 1,
                desired_lifecycle: "running".into(),
                state_revision: crate::domain::ids::Revision(0),
            })
            .unwrap();
        let owner_generation = store
            .start_owner(&crate::store::OwnerMetadata {
                owner_nonce: "delivery-test-owner".into(),
                state_root: temp.path().join("controller").display().to_string(),
                config_source: "factory".into(),
                process_start_identity: "delivery-test-process".into(),
                executable_path: "/tmp/rex-projects-test".into(),
                executable_digest: "b".repeat(64),
                rex_endpoint: None,
                rex_server_identity: None,
                rex_session_id: None,
                rex_block_id: None,
            })
            .unwrap();
        store
            .create_ticket_run(
                owner_generation,
                &project_id,
                &TicketNamespace::parse("fixture").unwrap(),
                &TicketId::parse("T-3").unwrap(),
                &TicketRunId::parse("run-1").unwrap(),
                1,
                "implementing",
                "In Progress",
            )
            .unwrap();
        let work_identity = WorkNodeIdentity {
            project_id: project_id.clone(),
            repository_id: RepositoryId::parse("demo").unwrap(),
            ticket_namespace: TicketNamespace::parse("fixture").unwrap(),
            ticket_id: TicketId::parse("T-3").unwrap(),
            ticket_run_id: TicketRunId::parse("run-1").unwrap(),
            work_node_id: "api".into(),
        };
        store
            .insert_initial_publication_baseline(
                owner_generation,
                &crate::store::publication_monitor::PublicationResource {
                    project_id: project_id.clone(),
                    ticket_run_id: TicketRunId::parse("run-1").unwrap(),
                    repository_id: RepositoryId::parse("demo").unwrap(),
                    branch: work_identity.branch_name().unwrap(),
                },
                "main",
                &Digest::parse("c".repeat(64)).unwrap(),
                &RepositoryPublicationObservation {
                    remote_head: None,
                    pull_requests: crate::delivery_forge::ObservationCapability::Known(Vec::new()),
                },
                1,
            )
            .unwrap();
        let mut context = EffectContext {
            store: &mut store,
            owner_generation,
            now_unix: 1,
        };
        assert!(matches!(
            handler
                .handle(EffectMode::Submit, &invalid_request, &mut context)
                .unwrap(),
            EffectObservation::Rejected { .. }
        ));
        assert!(!temp.path().join("state/worktrees/demo").exists());

        let (request_json, request_digest) = canonical_delivery_payload(&payload).unwrap();
        let request = EffectRequest {
            intent: crate::store::EffectIntent {
                project_id: project_id.clone(),
                subject_type: "ticket_run".into(),
                subject_id: "run-1".into(),
                operation_id: "prepare-1".into(),
                logical_key: "run-1:revision-1:prepare_worktrees".into(),
                kind: "prepare_worktrees".into(),
                request_json,
                request_digest,
                expected_revision: Some(1),
            },
            attempt_count: 0,
            created_at_unix: 1,
        };
        let first = match handler
            .handle(EffectMode::Submit, &request, &mut context)
            .unwrap()
        {
            EffectObservation::Applied { receipt } => receipt,
            other => panic!("worktree preparation result: {other:?}"),
        };
        let EffectObservation::Applied { receipt: second } = handler
            .handle(EffectMode::Reconcile, &request, &mut context)
            .unwrap()
        else {
            panic!("worktree preparation should replay its durable receipt");
        };
        assert_eq!(first, second);
        assert_eq!(
            first,
            crate::store::canonical_json(
                &serde_json::from_str::<serde_json::Value>(&first).unwrap()
            )
            .unwrap()
        );
        let receipt: PreparedWorktreesEffectReceipt = serde_json::from_str(&first).unwrap();
        assert_eq!(receipt.work_nodes.len(), 1);
        assert!(
            receipt.work_nodes[0]
                .worktree_path
                .starts_with(temp.path().join("state/worktrees").canonicalize().unwrap())
        );
    }

    #[test]
    fn publish_effect_rejects_invalid_forge_configuration_before_git_mutation() {
        let temp = tempfile::tempdir().unwrap();
        let executable = git_path();
        let (bare, base_sha) = seed_local_remote(temp.path(), &executable);
        let repository_id = RepositoryId::parse("demo").unwrap();
        let project_id = ProjectId::parse("project").unwrap();
        let gh_executable = temp.path().join("gh-fixture");
        std::fs::write(&gh_executable, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&gh_executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let configuration_digest = Digest::parse("d".repeat(64)).unwrap();
        let host_jobs = Arc::new(Mutex::new(HostJobPool::new(2, 2).unwrap()));
        let effects = RepositoryDeliveryEffects::new(
            RepositoryDeliveryEffectConfig {
                state_root: temp.path().join("state"),
                git: GitOptions {
                    executable,
                    environment: BTreeMap::new(),
                    timeout: Duration::from_secs(20),
                },
                inherited_environment: BTreeMap::new(),
                environment_binding: HostJobEnvironmentBinding {
                    snapshot_id: Digest::parse("e".repeat(64)).unwrap(),
                    policy_digest: Digest::parse("f".repeat(64)).unwrap(),
                },
                gh_executable,
                gh_environment: BTreeMap::new(),
                timeout: Duration::from_secs(5),
                configuration_digest: configuration_digest.clone(),
                repositories: BTreeMap::from([(
                    repository_id.clone(),
                    fixture_repository_config(bare.to_string_lossy().into_owned()),
                )]),
                project_repositories: BTreeMap::from([(
                    project_id.clone(),
                    BTreeSet::from([repository_id.clone()]),
                )]),
                max_hook_attempts: 3,
            },
            host_jobs,
        )
        .unwrap();
        let payload = PublishImplementationEffectPayload {
            schema_version: 1,
            source_revision: 1,
            configuration_digest,
            ticket_namespace: TicketNamespace::parse("fixture").unwrap(),
            ticket_id: TicketId::parse("T-4").unwrap(),
            ticket_run_id: TicketRunId::parse("run-4").unwrap(),
            work_node_id: WorkNodeId::parse("api").unwrap(),
            repository_id,
            expected_base_sha: base_sha.clone(),
            base_branch: "main".into(),
            commit_mode: CommitMode::Native,
            commit: WorkerDeliveryCommit::Native {
                previous_accepted_head: base_sha.clone(),
                worker_reported_head: base_sha,
                required_trailer: "Co-authored-by: Codex <noreply@openai.com>".into(),
            },
            expected_remote_head: None,
            pull_request: PullRequestContent {
                title: "Ship feature".into(),
                body: "Implementation details".into(),
                update_target: None,
            },
        };
        let (request_json, request_digest) = canonical_delivery_payload(&payload).unwrap();
        let request = EffectRequest {
            intent: crate::store::EffectIntent {
                project_id: project_id.clone(),
                subject_type: "ticket_run".into(),
                subject_id: "run-4".into(),
                operation_id: "publish-4".into(),
                logical_key: "run-4:revision-1:publish".into(),
                kind: "publish_implementation".into(),
                request_json,
                request_digest,
                expected_revision: Some(1),
            },
            attempt_count: 0,
            created_at_unix: 1,
        };

        let mut store =
            crate::store::ConfigStore::open_test(&temp.path().join("controller")).unwrap();
        let mut context = EffectContext {
            store: &mut store,
            owner_generation: 1,
            now_unix: 1,
        };
        assert!(matches!(
            effects
                .publish_implementation_handler()
                .handle(EffectMode::Submit, &request, &mut context)
                .unwrap(),
            EffectObservation::Rejected { .. }
        ));
        assert!(!temp.path().join("state/worktrees/demo").exists());
        assert!(!temp.path().join("state/repos/demo").exists());
    }

    #[test]
    fn persisted_publication_receipt_must_bind_commit_hooks_push_and_pr() {
        let project_id = ProjectId::parse("project").unwrap();
        let repository_id = RepositoryId::parse("demo").unwrap();
        let ticket_run_id = TicketRunId::parse("run-5").unwrap();
        let work_node_id = WorkNodeId::parse("api").unwrap();
        let work_plan = WorkPlan {
            nodes: vec![crate::engine::orchestration::PlannedWorkNode {
                id: work_node_id.clone(),
                repository: repository_id.clone(),
                task: "implement API change".into(),
                depends_on: Vec::new(),
                required_evidence: Vec::new(),
                investigation: false,
            }],
            requested_investigation_children: 0,
        };
        let configuration_digest = Digest::parse("e".repeat(64)).unwrap();
        let base = "a".repeat(40);
        let head = "b".repeat(40);
        let branch = "rex-projects/1234567890abcdef1234567890abcdef".to_owned();
        let payload = PublishImplementationEffectPayload {
            schema_version: 1,
            source_revision: 7,
            configuration_digest: configuration_digest.clone(),
            ticket_namespace: TicketNamespace::parse("fixture").unwrap(),
            ticket_id: TicketId::parse("T-5").unwrap(),
            ticket_run_id: ticket_run_id.clone(),
            work_node_id: work_node_id.clone(),
            repository_id: repository_id.clone(),
            expected_base_sha: base.clone(),
            base_branch: "main".into(),
            commit_mode: CommitMode::Native,
            commit: WorkerDeliveryCommit::Native {
                previous_accepted_head: base.clone(),
                worker_reported_head: head.clone(),
                required_trailer: "Co-authored-by: Codex <noreply@openai.com>".into(),
            },
            expected_remote_head: None,
            pull_request: PullRequestContent {
                title: "Ship feature".into(),
                body: "Details".into(),
                update_target: None,
            },
        };
        let (request_json, request_digest) = canonical_delivery_payload(&payload).unwrap();
        let request = EffectRequest {
            intent: crate::store::EffectIntent {
                project_id: project_id.clone(),
                subject_type: "ticket_run".into(),
                subject_id: ticket_run_id.to_string(),
                operation_id: "publish-op".into(),
                logical_key: "run-5:revision-7:publish".into(),
                kind: "publish_implementation".into(),
                request_json,
                request_digest,
                expected_revision: Some(7),
            },
            attempt_count: 1,
            created_at_unix: 1,
        };
        let prepared = PreparedWorktreeReceiptNode {
            work_node_id: work_node_id.clone(),
            repository_id: repository_id.clone(),
            worktree_path: PathBuf::from("/managed/worktree"),
            branch: branch.clone(),
            base_sha: base.clone(),
            commit_mode: CommitMode::Native,
        };
        let prepared_receipt = PreparedWorktreesEffectReceipt {
            schema_version: 1,
            ticket_run_id: ticket_run_id.clone(),
            work_nodes: vec![prepared.clone()],
        };
        let pr_operation = derived_operation_id(
            &request.intent.operation_id,
            &repository_id,
            work_node_id.as_str(),
            "pull-request",
        )
        .unwrap();
        let body = format!(
            "Details\n\n<!-- rex-projects-operation:{} -->",
            pr_operation.as_str()
        );
        let receipt = ImplementationPublicationReceipt {
            schema_version: 1,
            effect_operation_id: "publish-op".into(),
            source_revision: 7,
            configuration_digest: configuration_digest.clone(),
            ticket_run_id: ticket_run_id.clone(),
            repository_id: repository_id.clone(),
            work_node_id: work_node_id.clone(),
            commit: VerifiedCommit::Native {
                receipt: NativeCommitReceipt {
                    head: head.clone(),
                    base_sha: base,
                    commits: vec![head.clone()],
                },
            },
            hook_gate: HookGateReceipt {
                repository_id: repository_id.clone(),
                head: head.clone(),
                configuration_digest,
                hook_receipts: Vec::new(),
            },
            push: PushReceipt {
                repository_id: repository_id.clone(),
                branch: branch.clone(),
                expected_remote_head: None,
                observed_remote_head: head.clone(),
                pushed_head: head.clone(),
                force_with_lease: false,
            },
            pull_request: PublishedPullRequest {
                repository_id: repository_id.clone(),
                number: 42,
                node_id: "PR_fixture".into(),
                url: "https://github.com/acme/demo/pull/42".into(),
                state: "open".into(),
                source_branch: branch,
                source_head: head,
                base_branch: "main".into(),
                title: "Ship feature".into(),
                body_digest: sha256_hex(body.as_bytes()),
                operation_id: pr_operation,
            },
        };

        let json = serde_json::to_string(&receipt).unwrap();
        let stored_receipt = crate::store::SucceededEffectReceipt::for_test(&request, json.clone());
        let repository_config = fixture_repository_config("git@github.com:acme/demo.git".into());
        let repository_configs = BTreeMap::from([(repository_id.clone(), repository_config)]);
        let validated = validate_implementation_publication_receipt(
            &work_plan,
            &prepared_receipt,
            &project_id,
            &repository_configs,
            std::slice::from_ref(&stored_receipt),
        )
        .unwrap();
        assert_eq!(validated.source_revision, 7);
        let mut unsupported_preparation = prepared_receipt.clone();
        unsupported_preparation.schema_version = 2;
        assert!(
            validate_implementation_publication_receipt(
                &work_plan,
                &unsupported_preparation,
                &project_id,
                &repository_configs,
                std::slice::from_ref(&stored_receipt),
            )
            .is_err()
        );
        let second_node_id = WorkNodeId::parse("db").unwrap();
        let mut two_node_preparation = prepared_receipt.clone();
        two_node_preparation
            .work_nodes
            .push(PreparedWorktreeReceiptNode {
                work_node_id: second_node_id.clone(),
                repository_id: RepositoryId::parse("database").unwrap(),
                worktree_path: PathBuf::from("/managed/database-worktree"),
                branch: "rex-projects/abcdef0123456789abcdef0123456789".into(),
                base_sha: "a".repeat(40),
                commit_mode: CommitMode::Native,
            });
        let two_repository_configs = BTreeMap::from([
            (
                RepositoryId::parse("demo").unwrap(),
                fixture_repository_config("git@github.com:acme/demo.git".into()),
            ),
            (
                RepositoryId::parse("database").unwrap(),
                fixture_repository_config("git@github.com:acme/database.git".into()),
            ),
        ]);
        let mut two_node_work_plan = work_plan.clone();
        two_node_work_plan
            .nodes
            .push(crate::engine::orchestration::PlannedWorkNode {
                id: second_node_id.clone(),
                repository: RepositoryId::parse("database").unwrap(),
                task: "implement database change".into(),
                depends_on: Vec::new(),
                required_evidence: Vec::new(),
                investigation: false,
            });
        assert!(
            validate_implementation_publication_receipt(
                &two_node_work_plan,
                &two_node_preparation,
                &project_id,
                &two_repository_configs,
                std::slice::from_ref(&stored_receipt),
            )
            .is_err()
        );
        let mut ticket_run = crate::engine::reducer::TicketRun {
            project_id,
            ticket_run_id,
            revision: crate::domain::ids::Revision(7),
            phase: crate::engine::reducer::Phase::Publishing,
            activity: crate::engine::reducer::Activity::Running,
            external_status: crate::domain::types::TicketStatus::InProgress,
            required_review_revision: None,
        };
        let decision = crate::engine::reducer::reduce(
            &ticket_run,
            ticket_run.revision,
            crate::engine::reducer::Input::ImplementationPublished(validated),
        )
        .unwrap();
        assert_eq!(
            decision.ticket_run.phase,
            crate::engine::reducer::Phase::Reviewing
        );
        ticket_run.phase = crate::engine::reducer::Phase::Implementing;
        assert!(
            crate::engine::reducer::reduce(
                &ticket_run,
                ticket_run.revision,
                crate::engine::reducer::Input::EvidenceSubmitted,
            )
            .unwrap()
            .effects
            .contains(&EffectKind::PublishImplementation)
        );
        let mut tampered = receipt;
        tampered.push.pushed_head = "c".repeat(40);
        let tampered_json = serde_json::to_string(&tampered).unwrap();
        let tampered_receipt =
            crate::store::SucceededEffectReceipt::for_test(&request, tampered_json);
        assert!(
            validate_implementation_publication_receipt(
                &work_plan,
                &prepared_receipt,
                &ProjectId::parse("project").unwrap(),
                &repository_configs,
                &[tampered_receipt],
            )
            .is_err()
        );
    }
}
