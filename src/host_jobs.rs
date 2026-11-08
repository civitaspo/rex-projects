use std::collections::{BTreeMap, HashMap};
use std::ffi::{OsStr, OsString};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::domain::ids::Digest as ContentDigest;
use crate::process::{self, ProcessError, ProcessIdentity, ProcessRequest};
use crate::store::ConfigStore;
use crate::store::host_jobs::{
    HostJobIntent, HostJobKind, HostJobRecord, HostJobState, HostJobSystemReceipt,
};
use crate::worktrees::WorktreeLease;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostJobEnvironmentBinding {
    pub snapshot_id: ContentDigest,
    pub policy_digest: ContentDigest,
}

pub fn environment_policy_digest(
    policy_version: &str,
    environment: &BTreeMap<OsString, OsString>,
) -> Result<ContentDigest, String> {
    let mut digest = Sha256::new();
    digest.update(b"rex-host-environment-policy-v1\0");
    update_field(&mut digest, policy_version.as_bytes());
    digest.update((environment.len() as u64).to_be_bytes());
    for key in environment.keys() {
        update_field(&mut digest, &os_bytes(key));
    }
    ContentDigest::parse(format!("{:x}", digest.finalize()))
}

pub fn stable_host_job_id(operation_id: &str, method: &str, round: u32) -> String {
    let mut digest = Sha256::new();
    digest.update(b"rex-host-job-v1\0");
    update_field(&mut digest, operation_id.as_bytes());
    update_field(&mut digest, method.as_bytes());
    digest.update(round.to_be_bytes());
    format!("{:x}", digest.finalize())
}

/// Hash every immutable child-process input that can change its execution.
/// The digest can be persisted without storing the command's stdin or secrets.
pub fn process_request_digest(
    request: &ProcessRequest,
    environment: &HostJobEnvironmentBinding,
) -> String {
    let mut digest = Sha256::new();
    digest.update(b"rex-process-request-v1\0");
    update_field(&mut digest, &os_bytes(request.executable.as_os_str()));
    digest.update((request.args.len() as u64).to_be_bytes());
    for argument in &request.args {
        update_field(&mut digest, &os_bytes(argument));
    }
    update_field(&mut digest, &request.stdin);
    update_field(&mut digest, environment.snapshot_id.as_str().as_bytes());
    update_field(&mut digest, environment.policy_digest.as_str().as_bytes());
    match &request.cwd {
        Some(cwd) => {
            digest.update([1]);
            update_field(&mut digest, &os_bytes(cwd.as_os_str()));
        }
        None => {
            digest.update([0]);
        }
    }
    digest.update([u8::from(request.clear_environment)]);
    digest.update((request.environment.len() as u64).to_be_bytes());
    for key in request.environment.keys() {
        update_field(&mut digest, &os_bytes(key));
    }
    digest.update(request.timeout.as_nanos().to_be_bytes());
    digest.update(request.shutdown_grace.as_nanos().to_be_bytes());
    digest.update((request.stdout_limit as u64).to_be_bytes());
    digest.update((request.stderr_tail_limit as u64).to_be_bytes());
    format!("{:x}", digest.finalize())
}

fn update_field(digest: &mut Sha256, bytes: &[u8]) {
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
}

#[cfg(unix)]
fn os_bytes(value: &OsStr) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    value.as_bytes().to_vec()
}

#[cfg(windows)]
fn os_bytes(value: &OsStr) -> Vec<u8> {
    use std::os::windows::ffi::OsStrExt;
    value.encode_wide().flat_map(u16::to_be_bytes).collect()
}

#[cfg(not(any(unix, windows)))]
fn os_bytes(value: &OsStr) -> Vec<u8> {
    value.to_string_lossy().as_bytes().to_vec()
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostProcessReceipt {
    pub status_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr_tail: Vec<u8>,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub timed_out: bool,
    pub cleanup_confirmed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostJobProgress {
    Pending,
    Running,
    Unknown,
    /// A previously launched process identity was checked and confirmed absent;
    /// the immutable intent forbids another host-side attempt.
    ProcessAbsentNoRetry,
    ProcessCompleted(HostProcessReceipt),
    ProcessFailed(String),
    Succeeded(String),
    Failed(String),
}

struct ActiveJob {
    lane_id: String,
    worker: Option<JoinHandle<()>>,
    recovered: bool,
    _worktree_lease: Option<WorktreeLease>,
}

#[derive(Clone)]
enum WorkerEvent {
    Started {
        job_id: String,
        identity: ProcessIdentity,
    },
    Finished {
        job_id: String,
        result: Result<HostProcessReceipt, String>,
    },
    Unknown {
        job_id: String,
        reason: String,
    },
}

/// Foreground controller supervisor for bounded host processes. Workers only
/// execute commands and send events; every durable state transition stays here.
pub struct HostJobPool {
    max_jobs: usize,
    max_hook_jobs: usize,
    sender: Sender<WorkerEvent>,
    receiver: Receiver<WorkerEvent>,
    active: HashMap<String, ActiveJob>,
    completed: HashMap<String, Result<HostProcessReceipt, String>>,
}

impl HostJobPool {
    pub fn new(max_jobs: usize, max_hook_jobs: usize) -> Result<Self, String> {
        if max_jobs == 0 || max_hook_jobs == 0 {
            return Err("host job and repository hook capacities must be positive".into());
        }
        let (sender, receiver) = mpsc::channel();
        Ok(Self {
            max_jobs,
            max_hook_jobs,
            sender,
            receiver,
            active: HashMap::new(),
            completed: HashMap::new(),
        })
    }

    pub fn submit_or_poll(
        &mut self,
        store: &mut ConfigStore,
        owner_generation: u64,
        intent: &HostJobIntent,
        process_request: ProcessRequest,
        worktree_lease: Option<WorktreeLease>,
        now_unix: i64,
    ) -> Result<HostJobProgress, String> {
        self.drain_events(store, owner_generation, now_unix)?;
        let mut record = store.enqueue_host_job(owner_generation, intent, now_unix)?;
        if matches!(record.state, HostJobState::Succeeded | HostJobState::Failed) {
            return terminal_progress(&record);
        }
        if let Some(result) = self.completed.get(&intent.job_id) {
            return Ok(match result {
                Ok(receipt) => HostJobProgress::ProcessCompleted(receipt.clone()),
                Err(error) => HostJobProgress::ProcessFailed(error.clone()),
            });
        }
        if self
            .active
            .get(&intent.job_id)
            .is_some_and(|active| active.recovered)
        {
            match reconcile_record(&record)? {
                Recovery::Alive => return Ok(HostJobProgress::Unknown),
                Recovery::Unverifiable(reason) => {
                    store.mark_host_job_unknown(
                        owner_generation,
                        &intent.job_id,
                        &reason,
                        now_unix,
                    )?;
                    return Ok(HostJobProgress::Unknown);
                }
                Recovery::Absent => {
                    if store.retry_absent_host_job(owner_generation, &intent.job_id, now_unix)? {
                        record = store.host_job(&intent.job_id)?.expect("job just read");
                    } else {
                        return self.process_absent_without_retry(
                            store,
                            owner_generation,
                            intent,
                            &record,
                            worktree_lease,
                            now_unix,
                        );
                    }
                }
                Recovery::NoIdentity => return Ok(HostJobProgress::Unknown),
            }
        }
        if !self.active.contains_key(&intent.job_id) {
            if matches!(record.state, HostJobState::Starting) {
                store.mark_host_job_unknown(
                    owner_generation,
                    &intent.job_id,
                    "controller restarted before the process identity was recorded",
                    now_unix,
                )?;
                self.active.insert(
                    intent.job_id.clone(),
                    ActiveJob {
                        lane_id: intent.lane_id.clone(),
                        worker: None,
                        recovered: true,
                        _worktree_lease: worktree_lease,
                    },
                );
                return Ok(HostJobProgress::Unknown);
            }
            if matches!(
                record.state,
                HostJobState::Running | HostJobState::Unknown { .. }
            ) {
                match reconcile_record(&record)? {
                    Recovery::Alive => {
                        store.mark_host_job_unknown(
                            owner_generation,
                            &intent.job_id,
                            "the exact process identity is still present after controller restart",
                            now_unix,
                        )?;
                        self.active.insert(
                            intent.job_id.clone(),
                            ActiveJob {
                                lane_id: intent.lane_id.clone(),
                                worker: None,
                                recovered: true,
                                _worktree_lease: worktree_lease,
                            },
                        );
                        return Ok(HostJobProgress::Unknown);
                    }
                    Recovery::Unverifiable(reason) => {
                        store.mark_host_job_unknown(
                            owner_generation,
                            &intent.job_id,
                            &reason,
                            now_unix,
                        )?;
                        self.active.insert(
                            intent.job_id.clone(),
                            ActiveJob {
                                lane_id: intent.lane_id.clone(),
                                worker: None,
                                recovered: true,
                                _worktree_lease: worktree_lease,
                            },
                        );
                        return Ok(HostJobProgress::Unknown);
                    }
                    Recovery::Absent => {
                        if store.retry_absent_host_job(
                            owner_generation,
                            &intent.job_id,
                            now_unix,
                        )? {
                            record = store.host_job(&intent.job_id)?.expect("job just read");
                        } else {
                            return self.process_absent_without_retry(
                                store,
                                owner_generation,
                                intent,
                                &record,
                                worktree_lease,
                                now_unix,
                            );
                        }
                    }
                    Recovery::NoIdentity => {
                        store.mark_host_job_unknown(
                            owner_generation,
                            &intent.job_id,
                            "no exact process identity is available for restart reconciliation",
                            now_unix,
                        )?;
                        self.active.insert(
                            intent.job_id.clone(),
                            ActiveJob {
                                lane_id: intent.lane_id.clone(),
                                worker: None,
                                recovered: true,
                                _worktree_lease: worktree_lease,
                            },
                        );
                        return Ok(HostJobProgress::Unknown);
                    }
                }
            }
        }
        if !matches!(record.state, HostJobState::Pending) {
            return Ok(match record.state {
                HostJobState::Starting | HostJobState::Running => HostJobProgress::Running,
                HostJobState::Unknown { .. } => HostJobProgress::Unknown,
                HostJobState::Succeeded | HostJobState::Failed => terminal_progress(&record)?,
                HostJobState::Pending => HostJobProgress::Pending,
            });
        }
        if !self.slot_available(store, intent)? {
            return Ok(HostJobProgress::Pending);
        }
        let lease = self
            .active
            .remove(&intent.job_id)
            .and_then(|active| active._worktree_lease)
            .or(worktree_lease);
        if intent.kind.requires_worktree_lease() && lease.is_none() {
            return Err("repository hook jobs require an exclusive worktree lease".into());
        }
        if !intent.kind.requires_worktree_lease() && lease.is_some() {
            return Err("operation adapter jobs must not acquire a Git worktree lease".into());
        }
        if !store.start_host_job(owner_generation, &intent.job_id, now_unix)? {
            return Ok(HostJobProgress::Pending);
        }
        if let Err(error) = self.start_worker(intent, process_request, lease) {
            if !store.revert_host_job_start(owner_generation, &intent.job_id, now_unix)? {
                return Err("failed worker creation left an unreconciled host job".into());
            }
            return Err(error);
        }
        Ok(HostJobProgress::Running)
    }

    fn process_absent_without_retry(
        &mut self,
        store: &mut ConfigStore,
        owner_generation: u64,
        intent: &HostJobIntent,
        record: &HostJobRecord,
        worktree_lease: Option<WorktreeLease>,
        now_unix: i64,
    ) -> Result<HostJobProgress, String> {
        if intent.kind == HostJobKind::OperationAdapter {
            let Some(identity) = record.process_identity.as_ref() else {
                return Ok(HostJobProgress::Unknown);
            };
            if !matches!(record.state, HostJobState::Unknown { .. })
                && !store.mark_host_job_unknown(
                    owner_generation,
                    &intent.job_id,
                    "process identity was observed absent during recovery",
                    now_unix,
                )?
            {
                return Err("host job was not unknown after process absence observation".into());
            }
            if !store.mark_host_job_process_absent(
                owner_generation,
                &intent.job_id,
                intent,
                identity,
                now_unix,
            )? {
                return Err("host job process absence did not match its immutable identity".into());
            }
            self.finish_worker(&intent.job_id);
            let terminal = store
                .host_job(&intent.job_id)?
                .ok_or_else(|| "host job disappeared after process absence".to_owned())?;
            return terminal_progress(&terminal);
        }

        if !matches!(record.state, HostJobState::Unknown { .. }) {
            store.mark_host_job_unknown(
                owner_generation,
                &intent.job_id,
                "process absence is established but the hook retry budget forbids another run",
                now_unix,
            )?;
        }
        self.active
            .entry(intent.job_id.clone())
            .or_insert(ActiveJob {
                lane_id: intent.lane_id.clone(),
                worker: None,
                recovered: true,
                _worktree_lease: worktree_lease,
            });
        Ok(HostJobProgress::Unknown)
    }

    pub fn holds_worktree_lease(&self, job_id: &str) -> bool {
        self.active
            .get(job_id)
            .is_some_and(|active| active._worktree_lease.is_some())
    }

    pub fn holds_worktree_lease_for(&self, lane_id: &str) -> bool {
        self.active
            .values()
            .any(|active| active.lane_id == lane_id && active._worktree_lease.is_some())
    }

    /// Drain worker reports on the controller thread. Call once per controller tick.
    pub fn poll(
        &mut self,
        store: &mut ConfigStore,
        owner_generation: u64,
        now_unix: i64,
    ) -> Result<(), String> {
        self.drain_events(store, owner_generation, now_unix)
    }

    fn slot_available(&self, store: &ConfigStore, intent: &HostJobIntent) -> Result<bool, String> {
        if self
            .active
            .iter()
            .any(|(job_id, active)| job_id != &intent.job_id && active.lane_id == intent.lane_id)
        {
            return Ok(false);
        }
        let occupied = store.host_jobs_in_states(&[
            HostJobState::Starting,
            HostJobState::Running,
            HostJobState::Unknown {
                reason: String::new(),
            },
        ])?;
        let hook_jobs = occupied
            .iter()
            .filter(|job| job.intent.kind == HostJobKind::RepositoryHook)
            .count();
        Ok(occupied.len() < self.max_jobs
            && (intent.kind != HostJobKind::RepositoryHook || hook_jobs < self.max_hook_jobs)
            && !occupied
                .iter()
                .any(|job| job.intent.lane_id == intent.lane_id))
    }

    fn start_worker(
        &mut self,
        intent: &HostJobIntent,
        request: ProcessRequest,
        worktree_lease: Option<WorktreeLease>,
    ) -> Result<(), String> {
        if self.active.contains_key(&intent.job_id) {
            return Err("host job already has a worker".into());
        }
        let job_id = intent.job_id.clone();
        let started_job_id = job_id.clone();
        let sender = self.sender.clone();
        let worker = thread::Builder::new()
            .name(format!("rex-host-job-{}", short_id(&job_id)))
            .spawn(move || {
                let started_sender = sender.clone();
                let result = process::run_with_started_identity(request, move |identity| {
                    let _ = started_sender.send(WorkerEvent::Started {
                        job_id: started_job_id,
                        identity,
                    });
                });
                match result {
                    Ok(output) => {
                        let receipt = HostProcessReceipt {
                            status_code: output.status.and_then(|status| status.code()),
                            stdout: output.stdout,
                            stderr_tail: output.stderr_tail,
                            stdout_truncated: output.stdout_truncated,
                            stderr_truncated: output.stderr_truncated,
                            timed_out: output.timed_out,
                            cleanup_confirmed: output.cleanup_confirmed,
                        };
                        let _ = sender.send(WorkerEvent::Finished {
                            job_id,
                            result: Ok(receipt),
                        });
                    }
                    Err(ProcessError::CleanupUnconfirmed) => {
                        let _ = sender.send(WorkerEvent::Unknown {
                            job_id,
                            reason: "process cleanup could not be confirmed".into(),
                        });
                    }
                    Err(error) => {
                        let _ = sender.send(WorkerEvent::Finished {
                            job_id,
                            result: Err(error.to_string()),
                        });
                    }
                }
            })
            .map_err(|error| format!("cannot start host job worker: {error}"))?;
        self.active.insert(
            intent.job_id.clone(),
            ActiveJob {
                lane_id: intent.lane_id.clone(),
                worker: Some(worker),
                recovered: false,
                _worktree_lease: worktree_lease,
            },
        );
        Ok(())
    }

    fn drain_events(
        &mut self,
        store: &mut ConfigStore,
        owner_generation: u64,
        now_unix: i64,
    ) -> Result<(), String> {
        while let Ok(event) = self.receiver.try_recv() {
            match event {
                WorkerEvent::Started { job_id, identity } => {
                    if !store.mark_host_job_running(
                        owner_generation,
                        &job_id,
                        &identity,
                        now_unix,
                    )? {
                        return Err(
                            "host job start report does not match its durable Starting state"
                                .into(),
                        );
                    }
                }
                WorkerEvent::Finished { job_id, result } => {
                    self.completed.insert(job_id, result);
                }
                WorkerEvent::Unknown { job_id, reason } => {
                    if let Err(error) =
                        store.mark_host_job_unknown(owner_generation, &job_id, &reason, now_unix)
                    {
                        let _ = self.sender.send(WorkerEvent::Unknown { job_id, reason });
                        return Err(error);
                    }
                    if let Some(active) = self.active.get_mut(&job_id) {
                        if let Some(worker) = active.worker.take() {
                            if worker.is_finished() {
                                let _ = worker.join();
                            } else {
                                drop(worker);
                            }
                        }
                        active.recovered = true;
                    }
                }
            }
        }
        Ok(())
    }

    pub fn finish(
        &mut self,
        store: &mut ConfigStore,
        owner_generation: u64,
        job_id: &str,
        succeeded: bool,
        receipt_json: &str,
        now_unix: i64,
    ) -> Result<(), String> {
        if !store.finish_host_job(owner_generation, job_id, succeeded, receipt_json, now_unix)? {
            let record = store
                .host_job(job_id)?
                .ok_or_else(|| "host job disappeared".to_owned())?;
            if matches!(record.state, HostJobState::Succeeded) == succeeded
                && matches!(record.state, HostJobState::Succeeded | HostJobState::Failed)
                && record.receipt_json.as_deref() == Some(receipt_json)
            {
                self.completed.remove(job_id);
                self.finish_worker(job_id);
                return Ok(());
            }
            return Err("host job completion does not match a durable active state".into());
        }
        self.completed.remove(job_id);
        self.finish_worker(job_id);
        Ok(())
    }

    fn finish_worker(&mut self, job_id: &str) {
        if let Some(mut active) = self.active.remove(job_id)
            && let Some(worker) = active.worker.take()
        {
            if worker.is_finished() {
                let _ = worker.join();
            } else {
                drop(worker);
            }
        }
    }
}

impl Drop for HostJobPool {
    fn drop(&mut self) {
        for active in self.active.values_mut() {
            if let Some(worker) = active.worker.take() {
                let _ = worker.join();
            }
        }
    }
}

enum Recovery {
    Alive,
    Absent,
    Unverifiable(String),
    NoIdentity,
}

fn reconcile_record(record: &HostJobRecord) -> Result<Recovery, String> {
    let Some(identity) = record.process_identity.as_ref() else {
        return Ok(Recovery::NoIdentity);
    };
    if identity.quality != process::ProcessIdentityQuality::KernelBirthToken
        || identity.pid == 0
        || identity.process_group_id != identity.pid
        || identity.start_identity.trim().is_empty()
    {
        return Ok(Recovery::Unverifiable(
            "stored process identity is not a kernel birth-token identity".into(),
        ));
    }
    let current = match process::inspect_process_table() {
        Ok(current) => current,
        Err(error) => return Ok(Recovery::Unverifiable(error.to_string())),
    };
    Ok(
        if process::matching_processes(std::slice::from_ref(identity), &current).is_empty() {
            Recovery::Absent
        } else {
            Recovery::Alive
        },
    )
}

fn terminal_progress(record: &HostJobRecord) -> Result<HostJobProgress, String> {
    let receipt = record
        .receipt_json
        .clone()
        .ok_or_else(|| "terminal host job is missing its receipt".to_owned())?;
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(&receipt)
        && value.get("$host_job_state").is_some()
    {
        let system_receipt: HostJobSystemReceipt =
            serde_json::from_value(value).map_err(|error| error.to_string())?;
        return match system_receipt {
            HostJobSystemReceipt::ProcessAbsentNoRetry {
                schema_version,
                intent,
                process_identity,
                attempt_count,
            } if schema_version == 1
                && intent == record.intent
                && record.process_identity.as_ref() == Some(&process_identity)
                && attempt_count == record.attempt_count
                && matches!(record.state, HostJobState::Failed) =>
            {
                Ok(HostJobProgress::ProcessAbsentNoRetry)
            }
            _ => Err("host job process-absence receipt does not match its immutable record".into()),
        };
    }
    Ok(match record.state {
        HostJobState::Succeeded => HostJobProgress::Succeeded(receipt),
        HostJobState::Failed => HostJobProgress::Failed(receipt),
        _ => return Err("host job is not terminal".into()),
    })
}

fn short_id(id: &str) -> String {
    id.chars().take(12).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::ProcessIdentityQuality;
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    fn request(executable: PathBuf, args: &[&str]) -> ProcessRequest {
        ProcessRequest {
            executable,
            args: args.iter().map(Into::into).collect(),
            stdin: Vec::new(),
            cwd: None,
            clear_environment: true,
            environment: Default::default(),
            timeout: Duration::from_secs(2),
            shutdown_grace: Duration::from_millis(100),
            stdout_limit: 1024,
            stderr_tail_limit: 1024,
        }
    }

    #[test]
    #[ignore = "spawned by managed_host_job_reports_identity_before_exit"]
    fn managed_host_job_process_fixture() {
        thread::sleep(Duration::from_millis(250));
    }

    #[test]
    fn managed_host_job_reports_identity_before_exit() {
        let executable = std::env::current_exe().unwrap();
        let request = request(
            executable,
            &[
                "--ignored",
                "--exact",
                "host_jobs::tests::managed_host_job_process_fixture",
                "--nocapture",
            ],
        );
        let began = Instant::now();
        let mut callback_elapsed = None;
        let result = process::run_with_started_identity(request, |identity| {
            callback_elapsed = Some(began.elapsed());
            assert_eq!(identity.pid, identity.process_group_id);
            assert!(!identity.start_identity.is_empty());
        })
        .unwrap();
        assert!(result.cleanup_confirmed);
        assert!(began.elapsed() >= Duration::from_millis(200));
        assert!(callback_elapsed.unwrap() < Duration::from_millis(150));
    }

    #[test]
    fn stable_ids_bind_method_round_and_request_digest_binds_all_process_inputs() {
        let first_id = stable_host_job_id("operation-1", "operation.observe", 3);
        assert_eq!(
            stable_host_job_id("operation-1", "operation.observe", 3),
            first_id
        );
        assert_ne!(
            stable_host_job_id("operation-1", "operation.find", 3),
            first_id
        );
        assert_ne!(
            stable_host_job_id("operation-1", "operation.observe", 4),
            first_id
        );

        let binding = HostJobEnvironmentBinding {
            snapshot_id: ContentDigest::parse("a".repeat(64)).unwrap(),
            policy_digest: ContentDigest::parse("b".repeat(64)).unwrap(),
        };
        let mut original = request(PathBuf::from("/usr/bin/true"), &[]);
        original
            .environment
            .insert("TOKEN".into(), "secret-one".into());
        let digest = process_request_digest(&original, &binding);
        let mut changed = original.clone();
        changed.stdin.push(0);
        assert_ne!(process_request_digest(&changed, &binding), digest);
        let mut changed = original.clone();
        changed.clear_environment = !changed.clear_environment;
        assert_ne!(process_request_digest(&changed, &binding), digest);
        let mut changed = original.clone();
        changed
            .environment
            .insert("TOKEN".into(), "secret-two".into());
        assert_eq!(process_request_digest(&changed, &binding), digest);
        let mut different_environment = binding.clone();
        different_environment.snapshot_id = ContentDigest::parse("c".repeat(64)).unwrap();
        assert_ne!(
            process_request_digest(&original, &different_environment),
            digest
        );
        let mut different_environment = binding.clone();
        different_environment.policy_digest = ContentDigest::parse("d".repeat(64)).unwrap();
        assert_ne!(
            process_request_digest(&original, &different_environment),
            digest
        );
        let policy =
            environment_policy_digest("operation-adapter-v1", &original.environment).unwrap();
        assert_eq!(
            environment_policy_digest("operation-adapter-v1", &changed.environment).unwrap(),
            policy
        );
        let mut changed_selection = original.clone();
        changed_selection
            .environment
            .insert("OTHER".into(), "secret-three".into());
        assert_ne!(
            environment_policy_digest("operation-adapter-v1", &changed_selection.environment)
                .unwrap(),
            policy
        );
        let mut changed = original.clone();
        changed.shutdown_grace += Duration::from_millis(1);
        assert_ne!(process_request_digest(&changed, &binding), digest);
        let mut changed = original;
        changed.stderr_tail_limit += 1;
        assert_ne!(process_request_digest(&changed, &binding), digest);

        let intent = crate::store::host_jobs::HostJobIntent {
            job_id: first_id,
            effect_operation_id: "operation-1:operation.observe:3".into(),
            project_id: "project-1".into(),
            subject_id: "operation-1".into(),
            lane_id: "operation-1".into(),
            kind: HostJobKind::OperationAdapter,
            operation_method: Some(crate::store::host_jobs::OperationMethod::Observe),
            request_digest: digest,
            configuration_digest: "configuration-digest".into(),
            environment_snapshot_id: binding.snapshot_id,
            environment_policy_digest: binding.policy_digest,
            head: "source-sha".into(),
            source_digest: "subject-digest".into(),
            max_attempts: 2,
            retry_when_absent: true,
        };
        assert!(!serde_json::to_string(&intent).unwrap().contains("secret"));
    }

    #[test]
    fn confirmed_process_absence_is_typed_when_retries_are_forbidden() {
        let mut store = crate::store::host_jobs::in_memory_test_store();
        let job = crate::store::host_jobs::HostJobIntent {
            job_id: "operation-job".into(),
            effect_operation_id: "operation-1:operation.invoke:1".into(),
            project_id: "project-1".into(),
            subject_id: "operation-1".into(),
            lane_id: "operation-1".into(),
            kind: HostJobKind::OperationAdapter,
            operation_method: Some(crate::store::host_jobs::OperationMethod::Invoke),
            request_digest: "request-digest".into(),
            configuration_digest: "configuration-digest".into(),
            environment_snapshot_id: ContentDigest::parse("e".repeat(64)).unwrap(),
            environment_policy_digest: ContentDigest::parse("f".repeat(64)).unwrap(),
            head: "source-sha".into(),
            source_digest: "subject-digest".into(),
            max_attempts: 1,
            retry_when_absent: true,
        };
        store.enqueue_host_job(1, &job, 1).unwrap();
        assert!(store.start_host_job(1, &job.job_id, 2).unwrap());
        assert!(
            store
                .mark_host_job_running(
                    1,
                    &job.job_id,
                    &ProcessIdentity {
                        pid: u32::MAX,
                        parent_pid: 1,
                        process_group_id: u32::MAX,
                        start_identity: "nonexistent-kernel-birth-token".into(),
                        command: "operation-adapter".into(),
                        quality: ProcessIdentityQuality::KernelBirthToken,
                    },
                    3,
                )
                .unwrap()
        );
        let mut pool = HostJobPool::new(4, 2).unwrap();
        assert_eq!(
            pool.submit_or_poll(
                &mut store,
                1,
                &job,
                request(std::env::current_exe().unwrap(), &["--version"]),
                None,
                4,
            )
            .unwrap(),
            HostJobProgress::ProcessAbsentNoRetry
        );
        assert!(matches!(
            store.host_job(&job.job_id).unwrap().unwrap().state,
            HostJobState::Failed
        ));
        assert_eq!(
            store.host_job(&job.job_id).unwrap().unwrap().attempt_count,
            1
        );

        let mut find = job.clone();
        find.job_id = "operation-find-job".into();
        find.effect_operation_id = "operation-1:operation.find:1".into();
        find.operation_method = Some(crate::store::host_jobs::OperationMethod::Find);
        find.max_attempts = 2;
        assert_eq!(
            pool.submit_or_poll(
                &mut store,
                1,
                &find,
                request(std::env::current_exe().unwrap(), &["--version"]),
                None,
                5,
            )
            .unwrap(),
            HostJobProgress::Running
        );
        assert_eq!(
            store.host_job(&find.job_id).unwrap().unwrap().attempt_count,
            1
        );
    }
}

#[cfg(test)]
mod pool_tests {
    use super::*;
    use crate::domain::ids::RepositoryId;
    use crate::process::ProcessRequest;
    use crate::worktrees::{GitOptions, ManagedWorktree, WorktreeManager};
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    fn git_executable() -> PathBuf {
        let search_path = std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .collect::<Vec<_>>();
        crate::process::resolve_executable(Path::new("git"), &search_path)
            .expect("host job tests require Git on PATH")
    }

    fn request() -> ProcessRequest {
        ProcessRequest {
            executable: std::env::current_exe().unwrap(),
            args: [
                "--ignored",
                "--exact",
                "host_jobs::tests::managed_host_job_process_fixture",
                "--nocapture",
            ]
            .iter()
            .map(OsString::from)
            .collect(),
            stdin: Vec::new(),
            cwd: None,
            clear_environment: true,
            environment: Default::default(),
            timeout: Duration::from_secs(2),
            shutdown_grace: Duration::from_millis(100),
            stdout_limit: 1024,
            stderr_tail_limit: 1024,
        }
    }

    fn intent(
        job_id: &str,
        project: &str,
        worktree: &str,
    ) -> crate::store::host_jobs::HostJobIntent {
        crate::store::host_jobs::HostJobIntent {
            job_id: job_id.into(),
            effect_operation_id: format!("effect:{job_id}"),
            project_id: project.into(),
            subject_id: "hook".into(),
            lane_id: worktree.into(),
            kind: HostJobKind::RepositoryHook,
            operation_method: None,
            request_digest: format!("request:{job_id}"),
            configuration_digest: "config".into(),
            environment_snapshot_id: ContentDigest::parse("e".repeat(64)).unwrap(),
            environment_policy_digest: ContentDigest::parse("f".repeat(64)).unwrap(),
            head: "head".into(),
            source_digest: "source".into(),
            max_attempts: 2,
            retry_when_absent: true,
        }
    }

    fn lease_for(
        manager: &WorktreeManager,
        state_root: &Path,
        repository_id: &RepositoryId,
        index: u32,
    ) -> crate::worktrees::WorktreeLease {
        let suffix = format!("{index:032x}");
        let path = state_root
            .join("worktrees")
            .join(repository_id.as_str())
            .join(&suffix);
        std::fs::create_dir_all(&path).unwrap();
        manager
            .acquire_writer_lease(ManagedWorktree {
                repository_id: repository_id.clone(),
                path,
                branch: format!("rex-projects/{suffix}"),
                base_sha: "base".into(),
            })
            .unwrap()
    }

    #[test]
    fn separate_worktrees_run_in_parallel_and_same_worktree_stays_ordered() {
        let temp = tempfile::tempdir().unwrap();
        let state_root = temp.path().join("worktree-state");
        let manager = WorktreeManager::new(
            &state_root,
            GitOptions {
                executable: git_executable(),
                environment: Default::default(),
                timeout: Duration::from_secs(2),
            },
        )
        .unwrap();
        let state_root = state_root.canonicalize().unwrap();
        let repository_id = RepositoryId::parse("repo-a").unwrap();
        let first_worktree = state_root
            .join("worktrees/repo-a/00000000000000000000000000000001")
            .to_string_lossy()
            .into_owned();
        let second_worktree = state_root
            .join("worktrees/repo-a/00000000000000000000000000000002")
            .to_string_lossy()
            .into_owned();
        let first = intent("job-1", "project-1", &first_worktree);
        let second = intent("job-2", "project-2", &second_worktree);
        let same_worktree_waiter = intent("job-3", "project-3", &first_worktree);
        let mut store = crate::store::host_jobs::in_memory_test_store();
        let mut pool = HostJobPool::new(2, 2).unwrap();
        let began = Instant::now();
        assert_eq!(
            pool.submit_or_poll(
                &mut store,
                1,
                &first,
                request(),
                Some(lease_for(&manager, &state_root, &repository_id, 1)),
                1
            )
            .unwrap(),
            HostJobProgress::Running
        );
        assert_eq!(
            pool.submit_or_poll(
                &mut store,
                1,
                &second,
                request(),
                Some(lease_for(&manager, &state_root, &repository_id, 2)),
                1
            )
            .unwrap(),
            HostJobProgress::Running
        );
        assert_eq!(
            pool.submit_or_poll(&mut store, 1, &same_worktree_waiter, request(), None, 1)
                .unwrap(),
            HostJobProgress::Pending
        );
        assert_eq!(
            store
                .host_job(&same_worktree_waiter.job_id)
                .unwrap()
                .unwrap()
                .state,
            HostJobState::Pending
        );

        let mut completed = HashMap::new();
        while completed.len() < 2 {
            pool.poll(&mut store, 1, 2).unwrap();
            for job in [&first, &second] {
                if completed.contains_key(&job.job_id) {
                    continue;
                }
                match pool
                    .submit_or_poll(&mut store, 1, job, request(), None, 2)
                    .unwrap()
                {
                    HostJobProgress::ProcessCompleted(receipt) => {
                        assert_eq!(receipt.status_code, Some(0));
                        let receipt_json = serde_json::to_string(&receipt).unwrap();
                        pool.finish(&mut store, 1, &job.job_id, true, &receipt_json, 2)
                            .unwrap();
                        completed.insert(job.job_id.clone(), receipt);
                    }
                    HostJobProgress::Running
                    | HostJobProgress::Pending
                    | HostJobProgress::Unknown
                    | HostJobProgress::ProcessAbsentNoRetry => {}
                    other => panic!("unexpected host job progress: {other:?}"),
                }
            }
            assert!(
                began.elapsed() < Duration::from_millis(550),
                "independent jobs did not overlap"
            );
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(completed.len(), 2);
        assert_eq!(
            store
                .host_jobs_in_states(&[HostJobState::Pending])
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn operation_jobs_share_global_capacity_but_not_the_hook_cap_or_lease() {
        let temp = tempfile::tempdir().unwrap();
        let state_root = temp.path().join("worktree-state");
        let manager = WorktreeManager::new(
            &state_root,
            GitOptions {
                executable: git_executable(),
                environment: Default::default(),
                timeout: Duration::from_secs(2),
            },
        )
        .unwrap();
        let state_root = state_root.canonicalize().unwrap();
        let repository_id = RepositoryId::parse("repo-a").unwrap();
        let mut store = crate::store::host_jobs::in_memory_test_store();
        let mut pool = HostJobPool::new(2, 1).unwrap();

        let mut operation = intent("operation-job", "project-1", "operation-1");
        operation.kind = HostJobKind::OperationAdapter;
        operation.operation_method = Some(crate::store::host_jobs::OperationMethod::Invoke);
        operation.max_attempts = 1;
        operation.retry_when_absent = false;
        assert_eq!(
            pool.submit_or_poll(&mut store, 1, &operation, request(), None, 1)
                .unwrap(),
            HostJobProgress::Running
        );

        let first_hook_worktree = state_root
            .join("worktrees/repo-a/00000000000000000000000000000001")
            .to_string_lossy()
            .into_owned();
        let first_hook = intent("hook-1", "project-2", &first_hook_worktree);
        assert_eq!(
            pool.submit_or_poll(
                &mut store,
                1,
                &first_hook,
                request(),
                Some(lease_for(&manager, &state_root, &repository_id, 1)),
                1,
            )
            .unwrap(),
            HostJobProgress::Running
        );

        let second_hook_worktree = state_root
            .join("worktrees/repo-a/00000000000000000000000000000002")
            .to_string_lossy()
            .into_owned();
        let second_hook = intent("hook-2", "project-3", &second_hook_worktree);
        assert_eq!(
            pool.submit_or_poll(&mut store, 1, &second_hook, request(), None, 1)
                .unwrap(),
            HostJobProgress::Pending
        );

        let second_operation = intent("operation-job-2", "project-4", "operation-2");
        let mut second_operation = second_operation;
        second_operation.kind = HostJobKind::OperationAdapter;
        second_operation.operation_method = Some(crate::store::host_jobs::OperationMethod::Invoke);
        second_operation.max_attempts = 1;
        second_operation.retry_when_absent = false;
        assert_eq!(
            pool.submit_or_poll(&mut store, 1, &second_operation, request(), None, 1)
                .unwrap(),
            HostJobProgress::Pending
        );
    }
}
