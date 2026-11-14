use std::collections::{BTreeMap, HashMap, VecDeque};
use std::ffi::{OsStr, OsString};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};

use sha2::{Digest as _, Sha256};

use crate::domain::ids::Digest as ContentDigest;
use crate::process::{self, ProcessError, ProcessIdentity, ProcessRequest};
use crate::store::ConfigStore;
pub use crate::store::host_jobs::HostProcessReceipt;
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

fn can_replay_completed_process(
    record: &HostJobRecord,
    current_intent: &HostJobIntent,
    current_request: &ProcessRequest,
) -> bool {
    // Replay consumes the original invocation's output; it never runs in the new environment.
    let stored = &record.intent;
    if current_intent.environment_policy_digest != stored.environment_policy_digest {
        return false;
    }

    let current_binding = HostJobEnvironmentBinding {
        snapshot_id: current_intent.environment_snapshot_id.clone(),
        policy_digest: current_intent.environment_policy_digest.clone(),
    };
    if current_intent.request_digest != process_request_digest(current_request, &current_binding) {
        return false;
    }

    let stored_binding = HostJobEnvironmentBinding {
        snapshot_id: stored.environment_snapshot_id.clone(),
        policy_digest: stored.environment_policy_digest.clone(),
    };
    if stored.request_digest != process_request_digest(current_request, &stored_binding) {
        return false;
    }

    let mut normalized = current_intent.clone();
    normalized.request_digest.clone_from(&stored.request_digest);
    normalized
        .environment_snapshot_id
        .clone_from(&stored.environment_snapshot_id);
    normalized == *stored
}

/// Hash process inputs without storing command stdin or environment values.
/// Environment identity is represented by its snapshot and policy IDs; variable names are hashed.
/// Values are not recovered or used to authorize execution from this digest.
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostJobProgress {
    Pending,
    Running,
    Unknown,
    /// A previously launched process identity was checked and confirmed absent;
    /// the immutable intent forbids another host-side attempt.
    ProcessAbsentNoRetry,
    ProcessCompleted {
        receipt: HostProcessReceipt,
        /// The immutable launch binding retained by the durable host-job row.
        /// This remains authoritative when a controller restart captures a
        /// fresh environment snapshot before replaying the raw result.
        intent: Box<HostJobIntent>,
    },
    ProcessFailed(String),
    Succeeded(String),
    Failed(String),
}

struct ActiveJob {
    lane_id: String,
    worker: Option<JoinHandle<()>>,
    stop: Option<Arc<AtomicBool>>,
    recovered: bool,
    _worktree_lease: Option<Arc<WorktreeLease>>,
}

#[derive(Clone)]
enum WorkerEvent {
    Started {
        job_id: String,
        identity: ProcessIdentity,
    },
    Finished {
        job_id: String,
        intent: Box<HostJobIntent>,
        identity: Option<ProcessIdentity>,
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
    pending_events: VecDeque<WorkerEvent>,
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
            pending_events: VecDeque::new(),
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
        let worktree_lease = worktree_lease.map(Arc::new);
        self.drain_events(store, owner_generation, now_unix)?;
        let existing = store.host_job(&intent.job_id)?;
        let replayed = if let Some(record) = existing.as_ref() {
            if let Some(receipt) = record.process_receipt.as_ref() {
                if receipt.cleanup_confirmed
                    && record
                        .process_identity
                        .as_ref()
                        .is_some_and(is_exact_identity)
                    && record.receipt_json.is_none()
                    && matches!(
                        record.state,
                        HostJobState::Running | HostJobState::Unknown { .. }
                    )
                {
                    if !can_replay_completed_process(record, intent, &process_request) {
                        return Err(
                            "completed host process does not match the current immutable request"
                                .into(),
                        );
                    }
                    Some((record.clone(), receipt.clone()))
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };
        let mut record = match replayed.as_ref() {
            Some((record, _)) => record.clone(),
            None => store.enqueue_host_job(owner_generation, intent, now_unix)?,
        };
        if matches!(record.state, HostJobState::Succeeded | HostJobState::Failed) {
            return terminal_progress(&record);
        }
        if let Some((record, receipt)) = replayed {
            return Ok(HostJobProgress::ProcessCompleted {
                receipt,
                intent: Box::new(record.intent),
            });
        }
        if record.process_receipt.is_some() {
            store.mark_host_job_unknown(
                owner_generation,
                &intent.job_id,
                "stored host process result is not bound to a verified completed process",
                now_unix,
            )?;
            return Ok(HostJobProgress::Unknown);
        }
        if let Some(result) = self.completed.get(&intent.job_id) {
            return Ok(match result {
                Ok(receipt) => HostJobProgress::ProcessCompleted {
                    receipt: receipt.clone(),
                    intent: Box::new(record.intent.clone()),
                },
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
                        stop: None,
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
                                stop: None,
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
                                stop: None,
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
                                stop: None,
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
        worktree_lease: Option<Arc<WorktreeLease>>,
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
                stop: None,
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

    /// Collect only reports from already-launched host jobs. This never starts
    /// queued work or interprets the result as completion of its logical effect.
    pub fn drain_finished_processes(
        &mut self,
        store: &mut ConfigStore,
        owner_generation: u64,
        now_unix: i64,
    ) -> Result<(), String> {
        self.drain_events(store, owner_generation, now_unix)
    }

    pub fn request_shutdown(
        &mut self,
        store: &mut ConfigStore,
        owner_generation: u64,
        now_unix: i64,
    ) -> Result<(), String> {
        for active in self.active.values() {
            if let Some(stop) = &active.stop {
                stop.store(true, Ordering::Relaxed);
            }
        }
        self.drain_events(store, owner_generation, now_unix)?;
        let records = store.host_jobs_in_states(&[
            HostJobState::Starting,
            HostJobState::Running,
            HostJobState::Unknown {
                reason: String::new(),
            },
        ])?;
        for record in records {
            if record.process_receipt.is_some()
                || self
                    .active
                    .get(&record.intent.job_id)
                    .is_some_and(|active| {
                        active
                            .worker
                            .as_ref()
                            .is_some_and(|worker| !worker.is_finished())
                    })
            {
                continue;
            }
            let Some(identity) = record
                .process_identity
                .as_ref()
                .filter(|identity| is_exact_identity(identity))
            else {
                continue;
            };
            let current = process::inspect_process_table().map_err(|error| error.to_string())?;
            process::signal_process_group_if_observed(
                identity.process_group_id,
                std::slice::from_ref(identity),
                &current,
                process::ProcessSignal::Terminate,
            )
            .map_err(|error| error.to_string())?;
        }
        Ok(())
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
        worktree_lease: Option<Arc<WorktreeLease>>,
    ) -> Result<(), String> {
        if self.active.contains_key(&intent.job_id) {
            return Err("host job already has a worker".into());
        }
        let job_id = intent.job_id.clone();
        let started_job_id = job_id.clone();
        let worker_intent = intent.clone();
        let sender = self.sender.clone();
        let worker_lease = worktree_lease.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let worker = thread::Builder::new()
            .name(format!("rex-host-job-{}", short_id(&job_id)))
            .spawn(move || {
                let _worktree_lease = worker_lease;
                let started_sender = sender.clone();
                let mut process_identity = None;
                let result = process::run_with_started_identity_and_stop(
                    request,
                    |identity| {
                        process_identity = Some(identity.clone());
                        let _ = started_sender.send(WorkerEvent::Started {
                            job_id: started_job_id.clone(),
                            identity,
                        });
                    },
                    &worker_stop,
                );
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
                            intent: Box::new(worker_intent),
                            identity: process_identity,
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
                            intent: Box::new(worker_intent),
                            identity: process_identity,
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
                stop: Some(stop),
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
        while let Some(event) = self
            .pending_events
            .pop_front()
            .or_else(|| self.receiver.try_recv().ok())
        {
            let retry_event = event.clone();
            match event {
                WorkerEvent::Started { job_id, identity } => {
                    match store.mark_host_job_running(
                        owner_generation,
                        &job_id,
                        &identity,
                        now_unix,
                    ) {
                        Ok(true) => {}
                        Ok(false) => {
                            self.pending_events.push_front(retry_event);
                            return Err(
                                "host job start report does not match its durable Starting state"
                                    .into(),
                            );
                        }
                        Err(error) => {
                            self.pending_events.push_front(retry_event);
                            return Err(error);
                        }
                    }
                }
                WorkerEvent::Finished {
                    job_id,
                    intent,
                    identity,
                    result,
                } => {
                    if let Ok(receipt) = &result
                        && receipt.cleanup_confirmed
                    {
                        let Some(identity) = identity.as_ref() else {
                            self.pending_events.push_front(retry_event);
                            return Err("finished host job has no started process identity".into());
                        };
                        match store.record_host_process_result(
                            owner_generation,
                            &intent,
                            identity,
                            receipt,
                            now_unix,
                        ) {
                            Ok(true) => {}
                            Ok(false) => {
                                self.pending_events.push_front(retry_event);
                                return Err(
                                    "finished process result does not match durable host job authority".into(),
                                );
                            }
                            Err(error) => {
                                self.pending_events.push_front(retry_event);
                                return Err(error);
                            }
                        }
                    }
                    if matches!(&result, Ok(receipt) if !receipt.cleanup_confirmed) {
                        match store.mark_host_job_unknown(
                            owner_generation,
                            &job_id,
                            "host process completion did not confirm cleanup",
                            now_unix,
                        ) {
                            Ok(_) => {}
                            Err(error) => {
                                self.pending_events.push_front(retry_event);
                                return Err(error);
                            }
                        }
                        self.completed.remove(&job_id);
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
                        continue;
                    }
                    self.completed.insert(job_id, result);
                }
                WorkerEvent::Unknown { job_id, reason } => {
                    if let Err(error) =
                        store.mark_host_job_unknown(owner_generation, &job_id, &reason, now_unix)
                    {
                        self.pending_events.push_front(retry_event);
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
            if let Some(worker) = active.worker.take()
                && worker.is_finished()
            {
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

fn is_exact_identity(identity: &ProcessIdentity) -> bool {
    identity.quality == process::ProcessIdentityQuality::KernelBirthToken
        && identity.pid != 0
        && identity.process_group_id == identity.pid
        && !identity.start_identity.trim().is_empty()
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
    use std::path::{Path, PathBuf};
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
        use std::io::Write as _;
        if let Some(marker) = std::env::var_os("REX_HOST_JOB_INVOCATION_MARKER") {
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(marker)
                .unwrap();
            writeln!(file, "invoked").unwrap();
        }
        print!("fixed host process result");
        std::io::stdout().flush().unwrap();
        if let Some(release_file) = std::env::var_os("REX_HOST_JOB_RELEASE_FILE") {
            let deadline = Instant::now() + Duration::from_secs(2);
            while !Path::new(&release_file).exists() {
                assert!(Instant::now() < deadline);
                thread::sleep(Duration::from_millis(5));
            }
        } else {
            thread::sleep(Duration::from_millis(250));
        }
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
    fn shutdown_stops_running_worker_and_keeps_unidentified_claim() {
        let mut store = crate::store::host_jobs::in_memory_test_store();
        let mut pool = HostJobPool::new(2, 2).unwrap();
        let mut job = intent("shutdown-running", "project", "lane");
        job.kind = HostJobKind::OperationAdapter;
        job.max_attempts = 1;
        job.operation_method = Some(crate::store::host_jobs::OperationMethod::Invoke);
        let mut unknown = intent("shutdown-unknown", "project", "other-lane");
        unknown.kind = HostJobKind::OperationAdapter;
        unknown.max_attempts = 1;
        unknown.operation_method = Some(crate::store::host_jobs::OperationMethod::Invoke);
        store.enqueue_host_job(1, &unknown, 1).unwrap();
        assert!(store.start_host_job(1, &unknown.job_id, 2).unwrap());
        let mut command = request();
        command.executable = PathBuf::from("/bin/sh");
        command.args = vec![
            "-c".into(),
            "trap 'exit 0' TERM; while :; do :; done".into(),
        ];
        command.timeout = Duration::from_secs(30);
        assert_eq!(
            pool.submit_or_poll(&mut store, 1, &job, command, None, 3)
                .unwrap(),
            HostJobProgress::Running
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            pool.poll(&mut store, 1, 4).unwrap();
            if store
                .host_job(&job.job_id)
                .unwrap()
                .unwrap()
                .process_identity
                .is_some()
            {
                break;
            }
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(5));
        }
        loop {
            pool.request_shutdown(&mut store, 1, 5).unwrap();
            if store
                .host_job(&job.job_id)
                .unwrap()
                .unwrap()
                .process_receipt
                .is_some()
            {
                break;
            }
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(5));
        }
        let record = store.host_job(&job.job_id).unwrap().unwrap();
        assert!(record.process_receipt.unwrap().cleanup_confirmed);
        assert!(matches!(
            store.host_job(&unknown.job_id).unwrap().unwrap().state,
            HostJobState::Starting
        ));
        assert!(
            store
                .host_job(&unknown.job_id)
                .unwrap()
                .unwrap()
                .process_receipt
                .is_none()
        );
    }

    #[test]
    fn shutdown_retains_claim_when_process_identity_cannot_be_confirmed() {
        let mut store = crate::store::host_jobs::in_memory_test_store();
        let mut pool = HostJobPool::new(2, 2).unwrap();
        let mut job = intent("shutdown-mismatch", "project", "lane");
        job.kind = HostJobKind::OperationAdapter;
        job.operation_method = Some(crate::store::host_jobs::OperationMethod::Invoke);
        job.max_attempts = 1;
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let identity = ProcessIdentity {
            pid: child.id(),
            parent_pid: std::process::id(),
            process_group_id: child.id(),
            start_identity: "different-birth-token".into(),
            command: "sleep".into(),
            quality: process::ProcessIdentityQuality::KernelBirthToken,
        };
        store.enqueue_host_job(1, &job, 1).unwrap();
        assert!(store.start_host_job(1, &job.job_id, 2).unwrap());
        assert!(
            store
                .mark_host_job_running(1, &job.job_id, &identity, 3)
                .unwrap()
        );
        let result = pool.request_shutdown(&mut store, 1, 4);
        let still_running = child.try_wait().unwrap().is_none();
        child.kill().unwrap();
        child.wait().unwrap();
        result.unwrap();
        assert!(still_running);
        let record = store.host_job(&job.job_id).unwrap().unwrap();
        assert!(matches!(record.state, HostJobState::Running));
        assert!(record.process_receipt.is_none());
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
        let mut first = intent("job-1", "project-1", &first_worktree);
        let mut second = intent("job-2", "project-2", &second_worktree);
        let mut same_worktree_waiter = intent("job-3", "project-3", &first_worktree);
        let request = request();
        for job in [&mut first, &mut second, &mut same_worktree_waiter] {
            job.request_digest = process_request_digest(
                &request,
                &HostJobEnvironmentBinding {
                    snapshot_id: job.environment_snapshot_id.clone(),
                    policy_digest: job.environment_policy_digest.clone(),
                },
            );
        }
        let mut store = crate::store::host_jobs::in_memory_test_store();
        let mut pool = HostJobPool::new(2, 2).unwrap();
        let began = Instant::now();
        assert_eq!(
            pool.submit_or_poll(
                &mut store,
                1,
                &first,
                request.clone(),
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
                request.clone(),
                Some(lease_for(&manager, &state_root, &repository_id, 2)),
                1
            )
            .unwrap(),
            HostJobProgress::Running
        );
        assert_eq!(
            pool.submit_or_poll(
                &mut store,
                1,
                &same_worktree_waiter,
                request.clone(),
                None,
                1,
            )
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
                    .submit_or_poll(&mut store, 1, job, request.clone(), None, 2)
                    .unwrap()
                {
                    HostJobProgress::ProcessCompleted { receipt, .. } => {
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

    #[test]
    fn completed_process_result_survives_pool_restart_without_second_invocation() {
        let temp = tempfile::tempdir().unwrap();
        let marker = temp.path().join("invocations");
        let database = temp.path().join("state.sqlite3");
        let marker_count = |path: &Path| {
            std::fs::read_to_string(path)
                .map(|contents| contents.lines().count())
                .unwrap_or_default()
        };
        let mut job = intent("operation-replay", "project-1", "operation-1");
        job.kind = HostJobKind::OperationAdapter;
        job.operation_method = Some(crate::store::host_jobs::OperationMethod::Invoke);
        job.max_attempts = 1;
        job.retry_when_absent = false;
        let mut process_request = request();
        process_request.environment.insert(
            OsString::from("REX_HOST_JOB_INVOCATION_MARKER"),
            marker.as_os_str().to_owned(),
        );
        let original_binding = HostJobEnvironmentBinding {
            snapshot_id: job.environment_snapshot_id.clone(),
            policy_digest: job.environment_policy_digest.clone(),
        };
        job.request_digest = process_request_digest(&process_request, &original_binding);
        let mut store = crate::store::host_jobs::file_test_store(&database);
        let mut queued = job.clone();
        queued.job_id = "operation-queued".into();
        queued.effect_operation_id = "effect:operation-queued".into();
        store.enqueue_host_job(1, &queued, 1).unwrap();
        {
            let mut pool = HostJobPool::new(1, 1).unwrap();
            assert_eq!(
                pool.submit_or_poll(&mut store, 1, &job, process_request.clone(), None, 1)
                    .unwrap(),
                HostJobProgress::Running
            );
            let began = Instant::now();
            loop {
                pool.drain_finished_processes(&mut store, 1, 2).unwrap();
                if store
                    .host_job(&job.job_id)
                    .unwrap()
                    .unwrap()
                    .process_receipt
                    .is_some()
                {
                    break;
                }
                assert!(began.elapsed() < Duration::from_secs(3));
                thread::sleep(Duration::from_millis(5));
            }
            let record = store.host_job(&job.job_id).unwrap().unwrap();
            let raw_receipt = record.process_receipt.unwrap();
            assert!(raw_receipt.cleanup_confirmed);
            assert!(
                String::from_utf8_lossy(&raw_receipt.stdout).contains("fixed host process result")
            );
            assert!(record.receipt_json.is_none());
            assert_eq!(record.state, HostJobState::Running);
            assert_eq!(
                store
                    .host_job(&queued.job_id)
                    .unwrap()
                    .unwrap()
                    .attempt_count,
                0
            );
            assert_eq!(
                store.host_job(&queued.job_id).unwrap().unwrap().state,
                HostJobState::Pending
            );
            assert_eq!(marker_count(&marker), 1);
        }
        drop(store);

        let mut store = crate::store::host_jobs::file_test_store(&database);
        let mut restarted_pool = HostJobPool::new(1, 1).unwrap();
        let mut restarted_job = job.clone();
        restarted_job.environment_snapshot_id = ContentDigest::parse("d".repeat(64)).unwrap();
        restarted_job.request_digest = process_request_digest(
            &process_request,
            &HostJobEnvironmentBinding {
                snapshot_id: restarted_job.environment_snapshot_id.clone(),
                policy_digest: restarted_job.environment_policy_digest.clone(),
            },
        );
        assert!(store.enqueue_host_job(1, &restarted_job, 3).is_err());
        let progress = restarted_pool
            .submit_or_poll(
                &mut store,
                1,
                &restarted_job,
                process_request.clone(),
                None,
                3,
            )
            .unwrap();
        let HostJobProgress::ProcessCompleted {
            receipt: replayed,
            intent: replayed_intent,
        } = progress
        else {
            panic!("durable raw process result was not replayed: {progress:?}");
        };
        assert_eq!(*replayed_intent, job);
        assert!(String::from_utf8_lossy(&replayed.stdout).contains("fixed host process result"));
        assert_eq!(
            store.host_job(&job.job_id).unwrap().unwrap().attempt_count,
            1
        );
        assert_eq!(marker_count(&marker), 1);

        let mut changed_request = process_request;
        changed_request.stdin.push(b'x');
        let mut changed_intent = restarted_job;
        changed_intent.request_digest = process_request_digest(
            &changed_request,
            &HostJobEnvironmentBinding {
                snapshot_id: changed_intent.environment_snapshot_id.clone(),
                policy_digest: changed_intent.environment_policy_digest.clone(),
            },
        );
        assert!(
            restarted_pool
                .submit_or_poll(&mut store, 1, &changed_intent, changed_request, None, 4)
                .is_err()
        );
        assert_eq!(marker_count(&marker), 1);
    }

    #[test]
    fn dropping_pool_is_bounded_and_running_worker_keeps_worktree_lease() {
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
        let lease = lease_for(&manager, &state_root, &repository_id, 1);
        let lease_target = lease.worktree().clone();
        let mut store = crate::store::host_jobs::in_memory_test_store();
        let mut pool = HostJobPool::new(1, 1).unwrap();
        let job = intent(
            "drop-keeps-lease",
            "project-1",
            &lease_target.path.display().to_string(),
        );
        let release_file = temp.path().join("release-worker");
        let mut process_request = request();
        process_request.environment.insert(
            OsString::from("REX_HOST_JOB_RELEASE_FILE"),
            release_file.as_os_str().to_owned(),
        );
        assert_eq!(
            pool.submit_or_poll(&mut store, 1, &job, process_request, Some(lease), 1)
                .unwrap(),
            HostJobProgress::Running
        );

        let drop_started = Instant::now();
        drop(pool);
        assert!(drop_started.elapsed() < Duration::from_millis(200));
        assert!(manager.acquire_writer_lease(lease_target.clone()).is_err());
        std::fs::write(&release_file, "release").unwrap();

        let began = Instant::now();
        loop {
            if manager.acquire_writer_lease(lease_target.clone()).is_ok() {
                break;
            }
            assert!(began.elapsed() < Duration::from_secs(3));
            thread::sleep(Duration::from_millis(10));
        }
        assert!(matches!(
            store.host_job(&job.job_id).unwrap().unwrap().state,
            HostJobState::Starting | HostJobState::Running
        ));
    }

    #[test]
    fn cleanup_unconfirmed_process_result_is_not_exposed_to_effect_consumers() {
        let mut store = crate::store::host_jobs::in_memory_test_store();
        let mut job = intent("unclean-process", "project-1", "operation-1");
        job.kind = HostJobKind::OperationAdapter;
        job.operation_method = Some(crate::store::host_jobs::OperationMethod::Invoke);
        job.max_attempts = 1;
        job.retry_when_absent = false;
        job.lane_id = "operation-1".into();
        job.effect_operation_id = "operation-1:invoke:1".into();
        store.enqueue_host_job(1, &job, 10).unwrap();
        store.start_host_job(1, &job.job_id, 11).unwrap();
        let identity = ProcessIdentity {
            pid: u32::MAX,
            parent_pid: 1,
            process_group_id: u32::MAX,
            start_identity: "nonexistent-kernel-birth-token".into(),
            command: "fixture".into(),
            quality: process::ProcessIdentityQuality::KernelBirthToken,
        };
        let mut pool = HostJobPool::new(1, 1).unwrap();
        pool.sender
            .send(WorkerEvent::Started {
                job_id: job.job_id.clone(),
                identity: identity.clone(),
            })
            .unwrap();
        pool.sender
            .send(WorkerEvent::Finished {
                job_id: job.job_id.clone(),
                intent: Box::new(job.clone()),
                identity: Some(identity),
                result: Ok(HostProcessReceipt {
                    status_code: Some(0),
                    stdout: b"untrusted result".to_vec(),
                    stderr_tail: Vec::new(),
                    stdout_truncated: false,
                    stderr_truncated: false,
                    timed_out: false,
                    cleanup_confirmed: false,
                }),
            })
            .unwrap();

        pool.poll(&mut store, 1, 12).unwrap();

        assert!(!pool.completed.contains_key(&job.job_id));
        assert!(matches!(
            store.host_job(&job.job_id).unwrap().unwrap().state,
            HostJobState::Unknown { .. }
        ));
        assert!(
            store
                .host_job(&job.job_id)
                .unwrap()
                .unwrap()
                .process_receipt
                .is_none()
        );
    }
}
