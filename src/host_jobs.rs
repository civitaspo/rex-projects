use std::collections::HashMap;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};

use serde::{Deserialize, Serialize};

use crate::process::{self, ProcessError, ProcessIdentity, ProcessRequest};
use crate::store::ConfigStore;
use crate::store::host_jobs::{HostJobIntent, HostJobRecord, HostJobState};
use crate::worktrees::WorktreeLease;

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
    ProcessCompleted(HostProcessReceipt),
    ProcessFailed(String),
    Succeeded(String),
    Failed(String),
}

struct ActiveJob {
    worktree_id: String,
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
    sender: Sender<WorkerEvent>,
    receiver: Receiver<WorkerEvent>,
    active: HashMap<String, ActiveJob>,
    completed: HashMap<String, Result<HostProcessReceipt, String>>,
}

impl HostJobPool {
    pub fn new(max_jobs: usize) -> Result<Self, String> {
        if max_jobs == 0 {
            return Err("host job capacity must be positive".into());
        }
        let (sender, receiver) = mpsc::channel();
        Ok(Self {
            max_jobs,
            sender,
            receiver,
            active: HashMap::new(),
            completed: HashMap::new(),
        })
    }

    pub fn submit_or_poll(
        &mut self,
        store: &mut ConfigStore,
        intent: &HostJobIntent,
        process_request: ProcessRequest,
        worktree_lease: Option<WorktreeLease>,
        now_unix: i64,
    ) -> Result<HostJobProgress, String> {
        self.drain_events(store, now_unix)?;
        let mut record = store.enqueue_host_job(intent, now_unix)?;
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
                    store.mark_host_job_unknown(&intent.job_id, &reason, now_unix)?;
                    return Ok(HostJobProgress::Unknown);
                }
                Recovery::Absent => {
                    if store.retry_absent_host_job(&intent.job_id, now_unix)? {
                        record = store.host_job(&intent.job_id)?.expect("job just read");
                    } else {
                        store.mark_host_job_unknown(
                            &intent.job_id,
                            "process absence is established but the immutable retry budget forbids another run",
                            now_unix,
                        )?;
                        return Ok(HostJobProgress::Unknown);
                    }
                }
                Recovery::NoIdentity => return Ok(HostJobProgress::Unknown),
            }
        }
        if !self.active.contains_key(&intent.job_id) {
            if matches!(record.state, HostJobState::Starting) {
                store.mark_host_job_unknown(
                    &intent.job_id,
                    "controller restarted before the process identity was recorded",
                    now_unix,
                )?;
                self.active.insert(
                    intent.job_id.clone(),
                    ActiveJob {
                        worktree_id: intent.worktree_id.clone(),
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
                            &intent.job_id,
                            "the exact process identity is still present after controller restart",
                            now_unix,
                        )?;
                        self.active.insert(
                            intent.job_id.clone(),
                            ActiveJob {
                                worktree_id: intent.worktree_id.clone(),
                                worker: None,
                                recovered: true,
                                _worktree_lease: worktree_lease,
                            },
                        );
                        return Ok(HostJobProgress::Unknown);
                    }
                    Recovery::Unverifiable(reason) => {
                        store.mark_host_job_unknown(&intent.job_id, &reason, now_unix)?;
                        self.active.insert(
                            intent.job_id.clone(),
                            ActiveJob {
                                worktree_id: intent.worktree_id.clone(),
                                worker: None,
                                recovered: true,
                                _worktree_lease: worktree_lease,
                            },
                        );
                        return Ok(HostJobProgress::Unknown);
                    }
                    Recovery::Absent => {
                        if store.retry_absent_host_job(&intent.job_id, now_unix)? {
                            record = store.host_job(&intent.job_id)?.expect("job just read");
                        } else {
                            store.mark_host_job_unknown(
                                &intent.job_id,
                                "process absence is established but the immutable retry budget forbids another run",
                                now_unix,
                            )?;
                            self.active.insert(
                                intent.job_id.clone(),
                                ActiveJob {
                                    worktree_id: intent.worktree_id.clone(),
                                    worker: None,
                                    recovered: true,
                                    _worktree_lease: worktree_lease,
                                },
                            );
                            return Ok(HostJobProgress::Unknown);
                        }
                    }
                    Recovery::NoIdentity => {
                        store.mark_host_job_unknown(
                            &intent.job_id,
                            "no exact process identity is available for restart reconciliation",
                            now_unix,
                        )?;
                        self.active.insert(
                            intent.job_id.clone(),
                            ActiveJob {
                                worktree_id: intent.worktree_id.clone(),
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
            .or(worktree_lease)
            .ok_or_else(|| "host job requires an exclusive worktree lease".to_owned())?;
        if !store.start_host_job(&intent.job_id, now_unix)? {
            return Ok(HostJobProgress::Pending);
        }
        if let Err(error) = self.start_worker(intent, process_request, lease) {
            if !store.revert_host_job_start(&intent.job_id, now_unix)? {
                return Err("failed worker creation left an unreconciled host job".into());
            }
            return Err(error);
        }
        Ok(HostJobProgress::Running)
    }

    pub fn holds_worktree_lease(&self, job_id: &str) -> bool {
        self.active
            .get(job_id)
            .is_some_and(|active| active._worktree_lease.is_some())
    }

    pub fn holds_worktree_lease_for(&self, worktree_id: &str) -> bool {
        self.active
            .values()
            .any(|active| active.worktree_id == worktree_id && active._worktree_lease.is_some())
    }

    /// Drain worker reports on the controller thread. Call once per controller tick.
    pub fn poll(&mut self, store: &mut ConfigStore, now_unix: i64) -> Result<(), String> {
        self.drain_events(store, now_unix)
    }

    fn slot_available(&self, store: &ConfigStore, intent: &HostJobIntent) -> Result<bool, String> {
        if self.active.iter().any(|(job_id, active)| {
            job_id != &intent.job_id && active.worktree_id == intent.worktree_id
        }) {
            return Ok(false);
        }
        let occupied = store.host_jobs_in_states(&[
            HostJobState::Starting,
            HostJobState::Running,
            HostJobState::Unknown {
                reason: String::new(),
            },
        ])?;
        Ok(occupied.len() < self.max_jobs
            && !occupied
                .iter()
                .any(|job| job.intent.worktree_id == intent.worktree_id))
    }

    fn start_worker(
        &mut self,
        intent: &HostJobIntent,
        request: ProcessRequest,
        worktree_lease: WorktreeLease,
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
                worktree_id: intent.worktree_id.clone(),
                worker: Some(worker),
                recovered: false,
                _worktree_lease: Some(worktree_lease),
            },
        );
        Ok(())
    }

    fn drain_events(&mut self, store: &mut ConfigStore, now_unix: i64) -> Result<(), String> {
        while let Ok(event) = self.receiver.try_recv() {
            match event {
                WorkerEvent::Started { job_id, identity } => {
                    if !store.mark_host_job_running(&job_id, &identity, now_unix)? {
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
                    if let Err(error) = store.mark_host_job_unknown(&job_id, &reason, now_unix) {
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
        job_id: &str,
        succeeded: bool,
        receipt_json: &str,
        now_unix: i64,
    ) -> Result<(), String> {
        if !store.finish_host_job(job_id, succeeded, receipt_json, now_unix)? {
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
        if let Some(mut active) = self.active.remove(job_id) {
            if let Some(worker) = active.worker.take() {
                if worker.is_finished() {
                    let _ = worker.join();
                } else {
                    drop(worker);
                }
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
            worktree_id: worktree.into(),
            kind: "repository_hook".into(),
            request_digest: format!("request:{job_id}"),
            configuration_digest: "config".into(),
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
                executable: PathBuf::from("/run/current-system/sw/bin/git"),
                environment: Default::default(),
                timeout: Duration::from_secs(2),
            },
        )
        .unwrap();
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
        let mut pool = HostJobPool::new(2).unwrap();
        let began = Instant::now();
        assert_eq!(
            pool.submit_or_poll(
                &mut store,
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
                &second,
                request(),
                Some(lease_for(&manager, &state_root, &repository_id, 2)),
                1
            )
            .unwrap(),
            HostJobProgress::Running
        );
        assert_eq!(
            pool.submit_or_poll(&mut store, &same_worktree_waiter, request(), None, 1)
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
            pool.poll(&mut store, 2).unwrap();
            for job in [&first, &second] {
                if completed.contains_key(&job.job_id) {
                    continue;
                }
                match pool
                    .submit_or_poll(&mut store, job, request(), None, 2)
                    .unwrap()
                {
                    HostJobProgress::ProcessCompleted(receipt) => {
                        assert_eq!(receipt.status_code, Some(0));
                        let receipt_json = serde_json::to_string(&receipt).unwrap();
                        pool.finish(&mut store, &job.job_id, true, &receipt_json, 2)
                            .unwrap();
                        completed.insert(job.job_id.clone(), receipt);
                    }
                    HostJobProgress::Running | HostJobProgress::Pending => {}
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
}
