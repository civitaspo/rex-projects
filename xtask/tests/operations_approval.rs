use std::collections::BTreeMap;
#[cfg(target_os = "linux")]
use std::io::Read;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
#[path = "../../tests/support/linux_process_snapshot.rs"]
mod linux_process_snapshot;

use rex_projects::config::{
    AppliedConfig, Config, OperationActionConfig, OperationRecipe, OperationTarget,
    RepositoryOperationsConfig, SuccessPredicate,
};
use rex_projects::domain::ids::{
    Digest, HumanRequestId, ProjectId, RepositoryId, Revision, TicketId, TicketNamespace,
    TicketRunId,
};
use rex_projects::domain::types::{ApprovalMode, OperationSource};
use rex_projects::effects::{
    EffectContext, EffectHandler, EffectMode, EffectObservation, EffectRequest,
};
use rex_projects::human_runtime::{
    DurableHumanSubjectObserver, HumanDecisionChoice, HumanDecisionIntent,
    HumanPresenterEffectHandler, HumanPurpose, HumanSubjectKind, HumanSubjectObserver,
    process_queued_human_responses,
};
use rex_projects::launch::{RexView, RexViewKind};
use rex_projects::operations::{DeliveryFacts, validate_recipe};
use rex_projects::operations_runtime::{OperationEffectHandler, OperationExecutionMode};
use rex_projects::store::host_jobs::{HostJobState, OperationMethod};
use rex_projects::store::operations::DurableOperationState;
use rex_projects::store::{ConfigStore, ExpectedRevision, OwnerMetadata, ProjectRecord};

const SOURCE_SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const PROCESS_START_DIAGNOSTIC_DIR_ENV: &str = "REX_PROCESS_START_DIAGNOSTIC_DIR";

fn is_xtask_comm(comm: &[u8]) -> bool {
    comm.strip_suffix(b"\n").unwrap_or(comm) == b"xtask"
}

#[test]
fn xtask_comm_matches_linux_comm_bytes() {
    assert!(is_xtask_comm(b"xtask\n"));
    assert!(is_xtask_comm(b"xtask"));
    assert!(!is_xtask_comm(b"other\n"));
    assert!(!is_xtask_comm(b"xtask\nother"));
}

struct XdgStateHomeGuard(Option<std::ffi::OsString>);

impl XdgStateHomeGuard {
    fn set(path: &std::path::Path) -> Self {
        let prior = std::env::var_os("XDG_STATE_HOME");
        unsafe { std::env::set_var("XDG_STATE_HOME", path) };
        Self(prior)
    }
}

impl Drop for XdgStateHomeGuard {
    fn drop(&mut self) {
        match self.0.take() {
            Some(previous) => unsafe { std::env::set_var("XDG_STATE_HOME", previous) },
            None => unsafe { std::env::remove_var("XDG_STATE_HOME") },
        }
    }
}

struct ProcessStartDiagnosticDirGuard(Option<std::ffi::OsString>);

impl ProcessStartDiagnosticDirGuard {
    fn set(path: &std::path::Path) -> Self {
        let prior = std::env::var_os(PROCESS_START_DIAGNOSTIC_DIR_ENV);
        unsafe { std::env::set_var(PROCESS_START_DIAGNOSTIC_DIR_ENV, path) };
        Self(prior)
    }
}

impl Drop for ProcessStartDiagnosticDirGuard {
    fn drop(&mut self) {
        match self.0.take() {
            Some(previous) => unsafe {
                std::env::set_var(PROCESS_START_DIAGNOSTIC_DIR_ENV, previous)
            },
            None => unsafe { std::env::remove_var(PROCESS_START_DIAGNOSTIC_DIR_ENV) },
        }
    }
}

fn process_start_phase_markers(
    directory: &std::path::Path,
    caller_pid: u32,
    child_root_pid: u32,
) -> Vec<(String, String)> {
    use std::io::Read;

    let prefix = format!("{caller_pid}-{child_root_pid}-");
    let mut markers = std::fs::read_dir(directory)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name().into_string().ok()?;
            let stage = name.strip_prefix(&prefix)?.strip_suffix(".marker")?;
            let mut contents = Vec::new();
            std::fs::File::open(entry.path())
                .ok()?
                .take(128)
                .read_to_end(&mut contents)
                .ok()?;
            Some((
                stage.to_owned(),
                String::from_utf8_lossy(&contents).trim().to_owned(),
            ))
        })
        .collect::<Vec<_>>();
    markers.sort_by(|left, right| left.0.cmp(&right.0));
    markers
}

#[cfg(target_os = "linux")]
fn process_start_phase_summary(
    directory: &std::path::Path,
    caller_pid: u32,
    identities: &[(u32, String)],
) -> String {
    identities
        .iter()
        .map(|(child_root_pid, _)| {
            let markers = process_start_phase_markers(directory, caller_pid, *child_root_pid)
                .into_iter()
                .map(|(_, contents)| contents)
                .collect::<Vec<_>>()
                .join(";");
            format!("child_root_pid={child_root_pid},markers=[{markers}]")
        })
        .collect::<Vec<_>>()
        .join(";")
}

#[test]
fn queued_human_approval_gates_operation_fixture_invoke_and_reconcile() {
    let temp = tempfile::tempdir().expect("temporary operation state");
    let isolated_xdg = temp.path().join("xdg-state");
    let _xdg_state_home = XdgStateHomeGuard::set(&isolated_xdg);
    let process_start_diagnostic_dir = temp.path().join("process-start-diagnostics");
    std::fs::create_dir_all(&process_start_diagnostic_dir).unwrap();
    let _process_start_diagnostic_dir =
        ProcessStartDiagnosticDirGuard::set(&process_start_diagnostic_dir);
    let fixture_state = temp.path().join("fixture-state");
    let mut config: Config = toml::from_str(include_str!("../../examples/fixture/config.toml"))
        .expect("public fixture configuration parses");
    config.operation_actions.insert(
        "fixture_lost_reply".into(),
        OperationActionConfig::Command {
            command: vec![
                env!("CARGO_BIN_EXE_xtask").into(),
                "fixture".into(),
                "operations".into(),
                "--state-dir".into(),
                fixture_state.display().to_string(),
            ],
        },
    );
    let repository_id = RepositoryId::parse("example").unwrap();
    config
        .repositories
        .get_mut(&repository_id)
        .expect("fixture repository")
        .operations = Some(RepositoryOperationsConfig {
        recipe: "rollout".into(),
        allowed_actions: vec!["fixture_lost_reply".into()],
        human_approval_environments: vec![],
        instruction_files: vec![],
    });
    config.operation_recipes.insert(
        "rollout".into(),
        OperationRecipe {
            roles: BTreeMap::new(),
            required_stages: vec![],
            required_evidence: vec![],
            targets: vec![OperationTarget {
                id: "deploy_fixture".into(),
                repository: repository_id.clone(),
                environment: "test".into(),
                action: "fixture_lost_reply".into(),
                depends_on: vec![],
                source: OperationSource::parse("merge_commit").unwrap(),
                selector: BTreeMap::new(),
                success_predicate: SuccessPredicate::TargetSucceeded,
                timeout_seconds: 20,
                approval: ApprovalMode::Always,
            }],
            not_required_reason: None,
        },
    );
    let applied = AppliedConfig {
        config,
        profiles: BTreeMap::new(),
        source_root: "/fixture".into(),
        source_files: vec![],
        digest: Digest::parse("a".repeat(64)).unwrap(),
    };

    let state_root = temp.path().join("controller-state");
    let mut store = ConfigStore::open(&state_root).expect("open isolated state store");
    let project_id = ProjectId::parse("operations_project").unwrap();
    let ticket_id = TicketId::parse("PAY-approval").unwrap();
    let ticket_run_id = TicketRunId::parse("approval-run").unwrap();
    let ticket_namespace = TicketNamespace::parse("github:org/repo").unwrap();
    let config_revision = store
        .apply_snapshot("factory", &applied, ExpectedRevision::Bootstrap)
        .unwrap();
    store
        .insert_project(&ProjectRecord {
            id: project_id.clone(),
            config_source: "factory".into(),
            config_revision: config_revision.revision,
            config_digest: config_revision.digest.clone(),
            mode: "operations".into(),
            goal_revision: 0,
            desired_lifecycle: "running".into(),
            state_revision: Revision(0),
        })
        .unwrap();
    let owner = OwnerMetadata {
        owner_nonce: "approval-owner".into(),
        state_root: temp.path().to_string_lossy().into_owned(),
        config_source: "factory".into(),
        process_start_identity: "approval-owner".into(),
        executable_path: "/tmp/rex-projects-fixture".into(),
        executable_digest: "b".repeat(64),
        rex_endpoint: None,
        rex_server_identity: None,
        rex_session_id: None,
        rex_block_id: None,
    };
    let generation = store.start_owner(&owner).unwrap();
    store
        .create_ticket_run(
            generation,
            &project_id,
            &ticket_namespace,
            &ticket_id,
            &ticket_run_id,
            1,
            "operating",
            "In Progress",
        )
        .unwrap();
    let rex_view = RexView {
        view_id: RexView::derive_id(
            &project_id,
            RexViewKind::Ticket,
            Some(ticket_namespace.as_str()),
            Some(ticket_id.as_str()),
            1,
        )
        .unwrap(),
        project_id: project_id.clone(),
        kind: RexViewKind::Ticket,
        ticket_namespace: Some(ticket_namespace.to_string()),
        ticket_id: Some(ticket_id.to_string()),
        view_epoch: 1,
        rex_server_identity: "fixture-server".into(),
        rex_session_id: "fixture-session".into(),
        rex_window_id: "ticket-window".into(),
    };
    store.register_rex_view(generation, &rex_view).unwrap();

    let plan = validate_recipe(&applied.config, "rollout").unwrap();
    let target = &plan.targets()[0];
    let delivery = DeliveryFacts {
        merge_commits: BTreeMap::from([(target.repository.clone(), SOURCE_SHA.into())]),
        planned_revisions: BTreeMap::new(),
    };
    let operation_id = store
        .operations()
        .unwrap()
        .persist_plan(
            generation,
            &project_id,
            &ticket_id,
            &ticket_run_id,
            Revision(0),
            config_revision.revision,
            &applied,
            &plan,
            &delivery,
            100,
        )
        .unwrap()[0]
        .clone();
    let intent = store
        .operation_approval_intent(&operation_id)
        .unwrap()
        .expect("approval-required operation has a typed human review request");
    let approval_id = HumanRequestId::parse(intent.approval_request_id.unwrap()).unwrap();
    let host_jobs = Arc::new(Mutex::new(
        rex_projects::host_jobs::HostJobPool::new(4, 1).unwrap(),
    ));
    let host_environment = [
        (
            std::ffi::OsString::from("PATH"),
            std::env::var_os("PATH").unwrap(),
        ),
        (
            std::ffi::OsString::from("XDG_STATE_HOME"),
            isolated_xdg.as_os_str().to_owned(),
        ),
    ]
    .into_iter()
    .collect();
    let operation_handler = OperationEffectHandler::with_host_jobs(
        [applied.clone()],
        Duration::from_secs(2),
        Arc::clone(&host_jobs),
        host_environment,
        Digest::parse("c".repeat(64)).unwrap(),
    )
    .unwrap();

    let operation_claim = store
        .claim_next_due_effect(generation, 100, &["operation".into()])
        .unwrap()
        .expect("operation remains durably queued");
    let operation_effect = EffectRequest::from(operation_claim);
    let before_approval = {
        let mut context = EffectContext {
            store: &mut store,
            owner_generation: generation,
            now_unix: 100,
        };
        EffectHandler::handle(
            &operation_handler,
            EffectMode::Submit,
            &operation_effect,
            &mut context,
        )
        .unwrap()
    };
    assert!(matches!(before_approval, EffectObservation::Pending { .. }));
    assert!(
        !fixture_state.exists(),
        "approval must precede external invocation"
    );

    let human_claim = store
        .claim_next_due_effect(generation, 100, &["request_human_review".into()])
        .unwrap()
        .expect("plan enqueues the typed human review effect");
    let human_effect = EffectRequest::from(human_claim);
    let artifact_root = temp.path().join("human-artifacts");
    std::fs::create_dir_all(&artifact_root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&artifact_root, std::fs::Permissions::from_mode(0o700))
            .expect("private human artifact directory");
    }
    let observer = Arc::new(
        DurableHumanSubjectObserver::new(temp.path().join("declarative-config"))
            .expect("durable operation observer"),
    );
    let presenter = HumanPresenterEffectHandler::new(
        "local_html",
        vec!["/usr/bin/true".into()],
        BTreeMap::new(),
        artifact_root,
        observer.clone(),
    )
    .unwrap();
    let presented = {
        let mut context = EffectContext {
            store: &mut store,
            owner_generation: generation,
            now_unix: 100,
        };
        presenter
            .handle(EffectMode::Submit, &human_effect, &mut context)
            .unwrap()
    };
    assert!(matches!(presented, EffectObservation::Pending { .. }));
    let request = store
        .current_human_request(&approval_id)
        .unwrap()
        .expect("presenter registered request in durable inbox")
        .request;
    assert_eq!(request.purpose, HumanPurpose::OperationApproval);
    assert_eq!(request.subject.kind, HumanSubjectKind::Operation);
    assert_eq!(request.subject.ticket_run_id.as_ref(), Some(&ticket_run_id));

    let decision = HumanDecisionIntent {
        request_id: approval_id.clone(),
        response_id: "operation-approval-response".into(),
        expected_subject_digest: request.subject.digest().unwrap(),
        choice: HumanDecisionChoice::Approve,
        explanation: Some("Approve this exact fixture operation.".into()),
    };
    ConfigStore::enqueue_human_decision(&state_root, &decision, 101).unwrap();
    let processed =
        process_queued_human_responses(&mut store, generation, 10, 102, |store, request| {
            observer.observe_current_subject(store, request)
        })
        .unwrap();
    assert_eq!(processed.len(), 1);
    assert!(matches!(
        processed[0].result,
        rex_projects::store::human::HumanDecisionResult::Applied
    ));

    let fixture_receipt = fixture_state.join(format!("{operation_id}.json"));
    let invoke_job =
        rex_projects::host_jobs::stable_host_job_id(operation_id.as_str(), "operation.invoke", 1);
    let invoke_deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let mut context = EffectContext {
            store: &mut store,
            owner_generation: generation,
            now_unix: 103,
        };
        let outcome = EffectHandler::handle(
            &operation_handler,
            EffectMode::Submit,
            &operation_effect,
            &mut context,
        )
        .unwrap();
        assert!(matches!(outcome, EffectObservation::Pending { .. }));
        if fixture_receipt.exists()
            && store
                .operations()
                .unwrap()
                .operation(&operation_id)
                .unwrap()
                .unwrap()
                .state
                == DurableOperationState::Unknown
        {
            break;
        }
        if Instant::now() >= invoke_deadline {
            let operation = store
                .operations()
                .unwrap()
                .operation(&operation_id)
                .unwrap()
                .expect("durable operation remains present");
            let invoke_job_diagnostic = store
                .host_job(&invoke_job)
                .unwrap()
                .map(|job| {
                    let state = match job.state {
                        HostJobState::Pending => "pending",
                        HostJobState::Starting => "starting",
                        HostJobState::Running => "running",
                        HostJobState::Unknown { .. } => "unknown",
                        HostJobState::Succeeded => "succeeded",
                        HostJobState::Failed => "failed",
                    };
                    let safe_receipt = job
                        .receipt_json
                        .as_deref()
                        .and_then(|receipt| serde_json::from_str::<serde_json::Value>(receipt).ok())
                        .map(|receipt| {
                            format!(
                                "status_code={:?}, timed_out={:?}, cleanup_confirmed={:?}, stdout_truncated={:?}, stderr_truncated={:?}",
                                receipt.get("status_code").and_then(serde_json::Value::as_i64),
                                receipt.get("timed_out").and_then(serde_json::Value::as_bool),
                                receipt.get("cleanup_confirmed").and_then(serde_json::Value::as_bool),
                                receipt.get("stdout_truncated").and_then(serde_json::Value::as_bool),
                                receipt.get("stderr_truncated").and_then(serde_json::Value::as_bool),
                            )
                        })
                        .unwrap_or_else(|| "none".into());
                    format!(
                        "state={state}, attempt_count={}, safe_receipt=({safe_receipt})",
                        job.attempt_count
                    )
                })
                .unwrap_or_else(|| "missing".into());
            #[cfg(target_os = "linux")]
            let fixture_processes = linux_fixture_process_diagnostic(
                std::path::Path::new(env!("CARGO_BIN_EXE_xtask")),
                &fixture_state,
            );
            #[cfg(not(target_os = "linux"))]
            let fixture_processes = FixtureProcesses {
                diagnostic: "not_applicable".into(),
            };
            let fixture_process_diagnostic = fixture_processes.diagnostic;
            #[cfg(target_os = "linux")]
            let fixture_start_phase_diagnostic = process_start_phase_summary(
                &process_start_diagnostic_dir,
                std::process::id(),
                &fixture_processes.identities,
            );
            #[cfg(not(target_os = "linux"))]
            let fixture_start_phase_diagnostic = "not_applicable".to_owned();
            #[cfg(target_os = "linux")]
            let owner_thread_diagnostic = linux_process_snapshot::snapshot_with_thread_limit(
                std::process::id(),
                None,
                None,
                false,
                7,
            );
            #[cfg(not(target_os = "linux"))]
            let owner_thread_diagnostic = "not_applicable".to_owned();
            #[cfg(target_os = "linux")]
            let fixture_thread_diagnostic = fixture_processes
                .identities
                .into_iter()
                .take(1)
                .map(|(pid, birth)| {
                    linux_process_snapshot::snapshot_with_thread_limit(
                        pid,
                        Some(&birth),
                        Some(std::process::id()),
                        false,
                        1,
                    )
                })
                .collect::<Vec<_>>()
                .join(";");
            #[cfg(not(target_os = "linux"))]
            let fixture_thread_diagnostic = "not_applicable".to_owned();
            panic!(
                "pooled invoke did not settle: fixture_receipt_exists={}, operation_state={:?}, operation_external_reference_present={}, operation_terminal_receipt_present={}, invoke_host_job={invoke_job_diagnostic}, fixture_process={fixture_process_diagnostic}, fixture_start_phases={fixture_start_phase_diagnostic}, owner_threads={owner_thread_diagnostic}, fixture_threads={fixture_thread_diagnostic}",
                fixture_receipt.exists(),
                operation.state,
                operation.external_reference.is_some(),
                operation.terminal_receipt_json.is_some(),
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        fixture_receipt.exists(),
        "approved operation reached fixture adapter"
    );
    assert_eq!(
        store
            .operations()
            .unwrap()
            .operation(&operation_id)
            .unwrap()
            .unwrap()
            .state,
        DurableOperationState::Unknown,
        "lost invoke response must remain uncertain until exact reconciliation"
    );

    let reconcile_deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let mut context = EffectContext {
            store: &mut store,
            owner_generation: generation,
            now_unix: 104,
        };
        let reconciled = operation_handler
            .handle(
                OperationExecutionMode::Reconcile,
                &operation_effect.intent,
                operation_effect.attempt_count,
                &mut context,
            )
            .unwrap();
        if matches!(
            reconciled,
            rex_projects::operations_runtime::OperationExecutionOutcome::Applied { .. }
        ) {
            break;
        }
        assert!(
            matches!(
                reconciled,
                rex_projects::operations_runtime::OperationExecutionOutcome::Pending { .. }
            ),
            "reconciliation returned: {reconciled:?}"
        );
        assert!(
            Instant::now() < reconcile_deadline,
            "pooled reconciliation did not settle"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        store
            .operations()
            .unwrap()
            .operation(&operation_id)
            .unwrap()
            .unwrap()
            .state,
        DurableOperationState::Succeeded
    );
    let fixture_json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(fixture_receipt).unwrap()).unwrap();
    assert_eq!(
        fixture_json["external_reference"],
        format!("fixture-run:{operation_id}")
    );
    let operation_jobs = [
        (invoke_job, OperationMethod::Invoke),
        (
            rex_projects::host_jobs::stable_host_job_id(operation_id.as_str(), "operation.find", 1),
            OperationMethod::Find,
        ),
        (
            rex_projects::host_jobs::stable_host_job_id(
                operation_id.as_str(),
                "operation.observe",
                1,
            ),
            OperationMethod::Observe,
        ),
    ];
    let mut child_root_pids = Vec::new();
    for (job_id, method) in operation_jobs {
        let job = store
            .host_job(&job_id)
            .unwrap()
            .expect("pooled host job persisted");
        assert_eq!(job.intent.operation_method, Some(method));
        assert!(matches!(
            job.state,
            HostJobState::Succeeded | HostJobState::Failed
        ));
        let child_root_pid = job
            .process_identity
            .as_ref()
            .expect("completed host job records the child identity")
            .pid;
        child_root_pids.push(child_root_pid);
        let markers = process_start_phase_markers(
            &process_start_diagnostic_dir,
            std::process::id(),
            child_root_pid,
        );
        assert_eq!(
            markers
                .iter()
                .map(|(stage, _)| stage.as_str())
                .collect::<Vec<_>>(),
            [
                "initial_capture_after",
                "initial_capture_before",
                "initial_inspect_after",
                "initial_inspect_before",
                "input_writer_start",
                "on_started_after",
                "on_started_before",
            ],
            "host job {job_id} should leave one marker for each startup phase"
        );
        for (stage, contents) in markers {
            assert!(contents.contains(&format!("caller_pid={},", std::process::id())));
            assert!(contents.contains(&format!("child_root_pid={child_root_pid},")));
            assert!(contents.contains(&format!("stage={stage},")));
        }
    }
    child_root_pids.sort_unstable();
    child_root_pids.dedup();
    assert_eq!(
        child_root_pids.len(),
        3,
        "each operation job uses a distinct process"
    );
}

struct FixtureProcesses {
    diagnostic: String,
    #[cfg(target_os = "linux")]
    identities: Vec<(u32, String)>,
}

#[cfg(target_os = "linux")]
fn linux_fixture_process_diagnostic(
    executable: &std::path::Path,
    state_dir: &std::path::Path,
) -> FixtureProcesses {
    use std::os::unix::ffi::OsStrExt;
    use std::time::Duration;

    const MAX_ENTRIES: usize = 8192;
    const MAX_FIXTURE_MATCHES: usize = 4;
    const SCAN_BUDGET: Duration = Duration::from_secs(1);

    let started = Instant::now();
    let expected_executable = std::fs::canonicalize(executable).ok();
    let expected_state_dir = state_dir.as_os_str().as_bytes();
    let entries = match std::fs::read_dir("/proc") {
        Ok(entries) => entries,
        Err(_) => {
            return FixtureProcesses {
                diagnostic: "proc_scan_error".into(),
                identities: Vec::new(),
            };
        }
    };
    let mut numeric_entries = 0;
    let mut proc_read_errors = 0;
    let mut matched = Vec::new();
    let mut identities = Vec::new();
    let mut truncated = false;
    let mut matches_truncated = false;

    for entry in entries {
        if numeric_entries >= MAX_ENTRIES || started.elapsed() >= SCAN_BUDGET {
            truncated = true;
            break;
        }
        let Ok(entry) = entry else {
            proc_read_errors += 1;
            continue;
        };
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        numeric_entries += 1;

        let process_dir = entry.path();
        let comm = match read_proc_bytes(&process_dir.join("comm"), 64) {
            Ok(comm) => comm,
            Err(_) => {
                proc_read_errors += 1;
                continue;
            }
        };
        if !is_xtask_comm(&comm) {
            continue;
        }
        let executable_matches = std::fs::read_link(process_dir.join("exe"))
            .ok()
            .zip(expected_executable.as_ref())
            .is_some_and(|(actual, expected)| actual == *expected);
        if !executable_matches {
            continue;
        }
        let command_line = match read_proc_bytes(&process_dir.join("cmdline"), 4096) {
            Ok(command_line) => command_line,
            Err(_) => {
                proc_read_errors += 1;
                continue;
            }
        };
        if !command_line
            .split(|byte| *byte == 0)
            .any(|argument| argument == expected_state_dir)
        {
            continue;
        }
        if let Ok(Some(identity)) = rex_projects::process::process_identity_for_pid(pid) {
            if matched.len() < MAX_FIXTURE_MATCHES {
                matched.push(format!("pid={pid},birth={}", identity.start_identity));
                identities.push((pid, identity.start_identity));
            } else {
                matches_truncated = true;
            }
        }
    }

    FixtureProcesses {
        diagnostic: format!(
            "proc_numeric_entries={}, matches=[{}], matches_truncated={matches_truncated}, scan_elapsed_ms={}, truncated={}, proc_read_errors={proc_read_errors}",
            numeric_entries,
            matched.join(";"),
            started.elapsed().as_millis(),
            truncated,
        ),
        identities,
    }
}

#[cfg(target_os = "linux")]
fn read_proc_bytes(path: &std::path::Path, limit: u64) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(limit)
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}
