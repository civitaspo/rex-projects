use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use rex_projects::adapters::rex::{AgentBlockSpec, CreateDisposition, RexCliTransport};
use rex_projects::process::inspect_process_table;

/// Runs only against a disposable Rex instance when the caller supplies every
/// identity explicitly. The test creates and then closes only its own blocks.
#[test]
#[ignore = "requires a disposable Rex endpoint; see PR3a live adapter verification"]
fn live_rex_ticket_window_and_block_lifecycle() {
    let endpoint = std::env::var("REX_PROJECTS_TEST_ENDPOINT").unwrap();
    let instance = std::env::var("REX_PROJECTS_TEST_INSTANCE_ID").unwrap();
    let session = std::env::var("REX_PROJECTS_TEST_SESSION_ID").unwrap();
    let rex = PathBuf::from(std::env::var("REX_PROJECTS_TEST_REX_CLI").unwrap());
    let ticket_id = std::env::var("REX_PROJECTS_TEST_TICKET_ID").unwrap();
    let temp = tempfile::tempdir().unwrap();
    let transport =
        RexCliTransport::connect(&rex, &[], endpoint, instance, session, BTreeMap::new()).unwrap();
    let worker = AgentBlockSpec {
        run_id: format!("{ticket_id}-worker"),
        command: PathBuf::from("/bin/sleep"),
        args: vec!["30".into()],
        cwd: temp.path().to_path_buf(),
        path_prepend: vec![],
    };
    let reviewer = AgentBlockSpec {
        run_id: format!("{ticket_id}-reviewer"),
        ..worker.clone()
    };

    let window = transport
        .find_or_create_ticket_window("rex-projects-live-test", &ticket_id, &worker)
        .unwrap();
    assert_eq!(window.disposition, CreateDisposition::Created);
    let reused = transport
        .find_or_create_ticket_window("rex-projects-live-test", &ticket_id, &worker)
        .unwrap();
    assert_eq!(reused.window_id, window.window_id);
    assert_eq!(reused.disposition, CreateDisposition::Existing);
    let worker_block = window.initial_block_id.clone().unwrap();
    let reviewer_block = transport
        .create_agent_block(&window, &worker_block, &reviewer)
        .unwrap();
    transport.focus_block(&reviewer_block).unwrap();
    transport.zoom_block(&reviewer_block, true).unwrap();

    std::thread::sleep(Duration::from_millis(500));
    let observation = transport
        .observe_process(&window, &worker.run_id, &worker_block)
        .unwrap();
    assert!(observation.child.is_some() || observation.foreground.is_some());
    let process_table = inspect_process_table().unwrap();
    assert!(!process_table.is_empty());

    transport.zoom_block(&reviewer_block, false).unwrap();
    transport
        .close_agent_block(&window, &reviewer.run_id, &reviewer_block)
        .unwrap();
    transport
        .close_agent_block(&window, &worker.run_id, &worker_block)
        .unwrap();
}

/// Exercises the real foreground host launch and Agent run-step boundary with deterministic
/// EMULATED providers, stopping as soon as the Coordinator reads the dispatched TicketRun.
#[test]
#[ignore = "requires an explicitly disposable Rex server and owned session"]
fn live_rex_supervisor_dispatch_starts_coordinator_and_reads_host_inputs() {
    let endpoint = std::env::var("REX_PROJECTS_TEST_ENDPOINT").unwrap();
    let instance = std::env::var("REX_PROJECTS_TEST_INSTANCE_ID").unwrap();
    let session = std::env::var("REX_PROJECTS_TEST_SESSION_ID").unwrap();
    let rex = PathBuf::from(std::env::var("REX_PROJECTS_TEST_REX_CLI").unwrap());
    let test_binary = std::env::current_exe().unwrap();
    let xtask = test_binary
        .parent()
        .and_then(std::path::Path::parent)
        .expect("integration-test executable is under target/debug/deps")
        .join(if cfg!(windows) { "xtask.exe" } else { "xtask" });
    assert!(xtask.is_file(), "workspace xtask binary is available");
    let temporary = tempfile::tempdir().unwrap();
    let temporary_root = std::fs::canonicalize(temporary.path()).unwrap();
    let cli = temporary_root.join("rex-projects-supervisor-fixture");
    let built_cli = PathBuf::from(env!("CARGO_BIN_EXE_rex-projects"));
    std::fs::copy(&built_cli, &cli)
        .expect("copy the actual product binary to a long executable basename");
    #[cfg(unix)]
    std::fs::set_permissions(&cli, std::fs::metadata(&built_cli).unwrap().permissions()).unwrap();
    assert!(cli.is_file(), "actual product CLI binary copy is available");
    let fixture_root = std::env::var_os("REX_PROJECTS_TEST_FIXTURE_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| temporary_root.join("supervisor-coordinator-stage"));
    assert!(fixture_root.is_absolute(), "fixture root is absolute");
    assert!(
        !fixture_root.exists(),
        "fixture root is new and exclusively owned by this test"
    );
    let output = std::process::Command::new(&xtask)
        .args([
            "verify",
            "--cli",
            cli.to_str().unwrap(),
            "--rex",
            rex.to_str().unwrap(),
            "--rex-server",
            &endpoint,
            "--expected-instance",
            &instance,
            "--rex-session",
            &session,
            "--fixture-root",
            fixture_root.to_str().unwrap(),
        ])
        .env(
            "REX_PROJECTS_ACCEPTANCE_STAGE",
            "supervisor_coordinator_inbox",
        )
        .output()
        .expect("run the actual xtask acceptance driver");
    if !output.status.success() {
        let preserved_temp = temporary.keep();
        panic!(
            "bounded acceptance failed (fixture preserved at {}): stdout={} stderr={}",
            preserved_temp.display(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(fixture_root.join("acceptance-trace.json")).unwrap())
            .unwrap();
    println!(
        "bounded Supervisor-to-Coordinator acceptance trace: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(report["status"], "STAGE_PASSED");
    let trace = report["trace"].as_array().unwrap();
    assert!(trace.iter().any(|step| {
        step["step"] == "coordinator_inbox_boundary_observed" && step["status"] == "passed"
    }));
    assert!(trace.iter().any(|step| {
        step["step"] == "bounded_stage_stop_request" && step["status"] == "queued"
    }));
    let contract = trace
        .iter()
        .find(|step| step["step"] == "supervisor_coordinator_contract")
        .unwrap();
    assert_eq!(contract["status"], "passed");
    assert_eq!(
        contract["evidence"]["supervisor_prompt_role_profiles"]["coordinator"],
        "fixture_coordinator"
    );
    let coordinator = &contract["evidence"]["coordinator_dispatch_observation"];
    let ticket_run_id = coordinator["ticket_run_id"].as_str().unwrap();
    assert_eq!(coordinator["ticket_run_dispatch_id"], ticket_run_id);
    let package = coordinator
        .pointer("/input_files/package_path")
        .unwrap()
        .as_str()
        .unwrap();
    let snapshot = coordinator
        .pointer("/input_files/snapshot_path")
        .unwrap()
        .as_str()
        .unwrap();
    assert!(std::path::Path::new(package).is_file());
    assert!(std::path::Path::new(snapshot).is_file());
}
