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
