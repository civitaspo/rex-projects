use std::collections::VecDeque;
use std::io::{self, Read};
use std::process::Command;
use std::process::{Child, ExitStatus, Stdio};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const MAX_CAPTURED_STDERR_BYTES: usize = 8 * 1024;

struct ForegroundOwner {
    child: Child,
    stderr_reader: Option<JoinHandle<VecDeque<u8>>>,
}

impl ForegroundOwner {
    fn spawn(mut command: Command) -> io::Result<Self> {
        let mut child = command.stderr(Stdio::piped()).spawn()?;
        let mut stderr = child
            .stderr
            .take()
            .expect("piped stderr is available after spawn");
        let stderr_reader = std::thread::spawn(move || {
            let mut tail = VecDeque::with_capacity(MAX_CAPTURED_STDERR_BYTES);
            let mut chunk = [0; 2048];
            loop {
                let read = match stderr.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(read) => read,
                };
                for byte in &chunk[..read] {
                    if tail.len() == MAX_CAPTURED_STDERR_BYTES {
                        tail.pop_front();
                    }
                    tail.push_back(*byte);
                }
            }
            tail
        });
        Ok(Self {
            child,
            stderr_reader: Some(stderr_reader),
        })
    }

    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.child.try_wait()
    }

    fn wait(&mut self) -> io::Result<ExitStatus> {
        self.child.wait()
    }

    fn terminate(&mut self) {
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }

    fn stderr_tail(&mut self) -> String {
        self.stderr_reader
            .take()
            .and_then(|reader| reader.join().ok())
            .map(|bytes| {
                let bytes: Vec<u8> = bytes.into_iter().collect();
                String::from_utf8_lossy(&bytes).into_owned()
            })
            .unwrap_or_else(|| "<stderr capture unavailable>".into())
    }
}

impl Drop for ForegroundOwner {
    fn drop(&mut self) {
        self.terminate();
        if let Some(reader) = self.stderr_reader.take() {
            let _ = reader.join();
        }
    }
}

fn command(config: &std::path::Path, state: &std::path::Path, home: &std::path::Path) -> Command {
    let path = std::iter::once(home.join("bin"))
        .chain(std::env::split_paths(
            &std::env::var_os("PATH").unwrap_or_default(),
        ))
        .collect::<Vec<_>>();
    let mut command = Command::new(env!("CARGO_BIN_EXE_rex-projects"));
    command
        .args(["--config"])
        .arg(config)
        .args(["--state-root"])
        .arg(state)
        .env(
            "PATH",
            std::env::join_paths(path).expect("join fixture PATH"),
        )
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_STATE_HOME", home.join("state"))
        .env_remove("REX_PROJECTS_AGENT")
        .env_remove("REX_PROJECTS_CONTEXT")
        .env_remove("REX_SESSION")
        .env_remove("REX_BLOCK")
        .env_remove("REX_BLOCK_ID")
        .env_remove("REX_BIN_DIR")
        .env_remove("REX_SERVER")
        .env("REX_SESSION", "fixture-session")
        .env("REX_BLOCK", "fixture-block")
        .env("REX_CALL_LOG", home.join("rex-calls.log"))
        .env("REX_FORBIDDEN_MARKER", home.join("rex-mutation-attempted"));
    command
}

fn fixture(
    temp: &tempfile::TempDir,
) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let config = temp.path().join("factory.toml");
    let test_binary = std::env::current_exe().expect("locate CLI test executable");
    let xtask = test_binary
        .parent()
        .and_then(std::path::Path::parent)
        .expect("CLI test binary is under target/debug/deps")
        .join(if cfg!(windows) { "xtask.exe" } else { "xtask" });
    assert!(xtask.is_file(), "workspace xtask binary is available");
    let ticket_database = temp.path().join("ticket-adapter.sqlite3");
    let ticket_command = serde_json::to_string(&[
        xtask.to_string_lossy().into_owned(),
        "fixture".to_owned(),
        "ticket".to_owned(),
        "--database".to_owned(),
        ticket_database.to_string_lossy().into_owned(),
        "--namespace".to_owned(),
        "fixture/cli".to_owned(),
    ])
    .expect("encode the generic fixture command as TOML-compatible JSON");
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/fixture/config.toml"),
    )
    .unwrap();
    let source = source
        .replace(
            "command = [\"/absolute/path/to/ticket-adapter\"]",
            &format!("command = {ticket_command}"),
        )
        .replace(
            "https://example.invalid/team/example.git",
            "https://github.com/example/example.git",
        );
    std::fs::write(
        &config,
        source.replacen(
            "schema_version = 1",
            &format!(
                "schema_version = 1\nstate_root = \"{}\"\n\n[runtime.environment]\nsource = \"inherit\"",
                temp.path().join("runtime").display()
            ),
            1,
        ),
    )
    .unwrap();
    let profile_source =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/fixture/profiles");
    let profiles = temp.path().join("profiles");
    for profile in ["judgment_claude", "worker_codex"] {
        let destination = profiles.join(profile);
        std::fs::create_dir_all(&destination).unwrap();
        let profile_config =
            std::fs::read_to_string(profile_source.join(profile).join("config.toml"))
                .unwrap()
                .replace("/absolute/path/to/claude", &xtask.to_string_lossy())
                .replace("/absolute/path/to/codex", &xtask.to_string_lossy());
        std::fs::write(destination.join("config.toml"), profile_config).unwrap();
        std::fs::copy(
            profile_source.join(profile).join("instructions.md"),
            destination.join("instructions.md"),
        )
        .unwrap();
    }
    let state = temp.path().join("runtime");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let fixture_bin = home.join("bin");
    std::fs::create_dir_all(&fixture_bin).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&xtask, fixture_bin.join("gh"))
        .expect("provide the Rust fixture executable as the unused gh tool path");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let rex = fixture_bin.join("rex");
        std::fs::write(
            &rex,
            r##"#!/bin/sh
printf '%s\n' "$*" >> "$REX_CALL_LOG"
case "$*" in
  *whoami*) printf '%s\n' '{"endpoint":"http://fixture","instance_id":"fixture-server","host_id":"fixture-host","rex_version":"test"}' ;;
  *"api list"*) printf '%s\n' '{"methods":{"session.view":{},"session.new_window":{},"session.new_split":{},"session.focus_block":{},"session.zoom_block":{},"block.close":{}}}' ;;
  *"api call session.view"*) printf '%s\n' '{"windows":[{"layers":[{"blocks":[{"block_id":"fixture-block"}]}]}]}' ;;
  *"events -s fixture-session --json"*) exit 0 ;;
  *) touch "$REX_FORBIDDEN_MARKER"; exit 91 ;;
esac
"##,
        )
        .unwrap();
        std::fs::set_permissions(&rex, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    (config, state, home)
}

fn projection_fixture(
    temp: &tempfile::TempDir,
) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let config = temp.path().join("factory.toml");
    std::fs::write(
        &config,
        "schema_version = 1\n\n[adapters.tickets]\nkind = 'command'\ncommand = ['ticket-cli']\n\n[repositories.example]\nclone_url = 'https://github.com/example/repo.git'\nbase_branch = 'main'\nforge = 'github'\n\n[repositories.example.merge]\ninstructions = 'Follow the repository merge procedure.'\n\n[projects]\n",
    )
    .unwrap();
    let state = temp.path().join("state");
    let home = temp.path().join("home");
    std::fs::create_dir_all(home.join("bin")).unwrap();
    (config, state, home)
}

#[test]
fn dashboard_json_surfaces_ambiguous_launch_without_changing_ownership() {
    use sha2::Digest as _;

    let temp = tempfile::tempdir().unwrap();
    let (config, state, home) = projection_fixture(&temp);
    let applied = command(&config, &state, &home)
        .args(["config", "apply", "--bootstrap"])
        .output()
        .unwrap();
    assert!(
        applied.status.success(),
        "{}",
        String::from_utf8_lossy(&applied.stderr)
    );

    let db = rusqlite::Connection::open(state.join("state.sqlite3")).unwrap();
    db.execute_batch(
        "PRAGMA foreign_keys=OFF;
         INSERT INTO projects(project_id,config_source,config_revision,config_digest,mode,desired_lifecycle,created_at_unix) VALUES('project1','fixture',1,printf('%064d',0),'goal','running',1);
         INSERT INTO project_runtimes(project_id,desired_lifecycle,observed_lifecycle,controller_generation,project_epoch,next_due_at_unix) VALUES('project1','running','running',1,1,1);
         INSERT INTO ticket_runs(ticket_run_id,project_id,config_source,config_revision,config_digest,namespace,ticket_id,generation,internal_phase,activity,external_status,observed_status,revision) VALUES('ticketrun1','project1','fixture',1,printf('%064d',0),'fixture','ISSUE-1',1,'in_progress','active','In Progress','In Progress',1);
         INSERT INTO agent_runs(agent_run_id,project_id,config_source,config_revision,config_digest,role_session_id,logical_owner,finite_turn,launch_operation_id,state,controller_generation) VALUES('agentrun1','project1','fixture',1,printf('%064d',0),'ticket_run:ticketrun1:coordinator','coordinator',1,'operation1','unknown',1);
         INSERT INTO execution_slots(pool,slot_index,project_id,ticket_run_id,owner_kind,owner_id,reservation_epoch,controller_generation,disposition) VALUES('agent',0,'project1','ticketrun1','agent_run','agentrun1',1,1,'unknown');",
    )
    .unwrap();

    use rex_projects::domain::ids::{
        AgentRunId, Digest, OperationId, ProfileId, ProjectId, Revision, TicketRunId,
    };
    use rex_projects::domain::types::Role;
    use rex_projects::launch::AgentLaunchReservation;
    use std::path::PathBuf;

    let project_id = ProjectId::parse("project1").unwrap();
    let agent_run_id = AgentRunId::parse("agentrun1").unwrap();
    let ticket_run_id = TicketRunId::parse("ticketrun1").unwrap();
    let role_session_id = "ticket_run:ticketrun1:coordinator".to_owned();
    let mut wake_snapshot = rex_projects::agent_api::AgentWakeSnapshot {
        schema_version: 1,
        project_id: project_id.clone(),
        role_session_id: role_session_id.clone(),
        agent_run_id: agent_run_id.to_string(),
        digest: Digest::parse("0".repeat(64)).unwrap(),
        inputs: Vec::new(),
        worker_correction_context: None,
    };
    wake_snapshot.digest = wake_snapshot.content_digest().unwrap();
    let digest = || Digest::parse("0".repeat(64)).unwrap();
    let reservation = AgentLaunchReservation {
        schema_version: 1,
        agent_run_id,
        project_id,
        role: Role::Coordinator,
        role_session_id,
        parent_run_id: None,
        parent_role: None,
        ticket_run_id: Some(ticket_run_id),
        ticket_revision: Some(Revision(1)),
        config_revision: Revision(1),
        config_digest: digest(),
        attempt: 1,
        run_epoch: 1,
        controller_generation: 1,
        project_epoch: 1,
        operation_id: OperationId::parse("operation1").unwrap(),
        operation_recipe_id: None,
        worker_assignment: None,
        rex_view_id: digest(),
        runtime_binary_digest: digest(),
        environment_snapshot_id: digest(),
        profile_id: ProfileId::parse("fixture").unwrap(),
        profile_digest: digest(),
        instruction_digest: digest(),
        result_schema_digest: digest(),
        wake_snapshot,
        qualification_receipt_digest: digest(),
        descriptor_path: PathBuf::from("/tmp/descriptor.json"),
        workspace_path: PathBuf::from("/tmp/workspace"),
        control_dir: PathBuf::from("/tmp/control"),
        mailbox_directory: PathBuf::from("/tmp/mailbox"),
        mailbox_capability_digest: digest(),
        mailbox_expires_at_unix: 1000,
        mailbox_max_request_bytes: 1024,
        mailbox_max_pending_requests: 4,
        pool: "agent".into(),
        slot_index: 0,
        global_capacity: 1,
        project_capacity: 1,
    };
    reservation.validate().unwrap();
    let reservation_json = serde_json::to_string(&reservation).unwrap();
    let reservation_digest = reservation.digest().unwrap().to_string();
    db.execute(
        "INSERT INTO agent_launch_reservations(agent_run_id,project_id,operation_id,controller_generation,project_epoch,reservation_digest,reservation_json,lifecycle,created_at_unix,updated_at_unix,launch_phase) VALUES('agentrun1','project1','operation1',1,1,?1,?2,'reserved',1,1,'ambiguous')",
        rusqlite::params![reservation_digest, reservation_json],
    ).unwrap();
    let request = serde_json::json!({
        "schema_version": 1,
        "agent_run_id": "agentrun1",
        "launch_reservation_digest": reservation_digest
    });
    let request_json = serde_json::to_string(&request).unwrap();
    let request_digest = format!("{:x}", sha2::Sha256::digest(request_json.as_bytes()));
    db.execute(
        "INSERT INTO effects(operation_id,project_id,subject_type,subject_id,logical_key,kind,request_json,request_digest,status,attempt_count,next_attempt_at_unix,created_at_unix) VALUES('operation1','project1','agent_run','agentrun1','start','start_agent',?1,?2,'uncertain',1,1,1)",
        rusqlite::params![request_json, request_digest],
    ).unwrap();

    for _ in 0..2 {
        let output = command(&config, &state, &home)
            .args(["--json", "dashboard"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let snapshot: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let wait = snapshot["waits"]
            .as_array()
            .unwrap()
            .iter()
            .find(|wait| wait["kind"] == "agent_launch_handoff")
            .expect("ambiguous launch is shown in the dashboard");
        assert_eq!(wait["project_id"], "project1");
        assert_eq!(wait["ticket_run_id"], "ticketrun1");
        assert_eq!(
            snapshot["waits"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|row| row["kind"] == "agent_launch_handoff")
                .count(),
            1
        );
        assert!(
            !snapshot["waits"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["kind"] == "start_agent")
        );
        assert!(wait["detail"].as_str().unwrap().contains("agentrun1"));
        assert!(
            wait["detail"]
                .as_str()
                .unwrap()
                .contains("TicketRun ticketrun1")
        );
        assert!(
            wait["detail"]
                .as_str()
                .unwrap()
                .contains("Keep its execution slot and worktree reserved")
        );
        assert!(!wait["detail"].as_str().unwrap().contains("retry"));
        let phase: String = db
            .query_row(
                "SELECT launch_phase FROM agent_launch_reservations WHERE agent_run_id='agentrun1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let slot: String = db
            .query_row(
                "SELECT disposition FROM execution_slots WHERE owner_id='agentrun1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let status: String = db
            .query_row(
                "SELECT status FROM effects WHERE operation_id='operation1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            (phase.as_str(), slot.as_str(), status.as_str()),
            ("ambiguous", "unknown", "uncertain")
        );
    }

    for (pool, slot_index) in [("rex_projects_hook", 0), ("agent", 1)] {
        db.execute(
            "UPDATE execution_slots SET pool=?1,slot_index=?2 WHERE owner_id='agentrun1'",
            rusqlite::params![pool, slot_index],
        )
        .unwrap();
        let output = command(&config, &state, &home)
            .args(["--json", "dashboard"])
            .output()
            .unwrap();
        assert!(output.status.success());
        let snapshot: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(
            !snapshot["waits"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["kind"] == "agent_launch_handoff"),
            "a different execution slot must not match the launch reservation"
        );
    }
    db.execute_batch(
        "UPDATE execution_slots SET pool='agent',slot_index=0 WHERE owner_id='agentrun1';",
    )
    .unwrap();

    db.execute_batch(
        "DROP TRIGGER agent_launch_phase_transitions;
         UPDATE agent_launch_reservations SET launch_phase='create_attempted' WHERE agent_run_id='agentrun1';",
    )
    .unwrap();
    for status in ["uncertain", "failed"] {
        db.execute(
            "UPDATE effects SET status=?1 WHERE operation_id='operation1'",
            [status],
        )
        .unwrap();
        let output = command(&config, &state, &home)
            .args(["--json", "dashboard"])
            .output()
            .unwrap();
        assert!(output.status.success());
        let snapshot: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(
            snapshot["waits"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["kind"] == "agent_launch_handoff")
        );
    }
    for status in ["pending", "claimed", "succeeded"] {
        db.execute_batch("UPDATE agent_launch_reservations SET launch_phase='legacy_unknown' WHERE agent_run_id='agentrun1';").unwrap();
        db.execute(
            "UPDATE effects SET status=?1 WHERE operation_id='operation1'",
            [status],
        )
        .unwrap();
        let output = command(&config, &state, &home)
            .args(["--json", "dashboard"])
            .output()
            .unwrap();
        assert!(output.status.success());
        let snapshot: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(
            !snapshot["waits"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["kind"] == "agent_launch_handoff")
        );
        if status == "pending" {
            assert!(
                snapshot["waits"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|row| row["kind"] == "start_agent")
            );
        }
    }
    db.execute(
        "UPDATE effects SET status='uncertain' WHERE operation_id='operation1'",
        [],
    )
    .unwrap();
    let output = command(&config, &state, &home)
        .args(["--json", "dashboard"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let snapshot: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        snapshot["waits"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["kind"] == "agent_launch_handoff")
    );

    db.execute_batch("UPDATE effects SET status='failed',request_digest=printf('%064d',0) WHERE operation_id='operation1';").unwrap();
    let output = command(&config, &state, &home)
        .args(["--json", "dashboard"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let snapshot: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        !snapshot["waits"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["kind"] == "agent_launch_handoff")
    );
}

#[test]
fn dashboard_json_reads_schema_17_without_launch_phase_column() {
    let temp = tempfile::tempdir().unwrap();
    let (config, state, home) = projection_fixture(&temp);
    let applied = command(&config, &state, &home)
        .args(["config", "apply", "--bootstrap"])
        .output()
        .unwrap();
    assert!(
        applied.status.success(),
        "{}",
        String::from_utf8_lossy(&applied.stderr)
    );
    let db = rusqlite::Connection::open(state.join("state.sqlite3")).unwrap();
    db.execute_batch("DROP TRIGGER IF EXISTS agent_launch_phase_transitions; ALTER TABLE agent_launch_reservations DROP COLUMN launch_phase; PRAGMA user_version=17;").unwrap();
    drop(db);

    let output = command(&config, &state, &home)
        .args(["--json", "dashboard"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let snapshot: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        snapshot["waits"]
            .as_array()
            .unwrap()
            .iter()
            .all(|wait| wait["kind"] != "agent_launch_handoff")
    );
    let absent: i64 = rusqlite::Connection::open(state.join("state.sqlite3")).unwrap()
        .query_row("SELECT COUNT(*) FROM pragma_table_info('agent_launch_reservations') WHERE name='launch_phase'", [], |row| row.get(0)).unwrap();
    assert_eq!(absent, 0);
}

#[test]
fn version_reports_the_cargo_package_version() {
    let output = Command::new(env!("CARGO_BIN_EXE_rex-projects"))
        .arg("--version")
        .output()
        .expect("run rex-projects --version");

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).expect("version output is UTF-8"),
        format!("rex-projects {}\n", env!("CARGO_PKG_VERSION"))
    );
    assert!(output.stderr.is_empty());
}

fn inbox_fixture_snapshot(run_id: &str) -> rex_projects::agent_api::AgentWakeSnapshot {
    let source_id = "3".repeat(64);
    let artifact_id = "a".repeat(64);
    let mut snapshot = rex_projects::agent_api::AgentWakeSnapshot {
        schema_version: 1,
        project_id: rex_projects::domain::ids::ProjectId::parse("project1").unwrap(),
        role_session_id: "ticket_run:ticket1:coordinator".into(),
        agent_run_id: run_id.into(),
        digest: rex_projects::domain::ids::Digest::parse("0".repeat(64)).unwrap(),
        worker_correction_context: None,
        inputs: vec![rex_projects::agent_api::AgentWakeItem {
            wake_input_id: 5,
            source_type: "agent_result".into(),
            source_id: source_id.clone(),
            source_revision: 1,
            priority: 7,
            payload_json: serde_json::json!({"structured_result":{"summary":"Planner output"}}),
            host_artifact_source_evidence_ids: Vec::new(),
            host_artifacts: vec![rex_projects::agent_api::HostArtifactLocator {
                artifact_id: rex_projects::domain::ids::ArtifactId::parse(artifact_id.clone())
                    .unwrap(),
                kind: rex_projects::engine::orchestration::RoleArtifactKind::Plan,
                schema_version: 1,
                digest: rex_projects::domain::ids::Digest::parse("b".repeat(64)).unwrap(),
                bytes: 3,
                path: format!(".rex-artifacts/sha256/aa/{artifact_id}"),
                source_run_id: "planner-run".into(),
                source_evidence_id: source_id,
                source_authority_digest: rex_projects::domain::ids::Digest::parse("c".repeat(64))
                    .unwrap(),
            }],
            host_completion_context: None,
        }],
    };
    snapshot.digest = snapshot.content_digest().unwrap();
    snapshot
}

#[test]
fn postmortem_inbox_cli_preserves_validation_artifacts_and_unavailability() {
    use rex_projects::domain::ids::Digest;
    use rex_projects::mailbox::{MailboxCapability, MailboxLimits};
    use sha2::Digest as _;

    let temp = tempfile::tempdir().unwrap();
    let control = temp.path().join("control");
    let workspace = temp.path().join("workspace");
    let state = temp.path().join("unused-state");
    let run_id = "postmortem-run";
    MailboxCapability::create(
        run_id,
        &control,
        u64::MAX,
        MailboxLimits {
            max_request_bytes: 1_048_576,
            max_pending_requests: 32,
        },
    )
    .unwrap();
    let mut snapshot = inbox_fixture_snapshot(run_id);
    snapshot.role_session_id = "ticket_run:ticket1:postmortem".into();
    let item = &mut snapshot.inputs[0];
    item.source_type = "ticket_run_transition".into();
    item.source_revision = 8;
    item.payload_json = serde_json::json!({"target":"postmortem","ticket_run_id":"ticket1","revision":8,"message_id":item.source_id});
    item.host_artifact_source_evidence_ids =
        vec![item.host_artifacts[0].source_evidence_id.clone()];
    let bytes = b"check command: cargo test\nexit code: 0\n";
    let artifact = &mut item.host_artifacts[0];
    artifact.kind = rex_projects::engine::orchestration::RoleArtifactKind::TestReceipt;
    artifact.source_run_id = "worker-run".into();
    artifact.bytes = bytes.len() as u64;
    artifact.digest = Digest::parse(format!("{:x}", sha2::Sha256::digest(bytes))).unwrap();
    let path = workspace.join(&artifact.path);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, bytes).unwrap();
    item.host_completion_context = Some(serde_json::from_value(serde_json::json!({
        "schema_version":1,
        "scope":{"project_id":"project1","ticket_run_id":"ticket1","ticket_id":"ticket1","ticket_revision":8,"configuration_digest":"c".repeat(64)},
        "operation_completion":{"plan_digest":"a".repeat(64),"state":"not_required","not_required_reason":"CLI fixture","receipts":[]},
        "implementation_publication":{"accepted_plan_digest":"a".repeat(64),"configuration_digest":"c".repeat(64),"merge_work_id":"1".repeat(64),"assessed_revision":5,"awaiting_merge_revision":7,"prepared_receipt_digest":"2".repeat(64),"publication_set_digest":"3".repeat(64),"assessment_id":"assessment","assessment_evidence_id":"4".repeat(64),"assessment_result_digest":"5".repeat(64),"intent_evidence_id":"6".repeat(64),"intent_result_digest":"7".repeat(64),"assessment":{},"verification":null,"artifact_evidence_unavailable":"an earlier source is unavailable",
            "merge_verification":{"work_id":"1".repeat(64),"configuration_digest":"c".repeat(64),"accepted_plan_digest":"a".repeat(64),"assessment_id":"assessment","source_revision":7,"merge_commit_sha":"8".repeat(40),"included_head_sha":"9".repeat(40),"receipt_digest":"0".repeat(64),"receipt":{}}}
    })).unwrap());
    snapshot.digest = snapshot.content_digest().unwrap();
    rex_projects::agent_api::publish_wake_snapshot(&control, snapshot.clone()).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_rex-projects"))
        .arg("--state-root")
        .arg(&state)
        .args(["agent", "inbox", "--json"])
        .env("REX_PROJECTS_AGENT", "1")
        .env("REX_PROJECTS_RUN_ID", run_id)
        .env("REX_PROJECTS_CONTROL_DIR", &control)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let consumed: Vec<rex_projects::agent_api::AgentWakeItem> =
        serde_json::from_value(report["inputs"].clone()).unwrap();
    assert_eq!(consumed, snapshot.inputs);
    let received = &consumed[0].host_artifacts[0];
    let actual = std::fs::read(workspace.join(&received.path)).unwrap();
    assert_eq!(actual, bytes);
    assert_eq!(
        format!("{:x}", sha2::Sha256::digest(&actual)),
        received.digest.as_str()
    );
    assert!(!state.exists());
}

#[test]
fn agent_inbox_reads_the_scoped_snapshot_without_opening_state() {
    use rex_projects::mailbox::{MailboxCapability, MailboxLimits};

    let temp = tempfile::tempdir().unwrap();
    let control_dir = temp.path().join("control");
    let state_root = temp.path().join("unused-state");
    let run_id = "coordinator-run";
    MailboxCapability::create(
        run_id,
        &control_dir,
        u64::MAX,
        MailboxLimits {
            max_request_bytes: 1_048_576,
            max_pending_requests: 32,
        },
    )
    .unwrap();
    let snapshot_path = control_dir.join("inbox/snapshot.json");
    rex_projects::agent_api::publish_wake_snapshot(&control_dir, inbox_fixture_snapshot(run_id))
        .unwrap();
    let descriptor_before = std::fs::read(control_dir.join("descriptor.json")).unwrap();
    let snapshot_before = std::fs::read(&snapshot_path).unwrap();
    let run_inbox = |extra: &[&str]| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_rex-projects"));
        command
            .args(["--state-root"])
            .arg(&state_root)
            .args(["agent", "inbox", "--json"])
            .args(extra)
            .env("REX_PROJECTS_AGENT", "1")
            .env("REX_PROJECTS_RUN_ID", run_id)
            .env("REX_PROJECTS_CONTROL_DIR", &control_dir);
        command.output().unwrap()
    };

    let output = run_inbox(&[]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["run_id"], run_id);
    assert_eq!(report["after"], 0);
    assert_eq!(report["next_after"], 5);
    assert_eq!(
        report["inputs"][0]["payload_json"]["structured_result"]["summary"],
        "Planner output"
    );
    assert_eq!(
        report["inputs"][0]["host_artifacts"][0]["artifact_id"],
        "a".repeat(64)
    );

    let output = run_inbox(&["--after", "5"]);
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["after"], 5);
    assert_eq!(report["next_after"], 5);
    assert!(report["inputs"].as_array().unwrap().is_empty());
    assert_eq!(std::fs::read(&snapshot_path).unwrap(), snapshot_before);
    assert_eq!(
        std::fs::read(control_dir.join("descriptor.json")).unwrap(),
        descriptor_before
    );

    let wrong_run = run_inbox(&["--run", "another-run"]);
    assert!(!wrong_run.status.success());
    let wrong_run_snapshot = std::fs::read(&snapshot_path).unwrap();
    rex_projects::agent_api::publish_wake_snapshot(
        &control_dir,
        inbox_fixture_snapshot("another-run"),
    )
    .unwrap();
    let wrong_snapshot_run = run_inbox(&[]);
    assert!(!wrong_snapshot_run.status.success());
    let mismatched_snapshot = std::fs::read(&snapshot_path).unwrap();
    assert_ne!(mismatched_snapshot, wrong_run_snapshot);

    rex_projects::agent_api::publish_wake_snapshot(&control_dir, inbox_fixture_snapshot(run_id))
        .unwrap();
    let mut invalid_digest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&snapshot_path).unwrap()).unwrap();
    invalid_digest["digest"] = serde_json::Value::String("d".repeat(64));
    std::fs::write(&snapshot_path, serde_json::to_vec(&invalid_digest).unwrap()).unwrap();
    let bad_digest = run_inbox(&[]);
    assert!(!bad_digest.status.success());
    let invalid_digest_bytes = std::fs::read(&snapshot_path).unwrap();
    assert!(!invalid_digest_bytes.is_empty());

    let oversized_snapshot = vec![b'x'; 1024 * 1024 + 1];
    std::fs::write(&snapshot_path, &oversized_snapshot).unwrap();
    let oversized = run_inbox(&[]);
    assert!(!oversized.status.success());
    assert_eq!(std::fs::read(&snapshot_path).unwrap(), oversized_snapshot);

    std::fs::write(control_dir.join("descriptor.json"), b"{").unwrap();
    let malformed_descriptor = run_inbox(&[]);
    assert!(!malformed_descriptor.status.success());
    assert_eq!(
        std::fs::read(control_dir.join("descriptor.json")).unwrap(),
        b"{"
    );
    std::fs::write(control_dir.join("descriptor.json"), &descriptor_before).unwrap();

    let mut oversized_descriptor: serde_json::Value =
        serde_json::from_slice(&descriptor_before).unwrap();
    oversized_descriptor["max_request_bytes"] = serde_json::json!(1024 * 1024 + 1);
    std::fs::write(
        control_dir.join("descriptor.json"),
        serde_json::to_vec(&oversized_descriptor).unwrap(),
    )
    .unwrap();
    let bad_limits = run_inbox(&[]);
    assert!(!bad_limits.status.success());
    std::fs::write(control_dir.join("descriptor.json"), &descriptor_before).unwrap();

    #[cfg(unix)]
    {
        let inbox_dir = control_dir.join("inbox");
        let moved_inbox = temp.path().join("original-inbox");
        std::fs::rename(&inbox_dir, &moved_inbox).unwrap();
        std::os::unix::fs::symlink(&moved_inbox, &inbox_dir).unwrap();
        let unsafe_path = run_inbox(&[]);
        assert!(!unsafe_path.status.success());
        std::fs::remove_file(&inbox_dir).unwrap();
        std::fs::rename(&moved_inbox, &inbox_dir).unwrap();
    }

    assert_eq!(
        std::fs::read(control_dir.join("descriptor.json")).unwrap(),
        descriptor_before
    );
    assert!(
        !state_root.exists(),
        "inbox read must not create a state database"
    );
}

#[test]
fn supervisor_fixture_cli_handles_learning_batch_and_preserves_ticket_dispatch() {
    use rex_projects::agent_api::{AgentWakeItem, AgentWakeSnapshot};
    use rex_projects::domain::ids::{Digest, ProjectId};
    use rex_projects::mailbox::{MailboxCapability, MailboxLimits};
    use sha2::{Digest as _, Sha256};
    use std::path::{Path, PathBuf};

    fn invoke_fixture(inbox_item: AgentWakeItem, label: &str) -> serde_json::Value {
        let temp = tempfile::tempdir().unwrap();
        let run_id = format!("supervisor-{label}");
        let control_dir = temp.path().join("run/control");
        let state_dir = temp.path().join("fixture-state");
        MailboxCapability::create(
            &run_id,
            &control_dir,
            u64::MAX,
            MailboxLimits {
                max_request_bytes: 1_048_576,
                max_pending_requests: 32,
            },
        )
        .unwrap();

        let mut snapshot = AgentWakeSnapshot {
            schema_version: 1,
            project_id: ProjectId::parse("operations_project").unwrap(),
            role_session_id: "project:operations_project:supervisor".into(),
            agent_run_id: run_id.clone(),
            digest: Digest::parse("0".repeat(64)).unwrap(),
            worker_correction_context: None,
            inputs: vec![inbox_item],
        };
        snapshot.digest = snapshot.content_digest().unwrap();
        rex_projects::agent_api::publish_wake_snapshot(&control_dir, snapshot.clone()).unwrap();

        let product_cli = PathBuf::from(env!("CARGO_BIN_EXE_rex-projects"));
        let test_binary = std::env::current_exe().unwrap();
        let xtask = test_binary
            .parent()
            .and_then(std::path::Path::parent)
            .expect("integration-test executable is under target/debug/deps")
            .join(if cfg!(windows) { "xtask.exe" } else { "xtask" });
        assert!(xtask.is_file(), "workspace xtask binary is available");

        let schema_path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("schemas/agent-results/supervisor-v1.json");
        let schema = std::fs::read_to_string(schema_path).unwrap();
        let context_path = temp.path().join("supervisor-context.json");
        let context = serde_json::json!({
            "schema_version":1,
            "scenario":"acceptance_supervisor",
            "messages":[
                {
                    "role":"supervisor","lane":"qualification","kind":"progress",
                    "assertion":{"assertion":"succeeded"},
                    "structured_result":{"summary":"Qualification probe completed.","completed_node_keys":[],"pending_node_keys":[],"evidence":[],"next_observation_at":null}
                },
                {
                    "role":"supervisor","lane":"workflow","kind":"dispatch_request",
                    "assertion":{"assertion":"succeeded"},
                    "structured_result":{"ticket_reference":{"$fixture_ref":"inbox.ticket_id"},"expected_ticket_revision":{"$fixture_ref":"inbox.external_revision"},"coordinator_profile":{"$fixture_ref":"inbox.coordinator_profile"},"priority":1,"rationale":"The normalized ticket observation is eligible for dispatch."}
                }
            ]
        });
        std::fs::write(&context_path, serde_json::to_vec(&context).unwrap()).unwrap();

        let projection_path = temp.path().join("codex-output-schema.json");
        std::fs::write(
            &projection_path,
            br#"{"type":"object","properties":{"result":{"type":"string"}},"required":["result"],"additionalProperties":false}"#,
        )
        .unwrap();
        let inbox_command = format!(
            "'{}' agent inbox --run \"$REX_PROJECTS_RUN_ID\" --control-dir \"$REX_PROJECTS_CONTROL_DIR\" --json",
            product_cli.display()
        );
        let prompt = format!(
            "Return only a JSON object with exactly one property named `result`.\n<rex-projects-authoritative-result-schema>\n{schema}\n</rex-projects-authoritative-result-schema>\nApplied Project role profiles (trusted applied configuration; use the exact profile ID when requesting a role):\n```json\n{{\"coordinator\":\"fixture_coordinator\"}}\n```\nUse the public inbox command `{inbox_command}`."
        );
        let package_path = temp.path().join("run/run-step.package.json");
        std::fs::write(
            &package_path,
            serde_json::to_vec(&serde_json::json!({
                "descriptor":{
                    "run_id":run_id,
                    "role":"supervisor",
                    "control_dir":control_dir,
                    "ticket_run_id":null,
                    "wake_snapshot_digest":snapshot.digest
                },
                "prompt":prompt
            }))
            .unwrap(),
        )
        .unwrap();

        let output = Command::new(xtask)
            .args([
                "fixture",
                "agent",
                "--provider",
                "codex",
                "--role",
                "supervisor",
                "--scenario",
                "acceptance_supervisor",
                "--context",
            ])
            .arg(&context_path)
            .args(["--state-dir"])
            .arg(&state_dir)
            .args(["--runtime-binary"])
            .arg(&product_cli)
            .arg("--")
            .args(["exec", "--json", "--no-daemon", "--output-schema"])
            .arg(&projection_path)
            .args([
                "--sandbox",
                "workspace-write",
                "--ask-for-approval",
                "never",
                "-",
            ])
            .arg(prompt)
            .env("REX_PROJECTS_AGENT", "1")
            .env("REX_PROJECTS_CONTEXT", &context_path)
            .env("REX_PROJECTS_PROJECT_ID", "operations_project")
            .env("REX_PROJECTS_ROLE", "supervisor")
            .env("REX_PROJECTS_RUN_ID", &run_id)
            .env("REX_PROJECTS_CONTROL_DIR", &control_dir)
            .env("REX_PROJECTS_ATTEMPT", "1")
            .env("REX_PROJECTS_RUN_EPOCH", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "fixture CLI failed for {label}: {}",
            String::from_utf8_lossy(&output.stderr)
                .chars()
                .take(4096)
                .collect::<String>()
        );
        let (thread_id, parsed) = rex_projects::providers::parse_result(
            rex_projects::domain::types::AgentAdapter::Codex,
            &output.stdout,
            &rex_projects::roles::result_schema(rex_projects::domain::types::Role::Supervisor),
        )
        .unwrap();
        assert_eq!(
            thread_id.as_deref(),
            Some("fixture-codex-acceptance_supervisor-supervisor")
        );
        parsed
    }

    let config_digest = "c".repeat(64);
    let batch_base = serde_json::json!({
        "type":"supervisor_learning_batch",
        "project_id":"operations_project",
        "config_revision":7,
        "config_digest":config_digest,
        "issued_at_unix":1794577080,
        "prior_checkpoint":{},
        "maintenance":{},
        "findings":[]
    });
    let batch_digest = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&batch_base).unwrap())
    );
    let batch_id = format!("learning-{batch_digest}");
    let mut batch_payload = batch_base;
    batch_payload["batch_id"] = serde_json::json!(batch_id);
    batch_payload["batch_digest"] = serde_json::json!(batch_digest);
    let learning = invoke_fixture(
        AgentWakeItem {
            wake_input_id: 4,
            source_type: "learning_batch".into(),
            source_id: batch_id.clone(),
            source_revision: 2,
            priority: 1,
            payload_json: batch_payload,
            host_artifact_source_evidence_ids: vec![],
            host_artifacts: vec![],
            host_completion_context: None,
        },
        "learning-batch",
    );
    assert_eq!(learning["kind"], "learning_decision");
    assert_eq!(learning["structured_result"]["batch_id"], batch_id);
    assert_eq!(learning["structured_result"]["batch_digest"], batch_digest);
    assert_eq!(learning["structured_result"]["config_revision"], 7);
    assert!(
        learning["structured_result"]["observations"][0]
            .as_str()
            .unwrap()
            .contains("wake revision 2")
    );

    let ticket = invoke_fixture(
        AgentWakeItem {
            wake_input_id: 1,
            source_type: "ticket_observation".into(),
            source_id: "fixture/acceptance:T-42:ready".into(),
            source_revision: 22,
            priority: 30,
            payload_json: serde_json::json!({
                "schema_version":1,"kind":"ticket_observation","ticket_namespace":"fixture/acceptance",
                "ticket_id":"T-42","status":"ready","title":"Acceptance ticket","labels":[],
                "external_revision":"rev-opaque-42","goal_revision":0
            }),
            host_artifact_source_evidence_ids: vec![],
            host_artifacts: vec![],
            host_completion_context: None,
        },
        "ticket-dispatch",
    );
    assert_eq!(ticket["kind"], "dispatch_request");
    assert_eq!(ticket["structured_result"]["ticket_reference"], "T-42");
    assert_eq!(
        ticket["structured_result"]["expected_ticket_revision"],
        "rev-opaque-42"
    );
}

#[test]
fn agent_artifact_add_uses_limits_registered_for_its_run() {
    use rex_projects::mailbox::{MailboxCapability, MailboxLimits};

    let temp = tempfile::tempdir().unwrap();
    let control_dir = temp.path().join("control");
    let run_id = "worker-run";
    let limits = MailboxLimits {
        max_request_bytes: 1_048_576,
        max_pending_requests: 32,
    };
    MailboxCapability::create(run_id, &control_dir, u64::MAX, limits).unwrap();
    std::fs::write(control_dir.join("evidence.json"), b"{}").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_rex-projects"))
        .args([
            "agent",
            "artifact-add",
            "--control-dir",
            control_dir.to_str().unwrap(),
            "--run",
            run_id,
            "--path",
            "evidence.json",
            "--kind",
            "change",
            "--message-id",
            "artifact-request",
            "--wait-seconds",
            "0",
            "--json",
        ])
        .env("REX_PROJECTS_AGENT", "1")
        .env("REX_PROJECTS_PROJECT_ID", "project1")
        .env("REX_PROJECTS_OPERATION_ID", "operation-1")
        .env("REX_PROJECTS_ROLE", "worker")
        .env("REX_PROJECTS_ATTEMPT", "1")
        .env("REX_PROJECTS_RUN_EPOCH", "1")
        .env("REX_PROJECTS_SUBJECT_REVISION", "3")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["state"], "queued");
    assert_eq!(response["request_id"], "artifact-request");

    let mailbox = MailboxCapability::open_registered_for_run(run_id, &control_dir).unwrap();
    let pending = mailbox.pending(u64::MAX - 1).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(
        serde_json::to_value(&pending[0].envelope.method).unwrap(),
        "artifact.add"
    );
    assert_eq!(pending[0].envelope.run_id.as_deref(), Some(run_id));
    assert_eq!(pending[0].envelope.params["path"], "evidence.json");

    let wrong_run = Command::new(env!("CARGO_BIN_EXE_rex-projects"))
        .args([
            "agent",
            "artifact-add",
            "--control-dir",
            control_dir.to_str().unwrap(),
            "--run",
            "another-run",
            "--path",
            "evidence.json",
            "--kind",
            "change",
            "--message-id",
            "wrong-run-request",
            "--wait-seconds",
            "0",
            "--json",
        ])
        .env("REX_PROJECTS_AGENT", "1")
        .env("REX_PROJECTS_PROJECT_ID", "project1")
        .env("REX_PROJECTS_OPERATION_ID", "operation-1")
        .env("REX_PROJECTS_ROLE", "worker")
        .env("REX_PROJECTS_ATTEMPT", "1")
        .env("REX_PROJECTS_RUN_EPOCH", "1")
        .env("REX_PROJECTS_SUBJECT_REVISION", "3")
        .output()
        .unwrap();
    assert!(!wrong_run.status.success());
    assert_eq!(mailbox.pending(u64::MAX - 1).unwrap().len(), 1);
}

#[test]
#[ignore = "subprocess fixture for provider status CLI integration"]
fn provider_status_state_fixture() {
    use rex_projects::config;
    use rex_projects::domain::ids::{Digest, ProfileId, ProjectId};
    use rex_projects::domain::types::Role;
    use rex_projects::store::provider_qualification_runtime::{
        ProviderQualificationJobStatus, ProviderQualificationRequest, QualificationClaim,
    };
    use rex_projects::store::{ConfigStore, ExpectedRevision, OwnerMetadata};

    let config_path = std::path::PathBuf::from(
        std::env::var_os("REX_PROJECTS_TEST_CONFIG_PATH").expect("fixture config path is set"),
    );
    let state_root = std::path::PathBuf::from(
        std::env::var_os("REX_PROJECTS_TEST_STATE_ROOT").expect("fixture state path is set"),
    );
    let applied = config::load(&config_path).unwrap();
    let mut store = ConfigStore::open(&state_root).unwrap();
    let revision = store
        .apply_snapshot(
            &config_path.canonicalize().unwrap().display().to_string(),
            &applied,
            ExpectedRevision::Bootstrap,
        )
        .unwrap()
        .revision;
    let generation = store
        .start_owner(&OwnerMetadata {
            owner_nonce: "provider-status-integration".into(),
            state_root: state_root.display().to_string(),
            config_source: config_path.canonicalize().unwrap().display().to_string(),
            process_start_identity: "integration-test-process".into(),
            executable_path: std::env::current_exe().unwrap().display().to_string(),
            executable_digest: "a".repeat(64),
            rex_endpoint: None,
            rex_server_identity: None,
            rex_session_id: None,
            rex_block_id: None,
        })
        .unwrap();
    let request_id = "provider-status-terminal-failure";
    let request = ProviderQualificationRequest {
        request_id: request_id.into(),
        project_id: ProjectId::parse("goal_project").unwrap(),
        role: Role::Coordinator,
        profile_id: ProfileId::parse("judgment_claude").unwrap(),
        profile_digest: Digest::parse("b".repeat(64)).unwrap(),
        config_revision: revision.0,
        config_digest: applied.digest,
        target: rex_projects::store::provider_qualification_runtime::ProviderQualificationTarget::AppliedProfile,
    };
    store
        .enqueue_provider_qualification(generation, &request)
        .unwrap();
    assert!(matches!(
        store
            .claim_provider_qualification(generation, 1, 1)
            .unwrap(),
        QualificationClaim::Claimed { .. }
    ));
    store
        .fail_provider_qualification_before_launch(generation, request_id, "fixture_failure")
        .unwrap();
    assert_eq!(
        store
            .provider_qualification_job(request_id)
            .unwrap()
            .unwrap()
            .status,
        ProviderQualificationJobStatus::Failed
    );
}

#[test]
fn provider_status_json_reports_terminal_failure_and_actual_released_slot() {
    let temp = tempfile::tempdir().unwrap();
    let config_path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/fixture/config.toml");
    let state_root = temp.path().join("state");
    let xdg_state_home = temp.path().join("xdg-state");
    let setup = Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "provider_status_state_fixture"])
        .env("REX_PROJECTS_TEST_CONFIG_PATH", &config_path)
        .env("REX_PROJECTS_TEST_STATE_ROOT", &state_root)
        .env("XDG_STATE_HOME", &xdg_state_home)
        .output()
        .unwrap();
    assert!(
        setup.status.success(),
        "could not prepare terminal-state fixture: {}",
        String::from_utf8_lossy(&setup.stderr)
    );

    let request_id = "provider-status-terminal-failure";
    let output = Command::new(env!("CARGO_BIN_EXE_rex-projects"))
        .args(["--config"])
        .arg(&config_path)
        .args(["--state-root"])
        .arg(&state_root)
        .args(["--json", "provider", "status", "--request-id", request_id])
        .env_remove("REX_PROJECTS_AGENT")
        .env_remove("REX_PROJECTS_CONTEXT")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "provider status failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "failed");
    assert!(report["hold_reason"].is_null());
    assert!(
        report["next_safe_action"]
            .as_str()
            .unwrap()
            .contains("terminal")
    );
    assert_eq!(report["execution_slot"]["disposition"], "released");

    let text_output = Command::new(env!("CARGO_BIN_EXE_rex-projects"))
        .args(["--config"])
        .arg(&config_path)
        .args(["--state-root"])
        .arg(&state_root)
        .args(["provider", "status", "--request-id", request_id])
        .env_remove("REX_PROJECTS_AGENT")
        .env_remove("REX_PROJECTS_CONTEXT")
        .output()
        .unwrap();
    assert!(text_output.status.success());
    let text_output = String::from_utf8(text_output.stdout).unwrap();
    assert!(text_output.contains("Execution slot:"));
    assert!(!text_output.contains("Held slot:"));
}

#[test]
#[ignore = "subprocess fixture invoked by the bounded stderr test"]
fn stderr_exit_fixture() {
    use std::io::Write;
    std::io::stderr().write_all(&[b'x'; 20_000]).unwrap();
    std::process::exit(17);
}

#[test]
fn foreground_owner_reports_exit_status_and_bounds_captured_stderr() {
    let mut child = ForegroundOwner::spawn({
        let mut command = Command::new(std::env::current_exe().unwrap());
        command.args(["--exact", "stderr_exit_fixture", "--ignored", "--nocapture"]);
        command
    })
    .expect("spawn stderr fixture");
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        assert!(Instant::now() < deadline, "stderr fixture timed out");
        std::thread::sleep(Duration::from_millis(10));
    };
    let stderr = child.stderr_tail();
    assert_eq!(status.code(), Some(17));
    assert_eq!(stderr.len(), MAX_CAPTURED_STDERR_BYTES);
    assert!(stderr.bytes().all(|byte| byte == b'x'));
}

#[test]
fn unsupported_invocation_is_reported_as_usage_error() {
    let output = Command::new(env!("CARGO_BIN_EXE_rex-projects"))
        .arg("run")
        .output()
        .expect("run unsupported rex-projects command");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8(output.stderr)
            .expect("error output is UTF-8")
            .contains("unrecognized subcommand 'run'")
    );
}

#[test]
fn agent_marker_cannot_submit_human_claim_release() {
    let temp = tempfile::tempdir().unwrap();
    let (config, state, home) = fixture(&temp);
    let mutations: &[&[&str]] = &[
        &["human", "list"],
        &["config", "apply", "--bootstrap"],
        &["runtime", "run", "--once"],
        &["runtime", "stop"],
        &["project", "start", "goal_project"],
        &["project", "pause", "goal_project"],
        &["project", "resume", "goal_project"],
        &["project", "stop", "goal_project"],
        &[
            "ticket",
            "release-claim",
            "github:org/repo",
            "PAY-1",
            "run-1",
            "1",
            "0",
            "--reason",
            "cancel and re-triage",
            "--disposition",
            "cancel",
        ],
    ];
    for marker in ["REX_PROJECTS_AGENT", "REX_PROJECTS_CONTEXT"] {
        for arguments in mutations {
            let output = command(&config, &state, &home)
                .env(marker, "1")
                .args(arguments.iter().copied())
                .output()
                .unwrap();
            assert_eq!(output.status.code(), Some(77), "{marker}: {arguments:?}");
            assert!(String::from_utf8_lossy(&output.stderr).contains("human host context"));
            assert!(
                !state.join("state.sqlite3").exists(),
                "{marker}: {arguments:?}"
            );
        }
    }
}

#[test]
fn public_human_commands_parse_the_acceptance_request_arguments() {
    let temp = tempfile::tempdir().unwrap();
    let (config, state, home) = fixture(&temp);
    let initialized = command(&config, &state, &home)
        .args(["config", "apply", "--bootstrap"])
        .output()
        .unwrap();
    assert!(
        initialized.status.success(),
        "{}",
        String::from_utf8_lossy(&initialized.stderr)
    );

    let listed = command(&config, &state, &home)
        .args(["human", "list", "--project", "operations", "--json"])
        .output()
        .unwrap();
    assert!(
        listed.status.success(),
        "{}{}",
        String::from_utf8_lossy(&listed.stdout),
        String::from_utf8_lossy(&listed.stderr)
    );
    let listed: serde_json::Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert!(listed["requests"].is_array());

    let shown = command(&config, &state, &home)
        .args(["human", "show", "missing-request", "--json"])
        .output()
        .unwrap();
    assert_eq!(shown.status.code(), Some(3));
    let shown: serde_json::Value = serde_json::from_slice(&shown.stdout).unwrap();
    assert_eq!(shown["error"]["code"], "not_found");
    assert_eq!(shown["error"]["message"], "human request was not found");

    let responded = command(&config, &state, &home)
        .args([
            "human",
            "respond",
            "missing-request",
            "--subject-digest",
            &"a".repeat(64),
            "--choice",
            "approve",
            "--explanation",
            "acceptance parser fixture",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(responded.status.code(), Some(4));
    let responded: serde_json::Value = serde_json::from_slice(&responded.stdout).unwrap();
    assert_eq!(responded["error"]["code"], "conflict");
    assert!(
        responded["error"]["message"]
            .as_str()
            .is_some_and(|message| !message.is_empty())
    );
}

#[test]
fn version_json_is_enabled_when_global_flag_precedes_subcommand() {
    let output = Command::new(env!("CARGO_BIN_EXE_rex-projects"))
        .args(["--json", "version"])
        .output()
        .expect("run rex-projects --json version");
    assert!(output.status.success());
    let body: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
}

#[test]
fn config_validation_works_without_creating_state() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let config = root.join("examples/fixture/config.toml");
    let state = tempfile::tempdir().unwrap().path().join("missing-state");
    let output = Command::new(env!("CARGO_BIN_EXE_rex-projects"))
        .args(["--config"])
        .arg(config)
        .args(["--state-root"])
        .arg(&state)
        .args(["--json", "config", "validate"])
        .output()
        .expect("run config validate");
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("\"valid\": true")
    );
    assert!(!state.exists());
}

#[test]
fn project_list_reports_local_snapshot_and_does_not_initialize_missing_state() {
    let temp = tempfile::tempdir().unwrap();
    let (config, state, home) = fixture(&temp);
    let output = command(&config, &state, &home)
        .args(["--json", "project", "list"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["source"], "configured_snapshot");
    assert_eq!(report["freshness"], "configuration_only");
    assert_eq!(report["applied_revision"], serde_json::Value::Null);
    let projects = report["projects"].as_array().unwrap();
    assert_eq!(projects.len(), 2);
    assert_eq!(projects[0]["runtime_observation"], "not_observed");
    assert_eq!(projects[0]["desired_lifecycle"], serde_json::Value::Null);
    assert_eq!(projects[0]["project_epoch"], serde_json::Value::Null);
    assert!(!state.exists());
}

#[test]
fn project_list_identifies_applied_data_as_a_local_snapshot() {
    let temp = tempfile::tempdir().unwrap();
    let (config, state, home) = fixture(&temp);
    let applied = command(&config, &state, &home)
        .args(["config", "apply", "--bootstrap"])
        .output()
        .unwrap();
    assert!(
        applied.status.success(),
        "{}",
        String::from_utf8_lossy(&applied.stderr)
    );
    let output = command(&config, &state, &home)
        .args(["--json", "project", "list"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["freshness"], "local_snapshot");
    assert_eq!(report["source"], "applied_snapshot");
    assert_eq!(report["external_services_queried"], false);
    assert_eq!(
        report["projects"].as_array().unwrap().len(),
        2,
        "{report:#}"
    );
    assert!(report["observed_at_unix"].as_i64().unwrap() > 0);
}

#[test]
fn project_list_uses_applied_projects_when_current_configuration_differs() {
    let temp = tempfile::tempdir().unwrap();
    let (config, state, home) = fixture(&temp);
    let applied = command(&config, &state, &home)
        .args(["config", "apply", "--bootstrap"])
        .output()
        .unwrap();
    assert!(applied.status.success());

    let current = std::fs::read_to_string(&config).unwrap();
    std::fs::write(&config, current.replace("goal_project", "local_project")).unwrap();

    let output = command(&config, &state, &home)
        .args(["--json", "project", "list"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["source"], "applied_snapshot");
    assert_eq!(
        report["projects"]
            .as_array()
            .unwrap()
            .iter()
            .map(|project| project["id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["goal_project", "operations_project"]
    );
    assert_eq!(report["projects"][0]["runtime_observation"], "observed");
}

#[test]
fn policy_explain_marks_capabilities_unobserved_and_emits_merge_instruction_digest() {
    let temp = tempfile::tempdir().unwrap();
    let (config, state, home) = projection_fixture(&temp);
    let output = command(&config, &state, &home)
        .args(["--json", "policy", "explain", "--repository", "example"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["snapshot_source"], "configured_snapshot");
    assert_eq!(report["capabilities"]["status"], "not_observed");
    assert_eq!(report["external_services_queried"], false);
    assert_eq!(
        report["merge_policy"]["instructions"],
        "Follow the repository merge procedure."
    );
    assert_eq!(
        report["merge_policy"]["instructions_sha256"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
    assert!(!state.exists());
}

#[test]
fn policy_explain_uses_applied_canonical_profile_digest() {
    use sha2::Digest as _;

    let temp = tempfile::tempdir().unwrap();
    let (config, state, home) = fixture(&temp);
    let applied = rex_projects::config::load(&config).unwrap();
    let profile =
        &applied.profiles[&rex_projects::domain::ids::ProfileId::parse("worker_codex").unwrap()];
    let canonical = serde_json::to_string(&serde_json::to_value(profile).unwrap()).unwrap();
    let expected = format!("{:x}", sha2::Sha256::digest(canonical.as_bytes()));
    assert_ne!(
        expected,
        format!(
            "{:x}",
            sha2::Sha256::digest(serde_json::to_vec(profile).unwrap())
        )
    );

    let applied_output = command(&config, &state, &home)
        .args(["config", "apply", "--bootstrap"])
        .output()
        .unwrap();
    assert!(applied_output.status.success());

    let profile_config = temp.path().join("profiles/worker_codex/config.toml");
    let local = std::fs::read_to_string(&profile_config).unwrap();
    std::fs::write(
        profile_config,
        local.replace("configured-supported-model", "local-different-model"),
    )
    .unwrap();

    let output = command(&config, &state, &home)
        .args(["--json", "policy", "explain", "--repository", "example"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["snapshot_source"], "applied_snapshot");
    let roles = report["projects"][0]["effective_roles"].as_array().unwrap();
    let worker = roles.iter().find(|role| role["role"] == "Worker").unwrap();
    assert_eq!(worker["profile_digest"], expected);
}

#[test]
fn config_diff_is_read_only_and_reports_normalized_candidate_changes() {
    let temp = tempfile::tempdir().unwrap();
    let (config, state, home) = projection_fixture(&temp);
    let candidate = temp.path().join("candidate.toml");
    let source = std::fs::read_to_string(&config).unwrap();
    std::fs::write(
        &candidate,
        source.replace("base_branch = 'main'", "base_branch = 'trunk'"),
    )
    .unwrap();
    let output = command(&config, &state, &home)
        .args(["--json", "config", "diff", "--candidate"])
        .arg(&candidate)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["baseline"]["source"], "configured_snapshot");
    assert_eq!(report["baseline"]["applied"], false);
    assert_eq!(report["candidate"]["applied"], false);
    assert_eq!(report["candidate_applied"], false);
    assert_eq!(report["state_written"], false);
    assert_eq!(
        report["assessment_invalidation"]["status"],
        "not_established"
    );
    assert!(
        report["changes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| { entry["kind"] == "repository" && entry["id"] == "example" }),
        "{report:#}"
    );
    assert!(!state.exists());
}

#[test]
fn json_validation_error_is_machine_readable_and_never_opens_state() {
    let temp = tempfile::tempdir().unwrap();
    let invalid = temp.path().join("invalid.toml");
    std::fs::write(&invalid, "schema_version = 99\n").unwrap();
    let state = temp.path().join("state");
    let output = Command::new(env!("CARGO_BIN_EXE_rex-projects"))
        .args(["--config"])
        .arg(invalid)
        .args(["--state-root"])
        .arg(&state)
        .args(["--json", "config", "apply", "--bootstrap"])
        .env_remove("REX_PROJECTS_AGENT")
        .env_remove("REX_PROJECTS_CONTEXT")
        .output()
        .expect("run invalid config apply");
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    let body: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(body["error"]["code"], "invalid_request");
    assert!(!state.exists());
}

#[test]
fn version_metadata_matches_the_created_database_schema() {
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path().join("state");
    let config =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/fixture/config.toml");
    let apply = Command::new(env!("CARGO_BIN_EXE_rex-projects"))
        .arg("--config")
        .arg(config)
        .arg("--state-root")
        .arg(&state)
        .args(["config", "apply", "--bootstrap"])
        .env("XDG_STATE_HOME", temp.path().join("xdg-state"))
        .env_remove("REX_PROJECTS_AGENT")
        .env_remove("REX_PROJECTS_CONTEXT")
        .output()
        .unwrap();
    assert!(
        apply.status.success(),
        "{}",
        String::from_utf8_lossy(&apply.stderr)
    );
    let version = Command::new(env!("CARGO_BIN_EXE_rex-projects"))
        .args(["version", "--json"])
        .output()
        .unwrap();
    assert!(version.status.success());
    let metadata: serde_json::Value = serde_json::from_slice(&version.stdout).unwrap();
    let db = rusqlite::Connection::open_with_flags(
        state.join("state.sqlite3"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let actual_schema: i64 = db
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(metadata["database_schema"].as_i64(), Some(actual_schema));
}

#[test]
fn controller_once_publishes_local_project_status_then_releases_ownership() {
    let temp = tempfile::tempdir().unwrap();
    let (config, state, home) = fixture(&temp);
    let apply = command(&config, &state, &home)
        .args(["config", "apply", "--bootstrap"])
        .output()
        .unwrap();
    assert!(
        apply.status.success(),
        "{}",
        String::from_utf8_lossy(&apply.stderr)
    );

    let run = command(&config, &state, &home)
        .args(["runtime", "run", "--once"])
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert!(!state.join("runtime-owner.json").exists());

    let status = command(&config, &state, &home)
        .args(["--json", "status"])
        .output()
        .unwrap();
    assert!(status.status.success());
    let report: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    let status_projects = report["projects"].as_array().unwrap().clone();
    assert_eq!(report["owner"]["active"], false);
    assert_eq!(report["freshness"], "local_snapshot");
    assert_eq!(report["projects"].as_array().unwrap().len(), 2);

    let listed = command(&config, &state, &home)
        .args(["--json", "project", "list"])
        .output()
        .unwrap();
    assert!(listed.status.success());
    let listed: serde_json::Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(listed["source"], "applied_snapshot");
    assert_eq!(listed["projects"].as_array().unwrap().len(), 2);
    for project in listed["projects"].as_array().unwrap() {
        let status = status_projects
            .iter()
            .find(|status| status["id"] == project["id"])
            .unwrap();
        assert_eq!(project["runtime_observation"], "observed");
        assert_eq!(project["desired_lifecycle"], status["desired_lifecycle"]);
        assert_eq!(project["observed_lifecycle"], status["observed_lifecycle"]);
        assert_eq!(project["project_epoch"], status["project_epoch"]);
    }
}

#[cfg(unix)]
#[test]
fn controller_once_leaves_queued_qualification_and_never_uses_mutating_transports() {
    use rex_projects::domain::ids::{Digest, ProfileId, ProjectId};
    use rex_projects::domain::types::Role;
    use rex_projects::store::provider_qualification_runtime::{
        ProviderQualificationRequest, request_digest,
    };
    use sha2::{Digest as _, Sha256};
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().unwrap();
    let (config, state, home) = fixture(&temp);

    let call_log = temp.path().join("rex-calls.log");
    let forbidden_call = temp.path().join("rex-mutation-attempted");
    let provider_marker = temp.path().join("provider-started");
    let provider_stub = home.join("bin/provider-marker");
    std::fs::write(
        &provider_stub,
        "#!/bin/sh\ntouch \"$PROVIDER_MARKER\"\nexit 87\n",
    )
    .unwrap();
    std::fs::set_permissions(&provider_stub, std::fs::Permissions::from_mode(0o755)).unwrap();
    let profile_config = config
        .parent()
        .unwrap()
        .join("profiles/judgment_claude/config.toml");
    let profile = std::fs::read_to_string(&profile_config).unwrap().replace(
        "/absolute/path/to/claude",
        &provider_stub.display().to_string(),
    );
    std::fs::write(profile_config, profile).unwrap();

    let apply = command(&config, &state, &home)
        .args(["config", "apply", "--bootstrap"])
        .output()
        .unwrap();
    assert!(
        apply.status.success(),
        "{}",
        String::from_utf8_lossy(&apply.stderr)
    );

    let loaded = rex_projects::config::load(&config).unwrap();
    let project_id = ProjectId::parse("goal_project").unwrap();
    let profile_id = ProfileId::parse("judgment_claude").unwrap();
    let profile_bytes = serde_json::to_vec(&loaded.profiles[&profile_id]).unwrap();
    let profile_digest = Digest::parse(format!("{:x}", Sha256::digest(profile_bytes))).unwrap();
    let request = ProviderQualificationRequest {
        request_id: "once-queued-qualification".into(),
        project_id,
        role: Role::Supervisor,
        profile_id,
        profile_digest,
        config_revision: 1,
        config_digest: loaded.digest,
        target: rex_projects::store::provider_qualification_runtime::ProviderQualificationTarget::AppliedProfile,
    };
    let request_digest = request_digest(&request).unwrap();
    let connection = rusqlite::Connection::open(state.join("state.sqlite3")).unwrap();
    connection
        .execute(
            "INSERT INTO provider_qualification_jobs(request_id,project_id,role,profile_id,profile_digest,config_revision,config_digest,request_digest,status,controller_generation,created_at_unix,updated_at_unix) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,'queued',1,1,1)",
            rusqlite::params![
                request.request_id,
                request.project_id.as_str(),
                serde_json::to_value(request.role).unwrap().as_str().unwrap(),
                request.profile_id.as_str(),
                request.profile_digest.as_str(),
                request.config_revision,
                request.config_digest.as_str(),
                request_digest.as_str(),
            ],
        )
        .unwrap();
    drop(connection);

    let mut once_command = command(&config, &state, &home);
    once_command
        .args(["runtime", "run", "--once"])
        .env("REX_SESSION", "fixture-session")
        .env("REX_BLOCK", "fixture-block")
        .env("REX_CALL_LOG", &call_log)
        .env("REX_FORBIDDEN_MARKER", &forbidden_call)
        .env("PROVIDER_MARKER", &provider_marker);
    let mut once = ForegroundOwner::spawn(once_command).unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if once.try_wait().unwrap().is_some() {
            break;
        }
        if Instant::now() >= deadline {
            once.terminate();
            panic!("runtime run --once did not exit within 20 seconds");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let run_status = once.wait().unwrap();
    let run_stderr = once.stderr_tail();
    assert!(
        run_status.success(),
        "runtime run --once failed: {run_stderr}"
    );
    assert!(!forbidden_call.exists(), "a Rex mutation was attempted");
    assert!(!provider_marker.exists(), "a provider command was launched");
    let rex_calls = std::fs::read_to_string(&call_log).unwrap();
    assert!(rex_calls.contains("whoami"));
    assert!(rex_calls.contains("api list"));
    assert!(rex_calls.contains("api call session.view"));
    assert!(rex_calls.contains("events -s fixture-session --json"));
    assert!(!state.join("runtime-owner.json").exists());

    let connection = rusqlite::Connection::open(state.join("state.sqlite3")).unwrap();
    let queued: String = connection
        .query_row(
            "SELECT status FROM provider_qualification_jobs WHERE request_id=?1",
            [&request.request_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(queued, "queued");

    let status = command(&config, &state, &home)
        .args(["--json", "status"])
        .output()
        .unwrap();
    assert!(status.status.success());
    let report: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(report["owner"]["active"], false);
    assert_eq!(report["freshness"], "local_snapshot");
}

#[test]
fn provider_status_is_read_only_and_reports_missing_request_ids() {
    let temp = tempfile::tempdir().unwrap();
    let (config, state, home) = fixture(&temp);
    let apply = command(&config, &state, &home)
        .args(["config", "apply", "--bootstrap"])
        .output()
        .unwrap();
    assert!(
        apply.status.success(),
        "{}",
        String::from_utf8_lossy(&apply.stderr)
    );

    let missing_id = command(&config, &state, &home)
        .args(["--json", "provider", "status"])
        .output()
        .unwrap();
    assert_eq!(missing_id.status.code(), Some(2));
    let body: serde_json::Value = serde_json::from_slice(&missing_id.stdout).unwrap();
    assert_eq!(body["error"]["code"], "invalid_request");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("--request-id")
    );

    let missing_request = command(&config, &state, &home)
        .args([
            "--json",
            "provider",
            "status",
            "--request-id",
            "missing-qualification",
        ])
        .output()
        .unwrap();
    assert_eq!(missing_request.status.code(), Some(3));
    let body: serde_json::Value = serde_json::from_slice(&missing_request.stdout).unwrap();
    assert_eq!(body["error"]["code"], "not_found");
    assert_eq!(
        body["error"]["message"],
        "provider qualification request `missing-qualification` was not found"
    );
    assert!(missing_request.stderr.is_empty());
}

#[test]
fn project_start_queues_only_to_the_active_foreground_owner() {
    let temp = tempfile::tempdir().unwrap();
    let (config, state, home) = fixture(&temp);
    let apply = command(&config, &state, &home)
        .args(["config", "apply", "--bootstrap"])
        .output()
        .unwrap();
    assert!(apply.status.success());

    let mut owner_command = command(&config, &state, &home);
    owner_command.args(["runtime", "run"]);
    let mut owner = ForegroundOwner::spawn(owner_command)
        .expect("spawn foreground controller with captured stderr");
    let startup_deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = owner
            .try_wait()
            .expect("poll foreground controller process")
        {
            let stderr = owner.stderr_tail();
            panic!("foreground controller exited during startup ({status}); stderr: {stderr}");
        }
        let status = command(&config, &state, &home)
            .args(["--json", "status"])
            .output()
            .unwrap();
        if status.status.success()
            && serde_json::from_slice::<serde_json::Value>(&status.stdout)
                .is_ok_and(|report| report["owner"]["active"] == true)
        {
            break;
        }
        if Instant::now() >= startup_deadline {
            owner.terminate();
            let stderr = owner.stderr_tail();
            panic!("foreground controller startup timed out after 10s; stderr: {stderr}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let start = command(&config, &state, &home)
        .args([
            "--json",
            "project",
            "start",
            "goal_project",
            "--request-id",
            "start-1",
        ])
        .output()
        .unwrap();
    assert!(
        start.status.success(),
        "{}",
        String::from_utf8_lossy(&start.stdout)
    );
    let report: serde_json::Value = serde_json::from_slice(&start.stdout).unwrap();
    assert_eq!(report["state"], "queued");

    let mut updated_config = std::fs::read_to_string(&config).unwrap();
    updated_config = updated_config.replace(
        "Deliver the example migration.",
        "Deliver the revised example migration.",
    );
    std::fs::write(&config, updated_config).unwrap();
    let mut apply_processes = Vec::new();
    for _ in 0..8 {
        let mut apply = command(&config, &state, &home);
        apply
            .args(["config", "apply", "--expected-revision", "1", "--json"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        apply_processes.push(apply.spawn().unwrap());
    }
    let outputs = apply_processes
        .into_iter()
        .map(|process| process.wait_with_output().unwrap())
        .collect::<Vec<_>>();
    for output in &outputs {
        assert!(
            output.status.success(),
            "config apply stdout: {}; stderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["state"], "queued");
    }
    let mut applied = false;
    for _ in 0..100 {
        let connection = rusqlite::Connection::open(state.join("state.sqlite3")).unwrap();
        let revision: u64 = connection
            .query_row("SELECT revision FROM config_current", [], |row| row.get(0))
            .unwrap();
        let project_revision: u64 = connection
            .query_row(
                "SELECT config_revision FROM projects WHERE project_id='goal_project'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let owner_projection: serde_json::Value = serde_json::from_slice(
            &std::fs::read(state.join("runtime-owner.json")).unwrap_or_default(),
        )
        .unwrap_or_default();
        if revision == 2 && project_revision == 2 && owner_projection["config_revision"] == 2 {
            applied = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    if !applied {
        owner.terminate();
        let stderr = owner.stderr_tail();
        panic!(
            "active controller did not apply and load the durable config snapshot; stderr: {stderr}"
        );
    }

    let mut stale_config = std::fs::read_to_string(&config).unwrap();
    stale_config = stale_config.replace(
        "Deliver the revised example migration.",
        "Try a stale revision update.",
    );
    std::fs::write(&config, stale_config).unwrap();
    let stale = command(&config, &state, &home)
        .args(["config", "apply", "--expected-revision", "1", "--json"])
        .output()
        .unwrap();
    assert!(
        stale.status.success(),
        "request should queue for owner validation: {}",
        String::from_utf8_lossy(&stale.stdout)
    );
    let connection = rusqlite::Connection::open(state.join("state.sqlite3")).unwrap();
    let mut rejected = String::new();
    for _ in 0..100 {
        rejected = connection.query_row(
            "SELECT state FROM controller_commands WHERE kind='config_apply' ORDER BY sequence DESC LIMIT 1",
            [], |row| row.get(0),
        ).unwrap();
        if rejected == "rejected" {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert_eq!(rejected, "rejected");
    let owner_projection: serde_json::Value =
        serde_json::from_slice(&std::fs::read(state.join("runtime-owner.json")).unwrap()).unwrap();
    assert_eq!(
        owner_projection["config_revision"], 2,
        "rejected compare-and-swap must retain the loaded snapshot"
    );

    let stop = command(&config, &state, &home)
        .args(["runtime", "stop", "--request-id", "stop-1"])
        .output()
        .unwrap();
    assert!(stop.status.success());
    let status = owner.wait().unwrap();
    let stderr = owner.stderr_tail();
    assert!(
        status.success(),
        "foreground controller exited with {status}; stderr: {stderr}"
    );
}
