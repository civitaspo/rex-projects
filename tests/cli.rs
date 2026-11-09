use std::collections::VecDeque;
use std::io::{self, Read};
use std::process::Command;
use std::process::{Child, ExitStatus, Stdio};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

#[path = "support/linux_process_snapshot.rs"]
mod linux_process_snapshot;

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

#[test]
fn linux_owner_snapshot_is_bounded_and_omits_syscall_arguments() {
    fn write_stat(path: &std::path::Path, pid: u32, parent_pid: u32, start_ticks: u64) {
        let mut fields = vec!["S".to_owned(), parent_pid.to_string()];
        while fields.len() < 19 {
            fields.push("0".into());
        }
        fields.push(start_ticks.to_string());
        std::fs::write(
            path,
            format!("{pid} (fixture process) {}", fields.join(" ")),
        )
        .unwrap();
    }

    let temp = tempfile::tempdir().unwrap();
    let owner_pid = 123;
    let task_dir = temp.path().join(owner_pid.to_string()).join("task");
    std::fs::create_dir_all(&task_dir).unwrap();
    write_stat(
        &temp.path().join(owner_pid.to_string()).join("stat"),
        owner_pid,
        7,
        456,
    );
    for tid in owner_pid + 1..owner_pid + 8 + 3 {
        let thread_dir = task_dir.join(tid.to_string());
        std::fs::create_dir_all(&thread_dir).unwrap();
        write_stat(
            &thread_dir.join("stat"),
            tid,
            7,
            456 + u64::from(tid - owner_pid),
        );
        std::fs::write(thread_dir.join("wchan"), "futex_wait_queue\n").unwrap();
        std::fs::write(thread_dir.join("syscall"), "202 987654321 123456789\n").unwrap();
    }
    let leader_dir = task_dir.join(owner_pid.to_string());
    std::fs::create_dir_all(&leader_dir).unwrap();
    write_stat(&leader_dir.join("stat"), owner_pid, 7, 456);
    std::fs::write(leader_dir.join("wchan"), "futex_wait_queue\n").unwrap();
    std::fs::write(leader_dir.join("syscall"), "202 987654321 123456789\n").unwrap();
    std::fs::write(leader_dir.join("children"), "456\n").unwrap();
    let child_dir = temp.path().join("456");
    let child_task_dir = child_dir.join("task/456");
    std::fs::create_dir_all(&child_task_dir).unwrap();
    write_stat(&child_dir.join("stat"), 456, owner_pid, 789);
    write_stat(&child_task_dir.join("stat"), 456, owner_pid, 789);
    std::fs::write(child_task_dir.join("wchan"), "do_poll.constprop.0\n").unwrap();
    std::fs::write(child_task_dir.join("syscall"), "7 555444 333222\n").unwrap();

    let host_job_dir = task_dir.join("124");
    std::fs::write(host_job_dir.join("comm"), "rex-host-job-invoke\n").unwrap();
    let snapshot = linux_process_snapshot::snapshot_at_with_thread_limit(
        temp.path(),
        owner_pid,
        None,
        None,
        true,
        4,
    );
    assert!(
        snapshot.contains("pid=123,ppid=7,state=S,start_ticks=456"),
        "{snapshot}"
    );
    assert!(snapshot.contains("tid=124,role=host_job,state=S,wchan=futex_wait_queue,syscall=202"));
    assert!(
        snapshot.find("tid=124,role=host_job").unwrap()
            < snapshot.find("tid=123,role=leader").unwrap()
    );
    assert!(snapshot.contains(
        "pid=456,start_ticks=789,tid=456,role=leader,state=S,wchan=do_poll.constprop.0,syscall=7"
    ), "{snapshot}");
    assert!(snapshot.contains("wchan=futex_wait_queue,syscall=202"));
    assert!(snapshot.contains("threads_truncated=true"));
    assert_eq!(snapshot.matches("tid=").count(), 4);
    assert!(!snapshot.contains("987654321"));
    assert!(!snapshot.contains("fixture process"));

    let child = linux_process_snapshot::snapshot_at_with_thread_limit(
        temp.path(),
        456,
        Some("linux-start-ticks:789"),
        Some(owner_pid),
        false,
        8,
    );
    assert!(child.contains("pid=456,ppid=123,state=S,start_ticks=789"));
    assert!(
        linux_process_snapshot::snapshot_at_with_thread_limit(
            temp.path(),
            456,
            Some("linux-start-ticks:wrong"),
            Some(owner_pid),
            false,
            8,
        )
        .contains("identity_changed=true")
    );
    assert!(
        linux_process_snapshot::snapshot_at_with_thread_limit(
            temp.path(),
            456,
            Some("linux-start-ticks:789"),
            Some(7),
            false,
            8,
        )
        .contains("identity_changed=true")
    );
}

fn owner_process_snapshot(owner_pid: u32) -> String {
    #[cfg(target_os = "linux")]
    {
        linux_process_snapshot::snapshot(owner_pid, None, None, true)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = owner_pid;
        "unsupported_platform".into()
    }
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
        inputs: vec![rex_projects::agent_api::AgentWakeItem {
            wake_input_id: 5,
            source_type: "agent_result".into(),
            source_id: source_id.clone(),
            source_revision: 1,
            priority: 7,
            payload_json: serde_json::json!({"structured_result":{"summary":"Planner output"}}),
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
        }],
    };
    snapshot.digest = snapshot.content_digest().unwrap();
    snapshot
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
    let mut status_polls = 0;
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
        status_polls += 1;
        let report = serde_json::from_slice::<serde_json::Value>(&status.stdout);
        let active = report
            .as_ref()
            .map(|report| report["owner"]["active"].clone())
            .map_err(ToString::to_string);
        let status_stdout = String::from_utf8_lossy(&status.stdout);
        let status_stderr = String::from_utf8_lossy(&status.stderr);
        let status_diagnostic = format!(
            "exit={:?}, success={}, owner_active={active:?}, stdout={:?}, stderr={:?}",
            status.status.code(),
            status.status.success(),
            status_stdout.chars().take(2048).collect::<String>(),
            status_stderr.chars().take(2048).collect::<String>(),
        );
        if status.status.success() && report.is_ok_and(|report| report["owner"]["active"] == true) {
            break;
        }
        if Instant::now() >= startup_deadline {
            let owner_pid = owner.child.id();
            let process_snapshot = owner_process_snapshot(owner_pid);
            owner.terminate();
            let stderr = owner.stderr_tail();
            panic!(
                "foreground controller startup timed out after 10s; polls={status_polls}; last status={status_diagnostic}; owner_process_snapshot={process_snapshot:?}; controller stderr: {stderr}"
            );
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
    let mut apply_polls = 0;
    let mut last_applied_state = String::from("no reload observation received");
    for _ in 0..100 {
        apply_polls += 1;
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
        last_applied_state = format!(
            "config_revision={revision}, project_revision={project_revision}, owner_projection={owner_projection}"
        );
        if revision == 2 && project_revision == 2 && owner_projection["config_revision"] == 2 {
            applied = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    if !applied {
        let controller_status = owner.try_wait().unwrap();
        owner.terminate();
        let stderr = owner.stderr_tail();
        panic!(
            "active controller did not apply and load the durable config snapshot after {apply_polls} polls; last state: {last_applied_state}; controller status: {controller_status:?}; stderr: {stderr}"
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
