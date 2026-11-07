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
    let mut command = Command::new(env!("CARGO_BIN_EXE_rex-projects"));
    command
        .args(["--config"])
        .arg(config)
        .args(["--state-root"])
        .arg(state)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_STATE_HOME", home.join("state"));
    command
}

fn fixture(
    temp: &tempfile::TempDir,
) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let config = temp.path().join("factory.toml");
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/fixture/config.toml"),
    )
    .unwrap();
    std::fs::write(
        &config,
        source.replacen(
            "schema_version = 1",
            &format!(
                "schema_version = 1\nstate_root = \"{}\"",
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
        for file in ["config.toml", "instructions.md"] {
            std::fs::copy(
                profile_source.join(profile).join(file),
                destination.join(file),
            )
            .unwrap();
        }
    }
    let state = temp.path().join("runtime");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
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

#[test]
fn foreground_owner_reports_exit_status_and_bounds_captured_stderr() {
    let mut child = ForegroundOwner::spawn({
        let mut command = Command::new("python3");
        command.args([
            "-c",
            "import sys; sys.stderr.write('x' * 20000); sys.exit(17)",
        ]);
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
    assert_eq!(report["owner"]["active"], false);
    assert_eq!(report["freshness"], "local_snapshot");
    assert_eq!(report["projects"].as_array().unwrap().len(), 2);
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
    let apply = command(&config, &state, &home)
        .args(["config", "apply", "--expected-revision", "1", "--json"])
        .output()
        .unwrap();
    assert!(
        apply.status.success(),
        "{}",
        String::from_utf8_lossy(&apply.stdout)
    );
    let apply_report: serde_json::Value = serde_json::from_slice(&apply.stdout).unwrap();
    assert_eq!(apply_report["state"], "queued");
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
    assert!(
        applied,
        "active controller did not apply and load the durable config snapshot"
    );

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
