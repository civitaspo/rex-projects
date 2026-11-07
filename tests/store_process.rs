use std::fs;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use rex_projects::store::ConfigStore;

const CHILD_MODE: &str = "REX_PROJECTS_STORE_FIXTURE_MODE";
const STATE_ROOT: &str = "REX_PROJECTS_STORE_FIXTURE_STATE_ROOT";
const READY_FILE: &str = "REX_PROJECTS_STORE_FIXTURE_READY";

#[test]
fn owner_fixture_child() {
    let Ok(mode) = std::env::var(CHILD_MODE) else {
        return;
    };
    let state_root = PathBuf::from(std::env::var_os(STATE_ROOT).unwrap());
    match mode.as_str() {
        "hold" => {
            let _store = ConfigStore::open(&state_root).unwrap();
            fs::write(std::env::var_os(READY_FILE).unwrap(), b"ready").unwrap();
            loop {
                thread::sleep(Duration::from_secs(60));
            }
        }
        "probe" => {
            let error = match ConfigStore::open(&state_root) {
                Ok(_) => panic!("a second process acquired the machine controller lock"),
                Err(error) => error,
            };
            assert!(error.contains("machine controller lock is held"), "{error}");
        }
        "reopen" => {
            let _store = ConfigStore::open(&state_root).unwrap();
        }
        other => panic!("unknown fixture mode {other}"),
    }
}

#[test]
fn separate_state_roots_share_process_lock_and_recover_after_owner_death() {
    let temp = tempfile::tempdir().unwrap();
    let xdg_state = temp.path().join("xdg-state");
    let owner_root = temp.path().join("owner-state");
    let contender_root = temp.path().join("contender-state");
    let ready = temp.path().join("owner-ready");
    let test_binary = std::env::current_exe().unwrap();

    let mut owner = spawn_fixture(&test_binary, "hold", &owner_root, &xdg_state, Some(&ready));
    wait_for_file(&ready, &mut owner);

    let mut contender = spawn_fixture(&test_binary, "probe", &contender_root, &xdg_state, None);
    assert!(contender.wait().unwrap().success());

    owner.kill().unwrap();
    owner.wait().unwrap();

    let mut recovered = spawn_fixture(&test_binary, "reopen", &contender_root, &xdg_state, None);
    assert!(recovered.wait().unwrap().success());
}

fn spawn_fixture(
    test_binary: &std::path::Path,
    mode: &str,
    state_root: &std::path::Path,
    xdg_state: &std::path::Path,
    ready: Option<&std::path::Path>,
) -> Child {
    let mut command = Command::new(test_binary);
    command
        .arg("--exact")
        .arg("owner_fixture_child")
        .arg("--nocapture")
        .env(CHILD_MODE, mode)
        .env(STATE_ROOT, state_root)
        .env("XDG_STATE_HOME", xdg_state)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(ready) = ready {
        command.env(READY_FILE, ready);
    }
    command.spawn().unwrap()
}

fn wait_for_file(path: &std::path::Path, child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if path.exists() {
            return;
        }
        if let Some(status) = child.try_wait().unwrap() {
            panic!("owner fixture exited before acquiring lock: {status}");
        }
        thread::sleep(Duration::from_millis(20));
    }
    child.kill().unwrap();
    panic!("timed out waiting for owner fixture lock");
}
