#![cfg(unix)]

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Barrier};
use std::time::Duration;

use rex_projects::process::{ProcessOutput, ProcessRequest, run};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn sha256(path: &std::path::Path) -> String {
    let digest = Sha256::digest(fs::read(path).unwrap());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn link(source: &Path, destination: &Path) -> Result<ProcessOutput, String> {
    let search_path =
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()).collect::<Vec<_>>();
    let executable = search_path
        .iter()
        .map(|directory| directory.join("link"))
        .find(|path| {
            fs::metadata(path).is_ok_and(|metadata| {
                metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
            })
        })
        .ok_or_else(|| "could not resolve the host link executable".to_owned())?;
    run(ProcessRequest {
        executable,
        args: vec![
            source.as_os_str().to_owned(),
            destination.as_os_str().to_owned(),
        ],
        stdin: Vec::new(),
        cwd: None,
        clear_environment: true,
        environment: Default::default(),
        timeout: Duration::from_secs(2),
        shutdown_grace: Duration::from_millis(100),
        stdout_limit: 1024,
        stderr_tail_limit: 2048,
    })
    .map_err(|error| error.to_string())
}

#[test]
fn hard_link_publication_is_atomic_no_replace() {
    let temp = tempfile::Builder::new()
        .prefix("rex-projects link ")
        .tempdir()
        .unwrap();
    let source = temp.path().join("staging/rex-projects");
    let destination = temp.path().join("cache/rex-projects");
    fs::create_dir_all(source.parent().unwrap()).unwrap();
    fs::create_dir_all(destination.parent().unwrap()).unwrap();
    fs::write(&source, b"verified fixture executable\n").unwrap();

    let barrier = Arc::new(Barrier::new(8));
    let attempts: Vec<_> = (0..8)
        .map(|_| {
            let barrier = Arc::clone(&barrier);
            let source = source.clone();
            let destination = destination.clone();
            std::thread::spawn(move || {
                barrier.wait();
                link(&source, &destination)
            })
        })
        .collect();
    let results: Vec<_> = attempts
        .into_iter()
        .map(|attempt| attempt.join().unwrap())
        .collect();

    assert!(results.iter().all(|result| result.is_ok()));
    let results = results.into_iter().map(Result::unwrap).collect::<Vec<_>>();
    assert!(
        results
            .iter()
            .all(|result| !result.timed_out && result.cleanup_confirmed)
    );
    let successes = results
        .iter()
        .filter(|result| {
            result
                .status
                .as_ref()
                .is_some_and(|status| status.success())
        })
        .count();
    assert_eq!(successes, 1, "unexpected link utility results: {results:?}");
    assert_eq!(
        results
            .iter()
            .filter(|result| result
                .status
                .as_ref()
                .is_some_and(|status| !status.success()))
            .count(),
        7
    );
    assert_eq!(fs::read(&destination).unwrap(), fs::read(&source).unwrap());
    assert_eq!(
        fs::metadata(&destination).unwrap().ino(),
        fs::metadata(&source).unwrap().ino()
    );

    let outside = temp.path().join("outside");
    let symlink_destination = temp.path().join("symlink-winner");
    fs::write(&outside, b"preserve me").unwrap();
    symlink(&outside, &symlink_destination).unwrap();
    let symlink_result = link(&source, &symlink_destination).unwrap();
    assert!(!symlink_result.status.unwrap().success());
    assert!(
        fs::symlink_metadata(&symlink_destination)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read(&outside).unwrap(), b"preserve me");

    let directory_destination = temp.path().join("directory-winner");
    fs::create_dir(&directory_destination).unwrap();
    let directory_result = link(&source, &directory_destination).unwrap();
    assert!(!directory_result.status.unwrap().success());
    assert!(directory_destination.is_dir());
}

#[test]
fn copied_cli_snapshot_runs_from_a_path_with_spaces_and_reports_version() {
    let temp = tempfile::Builder::new()
        .prefix("rex-projects bootstrap ")
        .tempdir()
        .unwrap();
    let source = PathBuf::from(env!("CARGO_BIN_EXE_rex-projects"));
    let snapshot = temp.path().join("rex-projects");
    fs::copy(&source, &snapshot).unwrap();
    fs::set_permissions(&snapshot, fs::Permissions::from_mode(0o700)).unwrap();

    let expected_digest = sha256(&source);
    assert_eq!(sha256(&snapshot), expected_digest);
    assert!(snapshot.is_absolute());
    assert!(snapshot.to_string_lossy().contains(' '));

    let result = Command::new(&snapshot)
        .args(["version", "--json"])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let metadata: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(metadata["name"], "rex-projects");
    assert_eq!(metadata["version"], env!("CARGO_PKG_VERSION"));
    assert!(
        metadata["target"]
            .as_str()
            .is_some_and(|target| !target.is_empty())
    );
    assert_eq!(metadata["cli_protocol"], 1);
    assert!(
        metadata["database_schema"]
            .as_u64()
            .is_some_and(|schema| schema > 0)
    );
    assert!(metadata["dirty"].is_boolean());
}
