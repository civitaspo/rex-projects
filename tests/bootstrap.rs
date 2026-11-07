#![cfg(unix)]

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Barrier};

use serde_json::Value;
use sha2::{Digest, Sha256};

fn sha256(path: &std::path::Path) -> String {
    let digest = Sha256::digest(fs::read(path).unwrap());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
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
                fs::hard_link(source, destination)
            })
        })
        .collect();
    let results: Vec<_> = attempts
        .into_iter()
        .map(|attempt| attempt.join().unwrap())
        .collect();

    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| result
                .as_ref()
                .is_err_and(|error| error.kind() == std::io::ErrorKind::AlreadyExists))
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
    assert!(fs::hard_link(&source, &symlink_destination).is_err());
    assert!(
        fs::symlink_metadata(&symlink_destination)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read(&outside).unwrap(), b"preserve me");

    let directory_destination = temp.path().join("directory-winner");
    fs::create_dir(&directory_destination).unwrap();
    assert!(fs::hard_link(&source, &directory_destination).is_err());
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
