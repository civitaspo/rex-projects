use std::process::Command;

#[test]
fn internal_capture_helper_requires_marker_and_writes_only_to_private_file() {
    let binary = env!("CARGO_BIN_EXE_rex-projects");
    let denied = Command::new(binary)
        .args([
            "__internal",
            "env-capture",
            "/tmp/not-an-environment-file",
            "0123456789abcdef",
        ])
        .env("PRIVATE_CAPTURE_TEST_VALUE", "must-not-be-printed")
        .output()
        .unwrap();
    assert!(!denied.status.success());
    assert!(denied.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&denied.stderr).contains("must-not-be-printed"));

    let nonce = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let directory = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let output_path = directory.path().join("capture.bin");
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&output_path)
        .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&output_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    drop(file);

    let output = Command::new(binary)
        .args([
            "__internal",
            "env-capture",
            output_path.to_str().unwrap(),
            nonce,
        ])
        .env("REX_PROJECTS_CONTEXT", "environment_capture")
        .env_remove("REX_PROJECTS_AGENT")
        .env("PRIVATE_CAPTURE_TEST_VALUE", "must-not-be-printed")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "helper failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("must-not-be-printed"));

    let private_frame = std::fs::read(output_path).unwrap();
    assert!(private_frame.starts_with(b"\0REX-PROJECTS-ENV\0\x01"));
    assert!(
        private_frame
            .windows(nonce.len())
            .any(|window| window == nonce.as_bytes())
    );
    assert!(
        private_frame
            .windows(b"must-not-be-printed".len())
            .any(|window| window == b"must-not-be-printed")
    );
}
