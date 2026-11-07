use std::process::Command;

#[test]
fn internal_capture_helper_requires_host_marker_and_writes_private_protocol() {
    let binary = env!("CARGO_BIN_EXE_rex-projects");
    let denied = Command::new(binary)
        .args(["__internal", "env-capture", "0123456789abcdef"])
        .output()
        .unwrap();
    assert!(!denied.status.success());
    assert!(denied.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&denied.stderr).contains("PATH="));

    let nonce = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let output = Command::new(binary)
        .args(["__internal", "env-capture", nonce])
        .env("REX_PROJECTS_CONTEXT", "environment_capture")
        .env_remove("REX_PROJECTS_AGENT")
        .env(
            "PRIVATE_CAPTURE_TEST_VALUE",
            "must-not-be-printed-as-diagnostic",
        )
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stdout.starts_with(b"\0REX-PROJECTS-ENV\0\x01"));
    assert!(
        output
            .stdout
            .windows(nonce.len())
            .any(|window| window == nonce.as_bytes())
    );
    assert!(!String::from_utf8_lossy(&output.stderr).contains("must-not-be-printed"));
}
