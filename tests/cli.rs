use std::process::Command;

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
fn cargo_version_argument_is_compatible_with_release_probes() {
    let output = Command::new(env!("CARGO_BIN_EXE_rex-projects"))
        .arg(env!("CARGO_PKG_VERSION"))
        .output()
        .expect("run rex-projects with a version argument");
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
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
