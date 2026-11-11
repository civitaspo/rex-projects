use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rex_projects::process::{ProcessRequest, run};
use serde_json::{Value, json};

const PROBE_TIMEOUT: Duration = Duration::from_secs(10);
const SHUTDOWN_GRACE: Duration = Duration::from_secs(2);
const OUTPUT_LIMIT: usize = 64 * 1024;

/// Refuse to create resources until the configured binaries and disposable Rex identity match.
/// The full Project driver is deliberately reported as unsupported until its host transitions are
/// callable from the public CLI; protocol fixtures never stand in for product success.
pub fn preflight(
    cli: &Path,
    rex: &Path,
    rex_server: &str,
    expected_instance: &str,
    rex_session: &str,
    fixture_root: &Path,
) -> Result<bool, String> {
    let mut missing = Vec::new();
    if !valid_executable(cli) {
        missing.push("product CLI path is not an executable absolute path");
    }
    if !valid_executable(rex) {
        missing.push("Rex path is not an executable absolute path");
    }
    if !fixture_root.is_absolute() || fixture_root.exists() {
        missing.push("fixture root must be a new absolute path");
    }
    if expected_instance.trim().is_empty()
        || rex_server.trim().is_empty()
        || rex_session.trim().is_empty()
    {
        missing.push("Rex endpoint, expected instance, and owned session must be explicit");
    }

    if missing.is_empty() {
        match inspect_rex(rex, rex_server) {
            Ok(identity) if identity == expected_instance => {}
            Ok(_) => missing.push("Rex instance ID does not match the requested disposable server"),
            Err(_) => missing.push("Rex whoami JSON is unavailable or does not expose instance_id"),
        }
    }

    if missing.is_empty() {
        for (path, args, label) in required_cli_probes(cli) {
            match bounded_process(path, &args, None) {
                Ok(output) if output.status.is_some_and(|status| status.success()) => {}
                _ => missing.push(label),
            }
        }
    }

    if !missing.is_empty() {
        let report = json!({
            "status": "UNSUPPORTED",
            "product_cli": cli,
            "rex_server": rex_server,
            "expected_instance": expected_instance,
            "rex_session": rex_session,
            "fixture_root": fixture_root,
            "missing_capabilities": missing,
            "emulated_provider_qualification": false,
            "resources_created": false
        });
        println!(
            "{}",
            serde_json::to_string(&report).map_err(|error| error.to_string())?
        );
        return Ok(false);
    }
    Ok(true)
}

fn valid_executable(path: &Path) -> bool {
    path.is_absolute() && path.is_file() && {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::metadata(path).is_ok_and(|metadata| metadata.permissions().mode() & 0o111 != 0)
        }
        #[cfg(not(unix))]
        {
            true
        }
    }
}

fn inspect_rex(rex: &Path, server: &str) -> Result<String, String> {
    let mut args = vec![OsString::from("--autostart=false")];
    if !server.is_empty() {
        args.extend([OsString::from("--server"), OsString::from(server)]);
    }
    args.extend([OsString::from("whoami"), OsString::from("--json")]);
    let output = bounded_process(rex, &args, None)?;
    if !output.status.is_some_and(|status| status.success()) {
        return Err("Rex identity command failed".into());
    }
    let value: Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| "Rex identity output is not JSON".to_owned())?;
    value
        .get("instance_id")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| "Rex whoami did not return instance_id".into())
}

fn required_cli_probes(cli: &Path) -> Vec<(&Path, Vec<OsString>, &'static str)> {
    let path = cli;
    [
        (&["--help"][..], "product CLI help is unavailable"),
        (
            &["config", "validate", "--help"][..],
            "public config validation command is unavailable",
        ),
        (
            &["runtime", "run", "--help"][..],
            "foreground runtime command is unavailable",
        ),
        (
            &["project", "start", "--help"][..],
            "Project start command is unavailable",
        ),
        (
            &["project", "status", "--help"][..],
            "Project status command is unavailable",
        ),
        (
            &["human", "respond", "--help"][..],
            "human response command is unavailable",
        ),
        (
            &["dashboard", "--help"][..],
            "dashboard command is unavailable",
        ),
        (
            &["provider", "qualify", "--help"][..],
            "provider qualification command is unavailable",
        ),
        (
            &["--json", "provider", "status", "--help"][..],
            "provider qualification status command is unavailable",
        ),
    ]
    .into_iter()
    .map(|(words, label)| {
        (
            path,
            words.iter().map(|word| OsString::from(*word)).collect(),
            label,
        )
    })
    .collect()
}

fn bounded_process(
    executable: &Path,
    args: &[OsString],
    cwd: Option<&Path>,
) -> Result<rex_projects::process::ProcessOutput, String> {
    run(ProcessRequest {
        executable: executable.to_path_buf(),
        args: args.to_vec(),
        stdin: Vec::new(),
        cwd: cwd.map(PathBuf::from),
        clear_environment: true,
        environment: BTreeMap::from([
            (
                OsString::from("PATH"),
                std::env::var_os("PATH").unwrap_or_default(),
            ),
            (OsString::from("TERM"), OsString::from("dumb")),
            (OsString::from("NO_COLOR"), OsString::from("1")),
            (OsString::from("GH_PROMPT_DISABLED"), OsString::from("1")),
        ]),
        timeout: PROBE_TIMEOUT,
        shutdown_grace: SHUTDOWN_GRACE,
        stdout_limit: OUTPUT_LIMIT,
        stderr_tail_limit: OUTPUT_LIMIT,
    })
    .map_err(|error| error.to_string())
}
