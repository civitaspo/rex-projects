use std::fs;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

pub fn run(state_dir: &Path) -> Result<(), String> {
    fs::create_dir_all(state_dir)
        .map_err(|error| format!("create operations fixture state directory: {error}"))?;

    let mut line = String::new();
    io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|error| format!("read operations fixture request: {error}"))?;
    let request: Value = serde_json::from_str(&line)
        .map_err(|error| format!("parse operations fixture request: {error}"))?;
    let request_id = request
        .get("request_id")
        .cloned()
        .ok_or_else(|| "operations fixture request has no request_id".to_owned())?;
    let method = request
        .get("method")
        .and_then(Value::as_str)
        .ok_or_else(|| "operations fixture request has no method".to_owned())?;
    let params = request
        .get("params")
        .ok_or_else(|| "operations fixture request has no params".to_owned())?;
    let result = match method {
        "adapter.describe" => json!({
            "protocol_version": 1,
            "adapter_kind": "operations",
            "capabilities": [{
                "action_id": "fixture_echo",
                "parameter_schema": {"type": "object"},
                "selector_schema": {"type": "object"},
                "supports_find": true,
                "supports_observe": true,
                "idempotency": "reconcile_by_find"
            }]
        }),
        "operation.invoke" => {
            let action_id = string(params, "action_id")?;
            let operation_id = string(&request, "operation_id")?;
            let path = state_path(state_dir, operation_id)?;
            let stored = json!({
                "operation_id": operation_id,
                "correlation_key": params["correlation_key"],
                "action_id": params["action_id"],
                "target_id": params["target_id"],
                "repository_id": params["repository_id"],
                "environment": params["environment"],
                "source_sha": params["source_sha"],
                "external_reference": format!("fixture-run:{operation_id}"),
                "receipt": {"simulated": true}
            });
            if action_id == "fixture_lost_reply" && !path.exists() {
                write_json(&path, &stored)?;
                return Err("fixture intentionally dropped the first invoke reply".into());
            }
            if !path.exists() {
                write_json(&path, &stored)?;
            }
            json!({
                "outcome": "accepted",
                "external_reference": stored["external_reference"],
                "receipt": stored["receipt"]
            })
        }
        "operation.find" => {
            let path = state_path(state_dir, string(params, "operation_id")?)?;
            if let Some(stored) = read_json_if_present(&path)? {
                for field in [
                    "operation_id",
                    "correlation_key",
                    "action_id",
                    "target_id",
                    "repository_id",
                    "environment",
                    "source_sha",
                ] {
                    if stored[field] != params[field] {
                        return Err(format!("stored operation does not match `{field}`"));
                    }
                }
                json!({
                    "outcome": "found",
                    "operation_id": stored["operation_id"],
                    "correlation_key": stored["correlation_key"],
                    "action_id": stored["action_id"],
                    "target_id": stored["target_id"],
                    "repository_id": stored["repository_id"],
                    "environment": stored["environment"],
                    "source_sha": stored["source_sha"],
                    "external_reference": stored["external_reference"],
                    "receipt": stored["receipt"]
                })
            } else {
                json!({
                    "outcome": "absent",
                    "operation_id": params["operation_id"],
                    "correlation_key": params["correlation_key"],
                    "action_id": params["action_id"],
                    "target_id": params["target_id"],
                    "repository_id": params["repository_id"],
                    "environment": params["environment"],
                    "source_sha": params["source_sha"],
                    "observed_at": "2026-01-01T00:00:00Z",
                    "proof_scope": "fixture-local-deterministic-store"
                })
            }
        }
        "operation.observe" => json!({
            "provider_instance": "fixture-local",
            "external_run_id": params["external_reference"].as_str().unwrap_or("fixture-run"),
            "operation_id": request["operation_id"],
            "correlation_key": params["correlation_key"],
            "action_id": params["action_id"],
            "target_id": params["target_id"],
            "repository_id": params["repository_id"],
            "environment": params["environment"],
            "source_sha": params["source_sha"],
            "observed_at": "2026-01-01T00:00:00Z",
            "status": "unknown",
            "evidence": [],
            "jobs": {}
        }),
        other => return Err(format!("unsupported operations fixture method `{other}`")),
    };

    let response = json!({
        "schema_version": 1,
        "request_id": request_id,
        "result": result
    });
    serde_json::to_writer(io::stdout().lock(), &response)
        .map_err(|error| format!("write operations fixture response: {error}"))?;
    io::stdout()
        .write_all(b"\n")
        .map_err(|error| format!("finish operations fixture response: {error}"))
}

fn string<'a>(value: &'a Value, field: &str) -> Result<&'a str, String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("operations fixture request has no string `{field}`"))
}

fn state_path(state_dir: &Path, operation_id: &str) -> Result<PathBuf, String> {
    if operation_id.is_empty()
        || !operation_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err("operations fixture operation_id contains unsafe characters".into());
    }
    Ok(state_dir.join(format!("{operation_id}.json")))
}

fn write_json(path: &Path, value: &Value) -> Result<(), String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("serialize operations fixture state: {error}"))?;
    fs::write(path, bytes).map_err(|error| format!("persist operations fixture state: {error}"))
}

fn read_json_if_present(path: &Path) -> Result<Option<Value>, String> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|error| format!("parse operations fixture state: {error}")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("read operations fixture state: {error}")),
    }
}
