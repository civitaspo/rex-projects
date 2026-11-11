use std::ffi::OsString;
use std::path::Path;

use serde_json::Value;

use crate::providers::{Invocation, InvocationInput, decode_projected_result};

pub(super) fn build(input: InvocationInput<'_>) -> Result<Invocation, String> {
    let InvocationInput {
        executable,
        prefix,
        role_contract,
        prompt,
        paths,
        conversation_id,
        model,
        effort,
        codex_options,
        ..
    } = input;
    let mut args: Vec<OsString> = prefix;
    if let Some(control_dir) = paths.control_dir {
        validate_control_dir(control_dir)?;
        args.extend(["--add-dir".into(), control_dir.as_os_str().to_owned()]);
    }
    args.extend([
        "--no-daemon".into(),
        "--config".into(),
        format!(
            "developer_instructions={}",
            serde_json::to_string(role_contract).map_err(|e| e.to_string())?
        )
        .into(),
    ]);
    if let Some(model) = model {
        args.extend(["--model".into(), model.into()]);
    }
    if let Some(effort) = effort {
        args.extend([
            "--config".into(),
            format!("model_reasoning_effort={effort}").into(),
        ]);
    }
    if codex_options.is_some_and(|value| value.approve_for_me) {
        args.push("--approve-for-me".into());
    }
    args.extend([
        "--sandbox".into(),
        "workspace-write".into(),
        "--ask-for-approval".into(),
        "never".into(),
        "exec".into(),
    ]);
    if let Some(conversation_id) = conversation_id {
        validate_conversation_id(conversation_id)?;
        args.extend([
            "resume".into(),
            "--skip-git-repo-check".into(),
            conversation_id.into(),
        ]);
    } else {
        args.push("--skip-git-repo-check".into());
    }
    args.extend([
        "--json".into(),
        "--output-schema".into(),
        paths.schema_path.as_os_str().to_owned(),
        prompt.into(),
    ]);
    Ok(Invocation {
        executable,
        args,
        effective_mode: "workspace-write; approvals never; automatic provider execution",
    })
}

fn validate_control_dir(control_dir: &Path) -> Result<(), String> {
    if !control_dir.is_absolute() {
        return Err("Codex run control directory must be absolute".into());
    }
    let metadata = std::fs::symlink_metadata(control_dir)
        .map_err(|_| "Codex run control directory is unavailable")?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("Codex run control directory must be a real directory".into());
    }
    let canonical = control_dir
        .canonicalize()
        .map_err(|_| "Codex run control directory is unavailable")?;
    if canonical != control_dir {
        return Err("Codex run control directory must be canonical".into());
    }
    Ok(())
}

pub(super) fn parse_result(
    stdout: &str,
    schema: &Value,
) -> Result<(Option<String>, Value), String> {
    let mut thread_id = None;
    let mut result_text = None;
    let mut turn_failed = false;
    let mut successful_terminal_events = 0_u8;
    for line in stdout.lines() {
        let Ok(event) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        match event.get("type").and_then(Value::as_str) {
            Some("thread.started") => {
                if let Some(id) = event.get("thread_id").and_then(Value::as_str) {
                    validate_conversation_id(id)?;
                    if thread_id.as_deref().is_some_and(|old| old != id) {
                        return Err("Codex returned conflicting thread identities".into());
                    }
                    thread_id = Some(id.to_owned());
                }
            }
            Some("item.completed") => {
                let Some(item) = event.get("item") else {
                    continue;
                };
                if item.get("type").and_then(Value::as_str) == Some("agent_message")
                    && let Some(text) = item.get("text").and_then(Value::as_str)
                {
                    result_text = Some(text.to_owned());
                }
            }
            Some("turn.completed") => {
                if successful_terminal_events != 0 {
                    return Err("Codex returned multiple terminal events".into());
                }
                if result_text.is_none() {
                    return Err("Codex completed before its final agent message".into());
                }
                match event.get("is_error") {
                    Some(Value::Bool(true)) => turn_failed = true,
                    Some(Value::Bool(false)) | None => successful_terminal_events = 1,
                    Some(_) => return Err("Codex terminal error flag is malformed".into()),
                }
            }
            Some("turn.failed") => {
                if successful_terminal_events != 0 {
                    return Err("Codex returned a failure after completing the turn".into());
                }
                turn_failed = true;
            }
            _ => {}
        }
    }
    if turn_failed {
        return Err("Codex reported a failed turn".into());
    }
    if successful_terminal_events != 1 {
        return Err("Codex did not report a successful terminal event".into());
    }
    let result_text = result_text.ok_or("Codex did not produce a final agent message")?;
    let projected_result: Value =
        serde_json::from_str(&result_text).map_err(|_| "Codex final message is not valid JSON")?;
    let result = decode_projected_result(&projected_result, schema)?;
    Ok((thread_id, result))
}

fn validate_conversation_id(value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        Err("Codex conversation ID is malformed".into())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use serde_json::json;

    use super::{build, parse_result};
    use crate::providers::{InvocationInput, InvocationPaths};

    fn build_args(conversation_id: Option<&str>) -> Vec<String> {
        let schema = json!({"type":"object"});
        build(InvocationInput {
            executable: "/usr/bin/codex".into(),
            prefix: vec![],
            role_contract: "Follow the role contract.",
            prompt: "Complete the assigned turn.",
            schema: &schema,
            paths: InvocationPaths {
                schema_path: Path::new("/tmp/result-schema.json"),
                control_dir: None,
            },
            conversation_id,
            model: None,
            effort: None,
            codex_options: None,
            claude_options: None,
        })
        .unwrap()
        .args
        .into_iter()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect()
    }

    #[test]
    fn allows_initial_and_resumed_exec_outside_git_repositories() {
        let initial = build_args(None);
        let exec = initial
            .iter()
            .position(|argument| argument == "exec")
            .unwrap();
        assert_eq!(initial[exec + 1], "--skip-git-repo-check");
        assert!(initial.contains(&"--sandbox".into()));
        assert!(
            initial
                .windows(2)
                .any(|args| args == ["--sandbox", "workspace-write"])
        );
        assert!(
            initial
                .windows(2)
                .any(|args| args == ["--ask-for-approval", "never"])
        );

        let resumed = build_args(Some("thread-123"));
        let resume = resumed
            .iter()
            .position(|argument| argument == "resume")
            .unwrap();
        assert_eq!(resumed[resume + 1], "--skip-git-repo-check");
        assert_eq!(resumed[resume + 2], "thread-123");
        assert!(
            resumed
                .windows(2)
                .any(|args| args == ["--sandbox", "workspace-write"])
        );
        assert!(
            resumed
                .windows(2)
                .any(|args| args == ["--ask-for-approval", "never"])
        );
    }

    #[test]
    fn grants_only_the_canonical_run_control_directory_before_exec() {
        let temp = tempfile::tempdir().unwrap();
        let control_dir = temp.path().canonicalize().unwrap();
        let schema = json!({"type":"object"});
        let invocation = build(InvocationInput {
            executable: "/usr/bin/codex".into(),
            prefix: vec![],
            role_contract: "Follow the role contract.",
            prompt: "Complete the assigned turn.",
            schema: &schema,
            paths: InvocationPaths {
                schema_path: Path::new("/tmp/result-schema.json"),
                control_dir: Some(&control_dir),
            },
            conversation_id: Some("thread-123"),
            model: None,
            effort: None,
            codex_options: None,
            claude_options: None,
        })
        .unwrap();
        let args = invocation
            .args
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        let grant = args
            .iter()
            .position(|argument| argument == "--add-dir")
            .unwrap();
        let exec = args.iter().position(|argument| argument == "exec").unwrap();
        assert_eq!(args[grant + 1], control_dir.to_string_lossy());
        assert!(grant < exec);
        assert_eq!(args[exec + 1], "resume");
    }

    #[test]
    fn rejects_a_noncanonical_run_control_directory() {
        let temp = tempfile::tempdir().unwrap();
        let control_dir = temp
            .path()
            .join("..")
            .join(temp.path().file_name().unwrap());
        let schema = json!({"type":"object"});
        let result = build(InvocationInput {
            executable: "/usr/bin/codex".into(),
            prefix: vec![],
            role_contract: "Follow the role contract.",
            prompt: "Complete the assigned turn.",
            schema: &schema,
            paths: InvocationPaths {
                schema_path: Path::new("/tmp/result-schema.json"),
                control_dir: Some(&control_dir),
            },
            conversation_id: None,
            model: None,
            effort: None,
            codex_options: None,
            claude_options: None,
        });
        assert!(result.is_err());
    }

    #[test]
    fn extracts_only_final_structured_message_and_thread_identity() {
        let envelope = |ok| {
            serde_json::to_string(
                &json!({"result": serde_json::to_string(&json!({"ok": ok})).unwrap()}),
            )
            .unwrap()
        };
        let output = [
            json!({"type":"thread.started","thread_id":"thread-1"}),
            json!({"type":"item.completed","item":{"type":"agent_message","text":envelope(false)}}),
            json!({"type":"item.completed","item":{"type":"agent_message","text":envelope(true)}}),
            json!({"type":"turn.completed"}),
        ]
        .iter()
        .map(serde_json::Value::to_string)
        .collect::<Vec<_>>()
        .join("\n");
        let schema = json!({"type":"object","properties":{"ok":{"type":"boolean"}},"required":["ok"],"additionalProperties":false});
        let (thread, result) = parse_result(&output, &schema).unwrap();
        assert_eq!(thread.as_deref(), Some("thread-1"));
        assert_eq!(result, json!({"ok":true}));
    }

    #[test]
    fn rejects_failed_or_unstructured_turn() {
        let schema = json!({"type":"object"});
        assert!(parse_result("{\"type\":\"turn.failed\"}\n", &schema).is_err());
        assert!(parse_result("{\"type\":\"turn.completed\"}\n", &schema).is_err());
    }

    #[test]
    fn requires_exactly_one_successful_terminal_event_after_result() {
        let schema = json!({"type":"object"});
        let message = r#"{"type":"item.completed","item":{"type":"agent_message","text":"{\"result\":\"{}\"}"}}"#;
        assert!(parse_result(message, &schema).is_err());
        assert!(
            parse_result(
                &format!(
                    "{message}\n{{\"type\":\"turn.completed\"}}\n{{\"type\":\"turn.failed\"}}"
                ),
                &schema,
            )
            .is_err()
        );
        assert!(
            parse_result(
                &format!(
                    "{message}\n{{\"type\":\"turn.completed\"}}\n{{\"type\":\"turn.completed\"}}"
                ),
                &schema,
            )
            .is_err()
        );
        assert!(
            parse_result(
                &format!("{message}\n{{\"type\":\"turn.completed\"}}"),
                &schema,
            )
            .is_ok()
        );
    }

    #[test]
    fn host_rejects_projected_string_that_fails_the_source_schema() {
        let schema = json!({"type":"object","properties":{"ok":{"type":"boolean"}},"required":["ok"],"additionalProperties":false});
        let envelope = serde_json::to_string(&json!({
            "result": serde_json::to_string(&json!({"other": true})).unwrap()
        }))
        .unwrap();
        let output = format!(
            "{}\n{{\"type\":\"turn.completed\"}}",
            serde_json::json!({"type":"item.completed","item":{"type":"agent_message","text":envelope}})
        );
        assert!(parse_result(&output, &schema).is_err());
    }
}
