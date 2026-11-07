use std::ffi::OsString;

use serde_json::Value;

use crate::providers::{Invocation, InvocationInput, decode_projected_result};

pub(super) fn build(input: InvocationInput<'_>) -> Result<Invocation, String> {
    let InvocationInput {
        executable,
        prefix,
        role_contract,
        prompt,
        schema_path,
        conversation_id,
        model,
        effort,
        codex_options,
        ..
    } = input;
    let mut args: Vec<OsString> = prefix;
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
        args.extend(["resume".into(), conversation_id.into()]);
    }
    args.extend([
        "--json".into(),
        "--output-schema".into(),
        schema_path.as_os_str().to_owned(),
        prompt.into(),
    ]);
    Ok(Invocation {
        executable,
        args,
        effective_mode: "workspace-write; approvals never; automatic provider execution",
    })
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
    use serde_json::json;

    use super::parse_result;

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
