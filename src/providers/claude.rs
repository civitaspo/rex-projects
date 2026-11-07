use serde_json::Value;
use std::ffi::OsString;

use crate::providers::{Invocation, InvocationInput, decode_projected_result};

pub(super) fn build(input: InvocationInput<'_>) -> Result<Invocation, String> {
    let InvocationInput {
        executable,
        prefix,
        role_contract,
        prompt,
        schema,
        conversation_id,
        model,
        effort,
        claude_options,
        ..
    } = input;
    let mut args: Vec<OsString> = prefix;
    if let Some(conversation_id) = conversation_id {
        validate_conversation_id(conversation_id)?;
        args.extend(["--resume".into(), conversation_id.into()]);
    }
    args.extend([
        "--print".into(),
        "--output-format".into(),
        "json".into(),
        "--json-schema".into(),
        serde_json::to_string(schema)
            .map_err(|e| e.to_string())?
            .into(),
    ]);
    if let Some(model) = model {
        args.extend(["--model".into(), model.into()]);
    }
    if let Some(effort) = effort {
        args.extend(["--effort".into(), effort.into()]);
    }
    if let Some(options) = claude_options
        && (!matches!(
            options.permission_mode,
            crate::config::ClaudePermissionMode::Auto
        ) || !matches!(
            options.permission_prompts,
            crate::config::ClaudePermissionPrompts::None
        ))
    {
        return Err("unsupported Claude Code permission policy".into());
    }
    args.extend([
        "--permission-mode".into(),
        "auto".into(),
        "--permission-prompts".into(),
        "none".into(),
        "--append-system-prompt".into(),
        role_contract.into(),
        prompt.into(),
    ]);
    Ok(Invocation {
        executable,
        args,
        effective_mode: "auto; permission prompts denied unattended",
    })
}

pub(super) fn parse_result(
    stdout: &str,
    schema: &Value,
) -> Result<(Option<String>, Value), String> {
    let response: Value = serde_json::from_str(stdout.trim())
        .map_err(|_| "Claude Code output is not one JSON response")?;
    if response.get("is_error").and_then(Value::as_bool) == Some(true) {
        return Err("Claude Code reported an error".into());
    }
    let conversation_id = response
        .get("session_id")
        .and_then(Value::as_str)
        .map(str::to_owned);
    if let Some(id) = conversation_id.as_deref() {
        validate_conversation_id(id)?;
    }
    let projected_result = response
        .get("structured_output")
        .cloned()
        .ok_or("Claude Code did not return structured output")?;
    let result = decode_projected_result(&projected_result, schema)?;
    Ok((conversation_id, result))
}

fn validate_conversation_id(value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        Err("Claude Code conversation ID is malformed".into())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::parse_result;

    #[test]
    fn reads_only_structured_output_with_conversation_identity() {
        let output = r#"{"type":"result","session_id":"session-1","is_error":false,"structured_output":{"result":"{\"ok\":true}"},"result":"private prose"}"#;
        let schema = json!({"type":"object","properties":{"ok":{"type":"boolean"}},"required":["ok"],"additionalProperties":false});
        let (session, result) = parse_result(output, &schema).unwrap();
        assert_eq!(session.as_deref(), Some("session-1"));
        assert_eq!(result, json!({"ok":true}));
    }

    #[test]
    fn does_not_accept_error_or_missing_structured_output() {
        let schema = json!({"type":"object"});
        assert!(parse_result(r#"{"is_error":true,"structured_output":{}}"#, &schema).is_err());
        assert!(parse_result(r#"{"session_id":"s","result":"{}"}"#, &schema).is_err());
    }

    #[test]
    fn host_rejects_projected_string_that_fails_the_source_schema() {
        let schema = json!({"type":"object","properties":{"ok":{"type":"boolean"}},"required":["ok"],"additionalProperties":false});
        let output = r#"{"is_error":false,"structured_output":{"result":"{\"other\":true}"}}"#;
        assert!(parse_result(output, &schema).is_err());
    }
}
