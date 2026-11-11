mod claude;
mod codex;

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use jsonschema::{Validator, options};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::config::{ClaudeCodeOptions, CodexOptions, Profile, ProfileOptions};
use crate::domain::{ids::Digest, types::AgentAdapter};

pub const RESULT_SCHEMA_PROJECTION_VERSION: &str = "json-result-string-envelope-v1";

/// Identity for the provider-facing transport schema. The full source schema
/// remains authoritative and is validated after decoding the result string.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, schemars::JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderSchemaProjectionIdentity {
    pub source_schema_digest: Digest,
    pub provider_schema_digest: Digest,
    pub transform_version: String,
    /// Source schema keywords omitted from the provider transport schema.
    /// This is diagnostic; it never replaces host validation.
    pub unsupported_keywords: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderSchemaProjection {
    pub schema: Value,
    pub identity: ProviderSchemaProjectionIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Invocation {
    pub executable: PathBuf,
    pub args: Vec<OsString>,
    pub effective_mode: &'static str,
}

#[derive(Clone, Copy)]
pub struct InvocationPaths<'a> {
    pub schema_path: &'a Path,
    pub control_dir: Option<&'a Path>,
}

pub(super) struct InvocationInput<'a> {
    pub executable: PathBuf,
    pub prefix: Vec<OsString>,
    pub role_contract: &'a str,
    pub prompt: &'a str,
    pub schema: &'a Value,
    pub paths: InvocationPaths<'a>,
    pub conversation_id: Option<&'a str>,
    pub model: Option<&'a str>,
    pub effort: Option<&'a str>,
    pub codex_options: Option<&'a CodexOptions>,
    pub claude_options: Option<&'a ClaudeCodeOptions>,
}

pub fn build_invocation(
    profile: &Profile,
    role_contract: &str,
    prompt: &str,
    schema: &Value,
    paths: InvocationPaths<'_>,
    conversation_id: Option<&str>,
) -> Result<Invocation, String> {
    if profile.command.is_empty() || role_contract.trim().is_empty() || prompt.trim().is_empty() {
        return Err("provider command, role contract, and prompt must be non-empty".into());
    }
    let executable = PathBuf::from(&profile.command[0]);
    if !executable.is_absolute() {
        return Err("provider command must have a resolved absolute executable path".into());
    }
    if !executable.is_file() {
        return Err("configured provider executable is not a regular file".into());
    }
    validate_schema_definition(schema)?;
    let projection = project_result_schema(schema)?;
    let projected_prompt = projected_result_prompt(prompt, schema)?;
    let projected_contract = projected_result_contract(role_contract);
    let prefix = profile.command[1..].iter().map(OsString::from).collect();
    match profile.adapter {
        AgentAdapter::Codex => {
            let options = match &profile.options {
                Some(ProfileOptions::Codex(options)) => Some(options),
                Some(_) => return Err("Codex profile has mismatched provider options".into()),
                None => None,
            };
            codex::build(InvocationInput {
                executable,
                prefix,
                role_contract: &projected_contract,
                prompt: &projected_prompt,
                schema: &projection.schema,
                paths,
                conversation_id,
                model: profile.model.as_deref(),
                effort: profile.effort.as_deref(),
                codex_options: options,
                claude_options: None,
            })
        }
        AgentAdapter::ClaudeCode => {
            let options = match &profile.options {
                Some(ProfileOptions::ClaudeCode(options)) => Some(options),
                Some(_) => return Err("Claude Code profile has mismatched provider options".into()),
                None => None,
            };
            claude::build(InvocationInput {
                executable,
                prefix,
                role_contract: &projected_contract,
                prompt: &projected_prompt,
                schema: &projection.schema,
                paths,
                conversation_id,
                model: profile.model.as_deref(),
                effort: profile.effort.as_deref(),
                codex_options: None,
                claude_options: options,
            })
        }
    }
}

pub fn parse_result(
    adapter: AgentAdapter,
    stdout: &[u8],
    schema: &Value,
) -> Result<(Option<String>, Value), String> {
    validate_schema_definition(schema)?;
    let text = std::str::from_utf8(stdout).map_err(|_| "provider stdout is not valid UTF-8")?;
    match adapter {
        AgentAdapter::Codex => codex::parse_result(text, schema),
        AgentAdapter::ClaudeCode => claude::parse_result(text, schema),
    }
}

pub fn project_result_schema(schema: &Value) -> Result<ProviderSchemaProjection, String> {
    validate_schema_definition(schema)?;
    let encoded_source =
        serde_json::to_vec(schema).map_err(|_| "source result schema cannot be encoded")?;
    let provider_schema = serde_json::json!({
        "type": "object",
        "properties": {"result": {"type": "string"}},
        "required": ["result"],
        "additionalProperties": false,
    });
    let encoded_provider = serde_json::to_vec(&provider_schema)
        .map_err(|_| "provider result schema cannot be encoded")?;
    Ok(ProviderSchemaProjection {
        identity: ProviderSchemaProjectionIdentity {
            source_schema_digest: digest(&encoded_source)?,
            provider_schema_digest: digest(&encoded_provider)?,
            transform_version: RESULT_SCHEMA_PROJECTION_VERSION.into(),
            unsupported_keywords: source_schema_keywords(schema),
        },
        schema: provider_schema,
    })
}

fn digest(bytes: &[u8]) -> Result<Digest, String> {
    Digest::parse(format!("{:x}", Sha256::digest(bytes))).map_err(|error| error.to_string())
}

fn projected_result_contract(role_contract: &str) -> String {
    format!(
        "{role_contract}\n\nProvider structured output uses a transport envelope with one string property named `result`. Put the complete JSON object required by the authoritative result schema in that string. The host decodes it and validates it against the full schema. Do not return prose or any other envelope fields."
    )
}

fn projected_result_prompt(prompt: &str, source_schema: &Value) -> Result<String, String> {
    let schema = serde_json::to_string(source_schema)
        .map_err(|_| "source result schema cannot be encoded")?;
    Ok(format!(
        "{prompt}\n\nReturn only a JSON object with exactly one property named `result`. Its value must be a JSON string containing the complete result object. The result object must satisfy this authoritative JSON Schema exactly; the host will reject any mismatch.\n\n<rex-projects-authoritative-result-schema>\n{schema}\n</rex-projects-authoritative-result-schema>"
    ))
}

fn source_schema_keywords(schema: &Value) -> Vec<String> {
    const SCHEMA_MAP_CHILDREN: &[&str] = &[
        "$defs",
        "definitions",
        "properties",
        "patternProperties",
        "dependentSchemas",
    ];
    const SCHEMA_ARRAY_CHILDREN: &[&str] = &["allOf", "anyOf", "oneOf", "prefixItems"];
    const SCHEMA_SINGLE_CHILDREN: &[&str] = &[
        "additionalProperties",
        "contains",
        "else",
        "if",
        "items",
        "not",
        "propertyNames",
        "then",
        "unevaluatedItems",
        "unevaluatedProperties",
    ];
    const KEYWORDS: &[&str] = &[
        "$anchor",
        "$comment",
        "$defs",
        "$dynamicAnchor",
        "$dynamicRef",
        "$id",
        "$ref",
        "$schema",
        "$vocabulary",
        "additionalProperties",
        "allOf",
        "anyOf",
        "const",
        "contains",
        "contentEncoding",
        "contentMediaType",
        "contentSchema",
        "default",
        "dependentRequired",
        "dependentSchemas",
        "deprecated",
        "description",
        "else",
        "enum",
        "examples",
        "exclusiveMaximum",
        "exclusiveMinimum",
        "format",
        "if",
        "items",
        "maxItems",
        "maxLength",
        "maxProperties",
        "maximum",
        "minItems",
        "minLength",
        "minProperties",
        "minimum",
        "multipleOf",
        "not",
        "oneOf",
        "pattern",
        "patternProperties",
        "prefixItems",
        "properties",
        "propertyNames",
        "readOnly",
        "required",
        "then",
        "title",
        "type",
        "unevaluatedItems",
        "unevaluatedProperties",
        "uniqueItems",
        "writeOnly",
    ];

    let known: std::collections::BTreeSet<&str> = KEYWORDS.iter().copied().collect();
    let mut found = std::collections::BTreeSet::new();
    let mut pending = vec![schema];
    while let Some(value) = pending.pop() {
        let Some(object) = value.as_object() else {
            continue;
        };
        for (key, child) in object {
            if known.contains(key.as_str()) {
                found.insert(key.clone());
            }
            if SCHEMA_MAP_CHILDREN.contains(&key.as_str()) {
                if let Some(children) = child.as_object() {
                    pending.extend(children.values());
                }
            } else if SCHEMA_ARRAY_CHILDREN.contains(&key.as_str()) {
                if let Some(children) = child.as_array() {
                    pending.extend(children.iter());
                }
            } else if SCHEMA_SINGLE_CHILDREN.contains(&key.as_str()) {
                pending.push(child);
            }
        }
    }
    found.into_iter().collect()
}

fn decode_projected_result(value: &Value, source_schema: &Value) -> Result<Value, String> {
    let object = value
        .as_object()
        .ok_or("provider structured output is not the projected object envelope")?;
    if object.len() != 1 {
        return Err("provider structured output has unexpected envelope fields".into());
    }
    let encoded_result = object
        .get("result")
        .and_then(Value::as_str)
        .ok_or("provider structured output is missing its JSON result string")?;
    if encoded_result.len() > 1024 * 1024 {
        return Err("provider structured result exceeds 1 MiB".into());
    }
    let result: Value = serde_json::from_str(encoded_result)
        .map_err(|_| "provider result string is not valid JSON")?;
    validate_schema(&result, source_schema, "$.result")?;
    Ok(result)
}

pub fn validate_schema_definition(schema: &Value) -> Result<(), String> {
    if serde_json::to_vec(schema)
        .map_err(|_| "role result schema cannot be encoded")?
        .len()
        > 256 * 1024
    {
        return Err("role result schema exceeds 256 KiB".into());
    }
    validate_schema_shape(schema)?;
    offline_validator(schema)
        .map(|_| ())
        .map_err(|_| "role result schema is invalid or contains an unresolved reference".into())
}

fn validate_schema_shape(schema: &Value) -> Result<(), String> {
    const MAX_DEPTH: usize = 64;
    const MAX_NODES: usize = 10_000;
    let mut pending = vec![(schema, 0_usize)];
    let mut nodes = 0_usize;
    while let Some((value, depth)) = pending.pop() {
        nodes += 1;
        if nodes > MAX_NODES || depth > MAX_DEPTH {
            return Err("role result schema exceeds structural complexity limits".into());
        }
        match value {
            Value::Array(values) => pending.extend(values.iter().map(|value| (value, depth + 1))),
            Value::Object(values) => {
                pending.extend(values.values().map(|value| (value, depth + 1)));
            }
            _ => {}
        }
    }
    Ok(())
}

fn validate_schema(value: &Value, schema: &Value, path: &str) -> Result<(), String> {
    offline_validator(schema)
        .map_err(|_| format!("role result schema is invalid at {path}"))?
        .validate(value)
        .map_err(|_| format!("provider result does not satisfy role schema at {path}"))
}

fn offline_validator(schema: &Value) -> Result<Validator, jsonschema::ValidationError<'static>> {
    options().offline().build(schema)
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use crate::config::{ClaudeCodeOptions, Profile, ProfileOptions};
    use crate::domain::types::{AgentAdapter, CommitMode};

    use super::{
        InvocationPaths, RESULT_SCHEMA_PROJECTION_VERSION, build_invocation, project_result_schema,
        validate_schema, validate_schema_definition,
    };

    #[test]
    fn projection_uses_a_bounded_transport_and_records_source_constraints() {
        let source = json!({
            "$schema":"https://json-schema.org/draft/2020-12/schema",
            "type":"object",
            "properties":{"kind":{"const":"ok"},"name":{"type":"string","minLength":2}},
            "required":["kind","name"],
            "additionalProperties":false,
            "oneOf":[{"properties":{"kind":{"const":"ok"}}}]
        });
        let projection = project_result_schema(&source).unwrap();
        assert_eq!(
            projection.schema,
            json!({
                "type":"object",
                "properties":{"result":{"type":"string"}},
                "required":["result"],
                "additionalProperties":false
            })
        );
        assert_eq!(
            projection.identity.transform_version,
            RESULT_SCHEMA_PROJECTION_VERSION
        );
        assert!(
            projection
                .identity
                .unsupported_keywords
                .contains(&"oneOf".into())
        );
        assert!(
            projection
                .identity
                .unsupported_keywords
                .contains(&"minLength".into())
        );
        assert_eq!(
            projection.identity.source_schema_digest,
            project_result_schema(&source)
                .unwrap()
                .identity
                .source_schema_digest
        );
        assert_eq!(
            projection.identity.provider_schema_digest,
            project_result_schema(&source)
                .unwrap()
                .identity
                .provider_schema_digest
        );
    }

    #[test]
    fn claude_invocation_sends_projection_and_authoritative_schema_prompt() {
        let source = json!({
            "type":"object",
            "properties":{"ok":{"type":"boolean"}},
            "required":["ok"],
            "additionalProperties":false
        });
        let profile = Profile {
            adapter: AgentAdapter::ClaudeCode,
            command: vec!["/bin/sh".into()],
            description: None,
            model: None,
            effort: None,
            turn_timeout_seconds: 30,
            instruction_files: Vec::new(),
            skill_paths: Vec::new(),
            commit_mode: CommitMode::Auto,
            learned_guidance: None,
            options: Some(ProfileOptions::ClaudeCode(ClaudeCodeOptions::default())),
        };
        let invocation = build_invocation(
            &profile,
            "Worker contract",
            "Do the work",
            &source,
            InvocationPaths {
                schema_path: std::path::Path::new("unused-schema-path"),
                control_dir: None,
            },
            None,
        )
        .unwrap();
        let args = invocation
            .args
            .iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        let schema_arg = args
            .iter()
            .position(|value| value == "--json-schema")
            .unwrap();
        let provider_schema: Value = serde_json::from_str(&args[schema_arg + 1]).unwrap();
        assert_eq!(
            provider_schema,
            project_result_schema(&source).unwrap().schema
        );
        assert!(
            args.iter()
                .any(|value| value.contains("authoritative-result-schema"))
        );
        assert!(args.iter().any(|value| value.contains("\"ok\"")));
    }

    #[test]
    fn validates_closed_structured_result_and_nested_values() {
        let schema = json!({"type":"object","properties":{"items":{"type":"array","items":{"type":"integer"}}},"required":["items"],"additionalProperties":false});
        assert!(validate_schema(&json!({"items":[1,2]}), &schema, "$").is_ok());
        assert!(validate_schema(&json!({"items":["bad"]}), &schema, "$").is_err());
        assert!(validate_schema(&json!({"other":true}), &schema, "$").is_err());
        assert!(validate_schema(&json!({}), &schema, "$").is_err());
    }

    #[test]
    fn validates_full_local_schema_constraints_offline() {
        let schema = json!({
            "$schema":"https://json-schema.org/draft/2020-12/schema",
            "$defs":{"short":{"type":"string","minLength":3,"maxLength":8}},
            "oneOf":[
                {"type":"object","properties":{"kind":{"const":"named"},"name":{"$ref":"#/$defs/short"}},"required":["kind","name"],"additionalProperties":false},
                {"type":"object","properties":{"kind":{"const":"count"},"count":{"type":"integer","minimum":1}},"required":["kind","count"],"additionalProperties":false}
            ]
        });
        assert!(validate_schema_definition(&schema).is_ok());
        assert!(validate_schema(&json!({"kind":"named","name":"valid"}), &schema, "$").is_ok());
        assert!(validate_schema(&json!({"kind":"named","name":"x"}), &schema, "$").is_err());
        assert!(validate_schema(&json!({"kind":"count","count":0}), &schema, "$").is_err());
    }

    #[test]
    fn refuses_unresolved_external_schema_references() {
        assert!(
            validate_schema_definition(&json!({"$ref":"https://example.invalid/schema.json"}))
                .is_err()
        );
    }

    #[test]
    fn rejects_schemas_that_exceed_structural_complexity_limits() {
        let mut schema = json!({"type":"string"});
        for _ in 0..65 {
            schema = json!({"allOf":[schema]});
        }
        assert!(validate_schema_definition(&schema).is_err());
    }

    #[test]
    fn accepts_every_typed_role_payload_schema() {
        use crate::engine::orchestration::{RoleOutputKind, role_result_payload_schema};

        let kinds = [
            RoleOutputKind::Progress,
            RoleOutputKind::Irregularity,
            RoleOutputKind::HumanRequest,
            RoleOutputKind::TicketProposal,
            RoleOutputKind::DispatchRequest,
            RoleOutputKind::Intervention,
            RoleOutputKind::SpawnRequest,
            RoleOutputKind::InvestigationRequest,
            RoleOutputKind::PrepareWorktrees,
            RoleOutputKind::PlanReady,
            RoleOutputKind::ImplementationReady,
            RoleOutputKind::ReviewReady,
            RoleOutputKind::MergeAssessment,
            RoleOutputKind::MergeIntent,
            RoleOutputKind::OperationAction,
            RoleOutputKind::OperationResult,
            RoleOutputKind::PostmortemReady,
            RoleOutputKind::LearningDecision,
            RoleOutputKind::ProfileTrialResult,
            RoleOutputKind::ProfilePromotionProposal,
        ];
        for kind in kinds {
            let schema = role_result_payload_schema(kind);
            validate_schema_definition(&schema)
                .unwrap_or_else(|error| panic!("{kind:?} schema rejected: {error}"));
        }
    }
}
