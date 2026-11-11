use std::collections::BTreeSet;
use std::io::Write;

use schemars::JsonSchema;
use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use crate::domain::ids::{OperationId, ProjectId};
use crate::domain::types::Role;

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct RequestId(String);

impl RequestId {
    pub fn new(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        if value.is_empty() || value.len() > 255 || value.chars().any(char::is_control) {
            return Err("request_id must contain 1 to 255 non-control bytes".into());
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for RequestId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct MethodName(String);

impl MethodName {
    pub fn new(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 128
            || !value.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'.' || byte == b'_'
            })
            || value.starts_with('.')
            || value.ends_with('.')
            || value.contains("..")
        {
            return Err("method must be a dotted lowercase identifier".into());
        }
        Ok(Self(value))
    }
}

impl<'de> Deserialize<'de> for MethodName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestEnvelope<P> {
    pub schema_version: u32,
    pub request_id: RequestId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<OperationId>,
    pub method: MethodName,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<ProjectId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_subject_revision: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<Role>,
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub request_type: Option<String>,
    pub params: P,
}

impl<P> RequestEnvelope<P> {
    pub fn host(
        request_id: RequestId,
        operation_id: Option<OperationId>,
        method: MethodName,
        project_id: Option<ProjectId>,
        params: P,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            request_id,
            operation_id,
            method,
            project_id,
            run_id: None,
            attempt: None,
            run_epoch: None,
            expected_subject_revision: None,
            role: None,
            request_type: None,
            params,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(format!(
                "unsupported request schema version {}",
                self.schema_version
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseEnvelope<R> {
    pub schema_version: u32,
    pub request_id: RequestId,
    #[serde(default)]
    pub result: Option<R>,
    #[serde(default)]
    pub error: Option<ProtocolError>,
    #[serde(default)]
    pub extensions: std::collections::BTreeMap<String, serde_json::Value>,
}

impl<R> ResponseEnvelope<R> {
    pub fn validate_for(&self, request_id: &RequestId) -> Result<(), String> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(format!(
                "unsupported response schema version {}",
                self.schema_version
            ));
        }
        if &self.request_id != request_id {
            return Err("response request_id does not match request".into());
        }
        if self.result.is_some() == self.error.is_some() {
            return Err("response must contain exactly one of result or error".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolError {
    pub code: ErrorCode,
    pub message: String,
    pub retryable: bool,
    #[serde(default)]
    pub retry_after_ms: Option<u64>,
    #[serde(default)]
    pub details: std::collections::BTreeMap<String, serde_json::Value>,
}

#[derive(Clone, Copy, Debug, JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    NotFound,
    Unauthorized,
    Forbidden,
    Conflict,
    RateLimited,
    Unavailable,
    Unsupported,
    InvalidRequest,
}

#[derive(Debug)]
struct UniqueValue(serde_json::Value);

impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct UniqueVisitor;
        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = serde_json::Value;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON value without duplicate object keys")
            }
            fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
                Ok(value.into())
            }
            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(value.into())
            }
            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(value.into())
            }
            fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                serde_json::Number::from_f64(value)
                    .map(serde_json::Value::Number)
                    .ok_or_else(|| E::custom("invalid JSON number"))
            }
            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(value.to_owned().into())
            }
            fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
                Ok(value.into())
            }
            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(serde_json::Value::Null)
            }
            fn visit_none<E>(self) -> Result<Self::Value, E> {
                Ok(serde_json::Value::Null)
            }
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut values = Vec::new();
                while let Some(value) = seq.next_element::<UniqueValue>()? {
                    values.push(value.0);
                }
                Ok(serde_json::Value::Array(values))
            }
            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut values = serde_json::Map::new();
                let mut keys = BTreeSet::new();
                while let Some(key) = map.next_key::<String>()? {
                    if !keys.insert(key.clone()) {
                        return Err(serde::de::Error::custom(format!(
                            "duplicate JSON object key `{key}`"
                        )));
                    }
                    let value = map.next_value::<UniqueValue>()?;
                    values.insert(key, value.0);
                }
                Ok(serde_json::Value::Object(values))
            }
        }
        deserializer.deserialize_any(UniqueVisitor).map(UniqueValue)
    }
}

pub fn parse_unique<T: for<'de> Deserialize<'de>>(input: &[u8]) -> Result<T, String> {
    let value = serde_json::from_slice::<UniqueValue>(input).map_err(|error| error.to_string())?;
    serde_json::from_value(value.0).map_err(|error| error.to_string())
}

pub(crate) fn serialize_bounded(
    value: &impl Serialize,
    limit: usize,
) -> Result<Vec<u8>, serde_json::Error> {
    let mut writer = BoundedWriter {
        bytes: Vec::with_capacity(limit.min(8192)),
        limit,
    };
    serde_json::to_writer(&mut writer, value)?;
    Ok(writer.bytes)
}

struct BoundedWriter {
    bytes: Vec<u8>,
    limit: usize,
}

impl Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(std::io::Error::other(
                "serialized JSON value exceeds its byte limit",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MethodName, RequestEnvelope, RequestId, ResponseEnvelope, parse_unique, serialize_bounded,
    };

    #[test]
    fn bounded_serialization_stops_at_the_limit() {
        let value = serde_json::json!({"payload":"a long value"});
        assert!(serialize_bounded(&value, 4).is_err());
        let bytes = serialize_bounded(&value, 128).unwrap();
        assert!(bytes.len() <= 128);
        assert_eq!(parse_unique::<serde_json::Value>(&bytes).unwrap(), value);
    }

    #[test]
    fn rejects_duplicate_keys_at_every_json_object_depth() {
        let error = parse_unique::<serde_json::Value>(br#"{"params":{"x":1,"x":2}}"#).unwrap_err();
        assert!(error.contains("duplicate JSON object key `x`"));
    }

    #[test]
    fn response_must_match_request_and_have_exactly_one_result() {
        let request = RequestId::new("request-1").unwrap();
        let both = ResponseEnvelope {
            schema_version: 1,
            request_id: request.clone(),
            result: Some(()),
            error: None,
            extensions: Default::default(),
        };
        assert!(both.validate_for(&request).is_ok());
        let neither = ResponseEnvelope::<()> {
            schema_version: 1,
            request_id: request.clone(),
            result: None,
            error: None,
            extensions: Default::default(),
        };
        assert!(neither.validate_for(&request).is_err());
        let mismatch = RequestId::new("request-2").unwrap();
        assert!(both.validate_for(&mismatch).is_err());
    }

    #[test]
    fn request_rejects_unknown_fields() {
        let input =
            br#"{"schema_version":1,"request_id":"r1","method":"get","params":{},"stray":true}"#;
        assert!(parse_unique::<RequestEnvelope<serde_json::Value>>(input).is_err());
    }

    #[test]
    fn request_boundary_validates_identifiers_and_method_syntax() {
        assert!(RequestId::new("request\n1").is_err());
        assert!(MethodName::new("ticket..list").is_err());
        let request: RequestEnvelope<serde_json::Value> = parse_unique(
            br#"{"schema_version":1,"request_id":"r1","method":"ticket.list","project_id":"project-1","params":{}}"#,
        )
        .unwrap();
        assert!(request.validate().is_ok());
        let invalid: Result<RequestEnvelope<serde_json::Value>, _> = parse_unique(
            br#"{"schema_version":1,"request_id":"r1","method":"ticket.List","params":{}}"#,
        );
        assert!(invalid.is_err());
    }

    #[test]
    fn host_constructor_has_the_exact_host_wire_shape() {
        let request = RequestEnvelope::host(
            RequestId::new("r1").unwrap(),
            None,
            MethodName::new("ticket.describe").unwrap(),
            None,
            serde_json::json!({"schema_version": 1}),
        );
        assert_eq!(
            serde_json::to_value(request).unwrap(),
            serde_json::json!({
                "schema_version": 1,
                "request_id": "r1",
                "method": "ticket.describe",
                "params": {"schema_version": 1}
            })
        );
    }
}
