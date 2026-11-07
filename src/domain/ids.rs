use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

fn valid_local_id(value: &str) -> bool {
    let mut chars = value.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

macro_rules! string_id {
    ($name:ident) => {
        #[derive(Clone, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn parse(value: impl Into<String>) -> Result<Self, String> {
                let value = value.into();
                if value.is_empty() || value.len() > 255 || !valid_local_id(&value) {
                    return Err(format!("invalid {} `{value}`", stringify!($name)));
                }
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl TryFrom<String> for $name {
            type Error = String;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::parse(value)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::parse(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

string_id!(ProjectId);
string_id!(RepositoryId);
string_id!(ProfileId);
string_id!(AdapterId);

macro_rules! opaque_id {
    ($name:ident) => {
        #[derive(Clone, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn parse(value: impl Into<String>) -> Result<Self, String> {
                let value = value.into();
                if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
                    return Err(format!("invalid {}", stringify!($name)));
                }
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
            }
        }

        impl TryFrom<String> for $name {
            type Error = String;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::parse(value)
            }
        }
    };
}

opaque_id!(TicketId);
opaque_id!(TicketNamespace);
opaque_id!(TicketRunId);
opaque_id!(AgentRunId);
opaque_id!(HumanRequestId);
opaque_id!(OperationId);
opaque_id!(RexBlockId);

#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct Revision(pub u64);

#[derive(Clone, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn parse(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err("digest must be 64 lowercase hexadecimal characters".into());
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::{Digest, ProjectId};

    #[test]
    fn identifiers_are_branded_and_validated_when_deserialized() {
        assert!(ProjectId::parse("valid-project").is_ok());
        assert!(ProjectId::parse("../escape").is_err());
        assert!(serde_json::from_str::<ProjectId>("\"../escape\"").is_err());
    }

    #[test]
    fn digest_requires_canonical_lowercase_sha256_hex() {
        assert!(Digest::parse("a".repeat(64)).is_ok());
        assert!(Digest::parse("A".repeat(64)).is_err());
    }
}
