use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

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
opaque_id!(TicketRevision);
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

/// Opaque stable identity for a host-registered Agent artifact.
///
/// The syntax is deliberately identical to a SHA-256 digest, but an
/// `ArtifactId` is not itself proof that the host registered or acknowledged
/// an artifact. Consumers must resolve it against host-owned registration
/// state.
#[derive(Clone, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ArtifactId(String);

impl ArtifactId {
    pub fn parse(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err("artifact ID must be 64 lowercase hexadecimal characters".into());
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Mint a stable artifact identity from the canonical host registration
    /// identity. Fields are domain-separated and length-prefixed in this
    /// order: project ID, AgentRun ID, kind, big-endian schema version, and
    /// content digest. Call only after the host has verified the bytes. The
    /// returned ID alone is not an acknowledgement; persist the registration
    /// before returning it.
    pub fn from_registration_identity(
        project_id: &ProjectId,
        agent_run_id: &AgentRunId,
        kind: &str,
        schema_version: u32,
        content_digest: &Digest,
    ) -> Result<Self, String> {
        if kind.is_empty()
            || !kind
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
            || schema_version == 0
        {
            return Err("artifact registration identity has invalid kind or schema version".into());
        }
        let mut hasher = Sha256::new();
        hasher.update(b"rex-projects-artifact-id-v1\0");
        let schema_version = schema_version.to_be_bytes();
        for field in [
            project_id.as_str().as_bytes(),
            agent_run_id.as_str().as_bytes(),
            kind.as_bytes(),
            schema_version.as_slice(),
            content_digest.as_str().as_bytes(),
        ] {
            hasher.update((field.len() as u64).to_be_bytes());
            hasher.update(field);
        }
        Ok(Self(format!("{:x}", hasher.finalize())))
    }
}

impl fmt::Display for ArtifactId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ArtifactId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::{AgentRunId, ArtifactId, Digest, ProjectId};

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

    #[test]
    fn artifact_id_requires_canonical_lowercase_sha256_hex() {
        let valid = ArtifactId::parse("a".repeat(64)).unwrap();
        assert_eq!(valid.as_str(), "a".repeat(64));
        assert!(ArtifactId::parse("A".repeat(64)).is_err());
        assert!(ArtifactId::parse("a".repeat(63)).is_err());
        assert!(ArtifactId::parse("g".repeat(64)).is_err());

        let project = ProjectId::parse("project-a").unwrap();
        let run = AgentRunId::parse("worker-run-1").unwrap();
        let digest = Digest::parse("b".repeat(64)).unwrap();
        let minted =
            ArtifactId::from_registration_identity(&project, &run, "change", 1, &digest).unwrap();
        assert_eq!(minted.as_str().len(), 64);
        assert_eq!(
            minted,
            ArtifactId::from_registration_identity(&project, &run, "change", 1, &digest).unwrap()
        );
        assert_ne!(
            minted,
            ArtifactId::from_registration_identity(
                &project,
                &AgentRunId::parse("worker-run-2").unwrap(),
                "change",
                1,
                &digest
            )
            .unwrap()
        );
        assert_ne!(
            minted,
            ArtifactId::from_registration_identity(&project, &run, "review", 1, &digest).unwrap()
        );
        assert_ne!(
            minted,
            ArtifactId::from_registration_identity(&project, &run, "change", 2, &digest).unwrap()
        );
        assert_ne!(
            minted,
            ArtifactId::from_registration_identity(
                &project,
                &run,
                "change",
                1,
                &Digest::parse("c".repeat(64)).unwrap()
            )
            .unwrap()
        );
        assert!(
            ArtifactId::from_registration_identity(&project, &run, "Change", 1, &digest).is_err()
        );
        assert!(
            ArtifactId::from_registration_identity(&project, &run, "change", 0, &digest).is_err()
        );
    }
}
