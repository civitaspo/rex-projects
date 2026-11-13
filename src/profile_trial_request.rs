//! Host-derived, immutable inputs for staging one human profile-trial request.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::config::{AppliedConfig, Profile};
use crate::domain::ids::{Digest, HumanRequestId, ProfileId, ProjectId, Revision};
use crate::domain::types::Role;
use crate::learning_trials::{
    FrozenTrialInput, InlineFixtureV1, ProfileTrialAuthorization, TrialEvaluator, TrialPairSpec,
    TrialProfileSnapshot,
};

const POLICY: &[u8] = b"rex-profile-trial-request-policy-v1\0pairs=10;distinct_inputs=5;attempts_per_side=1;approval_ttl_seconds=86400;fixture=inline_fixture_v1;evaluator=structured_assertions_v1";
pub const APPROVAL_TTL_SECONDS: u64 = 86_400;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrialRequestMatrix {
    pub inputs: Vec<TrialMatrixInput>,
    pub pairs: Vec<TrialPairSpec>,
    #[serde(default)]
    pub scoped_exception: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrialMatrixInput {
    pub input_id: String,
    pub input: Value,
    #[serde(default)]
    pub fixture: InlineFixtureV1,
    #[serde(default)]
    pub assertions: Vec<crate::learning_trials::TrialAssertion>,
}

pub struct TrialAuthorizationSeed {
    pub project_id: ProjectId,
    pub role: Role,
    pub candidate_id: String,
    pub candidate_digest: Digest,
    pub base_profile_id: ProfileId,
    pub config_revision: Revision,
    pub config_digest: Digest,
    pub baseline_qualification_digest: Digest,
    pub candidate_qualification_digest: Digest,
    pub request_key: String,
    pub now_unix: u64,
}

pub struct FrozenTrialMatrix {
    pub baseline: TrialProfileSnapshot,
    pub candidate: TrialProfileSnapshot,
    pub inputs: Vec<FrozenTrialInput>,
    pub pairs: Vec<TrialPairSpec>,
    pub scoped_exception: Option<String>,
}

impl TrialRequestMatrix {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > crate::learning_trials::INLINE_FIXTURE_MATRIX_MAX_BYTES {
            return Err("trial request matrix exceeds the 512 KiB limit".into());
        }
        crate::protocol::parse_unique(bytes)
    }

    pub fn freeze(&self) -> Result<Vec<FrozenTrialInput>, String> {
        if self.inputs.len() < crate::learning::MIN_DISTINCT_INPUTS
            || self.inputs.len() > crate::learning::MAX_TRIAL_PAIRS_PER_REVISION
        {
            return Err("trial request requires 5 to 10 distinct inputs".into());
        }
        let mut seen = BTreeSet::new();
        self.inputs
            .iter()
            .map(|input| {
                if input.input_id.is_empty()
                    || input.input_id.len() > 128
                    || input.input_id.chars().any(char::is_control)
                    || !seen.insert(input.input_id.as_str())
                {
                    return Err("trial input IDs must be unique bounded tokens".into());
                }
                let input_json = serde_json::to_string(&input.input).map_err(|e| e.to_string())?;
                if input_json.len() > crate::learning_trials::MAX_FROZEN_INPUT_BYTES {
                    return Err("trial input exceeds the frozen input size limit".into());
                }
                input.fixture.validate()?;
                let evaluator = TrialEvaluator::StructuredAssertionsV1 {
                    assertions: input.assertions.clone(),
                };
                let evaluator_revision = evaluator.digest()?;
                let fixture_revision =
                    Digest::parse(format!("{:x}", Sha256::digest(b"inline_fixture_v1")))?;
                let input_digest =
                    Digest::parse(format!("{:x}", Sha256::digest(input_json.as_bytes())))?;
                Ok(FrozenTrialInput {
                    input_id: input.input_id.clone(),
                    input_digest,
                    input_json,
                    fixture_id: crate::learning_trials::INLINE_FIXTURE_ID.into(),
                    fixture_revision,
                    workspace_seed_digest: input.fixture.digest()?,
                    fixture_seed: input.fixture.clone(),
                    evaluator_id: evaluator.implementation_id().into(),
                    evaluator_revision,
                    evaluator,
                })
            })
            .collect()
    }
}

pub fn stable_ids(
    project: &ProjectId,
    request_key: &str,
) -> Result<(String, HumanRequestId), String> {
    if request_key.is_empty()
        || request_key.len() > 200
        || request_key.chars().any(char::is_control)
    {
        return Err("request key must be a nonempty bounded printable value".into());
    }
    let mut digest = b"rex-profile-trial-request-key-v1\0".to_vec();
    digest.extend(serde_json::to_vec(&(project, request_key)).map_err(|e| e.to_string())?);
    let hex = format!("{:x}", Sha256::digest(digest));
    let authorization = format!("profile-trial-{}", &hex[..40]);
    let human = HumanRequestId::parse(format!("profile-trial-{}", &hex[40..]))?;
    Ok((authorization, human))
}

pub fn canonical_profile(profile: &Profile) -> Result<String, String> {
    crate::store::canonical_json(profile)
}

pub fn profile_snapshot(
    applied: &AppliedConfig,
    profile_id: &ProfileId,
    source_profile_id: &ProfileId,
    profile: &Profile,
    package_files: Option<&BTreeMap<String, Vec<u8>>>,
    external_sources: Option<&BTreeMap<String, String>>,
) -> Result<TrialProfileSnapshot, String> {
    if !profile.skill_paths.is_empty() {
        return Err("profile trial requests do not support profiles with skill_paths until frozen skill delivery is available".into());
    }
    let logical_root = std::path::PathBuf::from(&applied.source_root)
        .join("profiles")
        .join(source_profile_id.as_str());
    let source_dir = applied
        .source_files
        .iter()
        .find(|source| {
            matches!(source.kind, crate::config::SourceKind::Directory)
                && std::path::Path::new(&source.path) == logical_root
        })
        .ok_or_else(|| {
            format!("profile `{profile_id}` is absent from the captured source manifest")
        })?;
    let canonical_root = std::path::PathBuf::from(&source_dir.canonical_path);
    let mut files = BTreeMap::new();
    let mut paths = profile.instruction_files.clone();
    paths.push("instructions.md".into());
    if let Some(guidance) = &profile.learned_guidance {
        paths.push(guidance.file.clone());
    }
    paths.sort();
    paths.dedup();
    for configured_path in paths {
        let configured = std::path::Path::new(&configured_path);
        let (snapshot_path, source) = if configured.is_absolute() {
            let source = applied.source_files.iter().find(|source| {
                matches!(source.kind, crate::config::SourceKind::File)
                    && std::path::Path::new(&source.path) == configured
            });
            let source = source.ok_or_else(|| {
                format!(
                    "absolute profile instruction `{configured_path}` is absent from the captured source manifest"
                )
            })?;
            let canonical = std::path::Path::new(&source.canonical_path);
            let relative = canonical.strip_prefix(&canonical_root).map_err(|_| {
                format!(
                    "absolute profile instruction `{configured_path}` escapes its captured profile directory"
                )
            })?;
            (relative.to_string_lossy().into_owned(), Some(source))
        } else {
            let logical = logical_root.join(configured);
            let canonical = canonical_root.join(configured);
            let source = applied.source_files.iter().find(|source| {
                matches!(source.kind, crate::config::SourceKind::File)
                    && (std::path::Path::new(&source.path) == logical
                        || std::path::Path::new(&source.canonical_path) == canonical)
            });
            (configured_path.clone(), source)
        };
        let bytes = if let Some(package) = package_files {
            let package_key = source
                .and_then(|source| {
                    external_sources.and_then(|mapping| mapping.get(&source.canonical_path))
                })
                .cloned()
                .unwrap_or_else(|| snapshot_path.clone());
            package.get(&package_key).cloned()
        } else {
            source.map(|source| source.contents.as_bytes().to_vec())
        };
        if let Some(bytes) = bytes {
            files.insert(snapshot_path, bytes);
        } else if profile.instruction_files.contains(&configured_path)
            || profile
                .learned_guidance
                .as_ref()
                .is_some_and(|guidance| guidance.file == configured_path)
        {
            return Err(format!(
                "captured profile is missing required instruction `{configured_path}`"
            ));
        }
    }
    let profile_digest = crate::store::agent_profile_digest(profile)?;
    let instruction_digest = Digest::parse(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&files).map_err(|e| e.to_string())?)
    ))?;
    Ok(TrialProfileSnapshot {
        profile_id: profile_id.clone(),
        profile_digest,
        instruction_digest,
        profile_config_json: canonical_profile(profile)?,
        instruction_files: files,
    })
}

pub fn make_authorization(
    seed: TrialAuthorizationSeed,
    matrix: FrozenTrialMatrix,
) -> Result<ProfileTrialAuthorization, String> {
    let (authorization_id, human_request_id) = stable_ids(&seed.project_id, &seed.request_key)?;
    let policy_digest = Digest::parse(format!("{:x}", Sha256::digest(POLICY)))?;
    let auth = ProfileTrialAuthorization {
        schema_version: crate::learning_trials::PROFILE_TRIAL_CAPSULE_SCHEMA_VERSION,
        authorization_id,
        project_id: seed.project_id,
        role: seed.role,
        candidate_id: seed.candidate_id,
        candidate_digest: seed.candidate_digest,
        base_profile_id: seed.base_profile_id,
        base_profile_digest: matrix.baseline.profile_digest.clone(),
        config_revision: seed.config_revision,
        config_digest: seed.config_digest.clone(),
        baseline_qualification_digest: seed.baseline_qualification_digest,
        candidate_qualification_digest: seed.candidate_qualification_digest,
        trial_policy_digest: policy_digest.clone(),
        baseline: matrix.baseline,
        candidate: matrix.candidate,
        inputs: matrix.inputs,
        pairs: matrix.pairs,
        scoped_exception: matrix.scoped_exception,
        human_request_id,
        human_subject_digest: Digest::parse("0".repeat(64))?,
        human_configuration_digest: seed.config_digest,
        human_policy_digest: policy_digest,
        human_response_receipt_digest: Digest::parse("0".repeat(64))?,
        authorized_at_unix: seed.now_unix,
        max_attempts_per_side: 1,
        expires_at_unix: seed.now_unix.saturating_add(APPROVAL_TTL_SECONDS),
    };
    auth.validate()?;
    Ok(auth)
}

#[cfg(test)]
mod tests {
    #[test]
    fn documented_matrix_has_valid_frozen_inputs_and_standard_coverage() {
        let matrix = super::TrialRequestMatrix::parse(include_bytes!(
            "../examples/profile-trial-matrix.json"
        ))
        .unwrap();
        let inputs = matrix.freeze().unwrap();
        assert_eq!(inputs.len(), 5);
        assert_eq!(matrix.pairs.len(), 10);
        for input in inputs {
            assert_eq!(
                matrix
                    .pairs
                    .iter()
                    .filter(|pair| pair.input_id == input.input_id)
                    .count(),
                2
            );
        }
    }
}
