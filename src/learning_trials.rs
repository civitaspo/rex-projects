//! Human-authorized, restartable fixture execution for profile trials.
//!
//! The capsule contains the entire comparison input and both frozen profiles. The
//! controller persists it before launch; agent output cannot mint a terminal receipt.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::domain::ids::{
    AgentRunId, Digest, HumanRequestId, OperationId, ProfileId, ProjectId, Revision,
};
use crate::domain::types::Role;
use crate::human_runtime::{
    HumanDecisionChoice, HumanPurpose, HumanRuntimeRequest, HumanSubjectBinding, HumanSubjectKind,
};
use crate::learning::{MAX_TRIAL_PAIRS_PER_REVISION, MIN_DISTINCT_INPUTS, TrialRunStatus};
use crate::store::human::HumanApprovalReceipt;

pub const MAX_FROZEN_INPUT_BYTES: usize = 256 * 1024;
pub const MAX_TRIAL_INSTRUCTION_BYTES: usize = 1024 * 1024;
pub const PROFILE_TRIAL_CAPSULE_SCHEMA_VERSION: u32 = 1;
pub const MAX_TRIAL_ASSERTIONS: usize = 32;
pub const MAX_TRIAL_EVALUATOR_BYTES: usize = 64 * 1024;
pub const INLINE_FIXTURE_MAX_FILES: usize = 64;
pub const INLINE_FIXTURE_MAX_BYTES: usize = 1024 * 1024;
pub const INLINE_FIXTURE_MATRIX_MAX_BYTES: usize = 512 * 1024;
pub const INLINE_FIXTURE_ID: &str = "inline_fixture_v1";

/// Canonical UTF-8 seed for a new disposable trial workspace.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InlineFixtureV1 {
    pub schema_version: u32,
    pub files: BTreeMap<String, String>,
}

impl InlineFixtureV1 {
    pub fn empty() -> Self {
        Self {
            schema_version: 1,
            files: BTreeMap::new(),
        }
    }

    pub fn digest(&self) -> Result<Digest, String> {
        self.validate()?;
        let canonical = serde_json::to_string(self).map_err(|e| e.to_string())?;
        content_digest(canonical.as_bytes())
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1 || self.files.len() > INLINE_FIXTURE_MAX_FILES {
            return Err("unsupported or oversized inline trial fixture".into());
        }
        let mut total = 0usize;
        let mut paths = std::collections::BTreeSet::new();
        for (path, contents) in &self.files {
            if !valid_trial_relative_path(path)
                || path
                    .split('/')
                    .any(|part| part.eq_ignore_ascii_case(".git"))
                || path
                    .split('/')
                    .any(|part| part.eq_ignore_ascii_case("rex-projects-control"))
            {
                return Err("inline fixture contains a forbidden or malformed path".into());
            }
            if paths.iter().any(|other: &&str| {
                path.starts_with(&format!("{other}/")) || other.starts_with(&format!("{path}/"))
            }) {
                return Err("inline fixture file paths have a file/directory collision".into());
            }
            paths.insert(path.as_str());
            total = total
                .checked_add(path.len())
                .and_then(|n| n.checked_add(contents.len()))
                .ok_or("inline fixture byte count overflow")?;
            if total > INLINE_FIXTURE_MAX_BYTES {
                return Err("inline fixture exceeds the 1 MiB limit".into());
            }
        }
        Ok(())
    }
}

impl Default for InlineFixtureV1 {
    fn default() -> Self {
        Self::empty()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrialSide {
    Baseline,
    Candidate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaunchPurpose {
    ProfileTrial,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TrialEvaluator {
    StructuredAssertionsV1 { assertions: Vec<TrialAssertion> },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrialAssertion {
    pub json_pointer: String,
    pub expected: Value,
}

impl TrialEvaluator {
    pub fn implementation_id(&self) -> &'static str {
        match self {
            Self::StructuredAssertionsV1 { .. } => "structured_assertions_v1",
        }
    }

    pub fn digest(&self) -> Result<Digest, String> {
        self.validate()?;
        let value = serde_json::to_value(self).map_err(|error| error.to_string())?;
        let canonical = serde_json::to_string(&value).map_err(|error| error.to_string())?;
        Digest::parse(format!("{:x}", Sha256::digest(canonical.as_bytes())))
    }

    pub fn validate(&self) -> Result<(), String> {
        let Self::StructuredAssertionsV1 { assertions } = self;
        if assertions.len() > MAX_TRIAL_ASSERTIONS {
            return Err("trial evaluator exceeds the 32 assertion limit".into());
        }
        let value = serde_json::to_value(self).map_err(|error| error.to_string())?;
        let canonical = serde_json::to_string(&value).map_err(|error| error.to_string())?;
        if canonical.len() > MAX_TRIAL_EVALUATOR_BYTES {
            return Err("trial evaluator exceeds the 64 KiB limit".into());
        }
        for assertion in assertions {
            validate_json_pointer(&assertion.json_pointer)?;
        }
        Ok(())
    }

    pub(crate) fn evaluate(&self, result: Option<&Value>) -> Result<HostTrialOutcome, String> {
        self.validate()?;
        let Self::StructuredAssertionsV1 { assertions } = self;
        if assertions.is_empty() {
            return Ok(HostTrialOutcome::Equivalent);
        }
        let Some(result) = result.filter(|result| !is_empty_result(result)) else {
            return Ok(HostTrialOutcome::Failed);
        };
        if assertions
            .iter()
            .any(|assertion| result.pointer(&assertion.json_pointer) != Some(&assertion.expected))
        {
            Ok(HostTrialOutcome::Regressed)
        } else {
            Ok(HostTrialOutcome::Improved)
        }
    }
}

fn validate_json_pointer(pointer: &str) -> Result<(), String> {
    if pointer.len() > 4096 || (!pointer.is_empty() && !pointer.starts_with('/')) {
        return Err("trial evaluator JSON pointer is malformed or too long".into());
    }
    let bytes = pointer.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'~' {
            if !bytes
                .get(index + 1)
                .is_some_and(|byte| matches!(byte, b'0' | b'1'))
            {
                return Err("trial evaluator JSON pointer has an invalid escape".into());
            }
            index += 1;
        }
        index += 1;
    }
    Ok(())
}

fn is_empty_result(result: &Value) -> bool {
    match result {
        Value::Null => true,
        Value::String(value) => value.is_empty(),
        Value::Array(values) => values.is_empty(),
        Value::Object(values) => values.is_empty(),
        Value::Bool(_) | Value::Number(_) => false,
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrialProfileSnapshot {
    pub profile_id: ProfileId,
    pub profile_digest: Digest,
    pub instruction_digest: Digest,
    /// Canonical serialization of the complete immutable execution profile.
    pub profile_config_json: String,
    /// Exact profile instruction bytes loaded by the host, keyed by safe relative path.
    pub instruction_files: BTreeMap<String, Vec<u8>>,
    /// Exact selected skill trees captured from the applied configuration manifest.
    /// Empty is omitted to preserve schema-1 authorization and capsule digests.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub skill_trees: BTreeMap<String, FrozenTrialSkillTree>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenTrialSkillTree {
    pub directory_name: String,
    pub files: BTreeMap<String, String>,
}

/// Stable safe identity for a configured skill root, independent of its workspace path.
pub fn trial_skill_root_key(configured_root: &str) -> Result<String, String> {
    if configured_root.is_empty() || configured_root.len() > 4096 || configured_root.contains('\0')
    {
        return Err("configured skill root is malformed".into());
    }
    let digest = content_digest(configured_root.as_bytes())?;
    Ok(format!("skill-{}", &digest.as_str()[..24]))
}

/// Compose the immutable original fixture and frozen skill payload for one provider workspace.
/// The original fixture digest stays authoritative; the capsule binds this deterministic result.
pub fn trial_workspace_seed(
    profile: &TrialProfileSnapshot,
    original: &InlineFixtureV1,
) -> Result<InlineFixtureV1, String> {
    original.validate()?;
    validate_trial_profile_snapshot(profile)?;
    let typed: crate::config::Profile =
        crate::protocol::parse_unique(profile.profile_config_json.as_bytes())?;
    let provider_root = match typed.adapter {
        crate::domain::types::AgentAdapter::Codex => ".agents/skills",
        crate::domain::types::AgentAdapter::ClaudeCode => ".claude/skills",
    };
    let mut combined = original.clone();
    let provider_config_dir = provider_root.split('/').next().unwrap_or(provider_root);
    let provider_skill_dir = provider_root.split('/').nth(1).unwrap_or("skills");
    if !profile.skill_trees.is_empty()
        && original.files.keys().any(|existing| {
            let mut parts = existing.split('/');
            parts
                .next()
                .is_some_and(|part| part.eq_ignore_ascii_case(provider_config_dir))
                && parts
                    .next()
                    .is_none_or(|part| part.eq_ignore_ascii_case(provider_skill_dir))
        })
    {
        return Err("trial fixture collides with the provider skill directory".into());
    }
    for tree in profile.skill_trees.values() {
        for (relative, contents) in &tree.files {
            let target = format!("{provider_root}/{}/{relative}", tree.directory_name);
            if combined
                .files
                .keys()
                .any(|existing| workspace_paths_collide(existing, &target))
            {
                return Err(
                    "frozen trial skill files collide with the fixture or each other".into(),
                );
            }
            if combined.files.insert(target, contents.clone()).is_some() {
                return Err("frozen trial skill files collide with the fixture".into());
            }
        }
    }
    combined.validate()?;
    Ok(combined)
}

fn workspace_paths_collide(left: &str, right: &str) -> bool {
    let left = left.to_lowercase();
    let right = right.to_lowercase();
    left == right
        || left.starts_with(&format!("{right}/"))
        || right.starts_with(&format!("{left}/"))
}

pub(crate) fn validate_trial_profile_snapshot(
    snapshot: &TrialProfileSnapshot,
) -> Result<(), String> {
    let profile: crate::config::Profile =
        crate::protocol::parse_unique(snapshot.profile_config_json.as_bytes())?;
    if crate::store::canonical_json(&profile)? != snapshot.profile_config_json
        || crate::store::agent_profile_digest(&profile)? != snapshot.profile_digest
        || digest_serialized(&snapshot.instruction_files)? != snapshot.instruction_digest
    {
        return Err("frozen profile snapshot identity is invalid".into());
    }
    let expected = profile
        .skill_paths
        .iter()
        .map(|path| trial_skill_root_key(path))
        .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
    if expected.len() != profile.skill_paths.len()
        || expected
            != snapshot
                .skill_trees
                .keys()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>()
    {
        return Err("frozen skill roots do not match the selected profile".into());
    }
    let mut total = 0usize;
    let mut count = 0usize;
    let mut directory_names = std::collections::BTreeSet::new();
    for tree in snapshot.skill_trees.values() {
        if tree.directory_name.is_empty()
            || tree.directory_name.len() > 64
            || !tree
                .directory_name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            || tree.directory_name.starts_with('-')
            || tree.directory_name.ends_with('-')
            || tree.directory_name.contains("--")
        {
            return Err("captured skill directory name must use 1 to 64 lowercase letters, digits, and single interior hyphens".into());
        }
        if !directory_names.insert(tree.directory_name.to_lowercase()) {
            return Err("selected skill directory names collide".into());
        }
        if profile.adapter == crate::domain::types::AgentAdapter::ClaudeCode
            && matches!(tree.directory_name.as_str(), "synced" | "anthropic-skills")
        {
            return Err("captured skill directory name is reserved by Claude Code".into());
        }
        if !tree.files.contains_key("SKILL.md") {
            return Err("each selected trial skill directory must contain SKILL.md".into());
        }
        for (path, contents) in &tree.files {
            if !valid_trial_relative_path(path)
                || path
                    .split('/')
                    .any(|part| part.eq_ignore_ascii_case(".git"))
                || path
                    .split('/')
                    .any(|part| part.eq_ignore_ascii_case("rex-projects-control"))
            {
                return Err("frozen skill tree contains a forbidden or malformed path".into());
            }
            count = count.checked_add(1).ok_or("skill file count overflow")?;
            total = total
                .checked_add(path.len())
                .and_then(|sum| sum.checked_add(contents.len()))
                .ok_or("skill byte count overflow")?;
        }
    }
    if count > INLINE_FIXTURE_MAX_FILES || total > INLINE_FIXTURE_MAX_BYTES {
        return Err("frozen trial skills exceed inline fixture bounds".into());
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenTrialInput {
    pub input_id: String,
    pub input_digest: Digest,
    /// Canonical task and fixture parameters; never interpreted as a path or command.
    pub input_json: String,
    pub fixture_id: String,
    pub fixture_revision: Digest,
    pub workspace_seed_digest: Digest,
    pub fixture_seed: InlineFixtureV1,
    /// Identifies the host-side fixture evaluator and its immutable rubric revision.
    pub evaluator_id: String,
    pub evaluator_revision: Digest,
    pub evaluator: TrialEvaluator,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrialPairSpec {
    pub pair_index: u8,
    pub input_id: String,
}

/// Immutable trial matrix. Its persisted state remains pending until the host records approval.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileTrialAuthorization {
    pub schema_version: u32,
    pub authorization_id: String,
    pub project_id: ProjectId,
    pub role: Role,
    pub candidate_id: String,
    pub candidate_digest: Digest,
    pub base_profile_id: ProfileId,
    pub base_profile_digest: Digest,
    pub config_revision: Revision,
    pub config_digest: Digest,
    pub baseline_qualification_digest: Digest,
    pub candidate_qualification_digest: Digest,
    pub trial_policy_digest: Digest,
    pub baseline: TrialProfileSnapshot,
    pub candidate: TrialProfileSnapshot,
    pub inputs: Vec<FrozenTrialInput>,
    pub pairs: Vec<TrialPairSpec>,
    pub scoped_exception: Option<String>,
    pub human_request_id: HumanRequestId,
    pub human_subject_digest: Digest,
    pub human_configuration_digest: Digest,
    pub human_policy_digest: Digest,
    pub human_response_receipt_digest: Digest,
    pub authorized_at_unix: u64,
    pub max_attempts_per_side: u8,
    pub expires_at_unix: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileTrialLaunchCapsule {
    pub schema_version: u32,
    pub purpose: LaunchPurpose,
    pub authorization_id: String,
    pub authorization_digest: Digest,
    pub human_response_receipt_digest: Digest,
    pub project_id: ProjectId,
    pub role: Role,
    pub candidate_id: String,
    pub candidate_digest: Digest,
    pub base_profile_id: ProfileId,
    pub base_profile_digest: Digest,
    pub config_revision: Revision,
    pub config_digest: Digest,
    pub provider_qualification_digest: Digest,
    pub pair_index: u8,
    pub max_attempts_per_side: u8,
    pub attempt_ordinal: u8,
    pub input_id: String,
    pub input_digest: Digest,
    pub input_json: String,
    pub fixture_id: String,
    pub fixture_revision: Digest,
    pub workspace_seed_digest: Digest,
    pub fixture_seed: InlineFixtureV1,
    pub evaluator_id: String,
    pub evaluator_revision: Digest,
    pub evaluator: TrialEvaluator,
    pub side: TrialSide,
    pub run_id: AgentRunId,
    pub operation_id: OperationId,
    pub attempt_id: String,
    pub profile: TrialProfileSnapshot,
    /// Trial workspaces use registered disposable fixtures and cannot submit factory effects.
    pub effects_disabled: bool,
}

/// Host-only terminal classification. The fixture evaluator, not the Agent, creates this value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HostTrialOutcome {
    Improved,
    Regressed,
    Equivalent,
    Timeout,
    Failed,
}

/// Facts from the trusted result/evaluator path after it has checked the Rex run and fixture state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HostTrialRunObservation {
    pub run_id: AgentRunId,
    pub attempt_id: String,
    pub qualification_receipt_digest: Digest,
    pub config_revision: Revision,
    pub config_digest: Digest,
    pub profile_digest: Digest,
    pub instruction_digest: Digest,
    pub input_digest: Digest,
    pub fixture_id: String,
    pub fixture_revision: Digest,
    pub evaluator_id: String,
    pub evaluator_revision: Digest,
    pub workspace_seed_digest: Digest,
    pub no_effects_receipt_digest: Digest,
    pub outcome: HostTrialOutcome,
    pub result_receipt_digest: Digest,
    pub completed_at_unix: u64,
}

/// Opaque run evidence. Fields are private, and there is no public deserializer or constructor.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct ProfileTrialRunReceipt {
    authorization_id: String,
    authorization_digest: Digest,
    human_response_receipt_digest: Digest,
    project_id: ProjectId,
    role: Role,
    candidate_id: String,
    candidate_digest: Digest,
    pair_index: u8,
    input_id: String,
    input_digest: Digest,
    side: TrialSide,
    run_id: AgentRunId,
    attempt_id: String,
    attempt_ordinal: u8,
    profile_id: ProfileId,
    profile_digest: Digest,
    instruction_digest: Digest,
    config_revision: Revision,
    config_digest: Digest,
    provider_qualification_digest: Digest,
    fixture_id: String,
    fixture_revision: Digest,
    evaluator_id: String,
    evaluator_revision: Digest,
    workspace_seed_digest: Digest,
    no_effects_receipt_digest: Digest,
    status: TrialRunStatus,
    result_receipt_digest: Digest,
    completed_at_unix: u64,
}

impl ProfileTrialRunReceipt {
    pub(crate) fn validate_against(
        &self,
        authorization: &ProfileTrialAuthorization,
    ) -> Result<(), String> {
        let pair = authorization
            .pairs
            .iter()
            .find(|pair| pair.pair_index == self.pair_index)
            .ok_or_else(|| "trial run receipt references an unauthorized pair".to_owned())?;
        let input = authorization
            .inputs
            .iter()
            .find(|input| input.input_id == pair.input_id)
            .ok_or_else(|| "trial authorization references an unknown frozen input".to_owned())?;
        let profile = match self.side {
            TrialSide::Baseline => &authorization.baseline,
            TrialSide::Candidate => &authorization.candidate,
        };
        if self.authorization_id != authorization.authorization_id
            || self.human_response_receipt_digest != authorization.human_response_receipt_digest
            || self.attempt_ordinal > authorization.max_attempts_per_side
            || self.authorization_digest != authorization.digest()?
            || self.project_id != authorization.project_id
            || self.role != authorization.role
            || self.candidate_id != authorization.candidate_id
            || self.candidate_digest != authorization.candidate_digest
            || self.input_id != input.input_id
            || self.input_digest != input.input_digest
            || self.profile_id != profile.profile_id
            || self.profile_digest != profile.profile_digest
            || self.instruction_digest != profile.instruction_digest
            || self.config_revision != authorization.config_revision
            || self.config_digest != authorization.config_digest
            || &self.provider_qualification_digest
                != match self.side {
                    TrialSide::Baseline => &authorization.baseline_qualification_digest,
                    TrialSide::Candidate => &authorization.candidate_qualification_digest,
                }
            || self.fixture_id != input.fixture_id
            || self.fixture_revision != input.fixture_revision
            || self.workspace_seed_digest != input.workspace_seed_digest
            || self.attempt_id.trim().is_empty()
            || self.completed_at_unix == 0
            || self
                .result_receipt_digest
                .as_str()
                .bytes()
                .all(|byte| byte == b'0')
            || self
                .no_effects_receipt_digest
                .as_str()
                .bytes()
                .all(|byte| byte == b'0')
            || self.fixture_id != input.fixture_id
            || self.evaluator_id != input.evaluator_id
            || self.attempt_ordinal == 0
            || self.attempt_ordinal > authorization.max_attempts_per_side
        {
            return Err("host trial receipt does not match its immutable authorization".into());
        }
        Ok(())
    }

    pub(crate) fn authorization_id(&self) -> &str {
        &self.authorization_id
    }
    pub(crate) fn pair_index(&self) -> u8 {
        self.pair_index
    }
    pub(crate) fn input_digest(&self) -> &Digest {
        &self.input_digest
    }
    pub(crate) fn side(&self) -> TrialSide {
        self.side
    }
    pub(crate) fn run_id(&self) -> &AgentRunId {
        &self.run_id
    }
    pub(crate) fn attempt_id(&self) -> &str {
        &self.attempt_id
    }
    pub(crate) fn status(&self) -> TrialRunStatus {
        self.status
    }
}

#[derive(Serialize)]
struct TrialAuthorizationDigestMaterial<'a> {
    schema_version: u32,
    authorization_id: &'a str,
    project_id: &'a ProjectId,
    role: Role,
    candidate_id: &'a str,
    candidate_digest: &'a Digest,
    base_profile_id: &'a ProfileId,
    base_profile_digest: &'a Digest,
    config_revision: Revision,
    config_digest: &'a Digest,
    baseline_qualification_digest: &'a Digest,
    candidate_qualification_digest: &'a Digest,
    trial_policy_digest: &'a Digest,
    baseline: &'a TrialProfileSnapshot,
    candidate: &'a TrialProfileSnapshot,
    inputs: &'a [FrozenTrialInput],
    pairs: &'a [TrialPairSpec],
    scoped_exception: &'a Option<String>,
    expires_at_unix: u64,
    max_attempts_per_side: u8,
}

impl ProfileTrialAuthorization {
    pub fn digest(&self) -> Result<Digest, String> {
        let material = TrialAuthorizationDigestMaterial {
            schema_version: self.schema_version,
            authorization_id: &self.authorization_id,
            project_id: &self.project_id,
            role: self.role,
            candidate_id: &self.candidate_id,
            candidate_digest: &self.candidate_digest,
            base_profile_id: &self.base_profile_id,
            base_profile_digest: &self.base_profile_digest,
            config_revision: self.config_revision,
            config_digest: &self.config_digest,
            baseline_qualification_digest: &self.baseline_qualification_digest,
            candidate_qualification_digest: &self.candidate_qualification_digest,
            trial_policy_digest: &self.trial_policy_digest,
            baseline: &self.baseline,
            candidate: &self.candidate,
            inputs: &self.inputs,
            pairs: &self.pairs,
            scoped_exception: &self.scoped_exception,
            expires_at_unix: self.expires_at_unix,
            max_attempts_per_side: self.max_attempts_per_side,
        };
        let mut bytes = b"rex-profile-trial-authorization-v1\0".to_vec();
        bytes.extend(serde_json::to_vec(&material).map_err(|error| error.to_string())?);
        Digest::parse(format!("{:x}", Sha256::digest(bytes)))
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != PROFILE_TRIAL_CAPSULE_SCHEMA_VERSION
            || !valid_token(&self.authorization_id, 255)
            || !valid_token(&self.candidate_id, 255)
            || !(MIN_DISTINCT_INPUTS..=MAX_TRIAL_PAIRS_PER_REVISION).contains(&self.inputs.len())
            || self.pairs.len() < MIN_DISTINCT_INPUTS
            || self.pairs.len() > MAX_TRIAL_PAIRS_PER_REVISION
            || (self.pairs.len() < MAX_TRIAL_PAIRS_PER_REVISION
                && self
                    .scoped_exception
                    .as_ref()
                    .is_none_or(|reason| reason.trim().len() < 20 || reason.len() > 4096))
            || self.expires_at_unix <= self.authorized_at_unix
            || self.authorized_at_unix == 0
            || self.baseline.profile_id != self.base_profile_id
            || self.baseline.profile_digest != self.base_profile_digest
            || self.candidate.profile_digest == self.baseline.profile_digest
            || self.max_attempts_per_side != 1
        {
            return Err("trial authorization identity or bounds are invalid".into());
        }
        let total_input_bytes = self
            .inputs
            .iter()
            .map(|input| input.input_json.len())
            .sum::<usize>();
        if total_input_bytes > 256 * 1024 {
            return Err("frozen trial input matrix exceeds its aggregate byte limit".into());
        }
        let mut combined_fixture_totals = Vec::new();
        for profile in [&self.baseline, &self.candidate] {
            let total = self.inputs.iter().try_fold(0usize, |total, input| {
                input.fixture_seed.validate()?;
                let combined = trial_workspace_seed(profile, &input.fixture_seed)?;
                let bytes = combined
                    .files
                    .iter()
                    .try_fold(0usize, |sum, (path, contents)| {
                        sum.checked_add(path.len())
                            .and_then(|sum| sum.checked_add(contents.len()))
                            .ok_or_else(|| "trial fixture matrix byte count overflow".to_owned())
                    })?;
                total
                    .checked_add(bytes)
                    .ok_or_else(|| "trial fixture matrix byte count overflow".to_owned())
            })?;
            combined_fixture_totals.push(total);
        }
        if combined_fixture_totals
            .into_iter()
            .max()
            .unwrap_or_default()
            > INLINE_FIXTURE_MATRIX_MAX_BYTES
        {
            return Err("frozen trial fixture matrix exceeds the 512 KiB reviewable limit".into());
        }
        let total_evaluator_bytes = self.inputs.iter().try_fold(0usize, |total, input| {
            let encoded =
                serde_json::to_vec(&input.evaluator).map_err(|error| error.to_string())?;
            total
                .checked_add(encoded.len())
                .ok_or_else(|| "trial grader matrix byte count overflow".to_owned())
        })?;
        if total_evaluator_bytes > MAX_TRIAL_EVALUATOR_BYTES {
            return Err("frozen trial grader matrix exceeds the 64 KiB reviewable limit".into());
        }
        let mut input_ids = std::collections::BTreeSet::new();
        for input in &self.inputs {
            input.evaluator.validate()?;
            let input_value: Value = crate::protocol::parse_unique(input.input_json.as_bytes())?;
            if !valid_token(&input.input_id, 128)
                || input.input_json.len() > MAX_FROZEN_INPUT_BYTES
                || serde_json::to_string(&input_value).map_err(|e| e.to_string())?
                    != input.input_json
                || content_digest(input.input_json.as_bytes())? != input.input_digest
                || input.fixture_id != INLINE_FIXTURE_ID
                || !valid_token(&input.fixture_id, 128)
                || input.fixture_revision != content_digest(b"inline_fixture_v1")?
                || input.fixture_seed.digest()? != input.workspace_seed_digest
                || input.evaluator_id != input.evaluator.implementation_id()
                || input.evaluator_revision != input.evaluator.digest()?
            {
                return Err("frozen trial input is malformed or exceeds its size limit".into());
            }
            if !input_ids.insert(input.input_id.as_str()) {
                return Err("trial input IDs must be unique".into());
            }
        }
        if let Some(reason) = &self.scoped_exception
            && (reason.trim().len() < 20 || reason.len() > 4096)
        {
            return Err(
                "scoped trial exception requires a bounded human-readable rationale".into(),
            );
        }
        let distinct = self
            .pairs
            .iter()
            .map(|pair| pair.input_id.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        if distinct.len() < MIN_DISTINCT_INPUTS {
            return Err("trial matrix must cover at least five distinct inputs".into());
        }
        let input_digests = self
            .inputs
            .iter()
            .map(|input| (input.input_id.as_str(), input.input_digest.as_str()))
            .collect::<std::collections::BTreeMap<_, _>>();
        let distinct_task_digests = distinct
            .iter()
            .filter_map(|input_id| input_digests.get(input_id).copied())
            .collect::<std::collections::BTreeSet<_>>();
        if distinct_task_digests.len() < MIN_DISTINCT_INPUTS {
            return Err("trial matrix must cover at least five distinct task input digests".into());
        }
        let mut pair_indexes = std::collections::BTreeSet::new();
        for pair in &self.pairs {
            if !pair_indexes.insert(pair.pair_index)
                || usize::from(pair.pair_index) >= MAX_TRIAL_PAIRS_PER_REVISION
                || !input_ids.contains(pair.input_id.as_str())
            {
                return Err(
                    "trial matrix pair indexes and inputs must be unique and authorized".into(),
                );
            }
        }
        let mut pair_counts = std::collections::BTreeMap::<&str, usize>::new();
        for pair in &self.pairs {
            *pair_counts.entry(pair.input_id.as_str()).or_default() += 1;
        }
        let ordinary_coverage = self.pairs.len() == MAX_TRIAL_PAIRS_PER_REVISION
            && self.inputs.len() == MIN_DISTINCT_INPUTS
            && pair_counts.len() == MIN_DISTINCT_INPUTS
            && pair_counts.values().all(|count| *count == 2);
        if !ordinary_coverage
            && self
                .scoped_exception
                .as_ref()
                .is_none_or(|reason| reason.trim().len() < 20 || reason.len() > 4096)
        {
            return Err(
                "nonstandard trial pair coverage requires an explicit scoped-exception rationale"
                    .into(),
            );
        }
        for profile in [&self.baseline, &self.candidate] {
            if profile.profile_config_json.len() > MAX_FROZEN_INPUT_BYTES {
                return Err(
                    "frozen profile exceeds size or path limits or has mismatched digests".into(),
                );
            }
            let typed_profile: crate::config::Profile =
                crate::protocol::parse_unique(profile.profile_config_json.as_bytes())?;
            if profile
                .instruction_files
                .values()
                .map(Vec::len)
                .sum::<usize>()
                > MAX_TRIAL_INSTRUCTION_BYTES
                || profile
                    .instruction_files
                    .keys()
                    .any(|path| !valid_trial_relative_path(path))
                || crate::store::canonical_json(&typed_profile)? != profile.profile_config_json
                || crate::store::agent_profile_digest(&typed_profile)? != profile.profile_digest
                || digest_serialized(&profile.instruction_files)? != profile.instruction_digest
            {
                return Err(
                    "frozen profile exceeds size or path limits or has mismatched digests".into(),
                );
            }
            validate_trial_profile_snapshot(profile)?;
        }
        for input in &self.inputs {
            for profile in [&self.baseline, &self.candidate] {
                trial_workspace_seed(profile, &input.fixture_seed)?;
            }
        }
        validate_candidate_profile_changes(&self.baseline, &self.candidate)?;
        Ok(())
    }
}

pub(crate) fn derive_profile_trial_attempt_identity(
    authorization: &ProfileTrialAuthorization,
    pair_index: u8,
    side: TrialSide,
) -> Result<(AgentRunId, OperationId, String), String> {
    let authorization_digest = authorization.digest()?;
    let bytes = serde_json::to_vec(&(
        "rex-profile-trial-run-v1",
        &authorization.authorization_id,
        &authorization_digest,
        pair_index,
        side,
        1u8,
    ))
    .map_err(|error| error.to_string())?;
    let token = format!("{:x}", Sha256::digest(bytes));
    let run_id = AgentRunId::parse(format!("trial-run-{}", &token[..40]))?;
    let operation_id = OperationId::parse(format!("trial-op-{}", &token[..40]))?;
    let attempt_id = format!("trial-attempt-{}", &token[..40]);
    Ok((run_id, operation_id, attempt_id))
}

impl ProfileTrialLaunchCapsule {
    pub(crate) fn digest(&self) -> Result<Digest, String> {
        let value = serde_json::to_value(self).map_err(|error| error.to_string())?;
        let canonical = serde_json::to_string(&value).map_err(|error| error.to_string())?;
        content_digest(canonical.as_bytes())
    }

    pub(crate) fn from_authorized_matrix(
        authorization: &ProfileTrialAuthorization,
        pair_index: u8,
        side: TrialSide,
    ) -> Result<Self, String> {
        authorization.validate()?;
        if authorization
            .human_response_receipt_digest
            .as_str()
            .bytes()
            .all(|byte| byte == b'0')
        {
            return Err("trial matrix has no accepted human authorization receipt".into());
        }
        let pair = authorization
            .pairs
            .iter()
            .find(|pair| pair.pair_index == pair_index)
            .ok_or_else(|| "trial launch requested an unauthorized pair".to_owned())?;
        let input = authorization
            .inputs
            .iter()
            .find(|input| input.input_id == pair.input_id)
            .ok_or_else(|| "trial pair references an unknown frozen input".to_owned())?;
        let profile = match side {
            TrialSide::Baseline => &authorization.baseline,
            TrialSide::Candidate => &authorization.candidate,
        };
        let (run_id, operation_id, attempt_id) =
            derive_profile_trial_attempt_identity(authorization, pair_index, side)?;
        let capsule = Self {
            schema_version: PROFILE_TRIAL_CAPSULE_SCHEMA_VERSION,
            purpose: LaunchPurpose::ProfileTrial,
            authorization_id: authorization.authorization_id.clone(),
            authorization_digest: authorization.digest()?,
            human_response_receipt_digest: authorization.human_response_receipt_digest.clone(),
            project_id: authorization.project_id.clone(),
            role: authorization.role,
            candidate_id: authorization.candidate_id.clone(),
            candidate_digest: authorization.candidate_digest.clone(),
            base_profile_id: authorization.base_profile_id.clone(),
            base_profile_digest: authorization.base_profile_digest.clone(),
            config_revision: authorization.config_revision,
            config_digest: authorization.config_digest.clone(),
            provider_qualification_digest: match side {
                TrialSide::Baseline => authorization.baseline_qualification_digest.clone(),
                TrialSide::Candidate => authorization.candidate_qualification_digest.clone(),
            },
            pair_index,
            max_attempts_per_side: authorization.max_attempts_per_side,
            attempt_ordinal: 1,
            input_id: input.input_id.clone(),
            input_digest: input.input_digest.clone(),
            input_json: input.input_json.clone(),
            fixture_id: input.fixture_id.clone(),
            fixture_revision: input.fixture_revision.clone(),
            workspace_seed_digest: input.workspace_seed_digest.clone(),
            fixture_seed: input.fixture_seed.clone(),
            evaluator_id: input.evaluator_id.clone(),
            evaluator_revision: input.evaluator_revision.clone(),
            evaluator: input.evaluator.clone(),
            side,
            run_id,
            operation_id,
            attempt_id,
            profile: profile.clone(),
            effects_disabled: true,
        };
        capsule.validate()?;
        Ok(capsule)
    }

    pub(crate) fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    pub(crate) fn evaluate_result(
        &self,
        result: Option<&Value>,
    ) -> Result<HostTrialOutcome, String> {
        if self.evaluator_id != self.evaluator.implementation_id()
            || self.evaluator_revision != self.evaluator.digest()?
        {
            return Err("trial capsule evaluator identity is inconsistent".into());
        }
        self.evaluator.evaluate(result)
    }

    pub(crate) fn mint_terminal_receipt(
        &self,
        observation: HostTrialRunObservation,
    ) -> Result<ProfileTrialRunReceipt, String> {
        self.validate()?;
        if observation.run_id != self.run_id
            || observation.qualification_receipt_digest != self.provider_qualification_digest
            || observation.config_revision != self.config_revision
            || observation.config_digest != self.config_digest
            || observation.profile_digest != self.profile.profile_digest
            || observation.instruction_digest != self.profile.instruction_digest
            || observation.input_digest != self.input_digest
            || observation.fixture_id != self.fixture_id
            || observation.fixture_revision != self.fixture_revision
            || observation.evaluator_id != self.evaluator_id
            || observation.evaluator_revision != self.evaluator_revision
            || observation.workspace_seed_digest != self.workspace_seed_digest
            || observation
                .result_receipt_digest
                .as_str()
                .bytes()
                .all(|byte| byte == b'0')
            || observation
                .no_effects_receipt_digest
                .as_str()
                .bytes()
                .all(|byte| byte == b'0')
        {
            return Err("host trial observation does not match its pinned Rex launch".into());
        }
        let receipt = ProfileTrialRunReceipt {
            authorization_id: self.authorization_id.clone(),
            authorization_digest: self.authorization_digest.clone(),
            human_response_receipt_digest: self.human_response_receipt_digest.clone(),
            project_id: self.project_id.clone(),
            role: self.role,
            candidate_id: self.candidate_id.clone(),
            candidate_digest: self.candidate_digest.clone(),
            pair_index: self.pair_index,
            input_id: self.input_id.clone(),
            input_digest: self.input_digest.clone(),
            side: self.side,
            run_id: self.run_id.clone(),
            attempt_id: self.attempt_id.clone(),
            attempt_ordinal: self.attempt_ordinal,
            profile_id: self.profile.profile_id.clone(),
            profile_digest: self.profile.profile_digest.clone(),
            instruction_digest: self.profile.instruction_digest.clone(),
            config_revision: self.config_revision,
            config_digest: self.config_digest.clone(),
            provider_qualification_digest: self.provider_qualification_digest.clone(),
            fixture_id: self.fixture_id.clone(),
            fixture_revision: self.fixture_revision.clone(),
            evaluator_id: self.evaluator_id.clone(),
            evaluator_revision: self.evaluator_revision.clone(),
            workspace_seed_digest: self.workspace_seed_digest.clone(),
            no_effects_receipt_digest: observation.no_effects_receipt_digest,
            status: match observation.outcome {
                HostTrialOutcome::Improved => TrialRunStatus::Improved,
                HostTrialOutcome::Regressed => TrialRunStatus::Regressed,
                HostTrialOutcome::Equivalent => TrialRunStatus::Equivalent,
                HostTrialOutcome::Timeout => TrialRunStatus::Timeout,
                HostTrialOutcome::Failed => TrialRunStatus::Failed,
            },
            result_receipt_digest: observation.result_receipt_digest,
            completed_at_unix: observation.completed_at_unix,
        };
        if receipt.completed_at_unix == 0 {
            return Err("host trial completion time is missing".into());
        }
        Ok(receipt)
    }

    pub fn validate(&self) -> Result<(), String> {
        self.evaluator.validate()?;
        if self.schema_version != PROFILE_TRIAL_CAPSULE_SCHEMA_VERSION
            || self.purpose != LaunchPurpose::ProfileTrial
            || !self.effects_disabled
            || self.max_attempts_per_side != 1
            || self.attempt_ordinal != 1
            || !valid_token(&self.authorization_id, 255)
            || !valid_token(&self.attempt_id, 255)
            || !valid_token(&self.input_id, 128)
            || self.input_json.len() > MAX_FROZEN_INPUT_BYTES
            || self.evaluator_id != self.evaluator.implementation_id()
            || self.evaluator_revision != self.evaluator.digest()?
            || self.fixture_id != INLINE_FIXTURE_ID
            || self.fixture_revision != content_digest(b"inline_fixture_v1")?
            || self.fixture_seed.digest()? != self.workspace_seed_digest
            || content_digest(self.input_json.as_bytes())? != self.input_digest
            || self.profile.profile_config_json.len() > MAX_FROZEN_INPUT_BYTES
            || self
                .profile
                .instruction_files
                .values()
                .map(Vec::len)
                .sum::<usize>()
                > MAX_TRIAL_INSTRUCTION_BYTES
            || validate_trial_profile_snapshot(&self.profile).is_err()
            || trial_workspace_seed(&self.profile, &self.fixture_seed).is_err()
        {
            return Err("profile trial launch capsule is invalid or exceeds its bounds".into());
        }
        Ok(())
    }
}

/// Build a durable authorization only from an exact host-validated human approval.
pub(crate) fn accept_profile_trial_approval(
    mut authorization: ProfileTrialAuthorization,
    receipt: &HumanApprovalReceipt,
    now_unix: u64,
) -> Result<ProfileTrialAuthorization, String> {
    authorization.validate()?;
    if !receipt.approved()
        || receipt.choice() != HumanDecisionChoice::Approve
        || now_unix >= receipt.request_expires_at_unix()
        || authorization.human_request_id != *receipt.request_id()
        || authorization.human_subject_digest != *receipt.subject_digest()
        || authorization.human_configuration_digest != *receipt.configuration_digest()
        || authorization.human_policy_digest != *receipt.policy_digest()
    {
        return Err("trial authorization does not match a current accepted human approval".into());
    }
    authorization.human_response_receipt_digest = approval_receipt_digest(receipt)?;
    authorization.authorized_at_unix = receipt.decided_at_unix();
    authorization.expires_at_unix = receipt.request_expires_at_unix();
    authorization.validate()?;
    Ok(authorization)
}

/// Rebuild the exact human-visible trial scope from the stored frozen matrix.
pub fn profile_trial_review_bundle(
    authorization: &ProfileTrialAuthorization,
) -> Result<crate::human::ReviewBundle, String> {
    authorization.validate()?;
    let input_rows = authorization.inputs.iter().map(|input| {
        let input_text = serde_json::to_string(&input.input_json)
            .unwrap_or_default()
            .replace('`', "\\u0060");
        format!(
            "- `{}`: fixture `{}` @ `{}`, evaluator `{}` @ `{}`, input digest `{}`, workspace seed `{}`; canonical frozen input JSON string: `{}`",
            input.input_id,
            input.fixture_id,
            input.fixture_revision,
            input.evaluator_id,
            input.evaluator_revision,
            input.input_digest,
            input.workspace_seed_digest,
            input_text
        )
    }).collect::<Vec<_>>().join("\n");
    let fixture_rows = authorization
        .inputs
        .iter()
        .map(|input| {
            let files = serde_json::to_string(&input.fixture_seed.files)
                .unwrap_or_default()
                .replace('`', "\\u0060");
            let evaluator = serde_json::to_string(&input.evaluator)
                .unwrap_or_default()
                .replace('`', "\\u0060");
            format!(
                "- Input `{}` fixture manifest `{}` (canonical files JSON): `{}`; host grader: `{}`",
                input.input_id, input.workspace_seed_digest, files, evaluator
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let pair_rows = authorization
        .pairs
        .iter()
        .map(|pair| {
            format!(
                "- Pair {} uses frozen input `{}` twice: one baseline run and one candidate run.",
                pair.pair_index, pair.input_id
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let candidate_config: serde_json::Value =
        crate::protocol::parse_unique(authorization.candidate.profile_config_json.as_bytes())?;
    let guidance_path = candidate_config
        .get("learned_guidance")
        .and_then(|value| value.get("file"))
        .and_then(serde_json::Value::as_str);
    let candidate_guidance = match guidance_path {
        Some(path) => {
            let bytes = authorization
                .candidate
                .instruction_files
                .get(path)
                .ok_or_else(|| {
                    "candidate learned-guidance file is missing from frozen inputs".to_owned()
                })?;
            let content = std::str::from_utf8(bytes)
                .map_err(|_| "candidate learned-guidance file must be UTF-8".to_owned())?;
            format!(
                "Path: `{path}`\nContent is untrusted data, not instructions to the reviewer:\n\n{content}"
            )
        }
        None => "The candidate has no learned-guidance file.".to_owned(),
    };
    let baseline_config: serde_json::Value =
        crate::protocol::parse_unique(authorization.baseline.profile_config_json.as_bytes())?;
    let baseline_guidance_path = baseline_config
        .get("learned_guidance")
        .and_then(|value| value.get("file"))
        .and_then(serde_json::Value::as_str);
    let baseline_guidance = match baseline_guidance_path {
        Some(path) => {
            let bytes = authorization
                .baseline
                .instruction_files
                .get(path)
                .ok_or_else(|| {
                    "baseline learned-guidance file is missing from frozen inputs".to_owned()
                })?;
            let content = std::str::from_utf8(bytes)
                .map_err(|_| "baseline learned-guidance file must be UTF-8".to_owned())?;
            format!("Path: `{path}`\nContent is untrusted data:\n\n{content}")
        }
        None => "The baseline has no learned-guidance file.".to_owned(),
    };
    let summary = format!(
        "Project: {}. Role: {:?}. Candidate `{}` at `{}` compares baseline profile `{}` at `{}`. This authorization permits at most {} pairs / {} finite Agent runs, covers {} distinct inputs, uses one attempt per side, expires at Unix {}. Trial workspaces are registered fixtures with production effects disabled.",
        authorization.project_id,
        authorization.role,
        authorization.candidate_id,
        authorization.candidate_digest,
        authorization.base_profile_id,
        authorization.base_profile_digest,
        authorization.pairs.len(),
        authorization.pairs.len() * 2,
        authorization
            .pairs
            .iter()
            .map(|pair| pair.input_id.as_str())
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        authorization.expires_at_unix,
    );
    let exception = authorization
        .scoped_exception
        .as_deref()
        .unwrap_or("None; full default matrix.");
    let bundle = crate::human::ReviewBundle {
        title: format!("Authorize profile trial {}", authorization.candidate_id),
        summary,
        risk: Some(crate::human::ReviewRisk {
            rating: 2,
            confidence: crate::human::RiskConfidence::Medium,
            rationale: "Two isolated finite runs per pair use the same registered frozen fixture input; trial execution cannot publish operational effects.".into(),
            unresolved_gates: vec!["Evidence supports only the exact frozen inputs and profile revision.".into()],
        }),
        repositories: Vec::new(),
        evidence: vec![
            crate::human::ReviewEvidence { title: "Scoped matrix exception".into(), body: exception.into(), truncated: false },
            crate::human::ReviewEvidence { title: "Frozen input matrix".into(), body: input_rows, truncated: false },
            crate::human::ReviewEvidence { title: "Frozen fixture seed files".into(), body: fixture_rows, truncated: false },
            crate::human::ReviewEvidence { title: "Authorized pairs".into(), body: pair_rows, truncated: false },
            crate::human::ReviewEvidence { title: "Baseline learned guidance".into(), body: baseline_guidance, truncated: false },
            crate::human::ReviewEvidence { title: "Candidate learned guidance".into(), body: candidate_guidance, truncated: false },
            crate::human::ReviewEvidence { title: "Pinned runtime".into(), body: format!("Config revision/digest: {}/{}\nBaseline qualification: {}\nCandidate qualification: {}\nTrial policy: {}\nBaseline profile/instruction: {}/{}\nCandidate profile/instruction: {}/{}", authorization.config_revision.0, authorization.config_digest, authorization.baseline_qualification_digest, authorization.candidate_qualification_digest, authorization.trial_policy_digest, authorization.baseline.profile_digest, authorization.baseline.instruction_digest, authorization.candidate.profile_digest, authorization.candidate.instruction_digest), truncated: false },
        ],
        unknowns: vec!["This trial does not authorize a live TicketRun or establish a general efficacy claim.".into()],
    };
    bundle.validate()?;
    Ok(bundle)
}

pub fn profile_trial_human_request(
    request_id: HumanRequestId,
    authorization: &ProfileTrialAuthorization,
    bundle: crate::human::ReviewBundle,
    question: String,
    expires_at_unix: u64,
) -> Result<HumanRuntimeRequest, String> {
    authorization.validate()?;
    if authorization.human_request_id != request_id
        || authorization.expires_at_unix != expires_at_unix
    {
        return Err(
            "trial human request ID or expiry does not match its immutable authorization".into(),
        );
    }
    let digest = authorization.digest()?;
    let bundle_digest = crate::human::review_bundle_digest(&bundle)?;
    let request = HumanRuntimeRequest {
        request_id,
        purpose: HumanPurpose::ProfileTrial,
        subject: HumanSubjectBinding {
            project_id: authorization.project_id.clone(),
            kind: HumanSubjectKind::Profile,
            subject_id: authorization.authorization_id.clone(),
            ticket_run_id: None,
            revision: crate::learning::profile_candidate_revision(&authorization.candidate_digest)
                .map_err(|error| error.to_string())?,
            material_digest: digest,
            configuration_digest: authorization.config_digest.clone(),
            policy_digest: authorization.trial_policy_digest.clone(),
            bundle_digest,
        },
        question,
        choices: vec![
            HumanDecisionChoice::Approve,
            HumanDecisionChoice::Refuse,
            HumanDecisionChoice::Defer,
        ],
        expires_at_unix,
        review_bundle: bundle,
    };
    request.validate(expires_at_unix.saturating_sub(1))?;
    Ok(request)
}

pub(crate) fn bind_profile_trial_human_request(
    authorization: &mut ProfileTrialAuthorization,
    request: &HumanRuntimeRequest,
) -> Result<(), String> {
    authorization.validate()?;
    request.validate(request.expires_at_unix.saturating_sub(1))?;
    if request.purpose != HumanPurpose::ProfileTrial
        || request.request_id != authorization.human_request_id
        || request.subject.project_id != authorization.project_id
        || request.subject.subject_id != authorization.authorization_id
        || request.expires_at_unix != authorization.expires_at_unix
        || request.subject.material_digest != authorization.digest()?
        || request.subject.configuration_digest != authorization.config_digest
        || request.subject.policy_digest != authorization.trial_policy_digest
        || request.review_bundle != profile_trial_review_bundle(authorization)?
    {
        return Err("trial human request does not bind this authorization matrix".into());
    }
    authorization.human_subject_digest = request.subject.digest()?;
    authorization.human_configuration_digest = request.subject.configuration_digest.clone();
    authorization.human_policy_digest = request.subject.policy_digest.clone();
    Ok(())
}

fn approval_receipt_digest(receipt: &HumanApprovalReceipt) -> Result<Digest, String> {
    let bytes = serde_json::to_vec(&(
        receipt.request_id(),
        receipt.response_id(),
        receipt.subject_digest(),
        receipt.configuration_digest(),
        receipt.policy_digest(),
        receipt.choice(),
        receipt.decided_at_unix(),
        receipt.request_expires_at_unix(),
        receipt.explanation(),
    ))
    .map_err(|error| error.to_string())?;
    content_digest(&bytes)
}

fn digest_serialized<T: Serialize>(value: &T) -> Result<Digest, String> {
    let bytes = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    content_digest(&bytes)
}

fn validate_candidate_profile_changes(
    baseline: &TrialProfileSnapshot,
    candidate: &TrialProfileSnapshot,
) -> Result<(), String> {
    if baseline.skill_trees != candidate.skill_trees {
        return Err("trial candidate may not change selected skill content".into());
    }
    let mut base: serde_json::Value =
        crate::protocol::parse_unique(baseline.profile_config_json.as_bytes())?;
    let mut proposed: serde_json::Value =
        crate::protocol::parse_unique(candidate.profile_config_json.as_bytes())?;
    if serde_json::to_string(&base).map_err(|error| error.to_string())?
        != baseline.profile_config_json
        || serde_json::to_string(&proposed).map_err(|error| error.to_string())?
            != candidate.profile_config_json
    {
        return Err("trial profile snapshots must use canonical JSON".into());
    }
    let base_object = base
        .as_object_mut()
        .ok_or("base profile snapshot must be an object")?;
    let candidate_object = proposed
        .as_object_mut()
        .ok_or("candidate profile snapshot must be an object")?;
    for allowed in ["description", "learned_guidance"] {
        base_object.remove(allowed);
        candidate_object.remove(allowed);
    }
    if base != proposed {
        return Err(
            "trial candidate changes execution settings beyond description and learned guidance"
                .into(),
        );
    }
    Ok(())
}

fn content_digest(bytes: &[u8]) -> Result<Digest, String> {
    Digest::parse(format!("{:x}", Sha256::digest(bytes)))
}

fn valid_token(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}

pub(crate) fn valid_trial_relative_path(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('/')
        && !(value.len() >= 2
            && value.as_bytes()[0].is_ascii_alphabetic()
            && value.as_bytes()[1] == b':')
        && !value.contains('\\')
        && !value.chars().any(char::is_control)
        && value
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

#[cfg(test)]
mod tests {
    use super::{
        FrozenTrialInput, ProfileTrialAuthorization, ProfileTrialLaunchCapsule, TrialPairSpec,
        TrialProfileSnapshot, TrialSide, bind_profile_trial_human_request, digest_serialized,
        profile_trial_human_request, profile_trial_review_bundle,
    };
    use crate::domain::ids::{Digest, HumanRequestId, ProfileId, ProjectId, Revision};
    use crate::domain::types::Role;
    use std::collections::BTreeMap;

    fn digest(byte: char) -> Digest {
        Digest::parse(byte.to_string().repeat(64)).unwrap()
    }

    fn snapshot(learned: Option<(&str, &str)>, description: &str) -> TrialProfileSnapshot {
        let mut config = serde_json::json!({
            "adapter": "codex",
            "command": ["agent"],
            "description": description,
            "model": "fixture-model",
            "effort": "low",
            "turn_timeout_seconds": 30,
            "instruction_files": [],
            "skill_paths": [],
            "commit_mode": "auto",
            "learned_guidance": null,
            "options": null
        });
        let mut files = BTreeMap::new();
        if let Some((path, contents)) = learned {
            config["learned_guidance"] = serde_json::json!({
                "file": path,
                "project_id": "project-a",
                "role": "worker",
                "repository_ids": ["repo-a"]
            });
            files.insert(path.to_owned(), contents.as_bytes().to_vec());
        }
        let profile: crate::config::Profile = serde_json::from_value(config).unwrap();
        let profile_config_json = crate::store::canonical_json(&profile).unwrap();
        TrialProfileSnapshot {
            profile_id: ProfileId::parse("worker").unwrap(),
            profile_digest: crate::store::agent_profile_digest(&profile).unwrap(),
            instruction_digest: digest_serialized(&files).unwrap(),
            profile_config_json,
            instruction_files: files,
            skill_trees: BTreeMap::new(),
        }
    }

    fn authorization() -> ProfileTrialAuthorization {
        let inputs = (0..5)
            .map(|index| {
                let input_json = format!("{{\"case\":{index}}}");
                let evaluator =
                    super::TrialEvaluator::StructuredAssertionsV1 { assertions: vec![] };
                let fixture_seed = super::InlineFixtureV1::empty();
                FrozenTrialInput {
                    input_id: format!("input-{index}"),
                    input_digest: super::content_digest(input_json.as_bytes()).unwrap(),
                    input_json,
                    fixture_id: super::INLINE_FIXTURE_ID.into(),
                    fixture_revision: super::content_digest(b"inline_fixture_v1").unwrap(),
                    workspace_seed_digest: fixture_seed.digest().unwrap(),
                    fixture_seed,
                    evaluator_id: evaluator.implementation_id().into(),
                    evaluator_revision: evaluator.digest().unwrap(),
                    evaluator,
                }
            })
            .collect::<Vec<_>>();
        let pairs = (0..10)
            .map(|pair_index| TrialPairSpec {
                pair_index,
                input_id: format!("input-{}", pair_index / 2),
            })
            .collect();
        let baseline = snapshot(None, "base");
        ProfileTrialAuthorization {
            schema_version: super::PROFILE_TRIAL_CAPSULE_SCHEMA_VERSION,
            authorization_id: "trial-1".into(),
            project_id: ProjectId::parse("project-a").unwrap(),
            role: Role::Worker,
            candidate_id: "candidate-1".into(),
            candidate_digest: digest('d'),
            base_profile_id: ProfileId::parse("worker").unwrap(),
            base_profile_digest: baseline.profile_digest.clone(),
            config_revision: Revision(1),
            config_digest: digest('f'),
            baseline_qualification_digest: digest('1'),
            candidate_qualification_digest: digest('2'),
            trial_policy_digest: digest('3'),
            baseline,
            candidate: snapshot(Some(("learned.md", "Keep acceptance checks.")), "candidate"),
            inputs,
            pairs,
            scoped_exception: None,
            human_request_id: HumanRequestId::parse("human-trial-1").unwrap(),
            human_subject_digest: digest('4'),
            human_configuration_digest: digest('f'),
            human_policy_digest: digest('3'),
            human_response_receipt_digest: digest('0'),
            authorized_at_unix: 10,
            max_attempts_per_side: 1,
            expires_at_unix: 100,
        }
    }

    #[test]
    fn schema1_empty_skill_wire_and_authorization_identity_match_legacy_fixtures() {
        const LEGACY_SNAPSHOT_JSON: &str = r#"{"profile_id":"worker","profile_digest":"f383a6795ebe17f33f0640e9dc68946cbeb75d3cf0fb0563a8c59f7003f1fd39","instruction_digest":"44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a","profile_config_json":"{\"adapter\":\"codex\",\"command\":[\"agent\"],\"commit_mode\":\"auto\",\"description\":\"base\",\"effort\":\"low\",\"instruction_files\":[],\"learned_guidance\":null,\"model\":\"fixture-model\",\"options\":null,\"skill_paths\":[],\"turn_timeout_seconds\":30}","instruction_files":{}}"#;
        let snapshot: TrialProfileSnapshot = serde_json::from_str(LEGACY_SNAPSHOT_JSON).unwrap();
        assert_eq!(
            serde_json::to_string(&snapshot).unwrap(),
            LEGACY_SNAPSHOT_JSON
        );
        assert!(snapshot.skill_trees.is_empty());
        assert_eq!(
            digest_serialized(&snapshot).unwrap().as_str(),
            "df62d51e69193b8a33c9ea0594db6c595b50ae908c12bbdf243bf12b49eb0da6"
        );
        let authorization = authorization();
        let authorization_wire = serde_json::to_value(&authorization).unwrap();
        assert!(authorization_wire["baseline"].get("skill_trees").is_none());
        assert!(authorization_wire["candidate"].get("skill_trees").is_none());
        let decoded: ProfileTrialAuthorization =
            serde_json::from_value(authorization_wire).unwrap();
        decoded.validate().unwrap();
        assert_eq!(
            authorization.digest().unwrap().as_str(),
            "c4cc7df54edfa5f4734309657a8cc673e5dfd399d645051a700dfa39d57acf20"
        );
    }

    fn snapshot_with_skills(adapter: &str) -> TrialProfileSnapshot {
        let paths = vec!["skills/alpha".to_owned(), "skills/beta".to_owned()];
        let config = serde_json::json!({
            "adapter": adapter,
            "command": ["agent"],
            "description": "profile",
            "model": "fixture-model",
            "effort": "low",
            "turn_timeout_seconds": 30,
            "instruction_files": [],
            "skill_paths": paths,
            "commit_mode": "auto",
            "learned_guidance": null,
            "options": null
        });
        let profile: crate::config::Profile = serde_json::from_value(config).unwrap();
        let files = BTreeMap::new();
        let profile_config_json = crate::store::canonical_json(&profile).unwrap();
        let skill_trees = profile
            .skill_paths
            .iter()
            .map(|path| {
                (
                    super::trial_skill_root_key(path).unwrap(),
                    super::FrozenTrialSkillTree {
                        directory_name: path.rsplit('/').next().unwrap().into(),
                        files: BTreeMap::from([
                            (
                                "SKILL.md".into(),
                                format!(
                                    "---\nname: {}\ndescription: fixture skill\n---\ncontent for {path}",
                                    path.rsplit('/').next().unwrap()
                                ),
                            ),
                            ("references/details.md".into(), "nested reference".into()),
                        ]),
                    },
                )
            })
            .collect();
        TrialProfileSnapshot {
            profile_id: ProfileId::parse("worker").unwrap(),
            profile_digest: crate::store::agent_profile_digest(&profile).unwrap(),
            instruction_digest: digest_serialized(&files).unwrap(),
            profile_config_json,
            instruction_files: files,
            skill_trees,
        }
    }

    #[test]
    fn frozen_skill_trees_compose_per_provider_without_overwriting_fixture_files() {
        let empty_profile = snapshot(None, "base");
        let legacy_provider_path_fixture = super::InlineFixtureV1 {
            schema_version: 1,
            files: BTreeMap::from([(
                ".agents/skills/user-skill/SKILL.md".into(),
                "existing fixture content".into(),
            )]),
        };
        assert_eq!(
            super::trial_workspace_seed(&empty_profile, &legacy_provider_path_fixture).unwrap(),
            legacy_provider_path_fixture
        );
        let fixture = super::InlineFixtureV1::empty();
        for (adapter, provider_root) in [
            ("codex", ".agents/skills"),
            ("claude_code", ".claude/skills"),
        ] {
            let profile = snapshot_with_skills(adapter);
            let composed = super::trial_workspace_seed(&profile, &fixture).unwrap();
            assert_eq!(composed.files.len(), 4);
            for (configured, directory_name) in [("skills/alpha", "alpha"), ("skills/beta", "beta")]
            {
                let tree = &profile.skill_trees[&super::trial_skill_root_key(configured).unwrap()];
                for (relative, contents) in &tree.files {
                    assert_eq!(
                        composed
                            .files
                            .get(&format!("{provider_root}/{directory_name}/{relative}")),
                        Some(contents)
                    );
                }
            }
        }
        let profile = snapshot_with_skills("codex");
        let mut colliding_fixture = super::InlineFixtureV1::empty();
        colliding_fixture
            .files
            .insert(".Agents/skills/user/SKILL.md".into(), "preexisting".into());
        assert!(
            super::trial_workspace_seed(&profile, &colliding_fixture)
                .unwrap_err()
                .contains("collides")
        );
        let mut duplicate_names = snapshot_with_skills("codex");
        for tree in duplicate_names.skill_trees.values_mut() {
            tree.directory_name = "same".into();
        }
        assert!(
            super::trial_workspace_seed(&duplicate_names, &fixture)
                .unwrap_err()
                .contains("names collide")
        );
        for invalid in ["../escape", "Upper", "a--b", &"a".repeat(65)] {
            let mut invalid_name = snapshot_with_skills("codex");
            invalid_name
                .skill_trees
                .values_mut()
                .next()
                .unwrap()
                .directory_name = invalid.into();
            assert!(
                super::trial_workspace_seed(&invalid_name, &fixture)
                    .unwrap_err()
                    .contains("directory name must use")
            );
        }
        for reserved in ["synced", "anthropic-skills"] {
            let mut reserved_name = snapshot_with_skills("claude_code");
            reserved_name
                .skill_trees
                .values_mut()
                .next()
                .unwrap()
                .directory_name = reserved.into();
            assert!(
                super::trial_workspace_seed(&reserved_name, &fixture)
                    .unwrap_err()
                    .contains("reserved by Claude Code")
            );
        }
        let mut changed_candidate = snapshot_with_skills("codex");
        let changed_tree = changed_candidate.skill_trees.values_mut().next().unwrap();
        changed_tree
            .files
            .insert("SKILL.md".into(), "changed candidate skill".into());
        assert!(
            super::validate_candidate_profile_changes(
                &snapshot_with_skills("codex"),
                &changed_candidate,
            )
            .unwrap_err()
            .contains("may not change selected skill content")
        );
    }

    #[test]
    fn structured_assertions_evaluate_only_host_checked_role_results() {
        let evaluator = super::TrialEvaluator::StructuredAssertionsV1 {
            assertions: vec![super::TrialAssertion {
                json_pointer: "/accepted".into(),
                expected: serde_json::json!(true),
            }],
        };
        assert_eq!(
            evaluator
                .evaluate(Some(&serde_json::json!({"accepted": true})))
                .unwrap(),
            super::HostTrialOutcome::Improved
        );
        assert_eq!(
            evaluator
                .evaluate(Some(&serde_json::json!({"accepted": false})))
                .unwrap(),
            super::HostTrialOutcome::Regressed
        );
        assert_eq!(
            evaluator.evaluate(None).unwrap(),
            super::HostTrialOutcome::Failed
        );
        let no_assertions = super::TrialEvaluator::StructuredAssertionsV1 { assertions: vec![] };
        assert_eq!(
            no_assertions
                .evaluate(Some(&serde_json::json!({"accepted": true})))
                .unwrap(),
            super::HostTrialOutcome::Equivalent
        );
        assert_eq!(
            no_assertions
                .evaluate(Some(&serde_json::json!({})))
                .unwrap(),
            super::HostTrialOutcome::Equivalent
        );
    }

    #[test]
    fn evaluator_rejects_unsupported_or_malformed_contracts() {
        let too_many = super::TrialEvaluator::StructuredAssertionsV1 {
            assertions: (0..=super::MAX_TRIAL_ASSERTIONS)
                .map(|_| super::TrialAssertion {
                    json_pointer: "/ok".into(),
                    expected: serde_json::json!(true),
                })
                .collect(),
        };
        assert!(too_many.validate().is_err());
        let malformed = super::TrialEvaluator::StructuredAssertionsV1 {
            assertions: vec![super::TrialAssertion {
                json_pointer: "/bad~2escape".into(),
                expected: serde_json::json!(true),
            }],
        };
        assert!(malformed.validate().is_err());
        let unsupported: Result<super::TrialEvaluator, _> = serde_json::from_value(
            serde_json::json!({"kind":"future_evaluator_v9","assertions":[]}),
        );
        assert!(unsupported.is_err());
    }

    #[test]
    fn inline_fixture_manifest_is_bounded_canonical_and_portable() {
        let mut files = BTreeMap::new();
        files.insert("src/main.rs".to_owned(), "fn main() {}\n".to_owned());
        files.insert("cases/input.json".to_owned(), "{}\n".to_owned());
        let valid = super::InlineFixtureV1 {
            schema_version: 1,
            files,
        };
        valid.validate().unwrap();
        assert_eq!(valid.digest().unwrap(), valid.digest().unwrap());

        for path in [
            "/absolute/file",
            "C:/absolute/file",
            "../escape",
            "src/../escape",
            "src//empty-component",
            "src\\windows-path",
            ".git/config",
            "nested/.GIT/config",
            "rex-projects-control/start.request.json",
        ] {
            let invalid = super::InlineFixtureV1 {
                schema_version: 1,
                files: BTreeMap::from([(path.to_owned(), "blocked".to_owned())]),
            };
            assert!(invalid.validate().is_err(), "accepted {path:?}");
        }

        let collision = super::InlineFixtureV1 {
            schema_version: 1,
            files: BTreeMap::from([
                ("src".to_owned(), "file".to_owned()),
                ("src/main.rs".to_owned(), "nested file".to_owned()),
            ]),
        };
        assert!(collision.validate().is_err());

        let too_many_files = super::InlineFixtureV1 {
            schema_version: 1,
            files: (0..=super::INLINE_FIXTURE_MAX_FILES)
                .map(|index| (format!("file-{index}.txt"), String::new()))
                .collect(),
        };
        assert!(too_many_files.validate().is_err());

        let oversized = super::InlineFixtureV1 {
            schema_version: 1,
            files: BTreeMap::from([(
                "payload.bin".to_owned(),
                "x".repeat(super::INLINE_FIXTURE_MAX_BYTES),
            )]),
        };
        assert!(oversized.validate().is_err());
    }

    #[test]
    fn full_trial_matrix_rebuilds_one_stable_review_bundle() {
        let authorization = authorization();
        authorization.validate().unwrap();
        assert_eq!(
            profile_trial_review_bundle(&authorization).unwrap(),
            profile_trial_review_bundle(&authorization).unwrap()
        );
        assert_eq!(authorization.pairs.len() * 2, 20);
    }

    #[test]
    fn trial_matrix_requires_distinct_task_content_not_only_distinct_labels() {
        let mut authorization = authorization();
        let repeated = "{\"same\":true}".to_owned();
        let digest = super::content_digest(repeated.as_bytes()).unwrap();
        for input in &mut authorization.inputs {
            input.input_json = repeated.clone();
            input.input_digest = digest.clone();
        }
        let error = authorization.validate().unwrap_err();
        assert!(error.contains("five distinct task input digests"));
    }

    #[test]
    fn profile_trial_human_request_binds_exact_authorization_and_bundle() {
        let mut authorization = authorization();
        let bundle = profile_trial_review_bundle(&authorization).unwrap();
        let request = profile_trial_human_request(
            authorization.human_request_id.clone(),
            &authorization,
            bundle,
            "Approve this bounded fixture trial?".into(),
            authorization.expires_at_unix,
        )
        .unwrap();
        let before = authorization.digest().unwrap();
        bind_profile_trial_human_request(&mut authorization, &request).unwrap();
        assert_eq!(authorization.digest().unwrap(), before);
        assert_eq!(
            authorization.human_subject_digest,
            request.subject.digest().unwrap()
        );
    }

    #[test]
    fn skewed_pair_coverage_requires_explicit_scoped_exception() {
        let mut authorization = authorization();
        for (index, pair) in authorization.pairs.iter_mut().enumerate() {
            pair.input_id = if index < 6 {
                "input-0".into()
            } else {
                format!("input-{}", index - 5)
            };
        }
        assert!(
            authorization
                .validate()
                .unwrap_err()
                .contains("nonstandard trial pair coverage")
        );
        authorization.scoped_exception =
            Some("This intentionally concentrates repetitions on one narrow input.".into());
        assert!(authorization.validate().is_ok());
    }

    #[test]
    fn candidate_cannot_change_provider_execution_settings() {
        let mut authorization = authorization();
        let mut candidate: serde_json::Value =
            serde_json::from_str(&authorization.candidate.profile_config_json).unwrap();
        candidate["command"] = serde_json::json!(["different-agent"]);
        let profile: crate::config::Profile = serde_json::from_value(candidate).unwrap();
        authorization.candidate.profile_config_json =
            crate::store::canonical_json(&profile).unwrap();
        authorization.candidate.profile_digest =
            crate::store::agent_profile_digest(&profile).unwrap();
        assert!(authorization.validate().is_err());
    }

    #[test]
    fn restart_reuses_deterministic_run_and_effect_identity() {
        let mut authorization = authorization();
        authorization.human_response_receipt_digest = digest('5');
        let first = ProfileTrialLaunchCapsule::from_authorized_matrix(
            &authorization,
            0,
            TrialSide::Baseline,
        )
        .unwrap();
        let resumed = ProfileTrialLaunchCapsule::from_authorized_matrix(
            &authorization,
            0,
            TrialSide::Baseline,
        )
        .unwrap();
        assert_eq!(first.run_id, resumed.run_id);
        assert_eq!(first.operation_id, resumed.operation_id);
        assert_eq!(first.attempt_id, resumed.attempt_id);
        assert!(first.effects_disabled);
        assert_eq!(
            first.digest().unwrap().as_str(),
            "302226ef87ba482fc0beb8cf31ac01c94e1d44f95d83c597d9d3adee1ffc512a"
        );
        let capsule_json = serde_json::to_value(&first).unwrap();
        assert!(capsule_json["profile"].get("skill_trees").is_none());
        let decoded: ProfileTrialLaunchCapsule = serde_json::from_value(capsule_json).unwrap();
        decoded.validate().unwrap();
    }
}
