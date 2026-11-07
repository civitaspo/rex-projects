//! Human-authorized, restartable fixture execution for profile trials.
//!
//! The capsule contains the entire comparison input and both frozen profiles. The
//! controller persists it before launch; agent output cannot mint a terminal receipt.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::domain::ids::{AgentRunId, Digest, HumanRequestId, ProfileId, ProjectId, Revision};
use crate::domain::types::Role;
use crate::human_runtime::{
    HumanDecisionChoice, HumanPurpose, HumanRuntimeRequest, HumanSubjectBinding, HumanSubjectKind,
};
use crate::learning::{MAX_TRIAL_PAIRS_PER_REVISION, MIN_DISTINCT_INPUTS, TrialRunStatus};
use crate::store::human::HumanApprovalReceipt;

pub const MAX_FROZEN_INPUT_BYTES: usize = 256 * 1024;
pub const MAX_TRIAL_INSTRUCTION_BYTES: usize = 1024 * 1024;
pub const PROFILE_TRIAL_CAPSULE_SCHEMA_VERSION: u32 = 1;

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
#[serde(deny_unknown_fields)]
pub struct TrialProfileSnapshot {
    pub profile_id: ProfileId,
    pub profile_digest: Digest,
    pub instruction_digest: Digest,
    /// Canonical serialization of the complete immutable execution profile.
    pub profile_config_json: String,
    /// Exact profile instruction bytes loaded by the host, keyed by safe relative path.
    pub instruction_files: BTreeMap<String, Vec<u8>>,
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
    /// Identifies the host-side fixture evaluator and its immutable rubric revision.
    pub evaluator_id: String,
    pub evaluator_revision: Digest,
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
    pub provider_qualification_digest: Digest,
    pub baseline: TrialProfileSnapshot,
    pub candidate: TrialProfileSnapshot,
    pub inputs: Vec<FrozenTrialInput>,
    pub pairs: Vec<TrialPairSpec>,
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
    pub evaluator_id: String,
    pub evaluator_revision: Digest,
    pub side: TrialSide,
    pub run_id: AgentRunId,
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
    pub qualification_receipt_digest: Digest,
    pub config_revision: Revision,
    pub config_digest: Digest,
    pub profile_digest: Digest,
    pub instruction_digest: Digest,
    pub input_digest: Digest,
    pub fixture_revision: Digest,
    pub workspace_seed_digest: Digest,
    pub outcome: HostTrialOutcome,
    pub result_receipt_digest: Digest,
    pub completed_at_unix: u64,
}

/// Opaque run evidence. Fields are private, and there is no public deserializer or constructor.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
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
    workspace_seed_digest: Digest,
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
            || self.provider_qualification_digest != authorization.provider_qualification_digest
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
    pub(crate) fn authorization_digest(&self) -> &Digest {
        &self.authorization_digest
    }
    pub(crate) fn human_response_receipt_digest(&self) -> &Digest {
        &self.human_response_receipt_digest
    }
    pub(crate) fn project_id(&self) -> &ProjectId {
        &self.project_id
    }
    pub(crate) fn role(&self) -> Role {
        self.role
    }
    pub(crate) fn candidate_id(&self) -> &str {
        &self.candidate_id
    }
    pub(crate) fn candidate_digest(&self) -> &Digest {
        &self.candidate_digest
    }
    pub(crate) fn pair_index(&self) -> u8 {
        self.pair_index
    }
    pub(crate) fn input_id(&self) -> &str {
        &self.input_id
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
    pub(crate) fn attempt_ordinal(&self) -> u8 {
        self.attempt_ordinal
    }
    pub(crate) fn profile_id(&self) -> &ProfileId {
        &self.profile_id
    }
    pub(crate) fn profile_digest(&self) -> &Digest {
        &self.profile_digest
    }
    pub(crate) fn instruction_digest(&self) -> &Digest {
        &self.instruction_digest
    }
    pub(crate) fn config_revision(&self) -> Revision {
        self.config_revision
    }
    pub(crate) fn config_digest(&self) -> &Digest {
        &self.config_digest
    }
    pub(crate) fn provider_qualification_digest(&self) -> &Digest {
        &self.provider_qualification_digest
    }
    pub(crate) fn fixture_id(&self) -> &str {
        &self.fixture_id
    }
    pub(crate) fn fixture_revision(&self) -> &Digest {
        &self.fixture_revision
    }
    pub(crate) fn workspace_seed_digest(&self) -> &Digest {
        &self.workspace_seed_digest
    }
    pub(crate) fn status(&self) -> TrialRunStatus {
        self.status
    }
    pub(crate) fn result_receipt_digest(&self) -> &Digest {
        &self.result_receipt_digest
    }
    pub(crate) fn completed_at_unix(&self) -> u64 {
        self.completed_at_unix
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
    provider_qualification_digest: &'a Digest,
    baseline: &'a TrialProfileSnapshot,
    candidate: &'a TrialProfileSnapshot,
    inputs: &'a [FrozenTrialInput],
    pairs: &'a [TrialPairSpec],
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
            provider_qualification_digest: &self.provider_qualification_digest,
            baseline: &self.baseline,
            candidate: &self.candidate,
            inputs: &self.inputs,
            pairs: &self.pairs,
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
            || self.expires_at_unix <= self.authorized_at_unix
            || self.authorized_at_unix == 0
            || self.baseline.profile_id != self.base_profile_id
            || self.baseline.profile_digest != self.base_profile_digest
            || self.candidate.profile_digest == self.baseline.profile_digest
            || self.max_attempts_per_side != 1
        {
            return Err("trial authorization identity or bounds are invalid".into());
        }
        let mut input_ids = std::collections::BTreeSet::new();
        for input in &self.inputs {
            if !valid_token(&input.input_id, 128)
                || input.input_json.len() > MAX_FROZEN_INPUT_BYTES
                || content_digest(input.input_json.as_bytes())? != input.input_digest
                || !valid_token(&input.fixture_id, 128)
                || !valid_token(&input.evaluator_id, 128)
            {
                return Err("frozen trial input is malformed or exceeds its size limit".into());
            }
            if !input_ids.insert(input.input_id.as_str()) {
                return Err("trial input IDs must be unique".into());
            }
        }
        let distinct = self
            .pairs
            .iter()
            .map(|pair| pair.input_id.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        if distinct.len() < MIN_DISTINCT_INPUTS {
            return Err("trial matrix must cover at least five distinct inputs".into());
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
        for profile in [&self.baseline, &self.candidate] {
            if profile.profile_config_json.len() > MAX_FROZEN_INPUT_BYTES
                || profile
                    .instruction_files
                    .values()
                    .map(Vec::len)
                    .sum::<usize>()
                    > MAX_TRIAL_INSTRUCTION_BYTES
                || profile
                    .instruction_files
                    .keys()
                    .any(|path| !valid_relative_path(path))
                || content_digest(profile.profile_config_json.as_bytes())? != profile.profile_digest
                || digest_serialized(&profile.instruction_files)? != profile.instruction_digest
            {
                return Err(
                    "frozen profile exceeds size or path limits or has mismatched digests".into(),
                );
            }
        }
        validate_candidate_profile_changes(&self.baseline, &self.candidate)?;
        Ok(())
    }
}

impl ProfileTrialLaunchCapsule {
    pub(crate) fn from_authorized_matrix(
        authorization: &ProfileTrialAuthorization,
        pair_index: u8,
        side: TrialSide,
        run_id: AgentRunId,
        attempt_id: String,
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
            provider_qualification_digest: authorization.provider_qualification_digest.clone(),
            pair_index,
            max_attempts_per_side: authorization.max_attempts_per_side,
            attempt_ordinal: 1,
            input_id: input.input_id.clone(),
            input_digest: input.input_digest.clone(),
            input_json: input.input_json.clone(),
            fixture_id: input.fixture_id.clone(),
            fixture_revision: input.fixture_revision.clone(),
            workspace_seed_digest: input.workspace_seed_digest.clone(),
            evaluator_id: input.evaluator_id.clone(),
            evaluator_revision: input.evaluator_revision.clone(),
            side,
            run_id,
            attempt_id,
            profile: profile.clone(),
            effects_disabled: true,
        };
        capsule.validate()?;
        Ok(capsule)
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
            || observation.fixture_revision != self.fixture_revision
            || observation.workspace_seed_digest != self.workspace_seed_digest
            || observation
                .result_receipt_digest
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
            workspace_seed_digest: self.workspace_seed_digest.clone(),
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
        if self.schema_version != PROFILE_TRIAL_CAPSULE_SCHEMA_VERSION
            || self.purpose != LaunchPurpose::ProfileTrial
            || !self.effects_disabled
            || self.max_attempts_per_side != 1
            || self.attempt_ordinal != 1
            || !valid_token(&self.authorization_id, 255)
            || !valid_token(&self.attempt_id, 255)
            || !valid_token(&self.input_id, 128)
            || self.input_json.len() > MAX_FROZEN_INPUT_BYTES
            || content_digest(self.input_json.as_bytes())? != self.input_digest
            || self.profile.profile_config_json.len() > MAX_FROZEN_INPUT_BYTES
            || self
                .profile
                .instruction_files
                .values()
                .map(Vec::len)
                .sum::<usize>()
                > MAX_TRIAL_INSTRUCTION_BYTES
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
            policy_digest: authorization.provider_qualification_digest.clone(),
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
        || request.subject.material_digest != authorization.digest()?
        || request.subject.configuration_digest != authorization.config_digest
        || request.subject.policy_digest != authorization.provider_qualification_digest
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

fn valid_relative_path(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('/')
        && value
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}
