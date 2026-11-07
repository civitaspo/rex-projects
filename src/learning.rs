//! Bounded profile-learning trials and human-gated declarative promotion.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::domain::ids::{Digest, HumanRequestId, ProfileId, ProjectId};
use crate::domain::types::Role;

pub const MAX_TRIAL_PAIRS_PER_REVISION: usize = 10;
pub const MIN_DISTINCT_INPUTS: usize = 5;
pub const MAX_CANDIDATES_PER_PROJECT: usize = 5;
pub const MAX_PROFILE_PACKAGE_BYTES: usize = 1024 * 1024;
pub const MAX_PROFILE_PACKAGE_FILES: usize = 100;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrialOutcome {
    Improved,
    Regressed,
    Inconclusive,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrialRunStatus {
    Improved,
    Regressed,
    Equivalent,
    Timeout,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TrialObservation {
    pub input_digest: Digest,
    pub baseline: TrialRunStatus,
    pub candidate: TrialRunStatus,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TrialEvidence {
    pub outcome: TrialOutcome,
    pub distinct_inputs: usize,
    pub completed_pairs: usize,
    pub timed_out_pairs: usize,
    pub improved_pairs: usize,
    pub regressed_pairs: usize,
    pub rationale: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateStatus {
    Proposed,
    Trialing,
    AwaitingApproval,
    Promoted,
    Superseded,
    Expired,
    Rejected,
}

impl CandidateStatus {
    fn consumes_slot(self) -> bool {
        matches!(
            self,
            Self::Proposed | Self::Trialing | Self::AwaitingApproval
        )
    }
    fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Promoted | Self::Superseded | Self::Expired | Self::Rejected
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CandidateRevision {
    pub candidate_id: String,
    pub project_id: ProjectId,
    pub role: Role,
    pub digest: Digest,
    pub created_at: String,
    pub expires_at: String,
    pub status: CandidateStatus,
}

/// Pure durable-snapshot logic: persistence remains owned by the machine-level
/// controller's store rather than by this feature module.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CandidateLedger {
    pub revisions: Vec<CandidateRevision>,
}

impl CandidateLedger {
    pub fn register(&mut self, revision: CandidateRevision) -> Result<(), LearningError> {
        if !valid_candidate_id(&revision.candidate_id)
            || !sortable_utc(&revision.created_at)
            || !sortable_utc(&revision.expires_at)
            || revision.expires_at <= revision.created_at
        {
            return Err(LearningError::Invalid(
                "candidate identity and increasing expiry are required".into(),
            ));
        }
        if let Some(existing) = self.revisions.iter().find(|r| {
            r.project_id == revision.project_id
                && r.candidate_id == revision.candidate_id
                && r.digest == revision.digest
        }) {
            return if existing == &revision {
                Ok(())
            } else {
                Err(LearningError::Conflict(
                    "candidate revision identity already has different content".into(),
                ))
            };
        }
        let retained = self
            .revisions
            .iter()
            .filter(|r| r.project_id == revision.project_id)
            .count();
        let active = self
            .revisions
            .iter()
            .filter(|r| r.project_id == revision.project_id && r.status.consumes_slot())
            .count();
        if revision.status.consumes_slot() && active >= MAX_CANDIDATES_PER_PROJECT {
            return Err(LearningError::Conflict(
                "project has reached the active candidate limit".into(),
            ));
        }
        if retained >= 20 {
            let oldest_terminal = self
                .revisions
                .iter()
                .enumerate()
                .filter(|(_, r)| r.project_id == revision.project_id && r.status.is_terminal())
                .min_by_key(|(_, r)| r.created_at.clone())
                .map(|(index, _)| index);
            match oldest_terminal {
                Some(index) => {
                    self.revisions.remove(index);
                }
                None => {
                    return Err(LearningError::Conflict(
                        "project has reached the retained candidate revision limit".into(),
                    ));
                }
            }
        }
        self.revisions.push(revision);
        Ok(())
    }

    pub fn expire_due(&mut self, now_rfc3339_utc: &str) -> Result<usize, LearningError> {
        if !sortable_utc(now_rfc3339_utc) {
            return Err(LearningError::Invalid(
                "expiry comparison requires canonical UTC timestamps".into(),
            ));
        }
        let mut expired = 0;
        for revision in &mut self.revisions {
            if revision.status == CandidateStatus::Proposed
                && revision.expires_at.as_str() <= now_rfc3339_utc
            {
                revision.status = CandidateStatus::Expired;
                expired += 1;
            }
        }
        Ok(expired)
    }

    pub fn supersede(&mut self, project: &ProjectId, role: Role, except_digest: &Digest) -> usize {
        let mut count = 0;
        for revision in &mut self.revisions {
            if revision.project_id == *project
                && revision.role == role
                && revision.status.consumes_slot()
                && revision.digest != *except_digest
            {
                revision.status = CandidateStatus::Superseded;
                count += 1;
            }
        }
        count
    }
}

fn valid_candidate_id(value: &str) -> bool {
    value.len() <= 255
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn sortable_utc(value: &str) -> bool {
    if value.len() != 20
        || value.as_bytes()[4] != b'-'
        || value.as_bytes()[7] != b'-'
        || value.as_bytes()[10] != b'T'
        || value.as_bytes()[13] != b':'
        || value.as_bytes()[16] != b':'
        || value.as_bytes()[19] != b'Z'
        || !value
            .bytes()
            .enumerate()
            .all(|(i, b)| matches!(i, 4 | 7 | 10 | 13 | 16 | 19) || b.is_ascii_digit())
    {
        return false;
    }
    let parse = |range: std::ops::Range<usize>| value[range].parse::<u32>().ok();
    let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) = (
        parse(0..4),
        parse(5..7),
        parse(8..10),
        parse(11..13),
        parse(14..16),
        parse(17..19),
    ) else {
        return false;
    };
    if year == 0 || !(1..=12).contains(&month) || hour > 23 || minute > 59 || second > 59 {
        return false;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_days = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    (1..=month_days).contains(&day)
}

fn unix_seconds_to_utc(seconds: u64) -> Result<String, LearningError> {
    let days = i64::try_from(seconds / 86_400)
        .map_err(|_| LearningError::Invalid("approval timestamp is out of range".into()))?;
    let day_seconds = seconds % 86_400;
    let shifted = days + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    if !(1..=9999).contains(&year) {
        return Err(LearningError::Invalid(
            "approval timestamp is out of range".into(),
        ));
    }
    let hour = day_seconds / 3_600;
    let minute = day_seconds % 3_600 / 60;
    let second = day_seconds % 60;
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
    ))
}

/// Account for every reserved pair, including timeouts and failures. The fixed
/// sample is process governance, not statistical proof of effectiveness.
pub fn evaluate_trials(
    observations: &[TrialObservation],
    expected_pairs: usize,
) -> Result<TrialEvidence, LearningError> {
    if expected_pairs == 0
        || expected_pairs > MAX_TRIAL_PAIRS_PER_REVISION
        || observations.len() > expected_pairs
    {
        return Err(LearningError::Invalid(
            "trial pair count is outside the configured bound".into(),
        ));
    }
    let distinct_inputs = observations
        .iter()
        .map(|o| o.input_digest.clone())
        .collect::<BTreeSet<_>>()
        .len();
    let timed_out_pairs = observations
        .iter()
        .filter(|o| o.baseline == TrialRunStatus::Timeout || o.candidate == TrialRunStatus::Timeout)
        .count();
    let incomplete_pairs = observations
        .iter()
        .filter(|o| {
            matches!(o.baseline, TrialRunStatus::Timeout | TrialRunStatus::Failed)
                || matches!(
                    o.candidate,
                    TrialRunStatus::Timeout | TrialRunStatus::Failed
                )
        })
        .count();
    let improved_pairs = observations
        .iter()
        .filter(|o| {
            o.candidate == TrialRunStatus::Improved && o.baseline != TrialRunStatus::Improved
        })
        .count();
    let regressed_pairs = observations
        .iter()
        .filter(|o| {
            o.candidate == TrialRunStatus::Regressed
                || (o.baseline == TrialRunStatus::Improved
                    && o.candidate == TrialRunStatus::Equivalent)
        })
        .count();
    let complete = observations.len() == expected_pairs
        && distinct_inputs >= MIN_DISTINCT_INPUTS
        && incomplete_pairs == 0;
    let outcome = if regressed_pairs > 0 {
        TrialOutcome::Regressed
    } else if complete && improved_pairs > 0 {
        TrialOutcome::Improved
    } else {
        TrialOutcome::Inconclusive
    };
    Ok(TrialEvidence {
        outcome,
        distinct_inputs,
        completed_pairs: observations.len() - incomplete_pairs,
        timed_out_pairs,
        improved_pairs,
        regressed_pairs,
        rationale: if complete {
            "Completed bounded paired evaluation; results are qualitative evidence, not a statistical guarantee.".into()
        } else {
            "Evaluation incomplete or lacked enough distinct inputs; no efficacy claim is made."
                .into()
        },
    })
}

/// Evidence that the controller has validated a durable human response.
/// Its fields and constructor are crate-private so callers cannot self-assert
/// approval. The caller must separately persist/apply the approved binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ValidatedHumanApproval {
    approver: String,
    rationale: String,
    approved_project_id: ProjectId,
    approved_role: Role,
    approved_profile_id: ProfileId,
    approved_candidate_digest: Digest,
    approved_manifest_digest: Digest,
    approved_evidence_digest: Digest,
    approved_config_revision: Digest,
    human_request_id: HumanRequestId,
    approval_subject_digest: Digest,
    approval_configuration_digest: Digest,
    approval_policy_digest: Digest,
    response_receipt_digest: Digest,
    authorized_at: String,
}

impl ValidatedHumanApproval {
    // Wired by the controller when its durable human-response receipt is added.
    #[allow(dead_code)]
    #[allow(clippy::too_many_arguments)]
    fn from_validated_response(
        approver: String,
        rationale: String,
        project_id: ProjectId,
        role: Role,
        profile_id: ProfileId,
        candidate_digest: Digest,
        manifest_digest: Digest,
        evidence_digest: Digest,
        config_revision: Digest,
        human_request_id: HumanRequestId,
        approval_subject_digest: Digest,
        approval_configuration_digest: Digest,
        approval_policy_digest: Digest,
        response_receipt_digest: Digest,
        authorized_at: String,
    ) -> Self {
        Self {
            approver,
            rationale,
            approved_project_id: project_id,
            approved_role: role,
            approved_profile_id: profile_id,
            approved_candidate_digest: candidate_digest,
            approved_manifest_digest: manifest_digest,
            approved_evidence_digest: evidence_digest,
            approved_config_revision: config_revision,
            human_request_id,
            approval_subject_digest,
            approval_configuration_digest,
            approval_policy_digest,
            response_receipt_digest,
            authorized_at,
        }
    }
}

/// Crate-private claims extracted only after validating a ProfilePackage's
/// crate-private approval object and complete file/evidence digests.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)] // Consumed by ConfigStore promotion persistence.
pub(crate) struct ValidatedPromotionClaims {
    pub project_id: ProjectId,
    pub role: Role,
    pub profile_id: ProfileId,
    pub candidate_digest: Digest,
    pub manifest_digest: Digest,
    pub evidence_digest: Digest,
    pub config_revision: Digest,
    pub human_request_id: HumanRequestId,
    pub approval_subject_digest: Digest,
    pub approval_configuration_digest: Digest,
    pub approval_policy_digest: Digest,
    pub response_receipt_digest: Digest,
    pub rationale: String,
    pub authorized_at: String,
}

#[allow(dead_code)] // Consumed by ConfigStore promotion persistence.
pub(crate) fn validated_promotion_claims(
    package: &ProfilePackage,
) -> Result<ValidatedPromotionClaims, LearningError> {
    validate_package(package)?;
    Ok(ValidatedPromotionClaims {
        project_id: package.approval.approved_project_id.clone(),
        role: package.approval.approved_role,
        profile_id: package.approval.approved_profile_id.clone(),
        candidate_digest: package.approval.approved_candidate_digest.clone(),
        manifest_digest: package.approval.approved_manifest_digest.clone(),
        evidence_digest: package.approval.approved_evidence_digest.clone(),
        config_revision: package.approval.approved_config_revision.clone(),
        human_request_id: package.approval.human_request_id.clone(),
        approval_subject_digest: package.approval.approval_subject_digest.clone(),
        approval_configuration_digest: package.approval.approval_configuration_digest.clone(),
        approval_policy_digest: package.approval.approval_policy_digest.clone(),
        response_receipt_digest: package.approval.response_receipt_digest.clone(),
        rationale: package.approval.rationale.clone(),
        authorized_at: package.approval.authorized_at.clone(),
    })
}

/// Stable digest of the complete profile package and config revision a person approves.
/// Callers use this when creating the durable human request; approval conversion recomputes it.
#[derive(Serialize)]
struct ProfileApprovalSubject<'a> {
    project_id: &'a ProjectId,
    role: Role,
    profile_id: &'a ProfileId,
    candidate_digest: &'a Digest,
    manifest_digest: &'a Digest,
    evidence_digest: &'a Digest,
    config_revision: &'a Digest,
}

pub fn profile_approval_subject_digest(
    project_id: &ProjectId,
    role: Role,
    profile_id: &ProfileId,
    candidate_digest: &Digest,
    files: &BTreeMap<String, Vec<u8>>,
    evidence: &TrialEvidence,
    config_revision: &Digest,
) -> Result<Digest, LearningError> {
    let manifest_digest = manifest_digest(files)?;
    let evidence_digest = evidence_digest(evidence)?;
    let subject = ProfileApprovalSubject {
        project_id,
        role,
        profile_id,
        candidate_digest,
        manifest_digest: &manifest_digest,
        evidence_digest: &evidence_digest,
        config_revision,
    };
    let mut bytes = b"rex-projects-profile-approval-v1\0".to_vec();
    bytes.extend(serde_json::to_vec(&subject)?);
    Ok(as_digest(Sha256::digest(bytes).as_slice()))
}

/// Convert an opaque receipt minted by the durable human runtime into a promotion package.
/// Every approved field is recomputed from the complete package and compared with the receipt.
#[allow(clippy::too_many_arguments)]
pub(crate) fn profile_package_from_accepted_approval(
    receipt: &crate::store::human::HumanApprovalReceipt,
    project_id: ProjectId,
    role: Role,
    profile_id: ProfileId,
    candidate_digest: Digest,
    evidence: TrialEvidence,
    files: BTreeMap<String, Vec<u8>>,
    approval_subject_digest: Digest,
    expected_profile_material_digest: Digest,
    config_revision: Digest,
    configuration_digest: Digest,
    policy_digest: Digest,
    now_unix: u64,
) -> Result<ProfilePackage, LearningError> {
    if !receipt.approved()
        || receipt.choice() != crate::human_runtime::HumanDecisionChoice::Approve
        || now_unix >= receipt.request_expires_at_unix()
    {
        return Err(LearningError::Invalid(
            "profile promotion requires a current accepted human approval".into(),
        ));
    }
    let manifest = manifest_digest(&files)?;
    let evidence_hash = evidence_digest(&evidence)?;
    let profile_material_digest = profile_approval_subject_digest(
        &project_id,
        role,
        &profile_id,
        &candidate_digest,
        &files,
        &evidence,
        &config_revision,
    )?;
    if profile_material_digest != expected_profile_material_digest
        || receipt.subject_digest() != &approval_subject_digest
        || receipt.configuration_digest() != &configuration_digest
        || receipt.policy_digest() != &policy_digest
    {
        return Err(LearningError::Conflict(
            "human approval does not bind the complete profile and current config/policy".into(),
        ));
    }
    let rationale = receipt
        .explanation()
        .ok_or_else(|| LearningError::Invalid("human approval rationale is required".into()))?
        .to_owned();
    if rationale.trim().is_empty()
        || (evidence.outcome == TrialOutcome::Inconclusive && rationale.trim().len() < 20)
    {
        return Err(LearningError::Invalid(
            "human rationale must be present and scope inconclusive evidence".into(),
        ));
    }
    let authorized_at = unix_seconds_to_utc(receipt.decided_at_unix())?;
    let receipt_bytes = serde_json::to_vec(&(
        receipt.request_id(),
        receipt.response_id(),
        receipt.subject_digest(),
        receipt.configuration_digest(),
        receipt.policy_digest(),
        receipt.choice(),
        receipt.decided_at_unix(),
        receipt.request_expires_at_unix(),
        &rationale,
    ))?;
    let response_receipt_digest = as_digest(Sha256::digest(receipt_bytes).as_slice());
    Ok(ProfilePackage {
        project_id: project_id.clone(),
        role,
        profile_id: profile_id.clone(),
        candidate_digest: candidate_digest.clone(),
        evidence,
        files,
        approval: ValidatedHumanApproval {
            approver: format!("human request {}", receipt.request_id()),
            rationale,
            approved_project_id: project_id,
            approved_role: role,
            approved_profile_id: profile_id,
            approved_candidate_digest: candidate_digest,
            approved_manifest_digest: manifest,
            approved_evidence_digest: evidence_hash,
            approved_config_revision: config_revision,
            human_request_id: receipt.request_id().clone(),
            approval_subject_digest,
            approval_configuration_digest: configuration_digest,
            approval_policy_digest: policy_digest,
            response_receipt_digest,
            authorized_at,
        },
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfilePackage {
    pub project_id: ProjectId,
    pub role: Role,
    pub profile_id: ProfileId,
    pub candidate_digest: Digest,
    pub evidence: TrialEvidence,
    pub files: BTreeMap<String, Vec<u8>>,
    pub(crate) approval: ValidatedHumanApproval,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProfilePublicationStatus {
    Published,
    AlreadyPublished,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfilePublicationReceipt {
    pub profile_path: PathBuf,
    pub profile_manifest_digest: Digest,
    pub human_response_receipt_digest: Digest,
    pub status: ProfilePublicationStatus,
}

#[derive(Debug)]
pub enum LearningError {
    Invalid(String),
    Conflict(String),
    Io(io::Error),
    Serialization(serde_json::Error),
}
impl std::fmt::Display for LearningError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(s) | Self::Conflict(s) => f.write_str(s),
            Self::Io(e) => write!(f, "profile promotion I/O failed: {e}"),
            Self::Serialization(e) => write!(f, "promotion manifest serialization failed: {e}"),
        }
    }
}
impl std::error::Error for LearningError {}
impl From<io::Error> for LearningError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<serde_json::Error> for LearningError {
    fn from(e: serde_json::Error) -> Self {
        Self::Serialization(e)
    }
}

/// Hash a declaration source and its current profiles tree for compare-and-swap.
pub fn config_revision(config_file: &Path, profiles_root: &Path) -> Result<Digest, LearningError> {
    let source = fs::read(config_file)?;
    let source_path = fs::canonicalize(config_file)?;
    let mut hasher = Sha256::new();
    hasher.update(b"rex-projects-config-revision-v1\0");
    let source_path = source_path
        .to_str()
        .ok_or_else(|| LearningError::Invalid("configuration source path must be UTF-8".into()))?;
    hash_frame(&mut hasher, source_path.as_bytes());
    hash_frame(&mut hasher, &source);
    match fs::symlink_metadata(profiles_root) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(LearningError::Conflict(
                    "profiles root must be a real directory during revision calculation".into(),
                ));
            }
            hash_tree(profiles_root, &mut hasher)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(as_digest(hasher.finalize().as_slice()))
}

/// Publish a complete, approved profile package through a CAS gate. Targets are
/// immutable and must not exist; all files are validated before any target is
/// visible. `declarative_root` is the user's configured XDG configuration source.
pub fn publish_approved_profile_package(
    declarative_root: &Path,
    config_file: &Path,
    expected_revision: &Digest,
    package: &ProfilePackage,
) -> Result<ProfilePublicationReceipt, LearningError> {
    validate_package(package)?;
    if package.approval.approved_config_revision != *expected_revision {
        return Err(LearningError::Conflict(
            "approval is bound to a different declarative configuration revision".into(),
        ));
    }
    let root = fs::canonicalize(declarative_root)?;
    let source = fs::canonicalize(config_file)?;
    if !source.starts_with(&root) {
        return Err(LearningError::Invalid(
            "configuration source must be inside the declarative root".into(),
        ));
    }
    let profiles = root.join("profiles");
    if entry_exists(&profiles)? && !fs::symlink_metadata(&profiles)?.file_type().is_dir() {
        return Err(LearningError::Conflict(
            "profiles path must be a real directory".into(),
        ));
    }
    let lock_path = root.join(".rex-projects-promotion.lock");
    let mut lock_options = OpenOptions::new();
    lock_options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        lock_options.custom_flags(libc::O_NOFOLLOW);
    }
    let lock = lock_options.open(&lock_path)?;
    fs2::FileExt::lock_exclusive(&lock)?;
    let result = publish_locked(&root, &source, &profiles, expected_revision, package);
    fs2::FileExt::unlock(&lock)?;
    result
}

fn publish_locked(
    root: &Path,
    source: &Path,
    profiles: &Path,
    expected: &Digest,
    p: &ProfilePackage,
) -> Result<ProfilePublicationReceipt, LearningError> {
    let target = profiles.join(p.profile_id.as_str());
    if entry_exists(&target)? {
        if package_directory_matches(&target, &p.files)? {
            return Ok(ProfilePublicationReceipt {
                profile_path: target,
                profile_manifest_digest: manifest_digest(&p.files)?,
                human_response_receipt_digest: p.approval.response_receipt_digest.clone(),
                status: ProfilePublicationStatus::AlreadyPublished,
            });
        }
        return Err(LearningError::Conflict(
            "profile target already exists with different content; managed profiles are never overwritten".into(),
        ));
    }
    let actual = config_revision(source, profiles)?;
    if &actual != expected || &p.approval.approved_config_revision != expected {
        return Err(LearningError::Conflict(
            "declarative configuration changed since approval".into(),
        ));
    }
    if !entry_exists(profiles)? {
        fs::create_dir(profiles)?;
    }
    if fs::symlink_metadata(profiles)?.file_type().is_symlink()
        || !fs::symlink_metadata(profiles)?.is_dir()
    {
        return Err(LearningError::Conflict(
            "profiles directory cannot be a symlink".into(),
        ));
    }
    let stage_root = root.join(".rex-projects-staging");
    create_private_dir(&stage_root)?;
    // Persist any newly created publication parents before the atomic rename.
    File::open(root)?.sync_all()?;
    let stage = stage_root.join(format!(
        "{}-{}",
        p.project_id,
        short_hash(p.candidate_digest.as_str().as_bytes())
    ));
    match create_private_dir_new(&stage) {
        Ok(()) => {}
        Err(LearningError::Io(e)) if e.kind() == io::ErrorKind::AlreadyExists => {
            if !package_directory_is_recoverable(&stage, &p.files)? {
                return Err(LearningError::Conflict(
                    "stale promotion staging directory has unexpected content".into(),
                ));
            }
            fs::remove_dir_all(&stage)?;
            create_private_dir_new(&stage)?;
        }
        Err(e) => return Err(e),
    }
    let result = (|| {
        for (relative, bytes) in &p.files {
            let rel = validated_relative_path(relative)?;
            let dest = stage.join(rel);
            let parent = dest.parent().unwrap();
            create_private_dir_all(parent)?;
            if path_has_symlink(&stage, dest.parent().unwrap())? {
                return Err(LearningError::Conflict(
                    "staging tree contains a symlink".into(),
                ));
            }
            let mut file_options = OpenOptions::new();
            file_options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                file_options.mode(0o600);
            }
            let mut f = file_options.open(&dest)?;
            f.write_all(bytes)?;
            f.sync_all()?;
        }
        sync_tree_dirs(&stage)?;
        // Recheck immediately before publication while the exclusive lock is held.
        if config_revision(source, profiles)? != *expected {
            return Err(LearningError::Conflict(
                "declarative configuration changed during promotion".into(),
            ));
        }
        let stage_dir = open_directory_nofollow(&stage_root)?;
        let profiles_dir = open_directory_nofollow(profiles)?;
        rename_directory_noreplace(
            &stage_dir,
            stage_name(&stage),
            &profiles_dir,
            p.profile_id.as_str(),
        )?;
        // Persist both sides of the rename. The profile parent contains the
        // new name; the staging parent no longer contains its old name.
        profiles_dir.sync_all()?;
        stage_dir.sync_all()?;
        let profile_manifest_digest = manifest_digest(&p.files)?;
        Ok(ProfilePublicationReceipt {
            profile_path: target.clone(),
            profile_manifest_digest,
            human_response_receipt_digest: p.approval.response_receipt_digest.clone(),
            status: ProfilePublicationStatus::Published,
        })
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&stage);
    }
    result
}

fn package_directory_matches(
    root: &Path,
    expected: &BTreeMap<String, Vec<u8>>,
) -> Result<bool, LearningError> {
    if !entry_exists(root)?
        || fs::symlink_metadata(root)?.file_type().is_symlink()
        || !fs::symlink_metadata(root)?.is_dir()
    {
        return Ok(false);
    }
    Ok(read_package_directory(root)? == *expected)
}

fn package_directory_is_recoverable(
    root: &Path,
    expected: &BTreeMap<String, Vec<u8>>,
) -> Result<bool, LearningError> {
    if !entry_exists(root)?
        || fs::symlink_metadata(root)?.file_type().is_symlink()
        || !fs::symlink_metadata(root)?.is_dir()
    {
        return Ok(false);
    }
    let found = read_package_directory(root)?;
    Ok(found.iter().all(|(path, bytes)| {
        expected
            .get(path)
            .is_some_and(|expected_bytes| expected_bytes.starts_with(bytes))
    }))
}

fn entry_exists(path: &Path) -> Result<bool, LearningError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn stage_name(stage: &Path) -> &str {
    stage
        .file_name()
        .and_then(|name| name.to_str())
        .expect("stage name is generated from safe identifiers")
}

fn create_private_dir_new(path: &Path) -> Result<(), LearningError> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)?;
    restrict_private_dir(path)
}

fn create_private_dir(path: &Path) -> Result<(), LearningError> {
    match create_private_dir_new(path) {
        Ok(()) => Ok(()),
        Err(LearningError::Io(error)) if error.kind() == io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(path)?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(LearningError::Conflict(
                    "promotion staging path must be a real directory".into(),
                ));
            }
            restrict_private_dir(path)
        }
        Err(error) => Err(error),
    }
}

fn create_private_dir_all(path: &Path) -> Result<(), LearningError> {
    if entry_exists(path)? {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(LearningError::Conflict(
                "staging parent must be a real directory".into(),
            ));
        }
        return Ok(());
    }
    let parent = path
        .parent()
        .ok_or_else(|| LearningError::Invalid("staging path has no parent".into()))?;
    create_private_dir_all(parent)?;
    create_private_dir_new(path)
}

fn restrict_private_dir(path: &Path) -> Result<(), LearningError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        open_directory_nofollow(path)?.set_permissions(fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn open_directory_nofollow(path: &Path) -> Result<File, LearningError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW);
    }
    Ok(options.open(path)?)
}

#[cfg(target_os = "macos")]
fn rename_directory_noreplace(
    from_dir: &File,
    from_name: &str,
    to_dir: &File,
    to_name: &str,
) -> Result<(), LearningError> {
    use std::ffi::CString;
    use std::os::fd::AsRawFd;
    let from = CString::new(from_name)
        .map_err(|_| LearningError::Invalid("invalid staging entry name".into()))?;
    let to = CString::new(to_name)
        .map_err(|_| LearningError::Invalid("invalid profile entry name".into()))?;
    // SAFETY: both handles are open no-follow directories and names are single,
    // validated components. RENAME_EXCL atomically refuses any existing dentry.
    let result = unsafe {
        libc::renameatx_np(
            from_dir.as_raw_fd(),
            from.as_ptr(),
            to_dir.as_raw_fd(),
            to.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error().into())
    }
}

#[cfg(target_os = "linux")]
fn rename_directory_noreplace(
    from_dir: &File,
    from_name: &str,
    to_dir: &File,
    to_name: &str,
) -> Result<(), LearningError> {
    use std::ffi::CString;
    use std::os::fd::AsRawFd;
    let from = CString::new(from_name)
        .map_err(|_| LearningError::Invalid("invalid staging entry name".into()))?;
    let to = CString::new(to_name)
        .map_err(|_| LearningError::Invalid("invalid profile entry name".into()))?;
    // SAFETY: both handles are open no-follow directories and names are single,
    // validated components. RENAME_NOREPLACE atomically refuses any dentry.
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            from_dir.as_raw_fd(),
            from.as_ptr(),
            to_dir.as_raw_fd(),
            to.as_ptr(),
            1u32,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error().into())
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn rename_directory_noreplace(
    _from_dir: &File,
    _from_name: &str,
    _to_dir: &File,
    _to_name: &str,
) -> Result<(), LearningError> {
    Err(LearningError::Invalid(
        "atomic no-replace profile publication is unsupported on this platform".into(),
    ))
}

fn read_package_directory(root: &Path) -> Result<BTreeMap<String, Vec<u8>>, LearningError> {
    fn visit(
        root: &Path,
        dir: &Path,
        out: &mut BTreeMap<String, Vec<u8>>,
    ) -> Result<(), LearningError> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                return Err(LearningError::Conflict(
                    "profile tree contains a symlink".into(),
                ));
            }
            if metadata.is_dir() {
                visit(root, &path, out)?;
            } else if metadata.is_file() {
                let relative = path.strip_prefix(root).map_err(|_| {
                    LearningError::Invalid("profile path escaped package root".into())
                })?;
                let key = relative.to_string_lossy().replace('\\', "/");
                out.insert(key, fs::read(path)?);
            } else {
                return Err(LearningError::Conflict(
                    "profile tree contains an unsupported file type".into(),
                ));
            }
        }
        Ok(())
    }
    let mut files = BTreeMap::new();
    visit(root, root, &mut files)?;
    Ok(files)
}

fn validate_package(p: &ProfilePackage) -> Result<(), LearningError> {
    if p.evidence.outcome == TrialOutcome::Regressed {
        return Err(LearningError::Invalid(
            "regressed candidates cannot be promoted".into(),
        ));
    }
    if p.approval.approver.trim().is_empty()
        || p.approval.rationale.trim().is_empty()
        || !sortable_utc(&p.approval.authorized_at)
    {
        return Err(LearningError::Invalid(
            "human approval requires approver, rationale, and timestamp".into(),
        ));
    }
    if p.evidence.outcome == TrialOutcome::Inconclusive && p.approval.rationale.trim().len() < 20 {
        return Err(LearningError::Invalid(
            "inconclusive promotion requires a scoped human rationale of at least 20 characters"
                .into(),
        ));
    }
    if p.approval.approved_project_id != p.project_id
        || p.approval.approved_role != p.role
        || p.approval.approved_profile_id != p.profile_id
    {
        return Err(LearningError::Conflict(
            "approval scope does not match this project, role, and profile".into(),
        ));
    }
    if p.approval
        .response_receipt_digest
        .as_str()
        .bytes()
        .all(|byte| byte == b'0')
    {
        return Err(LearningError::Invalid(
            "promotion requires a host-validated human response receipt".into(),
        ));
    }
    if p.files.is_empty() {
        return Err(LearningError::Invalid(
            "profile package manifest cannot be empty".into(),
        ));
    }
    if p.files.len() > MAX_PROFILE_PACKAGE_FILES {
        return Err(LearningError::Invalid(
            "profile manifest exceeds the file count limit".into(),
        ));
    }
    let mut total_bytes = 0usize;
    for (path, data) in &p.files {
        validated_relative_path(path)?;
        if data.is_empty() {
            return Err(LearningError::Invalid(
                "profile package files cannot be empty".into(),
            ));
        }
        total_bytes = total_bytes
            .checked_add(data.len())
            .ok_or_else(|| LearningError::Invalid("profile package size overflow".into()))?;
        if total_bytes > MAX_PROFILE_PACKAGE_BYTES {
            return Err(LearningError::Invalid(
                "profile package exceeds the byte limit".into(),
            ));
        }
    }
    let manifest = manifest_digest(&p.files)?;
    if p.approval.approved_manifest_digest != manifest
        || p.approval.approved_candidate_digest != p.candidate_digest
    {
        return Err(LearningError::Conflict(
            "approval does not bind this exact candidate and complete file manifest".into(),
        ));
    }
    if p.approval.approved_evidence_digest != evidence_digest(&p.evidence)? {
        return Err(LearningError::Conflict(
            "approval does not bind this exact trial evidence".into(),
        ));
    }
    Ok(())
}
pub fn manifest_digest(files: &BTreeMap<String, Vec<u8>>) -> Result<Digest, LearningError> {
    let rows: Vec<_> = files
        .iter()
        .map(|(p, b)| (p, as_digest(Sha256::digest(b).as_slice())))
        .collect();
    Ok(as_digest(
        Sha256::digest(serde_json::to_vec(&rows)?).as_slice(),
    ))
}
pub fn evidence_digest(evidence: &TrialEvidence) -> Result<Digest, LearningError> {
    Ok(as_digest(
        Sha256::digest(serde_json::to_vec(evidence)?).as_slice(),
    ))
}
fn validated_relative_path(s: &str) -> Result<PathBuf, LearningError> {
    let p = Path::new(s);
    if p.as_os_str().is_empty()
        || s.contains('\\')
        || s.split('/').any(|part| {
            part.is_empty()
                || part == "."
                || part == ".."
                || !part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        })
        || p.components().any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(LearningError::Invalid(
            "profile manifest paths must be normalized relative paths".into(),
        ));
    }
    Ok(p.to_path_buf())
}
fn path_has_symlink(root: &Path, path: &Path) -> Result<bool, LearningError> {
    let rel = path
        .strip_prefix(root)
        .map_err(|_| LearningError::Invalid("staging path escaped root".into()))?;
    let mut cur = root.to_path_buf();
    for c in rel.components() {
        cur.push(c);
        if fs::symlink_metadata(&cur)?.file_type().is_symlink() {
            return Ok(true);
        }
    }
    Ok(false)
}
fn hash_tree(path: &Path, h: &mut Sha256) -> Result<(), LearningError> {
    hash_tree_from(path, Path::new(""), h)
}

fn hash_tree_from(directory: &Path, prefix: &Path, h: &mut Sha256) -> Result<(), LearningError> {
    let mut entries = fs::read_dir(directory)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for e in entries {
        let p = e.path();
        let m = fs::symlink_metadata(&p)?;
        if m.file_type().is_symlink() {
            return Err(LearningError::Conflict(
                "declarative profile trees cannot contain symlinks during CAS".into(),
            ));
        }
        let name = e
            .file_name()
            .into_string()
            .map_err(|_| LearningError::Invalid("profile tree paths must be UTF-8".into()))?;
        if name.contains('\\') {
            return Err(LearningError::Invalid(
                "profile tree paths cannot contain backslashes".into(),
            ));
        }
        let relative = prefix.join(name);
        let relative = relative
            .to_str()
            .ok_or_else(|| LearningError::Invalid("profile tree paths must be UTF-8".into()))?;
        let mode = file_mode(&m);
        if m.is_dir() {
            hash_tree_record(h, relative, b'D', mode, 0, &[0; 32]);
            hash_tree_from(&p, Path::new(&relative), h)?;
        } else if m.is_file() {
            let contents = fs::read(&p)?;
            let content_digest = Sha256::digest(&contents);
            hash_tree_record(
                h,
                relative,
                b'F',
                mode,
                contents.len() as u64,
                content_digest.as_slice(),
            );
        } else {
            return Err(LearningError::Conflict(
                "unsupported file in declarative profile tree".into(),
            ));
        }
    }
    Ok(())
}

fn hash_tree_record(h: &mut Sha256, path: &str, kind: u8, mode: u32, size: u64, digest: &[u8]) {
    hash_frame(h, path.as_bytes());
    h.update([kind]);
    h.update(mode.to_be_bytes());
    h.update(size.to_be_bytes());
    h.update(digest);
}

fn hash_frame(h: &mut Sha256, bytes: &[u8]) {
    h.update((bytes.len() as u64).to_be_bytes());
    h.update(bytes);
}

#[cfg(unix)]
fn file_mode(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o7777
}

#[cfg(not(unix))]
fn file_mode(_metadata: &fs::Metadata) -> u32 {
    0
}
fn sync_tree_dirs(path: &Path) -> Result<(), LearningError> {
    for e in fs::read_dir(path)? {
        let e = e?;
        if e.file_type()?.is_dir() {
            sync_tree_dirs(&e.path())?;
        }
    }
    File::open(path)?.sync_all()?;
    Ok(())
}
fn as_digest(bytes: &[u8]) -> Digest {
    Digest::parse(bytes.iter().map(|b| format!("{b:02x}")).collect::<String>())
        .expect("SHA-256 digest")
}
fn short_hash(bytes: &[u8]) -> String {
    as_digest(Sha256::digest(bytes).as_slice()).as_str()[..16].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    #[test]
    fn candidate_registry_enforces_capacity_and_expires_to_release_slots() {
        let project = ProjectId::parse("proj").unwrap();
        let mut ledger = CandidateLedger::default();
        for n in 0..MAX_CANDIDATES_PER_PROJECT {
            ledger
                .register(CandidateRevision {
                    candidate_id: format!("candidate-{n}"),
                    project_id: project.clone(),
                    role: Role::Worker,
                    digest: hash(format!("candidate-{n}").as_bytes()),
                    created_at: "2026-11-01T00:00:00Z".into(),
                    expires_at: "2026-11-02T00:00:00Z".into(),
                    status: CandidateStatus::Proposed,
                })
                .unwrap();
        }
        let extra = CandidateRevision {
            candidate_id: "extra".into(),
            project_id: project.clone(),
            role: Role::Worker,
            digest: hash(b"extra"),
            created_at: "2026-11-01T00:00:00Z".into(),
            expires_at: "2026-11-02T00:00:00Z".into(),
            status: CandidateStatus::Proposed,
        };
        assert!(ledger.register(extra.clone()).is_err());
        assert_eq!(
            ledger.expire_due("2026-11-02T00:00:00Z").unwrap(),
            MAX_CANDIDATES_PER_PROJECT
        );
        ledger.register(extra).unwrap();
    }

    #[test]
    fn candidate_duplicate_requests_are_idempotent_or_fail_without_mutation() {
        let project = ProjectId::parse("proj").unwrap();
        let mut ledger = CandidateLedger::default();
        for n in 0..20 {
            ledger.revisions.push(CandidateRevision {
                candidate_id: format!("candidate-{n}"),
                project_id: project.clone(),
                role: Role::Worker,
                digest: hash(format!("candidate-{n}").as_bytes()),
                created_at: format!("2026-11-{:02}T00:00:00Z", n + 1),
                expires_at: "2027-01-01T00:00:00Z".into(),
                status: if n == 19 {
                    CandidateStatus::Proposed
                } else {
                    CandidateStatus::Expired
                },
            });
        }
        let existing = ledger.revisions[0].clone();
        let before = ledger.clone();
        ledger.register(existing.clone()).unwrap();
        assert_eq!(ledger, before);

        let mut conflicting_duplicate = existing;
        conflicting_duplicate.expires_at = "2027-02-01T00:00:00Z".into();
        assert!(ledger.register(conflicting_duplicate).is_err());
        assert_eq!(ledger, before);

        let mut invalid = before.revisions[0].clone();
        invalid.candidate_id = "../escape".into();
        assert!(ledger.register(invalid).is_err());
        assert_eq!(ledger, before);
    }

    #[test]
    fn timeout_and_distinct_input_limits_stay_inconclusive() {
        let d = hash(b"input");
        let obs = (0..10)
            .map(|_| TrialObservation {
                input_digest: d.clone(),
                baseline: TrialRunStatus::Improved,
                candidate: TrialRunStatus::Improved,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            evaluate_trials(&obs, 10).unwrap().outcome,
            TrialOutcome::Inconclusive
        );
        let mut obs = obs;
        obs[0].candidate = TrialRunStatus::Timeout;
        let e = evaluate_trials(&obs, 10).unwrap();
        assert_eq!(e.outcome, TrialOutcome::Inconclusive);
        assert_eq!(e.timed_out_pairs, 1);
    }
    #[test]
    fn paired_evaluation_marks_regression_and_rejects_it_for_promotion() {
        let obs = (0..5)
            .map(|n| TrialObservation {
                input_digest: hash(&[n]),
                baseline: TrialRunStatus::Equivalent,
                candidate: if n == 0 {
                    TrialRunStatus::Regressed
                } else {
                    TrialRunStatus::Improved
                },
            })
            .collect::<Vec<_>>();
        assert_eq!(
            evaluate_trials(&obs, 5).unwrap().outcome,
            TrialOutcome::Regressed
        );
    }

    #[test]
    fn failed_and_timed_out_legs_count_as_one_incomplete_pair() {
        let observation = TrialObservation {
            input_digest: hash(b"input"),
            baseline: TrialRunStatus::Timeout,
            candidate: TrialRunStatus::Failed,
        };
        let evidence = evaluate_trials(&[observation], 1).unwrap();
        assert_eq!(evidence.outcome, TrialOutcome::Inconclusive);
        assert_eq!(evidence.completed_pairs, 0);
        assert_eq!(evidence.timed_out_pairs, 1);
    }

    #[test]
    fn timestamp_validation_checks_calendar_and_leap_years() {
        assert!(sortable_utc("2024-02-29T23:59:59Z"));
        assert!(!sortable_utc("2023-02-29T00:00:00Z"));
        assert!(!sortable_utc("2026-13-01T00:00:00Z"));
        assert!(!sortable_utc("2026-04-31T00:00:00Z"));
        assert!(!sortable_utc("2026-01-01T24:00:00Z"));
    }
    fn approved_package(revision: Digest) -> ProfilePackage {
        let mut files = BTreeMap::new();
        files.insert("config.toml".into(), b"name='candidate'\n".to_vec());
        files.insert("instructions.md".into(), b"Use bounded retries.\n".to_vec());
        let md = manifest_digest(&files).unwrap();
        let candidate = hash(b"candidate revision");
        let evidence = TrialEvidence {
            outcome: TrialOutcome::Inconclusive,
            distinct_inputs: 3,
            completed_pairs: 4,
            timed_out_pairs: 1,
            improved_pairs: 3,
            regressed_pairs: 0,
            rationale: "incomplete evidence".into(),
        };
        ProfilePackage {
            project_id: ProjectId::parse("proj").unwrap(),
            role: Role::Worker,
            profile_id: ProfileId::parse("proj-worker-learned").unwrap(),
            candidate_digest: candidate.clone(),
            evidence: evidence.clone(),
            files,
            approval: ValidatedHumanApproval::from_validated_response(
                "human".into(),
                "Limited to this project and worker role after reviewing evidence.".into(),
                ProjectId::parse("proj").unwrap(),
                Role::Worker,
                ProfileId::parse("proj-worker-learned").unwrap(),
                candidate,
                md,
                evidence_digest(&evidence).unwrap(),
                revision,
                HumanRequestId::parse("test-human-request").unwrap(),
                hash(b"approval subject"),
                hash(b"approval config"),
                hash(b"approval policy"),
                hash(b"validated human response receipt"),
                "2026-11-07T00:00:00Z".into(),
            ),
        }
    }
    fn hash(bytes: &[u8]) -> Digest {
        as_digest(&Sha256::digest(bytes))
    }

    #[test]
    fn profile_approval_subject_binds_role_manifest_evidence_and_config_revision() {
        let project = ProjectId::parse("proj").unwrap();
        let profile = ProfileId::parse("worker-profile").unwrap();
        let candidate = hash(b"candidate");
        let revision = hash(b"config revision");
        let evidence = TrialEvidence {
            outcome: TrialOutcome::Improved,
            distinct_inputs: 5,
            completed_pairs: 5,
            timed_out_pairs: 0,
            improved_pairs: 2,
            regressed_pairs: 0,
            rationale: "bounded qualitative comparison".into(),
        };
        let files = BTreeMap::from([("instructions.md".into(), b"bounded".to_vec())]);
        let digest = profile_approval_subject_digest(
            &project,
            Role::Worker,
            &profile,
            &candidate,
            &files,
            &evidence,
            &revision,
        )
        .unwrap();
        assert_ne!(
            digest,
            profile_approval_subject_digest(
                &project,
                Role::Reviewer,
                &profile,
                &candidate,
                &files,
                &evidence,
                &revision,
            )
            .unwrap()
        );
        assert_ne!(
            digest,
            profile_approval_subject_digest(
                &project,
                Role::Worker,
                &profile,
                &candidate,
                &files,
                &evidence,
                &hash(b"other config"),
            )
            .unwrap()
        );
    }

    #[test]
    fn human_receipt_unix_timestamp_formats_real_utc_calendar_dates() {
        assert_eq!(unix_seconds_to_utc(0).unwrap(), "1970-01-01T00:00:00Z");
        assert_eq!(
            unix_seconds_to_utc(951_782_400).unwrap(),
            "2000-02-29T00:00:00Z"
        );
    }
    #[test]
    fn profile_promotion_requires_cas_and_is_no_replace() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        let config = root.join("config.toml");
        fs::write(&config, "schema_version = 1\n").unwrap();
        let profiles = root.join("profiles");
        fs::create_dir(&profiles).unwrap();
        let rev = config_revision(&config, &profiles).unwrap();
        let pkg = approved_package(rev.clone());
        let result = publish_approved_profile_package(root, &config, &rev, &pkg).unwrap();
        assert_eq!(result.status, ProfilePublicationStatus::Published);
        assert!(result.profile_path.join("instructions.md").exists());
        fs::write(&config, "unrelated edit after publication").unwrap();
        let retry = publish_approved_profile_package(root, &config, &rev, &pkg).unwrap();
        assert_eq!(retry.status, ProfilePublicationStatus::AlreadyPublished);
        assert_eq!(
            result.profile_manifest_digest,
            retry.profile_manifest_digest
        );
    }
    #[test]
    fn stale_config_revision_does_not_publish_any_file() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        let config = root.join("config.toml");
        fs::write(&config, "one").unwrap();
        let profiles = root.join("profiles");
        fs::create_dir(&profiles).unwrap();
        let old = config_revision(&config, &profiles).unwrap();
        let pkg = approved_package(old.clone());
        fs::write(&config, "two").unwrap();
        let current = config_revision(&config, &profiles).unwrap();
        assert!(publish_approved_profile_package(root, &config, &current, &pkg).is_err());
        assert!(!profiles.join("proj-worker-learned").exists());
    }

    #[test]
    fn profile_tree_revision_uses_unambiguous_framed_records() {
        let dir = tempdir().unwrap();
        let config = dir.path().join("config.toml");
        let profiles = dir.path().join("profiles");
        fs::write(&config, "same config").unwrap();
        fs::create_dir(&profiles).unwrap();
        fs::write(profiles.join("a"), b"xb\0\x02z").unwrap();
        let digest_a = config_revision(&config, &profiles).unwrap();
        fs::remove_file(profiles.join("a")).unwrap();
        fs::write(profiles.join("a"), b"x").unwrap();
        fs::write(profiles.join("b"), b"z").unwrap();
        let digest_b = config_revision(&config, &profiles).unwrap();
        assert_ne!(digest_a, digest_b);
    }

    #[test]
    fn no_replace_rename_preserves_existing_empty_directories_and_symlinks() {
        let root = tempdir().unwrap();
        let source_root = root.path().join("stage-root");
        let target_root = root.path().join("profiles");
        fs::create_dir(&source_root).unwrap();
        fs::create_dir(&target_root).unwrap();
        let source = source_root.join("package");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("config.toml"), "payload").unwrap();
        let empty_target = target_root.join("empty");
        fs::create_dir(&empty_target).unwrap();
        let from = open_directory_nofollow(&source_root).unwrap();
        let to = open_directory_nofollow(&target_root).unwrap();
        assert!(rename_directory_noreplace(&from, "package", &to, "empty").is_err());
        assert!(source.join("config.toml").is_file());
        assert!(empty_target.is_dir());

        let dangling = target_root.join("dangling");
        std::os::unix::fs::symlink("missing-target", &dangling).unwrap();
        assert!(rename_directory_noreplace(&from, "package", &to, "dangling").is_err());
        assert_eq!(
            fs::read_link(&dangling).unwrap(),
            PathBuf::from("missing-target")
        );
    }

    #[test]
    fn publication_rejects_and_preserves_a_dangling_target_symlink() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        let config = root.join("config.toml");
        fs::write(&config, "schema_version = 1\n").unwrap();
        let profiles = root.join("profiles");
        fs::create_dir(&profiles).unwrap();
        let revision = config_revision(&config, &profiles).unwrap();
        let package = approved_package(revision.clone());
        let target = profiles.join(package.profile_id.as_str());
        std::os::unix::fs::symlink("missing-managed-profile", &target).unwrap();
        let before = fs::read_link(&target).unwrap();
        assert!(publish_approved_profile_package(root, &config, &revision, &package).is_err());
        assert_eq!(fs::read_link(target).unwrap(), before);
    }
}
