//! Bounded profile-learning trials and human-gated declarative promotion.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::domain::ids::{Digest, ProfileId, ProjectId};
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
        if revision.candidate_id.is_empty()
            || !sortable_utc(&revision.created_at)
            || !sortable_utc(&revision.expires_at)
            || revision.expires_at <= revision.created_at
        {
            return Err(LearningError::Invalid(
                "candidate identity and increasing expiry are required".into(),
            ));
        }
        self.prune_terminal_to_limit(&revision.project_id);
        let retained = self
            .revisions
            .iter()
            .filter(|r| r.project_id == revision.project_id)
            .count();
        if retained >= 20 {
            return Err(LearningError::Conflict(
                "project has reached the retained candidate revision limit".into(),
            ));
        }
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
        if self.revisions.iter().any(|r| {
            r.project_id == revision.project_id
                && r.candidate_id == revision.candidate_id
                && r.digest == revision.digest
        }) {
            return Err(LearningError::Conflict(
                "candidate revision already exists".into(),
            ));
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

    fn prune_terminal_to_limit(&mut self, project: &ProjectId) {
        while self
            .revisions
            .iter()
            .filter(|r| r.project_id == *project)
            .count()
            >= 20
        {
            let oldest_terminal = self
                .revisions
                .iter()
                .enumerate()
                .filter(|(_, r)| r.project_id == *project && r.status.is_terminal())
                .min_by_key(|(_, r)| r.created_at.clone())
                .map(|(index, _)| index);
            match oldest_terminal {
                Some(index) => {
                    self.revisions.remove(index);
                }
                None => break,
            }
        }
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

fn sortable_utc(value: &str) -> bool {
    value.len() == 20
        && value.as_bytes()[4] == b'-'
        && value.as_bytes()[7] == b'-'
        && value.as_bytes()[10] == b'T'
        && value.as_bytes()[13] == b':'
        && value.as_bytes()[16] == b':'
        && value.as_bytes()[19] == b'Z'
        && value
            .bytes()
            .enumerate()
            .all(|(i, b)| matches!(i, 4 | 7 | 10 | 13 | 16 | 19) || b.is_ascii_digit())
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
    let failed_pairs = observations
        .iter()
        .filter(|o| o.baseline == TrialRunStatus::Failed || o.candidate == TrialRunStatus::Failed)
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
        && timed_out_pairs == 0
        && failed_pairs == 0;
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
        completed_pairs: observations.len() - timed_out_pairs - failed_pairs,
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HumanPromotionApproval {
    pub approver: String,
    pub rationale: String,
    pub approved_project_id: ProjectId,
    pub approved_role: Role,
    pub approved_profile_id: ProfileId,
    pub approved_candidate_digest: Digest,
    pub approved_manifest_digest: Digest,
    pub approved_evidence_digest: Digest,
    pub approved_config_revision: Digest,
    pub authorized_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfilePackage {
    pub project_id: ProjectId,
    pub role: Role,
    pub profile_id: ProfileId,
    pub candidate_digest: Digest,
    pub evidence: TrialEvidence,
    pub files: BTreeMap<String, Vec<u8>>,
    pub approval: HumanPromotionApproval,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PromotedProfile {
    pub profile_path: PathBuf,
    pub profile_digest: Digest,
    pub config_revision: Digest,
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
    hasher.update(source_path.to_string_lossy().as_bytes());
    hasher.update([0]);
    hasher.update(source);
    if profiles_root.exists() {
        hash_tree(profiles_root, &mut hasher)?;
    }
    Ok(as_digest(hasher.finalize().as_slice()))
}

/// Publish a complete, approved profile package through a CAS gate. Targets are
/// immutable and must not exist; all files are validated before any target is
/// visible. `declarative_root` is the user's configured XDG configuration source.
pub fn promote_profile(
    declarative_root: &Path,
    config_file: &Path,
    expected_revision: &Digest,
    package: &ProfilePackage,
) -> Result<PromotedProfile, LearningError> {
    validate_package(package)?;
    let root = fs::canonicalize(declarative_root)?;
    let source = fs::canonicalize(config_file)?;
    if !source.starts_with(&root) {
        return Err(LearningError::Invalid(
            "configuration source must be inside the declarative root".into(),
        ));
    }
    let profiles = root.join("profiles");
    if profiles.exists() && !fs::symlink_metadata(&profiles)?.file_type().is_dir() {
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
    let result = promote_locked(&root, &source, &profiles, expected_revision, package);
    fs2::FileExt::unlock(&lock)?;
    result
}

fn promote_locked(
    root: &Path,
    source: &Path,
    profiles: &Path,
    expected: &Digest,
    p: &ProfilePackage,
) -> Result<PromotedProfile, LearningError> {
    let target = profiles.join(p.profile_id.as_str());
    if target.exists() {
        if package_directory_matches(&target, &p.files)? {
            return Ok(PromotedProfile {
                profile_path: target,
                profile_digest: manifest_digest(&p.files)?,
                config_revision: config_revision(source, profiles)?,
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
    fs::create_dir_all(profiles)?;
    if fs::symlink_metadata(profiles)?.file_type().is_symlink() {
        return Err(LearningError::Conflict(
            "profiles directory cannot be a symlink".into(),
        ));
    }
    let stage_root = root.join(".rex-projects-staging");
    fs::create_dir_all(&stage_root)?;
    if !fs::symlink_metadata(&stage_root)?.file_type().is_dir() {
        return Err(LearningError::Conflict(
            "promotion staging path is not a directory".into(),
        ));
    }
    let stage = stage_root.join(format!(
        "{}-{}",
        p.project_id,
        short_hash(p.candidate_digest.as_str().as_bytes())
    ));
    match fs::create_dir(&stage) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            if !package_directory_is_recoverable(&stage, &p.files)? {
                return Err(LearningError::Conflict(
                    "stale promotion staging directory has unexpected content".into(),
                ));
            }
            fs::remove_dir_all(&stage)?;
            fs::create_dir(&stage)?;
        }
        Err(e) => return Err(e.into()),
    }
    let result = (|| {
        for (relative, bytes) in &p.files {
            let rel = validated_relative_path(relative)?;
            let dest = stage.join(rel);
            let parent = dest.parent().unwrap();
            fs::create_dir_all(parent)?;
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
        if target.exists() {
            return Err(LearningError::Conflict(
                "profile target appeared during promotion".into(),
            ));
        }
        fs::rename(&stage, &target)?;
        File::open(profiles)?.sync_all()?;
        let profile_digest = manifest_digest(&p.files)?;
        Ok(PromotedProfile {
            profile_path: target.clone(),
            profile_digest,
            config_revision: config_revision(source, profiles)?,
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
    if fs::symlink_metadata(root)?.file_type().is_symlink() || !fs::symlink_metadata(root)?.is_dir()
    {
        return Ok(false);
    }
    Ok(read_package_directory(root)? == *expected)
}

fn package_directory_is_recoverable(
    root: &Path,
    expected: &BTreeMap<String, Vec<u8>>,
) -> Result<bool, LearningError> {
    if fs::symlink_metadata(root)?.file_type().is_symlink() || !fs::symlink_metadata(root)?.is_dir()
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
        || p.approval.authorized_at.trim().is_empty()
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
    let mut entries = fs::read_dir(path)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let p = e.path();
        let m = fs::symlink_metadata(&p)?;
        h.update(e.file_name().to_string_lossy().as_bytes());
        h.update([0]);
        if m.file_type().is_symlink() {
            return Err(LearningError::Conflict(
                "declarative profile trees cannot contain symlinks during CAS".into(),
            ));
        }
        if m.is_dir() {
            h.update([1]);
            hash_tree(&p, h)?
        } else if m.is_file() {
            h.update([2]);
            h.update(fs::read(p)?)
        } else {
            return Err(LearningError::Conflict(
                "unsupported file in declarative profile tree".into(),
            ));
        }
    }
    Ok(())
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
            approval: HumanPromotionApproval {
                approver: "human".into(),
                rationale: "Limited to this project and worker role after reviewing evidence."
                    .into(),
                approved_project_id: ProjectId::parse("proj").unwrap(),
                approved_role: Role::Worker,
                approved_profile_id: ProfileId::parse("proj-worker-learned").unwrap(),
                approved_candidate_digest: candidate,
                approved_manifest_digest: md,
                approved_evidence_digest: evidence_digest(&evidence).unwrap(),
                approved_config_revision: revision,
                authorized_at: "2026-11-07T00:00:00Z".into(),
            },
        }
    }
    fn hash(bytes: &[u8]) -> Digest {
        as_digest(&Sha256::digest(bytes))
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
        let result = promote_profile(root, &config, &rev, &pkg).unwrap();
        assert!(result.profile_path.join("instructions.md").exists());
        let retry = promote_profile(root, &config, &rev, &pkg).unwrap();
        assert_eq!(result.profile_digest, retry.profile_digest);
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
        assert!(promote_profile(root, &config, &current, &pkg).is_err());
        assert!(!profiles.join("proj-worker-learned").exists());
    }
}
