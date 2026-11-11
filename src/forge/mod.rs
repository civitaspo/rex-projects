//! Provider-neutral forge observations and typed effect boundary.

use serde::{Deserialize, Serialize};
use sha2::Digest as _;

use crate::domain::ids::Digest;
use crate::domain::types::MergeMethod;
use crate::merge_policy::MergeSubject;

pub mod github;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RepositoryRef {
    pub host: String,
    pub owner: String,
    pub name: String,
    pub expected_id: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PullRequestRef {
    pub repository: RepositoryRef,
    pub number: u64,
    pub expected_node_id: Option<String>,
}

impl PullRequestRef {
    pub fn validate(&self) -> Result<(), String> {
        if self.number == 0 {
            return Err("pull request number must be positive".into());
        }
        for (label, value) in [
            ("host", self.repository.host.as_str()),
            ("owner", self.repository.owner.as_str()),
            ("repository name", self.repository.name.as_str()),
        ] {
            if value.is_empty()
                || value
                    .chars()
                    .any(|c| c.is_control() || c == '/' || c == '\\')
            {
                return Err(format!("invalid {label}"));
            }
        }
        if self.repository.host.contains('@') || self.repository.host.contains(':') {
            return Err("host must be a hostname without credentials or port syntax".into());
        }
        Ok(())
    }

    pub fn full_name(&self) -> String {
        format!("{}/{}", self.repository.owner, self.repository.name)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", content = "value", rename_all = "snake_case")]
pub enum Observed<T> {
    Complete {
        value: T,
        pages: u16,
        digest: Digest,
    },
    Unknown {
        reason: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        failure: Option<ForgeTransientFailure>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RepositoryIdentity {
    pub id: u64,
    pub full_name: String,
    pub default_branch: String,
    pub allow_merge_commit: bool,
    pub allow_squash_merge: bool,
    pub allow_rebase_merge: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PullRequestState {
    Open,
    Closed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PullRequestObservation {
    pub repository_id: u64,
    pub node_id: String,
    pub number: u64,
    pub state: PullRequestState,
    pub draft: bool,
    pub merged: bool,
    pub head_sha: String,
    pub head_ref: String,
    pub base_sha: String,
    pub base_ref: String,
    pub body: Option<String>,
    pub merge_commit_sha: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PullRequestFile {
    pub filename: String,
    pub status: String,
    pub additions: u64,
    pub deletions: u64,
    pub changes: u64,
    pub patch: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CheckRun {
    pub id: u64,
    pub name: String,
    pub head_sha: String,
    pub status: String,
    pub conclusion: Option<String>,
    pub app_id: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_slug: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_suite_id: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_id: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CommitStatus {
    pub context: String,
    pub state: String,
    pub sha: String,
    pub creator: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observation: Option<CommitStatusObservation>,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct CommitStatusObservation {
    pub status_id: u64,
    pub created_at: String,
    pub observed_ordinal: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Review {
    pub id: u64,
    pub user: Option<String>,
    pub state: String,
    pub commit_id: Option<String>,
    pub submitted_at: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReviewComment {
    pub id: u64,
    pub user: Option<String>,
    pub body: String,
    pub commit_id: Option<String>,
    pub in_reply_to_id: Option<u64>,
    pub created_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReviewThread {
    pub id: String,
    pub is_resolved: bool,
    pub comment_ids: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IssueComment {
    pub id: u64,
    pub user: Option<String>,
    pub body: String,
    pub created_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BranchProtection {
    pub strict_required_status_checks: bool,
    pub required_check_contexts: Vec<String>,
    pub required_approving_review_count: Option<u64>,
    pub dismiss_stale_reviews: Option<bool>,
    pub enforce_admins: bool,
    pub allow_force_pushes: bool,
    pub allow_deletions: bool,
    pub digest: Digest,
}

impl BranchProtection {
    /// Proves the observed server-side protections needed for unattended direct merge.
    /// This is not an atomic comparison against an assessed base SHA: GitHub's merge API has no
    /// expected-base parameter. Callers must preflight the base and verify ancestry afterwards.
    pub fn supports_execution_base_guard(
        &self,
        required_checks: &[String],
        required_approving_reviews: Option<u64>,
    ) -> bool {
        self.strict_required_status_checks
            && self.enforce_admins
            && !self.allow_force_pushes
            && !self.allow_deletions
            && !required_checks.is_empty()
            && required_checks
                .iter()
                .all(|required| self.required_check_contexts.contains(required))
            && required_approving_reviews.is_none_or(|required| {
                required > 0
                    && self
                        .required_approving_review_count
                        .is_some_and(|configured| configured >= required)
                    && self.dismiss_stale_reviews == Some(true)
            })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CommitObservation {
    pub sha: String,
    pub tree_sha: String,
    pub parents: Vec<String>,
    pub message: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CommitComparison {
    pub base_sha: String,
    pub head_sha: String,
    pub status: String,
    pub ahead_by: u64,
    pub behind_by: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ForgeObservation {
    pub repository: Observed<RepositoryIdentity>,
    pub pull_request: Observed<PullRequestObservation>,
    pub files: Observed<Vec<PullRequestFile>>,
    pub check_runs: Observed<Vec<CheckRun>>,
    pub statuses: Observed<Vec<CommitStatus>>,
    pub reviews: Observed<Vec<Review>>,
    pub review_comments: Observed<Vec<ReviewComment>>,
    pub review_threads: Observed<Vec<ReviewThread>>,
    pub issue_comments: Observed<Vec<IssueComment>>,
    pub branch_protection: Observed<BranchProtection>,
    pub merge_commit: Observed<Option<CommitObservation>>,
    pub target_comparison: Observed<Option<CommitComparison>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForgeTransientFailure {
    ProcessUnavailable,
    TimedOut,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForgeFailureKind {
    Permanent,
    Retryable(ForgeTransientFailure),
}

impl ForgeObservation {
    pub fn retryable_failure(&self) -> Option<ForgeTransientFailure> {
        let mut retryable = None;
        macro_rules! inspect {
            ($observation:expr) => {
                match $observation {
                    Observed::Complete { .. } => {}
                    Observed::Unknown {
                        failure: Some(failure),
                        ..
                    } => {
                        retryable.get_or_insert(*failure);
                    }
                    Observed::Unknown { .. } => return None,
                }
            };
        }
        inspect!(&self.repository);
        inspect!(&self.pull_request);
        inspect!(&self.files);
        inspect!(&self.check_runs);
        inspect!(&self.statuses);
        inspect!(&self.reviews);
        inspect!(&self.review_comments);
        inspect!(&self.review_threads);
        inspect!(&self.issue_comments);
        inspect!(&self.branch_protection);
        inspect!(&self.merge_commit);
        inspect!(&self.target_comparison);
        retryable
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RemoteEvidenceDigests {
    pub diff: Digest,
    pub checks: Digest,
    pub reviews: Digest,
    pub merge_comments: Digest,
    pub base_guard: Digest,
}

impl ForgeObservation {
    /// Compute stable evidence hashes only when every evidence collection was completely read.
    /// `pages` are transport metadata and intentionally do not affect semantic hashes.
    pub fn semantic_digests(&self) -> Result<RemoteEvidenceDigests, ForgeError> {
        fn complete<T>(value: &Observed<T>) -> Result<&T, ForgeError> {
            match value {
                Observed::Complete { value, .. } => Ok(value),
                Observed::Unknown { reason, .. } => Err(ForgeError::permanent(reason.clone())),
            }
        }
        let mut files = complete(&self.files)?.clone();
        files.sort_by(|a, b| a.filename.cmp(&b.filename).then(a.status.cmp(&b.status)));
        let mut checks = complete(&self.check_runs)?.clone();
        checks.sort_by_key(|a| a.id);
        let mut statuses = complete(&self.statuses)?.clone();
        statuses.sort_by(|a, b| {
            (&a.context, &a.sha, &a.observation, &a.state, &a.creator).cmp(&(
                &b.context,
                &b.sha,
                &b.observation,
                &b.state,
                &b.creator,
            ))
        });
        let mut reviews = complete(&self.reviews)?.clone();
        reviews.sort_by_key(|a| a.id);
        let mut review_comments = complete(&self.review_comments)?.clone();
        review_comments.sort_by_key(|a| a.id);
        let mut review_threads = complete(&self.review_threads)?.clone();
        review_threads.sort_by(|a, b| a.id.cmp(&b.id));
        for thread in &mut review_threads {
            thread.comment_ids.sort();
        }
        let mut issue_comments = complete(&self.issue_comments)?.clone();
        issue_comments.sort_by_key(|a| a.id);
        let protection = complete(&self.branch_protection)?;
        Ok(RemoteEvidenceDigests {
            diff: canonical_digest(&files)?,
            checks: canonical_digest(&(&checks, &statuses))?,
            reviews: canonical_digest(&(&reviews, &review_comments, &review_threads))?,
            merge_comments: canonical_digest(&issue_comments)?,
            base_guard: protection.digest.clone(),
        })
    }

    pub fn verify_subject_identity(
        &self,
        pull: &PullRequestRef,
        subject: &MergeSubject,
    ) -> Result<(), ForgeError> {
        self.verify_subject_identity_core(pull, subject)?;
        let digests = self.semantic_digests()?;
        if digests.diff != subject.diff_digest
            || digests.checks != subject.remote_checks_digest
            || digests.reviews != subject.review_digest
            || digests.merge_comments != subject.merge_comments_digest
            || subject.base_guard_digest.as_ref() != Some(&digests.base_guard)
        {
            return Err(ForgeError::permanent(
                "live forge evidence differs from approved subject".into(),
            ));
        }
        Ok(())
    }

    pub fn verify_subject_identity_core(
        &self,
        pull: &PullRequestRef,
        subject: &MergeSubject,
    ) -> Result<(), ForgeError> {
        let repository = match &self.repository {
            Observed::Complete { value, .. } => value,
            Observed::Unknown { reason, .. } => return Err(ForgeError::permanent(reason.clone())),
        };
        let pr = match &self.pull_request {
            Observed::Complete { value, .. } => value,
            Observed::Unknown { reason, .. } => return Err(ForgeError::permanent(reason.clone())),
        };
        if subject.forge != "github"
            || subject.forge_host != pull.repository.host
            || subject.forge_repository_id != repository.id
            || !repository.full_name.eq_ignore_ascii_case(&format!(
                "{}/{}",
                pull.repository.owner, pull.repository.name
            ))
            || subject.pull_request_id != pull.number.to_string()
            || subject.pull_request_node_id != pr.node_id
            || pr.number != pull.number
            || pull
                .repository
                .expected_id
                .is_some_and(|id| id != repository.id)
            || pull
                .expected_node_id
                .as_ref()
                .is_some_and(|id| id != &pr.node_id)
            || pr.head_sha != subject.head_sha
            || pr.base_sha != subject.base_sha
            || pr.base_ref != subject.base_ref
        {
            return Err(ForgeError::permanent(
                "live forge identity or revision differs from approved subject".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectCertainty {
    Applied,
    Recovered,
    DefinitelyAbsent,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EffectAcknowledgement {
    pub operation_key: String,
    pub request_digest: Digest,
    pub certainty: EffectCertainty,
    pub external_id: Option<String>,
    pub external_url: Option<String>,
    pub resulting_head_sha: Option<String>,
    pub resulting_merge_sha: Option<String>,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BodyUpdateIntent {
    pub pull: PullRequestRef,
    pub operation_key: String,
    pub expected_head_sha: String,
    pub expected_prior_body_digest: Digest,
    pub exact_body: String,
    pub approved_body_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CommentIntent {
    pub pull: PullRequestRef,
    pub operation_key: String,
    pub expected_head_sha: String,
    pub expected_base_sha: String,
    pub exact_body: String,
    pub authenticated_actor: String,
    pub attempt_started_unix: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DirectMergeIntent {
    pub pull: PullRequestRef,
    pub operation_key: String,
    pub method: MergeMethod,
    pub expected_head_sha: String,
    /// Preflight staleness check only. GitHub cannot atomically condition the merge on this SHA.
    pub expected_base_sha: String,
    /// Exact PR body assessed for this merge. The forge adapter must re-read and match it.
    pub expected_body: String,
    pub expected_body_digest: Digest,
    /// Exact provider commit message derived from the assessed body and procedure trailers.
    pub expected_commit_message: String,
    /// Optional expiry of the human approval; checked again after forge preflight.
    pub approval_expires_at_unix: Option<u64>,
    /// Exact final trailer block required by the reviewed procedure. Empty means no trailer is required.
    pub expected_trailers: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MergeEffectIntent {
    pub pull: PullRequestRef,
    pub operation_key: String,
    pub request_digest: Digest,
    pub operation: MergeEffectOperation,
    pub attempt_started_unix: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MergeEffectOperation {
    UpdateBody(BodyUpdateIntent),
    RequestComment(CommentIntent),
    DirectMerge(DirectMergeIntent),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Reconciliation {
    Recovered(EffectAcknowledgement),
    DefinitelyAbsent,
    Unknown(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForgeError {
    pub message: String,
    pub kind: ForgeFailureKind,
}

impl ForgeError {
    pub fn permanent(message: String) -> Self {
        Self {
            message,
            kind: ForgeFailureKind::Permanent,
        }
    }

    pub fn retryable(failure: ForgeTransientFailure, message: String) -> Self {
        Self {
            message,
            kind: ForgeFailureKind::Retryable(failure),
        }
    }
}

impl std::fmt::Display for ForgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ForgeError {}

pub trait Forge {
    fn observe(&self, pull: &PullRequestRef) -> Result<ForgeObservation, ForgeError>;
    fn observe_commit(
        &self,
        repository: &RepositoryRef,
        sha: &str,
    ) -> Result<Observed<CommitObservation>, ForgeError>;
    fn compare_commits(
        &self,
        repository: &RepositoryRef,
        base_sha: &str,
        head_sha: &str,
    ) -> Result<Observed<CommitComparison>, ForgeError>;
    fn update_body(&self, intent: &BodyUpdateIntent) -> Result<EffectAcknowledgement, ForgeError>;
    fn post_comment(&self, intent: &CommentIntent) -> Result<EffectAcknowledgement, ForgeError>;
    fn execute_merge(
        &self,
        intent: &DirectMergeIntent,
    ) -> Result<EffectAcknowledgement, ForgeError>;
    fn reconcile(&self, intent: &MergeEffectIntent) -> Result<Reconciliation, ForgeError>;
}

pub(crate) fn canonical_digest<T: Serialize>(value: &T) -> Result<Digest, ForgeError> {
    let bytes =
        serde_json::to_vec(value).map_err(|error| ForgeError::permanent(error.to_string()))?;
    let hash = sha2::Sha256::digest(bytes);
    let hex = hash
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Digest::parse(hex).map_err(ForgeError::permanent)
}

pub(crate) fn merge_commit_message(
    body: &str,
    expected_trailers: &[String],
) -> Result<String, ForgeError> {
    if expected_trailers.is_empty()
        || expected_trailers
            .iter()
            .any(|line| !line.starts_with("Co-authored-by: ") || line.contains(['\n', '\r']))
    {
        return Err(ForgeError::permanent(
            "required merge trailer block is invalid".into(),
        ));
    }
    let body = body.trim_end();
    let trailer_lines = body
        .lines()
        .filter(|line| line.starts_with("Co-authored-by: "))
        .collect::<Vec<_>>();
    let expected = expected_trailers
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    if !trailer_lines.is_empty() {
        let body_lines = body.lines().collect::<Vec<_>>();
        if trailer_lines != expected || !body_lines.ends_with(&expected) {
            return Err(ForgeError::permanent(
                "PR body has a different or misplaced co-author trailer block".into(),
            ));
        }
        return Ok(body.to_owned());
    }
    let mut message = body.to_owned();
    if !message.is_empty() {
        message.push_str("\n\n");
    }
    message.push_str(&expected_trailers.join("\n"));
    Ok(message)
}
