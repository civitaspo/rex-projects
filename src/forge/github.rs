//! GitHub REST adapter over the host's bounded `gh` process runner.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitStatus;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::{Map, Value};
use sha2::Digest as _;

use crate::domain::ids::Digest;
use crate::domain::types::MergeMethod;
use crate::forge::{
    BodyUpdateIntent, BranchProtection, CheckRun, CommentIntent, CommitComparison,
    CommitObservation, CommitStatus, DirectMergeIntent, EffectAcknowledgement, EffectCertainty,
    Forge, ForgeError, ForgeObservation, IssueComment, MergeEffectIntent, MergeEffectOperation,
    Observed, PullRequestFile, PullRequestObservation, PullRequestRef, PullRequestState,
    Reconciliation, RepositoryIdentity, RepositoryRef, Review, ReviewComment, ReviewThread,
    canonical_digest, merge_commit_message,
};
use crate::process::{ProcessError, ProcessOutput, ProcessRequest};

const ACCEPT_HEADER: &str = "Accept: application/vnd.github+json";
const API_VERSION_HEADER: &str = "X-GitHub-Api-Version: 2022-11-28";

pub trait GitHubCommandRunner: Send + Sync {
    fn run(&self, request: ProcessRequest) -> Result<ProcessOutput, ProcessError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemGitHubCommandRunner;

impl GitHubCommandRunner for SystemGitHubCommandRunner {
    fn run(&self, request: ProcessRequest) -> Result<ProcessOutput, ProcessError> {
        crate::process::run(request)
    }
}

pub struct GitHubCliForge<R> {
    runner: R,
    gh_path: PathBuf,
    host: String,
    environment: BTreeMap<OsString, OsString>,
    timeout: Duration,
    shutdown_grace: Duration,
    stdout_limit: usize,
    stderr_tail_limit: usize,
    page_limit: u16,
}

impl<R: GitHubCommandRunner> GitHubCliForge<R> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        runner: R,
        gh_path: PathBuf,
        host: impl Into<String>,
        environment: BTreeMap<OsString, OsString>,
        timeout: Duration,
        shutdown_grace: Duration,
        stdout_limit: usize,
        stderr_tail_limit: usize,
        page_limit: u16,
    ) -> Result<Self, ForgeError> {
        let host = host.into();
        if !valid_host(&host) || !gh_path.is_absolute() {
            return Err(ForgeError(
                "GitHub host must be a hostname and gh path must be absolute".into(),
            ));
        }
        if timeout.is_zero() || shutdown_grace.is_zero() || page_limit == 0 {
            return Err(ForgeError("GitHub runner bounds must be positive".into()));
        }
        Ok(Self {
            runner,
            gh_path,
            host,
            environment,
            timeout,
            shutdown_grace,
            stdout_limit,
            stderr_tail_limit,
            page_limit,
        })
    }

    fn validate_target(&self, target: &RepositoryRef) -> Result<(), ForgeError> {
        if target.host != self.host {
            return Err(ForgeError(
                "repository host differs from GitHub adapter host".into(),
            ));
        }
        let pull = PullRequestRef {
            repository: target.clone(),
            number: 1,
            expected_node_id: None,
        };
        pull.validate().map_err(ForgeError)
    }

    fn endpoint(&self, repository: &RepositoryRef, suffix: &str) -> Result<String, ForgeError> {
        self.validate_target(repository)?;
        let root = format!(
            "repos/{}/{}",
            path_component(&repository.owner)?,
            path_component(&repository.name)?
        );
        let suffix = suffix.trim_start_matches('/');
        Ok(if suffix.is_empty() {
            root
        } else {
            format!("{root}/{suffix}")
        })
    }

    fn run_api(
        &self,
        method: &str,
        endpoint: &str,
        body: Option<&[u8]>,
        paginate: bool,
    ) -> Result<ApiResponse, ForgeError> {
        let mut records = Vec::new();
        let mut page_documents = Vec::new();
        let max_pages = if paginate { self.page_limit } else { 1 };
        for page in 1..=max_pages {
            let mut args = vec![
                OsString::from("--hostname"),
                OsString::from(&self.host),
                OsString::from("api"),
                OsString::from(endpoint),
                OsString::from("--method"),
                OsString::from(method),
                OsString::from("--header"),
                OsString::from(ACCEPT_HEADER),
                OsString::from("--header"),
                OsString::from(API_VERSION_HEADER),
            ];
            if paginate {
                args.extend([
                    OsString::from("-F"),
                    OsString::from("per_page=100"),
                    OsString::from("-F"),
                    OsString::from(format!("page={page}")),
                ]);
            }
            let stdin = if let Some(body) = body {
                args.extend([OsString::from("--input"), OsString::from("-")]);
                body.to_vec()
            } else {
                Vec::new()
            };
            let mut environment = self.environment.clone();
            environment.insert("GH_PROMPT_DISABLED".into(), "1".into());
            environment.insert("GH_PAGER".into(), "cat".into());
            environment.insert("GH_NO_UPDATE_NOTIFIER".into(), "1".into());
            let request = ProcessRequest {
                executable: self.gh_path.clone(),
                args,
                stdin,
                cwd: None,
                clear_environment: true,
                environment,
                timeout: self.timeout,
                shutdown_grace: self.shutdown_grace,
                stdout_limit: self.stdout_limit,
                stderr_tail_limit: self.stderr_tail_limit,
            };
            let output = self
                .runner
                .run(request)
                .map_err(|error| ForgeError(format!("gh process could not complete: {error}")))?;
            if output.timed_out {
                return Err(ForgeError(
                    "gh request timed out; effect state is uncertain".into(),
                ));
            }
            if output.stdout_truncated || output.stderr_truncated {
                return Err(ForgeError(
                    "gh response exceeded the configured output limit".into(),
                ));
            }
            if !output.status.as_ref().is_some_and(ExitStatus::success) {
                return Err(ForgeError(
                    "gh API request failed; remote state is unknown".into(),
                ));
            }
            let value: Value = serde_json::from_slice(&output.stdout)
                .map_err(|_| ForgeError("gh returned malformed JSON".into()))?;
            let page_records = if paginate {
                if let Some(records) = value.as_array() {
                    records.clone()
                } else if let Some(object) = value.as_object() {
                    object
                        .values()
                        .filter_map(Value::as_array)
                        .max_by_key(|records| records.len())
                        .cloned()
                        .ok_or_else(|| {
                            ForgeError("paginated gh response had no collection".into())
                        })?
                } else {
                    return Err(ForgeError(
                        "paginated gh response was not a collection".into(),
                    ));
                }
            } else {
                vec![value.clone()]
            };
            records.extend(page_records.iter().cloned());
            page_documents.push(value);
            if !paginate || page_records.len() < 100 {
                break;
            }
            if page == max_pages {
                return Err(ForgeError(
                    "GitHub pagination reached the configured page limit with more results possible".into(),
                ));
            }
        }
        Ok(ApiResponse {
            records,
            pages: page_documents.len() as u16,
            page_documents,
        })
    }

    fn read_value(&self, repository: &RepositoryRef, suffix: &str) -> Result<Value, ForgeError> {
        let response = self.run_api("GET", &self.endpoint(repository, suffix)?, None, false)?;
        response
            .records
            .into_iter()
            .next()
            .ok_or_else(|| ForgeError("gh returned no response document".into()))
    }

    fn read_records(
        &self,
        repository: &RepositoryRef,
        suffix: &str,
        collection_field: Option<&str>,
    ) -> Result<(Vec<Value>, u16), ForgeError> {
        let response = self.run_api("GET", &self.endpoint(repository, suffix)?, None, true)?;
        let records = if let Some(field) = collection_field {
            let mut collected = Vec::new();
            for page in response.page_documents {
                let values = page
                    .get(field)
                    .and_then(Value::as_array)
                    .ok_or_else(|| ForgeError(format!("gh page did not contain `{field}`")))?;
                collected.extend(values.iter().cloned());
            }
            collected
        } else {
            response.records
        };
        Ok((records, response.pages))
    }

    fn observed<T: Serialize>(value: T, pages: u16) -> Result<Observed<T>, ForgeError> {
        let digest = canonical_digest(&value)?;
        Ok(Observed::Complete {
            value,
            pages,
            digest,
        })
    }

    fn unknown<T>(error: ForgeError) -> Observed<T> {
        Observed::Unknown { reason: error.0 }
    }

    fn observe_repository(&self, repository: &RepositoryRef) -> Observed<RepositoryIdentity> {
        let result = self.read_value(repository, "").and_then(parse_repository);
        match result {
            Ok(value) if repository.expected_id.is_some_and(|id| id != value.id) => {
                Self::unknown(ForgeError("repository numeric identity changed".into()))
            }
            Ok(value)
                if !value
                    .full_name
                    .eq_ignore_ascii_case(&format!("{}/{}", repository.owner, repository.name)) =>
            {
                Self::unknown(ForgeError(
                    "repository full name differs from configured identity".into(),
                ))
            }
            Ok(value) => {
                Self::observed(value, 1).expect("typed response serialization is infallible")
            }
            Err(error) => Self::unknown(error),
        }
    }

    fn observe_pull(&self, pull: &PullRequestRef) -> Observed<PullRequestObservation> {
        let suffix = format!("pulls/{}", pull.number);
        let result = self
            .read_value(&pull.repository, &suffix)
            .and_then(parse_pull_request);
        match result {
            Ok(value)
                if value.number != pull.number
                    || pull
                        .repository
                        .expected_id
                        .is_some_and(|id| id != value.repository_id)
                    || pull
                        .expected_node_id
                        .as_ref()
                        .is_some_and(|id| id != &value.node_id) =>
            {
                Self::unknown(ForgeError("pull request identity changed".into()))
            }
            Ok(value) => {
                Self::observed(value, 1).expect("typed response serialization is infallible")
            }
            Err(error) => Self::unknown(error),
        }
    }

    fn observe_list<T, F>(
        &self,
        repository: &RepositoryRef,
        suffix: &str,
        collection_field: Option<&str>,
        parse: F,
    ) -> Observed<Vec<T>>
    where
        T: Serialize,
        F: Fn(Value) -> Result<T, ForgeError>,
    {
        let result = self
            .read_records(repository, suffix, collection_field)
            .and_then(|(values, pages)| {
                let records = values
                    .into_iter()
                    .map(parse)
                    .collect::<Result<Vec<_>, _>>()?;
                Ok((records, pages))
            });
        match result {
            Ok((records, pages)) => {
                Self::observed(records, pages).expect("typed response serialization is infallible")
            }
            Err(error) => Self::unknown(error),
        }
    }

    fn observe_protection(
        &self,
        repository: &RepositoryRef,
        base_ref: &str,
    ) -> Observed<BranchProtection> {
        let result = path_component(base_ref)
            .and_then(|branch| {
                // An effective-rules response is required before using classic protection as
                // an execution-time base guard. Rulesets can add force-push/deletion or bypass
                // behavior that the classic endpoint does not report.
                let rules = self.read_value(repository, &format!("rules/branches/{branch}"))?;
                let rules = rules.as_array().ok_or_else(|| {
                    ForgeError("effective repository rules are not a complete array".into())
                })?;
                if !rules.is_empty() {
                    return Err(ForgeError(
                        "active repository rules need a registered executor or human handling"
                            .into(),
                    ));
                }
                self.read_value(repository, &format!("branches/{branch}/protection"))
            })
            .and_then(parse_branch_protection);
        match result {
            Ok(value) => Self::observed(value.clone(), 1)
                .expect("typed response serialization is infallible"),
            Err(error) => Self::unknown(error),
        }
    }

    fn observe_review_threads(&self, pull: &PullRequestRef) -> Observed<Vec<ReviewThread>> {
        let query = r#"query($owner:String!,$name:String!,$number:Int!){repository(owner:$owner,name:$name){pullRequest(number:$number){reviewThreads(first:100){nodes{id isResolved comments(first:100){nodes{id} pageInfo{hasNextPage}}} pageInfo{hasNextPage}}}}}"#;
        let body = serde_json::json!({
            "query": query,
            "variables": {
                "owner": pull.repository.owner,
                "name": pull.repository.name,
                "number": pull.number,
            }
        });
        let result = serde_json::to_vec(&body)
            .map_err(|error| ForgeError(error.to_string()))
            .and_then(|body| self.run_api("POST", "graphql", Some(&body), false))
            .and_then(|response| {
                let value =
                    response.records.into_iter().next().ok_or_else(|| {
                        ForgeError("GraphQL returned no response document".into())
                    })?;
                let connection = value
                    .pointer("/data/repository/pullRequest/reviewThreads")
                    .ok_or_else(|| ForgeError("review thread connection is unavailable".into()))?;
                if connection
                    .pointer("/pageInfo/hasNextPage")
                    .and_then(Value::as_bool)
                    != Some(false)
                {
                    return Err(ForgeError(
                        "review threads exceed the complete observation page".into(),
                    ));
                }
                let nodes = connection
                    .get("nodes")
                    .and_then(Value::as_array)
                    .ok_or_else(|| ForgeError("review thread nodes are malformed".into()))?;
                let mut threads = Vec::with_capacity(nodes.len());
                for node in nodes {
                    let comments = node.pointer("/comments").ok_or_else(|| {
                        ForgeError("review thread comments are unavailable".into())
                    })?;
                    if comments
                        .pointer("/pageInfo/hasNextPage")
                        .and_then(Value::as_bool)
                        != Some(false)
                    {
                        return Err(ForgeError(
                            "review thread comments exceed the complete observation page".into(),
                        ));
                    }
                    let comment_ids = comments
                        .get("nodes")
                        .and_then(Value::as_array)
                        .ok_or_else(|| {
                            ForgeError("review thread comment nodes are malformed".into())
                        })?
                        .iter()
                        .map(|comment| string(comment, "id"))
                        .collect::<Result<Vec<_>, _>>()?;
                    threads.push(ReviewThread {
                        id: string(node, "id")?,
                        is_resolved: boolean(node, "isResolved")?,
                        comment_ids,
                    });
                }
                Ok(threads)
            });
        match result {
            Ok(value) => {
                Self::observed(value, 1).expect("typed response serialization is infallible")
            }
            Err(error) => Self::unknown(error),
        }
    }

    fn observe_commit_inner(
        &self,
        repository: &RepositoryRef,
        sha: &str,
    ) -> Result<CommitObservation, ForgeError> {
        let sha = path_component(sha)?;
        parse_commit(self.read_value(repository, &format!("commits/{sha}"))?)
    }

    fn observe_comparison_inner(
        &self,
        repository: &RepositoryRef,
        base: &str,
        head: &str,
    ) -> Result<CommitComparison, ForgeError> {
        let base = path_component(base)?;
        let head = path_component(head)?;
        parse_comparison(
            self.read_value(repository, &format!("compare/{base}...{head}"))?,
            &base,
            &head,
        )
    }

    fn current_actor(&self, repository: &RepositoryRef) -> Result<String, ForgeError> {
        self.validate_target(repository)?;
        // `gh api user` is a global endpoint, so build it without repository path components.
        let response = self.run_api("GET", "user", None, false)?;
        let user = response
            .records
            .first()
            .ok_or_else(|| ForgeError("gh user response is empty".into()))?;
        string(user, "login")
    }

    fn observe_pull_for_effect(
        &self,
        pull: &PullRequestRef,
    ) -> Result<PullRequestObservation, ForgeError> {
        match self.observe_pull(pull) {
            Observed::Complete { value, .. } => Ok(value),
            Observed::Unknown { reason } => Err(ForgeError(reason)),
        }
    }

    fn mutate(
        &self,
        method: &str,
        endpoint: &str,
        body: Value,
        operation_key: &str,
        request_digest: &Digest,
    ) -> Result<EffectAcknowledgement, ForgeError> {
        if operation_key.is_empty() {
            return Err(ForgeError("effect operation key must be non-empty".into()));
        }
        let body_bytes =
            serde_json::to_vec(&body).map_err(|error| ForgeError(error.to_string()))?;
        let request_digest = request_digest.clone();
        let output = self.run_api(method, endpoint, Some(&body_bytes), false);
        match output {
            Ok(response) => Ok(EffectAcknowledgement {
                operation_key: operation_key.to_owned(),
                request_digest,
                certainty: EffectCertainty::Applied,
                external_id: response
                    .records
                    .first()
                    .and_then(|item| item.get("id"))
                    .map(value_to_string),
                external_url: response
                    .records
                    .first()
                    .and_then(|item| item.get("html_url"))
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                // The merge endpoint's `sha` is the resulting merge commit, not a new PR head.
                resulting_head_sha: None,
                resulting_merge_sha: response.records.first().and_then(|item| {
                    item.get("merge_commit_sha")
                        .and_then(Value::as_str)
                        .or_else(|| {
                            item.get("merged")
                                .and_then(Value::as_bool)
                                .filter(|merged| *merged)
                                .and_then(|_| item.get("sha"))
                                .and_then(Value::as_str)
                        })
                        .map(str::to_owned)
                }),
                reason: None,
            }),
            Err(error) => Ok(EffectAcknowledgement {
                operation_key: operation_key.to_owned(),
                request_digest,
                certainty: EffectCertainty::Unknown,
                external_id: None,
                external_url: None,
                resulting_head_sha: None,
                resulting_merge_sha: None,
                reason: Some(error.0),
            }),
        }
    }
}

impl<R: GitHubCommandRunner> Forge for GitHubCliForge<R> {
    fn observe(&self, pull: &PullRequestRef) -> Result<ForgeObservation, ForgeError> {
        pull.validate().map_err(ForgeError)?;
        self.validate_target(&pull.repository)?;
        let repository = self.observe_repository(&pull.repository);
        let pull_request = self.observe_pull(pull);
        let pr = match &pull_request {
            Observed::Complete { value, .. } => Some(value),
            Observed::Unknown { .. } => None,
        };
        let files = self.observe_list(
            &pull.repository,
            &format!("pulls/{}/files", pull.number),
            None,
            parse_file,
        );
        let files = match files {
            Observed::Complete { value, .. } if value.len() >= 3_000 => Self::unknown(ForgeError(
                "GitHub file listing reached its 3,000-file cap; complete diff is unknown".into(),
            )),
            other => other,
        };
        let check_runs = match pr {
            Some(pr) => self.observe_list(
                &pull.repository,
                &format!("commits/{}/check-runs", pr.head_sha),
                Some("check_runs"),
                parse_check_run,
            ),
            None => Self::unknown(ForgeError("pull request head is unknown".into())),
        };
        let statuses = match pr {
            Some(pr) => self.observe_list(
                &pull.repository,
                &format!("commits/{}/statuses", pr.head_sha),
                None,
                |value| parse_status(value, &pr.head_sha),
            ),
            None => Self::unknown(ForgeError("pull request head is unknown".into())),
        };
        let reviews = self.observe_list(
            &pull.repository,
            &format!("pulls/{}/reviews", pull.number),
            None,
            parse_review,
        );
        let review_comments = self.observe_list(
            &pull.repository,
            &format!("pulls/{}/comments", pull.number),
            None,
            parse_review_comment,
        );
        let review_threads = self.observe_review_threads(pull);
        let issue_comments = self.observe_list(
            &pull.repository,
            &format!("issues/{}/comments", pull.number),
            None,
            parse_issue_comment,
        );
        let branch_protection = match pr {
            Some(pr) => self.observe_protection(&pull.repository, &pr.base_ref),
            None => Self::unknown(ForgeError("pull request base branch is unknown".into())),
        };
        let (merge_commit, target_comparison) = match pr.filter(|pr| pr.merged) {
            Some(pr) => match pr.merge_commit_sha.as_deref() {
                Some(sha) => match self.observe_commit_inner(&pull.repository, sha) {
                    Ok(commit) => {
                        let comparison = commit.parents.first().map(|parent| {
                            self.observe_comparison_inner(&pull.repository, &pr.base_sha, parent)
                        });
                        (
                            Self::observed(Some(commit), 1)
                                .expect("typed response serialization is infallible"),
                            match comparison {
                                Some(Ok(item)) => Self::observed(Some(item), 1)
                                    .expect("typed response serialization is infallible"),
                                Some(Err(error)) => Self::unknown(error),
                                None => Self::unknown(ForgeError(
                                    "merge commit has no recorded parent".into(),
                                )),
                            },
                        )
                    }
                    Err(error) => (Self::unknown(error.clone()), Self::unknown(error)),
                },
                None => (
                    Self::unknown(ForgeError(
                        "merged pull request has no merge commit SHA".into(),
                    )),
                    Self::unknown(ForgeError("merge base is unavailable".into())),
                ),
            },
            None => (
                Self::observed(None, 1).expect("typed response serialization is infallible"),
                Self::observed(None, 1).expect("typed response serialization is infallible"),
            ),
        };
        Ok(ForgeObservation {
            repository,
            pull_request,
            files,
            check_runs,
            statuses,
            reviews,
            review_comments,
            review_threads,
            issue_comments,
            branch_protection,
            merge_commit,
            target_comparison,
        })
    }

    fn observe_commit(
        &self,
        repository: &RepositoryRef,
        sha: &str,
    ) -> Result<Observed<crate::forge::CommitObservation>, ForgeError> {
        self.validate_target(repository)?;
        match self.observe_commit_inner(repository, sha) {
            Ok(value) => Self::observed(value, 1),
            Err(error) => Ok(Self::unknown(error)),
        }
    }

    fn compare_commits(
        &self,
        repository: &RepositoryRef,
        base_sha: &str,
        head_sha: &str,
    ) -> Result<Observed<CommitComparison>, ForgeError> {
        self.validate_target(repository)?;
        match self.observe_comparison_inner(repository, base_sha, head_sha) {
            Ok(value) => Self::observed(value, 1),
            Err(error) => Ok(Self::unknown(error)),
        }
    }

    fn update_body(&self, _intent: &BodyUpdateIntent) -> Result<EffectAcknowledgement, ForgeError> {
        Err(ForgeError(
            "GitHub does not support atomic conditional PR-body updates; this effect requires human execution".into(),
        ))
    }

    fn post_comment(&self, intent: &CommentIntent) -> Result<EffectAcknowledgement, ForgeError> {
        intent.pull.validate().map_err(ForgeError)?;
        if intent.exact_body.is_empty() || intent.authenticated_actor.is_empty() {
            return Err(ForgeError(
                "merge request comment identity/body is empty".into(),
            ));
        }
        if self.current_actor(&intent.pull.repository)? != intent.authenticated_actor {
            return Err(ForgeError(
                "authenticated GitHub actor differs from effect intent".into(),
            ));
        }
        let before = self.observe_pull_for_effect(&intent.pull)?;
        if before.state != PullRequestState::Open
            || before.merged
            || before.head_sha != intent.expected_head_sha
            || before.base_sha != intent.expected_base_sha
        {
            return Ok(EffectAcknowledgement {
                operation_key: intent.operation_key.clone(),
                request_digest: canonical_digest(intent).map_err(|error| ForgeError(error.0))?,
                certainty: EffectCertainty::DefinitelyAbsent,
                external_id: None,
                external_url: None,
                resulting_head_sha: Some(before.head_sha),
                resulting_merge_sha: None,
                reason: Some(
                    "PR identity or revisions changed before merge request comment".into(),
                ),
            });
        }
        let endpoint = self.endpoint(
            &intent.pull.repository,
            &format!("issues/{}/comments", intent.pull.number),
        )?;
        self.mutate(
            "POST",
            &endpoint,
            serde_json::json!({"body": intent.exact_body}),
            &intent.operation_key,
            &canonical_digest(intent).map_err(|error| ForgeError(error.0))?,
        )
    }

    fn execute_merge(
        &self,
        intent: &DirectMergeIntent,
    ) -> Result<EffectAcknowledgement, ForgeError> {
        intent.pull.validate().map_err(ForgeError)?;
        if !valid_sha(&intent.expected_head_sha) || !valid_sha(&intent.expected_base_sha) {
            return Err(ForgeError(
                "merge expected revisions must be full SHA-1 or SHA-256 hex".into(),
            ));
        }
        let before = self.observe_pull_for_effect(&intent.pull)?;
        if before.state != PullRequestState::Open
            || before.merged
            || before.head_sha != intent.expected_head_sha
            || before.base_sha != intent.expected_base_sha
        {
            return Ok(EffectAcknowledgement {
                operation_key: intent.operation_key.clone(),
                request_digest: canonical_digest(intent).map_err(|error| ForgeError(error.0))?,
                certainty: EffectCertainty::DefinitelyAbsent,
                external_id: None,
                external_url: None,
                resulting_head_sha: Some(before.head_sha),
                resulting_merge_sha: None,
                reason: Some("PR identity or revisions changed before merge".into()),
            });
        }
        let live_body = before.body.as_deref().unwrap_or_default();
        if !direct_merge_body_matches(intent, live_body) {
            return Ok(EffectAcknowledgement {
                operation_key: intent.operation_key.clone(),
                request_digest: canonical_digest(intent).map_err(|error| ForgeError(error.0))?,
                certainty: EffectCertainty::DefinitelyAbsent,
                external_id: None,
                external_url: None,
                resulting_head_sha: Some(before.head_sha),
                resulting_merge_sha: None,
                reason: Some("PR body changed after merge assessment".into()),
            });
        }
        let endpoint = self.endpoint(
            &intent.pull.repository,
            &format!("pulls/{}/merge", intent.pull.number),
        )?;
        let mut body = Map::new();
        body.insert(
            "sha".into(),
            Value::String(intent.expected_head_sha.clone()),
        );
        body.insert(
            "merge_method".into(),
            Value::String(
                match intent.method {
                    MergeMethod::Merge => "merge",
                    MergeMethod::Squash => "squash",
                    MergeMethod::Rebase => "rebase",
                }
                .into(),
            ),
        );
        if !intent.expected_trailers.is_empty() {
            if intent.method != MergeMethod::Squash {
                return Err(ForgeError(
                    "GitHub only accepts a custom commit message for squash merges; required trailers cannot be guaranteed for this merge method".into(),
                ));
            }
            if intent
                .expected_trailers
                .iter()
                .any(|line| !line.starts_with("Co-authored-by: ") || line.contains(['\n', '\r']))
            {
                return Err(ForgeError("required merge trailer block is invalid".into()));
            }
            let derived = merge_commit_message(&intent.expected_body, &intent.expected_trailers)?;
            if derived != intent.expected_commit_message {
                return Err(ForgeError(
                    "exact squash commit message differs from the reviewed merge intent".into(),
                ));
            }
            body.insert(
                "commit_message".into(),
                Value::String(intent.expected_commit_message.clone()),
            );
        } else if !intent.expected_commit_message.is_empty() {
            return Err(ForgeError(
                "unreviewed squash commit message is not allowed".into(),
            ));
        }
        // GitHub accepts an expected head SHA but no expected base SHA. The separate base SHA is
        // retained in the durable request digest and must be re-observed by the executor.
        let mutation_digest = canonical_digest(intent).map_err(|error| ForgeError(error.0))?;
        if !human_approval_current(intent.approval_expires_at_unix, now_unix_seconds()) {
            return Ok(EffectAcknowledgement {
                operation_key: intent.operation_key.clone(),
                request_digest: mutation_digest,
                certainty: EffectCertainty::DefinitelyAbsent,
                external_id: None,
                external_url: None,
                resulting_head_sha: Some(before.head_sha),
                resulting_merge_sha: None,
                reason: Some(
                    "human approval expired after forge preflight; merge was not submitted".into(),
                ),
            });
        }
        self.mutate(
            "PUT",
            &endpoint,
            Value::Object(body),
            &intent.operation_key,
            &mutation_digest,
        )
    }

    fn reconcile(&self, intent: &MergeEffectIntent) -> Result<Reconciliation, ForgeError> {
        let observed = self.observe(&intent.pull)?;
        let pull = match observed.pull_request {
            Observed::Complete { value, .. } => value,
            Observed::Unknown { reason } => return Ok(Reconciliation::Unknown(reason)),
        };
        match &intent.operation {
            MergeEffectOperation::UpdateBody(body_intent) => {
                if pull.head_sha != body_intent.expected_head_sha {
                    return Ok(Reconciliation::Unknown(
                        "PR head changed while body update outcome is uncertain".into(),
                    ));
                }
                let actual_digest = hex_digest(pull.body.as_deref().unwrap_or_default().as_bytes());
                if actual_digest == body_intent.approved_body_digest.as_str() {
                    Ok(Reconciliation::Recovered(ack_for(
                        intent,
                        EffectCertainty::Recovered,
                        None,
                    )))
                } else if actual_digest == body_intent.expected_prior_body_digest.as_str() {
                    Ok(Reconciliation::DefinitelyAbsent)
                } else {
                    Ok(Reconciliation::Unknown(
                        "PR body changed concurrently; manual reconciliation required".into(),
                    ))
                }
            }
            MergeEffectOperation::RequestComment(comment) => {
                if self.current_actor(&intent.pull.repository)? != comment.authenticated_actor {
                    return Ok(Reconciliation::Unknown(
                        "authenticated GitHub actor changed".into(),
                    ));
                }
                let comments = match observed.issue_comments {
                    Observed::Complete { value, .. } => value,
                    Observed::Unknown { reason } => return Ok(Reconciliation::Unknown(reason)),
                };
                let matches = comments
                    .iter()
                    .filter(|candidate| {
                        candidate.body == comment.exact_body
                            && candidate.user.as_deref()
                                == Some(comment.authenticated_actor.as_str())
                            && timestamp_to_unix(&candidate.created_at)
                                .is_some_and(|created| created >= comment.attempt_started_unix)
                    })
                    .collect::<Vec<_>>();
                match matches.as_slice() {
                    [one] => Ok(Reconciliation::Recovered(ack_for(
                        intent,
                        EffectCertainty::Recovered,
                        Some(one.id.to_string()),
                    ))),
                    [] => Ok(Reconciliation::DefinitelyAbsent),
                    _ => Ok(Reconciliation::Unknown(
                        "multiple matching merge comments found".into(),
                    )),
                }
            }
            MergeEffectOperation::DirectMerge(merge_intent) => {
                if pull.merged {
                    let Some(merge_sha) = pull.merge_commit_sha.as_deref() else {
                        return Ok(Reconciliation::Unknown(
                            "merged PR has no merge commit identity".into(),
                        ));
                    };
                    let merge = match self.observe_commit_inner(&intent.pull.repository, merge_sha)
                    {
                        Ok(value) if value.sha == merge_sha => value,
                        Ok(_) => {
                            return Ok(Reconciliation::Unknown(
                                "merge commit identity differs".into(),
                            ));
                        }
                        Err(error) => return Ok(Reconciliation::Unknown(error.0)),
                    };
                    let includes_head = match merge_intent.method {
                        MergeMethod::Merge => {
                            merge.parents.contains(&merge_intent.expected_head_sha)
                        }
                        // A merged PR is associated with its exact reported head SHA. Equality
                        // with the PR head tree is too strict when the target has unrelated edits.
                        MergeMethod::Squash | MergeMethod::Rebase => true,
                    };
                    let Some(base_parent) = merge.parents.first() else {
                        return Ok(Reconciliation::Unknown(
                            "merge commit has no base parent".into(),
                        ));
                    };
                    let base_guard = match self.observe_comparison_inner(
                        &intent.pull.repository,
                        &merge_intent.expected_base_sha,
                        base_parent,
                    ) {
                        Ok(comparison) => comparison.behind_by == 0,
                        Err(error) => return Ok(Reconciliation::Unknown(error.0)),
                    };
                    if !includes_head
                        || !base_guard
                        || pull.head_sha != merge_intent.expected_head_sha
                    {
                        return Ok(Reconciliation::Unknown(
                            "merge does not prove the approved PR head and base".into(),
                        ));
                    }
                    Ok(Reconciliation::Recovered(ack_for(
                        intent,
                        EffectCertainty::Recovered,
                        Some(merge_sha.to_owned()),
                    )))
                } else if pull.state == PullRequestState::Open
                    && pull.head_sha == merge_intent.expected_head_sha
                    && pull.base_sha == merge_intent.expected_base_sha
                {
                    Ok(Reconciliation::DefinitelyAbsent)
                } else {
                    Ok(Reconciliation::Unknown(
                        "PR identity or revisions changed while merge outcome is uncertain".into(),
                    ))
                }
            }
        }
    }
}

#[derive(Clone, Debug)]
struct ApiResponse {
    records: Vec<Value>,
    pages: u16,
    page_documents: Vec<Value>,
}

fn parse_repository(value: Value) -> Result<RepositoryIdentity, ForgeError> {
    Ok(RepositoryIdentity {
        id: number(&value, "id")?,
        full_name: string(&value, "full_name")?,
        default_branch: string(&value, "default_branch")?,
        allow_merge_commit: boolean(&value, "allow_merge_commit")?,
        allow_squash_merge: boolean(&value, "allow_squash_merge")?,
        allow_rebase_merge: boolean(&value, "allow_rebase_merge")?,
    })
}

fn parse_pull_request(value: Value) -> Result<PullRequestObservation, ForgeError> {
    let state = match string(&value, "state")?.as_str() {
        "open" => PullRequestState::Open,
        "closed" => PullRequestState::Closed,
        _ => return Err(ForgeError("unknown GitHub pull request state".into())),
    };
    Ok(PullRequestObservation {
        repository_id: number_path(&value, &["base", "repo", "id"])
            .or_else(|_| number_path(&value, &["head", "repo", "id"]))?,
        node_id: string(&value, "node_id")?,
        number: number(&value, "number")?,
        state,
        draft: boolean(&value, "draft")?,
        merged: boolean(&value, "merged")?,
        head_sha: string_path(&value, &["head", "sha"])?,
        head_ref: string_path(&value, &["head", "ref"])?,
        base_sha: string_path(&value, &["base", "sha"])?,
        base_ref: string_path(&value, &["base", "ref"])?,
        body: optional_string(&value, "body"),
        merge_commit_sha: optional_string(&value, "merge_commit_sha"),
    })
}

fn parse_file(value: Value) -> Result<PullRequestFile, ForgeError> {
    Ok(PullRequestFile {
        filename: string(&value, "filename")?,
        status: string(&value, "status")?,
        additions: number(&value, "additions")?,
        deletions: number(&value, "deletions")?,
        changes: number(&value, "changes")?,
        patch: optional_string(&value, "patch"),
    })
}

fn parse_check_run(value: Value) -> Result<CheckRun, ForgeError> {
    Ok(CheckRun {
        id: number(&value, "id")?,
        name: string(&value, "name")?,
        head_sha: string(&value, "head_sha")?,
        status: string(&value, "status")?,
        conclusion: optional_string(&value, "conclusion"),
        app_id: value
            .get("app")
            .and_then(|v| v.get("id"))
            .and_then(Value::as_u64),
    })
}

fn parse_status(value: Value, requested_sha: &str) -> Result<CommitStatus, ForgeError> {
    let sha = value
        .get("sha")
        .and_then(Value::as_str)
        .unwrap_or(requested_sha)
        .to_owned();
    if sha != requested_sha {
        return Err(ForgeError(
            "commit status belongs to a different SHA".into(),
        ));
    }
    Ok(CommitStatus {
        context: string(&value, "context")?,
        state: string(&value, "state")?,
        sha,
        creator: value
            .get("creator")
            .and_then(|v| v.get("login"))
            .and_then(Value::as_str)
            .map(str::to_owned),
    })
}

fn parse_review(value: Value) -> Result<Review, ForgeError> {
    Ok(Review {
        id: number(&value, "id")?,
        user: login(&value),
        state: string(&value, "state")?,
        commit_id: optional_string(&value, "commit_id"),
        submitted_at: optional_string(&value, "submitted_at"),
    })
}

fn parse_review_comment(value: Value) -> Result<ReviewComment, ForgeError> {
    Ok(ReviewComment {
        id: number(&value, "id")?,
        user: login(&value),
        body: string(&value, "body")?,
        commit_id: optional_string(&value, "commit_id"),
        in_reply_to_id: value.get("in_reply_to_id").and_then(Value::as_u64),
        created_at: string(&value, "created_at")?,
    })
}

fn parse_issue_comment(value: Value) -> Result<IssueComment, ForgeError> {
    Ok(IssueComment {
        id: number(&value, "id")?,
        user: login(&value),
        body: string(&value, "body")?,
        created_at: string(&value, "created_at")?,
    })
}

fn parse_branch_protection(value: Value) -> Result<BranchProtection, ForgeError> {
    let strict = value
        .get("required_status_checks")
        .and_then(|v| v.get("strict"))
        .and_then(Value::as_bool)
        .ok_or_else(|| ForgeError("required status check strictness is unknown".into()))?;
    let contexts = value
        .get("required_status_checks")
        .and_then(|v| v.get("contexts"))
        .and_then(Value::as_array)
        .ok_or_else(|| ForgeError("required check contexts are unknown".into()))?
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    let review_policy = value
        .get("required_pull_request_reviews")
        .ok_or_else(|| ForgeError("required pull request review state is unknown".into()))?;
    let (required_approving_review_count, dismiss_stale_reviews) = if review_policy.is_null() {
        (None, None)
    } else {
        (
            Some(number(review_policy, "required_approving_review_count")?),
            Some(boolean(review_policy, "dismiss_stale_reviews")?),
        )
    };
    let enforce_admins = value
        .get("enforce_admins")
        .and_then(|v| v.get("enabled"))
        .and_then(Value::as_bool)
        .ok_or_else(|| ForgeError("admin enforcement state is unknown".into()))?;
    let allow_force_pushes = nested_enabled(&value, "allow_force_pushes")?;
    let allow_deletions = nested_enabled(&value, "allow_deletions")?;
    let mut normalized = BTreeMap::new();
    normalized.insert("strict".to_owned(), Value::Bool(strict));
    normalized.insert(
        "required_check_contexts".to_owned(),
        serde_json::to_value(&contexts).expect("strings serialize"),
    );
    normalized.insert(
        "required_approving_review_count".to_owned(),
        serde_json::to_value(required_approving_review_count).expect("option serializes"),
    );
    normalized.insert(
        "dismiss_stale_reviews".to_owned(),
        serde_json::to_value(dismiss_stale_reviews).expect("option serializes"),
    );
    normalized.insert("enforce_admins".to_owned(), Value::Bool(enforce_admins));
    normalized.insert(
        "allow_force_pushes".to_owned(),
        Value::Bool(allow_force_pushes),
    );
    normalized.insert("allow_deletions".to_owned(), Value::Bool(allow_deletions));
    let digest = canonical_digest(&normalized)?;
    Ok(BranchProtection {
        strict_required_status_checks: strict,
        required_check_contexts: contexts,
        required_approving_review_count,
        dismiss_stale_reviews,
        enforce_admins,
        allow_force_pushes,
        allow_deletions,
        digest,
    })
}

fn parse_commit(value: Value) -> Result<crate::forge::CommitObservation, ForgeError> {
    let parents = value
        .get("parents")
        .and_then(Value::as_array)
        .ok_or_else(|| ForgeError("commit parents are missing".into()))?
        .iter()
        .map(|v| string(v, "sha"))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(crate::forge::CommitObservation {
        sha: string(&value, "sha")?,
        tree_sha: string_path(&value, &["commit", "tree", "sha"])?,
        parents,
        message: string_path(&value, &["commit", "message"])?,
    })
}

fn parse_comparison(
    value: Value,
    requested_base: &str,
    requested_head: &str,
) -> Result<CommitComparison, ForgeError> {
    let base_sha = value
        .pointer("/base_commit/sha")
        .and_then(Value::as_str)
        .unwrap_or(requested_base);
    let head_sha = value
        .pointer("/head_commit/sha")
        .and_then(Value::as_str)
        .unwrap_or(requested_head);
    if base_sha != requested_base || head_sha != requested_head {
        return Err(ForgeError(
            "comparison response revisions differ from the requested pair".into(),
        ));
    }
    Ok(CommitComparison {
        base_sha: base_sha.to_owned(),
        head_sha: head_sha.to_owned(),
        status: string(&value, "status")?,
        ahead_by: number(&value, "ahead_by")?,
        behind_by: number(&value, "behind_by")?,
    })
}

#[cfg(test)]
fn flatten_pages(value: Value, limit: u16) -> Result<(Vec<Value>, u16), ForgeError> {
    let pages = value
        .as_array()
        .ok_or_else(|| ForgeError("paginated gh response was not an array".into()))?;
    if pages.len() > usize::from(limit) {
        return Err(ForgeError(
            "GitHub pagination exceeded the configured page limit".into(),
        ));
    }
    let count = pages.len().max(1) as u16;
    let mut records = Vec::new();
    for page in pages {
        if let Some(items) = page.as_array() {
            records.extend(items.iter().cloned());
        } else {
            records.push(page.clone());
        }
    }
    Ok((records, count))
}

fn number(value: &Value, key: &str) -> Result<u64, ForgeError> {
    value.get(key).and_then(Value::as_u64).ok_or_else(|| {
        ForgeError(format!(
            "GitHub response field `{key}` is missing or invalid"
        ))
    })
}

fn boolean(value: &Value, key: &str) -> Result<bool, ForgeError> {
    value.get(key).and_then(Value::as_bool).ok_or_else(|| {
        ForgeError(format!(
            "GitHub response field `{key}` is missing or invalid"
        ))
    })
}

fn string(value: &Value, key: &str) -> Result<String, ForgeError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| {
            ForgeError(format!(
                "GitHub response field `{key}` is missing or invalid"
            ))
        })
}

fn string_path(value: &Value, path: &[&str]) -> Result<String, ForgeError> {
    let node = path.iter().try_fold(value, |node, key| {
        if let Ok(index) = key.parse::<usize>() {
            node.as_array()?.get(index)
        } else {
            node.get(*key)
        }
    });
    node.and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| {
            ForgeError(format!(
                "GitHub response path `{}` is missing",
                path.join(".")
            ))
        })
}

fn number_path(value: &Value, path: &[&str]) -> Result<u64, ForgeError> {
    let node = path.iter().try_fold(value, |node, key| {
        if let Ok(index) = key.parse::<usize>() {
            node.as_array()?.get(index)
        } else {
            node.get(*key)
        }
    });
    node.and_then(Value::as_u64).ok_or_else(|| {
        ForgeError(format!(
            "GitHub response path `{}` is missing",
            path.join(".")
        ))
    })
}

fn optional_string(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn login(value: &Value) -> Option<String> {
    value
        .get("user")
        .and_then(|user| user.get("login"))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn nested_enabled(value: &Value, key: &str) -> Result<bool, ForgeError> {
    value
        .get(key)
        .and_then(|item| item.get("enabled"))
        .and_then(Value::as_bool)
        .ok_or_else(|| ForgeError(format!("branch protection `{key}` state is unknown")))
}

fn path_component(value: &str) -> Result<String, ForgeError> {
    if value.is_empty() || value == "." || value == ".." || value.chars().any(char::is_control) {
        return Err(ForgeError("invalid GitHub path component".into()));
    }
    let mut result = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            result.push(byte as char);
        } else {
            result.push('%');
            result.push_str(&format!("{byte:02X}"));
        }
    }
    Ok(result)
}

fn valid_host(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('.')
        && !value.ends_with('.')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
}

fn valid_sha(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn timestamp_to_unix(value: &str) -> Option<u64> {
    // GitHub's REST timestamps are RFC 3339 UTC. Reject offsets and malformed values rather
    // than doing a lexicographic comparison with a potentially different timezone.
    if value.len() < 20 || !value.ends_with('Z') || value.as_bytes().get(10) != Some(&b'T') {
        return None;
    }
    let year = value.get(0..4)?.parse::<i64>().ok()?;
    let month = value.get(5..7)?.parse::<i64>().ok()?;
    let day = value.get(8..10)?.parse::<i64>().ok()?;
    let hour = value.get(11..13)?.parse::<i64>().ok()?;
    let minute = value.get(14..16)?.parse::<i64>().ok()?;
    let second = value.get(17..19)?.parse::<i64>().ok()?;
    if value.as_bytes().get(4) != Some(&b'-')
        || value.as_bytes().get(7) != Some(&b'-')
        || value.as_bytes().get(13) != Some(&b':')
        || value.as_bytes().get(16) != Some(&b':')
        || !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    // Civil date to days since Unix epoch (Howard Hinnant's Gregorian conversion).
    let adjusted_year = year - i64::from(month <= 2);
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year - era * 400;
    let adjusted_month = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * adjusted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146097 + day_of_era - 719468;
    u64::try_from(days * 86400 + hour * 3600 + minute * 60 + second).ok()
}

fn hex_digest(bytes: &[u8]) -> String {
    let hash = sha2::Sha256::digest(bytes);
    hash.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn now_unix_seconds() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}

fn direct_merge_body_matches(intent: &DirectMergeIntent, live_body: &str) -> bool {
    live_body == intent.expected_body
        && hex_digest(live_body.as_bytes()) == intent.expected_body_digest.as_str()
}

fn human_approval_current(expires_at_unix: Option<u64>, now_unix: Option<u64>) -> bool {
    match expires_at_unix {
        None => true,
        Some(expires) => now_unix.is_some_and(|now| now < expires),
    }
}

fn value_to_string(value: &Value) -> String {
    value
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| value.to_string())
}

fn ack_for(
    intent: &MergeEffectIntent,
    certainty: EffectCertainty,
    external_id: Option<String>,
) -> EffectAcknowledgement {
    EffectAcknowledgement {
        operation_key: intent.operation_key.clone(),
        request_digest: intent.request_digest.clone(),
        certainty,
        external_id: external_id.clone(),
        external_url: None,
        resulting_head_sha: None,
        resulting_merge_sha: match &intent.operation {
            MergeEffectOperation::DirectMerge(_) => external_id.clone(),
            _ => None,
        },
        reason: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    struct FixtureRunner {
        replies: Mutex<VecDeque<Vec<u8>>>,
        requests: Mutex<Vec<ProcessRequest>>,
    }

    impl GitHubCommandRunner for FixtureRunner {
        fn run(&self, request: ProcessRequest) -> Result<ProcessOutput, ProcessError> {
            self.requests.lock().unwrap().push(request);
            let stdout = self
                .replies
                .lock()
                .unwrap()
                .pop_front()
                .expect("fixture reply");
            let status = std::process::Command::new("true")
                .status()
                .map_err(ProcessError::Start)?;
            Ok(ProcessOutput {
                status: Some(status),
                stdout,
                stderr_tail: Vec::new(),
                stdout_truncated: false,
                stderr_truncated: false,
                timed_out: false,
                cleanup_confirmed: true,
            })
        }
    }

    fn fixture_forge_responses(replies: Vec<Value>) -> GitHubCliForge<FixtureRunner> {
        GitHubCliForge::new(
            FixtureRunner {
                replies: Mutex::new(
                    replies
                        .into_iter()
                        .map(|reply| serde_json::to_vec(&reply).unwrap())
                        .collect(),
                ),
                requests: Mutex::new(Vec::new()),
            },
            PathBuf::from("/usr/bin/gh"),
            "github.com",
            BTreeMap::new(),
            Duration::from_secs(2),
            Duration::from_millis(100),
            10_000,
            1_000,
            5,
        )
        .unwrap()
    }

    fn fixture_forge(reply: Value) -> GitHubCliForge<FixtureRunner> {
        fixture_forge_responses(vec![reply])
    }

    fn test_pull() -> PullRequestRef {
        PullRequestRef {
            repository: RepositoryRef {
                host: "github.com".into(),
                owner: "octo".into(),
                name: "repo".into(),
                expected_id: Some(1),
            },
            number: 7,
            expected_node_id: None,
        }
    }

    #[test]
    fn paginated_response_flattens_pages_and_enforces_page_cap() {
        let (records, pages) =
            flatten_pages(serde_json::json!([[{"id":1}], [{"id":2}]]), 2).unwrap();
        assert_eq!(pages, 2);
        assert_eq!(records.len(), 2);
        assert!(flatten_pages(serde_json::json!([[{"id":1}], [{"id":2}]]), 1).is_err());
    }

    #[test]
    fn status_without_sha_is_bound_to_requested_head_and_mismatch_is_unknown() {
        let status = parse_status(
            serde_json::json!({"context":"ci","state":"success"}),
            "abc123",
        )
        .unwrap();
        assert_eq!(status.sha, "abc123");
        assert!(
            parse_status(
                serde_json::json!({"context":"ci","state":"success","sha":"other"}),
                "abc123",
            )
            .is_err()
        );
    }

    #[test]
    fn comparison_without_head_commit_still_binds_requested_pair() {
        let comparison = parse_comparison(
            serde_json::json!({"status":"ahead","ahead_by":1,"behind_by":0}),
            "base123",
            "head456",
        )
        .unwrap();
        assert_eq!(comparison.base_sha, "base123");
        assert_eq!(comparison.head_sha, "head456");
    }

    #[test]
    fn squash_message_preserves_one_exact_final_trailer_block() {
        let trailers = vec!["Co-authored-by: Agent <agent@example.com>".to_owned()];
        assert_eq!(
            merge_commit_message(
                "PR body\n\nCo-authored-by: Agent <agent@example.com>\n",
                &trailers
            )
            .unwrap(),
            "PR body\n\nCo-authored-by: Agent <agent@example.com>"
        );
        assert_eq!(
            merge_commit_message("PR body", &trailers).unwrap(),
            "PR body\n\nCo-authored-by: Agent <agent@example.com>"
        );
        assert!(
            merge_commit_message(
                "PR body\n\nCo-authored-by: Other <other@example.com>",
                &trailers,
            )
            .is_err()
        );
    }

    #[test]
    fn merge_preflight_binds_exact_body_and_rechecks_approval_expiry() {
        let expected_body = "PR body".to_owned();
        let intent = DirectMergeIntent {
            pull: test_pull(),
            operation_key: "merge-op".into(),
            method: MergeMethod::Squash,
            expected_head_sha: "a".repeat(40),
            expected_base_sha: "b".repeat(40),
            expected_body_digest: Digest::parse(hex_digest(expected_body.as_bytes())).unwrap(),
            expected_body: expected_body.clone(),
            expected_commit_message: "PR body\n\nCo-authored-by: Agent <agent@example.com>".into(),
            approval_expires_at_unix: Some(500),
            expected_trailers: vec!["Co-authored-by: Agent <agent@example.com>".into()],
        };
        assert!(direct_merge_body_matches(&intent, &expected_body));
        assert!(!direct_merge_body_matches(&intent, "changed body"));
        assert!(human_approval_current(Some(500), Some(499)));
        assert!(!human_approval_current(Some(500), Some(500)));
        assert!(!human_approval_current(Some(500), None));
        assert!(human_approval_current(None, None));
    }

    #[test]
    fn successful_merge_ack_does_not_mislabel_merge_sha_as_pr_head() {
        let head_sha = "a".repeat(40);
        let base_sha = "b".repeat(40);
        let merge_sha = "c".repeat(40);
        let body = "PR body";
        let forge = fixture_forge_responses(vec![
            serde_json::json!({
                "id": 1,
                "node_id": "PR_node",
                "number": 7,
                "state": "open",
                "draft": false,
                "merged": false,
                "head": {"sha": head_sha, "ref": "feature", "repo": {"id": 1}},
                "base": {"sha": base_sha, "ref": "main", "repo": {"id": 1}},
                "body": body
            }),
            serde_json::json!({"sha": merge_sha, "merged": true, "message": "Pull Request successfully merged"}),
        ]);
        let intent = DirectMergeIntent {
            pull: test_pull(),
            operation_key: "merge-op".into(),
            method: MergeMethod::Merge,
            expected_head_sha: head_sha,
            expected_base_sha: base_sha,
            expected_body: body.into(),
            expected_body_digest: Digest::parse(hex_digest(body.as_bytes())).unwrap(),
            expected_commit_message: String::new(),
            approval_expires_at_unix: None,
            expected_trailers: Vec::new(),
        };

        let acknowledgement = forge.execute_merge(&intent).unwrap();

        assert_eq!(acknowledgement.certainty, EffectCertainty::Applied);
        assert_eq!(acknowledgement.resulting_head_sha, None);
        assert_eq!(acknowledgement.resulting_merge_sha, Some(merge_sha));
    }

    #[test]
    fn missing_protection_fields_are_unknown_not_disabled() {
        let error = parse_branch_protection(serde_json::json!({"required_status_checks": null}));
        assert!(error.is_err());
    }

    #[test]
    fn configured_review_requirement_must_be_server_enforced_for_direct_merge() {
        let protection = parse_branch_protection(serde_json::json!({
            "required_status_checks": {"strict":true,"contexts":["ci"]},
            "required_pull_request_reviews": {"required_approving_review_count":1,"dismiss_stale_reviews":true},
            "enforce_admins": {"enabled":true},
            "allow_force_pushes": {"enabled":false},
            "allow_deletions": {"enabled":false}
        })).unwrap();
        assert!(protection.supports_execution_base_guard(&["ci".into()], None));
        assert!(protection.supports_execution_base_guard(&["ci".into()], Some(1)));
        assert!(!protection.supports_execution_base_guard(&["ci".into()], Some(2)));
        let without_review_guard = parse_branch_protection(serde_json::json!({
            "required_status_checks": {"strict":true,"contexts":["ci"]},
            "required_pull_request_reviews": {"required_approving_review_count":0,"dismiss_stale_reviews":false},
            "enforce_admins": {"enabled":true},
            "allow_force_pushes": {"enabled":false},
            "allow_deletions": {"enabled":false}
        })).unwrap();
        assert!(without_review_guard.supports_execution_base_guard(&["ci".into()], None));
        assert!(!without_review_guard.supports_execution_base_guard(&["ci".into()], Some(1)));
        let no_review_policy = parse_branch_protection(serde_json::json!({
            "required_status_checks": {"strict":true,"contexts":["ci"]},
            "required_pull_request_reviews": null,
            "enforce_admins": {"enabled":true},
            "allow_force_pushes": {"enabled":false},
            "allow_deletions": {"enabled":false}
        }))
        .unwrap();
        assert!(no_review_policy.supports_execution_base_guard(&["ci".into()], None));
        assert!(!no_review_policy.supports_execution_base_guard(&["ci".into()], Some(1)));
    }

    #[test]
    fn merge_method_is_closed_and_sha_is_sent_in_body() {
        for (method, expected) in [
            (MergeMethod::Merge, "merge"),
            (MergeMethod::Squash, "squash"),
            (MergeMethod::Rebase, "rebase"),
        ] {
            let value = serde_json::json!({"sha":"0123456789012345678901234567890123456789", "merge_method": expected});
            assert_eq!(value["merge_method"], expected);
            assert!(valid_sha(value["sha"].as_str().unwrap()));
            let _ = method;
        }
        assert!(!valid_sha("latest"));
    }

    #[test]
    fn host_and_path_parts_reject_injection() {
        assert!(!valid_host("https://github.com"));
        assert!(path_component("release/foo").is_ok());
        assert_eq!(path_component("../escape").unwrap(), "..%2Fescape");
    }

    #[test]
    fn github_rfc3339_timestamp_is_parsed_without_timezone_guessing() {
        assert_eq!(timestamp_to_unix("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(timestamp_to_unix("1970-01-01T00:00:01.100Z"), Some(1));
        assert_eq!(timestamp_to_unix("1970-01-01T01:00:00+01:00"), None);
    }

    #[test]
    fn graphql_review_threads_are_typed_and_query_uses_exact_pull_identity() {
        let fixture = serde_json::json!({
            "data": {"repository": {"pullRequest": {"reviewThreads": {
                "nodes": [{"id":"THREAD_1","isResolved":false,"comments": {
                    "nodes": [{"id":"COMMENT_1"}], "pageInfo": {"hasNextPage":false}
                }}], "pageInfo": {"hasNextPage":false}
            }}}}
        });
        assert!(
            fixture
                .pointer("/data/repository/pullRequest/reviewThreads")
                .is_some()
        );
        let forge = fixture_forge(fixture);
        let observed = forge.observe_review_threads(&test_pull());
        let Observed::Complete { value, .. } = observed else {
            panic!("review threads should be complete: {observed:?}")
        };
        assert_eq!(
            value,
            vec![ReviewThread {
                id: "THREAD_1".into(),
                is_resolved: false,
                comment_ids: vec!["COMMENT_1".into()],
            }]
        );
        let requests = forge.runner.requests.lock().unwrap();
        assert!(
            requests[0]
                .args
                .iter()
                .any(|argument| argument == "graphql")
        );
        let body: Value = serde_json::from_slice(&requests[0].stdin).unwrap();
        assert_eq!(body["variables"]["owner"], "octo");
        assert_eq!(body["variables"]["number"], 7);
    }

    #[test]
    fn incomplete_review_thread_pages_are_unknown_not_empty_or_resolved() {
        let forge = fixture_forge(
            serde_json::json!({"data":{"repository":{"pullRequest":{"reviewThreads":{
                "nodes":[], "pageInfo":{"hasNextPage":true}
            }}}}}),
        );
        assert!(matches!(
            forge.observe_review_threads(&test_pull()),
            Observed::Unknown { .. }
        ));
    }
}
