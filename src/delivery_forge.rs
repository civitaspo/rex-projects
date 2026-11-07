//! Idempotent GitHub pull-request publication for controller-owned delivery effects.
//!
//! PR creation is keyed by a durable operation ID in the body. After an uncertain CLI result,
//! the adapter searches the exact source/base pair and reconciles that marker before retrying.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::domain::ids::{OperationId, RepositoryId};
use crate::process::{self, ProcessRequest};

const OUTPUT_LIMIT: usize = 4 * 1024 * 1024;
const STDERR_TAIL_LIMIT: usize = 32 * 1024;
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);
const MAX_PR_LIST: usize = 100;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PullRequestPublicationIntent {
    pub operation_id: OperationId,
    pub repository_id: RepositoryId,
    pub clone_url: String,
    pub source_branch: String,
    pub source_head: String,
    pub base_branch: String,
    pub title: String,
    pub body: String,
    /// On update, bind the mutation to the exact PR and head observed by the caller.
    pub update_target: Option<PullRequestTarget>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PullRequestTarget {
    pub number: u64,
    pub expected_head: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishedPullRequest {
    pub repository_id: RepositoryId,
    pub number: u64,
    pub node_id: String,
    pub url: String,
    pub state: String,
    pub source_branch: String,
    pub source_head: String,
    pub base_branch: String,
    pub title: String,
    pub body_digest: String,
    pub operation_id: OperationId,
}

#[derive(Debug)]
pub enum PublicationError {
    Invalid(String),
    Conflict(String),
    Unknown(String),
    Process(String),
}

impl std::fmt::Display for PublicationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(message)
            | Self::Conflict(message)
            | Self::Unknown(message)
            | Self::Process(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for PublicationError {}

pub trait PullRequestPublisher {
    /// Create or update exactly one PR and reconcile an ambiguous CLI result before returning.
    fn publish(
        &self,
        intent: &PullRequestPublicationIntent,
    ) -> Result<PublishedPullRequest, PublicationError>;

    /// Read-only reconciliation for an already-submitted publication effect.
    fn reconcile(
        &self,
        intent: &PullRequestPublicationIntent,
    ) -> Result<Option<PublishedPullRequest>, PublicationError>;
}

pub struct GitHubPullRequestPublisher {
    executable: PathBuf,
    environment: BTreeMap<OsString, OsString>,
    timeout: Duration,
}

impl GitHubPullRequestPublisher {
    pub fn new(
        executable: PathBuf,
        environment: BTreeMap<OsString, OsString>,
        timeout: Duration,
    ) -> Result<Self, PublicationError> {
        if !executable.is_absolute() || timeout.is_zero() {
            return Err(PublicationError::Invalid(
                "gh executable must be an absolute path and timeout must be positive".into(),
            ));
        }
        Ok(Self {
            executable,
            environment,
            timeout,
        })
    }

    fn api_json<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        endpoint: &str,
        body: Option<&[u8]>,
    ) -> Result<T, PublicationError> {
        let mut args = vec![
            OsString::from("api"),
            OsString::from(endpoint),
            OsString::from("-X"),
            OsString::from(method),
            OsString::from("-H"),
            OsString::from("Accept: application/vnd.github+json"),
        ];
        if body.is_some() {
            args.push(OsString::from("--input"));
            args.push(OsString::from("-"));
        }
        let mut environment = self.environment.clone();
        environment.insert("GH_PROMPT_DISABLED".into(), "1".into());
        let output = process::run(ProcessRequest {
            executable: self.executable.clone(),
            args,
            stdin: body.unwrap_or_default().to_vec(),
            cwd: None,
            clear_environment: true,
            environment,
            timeout: self.timeout,
            shutdown_grace: SHUTDOWN_GRACE,
            stdout_limit: OUTPUT_LIMIT,
            stderr_tail_limit: STDERR_TAIL_LIMIT,
        })
        .map_err(|error| PublicationError::Process(error.to_string()))?;
        if !output.status.is_some_and(|status| status.success())
            || output.timed_out
            || !output.cleanup_confirmed
            || output.stdout_truncated
        {
            return Err(PublicationError::Unknown(
                "GitHub API command failed or its outcome is uncertain".into(),
            ));
        }
        serde_json::from_slice(&output.stdout)
            .map_err(|_| PublicationError::Unknown("GitHub returned invalid JSON".into()))
    }

    fn list_candidates(
        &self,
        owner: &str,
        repo: &str,
        head: &str,
        base: &str,
    ) -> Result<Vec<ApiPullRequest>, PublicationError> {
        let endpoint = format!(
            "repos/{owner}/{repo}/pulls?state=all&head={owner}%3A{head}&base={base}&per_page={MAX_PR_LIST}"
        );
        let rows: Vec<ApiPullRequest> = self.api_json("GET", &endpoint, None)?;
        if rows.len() == MAX_PR_LIST {
            return Err(PublicationError::Conflict(
                "GitHub PR search reached its page limit; refusing ambiguous reconciliation".into(),
            ));
        }
        Ok(rows)
    }
}

impl PullRequestPublisher for GitHubPullRequestPublisher {
    fn publish(
        &self,
        intent: &PullRequestPublicationIntent,
    ) -> Result<PublishedPullRequest, PublicationError> {
        validate_intent(intent)?;
        let (owner, repo) = github_repository(&intent.clone_url)?;
        if let Some(existing) = self.reconcile(intent)? {
            return Ok(existing);
        }
        if intent.update_target.is_none()
            && !self
                .list_candidates(&owner, &repo, &intent.source_branch, &intent.base_branch)?
                .is_empty()
        {
            return Err(PublicationError::Conflict(
                "a PR already exists for this source/base pair without this operation marker"
                    .into(),
            ));
        }
        let endpoint = format!("repos/{owner}/{repo}/pulls");
        let body = marked_body(intent);
        let payload_value = match intent.update_target.is_some() {
            true => serde_json::json!({
                "title": intent.title,
                "body": body,
            }),
            false => serde_json::json!({
                "title": intent.title,
                "head": intent.source_branch,
                "base": intent.base_branch,
                "body": body,
            }),
        };
        let payload = serde_json::to_vec(&payload_value)
            .map_err(|_| PublicationError::Invalid("cannot encode PR request".into()))?;
        let (method, endpoint) = match &intent.update_target {
            Some(target) => {
                let existing = self.get_pull(&owner, &repo, target.number)?;
                validate_update_target(intent, target, &existing)?;
                (
                    "PATCH",
                    format!("repos/{owner}/{repo}/pulls/{}", target.number),
                )
            }
            None => ("POST", endpoint),
        };
        match self.api_json::<ApiPullRequest>(method, &endpoint, Some(&payload)) {
            Ok(_) => {}
            Err(_) => {
                if let Some(found) = self.reconcile(intent)? {
                    return Ok(found);
                }
                return Err(PublicationError::Unknown(
                    "PR publication outcome is uncertain; operation marker was not observed".into(),
                ));
            }
        }
        self.reconcile(intent)?.ok_or_else(|| {
            PublicationError::Unknown(
                "published PR did not match its exact operation intent".into(),
            )
        })
    }

    fn reconcile(
        &self,
        intent: &PullRequestPublicationIntent,
    ) -> Result<Option<PublishedPullRequest>, PublicationError> {
        validate_intent(intent)?;
        let (owner, repo) = github_repository(&intent.clone_url)?;
        let rows =
            self.list_candidates(&owner, &repo, &intent.source_branch, &intent.base_branch)?;
        let marker = operation_marker(&intent.operation_id);
        let marked = rows
            .iter()
            .filter(|row| {
                row.body
                    .as_deref()
                    .is_some_and(|body| body.contains(&marker))
            })
            .collect::<Vec<_>>();
        if marked.len() > 1 {
            return Err(PublicationError::Conflict(
                "multiple PRs carry the same publication operation marker".into(),
            ));
        }
        let Some(row) = marked.into_iter().next() else {
            if let Some(target) = &intent.update_target
                && rows.len() == 1
                && rows[0].number == target.number
                && rows[0].head.sha == target.expected_head
            {
                return Ok(None);
            }
            if !rows.is_empty() {
                return Err(PublicationError::Conflict(
                    "a PR already exists for this source/base pair without this operation marker"
                        .into(),
                ));
            }
            return Ok(None);
        };
        validate_api_pr(intent, row)?;
        Ok(Some(PublishedPullRequest {
            repository_id: intent.repository_id.clone(),
            number: row.number,
            node_id: row.node_id.clone(),
            url: row.html_url.clone(),
            state: row.state.clone(),
            source_branch: row.head.ref_name.clone(),
            source_head: row.head.sha.clone(),
            base_branch: row.base.ref_name.clone(),
            title: row.title.clone(),
            body_digest: sha256(marked_body(intent).as_bytes()),
            operation_id: intent.operation_id.clone(),
        }))
    }
}

#[derive(Deserialize, Serialize)]
struct ApiPullRequest {
    number: u64,
    node_id: String,
    html_url: String,
    state: String,
    title: String,
    body: Option<String>,
    head: ApiBranch,
    base: ApiBranch,
}

#[derive(Deserialize, Serialize)]
struct ApiBranch {
    #[serde(rename = "ref")]
    ref_name: String,
    sha: String,
}

fn validate_intent(intent: &PullRequestPublicationIntent) -> Result<(), PublicationError> {
    validate_branch(&intent.source_branch)?;
    validate_branch(&intent.base_branch)?;
    validate_sha(&intent.source_head)?;
    if intent.title.trim().is_empty() || intent.title.contains(['\n', '\r']) {
        return Err(PublicationError::Invalid(
            "PR title must be one nonempty line".into(),
        ));
    }
    Ok(())
}

/// Validate that the configured repository URL can be safely addressed by the GitHub API adapter.
pub fn validate_github_clone_url(clone_url: &str) -> Result<(), PublicationError> {
    github_repository(clone_url).map(|_| ())
}

fn validate_update_target(
    intent: &PullRequestPublicationIntent,
    target: &PullRequestTarget,
    current: &ApiPullRequest,
) -> Result<(), PublicationError> {
    if target.number != current.number
        || current.head.sha != target.expected_head
        || current.head.sha != intent.source_head
        || current.head.ref_name != intent.source_branch
        || current.base.ref_name != intent.base_branch
    {
        return Err(PublicationError::Conflict(
            "PR changed since the update target was observed".into(),
        ));
    }
    Ok(())
}

fn validate_api_pr(
    intent: &PullRequestPublicationIntent,
    row: &ApiPullRequest,
) -> Result<(), PublicationError> {
    if row.head.ref_name != intent.source_branch
        || row.head.sha != intent.source_head
        || row.base.ref_name != intent.base_branch
        || row.title != intent.title
        || row.body.as_deref() != Some(marked_body(intent).as_str())
    {
        return Err(PublicationError::Conflict(
            "PR matching the operation marker has drifted from its immutable intent".into(),
        ));
    }
    Ok(())
}

impl GitHubPullRequestPublisher {
    fn get_pull(
        &self,
        owner: &str,
        repo: &str,
        number: u64,
    ) -> Result<ApiPullRequest, PublicationError> {
        self.api_json("GET", &format!("repos/{owner}/{repo}/pulls/{number}"), None)
    }
}

fn marked_body(intent: &PullRequestPublicationIntent) -> String {
    format!(
        "{}\n\n{}",
        intent.body.trim_end(),
        operation_marker(&intent.operation_id)
    )
}

fn operation_marker(operation_id: &OperationId) -> String {
    format!("<!-- rex-projects-operation:{} -->", operation_id.as_str())
}

fn github_repository(clone_url: &str) -> Result<(String, String), PublicationError> {
    let path = if let Some(rest) = clone_url.strip_prefix("git@github.com:") {
        rest
    } else if let Some(rest) = clone_url.strip_prefix("ssh://git@github.com/") {
        rest
    } else if let Some(rest) = clone_url.strip_prefix("https://github.com/") {
        rest
    } else {
        return Err(PublicationError::Invalid(
            "GitHub PR publication requires a github.com clone URL".into(),
        ));
    };
    let path = path.strip_suffix(".git").unwrap_or(path);
    let mut parts = path.split('/');
    let owner = parts.next().unwrap_or_default();
    let repo = parts.next().unwrap_or_default();
    if parts.next().is_some() || !valid_component(owner) || !valid_component(repo) {
        return Err(PublicationError::Invalid(
            "clone URL is not a GitHub repository URL".into(),
        ));
    }
    Ok((owner.to_owned(), repo.to_owned()))
}

fn valid_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn validate_branch(value: &str) -> Result<(), PublicationError> {
    if value.is_empty()
        || value.len() > 240
        || value.starts_with('-')
        || value.contains("..")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.'))
    {
        return Err(PublicationError::Invalid("invalid Git branch name".into()));
    }
    Ok(())
}

fn validate_sha(value: &str) -> Result<(), PublicationError> {
    if !matches!(value.len(), 40 | 64) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(PublicationError::Invalid("invalid Git object ID".into()));
    }
    Ok(())
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn fixture_publisher() -> (
        tempfile::TempDir,
        GitHubPullRequestPublisher,
        PullRequestPublicationIntent,
    ) {
        let temp = tempfile::tempdir().unwrap();
        let executable = temp.path().join("gh-fixture");
        let state = temp.path().join("created");
        let script = format!(
            "#!/bin/sh\nmethod=GET\nendpoint=\nprevious=\nfor arg in \"$@\"; do if [ \"$previous\" = -X ]; then method=$arg; fi; if [ \"$arg\" = -X ]; then previous=-X; else previous=; fi; case $arg in repos/*) endpoint=$arg;; esac; done\ncase \"$method:$endpoint\" in\nGET:repos/acme/demo/pulls?*) if [ -f \"$FIXTURE_STATE\" ]; then cat \"$FIXTURE_STATE\"; else printf '[]'; fi ;;\nGET:repos/acme/demo/pulls/7) cat \"$FIXTURE_STATE\" | sed 's/^\\[//;s/\\]$//' ;;\nPOST:repos/acme/demo/pulls) cat >/dev/null; printf '%s' '{row}' > \"$FIXTURE_STATE\"; exit 1 ;;\n*) exit 90 ;;\nesac\n",
            row = r#"[{"number":7,"node_id":"PR_fixture","html_url":"https://github.com/acme/demo/pull/7","state":"open","title":"Ship feature","body":"Details\n\n<!-- rex-projects-operation:publish-1 -->","head":{"ref":"rex-projects/work","sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"base":{"ref":"main","sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}]"#
        );
        std::fs::write(&executable, script).unwrap();
        let mut permissions = std::fs::metadata(&executable).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&executable, permissions).unwrap();
        let publisher = GitHubPullRequestPublisher::new(
            executable,
            BTreeMap::from([(OsString::from("FIXTURE_STATE"), state.into_os_string())]),
            Duration::from_secs(5),
        )
        .unwrap();
        let intent = PullRequestPublicationIntent {
            operation_id: OperationId::parse("publish-1").unwrap(),
            repository_id: RepositoryId::parse("demo").unwrap(),
            clone_url: "git@github.com:acme/demo.git".into(),
            source_branch: "rex-projects/work".into(),
            source_head: "a".repeat(40),
            base_branch: "main".into(),
            title: "Ship feature".into(),
            body: "Details".into(),
            update_target: None,
        };
        (temp, publisher, intent)
    }

    #[test]
    fn lost_create_reply_reconciles_marker_and_repeated_publish_does_not_duplicate() {
        let (_temp, publisher, intent) = fixture_publisher();
        let first = publisher.publish(&intent).unwrap();
        let second = publisher.publish(&intent).unwrap();
        assert_eq!(first.number, 7);
        assert_eq!(first, second);
    }

    #[test]
    fn clone_url_parser_rejects_non_github_hosts_and_url_injection() {
        assert_eq!(
            github_repository("https://github.com/acme/demo.git").unwrap(),
            ("acme".into(), "demo".into())
        );
        assert!(github_repository("https://evil.example/acme/demo").is_err());
        assert!(github_repository("https://github.com/acme/demo?x=1").is_err());
    }
}
