//! Linear ticket adapter implemented through the user's `linear` CLI.
//!
//! Ticket authentication and network access remain inside schpet/linear-cli. This module only
//! builds GraphQL documents and invokes `linear api` as a bounded child process.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::config::TicketAdapterConfig;
use crate::domain::ids::{OperationId, ProjectId};
use crate::process::{ProcessError, ProcessRequest, resolve_executable, run};
use crate::protocol::{ErrorCode, ProtocolError, RequestId, SCHEMA_VERSION, parse_unique};

use super::tickets::{
    AdapterCapabilities, AdapterDescription, CommentReceipt, CommentResult,
    DuplicateResolutionRequest, DuplicateResolutionResult, NormalizedTicket,
    NormalizedTicketStatus, OperationFindRequest, OperationLookup, OperationMatch,
    OperationMatchBasis, ReconciliationOutcome, ScopedTicketResult, TicketAdapter,
    TicketAdapterError, TicketCommentRequest, TicketCreateRequest, TicketGetRequest,
    TicketGetResult, TicketListRequest, TicketPage, TicketScope, TicketStatusValue,
    TicketUpdateRequest, TimelineEntry,
};

const STDOUT_LIMIT: usize = 4 * 1024 * 1024;
const STDERR_TAIL_LIMIT: usize = 16 * 1024;
const PAGE_LIMIT: u32 = 100;

const ISSUE_FIELDS: &str = r#"
id identifier title description url createdAt updatedAt dueDate priority
state { id name type }
team { id key }
project { id name }
projectMilestone { id name }
assignee { id name }
parent { id identifier }
labels(first: 100) { nodes { id name } pageInfo { hasNextPage } }
relations(first: 100) { nodes { id type relatedIssue { id identifier } } pageInfo { hasNextPage } }
inverseRelations(first: 100) { nodes { id type issue { id identifier } } pageInfo { hasNextPage } }
"#;

/// A bounded adapter for schpet/linear-cli v3.1.0's documented `linear api` command.
///
/// `command` is the user-configured executable and any fixed arguments, such as
/// `linear --workspace my-workspace`. No shell is involved, and only allowlisted values from
/// `environment_snapshot` are passed to the CLI. The CLI itself resolves credentials.
pub struct LinearCliAdapter {
    executable: PathBuf,
    args: Vec<OsString>,
    environment: BTreeMap<OsString, OsString>,
    cwd: PathBuf,
    read_timeout: Duration,
    write_timeout: Duration,
    shutdown_grace: Duration,
    status_values: BTreeMap<String, String>,
    namespace: OnceLock<String>,
    cli_version: OnceLock<String>,
}

impl LinearCliAdapter {
    pub fn new(
        config: &TicketAdapterConfig,
        environment_snapshot: &BTreeMap<OsString, OsString>,
        cwd: &Path,
        shutdown_grace: Duration,
    ) -> Result<Self, TicketAdapterError> {
        let Some(executable_name) = config.command.first() else {
            return Err(TicketAdapterError::Invalid(
                "Linear CLI command must not be empty".into(),
            ));
        };
        let search_path = environment_snapshot
            .get(OsStr::new("PATH"))
            .map(std::env::split_paths)
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        let executable = resolve_executable(Path::new(executable_name), &search_path)
            .ok_or_else(|| TicketAdapterError::Invalid("Linear CLI is unavailable".into()))?;
        let cwd = cwd.canonicalize().map_err(|_| {
            TicketAdapterError::Invalid("Linear CLI working directory is unavailable".into())
        })?;
        if !cwd.is_dir()
            || config.read_timeout_seconds == 0
            || config.write_timeout_seconds == 0
            || shutdown_grace.is_zero()
        {
            return Err(TicketAdapterError::Invalid(
                "Linear CLI working directory and deadlines must be valid".into(),
            ));
        }

        let mut values = BTreeMap::from([
            ("triage".to_owned(), config.status_values.triage.clone()),
            ("backlog".to_owned(), config.status_values.backlog.clone()),
            ("ready".to_owned(), config.status_values.ready.clone()),
            (
                "in_progress".to_owned(),
                config.status_values.in_progress.clone(),
            ),
            (
                "in_review".to_owned(),
                config.status_values.in_review.clone(),
            ),
            ("done".to_owned(), config.status_values.done.clone()),
            ("canceled".to_owned(), config.status_values.canceled.clone()),
        ]);
        if values
            .values()
            .any(|value| value.trim().is_empty() || value.chars().any(char::is_control))
        {
            return Err(TicketAdapterError::Invalid(
                "Linear workflow status values must be nonempty single-line names".into(),
            ));
        }
        // Preserve the exact spelling supplied by the project configuration.
        values
            .values_mut()
            .for_each(|value| *value = value.trim().to_owned());
        let unique_statuses = values
            .values()
            .map(|value| value.to_ascii_lowercase())
            .collect::<BTreeSet<_>>();
        if unique_statuses.len() != values.len() {
            return Err(TicketAdapterError::Invalid(
                "Linear workflow status mappings must name seven distinct states".into(),
            ));
        }
        for required in ["HOME", "PATH", "XDG_CONFIG_HOME"] {
            if !config.environment_allow.iter().any(|name| name == required) {
                return Err(TicketAdapterError::Invalid(format!(
                    "Linear CLI requires `{required}` in adapters.tickets.environment_allow so the configured CLI can use its own user configuration"
                )));
            }
        }
        let allow = config
            .environment_allow
            .iter()
            .map(OsString::from)
            .collect::<BTreeSet<_>>();
        let environment = environment_snapshot
            .iter()
            .filter(|(key, _)| allow.contains(*key))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();

        Ok(Self {
            executable,
            args: config.command.iter().skip(1).map(OsString::from).collect(),
            environment,
            cwd,
            read_timeout: Duration::from_secs(config.read_timeout_seconds),
            write_timeout: Duration::from_secs(config.write_timeout_seconds),
            shutdown_grace,
            status_values: values,
            namespace: OnceLock::new(),
            cli_version: OnceLock::new(),
        })
    }

    fn verify_cli_version(&self) -> Result<&str, TicketAdapterError> {
        if let Some(version) = self.cli_version.get() {
            return Ok(version);
        }
        let mut args = self.args.clone();
        args.push(OsString::from("--version"));
        let output = run(ProcessRequest {
            executable: self.executable.clone(),
            args,
            stdin: Vec::new(),
            cwd: Some(self.cwd.clone()),
            clear_environment: true,
            environment: self.environment.clone(),
            timeout: self.read_timeout,
            shutdown_grace: self.shutdown_grace,
            stdout_limit: 4096,
            stderr_tail_limit: STDERR_TAIL_LIMIT,
        })
        .map_err(|_| TicketAdapterError::Process {
            exit_code: None,
            timed_out: false,
            cleanup_confirmed: false,
        })?;
        if output.timed_out
            || output.stdout_truncated
            || !output.cleanup_confirmed
            || output.status.and_then(|status| status.code()) != Some(0)
        {
            return Err(TicketAdapterError::Process {
                exit_code: output.status.and_then(|status| status.code()),
                timed_out: output.timed_out,
                cleanup_confirmed: output.cleanup_confirmed,
            });
        }
        let text = String::from_utf8(output.stdout).map_err(|_| {
            TicketAdapterError::Protocol("Linear CLI version output was not UTF-8".into())
        })?;
        let version = text
            .split_whitespace()
            .last()
            .unwrap_or_default()
            .trim_start_matches('v');
        if version != "3.1.0" {
            return Err(TicketAdapterError::Invalid("Linear CLI adapter supports only the verified schpet/linear-cli v3.1.0 command contract".into()));
        }
        let _ = self.cli_version.set(version.to_owned());
        Ok(self.cli_version.get().expect("version was just cached"))
    }

    fn run_api(
        &self,
        document: &str,
        variables: &Value,
        mutation: bool,
    ) -> Result<Value, TicketAdapterError> {
        let variables = serde_json::to_string(variables).map_err(|_| {
            TicketAdapterError::Protocol("Linear API variables could not be encoded".into())
        })?;
        let mut args = self.args.clone();
        args.extend([
            OsString::from("--no-input"),
            OsString::from("api"),
            OsString::from("--variables-json"),
            OsString::from(variables),
            OsString::from(document),
        ]);
        let output = run(ProcessRequest {
            executable: self.executable.clone(),
            args,
            stdin: Vec::new(),
            cwd: Some(self.cwd.clone()),
            clear_environment: true,
            environment: self.environment.clone(),
            timeout: if mutation {
                self.write_timeout
            } else {
                self.read_timeout
            },
            shutdown_grace: self.shutdown_grace,
            stdout_limit: STDOUT_LIMIT,
            stderr_tail_limit: STDERR_TAIL_LIMIT,
        })
        .map_err(|error| match error {
            ProcessError::Start(_) | ProcessError::Invalid(_) => TicketAdapterError::Process {
                exit_code: None,
                timed_out: false,
                cleanup_confirmed: true,
            },
            _ if mutation => TicketAdapterError::Uncertain,
            _ => TicketAdapterError::Process {
                exit_code: None,
                timed_out: false,
                cleanup_confirmed: false,
            },
        })?;

        if output.timed_out || output.stdout_truncated || !output.cleanup_confirmed {
            return if mutation {
                Err(TicketAdapterError::Uncertain)
            } else {
                Err(TicketAdapterError::Process {
                    exit_code: output.status.and_then(|status| status.code()),
                    timed_out: output.timed_out,
                    cleanup_confirmed: output.cleanup_confirmed,
                })
            };
        }
        let exit_code = output.status.and_then(|status| status.code());
        if exit_code != Some(0) {
            return match exit_code {
                Some(4) => Err(application_error(
                    ErrorCode::Unauthorized,
                    "Linear CLI authentication failed; repair credentials with the CLI, then resume the Project",
                    false,
                )),
                Some(1 | 5) if mutation => Err(TicketAdapterError::Uncertain),
                None if mutation => Err(TicketAdapterError::Uncertain),
                Some(5) => Err(application_error(
                    ErrorCode::Unavailable,
                    "Linear CLI could not complete the request; retry according to the adapter policy",
                    true,
                )),
                _ => Err(TicketAdapterError::Process {
                    exit_code,
                    timed_out: false,
                    cleanup_confirmed: output.cleanup_confirmed,
                }),
            };
        }
        parse_unique::<Value>(&output.stdout)
            .map_err(|_| TicketAdapterError::Protocol("Linear CLI returned invalid JSON".into()))
    }

    fn data<'a>(&self, value: &'a Value) -> Result<&'a Value, TicketAdapterError> {
        value
            .get("data")
            .ok_or_else(|| TicketAdapterError::Protocol("Linear CLI response omitted data".into()))
    }

    fn namespace(&self) -> Result<&str, TicketAdapterError> {
        self.namespace.get().map(String::as_str).ok_or_else(|| {
            TicketAdapterError::Protocol(
                "Linear adapter describe must complete before ticket operations".into(),
            )
        })
    }

    fn pin_namespace(&self, namespace: String) -> Result<(), TicketAdapterError> {
        if namespace.is_empty() || namespace.chars().any(char::is_control) {
            return Err(TicketAdapterError::Protocol(
                "Linear workspace identity is invalid".into(),
            ));
        }
        match self.namespace.set(namespace.clone()) {
            Ok(()) => Ok(()),
            Err(_)
                if self
                    .namespace
                    .get()
                    .is_some_and(|existing| existing == &namespace) =>
            {
                Ok(())
            }
            Err(_) => Err(TicketAdapterError::Protocol(
                "Linear CLI changed workspace identity during this controller run".into(),
            )),
        }
    }

    fn team_id<'a>(&self, scope: &'a TicketScope) -> Result<&'a str, TicketAdapterError> {
        scope
            .as_map()
            .get("team_id")
            .map(String::as_str)
            .ok_or_else(|| {
                TicketAdapterError::Invalid("Linear ticket scope must include `team_id`".into())
            })
    }

    fn normalized_status(
        &self,
        native: &str,
    ) -> Result<NormalizedTicketStatus, TicketAdapterError> {
        self.status_values
            .iter()
            .find(|(_, value)| value.eq_ignore_ascii_case(native))
            .map(|(status, _)| parse_status(status))
            .transpose()?
            .ok_or_else(|| {
                TicketAdapterError::Protocol("Linear returned an unmapped workflow state".into())
            })
    }

    fn native_status(&self, status: NormalizedTicketStatus) -> Result<&str, TicketAdapterError> {
        self.status_values
            .get(status_name(status))
            .map(String::as_str)
            .ok_or_else(|| {
                TicketAdapterError::Invalid("Linear status mapping is incomplete".into())
            })
    }

    fn workflow_state_id(&self, team_id: &str, native: &str) -> Result<String, TicketAdapterError> {
        let response = self.run_api(
            "query RexProjectsWorkflowStates($team: ID!) { workflowStates(first: 100, filter: { team: { id: { eq: $team } } }) { nodes { id name } pageInfo { hasNextPage } } }",
            &json!({"team": team_id}),
            false,
        )?;
        let states = self
            .data(&response)?
            .pointer("/workflowStates/nodes")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                TicketAdapterError::Protocol("Linear workflow states response was malformed".into())
            })?;
        if response
            .pointer("/data/workflowStates/pageInfo/hasNextPage")
            .and_then(Value::as_bool)
            == Some(true)
        {
            return Err(TicketAdapterError::Protocol(
                "Linear workflow state lookup returned an incomplete page".into(),
            ));
        }
        let mut matching = states.iter().filter(|state| {
            state
                .get("name")
                .and_then(Value::as_str)
                .is_some_and(|name| name == native)
        });
        let Some(state) = matching.next() else {
            return Err(TicketAdapterError::Invalid(format!(
                "configured Linear workflow state `{native}` does not exist for the team"
            )));
        };
        if matching.next().is_some() {
            return Err(TicketAdapterError::Invalid(format!(
                "configured Linear workflow state `{native}` is ambiguous"
            )));
        }
        state
            .get("id")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| {
                TicketAdapterError::Protocol("Linear workflow state omitted its identifier".into())
            })
    }

    fn labels(&self, team_id: &str, names: &[String]) -> Result<Vec<String>, TicketAdapterError> {
        let mut result = Vec::with_capacity(names.len());
        for name in names {
            let response = self.run_api(
                "query RexProjectsLabel($team: ID!, $name: String!) { issueLabels(first: 100, filter: { team: { id: { eq: $team } }, name: { eq: $name } }) { nodes { id name } pageInfo { hasNextPage } } }",
                &json!({"team": team_id, "name": name}),
                false,
            )?;
            let labels = self
                .data(&response)?
                .pointer("/issueLabels/nodes")
                .and_then(Value::as_array)
                .ok_or_else(|| {
                    TicketAdapterError::Protocol("Linear labels response was malformed".into())
                })?;
            if response
                .pointer("/data/issueLabels/pageInfo/hasNextPage")
                .and_then(Value::as_bool)
                == Some(true)
            {
                return Err(TicketAdapterError::Protocol(
                    "Linear label lookup returned an incomplete page".into(),
                ));
            }
            let ids = labels
                .iter()
                .filter(|label| label.get("name").and_then(Value::as_str) == Some(name))
                .filter_map(|label| label.get("id").and_then(Value::as_str))
                .collect::<Vec<_>>();
            if ids.len() != 1 {
                return Err(TicketAdapterError::Invalid(format!(
                    "Linear label `{name}` is missing or ambiguous for the team"
                )));
            }
            result.push(ids[0].to_owned());
        }
        Ok(result)
    }

    fn get_issue_value(&self, ticket_id: &str) -> Result<Option<Value>, TicketAdapterError> {
        let response = self.run_api(
            &format!(
                "query RexProjectsTicket($id: String!) {{ issue(id: $id) {{ {ISSUE_FIELDS} }} }}"
            ),
            &json!({"id": ticket_id}),
            false,
        )?;
        let issue = self
            .data(&response)?
            .get("issue")
            .cloned()
            .unwrap_or(Value::Null);
        Ok((!issue.is_null()).then_some(issue))
    }

    fn get_timeline(
        &self,
        ticket_id: &str,
        limit: u32,
    ) -> Result<Vec<TimelineEntry>, TicketAdapterError> {
        let response = self.run_api(
            "query RexProjectsTicketTimeline($id: String!, $first: Int!) { issue(id: $id) { comments(first: $first) { nodes { body url createdAt user { name } } pageInfo { hasNextPage } } } }",
            &json!({"id": ticket_id, "first": limit}),
            false,
        )?;
        let issue = self
            .data(&response)?
            .get("issue")
            .filter(|issue| !issue.is_null())
            .ok_or_else(|| {
                application_error(ErrorCode::NotFound, "Linear issue was not found", false)
            })?;
        let comments = connection_nodes(issue, "comments")?;
        if issue
            .pointer("/comments/pageInfo/hasNextPage")
            .and_then(Value::as_bool)
            == Some(true)
        {
            return Err(TicketAdapterError::Protocol(
                "Linear timeline response exceeded its requested bound".into(),
            ));
        }
        Ok(comments
            .iter()
            .map(|comment| TimelineEntry {
                actor: comment
                    .pointer("/user/name")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_owned(),
                timestamp: comment
                    .get("createdAt")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                event: "comment".into(),
                summary: comment
                    .get("body")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                reference: comment
                    .get("url")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            })
            .collect())
    }

    fn normalized_ticket(
        &self,
        issue: &Value,
        scope: &TicketScope,
    ) -> Result<NormalizedTicket, TicketAdapterError> {
        let text = |key: &str| issue.get(key).and_then(Value::as_str).map(str::to_owned);
        let id = text("id")
            .filter(|id| !id.is_empty())
            .ok_or_else(|| TicketAdapterError::Protocol("Linear issue omitted its UUID".into()))?;
        let title = text("title")
            .filter(|title| !title.is_empty())
            .ok_or_else(|| TicketAdapterError::Protocol("Linear issue omitted its title".into()))?;
        let state = issue.get("state").ok_or_else(|| {
            TicketAdapterError::Protocol("Linear issue omitted its workflow state".into())
        })?;
        let native_state = state.get("name").and_then(Value::as_str).ok_or_else(|| {
            TicketAdapterError::Protocol("Linear workflow state omitted its name".into())
        })?;
        let team_id = issue
            .pointer("/team/id")
            .and_then(Value::as_str)
            .ok_or_else(|| TicketAdapterError::Protocol("Linear issue omitted its team".into()))?;
        if self.team_id(scope)? != team_id {
            return Err(TicketAdapterError::Protocol(
                "Linear issue escaped the configured team scope".into(),
            ));
        }
        let labels = connection_nodes(issue, "labels")?
            .iter()
            .filter_map(|label| label.get("name").and_then(Value::as_str).map(str::to_owned))
            .collect();
        if issue
            .pointer("/labels/pageInfo/hasNextPage")
            .and_then(Value::as_bool)
            == Some(true)
        {
            return Err(TicketAdapterError::Protocol(
                "Linear issue returned an incomplete label page".into(),
            ));
        }
        let dependencies = self.dependencies(issue)?;
        let native_priority = issue.get("priority").and_then(Value::as_i64);
        let priority = native_priority
            .map(|priority| match priority {
                0 => Ok(0),
                1 => Ok(5),
                2 => Ok(4),
                3 => Ok(3),
                4 => Ok(2),
                _ => Err(TicketAdapterError::Protocol(
                    "Linear returned an unsupported priority value".into(),
                )),
            })
            .transpose()?;
        let revision = text("updatedAt");
        Ok(NormalizedTicket {
            ticket_namespace: self.namespace()?.to_owned(),
            scope: scope.clone(),
            id,
            key: text("identifier"),
            url: text("url"),
            revision,
            title,
            body: text("description").unwrap_or_default(),
            status: TicketStatusValue {
                value: self.normalized_status(native_state)?,
                native_value: Some(native_state.to_owned()),
                provider_id: state.get("id").and_then(Value::as_str).map(str::to_owned),
                label: Some(native_state.to_owned()),
            },
            priority,
            labels,
            dependencies,
            created_at: text("createdAt"),
            updated_at: text("updatedAt"),
            extensions: BTreeMap::from([
                ("linear.team_id".into(), json!(team_id)),
                (
                    "linear.project_id".into(),
                    issue.pointer("/project/id").cloned().unwrap_or(Value::Null),
                ),
                (
                    "linear.milestone_id".into(),
                    issue
                        .pointer("/projectMilestone/id")
                        .cloned()
                        .unwrap_or(Value::Null),
                ),
                (
                    "linear.assignee_id".into(),
                    issue
                        .pointer("/assignee/id")
                        .cloned()
                        .unwrap_or(Value::Null),
                ),
                (
                    "linear.due_date".into(),
                    issue.get("dueDate").cloned().unwrap_or(Value::Null),
                ),
                (
                    "linear.parent_id".into(),
                    issue.pointer("/parent/id").cloned().unwrap_or(Value::Null),
                ),
            ]),
        })
    }

    fn dependencies(&self, issue: &Value) -> Result<Vec<String>, TicketAdapterError> {
        let mut ids = Vec::new();
        for relation in connection_nodes(issue, "inverseRelations")? {
            if relation.get("type").and_then(Value::as_str) == Some("blocks")
                && let Some(id) = relation
                    .pointer("/issue/identifier")
                    .and_then(Value::as_str)
            {
                ids.push(id.to_owned());
            }
        }
        if issue
            .pointer("/inverseRelations/pageInfo/hasNextPage")
            .and_then(Value::as_bool)
            == Some(true)
        {
            return Err(TicketAdapterError::Protocol("Linear returned more than 100 incoming issue relations; dependency state is incomplete".into()));
        }
        ids.sort();
        ids.dedup();
        Ok(ids)
    }

    fn issue_input(
        &self,
        scope: &TicketScope,
        input: &TicketCreateRequest,
        id: &str,
    ) -> Result<Value, TicketAdapterError> {
        let team_id = self.team_id(scope)?;
        let mut result = json!({"id": id, "teamId": team_id, "title": input.title, "description": input.body, "useDefaultTemplate": false});
        if let Some(status) = input.status {
            let native = self.native_status(status)?;
            result["stateId"] = json!(self.workflow_state_id(team_id, native)?);
        }
        if let Some(parent) = &input.parent {
            result["parentId"] = json!(parent);
        }
        if let Some(project) = &input.project {
            result["projectId"] = json!(project);
        }
        if let Some(milestone) = &input.milestone {
            result["projectMilestoneId"] = json!(milestone);
        }
        if let Some(assignee) = &input.assignee {
            result["assigneeId"] = json!(assignee);
        }
        if let Some(priority) = input.priority {
            result["priority"] = json!(linear_priority(priority)?);
        }
        if let Some(due_date) = &input.due_date {
            result["dueDate"] = json!(due_date);
        }
        if let Some(labels) = &input.labels {
            result["labelIds"] = json!(self.labels(team_id, labels)?);
        }
        if input
            .dependencies
            .as_ref()
            .is_some_and(|dependencies| !dependencies.is_empty())
        {
            return Err(TicketAdapterError::Invalid("Linear ticket create cannot atomically set dependencies; create the ticket, then enqueue relation operations".into()));
        }
        if input.template.is_some() {
            return Err(TicketAdapterError::Invalid(
                "Linear template-backed create is not supported by the typed adapter yet".into(),
            ));
        }
        Ok(result)
    }

    fn validate_existing_create(
        &self,
        issue: &Value,
        ticket: &NormalizedTicket,
        input: &TicketCreateRequest,
    ) -> Result<(), TicketAdapterError> {
        let matches = ticket.title == input.title
            && ticket.body == input.body
            && input
                .status
                .is_none_or(|status| ticket.status.value == status)
            && input
                .priority
                .is_none_or(|priority| ticket.priority == Some(priority))
            && input.labels.as_ref().is_none_or(|labels| {
                let mut expected = labels.clone();
                let mut actual = ticket.labels.clone();
                expected.sort();
                expected.dedup();
                actual.sort();
                actual.dedup();
                expected == actual
            })
            && input.project.as_ref().is_none_or(|value| {
                issue.pointer("/project/id").and_then(Value::as_str) == Some(value)
            })
            && input.milestone.as_ref().is_none_or(|value| {
                issue
                    .pointer("/projectMilestone/id")
                    .and_then(Value::as_str)
                    == Some(value)
            })
            && input.assignee.as_ref().is_none_or(|value| {
                issue.pointer("/assignee/id").and_then(Value::as_str) == Some(value)
            })
            && input
                .due_date
                .as_ref()
                .is_none_or(|value| issue.get("dueDate").and_then(Value::as_str) == Some(value));
        if !matches {
            return Err(application_error(
                ErrorCode::Conflict,
                "stable Linear creation key is already bound to different issue content",
                false,
            ));
        }
        if let Some(parent) = &input.parent {
            let parent_id = issue.pointer("/parent/id").and_then(Value::as_str);
            let parent_identifier = issue.pointer("/parent/identifier").and_then(Value::as_str);
            if parent_id != Some(parent) && parent_identifier != Some(parent) {
                return Err(application_error(
                    ErrorCode::Conflict,
                    "stable Linear creation key is already bound to a different parent",
                    false,
                ));
            }
        }
        Ok(())
    }

    fn update_fields(
        &self,
        ticket: &NormalizedTicket,
        input: &TicketUpdateRequest,
    ) -> Result<Value, TicketAdapterError> {
        let team_id = self.team_id(&input.scope)?;
        let mut fields = serde_json::Map::new();
        for (name, value) in &input.patch {
            match name.as_str() {
                "title" => fields.insert("title".into(), required_or_null_string(value, name)?),
                "body" => fields.insert("description".into(), required_or_null_string(value, name)?),
                "status" => {
                    let status = value.as_str().ok_or_else(|| TicketAdapterError::Invalid("status patch must be a normalized status string".into()))?;
                    let native = self.status_values.get(status).ok_or_else(|| TicketAdapterError::Invalid("unknown normalized Linear status".into()))?;
                    fields.insert("stateId".into(), json!(self.workflow_state_id(team_id, native)?))
                }
                "priority" => fields.insert("priority".into(), json!(linear_priority(value.as_i64().ok_or_else(|| TicketAdapterError::Invalid("priority patch must be an integer".into()))?)?)),
                "labels" => {
                    let labels = value.as_array().ok_or_else(|| TicketAdapterError::Invalid("labels patch must be a list of names".into()))?;
                    let labels = labels.iter().map(|label| label.as_str().map(str::to_owned).ok_or_else(|| TicketAdapterError::Invalid("label names must be strings".into()))).collect::<Result<Vec<_>,_>>()?;
                    fields.insert("labelIds".into(), json!(self.labels(team_id, &labels)?))
                }
                "assignee" => fields.insert("assigneeId".into(), value.clone()),
                "project" => fields.insert("projectId".into(), value.clone()),
                "milestone" => fields.insert("projectMilestoneId".into(), value.clone()),
                "due_date" => fields.insert("dueDate".into(), value.clone()),
                "parent" => fields.insert("parentId".into(), value.clone()),
                "dependencies" => return Err(TicketAdapterError::Invalid("Linear dependency patch requires relation operations and is not supported in a ticket.update patch".into())),
                "release" => return Err(TicketAdapterError::Invalid("Linear release association is not supported by the typed adapter yet".into())),
                _ => return Err(TicketAdapterError::Invalid("ticket update contains an unsupported field".into())),
            };
        }
        fields.insert("id".into(), json!(ticket.id));
        Ok(Value::Object(fields))
    }

    fn update_patch_matches(
        &self,
        ticket: &NormalizedTicket,
        patch: &BTreeMap<String, Value>,
    ) -> bool {
        patch.iter().all(|(field, expected)| match field.as_str() {
            "title" => expected.as_str() == Some(ticket.title.as_str()),
            "body" => expected
                .as_str()
                .unwrap_or_default()
                .eq(ticket.body.as_str()),
            "status" => expected
                .as_str()
                .is_some_and(|value| parse_status(value).ok() == Some(ticket.status.value)),
            "priority" => expected.as_i64() == ticket.priority,
            "labels" => {
                let Some(expected) = expected.as_array() else {
                    return false;
                };
                let Some(mut expected) = expected
                    .iter()
                    .map(|value| value.as_str().map(str::to_owned))
                    .collect::<Option<Vec<_>>>()
                else {
                    return false;
                };
                let mut observed = ticket.labels.clone();
                expected.sort();
                observed.sort();
                expected == observed
            }
            "assignee" => ticket.extensions.get("linear.assignee_id") == Some(expected),
            "project" => ticket.extensions.get("linear.project_id") == Some(expected),
            "milestone" => ticket.extensions.get("linear.milestone_id") == Some(expected),
            "due_date" => ticket.extensions.get("linear.due_date") == Some(expected),
            "parent" => ticket.extensions.get("linear.parent_id") == Some(expected),
            // These fields are rejected by update_fields, but keep this comparison closed if the
            // patch allowlist changes later.
            _ => false,
        })
    }

    fn update_issue(&self, input: Value) -> Result<(), TicketAdapterError> {
        let response = self.run_api(
            "mutation RexProjectsUpdateIssue($input: IssueUpdateInput!) { issueUpdate(input: $input) { success issue { id updatedAt } } }",
            &json!({"input": input}),
            true,
        )?;
        if self
            .data(&response)?
            .pointer("/issueUpdate/success")
            .and_then(Value::as_bool)
            != Some(true)
        {
            return Err(TicketAdapterError::Uncertain);
        }
        Ok(())
    }

    fn create_comment(
        &self,
        ticket_id: &str,
        comment_id: &str,
        body: &str,
    ) -> Result<Value, TicketAdapterError> {
        let response = self.run_api(
            "mutation RexProjectsCreateComment($input: CommentCreateInput!) { commentCreate(input: $input) { success comment { id body url createdAt issue { id } } } }",
            &json!({"input":{"id":comment_id,"issueId":ticket_id,"body":body,"doNotSubscribeToIssue":true}}),
            true,
        )?;
        self.data(&response)?
            .pointer("/commentCreate/comment")
            .cloned()
            .ok_or(TicketAdapterError::Uncertain)
    }

    fn find_comment(&self, comment_id: &str) -> Result<Option<Value>, TicketAdapterError> {
        let response = self.run_api(
            "query RexProjectsComment($id: String!) { comment(id: $id) { id body url createdAt issue { id } } }",
            &json!({"id":comment_id}),
            false,
        )?;
        let comment = self
            .data(&response)?
            .get("comment")
            .cloned()
            .unwrap_or(Value::Null);
        Ok((!comment.is_null()).then_some(comment))
    }

    fn create_uuid(
        &self,
        kind: &str,
        scope: &TicketScope,
        key: &str,
    ) -> Result<String, TicketAdapterError> {
        let scope = serde_json::to_vec(scope)
            .map_err(|_| TicketAdapterError::Invalid("ticket scope could not be encoded".into()))?;
        let mut digest = Sha256::new();
        digest.update(b"rex-projects/linear-cli/v3.1.0\0");
        digest.update(kind.as_bytes());
        digest.update([0]);
        digest.update(self.namespace()?.as_bytes());
        digest.update([0]);
        digest.update(scope);
        digest.update([0]);
        digest.update(key.as_bytes());
        let bytes = digest.finalize();
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&bytes[..16]);
        uuid[6] = (uuid[6] & 0x0f) | 0x40;
        uuid[8] = (uuid[8] & 0x3f) | 0x80;
        Ok(format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            uuid[0],
            uuid[1],
            uuid[2],
            uuid[3],
            uuid[4],
            uuid[5],
            uuid[6],
            uuid[7],
            uuid[8],
            uuid[9],
            uuid[10],
            uuid[11],
            uuid[12],
            uuid[13],
            uuid[14],
            uuid[15]
        ))
    }
}

impl TicketAdapter for LinearCliAdapter {
    fn describe(&self, request_id: RequestId) -> Result<AdapterDescription, TicketAdapterError> {
        let cli_version = self.verify_cli_version()?.to_owned();
        let response = self.run_api(
            "query RexProjectsIdentity { viewer { organization { urlKey } } }",
            &json!({}),
            false,
        )?;
        let workspace = self
            .data(&response)?
            .pointer("/viewer/organization/urlKey")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                TicketAdapterError::Protocol(
                    "Linear identity response omitted workspace slug".into(),
                )
            })?;
        let namespace = format!("linear/{workspace}");
        self.pin_namespace(namespace.clone())?;
        let mut status_values = self.status_values.clone();
        status_values.insert("ready".into(), self.status_values["ready"].clone());
        let _ = request_id;
        Ok(AdapterDescription {
            ticket_namespace: namespace,
            identity: BTreeMap::from([
                ("adapter".into(), json!("schpet/linear-cli")),
                ("cli_version".into(), json!(cli_version)),
                ("workspace".into(), json!(workspace)),
                ("transport".into(), json!("linear api CLI")),
            ]),
            supported_schema_versions: vec![SCHEMA_VERSION],
            native_value_convention: "workflow_state_name".into(),
            status_values: std::mem::take(&mut status_values),
            capabilities: AdapterCapabilities {
                pagination: true,
                filters: BTreeSet::from(["status".into(), "assignee".into(), "project".into(), "milestone".into(), "labels".into(), "updated_since".into()]),
                revision_support: true,
                conditional_revision_mutation: false,
                atomic_scope_mutation: false,
                remote_idempotency: Vec::new(),
                reconciliation: BTreeMap::from([
                    ("ticket.create".into(), "stable caller-supplied UUID; direct by-ID lookup; absent lookup remains unknown".into()),
                    ("ticket.comment".into(), "stable caller-supplied UUID; direct by-ID lookup; absent lookup remains unknown".into()),
                    ("ticket.update".into(), "no external operation receipt; uncertain outcome remains unknown".into()),
                ]),
                visibility_grace_seconds: 120.0,
                supported_optional_methods: BTreeSet::new(),
            },
        })
    }

    fn list(
        &self,
        request_id: RequestId,
        project_id: Option<ProjectId>,
        query: TicketListRequest,
    ) -> Result<TicketPage, TicketAdapterError> {
        self.namespace()?;
        let team_id = self.team_id(&query.scope)?;
        let page_size = query.page_size.unwrap_or(50).clamp(1, PAGE_LIMIT);
        if query.query.is_some() || query.release.is_some() {
            return Err(TicketAdapterError::Invalid(
                "Linear CLI adapter does not support free-text or release filters".into(),
            ));
        }
        let mut clauses = vec![json!({"team":{"id":{"eq":team_id}}})];
        if let Some(status) = query.status {
            clauses.push(json!({"state":{"name":{"eq":self.native_status(status)?}}}));
        }
        if let Some(assignee) = &query.assignee {
            clauses.push(json!({"assignee":{"id":{"eq":assignee}}}));
        }
        if let Some(project) = &query.project {
            clauses.push(json!({"project":{"id":{"eq":project}}}));
        }
        if let Some(milestone) = &query.milestone {
            clauses.push(json!({"projectMilestone":{"id":{"eq":milestone}}}));
        }
        if let Some(updated_since) = &query.updated_since {
            clauses.push(json!({"updatedAt":{"gt":updated_since}}));
        }
        if let Some(labels) = &query.labels {
            for label in labels {
                clauses.push(json!({"labels":{"some":{"name":{"eq":label}}}}));
            }
        }
        let filter = json!({"and":clauses});
        let response = self.run_api(
            &format!("query RexProjectsTickets($first: Int!, $after: String, $filter: IssueFilter!) {{ issues(first: $first, after: $after, filter: $filter) {{ nodes {{ {ISSUE_FIELDS} }} pageInfo {{ hasNextPage endCursor }} }} }}"),
            &json!({"first":page_size,"after":query.cursor,"filter":filter}),
            false,
        )?;
        let result = self
            .data(&response)?
            .get("issues")
            .ok_or_else(|| TicketAdapterError::Protocol("Linear issue page was missing".into()))?;
        let nodes = result
            .get("nodes")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                TicketAdapterError::Protocol("Linear issue page nodes were malformed".into())
            })?;
        let tickets = nodes
            .iter()
            .map(|issue| self.normalized_ticket(issue, &query.scope))
            .collect::<Result<Vec<_>, _>>()?;
        let page_info = result.get("pageInfo").ok_or_else(|| {
            TicketAdapterError::Protocol("Linear issue page omitted pageInfo".into())
        })?;
        let next_cursor = if page_info.get("hasNextPage").and_then(Value::as_bool) == Some(true) {
            Some(
                page_info
                    .get("endCursor")
                    .and_then(Value::as_str)
                    .filter(|cursor| !cursor.is_empty())
                    .ok_or_else(|| {
                        TicketAdapterError::Protocol(
                            "Linear page indicated more rows without a cursor".into(),
                        )
                    })?
                    .to_owned(),
            )
        } else {
            None
        };
        let mut applied_filters = BTreeMap::new();
        if let Some(status) = query.status {
            applied_filters.insert("status".into(), json!(status));
        }
        if let Some(assignee) = query.assignee {
            applied_filters.insert("assignee".into(), json!(assignee));
        }
        if let Some(project) = query.project {
            applied_filters.insert("project".into(), json!(project));
        }
        if let Some(milestone) = query.milestone {
            applied_filters.insert("milestone".into(), json!(milestone));
        }
        if let Some(release) = query.release {
            applied_filters.insert("release".into(), json!(release));
        }
        if let Some(labels) = query.labels {
            applied_filters.insert("labels".into(), json!(labels));
        }
        if let Some(q) = query.query {
            applied_filters.insert("q".into(), json!(q));
        }
        if let Some(updated_since) = query.updated_since {
            applied_filters.insert("updated_since".into(), json!(updated_since));
        }
        let observed_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .to_string();
        let _ = (request_id, project_id);
        Ok(TicketPage {
            ticket_namespace: self.namespace()?.to_owned(),
            tickets,
            applied_filters,
            next_cursor,
            observed_at,
            scan: BTreeMap::from([
                ("consistent_snapshot".into(), json!(false)),
                ("page_size".into(), json!(page_size)),
                ("cursor_source".into(), json!("linear graphQL connection")),
            ]),
        })
    }

    fn get(
        &self,
        _request_id: RequestId,
        _project_id: Option<ProjectId>,
        query: TicketGetRequest,
    ) -> Result<TicketGetResult, TicketAdapterError> {
        self.namespace()?;
        let issue = self.get_issue_value(&query.ticket_id)?.ok_or_else(|| {
            application_error(ErrorCode::NotFound, "Linear issue was not found", false)
        })?;
        let ticket = self.normalized_ticket(&issue, &query.scope)?;
        let limit = query.timeline_limit.unwrap_or(20).clamp(1, PAGE_LIMIT);
        let timeline = self.get_timeline(&query.ticket_id, limit)?;
        Ok(TicketGetResult {
            ticket_namespace: self.namespace()?.to_owned(),
            ticket,
            timeline,
        })
    }

    fn create(
        &self,
        _request_id: RequestId,
        _operation_id: OperationId,
        _project_id: Option<ProjectId>,
        input: TicketCreateRequest,
    ) -> Result<ScopedTicketResult, TicketAdapterError> {
        self.namespace()?;
        if input.creation_key.is_empty() || input.title.trim().is_empty() {
            return Err(TicketAdapterError::Invalid(
                "Linear create requires a stable creation key and title".into(),
            ));
        }
        if input.template.is_some()
            || input
                .dependencies
                .as_ref()
                .is_some_and(|values| !values.is_empty())
        {
            return Err(TicketAdapterError::Invalid(
                "Linear ticket templates and create-time dependencies are not supported; submit separate typed effects".into(),
            ));
        }
        let team_id = self.team_id(&input.scope)?.to_owned();
        let id = self.create_uuid("issue", &input.scope, &input.creation_key)?;
        if let Some(existing) = self.get_issue_value(&id)? {
            let ticket = self.normalized_ticket(&existing, &input.scope)?;
            self.validate_existing_create(&existing, &ticket, &input)?;
            return Ok(ScopedTicketResult {
                ticket_namespace: self.namespace()?.into(),
                ticket,
            });
        }
        let graphql_input = self.issue_input(&input.scope, &input, &id)?;
        let response = self.run_api(
            "mutation RexProjectsCreateIssue($input: IssueCreateInput!) { issueCreate(input: $input) { success issue { id identifier title description url createdAt updatedAt dueDate priority state { id name type } team { id key } project { id name } projectMilestone { id name } assignee { id name } parent { id identifier } labels(first: 100) { nodes { id name } pageInfo { hasNextPage } } relations(first: 100) { nodes { id type relatedIssue { id identifier } } pageInfo { hasNextPage } } inverseRelations(first: 100) { nodes { id type issue { id identifier } } pageInfo { hasNextPage } } } } }",
            &json!({"input":graphql_input}),
            true,
        )?;
        let issue = self
            .data(&response)?
            .pointer("/issueCreate/issue")
            .cloned()
            .ok_or(TicketAdapterError::Uncertain)?;
        let ticket = self.normalized_ticket(&issue, &input.scope)?;
        if ticket.id != id || ticket.title != input.title {
            return Err(TicketAdapterError::Uncertain);
        }
        if issue
            .get("team")
            .and_then(|team| team.get("id"))
            .and_then(Value::as_str)
            != Some(team_id.as_str())
        {
            return Err(TicketAdapterError::Protocol(
                "Linear created the issue outside the requested team".into(),
            ));
        }
        Ok(ScopedTicketResult {
            ticket_namespace: self.namespace()?.into(),
            ticket,
        })
    }

    fn update(
        &self,
        _request_id: RequestId,
        _operation_id: OperationId,
        _project_id: Option<ProjectId>,
        input: TicketUpdateRequest,
    ) -> Result<ScopedTicketResult, TicketAdapterError> {
        self.namespace()?;
        if input.expected_revision.is_empty() || input.patch.is_empty() {
            return Err(TicketAdapterError::Invalid(
                "Linear update needs an expected revision and a nonempty patch".into(),
            ));
        }
        let issue = self.get_issue_value(&input.ticket_id)?.ok_or_else(|| {
            application_error(ErrorCode::NotFound, "Linear issue was not found", false)
        })?;
        let ticket = self.normalized_ticket(&issue, &input.scope)?;
        if ticket.revision.as_deref() != Some(input.expected_revision.as_str()) {
            return Err(application_error(
                ErrorCode::Conflict,
                "Linear issue revision changed before update; reread and replan",
                false,
            ));
        }
        let update_input = self.update_fields(&ticket, &input)?;
        self.update_issue(update_input)?;
        let updated = self
            .get_issue_value(&input.ticket_id)?
            .ok_or(TicketAdapterError::Uncertain)?;
        let ticket = self.normalized_ticket(&updated, &input.scope)?;
        if ticket.id != input.ticket_id || !self.update_patch_matches(&ticket, &input.patch) {
            return Err(TicketAdapterError::Uncertain);
        }
        Ok(ScopedTicketResult {
            ticket_namespace: self.namespace()?.into(),
            ticket,
        })
    }

    fn comment(
        &self,
        _request_id: RequestId,
        _operation_id: OperationId,
        _project_id: Option<ProjectId>,
        input: TicketCommentRequest,
    ) -> Result<CommentResult, TicketAdapterError> {
        self.namespace()?;
        if input.comment_key.is_empty() || input.body.trim().is_empty() {
            return Err(TicketAdapterError::Invalid(
                "Linear comment requires a stable key and body".into(),
            ));
        }
        let ticket = self.get_issue_value(&input.ticket_id)?.ok_or_else(|| {
            application_error(ErrorCode::NotFound, "Linear issue was not found", false)
        })?;
        let normalized = self.normalized_ticket(&ticket, &input.scope)?;
        let comment_id = self.create_uuid(
            "comment",
            &input.scope,
            &format!("{}\0{}", input.ticket_id, input.comment_key),
        )?;
        let body = append_references(&input.body, &input.references);
        let existing = self.find_comment(&comment_id)?;
        let comment = if let Some(existing) = existing {
            existing
        } else {
            self.create_comment(&input.ticket_id, &comment_id, &body)?
        };
        if comment.get("id").and_then(Value::as_str) != Some(comment_id.as_str())
            || comment.pointer("/issue/id").and_then(Value::as_str)
                != Some(input.ticket_id.as_str())
        {
            return Err(TicketAdapterError::Protocol(
                "Linear comment receipt did not bind the requested ticket and key".into(),
            ));
        }
        if comment.get("body").and_then(Value::as_str) != Some(body.as_str()) {
            return Err(application_error(
                ErrorCode::Conflict,
                "stable Linear comment key is already bound to different content",
                false,
            ));
        }
        let created_at = comment
            .get("createdAt")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                TicketAdapterError::Protocol("Linear comment omitted createdAt".into())
            })?;
        Ok(CommentResult {
            ticket_namespace: normalized.ticket_namespace,
            comment: CommentReceipt {
                reference: comment
                    .get("url")
                    .and_then(Value::as_str)
                    .unwrap_or(&comment_id)
                    .to_owned(),
                ticket_id: input.ticket_id,
                key: input.comment_key,
                created_at: created_at.to_owned(),
            },
        })
    }

    fn resolve_duplicate(
        &self,
        _request_id: RequestId,
        _operation_id: OperationId,
        _project_id: Option<ProjectId>,
        _input: DuplicateResolutionRequest,
    ) -> Result<DuplicateResolutionResult, TicketAdapterError> {
        Err(TicketAdapterError::Invalid(
            "Linear duplicate resolution must be journaled by the host as separate comment and status-update effects".into(),
        ))
    }

    fn find_operation(
        &self,
        _request_id: RequestId,
        _project_id: Option<ProjectId>,
        input: OperationFindRequest,
    ) -> Result<OperationLookup, TicketAdapterError> {
        self.namespace()?;
        let mut matches = Vec::new();
        match input.method.as_str() {
            "ticket.create" if input.subject.contains_key("creation_key") => {
                let id = self.create_uuid("issue", &input.scope, &input.stable_external_key)?;
                if let Some(issue) = self.get_issue_value(&id)? {
                    let ticket = self.normalized_ticket(&issue, &input.scope)?;
                    matches.push(OperationMatch {
                        operation_id: input.operation_id.clone(),
                        method: input.method.clone(),
                        ticket_id: Some(ticket.id.clone()),
                        stable_external_key: Some(input.stable_external_key.clone()),
                        receipt: json!({"ticket":ticket}),
                    });
                }
            }
            "ticket.comment" if input.subject.contains_key("ticket_id") => {
                let ticket_id = input.subject.get("ticket_id").expect("validated subject");
                let id = self.create_uuid(
                    "comment",
                    &input.scope,
                    &format!("{ticket_id}\0{}", input.stable_external_key),
                )?;
                if let Some(comment) = self.find_comment(&id)? {
                    if comment.pointer("/issue/id").and_then(Value::as_str)
                        != Some(ticket_id.as_str())
                    {
                        return Err(TicketAdapterError::Protocol(
                            "Linear comment lookup returned a different ticket".into(),
                        ));
                    }
                    matches.push(OperationMatch { operation_id: input.operation_id.clone(), method: input.method.clone(), ticket_id: Some(ticket_id.clone()), stable_external_key: Some(input.stable_external_key.clone()), receipt: json!({"comment":{"ticket_id":ticket_id,"id":id,"body":comment.get("body")}}) });
                }
            }
            _ => {}
        }
        let found = !matches.is_empty();
        Ok(OperationLookup {
            ticket_namespace: self.namespace()?.to_owned(),
            outcome: if found {
                ReconciliationOutcome::Found
            } else {
                ReconciliationOutcome::Unknown
            },
            match_basis: found.then_some(OperationMatchBasis::StableExternalKey),
            reason: (!found).then(|| {
                "Linear direct lookup did not prove that the external effect is absent".into()
            }),
            matches,
            proof: found.then(|| json!({"lookup":"stable provider UUID"})),
        })
    }
}

fn application_error(code: ErrorCode, message: &str, retryable: bool) -> TicketAdapterError {
    TicketAdapterError::Application(ProtocolError {
        code,
        message: message.into(),
        retryable,
        retry_after_ms: None,
        details: BTreeMap::new(),
    })
}

fn connection_nodes<'a>(
    value: &'a Value,
    field: &str,
) -> Result<&'a Vec<Value>, TicketAdapterError> {
    value
        .get(field)
        .and_then(|connection| connection.get("nodes"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            TicketAdapterError::Protocol(format!("Linear {field} connection was malformed"))
        })
}

fn parse_status(value: &str) -> Result<NormalizedTicketStatus, TicketAdapterError> {
    match value {
        "triage" => Ok(NormalizedTicketStatus::Triage),
        "backlog" => Ok(NormalizedTicketStatus::Backlog),
        "ready" => Ok(NormalizedTicketStatus::Ready),
        "in_progress" => Ok(NormalizedTicketStatus::InProgress),
        "in_review" => Ok(NormalizedTicketStatus::InReview),
        "done" => Ok(NormalizedTicketStatus::Done),
        "canceled" => Ok(NormalizedTicketStatus::Canceled),
        _ => Err(TicketAdapterError::Invalid(
            "invalid normalized ticket status".into(),
        )),
    }
}

fn status_name(value: NormalizedTicketStatus) -> &'static str {
    match value {
        NormalizedTicketStatus::Triage => "triage",
        NormalizedTicketStatus::Backlog => "backlog",
        NormalizedTicketStatus::Ready => "ready",
        NormalizedTicketStatus::InProgress => "in_progress",
        NormalizedTicketStatus::InReview => "in_review",
        NormalizedTicketStatus::Done => "done",
        NormalizedTicketStatus::Canceled => "canceled",
    }
}

fn linear_priority(value: i64) -> Result<i64, TicketAdapterError> {
    match value {
        0 => Ok(0),
        5 => Ok(1),
        4 => Ok(2),
        3 => Ok(3),
        2 => Ok(4),
        _ => Err(TicketAdapterError::Invalid(
            "Linear priority must be 0 or 2..5 normalized".into(),
        )),
    }
}

fn required_or_null_string(value: &Value, field: &str) -> Result<Value, TicketAdapterError> {
    if value.is_null() || value.as_str().is_some_and(|text| !text.is_empty()) {
        Ok(value.clone())
    } else {
        Err(TicketAdapterError::Invalid(format!(
            "{field} patch must be a nonempty string or null"
        )))
    }
}

fn append_references(body: &str, references: &[String]) -> String {
    if references.is_empty() {
        return body.to_owned();
    }
    format!(
        "{body}\n\nReferences:\n{}",
        references
            .iter()
            .map(|reference| format!("- {reference}"))
            .collect::<Vec<_>>()
            .join("\n")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct FixtureDir(PathBuf);

    impl FixtureDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "rex-projects-linear-cli-test-{}-{}",
                std::process::id(),
                TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed),
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn executable(&self, body: &str) -> PathBuf {
            let path = self.0.join("linear");
            fs::write(&path, format!("#!/bin/sh\nset -eu\n{body}\n")).unwrap();
            let mut permissions = fs::metadata(&path).unwrap().permissions();
            permissions.set_mode(0o700);
            fs::set_permissions(&path, permissions).unwrap();
            path
        }
    }

    impl Drop for FixtureDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn deterministic_ids_are_uuid_v4_shaped_and_domain_separated() {
        let status_values = crate::config::StatusValues {
            triage: "Triage".into(),
            backlog: "Backlog".into(),
            ready: "To Do".into(),
            in_progress: "In Progress".into(),
            in_review: "In Review".into(),
            done: "Done".into(),
            canceled: "Canceled".into(),
        };
        let adapter = adapter(status_values);
        adapter.pin_namespace("linear/example".into()).unwrap();
        let scope =
            TicketScope::new(BTreeMap::from([("team_id".into(), "team-1".into())])).unwrap();
        let first = adapter.create_uuid("issue", &scope, "stable-key").unwrap();
        assert_eq!(
            first,
            adapter.create_uuid("issue", &scope, "stable-key").unwrap()
        );
        assert_ne!(
            first,
            adapter
                .create_uuid("comment", &scope, "stable-key")
                .unwrap()
        );
        assert_eq!(first.len(), 36);
        assert_eq!(first.as_bytes()[14], b'4');
    }

    fn adapter(status_values: crate::config::StatusValues) -> LinearCliAdapter {
        let values = BTreeMap::from([
            ("triage".to_owned(), status_values.triage),
            ("backlog".to_owned(), status_values.backlog),
            ("ready".to_owned(), status_values.ready),
            ("in_progress".to_owned(), status_values.in_progress),
            ("in_review".to_owned(), status_values.in_review),
            ("done".to_owned(), status_values.done),
            ("canceled".to_owned(), status_values.canceled),
        ]);
        LinearCliAdapter {
            executable: PathBuf::from("/usr/bin/true"),
            args: Vec::new(),
            environment: BTreeMap::new(),
            cwd: std::env::temp_dir(),
            read_timeout: Duration::from_secs(2),
            write_timeout: Duration::from_secs(2),
            shutdown_grace: Duration::from_millis(100),
            status_values: values,
            namespace: OnceLock::new(),
            cli_version: OnceLock::new(),
        }
    }

    fn status_values() -> crate::config::StatusValues {
        crate::config::StatusValues {
            triage: "Triage".into(),
            backlog: "Backlog".into(),
            ready: "To Do".into(),
            in_progress: "In Progress".into(),
            in_review: "In Review".into(),
            done: "Done".into(),
            canceled: "Canceled".into(),
        }
    }

    fn fixture_adapter(
        dir: &FixtureDir,
        script: &str,
        env: BTreeMap<OsString, OsString>,
        allow: &[&str],
    ) -> LinearCliAdapter {
        let command = dir.executable(script);
        let snapshot = env
            .into_iter()
            .chain([(OsString::from("PATH"), OsString::from("/usr/bin:/bin"))])
            .collect();
        let mut environment_allow = ["HOME", "PATH", "XDG_CONFIG_HOME"]
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        environment_allow.extend(allow.iter().map(|s| (*s).to_owned()));
        let config = TicketAdapterConfig {
            kind: "linear_cli".into(),
            command: vec![command.to_string_lossy().into_owned()],
            environment_allow,
            read_timeout_seconds: 3,
            write_timeout_seconds: 10,
            status_values: status_values(),
        };
        LinearCliAdapter::new(&config, &snapshot, &dir.0, Duration::from_millis(100)).unwrap()
    }

    #[test]
    fn describe_pins_workspace_and_uses_only_documented_noninteractive_cli_arguments() {
        let dir = FixtureDir::new();
        let log = dir.0.join("arguments.log");
        let script = "printf '%s\\n' \"$*\" >> \"$ARGS_LOG\"\ncase \"$*\" in *--version*) echo 'linear 3.1.0';; *) printf '%s' '{\"data\":{\"viewer\":{\"organization\":{\"urlKey\":\"acme\"}}}}';; esac".to_owned();
        let adapter = fixture_adapter(
            &dir,
            &script,
            BTreeMap::from([(OsString::from("ARGS_LOG"), log.clone().into_os_string())]),
            &["ARGS_LOG"],
        );
        let description = adapter
            .describe(RequestId::new("describe-1").unwrap())
            .unwrap();
        assert_eq!(description.ticket_namespace, "linear/acme");
        assert_eq!(description.identity["cli_version"], "3.1.0");
        assert!(!description.capabilities.conditional_revision_mutation);
        let calls = fs::read_to_string(log).unwrap();
        assert!(
            calls
                .lines()
                .any(|line| line.contains("--no-input api --variables-json"))
        );
        assert!(
            calls
                .lines()
                .any(|line| line.contains("RexProjectsIdentity"))
        );
        assert!(!calls.contains("auth login"));
    }

    #[test]
    fn list_normalizes_scope_status_priority_and_cursor_without_claiming_snapshot_consistency() {
        let dir = FixtureDir::new();
        let script = r#"
case "$*" in
  *--version*) echo 'linear 3.1.0';;
  *RexProjectsIdentity*) printf '%s' '{"data":{"viewer":{"organization":{"urlKey":"acme"}}}}';;
  *RexProjectsTickets*) printf '%s' '{"data":{"issues":{"nodes":[{"id":"ticket-1","identifier":"APP-1","title":"Example","description":"Body","url":"https://linear.example/APP-1","createdAt":"2026-11-07T00:00:00Z","updatedAt":"2026-11-07T00:01:00Z","dueDate":null,"priority":4,"state":{"id":"state-ready","name":"To Do","type":"unstarted"},"team":{"id":"team-1","key":"APP"},"project":null,"projectMilestone":null,"assignee":null,"parent":null,"labels":{"nodes":[{"id":"label-1","name":"bug"}],"pageInfo":{"hasNextPage":false}},"relations":{"nodes":[],"pageInfo":{"hasNextPage":false}},"inverseRelations":{"nodes":[],"pageInfo":{"hasNextPage":false}}}],"pageInfo":{"hasNextPage":true,"endCursor":"cursor-next"}}}}';;
  *) exit 2;;
esac
"#;
        let adapter = fixture_adapter(&dir, script, BTreeMap::new(), &[]);
        adapter
            .describe(RequestId::new("describe-list").unwrap())
            .unwrap();
        let scope =
            TicketScope::new(BTreeMap::from([("team_id".into(), "team-1".into())])).unwrap();
        let page = adapter
            .list(
                RequestId::new("list-1").unwrap(),
                None,
                TicketListRequest {
                    scope,
                    status: Some(NormalizedTicketStatus::Ready),
                    assignee: None,
                    project: None,
                    milestone: None,
                    release: None,
                    labels: None,
                    query: None,
                    cursor: Some("cursor-current".into()),
                    page_size: Some(10),
                    updated_since: None,
                },
            )
            .unwrap();
        assert_eq!(page.tickets.len(), 1);
        assert_eq!(page.tickets[0].id, "ticket-1");
        assert_eq!(page.tickets[0].status.value, NormalizedTicketStatus::Ready);
        assert_eq!(page.tickets[0].priority, Some(2));
        assert_eq!(page.applied_filters["status"], "ready");
        assert_eq!(page.next_cursor.as_deref(), Some("cursor-next"));
        assert_eq!(page.scan["consistent_snapshot"], false);
    }

    #[test]
    fn authentication_failure_is_typed_and_cli_stderr_is_not_exposed() {
        let dir = FixtureDir::new();
        let adapter = fixture_adapter(
            &dir,
            "if [ \"${1:-}\" = '--version' ]; then echo 'linear 3.1.0'; exit 0; fi\necho private-token-value >&2\nexit 4",
            BTreeMap::new(),
            &[],
        );
        let error = adapter
            .run_api("query { viewer { id } }", &json!({}), false)
            .unwrap_err();
        assert!(matches!(
            error,
            TicketAdapterError::Application(ProtocolError {
                code: ErrorCode::Unauthorized,
                ..
            })
        ));
        assert!(!error.to_string().contains("private-token-value"));
    }

    #[test]
    fn unsupported_cli_version_stops_before_accessing_provider_data() {
        let dir = FixtureDir::new();
        let adapter = fixture_adapter(&dir, "echo 'linear 3.2.0'", BTreeMap::new(), &[]);
        assert!(matches!(
            adapter.describe(RequestId::new("unsupported-version").unwrap()),
            Err(TicketAdapterError::Invalid(_))
        ));
    }

    #[test]
    fn update_success_requires_readback_to_match_every_requested_patch_field() {
        let issue = r#"{"data":{"issue":{"id":"ticket-1","identifier":"APP-1","title":"Old title","description":"Body","url":"https://linear.example/APP-1","createdAt":"2026-11-07T00:00:00Z","updatedAt":"2026-11-07T00:00:00Z","dueDate":null,"priority":2,"state":{"id":"state-ready","name":"To Do","type":"unstarted"},"team":{"id":"team-1","key":"APP"},"project":null,"projectMilestone":null,"assignee":null,"parent":null,"labels":{"nodes":[],"pageInfo":{"hasNextPage":false}},"relations":{"nodes":[],"pageInfo":{"hasNextPage":false}},"inverseRelations":{"nodes":[],"pageInfo":{"hasNextPage":false}}}}}"#;
        let script = format!(
            r#"case "$*" in
  *--version*) echo 'linear 3.1.0';;
  *RexProjectsTicket*) printf '%s' '{issue}';;
  *RexProjectsWorkflowStates*) printf '%s' '{{"data":{{"workflowStates":{{"nodes":[{{"id":"state-done","name":"Done"}}],"pageInfo":{{"hasNextPage":false}}}}}}}}';;
  *RexProjectsUpdateIssue*) printf '%s' '{{"data":{{"issueUpdate":{{"success":true,"issue":{{"id":"ticket-1","updatedAt":"2026-11-07T00:02:00Z"}}}}}}}}';;
  *) exit 2;;
esac"#
        );
        let scope =
            TicketScope::new(BTreeMap::from([("team_id".into(), "team-1".into())])).unwrap();

        for (request_id, patch) in [
            (
                "stale-status-readback",
                BTreeMap::from([("status".into(), json!("done"))]),
            ),
            (
                "stale-title-readback",
                BTreeMap::from([("title".into(), json!("New title"))]),
            ),
        ] {
            let dir = FixtureDir::new();
            let adapter = fixture_adapter(&dir, &script, BTreeMap::new(), &[]);
            adapter.pin_namespace("linear/acme".into()).unwrap();
            let result = adapter.update(
                RequestId::new(request_id).unwrap(),
                OperationId::parse("update-operation").unwrap(),
                None,
                TicketUpdateRequest {
                    scope: scope.clone(),
                    ticket_id: "ticket-1".into(),
                    expected_revision: "2026-11-07T00:00:00Z".into(),
                    patch,
                },
            );
            assert!(matches!(result, Err(TicketAdapterError::Uncertain)));
        }
    }

    #[test]
    fn comment_reconciliation_finds_only_the_stable_key_and_never_claims_absence() {
        let dir = FixtureDir::new();
        let adapter = adapter(status_values());
        adapter.pin_namespace("linear/acme".into()).unwrap();
        let scope =
            TicketScope::new(BTreeMap::from([("team_id".into(), "team-1".into())])).unwrap();
        let comment_id = adapter
            .create_uuid("comment", &scope, "ticket-1\0comment-key")
            .unwrap();
        let found_adapter = fixture_adapter(
            &dir,
            &format!(
                "printf '%s' '{{\"data\":{{\"comment\":{{\"id\":\"{comment_id}\",\"body\":\"done\",\"url\":\"https://linear.example/comment\",\"createdAt\":\"2026-11-07T00:00:00Z\",\"issue\":{{\"id\":\"ticket-1\"}}}}}}}}'"
            ),
            BTreeMap::new(),
            &[],
        );
        found_adapter.pin_namespace("linear/acme".into()).unwrap();
        let request = OperationFindRequest {
            scope: scope.clone(),
            operation_id: "outbox-op".into(),
            method: "ticket.comment".into(),
            stable_external_key: "comment-key".into(),
            subject: BTreeMap::from([("ticket_id".into(), "ticket-1".into())]),
        };
        let found = found_adapter
            .find_operation(
                RequestId::new("find-comment").unwrap(),
                None,
                request.clone(),
            )
            .unwrap();
        assert!(matches!(found.outcome, ReconciliationOutcome::Found));
        assert_eq!(
            found.match_basis,
            Some(OperationMatchBasis::StableExternalKey)
        );
        assert_eq!(found.matches[0].ticket_id.as_deref(), Some("ticket-1"));
        assert_eq!(
            found.matches[0].stable_external_key.as_deref(),
            Some("comment-key")
        );

        let absent = fixture_adapter(
            &dir,
            "printf '%s' '{\"data\":{\"comment\":null}}'",
            BTreeMap::new(),
            &[],
        );
        absent.pin_namespace("linear/acme".into()).unwrap();
        let lookup = absent
            .find_operation(RequestId::new("find-absent").unwrap(), None, request)
            .unwrap();
        assert!(matches!(lookup.outcome, ReconciliationOutcome::Unknown));
        assert!(lookup.proof.is_none());
    }

    #[test]
    fn mutation_exit_five_is_unknown_and_never_claimed_as_success() {
        let dir = FixtureDir::new();
        let adapter = fixture_adapter(
            &dir,
            "echo 'linear 3.1.0' >/dev/null\necho transient-error >&2\nexit 5",
            BTreeMap::new(),
            &[],
        );
        assert!(matches!(
            adapter.run_api("mutation { issueCreate }", &json!({}), true),
            Err(TicketAdapterError::Uncertain)
        ));
    }
}
