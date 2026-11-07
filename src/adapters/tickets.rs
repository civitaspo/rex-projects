use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::domain::ids::{OperationId, ProjectId};
use crate::process::{ProcessRequest, resolve_executable, run};
use crate::protocol::{MethodName, RequestEnvelope, RequestId, ResponseEnvelope, parse_unique};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TicketMethod {
    Describe,
    List,
    Get,
    Create,
    Update,
    Comment,
    Triage,
    ResolveDuplicate,
    FindOperation,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TicketScope(BTreeMap<String, String>);

impl TicketScope {
    pub fn new(values: BTreeMap<String, String>) -> Result<Self, TicketAdapterError> {
        if values.is_empty()
            || values.iter().any(|(key, value)| {
                key.is_empty()
                    || value.is_empty()
                    || key.chars().any(char::is_control)
                    || value.chars().any(char::is_control)
            })
        {
            return Err(TicketAdapterError::Invalid(
                "scope needs nonempty scalar identifiers".into(),
            ));
        }
        Ok(Self(values))
    }

    pub fn as_map(&self) -> &BTreeMap<String, String> {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NormalizedTicketStatus {
    Triage,
    Backlog,
    Ready,
    InProgress,
    InReview,
    Done,
    Canceled,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TicketStatusValue {
    pub value: NormalizedTicketStatus,
    #[serde(default)]
    pub native_value: Option<String>,
    #[serde(default)]
    pub provider_id: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NormalizedTicket {
    pub ticket_namespace: String,
    pub scope: TicketScope,
    pub id: String,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub revision: Option<String>,
    pub title: String,
    pub body: String,
    pub status: TicketStatusValue,
    #[serde(default)]
    pub priority: Option<i64>,
    #[serde(default)]
    pub labels: Vec<String>,
    #[serde(default)]
    pub dependencies: Vec<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
    #[serde(default)]
    pub extensions: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TicketPage {
    pub ticket_namespace: String,
    pub tickets: Vec<NormalizedTicket>,
    pub applied_filters: BTreeMap<String, Value>,
    #[serde(default)]
    pub next_cursor: Option<String>,
    pub observed_at: String,
    pub scan: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdapterDescription {
    pub ticket_namespace: String,
    pub identity: BTreeMap<String, Value>,
    pub supported_schema_versions: Vec<u32>,
    pub native_value_convention: String,
    pub status_values: BTreeMap<String, String>,
    pub capabilities: AdapterCapabilities,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdapterCapabilities {
    pub pagination: bool,
    pub filters: BTreeSet<String>,
    pub revision_support: bool,
    pub conditional_revision_mutation: bool,
    pub atomic_scope_mutation: bool,
    pub remote_idempotency: Vec<String>,
    pub reconciliation: BTreeMap<String, String>,
    pub visibility_grace_seconds: f64,
    pub supported_optional_methods: BTreeSet<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TicketGetResult {
    pub ticket_namespace: String,
    pub ticket: NormalizedTicket,
    #[serde(default)]
    pub timeline: Vec<TimelineEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScopedTicketResult {
    pub ticket_namespace: String,
    pub ticket: NormalizedTicket,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommentResult {
    pub ticket_namespace: String,
    pub comment: CommentReceipt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommentReceipt {
    pub reference: String,
    pub ticket_id: String,
    pub key: String,
    pub created_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DuplicateResolutionResult {
    pub ticket_namespace: String,
    pub duplicate: NormalizedTicket,
    pub canonical_ticket_id: String,
    pub comment_key: String,
    pub outcome: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TimelineEntry {
    pub actor: String,
    #[serde(rename = "time")]
    pub timestamp: String,
    pub event: String,
    pub summary: String,
    #[serde(default)]
    pub reference: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconciliationOutcome {
    Found,
    Absent,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationMatchBasis {
    OperationId,
    StableExternalKey,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperationMatch {
    pub operation_id: String,
    pub method: String,
    #[serde(default)]
    pub ticket_id: Option<String>,
    #[serde(default)]
    pub stable_external_key: Option<String>,
    pub receipt: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperationLookup {
    pub ticket_namespace: String,
    pub outcome: ReconciliationOutcome,
    #[serde(default)]
    pub match_basis: Option<OperationMatchBasis>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub matches: Vec<OperationMatch>,
    #[serde(default)]
    pub proof: Option<Value>,
}

#[derive(Clone, Debug, Serialize)]
pub struct TicketListRequest {
    pub scope: TicketScope,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<NormalizedTicketStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assignee: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub milestone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "q")]
    pub query: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_size: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_since: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct TicketGetRequest {
    pub scope: TicketScope,
    pub ticket_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeline_limit: Option<u32>,
}

#[derive(Clone, Debug, Serialize)]
pub struct TicketCreateRequest {
    pub scope: TicketScope,
    pub creation_key: String,
    pub title: String,
    pub body: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<NormalizedTicketStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dependencies: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub milestone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assignee: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub due_date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize)]
pub struct TicketUpdateRequest {
    pub scope: TicketScope,
    pub ticket_id: String,
    pub expected_revision: String,
    /// Only fields in Appendix H's normalized patch allowlist are accepted.
    pub patch: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize)]
pub struct TicketCommentRequest {
    pub scope: TicketScope,
    pub ticket_id: String,
    pub comment_key: String,
    pub body: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DuplicateResolutionRequest {
    pub scope: TicketScope,
    pub duplicate_ticket_id: String,
    pub canonical_ticket_id: String,
    pub operation_key: String,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct OperationFindRequest {
    pub scope: TicketScope,
    pub operation_id: String,
    pub method: String,
    pub stable_external_key: String,
    pub subject: BTreeMap<String, String>,
}

impl TicketMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Describe => "adapter.describe",
            Self::List => "ticket.list",
            Self::Get => "ticket.get",
            Self::Create => "ticket.create",
            Self::Update => "ticket.update",
            Self::Comment => "ticket.comment",
            Self::Triage => "ticket.triage",
            Self::ResolveDuplicate => "ticket.resolve_duplicate",
            Self::FindOperation => "operation.find",
        }
    }
}

#[derive(Debug)]
pub enum TicketAdapterError {
    Invalid(String),
    Process {
        exit_code: Option<i32>,
        timed_out: bool,
        cleanup_confirmed: bool,
    },
    Protocol(String),
    Application(crate::protocol::ProtocolError),
    Uncertain,
}

impl std::fmt::Display for TicketAdapterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(message) => write!(f, "invalid ticket adapter request: {message}"),
            Self::Process {
                timed_out: true, ..
            } => f.write_str("ticket adapter command timed out"),
            Self::Process { .. } => f.write_str("ticket adapter command failed"),
            Self::Protocol(message) => write!(f, "ticket adapter protocol error: {message}"),
            Self::Application(error) => write!(f, "ticket adapter returned {:?}", error.code),
            Self::Uncertain => f.write_str("ticket adapter effect has an uncertain outcome"),
        }
    }
}

impl std::error::Error for TicketAdapterError {}

pub struct TicketCommandAdapter {
    executable: PathBuf,
    args: Vec<OsString>,
    environment: BTreeMap<OsString, OsString>,
    cwd: PathBuf,
    timeout: Duration,
    shutdown_grace: Duration,
    stdout_limit: usize,
    stderr_tail_limit: usize,
    expected_ticket_namespace: OnceLock<String>,
}

/// Object-safe boundary used by the controller to dispatch normalized ticket operations.
pub trait TicketAdapter: Send + Sync {
    fn describe(&self, request_id: RequestId) -> Result<AdapterDescription, TicketAdapterError>;
    fn list(
        &self,
        request_id: RequestId,
        project_id: Option<ProjectId>,
        query: TicketListRequest,
    ) -> Result<TicketPage, TicketAdapterError>;
    fn get(
        &self,
        request_id: RequestId,
        project_id: Option<ProjectId>,
        query: TicketGetRequest,
    ) -> Result<TicketGetResult, TicketAdapterError>;
    fn create(
        &self,
        request_id: RequestId,
        operation_id: OperationId,
        project_id: Option<ProjectId>,
        input: TicketCreateRequest,
    ) -> Result<ScopedTicketResult, TicketAdapterError>;
    fn update(
        &self,
        request_id: RequestId,
        operation_id: OperationId,
        project_id: Option<ProjectId>,
        input: TicketUpdateRequest,
    ) -> Result<ScopedTicketResult, TicketAdapterError>;
    fn comment(
        &self,
        request_id: RequestId,
        operation_id: OperationId,
        project_id: Option<ProjectId>,
        input: TicketCommentRequest,
    ) -> Result<CommentResult, TicketAdapterError>;
    fn resolve_duplicate(
        &self,
        request_id: RequestId,
        operation_id: OperationId,
        project_id: Option<ProjectId>,
        input: DuplicateResolutionRequest,
    ) -> Result<DuplicateResolutionResult, TicketAdapterError>;
    fn find_operation(
        &self,
        request_id: RequestId,
        project_id: Option<ProjectId>,
        input: OperationFindRequest,
    ) -> Result<OperationLookup, TicketAdapterError>;
}

impl TicketCommandAdapter {
    pub fn new(
        command: &[String],
        environment_snapshot: &BTreeMap<OsString, OsString>,
        environment_allowlist: &[String],
        cwd: &Path,
        expected_ticket_namespace: String,
        timeout: Duration,
        shutdown_grace: Duration,
    ) -> Result<Self, TicketAdapterError> {
        Self::new_inner(
            command,
            environment_snapshot,
            environment_allowlist,
            cwd,
            Some(expected_ticket_namespace),
            timeout,
            shutdown_grace,
        )
    }

    /// Construct an adapter whose namespace is learned and pinned by its first successful
    /// `describe` call. Data operations fail until that call has completed.
    pub fn new_discovering_namespace(
        command: &[String],
        environment_snapshot: &BTreeMap<OsString, OsString>,
        environment_allowlist: &[String],
        cwd: &Path,
        timeout: Duration,
        shutdown_grace: Duration,
    ) -> Result<Self, TicketAdapterError> {
        Self::new_inner(
            command,
            environment_snapshot,
            environment_allowlist,
            cwd,
            None,
            timeout,
            shutdown_grace,
        )
    }

    fn new_inner(
        command: &[String],
        environment_snapshot: &BTreeMap<OsString, OsString>,
        environment_allowlist: &[String],
        cwd: &Path,
        expected_ticket_namespace: Option<String>,
        timeout: Duration,
        shutdown_grace: Duration,
    ) -> Result<Self, TicketAdapterError> {
        let Some(binary) = command.first() else {
            return Err(TicketAdapterError::Invalid(
                "command must not be empty".into(),
            ));
        };
        let path = Path::new(binary);
        let search_path = environment_snapshot
            .get(OsStr::new("PATH"))
            .map(std::env::split_paths)
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        let executable = resolve_executable(path, &search_path).ok_or_else(|| {
            TicketAdapterError::Invalid("configured command is unavailable".into())
        })?;
        let cwd = cwd
            .canonicalize()
            .map_err(|_| TicketAdapterError::Invalid("working directory is unavailable".into()))?;
        if !cwd.is_dir()
            || timeout.is_zero()
            || shutdown_grace.is_zero()
            || expected_ticket_namespace.as_ref().is_some_and(|namespace| {
                namespace.is_empty() || namespace.chars().any(char::is_control)
            })
        {
            return Err(TicketAdapterError::Invalid(
                "working directory and deadlines must be valid".into(),
            ));
        }
        let allow = environment_allowlist
            .iter()
            .map(OsString::from)
            .collect::<std::collections::BTreeSet<_>>();
        let environment = environment_snapshot
            .iter()
            .filter(|(key, _)| allow.contains(*key))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        Ok(Self {
            executable,
            args: command.iter().skip(1).map(OsString::from).collect(),
            environment,
            cwd,
            timeout,
            shutdown_grace,
            stdout_limit: 4 * 1024 * 1024,
            stderr_tail_limit: 64 * 1024,
            expected_ticket_namespace: expected_ticket_namespace
                .map_or_else(OnceLock::new, OnceLock::from),
        })
    }

    pub fn describe(
        &self,
        request_id: RequestId,
    ) -> Result<AdapterDescription, TicketAdapterError> {
        let description: AdapterDescription = self.call_json(
            request_id,
            None,
            TicketMethod::Describe,
            None,
            serde_json::json!({"schema_version": crate::protocol::SCHEMA_VERSION}),
        )?;
        self.pin_or_validate_namespace(&description.ticket_namespace)?;
        self.validate_namespace(&description.ticket_namespace)?;
        if !description
            .supported_schema_versions
            .contains(&crate::protocol::SCHEMA_VERSION)
        {
            return Err(TicketAdapterError::Protocol(
                "adapter does not support schema version 1".into(),
            ));
        }
        for status in [
            "triage",
            "backlog",
            "ready",
            "in_progress",
            "in_review",
            "done",
            "canceled",
        ] {
            if !description.status_values.contains_key(status) {
                return Err(TicketAdapterError::Protocol(
                    "adapter status map is missing a normalized status".into(),
                ));
            }
        }
        if description.status_values.len() != 7 {
            return Err(TicketAdapterError::Protocol(
                "adapter status map must contain exactly seven normalized statuses".into(),
            ));
        }
        if !description
            .capabilities
            .visibility_grace_seconds
            .is_finite()
            || description.capabilities.visibility_grace_seconds < 0.0
        {
            return Err(TicketAdapterError::Protocol(
                "adapter visibility grace must be a finite nonnegative number".into(),
            ));
        }
        Ok(description)
    }

    pub fn list(
        &self,
        request_id: RequestId,
        project_id: Option<ProjectId>,
        mut query: TicketListRequest,
    ) -> Result<TicketPage, TicketAdapterError> {
        if query
            .page_size
            .is_some_and(|size| !(1..=100).contains(&size))
        {
            return Err(TicketAdapterError::Invalid(
                "page_size must be 1..=100".into(),
            ));
        }
        if let Some(labels) = query.labels.as_mut() {
            labels.sort();
            labels.dedup();
        }
        let expected_scope = query.scope.clone();
        let params = serde_json::to_value(query)
            .map_err(|_| TicketAdapterError::Protocol("request encoding failed".into()))?;
        let expected_filters = params
            .as_object()
            .expect("typed list request serializes to an object")
            .iter()
            .filter(|(key, _)| !matches!(key.as_str(), "scope" | "cursor" | "page_size"))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<BTreeMap<_, _>>();
        let page: TicketPage =
            self.call_json(request_id, None, TicketMethod::List, project_id, params)?;
        self.validate_namespace(&page.ticket_namespace)?;
        if !page.observed_at.is_empty()
            && expected_filters
                .iter()
                .all(|(key, value)| page.applied_filters.get(key) == Some(value))
        {
            // Echoing filters prevents a provider from silently widening the scan.
        } else {
            return Err(TicketAdapterError::Protocol(
                "ticket list did not echo every requested filter and observation time".into(),
            ));
        }
        for ticket in &page.tickets {
            self.validate_ticket(ticket, &expected_scope)?;
        }
        Ok(page)
    }

    pub fn get(
        &self,
        request_id: RequestId,
        project_id: Option<ProjectId>,
        query: TicketGetRequest,
    ) -> Result<TicketGetResult, TicketAdapterError> {
        if query.ticket_id.is_empty() || !(1..=100).contains(&query.timeline_limit.unwrap_or(20)) {
            return Err(TicketAdapterError::Invalid(
                "ticket ID or timeline limit is invalid".into(),
            ));
        }
        let requested_ticket_id = query.ticket_id.clone();
        let scope = query.scope.clone();
        let result: TicketGetResult = self.call_json(
            request_id,
            None,
            TicketMethod::Get,
            project_id,
            serde_json::to_value(query)
                .map_err(|_| TicketAdapterError::Protocol("request encoding failed".into()))?,
        )?;
        self.validate_namespace(&result.ticket_namespace)?;
        self.validate_ticket(&result.ticket, &scope)?;
        if result.ticket.id != requested_ticket_id {
            return Err(TicketAdapterError::Protocol(
                "ticket.get returned a different ticket ID".into(),
            ));
        }
        Ok(result)
    }

    pub fn create(
        &self,
        request_id: RequestId,
        operation_id: OperationId,
        project_id: Option<ProjectId>,
        input: TicketCreateRequest,
    ) -> Result<ScopedTicketResult, TicketAdapterError> {
        if input.creation_key.is_empty() || input.title.is_empty() {
            return Err(TicketAdapterError::Invalid(
                "creation key and title must be nonempty".into(),
            ));
        }
        let scope = input.scope.clone();
        let result: ScopedTicketResult = self.call_json(
            request_id,
            Some(operation_id),
            TicketMethod::Create,
            project_id,
            serde_json::to_value(input)
                .map_err(|_| TicketAdapterError::Protocol("request encoding failed".into()))?,
        )?;
        self.validate_namespace(&result.ticket_namespace)?;
        self.validate_ticket(&result.ticket, &scope)?;
        Ok(result)
    }

    pub fn update(
        &self,
        request_id: RequestId,
        operation_id: OperationId,
        project_id: Option<ProjectId>,
        input: TicketUpdateRequest,
    ) -> Result<ScopedTicketResult, TicketAdapterError> {
        const ALLOWED: [&str; 12] = [
            "title",
            "body",
            "status",
            "priority",
            "labels",
            "assignee",
            "project",
            "milestone",
            "release",
            "due_date",
            "parent",
            "dependencies",
        ];
        if input.expected_revision.is_empty()
            || input.ticket_id.is_empty()
            || input.patch.is_empty()
            || input
                .patch
                .keys()
                .any(|key| !ALLOWED.contains(&key.as_str()))
        {
            return Err(TicketAdapterError::Invalid(
                "update needs scope, current revision, ticket ID, and a whitelisted nonempty patch"
                    .into(),
            ));
        }
        let scope = input.scope.clone();
        let requested_ticket_id = input.ticket_id.clone();
        let result: ScopedTicketResult = self.call_json(
            request_id,
            Some(operation_id),
            TicketMethod::Update,
            project_id,
            serde_json::to_value(input)
                .map_err(|_| TicketAdapterError::Protocol("request encoding failed".into()))?,
        )?;
        self.validate_namespace(&result.ticket_namespace)?;
        self.validate_ticket(&result.ticket, &scope)?;
        if result.ticket.id != requested_ticket_id {
            return Err(TicketAdapterError::Protocol(
                "ticket.update returned a different ticket ID".into(),
            ));
        }
        Ok(result)
    }

    pub fn comment(
        &self,
        request_id: RequestId,
        operation_id: OperationId,
        project_id: Option<ProjectId>,
        input: TicketCommentRequest,
    ) -> Result<CommentResult, TicketAdapterError> {
        let ticket_id = input.ticket_id.clone();
        let comment_key = input.comment_key.clone();
        if ticket_id.is_empty() || input.comment_key.is_empty() || input.body.is_empty() {
            return Err(TicketAdapterError::Invalid(
                "comment identity and body must be nonempty".into(),
            ));
        }
        let result: CommentResult = self.call_json(
            request_id,
            Some(operation_id),
            TicketMethod::Comment,
            project_id,
            serde_json::to_value(input)
                .map_err(|_| TicketAdapterError::Protocol("request encoding failed".into()))?,
        )?;
        self.validate_namespace(&result.ticket_namespace)?;
        if result.comment.ticket_id != ticket_id
            || result.comment.key != comment_key
            || result.comment.reference.is_empty()
            || result.comment.created_at.is_empty()
        {
            return Err(TicketAdapterError::Protocol(
                "comment result omitted ticket or receipt identity".into(),
            ));
        }
        Ok(result)
    }

    pub fn resolve_duplicate(
        &self,
        request_id: RequestId,
        operation_id: OperationId,
        project_id: Option<ProjectId>,
        input: DuplicateResolutionRequest,
    ) -> Result<DuplicateResolutionResult, TicketAdapterError> {
        if input.duplicate_ticket_id.is_empty()
            || input.canonical_ticket_id.is_empty()
            || input.duplicate_ticket_id == input.canonical_ticket_id
            || input.operation_key.is_empty()
            || input.reason.is_empty()
        {
            return Err(TicketAdapterError::Invalid(
                "duplicate resolution identities and reason are required".into(),
            ));
        }
        let scope = input.scope.clone();
        let duplicate_id = input.duplicate_ticket_id.clone();
        let canonical_id = input.canonical_ticket_id.clone();
        let operation_key = input.operation_key.clone();
        let result: DuplicateResolutionResult = self.call_json(
            request_id,
            Some(operation_id),
            TicketMethod::ResolveDuplicate,
            project_id,
            serde_json::to_value(input)
                .map_err(|_| TicketAdapterError::Protocol("request encoding failed".into()))?,
        )?;
        self.validate_namespace(&result.ticket_namespace)?;
        self.validate_ticket(&result.duplicate, &scope)?;
        if result.canonical_ticket_id != canonical_id
            || result.duplicate.id != duplicate_id
            || result.comment_key != operation_key
            || result.outcome != "resolved"
            || result.duplicate.status.value != NormalizedTicketStatus::Canceled
        {
            return Err(TicketAdapterError::Protocol(
                "duplicate resolution did not confirm the requested canonical ticket and cancellation".into(),
            ));
        }
        Ok(result)
    }

    pub fn find_operation(
        &self,
        request_id: RequestId,
        project_id: Option<ProjectId>,
        input: OperationFindRequest,
    ) -> Result<OperationLookup, TicketAdapterError> {
        let requested_operation_id = input.operation_id.clone();
        let requested_method = input.method.clone();
        let requested_subject = input.subject.clone();
        let requested_external_key = input.stable_external_key.clone();
        if input.operation_id.is_empty()
            || input.method.is_empty()
            || input.stable_external_key.is_empty()
            || input.subject.len() != 1
            || !input
                .subject
                .keys()
                .all(|key| key == "ticket_id" || key == "creation_key")
        {
            return Err(TicketAdapterError::Invalid(
                "operation lookup needs exact scoped identity".into(),
            ));
        }
        if input
            .subject
            .get("creation_key")
            .is_some_and(|key| key != &input.stable_external_key)
        {
            return Err(TicketAdapterError::Invalid(
                "creation subject must match stable external key".into(),
            ));
        }
        let result: OperationLookup = self.call_json(
            request_id,
            None,
            TicketMethod::FindOperation,
            project_id,
            serde_json::to_value(input)
                .map_err(|_| TicketAdapterError::Protocol("request encoding failed".into()))?,
        )?;
        self.validate_namespace(&result.ticket_namespace)?;
        if matches!(result.outcome, ReconciliationOutcome::Found) && result.matches.is_empty() {
            return Err(TicketAdapterError::Protocol(
                "found reconciliation has no receipts".into(),
            ));
        }
        if !matches!(result.outcome, ReconciliationOutcome::Found) && !result.matches.is_empty() {
            return Err(TicketAdapterError::Protocol(
                "non-found reconciliation contains receipts".into(),
            ));
        }
        if matches!(result.outcome, ReconciliationOutcome::Absent) && result.proof.is_none() {
            return Err(TicketAdapterError::Protocol(
                "adapter claimed absence without scoped proof".into(),
            ));
        }
        if matches!(result.outcome, ReconciliationOutcome::Unknown)
            && result.reason.as_deref().unwrap_or_default().is_empty()
        {
            return Err(TicketAdapterError::Protocol(
                "unknown reconciliation must explain why absence is not proven".into(),
            ));
        }
        if matches!(result.outcome, ReconciliationOutcome::Found) != result.match_basis.is_some() {
            return Err(TicketAdapterError::Protocol(
                "found reconciliation must declare its match basis".into(),
            ));
        }
        for matched in &result.matches {
            let subject_matches = if let Some(ticket_id) = requested_subject.get("ticket_id") {
                matched.ticket_id.as_deref() == Some(ticket_id)
                    && receipt_ticket_id(&matched.receipt) == Some(ticket_id.as_str())
            } else if requested_subject.contains_key("creation_key") {
                matched.stable_external_key.as_deref() == Some(&requested_external_key)
                    && matched
                        .ticket_id
                        .as_deref()
                        .is_some_and(|ticket_id| !ticket_id.is_empty())
                    && matched.ticket_id.as_deref() == receipt_ticket_id(&matched.receipt)
            } else {
                false
            };
            let operation_id_matches = match result.match_basis {
                Some(OperationMatchBasis::OperationId) => {
                    matched.operation_id == requested_operation_id
                }
                Some(OperationMatchBasis::StableExternalKey) => {
                    !matched.operation_id.is_empty()
                        && matched.stable_external_key.as_deref() == Some(&requested_external_key)
                }
                None => false,
            };
            if matched.method != requested_method || !operation_id_matches || !subject_matches {
                return Err(TicketAdapterError::Protocol(
                    "operation receipt does not bind the requested operation and subject".into(),
                ));
            }
        }
        Ok(result)
    }

    fn validate_namespace(&self, namespace: &str) -> Result<(), TicketAdapterError> {
        if self
            .expected_ticket_namespace
            .get()
            .is_some_and(|expected| expected == namespace)
        {
            Ok(())
        } else if self.expected_ticket_namespace.get().is_none() {
            Err(TicketAdapterError::Protocol(
                "adapter describe must pin the ticket namespace before data operations".into(),
            ))
        } else {
            Err(TicketAdapterError::Protocol(
                "adapter response changed the configured ticket namespace".into(),
            ))
        }
    }

    fn ensure_namespace_pinned(&self) -> Result<(), TicketAdapterError> {
        if self.expected_ticket_namespace.get().is_some() {
            Ok(())
        } else {
            Err(TicketAdapterError::Protocol(
                "adapter describe must pin the ticket namespace before data operations".into(),
            ))
        }
    }

    fn validate_ticket(
        &self,
        ticket: &NormalizedTicket,
        expected_scope: &TicketScope,
    ) -> Result<(), TicketAdapterError> {
        self.validate_namespace(&ticket.ticket_namespace)?;
        if &ticket.scope != expected_scope || ticket.id.is_empty() || ticket.title.is_empty() {
            return Err(TicketAdapterError::Protocol(
                "normalized ticket escaped scope or omitted identity".into(),
            ));
        }
        if ticket.revision.as_ref().is_some_and(String::is_empty) {
            return Err(TicketAdapterError::Protocol(
                "ticket revision must be nonempty when present".into(),
            ));
        }
        Ok(())
    }

    fn call_json<T: for<'de> Deserialize<'de>>(
        &self,
        request_id: RequestId,
        operation_id: Option<OperationId>,
        method: TicketMethod,
        project_id: Option<ProjectId>,
        params: Value,
    ) -> Result<T, TicketAdapterError> {
        if method != TicketMethod::Describe {
            self.ensure_namespace_pinned()?;
        }
        let request = RequestEnvelope {
            schema_version: crate::protocol::SCHEMA_VERSION,
            request_id: request_id.clone(),
            operation_id,
            method: MethodName::new(method.as_str()).map_err(TicketAdapterError::Invalid)?,
            project_id,
            run_id: None,
            attempt: None,
            run_epoch: None,
            expected_subject_revision: None,
            role: None,
            request_type: None,
            params,
        };
        request.validate().map_err(TicketAdapterError::Protocol)?;
        let has_operation_id = request.operation_id.is_some();
        let has_project_id = request.project_id.is_some();
        let mut request_value = serde_json::to_value(&request)
            .map_err(|_| TicketAdapterError::Protocol("request encoding failed".into()))?;
        if !has_operation_id {
            request_value
                .as_object_mut()
                .expect("serialized request envelope is an object")
                .remove("operation_id");
        }
        if !has_project_id {
            request_value
                .as_object_mut()
                .expect("serialized request envelope is an object")
                .remove("project_id");
        }
        let stdin = serde_json::to_vec(&request_value)
            .map_err(|_| TicketAdapterError::Protocol("request encoding failed".into()))?;
        let output = run(ProcessRequest {
            executable: self.executable.clone(),
            args: self.args.clone(),
            stdin,
            cwd: Some(self.cwd.clone()),
            clear_environment: true,
            environment: self.environment.clone(),
            timeout: self.timeout,
            shutdown_grace: self.shutdown_grace,
            stdout_limit: self.stdout_limit,
            stderr_tail_limit: self.stderr_tail_limit,
        })
        .map_err(|_| TicketAdapterError::Process {
            exit_code: None,
            timed_out: false,
            cleanup_confirmed: false,
        })?;
        if output.timed_out
            || !output.cleanup_confirmed
            || !output.status.is_some_and(|s| s.success())
        {
            return Err(TicketAdapterError::Process {
                exit_code: output.status.and_then(|s| s.code()),
                timed_out: output.timed_out,
                cleanup_confirmed: output.cleanup_confirmed,
            });
        }
        if output.stdout_truncated {
            return Err(TicketAdapterError::Protocol(
                "response exceeded the 4 MiB limit".into(),
            ));
        }
        if output.stdout.is_empty() {
            return Err(
                if matches!(
                    method,
                    TicketMethod::Create
                        | TicketMethod::Update
                        | TicketMethod::Comment
                        | TicketMethod::Triage
                        | TicketMethod::ResolveDuplicate
                ) {
                    TicketAdapterError::Uncertain
                } else {
                    TicketAdapterError::Protocol("adapter returned an empty read response".into())
                },
            );
        }
        let response: ResponseEnvelope<Value> =
            parse_unique(&output.stdout).map_err(TicketAdapterError::Protocol)?;
        if response.schema_version != crate::protocol::SCHEMA_VERSION {
            return Err(TicketAdapterError::Protocol(
                "adapter response schema version does not match".into(),
            ));
        }
        if response.request_id != request_id {
            return Err(TicketAdapterError::Protocol(format!(
                "adapter response request ID `{}` does not match `{}`",
                response.request_id.as_str(),
                request_id.as_str()
            )));
        }
        if response.result.is_some() == response.error.is_some() {
            return Err(TicketAdapterError::Protocol(
                "adapter response must contain exactly one result or error".into(),
            ));
        }
        if let Some(error) = response.error {
            return Err(TicketAdapterError::Application(error));
        }
        let value = response
            .result
            .ok_or_else(|| TicketAdapterError::Protocol("missing result".into()))?;
        serde_json::from_value(value).map_err(|_| {
            TicketAdapterError::Protocol("result did not match the normalized schema".into())
        })
    }

    fn pin_or_validate_namespace(&self, namespace: &str) -> Result<(), TicketAdapterError> {
        if namespace.is_empty() || namespace.chars().any(char::is_control) {
            return Err(TicketAdapterError::Protocol(
                "adapter returned an invalid ticket namespace".into(),
            ));
        }
        if let Some(expected) = self.expected_ticket_namespace.get() {
            return if expected == namespace {
                Ok(())
            } else {
                Err(TicketAdapterError::Protocol(
                    "adapter response changed the configured ticket namespace".into(),
                ))
            };
        }
        match self.expected_ticket_namespace.set(namespace.to_owned()) {
            Ok(()) => Ok(()),
            Err(_)
                if self
                    .expected_ticket_namespace
                    .get()
                    .is_some_and(|expected| expected == namespace) =>
            {
                Ok(())
            }
            Err(_) => Err(TicketAdapterError::Protocol(
                "adapter response changed the discovered ticket namespace".into(),
            )),
        }
    }
}

fn receipt_ticket_id(receipt: &Value) -> Option<&str> {
    receipt
        .pointer("/ticket/id")
        .or_else(|| receipt.pointer("/comment/ticket_id"))
        .or_else(|| receipt.pointer("/duplicate/id"))
        .and_then(Value::as_str)
}

use std::ffi::OsStr;

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::time::Duration;

    use serde_json::json;

    use crate::domain::ids::{OperationId, ProjectId};
    use crate::protocol::RequestId;

    use super::{
        DuplicateResolutionRequest, NormalizedTicketStatus, OperationFindRequest,
        ReconciliationOutcome, TicketAdapter, TicketCommandAdapter, TicketCommentRequest,
        TicketCreateRequest, TicketGetRequest, TicketListRequest, TicketScope, TicketUpdateRequest,
    };

    #[test]
    fn discovered_namespace_is_pinned_by_describe_before_data_calls() {
        let dir = tempfile::tempdir().unwrap();
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/tickets/ticket_fixture.py");
        let command = vec![
            "python3".into(),
            fixture.display().to_string(),
            "--database".into(),
            dir.path().join("tickets.sqlite").display().to_string(),
            "--namespace".into(),
            "fixture/tenant-a".into(),
            "--visibility-delay-seconds".into(),
            "0".into(),
        ];
        let adapter = TicketCommandAdapter::new_discovering_namespace(
            &command,
            &BTreeMap::from([(
                std::ffi::OsString::from("PATH"),
                std::env::var_os("PATH").unwrap(),
            )]),
            &[],
            dir.path(),
            Duration::from_secs(5),
            Duration::from_millis(100),
        )
        .unwrap();
        let project = Some(ProjectId::parse("project-1").unwrap());
        let create_request = create(scope("external-project"), "key", "Ticket");
        assert!(matches!(
            adapter.create(
                req("before-describe"),
                op("before-describe"),
                project.clone(),
                create_request.clone()
            ),
            Err(super::TicketAdapterError::Protocol(_))
        ));

        let object_safe: &dyn TicketAdapter = &adapter;
        let description = object_safe.describe(req("describe")).unwrap();
        assert_eq!(description.ticket_namespace, "fixture/tenant-a");
        let created = object_safe
            .create(
                req("after-describe"),
                op("after-describe"),
                project,
                create_request,
            )
            .unwrap();
        assert_eq!(created.ticket.ticket_namespace, "fixture/tenant-a");
        let tickets = object_safe
            .list(
                req("list-after-describe"),
                None,
                list(scope("external-project"), Some(10), None),
            )
            .unwrap();
        assert_eq!(tickets.tickets.len(), 1);
    }

    #[test]
    fn typed_adapter_round_trips_scope_revision_cursor_comments_and_duplicates() {
        let dir = tempfile::tempdir().unwrap();
        let adapter = fixture_adapter(&dir, None);
        let project = Some(ProjectId::parse("project-1").unwrap());
        let description = adapter.describe(req("describe")).unwrap();
        assert_eq!(description.ticket_namespace, "fixture/tenant-a");
        assert!(description.capabilities.conditional_revision_mutation);
        let ticket_scope = scope("external-project");
        let first = adapter
            .create(
                req("create-a"),
                op("create-a"),
                project.clone(),
                create(ticket_scope.clone(), "key-a", "Ticket A"),
            )
            .unwrap();
        let second = adapter
            .create(
                req("create-b"),
                op("create-b"),
                project.clone(),
                create(ticket_scope.clone(), "key-b", "Ticket B"),
            )
            .unwrap();
        assert_eq!(first.ticket.revision.as_deref(), Some("rev-1"));

        let first_page = adapter
            .list(
                req("list-a"),
                project.clone(),
                list(ticket_scope.clone(), Some(1), None),
            )
            .unwrap();
        assert_eq!(first_page.tickets.len(), 1);
        let cursor = first_page.next_cursor.clone().unwrap();
        let second_page = adapter
            .list(
                req("list-b"),
                project.clone(),
                list(ticket_scope.clone(), Some(1), Some(cursor.clone())),
            )
            .unwrap();
        assert_eq!(second_page.tickets.len(), 1);
        let other_scope = scope("different-project");
        let conflict = adapter.list(
            req("list-c"),
            project.clone(),
            list(other_scope, Some(1), Some(cursor)),
        );
        assert!(
            matches!(conflict, Err(super::TicketAdapterError::Application(error)) if matches!(error.code, crate::protocol::ErrorCode::Conflict))
        );

        let got = adapter
            .get(
                req("get"),
                project.clone(),
                TicketGetRequest {
                    scope: ticket_scope.clone(),
                    ticket_id: first.ticket.id.clone(),
                    timeline_limit: Some(20),
                },
            )
            .unwrap();
        let stale = adapter.update(
            req("stale"),
            op("stale"),
            project.clone(),
            TicketUpdateRequest {
                scope: ticket_scope.clone(),
                ticket_id: first.ticket.id.clone(),
                expected_revision: "rev-0".into(),
                patch: BTreeMap::from([("title".into(), json!("stale"))]),
            },
        );
        assert!(
            matches!(stale, Err(super::TicketAdapterError::Application(error)) if matches!(error.code, crate::protocol::ErrorCode::Conflict))
        );

        adapter
            .comment(
                req("comment"),
                op("comment"),
                project.clone(),
                TicketCommentRequest {
                    scope: ticket_scope.clone(),
                    ticket_id: got.ticket.id.clone(),
                    comment_key: "comment-a".into(),
                    body: "Progress update".into(),
                    references: vec![],
                },
            )
            .unwrap();
        let resolved = adapter
            .resolve_duplicate(
                req("duplicate"),
                op("duplicate"),
                project.clone(),
                DuplicateResolutionRequest {
                    scope: ticket_scope.clone(),
                    duplicate_ticket_id: second.ticket.id.clone(),
                    canonical_ticket_id: first.ticket.id.clone(),
                    operation_key: "duplicate-op".into(),
                    reason: "same work".into(),
                },
            )
            .unwrap();
        assert_eq!(
            resolved.duplicate.status.value,
            NormalizedTicketStatus::Canceled
        );
    }

    #[test]
    fn lost_create_response_is_uncertain_and_reconciliation_is_typed() {
        let dir = tempfile::tempdir().unwrap();
        let adapter = fixture_adapter(&dir, Some("create-lost"));
        let project = Some(ProjectId::parse("project-1").unwrap());
        let ticket_scope = scope("external-project");
        let lost = adapter.create(
            req("lost"),
            op("create-lost"),
            project.clone(),
            create(ticket_scope.clone(), "lost-key", "Lost response"),
        );
        assert!(matches!(lost, Err(super::TicketAdapterError::Uncertain)));
        let lookup = adapter
            .find_operation(
                req("find"),
                project,
                OperationFindRequest {
                    scope: ticket_scope,
                    operation_id: "create-lost".into(),
                    method: "ticket.create".into(),
                    stable_external_key: "lost-key".into(),
                    subject: BTreeMap::from([("creation_key".into(), "lost-key".into())]),
                },
            )
            .unwrap();
        assert!(matches!(lookup.outcome, ReconciliationOutcome::Found));
        assert_eq!(lookup.matches.len(), 1);
    }

    #[test]
    fn stable_creation_key_lookup_preserves_ambiguous_candidates() {
        let dir = tempfile::tempdir().unwrap();
        let adapter = fixture_adapter(&dir, None);
        let project = Some(ProjectId::parse("project-1").unwrap());
        let ticket_scope = scope("external-project");
        adapter
            .create(
                req("create-candidate-a"),
                op("create-candidate-a"),
                project.clone(),
                create(ticket_scope.clone(), "shared-key", "Candidate A"),
            )
            .unwrap();
        adapter
            .create(
                req("create-candidate-b"),
                op("create-candidate-b"),
                project.clone(),
                create(ticket_scope.clone(), "shared-key", "Candidate B"),
            )
            .unwrap();

        let lookup = adapter
            .find_operation(
                req("find-candidates"),
                project,
                OperationFindRequest {
                    scope: ticket_scope,
                    operation_id: "not-indexed-yet".into(),
                    method: "ticket.create".into(),
                    stable_external_key: "shared-key".into(),
                    subject: BTreeMap::from([("creation_key".into(), "shared-key".into())]),
                },
            )
            .unwrap();

        assert!(matches!(lookup.outcome, ReconciliationOutcome::Found));
        assert_eq!(
            lookup.match_basis,
            Some(super::OperationMatchBasis::StableExternalKey)
        );
        assert_eq!(lookup.matches.len(), 2);
        assert!(lookup.matches.iter().all(|matched| {
            matched.operation_id != "not-indexed-yet"
                && matched.stable_external_key.as_deref() == Some("shared-key")
        }));
    }

    #[test]
    fn rejects_ticket_receipts_bound_to_different_requested_identities() {
        let dir = tempfile::tempdir().unwrap();
        let project = Some(ProjectId::parse("project-1").unwrap());
        let ticket_scope = scope("external-project");
        let base = fixture_adapter(&dir, None);
        let first = base
            .create(
                req("identity-seed"),
                op("identity-seed"),
                project.clone(),
                create(ticket_scope.clone(), "identity-seed-key", "Seed"),
            )
            .unwrap();
        let second = base
            .create(
                req("identity-second"),
                op("identity-second"),
                project.clone(),
                create(ticket_scope.clone(), "identity-second-key", "Second"),
            )
            .unwrap();
        base.update(
            req("identity-update"),
            op("identity-update"),
            project.clone(),
            TicketUpdateRequest {
                scope: ticket_scope.clone(),
                ticket_id: first.ticket.id.clone(),
                expected_revision: first.ticket.revision.clone().unwrap(),
                patch: BTreeMap::from([("title".into(), json!("Identity update"))]),
            },
        )
        .unwrap();

        let get = response_mutator(&dir, "get-ticket-id");
        assert!(matches!(
            get.get(
                req("wrong-get"),
                project.clone(),
                TicketGetRequest {
                    scope: ticket_scope.clone(),
                    ticket_id: first.ticket.id.clone(),
                    timeline_limit: None,
                }
            ),
            Err(super::TicketAdapterError::Protocol(_))
        ));

        let update = response_mutator(&dir, "update-ticket-id");
        assert!(matches!(
            update.update(
                req("wrong-update"),
                op("wrong-update"),
                project.clone(),
                TicketUpdateRequest {
                    scope: ticket_scope.clone(),
                    ticket_id: first.ticket.id.clone(),
                    expected_revision: "rev-2".into(),
                    patch: BTreeMap::from([("title".into(), json!("Updated"))]),
                }
            ),
            Err(super::TicketAdapterError::Protocol(_))
        ));

        let comment = response_mutator(&dir, "comment-key");
        assert!(matches!(
            comment.comment(
                req("wrong-comment"),
                op("wrong-comment"),
                project.clone(),
                TicketCommentRequest {
                    scope: ticket_scope.clone(),
                    ticket_id: first.ticket.id.clone(),
                    comment_key: "requested-comment-key".into(),
                    body: "body".into(),
                    references: vec![],
                }
            ),
            Err(super::TicketAdapterError::Protocol(_))
        ));

        let duplicate = response_mutator(&dir, "duplicate-key");
        assert!(matches!(
            duplicate.resolve_duplicate(
                req("wrong-duplicate"),
                op("wrong-duplicate"),
                project.clone(),
                DuplicateResolutionRequest {
                    scope: ticket_scope.clone(),
                    duplicate_ticket_id: second.ticket.id.clone(),
                    canonical_ticket_id: first.ticket.id.clone(),
                    operation_key: "requested-duplicate-key".into(),
                    reason: "same work".into(),
                }
            ),
            Err(super::TicketAdapterError::Protocol(_))
        ));

        let unrelated_operation = response_mutator(&dir, "operation-id");
        assert!(matches!(
            unrelated_operation.find_operation(
                req("wrong-find-operation"),
                project.clone(),
                OperationFindRequest {
                    scope: ticket_scope.clone(),
                    operation_id: "identity-seed".into(),
                    method: "ticket.create".into(),
                    stable_external_key: "identity-seed-key".into(),
                    subject: BTreeMap::from([("creation_key".into(), "identity-seed-key".into(),)]),
                }
            ),
            Err(super::TicketAdapterError::Protocol(_))
        ));

        let unrelated_ticket = response_mutator(&dir, "operation-ticket-id");
        assert!(matches!(
            unrelated_ticket.find_operation(
                req("wrong-find-ticket"),
                project,
                OperationFindRequest {
                    scope: ticket_scope,
                    operation_id: "identity-update".into(),
                    method: "ticket.update".into(),
                    stable_external_key: "identity-update-key".into(),
                    subject: BTreeMap::from([("ticket_id".into(), first.ticket.id)]),
                }
            ),
            Err(super::TicketAdapterError::Protocol(_))
        ));
    }

    fn fixture_adapter(dir: &tempfile::TempDir, drop_once: Option<&str>) -> TicketCommandAdapter {
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/tickets/ticket_fixture.py");
        let db = dir.path().join("tickets.sqlite");
        let mut command = vec![
            "python3".into(),
            fixture.display().to_string(),
            "--database".into(),
            db.display().to_string(),
            "--namespace".into(),
            "fixture/tenant-a".into(),
            "--visibility-delay-seconds".into(),
            "0".into(),
        ];
        if let Some(operation_id) = drop_once {
            command.extend(["--drop-create-response-once".into(), operation_id.into()]);
        }
        TicketCommandAdapter::new(
            &command,
            &BTreeMap::from([(
                std::ffi::OsString::from("PATH"),
                std::env::var_os("PATH").unwrap(),
            )]),
            &[],
            dir.path(),
            "fixture/tenant-a".into(),
            Duration::from_secs(5),
            Duration::from_millis(100),
        )
        .unwrap()
    }

    fn response_mutator(dir: &tempfile::TempDir, mutation: &str) -> TicketCommandAdapter {
        let wrapper = dir.path().join("response_mutator.py");
        std::fs::write(
            &wrapper,
            r#"import json, subprocess, sys
mutation = sys.argv[1]
command = sys.argv[2:]
request = sys.stdin.buffer.read()
run = subprocess.run(command, input=request, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
response = json.loads(run.stdout)
result = response["result"]
if mutation == "get-ticket-id" or mutation == "update-ticket-id":
    result["ticket"]["id"] = "unrelated-ticket"
elif mutation == "comment-key":
    result["comment"]["key"] = "unrelated-comment-key"
elif mutation == "duplicate-key":
    result["comment_key"] = "unrelated-duplicate-key"
elif mutation == "operation-id":
    result["matches"][0]["operation_id"] = "UNRELATED-OP"
elif mutation == "operation-ticket-id":
    result["matches"][0]["ticket_id"] = "UNRELATED-TICKET"
sys.stdout.write(json.dumps(response, separators=(",", ":")))
"#,
        )
        .unwrap();
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/tickets/ticket_fixture.py");
        let command = vec![
            "python3".into(),
            wrapper.display().to_string(),
            mutation.into(),
            "python3".into(),
            fixture.display().to_string(),
            "--database".into(),
            dir.path().join("tickets.sqlite").display().to_string(),
            "--namespace".into(),
            "fixture/tenant-a".into(),
            "--visibility-delay-seconds".into(),
            "0".into(),
        ];
        TicketCommandAdapter::new(
            &command,
            &BTreeMap::from([(
                std::ffi::OsString::from("PATH"),
                std::env::var_os("PATH").unwrap(),
            )]),
            &[],
            dir.path(),
            "fixture/tenant-a".into(),
            Duration::from_secs(5),
            Duration::from_millis(100),
        )
        .unwrap()
    }

    fn req(id: &str) -> RequestId {
        RequestId::new(id).unwrap()
    }
    fn op(id: &str) -> OperationId {
        OperationId::parse(id).unwrap()
    }
    fn scope(project: &str) -> TicketScope {
        TicketScope::new(BTreeMap::from([("project".into(), project.into())])).unwrap()
    }
    fn create(scope: TicketScope, key: &str, title: &str) -> TicketCreateRequest {
        TicketCreateRequest {
            scope,
            creation_key: key.into(),
            title: title.into(),
            body: "Acceptance criteria".into(),
            status: Some(NormalizedTicketStatus::Ready),
            template: None,
            parent: None,
            dependencies: Some(vec![]),
            project: None,
            milestone: None,
            assignee: None,
            priority: None,
            due_date: None,
            labels: Some(vec!["fixture".into()]),
        }
    }
    fn list(
        scope: TicketScope,
        page_size: Option<u32>,
        cursor: Option<String>,
    ) -> TicketListRequest {
        TicketListRequest {
            scope,
            status: None,
            assignee: None,
            project: None,
            milestone: None,
            release: None,
            labels: Some(vec!["fixture".into()]),
            query: None,
            cursor,
            page_size,
            updated_since: None,
        }
    }
}

impl TicketAdapter for TicketCommandAdapter {
    fn describe(&self, request_id: RequestId) -> Result<AdapterDescription, TicketAdapterError> {
        TicketCommandAdapter::describe(self, request_id)
    }

    fn list(
        &self,
        request_id: RequestId,
        project_id: Option<ProjectId>,
        query: TicketListRequest,
    ) -> Result<TicketPage, TicketAdapterError> {
        TicketCommandAdapter::list(self, request_id, project_id, query)
    }

    fn get(
        &self,
        request_id: RequestId,
        project_id: Option<ProjectId>,
        query: TicketGetRequest,
    ) -> Result<TicketGetResult, TicketAdapterError> {
        TicketCommandAdapter::get(self, request_id, project_id, query)
    }

    fn create(
        &self,
        request_id: RequestId,
        operation_id: OperationId,
        project_id: Option<ProjectId>,
        input: TicketCreateRequest,
    ) -> Result<ScopedTicketResult, TicketAdapterError> {
        TicketCommandAdapter::create(self, request_id, operation_id, project_id, input)
    }

    fn update(
        &self,
        request_id: RequestId,
        operation_id: OperationId,
        project_id: Option<ProjectId>,
        input: TicketUpdateRequest,
    ) -> Result<ScopedTicketResult, TicketAdapterError> {
        TicketCommandAdapter::update(self, request_id, operation_id, project_id, input)
    }

    fn comment(
        &self,
        request_id: RequestId,
        operation_id: OperationId,
        project_id: Option<ProjectId>,
        input: TicketCommentRequest,
    ) -> Result<CommentResult, TicketAdapterError> {
        TicketCommandAdapter::comment(self, request_id, operation_id, project_id, input)
    }

    fn resolve_duplicate(
        &self,
        request_id: RequestId,
        operation_id: OperationId,
        project_id: Option<ProjectId>,
        input: DuplicateResolutionRequest,
    ) -> Result<DuplicateResolutionResult, TicketAdapterError> {
        TicketCommandAdapter::resolve_duplicate(self, request_id, operation_id, project_id, input)
    }

    fn find_operation(
        &self,
        request_id: RequestId,
        project_id: Option<ProjectId>,
        input: OperationFindRequest,
    ) -> Result<OperationLookup, TicketAdapterError> {
        TicketCommandAdapter::find_operation(self, request_id, project_id, input)
    }
}
