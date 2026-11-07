//! Typed human review requests and a self-contained, read-only HTML renderer.
//!
//! The HTML is for presentation only. Decisions are submitted through the host CLI,
//! which must persist them and re-check the current subject before waking a controller.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::domain::ids::{Digest, HumanRequestId, ProjectId, Revision, TicketId, TicketRunId};
use crate::domain::types::Role;
use crate::protocol::{
    MethodName, ProtocolError, RequestEnvelope, RequestId as ProtocolRequestId, SCHEMA_VERSION,
    parse_unique,
};

pub const MAX_REVIEW_TEXT_BYTES: usize = 1_048_576;
pub const MAX_REVIEW_ITEMS: usize = 256;

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HumanRequestKind {
    PlanReview,
    ChangeReview,
    ReleaseReview,
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HumanChoice {
    Approve,
    RequestChanges,
    RevisePlan,
    Defer,
    Cancel,
}

impl HumanRequestKind {
    pub fn allows(self, choice: HumanChoice) -> bool {
        match self {
            Self::PlanReview => matches!(
                choice,
                HumanChoice::Approve
                    | HumanChoice::RequestChanges
                    | HumanChoice::RevisePlan
                    | HumanChoice::Defer
                    | HumanChoice::Cancel
            ),
            Self::ChangeReview | Self::ReleaseReview => matches!(
                choice,
                HumanChoice::Approve
                    | HumanChoice::RequestChanges
                    | HumanChoice::Defer
                    | HumanChoice::Cancel
            ),
        }
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewSubject {
    pub project_id: ProjectId,
    pub ticket_id: TicketId,
    pub ticket_run_id: TicketRunId,
    pub ticket_revision: Revision,
    /// Digest of the exact PR identities and source/base revisions under review.
    pub repository_heads_digest: Digest,
    /// Digest of the applicable merge/release policy and repository instructions.
    pub policy_digest: Digest,
    /// Digest of the complete review bundle, including diff and evidence manifests.
    pub bundle_digest: Digest,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanRequest {
    pub request_id: HumanRequestId,
    pub kind: HumanRequestKind,
    pub subject: ReviewSubject,
    pub question: String,
    pub choices: Vec<HumanChoice>,
    /// Unix timestamp in seconds. Expiry changes eligibility; it does not delete history.
    pub expires_at: u64,
}

impl HumanRequest {
    pub fn validate(&self) -> Result<(), String> {
        if self.question.trim().is_empty() {
            return Err("human request question must not be empty".into());
        }
        validate_text(&self.question, "question")?;
        if self.choices.is_empty() || self.choices.len() > 5 {
            return Err("human request must offer between 1 and 5 choices".into());
        }
        let mut seen = BTreeSet::new();
        for choice in &self.choices {
            if !self.kind.allows(*choice) {
                return Err(format!(
                    "choice {choice:?} is not valid for {:?}",
                    self.kind
                ));
            }
            if !seen.insert(*choice as u8) {
                return Err("human request choices must be unique".into());
            }
        }
        Ok(())
    }
}

/// CLI presenter payload for `human.present`. The executable receives one JSON request on stdin
/// and returns one JSON response on stdout. Command execution and timeouts belong to the host
/// process adapter; this module validates the protocol payload only.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanPresentParams {
    pub request_id: HumanRequestId,
    pub kind: HumanRequestKind,
    pub subject: ReviewSubject,
    pub subject_digest: Digest,
    pub bundle_digest: Digest,
    pub bundle_path: String,
    pub summary_markdown: String,
    pub question: String,
    pub choices: Vec<HumanChoice>,
    pub expires_at: u64,
    pub response_command: String,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresentedReference {
    pub reference: String,
    #[serde(default)]
    pub location: Option<String>,
    pub request_id: HumanRequestId,
    pub subject_digest: Digest,
    pub bundle_digest: Digest,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HumanPresenterResponse {
    schema_version: u32,
    request_id: ProtocolRequestId,
    #[serde(default)]
    result: Option<PresentedReference>,
    #[serde(default)]
    error: Option<ProtocolError>,
    #[serde(default)]
    extensions: std::collections::BTreeMap<String, serde_json::Value>,
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DashboardView {
    Supervisors,
    Agents,
    TicketsAwaitingHuman,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DashboardRow {
    pub project_id: ProjectId,
    pub ticket_id: Option<TicketId>,
    pub request_id: Option<HumanRequestId>,
    pub role: Role,
    pub state: DashboardState,
    pub summary: String,
    pub focus: Option<RexFocusTarget>,
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DashboardState {
    Queued,
    Running,
    Parked,
    AwaitingHuman,
    Completed,
    Failed,
    Unknown,
}

/// A structured Rex location. Consumers call the Rex API with these fields; never turn terminal
/// text from an Agent or human into a command string.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RexFocusTarget {
    pub window_id: String,
    pub block_id: Option<String>,
}

impl RexFocusTarget {
    pub fn validate(&self) -> Result<(), String> {
        if self.window_id.is_empty()
            || self.window_id.len() > 255
            || self.window_id.chars().any(char::is_control)
        {
            return Err("invalid Rex window_id".into());
        }
        if let Some(block_id) = &self.block_id
            && (block_id.is_empty()
                || block_id.len() > 255
                || block_id.chars().any(char::is_control))
        {
            return Err("invalid Rex block_id".into());
        }
        Ok(())
    }
}

pub fn human_present_envelope(
    protocol_request_id: ProtocolRequestId,
    project_id: ProjectId,
    params: HumanPresentParams,
) -> RequestEnvelope<HumanPresentParams> {
    RequestEnvelope::host(
        protocol_request_id,
        None,
        MethodName::new("human.present").expect("static method is valid"),
        Some(project_id),
        params,
    )
}

/// Validate a configured presenter's response. It can only acknowledge presentation; it cannot
/// carry or grant an approval. Remote polling needs a separate adapter authentication contract.
pub fn parse_presented_reference(
    bytes: &[u8],
    protocol_request_id: &ProtocolRequestId,
    request: &HumanRequest,
) -> Result<PresentedReference, String> {
    let response: HumanPresenterResponse = parse_unique(bytes)?;
    if response.schema_version != SCHEMA_VERSION {
        return Err("unsupported presenter response schema version".into());
    }
    if &response.request_id != protocol_request_id {
        return Err("presenter response request_id does not match request".into());
    }
    if response.result.is_some() == response.error.is_some() {
        return Err("presenter response must contain exactly one of result or error".into());
    }
    let result = response
        .result
        .ok_or_else(|| "presenter returned an error instead of a reference".to_owned())?;
    if result.request_id != request.request_id
        || result.subject_digest != subject_digest(&request.subject)
        || result.bundle_digest != request.subject.bundle_digest
    {
        return Err("presenter reference does not match the current human request".into());
    }
    validate_text(&result.reference, "presenter reference")?;
    if result.reference.trim().is_empty() {
        return Err("presenter reference must not be empty".into());
    }
    if let Some(location) = &result.location {
        validate_safe_url(location)?;
    }
    Ok(result)
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanDecisionInput {
    pub request_id: HumanRequestId,
    pub expected_subject_digest: Digest,
    pub response_id: String,
    pub choice: HumanChoice,
    #[serde(default)]
    pub explanation: Option<String>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionValidation {
    Accepted,
    InvalidRequest,
    Expired,
    StaleSubject,
    ChoiceNotOffered,
    RequestMismatch,
    InvalidInput,
}

/// Re-check against freshly observed state immediately before persisting a response.
/// A stale or expired response is retained as a conflict, never repurposed for a newer request.
pub fn validate_decision(
    request: &HumanRequest,
    current: &ReviewSubject,
    input: &HumanDecisionInput,
    now: u64,
) -> DecisionValidation {
    if request.validate().is_err() {
        return DecisionValidation::InvalidRequest;
    }
    if input.response_id.trim().is_empty()
        || input.response_id.len() > 255
        || input.response_id.chars().any(char::is_control)
        || input
            .explanation
            .as_ref()
            .is_some_and(|text| validate_text(text, "explanation").is_err())
    {
        return DecisionValidation::InvalidInput;
    }
    if input.request_id != request.request_id {
        return DecisionValidation::RequestMismatch;
    }
    if now >= request.expires_at {
        return DecisionValidation::Expired;
    }
    if &request.subject != current
        || input.expected_subject_digest != subject_digest(&request.subject)
    {
        return DecisionValidation::StaleSubject;
    }
    if !request.kind.allows(input.choice) || !request.choices.contains(&input.choice) {
        return DecisionValidation::ChoiceNotOffered;
    }
    DecisionValidation::Accepted
}

pub fn subject_digest(subject: &ReviewSubject) -> Digest {
    let bytes =
        serde_json::to_vec(subject).expect("serializing a typed review subject cannot fail");
    Digest::parse(hex(&Sha256::digest(bytes))).expect("SHA-256 is canonical lowercase hex")
}

/// Same response ID and bytes may be replayed. Reusing an ID for different input is a conflict.
pub fn response_replay_matches(
    existing: &HumanDecisionInput,
    incoming: &HumanDecisionInput,
) -> bool {
    existing.response_id == incoming.response_id
        && serde_json::to_vec(existing).ok() == serde_json::to_vec(incoming).ok()
}

/// Agent-side markers are a cheap guard against accidental self-approval. Call at the host CLI
/// boundary before opening the database or enqueueing a durable command. This is not an auth
/// boundary against a deliberate same-user process that removes its environment.
pub fn reject_factory_child_context<I, K, V>(vars: I) -> Result<(), FactoryChildRejected>
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<std::ffi::OsStr>,
    V: AsRef<std::ffi::OsStr>,
{
    for (key, value) in vars {
        let key = key.as_ref();
        if (key == "REX_PROJECTS_AGENT" || key == "REX_PROJECTS_CONTEXT")
            && !value.as_ref().is_empty()
        {
            return Err(FactoryChildRejected);
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FactoryChildRejected;

impl FactoryChildRejected {
    pub const EXIT_CODE: i32 = 77;
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewBundle {
    pub title: String,
    pub summary: String,
    pub risk: Option<ReviewRisk>,
    pub repositories: Vec<RepositoryReview>,
    pub evidence: Vec<ReviewEvidence>,
    pub unknowns: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskConfidence {
    Low,
    Medium,
    High,
    Unknown,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewRisk {
    /// The Merge Decision Agent's ordinal rating, from 0 (narrow/understood) to 4 (high risk).
    pub rating: u8,
    pub confidence: RiskConfidence,
    pub rationale: String,
    pub unresolved_gates: Vec<String>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryReview {
    pub repository: String,
    pub pull_request: String,
    pub url: Option<String>,
    pub base_ref: String,
    pub base_sha: String,
    pub head_ref: String,
    pub head_sha: String,
    pub checks: Vec<String>,
    pub review_receipts: Vec<String>,
    pub merge_steps: Vec<String>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewEvidence {
    pub title: String,
    pub body: String,
    pub truncated: bool,
}

impl ReviewBundle {
    pub fn validate(&self) -> Result<(), String> {
        if self.repositories.len() + self.evidence.len() + self.unknowns.len() > MAX_REVIEW_ITEMS {
            return Err("review bundle contains too many items".into());
        }
        for (name, value) in [("title", &self.title), ("summary", &self.summary)] {
            validate_text(value, name)?;
        }
        if let Some(risk) = &self.risk {
            if risk.rating > 4 {
                return Err("risk rating must be between 0 and 4".into());
            }
            validate_text(&risk.rationale, "risk rationale")?;
            for gate in &risk.unresolved_gates {
                validate_text(gate, "unresolved gate")?;
            }
        }
        for (i, repo) in self.repositories.iter().enumerate() {
            for (name, value) in [
                ("repository", &repo.repository),
                ("pull_request", &repo.pull_request),
                ("base_ref", &repo.base_ref),
                ("base_sha", &repo.base_sha),
                ("head_ref", &repo.head_ref),
                ("head_sha", &repo.head_sha),
            ] {
                validate_text(value, &format!("repositories[{i}].{name}"))?;
            }
            if let Some(url) = &repo.url {
                validate_safe_url(url)?;
            }
            for item in repo
                .checks
                .iter()
                .chain(&repo.review_receipts)
                .chain(&repo.merge_steps)
            {
                validate_text(item, "repository evidence")?;
            }
        }
        for (i, evidence) in self.evidence.iter().enumerate() {
            validate_text(&evidence.title, &format!("evidence[{i}].title"))?;
            validate_text(&evidence.body, &format!("evidence[{i}].body"))?;
        }
        for unknown in &self.unknowns {
            validate_text(unknown, "unknown")?;
        }
        Ok(())
    }
}

pub fn review_bundle_digest(bundle: &ReviewBundle) -> Result<Digest, String> {
    bundle.validate()?;
    let bytes = serde_json::to_vec(bundle).map_err(|err| err.to_string())?;
    Digest::parse(hex(&Sha256::digest(bytes)))
}

/// Render only escaped text and validated HTTPS links. There is no JavaScript, remote asset,
/// form, or command in this file; the user makes a decision through the host CLI.
pub fn render_review_html(request: &HumanRequest, bundle: &ReviewBundle) -> Result<String, String> {
    request.validate()?;
    bundle.validate()?;
    if request.subject.bundle_digest != review_bundle_digest(bundle)? {
        return Err("review bundle digest does not match human request".into());
    }

    let mut html = String::with_capacity(8192);
    html.push_str("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">");
    html.push_str("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
    html.push_str("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; script-src 'none'\">");
    html.push_str("<title>");
    escape_into(&mut html, &bundle.title);
    html.push_str("</title>");
    html.push_str("<style>body{font:16px/1.55 system-ui,sans-serif;max-width:1000px;margin:2rem auto;padding:0 1rem;color:#20252b}article,section{border:1px solid #ccd2d8;border-radius:8px;padding:1rem;margin:1rem 0}code,pre{overflow-wrap:anywhere}pre{white-space:pre-wrap;background:#f4f6f8;padding:1rem}.meta{color:#53606b}.warning{border-left:4px solid #ba6b00;padding-left:1rem}</style></head><body>");
    html.push_str("<header><h1>");
    escape_into(&mut html, &bundle.title);
    html.push_str("</h1><p class=\"meta\">Request ");
    escape_into(&mut html, request.request_id.as_str());
    html.push_str(" · ");
    escape_into(&mut html, &format!("{:?}", request.kind));
    html.push_str(" · expires ");
    write!(html, "{}", request.expires_at).unwrap();
    html.push_str("</p><p>");
    escape_into(&mut html, &request.question);
    html.push_str("</p><p class=\"meta\">Project ");
    escape_into(&mut html, request.subject.project_id.as_str());
    html.push_str(" · ticket ");
    escape_into(&mut html, request.subject.ticket_id.as_str());
    html.push_str(" · run ");
    escape_into(&mut html, request.subject.ticket_run_id.as_str());
    html.push_str("</p></header>");
    html.push_str("<section><h2>Summary</h2><pre>");
    escape_into(&mut html, &bundle.summary);
    html.push_str("</pre></section>");
    if let Some(risk) = &bundle.risk {
        html.push_str("<section><h2>Risk assessment</h2><p>Rating ");
        write!(html, "{}", risk.rating).unwrap();
        html.push_str(" / 4 · confidence ");
        escape_into(&mut html, &format!("{:?}", risk.confidence));
        html.push_str("</p><pre>");
        escape_into(&mut html, &risk.rationale);
        html.push_str("</pre>");
        render_list(&mut html, "Unresolved gates", &risk.unresolved_gates);
        html.push_str("</section>");
    }
    html.push_str("<section><h2>Repositories and exact revisions</h2>");
    for repo in &bundle.repositories {
        html.push_str("<article><h3>");
        escape_into(&mut html, &repo.repository);
        html.push_str(" — ");
        if let Some(url) = &repo.url {
            html.push_str("<a rel=\"noopener noreferrer\" href=\"");
            escape_into(&mut html, url);
            html.push_str("\">");
            escape_into(&mut html, &repo.pull_request);
            html.push_str("</a>");
        } else {
            escape_into(&mut html, &repo.pull_request);
        }
        html.push_str("</h3><p>Base <code>");
        escape_into(&mut html, &repo.base_ref);
        html.push_str(" @ <code>");
        escape_into(&mut html, &repo.base_sha);
        html.push_str("</code>; head <code>");
        escape_into(&mut html, &repo.head_ref);
        html.push_str(" @ <code>");
        escape_into(&mut html, &repo.head_sha);
        html.push_str("</code></p>");
        render_list(&mut html, "Checks", &repo.checks);
        render_list(&mut html, "Review receipts", &repo.review_receipts);
        render_list(&mut html, "Typed merge steps", &repo.merge_steps);
        html.push_str("</article>");
    }
    html.push_str("</section><section><h2>Evidence</h2>");
    for item in &bundle.evidence {
        html.push_str("<article><h3>");
        escape_into(&mut html, &item.title);
        html.push_str("</h3>");
        if item.truncated {
            html.push_str("<p class=\"warning\">This evidence is truncated. Consult the full artifact before deciding.</p>");
        }
        html.push_str("<pre>");
        escape_into(&mut html, &item.body);
        html.push_str("</pre></article>");
    }
    html.push_str("</section><section><h2>Unknowns and residual risks</h2>");
    render_list(&mut html, "Unresolved", &bundle.unknowns);
    html.push_str("</section><section><h2>Decision</h2><p>Choose through <code>rex-projects human respond</code> using this request ID and current subject digest. Opening this page does not record approval.</p><ul>");
    for choice in &request.choices {
        html.push_str("<li><code>");
        escape_into(&mut html, choice_name(*choice));
        html.push_str("</code></li>");
    }
    html.push_str("</ul><p>Subject digest: <code>");
    escape_into(&mut html, &subject_digest(&request.subject).to_string());
    html.push_str("</code></p></section></body></html>");
    Ok(html)
}

/// Persist a private, immutable review bundle under an already-created private state directory.
/// A request directory is create-only, so a repeated or stale request can never overwrite the
/// artifact used by an earlier decision. The caller persists the HumanRequest before calling this.
pub fn write_local_review_artifact(
    root: &Path,
    request: &HumanRequest,
    bundle: &ReviewBundle,
) -> io::Result<PathBuf> {
    let html = render_review_html(request, bundle)
        .map_err(|message| io::Error::new(io::ErrorKind::InvalidInput, message))?;
    let root = fs::canonicalize(root)?;
    let metadata = fs::symlink_metadata(&root)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "artifact root must be a real directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "artifact root must not be accessible by group or other users",
            ));
        }
    }

    // HumanRequestId is an opaque external identifier and may contain path separators.
    let target = root.join(hex(&Sha256::digest(request.request_id.as_str().as_bytes())));
    create_private_directory(&target)?;
    write_private_file(
        &target.join("manifest.json"),
        &serde_json::to_vec_pretty(request).map_err(io::Error::other)?,
    )?;
    let mut summary = String::new();
    writeln!(summary, "# {}\n", bundle.title).unwrap();
    writeln!(summary, "Request: {}\n", request.request_id).unwrap();
    writeln!(summary, "{}\n", bundle.summary).unwrap();
    writeln!(
        summary,
        "Subject digest: {}\n",
        subject_digest(&request.subject)
    )
    .unwrap();
    write_private_file(&target.join("summary.md"), summary.as_bytes())?;
    write_private_file(&target.join("review.html"), html.as_bytes())?;
    File::open(&target)?.sync_all()?;
    File::open(&root)?.sync_all()?;
    Ok(target.join("review.html"))
}

fn create_private_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700).create(path)?;
    }
    #[cfg(not(unix))]
    fs::create_dir(path)?;
    Ok(())
}

fn write_private_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(bytes)?;
        file.sync_all()
    }
    #[cfg(not(unix))]
    {
        let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
        file.write_all(bytes)?;
        file.sync_all()
    }
}

fn render_list(html: &mut String, title: &str, items: &[String]) {
    html.push_str("<h4>");
    escape_into(html, title);
    html.push_str("</h4><ul>");
    for item in items {
        html.push_str("<li>");
        escape_into(html, item);
        html.push_str("</li>");
    }
    html.push_str("</ul>");
}

fn escape_into(out: &mut String, text: &str) {
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
}

fn validate_text(text: &str, field: &str) -> Result<(), String> {
    if text.len() > MAX_REVIEW_TEXT_BYTES || text.chars().any(|ch| ch == '\0') {
        return Err(format!("{field} is too large or contains NUL"));
    }
    Ok(())
}

pub(crate) fn validate_safe_url(url: &str) -> Result<(), String> {
    validate_text(url, "URL")?;
    if url.chars().any(char::is_whitespace) || url.contains('\\') {
        return Err("review link contains whitespace or a backslash".into());
    }
    let Some(rest) = url.strip_prefix("https://") else {
        return Err("review links must use https".into());
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.is_empty()
        || authority.contains('@')
        || authority.starts_with('.')
        || !authority.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':' | b'[' | b']')
        })
    {
        return Err("review link has an invalid authority".into());
    }
    Ok(())
}

fn choice_name(choice: HumanChoice) -> &'static str {
    match choice {
        HumanChoice::Approve => "approve",
        HumanChoice::RequestChanges => "request_changes",
        HumanChoice::RevisePlan => "revise_plan",
        HumanChoice::Defer => "defer",
        HumanChoice::Cancel => "cancel",
    }
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0xf) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::ResponseEnvelope;

    fn digest(ch: char) -> Digest {
        Digest::parse(ch.to_string().repeat(64)).unwrap()
    }
    fn sample() -> (HumanRequest, ReviewBundle) {
        let mut bundle = ReviewBundle {
            title: "Review <script>alert(1)</script>".into(),
            summary: "Safe <img src=x onerror=alert(1)> summary".into(),
            risk: Some(ReviewRisk {
                rating: 2,
                confidence: RiskConfidence::Medium,
                rationale: "Limited cross-module risk".into(),
                unresolved_gates: vec!["Human confirms release order".into()],
            }),
            repositories: vec![RepositoryReview {
                repository: "example/repo".into(),
                pull_request: "PR #4".into(),
                url: Some("https://example.test/pull/4?a=1&b=2".into()),
                base_ref: "main".into(),
                base_sha: "a".repeat(40),
                head_ref: "feature".into(),
                head_sha: "b".repeat(40),
                checks: vec!["test: success".into()],
                review_receipts: vec!["Reviewer found no blocker".into()],
                merge_steps: vec!["update body, then request merge".into()],
            }],
            evidence: vec![ReviewEvidence {
                title: "Diff".into(),
                body: "<script>bad()</script>".into(),
                truncated: true,
            }],
            unknowns: vec!["Deployment result not yet known".into()],
        };
        let bd = review_bundle_digest(&bundle).unwrap();
        let request = HumanRequest {
            request_id: HumanRequestId::parse("human-1").unwrap(),
            kind: HumanRequestKind::ChangeReview,
            subject: ReviewSubject {
                project_id: ProjectId::parse("p1").unwrap(),
                ticket_id: TicketId::parse("PAY-1").unwrap(),
                ticket_run_id: TicketRunId::parse("run-1").unwrap(),
                ticket_revision: Revision(4),
                repository_heads_digest: digest('c'),
                policy_digest: digest('d'),
                bundle_digest: bd,
            },
            question: "May this change be merged?".into(),
            choices: vec![
                HumanChoice::Approve,
                HumanChoice::RequestChanges,
                HumanChoice::Defer,
                HumanChoice::Cancel,
            ],
            expires_at: 500,
        };
        bundle.title.shrink_to_fit();
        (request, bundle)
    }

    #[test]
    fn human_present_envelope_leaves_agent_only_context_empty() {
        let (request, bundle) = sample();
        let params = HumanPresentParams {
            request_id: request.request_id.clone(),
            kind: request.kind,
            subject: request.subject.clone(),
            subject_digest: subject_digest(&request.subject),
            bundle_digest: request.subject.bundle_digest.clone(),
            bundle_path: "/private/review.html".into(),
            summary_markdown: bundle.summary,
            question: request.question,
            choices: request.choices,
            expires_at: request.expires_at,
            response_command: "rex-projects human respond".into(),
        };
        let envelope = human_present_envelope(
            ProtocolRequestId::new("call-1").unwrap(),
            request.subject.project_id,
            params,
        );
        assert!(envelope.run_id.is_none());
        assert!(envelope.attempt.is_none());
        assert!(envelope.run_epoch.is_none());
        assert!(envelope.expected_subject_revision.is_none());
        assert!(envelope.role.is_none());
        assert!(envelope.request_type.is_none());
    }

    #[test]
    fn html_escapes_untrusted_content_and_disables_active_content() {
        let (request, bundle) = sample();
        let html = render_review_html(&request, &bundle).unwrap();
        assert!(html.contains("&lt;script&gt;"));
        assert!(!html.contains("<script>"));
        assert!(!html.contains("<img src=x onerror="));
        assert!(html.contains("script-src 'none'"));
        assert!(html.contains("Opening this page does not record approval"));
        assert!(html.contains("https://example.test/pull/4?a=1&amp;b=2"));
    }

    #[test]
    fn dangerous_or_credential_bearing_links_are_rejected() {
        for url in [
            "javascript:alert(1)",
            "http://example.test/",
            "https://user:pass@example.test/x",
        ] {
            let mut bundle = sample().1;
            bundle.repositories[0].url = Some(url.into());
            assert!(bundle.validate().is_err(), "accepted {url}");
        }
    }

    #[test]
    fn decision_requires_current_whole_subject_expiry_and_offered_choice() {
        let (request, _) = sample();
        let input = HumanDecisionInput {
            request_id: request.request_id.clone(),
            expected_subject_digest: subject_digest(&request.subject),
            response_id: "answer-1".into(),
            choice: HumanChoice::Approve,
            explanation: None,
        };
        assert_eq!(
            validate_decision(&request, &request.subject, &input, 499),
            DecisionValidation::Accepted
        );
        assert_eq!(
            validate_decision(&request, &request.subject, &input, 500),
            DecisionValidation::Expired
        );
        let mut changed = request.subject.clone();
        changed.policy_digest = digest('e');
        assert_eq!(
            validate_decision(&request, &changed, &input, 400),
            DecisionValidation::StaleSubject
        );
        let mut unoffered = input.clone();
        unoffered.choice = HumanChoice::RevisePlan;
        assert_eq!(
            validate_decision(&request, &request.subject, &unoffered, 400),
            DecisionValidation::ChoiceNotOffered
        );
    }

    #[test]
    fn malformed_request_cannot_authorize_a_choice_invalid_for_its_kind() {
        let (mut request, _) = sample();
        request.choices = vec![HumanChoice::RevisePlan];
        assert!(request.validate().is_err());
        let input = HumanDecisionInput {
            request_id: request.request_id.clone(),
            expected_subject_digest: subject_digest(&request.subject),
            response_id: "answer-invalid-kind".into(),
            choice: HumanChoice::RevisePlan,
            explanation: None,
        };
        assert_eq!(
            validate_decision(&request, &request.subject, &input, 400),
            DecisionValidation::InvalidRequest
        );
    }

    #[test]
    fn response_replay_only_matches_identical_content() {
        let (request, _) = sample();
        let one = HumanDecisionInput {
            request_id: request.request_id,
            expected_subject_digest: subject_digest(&request.subject),
            response_id: "same-id".into(),
            choice: HumanChoice::Approve,
            explanation: None,
        };
        let mut replay = one.clone();
        assert!(response_replay_matches(&one, &replay));
        replay.explanation = Some("changed".into());
        assert!(!response_replay_matches(&one, &replay));
    }

    #[test]
    fn marked_factory_children_are_rejected_before_host_mutation() {
        assert!(reject_factory_child_context([("REX_PROJECTS_AGENT", "1")]).is_err());
        assert!(reject_factory_child_context([("REX_PROJECTS_CONTEXT", "project=p1")]).is_err());
        assert!(reject_factory_child_context([("REX_PROJECTS_CONTEXT", "")]).is_ok());
        assert!(reject_factory_child_context([("PATH", "/bin")]).is_ok());
    }

    #[test]
    fn render_rejects_empty_and_oversized_evidence_and_stale_bundle_digest() {
        let (mut request, mut bundle) = sample();
        bundle.evidence[0].body = "x".repeat(MAX_REVIEW_TEXT_BYTES + 1);
        assert!(render_review_html(&request, &bundle).is_err());
        bundle.evidence[0].body = "changed".into();
        assert!(render_review_html(&request, &bundle).is_err());
        request.subject.bundle_digest = review_bundle_digest(&bundle).unwrap();
        assert!(render_review_html(&request, &bundle).is_ok());
    }

    #[test]
    fn local_artifact_is_private_immutable_and_uses_safe_path_component() {
        let temp = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let (mut request, bundle) = sample();
        request.request_id = HumanRequestId::parse("../../ticket-1").unwrap();
        request.subject.bundle_digest = review_bundle_digest(&bundle).unwrap();
        let html = write_local_review_artifact(temp.path(), &request, &bundle).unwrap();
        assert_eq!(html.file_name().unwrap(), "review.html");
        assert!(html.starts_with(fs::canonicalize(temp.path()).unwrap()));
        assert!(write_local_review_artifact(temp.path(), &request, &bundle).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&html).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(html.parent().unwrap())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
    }

    #[test]
    fn configured_presenter_reference_is_tied_to_request_and_cannot_decide() {
        let (request, _) = sample();
        let protocol_id = ProtocolRequestId::new("call-1").unwrap();
        let response = ResponseEnvelope {
            schema_version: SCHEMA_VERSION,
            request_id: ProtocolRequestId::new("call-1").unwrap(),
            result: Some(PresentedReference {
                reference: "review-42".into(),
                location: Some("https://reviews.example.test/42".into()),
                request_id: request.request_id.clone(),
                subject_digest: subject_digest(&request.subject),
                bundle_digest: request.subject.bundle_digest.clone(),
            }),
            error: None,
            extensions: Default::default(),
        };
        let json = serde_json::to_vec(&response).unwrap();
        assert!(parse_presented_reference(&json, &protocol_id, &request).is_ok());
        let duplicate_key = br#"{"schema_version":1,"request_id":"call-1","request_id":"call-1","result":{"reference":"r","request_id":"human-1","subject_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","bundle_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"error":null,"extensions":{}}"#;
        assert!(parse_presented_reference(duplicate_key, &protocol_id, &request).is_err());
        let mut stale = response;
        stale.result.as_mut().unwrap().bundle_digest = digest('f');
        assert!(
            parse_presented_reference(&serde_json::to_vec(&stale).unwrap(), &protocol_id, &request)
                .is_err()
        );
    }

    #[test]
    fn dashboard_focus_is_typed_and_rejects_control_text() {
        let focus = RexFocusTarget {
            window_id: "window-12".into(),
            block_id: Some("block-3".into()),
        };
        assert!(focus.validate().is_ok());
        let malformed = RexFocusTarget {
            window_id: "window-12\nrex send approve".into(),
            block_id: None,
        };
        assert!(malformed.validate().is_err());
    }
}
