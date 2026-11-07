//! Host-side lifecycle and presenter payloads for durable human decisions.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::domain::ids::{Digest, HumanRequestId, ProjectId, Revision, TicketRunId};
use crate::human::{ReviewBundle, review_bundle_digest};
use crate::protocol::{
    MethodName, ProtocolError, RequestEnvelope, RequestId as ProtocolRequestId, SCHEMA_VERSION,
    parse_unique,
};

pub const MAX_HUMAN_REQUEST_BYTES: usize = 1_048_576;

#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum HumanSubjectKind {
    TicketRun,
    Plan,
    Operation,
    Profile,
    Goal,
    ProjectConfiguration,
    Release,
}

#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum HumanPurpose {
    PlanDecision,
    TicketReview,
    OperationApproval,
    ProfilePromotion,
    GoalChange,
    GoalCompletion,
    ProjectConfiguration,
    ReleaseDecision,
}

#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum HumanDecisionChoice {
    Approve,
    RequestChanges,
    RevisePlan,
    Defer,
    Cancel,
    Refuse,
}

impl HumanPurpose {
    pub fn subject_kind(self) -> HumanSubjectKind {
        match self {
            Self::PlanDecision => HumanSubjectKind::Plan,
            Self::TicketReview => HumanSubjectKind::TicketRun,
            Self::OperationApproval => HumanSubjectKind::Operation,
            Self::ProfilePromotion => HumanSubjectKind::Profile,
            Self::GoalChange | Self::GoalCompletion => HumanSubjectKind::Goal,
            Self::ProjectConfiguration => HumanSubjectKind::ProjectConfiguration,
            Self::ReleaseDecision => HumanSubjectKind::Release,
        }
    }

    pub fn allows(self, choice: HumanDecisionChoice) -> bool {
        match self {
            Self::PlanDecision => matches!(
                choice,
                HumanDecisionChoice::Approve
                    | HumanDecisionChoice::RevisePlan
                    | HumanDecisionChoice::Defer
                    | HumanDecisionChoice::Cancel
            ),
            Self::TicketReview | Self::GoalCompletion => matches!(
                choice,
                HumanDecisionChoice::Approve
                    | HumanDecisionChoice::RequestChanges
                    | HumanDecisionChoice::Defer
                    | HumanDecisionChoice::Cancel
            ),
            Self::OperationApproval
            | Self::ProfilePromotion
            | Self::ProjectConfiguration
            | Self::ReleaseDecision => matches!(
                choice,
                HumanDecisionChoice::Approve
                    | HumanDecisionChoice::Refuse
                    | HumanDecisionChoice::Defer
            ),
            Self::GoalChange => matches!(
                choice,
                HumanDecisionChoice::Approve
                    | HumanDecisionChoice::Refuse
                    | HumanDecisionChoice::RevisePlan
            ),
        }
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanSubjectBinding {
    pub project_id: ProjectId,
    pub kind: HumanSubjectKind,
    /// Stable ID from the typed domain object. Never interpreted as a path or command.
    pub subject_id: String,
    pub revision: Revision,
    /// Digest of the complete subject material, including immutable object identity.
    pub material_digest: Digest,
    pub configuration_digest: Digest,
    pub policy_digest: Digest,
    pub bundle_digest: Digest,
}

#[derive(Serialize)]
struct SubjectDigestMaterial<'a> {
    project_id: &'a ProjectId,
    kind: HumanSubjectKind,
    subject_id: &'a str,
    revision: Revision,
    material_digest: &'a Digest,
    configuration_digest: &'a Digest,
    policy_digest: &'a Digest,
    bundle_digest: &'a Digest,
}

impl HumanSubjectBinding {
    pub fn digest(&self) -> Result<Digest, String> {
        self.validate()?;
        let bytes = serde_json::to_vec(&SubjectDigestMaterial {
            project_id: &self.project_id,
            kind: self.kind,
            subject_id: &self.subject_id,
            revision: self.revision,
            material_digest: &self.material_digest,
            configuration_digest: &self.configuration_digest,
            policy_digest: &self.policy_digest,
            bundle_digest: &self.bundle_digest,
        })
        .map_err(|error| error.to_string())?;
        Digest::parse(hex(&Sha256::digest(bytes)))
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.kind == HumanSubjectKind::TicketRun {
            TicketRunId::parse(self.subject_id.clone())?;
        } else if self.subject_id.is_empty()
            || self.subject_id.len() > 512
            || self.subject_id.chars().any(char::is_control)
        {
            return Err("subject_id must contain 1 to 512 non-control bytes".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanRuntimeRequest {
    pub request_id: HumanRequestId,
    pub purpose: HumanPurpose,
    pub subject: HumanSubjectBinding,
    pub question: String,
    pub choices: Vec<HumanDecisionChoice>,
    pub expires_at_unix: u64,
    pub review_bundle: ReviewBundle,
}

impl HumanRuntimeRequest {
    pub fn subject_digest(&self) -> Result<Digest, String> {
        self.subject.digest()
    }

    pub fn validate(&self, now: u64) -> Result<(), String> {
        self.subject.validate()?;
        if self.subject.kind != self.purpose.subject_kind() {
            return Err("human purpose does not match subject kind".into());
        }
        if self.question.trim().is_empty() || self.question.len() > MAX_HUMAN_REQUEST_BYTES {
            return Err("human question must be nonempty and bounded".into());
        }
        if self.expires_at_unix <= now {
            return Err("human request expiry must be in the future".into());
        }
        if self.choices.is_empty() || self.choices.len() > 6 {
            return Err("human request must offer between one and six choices".into());
        }
        let mut unique = BTreeSet::new();
        for choice in &self.choices {
            if !self.purpose.allows(*choice) {
                return Err(format!(
                    "choice {choice:?} is not valid for {:?}",
                    self.purpose
                ));
            }
            if !unique.insert(*choice) {
                return Err("human choices must be unique".into());
            }
        }
        let bundle_digest = review_bundle_digest(&self.review_bundle)?;
        if bundle_digest != self.subject.bundle_digest {
            return Err("review bundle digest does not match the bound subject".into());
        }
        let encoded = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        if encoded.len() > MAX_HUMAN_REQUEST_BYTES {
            return Err("human request exceeds the configured size limit".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanDecisionIntent {
    pub response_id: String,
    pub request_id: HumanRequestId,
    pub expected_subject_digest: Digest,
    pub choice: HumanDecisionChoice,
    #[serde(default)]
    pub explanation: Option<String>,
}

impl HumanDecisionIntent {
    pub fn validate(&self) -> Result<(), String> {
        if self.response_id.is_empty()
            || self.response_id.len() > 255
            || self.response_id.chars().any(char::is_control)
        {
            return Err("response_id must contain 1 to 255 non-control bytes".into());
        }
        if let Some(explanation) = &self.explanation
            && explanation.len() > 65_536
        {
            return Err("decision explanation exceeds the size limit".into());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HumanRequestLifecycle {
    Pending,
    Presented,
    ResponseQueued,
    Decided,
    Stale,
    Expired,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HumanWakeTarget {
    Coordinator,
    Supervisor,
    Operator,
}

impl HumanRuntimeRequest {
    pub fn wake_target(&self) -> HumanWakeTarget {
        match self.purpose {
            HumanPurpose::GoalChange
            | HumanPurpose::GoalCompletion
            | HumanPurpose::ProfilePromotion
            | HumanPurpose::ProjectConfiguration => HumanWakeTarget::Supervisor,
            HumanPurpose::OperationApproval | HumanPurpose::ReleaseDecision => {
                HumanWakeTarget::Operator
            }
            _ => HumanWakeTarget::Coordinator,
        }
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanRequestSummary {
    pub request: HumanRuntimeRequest,
    pub lifecycle: HumanRequestLifecycle,
    pub bundle_path: String,
    pub presentation_reference: Option<String>,
}

/// Versioned command-presenter payload. Presenters may return a display reference, but never a
/// decision; authoritative decisions arrive only through `human respond` and controller checks.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanRuntimePresentParams {
    pub request_id: HumanRequestId,
    pub purpose: HumanPurpose,
    pub subject: HumanSubjectBinding,
    pub subject_digest: Digest,
    pub bundle_digest: Digest,
    pub bundle_path: String,
    pub summary_markdown: String,
    pub question: String,
    pub choices: Vec<HumanDecisionChoice>,
    pub expires_at: u64,
    pub response_command: String,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanRuntimePresentedReference {
    pub reference: String,
    #[serde(default)]
    pub location: Option<String>,
    pub request_id: HumanRequestId,
    pub subject_digest: Digest,
    pub bundle_digest: Digest,
}

#[derive(Clone, Debug, JsonSchema, Deserialize)]
#[serde(deny_unknown_fields)]
struct HumanRuntimePresenterResponse {
    schema_version: u32,
    request_id: ProtocolRequestId,
    #[serde(default)]
    result: Option<HumanRuntimePresentedReference>,
    #[serde(default)]
    error: Option<ProtocolError>,
    #[serde(default)]
    extensions: std::collections::BTreeMap<String, serde_json::Value>,
}

pub fn human_runtime_present_envelope(
    protocol_request_id: ProtocolRequestId,
    request: &HumanRuntimeRequest,
    bundle_path: String,
    response_command: String,
) -> Result<RequestEnvelope<HumanRuntimePresentParams>, String> {
    request.validate(request.expires_at_unix.saturating_sub(1))?;
    if bundle_path.is_empty()
        || bundle_path.len() > 4096
        || bundle_path.chars().any(char::is_control)
        || response_command.is_empty()
        || response_command.len() > 4096
    {
        return Err(
            "human presenter path and response command must be bounded and nonempty".into(),
        );
    }
    let subject_digest = request.subject.digest()?;
    let params = HumanRuntimePresentParams {
        request_id: request.request_id.clone(),
        purpose: request.purpose,
        subject: request.subject.clone(),
        subject_digest,
        bundle_digest: request.subject.bundle_digest.clone(),
        bundle_path,
        summary_markdown: format!(
            "# {}\n\n{}",
            request.review_bundle.title, request.review_bundle.summary
        ),
        question: request.question.clone(),
        choices: request.choices.clone(),
        expires_at: request.expires_at_unix,
        response_command,
    };
    let envelope = RequestEnvelope {
        schema_version: SCHEMA_VERSION,
        request_id: protocol_request_id,
        operation_id: None,
        method: MethodName::new("human.present").expect("static method is valid"),
        project_id: Some(request.subject.project_id.clone()),
        run_id: None,
        attempt: None,
        run_epoch: None,
        expected_subject_revision: Some(request.subject.revision.0),
        role: None,
        request_type: None,
        params,
    };
    envelope.validate()?;
    let encoded = serde_json::to_vec(&envelope).map_err(|error| error.to_string())?;
    if encoded.len() > MAX_HUMAN_REQUEST_BYTES {
        return Err("human presenter request exceeds size limit".into());
    }
    Ok(envelope)
}

pub fn parse_runtime_presenter_reference(
    bytes: &[u8],
    protocol_request_id: &ProtocolRequestId,
    request: &HumanRuntimeRequest,
) -> Result<HumanRuntimePresentedReference, String> {
    if bytes.len() > 65_536 {
        return Err("human presenter response exceeds size limit".into());
    }
    let response: HumanRuntimePresenterResponse = parse_unique(bytes)?;
    let _extensions = &response.extensions;
    if response.schema_version != SCHEMA_VERSION {
        return Err("unsupported human presenter response schema version".into());
    }
    if &response.request_id != protocol_request_id {
        return Err("human presenter response request ID does not match".into());
    }
    if response.result.is_some() == response.error.is_some() {
        return Err("human presenter response must contain exactly one result or error".into());
    }
    let result = response
        .result
        .ok_or_else(|| "human presenter reported an error".to_owned())?;
    if let Some(location) = &result.location {
        crate::human::validate_safe_url(location)?;
    }
    if result.request_id != request.request_id
        || result.subject_digest != request.subject.digest()?
        || result.bundle_digest != request.subject.bundle_digest
        || result.reference.is_empty()
        || result.reference.len() > 4096
        || result.reference.chars().any(char::is_control)
        || result
            .location
            .as_ref()
            .is_some_and(|location| location.len() > 4096 || location.chars().any(char::is_control))
    {
        return Err("human presenter reference does not match the current request".into());
    }
    Ok(result)
}

/// Execute a configured presenter as a bounded host child. Presenter output can prove only that
/// a review artifact was presented; it never carries an authoritative decision.
pub fn run_command_presenter(
    command: &[String],
    environment: &std::collections::BTreeMap<OsString, OsString>,
    protocol_request_id: ProtocolRequestId,
    request: &HumanRuntimeRequest,
    bundle_path: String,
) -> Result<HumanRuntimePresentedReference, String> {
    if command.is_empty() || command.iter().any(String::is_empty) {
        return Err("human command presenter argv must be nonempty".into());
    }
    let executable = resolve_human_child(&command[0], environment)?;
    let response_command = format!(
        "rex-projects human respond {} --subject-digest {} --choice <choice> --explanation <text>",
        request.request_id,
        request.subject.digest()?
    );
    let envelope = human_runtime_present_envelope(
        protocol_request_id.clone(),
        request,
        bundle_path,
        response_command,
    )?;
    let stdin = serde_json::to_vec(&envelope).map_err(|error| error.to_string())?;
    let output = crate::process::run(crate::process::ProcessRequest {
        executable,
        args: command[1..].iter().map(OsString::from).collect(),
        stdin,
        cwd: None,
        clear_environment: true,
        environment: environment.clone(),
        timeout: Duration::from_secs(60),
        shutdown_grace: Duration::from_secs(2),
        stdout_limit: 65_536,
        stderr_tail_limit: 4096,
    })
    .map_err(|error| error.to_string())?;
    if output.timed_out || output.stdout_truncated || output.stderr_truncated {
        return Err("human presenter timed out or exceeded an output limit".into());
    }
    if !output
        .status
        .as_ref()
        .is_some_and(|status| status.success())
    {
        return Err("human presenter exited unsuccessfully".into());
    }
    parse_runtime_presenter_reference(&output.stdout, &protocol_request_id, request)
}

/// Open the local static review page using a configured argv. The path is appended as one
/// argument; no shell is involved and the page itself cannot record a decision.
pub fn open_runtime_review_html(
    opener: &[String],
    environment: &std::collections::BTreeMap<OsString, OsString>,
    html_path: &Path,
) -> Result<(), String> {
    if opener.is_empty() || opener.iter().any(String::is_empty) || !html_path.is_absolute() {
        return Err(
            "local human opener requires a nonempty argv and absolute artifact path".into(),
        );
    }
    let executable = resolve_human_child(&opener[0], environment)?;
    let mut args = opener[1..].iter().map(OsString::from).collect::<Vec<_>>();
    args.push(html_path.as_os_str().to_owned());
    let output = crate::process::run(crate::process::ProcessRequest {
        executable,
        args,
        stdin: Vec::new(),
        cwd: None,
        clear_environment: true,
        environment: environment.clone(),
        timeout: Duration::from_secs(30),
        shutdown_grace: Duration::from_secs(2),
        stdout_limit: 4096,
        stderr_tail_limit: 4096,
    })
    .map_err(|error| error.to_string())?;
    if output.timed_out
        || !output
            .status
            .as_ref()
            .is_some_and(|status| status.success())
    {
        return Err("configured local human opener failed".into());
    }
    Ok(())
}

fn resolve_human_child(
    program: &str,
    environment: &std::collections::BTreeMap<OsString, OsString>,
) -> Result<PathBuf, String> {
    let search_path = environment
        .get(&OsString::from("PATH"))
        .map(|path| std::env::split_paths(path).collect::<Vec<_>>())
        .unwrap_or_default();
    crate::process::resolve_executable(Path::new(program), &search_path).ok_or_else(|| {
        "configured human presenter/opener executable was not found in its child PATH".to_owned()
    })
}

/// Build a static, offline review page for all typed subject kinds. Approval is always entered
/// through the host CLI; loading or opening the page records no decision.
pub fn render_runtime_review_html(request: &HumanRuntimeRequest) -> Result<String, String> {
    request.validate(request.expires_at_unix.saturating_sub(1))?;
    let mut html = String::new();
    html.push_str("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">");
    html.push_str("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
    html.push_str("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; script-src 'none'\">");
    html.push_str("<title>");
    escape_into(&mut html, &request.review_bundle.title);
    html.push_str("</title>");
    html.push_str("<style>body{font:16px/1.55 system-ui,sans-serif;max-width:1000px;margin:2rem auto;padding:0 1rem;color:#20252b}article,section{border:1px solid #ccd2d8;border-radius:8px;padding:1rem;margin:1rem 0}pre,code{overflow-wrap:anywhere}pre{white-space:pre-wrap;background:#f4f6f8;padding:1rem}.warning{border-left:4px solid #ba6b00;padding-left:1rem}</style></head><body>");
    html.push_str("<header><h1>");
    escape_into(&mut html, &request.review_bundle.title);
    html.push_str("</h1><p>Request ");
    escape_into(&mut html, request.request_id.as_str());
    html.push_str(" · purpose ");
    escape_into(&mut html, &format!("{:?}", request.purpose));
    html.push_str(" · expires ");
    write!(html, "{}", request.expires_at_unix).unwrap();
    html.push_str("</p><p>");
    escape_into(&mut html, &request.question);
    html.push_str("</p><p>Project ");
    escape_into(&mut html, request.subject.project_id.as_str());
    html.push_str(" · ");
    escape_into(&mut html, &format!("{:?}", request.subject.kind));
    html.push(' ');
    escape_into(&mut html, &request.subject.subject_id);
    html.push_str(" · revision ");
    write!(html, "{}", request.subject.revision.0).unwrap();
    html.push_str("</p><p>Subject digest <code>");
    escape_into(&mut html, &request.subject_digest()?.to_string());
    html.push_str("</code></p></header>");
    html.push_str("<section><h2>Summary</h2><pre>");
    escape_into(&mut html, &request.review_bundle.summary);
    html.push_str("</pre></section>");
    if let Some(risk) = &request.review_bundle.risk {
        html.push_str("<section><h2>Risk</h2><p>Rating ");
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
    for repository in &request.review_bundle.repositories {
        html.push_str("<article><h3>");
        escape_into(&mut html, &repository.repository);
        html.push_str(" · ");
        if let Some(url) = &repository.url {
            html.push_str("<a rel=\"noopener noreferrer\" href=\"");
            escape_into(&mut html, url);
            html.push_str("\">");
            escape_into(&mut html, &repository.pull_request);
            html.push_str("</a>");
        } else {
            escape_into(&mut html, &repository.pull_request);
        }
        html.push_str("</h3><p>Base <code>");
        escape_into(&mut html, &repository.base_ref);
        html.push_str(" @ ");
        escape_into(&mut html, &repository.base_sha);
        html.push_str("</code>; head <code>");
        escape_into(&mut html, &repository.head_ref);
        html.push_str(" @ ");
        escape_into(&mut html, &repository.head_sha);
        html.push_str("</code></p>");
        render_list(&mut html, "Checks", &repository.checks);
        render_list(&mut html, "Review receipts", &repository.review_receipts);
        render_list(&mut html, "Typed merge steps", &repository.merge_steps);
        html.push_str("</article>");
    }
    html.push_str("</section><section><h2>Evidence</h2>");
    for evidence in &request.review_bundle.evidence {
        html.push_str("<article><h3>");
        escape_into(&mut html, &evidence.title);
        html.push_str("</h3>");
        if evidence.truncated {
            html.push_str("<p class=\"warning\">Evidence is truncated. Consult the full artifact before deciding.</p>");
        }
        html.push_str("<pre>");
        escape_into(&mut html, &evidence.body);
        html.push_str("</pre></article>");
    }
    html.push_str("</section><section><h2>Unknowns</h2>");
    render_list(&mut html, "Unresolved", &request.review_bundle.unknowns);
    html.push_str("</section><section><h2>Choices</h2><ul>");
    for choice in &request.choices {
        html.push_str("<li><code>");
        escape_into(&mut html, &format!("{choice:?}"));
        html.push_str("</code></li>");
    }
    html.push_str("</ul><p>Opening this page does not record a decision. Use <code>rex-projects human respond</code> with this request ID and subject digest.</p></section></body></html>");
    Ok(html)
}

pub fn write_runtime_review_artifact(
    root: &Path,
    request: &HumanRuntimeRequest,
) -> io::Result<PathBuf> {
    let html = render_runtime_review_html(request)
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
                "artifact root must be private",
            ));
        }
    }
    let directory = root.join(hex(&Sha256::digest(request.request_id.as_str().as_bytes())));
    create_private_dir(&directory)?;
    write_private_file(
        &directory.join("manifest.json"),
        &serde_json::to_vec_pretty(request).map_err(io::Error::other)?,
    )?;
    write_private_file(&directory.join("review.html"), html.as_bytes())?;
    let mut summary = String::new();
    writeln!(
        summary,
        "# {}\n\n{}",
        request.review_bundle.title, request.review_bundle.summary
    )
    .unwrap();
    write_private_file(&directory.join("summary.md"), summary.as_bytes())?;
    File::open(&directory)?.sync_all()?;
    File::open(&root)?.sync_all()?;
    Ok(directory.join("review.html"))
}

fn create_private_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        let mut builder = fs::DirBuilder::new();
        match builder.mode(0o700).create(path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let metadata = fs::symlink_metadata(path)?;
                if metadata.file_type().is_symlink()
                    || !metadata.is_dir()
                    || metadata.permissions().mode() & 0o077 != 0
                {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "existing artifact directory is not a private real directory",
                    ));
                }
            }
            Err(error) => return Err(error),
        }
    }
    #[cfg(not(unix))]
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(path)?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "existing artifact directory is not a real directory",
                ));
            }
        }
        Err(error) => return Err(error),
    }
    Ok(())
}

fn write_private_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        let mut file = match options.open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let metadata = fs::symlink_metadata(path)?;
                if metadata.file_type().is_symlink()
                    || !metadata.is_file()
                    || metadata.permissions().mode() & 0o077 != 0
                {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "existing review artifact is not a private regular file",
                    ));
                }
                let mut reader = OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(path)?;
                let mut existing = Vec::new();
                reader.read_to_end(&mut existing)?;
                if existing == bytes {
                    return Ok(());
                }
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "review artifact path already contains different request data",
                ));
            }
            Err(error) => return Err(error),
        };
        file.write_all(bytes)?;
        file.sync_all()
    }
    #[cfg(not(unix))]
    {
        let mut file = match OpenOptions::new().write(true).create_new(true).open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let metadata = fs::symlink_metadata(path)?;
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "existing review artifact is not a regular file",
                    ));
                }
                if fs::read(path)? == bytes {
                    return Ok(());
                }
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "review artifact path already contains different request data",
                ));
            }
            Err(error) => return Err(error),
        };
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

fn escape_into(html: &mut String, text: &str) {
    for character in text.chars() {
        match character {
            '&' => html.push_str("&amp;"),
            '<' => html.push_str("&lt;"),
            '>' => html.push_str("&gt;"),
            '"' => html.push_str("&quot;"),
            '\'' => html.push_str("&#39;"),
            _ => html.push(character),
        }
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
mod presenter_tests {
    use super::*;
    use crate::human::ReviewBundle;

    fn sample_request() -> HumanRuntimeRequest {
        let bundle = ReviewBundle {
            title: "Approve operation".into(),
            summary: "Deploy one target.".into(),
            risk: None,
            repositories: Vec::new(),
            evidence: Vec::new(),
            unknowns: vec!["final rollout timing".into()],
        };
        let subject = HumanSubjectBinding {
            project_id: ProjectId::parse("p1").unwrap(),
            kind: HumanSubjectKind::Operation,
            subject_id: "deploy-1".into(),
            revision: Revision(3),
            material_digest: Digest::parse("a".repeat(64)).unwrap(),
            configuration_digest: Digest::parse("b".repeat(64)).unwrap(),
            policy_digest: Digest::parse("c".repeat(64)).unwrap(),
            bundle_digest: review_bundle_digest(&bundle).unwrap(),
        };
        HumanRuntimeRequest {
            request_id: HumanRequestId::parse("human-1").unwrap(),
            purpose: HumanPurpose::OperationApproval,
            subject,
            question: "Run the deploy?".into(),
            choices: vec![
                HumanDecisionChoice::Approve,
                HumanDecisionChoice::Refuse,
                HumanDecisionChoice::Defer,
            ],
            expires_at_unix: 100,
            review_bundle: bundle,
        }
    }

    #[test]
    fn generic_command_presenter_is_bound_to_complete_subject_and_can_only_present() {
        let request = sample_request();
        let protocol_id = ProtocolRequestId::new("protocol-1").unwrap();
        let envelope = human_runtime_present_envelope(
            protocol_id.clone(),
            &request,
            "/private/review.html".into(),
            "rex-projects human respond human-1 --subject-digest <digest>".into(),
        )
        .unwrap();
        assert_eq!(
            serde_json::to_value(&envelope).unwrap()["method"],
            "human.present"
        );
        assert_eq!(envelope.params.purpose, HumanPurpose::OperationApproval);
        assert_eq!(
            envelope.params.subject_digest,
            request.subject.digest().unwrap()
        );
        assert_eq!(envelope.expected_subject_revision, Some(3));

        let reference = HumanRuntimePresentedReference {
            reference: "reviewer-42".into(),
            location: Some("https://reviews.example/request/42".into()),
            request_id: request.request_id.clone(),
            subject_digest: request.subject.digest().unwrap(),
            bundle_digest: request.subject.bundle_digest.clone(),
        };
        let response = serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "request_id": protocol_id.as_str(),
            "result": reference,
            "error": null,
            "extensions": {}
        });
        let bytes = serde_json::to_vec(&response).unwrap();
        assert_eq!(
            parse_runtime_presenter_reference(&bytes, &protocol_id, &request).unwrap(),
            serde_json::from_value(response["result"].clone()).unwrap()
        );
        let mut forged = response;
        forged["result"]["subject_digest"] = serde_json::json!("d".repeat(64));
        let forged = serde_json::to_vec(&forged).unwrap();
        assert!(parse_runtime_presenter_reference(&forged, &protocol_id, &request).is_err());
        let mut unsafe_location: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        unsafe_location["result"]["location"] = serde_json::json!("javascript:alert(1)");
        let unsafe_location = serde_json::to_vec(&unsafe_location).unwrap();
        assert!(
            parse_runtime_presenter_reference(&unsafe_location, &protocol_id, &request).is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn presenter_binary_resolution_uses_the_explicit_child_path() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let bin = temp.path().join("login shell bin");
        std::fs::create_dir(&bin).unwrap();
        let executable = bin.join("review presenter");
        std::fs::write(&executable, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let environment = std::collections::BTreeMap::from([(
            OsString::from("PATH"),
            bin.as_os_str().to_owned(),
        )]);
        assert_eq!(
            resolve_human_child("review presenter", &environment).unwrap(),
            executable.canonicalize().unwrap()
        );
    }
}
