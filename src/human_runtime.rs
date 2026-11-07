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
use crate::effects::{
    EffectContext, EffectHandler, EffectKind, EffectMode, EffectObservation, EffectRequest,
};
use crate::engine::orchestration::{
    AgentAssertion, HumanRequestPayload, RoleArtifactReference, RoleResultBinding,
};
use crate::human::{ReviewBundle, ReviewEvidence, review_bundle_digest};
use crate::protocol::{
    MethodName, ProtocolError, RequestEnvelope, RequestId as ProtocolRequestId, SCHEMA_VERSION,
    parse_unique,
};

pub const MAX_HUMAN_REQUEST_BYTES: usize = 1_048_576;
pub const MAX_HUMAN_RESPONSE_BATCH: usize = 64;

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
    Publication,
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
    ProfileTrial,
    GoalChange,
    GoalCompletion,
    PublicationAdoption,
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
            Self::ProfilePromotion | Self::ProfileTrial => HumanSubjectKind::Profile,
            Self::GoalChange | Self::GoalCompletion => HumanSubjectKind::Goal,
            Self::PublicationAdoption => HumanSubjectKind::Publication,
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
            | Self::ProfileTrial
            | Self::PublicationAdoption
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
    /// Owning ticket scope for ticket-scoped operations.
    #[serde(default)]
    pub ticket_run_id: Option<TicketRunId>,
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
    ticket_run_id: &'a Option<TicketRunId>,
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
            ticket_run_id: &self.ticket_run_id,
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
            let ticket_run = TicketRunId::parse(self.subject_id.clone())?;
            if self
                .ticket_run_id
                .as_ref()
                .is_some_and(|bound| bound != &ticket_run)
            {
                return Err(
                    "ticket subject's explicit ticket_run_id does not match subject_id".into(),
                );
            }
        } else if self.subject_id.is_empty()
            || self.subject_id.len() > 512
            || self.subject_id.chars().any(char::is_control)
        {
            return Err("subject_id must contain 1 to 512 non-control bytes".into());
        }
        if matches!(
            self.kind,
            HumanSubjectKind::Operation | HumanSubjectKind::Plan | HumanSubjectKind::Publication
        ) && self.ticket_run_id.is_none()
        {
            return Err(
                "ticket-scoped human decisions must bind their owning ticket_run_id".into(),
            );
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
            | HumanPurpose::ProfileTrial
            | HumanPurpose::ProjectConfiguration => HumanWakeTarget::Supervisor,
            HumanPurpose::OperationApproval | HumanPurpose::ReleaseDecision => {
                HumanWakeTarget::Operator
            }
            HumanPurpose::PublicationAdoption => HumanWakeTarget::Coordinator,
            _ => HumanWakeTarget::Coordinator,
        }
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanRequestSummary {
    pub request: HumanRuntimeRequest,
    pub lifecycle: HumanRequestLifecycle,
    pub rex_view_id: Digest,
    pub bundle_path: String,
    pub presentation_reference: Option<String>,
}

/// Result of validating one durably queued response against a fresh host observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessedHumanResponse {
    pub response_id: String,
    pub result: crate::store::human::HumanDecisionResult,
}

/// Drain a bounded response batch. The observer must query authoritative current state (provider,
/// repository heads, and applicable policy) for each request; a missing observation leaves that
/// response queued so a transient provider failure cannot accidentally turn into stale approval.
pub fn process_queued_human_responses<F>(
    store: &mut crate::store::ConfigStore,
    owner_generation: u64,
    limit: usize,
    now: u64,
    mut observe: F,
) -> Result<Vec<ProcessedHumanResponse>, String>
where
    F: FnMut(
        &crate::store::ConfigStore,
        &HumanRuntimeRequest,
    ) -> Result<HumanSubjectObservation, String>,
{
    if limit == 0 || limit > MAX_HUMAN_RESPONSE_BATCH {
        return Err("human response batch limit must be between 1 and 64".into());
    }
    let queued = store.pending_human_decisions(owner_generation, limit)?;
    let mut processed = Vec::with_capacity(queued.len());
    for item in queued {
        // Re-observation receives the same owner-fenced store connection used by the controller.
        // Domain resolvers must query current persisted intent and provider state here; they must
        // never treat the queued request's own subject as evidence of current authority.
        let result = match observe(store, &item.request)? {
            HumanSubjectObservation::Current(current_subject) => store.process_human_decision(
                owner_generation,
                &item.intent.response_id,
                &current_subject,
                now,
            )?,
            HumanSubjectObservation::Gone(reason) => store.reject_human_decision_stale(
                owner_generation,
                &item.intent.response_id,
                &reason,
                now,
            )?,
            HumanSubjectObservation::TemporarilyUnavailable => continue,
        };
        processed.push(ProcessedHumanResponse {
            response_id: item.intent.response_id,
            result,
        });
    }
    Ok(processed)
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
    let mut envelope = RequestEnvelope::host(
        protocol_request_id,
        None,
        MethodName::new("human.present").expect("static method is valid"),
        Some(request.subject.project_id.clone()),
        params,
    );
    envelope.expected_subject_revision = Some(request.subject.revision.0);
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

/// Provider-facing host adapter used to re-observe the complete authority behind a human
/// decision. Provider errors and `TemporarilyUnavailable` leave the response queued for retry;
/// `Gone` terminalizes it as stale and wakes the responsible role.
pub trait HumanSubjectObserver: Send + Sync {
    fn observe_current_subject(
        &self,
        store: &crate::store::ConfigStore,
        request: &HumanRuntimeRequest,
    ) -> Result<HumanSubjectObservation, String>;
}

/// Read-only adapter for the current, complete remote state of one owned publication resource.
/// Implementations reuse the configured Git/Forge clients and preserve unknown capabilities.
pub trait PublicationAdoptionSource: Send + Sync {
    fn observe_publication(
        &self,
        resource: &crate::store::publication_monitor::PublicationResource,
    ) -> Result<crate::delivery_runtime::RepositoryPublicationObservation, String>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HumanSubjectObservation {
    Current(HumanSubjectBinding),
    Gone(String),
    TemporarilyUnavailable,
}

/// Host observer for approval subjects whose authority is already represented by durable,
/// immutable controller records. It reconstructs the subject from those records and the current
/// applied configuration; queued request fields are used only as lookup keys and are never copied
/// into the returned binding.
///
/// Ticket reviews require a configured forge observation adapter and are deliberately rejected
/// here until that adapter is supplied by the runtime composition.
pub struct DurableHumanSubjectObserver {
    declarative_root: PathBuf,
    delivery_effects: Option<std::sync::Arc<crate::delivery_runtime::RepositoryDeliveryEffects>>,
    owner_generation: Option<u64>,
    publication_source: Option<std::sync::Arc<dyn PublicationAdoptionSource>>,
}

impl DurableHumanSubjectObserver {
    pub fn new(declarative_root: PathBuf) -> Result<Self, String> {
        if !declarative_root.is_absolute() {
            return Err("profile declarative root must be absolute".into());
        }
        Ok(Self {
            declarative_root,
            delivery_effects: None,
            owner_generation: None,
            publication_source: None,
        })
    }

    pub fn with_delivery(
        declarative_root: PathBuf,
        owner_generation: u64,
        delivery_effects: std::sync::Arc<crate::delivery_runtime::RepositoryDeliveryEffects>,
    ) -> Result<Self, String> {
        if !declarative_root.is_absolute() || owner_generation == 0 {
            return Err("human observer requires an absolute config root and active owner".into());
        }
        Ok(Self {
            declarative_root,
            delivery_effects: Some(delivery_effects),
            owner_generation: Some(owner_generation),
            publication_source: None,
        })
    }

    pub fn with_publication_adoption(
        declarative_root: PathBuf,
        owner_generation: u64,
        publication_source: std::sync::Arc<dyn PublicationAdoptionSource>,
    ) -> Result<Self, String> {
        if !declarative_root.is_absolute() || owner_generation == 0 {
            return Err("human observer requires an absolute config root and active owner".into());
        }
        Ok(Self {
            declarative_root,
            delivery_effects: None,
            owner_generation: Some(owner_generation),
            publication_source: Some(publication_source),
        })
    }
}

impl HumanSubjectObserver for DurableHumanSubjectObserver {
    fn observe_current_subject(
        &self,
        store: &crate::store::ConfigStore,
        request: &HumanRuntimeRequest,
    ) -> Result<HumanSubjectObservation, String> {
        match request.purpose {
            HumanPurpose::OperationApproval => observe_operation_subject(store, request),
            HumanPurpose::ProfilePromotion => {
                observe_profile_subject(store, request, &self.declarative_root)
            }
            HumanPurpose::ProfileTrial => observe_profile_trial_subject(store, request),
            HumanPurpose::PlanDecision | HumanPurpose::GoalCompletion => {
                observe_typed_role_authority(store, request)
            }
            HumanPurpose::PublicationAdoption => {
                match (&self.publication_source, self.owner_generation) {
                    (Some(source), Some(generation)) => observe_publication_adoption_subject(
                        store,
                        request,
                        source.as_ref(),
                        generation,
                    ),
                    _ => Err(
                        "publication adoption requires the configured fresh remote observer".into(),
                    ),
                }
            }
            HumanPurpose::TicketReview => {
                let _configured =
                    self.delivery_effects.is_some() && self.owner_generation.is_some();
                Err("ticket review is unavailable until the canonical durable MergeWorkItem observer is integrated".into())
            }
            purpose => Err(format!(
                "no authoritative host observer is configured for {purpose:?}; decision remains queued"
            )),
        }
    }
}

fn observe_profile_trial_subject(
    store: &crate::store::ConfigStore,
    request: &HumanRuntimeRequest,
) -> Result<HumanSubjectObservation, String> {
    let Some(authorization) =
        store.pending_profile_trial_authorization_for_request(&request.request_id)?
    else {
        return Ok(HumanSubjectObservation::Gone(
            "the profile trial authorization is no longer pending".into(),
        ));
    };
    if authorization.project_id != request.subject.project_id
        || authorization.authorization_id != request.subject.subject_id
        || authorization.human_request_id != request.request_id
    {
        return Ok(HumanSubjectObservation::Gone(
            "the profile trial request no longer matches its durable authorization".into(),
        ));
    }
    let bundle = crate::learning_trials::profile_trial_review_bundle(&authorization)?;
    let expected = crate::learning_trials::profile_trial_human_request(
        request.request_id.clone(),
        &authorization,
        bundle,
        request.question.clone(),
        authorization.expires_at_unix,
    )?;
    if expected != *request {
        return Ok(HumanSubjectObservation::Gone(
            "the profile trial review scope, evidence, or choices changed".into(),
        ));
    }
    Ok(HumanSubjectObservation::Current(expected.subject))
}

fn observe_publication_adoption_subject(
    store: &crate::store::ConfigStore,
    request: &HumanRuntimeRequest,
    source: &dyn PublicationAdoptionSource,
    _owner_generation: u64,
) -> Result<HumanSubjectObservation, String> {
    let Some(HumanAuthorityMaterial::PublicationAdoption { material }) =
        store.human_request_authority(&request.request_id)?
    else {
        return Ok(HumanSubjectObservation::Gone(
            "the publication adoption authority is no longer available".into(),
        ));
    };
    let Some(latest) = store.latest_unresolved_publication(&material.resource)? else {
        return Ok(HumanSubjectObservation::Gone(
            "the publication irregularity is no longer unresolved".into(),
        ));
    };
    if latest.event_id != material.event_id
        || latest.revision != material.event_revision
        || latest.observation_digest != material.previous_observation_digest
    {
        return Ok(HumanSubjectObservation::Gone(
            "a newer publication observation superseded this adoption request".into(),
        ));
    }
    let Some(project) = store.project(&material.resource.project_id)? else {
        return Ok(HumanSubjectObservation::Gone(
            "the Project for this publication no longer exists".into(),
        ));
    };
    let Some(snapshot) = store.load_snapshot(&project.config_source)? else {
        return Ok(HumanSubjectObservation::TemporarilyUnavailable);
    };
    if snapshot.revision != project.config_revision
        || snapshot.config.digest != project.config_digest
        || snapshot.config.digest != material.configuration_digest
    {
        return Ok(HumanSubjectObservation::Gone(
            "the Project configuration changed after publication adoption was prepared".into(),
        ));
    }
    let Some(repository) = snapshot
        .config
        .config
        .repositories
        .get(&material.resource.repository_id)
    else {
        return Ok(HumanSubjectObservation::Gone(
            "the affected repository is no longer configured".into(),
        ));
    };
    if publication_adoption_policy_digest(repository)? != material.policy_digest {
        return Ok(HumanSubjectObservation::Gone(
            "the repository publication adoption policy changed".into(),
        ));
    }
    let current_observation = source.observe_publication(&material.resource)?;
    let mut current_material = material.clone();
    current_material.current_observation_digest =
        publication_observation_digest(&current_observation)?;
    current_material.current_observation = current_observation;
    let expected = publication_adoption_request(request.request_id.clone(), current_material)?;
    if expected != *request {
        return Ok(HumanSubjectObservation::Gone(
            "the selected external resource or its complete remote evidence changed".into(),
        ));
    }
    Ok(HumanSubjectObservation::Current(expected.subject))
}

fn observe_operation_subject(
    store: &crate::store::ConfigStore,
    request: &HumanRuntimeRequest,
) -> Result<HumanSubjectObservation, String> {
    let operation_id = crate::domain::ids::OperationId::parse(request.subject.subject_id.clone())?;
    let Some(intent) = store.operation_approval_intent(&operation_id)? else {
        return Ok(HumanSubjectObservation::Gone(
            "the operation approval intent no longer exists or is no longer awaiting approval"
                .into(),
        ));
    };
    let Some(project) = store.project(&intent.project_id)? else {
        return Ok(HumanSubjectObservation::TemporarilyUnavailable);
    };
    let Some(snapshot) = store.load_snapshot(&project.config_source)? else {
        return Ok(HumanSubjectObservation::TemporarilyUnavailable);
    };
    if snapshot.revision != project.config_revision
        || snapshot.config.digest != project.config_digest
    {
        return Err("current operation configuration snapshot is inconsistent".into());
    }
    let applied = &snapshot.config;
    let bundle = crate::operations::operation_review_bundle(
        applied,
        &intent.subject,
        &intent.target,
        &intent.ticket_id,
    )?;
    let binding =
        crate::operations::operation_human_subject_binding(applied, &intent.subject, &bundle)?;
    let expected_request_id = intent
        .approval_request_id
        .as_deref()
        .ok_or("operation approval request has no durable request ID")?;
    if request.purpose != HumanPurpose::OperationApproval
        || request.request_id.as_str() != expected_request_id
        || request.review_bundle != bundle
        || request.subject != binding
        || !request.choices.contains(&HumanDecisionChoice::Approve)
    {
        return Ok(HumanSubjectObservation::Gone(
            "the operation approval evidence or policy changed; review the new request".into(),
        ));
    }
    Ok(HumanSubjectObservation::Current(binding))
}

fn observe_profile_subject(
    store: &crate::store::ConfigStore,
    request: &HumanRuntimeRequest,
    declarative_root: &Path,
) -> Result<HumanSubjectObservation, String> {
    let Some(project) = store.project(&request.subject.project_id)? else {
        return Ok(HumanSubjectObservation::Gone(
            "the project for this profile approval no longer exists".into(),
        ));
    };
    let Some(snapshot) = store.load_snapshot(&project.config_source)? else {
        return Ok(HumanSubjectObservation::TemporarilyUnavailable);
    };
    if snapshot.revision != project.config_revision
        || snapshot.config.digest != project.config_digest
    {
        return Err("current profile configuration snapshot is inconsistent".into());
    }
    let Some(candidate) =
        store.current_learning_candidate_package(&project.id, &request.subject.subject_id)?
    else {
        return Ok(HumanSubjectObservation::Gone(
            "the profile candidate is no longer awaiting approval".into(),
        ));
    };
    let Some(evidence) = candidate.evidence.as_ref() else {
        return Err("profile candidate has no completed trial evidence".into());
    };
    let config_file = declarative_root.join("config.toml");
    let declarative_profile_root = declarative_root.join("profiles");
    let expected_config_revision =
        crate::learning::config_revision(&config_file, &declarative_profile_root)
            .map_err(|error| error.to_string())?;
    let material_digest = crate::learning::profile_approval_subject_digest(
        &project.id,
        candidate.revision.role,
        &candidate.profile_id,
        &candidate.revision.digest,
        &candidate.files,
        evidence,
        &expected_config_revision,
    )
    .map_err(|error| error.to_string())?;
    let bundle = crate::learning::profile_candidate_review_bundle(&candidate)
        .map_err(|error| error.to_string())?;
    let policy_digest = profile_policy_digest(&snapshot.config.config.learning)?;
    let binding = HumanSubjectBinding {
        project_id: project.id,
        kind: HumanSubjectKind::Profile,
        subject_id: candidate.revision.candidate_id,
        ticket_run_id: None,
        revision: crate::learning::profile_candidate_revision(&candidate.revision.digest)
            .map_err(|error| error.to_string())?,
        material_digest,
        configuration_digest: snapshot.config.digest,
        policy_digest,
        bundle_digest: review_bundle_digest(&bundle)?,
    };
    Ok(HumanSubjectObservation::Current(binding))
}

fn observe_typed_role_authority(
    store: &crate::store::ConfigStore,
    request: &HumanRuntimeRequest,
) -> Result<HumanSubjectObservation, String> {
    let Some(authority) = store.human_request_authority(&request.request_id)? else {
        return Ok(HumanSubjectObservation::Gone(
            "the typed Planner or goal authority evidence is missing".into(),
        ));
    };
    authority.validate_for(request)?;
    let source = match &authority {
        HumanAuthorityMaterial::PlannerClarification { source, .. }
        | HumanAuthorityMaterial::GoalCompletion { source, .. } => source,
        HumanAuthorityMaterial::PublicationAdoption { .. } => {
            return Ok(HumanSubjectObservation::Gone(
                "publication adoption is not a Planner or goal decision".into(),
            ));
        }
    };
    if !store.human_role_result_is_current_source(source)? {
        return Ok(HumanSubjectObservation::Gone(
            "the source Agent result is no longer an accepted immutable result".into(),
        ));
    }
    let Some(project) = store.project(&request.subject.project_id)? else {
        return Ok(HumanSubjectObservation::Gone(
            "the Project for this human decision no longer exists".into(),
        ));
    };
    let Some(snapshot) = store.load_snapshot(&project.config_source)? else {
        return Ok(HumanSubjectObservation::TemporarilyUnavailable);
    };
    if snapshot.revision != project.config_revision
        || snapshot.config.digest != project.config_digest
        || snapshot.config.digest != request.subject.configuration_digest
        || source.binding.config_digest != snapshot.config.digest
        || source.binding.config_revision != snapshot.revision
    {
        return Ok(HumanSubjectObservation::Gone(
            "the Project configuration changed after the human request was prepared".into(),
        ));
    }
    match &authority {
        HumanAuthorityMaterial::PlannerClarification { source, .. } => {
            let Some(ticket_run_id) = source.binding.ticket_run_id.as_ref() else {
                return Ok(HumanSubjectObservation::Gone(
                    "Planner clarification is missing its TicketRun scope".into(),
                ));
            };
            let Some((project_id, revision, phase, _)) =
                store.current_ticket_human_scope(ticket_run_id)?
            else {
                return Ok(HumanSubjectObservation::Gone(
                    "the Planner TicketRun no longer exists".into(),
                ));
            };
            if project_id != request.subject.project_id
                || revision != request.subject.revision.0
                || source.binding.ticket_revision != Some(request.subject.revision)
                || phase != "planning"
            {
                return Ok(HumanSubjectObservation::Gone(
                    "the Planner TicketRun phase or revision changed".into(),
                ));
            }
        }
        HumanAuthorityMaterial::GoalCompletion {
            goal_revision,
            acceptance_criteria,
            evidence,
            ..
        } => {
            let configured_goal = snapshot
                .config
                .config
                .projects
                .get(&project.id)
                .and_then(|config| config.goal.as_ref());
            if project.goal_revision != *goal_revision
                || configured_goal.is_none_or(|goal| {
                    goal.revision != *goal_revision || &goal.acceptance != acceptance_criteria
                })
                || !evidence.incomplete_ticket_ids.is_empty()
                || !store.goal_completion_work_is_clear(&project.id)?
                || evidence
                    .satisfied_acceptance
                    .iter()
                    .cloned()
                    .collect::<BTreeSet<_>>()
                    != acceptance_criteria.iter().cloned().collect::<BTreeSet<_>>()
            {
                return Ok(HumanSubjectObservation::Gone(
                    "goal revision, acceptance criteria, or completion evidence changed".into(),
                ));
            }
        }
        HumanAuthorityMaterial::PublicationAdoption { .. } => unreachable!("handled above"),
    }
    Ok(HumanSubjectObservation::Current(request.subject.clone()))
}

pub fn profile_policy_digest(policy: &crate::config::LearningConfig) -> Result<Digest, String> {
    let bytes = serde_json::to_vec(policy).map_err(|error| error.to_string())?;
    let mut material = b"rex-projects-profile-policy-v1\0".to_vec();
    material.extend(bytes);
    Digest::parse(hex(&Sha256::digest(material)))
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanPresentationEffect {
    pub request: HumanRuntimeRequest,
    pub rex_view_id: Digest,
    #[serde(default)]
    pub authority: Option<HumanAuthorityMaterial>,
}

/// Host-built provenance needed to reconstruct a Planner clarification or a
/// Supervisor goal-completion request after a crash. The source points at an
/// immutable, already-validated role result; document bytes must come from
/// the host artifact registry, never from a path supplied to this structure.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HumanAuthorityMaterial {
    PlannerClarification {
        source: HumanRoleResultSource,
        documents: Vec<HumanEvidenceDocument>,
    },
    GoalCompletion {
        source: HumanRoleResultSource,
        goal_revision: u64,
        acceptance_criteria: Vec<String>,
        evidence: HumanGoalCompletionEvidence,
        documents: Vec<HumanEvidenceDocument>,
    },
    PublicationAdoption {
        material: PublicationAdoptionAuthority,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanRoleResultSource {
    pub binding: RoleResultBinding,
    pub message_id: String,
    pub result_digest: Digest,
    pub result_kind: crate::engine::orchestration::RoleOutputKind,
    pub assertion: AgentAssertion,
    pub human_request: HumanRequestPayload,
    pub claimed_artifact_refs: Vec<RoleArtifactReference>,
}

/// Immutable evidence copied from the host-validated Supervisor proposal. The host rechecks the
/// current goal criteria and open work before accepting a response; this is never authority by
/// itself.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanGoalCompletionEvidence {
    pub satisfied_acceptance: Vec<String>,
    pub incomplete_ticket_ids: Vec<crate::domain::ids::TicketId>,
    pub deferred_risks: Vec<String>,
    pub operation_results: Vec<String>,
    pub subject_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanEvidenceDocument {
    pub reference: RoleArtifactReference,
    /// Bounded verified bytes copied from the artifact registry at request time.
    pub bytes: Vec<u8>,
}

/// Exact remote state a human is being asked to adopt after an unexpected publication.
/// The producer must create this only from a fresh, complete host observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationAdoptionAuthority {
    pub resource: crate::store::publication_monitor::PublicationResource,
    pub event_id: String,
    pub event_revision: u64,
    pub previous_observation_digest: Digest,
    pub selected_resource: SelectedPublicationResource,
    pub current_observation: crate::delivery_runtime::RepositoryPublicationObservation,
    pub current_observation_digest: Digest,
    pub configuration_digest: Digest,
    pub policy_digest: Digest,
    pub expires_at_unix: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SelectedPublicationResource {
    Branch {
        head: String,
    },
    PullRequest {
        number: u64,
        node_id: String,
        head_sha: String,
        base_sha: String,
    },
}

impl PublicationAdoptionAuthority {
    pub fn compute_observation_digest(&self) -> Result<Digest, String> {
        publication_observation_digest(&self.current_observation)
    }

    pub fn material_digest(&self) -> Result<Digest, String> {
        let material = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        if material.len() > MAX_HUMAN_REQUEST_BYTES {
            return Err(
                "publication adoption evidence exceeds the human request size limit".into(),
            );
        }
        Digest::parse(hex(&Sha256::digest(material)))
    }

    pub fn review_bundle(&self) -> Result<ReviewBundle, String> {
        validate_publication_adoption_authority(self)?;
        let resource = &self.resource;
        let selected = serde_json::to_string_pretty(&self.selected_resource)
            .map_err(|error| error.to_string())?;
        let observation = serde_json::to_string_pretty(&self.current_observation)
            .map_err(|error| error.to_string())?;
        let bundle = ReviewBundle {
            title: "Adopt an external publication".into(),
            summary: format!(
                "Review the unexpected remote state for project {}, ticket run {}, repository {}, branch {}. The selected resource is shown below.",
                resource.project_id,
                resource.ticket_run_id,
                resource.repository_id,
                resource.branch
            ),
            risk: Some(crate::human::ReviewRisk {
                rating: 3,
                confidence: crate::human::RiskConfidence::High,
                rationale: "This adopts an externally created or changed remote resource into the project record. It does not create a host publication receipt.".into(),
                unresolved_gates: vec!["Confirm the exact resource identity and current remote state.".into()],
            }),
            repositories: Vec::new(),
            evidence: vec![
                ReviewEvidence {
                    title: "Selected resource to adopt".into(),
                    body: selected,
                    truncated: false,
                },
                ReviewEvidence {
                    title: "Complete current remote observation".into(),
                    body: observation,
                    truncated: false,
                },
            ],
            unknowns: vec![
                "The selected resource was created outside the rex-projects host effect journal.".into(),
                format!("Previous irregularity observation digest: {}", self.previous_observation_digest),
                format!("Fresh observation digest: {}", self.current_observation_digest),
            ],
        };
        bundle.validate()?;
        Ok(bundle)
    }
}

pub fn publication_observation_digest(
    observation: &crate::delivery_runtime::RepositoryPublicationObservation,
) -> Result<Digest, String> {
    let bytes = serde_json::to_vec(observation).map_err(|error| error.to_string())?;
    let mut material = b"rex-projects-publication-observation-v1\0".to_vec();
    material.extend(bytes);
    Digest::parse(hex(&Sha256::digest(material)))
}

fn validate_publication_adoption_authority(
    authority: &PublicationAdoptionAuthority,
) -> Result<(), String> {
    if authority.event_id.is_empty()
        || authority.event_id.len() > 512
        || authority.event_id.chars().any(char::is_control)
        || authority.event_revision == 0
        || authority.expires_at_unix == 0
        || authority.compute_observation_digest()? != authority.current_observation_digest
    {
        return Err(
            "publication adoption authority identity or observation digest is invalid".into(),
        );
    }
    let crate::delivery_forge::ObservationCapability::Known(pulls) =
        &authority.current_observation.pull_requests
    else {
        return Err("publication adoption requires a complete pull-request observation".into());
    };
    if pulls.iter().any(|pull| {
        !matches!(
            pull.timeline,
            crate::delivery_forge::ObservationCapability::Known(_)
        )
    }) {
        return Err("publication adoption requires complete pull-request timelines".into());
    }
    match (&authority.selected_resource, &authority.current_observation) {
        (SelectedPublicationResource::Branch { head }, observation)
            if observation.remote_head.as_deref() == Some(head.as_str()) => {}
        (
            SelectedPublicationResource::PullRequest {
                number,
                node_id,
                head_sha,
                base_sha,
            },
            observation,
        ) => {
            let crate::delivery_forge::ObservationCapability::Known(pulls) =
                &observation.pull_requests
            else {
                unreachable!()
            };
            let matches = pulls
                .iter()
                .filter(|pull| {
                    pull.number == *number
                        && pull.node_id == *node_id
                        && pull.source_head == *head_sha
                        && pull.base_sha == *base_sha
                })
                .count();
            if matches != 1 {
                return Err("selected pull request is missing, ambiguous, or changed in the current observation".into());
            }
        }
        _ => {
            return Err(
                "selected publication resource is not present in the current observation".into(),
            );
        }
    }
    Ok(())
}

/// Construct the immutable request used by both the producer and response observer.
pub fn publication_adoption_request(
    request_id: HumanRequestId,
    material: PublicationAdoptionAuthority,
) -> Result<HumanRuntimeRequest, String> {
    validate_publication_adoption_authority(&material)?;
    let review_bundle = material.review_bundle()?;
    let subject = HumanSubjectBinding {
        project_id: material.resource.project_id.clone(),
        kind: HumanSubjectKind::Publication,
        subject_id: material.event_id.clone(),
        ticket_run_id: Some(material.resource.ticket_run_id.clone()),
        revision: Revision(material.event_revision),
        material_digest: material.material_digest()?,
        configuration_digest: material.configuration_digest.clone(),
        policy_digest: material.policy_digest.clone(),
        bundle_digest: review_bundle_digest(&review_bundle)?,
    };
    let request = HumanRuntimeRequest {
        request_id,
        purpose: HumanPurpose::PublicationAdoption,
        subject,
        question: format!(
            "Adopt the selected external resource for repository {} branch {}?",
            material.resource.repository_id, material.resource.branch
        ),
        choices: vec![
            HumanDecisionChoice::Approve,
            HumanDecisionChoice::Refuse,
            HumanDecisionChoice::Defer,
        ],
        expires_at_unix: material.expires_at_unix,
        review_bundle,
    };
    request.validate(material.expires_at_unix.saturating_sub(1))?;
    Ok(request)
}

pub fn publication_adoption_policy_digest(
    repository: &crate::config::RepositoryConfig,
) -> Result<Digest, String> {
    let bytes = serde_json::to_vec(&(
        "rex-projects-publication-adoption-policy-v1",
        &repository.forge,
        &repository.base_branch,
        &repository.merge,
    ))
    .map_err(|error| error.to_string())?;
    Digest::parse(hex(&Sha256::digest(bytes)))
}

impl HumanAuthorityMaterial {
    pub fn validate_for(&self, request: &HumanRuntimeRequest) -> Result<(), String> {
        if let Self::PublicationAdoption { material } = self {
            if publication_adoption_request(request.request_id.clone(), material.clone())?
                != *request
            {
                return Err(
                    "publication adoption authority does not match its human request".into(),
                );
            }
            return Ok(());
        }
        let (source, required_purpose, required_role) = match self {
            Self::PlannerClarification { source, documents } => {
                let total = documents.iter().try_fold(0usize, |total, document| {
                    if document.bytes.len() as u64 != document.reference.bytes
                        || hex(&Sha256::digest(&document.bytes))
                            != document.reference.digest.as_str()
                    {
                        return Err(
                            "human evidence document does not match its registered artifact digest"
                                .to_owned(),
                        );
                    }
                    total
                        .checked_add(document.bytes.len())
                        .ok_or_else(|| "human evidence size overflow".to_owned())
                })?;
                if total > MAX_HUMAN_REQUEST_BYTES {
                    return Err(
                        "human evidence documents exceed the review request size limit".into(),
                    );
                }
                let mut references = documents
                    .iter()
                    .map(|document| document.reference.clone())
                    .collect::<Vec<_>>();
                references.sort_by(|left, right| left.path.cmp(&right.path));
                let mut claimed = source.claimed_artifact_refs.clone();
                claimed.sort_by(|left, right| left.path.cmp(&right.path));
                if references != claimed
                    || source.result_kind
                        != crate::engine::orchestration::RoleOutputKind::HumanRequest
                    || source.human_request.kind != "clarification"
                    || source.human_request.evidence_references != source.claimed_artifact_refs
                {
                    return Err(
                        "Planner evidence documents do not match its validated HumanRequest result"
                            .into(),
                    );
                }
                (
                    source,
                    HumanPurpose::PlanDecision,
                    crate::domain::types::Role::Planner,
                )
            }
            Self::GoalCompletion {
                source,
                goal_revision,
                acceptance_criteria,
                evidence,
                documents,
            } => {
                let total = documents.iter().try_fold(0usize, |total, document| {
                    if document.bytes.len() as u64 != document.reference.bytes
                        || hex(&Sha256::digest(&document.bytes))
                            != document.reference.digest.as_str()
                    {
                        return Err(
                            "goal evidence document does not match its registered artifact digest"
                                .to_owned(),
                        );
                    }
                    total
                        .checked_add(document.bytes.len())
                        .ok_or_else(|| "goal evidence size overflow".to_owned())
                })?;
                if total > MAX_HUMAN_REQUEST_BYTES {
                    return Err(
                        "goal evidence documents exceed the review request size limit".into(),
                    );
                }
                if *goal_revision == 0
                    || request.subject.revision.0 != *goal_revision
                    || acceptance_criteria.is_empty()
                    || acceptance_criteria
                        .iter()
                        .any(|value| value.trim().is_empty())
                    || evidence
                        .satisfied_acceptance
                        .iter()
                        .any(|value| value.trim().is_empty())
                {
                    return Err("goal-completion evidence or goal revision is invalid".into());
                }
                let mut references = documents
                    .iter()
                    .map(|document| document.reference.clone())
                    .collect::<Vec<_>>();
                references.sort_by(|left, right| left.path.cmp(&right.path));
                let mut claimed = source.claimed_artifact_refs.clone();
                claimed.sort_by(|left, right| left.path.cmp(&right.path));
                if source.result_kind != crate::engine::orchestration::RoleOutputKind::HumanRequest
                    || source.human_request.kind != "goal_completion"
                    || source.human_request.evidence_references != source.claimed_artifact_refs
                    || references != claimed
                {
                    return Err(
                        "goal completion evidence does not match its validated typed request"
                            .into(),
                    );
                }
                (
                    source,
                    HumanPurpose::GoalCompletion,
                    crate::domain::types::Role::Supervisor,
                )
            }
            Self::PublicationAdoption { .. } => unreachable!("handled above"),
        };
        let binding = &source.binding;
        if request.purpose != required_purpose
            || binding.role != required_role
            || binding.project_id != request.subject.project_id
            || binding.ticket_run_id != request.subject.ticket_run_id
            || binding.ticket_revision
                != request
                    .subject
                    .ticket_run_id
                    .as_ref()
                    .map(|_| request.subject.revision)
            || binding.config_digest != request.subject.configuration_digest
            || source.assertion != AgentAssertion::Succeeded
            || source.message_id.trim().is_empty()
            || source.message_id.len() > 255
            || source.message_id.chars().any(char::is_control)
        {
            return Err("human authority source does not match the request scope".into());
        }
        let material_digest = self.material_digest()?;
        if request.subject.material_digest != material_digest {
            return Err(
                "human request material digest does not match its canonical authority".into(),
            );
        }
        if request.subject.policy_digest != self.policy_digest()? {
            return Err("human request policy digest does not match its role authority".into());
        }
        if request.review_bundle != self.review_bundle()? {
            return Err("human review bundle does not match its canonical typed authority".into());
        }
        Ok(())
    }

    pub fn material_digest(&self) -> Result<Digest, String> {
        let bytes = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        if bytes.len() > MAX_HUMAN_REQUEST_BYTES {
            return Err("human authority material exceeds the request size limit".into());
        }
        Digest::parse(hex(&Sha256::digest(bytes)))
    }

    pub fn policy_digest(&self) -> Result<Digest, String> {
        let binding = match self {
            Self::PlannerClarification { source, .. } | Self::GoalCompletion { source, .. } => {
                &source.binding
            }
            Self::PublicationAdoption { material } => return Ok(material.policy_digest.clone()),
        };
        let bytes = serde_json::to_vec(&(
            &binding.profile_digest,
            &binding.instruction_digest,
            &binding.provider_capability_receipt_digest,
            &binding.result_schema_digest,
        ))
        .map_err(|error| error.to_string())?;
        Digest::parse(hex(&Sha256::digest(bytes)))
    }

    pub fn review_bundle(&self) -> Result<ReviewBundle, String> {
        let bundle = match self {
            Self::PlannerClarification { source, documents } => ReviewBundle {
                title: "Planner clarification request".into(),
                summary: format!(
                    "The Planner requires a human decision for ticket run {} at revision {}.",
                    source.binding.ticket_run_id.as_ref().map_or("unknown", TicketRunId::as_str),
                    source.binding.ticket_revision.map_or(0, |revision| revision.0),
                ),
                risk: None,
                repositories: Vec::new(),
                evidence: documents
                    .iter()
                    .map(|document| ReviewEvidence {
                        title: document.reference.path.clone(),
                        body: String::from_utf8_lossy(&document.bytes).into_owned(),
                        truncated: false,
                    })
                    .collect(),
                unknowns: vec![
                    "Planner-authored evidence is an assertion; review it against the repository and ticket context.".into(),
                ],
            },
            Self::GoalCompletion {
                source,
                goal_revision,
                acceptance_criteria,
                evidence,
                documents,
            } => ReviewBundle {
                title: format!("Goal completion review: revision {goal_revision}"),
                summary: format!(
                    "Supervisor requests confirmation that the goal for project {} is complete.",
                    source.binding.project_id,
                ),
                risk: None,
                repositories: Vec::new(),
                evidence: vec![
                    ReviewEvidence {
                        title: "Configured acceptance criteria".into(),
                        body: acceptance_criteria.join("\n"),
                        truncated: false,
                    },
                    ReviewEvidence {
                        title: "Supervisor completion evidence".into(),
                        body: serde_json::to_string_pretty(evidence)
                            .map_err(|error| error.to_string())?,
                        truncated: false,
                    },
                ]
                .into_iter()
                .chain(documents.iter().map(|document| ReviewEvidence {
                    title: document.reference.path.clone(),
                    body: String::from_utf8_lossy(&document.bytes).into_owned(),
                    truncated: false,
                }))
                .collect(),
                unknowns: vec![
                    "Completion evidence is a Supervisor assertion and must be checked against current project state.".into(),
                ],
            },
            Self::PublicationAdoption { material } => material.review_bundle()?,
        };
        bundle.validate()?;
        Ok(bundle)
    }
}

/// Configured host-side presenter. Its effect request contains only host-built typed review
/// material; presenter output may save a location, never a human choice. Decisions enter through
/// `human respond` and are revalidated in the owning controller.
pub struct HumanPresenterEffectHandler {
    kind: EffectKind,
    command: Vec<String>,
    local_html: bool,
    environment: std::collections::BTreeMap<OsString, OsString>,
    artifact_root: PathBuf,
    observer: std::sync::Arc<dyn HumanSubjectObserver>,
}

impl HumanPresenterEffectHandler {
    pub fn new(
        presenter_kind: &str,
        command: Vec<String>,
        environment: std::collections::BTreeMap<OsString, OsString>,
        artifact_root: PathBuf,
        observer: std::sync::Arc<dyn HumanSubjectObserver>,
    ) -> Result<Self, String> {
        if !matches!(presenter_kind, "local_html" | "command")
            || command.is_empty()
            || command.iter().any(String::is_empty)
            || !artifact_root.is_absolute()
        {
            return Err(
                "human presenter needs a supported kind, nonempty argv, and absolute artifact root"
                    .into(),
            );
        }
        Ok(Self {
            kind: EffectKind::RequestHumanReview,
            command,
            local_html: presenter_kind == "local_html",
            environment,
            artifact_root,
            observer,
        })
    }

    fn present(
        &self,
        request: &EffectRequest,
        context: &mut EffectContext<'_>,
    ) -> Result<EffectObservation, String> {
        let now = u64::try_from(context.now_unix)
            .map_err(|_| "controller time is before the Unix epoch".to_owned())?;
        let effect: HumanPresentationEffect = parse_unique(request.intent.request_json.as_bytes())?;
        let review = &effect.request;
        let subject_scope_matches = effect_subject_matches(
            &request.intent.subject_type,
            &request.intent.subject_id,
            review,
        );
        if request.intent.project_id != review.subject.project_id
            || !subject_scope_matches
            || request.intent.expected_revision != Some(review.subject.revision.0)
        {
            return Err(
                "human presentation effect identity does not match its typed subject".into(),
            );
        }
        review.validate(now)?;
        if effect.authority.is_none()
            && matches!(
                review.purpose,
                HumanPurpose::PlanDecision | HumanPurpose::GoalCompletion
            )
        {
            return Err(
                "Planner/goal human requests require durable typed authority material".into(),
            );
        }
        let html_path = write_runtime_review_artifact(&self.artifact_root, review)
            .map_err(|error| format!("write human review artifact: {error}"))?;
        let inserted = if let Some(authority) = &effect.authority {
            context.store.register_human_request_with_authority(
                context.owner_generation,
                review,
                &effect.rex_view_id,
                &html_path,
                authority,
                now,
            )?
        } else {
            context.store.register_human_request(
                context.owner_generation,
                review,
                &effect.rex_view_id,
                &html_path,
                now,
            )?
        };
        if !inserted {
            let existing = context
                .store
                .current_human_request(&review.request_id)?
                .ok_or_else(|| "durable human request disappeared".to_owned())?;
            if existing.lifecycle != HumanRequestLifecycle::Pending {
                return observation_for_lifecycle(existing.lifecycle, &review.request_id);
            }
        }

        let attempted_at_unix = now;
        let (receipt, observation) = if self.local_html {
            match open_runtime_review_html(&self.command, &self.environment, &html_path) {
                Ok(()) => (
                    crate::store::human::HumanPresentationReceipt {
                        request_id: review.request_id.clone(),
                        presenter_kind: "local_html".into(),
                        reference: Some(html_path.to_string_lossy().into_owned()),
                        location: None,
                        outcome: "opened".into(),
                        detail: None,
                        attempted_at_unix,
                    },
                    EffectObservation::Pending {
                        receipt: format!("human review opened: {}", review.request_id),
                    },
                ),
                Err(error) => {
                    let receipt = failed_presentation_receipt(
                        &review.request_id,
                        "local_html",
                        attempted_at_unix,
                        &error,
                    );
                    context
                        .store
                        .record_human_presentation(context.owner_generation, &receipt)?;
                    return Err(error);
                }
            }
        } else {
            match run_command_presenter(
                &self.command,
                &self.environment,
                ProtocolRequestId::new(format!(
                    "human-present-{}",
                    hex(&Sha256::digest(review.request_id.as_str().as_bytes()))
                ))?,
                review,
                html_path.to_string_lossy().into_owned(),
            ) {
                Ok(reference) => (
                    crate::store::human::HumanPresentationReceipt {
                        request_id: review.request_id.clone(),
                        presenter_kind: "command".into(),
                        reference: Some(reference.reference),
                        location: reference.location,
                        outcome: "presented".into(),
                        detail: None,
                        attempted_at_unix,
                    },
                    EffectObservation::Pending {
                        receipt: format!("human review presented: {}", review.request_id),
                    },
                ),
                Err(error) => {
                    let receipt = failed_presentation_receipt(
                        &review.request_id,
                        "command",
                        attempted_at_unix,
                        &error,
                    );
                    context
                        .store
                        .record_human_presentation(context.owner_generation, &receipt)?;
                    return Err(error);
                }
            }
        };
        context
            .store
            .record_human_presentation(context.owner_generation, &receipt)?;
        Ok(observation)
    }

    fn reconcile(
        &self,
        request: &EffectRequest,
        context: &mut EffectContext<'_>,
    ) -> Result<EffectObservation, String> {
        let effect: HumanPresentationEffect = parse_unique(request.intent.request_json.as_bytes())?;
        // Processing is bounded. Each response is paired with a newly observed full subject;
        // transient observation errors preserve the durable queue for a later controller tick.
        let now = u64::try_from(context.now_unix)
            .map_err(|_| "controller time is before the Unix epoch".to_owned())?;
        process_queued_human_responses(
            context.store,
            context.owner_generation,
            MAX_HUMAN_RESPONSE_BATCH,
            now,
            |store, human_request| self.observer.observe_current_subject(store, human_request),
        )?;
        let summary = context
            .store
            .current_human_request(&effect.request.request_id)?
            .ok_or_else(|| "durable human request is missing during reconciliation".to_owned())?;
        if summary.lifecycle == HumanRequestLifecycle::Pending {
            // A crash or lost presenter reply may leave a durable request without a presentation
            // receipt. Reuse the stable request ID so command adapters can deduplicate safely.
            return self.present(request, context);
        }
        observation_for_lifecycle(summary.lifecycle, &effect.request.request_id)
    }
}

fn effect_subject_matches(
    effect_subject_type: &str,
    effect_subject_id: &str,
    request: &HumanRuntimeRequest,
) -> bool {
    match request.purpose {
        HumanPurpose::OperationApproval => {
            effect_subject_type == "ticket_run"
                && request
                    .subject
                    .ticket_run_id
                    .as_ref()
                    .is_some_and(|ticket_run_id| effect_subject_id == ticket_run_id.as_str())
        }
        _ => effect_subject_id == request.subject.subject_id,
    }
}

impl EffectHandler for HumanPresenterEffectHandler {
    fn kind(&self) -> EffectKind {
        self.kind
    }

    fn handle(
        &self,
        mode: EffectMode,
        request: &EffectRequest,
        context: &mut EffectContext<'_>,
    ) -> Result<EffectObservation, String> {
        match mode {
            EffectMode::Submit => self.present(request, context),
            EffectMode::Reconcile => self.reconcile(request, context),
        }
    }
}

fn observation_for_lifecycle(
    lifecycle: HumanRequestLifecycle,
    request_id: &HumanRequestId,
) -> Result<EffectObservation, String> {
    match lifecycle {
        HumanRequestLifecycle::Pending
        | HumanRequestLifecycle::Presented
        | HumanRequestLifecycle::ResponseQueued => Ok(EffectObservation::Pending {
            receipt: format!("awaiting human decision: {request_id}"),
        }),
        HumanRequestLifecycle::Decided => Ok(EffectObservation::Applied {
            receipt: format!("human response validated: {request_id}"),
        }),
        HumanRequestLifecycle::Stale
        | HumanRequestLifecycle::Expired
        | HumanRequestLifecycle::Cancelled => Ok(EffectObservation::Rejected {
            receipt: format!("human request is {lifecycle:?}: {request_id}"),
        }),
    }
}

fn failed_presentation_receipt(
    request_id: &HumanRequestId,
    kind: &str,
    attempted_at_unix: u64,
    error: &str,
) -> crate::store::human::HumanPresentationReceipt {
    crate::store::human::HumanPresentationReceipt {
        request_id: request_id.clone(),
        presenter_kind: kind.into(),
        reference: None,
        location: None,
        outcome: "failed".into(),
        detail: Some(error.chars().take(4096).collect()),
        attempted_at_unix,
    }
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
            ticket_run_id: Some(TicketRunId::parse("run-1").unwrap()),
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
    fn operation_subject_digest_binds_its_owning_ticket_run() {
        let request = sample_request();
        let first = request.subject.digest().unwrap();
        let mut changed = request.subject.clone();
        changed.ticket_run_id = Some(TicketRunId::parse("another-run").unwrap());
        assert_ne!(first, changed.digest().unwrap());
        changed.ticket_run_id = None;
        assert!(changed.validate().is_err());
    }

    fn publication_authority(
        selected_resource: SelectedPublicationResource,
        pull_requests: crate::delivery_forge::ObservationCapability<
            Vec<crate::delivery_forge::ObservedPullRequest>,
        >,
    ) -> PublicationAdoptionAuthority {
        let mut authority = PublicationAdoptionAuthority {
            resource: crate::store::publication_monitor::PublicationResource {
                project_id: ProjectId::parse("p1").unwrap(),
                ticket_run_id: TicketRunId::parse("run-1").unwrap(),
                repository_id: crate::domain::ids::RepositoryId::parse("repo-1").unwrap(),
                branch: "feature/example".into(),
            },
            event_id: "irregularity-1".into(),
            event_revision: 2,
            previous_observation_digest: Digest::parse("a".repeat(64)).unwrap(),
            selected_resource,
            current_observation: crate::delivery_runtime::RepositoryPublicationObservation {
                remote_head: Some("head-2".into()),
                pull_requests,
            },
            current_observation_digest: Digest::parse("b".repeat(64)).unwrap(),
            configuration_digest: Digest::parse("c".repeat(64)).unwrap(),
            policy_digest: Digest::parse("d".repeat(64)).unwrap(),
            expires_at_unix: 500,
        };
        authority.current_observation_digest = authority.compute_observation_digest().unwrap();
        authority
    }

    #[test]
    fn publication_adoption_binds_the_exact_observed_branch_and_request() {
        let authority = publication_authority(
            SelectedPublicationResource::Branch {
                head: "head-2".into(),
            },
            crate::delivery_forge::ObservationCapability::Known(Vec::new()),
        );
        let request = publication_adoption_request(
            HumanRequestId::parse("human-adopt-1").unwrap(),
            authority.clone(),
        )
        .unwrap();
        request.validate(100).unwrap();
        let material = HumanAuthorityMaterial::PublicationAdoption {
            material: authority,
        };
        material.validate_for(&request).unwrap();

        let changed = publication_authority(
            SelectedPublicationResource::Branch {
                head: "head-1".into(),
            },
            crate::delivery_forge::ObservationCapability::Known(Vec::new()),
        );
        assert!(changed.review_bundle().is_err());
    }

    #[test]
    fn publication_adoption_rejects_unknown_or_incomplete_remote_evidence() {
        let unknown = publication_authority(
            SelectedPublicationResource::Branch {
                head: "head-2".into(),
            },
            crate::delivery_forge::ObservationCapability::Unknown,
        );
        assert!(unknown.review_bundle().is_err());

        let pull = crate::delivery_forge::ObservedPullRequest {
            number: 7,
            node_id: "PR_node_7".into(),
            url: "https://example.invalid/owner/repo/pull/7".into(),
            state: "open".into(),
            merged: false,
            merged_at: None,
            source_branch: "feature/example".into(),
            source_head: "head-2".into(),
            base_branch: "main".into(),
            base_sha: "base-1".into(),
            title: "change".into(),
            body: None,
            timeline: crate::delivery_forge::ObservationCapability::Unknown,
        };
        let incomplete = publication_authority(
            SelectedPublicationResource::PullRequest {
                number: 7,
                node_id: "PR_node_7".into(),
                head_sha: "head-2".into(),
                base_sha: "base-1".into(),
            },
            crate::delivery_forge::ObservationCapability::Known(vec![pull]),
        );
        assert!(incomplete.review_bundle().is_err());
    }

    #[test]
    fn operation_presentation_uses_ticket_scope_but_keeps_operation_subject_id() {
        let request = sample_request();
        assert_eq!(request.subject.subject_id, "deploy-1");
        assert!(effect_subject_matches("ticket_run", "run-1", &request));
        assert!(!effect_subject_matches("operation", "deploy-1", &request));
        assert!(!effect_subject_matches("ticket_run", "other-run", &request));
    }

    #[test]
    fn planner_authority_reconstructs_bundle_and_rejects_policy_or_scope_changes() {
        use crate::domain::ids::{AgentRunId, OperationId};
        use crate::domain::types::Role;
        use crate::engine::orchestration::{RoleOutputKind, RoleResultBinding, RoleSessionId};

        let source = HumanRoleResultSource {
            binding: RoleResultBinding {
                agent_run_id: AgentRunId::parse("planner-run").unwrap(),
                operation_id: OperationId::parse("planner-op").unwrap(),
                project_id: ProjectId::parse("p1").unwrap(),
                role_session_id: RoleSessionId::parse("planner-session").unwrap(),
                role: Role::Planner,
                parent_run_id: Some(AgentRunId::parse("coordinator-run").unwrap()),
                parent_role: Some(Role::Coordinator),
                ticket_run_id: Some(TicketRunId::parse("run-1").unwrap()),
                ticket_revision: Some(Revision(3)),
                config_revision: Revision(7),
                config_digest: Digest::parse("b".repeat(64)).unwrap(),
                profile_digest: Digest::parse("c".repeat(64)).unwrap(),
                instruction_digest: Digest::parse("d".repeat(64)).unwrap(),
                provider_capability_receipt_digest: Digest::parse("e".repeat(64)).unwrap(),
                result_schema_digest: Digest::parse("f".repeat(64)).unwrap(),
                controller_generation: 2,
                run_epoch: 1,
                attempt: 1,
            },
            message_id: "planner-result-1".into(),
            result_digest: Digest::parse("a".repeat(64)).unwrap(),
            result_kind: RoleOutputKind::HumanRequest,
            assertion: AgentAssertion::Succeeded,
            human_request: HumanRequestPayload {
                kind: "clarification".into(),
                question: "Which option?".into(),
                choices: vec!["a".into()],
                evidence_references: Vec::new(),
                subject_digest: Digest::parse("a".repeat(64)).unwrap(),
                requested_continuation: None,
            },
            claimed_artifact_refs: Vec::new(),
        };
        let authority = HumanAuthorityMaterial::PlannerClarification {
            source,
            documents: Vec::new(),
        };
        let bundle = authority.review_bundle().unwrap();
        let request = HumanRuntimeRequest {
            request_id: HumanRequestId::parse("plan-review-1").unwrap(),
            purpose: HumanPurpose::PlanDecision,
            subject: HumanSubjectBinding {
                project_id: ProjectId::parse("p1").unwrap(),
                kind: HumanSubjectKind::Plan,
                subject_id: "plan-1".into(),
                ticket_run_id: Some(TicketRunId::parse("run-1").unwrap()),
                revision: Revision(3),
                material_digest: authority.material_digest().unwrap(),
                configuration_digest: Digest::parse("b".repeat(64)).unwrap(),
                policy_digest: authority.policy_digest().unwrap(),
                bundle_digest: review_bundle_digest(&bundle).unwrap(),
            },
            question: "Which architecture should the Planner use?".into(),
            choices: vec![
                HumanDecisionChoice::Approve,
                HumanDecisionChoice::RevisePlan,
                HumanDecisionChoice::Defer,
            ],
            expires_at_unix: 200,
            review_bundle: bundle,
        };
        authority.validate_for(&request).unwrap();

        let mut changed = authority.clone();
        if let HumanAuthorityMaterial::PlannerClarification { source, .. } = &mut changed {
            source.binding.instruction_digest = Digest::parse("1".repeat(64)).unwrap();
        }
        assert!(changed.validate_for(&request).is_err());

        let mut wrong_kind = authority.clone();
        if let HumanAuthorityMaterial::PlannerClarification { source, .. } = &mut wrong_kind {
            source.human_request.kind = "goal_completion".into();
        }
        assert!(wrong_kind.validate_for(&request).is_err());

        let mut unsuccessful = authority;
        if let HumanAuthorityMaterial::PlannerClarification { source, .. } = &mut unsuccessful {
            source.assertion = AgentAssertion::Blocked {
                reason: "missing information".into(),
            };
        }
        assert!(unsuccessful.validate_for(&request).is_err());
    }

    #[test]
    fn goal_completion_authority_binds_supervisor_evidence_and_goal_revision() {
        use crate::domain::ids::{AgentRunId, OperationId};
        use crate::domain::types::Role;
        use crate::engine::orchestration::{RoleOutputKind, RoleResultBinding, RoleSessionId};

        let source = HumanRoleResultSource {
            binding: RoleResultBinding {
                agent_run_id: AgentRunId::parse("supervisor-run").unwrap(),
                operation_id: OperationId::parse("supervisor-op").unwrap(),
                project_id: ProjectId::parse("project-a").unwrap(),
                role_session_id: RoleSessionId::parse("supervisor-session").unwrap(),
                role: Role::Supervisor,
                parent_run_id: None,
                parent_role: None,
                ticket_run_id: None,
                ticket_revision: None,
                config_revision: Revision(4),
                config_digest: Digest::parse("a".repeat(64)).unwrap(),
                profile_digest: Digest::parse("b".repeat(64)).unwrap(),
                instruction_digest: Digest::parse("c".repeat(64)).unwrap(),
                provider_capability_receipt_digest: Digest::parse("d".repeat(64)).unwrap(),
                result_schema_digest: Digest::parse("e".repeat(64)).unwrap(),
                controller_generation: 8,
                run_epoch: 2,
                attempt: 1,
            },
            message_id: "completion-result-1".into(),
            result_digest: Digest::parse("f".repeat(64)).unwrap(),
            result_kind: RoleOutputKind::HumanRequest,
            assertion: AgentAssertion::Succeeded,
            human_request: HumanRequestPayload {
                kind: "goal_completion".into(),
                question: "Review whether this goal is complete.".into(),
                choices: vec!["approve".into(), "request_changes".into()],
                evidence_references: Vec::new(),
                subject_digest: Digest::parse("1".repeat(64)).unwrap(),
                requested_continuation: None,
            },
            claimed_artifact_refs: Vec::new(),
        };
        let authority = HumanAuthorityMaterial::GoalCompletion {
            source,
            goal_revision: 3,
            acceptance_criteria: vec!["api is available".into()],
            evidence: HumanGoalCompletionEvidence {
                satisfied_acceptance: vec!["api is available".into()],
                incomplete_ticket_ids: Vec::new(),
                deferred_risks: Vec::new(),
                operation_results: vec!["host ledger is clear".into()],
                subject_digest: Digest::parse("1".repeat(64)).unwrap(),
            },
            documents: Vec::new(),
        };
        let bundle = authority.review_bundle().unwrap();
        let request = HumanRuntimeRequest {
            request_id: HumanRequestId::parse("goal-completion-evidence-1").unwrap(),
            purpose: HumanPurpose::GoalCompletion,
            subject: HumanSubjectBinding {
                project_id: ProjectId::parse("project-a").unwrap(),
                kind: HumanSubjectKind::Goal,
                subject_id: "project-a".into(),
                ticket_run_id: None,
                revision: Revision(3),
                material_digest: authority.material_digest().unwrap(),
                configuration_digest: Digest::parse("a".repeat(64)).unwrap(),
                policy_digest: authority.policy_digest().unwrap(),
                bundle_digest: review_bundle_digest(&bundle).unwrap(),
            },
            question: "Review whether this goal is complete.".into(),
            choices: vec![
                HumanDecisionChoice::Approve,
                HumanDecisionChoice::RequestChanges,
            ],
            expires_at_unix: 200,
            review_bundle: bundle,
        };
        authority.validate_for(&request).unwrap();

        let mut stale_revision = request;
        stale_revision.subject.revision = Revision(4);
        assert!(authority.validate_for(&stale_revision).is_err());
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
