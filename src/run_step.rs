use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::time::Duration;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::adapters::rex::RexQualificationFixture;
use crate::config::Profile;
use crate::domain::ids::{AgentRunId, Digest, OperationId, ProjectId, RexBlockId, TicketRunId};
use crate::domain::types::{AgentAdapter, CommitMode, Role};
use crate::process::{self, ProcessError, ProcessIdentity, ProcessIdentityQuality, ProcessSignal};
use crate::providers;

const MAX_PROVIDER_STDOUT: usize = 8 * 1024 * 1024;
const MAX_PROVIDER_STDERR_TAIL: usize = 64 * 1024;
const MAX_RESULT_BYTES: usize = 1024 * 1024;
const PROCESS_SAMPLE_INTERVAL: Duration = Duration::from_millis(200);

pub trait ProcessObserver {
    type Identity: Clone + std::fmt::Debug + Eq + ProcessIdentityView;

    fn after_spawn(&mut self, _pid: u32) -> Result<(), String> {
        Ok(())
    }
    fn inspect(&mut self) -> Result<Vec<Self::Identity>, String>;
    fn try_wait(&mut self, child: &mut std::process::Child) -> std::io::Result<Option<ExitStatus>> {
        child.try_wait()
    }
    fn pid(identity: &Self::Identity) -> u32;
    fn group(identity: &Self::Identity) -> u32;
    fn capture_tree(&self, root_pid: u32, table: &[Self::Identity]) -> Vec<Self::Identity>;
    fn matching(
        &self,
        observed: &[Self::Identity],
        current: &[Self::Identity],
    ) -> Vec<Self::Identity>;
    fn signal_group_if_observed(
        &self,
        group: u32,
        observed: &[Self::Identity],
        current: &[Self::Identity],
        signal: ProcessSignal,
    ) -> Result<bool, String>;
}

/// Production observer backed by identity-checked process-table operations.
#[derive(Default)]
pub struct SystemProcessObserver;

impl ProcessObserver for SystemProcessObserver {
    type Identity = ProcessIdentity;

    fn inspect(&mut self) -> Result<Vec<Self::Identity>, String> {
        process::inspect_process_table().map_err(process_error_message)
    }

    fn pid(identity: &Self::Identity) -> u32 {
        identity.pid
    }

    fn group(identity: &Self::Identity) -> u32 {
        identity.process_group_id
    }

    fn capture_tree(&self, root_pid: u32, table: &[Self::Identity]) -> Vec<Self::Identity> {
        process::capture_process_tree(root_pid, table)
    }

    fn matching(
        &self,
        observed: &[Self::Identity],
        current: &[Self::Identity],
    ) -> Vec<Self::Identity> {
        process::matching_processes(observed, current)
    }

    fn signal_group_if_observed(
        &self,
        group: u32,
        observed: &[Self::Identity],
        current: &[Self::Identity],
        signal: ProcessSignal,
    ) -> Result<bool, String> {
        process::signal_process_group_if_observed(group, observed, current, signal)
            .map_err(process_error_message)
    }
}

fn process_error_message(error: ProcessError) -> String {
    error.to_string()
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunDescriptor {
    pub schema_version: u32,
    pub project_id: ProjectId,
    pub run_id: AgentRunId,
    pub operation_id: OperationId,
    pub role: Role,
    pub ticket_run_id: Option<TicketRunId>,
    pub expected_subject_revision: u64,
    pub attempt: u32,
    pub run_epoch: u64,
    pub controller_generation: u64,
    pub workspace: PathBuf,
    pub control_dir: PathBuf,
    pub rex_session_id: String,
    pub rex_block_id: RexBlockId,
    pub profile_digest: Digest,
    pub instruction_digest: Digest,
    pub plan_digest: Option<Digest>,
    pub environment_snapshot_id: Digest,
    /// Digest of the immutable host-published wake snapshot for this finite turn.
    pub wake_snapshot_digest: Digest,
    pub provider_capability: ProviderCapabilityEvidence,
    pub result_schema: Value,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
/// Untrusted launch-time copy of host qualification data.
///
/// The controller must load and verify the referenced immutable receipt before
/// authorizing this run; matching fields here only prevents accidental stale
/// profile/path reuse and is not a trust boundary against the same OS user.
pub struct ProviderCapabilityEvidence {
    pub schema_version: u32,
    pub adapter: AgentAdapter,
    pub profile_digest: Digest,
    pub version: String,
    pub executable_path: PathBuf,
    pub executable_digest: Digest,
    pub permission_mode: String,
    pub invocation_options_digest: Digest,
    pub commit_mode: CommitMode,
    pub schema_projection: providers::ProviderSchemaProjectionIdentity,
    pub receipt_digest: Digest,
    pub status: ProviderQualificationStatus,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderQualificationStatus {
    Verified,
    FixtureOnly,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConversationContinuation {
    pub provider: AgentAdapter,
    pub conversation_id: String,
    pub profile_digest: Digest,
    pub instruction_digest: Digest,
    pub workspace: PathBuf,
}

#[derive(Clone, Debug)]
pub struct TurnRequest {
    pub descriptor: RunDescriptor,
    pub profile: Profile,
    pub role_contract: String,
    pub prompt: String,
    pub environment: BTreeMap<OsString, OsString>,
    pub continuation: Option<ConversationContinuation>,
    pub shutdown_grace: Duration,
}

/// Host-created constraints for one isolated provider qualification turn.
///
/// This is crate-internal because only the controller's disposable doctor flow
/// may start a provider before a persisted qualification receipt exists.
#[allow(dead_code)]
pub(crate) struct DisposableQualificationContext {
    pub(crate) workspace_root: PathBuf,
    pub(crate) rex_fixture: RexQualificationFixture,
    pub(crate) deadline: Duration,
    pub(crate) expected_permission_mode: String,
    pub(crate) prompts_denied: bool,
}

/// Ephemeral authorization for exactly one disposable qualification request.
/// It is consumed by `run_qualification_turn` and is never persisted.
#[allow(dead_code)]
pub(crate) struct QualificationPermit {
    request_binding: Digest,
    context: DisposableQualificationContext,
    issued_at: std::time::Instant,
}

#[allow(dead_code)]
const MAX_QUALIFICATION_DEADLINE: Duration = Duration::from_secs(30 * 60);

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedProcess {
    pub pid: u32,
    pub parent_pid: u32,
    pub process_group_id: u32,
    pub start_identity: String,
    pub command: String,
    pub identity_quality: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupState {
    Confirmed,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TurnOutcome {
    Completed,
    ProviderFailed,
    TimedOut,
    Cancelled,
    MissingResult,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunReceipt {
    pub run_id: AgentRunId,
    pub attempt: u32,
    pub provider: AgentAdapter,
    pub effective_permission_mode: String,
    pub conversation_id: Option<String>,
    pub provider_version: Option<String>,
    pub capability_receipt_digest: Option<Digest>,
    pub schema_projection: providers::ProviderSchemaProjectionIdentity,
    pub launch_pid_hint: Option<u32>,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub cancellation_signal: Option<i32>,
    pub cleanup: CleanupState,
    pub cleanup_detail: Option<String>,
    pub processes: Vec<ObservedProcess>,
    pub result_digest: Option<Digest>,
    pub outcome: TurnOutcome,
}

#[derive(Clone, Debug)]
pub struct TurnResult {
    pub receipt: RunReceipt,
    pub structured_result: Option<Value>,
}

#[derive(Debug)]
pub enum RunError {
    Invalid(String),
    Io(std::io::Error),
    Process(String),
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(message) => write!(f, "invalid Agent run: {message}"),
            Self::Io(_) => f.write_str("Agent run I/O failed"),
            Self::Process(message) => write!(f, "Agent process state is unresolved: {message}"),
        }
    }
}

impl std::error::Error for RunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Invalid(_) | Self::Process(_) => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct PreparedTurn {
    pub executable: PathBuf,
    pub args: Vec<OsString>,
    pub environment: BTreeMap<OsString, OsString>,
    pub working_directory: PathBuf,
    pub timeout: Duration,
    pub shutdown_grace: Duration,
    pub effective_permission_mode: &'static str,
    pub conversation_id: Option<String>,
    pub provider_version: Option<String>,
    pub capability_receipt_digest: Option<Digest>,
    pub executable_digest: Digest,
    pub absolute_deadline: Option<std::time::Instant>,
}

#[allow(dead_code)]
pub(crate) struct ProfileRuntimeIdentity {
    pub(crate) adapter: AgentAdapter,
    pub(crate) executable_path: PathBuf,
    pub(crate) executable_digest: Digest,
    pub(crate) commit_mode: CommitMode,
    pub(crate) invocation_options_digest: Digest,
    pub(crate) effective_permission_mode: &'static str,
}

/// Returns the exact executable and invocation identity derived from an
/// applied profile. Callers must compare every field before trusting a stored
/// qualification receipt.
#[allow(dead_code)]
pub(crate) fn profile_runtime_identity(
    profile: &Profile,
) -> Result<ProfileRuntimeIdentity, RunError> {
    if profile.command.is_empty() || !Path::new(&profile.command[0]).is_absolute() {
        return Err(RunError::Invalid(
            "provider profile command must start with an absolute executable path".into(),
        ));
    }
    let executable_path = Path::new(&profile.command[0])
        .canonicalize()
        .map_err(RunError::Io)?;
    let invocation = providers::build_invocation(
        profile,
        "runtime identity probe",
        "runtime identity probe",
        &serde_json::json!({"type":"object"}),
        Path::new("qualification-schema.json"),
        None,
    )
    .map_err(RunError::Invalid)?;
    Ok(ProfileRuntimeIdentity {
        adapter: profile.adapter,
        executable_digest: hash_file(&executable_path)?,
        executable_path,
        commit_mode: profile.commit_mode,
        invocation_options_digest: invocation_options_digest(profile)?,
        effective_permission_mode: invocation.effective_mode,
    })
}

#[allow(dead_code)]
pub(crate) fn issue_qualification_permit(
    request: &TurnRequest,
    mut context: DisposableQualificationContext,
) -> Result<QualificationPermit, RunError> {
    validate_request(request)?;
    if request.descriptor.provider_capability.status != ProviderQualificationStatus::Unknown {
        return Err(RunError::Invalid(
            "qualification bootstrap requires unknown, not persisted provider evidence".into(),
        ));
    }
    if context.deadline.is_zero() || context.deadline > MAX_QUALIFICATION_DEADLINE {
        return Err(RunError::Invalid(
            "disposable qualification deadline must be positive and at most 30 minutes".into(),
        ));
    }
    let maximum_turn = Duration::from_secs(request.profile.turn_timeout_seconds)
        .checked_add(request.shutdown_grace)
        .ok_or_else(|| RunError::Invalid("qualification timeout overflow".into()))?;
    let cleanup_budget = request
        .shutdown_grace
        .checked_add(Duration::from_secs(7))
        .ok_or_else(|| RunError::Invalid("qualification cleanup budget overflow".into()))?;
    if maximum_turn
        .checked_add(cleanup_budget)
        .is_none_or(|minimum| minimum > context.deadline)
    {
        return Err(RunError::Invalid(
            "qualification deadline must cover the provider turn and bounded cleanup reserve"
                .into(),
        ));
    }
    if !context.prompts_denied {
        return Err(RunError::Invalid(
            "unattended qualification must deny provider permission prompts".into(),
        ));
    }
    let root = validate_disposable_paths(request, &context.workspace_root)?;
    context.workspace_root.clone_from(&root);
    if context.rex_fixture.session_id() != request.descriptor.rex_session_id
        || context.rex_fixture.block_id() != request.descriptor.rex_block_id.as_str()
        || context.rex_fixture.operation_id() != request.descriptor.run_id.as_str()
        || [
            context.rex_fixture.endpoint(),
            context.rex_fixture.instance_id(),
            context.rex_fixture.session_id(),
            context.rex_fixture.window_id(),
            context.rex_fixture.block_id(),
        ]
        .into_iter()
        .any(|value| value.trim().is_empty() || value.chars().any(char::is_control))
    {
        return Err(RunError::Invalid(
            "qualification request is not bound to its disposable Rex fixture".into(),
        ));
    }
    let runtime_identity = profile_runtime_identity(&request.profile)?;
    if runtime_identity.effective_permission_mode != context.expected_permission_mode {
        return Err(RunError::Invalid(
            "qualification permission policy does not match the provider invocation".into(),
        ));
    }
    validate_capability_evidence(
        request,
        runtime_identity.effective_permission_mode,
        false,
        true,
    )?;
    let request_binding = qualification_request_binding(request, &context)?;
    Ok(QualificationPermit {
        request_binding,
        context,
        issued_at: std::time::Instant::now(),
    })
}

#[allow(dead_code)]
pub(crate) fn run_qualification_turn<O: ProcessObserver>(
    request: &TurnRequest,
    permit: QualificationPermit,
    observer: &mut O,
) -> Result<TurnResult, RunError> {
    if request.descriptor.provider_capability.status != ProviderQualificationStatus::Unknown {
        return Err(RunError::Invalid(
            "qualification permit can only authorize an unknown provider profile".into(),
        ));
    }
    let context = permit.context;
    if permit.issued_at.elapsed() >= context.deadline
        || qualification_request_binding(request, &context)? != permit.request_binding
    {
        return Err(RunError::Invalid(
            "qualification permit expired or does not match this exact request".into(),
        ));
    }
    if validate_disposable_paths(request, &context.workspace_root)? != context.workspace_root {
        return Err(RunError::Invalid(
            "qualification workspace paths changed after permit issuance".into(),
        ));
    }
    let remaining = context.deadline.saturating_sub(permit.issued_at.elapsed());
    let maximum_turn = Duration::from_secs(request.profile.turn_timeout_seconds)
        .checked_add(request.shutdown_grace)
        .ok_or_else(|| RunError::Invalid("qualification timeout overflow".into()))?;
    if maximum_turn > remaining {
        return Err(RunError::Invalid(
            "qualification permit no longer has enough time for the bounded turn and cleanup grace"
                .into(),
        ));
    }
    let mut prepared = prepare_with_qualification(request, false, true)?;
    prepared.absolute_deadline = Some(permit.issued_at + context.deadline);
    run_prepared(request, prepared, observer)
}

pub fn prepare(request: &TurnRequest) -> Result<PreparedTurn, RunError> {
    prepare_with_qualification(request, false, false)
}

fn prepare_with_qualification(
    request: &TurnRequest,
    allow_fixture_qualification: bool,
    allow_unknown_qualification: bool,
) -> Result<PreparedTurn, RunError> {
    validate_request(request)?;
    let conversation_id = validate_continuation(request)?;
    let provider_schema = providers::project_result_schema(&request.descriptor.result_schema)
        .map_err(RunError::Invalid)?;
    let schema_path = if request.profile.adapter == AgentAdapter::Codex {
        let control_dir = request
            .descriptor
            .control_dir
            .canonicalize()
            .map_err(RunError::Io)?;
        Some(write_schema_snapshot(
            &control_dir,
            &provider_schema.schema,
        )?)
    } else {
        None
    };
    let mut invocation = providers::build_invocation(
        &request.profile,
        &request.role_contract,
        &request.prompt,
        &request.descriptor.result_schema,
        schema_path.as_deref().unwrap_or_else(|| Path::new("")),
        conversation_id.as_deref(),
    )
    .map_err(RunError::Invalid)?;
    let executable_digest = validate_capability_evidence(
        request,
        invocation.effective_mode,
        allow_fixture_qualification,
        allow_unknown_qualification,
    )?;
    invocation.executable = Path::new(&invocation.executable)
        .canonicalize()
        .map_err(RunError::Io)?;
    let environment = factory_environment(&request.environment, &request.descriptor)?;
    Ok(PreparedTurn {
        executable: invocation.executable,
        args: invocation.args,
        environment,
        working_directory: request
            .descriptor
            .workspace
            .canonicalize()
            .map_err(RunError::Io)?,
        timeout: Duration::from_secs(request.profile.turn_timeout_seconds),
        shutdown_grace: request.shutdown_grace,
        effective_permission_mode: invocation.effective_mode,
        conversation_id,
        provider_version: if request.descriptor.provider_capability.status
            == ProviderQualificationStatus::Unknown
        {
            None
        } else {
            Some(request.descriptor.provider_capability.version.clone())
        },
        capability_receipt_digest: if request.descriptor.provider_capability.status
            == ProviderQualificationStatus::Unknown
        {
            None
        } else {
            Some(
                request
                    .descriptor
                    .provider_capability
                    .receipt_digest
                    .clone(),
            )
        },
        executable_digest,
        absolute_deadline: None,
    })
}

pub fn run_turn<O: ProcessObserver>(
    request: &TurnRequest,
    observer: &mut O,
) -> Result<TurnResult, RunError> {
    run_turn_with_context(request, observer, RunContext::FactoryAgent)
}

/// Run one approved profile trial without granting factory Agent environment markers.
pub fn run_profile_trial_turn<O: ProcessObserver>(
    request: &TurnRequest,
    observer: &mut O,
) -> Result<TurnResult, RunError> {
    run_turn_with_context(request, observer, RunContext::ProfileTrial)
}

#[cfg(test)]
fn run_fixture_turn<O: ProcessObserver>(
    request: &TurnRequest,
    observer: &mut O,
) -> Result<TurnResult, RunError> {
    run_turn_with_qualification(request, observer, true)
}

#[derive(Clone, Copy)]
enum RunContext {
    FactoryAgent,
    ProfileTrial,
}

fn run_turn_with_qualification<O: ProcessObserver>(
    request: &TurnRequest,
    observer: &mut O,
    allow_fixture_qualification: bool,
) -> Result<TurnResult, RunError> {
    let prepared = prepare_with_qualification(request, allow_fixture_qualification, false)?;
    run_prepared(request, prepared, observer)
}

fn run_turn_with_context<O: ProcessObserver>(
    request: &TurnRequest,
    observer: &mut O,
    context: RunContext,
) -> Result<TurnResult, RunError> {
    let prepared = match context {
        RunContext::FactoryAgent => prepare_with_qualification(request, false, false)?,
        RunContext::ProfileTrial => prepare_for_profile_trial(request)?,
    };
    run_prepared(request, prepared, observer)
}

fn prepare_for_profile_trial(request: &TurnRequest) -> Result<PreparedTurn, RunError> {
    let mut prepared = prepare_with_qualification(request, false, false)?;
    prepared.environment = profile_trial_environment(&request.environment, &request.descriptor);
    Ok(prepared)
}

fn run_prepared<O: ProcessObserver>(
    request: &TurnRequest,
    prepared: PreparedTurn,
    observer: &mut O,
) -> Result<TurnResult, RunError> {
    #[cfg(unix)]
    let _signal_lock = SIGNAL_LOCK
        .lock()
        .map_err(|_| RunError::Process("process signal handler lock was poisoned".into()))?;
    #[cfg(unix)]
    let _signal_guard = SignalGuard::install()?;

    if hash_file(&prepared.executable)? != prepared.executable_digest {
        return Err(RunError::Invalid(
            "provider executable changed after capability qualification".into(),
        ));
    }
    let working_directory = canonical_real_directory(&prepared.working_directory, "workspace")?;
    if working_directory != prepared.working_directory {
        return Err(RunError::Invalid(
            "provider workspace path changed after preparation".into(),
        ));
    }
    let mut turn_timeout = if let Some(absolute_deadline) = prepared.absolute_deadline {
        let remaining = absolute_deadline.saturating_duration_since(std::time::Instant::now());
        let cleanup_budget = prepared
            .shutdown_grace
            .checked_add(Duration::from_secs(7))
            .ok_or_else(|| RunError::Invalid("qualification cleanup budget overflow".into()))?;
        if remaining <= cleanup_budget {
            return Err(RunError::Invalid(
                "qualification deadline leaves no bounded time for provider execution and cleanup"
                    .into(),
            ));
        }
        prepared.timeout.min(remaining - cleanup_budget)
    } else {
        prepared.timeout
    };
    let working_directory_handle = File::open(&working_directory).map_err(RunError::Io)?;
    let mut command = std::process::Command::new(&prepared.executable);
    command
        .args(&prepared.args)
        .current_dir(&working_directory)
        .env_clear()
        .envs(&prepared.environment)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        use std::os::unix::process::CommandExt;
        let working_directory_fd = working_directory_handle.as_raw_fd();
        // SAFETY: The descriptor remains open in the parent until `spawn`
        // returns, and this child hook only changes the child process cwd to
        // that already-open directory before exec.
        unsafe {
            command.pre_exec(move || {
                if libc::fchdir(working_directory_fd) == 0 {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error())
                }
            });
        }
        command.process_group(0);
    }
    if let Some(absolute_deadline) = prepared.absolute_deadline {
        let remaining = absolute_deadline.saturating_duration_since(std::time::Instant::now());
        let cleanup_budget = prepared
            .shutdown_grace
            .checked_add(Duration::from_secs(7))
            .ok_or_else(|| RunError::Invalid("qualification cleanup budget overflow".into()))?;
        if remaining <= cleanup_budget {
            return Err(RunError::Invalid(
                "qualification deadline leaves no bounded time for provider execution and cleanup"
                    .into(),
            ));
        }
        turn_timeout = turn_timeout.min(remaining - cleanup_budget);
    }
    let mut child = command.spawn().map_err(RunError::Io)?;
    let pid = child.id();
    let stdout = child.stdout.take().expect("provider stdout is piped");
    let stderr = child.stderr.take().expect("provider stderr is piped");
    let stdout_reader = std::thread::spawn(move || read_bounded(stdout, MAX_PROVIDER_STDOUT));
    let stderr_reader = std::thread::spawn(move || read_tail(stderr, MAX_PROVIDER_STDERR_TAIL));

    let registration_error = observer.after_spawn(pid).err();

    let initial_table = match observer.inspect() {
        Ok(table) => table,
        Err(error) => {
            let _child_stopped = stop_direct_child(&mut child, Duration::from_secs(3));
            discard_readers(stdout_reader, stderr_reader);
            return Ok(unresolved_receipt(
                request,
                &prepared,
                Some(registration_error.unwrap_or(error)),
                false,
                None,
                Some(pid),
                vec![unobserved_process_hint(pid)],
                CleanupState::Unknown,
            ));
        }
    };
    let Some(root) = initial_table.iter().find(|entry| O::pid(entry) == pid) else {
        let _child_stopped = stop_direct_child(&mut child, Duration::from_secs(3));
        discard_readers(stdout_reader, stderr_reader);
        let mut processes = vec![unobserved_process_hint(pid)];
        processes.extend(
            initial_table
                .iter()
                .filter(|entry| {
                    O::pid(entry) == pid || O::group(entry) == pid || entry.parent_pid() == pid
                })
                .cloned()
                .map(observed_process),
        );
        return Ok(unresolved_receipt(
            request,
            &prepared,
            Some(registration_error.unwrap_or_else(|| {
                "provider process identity was not observable at launch".into()
            })),
            false,
            None,
            Some(pid),
            processes,
            CleanupState::Unknown,
        ));
    };
    let root_identity = root.clone();
    let process_group = O::group(&root_identity);
    if process_group != pid {
        let _ = stop_direct_child(&mut child, Duration::from_secs(3));
        discard_readers(stdout_reader, stderr_reader);
        let observed = observer.capture_tree(pid, &initial_table);
        return Ok(unresolved_receipt(
            request,
            &prepared,
            Some("provider did not start in its own process group".into()),
            false,
            None,
            Some(pid),
            observed.into_iter().map(observed_process).collect(),
            CleanupState::Unknown,
        ));
    }
    let mut observed = observer.capture_tree(pid, &initial_table);
    if !observed.iter().any(|item| O::pid(item) == pid) {
        observed.push(root_identity);
    }
    if let Some(error) = registration_error {
        let cleanup = stop_observed_groups(
            observer,
            &mut child,
            process_group,
            &mut observed,
            &prepared,
        )
        .unwrap_or(false);
        discard_readers(stdout_reader, stderr_reader);
        return Ok(unresolved_receipt(
            request,
            &prepared,
            Some(error),
            false,
            None,
            Some(pid),
            observed.into_iter().map(observed_process).collect(),
            if cleanup {
                CleanupState::Confirmed
            } else {
                CleanupState::Unknown
            },
        ));
    }
    let started = std::time::Instant::now();
    let deadline = if let Some(absolute_deadline) = prepared.absolute_deadline {
        let cleanup_budget = prepared
            .shutdown_grace
            .checked_add(Duration::from_secs(7))
            .ok_or_else(|| RunError::Invalid("qualification cleanup budget overflow".into()))?;
        let remaining = absolute_deadline
            .saturating_duration_since(started)
            .saturating_sub(cleanup_budget);
        started + turn_timeout.min(remaining)
    } else {
        started + turn_timeout
    };
    let mut child_status = None;
    let mut outcome = TurnOutcome::ProviderFailed;
    let mut timed_out = false;
    let mut cancellation_signal = None;
    let mut cleanup_known = true;
    let mut inspection_error = None;

    loop {
        match observer.try_wait(&mut child) {
            Ok(Some(status)) => {
                child_status = Some(status);
                break;
            }
            Ok(None) => {}
            Err(error) => {
                inspection_error = Some(format!("cannot inspect provider wrapper exit: {error}"));
                cleanup_known = match stop_observed_groups(
                    observer,
                    &mut child,
                    process_group,
                    &mut observed,
                    &prepared,
                ) {
                    Ok(stopped) => stopped,
                    Err(cleanup_error) => {
                        inspection_error = Some(cleanup_error.to_string());
                        false
                    }
                };
                break;
            }
        }
        let table = match observer.inspect() {
            Ok(table) => table,
            Err(error) => {
                inspection_error = Some(error);
                cleanup_known = match stop_observed_groups(
                    observer,
                    &mut child,
                    process_group,
                    &mut observed,
                    &prepared,
                ) {
                    Ok(stopped) => stopped,
                    Err(cleanup_error) => {
                        inspection_error = Some(cleanup_error.to_string());
                        false
                    }
                };
                break;
            }
        };
        merge_observed(observer, pid, &table, &mut observed);
        #[cfg(unix)]
        let received = PENDING_SIGNAL.swap(0, std::sync::atomic::Ordering::Relaxed);
        #[cfg(not(unix))]
        let received = 0;
        if received != 0 {
            cancellation_signal = Some(received);
            outcome = TurnOutcome::Cancelled;
            cleanup_known = match stop_observed_groups(
                observer,
                &mut child,
                process_group,
                &mut observed,
                &prepared,
            ) {
                Ok(stopped) => stopped,
                Err(error) => {
                    inspection_error = Some(error.to_string());
                    false
                }
            };
            break;
        }
        if std::time::Instant::now() >= deadline {
            timed_out = true;
            outcome = TurnOutcome::TimedOut;
            cleanup_known = match stop_observed_groups(
                observer,
                &mut child,
                process_group,
                &mut observed,
                &prepared,
            ) {
                Ok(stopped) => stopped,
                Err(error) => {
                    inspection_error = Some(error.to_string());
                    false
                }
            };
            break;
        }
        std::thread::sleep(PROCESS_SAMPLE_INTERVAL);
    }

    if cleanup_known && !timed_out && cancellation_signal.is_none() {
        cleanup_known = match stop_observed_groups(
            observer,
            &mut child,
            process_group,
            &mut observed,
            &prepared,
        ) {
            Ok(stopped) => stopped,
            Err(error) => {
                inspection_error = Some(error.to_string());
                false
            }
        };
    }
    if let Some(status) = child_status {
        child_status = Some(status);
    } else if cleanup_known {
        match observer.try_wait(&mut child) {
            Ok(status) => child_status = status,
            Err(error) => {
                cleanup_known = false;
                inspection_error.get_or_insert_with(|| {
                    format!("cannot confirm provider wrapper exit: {error}")
                });
            }
        }
    }
    if child_status.is_none() {
        cleanup_known = false;
        inspection_error.get_or_insert_with(|| "provider wrapper exit was not confirmed".into());
    }

    let stdout = match join_reader(stdout_reader, Duration::from_millis(500)) {
        Some(Ok(result)) => result,
        Some(Err(error)) => {
            cleanup_known = false;
            inspection_error
                .get_or_insert_with(|| format!("provider stdout capture failed: {error}"));
            BoundedOutput {
                bytes: Vec::new(),
                truncated: true,
            }
        }
        None => {
            cleanup_known = false;
            inspection_error.get_or_insert_with(|| {
                "provider stdout pipe did not close after process cleanup".into()
            });
            BoundedOutput {
                bytes: Vec::new(),
                truncated: true,
            }
        }
    };
    let _stderr_tail = match join_reader(stderr_reader, Duration::from_millis(500)) {
        Some(Ok(result)) => result,
        Some(Err(error)) => {
            cleanup_known = false;
            inspection_error
                .get_or_insert_with(|| format!("provider stderr capture failed: {error}"));
            BoundedOutput {
                bytes: Vec::new(),
                truncated: true,
            }
        }
        None => {
            cleanup_known = false;
            inspection_error.get_or_insert_with(|| {
                "provider stderr pipe did not close after process cleanup".into()
            });
            BoundedOutput {
                bytes: Vec::new(),
                truncated: true,
            }
        }
    };
    let stdout_truncated = stdout.truncated;
    let stdout = stdout.bytes;
    let exit_code = child_status.as_ref().and_then(ExitStatus::code);
    let mut structured_result = None;
    let mut conversation_id = prepared.conversation_id.clone();
    if cleanup_known && !timed_out && cancellation_signal.is_none() && exit_code == Some(0) {
        if stdout_truncated || stdout.len() > MAX_RESULT_BYTES {
            outcome = TurnOutcome::MissingResult;
        } else {
            match providers::parse_result(
                request.profile.adapter,
                &stdout,
                &request.descriptor.result_schema,
            ) {
                Ok((observed_conversation, result)) => {
                    let conversation_matches = match (
                        request.continuation.as_ref(),
                        observed_conversation.as_deref(),
                    ) {
                        (None, Some(_)) => true,
                        (Some(previous), Some(current)) => previous.conversation_id == current,
                        _ => false,
                    };
                    if !conversation_matches {
                        outcome = TurnOutcome::MissingResult;
                    } else {
                        conversation_id = observed_conversation;
                        structured_result = Some(result);
                        outcome = TurnOutcome::Completed;
                    }
                }
                Err(_) => outcome = TurnOutcome::MissingResult,
            }
        }
    }
    if !cleanup_known {
        outcome = TurnOutcome::ProviderFailed;
        structured_result = None;
    }
    if prepared
        .absolute_deadline
        .is_some_and(|absolute| std::time::Instant::now() > absolute)
    {
        cleanup_known = false;
        outcome = TurnOutcome::ProviderFailed;
        structured_result = None;
        inspection_error.get_or_insert_with(|| "qualification deadline exceeded".into());
    }
    let result_digest = structured_result
        .as_ref()
        .and_then(|value| serde_json::to_vec(value).ok())
        .map(|bytes| sha256(&bytes));
    Ok(TurnResult {
        receipt: RunReceipt {
            run_id: request.descriptor.run_id.clone(),
            attempt: request.descriptor.attempt,
            provider: request.profile.adapter,
            effective_permission_mode: prepared.effective_permission_mode.to_owned(),
            conversation_id,
            provider_version: prepared.provider_version.clone(),
            capability_receipt_digest: prepared.capability_receipt_digest.clone(),
            schema_projection: request
                .descriptor
                .provider_capability
                .schema_projection
                .clone(),
            launch_pid_hint: Some(pid),
            exit_code,
            timed_out,
            cancellation_signal,
            cleanup: if cleanup_known {
                CleanupState::Confirmed
            } else {
                CleanupState::Unknown
            },
            cleanup_detail: inspection_error,
            processes: observed.into_iter().map(observed_process).collect(),
            result_digest,
            outcome,
        },
        structured_result,
    })
}

#[allow(clippy::too_many_arguments)]
fn unresolved_receipt(
    request: &TurnRequest,
    prepared: &PreparedTurn,
    error: Option<String>,
    timed_out: bool,
    cancellation_signal: Option<i32>,
    launch_pid_hint: Option<u32>,
    processes: Vec<ObservedProcess>,
    cleanup: CleanupState,
) -> TurnResult {
    TurnResult {
        receipt: RunReceipt {
            run_id: request.descriptor.run_id.clone(),
            attempt: request.descriptor.attempt,
            provider: request.profile.adapter,
            effective_permission_mode: prepared.effective_permission_mode.to_owned(),
            conversation_id: prepared.conversation_id.clone(),
            provider_version: prepared.provider_version.clone(),
            capability_receipt_digest: prepared.capability_receipt_digest.clone(),
            schema_projection: request
                .descriptor
                .provider_capability
                .schema_projection
                .clone(),
            launch_pid_hint,
            exit_code: None,
            timed_out,
            cancellation_signal,
            cleanup,
            cleanup_detail: error,
            processes,
            result_digest: None,
            outcome: TurnOutcome::ProviderFailed,
        },
        structured_result: None,
    }
}

fn unobserved_process_hint(pid: u32) -> ObservedProcess {
    ObservedProcess {
        pid,
        parent_pid: 0,
        process_group_id: 0,
        start_identity: String::new(),
        command: "unobserved-provider-child".into(),
        identity_quality: "unverified_pid_hint".into(),
    }
}

fn stop_direct_child(child: &mut std::process::Child, grace: Duration) -> bool {
    match child.try_wait() {
        Ok(Some(_)) => return true,
        Ok(None) => {}
        Err(_) => return false,
    }
    if child.kill().is_err() {
        return matches!(child.try_wait(), Ok(Some(_)));
    }
    let deadline = std::time::Instant::now() + grace;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return true,
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(PROCESS_SAMPLE_INTERVAL);
            }
            Ok(None) | Err(_) => return false,
        }
    }
}

fn discard_readers(
    stdout_reader: std::thread::JoinHandle<std::io::Result<BoundedOutput>>,
    stderr_reader: std::thread::JoinHandle<std::io::Result<BoundedOutput>>,
) {
    let _ = join_reader(stdout_reader, Duration::from_millis(100));
    let _ = join_reader(stderr_reader, Duration::from_millis(100));
}

fn observed_process<T>(identity: T) -> ObservedProcess
where
    T: ProcessIdentityView,
{
    ObservedProcess {
        pid: identity.pid(),
        parent_pid: identity.parent_pid(),
        process_group_id: identity.process_group_id(),
        start_identity: identity.start_identity().to_owned(),
        command: identity.command().to_owned(),
        identity_quality: identity.identity_quality().to_owned(),
    }
}

pub trait ProcessIdentityView {
    fn pid(&self) -> u32;
    fn parent_pid(&self) -> u32;
    fn process_group_id(&self) -> u32;
    fn start_identity(&self) -> &str;
    fn command(&self) -> &str;
    fn identity_quality(&self) -> &'static str;
}

impl ProcessIdentityView for ProcessIdentity {
    fn pid(&self) -> u32 {
        self.pid
    }
    fn parent_pid(&self) -> u32 {
        self.parent_pid
    }
    fn process_group_id(&self) -> u32 {
        self.process_group_id
    }
    fn start_identity(&self) -> &str {
        &self.start_identity
    }
    fn command(&self) -> &str {
        &self.command
    }
    fn identity_quality(&self) -> &'static str {
        match self.quality {
            ProcessIdentityQuality::KernelBirthToken => "kernel_birth_token",
            ProcessIdentityQuality::SecondPrecision => "second_precision",
        }
    }
}

fn merge_observed<O: ProcessObserver>(
    observer: &O,
    root_pid: u32,
    current: &[O::Identity],
    observed: &mut Vec<O::Identity>,
) {
    for identity in observer.capture_tree(root_pid, current) {
        if !observed.contains(&identity) {
            observed.push(identity);
        }
    }
}

fn stop_observed_groups<O: ProcessObserver>(
    observer: &mut O,
    child: &mut std::process::Child,
    process_group: u32,
    observed: &mut Vec<O::Identity>,
    prepared: &PreparedTurn,
) -> Result<bool, RunError> {
    let current = observer.inspect().map_err(RunError::Process)?;
    let groups = observed
        .iter()
        .map(O::group)
        .filter(|group| *group != 0)
        .collect::<std::collections::BTreeSet<_>>();
    for group in groups {
        observer
            .signal_group_if_observed(group, observed, &current, ProcessSignal::Interrupt)
            .map_err(RunError::Process)?;
    }
    if observe_until_stopped(
        observer,
        child,
        process_group,
        observed,
        prepared.shutdown_grace,
    )? {
        return Ok(true);
    }
    signal_groups(observer, observed, ProcessSignal::Terminate)?;
    if observe_until_stopped(
        observer,
        child,
        process_group,
        observed,
        Duration::from_secs(3),
    )? {
        return Ok(true);
    }
    signal_groups(observer, observed, ProcessSignal::Kill)?;
    observe_until_stopped(
        observer,
        child,
        process_group,
        observed,
        Duration::from_secs(3),
    )
}

fn signal_groups<O: ProcessObserver>(
    observer: &mut O,
    observed: &[O::Identity],
    signal: ProcessSignal,
) -> Result<(), RunError> {
    let current = observer.inspect().map_err(RunError::Process)?;
    let groups = observed
        .iter()
        .map(O::group)
        .filter(|group| *group != 0)
        .collect::<std::collections::BTreeSet<_>>();
    for group in groups {
        observer
            .signal_group_if_observed(group, observed, &current, signal)
            .map_err(RunError::Process)?;
    }
    Ok(())
}

fn observe_until_stopped<O: ProcessObserver>(
    observer: &mut O,
    child: &mut std::process::Child,
    root_group: u32,
    observed: &mut Vec<O::Identity>,
    grace: Duration,
) -> Result<bool, RunError> {
    let deadline = std::time::Instant::now() + grace;
    loop {
        // Reap the wrapper as soon as it exits so zombie entries do not keep
        // the observed process identity alive indefinitely.
        let _ = observer.try_wait(child);
        let current = observer.inspect().map_err(RunError::Process)?;
        let root = observed
            .iter()
            .find(|identity| O::group(identity) == root_group)
            .map(O::pid)
            .unwrap_or(root_group);
        merge_observed(observer, root, &current, observed);
        let live = observer.matching(observed, &current);
        if live.is_empty() {
            return Ok(true);
        }
        if std::time::Instant::now() >= deadline {
            return Ok(false);
        }
        std::thread::sleep(PROCESS_SAMPLE_INTERVAL);
    }
}

struct BoundedOutput {
    bytes: Vec<u8>,
    truncated: bool,
}

fn read_bounded(mut reader: impl std::io::Read, limit: usize) -> std::io::Result<BoundedOutput> {
    let mut bytes = Vec::with_capacity(limit.min(8192));
    let mut buffer = [0_u8; 8192];
    let mut truncated = false;
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            return Ok(BoundedOutput { bytes, truncated });
        }
        let remaining = limit.saturating_sub(bytes.len());
        bytes.extend_from_slice(&buffer[..count.min(remaining)]);
        truncated |= count > remaining;
    }
}

fn read_tail(mut reader: impl std::io::Read, limit: usize) -> std::io::Result<BoundedOutput> {
    let mut bytes = Vec::with_capacity(limit.min(8192));
    let mut buffer = [0_u8; 8192];
    let mut truncated = false;
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            return Ok(BoundedOutput { bytes, truncated });
        }
        if count >= limit {
            bytes.clear();
            bytes.extend_from_slice(&buffer[count - limit..count]);
            truncated = true;
            continue;
        }
        let overflow = bytes.len().saturating_add(count).saturating_sub(limit);
        if overflow > 0 {
            bytes.drain(..overflow);
            truncated = true;
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
}

fn join_reader<T>(
    handle: std::thread::JoinHandle<std::io::Result<T>>,
    timeout: Duration,
) -> Option<std::io::Result<T>> {
    let deadline = std::time::Instant::now() + timeout;
    while !handle.is_finished() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    handle.is_finished().then(|| {
        handle
            .join()
            .unwrap_or_else(|_| Err(std::io::Error::other("provider output reader panicked")))
    })
}

fn sha256(bytes: &[u8]) -> Digest {
    use sha2::{Digest as _, Sha256};
    Digest::parse(format!("{:x}", Sha256::digest(bytes))).expect("SHA-256 has canonical hex")
}

#[cfg(unix)]
static SIGNAL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
#[cfg(unix)]
static PENDING_SIGNAL: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

#[cfg(unix)]
extern "C" fn record_signal(signal: libc::c_int) {
    PENDING_SIGNAL.store(signal, std::sync::atomic::Ordering::Relaxed);
}

#[cfg(unix)]
struct SignalGuard {
    previous: Vec<(libc::c_int, libc::sighandler_t)>,
}

#[cfg(unix)]
impl SignalGuard {
    fn install() -> Result<Self, RunError> {
        use std::mem;
        PENDING_SIGNAL.store(0, std::sync::atomic::Ordering::Relaxed);
        let mut previous = Vec::new();
        for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            // SAFETY: the handler only stores a signal number in an atomic and
            // the previous process-local handlers are restored by Drop.
            let old =
                unsafe { libc::signal(signal, record_signal as *const () as libc::sighandler_t) };
            if old == libc::SIG_ERR {
                for (installed, handler) in previous.drain(..) {
                    // SAFETY: restores a handler returned by libc::signal.
                    unsafe { libc::signal(installed, handler) };
                }
                return Err(RunError::Process(
                    "cannot install cancellation signal handler".into(),
                ));
            }
            let _ = mem::size_of_val(&old);
            previous.push((signal, old));
        }
        Ok(Self { previous })
    }
}

#[cfg(unix)]
impl Drop for SignalGuard {
    fn drop(&mut self) {
        for (signal, handler) in self.previous.drain(..) {
            // SAFETY: `handler` is the exact process-local handler returned by
            // libc::signal before this guard installed its temporary handler.
            unsafe { libc::signal(signal, handler) };
        }
    }
}

fn validate_request(request: &TurnRequest) -> Result<(), RunError> {
    let descriptor = &request.descriptor;
    if descriptor.schema_version != 1 || descriptor.attempt == 0 || descriptor.run_epoch == 0 {
        return Err(RunError::Invalid(
            "unsupported descriptor or invalid run epoch".into(),
        ));
    }
    if descriptor.controller_generation == 0 {
        return Err(RunError::Invalid(
            "controller generation must be positive".into(),
        ));
    }
    if descriptor.rex_session_id.is_empty()
        || descriptor.rex_session_id.chars().any(char::is_control)
        || request.shutdown_grace.is_zero()
        || request.profile.turn_timeout_seconds == 0
    {
        return Err(RunError::Invalid(
            "invalid Rex identity or process timeout".into(),
        ));
    }
    if request.profile.command.is_empty()
        || !Path::new(&request.profile.command[0]).is_absolute()
        || !Path::new(&request.profile.command[0]).is_file()
    {
        return Err(RunError::Invalid(
            "provider executable must be the resolved absolute regular file from the applied profile".into(),
        ));
    }
    if request.role_contract.trim().is_empty() || request.prompt.trim().is_empty() {
        return Err(RunError::Invalid(
            "role contract and prompt must be non-empty".into(),
        ));
    }
    if serde_json::to_vec(&descriptor.result_schema)
        .map_err(|e| RunError::Invalid(e.to_string()))?
        .len()
        > 256 * 1024
    {
        return Err(RunError::Invalid("result schema exceeds 256 KiB".into()));
    }
    providers::validate_schema_definition(&descriptor.result_schema).map_err(RunError::Invalid)?;
    let workspace = descriptor.workspace.canonicalize().map_err(RunError::Io)?;
    if !workspace.is_dir() {
        return Err(RunError::Invalid(
            "assigned workspace is not a directory".into(),
        ));
    }
    if !descriptor.control_dir.is_absolute() {
        return Err(RunError::Invalid(
            "control directory must be absolute".into(),
        ));
    }
    Ok(())
}

fn validate_continuation(request: &TurnRequest) -> Result<Option<String>, RunError> {
    let Some(continuation) = &request.continuation else {
        return Ok(None);
    };
    let descriptor = &request.descriptor;
    if continuation.provider != request.profile.adapter
        || continuation.profile_digest != descriptor.profile_digest
        || continuation.instruction_digest != descriptor.instruction_digest
        || continuation.workspace != descriptor.workspace
    {
        return Err(RunError::Invalid(
            "native conversation cannot resume under a changed provider, profile, instruction set, or workspace".into(),
        ));
    }
    if continuation.conversation_id.is_empty()
        || continuation.conversation_id.len() > 256
        || continuation.conversation_id.chars().any(char::is_control)
    {
        return Err(RunError::Invalid(
            "native conversation identity is malformed".into(),
        ));
    }
    Ok(Some(continuation.conversation_id.clone()))
}

fn validate_capability_evidence(
    request: &TurnRequest,
    effective_permission_mode: &str,
    allow_fixture_qualification: bool,
    allow_unknown_qualification: bool,
) -> Result<Digest, RunError> {
    let evidence = &request.descriptor.provider_capability;
    let expected_projection = providers::project_result_schema(&request.descriptor.result_schema)
        .map_err(RunError::Invalid)?
        .identity;
    let expected_executable = Path::new(&request.profile.command[0])
        .canonicalize()
        .map_err(RunError::Io)?;
    if evidence.schema_version != 1
        || evidence.adapter != request.profile.adapter
        || evidence.profile_digest != request.descriptor.profile_digest
        || evidence.version.trim().is_empty()
        || evidence.version.len() > 128
        || evidence.permission_mode != effective_permission_mode
        || evidence.commit_mode != request.profile.commit_mode
        || evidence.invocation_options_digest != invocation_options_digest(&request.profile)?
        || evidence.schema_projection != expected_projection
        || !evidence.executable_path.is_absolute()
        || evidence.executable_path != expected_executable
    {
        return Err(RunError::Invalid(
            "provider capability evidence does not match this run descriptor and profile".into(),
        ));
    }
    match evidence.status {
        ProviderQualificationStatus::Verified => {}
        ProviderQualificationStatus::FixtureOnly if allow_fixture_qualification => {}
        ProviderQualificationStatus::Unknown if allow_unknown_qualification => {}
        ProviderQualificationStatus::FixtureOnly | ProviderQualificationStatus::Unknown => {
            return Err(RunError::Invalid(
                "provider profile lacks verified unattended qualification".into(),
            ));
        }
    }
    let actual_digest = hash_file(&expected_executable)?;
    if actual_digest != evidence.executable_digest {
        return Err(RunError::Invalid(
            "provider executable digest differs from capability qualification".into(),
        ));
    }
    Ok(actual_digest)
}

pub(crate) fn invocation_options_digest(profile: &Profile) -> Result<Digest, RunError> {
    let bytes = serde_json::to_vec(&serde_json::json!({
        "adapter": profile.adapter,
        "command": profile.command,
        "model": profile.model,
        "effort": profile.effort,
        "options": profile.options,
        "commit_mode": profile.commit_mode,
    }))
    .map_err(|error| RunError::Invalid(error.to_string()))?;
    Ok(sha256(&bytes))
}

#[allow(dead_code)]
fn canonical_real_directory(path: &Path, name: &str) -> Result<PathBuf, RunError> {
    let metadata = fs::symlink_metadata(path).map_err(RunError::Io)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(RunError::Invalid(format!(
            "qualification {name} must be an existing real directory"
        )));
    }
    path.canonicalize().map_err(RunError::Io)
}

#[allow(dead_code)]
fn validate_disposable_paths(
    request: &TurnRequest,
    workspace_root: &Path,
) -> Result<PathBuf, RunError> {
    let root = canonical_real_directory(workspace_root, "disposable root")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::metadata(&root).map_err(RunError::Io)?;
        // SAFETY: `geteuid` reads the current effective UID and has no preconditions.
        let effective_uid = unsafe { libc::geteuid() };
        if metadata.uid() != effective_uid || metadata.mode() & 0o077 != 0 {
            return Err(RunError::Invalid(
                "disposable qualification root must be owned by this user and private".into(),
            ));
        }
    }
    let workspace = canonical_real_directory(&request.descriptor.workspace, "workspace")?;
    let control_dir =
        canonical_real_directory(&request.descriptor.control_dir, "control directory")?;
    if workspace == root
        || workspace.parent() != Some(root.as_path())
        || control_dir == root
        || control_dir.parent() != Some(root.as_path())
        || workspace == control_dir
    {
        return Err(RunError::Invalid(
            "qualification workspace and control directory must be distinct sibling directories under the disposable root".into(),
        ));
    }
    if fs::read_dir(&workspace)
        .map_err(RunError::Io)?
        .next()
        .is_some()
    {
        return Err(RunError::Invalid(
            "qualification workspace must be empty before provider launch".into(),
        ));
    }
    Ok(root)
}

#[allow(dead_code)]
fn qualification_request_binding(
    request: &TurnRequest,
    context: &DisposableQualificationContext,
) -> Result<Digest, RunError> {
    use sha2::Digest as _;

    let mut environment_hasher = sha2::Sha256::new();
    for (key, value) in &request.environment {
        for bytes in [key.as_encoded_bytes(), value.as_encoded_bytes()] {
            environment_hasher.update((bytes.len() as u64).to_le_bytes());
            environment_hasher.update(bytes);
        }
    }
    let environment_digest = Digest::parse(format!("{:x}", environment_hasher.finalize()))
        .map_err(|error| RunError::Invalid(error.to_string()))?;
    let serialized = serde_json::to_vec(&serde_json::json!({
        "descriptor": request.descriptor,
        "profile": request.profile,
        "role_contract_digest": sha256(request.role_contract.as_bytes()),
        "prompt_digest": sha256(request.prompt.as_bytes()),
        "environment_digest": environment_digest,
        "continuation": request.continuation,
        "shutdown_grace_millis": request.shutdown_grace.as_millis(),
        "workspace_root": context.workspace_root,
        "rex_endpoint": context.rex_fixture.endpoint(),
        "rex_instance_id": context.rex_fixture.instance_id(),
        "rex_session_id": context.rex_fixture.session_id(),
        "rex_window_id": context.rex_fixture.window_id(),
        "rex_block_id": context.rex_fixture.block_id(),
        "rex_operation_id": context.rex_fixture.operation_id(),
        "deadline_millis": context.deadline.as_millis(),
        "expected_permission_mode": context.expected_permission_mode,
        "prompts_denied": context.prompts_denied,
    }))
    .map_err(|error| RunError::Invalid(error.to_string()))?;
    Ok(sha256(&serialized))
}

fn hash_file(path: &Path) -> Result<Digest, RunError> {
    use sha2::Digest as _;

    let metadata = fs::symlink_metadata(path).map_err(RunError::Io)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > 1024 * 1024 * 1024
    {
        return Err(RunError::Invalid(
            "provider executable must be a regular file below the 1 GiB limit".into(),
        ));
    }
    let mut file = File::open(path).map_err(RunError::Io)?;
    let mut hasher = sha2::Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(RunError::Io)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Digest::parse(format!("{:x}", hasher.finalize()))
        .map_err(|error| RunError::Invalid(error.to_string()))
}

fn factory_environment(
    snapshot: &BTreeMap<OsString, OsString>,
    descriptor: &RunDescriptor,
) -> Result<BTreeMap<OsString, OsString>, RunError> {
    let mut environment = snapshot
        .iter()
        .filter(|(key, _)| {
            let key = key.to_string_lossy();
            !key.starts_with("REX_PROJECTS_")
                && !matches!(
                    key.as_ref(),
                    "GIT_DIR"
                        | "GIT_WORK_TREE"
                        | "GIT_INDEX_FILE"
                        | "GIT_COMMON_DIR"
                        | "GIT_OBJECT_DIRECTORY"
                        | "GIT_ALTERNATE_OBJECT_DIRECTORIES"
                        | "GIT_CONFIG_GLOBAL"
                        | "GIT_CONFIG_SYSTEM"
                        | "GIT_CONFIG_COUNT"
                        | "GIT_CONFIG_PARAMETERS"
                )
        })
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<BTreeMap<_, _>>();
    for (key, value) in [
        ("GIT_CONFIG_GLOBAL", "/dev/null"),
        ("GIT_CONFIG_SYSTEM", "/dev/null"),
        ("GIT_TERMINAL_PROMPT", "0"),
    ] {
        environment.insert(OsString::from(key), OsString::from(value));
    }
    for (key, value) in [
        ("REX_PROJECTS_CONTEXT", "agent"),
        ("REX_PROJECTS_AGENT", "1"),
        ("REX_PROJECTS_PROJECT_ID", descriptor.project_id.as_str()),
        ("REX_PROJECTS_ROLE", role_name(descriptor.role)),
        ("REX_PROJECTS_RUN_ID", descriptor.run_id.as_str()),
        (
            "REX_PROJECTS_OPERATION_ID",
            descriptor.operation_id.as_str(),
        ),
    ] {
        environment.insert(OsString::from(key), OsString::from(value));
    }
    environment.insert(
        OsString::from("REX_PROJECTS_ATTEMPT"),
        OsString::from(descriptor.attempt.to_string()),
    );
    environment.insert(
        OsString::from("REX_PROJECTS_RUN_EPOCH"),
        OsString::from(descriptor.run_epoch.to_string()),
    );
    environment.insert(
        OsString::from("REX_PROJECTS_SUBJECT_REVISION"),
        OsString::from(descriptor.expected_subject_revision.to_string()),
    );
    environment.insert(
        OsString::from("REX_PROJECTS_CONTROL_DIR"),
        descriptor.control_dir.as_os_str().to_owned(),
    );
    if let Some(ticket_run_id) = &descriptor.ticket_run_id {
        environment.insert(
            OsString::from("REX_PROJECTS_TICKET_RUN_ID"),
            OsString::from(ticket_run_id.as_str()),
        );
    }
    environment.insert(
        OsString::from("REX_SESSION"),
        OsString::from(&descriptor.rex_session_id),
    );
    environment.insert(
        OsString::from("REX_BLOCK"),
        OsString::from(descriptor.rex_block_id.as_str()),
    );
    environment.insert(
        OsString::from("REX_BLOCK_ID"),
        OsString::from(descriptor.rex_block_id.as_str()),
    );
    Ok(environment)
}

fn profile_trial_environment(
    snapshot: &BTreeMap<OsString, OsString>,
    descriptor: &RunDescriptor,
) -> BTreeMap<OsString, OsString> {
    let mut environment = snapshot
        .iter()
        .filter(|(key, _)| !key.to_string_lossy().starts_with("REX_PROJECTS_"))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<BTreeMap<_, _>>();
    for (key, value) in [
        ("REX_PROJECTS_CONTEXT", "profile_trial"),
        ("REX_PROJECTS_AGENT", "0"),
        ("REX_SESSION", descriptor.rex_session_id.as_str()),
        ("REX_BLOCK", descriptor.rex_block_id.as_str()),
        ("REX_BLOCK_ID", descriptor.rex_block_id.as_str()),
    ] {
        environment.insert(OsString::from(key), OsString::from(value));
    }
    environment
}

fn role_name(role: Role) -> &'static str {
    match role {
        Role::Supervisor => "supervisor",
        Role::Coordinator => "coordinator",
        Role::Planner => "planner",
        Role::Worker => "worker",
        Role::Reviewer => "reviewer",
        Role::MergeDecision => "merge_decision",
        Role::Operator => "operator",
        Role::Postmortem => "postmortem",
    }
}

fn write_schema_snapshot(control_dir: &Path, schema: &Value) -> Result<PathBuf, RunError> {
    let metadata = fs::symlink_metadata(control_dir).map_err(RunError::Io)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(RunError::Invalid(
            "result schema control path must be an existing real directory".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(control_dir, fs::Permissions::from_mode(0o700))
            .map_err(RunError::Io)?;
    }
    let directory = control_dir.canonicalize().map_err(RunError::Io)?;
    let path = directory.join("result.schema.json");
    let bytes = serde_json::to_vec(schema).map_err(|e| RunError::Invalid(e.to_string()))?;
    match OpenOptions::new().write(true).create_new(true).open(&path) {
        Ok(mut file) => {
            set_private_mode(&file, 0o400)?;
            file.write_all(&bytes).map_err(RunError::Io)?;
            file.sync_all().map_err(RunError::Io)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(&path).map_err(RunError::Io)?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(RunError::Invalid(
                    "existing result schema snapshot is not a regular file".into(),
                ));
            }
            let existing = fs::read(&path).map_err(RunError::Io)?;
            if existing != bytes {
                return Err(RunError::Invalid(
                    "existing result schema snapshot differs from this run".into(),
                ));
            }
        }
        Err(error) => return Err(RunError::Io(error)),
    }
    Ok(path)
}

fn set_private_mode(file: &std::fs::File, mode: u32) -> Result<(), RunError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(mode))
            .map_err(RunError::Io)?;
    }
    #[cfg(not(unix))]
    let _ = (file, mode);
    Ok(())
}

#[cfg(test)]
mod tests {
    static TEST_RUN_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    use std::collections::BTreeMap;
    use std::ffi::{OsStr, OsString};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::ExitStatus;
    use std::time::Duration;

    use serde_json::{Value, json};
    use tempfile::tempdir;

    use crate::config::{ClaudeCodeOptions, CodexOptions, Profile};
    use crate::domain::ids::{AgentRunId, Digest, OperationId, ProjectId, RexBlockId, TicketRunId};
    use crate::domain::types::{AgentAdapter, CommitMode, Role};
    use crate::process::{self, ProcessIdentity};

    use super::{
        CleanupState, ConversationContinuation, DisposableQualificationContext, ObservedProcess,
        ProcessObserver, ProcessSignal, ProviderCapabilityEvidence, ProviderQualificationStatus,
        RunDescriptor, RunReceipt, SystemProcessObserver, TurnOutcome, TurnRequest,
        factory_environment, issue_qualification_permit, prepare, prepare_with_qualification,
        run_fixture_turn, run_qualification_turn, run_turn,
    };

    #[test]
    fn run_receipt_spool_round_trips_strictly() {
        let receipt = RunReceipt {
            run_id: AgentRunId::parse("run-a").unwrap(),
            attempt: 1,
            provider: AgentAdapter::ClaudeCode,
            effective_permission_mode: "auto".into(),
            conversation_id: Some("conversation-a".into()),
            provider_version: None,
            capability_receipt_digest: None,
            schema_projection: crate::providers::project_result_schema(&json!({"type":"object"}))
                .unwrap()
                .identity,
            launch_pid_hint: Some(42),
            exit_code: Some(0),
            timed_out: false,
            cancellation_signal: None,
            cleanup: CleanupState::Confirmed,
            cleanup_detail: None,
            processes: vec![ObservedProcess {
                pid: 42,
                parent_pid: 1,
                process_group_id: 42,
                start_identity: "birth-token".into(),
                command: "claude".into(),
                identity_quality: "kernel_birth_token".into(),
            }],
            result_digest: Some(Digest::parse("b".repeat(64)).unwrap()),
            outcome: TurnOutcome::Completed,
        };
        let json = serde_json::to_value(&receipt).unwrap();
        let decoded: RunReceipt = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(serde_json::to_value(decoded).unwrap(), json);

        let mut extra_receipt_field = json.clone();
        extra_receipt_field["unrecognized"] = json!(true);
        assert!(serde_json::from_value::<RunReceipt>(extra_receipt_field).is_err());

        let mut extra_process_field = json;
        extra_process_field["processes"][0]["unrecognized"] = json!(true);
        assert!(serde_json::from_value::<RunReceipt>(extra_process_field).is_err());
    }

    fn profile(adapter: AgentAdapter, command: &str) -> Profile {
        Profile {
            adapter,
            command: vec![command.into()],
            description: None,
            model: Some("model-a".into()),
            effort: Some("high".into()),
            turn_timeout_seconds: 60,
            instruction_files: vec![],
            skill_paths: vec![],
            commit_mode: CommitMode::Auto,
            learned_guidance: None,
            options: match adapter {
                AgentAdapter::Codex => {
                    Some(crate::config::ProfileOptions::Codex(CodexOptions::default()))
                }
                AgentAdapter::ClaudeCode => Some(crate::config::ProfileOptions::ClaudeCode(
                    ClaudeCodeOptions::default(),
                )),
            },
        }
    }

    fn descriptor(root: &Path, profile: &Profile) -> RunDescriptor {
        let profile_digest = Digest::parse("a".repeat(64)).unwrap();
        let result_schema = json!({"type":"object","properties":{"ok":{"type":"boolean"}},"required":["ok"],"additionalProperties":false});
        RunDescriptor {
            schema_version: 1,
            project_id: ProjectId::parse("project-a").unwrap(),
            run_id: AgentRunId::parse("run-a").unwrap(),
            operation_id: OperationId::parse("operation-a").unwrap(),
            role: Role::Worker,
            ticket_run_id: Some(TicketRunId::parse("ticket-run-a").unwrap()),
            expected_subject_revision: 1,
            attempt: 1,
            run_epoch: 2,
            controller_generation: 3,
            workspace: root.join("workspace"),
            control_dir: root.join("control"),
            rex_session_id: "session-a".into(),
            rex_block_id: RexBlockId::parse("block-a").unwrap(),
            profile_digest: profile_digest.clone(),
            instruction_digest: Digest::parse("b".repeat(64)).unwrap(),
            plan_digest: None,
            environment_snapshot_id: Digest::parse("c".repeat(64)).unwrap(),
            wake_snapshot_digest: Digest::parse("d".repeat(64)).unwrap(),
            provider_capability: fixture_capability(profile, profile_digest, &result_schema),
            result_schema,
        }
    }

    fn request(root: &Path, adapter: AgentAdapter, command: &str) -> TurnRequest {
        fs::create_dir_all(root.join("workspace")).unwrap();
        fs::create_dir_all(root.join("control")).unwrap();
        let profile = profile(adapter, command);
        TurnRequest {
            descriptor: descriptor(root, &profile),
            profile,
            role_contract: "Worker must use the mailbox".into(),
            prompt: "Do the assigned work".into(),
            environment: BTreeMap::from([
                (OsString::from("PATH"), OsString::from("/usr/bin")),
                (
                    OsString::from("REX_PROJECTS_AGENT"),
                    OsString::from("stale"),
                ),
                (OsString::from("REX_SESSION"), OsString::from("old-session")),
            ]),
            continuation: None,
            shutdown_grace: Duration::from_secs(3),
        }
    }

    fn fixture_capability(
        profile: &Profile,
        profile_digest: Digest,
        result_schema: &Value,
    ) -> ProviderCapabilityEvidence {
        let executable_path = Path::new(&profile.command[0]).canonicalize().unwrap();
        let permission_mode = match profile.adapter {
            AgentAdapter::Codex => "workspace-write; approvals never; automatic provider execution",
            AgentAdapter::ClaudeCode => "auto; permission prompts denied unattended",
        };
        ProviderCapabilityEvidence {
            schema_version: 1,
            adapter: profile.adapter,
            profile_digest,
            version: "fixture-1".into(),
            executable_digest: super::hash_file(&executable_path).unwrap(),
            executable_path,
            permission_mode: permission_mode.into(),
            invocation_options_digest: super::invocation_options_digest(profile).unwrap(),
            commit_mode: profile.commit_mode,
            schema_projection: crate::providers::project_result_schema(result_schema)
                .unwrap()
                .identity,
            receipt_digest: Digest::parse("e".repeat(64)).unwrap(),
            status: ProviderQualificationStatus::FixtureOnly,
        }
    }

    #[cfg(unix)]
    fn executable() -> PathBuf {
        PathBuf::from("/bin/sh")
    }

    #[cfg(unix)]
    #[derive(Clone, Debug, Eq, PartialEq)]
    struct TestIdentity {
        pid: u32,
        group: u32,
        command: String,
    }

    #[cfg(unix)]
    impl super::ProcessIdentityView for TestIdentity {
        fn pid(&self) -> u32 {
            self.pid
        }
        fn parent_pid(&self) -> u32 {
            std::process::id()
        }
        fn process_group_id(&self) -> u32 {
            self.group
        }
        fn start_identity(&self) -> &str {
            "test-only-process-identity"
        }
        fn command(&self) -> &str {
            &self.command
        }
        fn identity_quality(&self) -> &'static str {
            "test_only"
        }
    }

    #[cfg(unix)]
    #[derive(Default)]
    struct TestObserver {
        root_pid: Option<u32>,
        kill_marker: Option<PathBuf>,
        signals: std::sync::Arc<std::sync::Mutex<Vec<ProcessSignal>>>,
        fail_registration: bool,
        fail_inspection: bool,
        hide_root: bool,
        wrong_group: bool,
        fail_wait_once: bool,
        after_spawn_delay: Duration,
    }

    #[cfg(unix)]
    struct DelayedSystemObserver {
        after_spawn_delay: Duration,
        root_pid: Option<u32>,
    }

    #[cfg(unix)]
    impl ProcessObserver for DelayedSystemObserver {
        type Identity = ProcessIdentity;

        fn after_spawn(&mut self, pid: u32) -> Result<(), String> {
            self.root_pid = Some(pid);
            std::thread::sleep(self.after_spawn_delay);
            Ok(())
        }

        fn inspect(&mut self) -> Result<Vec<Self::Identity>, String> {
            process::inspect_process_table().map_err(|error| error.to_string())
        }

        fn pid(identity: &Self::Identity) -> u32 {
            identity.pid
        }

        fn group(identity: &Self::Identity) -> u32 {
            identity.process_group_id
        }

        fn capture_tree(&self, root_pid: u32, table: &[Self::Identity]) -> Vec<Self::Identity> {
            process::capture_process_tree(root_pid, table)
        }

        fn matching(
            &self,
            observed: &[Self::Identity],
            current: &[Self::Identity],
        ) -> Vec<Self::Identity> {
            process::matching_processes(observed, current)
        }

        fn signal_group_if_observed(
            &self,
            group: u32,
            observed: &[Self::Identity],
            current: &[Self::Identity],
            signal: ProcessSignal,
        ) -> Result<bool, String> {
            process::signal_process_group_if_observed(group, observed, current, signal)
                .map_err(|error| error.to_string())
        }
    }

    #[cfg(unix)]
    impl ProcessObserver for TestObserver {
        type Identity = TestIdentity;

        fn after_spawn(&mut self, pid: u32) -> Result<(), String> {
            self.root_pid = Some(pid);
            std::thread::sleep(self.after_spawn_delay);
            if self.fail_registration {
                Err("injected registration failure".into())
            } else {
                Ok(())
            }
        }

        fn inspect(&mut self) -> Result<Vec<Self::Identity>, String> {
            if self.fail_inspection {
                return Err("injected process inspection failure".into());
            }
            let Some(pid) = self.root_pid else {
                return Ok(Vec::new());
            };
            if self.hide_root {
                return Ok(Vec::new());
            }
            // SAFETY: signal 0 checks whether this test-owned PID still exists.
            let alive = unsafe { libc::kill(pid as libc::pid_t, 0) } == 0;
            Ok(if alive {
                vec![TestIdentity {
                    pid,
                    group: if self.wrong_group {
                        pid.saturating_add(1)
                    } else {
                        pid
                    },
                    command: "fake-provider".into(),
                }]
            } else {
                Vec::new()
            })
        }

        fn try_wait(
            &mut self,
            child: &mut std::process::Child,
        ) -> std::io::Result<Option<ExitStatus>> {
            if self.fail_wait_once {
                self.fail_wait_once = false;
                return Err(std::io::Error::other("injected wait failure"));
            }
            child.try_wait()
        }

        fn pid(identity: &Self::Identity) -> u32 {
            identity.pid
        }

        fn group(identity: &Self::Identity) -> u32 {
            identity.group
        }

        fn capture_tree(&self, root_pid: u32, table: &[Self::Identity]) -> Vec<Self::Identity> {
            table
                .iter()
                .filter(|identity| identity.pid == root_pid)
                .cloned()
                .collect()
        }

        fn matching(
            &self,
            observed: &[Self::Identity],
            current: &[Self::Identity],
        ) -> Vec<Self::Identity> {
            observed
                .iter()
                .filter(|identity| current.contains(identity))
                .cloned()
                .collect()
        }

        fn signal_group_if_observed(
            &self,
            group: u32,
            observed: &[Self::Identity],
            current: &[Self::Identity],
            signal: ProcessSignal,
        ) -> Result<bool, String> {
            if !observed
                .iter()
                .any(|identity| identity.group == group && current.contains(identity))
            {
                return Ok(false);
            }
            self.signals.lock().unwrap().push(signal);
            if signal == ProcessSignal::Kill
                && let Some(marker) = &self.kill_marker
            {
                fs::write(marker, "stop").map_err(|error| error.to_string())?;
            }
            Ok(true)
        }
    }

    #[cfg(unix)]
    fn fake_claude(root: &std::path::Path, response: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = root.join("fake claude");
        fs::write(
            &path,
            format!(
                "#!/bin/sh\nsleep 0.25\nprintf '%s' '{}'\n",
                response.replace('\'', "'\\''")
            ),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    #[test]
    fn overlays_fresh_scoped_markers_and_keeps_the_captured_user_environment() {
        let root = tempdir().unwrap();
        let env = factory_environment(
            &request(root.path(), AgentAdapter::Codex, "/bin/sh").environment,
            &descriptor(root.path(), &profile(AgentAdapter::Codex, "/bin/sh")),
        )
        .unwrap();
        assert_eq!(
            env.get(OsStr::new("REX_PROJECTS_AGENT"))
                .and_then(|v| v.to_str()),
            Some("1")
        );
        assert_eq!(
            env.get(OsStr::new("REX_PROJECTS_ROLE"))
                .and_then(|v| v.to_str()),
            Some("worker")
        );
        assert_eq!(
            env.get(OsStr::new("REX_SESSION")).and_then(|v| v.to_str()),
            Some("session-a")
        );
        assert_eq!(
            env.get(OsStr::new("PATH")).and_then(|v| v.to_str()),
            Some("/usr/bin")
        );
    }

    #[test]
    fn codex_and_claude_commands_use_verified_automatic_modes_and_contracts() {
        let root = tempdir().unwrap();
        let codex = prepare_with_qualification(
            &request(
                root.path(),
                AgentAdapter::Codex,
                executable().to_str().unwrap(),
            ),
            true,
            false,
        )
        .unwrap();
        let codex = codex
            .args
            .iter()
            .map(|v| v.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(" ");
        assert!(codex.contains("--no-daemon"));
        assert!(codex.contains("--ask-for-approval never"));
        assert!(codex.contains("Worker must use the mailbox"));
        let claude = prepare_with_qualification(
            &request(
                root.path(),
                AgentAdapter::ClaudeCode,
                executable().to_str().unwrap(),
            ),
            true,
            false,
        )
        .unwrap();
        let claude = claude
            .args
            .iter()
            .map(|v| v.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(" ");
        assert!(claude.contains("--permission-mode auto"));
        assert!(claude.contains("--permission-prompts none"));
        assert!(claude.contains("--append-system-prompt Worker must use the mailbox"));
    }

    #[test]
    fn refuses_resume_after_profile_or_instruction_change() {
        let root = tempdir().unwrap();
        let mut turn = request(
            root.path(),
            AgentAdapter::ClaudeCode,
            executable().to_str().unwrap(),
        );
        turn.continuation = Some(ConversationContinuation {
            provider: AgentAdapter::ClaudeCode,
            conversation_id: "session-old".into(),
            profile_digest: Digest::parse("d".repeat(64)).unwrap(),
            instruction_digest: Digest::parse("b".repeat(64)).unwrap(),
            workspace: turn.descriptor.workspace.clone(),
        });
        assert!(prepare_with_qualification(&turn, true, false).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn fake_provider_runs_finite_structured_turn_and_resumes_same_conversation() {
        let _run_lock = TEST_RUN_LOCK.lock().unwrap();
        let root = tempdir().unwrap();
        let executable = fake_claude(
            root.path(),
            r#"{"type":"result","session_id":"session-a","is_error":false,"structured_output":{"ok":true}}"#,
        );
        let executable = executable.to_str().unwrap();
        let mut turn = request(root.path(), AgentAdapter::ClaudeCode, executable);
        assert!(prepare(&turn).is_err());
        let first = run_fixture_turn(&turn, &mut SystemProcessObserver).unwrap();
        assert!(matches!(first.receipt.outcome, TurnOutcome::Completed));
        assert!(matches!(first.receipt.cleanup, CleanupState::Confirmed));
        assert_eq!(first.receipt.conversation_id.as_deref(), Some("session-a"));
        assert_eq!(first.receipt.provider_version.as_deref(), Some("fixture-1"));
        assert_eq!(
            first.receipt.capability_receipt_digest,
            Some(Digest::parse("e".repeat(64)).unwrap())
        );
        assert!(first.receipt.processes.iter().any(|process| {
            process.identity_quality == "kernel_birth_token" && !process.start_identity.is_empty()
        }));
        assert_eq!(first.structured_result, Some(json!({"ok":true})));

        turn.continuation = Some(ConversationContinuation {
            provider: AgentAdapter::ClaudeCode,
            conversation_id: "session-a".into(),
            profile_digest: turn.descriptor.profile_digest.clone(),
            instruction_digest: turn.descriptor.instruction_digest.clone(),
            workspace: turn.descriptor.workspace.clone(),
        });
        let resumed = run_fixture_turn(&turn, &mut TestObserver::default()).unwrap();
        assert!(matches!(resumed.receipt.outcome, TurnOutcome::Completed));
        assert_eq!(
            resumed.receipt.conversation_id.as_deref(),
            Some("session-a")
        );
    }

    #[cfg(unix)]
    #[test]
    fn disposable_qualification_runs_unknown_profile_only_with_bound_ephemeral_permit() {
        let _run_lock = TEST_RUN_LOCK.lock().unwrap();
        let root = tempdir().unwrap();
        let executable = fake_claude(
            root.path(),
            r#"{"type":"result","session_id":"session-a","is_error":false,"structured_output":{"ok":true}}"#,
        );
        let mut turn = request(
            root.path(),
            AgentAdapter::ClaudeCode,
            executable.to_str().unwrap(),
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        turn.descriptor.provider_capability.status = ProviderQualificationStatus::Unknown;
        turn.descriptor.rex_session_id = "rex-projects-doctor-qualification-test".into();
        turn.descriptor.rex_block_id = RexBlockId::parse("block-a").unwrap();

        assert!(run_turn(&turn, &mut SystemProcessObserver).is_err());
        assert!(prepare(&turn).is_err());

        let identity = super::profile_runtime_identity(&turn.profile).unwrap();
        let context = DisposableQualificationContext {
            workspace_root: root.path().to_path_buf(),
            rex_fixture: crate::adapters::rex::test_qualification_fixture(),
            deadline: Duration::from_secs(90),
            expected_permission_mode: identity.effective_permission_mode.into(),
            prompts_denied: true,
        };
        let permit = issue_qualification_permit(&turn, context).unwrap();
        let result = run_qualification_turn(&turn, permit, &mut SystemProcessObserver).unwrap();
        assert!(matches!(result.receipt.outcome, TurnOutcome::Completed));
        assert!(matches!(result.receipt.cleanup, CleanupState::Confirmed));
        assert_eq!(result.structured_result, Some(json!({"ok":true})));
        assert!(result.receipt.provider_version.is_none());
        assert!(result.receipt.capability_receipt_digest.is_none());
        assert_eq!(
            turn.descriptor.provider_capability.status,
            ProviderQualificationStatus::Unknown,
            "the ephemeral turn must not promote evidence to Verified"
        );

        let identity = super::profile_runtime_identity(&turn.profile).unwrap();
        let permit = issue_qualification_permit(
            &turn,
            DisposableQualificationContext {
                workspace_root: root.path().to_path_buf(),
                rex_fixture: crate::adapters::rex::test_qualification_fixture(),
                deadline: Duration::from_secs(90),
                expected_permission_mode: identity.effective_permission_mode.into(),
                prompts_denied: true,
            },
        )
        .unwrap();
        turn.prompt.push_str(" with changed input");
        assert!(run_qualification_turn(&turn, permit, &mut SystemProcessObserver).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn qualification_permit_rejects_path_swap_and_expired_deadline_before_spawn() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let _run_lock = TEST_RUN_LOCK.lock().unwrap();
        let root = tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let executable = fake_claude(
            root.path(),
            r#"{"type":"result","session_id":"session-a","is_error":false,"structured_output":{"ok":true}}"#,
        );
        let mut turn = request(
            root.path(),
            AgentAdapter::ClaudeCode,
            executable.to_str().unwrap(),
        );
        turn.descriptor.provider_capability.status = ProviderQualificationStatus::Unknown;
        turn.descriptor.rex_session_id = "rex-projects-doctor-qualification-test".into();
        turn.descriptor.rex_block_id = RexBlockId::parse("block-a").unwrap();
        let original_control_dir = turn.descriptor.control_dir.clone();
        let nested_control_dir = turn.descriptor.workspace.join("nested-control");
        fs::create_dir(&nested_control_dir).unwrap();
        turn.descriptor.control_dir = nested_control_dir.clone();
        let identity = super::profile_runtime_identity(&turn.profile).unwrap();
        assert!(
            issue_qualification_permit(
                &turn,
                DisposableQualificationContext {
                    workspace_root: root.path().to_path_buf(),
                    rex_fixture: crate::adapters::rex::test_qualification_fixture(),
                    deadline: Duration::from_secs(90),
                    expected_permission_mode: identity.effective_permission_mode.into(),
                    prompts_denied: true,
                },
            )
            .is_err()
        );
        fs::remove_dir(&nested_control_dir).unwrap();
        turn.descriptor.control_dir = original_control_dir;
        let identity = super::profile_runtime_identity(&turn.profile).unwrap();
        let permit = issue_qualification_permit(
            &turn,
            DisposableQualificationContext {
                workspace_root: root.path().to_path_buf(),
                rex_fixture: crate::adapters::rex::test_qualification_fixture(),
                deadline: Duration::from_secs(90),
                expected_permission_mode: identity.effective_permission_mode.into(),
                prompts_denied: true,
            },
        )
        .unwrap();
        let workspace = turn.descriptor.workspace.clone();
        fs::remove_dir(&workspace).unwrap();
        let outside = root.path().join("outside-workspace");
        fs::create_dir(&outside).unwrap();
        symlink(&outside, &workspace).unwrap();
        let mut observer = TestObserver::default();
        assert!(run_qualification_turn(&turn, permit, &mut observer).is_err());
        assert!(observer.root_pid.is_none());

        fs::remove_file(&workspace).unwrap();
        fs::remove_dir(&outside).unwrap();
        fs::create_dir(&workspace).unwrap();
        turn.profile.turn_timeout_seconds = 1;
        turn.shutdown_grace = Duration::from_millis(1);
        let identity = super::profile_runtime_identity(&turn.profile).unwrap();
        let permit = issue_qualification_permit(
            &turn,
            DisposableQualificationContext {
                workspace_root: root.path().to_path_buf(),
                rex_fixture: crate::adapters::rex::test_qualification_fixture(),
                deadline: Duration::from_millis(8_100),
                expected_permission_mode: identity.effective_permission_mode.into(),
                prompts_denied: true,
            },
        )
        .unwrap();
        std::thread::sleep(Duration::from_millis(8_150));
        let mut observer = TestObserver::default();
        assert!(run_qualification_turn(&turn, permit, &mut observer).is_err());
        assert!(observer.root_pid.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn qualification_setup_delay_past_deadline_never_returns_a_completed_turn() {
        let _run_lock = TEST_RUN_LOCK.lock().unwrap();
        let root = tempdir().unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let executable = root.path().join("long-running fake claude");
        fs::write(
            &executable,
            "#!/bin/sh\nsleep 30\nprintf '%s' '{\"type\":\"result\",\"session_id\":\"session-a\",\"is_error\":false,\"structured_output\":{\"ok\":true}}'\n",
        )
        .unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let mut turn = request(
            root.path(),
            AgentAdapter::ClaudeCode,
            executable.to_str().unwrap(),
        );
        turn.descriptor.provider_capability.status = ProviderQualificationStatus::Unknown;
        turn.descriptor.rex_session_id = "rex-projects-doctor-qualification-test".into();
        turn.descriptor.rex_block_id = RexBlockId::parse("block-a").unwrap();
        turn.profile.turn_timeout_seconds = 1;
        turn.shutdown_grace = Duration::from_millis(1);
        let identity = super::profile_runtime_identity(&turn.profile).unwrap();
        let permit = issue_qualification_permit(
            &turn,
            DisposableQualificationContext {
                workspace_root: root.path().to_path_buf(),
                rex_fixture: crate::adapters::rex::test_qualification_fixture(),
                deadline: Duration::from_millis(8_100),
                expected_permission_mode: identity.effective_permission_mode.into(),
                prompts_denied: true,
            },
        )
        .unwrap();
        let mut observer = DelayedSystemObserver {
            after_spawn_delay: Duration::from_millis(8_200),
            root_pid: None,
        };
        let result = run_qualification_turn(&turn, permit, &mut observer).unwrap();
        assert!(!matches!(result.receipt.outcome, TurnOutcome::Completed));
        assert!(matches!(result.receipt.cleanup, CleanupState::Unknown));
        assert!(result.structured_result.is_none());
        assert!(result.receipt.provider_version.is_none());
        assert!(result.receipt.capability_receipt_digest.is_none());
        let root_pid = observer.root_pid.unwrap();
        let remaining = process::inspect_process_table().unwrap();
        let observed_pids = result
            .receipt
            .processes
            .iter()
            .map(|identity| identity.pid)
            .chain(std::iter::once(root_pid))
            .collect::<std::collections::BTreeSet<_>>();
        assert!(
            observed_pids
                .iter()
                .all(|pid| !remaining.iter().any(|identity| identity.pid == *pid)),
            "the live provider and its captured descendants must be stopped before return"
        );
    }

    #[cfg(unix)]
    #[test]
    fn fake_provider_rejects_changed_conversation_and_invalid_result() {
        let _run_lock = TEST_RUN_LOCK.lock().unwrap();
        let root = tempdir().unwrap();
        let executable = fake_claude(
            root.path(),
            r#"{"type":"result","session_id":"session-new","is_error":false,"structured_output":{"ok":true}}"#,
        );
        let executable = executable.to_str().unwrap();
        let mut turn = request(root.path(), AgentAdapter::ClaudeCode, executable);
        turn.continuation = Some(ConversationContinuation {
            provider: AgentAdapter::ClaudeCode,
            conversation_id: "session-old".into(),
            profile_digest: turn.descriptor.profile_digest.clone(),
            instruction_digest: turn.descriptor.instruction_digest.clone(),
            workspace: turn.descriptor.workspace.clone(),
        });
        let result = run_fixture_turn(&turn, &mut TestObserver::default()).unwrap();
        assert!(matches!(result.receipt.outcome, TurnOutcome::MissingResult));
        assert!(result.structured_result.is_none());

        let invalid = fake_claude(root.path(), "not-json");
        turn.continuation = None;
        turn.profile.command = vec![invalid.to_str().unwrap().into()];
        turn.descriptor.provider_capability = fixture_capability(
            &turn.profile,
            turn.descriptor.profile_digest.clone(),
            &turn.descriptor.result_schema,
        );
        let result = run_fixture_turn(&turn, &mut TestObserver::default()).unwrap();
        assert!(matches!(result.receipt.outcome, TurnOutcome::MissingResult));
        assert!(result.structured_result.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn post_spawn_observation_failures_retain_identity_or_an_explicit_pid_hint() {
        let _run_lock = TEST_RUN_LOCK.lock().unwrap();
        let root = tempdir().unwrap();
        let executable = fake_claude(
            root.path(),
            r#"{"type":"result","session_id":"session-a","is_error":false,"structured_output":{"ok":true}}"#,
        );
        let make_turn = || {
            request(
                root.path(),
                AgentAdapter::ClaudeCode,
                executable.to_str().unwrap(),
            )
        };

        let mut registration_failure = TestObserver {
            fail_registration: true,
            ..TestObserver::default()
        };
        let registration = run_fixture_turn(&make_turn(), &mut registration_failure).unwrap();
        assert!(registration.receipt.launch_pid_hint.is_some());
        assert!(matches!(
            registration.receipt.cleanup,
            CleanupState::Confirmed
        ));
        assert!(registration.receipt.processes.iter().any(|process| {
            process.identity_quality == "test_only" && !process.start_identity.is_empty()
        }));

        let mut inspection_failure = TestObserver {
            fail_inspection: true,
            ..TestObserver::default()
        };
        let inspection = run_fixture_turn(&make_turn(), &mut inspection_failure).unwrap();
        assert!(matches!(inspection.receipt.cleanup, CleanupState::Unknown));
        assert!(inspection.receipt.processes.iter().any(|process| {
            process.identity_quality == "unverified_pid_hint" && process.start_identity.is_empty()
        }));

        let mut missing_root = TestObserver {
            hide_root: true,
            ..TestObserver::default()
        };
        let missing = run_fixture_turn(&make_turn(), &mut missing_root).unwrap();
        assert!(matches!(missing.receipt.cleanup, CleanupState::Unknown));
        assert_eq!(missing.receipt.processes.len(), 1);
        assert_eq!(
            missing.receipt.processes[0].identity_quality,
            "unverified_pid_hint"
        );

        let mut wrong_group = TestObserver {
            wrong_group: true,
            ..TestObserver::default()
        };
        let group = run_fixture_turn(&make_turn(), &mut wrong_group).unwrap();
        assert!(matches!(group.receipt.cleanup, CleanupState::Unknown));
        assert!(group.receipt.processes.iter().any(|process| {
            process.identity_quality == "test_only" && process.process_group_id != process.pid
        }));

        let mut wait_failure = TestObserver {
            fail_wait_once: true,
            ..TestObserver::default()
        };
        let wait = run_fixture_turn(&make_turn(), &mut wait_failure).unwrap();
        assert!(matches!(wait.receipt.cleanup, CleanupState::Confirmed));
        assert!(wait.receipt.cleanup_detail.is_some());
        assert!(!wait.receipt.processes.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn cancellation_escalates_and_confirms_fake_provider_cleanup() {
        let _run_lock = TEST_RUN_LOCK.lock().unwrap();
        let root = tempdir().unwrap();
        let executable = root.path().join("fake claude");
        let kill_marker = root.path().join("kill marker");
        use std::os::unix::fs::PermissionsExt;
        fs::write(
            &executable,
            format!(
                "#!/bin/sh\nwhile [ ! -e '{}' ]; do sleep 0.05; done\nprintf '%s' '{}'\n",
                kill_marker.display(),
                r#"{"type":"result","session_id":"cancelled","is_error":false,"structured_output":{"ok":true}}"#
            ),
        )
        .unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let mut turn = request(
            root.path(),
            AgentAdapter::ClaudeCode,
            executable.to_str().unwrap(),
        );
        turn.shutdown_grace = Duration::from_millis(50);
        let canceller = std::thread::spawn(|| {
            std::thread::sleep(Duration::from_millis(300));
            super::PENDING_SIGNAL.store(libc::SIGTERM, std::sync::atomic::Ordering::Relaxed);
        });
        let mut observer = TestObserver {
            kill_marker: Some(kill_marker),
            ..TestObserver::default()
        };
        let result = run_fixture_turn(&turn, &mut observer).unwrap();
        canceller.join().unwrap();
        assert!(matches!(result.receipt.outcome, TurnOutcome::Cancelled));
        assert!(matches!(result.receipt.cleanup, CleanupState::Confirmed));
        assert!(result.receipt.cancellation_signal.is_some());
        assert!(result.structured_result.is_none());
        assert!(
            observer
                .signals
                .lock()
                .unwrap()
                .contains(&ProcessSignal::Kill)
        );
    }
}
