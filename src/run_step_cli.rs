//! Runtime boundary for the finite-turn wrapper and host phase-two launch finalization.

use std::path::Path;

use sha2::{Digest as _, Sha256};

use crate::adapters::rex::{CreateDisposition, RexCliTransport, RexContextBlock, TicketWindow};
use crate::domain::ids::Digest;
use crate::domain::types::Role;
use crate::launch::{
    AgentLaunchAuthority, AgentLaunchReservation, LaunchDecision, ObservedWrapperIdentity,
    RexBlockLifecycle, RexBlockOwnership, RexViewBlock,
};
use crate::process::{
    ProcessIdentity, ProcessIdentityQuality, ProcessSignal, inspect_process_table,
};
use crate::run_step_package::RunStepPackage;
use crate::run_step_spool::{RunFamilyBinding, RunFamilyCoverage, RunFamilyRecord, RunStepSpool};
use crate::store::ConfigStore;

fn wait_for_start_request(
    spool: &RunStepSpool,
    timeout: std::time::Duration,
    mut check_owner: impl FnMut() -> Result<(), String>,
) -> Result<crate::run_step_spool::StartRequestEnvelope, String> {
    let deadline = std::time::Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| "start request deadline overflow".to_owned())?;
    loop {
        check_owner()?;
        match spool.read_start_request() {
            Ok(request) => return Ok(request),
            Err(error) if error == "run-step spool file is not present" => {}
            Err(error) => return Err(error),
        }
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err("timed out waiting for wrapper start request".into());
        }
        std::thread::sleep(std::time::Duration::from_millis(50).min(remaining));
    }
}

/// Publish the immutable package, bind the observed block and authority, then ACK only after
/// the start request has been checked against that durable host state.
pub fn finalize_and_ack_start(
    store: &mut ConfigStore,
    owner_generation: u64,
    reservation: &AgentLaunchReservation,
    package: &RunStepPackage,
    observed_block: &RexContextBlock,
    rex: &RexCliTransport,
) -> Result<AgentLaunchAuthority, String> {
    reservation.validate()?;
    package.validate()?;
    if owner_generation != reservation.controller_generation
        || package.controller_generation != owner_generation
        || package.descriptor.run_id != reservation.agent_run_id
        || package.project_id != reservation.project_id
        || package.operation_id != reservation.operation_id
        || package.descriptor.operation_id != reservation.operation_id
        || package.descriptor.role != reservation.role
        || package.descriptor.ticket_run_id != reservation.ticket_run_id
        || package.descriptor.expected_subject_revision
            != reservation
                .ticket_revision
                .map(|value| value.0)
                .unwrap_or(0)
        || package.descriptor.attempt != reservation.attempt
        || package.descriptor.run_epoch != reservation.run_epoch
        || package.descriptor.profile_digest != reservation.profile_digest
        || package.descriptor.instruction_digest != reservation.instruction_digest
        || package.descriptor.provider_capability.receipt_digest
            != reservation.qualification_receipt_digest
        || digest_bytes(
            &serde_json::to_vec(&package.descriptor.result_schema)
                .map_err(|error| error.to_string())?,
        )? != reservation.result_schema_digest
        || package.descriptor.environment_snapshot_id != reservation.environment_snapshot_id
        || package.descriptor.wake_snapshot_digest != reservation.wake_snapshot.digest
        || package.descriptor.workspace != reservation.workspace_path
        || package.descriptor.control_dir != reservation.control_dir
        || package.descriptor.rex_session_id != observed_block.session_id
        || package.descriptor.rex_block_id.as_str() != observed_block.block_id
        || package.rex_server_identity != observed_block.server_instance_id
        || package.rex_window_id != observed_block.window_id
    {
        return Err(
            "final run-step package does not match the reservation and observed Rex block".into(),
        );
    }

    let package_digest = package.publish_once(&reservation.descriptor_path)?;
    let authority = AgentLaunchAuthority {
        agent_run_id: reservation.agent_run_id.clone(),
        project_id: reservation.project_id.clone(),
        role: reservation.role,
        role_session_id: reservation.role_session_id.clone(),
        parent_run_id: reservation.parent_run_id.clone(),
        parent_role: reservation.parent_role,
        ticket_run_id: reservation.ticket_run_id.clone(),
        ticket_revision: reservation.ticket_revision,
        config_revision: reservation.config_revision,
        config_digest: reservation.config_digest.clone(),
        attempt: reservation.attempt,
        run_epoch: reservation.run_epoch,
        controller_generation: reservation.controller_generation,
        operation_id: reservation.operation_id.clone(),
        operation_recipe_id: reservation.operation_recipe_id.clone(),
        rex_view_id: reservation.rex_view_id.clone(),
        descriptor_digest: package_digest,
        runtime_binary_digest: reservation.runtime_binary_digest.clone(),
        descriptor_path: reservation.descriptor_path.clone(),
        environment_snapshot_id: reservation.environment_snapshot_id.clone(),
        profile_id: reservation.profile_id.clone(),
        profile_digest: reservation.profile_digest.clone(),
        instruction_digest: reservation.instruction_digest.clone(),
        result_schema_digest: reservation.result_schema_digest.clone(),
        wake_snapshot_digest: reservation.wake_snapshot.digest.clone(),
        qualification_receipt_digest: reservation.qualification_receipt_digest.clone(),
        rex_server_identity: observed_block.server_instance_id.clone(),
        rex_session_id: observed_block.session_id.clone(),
        rex_window_id: observed_block.window_id.clone(),
        rex_block_id: observed_block.block_id.clone(),
        workspace_path: reservation.workspace_path.clone(),
        control_dir: reservation.control_dir.clone(),
        mailbox_capability_digest: reservation.mailbox_capability_digest.clone(),
    };
    store.register_agent_launch_authority(owner_generation, &authority)?;
    store.register_rex_view_block(
        owner_generation,
        &RexViewBlock {
            view_id: reservation.rex_view_id.clone(),
            block_id: observed_block.block_id.clone(),
            agent_run_id: Some(reservation.agent_run_id.clone()),
            role: Some(reservation.role),
            ownership: RexBlockOwnership::Factory,
            lifecycle: RexBlockLifecycle::Active,
            process_absent_confirmed: false,
            retained_until_unix: None,
        },
    )?;
    store.finalize_agent_launch_reservation(
        owner_generation,
        &reservation.agent_run_id,
        &reservation.digest()?,
        &authority,
    )?;
    crate::agent_api::publish_wake_snapshot(
        &reservation.control_dir,
        reservation.wake_snapshot.clone(),
    )?;

    let spool = RunStepSpool::open(&reservation.control_dir)?;
    let start = wait_for_start_request(
        &spool,
        std::time::Duration::from_secs(package.start_ack_timeout_seconds),
        || {
            if store.owner_generation()? != Some(owner_generation) {
                return Err(
                    "controller owner generation changed before start acknowledgement".into(),
                );
            }
            if store.should_stop(owner_generation)? {
                return Err("controller stop requested before start acknowledgement".into());
            }
            if store.pending_machine_stop_requested(owner_generation)? {
                return Err("controller stop requested before start acknowledgement".into());
            }
            Ok(())
        },
    )?;
    let request = &start.request;
    if request.operation_id != reservation.operation_id
        || request.agent_run_id != reservation.agent_run_id
        || request.project_id != reservation.project_id
        || request.controller_generation != owner_generation
        || request.descriptor_digest != authority.descriptor_digest
        || request.runtime_binary_digest != reservation.runtime_binary_digest
        || request.environment_snapshot_id != reservation.environment_snapshot_id
        || request.qualification_receipt_digest != reservation.qualification_receipt_digest
        || request.rex_session_id != observed_block.session_id
        || request.rex_block_id != observed_block.block_id
    {
        return Err("wrapper start request does not match the finalized host launch".into());
    }
    spool.publish_run_family_binding_once(&RunFamilyBinding {
        schema_version: 1,
        agent_run_id: authority.agent_run_id.clone(),
        reservation_epoch: reservation.run_epoch,
        authority_digest: authority.digest()?,
        descriptor_digest: authority.descriptor_digest.clone(),
        wrapper_pid: request.wrapper_pid,
        wrapper_start_identity: request.wrapper_start_identity.clone(),
    })?;
    if let Some(receipt) = store.persisted_start_receipt(request)? {
        spool.publish_start_receipt(&start, receipt)?;
        return Ok(authority);
    }
    let fresh_block = rex
        .validate_context_block(&observed_block.block_id)
        .map_err(|error| format!("revalidate Rex block before start ACK: {error}"))?;
    if fresh_block != *observed_block
        || fresh_block.session_id != authority.rex_session_id
        || fresh_block.window_id != authority.rex_window_id
        || fresh_block.server_instance_id != authority.rex_server_identity
    {
        return Err("Rex block identity changed before host start acknowledgement".into());
    }
    let rex_window = TicketWindow {
        server_instance_id: authority.rex_server_identity.clone(),
        session_id: authority.rex_session_id.clone(),
        window_id: authority.rex_window_id.clone(),
        label: String::new(),
        initial_block_id: None,
        disposition: CreateDisposition::Existing,
    };
    let rex_process = rex
        .observe_process(
            &rex_window,
            authority.agent_run_id.as_str(),
            &authority.rex_block_id,
        )
        .map_err(|error| format!("observe Rex wrapper process before ACK: {error}"))?;
    let expected_executable = std::env::current_exe().map_err(|error| error.to_string())?;
    let rex_reports_wrapper = rex_process
        .child
        .iter()
        .chain(rex_process.foreground.iter())
        .chain(rex_process.ancestors.iter().flatten())
        .any(|process| {
            process.pid == request.wrapper_pid
                && process.path.as_deref().is_some_and(|path| {
                    std::fs::canonicalize(path).ok() == Some(expected_executable.clone())
                })
        });
    if !rex_reports_wrapper {
        return Err("Rex process observation does not identify the requested wrapper".into());
    }
    let observed = observe_wrapper_process(
        request.wrapper_pid,
        &request.wrapper_start_identity,
        &request.runtime_binary_digest,
        &authority.rex_session_id,
        &authority.rex_block_id,
    )?;
    let receipt = store.authorize_agent_start(owner_generation, request, &observed)?;
    if receipt.decision != LaunchDecision::Accepted {
        return Err("host did not accept the exact wrapper start request".into());
    }
    spool.publish_start_receipt(&start, receipt)?;
    Ok(authority)
}

/// Recover an uncertain StartAgent effect after the wrapper consumed its one-use environment
/// handoff. This path only accepts an already persisted host acknowledgement, and revalidates
/// the immutable authority and the live Rex block before allowing the dispatcher to finish it.
pub fn reconcile_accepted_start(
    store: &ConfigStore,
    owner_generation: u64,
    reservation: &AgentLaunchReservation,
    rex: &RexCliTransport,
) -> Result<Option<AgentLaunchAuthority>, String> {
    reservation.validate()?;
    if reservation.controller_generation != owner_generation {
        return Err("launch reservation belongs to another controller generation".into());
    }
    let Some(authority) = store.agent_launch_authority(&reservation.agent_run_id)? else {
        return Ok(None);
    };
    if authority.controller_generation != owner_generation
        || authority.agent_run_id != reservation.agent_run_id
        || authority.project_id != reservation.project_id
        || authority.role != reservation.role
        || authority.role_session_id != reservation.role_session_id
        || authority.parent_run_id != reservation.parent_run_id
        || authority.parent_role != reservation.parent_role
        || authority.ticket_run_id != reservation.ticket_run_id
        || authority.ticket_revision != reservation.ticket_revision
        || authority.config_revision != reservation.config_revision
        || authority.config_digest != reservation.config_digest
        || authority.attempt != reservation.attempt
        || authority.run_epoch != reservation.run_epoch
        || authority.operation_id != reservation.operation_id
        || authority.operation_recipe_id != reservation.operation_recipe_id
        || authority.rex_view_id != reservation.rex_view_id
        || authority.runtime_binary_digest != reservation.runtime_binary_digest
        || authority.descriptor_path != reservation.descriptor_path
        || authority.environment_snapshot_id != reservation.environment_snapshot_id
        || authority.profile_id != reservation.profile_id
        || authority.profile_digest != reservation.profile_digest
        || authority.instruction_digest != reservation.instruction_digest
        || authority.result_schema_digest != reservation.result_schema_digest
        || authority.wake_snapshot_digest != reservation.wake_snapshot.digest
        || authority.qualification_receipt_digest != reservation.qualification_receipt_digest
        || authority.workspace_path != reservation.workspace_path
        || authority.control_dir != reservation.control_dir
        || authority.mailbox_capability_digest != reservation.mailbox_capability_digest
    {
        return Err("persisted launch authority does not match the immutable reservation".into());
    }

    let spool = RunStepSpool::open(&reservation.control_dir)?;
    let start = spool.read_start_request()?;
    let request = &start.request;
    if request.operation_id != authority.operation_id
        || request.agent_run_id != authority.agent_run_id
        || request.project_id != authority.project_id
        || request.controller_generation != owner_generation
        || request.descriptor_digest != authority.descriptor_digest
        || request.runtime_binary_digest != authority.runtime_binary_digest
        || request.environment_snapshot_id != authority.environment_snapshot_id
        || request.qualification_receipt_digest != authority.qualification_receipt_digest
        || request.rex_session_id != authority.rex_session_id
        || request.rex_block_id != authority.rex_block_id
    {
        return Err("persisted start request does not match launch authority".into());
    }
    let Some(receipt) = store.persisted_start_receipt(request)? else {
        return Ok(None);
    };
    if receipt.decision != LaunchDecision::Accepted {
        return Err("persisted StartAgent receipt is not accepted".into());
    }
    let block = rex
        .validate_context_block(&authority.rex_block_id)
        .map_err(|error| format!("revalidate accepted Rex block: {error}"))?;
    if block.session_id != authority.rex_session_id
        || block.window_id != authority.rex_window_id
        || block.server_instance_id != authority.rex_server_identity
    {
        return Err("accepted launch Rex block no longer matches its persisted authority".into());
    }
    let window = TicketWindow {
        server_instance_id: authority.rex_server_identity.clone(),
        session_id: authority.rex_session_id.clone(),
        window_id: authority.rex_window_id.clone(),
        label: String::new(),
        initial_block_id: None,
        disposition: CreateDisposition::Existing,
    };
    let process = rex
        .observe_process(
            &window,
            authority.agent_run_id.as_str(),
            &authority.rex_block_id,
        )
        .map_err(|error| format!("revalidate accepted Rex process: {error}"))?;
    let rex_reports_wrapper = process
        .child
        .iter()
        .chain(process.foreground.iter())
        .chain(process.ancestors.iter().flatten())
        .any(|process| {
            process.pid == request.wrapper_pid
                && process.path.as_deref().is_some_and(|path| {
                    std::fs::canonicalize(path).ok() == std::env::current_exe().ok()
                })
        });
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    if digest_file(&executable)? != authority.runtime_binary_digest {
        return Err("running rex-projects binary differs from launch authority".into());
    }
    let live_process_matches = inspect_process_table()
        .map_err(|error| format!("reobserve accepted wrapper process: {error}"))?
        .into_iter()
        .find(|process| process.pid == request.wrapper_pid)
        .is_some_and(|process| {
            process.quality == ProcessIdentityQuality::KernelBirthToken
                && process.start_identity == request.wrapper_start_identity
        });
    if !rex_reports_wrapper || !live_process_matches {
        // The wrapper may have completed between the original ACK and effect commit. In that
        // case a validated terminal turn envelope is the durable evidence that makes replay safe.
        spool.read_turn_result(&start).map_err(|_| {
            "accepted wrapper is no longer observable and has no validated terminal result"
                .to_owned()
        })?;
    }
    match spool.read_start_receipt(&start)? {
        Some(published) if published == receipt => {}
        Some(_) => {
            return Err("published StartAgent receipt differs from durable host authority".into());
        }
        None => {
            store.validate_agent_launch_replay(owner_generation, reservation)?;
            spool.publish_start_receipt(&start, receipt)?;
        }
    }
    Ok(Some(authority))
}

/// Stable identity digest helper shared by the CLI and runtime acceptance tests.
pub fn digest_bytes(bytes: &[u8]) -> Result<Digest, String> {
    Digest::parse(format!("{:x}", Sha256::digest(bytes)))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunStepCliResult {
    pub run_id: String,
    pub result_digest: String,
}

/// Run one bounded finite turn from the exact host package and return only its receipt summary.
pub fn run_step(
    run_id: &str,
    package_path: &Path,
    environment_handoff: &Path,
) -> Result<RunStepCliResult, String> {
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::fs::{self, OpenOptions};
    use std::io::Read;
    use std::time::{Duration, Instant};

    if std::env::var_os("REX_PROJECTS_AGENT").is_none() {
        return Err("agent run-step must run inside a Rex Projects Agent block".into());
    }
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(300))
        .ok_or("package wait deadline overflow")?;
    let bytes = loop {
        match fs::symlink_metadata(package_path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink()
                    || !metadata.is_file()
                    || metadata.len() > 8 * 1024 * 1024
                {
                    return Err(
                        "run-step package must be a bounded regular non-symlink file".into(),
                    );
                }
                #[cfg(unix)]
                let file = {
                    use std::os::unix::fs::OpenOptionsExt;
                    OpenOptions::new()
                        .read(true)
                        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
                        .open(package_path)
                        .map_err(|e| e.to_string())?
                };
                #[cfg(not(unix))]
                let mut file = OpenOptions::new()
                    .read(true)
                    .open(package_path)
                    .map_err(|e| e.to_string())?;
                let opened = file.metadata().map_err(|e| e.to_string())?;
                if !opened.is_file() || opened.len() > 8 * 1024 * 1024 {
                    return Err("run-step package changed to an invalid file".into());
                }
                let mut bytes = Vec::with_capacity(opened.len() as usize);
                file.take(8 * 1024 * 1024 + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|e| e.to_string())?;
                if bytes.len() > 8 * 1024 * 1024 {
                    return Err("run-step package exceeds its byte limit".into());
                }
                break bytes;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if Instant::now() >= deadline {
                    return Err("timed out waiting for host run-step package".into());
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(error) => return Err(format!("run-step package: {error}")),
        }
    };
    let package: RunStepPackage = crate::protocol::parse_unique(&bytes)?;
    package.validate()?;
    let descriptor_digest = digest_bytes(&bytes)?;
    if package.descriptor.run_id.as_str() != run_id {
        return Err("run-step package does not match --run".into());
    }
    let session =
        std::env::var("REX_SESSION").map_err(|_| "Rex block has no REX_SESSION identity")?;
    let block = std::env::var("REX_BLOCK").map_err(|_| "Rex block has no REX_BLOCK identity")?;
    if session != package.descriptor.rex_session_id
        || block != package.descriptor.rex_block_id.as_str()
    {
        return Err("Rex block context does not match the immutable run descriptor".into());
    }
    let current_exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let exe_digest = digest_file(&current_exe)?;
    if exe_digest != package.runtime_binary_digest {
        return Err("running rex-projects binary does not match pinned launch digest".into());
    }
    let rex = crate::adapters::rex::RexCliTransport::connect(
        &package.rex_cli_path,
        &package.rex_search_path,
        package.rex_endpoint.clone(),
        package.rex_server_identity.clone(),
        session.clone(),
        std::env::vars_os().collect::<BTreeMap<_, _>>(),
    )
    .map_err(|e| e.to_string())?;
    let context = rex
        .validate_context_block(&block)
        .map_err(|e| e.to_string())?;
    if context.window_id != package.rex_window_id {
        return Err("Rex block is in a different pinned window".into());
    }
    let spool = RunStepSpool::open(&package.descriptor.control_dir)?;
    let start = spool.publish_start_once(crate::launch::AgentStartRequest {
        schema_version: crate::launch::LAUNCH_SCHEMA_VERSION,
        operation_id: package.operation_id.clone(),
        agent_run_id: package.descriptor.run_id.clone(),
        project_id: package.project_id.clone(),
        controller_generation: package.controller_generation,
        descriptor_digest,
        runtime_binary_digest: package.runtime_binary_digest.clone(),
        environment_snapshot_id: package.descriptor.environment_snapshot_id.clone(),
        qualification_receipt_digest: package.qualification_receipt_digest.clone(),
        wrapper_pid: std::process::id(),
        wrapper_start_identity: process_start_identity()?,
        rex_session_id: session.clone(),
        rex_block_id: block.clone(),
    })?;
    let launch_receipt = spool.wait_start_receipt(
        &start,
        Duration::from_secs(package.start_ack_timeout_seconds),
    )?;
    if launch_receipt.decision != LaunchDecision::Accepted
        || launch_receipt.operation_id != package.operation_id
        || launch_receipt.runtime_binary_digest != package.runtime_binary_digest
        || launch_receipt.qualification_receipt_digest != package.qualification_receipt_digest
    {
        return Err("host did not durably accept this exact Agent launch".into());
    }
    let family_binding = spool.read_run_family_binding()?;
    if family_binding.agent_run_id != package.descriptor.run_id
        || family_binding.reservation_epoch != package.descriptor.run_epoch
        || family_binding.descriptor_digest != start.request.descriptor_digest
        || family_binding.wrapper_pid != std::process::id()
        || family_binding.wrapper_start_identity != start.request.wrapper_start_identity
    {
        return Err("host process-family binding does not match the accepted launch".into());
    }
    let mut environment = crate::environment::EnvironmentHandoff::consume_file(
        environment_handoff,
        &package.descriptor.environment_snapshot_id,
        package.operation_id.as_str(),
    )
    .map_err(|e| e.to_string())?;
    environment.insert(OsString::from("REX_SESSION"), OsString::from(&session));
    environment.insert(OsString::from("REX_BLOCK"), OsString::from(&block));
    environment.insert(OsString::from("REX_BLOCK_ID"), OsString::from(&block));
    environment.insert(
        OsString::from("REX_PROJECTS_CONTEXT"),
        OsString::from("agent"),
    );
    environment.insert(OsString::from("REX_PROJECTS_AGENT"), OsString::from("1"));
    environment.insert(
        OsString::from("REX_PROJECTS_PROJECT_ID"),
        OsString::from(package.project_id.as_str()),
    );
    environment.insert(
        OsString::from("REX_PROJECTS_ROLE"),
        OsString::from(role_name(package.descriptor.role)),
    );
    environment.insert(
        OsString::from("REX_PROJECTS_RUN_ID"),
        OsString::from(run_id),
    );
    let continuation =
        package
            .continuation
            .map(|value| crate::run_step::ConversationContinuation {
                provider: value.provider,
                conversation_id: value.conversation_id,
                profile_digest: value.profile_digest,
                instruction_digest: value.instruction_digest,
                workspace: value.workspace,
            });
    let request = crate::run_step::TurnRequest {
        descriptor: package.descriptor,
        profile: package.profile,
        role_contract: package.role_contract,
        prompt: package.prompt,
        environment,
        continuation,
        shutdown_grace: Duration::from_secs(package.shutdown_grace_seconds),
    };
    let mut observer = DurableFamilyObserver::new(&spool, family_binding);
    let result = crate::run_step::run_turn(&request, &mut observer).map_err(|e| e.to_string())?;
    let envelope = spool.publish_turn_result_once(&start, result)?;
    Ok(RunStepCliResult {
        run_id: run_id.to_owned(),
        result_digest: envelope.result_digest,
    })
}

pub(crate) struct DurableFamilyObserver<'a> {
    spool: &'a RunStepSpool,
    binding: RunFamilyBinding,
    inner: crate::run_step::SystemProcessObserver,
    provider_root: Option<ProcessIdentity>,
    provider_executable_path: Option<std::path::PathBuf>,
    provider_executable_digest: Option<Digest>,
    interrupted: bool,
}

impl<'a> DurableFamilyObserver<'a> {
    pub(crate) fn new(spool: &'a RunStepSpool, binding: RunFamilyBinding) -> Self {
        Self {
            spool,
            binding,
            inner: crate::run_step::SystemProcessObserver,
            provider_root: None,
            provider_executable_path: None,
            provider_executable_digest: None,
            interrupted: false,
        }
    }

    fn write_phase(
        &mut self,
        provider_pid: u32,
        tree: &[ProcessIdentity],
        coverage: RunFamilyCoverage,
    ) -> Result<(), String> {
        if self.interrupted && coverage != RunFamilyCoverage::Interrupted {
            return Err("run-step process-family observation was interrupted".into());
        }
        let result = self.write_phase_inner(provider_pid, tree, coverage);
        if result.is_err() {
            self.interrupted = true;
        }
        result
    }

    fn write_phase_inner(
        &mut self,
        provider_pid: u32,
        tree: &[ProcessIdentity],
        coverage: RunFamilyCoverage,
    ) -> Result<(), String> {
        let root = match &self.provider_root {
            Some(root) => root.clone(),
            None => {
                let root = tree
                    .iter()
                    .find(|process| process.pid == provider_pid)
                    .cloned()
                    .ok_or("run-step sample omitted the exact provider root")?;
                self.provider_root = Some(root.clone());
                root
            }
        };
        let mut process_tree = tree.to_vec();
        process_tree.sort_by(|left, right| {
            (left.pid, &left.start_identity).cmp(&(right.pid, &right.start_identity))
        });
        let wrapper_process = crate::process::process_identity_for_pid(self.binding.wrapper_pid)
            .map_err(|error| error.to_string())?
            .filter(|process| {
                process.pid == self.binding.wrapper_pid
                    && process.start_identity == self.binding.wrapper_start_identity
                    && process.quality == ProcessIdentityQuality::KernelBirthToken
            })
            .ok_or("run-step wrapper birth identity is no longer observable")?;
        if root.parent_pid != wrapper_process.pid {
            return Err("provider root is not a direct child of the bound run-step wrapper".into());
        }
        let provider_executable_path = self
            .provider_executable_path
            .clone()
            .ok_or("provider image identity was not observed while its root was live")?;
        let provider_executable_digest = self
            .provider_executable_digest
            .clone()
            .ok_or("provider image digest was not observed while its root was live")?;
        let bytes = serde_json::to_vec(&process_tree).map_err(|error| error.to_string())?;
        self.spool.write_run_family_record(&RunFamilyRecord {
            schema_version: 2,
            binding: self.binding.clone(),
            observed_at_unix: unix_now_seconds()?,
            coverage,
            wrapper_process,
            provider_root: root,
            provider_executable_path,
            provider_executable_digest,
            process_tree_digest: Digest::parse(format!("{:x}", Sha256::digest(bytes)))?,
            process_tree,
        })
    }
}

impl crate::run_step::ProcessObserver for DurableFamilyObserver<'_> {
    type Identity = ProcessIdentity;

    fn after_spawn(&mut self, pid: u32) -> Result<(), String> {
        crate::run_step::ProcessObserver::after_spawn(&mut self.inner, pid)
    }
    fn inspect(&mut self) -> Result<Vec<Self::Identity>, String> {
        crate::run_step::ProcessObserver::inspect(&mut self.inner)
    }
    fn try_wait(
        &mut self,
        child: &mut std::process::Child,
    ) -> std::io::Result<Option<std::process::ExitStatus>> {
        crate::run_step::ProcessObserver::try_wait(&mut self.inner, child)
    }
    fn pid(identity: &Self::Identity) -> u32 {
        <crate::run_step::SystemProcessObserver as crate::run_step::ProcessObserver>::pid(identity)
    }
    fn group(identity: &Self::Identity) -> u32 {
        <crate::run_step::SystemProcessObserver as crate::run_step::ProcessObserver>::group(
            identity,
        )
    }
    fn capture_tree(&self, root_pid: u32, table: &[Self::Identity]) -> Vec<Self::Identity> {
        crate::run_step::ProcessObserver::capture_tree(&self.inner, root_pid, table)
    }
    fn matching(
        &self,
        observed: &[Self::Identity],
        current: &[Self::Identity],
    ) -> Vec<Self::Identity> {
        crate::run_step::ProcessObserver::matching(&self.inner, observed, current)
    }
    fn signal_group_if_observed(
        &self,
        group: u32,
        observed: &[Self::Identity],
        current: &[Self::Identity],
        signal: ProcessSignal,
    ) -> Result<bool, String> {
        crate::run_step::ProcessObserver::signal_group_if_observed(
            &self.inner,
            group,
            observed,
            current,
            signal,
        )
    }

    fn observe_provider_image(
        &mut self,
        pid: u32,
        start_identity: &str,
        expected_path: &Path,
        expected_digest: &Digest,
    ) -> Result<(), String> {
        let identity = crate::process::process_identity_for_pid(pid)
            .map_err(|error| error.to_string())?
            .filter(|process| {
                process.pid == pid
                    && process.start_identity == start_identity
                    && process.quality == ProcessIdentityQuality::KernelBirthToken
            })
            .ok_or("provider root birth identity is not live during image inspection")?;
        let observed_path = crate::process::executable_path_for_identity(&identity)
            .map_err(|error| error.to_string())?
            .ok_or("provider executable image is unavailable for the live root identity")?;
        let expected_path = std::fs::canonicalize(expected_path).map_err(|e| e.to_string())?;
        let observed_path = std::fs::canonicalize(observed_path).map_err(|e| e.to_string())?;
        let observed_digest = digest_file(&observed_path)?;
        if observed_path != expected_path || observed_digest != *expected_digest {
            return Err("live provider image differs from the qualified executable".into());
        }
        match (
            &self.provider_executable_path,
            &self.provider_executable_digest,
        ) {
            (None, None) => {
                self.provider_executable_path = Some(observed_path);
                self.provider_executable_digest = Some(observed_digest);
                Ok(())
            }
            (Some(path), Some(digest)) if path == &observed_path && digest == &observed_digest => {
                Ok(())
            }
            _ => Err("provider image identity changed during one run".into()),
        }
    }
    fn checkpoint_family(
        &mut self,
        provider_pid: u32,
        tree: &[Self::Identity],
    ) -> Result<(), String> {
        self.write_phase(provider_pid, tree, RunFamilyCoverage::Observing)
    }
    fn complete_family(
        &mut self,
        provider_pid: u32,
        tree: &[Self::Identity],
    ) -> Result<(), String> {
        self.write_phase(provider_pid, tree, RunFamilyCoverage::Complete)
    }
    fn interrupt_family(&mut self) -> Result<(), String> {
        self.interrupted = true;
        let Some(mut record) = self.spool.read_run_family_record()? else {
            return Ok(());
        };
        if record.coverage == RunFamilyCoverage::Observing {
            record.coverage = RunFamilyCoverage::Interrupted;
            record.observed_at_unix = unix_now_seconds()?;
            self.spool.write_run_family_record(&record)?;
        }
        Ok(())
    }
}

fn unix_now_seconds() -> Result<i64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .map_err(|_| "system clock is before Unix epoch".into())
}

fn digest_file(path: &Path) -> Result<Digest, String> {
    use std::io::Read;
    let metadata = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("runtime executable must be a regular non-symlink file".into());
    }
    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|e| e.to_string())?
    };
    #[cfg(not(unix))]
    let mut file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buffer).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Digest::parse(format!("{:x}", hasher.finalize()))
}

fn process_start_identity() -> Result<String, String> {
    observed_process_start_identity(std::process::id())
        .filter(|identity| !identity.is_empty())
        .ok_or_else(|| "cannot observe wrapper process start identity".into())
}

fn observed_process_start_identity(pid: u32) -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
        let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
        let found = unsafe {
            libc::proc_pidinfo(
                pid as libc::c_int,
                libc::PROC_PIDTBSDINFO,
                0,
                info.as_mut_ptr().cast(),
                size,
            )
        };
        if found != size {
            return None;
        }
        let info = unsafe { info.assume_init() };
        Some(format!(
            "macos-start:{}:{}",
            info.pbi_start_tvsec, info.pbi_start_tvusec
        ))
    }
    #[cfg(target_os = "linux")]
    {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        Some(format!(
            "linux-start-ticks:{}",
            stat.rsplit_once(')')?.1.split_whitespace().nth(19)?
        ))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = pid;
        None
    }
}

fn observe_wrapper_process(
    pid: u32,
    claimed_start_identity: &str,
    expected_executable_digest: &Digest,
    rex_session_id: &str,
    rex_block_id: &str,
) -> Result<ObservedWrapperIdentity, String> {
    let current = inspect_process_table().map_err(|error| error.to_string())?;
    let identity = current
        .iter()
        .find(|process| process.pid == pid)
        .ok_or_else(|| "wrapper PID is not present in the host process table".to_owned())?;
    if identity.quality != ProcessIdentityQuality::KernelBirthToken
        || identity.start_identity != claimed_start_identity
    {
        return Err("wrapper PID birth identity does not match the host observation".into());
    }
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    let expected_path = std::fs::canonicalize(&executable).map_err(|error| error.to_string())?;
    let observed_path = crate::process::executable_path_for_identity(identity)
        .map_err(|error| error.to_string())?
        .ok_or("wrapper executable image is unavailable for the live PID birth identity")?;
    let observed_path = std::fs::canonicalize(observed_path).map_err(|error| error.to_string())?;
    if digest_file(&executable)? != *expected_executable_digest
        || observed_path != expected_path
        || digest_file(&observed_path)? != *expected_executable_digest
    {
        return Err("wrapper process does not match the pinned rex-projects executable".into());
    }
    Ok(ObservedWrapperIdentity {
        pid,
        start_identity: identity.start_identity.clone(),
        rex_session_id: rex_session_id.to_owned(),
        rex_block_id: rex_block_id.to_owned(),
        runtime_binary_digest: expected_executable_digest.clone(),
    })
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

#[cfg(test)]
mod tests {
    use super::{observe_wrapper_process, observed_process_start_identity, wait_for_start_request};
    use crate::domain::ids::{AgentRunId, Digest, OperationId, ProjectId};
    use crate::launch::AgentStartRequest;
    use crate::run_step_spool::RunStepSpool;
    use std::time::Duration;
    use tempfile::tempdir;

    fn start_request() -> AgentStartRequest {
        AgentStartRequest {
            schema_version: 1,
            operation_id: OperationId::parse("op-1").unwrap(),
            agent_run_id: AgentRunId::parse("run-1").unwrap(),
            project_id: ProjectId::parse("project-a").unwrap(),
            controller_generation: 1,
            descriptor_digest: digest('a'),
            runtime_binary_digest: digest('b'),
            environment_snapshot_id: digest('c'),
            qualification_receipt_digest: digest('d'),
            wrapper_pid: 100,
            wrapper_start_identity: "birth-100".into(),
            rex_session_id: "session-1".into(),
            rex_block_id: "block-1".into(),
        }
    }

    fn digest(value: char) -> Digest {
        Digest::parse(value.to_string().repeat(64)).unwrap()
    }

    #[test]
    fn host_waits_for_delayed_wrapper_start_request_before_validating_it() {
        let temp = tempdir().unwrap();
        let spool = RunStepSpool::open(temp.path()).unwrap();
        let writer_spool = spool.clone();
        let expected = start_request();
        let writer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            writer_spool.publish_start_once(expected).unwrap()
        });

        let observed = wait_for_start_request(&spool, Duration::from_secs(2), || Ok(())).unwrap();
        let published = writer.join().unwrap();
        assert_eq!(observed.request_digest, published.request_digest);
        assert_eq!(observed.request, published.request);
    }

    #[test]
    fn host_start_request_wait_stops_when_owner_check_cancels() {
        let temp = tempdir().unwrap();
        let spool = RunStepSpool::open(temp.path()).unwrap();
        let error = wait_for_start_request(&spool, Duration::from_secs(2), || {
            Err("controller owner generation changed".into())
        })
        .unwrap_err();
        assert_eq!(error, "controller owner generation changed");
    }

    #[test]
    fn current_wrapper_start_identity_is_observable() {
        let pid = std::process::id();
        let identity = observed_process_start_identity(pid).unwrap();
        let process = crate::process::inspect_process_table()
            .unwrap()
            .into_iter()
            .find(|process| process.pid == pid)
            .unwrap();
        assert_eq!(identity, process.start_identity);
    }

    #[test]
    fn wrapper_process_observation_accepts_kernel_truncated_executable_names() {
        let pid = std::process::id();
        let process = crate::process::inspect_process_table()
            .unwrap()
            .into_iter()
            .find(|process| process.pid == pid)
            .unwrap();
        let executable = std::env::current_exe().unwrap();
        let basename = executable.file_name().unwrap().to_str().unwrap();
        assert_ne!(
            process.command, basename,
            "the test executable name is truncated by the kernel process table"
        );
        let expected_digest = super::digest_file(&executable).unwrap();

        let observed = observe_wrapper_process(
            pid,
            &process.start_identity,
            &expected_digest,
            "fixture-session",
            "fixture-block",
        )
        .unwrap();

        assert_eq!(observed.pid, pid);
        assert_eq!(observed.runtime_binary_digest, expected_digest);
    }

    #[test]
    fn wrapper_process_observation_still_rejects_a_different_pinned_image_digest() {
        let pid = std::process::id();
        let process = crate::process::inspect_process_table()
            .unwrap()
            .into_iter()
            .find(|process| process.pid == pid)
            .unwrap();
        assert!(
            observe_wrapper_process(
                pid,
                &process.start_identity,
                &digest('a'),
                "fixture-session",
                "fixture-block",
            )
            .is_err()
        );
    }

    #[test]
    fn host_process_observation_rejects_a_stale_pid_birth_token() {
        let stale = Digest::parse("a".repeat(64)).unwrap();
        assert!(
            observe_wrapper_process(
                std::process::id(),
                "stale-birth-token",
                &stale,
                "session",
                "block",
            )
            .is_err()
        );
    }
}
