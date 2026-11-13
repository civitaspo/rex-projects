//! Runtime boundary for the finite-turn wrapper and host phase-two launch finalization.

use std::path::Path;

use sha2::{Digest as _, Sha256};

use crate::adapters::rex::{CreateDisposition, RexCliTransport, RexContextBlock, TicketWindow};
use crate::domain::ids::Digest;
use crate::domain::types::Role;
use crate::launch::{
    AgentLaunchAuthority, AgentLaunchReservation, AgentStartRequest, LaunchAnchorIdentity,
    LaunchDecision, ObservedWrapperIdentity, RexBlockLifecycle, RexBlockOwnership, RexViewBlock,
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
        || package.execution_slot_epoch != reservation.project_epoch
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
        || package.descriptor.worker_assignment != reservation.worker_assignment
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
        || package.supervision_mode.is_some() != request.rex_launch_anchor.is_some()
    {
        return Err("wrapper start request does not match the finalized host launch".into());
    }
    spool.publish_run_family_binding_once(&RunFamilyBinding {
        schema_version: 1,
        agent_run_id: authority.agent_run_id.clone(),
        reservation_epoch: reservation.project_epoch,
        authority_digest: authority.digest()?,
        descriptor_digest: authority.descriptor_digest.clone(),
        wrapper_pid: request.wrapper_pid,
        wrapper_start_identity: request.wrapper_start_identity.clone(),
        rex_launch_anchor: request.rex_launch_anchor.clone(),
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
            process.pid
                == request
                    .rex_launch_anchor
                    .as_ref()
                    .map_or(request.wrapper_pid, |anchor| anchor.pid)
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
        request.rex_launch_anchor.as_ref(),
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
    let rex_reports_launch_process =
        accepted_rex_observation_reports_launch_process(&process, request).is_some_and(|process| {
            process.path.as_deref().is_some_and(|path| {
                std::fs::canonicalize(path).ok().is_some_and(|path| {
                    digest_file(&path).ok().as_ref() == Some(&authority.runtime_binary_digest)
                })
            })
        });
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    if digest_file(&executable)? != authority.runtime_binary_digest {
        return Err("running rex-projects binary differs from launch authority".into());
    }
    let process_table = inspect_process_table()
        .map_err(|error| format!("reobserve accepted wrapper process: {error}"))?;
    let supervisor = process_table
        .iter()
        .find(|process| process.pid == request.wrapper_pid);
    let live_process_matches = accepted_supervisor_topology_matches(request, &process_table)
        && supervisor.is_some_and(|process| {
            executable_digest_for_process(process).ok().as_ref()
                == Some(&authority.runtime_binary_digest)
        })
        && request.rex_launch_anchor.as_ref().is_none_or(|anchor| {
            process_table
                .iter()
                .find(|process| process.pid == anchor.pid)
                .is_some_and(|process| {
                    executable_digest_for_process(process).ok().as_ref()
                        == Some(&authority.runtime_binary_digest)
                })
        });
    if !rex_reports_launch_process || !live_process_matches {
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

fn accepted_rex_observation_reports_launch_process<'a>(
    observation: &'a crate::adapters::rex::RexProcessObservation,
    request: &AgentStartRequest,
) -> Option<&'a crate::adapters::rex::RexProcessInfo> {
    let expected_pid = request
        .rex_launch_anchor
        .as_ref()
        .map_or(request.wrapper_pid, |anchor| anchor.pid);
    observation
        .child
        .as_ref()
        .filter(|process| process.pid == expected_pid)
        .or_else(|| {
            observation
                .foreground
                .iter()
                .chain(observation.ancestors.iter().flatten())
                .find(|process| process.pid == expected_pid)
        })
}

fn accepted_supervisor_topology_matches(
    request: &AgentStartRequest,
    process_table: &[ProcessIdentity],
) -> bool {
    let Some(supervisor) = process_table.iter().find(|process| {
        process.pid == request.wrapper_pid
            && process.start_identity == request.wrapper_start_identity
            && process.quality == ProcessIdentityQuality::KernelBirthToken
    }) else {
        return false;
    };
    request.rex_launch_anchor.as_ref().is_none_or(|anchor| {
        supervisor.parent_pid == anchor.pid
            && process_table.iter().any(|process| {
                process.pid == anchor.pid
                    && process.start_identity == anchor.start_identity
                    && process.quality == ProcessIdentityQuality::KernelBirthToken
            })
    })
}

fn executable_digest_for_process(identity: &ProcessIdentity) -> Result<Digest, String> {
    let path = crate::process::executable_path_for_identity(identity)
        .map_err(|error| error.to_string())?
        .ok_or("process executable is unavailable for its exact birth identity")?;
    let canonical = std::fs::canonicalize(path).map_err(|error| error.to_string())?;
    digest_file(&canonical)
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

pub(crate) fn validate_run_family_binding(
    package: &RunStepPackage,
    family_binding: &RunFamilyBinding,
    start_request: &crate::launch::AgentStartRequest,
    wrapper_pid: u32,
    wrapper_start_identity: &str,
) -> Result<(), String> {
    if family_binding.agent_run_id != package.descriptor.run_id
        || family_binding.reservation_epoch != package.execution_slot_epoch
        || family_binding.descriptor_digest != start_request.descriptor_digest
        || start_request.wrapper_pid != wrapper_pid
        || family_binding.wrapper_pid != wrapper_pid
        || start_request.wrapper_start_identity != wrapper_start_identity
        || family_binding.wrapper_start_identity != wrapper_start_identity
        || family_binding.rex_launch_anchor != start_request.rex_launch_anchor
        || package.supervision_mode.is_some() != start_request.rex_launch_anchor.is_some()
    {
        return Err("host process-family binding does not match the accepted launch".into());
    }
    Ok(())
}

/// Run one bounded finite turn from the exact host package and return only its receipt summary.
pub fn run_step(
    run_id: &str,
    package_path: &Path,
    environment_handoff: &Path,
) -> Result<RunStepCliResult, String> {
    if std::env::var_os("REX_PROJECTS_AGENT").is_none() {
        return Err("agent run-step must run inside a Rex Projects Agent block".into());
    }
    let (package, _) = read_run_step_package(package_path)?;
    if package.supervision_mode.is_none() {
        return run_step_foreground(run_id, package_path, environment_handoff, None, None, None);
    }
    if !cfg!(unix) {
        return Err("anchored finite-turn supervision requires Unix session isolation".into());
    }
    let anchor = LaunchAnchorIdentity {
        pid: std::process::id(),
        start_identity: process_start_identity()?,
    };
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    let mut command = std::process::Command::new(executable);
    command
        .arg("agent")
        .arg("run-step-supervisor")
        .arg("--run")
        .arg(run_id)
        .arg("--package")
        .arg(package_path)
        .arg("--environment-handoff")
        .arg(environment_handoff)
        .arg("--anchor-pid")
        .arg(anchor.pid.to_string())
        .arg("--anchor-start-identity")
        .arg(&anchor.start_identity)
        .env("REX_PROJECTS_INTERNAL_SUPERVISOR", "1");
    let mut supervisor = spawn_detached_supervisor(command)
        .map_err(|error| format!("start finite-turn supervisor: {error}"))?;
    let _anchor_eof_pipe = supervisor
        .stdin
        .take()
        .ok_or("finite-turn supervisor has no private anchor pipe")?;
    let status = supervisor
        .wait()
        .map_err(|error| format!("wait for finite-turn supervisor: {error}"))?;
    if !status.success() {
        return Err(format!("finite-turn supervisor exited with {status}"));
    }
    let spool = RunStepSpool::open(&package.descriptor.control_dir)?;
    let start = spool.read_start_request()?;
    let result = spool.read_turn_result(&start)?;
    Ok(RunStepCliResult {
        run_id: run_id.to_owned(),
        result_digest: result.result_digest,
    })
}

#[cfg(unix)]
fn spawn_detached_supervisor(
    mut command: std::process::Command,
) -> std::io::Result<std::process::Child> {
    use std::os::unix::process::CommandExt;

    command
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    // SAFETY: setsid is the only child-side operation and runs before exec.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
    command.spawn()
}

/// Internal child entry point. It accepts only the exact still-live Rex shim that launched it,
/// then turns EOF on the private pipe into bounded cancellation in the ordinary turn loop.
pub fn run_step_supervisor(
    run_id: &str,
    package_path: &Path,
    environment_handoff: &Path,
    anchor: LaunchAnchorIdentity,
) -> Result<RunStepCliResult, String> {
    if std::env::var("REX_PROJECTS_INTERNAL_SUPERVISOR").as_deref() != Ok("1") {
        return Err("internal finite-turn supervisor marker is missing".into());
    }
    let (package, _) = read_run_step_package(package_path)?;
    if package.supervision_mode
        != Some(crate::run_step_package::RunStepSupervisionMode::AnchoredSupervisor)
    {
        return Err("run-step package does not authorize an anchored supervisor".into());
    }
    let initial_wrapper_process =
        validate_supervisor_parent(&anchor, &package.runtime_binary_digest)?;
    let anchor_closed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let closed_for_reader = anchor_closed.clone();
    std::thread::spawn(move || {
        use std::io::Read;
        let mut stdin = std::io::stdin().lock();
        let mut byte = [0_u8; 1];
        loop {
            match stdin.read(&mut byte) {
                Ok(_) => {
                    closed_for_reader.store(true, std::sync::atomic::Ordering::Release);
                    return;
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => {
                    closed_for_reader.store(true, std::sync::atomic::Ordering::Release);
                    return;
                }
            }
        }
    });
    if anchor_closed.load(std::sync::atomic::Ordering::Acquire) {
        return Err("Rex launch anchor closed before start acknowledgement".into());
    }
    run_step_foreground(
        run_id,
        package_path,
        environment_handoff,
        Some(anchor),
        Some(anchor_closed),
        Some(initial_wrapper_process),
    )
}

fn read_run_step_package(package_path: &Path) -> Result<(RunStepPackage, Vec<u8>), String> {
    use std::fs::{self, OpenOptions};
    use std::io::Read;
    use std::time::{Duration, Instant};

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
                        .map_err(|error| error.to_string())?
                };
                #[cfg(not(unix))]
                let mut file = OpenOptions::new()
                    .read(true)
                    .open(package_path)
                    .map_err(|error| error.to_string())?;
                let metadata = file.metadata().map_err(|error| error.to_string())?;
                if !metadata.is_file() || metadata.len() > 8 * 1024 * 1024 {
                    return Err("run-step package changed to an invalid file".into());
                }
                let mut bytes = Vec::with_capacity(metadata.len() as usize);
                file.take(8 * 1024 * 1024 + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|error| error.to_string())?;
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
    Ok((package, bytes))
}

fn wait_start_receipt_or_anchor_close(
    spool: &RunStepSpool,
    start: &crate::run_step_spool::StartRequestEnvelope,
    timeout: std::time::Duration,
    anchor_closed: Option<&std::sync::Arc<std::sync::atomic::AtomicBool>>,
) -> Result<crate::launch::AgentLaunchReceipt, String> {
    let deadline = std::time::Instant::now()
        .checked_add(timeout)
        .ok_or("start acknowledgement deadline overflow")?;
    loop {
        if anchor_closed.is_some_and(|closed| closed.load(std::sync::atomic::Ordering::Acquire)) {
            return Err("Rex launch anchor closed before start acknowledgement".into());
        }
        if let Some(receipt) = spool.read_start_receipt(start)? {
            return Ok(receipt);
        }
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err("timed out waiting for the host start decision".into());
        }
        std::thread::sleep(std::time::Duration::from_millis(50).min(remaining));
    }
}

fn validate_supervisor_parent(
    anchor: &LaunchAnchorIdentity,
    expected_digest: &Digest,
) -> Result<ProcessIdentity, String> {
    if anchor.pid == 0
        || anchor.pid == std::process::id()
        || anchor.start_identity.trim().is_empty()
    {
        return Err("finite-turn supervisor has an invalid Rex launch anchor".into());
    }
    #[cfg(unix)]
    // SAFETY: getppid has no preconditions and only reads this process's parent pid.
    let parent_pid = unsafe { libc::getppid() } as u32;
    #[cfg(not(unix))]
    let parent_pid = 0;
    if parent_pid != anchor.pid {
        return Err(
            "finite-turn supervisor is not the direct child of its Rex launch anchor".into(),
        );
    }
    let current = inspect_process_table().map_err(|error| error.to_string())?;
    let supervisor_pid = std::process::id();
    let supervisor = current
        .iter()
        .find(|process| process.pid == supervisor_pid)
        .ok_or("finite-turn supervisor identity is not observable")?;
    let parent = current
        .iter()
        .find(|process| process.pid == anchor.pid)
        .ok_or("Rex launch anchor identity is not observable")?;
    if supervisor.quality != ProcessIdentityQuality::KernelBirthToken
        || supervisor.parent_pid != anchor.pid
        || parent.quality != ProcessIdentityQuality::KernelBirthToken
        || parent.start_identity != anchor.start_identity
    {
        return Err(
            "finite-turn supervisor parent identity does not match its Rex launch anchor".into(),
        );
    }
    let expected_executable =
        std::fs::canonicalize(std::env::current_exe().map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    for process in [supervisor, parent] {
        let observed = crate::process::executable_path_for_identity(process)
            .map_err(|error| error.to_string())?
            .ok_or("finite-turn launch process executable is unavailable")?;
        let observed = std::fs::canonicalize(observed).map_err(|error| error.to_string())?;
        if observed != expected_executable || digest_file(&observed)? != *expected_digest {
            return Err(
                "finite-turn launch process does not match the pinned runtime binary".into(),
            );
        }
    }
    Ok(supervisor.clone())
}

fn run_step_foreground(
    run_id: &str,
    package_path: &Path,
    environment_handoff: &Path,
    launch_anchor: Option<LaunchAnchorIdentity>,
    anchor_closed: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    initial_wrapper_process: Option<ProcessIdentity>,
) -> Result<RunStepCliResult, String> {
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::time::Duration;

    if std::env::var_os("REX_PROJECTS_AGENT").is_none() {
        return Err("agent run-step must run inside a Rex Projects Agent block".into());
    }
    let (package, bytes) = read_run_step_package(package_path)?;
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
    if package.supervision_mode.is_some() != launch_anchor.is_some() {
        return Err("run-step supervision mode does not match its exact launch anchor".into());
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
        wrapper_start_identity: initial_wrapper_process
            .as_ref()
            .map(|process| process.start_identity.clone())
            .map_or_else(process_start_identity, Ok)?,
        rex_launch_anchor: launch_anchor.clone(),
        rex_session_id: session.clone(),
        rex_block_id: block.clone(),
    })?;
    let launch_receipt = wait_start_receipt_or_anchor_close(
        &spool,
        &start,
        Duration::from_secs(package.start_ack_timeout_seconds),
        anchor_closed.as_ref(),
    )?;
    if launch_receipt.decision != LaunchDecision::Accepted
        || launch_receipt.operation_id != package.operation_id
        || launch_receipt.runtime_binary_digest != package.runtime_binary_digest
        || launch_receipt.qualification_receipt_digest != package.qualification_receipt_digest
    {
        return Err("host did not durably accept this exact Agent launch".into());
    }
    if anchor_closed
        .as_ref()
        .is_some_and(|closed| closed.load(std::sync::atomic::Ordering::Acquire))
    {
        return Err("Rex launch anchor closed before environment handoff".into());
    }
    let family_binding = spool.read_run_family_binding()?;
    validate_run_family_binding(
        &package,
        &family_binding,
        &start.request,
        std::process::id(),
        &start.request.wrapper_start_identity,
    )?;
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
    if anchor_closed
        .as_ref()
        .is_some_and(|closed| closed.load(std::sync::atomic::Ordering::Acquire))
    {
        return Err("Rex launch anchor closed before provider start".into());
    }
    let mut observer = DurableFamilyObserver::new(
        &spool,
        family_binding,
        anchor_closed,
        initial_wrapper_process,
    );
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
    anchor_closed: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    wrapper_process: Option<ProcessIdentity>,
    #[cfg(test)]
    first_checkpoint_test_delay: Option<(std::time::Duration, std::path::PathBuf)>,
}

impl<'a> DurableFamilyObserver<'a> {
    pub(crate) fn new(
        spool: &'a RunStepSpool,
        binding: RunFamilyBinding,
        anchor_closed: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
        initial_wrapper_process: Option<ProcessIdentity>,
    ) -> Self {
        Self {
            spool,
            binding,
            inner: crate::run_step::SystemProcessObserver,
            provider_root: None,
            provider_executable_path: None,
            provider_executable_digest: None,
            interrupted: false,
            anchor_closed,
            wrapper_process: initial_wrapper_process,
            #[cfg(test)]
            first_checkpoint_test_delay: None,
        }
    }

    #[cfg(test)]
    fn delay_first_checkpoint_for_test(
        &mut self,
        duration: std::time::Duration,
        marker: std::path::PathBuf,
    ) {
        self.first_checkpoint_test_delay = Some((duration, marker));
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
        if self.binding.rex_launch_anchor.is_some() && self.wrapper_process.is_none() {
            return Err("anchored supervisor lacks its startup process identity snapshot".into());
        }
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
        let live_wrapper = crate::process::process_identity_for_pid(self.binding.wrapper_pid)
            .map_err(|error| error.to_string())?
            .filter(|process| {
                process.pid == self.binding.wrapper_pid
                    && process.start_identity == self.binding.wrapper_start_identity
                    && process.quality == ProcessIdentityQuality::KernelBirthToken
            })
            .ok_or("run-step wrapper birth identity is no longer observable")?;
        let wrapper_process = match &self.wrapper_process {
            Some(previous)
                if previous.pid == live_wrapper.pid
                    && previous.start_identity == live_wrapper.start_identity
                    && previous.process_group_id == live_wrapper.process_group_id
                    && previous.quality == live_wrapper.quality =>
            {
                if self
                    .binding
                    .rex_launch_anchor
                    .as_ref()
                    .is_some_and(|anchor| previous.parent_pid != anchor.pid)
                {
                    return Err(
                        "anchored supervisor startup ancestry differs from its binding".into(),
                    );
                }
                previous.clone()
            }
            Some(_) => return Err("run-step wrapper identity changed during one run".into()),
            None => {
                self.wrapper_process = Some(live_wrapper.clone());
                live_wrapper
            }
        };
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

    fn cancellation_requested(&mut self) -> bool {
        self.anchor_closed
            .as_ref()
            .is_some_and(|closed| closed.load(std::sync::atomic::Ordering::Acquire))
    }
    fn cancellation_cause(&self) -> Option<crate::run_step::CancellationCause> {
        self.binding.rex_launch_anchor.as_ref().map(|anchor| {
            crate::run_step::CancellationCause::RexLaunchAnchorClosed {
                pid: anchor.pid,
                start_identity: anchor.start_identity.clone(),
            }
        })
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
        #[cfg(test)]
        if let Some((delay, marker)) = self.first_checkpoint_test_delay.take() {
            std::fs::write(marker, provider_pid.to_string()).map_err(|error| error.to_string())?;
            std::thread::sleep(delay);
        }
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
    claimed_anchor: Option<&LaunchAnchorIdentity>,
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
    let anchor_identity = match claimed_anchor {
        Some(anchor) => {
            if identity.parent_pid != anchor.pid || anchor.pid == pid {
                return Err(
                    "supervisor is not a direct child of the exact Rex launch anchor".into(),
                );
            }
            let anchor_process = current
                .iter()
                .find(|process| process.pid == anchor.pid)
                .ok_or("Rex launch anchor PID is not present in the host process table")?;
            if anchor_process.quality != ProcessIdentityQuality::KernelBirthToken
                || anchor_process.start_identity != anchor.start_identity
            {
                return Err(
                    "Rex launch anchor PID birth identity does not match the host observation"
                        .into(),
                );
            }
            let anchor_path = crate::process::executable_path_for_identity(anchor_process)
                .map_err(|error| error.to_string())?
                .ok_or("Rex launch anchor executable image is unavailable")?;
            let anchor_path =
                std::fs::canonicalize(anchor_path).map_err(|error| error.to_string())?;
            if anchor_path != expected_path
                || digest_file(&anchor_path)? != *expected_executable_digest
            {
                return Err(
                    "Rex launch anchor does not match the pinned rex-projects executable".into(),
                );
            }
            Some(anchor.clone())
        }
        None => None,
    };
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
        rex_launch_anchor: anchor_identity,
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
    use super::{
        DurableFamilyObserver, LaunchAnchorIdentity,
        accepted_rex_observation_reports_launch_process, accepted_supervisor_topology_matches,
        observe_wrapper_process, observed_process_start_identity, wait_for_start_request,
        wait_start_receipt_or_anchor_close,
    };
    use crate::config::{ClaudeCodeOptions, Profile, ProfileOptions};
    use crate::domain::ids::{AgentRunId, Digest, OperationId, ProjectId, RexBlockId};
    use crate::domain::types::{AgentAdapter, CommitMode, Role};
    use crate::launch::AgentStartRequest;
    use crate::process::{ProcessIdentity, ProcessIdentityQuality};
    use crate::run_step::{
        ProviderCapabilityEvidence, ProviderQualificationStatus, RunDescriptor, TurnRequest,
    };
    use crate::run_step_spool::{
        BlockLossCleanupSnapshot, RunFamilyBinding, RunFamilyCoverage, RunStepSpool,
    };
    use serde_json::json;
    use sha2::{Digest as _, Sha256};
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::Duration;
    use tempfile::tempdir;

    const BLOCK_LOSS_CHILD_ENV: &str = "REX_TEST_BLOCK_LOSS_RUN_STEP_CHILD";
    const BLOCK_LOSS_ROOT_ENV: &str = "REX_TEST_BLOCK_LOSS_RUN_STEP_ROOT";
    const BLOCK_LOSS_GRACE_ENV: &str = "REX_TEST_BLOCK_LOSS_RUN_STEP_GRACE";
    const BLOCK_LOSS_UNPUBLISHED_CHILD_ENV: &str = "REX_TEST_BLOCK_LOSS_UNPUBLISHED_CHILD";
    const BLOCK_LOSS_UNPUBLISHED_MARKER_ENV: &str = "REX_TEST_BLOCK_LOSS_UNPUBLISHED_MARKER";
    const ANCHORED_CHILD_ENV: &str = "REX_TEST_ANCHORED_SUPERVISOR_CHILD";
    const ANCHORED_SHIM_ENV: &str = "REX_TEST_ANCHORED_SHIM_CHILD";
    const ANCHORED_SHIM_MARKER_ENV: &str = "REX_TEST_ANCHORED_SHIM_MARKER";
    const ANCHOR_PID_ENV: &str = "REX_TEST_ANCHOR_PID";
    const ANCHOR_START_ENV: &str = "REX_TEST_ANCHOR_START";
    const FIRST_CHECKPOINT_MARKER_ENV: &str = "REX_TEST_FIRST_FAMILY_CHECKPOINT_MARKER";
    const CONNECTED_EOF_PACKAGE_ENV: &str = "REX_TEST_CONNECTED_EOF_PACKAGE";
    const CONNECTED_EOF_AUTHORITY_ENV: &str = "REX_TEST_CONNECTED_EOF_AUTHORITY";

    fn fixture_digest(value: char) -> Digest {
        Digest::parse(value.to_string().repeat(64)).unwrap()
    }

    fn block_loss_turn_request(
        root: &Path,
        provider_exit_marker: &Path,
        shutdown_grace: Duration,
    ) -> TurnRequest {
        fs::create_dir_all(root.join("workspace")).unwrap();
        fs::create_dir_all(root.join("control")).unwrap();
        let executable = fs::canonicalize("/usr/bin/perl").unwrap();
        let script = r#"
while (-e $ARGV[2]) { select undef, undef, undef, 0.01; }
$SIG{TERM} = 'IGNORE';
$SIG{INT} = 'IGNORE';
open my $ready, '>', $ARGV[1] or die $!;
print {$ready} "$$\n";
close $ready or die $!;
while (! -e $ARGV[0]) { select undef, undef, undef, 0.05; }
"#;
        let profile = Profile {
            adapter: AgentAdapter::ClaudeCode,
            command: vec![
                executable.display().to_string(),
                "-e".into(),
                script.into(),
                provider_exit_marker.display().to_string(),
                root.join("provider-ready").display().to_string(),
                root.join("provider-init-gate").display().to_string(),
            ],
            description: None,
            model: Some("fixture-model".into()),
            effort: None,
            turn_timeout_seconds: 60,
            instruction_files: Vec::new(),
            skill_paths: Vec::new(),
            commit_mode: CommitMode::Host,
            learned_guidance: None,
            options: Some(ProfileOptions::ClaudeCode(ClaudeCodeOptions::default())),
        };
        let profile_digest = fixture_digest('a');
        let result_schema = json!({"type":"object","properties":{"ok":{"type":"boolean"}},"required":["ok"],"additionalProperties":false});
        let projection = crate::providers::project_result_schema(&result_schema).unwrap();
        let provider_capability = ProviderCapabilityEvidence {
            schema_version: 1,
            adapter: AgentAdapter::ClaudeCode,
            profile_digest: profile_digest.clone(),
            version: "block-loss-run-step-test".into(),
            executable_path: executable.clone(),
            executable_digest: super::digest_file(&executable).unwrap(),
            permission_mode: "auto; permission prompts denied unattended".into(),
            invocation_options_digest: crate::run_step::invocation_options_digest(&profile)
                .unwrap(),
            commit_mode: profile.commit_mode,
            schema_projection: projection.identity,
            receipt_digest: fixture_digest('b'),
            status: ProviderQualificationStatus::Verified,
        };
        TurnRequest {
            descriptor: RunDescriptor {
                schema_version: 1,
                project_id: ProjectId::parse("project-block-loss-run-step").unwrap(),
                run_id: AgentRunId::parse("run-block-loss-run-step").unwrap(),
                operation_id: OperationId::parse("operation-block-loss-run-step").unwrap(),
                role: Role::Worker,
                ticket_run_id: None,
                expected_subject_revision: 0,
                attempt: 1,
                run_epoch: 1,
                controller_generation: 1,
                workspace: root.join("workspace"),
                control_dir: root.join("control"),
                worker_assignment: None,
                rex_session_id: "session-block-loss-run-step".into(),
                rex_block_id: RexBlockId::parse("block-block-loss-run-step").unwrap(),
                profile_digest,
                instruction_digest: fixture_digest('c'),
                plan_digest: None,
                environment_snapshot_id: fixture_digest('d'),
                wake_snapshot_digest: fixture_digest('e'),
                provider_capability,
                result_schema,
            },
            profile,
            role_contract: "fixture Worker".into(),
            prompt: "wait for the test harness".into(),
            environment: BTreeMap::from([(
                OsString::from("PATH"),
                OsString::from("/bin:/usr/bin"),
            )]),
            continuation: None,
            shutdown_grace,
        }
    }

    fn run_block_loss_child(root: PathBuf) {
        let anchor = std::env::var_os(ANCHORED_CHILD_ENV).map(|_| LaunchAnchorIdentity {
            pid: std::env::var(ANCHOR_PID_ENV).unwrap().parse().unwrap(),
            start_identity: std::env::var(ANCHOR_START_ENV).unwrap(),
        });
        let anchor_closed = anchor.as_ref().map(|_| {
            let closed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let reader_closed = closed.clone();
            std::thread::spawn(move || {
                use std::io::Read;
                let mut stdin = std::io::stdin().lock();
                let mut byte = [0_u8; 1];
                loop {
                    match stdin.read(&mut byte) {
                        Ok(_) => {
                            reader_closed.store(true, std::sync::atomic::Ordering::Release);
                            return;
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(_) => {
                            reader_closed.store(true, std::sync::atomic::Ordering::Release);
                            return;
                        }
                    }
                }
            });
            closed
        });
        let shutdown_grace = Duration::from_secs(
            std::env::var(BLOCK_LOSS_GRACE_ENV)
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(1),
        );
        let connected_package = std::env::var_os(CONNECTED_EOF_PACKAGE_ENV).map(PathBuf::from);
        let (
            request,
            descriptor_digest,
            runtime_binary_digest,
            qualification_digest,
            _authority_digest,
            reservation_epoch,
        ) = if let Some(package_path) = connected_package.as_ref() {
            let package: crate::run_step_package::RunStepPackage =
                crate::protocol::parse_unique(&fs::read(package_path).unwrap()).unwrap();
            let descriptor_digest = super::digest_file(package_path).unwrap();
            let request = crate::run_step::TurnRequest {
                descriptor: package.descriptor.clone(),
                profile: package.profile.clone(),
                role_contract: package.role_contract.clone(),
                prompt: package.prompt.clone(),
                environment: BTreeMap::from([(
                    OsString::from("PATH"),
                    OsString::from("/bin:/usr/bin"),
                )]),
                continuation: None,
                shutdown_grace: Duration::from_secs(package.shutdown_grace_seconds),
            };
            (
                request,
                descriptor_digest,
                package.runtime_binary_digest,
                package.qualification_receipt_digest,
                Digest::parse(std::env::var(CONNECTED_EOF_AUTHORITY_ENV).unwrap()).unwrap(),
                package.execution_slot_epoch,
            )
        } else {
            let request =
                block_loss_turn_request(&root, &root.join("provider-exit"), shutdown_grace);
            (
                request,
                fixture_digest('f'),
                super::digest_file(&std::env::current_exe().unwrap()).unwrap(),
                fixture_digest('b'),
                fixture_digest('2'),
                1,
            )
        };
        let wrapper_pid = std::process::id();
        let wrapper_process = crate::process::process_identity_for_pid(wrapper_pid)
            .unwrap()
            .unwrap();
        let wrapper_start_identity = wrapper_process.start_identity.clone();
        let spool = RunStepSpool::open(&request.descriptor.control_dir).unwrap();
        let start = spool
            .publish_start_once(AgentStartRequest {
                schema_version: 1,
                operation_id: request.descriptor.operation_id.clone(),
                agent_run_id: request.descriptor.run_id.clone(),
                project_id: request.descriptor.project_id.clone(),
                controller_generation: request.descriptor.controller_generation,
                descriptor_digest: descriptor_digest.clone(),
                runtime_binary_digest,
                environment_snapshot_id: request.descriptor.environment_snapshot_id.clone(),
                qualification_receipt_digest: qualification_digest.clone(),
                wrapper_pid,
                wrapper_start_identity: wrapper_start_identity.clone(),
                rex_launch_anchor: anchor.clone(),
                rex_session_id: request.descriptor.rex_session_id.clone(),
                rex_block_id: request.descriptor.rex_block_id.as_str().to_owned(),
            })
            .unwrap();
        let binding_authority_digest = if connected_package.is_some() {
            Digest::parse(std::env::var(CONNECTED_EOF_AUTHORITY_ENV).unwrap()).unwrap()
        } else {
            fixture_digest('2')
        };
        spool
            .publish_run_family_binding_once(&RunFamilyBinding {
                schema_version: 1,
                agent_run_id: request.descriptor.run_id.clone(),
                reservation_epoch,
                authority_digest: binding_authority_digest,
                descriptor_digest,
                wrapper_pid,
                wrapper_start_identity,
                rex_launch_anchor: anchor,
            })
            .unwrap();
        if connected_package.is_some() {
            spool
                .wait_start_receipt(&start, Duration::from_secs(10))
                .unwrap();
        }
        let mut observer = DurableFamilyObserver::new(
            &spool,
            spool.read_run_family_binding().unwrap(),
            anchor_closed,
            Some(wrapper_process),
        );
        if let Some(marker) = std::env::var_os(FIRST_CHECKPOINT_MARKER_ENV) {
            observer
                .delay_first_checkpoint_for_test(Duration::from_millis(500), PathBuf::from(marker));
        }
        let result = crate::run_step::run_turn(&request, &mut observer).unwrap();
        spool.publish_turn_result_once(&start, result).unwrap();
    }

    fn wait_for_observing_family(spool: &RunStepSpool) -> crate::run_step_spool::RunFamilyRecord {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(family) = spool.read_run_family_record().unwrap()
                && family.coverage == RunFamilyCoverage::Observing
            {
                return family;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "family did not become Observing"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn block_loss_snapshot(
        family: &crate::run_step_spool::RunFamilyRecord,
    ) -> BlockLossCleanupSnapshot {
        let mut process_tree = family.process_tree.clone();
        process_tree.push(family.wrapper_process.clone());
        process_tree.sort_by(|left, right| {
            (left.pid, &left.start_identity).cmp(&(right.pid, &right.start_identity))
        });
        let bytes = serde_json::to_vec(&process_tree).unwrap();
        BlockLossCleanupSnapshot {
            schema_version: crate::run_step_spool::BLOCK_LOSS_SNAPSHOT_VERSION,
            agent_run_id: family.binding.agent_run_id.clone(),
            reservation_epoch: family.binding.reservation_epoch,
            authority_digest: family.binding.authority_digest.clone(),
            launch_tree_digest: family.process_tree_digest.clone(),
            observed_at_unix: super::unix_now_seconds().unwrap(),
            cleanup_covered: false,
            process_tree,
            process_tree_digest: Digest::parse(format!("{:x}", Sha256::digest(&bytes))).unwrap(),
        }
    }

    fn signal_groups(
        process_tree: &[crate::process::ProcessIdentity],
        signal: crate::process::ProcessSignal,
    ) -> bool {
        let current = crate::process::inspect_process_table().unwrap();
        let mut signalled = false;
        for group in process_tree
            .iter()
            .map(|process| process.process_group_id)
            .collect::<std::collections::BTreeSet<_>>()
        {
            signalled |= crate::process::signal_process_group_if_observed(
                group,
                process_tree,
                &current,
                signal,
            )
            .unwrap_or(false);
        }
        signalled
    }

    fn process_is_live(identity: &crate::process::ProcessIdentity) -> bool {
        crate::process::inspect_process_table()
            .unwrap()
            .iter()
            .any(|current| {
                current.pid == identity.pid && current.start_identity == identity.start_identity
            })
    }

    fn wait_for_family_absence(family: &crate::run_step_spool::RunFamilyRecord) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            if !process_is_live(&family.wrapper_process)
                && family
                    .process_tree
                    .iter()
                    .all(|identity| !process_is_live(identity))
            {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "observed family did not exit"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    struct BlockLossChildGuard {
        child: std::process::Child,
        child_identity: Option<crate::process::ProcessIdentity>,
        spool: RunStepSpool,
        family: Option<crate::run_step_spool::RunFamilyRecord>,
        snapshot: Option<BlockLossCleanupSnapshot>,
        finished: bool,
    }

    impl BlockLossChildGuard {
        fn new(child: std::process::Child, spool: RunStepSpool) -> Self {
            let deadline = std::time::Instant::now() + Duration::from_millis(250);
            let child_identity = loop {
                let identity = crate::process::inspect_process_table()
                    .ok()
                    .and_then(|table| {
                        table.into_iter().find(|process| {
                            process.pid == child.id()
                                && process.quality
                                    == crate::process::ProcessIdentityQuality::KernelBirthToken
                        })
                    });
                if identity.is_some() || std::time::Instant::now() >= deadline {
                    break identity;
                }
                std::thread::sleep(Duration::from_millis(5));
            };
            Self {
                child,
                child_identity,
                spool,
                family: None,
                snapshot: None,
                finished: false,
            }
        }

        fn observe(&mut self, family: crate::run_step_spool::RunFamilyRecord) {
            self.snapshot = Some(block_loss_snapshot(&family));
            self.family = Some(family);
        }

        fn wait_bounded(&mut self, timeout: Duration) -> std::io::Result<std::process::ExitStatus> {
            let deadline = std::time::Instant::now() + timeout;
            loop {
                if let Some(status) = self.child.try_wait()? {
                    return Ok(status);
                }
                if std::time::Instant::now() >= deadline {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "run-step child exceeded bounded receipt-writer wait",
                    ));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }

        fn cleanup(&mut self) {
            if self.family.is_none() {
                self.family = self.spool.read_run_family_record().ok().flatten();
            }
            if self.snapshot.is_none()
                && let Some(family) = &self.family
            {
                self.snapshot = Some(block_loss_snapshot(family));
            }
            if self.snapshot.is_none()
                && let (Some(root), Ok(current)) = (
                    self.child_identity.as_ref(),
                    crate::process::inspect_process_table(),
                )
            {
                let root_is_same_birth = current.iter().any(|process| {
                    process.pid == root.pid
                        && process.start_identity == root.start_identity
                        && process.quality
                            == crate::process::ProcessIdentityQuality::KernelBirthToken
                });
                let observed = if root_is_same_birth {
                    crate::process::capture_process_tree(root.pid, &current)
                } else {
                    Vec::new()
                };
                let observed_root_is_same_birth = observed.iter().any(|process| {
                    process.pid == root.pid && process.start_identity == root.start_identity
                });
                if observed_root_is_same_birth {
                    for group in observed
                        .iter()
                        .map(|process| process.process_group_id)
                        .collect::<std::collections::BTreeSet<_>>()
                    {
                        let _ = crate::process::signal_process_group_if_observed(
                            group,
                            &observed,
                            &current,
                            crate::process::ProcessSignal::Kill,
                        );
                    }
                }
            }
            if let Some(snapshot) = &self.snapshot
                && let Ok(current) = crate::process::inspect_process_table()
            {
                for group in snapshot
                    .process_tree
                    .iter()
                    .map(|p| p.process_group_id)
                    .collect::<std::collections::BTreeSet<_>>()
                {
                    let _ = crate::process::signal_process_group_if_observed(
                        group,
                        &snapshot.process_tree,
                        &current,
                        crate::process::ProcessSignal::Kill,
                    );
                }
            }
            let _ = self.child.kill();
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            loop {
                match self.child.try_wait() {
                    Ok(Some(_)) | Err(_) => break,
                    Ok(None) if std::time::Instant::now() >= deadline => break,
                    Ok(None) => std::thread::sleep(Duration::from_millis(10)),
                }
            }
        }
    }

    impl Drop for BlockLossChildGuard {
        fn drop(&mut self) {
            if !self.finished {
                self.cleanup();
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn block_loss_run_step_child() {
        if std::env::var_os(BLOCK_LOSS_CHILD_ENV).is_none() {
            return;
        }
        run_block_loss_child(PathBuf::from(
            std::env::var_os(BLOCK_LOSS_ROOT_ENV).unwrap(),
        ));
    }

    #[cfg(unix)]
    #[test]
    fn anchored_shim_child() {
        if std::env::var_os(ANCHORED_SHIM_ENV).is_none() {
            return;
        }
        let root = PathBuf::from(std::env::var_os(BLOCK_LOSS_ROOT_ENV).unwrap());
        let anchor_pid = std::process::id();
        let anchor_start = observed_process_start_identity(anchor_pid).unwrap();
        let executable = std::env::current_exe().unwrap();
        let mut command = Command::new(executable);
        command
            .args([
                "--exact",
                "run_step_cli::tests::block_loss_run_step_child",
                "--nocapture",
            ])
            .env(ANCHORED_CHILD_ENV, "1")
            .env(ANCHOR_PID_ENV, anchor_pid.to_string())
            .env(ANCHOR_START_ENV, &anchor_start)
            .env(BLOCK_LOSS_CHILD_ENV, "1")
            .env(BLOCK_LOSS_ROOT_ENV, &root)
            .env(BLOCK_LOSS_GRACE_ENV, "1");
        if let Some(marker) = std::env::var_os(FIRST_CHECKPOINT_MARKER_ENV) {
            command.env(FIRST_CHECKPOINT_MARKER_ENV, marker);
        }
        let mut supervisor = super::spawn_detached_supervisor(command).unwrap();
        let _anchor_pipe = supervisor.stdin.take().unwrap();
        let supervisor_identity = loop {
            if let Some(identity) = crate::process::process_identity_for_pid(supervisor.id())
                .unwrap()
                .filter(|identity| {
                    identity.quality == crate::process::ProcessIdentityQuality::KernelBirthToken
                })
            {
                break identity;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        fs::write(
            std::env::var_os(ANCHORED_SHIM_MARKER_ENV).unwrap(),
            format!(
                "{}\n{}",
                supervisor.id(),
                supervisor_identity.start_identity
            ),
        )
        .unwrap();
        let status = supervisor.wait().unwrap();
        assert!(status.success(), "anchored supervisor failed: {status}");
    }

    #[cfg(unix)]
    #[test]
    fn anchored_eof_receipt_passes_host_verifier_and_releases_only_its_slot() {
        use crate::launch::{ObservedProviderStart, ProviderProcessIdentity};
        use crate::run_step_spool::BlockLossCleanupSnapshot;
        use crate::store::agent_recovery::RecoverableAgentRun;
        use crate::store::agent_runtime::tests::{
            prepared_anchored_block_loss_fixture_exiting_one, test_agent_launch_states,
            test_execution_slot_disposition, test_lifecycle_fact_counts,
            test_terminal_receipt_count,
        };
        use sha2::{Digest as _, Sha256};

        let root = tempdir().unwrap();
        let mut fixture = prepared_anchored_block_loss_fixture_exiting_one(root.path());
        let package_path = fixture.authority.descriptor_path.clone();
        let marker = root.path().join("supervisor.identity");
        let shim_command = || {
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "run_step_cli::tests::anchored_shim_child",
                    "--nocapture",
                ])
                .env(ANCHORED_SHIM_ENV, "1")
                .env(ANCHORED_SHIM_MARKER_ENV, &marker)
                .env(BLOCK_LOSS_ROOT_ENV, root.path())
                .env(CONNECTED_EOF_PACKAGE_ENV, &package_path)
                .env(
                    CONNECTED_EOF_AUTHORITY_ENV,
                    fixture.authority_digest.as_str(),
                )
                .env(BLOCK_LOSS_GRACE_ENV, "1")
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            command
        };
        let mut shim = shim_command().spawn().unwrap();
        let marker_deadline = std::time::Instant::now() + Duration::from_secs(3);
        while !marker.exists() {
            assert!(std::time::Instant::now() < marker_deadline);
            std::thread::sleep(Duration::from_millis(10));
        }

        let spool = RunStepSpool::open(&fixture.authority.control_dir).unwrap();
        let start = loop {
            if let Ok(start) = spool.read_start_request() {
                break start;
            }
            assert!(std::time::Instant::now() < marker_deadline + Duration::from_secs(3));
            std::thread::sleep(Duration::from_millis(10));
        };
        let observed = observe_wrapper_process(
            start.request.wrapper_pid,
            &start.request.wrapper_start_identity,
            start.request.rex_launch_anchor.as_ref(),
            &start.request.runtime_binary_digest,
            &start.request.rex_session_id,
            &start.request.rex_block_id,
        )
        .unwrap();
        fixture
            .store
            .authorize_agent_start(fixture.generation, &start.request, &observed)
            .unwrap();
        spool
            .publish_start_receipt(
                &start,
                fixture
                    .store
                    .persisted_start_receipt(&start.request)
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();

        let observing = wait_for_observing_family(&spool);
        assert_eq!(observing.binding.authority_digest, fixture.authority_digest);
        assert_eq!(
            observing.binding.rex_launch_anchor,
            start.request.rex_launch_anchor
        );
        let mut provider_tree = vec![ProviderProcessIdentity {
            pid: observing.wrapper_process.pid,
            parent_pid: observing.wrapper_process.parent_pid,
            process_group_id: observing.wrapper_process.process_group_id,
            start_identity: observing.wrapper_process.start_identity.clone(),
            identity_quality: observing.wrapper_process.quality,
        }];
        provider_tree.extend(observing.process_tree.iter().map(|process| {
            ProviderProcessIdentity {
                pid: process.pid,
                parent_pid: process.parent_pid,
                process_group_id: process.process_group_id,
                start_identity: process.start_identity.clone(),
                identity_quality: process.quality,
            }
        }));
        provider_tree.push(ProviderProcessIdentity {
            pid: u32::MAX - 1,
            parent_pid: observing.provider_root.pid,
            process_group_id: observing.provider_root.process_group_id,
            start_identity: "historical-launch-only-birth".into(),
            identity_quality: ProcessIdentityQuality::KernelBirthToken,
        });
        let provider_tree_digest = Digest::parse(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&provider_tree).unwrap())
        ))
        .unwrap();
        let provider = ObservedProviderStart {
            agent_run_id: fixture.authority.agent_run_id.clone(),
            operation_id: fixture.authority.operation_id.clone(),
            provider_pid: observing.provider_root.pid,
            provider_start_identity: observing.provider_root.start_identity.clone(),
            executable_digest: fixture.qualification.executable_digest.clone(),
            process_tree_digest: provider_tree_digest.clone(),
            process_tree_confirmed: true,
            process_tree: provider_tree,
        };
        provider
            .validate_complete_process_tree(&fixture.qualification)
            .unwrap();
        fixture
            .store
            .confirm_provider_started(fixture.generation, &provider)
            .unwrap();

        shim.kill().unwrap();
        assert!(!shim.wait().unwrap().success());
        let result_deadline = std::time::Instant::now() + Duration::from_secs(10);
        let result = loop {
            if let Ok(result) = spool.read_turn_result(&start) {
                break result;
            }
            assert!(std::time::Instant::now() < result_deadline);
            std::thread::sleep(Duration::from_millis(20));
        };
        let family = spool.read_run_family_record().unwrap().unwrap();
        assert_eq!(family.coverage, RunFamilyCoverage::Complete);
        assert!(matches!(
            result.receipt.cancellation_cause,
            Some(crate::run_step::CancellationCause::RexLaunchAnchorClosed { .. })
        ));
        assert_eq!(result.receipt.exit_code, Some(1));
        let cleanup_deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let current = crate::process::inspect_process_table().unwrap();
            let identities = std::iter::once(&family.wrapper_process)
                .chain(family.process_tree.iter())
                .collect::<Vec<_>>();
            if identities.iter().all(|saved| {
                !current.iter().any(|observed| {
                    observed.pid == saved.pid && observed.start_identity == saved.start_identity
                })
            }) {
                break;
            }
            assert!(
                std::time::Instant::now() < cleanup_deadline,
                "producer emitted a terminal result before the complete process family was absent"
            );
            std::thread::sleep(Duration::from_millis(20));
        }

        let mut snapshot_processes = provider
            .process_tree
            .iter()
            .map(|process| ProcessIdentity {
                pid: process.pid,
                parent_pid: process.parent_pid,
                process_group_id: process.process_group_id,
                start_identity: process.start_identity.clone(),
                command: String::new(),
                quality: process.identity_quality,
            })
            .collect::<Vec<_>>();
        snapshot_processes.extend(family.process_tree.clone());
        snapshot_processes.push(family.wrapper_process.clone());
        snapshot_processes.sort_by(|left, right| {
            (left.pid, &left.start_identity).cmp(&(right.pid, &right.start_identity))
        });
        snapshot_processes.dedup_by(|right, left| {
            right.pid == left.pid
                && right.parent_pid == left.parent_pid
                && right.process_group_id == left.process_group_id
                && right.start_identity == left.start_identity
                && right.quality == left.quality
        });
        let snapshot_bytes = serde_json::to_vec(&snapshot_processes).unwrap();
        let snapshot = BlockLossCleanupSnapshot {
            schema_version: crate::run_step_spool::BLOCK_LOSS_SNAPSHOT_VERSION,
            agent_run_id: fixture.authority.agent_run_id.clone(),
            reservation_epoch: fixture.reservation.project_epoch,
            authority_digest: fixture.authority_digest.clone(),
            launch_tree_digest: provider_tree_digest,
            observed_at_unix: super::unix_now_seconds().unwrap(),
            cleanup_covered: false,
            process_tree: snapshot_processes,
            process_tree_digest: Digest::parse(format!("{:x}", Sha256::digest(snapshot_bytes)))
                .unwrap(),
        };
        let wrapper_json = serde_json::to_string(&observed).unwrap();
        let run = RecoverableAgentRun {
            agent_run_id: fixture.authority.agent_run_id.clone(),
            current_generation: fixture.generation,
            previous_generation: fixture.generation,
            authority: fixture.authority.clone(),
            authority_digest: fixture.authority_digest.clone(),
            agent_state: "running".into(),
            started_at_unix: Some(1),
            launch_state: "running".into(),
            process_identity_json: None,
            wrapper_identity_json: Some(wrapper_json),
            provider_tree_json: None,
            pool: fixture.reservation.pool.clone(),
            slot_index: fixture.reservation.slot_index,
            reservation_epoch: fixture.reservation.project_epoch,
            slot_disposition: "live".into(),
        };
        let cleanup = crate::store::agent_results::verify_cancelled_agent_cleanup(
            &fixture.store,
            fixture.generation,
            &run,
            &start,
            &result,
            &family,
            &snapshot,
        )
        .unwrap();
        assert!(
            fixture
                .store
                .reconcile_cancelled_agent_block(fixture.generation, &run, &snapshot, &cleanup)
                .unwrap()
        );
        assert_eq!(
            test_execution_slot_disposition(&fixture.store, &fixture.slot_owner_id),
            "released"
        );
        assert_eq!(
            test_execution_slot_disposition(&fixture.store, "unrelated-run"),
            "unknown"
        );
        assert_eq!(
            test_agent_launch_states(&fixture.store, &fixture.slot_owner_id),
            ("cancelled".into(), fixture.generation, "cancelled".into())
        );
        assert_eq!(
            test_lifecycle_fact_counts(
                &fixture.store,
                &fixture.slot_owner_id,
                fixture.reservation.project_epoch,
            ),
            (1, 1)
        );
        assert_eq!(
            test_terminal_receipt_count(&fixture.store, &fixture.slot_owner_id),
            0
        );
    }

    #[cfg(unix)]
    #[test]
    fn runtime_services_reconnect_recovers_a_real_run_step_after_missed_block_close() {
        use crate::adapters::rex::{RexCliTransport, RexIdentity};
        use crate::engine::factory_runtime::FactoryRuntimeObservationServices;
        use crate::runtime_services::{RuntimeExecutable, RuntimeServices};
        use crate::store::agent_runtime::tests::{
            prepared_anchored_block_loss_fixture, test_agent_launch_states,
            test_execution_slot_disposition,
        };

        let root = tempdir().unwrap();
        let mut fixture = prepared_anchored_block_loss_fixture(root.path());
        let state_root = root.path().join("state");
        let rex = root.path().join("rex connected recovery fixture");
        let first_reader_pid = root.path().join("first reader pid");
        let replacement_reader_pid = root.path().join("replacement reader pid");
        let subscription_count = root.path().join("subscription count");
        let allow_first_eof = root.path().join("allow first eof");
        let closed = root.path().join("block closed");
        let process_observation_file = root.path().join("process observation.json");
        let shell_path =
            |path: &Path| format!("'{}'", path.display().to_string().replace('\'', "'\\''"));
        let first_reader_pid_pending = first_reader_pid.with_extension("pid.pending");
        let replacement_reader_pid_pending = replacement_reader_pid.with_extension("pid.pending");
        let endpoint = "unix:///tmp/rex-connected-recovery-fixture.sock";
        let instance = "rex-instance";
        let session = fixture.authority.rex_session_id.clone();
        let block = fixture.authority.rex_block_id.clone();
        let window = fixture.authority.rex_window_id.clone();
        let run_id = fixture.authority.agent_run_id.to_string();
        let label = crate::adapters::rex::owned_agent_block_label(&run_id).unwrap();
        let script = format!(
            r##"#!/bin/sh
case "$*" in
  *"whoami --json"*) printf '%s\n' '{{"endpoint":"{endpoint}","instance_id":"{instance}","host_id":"fixture","rex_version":"1"}}' ;;
  *"api list --json"*) printf '%s\n' '{{"methods":{{"session.view":{{}},"session.new_window":{{}},"session.new_split":{{}},"session.focus_block":{{}},"session.zoom_block":{{}},"block.close":{{}}}}}}' ;;
  *"events -s {session} --json"*) n=0; [ ! -f {subscription_count} ] || n=$(cat {subscription_count}); n=$((n + 1)); printf '%s\n' "$n" > {subscription_count}; if [ "$n" -eq 1 ]; then printf '%s\n' "$$" > {first_reader_pid_pending}; mv {first_reader_pid_pending} {first_reader_pid}; while [ ! -f {allow_first_eof} ]; do /bin/sleep 0.01; done; exit 0; fi; printf '%s\n' "$$" > {replacement_reader_pid_pending}; mv {replacement_reader_pid_pending} {replacement_reader_pid}; exec /bin/sleep 30 ;;
  *"api call session.view"*) if [ -f {closed} ]; then printf '%s\n' '{{"session_id":"{session}","windows":[{{"window_id":"{window}","layers":[]}}]}}'; else printf '%s\n' '{{"session_id":"{session}","windows":[{{"window_id":"{window}","layers":[{{"blocks":[{{"block_id":"{block}","label":"{label}","flavor":"com.superlogical.terminal.shell"}}]}}]}}]}}'; fi ;;
  *"api call com.superlogical.terminal.process"*) cat {process_observation_file} ;;
  *"api call block.close"*) touch {closed}; printf '%s\n' '{{}}' ;;
  *) exit 64 ;;
esac
"##,
            endpoint = endpoint,
            instance = instance,
            session = session,
            window = window,
            block = block,
            label = label,
            subscription_count = shell_path(&subscription_count),
            first_reader_pid = shell_path(&first_reader_pid),
            first_reader_pid_pending = shell_path(&first_reader_pid_pending),
            allow_first_eof = shell_path(&allow_first_eof),
            replacement_reader_pid = shell_path(&replacement_reader_pid),
            replacement_reader_pid_pending = shell_path(&replacement_reader_pid_pending),
            closed = shell_path(&closed),
            process_observation_file = shell_path(&process_observation_file),
        );
        fs::write(&rex, script).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&rex, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let anchor_marker = root.path().join("supervisor identity");
        let applied_config_path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/fixture/config.toml");
        let mut applied = crate::config::load(&applied_config_path).unwrap();
        applied.config.runtime.rex_binary = rex.display().to_string();
        applied.config.runtime.environment.source = crate::config::EnvironmentSource::Inherit;
        applied
            .config
            .repositories
            .get_mut(&crate::domain::ids::RepositoryId::parse("example").unwrap())
            .unwrap()
            .clone_url = "https://github.com/example/example.git".into();
        let ticket_adapter = root.path().join("ticket adapter fixture");
        let description = r#"{"ticket_namespace":"fixture:workspace","identity":{},"supported_schema_versions":[1],"native_value_convention":"fixture-native-values","status_values":{"triage":"triage","backlog":"backlog","ready":"ready","in_progress":"in_progress","in_review":"in_review","done":"done","canceled":"canceled"},"capabilities":{"pagination":false,"filters":[],"revision_support":false,"conditional_revision_mutation":false,"atomic_scope_mutation":false,"remote_idempotency":[],"reconciliation":{},"visibility_grace_seconds":0.0,"supported_optional_methods":[]}}"#;
        let ticket_adapter_script = format!(
            "#!/bin/sh\nrequest=$(cat)\nrequest_id=$(printf '%s' \"$request\" | sed -E -n 's/.*\\\"request_id\\\":\\\"([^\\\"]*)\\\".*/\\1/p')\ncase \"$request\" in\n  *adapter.describe*) result='{description}' ;;\n  *) exit 64 ;;\nesac\nprintf '{{\"schema_version\":1,\"request_id\":\"%s\",\"result\":%s}}\\n' \"$request_id\" \"$result\"\n",
            description = description.replace('\'', "'\\''"),
        );
        fs::write(&ticket_adapter, ticket_adapter_script).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&ticket_adapter, fs::Permissions::from_mode(0o700)).unwrap();
        }
        applied.config.adapters.tickets.command = vec![ticket_adapter.display().to_string()];
        let package_path = fixture.authority.descriptor_path.clone();
        let package: crate::run_step_package::RunStepPackage =
            crate::protocol::parse_unique(&fs::read(&package_path).unwrap()).unwrap();
        let spool = RunStepSpool::open(&fixture.authority.control_dir).unwrap();
        applied.profiles.insert(
            fixture.authority.profile_id.clone(),
            package.profile.clone(),
        );
        let config_file = applied_config_path;
        let mut shim_command = Command::new(std::env::current_exe().unwrap());
        shim_command
            .args([
                "--exact",
                "run_step_cli::tests::anchored_shim_child",
                "--nocapture",
            ])
            .env(ANCHORED_SHIM_ENV, "1")
            .env(ANCHORED_SHIM_MARKER_ENV, &anchor_marker)
            .env(BLOCK_LOSS_ROOT_ENV, root.path())
            .env(CONNECTED_EOF_PACKAGE_ENV, &package_path)
            .env(
                CONNECTED_EOF_AUTHORITY_ENV,
                fixture.authority_digest.as_str(),
            )
            .env(BLOCK_LOSS_GRACE_ENV, "1")
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            shim_command.process_group(0);
        }
        let mut shim = BlockLossChildGuard::new(shim_command.spawn().unwrap(), spool.clone());
        assert_eq!(
            shim.child_identity
                .as_ref()
                .map(|identity| identity.process_group_id),
            Some(shim.child.id()),
            "guarded run-step child must own a private process group for cleanup"
        );
        let start_deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !anchor_marker.exists() {
            assert!(
                std::time::Instant::now() < start_deadline,
                "run-step supervisor did not start"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let process_observation = serde_json::json!({
            "last_exit": null,
            "child": {"pid": shim.child.id(), "user_id": 501, "name": "rex-projects", "path": std::env::current_exe().unwrap()},
            "foreground": {"pid": shim.child.id(), "user_id": 501, "name": "rex-projects", "path": std::env::current_exe().unwrap()},
            "ancestors": []
        });
        fs::write(&process_observation_file, process_observation.to_string()).unwrap();
        let environment = crate::environment::capture(&applied.config.runtime.environment).unwrap();
        let runtime_binary = std::env::current_exe().unwrap();
        let mut services = RuntimeServices::new(
            &applied,
            &environment,
            &config_file,
            &state_root,
            fixture.generation,
            &RexIdentity {
                endpoint: endpoint.into(),
                instance_id: instance.into(),
                session_id: session.clone(),
                block_id: Some("fixture-controller-block".into()),
            },
            RuntimeExecutable {
                path: &runtime_binary,
                digest: &fixture.authority.runtime_binary_digest,
            },
        )
        .unwrap();
        let start = loop {
            if let Ok(start) = spool.read_start_request() {
                break start;
            }
            assert!(std::time::Instant::now() < start_deadline + Duration::from_secs(5));
            std::thread::sleep(Duration::from_millis(10));
        };
        let observed = observe_wrapper_process(
            start.request.wrapper_pid,
            &start.request.wrapper_start_identity,
            start.request.rex_launch_anchor.as_ref(),
            &start.request.runtime_binary_digest,
            &start.request.rex_session_id,
            &start.request.rex_block_id,
        )
        .unwrap();
        let receipt = fixture
            .store
            .authorize_agent_start(fixture.generation, &start.request, &observed)
            .unwrap();
        spool.publish_start_receipt(&start, receipt).unwrap();

        let rex_transport = RexCliTransport::connect(
            &rex,
            &std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
                .collect::<Vec<_>>(),
            endpoint.into(),
            instance.into(),
            session.clone(),
            environment.child_environment(
                crate::environment::ChildContext::HostOperation,
                &std::collections::BTreeMap::new(),
            ),
        )
        .unwrap();
        let first_reader_deadline = std::time::Instant::now() + Duration::from_secs(3);
        while !first_reader_pid.exists() {
            assert!(std::time::Instant::now() < first_reader_deadline);
            std::thread::sleep(Duration::from_millis(10));
        }
        let reader_identity = crate::process::process_identity_for_pid(
            fs::read_to_string(&first_reader_pid)
                .unwrap()
                .trim()
                .parse()
                .unwrap(),
        )
        .unwrap()
        .unwrap();

        let observing_family = wait_for_observing_family(&spool);
        assert_eq!(
            observing_family.provider_executable_path, fixture.qualification.executable_path,
            "provider readiness must come from the exact qualified executable"
        );
        assert_eq!(
            observing_family.provider_executable_digest,
            fixture.qualification.executable_digest
        );
        assert_eq!(
            crate::process::process_identity_for_pid(observing_family.provider_root.pid)
                .unwrap()
                .filter(|identity| {
                    identity.start_identity == observing_family.provider_root.start_identity
                        && identity.quality
                            == crate::process::ProcessIdentityQuality::KernelBirthToken
                })
                .map(|identity| identity.pid),
            Some(observing_family.provider_root.pid),
            "the observed provider root must still be live before recovery"
        );

        let ticket_window = crate::adapters::rex::TicketWindow {
            server_instance_id: instance.into(),
            session_id: session.clone(),
            window_id: window.clone(),
            label: String::new(),
            initial_block_id: Some(block.clone()),
            disposition: crate::adapters::rex::CreateDisposition::Existing,
        };
        let rex_observation = rex_transport
            .observe_process(&ticket_window, &run_id, &block)
            .unwrap();
        let launch_anchor = start
            .request
            .rex_launch_anchor
            .as_ref()
            .expect("anchored fixture must persist its Rex launch anchor");
        assert_eq!(
            rex_observation.child.as_ref().map(|process| process.pid),
            Some(launch_anchor.pid),
            "fixture Rex child must be the exact saved launch anchor"
        );
        let first = FactoryRuntimeObservationServices::recover_agents(
            &mut services,
            &mut fixture.store,
            fixture.generation,
            super::unix_now_seconds().unwrap(),
        )
        .unwrap();
        assert!(
            first.observations.iter().any(|observation| {
                observation.agent_run_id == fixture.authority.agent_run_id
                    && observation.disposition
                        == crate::agent_recovery::AgentRecoveryDisposition::ProviderStarted
            }),
            "connected startup observation was {first:?}"
        );
        assert_eq!(
            test_execution_slot_disposition(&fixture.store, &fixture.slot_owner_id),
            "live"
        );
        let recovery_run = fixture
            .store
            .recoverable_agent_runs(fixture.generation, 8)
            .unwrap()
            .into_iter()
            .find(|run| run.agent_run_id == fixture.authority.agent_run_id)
            .expect("the accepted run must be available before block loss");
        assert_eq!(
            crate::process::process_identity_for_pid(reader_identity.pid)
                .unwrap()
                .unwrap()
                .start_identity,
            reader_identity.start_identity
        );

        fs::write(&allow_first_eof, b"eof").unwrap();
        let eof_deadline = std::time::Instant::now() + Duration::from_secs(2);
        while crate::process::process_identity_for_pid(reader_identity.pid)
            .unwrap()
            .is_some()
        {
            assert!(
                std::time::Instant::now() < eof_deadline,
                "reader EOF was not reaped"
            );
            let _ = FactoryRuntimeObservationServices::recover_agents(
                &mut services,
                &mut fixture.store,
                fixture.generation,
                super::unix_now_seconds().unwrap(),
            )
            .unwrap();
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(
            test_execution_slot_disposition(&fixture.store, &fixture.slot_owner_id),
            "live",
            "an event-reader EOF cannot release the running Agent reservation"
        );
        rex_transport
            .close_agent_block(&ticket_window, &run_id, &block)
            .unwrap();
        assert!(closed.exists());
        let first_post_close = FactoryRuntimeObservationServices::recover_agents(
            &mut services,
            &mut fixture.store,
            fixture.generation,
            super::unix_now_seconds().unwrap(),
        )
        .unwrap();
        assert_eq!(first_post_close.examined, 1);
        assert_eq!(
            test_execution_slot_disposition(&fixture.store, &fixture.slot_owner_id),
            "live",
            "the matching slot remains owned while the exact run-step family is live"
        );
        let family_while_owned = spool.read_run_family_record().unwrap().unwrap();
        let mut exact_family = family_while_owned.process_tree.clone();
        exact_family.push(family_while_owned.wrapper_process.clone());
        let current_processes = crate::process::inspect_process_table().unwrap();
        assert!(
            !crate::process::matching_processes(&exact_family, &current_processes).is_empty(),
            "the exact persisted run-step family is still live while its slot remains owned"
        );
        assert_eq!(
            test_execution_slot_disposition(&fixture.store, "unrelated-run"),
            "unknown"
        );
        assert_eq!(
            fixture
                .store
                .test_connection()
                .query_row(
                    "SELECT COUNT(*) FROM execution_slots WHERE owner_id='unrelated-run' AND disposition='unknown'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1,
            "the seeded unrelated reservation remains present and unchanged"
        );

        let recovery_deadline = std::time::Instant::now() + Duration::from_secs(20);
        let mut reconnected = false;
        let mut matching_terminal_proof = false;
        let mut verified_cancelled_writer_may_be_terminated = false;
        while std::time::Instant::now() < recovery_deadline {
            let report = FactoryRuntimeObservationServices::recover_agents(
                &mut services,
                &mut fixture.store,
                fixture.generation,
                super::unix_now_seconds().unwrap(),
            )
            .unwrap();
            if fs::read_to_string(&subscription_count).is_ok_and(|text| text.trim() == "2")
                && let Ok(pid) = fs::read_to_string(&replacement_reader_pid)
                && let Ok(pid) = pid.trim().parse::<u32>()
                && let Some(identity) = crate::process::process_identity_for_pid(pid).unwrap()
                && identity.quality == ProcessIdentityQuality::KernelBirthToken
            {
                reconnected = true;
            }
            let slot = test_execution_slot_disposition(&fixture.store, &fixture.slot_owner_id);
            if slot == "released" {
                let family = spool.read_run_family_record().unwrap().unwrap();
                assert_eq!(family.coverage, RunFamilyCoverage::Complete);
                wait_for_family_absence(&family);
                let cleanup = spool
                    .read_block_loss_cleanup_snapshot()
                    .unwrap()
                    .expect("recovery must persist its exact absence proof");
                assert_eq!(cleanup.agent_run_id, fixture.authority.agent_run_id);
                assert_eq!(cleanup.reservation_epoch, fixture.reservation.project_epoch);
                assert!(
                    crate::process::matching_processes(
                        &cleanup.process_tree,
                        &crate::process::inspect_process_table().unwrap()
                    )
                    .is_empty()
                );
                let child_status = shim.wait_bounded(Duration::from_secs(5)).unwrap();
                let mut child_stderr = String::new();
                if let Some(mut pipe) = shim.child.stderr.take() {
                    use std::io::Read;
                    pipe.read_to_string(&mut child_stderr).unwrap();
                }
                match spool.read_turn_result(&start) {
                    Ok(result) => {
                        assert!(matches!(
                            result.receipt.outcome,
                            crate::run_step::TurnOutcome::Cancelled
                        ));
                        result.validate_for(&start).unwrap();
                        assert_eq!(result.receipt.processes.len(), family.process_tree.len());
                        assert!(
                            family.process_tree.iter().all(|identity| {
                                result.receipt.processes.iter().any(|observed| {
                                    observed.pid == identity.pid
                                        && observed.parent_pid == identity.parent_pid
                                        && observed.process_group_id == identity.process_group_id
                                        && observed.start_identity == identity.start_identity
                                        && observed.identity_quality == "kernel_birth_token"
                                })
                            }),
                            "cancelled receipt must bind the complete family"
                        );
                        verified_cancelled_writer_may_be_terminated = true;
                        if !cleanup.cleanup_covered {
                            assert_eq!(recovery_run.agent_state, "running");
                            assert_eq!(recovery_run.launch_state, "running");
                        }
                    }
                    Err(error)
                        if error == "run-step spool file is not present"
                            && cleanup.cleanup_covered =>
                    {
                        use std::os::unix::process::ExitStatusExt;
                        assert!(
                            matches!(child_status.signal(), Some(libc::SIGTERM | libc::SIGKILL)),
                            "missing result requires covered absence proof and expected writer cancellation; status={child_status}, stderr={child_stderr}"
                        );
                        verified_cancelled_writer_may_be_terminated = true;
                    }
                    Err(error) => panic!("read terminal run-step result: {error}"),
                }
                assert_eq!(
                    test_agent_launch_states(&fixture.store, &fixture.slot_owner_id),
                    ("cancelled".into(), fixture.generation, "cancelled".into())
                );
                let facts = fixture
                    .store
                    .test_connection()
                    .prepare(
                        "SELECT fact_type,proof_digest FROM agent_block_lifecycle_facts WHERE agent_run_id=?1 AND reservation_epoch=?2 AND fact_type IN ('exit_confirmed','slot_released') ORDER BY fact_type",
                    )
                    .unwrap()
                    .query_map(
                        rusqlite::params![
                            fixture.authority.agent_run_id.as_str(),
                            fixture.reservation.project_epoch
                        ],
                        |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
                    )
                    .unwrap()
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap();
                assert_eq!(facts.len(), 2);
                assert_eq!(facts[0].0, "exit_confirmed");
                assert_eq!(facts[1].0, "slot_released");
                let proof_digest = facts[0]
                    .1
                    .as_deref()
                    .ok_or("exit-confirmed proof digest was absent")
                    .unwrap();
                crate::domain::ids::Digest::parse(proof_digest.to_owned()).unwrap();
                assert_eq!(facts[0].1, facts[1].1);
                matching_terminal_proof = true;
                if reconnected {
                    break;
                }
            } else {
                assert_eq!(slot, "live", "unknown slot dispositions fail closed");
            }
            assert!(report.examined <= 1);
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(reconnected, "the production event reader must reconnect");
        assert!(
            matching_terminal_proof,
            "a matching exact-family exit proof must accompany release"
        );
        assert_eq!(
            test_execution_slot_disposition(&fixture.store, &fixture.slot_owner_id),
            "released"
        );
        assert_eq!(
            test_execution_slot_disposition(&fixture.store, "unrelated-run"),
            "unknown"
        );
        let events = fixture.store.test_connection().query_row(
            "SELECT COUNT(*) FROM agent_block_lifecycle_facts WHERE agent_run_id=?1 AND reservation_epoch=?2 AND fact_type='event_received'",
            rusqlite::params![fixture.authority.agent_run_id.as_str(), fixture.reservation.project_epoch],
            |row| row.get::<_, i64>(0),
        ).unwrap();
        assert_eq!(
            events, 0,
            "the close was not delivered to either event subscription"
        );

        drop(services);
        let final_status = shim.wait_bounded(Duration::from_secs(5)).unwrap();
        if verified_cancelled_writer_may_be_terminated {
            use std::os::unix::process::ExitStatusExt;
            assert!(
                final_status.success()
                    || matches!(final_status.signal(), Some(libc::SIGTERM | libc::SIGKILL)),
                "verified cancelled result permits normal or signal termination only: {final_status}"
            );
        } else {
            assert!(
                final_status.success(),
                "run-step child failed: {final_status}"
            );
        }
        shim.finished = true;
    }

    #[cfg(unix)]
    #[test]
    fn shim_death_reparents_supervisor_without_invalidating_durable_family() {
        let root = tempdir().unwrap();
        let control_dir = root.path().join("control");
        let marker = root.path().join("supervisor.identity");
        let first_checkpoint_marker = root.path().join("first-family-checkpoint");
        fs::create_dir_all(&control_dir).unwrap();
        let spool = RunStepSpool::open(&control_dir).unwrap();
        let executable = std::env::current_exe().unwrap();
        let mut shim_command = Command::new(&executable);
        shim_command
            .args([
                "--exact",
                "run_step_cli::tests::anchored_shim_child",
                "--nocapture",
            ])
            .env(ANCHORED_SHIM_ENV, "1")
            .env(ANCHORED_SHIM_MARKER_ENV, &marker)
            .env(FIRST_CHECKPOINT_MARKER_ENV, &first_checkpoint_marker)
            .env(BLOCK_LOSS_ROOT_ENV, root.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut shim = shim_command.spawn().unwrap();
        let marker_deadline = std::time::Instant::now() + Duration::from_secs(2);
        while !marker.exists() || !first_checkpoint_marker.exists() {
            assert!(std::time::Instant::now() < marker_deadline);
            std::thread::sleep(Duration::from_millis(10));
        }
        let marker_contents = fs::read_to_string(&marker).unwrap();
        let mut marker_lines = marker_contents.lines();
        let supervisor_pid: u32 = marker_lines.next().unwrap().parse().unwrap();
        let supervisor_birth = marker_lines.next().unwrap();
        let provider_pid: u32 = fs::read_to_string(&first_checkpoint_marker)
            .unwrap()
            .parse()
            .unwrap();
        let shim_identity = crate::process::process_identity_for_pid(shim.id())
            .unwrap()
            .unwrap();

        let start = spool.read_start_request().unwrap();
        let observed = observe_wrapper_process(
            start.request.wrapper_pid,
            &start.request.wrapper_start_identity,
            start.request.rex_launch_anchor.as_ref(),
            &start.request.runtime_binary_digest,
            &start.request.rex_session_id,
            &start.request.rex_block_id,
        )
        .unwrap();
        observed.matches_start_request(&start.request).unwrap();

        shim.kill().unwrap();
        let shim_status = shim.wait().unwrap();
        assert!(!shim_status.success());
        let reparented_supervisor = crate::process::process_identity_for_pid(supervisor_pid)
            .unwrap()
            .unwrap();
        assert_eq!(reparented_supervisor.start_identity, supervisor_birth);
        assert_ne!(reparented_supervisor.parent_pid, shim.id());

        let result_deadline = std::time::Instant::now() + Duration::from_secs(10);
        let result = loop {
            if let Ok(result) = spool.read_turn_result(&start) {
                break result;
            }
            assert!(std::time::Instant::now() < result_deadline);
            std::thread::sleep(Duration::from_millis(20));
        };
        assert!(matches!(
            result.receipt.outcome,
            crate::run_step::TurnOutcome::Cancelled
        ));
        assert!(matches!(
            result.receipt.cleanup,
            crate::run_step::CleanupState::Confirmed
        ));
        let final_family = spool.read_run_family_record().unwrap().unwrap();
        assert_eq!(final_family.coverage, RunFamilyCoverage::Complete);
        assert_eq!(final_family.wrapper_process.pid, supervisor_pid);
        assert_eq!(
            final_family.wrapper_process.start_identity,
            supervisor_birth
        );
        assert_eq!(final_family.wrapper_process.parent_pid, shim_identity.pid);
        assert_eq!(final_family.provider_root.pid, provider_pid);
    }

    #[cfg(unix)]
    #[test]
    fn block_loss_unpublished_tree_child() {
        if std::env::var_os(BLOCK_LOSS_UNPUBLISHED_CHILD_ENV).is_none() {
            return;
        }
        use std::os::unix::process::CommandExt;

        let marker = PathBuf::from(std::env::var_os(BLOCK_LOSS_UNPUBLISHED_MARKER_ENV).unwrap());
        let mut provider = Command::new("/bin/sleep")
            .arg("300")
            .process_group(0)
            .spawn()
            .unwrap();
        let pending_marker = marker.with_extension("pid.pending");
        fs::write(&pending_marker, provider.id().to_string()).unwrap();
        fs::rename(pending_marker, marker).unwrap();
        loop {
            if let Some(status) = provider.try_wait().unwrap() {
                panic!("provider exited before the parent cleanup: {status}");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[cfg(unix)]
    #[test]
    fn guard_kills_birth_checked_descendants_before_root_without_family_record() {
        use std::os::unix::process::CommandExt;

        let root = tempdir().unwrap();
        let marker = root.path().join("provider.pid");
        fs::create_dir_all(root.path().join("control")).unwrap();
        let spool = RunStepSpool::open(&root.path().join("control")).unwrap();
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "run_step_cli::tests::block_loss_unpublished_tree_child",
                "--nocapture",
            ])
            .env(BLOCK_LOSS_UNPUBLISHED_CHILD_ENV, "1")
            .env(BLOCK_LOSS_UNPUBLISHED_MARKER_ENV, &marker)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .unwrap();
        let guard = BlockLossChildGuard::new(child, spool);
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !marker.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "provider marker was not published"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let provider_pid: u32 = fs::read_to_string(&marker).unwrap().parse().unwrap();
        let current = crate::process::inspect_process_table().unwrap();
        let tree = crate::process::capture_process_tree(guard.child.id(), &current);
        let wrapper = tree
            .iter()
            .find(|process| process.pid == guard.child.id())
            .unwrap();
        let provider = tree
            .iter()
            .find(|process| process.pid == provider_pid)
            .unwrap();
        assert_eq!(
            wrapper.quality,
            crate::process::ProcessIdentityQuality::KernelBirthToken
        );
        assert_eq!(
            provider.quality,
            crate::process::ProcessIdentityQuality::KernelBirthToken
        );
        assert_ne!(wrapper.process_group_id, provider.process_group_id);

        drop(guard);
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while tree.iter().any(process_is_live) {
            assert!(
                std::time::Instant::now() < deadline,
                "unpublished child family survived guard cleanup"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[cfg(unix)]
    #[test]
    fn host_kills_provider_at_three_seconds_but_preserves_run_step_receipt_writer() {
        use std::os::unix::process::CommandExt;

        let root = tempdir().unwrap();
        fs::write(root.path().join("provider-init-gate"), b"").unwrap();
        let control_dir = root.path().join("control");
        fs::create_dir_all(&control_dir).unwrap();
        let spool = RunStepSpool::open(&control_dir).unwrap();
        let writer = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "run_step_cli::tests::block_loss_run_step_child",
                "--nocapture",
            ])
            .env(BLOCK_LOSS_CHILD_ENV, "1")
            .env(BLOCK_LOSS_ROOT_ENV, root.path())
            .env(BLOCK_LOSS_GRACE_ENV, "30")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .unwrap();
        let mut writer = BlockLossChildGuard::new(writer, spool.clone());

        let family = wait_for_observing_family(&spool);
        writer.observe(family.clone());
        assert!(!root.path().join("provider-ready").exists());
        fs::remove_file(root.path().join("provider-init-gate")).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let ready_pid = fs::read_to_string(root.path().join("provider-ready"))
                .ok()
                .and_then(|pid| pid.trim().parse::<u32>().ok());
            if ready_pid == Some(family.provider_root.pid) {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "observed provider did not publish signal-handler readiness"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(process_is_live(&family.provider_root));
        let start = spool.read_start_request().unwrap();
        let snapshot = block_loss_snapshot(&family);
        assert_eq!(
            snapshot
                .process_tree
                .iter()
                .map(|process| process.process_group_id)
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            2,
            "fixture must keep the wrapper writer and provider in separate groups"
        );
        let first_term_sent = signal_groups(
            &snapshot.process_tree,
            crate::process::ProcessSignal::Terminate,
        );
        std::thread::sleep(Duration::from_secs(3));
        let wrapper_alive_at_three = process_is_live(&family.wrapper_process);
        let provider_alive_at_three = process_is_live(&family.provider_root);
        let wrapper = crate::launch::ObservedWrapperIdentity {
            pid: family.wrapper_process.pid,
            start_identity: family.wrapper_process.start_identity.clone(),
            rex_session_id: start.request.rex_session_id.clone(),
            rex_block_id: start.request.rex_block_id.clone(),
            runtime_binary_digest: start.request.runtime_binary_digest.clone(),
            rex_launch_anchor: None,
        };
        let second_signal_sent = crate::agent_recovery::signal_missing_block_process_groups(
            &snapshot,
            &wrapper,
            &crate::process::inspect_process_table().unwrap(),
            3,
            Some(42),
        );
        let provider_absent_after_kill = wait_until_provider_absent(&snapshot, &family);
        if !provider_absent_after_kill {
            let current = crate::process::inspect_process_table().unwrap();
            for group in family
                .process_tree
                .iter()
                .map(|process| process.process_group_id)
                .collect::<std::collections::BTreeSet<_>>()
            {
                let _ = crate::process::signal_process_group_if_observed(
                    group,
                    &snapshot.process_tree,
                    &current,
                    crate::process::ProcessSignal::Kill,
                );
            }
        }
        let writer_status = writer.wait_bounded(Duration::from_secs(10)).unwrap();
        wait_for_family_absence(&family);
        writer.finished = true;

        let family_after = spool.read_run_family_record().unwrap().unwrap();
        let result_after = spool.read_turn_result(&start).unwrap();
        assert!(first_term_sent && second_signal_sent);
        assert!(
            wrapper_alive_at_three && provider_alive_at_three,
            "wrapper_alive_at_three={wrapper_alive_at_three}, provider_alive_at_three={provider_alive_at_three}"
        );
        assert!(provider_absent_after_kill);
        assert!(writer_status.success());
        assert_eq!(family_after.coverage, RunFamilyCoverage::Complete);
        assert!(matches!(
            result_after.receipt.outcome,
            crate::run_step::TurnOutcome::Cancelled
        ));
        assert!(matches!(
            result_after.receipt.cleanup,
            crate::run_step::CleanupState::Confirmed
        ));
    }

    #[cfg(unix)]
    #[test]
    fn anchored_supervisor_pipe_eof_cancels_provider_and_publishes_complete_receipt() {
        let root = tempdir().unwrap();
        let control_dir = root.path().join("control");
        fs::create_dir_all(&control_dir).unwrap();
        let spool = RunStepSpool::open(&control_dir).unwrap();
        let anchor_pid = std::process::id();
        let anchor_start = observed_process_start_identity(anchor_pid).unwrap();
        let executable = std::env::current_exe().unwrap();
        let mut command = Command::new(&executable);
        command
            .args([
                "--exact",
                "run_step_cli::tests::block_loss_run_step_child",
                "--nocapture",
            ])
            .env(ANCHORED_CHILD_ENV, "1")
            .env(ANCHOR_PID_ENV, anchor_pid.to_string())
            .env(ANCHOR_START_ENV, &anchor_start)
            .env(BLOCK_LOSS_CHILD_ENV, "1")
            .env(BLOCK_LOSS_ROOT_ENV, root.path())
            .env(BLOCK_LOSS_GRACE_ENV, "1");
        let mut supervisor = super::spawn_detached_supervisor(command).unwrap();
        let anchor_pipe = supervisor.stdin.take().unwrap();
        let family = wait_for_observing_family(&spool);
        assert_eq!(
            family.binding.rex_launch_anchor,
            Some(LaunchAnchorIdentity {
                pid: anchor_pid,
                start_identity: anchor_start.clone(),
            })
        );
        assert_eq!(family.provider_root.parent_pid, family.wrapper_process.pid);
        let anchor_identity = crate::process::process_identity_for_pid(anchor_pid)
            .unwrap()
            .unwrap();
        assert_ne!(
            family.wrapper_process.process_group_id,
            anchor_identity.process_group_id
        );

        let start = spool.read_start_request().unwrap();
        let expected_digest = super::digest_file(&executable).unwrap();
        let observed = observe_wrapper_process(
            start.request.wrapper_pid,
            &start.request.wrapper_start_identity,
            start.request.rex_launch_anchor.as_ref(),
            &expected_digest,
            &start.request.rex_session_id,
            &start.request.rex_block_id,
        )
        .unwrap();
        observed.matches_start_request(&start.request).unwrap();

        drop(anchor_pipe);
        let status = supervisor.wait().unwrap();
        assert!(status.success(), "supervisor test child failed: {status}");
        let result = spool.read_turn_result(&start).unwrap();
        assert!(matches!(
            result.receipt.outcome,
            crate::run_step::TurnOutcome::Cancelled
        ));
        assert!(matches!(
            result.receipt.cleanup,
            crate::run_step::CleanupState::Confirmed
        ));
        assert_eq!(
            spool.read_run_family_record().unwrap().unwrap().coverage,
            RunFamilyCoverage::Complete
        );
    }

    fn wait_until_provider_absent(
        snapshot: &BlockLossCleanupSnapshot,
        family: &crate::run_step_spool::RunFamilyRecord,
    ) -> bool {
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            let provider_absent = snapshot.process_tree.iter().all(|identity| {
                identity.pid == family.wrapper_process.pid || !process_is_live(identity)
            });
            if provider_absent {
                return true;
            }
            if std::time::Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

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
            rex_launch_anchor: None,
            rex_session_id: "session-1".into(),
            rex_block_id: "block-1".into(),
        }
    }

    #[test]
    fn accepted_start_replay_binds_rex_anchor_and_live_supervisor_ancestry() {
        let mut request = start_request();
        request.rex_launch_anchor = Some(LaunchAnchorIdentity {
            pid: 90,
            start_identity: "shim-born".into(),
        });
        let rex_process = |pid| crate::adapters::rex::RexProcessInfo {
            pid,
            user_id: 1,
            name: "rex-projects".into(),
            argv0: None,
            path: None,
            invoked_path: None,
            script: None,
            cwd: None,
            user: None,
        };
        let observation = crate::adapters::rex::RexProcessObservation {
            last_exit: None,
            child: Some(rex_process(90)),
            foreground: Some(rex_process(100)),
            ancestors: None,
        };
        assert!(accepted_rex_observation_reports_launch_process(&observation, &request).is_some());
        let mut wrong_anchor = observation.clone();
        wrong_anchor.child = Some(rex_process(91));
        assert!(accepted_rex_observation_reports_launch_process(&wrong_anchor, &request).is_none());

        let process = |pid, parent_pid, start_identity: &str| ProcessIdentity {
            pid,
            parent_pid,
            process_group_id: pid,
            start_identity: start_identity.into(),
            command: "rex-projects".into(),
            quality: ProcessIdentityQuality::KernelBirthToken,
        };
        let live = vec![process(90, 1, "shim-born"), process(100, 90, "birth-100")];
        assert!(accepted_supervisor_topology_matches(&request, &live));
        assert!(!accepted_supervisor_topology_matches(
            &request,
            &[process(90, 1, "reused-shim"), process(100, 90, "birth-100")]
        ));
        assert!(!accepted_supervisor_topology_matches(
            &request,
            &[process(90, 1, "shim-born"), process(100, 89, "birth-100")]
        ));

        request.rex_launch_anchor = None;
        let legacy = crate::adapters::rex::RexProcessObservation {
            last_exit: None,
            child: Some(rex_process(100)),
            foreground: Some(rex_process(100)),
            ancestors: None,
        };
        assert!(accepted_rex_observation_reports_launch_process(&legacy, &request).is_some());
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
    fn anchored_start_ack_wait_stops_immediately_on_pipe_eof() {
        let root = tempdir().unwrap();
        fs::create_dir_all(root.path().join("control")).unwrap();
        let spool = RunStepSpool::open(&root.path().join("control")).unwrap();
        let start = spool.publish_start_once(start_request()).unwrap();
        let closed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let close = closed.clone();
        let worker = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(60));
            close.store(true, std::sync::atomic::Ordering::Release);
        });
        let started = std::time::Instant::now();
        let result = wait_start_receipt_or_anchor_close(
            &spool,
            &start,
            Duration::from_secs(30),
            Some(&closed),
        );
        worker.join().unwrap();
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(spool.read_result().is_err());
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
            None,
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
                None,
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
                None,
                &stale,
                "session",
                "block",
            )
            .is_err()
        );
    }
}
