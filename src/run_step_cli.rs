//! Runtime boundary for the finite-turn wrapper and host phase-two launch finalization.

use std::path::Path;

use sha2::{Digest as _, Sha256};

use crate::adapters::rex::RexContextBlock;
use crate::domain::ids::Digest;
use crate::domain::types::Role;
use crate::launch::{
    AgentLaunchAuthority, AgentLaunchReservation, LaunchDecision, ObservedWrapperIdentity,
    RexBlockLifecycle, RexBlockOwnership, RexViewBlock,
};
use crate::run_step_package::RunStepPackage;
use crate::run_step_spool::RunStepSpool;
use crate::store::ConfigStore;

/// Publish the immutable package, bind the observed block and authority, then ACK only after
/// the start request has been checked against that durable host state.
pub fn finalize_and_ack_start(
    store: &mut ConfigStore,
    owner_generation: u64,
    reservation: &AgentLaunchReservation,
    package: &RunStepPackage,
    observed_block: &RexContextBlock,
) -> Result<AgentLaunchAuthority, String> {
    reservation.validate()?;
    package.validate()?;
    if owner_generation != reservation.controller_generation
        || package.controller_generation != owner_generation
        || package.descriptor.run_id != reservation.agent_run_id
        || package.project_id != reservation.project_id
        || package.operation_id != reservation.operation_id
        || package.descriptor.role != reservation.role
        || package.descriptor.ticket_run_id != reservation.ticket_run_id
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

    let spool = RunStepSpool::open(&reservation.control_dir)?;
    let start = spool.read_start_request()?;
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
    let receipt = store.authorize_agent_start(
        owner_generation,
        request,
        &ObservedWrapperIdentity {
            pid: request.wrapper_pid,
            start_identity: request.wrapper_start_identity.clone(),
            rex_session_id: request.rex_session_id.clone(),
            rex_block_id: request.rex_block_id.clone(),
            runtime_binary_digest: request.runtime_binary_digest.clone(),
        },
    )?;
    if receipt.decision != LaunchDecision::Accepted {
        return Err("host did not accept the exact wrapper start request".into());
    }
    spool.publish_start_receipt(&start, receipt)?;
    Ok(authority)
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
    let result = crate::run_step::run_turn(&request, &mut crate::run_step::SystemProcessObserver)
        .map_err(|e| e.to_string())?;
    let envelope = spool.publish_turn_result_once(&start, result)?;
    Ok(RunStepCliResult {
        run_id: run_id.to_owned(),
        result_digest: envelope.result_digest,
    })
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
            "{}:{}",
            info.pbi_start_tvsec, info.pbi_start_tvusec
        ))
    }
    #[cfg(target_os = "linux")]
    {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        Some(
            stat.rsplit_once(')')?
                .1
                .split_whitespace()
                .nth(19)?
                .to_owned(),
        )
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = pid;
        None
    }
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
    use super::observed_process_start_identity;

    #[test]
    fn current_wrapper_start_identity_is_observable() {
        assert!(
            observed_process_start_identity(std::process::id())
                .is_some_and(|identity| !identity.is_empty())
        );
    }
}
