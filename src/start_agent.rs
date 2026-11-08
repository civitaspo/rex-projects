//! Effect handler for launching one immutable finite-turn Agent through Rex.

use std::sync::Arc;

use crate::adapters::rex::{RexCliTransport, RexContextBlock};
use crate::domain::types::Role;
use crate::effects::{EffectContext, EffectHandler, EffectMode, EffectObservation, EffectRequest};
use crate::engine::reducer::EffectKind;
use crate::launch::{AgentLaunchReservation, StartAgentEffectPayload};
use crate::run_step_cli::finalize_and_ack_start;
use crate::run_step_package::RunStepPackage;

/// Runtime-specific inputs belong in the host composition layer: ticket lookup, role prompt
/// rendering, environment snapshot/handoff policy, and Rex view preparation all need that layer's
/// current configuration and adapters. The handler owns the durable ordering and authority gate.
pub trait StartAgentMaterializer: Send + Sync {
    /// Return the stable, private, operation-scoped one-use environment handoff path. A retry
    /// must return the same path; it must never mint a replacement for a consumed launch.
    fn environment_handoff_path(
        &self,
        store: &mut crate::store::ConfigStore,
        owner_generation: u64,
        now_unix: i64,
        reservation: &AgentLaunchReservation,
    ) -> Result<std::path::PathBuf, String>;

    /// Create or reconcile the exact parked Rex wrapper for this reservation. On retry this must
    /// locate the existing run-owned block before attempting any create operation.
    fn ensure_parked_wrapper(
        &self,
        store: &mut crate::store::ConfigStore,
        owner_generation: u64,
        now_unix: i64,
        reservation: &AgentLaunchReservation,
        package_path: &std::path::Path,
        environment_handoff: &std::path::Path,
    ) -> Result<RexContextBlock, String>;

    /// Build the immutable package from the applied config, effective role prompt, qualified
    /// profile, captured environment, and the observed real Rex block.
    fn build_package(
        &self,
        store: &mut crate::store::ConfigStore,
        owner_generation: u64,
        now_unix: i64,
        reservation: &AgentLaunchReservation,
        observed_block: &RexContextBlock,
        environment_handoff: &std::path::Path,
    ) -> Result<RunStepPackage, String>;

    /// Rex transport pinned to the controller's startup endpoint, instance, and session.
    fn rex_transport(&self) -> &RexCliTransport;
}

pub struct StartAgentEffectHandler {
    role: Option<Role>,
    materializer: Arc<dyn StartAgentMaterializer>,
}

impl StartAgentEffectHandler {
    pub fn new(role: Role, materializer: Arc<dyn StartAgentMaterializer>) -> Result<Self, String> {
        Ok(Self {
            role: Some(role),
            materializer,
        })
    }

    pub fn for_all_roles(materializer: Arc<dyn StartAgentMaterializer>) -> Self {
        Self {
            role: None,
            materializer,
        }
    }
}

impl EffectHandler for StartAgentEffectHandler {
    fn kind(&self) -> EffectKind {
        EffectKind::StartAgent
    }

    fn handle(
        &self,
        mode: EffectMode,
        request: &EffectRequest,
        context: &mut EffectContext<'_>,
    ) -> Result<EffectObservation, String> {
        let payload: StartAgentEffectPayload =
            crate::protocol::parse_unique(request.intent.request_json.as_bytes())?;
        payload.validate()?;
        if request.intent.subject_type != "agent_run"
            || request.intent.subject_id != payload.agent_run_id.as_str()
        {
            return Err("StartAgent effect subject does not match its typed payload".into());
        }
        let Some(reservation) = context
            .store
            .agent_launch_reservation(&payload.agent_run_id, &payload.launch_reservation_digest)?
        else {
            return Err("StartAgent effect has no durable launch reservation".into());
        };
        if request.intent.project_id != reservation.project_id
            || request.intent.operation_id != reservation.operation_id.as_str()
            || request.intent.kind != "start_agent"
            || self.role.is_some_and(|role| role != reservation.role)
        {
            return Err("StartAgent effect does not match the reserved role and operation".into());
        }

        if mode == EffectMode::Reconcile
            && let Some(authority) = crate::run_step_cli::reconcile_accepted_start(
                context.store,
                context.owner_generation,
                &reservation,
                self.materializer.rex_transport(),
            )?
        {
            let authority_digest = authority.digest()?;
            return Ok(EffectObservation::Applied {
                receipt: serde_json::json!({
                    "schema_version": 1,
                    "state": "launch_accepted",
                    "agent_run_id": authority.agent_run_id,
                    "operation_id": authority.operation_id,
                    "authority_digest": authority_digest,
                    "descriptor_digest": authority.descriptor_digest,
                })
                .to_string(),
            });
        }

        let environment_handoff = self.materializer.environment_handoff_path(
            context.store,
            context.owner_generation,
            context.now_unix,
            &reservation,
        )?;
        if !environment_handoff.is_absolute() {
            return Err("environment handoff path must be absolute".into());
        }
        let observed_block = self.materializer.ensure_parked_wrapper(
            context.store,
            context.owner_generation,
            context.now_unix,
            &reservation,
            &reservation.descriptor_path,
            &environment_handoff,
        )?;
        let package = self.materializer.build_package(
            context.store,
            context.owner_generation,
            context.now_unix,
            &reservation,
            &observed_block,
            &environment_handoff,
        )?;
        register_reserved_mailbox(context.store, context.owner_generation, &reservation)?;
        let authority = finalize_and_ack_start(
            context.store,
            context.owner_generation,
            &reservation,
            &package,
            &observed_block,
            self.materializer.rex_transport(),
        )?;
        let authority_digest = authority.digest()?;
        Ok(EffectObservation::Applied {
            receipt: serde_json::json!({
                "schema_version": 1,
                "state": "launch_accepted",
                "agent_run_id": authority.agent_run_id,
                "operation_id": authority.operation_id,
                "authority_digest": authority_digest,
                "descriptor_digest": authority.descriptor_digest,
            })
            .to_string(),
        })
    }
}

pub(crate) fn register_reserved_mailbox(
    store: &mut crate::store::ConfigStore,
    owner_generation: u64,
    reservation: &AgentLaunchReservation,
) -> Result<(), String> {
    let limits = crate::mailbox::MailboxLimits {
        max_request_bytes: usize::try_from(reservation.mailbox_max_request_bytes)
            .map_err(|_| "Agent mailbox request limit exceeds this platform")?,
        max_pending_requests: usize::try_from(reservation.mailbox_max_pending_requests)
            .map_err(|_| "Agent mailbox pending limit exceeds this platform")?,
    };
    let mailbox = store.register_agent_mailbox(
        owner_generation,
        reservation.agent_run_id.as_str(),
        &reservation.mailbox_directory,
        reservation.mailbox_expires_at_unix,
        limits,
    )?;
    let canonical_mailbox_directory = std::fs::canonicalize(&reservation.mailbox_directory)
        .map_err(|error| format!("canonicalize Agent mailbox directory: {error}"))?;
    if mailbox.agent_run_id != reservation.agent_run_id.as_str()
        || mailbox.canonical_directory != canonical_mailbox_directory.display().to_string()
        || mailbox.capability_digest != reservation.mailbox_capability_digest.as_str()
        || mailbox.expires_at_unix != reservation.mailbox_expires_at_unix
        || mailbox.max_request_bytes != limits.max_request_bytes
        || mailbox.max_pending_requests != limits.max_pending_requests
    {
        return Err(
            "registered Agent mailbox differs from the immutable launch reservation".into(),
        );
    }
    Ok(())
}
