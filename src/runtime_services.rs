//! Concrete host adapters assembled for one foreground controller.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::adapters::rex::{RexCliTransport, RexIdentity};
use crate::adapters::tickets::{
    NormalizedTicketStatus, TicketAdapter, TicketListRequest, TicketScope, build_ticket_adapter,
};
use crate::artifacts::ArtifactStore;
use crate::config::{AppliedConfig, Config};
use crate::domain::ids::{AdapterId, Digest, TicketId, TicketNamespace};
use crate::domain::types::{Role, TicketStatus};
use crate::effects::EffectHandler;
use crate::engine::factory_runtime::{ExternalTicketPage, FactoryRuntimeServices};
use crate::environment::{ChildContext, EnvironmentSnapshot};
use crate::protocol::RequestId;
use crate::store::ConfigStore;
use crate::store::scheduler::{ObservedTicket, TicketScanKey};

static REQUEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// Long-lived adapters and effect handlers for a single controller process.
/// Adapter namespaces are learned once and pinned by their `describe` call.
pub struct RuntimeServices {
    tickets: Box<dyn TicketAdapter>,
    namespaces: BTreeMap<AdapterId, TicketNamespace>,
    handlers: Vec<Box<dyn EffectHandler>>,
    config: Config,
    configuration_digest: Digest,
    applied_config: AppliedConfig,
    environment: EnvironmentSnapshot,
    host_environment: BTreeMap<OsString, OsString>,
    rex_identity: RexIdentity,
    rex: RexCliTransport,
    state_root: PathBuf,
    config_dir: PathBuf,
    owner_generation: u64,
    runtime_binary: PathBuf,
    runtime_binary_digest: Digest,
    artifacts: ArtifactStore,
}

impl RuntimeServices {
    pub fn new(
        applied_config: &AppliedConfig,
        environment: &EnvironmentSnapshot,
        config_dir: &Path,
        state_root: &Path,
        owner_generation: u64,
        rex_identity: &RexIdentity,
        runtime_binary: &Path,
        runtime_binary_digest: &Digest,
    ) -> Result<Self, String> {
        if owner_generation == 0 || !runtime_binary.is_absolute() {
            return Err(
                "RuntimeServices requires an active owner and absolute runtime binary".into(),
            );
        }
        let mut active_rex_environment = BTreeMap::new();
        active_rex_environment.insert(
            OsString::from("REX_SESSION"),
            OsString::from(&rex_identity.session_id),
        );
        if let Some(block_id) = &rex_identity.block_id {
            active_rex_environment.insert(OsString::from("REX_BLOCK"), OsString::from(block_id));
            active_rex_environment.insert(OsString::from("REX_BLOCK_ID"), OsString::from(block_id));
        }
        let host_environment =
            environment.child_environment(ChildContext::HostOperation, &active_rex_environment);
        let tickets = build_ticket_adapter(&applied_config.config, &host_environment, config_dir)
            .map_err(|error| error.to_string())?;
        let search_path = host_environment
            .get(std::ffi::OsStr::new("PATH"))
            .map(std::env::split_paths)
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        let rex_binary = crate::process::resolve_executable(
            Path::new(&applied_config.config.runtime.rex_binary),
            &search_path,
        )
        .ok_or("configured Rex executable is unavailable in the captured environment")?;
        let rex = RexCliTransport::connect(
            &rex_binary,
            &search_path,
            rex_identity.endpoint.clone(),
            rex_identity.instance_id.clone(),
            rex_identity.session_id.clone(),
            host_environment.clone(),
        )
        .map_err(|error| error.to_string())?;
        let artifact_root = state_root.join("artifacts");
        let artifacts = ArtifactStore::open(&artifact_root)?;
        Ok(Self {
            tickets,
            namespaces: BTreeMap::new(),
            handlers: Vec::new(),
            config: applied_config.config.clone(),
            configuration_digest: applied_config.digest.clone(),
            applied_config: applied_config.clone(),
            environment: environment.clone(),
            host_environment,
            rex_identity: rex_identity.clone(),
            rex,
            state_root: state_root.to_owned(),
            config_dir: config_dir.to_owned(),
            owner_generation,
            runtime_binary: runtime_binary.to_owned(),
            runtime_binary_digest: runtime_binary_digest.clone(),
            artifacts,
        })
    }

    fn request_id(&self, purpose: &str) -> Result<RequestId, String> {
        let sequence = REQUEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        RequestId::new(format!("rex-projects-{purpose}-{sequence}"))
    }

    pub fn configuration_digest(&self) -> &Digest {
        &self.configuration_digest
    }
}

impl FactoryRuntimeServices for RuntimeServices {
    fn ingest_one_agent_result(
        &mut self,
        _store: &mut ConfigStore,
        _owner_generation: u64,
        _now_unix: i64,
    ) -> Result<bool, String> {
        // Mailbox decoding is wired when the provider run-step bridge is composed.
        Ok(false)
    }

    fn ticket_namespace(&mut self, adapter: &AdapterId) -> Result<TicketNamespace, String> {
        if let Some(namespace) = self.namespaces.get(adapter) {
            return Ok(namespace.clone());
        }
        if adapter.as_str() != "tickets" {
            return Err(format!("unknown configured ticket adapter `{adapter}`"));
        }
        let description = self
            .tickets
            .describe(self.request_id("describe")?)
            .map_err(|error| error.to_string())?;
        let namespace = TicketNamespace::parse(description.ticket_namespace)?;
        self.namespaces.insert(adapter.clone(), namespace.clone());
        Ok(namespace)
    }

    fn list_ticket_page(
        &mut self,
        key: &TicketScanKey,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<ExternalTicketPage, String> {
        if limit == 0 || limit > 100 {
            return Err("ticket page limit must be between 1 and 100".into());
        }
        let project = self
            .config
            .projects
            .get(&key.project_id)
            .ok_or_else(|| format!("missing configured Project `{}`", key.project_id))?;
        if project.ticket_adapter != key.adapter_id {
            return Err("ticket scan adapter does not match Project configuration".into());
        }
        let scope_values = project
            .ticket_scope
            .iter()
            .map(|(key, value)| {
                value
                    .as_str()
                    .map(|value| (key.clone(), value.to_owned()))
                    .ok_or_else(|| format!("ticket scope `{key}` must be a string"))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        let scope = TicketScope::new(scope_values).map_err(|error| error.to_string())?;
        let page = self
            .tickets
            .list(
                self.request_id("list")?,
                None,
                TicketListRequest {
                    scope,
                    status: Some(normalized_status(key.status)),
                    assignee: None,
                    project: None,
                    milestone: None,
                    release: None,
                    labels: None,
                    query: None,
                    cursor: cursor.map(str::to_owned),
                    page_size: Some(limit as u32),
                    updated_since: None,
                },
            )
            .map_err(|error| error.to_string())?;
        let namespace = TicketNamespace::parse(page.ticket_namespace)?;
        if namespace != key.namespace {
            return Err("ticket adapter namespace changed after it was pinned".into());
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "system clock is before the Unix epoch".to_owned())?
            .as_secs() as i64;
        let tickets = page
            .tickets
            .into_iter()
            .map(|ticket| {
                let ticket_namespace = TicketNamespace::parse(ticket.ticket_namespace)?;
                if ticket_namespace != key.namespace
                    || ticket.status.value != normalized_status(key.status)
                {
                    return Err("ticket adapter returned an out-of-scope ticket".to_owned());
                }
                Ok(ObservedTicket {
                    id: TicketId::parse(ticket.id)?,
                    revision: ticket.revision,
                    status: key.status,
                    title: ticket.title,
                    labels: ticket.labels,
                    created_at: ticket.created_at,
                    observed_at_unix: now,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok(ExternalTicketPage {
            tickets,
            next_cursor: page.next_cursor,
        })
    }

    fn prepare_role_launch(
        &mut self,
        store: &mut ConfigStore,
        owner_generation: u64,
        config: &Config,
        candidate: &crate::store::scheduler::PendingRoleWakeSession,
        now_unix: i64,
    ) -> Result<bool, String> {
        if owner_generation != self.owner_generation {
            return Err("RuntimeServices owner generation changed".into());
        }
        if candidate.role != Role::Supervisor {
            return Err(format!(
                "{} launch requires its typed TicketRun or prepared-worktree authority",
                role_name(candidate.role)
            ));
        }
        if candidate.ticket_run_id.is_some()
            || candidate.role_session_id != format!("project:{}:supervisor", candidate.project_id)
        {
            return Err("Supervisor wake does not match its Project role session".into());
        }
        if serde_json::to_vec(config).map_err(|error| error.to_string())?
            != serde_json::to_vec(&self.config).map_err(|error| error.to_string())?
        {
            return Err("runtime configuration changed without rebuilding host services".into());
        }
        let project = self
            .applied_config
            .config
            .projects
            .get(&candidate.project_id)
            .ok_or("pending Supervisor references an unconfigured Project")?;
        let roles = crate::config::effective_project_roles(
            &candidate.project_id,
            &self.applied_config.config.projects,
        )?;
        let profile_id = roles
            .get(&Role::Supervisor)
            .ok_or("Project has no effective Supervisor profile")?;
        let profile = self
            .applied_config
            .profiles
            .get(profile_id)
            .ok_or("Supervisor profile is absent from the applied configuration")?;
        let profile_digest = digest_serialized(profile)?;
        let runtime_identity = crate::run_step::profile_runtime_identity(profile)
            .map_err(|error| error.to_string())?;
        let qualifications = store.verified_provider_qualifications(
            &candidate.project_id,
            profile_id,
            &profile_digest,
            32,
        )?;
        let qualification = qualifications
            .into_iter()
            .find(|qualification| {
                qualification.adapter == runtime_identity.adapter
                    && qualification.executable_path
                        == runtime_identity.executable_path.display().to_string()
                    && qualification.executable_digest == runtime_identity.executable_digest
                    && qualification.commit_mode == runtime_identity.commit_mode
                    && qualification.invocation_options_digest
                        == runtime_identity.invocation_options_digest
                    && qualification.permission_mode == runtime_identity.effective_permission_mode
            })
            .ok_or("Supervisor profile has no exact verified unattended qualification")?;
        let qualification_digest = qualification.canonical_digest()?;
        let wake_inputs = store.pending_role_wake_inputs(
            &candidate.project_id,
            &candidate.role_session_id,
            256,
        )?;
        if wake_inputs.is_empty() {
            return Ok(false);
        }
        let seed = serde_json::to_vec(&(
            "rex-projects-agent-run-v1",
            &candidate.project_id,
            &candidate.role_session_id,
            wake_inputs
                .iter()
                .map(|input| input.wake_input_id)
                .collect::<Vec<_>>(),
        ))
        .map_err(|error| error.to_string())?;
        let seed_digest = digest_bytes(&seed)?;
        let short = &seed_digest.as_str()[..32];
        let run_id = crate::domain::ids::AgentRunId::parse(format!("agent-{short}"))?;
        let operation_id = crate::domain::ids::OperationId::parse(format!("start-{short}"))?;
        let runnable = store
            .runnable_projects(owner_generation)?
            .into_iter()
            .find(|project| project.record.id == candidate.project_id)
            .ok_or("Supervisor Project is not runnable under this controller")?;
        if runnable.record.config_digest != self.configuration_digest
            || store.current_revision(&runnable.record.config_source)?
                != Some(runnable.record.config_revision)
        {
            return Err(
                "Supervisor Project configuration is not the current applied revision".into(),
            );
        }

        let view = self.ensure_supervisor_view(store, &candidate.project_id, now_unix)?;
        let project_root = self
            .state_root
            .join("projects")
            .join(candidate.project_id.as_str());
        let workspace = project_root.join("role-workspaces").join("supervisor");
        let run_root = self.state_root.join("agents").join(run_id.as_str());
        let control_dir = run_root.join("control");
        create_private_dir(&workspace)?;
        create_private_dir(&control_dir)?;
        let wake_snapshot = crate::agent_api::AgentWakeSnapshot {
            schema_version: 1,
            project_id: candidate.project_id.clone(),
            role_session_id: candidate.role_session_id.clone(),
            agent_run_id: run_id.as_str().to_owned(),
            digest: Digest::parse("0".repeat(64))?,
            inputs: wake_inputs
                .into_iter()
                .map(|input| crate::agent_api::AgentWakeItem {
                    wake_input_id: input.wake_input_id,
                    source_type: input.source_type,
                    source_id: input.source_id,
                    source_revision: input.source_revision,
                    priority: input.priority,
                    payload_json: input.payload_json,
                })
                .collect(),
        };
        let mut wake_snapshot = wake_snapshot;
        wake_snapshot.digest = wake_snapshot.content_digest()?;
        let rendered = crate::roles::render_role_prompt(
            &self.applied_config,
            &crate::roles::PromptContext {
                project_id: candidate.project_id.clone(),
                profile_id: Some(profile_id.clone()),
                role: Role::Supervisor,
                operation_recipe: None,
                repositories: project.repositories.clone(),
                ticket: None,
                recovery_summary: None,
                accepted_plan: None,
                previous_decisions: Vec::new(),
                required_evidence: Vec::new(),
                stop_conditions: Vec::new(),
                assigned_commit_mode: None,
            },
        )?;
        let result_schema = rendered.result_schema.clone();
        let schema_projection = crate::providers::project_result_schema(&result_schema)?;
        let _schema_projection = schema_projection.identity;
        let result_schema_digest = digest_serialized(&result_schema)?;
        let capacity = u32::try_from(self.config.runtime.max_agent_runs)
            .map_err(|_| "runtime.max_agent_runs exceeds the supported slot count")?;
        if capacity == 0 {
            return Err("runtime.max_agent_runs must be positive".into());
        }
        let Some(slot_index) =
            store.available_execution_slot(&candidate.project_id, "agent", capacity, capacity)?
        else {
            return Ok(false);
        };
        if now_unix < 0 {
            return Err("controller clock is before the Unix epoch".into());
        }
        let reservation = crate::launch::AgentLaunchReservation {
            schema_version: crate::launch::LAUNCH_SCHEMA_VERSION,
            agent_run_id: run_id,
            project_id: candidate.project_id.clone(),
            role: Role::Supervisor,
            role_session_id: candidate.role_session_id.clone(),
            parent_run_id: None,
            parent_role: None,
            ticket_run_id: None,
            ticket_revision: None,
            config_revision: runnable.record.config_revision,
            config_digest: runnable.record.config_digest,
            attempt: 1,
            run_epoch: 1,
            controller_generation: owner_generation,
            project_epoch: runnable.project_epoch,
            operation_id,
            operation_recipe_id: None,
            rex_view_id: view.view_id.clone(),
            runtime_binary_digest: self.runtime_binary_digest.clone(),
            environment_snapshot_id: self.environment.metadata().id.clone(),
            profile_id: profile_id.clone(),
            profile_digest,
            instruction_digest: rendered.instruction_digest,
            result_schema_digest,
            wake_snapshot,
            qualification_receipt_digest: qualification_digest,
            descriptor_path: run_root.join("run-step.package.json"),
            workspace_path: workspace,
            control_dir: control_dir.clone(),
            mailbox_directory: control_dir,
            mailbox_capability_digest: digest_bytes(seed_digest.as_str().as_bytes())?,
            mailbox_expires_at_unix: u64::try_from(
                now_unix
                    .checked_add(profile.turn_timeout_seconds as i64)
                    .and_then(|value| value.checked_add(86_400))
                    .ok_or("Agent mailbox expiration overflow")?,
            )
            .map_err(|_| "Agent mailbox expiration is negative")?,
            mailbox_max_request_bytes: 1_048_576,
            mailbox_max_pending_requests: 32,
            pool: "agent".into(),
            slot_index,
            global_capacity: capacity,
            project_capacity: capacity,
        };
        match store.prepare_role_launch(&reservation)? {
            crate::store::agent_runtime::LaunchPreparationOutcome::Prepared { .. } => Ok(true),
            crate::store::agent_runtime::LaunchPreparationOutcome::CapacityUnavailable => Ok(false),
        }
    }

    fn effect_handlers(&self) -> Vec<&dyn EffectHandler> {
        self.handlers.iter().map(Box::as_ref).collect()
    }
}

impl RuntimeServices {
    fn ensure_supervisor_view(
        &self,
        store: &mut ConfigStore,
        project_id: &crate::domain::ids::ProjectId,
        now_unix: i64,
    ) -> Result<crate::launch::RexView, String> {
        for record in store.rex_view_history(project_id)? {
            if record.lifecycle != "active"
                || record.view.kind != crate::launch::RexViewKind::Supervisor
            {
                continue;
            }
            if record.view.rex_server_identity == self.rex_identity.instance_id
                && record.view.rex_session_id == self.rex_identity.session_id
            {
                return Ok(record.view);
            } else {
                return Err("Project already has an active Rex view on another session".into());
            }
        }
        let epoch = store
            .rex_view_history(project_id)?
            .iter()
            .map(|record| record.view.view_epoch)
            .max()
            .unwrap_or(0)
            .saturating_add(1);
        let bootstrap_id = format!("project-{}-view-{epoch}", project_id);
        let spec = crate::adapters::rex::AgentBlockSpec {
            run_id: bootstrap_id,
            command: PathBuf::from("/usr/bin/env"),
            args: vec![
                self.runtime_binary.display().to_string(),
                "status".into(),
                "--json".into(),
            ],
            cwd: self.state_root.clone(),
            path_prepend: self.search_path(),
        };
        let window = self
            .rex
            .find_or_create_project_window(project_id, &spec)
            .map_err(|error| error.to_string())?;
        let view = crate::launch::RexView {
            view_id: crate::launch::RexView::derive_id(
                project_id,
                crate::launch::RexViewKind::Supervisor,
                None,
                None,
                epoch,
            )?,
            project_id: project_id.clone(),
            kind: crate::launch::RexViewKind::Supervisor,
            ticket_namespace: None,
            ticket_id: None,
            view_epoch: epoch,
            rex_server_identity: window.server_instance_id,
            rex_session_id: window.session_id,
            rex_window_id: window.window_id,
        };
        store.register_rex_view(self.owner_generation, &view)?;
        let _ = now_unix;
        Ok(view)
    }

    fn search_path(&self) -> Vec<PathBuf> {
        self.host_environment
            .get(std::ffi::OsStr::new("PATH"))
            .map(std::env::split_paths)
            .into_iter()
            .flatten()
            .collect()
    }
}

fn digest_serialized(value: &impl serde::Serialize) -> Result<Digest, String> {
    let bytes = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    digest_bytes(&bytes)
}

fn digest_bytes(bytes: &[u8]) -> Result<Digest, String> {
    use sha2::Digest as _;
    Digest::parse(format!("{:x}", sha2::Sha256::digest(bytes)))
}

fn create_private_dir(path: &Path) -> Result<(), String> {
    std::fs::create_dir_all(path).map_err(|error| error.to_string())?;
    let metadata = std::fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!("{} must be a real directory", path.display()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|error| error.to_string())?;
    }
    Ok(())
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

fn normalized_status(status: TicketStatus) -> NormalizedTicketStatus {
    match status {
        TicketStatus::Triage => NormalizedTicketStatus::Triage,
        TicketStatus::Backlog => NormalizedTicketStatus::Backlog,
        TicketStatus::Ready => NormalizedTicketStatus::Ready,
        TicketStatus::InProgress => NormalizedTicketStatus::InProgress,
        TicketStatus::InReview => NormalizedTicketStatus::InReview,
        TicketStatus::Done => NormalizedTicketStatus::Done,
        TicketStatus::Canceled => NormalizedTicketStatus::Canceled,
    }
}
