//! Concrete host adapters assembled for one foreground controller.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::adapters::rex::{
    AgentBlockSpec, CreateDisposition, RexCliTransport, RexContextBlock, RexIdentity, RexWindow,
    owned_agent_block_label, owned_supervisor_window_label, owned_ticket_window_label,
};
use crate::adapters::tickets::{
    NormalizedTicketStatus, TicketAdapter, TicketGetRequest, TicketListRequest, TicketScope,
    build_ticket_adapter,
};
use crate::artifacts::ArtifactStore;
use crate::config::{AppliedConfig, Config};
use crate::domain::ids::{AdapterId, Digest, RexBlockId, TicketId, TicketNamespace};
use crate::domain::types::{Role, TicketStatus};
use crate::effects::EffectHandler;
use crate::engine::factory_runtime::{ExternalTicketPage, FactoryRuntimeServices};
use crate::environment::{ChildContext, EnvironmentSnapshot};
use crate::protocol::RequestId;
use crate::runtime_delivery::RuntimeDelivery;
use crate::store::ConfigStore;
use crate::store::scheduler::{ObservedTicket, TicketScanKey};

static REQUEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// Long-lived adapters and effect handlers for a single controller process.
/// Adapter namespaces are learned once and pinned by their `describe` call.
pub struct RuntimeServices {
    tickets: Arc<dyn TicketAdapter>,
    namespaces: BTreeMap<AdapterId, TicketNamespace>,
    handlers: Vec<Box<dyn EffectHandler>>,
    config: Config,
    configuration_digest: Digest,
    applied_config: AppliedConfig,
    environment: EnvironmentSnapshot,
    host_environment: BTreeMap<OsString, OsString>,
    rex_identity: RexIdentity,
    rex: Arc<RexCliTransport>,
    rex_cli_path: PathBuf,
    rex_search_path: Vec<PathBuf>,
    state_root: PathBuf,
    config_dir: PathBuf,
    owner_generation: u64,
    runtime_binary: PathBuf,
    runtime_binary_digest: Digest,
    artifacts: ArtifactStore,
    delivery: RuntimeDelivery,
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
        let tickets: Arc<dyn TicketAdapter> = Arc::from(
            build_ticket_adapter(&applied_config.config, &host_environment, config_dir)
                .map_err(|error| error.to_string())?,
        );
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
        let rex = Arc::new(
            RexCliTransport::connect(
                &rex_binary,
                &search_path,
                rex_identity.endpoint.clone(),
                rex_identity.instance_id.clone(),
                rex_identity.session_id.clone(),
                host_environment.clone(),
            )
            .map_err(|error| error.to_string())?,
        );
        let artifact_root = state_root.join("artifacts");
        let artifacts = ArtifactStore::open(&artifact_root)?;
        let delivery =
            crate::runtime_delivery::build(applied_config, state_root, &host_environment)?;
        let mut handlers = Vec::new();
        let scopes = applied_config
            .config
            .projects
            .iter()
            .map(|(project_id, project)| {
                let values = project
                    .ticket_scope
                    .iter()
                    .map(|(key, value)| {
                        value
                            .as_str()
                            .map(|value| (key.clone(), value.to_owned()))
                            .ok_or_else(|| format!("ticket scope `{key}` must be a string"))
                    })
                    .collect::<Result<BTreeMap<_, _>, _>>()?;
                Ok((
                    project_id.clone(),
                    TicketScope::new(values).map_err(|e| e.to_string())?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>, String>>()?;
        handlers.extend(
            crate::engine::ticket_effect_handlers::TicketEffectHandlers::new(
                tickets.clone(),
                scopes,
            )
            .into_handlers(),
        );
        if let Some(human) = &applied_config.config.human {
            let declarative_root = host_environment
                .get(std::ffi::OsStr::new("XDG_CONFIG_HOME"))
                .map(PathBuf::from)
                .or_else(|| {
                    host_environment
                        .get(std::ffi::OsStr::new("HOME"))
                        .map(|home| PathBuf::from(home).join(".config"))
                })
                .ok_or("captured environment has neither XDG_CONFIG_HOME nor HOME")?
                .join("rex-projects");
            let observer = crate::human_runtime::DurableHumanSubjectObserver::with_delivery(
                declarative_root,
                owner_generation,
                delivery.shared_effects(),
            )?;
            handlers.push(Box::new(
                crate::human_runtime::HumanPresenterEffectHandler::new(
                    &human.kind,
                    human.command.clone(),
                    host_environment.clone(),
                    artifact_root.clone(),
                    Arc::new(observer),
                )?,
            ));
        }
        handlers.push(Box::new(
            crate::operations_runtime::OperationEffectHandler::new(
                [applied_config.clone()],
                Duration::from_secs(applied_config.config.runtime.shutdown_grace_seconds),
            )?,
        ));
        if let Some(knowledge) = &applied_config.config.knowledge {
            let root = PathBuf::from(&knowledge.root);
            let root = if root.is_absolute() {
                root
            } else {
                config_dir.join(root)
            };
            handlers.push(Box::new(
                crate::knowledge_effect::KnowledgeEffectHandler::new(root),
            ));
        }
        let declarative_root = host_environment
            .get(std::ffi::OsStr::new("XDG_CONFIG_HOME"))
            .map(PathBuf::from)
            .or_else(|| {
                host_environment
                    .get(std::ffi::OsStr::new("HOME"))
                    .map(|home| PathBuf::from(home).join(".config"))
            })
            .ok_or("captured environment has neither XDG_CONFIG_HOME nor HOME")?
            .join("rex-projects")
            .join("profiles");
        handlers.push(Box::new(crate::profile_effect::ProfileEffectHandler::new(
            declarative_root,
        )));
        let materializer = Arc::new(RuntimeAgentMaterializer {
            applied_config: applied_config.clone(),
            environment: environment.clone(),
            state_root: state_root.to_owned(),
            owner_generation,
            runtime_binary: runtime_binary.to_owned(),
            runtime_binary_digest: runtime_binary_digest.clone(),
            rex_cli_path: rex_binary.clone(),
            rex_search_path: search_path.clone(),
            rex_identity: rex_identity.clone(),
            rex: rex.clone(),
            tickets: tickets.clone(),
        });
        handlers.push(Box::new(
            crate::start_agent::StartAgentEffectHandler::for_all_roles(materializer),
        ));
        Ok(Self {
            tickets,
            namespaces: BTreeMap::new(),
            handlers,
            config: applied_config.config.clone(),
            configuration_digest: applied_config.digest.clone(),
            applied_config: applied_config.clone(),
            environment: environment.clone(),
            host_environment,
            rex_identity: rex_identity.clone(),
            rex,
            rex_cli_path: rex_binary,
            rex_search_path: search_path,
            state_root: state_root.to_owned(),
            config_dir: config_dir.to_owned(),
            owner_generation,
            runtime_binary: runtime_binary.to_owned(),
            runtime_binary_digest: runtime_binary_digest.clone(),
            artifacts,
            delivery,
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

struct RuntimeAgentMaterializer {
    applied_config: AppliedConfig,
    environment: EnvironmentSnapshot,
    state_root: PathBuf,
    owner_generation: u64,
    runtime_binary: PathBuf,
    runtime_binary_digest: Digest,
    rex_cli_path: PathBuf,
    rex_search_path: Vec<PathBuf>,
    rex_identity: RexIdentity,
    rex: Arc<RexCliTransport>,
    tickets: Arc<dyn TicketAdapter>,
}

impl crate::start_agent::StartAgentMaterializer for RuntimeAgentMaterializer {
    fn environment_handoff_path(
        &self,
        store: &mut ConfigStore,
        owner_generation: u64,
        _now_unix: i64,
        reservation: &crate::launch::AgentLaunchReservation,
    ) -> Result<PathBuf, String> {
        self.validate_reservation(store, owner_generation, reservation)?;
        let handoff = self
            .environment
            .create_handoff_for_operation(&self.state_root, reservation.operation_id.as_str())
            .map_err(|error| error.to_string())?;
        if handoff.snapshot_id() != &reservation.environment_snapshot_id {
            return Err("launch environment snapshot changed after reservation".into());
        }
        Ok(handoff.path().to_owned())
    }

    fn ensure_parked_wrapper(
        &self,
        store: &mut ConfigStore,
        owner_generation: u64,
        _now_unix: i64,
        reservation: &crate::launch::AgentLaunchReservation,
        package_path: &Path,
        environment_handoff: &Path,
    ) -> Result<RexContextBlock, String> {
        self.validate_reservation(store, owner_generation, reservation)?;
        if package_path != reservation.descriptor_path
            || !environment_handoff.is_absolute()
            || !reservation.workspace_path.is_absolute()
        {
            return Err("run-step wrapper paths do not match the immutable reservation".into());
        }
        let record = store
            .rex_view_history(&reservation.project_id)?
            .into_iter()
            .find(|record| {
                record.lifecycle == "active" && record.view.view_id == reservation.rex_view_id
            })
            .ok_or("launch reservation has no active Rex view")?;
        if record.view.rex_server_identity != self.rex_identity.instance_id
            || record.view.rex_session_id != self.rex_identity.session_id
        {
            return Err("launch Rex view is not on the pinned Rex session".into());
        }
        let label = match record.view.kind {
            crate::launch::RexViewKind::Supervisor => {
                if reservation.role != Role::Supervisor {
                    return Err("non-Supervisor launch references a Supervisor Rex view".into());
                }
                owned_supervisor_window_label(reservation.project_id.as_str())
            }
            crate::launch::RexViewKind::Ticket => {
                let namespace = record
                    .view
                    .ticket_namespace
                    .as_deref()
                    .ok_or("ticket Rex view is missing its namespace")?;
                let ticket_id = record
                    .view
                    .ticket_id
                    .as_deref()
                    .ok_or("ticket Rex view is missing its ticket ID")?;
                owned_ticket_window_label(namespace, ticket_id)
                    .map_err(|error| error.to_string())?
            }
        };
        let window = RexWindow {
            server_instance_id: record.view.rex_server_identity,
            session_id: record.view.rex_session_id,
            window_id: record.view.rex_window_id,
            label: label.clone(),
            initial_block_id: None,
            disposition: CreateDisposition::Existing,
        };
        let blocks = self
            .rex
            .list_window_blocks(&window, &label)
            .map_err(|error| error.to_string())?;
        let expected_label = owned_agent_block_label(reservation.agent_run_id.as_str())
            .map_err(|error| error.to_string())?;
        let existing = blocks
            .iter()
            .filter(|block| block.label == expected_label)
            .collect::<Vec<_>>();
        if existing.len() > 1 {
            return Err("multiple Rex blocks claim the same AgentRun".into());
        }
        if let Some(block) = existing.first() {
            let observed = self
                .rex
                .validate_context_block(&block.block_id)
                .map_err(|error| error.to_string())?;
            if observed.window_id != window.window_id || observed.label != expected_label {
                return Err("existing Rex block does not match the AgentRun reservation".into());
            }
            return Ok(observed);
        }
        let anchor = blocks
            .first()
            .ok_or("owned Rex view has no anchor block for a finite Agent turn")?;
        let spec = AgentBlockSpec {
            run_id: reservation.agent_run_id.as_str().to_owned(),
            command: PathBuf::from("/usr/bin/env"),
            args: vec![
                "REX_PROJECTS_AGENT=1".into(),
                "REX_PROJECTS_CONTEXT=agent".into(),
                format!("REX_PROJECTS_PROJECT_ID={}", reservation.project_id),
                format!(
                    "REX_PROJECTS_ROLE={}",
                    crate::roles::role_name(reservation.role)
                ),
                format!("REX_PROJECTS_RUN_ID={}", reservation.agent_run_id),
                self.runtime_binary.display().to_string(),
                "agent".into(),
                "run-step".into(),
                "--run".into(),
                reservation.agent_run_id.as_str().to_owned(),
                "--package".into(),
                package_path.display().to_string(),
                "--environment-handoff".into(),
                environment_handoff.display().to_string(),
            ],
            cwd: reservation.workspace_path.clone(),
            path_prepend: self.rex_search_path.clone(),
        };
        let block_id = self
            .rex
            .create_agent_block(&window, &anchor.block_id, &spec)
            .map_err(|error| error.to_string())?;
        let observed = self
            .rex
            .validate_context_block(&block_id)
            .map_err(|error| error.to_string())?;
        if observed.window_id != window.window_id || observed.label != expected_label {
            return Err("new Rex block does not match the AgentRun reservation".into());
        }
        Ok(observed)
    }

    fn build_package(
        &self,
        store: &mut ConfigStore,
        owner_generation: u64,
        now_unix: i64,
        reservation: &crate::launch::AgentLaunchReservation,
        observed_block: &RexContextBlock,
        _environment_handoff: &Path,
    ) -> Result<crate::run_step_package::RunStepPackage, String> {
        self.validate_reservation(store, owner_generation, reservation)?;
        let project = self
            .applied_config
            .config
            .projects
            .get(&reservation.project_id)
            .ok_or("Agent reservation references an unconfigured Project")?;
        let active_run = if let Some(ticket_run_id) = &reservation.ticket_run_id {
            Some(
                store
                    .active_ticket_runs(owner_generation, 256)?
                    .into_iter()
                    .find(|run| run.ticket_run_id == *ticket_run_id)
                    .ok_or("Agent reservation references a missing or terminal TicketRun")?,
            )
        } else {
            None
        };
        let ticket = if let Some(active_run) = &active_run {
            if active_run.project_id != reservation.project_id
                || Some(active_run.revision) != reservation.ticket_revision.map(|r| r.0)
            {
                return Err("TicketRun revision changed after Agent reservation".into());
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
            let result = self
                .tickets
                .get(
                    RequestId::new(format!("rex-projects-ticket-{}", reservation.agent_run_id))?,
                    Some(reservation.project_id.clone()),
                    TicketGetRequest {
                        scope: TicketScope::new(scope_values).map_err(|e| e.to_string())?,
                        ticket_id: active_run.ticket_id.as_str().to_owned(),
                        timeline_limit: Some(20),
                    },
                )
                .map_err(|error| error.to_string())?;
            if result.ticket_namespace != active_run.namespace.as_str()
                || result.ticket.id != active_run.ticket_id.as_str()
                || result
                    .ticket
                    .revision
                    .as_deref()
                    .unwrap_or_default()
                    .is_empty()
            {
                return Err("ticket adapter returned a stale or unscoped ticket".into());
            }
            Some(crate::roles::TicketBrief {
                ticket_id: active_run.ticket_id.clone(),
                ticket_revision: active_run.revision,
                title: result.ticket.title,
                body: result.ticket.body,
                acceptance: Vec::new(),
            })
        } else {
            None
        };
        if reservation.role == Role::Worker {
            return Err("Worker package requires the opaque prepared-worktree launch token".into());
        }
        let profile = self
            .applied_config
            .profiles
            .get(&reservation.profile_id)
            .ok_or("Agent profile is missing from the applied configuration")?;
        let profile_digest = digest_serialized(profile)?;
        if profile_digest != reservation.profile_digest {
            return Err("Agent profile changed after launch reservation".into());
        }
        let operation_recipe = reservation.operation_recipe_id.clone();
        let accepted_plan = if let Some(run) = active_run.as_ref() {
            let accepted = store.latest_accepted_work_plan(&run.project_id, &run.ticket_run_id)?;
            if let Some(plan) = &accepted {
                plan.validate_for(project, &self.applied_config.digest)?;
            }
            accepted
        } else {
            None
        };
        let rendered = crate::roles::render_role_prompt(
            &self.applied_config,
            &crate::roles::PromptContext {
                project_id: reservation.project_id.clone(),
                profile_id: Some(reservation.profile_id.clone()),
                role: reservation.role,
                operation_recipe,
                repositories: project.repositories.clone(),
                ticket,
                recovery_summary: None,
                accepted_plan: accepted_plan
                    .as_ref()
                    .map(|plan| serde_json::to_string(&plan.proposal))
                    .transpose()
                    .map_err(|error| error.to_string())?,
                previous_decisions: Vec::new(),
                required_evidence: Vec::new(),
                stop_conditions: Vec::new(),
                assigned_commit_mode: Some(profile.commit_mode),
            },
        )?;
        if rendered.instruction_digest != reservation.instruction_digest
            || rendered.result_schema_digest != reservation.result_schema_digest
        {
            return Err("rendered role package no longer matches its durable reservation".into());
        }
        let runtime_identity = crate::run_step::profile_runtime_identity(profile)
            .map_err(|error| error.to_string())?;
        let qualifications = store.verified_provider_qualifications(
            &reservation.project_id,
            &reservation.profile_id,
            &reservation.profile_digest,
            32,
        )?;
        let qualification = qualifications
            .into_iter()
            .find(|qualification| {
                qualification.canonical_digest().ok().as_ref()
                    == Some(&reservation.qualification_receipt_digest)
                    && qualification.adapter == runtime_identity.adapter
                    && qualification.executable_path
                        == runtime_identity.executable_path.display().to_string()
                    && qualification.executable_digest == runtime_identity.executable_digest
                    && qualification.commit_mode == runtime_identity.commit_mode
                    && qualification.invocation_options_digest
                        == runtime_identity.invocation_options_digest
                    && qualification.permission_mode == runtime_identity.effective_permission_mode
            })
            .ok_or("launch reservation no longer matches a verified provider qualification")?;
        qualification.validate_for_unattended_launch()?;
        let projection = crate::providers::project_result_schema(&rendered.result_schema)?;
        let rex_block_id = RexBlockId::parse(observed_block.block_id.clone())?;
        let capability = crate::run_step::ProviderCapabilityEvidence {
            schema_version: 1,
            adapter: qualification.adapter,
            profile_digest: reservation.profile_digest.clone(),
            version: qualification.provider_version,
            executable_path: runtime_identity.executable_path,
            executable_digest: runtime_identity.executable_digest,
            permission_mode: qualification.permission_mode,
            invocation_options_digest: runtime_identity.invocation_options_digest,
            commit_mode: runtime_identity.commit_mode,
            schema_projection: projection.identity,
            receipt_digest: reservation.qualification_receipt_digest.clone(),
            status: crate::run_step::ProviderQualificationStatus::Verified,
        };
        let descriptor = crate::run_step::RunDescriptor {
            schema_version: 1,
            project_id: reservation.project_id.clone(),
            run_id: reservation.agent_run_id.clone(),
            role: reservation.role,
            ticket_run_id: reservation.ticket_run_id.clone(),
            attempt: reservation.attempt,
            run_epoch: reservation.run_epoch,
            controller_generation: reservation.controller_generation,
            workspace: reservation.workspace_path.clone(),
            control_dir: reservation.control_dir.clone(),
            rex_session_id: observed_block.session_id.clone(),
            rex_block_id,
            profile_digest: reservation.profile_digest.clone(),
            instruction_digest: reservation.instruction_digest.clone(),
            plan_digest: accepted_plan.as_ref().map(|plan| plan.plan_digest.clone()),
            environment_snapshot_id: reservation.environment_snapshot_id.clone(),
            wake_snapshot_digest: reservation.wake_snapshot.digest.clone(),
            provider_capability: capability,
            result_schema: rendered.result_schema,
        };
        let window_id = observed_block.window_id.clone();
        let package = crate::run_step_package::RunStepPackage {
            schema_version: 1,
            descriptor,
            operation_id: reservation.operation_id.clone(),
            project_id: reservation.project_id.clone(),
            controller_generation: reservation.controller_generation,
            runtime_binary_digest: self.runtime_binary_digest.clone(),
            qualification_receipt_digest: reservation.qualification_receipt_digest.clone(),
            rex_cli_path: self.rex_cli_path.clone(),
            rex_search_path: self.rex_search_path.clone(),
            rex_endpoint: self.rex_identity.endpoint.clone(),
            rex_server_identity: self.rex_identity.instance_id.clone(),
            rex_window_id: window_id,
            profile: profile.clone(),
            role_contract: crate::roles::builtin_role_contract(reservation.role).to_owned(),
            prompt: rendered.text,
            continuation: None,
            shutdown_grace_seconds: self.applied_config.config.runtime.shutdown_grace_seconds,
            start_ack_timeout_seconds: 30,
        };
        package.validate()?;
        let _ = now_unix;
        Ok(package)
    }

    fn rex_transport(&self) -> &RexCliTransport {
        &self.rex
    }
}

impl RuntimeAgentMaterializer {
    fn validate_reservation(
        &self,
        store: &mut ConfigStore,
        owner_generation: u64,
        reservation: &crate::launch::AgentLaunchReservation,
    ) -> Result<(), String> {
        reservation.validate()?;
        if owner_generation != self.owner_generation
            || reservation.controller_generation != owner_generation
            || reservation.config_digest != self.applied_config.digest
            || reservation.runtime_binary_digest != self.runtime_binary_digest
            || reservation.environment_snapshot_id != self.environment.metadata().id
        {
            return Err(
                "Agent launch reservation is stale for the active controller snapshot".into(),
            );
        }
        let project = store
            .runnable_projects(owner_generation)?
            .into_iter()
            .find(|project| project.record.id == reservation.project_id)
            .ok_or("Agent launch Project is no longer runnable")?;
        if project.record.config_revision != reservation.config_revision
            || project.record.config_digest != reservation.config_digest
            || project.project_epoch != reservation.project_epoch
            || store.current_revision(&project.record.config_source)?
                != Some(reservation.config_revision)
        {
            return Err("Agent launch Project revision changed after reservation".into());
        }
        Ok(())
    }
}

impl FactoryRuntimeServices for RuntimeServices {
    fn recover_agents(
        &mut self,
        store: &mut ConfigStore,
        owner_generation: u64,
        now_unix: i64,
    ) -> Result<crate::agent_recovery::AgentRecoveryReport, String> {
        let policy = crate::agent_recovery::RecoveryPolicy {
            rex_session_id: self.rex_identity.session_id.clone(),
            turn_timeout_seconds: self
                .applied_config
                .profiles
                .iter()
                .map(|(profile_id, profile)| (profile_id.clone(), profile.turn_timeout_seconds))
                .collect(),
            heartbeat_stale_after_seconds: 30,
            max_observations_per_tick: 8,
            now_unix,
        };
        crate::agent_recovery::AgentRecoveryRuntime::tick(
            store,
            owner_generation,
            &self.rex,
            &policy,
        )
    }

    fn ingest_one_agent_result(
        &mut self,
        store: &mut ConfigStore,
        owner_generation: u64,
        _now_unix: i64,
    ) -> Result<Option<crate::store::agent_results::IngestedAgentResult>, String> {
        store.ingest_next_spooled_agent_result(&self.artifacts, owner_generation, 32)
    }

    fn observe_base_heads(
        &mut self,
    ) -> Result<BTreeMap<crate::domain::ids::RepositoryId, String>, String> {
        self.delivery.observe_base_heads()
    }

    fn configuration_digest(&self) -> &Digest {
        &self.configuration_digest
    }

    fn profile_commit_mode(
        &self,
        project_id: &crate::domain::ids::ProjectId,
        role: Role,
    ) -> Result<crate::domain::types::CommitMode, String> {
        let project = self
            .applied_config
            .config
            .projects
            .get(project_id)
            .ok_or("Project is not present in applied configuration")?;
        let profile_id = project
            .roles
            .get(&role)
            .ok_or("Project role has no configured profile")?;
        self.applied_config
            .profiles
            .get(profile_id)
            .map(|profile| profile.commit_mode)
            .ok_or_else(|| "configured role profile is missing".into())
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

    fn observe_publications(
        &mut self,
        store: &mut ConfigStore,
        owner_generation: u64,
        now_unix: i64,
    ) -> Result<crate::runtime_delivery::PublicationMonitorTick, String> {
        self.delivery
            .observe_publications(store, owner_generation, now_unix)
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
            return self.prepare_ticket_role_launch(store, config, candidate, now_unix);
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
        let profile_digest = digest_serialized(&profile)?;
        let runtime_identity = crate::run_step::profile_runtime_identity(&profile)
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
        let mut handlers = self.delivery.handlers();
        handlers.extend(self.handlers.iter().map(Box::as_ref));
        handlers
    }
}

impl RuntimeServices {
    fn prepare_ticket_role_launch(
        &mut self,
        store: &mut ConfigStore,
        config: &Config,
        candidate: &crate::store::scheduler::PendingRoleWakeSession,
        now_unix: i64,
    ) -> Result<bool, String> {
        if serde_json::to_vec(config).map_err(|error| error.to_string())?
            != serde_json::to_vec(&self.config).map_err(|error| error.to_string())?
        {
            return Err("runtime configuration changed without rebuilding host services".into());
        }
        let ticket_run_id = candidate
            .ticket_run_id
            .as_ref()
            .ok_or("ticket role wake lacks TicketRun identity")?;
        if candidate.role == Role::Worker {
            if candidate.work_node_id.is_none() {
                return Err("generic or malformed Worker wake cannot authorize a launch".into());
            }
            return Err(
                "Worker launch requires the dedicated prepared-worktree reservation API".into(),
            );
        }
        if candidate.work_node_id.is_some()
            || candidate.role_session_id
                != format!("ticket_run:{ticket_run_id}:{}", role_name(candidate.role))
        {
            return Err("ticket role wake scope does not match its TicketRun".into());
        }
        let active_run = store
            .active_ticket_runs(self.owner_generation, 256)?
            .into_iter()
            .find(|run| run.ticket_run_id == *ticket_run_id)
            .ok_or("ticket role refers to a missing or terminal TicketRun")?;
        if active_run.project_id != candidate.project_id
            || !role_allowed_in_phase(candidate.role, active_run.phase)
        {
            return Err("ticket role does not match the active TicketRun phase".into());
        }
        let project = self
            .applied_config
            .config
            .projects
            .get(&candidate.project_id)
            .ok_or("pending ticket role references an unconfigured Project")?
            .clone();
        let runnable = store
            .runnable_projects(self.owner_generation)?
            .into_iter()
            .find(|project| project.record.id == candidate.project_id)
            .ok_or("ticket Project is not runnable under this controller")?;
        if runnable.record.config_digest != self.configuration_digest
            || runnable.project_epoch != active_run.project_epoch
            || store.current_revision(&runnable.record.config_source)?
                != Some(runnable.record.config_revision)
        {
            return Err("ticket Project configuration or epoch changed".into());
        }
        let mut profile_id = crate::config::effective_project_roles(
            &candidate.project_id,
            &self.applied_config.config.projects,
        )?
        .get(&candidate.role)
        .cloned()
        .ok_or("Project has no profile for this ticket role")?;
        if let Some(recipe_id) = &active_run.recipe_id {
            let recipe = self
                .applied_config
                .config
                .operation_recipes
                .get(recipe_id)
                .ok_or("TicketRun references an unknown operation recipe")?;
            if let Some(recipe_profile) = recipe.roles.get(&candidate.role) {
                profile_id = recipe_profile.clone();
            }
        }
        let profile = self
            .applied_config
            .profiles
            .get(&profile_id)
            .ok_or("ticket role profile is absent from applied configuration")?
            .clone();
        let profile_digest = digest_serialized(&profile)?;
        let runtime_identity = crate::run_step::profile_runtime_identity(&profile)
            .map_err(|error| error.to_string())?;
        let qualification = self.verified_qualification(
            store,
            &candidate.project_id,
            &profile_id,
            &profile_digest,
            &runtime_identity,
        )?;
        let scope = project
            .ticket_scope
            .iter()
            .map(|(key, value)| {
                value
                    .as_str()
                    .map(|value| (key.clone(), value.to_owned()))
                    .ok_or_else(|| format!("ticket scope `{key}` must be a string"))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        let scope = TicketScope::new(scope).map_err(|error| error.to_string())?;
        let namespace = self.ticket_namespace(&project.ticket_adapter)?;
        if namespace != active_run.namespace {
            return Err("TicketRun namespace differs from configured ticket adapter".into());
        }
        let ticket = self
            .tickets
            .get(
                self.request_id("get")?,
                None,
                TicketGetRequest {
                    scope,
                    ticket_id: active_run.ticket_id.as_str().to_owned(),
                    timeline_limit: Some(20),
                },
            )
            .map_err(|error| error.to_string())?;
        if ticket.ticket_namespace != namespace.as_str()
            || ticket.ticket.ticket_namespace != namespace.as_str()
            || ticket.ticket.id != active_run.ticket_id.as_str()
        {
            return Err("ticket adapter returned a mismatched ticket identity".into());
        }
        let view = self.ensure_ticket_view(
            store,
            &candidate.project_id,
            &active_run.namespace,
            &active_run.ticket_id,
            now_unix,
        )?;
        let accepted_plan =
            store.latest_accepted_work_plan(&candidate.project_id, ticket_run_id)?;
        if let Some(plan) = &accepted_plan {
            plan.validate_for(&project, &self.configuration_digest)?;
        }
        let rendered = crate::roles::render_role_prompt(
            &self.applied_config,
            &crate::roles::PromptContext {
                project_id: candidate.project_id.clone(),
                profile_id: Some(profile_id.clone()),
                role: candidate.role,
                operation_recipe: active_run.recipe_id.clone(),
                repositories: project.repositories.clone(),
                ticket: Some(crate::roles::TicketBrief {
                    ticket_id: active_run.ticket_id.clone(),
                    ticket_revision: active_run.revision,
                    title: ticket.ticket.title,
                    body: ticket.ticket.body,
                    acceptance: Vec::new(),
                }),
                recovery_summary: None,
                accepted_plan: accepted_plan
                    .as_ref()
                    .map(|plan| serde_json::to_string(&plan.proposal))
                    .transpose()
                    .map_err(|error| error.to_string())?,
                previous_decisions: Vec::new(),
                required_evidence: Vec::new(),
                stop_conditions: Vec::new(),
                assigned_commit_mode: None,
            },
        )?;
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
        let suffix = &seed_digest.as_str()[..32];
        let agent_run_id = crate::domain::ids::AgentRunId::parse(format!("agent-{suffix}"))?;
        let operation_id = crate::domain::ids::OperationId::parse(format!("start-{suffix}"))?;
        let workspace = self
            .state_root
            .join("projects")
            .join(candidate.project_id.as_str())
            .join("role-workspaces")
            .join(role_name(candidate.role));
        let run_root = self.state_root.join("agents").join(agent_run_id.as_str());
        let control_dir = run_root.join("control");
        create_private_dir(&workspace)?;
        create_private_dir(&control_dir)?;
        let mut wake_snapshot = crate::agent_api::AgentWakeSnapshot {
            schema_version: 1,
            project_id: candidate.project_id.clone(),
            role_session_id: candidate.role_session_id.clone(),
            agent_run_id: agent_run_id.as_str().to_owned(),
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
        wake_snapshot.digest = wake_snapshot.content_digest()?;
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
        let reservation = crate::launch::AgentLaunchReservation {
            schema_version: crate::launch::LAUNCH_SCHEMA_VERSION,
            agent_run_id,
            project_id: candidate.project_id.clone(),
            role: candidate.role,
            role_session_id: candidate.role_session_id.clone(),
            parent_run_id: None,
            parent_role: None,
            ticket_run_id: Some(ticket_run_id.clone()),
            ticket_revision: Some(crate::domain::ids::Revision(active_run.revision)),
            config_revision: runnable.record.config_revision,
            config_digest: runnable.record.config_digest,
            attempt: 1,
            run_epoch: active_run.revision,
            controller_generation: self.owner_generation,
            project_epoch: active_run.project_epoch,
            operation_id,
            operation_recipe_id: active_run.recipe_id,
            rex_view_id: view.view_id,
            runtime_binary_digest: self.runtime_binary_digest.clone(),
            environment_snapshot_id: self.environment.metadata().id.clone(),
            profile_id,
            profile_digest,
            instruction_digest: rendered.instruction_digest,
            result_schema_digest: digest_serialized(&rendered.result_schema)?,
            wake_snapshot,
            qualification_receipt_digest: qualification.canonical_digest()?,
            descriptor_path: run_root.join("run-step.package.json"),
            workspace_path: workspace,
            control_dir: control_dir.clone(),
            mailbox_directory: control_dir,
            mailbox_capability_digest: digest_bytes(seed_digest.as_str().as_bytes())?,
            mailbox_expires_at_unix: mailbox_expiration(now_unix, profile.turn_timeout_seconds)?,
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

    fn verified_qualification(
        &self,
        store: &ConfigStore,
        project_id: &crate::domain::ids::ProjectId,
        profile_id: &crate::domain::ids::ProfileId,
        profile_digest: &Digest,
        runtime_identity: &crate::run_step::ProfileRuntimeIdentity,
    ) -> Result<crate::launch::ProviderQualification, String> {
        store
            .verified_provider_qualifications(project_id, profile_id, profile_digest, 32)?
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
            .ok_or_else(|| "profile has no exact verified unattended qualification".into())
    }

    fn ensure_ticket_view(
        &self,
        store: &mut ConfigStore,
        project_id: &crate::domain::ids::ProjectId,
        namespace: &TicketNamespace,
        ticket_id: &TicketId,
        now_unix: i64,
    ) -> Result<crate::launch::RexView, String> {
        for record in store.rex_view_history(project_id)? {
            if record.lifecycle != "active"
                || record.view.kind != crate::launch::RexViewKind::Ticket
                || record.view.ticket_namespace.as_deref() != Some(namespace.as_str())
                || record.view.ticket_id.as_deref() != Some(ticket_id.as_str())
            {
                continue;
            }
            if record.view.rex_server_identity == self.rex_identity.instance_id
                && record.view.rex_session_id == self.rex_identity.session_id
            {
                return Ok(record.view);
            }
            return Err("TicketRun already has an active Rex view on another session".into());
        }
        let epoch = store
            .rex_view_history(project_id)?
            .iter()
            .filter(|record| {
                record.view.kind == crate::launch::RexViewKind::Ticket
                    && record.view.ticket_namespace.as_deref() == Some(namespace.as_str())
                    && record.view.ticket_id.as_deref() == Some(ticket_id.as_str())
            })
            .map(|record| record.view.view_epoch)
            .max()
            .unwrap_or(0)
            .saturating_add(1);
        let spec = crate::adapters::rex::AgentBlockSpec {
            run_id: format!("ticket-{}-view-{epoch}", ticket_id.as_str()),
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
            .find_or_create_ticket_window(namespace.as_str(), ticket_id.as_str(), &spec)
            .map_err(|error| error.to_string())?;
        let view = crate::launch::RexView {
            view_id: crate::launch::RexView::derive_id(
                project_id,
                crate::launch::RexViewKind::Ticket,
                Some(namespace.as_str()),
                Some(ticket_id.as_str()),
                epoch,
            )?,
            project_id: project_id.clone(),
            kind: crate::launch::RexViewKind::Ticket,
            ticket_namespace: Some(namespace.as_str().to_owned()),
            ticket_id: Some(ticket_id.as_str().to_owned()),
            view_epoch: epoch,
            rex_server_identity: window.server_instance_id,
            rex_session_id: window.session_id,
            rex_window_id: window.window_id,
        };
        store.register_rex_view(self.owner_generation, &view)?;
        let _ = now_unix;
        Ok(view)
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

fn role_allowed_in_phase(role: Role, phase: crate::engine::reducer::Phase) -> bool {
    use crate::engine::reducer::Phase;
    match role {
        Role::Supervisor => false,
        Role::Coordinator => !matches!(phase, Phase::Done | Phase::Canceled),
        Role::Planner => phase == Phase::Planning,
        Role::Worker => phase == Phase::Implementing,
        Role::Reviewer => phase == Phase::Reviewing,
        Role::MergeDecision => matches!(phase, Phase::Assessing | Phase::AwaitingMerge),
        Role::Operator => phase == Phase::Operating,
        Role::Postmortem => phase == Phase::Postmortem,
    }
}

fn mailbox_expiration(now_unix: i64, turn_timeout_seconds: u64) -> Result<u64, String> {
    let timeout = i64::try_from(turn_timeout_seconds)
        .map_err(|_| "Agent turn timeout exceeds supported range")?;
    u64::try_from(
        now_unix
            .checked_add(timeout)
            .and_then(|value| value.checked_add(86_400))
            .ok_or("Agent mailbox expiration overflow")?,
    )
    .map_err(|_| "Agent mailbox expiration is negative".into())
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
