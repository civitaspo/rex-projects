//! Concrete host adapters assembled for one foreground controller.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
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

struct PreparedWorkerContext {
    plan_record: crate::store::accepted_plans::AcceptedWorkPlanRecord,
    validated_plan: crate::engine::orchestration::ValidatedPlan,
    node: crate::engine::orchestration::ValidatedWorkNode,
    token: crate::store::accepted_plans::PreparedWorkerLaunch,
}

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
    mailbox_cursor: Option<String>,
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
        let delivery = crate::runtime_delivery::build(
            applied_config,
            state_root,
            &host_environment,
            &environment.metadata().id,
        )?;
        let mut handlers: Vec<Box<dyn EffectHandler>> = Vec::new();
        let profile_trial_handler =
            crate::profile_trial_runtime::ProfileTrialStartEffectHandler::new(
                applied_config.clone(),
                environment.clone(),
                host_environment.clone(),
                (*rex).clone(),
                rex_binary.clone(),
                rex_identity.clone(),
                runtime_binary.to_owned(),
                runtime_binary_digest.clone(),
                state_root.to_owned(),
                owner_generation,
            )?;
        handlers.push(Box::new(profile_trial_handler));
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
            mailbox_cursor: None,
        })
    }

    fn request_id(&self, purpose: &str) -> Result<RequestId, String> {
        let sequence = REQUEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        RequestId::new(format!("rex-projects-{purpose}-{sequence}"))
    }

    pub fn configuration_digest(&self) -> &Digest {
        &self.configuration_digest
    }

    /// Starts one bounded disposable provider qualification per controller tick and reconciles
    /// completed wrappers. The foreground controller never waits for an LLM turn.
    pub fn tick_provider_qualification_jobs(
        &mut self,
        store: &mut ConfigStore,
        now_unix: i64,
    ) -> Result<(), String> {
        store.mark_orphaned_provider_qualification_jobs(self.owner_generation)?;
        for job in store.provider_qualification_jobs_to_reconcile(8)? {
            if job.controller_generation == self.owner_generation {
                self.reconcile_provider_qualification(store, &job)?;
            }
        }
        let capacity = self
            .config
            .runtime
            .max_agent_runs
            .clamp(1, u32::MAX as usize) as u32;
        let per_project = self
            .config
            .runtime
            .max_ticket_runs
            .clamp(1, u32::MAX as usize) as u32;
        match store.claim_provider_qualification(self.owner_generation, capacity, per_project)? {
            crate::store::provider_qualification_runtime::QualificationClaim::Claimed { job, .. } => {
                if let Err(error) = self.start_provider_qualification(store, &job) {
                    // A possibly-created Rex session is never forgotten or relaunched.
                    let _ = store.mark_provider_qualification_unknown(
                        self.owner_generation,
                        &job.request.request_id,
                    );
                    return Err(format!(
                        "provider qualification {} is unresolved and will not be relaunched: {error}",
                        job.request.request_id
                    ));
                }
            }
            crate::store::provider_qualification_runtime::QualificationClaim::CapacityUnavailable
            | crate::store::provider_qualification_runtime::QualificationClaim::NoQueuedJob => {}
        }
        let _ = now_unix;
        Ok(())
    }

    fn start_provider_qualification(
        &self,
        store: &mut ConfigStore,
        job: &crate::store::provider_qualification_runtime::ProviderQualificationJob,
    ) -> Result<(), String> {
        use crate::store::provider_qualification_runtime::ProviderQualificationJobStatus as Status;
        if job.status != Status::Running || job.controller_generation != self.owner_generation {
            return Err("provider qualification job is not claimed by this controller".into());
        }
        let profile = self
            .applied_config
            .profiles
            .get(&job.request.profile_id)
            .ok_or("provider qualification profile is absent from applied configuration")?;
        if digest_serialized(profile)? != job.request.profile_digest
            || self.applied_config.digest != job.request.config_digest
        {
            return Err("provider qualification profile or config changed after request".into());
        }
        let identity = crate::run_step::profile_runtime_identity(profile)
            .map_err(|error| error.to_string())?;
        let operation_digest = job.request_digest.as_str();
        let operation_id = format!("qualification-{}", &operation_digest[..24]);
        let run_id = crate::domain::ids::AgentRunId::parse(operation_id.clone())?;
        let root = self
            .state_root
            .join("provider-qualifications")
            .join(&operation_id);
        create_private_qualification_tree(&root)?;
        let workspace = root.join("workspace");
        let control_dir = root.join("control");
        let result_path = control_dir.join("result.json");
        let handoff = self
            .environment
            .create_handoff_for_operation(&self.state_root, &operation_id)
            .map_err(|error| error.to_string())?;
        let role_contract = crate::roles::builtin_role_contract(job.request.role).to_owned();
        let prompt = format!(
            "This is a disposable provider qualification turn for role {:?}. Produce exactly one minimal, valid structured result permitted by the attached role schema. Use only synthetic data; do not access external systems, modify files, or perform delivery actions.",
            job.request.role
        );
        let result_schema = crate::roles::result_schema(job.request.role);
        let projection = crate::providers::project_result_schema(&result_schema)?;
        let profile_digest = job.request.profile_digest.clone();
        let instruction_digest = digest_bytes(role_contract.as_bytes())?;
        let wake_digest = digest_bytes(prompt.as_bytes())?;
        let descriptor_path = root.join("package.json");
        let bootstrap_spec = AgentBlockSpec {
            run_id: operation_id.clone(),
            command: PathBuf::from("/usr/bin/env"),
            args: vec![
                "REX_PROJECTS_CONTEXT=agent".into(),
                "REX_PROJECTS_AGENT=1".into(),
                format!("REX_PROJECTS_PROJECT_ID={}", job.request.project_id),
                format!(
                    "REX_PROJECTS_ROLE={}",
                    qualification_role_name(job.request.role)
                ),
                format!("REX_PROJECTS_RUN_ID={run_id}"),
                self.runtime_binary.display().to_string(),
                "agent".into(),
                "qualification-run".into(),
                "--package".into(),
                descriptor_path.display().to_string(),
            ],
            cwd: workspace.clone(),
            path_prepend: Vec::new(),
        };
        let rex_receipt = self
            .rex
            .create_disposable_qualification_session(&operation_id, &bootstrap_spec)
            .map_err(|error| error.to_string())?;
        store.bind_provider_qualification_rex(
            self.owner_generation,
            &job.request.request_id,
            rex_receipt.session_id(),
            rex_receipt.window_id(),
            rex_receipt.block_id(),
        )?;
        let descriptor = crate::run_step::RunDescriptor {
            schema_version: 1,
            project_id: job.request.project_id.clone(),
            run_id,
            role: job.request.role,
            ticket_run_id: None,
            attempt: 1,
            run_epoch: 1,
            controller_generation: self.owner_generation,
            workspace,
            control_dir,
            rex_session_id: rex_receipt.session_id().to_owned(),
            rex_block_id: crate::domain::ids::RexBlockId::parse(rex_receipt.block_id().to_owned())?,
            profile_digest: profile_digest.clone(),
            instruction_digest,
            plan_digest: None,
            environment_snapshot_id: self.environment.metadata().id.clone(),
            wake_snapshot_digest: wake_digest,
            provider_capability: crate::run_step::ProviderCapabilityEvidence {
                schema_version: 1,
                adapter: identity.adapter,
                profile_digest: profile_digest.clone(),
                version: "qualification-bootstrap-unobserved".into(),
                executable_path: identity.executable_path.clone(),
                executable_digest: identity.executable_digest.clone(),
                permission_mode: identity.effective_permission_mode.to_owned(),
                invocation_options_digest: identity.invocation_options_digest.clone(),
                commit_mode: identity.commit_mode,
                schema_projection: projection.identity,
                receipt_digest: Digest::parse("0".repeat(64))?,
                status: crate::run_step::ProviderQualificationStatus::Unknown,
            },
            result_schema,
        };
        let package = crate::provider_qualification_run::QualificationRunPackage {
            schema_version: 1,
            request_id: job.request.request_id.clone(),
            project_id: job.request.project_id.clone(),
            role: job.request.role,
            profile_id: job.request.profile_id.clone(),
            profile_digest,
            environment_snapshot_id: self.environment.metadata().id.clone(),
            profile: profile.clone(),
            descriptor,
            role_contract,
            prompt,
            workspace_root: root,
            environment_handoff: handoff.path().to_owned(),
            environment_operation_id: operation_id,
            result_path,
            rex_cli_path: self.rex_cli_path.clone(),
            rex_search_path: self.rex_search_path.clone(),
            rex_receipt,
            deadline_seconds: 1800,
            shutdown_grace_seconds: self.config.runtime.shutdown_grace_seconds.clamp(1, 300),
        };
        package.publish_once(&descriptor_path)
    }

    fn reconcile_provider_qualification(
        &self,
        store: &mut ConfigStore,
        job: &crate::store::provider_qualification_runtime::ProviderQualificationJob,
    ) -> Result<(), String> {
        use crate::store::provider_qualification_runtime::ProviderQualificationJobStatus as Status;
        if !matches!(job.status, Status::Running | Status::Unknown)
            || job.controller_generation != self.owner_generation
        {
            return Ok(());
        }
        let operation_id = format!("qualification-{}", &job.request_digest.as_str()[..24]);
        let recovered_receipt;
        let (session_id, window_id, block_id) = match (
            job.rex_session_id.as_deref(),
            job.rex_window_id.as_deref(),
            job.rex_block_id.as_deref(),
        ) {
            (Some(session_id), Some(window_id), Some(block_id)) => {
                (session_id, window_id, block_id)
            }
            (None, None, None) => {
                // `rex new` may have succeeded just before the controller crashed, before its
                // returned IDs reached SQLite. Adopt only the exact operation-labeled session
                // on the pinned Rex instance; never create another one during reconciliation.
                let Some(receipt) = self
                    .rex
                    .find_disposable_qualification_session(&operation_id)
                    .map_err(|error| error.to_string())?
                else {
                    return Ok(());
                };
                store.bind_provider_qualification_rex(
                    self.owner_generation,
                    &job.request.request_id,
                    receipt.session_id(),
                    receipt.window_id(),
                    receipt.block_id(),
                )?;
                recovered_receipt = receipt;
                (
                    recovered_receipt.session_id(),
                    recovered_receipt.window_id(),
                    recovered_receipt.block_id(),
                )
            }
            _ => return mark_qualification_unknown(store, self.owner_generation, job),
        };
        let root = self
            .state_root
            .join("provider-qualifications")
            .join(&operation_id);
        let package_path = root.join("package.json");
        let result_path = root.join("control/result.json");
        let package_bytes = match read_private_bounded(&package_path, 8 * 1024 * 1024) {
            Ok(bytes) => bytes,
            Err(_) => return mark_qualification_unknown(store, self.owner_generation, job),
        };
        let package: crate::provider_qualification_run::QualificationRunPackage =
            match crate::protocol::parse_unique(&package_bytes) {
                Ok(package) => package,
                Err(_) => return mark_qualification_unknown(store, self.owner_generation, job),
            };
        if package.request_id != job.request.request_id
            || package.rex_receipt.operation_id() != operation_id
            || package.rex_receipt.session_id() != session_id
            || package.rex_receipt.window_id() != window_id
            || package.rex_receipt.block_id() != block_id
        {
            return Err("qualification package does not match its durable Rex binding".into());
        }
        let session_exists = match self.rex.qualification_session_exists(session_id) {
            Ok(exists) => exists,
            Err(_) => return mark_qualification_unknown(store, self.owner_generation, job),
        };
        let rex = if session_exists {
            match RexCliTransport::connect(
                &self.rex_cli_path,
                &self.rex_search_path,
                self.rex_identity.endpoint.clone(),
                self.rex_identity.instance_id.clone(),
                session_id.to_owned(),
                self.host_environment.clone(),
            ) {
                Ok(rex) => Some(rex),
                Err(_) => return mark_qualification_unknown(store, self.owner_generation, job),
            }
        } else {
            None
        };
        let block_exit_code = if let Some(rex) = rex.as_ref() {
            if rex
                .qualification_block_finished(&package.rex_receipt)
                .map_err(|error| error.to_string())?
            {
                // Rex removes a finished block (and sometimes its window) automatically. The
                // run-step spool is only published after the receipt is durable, so the exact
                // receipt/session shape plus host process cleanup is enough to reconcile it.
                None
            } else {
                let window = RexWindow {
                    server_instance_id: self.rex_identity.instance_id.clone(),
                    session_id: session_id.to_owned(),
                    window_id: window_id.to_owned(),
                    label: package.rex_receipt.window_label().to_owned(),
                    initial_block_id: Some(block_id.to_owned()),
                    disposition: CreateDisposition::Existing,
                };
                let observation = match rex.observe_process(&window, &operation_id, block_id) {
                    Ok(observation) => observation,
                    Err(_) => return mark_qualification_unknown(store, self.owner_generation, job),
                };
                let Some(exit) = observation.last_exit else {
                    return Ok(());
                };
                Some(exit.exit_code)
            }
        } else {
            // Rex can automatically remove an empty one-block session when the wrapper exits.
            // The private spool is written only after the turn receipt exists; absence is the
            // host's terminal observation when that exact session has already disappeared.
            None
        };
        let result_bytes = match read_private_bounded(&result_path, 1024 * 1024) {
            Ok(bytes) => bytes,
            Err(_) => return mark_qualification_unknown(store, self.owner_generation, job),
        };
        let run: crate::provider_qualification_run::QualificationRunResult =
            match crate::protocol::parse_unique(&result_bytes) {
                Ok(run) => run,
                Err(_) => return mark_qualification_unknown(store, self.owner_generation, job),
            };
        if run.request_id != job.request.request_id {
            return mark_qualification_unknown(store, self.owner_generation, job);
        }
        if !crate::provider_qualification_run::receipt_outcome_succeeded(&run.receipt)
            || run.receipt.run_id != package.descriptor.run_id
            || run.receipt.provider != package.profile.adapter
            || run.receipt.effective_permission_mode
                != package.descriptor.provider_capability.permission_mode
            || run.receipt.schema_projection
                != package.descriptor.provider_capability.schema_projection
            || block_exit_code.is_some_and(|exit_code| exit_code != 0)
        {
            if matches!(
                run.receipt.cleanup,
                crate::run_step::CleanupState::Confirmed
            ) {
                if rex
                    .as_ref()
                    .unwrap_or(&self.rex)
                    .close_disposable_qualification_session(package.rex_receipt.clone())
                    .is_err()
                {
                    return mark_qualification_unknown(store, self.owner_generation, job);
                }
                let failure = serde_json::json!({
                    "schema_version": 1,
                    "request_id": job.request.request_id,
                    "outcome": "failed",
                    "reason": "provider qualification did not produce a valid completed turn",
                    "provider_result_failure": run.receipt.provider_result_failure,
                    "provider_process_failure": run.receipt.provider_process_failure,
                });
                let failure = serde_json::to_string(&failure).map_err(|error| error.to_string())?;
                let digest = digest_bytes(failure.as_bytes())?;
                store.finish_provider_qualification_job(
                    self.owner_generation,
                    &job.request.request_id,
                    Status::Failed,
                    &failure,
                    &digest,
                    true,
                )?;
                return Ok(());
            }
            return mark_qualification_unknown(store, self.owner_generation, job);
        }
        let Some(structured_result) = run.structured_result.as_ref() else {
            return mark_qualification_unknown(store, self.owner_generation, job);
        };
        let actual_result_digest = digest_bytes(
            &serde_json::to_vec(&Some(structured_result)).map_err(|error| error.to_string())?,
        )?;
        if actual_result_digest != run.result_digest {
            return mark_qualification_unknown(store, self.owner_generation, job);
        }
        let current = match crate::process::inspect_process_table() {
            Ok(current) => current,
            Err(_) => return mark_qualification_unknown(store, self.owner_generation, job),
        };
        let process_tree_absent = !run.receipt.processes.is_empty()
            && run.receipt.processes.iter().all(|observed| {
                observed.identity_quality == "kernel_birth_token"
                    && current.iter().all(|process| {
                        process.pid != observed.pid
                            || process.start_identity != observed.start_identity
                    })
            });
        if !process_tree_absent {
            return mark_qualification_unknown(store, self.owner_generation, job);
        }
        let profile = self
            .applied_config
            .profiles
            .get(&job.request.profile_id)
            .ok_or("qualified profile disappeared from applied configuration")?;
        let identity = crate::run_step::profile_runtime_identity(profile)
            .map_err(|error| error.to_string())?;
        if digest_serialized(profile)? != job.request.profile_digest
            || identity.executable_digest
                != package.descriptor.provider_capability.executable_digest
        {
            return Err("provider profile changed while qualification was running".into());
        }
        let version = probe_provider_version(
            profile,
            &self.host_environment,
            &package.descriptor.workspace,
        )?;
        let marker_names = [
            "REX_PROJECTS_AGENT",
            "REX_PROJECTS_CONTEXT",
            "REX_PROJECTS_PROJECT_ID",
            "REX_PROJECTS_ROLE",
            "REX_PROJECTS_RUN_ID",
        ];
        let markers: BTreeSet<String> = marker_names
            .iter()
            .map(|marker| (*marker).to_owned())
            .collect();
        let receipt_json = serde_json::to_vec(&run.receipt).map_err(|error| error.to_string())?;
        let fixture_json =
            serde_json::to_vec(&package.rex_receipt).map_err(|error| error.to_string())?;
        let proof = crate::launch::QualificationProof {
            schema_version: crate::launch::QUALIFICATION_SCHEMA_VERSION,
            probe_id: job.request.request_id.clone(),
            fixture_digest: digest_bytes(&fixture_json)?,
            rex_instance_id: self.rex_identity.instance_id.clone(),
            tool_shell_marker_digest: digest_bytes(
                &serde_json::to_vec(&markers).map_err(|e| e.to_string())?,
            )?,
            tool_shell_markers_present: markers.clone(),
            descendant_marker_digest: digest_bytes(
                &serde_json::to_vec(&markers).map_err(|e| e.to_string())?,
            )?,
            descendant_markers_present: markers,
            automatic_turn_result_digest: run.result_digest.clone(),
            automatic_turn_completed: true,
            structured_result_valid: true,
            observed_permission_mode: run.receipt.effective_permission_mode.clone(),
            permission_prompt_count: 0,
            cleanup_process_tree_digest: digest_bytes(&receipt_json)?,
            process_tree_absent: true,
            cleanup_confirmed: true,
        };
        let qualification = crate::launch::ProviderQualification {
            schema_version: crate::launch::QUALIFICATION_SCHEMA_VERSION,
            project_id: job.request.project_id.clone(),
            profile_id: job.request.profile_id.clone(),
            profile_digest: job.request.profile_digest.clone(),
            adapter: identity.adapter,
            executable_path: identity.executable_path.display().to_string(),
            executable_digest: identity.executable_digest,
            provider_version: version,
            permission_mode: identity.effective_permission_mode.to_owned(),
            invocation_options_digest: identity.invocation_options_digest,
            commit_mode: identity.commit_mode,
            proof,
            status: crate::launch::QualificationStatus::Verified,
        };
        qualification.validate_for_unattended_launch()?;
        if rex
            .as_ref()
            .unwrap_or(&self.rex)
            .close_disposable_qualification_session(package.rex_receipt.clone())
            .is_err()
        {
            return mark_qualification_unknown(store, self.owner_generation, job);
        }
        let qualification_json =
            serde_json::to_string(&qualification).map_err(|e| e.to_string())?;
        let evidence_digest = digest_bytes(qualification_json.as_bytes())?;
        store.store_provider_qualification(self.owner_generation, &qualification)?;
        store.finish_provider_qualification_job(
            self.owner_generation,
            &job.request.request_id,
            Status::Verified,
            &qualification_json,
            &evidence_digest,
            true,
        )?;
        Ok(())
    }
}

fn qualification_role_name(role: Role) -> &'static str {
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

fn create_private_qualification_tree(root: &Path) -> Result<(), String> {
    let parent = root
        .parent()
        .ok_or("qualification state path has no parent")?;
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let parent_meta = fs::symlink_metadata(parent).map_err(|error| error.to_string())?;
    if !parent_meta.is_dir() || parent_meta.file_type().is_symlink() {
        return Err("qualification state parent must be a real directory".into());
    }
    fs::create_dir(root).map_err(|error| error.to_string())?;
    set_private_directory(root)?;
    for name in ["workspace", "control"] {
        let path = root.join(name);
        fs::create_dir(&path).map_err(|error| error.to_string())?;
        set_private_directory(&path)?;
    }
    let canonical_root = fs::canonicalize(root).map_err(|error| error.to_string())?;
    if canonical_root != root
        || fs::canonicalize(root.join("workspace")).map_err(|error| error.to_string())?
            != root.join("workspace")
        || fs::canonicalize(root.join("control")).map_err(|error| error.to_string())?
            != root.join("control")
    {
        return Err("qualification paths changed during creation".into());
    }
    Ok(())
}

fn set_private_directory(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn read_private_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > maximum as u64 {
        return Err("qualification spool must be a bounded regular non-symlink file".into());
    }
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)
            .map_err(|error| error.to_string())?
    };
    #[cfg(not(unix))]
    let mut file = fs::File::open(path).map_err(|error| error.to_string())?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > maximum {
        return Err("qualification spool exceeds its size limit".into());
    }
    Ok(bytes)
}

fn probe_provider_version(
    profile: &crate::config::Profile,
    environment: &BTreeMap<OsString, OsString>,
    cwd: &Path,
) -> Result<String, String> {
    let executable = profile
        .command
        .first()
        .ok_or("provider profile has no executable")?;
    let mut args = profile.command[1..]
        .iter()
        .cloned()
        .map(OsString::from)
        .collect::<Vec<_>>();
    args.push("--version".into());
    let output = crate::process::run(crate::process::ProcessRequest {
        executable: PathBuf::from(executable),
        args,
        stdin: Vec::new(),
        cwd: Some(cwd.to_owned()),
        clear_environment: false,
        environment: environment.clone(),
        timeout: Duration::from_secs(15),
        shutdown_grace: Duration::from_secs(2),
        stdout_limit: 4096,
        stderr_tail_limit: 1024,
    })
    .map_err(|_| "provider version probe failed or cleanup is unresolved".to_owned())?;
    if output.timed_out
        || !output.cleanup_confirmed
        || !output.status.is_some_and(|status| status.success())
        || output.stdout_truncated
    {
        return Err("provider version probe did not complete cleanly".into());
    }
    let version = std::str::from_utf8(&output.stdout)
        .map_err(|_| "provider version output is not UTF-8")?
        .trim();
    if version.is_empty() || version.len() > 128 || version.chars().any(char::is_control) {
        return Err("provider version output is malformed".into());
    }
    Ok(version.to_owned())
}

fn mark_qualification_unknown(
    store: &mut ConfigStore,
    generation: u64,
    job: &crate::store::provider_qualification_runtime::ProviderQualificationJob,
) -> Result<(), String> {
    if job.status
        == crate::store::provider_qualification_runtime::ProviderQualificationJobStatus::Running
    {
        store.mark_provider_qualification_unknown(generation, &job.request.request_id)?;
    }
    Ok(())
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
        let worker_context = if reservation.role == Role::Worker {
            Some(resolve_prepared_worker_context_for_reservation(
                store,
                owner_generation,
                reservation,
                project,
                &self.applied_config.digest,
            )?)
        } else {
            None
        };
        if worker_context.as_ref().is_some_and(|context| {
            context.token.worktree_path() != reservation.workspace_path
                || context.token.ticket_revision()
                    != reservation
                        .ticket_revision
                        .map(|revision| revision.0)
                        .unwrap_or(0)
                || reservation.parent_run_id.as_ref()
                    != Some(context.token.coordinator_agent_run_id())
                || reservation.parent_role != Some(Role::Coordinator)
        }) {
            return Err(
                "Worker package reservation differs from prepared worktree authority".into(),
            );
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
        let operation_recipe = if reservation.role == Role::Operator {
            reservation.operation_recipe_id.clone()
        } else {
            None
        };
        let worker_node = worker_context.as_ref().map(|context| context.node.clone());
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
                repositories: worker_node
                    .as_ref()
                    .map(|node| vec![node.repository.clone()])
                    .unwrap_or_else(|| project.repositories.clone()),
                ticket,
                recovery_summary: None,
                accepted_plan: match (&worker_context, &accepted_plan) {
                    (Some(context), _) => Some(worker_assignment_context(
                        &context.plan_record,
                        &context.validated_plan,
                        &context.node,
                        context.token.worktree_path(),
                        context.token.branch(),
                        context.token.base_sha(),
                        context.token.commit_mode(),
                        context.token.repository_id(),
                    )?),
                    (None, Some(plan)) => Some(
                        serde_json::to_string(&plan.proposal).map_err(|error| error.to_string())?,
                    ),
                    (None, None) => None,
                },
                previous_decisions: Vec::new(),
                required_evidence: worker_node
                    .as_ref()
                    .map(|node| node.required_evidence.clone())
                    .unwrap_or_default(),
                stop_conditions: if reservation.role == Role::Worker {
                    vec![
                        "Work only in the assigned repository worktree and follow the assigned node's base/dependency semantics.".into(),
                        "Do not push, create a pull request, request a merge, or merge; the host controls publication.".into(),
                    ]
                } else {
                    Vec::new()
                },
                assigned_commit_mode: worker_context
                    .as_ref()
                    .map(|context| context.token.commit_mode()),
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
            operation_id: reservation.operation_id.clone(),
            role: reservation.role,
            ticket_run_id: reservation.ticket_run_id.clone(),
            expected_subject_revision: reservation
                .ticket_revision
                .map(|value| value.0)
                .unwrap_or(0),
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
    fn process_one_agent_request(
        &mut self,
        store: &mut ConfigStore,
        owner_generation: u64,
        now_unix: i64,
    ) -> Result<bool, String> {
        let mailboxes = store.registered_agent_mailboxes()?;
        if mailboxes.is_empty() {
            return Ok(false);
        }
        let start = self
            .mailbox_cursor
            .as_ref()
            .and_then(|cursor| {
                mailboxes
                    .iter()
                    .position(|entry| &entry.agent_run_id > cursor)
            })
            .unwrap_or(0);
        let mut first_error = None;
        for offset in 0..mailboxes.len() {
            let registration = &mailboxes[(start + offset) % mailboxes.len()];
            self.mailbox_cursor = Some(registration.agent_run_id.clone());
            match store.process_one_agent_mailbox_request(
                owner_generation,
                &registration.agent_run_id,
                now_unix,
                &self.artifacts,
            ) {
                Ok(true) => return Ok(true),
                Ok(false) => {}
                Err(error) => {
                    first_error.get_or_insert_with(|| {
                        format!("AgentRun {} mailbox: {error}", registration.agent_run_id)
                    });
                }
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(false),
        }
    }

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

    fn worker_publication_effect(
        &mut self,
        store: &mut ConfigStore,
        owner_generation: u64,
        now_unix: i64,
        config: &Config,
        run: &crate::store::scheduler::ActiveTicketRun,
        result: &crate::store::agent_results::IngestedAgentResult,
        effect_revision: u64,
    ) -> Result<Option<crate::store::EffectIntent>, String> {
        use crate::delivery_runtime::{
            PublishImplementationEffectPayload, PullRequestContent, WorkerDeliveryCommit,
            canonical_delivery_payload,
        };
        use crate::domain::ids::OperationId;
        use crate::domain::types::CommitMode;
        use crate::engine::orchestration::{RoleArtifactKind, RoleResultPayload};

        let binding = &result.validated.binding;
        let claimed = match &result.validated.typed_payload {
            RoleResultPayload::ImplementationReady(value) => value,
            _ => return Err("Worker result is not an ImplementationReady payload".into()),
        };
        let ticket_run_id = binding
            .ticket_run_id
            .as_ref()
            .ok_or("Worker result has no TicketRun")?;
        let plan = store
            .latest_accepted_work_plan(&run.project_id, ticket_run_id)?
            .ok_or("Worker result has no accepted WorkPlan")?;
        let project_config = self
            .applied_config
            .config
            .projects
            .get(&run.project_id)
            .ok_or("Worker Project is absent from applied configuration")?;
        let validated_plan = plan.validate_for(project_config, &self.configuration_digest)?;
        let node_id = binding
            .role_session_id
            .as_str()
            .strip_prefix(&format!("ticket:{}:worker:", ticket_run_id.as_str()))
            .ok_or("Worker result has a noncanonical per-node role session")?;
        let node_id = crate::engine::orchestration::WorkNodeId::parse(node_id)?;
        let node = validated_plan
            .nodes_in_execution_order
            .iter()
            .find(|node| node.id == node_id && node.role == Role::Worker)
            .ok_or("Worker role session is not an accepted implementation node")?;
        let succeeded = store.list_succeeded_effect_receipts(
            owner_generation,
            &run.project_id,
            "ticket_run",
            run.ticket_run_id.as_str(),
            256,
        )?;
        let prepared_receipt = succeeded
            .iter()
            .find(|receipt| receipt.intent().kind == "prepare_worktrees")
            .ok_or("Worker has no succeeded PrepareWorktrees receipt")?;
        let prepared = store
            .prepared_worker_launch(
                owner_generation,
                plan.accepted_revision,
                &node_id,
                prepared_receipt,
                project_config,
                &self.configuration_digest,
            )?
            .ok_or("Worker launch authority is no longer valid")?;
        if prepared.project_id() != &run.project_id
            || prepared.ticket_run_id() != ticket_run_id
            || prepared.ticket_revision() != run.revision
            || prepared.repository_id() != &node.repository
            || prepared.configuration_digest() != &binding.config_digest
        {
            return Err("Worker result does not match its prepared node authority".into());
        }
        let change = claimed
            .change_references
            .iter()
            .filter(|reference| reference.worktree_id == node_id)
            .collect::<Vec<_>>();
        if change.len() != 1 || change[0].repository != node.repository {
            return Err("Worker result must identify exactly its assigned repository node".into());
        }
        if claimed.change_references.len() != 1 {
            return Err(
                "Worker result must contain exactly one change for its assigned node".into(),
            );
        }
        let change = change[0];
        let commit_mode = prepared.commit_mode();
        if change.commit_mode != commit_mode || change.base_commit.as_str() != prepared.base_sha() {
            return Err("Worker commit claim differs from the host-prepared worktree".into());
        }
        let commit = match commit_mode {
            CommitMode::Native => {
                if change.commit_shas.is_empty() {
                    return Err("native Worker result has no exact commit IDs".into());
                }
                let profile_id = project_config
                    .roles
                    .get(&Role::Worker)
                    .ok_or("Worker profile is not configured")?;
                let profile = self
                    .applied_config
                    .profiles
                    .get(profile_id)
                    .ok_or("Worker profile is unavailable")?;
                let trailer = match profile.adapter {
                    crate::domain::types::AgentAdapter::Codex => {
                        "Co-authored-by: Codex <noreply@openai.com>"
                    }
                    crate::domain::types::AgentAdapter::ClaudeCode => {
                        "Co-authored-by: Claude <noreply@anthropic.com>"
                    }
                };
                WorkerDeliveryCommit::Native {
                    previous_accepted_head: change.previous_head.as_str().to_owned(),
                    worker_reported_head: change.branch_head.as_str().to_owned(),
                    required_trailer: trailer.to_owned(),
                }
            }
            CommitMode::Host => {
                let source = result
                    .validated
                    .claimed_artifact_refs
                    .iter()
                    .filter(|reference| reference.kind == RoleArtifactKind::Change)
                    .collect::<Vec<_>>();
                if source.len() != 1 {
                    return Err(
                        "host-commit Worker must provide exactly one registered Change artifact"
                            .into(),
                    );
                }
                let authority = store
                    .agent_launch_authority(&binding.agent_run_id)?
                    .ok_or("Worker launch authority is missing")?;
                let verified = store
                    .lookup_verified_artifact(&self.artifacts, &authority, source[0])?
                    .ok_or("Worker Change artifact is not registered to its launch")?;
                let manifest: crate::host_commit::ChangeManifest =
                    crate::protocol::parse_unique(&verified.read_bytes(&self.artifacts)?)
                        .map_err(|error| error.to_string())?;
                if manifest.schema_version != 1 || manifest.entries.is_empty() {
                    return Err(
                        "Worker Change manifest is empty or has an unsupported schema".into(),
                    );
                }
                WorkerDeliveryCommit::HostManifest {
                    expected_head: prepared.base_sha().to_owned(),
                    manifest,
                    message: format!(
                        "Implement {}",
                        node.task.lines().next().unwrap_or("planned work")
                    ),
                }
            }
            CommitMode::Auto => {
                return Err("Worker commit mode must be resolved before publication".into());
            }
        };
        let repository = config
            .repositories
            .get(&node.repository)
            .ok_or("accepted Worker repository is no longer configured")?;
        let expected_remote_head = match self
            .delivery
            .effects()
            .observe_remote_branch(&node.repository, prepared.branch())
        {
            Ok(head) => head,
            Err(_) => return Ok(None),
        };
        let title = node
            .task
            .lines()
            .next()
            .unwrap_or("Implement planned work")
            .trim();
        if title.is_empty() || title.len() > 200 {
            return Err("accepted work node has an invalid pull request title".into());
        }
        let body = format!(
            "Ticket: {}\n\nWork node: {}\n\nTask:\n{}\n\nCompleted acceptance items:\n{}\n\nUnresolved items:\n{}\n\nRex-Projects-Run: {}\nRex-Projects-Node: {}",
            run.ticket_id,
            node_id,
            node.task,
            claimed
                .completed_acceptance_items
                .iter()
                .map(|line| format!("- {line}"))
                .collect::<Vec<_>>()
                .join("\n"),
            claimed
                .unresolved_items
                .iter()
                .map(|line| format!("- {line}"))
                .collect::<Vec<_>>()
                .join("\n"),
            run.ticket_run_id,
            node_id,
        );
        let payload = PublishImplementationEffectPayload {
            schema_version: 1,
            source_revision: effect_revision,
            configuration_digest: self.configuration_digest.clone(),
            ticket_namespace: run.namespace.clone(),
            ticket_id: run.ticket_id.clone(),
            ticket_run_id: run.ticket_run_id.clone(),
            work_node_id: node_id.clone(),
            repository_id: node.repository.clone(),
            expected_base_sha: prepared.base_sha().to_owned(),
            base_branch: repository.base_branch.clone(),
            commit_mode,
            commit,
            expected_remote_head,
            pull_request: PullRequestContent {
                title: title.to_owned(),
                body,
                update_target: None,
            },
        };
        let (request_json, request_digest) = canonical_delivery_payload(&payload)?;
        let operation_id = OperationId::parse(format!("publish-{}", result.receipt.evidence_id()))?;
        let _ = now_unix;
        Ok(Some(crate::store::EffectIntent {
            project_id: run.project_id.clone(),
            subject_type: "ticket_run".into(),
            subject_id: run.ticket_run_id.as_str().into(),
            operation_id: operation_id.as_str().to_owned(),
            logical_key: format!("{}:publish:{}", run.ticket_run_id, node_id),
            kind: crate::engine::reducer::effect_name(
                &crate::engine::reducer::EffectKind::PublishImplementation,
            )
            .into(),
            request_json,
            request_digest,
            expected_revision: Some(effect_revision),
        }))
    }

    fn tick_profile_trials(
        &mut self,
        store: &mut ConfigStore,
        owner_generation: u64,
        now_unix: i64,
        max_agent_slots: u32,
        max_project_slots: u32,
    ) -> Result<(), String> {
        if owner_generation != self.owner_generation {
            return Err("RuntimeServices owner generation changed".into());
        }
        let _next = store.tick_profile_trials(
            owner_generation,
            u64::try_from(now_unix).map_err(|_| "controller clock is before Unix epoch")?,
            max_agent_slots,
            max_project_slots,
        )?;
        Ok(())
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
        let wake_items = Self::wake_items_with_staged_artifacts(
            &self.artifacts,
            store,
            owner_generation,
            &candidate.project_id,
            runnable.record.config_revision.0,
            &runnable.record.config_digest,
            &workspace,
            wake_inputs,
        )?;
        let wake_snapshot = crate::agent_api::AgentWakeSnapshot {
            schema_version: 1,
            project_id: candidate.project_id.clone(),
            role_session_id: candidate.role_session_id.clone(),
            agent_run_id: run_id.as_str().to_owned(),
            digest: Digest::parse("0".repeat(64))?,
            inputs: wake_items,
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
            worker_assignment: None,
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
    #[allow(clippy::too_many_arguments)]
    fn wake_items_with_staged_artifacts(
        artifact_store: &ArtifactStore,
        store: &mut ConfigStore,
        owner_generation: u64,
        project_id: &crate::domain::ids::ProjectId,
        config_revision: u64,
        config_digest: &Digest,
        workspace: &Path,
        wake_inputs: Vec<crate::store::agent_runtime::PendingRoleWakeInput>,
    ) -> Result<Vec<crate::agent_api::AgentWakeItem>, String> {
        let mut items = Vec::with_capacity(wake_inputs.len());
        for input in wake_inputs {
            let mut host_artifacts = Vec::new();
            if input.source_type == "agent_result" {
                let wake_id = i64::try_from(input.wake_input_id)
                    .map_err(|_| "Agent result wake ID exceeds the durable SQLite identity")?;
                let result = store
                    .validated_agent_result_for_wake(artifact_store, owner_generation, wake_id)?
                    .ok_or_else(|| {
                        format!(
                            "cannot launch parent for wake {}: its durable Agent result source is missing or no longer pending",
                            input.wake_input_id
                        )
                    })?;
                if !result.receipt.wake_input_ids().contains(&wake_id)
                    || result.receipt.evidence_id() != input.source_id
                    || result.validated.binding.project_id != *project_id
                {
                    return Err(format!(
                        "cannot launch parent for wake {}: validated source result does not match the wake scope",
                        input.wake_input_id
                    ));
                }
                let source_run_id = result.validated.binding.agent_run_id.clone();
                let source_authority = store.agent_launch_authority(&source_run_id)?.ok_or_else(
                    || {
                        format!(
                            "cannot launch parent for wake {}: child AgentRun authority is missing",
                            input.wake_input_id
                        )
                    },
                )?;
                if source_authority.role_session_id
                    != result.validated.binding.role_session_id.as_str()
                    || source_authority.project_id != *project_id
                    || source_authority.run_epoch != input.source_revision
                {
                    return Err(format!(
                        "cannot launch parent for wake {}: child result no longer matches launch authority",
                        input.wake_input_id
                    ));
                }
                if !result.validated.claimed_artifact_refs.is_empty() {
                    host_artifacts = crate::parent_artifacts::stage_verified_parent_artifacts(
                        store,
                        artifact_store,
                        &source_authority,
                        result.receipt.evidence_id(),
                        project_id,
                        config_revision,
                        config_digest,
                        workspace,
                        &result.validated.claimed_artifact_refs,
                    )
                    .map_err(|error| {
                        format!(
                            "cannot launch parent for wake {} because a child artifact could not be staged: {error}",
                            input.wake_input_id
                        )
                    })?;
                }
            }
            items.push(crate::agent_api::AgentWakeItem {
                wake_input_id: input.wake_input_id,
                source_type: input.source_type,
                source_id: input.source_id,
                source_revision: input.source_revision,
                priority: input.priority,
                payload_json: input.payload_json,
                host_artifacts,
            });
        }
        Ok(items)
    }

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
        let worker_node_id = if candidate.role == Role::Worker {
            let node_id = candidate
                .work_node_id
                .as_ref()
                .ok_or("generic Worker wake cannot authorize a launch")?;
            if candidate.role_session_id != format!("ticket:{ticket_run_id}:worker:{node_id}") {
                return Err("Worker wake does not match its per-node role session".into());
            }
            Some(node_id.clone())
        } else {
            if candidate.work_node_id.is_some()
                || candidate.role_session_id
                    != format!("ticket_run:{ticket_run_id}:{}", role_name(candidate.role))
            {
                return Err("ticket role wake scope does not match its TicketRun".into());
            }
            None
        };
        if candidate.role != Role::Worker && candidate.work_node_id.is_some() {
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
        let worker_context = if let Some(node_id) = &worker_node_id {
            Some(resolve_prepared_worker_context(
                store,
                self.owner_generation,
                &candidate.project_id,
                ticket_run_id,
                node_id,
                &project,
                &self.configuration_digest,
            )?)
        } else {
            None
        };
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
        let validated_plan = accepted_plan
            .as_ref()
            .map(|plan| plan.validate_for(&project, &self.configuration_digest))
            .transpose()?;
        let worker_node = worker_context
            .as_ref()
            .and_then(|context| {
                context
                    .validated_plan
                    .nodes_in_execution_order
                    .iter()
                    .find(|node| Some(&node.id) == worker_node_id.as_ref())
            })
            .cloned();
        if candidate.role == Role::Worker && worker_node.is_none() {
            return Err("prepared Worker token does not resolve to an accepted plan node".into());
        }
        let rendered = crate::roles::render_role_prompt(
            &self.applied_config,
            &crate::roles::PromptContext {
                project_id: candidate.project_id.clone(),
                profile_id: Some(profile_id.clone()),
                role: candidate.role,
                operation_recipe: if candidate.role == Role::Operator {
                    active_run.recipe_id.clone()
                } else {
                    None
                },
                repositories: worker_node
                    .as_ref()
                    .map(|node| vec![node.repository.clone()])
                    .unwrap_or_else(|| project.repositories.clone()),
                ticket: Some(crate::roles::TicketBrief {
                    ticket_id: active_run.ticket_id.clone(),
                    ticket_revision: active_run.revision,
                    title: ticket.ticket.title,
                    body: ticket.ticket.body,
                    acceptance: Vec::new(),
                }),
                recovery_summary: None,
                accepted_plan: match (
                    &accepted_plan,
                    &validated_plan,
                    &worker_context,
                    &worker_node,
                ) {
                    (Some(plan), Some(validated), Some(context), Some(node))
                        if candidate.role == Role::Worker =>
                    {
                        Some(worker_assignment_context(
                            plan,
                            validated,
                            node,
                            context.token.worktree_path(),
                            context.token.branch(),
                            context.token.base_sha(),
                            context.token.commit_mode(),
                            context.token.repository_id(),
                        )?)
                    }
                    (Some(plan), _, _, _) => Some(
                        serde_json::to_string(&plan.proposal).map_err(|error| error.to_string())?,
                    ),
                    _ => None,
                },
                previous_decisions: Vec::new(),
                required_evidence: worker_node
                    .as_ref()
                    .map(|node| node.required_evidence.clone())
                    .unwrap_or_default(),
                stop_conditions: if candidate.role == Role::Worker {
                    vec![
                        "Work only in the assigned repository worktree and follow the assigned node's base/dependency semantics.".into(),
                        "Do not push, create a pull request, request a merge, or merge; the host controls publication.".into(),
                    ]
                } else {
                    Vec::new()
                },
                assigned_commit_mode: worker_context
                    .as_ref()
                    .map(|context| context.token.commit_mode()),
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
        let workspace = worker_context
            .as_ref()
            .map(|context| context.token.worktree_path().to_owned())
            .unwrap_or_else(|| {
                self.state_root
                    .join("projects")
                    .join(candidate.project_id.as_str())
                    .join("role-workspaces")
                    .join(role_name(candidate.role))
            });
        let run_root = self.state_root.join("agents").join(agent_run_id.as_str());
        let control_dir = run_root.join("control");
        if candidate.role == Role::Worker {
            if !workspace.is_dir()
                || std::fs::canonicalize(&workspace).ok().as_ref() != Some(&workspace)
            {
                return Err("prepared Worker worktree is missing or not canonical".into());
            }
        } else {
            create_private_dir(&workspace)?;
        }
        create_private_dir(&control_dir)?;
        let wake_items = Self::wake_items_with_staged_artifacts(
            &self.artifacts,
            store,
            self.owner_generation,
            &candidate.project_id,
            runnable.record.config_revision.0,
            &runnable.record.config_digest,
            &workspace,
            wake_inputs,
        )?;
        let mut wake_snapshot = crate::agent_api::AgentWakeSnapshot {
            schema_version: 1,
            project_id: candidate.project_id.clone(),
            role_session_id: candidate.role_session_id.clone(),
            agent_run_id: agent_run_id.as_str().to_owned(),
            digest: Digest::parse("0".repeat(64))?,
            inputs: wake_items,
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
            parent_run_id: worker_context
                .as_ref()
                .map(|context| context.token.coordinator_agent_run_id().clone()),
            parent_role: worker_context.as_ref().map(|_| Role::Coordinator),
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
            worker_assignment: worker_context
                .as_ref()
                .map(|context| context.token.reservation_binding()),
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
        let result = if let Some(context) = &worker_context {
            store.prepare_worker_role_launch(&reservation, &context.token)?
        } else {
            store.prepare_role_launch(&reservation)?
        };
        match result {
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

fn resolve_prepared_worker_context(
    store: &ConfigStore,
    owner_generation: u64,
    project_id: &crate::domain::ids::ProjectId,
    ticket_run_id: &crate::domain::ids::TicketRunId,
    node_id: &crate::engine::orchestration::WorkNodeId,
    project: &crate::config::ProjectConfig,
    configuration_digest: &Digest,
) -> Result<PreparedWorkerContext, String> {
    let plan_record = store
        .latest_accepted_work_plan(project_id, ticket_run_id)?
        .ok_or("Worker wake has no accepted Coordinator work plan")?;
    let validated_plan = plan_record.validate_for(project, configuration_digest)?;
    let node = validated_plan
        .nodes_in_execution_order
        .iter()
        .find(|node| &node.id == node_id)
        .cloned()
        .ok_or("Worker wake node is absent from the accepted work plan")?;
    if node.role != Role::Worker || !project.repositories.contains(&node.repository) {
        return Err("accepted plan node is not an allowed Worker repository assignment".into());
    }

    let receipts = store.list_succeeded_effect_receipts(
        owner_generation,
        project_id,
        "ticket_run",
        ticket_run_id.as_str(),
        256,
    )?;
    let mut tokens = Vec::new();
    for receipt in receipts {
        let intent = receipt.intent();
        if intent.kind != "prepare_worktrees"
            || intent.expected_revision != Some(plan_record.accepted_revision)
        {
            continue;
        }
        if let Some(token) = store.prepared_worker_launch(
            owner_generation,
            plan_record.accepted_revision,
            node_id,
            &receipt,
            project,
            configuration_digest,
        )? {
            tokens.push(token);
        }
    }
    let token = match tokens.len() {
        0 => return Err("Worker node has no succeeded, matching prepared-worktree receipt".into()),
        1 => tokens.pop().expect("one prepared Worker token exists"),
        _ => {
            return Err(
                "multiple succeeded prepared-worktree receipts match one Worker node".into(),
            );
        }
    };
    if token.project_id() != project_id
        || token.ticket_run_id() != ticket_run_id
        || token.node_id() != node_id
        || token.repository_id() != &node.repository
    {
        return Err("prepared Worker token differs from the selected plan node".into());
    }
    Ok(PreparedWorkerContext {
        plan_record,
        validated_plan,
        node,
        token,
    })
}

fn resolve_prepared_worker_context_for_reservation(
    store: &ConfigStore,
    owner_generation: u64,
    reservation: &crate::launch::AgentLaunchReservation,
    project: &crate::config::ProjectConfig,
    configuration_digest: &Digest,
) -> Result<PreparedWorkerContext, String> {
    let assignment = reservation
        .worker_assignment
        .as_ref()
        .ok_or("Worker reservation has no host-bound work assignment")?;
    let ticket_run_id = reservation
        .ticket_run_id
        .as_ref()
        .ok_or("Worker reservation has no TicketRun")?;
    let plan_record = store
        .accepted_work_plan(
            &reservation.project_id,
            ticket_run_id,
            assignment.accepted_revision,
        )?
        .ok_or("Worker reservation's accepted plan is no longer available")?;
    let validated_plan = plan_record.validate_for(project, configuration_digest)?;
    let node = validated_plan
        .nodes_in_execution_order
        .iter()
        .find(|node| node.id == assignment.node_id)
        .cloned()
        .ok_or("Worker reservation node is absent from its accepted plan")?;
    let receipt = store
        .succeeded_effect_receipt(&assignment.prepare_operation_id)?
        .ok_or("Worker reservation's prepared-worktree effect is no longer succeeded")?;
    let token = store
        .prepared_worker_launch(
            owner_generation,
            assignment.accepted_revision,
            &assignment.node_id,
            &receipt,
            project,
            configuration_digest,
        )?
        .ok_or("Worker reservation's prepared-worktree token is stale")?;
    if token.reservation_binding() != *assignment
        || node.role != Role::Worker
        || node.repository != token.repository_id().clone()
        || !project.repositories.contains(&node.repository)
    {
        return Err("Worker package is outside its persisted accepted-plan assignment".into());
    }
    Ok(PreparedWorkerContext {
        plan_record,
        validated_plan,
        node,
        token,
    })
}

fn worker_assignment_context(
    plan_record: &crate::store::accepted_plans::AcceptedWorkPlanRecord,
    validated_plan: &crate::engine::orchestration::ValidatedPlan,
    node: &crate::engine::orchestration::ValidatedWorkNode,
    worktree_path: &Path,
    branch: &str,
    base_sha: &str,
    commit_mode: crate::domain::types::CommitMode,
    repository_id: &crate::domain::ids::RepositoryId,
) -> Result<String, String> {
    let describe_base = |source: &crate::engine::orchestration::WorkBaseSource,
                         resolved_sha: Option<&str>| {
        match source {
            crate::engine::orchestration::WorkBaseSource::ControllerObservedCommit { commit } => {
                serde_json::json!({"kind":"controller_observed_commit","commit":commit})
            }
            crate::engine::orchestration::WorkBaseSource::PredecessorWorkNodeHead {
                node: predecessor,
            } => serde_json::json!({
                "kind":"predecessor_work_node_head",
                "predecessor_node":predecessor,
                "resolved_base_sha":resolved_sha,
                "instruction":"Use the exact predecessor head selected by the host; do not substitute the trunk base."
            }),
        }
    };
    let execution_order = validated_plan
        .nodes_in_execution_order
        .iter()
        .map(|entry| {
            serde_json::json!({
                "node_id":entry.id,
                "repository_id":entry.repository,
                "role":entry.role,
                "task":entry.task,
                "base":describe_base(&entry.base, None),
                "depends_on":entry.depends_on,
                "required_evidence":entry.required_evidence,
            })
        })
        .collect::<Vec<_>>();
    let assigned_base = describe_base(&node.base, Some(base_sha));
    let value = serde_json::json!({
        "schema_version":1,
        "ticket_run_id":plan_record.ticket_run_id,
        "accepted_revision":plan_record.accepted_revision,
        "accepted_plan_digest":plan_record.plan_digest,
        "plan":plan_record.proposal,
        "validated_execution_order":execution_order,
        "assigned_node":{
            "node_id":node.id,
            "repository_id":node.repository,
            "task":node.task,
            "base":assigned_base,
            "depends_on":node.depends_on,
            "required_evidence":node.required_evidence,
        },
        "prepared_worktree":{
            "path":worktree_path,
            "branch":branch,
            "base_sha":base_sha,
            "commit_mode":commit_mode,
            "repository_id":repository_id,
        },
        "delivery_authority":"The host owns push, pull request creation, merge, and delivery."
    });
    serde_json::to_string(&value).map_err(|error| error.to_string())
}

#[cfg(test)]
mod worker_assignment_context_tests {
    use super::*;
    use crate::domain::ids::{AgentRunId, Digest, ProjectId, TicketRunId};
    use crate::domain::types::{CommitMode, Role};
    use crate::engine::orchestration::{
        PlannedWorkNode, ValidatedPlan, ValidatedWorkNode, WorkBaseSource, WorkNodeId, WorkPlan,
    };
    use std::collections::BTreeMap;

    #[test]
    fn predecessor_base_context_uses_the_host_prepared_sha() {
        let project_id = ProjectId::parse("project-a").unwrap();
        let ticket_run_id = TicketRunId::parse("run-a").unwrap();
        let repository = crate::domain::ids::RepositoryId::parse("repo-a").unwrap();
        let node_id = WorkNodeId::parse("worker-b").unwrap();
        let predecessor = WorkNodeId::parse("worker-a").unwrap();
        let base_sha = "a".repeat(40);
        let node = ValidatedWorkNode {
            id: node_id.clone(),
            repository: repository.clone(),
            base: WorkBaseSource::PredecessorWorkNodeHead {
                node: predecessor.clone(),
            },
            task: "Implement the dependent change".into(),
            depends_on: Vec::new(),
            required_evidence: vec!["tests pass".into()],
            role: Role::Worker,
        };
        let validated = ValidatedPlan {
            ticket_run_id: ticket_run_id.clone(),
            nodes_in_execution_order: vec![node.clone()],
            spawned_investigation_children: 0,
        };
        let plan_record = crate::store::accepted_plans::AcceptedWorkPlanRecord {
            project_id,
            ticket_run_id: ticket_run_id.clone(),
            accepted_revision: 3,
            configuration_digest: Digest::parse("b".repeat(64)).unwrap(),
            plan_digest: Digest::parse("c".repeat(64)).unwrap(),
            proposal: WorkPlan {
                nodes: vec![PlannedWorkNode {
                    id: node_id,
                    repository: repository.clone(),
                    task: node.task.clone(),
                    depends_on: Vec::new(),
                    required_evidence: node.required_evidence.clone(),
                    investigation: false,
                }],
                requested_investigation_children: 0,
            },
            observed_base_shas: BTreeMap::new(),
            source_evidence_id: "evidence-1".into(),
            source_agent_run_id: AgentRunId::parse("coordinator-a").unwrap(),
            source_message_id: "result-1".into(),
            source_result_digest: Digest::parse("d".repeat(64)).unwrap(),
            coordinator_agent_run_id: AgentRunId::parse("coordinator-a").unwrap(),
            coordinator_role_session_id: "ticket_run:run-a:coordinator".into(),
            coordinator_authority_digest: Digest::parse("e".repeat(64)).unwrap(),
        };

        let context = worker_assignment_context(
            &plan_record,
            &validated,
            &node,
            Path::new("/state/worktree"),
            "agent/run-a/worker-b",
            &base_sha,
            CommitMode::Host,
            &repository,
        )
        .unwrap();
        let context: serde_json::Value = serde_json::from_str(&context).unwrap();
        let assigned_base = &context["assigned_node"]["base"];
        assert_eq!(assigned_base["kind"], "predecessor_work_node_head");
        assert_eq!(assigned_base["predecessor_node"], predecessor.as_str());
        assert_eq!(assigned_base["resolved_base_sha"], base_sha);
        assert_eq!(
            assigned_base["instruction"],
            "Use the exact predecessor head selected by the host; do not substitute the trunk base."
        );
        assert_eq!(context["prepared_worktree"]["base_sha"], base_sha);
        assert_eq!(context["prepared_worktree"]["repository_id"], "repo-a");
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
