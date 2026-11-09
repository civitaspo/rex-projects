//! Concrete host adapters assembled for one foreground controller.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

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
use crate::domain::ids::{AdapterId, Digest, RexBlockId, TicketId, TicketNamespace, TicketRunId};
use crate::domain::types::{Role, TicketStatus};
use crate::effects::EffectHandler;
use crate::engine::factory_runtime::{ExternalTicketPage, FactoryRuntimeServices};
use crate::environment::{ChildContext, EnvironmentSnapshot};
use crate::protocol::RequestId;
use crate::runtime_delivery::RuntimeDelivery;
use crate::store::ConfigStore;
use crate::store::scheduler::{ObservedTicket, TicketScanKey};

static REQUEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

pub(crate) mod merge;

struct PreparedWorkerContext {
    plan_record: crate::store::accepted_plans::AcceptedWorkPlanRecord,
    validated_plan: crate::engine::orchestration::ValidatedPlan,
    node: crate::engine::orchestration::ValidatedWorkNode,
    token: crate::store::accepted_plans::PreparedWorkerLaunch,
}

pub(crate) fn worker_publication_identity(
    ticket_run_id: &crate::domain::ids::TicketRunId,
    node_id: &crate::engine::orchestration::WorkNodeId,
    evidence_id: &str,
) -> Result<(String, String), String> {
    use crate::domain::ids::OperationId;

    let operation_id = OperationId::parse(format!("publish-{evidence_id}"))?
        .as_str()
        .to_owned();
    let logical_key = format!("{}:publish:{}:{evidence_id}", ticket_run_id, node_id);
    Ok((operation_id, logical_key))
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
    rex_events: Option<crate::adapters::rex::RexEventStream>,
    rex_inventory_required: bool,
    rex_inventory_last_checked: Option<Instant>,
    rex_event_retry_after: Option<Instant>,
    rex_cli_path: PathBuf,
    rex_search_path: Vec<PathBuf>,
    state_root: PathBuf,
    owner_generation: u64,
    runtime_binary: PathBuf,
    runtime_binary_digest: Digest,
    config_file: PathBuf,
    artifacts: ArtifactStore,
    delivery: RuntimeDelivery,
    mailbox_cursor: Option<String>,
    rex_lifecycle_cursor: usize,
    rex_lifecycle_last_tick: Option<i64>,
    agent_recovery: crate::agent_recovery::AgentRecoveryRuntime,
}

pub(crate) fn operator_plan_ready_for_launch(
    store: &mut ConfigStore,
    owner_generation: u64,
    config: &Config,
    configuration_digest: &Digest,
    run: &crate::store::scheduler::ActiveTicketRun,
) -> Result<bool, String> {
    let current = store
        .active_ticket_runs(owner_generation, 256)?
        .into_iter()
        .find(|candidate| candidate.ticket_run_id == run.ticket_run_id);
    let Some(current) = current else {
        return Ok(false);
    };
    if current.project_id != run.project_id
        || current.revision != run.revision
        || current.phase != crate::engine::reducer::Phase::Operating
        || current.activity != crate::engine::reducer::Activity::Running
    {
        return Ok(false);
    }
    let plan = store
        .operations()?
        .plan_state(&run.project_id, &run.ticket_run_id)?;
    let Some(plan) = plan else {
        return Ok(false);
    };
    Ok(plan.state == "required"
        && crate::engine::host_transitions::validate_persisted_operation_plan(
            store,
            config,
            configuration_digest,
            run,
            &plan,
        )
        .is_ok())
}

pub struct RuntimeExecutable<'a> {
    pub path: &'a Path,
    pub digest: &'a Digest,
}

struct WorkerAssignmentContext<'a> {
    plan_record: &'a crate::store::accepted_plans::AcceptedWorkPlanRecord,
    validated_plan: &'a crate::engine::orchestration::ValidatedPlan,
    node: &'a crate::engine::orchestration::ValidatedWorkNode,
    ticket_revision: u64,
    correction_context: Option<&'a crate::agent_api::WorkerCorrectionContext>,
    worktree_path: &'a Path,
    branch: &'a str,
    base_sha: &'a str,
    expected_head: &'a str,
    host_artifacts: &'a [crate::agent_api::HostArtifactLocator],
    verification: Option<&'a WorkerVerificationAssignment>,
    recovery_authorization: Option<&'a crate::engine::orchestration::WorkerRecoveryAuthorization>,
    retained_host_commit: Option<&'a crate::delivery_runtime::CommitWorkerManifestEffectReceipt>,
    commit_mode: crate::domain::types::CommitMode,
    repository_id: &'a crate::domain::ids::RepositoryId,
}

fn register_merge_effect_handler(
    handlers: &mut Vec<Box<dyn EffectHandler>>,
    source: &Arc<merge::RuntimeMergeEvidenceSource>,
) {
    handlers.push(Box::new(source.effect_handler()));
}

struct WorkerVerificationAssignment {
    publication_revision: u64,
    publication_operation_id: String,
    published_head: String,
}

struct ReviewerPublicationConfig<'a> {
    project: &'a crate::config::ProjectConfig,
    configuration_digest: &'a Digest,
    repositories: &'a BTreeMap<crate::domain::ids::RepositoryId, crate::config::RepositoryConfig>,
}

fn accepted_publication_subject(
    store: &ConfigStore,
    owner_generation: u64,
    project_id: &crate::domain::ids::ProjectId,
    ticket_run_id: &crate::domain::ids::TicketRunId,
    revision: u64,
    config: &ReviewerPublicationConfig<'_>,
) -> Result<crate::delivery_runtime::ImplementationPublicationSetSubject, String> {
    let snapshot = store.accepted_implementation_publication_snapshot(
        owner_generation,
        project_id,
        ticket_run_id,
        revision,
    )?;
    let subject_matches_current_revision = snapshot.publication_revision() == revision
        || snapshot.publication_revision().checked_add(1) == Some(revision)
            && snapshot.verification().is_none()
        || snapshot.verification().is_some_and(|verification| {
            verification.review_revision == revision
                || verification.review_revision.checked_add(1) == Some(revision)
        });
    if !subject_matches_current_revision {
        return Err(
            "review or merge prompt is not at the current accepted publication or verification revision".into(),
        );
    }
    let accepted = snapshot.accepted_plan();
    if accepted.configuration_digest != *config.configuration_digest {
        return Err("accepted work plan belongs to a stale configuration snapshot".into());
    }
    accepted.validate_for(config.project, config.configuration_digest)?;
    let validated = crate::delivery_runtime::validate_implementation_publication_receipt(
        &accepted.proposal,
        snapshot.prepared_receipt(),
        project_id,
        config.repositories,
        snapshot.publication_receipts(),
    )?;
    let mut subject = crate::delivery_runtime::implementation_publication_set_subject(
        &accepted.plan_digest,
        &accepted.proposal,
        &validated,
        snapshot.publication_receipts(),
        snapshot.publication_revision(),
    )?;
    subject.verification = snapshot.verification().map(|verification| {
        crate::delivery_runtime::WorkerVerificationSubject {
            review_revision: verification.review_revision,
            source_evidence_id: verification.source_evidence_id.clone(),
            source_agent_run_id: verification.source_agent_run_id.clone(),
            source_result_digest: verification.source_result_digest.clone(),
            publication_revision: verification.publication_revision,
            publication_operation_id: verification.publication_operation_id.clone(),
            published_head: verification.published_head.as_str().to_owned(),
            work_node_id: verification.work_node_id.clone(),
            repository_id: verification.repository_id.clone(),
            test_receipt_artifacts: verification.test_receipt_artifacts.clone(),
        }
    });
    Ok(subject)
}

fn postmortem_completion_context(
    store: &mut ConfigStore,
    owner_generation: u64,
    run: &crate::store::scheduler::ActiveTicketRun,
    config_digest: &Digest,
) -> Result<crate::agent_api::HostCompletionContext, String> {
    use crate::store::operations::CompletionGate;
    use sha2::Digest as _;

    if run.phase != crate::engine::reducer::Phase::Postmortem
        || store
            .operations()?
            .completion_gate(&run.project_id, &run.ticket_run_id)?
            != CompletionGate::WaitingForPostmortem
    {
        return Err("Postmortem launch is missing a current completed operation gate".into());
    }
    let plan = store
        .operations()?
        .plan_state(&run.project_id, &run.ticket_run_id)?
        .ok_or("Postmortem launch has no persisted operation plan")?;
    if plan.config_digest != *config_digest
        || !matches!(plan.state.as_str(), "succeeded" | "not_required")
        || (plan.state == "not_required" && plan.not_required_reason.is_none())
    {
        return Err(
            "Postmortem operation plan is stale or lacks its explicit completion reason".into(),
        );
    }
    let merge_transition = store
        .ticket_run_transition_evidence(
            owner_generation,
            &run.project_id,
            &run.ticket_run_id,
            run.revision.saturating_sub(256),
            256,
        )?
        .into_iter()
        .find_map(|(revision, evidence)| {
            (evidence["kind"] == "merge_verified").then_some((revision, evidence))
        })
        .ok_or("Postmortem launch lacks persisted host-verified merge evidence")?;
    let source_revision = merge_transition.1["source_revision"]
        .as_u64()
        .ok_or("merge verification transition lacks its source revision")?;
    if source_revision.checked_add(1) != Some(merge_transition.0)
        || merge_transition.0 > run.revision
    {
        return Err(
            "merge verification evidence is outside the current TicketRun revision chain".into(),
        );
    }
    let merge_work = store
        .merge_work_item(
            &run.project_id,
            &run.ticket_run_id,
            crate::domain::ids::Revision(source_revision),
        )?
        .ok_or("merge verification transition has no registered MergeWork receipt")?;
    if merge_transition.1["work_id"].as_str() != Some(merge_work.work_id.as_str())
        || merge_work.configuration_digest != *config_digest
    {
        return Err(
            "Postmortem MergeWork receipt differs from the current Project or accepted plan".into(),
        );
    }
    let succeeded_effects = store.list_succeeded_effect_receipts(
        owner_generation,
        &run.project_id,
        "ticket_run",
        run.ticket_run_id.as_str(),
        256,
    )?;
    let operation_receipts = succeeded_effects
        .iter()
        .filter(|receipt| receipt.intent().kind == "operation")
        .map(|receipt| {
            let intent = receipt.intent();
            Ok(crate::agent_api::HostPublicationReceipt {
                operation_id: intent.operation_id.clone(),
                kind: intent.kind.clone(),
                request_digest: Digest::parse(intent.request_digest.clone())?,
                receipt_digest: Digest::parse(format!(
                    "{:x}",
                    sha2::Sha256::digest(receipt.receipt_json().as_bytes())
                ))?,
                receipt: serde_json::from_str(receipt.receipt_json())
                    .map_err(|error| format!("invalid persisted operation receipt: {error}"))?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let merge_effect = succeeded_effects
        .into_iter()
        .find_map(|receipt| {
            let intent = receipt.intent();
            if intent.kind != "merge" || intent.expected_revision != Some(source_revision) {
                return None;
            }
            let request: crate::merge_executor::MergeStepEffectRequest =
                serde_json::from_str(&intent.request_json).ok()?;
            let verification_step = merge_work.document.procedure.steps.last()?;
            if request.work_id != merge_work.work_id
                || request.awaiting_merge_revision.0 != source_revision
                || request.step_key != verification_step.key
                || request.prior_receipts.len() + 1 != merge_work.document.procedure.steps.len()
            {
                return None;
            }
            let verified: crate::merge_executor::MergeVerificationReceipt =
                serde_json::from_str(receipt.receipt_json()).ok()?;
            if merge_transition.1["merge_commit_sha"].as_str()
                != Some(verified.merge_commit_sha.as_str())
                || merge_transition.1["included_head_sha"].as_str()
                    != Some(verified.included_head_sha.as_str())
                || verified.included_head_sha != merge_work.document.evidence.subject.head_sha
            {
                return None;
            }
            Some((receipt, verified))
        })
        .ok_or("Postmortem launch lacks the exact succeeded MergeWork verification receipt")?;
    let merge_receipt_json: serde_json::Value = serde_json::from_str(merge_effect.0.receipt_json())
        .map_err(|error| format!("persisted merge verification receipt is invalid: {error}"))?;
    let merge_receipt_digest = Digest::parse(format!(
        "{:x}",
        sha2::Sha256::digest(merge_effect.0.receipt_json().as_bytes())
    ))?;
    Ok(crate::agent_api::HostCompletionContext {
        schema_version: 1,
        scope: crate::agent_api::HostCompletionScope {
            project_id: run.project_id.clone(),
            ticket_run_id: run.ticket_run_id.clone(),
            ticket_id: run.ticket_id.clone(),
            ticket_revision: run.revision,
            configuration_digest: config_digest.clone(),
        },
        operation_completion: crate::agent_api::HostOperationCompletion {
            plan_digest: plan.plan_digest,
            state: plan.state,
            not_required_reason: plan.not_required_reason,
            receipts: operation_receipts,
        },
        implementation_publication: crate::agent_api::HostImplementationPublication {
            accepted_plan_digest: merge_work.accepted_plan_digest.clone(),
            configuration_digest: merge_work.configuration_digest.clone(),
            merge_work_id: merge_work.work_id.clone(),
            assessed_revision: merge_work.assessed_revision.0,
            awaiting_merge_revision: merge_work.awaiting_merge_revision.0,
            prepared_receipt_digest: merge_work.prepared_receipt_digest.clone(),
            publication_set_digest: merge_work.publication_set_digest.clone(),
            assessment_id: merge_work.document.assessment_id.clone(),
            assessment_evidence_id: merge_work.document.assessment_evidence_id.clone(),
            assessment_result_digest: merge_work.document.assessment_result_digest.clone(),
            intent_evidence_id: merge_work.document.intent_evidence_id.clone(),
            intent_result_digest: merge_work.document.intent_result_digest.clone(),
            assessment: serde_json::to_value(&merge_work.document.assessment)
                .map_err(|error| error.to_string())?,
            verification: None,
            merge_verification: crate::agent_api::HostMergeVerification {
                work_id: merge_work.work_id,
                configuration_digest: merge_work.configuration_digest,
                accepted_plan_digest: merge_work.accepted_plan_digest,
                assessment_id: merge_work.document.assessment_id,
                source_revision,
                merge_commit_sha: merge_effect.1.merge_commit_sha,
                included_head_sha: merge_effect.1.included_head_sha,
                receipt_digest: merge_receipt_digest,
                receipt: merge_receipt_json,
            },
        },
    })
}

#[cfg(test)]
pub(crate) fn postmortem_completion_context_for_test(
    store: &mut ConfigStore,
    owner_generation: u64,
    run: &crate::store::scheduler::ActiveTicketRun,
    config_digest: &Digest,
) -> Result<crate::agent_api::HostCompletionContext, String> {
    postmortem_completion_context(store, owner_generation, run, config_digest)
}

impl RuntimeServices {
    pub fn new(
        applied_config: &AppliedConfig,
        environment: &EnvironmentSnapshot,
        config_file: &Path,
        state_root: &Path,
        owner_generation: u64,
        rex_identity: &RexIdentity,
        runtime_executable: RuntimeExecutable<'_>,
    ) -> Result<Self, String> {
        let RuntimeExecutable {
            path: runtime_binary,
            digest: runtime_binary_digest,
        } = runtime_executable;
        if owner_generation == 0 || !runtime_binary.is_absolute() {
            return Err(
                "RuntimeServices requires an active owner and absolute runtime binary".into(),
            );
        }
        let config_file = config_file.to_owned();
        let config_dir = config_file
            .parent()
            .ok_or("configuration file has no parent directory")?;
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
        let rex_events = rex.subscribe_events().ok();
        let artifact_root = state_root.join("artifacts");
        let artifacts = ArtifactStore::open(&artifact_root)?;
        let delivery = crate::runtime_delivery::build(
            applied_config,
            state_root,
            &host_environment,
            &environment.metadata().id,
        )?;
        let mut handlers: Vec<Box<dyn EffectHandler>> = Vec::new();
        handlers.push(Box::new(
            delivery
                .shared_effects()
                .commit_worker_manifest_handler(artifacts.clone()),
        ));
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
        let merge_source = Arc::new(merge::RuntimeMergeEvidenceSource::new(
            applied_config.clone(),
            search_path.clone(),
            host_environment.clone(),
        ));
        register_merge_effect_handler(&mut handlers, &merge_source);
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
            let observer =
                crate::human_runtime::DurableHumanSubjectObserver::with_merge_work_review(
                    declarative_root,
                    owner_generation,
                    delivery.shared_effects(),
                    merge_source.clone(),
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
            crate::operations_runtime::OperationEffectHandler::with_host_jobs(
                [applied_config.clone()],
                Duration::from_secs(applied_config.config.runtime.shutdown_grace_seconds),
                delivery.host_jobs(),
                host_environment.clone(),
                environment.metadata().id.clone(),
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
            delivery_effects: delivery.shared_effects(),
        });
        handlers.push(Box::new(crate::stop_owned_runs::StopOwnedRunsHandler::new(
            rex.clone(),
            runtime_binary.to_owned(),
            runtime_binary_digest.clone(),
            Duration::from_secs(applied_config.config.runtime.shutdown_grace_seconds),
        )?));
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
            rex_events,
            rex_inventory_required: true,
            rex_inventory_last_checked: None,
            rex_event_retry_after: None,
            rex_cli_path: rex_binary,
            rex_search_path: search_path,
            state_root: state_root.to_owned(),
            owner_generation,
            runtime_binary: runtime_binary.to_owned(),
            runtime_binary_digest: runtime_binary_digest.clone(),
            config_file,
            artifacts,
            delivery,
            mailbox_cursor: None,
            rex_lifecycle_cursor: 0,
            rex_lifecycle_last_tick: None,
            agent_recovery: crate::agent_recovery::AgentRecoveryRuntime::default(),
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
                if let Err(error) = self.preflight_provider_qualification_deadline(&job) {
                    store.fail_provider_qualification_before_launch(
                        self.owner_generation,
                        &job.request.request_id,
                        "local_preflight_failed",
                    )?;
                    return Err(format!(
                        "provider qualification {} failed before Rex launch: {error}",
                        job.request.request_id
                    ));
                }
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

    fn preflight_provider_qualification_deadline(
        &self,
        job: &crate::store::provider_qualification_runtime::ProviderQualificationJob,
    ) -> Result<u64, String> {
        let profile = self
            .applied_config
            .profiles
            .get(&job.request.profile_id)
            .ok_or("provider qualification profile is absent from applied configuration")?;
        preflight_provider_qualification_job(
            profile,
            job,
            &self.applied_config.digest,
            self.config.runtime.shutdown_grace_seconds,
        )
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
        if crate::store::agent_profile_digest(profile)? != job.request.profile_digest
            || self.applied_config.digest != job.request.config_digest
        {
            return Err("provider qualification profile or config changed after request".into());
        }
        let shutdown_grace_seconds = self.config.runtime.shutdown_grace_seconds.clamp(1, 300);
        let deadline_seconds = crate::run_step::qualification_deadline_seconds(
            profile.turn_timeout_seconds,
            shutdown_grace_seconds,
        )?;
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
        let descriptor_path = root.join("package.json");
        let prompt = format!(
            "This is a disposable provider qualification turn for role {:?}. First invoke the available shell tool to run `{} agent qualification-probe --package {}` exactly as written. Wait for it to succeed. Then produce exactly one minimal, valid structured result permitted by the attached role schema. Use only synthetic data; do not access external systems or perform delivery actions.",
            job.request.role,
            shell_quote(&self.runtime_binary)?,
            shell_quote(&descriptor_path)?,
        );
        let result_schema = crate::roles::result_schema(job.request.role);
        let projection = crate::providers::project_result_schema(&result_schema)?;
        let profile_digest = job.request.profile_digest.clone();
        let instruction_digest = digest_bytes(role_contract.as_bytes())?;
        let wake_digest = digest_bytes(prompt.as_bytes())?;
        let bootstrap_spec = AgentBlockSpec {
            run_id: operation_id.clone(),
            command: PathBuf::from("/usr/bin/env"),
            args: vec![
                "REX_PROJECTS_CONTEXT=agent".into(),
                "REX_PROJECTS_AGENT=1".into(),
                format!("REX_PROJECTS_PROJECT_ID={}", job.request.project_id),
                format!(
                    "REX_PROJECTS_ROLE={}",
                    crate::provider_qualification_run::qualification_role_name(job.request.role)
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
            operation_id: crate::domain::ids::OperationId::parse(operation_id.clone())?,
            role: job.request.role,
            ticket_run_id: None,
            expected_subject_revision: job.request.config_revision,
            attempt: 1,
            run_epoch: 1,
            controller_generation: self.owner_generation,
            workspace: workspace.clone(),
            control_dir,
            worker_assignment: None,
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
            request_digest: job.request_digest.clone(),
            config_revision: job.request.config_revision,
            config_digest: job.request.config_digest.clone(),
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
            marker_probe_path: workspace.join("marker-probe.json"),
            marker_probe_challenge: crate::provider_qualification_run::new_marker_probe_challenge(
            )?,
            runtime_binary_path: self.runtime_binary.clone(),
            runtime_binary_digest: self.runtime_binary_digest.clone(),
            rex_cli_path: self.rex_cli_path.clone(),
            rex_search_path: self.rex_search_path.clone(),
            rex_receipt,
            deadline_seconds,
            shutdown_grace_seconds,
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
        if crate::provider_qualification_run::validate_package(&package, &package_path).is_err()
            || package.workspace_root != root
            || package.descriptor.workspace != root.join("workspace")
            || package.descriptor.control_dir != root.join("control")
            || package.result_path != result_path
            || package.marker_probe_path != root.join("workspace/marker-probe.json")
        {
            return mark_qualification_unknown(store, self.owner_generation, job);
        }
        if package.request_id != job.request.request_id
            || package.request_digest != job.request_digest
            || package.config_revision != job.request.config_revision
            || package.config_digest != job.request.config_digest
            || package.profile_id != job.request.profile_id
            || package.profile_digest != job.request.profile_digest
            || package.runtime_binary_path != self.runtime_binary
            || package.runtime_binary_digest != self.runtime_binary_digest
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
                let observation = match rex.observe_qualification_process(&package.rex_receipt) {
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
        if run.request_id != job.request.request_id
            || run.receipt.run_id != package.descriptor.run_id
            || run.receipt.provider != package.profile.adapter
            || run.receipt.effective_permission_mode
                != package.descriptor.provider_capability.permission_mode
            || run.receipt.schema_projection
                != package.descriptor.provider_capability.schema_projection
        {
            return mark_qualification_unknown(store, self.owner_generation, job);
        }
        // A terminal but unusable qualification may release its slot only after the
        // receipt records confirmed cleanup and a fresh host snapshot proves every
        // captured kernel identity absent. Keep this check ahead of marker/result
        // validation so a safely failed probe can be recorded as Failed.
        let current = match crate::process::inspect_process_table() {
            Ok(current) => current,
            Err(_) => return mark_qualification_unknown(store, self.owner_generation, job),
        };
        let process_tree_absent = matches!(
            run.receipt.cleanup,
            crate::run_step::CleanupState::Confirmed
        ) && !run.receipt.processes.is_empty()
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
        let probe_bytes = match read_private_bounded(&package.marker_probe_path, 16 * 1024) {
            Ok(bytes) => bytes,
            Err(_) => {
                return finish_qualification_failed(
                    store,
                    self.owner_generation,
                    job,
                    &package,
                    &run,
                    rex.as_ref().unwrap_or(&self.rex),
                    "provider marker report is missing",
                );
            }
        };
        let probe: crate::provider_qualification_run::MarkerProbeReport =
            match crate::protocol::parse_unique(&probe_bytes) {
                Ok(probe) => probe,
                Err(_) => {
                    return finish_qualification_failed(
                        store,
                        self.owner_generation,
                        job,
                        &package,
                        &run,
                        rex.as_ref().unwrap_or(&self.rex),
                        "provider marker report is invalid",
                    );
                }
            };
        let verified_markers =
            match crate::provider_qualification_run::verify_marker_probe(&package, &probe) {
                Ok(verified) => verified,
                Err(_) => {
                    return finish_qualification_failed(
                        store,
                        self.owner_generation,
                        job,
                        &package,
                        &run,
                        rex.as_ref().unwrap_or(&self.rex),
                        "provider marker proof did not verify",
                    );
                }
            };
        let probe_process = run.receipt.processes.iter().find(|process| {
            process.pid == probe.tool_pid && process.identity_quality == "kernel_birth_token"
        });
        let descendant_process = run.receipt.processes.iter().find(|process| {
            process.pid == probe.descendant_pid && process.identity_quality == "kernel_birth_token"
        });
        if probe_process.is_none_or(|process| process.parent_pid != probe.tool_parent_pid)
            || descendant_process.is_none_or(|process| process.parent_pid != probe.tool_pid)
            || !run.receipt.processes.iter().any(|process| {
                process.pid == probe.tool_parent_pid
                    && process.identity_quality == "kernel_birth_token"
            })
        {
            return finish_qualification_failed(
                store,
                self.owner_generation,
                job,
                &package,
                &run,
                rex.as_ref().unwrap_or(&self.rex),
                "provider marker process identities did not verify",
            );
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
            return finish_qualification_failed(
                store,
                self.owner_generation,
                job,
                &package,
                &run,
                rex.as_ref().unwrap_or(&self.rex),
                "provider qualification did not produce a valid completed turn",
            );
        }
        let Some(structured_result) = run.structured_result.as_ref() else {
            return finish_qualification_failed(
                store,
                self.owner_generation,
                job,
                &package,
                &run,
                rex.as_ref().unwrap_or(&self.rex),
                "provider structured result is missing",
            );
        };
        let actual_result_digest = digest_bytes(
            &serde_json::to_vec(&Some(structured_result)).map_err(|error| error.to_string())?,
        )?;
        if actual_result_digest != run.result_digest {
            return finish_qualification_failed(
                store,
                self.owner_generation,
                job,
                &package,
                &run,
                rex.as_ref().unwrap_or(&self.rex),
                "provider structured result digest is invalid",
            );
        }
        let Some(profile) = self.applied_config.profiles.get(&job.request.profile_id) else {
            return finish_qualification_failed(
                store,
                self.owner_generation,
                job,
                &package,
                &run,
                rex.as_ref().unwrap_or(&self.rex),
                "provider profile changed during qualification",
            );
        };
        let identity = match crate::run_step::profile_runtime_identity(profile) {
            Ok(identity) => identity,
            Err(_) => {
                return finish_qualification_failed(
                    store,
                    self.owner_generation,
                    job,
                    &package,
                    &run,
                    rex.as_ref().unwrap_or(&self.rex),
                    "provider profile identity is invalid",
                );
            }
        };
        if crate::store::agent_profile_digest(profile)? != job.request.profile_digest
            || identity.executable_digest
                != package.descriptor.provider_capability.executable_digest
        {
            return finish_qualification_failed(
                store,
                self.owner_generation,
                job,
                &package,
                &run,
                rex.as_ref().unwrap_or(&self.rex),
                "provider profile changed during qualification",
            );
        }
        let version = match probe_provider_version(
            profile,
            &self.host_environment,
            &package.descriptor.workspace,
        ) {
            Ok(version) => version,
            Err(_) => {
                return finish_qualification_failed(
                    store,
                    self.owner_generation,
                    job,
                    &package,
                    &run,
                    rex.as_ref().unwrap_or(&self.rex),
                    "provider version probe failed",
                );
            }
        };
        let receipt_json = serde_json::to_vec(&run.receipt).map_err(|error| error.to_string())?;
        let fixture_json =
            serde_json::to_vec(&package.rex_receipt).map_err(|error| error.to_string())?;
        let proof = crate::launch::QualificationProof {
            schema_version: crate::launch::QUALIFICATION_SCHEMA_VERSION,
            probe_id: job.request.request_id.clone(),
            fixture_digest: digest_bytes(&fixture_json)?,
            rex_instance_id: self.rex_identity.instance_id.clone(),
            tool_shell_marker_digest: verified_markers.tool_shell_marker_digest,
            tool_shell_markers_present: verified_markers.tool_shell_markers_present,
            descendant_marker_digest: verified_markers.descendant_marker_digest,
            descendant_markers_present: verified_markers.descendant_markers_present,
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
        if qualification.validate_for_unattended_launch().is_err() {
            return finish_qualification_failed(
                store,
                self.owner_generation,
                job,
                &package,
                &run,
                rex.as_ref().unwrap_or(&self.rex),
                "provider qualification proof is incomplete",
            );
        }
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

fn shell_quote(path: &Path) -> Result<String, String> {
    let path = path
        .to_str()
        .ok_or("provider qualification command path is not valid UTF-8")?;
    Ok(format!("'{}'", path.replace('\'', "'\\''")))
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

fn finish_qualification_failed(
    store: &mut ConfigStore,
    generation: u64,
    job: &crate::store::provider_qualification_runtime::ProviderQualificationJob,
    package: &crate::provider_qualification_run::QualificationRunPackage,
    run: &crate::provider_qualification_run::QualificationRunResult,
    rex: &RexCliTransport,
    reason: &str,
) -> Result<(), String> {
    use crate::store::provider_qualification_runtime::ProviderQualificationJobStatus as Status;
    if !matches!(
        run.receipt.cleanup,
        crate::run_step::CleanupState::Confirmed
    ) || run.receipt.processes.is_empty()
        || !matches!(
            reason,
            "provider marker report is missing"
                | "provider marker report is invalid"
                | "provider marker proof did not verify"
                | "provider marker process identities did not verify"
                | "provider qualification did not produce a valid completed turn"
                | "provider structured result is missing"
                | "provider structured result digest is invalid"
                | "provider profile changed during qualification"
                | "provider profile identity is invalid"
                | "provider version probe failed"
                | "provider qualification proof is incomplete"
        )
    {
        return mark_qualification_unknown(store, generation, job);
    }
    let current = match crate::process::inspect_process_table() {
        Ok(current) => current,
        Err(_) => return mark_qualification_unknown(store, generation, job),
    };
    let identities_absent = run.receipt.processes.iter().all(|observed| {
        observed.identity_quality == "kernel_birth_token"
            && current.iter().all(|process| {
                process.pid != observed.pid || process.start_identity != observed.start_identity
            })
    });
    if !identities_absent
        || rex
            .close_disposable_qualification_session(package.rex_receipt.clone())
            .is_err()
    {
        return mark_qualification_unknown(store, generation, job);
    }
    let failure = serde_json::json!({
        "schema_version": 1,
        "request_id": job.request.request_id,
        "outcome": "failed",
        "reason": reason,
    });
    let failure = serde_json::to_string(&failure).map_err(|error| error.to_string())?;
    let digest = digest_bytes(failure.as_bytes())?;
    store.finish_provider_qualification_job(
        generation,
        &job.request.request_id,
        Status::Failed,
        &failure,
        &digest,
        true,
    )
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
    delivery_effects: Arc<crate::delivery_runtime::RepositoryDeliveryEffects>,
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
        let recorded = store.rex_view_blocks(&reservation.rex_view_id)?;
        if !crate::rex_view_lifecycle::has_block_capacity(
            &recorded,
            &blocks,
            self.applied_config.config.runtime.max_blocks_per_tab,
        ) {
            return Err("Rex view reached its configured block capacity".into());
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
        let profile_digest = crate::store::agent_profile_digest(profile)?;
        if profile_digest != reservation.profile_digest {
            return Err("Agent profile changed after launch reservation".into());
        }
        let operation_recipe = if reservation.role == Role::Operator {
            reservation.operation_recipe_id.clone()
        } else {
            None
        };
        let worker_node = worker_context.as_ref().map(|context| context.node.clone());
        let implementation_publication_subject =
            if matches!(reservation.role, Role::Reviewer | Role::MergeDecision) {
                let run = active_run
                    .as_ref()
                    .ok_or("review or MergeDecision reservation has no TicketRun")?;
                Some(accepted_publication_subject(
                    store,
                    self.owner_generation,
                    &run.project_id,
                    &run.ticket_run_id,
                    run.revision,
                    &ReviewerPublicationConfig {
                        project,
                        configuration_digest: &self.applied_config.digest,
                        repositories: &self.applied_config.config.repositories,
                    },
                )?)
            } else {
                None
            };
        let accepted_plan = if let Some(run) = active_run.as_ref() {
            let accepted = store.latest_accepted_work_plan(&run.project_id, &run.ticket_run_id)?;
            if let Some(plan) = &accepted {
                plan.validate_for(project, &self.applied_config.digest)?;
            }
            accepted
        } else {
            None
        };
        let worker_recovery_authorization = if let Some(context) = &worker_context {
            let authorization = reservation.wake_snapshot.worker_recovery_authorization()?;
            validate_worker_recovery_assignment(
                authorization.as_ref(),
                &context.plan_record,
                &context.node,
                context.token.expected_head(),
                context.token.ticket_run_id(),
                reservation
                    .ticket_revision
                    .map(|revision| revision.0)
                    .unwrap_or(0),
            )?;
            if let Some(authorization) = &authorization
                && self
                    .delivery_effects
                    .observe_local_head_at(context.token.worktree_path())?
                    != authorization.expected_head
            {
                return Err("Worker recovery worktree changed after authorization".into());
            }
            if authorization.is_none() && context.token.expected_head() != context.token.base_sha()
            {
                ensure_worker_worktree_at_expected_head(
                    context.token.worktree_path(),
                    context.token.expected_head(),
                    |path| self.delivery_effects.observe_local_head_at(path),
                    "Worker rework worktree changed after publication authorization",
                )?;
            }
            authorization
        } else {
            None
        };
        let worker_verification = match (&worker_context, &worker_node) {
            (Some(context), Some(node)) => worker_verification_assignment(
                store,
                self.owner_generation,
                &context.token,
                node,
                worker_recovery_authorization.as_ref(),
            )?,
            _ => None,
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
                recovery_summary: match (&active_run, &accepted_plan) {
                    (Some(run), Some(plan)) if reservation.role == Role::Coordinator => {
                        coordinator_worker_recovery_summary(
                            store,
                            owner_generation,
                            run,
                            plan,
                            project,
                            &self.applied_config.digest,
                            &self.delivery_effects,
                        )?
                    }
                    _ => None,
                },
                accepted_plan: match (&worker_context, &accepted_plan) {
                    (Some(context), _) => Some(worker_assignment_for_reservation(
                        store,
                        reservation,
                        context,
                        worker_verification.as_ref(),
                        worker_recovery_authorization.as_ref(),
                    )?),
                    (None, Some(plan)) => Some(
                        serde_json::to_string(&plan.proposal).map_err(|error| error.to_string())?,
                    ),
                    (None, None) => None,
                },
                accepted_plan_digest: accepted_plan
                    .as_ref()
                    .filter(|_| worker_context.is_none())
                    .map(|plan| plan.plan_digest.clone()),
                implementation_publication_subject,
                completion_context: if reservation.role == Role::Postmortem {
                    Some(
                        serde_json::to_value(postmortem_completion_context(
                            store,
                            owner_generation,
                            active_run
                                .as_ref()
                                .ok_or("Postmortem reservation has no TicketRun")?,
                            &self.applied_config.digest,
                        )?)
                        .map_err(|error| error.to_string())?,
                    )
                } else {
                    None
                },
                previous_decisions: crate::roles::worker_recovery_decisions(
                    worker_recovery_authorization.as_ref(),
                ),
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
            &self.runtime_binary,
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
            worker_assignment: reservation.worker_assignment.clone(),
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
            schema_version: 2,
            execution_slot_epoch: reservation.project_epoch,
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
            supervision_mode: Some(
                crate::run_step_package::RunStepSupervisionMode::AnchoredSupervisor,
            ),
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
        process_one_registered_agent_request(
            store,
            owner_generation,
            now_unix,
            &self.artifacts,
            &self.applied_config.profiles,
            &mut self.mailbox_cursor,
        )
    }

    fn process_one_merge_human_response(
        &mut self,
        store: &mut ConfigStore,
        owner_generation: u64,
        now_unix: i64,
    ) -> Result<bool, String> {
        let declarative_root = self
            .host_environment
            .get(std::ffi::OsStr::new("XDG_CONFIG_HOME"))
            .map(PathBuf::from)
            .or_else(|| {
                self.host_environment
                    .get(std::ffi::OsStr::new("HOME"))
                    .map(|home| PathBuf::from(home).join(".config"))
            })
            .ok_or("captured environment has neither XDG_CONFIG_HOME nor HOME")?
            .join("rex-projects");
        let source = Arc::new(merge::RuntimeMergeEvidenceSource::new(
            self.applied_config.clone(),
            self.rex_search_path.clone(),
            self.host_environment.clone(),
        ));
        let observer = crate::human_runtime::DurableHumanSubjectObserver::with_merge_work_review(
            declarative_root,
            owner_generation,
            self.delivery.shared_effects(),
            source,
        )?;
        let now =
            u64::try_from(now_unix).map_err(|_| "controller clock is before the Unix epoch")?;
        for queued in store.pending_human_decisions(owner_generation, 64)? {
            if queued.request.purpose != crate::human_runtime::HumanPurpose::TicketReview {
                continue;
            }
            match crate::human_runtime::HumanSubjectObserver::observe_current_subject(
                &observer,
                store,
                &queued.request,
            )? {
                crate::human_runtime::HumanSubjectObservation::Current(subject) => {
                    store.process_human_decision(
                        owner_generation,
                        &queued.intent.response_id,
                        &subject,
                        now,
                    )?;
                }
                crate::human_runtime::HumanSubjectObservation::Gone(reason) => {
                    store.reject_human_decision_stale(
                        owner_generation,
                        &queued.intent.response_id,
                        &reason,
                        now,
                    )?;
                }
                crate::human_runtime::HumanSubjectObservation::TemporarilyUnavailable => continue,
            }
            return Ok(true);
        }
        Ok(false)
    }

    fn recover_agents(
        &mut self,
        store: &mut ConfigStore,
        owner_generation: u64,
        now_unix: i64,
    ) -> Result<crate::agent_recovery::AgentRecoveryReport, String> {
        crate::engine::factory_runtime::FactoryRuntimeObservationServices::recover_agents(
            self,
            store,
            owner_generation,
            now_unix,
        )
    }

    fn maintain_rex_views(
        &mut self,
        store: &mut ConfigStore,
        owner_generation: u64,
        now_unix: i64,
        config: &Config,
    ) -> Result<(), String> {
        if self
            .rex_lifecycle_last_tick
            .is_some_and(|previous| now_unix.saturating_sub(previous) < 1)
        {
            return Ok(());
        }
        self.rex_lifecycle_last_tick = Some(now_unix);
        let projects = config.projects.keys().cloned().collect::<Vec<_>>();
        let views = crate::rex_view_lifecycle::project_views(
            store,
            &projects,
            &self.rex_identity.instance_id,
            &self.rex_identity.session_id,
        )?;
        if views.is_empty() {
            return Ok(());
        }
        let index = self.rex_lifecycle_cursor % views.len();
        self.rex_lifecycle_cursor = self.rex_lifecycle_cursor.wrapping_add(1);
        let retention_seconds = config
            .runtime
            .completed_ticket_tab_retention_hours
            .checked_mul(60 * 60)
            .ok_or("ticket tab retention exceeds supported range")?;
        let anchor_run_id = store
            .rex_view_anchor(&views[index].view.view_id)?
            .map(|anchor| anchor.run_id)
            .unwrap_or_else(|| match views[index].view.kind {
                crate::launch::RexViewKind::Ticket => format!(
                    "ticket-{}-view-{}",
                    views[index].view.ticket_id.as_deref().unwrap_or_default(),
                    views[index].view.view_epoch
                ),
                crate::launch::RexViewKind::Supervisor => format!(
                    "project-{}-view-{}",
                    views[index].view.project_id, views[index].view.view_epoch
                ),
            });
        let anchor_spec = self.view_anchor_spec(anchor_run_id);
        crate::rex_view_lifecycle::maintain_view(
            store,
            owner_generation,
            now_unix.max(0) as u64,
            &views[index],
            &self.rex,
            crate::rex_view_lifecycle::RexViewLifecyclePolicy {
                max_blocks_per_tab: config.runtime.max_blocks_per_tab,
                completed_blocks_to_keep: config.runtime.completed_blocks_to_keep,
                completed_ticket_tab_retention_seconds: retention_seconds,
            },
            Some(&anchor_spec),
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

    fn read_verified_artifact(
        &self,
        artifact: &crate::store::artifact_registry::VerifiedArtifact,
    ) -> Result<Vec<u8>, String> {
        artifact.read_bytes(&self.artifacts)
    }

    fn observe_base_heads(
        &mut self,
    ) -> Result<BTreeMap<crate::domain::ids::RepositoryId, String>, String> {
        self.delivery.observe_base_heads()
    }

    fn observe_worker_recovery_head(
        &self,
        candidate: &crate::engine::orchestration::WorkerRecoveryCandidate,
    ) -> Result<Option<String>, String> {
        self.delivery
            .effects()
            .observe_local_head_at(&candidate.worktree_path)
            .map(Some)
    }

    fn verify_worker_verification_worktree(
        &self,
        store: &mut ConfigStore,
        project_id: &crate::domain::ids::ProjectId,
        ticket_run_id: &TicketRunId,
        assignment: &crate::launch::WorkerLaunchBinding,
    ) -> Result<(), String> {
        crate::parent_artifacts::verify_worker_worktree_with_host_artifacts(
            store,
            &self.artifacts,
            project_id,
            ticket_run_id,
            assignment,
            |path, expected_head, host_artifacts| {
                self.delivery.effects().verify_clean_published_worktree_at(
                    path,
                    expected_head,
                    host_artifacts,
                )
            },
        )
    }

    fn configuration_digest(&self) -> &Digest {
        &self.configuration_digest
    }

    fn human_evidence_documents(
        &mut self,
        store: &mut ConfigStore,
        result: &crate::store::agent_results::IngestedAgentResult,
    ) -> Result<Vec<crate::human_runtime::HumanEvidenceDocument>, String> {
        let references = &result.validated.claimed_artifact_refs;
        let total = references.iter().try_fold(0u64, |total, reference| {
            total
                .checked_add(reference.bytes)
                .ok_or_else(|| "human evidence byte count overflow".to_owned())
        })?;
        if total > crate::human_runtime::MAX_HUMAN_REQUEST_BYTES as u64 {
            return Err("Coordinator human evidence exceeds the review request size limit".into());
        }
        let authority = store
            .agent_launch_authority(&result.validated.binding.agent_run_id)?
            .ok_or("human evidence source Agent launch authority is missing")?;
        references
            .iter()
            .map(|reference| {
                let verified = store
                    .lookup_verified_artifact(&self.artifacts, &authority, reference)?
                    .ok_or_else(|| "human evidence artifact is no longer registered".to_owned())?;
                let bytes = verified.read_bytes(&self.artifacts)?;
                Ok(crate::human_runtime::HumanEvidenceDocument {
                    reference: reference.clone(),
                    bytes,
                })
            })
            .collect()
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
        config: &Config,
        run: &crate::store::scheduler::ActiveTicketRun,
        result: &crate::store::agent_results::IngestedAgentResult,
        effect_revision: u64,
    ) -> Result<Option<crate::store::EffectIntent>, String> {
        use crate::delivery_runtime::{
            PublishImplementationEffectPayload, PullRequestContent, WorkerDeliveryCommit,
            canonical_delivery_payload,
        };
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
        let mut prepared = None;
        for prepared_receipt in succeeded
            .iter()
            .filter(|receipt| receipt.intent().kind == "prepare_worktrees")
        {
            if let Some(launch) = store.prepared_worker_launch(
                owner_generation,
                plan.accepted_revision,
                &node_id,
                prepared_receipt,
                project_config,
                &self.configuration_digest,
            )? {
                prepared = Some(launch);
                break;
            }
        }
        let prepared = prepared.ok_or("Worker launch authority is no longer valid")?;
        if prepared.project_id() != &run.project_id
            || prepared.ticket_run_id() != ticket_run_id
            || prepared.ticket_revision() != run.revision
            || prepared.repository_id() != &node.repository
            || prepared.configuration_digest() != &binding.config_digest
        {
            return Err("Worker result does not match its prepared node authority".into());
        }
        let reservation = store
            .agent_launch_reservation_for_run(&binding.agent_run_id)?
            .ok_or("Worker result has no immutable launch reservation")?;
        if reservation.worker_assignment.as_ref() != Some(&prepared.reservation_binding()) {
            return Err("Worker result reservation differs from its prepared assignment".into());
        }
        let recovery_authorization = reservation.wake_snapshot.worker_recovery_authorization()?;
        let recovery_head = recovery_authorization
            .as_ref()
            .map(|authorization| authorization.expected_head.as_str())
            .unwrap_or_else(|| prepared.expected_head());
        if claimed.change_references.len() != 1 {
            return Err(
                "Worker result must contain exactly one change for its assigned node".into(),
            );
        }
        let change = crate::engine::orchestration::change_reference_for_assignment(
            &claimed.change_references,
            &node.repository,
            &node_id,
            prepared.worktree_path(),
        )?;
        let retained_commit = retained_host_commit(
            store,
            &binding.project_id,
            &binding.config_digest,
            recovery_authorization.as_ref(),
        )?;
        let reuse_retained_commit = retained_commit.as_ref().is_some_and(|receipt| {
            change.host_commit_operation_id.as_deref() == Some(receipt.commit.operation_id.as_str())
        });
        let expected_head = if reuse_retained_commit {
            retained_commit
                .as_ref()
                .expect("matched retained commit")
                .commit
                .expected_head
                .as_str()
        } else {
            recovery_head
        };
        if change.previous_head.as_str() != expected_head {
            return Err("Worker change does not start at its host-authorized expected HEAD".into());
        }
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
                    previous_accepted_head: expected_head.to_owned(),
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
                let operation_id = crate::domain::ids::OperationId::parse(
                    change
                        .host_commit_operation_id
                        .clone()
                        .ok_or("host-commit Worker result omits repository.commit operation ID")?,
                )?;
                let committed_effect = store
                    .succeeded_effect_receipt(operation_id.as_str())?
                    .ok_or("Worker repository.commit operation has no durable succeeded receipt")?;
                if committed_effect.intent().kind
                    != crate::engine::reducer::effect_name(
                        &crate::engine::reducer::EffectKind::CommitWorkerManifest,
                    )
                    || committed_effect.intent().project_id != binding.project_id
                    || committed_effect.intent().subject_id != ticket_run_id.as_str()
                {
                    return Err(
                        "Worker repository.commit receipt has the wrong durable scope".into(),
                    );
                }
                let receipt: crate::delivery_runtime::CommitWorkerManifestEffectReceipt =
                    crate::protocol::parse_unique(committed_effect.receipt_json().as_bytes())?;
                let source = *source.first().expect("one Change artifact");
                let (expected_worker, manifest_matches) = if reuse_retained_commit {
                    let recovery = recovery_authorization
                        .as_ref()
                        .expect("retained commit requires recovery authority");
                    if retained_commit.as_ref() != Some(&receipt) {
                        return Err("retained commit changed after recovery validation".into());
                    }
                    (
                        &recovery.prior_worker_agent_run_id,
                        source.kind == receipt.manifest_artifact.kind
                            && source.schema_version == receipt.manifest_artifact.schema_version
                            && source.bytes == receipt.manifest_artifact.bytes
                            && source.digest == receipt.manifest_artifact.digest,
                    )
                } else {
                    (&binding.agent_run_id, source == &receipt.manifest_artifact)
                };
                if receipt.agent_run_id != *expected_worker
                    || receipt.message_id.trim().is_empty()
                    || receipt.ticket_run_id != *ticket_run_id
                    || receipt.work_node_id != node_id
                    || receipt.repository_id != node.repository
                    || receipt.base_sha != prepared.base_sha()
                    || !manifest_matches
                    || receipt.commit.operation_id != operation_id
                    || receipt.commit.expected_head != expected_head
                    || receipt.commit.observed_head != change.branch_head.as_str()
                    || receipt.commit.observed_head == receipt.commit.expected_head
                    || change.commit_shas.as_slice() != [change.branch_head.clone()]
                {
                    return Err("Worker result does not match its exact host commit receipt".into());
                }
                WorkerDeliveryCommit::HostReceipt {
                    operation_id,
                    expected_head: expected_head.to_owned(),
                    worker_reported_head: change.branch_head.as_str().to_owned(),
                    receipt: Box::new(receipt),
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
        let title = self
            .delivery
            .effects()
            .observe_commit_subject_at(prepared.worktree_path(), change.branch_head.as_str())?;
        if title.is_empty() || title.len() > 200 {
            return Err("observed Worker commit has an invalid pull request title".into());
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
                title,
                body,
                update_target: None,
            },
        };
        let (request_json, request_digest) = canonical_delivery_payload(&payload)?;
        let (operation_id, logical_key) =
            worker_publication_identity(ticket_run_id, &node_id, result.receipt.evidence_id())?;
        Ok(Some(crate::store::EffectIntent {
            project_id: run.project_id.clone(),
            subject_type: "ticket_run".into(),
            subject_id: run.ticket_run_id.as_str().into(),
            operation_id,
            logical_key,
            kind: crate::engine::reducer::effect_name(
                &crate::engine::reducer::EffectKind::PublishImplementation,
            )
            .into(),
            request_json,
            request_digest,
            expected_revision: Some(effect_revision),
        }))
    }

    fn observe_merge_assessment(
        &mut self,
        subject: &crate::delivery_runtime::ImplementationPublicationSetSubject,
        result: &crate::store::agent_results::IngestedAgentResult,
    ) -> Result<Option<crate::merge_runtime::MergeEvidenceObservation>, String> {
        if result.validated.binding.config_digest != self.configuration_digest {
            return Err("MergeAssessment source belongs to a stale runtime configuration".into());
        }
        let source = merge::RuntimeMergeEvidenceSource::new(
            self.applied_config.clone(),
            self.rex_search_path.clone(),
            self.host_environment.clone(),
        );
        source
            .observe_publication_subject(subject, result)
            .map(Some)
    }

    fn prepare_merge_body_proposal(
        &self,
        project_id: &crate::domain::ids::ProjectId,
        subject: &crate::delivery_runtime::ImplementationPublicationSetSubject,
        accepted_plan: &crate::engine::orchestration::WorkPlan,
        assessment_id: &Digest,
        observation: &crate::merge_runtime::MergeEvidenceObservation,
    ) -> Result<crate::store::merge_work::PreparedMergeBodyProposal, String> {
        merge::RuntimeMergeEvidenceSource::new(
            self.applied_config.clone(),
            self.rex_search_path.clone(),
            self.host_environment.clone(),
        )
        .prepare_body_proposal(
            project_id,
            subject,
            accepted_plan,
            assessment_id,
            observation,
        )
    }

    fn resolve_merge_work_document(
        &mut self,
        subject: &crate::delivery_runtime::ImplementationPublicationSetSubject,
        accepted_plan: &crate::engine::orchestration::WorkPlan,
        assessment: &crate::store::merge_work::TrustedMergeAssessment,
        intent: &crate::engine::orchestration::MergeIntentPayload,
        result: &crate::store::agent_results::IngestedAgentResult,
    ) -> Result<crate::store::merge_work::MergeWorkDocument, String> {
        merge::RuntimeMergeEvidenceSource::new(
            self.applied_config.clone(),
            self.rex_search_path.clone(),
            self.host_environment.clone(),
        )
        .prepare_merge_work_document(subject, accepted_plan, assessment, intent, result)
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
        crate::engine::factory_runtime::FactoryRuntimeObservationServices::observe_publications(
            self,
            store,
            owner_generation,
            now_unix,
        )
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
        let profile_digest = crate::store::agent_profile_digest(profile)?;
        let Some(qualification) = exact_profile_qualification(
            store,
            &candidate.project_id,
            profile_id,
            profile,
            &profile_digest,
        )?
        else {
            eprintln!(
                "rex-projects: parked Supervisor launch for Project {}: profile {} has no exact verified provider qualification; run `rex-projects provider qualify --project {} --role supervisor`",
                candidate.project_id, profile_id, candidate.project_id
            );
            return Ok(false);
        };
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
        if !self.view_has_block_capacity(store, &view)? {
            return Ok(false);
        }
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
            None,
        )?;
        let wake_snapshot = crate::agent_api::AgentWakeSnapshot {
            schema_version: 1,
            project_id: candidate.project_id.clone(),
            role_session_id: candidate.role_session_id.clone(),
            agent_run_id: run_id.as_str().to_owned(),
            digest: Digest::parse("0".repeat(64))?,
            inputs: wake_items,

            worker_correction_context: None,
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
                accepted_plan_digest: None,
                implementation_publication_subject: None,
                completion_context: None,
                previous_decisions: Vec::new(),
                required_evidence: Vec::new(),
                stop_conditions: Vec::new(),
                assigned_commit_mode: None,
            },
            &self.runtime_binary,
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
        let mailbox_expires_at_unix = u64::try_from(
            now_unix
                .checked_add(profile.turn_timeout_seconds as i64)
                .and_then(|value| value.checked_add(86_400))
                .ok_or("Agent mailbox expiration overflow")?,
        )
        .map_err(|_| "Agent mailbox expiration is negative")?;
        let mailbox_max_request_bytes = 1_048_576_u64;
        let mailbox_max_pending_requests = 32_u32;
        let mailbox_capability_digest = mailbox_capability_digest(
            &run_id,
            mailbox_expires_at_unix,
            mailbox_max_request_bytes,
            mailbox_max_pending_requests,
        )?;
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
            mailbox_capability_digest,
            mailbox_expires_at_unix,
            mailbox_max_request_bytes,
            mailbox_max_pending_requests,
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

pub(crate) fn process_one_registered_agent_request(
    store: &mut ConfigStore,
    owner_generation: u64,
    now_unix: i64,
    artifacts: &ArtifactStore,
    profiles: &BTreeMap<crate::domain::ids::ProfileId, crate::config::Profile>,
    mailbox_cursor: &mut Option<String>,
) -> Result<bool, String> {
    let mailboxes = store.registered_agent_mailboxes(owner_generation)?;
    if mailboxes.is_empty() {
        return Ok(false);
    }
    let start = mailbox_cursor
        .as_ref()
        .and_then(|cursor| {
            mailboxes
                .iter()
                .position(|entry| &entry.agent_run_id > cursor)
        })
        .unwrap_or(0);
    for offset in 0..mailboxes.len() {
        let registration = &mailboxes[(start + offset) % mailboxes.len()];
        *mailbox_cursor = Some(registration.agent_run_id.clone());
        match store.process_one_agent_mailbox_request(
            owner_generation,
            &registration.agent_run_id,
            now_unix,
            artifacts,
            profiles,
        ) {
            Ok(true) => return Ok(true),
            Ok(false) => {}
            Err(crate::store::agent_mailbox::AgentMailboxProcessingError::LocalMailbox(error)) => {
                eprintln!(
                    "rex-projects: AgentRun {} mailbox needs attention: {error}",
                    registration.agent_run_id
                );
            }
            Err(crate::store::agent_mailbox::AgentMailboxProcessingError::Authority(error)) => {
                return Err(format!(
                    "AgentRun {} mailbox authority/storage failure: {error}",
                    registration.agent_run_id
                ));
            }
        }
    }
    Ok(false)
}

impl crate::engine::factory_runtime::FactoryRuntimeObservationServices for RuntimeServices {
    fn recover_agents(
        &mut self,
        store: &mut ConfigStore,
        owner_generation: u64,
        now_unix: i64,
    ) -> Result<crate::agent_recovery::AgentRecoveryReport, String> {
        let now = Instant::now();
        if self
            .rex_events
            .as_mut()
            .is_some_and(|stream| !stream.is_alive().unwrap_or(false))
        {
            self.rex_events = None;
            self.rex_inventory_required = true;
            self.rex_inventory_last_checked = None;
            self.rex_event_retry_after = Some(now + Duration::from_secs(5));
        }
        if self.rex_events.is_none()
            && self
                .rex_event_retry_after
                .is_none_or(|retry_after| now >= retry_after)
        {
            match self.rex.subscribe_events() {
                Ok(events) => {
                    self.rex_events = Some(events);
                    self.rex_event_retry_after = None;
                    self.rex_inventory_required = true;
                    self.rex_inventory_last_checked = None;
                }
                Err(_) => {
                    self.rex_event_retry_after = Some(now + Duration::from_secs(5));
                }
            }
        }
        if let Some(events) = &self.rex_events {
            for signal in events.drain(128) {
                if let crate::adapters::rex::RexEventSignal::BlockClosed {
                    session_id,
                    block_id,
                } = &signal
                    && session_id == &self.rex_identity.session_id
                {
                    store.record_agent_block_close_event(
                        owner_generation,
                        &self.rex_identity.instance_id,
                        session_id,
                        block_id,
                        now_unix,
                    )?;
                }
                if crate::adapters::rex::rex_event_requires_inventory(
                    &signal,
                    &self.rex_identity.session_id,
                ) {
                    self.rex_inventory_required = true;
                    self.rex_inventory_last_checked = None;
                }
            }
        }
        if self.rex_inventory_required
            && self
                .rex_inventory_last_checked
                .is_none_or(|checked| now.duration_since(checked) >= Duration::from_secs(5))
        {
            // This pinned inventory is only a wake/reconciliation input. The recovery
            // runtime still verifies each persisted AgentRun and its process identities.
            if self.rex.list_owned_windows_and_blocks().is_ok() {
                self.rex_inventory_required = false;
                self.rex_inventory_last_checked = Some(now);
            } else {
                // Per-run recovery below independently retains every uncertain slot. Keep
                // the inventory pending and retry at a bounded cadence without stopping the
                // foreground controller.
                self.rex_inventory_last_checked = Some(now);
            }
        }
        if self
            .rex_inventory_last_checked
            .is_some_and(|checked| now.duration_since(checked) >= Duration::from_secs(5))
        {
            self.rex_inventory_required = true;
        }
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
        self.agent_recovery
            .tick(store, owner_generation, &self.rex, &policy)
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
}

impl RuntimeServices {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn wake_items_with_staged_artifacts(
        artifact_store: &ArtifactStore,
        store: &mut ConfigStore,
        owner_generation: u64,
        project_id: &crate::domain::ids::ProjectId,
        config_revision: u64,
        config_digest: &Digest,
        workspace: &Path,
        wake_inputs: Vec<crate::store::agent_runtime::PendingRoleWakeInput>,
        completion_context: Option<&crate::agent_api::HostCompletionContext>,
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
            } else if input.source_type == "worker_recovery_authorization" {
                let authorization: crate::engine::orchestration::WorkerRecoveryAuthorization =
                    serde_json::from_value(
                        input
                            .payload_json
                            .get("authorization")
                            .cloned()
                            .ok_or("Worker recovery wake has no host authorization")?,
                    )
                    .map_err(|error| format!("invalid Worker recovery authorization: {error}"))?;
                authorization.validate()?;
                if input.source_id != authorization.prior_worker_result_evidence_id
                    || input.source_revision != authorization.ticket_revision
                {
                    return Err(
                        "Worker recovery wake source differs from its host authorization".into(),
                    );
                }
                if !authorization.prior_artifact_refs.is_empty() {
                    let authority = store
                        .agent_launch_authority(&authorization.prior_worker_agent_run_id)?
                        .ok_or("Worker recovery prior run lost its launch authority")?;
                    if authority.project_id != *project_id
                        || authority.ticket_run_id.as_ref() != Some(&authorization.ticket_run_id)
                        || authority.role != Role::Worker
                    {
                        return Err(
                            "Worker recovery artifacts belong to a different prior Worker".into(),
                        );
                    }
                    host_artifacts = crate::parent_artifacts::stage_verified_parent_artifacts(
                        store,
                        artifact_store,
                        &authority,
                        &authorization.prior_worker_result_evidence_id,
                        project_id,
                        config_revision,
                        config_digest,
                        workspace,
                        &authorization.prior_artifact_refs,
                    )
                    .map_err(|error| {
                        format!("cannot stage prior Worker recovery artifacts: {error}")
                    })?;
                }
            } else if input.source_type == "ticket_run_transition"
                && input.payload_json["target"] == "reviewer"
            {
                let ticket_run_id = crate::domain::ids::TicketRunId::parse(
                    input.payload_json["ticket_run_id"]
                        .as_str()
                        .ok_or("Reviewer transition wake has no TicketRun ID")?
                        .to_owned(),
                )?;
                if input.payload_json["revision"].as_u64() != Some(input.source_revision)
                    || input.payload_json["message_id"].as_str() != Some(input.source_id.as_str())
                {
                    return Err(
                        "Reviewer transition wake differs from its durable source identity".into(),
                    );
                }
                let snapshot = store.accepted_implementation_publication_snapshot(
                    owner_generation,
                    project_id,
                    &ticket_run_id,
                    input.source_revision,
                )?;
                if snapshot.publication_revision() != input.source_revision
                    && snapshot.verification().is_none_or(|verification| {
                        verification.review_revision != input.source_revision
                    })
                {
                    return Err(
                        "Reviewer wake does not name the current publication or verification subject".into(),
                    );
                }
                for publication in snapshot.publication_receipts() {
                    let source = store.validated_worker_publication_source_for_node(
                        artifact_store,
                        owner_generation,
                        project_id,
                        &ticket_run_id,
                        publication,
                    )?;
                    let references = source
                        .validated
                        .claimed_artifact_refs
                        .iter()
                        .filter(|reference| {
                            matches!(
                                reference.kind,
                                crate::engine::orchestration::RoleArtifactKind::TestReceipt
                                    | crate::engine::orchestration::RoleArtifactKind::General
                            )
                        })
                        .cloned()
                        .collect::<Vec<_>>();
                    if references.is_empty() {
                        continue;
                    }
                    let source_authority = store
                        .agent_launch_authority(&source.validated.binding.agent_run_id)?
                        .ok_or("published Worker check evidence lost its launch authority")?;
                    let staged = crate::parent_artifacts::stage_verified_parent_artifacts(
                        store,
                        artifact_store,
                        &source_authority,
                        source.receipt.evidence_id(),
                        project_id,
                        config_revision,
                        config_digest,
                        workspace,
                        &references,
                    )
                    .map_err(|error| {
                        format!(
                            "cannot stage published Worker check evidence for Reviewer: {error}"
                        )
                    })?;
                    host_artifacts.extend(staged);
                }
                if let Some(verification) = snapshot.verification() {
                    let source = store.validated_worker_verification_source(
                        artifact_store,
                        owner_generation,
                        project_id,
                        &ticket_run_id,
                        verification,
                    )?;
                    let source_authority = store
                        .agent_launch_authority(&source.validated.binding.agent_run_id)?
                        .ok_or("verified Worker check evidence lost its launch authority")?;
                    let staged = crate::parent_artifacts::stage_verified_parent_artifacts(
                        store,
                        artifact_store,
                        &source_authority,
                        source.receipt.evidence_id(),
                        project_id,
                        config_revision,
                        config_digest,
                        workspace,
                        &verification.test_receipt_artifacts,
                    )
                    .map_err(|error| {
                        format!("cannot stage verification-only Worker TestReceipt evidence for Reviewer: {error}")
                    })?;
                    host_artifacts.extend(staged);
                }
            }
            let host_artifact_source_evidence_ids =
                if input.source_type == "ticket_run_transition" && !host_artifacts.is_empty() {
                    let evidence_ids = host_artifacts
                        .iter()
                        .map(|artifact| artifact.source_evidence_id.clone())
                        .collect::<std::collections::BTreeSet<_>>();
                    evidence_ids.into_iter().collect()
                } else {
                    Vec::new()
                };
            let is_postmortem_transition = input.source_type == "ticket_run_transition"
                && input.payload_json["target"] == "postmortem";
            items.push(crate::agent_api::AgentWakeItem {
                wake_input_id: input.wake_input_id,
                source_type: input.source_type,
                source_id: input.source_id,
                source_revision: input.source_revision,
                priority: input.priority,
                payload_json: input.payload_json,
                host_artifact_source_evidence_ids,
                host_artifacts,
                host_completion_context: if is_postmortem_transition {
                    completion_context.cloned()
                } else {
                    None
                },
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
            || !role_allowed_for_run(candidate.role, active_run.phase, active_run.activity)
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
        if candidate.role == Role::Operator
            && !operator_plan_ready_for_launch(
                store,
                self.owner_generation,
                config,
                &self.configuration_digest,
                &active_run,
            )?
        {
            return Ok(false);
        }
        if candidate.role == Role::Postmortem && self.applied_config.config.knowledge.is_none() {
            crate::engine::host_transitions::block_run_for_host_readiness(
                store,
                self.owner_generation,
                &active_run,
                "postmortem_capability_unavailable",
                "Postmortem publication requires a configured knowledge root and publisher",
            )?;
            return Ok(false);
        }
        if candidate.role == Role::Coordinator
            && store.ticket_run_has_unsettled_implementation_publication(
                &candidate.project_id,
                ticket_run_id,
            )?
        {
            return Ok(false);
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
        let profile_digest = crate::store::agent_profile_digest(&profile)?;
        let Some(qualification) = exact_profile_qualification(
            store,
            &candidate.project_id,
            &profile_id,
            &profile,
            &profile_digest,
        )?
        else {
            eprintln!(
                "rex-projects: parked ticket role launch for Project {}: role {} profile {} has no exact verified provider qualification; run `rex-projects provider qualify --project {} --role {}`",
                candidate.project_id,
                role_name(candidate.role),
                profile_id,
                candidate.project_id,
                role_name(candidate.role),
            );
            return Ok(false);
        };
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
        if !self.view_has_block_capacity(store, &view)? {
            return Ok(false);
        }
        let accepted_plan =
            store.latest_accepted_work_plan(&candidate.project_id, ticket_run_id)?;
        if let Some(plan) = &accepted_plan {
            plan.validate_for(&project, &self.configuration_digest)?;
        }
        let validated_plan = accepted_plan
            .as_ref()
            .map(|plan| plan.validate_for(&project, &self.configuration_digest))
            .transpose()?;
        let wake_inputs = store.pending_role_wake_inputs(
            &candidate.project_id,
            &candidate.role_session_id,
            256,
        )?;
        if wake_inputs.is_empty() {
            return Ok(false);
        }
        let worker_recovery_authorization = worker_recovery_authorization_from_inputs(
            &wake_inputs,
            candidate.role,
            ticket_run_id,
            active_run.revision,
            worker_node_id.as_ref(),
            accepted_plan.as_ref(),
        )?;
        let implementation_publication_subject =
            if matches!(candidate.role, Role::Reviewer | Role::MergeDecision) {
                Some(accepted_publication_subject(
                    store,
                    self.owner_generation,
                    &active_run.project_id,
                    ticket_run_id,
                    active_run.revision,
                    &ReviewerPublicationConfig {
                        project: &project,
                        configuration_digest: &self.configuration_digest,
                        repositories: &self.applied_config.config.repositories,
                    },
                )?)
            } else {
                None
            };
        let completion_context = if candidate.role == Role::Postmortem {
            Some(postmortem_completion_context(
                store,
                self.owner_generation,
                &active_run,
                &self.configuration_digest,
            )?)
        } else {
            None
        };
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
        let worker_correction_context = if candidate.role == Role::Worker {
            worker_correction_context_for_launch(
                store,
                self.owner_generation,
                &active_run.project_id,
                ticket_run_id,
                active_run.revision,
                &self.configuration_digest,
                accepted_plan
                    .as_ref()
                    .ok_or("Worker correction context requires an accepted plan")?,
            )?
        } else {
            None
        };
        let worker_verification = match (&worker_context, &worker_node) {
            (Some(context), Some(node)) if candidate.role == Role::Worker => {
                worker_verification_assignment(
                    store,
                    self.owner_generation,
                    &context.token,
                    node,
                    worker_recovery_authorization.as_ref(),
                )?
            }
            _ => None,
        };
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
                recovery_summary: if candidate.role == Role::Coordinator
                    && active_run.phase == crate::engine::reducer::Phase::Implementing
                {
                    accepted_plan
                        .as_ref()
                        .map(|plan| {
                            coordinator_worker_recovery_summary(
                                store,
                                self.owner_generation,
                                &active_run,
                                plan,
                                &project,
                                &self.configuration_digest,
                                self.delivery.effects(),
                            )
                        })
                        .transpose()?
                        .flatten()
                } else {
                    None
                },
                accepted_plan: match (
                    &accepted_plan,
                    &validated_plan,
                    &worker_context,
                    &worker_node,
                ) {
                    (Some(plan), Some(validated), Some(context), Some(node))
                        if candidate.role == Role::Worker =>
                    {
                        validate_worker_recovery_assignment(
                            worker_recovery_authorization.as_ref(),
                            plan,
                            node,
                            context.token.expected_head(),
                            context.token.ticket_run_id(),
                            active_run.revision,
                        )?;
                        if let Some(authorization) = &worker_recovery_authorization
                            && self
                                .delivery
                                .effects()
                                .observe_local_head_at(context.token.worktree_path())?
                                != authorization.expected_head
                        {
                            return Err(
                                "Worker recovery worktree changed before launch reservation".into(),
                            );
                        }
                        if worker_recovery_authorization.is_none()
                            && context.token.expected_head() != context.token.base_sha()
                        {
                            ensure_worker_worktree_at_expected_head(
                                context.token.worktree_path(),
                                context.token.expected_head(),
                                |path| self.delivery.effects().observe_local_head_at(path),
                                "Worker rework worktree changed before launch reservation",
                            )?;
                        }
                        let expected_head = worker_recovery_authorization
                            .as_ref()
                            .map(|authorization| authorization.expected_head.as_str())
                            .unwrap_or_else(|| context.token.expected_head());
                        Some(worker_assignment_context(&WorkerAssignmentContext {
                            plan_record: plan,
                            validated_plan: validated,
                            node,
                            ticket_revision: active_run.revision,
                            correction_context: worker_correction_context.as_ref(),
                            worktree_path: context.token.worktree_path(),
                            branch: context.token.branch(),
                            base_sha: context.token.base_sha(),
                            expected_head,
                            host_artifacts: &store.persisted_worker_host_artifacts(
                                context.token.project_id(),
                                context.token.ticket_run_id(),
                                &context.token.reservation_binding(),
                            )?,
                            verification: worker_verification.as_ref(),
                            recovery_authorization: worker_recovery_authorization.as_ref(),
                            retained_host_commit: retained_host_commit(
                                store,
                                &candidate.project_id,
                                &self.configuration_digest,
                                worker_recovery_authorization.as_ref(),
                            )?
                            .as_ref(),
                            commit_mode: context.token.commit_mode(),
                            repository_id: context.token.repository_id(),
                        })?)
                    }
                    (Some(plan), _, _, _) => Some(
                        serde_json::to_string(&plan.proposal).map_err(|error| error.to_string())?,
                    ),
                    _ => None,
                },
                accepted_plan_digest: accepted_plan
                    .as_ref()
                    .filter(|_| candidate.role != Role::Worker)
                    .map(|plan| plan.plan_digest.clone()),
                implementation_publication_subject,
                completion_context: completion_context
                    .as_ref()
                    .map(serde_json::to_value)
                    .transpose()
                    .map_err(|error| error.to_string())?,
                previous_decisions: crate::roles::worker_recovery_decisions(
                    if candidate.role == Role::Worker {
                        worker_recovery_authorization.as_ref()
                    } else {
                        None
                    },
                ),
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
            &self.runtime_binary,
        )?;
        let expected_parent_role = match candidate.role {
            Role::Coordinator => Some(Role::Supervisor),
            Role::Worker => None,
            _ => Some(Role::Coordinator),
        };
        let parent_authority = if candidate.role == Role::Coordinator {
            Some(store.supervisor_parent_for_ticket_run(&candidate.project_id, ticket_run_id)?)
        } else if candidate.role == Role::Worker {
            None
        } else {
            let Some(parent) = store
                .coordinator_child_parent(&candidate.project_id, &candidate.role_session_id)?
            else {
                return Ok(false);
            };
            Some(parent)
        };
        if let Some(expected_parent_role) = expected_parent_role {
            let parent_authority = parent_authority
                .as_ref()
                .ok_or("ticket role parent authority is missing")?;
            if parent_authority.role != expected_parent_role
                || parent_authority.project_id != candidate.project_id
                || parent_authority.config_revision != runnable.record.config_revision
                || parent_authority.config_digest != runnable.record.config_digest
                || parent_authority
                    .ticket_run_id
                    .as_ref()
                    .is_some_and(|id| id != ticket_run_id)
                || parent_authority
                    .ticket_revision
                    .is_some_and(|revision| revision.0 != active_run.revision)
            {
                return Err(
                    "ticket role parent authority is stale or outside the current TicketRun".into(),
                );
            }
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
            completion_context.as_ref(),
        )?;
        let mut wake_snapshot = crate::agent_api::AgentWakeSnapshot {
            schema_version: 1,
            project_id: candidate.project_id.clone(),
            role_session_id: candidate.role_session_id.clone(),
            agent_run_id: agent_run_id.as_str().to_owned(),
            digest: Digest::parse("0".repeat(64))?,
            inputs: wake_items,
            worker_correction_context,
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
        let mailbox_expires_at_unix = mailbox_expiration(now_unix, profile.turn_timeout_seconds)?;
        let mailbox_max_request_bytes = 1_048_576_u64;
        let mailbox_max_pending_requests = 32_u32;
        let mailbox_capability_digest = mailbox_capability_digest(
            &agent_run_id,
            mailbox_expires_at_unix,
            mailbox_max_request_bytes,
            mailbox_max_pending_requests,
        )?;
        let reservation = crate::launch::AgentLaunchReservation {
            schema_version: crate::launch::LAUNCH_SCHEMA_VERSION,
            agent_run_id,
            project_id: candidate.project_id.clone(),
            role: candidate.role,
            role_session_id: candidate.role_session_id.clone(),
            parent_run_id: worker_context
                .as_ref()
                .map(|context| context.token.coordinator_agent_run_id().clone())
                .or_else(|| {
                    parent_authority
                        .as_ref()
                        .map(|authority| authority.agent_run_id.clone())
                }),
            parent_role: worker_context
                .as_ref()
                .map(|_| Role::Coordinator)
                .or_else(|| parent_authority.as_ref().map(|authority| authority.role)),
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
            mailbox_capability_digest,
            mailbox_expires_at_unix,
            mailbox_max_request_bytes,
            mailbox_max_pending_requests,
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

    fn view_has_block_capacity(
        &self,
        store: &ConfigStore,
        view: &crate::launch::RexView,
    ) -> Result<bool, String> {
        let label = match view.kind {
            crate::launch::RexViewKind::Supervisor => {
                owned_supervisor_window_label(view.project_id.as_str())
            }
            crate::launch::RexViewKind::Ticket => owned_ticket_window_label(
                view.ticket_namespace
                    .as_deref()
                    .ok_or("ticket view namespace is missing")?,
                view.ticket_id
                    .as_deref()
                    .ok_or("ticket view ID is missing")?,
            )
            .map_err(|error| error.to_string())?,
        };
        let window = RexWindow {
            server_instance_id: view.rex_server_identity.clone(),
            session_id: view.rex_session_id.clone(),
            window_id: view.rex_window_id.clone(),
            label: label.clone(),
            initial_block_id: None,
            disposition: CreateDisposition::Existing,
        };
        let blocks = self
            .rex
            .list_window_blocks(&window, &label)
            .map_err(|error| error.to_string())?;
        let records = store.rex_view_blocks(&view.view_id)?;
        Ok(crate::rex_view_lifecycle::has_block_capacity(
            &records,
            &blocks,
            self.config.runtime.max_blocks_per_tab,
        ))
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
        let spec = self.view_anchor_spec(format!("ticket-{}-view-{epoch}", ticket_id.as_str()));
        let window = self
            .rex
            .find_or_create_ticket_window(namespace.as_str(), ticket_id.as_str(), &spec)
            .map_err(|error| error.to_string())?;
        let anchor_block_id = window.initial_block_id.clone();
        let anchor_disposition = window.disposition;
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
            rex_server_identity: window.server_instance_id.clone(),
            rex_session_id: window.session_id.clone(),
            rex_window_id: window.window_id.clone(),
        };
        store.register_rex_view(self.owner_generation, &view)?;
        self.record_created_view_anchor(
            store,
            &view,
            &window,
            &spec,
            anchor_disposition,
            anchor_block_id,
        )?;
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
        let spec = self.view_anchor_spec(format!("project-{}-view-{epoch}", project_id));
        let window = self
            .rex
            .find_or_create_project_window(project_id, &spec)
            .map_err(|error| error.to_string())?;
        let anchor_block_id = window.initial_block_id.clone();
        let anchor_disposition = window.disposition;
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
            rex_server_identity: window.server_instance_id.clone(),
            rex_session_id: window.session_id.clone(),
            rex_window_id: window.window_id.clone(),
        };
        store.register_rex_view(self.owner_generation, &view)?;
        self.record_created_view_anchor(
            store,
            &view,
            &window,
            &spec,
            anchor_disposition,
            anchor_block_id,
        )?;
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

    fn view_anchor_spec(&self, run_id: String) -> AgentBlockSpec {
        AgentBlockSpec {
            run_id,
            command: PathBuf::from("/usr/bin/env"),
            args: view_anchor_args(&self.runtime_binary, &self.config_file, &self.state_root),
            cwd: self.state_root.clone(),
            path_prepend: self.search_path(),
        }
    }

    fn record_created_view_anchor(
        &self,
        store: &mut ConfigStore,
        view: &crate::launch::RexView,
        window: &RexWindow,
        spec: &AgentBlockSpec,
        disposition: CreateDisposition,
        block_id: Option<String>,
    ) -> Result<(), String> {
        if disposition != CreateDisposition::Created {
            return Ok(());
        }
        let Some(block_id) = block_id else {
            return Ok(());
        };
        let label = owned_agent_block_label(&spec.run_id).map_err(|error| error.to_string())?;
        let blocks = self
            .rex
            .list_window_blocks(window, &window.label)
            .map_err(|error| error.to_string())?;
        if !blocks
            .iter()
            .any(|block| block.block_id == block_id && block.label == label)
            || !self
                .rex
                .agent_block_matches_spec(window, spec, &block_id)
                .map_err(|error| error.to_string())?
        {
            return Ok(());
        }
        let command_digest = crate::rex_view_lifecycle::anchor_command_digest(spec)?;
        store.register_rex_view_anchor(
            self.owner_generation,
            &view.view_id,
            &block_id,
            &spec.run_id,
            &label,
            &command_digest,
        )?;
        Ok(())
    }
}

fn view_anchor_args(runtime_binary: &Path, config_file: &Path, state_root: &Path) -> Vec<String> {
    vec![
        runtime_binary.display().to_string(),
        "--config".into(),
        config_file.display().to_string(),
        "--state-root".into(),
        state_root.display().to_string(),
        "status".into(),
        "--json".into(),
    ]
}

#[cfg(test)]
mod view_anchor_args_tests {
    use super::view_anchor_args;
    use std::path::Path;

    #[test]
    fn status_anchor_uses_the_pinned_config_and_state_root_before_the_command() {
        assert_eq!(
            view_anchor_args(
                Path::new("/opt/rex-projects"),
                Path::new("/etc/rex-projects/config.toml"),
                Path::new("/var/lib/rex-projects"),
            ),
            [
                "/opt/rex-projects",
                "--config",
                "/etc/rex-projects/config.toml",
                "--state-root",
                "/var/lib/rex-projects",
                "status",
                "--json",
            ]
        );
    }
}

#[cfg(test)]
mod merge_handler_registration_tests {
    use super::{merge, register_merge_effect_handler};
    use crate::effects::EffectHandler;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    #[test]
    fn merge_effect_handler_is_registered_without_a_human_presenter() {
        let config_path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/fixture/config.toml");
        let applied = crate::config::load(&config_path).unwrap();
        assert!(applied.config.human.is_none());

        let source = Arc::new(merge::RuntimeMergeEvidenceSource::new(
            applied,
            Vec::new(),
            BTreeMap::new(),
        ));
        let mut handlers: Vec<Box<dyn EffectHandler>> = Vec::new();
        register_merge_effect_handler(&mut handlers, &source);

        assert_eq!(handlers.len(), 1);
        assert_eq!(
            handlers[0].kind(),
            crate::effects::EffectKind::Merge,
            "automatic merge procedures need the merge handler even when no HumanPresenter is configured"
        );
    }
}

fn digest_serialized(value: &impl serde::Serialize) -> Result<Digest, String> {
    let bytes = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    digest_bytes(&bytes)
}

fn exact_profile_qualification(
    store: &ConfigStore,
    project_id: &crate::domain::ids::ProjectId,
    profile_id: &crate::domain::ids::ProfileId,
    profile: &crate::config::Profile,
    profile_digest: &Digest,
) -> Result<Option<crate::launch::ProviderQualification>, String> {
    let qualifications =
        store.verified_provider_qualifications(project_id, profile_id, profile_digest, 32)?;
    if qualifications.is_empty() {
        return Ok(None);
    }
    let runtime_identity =
        crate::run_step::profile_runtime_identity(profile).map_err(|error| error.to_string())?;
    Ok(qualifications.into_iter().find(|qualification| {
        qualification.adapter == runtime_identity.adapter
            && qualification.executable_path
                == runtime_identity.executable_path.display().to_string()
            && qualification.executable_digest == runtime_identity.executable_digest
            && qualification.commit_mode == runtime_identity.commit_mode
            && qualification.invocation_options_digest == runtime_identity.invocation_options_digest
            && qualification.permission_mode == runtime_identity.effective_permission_mode
    }))
}

fn preflight_provider_qualification_job(
    profile: &crate::config::Profile,
    job: &crate::store::provider_qualification_runtime::ProviderQualificationJob,
    applied_config_digest: &Digest,
    configured_shutdown_grace_seconds: u64,
) -> Result<u64, String> {
    if crate::store::agent_profile_digest(profile)? != job.request.profile_digest
        || applied_config_digest != &job.request.config_digest
    {
        return Err("provider qualification profile or config changed after request".into());
    }
    let shutdown_grace_seconds = configured_shutdown_grace_seconds.clamp(1, 300);
    let deadline_seconds = crate::run_step::qualification_deadline_seconds(
        profile.turn_timeout_seconds,
        shutdown_grace_seconds,
    )?;
    let deadline = std::time::Duration::from_secs(deadline_seconds);
    std::time::Instant::now()
        .checked_add(deadline)
        .ok_or("provider qualification deadline cannot be represented by this platform")?;
    crate::run_step::profile_runtime_identity(profile).map_err(|error| error.to_string())?;
    Ok(deadline_seconds)
}

#[cfg(test)]
mod provider_qualification_lookup_tests {
    use super::exact_profile_qualification;
    use crate::domain::ids::{ProfileId, ProjectId};
    use crate::store::ConfigStore;

    #[test]
    fn unqualified_profile_parks_without_resolving_provider_executable() {
        let temp = tempfile::tempdir().unwrap();
        let store = ConfigStore::open_test(temp.path()).unwrap();
        let executable = temp.path().join("missing-provider");
        let profile: crate::config::Profile = serde_json::from_value(serde_json::json!({
            "adapter": "codex",
            "command": [executable.display().to_string()],
            "turn_timeout_seconds": 60,
            "commit_mode": "native"
        }))
        .unwrap();

        let profile_digest = crate::store::agent_profile_digest(&profile).unwrap();
        let qualification = exact_profile_qualification(
            &store,
            &ProjectId::parse("project-a").unwrap(),
            &ProfileId::parse("profile-a").unwrap(),
            &profile,
            &profile_digest,
        )
        .unwrap();

        assert!(qualification.is_none());
        assert!(!executable.exists());
    }
}

fn digest_bytes(bytes: &[u8]) -> Result<Digest, String> {
    use sha2::Digest as _;
    Digest::parse(format!("{:x}", sha2::Sha256::digest(bytes)))
}

fn mailbox_capability_digest(
    agent_run_id: &crate::domain::ids::AgentRunId,
    expires_at_unix: u64,
    max_request_bytes: u64,
    max_pending_requests: u32,
) -> Result<Digest, String> {
    let limits = crate::mailbox::MailboxLimits {
        max_request_bytes: usize::try_from(max_request_bytes)
            .map_err(|_| "Agent mailbox request limit exceeds this platform")?,
        max_pending_requests: usize::try_from(max_pending_requests)
            .map_err(|_| "Agent mailbox pending limit exceeds this platform")?,
    };
    Digest::parse(crate::mailbox::MailboxDescriptor::capability_digest(
        agent_run_id.as_str(),
        expires_at_unix,
        limits,
    )?)
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

#[cfg(test)]
mod provider_qualification_preflight_tests {
    use super::*;
    use crate::domain::ids::{ProfileId, ProjectId};
    use crate::store::provider_qualification_runtime::{
        ProviderQualificationJob, ProviderQualificationJobStatus, ProviderQualificationRequest,
    };

    #[test]
    fn preflight_accepts_the_canonical_digest_for_an_unchanged_qualification_job() {
        let profile: crate::config::Profile = serde_json::from_value(serde_json::json!({
            "adapter": "codex",
            "command": [std::env::current_exe().unwrap().display().to_string()],
            "turn_timeout_seconds": 60,
            "commit_mode": "native"
        }))
        .unwrap();
        let profile_digest = crate::store::agent_profile_digest(&profile).unwrap();
        assert_ne!(digest_serialized(&profile).unwrap(), profile_digest);
        let config_digest = Digest::parse("a".repeat(64)).unwrap();
        let job = ProviderQualificationJob {
            request: ProviderQualificationRequest {
                request_id: "qualification-test".into(),
                project_id: ProjectId::parse("project-a").unwrap(),
                role: Role::Supervisor,
                profile_id: ProfileId::parse("default-codex").unwrap(),
                profile_digest,
                config_revision: 1,
                config_digest: config_digest.clone(),
            },
            request_digest: Digest::parse("b".repeat(64)).unwrap(),
            status: ProviderQualificationJobStatus::Running,
            controller_generation: 1,
            rex_session_id: None,
            rex_window_id: None,
            rex_block_id: None,
            result_json: None,
            evidence_digest: None,
            created_at_unix: 1,
            updated_at_unix: 1,
        };

        assert!(preflight_provider_qualification_job(&profile, &job, &config_digest, 30).is_ok());
    }
}

pub(crate) fn role_allowed_in_phase(role: Role, phase: crate::engine::reducer::Phase) -> bool {
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

fn role_allowed_for_run(
    role: Role,
    phase: crate::engine::reducer::Phase,
    activity: crate::engine::reducer::Activity,
) -> bool {
    role_allowed_in_phase(role, phase)
        && (!matches!(role, Role::Reviewer | Role::Operator | Role::Postmortem)
            || activity == crate::engine::reducer::Activity::Running)
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

fn coordinator_worker_recovery_summary(
    store: &ConfigStore,
    owner_generation: u64,
    run: &crate::store::scheduler::ActiveTicketRun,
    plan: &crate::store::accepted_plans::AcceptedWorkPlanRecord,
    project: &crate::config::ProjectConfig,
    configuration_digest: &Digest,
    delivery: &crate::delivery_runtime::RepositoryDeliveryEffects,
) -> Result<Option<String>, String> {
    if run.phase != crate::engine::reducer::Phase::Implementing {
        return Ok(None);
    }
    let candidates = store.worker_recovery_candidates(
        owner_generation,
        run,
        plan,
        project,
        configuration_digest,
    )?;
    verified_worker_recovery_summary(candidates, |path| delivery.observe_local_head_at(path))
}

pub(crate) fn verified_worker_recovery_summary(
    candidates: Vec<crate::engine::orchestration::WorkerRecoveryCandidate>,
    mut observe_head: impl FnMut(&Path) -> Result<String, String>,
) -> Result<Option<String>, String> {
    let mut verified = Vec::new();
    for candidate in candidates {
        if observe_head(&candidate.worktree_path)? == candidate.expected_head {
            verified.push(candidate);
        }
    }
    if verified.is_empty() {
        Ok(None)
    } else {
        serde_json::to_string(&verified)
            .map(Some)
            .map_err(|error| error.to_string())
    }
}

fn ensure_worker_worktree_at_expected_head(
    worktree_path: &Path,
    expected_head: &str,
    mut observe_head: impl FnMut(&Path) -> Result<String, String>,
    mismatch: &str,
) -> Result<(), String> {
    let observed = observe_head(worktree_path)?;
    if observed != expected_head {
        return Err(mismatch.into());
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn prepared_worker_assignment_for_test(
    store: &ConfigStore,
    owner_generation: u64,
    plan_record: &crate::store::accepted_plans::AcceptedWorkPlanRecord,
    validated_plan: &crate::engine::orchestration::ValidatedPlan,
    token: &crate::store::accepted_plans::PreparedWorkerLaunch,
    node: &crate::engine::orchestration::ValidatedWorkNode,
    recovery_authorization: Option<&crate::engine::orchestration::WorkerRecoveryAuthorization>,
) -> Result<String, String> {
    let run = store
        .active_ticket_runs(owner_generation, 128)?
        .into_iter()
        .find(|run| run.ticket_run_id == *token.ticket_run_id())
        .ok_or("Worker assignment test has no active TicketRun")?;
    let correction_context = worker_correction_context_for_launch(
        store,
        owner_generation,
        token.project_id(),
        token.ticket_run_id(),
        run.revision,
        token.configuration_digest(),
        plan_record,
    )?;
    let verification = worker_verification_assignment(
        store,
        owner_generation,
        token,
        node,
        recovery_authorization,
    )?;
    let retained = retained_host_commit(
        store,
        token.project_id(),
        token.configuration_digest(),
        recovery_authorization,
    )?;
    worker_assignment_context(&WorkerAssignmentContext {
        plan_record,
        validated_plan,
        node,
        ticket_revision: run.revision,
        correction_context: correction_context.as_ref(),
        worktree_path: token.worktree_path(),
        branch: token.branch(),
        base_sha: token.base_sha(),
        expected_head: recovery_authorization
            .map(|authorization| authorization.expected_head.as_str())
            .unwrap_or_else(|| token.expected_head()),
        host_artifacts: &store.persisted_worker_host_artifacts(
            token.project_id(),
            token.ticket_run_id(),
            &token.reservation_binding(),
        )?,
        verification: verification.as_ref(),
        recovery_authorization,
        retained_host_commit: retained.as_ref(),
        commit_mode: token.commit_mode(),
        repository_id: token.repository_id(),
    })
}

#[cfg(test)]
pub(crate) fn prepared_worker_assignment_from_reservation_for_test(
    store: &ConfigStore,
    reservation: &crate::launch::AgentLaunchReservation,
    plan_record: &crate::store::accepted_plans::AcceptedWorkPlanRecord,
    validated_plan: &crate::engine::orchestration::ValidatedPlan,
    token: &crate::store::accepted_plans::PreparedWorkerLaunch,
    node: &crate::engine::orchestration::ValidatedWorkNode,
    recovery_authorization: Option<&crate::engine::orchestration::WorkerRecoveryAuthorization>,
) -> Result<String, String> {
    let context = PreparedWorkerContext {
        plan_record: plan_record.clone(),
        validated_plan: validated_plan.clone(),
        node: node.clone(),
        token: token.clone(),
    };
    let verification = worker_verification_assignment(
        store,
        reservation.controller_generation,
        token,
        node,
        recovery_authorization,
    )?;
    worker_assignment_for_reservation(
        store,
        reservation,
        &context,
        verification.as_ref(),
        recovery_authorization,
    )
}

#[cfg(test)]
pub(crate) fn render_reserved_worker_prompt_for_test(
    applied_config: &AppliedConfig,
    reservation: &crate::launch::AgentLaunchReservation,
    plan_record: &crate::store::accepted_plans::AcceptedWorkPlanRecord,
    validated_plan: &crate::engine::orchestration::ValidatedPlan,
    token: &crate::store::accepted_plans::PreparedWorkerLaunch,
    node: &crate::engine::orchestration::ValidatedWorkNode,
    ticket: crate::roles::TicketBrief,
) -> Result<String, String> {
    let prepared_context = PreparedWorkerContext {
        plan_record: plan_record.clone(),
        validated_plan: validated_plan.clone(),
        node: node.clone(),
        token: token.clone(),
    };
    let assignment = worker_assignment_from_reserved_snapshot(
        reservation,
        &prepared_context,
        &[],
        None,
        None,
        None,
    )?;
    let mut render_config = applied_config.clone();
    render_config.source_files.clear();
    render_config.source_root = reservation.workspace_path.display().to_string();
    let profile_id = render_config
        .config
        .projects
        .get(&reservation.project_id)
        .and_then(|project| project.roles.get(&Role::Worker))
        .cloned()
        .ok_or("Worker profile is missing from the applied Project")?;
    let profile_root = reservation
        .workspace_path
        .join("profiles")
        .join(profile_id.as_str());
    std::fs::create_dir_all(&profile_root).map_err(|error| error.to_string())?;
    let canonical_profile_root =
        std::fs::canonicalize(&profile_root).map_err(|error| error.to_string())?;
    use sha2::Digest as _;
    let profile_root_digest = Digest::parse(format!(
        "{:x}",
        sha2::Sha256::digest(canonical_profile_root.display().to_string().as_bytes())
    ))?;
    render_config.source_files.push(crate::config::SourceFile {
        kind: crate::config::SourceKind::Directory,
        path: profile_root.display().to_string(),
        canonical_path: canonical_profile_root.display().to_string(),
        sha256: profile_root_digest,
        bytes: 0,
        contents: String::new(),
    });
    let rendered = crate::roles::render_role_prompt(
        &render_config,
        &crate::roles::PromptContext {
            project_id: reservation.project_id.clone(),
            profile_id: None,
            role: Role::Worker,
            operation_recipe: None,
            repositories: vec![node.repository.clone()],
            ticket: Some(ticket),
            recovery_summary: None,
            accepted_plan: Some(assignment),
            accepted_plan_digest: None,
            implementation_publication_subject: None,
            completion_context: None,
            previous_decisions: Vec::new(),
            required_evidence: node.required_evidence.clone(),
            stop_conditions: vec![
                "Work only in the assigned repository worktree and follow the assigned node's base/dependency semantics.".into(),
                "Do not push, create a pull request, request a merge, or merge; the host controls publication.".into(),
            ],
            assigned_commit_mode: Some(token.commit_mode()),
        },
        Path::new("/bin/true"),
    )?;
    Ok(rendered.text)
}

pub(crate) fn worker_correction_context_for_launch(
    store: &ConfigStore,
    owner_generation: u64,
    project_id: &crate::domain::ids::ProjectId,
    ticket_run_id: &crate::domain::ids::TicketRunId,
    ticket_revision: u64,
    configuration_digest: &Digest,
    plan_record: &crate::store::accepted_plans::AcceptedWorkPlanRecord,
) -> Result<Option<crate::agent_api::WorkerCorrectionContext>, String> {
    if plan_record.project_id != *project_id
        || plan_record.ticket_run_id != *ticket_run_id
        || plan_record.configuration_digest != *configuration_digest
    {
        return Err("Worker correction context does not match the accepted plan scope".into());
    }
    let instruction =
        store.latest_coordinator_instruction(project_id, ticket_run_id, ticket_revision)?;
    let review = store.latest_worker_reviewer_correction(
        owner_generation,
        project_id,
        ticket_run_id,
        ticket_revision,
        configuration_digest,
        &plan_record.plan_digest,
    )?;
    if instruction.is_none() && review.is_none() {
        return Ok(None);
    }
    let context = crate::agent_api::WorkerCorrectionContext {
        schema_version: 1,
        project_id: project_id.clone(),
        ticket_run_id: ticket_run_id.clone(),
        ticket_revision,
        configuration_digest: configuration_digest.clone(),
        accepted_plan_digest: plan_record.plan_digest.clone(),
        coordinator_instruction: instruction.map(|instruction| {
            crate::agent_api::WorkerCoordinatorInstruction {
                wake_input_id: instruction.wake_input_id,
                request_id: instruction.request_id,
                source_revision: instruction.source_revision,
                body_digest: instruction.body_digest,
                body: instruction.body,
            }
        }),
        reviewer_correction: review.map(|review| crate::agent_api::WorkerReviewerCorrection {
            evidence_id: review.evidence_id,
            result_digest: review.result_digest,
            source_revision: review.source_revision,
            accepted_revision: review.accepted_revision,
            publication_revision: review.publication_revision,
            publication_subject_digest: review.assessment.subject_digest.clone(),
            assessment: review.assessment,
        }),
    };
    context.validate_for_assignment(
        project_id,
        ticket_run_id,
        ticket_revision,
        configuration_digest,
        &plan_record.plan_digest,
    )?;
    Ok(Some(context))
}

fn worker_verification_assignment(
    store: &ConfigStore,
    owner_generation: u64,
    token: &crate::store::accepted_plans::PreparedWorkerLaunch,
    node: &crate::engine::orchestration::ValidatedWorkNode,
    recovery_authorization: Option<&crate::engine::orchestration::WorkerRecoveryAuthorization>,
) -> Result<Option<WorkerVerificationAssignment>, String> {
    let expected_head = recovery_authorization
        .map(|authorization| authorization.expected_head.as_str())
        .unwrap_or_else(|| token.expected_head());
    if recovery_authorization.is_some_and(|authorization| {
        authorization.ticket_run_id != *token.ticket_run_id()
            || authorization.ticket_revision != token.ticket_revision()
            || authorization.work_node_id != node.id
            || authorization.accepted_plan_digest != *token.plan_digest()
            || authorization.expected_head != expected_head
    }) {
        return Err("Worker recovery authorization differs from its prepared assignment".into());
    }

    // A prepared token at its base identifies first work for this accepted plan. A recovery
    // authorization may advance that worktree through a retained host commit, but there is no
    // accepted publication to verify yet.
    if token.expected_head() == token.base_sha() {
        return Ok(None);
    }

    // Correction work starts from a host accepted publication. Verify that publication from
    // the prepared token, then only classify the worker as verification-only while recovery
    // still points at that exact published head.
    let published_head = token.expected_head();
    let snapshot = store.accepted_implementation_publication_snapshot(
        owner_generation,
        token.project_id(),
        token.ticket_run_id(),
        token.ticket_revision(),
    )?;
    let matching = snapshot
        .publication_receipts()
        .iter()
        .filter_map(|publication| {
            let request: crate::delivery_runtime::PublishImplementationEffectPayload =
                crate::protocol::parse_unique(publication.intent().request_json.as_bytes()).ok()?;
            (request.work_node_id == node.id).then_some((publication, request))
        })
        .collect::<Vec<_>>();
    if matching.len() != 1 {
        return Err(
            "correction Worker publication must cover its accepted node exactly once".into(),
        );
    }
    let (publication, request) = &matching[0];
    let receipt: crate::delivery_runtime::ImplementationPublicationReceipt =
        crate::protocol::parse_unique(publication.receipt_json().as_bytes())?;
    if request.ticket_run_id != *token.ticket_run_id()
        || request.repository_id != node.repository
        || request.configuration_digest != *token.configuration_digest()
        || request.source_revision.checked_add(1) != Some(snapshot.publication_revision())
        || receipt.ticket_run_id != *token.ticket_run_id()
        || receipt.work_node_id != node.id
        || receipt.repository_id != node.repository
        || receipt.configuration_digest != *token.configuration_digest()
        || receipt.commit.head() != published_head
    {
        return Err(
            "correction Worker publication differs from its host-prepared assignment".into(),
        );
    }
    if expected_head != published_head {
        return Ok(None);
    }
    Ok(Some(WorkerVerificationAssignment {
        publication_revision: snapshot.publication_revision(),
        publication_operation_id: publication.intent().operation_id.as_str().to_owned(),
        published_head: published_head.to_owned(),
    }))
}

fn retained_host_commit(
    store: &ConfigStore,
    project_id: &crate::domain::ids::ProjectId,
    config_digest: &Digest,
    recovery: Option<&crate::engine::orchestration::WorkerRecoveryAuthorization>,
) -> Result<Option<crate::delivery_runtime::CommitWorkerManifestEffectReceipt>, String> {
    use crate::delivery_runtime::{
        CommitWorkerManifestEffectPayload, CommitWorkerManifestEffectReceipt,
    };
    let Some(recovery) = recovery else {
        return Ok(None);
    };
    recovery.validate()?;
    let Some(operation_id) = &recovery.prior_host_commit_operation_id else {
        return Ok(None);
    };
    let succeeded = store
        .succeeded_effect_receipt(operation_id.as_str())?
        .ok_or("retained Worker commit is not durably succeeded")?;
    let payload: CommitWorkerManifestEffectPayload =
        crate::protocol::parse_unique(succeeded.intent().request_json.as_bytes())?;
    let receipt: CommitWorkerManifestEffectReceipt =
        crate::protocol::parse_unique(succeeded.receipt_json().as_bytes())?;
    let receipt_digest = digest_bytes(succeeded.receipt_json().as_bytes())?;
    if succeeded.intent().kind != "commit_worker_manifest"
        || succeeded.intent().project_id != *project_id
        || succeeded.intent().subject_type != "ticket_run"
        || succeeded.intent().subject_id != recovery.ticket_run_id.as_str()
        || succeeded.intent().expected_revision != Some(recovery.ticket_revision)
        || payload.schema_version != 1
        || payload.agent_run_id != recovery.prior_worker_agent_run_id
        || payload.project_id != *project_id
        || payload.configuration_digest != *config_digest
        || payload.ticket_revision != recovery.ticket_revision
        || payload.ticket_run_id != recovery.ticket_run_id
        || payload.work_node_id != recovery.work_node_id
        || receipt.schema_version != 1
        || receipt.agent_run_id != recovery.prior_worker_agent_run_id
        || receipt.message_id != payload.message_id
        || receipt.message_id.trim().is_empty()
        || receipt.ticket_run_id != recovery.ticket_run_id
        || receipt.work_node_id != recovery.work_node_id
        || receipt.repository_id != payload.repository_id
        || receipt.base_sha != payload.expected_base_sha
        || receipt.manifest_artifact != payload.manifest_artifact
        || receipt.commit.operation_id != *operation_id
        || receipt.commit.expected_head != payload.expected_head
        || receipt.commit.repository_id != payload.repository_id
        || receipt.commit.manifest_digest != payload.manifest_digest
        || receipt.commit.observed_head != recovery.expected_head
        || receipt.commit.observed_head == receipt.commit.expected_head
        || !receipt.commit.signature_verified
        || !receipt.commit.hooks_completed
        || !receipt.commit.index_synchronized
        || receipt.commit.index_sync_conflict
        || recovery.prior_host_commit_receipt_digest.as_ref() != Some(&receipt_digest)
        || !recovery
            .prior_artifact_refs
            .contains(&receipt.manifest_artifact)
    {
        return Err("retained Worker commit differs from its exact recovery authority".into());
    }
    Ok(Some(receipt))
}

fn worker_assignment_context(context: &WorkerAssignmentContext<'_>) -> Result<String, String> {
    let WorkerAssignmentContext {
        plan_record,
        validated_plan,
        node,
        ticket_revision,
        correction_context,
        worktree_path,
        branch,
        base_sha,
        expected_head,
        host_artifacts,
        verification,
        recovery_authorization,
        retained_host_commit,
        commit_mode,
        repository_id,
    } = context;
    if let Some(correction_context) = correction_context {
        correction_context.validate_for_assignment(
            &plan_record.project_id,
            &plan_record.ticket_run_id,
            *ticket_revision,
            &plan_record.configuration_digest,
            &plan_record.plan_digest,
        )?;
    }
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
        "implementation_ready_identity":{
            "repository":node.repository,
            "change_reference_worktree_id":node.id,
            "worktree_id_semantics":"Use assigned_node.node_id exactly. In schema v1 this is the logical work node ID, not the managed worktree directory ID."
        },
        "prepared_worktree":{
            "path":worktree_path,
            "branch":branch,
            "base_sha":base_sha,
            "expected_head":expected_head,
            "host_artifacts":host_artifacts,
            "verification_only":verification.is_some(),
            "accepted_publication":verification.map(|value| serde_json::json!({
                "publication_revision":value.publication_revision,
                "publication_operation_id":value.publication_operation_id,
                "published_head":value.published_head,
            })),
            "commit_mode":commit_mode,
            "repository_id":repository_id,
        },
        "worker_recovery_authorization":recovery_authorization,
        "worker_correction_context":correction_context,
        "retained_host_commit":retained_host_commit,
        "delivery_authority":"The host owns push, pull request creation, merge, and delivery."
    });
    serde_json::to_string(&value).map_err(|error| error.to_string())
}

fn worker_assignment_for_reservation(
    store: &ConfigStore,
    reservation: &crate::launch::AgentLaunchReservation,
    context: &PreparedWorkerContext,
    verification: Option<&WorkerVerificationAssignment>,
    recovery_authorization: Option<&crate::engine::orchestration::WorkerRecoveryAuthorization>,
) -> Result<String, String> {
    let host_artifacts = store.persisted_worker_host_artifacts(
        context.token.project_id(),
        context.token.ticket_run_id(),
        &context.token.reservation_binding(),
    )?;
    let retained = retained_host_commit(
        store,
        &reservation.project_id,
        &reservation.config_digest,
        recovery_authorization,
    )?;
    worker_assignment_from_reserved_snapshot(
        reservation,
        context,
        &host_artifacts,
        verification,
        recovery_authorization,
        retained.as_ref(),
    )
}

fn worker_assignment_from_reserved_snapshot(
    reservation: &crate::launch::AgentLaunchReservation,
    context: &PreparedWorkerContext,
    host_artifacts: &[crate::agent_api::HostArtifactLocator],
    verification: Option<&WorkerVerificationAssignment>,
    recovery_authorization: Option<&crate::engine::orchestration::WorkerRecoveryAuthorization>,
    retained_host_commit: Option<&crate::delivery_runtime::CommitWorkerManifestEffectReceipt>,
) -> Result<String, String> {
    worker_assignment_context(&WorkerAssignmentContext {
        plan_record: &context.plan_record,
        validated_plan: &context.validated_plan,
        node: &context.node,
        ticket_revision: reservation
            .ticket_revision
            .ok_or("Worker reservation lacks TicketRun revision")?
            .0,
        correction_context: reservation.wake_snapshot.worker_correction_context.as_ref(),
        worktree_path: context.token.worktree_path(),
        branch: context.token.branch(),
        base_sha: context.token.base_sha(),
        expected_head: recovery_authorization
            .map(|authorization| authorization.expected_head.as_str())
            .unwrap_or_else(|| context.token.expected_head()),
        host_artifacts,
        verification,
        recovery_authorization,
        retained_host_commit,
        commit_mode: context.token.commit_mode(),
        repository_id: context.token.repository_id(),
    })
}

#[cfg(test)]
mod coordinator_publication_gate_tests {
    use crate::domain::ids::{ProjectId, TicketRunId};
    use crate::store::ConfigStore;

    #[test]
    fn coordinator_waits_only_for_an_unsettled_publication_on_its_ticket_run() {
        let temp = tempfile::tempdir().unwrap();
        let store = ConfigStore::open_test(temp.path()).unwrap();
        let digest = "a".repeat(64);
        store
            .test_connection()
            .execute_batch(&format!(
                "INSERT INTO config_snapshots(source_identity,revision,digest,digest_algorithm,representation,effective_config_json,source_manifest_json,applied_at_unix) VALUES ('fixture',1,'{digest}','sha256','canonical_json_utf8_sorted_keys','{{}}','{{}}',1);
                 INSERT INTO config_current(source_identity,revision) VALUES ('fixture',1);
                 INSERT INTO projects(project_id,config_source,config_revision,config_digest,mode,goal_revision,desired_lifecycle,state_revision,created_at_unix) VALUES ('project-a','fixture',1,'{digest}','operations',0,'running',0,1);
                 INSERT INTO effects(operation_id,project_id,subject_type,subject_id,logical_key,kind,request_json,request_digest,status,attempt_count,next_attempt_at_unix,created_at_unix) VALUES ('publish-1','project-a','ticket_run','ticket-run-a','publish-1','publish_implementation','{{}}','{digest}','pending',0,1,1);
                 INSERT INTO effects(operation_id,project_id,subject_type,subject_id,logical_key,kind,request_json,request_digest,status,attempt_count,next_attempt_at_unix,created_at_unix) VALUES ('publish-other','project-a','ticket_run','ticket-run-b','publish-other','publish_implementation','{{}}','{digest}','pending',0,1,1);"
            ))
            .unwrap();

        let project = ProjectId::parse("project-a").unwrap();
        let ticket_run = TicketRunId::parse("ticket-run-a").unwrap();
        assert!(
            store
                .ticket_run_has_unsettled_implementation_publication(&project, &ticket_run)
                .unwrap()
        );
        assert!(
            !store
                .ticket_run_has_unsettled_implementation_publication(
                    &project,
                    &TicketRunId::parse("ticket-run-c").unwrap(),
                )
                .unwrap()
        );

        for status in ["claimed", "uncertain"] {
            store
                .test_connection()
                .execute(
                    "UPDATE effects SET status=?1 WHERE operation_id='publish-1'",
                    [status],
                )
                .unwrap();
            assert!(
                store
                    .ticket_run_has_unsettled_implementation_publication(&project, &ticket_run)
                    .unwrap()
            );
        }

        store
            .test_connection()
            .execute(
                "UPDATE effects SET status='succeeded' WHERE operation_id='publish-1'",
                [],
            )
            .unwrap();
        assert!(
            !store
                .ticket_run_has_unsettled_implementation_publication(&project, &ticket_run)
                .unwrap()
        );
        assert!(
            store
                .ticket_run_has_unsettled_implementation_publication(
                    &project,
                    &TicketRunId::parse("ticket-run-b").unwrap(),
                )
                .unwrap()
        );
    }
}

fn worker_recovery_authorization_from_inputs(
    inputs: &[crate::store::agent_runtime::PendingRoleWakeInput],
    role: Role,
    ticket_run_id: &crate::domain::ids::TicketRunId,
    ticket_revision: u64,
    node_id: Option<&crate::engine::orchestration::WorkNodeId>,
    accepted_plan: Option<&crate::store::accepted_plans::AcceptedWorkPlanRecord>,
) -> Result<Option<crate::engine::orchestration::WorkerRecoveryAuthorization>, String> {
    let mut parsed = None;
    for input in inputs
        .iter()
        .filter(|input| input.source_type == "worker_recovery_authorization")
    {
        let authorization: crate::engine::orchestration::WorkerRecoveryAuthorization =
            serde_json::from_value(
                input
                    .payload_json
                    .get("authorization")
                    .cloned()
                    .ok_or("Worker recovery wake has no host authorization")?,
            )
            .map_err(|error| format!("invalid Worker recovery authorization: {error}"))?;
        authorization.validate()?;
        if input.source_id != authorization.prior_worker_result_evidence_id
            || authorization.ticket_run_id != *ticket_run_id
            || authorization.ticket_revision != ticket_revision
            || input.source_revision != ticket_revision
            || node_id != Some(&authorization.work_node_id)
            || accepted_plan
                .is_none_or(|plan| plan.plan_digest != authorization.accepted_plan_digest)
        {
            return Err("Worker recovery wake is stale or outside the accepted node".into());
        }
        if parsed.replace(authorization).is_some() {
            return Err("Worker role session has multiple recovery authorities".into());
        }
    }
    if role != Role::Worker && parsed.is_some() {
        return Err("non-Worker role cannot consume a Worker recovery authority".into());
    }
    Ok(parsed)
}

#[cfg(test)]
mod coordinator_worker_recovery_prompt_tests {
    use super::*;
    use crate::domain::ids::{AgentRunId, Digest, TicketId};
    use crate::domain::types::Role;
    use crate::engine::orchestration::{WorkNodeId, WorkerRecoveryCandidate};
    use crate::roles::{PromptContext, TicketBrief};
    use std::process::Command;

    fn git_head(path: &Path) -> String {
        let output = Command::new("git")
            .arg("-C")
            .arg(path)
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap();
        assert!(output.status.success());
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    #[test]
    fn verified_recovery_summary_reaches_the_coordinator_prompt_file() {
        let checkout = Path::new(env!("CARGO_MANIFEST_DIR"));
        let head = git_head(checkout);
        let candidate = WorkerRecoveryCandidate {
            work_node_id: WorkNodeId::parse("worker-node-a").unwrap(),
            ticket_revision: 4,
            worktree_path: checkout.to_owned(),
            accepted_plan_digest: Digest::parse("a".repeat(64)).unwrap(),
            prior_worker_agent_run_id: AgentRunId::parse("prior-worker-run").unwrap(),
            prior_host_commit_operation_id: None,
            expected_head: head.clone(),
            prior_terminal_digest: Digest::parse("b".repeat(64)).unwrap(),
            prior_absence_digest: Digest::parse("c".repeat(64)).unwrap(),
            prior_host_commit_receipt_digest: None,
            prior_worker_result_evidence_id: "worker-result-evidence".into(),
            prior_artifact_refs: Vec::new(),
        };
        let summary = verified_worker_recovery_summary(vec![candidate], |path| Ok(git_head(path)))
            .unwrap()
            .expect("matching host-observed HEAD should be advertised");
        let applied = crate::config::load(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/fixture/config.toml"),
        )
        .expect("load the repository fixture configuration");
        let rendered = crate::roles::render_role_prompt(
            &applied,
            &PromptContext {
                project_id: crate::domain::ids::ProjectId::parse("goal_project").unwrap(),
                profile_id: None,
                role: Role::Coordinator,
                operation_recipe: None,
                repositories: vec![crate::domain::ids::RepositoryId::parse("example").unwrap()],
                ticket: Some(TicketBrief {
                    ticket_id: TicketId::parse("PAY-12").unwrap(),
                    ticket_revision: 4,
                    title: "Recover a blocked worker".into(),
                    body: "Retry the same accepted node after the blocker is removed.".into(),
                    acceptance: Vec::new(),
                }),
                recovery_summary: Some(summary),
                accepted_plan: None,
                accepted_plan_digest: None,
                implementation_publication_subject: None,
                completion_context: None,
                previous_decisions: Vec::new(),
                required_evidence: Vec::new(),
                stop_conditions: Vec::new(),
                assigned_commit_mode: None,
            },
            &std::env::current_exe().unwrap(),
        )
        .unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let prompt_path = workspace.path().join("coordinator-prompt.md");
        std::fs::write(&prompt_path, rendered.text).unwrap();
        let observed_prompt = std::fs::read_to_string(prompt_path).unwrap();
        assert!(observed_prompt.contains("prior-worker-run"));
        assert!(observed_prompt.contains(&head));

        let stale = WorkerRecoveryCandidate {
            work_node_id: WorkNodeId::parse("worker-node-a").unwrap(),
            ticket_revision: 4,
            worktree_path: checkout.to_owned(),
            accepted_plan_digest: Digest::parse("a".repeat(64)).unwrap(),
            prior_worker_agent_run_id: AgentRunId::parse("stale-worker-run").unwrap(),
            prior_host_commit_operation_id: None,
            expected_head: "0".repeat(40),
            prior_terminal_digest: Digest::parse("b".repeat(64)).unwrap(),
            prior_absence_digest: Digest::parse("c".repeat(64)).unwrap(),
            prior_host_commit_receipt_digest: None,
            prior_worker_result_evidence_id: "stale-evidence".into(),
            prior_artifact_refs: Vec::new(),
        };
        assert!(
            verified_worker_recovery_summary(vec![stale], |path| Ok(git_head(path)))
                .unwrap()
                .is_none()
        );
    }
}

#[cfg(test)]
mod reviewer_activity_gate_tests {
    use super::role_allowed_for_run;
    use crate::domain::types::Role;
    use crate::engine::reducer::{Activity, Phase};

    #[test]
    fn reviewer_wake_is_not_launchable_after_human_escalation_blocks_run() {
        assert!(role_allowed_for_run(
            Role::Reviewer,
            Phase::Reviewing,
            Activity::Running
        ));
        assert!(!role_allowed_for_run(
            Role::Reviewer,
            Phase::Reviewing,
            Activity::Blocked
        ));
        assert!(!role_allowed_for_run(
            Role::Reviewer,
            Phase::Assessing,
            Activity::Running
        ));
    }
}

#[cfg(test)]
mod worker_rework_head_tests {
    use super::ensure_worker_worktree_at_expected_head;
    use std::path::Path;
    use std::process::Command;

    fn git(directory: &Path, arguments: &[&str]) -> String {
        let output = Command::new("git")
            .arg("-C")
            .arg(directory)
            .args(arguments)
            .output()
            .expect("git is installed for repository tests");
        assert!(
            output.status.success(),
            "git {arguments:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    #[test]
    fn correction_worker_rejects_a_managed_worktree_that_moved_after_publication() {
        let temp = tempfile::tempdir().unwrap();
        let repository = temp.path().join("repository");
        let worktree = temp.path().join("worktree");
        std::fs::create_dir_all(&repository).unwrap();
        git(&repository, &["init", "-b", "main"]);
        git(&repository, &["config", "user.name", "rex-projects test"]);
        git(
            &repository,
            &["config", "user.email", "rex-projects@example.invalid"],
        );
        std::fs::write(repository.join("tracked.txt"), "published\n").unwrap();
        git(&repository, &["add", "tracked.txt"]);
        git(&repository, &["commit", "-m", "published implementation"]);
        let published_head = git(&repository, &["rev-parse", "HEAD"]);
        git(
            &repository,
            &[
                "worktree",
                "add",
                "--detach",
                worktree.to_str().unwrap(),
                &published_head,
            ],
        );

        let observe = |path: &Path| {
            let output = Command::new("git")
                .args(["-C", path.to_str().unwrap(), "rev-parse", "HEAD"])
                .output()
                .map_err(|error| error.to_string())?;
            if !output.status.success() {
                return Err(String::from_utf8_lossy(&output.stderr).into_owned());
            }
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
        };
        ensure_worker_worktree_at_expected_head(
            &worktree,
            &published_head,
            observe,
            "stale worktree",
        )
        .expect("a worktree at the accepted publication is launchable");

        git(&worktree, &["config", "user.name", "rex-projects test"]);
        git(
            &worktree,
            &["config", "user.email", "rex-projects@example.invalid"],
        );
        std::fs::write(worktree.join("tracked.txt"), "unexpected later change\n").unwrap();
        git(&worktree, &["add", "tracked.txt"]);
        git(&worktree, &["commit", "-m", "unexpected worktree advance"]);
        let result = ensure_worker_worktree_at_expected_head(
            &worktree,
            &published_head,
            observe,
            "Worker rework worktree changed after publication authorization",
        );
        assert_eq!(
            result.unwrap_err(),
            "Worker rework worktree changed after publication authorization"
        );
    }
}

fn validate_worker_recovery_assignment(
    authorization: Option<&crate::engine::orchestration::WorkerRecoveryAuthorization>,
    plan: &crate::store::accepted_plans::AcceptedWorkPlanRecord,
    node: &crate::engine::orchestration::ValidatedWorkNode,
    assigned_expected_head: &str,
    ticket_run_id: &crate::domain::ids::TicketRunId,
    ticket_revision: u64,
) -> Result<(), String> {
    if let Some(authorization) = authorization {
        authorization.validate()?;
        if authorization.ticket_run_id != *ticket_run_id
            || authorization.ticket_revision != ticket_revision
            || authorization.work_node_id != node.id
            || authorization.accepted_plan_digest != plan.plan_digest
            || node.role != Role::Worker
            || (authorization.prior_host_commit_operation_id.is_none()
                && authorization.expected_head != assigned_expected_head)
        {
            return Err(
                "Worker recovery authority differs from its accepted plan assignment".into(),
            );
        }
    }
    Ok(())
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
    fn retained_commit_requires_the_exact_durable_recovery_receipt() {
        use crate::delivery_runtime::{
            CommitWorkerManifestEffectPayload, CommitWorkerManifestEffectReceipt,
            canonical_delivery_payload,
        };
        use crate::store::{
            EffectIntent, EffectOutcome, ExpectedRevision, OwnerMetadata, ProjectRecord,
        };
        let temp = tempfile::tempdir().unwrap();
        let mut store = ConfigStore::open_test(temp.path()).unwrap();
        let applied = crate::config::load(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/fixture/config.toml"),
        )
        .unwrap();
        let revision = store
            .apply_snapshot("retained-commit", &applied, ExpectedRevision::Bootstrap)
            .unwrap();
        let project_id = ProjectId::parse("retained-project").unwrap();
        store
            .insert_project(&ProjectRecord {
                id: project_id.clone(),
                config_source: "retained-commit".into(),
                config_revision: revision.revision,
                config_digest: applied.digest.clone(),
                mode: "operations".into(),
                goal_revision: 0,
                desired_lifecycle: "running".into(),
                state_revision: crate::domain::ids::Revision(0),
            })
            .unwrap();
        let generation = store
            .start_owner(&OwnerMetadata {
                owner_nonce: "retained-owner".into(),
                state_root: temp.path().display().to_string(),
                config_source: "retained-commit".into(),
                process_start_identity: "fixture-owner".into(),
                executable_path: "/fixture/rex-projects".into(),
                executable_digest: "a".repeat(64),
                rex_endpoint: None,
                rex_server_identity: None,
                rex_session_id: None,
                rex_block_id: None,
            })
            .unwrap();
        let payload: CommitWorkerManifestEffectPayload = serde_json::from_value(serde_json::json!({
            "schema_version":1, "agent_run_id":"prior-worker", "project_id":project_id,
            "message_id":"commit-request", "configuration_digest":applied.digest,
            "ticket_revision":3, "ticket_namespace":"fixture", "ticket_id":"50",
            "ticket_run_id":"retained-run", "work_node_id":"docs", "repository_id":"repo-a",
            "worktree_path":"/fixture/worktree", "branch":"rex-projects/docs",
            "prepare_operation_id":"prepare-docs", "expected_base_sha":"a".repeat(40),
            "expected_head":"a".repeat(40),
                "manifest_artifact":{"artifact_id":"7".repeat(64), "kind":"change",
                "schema_version":1,"path":"prior-worker/change.json","digest":"b".repeat(64),"bytes":50},
            "manifest_digest":"c".repeat(64),
            "manifest":{"schema_version":1,"entries":[{"kind":"delete","path":"old.md"}]},
            "commit_message":"docs: clarify adapter setup", "required_trailer":"Co-authored-by: Codex <noreply@openai.com>"
        })).unwrap();
        let receipt = CommitWorkerManifestEffectReceipt {
            schema_version: 1,
            agent_run_id: payload.agent_run_id.clone(),
            message_id: payload.message_id.clone(),
            ticket_run_id: payload.ticket_run_id.clone(),
            work_node_id: payload.work_node_id.clone(),
            repository_id: payload.repository_id.clone(),
            base_sha: payload.expected_base_sha.clone(),
            manifest_artifact: payload.manifest_artifact.clone(),
            commit: crate::host_commit::HostCommitReceipt {
                operation_id: crate::domain::ids::OperationId::parse("retained-operation").unwrap(),
                repository_id: payload.repository_id.clone(),
                expected_head: payload.expected_head.clone(),
                observed_head: "d".repeat(40),
                tree: "e".repeat(40),
                manifest_digest: payload.manifest_digest.clone(),
                signature_verified: true,
                hooks_completed: true,
                index_synchronized: true,
                index_sync_conflict: false,
            },
        };
        let receipt_json = serde_json::to_string(&receipt).unwrap();
        let mut recovery = crate::engine::orchestration::WorkerRecoveryAuthorization {
            schema_version: 1,
            ticket_run_id: payload.ticket_run_id.clone(),
            ticket_revision: 3,
            work_node_id: payload.work_node_id.clone(),
            accepted_plan_digest: Digest::parse("f".repeat(64)).unwrap(),
            prior_worker_agent_run_id: payload.agent_run_id.clone(),
            prior_terminal_digest: Digest::parse("1".repeat(64)).unwrap(),
            prior_absence_digest: Digest::parse("2".repeat(64)).unwrap(),
            prior_host_commit_operation_id: Some(receipt.commit.operation_id.clone()),
            prior_host_commit_receipt_digest: Some(digest_bytes(receipt_json.as_bytes()).unwrap()),
            expected_head: receipt.commit.observed_head.clone(),
            source_coordinator_evidence_id: "coordinator-evidence".into(),
            prior_worker_result_evidence_id: "worker-evidence".into(),
            prior_artifact_refs: vec![receipt.manifest_artifact.clone()],
        };
        let (request_json, request_digest) = canonical_delivery_payload(&payload).unwrap();
        store
            .create_ticket_run(
                generation,
                &project_id,
                &payload.ticket_namespace,
                &payload.ticket_id,
                &payload.ticket_run_id,
                1,
                "implementing",
                "In Progress",
            )
            .unwrap();
        store
            .test_connection()
            .execute(
                "UPDATE ticket_runs SET revision=3 WHERE ticket_run_id=?1",
                [payload.ticket_run_id.as_str()],
            )
            .unwrap();
        let intent = EffectIntent {
            project_id: project_id.clone(),
            subject_type: "ticket_run".into(),
            subject_id: payload.ticket_run_id.to_string(),
            operation_id: receipt.commit.operation_id.to_string(),
            logical_key: "retained-commit-docs".into(),
            kind: "commit_worker_manifest".into(),
            request_json,
            request_digest,
            expected_revision: Some(3),
        };
        store.enqueue_effect(generation, &intent).unwrap();
        assert!(
            retained_host_commit(&store, &project_id, &applied.digest, Some(&recovery)).is_err()
        );
        let claim = store
            .claim_next_due_effect(generation, i64::MAX, std::slice::from_ref(&intent.kind))
            .unwrap()
            .unwrap();
        assert_eq!(claim.intent.operation_id, intent.operation_id);
        store
            .finish_effect(
                &intent.operation_id,
                generation,
                EffectOutcome::Succeeded,
                Some(&receipt_json),
            )
            .unwrap();
        assert_eq!(
            retained_host_commit(&store, &project_id, &applied.digest, Some(&recovery)).unwrap(),
            Some(receipt.clone())
        );
        recovery.prior_artifact_refs.clear();
        assert!(
            retained_host_commit(&store, &project_id, &applied.digest, Some(&recovery)).is_err()
        );
        recovery
            .prior_artifact_refs
            .push(receipt.manifest_artifact.clone());
        recovery.ticket_revision += 1;
        assert!(
            retained_host_commit(&store, &project_id, &applied.digest, Some(&recovery)).is_err()
        );
        recovery.ticket_revision -= 1;
        assert!(
            retained_host_commit(
                &store,
                &ProjectId::parse("foreign").unwrap(),
                &applied.digest,
                Some(&recovery)
            )
            .is_err()
        );
        recovery.prior_host_commit_receipt_digest = Some(Digest::parse("9".repeat(64)).unwrap());
        assert!(
            retained_host_commit(&store, &project_id, &applied.digest, Some(&recovery)).is_err()
        );
    }

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

        let context = worker_assignment_context(&WorkerAssignmentContext {
            plan_record: &plan_record,
            validated_plan: &validated,
            node: &node,
            ticket_revision: plan_record.accepted_revision,
            correction_context: None,
            worktree_path: Path::new("/state/worktree"),
            branch: "agent/run-a/worker-b",
            base_sha: &base_sha,
            expected_head: &base_sha,
            host_artifacts: &[],
            verification: None,
            recovery_authorization: None,
            retained_host_commit: None,
            commit_mode: CommitMode::Host,
            repository_id: &repository,
        })
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
        assert_eq!(context["prepared_worktree"]["expected_head"], base_sha);
        assert_eq!(context["prepared_worktree"]["verification_only"], false);
        assert_eq!(context["prepared_worktree"]["repository_id"], "repo-a");
        assert_eq!(
            context["implementation_ready_identity"]["repository"],
            "repo-a"
        );
        assert_eq!(
            context["implementation_ready_identity"]["change_reference_worktree_id"],
            "worker-b"
        );

        let publication_head = "3".repeat(40);
        let verification = WorkerVerificationAssignment {
            publication_revision: 5,
            publication_operation_id: "publish-worker-1".into(),
            published_head: publication_head.clone(),
        };
        let verification_context = worker_assignment_context(&WorkerAssignmentContext {
            plan_record: &plan_record,
            validated_plan: &validated,
            node: &node,
            ticket_revision: plan_record.accepted_revision,
            correction_context: None,
            worktree_path: Path::new("/state/worktree"),
            branch: "agent/run-a/worker-b",
            base_sha: &base_sha,
            expected_head: &publication_head,
            host_artifacts: &[],
            verification: Some(&verification),
            recovery_authorization: None,
            retained_host_commit: None,
            commit_mode: CommitMode::Host,
            repository_id: &repository,
        })
        .unwrap();
        let verification_context: serde_json::Value =
            serde_json::from_str(&verification_context).unwrap();
        assert_eq!(
            verification_context["prepared_worktree"]["verification_only"],
            true
        );
        assert_eq!(
            verification_context["prepared_worktree"]["accepted_publication"]["publication_operation_id"],
            "publish-worker-1"
        );
        assert_eq!(
            verification_context["prepared_worktree"]["accepted_publication"]["publication_revision"],
            5
        );
        assert_eq!(
            verification_context["prepared_worktree"]["accepted_publication"]["published_head"],
            publication_head
        );

        let prior_operation = crate::domain::ids::OperationId::parse("host-commit-prior").unwrap();
        let recovery = crate::engine::orchestration::WorkerRecoveryAuthorization {
            schema_version: 1,
            ticket_run_id: ticket_run_id.clone(),
            ticket_revision: 3,
            work_node_id: crate::engine::orchestration::WorkNodeId::parse("worker-b").unwrap(),
            accepted_plan_digest: plan_record.plan_digest.clone(),
            prior_worker_agent_run_id: AgentRunId::parse("worker-run-prior").unwrap(),
            prior_terminal_digest: Digest::parse("f".repeat(64)).unwrap(),
            prior_absence_digest: Digest::parse("1".repeat(64)).unwrap(),
            prior_host_commit_operation_id: Some(prior_operation.clone()),
            prior_host_commit_receipt_digest: Some(Digest::parse("2".repeat(64)).unwrap()),
            expected_head: "3".repeat(40),
            source_coordinator_evidence_id: "coordinator-evidence".into(),
            prior_worker_result_evidence_id: "worker-evidence".into(),
            prior_artifact_refs: Vec::new(),
        };
        let retained: crate::delivery_runtime::CommitWorkerManifestEffectReceipt =
            serde_json::from_value(serde_json::json!({
                "schema_version":1,"agent_run_id":"worker-run-prior","message_id":"prior-commit",
                "ticket_run_id":ticket_run_id,"work_node_id":"worker-b","repository_id":repository,
                "base_sha":base_sha,
                "manifest_artifact":{"artifact_id":"7".repeat(64),"kind":"change","schema_version":1,
                    "path":"worker-run-prior/change.json","digest":"4".repeat(64),"bytes":100},
                "commit":{"operation_id":prior_operation,"repository_id":repository,
                    "expected_head":base_sha,"observed_head":recovery.expected_head,"tree":"5".repeat(40),
                    "manifest_digest":"6".repeat(64),"signature_verified":true,"hooks_completed":true,
                    "index_synchronized":true,"index_sync_conflict":false}
            })).unwrap();
        let recovery_context = worker_assignment_context(&WorkerAssignmentContext {
            plan_record: &plan_record,
            validated_plan: &validated,
            node: &node,
            ticket_revision: plan_record.accepted_revision,
            correction_context: None,
            worktree_path: Path::new("/state/worktree"),
            branch: "agent/run-a/worker-b",
            base_sha: &base_sha,
            expected_head: &recovery.expected_head,
            host_artifacts: &[],
            verification: None,
            recovery_authorization: Some(&recovery),
            retained_host_commit: Some(&retained),
            commit_mode: CommitMode::Host,
            repository_id: &repository,
        })
        .unwrap();
        let context_directory = tempfile::tempdir().unwrap();
        let assignment_path = context_directory.path().join("worker-assignment.json");
        std::fs::write(&assignment_path, recovery_context).unwrap();
        let recovery_context: serde_json::Value =
            serde_json::from_slice(&std::fs::read(assignment_path).unwrap()).unwrap();
        assert_eq!(recovery_context["prepared_worktree"]["base_sha"], base_sha);
        assert_eq!(
            recovery_context["prepared_worktree"]["expected_head"],
            recovery.expected_head
        );
        assert_eq!(
            recovery_context["prepared_worktree"]["verification_only"],
            false
        );
        assert_eq!(
            recovery_context["retained_host_commit"]["commit"]["operation_id"],
            prior_operation.as_str()
        );
        assert_eq!(
            recovery_context["implementation_ready_identity"]["change_reference_worktree_id"],
            "worker-b"
        );
        assert_eq!(
            recovery_context["retained_host_commit"]["manifest_artifact"]["path"],
            retained.manifest_artifact.path
        );
        assert_eq!(
            recovery_context["worker_recovery_authorization"]["prior_worker_agent_run_id"],
            "worker-run-prior"
        );
        assert_eq!(
            recovery_context["worker_recovery_authorization"]["prior_host_commit_operation_id"],
            prior_operation.as_str()
        );
        validate_worker_recovery_assignment(
            Some(&recovery),
            &plan_record,
            &node,
            &recovery.expected_head,
            &ticket_run_id,
            3,
        )
        .unwrap();
        assert!(
            validate_worker_recovery_assignment(
                Some(&recovery),
                &plan_record,
                &node,
                &recovery.expected_head,
                &ticket_run_id,
                4,
            )
            .is_err()
        );
        let mut correction_recovery = recovery.clone();
        correction_recovery.prior_host_commit_operation_id = None;
        correction_recovery.prior_host_commit_receipt_digest = None;
        assert_ne!(correction_recovery.expected_head, base_sha);
        validate_worker_recovery_assignment(
            Some(&correction_recovery),
            &plan_record,
            &node,
            &correction_recovery.expected_head,
            &ticket_run_id,
            3,
        )
        .expect("no-commit recovery remains bound to the published expected HEAD");
        assert!(
            validate_worker_recovery_assignment(
                Some(&correction_recovery),
                &plan_record,
                &node,
                &base_sha,
                &ticket_run_id,
                3,
            )
            .is_err()
        );

        let wake = crate::store::agent_runtime::PendingRoleWakeInput {
            wake_input_id: 1,
            source_type: "worker_recovery_authorization".into(),
            source_id: recovery.prior_worker_result_evidence_id.clone(),
            source_revision: 3,
            priority: 10,
            payload_json: serde_json::json!({"authorization": recovery}),
        };
        assert!(
            worker_recovery_authorization_from_inputs(
                std::slice::from_ref(&wake),
                Role::Worker,
                &ticket_run_id,
                3,
                Some(&node.id),
                Some(&plan_record),
            )
            .unwrap()
            .is_some()
        );
        let mut stale_wake = wake;
        stale_wake.source_revision = 2;
        assert!(
            worker_recovery_authorization_from_inputs(
                &[stale_wake],
                Role::Worker,
                &ticket_run_id,
                3,
                Some(&node.id),
                Some(&plan_record),
            )
            .is_err()
        );
    }
}
