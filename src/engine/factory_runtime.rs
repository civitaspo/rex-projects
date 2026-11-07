//! Runtime decisions shared by the Project scheduler and TicketRun controller.
//!
//! This module contains no provider, Rex, or SQLite calls. Callers persist each
//! returned decision before performing its effects.

use std::collections::{BTreeSet, HashMap};

use crate::agent_recovery::AgentRecoveryReport;
use crate::config::{Config, ProjectConfig};
use crate::domain::ids::{Digest, OperationId, ProjectId, Revision, TicketNamespace, TicketRunId};
use crate::domain::types::{ProjectMode, Role, TicketStatus};
use crate::effects::{DispatchTick, EffectDispatcher, EffectHandler, EffectLimits};
use crate::engine::reducer::{Activity, Input, Phase, TicketRun};
use crate::store::scheduler::RunnableProject;
use crate::store::scheduler::{
    ObservedTicket, PendingRoleWakeSession, TicketObservationClassification, TicketScanKey,
};
use crate::store::{ConfigStore, DurableInput, EffectIntent, durable_input_digest};

/// Result of matching a normalized ticket to the configured Project policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TicketDisposition {
    /// The ticket is eligible to become a TicketRun.
    Dispatch { recipe_id: Option<String> },
    /// The ticket remains untouched until a human resolves a policy question.
    AwaitHuman { reason: String },
    /// The ticket is intentionally outside the configured dispatch states.
    Skip,
}

/// Resolve an Operations Project's recipe without relying on TOML declaration
/// order. Goal Projects always use their goal pipeline instead of label recipes.
pub fn ticket_disposition(
    config: &Config,
    project: &ProjectConfig,
    status: TicketStatus,
    labels: &BTreeSet<String>,
) -> TicketDisposition {
    if !project.dispatch_states.contains(&status) {
        return TicketDisposition::Skip;
    }
    if project.mode == ProjectMode::Goal {
        return TicketDisposition::Dispatch { recipe_id: None };
    }

    let matches: Vec<_> = project
        .operation_matches
        .iter()
        .filter(|rule| rule.labels_all.iter().all(|label| labels.contains(label)))
        .collect();
    match matches.as_slice() {
        [] => TicketDisposition::AwaitHuman {
            reason: "no Operations recipe matches the ticket labels".into(),
        },
        [rule] if config.operation_recipes.contains_key(&rule.recipe) => {
            let recipe = &config.operation_recipes[&rule.recipe];
            if recipe.targets.iter().any(|target| {
                !project.repositories.contains(&target.repository)
                    || config
                        .repositories
                        .get(&target.repository)
                        .and_then(|repository| repository.operations.as_ref())
                        .is_none_or(|policy| !policy.allowed_actions.contains(&target.action))
                    || !config.operation_actions.contains_key(&target.action)
            }) {
                TicketDisposition::AwaitHuman {
                    reason: "the selected recipe references an action or repository outside Project policy".into(),
                }
            } else {
                TicketDisposition::Dispatch {
                    recipe_id: Some(rule.recipe.clone()),
                }
            }
        }
        [_] => TicketDisposition::AwaitHuman {
            reason: "the selected Operations recipe is not configured".into(),
        },
        _ => TicketDisposition::AwaitHuman {
            reason: "multiple Operations recipes match the ticket labels".into(),
        },
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalTicketPage {
    pub tickets: Vec<ObservedTicket>,
    pub next_cursor: Option<String>,
}

/// Host adapters implement this port with the configured ticket CLI and a
/// pinned namespace. No authentication state is supplied by rex-projects.
pub trait FactoryRuntimeServices {
    /// Process at most one active-run request from the run-local mailbox spool. The host verifies
    /// the request against the persisted launch authority before acknowledging it.
    fn process_one_agent_request(
        &mut self,
        store: &mut ConfigStore,
        owner_generation: u64,
        now_unix: i64,
    ) -> Result<bool, String>;

    fn recover_agents(
        &mut self,
        store: &mut ConfigStore,
        owner_generation: u64,
        now_unix: i64,
    ) -> Result<AgentRecoveryReport, String>;
    /// Import and validate at most one completed mailbox result, then commit
    /// its typed reducer transition through the runtime's durable boundary.
    fn ingest_one_agent_result(
        &mut self,
        store: &mut ConfigStore,
        owner_generation: u64,
        now_unix: i64,
    ) -> Result<Option<crate::store::agent_results::IngestedAgentResult>, String>;

    fn observe_base_heads(
        &mut self,
    ) -> Result<std::collections::BTreeMap<crate::domain::ids::RepositoryId, String>, String>;

    fn configuration_digest(&self) -> &Digest;

    fn profile_commit_mode(
        &self,
        project_id: &ProjectId,
        role: Role,
    ) -> Result<crate::domain::types::CommitMode, String>;

    /// Build a typed publication intent from a completed Worker result plus the
    /// accepted plan and host-minted prepared-worktree authority.
    fn worker_publication_effect(
        &mut self,
        store: &mut ConfigStore,
        owner_generation: u64,
        now_unix: i64,
        config: &Config,
        run: &crate::store::scheduler::ActiveTicketRun,
        result: &crate::store::agent_results::IngestedAgentResult,
        effect_revision: u64,
    ) -> Result<Option<EffectIntent>, String>;

    /// Accept at most one due profile-trial approval or queue its next run/side.
    /// Implementations reserve from the same bounded execution-slot pool as Agent launches.
    fn tick_profile_trials(
        &mut self,
        store: &mut ConfigStore,
        owner_generation: u64,
        now_unix: i64,
        max_agent_slots: u32,
        max_project_slots: u32,
    ) -> Result<(), String>;

    fn ticket_namespace(
        &mut self,
        adapter: &crate::domain::ids::AdapterId,
    ) -> Result<TicketNamespace, String>;

    fn list_ticket_page(
        &mut self,
        key: &TicketScanKey,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<ExternalTicketPage, String>;

    /// Reconcile a bounded number of externally published pull requests against
    /// their persisted host receipts. Unknown observations must remain durable
    /// and must not fail the foreground loop.
    fn observe_publications(
        &mut self,
        store: &mut ConfigStore,
        owner_generation: u64,
        now_unix: i64,
    ) -> Result<crate::runtime_delivery::PublicationMonitorTick, String>;

    /// Build and durably prepare at most one finite-turn launch for this exact
    /// pending role session. The Store implementation must recheck the wake
    /// set, project epoch, active-run state, and slot capacity atomically.
    /// Returning `false` means the candidate is no longer launchable; it must
    /// leave its wake inputs pending.
    fn prepare_role_launch(
        &mut self,
        store: &mut ConfigStore,
        owner_generation: u64,
        config: &Config,
        candidate: &PendingRoleWakeSession,
        now_unix: i64,
    ) -> Result<bool, String>;

    fn effect_handlers(&self) -> Vec<&dyn EffectHandler>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FactoryTickReport {
    pub ingested_agent_result: bool,
    pub agent_recovery: AgentRecoveryReport,
    pub publication_monitor: crate::runtime_delivery::PublicationMonitorTick,
    pub effect: DispatchTick,
    pub role_run_started: bool,
    pub supervisor_learning_project: Option<ProjectId>,
    pub scanned: Option<TicketScanKey>,
    pub ticket_run_started: Option<TicketRunId>,
    /// Recoverable external CLI failures observed this tick. These are
    /// reported to the controller while unrelated Projects continue.
    pub external_errors: Vec<String>,
}

/// One bounded foreground controller iteration. Results and one outbox effect
/// get priority over a new external scan; no iteration reads more than one
/// ticket page or starts more than one TicketRun.
pub struct FactoryRuntime;

impl FactoryRuntime {
    pub fn tick(
        store: &mut ConfigStore,
        owner_generation: u64,
        now_unix: i64,
        config: &Config,
        services: &mut impl FactoryRuntimeServices,
    ) -> Result<FactoryTickReport, String> {
        store.activate_starting_projects(owner_generation)?;
        let _processed_agent_request =
            services.process_one_agent_request(store, owner_generation, now_unix)?;
        let agent_result = services.ingest_one_agent_result(store, owner_generation, now_unix)?;
        let ingested_agent_result = if let Some(result) = &agent_result {
            apply_agent_result(store, owner_generation, now_unix, config, services, result)?
        } else {
            false
        };
        let publication_monitor =
            services.observe_publications(store, owner_generation, now_unix)?;
        let agent_recovery = services.recover_agents(store, owner_generation, now_unix)?;
        let learning_now_unix =
            u64::try_from(now_unix).map_err(|_| "controller clock is before the Unix epoch")?;
        let profile_trial_capacity = u32::try_from(config.runtime.max_agent_runs)
            .map_err(|_| "runtime.max_agent_runs exceeds the supported slot count")?;
        let _queued_profile_trial = store.tick_profile_trials(
            owner_generation,
            learning_now_unix,
            profile_trial_capacity,
            profile_trial_capacity,
        )?;
        let handlers = services.effect_handlers();
        let limits = EffectLimits {
            max_attempts: 100,
            max_age: std::time::Duration::from_secs(30 * 24 * 60 * 60),
            retry_base: std::time::Duration::from_secs(2),
            retry_max: std::time::Duration::from_secs(15 * 60),
        };
        let effect = EffectDispatcher::tick(store, owner_generation, now_unix, &handlers, limits)
            .map_err(|error| error.to_string())?;
        // Handler return values are not workflow proof. Consume only persisted
        // succeeded receipts and commit their typed transition before choosing
        // the next role wake.
        let _host_transition_applied = super::host_transitions::consume_one_host_transition(
            store,
            owner_generation,
            now_unix,
            config,
            services.configuration_digest(),
        )?;

        // A result or an already-persisted effect is processed before another
        // role turn. Launch preparation is bounded to one successful turn and
        // a finite candidate window so one stale/unlaunchable wake cannot
        // monopolize the foreground machine controller.
        let candidates = store.pending_role_wake_sessions(owner_generation, 32)?;
        let mut role_run_started = false;
        for candidate in &candidates {
            if !config.projects.contains_key(&candidate.project_id) {
                continue;
            }
            if services.prepare_role_launch(store, owner_generation, config, candidate, now_unix)? {
                role_run_started = true;
                break;
            }
        }

        let runnable = store.runnable_projects(owner_generation)?;
        let configured_projects = config.projects.keys().cloned().collect::<Vec<_>>();
        let learning_interval = config
            .learning
            .review_interval_hours
            .checked_mul(60 * 60)
            .ok_or("learning review interval exceeds supported range")?;
        let supervisor_learning_project = store.queue_due_supervisor_learning(
            owner_generation,
            &configured_projects,
            now_unix,
            learning_interval,
            12,
        )?;
        let (keys, mut external_errors) = build_scan_keys(config, &runnable, services);
        if let Some(key) = next_pending_candidate_key(store, &runnable, config, &keys)? {
            if let Some((project_run, disposition)) =
                next_disposition(store, config, &runnable, &key)?
            {
                let ticket_id = project_run.ticket_id;
                let is_dispatch = matches!(&disposition, TicketDisposition::Dispatch { .. });
                let recipe_id = match &disposition {
                    TicketDisposition::Dispatch { recipe_id } => recipe_id.clone(),
                    TicketDisposition::AwaitHuman { reason } => {
                        store.classify_ticket_observation(
                            owner_generation,
                            &key,
                            &ticket_id,
                            TicketObservationClassification::Human,
                            reason,
                            now_unix,
                        )?;
                        None
                    }
                    TicketDisposition::Skip => {
                        store.classify_ticket_observation(
                            owner_generation,
                            &key,
                            &ticket_id,
                            TicketObservationClassification::Ignored,
                            "ticket status is outside configured dispatch policy",
                            now_unix,
                        )?;
                        None
                    }
                };
                let ticket_run_started = if is_dispatch {
                    store.create_dispatched_ticket_run(
                        owner_generation,
                        &key,
                        &ticket_id,
                        recipe_id.as_deref(),
                        &config.projects[&key.project_id].dispatch_states,
                        config.projects[&key.project_id].max_active_tickets,
                        now_unix,
                    )?
                } else {
                    None
                };
                store.mark_ticket_scan_served(owner_generation, &key)?;
                return Ok(FactoryTickReport {
                    ingested_agent_result,
                    agent_recovery,
                    publication_monitor,
                    effect,
                    role_run_started,
                    supervisor_learning_project,
                    scanned: None,
                    ticket_run_started,
                    external_errors,
                });
            }
        }

        let Some((key, cursor)) = store.next_due_ticket_scan(&keys, now_unix)? else {
            return Ok(FactoryTickReport {
                ingested_agent_result,
                agent_recovery,
                publication_monitor,
                effect,
                role_run_started,
                supervisor_learning_project,
                scanned: None,
                ticket_run_started: None,
                external_errors,
            });
        };
        let page = match services.list_ticket_page(&key, cursor.cursor.as_deref(), 100) {
            Ok(page) => page,
            Err(error) => {
                store.defer_ticket_scan_after_error(
                    owner_generation,
                    &key,
                    cursor.cursor.as_deref(),
                    cursor.generation,
                    cursor.page_count,
                    now_unix,
                    config.runtime.external_poll_seconds.clamp(2, 3600),
                )?;
                external_errors.push(error);
                return Ok(FactoryTickReport {
                    ingested_agent_result,
                    agent_recovery,
                    publication_monitor,
                    effect,
                    role_run_started,
                    supervisor_learning_project,
                    scanned: None,
                    ticket_run_started: None,
                    external_errors,
                });
            }
        };
        if page.tickets.len() > 100
            || page
                .tickets
                .iter()
                .any(|ticket| ticket.status != key.status)
        {
            return Err(
                "ticket adapter returned an oversized page or status outside the requested filter"
                    .into(),
            );
        }
        store.record_ticket_scan_page(
            owner_generation,
            &key,
            cursor.cursor.as_deref(),
            cursor.generation,
            cursor.page_count,
            page.next_cursor.as_deref(),
            &page.tickets,
            now_unix,
            config.runtime.external_poll_seconds,
        )?;
        Ok(FactoryTickReport {
            ingested_agent_result,
            agent_recovery,
            publication_monitor,
            effect,
            role_run_started,
            supervisor_learning_project,
            scanned: Some(key),
            ticket_run_started: None,
            external_errors,
        })
    }
}

fn apply_agent_result(
    store: &mut ConfigStore,
    owner_generation: u64,
    now_unix: i64,
    config: &Config,
    services: &mut impl FactoryRuntimeServices,
    result: &crate::store::agent_results::IngestedAgentResult,
) -> Result<bool, String> {
    use crate::engine::orchestration::{RoleOutputKind, RoleResultPayload, WorkBaseSource};

    let binding = &result.validated.binding;
    if result.validated.kind == RoleOutputKind::ImplementationReady
        && binding.role == Role::Worker
        && result.validated.assertion == crate::engine::orchestration::AgentAssertion::Succeeded
    {
        return apply_worker_result(store, owner_generation, now_unix, config, services, result);
    }
    if result.validated.kind != RoleOutputKind::PlanReady
        || binding.role != Role::Coordinator
        || binding.ticket_run_id.is_none()
        || result.validated.assertion != crate::engine::orchestration::AgentAssertion::Succeeded
    {
        // Other role results remain durable claims and are delivered through
        // the persisted parent wake. They cannot directly advance reducer state.
        let revision = binding
            .ticket_revision
            .map(|revision| revision.0)
            .unwrap_or(binding.config_revision.0);
        store.acknowledge_validated_agent_result(
            owner_generation,
            result.receipt.evidence_id(),
            revision.max(1),
            crate::store::agent_results::ResultDisposition::RetainedAsClaim,
        )?;
        return Ok(false);
    }
    let ticket_run_id = binding
        .ticket_run_id
        .as_ref()
        .ok_or("Coordinator PlanReady result lacks TicketRun scope")?;
    let project = config
        .projects
        .get(&binding.project_id)
        .ok_or("Agent result Project is no longer configured")?;
    let project_record = store
        .project(&binding.project_id)?
        .ok_or("Agent result Project has no durable configuration record")?;
    let configuration_digest = services.configuration_digest().clone();
    if project_record.config_digest != configuration_digest
        || binding.config_digest != configuration_digest
        || binding.config_revision != project_record.config_revision
    {
        return Err("Coordinator result belongs to a stale configuration snapshot".into());
    }
    let source_revision = binding
        .ticket_revision
        .ok_or("Coordinator PlanReady result lacks TicketRun revision")?;
    let current = store
        .active_ticket_runs(owner_generation, 128)?
        .into_iter()
        .find(|run| run.ticket_run_id == *ticket_run_id)
        .ok_or("Coordinator PlanReady result references no active TicketRun")?;
    if current.project_id != binding.project_id
        || current.revision != source_revision.0
        || current.phase != Phase::Planning
    {
        return Err("Coordinator PlanReady result is stale or outside Planning".into());
    }
    let RoleResultPayload::PlanReady(proposal) = &result.validated.typed_payload else {
        return Err("validated PlanReady kind has a different typed payload".into());
    };
    let observed_bases = services.observe_base_heads()?;
    let validated = crate::engine::orchestration::validate_work_plan(
        ticket_run_id,
        project,
        proposal.plan.clone(),
        &observed_bases,
    )?;
    let mut work_nodes = Vec::new();
    for node in validated
        .nodes_in_execution_order
        .iter()
        .filter(|node| node.role == Role::Worker)
    {
        // A dependent node must be prepared from its predecessor's validated
        // accepted head. Until that head exists, preparing it from the trunk
        // would violate the plan's declared Git base, so fail closed here.
        let WorkBaseSource::ControllerObservedCommit { commit } = &node.base else {
            return Err(format!(
                "work node {} depends on a predecessor head that is not available before implementation",
                node.id
            ));
        };
        if !config.repositories.contains_key(&node.repository) {
            return Err("validated work node repository is no longer configured".into());
        }
        work_nodes.push(crate::delivery_runtime::PreparedWorktreeNodeRequest {
            work_node_id: node.id.clone(),
            repository_id: node.repository.clone(),
            expected_base_sha: commit.clone(),
            commit_mode: services.profile_commit_mode(&binding.project_id, Role::Worker)?,
        });
    }
    if work_nodes.is_empty() {
        return Err("Coordinator plan contains no implementation Worker nodes".into());
    }
    let accepted_revision = source_revision
        .0
        .checked_add(1)
        .ok_or("TicketRun revision overflow")?;
    let payload = crate::delivery_runtime::PrepareWorktreesEffectPayload {
        schema_version: 1,
        source_revision: accepted_revision,
        configuration_digest: configuration_digest.clone(),
        ticket_namespace: current.namespace,
        ticket_id: current.ticket_id,
        ticket_run_id: ticket_run_id.clone(),
        work_nodes,
    };
    let (request_json, request_digest) =
        crate::delivery_runtime::canonical_delivery_payload(&payload)?;
    let operation_id = OperationId::parse(format!("prepare-{}", result.receipt.evidence_id()))?;
    let effect = EffectIntent {
        project_id: binding.project_id.clone(),
        subject_type: "ticket_run".into(),
        subject_id: ticket_run_id.as_str().into(),
        operation_id: operation_id.as_str().to_owned(),
        logical_key: format!("{}:prepare:{}", ticket_run_id, result.receipt.evidence_id()),
        kind: crate::engine::reducer::effect_name(
            &crate::engine::reducer::EffectKind::PrepareWorktrees,
        )
        .into(),
        request_json,
        request_digest,
        expected_revision: Some(accepted_revision),
    };
    let input_payload = serde_json::json!({
        "schema_version": 1,
        "kind": "plan_accepted",
        "evidence_id": result.receipt.evidence_id(),
        "result_digest": result.validated.result_digest,
        "source_revision": source_revision.0,
        "accepted_revision": accepted_revision,
    })
    .to_string();
    let durable = DurableInput {
        producer_id: "rex-projects-agent-result".into(),
        message_id: format!("plan-ready:{}", result.receipt.evidence_id()),
        content_digest: durable_input_digest("ticket_run", &input_payload),
        recipient: "ticket_run".into(),
        payload: input_payload.clone(),
    };
    store.commit_validated_work_plan(
        owner_generation,
        ticket_run_id,
        Revision(source_revision.0),
        &configuration_digest,
        &validated,
        result,
        &durable,
        "host validated Coordinator PlanReady against current Project configuration and observed repository bases",
        &input_payload,
        &[effect],
    )?;
    store.acknowledge_validated_agent_result(
        owner_generation,
        result.receipt.evidence_id(),
        accepted_revision,
        crate::store::agent_results::ResultDisposition::Applied,
    )?;
    let _ = now_unix;
    Ok(true)
}

fn apply_worker_result(
    store: &mut ConfigStore,
    owner_generation: u64,
    now_unix: i64,
    config: &Config,
    services: &mut impl FactoryRuntimeServices,
    result: &crate::store::agent_results::IngestedAgentResult,
) -> Result<bool, String> {
    use crate::engine::orchestration::RoleResultPayload;

    let binding = &result.validated.binding;
    let ticket_run_id = binding
        .ticket_run_id
        .as_ref()
        .ok_or("Worker ImplementationReady result lacks TicketRun scope")?;
    let expected_revision = binding
        .ticket_revision
        .ok_or("Worker ImplementationReady result lacks TicketRun revision")?;
    let run = store
        .active_ticket_runs(owner_generation, 128)?
        .into_iter()
        .find(|run| run.ticket_run_id == *ticket_run_id)
        .ok_or("Worker result references no active TicketRun")?;
    if run.project_id != binding.project_id
        || run.revision != expected_revision.0
        || run.phase != Phase::Implementing
    {
        return Err("Worker ImplementationReady result is stale or outside Implementing".into());
    }
    let project_record = store
        .project(&binding.project_id)?
        .ok_or("Worker result Project has no durable configuration record")?;
    let configuration_digest = services.configuration_digest().clone();
    if project_record.config_digest != configuration_digest
        || binding.config_digest != configuration_digest
        || binding.config_revision != project_record.config_revision
    {
        return Err("Worker result belongs to a stale configuration snapshot".into());
    }
    let RoleResultPayload::ImplementationReady(_claim) = &result.validated.typed_payload else {
        return Err("validated ImplementationReady kind has a different typed payload".into());
    };
    let effect_revision = run
        .revision
        .checked_add(1)
        .ok_or("TicketRun revision overflow")?;
    let effect = services.worker_publication_effect(
        store,
        owner_generation,
        now_unix,
        config,
        &run,
        result,
        effect_revision,
    )?;
    let Some(effect) = effect else {
        // An external observation can be temporarily unavailable. Keep the
        // result durable and unacknowledged so a later foreground tick retries.
        return Ok(false);
    };
    let input_payload = serde_json::json!({
        "schema_version": 1,
        "kind": "worker_implementation_ready",
        "evidence_id": result.receipt.evidence_id(),
        "result_digest": result.validated.result_digest,
        "source_revision": run.revision,
        "publication_operation_id": effect.operation_id,
    })
    .to_string();
    let durable = DurableInput {
        producer_id: "rex-projects-agent-result".into(),
        message_id: format!("implementation-ready:{}", result.receipt.evidence_id()),
        content_digest: durable_input_digest("ticket_run", &input_payload),
        recipient: "ticket_run".into(),
        payload: input_payload.clone(),
    };
    store.commit_ticket_transition(
        owner_generation,
        ticket_run_id,
        Revision(run.revision),
        &durable,
        Input::EvidenceSubmitted,
        "host bound Worker output to its accepted work node and prepared repository before publication",
        &input_payload,
        &[effect],
    )?;
    store.acknowledge_validated_agent_result(
        owner_generation,
        result.receipt.evidence_id(),
        effect_revision,
        crate::store::agent_results::ResultDisposition::Applied,
    )?;
    Ok(true)
}

fn build_scan_keys(
    config: &Config,
    projects: &[RunnableProject],
    services: &mut impl FactoryRuntimeServices,
) -> (Vec<TicketScanKey>, Vec<String>) {
    let mut keys = Vec::new();
    let mut errors = Vec::new();
    let mut namespaces = HashMap::<crate::domain::ids::AdapterId, TicketNamespace>::new();
    for runtime_project in projects {
        let Some(project) = config.projects.get(&runtime_project.record.id) else {
            continue;
        };
        let namespace = if let Some(namespace) = namespaces.get(&project.ticket_adapter) {
            namespace.clone()
        } else {
            let namespace = match services.ticket_namespace(&project.ticket_adapter) {
                Ok(namespace) => namespace,
                Err(error) => {
                    errors.push(error);
                    continue;
                }
            };
            namespaces.insert(project.ticket_adapter.clone(), namespace.clone());
            namespace
        };
        for status in &project.dispatch_states {
            match TicketScanKey::for_project(
                &runtime_project.record.id,
                &project.ticket_adapter,
                &namespace,
                project,
                *status,
            ) {
                Ok(key) => keys.push(key),
                Err(error) => errors.push(error),
            }
        }
    }
    (keys, errors)
}

struct PendingCandidate {
    ticket_id: crate::domain::ids::TicketId,
}

fn next_pending_candidate_key(
    store: &ConfigStore,
    projects: &[RunnableProject],
    config: &Config,
    keys: &[TicketScanKey],
) -> Result<Option<TicketScanKey>, String> {
    let mut candidates = Vec::new();
    for key in keys {
        let project = &config.projects[&key.project_id];
        if !store.project_has_ticket_capacity(&key.project_id, project.max_active_tickets)? {
            continue;
        }
        if store.pending_ticket_observations(key, 1)?.is_empty() {
            continue;
        }
        candidates.push((key.clone(), store.ticket_scan_cursor(key)?));
    }
    let _ = projects;
    candidates.sort_by(|(left_key, left), (right_key, right)| {
        (
            left.last_served_sequence,
            left.next_due_at_unix,
            left_key.project_id.as_str(),
            status_sort_key(left_key.status),
        )
            .cmp(&(
                right.last_served_sequence,
                right.next_due_at_unix,
                right_key.project_id.as_str(),
                status_sort_key(right_key.status),
            ))
    });
    Ok(candidates.into_iter().next().map(|(key, _)| key))
}

fn next_disposition(
    store: &ConfigStore,
    config: &Config,
    _projects: &[RunnableProject],
    key: &TicketScanKey,
) -> Result<Option<(PendingCandidate, TicketDisposition)>, String> {
    let project = config
        .projects
        .get(&key.project_id)
        .ok_or_else(|| "runnable Project is missing from the applied configuration".to_owned())?;
    let Some(ticket) = store
        .pending_ticket_observations(key, 1)?
        .into_iter()
        .next()
    else {
        return Ok(None);
    };
    let labels = ticket.labels.iter().cloned().collect::<BTreeSet<_>>();
    let disposition = ticket_disposition(config, project, ticket.status, &labels);
    Ok(Some((
        PendingCandidate {
            ticket_id: ticket.ticket_id,
        },
        disposition,
    )))
}

fn status_sort_key(status: TicketStatus) -> u8 {
    match status {
        TicketStatus::Triage => 0,
        TicketStatus::Backlog => 1,
        TicketStatus::Ready => 2,
        TicketStatus::InProgress => 3,
        TicketStatus::InReview => 4,
        TicketStatus::Done => 5,
        TicketStatus::Canceled => 6,
    }
}

/// Stable identity for an autonomous goal-ticket proposal. The durable v9
/// ledger reserves this key before submitting a create effect, so retries and
/// controller restarts reuse one request instead of creating another ticket.
pub fn goal_ticket_request_key(
    project: &ProjectId,
    goal_revision: u64,
    title: &str,
    body: &str,
    labels: &BTreeSet<String>,
) -> Result<String, String> {
    let title = title.split_whitespace().collect::<Vec<_>>().join(" ");
    let body = body.replace("\r\n", "\n").replace('\r', "\n");
    if goal_revision == 0 || title.is_empty() || title.len() > 512 || body.len() > 65_536 {
        return Err("goal ticket proposal is outside configured size limits".into());
    }
    if labels.len() > 128
        || labels
            .iter()
            .any(|label| label.trim().is_empty() || label.len() > 128)
    {
        return Err("goal ticket proposal labels are invalid".into());
    }
    let canonical = serde_json::json!({
        "project_id": project.as_str(),
        "goal_revision": goal_revision,
        "title": title,
        "body": body,
        "labels": labels,
    });
    let bytes = serde_json::to_vec(&canonical).map_err(|error| error.to_string())?;
    use sha2::Digest as _;
    Ok(format!("goal-{:x}", sha2::Sha256::digest(bytes)))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GoalTicketAdmission {
    Reserve { request_key: String },
    ReuseExisting,
    LimitReached,
}

/// Apply the Project's per-goal-revision creation cap. The Store repeats this
/// decision in the same transaction that reserves the external create effect.
pub fn goal_ticket_admission(
    request_key: &str,
    request_digest: &str,
    existing_digest: Option<&str>,
    already_reserved: usize,
    maximum: usize,
) -> Result<GoalTicketAdmission, String> {
    if let Some(existing) = existing_digest {
        return if existing == request_digest {
            Ok(GoalTicketAdmission::ReuseExisting)
        } else {
            Err("goal ticket request key is already bound to different content".into())
        };
    }
    if request_key.is_empty() || request_digest.is_empty() || maximum == 0 {
        return Err("goal ticket admission request is invalid".into());
    }
    if already_reserved >= maximum {
        return Ok(GoalTicketAdmission::LimitReached);
    }
    Ok(GoalTicketAdmission::Reserve {
        request_key: request_key.to_owned(),
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GoalTicketProposal {
    pub title: String,
    pub body: String,
    pub labels: BTreeSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedGoalTicket {
    pub request_key: String,
    pub request_digest: String,
    pub proposal: GoalTicketProposal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GoalSupervisorAction {
    Create(Vec<PreparedGoalTicket>),
    RequestCompletionConfirmation,
    Idle,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum GoalTicketMatchBasis {
    OperationId,
    StableExternalKey,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GoalTicketCandidate {
    pub ticket_id: String,
    pub match_basis: GoalTicketMatchBasis,
    pub created_at: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalGoalTicket {
    pub canonical_ticket_id: String,
    pub duplicate_ticket_ids: Vec<String>,
}

/// Canonicalize multiple receipts for one stable create key. Prefer an exact
/// operation-ID match, then the earliest provider creation time, then ticket
/// ID. Every other candidate is returned for explicit duplicate comment and
/// Canceled resolution through a durable ticket effect.
pub fn canonicalize_goal_ticket_candidates(
    candidates: &[GoalTicketCandidate],
) -> Result<CanonicalGoalTicket, String> {
    if candidates.is_empty() {
        return Err("goal ticket create has no matching candidate".into());
    }
    if candidates
        .iter()
        .any(|candidate| candidate.ticket_id.trim().is_empty())
    {
        return Err("goal ticket candidate has an empty ID".into());
    }
    let mut unique = std::collections::BTreeMap::<String, GoalTicketCandidate>::new();
    for candidate in candidates {
        unique
            .entry(candidate.ticket_id.clone())
            .and_modify(|existing| {
                if (
                    candidate.match_basis,
                    candidate.created_at.as_deref().unwrap_or("~"),
                ) < (
                    existing.match_basis,
                    existing.created_at.as_deref().unwrap_or("~"),
                ) {
                    *existing = candidate.clone();
                }
            })
            .or_insert_with(|| candidate.clone());
    }
    let mut sorted = unique.into_values().collect::<Vec<_>>();
    sorted.sort_by(|left, right| {
        (
            left.match_basis,
            left.created_at.as_deref().unwrap_or("~"),
            &left.ticket_id,
        )
            .cmp(&(
                right.match_basis,
                right.created_at.as_deref().unwrap_or("~"),
                &right.ticket_id,
            ))
    });
    let canonical_ticket_id = sorted[0].ticket_id.clone();
    let duplicate_ticket_ids = sorted
        .iter()
        .skip(1)
        .map(|candidate| candidate.ticket_id.clone())
        .collect();
    Ok(CanonicalGoalTicket {
        canonical_ticket_id,
        duplicate_ticket_ids,
    })
}

/// Bound autonomous ticket creation to the configured active-run and
/// per-goal-revision limits. A completion claim stops new creates and always
/// asks a human for final confirmation; it never changes Project state itself.
pub fn bound_goal_supervisor_action(
    project_id: &ProjectId,
    project: &ProjectConfig,
    already_active: usize,
    already_reserved_for_goal: usize,
    completion_claimed: bool,
    proposals: &[GoalTicketProposal],
) -> Result<GoalSupervisorAction, String> {
    if project.mode != ProjectMode::Goal {
        return Err("goal Supervisor action requires a Goal Project".into());
    }
    let goal_revision = project
        .goal
        .as_ref()
        .ok_or_else(|| "Goal Project has no configured goal".to_owned())?
        .revision;
    if completion_claimed {
        return Ok(GoalSupervisorAction::RequestCompletionConfirmation);
    }
    let active_slots = project.max_active_tickets.saturating_sub(already_active);
    let creation_slots = project
        .max_created_tickets_per_goal_revision
        .saturating_sub(already_reserved_for_goal);
    let limit = active_slots.min(creation_slots);
    let mut seen = BTreeSet::new();
    let mut prepared = Vec::new();
    for proposal in proposals {
        if prepared.len() >= limit {
            break;
        }
        let request_key = goal_ticket_request_key(
            project_id,
            goal_revision,
            &proposal.title,
            &proposal.body,
            &proposal.labels,
        )?;
        if !seen.insert(request_key.clone()) {
            continue;
        }
        let request_digest = goal_ticket_request_digest(proposal)?;
        prepared.push(PreparedGoalTicket {
            request_key,
            request_digest,
            proposal: proposal.clone(),
        });
    }
    if prepared.is_empty() {
        Ok(GoalSupervisorAction::Idle)
    } else {
        Ok(GoalSupervisorAction::Create(prepared))
    }
}

fn goal_ticket_request_digest(proposal: &GoalTicketProposal) -> Result<String, String> {
    let mut labels = proposal.labels.iter().cloned().collect::<Vec<_>>();
    labels.sort();
    let value = serde_json::json!({
        "title": proposal.title.split_whitespace().collect::<Vec<_>>().join(" "),
        "body": proposal.body.replace("\r\n", "\n").replace('\r', "\n"),
        "labels": labels,
    });
    let bytes = serde_json::to_vec(&value).map_err(|error| error.to_string())?;
    use sha2::Digest as _;
    Ok(format!("{:x}", sha2::Sha256::digest(bytes)))
}

/// Pick one status filter per due tick, rotating through the configured order.
/// A Project with several dispatch statuses therefore cannot monopolize one
/// idle controller tick with a multi-query scan.
pub fn next_status_filter(
    statuses: &[TicketStatus],
    last_index: Option<usize>,
) -> Option<(usize, TicketStatus)> {
    if statuses.is_empty() {
        return None;
    }
    let next = last_index.map_or(0, |index| (index + 1) % statuses.len());
    Some((next, statuses[next]))
}

/// The TicketRun reducer is the only authority that advances a ticket phase.
/// This maps host-validated role output and host observations into reducer
/// inputs; raw Agent success assertions are never accepted here.
pub fn transition_for_role(
    role: Role,
    phase: Phase,
    event: ValidatedWorkflowEvent,
) -> Result<Input, String> {
    use ValidatedWorkflowEvent as Event;
    match (role, phase, event) {
        (Role::Coordinator, Phase::Planning, Event::PlanAccepted) => Ok(Input::PlanAccepted),
        (Role::Coordinator, Phase::Preparing, Event::WorktreesPrepared) => {
            Ok(Input::WorktreesPrepared)
        }
        (Role::Worker, Phase::Implementing, Event::ImplementationAccepted) => {
            Ok(Input::EvidenceSubmitted)
        }
        (Role::Reviewer, Phase::Reviewing, Event::CorrectionsRequired) => {
            Ok(Input::CorrectionsRemain)
        }
        (Role::Reviewer, Phase::Reviewing, Event::ReviewConverged) => Ok(Input::ReviewConverged),
        (Role::MergeDecision, Phase::Assessing, Event::HumanReviewRequired) => {
            Ok(Input::RequireHumanReview)
        }
        _ => {
            Err("validated workflow event is not allowed for this role and TicketRun phase".into())
        }
    }
}

/// Map authoritative host observations to reducer inputs. These observations
/// come from Git/forge, the operation ledger, or the ticket adapter rather
/// than a model's claim that its task succeeded.
pub fn transition_for_observation(
    phase: Phase,
    event: ValidatedHostObservation,
) -> Result<Input, String> {
    match (phase, event) {
        (Phase::AwaitingMerge, ValidatedHostObservation::MergeApplied) => Ok(Input::MergeVerified),
        (Phase::Operating, ValidatedHostObservation::OperationsSucceeded) => {
            Ok(Input::OperationsSucceeded)
        }
        (Phase::Operating, ValidatedHostObservation::OperationsNotRequired) => {
            Ok(Input::OperationsNotRequired)
        }
        (Phase::Operating, ValidatedHostObservation::OperationFailed) => Ok(Input::OperationFailed),
        (Phase::Completing, ValidatedHostObservation::TicketCompleted) => {
            Ok(Input::CompletionObserved)
        }
        (Phase::Postmortem, ValidatedHostObservation::KnowledgePublished) => {
            Ok(Input::KnowledgePublished)
        }
        (_, ValidatedHostObservation::TicketCanceled) => Ok(Input::ExternalCanceled),
        _ => Err("host observation is not valid for this TicketRun phase".into()),
    }
}

/// A host-derived fact. Construct these only after process, hook, forge,
/// operation, or publication evidence has been independently validated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidatedWorkflowEvent {
    PlanAccepted,
    WorktreesPrepared,
    ImplementationAccepted,
    CorrectionsRequired,
    ReviewConverged,
    HumanReviewRequired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidatedHostObservation {
    MergeApplied,
    OperationsSucceeded,
    OperationsNotRequired,
    OperationFailed,
    TicketCompleted,
    TicketCanceled,
    KnowledgePublished,
}

/// Derive the stable logical identity of a role session. Attempt and finite
/// turn number are intentionally excluded so parked work resumes in place.
pub fn role_session_key(
    project: &ProjectId,
    ticket_run: Option<&TicketRunId>,
    role: Role,
) -> Result<String, String> {
    match (role, ticket_run) {
        (Role::Supervisor, None) => Ok(format!("project:{}:supervisor", project.as_str())),
        (Role::Supervisor, Some(_)) => {
            Err("Supervisor sessions are Project-scoped, not TicketRun-scoped".into())
        }
        (_, Some(run)) => Ok(format!("ticket_run:{}:{}", run.as_str(), role_name(role))),
        (_, None) => Err("ticket workflow roles require a TicketRun scope".into()),
    }
}

pub(crate) fn role_name(role: Role) -> &'static str {
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

/// Reconstruct the typed reducer state from its durable string representation.
pub fn ticket_run_from_record(
    project_id: ProjectId,
    ticket_run_id: TicketRunId,
    revision: u64,
    phase: &str,
    activity: &str,
    external_status: TicketStatus,
    required_review_revision: Option<u64>,
) -> Result<TicketRun, String> {
    let phase: Phase = serde_json::from_str(&format!("\"{phase}\""))
        .map_err(|error| format!("unknown stored TicketRun phase: {error}"))?;
    let activity: Activity = serde_json::from_str(&format!("\"{activity}\""))
        .map_err(|error| format!("unknown stored TicketRun activity: {error}"))?;
    Ok(TicketRun {
        project_id,
        ticket_run_id,
        revision: crate::domain::ids::Revision(revision),
        phase,
        activity,
        external_status,
        required_review_revision: required_review_revision.map(crate::domain::ids::Revision),
    })
}

/// A bounded scan identity. Scope and filters are kept in separate fields so
/// adapters cannot accidentally share a cursor between Projects.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ScanKey {
    pub project_id: ProjectId,
    pub ticket_namespace: TicketNamespace,
    pub scope_digest: String,
    pub filter_digest: String,
}

/// A Project-local cache used while materializing a single due scheduler tick.
#[derive(Default)]
pub struct TickBudget {
    pub ticket_pages: usize,
    pub effect_dispatches: usize,
}

impl TickBudget {
    pub fn observe_ticket_page(&mut self) -> Result<(), String> {
        if self.ticket_pages >= 1 {
            return Err("one scheduler tick may fetch at most one ticket page".into());
        }
        self.ticket_pages += 1;
        Ok(())
    }
}

/// Track per-Project status-filter rotation without maintaining any remote
/// service state in memory between controller iterations.
#[derive(Default)]
pub struct FilterRotation {
    last_index_by_project: HashMap<ProjectId, usize>,
}

/// A single durable unit that the foreground controller may service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScheduledWork {
    /// A human response or agent result has already been persisted and must be
    /// offered to its role before new tickets are discovered.
    Wake { sequence: i64, priority: u8 },
    /// An external effect is due or has an uncertain receipt to reconcile.
    Effect { sequence: i64, uncertain: bool },
    /// A Project has a ticket status scan due.
    ProjectScan {
        project_id: ProjectId,
        next_due_at_unix: i64,
        last_served_sequence: u64,
    },
}

/// Select exactly one item per controller iteration. Higher persisted wake
/// priority wins first; known effects precede uncertainty reconciliation;
/// due scans are last, ordered by a persisted machine-wide serving sequence
/// before due time and Project ID. This prevents one multi-page Project scan
/// from monopolizing the controller across restarts.
pub fn select_scheduled_work(
    candidates: &[ScheduledWork],
    now_unix: i64,
) -> Option<&ScheduledWork> {
    candidates
        .iter()
        .filter(|candidate| {
            !matches!(candidate,
                ScheduledWork::ProjectScan { next_due_at_unix, .. } if *next_due_at_unix > now_unix
            )
        })
        .min_by_key(|candidate| match candidate {
            ScheduledWork::Wake { sequence, priority } => (
                0_u8,
                i64::from(u8::MAX - *priority),
                *sequence,
                String::new(),
            ),
            ScheduledWork::Effect {
                sequence,
                uncertain,
            } => (1, i64::from(*uncertain), *sequence, String::new()),
            ScheduledWork::ProjectScan {
                project_id,
                next_due_at_unix,
                last_served_sequence,
            } => (
                2,
                i64::try_from(*last_served_sequence).unwrap_or(i64::MAX),
                *next_due_at_unix,
                project_id.as_str().to_owned(),
            ),
        })
}

impl FilterRotation {
    pub fn next(
        &mut self,
        project: &ProjectId,
        statuses: &[TicketStatus],
    ) -> Option<(usize, TicketStatus)> {
        let last = self.last_index_by_project.get(project).copied();
        let selected = next_status_filter(statuses, last)?;
        self.last_index_by_project
            .insert(project.clone(), selected.0);
        Some(selected)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{
        FilterRotation, TickBudget, TicketDisposition, ValidatedHostObservation,
        ValidatedWorkflowEvent, next_status_filter, role_session_key, ticket_disposition,
        transition_for_observation, transition_for_role,
    };
    use crate::config::Config;
    use crate::domain::ids::ProjectId;
    use crate::domain::types::{Role, TicketStatus};
    use crate::engine::reducer::Phase;

    #[test]
    fn filter_rotation_advances_one_status_at_a_time_and_wraps() {
        let statuses = [
            TicketStatus::Ready,
            TicketStatus::Backlog,
            TicketStatus::Triage,
        ];
        assert_eq!(
            next_status_filter(&statuses, None),
            Some((0, TicketStatus::Ready))
        );
        assert_eq!(
            next_status_filter(&statuses, Some(2)),
            Some((0, TicketStatus::Ready))
        );
        let project = ProjectId::parse("project-a").unwrap();
        let mut rotation = FilterRotation::default();
        assert_eq!(
            rotation.next(&project, &statuses),
            Some((0, TicketStatus::Ready))
        );
        assert_eq!(
            rotation.next(&project, &statuses),
            Some((1, TicketStatus::Backlog))
        );
    }

    #[test]
    fn a_tick_rejects_a_second_ticket_page() {
        let mut budget = TickBudget::default();
        assert_eq!(budget.observe_ticket_page(), Ok(()));
        assert!(budget.observe_ticket_page().is_err());
    }

    #[test]
    fn persisted_wakes_precede_effects_and_due_project_scans() {
        use super::ScheduledWork;

        let candidates = [
            ScheduledWork::ProjectScan {
                project_id: ProjectId::parse("alpha").unwrap(),
                next_due_at_unix: 2,
                last_served_sequence: 0,
            },
            ScheduledWork::Wake {
                sequence: 10,
                priority: 2,
            },
            ScheduledWork::Wake {
                sequence: 11,
                priority: 1,
            },
            ScheduledWork::Effect {
                sequence: 1,
                uncertain: false,
            },
        ];
        assert_eq!(
            super::select_scheduled_work(&candidates, 0),
            Some(&ScheduledWork::Wake {
                sequence: 10,
                priority: 2
            })
        );
    }

    #[test]
    fn due_project_scans_rotate_by_persisted_service_sequence() {
        use super::ScheduledWork;

        let candidates = [
            ScheduledWork::ProjectScan {
                project_id: ProjectId::parse("alpha").unwrap(),
                next_due_at_unix: 3,
                last_served_sequence: 9,
            },
            ScheduledWork::ProjectScan {
                project_id: ProjectId::parse("beta").unwrap(),
                next_due_at_unix: 4,
                last_served_sequence: 10,
            },
            ScheduledWork::ProjectScan {
                project_id: ProjectId::parse("gamma").unwrap(),
                next_due_at_unix: 2,
                last_served_sequence: 2,
            },
        ];
        assert_eq!(
            super::select_scheduled_work(&candidates, 5),
            Some(&candidates[2])
        );
        assert_eq!(super::select_scheduled_work(&candidates, 1), None);
    }

    #[test]
    fn operations_recipe_ambiguity_is_a_human_decision() {
        let mut config: Config =
            toml::from_str(include_str!("../../examples/fixture/config.toml")).unwrap();
        let project = config
            .projects
            .get(&crate::domain::ids::ProjectId::parse("operations_project").unwrap())
            .unwrap()
            .clone();
        let labels = BTreeSet::from(["docs".to_owned()]);
        assert_eq!(
            ticket_disposition(&config, &project, TicketStatus::Ready, &labels),
            TicketDisposition::Dispatch {
                recipe_id: Some("docs_only".into())
            }
        );
        assert!(matches!(
            ticket_disposition(&config, &project, TicketStatus::Ready, &BTreeSet::new()),
            TicketDisposition::AwaitHuman { .. }
        ));
        let mut ambiguous = project.clone();
        ambiguous
            .operation_matches
            .push(ambiguous.operation_matches[0].clone());
        assert!(matches!(
            ticket_disposition(&config, &ambiguous, TicketStatus::Ready, &labels),
            TicketDisposition::AwaitHuman { reason } if reason.contains("multiple")
        ));
        assert_eq!(
            ticket_disposition(&config, &project, TicketStatus::Done, &labels),
            TicketDisposition::Skip
        );
        config.operation_recipes.remove("docs_only");
        assert!(matches!(
            ticket_disposition(&config, &project, TicketStatus::Ready, &labels),
            TicketDisposition::AwaitHuman { .. }
        ));
    }

    #[test]
    fn goal_ticket_proposals_have_stable_keys_and_enforce_the_cap() {
        use super::{
            GoalSupervisorAction, GoalTicketAdmission, GoalTicketCandidate, GoalTicketMatchBasis,
            GoalTicketProposal, bound_goal_supervisor_action, canonicalize_goal_ticket_candidates,
            goal_ticket_admission, goal_ticket_request_key,
        };

        let project = ProjectId::parse("project-a").unwrap();
        let labels = BTreeSet::from(["docs".to_owned(), "urgent".to_owned()]);
        let key =
            goal_ticket_request_key(&project, 2, "  Add   migration ", "body\r\nline", &labels)
                .unwrap();
        assert_eq!(
            key,
            goal_ticket_request_key(&project, 2, "Add migration", "body\nline", &labels).unwrap()
        );
        assert_ne!(
            key,
            goal_ticket_request_key(&project, 3, "Add migration", "body\nline", &labels).unwrap()
        );
        assert_eq!(
            goal_ticket_admission(&key, "digest", None, 0, 1).unwrap(),
            GoalTicketAdmission::Reserve {
                request_key: key.clone()
            }
        );
        assert_eq!(
            goal_ticket_admission(&key, "digest", Some("digest"), 1, 1).unwrap(),
            GoalTicketAdmission::ReuseExisting
        );
        assert_eq!(
            goal_ticket_admission(&key, "digest", None, 1, 1).unwrap(),
            GoalTicketAdmission::LimitReached
        );
        assert!(goal_ticket_admission(&key, "new", Some("digest"), 0, 1).is_err());

        let canonical = canonicalize_goal_ticket_candidates(&[
            GoalTicketCandidate {
                ticket_id: "PAY-2".into(),
                match_basis: GoalTicketMatchBasis::StableExternalKey,
                created_at: Some("2026-11-01T00:00:00Z".into()),
            },
            GoalTicketCandidate {
                ticket_id: "PAY-1".into(),
                match_basis: GoalTicketMatchBasis::OperationId,
                created_at: Some("2026-11-02T00:00:00Z".into()),
            },
            GoalTicketCandidate {
                ticket_id: "PAY-1".into(),
                match_basis: GoalTicketMatchBasis::StableExternalKey,
                created_at: Some("2026-11-02T00:00:00Z".into()),
            },
        ])
        .unwrap();
        assert_eq!(canonical.canonical_ticket_id, "PAY-1");
        assert_eq!(canonical.duplicate_ticket_ids, vec!["PAY-2"]);

        let config: Config =
            toml::from_str(include_str!("../../examples/fixture/config.toml")).unwrap();
        let goal_project = config
            .projects
            .get(&ProjectId::parse("goal_project").unwrap())
            .unwrap();
        let proposals = vec![
            GoalTicketProposal {
                title: "First".into(),
                body: "body".into(),
                labels: BTreeSet::new(),
            },
            GoalTicketProposal {
                title: "Second".into(),
                body: "body".into(),
                labels: BTreeSet::new(),
            },
        ];
        assert!(matches!(
            bound_goal_supervisor_action(
                &ProjectId::parse("goal_project").unwrap(),
                goal_project,
                0,
                19,
                false,
                &proposals
            )
            .unwrap(),
            GoalSupervisorAction::Create(items) if items.len() == 1
        ));
        assert_eq!(
            bound_goal_supervisor_action(
                &ProjectId::parse("goal_project").unwrap(),
                goal_project,
                0,
                0,
                true,
                &proposals
            )
            .unwrap(),
            GoalSupervisorAction::RequestCompletionConfirmation
        );
    }

    #[test]
    fn only_host_validated_role_events_can_advance_a_phase() {
        assert_eq!(
            transition_for_role(
                Role::Coordinator,
                Phase::Planning,
                ValidatedWorkflowEvent::PlanAccepted
            ),
            Ok(crate::engine::reducer::Input::PlanAccepted)
        );
        assert_eq!(
            transition_for_observation(
                Phase::AwaitingMerge,
                ValidatedHostObservation::MergeApplied
            ),
            Ok(crate::engine::reducer::Input::MergeVerified)
        );
        assert_eq!(
            transition_for_observation(
                Phase::Postmortem,
                ValidatedHostObservation::KnowledgePublished
            ),
            Ok(crate::engine::reducer::Input::KnowledgePublished)
        );
        assert!(
            transition_for_observation(Phase::Postmortem, ValidatedHostObservation::MergeApplied)
                .is_err()
        );
        assert!(
            transition_for_role(
                Role::Coordinator,
                Phase::Implementing,
                ValidatedWorkflowEvent::PlanAccepted
            )
            .is_err()
        );
        assert_eq!(
            role_session_key(
                &ProjectId::parse("project-a").unwrap(),
                None,
                Role::Supervisor
            ),
            Ok("project:project-a:supervisor".into())
        );
        assert!(
            role_session_key(
                &ProjectId::parse("project-a").unwrap(),
                None,
                Role::Coordinator
            )
            .is_err()
        );
    }
}
