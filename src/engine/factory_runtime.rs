//! Runtime decisions shared by the Project scheduler and TicketRun controller.
//!
//! This module contains no provider, Rex, or SQLite calls. Callers persist each
//! returned decision before performing its effects.

use std::collections::{BTreeSet, HashMap};

use sha2::Digest as _;

use crate::agent_recovery::AgentRecoveryReport;
use crate::config::{Config, ProjectConfig};
use crate::domain::ids::{Digest, OperationId, ProjectId, Revision, TicketNamespace, TicketRunId};
use crate::domain::types::{ProjectMode, Role, TicketStatus};
use crate::effects::{DispatchTick, EffectDispatcher, EffectHandler, EffectLimits};
use crate::engine::reducer::{Activity, Input, Phase, TicketRun};
use crate::store::scheduler::RunnableProject;
use crate::store::scheduler::{
    ObservedTicket, PendingRoleWakeSession, TicketObservationClassification,
    TicketScanErrorBackoff, TicketScanKey, TicketScanPage,
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

    /// Drain one queued exact-scope merge review response. TicketReview decisions are host inputs,
    /// so they are not delivered to an Agent role session.
    fn process_one_merge_human_response(
        &mut self,
        _store: &mut ConfigStore,
        _owner_generation: u64,
        _now_unix: i64,
    ) -> Result<bool, String> {
        Ok(false)
    }

    /// Validate one human request to resume an exhausted MergeDecision claim using
    /// the configured external ticket CLI and fresh host Forge evidence.
    fn process_one_merge_claim_recovery(
        &mut self,
        _store: &mut ConfigStore,
        _owner_generation: u64,
        _now_unix: i64,
        _config: &Config,
    ) -> Result<bool, String> {
        Ok(false)
    }

    fn recover_agents(
        &mut self,
        store: &mut ConfigStore,
        owner_generation: u64,
        now_unix: i64,
    ) -> Result<AgentRecoveryReport, String>;

    /// Reconcile one persisted Rex view before launch decisions. Implementations must bound
    /// external work so this does not make a controller iteration unbounded.
    fn maintain_rex_views(
        &mut self,
        _store: &mut ConfigStore,
        _owner_generation: u64,
        _now_unix: i64,
        _config: &Config,
    ) -> Result<(), String> {
        Ok(())
    }
    /// Import and validate at most one completed mailbox result, then commit
    /// its typed reducer transition through the runtime's durable boundary.
    fn ingest_one_agent_result(
        &mut self,
        store: &mut ConfigStore,
        owner_generation: u64,
        now_unix: i64,
    ) -> Result<Option<crate::store::agent_results::IngestedAgentResult>, String>;

    fn read_verified_artifact(
        &self,
        artifact: &crate::store::artifact_registry::VerifiedArtifact,
    ) -> Result<Vec<u8>, String>;

    fn observe_base_heads(
        &mut self,
    ) -> Result<std::collections::BTreeMap<crate::domain::ids::RepositoryId, String>, String>;

    /// Observe a host-persisted Worker worktree using the configured bounded Git adapter.
    /// The default deliberately fails closed so test/runtime implementations cannot assert
    /// that a recovery worktree is at the expected revision without observing it.
    fn observe_worker_recovery_head(
        &self,
        _candidate: &crate::engine::orchestration::WorkerRecoveryCandidate,
    ) -> Result<Option<String>, String> {
        Ok(None)
    }

    fn configuration_digest(&self) -> &Digest;

    fn human_evidence_documents(
        &mut self,
        _store: &mut ConfigStore,
        result: &crate::store::agent_results::IngestedAgentResult,
    ) -> Result<Vec<crate::human_runtime::HumanEvidenceDocument>, String> {
        if result.validated.claimed_artifact_refs.is_empty() {
            Ok(Vec::new())
        } else {
            Err("Supervisor goal evidence artifacts are unavailable to the host consumer".into())
        }
    }

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
        config: &Config,
        run: &crate::store::scheduler::ActiveTicketRun,
        result: &crate::store::agent_results::IngestedAgentResult,
        effect_revision: u64,
    ) -> Result<Option<EffectIntent>, String>;

    /// Build a fresh host observation for an accepted, exact publication subject before
    /// persisting a MergeDecision assessment. Implementations fail closed when the Forge snapshot
    /// is incomplete or unsupported.
    fn observe_merge_assessment(
        &mut self,
        _subject: &crate::delivery_runtime::ImplementationPublicationSetSubject,
        _result: &crate::store::agent_results::IngestedAgentResult,
    ) -> Result<
        Option<crate::merge_runtime::MergeEvidenceObservation>,
        crate::merge_runtime::MergeObservationError,
    > {
        Err("host MergeDecision evidence observation is unavailable".into())
    }

    /// Re-observe a previously accepted publication set for a one-use human recovery.
    /// The original immutable instruction digest remains part of the subject.
    fn observe_recovery_merge_assessment(
        &mut self,
        _subject: &crate::delivery_runtime::ImplementationPublicationSetSubject,
        _instruction_digest: &Digest,
    ) -> Result<
        Option<crate::merge_runtime::MergeEvidenceObservation>,
        crate::merge_runtime::MergeObservationError,
    > {
        Err("fresh recovery MergeDecision observation is unavailable".into())
    }

    /// Construct the exact immutable PR-body target from the same fresh host observation and
    /// accepted Worker plan. Implementations fail closed unless the proposal is host-derived.
    fn prepare_merge_body_proposal(
        &self,
        _project_id: &ProjectId,
        _subject: &crate::delivery_runtime::ImplementationPublicationSetSubject,
        _accepted_plan: &crate::engine::orchestration::WorkPlan,
        _assessment_id: &crate::domain::ids::Digest,
        _observation: &crate::merge_runtime::MergeEvidenceObservation,
    ) -> Result<crate::store::merge_work::PreparedMergeBodyProposal, String> {
        Err("host MergeDecision PR-body proposal is unavailable".into())
    }

    /// Resolve an authenticated MergeIntent into the exact repository procedure. The default
    /// keeps implementations fail-closed until they provide the host instruction resolver.
    fn resolve_merge_work_document(
        &mut self,
        _subject: &crate::delivery_runtime::ImplementationPublicationSetSubject,
        _accepted_plan: &crate::engine::orchestration::WorkPlan,
        _assessment: &crate::store::merge_work::TrustedMergeAssessment,
        _intent: &crate::engine::orchestration::MergeIntentPayload,
        _result: &crate::store::agent_results::IngestedAgentResult,
    ) -> Result<crate::store::merge_work::MergeWorkDocument, String> {
        Err("host MergeIntent procedure resolution is unavailable".into())
    }

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

    /// Validate a correction Worker checkout before it can return its bounded test evidence.
    /// Implementations must compare the exact expected HEAD and reject tracked or untracked edits.
    fn verify_worker_verification_worktree(
        &self,
        _store: &mut ConfigStore,
        _project_id: &crate::domain::ids::ProjectId,
        _ticket_run_id: &crate::domain::ids::TicketRunId,
        _assignment: &crate::launch::WorkerLaunchBinding,
    ) -> Result<(), String> {
        Err("Worker verification worktree observation is unavailable".into())
    }

    fn effect_handlers(&self) -> Vec<&dyn EffectHandler>;
}

/// The only external capabilities permitted during `runtime run --once`.
/// Implementations observe existing state and may record recovery evidence locally.
pub trait FactoryRuntimeObservationServices {
    fn recover_agents(
        &mut self,
        store: &mut ConfigStore,
        owner_generation: u64,
        now_unix: i64,
    ) -> Result<AgentRecoveryReport, String>;

    fn observe_publications(
        &mut self,
        store: &mut ConfigStore,
        owner_generation: u64,
        now_unix: i64,
    ) -> Result<crate::runtime_delivery::PublicationMonitorTick, String>;
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
    /// Reconcile bounded observations and existing Agent recovery evidence without
    /// dispatching effects, starting provider work, maintaining Rex views, or scanning tickets.
    pub fn tick_once(
        store: &mut ConfigStore,
        owner_generation: u64,
        now_unix: i64,
        services: &mut impl FactoryRuntimeObservationServices,
    ) -> Result<(), String> {
        store.activate_starting_projects(owner_generation)?;
        services.observe_publications(store, owner_generation, now_unix)?;
        services.recover_agents(store, owner_generation, now_unix)?;
        Ok(())
    }

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
        let _processed_merge_human_response =
            services.process_one_merge_human_response(store, owner_generation, now_unix)?;
        let _processed_merge_claim_recovery =
            services.process_one_merge_claim_recovery(store, owner_generation, now_unix, config)?;
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

        // A final mailbox receipt can make a terminal Worker's recovery candidate
        // eligible after its previous Coordinator turn already took a prompt
        // snapshot. Re-scan durable candidates every iteration: if the controller
        // stops between the receipt and this transaction, the next process repeats
        // the scan and persists the same idempotent Coordinator wake.
        queue_ready_worker_recovery_wakes(
            store,
            owner_generation,
            now_unix,
            config,
            services.configuration_digest(),
        )?;

        let configured_projects = config.projects.keys().cloned().collect::<Vec<_>>();
        let learning_interval = config
            .learning
            .review_interval_hours
            .checked_mul(60 * 60)
            .ok_or("learning review interval exceeds supported range")?;
        let _supervisor_reviews_queued = store.queue_due_supervisor_reviews(
            owner_generation,
            &configured_projects,
            now_unix,
            i64::try_from(learning_interval)
                .map_err(|_| "Supervisor review interval exceeds supported range")?,
        )?;

        services.maintain_rex_views(store, owner_generation, now_unix, config)?;

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
        let supervisor_learning_project = store.queue_due_supervisor_learning(
            owner_generation,
            &configured_projects,
            now_unix,
            learning_interval,
            12,
        )?;
        let (keys, mut external_errors) = build_scan_keys(config, &runnable, services);
        if let Some(key) = next_pending_candidate_key(store, &runnable, config, &keys)?
            && let Some((project_run, disposition)) =
                next_disposition(store, config, &runnable, &key)?
        {
            let ticket_id = project_run.ticket_id;
            match &disposition {
                TicketDisposition::Dispatch { .. } => {
                    if let Some(ticket) = store.pending_ticket_observations(&key, 1)?.first() {
                        store.enqueue_supervisor_ticket_observation(
                            owner_generation,
                            &key,
                            ticket,
                            now_unix,
                        )?;
                    }
                }
                TicketDisposition::AwaitHuman { reason } => {
                    store.classify_ticket_observation(
                        owner_generation,
                        &key,
                        &ticket_id,
                        TicketObservationClassification::Human,
                        reason,
                        now_unix,
                    )?;
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
                }
            }
            store.mark_ticket_scan_served(owner_generation, &key)?;
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
                    TicketScanErrorBackoff {
                        key: &key,
                        expected_cursor: cursor.cursor.as_deref(),
                        expected_generation: cursor.generation,
                        expected_page_count: cursor.page_count,
                        now_unix,
                        retry_after_seconds: config.runtime.external_poll_seconds.clamp(2, 3600),
                    },
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
            TicketScanPage {
                key: &key,
                expected_cursor: cursor.cursor.as_deref(),
                expected_generation: cursor.generation,
                expected_page_count: cursor.page_count,
                next_cursor: page.next_cursor.as_deref(),
                tickets: &page.tickets,
                now_unix,
                poll_seconds: config.runtime.external_poll_seconds,
            },
        )?;
        for ticket in &page.tickets {
            let status_key = TicketScanKey {
                project_id: key.project_id.clone(),
                adapter_id: key.adapter_id.clone(),
                namespace: key.namespace.clone(),
                scope_digest: key.scope_digest.clone(),
                filter_digest: key.filter_digest.clone(),
                status: key.status,
            };
            let pending = store.pending_ticket_observations(&status_key, 100)?;
            if let Some(observation) = pending
                .iter()
                .find(|candidate| candidate.ticket_id == ticket.id)
            {
                store.enqueue_supervisor_ticket_observation(
                    owner_generation,
                    &status_key,
                    observation,
                    now_unix,
                )?;
            }
        }
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

pub(crate) fn queue_ready_worker_recovery_wakes(
    store: &mut ConfigStore,
    owner_generation: u64,
    now_unix: i64,
    config: &Config,
    configuration_digest: &Digest,
) -> Result<usize, String> {
    use crate::engine::reducer::Phase;

    let mut queued = 0;
    for runnable in store.runnable_projects(owner_generation)? {
        let Some(project) = config.projects.get(&runnable.record.id) else {
            continue;
        };
        let mut offset = 0_u64;
        loop {
            let runs = store.active_ticket_runs_page_for_project(
                owner_generation,
                &runnable.record.id,
                offset,
                256,
            )?;
            let page_len = runs.len();
            for run in runs.into_iter().filter(|run| {
                run.phase == Phase::Implementing && run.project_epoch == runnable.project_epoch
            }) {
                let Some(plan) =
                    store.latest_accepted_work_plan(&run.project_id, &run.ticket_run_id)?
                else {
                    continue;
                };
                if plan.configuration_digest != *configuration_digest {
                    continue;
                }
                for candidate in store.worker_recovery_candidates(
                    owner_generation,
                    &run,
                    &plan,
                    project,
                    configuration_digest,
                )? {
                    if store.queue_worker_recovery_ready_wake(
                        owner_generation,
                        &run,
                        &plan,
                        configuration_digest,
                        &candidate,
                        now_unix,
                    )? {
                        queued += 1;
                    }
                }
            }
            if page_len < 256 {
                break;
            }
            offset = offset.saturating_add(page_len as u64);
        }
    }
    Ok(queued)
}

fn validate_merge_reassessment_plan_scope(
    store: &ConfigStore,
    owner_generation: u64,
    run: &crate::store::scheduler::ActiveTicketRun,
    proposal: &crate::engine::orchestration::PlanReadyPayload,
) -> Result<(), String> {
    let Some((transition_revision, evidence)) = store
        .ticket_run_transition_evidence(
            owner_generation,
            &run.project_id,
            &run.ticket_run_id,
            0,
            256,
        )?
        .into_iter()
        .find(|(_, evidence)| evidence["kind"] == "merge_reassessment_required")
    else {
        return Ok(());
    };
    if transition_revision > run.revision {
        return Err("Coordinator rework plan is not after its host reassessment request".into());
    }
    let source_revision = evidence["source_revision"]
        .as_u64()
        .ok_or("merge reassessment lacks its immutable source revision")?;
    if evidence["ticket_run_id"].as_str() != Some(run.ticket_run_id.as_str())
        || source_revision >= transition_revision
    {
        return Err("merge reassessment transition has an invalid TicketRun scope".into());
    }
    let work = store
        .merge_work_item(
            &run.project_id,
            &run.ticket_run_id,
            crate::domain::ids::Revision(source_revision),
        )?
        .ok_or("merge reassessment lost its immutable MergeWorkItem")?;
    let prior = store
        .latest_accepted_work_plan(&run.project_id, &run.ticket_run_id)?
        .ok_or("merge reassessment has no prior accepted work plan")?;
    if evidence["work_id"].as_str() != Some(work.work_id.as_str())
        || evidence["prior_accepted_plan_digest"].as_str()
            != Some(work.accepted_plan_digest.as_str())
        || prior.plan_digest != work.accepted_plan_digest
        || evidence["prior_accepted_plan"]
            != serde_json::to_value(&prior.proposal).map_err(|error| error.to_string())?
        || proposal.plan != prior.proposal
    {
        return Err("Coordinator rework plan changed the prior accepted tasks, repositories, nodes, or dependencies; only freshly observed bases may change".into());
    }
    Ok(())
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
    if binding.role == Role::Coordinator
        && binding.ticket_run_id.is_some()
        && let Some(recovery) = store.recovery_authorization_for_coordinator_result(result)?
    {
        let is_recovery_spawn = result.validated.kind == RoleOutputKind::SpawnRequest
            && result.validated.assertion
                == crate::engine::orchestration::AgentAssertion::Succeeded;
        if is_recovery_spawn {
            return apply_coordinator_spawn_request(
                store,
                owner_generation,
                now_unix,
                config,
                services,
                result,
            );
        }
        store.fail_merge_claim_recovery_attempt(
            owner_generation,
            &recovery.request_id,
            result,
            "the authorized Coordinator turn did not return its one MergeDecision SpawnRequest",
            now_unix,
        )?;
        return Ok(true);
    }
    if binding.role == Role::MergeDecision
        && binding.ticket_run_id.is_some()
        && let Some(recovery) = store.recovery_authorization_for_merge_result(result)?
    {
        let recovery_status = store
            .merge_claim_recovery_status(&recovery.request_id)?
            .ok_or("MergeDecision recovery request disappeared during result dispatch")?;
        let is_resumed_assessment = recovery_status.state == "consumed"
            && result.validated.kind == RoleOutputKind::MergeAssessment
            && result.validated.assertion
                == crate::engine::orchestration::AgentAssertion::Succeeded;
        let is_resumed_merge_intent = if recovery_status.state == "accepted"
            && result.validated.kind == RoleOutputKind::MergeIntent
            && result.validated.assertion == crate::engine::orchestration::AgentAssertion::Succeeded
        {
            let ticket_run_id = binding
                .ticket_run_id
                .as_ref()
                .ok_or("recovery MergeIntent has no TicketRun")?;
            match store.trusted_merge_assessment(
                &binding.project_id,
                ticket_run_id,
                binding
                    .ticket_revision
                    .ok_or("recovery MergeIntent has no TicketRun revision")?,
            )? {
                Some(assessment) => store
                    .merge_claim_recovery_subject_for_assessment(
                        &binding.project_id,
                        ticket_run_id,
                        &assessment.source_evidence_id,
                    )?
                    .is_some_and(|subject| subject == recovery.subject),
                None => false,
            }
        } else {
            false
        };
        if !is_resumed_assessment && !is_resumed_merge_intent {
            store.fail_resumed_merge_claim_recovery(
                owner_generation,
                &recovery,
                result,
                "the one authorized MergeDecision turn did not return a successful assessment",
                now_unix,
            )?;
            return Ok(true);
        }
    }
    if result.validated.kind == RoleOutputKind::SpawnRequest
        && binding.role == Role::Coordinator
        && binding.ticket_run_id.is_some()
        && result.validated.assertion == crate::engine::orchestration::AgentAssertion::Succeeded
    {
        return apply_coordinator_spawn_request(
            store,
            owner_generation,
            now_unix,
            config,
            services,
            result,
        );
    }
    if binding.role == Role::Supervisor
        && result.validated.kind == RoleOutputKind::Intervention
        && result.validated.assertion == crate::engine::orchestration::AgentAssertion::Succeeded
    {
        return store.apply_supervisor_intervention(owner_generation, result);
    }
    if binding.role == Role::Supervisor
        && result.validated.kind == RoleOutputKind::TicketProposal
        && result.validated.assertion == crate::engine::orchestration::AgentAssertion::Succeeded
    {
        return apply_supervisor_ticket_proposal(
            store,
            owner_generation,
            now_unix,
            config,
            services,
            result,
        );
    }
    if binding.role == Role::Supervisor
        && result.validated.kind == RoleOutputKind::DispatchRequest
        && result.validated.assertion == crate::engine::orchestration::AgentAssertion::Succeeded
    {
        return apply_supervisor_dispatch_request(
            store,
            owner_generation,
            now_unix,
            config,
            services,
            result,
        );
    }
    if binding.role == Role::Supervisor
        && result.validated.kind == RoleOutputKind::HumanRequest
        && result.validated.assertion == crate::engine::orchestration::AgentAssertion::Succeeded
        && matches!(
            &result.validated.typed_payload,
            RoleResultPayload::HumanRequest(request) if request.kind == "goal_completion"
        )
    {
        return apply_supervisor_goal_completion_request(
            store,
            owner_generation,
            now_unix,
            config,
            services,
            result,
        );
    }
    if result.validated.kind == RoleOutputKind::ImplementationReady
        && binding.role == Role::Worker
        && result.validated.assertion == crate::engine::orchestration::AgentAssertion::Succeeded
    {
        return apply_worker_result(store, owner_generation, config, services, result);
    }
    if result.validated.kind == RoleOutputKind::VerificationReady
        && binding.role == Role::Worker
        && result.validated.assertion == crate::engine::orchestration::AgentAssertion::Succeeded
    {
        return crate::worker_verification::apply_worker_verification_result(
            store,
            owner_generation,
            config,
            services,
            result,
        );
    }
    if result.validated.kind == RoleOutputKind::ReviewReady
        && binding.role == Role::Reviewer
        && result.validated.assertion == crate::engine::orchestration::AgentAssertion::Succeeded
    {
        return apply_reviewer_result(store, owner_generation, now_unix, config, services, result);
    }
    if result.validated.kind == RoleOutputKind::MergeAssessment
        && binding.role == Role::MergeDecision
        && result.validated.assertion == crate::engine::orchestration::AgentAssertion::Succeeded
    {
        return apply_merge_assessment(store, owner_generation, now_unix, config, services, result);
    }
    if result.validated.kind == RoleOutputKind::MergeIntent
        && binding.role == Role::MergeDecision
        && result.validated.assertion == crate::engine::orchestration::AgentAssertion::Succeeded
    {
        let recovery = store.recovery_authorization_for_merge_failure(result)?;
        return match apply_merge_intent(store, owner_generation, now_unix, config, services, result)
        {
            Ok(applied) => Ok(applied),
            Err(error) => {
                let Some(recovery) = recovery else {
                    return Err(error);
                };
                let revision = binding
                    .ticket_revision
                    .ok_or("resumed MergeIntent has no TicketRun revision")?;
                let ticket_run_id = binding
                    .ticket_run_id
                    .as_ref()
                    .ok_or("resumed MergeIntent has no TicketRun")?;
                let awaiting_merge_revision = revision
                    .0
                    .checked_add(2)
                    .ok_or("resumed MergeIntent awaiting-merge revision overflow")?;
                let work_item_already_persisted = store
                    .merge_work_item(
                        &binding.project_id,
                        ticket_run_id,
                        Revision(awaiting_merge_revision),
                    )?
                    .is_some();
                if work_item_already_persisted {
                    return Err(error);
                }
                store.fail_resumed_merge_claim_recovery(
                    owner_generation,
                    &recovery,
                    result,
                    &format!(
                        "resumed MergeIntent failed before its durable merge-work item: {error}"
                    ),
                    now_unix,
                )?;
                Ok(true)
            }
        };
    }
    if result.validated.assertion == crate::engine::orchestration::AgentAssertion::Succeeded
        && binding.role == Role::Postmortem
        && result.validated.kind == RoleOutputKind::PostmortemReady
    {
        return apply_postmortem_result(
            store,
            owner_generation,
            now_unix,
            config,
            services,
            result,
        );
    }
    if result.validated.assertion == crate::engine::orchestration::AgentAssertion::Succeeded
        && binding.role == Role::Operator
        && result.validated.kind == RoleOutputKind::OperationResult
    {
        return apply_operator_result(store, owner_generation, now_unix, services, result);
    }
    if binding.role == Role::Coordinator
        && result.validated.kind == RoleOutputKind::HumanRequest
        && let RoleResultPayload::HumanRequest(payload) = &result.validated.typed_payload
        && payload.kind == "clarification"
    {
        let Some(ticket_run_id) = binding.ticket_run_id.as_ref() else {
            return Err("Coordinator clarification result lacks TicketRun scope".into());
        };
        let revision = binding
            .ticket_revision
            .ok_or("Coordinator clarification result lacks TicketRun revision")?;
        if !config.projects.contains_key(&binding.project_id) {
            return Err("Coordinator clarification Project is no longer configured".into());
        }
        let record = store
            .project(&binding.project_id)?
            .ok_or("Coordinator clarification Project has no durable configuration")?;
        if record.config_digest != services.configuration_digest().clone()
            || record.config_digest != binding.config_digest
            || record.config_revision != binding.config_revision
        {
            return Err(
                "Coordinator clarification belongs to a stale Project configuration".into(),
            );
        }
        let current = store
            .active_ticket_runs(owner_generation, 128)?
            .into_iter()
            .find(|run| run.ticket_run_id == *ticket_run_id)
            .ok_or("Coordinator clarification references no active TicketRun")?;
        if current.project_id != binding.project_id
            || current.revision != revision.0
            || matches!(
                current.phase,
                Phase::WaitingHuman | Phase::Done | Phase::Canceled
            )
        {
            return Err(
                "Coordinator clarification is stale or conflicts with human code review".into(),
            );
        }
        let documents = services.human_evidence_documents(store, result)?;
        let request_id = crate::domain::ids::HumanRequestId::parse(format!(
            "clarify-{}",
            result.receipt.evidence_id()
        ))?;
        let rex_view_id = store
            .active_ticket_view_id(owner_generation, &binding.project_id, ticket_run_id)?
            .ok_or("Coordinator clarification has no active ticket Rex view")?;
        let source = crate::human_runtime::HumanRoleResultSource {
            binding: binding.clone(),
            message_id: result.validated.message_id.clone(),
            result_digest: result.validated.result_digest.clone(),
            result_kind: result.validated.kind,
            assertion: result.validated.assertion.clone(),
            human_request: payload.clone(),
            claimed_artifact_refs: result.validated.claimed_artifact_refs.clone(),
        };
        let expires_at_unix = u64::try_from(now_unix)
            .map_err(|_| "controller time is before the Unix epoch")?
            .saturating_add(7 * 24 * 60 * 60);
        let presentation =
            crate::human_runtime::HumanAuthorityMaterial::coordinator_clarification_effect(
                request_id.clone(),
                rex_view_id,
                source,
                documents,
                expires_at_unix,
            )?;
        presentation
            .request
            .validate(expires_at_unix.saturating_sub(1))?;
        let request_json = crate::store::canonical_json(&presentation)?;
        let request_digest = Digest::parse(format!(
            "{:x}",
            sha2::Sha256::digest(request_json.as_bytes())
        ))?;
        let operation_id = OperationId::parse(format!("present-{}", request_id.as_str()))?;
        let _inserted = store.enqueue_effect(
            owner_generation,
            &EffectIntent {
                project_id: binding.project_id.clone(),
                subject_type: "ticket_run".into(),
                subject_id: ticket_run_id.as_str().into(),
                operation_id: operation_id.as_str().into(),
                logical_key: format!(
                    "{}:{}:coordinator-clarification:{}",
                    ticket_run_id, revision.0, request_id
                ),
                kind: "request_human_review".into(),
                request_json,
                request_digest: request_digest.to_string(),
                expected_revision: Some(revision.0),
            },
        )?;
        let ack_revision = revision.0.max(1);
        store.acknowledge_validated_agent_result(
            owner_generation,
            result.receipt.evidence_id(),
            ack_revision,
            crate::store::agent_results::ResultDisposition::RetainedAsClaim,
        )?;
        return Ok(true);
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
    if store.acknowledge_committed_role_result(
        owner_generation,
        "plan_accepted",
        result.receipt.evidence_id(),
        &result.validated.result_digest,
        &binding.project_id,
        ticket_run_id,
    )? {
        return Ok(true);
    }
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
    validate_merge_reassessment_plan_scope(store, owner_generation, &current, proposal)?;
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
        // accepted head; preparing it from trunk would violate the declared Git base.
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
        "transition": "plan_accepted",
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

fn apply_supervisor_goal_completion_request(
    store: &mut ConfigStore,
    owner_generation: u64,
    now_unix: i64,
    config: &Config,
    services: &mut impl FactoryRuntimeServices,
    result: &crate::store::agent_results::IngestedAgentResult,
) -> Result<bool, String> {
    use crate::engine::orchestration::{GoalCompletionDecision, RoleResultPayload};

    let binding = &result.validated.binding;
    let project = config
        .projects
        .get(&binding.project_id)
        .ok_or("Supervisor completion request Project is no longer configured")?;
    let goal = project
        .goal
        .as_ref()
        .ok_or("goal completion requires a configured Goal Project")?;
    let record = store
        .project(&binding.project_id)?
        .ok_or("Supervisor completion request has no durable Project record")?;
    let launch = store
        .agent_launch_authority(&binding.agent_run_id)?
        .ok_or("Supervisor completion request has no launch authority")?;
    let runnable = store
        .runnable_projects(owner_generation)?
        .into_iter()
        .find(|candidate| candidate.record.id == binding.project_id)
        .ok_or("Supervisor completion request Project is not running")?;
    let launch_project_epoch = store
        .agent_launch_project_epoch(&binding.agent_run_id)?
        .ok_or("Supervisor completion request has no launch project epoch")?;
    if binding.ticket_run_id.is_some()
        || binding.role_session_id.as_str() != format!("project:{}:supervisor", binding.project_id)
        || binding.controller_generation != owner_generation
        || binding.config_digest != *services.configuration_digest()
        || binding.config_revision != record.config_revision
        || record.config_digest != *services.configuration_digest()
        || store.current_revision(&record.config_source)? != Some(record.config_revision)
        || launch.controller_generation != owner_generation
        || launch.role != Role::Supervisor
        || launch.role_session_id != binding.role_session_id.as_str()
        || launch.config_revision != binding.config_revision
        || launch.config_digest != binding.config_digest
        || launch.project_id != binding.project_id
        || launch.agent_run_id != binding.agent_run_id
        || launch.run_epoch != binding.run_epoch
        || launch.attempt != binding.attempt
        || launch_project_epoch != runnable.project_epoch
        || record.mode != "goal"
        || record.goal_revision != goal.revision
    {
        return Err(
            "Supervisor completion request is stale or outside current Goal authority".into(),
        );
    }
    let RoleResultPayload::HumanRequest(payload) = &result.validated.typed_payload else {
        return Err("validated HumanRequest kind has a different typed payload".into());
    };
    if payload.kind != "goal_completion" {
        return Err("Supervisor human request is not a Goal completion request".into());
    }

    let logical_key = format!(
        "goal-completion:{}:{}",
        binding.project_id,
        result.receipt.evidence_id()
    );
    if let Some(existing) = store.effect_by_logical_key(&logical_key)? {
        if existing.project_id != binding.project_id || existing.kind != "request_human_review" {
            return Err("Goal completion replay key is bound to a different durable effect".into());
        }
        let effect: crate::human_runtime::HumanPresentationEffect =
            crate::protocol::parse_unique(existing.request_json.as_bytes())?;
        let matches_source = matches!(
            &effect.authority,
            Some(crate::human_runtime::HumanAuthorityMaterial::GoalCompletion { source, .. })
                if source.binding == *binding
                    && source.message_id == result.validated.message_id
                    && source.result_digest == result.validated.result_digest
                    && source.human_request == *payload
        );
        if !matches_source {
            return Err("Goal completion replay does not match the existing human request".into());
        }
        store.acknowledge_validated_agent_result(
            owner_generation,
            result.receipt.evidence_id(),
            record.state_revision.0.max(1),
            crate::store::agent_results::ResultDisposition::Applied,
        )?;
        return Ok(true);
    }

    let active_runs = store
        .active_ticket_runs(owner_generation, 256)?
        .into_iter()
        .filter(|run| run.project_id == binding.project_id)
        .count();
    let acceptance = goal.acceptance.iter().cloned().collect::<BTreeSet<_>>();
    let goal_evidence = crate::engine::orchestration::GoalCompletionEvidence {
        satisfied_acceptance: goal.acceptance.clone(),
        incomplete_ticket_ids: Vec::new(),
        deferred_risks: Vec::new(),
        operation_results: vec![
            "No unfinished or unsuccessful Goal Project work remains in the host ledger.".into(),
        ],
        subject_digest: payload.subject_digest.clone(),
    };
    if !matches!(
        crate::engine::orchestration::propose_goal_completion(
            project,
            goal_evidence.clone(),
            &acceptance,
            active_runs
        ),
        GoalCompletionDecision::RequestHumanConfirmation { .. }
    ) || !store.goal_completion_work_is_clear(&binding.project_id)?
    {
        return Err(
            "Goal completion is not ready for human confirmation while work remains".into(),
        );
    }
    let documents = services.human_evidence_documents(store, result)?;
    let choices = payload
        .choices
        .iter()
        .map(|choice| match choice.as_str() {
            "approve" => Ok(crate::human_runtime::HumanDecisionChoice::Approve),
            "request_changes" => Ok(crate::human_runtime::HumanDecisionChoice::RequestChanges),
            "defer" => Ok(crate::human_runtime::HumanDecisionChoice::Defer),
            "cancel" => Ok(crate::human_runtime::HumanDecisionChoice::Cancel),
            _ => Err(format!("unsupported Goal completion choice `{choice}`")),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let source = crate::human_runtime::HumanRoleResultSource {
        binding: binding.clone(),
        message_id: result.validated.message_id.clone(),
        result_digest: result.validated.result_digest.clone(),
        result_kind: result.validated.kind,
        assertion: result.validated.assertion.clone(),
        human_request: payload.clone(),
        claimed_artifact_refs: result.validated.claimed_artifact_refs.clone(),
    };
    let evidence = crate::human_runtime::HumanGoalCompletionEvidence {
        satisfied_acceptance: goal.acceptance.clone(),
        incomplete_ticket_ids: Vec::new(),
        deferred_risks: goal_evidence.deferred_risks,
        operation_results: goal_evidence.operation_results,
        subject_digest: payload.subject_digest.clone(),
    };
    let authority = crate::human_runtime::HumanAuthorityMaterial::GoalCompletion {
        source,
        goal_revision: goal.revision,
        acceptance_criteria: goal.acceptance.clone(),
        evidence,
        documents,
    };
    let request_id = crate::domain::ids::HumanRequestId::parse(format!(
        "goal-completion-{}",
        result.receipt.evidence_id()
    ))?;
    let material_digest = authority.material_digest()?;
    let policy_digest = authority.policy_digest()?;
    let bundle = authority.review_bundle()?;
    let bundle_digest = crate::human::review_bundle_digest(&bundle)?;
    let request = crate::human_runtime::HumanRuntimeRequest {
        request_id,
        purpose: crate::human_runtime::HumanPurpose::GoalCompletion,
        subject: crate::human_runtime::HumanSubjectBinding {
            project_id: binding.project_id.clone(),
            kind: crate::human_runtime::HumanSubjectKind::Goal,
            subject_id: binding.project_id.as_str().to_owned(),
            ticket_run_id: None,
            revision: crate::domain::ids::Revision(goal.revision),
            material_digest,
            configuration_digest: binding.config_digest.clone(),
            policy_digest,
            bundle_digest,
        },
        question: payload.question.clone(),
        choices,
        expires_at_unix: u64::try_from(now_unix)
            .map_err(|_| "controller time is before the Unix epoch")?
            .saturating_add(7 * 24 * 60 * 60),
        review_bundle: bundle,
    };
    authority.validate_for(&request)?;
    request.validate(
        u64::try_from(now_unix).map_err(|_| "controller time is before the Unix epoch")?,
    )?;
    let view_id = store
        .rex_view_history(&binding.project_id)?
        .into_iter()
        .find(|record| {
            record.lifecycle == "active"
                && record.view.kind == crate::launch::RexViewKind::Supervisor
        })
        .map(|record| record.view.view_id)
        .ok_or("Goal completion request has no active Supervisor Rex view")?;
    let presentation = crate::human_runtime::HumanPresentationEffect {
        request: request.clone(),
        rex_view_id: view_id,
        authority: Some(authority),
    };
    let request_json = serde_json::to_string(&presentation).map_err(|error| error.to_string())?;
    let operation_id = OperationId::parse(format!("goal-human-{}", result.receipt.evidence_id()))?;
    let effect = EffectIntent {
        project_id: binding.project_id.clone(),
        subject_type: "project".into(),
        subject_id: binding.project_id.as_str().into(),
        operation_id: operation_id.as_str().to_owned(),
        logical_key,
        kind: "request_human_review".into(),
        request_digest: durable_input_digest("human_presentation", &request_json),
        request_json,
        expected_revision: Some(goal.revision),
    };
    store.enqueue_effect(owner_generation, &effect)?;
    store.acknowledge_validated_agent_result(
        owner_generation,
        result.receipt.evidence_id(),
        record.state_revision.0.max(1),
        crate::store::agent_results::ResultDisposition::Applied,
    )?;
    Ok(true)
}

fn apply_supervisor_dispatch_request(
    store: &mut ConfigStore,
    owner_generation: u64,
    now_unix: i64,
    config: &Config,
    services: &mut impl FactoryRuntimeServices,
    result: &crate::store::agent_results::IngestedAgentResult,
) -> Result<bool, String> {
    use crate::engine::orchestration::RoleResultPayload;

    let binding = &result.validated.binding;
    let project = config
        .projects
        .get(&binding.project_id)
        .ok_or("Supervisor result Project is no longer configured")?;
    let current = store
        .project(&binding.project_id)?
        .ok_or("Supervisor result Project has no durable configuration record")?;
    let authority = store
        .agent_launch_authority(&binding.agent_run_id)?
        .ok_or("Supervisor result has no launch authority")?;
    if binding.controller_generation != owner_generation
        || authority.controller_generation != owner_generation
    {
        store.acknowledge_validated_agent_result(
            owner_generation,
            result.receipt.evidence_id(),
            current.state_revision.0.max(1),
            crate::store::agent_results::ResultDisposition::RejectedByHost,
        )?;
        return Ok(true);
    }
    let runnable = store
        .runnable_projects(owner_generation)?
        .into_iter()
        .find(|project| project.record.id == binding.project_id)
        .ok_or("Supervisor result Project is not running under this controller")?;
    let launch_project_epoch = store
        .agent_launch_project_epoch(&binding.agent_run_id)?
        .ok_or("Supervisor dispatch has no launch project epoch")?;
    let configuration_digest = services.configuration_digest().clone();
    if binding.ticket_run_id.is_some()
        || binding.role_session_id.as_str() != format!("project:{}:supervisor", binding.project_id)
        || binding.controller_generation != owner_generation
        || binding.config_digest != configuration_digest
        || binding.config_revision != current.config_revision
        || current.config_digest != configuration_digest
        || store.current_revision(&current.config_source)? != Some(current.config_revision)
        || authority.controller_generation != owner_generation
        || authority.role != Role::Supervisor
        || authority.role_session_id != binding.role_session_id.as_str()
        || authority.config_revision != binding.config_revision
        || authority.config_digest != binding.config_digest
        || authority.project_id != binding.project_id
        || authority.agent_run_id != binding.agent_run_id
        || authority.run_epoch != binding.run_epoch
        || authority.attempt != binding.attempt
        || launch_project_epoch != runnable.project_epoch
    {
        return Err("Supervisor dispatch is stale or outside the current Project authority".into());
    }
    let RoleResultPayload::DispatchRequest(dispatch) = &result.validated.typed_payload else {
        return Err("validated DispatchRequest kind has a different typed payload".into());
    };
    let configured_roles =
        crate::config::effective_project_roles(&binding.project_id, &config.projects)?;
    if configured_roles.get(&Role::Coordinator) != Some(&dispatch.coordinator_profile) {
        return Err(
            "Supervisor requested a Coordinator profile outside current Project policy".into(),
        );
    }
    let namespace = services.ticket_namespace(&project.ticket_adapter)?;
    let mut candidate = None;
    for status in &project.dispatch_states {
        let key = TicketScanKey::for_project(
            &binding.project_id,
            &project.ticket_adapter,
            &namespace,
            project,
            *status,
        )?;
        if let Some(observation) = store
            .pending_ticket_observations(&key, 100)?
            .into_iter()
            .find(|ticket| ticket.ticket_id == dispatch.ticket_reference)
        {
            if observation.revision.as_deref() != Some(dispatch.expected_ticket_revision.as_str()) {
                return Err(
                    "Supervisor dispatch references a stale external ticket revision".into(),
                );
            }
            let labels = observation.labels.iter().cloned().collect::<BTreeSet<_>>();
            let disposition = ticket_disposition(config, project, observation.status, &labels);
            let TicketDisposition::Dispatch { recipe_id } = disposition else {
                return Err("Supervisor dispatch target is outside current ticket policy".into());
            };
            candidate = Some((key, observation, recipe_id));
            break;
        }
    }
    let Some((key, observation, recipe_id)) = candidate else {
        return Err(
            "Supervisor dispatch target is not a current eligible ticket observation".into(),
        );
    };
    let authority = crate::store::scheduler::SupervisorDispatchAuthority {
        evidence_id: result.receipt.evidence_id().to_owned(),
        priority: dispatch.priority,
        expected_external_revision: dispatch.expected_ticket_revision.as_str().to_owned(),
    };
    let run_id = store.create_dispatched_ticket_run(
        owner_generation,
        &key,
        &observation.ticket_id,
        recipe_id.as_deref(),
        &project.dispatch_states,
        project.max_active_tickets,
        &authority,
        now_unix,
    )?;
    let Some(_run_id) = run_id else {
        return Err("Supervisor dispatch lost its capacity or ticket-observation race".into());
    };
    store.acknowledge_validated_agent_result(
        owner_generation,
        result.receipt.evidence_id(),
        current.state_revision.0.max(1),
        crate::store::agent_results::ResultDisposition::Applied,
    )?;
    Ok(true)
}

fn apply_supervisor_ticket_proposal(
    store: &mut ConfigStore,
    owner_generation: u64,
    now_unix: i64,
    config: &Config,
    services: &mut impl FactoryRuntimeServices,
    result: &crate::store::agent_results::IngestedAgentResult,
) -> Result<bool, String> {
    use crate::engine::orchestration::RoleResultPayload;

    let binding = &result.validated.binding;
    let project = config
        .projects
        .get(&binding.project_id)
        .ok_or("Supervisor result Project is no longer configured")?;
    let configured_goal = project
        .goal
        .as_ref()
        .ok_or("Supervisor ticket proposal requires a configured goal")?;
    let current = store
        .project(&binding.project_id)?
        .ok_or("Supervisor result Project has no durable configuration record")?;
    let authority = store
        .agent_launch_authority(&binding.agent_run_id)?
        .ok_or("Supervisor result has no launch authority")?;
    let runnable = store
        .runnable_projects(owner_generation)?
        .into_iter()
        .find(|project| project.record.id == binding.project_id)
        .ok_or("Supervisor result Project is not running under this controller")?;
    let launch_project_epoch = store
        .agent_launch_project_epoch(&binding.agent_run_id)?
        .ok_or("Supervisor ticket proposal has no launch project epoch")?;
    let configuration_digest = services.configuration_digest().clone();
    if binding.ticket_run_id.is_some()
        || binding.role_session_id.as_str() != format!("project:{}:supervisor", binding.project_id)
        || binding.controller_generation != owner_generation
        || binding.config_digest != configuration_digest
        || binding.config_revision != current.config_revision
        || current.config_digest != configuration_digest
        || store.current_revision(&current.config_source)? != Some(current.config_revision)
        || authority.controller_generation != owner_generation
        || authority.role != Role::Supervisor
        || authority.project_id != binding.project_id
        || authority.agent_run_id != binding.agent_run_id
        || current.mode != "goal"
        || current.goal_revision != configured_goal.revision
        || authority.config_revision != binding.config_revision
        || authority.config_digest != binding.config_digest
        || authority.run_epoch != binding.run_epoch
        || authority.attempt != binding.attempt
        || launch_project_epoch != runnable.project_epoch
    {
        return Err(
            "Supervisor result is stale or outside the current Goal Project authority".into(),
        );
    }
    let RoleResultPayload::TicketProposal(proposal) = &result.validated.typed_payload else {
        return Err("validated TicketProposal kind has a different typed payload".into());
    };
    if proposal.goal_revision != configured_goal.revision
        || proposal.gap_key.trim().is_empty()
        || proposal.acceptance.is_empty()
        || proposal
            .acceptance
            .iter()
            .any(|value| value.trim().is_empty())
        || proposal.priority_rationale.trim().is_empty()
    {
        return Err(
            "Supervisor ticket proposal does not match the configured goal revision".into(),
        );
    }
    let mut body = format!(
        "{}\n\nGoal gap: {}\n\nAcceptance:\n{}\n\nPriority rationale: {}",
        proposal.body.trim(),
        proposal.gap_key.trim(),
        proposal
            .acceptance
            .iter()
            .map(|item| format!("- {}", item.trim()))
            .collect::<Vec<_>>()
            .join("\n"),
        proposal.priority_rationale.trim(),
    );
    body = body.replace("\r\n", "\n").replace('\r', "\n");
    let proposal = GoalTicketProposal {
        title: proposal.title.clone(),
        body,
        labels: BTreeSet::new(),
    };
    let replay_key = goal_ticket_request_key(
        &binding.project_id,
        configured_goal.revision,
        &proposal.title,
        &proposal.body,
        &proposal.labels,
    )?;
    let replay_digest =
        goal_ticket_request_digest(&binding.project_id, configured_goal.revision, &proposal)?;
    if let Some(existing_digest) = store.goal_ticket_reservation_digest(
        owner_generation,
        &binding.project_id,
        configured_goal.revision,
        &replay_key,
    )? {
        if existing_digest != replay_digest {
            return Err(
                "replayed Goal ticket proposal differs from its existing reservation".into(),
            );
        }
        store.acknowledge_validated_agent_result(
            owner_generation,
            result.receipt.evidence_id(),
            current.state_revision.0.max(1),
            crate::store::agent_results::ResultDisposition::Applied,
        )?;
        return Ok(true);
    }
    let active = store
        .active_ticket_runs(owner_generation, 256)?
        .into_iter()
        .filter(|run| run.project_id == binding.project_id)
        .count();
    let reserved = store.goal_ticket_reservation_count(
        owner_generation,
        &binding.project_id,
        configured_goal.revision,
    )?;
    let GoalSupervisorAction::Create(prepared) = bound_goal_supervisor_action(
        &binding.project_id,
        project,
        active,
        reserved,
        false,
        &[proposal],
    )?
    else {
        store.acknowledge_validated_agent_result(
            owner_generation,
            result.receipt.evidence_id(),
            binding.config_revision.0,
            crate::store::agent_results::ResultDisposition::RetainedAsClaim,
        )?;
        return Ok(false);
    };
    let prepared = prepared
        .first()
        .ok_or("bounded Supervisor ticket proposal produced no reservation")?;
    let typed_proposal = crate::engine::ticket_effects::GoalTicketProposal {
        project_id: binding.project_id.clone(),
        goal_revision: configured_goal.revision,
        title: prepared.proposal.title.clone(),
        body: prepared.proposal.body.clone(),
        labels: prepared.proposal.labels.clone(),
    };
    let proposal_json = serde_json::to_string(
        &serde_json::to_value(&typed_proposal).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let proposal_digest = prepared.request_digest.clone();
    let namespace = services.ticket_namespace(&project.ticket_adapter)?;
    let scope = project
        .ticket_scope
        .iter()
        .map(|(key, value)| {
            value
                .as_str()
                .map(|value| (key.clone(), value.to_owned()))
                .ok_or_else(|| format!("ticket scope `{key}` must be a string"))
        })
        .collect::<Result<std::collections::BTreeMap<_, _>, _>>()?;
    let request = crate::engine::ticket_effects::CreateGoalTicket {
        schema_version: 1,
        project_id: binding.project_id.clone(),
        namespace: namespace.clone(),
        goal_revision: configured_goal.revision,
        request_key: prepared.request_key.clone(),
        request_digest: crate::domain::ids::Digest::parse(&proposal_digest)?,
        proposal: typed_proposal,
        request: crate::engine::ticket_effects::TicketCreationRequest {
            scope,
            creation_key: prepared.request_key.clone(),
            title: prepared.proposal.title.clone(),
            body: prepared.proposal.body.clone(),
            status: Some(TicketStatus::Ready),
            template: None,
            parent: match &result.validated.typed_payload {
                RoleResultPayload::TicketProposal(value) => {
                    value.parent.as_ref().map(|id| id.as_str().to_owned())
                }
                _ => None,
            },
            dependencies: match &result.validated.typed_payload {
                RoleResultPayload::TicketProposal(value) => Some(
                    value
                        .dependencies
                        .iter()
                        .map(|id| id.as_str().to_owned())
                        .collect(),
                ),
                _ => None,
            },
            project: None,
            milestone: None,
            assignee: None,
            priority: None,
            due_date: None,
            labels: Some(prepared.proposal.labels.iter().cloned().collect()),
        },
    };
    request.validate()?;
    let reservation = store.reserve_goal_ticket_creation(
        owner_generation,
        crate::store::scheduler::GoalTicketCreation {
            project_id: &binding.project_id,
            namespace: &namespace,
            request_key: &prepared.request_key,
            request_digest: &proposal_digest,
            proposal_json: &proposal_json,
            ticket_request: &request,
            maximum: project.max_created_tickets_per_goal_revision,
            now_unix,
        },
    )?;
    if reservation.request_digest != request.request_digest.as_str() {
        return Err("reserved Goal ticket digest differs from the typed create request".into());
    }
    store.acknowledge_validated_agent_result(
        owner_generation,
        result.receipt.evidence_id(),
        current.state_revision.0.max(1),
        crate::store::agent_results::ResultDisposition::Applied,
    )?;
    Ok(true)
}

fn apply_reviewer_result(
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
        .ok_or("Reviewer ReviewReady result lacks TicketRun scope")?;
    let source_revision = binding
        .ticket_revision
        .ok_or("Reviewer ReviewReady result lacks TicketRun revision")?;
    if store.acknowledge_committed_role_result(
        owner_generation,
        "review_assessment",
        result.receipt.evidence_id(),
        &result.validated.result_digest,
        &binding.project_id,
        ticket_run_id,
    )? {
        return Ok(true);
    }
    let run = store
        .active_ticket_runs(owner_generation, 128)?
        .into_iter()
        .find(|run| run.ticket_run_id == *ticket_run_id)
        .ok_or("Reviewer result references no active TicketRun")?;
    if run.project_id != binding.project_id
        || run.revision != source_revision.0
        || !reviewer_result_allowed(run.phase, run.activity)
    {
        return Err(
            "Reviewer ReviewReady result is stale, blocked, or outside active Reviewing".into(),
        );
    }
    if crate::store::agent_results::acknowledge_obsolete_configuration_result(
        store,
        owner_generation,
        binding,
        result.receipt.evidence_id(),
        services.configuration_digest(),
    )? {
        return Ok(true);
    }
    let project_record = store
        .project(&binding.project_id)?
        .ok_or("Reviewer result Project has no durable configuration record")?;
    let configuration_digest = services.configuration_digest().clone();
    if project_record.config_digest != configuration_digest
        || binding.config_digest != configuration_digest
        || binding.config_revision != project_record.config_revision
    {
        return Err("Reviewer result belongs to a stale configuration snapshot".into());
    }
    let project = config
        .projects
        .get(&binding.project_id)
        .ok_or("Reviewer result Project is no longer configured")?;
    let snapshot = store.accepted_implementation_publication_snapshot(
        owner_generation,
        &run.project_id,
        ticket_run_id,
        run.revision,
    )?;
    let accepted = snapshot.accepted_plan();
    if accepted.configuration_digest != configuration_digest {
        return Err("accepted work plan belongs to a stale configuration snapshot".into());
    }
    let _validated_plan = accepted.validate_for(project, &configuration_digest)?;
    if snapshot.publication_revision() != run.revision
        && snapshot
            .verification()
            .is_none_or(|verification| verification.review_revision != run.revision)
    {
        return Err("Reviewer result does not match the current publication transition".into());
    }
    let publications = snapshot.publication_receipts();
    let validated_publications =
        crate::delivery_runtime::validate_implementation_publication_receipt(
            &accepted.proposal,
            snapshot.prepared_receipt(),
            &run.project_id,
            &config.repositories,
            publications,
        )?;
    let RoleResultPayload::ReviewReady(assessment) = &result.validated.typed_payload else {
        return Err("validated ReviewReady kind has a different typed payload".into());
    };
    if assessment.subject_kind != "implementation_publication_set" {
        return Err("Reviewer assessment names a different subject kind".into());
    }
    let mut subject = crate::delivery_runtime::implementation_publication_set_subject(
        &accepted.plan_digest,
        &accepted.proposal,
        &validated_publications,
        publications,
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
    let expected_subject_digest = subject.digest()?.to_string();
    if assessment.subject_digest.as_str() != expected_subject_digest {
        return Err(
            "Reviewer assessment does not match the current published PR and head set".into(),
        );
    }
    let expected_coverage = subject
        .coverage
        .iter()
        .map(|node| node.as_str().to_owned())
        .collect::<BTreeSet<_>>();
    let actual_coverage = assessment
        .evidence_coverage
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if actual_coverage != expected_coverage
        || actual_coverage.len() != assessment.evidence_coverage.len()
    {
        return Err(
            "Reviewer evidence coverage does not match every implementation work node".into(),
        );
    }
    let unresolved = !assessment.findings.is_empty() || !assessment.unknowns.is_empty();
    let completed_rounds =
        store.applied_reviewer_correction_round_count(&run.project_id, ticket_run_id)?;
    let (transition, transition_name) = review_assessment_transition(
        &assessment.disposition,
        unresolved,
        crate::engine::orchestration::ReviewProgress {
            completed_rounds,
            maximum_rounds: project.max_review_rounds,
        },
    )?;
    let accepted_revision = run
        .revision
        .checked_add(1)
        .ok_or("TicketRun revision overflow")?;
    let input_payload = serde_json::json!({
        "schema_version": 1,
        "kind": "review_assessment",
        "evidence_id": result.receipt.evidence_id(),
        "result_digest": result.validated.result_digest,
        "source_revision": run.revision,
        "accepted_revision": accepted_revision,
        "completed_rounds": completed_rounds + 1,
        "maximum_rounds": project.max_review_rounds,
        "transition": transition_name,
        "assessment": assessment,
        "publication_subject": subject,
    })
    .to_string();
    let durable = DurableInput {
        producer_id: "rex-projects-agent-result".into(),
        message_id: format!("review-ready:{}", result.receipt.evidence_id()),
        content_digest: durable_input_digest("ticket_run", &input_payload),
        recipient: "ticket_run".into(),
        payload: input_payload.clone(),
    };
    store.commit_ticket_transition(
        owner_generation,
        ticket_run_id,
        Revision(run.revision),
        &durable,
        transition,
        "host validated Reviewer assessment against the current accepted plan and complete publication receipt set",
        &input_payload,
        &[],
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

fn block_merge_observation_for_human(
    store: &mut ConfigStore,
    owner_generation: u64,
    run: &crate::store::scheduler::ActiveTicketRun,
    result: &crate::store::agent_results::IngestedAgentResult,
    now_unix: i64,
    state: &str,
) -> Result<(), String> {
    let payload = serde_json::json!({
        "kind": "merge_observation_blocked",
        "source_evidence_id": result.receipt.evidence_id(),
        "source_result_digest": result.validated.result_digest.as_str(),
        "state": state,
        "external_status": "in_progress"
    });
    let payload_json = crate::store::canonical_json(&payload)?;
    let durable = DurableInput {
        producer_id: "rex-projects-merge-observation".into(),
        message_id: format!("merge-observation-blocked:{}", result.receipt.evidence_id()),
        content_digest: durable_input_digest("ticket_run", &payload_json),
        recipient: "ticket_run".into(),
        payload: payload_json.clone(),
    };
    store.commit_ticket_transition(
        owner_generation,
        &run.ticket_run_id,
        crate::domain::ids::Revision(run.revision),
        &durable,
        crate::engine::reducer::Input::MergeAssessmentCorrectionExhausted,
        "fresh MergeDecision evidence could not be safely obtained",
        &payload_json,
        &[],
    )?;
    let _ = now_unix;
    Ok(())
}

fn acknowledge_unsupported_request_block_replay(
    store: &mut ConfigStore,
    owner_generation: u64,
    run: &crate::store::scheduler::ActiveTicketRun,
    result: &crate::store::agent_results::IngestedAgentResult,
    source_revision: u64,
) -> Result<bool, String> {
    if run.phase != Phase::Assessing || run.activity != Activity::Blocked {
        return Ok(false);
    }
    let already_blocked = store
        .ticket_run_transition_evidence(
            owner_generation,
            &run.project_id,
            &run.ticket_run_id,
            source_revision,
            32,
        )?
        .into_iter()
        .any(|(_, evidence)| {
            evidence["kind"] == "merge_observation_blocked"
                && evidence["state"] == "request_executor_unsupported"
                && evidence["source_evidence_id"].as_str() == Some(result.receipt.evidence_id())
                && evidence["source_result_digest"].as_str()
                    == Some(result.validated.result_digest.as_str())
        });
    if !already_blocked {
        return Ok(false);
    }
    store.acknowledge_validated_agent_result(
        owner_generation,
        result.receipt.evidence_id(),
        run.revision,
        crate::store::agent_results::ResultDisposition::Applied,
    )?;
    Ok(true)
}

fn block_unsupported_request_merge_assessment(
    store: &mut ConfigStore,
    owner_generation: u64,
    run: &crate::store::scheduler::ActiveTicketRun,
    result: &crate::store::agent_results::IngestedAgentResult,
    publication_set_digest: &crate::domain::ids::Digest,
    now_unix: i64,
) -> Result<(), String> {
    store.record_merge_observation_failure(
        owner_generation,
        result,
        publication_set_digest,
        now_unix,
        crate::store::agent_results::MergeObservationFailureCode::PermanentlyInvalid,
    )?;
    block_merge_observation_for_human(
        store,
        owner_generation,
        run,
        result,
        now_unix,
        "request_executor_unsupported",
    )?;
    store.acknowledge_validated_agent_result(
        owner_generation,
        result.receipt.evidence_id(),
        run.revision
            .checked_add(1)
            .ok_or("TicketRun revision overflow while blocking Request executor")?,
        crate::store::agent_results::ResultDisposition::Applied,
    )?;
    Ok(())
}

fn apply_merge_assessment(
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
        .ok_or("MergeAssessment result lacks TicketRun scope")?;
    let source_revision = binding
        .ticket_revision
        .ok_or("MergeAssessment result lacks TicketRun revision")?;
    if store
        .validated_agent_result_ack(result.receipt.evidence_id())?
        .is_some()
    {
        return Ok(true);
    }
    let deferred = store
        .merge_observation_deferral(result.receipt.evidence_id())?
        .is_some();
    let active_run = store
        .active_ticket_runs(owner_generation, 128)?
        .into_iter()
        .find(|run| run.ticket_run_id == *ticket_run_id);
    let Some(run) = active_run else {
        if deferred {
            store.invalidate_merge_observation_deferral(
                owner_generation,
                result.receipt.evidence_id(),
                now_unix,
            )?;
            return Ok(true);
        }
        return Err("MergeAssessment result references no active TicketRun".into());
    };
    if acknowledge_unsupported_request_block_replay(
        store,
        owner_generation,
        &run,
        result,
        source_revision.0,
    )? {
        return Ok(true);
    }
    if binding.role != Role::MergeDecision
        || run.project_id != binding.project_id
        || run.revision != source_revision.0
        || run.phase != Phase::Assessing
        || run.activity != Activity::Running
    {
        if deferred {
            store.invalidate_merge_observation_deferral(
                owner_generation,
                result.receipt.evidence_id(),
                now_unix,
            )?;
            return Ok(true);
        }
        return Err("MergeAssessment result is stale, blocked, or outside active Assessing".into());
    }
    if binding.config_digest != *services.configuration_digest()
        && let Some(recovery) = store.recovery_authorization_for_merge_failure(result)?
    {
        store.fail_resumed_merge_claim_recovery(
            owner_generation,
            &recovery,
            result,
            "resumed MergeDecision result belongs to an obsolete Project configuration",
            now_unix,
        )?;
        return Ok(true);
    }
    if crate::store::agent_results::acknowledge_obsolete_configuration_result(
        store,
        owner_generation,
        binding,
        result.receipt.evidence_id(),
        services.configuration_digest(),
    )? {
        return Ok(true);
    }
    let configuration_digest = services.configuration_digest().clone();
    let project_record = store
        .project(&binding.project_id)?
        .ok_or("MergeDecision Project has no durable configuration record")?;
    if binding.config_digest != configuration_digest
        || project_record.config_digest != configuration_digest
        || binding.config_revision != project_record.config_revision
    {
        return Err("MergeAssessment result belongs to a stale Project configuration".into());
    }
    if let Some(deferral) = store.merge_observation_deferral(result.receipt.evidence_id())? {
        let blocked_reason = match deferral.state {
            crate::store::agent_results::MergeObservationDeferralState::Waiting { .. } => None,
            crate::store::agent_results::MergeObservationDeferralState::Exhausted { .. } => {
                Some("retry_exhausted")
            }
            crate::store::agent_results::MergeObservationDeferralState::PermanentlyInvalid => {
                Some("permanent_invalid")
            }
        };
        if let Some(reason) = blocked_reason {
            block_merge_observation_for_human(
                store,
                owner_generation,
                &run,
                result,
                now_unix,
                reason,
            )?;
            return Ok(true);
        }
    }
    let project = config
        .projects
        .get(&binding.project_id)
        .ok_or("MergeDecision Project is no longer configured")?;
    let recovery = store.recovery_authorization_for_merge_result(result)?;
    let snapshot = if let Some(recovery) = &recovery {
        if recovery.subject.instruction_digest != binding.instruction_digest
            || recovery.subject.blocked_revision.checked_add(1) != Some(run.revision)
        {
            store.fail_resumed_merge_claim_recovery(
                owner_generation,
                recovery,
                result,
                "resumed MergeDecision authority or revision differs from the approved recovery subject",
                now_unix,
            )?;
            return Ok(true);
        }
        store.merge_claim_recovery_publication_snapshot(&recovery.subject)?
    } else {
        store.accepted_implementation_publication_snapshot(
            owner_generation,
            &run.project_id,
            ticket_run_id,
            run.revision,
        )?
    };
    let accepted = snapshot.accepted_plan();
    if accepted.configuration_digest != configuration_digest {
        return Err("accepted work plan belongs to a stale configuration snapshot".into());
    }
    accepted.validate_for(project, &configuration_digest)?;
    let expected_assessing_revision = match snapshot.verification() {
        Some(verification) => verification
            .review_revision
            .checked_add(1)
            .ok_or("verification review revision overflow")?,
        None => snapshot
            .publication_revision()
            .checked_add(1)
            .ok_or("publication review revision overflow")?,
    };
    if recovery.is_none() && run.revision != expected_assessing_revision {
        return Err(
            "MergeDecision is not at the exact accepted review-convergence revision".into(),
        );
    }
    let publications = snapshot.publication_receipts();
    let validated_publications =
        crate::delivery_runtime::validate_implementation_publication_receipt(
            &accepted.proposal,
            snapshot.prepared_receipt(),
            &run.project_id,
            &config.repositories,
            publications,
        )?;
    let mut publication_subject = crate::delivery_runtime::implementation_publication_set_subject(
        &accepted.plan_digest,
        &accepted.proposal,
        &validated_publications,
        publications,
        snapshot.publication_revision(),
    )?;
    publication_subject.verification = snapshot.verification().map(|verification| {
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
    let publication_set_digest = publication_subject.digest()?;
    if let Some(recovery) = &recovery
        && publication_set_digest != recovery.subject.publication_set_digest
    {
        store.fail_resumed_merge_claim_recovery(
            owner_generation,
            recovery,
            result,
            "accepted publication set changed during the resumed MergeDecision turn",
            now_unix,
        )?;
        return Ok(true);
    }
    let observation_result = match &recovery {
        Some(recovery) => services.observe_recovery_merge_assessment(
            &publication_subject,
            &recovery.subject.instruction_digest,
        ),
        None => services.observe_merge_assessment(&publication_subject, result),
    };
    let observation = match observation_result {
        Ok(Some(observation)) => observation,
        Ok(None) => {
            if let Some(recovery) = &recovery {
                store.fail_resumed_merge_claim_recovery(
                    owner_generation,
                    recovery,
                    result,
                    "host MergeDecision observation was empty during the one resumed turn",
                    now_unix,
                )?;
                return Ok(true);
            }
            return Err("host MergeDecision observation is unavailable".into());
        }
        Err(crate::merge_runtime::MergeObservationError::Retryable(failure)) => {
            if let Some(recovery) = &recovery {
                store.fail_resumed_merge_claim_recovery(
                    owner_generation,
                    recovery,
                    result,
                    "fresh Forge evidence was temporarily unavailable during the one resumed turn",
                    now_unix,
                )?;
                return Ok(true);
            }
            let failure_code = match failure {
                crate::forge::ForgeTransientFailure::ProcessUnavailable => {
                    crate::store::agent_results::MergeObservationFailureCode::ProcessUnavailable
                }
                crate::forge::ForgeTransientFailure::TimedOut => {
                    crate::store::agent_results::MergeObservationFailureCode::TimedOut
                }
            };
            let state = store.record_merge_observation_failure(
                owner_generation,
                result,
                &publication_set_digest,
                now_unix,
                failure_code,
            )?;
            if matches!(
                state,
                crate::store::agent_results::MergeObservationDeferralState::Waiting { .. }
            ) {
                return Ok(true);
            }
            block_merge_observation_for_human(
                store,
                owner_generation,
                &run,
                result,
                now_unix,
                "retry_exhausted",
            )?;
            return Ok(true);
        }
        Err(crate::merge_runtime::MergeObservationError::Permanent(_)) => {
            if let Some(recovery) = &recovery {
                store.fail_resumed_merge_claim_recovery(
                    owner_generation,
                    recovery,
                    result,
                    "fresh Forge evidence no longer validates the one resumed turn",
                    now_unix,
                )?;
                return Ok(true);
            }
            store.record_merge_observation_failure(
                owner_generation,
                result,
                &publication_set_digest,
                now_unix,
                crate::store::agent_results::MergeObservationFailureCode::PermanentlyInvalid,
            )?;
            block_merge_observation_for_human(
                store,
                owner_generation,
                &run,
                result,
                now_unix,
                "permanent_invalid",
            )?;
            return Ok(true);
        }
    };
    if observation.publication_set_digest != publication_set_digest {
        if let Some(recovery) = &recovery {
            store.fail_resumed_merge_claim_recovery(
                owner_generation,
                recovery,
                result,
                "fresh Forge observation belongs to a different publication set",
                now_unix,
            )?;
            return Ok(true);
        }
        return Err(
            "host MergeDecision observation is bound to a different publication set".into(),
        );
    }
    let RoleResultPayload::MergeAssessment(claim) = &result.validated.typed_payload else {
        return Err("validated MergeAssessment kind has a different typed payload".into());
    };
    let trusted = match crate::merge_runtime::assess_merge_claim(
        claim,
        &result.validated.result_digest,
        &observation,
    ) {
        Ok(trusted) => trusted,
        Err(crate::merge_runtime::MergeAssessmentError::PullRequestReferenceMismatch(reason)) => {
            if let Some(recovery) = &recovery {
                store.fail_resumed_merge_claim_recovery(
                    owner_generation,
                    recovery,
                    result,
                    &format!(
                        "resumed MergeDecision still mismatched the observed pull request: {reason}"
                    ),
                    now_unix,
                )?;
                return Ok(true);
            }
            store.reject_merge_assessment_claim(
                owner_generation,
                result,
                publication_set_digest.as_str(),
                &observation.pull_request_reference,
                &reason,
            )?;
            return Ok(true);
        }
        Err(
            crate::merge_runtime::MergeAssessmentError::InvalidAgentClaim(error)
            | crate::merge_runtime::MergeAssessmentError::Host(error),
        ) => {
            if let Some(recovery) = &recovery {
                store.fail_resumed_merge_claim_recovery(
                    owner_generation,
                    recovery,
                    result,
                    &format!("resumed MergeDecision claim failed host validation: {error}"),
                    now_unix,
                )?;
                return Ok(true);
            }
            return Err(error);
        }
    };
    if observation.policy.executor == crate::domain::types::MergeExecutor::Request
        && trusted.assessment.disposition == crate::merge_policy::MergeDisposition::Blocked
    {
        if let Some(recovery) = &recovery {
            store.fail_resumed_merge_claim_recovery(
                owner_generation,
                recovery,
                result,
                "configured Request executor has no verifiable execution contract",
                now_unix,
            )?;
            return Ok(true);
        }
        block_unsupported_request_merge_assessment(
            store,
            owner_generation,
            &run,
            result,
            &publication_set_digest,
            now_unix,
        )?;
        return Ok(true);
    }
    let assessment_id = crate::merge_runtime::assessment_id(
        &run.project_id,
        ticket_run_id,
        Revision(run.revision),
        result.receipt.evidence_id(),
        &result.validated.result_digest,
        &trusted.evidence,
    )?;
    let prepared_body_proposal = services.prepare_merge_body_proposal(
        &run.project_id,
        &publication_subject,
        &accepted.proposal,
        &assessment_id,
        &observation,
    )?;
    let persisted = crate::store::merge_work::TrustedMergeAssessment {
        schema_version: 1,
        assessment_id,
        project_id: run.project_id,
        ticket_run_id: ticket_run_id.clone(),
        revision: Revision(run.revision),
        configuration_digest,
        source_evidence_id: result.receipt.evidence_id().to_owned(),
        source_result_digest: result.validated.result_digest.clone(),
        publication_set_digest: trusted.publication_set_digest,
        pull_request_reference: trusted.pull_request_reference,
        policy_digest: trusted.policy_digest,
        policy: observation.policy,
        evidence: trusted.evidence,
        assessment: trusted.assessment,
        baseline_issue_comments: trusted.baseline_issue_comments,
        prepared_body_proposal: Some(prepared_body_proposal),
    };
    store.persist_trusted_merge_assessment(
        owner_generation,
        result,
        &persisted,
        recovery.as_ref(),
        now_unix,
    )?;
    Ok(true)
}

fn apply_merge_intent(
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
        .ok_or("MergeIntent result lacks TicketRun scope")?;
    let revision = binding
        .ticket_revision
        .ok_or("MergeIntent result lacks TicketRun revision")?;
    let run = store
        .active_ticket_runs(owner_generation, 128)?
        .into_iter()
        .find(|run| run.ticket_run_id == *ticket_run_id)
        .ok_or("MergeIntent result references no active TicketRun")?;
    if acknowledge_unsupported_request_block_replay(
        store,
        owner_generation,
        &run,
        result,
        revision.0,
    )? {
        return Ok(true);
    }
    if binding.role == Role::MergeDecision
        && run.phase == Phase::WaitingHuman
        && run.activity == Activity::Blocked
        && let Some(accepted_revision) = run.revision.checked_add(1)
        && let Some(item) =
            store.merge_work_item(&run.project_id, ticket_run_id, Revision(accepted_revision))?
        && merge_intent_replay_matches(
            &run.project_id,
            run.revision,
            binding,
            result,
            &MergeIntentReplayIdentity {
                assessed_revision: item.assessed_revision,
                awaiting_merge_revision: item.awaiting_merge_revision,
                configuration_digest: item.configuration_digest,
                intent_evidence_id: item.document.intent_evidence_id,
                intent_result_digest: item.document.intent_result_digest,
            },
        )
    {
        acknowledge_merge_intent_replay(store, owner_generation, result, run.revision)?;
        return Ok(true);
    }
    if binding.role != Role::MergeDecision
        || run.project_id != binding.project_id
        || run.revision != revision.0
        || run.phase != Phase::Assessing
        || run.activity != Activity::Running
    {
        return Err("MergeIntent result is stale, blocked, or outside active Assessing".into());
    }
    let trusted = store
        .trusted_merge_assessment(&run.project_id, ticket_run_id, Revision(run.revision))?
        .ok_or("MergeIntent has no host-validated assessment for this exact revision")?;
    let RoleResultPayload::MergeIntent(intent) = &result.validated.typed_payload else {
        return Err("validated MergeIntent kind has a different typed payload".into());
    };
    if trusted.project_id != run.project_id
        || trusted.ticket_run_id != *ticket_run_id
        || trusted.revision != Revision(run.revision)
        || trusted.configuration_digest != binding.config_digest
        || intent.assessment_id != trusted.assessment_id.as_str()
        || intent.policy_digest != trusted.policy_digest
        || intent.pr_identities != [trusted.pull_request_reference.clone()]
        || trusted.evidence.subject.prepared_body_digest.is_none()
    {
        return Err("MergeIntent does not match the immutable host assessment, exact PR, policy, or reviewed body".into());
    }
    let project_record = store
        .project(&run.project_id)?
        .ok_or("MergeDecision Project has no durable configuration record")?;
    if binding.config_digest != *services.configuration_digest()
        || project_record.config_digest != *services.configuration_digest()
        || binding.config_revision != project_record.config_revision
    {
        return Err("MergeIntent result belongs to a stale Project configuration".into());
    }
    if trusted.policy.executor == crate::domain::types::MergeExecutor::Request {
        if let Some(recovery) = store.recovery_authorization_for_merge_failure(result)? {
            store.fail_resumed_merge_claim_recovery(
                owner_generation,
                &recovery,
                result,
                "legacy Request MergeIntent has no verifiable execution contract",
                now_unix,
            )?;
            return Ok(true);
        }
        block_merge_observation_for_human(
            store,
            owner_generation,
            &run,
            result,
            now_unix,
            "request_executor_unsupported",
        )?;
        store.acknowledge_validated_agent_result(
            owner_generation,
            result.receipt.evidence_id(),
            run.revision
                .checked_add(1)
                .ok_or("TicketRun revision overflow while blocking legacy Request MergeIntent")?,
            crate::store::agent_results::ResultDisposition::Applied,
        )?;
        return Ok(true);
    }
    let project = config
        .projects
        .get(&run.project_id)
        .ok_or("MergeDecision Project is no longer configured")?;
    let snapshot = if let Some(subject) = store.merge_claim_recovery_subject_for_assessment(
        &run.project_id,
        ticket_run_id,
        &trusted.source_evidence_id,
    )? {
        if subject.blocked_revision.checked_add(1) != Some(run.revision)
            || subject.configuration_digest != binding.config_digest
        {
            return Err(
                "MergeIntent recovery lineage differs from the accepted resumed assessment".into(),
            );
        }
        store.merge_claim_recovery_publication_snapshot(&subject)?
    } else {
        store.accepted_implementation_publication_snapshot(
            owner_generation,
            &run.project_id,
            ticket_run_id,
            run.revision,
        )?
    };
    let accepted = snapshot.accepted_plan();
    if accepted.configuration_digest != *services.configuration_digest() {
        return Err("accepted work plan belongs to a stale configuration snapshot".into());
    }
    accepted.validate_for(project, services.configuration_digest())?;
    let validated_publications =
        crate::delivery_runtime::validate_implementation_publication_receipt(
            &accepted.proposal,
            snapshot.prepared_receipt(),
            &run.project_id,
            &config.repositories,
            snapshot.publication_receipts(),
        )?;
    let mut publication_subject = crate::delivery_runtime::implementation_publication_set_subject(
        &accepted.plan_digest,
        &accepted.proposal,
        &validated_publications,
        snapshot.publication_receipts(),
        snapshot.publication_revision(),
    )?;
    publication_subject.verification = snapshot.verification().map(|verification| {
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
    if publication_subject.digest()? != trusted.publication_set_digest {
        return Err(
            "MergeIntent host assessment belongs to a different accepted publication set".into(),
        );
    }
    let document = services.resolve_merge_work_document(
        &publication_subject,
        &accepted.proposal,
        &trusted,
        intent,
        result,
    )?;
    let assessed_revision = Revision(run.revision);
    let awaiting_merge_revision = Revision(
        assessed_revision
            .0
            .checked_add(2)
            .ok_or("MergeIntent human approval revision overflow")?,
    );
    let prepared_receipt_digest = crate::forge::canonical_digest(snapshot.prepared_receipt())
        .map_err(|error| error.to_string())?;
    let work_item = crate::store::merge_work::MergeWorkItem::new(
        run.project_id.clone(),
        ticket_run_id.clone(),
        assessed_revision,
        awaiting_merge_revision,
        trusted.configuration_digest.clone(),
        accepted.plan_digest.clone(),
        prepared_receipt_digest,
        trusted.publication_set_digest.clone(),
        document,
    )?;
    store.persist_merge_work_item(owner_generation, &work_item, now_unix)?;
    let review_revision = Revision(
        assessed_revision
            .0
            .checked_add(1)
            .ok_or("MergeIntent human review revision overflow")?,
    );
    let view_id = store
        .active_ticket_view_id(owner_generation, &run.project_id, ticket_run_id)?
        .ok_or("MergeIntent has no active TicketRun Rex view")?;
    let request_id = crate::domain::ids::HumanRequestId::parse(format!(
        "merge-review-{}",
        result.receipt.evidence_id()
    ))?;
    let expires_at = u64::try_from(now_unix)
        .map_err(|_| "controller time is before the Unix epoch")?
        .saturating_add(7 * 24 * 60 * 60);
    let work_id = work_item.work_id.clone();
    let presentation = crate::human_runtime::HumanAuthorityMaterial::merge_work_review_effect(
        request_id.clone(),
        view_id,
        work_item,
        expires_at,
    )?;
    let request_json = crate::store::canonical_json(&presentation)?;
    let review_effect = EffectIntent {
        project_id: run.project_id.clone(),
        subject_type: "ticket_run".into(),
        subject_id: ticket_run_id.as_str().into(),
        operation_id: OperationId::parse(format!("present-{}", request_id.as_str()))?
            .as_str()
            .into(),
        logical_key: format!(
            "{}:{}:merge-review:{}",
            ticket_run_id, run.revision, request_id
        ),
        kind: "request_human_review".into(),
        request_digest: format!("{:x}", sha2::Sha256::digest(request_json.as_bytes())),
        request_json,
        expected_revision: Some(review_revision.0),
    };
    let expected_external_revision = store.ticket_run_external_revision(
        owner_generation,
        &run.project_id,
        ticket_run_id,
        run.revision,
    )?;
    let status_payload = crate::engine::ticket_effects::PublishTicketStatus {
        schema_version: 1,
        project_id: run.project_id.clone(),
        namespace: run.namespace.clone(),
        ticket_id: run.ticket_id.clone(),
        ticket_run_id: ticket_run_id.clone(),
        ticket_run_revision: review_revision.0,
        expected_external_revision: Some(expected_external_revision),
        desired_status: crate::domain::types::TicketStatus::InReview,
        reason: "MergeDecision requires human review of the exact host-validated merge procedure"
            .into(),
    };
    status_payload.validate()?;
    let status_json = crate::store::canonical_json(&status_payload)?;
    let status_effect = EffectIntent {
        project_id: run.project_id.clone(),
        subject_type: "ticket_run".into(),
        subject_id: ticket_run_id.as_str().into(),
        operation_id: OperationId::parse(format!(
            "publish-status-merge-review-{}-{}",
            ticket_run_id, run.revision
        ))?
        .as_str()
        .into(),
        logical_key: format!(
            "{}:{}:publish-status-after-merge-review",
            ticket_run_id, run.revision
        ),
        kind: "publish_ticket_status".into(),
        request_digest: format!("{:x}", sha2::Sha256::digest(status_json.as_bytes())),
        request_json: status_json,
        expected_revision: Some(review_revision.0),
    };
    let accepted_revision = review_revision;
    let input_payload = crate::store::canonical_json(&serde_json::json!({
        "schema_version": 1,
        "kind": "merge_intent",
        "evidence_id": result.receipt.evidence_id(),
        "result_digest": result.validated.result_digest,
        "assessment_id": trusted.assessment_id,
        "work_id": work_id,
        "source_revision": run.revision,
        "accepted_revision": accepted_revision,
    }))?;
    let durable = DurableInput {
        producer_id: "rex-projects-agent-result".into(),
        message_id: format!("merge-intent:{}", result.receipt.evidence_id()),
        content_digest: durable_input_digest("ticket_run", &input_payload),
        recipient: "ticket_run".into(),
        payload: input_payload.clone(),
    };
    store.commit_ticket_transition(
        owner_generation,
        ticket_run_id,
        assessed_revision,
        &durable,
        Input::RequireHumanReview,
        "host validated MergeIntent against the same-revision trusted assessment and persisted its exact review procedure",
        &input_payload,
        &[review_effect, status_effect],
    )?;
    store.acknowledge_validated_agent_result(
        owner_generation,
        result.receipt.evidence_id(),
        accepted_revision.0,
        crate::store::agent_results::ResultDisposition::Applied,
    )?;
    Ok(true)
}

struct MergeIntentReplayIdentity {
    assessed_revision: Revision,
    awaiting_merge_revision: Revision,
    configuration_digest: crate::domain::ids::Digest,
    intent_evidence_id: String,
    intent_result_digest: crate::domain::ids::Digest,
}

fn merge_intent_replay_matches(
    run_project_id: &crate::domain::ids::ProjectId,
    run_revision: u64,
    binding: &crate::engine::orchestration::RoleResultBinding,
    result: &crate::store::agent_results::IngestedAgentResult,
    item: &MergeIntentReplayIdentity,
) -> bool {
    let Some(ticket_run_id) = binding.ticket_run_id.as_ref() else {
        return false;
    };
    binding.role == Role::MergeDecision
        && binding.project_id == *run_project_id
        && binding.ticket_revision == Some(item.assessed_revision)
        && item.assessed_revision.0.checked_add(1) == Some(run_revision)
        && item.awaiting_merge_revision.0.checked_sub(1) == Some(run_revision)
        && item.configuration_digest == binding.config_digest
        && item.intent_evidence_id == result.receipt.evidence_id()
        && item.intent_result_digest == result.validated.result_digest
        && result.validated.binding.project_id == *run_project_id
        && result.validated.binding.ticket_run_id.as_ref() == Some(ticket_run_id)
        && result.validated.binding.ticket_revision == Some(item.assessed_revision)
        && result.validated.kind == crate::engine::orchestration::RoleOutputKind::MergeIntent
        && result.validated.assertion == crate::engine::orchestration::AgentAssertion::Succeeded
}

fn acknowledge_merge_intent_replay(
    store: &mut ConfigStore,
    owner_generation: u64,
    result: &crate::store::agent_results::IngestedAgentResult,
    accepted_revision: u64,
) -> Result<(), String> {
    store.acknowledge_validated_agent_result(
        owner_generation,
        result.receipt.evidence_id(),
        accepted_revision,
        crate::store::agent_results::ResultDisposition::Applied,
    )
}

fn review_transition(
    disposition: crate::engine::orchestration::ReviewDisposition,
) -> (Input, &'static str) {
    use crate::engine::orchestration::ReviewDisposition as D;
    match disposition {
        D::StartCorrectionWorker => (Input::CorrectionsRemain, "corrections_remain"),
        D::StartMergeDecision => (Input::ReviewConverged, "review_converged"),
        D::HumanRequiredAtRoundLimit => (
            Input::ReviewEscalationRequired,
            "review_round_limit_reached",
        ),
    }
}

fn review_assessment_transition(
    raw_disposition: &str,
    has_unresolved_items: bool,
    progress: crate::engine::orchestration::ReviewProgress,
) -> Result<(Input, &'static str), String> {
    use crate::engine::orchestration::review_disposition;

    let disposition = raw_disposition.trim().to_ascii_lowercase();
    if disposition.is_empty() {
        return Err("Reviewer assessment has an empty disposition".into());
    }
    match disposition.as_str() {
        "approved" if !has_unresolved_items => Ok((Input::ReviewConverged, "review_converged")),
        "approved" | "changes_requested" if has_unresolved_items => {
            Ok(review_transition(review_disposition(progress, true)?))
        }
        "changes_requested" => Ok((Input::ReviewEscalationRequired, "review_requires_human")),
        _ => Ok((
            Input::ReviewEscalationRequired,
            "review_disposition_unrecognized",
        )),
    }
}

fn reviewer_result_allowed(phase: Phase, activity: crate::engine::reducer::Activity) -> bool {
    phase == Phase::Reviewing && activity == crate::engine::reducer::Activity::Running
}

fn apply_operator_result(
    store: &mut ConfigStore,
    owner_generation: u64,
    now_unix: i64,
    services: &impl FactoryRuntimeServices,
    result: &crate::store::agent_results::IngestedAgentResult,
) -> Result<bool, String> {
    let binding = &result.validated.binding;
    let ticket_run_id = binding
        .ticket_run_id
        .as_ref()
        .ok_or("Operator result lacks TicketRun scope")?;
    let revision = binding
        .ticket_revision
        .ok_or("Operator result lacks TicketRun revision")?;
    let run = store
        .active_ticket_runs(owner_generation, 128)?
        .into_iter()
        .find(|run| run.ticket_run_id == *ticket_run_id)
        .ok_or("Operator result references no active TicketRun")?;
    if run.project_id != binding.project_id
        || run.revision != revision.0
        || run.phase != Phase::Operating
    {
        return Err("Operator result is stale or outside Operating".into());
    }
    validate_result_configuration(store, services.configuration_digest(), binding)?;
    let gate = store
        .operations()?
        .completion_gate(&run.project_id, ticket_run_id)?;
    if gate != crate::store::operations::CompletionGate::WaitingForPostmortem {
        return Ok(false);
    }
    let crate::engine::orchestration::RoleResultPayload::OperationResult(_) =
        &result.validated.typed_payload
    else {
        return Err("validated OperationResult kind has a different typed payload".into());
    };
    store.acknowledge_validated_agent_result(
        owner_generation,
        result.receipt.evidence_id(),
        revision.0,
        crate::store::agent_results::ResultDisposition::Applied,
    )?;
    let _ = now_unix;
    Ok(true)
}

fn apply_postmortem_result(
    store: &mut ConfigStore,
    owner_generation: u64,
    now_unix: i64,
    config: &Config,
    services: &impl FactoryRuntimeServices,
    result: &crate::store::agent_results::IngestedAgentResult,
) -> Result<bool, String> {
    use crate::domain::ids::OperationId;
    use crate::engine::orchestration::RoleResultPayload;

    let binding = &result.validated.binding;
    let ticket_run_id = binding
        .ticket_run_id
        .as_ref()
        .ok_or("Postmortem result lacks TicketRun scope")?;
    let revision = binding
        .ticket_revision
        .ok_or("Postmortem result lacks TicketRun revision")?;
    let run = store
        .active_ticket_runs(owner_generation, 128)?
        .into_iter()
        .find(|run| run.ticket_run_id == *ticket_run_id)
        .ok_or("Postmortem result references no active TicketRun")?;
    if run.project_id != binding.project_id
        || run.revision != revision.0
        || run.phase != Phase::Postmortem
    {
        return Err("Postmortem result is stale or outside Postmortem".into());
    }
    validate_result_configuration(store, services.configuration_digest(), binding)?;
    let max_source_bytes = config
        .knowledge
        .as_ref()
        .ok_or("Postmortem publication requires configured knowledge limits")?
        .max_source_bytes;
    let max_source_bytes = usize::try_from(max_source_bytes)
        .map_err(|_| "knowledge.max_source_bytes exceeds the supported size")?;
    let RoleResultPayload::PostmortemReady(payload) = &result.validated.typed_payload else {
        return Err("validated PostmortemReady kind has a different typed payload".into());
    };
    if payload.findings.is_empty()
        || payload.source_references.is_empty()
        || !payload.unresolved_provenance.is_empty()
        || payload.source_references.len() != result.verified_artifacts.len()
    {
        return Err("Postmortem result lacks resolved, registered source artifacts".into());
    }
    let title = payload
        .candidate_publication_manifest
        .get("title")
        .filter(|value| !value.trim().is_empty())
        .ok_or("Postmortem manifest lacks title")?
        .clone();
    let summary = payload
        .candidate_publication_manifest
        .get("summary")
        .filter(|value| !value.trim().is_empty())
        .ok_or("Postmortem manifest lacks summary")?
        .clone();
    let operation_id = OperationId::parse(format!("knowledge-{}", result.receipt.evidence_id()))?;
    if let Some(intent) = store.knowledge_publication_intent(&operation_id)? {
        if intent.project_id != run.project_id || intent.ticket_run_id != *ticket_run_id {
            return Err("stored knowledge request does not match this Postmortem result".into());
        }
        store.prepare_knowledge_publication(owner_generation, &intent)?;
        store.acknowledge_validated_agent_result(
            owner_generation,
            result.receipt.evidence_id(),
            revision.0,
            crate::store::agent_results::ResultDisposition::Applied,
        )?;
        return Ok(true);
    }
    let mut source_bytes = 0usize;
    let sources = payload
        .source_references
        .iter()
        .zip(&result.verified_artifacts)
        .map(|(reference, verified)| {
            if verified.reference() != reference
                || reference.kind != crate::engine::orchestration::RoleArtifactKind::Postmortem
            {
                return Err("Postmortem source is not the matching registered artifact".to_owned());
            }
            let artifact_size = usize::try_from(reference.bytes)
                .map_err(|_| "Postmortem source exceeds the article byte limit")?;
            source_bytes = source_bytes
                .checked_add(artifact_size)
                .ok_or("Postmortem source byte count overflow")?;
            if source_bytes > max_source_bytes {
                return Err("Postmortem source material exceeds the configured byte limit".into());
            }
            let content = services.read_verified_artifact(verified)?;
            if content.len() != artifact_size {
                return Err("registered Postmortem source size changed after verification".into());
            }
            let content = String::from_utf8(content)
                .map_err(|_| "registered Postmortem source is not UTF-8")?;
            Ok(crate::knowledge::KnowledgeSource {
                id: reference.artifact_id.as_str().to_owned(),
                title: "Registered Postmortem source".into(),
                resource: format!("rex-artifact://{}", reference.artifact_id),
                content,
                digest: reference.digest.clone(),
                trusted: false,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let input = crate::knowledge::PostmortemInput {
        operation_id: operation_id.clone(),
        project_id: run.project_id.clone(),
        ticket_run_id: ticket_run_id.clone(),
        title,
        summary,
        findings: payload.findings.clone(),
        sources,
        generated_at: format_utc_timestamp(now_unix)?,
        max_source_bytes,
    };
    let request_json = serde_json::to_string(&input).map_err(|error| error.to_string())?;
    use sha2::Digest as _;
    let request_digest = Digest::parse(format!(
        "{:x}",
        sha2::Sha256::digest(request_json.as_bytes())
    ))?;
    let intent = crate::store::KnowledgePublicationIntent {
        operation_id,
        project_id: run.project_id,
        ticket_run_id: ticket_run_id.clone(),
        request_digest,
        request_json,
    };
    store.prepare_knowledge_publication(owner_generation, &intent)?;
    store.acknowledge_validated_agent_result(
        owner_generation,
        result.receipt.evidence_id(),
        revision.0,
        crate::store::agent_results::ResultDisposition::Applied,
    )?;
    Ok(true)
}

fn validate_result_configuration(
    store: &ConfigStore,
    current_digest: &Digest,
    binding: &crate::engine::orchestration::RoleResultBinding,
) -> Result<(), String> {
    let project = store
        .project(&binding.project_id)?
        .ok_or("role result Project has no durable configuration record")?;
    if project.config_digest != *current_digest
        || binding.config_digest != *current_digest
        || binding.config_revision != project.config_revision
    {
        return Err("role result belongs to a stale configuration snapshot".into());
    }
    Ok(())
}

fn format_utc_timestamp(unix: i64) -> Result<String, String> {
    let days = unix.div_euclid(86_400);
    let seconds = unix.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    if !(0..=9999).contains(&year) {
        return Err("timestamp is outside supported UTC years".into());
    }
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        seconds / 3600,
        seconds / 60 % 60,
        seconds % 60
    ))
}

fn apply_worker_result(
    store: &mut ConfigStore,
    owner_generation: u64,
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
    if store.acknowledge_committed_role_result(
        owner_generation,
        "worker_implementation_ready",
        result.receipt.evidence_id(),
        &result.validated.result_digest,
        &binding.project_id,
        ticket_run_id,
    )? {
        return Ok(true);
    }
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
    if crate::store::agent_results::acknowledge_obsolete_configuration_result(
        store,
        owner_generation,
        binding,
        result.receipt.evidence_id(),
        services.configuration_digest(),
    )? {
        return Ok(true);
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
    let input_payload = worker_result_transition_payload(
        result.receipt.evidence_id(),
        &result.validated.result_digest,
        run.revision,
        &effect.operation_id,
        effect_revision,
    );
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

pub(crate) fn worker_result_transition_payload(
    evidence_id: &str,
    result_digest: &Digest,
    source_revision: u64,
    publication_operation_id: &str,
    accepted_revision: u64,
) -> String {
    serde_json::json!({
        "schema_version": 1,
        "kind": "worker_implementation_ready",
        "evidence_id": evidence_id,
        "result_digest": result_digest,
        "source_revision": source_revision,
        "accepted_revision": accepted_revision,
        "publication_operation_id": publication_operation_id,
        "transition": "worker_implementation_ready",
    })
    .to_string()
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
    let proposal = canonical_goal_ticket_proposal(project, goal_revision, title, body, labels)?;
    let bytes =
        serde_json::to_vec(&serde_json::to_value(&proposal).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    use sha2::Digest as _;
    Ok(format!("goal-{:x}", sha2::Sha256::digest(bytes)))
}

fn canonical_goal_ticket_proposal(
    project: &ProjectId,
    goal_revision: u64,
    title: &str,
    body: &str,
    labels: &BTreeSet<String>,
) -> Result<crate::engine::ticket_effects::GoalTicketProposal, String> {
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
    Ok(crate::engine::ticket_effects::GoalTicketProposal {
        project_id: project.clone(),
        goal_revision,
        title,
        body,
        labels: labels.clone(),
    })
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
        let normalized = GoalTicketProposal {
            title: proposal
                .title
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" "),
            body: proposal.body.replace("\r\n", "\n").replace('\r', "\n"),
            labels: proposal.labels.clone(),
        };
        let request_digest = goal_ticket_request_digest(project_id, goal_revision, &normalized)?;
        prepared.push(PreparedGoalTicket {
            request_key,
            request_digest,
            proposal: normalized,
        });
    }
    if prepared.is_empty() {
        Ok(GoalSupervisorAction::Idle)
    } else {
        Ok(GoalSupervisorAction::Create(prepared))
    }
}

fn goal_ticket_request_digest(
    project_id: &ProjectId,
    goal_revision: u64,
    proposal: &GoalTicketProposal,
) -> Result<String, String> {
    let canonical = canonical_goal_ticket_proposal(
        project_id,
        goal_revision,
        &proposal.title,
        &proposal.body,
        &proposal.labels,
    )?;
    let bytes =
        serde_json::to_vec(&serde_json::to_value(&canonical).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
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
fn apply_coordinator_spawn_request(
    store: &mut ConfigStore,
    owner_generation: u64,
    now_unix: i64,
    config: &Config,
    services: &impl FactoryRuntimeServices,
    result: &crate::store::agent_results::IngestedAgentResult,
) -> Result<bool, String> {
    let binding = &result.validated.binding;
    let ticket_run_id = binding
        .ticket_run_id
        .as_ref()
        .ok_or("Coordinator SpawnRequest lacks TicketRun scope")?;
    let crate::engine::orchestration::RoleResultPayload::SpawnRequest(request) =
        &result.validated.typed_payload
    else {
        return Err("validated SpawnRequest kind has a different typed payload".into());
    };
    if let Some(recovery) = store.recovery_authorization_for_coordinator_result(result)? {
        let requested_plan_matches = store
            .latest_accepted_work_plan(&binding.project_id, ticket_run_id)?
            .is_some_and(|plan| {
                request.plan_digest.as_ref() == Some(&plan.plan_digest)
                    && plan.plan_digest == recovery.subject.accepted_plan_digest
                    && plan
                        .proposal
                        .nodes
                        .iter()
                        .any(|node| node.id == request.work_node)
            });
        if request.role != Role::MergeDecision
            || request.worker_recovery.is_some()
            || !request.allowed_repositories.is_empty()
            || !request.artifact_inputs.is_empty()
            || request.parent_run_id.as_ref() != Some(&binding.agent_run_id)
            || !requested_plan_matches
            || request.plan_digest.as_ref() != Some(&recovery.subject.accepted_plan_digest)
        {
            store.fail_merge_claim_recovery_attempt(
                owner_generation,
                &recovery.request_id,
                result,
                "Coordinator did not request exactly the accepted MergeDecision node",
                now_unix,
            )?;
            return Ok(true);
        }
        let project_record = store
            .project(&binding.project_id)?
            .ok_or("Coordinator SpawnRequest Project has no durable configuration record")?;
        let configuration_digest = services.configuration_digest();
        if project_record.config_digest != *configuration_digest
            || binding.config_digest != *configuration_digest
            || binding.config_revision != project_record.config_revision
        {
            store.fail_merge_claim_recovery_attempt(
                owner_generation,
                &recovery.request_id,
                result,
                "Coordinator recovery result belongs to a stale configuration snapshot",
                now_unix,
            )?;
            return Ok(true);
        }
        let current = store
            .active_ticket_runs(owner_generation, 128)?
            .into_iter()
            .find(|run| run.ticket_run_id == *ticket_run_id)
            .ok_or("Coordinator recovery SpawnRequest references no active TicketRun")?;
        if current.project_id != binding.project_id
            || binding.ticket_revision.map(|revision| revision.0) != Some(current.revision)
            || current.revision != recovery.subject.blocked_revision.saturating_add(1)
            || current.phase != Phase::Assessing
            || current.activity != Activity::Running
        {
            store.fail_merge_claim_recovery_attempt(
                owner_generation,
                &recovery.request_id,
                result,
                "Coordinator recovery result is stale or outside the authorized Assessing revision",
                now_unix,
            )?;
            return Ok(true);
        }
        let mut profile =
            crate::config::effective_project_roles(&binding.project_id, &config.projects)?
                .get(&Role::MergeDecision)
                .cloned()
                .ok_or("Project has no MergeDecision profile")?;
        if let Some(recipe_id) = current.recipe_id.as_ref()
            && let Some(recipe_profile) = config
                .operation_recipes
                .get(recipe_id)
                .and_then(|recipe| recipe.roles.get(&Role::MergeDecision))
        {
            profile = recipe_profile.clone();
        }
        if request.profile_id != profile {
            store.fail_merge_claim_recovery_attempt(
                owner_generation,
                &recovery.request_id,
                result,
                "Coordinator requested a MergeDecision profile outside current Project policy",
                now_unix,
            )?;
            return Ok(true);
        }
        let session = format!("ticket_run:{ticket_run_id}:merge_decision");
        let payload = serde_json::json!({
            "kind": "coordinator_spawn",
            "request": request,
            "source_evidence_id": result.receipt.evidence_id(),
        });
        store.persist_coordinator_child_wake(
            owner_generation,
            result,
            Role::MergeDecision,
            &session,
            current.revision,
            &payload,
        )?;
        return Ok(true);
    }
    if matches!(request.role, Role::Supervisor | Role::Coordinator)
        || (request.role == Role::Worker && request.worker_recovery.is_none())
        || (request.role != Role::Worker && request.worker_recovery.is_some())
    {
        return Err("Coordinator SpawnRequest targets a role without a generic launch path".into());
    }
    let project_record = store
        .project(&binding.project_id)?
        .ok_or("Coordinator SpawnRequest Project has no durable configuration record")?;
    let configuration_digest = services.configuration_digest();
    if project_record.config_digest != *configuration_digest
        || binding.config_digest != *configuration_digest
        || binding.config_revision != project_record.config_revision
    {
        return Err("Coordinator SpawnRequest belongs to a stale configuration snapshot".into());
    }
    let source_revision = binding
        .ticket_revision
        .ok_or("Coordinator SpawnRequest lacks TicketRun revision")?;
    let current = store
        .active_ticket_runs(owner_generation, 128)?
        .into_iter()
        .find(|run| run.ticket_run_id == *ticket_run_id)
        .ok_or("Coordinator SpawnRequest references no active TicketRun")?;
    if current.project_id != binding.project_id || current.revision != source_revision.0 {
        return Err("Coordinator SpawnRequest is stale or outside its TicketRun".into());
    }
    if current.activity == Activity::Blocked {
        store.acknowledge_validated_agent_result(
            owner_generation,
            result.receipt.evidence_id(),
            current.revision,
            crate::store::agent_results::ResultDisposition::RejectedByHost,
        )?;
        return Ok(true);
    }
    if !config
        .projects
        .get(&binding.project_id)
        .is_some_and(|project| {
            request
                .allowed_repositories
                .iter()
                .all(|id| project.repositories.contains(id))
        })
    {
        return Err(
            "Coordinator SpawnRequest references a repository outside Project policy".into(),
        );
    }
    let accepted = store.latest_accepted_work_plan(&binding.project_id, ticket_run_id)?;
    if request.role == Role::Planner {
        match (accepted.as_ref(), request.plan_digest.as_ref()) {
            (None, None) => {}
            (Some(plan), Some(plan_digest))
                if &plan.plan_digest == plan_digest
                    && plan
                        .proposal
                        .nodes
                        .iter()
                        .any(|node| node.id == request.work_node && node.investigation) => {}
            _ => {
                return Err(
                    "Coordinator Planner SpawnRequest must match an accepted investigation node or be an unbound pre-plan request".into(),
                );
            }
        }
    } else {
        let accepted = accepted.ok_or("Coordinator SpawnRequest has no accepted plan")?;
        if request.plan_digest.as_ref() != Some(&accepted.plan_digest)
            || !accepted
                .proposal
                .nodes
                .iter()
                .any(|node| node.id == request.work_node)
        {
            return Err("Coordinator SpawnRequest does not match an accepted plan node".into());
        }
        if request.role == Role::Worker {
            let project = config
                .projects
                .get(&binding.project_id)
                .ok_or("Worker recovery Project is no longer configured")?;
            let expected_profile =
                crate::config::effective_project_roles(&binding.project_id, &config.projects)?
                    .get(&Role::Worker)
                    .cloned()
                    .ok_or("Project has no Worker profile")?;
            let expected_profile = current
                .recipe_id
                .as_ref()
                .and_then(|recipe_id| config.operation_recipes.get(recipe_id))
                .and_then(|recipe| recipe.roles.get(&Role::Worker))
                .cloned()
                .unwrap_or(expected_profile);
            if request.profile_id != expected_profile {
                return Err("Worker recovery profile differs from current Project policy".into());
            }
            let validated = accepted.validate_for(project, configuration_digest)?;
            let node = validated
                .nodes_in_execution_order
                .iter()
                .find(|node| node.id == request.work_node && node.role == Role::Worker)
                .ok_or("Worker recovery request does not name an accepted Worker node")?;
            if request.allowed_repositories.as_slice() != [node.repository.clone()] {
                return Err(
                    "Worker recovery repository scope differs from the accepted node".into(),
                );
            }
            let recovery = request
                .worker_recovery
                .as_ref()
                .ok_or("Worker recovery request lacks its prior Worker identity")?;
            let candidate = store.worker_recovery_candidates(
                owner_generation,
                &current,
                &accepted,
                project,
                configuration_digest,
            )?.into_iter().find(|candidate| {
                candidate.prior_worker_agent_run_id == recovery.prior_worker_agent_run_id
                    && candidate.ticket_revision == current.revision
                    && candidate.work_node_id == request.work_node
                    && candidate.accepted_plan_digest == accepted.plan_digest
                    && candidate.prior_host_commit_operation_id == recovery.prior_host_commit_operation_id
            }).ok_or("Worker recovery request does not match a current host-verified retry candidate")?;
            if services
                .observe_worker_recovery_head(&candidate)?
                .as_deref()
                != Some(candidate.expected_head.as_str())
            {
                return Err(
                    "Worker recovery worktree HEAD is not the host-accepted continuation point"
                        .into(),
                );
            }
            let authorization = crate::engine::orchestration::WorkerRecoveryAuthorization {
                schema_version: 1,
                ticket_run_id: current.ticket_run_id.clone(),
                ticket_revision: candidate.ticket_revision,
                work_node_id: candidate.work_node_id,
                accepted_plan_digest: candidate.accepted_plan_digest,
                prior_worker_agent_run_id: candidate.prior_worker_agent_run_id,
                prior_terminal_digest: candidate.prior_terminal_digest,
                prior_absence_digest: candidate.prior_absence_digest,
                prior_host_commit_operation_id: candidate.prior_host_commit_operation_id,
                prior_host_commit_receipt_digest: candidate.prior_host_commit_receipt_digest,
                expected_head: candidate.expected_head,
                source_coordinator_evidence_id: result.receipt.evidence_id().to_owned(),
                prior_worker_result_evidence_id: candidate.prior_worker_result_evidence_id,
                prior_artifact_refs: candidate.prior_artifact_refs,
            };
            store.persist_worker_recovery_wake(
                owner_generation,
                result,
                &authorization,
                source_revision.0,
            )?;
            return Ok(true);
        }
        if request.worker_recovery.is_some() {
            return Err("non-Worker SpawnRequest cannot carry Worker recovery context".into());
        }
    }
    let mut expected_profile =
        crate::config::effective_project_roles(&binding.project_id, &config.projects)?
            .get(&request.role)
            .cloned()
            .ok_or("Project has no profile for the requested child role")?;
    if let Some(recipe_id) = &current.recipe_id
        && let Some(recipe_profile) = config
            .operation_recipes
            .get(recipe_id)
            .and_then(|recipe| recipe.roles.get(&request.role))
    {
        expected_profile = recipe_profile.clone();
    }
    if expected_profile != request.profile_id {
        return Err("Coordinator SpawnRequest profile differs from current Project policy".into());
    }
    if !crate::runtime_services::role_allowed_in_phase(request.role, current.phase) {
        let phase = serde_json::to_value(current.phase)
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned))
            .ok_or("TicketRun phase is not serializable")?;
        let allowed_roles = [
            Role::Planner,
            Role::Worker,
            Role::Reviewer,
            Role::MergeDecision,
            Role::Operator,
            Role::Postmortem,
        ]
        .into_iter()
        .filter(|role| crate::runtime_services::role_allowed_in_phase(*role, current.phase))
        .map(|role| serde_json::to_value(role).map_err(|error| error.to_string()))
        .collect::<Result<Vec<_>, _>>()?;
        let next_step = if current.phase == crate::engine::reducer::Phase::Implementing {
            "Continue with a Worker only when a host-verified verification or recovery authorization is available; otherwise wait for the required host phase transition."
        } else {
            "Do not request a child role that is illegal in the current phase. Continue only with a host-authorized role from allowed_roles, or wait for the required host phase transition."
        };
        let payload = serde_json::json!({
            "kind": "coordinator_spawn_rejected",
            "source_evidence_id": result.receipt.evidence_id(),
            "requested_role": request.role,
            "current_phase": phase,
            "allowed_roles": allowed_roles,
            "next_step": next_step
        });
        store.reject_coordinator_child_wake(owner_generation, result, current.phase, &payload)?;
        return Ok(true);
    }
    let session = format!("ticket_run:{ticket_run_id}:{}", role_name(request.role));
    let payload = serde_json::json!({
        "kind": "coordinator_spawn",
        "request": request,
        "source_evidence_id": result.receipt.evidence_id(),
    });
    store.persist_coordinator_child_wake(
        owner_generation,
        result,
        request.role,
        &session,
        source_revision.0,
        &payload,
    )?;
    Ok(true)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    pub(crate) struct PostmortemTestServices {
        pub(crate) digest: crate::domain::ids::Digest,
        pub(crate) artifacts: crate::artifacts::ArtifactStore,
    }

    impl super::FactoryRuntimeServices for PostmortemTestServices {
        fn recover_agents(
            &mut self,
            _: &mut crate::store::ConfigStore,
            _: u64,
            _: i64,
        ) -> Result<crate::agent_recovery::AgentRecoveryReport, String> {
            Err("unused by postmortem consumer test".into())
        }

        fn ingest_one_agent_result(
            &mut self,
            _: &mut crate::store::ConfigStore,
            _: u64,
            _: i64,
        ) -> Result<Option<crate::store::agent_results::IngestedAgentResult>, String> {
            Err("unused by postmortem consumer test".into())
        }

        fn process_one_agent_request(
            &mut self,
            _: &mut crate::store::ConfigStore,
            _: u64,
            _: i64,
        ) -> Result<bool, String> {
            Err("unused by postmortem consumer test".into())
        }

        fn read_verified_artifact(
            &self,
            artifact: &crate::store::artifact_registry::VerifiedArtifact,
        ) -> Result<Vec<u8>, String> {
            artifact.read_bytes(&self.artifacts)
        }

        fn observe_base_heads(
            &mut self,
        ) -> Result<std::collections::BTreeMap<crate::domain::ids::RepositoryId, String>, String>
        {
            Err("unused by postmortem consumer test".into())
        }

        fn configuration_digest(&self) -> &crate::domain::ids::Digest {
            &self.digest
        }

        fn profile_commit_mode(
            &self,
            _: &ProjectId,
            _: Role,
        ) -> Result<crate::domain::types::CommitMode, String> {
            Err("unused by postmortem consumer test".into())
        }

        fn worker_publication_effect(
            &mut self,
            _: &mut crate::store::ConfigStore,
            _: u64,
            _: &Config,
            _: &crate::store::scheduler::ActiveTicketRun,
            _: &crate::store::agent_results::IngestedAgentResult,
            _: u64,
        ) -> Result<Option<crate::store::EffectIntent>, String> {
            Err("unused by postmortem consumer test".into())
        }

        fn tick_profile_trials(
            &mut self,
            _: &mut crate::store::ConfigStore,
            _: u64,
            _: i64,
            _: u32,
            _: u32,
        ) -> Result<(), String> {
            Err("unused by postmortem consumer test".into())
        }

        fn ticket_namespace(
            &mut self,
            _: &crate::domain::ids::AdapterId,
        ) -> Result<crate::domain::ids::TicketNamespace, String> {
            Err("unused by postmortem consumer test".into())
        }

        fn list_ticket_page(
            &mut self,
            _: &crate::store::scheduler::TicketScanKey,
            _: Option<&str>,
            _: usize,
        ) -> Result<super::ExternalTicketPage, String> {
            Err("unused by postmortem consumer test".into())
        }

        fn observe_publications(
            &mut self,
            _: &mut crate::store::ConfigStore,
            _: u64,
            _: i64,
        ) -> Result<crate::runtime_delivery::PublicationMonitorTick, String> {
            Err("unused by postmortem consumer test".into())
        }

        fn prepare_role_launch(
            &mut self,
            _: &mut crate::store::ConfigStore,
            _: u64,
            _: &Config,
            _: &crate::store::scheduler::PendingRoleWakeSession,
            _: i64,
        ) -> Result<bool, String> {
            Err("unused by postmortem consumer test".into())
        }

        fn effect_handlers(&self) -> Vec<&dyn crate::effects::EffectHandler> {
            Vec::new()
        }
    }

    pub(crate) fn apply_postmortem_result(
        store: &mut crate::store::ConfigStore,
        owner_generation: u64,
        now_unix: i64,
        config: &Config,
        services: &mut PostmortemTestServices,
        result: &crate::store::agent_results::IngestedAgentResult,
    ) -> Result<bool, String> {
        super::apply_agent_result(store, owner_generation, now_unix, config, services, result)
    }

    use super::{
        FilterRotation, TickBudget, TicketDisposition, ValidatedHostObservation,
        ValidatedWorkflowEvent, canonical_goal_ticket_proposal, next_status_filter,
        role_session_key, ticket_disposition, transition_for_observation, transition_for_role,
    };
    use crate::config::Config;
    use crate::domain::ids::{Digest, ProjectId, TicketNamespace};
    use crate::domain::types::{Role, TicketStatus};
    use crate::engine::reducer::Phase;
    use sha2::Digest as ShaDigest;

    struct WorkerPublicationFixtureServices {
        configuration_digest: Digest,
        published_effect: Option<crate::store::EffectIntent>,
        pending_artifacts: Option<crate::artifacts::ArtifactStore>,
        ticket_page: Option<super::ExternalTicketPage>,
        merge_observation: Option<crate::merge_runtime::MergeEvidenceObservation>,
        merge_observation_timeout: Option<crate::config::AppliedConfig>,
        merge_observation_replies: Option<(crate::config::AppliedConfig, Vec<serde_json::Value>)>,
        merge_body_proposal: Option<crate::store::merge_work::PreparedMergeBodyProposal>,
        merge_work_document: Option<crate::store::merge_work::MergeWorkDocument>,
    }

    impl super::FactoryRuntimeServices for WorkerPublicationFixtureServices {
        fn process_one_agent_request(
            &mut self,
            _: &mut crate::store::ConfigStore,
            _: u64,
            _: i64,
        ) -> Result<bool, String> {
            Ok(false)
        }

        fn recover_agents(
            &mut self,
            _: &mut crate::store::ConfigStore,
            _: u64,
            _: i64,
        ) -> Result<crate::agent_recovery::AgentRecoveryReport, String> {
            Ok(crate::agent_recovery::AgentRecoveryReport {
                examined: 0,
                observations: Vec::new(),
                more_pending: false,
            })
        }

        fn ingest_one_agent_result(
            &mut self,
            store: &mut crate::store::ConfigStore,
            owner_generation: u64,
            now_unix: i64,
        ) -> Result<Option<crate::store::agent_results::IngestedAgentResult>, String> {
            self.pending_artifacts
                .as_ref()
                .map(|artifacts| {
                    store
                        .runnable_validated_agent_results(artifacts, owner_generation, now_unix, 1)
                        .map(|mut results| results.pop())
                })
                .unwrap_or(Ok(None))
        }

        fn observe_base_heads(
            &mut self,
        ) -> Result<BTreeMap<crate::domain::ids::RepositoryId, String>, String> {
            Ok(BTreeMap::new())
        }

        fn configuration_digest(&self) -> &Digest {
            &self.configuration_digest
        }

        fn read_verified_artifact(
            &self,
            _: &crate::store::artifact_registry::VerifiedArtifact,
        ) -> Result<Vec<u8>, String> {
            Err("unused by Worker publication fixture".into())
        }

        fn profile_commit_mode(
            &self,
            _: &ProjectId,
            _: Role,
        ) -> Result<crate::domain::types::CommitMode, String> {
            Ok(crate::domain::types::CommitMode::Native)
        }

        fn worker_publication_effect(
            &mut self,
            _: &mut crate::store::ConfigStore,
            _: u64,
            _: &Config,
            run: &crate::store::scheduler::ActiveTicketRun,
            result: &crate::store::agent_results::IngestedAgentResult,
            effect_revision: u64,
        ) -> Result<Option<crate::store::EffectIntent>, String> {
            let request_json = "{\"evidence_id\":\"fixture\",\"node\":\"node-a\"}".to_owned();
            let effect = crate::store::EffectIntent {
                project_id: run.project_id.clone(),
                subject_type: "ticket_run".into(),
                subject_id: run.ticket_run_id.as_str().into(),
                operation_id: format!("publish-{}", result.receipt.evidence_id()),
                logical_key: format!("{}:publish:node-a", run.ticket_run_id),
                kind: "publish_implementation".into(),
                request_digest: format!("{:x}", sha2::Sha256::digest(request_json.as_bytes())),
                request_json,
                expected_revision: Some(effect_revision),
            };
            self.published_effect = Some(effect.clone());
            Ok(Some(effect))
        }

        fn observe_merge_assessment(
            &mut self,
            subject: &crate::delivery_runtime::ImplementationPublicationSetSubject,
            result: &crate::store::agent_results::IngestedAgentResult,
        ) -> Result<
            Option<crate::merge_runtime::MergeEvidenceObservation>,
            crate::merge_runtime::MergeObservationError,
        > {
            if let Some(applied) = &self.merge_observation_timeout {
                return crate::runtime_services::merge::tests::observe_publication_timeout_for_store_test(
                    applied.clone(),
                    subject,
                    result,
                )
                .map(Some);
            }
            if let Some((applied, replies)) = &self.merge_observation_replies {
                return crate::runtime_services::merge::tests::observe_publication_for_store_test(
                    applied.clone(),
                    subject,
                    result,
                    replies.clone(),
                )
                .map(Some)
                .map_err(Into::into);
            }
            self.merge_observation
                .clone()
                .map(Some)
                .ok_or_else(|| "MergeAssessment fixture observation is missing".into())
        }

        fn observe_recovery_merge_assessment(
            &mut self,
            _: &crate::delivery_runtime::ImplementationPublicationSetSubject,
            _: &Digest,
        ) -> Result<
            Option<crate::merge_runtime::MergeEvidenceObservation>,
            crate::merge_runtime::MergeObservationError,
        > {
            self.merge_observation
                .clone()
                .map(Some)
                .ok_or_else(|| "recovery MergeAssessment fixture observation is missing".into())
        }

        fn prepare_merge_body_proposal(
            &self,
            _: &ProjectId,
            _: &crate::delivery_runtime::ImplementationPublicationSetSubject,
            _: &crate::engine::orchestration::WorkPlan,
            _: &Digest,
            _: &crate::merge_runtime::MergeEvidenceObservation,
        ) -> Result<crate::store::merge_work::PreparedMergeBodyProposal, String> {
            self.merge_body_proposal
                .clone()
                .ok_or_else(|| "MergeAssessment fixture body proposal is missing".into())
        }

        fn resolve_merge_work_document(
            &mut self,
            _: &crate::delivery_runtime::ImplementationPublicationSetSubject,
            _: &crate::engine::orchestration::WorkPlan,
            _: &crate::store::merge_work::TrustedMergeAssessment,
            _: &crate::engine::orchestration::MergeIntentPayload,
            _: &crate::store::agent_results::IngestedAgentResult,
        ) -> Result<crate::store::merge_work::MergeWorkDocument, String> {
            self.merge_work_document
                .clone()
                .ok_or_else(|| "MergeIntent fixture document is missing".into())
        }

        fn tick_profile_trials(
            &mut self,
            _: &mut crate::store::ConfigStore,
            _: u64,
            _: i64,
            _: u32,
            _: u32,
        ) -> Result<(), String> {
            Ok(())
        }

        fn ticket_namespace(
            &mut self,
            _: &crate::domain::ids::AdapterId,
        ) -> Result<TicketNamespace, String> {
            TicketNamespace::parse("fixture")
        }

        fn list_ticket_page(
            &mut self,
            _: &super::TicketScanKey,
            _: Option<&str>,
            _: usize,
        ) -> Result<super::ExternalTicketPage, String> {
            Ok(self
                .ticket_page
                .clone()
                .unwrap_or(super::ExternalTicketPage {
                    tickets: Vec::new(),
                    next_cursor: None,
                }))
        }

        fn observe_publications(
            &mut self,
            _: &mut crate::store::ConfigStore,
            _: u64,
            _: i64,
        ) -> Result<crate::runtime_delivery::PublicationMonitorTick, String> {
            Ok(crate::runtime_delivery::PublicationMonitorTick::Idle)
        }

        fn prepare_role_launch(
            &mut self,
            _: &mut crate::store::ConfigStore,
            _: u64,
            _: &Config,
            _: &crate::store::scheduler::PendingRoleWakeSession,
            _: i64,
        ) -> Result<bool, String> {
            Ok(false)
        }

        fn verify_worker_verification_worktree(
            &self,
            store: &mut crate::store::ConfigStore,
            project_id: &crate::domain::ids::ProjectId,
            ticket_run_id: &crate::domain::ids::TicketRunId,
            assignment: &crate::launch::WorkerLaunchBinding,
        ) -> Result<(), String> {
            use std::ffi::OsString;
            use std::time::Duration;

            let search_path = std::env::var_os("PATH")
                .map(|value| std::env::split_paths(&value).collect::<Vec<_>>())
                .unwrap_or_default();
            let git = crate::process::resolve_executable(std::path::Path::new("git"), &search_path)
                .ok_or("test fixture could not resolve git")?;
            let expected_head = assignment
                .expected_head
                .as_deref()
                .ok_or("test fixture verification assignment has no expected head")?;
            let path = assignment.worktree_path.as_path();
            let run = |args: &[&str]| -> Result<String, String> {
                let mut environment = BTreeMap::new();
                if let Some(path) = std::env::var_os("PATH") {
                    environment.insert(OsString::from("PATH"), path);
                }
                let output = crate::process::run(crate::process::ProcessRequest {
                    executable: git.clone(),
                    args: args.iter().map(OsString::from).collect(),
                    stdin: Vec::new(),
                    cwd: Some(path.to_owned()),
                    clear_environment: true,
                    environment,
                    timeout: Duration::from_secs(5),
                    shutdown_grace: Duration::from_secs(1),
                    stdout_limit: 64 * 1024,
                    stderr_tail_limit: 8 * 1024,
                })
                .map_err(|error| error.to_string())?;
                if output.timed_out
                    || !output.cleanup_confirmed
                    || !output
                        .status
                        .as_ref()
                        .is_some_and(std::process::ExitStatus::success)
                {
                    return Err("test fixture Git worktree observation failed".into());
                }
                String::from_utf8(output.stdout)
                    .map_err(|_| "test fixture Git output was not UTF-8".into())
            };
            let observed_head = run(&["rev-parse", "--verify", "HEAD"])?;
            if observed_head.trim() != expected_head {
                return Err("test fixture Worker worktree HEAD changed".into());
            }
            let locators =
                store.persisted_worker_host_artifacts(project_id, ticket_run_id, assignment)?;
            let allowed_paths = locators
                .iter()
                .map(|locator| locator.path.as_str())
                .collect::<BTreeSet<_>>();
            for line in run(&["status", "--porcelain=v1", "--untracked-files=all"])?.lines() {
                if !line.starts_with("?? ") || !allowed_paths.contains(&line[3..]) {
                    return Err("test fixture Worker verification worktree is dirty".into());
                }
            }
            Ok(())
        }

        fn effect_handlers(&self) -> Vec<&dyn crate::effects::EffectHandler> {
            Vec::new()
        }
    }

    pub(crate) fn apply_agent_result_for_test(
        store: &mut crate::store::ConfigStore,
        owner_generation: u64,
        now_unix: i64,
        config: &Config,
        configuration_digest: Digest,
        result: &crate::store::agent_results::IngestedAgentResult,
    ) -> Result<bool, String> {
        let mut services = WorkerPublicationFixtureServices {
            configuration_digest,
            published_effect: None,
            pending_artifacts: None,
            ticket_page: None,
            merge_observation: None,
            merge_observation_timeout: None,
            merge_observation_replies: None,
            merge_body_proposal: None,
            merge_work_document: None,
        };
        super::apply_agent_result(
            store,
            owner_generation,
            now_unix,
            config,
            &mut services,
            result,
        )
    }

    pub(crate) fn apply_agent_result_with_merge_work_document_for_test(
        store: &mut crate::store::ConfigStore,
        owner_generation: u64,
        now_unix: i64,
        config: &Config,
        configuration_digest: Digest,
        result: &crate::store::agent_results::IngestedAgentResult,
        document: crate::store::merge_work::MergeWorkDocument,
    ) -> Result<bool, String> {
        let mut services = WorkerPublicationFixtureServices {
            configuration_digest,
            published_effect: None,
            pending_artifacts: None,
            ticket_page: None,
            merge_observation: None,
            merge_observation_timeout: None,
            merge_observation_replies: None,
            merge_body_proposal: None,
            merge_work_document: Some(document),
        };
        super::apply_agent_result(
            store,
            owner_generation,
            now_unix,
            config,
            &mut services,
            result,
        )
    }

    pub(crate) fn apply_coordinator_spawn_request_for_test(
        store: &mut crate::store::ConfigStore,
        owner_generation: u64,
        now_unix: i64,
        config: &Config,
        configuration_digest: Digest,
        result: &crate::store::agent_results::IngestedAgentResult,
    ) -> Result<bool, String> {
        let services = WorkerPublicationFixtureServices {
            configuration_digest,
            published_effect: None,
            pending_artifacts: None,
            ticket_page: None,
            merge_observation: None,
            merge_observation_timeout: None,
            merge_observation_replies: None,
            merge_body_proposal: None,
            merge_work_document: None,
        };
        super::apply_coordinator_spawn_request(
            store,
            owner_generation,
            now_unix,
            config,
            &services,
            result,
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "The fixture binds the exact host observation and proposal to one validated result"
    )]
    pub(crate) fn apply_merge_assessment_for_test(
        store: &mut crate::store::ConfigStore,
        owner_generation: u64,
        now_unix: i64,
        config: &Config,
        configuration_digest: Digest,
        result: &crate::store::agent_results::IngestedAgentResult,
        observation: crate::merge_runtime::MergeEvidenceObservation,
        proposal: Option<crate::store::merge_work::PreparedMergeBodyProposal>,
    ) -> Result<bool, String> {
        let mut services = WorkerPublicationFixtureServices {
            configuration_digest,
            published_effect: None,
            pending_artifacts: None,
            ticket_page: None,
            merge_observation: Some(observation),
            merge_observation_timeout: None,
            merge_observation_replies: None,
            merge_body_proposal: proposal,
            merge_work_document: None,
        };
        super::apply_merge_assessment(
            store,
            owner_generation,
            now_unix,
            config,
            &mut services,
            result,
        )
    }

    pub(crate) fn tick_with_merge_observation_timeout_for_test(
        store: &mut crate::store::ConfigStore,
        owner_generation: u64,
        now_unix: i64,
        config: &Config,
        configuration_digest: Digest,
        artifacts: crate::artifacts::ArtifactStore,
        applied: crate::config::AppliedConfig,
    ) -> Result<super::FactoryTickReport, String> {
        let mut services = WorkerPublicationFixtureServices {
            configuration_digest,
            published_effect: None,
            pending_artifacts: Some(artifacts),
            ticket_page: None,
            merge_observation: None,
            merge_observation_timeout: Some(applied),
            merge_observation_replies: None,
            merge_body_proposal: None,
            merge_work_document: None,
        };
        super::FactoryRuntime::tick(store, owner_generation, now_unix, config, &mut services)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "The fixture binds fresh Forge replies and the body proposal to one runtime tick"
    )]
    pub(crate) fn tick_with_merge_observation_replies_for_test(
        store: &mut crate::store::ConfigStore,
        owner_generation: u64,
        now_unix: i64,
        config: &Config,
        configuration_digest: Digest,
        artifacts: crate::artifacts::ArtifactStore,
        applied: crate::config::AppliedConfig,
        replies: Vec<serde_json::Value>,
        proposal: Option<crate::store::merge_work::PreparedMergeBodyProposal>,
    ) -> Result<super::FactoryTickReport, String> {
        let mut services = WorkerPublicationFixtureServices {
            configuration_digest,
            published_effect: None,
            pending_artifacts: Some(artifacts),
            ticket_page: None,
            merge_observation: None,
            merge_observation_timeout: None,
            merge_observation_replies: Some((applied, replies)),
            merge_body_proposal: proposal,
            merge_work_document: None,
        };
        super::FactoryRuntime::tick(store, owner_generation, now_unix, config, &mut services)
    }

    pub(crate) fn apply_merge_intent_for_test(
        store: &mut crate::store::ConfigStore,
        owner_generation: u64,
        now_unix: i64,
        config: &Config,
        configuration_digest: Digest,
        result: &crate::store::agent_results::IngestedAgentResult,
        document: crate::store::merge_work::MergeWorkDocument,
    ) -> Result<bool, String> {
        let mut services = WorkerPublicationFixtureServices {
            configuration_digest,
            published_effect: None,
            pending_artifacts: None,
            ticket_page: None,
            merge_observation: None,
            merge_observation_timeout: None,
            merge_observation_replies: None,
            merge_body_proposal: None,
            merge_work_document: Some(document),
        };
        super::apply_merge_intent(
            store,
            owner_generation,
            now_unix,
            config,
            &mut services,
            result,
        )
    }

    #[test]
    fn host_validated_supervisor_dispatch_allocates_only_the_exact_opaque_ticket_revision() {
        use crate::domain::ids::{Digest, ProjectId, TicketId, TicketNamespace};
        use crate::domain::types::{Role, TicketStatus};
        use crate::engine::orchestration::{AgentAssertion, RoleOutputKind};
        use crate::roles::RoleResultMessage;
        use crate::store::scheduler::{ObservedTicket, TicketScanKey, TicketScanPage};
        use rusqlite::params;
        use serde_json::json;

        fn run(ticket_reference: &str, expected_revision: &str) -> (Result<bool, String>, usize) {
            let payload = json!({
                "ticket_reference": ticket_reference,
                "expected_ticket_revision": expected_revision,
                "coordinator_profile": "judgment_claude",
                "priority": 3,
                "rationale": "dispatch the exact observed ticket revision"
            });
            let result_digest = Digest::parse(format!(
                "{:x}",
                sha2::Sha256::digest(serde_json::to_vec(&payload).unwrap())
            ))
            .unwrap();
            let mut fixture =
                crate::store::agent_results::host_validation_fixture::host_validated_result(
                    Role::Supervisor,
                    RoleResultMessage {
                        schema_version: crate::engine::orchestration::ROLE_RESULT_SCHEMA_VERSION,
                        message_id: format!("supervisor-dispatch-{expected_revision}"),
                        kind: RoleOutputKind::DispatchRequest,
                        assertion: AgentAssertion::Succeeded,
                        structured_result: payload,
                        result_digest: Some(result_digest),
                        artifact_refs: Vec::new(),
                    },
                )
                .unwrap();
            let project_id = ProjectId::parse("fixture-project").unwrap();
            fixture
                .store
                .set_project_lifecycle(fixture.owner_generation, &project_id, "running")
                .unwrap();
            let mut config: Config =
                toml::from_str(include_str!("../../examples/fixture/config.toml")).unwrap();
            let mut project = config
                .projects
                .remove(&ProjectId::parse("goal_project").unwrap())
                .unwrap();
            project.dispatch_states = vec![TicketStatus::Ready];
            config.projects.insert(project_id.clone(), project);
            let project = config.projects.get(&project_id).unwrap();
            let namespace = TicketNamespace::parse("fixture").unwrap();
            let key = TicketScanKey::for_project(
                &project_id,
                &project.ticket_adapter,
                &namespace,
                project,
                TicketStatus::Ready,
            )
            .unwrap();
            fixture
                .store
                .record_ticket_scan_page(
                    fixture.owner_generation,
                    TicketScanPage {
                        key: &key,
                        expected_cursor: None,
                        expected_generation: 0,
                        expected_page_count: 0,
                        next_cursor: None,
                        tickets: &[ObservedTicket {
                            id: TicketId::parse("43").unwrap(),
                            revision: Some(
                                "3ef900fc1927e9ad609e95b52b74a048fd9baa76194eb0ba60d738df088727b4"
                                    .into(),
                            ),
                            status: TicketStatus::Ready,
                            title: "Fixture ticket".into(),
                            labels: Vec::new(),
                            created_at: None,
                            observed_at_unix: 1,
                        }],
                        now_unix: 1,
                        poll_seconds: 60,
                    },
                )
                .unwrap();
            let binding = &fixture.ingested.validated.binding;
            fixture
                .store
                .test_connection()
                .execute(
                    "INSERT INTO agent_launch_reservations(agent_run_id,project_id,operation_id,controller_generation,project_epoch,reservation_digest,reservation_json,lifecycle,created_at_unix,updated_at_unix) VALUES (?1,?2,?3,?4,1,?5,'{}','authorized',1,1)",
                    params![
                        binding.agent_run_id.as_str(),
                        binding.project_id.as_str(),
                        binding.operation_id.as_str(),
                        fixture.owner_generation,
                        "d".repeat(64),
                    ],
                )
                .unwrap();
            let mut services = WorkerPublicationFixtureServices {
                configuration_digest: Digest::parse("a".repeat(64)).unwrap(),
                published_effect: None,
                pending_artifacts: None,
                ticket_page: None,
                merge_observation: None,
                merge_observation_timeout: None,
                merge_observation_replies: None,
                merge_body_proposal: None,
                merge_work_document: None,
            };
            let applied = super::apply_agent_result(
                &mut fixture.store,
                fixture.owner_generation,
                2,
                &config,
                &mut services,
                &fixture.ingested,
            );
            let count = fixture
                .store
                .test_connection()
                .query_row(
                    "SELECT COUNT(*) FROM ticket_runs WHERE project_id=?1 AND ticket_id='43'",
                    [project_id.as_str()],
                    |row| row.get(0),
                )
                .unwrap();
            (applied, count)
        }

        let revision = "3ef900fc1927e9ad609e95b52b74a048fd9baa76194eb0ba60d738df088727b4";
        let (allocated, allocated_count) = run("43", revision);
        assert!(allocated.unwrap());
        assert_eq!(allocated_count, 1);

        let (qualified, qualified_count) = run("github:civitaspo/rex-projects:43", revision);
        assert!(
            qualified
                .unwrap_err()
                .contains("not a current eligible ticket observation")
        );
        assert_eq!(qualified_count, 0);

        let (stale, stale_count) = run("43", "rev-stale");
        assert!(
            stale
                .unwrap_err()
                .contains("stale external ticket revision")
        );
        assert_eq!(stale_count, 0);
    }

    #[test]
    fn merge_intent_without_same_revision_trusted_assessment_is_not_acknowledged() {
        use crate::domain::ids::Digest;
        use crate::domain::types::Role;
        use crate::engine::orchestration::{AgentAssertion, RoleOutputKind};
        use crate::roles::RoleResultMessage;
        use serde_json::json;

        let payload = json!({
            "assessment_id": "assessment-1",
            "pr_identities": ["repo-a#42"],
            "policy_digest": "a".repeat(64),
            "prepared_body_digest": "b".repeat(64),
            "steps": [
                {"kind":"request_merge", "instruction_reference":"merge.instructions#request", "rationale":"the repository requires a merge request"},
                {"kind":"verify_merge_commit", "instruction_reference":"merge.instructions#verify", "rationale":"confirm the resulting commit"}
            ],
            "post_merge_verification": [
                {"kind":"merge_commit_recorded", "instruction_reference":"merge.instructions#verify", "rationale":"verify the remote merge commit"}
            ]
        });
        let result_digest = Digest::parse(format!(
            "{:x}",
            sha2::Sha256::digest(serde_json::to_vec(&payload).unwrap())
        ))
        .unwrap();
        let mut fixture =
            crate::store::agent_results::host_validation_fixture::host_validated_result(
                Role::MergeDecision,
                RoleResultMessage {
                    schema_version: crate::engine::orchestration::ROLE_RESULT_SCHEMA_VERSION,
                    message_id: "merge-decision-intent".into(),
                    kind: RoleOutputKind::MergeIntent,
                    assertion: AgentAssertion::Succeeded,
                    structured_result: payload,
                    result_digest: Some(result_digest),
                    artifact_refs: Vec::new(),
                },
            )
            .unwrap();
        fixture
            .store
            .test_connection()
            .execute(
                "UPDATE ticket_runs SET internal_phase='assessing', external_status='in_progress', observed_status='in_progress' WHERE ticket_run_id='fixture-ticket-run'",
                [],
            )
            .unwrap();
        let config: Config =
            toml::from_str(include_str!("../../examples/fixture/config.toml")).unwrap();
        let mut services = WorkerPublicationFixtureServices {
            configuration_digest: Digest::parse("a".repeat(64)).unwrap(),
            published_effect: None,
            pending_artifacts: Some(fixture.artifacts),
            ticket_page: None,
            merge_observation: None,
            merge_observation_timeout: None,
            merge_observation_replies: None,
            merge_body_proposal: None,
            merge_work_document: None,
        };

        let error = super::FactoryRuntime::tick(
            &mut fixture.store,
            fixture.owner_generation,
            2,
            &config,
            &mut services,
        )
        .unwrap_err();
        assert!(error.contains("no host-validated assessment for this exact revision"));
        assert_eq!(
            crate::store::agent_results::host_validation_fixture::result_ack(
                &fixture.store,
                fixture.ingested.receipt.evidence_id(),
            )
            .unwrap()
            .map(|(_, disposition)| disposition),
            None
        );
    }

    #[test]
    fn committed_merge_intent_replay_acknowledges_only_its_exact_work_identity() {
        use crate::domain::ids::{Digest, Revision};
        use crate::domain::types::Role;
        use crate::engine::orchestration::{AgentAssertion, RoleOutputKind};
        use crate::roles::RoleResultMessage;
        use serde_json::json;

        let payload = json!({
            "assessment_id": "assessment-1",
            "pr_identities": ["repo-a#42"],
            "policy_digest": "a".repeat(64),
            "prepared_body_digest": "b".repeat(64),
            "steps": [
                {"kind":"request_merge", "instruction_reference":"merge.instructions#request", "rationale":"request the configured merge"},
                {"kind":"verify_merge_commit", "instruction_reference":"merge.instructions#verify", "rationale":"verify the resulting commit"}
            ],
            "post_merge_verification": [
                {"kind":"merge_commit_recorded", "instruction_reference":"merge.instructions#verify", "rationale":"verify the remote merge commit"}
            ]
        });
        let result_digest = Digest::parse(format!(
            "{:x}",
            sha2::Sha256::digest(serde_json::to_vec(&payload).unwrap())
        ))
        .unwrap();
        let mut fixture =
            crate::store::agent_results::host_validation_fixture::host_validated_result(
                Role::MergeDecision,
                RoleResultMessage {
                    schema_version: crate::engine::orchestration::ROLE_RESULT_SCHEMA_VERSION,
                    message_id: "merge-decision-replay".into(),
                    kind: RoleOutputKind::MergeIntent,
                    assertion: AgentAssertion::Succeeded,
                    structured_result: payload,
                    result_digest: Some(result_digest),
                    artifact_refs: Vec::new(),
                },
            )
            .unwrap();
        let result = &fixture.ingested;
        let binding = &result.validated.binding;
        let assessed_revision = binding.ticket_revision.unwrap();
        let run_revision = assessed_revision.0.checked_add(1).unwrap();
        let identity = super::MergeIntentReplayIdentity {
            assessed_revision,
            awaiting_merge_revision: Revision(run_revision.checked_add(1).unwrap()),
            configuration_digest: binding.config_digest.clone(),
            intent_evidence_id: result.receipt.evidence_id().into(),
            intent_result_digest: result.validated.result_digest.clone(),
        };
        assert!(super::merge_intent_replay_matches(
            &binding.project_id,
            run_revision,
            binding,
            result,
            &identity,
        ));
        let mut wrong_identity = super::MergeIntentReplayIdentity {
            intent_result_digest: Digest::parse("f".repeat(64)).unwrap(),
            ..identity
        };
        assert!(!super::merge_intent_replay_matches(
            &binding.project_id,
            run_revision,
            binding,
            result,
            &wrong_identity,
        ));
        wrong_identity.intent_result_digest = result.validated.result_digest.clone();
        assert!(!super::merge_intent_replay_matches(
            &binding.project_id,
            run_revision.checked_add(1).unwrap(),
            binding,
            result,
            &wrong_identity,
        ));

        super::acknowledge_merge_intent_replay(
            &mut fixture.store,
            fixture.owner_generation,
            result,
            run_revision,
        )
        .unwrap();
        super::acknowledge_merge_intent_replay(
            &mut fixture.store,
            fixture.owner_generation,
            result,
            run_revision,
        )
        .unwrap();
        assert_eq!(
            crate::store::agent_results::host_validation_fixture::result_ack(
                &fixture.store,
                result.receipt.evidence_id(),
            )
            .unwrap(),
            Some((run_revision, "applied".into()))
        );
    }

    #[test]
    fn production_scan_rearms_same_ticket_after_release_and_dispatches_new_generation() {
        use crate::domain::ids::{Digest, ProjectId, TicketId, TicketNamespace};
        use crate::domain::types::{Role, TicketStatus};
        use crate::engine::orchestration::{AgentAssertion, RoleOutputKind};
        use crate::roles::RoleResultMessage;
        use crate::store::scheduler::{ObservedTicket, TicketScanKey, TicketScanPage};
        use crate::store::{ConfigStore, HumanClaimRelease};
        use rusqlite::params;
        use serde_json::json;

        fn dispatch_message(message_id: &str, revision: &str) -> RoleResultMessage {
            let payload = json!({
                "ticket_reference": "43",
                "expected_ticket_revision": revision,
                "coordinator_profile": "judgment_claude",
                "priority": 3,
                "rationale": "resume the exact ticket after a successful fresh scan"
            });
            let result_digest = Digest::parse(format!(
                "{:x}",
                sha2::Sha256::digest(serde_json::to_vec(&payload).unwrap())
            ))
            .unwrap();
            RoleResultMessage {
                schema_version: crate::engine::orchestration::ROLE_RESULT_SCHEMA_VERSION,
                message_id: message_id.into(),
                kind: RoleOutputKind::DispatchRequest,
                assertion: AgentAssertion::Succeeded,
                structured_result: payload,
                result_digest: Some(result_digest),
                artifact_refs: Vec::new(),
            }
        }

        let revision = "rev-43-stable";
        let mut fixture =
            crate::store::agent_results::host_validation_fixture::host_validated_result(
                Role::Supervisor,
                dispatch_message("supervisor-dispatch-generation-one", revision),
            )
            .unwrap();
        let project_id = ProjectId::parse("fixture-project").unwrap();
        let namespace = TicketNamespace::parse("fixture").unwrap();
        fixture
            .store
            .set_project_lifecycle(fixture.owner_generation, &project_id, "running")
            .unwrap();

        let mut config: Config =
            toml::from_str(include_str!("../../examples/fixture/config.toml")).unwrap();
        let mut project = config
            .projects
            .remove(&ProjectId::parse("operations_project").unwrap())
            .unwrap();
        project.dispatch_states = vec![TicketStatus::Ready];
        config.projects.insert(project_id.clone(), project);
        let project = config.projects.get(&project_id).unwrap();
        let key = TicketScanKey::for_project(
            &project_id,
            &project.ticket_adapter,
            &namespace,
            project,
            TicketStatus::Ready,
        )
        .unwrap();
        let observed_ticket = ObservedTicket {
            id: TicketId::parse("43").unwrap(),
            revision: Some(revision.into()),
            status: TicketStatus::Ready,
            title: "Fixture ticket".into(),
            labels: vec!["docs".into()],
            created_at: None,
            observed_at_unix: 1,
        };
        fixture
            .store
            .record_ticket_scan_page(
                fixture.owner_generation,
                TicketScanPage {
                    key: &key,
                    expected_cursor: None,
                    expected_generation: 0,
                    expected_page_count: 0,
                    next_cursor: None,
                    tickets: std::slice::from_ref(&observed_ticket),
                    now_unix: 1,
                    poll_seconds: 60,
                },
            )
            .unwrap();
        assert!(
            fixture
                .store
                .enqueue_supervisor_ticket_observation(
                    fixture.owner_generation,
                    &key,
                    &crate::store::scheduler::PendingTicketObservation {
                        ticket_id: observed_ticket.id.clone(),
                        revision: observed_ticket.revision.clone(),
                        status: observed_ticket.status,
                        title: observed_ticket.title.clone(),
                        labels: observed_ticket.labels.clone(),
                        observed_at_unix: observed_ticket.observed_at_unix,
                    },
                    1,
                )
                .unwrap()
        );
        fixture
            .store
            .test_connection()
            .execute(
                "UPDATE role_wake_inputs SET lifecycle='consumed' WHERE source_type='ticket_observation' AND source_id='fixture:43:ready'",
                [],
            )
            .unwrap();

        let first_binding = &fixture.ingested.validated.binding;
        fixture
            .store
            .test_connection()
            .execute(
                "INSERT INTO agent_launch_reservations(agent_run_id,project_id,operation_id,controller_generation,project_epoch,reservation_digest,reservation_json,lifecycle,created_at_unix,updated_at_unix) VALUES (?1,?2,?3,?4,1,?5,'{}','authorized',1,1)",
                params![
                    first_binding.agent_run_id.as_str(),
                    first_binding.project_id.as_str(),
                    first_binding.operation_id.as_str(),
                    fixture.owner_generation,
                    "d".repeat(64),
                ],
            )
            .unwrap();
        let mut result_services = WorkerPublicationFixtureServices {
            configuration_digest: Digest::parse("a".repeat(64)).unwrap(),
            published_effect: None,
            pending_artifacts: None,
            ticket_page: None,
            merge_observation: None,
            merge_observation_timeout: None,
            merge_observation_replies: None,
            merge_body_proposal: None,
            merge_work_document: None,
        };
        assert!(
            super::apply_agent_result(
                &mut fixture.store,
                fixture.owner_generation,
                2,
                &config,
                &mut result_services,
                &fixture.ingested,
            )
            .unwrap()
        );

        let old_run = fixture
            .store
            .active_ticket_runs(fixture.owner_generation, 10)
            .unwrap()
            .into_iter()
            .find(|run| run.ticket_id.as_str() == "43")
            .unwrap();
        fixture
            .store
            .set_project_lifecycle(fixture.owner_generation, &project_id, "paused")
            .unwrap();
        ConfigStore::append_human_claim_release(
            fixture._temp.path(),
            "release-cycle-one",
            &HumanClaimRelease {
                namespace: namespace.as_str().into(),
                ticket: "43".into(),
                ticket_run_id: old_run.ticket_run_id.as_str().into(),
                generation: 1,
                expected_revision: old_run.revision,
                reason: "replace the incompatible assigned repository base".into(),
                disposition: "cancel".into(),
            },
            fixture.owner_generation,
        )
        .unwrap();
        fixture
            .store
            .process_next_control(fixture.owner_generation)
            .unwrap()
            .unwrap();
        let reconciliation_state: String = fixture
            .store
            .test_connection()
            .query_row(
                "SELECT state FROM ticket_claim_reconciliations WHERE namespace='fixture' AND ticket_id='43'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(reconciliation_state, "pending");
        fixture
            .store
            .set_project_lifecycle(fixture.owner_generation, &project_id, "running")
            .unwrap();

        let mut scan_services = WorkerPublicationFixtureServices {
            configuration_digest: Digest::parse("a".repeat(64)).unwrap(),
            published_effect: None,
            pending_artifacts: None,
            ticket_page: Some(super::ExternalTicketPage {
                tickets: Vec::new(),
                next_cursor: None,
            }),
            merge_observation: None,
            merge_observation_timeout: None,
            merge_observation_replies: None,
            merge_body_proposal: None,
            merge_work_document: None,
        };
        let absent_report = super::FactoryRuntime::tick(
            &mut fixture.store,
            fixture.owner_generation,
            100,
            &config,
            &mut scan_services,
        )
        .unwrap();
        assert!(
            absent_report.scanned.is_some(),
            "the production tick must poll the configured ticket port"
        );
        let absent_reconciliation_state: String = fixture
            .store
            .test_connection()
            .query_row(
                "SELECT state FROM ticket_claim_reconciliations WHERE namespace='fixture' AND ticket_id='43'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(absent_reconciliation_state, "pending");
        let wakes_after_absent_poll = fixture
            .store
            .pending_role_wake_inputs(&project_id, "project:fixture-project:supervisor", 16)
            .unwrap();
        assert!(
            wakes_after_absent_poll
                .iter()
                .all(|wake| !wake.source_id.ends_with("release-cycle-one")),
            "an absent external ticket must not create a release-cycle Supervisor wake: {wakes_after_absent_poll:?}"
        );

        // A second Project may share the same external namespace and have a
        // cached observation/wake for this ticket. Its fresh page must not
        // satisfy the release gate or receive the release-specific wake.
        let other_project_id = ProjectId::parse("fixture-other-project").unwrap();
        let mut other_project_record = fixture.store.project(&project_id).unwrap().unwrap();
        other_project_record.id = other_project_id.clone();
        fixture.store.insert_project(&other_project_record).unwrap();
        fixture
            .store
            .set_project_lifecycle(fixture.owner_generation, &other_project_id, "running")
            .unwrap();
        let other_key = TicketScanKey::for_project(
            &other_project_id,
            &project.ticket_adapter,
            &namespace,
            project,
            TicketStatus::Ready,
        )
        .unwrap();
        fixture
            .store
            .record_ticket_scan_page(
                fixture.owner_generation,
                TicketScanPage {
                    key: &other_key,
                    expected_cursor: None,
                    expected_generation: 0,
                    expected_page_count: 0,
                    next_cursor: None,
                    tickets: std::slice::from_ref(&observed_ticket),
                    now_unix: 150,
                    poll_seconds: 60,
                },
            )
            .unwrap();
        fixture
            .store
            .enqueue_supervisor_ticket_observation(
                fixture.owner_generation,
                &other_key,
                &crate::store::scheduler::PendingTicketObservation {
                    ticket_id: observed_ticket.id.clone(),
                    revision: observed_ticket.revision.clone(),
                    status: observed_ticket.status,
                    title: observed_ticket.title.clone(),
                    labels: observed_ticket.labels.clone(),
                    observed_at_unix: 150,
                },
                150,
            )
            .unwrap();
        let cross_project_wakes = fixture
            .store
            .pending_role_wake_inputs(
                &other_project_id,
                "project:fixture-other-project:supervisor",
                16,
            )
            .unwrap();
        assert!(cross_project_wakes.iter().any(|wake| {
            wake.source_id == "fixture:43:ready"
                && wake.payload_json["external_revision"] == revision
        }));
        let other_project_claim = fixture
            .store
            .create_dispatched_ticket_run(
                fixture.owner_generation,
                &other_key,
                &TicketId::parse("43").unwrap(),
                Some("docs_only"),
                &[TicketStatus::Ready],
                1,
                &crate::store::scheduler::SupervisorDispatchAuthority {
                    evidence_id: "other-project-cached-wake".into(),
                    priority: 3,
                    expected_external_revision: revision.into(),
                },
                151,
            )
            .unwrap();
        assert!(other_project_claim.is_none());
        let still_pending: String = fixture
            .store
            .test_connection()
            .query_row(
                "SELECT state FROM ticket_claim_reconciliations WHERE namespace='fixture' AND ticket_id='43'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(still_pending, "pending");

        fixture
            .store
            .test_connection()
            .execute(
                "UPDATE ticket_observations SET dispatch_state='pending' WHERE project_id='fixture-project' AND ticket_id='43'",
                [],
            )
            .unwrap();
        assert!(
            fixture
                .store
                .create_dispatched_ticket_run(
                    fixture.owner_generation,
                    &key,
                    &TicketId::parse("43").unwrap(),
                    Some("docs_only"),
                    &[TicketStatus::Ready],
                    1,
                    &crate::store::scheduler::SupervisorDispatchAuthority {
                        evidence_id: "stale-cached-observation".into(),
                        priority: 3,
                        expected_external_revision: revision.into(),
                    },
                    101,
                )
                .unwrap()
                .is_none()
        );
        fixture
            .store
            .test_connection()
            .execute(
                "UPDATE ticket_observations SET dispatch_state='started' WHERE project_id='fixture-project' AND ticket_id='43'",
                [],
            )
            .unwrap();

        scan_services.ticket_page = Some(super::ExternalTicketPage {
            tickets: vec![ObservedTicket {
                observed_at_unix: 200,
                ..observed_ticket.clone()
            }],
            next_cursor: None,
        });
        let report = super::FactoryRuntime::tick(
            &mut fixture.store,
            fixture.owner_generation,
            200,
            &config,
            &mut scan_services,
        )
        .unwrap();
        assert!(report.scanned.is_some());
        let pending_supervisor_wakes = fixture
            .store
            .pending_role_wake_inputs(&project_id, "project:fixture-project:supervisor", 16)
            .unwrap();
        let release_wakes = pending_supervisor_wakes
            .iter()
            .filter(|wake| wake.source_id.ends_with("release-cycle-one"))
            .collect::<Vec<_>>();
        assert_eq!(release_wakes.len(), 1);
        assert_eq!(
            release_wakes[0].source_id,
            "fixture:43:ready:resume:release-cycle-one"
        );
        assert_eq!(release_wakes[0].payload_json["external_revision"], revision);
        let repolled_state: String = fixture
            .store
            .test_connection()
            .query_row(
                "SELECT state FROM ticket_claim_reconciliations WHERE namespace='fixture' AND ticket_id='43'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(repolled_state, "repolled_open");
        let other_project_claim_after_origin_repoll = fixture
            .store
            .create_dispatched_ticket_run(
                fixture.owner_generation,
                &other_key,
                &TicketId::parse("43").unwrap(),
                Some("docs_only"),
                &[TicketStatus::Ready],
                1,
                &crate::store::scheduler::SupervisorDispatchAuthority {
                    evidence_id: "other-project-same-revision-after-repoll".into(),
                    priority: 3,
                    expected_external_revision: revision.into(),
                },
                201,
            )
            .unwrap();
        assert!(other_project_claim_after_origin_repoll.is_none());
        let other_project_resume_wakes = fixture
            .store
            .pending_role_wake_inputs(
                &other_project_id,
                "project:fixture-other-project:supervisor",
                16,
            )
            .unwrap();
        assert!(
            other_project_resume_wakes
                .iter()
                .all(|wake| { !wake.source_id.ends_with("release-cycle-one") })
        );
        let legacy_other_run =
            crate::domain::ids::TicketRunId::parse("fixture-other-project-ticket-43-g1").unwrap();
        fixture
            .store
            .create_ticket_run(
                fixture.owner_generation,
                &other_project_id,
                &namespace,
                &TicketId::parse("43").unwrap(),
                &legacy_other_run,
                1,
                "queued",
                "ready",
            )
            .unwrap();
        fixture
            .store
            .test_connection()
            .execute(
                "INSERT INTO ticket_run_context(ticket_run_id,project_id,project_epoch,recipe_id,goal_revision,created_at_unix) VALUES (?1,?2,1,NULL,0,1)",
                params![legacy_other_run.as_str(), other_project_id.as_str()],
            )
            .unwrap();
        assert!(
            fixture
                .store
                .claim_ticket(
                    fixture.owner_generation,
                    &namespace,
                    &TicketId::parse("43").unwrap(),
                    &other_project_id,
                    &legacy_other_run,
                    1,
                )
                .is_err()
        );
        fixture
            .store
            .set_project_lifecycle(fixture.owner_generation, &other_project_id, "stopped")
            .unwrap();

        // A later successful authoritative page may report a new external
        // revision while this same reconciliation remains open. The release
        // gate must advance atomically with the observation or no dispatch
        // revision can satisfy both records.
        let refreshed_revision = "rev-43-updated-after-release";
        scan_services.ticket_page = Some(super::ExternalTicketPage {
            tickets: vec![ObservedTicket {
                revision: Some(refreshed_revision.into()),
                observed_at_unix: 300,
                ..observed_ticket.clone()
            }],
            next_cursor: None,
        });
        let refreshed_report = super::FactoryRuntime::tick(
            &mut fixture.store,
            fixture.owner_generation,
            300,
            &config,
            &mut scan_services,
        )
        .unwrap();
        assert!(refreshed_report.scanned.is_some());
        let (reconciliation_revision, observation_revision): (Option<String>, Option<String>) =
            fixture.store.test_connection().query_row(
                "SELECT r.external_revision,o.external_revision FROM ticket_claim_reconciliations r JOIN ticket_observations o ON o.namespace=r.namespace AND o.ticket_id=r.ticket_id WHERE r.namespace='fixture' AND r.ticket_id='43'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            ).unwrap();
        assert_eq!(reconciliation_revision.as_deref(), Some(refreshed_revision));
        assert_eq!(observation_revision.as_deref(), Some(refreshed_revision));
        let refreshed_wakes = fixture
            .store
            .pending_role_wake_inputs(&project_id, "project:fixture-project:supervisor", 16)
            .unwrap();
        assert!(refreshed_wakes.iter().any(|wake| {
            wake.source_id == "fixture:43:ready:resume:release-cycle-one"
                && wake.payload_json["external_revision"] == refreshed_revision
        }));

        let fixture_root = std::fs::canonicalize(fixture._temp.path()).unwrap();
        let second =
            crate::store::agent_results::host_validation_fixture::host_validated_result_in(
                &mut fixture.store,
                &fixture_root,
                fixture.owner_generation,
                project_id.clone(),
                old_run.ticket_run_id.clone(),
                Role::Supervisor,
                dispatch_message("supervisor-dispatch-generation-two", refreshed_revision),
            )
            .unwrap();
        let second_binding = &second.ingested.validated.binding;
        fixture
            .store
            .test_connection()
            .execute(
                "INSERT INTO agent_launch_reservations(agent_run_id,project_id,operation_id,controller_generation,project_epoch,reservation_digest,reservation_json,lifecycle,created_at_unix,updated_at_unix) VALUES (?1,?2,?3,?4,1,?5,'{}','authorized',1,1)",
                params![
                    second_binding.agent_run_id.as_str(),
                    second_binding.project_id.as_str(),
                    second_binding.operation_id.as_str(),
                    fixture.owner_generation,
                    "e".repeat(64),
                ],
            )
            .unwrap();
        assert!(
            super::apply_agent_result(
                &mut fixture.store,
                fixture.owner_generation,
                101,
                &config,
                &mut result_services,
                &second.ingested,
            )
            .unwrap()
        );

        let generations: Vec<(u64, String, String)> = fixture
            .store
            .test_connection()
            .prepare(
                "SELECT generation,internal_phase,ticket_run_id FROM ticket_runs WHERE project_id='fixture-project' AND ticket_id='43' ORDER BY generation",
            )
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(
            generations
                .iter()
                .map(|(generation, phase, _)| (*generation, phase.as_str()))
                .collect::<Vec<_>>(),
            [(1, "canceled"), (2, "planning")]
        );
        let claim_generation: u64 = fixture
            .store
            .test_connection()
            .query_row(
                "SELECT generation FROM ticket_claims WHERE namespace='fixture' AND ticket_id='43'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(claim_generation, 2);
        let reconciliation_count: u64 = fixture
            .store
            .test_connection()
            .query_row(
                "SELECT COUNT(*) FROM ticket_claim_reconciliations WHERE namespace='fixture' AND ticket_id='43'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(reconciliation_count, 0);
        let coordinator_wakes = fixture
            .store
            .pending_role_wake_inputs(
                &project_id,
                &format!("ticket_run:{}:coordinator", generations[1].2),
                8,
            )
            .unwrap();
        assert_eq!(coordinator_wakes.len(), 1);
        assert_eq!(coordinator_wakes[0].source_type, "ticket_run_dispatch");

        // A second release exercises a same-Project scope change: only an
        // observation written under the new current scope may satisfy the
        // release gate. The former scan key cannot dispatch it.
        let generation_two =
            crate::domain::ids::TicketRunId::parse(generations[1].2.clone()).unwrap();
        let generation_two_revision: u64 = fixture
            .store
            .test_connection()
            .query_row(
                "SELECT revision FROM ticket_runs WHERE ticket_run_id=?1",
                [generation_two.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        fixture
            .store
            .set_project_lifecycle(fixture.owner_generation, &project_id, "paused")
            .unwrap();
        ConfigStore::append_human_claim_release(
            fixture._temp.path(),
            "release-cycle-two",
            &HumanClaimRelease {
                namespace: namespace.as_str().into(),
                ticket: "43".into(),
                ticket_run_id: generation_two.as_str().into(),
                generation: 2,
                expected_revision: generation_two_revision,
                reason: "exercise the changed scan scope after release".into(),
                disposition: "cancel".into(),
            },
            fixture.owner_generation,
        )
        .unwrap();
        fixture
            .store
            .process_next_control(fixture.owner_generation)
            .unwrap()
            .unwrap();
        fixture
            .store
            .set_project_lifecycle(fixture.owner_generation, &project_id, "running")
            .unwrap();
        let mut current_scope_key = key.clone();
        current_scope_key.scope_digest = Digest::parse("c".repeat(64)).unwrap();
        let current_scope_ticket = ObservedTicket {
            revision: Some(refreshed_revision.into()),
            observed_at_unix: 400,
            ..observed_ticket.clone()
        };
        fixture
            .store
            .record_ticket_scan_page(
                fixture.owner_generation,
                TicketScanPage {
                    key: &current_scope_key,
                    expected_cursor: None,
                    expected_generation: 0,
                    expected_page_count: 0,
                    next_cursor: None,
                    tickets: std::slice::from_ref(&current_scope_ticket),
                    now_unix: 400,
                    poll_seconds: 60,
                },
            )
            .unwrap();
        let current_scope_observation = crate::store::scheduler::PendingTicketObservation {
            ticket_id: current_scope_ticket.id.clone(),
            revision: current_scope_ticket.revision.clone(),
            status: current_scope_ticket.status,
            title: current_scope_ticket.title.clone(),
            labels: current_scope_ticket.labels.clone(),
            observed_at_unix: 400,
        };
        fixture
            .store
            .enqueue_supervisor_ticket_observation(
                fixture.owner_generation,
                &current_scope_key,
                &current_scope_observation,
                400,
            )
            .unwrap();
        assert!(
            fixture
                .store
                .create_dispatched_ticket_run(
                    fixture.owner_generation,
                    &key,
                    &current_scope_ticket.id,
                    Some("docs_only"),
                    &[TicketStatus::Ready],
                    1,
                    &crate::store::scheduler::SupervisorDispatchAuthority {
                        evidence_id: "old-scope-cannot-consume-new-scope-observation".into(),
                        priority: 3,
                        expected_external_revision: refreshed_revision.into(),
                    },
                    401,
                )
                .unwrap()
                .is_none()
        );
        let current_scope_run = fixture
            .store
            .create_dispatched_ticket_run(
                fixture.owner_generation,
                &current_scope_key,
                &current_scope_ticket.id,
                Some("docs_only"),
                &[TicketStatus::Ready],
                1,
                &crate::store::scheduler::SupervisorDispatchAuthority {
                    evidence_id: "new-current-scope-can-consume-release".into(),
                    priority: 3,
                    expected_external_revision: refreshed_revision.into(),
                },
                402,
            )
            .unwrap();
        assert!(current_scope_run.is_some());
    }

    #[test]
    fn controller_restart_rejects_stale_supervisor_dispatch_during_production_tick() {
        use crate::domain::ids::{Digest, ProjectId, TicketNamespace};
        use crate::domain::types::{Role, TicketStatus};
        use crate::engine::orchestration::{AgentAssertion, RoleOutputKind};
        use crate::roles::RoleResultMessage;
        use crate::store::OwnerMetadata;
        use crate::store::scheduler::{ObservedTicket, TicketScanKey, TicketScanPage};
        use serde_json::json;

        let revision = "3ef900fc1927e9ad609e95b52b74a048fd9baa76194eb0ba60d738df088727b4";
        let payload = json!({
            "ticket_reference": "github:civitaspo/rex-projects:43",
            "expected_ticket_revision": revision,
            "coordinator_profile": "judgment_claude",
            "priority": 3,
            "rationale": "dispatch the exact observed ticket revision"
        });
        let result_digest = Digest::parse(format!(
            "{:x}",
            sha2::Sha256::digest(serde_json::to_vec(&payload).unwrap())
        ))
        .unwrap();
        let mut fixture =
            crate::store::agent_results::host_validation_fixture::host_validated_result(
                Role::Supervisor,
                RoleResultMessage {
                    schema_version: crate::engine::orchestration::ROLE_RESULT_SCHEMA_VERSION,
                    message_id: "supervisor-dispatch-old-generation".into(),
                    kind: RoleOutputKind::DispatchRequest,
                    assertion: AgentAssertion::Succeeded,
                    structured_result: payload,
                    result_digest: Some(result_digest),
                    artifact_refs: Vec::new(),
                },
            )
            .unwrap();
        let project_id = ProjectId::parse("fixture-project").unwrap();
        fixture
            .store
            .set_project_lifecycle(fixture.owner_generation, &project_id, "running")
            .unwrap();
        let mut config: Config =
            toml::from_str(include_str!("../../examples/fixture/config.toml")).unwrap();
        let mut project = config
            .projects
            .remove(&ProjectId::parse("goal_project").unwrap())
            .unwrap();
        project.dispatch_states = vec![TicketStatus::Ready];
        config.projects.insert(project_id.clone(), project);
        let project = config.projects.get(&project_id).unwrap();
        let namespace = TicketNamespace::parse("github:civitaspo/rex-projects").unwrap();
        let key = TicketScanKey::for_project(
            &project_id,
            &project.ticket_adapter,
            &namespace,
            project,
            TicketStatus::Ready,
        )
        .unwrap();
        fixture
            .store
            .record_ticket_scan_page(
                fixture.owner_generation,
                TicketScanPage {
                    key: &key,
                    expected_cursor: None,
                    expected_generation: 0,
                    expected_page_count: 0,
                    next_cursor: None,
                    tickets: &[ObservedTicket {
                        id: crate::domain::ids::TicketId::parse("43").unwrap(),
                        revision: Some(revision.into()),
                        status: TicketStatus::Ready,
                        title: "Fixture ticket".into(),
                        labels: Vec::new(),
                        created_at: None,
                        observed_at_unix: 1,
                    }],
                    now_unix: 1,
                    poll_seconds: 60,
                },
            )
            .unwrap();

        fixture
            .store
            .test_connection()
            .execute(
                "UPDATE execution_slots SET disposition='unknown' WHERE owner_kind='agent_run' AND owner_id=?1",
                [fixture.ingested.validated.binding.agent_run_id.as_str()],
            )
            .unwrap();
        fixture.store.stop_owner(fixture.owner_generation).unwrap();
        let owner_generation = fixture
            .store
            .start_owner(&OwnerMetadata {
                owner_nonce: "fixture-restarted-owner".into(),
                state_root: fixture._temp.path().display().to_string(),
                config_source: "fixture".into(),
                process_start_identity: "fixture-restarted-process".into(),
                executable_path: "/test/fixture".into(),
                executable_digest: "c".repeat(64),
                rex_endpoint: Some("http://fixture".into()),
                rex_server_identity: Some("fixture-rex".into()),
                rex_session_id: Some("fixture-session".into()),
                rex_block_id: Some("fixture-block".into()),
            })
            .unwrap();
        let slot_disposition: String = fixture
            .store
            .test_connection()
            .query_row(
                "SELECT disposition FROM execution_slots WHERE owner_kind='agent_run' AND owner_id=?1",
                [fixture.ingested.validated.binding.agent_run_id.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(slot_disposition, "unknown");
        let artifacts = fixture.artifacts.clone();
        let mut services = WorkerPublicationFixtureServices {
            configuration_digest: Digest::parse("a".repeat(64)).unwrap(),
            published_effect: None,
            pending_artifacts: Some(fixture.artifacts),
            ticket_page: None,
            merge_observation: None,
            merge_observation_timeout: None,
            merge_observation_replies: None,
            merge_body_proposal: None,
            merge_work_document: None,
        };

        let tick = super::FactoryRuntime::tick(
            &mut fixture.store,
            owner_generation,
            2,
            &config,
            &mut services,
        );
        assert!(
            tick.is_ok(),
            "stale result must not stop controller: {tick:?}"
        );
        let ticket_runs: u64 = fixture
            .store
            .test_connection()
            .query_row("SELECT COUNT(*) FROM ticket_runs", [], |row| row.get(0))
            .unwrap();
        assert_eq!(ticket_runs, 0);
        assert_eq!(
            crate::store::agent_results::host_validation_fixture::result_ack(
                &fixture.store,
                fixture.ingested.receipt.evidence_id(),
            )
            .unwrap()
            .map(|(_, disposition)| disposition),
            Some("rejected_by_host".to_owned())
        );
        let slot_disposition: String = fixture
            .store
            .test_connection()
            .query_row(
                "SELECT disposition FROM execution_slots WHERE owner_kind='agent_run' AND owner_id=?1",
                [fixture.ingested.validated.binding.agent_run_id.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(slot_disposition, "unknown");

        let pending = fixture
            .store
            .pending_validated_agent_results(&artifacts, owner_generation, 1)
            .unwrap();
        assert!(pending.is_empty());
        let second_tick = super::FactoryRuntime::tick(
            &mut fixture.store,
            owner_generation,
            3,
            &config,
            &mut services,
        );
        assert!(
            second_tick.is_ok(),
            "acknowledged stale result must remain idempotent: {second_tick:?}"
        );
        let ticket_runs: u64 = fixture
            .store
            .test_connection()
            .query_row("SELECT COUNT(*) FROM ticket_runs", [], |row| row.get(0))
            .unwrap();
        assert_eq!(ticket_runs, 0);
        assert_eq!(
            crate::store::agent_results::host_validation_fixture::result_ack(
                &fixture.store,
                fixture.ingested.receipt.evidence_id(),
            )
            .unwrap()
            .map(|(_, disposition)| disposition),
            Some("rejected_by_host".to_owned())
        );
    }

    #[test]
    fn host_validated_worker_result_advances_and_persists_publication_before_ack() {
        use crate::domain::ids::Digest;
        use crate::engine::orchestration::{AgentAssertion, RoleOutputKind};
        use crate::roles::RoleResultMessage;
        use serde_json::json;

        let structured_result = json!({
            "change_references": [{
                "repository": "repo-a",
                "worktree_id": "node-a",
                "commit_mode": "native",
                "base_commit": "0000000000000000000000000000000000000000",
                "previous_head": "1111111111111111111111111111111111111111",
                "branch_head": "2222222222222222222222222222222222222222",
                "commit_shas": ["2222222222222222222222222222222222222222"]
            }],
            "completed_acceptance_items": ["tests pass"],
            "unresolved_items": [],
            "irregularity_references": []
        });
        let result_digest = Digest::parse(format!(
            "{:x}",
            sha2::Sha256::digest(serde_json::to_vec(&structured_result).unwrap())
        ))
        .unwrap();
        let mut fixture =
            crate::store::agent_results::host_validation_fixture::host_validated_result(
                Role::Worker,
                RoleResultMessage {
                    schema_version: 1,
                    message_id: "worker-message-1".into(),
                    kind: RoleOutputKind::ImplementationReady,
                    assertion: AgentAssertion::Succeeded,
                    structured_result,
                    result_digest: Some(result_digest),
                    artifact_refs: Vec::new(),
                },
            )
            .unwrap();
        let config: Config =
            toml::from_str(include_str!("../../examples/fixture/config.toml")).unwrap();
        let mut services = WorkerPublicationFixtureServices {
            configuration_digest: Digest::parse("a".repeat(64)).unwrap(),
            published_effect: None,
            pending_artifacts: None,
            ticket_page: None,
            merge_observation: None,
            merge_observation_timeout: None,
            merge_observation_replies: None,
            merge_body_proposal: None,
            merge_work_document: None,
        };

        assert!(
            super::apply_agent_result(
                &mut fixture.store,
                fixture.owner_generation,
                10,
                &config,
                &mut services,
                &fixture.ingested,
            )
            .unwrap()
        );

        let run = fixture
            .store
            .active_ticket_runs(fixture.owner_generation, 1)
            .unwrap()
            .remove(0);
        assert_eq!(run.phase, Phase::Publishing);
        assert_eq!(run.revision, 5);
        let intended = services.published_effect.unwrap();
        assert_eq!(
            fixture
                .store
                .effect_by_logical_key(&intended.logical_key)
                .unwrap(),
            Some(intended.clone())
        );
        let acknowledgement = crate::store::agent_results::host_validation_fixture::result_ack(
            &fixture.store,
            fixture.ingested.receipt.evidence_id(),
        )
        .unwrap();
        assert_eq!(acknowledgement, Some((5, "applied".into())));
        assert!(
            fixture
                .store
                .pending_validated_agent_results(&fixture.artifacts, fixture.owner_generation, 8)
                .unwrap()
                .is_empty()
        );

        let state_root = fixture._temp.path().to_path_buf();
        drop(fixture.store);
        let mut reopened = crate::store::ConfigStore::open_test(&state_root).unwrap();
        assert_eq!(
            reopened
                .active_ticket_runs(fixture.owner_generation, 1)
                .unwrap()[0]
                .phase,
            Phase::Publishing
        );
        assert_eq!(
            reopened
                .effect_by_logical_key(&intended.logical_key)
                .unwrap(),
            Some(intended)
        );
        assert_eq!(
            crate::store::agent_results::host_validation_fixture::result_ack(
                &reopened,
                fixture.ingested.receipt.evidence_id(),
            )
            .unwrap(),
            Some((5, "applied".into())),
        );
        assert!(
            reopened
                .pending_validated_agent_results(&fixture.artifacts, fixture.owner_generation, 8)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn host_validated_preplan_coordinator_request_creates_planner_wake_without_digest() {
        use crate::domain::ids::Digest;
        use crate::engine::orchestration::{AgentAssertion, RoleOutputKind};
        use crate::roles::RoleResultMessage;
        use serde_json::json;

        let structured_result = json!({
            "work_node": "initial-plan",
            "role": "planner",
            "profile_id": "fixture-profile",
            "allowed_repositories": [],
            "artifact_inputs": [],
            "parent_run_id": null
        });
        let result_digest = Digest::parse(format!(
            "{:x}",
            sha2::Sha256::digest(serde_json::to_vec(&structured_result).unwrap())
        ))
        .unwrap();
        let mut fixture =
            crate::store::agent_results::host_validation_fixture::host_validated_result(
                Role::Coordinator,
                RoleResultMessage {
                    schema_version: 1,
                    message_id: "coordinator-plan-request-1".into(),
                    kind: RoleOutputKind::SpawnRequest,
                    assertion: AgentAssertion::Succeeded,
                    structured_result,
                    result_digest: Some(result_digest),
                    artifact_refs: Vec::new(),
                },
            )
            .unwrap();
        let config: Config = serde_json::from_value(json!({
            "schema_version": 1,
            "adapters": {"tickets": {"kind": "command", "command": ["ticket-cli"]}},
            "projects": {"fixture-project": {
                "mode": "goal",
                "ticket_adapter": "tickets",
                "goal": {"revision": 1, "statement": "fixture goal", "acceptance": ["produce a valid plan"]},
                "roles": {"coordinator": "fixture-profile", "planner": "fixture-profile"}
            }}
        }))
        .unwrap();
        let configuration_digest = Digest::parse("a".repeat(64)).unwrap();
        let mut services = WorkerPublicationFixtureServices {
            configuration_digest,
            published_effect: None,
            pending_artifacts: None,
            ticket_page: None,
            merge_observation: None,
            merge_observation_timeout: None,
            merge_observation_replies: None,
            merge_body_proposal: None,
            merge_work_document: None,
        };

        assert!(
            super::apply_agent_result(
                &mut fixture.store,
                fixture.owner_generation,
                10,
                &config,
                &mut services,
                &fixture.ingested,
            )
            .unwrap()
        );

        let project_id = ProjectId::parse("fixture-project").unwrap();
        let wakes = fixture
            .store
            .pending_role_wake_inputs(&project_id, "ticket_run:fixture-ticket-run:planner", 8)
            .unwrap();
        assert_eq!(wakes.len(), 1);
        assert_eq!(wakes[0].source_id, fixture.ingested.receipt.evidence_id());
        let payload = &wakes[0].payload_json;
        assert_eq!(payload["request"]["role"], "planner");
        assert!(payload["request"].get("plan_digest").is_none());
        assert_eq!(
            crate::store::agent_results::host_validation_fixture::result_ack(
                &fixture.store,
                fixture.ingested.receipt.evidence_id(),
            )
            .unwrap(),
            Some((3, "applied".into()))
        );
    }

    #[test]
    fn phase_ineligible_coordinator_spawn_is_acknowledged_and_wakes_same_coordinator() {
        use crate::domain::ids::Digest;
        use crate::engine::orchestration::{AgentAssertion, RoleOutputKind};
        use crate::roles::RoleResultMessage;
        use serde_json::json;

        let structured_result = json!({
            "work_node": "initial-plan",
            "role": "planner",
            "profile_id": "fixture-profile",
            "allowed_repositories": [],
            "artifact_inputs": [],
            "parent_run_id": null
        });
        let result_digest = Digest::parse(format!(
            "{:x}",
            sha2::Sha256::digest(serde_json::to_vec(&structured_result).unwrap())
        ))
        .unwrap();
        let mut fixture =
            crate::store::agent_results::host_validation_fixture::host_validated_result(
                Role::Coordinator,
                RoleResultMessage {
                    schema_version: 1,
                    message_id: "coordinator-phase-rejected-1".into(),
                    kind: RoleOutputKind::SpawnRequest,
                    assertion: AgentAssertion::Succeeded,
                    structured_result,
                    result_digest: Some(result_digest),
                    artifact_refs: Vec::new(),
                },
            )
            .unwrap();
        fixture
            .store
            .test_connection()
            .execute(
                "UPDATE ticket_runs SET internal_phase='implementing' WHERE ticket_run_id='fixture-ticket-run'",
                [],
            )
            .unwrap();
        let config: Config = serde_json::from_value(json!({
            "schema_version": 1,
            "adapters": {"tickets": {"kind": "command", "command": ["ticket-cli"]}},
            "projects": {"fixture-project": {
                "mode": "goal",
                "ticket_adapter": "tickets",
                "goal": {"revision": 1, "statement": "fixture goal", "acceptance": ["produce a valid plan"]},
                "roles": {"coordinator": "fixture-profile", "planner": "fixture-profile"}
            }}
        }))
        .unwrap();
        let mut services = WorkerPublicationFixtureServices {
            configuration_digest: Digest::parse("a".repeat(64)).unwrap(),
            published_effect: None,
            pending_artifacts: None,
            ticket_page: None,
            merge_observation: None,
            merge_observation_timeout: None,
            merge_observation_replies: None,
            merge_body_proposal: None,
            merge_work_document: None,
        };
        let coordinator_session = "ticket_run:fixture-ticket-run:coordinator";

        for _ in 0..2 {
            assert!(
                super::apply_agent_result(
                    &mut fixture.store,
                    fixture.owner_generation,
                    10,
                    &config,
                    &mut services,
                    &fixture.ingested,
                )
                .unwrap()
            );
        }

        let project_id = ProjectId::parse("fixture-project").unwrap();
        let wakes = fixture
            .store
            .pending_role_wake_inputs(&project_id, coordinator_session, 8)
            .unwrap();
        assert_eq!(wakes.len(), 1);
        let rejected = wakes
            .iter()
            .find(|wake| wake.source_type == "coordinator_spawn_rejected")
            .unwrap();
        assert_eq!(rejected.source_id, fixture.ingested.receipt.evidence_id());
        assert_eq!(rejected.payload_json["current_phase"], "implementing");
        assert_eq!(rejected.payload_json["requested_role"], "planner");
        assert!(
            rejected.payload_json["next_step"]
                .as_str()
                .unwrap()
                .contains("host-verified")
        );
        assert!(
            fixture
                .store
                .pending_role_wake_inputs(&project_id, "ticket_run:fixture-ticket-run:planner", 8)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            crate::store::agent_results::host_validation_fixture::result_ack(
                &fixture.store,
                fixture.ingested.receipt.evidence_id(),
            )
            .unwrap(),
            Some((3, "rejected_by_host".into()))
        );

        let negative_structured_result = json!({
            "work_node": "initial-plan",
            "role": "planner",
            "profile_id": "fixture-profile",
            "allowed_repositories": [],
            "artifact_inputs": [],
            "parent_run_id": null
        });
        let negative_result_digest = Digest::parse(format!(
            "{:x}",
            sha2::Sha256::digest(serde_json::to_vec(&negative_structured_result).unwrap())
        ))
        .unwrap();
        let mut negative_fixture =
            crate::store::agent_results::host_validation_fixture::host_validated_result(
                Role::Coordinator,
                RoleResultMessage {
                    schema_version: 1,
                    message_id: "coordinator-phase-rejected-bad-authority".into(),
                    kind: RoleOutputKind::SpawnRequest,
                    assertion: AgentAssertion::Succeeded,
                    structured_result: negative_structured_result,
                    result_digest: Some(negative_result_digest),
                    artifact_refs: Vec::new(),
                },
            )
            .unwrap();
        negative_fixture
            .store
            .test_connection()
            .execute(
                "UPDATE ticket_runs SET internal_phase='implementing' WHERE ticket_run_id='fixture-ticket-run'",
                [],
            )
            .unwrap();
        negative_fixture
            .store
            .test_connection()
            .execute("DROP TRIGGER agent_launch_authority_immutable_update", [])
            .unwrap();
        negative_fixture
            .store
            .test_connection()
            .execute(
                "UPDATE agent_launch_authority SET authority_digest=?2 WHERE agent_run_id=?1",
                rusqlite::params!["fixture-agent-run", "f".repeat(64)],
            )
            .unwrap();
        assert!(
            super::apply_agent_result(
                &mut negative_fixture.store,
                negative_fixture.owner_generation,
                10,
                &config,
                &mut services,
                &negative_fixture.ingested,
            )
            .is_err()
        );
        assert_eq!(
            crate::store::agent_results::host_validation_fixture::result_ack(
                &negative_fixture.store,
                negative_fixture.ingested.receipt.evidence_id(),
            )
            .unwrap(),
            None
        );
        assert!(
            negative_fixture
                .store
                .pending_role_wake_inputs(&project_id, coordinator_session, 8)
                .unwrap()
                .iter()
                .all(|wake| wake.source_id != negative_fixture.ingested.receipt.evidence_id())
        );
    }

    #[test]
    fn phase_ineligible_reviewer_spawn_with_accepted_plan_and_general_artifact_is_rejected() {
        use crate::domain::ids::{AgentRunId, ArtifactId, Digest, RepositoryId};
        use crate::engine::orchestration::{
            AgentAssertion, PlannedWorkNode, RoleArtifactKind, RoleArtifactReference,
            RoleOutputKind, SpawnRequestPayload, WorkPlan,
        };
        use crate::roles::RoleResultMessage;
        use crate::store::accepted_plans::PersistedWorkPlan;
        use std::collections::BTreeMap;

        let project_id = ProjectId::parse("fixture-project").unwrap();
        let ticket_run_id = crate::domain::ids::TicketRunId::parse("fixture-ticket-run").unwrap();
        let repository = RepositoryId::parse("repo-a").unwrap();
        let work_node = crate::engine::orchestration::WorkNodeId::parse("node-a").unwrap();
        let run_id = AgentRunId::parse("fixture-agent-run").unwrap();
        let general_bytes = b"Coordinator registered general evidence";
        let general_digest =
            Digest::parse(format!("{:x}", sha2::Sha256::digest(general_bytes))).unwrap();
        let general_artifact_id = ArtifactId::from_registration_identity(
            &project_id,
            &run_id,
            "general",
            1,
            &general_digest,
        )
        .unwrap();
        let general_reference = RoleArtifactReference {
            artifact_id: general_artifact_id.clone(),
            kind: RoleArtifactKind::General,
            schema_version: 1,
            path: format!(
                "sha256/{}/{}",
                &general_artifact_id.as_str()[..2],
                general_artifact_id.as_str()
            ),
            digest: general_digest,
            bytes: general_bytes.len() as u64,
        };
        let proposal = WorkPlan {
            nodes: vec![PlannedWorkNode {
                id: work_node.clone(),
                repository: repository.clone(),
                task: "implement the requested change".into(),
                depends_on: Vec::new(),
                required_evidence: vec!["tests pass".into()],
                investigation: false,
            }],
            requested_investigation_children: 0,
        };
        let persisted_plan = PersistedWorkPlan {
            schema_version: 1,
            proposal: proposal.clone(),
            observed_base_shas: BTreeMap::new(),
        };
        let plan_json = crate::store::canonical_json(&persisted_plan).unwrap();
        let plan_digest =
            Digest::parse(format!("{:x}", sha2::Sha256::digest(plan_json.as_bytes()))).unwrap();
        let request = SpawnRequestPayload {
            work_node: work_node.clone(),
            role: Role::Reviewer,
            profile_id: crate::domain::ids::ProfileId::parse("fixture-profile").unwrap(),
            plan_digest: Some(plan_digest.clone()),
            worker_recovery: None,
            allowed_repositories: vec![repository.clone()],
            artifact_inputs: vec![general_reference.clone()],
            parent_run_id: None,
        };
        let structured_result = serde_json::to_value(&request).unwrap();
        let result_digest = Digest::parse(format!(
            "{:x}",
            sha2::Sha256::digest(serde_json::to_vec(&structured_result).unwrap())
        ))
        .unwrap();
        let mut fixture =
            crate::store::agent_results::host_validation_fixture::host_validated_terminal_result(
                Role::Coordinator,
                RoleResultMessage {
                    schema_version: 1,
                    message_id: "coordinator-review-request-with-general-artifact".into(),
                    kind: RoleOutputKind::SpawnRequest,
                    assertion: AgentAssertion::Succeeded,
                    structured_result,
                    result_digest: Some(result_digest),
                    artifact_refs: vec![general_reference.clone()],
                },
            )
            .unwrap();
        let authority = fixture
            .store
            .agent_launch_authority(&run_id)
            .unwrap()
            .unwrap();
        std::fs::create_dir_all(authority.workspace_path.join("evidence")).unwrap();
        std::fs::write(
            authority.workspace_path.join("evidence/context.txt"),
            general_bytes,
        )
        .unwrap();
        let artifact_request_id = "coordinator-general-artifact";
        let mailbox = crate::mailbox::MailboxCapability::open_registered_for_run(
            run_id.to_string(),
            &authority.control_dir.join("mailbox"),
        )
        .unwrap();
        let artifact_request = crate::engine::orchestration::ArtifactAddRequest {
            schema_version: 1,
            message_id: artifact_request_id.into(),
            path: "evidence/context.txt".into(),
            kind: RoleArtifactKind::General,
            artifact_schema_version: 1,
        };
        let artifact_envelope = crate::protocol::RequestEnvelope {
            schema_version: crate::protocol::SCHEMA_VERSION,
            request_id: crate::protocol::RequestId::new(artifact_request_id).unwrap(),
            operation_id: Some(authority.operation_id.clone()),
            method: crate::protocol::MethodName::new("artifact.add").unwrap(),
            project_id: Some(project_id.clone()),
            run_id: Some(run_id.to_string()),
            attempt: Some(authority.attempt),
            run_epoch: Some(authority.run_epoch),
            expected_subject_revision: Some(authority.ticket_revision.unwrap().0),
            role: Some(Role::Coordinator),
            request_type: None,
            params: serde_json::to_value(&artifact_request).unwrap(),
        };
        let mailbox_now = crate::mailbox::unix_time_now().unwrap();
        mailbox
            .queue(
                artifact_request_id,
                &serde_json::to_vec(&artifact_envelope).unwrap(),
                mailbox_now,
            )
            .unwrap();
        let mailbox_request = mailbox.pending(mailbox_now).unwrap().remove(0);
        let registered = fixture
            .store
            .process_artifact_add(
                fixture.owner_generation,
                &authority,
                &fixture.artifacts,
                &mailbox,
                &mailbox_request,
                &artifact_request,
            )
            .unwrap();
        assert_eq!(registered.reference(), &general_reference);

        let ingested = crate::store::agent_results::ingest_next_spooled_agent_result(
            &mut fixture.store,
            &fixture.artifacts,
            fixture.owner_generation,
            8,
        )
        .unwrap()
        .unwrap();
        assert_eq!(ingested.validated.binding.role, Role::Coordinator);
        assert_eq!(ingested.validated.kind, RoleOutputKind::SpawnRequest);
        assert_eq!(ingested.verified_artifacts.len(), 1);
        assert_eq!(
            ingested.verified_artifacts[0].reference(),
            &general_reference
        );
        assert_eq!(
            ingested.validated.typed_payload,
            crate::engine::orchestration::RoleResultPayload::SpawnRequest(request.clone())
        );
        fixture
            .store
            .test_connection()
            .execute(
                "UPDATE ticket_runs SET internal_phase='implementing' WHERE ticket_run_id=?1",
                [ticket_run_id.as_str()],
            )
            .unwrap();
        fixture
            .store
            .test_connection()
            .execute(
                "INSERT INTO accepted_work_plans(project_id,ticket_run_id,accepted_revision,configuration_digest,plan_digest,plan_json,source_evidence_id,source_agent_run_id,source_message_id,source_result_digest,coordinator_agent_run_id,coordinator_role_session_id,coordinator_authority_digest,created_at_unix) VALUES (?1,?2,3,?3,?4,?5,?6,?7,?8,?9,?7,?10,?11,1)",
                rusqlite::params![
                    project_id.as_str(),
                    ticket_run_id.as_str(),
                    authority.config_digest.as_str(),
                    plan_digest.as_str(),
                    plan_json,
                    ingested.receipt.evidence_id(),
                    authority.agent_run_id.as_str(),
                    ingested.receipt.message_id(),
                    ingested.receipt.content_digest().as_str(),
                    authority.role_session_id,
                    authority.digest().unwrap().as_str(),
                ],
            )
            .unwrap();
        let config: Config = serde_json::from_value(serde_json::json!({
            "schema_version": 1,
            "adapters": {"tickets": {"kind": "command", "command": ["ticket-cli"]}},
            "projects": {"fixture-project": {
                "mode": "goal",
                "ticket_adapter": "tickets",
                "repositories": ["repo-a"],
                "goal": {"revision": 1, "statement": "fixture goal", "acceptance": ["produce a valid review request"]},
                "roles": {"coordinator": "fixture-profile", "reviewer": "fixture-profile"}
            }}
        }))
        .unwrap();
        let mut services = WorkerPublicationFixtureServices {
            configuration_digest: authority.config_digest.clone(),
            published_effect: None,
            pending_artifacts: None,
            ticket_page: None,
            merge_observation: None,
            merge_observation_timeout: None,
            merge_observation_replies: None,
            merge_body_proposal: None,
            merge_work_document: None,
        };
        for _ in 0..2 {
            assert!(
                super::apply_agent_result(
                    &mut fixture.store,
                    fixture.owner_generation,
                    10,
                    &config,
                    &mut services,
                    &ingested,
                )
                .unwrap()
            );
        }
        let coordinator_session = format!("ticket_run:{ticket_run_id}:coordinator");
        let wakes = fixture
            .store
            .pending_role_wake_inputs(&project_id, &coordinator_session, 16)
            .unwrap();
        assert_eq!(
            wakes
                .iter()
                .filter(|wake| wake.source_type == "coordinator_spawn_rejected")
                .count(),
            1
        );
        assert!(wakes.iter().any(|wake| {
            wake.source_type == "coordinator_spawn_rejected"
                && wake.source_id == ingested.receipt.evidence_id()
                && wake.payload_json["requested_role"] == "reviewer"
                && wake.payload_json["current_phase"] == "implementing"
        }));
        assert!(
            fixture
                .store
                .pending_role_wake_inputs(
                    &project_id,
                    &format!("ticket_run:{ticket_run_id}:reviewer"),
                    16
                )
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            crate::store::agent_results::host_validation_fixture::result_ack(
                &fixture.store,
                ingested.receipt.evidence_id(),
            )
            .unwrap(),
            Some((3, "rejected_by_host".into()))
        );
    }

    #[test]
    fn reviewer_spawn_in_reviewing_persists_candidate_and_coordinator_parent() {
        assert_judgment_spawn_persists_candidate_and_coordinator_parent(
            Role::Reviewer,
            "reviewing",
        );
    }

    #[test]
    fn merge_decision_spawn_in_assessing_persists_candidate_and_coordinator_parent() {
        assert_judgment_spawn_persists_candidate_and_coordinator_parent(
            Role::MergeDecision,
            "assessing",
        );
    }

    #[test]
    fn operator_spawn_in_operating_persists_candidate_and_coordinator_parent() {
        assert_judgment_spawn_persists_candidate_and_coordinator_parent(
            Role::Operator,
            "operating",
        );
    }

    #[test]
    fn postmortem_spawn_in_postmortem_persists_candidate_and_coordinator_parent() {
        assert_judgment_spawn_persists_candidate_and_coordinator_parent(
            Role::Postmortem,
            "postmortem",
        );
    }

    fn assert_judgment_spawn_persists_candidate_and_coordinator_parent(
        child_role: Role,
        phase: &str,
    ) {
        use crate::domain::ids::{AgentRunId, ArtifactId, Digest, RepositoryId};
        use crate::engine::orchestration::{
            AgentAssertion, PlannedWorkNode, RoleArtifactKind, RoleArtifactReference,
            RoleOutputKind, SpawnRequestPayload, WorkPlan,
        };
        use crate::roles::RoleResultMessage;
        use crate::store::accepted_plans::PersistedWorkPlan;
        use std::collections::BTreeMap;

        let project_id = ProjectId::parse("fixture-project").unwrap();
        let ticket_run_id = crate::domain::ids::TicketRunId::parse("fixture-ticket-run").unwrap();
        let repository = RepositoryId::parse("repo-a").unwrap();
        let work_node = crate::engine::orchestration::WorkNodeId::parse("node-a").unwrap();
        let run_id = AgentRunId::parse("fixture-agent-run").unwrap();
        let general_bytes = b"Coordinator registered general evidence";
        let general_digest =
            Digest::parse(format!("{:x}", sha2::Sha256::digest(general_bytes))).unwrap();
        let general_artifact_id = ArtifactId::from_registration_identity(
            &project_id,
            &run_id,
            "general",
            1,
            &general_digest,
        )
        .unwrap();
        let general_reference = RoleArtifactReference {
            artifact_id: general_artifact_id.clone(),
            kind: RoleArtifactKind::General,
            schema_version: 1,
            path: format!(
                "sha256/{}/{}",
                &general_artifact_id.as_str()[..2],
                general_artifact_id.as_str()
            ),
            digest: general_digest,
            bytes: general_bytes.len() as u64,
        };
        let proposal = WorkPlan {
            nodes: vec![PlannedWorkNode {
                id: work_node.clone(),
                repository: repository.clone(),
                task: "implement the requested change".into(),
                depends_on: Vec::new(),
                required_evidence: vec!["tests pass".into()],
                investigation: false,
            }],
            requested_investigation_children: 0,
        };
        let persisted_plan = PersistedWorkPlan {
            schema_version: 1,
            proposal: proposal.clone(),
            observed_base_shas: BTreeMap::new(),
        };
        let plan_json = crate::store::canonical_json(&persisted_plan).unwrap();
        let plan_digest =
            Digest::parse(format!("{:x}", sha2::Sha256::digest(plan_json.as_bytes()))).unwrap();
        let request = SpawnRequestPayload {
            work_node: work_node.clone(),
            role: child_role,
            profile_id: crate::domain::ids::ProfileId::parse("fixture-profile").unwrap(),
            plan_digest: Some(plan_digest.clone()),
            worker_recovery: None,
            allowed_repositories: vec![repository.clone()],
            artifact_inputs: vec![general_reference.clone()],
            parent_run_id: None,
        };
        let structured_result = serde_json::to_value(&request).unwrap();
        let result_digest = Digest::parse(format!(
            "{:x}",
            sha2::Sha256::digest(serde_json::to_vec(&structured_result).unwrap())
        ))
        .unwrap();
        let mut fixture =
            crate::store::agent_results::host_validation_fixture::host_validated_terminal_result(
                Role::Coordinator,
                RoleResultMessage {
                    schema_version: 1,
                    message_id: "coordinator-judgment-request-with-general-artifact-accepted"
                        .into(),
                    kind: RoleOutputKind::SpawnRequest,
                    assertion: AgentAssertion::Succeeded,
                    structured_result,
                    result_digest: Some(result_digest),
                    artifact_refs: vec![general_reference.clone()],
                },
            )
            .unwrap();
        let authority = fixture
            .store
            .agent_launch_authority(&run_id)
            .unwrap()
            .unwrap();
        std::fs::create_dir_all(authority.workspace_path.join("evidence")).unwrap();
        std::fs::write(
            authority.workspace_path.join("evidence/context.txt"),
            general_bytes,
        )
        .unwrap();
        let artifact_request_id = "coordinator-general-artifact";
        let mailbox = crate::mailbox::MailboxCapability::open_registered_for_run(
            run_id.to_string(),
            &authority.control_dir.join("mailbox"),
        )
        .unwrap();
        let artifact_request = crate::engine::orchestration::ArtifactAddRequest {
            schema_version: 1,
            message_id: artifact_request_id.into(),
            path: "evidence/context.txt".into(),
            kind: RoleArtifactKind::General,
            artifact_schema_version: 1,
        };
        let artifact_envelope = crate::protocol::RequestEnvelope {
            schema_version: crate::protocol::SCHEMA_VERSION,
            request_id: crate::protocol::RequestId::new(artifact_request_id).unwrap(),
            operation_id: Some(authority.operation_id.clone()),
            method: crate::protocol::MethodName::new("artifact.add").unwrap(),
            project_id: Some(project_id.clone()),
            run_id: Some(run_id.to_string()),
            attempt: Some(authority.attempt),
            run_epoch: Some(authority.run_epoch),
            expected_subject_revision: Some(authority.ticket_revision.unwrap().0),
            role: Some(Role::Coordinator),
            request_type: None,
            params: serde_json::to_value(&artifact_request).unwrap(),
        };
        let mailbox_now = crate::mailbox::unix_time_now().unwrap();
        mailbox
            .queue(
                artifact_request_id,
                &serde_json::to_vec(&artifact_envelope).unwrap(),
                mailbox_now,
            )
            .unwrap();
        let mailbox_request = mailbox.pending(mailbox_now).unwrap().remove(0);
        let registered = fixture
            .store
            .process_artifact_add(
                fixture.owner_generation,
                &authority,
                &fixture.artifacts,
                &mailbox,
                &mailbox_request,
                &artifact_request,
            )
            .unwrap();
        assert_eq!(registered.reference(), &general_reference);

        let ingested = crate::store::agent_results::ingest_next_spooled_agent_result(
            &mut fixture.store,
            &fixture.artifacts,
            fixture.owner_generation,
            8,
        )
        .unwrap()
        .unwrap();
        assert_eq!(ingested.validated.binding.role, Role::Coordinator);
        assert_eq!(ingested.validated.kind, RoleOutputKind::SpawnRequest);
        assert_eq!(ingested.verified_artifacts.len(), 1);
        assert_eq!(
            ingested.verified_artifacts[0].reference(),
            &general_reference
        );
        assert_eq!(
            ingested.validated.typed_payload,
            crate::engine::orchestration::RoleResultPayload::SpawnRequest(request.clone())
        );
        fixture
            .store
            .test_connection()
            .execute(
                "UPDATE ticket_runs SET internal_phase=?2 WHERE ticket_run_id=?1",
                rusqlite::params![ticket_run_id.as_str(), phase],
            )
            .unwrap();
        fixture
            .store
            .test_connection()
            .execute(
                "INSERT INTO accepted_work_plans(project_id,ticket_run_id,accepted_revision,configuration_digest,plan_digest,plan_json,source_evidence_id,source_agent_run_id,source_message_id,source_result_digest,coordinator_agent_run_id,coordinator_role_session_id,coordinator_authority_digest,created_at_unix) VALUES (?1,?2,3,?3,?4,?5,?6,?7,?8,?9,?7,?10,?11,1)",
                rusqlite::params![
                    project_id.as_str(),
                    ticket_run_id.as_str(),
                    authority.config_digest.as_str(),
                    plan_digest.as_str(),
                    plan_json,
                    ingested.receipt.evidence_id(),
                    authority.agent_run_id.as_str(),
                    ingested.receipt.message_id(),
                    ingested.receipt.content_digest().as_str(),
                    authority.role_session_id,
                    authority.digest().unwrap().as_str(),
                ],
            )
            .unwrap();
        let config: Config = serde_json::from_value(serde_json::json!({
            "schema_version": 1,
            "adapters": {"tickets": {"kind": "command", "command": ["ticket-cli"]}},
            "projects": {"fixture-project": {
                "mode": "goal",
                "ticket_adapter": "tickets",
                "repositories": ["repo-a"],
                "goal": {"revision": 1, "statement": "fixture goal", "acceptance": ["produce a valid review request"]},
                "roles": {"coordinator": "fixture-profile", "reviewer": "fixture-profile", "merge_decision": "fixture-profile", "operator": "fixture-profile", "postmortem": "fixture-profile"}
            }}
        }))
        .unwrap();
        let mut services = WorkerPublicationFixtureServices {
            configuration_digest: authority.config_digest.clone(),
            published_effect: None,
            pending_artifacts: None,
            ticket_page: None,
            merge_observation: None,
            merge_observation_timeout: None,
            merge_observation_replies: None,
            merge_body_proposal: None,
            merge_work_document: None,
        };
        for _ in 0..2 {
            assert!(
                super::apply_agent_result(
                    &mut fixture.store,
                    fixture.owner_generation,
                    10,
                    &config,
                    &mut services,
                    &ingested,
                )
                .unwrap()
            );
        }
        let child_session = format!(
            "ticket_run:{ticket_run_id}:{}",
            super::role_name(child_role)
        );
        let current_ticket_revision = fixture
            .store
            .active_ticket_runs(fixture.owner_generation, 16)
            .unwrap()
            .into_iter()
            .find(|run| run.ticket_run_id == ticket_run_id)
            .unwrap()
            .revision;
        let child_wakes = fixture
            .store
            .pending_role_wake_inputs(&project_id, &child_session, 16)
            .unwrap();
        assert_eq!(child_wakes.len(), 1);
        assert_eq!(child_wakes[0].source_type, "coordinator_child");
        assert_eq!(child_wakes[0].source_id, ingested.receipt.evidence_id());
        assert_eq!(child_wakes[0].source_revision, current_ticket_revision);

        fixture
            .store
            .test_connection()
            .execute(
                "UPDATE project_runtimes SET observed_lifecycle='running',controller_generation=?2 WHERE project_id=?1",
                rusqlite::params![project_id.as_str(), fixture.owner_generation],
            )
            .unwrap();
        let candidates = fixture
            .store
            .pending_role_wake_sessions(fixture.owner_generation, 16)
            .unwrap();
        let child_candidate = candidates
            .iter()
            .find(|candidate| candidate.role_session_id == child_session)
            .expect("persisted Coordinator child wake is offered as a judgment launch candidate");
        assert_eq!(child_candidate.role, child_role);
        assert_eq!(child_candidate.ticket_run_id.as_ref(), Some(&ticket_run_id));
        let parent = fixture
            .store
            .coordinator_child_parent(&project_id, &child_session)
            .unwrap()
            .expect("judgment candidate is bound to the completed Coordinator result");
        assert_eq!(parent.agent_run_id, run_id);
        assert_eq!(parent.role, Role::Coordinator);
        assert_eq!(parent.ticket_run_id.as_ref(), Some(&ticket_run_id));
        assert_eq!(
            parent.ticket_revision.map(|revision| revision.0),
            Some(current_ticket_revision),
            "Coordinator child authority must bind to the current TicketRun revision"
        );
        assert_eq!(
            parent.role_session_id,
            format!("ticket_run:{ticket_run_id}:coordinator")
        );
        assert_eq!(
            crate::store::agent_results::host_validation_fixture::result_ack(
                &fixture.store,
                ingested.receipt.evidence_id(),
            )
            .unwrap(),
            Some((3, "applied".into()))
        );
    }

    #[test]
    fn plan_bound_planner_request_requires_the_exact_digest_before_persisting_a_wake() {
        use crate::domain::ids::{Digest, RepositoryId};
        use crate::engine::orchestration::{
            AgentAssertion, PlannedWorkNode, RoleOutputKind, WorkPlan,
        };
        use crate::roles::RoleResultMessage;
        use serde_json::json;

        let config: Config = serde_json::from_value(json!({
            "schema_version": 1,
            "adapters": {"tickets": {"kind": "command", "command": ["ticket-cli"]}},
            "projects": {"fixture-project": {
                "mode": "goal",
                "ticket_adapter": "tickets",
                "goal": {"revision": 1, "statement": "fixture goal", "acceptance": ["produce a valid plan"]},
                "roles": {"coordinator": "fixture-profile", "planner": "fixture-profile"}
            }}
        }))
        .unwrap();
        let configuration_digest = Digest::parse("a".repeat(64)).unwrap();

        for (case, requested_digest) in [("missing", None), ("wrong", Some("b".repeat(64)))] {
            let mut structured_result = json!({
                "work_node": "investigate",
                "role": "planner",
                "profile_id": "fixture-profile",
                "allowed_repositories": [],
                "artifact_inputs": [],
                "parent_run_id": null
            });
            if let Some(digest) = requested_digest {
                structured_result["plan_digest"] = json!(digest);
            }
            let result_digest = Digest::parse(format!(
                "{:x}",
                sha2::Sha256::digest(serde_json::to_vec(&structured_result).unwrap())
            ))
            .unwrap();
            let mut fixture =
                crate::store::agent_results::host_validation_fixture::host_validated_result(
                    Role::Coordinator,
                    RoleResultMessage {
                        schema_version: 1,
                        message_id: format!("coordinator-plan-request-{case}"),
                        kind: RoleOutputKind::SpawnRequest,
                        assertion: AgentAssertion::Succeeded,
                        structured_result,
                        result_digest: Some(result_digest),
                        artifact_refs: Vec::new(),
                    },
                )
                .unwrap();

            let persisted_plan = crate::store::accepted_plans::PersistedWorkPlan {
                schema_version: 1,
                proposal: WorkPlan {
                    nodes: vec![PlannedWorkNode {
                        id: crate::engine::orchestration::WorkNodeId::parse("investigate").unwrap(),
                        repository: RepositoryId::parse("repo-a").unwrap(),
                        task: "investigate the API contract".into(),
                        depends_on: Vec::new(),
                        required_evidence: vec!["API behavior".into()],
                        investigation: true,
                    }],
                    requested_investigation_children: 1,
                },
                observed_base_shas: BTreeMap::new(),
            };
            let plan_value = serde_json::to_value(persisted_plan).unwrap();
            let plan_json = serde_json::to_string(&plan_value).unwrap();
            let accepted_digest =
                Digest::parse(format!("{:x}", sha2::Sha256::digest(plan_json.as_bytes()))).unwrap();
            fixture
                .store
                .test_connection()
                .execute(
                    "INSERT INTO accepted_work_plans(project_id,ticket_run_id,accepted_revision,configuration_digest,plan_digest,plan_json,source_evidence_id,source_agent_run_id,source_message_id,source_result_digest,coordinator_agent_run_id,coordinator_role_session_id,coordinator_authority_digest,created_at_unix) VALUES ('fixture-project','fixture-ticket-run',3,?1,?2,?3,'plan-evidence','fixture-agent-run','plan-message',?4,'fixture-agent-run','ticket_run:fixture-ticket-run:coordinator',?4,1)",
                    rusqlite::params![configuration_digest.as_str(), accepted_digest.as_str(), plan_json, "c".repeat(64)],
                )
                .unwrap();
            let mut services = WorkerPublicationFixtureServices {
                configuration_digest: configuration_digest.clone(),
                published_effect: None,
                pending_artifacts: None,
                ticket_page: None,
                merge_observation: None,
                merge_observation_timeout: None,
                merge_observation_replies: None,
                merge_body_proposal: None,
                merge_work_document: None,
            };
            let wake_count_before: u32 = fixture
                .store
                .test_connection()
                .query_row("SELECT COUNT(*) FROM role_wake_inputs", [], |row| {
                    row.get(0)
                })
                .unwrap();

            assert!(
                super::apply_agent_result(
                    &mut fixture.store,
                    fixture.owner_generation,
                    10,
                    &config,
                    &mut services,
                    &fixture.ingested,
                )
                .is_err()
            );
            let wake_count: u32 = fixture
                .store
                .test_connection()
                .query_row("SELECT COUNT(*) FROM role_wake_inputs", [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(
                wake_count, wake_count_before,
                "{case} digest must not create a Planner wake"
            );
            assert_eq!(
                crate::store::agent_results::host_validation_fixture::result_ack(
                    &fixture.store,
                    fixture.ingested.receipt.evidence_id(),
                )
                .unwrap(),
                None,
                "{case} digest must not acknowledge the Coordinator result"
            );
        }
    }

    #[test]
    fn obsolete_host_validated_worker_result_is_acknowledged_without_publication() {
        use crate::domain::ids::Digest;
        use crate::engine::orchestration::{AgentAssertion, RoleOutputKind};
        use crate::roles::RoleResultMessage;
        use serde_json::json;

        let structured_result = json!({
            "change_references": [{
                "repository": "repo-a", "worktree_id": "node-a", "commit_mode": "native",
                "base_commit": "0000000000000000000000000000000000000000",
                "previous_head": "1111111111111111111111111111111111111111",
                "branch_head": "2222222222222222222222222222222222222222",
                "commit_shas": ["2222222222222222222222222222222222222222"]
            }],
            "completed_acceptance_items": ["tests pass"],
            "unresolved_items": [], "irregularity_references": []
        });
        let result_digest = Digest::parse(format!(
            "{:x}",
            sha2::Sha256::digest(serde_json::to_vec(&structured_result).unwrap())
        ))
        .unwrap();
        let mut fixture =
            crate::store::agent_results::host_validation_fixture::host_validated_result(
                Role::Worker,
                RoleResultMessage {
                    schema_version: 1,
                    message_id: "obsolete-config-worker-result".into(),
                    kind: RoleOutputKind::ImplementationReady,
                    assertion: AgentAssertion::Succeeded,
                    structured_result,
                    result_digest: Some(result_digest),
                    artifact_refs: Vec::new(),
                },
            )
            .unwrap();
        let current_digest = Digest::parse("b".repeat(64)).unwrap();
        let mut snapshot = fixture
            .store
            .load_snapshot("fixture")
            .unwrap()
            .unwrap()
            .config;
        let config: Config = serde_json::from_value(json!({
            "schema_version": 1,
            "adapters": {"tickets": {"kind": "command", "command": ["ticket-cli"]}},
            "projects": {"fixture-project": {
                "mode": "goal",
                "ticket_adapter": "tickets",
                "goal": {"revision": 1, "statement": "fixture goal", "acceptance": ["resume the ticket"]},
                "roles": {"supervisor": "fixture-profile", "coordinator": "fixture-profile"}
            }}
        }))
        .unwrap();
        let profile: crate::config::Profile = serde_json::from_value(json!({
            "adapter": "codex", "command": ["/bin/codex"], "model": "fixture",
            "commit_mode": "native", "turn_timeout_seconds": 60
        }))
        .unwrap();
        let profile_digest = Digest::parse(format!(
            "{:x}",
            sha2::Sha256::digest(crate::store::canonical_json(&profile).unwrap().as_bytes())
        ))
        .unwrap();
        snapshot.config = config.clone();
        snapshot.profiles = std::collections::BTreeMap::from([(
            crate::domain::ids::ProfileId::parse("fixture-profile").unwrap(),
            profile,
        )]);
        snapshot.digest = current_digest.clone();
        let applied = fixture
            .store
            .apply_snapshot(
                "fixture",
                &snapshot,
                crate::store::ExpectedRevision::Current(crate::domain::ids::Revision(1)),
            )
            .unwrap();
        assert_eq!(applied.revision.0, 2);
        let project_id = crate::domain::ids::ProjectId::parse("fixture-project").unwrap();
        let ticket_run = crate::domain::ids::TicketRunId::parse("fixture-ticket-run").unwrap();
        let coordinator_session = format!("ticket_run:{ticket_run}:coordinator");
        fixture
            .store
            .set_project_lifecycle(fixture.owner_generation, &project_id, "running")
            .unwrap();

        for index in 0..33 {
            let ticket_run_id =
                crate::domain::ids::TicketRunId::parse(format!("terminal-starvation-{index:02}"))
                    .unwrap();
            fixture
                .store
                .create_ticket_run(
                    fixture.owner_generation,
                    &project_id,
                    &crate::domain::ids::TicketNamespace::parse("fixture").unwrap(),
                    &crate::domain::ids::TicketId::parse(format!("TERMINAL-{index:02}")).unwrap(),
                    &ticket_run_id,
                    1,
                    if index == 32 { "canceled" } else { "done" },
                    if index == 32 { "canceled" } else { "done" },
                )
                .unwrap();
            let role_session_id = if index == 1 {
                format!("ticket:{ticket_run_id}:worker:node-a")
            } else {
                format!("ticket_run:{ticket_run_id}:coordinator")
            };
            fixture
                .store
                .test_connection()
                .execute(
                    "INSERT INTO role_wake_inputs(project_id,role_session_id,source_type,source_id,source_revision,priority,payload_json,lifecycle,created_at_unix) VALUES (?1,?2,'ticket_run_transition',?3,1,100,'{}','pending',1)",
                    rusqlite::params![project_id.as_str(), role_session_id, ticket_run_id.as_str()],
                )
                .unwrap();
        }
        let existing_qualification_json: String = fixture
            .store
            .test_connection()
            .query_row(
                "SELECT receipt_json FROM provider_qualifications WHERE project_id='fixture-project' AND profile_id='fixture-profile' ORDER BY created_at_unix LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let mut qualification: crate::launch::ProviderQualification =
            crate::protocol::parse_unique(existing_qualification_json.as_bytes()).unwrap();
        qualification.profile_digest = profile_digest.clone();
        let qualification_digest = fixture
            .store
            .store_provider_qualification(fixture.owner_generation, &qualification)
            .unwrap();
        let mut services = WorkerPublicationFixtureServices {
            configuration_digest: current_digest.clone(),
            published_effect: None,
            pending_artifacts: None,
            ticket_page: None,
            merge_observation: None,
            merge_observation_timeout: None,
            merge_observation_replies: None,
            merge_body_proposal: None,
            merge_work_document: None,
        };

        assert!(
            super::apply_agent_result(
                &mut fixture.store,
                fixture.owner_generation,
                10,
                &config,
                &mut services,
                &fixture.ingested
            )
            .unwrap()
        );
        assert!(services.published_effect.is_none());
        let ack = crate::store::agent_results::host_validation_fixture::result_ack(
            &fixture.store,
            fixture.ingested.receipt.evidence_id(),
        )
        .unwrap();
        assert_eq!(ack, Some((4, "rejected_by_host".into())));
        assert!(
            super::apply_agent_result(
                &mut fixture.store,
                fixture.owner_generation,
                10,
                &config,
                &mut services,
                &fixture.ingested
            )
            .unwrap()
        );
        assert_eq!(
            crate::store::agent_results::host_validation_fixture::result_ack(
                &fixture.store,
                fixture.ingested.receipt.evidence_id()
            )
            .unwrap(),
            Some((4, "rejected_by_host".into()))
        );

        let project = project_id.clone();
        let pending_wakes = fixture
            .store
            .pending_role_wake_inputs(&project, &coordinator_session, 256)
            .unwrap();
        assert_eq!(pending_wakes.len(), 1);
        assert_eq!(pending_wakes[0].source_type, "agent_result");
        assert_eq!(
            pending_wakes[0].source_id,
            fixture.ingested.receipt.evidence_id()
        );
        assert!(
            fixture
                .store
                .pending_role_wake_sessions(fixture.owner_generation, 32)
                .unwrap()
                .is_empty()
        );
        let launch_candidate = fixture
            .store
            .pending_role_wake_sessions(fixture.owner_generation, 32)
            .unwrap()
            .into_iter()
            .find(|candidate| candidate.role_session_id == coordinator_session)
            .expect("the runnable Coordinator survives the bounded terminal-wake drain");
        assert_eq!(launch_candidate.role, Role::Coordinator);
        assert_eq!(launch_candidate.ticket_run_id.as_ref(), Some(&ticket_run));
        let retired_terminal_wakes: u64 = fixture
            .store
            .test_connection()
            .query_row(
                "SELECT COUNT(*) FROM role_wake_inputs WHERE source_type='ticket_run_transition' AND lifecycle='superseded'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(retired_terminal_wakes, 33);

        let supervisor_view_id = crate::launch::RexView::derive_id(
            &project,
            crate::launch::RexViewKind::Supervisor,
            None,
            None,
            1,
        )
        .unwrap();
        fixture
            .store
            .register_rex_view(
                fixture.owner_generation,
                &crate::launch::RexView {
                    view_id: supervisor_view_id.clone(),
                    project_id: project.clone(),
                    kind: crate::launch::RexViewKind::Supervisor,
                    ticket_namespace: None,
                    ticket_id: None,
                    view_epoch: 1,
                    rex_server_identity: "fixture-rex".into(),
                    rex_session_id: "fixture-supervisor-session".into(),
                    rex_window_id: "fixture-supervisor-window".into(),
                },
            )
            .unwrap();

        // The pre-existing Supervisor is a fixture prerecord; register its typed authority
        // through the production verifier so the replan has a valid parent lineage.
        let supervisor_run_id =
            crate::domain::ids::AgentRunId::parse("fixture-supervisor-run").unwrap();
        let supervisor_operation =
            crate::domain::ids::OperationId::parse("fixture-supervisor-operation").unwrap();
        let supervisor_session = format!("project:{project}:supervisor");
        fixture
            .store
            .test_connection()
            .execute(
                "INSERT INTO agent_runs(agent_run_id,project_id,config_source,config_revision,config_digest,role_session_id,role,logical_owner,finite_turn,launch_operation_id,state,controller_generation) VALUES (?1,?2,'fixture',?3,?4,?5,'supervisor','fixture-owner',1,?6,'launch_pending',?7)",
                rusqlite::params![
                    supervisor_run_id.as_str(), project.as_str(), applied.revision.0,
                    current_digest.as_str(), supervisor_session, supervisor_operation.as_str(),
                    fixture.owner_generation
                ],
            )
            .unwrap();
        let supervisor_control = fixture._temp.path().join("supervisor-control");
        std::fs::create_dir(&supervisor_control).unwrap();
        let supervisor_mailbox_digest = Digest::parse("c".repeat(64)).unwrap();
        fixture
            .store
            .test_connection()
            .execute(
                "INSERT INTO agent_mailboxes(agent_run_id,canonical_directory,capability_digest,expires_at_unix,max_request_bytes,max_pending_requests) VALUES (?1,?2,?3,9999999999,1048576,32)",
                rusqlite::params![
                    supervisor_run_id.as_str(), supervisor_control.display().to_string(),
                    supervisor_mailbox_digest.as_str()
                ],
            )
            .unwrap();
        let supervisor_authority = crate::launch::AgentLaunchAuthority {
            agent_run_id: supervisor_run_id.clone(),
            project_id: project.clone(),
            role: Role::Supervisor,
            role_session_id: supervisor_session,
            parent_run_id: None,
            parent_role: None,
            ticket_run_id: None,
            ticket_revision: None,
            config_revision: applied.revision,
            config_digest: current_digest.clone(),
            attempt: 1,
            run_epoch: 1,
            controller_generation: fixture.owner_generation,
            operation_id: supervisor_operation,
            operation_recipe_id: None,
            rex_view_id: supervisor_view_id,
            descriptor_digest: Digest::parse("d".repeat(64)).unwrap(),
            runtime_binary_digest: Digest::parse("e".repeat(64)).unwrap(),
            descriptor_path: fixture._temp.path().join("supervisor-package.json"),
            environment_snapshot_id: Digest::parse("f".repeat(64)).unwrap(),
            profile_id: crate::domain::ids::ProfileId::parse("fixture-profile").unwrap(),
            profile_digest: profile_digest.clone(),
            instruction_digest: Digest::parse("1".repeat(64)).unwrap(),
            result_schema_digest: Digest::parse("2".repeat(64)).unwrap(),
            wake_snapshot_digest: Digest::parse("3".repeat(64)).unwrap(),
            qualification_receipt_digest: qualification_digest.clone(),
            rex_server_identity: "fixture-rex".into(),
            rex_session_id: "fixture-supervisor-session".into(),
            rex_window_id: "fixture-supervisor-window".into(),
            rex_block_id: "fixture-supervisor-block".into(),
            workspace_path: fixture._temp.path().join("supervisor-workspace"),
            control_dir: supervisor_control,
            mailbox_capability_digest: supervisor_mailbox_digest,
        };
        fixture
            .store
            .register_agent_launch_authority(fixture.owner_generation, &supervisor_authority)
            .unwrap();
        fixture
            .store
            .test_connection()
            .execute(
                "UPDATE agent_runs SET state='running' WHERE agent_run_id=?1",
                [supervisor_run_id.as_str()],
            )
            .unwrap();

        let worker_authority = fixture
            .store
            .agent_launch_authority(
                &crate::domain::ids::AgentRunId::parse("fixture-agent-run").unwrap(),
            )
            .unwrap()
            .unwrap();
        let original_coordinator_id =
            crate::domain::ids::AgentRunId::parse("fixture-parent-run").unwrap();
        assert_eq!(
            worker_authority.parent_run_id,
            Some(original_coordinator_id.clone())
        );
        assert_eq!(worker_authority.parent_role, Some(Role::Coordinator));
        let original_coordinator = fixture
            .store
            .agent_launch_authority(&original_coordinator_id)
            .unwrap()
            .unwrap();
        assert_eq!(original_coordinator.role, Role::Coordinator);
        assert_eq!(original_coordinator.role_session_id, coordinator_session);
        let view_id = worker_authority.rex_view_id.clone();
        let wake_run_id =
            crate::domain::ids::AgentRunId::parse("fixture-coordinator-replan").unwrap();
        let wake_items = pending_wakes
            .iter()
            .map(|wake| crate::agent_api::AgentWakeItem {
                wake_input_id: wake.wake_input_id,
                source_type: wake.source_type.clone(),
                source_id: wake.source_id.clone(),
                source_revision: wake.source_revision,
                priority: wake.priority,
                payload_json: wake.payload_json.clone(),
                host_artifact_source_evidence_ids: Vec::new(),
                host_artifacts: Vec::new(),
                host_completion_context: None,
            })
            .collect();
        let mut wake_snapshot = crate::agent_api::AgentWakeSnapshot {
            schema_version: 1,
            project_id: project.clone(),
            role_session_id: coordinator_session.clone(),
            agent_run_id: wake_run_id.as_str().into(),
            digest: Digest::parse("0".repeat(64)).unwrap(),
            inputs: wake_items,

            worker_correction_context: None,
        };
        wake_snapshot.digest = wake_snapshot.content_digest().unwrap();
        let workspace = fixture._temp.path().join("coordinator-replan-workspace");
        let control = fixture._temp.path().join("coordinator-replan-control");
        std::fs::create_dir(&workspace).unwrap();
        std::fs::create_dir(&control).unwrap();
        let runnable = fixture
            .store
            .runnable_projects(fixture.owner_generation)
            .unwrap()
            .into_iter()
            .find(|item| item.record.id == project)
            .unwrap();
        assert_eq!(runnable.record.config_revision, applied.revision);
        assert_eq!(runnable.record.config_digest, current_digest);
        let reservation = crate::launch::AgentLaunchReservation {
            schema_version: crate::launch::LAUNCH_SCHEMA_VERSION,
            agent_run_id: wake_run_id.clone(),
            project_id: project.clone(),
            role: Role::Coordinator,
            role_session_id: launch_candidate.role_session_id.clone(),
            parent_run_id: Some(supervisor_run_id.clone()),
            parent_role: Some(Role::Supervisor),
            ticket_run_id: Some(ticket_run.clone()),
            ticket_revision: Some(crate::domain::ids::Revision(4)),
            config_revision: applied.revision,
            config_digest: current_digest.clone(),
            attempt: 1,
            run_epoch: 2,
            controller_generation: fixture.owner_generation,
            project_epoch: runnable.project_epoch,
            operation_id: crate::domain::ids::OperationId::parse("fixture-coordinator-replan-op")
                .unwrap(),
            operation_recipe_id: None,
            worker_assignment: None,
            rex_view_id: view_id.clone(),
            runtime_binary_digest: Digest::parse("4".repeat(64)).unwrap(),
            environment_snapshot_id: Digest::parse("5".repeat(64)).unwrap(),
            profile_id: crate::domain::ids::ProfileId::parse("fixture-profile").unwrap(),
            profile_digest: profile_digest.clone(),
            instruction_digest: Digest::parse("6".repeat(64)).unwrap(),
            result_schema_digest: Digest::parse("7".repeat(64)).unwrap(),
            wake_snapshot: wake_snapshot.clone(),
            qualification_receipt_digest: qualification_digest.clone(),
            descriptor_path: fixture._temp.path().join("coordinator-replan-package.json"),
            workspace_path: workspace.clone(),
            control_dir: control.clone(),
            mailbox_directory: control,
            mailbox_capability_digest: Digest::parse("8".repeat(64)).unwrap(),
            mailbox_expires_at_unix: 9_999_999_999,
            mailbox_max_request_bytes: 1_048_576,
            mailbox_max_pending_requests: 32,
            pool: "agent".into(),
            slot_index: 0,
            global_capacity: 4,
            project_capacity: 4,
        };
        let reservation_digest = reservation.digest().unwrap();
        assert!(matches!(
            fixture.store.prepare_role_launch(&reservation).unwrap(),
            crate::store::agent_runtime::LaunchPreparationOutcome::Prepared { .. }
        ));
        assert_eq!(
            fixture
                .store
                .test_connection()
                .query_row(
                    "SELECT lifecycle FROM role_wake_inputs WHERE project_id=?1 AND role_session_id=?2 AND source_type='agent_result'",
                    rusqlite::params![project.as_str(), coordinator_session],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "assigned",
            "the real launch reservation assigns the selected wake"
        );
        assert_eq!(
            fixture
                .store
                .agent_launch_reservation(&wake_run_id, &reservation_digest)
                .unwrap(),
            Some(reservation.clone())
        );
        assert_eq!(
            fixture
                .store
                .verified_provider_qualifications(
                    &project,
                    &reservation.profile_id,
                    &reservation.profile_digest,
                    4,
                )
                .unwrap(),
            vec![qualification.clone()]
        );
        let authority = crate::launch::AgentLaunchAuthority {
            agent_run_id: wake_run_id.clone(),
            project_id: project.clone(),
            role: Role::Coordinator,
            role_session_id: coordinator_session.clone(),
            parent_run_id: reservation.parent_run_id.clone(),
            parent_role: reservation.parent_role,
            ticket_run_id: Some(ticket_run.clone()),
            ticket_revision: reservation.ticket_revision,
            config_revision: reservation.config_revision,
            config_digest: reservation.config_digest.clone(),
            attempt: reservation.attempt,
            run_epoch: reservation.run_epoch,
            controller_generation: reservation.controller_generation,
            operation_id: reservation.operation_id.clone(),
            operation_recipe_id: reservation.operation_recipe_id.clone(),
            rex_view_id: reservation.rex_view_id.clone(),
            descriptor_digest: Digest::parse("9".repeat(64)).unwrap(),
            runtime_binary_digest: reservation.runtime_binary_digest.clone(),
            descriptor_path: reservation.descriptor_path.clone(),
            environment_snapshot_id: reservation.environment_snapshot_id.clone(),
            profile_id: reservation.profile_id.clone(),
            profile_digest: reservation.profile_digest.clone(),
            instruction_digest: reservation.instruction_digest.clone(),
            result_schema_digest: reservation.result_schema_digest.clone(),
            wake_snapshot_digest: wake_snapshot.digest.clone(),
            qualification_receipt_digest: reservation.qualification_receipt_digest.clone(),
            rex_server_identity: worker_authority.rex_server_identity,
            rex_session_id: worker_authority.rex_session_id,
            rex_window_id: worker_authority.rex_window_id,
            rex_block_id: "fixture-coordinator-replan-block".into(),
            workspace_path: reservation.workspace_path.clone(),
            control_dir: reservation.control_dir.clone(),
            mailbox_capability_digest: reservation.mailbox_capability_digest.clone(),
        };
        fixture
            .store
            .register_agent_launch_authority(fixture.owner_generation, &authority)
            .unwrap();
        fixture
            .store
            .register_rex_view_block(
                fixture.owner_generation,
                &crate::launch::RexViewBlock {
                    view_id: reservation.rex_view_id.clone(),
                    block_id: authority.rex_block_id.clone(),
                    agent_run_id: Some(wake_run_id.clone()),
                    role: Some(Role::Coordinator),
                    ownership: crate::launch::RexBlockOwnership::Factory,
                    lifecycle: crate::launch::RexBlockLifecycle::Active,
                    process_absent_confirmed: false,
                    retained_until_unix: None,
                },
            )
            .unwrap();
        fixture
            .store
            .finalize_agent_launch_reservation(
                fixture.owner_generation,
                &wake_run_id,
                &reservation_digest,
                &authority,
            )
            .unwrap();
        let (persisted_wake_digest, persisted_wake_json): (String, String) = fixture
            .store
            .test_connection()
            .query_row(
                "SELECT snapshot_digest,snapshot_json FROM agent_wake_context WHERE agent_run_id=?1",
                [wake_run_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let persisted_wake: crate::agent_api::AgentWakeSnapshot =
            crate::protocol::parse_unique(persisted_wake_json.as_bytes()).unwrap();
        assert_eq!(persisted_wake_digest, wake_snapshot.digest.as_str());
        assert_eq!(persisted_wake, wake_snapshot);
        assert!(matches!(
            fixture.store.prepare_role_launch(&reservation).unwrap(),
            crate::store::agent_runtime::LaunchPreparationOutcome::Prepared { .. }
        ));
        assert_eq!(
            fixture
                .store
                .agent_launch_reservation(&wake_run_id, &reservation_digest)
                .unwrap(),
            Some(reservation)
        );
        assert_eq!(
            fixture
                .store
                .test_connection()
                .query_row(
                    "SELECT count(*) FROM agent_result_wakes WHERE evidence_id=?1",
                    [fixture.ingested.receipt.evidence_id()],
                    |row| row.get::<_, u64>(0),
                )
                .unwrap(),
            1,
            "replaying the rejected result must not add a duplicate Coordinator wake"
        );
        assert_eq!(
            fixture
                .store
                .test_connection()
                .query_row(
                    "SELECT count(*) FROM agent_runs WHERE role_session_id=?1 AND role='coordinator'",
                    [&coordinator_session],
                    |row| row.get::<_, u64>(0),
                )
                .unwrap(),
            2,
            "result replay must not reserve another Coordinator AgentRun"
        );
        assert_eq!(
            fixture
                .store
                .test_connection()
                .query_row(
                    "SELECT revision FROM ticket_runs WHERE ticket_run_id=?1",
                    [ticket_run.as_str()],
                    |row| row.get::<_, u64>(0),
                )
                .unwrap(),
            4,
            "replanning must keep the TicketRun revision bound by the Worker result"
        );
    }

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
    fn reviewer_corrections_stop_at_the_configured_round_limit() {
        use super::review_transition;
        use crate::engine::orchestration::{ReviewDisposition, ReviewProgress, review_disposition};
        use crate::engine::reducer::Input;

        let before_limit = review_disposition(
            ReviewProgress {
                completed_rounds: 2,
                maximum_rounds: 3,
            },
            true,
        )
        .unwrap();
        assert_eq!(
            review_transition(before_limit),
            (Input::CorrectionsRemain, "corrections_remain")
        );

        let at_limit = review_disposition(
            ReviewProgress {
                completed_rounds: 3,
                maximum_rounds: 3,
            },
            true,
        )
        .unwrap();
        assert_eq!(at_limit, ReviewDisposition::HumanRequiredAtRoundLimit);
        assert_eq!(
            review_transition(at_limit),
            (
                Input::ReviewEscalationRequired,
                "review_round_limit_reached"
            )
        );
    }

    #[test]
    fn reviewer_disposition_cannot_override_unknowns_or_claim_convergence() {
        use super::{review_assessment_transition, reviewer_result_allowed};
        use crate::engine::orchestration::ReviewProgress;
        use crate::engine::reducer::Activity;
        use crate::engine::reducer::Input;

        let progress = ReviewProgress {
            completed_rounds: 0,
            maximum_rounds: 3,
        };
        assert_eq!(
            review_assessment_transition("approved", false, progress).unwrap(),
            (Input::ReviewConverged, "review_converged")
        );
        assert_eq!(
            review_assessment_transition("approved", true, progress).unwrap(),
            (Input::CorrectionsRemain, "corrections_remain")
        );
        assert_eq!(
            review_assessment_transition("changes_requested", false, progress).unwrap(),
            (Input::ReviewEscalationRequired, "review_requires_human")
        );
        assert_eq!(
            review_assessment_transition("rejected", false, progress).unwrap(),
            (
                Input::ReviewEscalationRequired,
                "review_disposition_unrecognized"
            )
        );
        assert!(reviewer_result_allowed(Phase::Reviewing, Activity::Running));
        assert!(!reviewer_result_allowed(
            Phase::Reviewing,
            Activity::Blocked
        ));
        assert!(!reviewer_result_allowed(
            Phase::Assessing,
            Activity::Running
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
        let GoalSupervisorAction::Create(prepared) = bound_goal_supervisor_action(
            &ProjectId::parse("goal_project").unwrap(),
            goal_project,
            0,
            19,
            false,
            &proposals,
        )
        .unwrap() else {
            panic!("the available Goal budget should admit one proposal");
        };
        let canonical = canonical_goal_ticket_proposal(
            &ProjectId::parse("goal_project").unwrap(),
            goal_project.goal.as_ref().unwrap().revision,
            &prepared[0].proposal.title,
            &prepared[0].proposal.body,
            &prepared[0].proposal.labels,
        )
        .unwrap();
        let canonical_json =
            serde_json::to_string(&serde_json::to_value(&canonical).unwrap()).unwrap();
        let expected_digest = format!("{:x}", sha2::Sha256::digest(canonical_json.as_bytes()));
        assert_eq!(prepared[0].request_digest, expected_digest);
        assert_eq!(prepared[0].request_key, format!("goal-{expected_digest}"));
        crate::engine::ticket_effects::CreateGoalTicket {
            schema_version: 1,
            project_id: ProjectId::parse("goal_project").unwrap(),
            namespace: TicketNamespace::parse("fixture:workspace").unwrap(),
            goal_revision: goal_project.goal.as_ref().unwrap().revision,
            request_key: prepared[0].request_key.clone(),
            request_digest: Digest::parse(prepared[0].request_digest.clone()).unwrap(),
            proposal: canonical,
            request: crate::engine::ticket_effects::TicketCreationRequest {
                scope: BTreeMap::from([("project".into(), "fixture".into())]),
                creation_key: prepared[0].request_key.clone(),
                title: prepared[0].proposal.title.clone(),
                body: prepared[0].proposal.body.clone(),
                status: Some(TicketStatus::Ready),
                template: None,
                parent: None,
                dependencies: None,
                project: None,
                milestone: None,
                assignee: None,
                priority: None,
                due_date: None,
                labels: Some(Vec::new()),
            },
        }
        .validate()
        .unwrap();
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

    #[test]
    fn coordinator_clarification_result_creates_durable_presentation_and_acknowledges_claim() {
        use super::ExternalTicketPage;
        use super::{FactoryRuntimeServices, apply_agent_result};
        use crate::agent_recovery::AgentRecoveryReport;
        use crate::domain::ids::{
            AdapterId, AgentRunId, Digest, OperationId, ProjectId, Revision, TicketNamespace,
            TicketRunId,
        };
        use crate::domain::types::Role;
        use crate::effects::EffectHandler;
        use crate::engine::orchestration::{
            AgentAssertion, HumanRequestPayload, RoleOutputKind, RoleResultBinding,
            RoleResultPayload, RoleSessionId, ValidatedRoleResult,
        };
        use crate::human_runtime::HumanPresentationEffect;
        use crate::launch::{RexView, RexViewKind};
        use crate::runtime_delivery::PublicationMonitorTick;
        use crate::store::agent_results::{IngestedAgentResult, StoredRoleResultReceipt};
        use crate::store::scheduler::TicketScanKey;
        use crate::store::{ConfigStore, ExpectedRevision, OwnerMetadata, ProjectRecord};
        use std::path::Path;
        use tempfile::tempdir;

        struct Services(Digest);
        impl FactoryRuntimeServices for Services {
            fn recover_agents(
                &mut self,
                _: &mut ConfigStore,
                _: u64,
                _: i64,
            ) -> Result<AgentRecoveryReport, String> {
                Err("unused".into())
            }
            fn ingest_one_agent_result(
                &mut self,
                _: &mut ConfigStore,
                _: u64,
                _: i64,
            ) -> Result<Option<IngestedAgentResult>, String> {
                Err("unused".into())
            }
            fn process_one_agent_request(
                &mut self,
                _: &mut ConfigStore,
                _: u64,
                _: i64,
            ) -> Result<bool, String> {
                Err("unused".into())
            }
            fn observe_base_heads(
                &mut self,
            ) -> Result<std::collections::BTreeMap<crate::domain::ids::RepositoryId, String>, String>
            {
                Err("unused".into())
            }
            fn configuration_digest(&self) -> &Digest {
                &self.0
            }
            fn read_verified_artifact(
                &self,
                _: &crate::store::artifact_registry::VerifiedArtifact,
            ) -> Result<Vec<u8>, String> {
                Err("unused".into())
            }
            fn profile_commit_mode(
                &self,
                _: &ProjectId,
                _: Role,
            ) -> Result<crate::domain::types::CommitMode, String> {
                Err("unused".into())
            }
            fn tick_profile_trials(
                &mut self,
                _: &mut ConfigStore,
                _: u64,
                _: i64,
                _: u32,
                _: u32,
            ) -> Result<(), String> {
                Err("unused".into())
            }
            fn ticket_namespace(&mut self, _: &AdapterId) -> Result<TicketNamespace, String> {
                Err("unused".into())
            }
            fn list_ticket_page(
                &mut self,
                _: &TicketScanKey,
                _: Option<&str>,
                _: usize,
            ) -> Result<ExternalTicketPage, String> {
                Err("unused".into())
            }
            fn observe_publications(
                &mut self,
                _: &mut ConfigStore,
                _: u64,
                _: i64,
            ) -> Result<PublicationMonitorTick, String> {
                Err("unused".into())
            }
            fn prepare_role_launch(
                &mut self,
                _: &mut ConfigStore,
                _: u64,
                _: &Config,
                _: &super::PendingRoleWakeSession,
                _: i64,
            ) -> Result<bool, String> {
                Err("unused".into())
            }
            fn worker_publication_effect(
                &mut self,
                _: &mut ConfigStore,
                _: u64,
                _: &Config,
                _: &crate::store::scheduler::ActiveTicketRun,
                _: &IngestedAgentResult,
                _: u64,
            ) -> Result<Option<crate::store::EffectIntent>, String> {
                Err("unused".into())
            }
            fn effect_handlers(&self) -> Vec<&dyn EffectHandler> {
                Vec::new()
            }
        }

        let temp = tempdir().unwrap();
        let loaded = crate::config::load(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/fixture/config.toml"),
        )
        .unwrap();
        let config = loaded.config.clone();
        let project_id = ProjectId::parse("operations_project").unwrap();
        let mut store = ConfigStore::open_test(temp.path()).unwrap();
        let applied = store
            .apply_snapshot("fixture", &loaded, ExpectedRevision::Bootstrap)
            .unwrap();
        store
            .insert_project(&ProjectRecord {
                id: project_id.clone(),
                config_source: "fixture".into(),
                config_revision: applied.revision,
                config_digest: loaded.digest.clone(),
                mode: "goal".into(),
                goal_revision: 1,
                desired_lifecycle: "running".into(),
                state_revision: Revision(0),
            })
            .unwrap();
        let ticket_run_id = TicketRunId::parse("clarify-run").unwrap();
        store.test_connection().execute(
            "INSERT INTO ticket_runs(ticket_run_id,project_id,config_source,config_revision,config_digest,namespace,ticket_id,generation,internal_phase,activity,external_status,observed_status,revision,required_review_revision) VALUES (?1,?2,'fixture',?3,?4,'github:org/repo','T-42',1,'queued','ready','in_progress','in_progress',1,NULL)",
            rusqlite::params![ticket_run_id.as_str(), project_id.as_str(), applied.revision.0, loaded.digest.as_str()],
        ).unwrap();
        let owner_generation = store
            .start_owner(&OwnerMetadata {
                owner_nonce: "clarification-test-owner".into(),
                state_root: temp.path().to_string_lossy().into_owned(),
                config_source: "fixture".into(),
                process_start_identity: "test-start".into(),
                executable_path: "/tmp/rex-projects-test".into(),
                executable_digest: "e".repeat(64),
                rex_endpoint: None,
                rex_server_identity: None,
                rex_session_id: None,
                rex_block_id: None,
            })
            .unwrap();
        store.test_connection().execute(
            "UPDATE project_runtimes SET observed_lifecycle='running',controller_generation=?2 WHERE project_id=?1",
            rusqlite::params![project_id.as_str(), owner_generation],
        ).unwrap();
        store.test_connection().execute(
            "INSERT INTO ticket_run_context(ticket_run_id,project_id,project_epoch,recipe_id,goal_revision,created_at_unix) VALUES (?1,?2,1,'docs_only',1,1)",
            rusqlite::params![ticket_run_id.as_str(), project_id.as_str()],
        ).unwrap();
        let view = RexView {
            view_id: RexView::derive_id(
                &project_id,
                RexViewKind::Ticket,
                Some("github:org/repo"),
                Some("T-42"),
                1,
            )
            .unwrap(),
            project_id: project_id.clone(),
            kind: RexViewKind::Ticket,
            ticket_namespace: Some("github:org/repo".into()),
            ticket_id: Some("T-42".into()),
            view_epoch: 1,
            rex_server_identity: "server".into(),
            rex_session_id: "session".into(),
            rex_window_id: "ticket-window".into(),
        };
        store.register_rex_view(owner_generation, &view).unwrap();

        // This test exercises the host consumer boundary; the evidence row is seeded as if the
        // normal ingestion path had already committed it. The typed result remains immutable.
        store
            .test_connection()
            .execute_batch("PRAGMA foreign_keys=OFF")
            .unwrap();
        store.test_connection().execute(
            "INSERT INTO agent_result_evidence(evidence_id,agent_run_id,project_id,role,ticket_run_id,attempt,run_epoch,message_id,content_digest,outcome,result_digest,result_json,artifact_refs_json,received_at_unix) VALUES ('evidence-clarify','agent-clarify',?1,'coordinator',?2,1,1,'message-clarify',?3,'completed',?4,'{}','[]',1)",
            rusqlite::params![project_id.as_str(), ticket_run_id.as_str(), "a".repeat(64), "b".repeat(64)],
        ).unwrap();
        store
            .test_connection()
            .execute_batch("PRAGMA foreign_keys=ON")
            .unwrap();

        let payload = HumanRequestPayload {
            kind: "clarification".into(),
            question: "Which release window should we use?".into(),
            choices: vec!["weekday".into(), "weekend".into()],
            evidence_references: Vec::new(),
            subject_digest: Digest::parse("c".repeat(64)).unwrap(),
            requested_continuation: Some("continue implementation".into()),
        };
        let binding = RoleResultBinding {
            agent_run_id: AgentRunId::parse("agent-clarify").unwrap(),
            operation_id: OperationId::parse("op-clarify").unwrap(),
            project_id: project_id.clone(),
            role_session_id: RoleSessionId::parse("coordinator-session").unwrap(),
            role: Role::Coordinator,
            parent_run_id: Some(AgentRunId::parse("supervisor-run").unwrap()),
            parent_role: Some(Role::Supervisor),
            ticket_run_id: Some(ticket_run_id.clone()),
            ticket_revision: Some(Revision(1)),
            config_revision: applied.revision,
            config_digest: loaded.digest.clone(),
            profile_digest: Digest::parse("d".repeat(64)).unwrap(),
            instruction_digest: Digest::parse("e".repeat(64)).unwrap(),
            provider_capability_receipt_digest: Digest::parse("f".repeat(64)).unwrap(),
            result_schema_digest: Digest::parse("1".repeat(64)).unwrap(),
            controller_generation: owner_generation,
            run_epoch: 1,
            attempt: 1,
        };
        let structured_result = serde_json::to_value(&payload).unwrap();
        let result = IngestedAgentResult {
            validated: ValidatedRoleResult {
                binding,
                message_id: "message-clarify".into(),
                kind: RoleOutputKind::HumanRequest,
                assertion: AgentAssertion::Succeeded,
                structured_result,
                typed_payload: RoleResultPayload::HumanRequest(payload),
                result_digest: Digest::parse("b".repeat(64)).unwrap(),
                claimed_artifact_refs: Vec::new(),
                wake_recipients: Vec::new(),
            },
            receipt: StoredRoleResultReceipt::test_receipt("evidence-clarify"),
            verified_artifacts: Vec::new(),
        };
        let mut services = Services(loaded.digest.clone());
        assert!(
            apply_agent_result(
                &mut store,
                owner_generation,
                50,
                &config,
                &mut services,
                &result
            )
            .unwrap()
        );
        let ack: (u64, String) = store.test_connection().query_row(
            "SELECT reducer_revision,disposition FROM agent_result_reducer_ack WHERE evidence_id='evidence-clarify'", [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).unwrap();
        assert_eq!(ack, (1, "retained_as_claim".into()));
        let effect_json: String = store
            .test_connection()
            .query_row(
                "SELECT request_json FROM effects WHERE kind='request_human_review'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let effect: HumanPresentationEffect = serde_json::from_str(&effect_json).unwrap();
        assert_eq!(
            effect.request.purpose,
            crate::human_runtime::HumanPurpose::CoordinatorClarification
        );
        assert_eq!(effect.request.subject.ticket_run_id, Some(ticket_run_id));
        assert_eq!(
            effect.request.question,
            "Which release window should we use?"
        );
        let status: String = store
            .test_connection()
            .query_row(
                "SELECT external_status FROM ticket_runs WHERE ticket_run_id='clarify-run'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(status, "in_progress");
    }
}
