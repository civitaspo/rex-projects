//! Construction of host-owned repository delivery adapters from applied configuration.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::config::{AppliedConfig, RepositoryConfig};
use crate::delivery_forge::validate_github_clone_url;
use crate::delivery_runtime::{RepositoryDeliveryEffectConfig, RepositoryDeliveryEffects};
use crate::domain::ids::{ProjectId, RepositoryId};
use crate::effects::EffectHandler;
use crate::host_jobs::{HostJobEnvironmentBinding, HostJobPool};
use crate::process::{self, ProcessRequest, resolve_executable};
use crate::worktrees::GitOptions;

const GIT_TIMEOUT: Duration = Duration::from_secs(120);
const GH_TIMEOUT: Duration = Duration::from_secs(120);
const TOOL_SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

#[cfg(test)]
mod adoption_tests;

/// Repository effect handlers and the observer used to detect out-of-band publication.
pub struct RuntimeDelivery {
    applied_config: AppliedConfig,
    handlers: Vec<Box<dyn EffectHandler>>,
    effects: std::sync::Arc<RepositoryDeliveryEffects>,
    host_jobs: Arc<Mutex<HostJobPool>>,
    git_executable: PathBuf,
    git_environment: BTreeMap<OsString, OsString>,
    repositories: BTreeMap<RepositoryId, RepositoryConfig>,
    configuration_digest: crate::domain::ids::Digest,
    publication_cursor: std::sync::atomic::AtomicUsize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublicationMonitorTick {
    Idle,
    EffectReconciling,
    Unknown,
    Unchanged,
    BaselineAdvanced { revision: u64 },
    IrregularityRecorded { revision: u64 },
    HumanReviewPending { request_id: String },
    HumanReviewApplied { revision: u64 },
}

struct RuntimePublicationAdoptionSource {
    effects: Arc<RepositoryDeliveryEffects>,
    repositories: BTreeMap<RepositoryId, RepositoryConfig>,
}

impl crate::human_runtime::PublicationAdoptionSource for RuntimePublicationAdoptionSource {
    fn observe_publication(
        &self,
        resource: &crate::store::publication_monitor::PublicationResource,
    ) -> Result<Option<crate::delivery_runtime::RepositoryPublicationObservation>, String> {
        if !self.repositories.contains_key(&resource.repository_id) {
            return Err(format!("unknown repository `{}`", resource.repository_id));
        }
        let observation = (|| {
            let remote_head = self
                .effects
                .observe_remote_branch(&resource.repository_id, &resource.branch)?;
            let pulls = self
                .effects
                .observe_current_pull_requests(&resource.repository_id, &resource.branch)?;
            Ok::<_, String>(crate::delivery_runtime::RepositoryPublicationObservation {
                remote_head,
                pull_requests: pulls.pull_requests,
            })
        })();
        let Ok(mut observation) = observation else {
            return Ok(None);
        };
        if let crate::delivery_forge::ObservationCapability::Known(entries) =
            &mut observation.pull_requests
        {
            entries.sort_by_key(|pull| pull.number);
        }
        Ok(Some(observation))
    }
}

impl RuntimeDelivery {
    pub fn handlers(&self) -> Vec<&dyn EffectHandler> {
        self.handlers.iter().map(Box::as_ref).collect()
    }

    pub fn effects(&self) -> &RepositoryDeliveryEffects {
        &self.effects
    }

    pub fn shared_effects(&self) -> std::sync::Arc<RepositoryDeliveryEffects> {
        std::sync::Arc::clone(&self.effects)
    }

    pub fn publication_adoption_source(
        &self,
    ) -> Arc<dyn crate::human_runtime::PublicationAdoptionSource> {
        Arc::new(RuntimePublicationAdoptionSource {
            effects: Arc::clone(&self.effects),
            repositories: self.repositories.clone(),
        })
    }

    pub fn host_jobs(&self) -> Arc<Mutex<HostJobPool>> {
        Arc::clone(&self.host_jobs)
    }

    fn observe_snapshot(
        &self,
        repository_id: &RepositoryId,
        branch: &str,
    ) -> Result<crate::delivery_runtime::RepositoryPublicationObservation, String> {
        self.repositories
            .get(repository_id)
            .ok_or_else(|| format!("unknown repository `{repository_id}`"))?;
        let remote_head = self.effects.observe_remote_branch(repository_id, branch)?;
        let pulls = self
            .effects
            .observe_current_pull_requests(repository_id, branch)?;
        let mut observation = crate::delivery_runtime::RepositoryPublicationObservation {
            remote_head,
            pull_requests: pulls.pull_requests,
        };
        if let crate::delivery_forge::ObservationCapability::Known(entries) =
            &mut observation.pull_requests
        {
            entries.sort_by_key(|pull| pull.number);
        }
        Ok(observation)
    }

    fn observe_monitor_snapshot(
        &self,
        repository_id: &RepositoryId,
        branch: &str,
    ) -> Option<crate::delivery_runtime::RepositoryPublicationObservation> {
        self.observe_snapshot(repository_id, branch).ok()
    }

    /// Build a human adoption request from the latest unresolved event and a new host-side
    /// observation. The requested resource must still be present in that complete observation.
    pub fn publication_adoption_request(
        &self,
        store: &crate::store::ConfigStore,
        resource: &crate::store::publication_monitor::PublicationResource,
        selected_resource: crate::human_runtime::SelectedPublicationResource,
        request_id: crate::domain::ids::HumanRequestId,
        expires_at_unix: u64,
    ) -> Result<
        (
            crate::human_runtime::HumanRuntimeRequest,
            crate::human_runtime::HumanAuthorityMaterial,
        ),
        String,
    > {
        let observation = self.observe_snapshot(&resource.repository_id, &resource.branch)?;
        self.publication_adoption_request_for_observation(
            store,
            resource,
            selected_resource,
            request_id,
            expires_at_unix,
            observation,
        )
    }

    fn publication_adoption_request_for_observation(
        &self,
        store: &crate::store::ConfigStore,
        resource: &crate::store::publication_monitor::PublicationResource,
        selected_resource: crate::human_runtime::SelectedPublicationResource,
        request_id: crate::domain::ids::HumanRequestId,
        expires_at_unix: u64,
        current_observation: crate::delivery_runtime::RepositoryPublicationObservation,
    ) -> Result<
        (
            crate::human_runtime::HumanRuntimeRequest,
            crate::human_runtime::HumanAuthorityMaterial,
        ),
        String,
    > {
        let unresolved = store
            .latest_unresolved_publication(resource)?
            .ok_or("publication resource has no unresolved irregularity")?;
        let repository = self
            .repositories
            .get(&resource.repository_id)
            .ok_or_else(|| format!("unknown repository `{}`", resource.repository_id))?;
        let current_observation_digest =
            crate::human_runtime::publication_observation_digest(&current_observation)?;
        let authority = crate::human_runtime::PublicationAdoptionAuthority {
            resource: resource.clone(),
            event_id: unresolved.event_id,
            event_revision: unresolved.revision,
            previous_observation_digest: unresolved.observation_digest,
            selected_resource,
            current_observation,
            current_observation_digest,
            configuration_digest: self.configuration_digest.clone(),
            policy_digest: crate::human_runtime::publication_adoption_policy_digest(repository)?,
            expires_at_unix,
        };
        let request =
            crate::human_runtime::publication_adoption_request(request_id, authority.clone())?;
        let material = crate::human_runtime::HumanAuthorityMaterial::PublicationAdoption {
            material: authority,
        };
        Ok((request, material))
    }

    /// Inspect at most one accepted work node per call. The process-local round-robin cursor
    /// prevents starvation while the controller runs; after restart, enumeration restarts.
    pub fn observe_publications(
        &self,
        store: &mut crate::store::ConfigStore,
        owner_generation: u64,
        now_unix: i64,
    ) -> Result<PublicationMonitorTick, String> {
        let active = store.active_ticket_runs(owner_generation, 256)?;
        let mut candidates = Vec::new();
        for run in active {
            let Some(plan) =
                store.latest_accepted_work_plan(&run.project_id, &run.ticket_run_id)?
            else {
                continue;
            };
            let project_config = self
                .applied_config
                .config
                .projects
                .get(&run.project_id)
                .ok_or("accepted plan references an unconfigured Project")?;
            let validated_plan = plan.validate_for(project_config, &self.applied_config.digest)?;
            let receipts = store.list_succeeded_effect_receipts(
                owner_generation,
                &run.project_id,
                "ticket_run",
                run.ticket_run_id.as_str(),
                256,
            )?;
            for receipt in receipts
                .iter()
                .filter(|entry| entry.intent().kind == "prepare_worktrees")
            {
                let prepared: crate::delivery_runtime::PreparedWorktreesEffectReceipt =
                    crate::protocol::parse_unique(receipt.receipt_json().as_bytes())
                        .map_err(|error| error.to_string())?;
                if prepared.ticket_run_id != run.ticket_run_id {
                    continue;
                }
                for node in prepared.work_nodes {
                    if validated_plan
                        .nodes_in_execution_order
                        .iter()
                        .any(|planned| {
                            planned.id == node.work_node_id
                                && planned.repository == node.repository_id
                                && planned.role == crate::domain::types::Role::Worker
                        })
                        && store
                            .prepared_worker_launch(
                                owner_generation,
                                plan.accepted_revision,
                                &node.work_node_id,
                                receipt,
                                project_config,
                                &self.applied_config.digest,
                            )?
                            .is_some()
                    {
                        let resource = crate::store::publication_monitor::PublicationResource {
                            project_id: run.project_id.clone(),
                            ticket_run_id: run.ticket_run_id.clone(),
                            repository_id: node.repository_id.clone(),
                            branch: node.branch.clone(),
                        };
                        candidates.push((resource, receipts.clone()));
                    }
                }
            }
        }
        if candidates.is_empty() {
            return Ok(PublicationMonitorTick::Idle);
        }
        let index = self
            .publication_cursor
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            % candidates.len();
        let (resource, receipts) = candidates.swap_remove(index);
        if let Some(unresolved) = store.latest_unresolved_publication(&resource)? {
            if let Some(revision) = self.apply_accepted_publication_adoption(
                store,
                owner_generation,
                &resource,
                &unresolved,
                now_unix,
            )? {
                return Ok(PublicationMonitorTick::HumanReviewApplied { revision });
            }
            if let Some(request_id) = self.enqueue_publication_adoption_review(
                store,
                owner_generation,
                &resource,
                &unresolved,
                now_unix,
            )? {
                return Ok(PublicationMonitorTick::HumanReviewPending { request_id });
            }
            return Ok(PublicationMonitorTick::Unknown);
        }
        if store.publication_effect_in_flight(
            &resource.project_id,
            &resource.ticket_run_id,
            &resource.repository_id,
            &resource.branch,
        )? {
            return Ok(PublicationMonitorTick::EffectReconciling);
        }
        let Some(mut baseline) = store.load_publication_baseline(&resource)? else {
            let Some(observation) =
                self.observe_monitor_snapshot(&resource.repository_id, &resource.branch)
            else {
                return Ok(PublicationMonitorTick::Unknown);
            };
            let digest = canonical_observation_digest(&observation)?;
            let saved = store.record_publication_irregularity(owner_generation, &crate::store::publication_monitor::PublicationIrregularity {
                resource, observation_digest: digest, observed_at_unix: now_unix, facts: serde_json::json!({"reason":"prepared work node has no trusted pre-mutation baseline","observed_remote_head":observation.remote_head,"pull_requests":observation.pull_requests}),
            })?;
            return Ok(PublicationMonitorTick::IrregularityRecorded {
                revision: saved.revision,
            });
        };
        if baseline.configuration_digest != self.configuration_digest {
            return Ok(PublicationMonitorTick::Unknown);
        }
        let Some(observation) =
            self.observe_monitor_snapshot(&resource.repository_id, &resource.branch)
        else {
            return Ok(PublicationMonitorTick::Unknown);
        };
        let publication = receipts
            .iter()
            .filter(|entry| entry.intent().kind == "publish_implementation")
            .filter_map(|entry| {
                let payload: crate::delivery_runtime::PublishImplementationEffectPayload =
                    crate::protocol::parse_unique(entry.intent().request_json.as_bytes()).ok()?;
                if payload.repository_id != resource.repository_id {
                    return None;
                }
                let receipt: crate::delivery_runtime::ImplementationPublicationReceipt =
                    crate::protocol::parse_unique(entry.receipt_json().as_bytes()).ok()?;
                (payload.ticket_run_id == resource.ticket_run_id
                    && receipt.push.branch == resource.branch)
                    .then_some((entry, receipt))
            })
            .next_back();
        let mut host = crate::publication_monitor::ReconciledHostEffects::default();
        if let Some((_, receipt)) = publication.as_ref() {
            if observation.remote_head.as_deref() == Some(receipt.push.pushed_head.as_str()) {
                host.confirmed_push_head = Some(receipt.push.pushed_head.clone());
            }
            if let crate::delivery_forge::ObservationCapability::Known(pulls) =
                &observation.pull_requests
                && let Some(pull) = pulls
                    .iter()
                    .find(|pull| pull.number == receipt.pull_request.number)
                && pull.node_id == receipt.pull_request.node_id
                && pull.source_head == receipt.pull_request.source_head
                && pull.source_branch == receipt.pull_request.source_branch
                && pull.base_branch == receipt.pull_request.base_branch
                && pull.title == receipt.pull_request.title
                && pull.body.as_deref().map(|body| sha256(body.as_bytes()))
                    == Some(receipt.pull_request.body_digest.clone())
            {
                host.confirmed_pull_request = Some(pull.clone());
            }
        }
        match store.classify_publication_observation(&resource, &observation, &host)? {
            crate::publication_monitor::PublicationClassification::Unchanged => {
                Ok(PublicationMonitorTick::Unchanged)
            }
            crate::publication_monitor::PublicationClassification::UnknownCapability => {
                Ok(PublicationMonitorTick::Unknown)
            }
            crate::publication_monitor::PublicationClassification::Unexpected { reason } => {
                let digest = canonical_observation_digest(&observation)?;
                let saved = store.record_publication_irregularity(owner_generation, &crate::store::publication_monitor::PublicationIrregularity { resource, observation_digest: digest, observed_at_unix: now_unix, facts: serde_json::json!({"reason":reason,"observed_remote_head":observation.remote_head,"pull_requests":observation.pull_requests}) })?;
                Ok(PublicationMonitorTick::IrregularityRecorded {
                    revision: saved.revision,
                })
            }
            crate::publication_monitor::PublicationClassification::HostEffectConfirmed => {
                let Some((succeeded, _)) = publication else {
                    return Err(
                        "monitor classified a host effect without a succeeded durable receipt"
                            .into(),
                    );
                };
                if host.confirmed_pull_request.is_none() || host.confirmed_push_head.is_none() {
                    let digest = canonical_observation_digest(&observation)?;
                    let saved = store.record_publication_irregularity(owner_generation, &crate::store::publication_monitor::PublicationIrregularity { resource, observation_digest: digest, observed_at_unix: now_unix, facts: serde_json::json!({"reason":"remote state changed but does not match a complete succeeded publication receipt","observed_remote_head":observation.remote_head,"pull_requests":observation.pull_requests}) })?;
                    return Ok(PublicationMonitorTick::IrregularityRecorded {
                        revision: saved.revision,
                    });
                }
                baseline = store.advance_publication_baseline(
                    owner_generation,
                    &baseline,
                    &observation,
                    succeeded,
                    now_unix,
                )?;
                Ok(PublicationMonitorTick::BaselineAdvanced {
                    revision: baseline.revision,
                })
            }
        }
    }

    fn enqueue_publication_adoption_review(
        &self,
        store: &mut crate::store::ConfigStore,
        owner_generation: u64,
        resource: &crate::store::publication_monitor::PublicationResource,
        unresolved: &crate::store::publication_monitor::UnresolvedPublicationIrregularity,
        now_unix: i64,
    ) -> Result<Option<String>, String> {
        if self.applied_config.config.human.is_none() {
            return Ok(None);
        }
        let now =
            u64::try_from(now_unix).map_err(|_| "controller clock is before the Unix epoch")?;
        let Some(observation) =
            self.observe_monitor_snapshot(&resource.repository_id, &resource.branch)
        else {
            return Ok(None);
        };
        let Ok(selected) = selected_publication_resource(&observation) else {
            // Unknown capability or multiple candidate PRs requires a later fresh observation
            // and must leave the publication hold intact without failing the controller tick.
            return Ok(None);
        };
        let observation_digest =
            crate::human_runtime::publication_observation_digest(&observation)?;
        let identity = serde_json::to_vec(&(
            resource,
            &unresolved.event_id,
            unresolved.revision,
            &observation_digest,
        ))
        .map_err(|error| error.to_string())?;
        let stable = sha256(&identity);
        let mut selected_request = None;
        for attempt in 0..32u8 {
            let request_id = crate::domain::ids::HumanRequestId::parse(format!(
                "publication-adoption-{}-{attempt}",
                &stable[..32]
            ))?;
            if let Some(existing) = store.current_human_request(&request_id)? {
                match existing.lifecycle {
                    crate::human_runtime::HumanRequestLifecycle::Stale
                    | crate::human_runtime::HumanRequestLifecycle::Expired
                    | crate::human_runtime::HumanRequestLifecycle::Cancelled => continue,
                    crate::human_runtime::HumanRequestLifecycle::Decided
                        if existing.request.expires_at_unix <= now
                            && store.human_decision_choice(&request_id)?
                                == Some(crate::human_runtime::HumanDecisionChoice::Approve) =>
                    {
                        // A prior approval that expired during downtime cannot authorize
                        // adoption. Give this exact observation a fresh, bounded approval ID.
                        continue;
                    }
                    crate::human_runtime::HumanRequestLifecycle::Decided
                        if matches!(
                            store.human_decision_choice(&request_id)?,
                            Some(
                                crate::human_runtime::HumanDecisionChoice::Refuse
                                    | crate::human_runtime::HumanDecisionChoice::Defer
                            )
                        ) =>
                    {
                        // A refusal or explicit deferral remains a hold. Do not create a new
                        // prompt for the same unresolved observation on every controller tick.
                        return Ok(None);
                    }
                    _ => return Ok(Some(request_id.as_str().to_owned())),
                }
            }
            let logical_key = format!("publication-adoption:{}", request_id.as_str());
            if let Some(existing) = store.effect_by_logical_key(&logical_key)? {
                let effect: crate::human_runtime::HumanPresentationEffect =
                    crate::protocol::parse_unique(existing.request_json.as_bytes())?;
                if effect.request.request_id != request_id {
                    return Err(
                        "publication adoption presentation key is bound to another request".into(),
                    );
                }
                return Ok(Some(request_id.as_str().to_owned()));
            }
            selected_request = Some((request_id, logical_key));
            break;
        }
        let Some((request_id, logical_key)) = selected_request else {
            return Err("publication adoption request retry limit was exhausted".into());
        };
        let expires_at = now
            .checked_add(7 * 24 * 60 * 60)
            .ok_or("publication review expiry overflow")?;
        let (request, authority) = self.publication_adoption_request_for_observation(
            store,
            resource,
            selected,
            request_id.clone(),
            expires_at,
            observation,
        )?;
        if request.subject.revision.0 != unresolved.revision
            || request.subject.subject_id != unresolved.event_id
        {
            return Err("publication review request differs from the unresolved event".into());
        }
        let mut offset = 0u64;
        let run = loop {
            let page = store.active_ticket_runs_page_for_project(
                owner_generation,
                &resource.project_id,
                offset,
                256,
            )?;
            if let Some(run) = page
                .iter()
                .find(|run| run.ticket_run_id == resource.ticket_run_id)
                .cloned()
            {
                break Some(run);
            }
            if page.len() < 256 {
                break None;
            }
            offset = offset
                .checked_add(page.len() as u64)
                .ok_or("active TicketRun page offset overflow")?;
        };
        let Some(run) = run else {
            return Ok(None);
        };
        let view = store
            .rex_view_history(&resource.project_id)?
            .into_iter()
            .find(|record| {
                record.lifecycle == "active"
                    && record.view.kind == crate::launch::RexViewKind::Ticket
                    && record.view.ticket_namespace.as_deref() == Some(run.namespace.as_str())
                    && record.view.ticket_id.as_deref() == Some(run.ticket_id.as_str())
            });
        let Some(view) = view else {
            return Ok(None);
        };
        let authority = crate::human_runtime::HumanAuthorityMaterial::PublicationAdoption {
            material: match authority {
                crate::human_runtime::HumanAuthorityMaterial::PublicationAdoption { material } => {
                    material
                }
                _ => return Err("publication request builder returned the wrong authority".into()),
            },
        };
        let effect = crate::human_runtime::HumanPresentationEffect {
            request: request.clone(),
            rex_view_id: view.view.view_id,
            authority: Some(authority),
        };
        let request_json = crate::store::canonical_json(&effect)?;
        let request_digest = crate::domain::ids::Digest::parse(sha256(request_json.as_bytes()))?;
        let intent = crate::store::EffectIntent {
            project_id: resource.project_id.clone(),
            subject_type: "ticket_run".into(),
            subject_id: resource.ticket_run_id.as_str().to_owned(),
            operation_id: format!("present-{}", request_id.as_str()),
            logical_key,
            kind: crate::engine::reducer::effect_name(
                &crate::engine::reducer::EffectKind::RequestHumanReview,
            )
            .into(),
            request_json,
            request_digest: request_digest.as_str().to_owned(),
            expected_revision: Some(run.revision),
        };
        store.enqueue_effect(owner_generation, &intent)?;
        Ok(Some(request_id.as_str().to_owned()))
    }

    fn apply_accepted_publication_adoption(
        &self,
        store: &mut crate::store::ConfigStore,
        owner_generation: u64,
        resource: &crate::store::publication_monitor::PublicationResource,
        unresolved: &crate::store::publication_monitor::UnresolvedPublicationIrregularity,
        now_unix: i64,
    ) -> Result<Option<u64>, String> {
        let now =
            u64::try_from(now_unix).map_err(|_| "controller clock is before the Unix epoch")?;
        let Some(summary) =
            store.current_human_request_for_publication_event(&unresolved.event_id)?
        else {
            return Ok(None);
        };
        let Some(approval) =
            store.accepted_publication_adoption_approval(&summary.request.request_id, now)?
        else {
            return Ok(None);
        };
        let repository = self
            .repositories
            .get(&resource.repository_id)
            .ok_or_else(|| format!("unknown repository `{}`", resource.repository_id))?;
        let Some(observation) =
            self.observe_monitor_snapshot(&resource.repository_id, &resource.branch)
        else {
            return Ok(None);
        };
        let material = approval.authority();
        if crate::human_runtime::publication_observation_digest(&observation)?
            != material.current_observation_digest
        {
            return Ok(None);
        }
        let baseline = store.adopt_publication_snapshot(
            owner_generation,
            &approval,
            &observation,
            &self.configuration_digest,
            &repository.base_branch,
            now_unix,
        )?;
        Ok(Some(baseline.revision))
    }

    /// Resolve each configured base branch to its current remote commit without cloning or
    /// mutating a managed repository. The returned map is a single bounded read pass.
    pub fn observe_base_heads(&self) -> Result<BTreeMap<RepositoryId, String>, String> {
        let mut heads = BTreeMap::new();
        for (repository_id, repository) in &self.repositories {
            let reference = format!("refs/heads/{}", repository.base_branch);
            let output = process::run(ProcessRequest {
                executable: self.git_executable.clone(),
                args: vec![
                    OsString::from("ls-remote"),
                    OsString::from("--heads"),
                    OsString::from(&repository.clone_url),
                    OsString::from(&reference),
                ],
                stdin: Vec::new(),
                cwd: None,
                clear_environment: true,
                environment: self.git_environment.clone(),
                timeout: GIT_TIMEOUT,
                shutdown_grace: TOOL_SHUTDOWN_GRACE,
                stdout_limit: 64 * 1024,
                stderr_tail_limit: 16 * 1024,
            })
            .map_err(|error| format!("could not observe `{repository_id}` base branch: {error}"))?;
            if !output.status.is_some_and(|status| status.success())
                || output.timed_out
                || !output.cleanup_confirmed
                || output.stdout_truncated
            {
                return Err(format!(
                    "could not establish the remote base head for `{repository_id}`"
                ));
            }
            let text = std::str::from_utf8(&output.stdout)
                .map_err(|_| format!("Git returned non-UTF-8 output for `{repository_id}`"))?;
            let mut rows = text.lines();
            let line = rows
                .next()
                .ok_or_else(|| format!("configured base branch is absent for `{repository_id}`"))?;
            if rows.next().is_some() {
                return Err(format!(
                    "Git returned multiple remote refs for `{repository_id}`"
                ));
            }
            let (sha, observed_reference) = line
                .split_once('\t')
                .ok_or_else(|| format!("Git returned a malformed ref for `{repository_id}`"))?;
            if observed_reference != reference || !valid_git_sha(sha) {
                return Err(format!(
                    "Git returned an unexpected remote ref for `{repository_id}`"
                ));
            }
            heads.insert(repository_id.clone(), sha.to_owned());
        }
        Ok(heads)
    }
}

impl crate::human_runtime::PublicationAdoptionSource for RuntimeDelivery {
    fn observe_publication(
        &self,
        resource: &crate::store::publication_monitor::PublicationResource,
    ) -> Result<Option<crate::delivery_runtime::RepositoryPublicationObservation>, String> {
        match self.observe_snapshot(&resource.repository_id, &resource.branch) {
            Ok(observation) => Ok(Some(observation)),
            Err(_) => Ok(None),
        }
    }
}

/// Resolve host tools from the environment captured for this Rex controller, then build the
/// real repository delivery handlers over the same managed state root used by the controller.
pub fn build(
    applied_config: &AppliedConfig,
    state_root: &Path,
    captured_host_env: &BTreeMap<OsString, OsString>,
    environment_snapshot_id: &crate::domain::ids::Digest,
) -> Result<RuntimeDelivery, String> {
    if !state_root.is_absolute() {
        return Err("repository delivery state root must be absolute".into());
    }
    let search_path = captured_host_env
        .get(OsStr::new("PATH"))
        .map(std::env::split_paths)
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    if search_path.is_empty() {
        return Err("captured host environment has no usable PATH".into());
    }
    let git = resolve_executable(Path::new("git"), &search_path)
        .ok_or("git executable is unavailable in the captured host PATH")?;
    let gh = resolve_executable(Path::new("gh"), &search_path)
        .ok_or("gh executable is unavailable in the captured host PATH")?;

    let mut repositories = BTreeMap::<RepositoryId, RepositoryConfig>::new();
    for (repository_id, repository) in &applied_config.config.repositories {
        validate_repository(repository_id, repository)?;
        repositories.insert(repository_id.clone(), repository.clone());
    }
    let mut project_repositories = BTreeMap::<ProjectId, BTreeSet<RepositoryId>>::new();
    for (project_id, project) in &applied_config.config.projects {
        let selected = project
            .repositories
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        for repository_id in &selected {
            let repository = repositories.get(repository_id).ok_or_else(|| {
                format!("Project `{project_id}` references unknown repository `{repository_id}`")
            })?;
            if repository.forge != "github" {
                return Err(format!(
                    "repository `{repository_id}` uses unsupported delivery forge `{}`; this runtime supports GitHub",
                    repository.forge
                ));
            }
        }
        project_repositories.insert(project_id.clone(), selected);
    }

    let environment_binding = HostJobEnvironmentBinding {
        snapshot_id: environment_snapshot_id.clone(),
        policy_digest: crate::host_jobs::environment_policy_digest(
            "rex-projects-host-runtime-v1",
            captured_host_env,
        )?,
    };
    let host_jobs = Arc::new(Mutex::new(HostJobPool::new(
        applied_config.config.runtime.max_host_jobs,
        applied_config.config.runtime.max_rex_projects_hook_runs,
    )?));
    let effects = RepositoryDeliveryEffects::new(
        RepositoryDeliveryEffectConfig {
            state_root: state_root.to_owned(),
            git: GitOptions {
                executable: git.clone(),
                environment: captured_host_env.clone(),
                timeout: GIT_TIMEOUT,
            },
            inherited_environment: captured_host_env.clone(),
            environment_binding,
            gh_executable: gh,
            gh_environment: captured_host_env.clone(),
            timeout: GH_TIMEOUT,
            configuration_digest: applied_config.digest.clone(),
            repositories: repositories.clone(),
            project_repositories,
            max_hook_attempts: maximum_project_hook_attempts(&applied_config.config)?,
        },
        Arc::clone(&host_jobs),
    )?;
    let handlers: Vec<Box<dyn EffectHandler>> = vec![
        Box::new(effects.prepare_worktrees_handler()),
        Box::new(effects.publish_implementation_handler()),
    ];
    Ok(RuntimeDelivery {
        applied_config: applied_config.clone(),
        handlers,
        effects,
        host_jobs,
        git_executable: git,
        git_environment: captured_host_env.clone(),
        repositories,
        configuration_digest: applied_config.digest.clone(),
        publication_cursor: std::sync::atomic::AtomicUsize::new(0),
    })
}

fn valid_git_sha(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn selected_publication_resource(
    observation: &crate::delivery_runtime::RepositoryPublicationObservation,
) -> Result<crate::human_runtime::SelectedPublicationResource, String> {
    let crate::delivery_forge::ObservationCapability::Known(pulls) = &observation.pull_requests
    else {
        return Err("publication adoption requires a complete pull-request observation".into());
    };
    if pulls.len() > 1 {
        return Err(
            "publication adoption cannot select among multiple pull requests automatically".into(),
        );
    }
    if let Some(pull) = pulls.first() {
        return Ok(
            crate::human_runtime::SelectedPublicationResource::PullRequest {
                number: pull.number,
                node_id: pull.node_id.clone(),
                head_sha: pull.source_head.clone(),
                base_sha: pull.base_sha.clone(),
            },
        );
    }
    let head = observation
        .remote_head
        .clone()
        .ok_or("publication adoption has no current branch or pull request to review")?;
    Ok(crate::human_runtime::SelectedPublicationResource::Branch { head })
}

fn canonical_observation_digest(
    observation: &crate::delivery_runtime::RepositoryPublicationObservation,
) -> Result<String, String> {
    let mut normalized = observation.clone();
    if let crate::delivery_forge::ObservationCapability::Known(pulls) =
        &mut normalized.pull_requests
    {
        pulls.sort_by_key(|pull| pull.number);
    }
    let json = serde_json::to_value(normalized).map_err(|error| error.to_string())?;
    let canonical = serde_json::to_string(&json).map_err(|error| error.to_string())?;
    Ok(sha256(canonical.as_bytes()))
}

fn sha256(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    sha2::Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn maximum_project_hook_attempts(config: &crate::config::Config) -> Result<u32, String> {
    let retries = config
        .projects
        .values()
        .map(|project| project.max_effect_retries)
        .max()
        .unwrap_or(0);
    u32::try_from(retries.saturating_add(1))
        .map_err(|_| "project hook retry limit exceeds the supported range".into())
}

fn validate_repository(
    repository_id: &RepositoryId,
    repository: &RepositoryConfig,
) -> Result<(), String> {
    if repository.forge != "github" {
        return Err(format!(
            "repository `{repository_id}` uses unsupported delivery forge `{}`; this runtime supports GitHub",
            repository.forge
        ));
    }
    validate_github_clone_url(&repository.clone_url).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    use super::*;

    fn applied_config(clone_url: &str, forge: &str) -> AppliedConfig {
        let value = serde_json::json!({
            "schema_version": 1,
            "adapters": {"tickets": {
                "kind": "command",
                "command": ["ticket-cli"]
            }},
            "repositories": {"repo": {
                "clone_url": clone_url, "base_branch":"main", "forge":forge
            }},
            "projects": {"project": {
                "mode":"operations", "ticket_adapter":"tickets", "repositories":["repo"]
            }}
        });
        AppliedConfig {
            config: serde_json::from_value(value).unwrap(),
            profiles: BTreeMap::new(),
            source_root: String::new(),
            source_files: Vec::new(),
            digest: crate::domain::ids::Digest::parse("a".repeat(64)).unwrap(),
        }
    }

    fn tool_path(root: &Path) -> PathBuf {
        fs::create_dir_all(root).unwrap();
        for name in ["git", "gh"] {
            let path = root.join(name);
            let body = if name == "git" {
                "#!/bin/sh\nprintf 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\\trefs/heads/main\\n'\n"
            } else {
                "#!/bin/sh\nexit 0\n"
            };
            fs::write(&path, body).unwrap();
            let mut permissions = fs::metadata(&path).unwrap().permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(path, permissions).unwrap();
        }
        root.to_owned()
    }

    #[test]
    fn failed_remote_observation_is_unknown_to_monitor_and_unavailable_to_adoption() {
        let temp = tempfile::tempdir().unwrap();
        let bin = tool_path(&temp.path().join("bin"));
        fs::write(bin.join("git"), "#!/bin/sh\nexit 17\n").unwrap();
        let env = BTreeMap::from([(OsString::from("PATH"), bin.into_os_string())]);
        let delivery = build(
            &applied_config("git@github.com:acme/demo.git", "github"),
            temp.path(),
            &env,
            &crate::domain::ids::Digest::parse("a".repeat(64)).unwrap(),
        )
        .unwrap();
        let repository = RepositoryId::parse("repo").unwrap();
        assert!(
            delivery
                .observe_monitor_snapshot(&repository, "main")
                .is_none()
        );
        let resource = crate::store::publication_monitor::PublicationResource {
            project_id: ProjectId::parse("project").unwrap(),
            ticket_run_id: crate::domain::ids::TicketRunId::parse("ticket-run").unwrap(),
            repository_id: repository,
            branch: "main".into(),
        };
        assert!(
            crate::human_runtime::PublicationAdoptionSource::observe_publication(
                &delivery, &resource,
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn builds_delivery_handlers_from_captured_path_and_managed_state() {
        let temp = tempfile::tempdir().unwrap();
        let bin = tool_path(&temp.path().join("bin"));
        let env = BTreeMap::from([(OsString::from("PATH"), bin.into_os_string())]);
        let delivery = build(
            &applied_config("git@github.com:acme/demo.git", "github"),
            temp.path(),
            &env,
            &crate::domain::ids::Digest::parse("a".repeat(64)).unwrap(),
        )
        .unwrap();
        let kinds = delivery
            .handlers()
            .iter()
            .map(|handler| crate::engine::reducer::effect_name(&handler.kind()).to_owned())
            .collect::<Vec<_>>();
        assert_eq!(kinds, ["prepare_worktrees", "publish_implementation"]);
        assert!(temp.path().join("repos").is_dir());
        assert_eq!(
            delivery.observe_base_heads().unwrap()[&RepositoryId::parse("repo").unwrap()],
            "a".repeat(40)
        );
    }

    #[test]
    fn rejects_missing_tools_and_unsupported_forge_before_creating_state() {
        let temp = tempfile::tempdir().unwrap();
        let empty_env = BTreeMap::from([(OsString::from("PATH"), OsString::new())]);
        assert!(
            build(
                &applied_config("git@github.com:acme/demo.git", "github"),
                temp.path(),
                &empty_env,
                &crate::domain::ids::Digest::parse("a".repeat(64)).unwrap(),
            )
            .is_err()
        );
        assert!(!temp.path().join("delivery").exists());

        let bin = tool_path(&temp.path().join("bin"));
        let env = BTreeMap::from([(OsString::from("PATH"), bin.into_os_string())]);
        assert!(
            build(
                &applied_config("ssh://git@example.invalid/acme/demo.git", "forgejo"),
                temp.path(),
                &env,
                &crate::domain::ids::Digest::parse("a".repeat(64)).unwrap(),
            )
            .is_err()
        );
        assert!(!temp.path().join("delivery").exists());
    }
}
