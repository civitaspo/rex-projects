//! Apply TicketRun transitions only from receipts persisted by trusted host
//! effect handlers. This module never consumes Agent assertions.

use crate::config::Config;
use crate::delivery_runtime::{
    PrepareWorktreesEffectPayload, PreparedWorktreeReceiptNode, PreparedWorktreesEffectReceipt,
};
use crate::domain::ids::{Digest, OperationId, Revision};
use crate::effects::EffectKind;
use crate::engine::reducer::{Input, Phase};
use crate::store::operations::CompletionGate;
use crate::store::{ConfigStore, DurableInput, EffectIntent, durable_input_digest};

const MAX_RUNS_PER_TICK: usize = 128;
const MAX_RECEIPTS_PER_RUN: usize = 256;

/// Consume at most one authoritative host receipt and commit its reducer
/// transition. The Inbox message ID is derived from the immutable effect ID,
/// so a crash after the transition can replay the same durable input safely.
pub fn consume_one_host_transition(
    store: &mut ConfigStore,
    owner_generation: u64,
    now_unix: i64,
    config: &Config,
    configuration_digest: &Digest,
) -> Result<bool, String> {
    for run in store.active_ticket_runs(owner_generation, MAX_RUNS_PER_TICK)? {
        let receipts = store.list_succeeded_effect_receipts(
            owner_generation,
            &run.project_id,
            "ticket_run",
            run.ticket_run_id.as_str(),
            MAX_RECEIPTS_PER_RUN,
        )?;

        if run.phase == Phase::WaitingHuman {
            let awaiting_revision = Revision(
                run.revision
                    .checked_add(1)
                    .ok_or("TicketRun revision is exhausted")?,
            );
            let Some(work_item) =
                store.merge_work_item(&run.project_id, &run.ticket_run_id, awaiting_revision)?
            else {
                continue;
            };
            if work_item.assessed_revision.0.saturating_add(1) != run.revision {
                continue;
            }
            let request_id = crate::domain::ids::HumanRequestId::parse(format!(
                "merge-review-{}",
                work_item.document.intent_evidence_id
            ))?;
            let now =
                u64::try_from(now_unix).map_err(|_| "controller clock is before the Unix epoch")?;
            let Some(approval) =
                store.accepted_merge_work_review_approval(&request_id, &work_item, now)?
            else {
                continue;
            };
            let step = work_item
                .document
                .procedure
                .steps
                .first()
                .ok_or("approved merge work item has no first procedure step")?;
            let step_request = crate::merge_executor::MergeStepEffectRequest {
                schema_version: 1,
                work_id: work_item.work_id.clone(),
                request_id,
                assessed_revision: work_item.assessed_revision,
                awaiting_merge_revision: work_item.awaiting_merge_revision,
                step_key: step.key.clone(),
                prior_receipts: Vec::new(),
            };
            let request_json = crate::store::canonical_json(&step_request)?;
            let next_revision = Revision(awaiting_revision.0);
            let merge_effect = EffectIntent {
                project_id: run.project_id.clone(),
                subject_type: "ticket_run".into(),
                subject_id: run.ticket_run_id.as_str().into(),
                operation_id: OperationId::parse(format!(
                    "merge-{}-{:03}-{}",
                    work_item.work_id, 0, step.key
                ))?
                .as_str()
                .into(),
                logical_key: format!(
                    "{}:{}:{}:{:03}:{}",
                    run.ticket_run_id, next_revision.0, work_item.work_id, 0, step.key
                ),
                kind: effect_name(EffectKind::Merge).into(),
                request_digest: sha256_hex(request_json.as_bytes()),
                request_json,
                expected_revision: Some(next_revision.0),
            };
            let payload_json = serde_json::json!({
                "schema_version": 1,
                "kind": "merge_review_approved",
                "ticket_run_id": run.ticket_run_id,
                "source_revision": run.revision,
                "accepted_revision": next_revision,
                "work_id": work_item.work_id,
                "response_id": approval.receipt().response_id(),
                "procedure_step": step.key,
            })
            .to_string();
            let durable = durable_host_input(
                &format!("merge-review-approved:{}", approval.receipt().response_id()),
                &payload_json,
            );
            let expected_external_revision = store.ticket_run_external_revision(
                owner_generation,
                &run.project_id,
                &run.ticket_run_id,
                run.revision,
            )?;
            let status_payload = crate::engine::ticket_effects::PublishTicketStatus {
                schema_version: 1,
                project_id: run.project_id.clone(),
                namespace: run.namespace.clone(),
                ticket_id: run.ticket_id.clone(),
                ticket_run_id: run.ticket_run_id.clone(),
                ticket_run_revision: next_revision.0,
                expected_external_revision: Some(expected_external_revision),
                desired_status: crate::domain::types::TicketStatus::InProgress,
                reason: "human approved the exact merge procedure".into(),
            };
            status_payload.validate()?;
            let status_json = crate::store::canonical_json(&status_payload)?;
            let status_effect = EffectIntent {
                project_id: run.project_id.clone(),
                subject_type: "ticket_run".into(),
                subject_id: run.ticket_run_id.as_str().into(),
                operation_id: OperationId::parse(format!(
                    "publish-status-merge-{}-{}",
                    run.ticket_run_id, run.revision
                ))?
                .as_str()
                .into(),
                logical_key: format!(
                    "{}:{}:publish-status-after-merge-review",
                    run.ticket_run_id, run.revision
                ),
                kind: effect_name(EffectKind::PublishTicketStatus).into(),
                request_digest: sha256_hex(status_json.as_bytes()),
                request_json: status_json,
                expected_revision: Some(next_revision.0),
            };
            store.commit_ticket_transition(
                owner_generation,
                &run.ticket_run_id,
                Revision(run.revision),
                &durable,
                Input::HumanReviewApproved,
                "host revalidated the exact persisted MergeWorkItem and human approval receipt",
                &payload_json,
                &[merge_effect, status_effect],
            )?;
            return Ok(true);
        }

        if run.phase == Phase::AwaitingMerge
            && advance_approved_merge_procedure(store, owner_generation, now_unix, &run, &receipts)?
        {
            return Ok(true);
        }

        if run.phase == Phase::Preparing {
            for stored in &receipts {
                let intent = stored.intent();
                if intent.kind != effect_name(EffectKind::PrepareWorktrees)
                    || intent.expected_revision != Some(run.revision)
                    || intent.subject_type != "ticket_run"
                    || intent.subject_id != run.ticket_run_id.as_str()
                    || intent.project_id != run.project_id
                {
                    continue;
                }
                let payload: PrepareWorktreesEffectPayload =
                    decode_canonical(&intent.request_json, &intent.request_digest)?;
                validate_prepare_binding(&payload, &run, run.revision)?;
                let (proof, receipt) =
                    crate::delivery_runtime::validate_prepared_worktree_stage(stored)?;
                crate::delivery_runtime::validate_prepared_receipt(&payload, &receipt)?;
                if !validate_prepared_stage_against_plan(
                    store,
                    config,
                    configuration_digest,
                    &run,
                    &receipts,
                    &payload,
                )? {
                    continue;
                }

                let mut publish_effects = Vec::new();
                if proof.has_base_refresh() {
                    if receipt.work_nodes.len() != 1 {
                        return Err(
                            "base refresh publication currently requires one work node".into()
                        );
                    }
                    let node = &receipt.work_nodes[0];
                    let refresh = node
                        .base_refresh
                        .as_ref()
                        .ok_or("refresh proof has no branch refresh receipt")?;
                    let source = node
                        .base_refresh_source
                        .as_ref()
                        .ok_or("refresh proof has no prior publication authority")?;
                    let repository = config
                        .repositories
                        .get(&node.repository_id)
                        .ok_or("refreshed repository is no longer configured")?;
                    let next_revision = run
                        .revision
                        .checked_add(1)
                        .ok_or("TicketRun revision overflow")?;
                    let publication = crate::delivery_runtime::PublishImplementationEffectPayload {
                        schema_version: 1,
                        source_revision: next_revision,
                        configuration_digest: configuration_digest.clone(),
                        ticket_namespace: run.namespace.clone(),
                        ticket_id: run.ticket_id.clone(),
                        ticket_run_id: run.ticket_run_id.clone(),
                        work_node_id: node.work_node_id.clone(),
                        repository_id: node.repository_id.clone(),
                        expected_base_sha: refresh.new_parent_sha.clone(),
                        base_branch: repository.base_branch.clone(),
                        commit_mode: node.commit_mode,
                        commit: crate::delivery_runtime::WorkerDeliveryCommit::HostBaseRefresh {
                            prepare_operation_id: OperationId::parse(intent.operation_id.clone())?,
                            prepare_receipt_digest: crate::domain::ids::Digest::parse(sha256_hex(
                                stored.receipt_json().as_bytes(),
                            ))?,
                            prior_publication_operation_id: source
                                .prior_publication_operation_id
                                .clone(),
                            prior_publication_receipt_digest: source
                                .prior_publication_receipt_digest
                                .clone(),
                            receipt: Box::new(refresh.clone()),
                        },
                        expected_remote_head: Some(refresh.old_child_head.clone()),
                        pull_request: crate::delivery_runtime::PullRequestContent {
                            title: source.pull_request_title.clone(),
                            body: source.exact_body.clone(),
                            update_target: Some(crate::delivery_forge::PullRequestTarget {
                                number: source.pull_request_number,
                                expected_head: refresh.old_child_head.clone(),
                            }),
                        },
                    };
                    let (request_json, request_digest) =
                        crate::delivery_runtime::canonical_delivery_payload(&publication)?;
                    let operation_id = OperationId::parse(format!(
                        "refresh-publish-{}",
                        sha256_hex(
                            format!(
                                "{}:{}",
                                intent.operation_id, source.prior_publication_operation_id
                            )
                            .as_bytes()
                        )
                    ))?;
                    publish_effects.push(EffectIntent {
                        project_id: run.project_id.clone(),
                        subject_type: "ticket_run".into(),
                        subject_id: run.ticket_run_id.as_str().into(),
                        operation_id: operation_id.as_str().into(),
                        logical_key: format!(
                            "{}:{}:host-base-refresh-publication",
                            run.ticket_run_id, next_revision
                        ),
                        kind: effect_name(EffectKind::PublishImplementation).into(),
                        request_digest,
                        request_json,
                        expected_revision: Some(next_revision),
                    });
                }
                let payload_json = serde_json::json!({
                    "schema_version": 1,
                    "kind": "worktrees_prepared",
                    "operation_id": intent.operation_id,
                    "project_id": run.project_id,
                    "ticket_run_id": run.ticket_run_id,
                    "source_revision": run.revision,
                    "receipt_digest": sha256_hex(stored.receipt_json().as_bytes()),
                    "work_node_ids": receipt.work_nodes.iter().map(|node| node.work_node_id.as_str()).collect::<Vec<_>>(),
                })
                .to_string();
                let durable = DurableInput {
                    producer_id: "rex-projects-host-effect".into(),
                    message_id: format!("prepare-worktrees:{}", intent.operation_id),
                    content_digest: durable_input_digest("ticket_run", &payload_json),
                    recipient: "ticket_run".into(),
                    payload: payload_json.clone(),
                };
                store.commit_ticket_transition(
                    owner_generation,
                    &run.ticket_run_id,
                    Revision(run.revision),
                    &durable,
                    Input::WorktreesPrepared(proof),
                    "host-validated worktree preparation receipt",
                    &payload_json,
                    &publish_effects,
                )?;
                return Ok(true);
            }
        }

        if run.phase == Phase::Publishing
            && advance_work_plan_stage(
                store,
                owner_generation,
                config,
                configuration_digest,
                &run,
                &receipts,
            )?
        {
            return Ok(true);
        }

        if run.phase == Phase::Operating
            && run.activity != crate::engine::reducer::Activity::Blocked
        {
            let plan = {
                let operations = store.operations()?;
                operations.plan_state(&run.project_id, &run.ticket_run_id)?
            };
            let Some(plan) = plan else {
                match persist_operating_plan_from_verified_merge(
                    store,
                    owner_generation,
                    now_unix,
                    config,
                    configuration_digest,
                    &run,
                    &receipts,
                ) {
                    Ok(()) => return Ok(true),
                    Err(reason) => {
                        block_run_for_host_readiness(
                            store,
                            owner_generation,
                            &run,
                            "operation_plan_unavailable",
                            &reason,
                        )?;
                        return Ok(true);
                    }
                }
            };
            if let Err(reason) =
                validate_persisted_operation_plan(store, config, configuration_digest, &run, &plan)
            {
                block_run_for_host_readiness(
                    store,
                    owner_generation,
                    &run,
                    "operation_plan_unavailable",
                    &reason,
                )?;
                return Ok(true);
            }
            let gate = {
                let operations = store.operations()?;
                operations.completion_gate(&run.project_id, &run.ticket_run_id)?
            };
            if gate == CompletionGate::WaitingForPostmortem {
                let input = if plan.state == "not_required" {
                    Input::OperationsNotRequired
                } else if plan.state == "succeeded" {
                    Input::OperationsSucceeded
                } else {
                    continue;
                };
                let payload_json = serde_json::json!({
                    "schema_version": 1,
                    "kind": "operations_gate_satisfied",
                    "ticket_run_id": run.ticket_run_id,
                    "source_revision": run.revision,
                    "operation_plan_digest": plan.plan_digest,
                    "plan_state": plan.state,
                })
                .to_string();
                let durable = durable_host_input(
                    &format!("operations-ready:{}", run.revision),
                    &payload_json,
                );
                store.commit_ticket_transition(
                    owner_generation,
                    &run.ticket_run_id,
                    Revision(run.revision),
                    &durable,
                    input,
                    "all required Operator operations succeeded or were explicitly skipped",
                    &payload_json,
                    &[],
                )?;
                return Ok(true);
            }
        }

        if run.phase == Phase::Postmortem {
            for stored in &receipts {
                let intent = stored.intent();
                if intent.kind != effect_name(EffectKind::PublishKnowledge)
                    || intent.expected_revision != Some(run.revision)
                    || intent.subject_type != "ticket_run"
                    || intent.subject_id != run.ticket_run_id.as_str()
                    || intent.project_id != run.project_id
                {
                    continue;
                }
                let operation_id = OperationId::parse(intent.operation_id.clone())?;
                let durable_request = store
                    .knowledge_publication_intent(&operation_id)?
                    .ok_or("successful knowledge effect has no durable publication request")?;
                if durable_request.project_id != run.project_id
                    || durable_request.ticket_run_id != run.ticket_run_id
                    || durable_request.operation_id != operation_id
                    || sha256_hex(durable_request.request_json.as_bytes())
                        != durable_request.request_digest.as_str()
                {
                    return Err(
                        "durable Postmortem request does not match its TicketRun effect".into(),
                    );
                }
                let publication = store
                    .knowledge_publication_receipt(&operation_id)?
                    .ok_or("successful knowledge effect has no persisted publication receipt")?;
                let effect_receipt: crate::store::KnowledgePublicationReceipt =
                    decode_canonical_receipt(stored.receipt_json())?;
                if effect_receipt != publication
                    || publication.manifest.project_id != run.project_id
                    || publication.manifest.ticket_run_id != run.ticket_run_id
                    || publication.manifest.operation_id != operation_id
                {
                    return Err(
                        "Postmortem publication receipt does not match its durable effect".into(),
                    );
                }
                {
                    let mut operations = store.operations()?;
                    operations.record_postmortem_receipt(
                        owner_generation,
                        &run.project_id,
                        &run.ticket_run_id,
                        &publication.manifest_digest,
                        now_unix,
                    )?;
                }
                let next_revision = run
                    .revision
                    .checked_add(1)
                    .ok_or_else(|| "TicketRun revision is exhausted".to_owned())?;
                let completion_intent = completion_effect_intent(
                    &run.project_id,
                    &run.ticket_run_id,
                    run.revision,
                    next_revision,
                )?;
                let payload_json = serde_json::json!({
                    "schema_version": 1,
                    "kind": "knowledge_published",
                    "ticket_run_id": run.ticket_run_id,
                    "source_revision": run.revision,
                    "publication_operation_id": operation_id,
                    "manifest_digest": publication.manifest_digest,
                })
                .to_string();
                let durable = durable_host_input(
                    &format!("knowledge-published:{}", intent.operation_id),
                    &payload_json,
                );
                store.commit_ticket_transition(
                    owner_generation,
                    &run.ticket_run_id,
                    Revision(run.revision),
                    &durable,
                    Input::KnowledgePublished,
                    "host-validated Postmortem publication receipt",
                    &payload_json,
                    &[completion_intent],
                )?;
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn persist_operating_plan_from_verified_merge(
    store: &mut ConfigStore,
    owner_generation: u64,
    now_unix: i64,
    config: &Config,
    configuration_digest: &Digest,
    run: &crate::store::scheduler::ActiveTicketRun,
    receipts: &[crate::store::SucceededEffectReceipt],
) -> Result<(), String> {
    let (snapshot, plan) = configured_operation_plan(store, config, configuration_digest, run)?;
    let awaiting_merge_revision = run
        .revision
        .checked_sub(1)
        .map(Revision)
        .ok_or("Operating TicketRun has no preceding AwaitingMerge revision")?;
    let item = store
        .merge_work_item(&run.project_id, &run.ticket_run_id, awaiting_merge_revision)?
        .ok_or("Operating TicketRun has no immutable verified MergeWorkItem")?;
    if item.awaiting_merge_revision != awaiting_merge_revision
        || item.configuration_digest != *configuration_digest
        || item.project_id != run.project_id
        || item.ticket_run_id != run.ticket_run_id
    {
        return Err("verified MergeWorkItem does not match the current Operating TicketRun".into());
    }
    let verified = find_verified_merge_receipt(&item, receipts)
        .ok_or("no succeeded host MergeVerificationReceipt matches the immutable MergeWorkItem")?;
    let repository = crate::domain::ids::RepositoryId::parse(
        item.document.evidence.subject.repository_id.clone(),
    )?;
    let delivery_facts = crate::operations::DeliveryFacts {
        merge_commits: std::collections::BTreeMap::from([(repository, verified.merge_commit_sha)]),
        planned_revisions: std::collections::BTreeMap::new(),
    };

    let mut operations = store.operations()?;
    operations.persist_plan(
        owner_generation,
        &run.project_id,
        &run.ticket_id,
        &run.ticket_run_id,
        Revision(run.revision),
        snapshot.revision,
        &snapshot.config,
        &plan,
        &delivery_facts,
        now_unix,
    )?;
    Ok(())
}

fn configured_operation_plan(
    store: &ConfigStore,
    config: &Config,
    configuration_digest: &Digest,
    run: &crate::store::scheduler::ActiveTicketRun,
) -> Result<
    (
        crate::store::StoredSnapshot,
        crate::operations::ValidatedOperationPlan,
    ),
    String,
> {
    let project_record = store
        .project(&run.project_id)?
        .ok_or("operation plan Project configuration is missing")?;
    let snapshot = store
        .load_snapshot(&project_record.config_source)?
        .ok_or("operation plan applied configuration snapshot is missing")?;
    let snapshot_config =
        serde_json::to_value(&snapshot.config.config).map_err(|error| error.to_string())?;
    let active_config = serde_json::to_value(config).map_err(|error| error.to_string())?;
    if snapshot.revision != project_record.config_revision
        || snapshot.config.digest != project_record.config_digest
        || snapshot.config.digest != *configuration_digest
        || snapshot_config != active_config
    {
        return Err(
            "operation plan configuration is stale or differs from the active runtime".into(),
        );
    }

    let recipe_id = run
        .recipe_id
        .as_deref()
        .ok_or("TicketRun has no selected operation recipe")?;
    let plan = crate::operations::validate_recipe(&snapshot.config.config, recipe_id)
        .map_err(|error| error.to_string())?;
    for target in plan.targets() {
        let repository = snapshot
            .config
            .config
            .repositories
            .get(&target.repository)
            .ok_or_else(|| {
                format!(
                    "operation target `{}` has no configured repository",
                    target.id
                )
            })?;
        let needs_human =
            repository.operations.as_ref().is_some_and(|policy| {
                policy
                    .human_approval_environments
                    .iter()
                    .any(|environment| environment == &target.environment)
            }) || matches!(target.approval, crate::domain::types::ApprovalMode::Always);
        if needs_human && snapshot.config.config.human.is_none() {
            return Err(format!(
                "operation target `{}` requires human approval but no HumanPresenter is configured",
                target.id
            ));
        }
    }
    Ok((snapshot, plan))
}

pub(crate) fn validate_persisted_operation_plan(
    store: &ConfigStore,
    config: &Config,
    configuration_digest: &Digest,
    run: &crate::store::scheduler::ActiveTicketRun,
    persisted: &crate::store::operations::OperationPlanState,
) -> Result<(), String> {
    let (_, expected) = configured_operation_plan(store, config, configuration_digest, run)?;
    if persisted.recipe_id != expected.recipe_id()
        || persisted.plan_digest != *expected.digest()
        || persisted.config_digest != *configuration_digest
        || (expected.targets().is_empty()
            && (persisted.state != "not_required"
                || persisted.not_required_reason
                    != expected.not_required_reason().map(str::to_owned)))
        || (!expected.targets().is_empty()
            && (persisted.state == "not_required" || persisted.not_required_reason.is_some()))
    {
        return Err("durable operation plan does not match the TicketRun's current recipe and configuration".into());
    }
    Ok(())
}

pub(crate) fn block_run_for_host_readiness(
    store: &mut ConfigStore,
    owner_generation: u64,
    run: &crate::store::scheduler::ActiveTicketRun,
    kind: &str,
    reason: &str,
) -> Result<(), String> {
    let payload = serde_json::json!({
        "schema_version": 1,
        "kind": kind,
        "ticket_run_id": run.ticket_run_id,
        "source_revision": run.revision,
        "reason": reason,
    })
    .to_string();
    let input = durable_host_input(
        &format!(
            "operation-plan-unavailable:{}:{}",
            run.ticket_run_id, run.revision
        ),
        &payload,
    );
    store.commit_ticket_transition(
        owner_generation,
        &run.ticket_run_id,
        Revision(run.revision),
        &input,
        Input::OperationFailed,
        "host could not prepare the immutable operation plan from current verified merge facts and configuration",
        &payload,
        &[],
    )?;
    Ok(())
}

fn advance_work_plan_stage(
    store: &mut ConfigStore,
    owner_generation: u64,
    config: &Config,
    configuration_digest: &Digest,
    run: &crate::store::scheduler::ActiveTicketRun,
    receipts: &[crate::store::SucceededEffectReceipt],
) -> Result<bool, String> {
    use crate::engine::orchestration::{WorkBaseSource, WorkNodeId};

    let Some(accepted) = store.latest_accepted_work_plan(&run.project_id, &run.ticket_run_id)?
    else {
        return Ok(false);
    };
    if accepted.configuration_digest != *configuration_digest {
        return Err("accepted work plan belongs to a stale configuration snapshot".into());
    }
    let project = config
        .projects
        .get(&run.project_id)
        .ok_or("publishing TicketRun Project is no longer configured")?;
    let validated = accepted.validate_for(project, configuration_digest)?;

    let mut prepared = std::collections::BTreeMap::<WorkNodeId, PreparedWorktreeReceiptNode>::new();
    let mut prepared_sources = std::collections::BTreeMap::<WorkNodeId, serde_json::Value>::new();
    let mut publications = std::collections::BTreeMap::<
        WorkNodeId,
        (
            u64,
            crate::store::SucceededEffectReceipt,
            crate::delivery_runtime::ValidatedWorkNodePublication,
        ),
    >::new();
    for stored in receipts {
        let intent = stored.intent();
        if intent.project_id != run.project_id
            || intent.subject_type != "ticket_run"
            || intent.subject_id != run.ticket_run_id.as_str()
        {
            continue;
        }
        if intent.kind == effect_name(EffectKind::PrepareWorktrees) {
            let Some(expected_revision) = intent.expected_revision else {
                continue;
            };
            if expected_revision < accepted.accepted_revision || expected_revision > run.revision {
                continue;
            }
            let payload: PrepareWorktreesEffectPayload =
                decode_canonical(&intent.request_json, &intent.request_digest)?;
            if payload.ticket_run_id != run.ticket_run_id
                || payload.configuration_digest != accepted.configuration_digest
                || payload.source_revision != expected_revision
            {
                return Err("prepared worktree request does not match accepted plan stage".into());
            }
            let receipt: PreparedWorktreesEffectReceipt =
                decode_canonical_receipt(stored.receipt_json())?;
            crate::delivery_runtime::validate_prepared_receipt(&payload, &receipt)?;
            let receipt_digest = sha256_hex(stored.receipt_json().as_bytes());
            for node in receipt.work_nodes {
                prepared_sources.insert(
                    node.work_node_id.clone(),
                    serde_json::json!({
                        "work_node_id": node.work_node_id,
                        "operation_id": intent.operation_id,
                        "receipt_digest": receipt_digest,
                    }),
                );
                prepared.insert(node.work_node_id.clone(), node);
            }
        }
    }
    for stored in receipts {
        let intent = stored.intent();
        if intent.project_id == run.project_id
            && intent.subject_type == "ticket_run"
            && intent.subject_id == run.ticket_run_id.as_str()
            && intent.kind == effect_name(EffectKind::PublishImplementation)
        {
            let Some(expected_revision) = intent.expected_revision else {
                continue;
            };
            if expected_revision < accepted.accepted_revision {
                continue;
            }
            if expected_revision > run.revision {
                continue;
            }
            let payload: crate::delivery_runtime::PublishImplementationEffectPayload =
                decode_canonical(&intent.request_json, &intent.request_digest)?;
            let Some(prepared_node) = prepared.get(&payload.work_node_id) else {
                // A missing stage preparation receipt cannot authorize a graph edge.
                continue;
            };
            let proof = crate::delivery_runtime::validate_work_node_publication_receipt(
                &accepted.proposal,
                prepared_node,
                &run.project_id,
                &config.repositories,
                stored,
                expected_revision,
            )?;
            match publications.get(&payload.work_node_id) {
                Some((previous_revision, _, _)) if *previous_revision == expected_revision => {
                    return Err(
                        "multiple publication receipts target one node at the same stage".into(),
                    );
                }
                Some((previous_revision, _, _)) if *previous_revision > expected_revision => {}
                _ => {
                    publications.insert(
                        payload.work_node_id,
                        (expected_revision, stored.clone(), proof),
                    );
                }
            }
        }
    }

    let current_publication = publications
        .values()
        .find(|(revision, _, _)| *revision == run.revision);
    let Some((_, current_receipt, current_proof)) = current_publication else {
        return Ok(false);
    };
    let mut prepared_nodes = prepared.values().cloned().collect::<Vec<_>>();
    let mut base_refreshes = prepared_nodes
        .iter()
        .filter_map(|node| node.base_refresh.clone())
        .collect::<Vec<_>>();
    prepared_nodes.sort_by(|left, right| left.work_node_id.cmp(&right.work_node_id));
    base_refreshes.sort_by(|left, right| left.branch.cmp(&right.branch));
    let mut prepared_receipt = PreparedWorktreesEffectReceipt {
        schema_version: 1,
        ticket_run_id: run.ticket_run_id.clone(),
        work_nodes: prepared_nodes,
        base_refreshes,
    };
    prepared_receipt
        .work_nodes
        .sort_by(|left, right| left.work_node_id.cmp(&right.work_node_id));

    let worker_nodes = validated
        .nodes_in_execution_order
        .iter()
        .filter(|node| node.role == crate::domain::types::Role::Worker)
        .collect::<Vec<_>>();
    if publications.len() == worker_nodes.len() {
        let publication_receipts = publications
            .values()
            .map(|(_, receipt, _)| receipt.clone())
            .collect::<Vec<_>>();
        let proof = crate::delivery_runtime::validate_implementation_publication_receipt(
            &accepted.proposal,
            &prepared_receipt,
            &run.project_id,
            &config.repositories,
            &publication_receipts,
        )?;
        let publication_bindings = publications
            .iter()
            .map(|(work_node_id, (_, receipt, _))| {
                serde_json::json!({
                    "work_node_id": work_node_id,
                    "operation_id": receipt.intent().operation_id,
                    "receipt_digest": sha256_hex(receipt.receipt_json().as_bytes()),
                })
            })
            .collect::<Vec<_>>();
        let prepared_bindings = worker_nodes
            .iter()
            .map(|node| prepared_sources.get(&node.id).cloned())
            .collect::<Option<Vec<_>>>()
            .ok_or("prepared worktree receipts do not cover every implementation node")?;
        if prepared_bindings.len() != worker_nodes.len() {
            return Err("prepared worktree receipts do not cover every implementation node".into());
        }
        let receipt_digest = sha256_hex(
            serde_json::to_string(&(&accepted.plan_digest, &publication_bindings))
                .map_err(|error| error.to_string())?
                .as_bytes(),
        );
        let payload_json = serde_json::json!({
            "schema_version": 1,
            "kind": "implementation_published",
            "ticket_run_id": run.ticket_run_id,
            "source_revision": run.revision,
            "configuration_digest": accepted.configuration_digest,
            "plan_digest": accepted.plan_digest,
            "prepared_receipts": prepared_bindings,
            "publication_receipts": publication_bindings,
            "publication_set_digest": receipt_digest,
        })
        .to_string();
        let durable = durable_host_input(
            &format!(
                "implementation-published:{}:{}",
                run.ticket_run_id, receipt_digest
            ),
            &payload_json,
        );
        store.commit_ticket_transition(
            owner_generation,
            &run.ticket_run_id,
            Revision(run.revision),
            &durable,
            Input::ImplementationPublished(proof),
            "host-validated complete implementation publication receipts",
            &payload_json,
            &[],
        )?;
        return Ok(true);
    }

    let current_node = validated
        .nodes_in_execution_order
        .iter()
        .find(|node| node.id == *current_proof.work_node_id())
        .ok_or("publication proof names a node outside the validated plan")?;
    if current_node
        .depends_on
        .iter()
        .any(|dependency| !publications.contains_key(&dependency.node))
    {
        return Ok(false);
    }
    if let WorkBaseSource::PredecessorWorkNodeHead { node } = &current_node.base {
        let (Some((_, _, predecessor)), Some(prepared_node)) =
            (publications.get(node), prepared.get(&current_node.id))
        else {
            return Ok(false);
        };
        if prepared_node.base_sha != predecessor.head() {
            return Ok(false);
        }
    }

    let Some(next_node) = worker_nodes.into_iter().find(|node| {
        !publications.contains_key(&node.id)
            && node
                .depends_on
                .iter()
                .all(|dependency| publications.contains_key(&dependency.node))
    }) else {
        // No ready node means at least one predecessor receipt is absent or stale.
        return Ok(false);
    };
    let expected_base_sha = match &next_node.base {
        WorkBaseSource::ControllerObservedCommit { commit } => commit.clone(),
        WorkBaseSource::PredecessorWorkNodeHead { node } => {
            let Some((_, _, predecessor)) = publications.get(node) else {
                return Ok(false);
            };
            predecessor.head().to_owned()
        }
    };
    let next_revision = run
        .revision
        .checked_add(1)
        .ok_or("TicketRun revision overflow")?;
    let commit_mode = prepared
        .values()
        .next()
        .map(|node| node.commit_mode)
        .ok_or("accepted Worker plan has no prepared commit mode")?;
    let payload = PrepareWorktreesEffectPayload {
        schema_version: 1,
        source_revision: next_revision,
        configuration_digest: configuration_digest.clone(),
        ticket_namespace: run.namespace.clone(),
        ticket_id: run.ticket_id.clone(),
        ticket_run_id: run.ticket_run_id.clone(),
        work_nodes: vec![crate::delivery_runtime::PreparedWorktreeNodeRequest {
            work_node_id: next_node.id.clone(),
            repository_id: next_node.repository.clone(),
            expected_base_sha,
            commit_mode,
        }],
    };
    let (request_json, request_digest) =
        crate::delivery_runtime::canonical_delivery_payload(&payload)?;
    let operation_id = OperationId::parse(format!(
        "prepare-{}",
        sha256_hex(
            format!(
                "{}:{}:{}:{}",
                accepted.plan_digest,
                next_node.id,
                current_proof.work_node_id(),
                sha256_hex(current_receipt.receipt_json().as_bytes()),
            )
            .as_bytes()
        )
    ))?;
    let effect = EffectIntent {
        project_id: run.project_id.clone(),
        subject_type: "ticket_run".into(),
        subject_id: run.ticket_run_id.as_str().into(),
        operation_id: operation_id.as_str().to_owned(),
        logical_key: format!(
            "{}:prepare:{}:{}",
            run.ticket_run_id, accepted.plan_digest, next_node.id
        ),
        kind: effect_name(EffectKind::PrepareWorktrees).into(),
        request_json,
        request_digest,
        expected_revision: Some(next_revision),
    };
    let payload_json = serde_json::json!({
        "schema_version": 1,
        "kind": "work_node_published",
        "ticket_run_id": run.ticket_run_id,
        "source_revision": run.revision,
        "work_node_id": current_proof.work_node_id(),
        "head": current_proof.head(),
        "next_work_node_id": next_node.id,
    })
    .to_string();
    let durable = durable_host_input(
        &format!(
            "work-node-published:{}:{}",
            run.ticket_run_id,
            current_proof.work_node_id()
        ),
        &payload_json,
    );
    store.commit_ticket_transition(
        owner_generation,
        &run.ticket_run_id,
        Revision(run.revision),
        &durable,
        Input::WorkNodePublished(current_proof.clone()),
        "host-validated node publication and scheduled the next ready work node",
        &payload_json,
        &[effect],
    )?;
    Ok(true)
}

fn advance_approved_merge_procedure(
    store: &mut ConfigStore,
    owner_generation: u64,
    now_unix: i64,
    run: &crate::store::scheduler::ActiveTicketRun,
    receipts: &[crate::store::SucceededEffectReceipt],
) -> Result<bool, String> {
    use crate::merge_executor::{
        MergeStepEffectRequest, MergeStepReceipt, MergeVerificationReceipt,
    };
    use crate::merge_policy::MergeProcedureOperation;

    let revision = Revision(run.revision);
    let Some(item) = store.merge_work_item(&run.project_id, &run.ticket_run_id, revision)? else {
        return Ok(false);
    };
    let mut completed = Vec::<MergeStepReceipt>::new();
    let mut verification = None;
    for stored in receipts {
        let effect = stored.intent();
        if effect.kind != effect_name(EffectKind::Merge)
            || effect.project_id != run.project_id
            || effect.subject_type != "ticket_run"
            || effect.subject_id != run.ticket_run_id.as_str()
            || effect.expected_revision != Some(run.revision)
        {
            continue;
        }
        let request: MergeStepEffectRequest = match serde_json::from_str(&effect.request_json) {
            Ok(request) => request,
            Err(_) => continue,
        };
        if request.work_id != item.work_id
            || request.awaiting_merge_revision != revision
            || request.assessed_revision != item.assessed_revision
        {
            continue;
        }
        if let Ok(receipt) = serde_json::from_str::<MergeStepReceipt>(stored.receipt_json()) {
            if receipt.step_key != request.step_key
                || receipt.operation_key.is_empty()
                || receipt.request_digest != receipt.effect_intent.request_digest
                || receipt.acknowledgement.operation_key != receipt.operation_key
                || receipt.acknowledgement.request_digest != receipt.request_digest
                || !matches!(
                    receipt.certainty,
                    crate::forge::EffectCertainty::Applied
                        | crate::forge::EffectCertainty::Recovered
                )
            {
                continue;
            }
            if !request.prior_receipts.is_empty() && request.prior_receipts != completed {
                continue;
            }
            completed.push(receipt);
        } else if let Ok(receipt) =
            serde_json::from_str::<MergeVerificationReceipt>(stored.receipt_json())
            && item.document.procedure.steps.iter().any(|step| {
                step.key == request.step_key
                    && matches!(
                        step.operation,
                        MergeProcedureOperation::VerifyMergeCommit { .. }
                    )
            })
            && request.prior_receipts == completed
        {
            verification = Some(receipt);
        }
    }
    if let Some(verified) =
        verification.filter(|verified| merge_verification_matches(verified, &item, &completed))
    {
        let payload = serde_json::json!({
            "schema_version":1,"kind":"merge_verified","ticket_run_id":run.ticket_run_id,
            "source_revision":run.revision,"work_id":item.work_id,"merge_commit_sha":verified.merge_commit_sha,
            "included_head_sha":verified.included_head_sha,
        }).to_string();
        let input = durable_host_input(&format!("merge-verified:{}", item.work_id), &payload);
        store.commit_ticket_transition(
            owner_generation,
            &run.ticket_run_id,
            revision,
            &input,
            Input::MergeVerified,
            "host verified the exact approved merge procedure and commit receipt",
            &payload,
            &[],
        )?;
        return Ok(true);
    }

    // A provider-reconciled prepared-body step proves the old effect's exact
    // target is already present, but it does not authorize continuing into a
    // merge when the immutable work item has no execution-time base guard.
    // Start a fresh assessment now; this preserves the body receipt while
    // ensuring no later step is emitted under the stale approval.
    if item.document.authority.execution_time_base_guard != crate::merge_policy::EvidenceState::Pass
        && completed.len() == 1
        && item.document.procedure.steps.first().is_some_and(|first| {
            first.key == completed[0].step_key
                && matches!(
                    first.operation,
                    MergeProcedureOperation::UpdatePullRequestBody { .. }
                )
        })
        && item.document.procedure.steps.len() > 1
    {
        let receipt = &completed[0];
        let subject = &item.document.assessment.subject;
        let body_matches_work = match &receipt.effect_intent.operation {
            crate::forge::MergeEffectOperation::UpdateBody(body) => {
                let expected_body_digest = item
                    .document
                    .prepared_body
                    .as_deref()
                    .map(|body| sha256_hex(body.as_bytes()));
                body.pull.number.to_string() == subject.pull_request_id
                    && body.pull.expected_node_id.as_deref()
                        == Some(subject.pull_request_node_id.as_str())
                    && body.pull.repository.expected_id == Some(subject.forge_repository_id)
                    && body.pull.repository.host == subject.forge_host
                    && body.expected_head_sha == subject.head_sha
                    && item.document.prepared_body.as_deref() == Some(body.exact_body.as_str())
                    && expected_body_digest.as_deref() == Some(body.approved_body_digest.as_str())
            }
            _ => false,
        };
        if !body_matches_work {
            return Ok(false);
        }
        let receipt_digest = crate::domain::ids::Digest::parse(sha256_hex(
            crate::store::canonical_json(receipt)?.as_bytes(),
        ))?;
        let proof = crate::engine::reducer::MergeReassessmentProof::from_reconciled_first_step(
            item.work_id.as_str().to_owned(),
            receipt_digest.clone(),
        )?;
        let prior_plan = store
            .latest_accepted_work_plan(&run.project_id, &run.ticket_run_id)?
            .ok_or("reassessment has no previously accepted work plan")?;
        if prior_plan.plan_digest != item.accepted_plan_digest {
            return Err("reassessment MergeWork does not bind the current accepted plan".into());
        }
        let payload = serde_json::json!({
            "schema_version": 1,
            "kind": "merge_reassessment_required",
            "ticket_run_id": run.ticket_run_id,
            "source_revision": run.revision,
            "work_id": item.work_id,
            "receipt_digest": receipt_digest,
            "required_next_action": "reassess only the existing work against the current protected base; preserve the same work-node IDs, repositories, tasks, dependencies, and accepted scope; the controller will refresh the owned branch and require a fresh Reviewer result, Merge Decision, and human approval",
            "prior_accepted_plan_digest": prior_plan.plan_digest,
            "prior_accepted_plan": prior_plan.proposal,
        })
        .to_string();
        let input = durable_host_input(
            &format!("merge-reassessment:{}:{}", item.work_id, run.revision),
            &payload,
        );
        store.commit_ticket_transition(
            owner_generation,
            &run.ticket_run_id,
            revision,
            &input,
            Input::MergeReassessmentRequired(proof),
            "host reconciled the prepared body but the saved merge work has no execution-time base guard; a fresh assessment and approval are required",
            &payload,
            &[],
        )?;
        return Ok(true);
    }
    let Some(next_index) = item
        .document
        .procedure
        .steps
        .iter()
        .position(|step| !completed.iter().any(|receipt| receipt.step_key == step.key))
    else {
        return Ok(false);
    };
    let step = &item.document.procedure.steps[next_index];
    if completed.len() != next_index {
        return Ok(false);
    }
    // Verification is a read-only terminal step. It is scheduled through the same durable
    // outbox as mutations so a restart repeats only a fresh observation.
    let request_id = crate::domain::ids::HumanRequestId::parse(format!(
        "merge-review-{}",
        item.document.intent_evidence_id
    ))?;
    let request = MergeStepEffectRequest {
        schema_version: 1,
        work_id: item.work_id.clone(),
        request_id,
        assessed_revision: item.assessed_revision,
        awaiting_merge_revision: item.awaiting_merge_revision,
        step_key: step.key.clone(),
        prior_receipts: completed,
    };
    let request_json = crate::store::canonical_json(&request)?;
    let operation_id = OperationId::parse(format!(
        "merge-{}-{:03}-{}",
        item.work_id, next_index, step.key
    ))?;
    let effect = EffectIntent {
        project_id: run.project_id.clone(),
        subject_type: "ticket_run".into(),
        subject_id: run.ticket_run_id.as_str().into(),
        operation_id: operation_id.as_str().into(),
        logical_key: format!(
            "{}:{}:{}:{:03}:{}",
            run.ticket_run_id, run.revision, item.work_id, next_index, step.key
        ),
        kind: effect_name(EffectKind::Merge).into(),
        request_digest: sha256_hex(request_json.as_bytes()),
        request_json,
        expected_revision: Some(run.revision),
    };
    let _ = now_unix;
    store.enqueue_effect(owner_generation, &effect)?;
    Ok(true)
}

fn find_verified_merge_receipt(
    item: &crate::store::merge_work::MergeWorkItem,
    receipts: &[crate::store::SucceededEffectReceipt],
) -> Option<crate::merge_executor::MergeVerificationReceipt> {
    use crate::merge_executor::{
        MergeStepEffectRequest, MergeStepReceipt, MergeVerificationReceipt,
    };
    use crate::merge_policy::MergeProcedureOperation;

    let verify_index = item.document.procedure.steps.len().checked_sub(1)?;
    let verify_step = item.document.procedure.steps.get(verify_index)?;
    if !matches!(
        verify_step.operation,
        MergeProcedureOperation::VerifyMergeCommit { .. }
    ) {
        return None;
    }

    let mut completed = Vec::<MergeStepReceipt>::new();
    for stored in receipts {
        let effect = stored.intent();
        if effect.kind != effect_name(EffectKind::Merge)
            || effect.project_id != item.project_id
            || effect.subject_type != "ticket_run"
            || effect.subject_id != item.ticket_run_id.as_str()
            || effect.expected_revision != Some(item.awaiting_merge_revision.0)
        {
            continue;
        }
        let request: MergeStepEffectRequest =
            match decode_canonical(&effect.request_json, &effect.request_digest) {
                Ok(request) => request,
                Err(_) => continue,
            };
        if request.schema_version != 1
            || request.work_id != item.work_id
            || request.awaiting_merge_revision != item.awaiting_merge_revision
            || request.assessed_revision != item.assessed_revision
        {
            continue;
        }
        if let Ok(step_receipt) =
            decode_canonical_receipt::<MergeStepReceipt>(stored.receipt_json())
        {
            let expected_operation = item
                .document
                .procedure
                .steps
                .iter()
                .position(|step| step.key == request.step_key)
                .map(|index| format!("merge-{}-{index:03}-{}", item.work_id, request.step_key));
            if expected_operation.as_deref() != Some(effect.operation_id.as_str())
                || step_receipt.step_key != request.step_key
                || step_receipt.operation_key.is_empty()
                || step_receipt.request_digest != step_receipt.effect_intent.request_digest
                || step_receipt.acknowledgement.operation_key != step_receipt.operation_key
                || step_receipt.acknowledgement.request_digest != step_receipt.request_digest
                || !matches!(
                    step_receipt.certainty,
                    crate::forge::EffectCertainty::Applied
                        | crate::forge::EffectCertainty::Recovered
                )
                || request.prior_receipts != completed
            {
                continue;
            }
            completed.push(step_receipt);
            continue;
        }

        let Ok(verified) =
            decode_canonical_receipt::<MergeVerificationReceipt>(stored.receipt_json())
        else {
            continue;
        };
        let expected_request_id = crate::domain::ids::HumanRequestId::parse(format!(
            "merge-review-{}",
            item.document.intent_evidence_id
        ))
        .ok()?;
        if request.step_key != verify_step.key
            || request.prior_receipts != completed
            || request.request_id != expected_request_id
            || !merge_verification_matches(&verified, item, &completed)
        {
            continue;
        }
        return Some(verified);
    }
    None
}

fn merge_verification_matches(
    verified: &crate::merge_executor::MergeVerificationReceipt,
    item: &crate::store::merge_work::MergeWorkItem,
    completed: &[crate::merge_executor::MergeStepReceipt],
) -> bool {
    use crate::merge_executor::MergeMethodEvidence;
    use crate::merge_policy::MergeProcedureOperation;

    !(item.document.procedure.steps.last().is_none_or(|step| {
        !matches!(
            &step.operation,
            MergeProcedureOperation::VerifyMergeCommit { .. }
        )
    }) || completed.len() + 1 != item.document.procedure.steps.len()
        || completed.iter().enumerate().any(|(index, receipt)| {
            item.document
                .procedure
                .steps
                .get(index)
                .is_none_or(|step| step.key != receipt.step_key)
        })
        || verified.included_head_sha != item.document.evidence.subject.head_sha
        || verified.merge_method != item.document.procedure.method
        || verified.base_ancestry.comparison_base_sha != item.document.evidence.subject.base_sha
        || verified.base_ancestry.comparison_head_sha != verified.base_parent_sha
        || verified.base_ancestry.behind_by != 0
        || match &verified.method_evidence {
            MergeMethodEvidence::DirectMergeAcknowledgement {
                operation_key,
                request_digest,
            } => !completed.iter().any(|receipt| {
                receipt.operation_key == *operation_key
                    && receipt.request_digest == *request_digest
                    && receipt.acknowledgement.resulting_merge_sha.as_deref()
                        == Some(verified.merge_commit_sha.as_str())
                    && matches!(
                        &receipt.effect_intent.operation,
                        crate::forge::MergeEffectOperation::DirectMerge(intent)
                            if intent.method == verified.merge_method
                    )
            }),
            MergeMethodEvidence::MergeCommitParents { parent_count } => {
                verified.merge_method != crate::domain::types::MergeMethod::Merge
                    || *parent_count != 2
            }
            MergeMethodEvidence::SingleParentCommit { parent_sha } => {
                !matches!(
                    verified.merge_method,
                    crate::domain::types::MergeMethod::Squash
                        | crate::domain::types::MergeMethod::Rebase
                ) || parent_sha != &verified.base_parent_sha
            }
        }
        || verified.expected_trailers
            != item
                .document
                .procedure
                .steps
                .iter()
                .find_map(|step| {
                    if let MergeProcedureOperation::VerifyMergeCommit { expected_trailers } =
                        &step.operation
                    {
                        Some(expected_trailers.clone())
                    } else {
                        None
                    }
                })
                .unwrap_or_default())
}

fn validate_prepared_stage_against_plan(
    store: &ConfigStore,
    config: &Config,
    configuration_digest: &Digest,
    run: &crate::store::scheduler::ActiveTicketRun,
    receipts: &[crate::store::SucceededEffectReceipt],
    request: &PrepareWorktreesEffectPayload,
) -> Result<bool, String> {
    use crate::engine::orchestration::{ValidatedPlan, WorkBaseSource, WorkNodeId};

    let Some(accepted) = store.latest_accepted_work_plan(&run.project_id, &run.ticket_run_id)?
    else {
        return Ok(false);
    };
    if accepted.configuration_digest != *configuration_digest
        || request.ticket_run_id != run.ticket_run_id
        || request.configuration_digest != accepted.configuration_digest
    {
        return Ok(false);
    }
    let project = config
        .projects
        .get(&run.project_id)
        .ok_or("preparing TicketRun Project is no longer configured")?;
    let validated: ValidatedPlan = accepted.validate_for(project, configuration_digest)?;
    let mut prepared = std::collections::BTreeMap::<WorkNodeId, PreparedWorktreeReceiptNode>::new();
    for stored in receipts
        .iter()
        .filter(|stored| stored.intent().kind == effect_name(EffectKind::PrepareWorktrees))
    {
        let payload: PrepareWorktreesEffectPayload = decode_canonical(
            &stored.intent().request_json,
            &stored.intent().request_digest,
        )?;
        if payload.ticket_run_id != run.ticket_run_id
            || payload.configuration_digest != accepted.configuration_digest
        {
            continue;
        }
        let receipt: PreparedWorktreesEffectReceipt =
            decode_canonical_receipt(stored.receipt_json())?;
        crate::delivery_runtime::validate_prepared_receipt(&payload, &receipt)?;
        for node in receipt.work_nodes {
            prepared.insert(node.work_node_id.clone(), node);
        }
    }
    let mut published = std::collections::BTreeMap::<
        WorkNodeId,
        crate::delivery_runtime::ValidatedWorkNodePublication,
    >::new();
    for stored in receipts
        .iter()
        .filter(|stored| stored.intent().kind == effect_name(EffectKind::PublishImplementation))
    {
        let publication: crate::delivery_runtime::PublishImplementationEffectPayload =
            decode_canonical(
                &stored.intent().request_json,
                &stored.intent().request_digest,
            )?;
        let Some(prepared_node) = prepared.get(&publication.work_node_id) else {
            continue;
        };
        if prepared_node.base_refresh.is_some()
            && publication.expected_base_sha != prepared_node.base_sha
        {
            // The old publication remains historical evidence, but cannot be
            // rebound to the host-refreshed worktree as current authority.
            continue;
        }
        let Some(revision) = stored.intent().expected_revision else {
            continue;
        };
        let proof = crate::delivery_runtime::validate_work_node_publication_receipt(
            &accepted.proposal,
            prepared_node,
            &run.project_id,
            &config.repositories,
            stored,
            revision,
        )?;
        published.insert(publication.work_node_id, proof);
    }

    for requested in &request.work_nodes {
        let Some(node) = validated.nodes_in_execution_order.iter().find(|node| {
            node.id == requested.work_node_id && node.role == crate::domain::types::Role::Worker
        }) else {
            return Ok(false);
        };
        if node.repository != requested.repository_id
            || node
                .depends_on
                .iter()
                .any(|dependency| !published.contains_key(&dependency.node))
        {
            return Ok(false);
        }
        let expected_base = match &node.base {
            WorkBaseSource::ControllerObservedCommit { commit } => commit.as_str(),
            WorkBaseSource::PredecessorWorkNodeHead { node } => {
                let Some(predecessor) = published.get(node) else {
                    return Ok(false);
                };
                predecessor.head()
            }
        };
        if requested.expected_base_sha != expected_base {
            return Ok(false);
        }
    }
    Ok(true)
}

fn durable_host_input(message_id: &str, payload: &str) -> DurableInput {
    DurableInput {
        producer_id: "rex-projects-host-transition".into(),
        message_id: message_id.into(),
        content_digest: durable_input_digest("ticket_run", payload),
        recipient: "ticket_run".into(),
        payload: payload.into(),
    }
}

fn completion_effect_intent(
    project_id: &crate::domain::ids::ProjectId,
    ticket_run_id: &crate::domain::ids::TicketRunId,
    source_revision: u64,
    effect_revision: u64,
) -> Result<EffectIntent, String> {
    let payload = serde_json::json!({
        "schema_version": 1,
        "project_id": project_id,
        "ticket_run_id": ticket_run_id,
        "ticket_run_revision": effect_revision,
    });
    let request_json = serde_json::to_string(&payload).map_err(|error| error.to_string())?;
    let operation_id = OperationId::parse(format!(
        "complete-{}",
        sha256_hex(format!("{}:{}:complete_ticket", ticket_run_id, source_revision).as_bytes())
    ))?;
    Ok(EffectIntent {
        project_id: project_id.clone(),
        subject_type: "ticket_run".into(),
        subject_id: ticket_run_id.as_str().into(),
        operation_id: operation_id.as_str().to_owned(),
        logical_key: format!("{}:{}:complete_ticket", ticket_run_id, source_revision),
        kind: effect_name(EffectKind::CompleteTicket).into(),
        request_digest: sha256_hex(request_json.as_bytes()),
        request_json,
        expected_revision: Some(effect_revision),
    })
}

fn validate_prepare_binding(
    payload: &PrepareWorktreesEffectPayload,
    run: &crate::store::scheduler::ActiveTicketRun,
    revision: u64,
) -> Result<(), String> {
    if payload.schema_version != 1
        || payload.ticket_run_id != run.ticket_run_id
        || payload.ticket_namespace != run.namespace
        || payload.ticket_id != run.ticket_id
        || payload.source_revision != revision
        || payload.work_nodes.is_empty()
        || payload.work_nodes.len() > 64
    {
        return Err("prepare worktree effect is stale or has invalid scope".into());
    }
    Ok(())
}

fn decode_canonical<T: serde::de::DeserializeOwned>(json: &str, digest: &str) -> Result<T, String> {
    if sha256_hex(json.as_bytes()) != digest {
        return Err("persisted host effect request digest does not match its bytes".into());
    }
    let value = crate::protocol::parse_unique::<serde_json::Value>(json.as_bytes())
        .map_err(|error| format!("persisted host effect request is invalid: {error}"))?;
    if serde_json::to_string(&value).map_err(|error| error.to_string())? != json {
        return Err("persisted host effect request is not canonical JSON".into());
    }
    serde_json::from_value(value)
        .map_err(|error| format!("persisted host effect request has invalid schema: {error}"))
}

fn decode_canonical_receipt<T: serde::de::DeserializeOwned>(json: &str) -> Result<T, String> {
    if json.len() > 1_048_576 {
        return Err("persisted host effect receipt exceeds its size limit".into());
    }
    let value = crate::protocol::parse_unique::<serde_json::Value>(json.as_bytes())
        .map_err(|error| format!("persisted host effect receipt is invalid: {error}"))?;
    serde_json::from_value(value)
        .map_err(|error| format!("persisted host effect receipt has invalid schema: {error}"))
}

fn effect_name(kind: EffectKind) -> &'static str {
    crate::engine::reducer::effect_name(&kind)
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    format!("{:x}", sha2::Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::delivery_runtime::{
        PrepareWorktreesEffectPayload, PreparedWorktreeNodeRequest, PreparedWorktreeReceiptNode,
        PreparedWorktreesEffectReceipt,
    };
    use crate::domain::ids::{Digest, RepositoryId, TicketId, TicketNamespace, TicketRunId};
    use crate::domain::types::CommitMode;
    use crate::engine::orchestration::WorkNodeId;

    use crate::delivery_runtime::validate_prepared_receipt;

    fn request() -> PrepareWorktreesEffectPayload {
        PrepareWorktreesEffectPayload {
            schema_version: 1,
            source_revision: 2,
            configuration_digest: Digest::parse("a".repeat(64)).unwrap(),
            ticket_namespace: TicketNamespace::parse("tenant-a").unwrap(),
            ticket_id: TicketId::parse("PAY-12").unwrap(),
            ticket_run_id: TicketRunId::parse("run-12").unwrap(),
            work_nodes: vec![PreparedWorktreeNodeRequest {
                work_node_id: WorkNodeId::parse("implementation").unwrap(),
                repository_id: RepositoryId::parse("service").unwrap(),
                expected_base_sha: "b".repeat(40),
                commit_mode: CommitMode::Native,
            }],
        }
    }

    fn receipt() -> PreparedWorktreesEffectReceipt {
        PreparedWorktreesEffectReceipt {
            schema_version: 1,
            ticket_run_id: TicketRunId::parse("run-12").unwrap(),
            work_nodes: vec![PreparedWorktreeReceiptNode {
                work_node_id: WorkNodeId::parse("implementation").unwrap(),
                repository_id: RepositoryId::parse("service").unwrap(),
                worktree_path: PathBuf::from("/state/worktrees/run-12/implementation"),
                branch: "rex/run-12/implementation".into(),
                base_sha: "b".repeat(40),
                commit_mode: CommitMode::Native,
                base_refresh: None,
                base_refresh_source: None,
            }],
            base_refreshes: Vec::new(),
        }
    }

    #[test]
    fn prepared_worktree_receipt_must_cover_exact_requested_identity_and_base() {
        validate_prepared_receipt(&request(), &receipt()).unwrap();

        let mut changed_base = receipt();
        changed_base.work_nodes[0].base_sha = "c".repeat(40);
        assert!(validate_prepared_receipt(&request(), &changed_base).is_err());

        let mut extra_node = receipt();
        extra_node.work_nodes.push(extra_node.work_nodes[0].clone());
        assert!(validate_prepared_receipt(&request(), &extra_node).is_err());

        let mut wrong_run = receipt();
        wrong_run.ticket_run_id = TicketRunId::parse("run-other").unwrap();
        assert!(validate_prepared_receipt(&request(), &wrong_run).is_err());
    }

    #[test]
    fn merge_work_receipt_consumer_enforces_approval_and_builds_postmortem_inbox() {
        merge_review_approval_fixture(false, false);
    }

    #[test]
    fn verified_merge_persists_required_operator_plan_and_launch_readiness() {
        merge_review_approval_fixture(true, false);
    }

    #[test]
    fn reconciled_prepared_body_reassesses_before_old_merge_step_is_queued() {
        merge_review_approval_fixture(false, true);
    }

    fn merge_review_approval_fixture(required_operations: bool, reassessment_case: bool) {
        use crate::domain::ids::{
            Digest, HumanRequestId, OperationId, ProjectId, Revision, TicketRunId,
        };
        use crate::domain::types::{MergeExecutor, MergeMethod};
        use crate::engine::orchestration::{
            MergeProcedureStepKind, PostMergeVerification, PostMergeVerificationKind,
        };
        use crate::engine::reducer::EffectKind;
        use crate::forge::{
            BodyUpdateIntent, CommentIntent, CommitComparison, CommitObservation,
            DirectMergeIntent, EffectAcknowledgement, EffectCertainty, Forge, ForgeError,
            ForgeObservation, MergeEffectIntent, MergeEffectOperation, Observed, PullRequestRef,
            Reconciliation, RepositoryRef,
        };
        use crate::human_runtime::{
            HumanAuthorityMaterial, HumanDecisionChoice, HumanDecisionIntent, HumanPurpose,
        };
        use crate::launch::{RexView, RexViewKind};
        use crate::merge_executor::{
            MergeBaseAncestryProof, MergeMethodEvidence, MergeProcedureExecutor,
            MergeStepEffectRequest, MergeStepReceipt, MergeVerificationReceipt,
        };
        use crate::merge_policy::{
            Confidence, EvidenceState, MergeEvidenceSnapshot, MergePolicy, MergeProcedureOperation,
            MergeProcedureStep, MergeSubject, RiskWeights, evaluate_merge_policy,
        };
        use crate::store::merge_work::{MergeWorkDocument, MergeWorkItem};
        use crate::store::{
            ConfigStore, EffectOutcome, ExpectedRevision, OwnerMetadata, ProjectRecord,
        };
        use rusqlite::params;
        use sha2::Digest as _;
        use std::path::Path;
        use std::{fs, os::unix::fs::PermissionsExt};
        use tempfile::tempdir;

        fn digest(ch: char) -> Digest {
            Digest::parse(ch.to_string().repeat(64)).unwrap()
        }

        struct VerificationForge {
            commit: CommitObservation,
        }

        impl Forge for VerificationForge {
            fn observe(&self, _: &PullRequestRef) -> Result<ForgeObservation, ForgeError> {
                Err(ForgeError(
                    "verification fixture supplies its observation directly".into(),
                ))
            }

            fn observe_commit(
                &self,
                _: &RepositoryRef,
                sha: &str,
            ) -> Result<Observed<CommitObservation>, ForgeError> {
                if self.commit.sha != sha {
                    return Err(ForgeError("unexpected merge commit SHA".into()));
                }
                Ok(Observed::Complete {
                    value: self.commit.clone(),
                    pages: 1,
                    digest: digest('a'),
                })
            }

            fn compare_commits(
                &self,
                _: &RepositoryRef,
                base_sha: &str,
                head_sha: &str,
            ) -> Result<Observed<CommitComparison>, ForgeError> {
                Ok(Observed::Complete {
                    value: CommitComparison {
                        base_sha: base_sha.into(),
                        head_sha: head_sha.into(),
                        status: "ahead".into(),
                        ahead_by: 1,
                        behind_by: 0,
                    },
                    pages: 1,
                    digest: digest('b'),
                })
            }

            fn update_body(
                &self,
                _: &BodyUpdateIntent,
            ) -> Result<EffectAcknowledgement, ForgeError> {
                Err(ForgeError("unused verification fixture method".into()))
            }

            fn post_comment(&self, _: &CommentIntent) -> Result<EffectAcknowledgement, ForgeError> {
                Err(ForgeError("unused verification fixture method".into()))
            }

            fn execute_merge(
                &self,
                _: &DirectMergeIntent,
            ) -> Result<EffectAcknowledgement, ForgeError> {
                Err(ForgeError("unused verification fixture method".into()))
            }

            fn reconcile(&self, _: &MergeEffectIntent) -> Result<Reconciliation, ForgeError> {
                Err(ForgeError("unused verification fixture method".into()))
            }
        }

        fn item(
            project_id: ProjectId,
            ticket_run_id: TicketRunId,
            config_digest: Digest,
            accepted_plan_digest: Digest,
            reassessment_case: bool,
        ) -> MergeWorkItem {
            let comments = Vec::<crate::forge::IssueComment>::new();
            let comments_digest = crate::forge::canonical_digest(&comments).unwrap();
            let subject = MergeSubject {
                repository_id: "example".into(),
                forge: "github".into(),
                forge_host: "github.com".into(),
                forge_repository_id: 7,
                pull_request_id: "9".into(),
                pull_request_node_id: "PR_node".into(),
                head_sha: "a".repeat(40),
                base_ref: "main".into(),
                base_sha: "b".repeat(40),
                config_digest: config_digest.clone(),
                instruction_digest: digest('2'),
                hooks_digest: digest('3'),
                remote_checks_digest: digest('4'),
                diff_digest: digest('5'),
                merge_comments_digest: comments_digest,
                base_guard_digest: Some(digest('6')),
                review_digest: digest('7'),
                prepared_body_digest: Some(if reassessment_case {
                    Digest::parse(super::sha256_hex(b"Prior body\n")).unwrap()
                } else {
                    digest('8')
                }),
            };
            let policy = MergePolicy {
                auto_merge_enabled: false,
                minimum_reliability_score: 90,
                method: MergeMethod::Squash,
                executor: MergeExecutor::Direct,
                required_checks: Vec::new(),
                required_approving_reviews: None,
                risk_weights: RiskWeights::default(),
            };
            let evidence = MergeEvidenceSnapshot {
                subject: subject.clone(),
                current_subject: subject.clone(),
                gates: Vec::new(),
                risk: Vec::new(),
                confidence: Confidence::High,
                human_review_required: true,
                execution_time_base_guard: if reassessment_case {
                    EvidenceState::Unknown
                } else {
                    EvidenceState::Pass
                },
            };
            let assessment = evaluate_merge_policy(&policy, &evidence).unwrap();
            let mut procedure_steps = Vec::new();
            if reassessment_case {
                procedure_steps.push(MergeProcedureStep {
                    key: "body".into(),
                    prerequisites: Vec::new(),
                    operation: MergeProcedureOperation::UpdatePullRequestBody {
                        expected_prior_body_digest: subject.prepared_body_digest.clone().unwrap(),
                        approved_body_digest: Digest::parse(super::sha256_hex(b"Reviewed body\n"))
                            .unwrap(),
                    },
                    instruction_digest: subject.instruction_digest.clone(),
                });
            }
            procedure_steps.extend([
                MergeProcedureStep {
                    key: "merge".into(),
                    prerequisites: if reassessment_case {
                        vec!["body".into()]
                    } else {
                        Vec::new()
                    },
                    operation: MergeProcedureOperation::ExecuteMerge {
                        expected_head_sha: subject.head_sha.clone(),
                        base_guard_rule_digest: subject.base_guard_digest.clone().unwrap(),
                    },
                    instruction_digest: subject.instruction_digest.clone(),
                },
                MergeProcedureStep {
                    key: "verify".into(),
                    prerequisites: vec!["merge".into()],
                    operation: MergeProcedureOperation::VerifyMergeCommit {
                        expected_trailers: vec![
                            "Co-authored-by: Agent <agent@example.test>".into(),
                        ],
                    },
                    instruction_digest: subject.instruction_digest.clone(),
                },
            ]);
            let procedure = crate::merge_policy::build_merge_procedure(
                policy.method,
                policy.executor,
                procedure_steps,
                &subject,
            )
            .unwrap();
            let policy_digest = crate::forge::canonical_digest(&policy).unwrap();
            let intent = crate::engine::orchestration::MergeIntentPayload {
                assessment_id: "assessment-1".into(),
                pr_identities: vec!["example#9".into()],
                policy_digest: policy_digest.clone(),
                prepared_body_digest: if reassessment_case {
                    Digest::parse(super::sha256_hex(b"Reviewed body\n")).unwrap()
                } else {
                    subject.prepared_body_digest.clone().unwrap()
                },
                steps: if reassessment_case {
                    vec![
                        crate::engine::orchestration::MergeProcedureStep {
                            kind: MergeProcedureStepKind::UpdatePullRequestBody,
                            instruction_reference: "merge.instructions#body".into(),
                            rationale: "ensure the prepared body is present".into(),
                        },
                        crate::engine::orchestration::MergeProcedureStep {
                            kind: MergeProcedureStepKind::DirectMerge,
                            instruction_reference: "merge.instructions#merge".into(),
                            rationale: "execute the approved merge".into(),
                        },
                        crate::engine::orchestration::MergeProcedureStep {
                            kind: MergeProcedureStepKind::VerifyMergeCommit,
                            instruction_reference: "merge.instructions#verify".into(),
                            rationale: "verify the resulting commit".into(),
                        },
                    ]
                } else {
                    vec![
                        crate::engine::orchestration::MergeProcedureStep {
                            kind: MergeProcedureStepKind::DirectMerge,
                            instruction_reference: "merge.instructions#merge".into(),
                            rationale: "execute the approved merge".into(),
                        },
                        crate::engine::orchestration::MergeProcedureStep {
                            kind: MergeProcedureStepKind::VerifyMergeCommit,
                            instruction_reference: "merge.instructions#verify".into(),
                            rationale: "verify the resulting commit".into(),
                        },
                    ]
                },
                post_merge_verification: vec![PostMergeVerification {
                    kind: PostMergeVerificationKind::MergeCommitRecorded,
                    instruction_reference: "merge.instructions#verify".into(),
                    rationale: "confirm the remote merge commit".into(),
                }],
            };
            let document = MergeWorkDocument {
                schema_version: 1,
                assessment_id: "assessment-1".into(),
                assessment_evidence_id: "assessment-evidence".into(),
                assessment_result_digest: digest('a'),
                intent_evidence_id: "intent-evidence".into(),
                intent_result_digest: digest('b'),
                policy: policy.clone(),
                evidence,
                baseline_issue_comments: comments,
                assessment,
                intent,
                authority: crate::merge_executor::ResolvedMergeAuthority {
                    policy_digest,
                    instruction_digest: subject.instruction_digest.clone(),
                    sources: Default::default(),
                    request_comment_proofs: Vec::new(),
                    execution_time_base_guard: if reassessment_case {
                        EvidenceState::Unknown
                    } else {
                        EvidenceState::Pass
                    },
                    base_guard_digest: subject.base_guard_digest.clone(),
                },
                procedure,
                prepared_body: reassessment_case.then(|| "Reviewed body\n".into()),
            };
            MergeWorkItem::new(
                project_id,
                ticket_run_id,
                Revision(4),
                Revision(6),
                config_digest,
                accepted_plan_digest,
                digest('d'),
                digest('e'),
                document,
            )
            .unwrap()
        }

        let temp = tempdir().unwrap();
        let mut loaded = crate::config::load(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/fixture/config.toml"),
        )
        .unwrap();
        let recipe_id = if required_operations {
            loaded.config.operation_actions.insert(
                "observe_deployment".into(),
                crate::config::OperationActionConfig::ForgeObservation,
            );
            loaded
                .config
                .repositories
                .get_mut(&crate::domain::ids::RepositoryId::parse("example").unwrap())
                .unwrap()
                .operations = Some(crate::config::RepositoryOperationsConfig {
                recipe: "required_deploy".into(),
                allowed_actions: vec!["observe_deployment".into()],
                human_approval_environments: Vec::new(),
                instruction_files: Vec::new(),
            });
            loaded.config.operation_recipes.insert(
                "required_deploy".into(),
                serde_json::from_value(serde_json::json!({
                    "targets": [{
                        "id": "deployment",
                        "repository": "example",
                        "environment": "staging",
                        "action": "observe_deployment",
                        "source": "merge_commit",
                        "success_predicate": {"kind":"target_succeeded"},
                        "timeout_seconds": 60,
                        "approval": "repository_policy"
                    }]
                }))
                .unwrap(),
            );
            loaded.digest = Digest::parse(format!(
                "{:x}",
                sha2::Sha256::digest(serde_json::to_vec(&loaded.config).unwrap())
            ))
            .unwrap();
            "required_deploy"
        } else {
            "docs_only"
        };
        let project_id = ProjectId::parse("goal_project").unwrap();
        let ticket_run_id = TicketRunId::parse("run-merge-review").unwrap();
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
        store
            .test_connection()
            .execute(
                "INSERT INTO ticket_runs(ticket_run_id,project_id,config_source,config_revision,config_digest,namespace,ticket_id,generation,internal_phase,activity,external_status,observed_status,revision,required_review_revision,external_revision) VALUES (?1,?2,'fixture',?3,?4,'github:org/repo','T-9',1,'waiting_human','blocked','in_progress','in_progress',5,5,'ticket-revision-before-approval')",
                params![ticket_run_id.as_str(), project_id.as_str(), applied.revision.0, loaded.digest.as_str()],
            )
            .unwrap();
        store
            .test_connection()
            .execute(
                "INSERT INTO ticket_run_context(ticket_run_id,project_id,project_epoch,recipe_id,goal_revision,created_at_unix) VALUES (?1,?2,1,?3,1,1)",
                params![ticket_run_id.as_str(), project_id.as_str(), recipe_id],
            )
            .unwrap();
        let generation = store
            .start_owner(&OwnerMetadata {
                owner_nonce: "merge-transition-test-owner".into(),
                state_root: temp.path().to_string_lossy().into_owned(),
                config_source: "fixture".into(),
                process_start_identity: "test-start".into(),
                executable_path: "/tmp/rex-projects-test".into(),
                executable_digest: "f".repeat(64),
                rex_endpoint: None,
                rex_server_identity: None,
                rex_session_id: None,
                rex_block_id: None,
            })
            .unwrap();
        store
            .test_connection()
            .execute(
                "UPDATE project_runtimes SET observed_lifecycle='running',controller_generation=?2 WHERE project_id=?1",
                params![project_id.as_str(), generation],
            )
            .unwrap();
        let view = RexView {
            view_id: RexView::derive_id(
                &project_id,
                RexViewKind::Ticket,
                Some("github:org/repo"),
                Some("T-9"),
                1,
            )
            .unwrap(),
            project_id: project_id.clone(),
            kind: RexViewKind::Ticket,
            ticket_namespace: Some("github:org/repo".into()),
            ticket_id: Some("T-9".into()),
            view_epoch: 1,
            rex_server_identity: "test-server".into(),
            rex_session_id: "test-session".into(),
            rex_window_id: "ticket-window".into(),
        };
        store.register_rex_view(generation, &view).unwrap();

        let accepted_proposal = crate::engine::orchestration::WorkPlan {
            nodes: vec![crate::engine::orchestration::PlannedWorkNode {
                id: crate::engine::orchestration::WorkNodeId::parse("worker").unwrap(),
                repository: crate::domain::ids::RepositoryId::parse("example").unwrap(),
                task: "Implement the accepted ticket scope".into(),
                depends_on: Vec::new(),
                required_evidence: vec!["tests".into()],
                investigation: false,
            }],
            requested_investigation_children: 0,
        };
        let persisted_plan = crate::store::accepted_plans::PersistedWorkPlan {
            schema_version: 1,
            proposal: accepted_proposal,
            observed_base_shas: std::collections::BTreeMap::from([(
                crate::domain::ids::RepositoryId::parse("example").unwrap(),
                "b".repeat(40),
            )]),
        };
        let plan_json = crate::store::canonical_json(&persisted_plan).unwrap();
        let plan_digest = Digest::parse(super::sha256_hex(plan_json.as_bytes())).unwrap();
        store.test_connection().execute(
            "INSERT INTO accepted_work_plans(project_id,ticket_run_id,accepted_revision,configuration_digest,plan_digest,plan_json,source_evidence_id,source_agent_run_id,source_message_id,source_result_digest,coordinator_agent_run_id,coordinator_role_session_id,coordinator_authority_digest,created_at_unix) VALUES (?1,?2,2,?3,?4,?5,'source-evidence','coordinator-run','source-message',?6,'coordinator-run','coordinator-session',?7,1)",
            params![project_id.as_str(), ticket_run_id.as_str(), loaded.digest.as_str(), plan_digest.as_str(), plan_json, "a".repeat(64), "b".repeat(64)],
        ).unwrap();
        let work_item = item(
            project_id.clone(),
            ticket_run_id.clone(),
            loaded.digest.clone(),
            plan_digest,
            reassessment_case,
        );
        let work_json = crate::store::canonical_json(&serde_json::json!({
            "schema_version": 1,
            "project_id": project_id,
            "ticket_run_id": ticket_run_id,
            "assessed_revision": 4,
            "awaiting_merge_revision": 6,
            "configuration_digest": loaded.digest,
            "accepted_plan_digest": work_item.accepted_plan_digest,
            "prepared_receipt_digest": work_item.prepared_receipt_digest,
            "publication_set_digest": work_item.publication_set_digest,
            "document": work_item.document,
        }))
        .unwrap();
        store
            .test_connection()
            .execute(
                "INSERT INTO merge_work_items(work_id,project_id,ticket_run_id,assessed_revision,awaiting_merge_revision,configuration_digest,accepted_plan_digest,prepared_receipt_digest,publication_set_digest,work_digest,work_json,created_at_unix) VALUES (?1,?2,?3,4,6,?4,?5,?6,?7,?1,?8,1)",
                params![
                    work_item.work_id.as_str(),
                    project_id.as_str(),
                    ticket_run_id.as_str(),
                    work_item.configuration_digest.as_str(),
                    work_item.accepted_plan_digest.as_str(),
                    work_item.prepared_receipt_digest.as_str(),
                    work_item.publication_set_digest.as_str(),
                    work_json,
                ],
            )
            .unwrap();

        let request_id = HumanRequestId::parse("merge-review-intent-evidence").unwrap();
        let authority = HumanAuthorityMaterial::MergeWorkReview {
            work_item: Box::new(work_item.clone()),
        };
        let artifact_root = temp.path().join("review-artifacts");
        fs::create_dir(&artifact_root).unwrap();
        fs::set_permissions(&artifact_root, fs::Permissions::from_mode(0o700)).unwrap();
        let request = HumanAuthorityMaterial::merge_work_review_request(
            request_id.clone(),
            work_item.clone(),
            1000,
        )
        .unwrap();
        let artifact_path =
            crate::human_runtime::write_runtime_review_artifact(&artifact_root, &request).unwrap();
        assert_eq!(request.purpose, HumanPurpose::TicketReview);
        store
            .register_human_request_with_authority(
                generation,
                &request,
                &view.view_id,
                &artifact_path,
                &authority,
                10,
            )
            .unwrap();
        let decision = HumanDecisionIntent {
            request_id: request_id.clone(),
            response_id: "approved-merge-review".into(),
            expected_subject_digest: request.subject.digest().unwrap(),
            choice: HumanDecisionChoice::Approve,
            explanation: Some("Approved the exact merge procedure.".into()),
        };
        ConfigStore::enqueue_human_decision(temp.path(), &decision, 11).unwrap();
        assert!(matches!(
            store
                .process_human_decision(generation, &decision.response_id, &request.subject, 12)
                .unwrap(),
            crate::store::human::HumanDecisionResult::Applied
        ));

        let config: crate::config::Config =
            toml::from_str(include_str!("../../examples/fixture/config.toml")).unwrap();
        assert!(super::consume_one_host_transition(
            &mut store,
            generation,
            13,
            &config,
            &loaded.digest,
        )
        .unwrap());
        let awaiting = store
            .active_ticket_runs(generation, 10)
            .unwrap()
            .into_iter()
            .find(|run| run.ticket_run_id == ticket_run_id)
            .unwrap();
        assert_eq!(awaiting.phase, super::Phase::AwaitingMerge);
        assert_eq!(awaiting.revision, 6);
        let status_intent = store
            .effect_by_logical_key(&format!(
                "{}:5:publish-status-after-merge-review",
                ticket_run_id
            ))
            .unwrap()
            .unwrap();
        let status_payload: crate::engine::ticket_effects::PublishTicketStatus =
            serde_json::from_str(&status_intent.request_json).unwrap();
        assert_eq!(
            status_payload.desired_status,
            crate::domain::types::TicketStatus::InProgress
        );
        assert_eq!(
            status_payload.expected_external_revision.as_deref(),
            Some("ticket-revision-before-approval"),
            "human approval must preserve the current external CAS revision"
        );
        let first = store
            .effect_by_logical_key(&format!(
                "{}:6:{}:000:{}",
                ticket_run_id,
                work_item.work_id,
                if reassessment_case { "body" } else { "merge" }
            ))
            .unwrap()
            .unwrap();
        let first_request: MergeStepEffectRequest =
            serde_json::from_str(&first.request_json).unwrap();
        assert_eq!(
            first_request.step_key,
            if reassessment_case { "body" } else { "merge" }
        );
        assert_eq!(first.expected_revision, Some(6));

        if reassessment_case {
            store
                .test_connection()
                .execute(
                    "UPDATE projects SET desired_lifecycle='running' WHERE project_id=?1",
                    [project_id.as_str()],
                )
                .unwrap();
            for index in 0..256 {
                let earlier_id = format!("run-earlier-{index:03}");
                store.test_connection().execute(
                    "INSERT INTO ticket_runs(ticket_run_id,project_id,config_source,config_revision,config_digest,namespace,ticket_id,generation,internal_phase,activity,external_status,observed_status,revision,required_review_revision) SELECT ?1,project_id,config_source,config_revision,config_digest,namespace,?1,generation,internal_phase,activity,external_status,observed_status,revision,required_review_revision FROM ticket_runs WHERE ticket_run_id=?2",
                    params![earlier_id, ticket_run_id.as_str()],
                ).unwrap();
                store.test_connection().execute(
                    "INSERT INTO ticket_run_context SELECT ?1,project_id,project_epoch,recipe_id,goal_revision,created_at_unix FROM ticket_run_context WHERE ticket_run_id=?2",
                    params![earlier_id, ticket_run_id.as_str()],
                ).unwrap();
            }
            let error = crate::runtime_services::merge::tests::reconcile_merge_for_store_test(
                loaded.clone(),
                &crate::effects::EffectRequest {
                    intent: first.clone(),
                    attempt_count: 1,
                    created_at_unix: 13,
                },
                &mut crate::effects::EffectContext {
                    store: &mut store,
                    owner_generation: generation,
                    now_unix: 13,
                },
            )
            .unwrap_err();
            assert_eq!(
                error,
                "merge observation requires a github.com repository URL"
            );
            store
                .test_connection()
                .execute(
                    "DELETE FROM ticket_run_context WHERE ticket_run_id LIKE 'run-earlier-%'",
                    [],
                )
                .unwrap();
            store
                .test_connection()
                .execute(
                    "DELETE FROM ticket_runs WHERE ticket_run_id LIKE 'run-earlier-%'",
                    [],
                )
                .unwrap();
        }

        let merge_kind = super::effect_name(EffectKind::Merge).to_owned();
        let initial_claim = store
            .claim_next_due_effect(generation, i64::MAX, std::slice::from_ref(&merge_kind))
            .unwrap()
            .unwrap();
        assert_eq!(initial_claim.intent.operation_id, first.operation_id);
        let operation_key = "approved-merge-operation".to_owned();
        let expected_trailers = vec!["Co-authored-by: Agent <agent@example.test>".into()];
        let pull = PullRequestRef {
            repository: RepositoryRef {
                host: "github.com".into(),
                owner: "org".into(),
                name: "repo".into(),
                expected_id: Some(7),
            },
            number: 9,
            expected_node_id: Some("PR_node".into()),
        };
        if reassessment_case {
            let operation_key = format!("{}:body", first.operation_id);
            let body = BodyUpdateIntent {
                pull: pull.clone(),
                operation_key: operation_key.clone(),
                expected_head_sha: "a".repeat(40),
                expected_prior_body_digest: Digest::parse(super::sha256_hex(b"Prior body\n"))
                    .unwrap(),
                exact_body: "Reviewed body\n".into(),
                approved_body_digest: Digest::parse(super::sha256_hex(b"Reviewed body\n")).unwrap(),
            };
            let request_digest = crate::forge::canonical_digest(&body).unwrap();
            let effect_intent = MergeEffectIntent {
                pull: pull.clone(),
                operation_key: operation_key.clone(),
                request_digest: request_digest.clone(),
                operation: MergeEffectOperation::UpdateBody(body),
                attempt_started_unix: 16,
            };
            let receipt = MergeStepReceipt {
                step_key: "body".into(),
                operation_key: operation_key.clone(),
                certainty: EffectCertainty::Recovered,
                request_digest: request_digest.clone(),
                effect_intent,
                acknowledgement: EffectAcknowledgement {
                    operation_key,
                    request_digest,
                    certainty: EffectCertainty::Recovered,
                    external_id: None,
                    external_url: None,
                    resulting_head_sha: Some("a".repeat(40)),
                    resulting_merge_sha: None,
                    reason: Some(
                        "exact prepared body observed during provider reconciliation".into(),
                    ),
                },
            };
            let receipt_json = crate::store::canonical_json(&receipt).unwrap();
            store
                .finish_effect(
                    &first.operation_id,
                    generation,
                    EffectOutcome::Succeeded,
                    Some(&receipt_json),
                )
                .unwrap();
            assert!(
                super::consume_one_host_transition(
                    &mut store,
                    generation,
                    14,
                    &config,
                    &loaded.digest,
                )
                .unwrap()
            );
            let reassessed = store
                .active_ticket_runs(generation, 10)
                .unwrap()
                .into_iter()
                .find(|run| run.ticket_run_id == ticket_run_id)
                .unwrap();
            assert_eq!(reassessed.phase, super::Phase::Planning);
            assert_eq!(reassessed.revision, 7);
            assert!(
                store
                    .effect_by_logical_key(&format!(
                        "{}:6:{}:001:merge",
                        ticket_run_id, work_item.work_id
                    ))
                    .unwrap()
                    .is_none()
            );
            let coordinator_wakes = store
                .pending_role_wake_inputs(
                    &project_id,
                    &format!("ticket_run:{ticket_run_id}:coordinator"),
                    8,
                )
                .unwrap()
                .into_iter()
                .filter(|wake| {
                    wake.source_type == "ticket_run_transition"
                        && wake.source_revision == 7
                        && wake.payload_json["ticket_run_id"] == ticket_run_id.as_str()
                })
                .collect::<Vec<_>>();
            assert_eq!(coordinator_wakes.len(), 1);
            let transition_evidence = store
                .ticket_run_transition_evidence(generation, &project_id, &ticket_run_id, 6, 1)
                .unwrap();
            assert_eq!(
                transition_evidence[0].1["kind"],
                "merge_reassessment_required"
            );
            assert_eq!(
                transition_evidence[0].1["work_id"],
                work_item.work_id.as_str()
            );
            assert!(transition_evidence[0].1["receipt_digest"].is_string());
            assert!(
                store
                    .accepted_merge_work_review_approval(&request_id, &work_item, 15)
                    .unwrap()
                    .is_some()
            );
            return;
        }
        let direct_merge = DirectMergeIntent {
            pull: pull.clone(),
            operation_key: operation_key.clone(),
            method: MergeMethod::Squash,
            expected_head_sha: "a".repeat(40),
            expected_base_sha: "b".repeat(40),
            expected_body: "Reviewed body\n".into(),
            expected_body_digest: Digest::parse(super::sha256_hex(b"Reviewed body\n")).unwrap(),
            expected_commit_message: "Reviewed body\n\nCo-authored-by: Agent <agent@example.test>"
                .into(),
            approval_expires_at_unix: Some(1000),
            expected_trailers,
        };
        let request_digest = crate::forge::canonical_digest(&direct_merge).unwrap();
        let effect_intent = MergeEffectIntent {
            pull: pull.clone(),
            operation_key: operation_key.clone(),
            request_digest: request_digest.clone(),
            operation: MergeEffectOperation::DirectMerge(direct_merge),
            attempt_started_unix: 16,
        };
        let receipt = MergeStepReceipt {
            step_key: first_request.step_key.clone(),
            operation_key: operation_key.clone(),
            certainty: EffectCertainty::Applied,
            request_digest: request_digest.clone(),
            effect_intent,
            acknowledgement: EffectAcknowledgement {
                operation_key,
                request_digest: request_digest.clone(),
                certainty: EffectCertainty::Applied,
                external_id: Some("merge-commit-1".into()),
                external_url: None,
                resulting_head_sha: Some("a".repeat(40)),
                resulting_merge_sha: Some("c".repeat(40)),
                reason: None,
            },
        };
        let receipt_json = crate::store::canonical_json(&receipt).unwrap();
        store
            .finish_effect(
                &first.operation_id,
                generation,
                EffectOutcome::Succeeded,
                Some(&receipt_json),
            )
            .unwrap();
        super::consume_one_host_transition(&mut store, generation, 14, &config, &loaded.digest)
            .unwrap();
        assert!(
            store
                .effect_by_logical_key(&format!(
                    "{}:6:{}:001:verify",
                    ticket_run_id, work_item.work_id
                ))
                .unwrap()
                .is_some()
        );

        assert_eq!(
            store
                .active_ticket_runs(generation, 10)
                .unwrap()
                .into_iter()
                .find(|run| run.ticket_run_id == ticket_run_id)
                .unwrap()
                .revision,
            6
        );

        let second = store
            .active_ticket_runs(generation, 10)
            .unwrap()
            .into_iter()
            .find(|run| run.ticket_run_id == ticket_run_id)
            .unwrap();
        assert_eq!(second.phase, super::Phase::AwaitingMerge);
        assert_eq!(second.revision, 6);
        let verify_effect = store
            .effect_by_logical_key(&format!(
                "{}:6:{}:001:verify",
                ticket_run_id, work_item.work_id
            ))
            .unwrap()
            .unwrap();
        let verify_request: MergeStepEffectRequest =
            serde_json::from_str(&verify_effect.request_json).unwrap();
        assert_eq!(verify_request.step_key, "verify");
        assert_eq!(verify_request.prior_receipts, vec![receipt.clone()]);

        let trailers = vec!["Co-authored-by: Agent <agent@example.test>".to_owned()];
        let pull = PullRequestRef {
            repository: RepositoryRef {
                host: "github.com".into(),
                owner: "org".into(),
                name: "repo".into(),
                expected_id: Some(7),
            },
            number: 9,
            expected_node_id: Some("PR_node".into()),
        };
        let commit = CommitObservation {
            sha: "c".repeat(40),
            tree_sha: "tree".into(),
            parents: vec!["d".repeat(40)],
            message: "Reviewed body\n\nCo-authored-by: Agent <agent@example.test>".into(),
        };
        let observed = ForgeObservation {
            repository: Observed::Unknown {
                reason: "not needed for commit verification".into(),
            },
            pull_request: Observed::Complete {
                value: crate::forge::PullRequestObservation {
                    repository_id: 7,
                    node_id: "PR_node".into(),
                    number: 9,
                    state: crate::forge::PullRequestState::Closed,
                    draft: false,
                    merged: true,
                    head_sha: "a".repeat(40),
                    head_ref: "feature".into(),
                    base_sha: "f".repeat(40),
                    base_ref: "main".into(),
                    body: Some("Reviewed body\n".into()),
                    merge_commit_sha: Some("c".repeat(40)),
                },
                pages: 1,
                digest: digest('c'),
            },
            files: Observed::Unknown {
                reason: "not needed for commit verification".into(),
            },
            check_runs: Observed::Unknown {
                reason: "not needed for commit verification".into(),
            },
            statuses: Observed::Unknown {
                reason: "not needed for commit verification".into(),
            },
            reviews: Observed::Unknown {
                reason: "not needed for commit verification".into(),
            },
            review_comments: Observed::Unknown {
                reason: "not needed for commit verification".into(),
            },
            review_threads: Observed::Unknown {
                reason: "not needed for commit verification".into(),
            },
            issue_comments: Observed::Unknown {
                reason: "not needed for commit verification".into(),
            },
            branch_protection: Observed::Unknown {
                reason: "not needed for commit verification".into(),
            },
            merge_commit: Observed::Unknown {
                reason: "not needed for commit verification".into(),
            },
            target_comparison: Observed::Unknown {
                reason: "not needed for commit verification".into(),
            },
        };
        let executor = MergeProcedureExecutor::new(VerificationForge { commit });
        let verified = executor
            .verify_observed_merge_for_test(
                &pull,
                &work_item.document.evidence.subject,
                MergeMethod::Squash,
                &trailers,
                &observed,
                std::slice::from_ref(&receipt),
            )
            .unwrap()
            .unwrap();
        assert_eq!(verified.base_parent_sha, "d".repeat(40));
        assert_eq!(verified.base_ancestry.comparison_base_sha, "b".repeat(40));
        assert_eq!(verified.base_ancestry.comparison_head_sha, "d".repeat(40));
        assert_eq!(verified.base_ancestry.behind_by, 0);
        assert_eq!(
            verified.method_evidence,
            MergeMethodEvidence::DirectMergeAcknowledgement {
                operation_key: "approved-merge-operation".into(),
                request_digest: request_digest.clone(),
            }
        );
        let wrong_method = MergeVerificationReceipt {
            merge_method: MergeMethod::Rebase,
            ..verified.clone()
        };
        let wrong_json = crate::store::canonical_json(&wrong_method).unwrap();
        let wrong_verify = verify_effect.clone();
        let wrong_claim = store
            .claim_next_due_effect(generation, i64::MAX, std::slice::from_ref(&merge_kind))
            .unwrap()
            .unwrap();
        assert_eq!(wrong_claim.intent.operation_id, wrong_verify.operation_id);
        store
            .finish_effect(
                &wrong_verify.operation_id,
                generation,
                EffectOutcome::Succeeded,
                Some(&wrong_json),
            )
            .unwrap();
        super::consume_one_host_transition(&mut store, generation, 18, &config, &loaded.digest)
            .unwrap();
        let still_awaiting = store
            .active_ticket_runs(generation, 10)
            .unwrap()
            .into_iter()
            .find(|run| run.ticket_run_id == ticket_run_id)
            .unwrap();
        assert_eq!(still_awaiting.phase, super::Phase::AwaitingMerge);
        assert_eq!(still_awaiting.revision, 6);

        let wrong_ancestry = MergeVerificationReceipt {
            base_ancestry: MergeBaseAncestryProof {
                comparison_head_sha: "e".repeat(40),
                ..verified.base_ancestry.clone()
            },
            ..verified.clone()
        };
        let wrong_ancestry_json = crate::store::canonical_json(&wrong_ancestry).unwrap();
        let wrong_ancestry_effect = crate::store::EffectIntent {
            operation_id: OperationId::parse("merge-negative-ancestry")
                .unwrap()
                .as_str()
                .into(),
            logical_key: "merge-negative-ancestry".into(),
            request_digest: super::sha256_hex(verify_effect.request_json.as_bytes()),
            request_json: verify_effect.request_json.clone(),
            expected_revision: Some(6),
            ..verify_effect.clone()
        };
        store
            .enqueue_effect(generation, &wrong_ancestry_effect)
            .unwrap();
        let wrong_ancestry_claim = store
            .claim_next_due_effect(generation, i64::MAX, std::slice::from_ref(&merge_kind))
            .unwrap()
            .unwrap();
        assert_eq!(
            wrong_ancestry_claim.intent.operation_id,
            wrong_ancestry_effect.operation_id
        );
        store
            .finish_effect(
                &wrong_ancestry_effect.operation_id,
                generation,
                EffectOutcome::Succeeded,
                Some(&wrong_ancestry_json),
            )
            .unwrap();
        super::consume_one_host_transition(&mut store, generation, 19, &config, &loaded.digest)
            .unwrap();
        assert_eq!(
            store
                .active_ticket_runs(generation, 10)
                .unwrap()
                .into_iter()
                .find(|run| run.ticket_run_id == ticket_run_id)
                .unwrap()
                .phase,
            super::Phase::AwaitingMerge
        );

        let verified_json = crate::store::canonical_json(&verified).unwrap();
        let valid_verify = crate::store::EffectIntent {
            operation_id: OperationId::parse("merge-positive-verification")
                .unwrap()
                .as_str()
                .into(),
            logical_key: "merge-positive-verification".into(),
            request_digest: super::sha256_hex(verify_effect.request_json.as_bytes()),
            request_json: verify_effect.request_json,
            expected_revision: Some(6),
            ..verify_effect
        };
        store.enqueue_effect(generation, &valid_verify).unwrap();
        let verify_claim = store
            .claim_next_due_effect(generation, i64::MAX, std::slice::from_ref(&merge_kind))
            .unwrap()
            .unwrap();
        assert_eq!(verify_claim.intent.operation_id, valid_verify.operation_id);
        store
            .finish_effect(
                &valid_verify.operation_id,
                generation,
                EffectOutcome::Succeeded,
                Some(&verified_json),
            )
            .unwrap();
        assert!(super::consume_one_host_transition(
            &mut store,
            generation,
            20,
            &config,
            &loaded.digest,
        )
        .unwrap());
        let operating = store
            .active_ticket_runs(generation, 10)
            .unwrap()
            .into_iter()
            .find(|run| run.ticket_run_id == ticket_run_id)
            .unwrap();
        assert_eq!(operating.phase, super::Phase::Operating);
        assert_eq!(operating.revision, 7);
        for (role, target) in [("operator", "operator"), ("coordinator", "coordinator")] {
            let wake_session = format!("ticket_run:{ticket_run_id}:{role}");
            let wakes = store
                .pending_role_wake_inputs(&project_id, &wake_session, 256)
                .unwrap();
            assert!(
                wakes.iter().any(|wake| {
                    wake.source_type == "ticket_run_transition"
                        && wake.source_revision == 7
                        && wake.payload_json["target"] == target
                }),
                "MergeVerified must durably wake {role} at the Operating revision"
            );
        }
        let verified_receipts = store
            .list_succeeded_effect_receipts(
                generation,
                &project_id,
                "ticket_run",
                ticket_run_id.as_str(),
                256,
            )
            .unwrap();
        assert!(
            super::find_verified_merge_receipt(&work_item, &verified_receipts).is_some(),
            "fixture's successful effects must contain the exact verified receipt"
        );

        let wrong_configuration = Digest::parse("e".repeat(64)).unwrap();
        assert!(
            super::persist_operating_plan_from_verified_merge(
                &mut store,
                generation,
                21,
                &loaded.config,
                &wrong_configuration,
                &operating,
                &verified_receipts,
            )
            .is_err()
        );
        let mut stale_operating = operating.clone();
        stale_operating.revision += 1;
        assert!(
            super::persist_operating_plan_from_verified_merge(
                &mut store,
                generation,
                21,
                &loaded.config,
                &loaded.digest,
                &stale_operating,
                &verified_receipts,
            )
            .is_err()
        );
        store
            .test_connection()
            .execute(
                "UPDATE effects SET receipt_json='{}' WHERE operation_id=?1",
                [valid_verify.operation_id.as_str()],
            )
            .unwrap();
        let tampered_receipts = store
            .list_succeeded_effect_receipts(
                generation,
                &project_id,
                "ticket_run",
                ticket_run_id.as_str(),
                256,
            )
            .unwrap();
        assert!(
            super::persist_operating_plan_from_verified_merge(
                &mut store,
                generation,
                21,
                &loaded.config,
                &loaded.digest,
                &operating,
                &tampered_receipts,
            )
            .is_err()
        );
        store
            .test_connection()
            .execute(
                "UPDATE effects SET receipt_json=?2 WHERE operation_id=?1",
                params![valid_verify.operation_id.as_str(), verified_json],
            )
            .unwrap();

        // The verified merge receipt, rather than the Agent result or a generic merge event,
        // supplies the delivery SHA for the immutable operation plan.
        assert!(
            super::consume_one_host_transition(
                &mut store,
                generation,
                21,
                &loaded.config,
                &loaded.digest,
            )
            .unwrap()
        );
        let plan = store
            .operations()
            .unwrap()
            .plan_state(&project_id, &ticket_run_id)
            .unwrap()
            .unwrap_or_else(|| {
                panic!(
                    "required operation plan missing; run={:?}; wakes={:?}; last_transition={:?}; evidence={:?}",
                    store.active_ticket_runs(generation, 10).unwrap(),
                    store.pending_role_wake_inputs(&project_id, "project_supervisor", 10).unwrap(),
                    store.test_connection().query_row(
                        "SELECT decision_reason FROM transitions WHERE entity_type='ticket_run' AND entity_id=?1 ORDER BY new_revision DESC LIMIT 1",
                        [ticket_run_id.as_str()],
                        |row| row.get::<_, String>(0),
                    ).unwrap(),
                    store.test_connection().query_row(
                        "SELECT evidence_json FROM transitions WHERE entity_type='ticket_run' AND entity_id=?1 ORDER BY new_revision DESC LIMIT 1",
                        [ticket_run_id.as_str()],
                        |row| row.get::<_, String>(0),
                    ).unwrap()
                )
            });
        if required_operations {
            assert_eq!(plan.recipe_id, "required_deploy");
            assert_eq!(plan.state, "required");
            assert_eq!(plan.not_required_reason, None);
            let operation_request_json: String = store
                .test_connection()
                .query_row(
                    "SELECT request_json FROM effects WHERE kind='operation' AND subject_id=?1",
                    [ticket_run_id.as_str()],
                    |row| row.get(0),
                )
                .unwrap();
            let operation_request: crate::store::operations::OperationEffectRequest =
                serde_json::from_str(&operation_request_json).unwrap();
            assert_eq!(
                operation_request.subject.source_sha, verified.merge_commit_sha,
                "required Operator work must use the exact verified merge SHA"
            );
            assert!(
                crate::runtime_services::operator_plan_ready_for_launch(
                    &mut store,
                    generation,
                    &loaded.config,
                    &loaded.digest,
                    &operating,
                )
                .unwrap()
            );
            assert!(
                !crate::runtime_services::operator_plan_ready_for_launch(
                    &mut store,
                    generation,
                    &loaded.config,
                    &wrong_configuration,
                    &operating,
                )
                .unwrap()
            );
            assert!(
                !crate::runtime_services::operator_plan_ready_for_launch(
                    &mut store,
                    generation,
                    &loaded.config,
                    &loaded.digest,
                    &stale_operating,
                )
                .unwrap()
            );
            assert!(
                !super::consume_one_host_transition(
                    &mut store,
                    generation,
                    22,
                    &loaded.config,
                    &loaded.digest,
                )
                .unwrap()
            );
            let still_operating = store.active_ticket_runs(generation, 10).unwrap()[0].clone();
            assert_eq!(still_operating.phase, super::Phase::Operating);
            return;
        }
        assert_eq!(plan.recipe_id, "docs_only");
        assert_eq!(plan.state, "not_required");
        assert_eq!(
            plan.not_required_reason.as_deref(),
            Some("This fixture has no deployed runtime target.")
        );

        // A restart between the durable plan insert and the reducer transition replays from the
        // stored plan and advances to Postmortem exactly once.
        assert!(
            super::consume_one_host_transition(
                &mut store,
                generation,
                22,
                &loaded.config,
                &loaded.digest,
            )
            .unwrap()
        );
        let postmortem = store
            .active_ticket_runs(generation, 10)
            .unwrap()
            .into_iter()
            .find(|run| run.ticket_run_id == ticket_run_id)
            .unwrap();
        assert_eq!(postmortem.phase, super::Phase::Postmortem);
        assert_eq!(postmortem.revision, 8);
        let coordinator_wakes = store
            .pending_role_wake_inputs(
                &project_id,
                &format!("ticket_run:{ticket_run_id}:coordinator"),
                256,
            )
            .unwrap();
        assert!(
            coordinator_wakes.iter().any(|wake| {
                wake.source_type == "ticket_run_transition"
                    && wake.source_revision == 8
                    && wake.payload_json["target"] == "coordinator"
            }),
            "OperationsNotRequired must durably wake Coordinator at Postmortem revision"
        );
        let completion_context = crate::runtime_services::postmortem_completion_context_for_test(
            &mut store,
            generation,
            &postmortem,
            &loaded.digest,
        )
        .unwrap();
        assert_eq!(
            completion_context.operation_completion.state,
            "not_required"
        );
        assert_eq!(
            completion_context
                .operation_completion
                .not_required_reason
                .as_deref(),
            Some("This fixture has no deployed runtime target.")
        );
        assert_eq!(
            completion_context
                .implementation_publication
                .merge_verification
                .merge_commit_sha,
            verified.merge_commit_sha
        );
        assert_eq!(
            completion_context
                .implementation_publication
                .merge_verification
                .included_head_sha,
            verified.included_head_sha
        );
        let completion_json = serde_json::to_value(&completion_context).unwrap();
        let human_decision = &completion_json["human_decision"];
        assert_eq!(human_decision["request_id"], request_id.as_str());
        assert_eq!(human_decision["work_id"], work_item.work_id.as_str());
        assert_eq!(
            human_decision["receipt"]["response_id"],
            decision.response_id
        );
        assert_eq!(human_decision["receipt"]["choice"], "approve");
        assert_eq!(human_decision["receipt"]["approved"], true);
        assert_eq!(
            human_decision["request_digest"],
            crate::forge::canonical_digest(&serde_json::to_value(&request).unwrap())
                .unwrap()
                .as_str()
        );
        assert_eq!(
            human_decision["receipt_digest"],
            crate::forge::canonical_digest(&human_decision["receipt"])
                .unwrap()
                .as_str()
        );
        assert!(
            store
                .accepted_merge_work_review_approval(&request_id, &work_item, 1001)
                .unwrap()
                .is_none(),
            "historical evidence must not extend the live approval lifetime"
        );
        assert_eq!(
            store
                .historical_merge_work_review_evidence(&request_id, &work_item)
                .unwrap(),
            completion_context.human_decision,
            "Postmortem must retain the exact approval after its live expiry"
        );
        let mut unrelated_work = work_item.clone();
        unrelated_work.work_id = digest('f');
        assert!(
            store
                .historical_merge_work_review_evidence(&request_id, &unrelated_work)
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .historical_merge_work_review_evidence(
                    &HumanRequestId::parse("missing-merge-request").unwrap(),
                    &work_item,
                )
                .unwrap()
                .is_none()
        );
        let mut legacy_context = completion_json.clone();
        legacy_context
            .as_object_mut()
            .unwrap()
            .remove("human_decision");
        let legacy: crate::agent_api::HostCompletionContext =
            serde_json::from_value(legacy_context.clone()).unwrap();
        assert!(legacy.human_decision.is_none());
        assert_eq!(serde_json::to_value(legacy).unwrap(), legacy_context);
        let session = format!("ticket_run:{}:postmortem", ticket_run_id);
        let inputs = store
            .pending_role_wake_inputs(&project_id, &session, 256)
            .unwrap();
        let postmortem_wakes = inputs
            .into_iter()
            .filter(|input| {
                input.source_type == "ticket_run_transition"
                    && input.payload_json["target"] == "postmortem"
            })
            .collect::<Vec<_>>();
        assert_eq!(postmortem_wakes.len(), 1);
        let wake = &postmortem_wakes[0];
        let mut inbox = crate::agent_api::AgentWakeSnapshot {
            schema_version: 1,
            project_id: project_id.clone(),
            role_session_id: session,
            agent_run_id: "agent-postmortem-fixture".into(),
            digest: digest('0'),
            inputs: vec![crate::agent_api::AgentWakeItem {
                wake_input_id: wake.wake_input_id,
                source_type: wake.source_type.clone(),
                source_id: wake.source_id.clone(),
                source_revision: wake.source_revision,
                priority: wake.priority,
                payload_json: wake.payload_json.clone(),
                host_artifact_source_evidence_ids: Vec::new(),
                host_artifacts: Vec::new(),
                host_completion_context: Some(completion_context.clone()),
            }],

            worker_correction_context: None,
        };
        inbox.digest = inbox.content_digest().unwrap();
        let inbox_root = tempfile::tempdir().unwrap();
        crate::agent_api::publish_wake_snapshot(inbox_root.path(), inbox.clone()).unwrap();
        let consumed =
            crate::agent_api::read_inbox(inbox_root.path(), "agent-postmortem-fixture", 0).unwrap();
        assert_eq!(
            consumed[0].host_completion_context,
            Some(completion_context)
        );

        let original_receipt = human_decision["receipt"].clone();
        for (field, value) in [
            ("request_id", serde_json::json!("another-request")),
            ("response_id", serde_json::json!("another-response")),
            ("subject_digest", serde_json::json!(digest('f'))),
            ("decided_at_unix", serde_json::json!(1000)),
            ("request_expires_at_unix", serde_json::json!(2000)),
            ("approved", serde_json::json!(false)),
        ] {
            let mut altered = original_receipt.clone();
            altered[field] = value;
            store
                .test_connection()
                .execute(
                    "UPDATE human_decisions SET receipt_json=?1 WHERE request_id=?2",
                    params![altered.to_string(), request_id.as_str()],
                )
                .unwrap();
            let context = crate::runtime_services::postmortem_completion_context_for_test(
                &mut store,
                generation,
                &postmortem,
                &loaded.digest,
            )
            .unwrap();
            assert!(context.human_decision.is_none(), "accepted altered {field}");
        }
        store
            .test_connection()
            .execute(
                "UPDATE human_decisions SET receipt_json=?1,subject_digest=?2 WHERE request_id=?3",
                params![
                    original_receipt.to_string(),
                    digest('f').as_str(),
                    request_id.as_str()
                ],
            )
            .unwrap();
        assert!(
            store
                .historical_merge_work_review_evidence(&request_id, &work_item)
                .unwrap()
                .is_none(),
            "receipt JSON must not override conflicting stored decision columns"
        );
    }
}
