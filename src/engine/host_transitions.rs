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
                    &[],
                )?;
                return Ok(true);
            }
        }

        if run.phase == Phase::Publishing {
            if advance_work_plan_stage(
                store,
                owner_generation,
                config,
                configuration_digest,
                &run,
                &receipts,
            )? {
                return Ok(true);
            }
        }

        if run.phase == Phase::Operating
            && run.activity != crate::engine::reducer::Activity::Blocked
        {
            let plan = {
                let operations = store.operations()?;
                operations.plan_state(&run.project_id, &run.ticket_run_id)?
            };
            let Some(plan) = plan else {
                continue;
            };
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
            if expected_revision > run.revision {
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
    let mut prepared_receipt = PreparedWorktreesEffectReceipt {
        schema_version: 1,
        ticket_run_id: run.ticket_run_id.clone(),
        work_nodes: prepared.values().cloned().collect(),
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
            }],
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
}
