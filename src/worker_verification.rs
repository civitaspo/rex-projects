//! Host validation for Worker check-only handoffs after a Reviewer requests corrections.

use std::collections::BTreeSet;

use crate::config::Config;
use crate::domain::types::Role;
use crate::engine::factory_runtime::FactoryRuntimeServices;
use crate::engine::orchestration::{RoleOutputKind, RoleResultPayload};
use crate::engine::reducer::{Activity, Input, Phase};
use crate::store::ConfigStore;
use crate::store::agent_results::{IngestedAgentResult, ResultDisposition};
use crate::store::{DurableInput, durable_input_digest};

pub(crate) fn apply_worker_verification_result(
    store: &mut ConfigStore,
    owner_generation: u64,
    config: &Config,
    services: &mut impl FactoryRuntimeServices,
    result: &IngestedAgentResult,
) -> Result<bool, String> {
    let binding = &result.validated.binding;
    let ticket_run_id = binding
        .ticket_run_id
        .as_ref()
        .ok_or("Worker VerificationReady result lacks TicketRun scope")?;
    let source_revision = binding
        .ticket_revision
        .ok_or("Worker VerificationReady result lacks TicketRun revision")?;
    if store.acknowledge_committed_role_result(
        owner_generation,
        "worker_verification_completed",
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
        .ok_or("Worker verification result references no active TicketRun")?;
    if binding.role != Role::Worker
        || result.validated.kind != RoleOutputKind::VerificationReady
        || run.project_id != binding.project_id
        || run.revision != source_revision.0
        || run.phase != Phase::Implementing
        || run.activity != Activity::Running
    {
        return Err("Worker verification result is stale or outside active Implementing".into());
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
        .ok_or("Worker verification Project has no durable configuration record")?;
    let configuration_digest = services.configuration_digest().clone();
    if project_record.config_digest != configuration_digest
        || binding.config_digest != configuration_digest
        || binding.config_revision != project_record.config_revision
    {
        return Err("Worker verification belongs to a stale configuration snapshot".into());
    }
    let project = config
        .projects
        .get(&binding.project_id)
        .ok_or("Worker verification Project is no longer configured")?;
    let accepted = store
        .latest_accepted_work_plan(&binding.project_id, ticket_run_id)?
        .ok_or("Worker verification has no accepted work plan")?;
    let validated_plan = accepted.validate_for(project, &configuration_digest)?;
    let RoleResultPayload::VerificationReady(claim) = &result.validated.typed_payload else {
        return Err("validated VerificationReady kind has a different typed payload".into());
    };
    let node = validated_plan
        .nodes_in_execution_order
        .iter()
        .find(|node| node.id == claim.work_node_id)
        .ok_or("Worker verification names a node outside its accepted plan")?;
    if node.role != Role::Worker || node.repository != claim.repository {
        return Err("Worker verification node or repository differs from its accepted plan".into());
    }

    let reservation = store
        .agent_launch_reservation_for_run(&binding.agent_run_id)?
        .ok_or("Worker verification has no immutable launch reservation")?;
    let recovery_authorization = reservation.wake_snapshot.worker_recovery_authorization()?;
    if reservation.controller_generation != owner_generation
        || reservation.project_id != binding.project_id
        || reservation.role != Role::Worker
        || reservation.ticket_run_id.as_ref() != Some(ticket_run_id)
        || reservation.ticket_revision != Some(source_revision)
    {
        return Err("Worker verification reservation is outside the correction assignment".into());
    }
    if let Some(authorization) = &recovery_authorization {
        authorization.validate()?;
        if authorization.ticket_run_id != *ticket_run_id
            || authorization.ticket_revision != source_revision.0
            || authorization.work_node_id != claim.work_node_id
            || authorization.accepted_plan_digest != accepted.plan_digest
            || authorization.expected_head != claim.published_head.as_str()
        {
            return Err("Worker recovery authorization is not for this exact published verification assignment".into());
        }
    }
    let assignment = reservation
        .worker_assignment
        .as_ref()
        .ok_or("Worker verification reservation has no prepared node assignment")?;
    if assignment.node_id != claim.work_node_id
        || assignment.repository_id != claim.repository
        || assignment.ticket_revision != run.revision
        || assignment.configuration_digest != configuration_digest
        || assignment.plan_digest != accepted.plan_digest
        || assignment.expected_head.as_deref() != Some(claim.published_head.as_str())
    {
        return Err("Worker verification differs from its immutable node reservation".into());
    }
    let prepare = store
        .succeeded_effect_receipt(&assignment.prepare_operation_id)?
        .ok_or("Worker verification preparation receipt is no longer succeeded")?;
    let prepared = store
        .prepared_worker_launch(
            owner_generation,
            assignment.accepted_revision,
            &assignment.node_id,
            &prepare,
            project,
            &configuration_digest,
        )?
        .ok_or("Worker verification prepared-worktree authority is stale")?;
    if prepared.reservation_binding() != *assignment
        || prepared.expected_head() == prepared.base_sha()
        || prepared.expected_head() != claim.published_head.as_str()
    {
        return Err(
            "Worker verification is not a correction assignment at the accepted published head"
                .into(),
        );
    }

    let snapshot = store.accepted_implementation_publication_snapshot(
        owner_generation,
        &run.project_id,
        ticket_run_id,
        run.revision,
    )?;
    crate::delivery_runtime::validate_implementation_publication_receipt(
        &accepted.proposal,
        snapshot.prepared_receipt(),
        &run.project_id,
        &config.repositories,
        snapshot.publication_receipts(),
    )?;
    let matching = snapshot
        .publication_receipts()
        .iter()
        .filter_map(|receipt| {
            let request: crate::delivery_runtime::PublishImplementationEffectPayload =
                crate::protocol::parse_unique(receipt.intent().request_json.as_bytes()).ok()?;
            (request.work_node_id == claim.work_node_id).then_some((receipt, request))
        })
        .collect::<Vec<_>>();
    if matching.len() != 1 {
        return Err(
            "Worker verification publication does not cover its accepted node exactly once".into(),
        );
    }
    let (publication_receipt, publication_request) = &matching[0];
    let publication_receipt_body: crate::delivery_runtime::ImplementationPublicationReceipt =
        crate::protocol::parse_unique(publication_receipt.receipt_json().as_bytes())?;
    if publication_receipt.intent().operation_id != claim.publication_operation_id.as_str()
        || publication_request.ticket_run_id != *ticket_run_id
        || publication_request.source_revision.checked_add(1)
            != Some(snapshot.publication_revision())
        || publication_request.repository_id != claim.repository
        || publication_request.configuration_digest != configuration_digest
        || publication_receipt_body.work_node_id != claim.work_node_id
        || publication_receipt_body.repository_id != claim.repository
        || publication_receipt_body.configuration_digest != configuration_digest
        || publication_receipt_body.commit.head() != claim.published_head.as_str()
        || prepared.expected_head() != publication_receipt_body.commit.head()
    {
        return Err(
            "Worker verification does not cite the exact accepted publication receipt".into(),
        );
    }
    services.verify_worker_verification_worktree(
        prepared.worktree_path(),
        publication_receipt_body.commit.head(),
    )?;

    let requested_receipts = claim
        .test_receipt_artifact_ids
        .iter()
        .collect::<BTreeSet<_>>();
    let verified_receipts = result
        .verified_artifacts
        .iter()
        .filter(|artifact| {
            artifact.reference().kind == crate::engine::orchestration::RoleArtifactKind::TestReceipt
        })
        .collect::<Vec<_>>();
    let verified_ids = verified_receipts
        .iter()
        .map(|artifact| &artifact.reference().artifact_id)
        .collect::<BTreeSet<_>>();
    if requested_receipts != verified_ids
        || verified_receipts.len() != claim.test_receipt_artifact_ids.len()
    {
        return Err("Worker verification TestReceipt artifacts are not host-registered for this exact result".into());
    }
    let test_receipt_artifacts = verified_receipts
        .iter()
        .map(|artifact| artifact.reference().clone())
        .collect::<Vec<_>>();

    let accepted_revision = run
        .revision
        .checked_add(1)
        .ok_or("TicketRun revision overflow")?;
    let verification = serde_json::json!({
        "schema_version": 1,
        "review_revision": accepted_revision,
        "source_revision": run.revision,
        "source_evidence_id": result.receipt.evidence_id(),
        "source_agent_run_id": binding.agent_run_id,
        "source_result_digest": result.validated.result_digest,
        "publication_revision": snapshot.publication_revision(),
        "publication_operation_id": publication_receipt.intent().operation_id,
        "published_head": publication_receipt_body.commit.head(),
        "work_node_id": claim.work_node_id,
        "repository_id": claim.repository,
        "test_receipt_artifacts": test_receipt_artifacts,
    });
    let payload = serde_json::json!({
        "schema_version": 1,
        "kind": "worker_verification_completed",
        "evidence_id": result.receipt.evidence_id(),
        "result_digest": result.validated.result_digest,
        "source_revision": run.revision,
        "accepted_revision": accepted_revision,
        "publication_revision": snapshot.publication_revision(),
        "verification": verification,
        "transition": "worker_verification_completed",
    });
    let payload_json = serde_json::to_string(&payload).map_err(|error| error.to_string())?;
    let durable = DurableInput {
        producer_id: "rex-projects-agent-result".into(),
        message_id: format!("worker-verification:{}", result.receipt.evidence_id()),
        content_digest: durable_input_digest("ticket_run", &payload_json),
        recipient: "ticket_run".into(),
        payload: payload_json.clone(),
    };
    store.commit_ticket_transition(
        owner_generation,
        ticket_run_id,
        crate::domain::ids::Revision(run.revision),
        &durable,
        Input::WorkerVerificationCompleted,
        "host validated the correction Worker checks against the exact current publication and clean worktree",
        &payload_json,
        &[],
    )?;
    store.acknowledge_validated_agent_result(
        owner_generation,
        result.receipt.evidence_id(),
        accepted_revision,
        ResultDisposition::Applied,
    )?;
    Ok(true)
}
