//! CLI-backed host handlers for external ticket effects.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use crate::adapters::tickets::{
    CommentResult, NormalizedTicketStatus, OperationFindRequest, OperationLookup,
    OperationMatchBasis, ReconciliationOutcome, ScopedTicketResult, TicketAdapter,
    TicketAdapterError, TicketCommentRequest, TicketCreateRequest, TicketGetRequest, TicketScope,
    TicketUpdateRequest,
};
use crate::domain::ids::{
    OperationId, ProjectId, Revision, TicketId, TicketNamespace, TicketRunId,
};
use crate::domain::types::TicketStatus;
use crate::effects::{
    AbsentProof, EffectContext, EffectHandler, EffectMode, EffectObservation, EffectRequest,
};
use crate::engine::reducer::EffectKind;
use crate::engine::ticket_effects::{
    CreateGoalTicket, PublishTicketStatus, ResolveDuplicateTicket,
};
use crate::protocol::RequestId;
use crate::store::scheduler::{GoalTicketCandidateRecord, GoalTicketDuplicateResolution};
use crate::store::{DurableInput, EffectIntent, durable_input_digest};

static REQUEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// Handlers share the configured CLI adapter and immutable project scopes.
/// The controller can keep using the same adapter for reads and scans.
pub struct TicketEffectHandlers {
    adapter: Arc<dyn TicketAdapter>,
    scopes: BTreeMap<ProjectId, TicketScope>,
}

impl TicketEffectHandlers {
    pub fn new(adapter: Arc<dyn TicketAdapter>, scopes: BTreeMap<ProjectId, TicketScope>) -> Self {
        Self { adapter, scopes }
    }

    pub fn into_handlers(self) -> Vec<Box<dyn EffectHandler>> {
        vec![
            Box::new(PublishTicketStatusHandler::new(
                self.adapter.clone(),
                self.scopes.clone(),
            )),
            Box::new(CreateGoalTicketHandler::new(self.adapter.clone())),
            Box::new(ResolveDuplicateHandler::new(
                self.adapter.clone(),
                self.scopes.clone(),
            )),
            Box::new(CompleteTicketHandler),
        ]
    }
}

struct PublishTicketStatusHandler {
    adapter: Arc<dyn TicketAdapter>,
    scopes: BTreeMap<ProjectId, TicketScope>,
}

impl PublishTicketStatusHandler {
    fn new(adapter: Arc<dyn TicketAdapter>, scopes: BTreeMap<ProjectId, TicketScope>) -> Self {
        Self { adapter, scopes }
    }

    fn scope(&self, payload: &PublishTicketStatus) -> Result<TicketScope, String> {
        self.scopes
            .get(&payload.project_id)
            .cloned()
            .ok_or_else(|| {
                format!(
                    "ticket scope is not configured for Project `{}`",
                    payload.project_id
                )
            })
    }

    fn verify_result(
        &self,
        payload: &PublishTicketStatus,
        result: &ScopedTicketResult,
    ) -> Result<(), String> {
        validate_ticket_status_receipt(payload, result)?;
        if result.ticket.scope != self.scope(payload)? {
            return Err(
                "ticket adapter status receipt is outside the configured Project scope".into(),
            );
        }
        Ok(())
    }

    fn replacement_for_adopted_done(
        &self,
        context: &crate::effects::EffectContext<'_>,
        request: &EffectRequest,
        payload: &PublishTicketStatus,
    ) -> Result<Option<EffectIntent>, String> {
        let key = format!("{}:adopted_done", request.intent.logical_key);
        let Some(intent) = context.store.effect_by_logical_key(&key)? else {
            return Ok(None);
        };
        let child: PublishTicketStatus = decode_payload(&EffectRequest {
            intent: intent.clone(),
            attempt_count: 0,
            created_at_unix: request.created_at_unix,
        })?;
        if intent.operation_id != format!("{}-adopted-done", request.intent.operation_id)
            || child.project_id != payload.project_id
            || child.ticket_run_id != payload.ticket_run_id
            || child.ticket_run_revision != payload.ticket_run_revision
            || child.ticket_id != payload.ticket_id
            || child.namespace != payload.namespace
            || child.desired_status != TicketStatus::Done
            || child.expected_external_revision.is_none()
        {
            return Err("deterministic Done replacement intent has mismatched scope".into());
        }
        Ok(Some(intent))
    }

    fn reconcile_done_external_revision(
        &self,
        request: &EffectRequest,
        payload: &PublishTicketStatus,
        scope: TicketScope,
        context: &mut crate::effects::EffectContext<'_>,
    ) -> Result<EffectObservation, String> {
        let current = self
            .adapter
            .get(
                request_id("status-adoption-get")?,
                None,
                TicketGetRequest {
                    scope: scope.clone(),
                    ticket_id: payload.ticket_id.as_str().into(),
                    timeline_limit: Some(1),
                },
            )
            .map_err(adapter_error)?;
        validate_ticket_identity(
            &current.ticket_namespace,
            &current.ticket,
            &payload.namespace,
            &payload.ticket_id,
        )?;
        if current.ticket.scope != scope {
            return Err(
                "ticket status adoption observation is outside the configured Project scope".into(),
            );
        }
        let current_revision = current
            .ticket
            .revision
            .as_deref()
            .filter(|revision| !revision.is_empty())
            .ok_or(
                "ticket adapter omitted the current revision required for guarded Done publication",
            )?;
        let currently_in_progress =
            current.ticket.status.value == NormalizedTicketStatus::InProgress;
        if !currently_in_progress
            || payload.expected_external_revision.as_deref() == Some(current_revision)
        {
            return Ok(EffectObservation::Pending { receipt: "Done status publication remains unresolved; external ticket is not an adoptable changed In Progress revision".into() });
        }
        let proof = context
            .store
            .ticket_completion_proof(
                context.owner_generation,
                &payload.project_id,
                &payload.ticket_run_id,
                payload.ticket_run_revision.saturating_sub(1),
            )?
            .ok_or("Done status adoption requires the validated completion and Postmortem proof")?;
        let Some(project) = context.store.project(&payload.project_id)? else {
            return Err("Done status adoption Project is missing".into());
        };
        let identity = serde_json::to_vec(&(
            &request.intent.operation_id,
            &payload.project_id,
            &payload.ticket_run_id,
            payload.ticket_run_revision,
            current_revision,
            &project.config_digest,
            proof.plan_digest(),
            proof.postmortem_receipt_digest(),
            proof.knowledge_manifest_digest(),
        ))
        .map_err(|error| error.to_string())?;
        let stable_hex = format!("{:x}", Sha256::digest(identity));
        let request_stable = format!("ticket-status-adoption-{}", &stable_hex[..32]);
        let human_request_id = crate::domain::ids::HumanRequestId::parse(request_stable)?;
        let expires_at = u64::try_from(context.now_unix)
            .map_err(|_| "controller time is before Unix epoch")?
            .saturating_add(7 * 24 * 60 * 60);
        let authority = crate::human_runtime::TicketStatusAdoptionAuthority {
            project_id: payload.project_id.clone(),
            ticket_run_id: payload.ticket_run_id.clone(),
            ticket_run_revision: payload.ticket_run_revision,
            namespace: payload.namespace.clone(),
            ticket_id: payload.ticket_id.clone(),
            original_effect_id: request.intent.operation_id.clone(),
            previous_external_revision: payload.expected_external_revision.clone(),
            current_ticket_json: serde_json::to_string(&current)
                .map_err(|error| error.to_string())?,
            completion_plan_digest: proof.plan_digest().clone(),
            postmortem_receipt_digest: proof.postmortem_receipt_digest().clone(),
            knowledge_operation_id: proof.knowledge_operation_id().to_owned(),
            knowledge_manifest_digest: proof.knowledge_manifest_digest().clone(),
            configuration_digest: project.config_digest.clone(),
            policy_digest: crate::human_runtime::ticket_status_adoption_policy_digest(
                &payload.project_id,
                &payload.ticket_id,
                &project.config_digest,
            )?,
            expires_at_unix: expires_at,
        };
        let human_request = crate::human_runtime::ticket_status_adoption_request(
            human_request_id.clone(),
            authority.clone(),
        )?;
        let logical_key = format!("ticket-status-adoption:{}", human_request_id.as_str());
        if let Some(existing) = context.store.current_human_request(&human_request_id)? {
            // Expiry is assigned once; every replay must still prove the full exact snapshot.
            let replay_authority = crate::human_runtime::TicketStatusAdoptionAuthority {
                expires_at_unix: existing.request.expires_at_unix,
                ..authority.clone()
            };
            let replay_request = crate::human_runtime::ticket_status_adoption_request(
                human_request_id.clone(),
                replay_authority,
            )?;
            if replay_request != existing.request {
                return Err("stable ticket status adoption request changed content".into());
            }
            if let Some(approval) = context.store.accepted_ticket_status_adoption_approval(
                &human_request_id,
                u64::try_from(context.now_unix).unwrap_or(0),
            )? {
                let fresh = self
                    .adapter
                    .get(
                        request_id("status-adoption-recheck")?,
                        None,
                        TicketGetRequest {
                            scope: self.scope(payload)?,
                            ticket_id: payload.ticket_id.as_str().into(),
                            timeline_limit: Some(1),
                        },
                    )
                    .map_err(adapter_error)?;
                let fresh_json =
                    serde_json::to_string(&fresh).map_err(|error| error.to_string())?;
                if fresh_json != approval.authority().current_ticket_json {
                    return Err(
                        "external ticket changed after human status-adoption approval".into(),
                    );
                }
                let replacement = context.store.adopt_done_ticket_status_revision(
                    context.owner_generation,
                    &request.intent,
                    payload,
                    &approval,
                    &proof,
                    context.now_unix,
                )?;
                return Ok(EffectObservation::Rejected { receipt: serde_json::json!({"outcome":"superseded_after_approved_revision_adoption","replacement_operation_id":replacement.operation_id,"approval_request_id":human_request_id.as_str()}).to_string() });
            }
            return Ok(EffectObservation::Pending {
                receipt: format!(
                    "awaiting explicit human approval for changed ticket revision: {}",
                    human_request_id.as_str()
                ),
            });
        }
        let view_id = context
            .store
            .active_ticket_run_view_id(&payload.ticket_run_id)?
            .ok_or("completed ticket has no active Rex view for status-adoption review")?;
        let request = crate::human_runtime::HumanPresentationEffect {
            request: human_request,
            rex_view_id: view_id,
            authority: Some(
                crate::human_runtime::HumanAuthorityMaterial::TicketStatusAdoption {
                    material: authority,
                },
            ),
        };
        let request_json = crate::store::canonical_json(&request)?;
        let intent = EffectIntent {
            project_id: payload.project_id.clone(),
            subject_type: "ticket_run".into(),
            subject_id: payload.ticket_run_id.as_str().into(),
            operation_id: format!("present-{}", human_request_id.as_str()),
            logical_key,
            kind: "request_human_review".into(),
            request_digest: format!("{:x}", Sha256::digest(request_json.as_bytes())),
            request_json,
            expected_revision: Some(payload.ticket_run_revision),
        };
        context
            .store
            .enqueue_effect(context.owner_generation, &intent)?;
        Ok(EffectObservation::Pending {
            receipt: format!(
                "awaiting explicit human approval for changed ticket revision: {}",
                human_request_id.as_str()
            ),
        })
    }
}

pub(crate) fn validate_ticket_status_receipt(
    payload: &PublishTicketStatus,
    result: &ScopedTicketResult,
) -> Result<(), String> {
    payload.validate()?;
    if result.ticket_namespace != payload.namespace.as_str()
        || result.ticket.ticket_namespace != payload.namespace.as_str()
        || result.ticket.id != payload.ticket_id.as_str()
        || result.ticket.status.value != normalized_status(payload.desired_status)
    {
        return Err("ticket adapter status receipt does not match the requested mutation".into());
    }
    if result
        .ticket
        .revision
        .as_deref()
        .is_none_or(|revision| revision.trim().is_empty() || revision.len() > 512)
    {
        return Err("ticket adapter status receipt has no bounded external revision".into());
    }
    Ok(())
}

impl EffectHandler for PublishTicketStatusHandler {
    fn kind(&self) -> EffectKind {
        EffectKind::PublishTicketStatus
    }

    fn handle(
        &self,
        mode: EffectMode,
        request: &EffectRequest,
        context: &mut EffectContext<'_>,
    ) -> Result<EffectObservation, String> {
        let payload: PublishTicketStatus = decode_payload(request)?;
        payload.validate()?;
        if request.intent.kind != "publish_ticket_status"
            || request.intent.expected_revision != Some(payload.ticket_run_revision)
            || request.intent.subject_type != "ticket_run"
            || request.intent.subject_id != payload.ticket_run_id.as_str()
            || request.intent.project_id != payload.project_id
        {
            return Err("ticket status effect identity does not match its durable intent".into());
        }
        if mode == EffectMode::Reconcile
            && payload.desired_status == TicketStatus::Done
            && let Some(replacement) =
                self.replacement_for_adopted_done(context, request, &payload)?
        {
            return Ok(EffectObservation::Rejected {
                receipt: serde_json::json!({"outcome":"superseded_after_approved_revision_adoption","replacement_operation_id":replacement.operation_id}).to_string(),
            });
        }
        context
            .store
            .validate_ticket_status_publication(context.owner_generation, &payload)?;
        let scope = self.scope(&payload)?;
        match mode {
            EffectMode::Submit => {
                let current = self
                    .adapter
                    .get(
                        request_id("status-get")?,
                        None,
                        TicketGetRequest {
                            scope: scope.clone(),
                            ticket_id: payload.ticket_id.as_str().into(),
                            timeline_limit: Some(1),
                        },
                    )
                    .map_err(adapter_error)?;
                validate_ticket_identity(
                    &current.ticket_namespace,
                    &current.ticket,
                    &payload.namespace,
                    &payload.ticket_id,
                )?;
                if current.ticket.scope != scope {
                    return Err("ticket status publication observation is outside the configured Project scope".into());
                }
                if payload
                    .expected_external_revision
                    .as_deref()
                    .is_some_and(|revision| current.ticket.revision.as_deref() != Some(revision))
                {
                    return Err("external ticket revision changed before status publication".into());
                }
                let expected_revision = current.ticket.revision.ok_or_else(|| "ticket adapter omitted the revision required for conditional status mutation".to_owned())?;
                let mut patch = BTreeMap::new();
                patch.insert(
                    "status".into(),
                    serde_json::to_value(normalized_status(payload.desired_status))
                        .map_err(|error| error.to_string())?,
                );
                let result = self
                    .adapter
                    .update(
                        request_id("status-update")?,
                        operation_id(&request.intent.operation_id)?,
                        None,
                        TicketUpdateRequest {
                            scope,
                            ticket_id: payload.ticket_id.as_str().into(),
                            expected_revision,
                            patch,
                        },
                    )
                    .map_err(adapter_error)?;
                self.verify_result(&payload, &result)?;
                observation_applied(&result)
            }
            EffectMode::Reconcile => match lookup_operation(
                self.adapter.as_ref(),
                request,
                OperationFindRequest {
                    scope: scope.clone(),
                    operation_id: request.intent.operation_id.clone(),
                    stable_external_key: request.intent.operation_id.clone(),
                    method: "ticket.update".into(),
                    subject: [("ticket_id".into(), payload.ticket_id.as_str().into())].into(),
                },
                EffectKind::PublishTicketStatus,
            )? {
                Lookup::Found { mut receipts, .. } => {
                    if receipts.len() != 1 {
                        return Err("status operation lookup returned multiple matches".into());
                    }
                    let result: ScopedTicketResult = serde_json::from_value(receipts.remove(0))
                        .map_err(|_| "status operation receipt has an invalid schema".to_owned())?;
                    self.verify_result(&payload, &result)?;
                    observation_applied(&result)
                }
                Lookup::Absent(proof) => Ok(EffectObservation::AuthoritativelyAbsent { proof }),
                Lookup::Unknown(_receipt) if payload.desired_status == TicketStatus::Done => {
                    self.reconcile_done_external_revision(request, &payload, scope, context)
                }
                Lookup::Unknown(receipt) => Ok(EffectObservation::Pending { receipt }),
            },
        }
    }
}

struct CreateGoalTicketHandler {
    adapter: Arc<dyn TicketAdapter>,
}

impl CreateGoalTicketHandler {
    fn new(adapter: Arc<dyn TicketAdapter>) -> Self {
        Self { adapter }
    }

    fn store_candidates(
        &self,
        payload: &CreateGoalTicket,
        request: &EffectRequest,
        context: &mut EffectContext<'_>,
        candidates: &[crate::adapters::tickets::OperationMatch],
        basis: OperationMatchBasis,
    ) -> Result<EffectObservation, String> {
        if candidates.is_empty() || candidates.len() > 100 {
            return Err(
                "ticket create reconciliation returned no candidates or exceeded the limit".into(),
            );
        }
        let mut records = Vec::with_capacity(candidates.len());
        for candidate in candidates {
            let identity_matches = match basis {
                OperationMatchBasis::OperationId => {
                    candidate.operation_id == request.intent.operation_id
                }
                OperationMatchBasis::StableExternalKey => {
                    candidate.stable_external_key.as_deref()
                        == Some(payload.request.creation_key.as_str())
                }
            };
            if candidate.method != "ticket.create" || !identity_matches {
                return Err(
                    "ticket create receipt is bound to a different external operation".into(),
                );
            }
            let ticket: crate::adapters::tickets::NormalizedTicket =
                serde_json::from_value(candidate.receipt.clone())
                    .or_else(|_| serde_json::from_value(candidate.receipt["ticket"].clone()))
                    .map_err(|_| {
                        "ticket create receipt has an invalid normalized ticket".to_owned()
                    })?;
            let namespace = TicketNamespace::parse(ticket.ticket_namespace.clone())?;
            if namespace != payload.namespace || ticket.id.is_empty() {
                return Err(
                    "ticket create receipt changed namespace or omitted its identity".into(),
                );
            }
            records.push(GoalTicketCandidateRecord {
                namespace,
                ticket_id: TicketId::parse(ticket.id)?,
                match_basis: match basis {
                    OperationMatchBasis::OperationId => {
                        crate::engine::factory_runtime::GoalTicketMatchBasis::OperationId
                    }
                    OperationMatchBasis::StableExternalKey => {
                        crate::engine::factory_runtime::GoalTicketMatchBasis::StableExternalKey
                    }
                },
                created_at: ticket.created_at,
            });
        }
        let operation = operation_id(&request.intent.operation_id)?;
        let receipt = context.store.record_goal_ticket_candidates(
            context.owner_generation,
            &operation,
            &records,
            context.now_unix,
        )?;
        let receipt = json!({
            "canonical_namespace": receipt.canonical_namespace.as_str(),
            "canonical_ticket_id": receipt.canonical_ticket_id.as_str(),
            "duplicate_ticket_ids": receipt.duplicate_ticket_ids.iter().map(TicketId::as_str).collect::<Vec<_>>(),
        });
        Ok(EffectObservation::Applied {
            receipt: serde_json::to_string(&receipt).map_err(|error| error.to_string())?,
        })
    }
}

impl EffectHandler for CreateGoalTicketHandler {
    fn kind(&self) -> EffectKind {
        EffectKind::TicketCreate
    }

    fn handle(
        &self,
        mode: EffectMode,
        request: &EffectRequest,
        context: &mut EffectContext<'_>,
    ) -> Result<EffectObservation, String> {
        let payload: CreateGoalTicket = decode_payload(request)?;
        payload.validate()?;
        if request.intent.kind != "ticket_create"
            || request.intent.operation_id
                != goal_creation_operation_id(
                    &payload.project_id,
                    payload.goal_revision,
                    &payload.request_key,
                )
            || request.intent.project_id != payload.project_id
            || request.intent.subject_type != "project"
            || request.intent.subject_id != payload.project_id.as_str()
        {
            return Err("goal ticket create identity does not match its durable intent".into());
        }
        match mode {
            EffectMode::Submit => {
                let scope = TicketScope::new(payload.request.scope.clone())
                    .map_err(|error| error.to_string())?;
                let result = self
                    .adapter
                    .create(
                        request_id("goal-create")?,
                        operation_id(&request.intent.operation_id)?,
                        None,
                        TicketCreateRequest {
                            scope,
                            creation_key: payload.request.creation_key.clone(),
                            title: payload.request.title.clone(),
                            body: payload.request.body.clone(),
                            status: payload.request.status.map(normalized_status),
                            template: payload.request.template.clone(),
                            parent: payload.request.parent.clone(),
                            dependencies: payload.request.dependencies.clone(),
                            project: payload.request.project.clone(),
                            milestone: payload.request.milestone.clone(),
                            assignee: payload.request.assignee.clone(),
                            priority: payload.request.priority,
                            due_date: payload.request.due_date.clone(),
                            labels: payload.request.labels.clone(),
                        },
                    )
                    .map_err(adapter_error)?;
                if result.ticket_namespace != payload.namespace.as_str()
                    || result.ticket.ticket_namespace != payload.namespace.as_str()
                    || result.ticket.id.is_empty()
                {
                    return Err(
                        "ticket adapter create receipt has the wrong namespace or no identity"
                            .into(),
                    );
                }
                let candidate = crate::adapters::tickets::OperationMatch {
                    operation_id: request.intent.operation_id.clone(),
                    method: "ticket.create".into(),
                    ticket_id: Some(result.ticket.id.clone()),
                    stable_external_key: Some(payload.request.creation_key.clone()),
                    receipt: serde_json::to_value(result).map_err(|error| error.to_string())?,
                };
                self.store_candidates(
                    &payload,
                    request,
                    context,
                    &[candidate],
                    OperationMatchBasis::OperationId,
                )
            }
            EffectMode::Reconcile => {
                let scope = TicketScope::new(payload.request.scope.clone())
                    .map_err(|error| error.to_string())?;
                match lookup_operation(
                    self.adapter.as_ref(),
                    request,
                    OperationFindRequest {
                        scope,
                        operation_id: request.intent.operation_id.clone(),
                        stable_external_key: payload.request.creation_key.clone(),
                        method: "ticket.create".into(),
                        subject: [("creation_key".into(), payload.request.creation_key.clone())]
                            .into(),
                    },
                    EffectKind::TicketCreate,
                )? {
                    Lookup::Found { receipts, basis } => {
                        let matches: Vec<crate::adapters::tickets::OperationMatch> =
                            serde_json::from_value(Value::Array(receipts)).map_err(|_| {
                                "ticket create reconciliation receipt has an invalid schema"
                                    .to_owned()
                            })?;
                        self.store_candidates(&payload, request, context, &matches, basis)
                    }
                    Lookup::Absent(proof) => Ok(EffectObservation::AuthoritativelyAbsent { proof }),
                    Lookup::Unknown(receipt) => Ok(EffectObservation::Pending { receipt }),
                }
            }
        }
    }
}

struct ResolveDuplicateHandler {
    adapter: Arc<dyn TicketAdapter>,
    scopes: BTreeMap<ProjectId, TicketScope>,
}

impl ResolveDuplicateHandler {
    fn new(adapter: Arc<dyn TicketAdapter>, scopes: BTreeMap<ProjectId, TicketScope>) -> Self {
        Self { adapter, scopes }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DuplicateProgress {
    phase: String,
    comment_receipt: Option<Value>,
}

impl ResolveDuplicateHandler {
    fn handle_duplicate(
        &self,
        mode: EffectMode,
        request: &EffectRequest,
        context: &mut EffectContext<'_>,
    ) -> Result<EffectObservation, String> {
        let payload: ResolveDuplicateTicket = decode_payload(request)?;
        payload.validate()?;
        if payload.schema_version != 1
            || payload.project_id != request.intent.project_id
            || request.intent.kind != "ticket_resolve_duplicate"
            || request.intent.subject_type != "project"
            || request.intent.subject_id != payload.project_id.as_str()
        {
            return Err("duplicate ticket effect identity or resolution is invalid".into());
        }
        let scope = self
            .scopes
            .get(&payload.project_id)
            .cloned()
            .ok_or_else(|| "ticket scope is not configured for duplicate resolution".to_owned())?;
        let namespace = &payload.namespace;
        let duplicate = &payload.duplicate_ticket_id;
        let canonical = &payload.canonical_ticket_id;
        let comment_operation = sub_operation(&request.intent.operation_id, "comment")?;
        let cancel_operation = sub_operation(&request.intent.operation_id, "cancel")?;
        let prior = context.store.load_effect_progress(
            &request.intent.operation_id,
            context.owner_generation,
            &request.intent.request_digest,
        )?;
        let mut progress = match prior {
            Some(value) => serde_json::from_str::<DuplicateProgress>(&value)
                .map_err(|_| "duplicate effect progress has an invalid schema".to_owned())?,
            None => DuplicateProgress {
                phase: "comment_pending".into(),
                comment_receipt: None,
            },
        };
        if progress.phase == "resolved" {
            let _ = context.store.mark_goal_ticket_duplicate_resolved(
                context.owner_generation,
                GoalTicketDuplicateResolution {
                    project_id: &payload.project_id,
                    goal_revision: payload.goal_revision,
                    request_key: &payload.request_key,
                    namespace: &payload.namespace,
                    duplicate: &payload.duplicate_ticket_id,
                    now_unix: context.now_unix,
                },
            )?;
            return Ok(EffectObservation::Applied {
                receipt: "{\"resolved\":true}".into(),
            });
        }

        if progress.phase == "comment_pending" {
            match mode {
                EffectMode::Submit => {
                    let comment = self
                        .adapter
                        .comment(
                            request_id("duplicate-comment")?,
                            comment_operation.clone(),
                            None,
                            TicketCommentRequest {
                                scope: scope.clone(),
                                ticket_id: duplicate.as_str().into(),
                                comment_key: comment_operation.as_str().into(),
                                body: payload.comment_body.clone(),
                                references: vec![canonical.as_str().into()],
                            },
                        )
                        .map_err(adapter_error)?;
                    verify_comment(&comment, namespace, duplicate)?;
                    progress.phase = "comment_confirmed".into();
                    progress.comment_receipt =
                        Some(serde_json::to_value(comment).map_err(|error| error.to_string())?);
                    save_duplicate_progress(context, request, &progress)?;
                }
                EffectMode::Reconcile => match lookup_operation(
                    self.adapter.as_ref(),
                    request,
                    OperationFindRequest {
                        scope: scope.clone(),
                        operation_id: comment_operation.as_str().into(),
                        stable_external_key: comment_operation.as_str().into(),
                        method: "ticket.comment".into(),
                        subject: [("ticket_id".into(), duplicate.as_str().into())].into(),
                    },
                    EffectKind::TicketResolveDuplicate,
                )? {
                    Lookup::Found { mut receipts, .. } => {
                        if receipts.len() != 1 {
                            return Err("duplicate comment lookup returned multiple matches".into());
                        }
                        let comment: CommentResult = serde_json::from_value(receipts.remove(0))
                            .map_err(|_| "duplicate comment receipt is invalid".to_owned())?;
                        verify_comment(&comment, namespace, duplicate)?;
                        progress.phase = "comment_confirmed".into();
                        progress.comment_receipt =
                            Some(serde_json::to_value(comment).map_err(|error| error.to_string())?);
                        save_duplicate_progress(context, request, &progress)?;
                    }
                    Lookup::Absent(proof) => {
                        return Ok(EffectObservation::AuthoritativelyAbsent { proof });
                    }
                    Lookup::Unknown(receipt) => return Ok(EffectObservation::Pending { receipt }),
                },
            }
        }

        if mode == EffectMode::Reconcile {
            return match lookup_operation(
                self.adapter.as_ref(),
                request,
                OperationFindRequest {
                    scope: scope.clone(),
                    operation_id: cancel_operation.as_str().into(),
                    stable_external_key: cancel_operation.as_str().into(),
                    method: "ticket.update".into(),
                    subject: [("ticket_id".into(), duplicate.as_str().into())].into(),
                },
                EffectKind::TicketResolveDuplicate,
            )? {
                Lookup::Found { mut receipts, .. } => {
                    if receipts.len() != 1 {
                        return Err(
                            "duplicate cancellation lookup returned multiple matches".into()
                        );
                    }
                    let result: ScopedTicketResult = serde_json::from_value(receipts.remove(0))
                        .map_err(|_| "duplicate cancellation receipt is invalid".to_owned())?;
                    verify_canceled(&result, namespace, duplicate)?;
                    self.finish_duplicate(context, request, &payload, &mut progress, Some(result))
                }
                Lookup::Absent(proof) => Ok(EffectObservation::AuthoritativelyAbsent { proof }),
                Lookup::Unknown(receipt) => Ok(EffectObservation::Pending { receipt }),
            };
        }

        let current = self
            .adapter
            .get(
                request_id("duplicate-get")?,
                None,
                TicketGetRequest {
                    scope: scope.clone(),
                    ticket_id: duplicate.as_str().into(),
                    timeline_limit: Some(1),
                },
            )
            .map_err(adapter_error)?;
        validate_ticket_identity(
            &current.ticket_namespace,
            &current.ticket,
            namespace,
            duplicate,
        )?;
        if payload
            .expected_external_revision
            .as_deref()
            .is_some_and(|revision| current.ticket.revision.as_deref() != Some(revision))
        {
            return Err("duplicate ticket revision changed before cancellation".into());
        }
        if current.ticket.status.value == NormalizedTicketStatus::Canceled {
            return self.finish_duplicate(context, request, &payload, &mut progress, None);
        }
        let expected_revision = current.ticket.revision.ok_or_else(|| {
            "ticket adapter omitted the revision required for duplicate cancellation".to_owned()
        })?;
        let mut patch = BTreeMap::new();
        patch.insert(
            "status".into(),
            serde_json::to_value(NormalizedTicketStatus::Canceled)
                .map_err(|error| error.to_string())?,
        );
        let canceled = self
            .adapter
            .update(
                request_id("duplicate-cancel")?,
                cancel_operation,
                None,
                TicketUpdateRequest {
                    scope,
                    ticket_id: duplicate.as_str().into(),
                    expected_revision,
                    patch,
                },
            )
            .map_err(adapter_error)?;
        verify_canceled(&canceled, namespace, duplicate)?;
        self.finish_duplicate(context, request, &payload, &mut progress, Some(canceled))
    }

    fn finish_duplicate(
        &self,
        context: &mut EffectContext<'_>,
        request: &EffectRequest,
        payload: &ResolveDuplicateTicket,
        progress: &mut DuplicateProgress,
        receipt: Option<ScopedTicketResult>,
    ) -> Result<EffectObservation, String> {
        progress.phase = "resolved".into();
        save_duplicate_progress(context, request, progress)?;
        let _ = context.store.mark_goal_ticket_duplicate_resolved(
            context.owner_generation,
            GoalTicketDuplicateResolution {
                project_id: &payload.project_id,
                goal_revision: payload.goal_revision,
                request_key: &payload.request_key,
                namespace: &payload.namespace,
                duplicate: &payload.duplicate_ticket_id,
                now_unix: context.now_unix,
            },
        )?;
        let receipt = receipt
            .map(serde_json::to_value)
            .transpose()
            .map_err(|error| error.to_string())?
            .unwrap_or_else(|| json!({"already_canceled": true}));
        Ok(EffectObservation::Applied {
            receipt: serde_json::to_string(&receipt).map_err(|error| error.to_string())?,
        })
    }
}

impl EffectHandler for ResolveDuplicateHandler {
    fn kind(&self) -> EffectKind {
        EffectKind::TicketResolveDuplicate
    }
    fn handle(
        &self,
        mode: EffectMode,
        request: &EffectRequest,
        context: &mut EffectContext<'_>,
    ) -> Result<EffectObservation, String> {
        self.handle_duplicate(mode, request, context)
    }
}

struct CompleteTicketHandler;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompleteTicketIntent {
    schema_version: u32,
    project_id: ProjectId,
    ticket_run_id: TicketRunId,
    ticket_run_revision: u64,
}

impl EffectHandler for CompleteTicketHandler {
    fn kind(&self) -> EffectKind {
        EffectKind::CompleteTicket
    }
    fn handle(
        &self,
        _mode: EffectMode,
        request: &EffectRequest,
        context: &mut EffectContext<'_>,
    ) -> Result<EffectObservation, String> {
        let payload: CompleteTicketIntent = decode_payload(request)?;
        if payload.schema_version != 1
            || payload.ticket_run_revision == 0
            || payload.project_id != request.intent.project_id
            || request.intent.expected_revision != Some(payload.ticket_run_revision)
            || request.intent.subject_type != "ticket_run"
            || request.intent.subject_id != payload.ticket_run_id.as_str()
        {
            return Err("TicketRun completion effect identity is invalid".into());
        }
        let Some(proof) = context.store.ticket_completion_proof(
            context.owner_generation,
            &payload.project_id,
            &payload.ticket_run_id,
            payload.ticket_run_revision,
        )?
        else {
            return Err("TicketRun completion receipts are not yet available".into());
        };
        let target = context.store.ticket_run_status_target(
            context.owner_generation,
            &payload.project_id,
            &payload.ticket_run_id,
            payload.ticket_run_revision,
        )?;
        let new_revision = payload
            .ticket_run_revision
            .checked_add(1)
            .ok_or_else(|| "TicketRun revision is exhausted".to_owned())?;
        let status_payload = PublishTicketStatus {
            schema_version: 1,
            project_id: payload.project_id.clone(),
            namespace: target.namespace,
            ticket_id: target.ticket_id,
            ticket_run_id: payload.ticket_run_id.clone(),
            ticket_run_revision: new_revision,
            expected_external_revision: target.external_revision,
            desired_status: TicketStatus::Done,
            reason: "TicketRun completed after validated operation and Postmortem receipts".into(),
        };
        status_payload.validate()?;
        let status_json = serde_json::to_string(
            &serde_json::to_value(&status_payload).map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        let status_digest = format!("{:x}", Sha256::digest(status_json.as_bytes()));
        let status_id = sub_operation(&request.intent.operation_id, "publish-done")?;
        let status_effect = EffectIntent {
            project_id: payload.project_id.clone(),
            subject_type: "ticket_run".into(),
            subject_id: payload.ticket_run_id.as_str().into(),
            operation_id: status_id.as_str().into(),
            logical_key: format!("{}:publish_done", request.intent.logical_key),
            kind: serde_json::to_value(EffectKind::PublishTicketStatus)
                .map_err(|error| error.to_string())?
                .as_str()
                .ok_or_else(|| "effect kind did not serialize as a string".to_owned())?
                .into(),
            request_json: status_json,
            request_digest: status_digest,
            expected_revision: Some(new_revision),
        };
        let input_payload = json!({"type":"completion_observed","ticket_run_id":payload.ticket_run_id.as_str(),"revision":payload.ticket_run_revision}).to_string();
        let input = DurableInput {
            producer_id: format!("host:complete-ticket:{}", payload.project_id.as_str()),
            message_id: request.intent.operation_id.clone(),
            content_digest: durable_input_digest("ticket_run", &input_payload),
            recipient: "ticket_run".into(),
            payload: input_payload.clone(),
        };
        let evidence = json!({"effect_operation_id": request.intent.operation_id, "proof_plan_digest": proof.plan_digest().as_str(), "postmortem_receipt_digest": proof.postmortem_receipt_digest().as_str(), "knowledge_operation_id": proof.knowledge_operation_id(), "knowledge_manifest_digest": proof.knowledge_manifest_digest().as_str()}).to_string();
        let result = context.store.commit_ticket_completion(
            context.owner_generation,
            &payload.ticket_run_id,
            Revision(payload.ticket_run_revision),
            &input,
            "host validated completion receipts",
            &evidence,
            &[status_effect],
            &proof,
        )?;
        Ok(EffectObservation::Applied {
            receipt: serde_json::to_string(&result.receipt).map_err(|error| error.to_string())?,
        })
    }
}

enum Lookup {
    Found {
        receipts: Vec<Value>,
        basis: OperationMatchBasis,
    },
    Absent(AbsentProof),
    Unknown(String),
}

fn lookup_operation(
    adapter: &dyn TicketAdapter,
    request: &EffectRequest,
    lookup: OperationFindRequest,
    handler_kind: EffectKind,
) -> Result<Lookup, String> {
    let operation = operation_id(&lookup.operation_id)?;
    let result: OperationLookup = adapter
        .find_operation(
            request_id("operation-find")?,
            None,
            OperationFindRequest {
                operation_id: operation.as_str().into(),
                ..lookup
            },
        )
        .map_err(adapter_error)?;
    match result.outcome {
        ReconciliationOutcome::Found => {
            let basis = result
                .match_basis
                .ok_or_else(|| "ticket operation lookup omitted its match basis".to_owned())?;
            Ok(Lookup::Found {
                receipts: result
                    .matches
                    .into_iter()
                    .map(|matched| matched.receipt)
                    .collect(),
                basis,
            })
        }
        ReconciliationOutcome::Absent => {
            let evidence =
                serde_json::to_string(&result.proof.ok_or_else(|| {
                    "ticket adapter omitted authoritative absence proof".to_owned()
                })?)
                .map_err(|error| error.to_string())?;
            let proof = AbsentProof::from_authoritative_lookup(
                handler_kind,
                request,
                "configured ticket adapter operation.find",
                evidence,
            )?;
            Ok(Lookup::Absent(proof))
        }
        ReconciliationOutcome::Unknown => Ok(Lookup::Unknown(
            serde_json::to_string(&result).map_err(|error| error.to_string())?,
        )),
    }
}

fn decode_payload<T: DeserializeOwned>(request: &EffectRequest) -> Result<T, String> {
    crate::protocol::parse_unique(request.intent.request_json.as_bytes())
        .map_err(|error| format!("ticket effect request is invalid: {error}"))
}

fn request_id(purpose: &str) -> Result<RequestId, String> {
    let sequence = REQUEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    RequestId::new(format!("rex-projects-{purpose}-{sequence}"))
}

fn operation_id(value: &str) -> Result<OperationId, String> {
    OperationId::parse(value.to_owned())
}

fn sub_operation(parent: &str, phase: &str) -> Result<OperationId, String> {
    let digest = format!(
        "{:x}",
        Sha256::digest(format!("{parent}\0{phase}").as_bytes())
    );
    OperationId::parse(format!("op-{}", &digest[..48]))
}

fn goal_creation_operation_id(
    project: &ProjectId,
    goal_revision: u64,
    request_key: &str,
) -> String {
    let digest = format!(
        "{:x}",
        Sha256::digest(
            format!(
                "goal-ticket\0{}\0{goal_revision}\0{request_key}",
                project.as_str()
            )
            .as_bytes()
        )
    );
    format!("op-{}", &digest[..48])
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

fn validate_ticket_identity(
    result_namespace: &str,
    ticket: &crate::adapters::tickets::NormalizedTicket,
    namespace: &TicketNamespace,
    ticket_id: &TicketId,
) -> Result<(), String> {
    if result_namespace != namespace.as_str()
        || ticket.ticket_namespace != namespace.as_str()
        || ticket.id != ticket_id.as_str()
    {
        return Err("ticket adapter returned a different ticket or namespace".into());
    }
    Ok(())
}

fn verify_comment(
    result: &CommentResult,
    namespace: &TicketNamespace,
    ticket_id: &TicketId,
) -> Result<(), String> {
    if result.ticket_namespace != namespace.as_str()
        || result.comment.ticket_id != ticket_id.as_str()
        || result.comment.reference.is_empty()
    {
        return Err("duplicate comment receipt does not match its target".into());
    }
    Ok(())
}

fn verify_canceled(
    result: &ScopedTicketResult,
    namespace: &TicketNamespace,
    ticket_id: &TicketId,
) -> Result<(), String> {
    validate_ticket_identity(
        &result.ticket_namespace,
        &result.ticket,
        namespace,
        ticket_id,
    )?;
    if result.ticket.status.value != NormalizedTicketStatus::Canceled {
        return Err("duplicate cancellation receipt is not canceled".into());
    }
    Ok(())
}

fn save_duplicate_progress(
    context: &mut EffectContext<'_>,
    request: &EffectRequest,
    progress: &DuplicateProgress,
) -> Result<(), String> {
    let json =
        serde_json::to_string(&serde_json::to_value(progress).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    context.store.save_effect_progress(
        &request.intent.operation_id,
        context.owner_generation,
        &request.intent.request_digest,
        &json,
        context.now_unix,
    )
}

fn adapter_error(error: TicketAdapterError) -> String {
    error.to_string()
}

fn observation_applied<T: Serialize>(value: &T) -> Result<EffectObservation, String> {
    Ok(EffectObservation::Applied {
        receipt: serde_json::to_string(value).map_err(|error| error.to_string())?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use crate::adapters::tickets::{
        AdapterCapabilities, AdapterDescription, DuplicateResolutionRequest,
        DuplicateResolutionResult, NormalizedTicket, OperationMatch, TicketGetResult,
        TicketListRequest, TicketPage, TicketStatusValue,
    };
    use crate::config::{AppliedConfig, SourceFile, SourceKind};
    use crate::domain::ids::{Digest, Revision};
    use crate::engine::reducer::Input;
    use crate::human_runtime::{HumanSubjectObservation, HumanSubjectObserver};
    use crate::store::{ExpectedRevision, OwnerMetadata, ProjectRecord};

    struct FixedTicketSubjectObserver;

    impl HumanSubjectObserver for FixedTicketSubjectObserver {
        fn observe_current_subject(
            &self,
            _store: &crate::store::ConfigStore,
            request: &crate::human_runtime::HumanRuntimeRequest,
        ) -> Result<HumanSubjectObservation, String> {
            Ok(HumanSubjectObservation::Current(request.subject.clone()))
        }
    }

    struct FakeTicketStatusAdoptionSource {
        adapter: Arc<FakeAdapter>,
        scope: TicketScope,
    }

    impl crate::human_runtime::TicketStatusAdoptionSource for FakeTicketStatusAdoptionSource {
        fn observe_ticket_status_adoption(
            &self,
            authority: &crate::human_runtime::TicketStatusAdoptionAuthority,
        ) -> Result<Option<String>, String> {
            let observed = self
                .adapter
                .get(
                    request_id("test-status-adoption-observe")?,
                    None,
                    TicketGetRequest {
                        scope: self.scope.clone(),
                        ticket_id: authority.ticket_id.as_str().into(),
                        timeline_limit: Some(1),
                    },
                )
                .map_err(adapter_error)?;
            serde_json::to_string(&observed)
                .map(Some)
                .map_err(|error| error.to_string())
        }
    }

    struct FakeAdapter {
        namespace: String,
        calls: Mutex<Vec<&'static str>>,
        operations: Mutex<Vec<OperationMatch>>,
        ticket: Mutex<NormalizedTicket>,
        fail_next_update: Mutex<bool>,
        unknown_lookups: Mutex<bool>,
    }

    impl FakeAdapter {
        fn new(
            scope: TicketScope,
            namespace: &str,
            ticket_id: &str,
            status: NormalizedTicketStatus,
        ) -> Self {
            Self {
                namespace: namespace.into(),
                calls: Mutex::new(Vec::new()),
                operations: Mutex::new(Vec::new()),
                fail_next_update: Mutex::new(false),
                unknown_lookups: Mutex::new(false),
                ticket: Mutex::new(NormalizedTicket {
                    ticket_namespace: namespace.into(),
                    scope,
                    id: ticket_id.into(),
                    key: None,
                    url: None,
                    revision: Some("revision-1".into()),
                    title: "A ticket".into(),
                    body: "Criteria".into(),
                    status: TicketStatusValue {
                        value: status,
                        native_value: None,
                        provider_id: None,
                        label: None,
                    },
                    priority: None,
                    labels: vec![],
                    dependencies: vec![],
                    created_at: Some("2026-01-01T00:00:00Z".into()),
                    updated_at: None,
                    extensions: BTreeMap::new(),
                }),
            }
        }

        fn save_operation(
            &self,
            operation_id: &OperationId,
            method: &str,
            ticket_id: &str,
            stable_key: Option<String>,
            receipt: Value,
        ) {
            self.operations.lock().unwrap().push(OperationMatch {
                operation_id: operation_id.as_str().into(),
                method: method.into(),
                ticket_id: Some(ticket_id.into()),
                stable_external_key: stable_key,
                receipt,
            });
        }
    }

    impl TicketAdapter for FakeAdapter {
        fn describe(
            &self,
            _request_id: RequestId,
        ) -> Result<AdapterDescription, TicketAdapterError> {
            Ok(AdapterDescription {
                ticket_namespace: self.namespace.clone(),
                identity: BTreeMap::new(),
                supported_schema_versions: vec![1],
                native_value_convention: "test".into(),
                status_values: BTreeMap::new(),
                capabilities: AdapterCapabilities {
                    pagination: true,
                    filters: Default::default(),
                    revision_support: true,
                    conditional_revision_mutation: true,
                    atomic_scope_mutation: true,
                    remote_idempotency: vec!["operation_id".into()],
                    reconciliation: BTreeMap::new(),
                    visibility_grace_seconds: 0.0,
                    supported_optional_methods: Default::default(),
                },
            })
        }

        fn list(
            &self,
            _request_id: RequestId,
            _project_id: Option<ProjectId>,
            _query: TicketListRequest,
        ) -> Result<TicketPage, TicketAdapterError> {
            Err(TicketAdapterError::Invalid("unused fake list".into()))
        }

        fn get(
            &self,
            _request_id: RequestId,
            _project_id: Option<ProjectId>,
            query: TicketGetRequest,
        ) -> Result<TicketGetResult, TicketAdapterError> {
            self.calls.lock().unwrap().push("get");
            let mut ticket = self.ticket.lock().unwrap().clone();
            ticket.id = query.ticket_id;
            Ok(TicketGetResult {
                ticket_namespace: self.namespace.clone(),
                ticket,
                timeline: vec![],
            })
        }

        fn create(
            &self,
            _request_id: RequestId,
            operation_id: OperationId,
            _project_id: Option<ProjectId>,
            input: TicketCreateRequest,
        ) -> Result<ScopedTicketResult, TicketAdapterError> {
            self.calls.lock().unwrap().push("create");
            let result = ScopedTicketResult {
                ticket_namespace: self.namespace.clone(),
                ticket: NormalizedTicket {
                    ticket_namespace: self.namespace.clone(),
                    scope: input.scope,
                    id: "ticket-created".into(),
                    key: None,
                    url: None,
                    revision: Some("created-revision".into()),
                    title: input.title,
                    body: input.body,
                    status: TicketStatusValue {
                        value: input.status.unwrap_or(NormalizedTicketStatus::Ready),
                        native_value: None,
                        provider_id: None,
                        label: None,
                    },
                    priority: input.priority,
                    labels: input.labels.unwrap_or_default(),
                    dependencies: input.dependencies.unwrap_or_default(),
                    created_at: Some("2026-01-02T00:00:00Z".into()),
                    updated_at: None,
                    extensions: BTreeMap::new(),
                },
            };
            self.save_operation(
                &operation_id,
                "ticket.create",
                &result.ticket.id,
                Some(input.creation_key),
                serde_json::to_value(&result).unwrap(),
            );
            Ok(result)
        }

        fn update(
            &self,
            _request_id: RequestId,
            operation_id: OperationId,
            _project_id: Option<ProjectId>,
            input: TicketUpdateRequest,
        ) -> Result<ScopedTicketResult, TicketAdapterError> {
            self.calls.lock().unwrap().push("update");
            let mut fail_next = self.fail_next_update.lock().unwrap();
            if *fail_next {
                *fail_next = false;
                return Err(TicketAdapterError::Uncertain);
            }
            drop(fail_next);
            let status = serde_json::from_value::<NormalizedTicketStatus>(
                input.patch.get("status").cloned().unwrap_or(Value::Null),
            )
            .map_err(|error| TicketAdapterError::Invalid(error.to_string()))?;
            let mut ticket = self.ticket.lock().unwrap();
            if ticket.revision.as_deref() != Some(input.expected_revision.as_str()) {
                return Err(TicketAdapterError::Invalid("stale revision".into()));
            }
            ticket.id = input.ticket_id;
            ticket.revision = Some("revision-2".into());
            ticket.status.value = status;
            let result = ScopedTicketResult {
                ticket_namespace: self.namespace.clone(),
                ticket: ticket.clone(),
            };
            self.save_operation(
                &operation_id,
                "ticket.update",
                &result.ticket.id,
                None,
                serde_json::to_value(&result).unwrap(),
            );
            Ok(result)
        }

        fn comment(
            &self,
            _request_id: RequestId,
            operation_id: OperationId,
            _project_id: Option<ProjectId>,
            input: TicketCommentRequest,
        ) -> Result<CommentResult, TicketAdapterError> {
            self.calls.lock().unwrap().push("comment");
            let result = CommentResult {
                ticket_namespace: self.namespace.clone(),
                comment: crate::adapters::tickets::CommentReceipt {
                    reference: "comment-1".into(),
                    ticket_id: input.ticket_id.clone(),
                    key: input.comment_key,
                    created_at: "2026-01-02T00:00:00Z".into(),
                },
            };
            self.save_operation(
                &operation_id,
                "ticket.comment",
                &input.ticket_id,
                None,
                serde_json::to_value(&result).unwrap(),
            );
            Ok(result)
        }

        fn resolve_duplicate(
            &self,
            _request_id: RequestId,
            _operation_id: OperationId,
            _project_id: Option<ProjectId>,
            _input: DuplicateResolutionRequest,
        ) -> Result<DuplicateResolutionResult, TicketAdapterError> {
            Err(TicketAdapterError::Invalid(
                "atomic duplicate resolution must not be used".into(),
            ))
        }

        fn find_operation(
            &self,
            _request_id: RequestId,
            _project_id: Option<ProjectId>,
            input: OperationFindRequest,
        ) -> Result<OperationLookup, TicketAdapterError> {
            let found = self
                .operations
                .lock()
                .unwrap()
                .iter()
                .filter(|item| {
                    item.method == input.method
                        && (item.operation_id == input.operation_id
                            || item.stable_external_key.as_deref()
                                == Some(input.stable_external_key.as_str()))
                })
                .cloned()
                .collect::<Vec<_>>();
            if found.is_empty() {
                if *self.unknown_lookups.lock().unwrap() {
                    return Ok(OperationLookup {
                        ticket_namespace: self.namespace.clone(),
                        outcome: ReconciliationOutcome::Unknown,
                        match_basis: None,
                        reason: Some("fixture cannot establish remote operation visibility".into()),
                        matches: vec![],
                        proof: None,
                    });
                }
                Ok(OperationLookup {
                    ticket_namespace: self.namespace.clone(),
                    outcome: ReconciliationOutcome::Absent,
                    match_basis: None,
                    reason: None,
                    matches: vec![],
                    proof: Some(json!({"checked": input.operation_id})),
                })
            } else {
                let basis = if found
                    .iter()
                    .all(|item| item.operation_id == input.operation_id)
                {
                    OperationMatchBasis::OperationId
                } else {
                    OperationMatchBasis::StableExternalKey
                };
                Ok(OperationLookup {
                    ticket_namespace: self.namespace.clone(),
                    outcome: ReconciliationOutcome::Found,
                    match_basis: Some(basis),
                    reason: None,
                    matches: found,
                    proof: None,
                })
            }
        }
    }

    fn test_store() -> (tempfile::TempDir, crate::store::ConfigStore, ProjectId, u64) {
        let temp = tempfile::tempdir().unwrap();
        let mut store = crate::store::ConfigStore::open_test(temp.path()).unwrap();
        let digest = "a".repeat(64);
        let applied = store
            .apply_snapshot(
                "factory",
                &AppliedConfig {
                    config: serde_json::from_value(json!({
                        "schema_version": 1,
                        "adapters": {"tickets": {"kind":"command","command":["test"]}},
                        "projects": {}
                    }))
                    .unwrap(),
                    profiles: BTreeMap::new(),
                    source_root: "/tmp/config".into(),
                    source_files: vec![SourceFile {
                        kind: SourceKind::File,
                        path: "/tmp/config/config.toml".into(),
                        canonical_path: "/tmp/config/config.toml".into(),
                        sha256: Digest::parse(digest.clone()).unwrap(),
                        bytes: 1,
                        contents: "x".into(),
                    }],
                    digest: Digest::parse(digest.clone()).unwrap(),
                },
                ExpectedRevision::Bootstrap,
            )
            .unwrap();
        let project = ProjectId::parse("handler-test").unwrap();
        store
            .insert_project(&ProjectRecord {
                id: project.clone(),
                config_source: "factory".into(),
                config_revision: applied.revision,
                config_digest: Digest::parse(digest).unwrap(),
                mode: "goal".into(),
                goal_revision: 1,
                desired_lifecycle: "running".into(),
                state_revision: Revision(0),
            })
            .unwrap();
        let generation = store
            .start_owner(&OwnerMetadata {
                owner_nonce: "handler-test-owner".into(),
                state_root: temp.path().display().to_string(),
                config_source: "factory".into(),
                process_start_identity: "test".into(),
                executable_path: "/tmp/rex-projects-test".into(),
                executable_digest: "f".repeat(64),
                rex_endpoint: None,
                rex_server_identity: None,
                rex_session_id: None,
                rex_block_id: None,
            })
            .unwrap();
        (temp, store, project, generation)
    }

    fn hash(value: &str) -> String {
        format!("{:x}", Sha256::digest(value.as_bytes()))
    }

    fn effect_request(
        project: &ProjectId,
        subject_type: &str,
        subject_id: &str,
        operation: &str,
        kind: &str,
        payload: Value,
    ) -> EffectRequest {
        let request_json = serde_json::to_string(&payload).unwrap();
        EffectRequest {
            intent: crate::store::EffectIntent {
                project_id: project.clone(),
                subject_type: subject_type.into(),
                subject_id: subject_id.into(),
                operation_id: operation.into(),
                logical_key: format!("{operation}:logical"),
                kind: kind.into(),
                request_digest: hash(&request_json),
                request_json,
                expected_revision: Some(1),
            },
            attempt_count: 0,
            created_at_unix: 1,
        }
    }

    fn scope() -> TicketScope {
        TicketScope::new(BTreeMap::from([("project".into(), "fixture".into())])).unwrap()
    }

    #[test]
    fn duplicate_effect_comments_then_cancels_with_stable_phase_operations() {
        let (_temp, mut store, project, owner) = test_store();
        let namespace = TicketNamespace::parse("fixture:workspace").unwrap();
        let proposal = crate::engine::ticket_effects::GoalTicketProposal {
            project_id: project.clone(),
            goal_revision: 1,
            title: "Add behavior".into(),
            body: "Criteria".into(),
            labels: Default::default(),
        };
        let proposal_json =
            serde_json::to_string(&serde_json::to_value(&proposal).unwrap()).unwrap();
        let proposal_digest = hash(&proposal_json);
        let key = format!("goal-{proposal_digest}");
        let ticket_request = CreateGoalTicket {
            schema_version: 1,
            project_id: project.clone(),
            namespace: namespace.clone(),
            goal_revision: 1,
            request_key: key.clone(),
            request_digest: Digest::parse(proposal_digest.clone()).unwrap(),
            proposal: crate::engine::ticket_effects::GoalTicketProposal {
                project_id: project.clone(),
                goal_revision: 1,
                title: "Add behavior".into(),
                body: "Criteria".into(),
                labels: Default::default(),
            },
            request: crate::engine::ticket_effects::TicketCreationRequest {
                scope: scope().as_map().clone(),
                creation_key: key.clone(),
                title: "Add behavior".into(),
                body: "Criteria".into(),
                status: Some(TicketStatus::Ready),
                template: None,
                parent: None,
                dependencies: None,
                project: None,
                milestone: None,
                assignee: None,
                priority: None,
                due_date: None,
                labels: Some(vec![]),
            },
        };
        let reservation = store
            .reserve_goal_ticket_creation(
                owner,
                crate::store::scheduler::GoalTicketCreation {
                    project_id: &project,
                    namespace: &namespace,
                    request_key: &key,
                    request_digest: &proposal_digest,
                    proposal_json: &proposal_json,
                    ticket_request: &ticket_request,
                    maximum: 5,
                    now_unix: 1,
                },
            )
            .unwrap();
        store
            .record_goal_ticket_candidates(
                owner,
                &reservation.operation_id,
                &[
                    GoalTicketCandidateRecord {
                        namespace: namespace.clone(),
                        ticket_id: TicketId::parse("ticket-canonical").unwrap(),
                        match_basis:
                            crate::engine::factory_runtime::GoalTicketMatchBasis::OperationId,
                        created_at: Some("2026-01-01T00:00:00Z".into()),
                    },
                    GoalTicketCandidateRecord {
                        namespace: namespace.clone(),
                        ticket_id: TicketId::parse("ticket-duplicate").unwrap(),
                        match_basis:
                            crate::engine::factory_runtime::GoalTicketMatchBasis::StableExternalKey,
                        created_at: Some("2026-01-02T00:00:00Z".into()),
                    },
                ],
                2,
            )
            .unwrap();
        let claimed = store
            .claim_next_due_effect(owner, 3, &["ticket_resolve_duplicate".into()])
            .unwrap()
            .unwrap();
        let request: EffectRequest = claimed.into();
        let adapter = Arc::new(FakeAdapter::new(
            scope(),
            namespace.as_str(),
            "ticket-duplicate",
            NormalizedTicketStatus::InProgress,
        ));
        let handler = ResolveDuplicateHandler::new(
            adapter.clone(),
            BTreeMap::from([(project.clone(), scope())]),
        );
        *adapter.fail_next_update.lock().unwrap() = true;
        let mut context = EffectContext {
            store: &mut store,
            owner_generation: owner,
            now_unix: 3,
        };
        assert!(
            handler
                .handle(EffectMode::Submit, &request, &mut context)
                .is_err()
        );
        assert!(matches!(
            handler
                .handle(EffectMode::Reconcile, &request, &mut context)
                .unwrap(),
            EffectObservation::AuthoritativelyAbsent { .. }
        ));
        let observation = handler
            .handle(EffectMode::Submit, &request, &mut context)
            .unwrap();
        assert!(matches!(observation, EffectObservation::Applied { .. }));
        assert_eq!(
            *adapter.calls.lock().unwrap(),
            ["comment", "get", "update", "get", "update"]
        );
        let progress = context
            .store
            .load_effect_progress(
                &request.intent.operation_id,
                owner,
                &request.intent.request_digest,
            )
            .unwrap()
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&progress).unwrap()["phase"],
            "resolved"
        );
        assert!(
            handler
                .handle(EffectMode::Submit, &request, &mut context)
                .unwrap()
                .eq(&EffectObservation::Applied {
                    receipt: "{\"resolved\":true}".into()
                })
        );
        assert_eq!(
            *adapter.calls.lock().unwrap(),
            ["comment", "get", "update", "get", "update"]
        );
    }

    #[test]
    fn status_publication_uses_conditional_update_and_checks_run_authority() {
        let (_temp, mut store, project, owner) = test_store();
        let namespace = TicketNamespace::parse("fixture:workspace").unwrap();
        let ticket = TicketId::parse("ticket-status").unwrap();
        let run = TicketRunId::parse("run-status").unwrap();
        store
            .create_ticket_run(
                owner, &project, &namespace, &ticket, &run, 1, "queued", "ready",
            )
            .unwrap();
        store
            .test_connection()
            .execute(
                "UPDATE ticket_runs SET external_revision='revision-1' WHERE project_id=?1 AND ticket_run_id=?2",
                rusqlite::params![project.as_str(), run.as_str()],
            )
            .unwrap();
        let status = PublishTicketStatus {
            schema_version: 1,
            project_id: project.clone(),
            namespace: namespace.clone(),
            ticket_id: ticket.clone(),
            ticket_run_id: run.clone(),
            ticket_run_revision: 1,
            expected_external_revision: Some("revision-1".into()),
            desired_status: TicketStatus::InProgress,
            reason: "dispatch".into(),
        };
        let status_value = serde_json::to_value(&status).unwrap();
        let status_json = serde_json::to_string(&status_value).unwrap();
        let status_intent = EffectIntent {
            project_id: project.clone(),
            subject_type: "ticket_run".into(),
            subject_id: run.as_str().into(),
            operation_id: "op-status-publication".into(),
            logical_key: "status-publication".into(),
            kind: "publish_ticket_status".into(),
            request_json: status_json.clone(),
            request_digest: hash(&status_json),
            expected_revision: Some(1),
        };
        let transition_payload = "{\"kind\":\"dispatch\"}";
        store
            .commit_ticket_transition(
                owner,
                &run,
                Revision(0),
                &DurableInput {
                    producer_id: "host:test".into(),
                    message_id: "dispatch-1".into(),
                    content_digest: durable_input_digest("ticket_run", transition_payload),
                    recipient: "ticket_run".into(),
                    payload: transition_payload.into(),
                },
                Input::Dispatch,
                "dispatch",
                "{}",
                std::slice::from_ref(&status_intent),
            )
            .unwrap();
        let mut missing_revision = status.clone();
        missing_revision.expected_external_revision = None;
        assert!(
            store
                .validate_ticket_status_publication(owner, &missing_revision)
                .is_err()
        );
        let adapter = Arc::new(FakeAdapter::new(
            scope(),
            namespace.as_str(),
            ticket.as_str(),
            NormalizedTicketStatus::Ready,
        ));
        let handler = PublishTicketStatusHandler::new(
            adapter.clone(),
            BTreeMap::from([(project.clone(), scope())]),
        );
        let claimed = store
            .claim_next_due_effect(owner, i64::MAX, &["publish_ticket_status".into()])
            .unwrap()
            .unwrap();
        let request = EffectRequest {
            intent: claimed.intent,
            attempt_count: claimed.attempt_count,
            created_at_unix: claimed.created_at_unix,
        };
        let mut context = EffectContext {
            store: &mut store,
            owner_generation: owner,
            now_unix: 4,
        };
        let submission = handler
            .handle(EffectMode::Submit, &request, &mut context)
            .unwrap();
        assert!(matches!(submission, EffectObservation::Applied { .. }));
        context
            .store
            .defer_effect_reconciliation("op-status-publication", owner, None, None, 5)
            .unwrap();
        let uncertain = context
            .store
            .claim_next_due_effect(owner, 5, &["publish_ticket_status".into()])
            .unwrap()
            .unwrap();
        let uncertain_request = EffectRequest {
            intent: uncertain.intent,
            attempt_count: uncertain.attempt_count,
            created_at_unix: uncertain.created_at_unix,
        };
        let reconciled = handler
            .handle(EffectMode::Reconcile, &uncertain_request, &mut context)
            .unwrap();
        let EffectObservation::Applied { receipt } = reconciled else {
            panic!("operation lookup did not recover the applied status receipt");
        };
        let valid_result = ScopedTicketResult {
            ticket_namespace: namespace.as_str().into(),
            ticket: adapter.ticket.lock().unwrap().clone(),
        };
        let mut invalid_result = valid_result.clone();
        invalid_result.ticket.revision = None;
        let invalid_receipt = serde_json::to_string(&invalid_result).unwrap();
        assert!(
            context
                .store
                .finish_effect(
                    "op-status-publication",
                    owner,
                    crate::store::EffectOutcome::Succeeded,
                    Some(&invalid_receipt),
                )
                .is_err()
        );
        let claim_state: (String, Option<u64>, Option<String>) = context
            .store
            .test_connection()
            .query_row(
                "SELECT status,owner_generation,receipt_json FROM effects WHERE operation_id='op-status-publication'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(claim_state.0, "claimed");
        assert_eq!(claim_state.1, Some(owner));
        assert_eq!(claim_state.2, None);
        let revision_after_invalid_receipt: Option<String> = context
            .store
            .test_connection()
            .query_row(
                "SELECT external_revision FROM ticket_runs WHERE project_id=?1 AND ticket_run_id=?2",
                rusqlite::params![project.as_str(), run.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            revision_after_invalid_receipt.as_deref(),
            Some("revision-1")
        );
        context
            .store
            .finish_effect(
                "op-status-publication",
                owner,
                crate::store::EffectOutcome::Succeeded,
                Some(&receipt),
            )
            .unwrap();
        assert_eq!(*adapter.calls.lock().unwrap(), ["get", "update"]);
        assert_eq!(
            adapter.ticket.lock().unwrap().status.value,
            NormalizedTicketStatus::InProgress
        );
        let saved_revision: Option<String> = context
            .store
            .test_connection()
            .query_row(
                "SELECT external_revision FROM ticket_runs WHERE project_id=?1 AND ticket_run_id=?2",
                rusqlite::params![project.as_str(), run.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(saved_revision.as_deref(), Some("revision-2"));
        validate_ticket_status_receipt(&status, &valid_result).unwrap();
        for invalid_revision in [None, Some(String::new()), Some("r".repeat(513))] {
            let mut invalid_result = valid_result.clone();
            invalid_result.ticket.revision = invalid_revision;
            assert!(validate_ticket_status_receipt(&status, &invalid_result).is_err());
        }
    }

    #[test]
    fn initial_dispatch_status_outbox_reaches_ticket_adapter() {
        use crate::domain::ids::{AdapterId, Digest, TicketId, TicketNamespace};
        use crate::store::scheduler::{
            ObservedTicket, SupervisorDispatchAuthority, TicketScanKey, TicketScanPage,
        };

        let (_temp, mut store, project, owner) = test_store();
        store
            .set_project_lifecycle(owner, &project, "running")
            .unwrap();
        let namespace = TicketNamespace::parse("fixture:workspace").unwrap();
        let ticket = TicketId::parse("ticket-dispatch-status").unwrap();
        let key = TicketScanKey {
            project_id: project.clone(),
            adapter_id: AdapterId::parse("tickets").unwrap(),
            namespace: namespace.clone(),
            scope_digest: Digest::parse("a".repeat(64)).unwrap(),
            filter_digest: Digest::parse("b".repeat(64)).unwrap(),
            status: TicketStatus::Ready,
        };
        let observed = ObservedTicket {
            id: ticket.clone(),
            revision: Some("revision-1".into()),
            status: TicketStatus::Ready,
            title: "Dispatch status fixture".into(),
            labels: Vec::new(),
            created_at: None,
            observed_at_unix: 2,
        };
        store
            .record_ticket_scan_page(
                owner,
                TicketScanPage {
                    key: &key,
                    expected_cursor: None,
                    expected_generation: 0,
                    expected_page_count: 0,
                    next_cursor: None,
                    tickets: std::slice::from_ref(&observed),
                    now_unix: 2,
                    poll_seconds: 60,
                },
            )
            .unwrap();
        let run = store
            .create_dispatched_ticket_run(
                owner,
                &key,
                &ticket,
                Some("docs_only"),
                &[TicketStatus::Ready],
                1,
                &SupervisorDispatchAuthority {
                    evidence_id: "dispatch-status-evidence".into(),
                    priority: 3,
                    expected_external_revision: "revision-1".into(),
                },
                3,
            )
            .unwrap()
            .unwrap();
        let fake = FakeAdapter::new(
            scope(),
            namespace.as_str(),
            ticket.as_str(),
            NormalizedTicketStatus::Ready,
        );
        fake.ticket.lock().unwrap().revision = Some("revision-1".into());
        let adapter = Arc::new(fake);
        let owned_handlers = TicketEffectHandlers::new(
            adapter.clone(),
            BTreeMap::from([(project.clone(), scope())]),
        )
        .into_handlers();
        let handler_refs = owned_handlers
            .iter()
            .map(|handler| handler.as_ref())
            .collect::<Vec<_>>();
        let dispatched = crate::effects::EffectDispatcher::tick(
            &mut store,
            owner,
            4,
            &handler_refs,
            crate::effects::EffectLimits {
                max_attempts: 5,
                max_age: std::time::Duration::from_secs(300),
                retry_base: std::time::Duration::from_secs(1),
                retry_max: std::time::Duration::from_secs(10),
            },
        )
        .unwrap();
        assert!(matches!(
            dispatched,
            crate::effects::DispatchTick::Completed { .. }
        ));
        assert_eq!(*adapter.calls.lock().unwrap(), ["get", "update"]);
        assert_eq!(
            adapter.ticket.lock().unwrap().status.value,
            NormalizedTicketStatus::InProgress
        );
        let saved_revision: Option<String> = store
            .test_connection()
            .query_row(
                "SELECT external_revision FROM ticket_runs WHERE project_id=?1 AND ticket_run_id=?2",
                rusqlite::params![project.as_str(), run.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            saved_revision.as_deref(),
            Some("revision-2"),
            "a successful ticket adapter status update must advance the saved CAS revision"
        );
    }

    #[test]
    fn goal_create_records_host_verified_candidate_from_cli_receipt() {
        let (_temp, mut store, project, owner) = test_store();
        let namespace = TicketNamespace::parse("fixture:workspace").unwrap();
        let proposal = crate::engine::ticket_effects::GoalTicketProposal {
            project_id: project.clone(),
            goal_revision: 1,
            title: "Create a ticket".into(),
            body: "Criteria".into(),
            labels: Default::default(),
        };
        let proposal_bytes = serde_json::to_vec(&serde_json::to_value(&proposal).unwrap()).unwrap();
        let proposal_digest = hash(std::str::from_utf8(&proposal_bytes).unwrap());
        let request_key = format!("goal-{proposal_digest}");
        let proposal_json =
            serde_json::to_string(&serde_json::to_value(&proposal).unwrap()).unwrap();
        let payload = CreateGoalTicket {
            schema_version: 1,
            project_id: project.clone(),
            namespace: namespace.clone(),
            goal_revision: 1,
            request_key: request_key.clone(),
            request_digest: Digest::parse(proposal_digest.clone()).unwrap(),
            proposal: proposal.clone(),
            request: crate::engine::ticket_effects::TicketCreationRequest {
                scope: scope().as_map().clone(),
                creation_key: request_key.clone(),
                title: proposal.title.clone(),
                body: proposal.body.clone(),
                status: Some(TicketStatus::Ready),
                template: None,
                parent: None,
                dependencies: None,
                project: None,
                milestone: None,
                assignee: None,
                priority: None,
                due_date: None,
                labels: Some(vec![]),
            },
        };
        let reservation = store
            .reserve_goal_ticket_creation(
                owner,
                crate::store::scheduler::GoalTicketCreation {
                    project_id: &project,
                    namespace: &namespace,
                    request_key: &request_key,
                    request_digest: &proposal_digest,
                    proposal_json: &proposal_json,
                    ticket_request: &payload,
                    maximum: 5,
                    now_unix: 1,
                },
            )
            .unwrap();
        let adapter = Arc::new(FakeAdapter::new(
            scope(),
            namespace.as_str(),
            "placeholder",
            NormalizedTicketStatus::Ready,
        ));
        let handler = CreateGoalTicketHandler::new(adapter.clone());
        let mut context = EffectContext {
            store: &mut store,
            owner_generation: owner,
            now_unix: 4,
        };
        let request = effect_request(
            &project,
            "project",
            project.as_str(),
            reservation.operation_id.as_str(),
            "ticket_create",
            serde_json::to_value(payload).unwrap(),
        );
        let observation = handler
            .handle(EffectMode::Submit, &request, &mut context)
            .unwrap();
        assert!(matches!(observation, EffectObservation::Applied { .. }));
        assert_eq!(*adapter.calls.lock().unwrap(), ["create"]);
        let receipt = context
            .store
            .record_goal_ticket_candidates(
                owner,
                &reservation.operation_id,
                &[GoalTicketCandidateRecord {
                    namespace,
                    ticket_id: TicketId::parse("ticket-created").unwrap(),
                    match_basis: crate::engine::factory_runtime::GoalTicketMatchBasis::OperationId,
                    created_at: Some("2026-01-02T00:00:00Z".into()),
                }],
                5,
            )
            .unwrap();
        assert_eq!(receipt.canonical_ticket_id.as_str(), "ticket-created");
    }

    #[test]
    fn knowledge_published_transition_requires_a_durable_knowledge_receipt() {
        let (_temp, mut store, project, owner) = test_store();
        let namespace = TicketNamespace::parse("fixture:workspace").unwrap();
        let ticket = TicketId::parse("ticket-completion").unwrap();
        let run = TicketRunId::parse("run-completion").unwrap();
        store
            .create_ticket_run(
                owner,
                &project,
                &namespace,
                &ticket,
                &run,
                1,
                "postmortem",
                "in_progress",
            )
            .unwrap();
        let payload = json!({"schema_version":1,"project_id":project.as_str(),"ticket_run_id":run.as_str(),"ticket_run_revision":1});
        let payload_json = serde_json::to_string(&payload).unwrap();
        let effect = EffectIntent {
            project_id: project.clone(),
            subject_type: "ticket_run".into(),
            subject_id: run.as_str().into(),
            operation_id: "op-complete-ticket".into(),
            logical_key: "complete-ticket".into(),
            kind: "complete_ticket".into(),
            request_digest: hash(&payload_json),
            request_json: payload_json.clone(),
            expected_revision: Some(1),
        };
        let transition_payload = "{\"kind\":\"knowledge_published\"}";
        let error = store
            .commit_ticket_transition(
                owner,
                &run,
                Revision(0),
                &DurableInput {
                    producer_id: "host:test".into(),
                    message_id: "knowledge-published".into(),
                    content_digest: durable_input_digest("ticket_run", transition_payload),
                    recipient: "ticket_run".into(),
                    payload: transition_payload.into(),
                },
                Input::KnowledgePublished,
                "knowledge published",
                "{}",
                &[effect],
            )
            .err()
            .expect("transition must require a durable knowledge publication");
        assert!(error.contains("ticket cannot become Done before durable knowledge publication"));
    }
    #[test]
    fn manual_knowledge_intent_completes_and_publishes_external_done() {
        manual_knowledge_intent_completion_status_flow(false, false);
    }

    #[test]
    fn uncertain_done_status_adopts_exact_external_revision_and_replays_child() {
        manual_knowledge_intent_completion_status_flow(true, false);
    }

    #[test]
    fn ticket_status_adoption_rejects_project_config_changed_after_approval() {
        manual_knowledge_intent_completion_status_flow(true, true);
    }

    fn manual_knowledge_intent_completion_status_flow(
        adopt_external_revision: bool,
        change_config_after_approval: bool,
    ) {
        use crate::knowledge::PostmortemInput;
        use crate::knowledge_effect::KnowledgeEffectHandler;
        use crate::store::EffectOutcome;

        let (temp, mut store, project, owner) = test_store();
        let namespace = TicketNamespace::parse("fixture:workspace").unwrap();
        let ticket = TicketId::parse("ticket-knowledge-done").unwrap();
        let run = TicketRunId::parse("run-knowledge-done").unwrap();
        store
            .create_ticket_run(
                owner,
                &project,
                &namespace,
                &ticket,
                &run,
                1,
                "postmortem",
                "In Progress",
            )
            .unwrap();
        let initial_external_revision = if adopt_external_revision {
            "revision-73"
        } else {
            "revision-1"
        };
        rusqlite::Connection::open(temp.path().join("state.sqlite3"))
            .unwrap()
            .execute(
                "UPDATE ticket_runs SET external_revision=?1 WHERE project_id=?2 AND ticket_run_id=?3",
                rusqlite::params![initial_external_revision, project.as_str(), run.as_str()],
            )
            .unwrap();

        let applied_snapshot = store.load_snapshot("factory").unwrap().unwrap();
        let applied = applied_snapshot.config;
        let plan = crate::operations::validate_recipe_value(
            &applied.config,
            "not-required",
            &crate::config::OperationRecipe {
                roles: BTreeMap::new(),
                required_stages: Vec::new(),
                required_evidence: Vec::new(),
                targets: Vec::new(),
                not_required_reason: Some("No deployment is required for this ticket.".into()),
            },
        )
        .unwrap();
        store
            .operations()
            .unwrap()
            .persist_plan(
                owner,
                &project,
                &ticket,
                &run,
                Revision(0),
                applied_snapshot.revision,
                &applied,
                &plan,
                &crate::operations::DeliveryFacts {
                    merge_commits: BTreeMap::new(),
                    planned_revisions: BTreeMap::new(),
                },
                1,
            )
            .unwrap();
        let operation_receipt = crate::domain::ids::Digest::parse("b".repeat(64)).unwrap();
        store
            .operations()
            .unwrap()
            .record_postmortem_receipt(owner, &project, &run, &operation_receipt, 9)
            .unwrap();
        let postmortem_operation = OperationId::parse("knowledge-done-postmortem").unwrap();
        let postmortem = PostmortemInput {
            operation_id: postmortem_operation.clone(),
            project_id: project.clone(),
            ticket_run_id: run.clone(),
            title: "Ticket completion learning".into(),
            summary: "The bounded operation completed without deployment.".into(),
            findings: vec!["No deployment was required.".into()],
            sources: vec![],
            generated_at: "2026-11-07T00:00:00Z".into(),
            max_source_bytes: 1024,
        };
        let request_json = serde_json::to_string(&postmortem).unwrap();
        let request_digest = hash(&request_json);
        let publication_intent = crate::store::KnowledgePublicationIntent {
            operation_id: postmortem_operation.clone(),
            project_id: project.clone(),
            ticket_run_id: run.clone(),
            request_digest: crate::domain::ids::Digest::parse(request_digest).unwrap(),
            request_json,
        };
        store
            .prepare_knowledge_publication(owner, &publication_intent)
            .unwrap();
        let knowledge_effect = store
            .claim_next_due_effect(owner, i64::MAX, &["publish_knowledge".into()])
            .unwrap()
            .expect("publication intent creates a durable effect");
        let knowledge_request = EffectRequest {
            intent: knowledge_effect.intent.clone(),
            attempt_count: knowledge_effect.attempt_count,
            created_at_unix: knowledge_effect.created_at_unix,
        };
        let mut context = EffectContext {
            store: &mut store,
            owner_generation: owner,
            now_unix: 10,
        };
        let knowledge_handler = KnowledgeEffectHandler::new(temp.path().join("knowledge"));
        let knowledge_observation = knowledge_handler
            .handle(EffectMode::Submit, &knowledge_request, &mut context)
            .unwrap();
        let EffectObservation::Applied { receipt } = knowledge_observation else {
            panic!("knowledge publication did not return a terminal receipt");
        };
        context
            .store
            .finish_effect(
                &knowledge_effect.intent.operation_id,
                owner,
                EffectOutcome::Succeeded,
                Some(&receipt),
            )
            .unwrap();
        let completion_intent = EffectIntent {
            project_id: project.clone(),
            subject_type: "ticket_run".into(),
            subject_id: run.as_str().into(),
            operation_id: "complete-ticket-knowledge-done".into(),
            logical_key: "complete-ticket-knowledge-done".into(),
            kind: "complete_ticket".into(),
            request_json: serde_json::json!({
                "schema_version":1,
                "project_id":project.as_str(),
                "ticket_run_id":run.as_str(),
                "ticket_run_revision":1
            })
            .to_string(),
            request_digest: String::new(),
            expected_revision: Some(1),
        };
        let mut completion_intent = completion_intent;
        completion_intent.request_digest = hash(&completion_intent.request_json);
        let knowledge_published = "{\"kind\":\"knowledge_published\"}";
        context
            .store
            .commit_ticket_transition(
                owner,
                &run,
                Revision(0),
                &crate::store::DurableInput {
                    producer_id: "host:test".into(),
                    message_id: "knowledge-published-done".into(),
                    content_digest: crate::store::durable_input_digest(
                        "ticket_run",
                        knowledge_published,
                    ),
                    recipient: "ticket_run".into(),
                    payload: knowledge_published.into(),
                },
                Input::KnowledgePublished,
                "knowledge publication receipt persisted",
                "{}",
                &[completion_intent],
            )
            .unwrap();
        let completion_effect = context
            .store
            .claim_next_due_effect(owner, i64::MAX, &["complete_ticket".into()])
            .unwrap()
            .expect("completion transition creates a durable effect");
        let completion_request = EffectRequest {
            intent: completion_effect.intent.clone(),
            attempt_count: completion_effect.attempt_count,
            created_at_unix: completion_effect.created_at_unix,
        };
        let completion = CompleteTicketHandler
            .handle(EffectMode::Submit, &completion_request, &mut context)
            .unwrap();
        assert!(matches!(completion, EffectObservation::Applied { .. }));
        context
            .store
            .finish_effect(
                &completion_effect.intent.operation_id,
                owner,
                EffectOutcome::Succeeded,
                Some("host validated completion receipts"),
            )
            .unwrap();

        let status_effect = context
            .store
            .claim_next_due_effect(owner, i64::MAX, &["publish_ticket_status".into()])
            .unwrap()
            .expect("completion creates an external Done status effect");
        let status_request = EffectRequest {
            intent: status_effect.intent.clone(),
            attempt_count: status_effect.attempt_count,
            created_at_unix: status_effect.created_at_unix,
        };
        let adapter = Arc::new(FakeAdapter::new(
            scope(),
            namespace.as_str(),
            ticket.as_str(),
            NormalizedTicketStatus::InProgress,
        ));
        let status_handler = PublishTicketStatusHandler::new(
            adapter.clone(),
            BTreeMap::from([(project.clone(), scope())]),
        );
        if !adopt_external_revision {
            let status = status_handler
                .handle(EffectMode::Submit, &status_request, &mut context)
                .unwrap();
            assert!(matches!(status, EffectObservation::Applied { .. }));
            assert_eq!(
                adapter.ticket.lock().unwrap().status.value,
                NormalizedTicketStatus::Done
            );
            return;
        }
        // The external ticket was changed after its initial Ready revision, while the old Done
        // status intent still carries that original revision. Operation lookup is inconclusive.
        adapter.ticket.lock().unwrap().revision = Some("revision-74".into());
        *adapter.unknown_lookups.lock().unwrap() = true;
        let view = crate::launch::RexView {
            view_id: crate::launch::RexView::derive_id(
                &project,
                crate::launch::RexViewKind::Ticket,
                Some(namespace.as_str()),
                Some(ticket.as_str()),
                1,
            )
            .unwrap(),
            project_id: project.clone(),
            kind: crate::launch::RexViewKind::Ticket,
            ticket_namespace: Some(namespace.as_str().into()),
            ticket_id: Some(ticket.as_str().into()),
            view_epoch: 1,
            rex_server_identity: "test-server".into(),
            rex_session_id: "test-session".into(),
            rex_window_id: "ticket-window".into(),
        };
        context.store.register_rex_view(owner, &view).unwrap();
        let waiting = status_handler
            .handle(EffectMode::Reconcile, &status_request, &mut context)
            .unwrap();
        assert!(matches!(waiting, EffectObservation::Pending { .. }));
        let presentation = context
            .store
            .claim_next_due_effect(owner, i64::MAX, &["request_human_review".into()])
            .unwrap()
            .unwrap();
        let presentation_request = EffectRequest {
            intent: presentation.intent.clone(),
            attempt_count: presentation.attempt_count,
            created_at_unix: presentation.created_at_unix,
        };
        let human_effect: crate::human_runtime::HumanPresentationEffect =
            crate::protocol::parse_unique(presentation.intent.request_json.as_bytes()).unwrap();
        let human_request = human_effect.request.clone();
        let presenter = crate::human_runtime::HumanPresenterEffectHandler::new(
            "local_html",
            vec!["/usr/bin/true".into()],
            [(
                std::ffi::OsString::from("PATH"),
                std::ffi::OsString::from("/usr/bin"),
            )]
            .into_iter()
            .collect(),
            temp.path().join("review-artifacts"),
            Arc::new(FixedTicketSubjectObserver),
        )
        .unwrap();
        assert!(matches!(
            presenter
                .handle(EffectMode::Submit, &presentation_request, &mut context)
                .unwrap(),
            EffectObservation::Pending { .. }
        ));
        let response = crate::human_runtime::HumanDecisionIntent {
            request_id: human_request.request_id.clone(),
            response_id: "ticket-status-adoption-approve".into(),
            expected_subject_digest: human_request.subject.digest().unwrap(),
            choice: crate::human_runtime::HumanDecisionChoice::Approve,
            explanation: Some("Reviewed the exact current ticket and completion evidence.".into()),
        };
        crate::store::ConfigStore::enqueue_human_decision(temp.path(), &response, 12).unwrap();
        let adoption_observer =
            crate::human_runtime::DurableHumanSubjectObserver::new(temp.path().join("profiles"))
                .unwrap()
                .with_ticket_status_adoption_source(Arc::new(FakeTicketStatusAdoptionSource {
                    adapter: adapter.clone(),
                    scope: scope(),
                }));
        crate::human_runtime::process_queued_human_responses(
            context.store,
            owner,
            8,
            13,
            |store, request| {
                crate::human_runtime::HumanSubjectObserver::observe_current_subject(
                    &adoption_observer,
                    store,
                    request,
                )
            },
        )
        .unwrap();
        let accepted = context
            .store
            .accepted_ticket_status_adoption_approval(&human_request.request_id, 14)
            .unwrap()
            .expect("public queued approval is accepted after fresh ticket re-observation");
        assert_eq!(
            accepted.authority().current_ticket_json,
            serde_json::to_string(&crate::adapters::tickets::TicketGetResult {
                ticket_namespace: namespace.as_str().into(),
                ticket: adapter.ticket.lock().unwrap().clone(),
                timeline: vec![],
            })
            .unwrap()
        );
        let child_key = format!("{}:adopted_done", status_request.intent.logical_key);
        if change_config_after_approval {
            let mut changed_snapshot = context.store.load_snapshot("factory").unwrap().unwrap();
            changed_snapshot.config.digest = Digest::parse("c".repeat(64)).unwrap();
            changed_snapshot.config.source_files[0].contents = "changed config".into();
            changed_snapshot.config.source_files[0].bytes = "changed config".len() as u64;
            changed_snapshot.config.source_files[0].sha256 = Digest::parse("d".repeat(64)).unwrap();
            let changed = context
                .store
                .apply_snapshot(
                    "factory",
                    &changed_snapshot.config,
                    crate::store::ExpectedRevision::Current(changed_snapshot.revision),
                )
                .unwrap();
            rusqlite::Connection::open(temp.path().join("state.sqlite3"))
                .unwrap()
                .execute(
                    "UPDATE projects SET config_revision=?1,config_digest=?2 WHERE project_id=?3",
                    rusqlite::params![
                        changed.revision.0,
                        changed.digest.as_str(),
                        project.as_str()
                    ],
                )
                .unwrap();
            let payload: crate::engine::ticket_effects::PublishTicketStatus =
                crate::protocol::parse_unique(status_request.intent.request_json.as_bytes())
                    .unwrap();
            let proof = context
                .store
                .ticket_completion_proof(owner, &project, &run, payload.ticket_run_revision - 1)
                .unwrap()
                .unwrap();
            assert!(
                context
                    .store
                    .adopt_done_ticket_status_revision(
                        owner,
                        &status_request.intent,
                        &payload,
                        &accepted,
                        &proof,
                        15,
                    )
                    .unwrap_err()
                    .contains("Project configuration changed during ticket status adoption")
            );
            let saved_revision: String = rusqlite::Connection::open(temp.path().join("state.sqlite3"))
                .unwrap().query_row(
                    "SELECT external_revision FROM ticket_runs WHERE project_id=?1 AND ticket_run_id=?2",
                    rusqlite::params![project.as_str(), run.as_str()], |row| row.get(0),
                ).unwrap();
            assert_eq!(saved_revision, "revision-73");
            assert!(
                context
                    .store
                    .effect_by_logical_key(&child_key)
                    .unwrap()
                    .is_none()
            );
            return;
        }
        let adopted = status_handler
            .handle(EffectMode::Reconcile, &status_request, &mut context)
            .unwrap();
        assert!(matches!(adopted, EffectObservation::Rejected { .. }));
        let child = context
            .store
            .effect_by_logical_key(&child_key)
            .unwrap()
            .expect("approved adoption creates a replacement");
        let replay = status_handler
            .handle(EffectMode::Reconcile, &status_request, &mut context)
            .unwrap();
        assert!(matches!(replay, EffectObservation::Rejected { .. }));
        assert_eq!(
            context.store.effect_by_logical_key(&child_key).unwrap(),
            Some(child.clone())
        );
        let replacement = context
            .store
            .claim_next_due_effect(owner, i64::MAX, &["publish_ticket_status".into()])
            .unwrap()
            .expect("replacement status intent is durable");
        let replacement_request = EffectRequest {
            intent: replacement.intent.clone(),
            attempt_count: replacement.attempt_count,
            created_at_unix: replacement.created_at_unix,
        };
        let status = status_handler
            .handle(EffectMode::Submit, &replacement_request, &mut context)
            .unwrap();
        assert!(matches!(status, EffectObservation::Applied { .. }));
        assert_eq!(
            adapter.ticket.lock().unwrap().status.value,
            NormalizedTicketStatus::Done
        );
        assert_eq!(
            adapter
                .calls
                .lock()
                .unwrap()
                .iter()
                .filter(|call| **call == "update")
                .count(),
            1
        );
    }
    #[test]
    fn knowledge_publication_then_completion_effect_publishes_external_done() {
        use crate::domain::types::Role;
        use crate::engine::orchestration::{AgentAssertion, RoleOutputKind};
        use crate::knowledge_effect::KnowledgeEffectHandler;
        use crate::store::EffectOutcome;

        let structured_result = json!({
            "candidate_publication_manifest": {
                "title": "Ticket completion learning",
                "summary": "The bounded operation completed without deployment."
            },
            "findings": ["No deployment was required."],
            "source_references": [],
            "unresolved_provenance": []
        });
        let result_digest = Digest::parse(hash(&structured_result.to_string())).unwrap();
        let message = crate::roles::RoleResultMessage {
            schema_version: crate::engine::orchestration::ROLE_RESULT_SCHEMA_VERSION,
            message_id: "postmortem-done-ingress".into(),
            kind: RoleOutputKind::PostmortemReady,
            assertion: AgentAssertion::Succeeded,
            structured_result,
            result_digest: Some(result_digest),
            artifact_refs: vec![],
        };
        let mut fixture =
            crate::store::agent_results::host_validation_fixture::host_validated_result(
                Role::Postmortem,
                message,
            )
            .unwrap();
        let project = ProjectId::parse("fixture-project").unwrap();
        let owner = fixture.owner_generation;
        let namespace = TicketNamespace::parse("fixture").unwrap();
        let ticket = TicketId::parse("T-1").unwrap();
        let run = TicketRunId::parse("fixture-ticket-run").unwrap();
        fixture
            .store
            .test_connection()
            .execute(
                "UPDATE ticket_runs SET external_revision='revision-1' WHERE project_id=?1 AND ticket_run_id=?2",
                rusqlite::params![project.as_str(), run.as_str()],
            )
            .unwrap();
        let applied_snapshot = fixture.store.load_snapshot("fixture").unwrap().unwrap();
        let applied = applied_snapshot.config;
        let plan = crate::operations::validate_recipe_value(
            &applied.config,
            "not-required",
            &crate::config::OperationRecipe {
                roles: BTreeMap::new(),
                required_stages: Vec::new(),
                required_evidence: Vec::new(),
                targets: Vec::new(),
                not_required_reason: Some("No deployment is required for this ticket.".into()),
            },
        )
        .unwrap();
        fixture
            .store
            .operations()
            .unwrap()
            .persist_plan(
                owner,
                &project,
                &ticket,
                &run,
                Revision(1),
                applied_snapshot.revision,
                &applied,
                &plan,
                &crate::operations::DeliveryFacts {
                    merge_commits: BTreeMap::new(),
                    planned_revisions: BTreeMap::new(),
                },
                1,
            )
            .unwrap();

        let mut config: crate::config::Config = serde_json::from_value(json!({
            "schema_version": 1,
            "adapters": {"tickets": {"kind":"command", "command":["test"]}},
            "projects": {},
            "knowledge": {"format":"okf", "root":"knowledge", "max_source_bytes":1024}
        }))
        .unwrap();
        let mut services = crate::engine::factory_runtime::tests::PostmortemTestServices {
            digest: Digest::parse("a".repeat(64)).unwrap(),
            artifacts: fixture.artifacts.clone(),
        };
        config.knowledge.as_mut().unwrap().max_source_bytes = 1;
        assert!(
            crate::engine::factory_runtime::tests::apply_postmortem_result(
                &mut fixture.store,
                owner,
                1_800_000_000,
                &config,
                &mut services,
                &fixture.ingested,
            )
            .unwrap_err()
            .contains("configured byte limit")
        );
        config.knowledge.as_mut().unwrap().max_source_bytes = 1024;
        assert!(
            crate::engine::factory_runtime::tests::apply_postmortem_result(
                &mut fixture.store,
                owner,
                1_800_000_000,
                &config,
                &mut services,
                &fixture.ingested,
            )
            .unwrap()
        );
        let operation_id = OperationId::parse(format!(
            "knowledge-{}",
            fixture.ingested.receipt.evidence_id()
        ))
        .unwrap();
        let publication = fixture
            .store
            .knowledge_publication_intent(&operation_id)
            .unwrap()
            .unwrap();
        assert!(
            publication
                .request_json
                .contains("Host-registered Postmortem evidence.")
        );
        let original_request_digest = publication.request_digest.clone();
        let mut retry_services = crate::engine::factory_runtime::tests::PostmortemTestServices {
            digest: Digest::parse("a".repeat(64)).unwrap(),
            artifacts: fixture.artifacts.clone(),
        };
        assert!(
            crate::engine::factory_runtime::tests::apply_postmortem_result(
                &mut fixture.store,
                owner,
                1_900_000_000,
                &config,
                &mut retry_services,
                &fixture.ingested,
            )
            .unwrap()
        );
        let replayed_publication = fixture
            .store
            .knowledge_publication_intent(&operation_id)
            .unwrap()
            .unwrap();
        assert_eq!(replayed_publication.request_digest, original_request_digest);
        assert_eq!(replayed_publication.request_json, publication.request_json);

        let knowledge_effect = fixture
            .store
            .claim_next_due_effect(owner, i64::MAX, &["publish_knowledge".into()])
            .unwrap()
            .expect("publication intent creates a durable effect");
        let knowledge_request = EffectRequest {
            intent: knowledge_effect.intent.clone(),
            attempt_count: knowledge_effect.attempt_count,
            created_at_unix: knowledge_effect.created_at_unix,
        };
        {
            let mut context = EffectContext {
                store: &mut fixture.store,
                owner_generation: owner,
                now_unix: 10,
            };
            let knowledge_handler =
                KnowledgeEffectHandler::new(fixture._temp.path().join("knowledge"));
            let knowledge_observation = knowledge_handler
                .handle(EffectMode::Submit, &knowledge_request, &mut context)
                .unwrap();
            let EffectObservation::Applied { receipt } = knowledge_observation else {
                panic!("knowledge publication did not return a terminal receipt");
            };
            context
                .store
                .finish_effect(
                    &knowledge_effect.intent.operation_id,
                    owner,
                    EffectOutcome::Succeeded,
                    Some(&receipt),
                )
                .unwrap();
        }
        assert!(
            crate::engine::host_transitions::consume_one_host_transition(
                &mut fixture.store,
                owner,
                1_800_000_000,
                &config,
                &Digest::parse("a".repeat(64)).unwrap(),
            )
            .unwrap()
        );
        let mut context = EffectContext {
            store: &mut fixture.store,
            owner_generation: owner,
            now_unix: 11,
        };
        let completion_effect = context
            .store
            .claim_next_due_effect(owner, i64::MAX, &["complete_ticket".into()])
            .unwrap()
            .expect("completion transition creates a durable effect");
        let completion_request = EffectRequest {
            intent: completion_effect.intent.clone(),
            attempt_count: completion_effect.attempt_count,
            created_at_unix: completion_effect.created_at_unix,
        };
        let completion = CompleteTicketHandler
            .handle(EffectMode::Submit, &completion_request, &mut context)
            .unwrap();
        assert!(matches!(completion, EffectObservation::Applied { .. }));
        context
            .store
            .finish_effect(
                &completion_effect.intent.operation_id,
                owner,
                EffectOutcome::Succeeded,
                Some("host validated completion receipts"),
            )
            .unwrap();

        let status_effect = context
            .store
            .claim_next_due_effect(owner, i64::MAX, &["publish_ticket_status".into()])
            .unwrap()
            .expect("completion creates an external Done status effect");
        let status_request = EffectRequest {
            intent: status_effect.intent.clone(),
            attempt_count: status_effect.attempt_count,
            created_at_unix: status_effect.created_at_unix,
        };
        let adapter = Arc::new(FakeAdapter::new(
            scope(),
            namespace.as_str(),
            ticket.as_str(),
            NormalizedTicketStatus::InProgress,
        ));
        let status_handler = PublishTicketStatusHandler::new(
            adapter.clone(),
            BTreeMap::from([(project.clone(), scope())]),
        );
        let status = status_handler
            .handle(EffectMode::Submit, &status_request, &mut context)
            .unwrap();
        let EffectObservation::Applied { receipt } = status else {
            panic!("status publication did not return a terminal receipt");
        };
        assert_eq!(
            adapter.ticket.lock().unwrap().status.value,
            NormalizedTicketStatus::Done
        );
        context
            .store
            .finish_effect(
                &status_effect.intent.operation_id,
                owner,
                EffectOutcome::Succeeded,
                Some(&receipt),
            )
            .unwrap();
    }
}
