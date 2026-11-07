//! Host-side Operator effect execution and reconciliation.
//!
//! The shared outbox dispatcher invokes this handler outside its SQLite
//! transaction. Each operation has one immutable effect identity for its
//! entire invoke/find/observe lifecycle. `Unknown` is reconciled by exact
//! operation identity before any retry can be considered.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::config::AppliedConfig;
use crate::domain::ids::{Digest, HumanRequestId, OperationId};
use crate::effects::{
    AbsentProof, EffectContext, EffectHandler, EffectKind, EffectMode, EffectObservation,
    EffectRequest,
};
use crate::human::ReviewBundle;
use crate::operations::{
    AdapterCall, FindOutcome, FindParams, InvokeOutcome, InvokeResult, OperationObservation,
    OperationPermit, PredicateResult, ProcessCommandRunner, authorize_operation,
    call_command_adapter, new_request, operation_human_subject_binding, validate_recipe,
    verify_operation_approval,
};
use crate::store::{
    EffectIntent,
    operations::{DurableOperationState, OperationEffectRequest},
};

pub fn operation_review_bundle(
    applied: &AppliedConfig,
    request: &OperationEffectRequest,
) -> Result<ReviewBundle, String> {
    crate::operations::operation_review_bundle(
        applied,
        &request.subject,
        &request.target,
        &request.ticket_id,
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationExecutionMode {
    Submit,
    Reconcile,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum OperationExecutionOutcome {
    Applied {
        receipt_json: String,
    },
    Pending {
        receipt_json: String,
    },
    Rejected {
        receipt_json: String,
    },
    AuthoritativelyAbsent {
        handler_kind: String,
        operation_id: String,
        request_digest: String,
        project_id: String,
        subject_type: String,
        subject_id: String,
        authority: String,
        evidence: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredTerminalReceipt {
    operation_id: OperationId,
    request_digest: Digest,
    outcome: OperationExecutionOutcome,
}

impl EffectHandler for OperationEffectHandler {
    fn kind(&self) -> EffectKind {
        EffectKind::Operation
    }

    fn handle(
        &self,
        mode: EffectMode,
        request: &EffectRequest,
        context: &mut EffectContext<'_>,
    ) -> Result<EffectObservation, String> {
        let mode = match mode {
            EffectMode::Submit => OperationExecutionMode::Submit,
            EffectMode::Reconcile => OperationExecutionMode::Reconcile,
        };
        match self.handle(mode, &request.intent, request.attempt_count, context)? {
            OperationExecutionOutcome::Applied { receipt_json } => Ok(EffectObservation::Applied {
                receipt: receipt_json,
            }),
            OperationExecutionOutcome::Pending { receipt_json } => Ok(EffectObservation::Pending {
                receipt: receipt_json,
            }),
            OperationExecutionOutcome::Rejected { receipt_json } => {
                Ok(EffectObservation::Rejected {
                    receipt: receipt_json,
                })
            }
            OperationExecutionOutcome::AuthoritativelyAbsent {
                authority,
                evidence,
                ..
            } => Ok(EffectObservation::AuthoritativelyAbsent {
                proof: AbsentProof::from_authoritative_lookup(
                    EffectKind::Operation,
                    request,
                    authority,
                    evidence,
                )?,
            }),
        }
    }
}

/// Config snapshots are supplied by the owning controller, indexed by their
/// immutable digest. The handler never loads agent-provided config or commands.
pub struct OperationEffectHandler {
    snapshots: BTreeMap<String, AppliedConfig>,
    process_shutdown_grace: Duration,
}

impl OperationEffectHandler {
    pub fn new(
        snapshots: impl IntoIterator<Item = AppliedConfig>,
        process_shutdown_grace: Duration,
    ) -> Result<Self, String> {
        if process_shutdown_grace.is_zero() {
            return Err("process shutdown grace must be non-zero".into());
        }
        let mut by_digest = BTreeMap::new();
        for snapshot in snapshots {
            let digest = snapshot.digest.to_string();
            if by_digest.insert(digest.clone(), snapshot).is_some() {
                return Err(format!("duplicate applied config snapshot `{digest}`"));
            }
        }
        if by_digest.is_empty() {
            return Err("at least one applied config snapshot is required".into());
        }
        Ok(Self {
            snapshots: by_digest,
            process_shutdown_grace,
        })
    }

    pub fn handle(
        &self,
        mode: OperationExecutionMode,
        effect: &EffectIntent,
        attempt_count: u32,
        context: &mut EffectContext<'_>,
    ) -> Result<OperationExecutionOutcome, String> {
        let (request, applied, target, permit) = {
            let store = context.store.operations()?;
            let request = store.effect_request(effect)?;
            let record = store
                .operation(&request.subject.operation_id)?
                .ok_or_else(|| "durable operation row is missing".to_owned())?;
            if record.request_digest != Digest::parse(effect.request_digest.clone())?
                || record.subject_digest != request.subject.digest().map_err(|e| e.to_string())?
            {
                return Err("operation row is not bound to the immutable effect subject".into());
            }
            if matches!(
                record.state,
                DurableOperationState::Succeeded
                    | DurableOperationState::Failed
                    | DurableOperationState::Skipped
            ) {
                let cached: StoredTerminalReceipt =
                    serde_json::from_str(record.terminal_receipt_json.as_deref().ok_or_else(
                        || "terminal operation result has no durable receipt".to_owned(),
                    )?)
                    .map_err(|_| "terminal operation receipt is invalid".to_owned())?;
                if cached.operation_id != OperationId::parse(effect.operation_id.clone())?
                    || cached.request_digest != Digest::parse(effect.request_digest.clone())?
                {
                    return Err(
                        "terminal operation receipt is bound to a different immutable intent"
                            .into(),
                    );
                }
                let state_matches = matches!(
                    (&record.state, &cached.outcome),
                    (
                        DurableOperationState::Succeeded,
                        OperationExecutionOutcome::Applied { .. }
                    ) | (
                        DurableOperationState::Skipped,
                        OperationExecutionOutcome::Applied { .. }
                    ) | (
                        DurableOperationState::Failed,
                        OperationExecutionOutcome::Rejected { .. }
                    )
                );
                if !state_matches {
                    return Err(
                        "terminal operation receipt does not match its persisted state".into(),
                    );
                }
                return Ok(cached.outcome);
            }
            drop(store);
            let applied = self
                .snapshots
                .get(request.config_digest.as_str())
                .ok_or_else(|| "applied operation config snapshot is unavailable".to_owned())?;
            validate_request_config(&request, applied)?;
            let plan = validate_recipe(&applied.config, &request.recipe_id)
                .map_err(|error| error.to_string())?;
            if plan.digest() != &request.plan_digest {
                return Err("operation recipe digest changed after intent creation".into());
            }
            let target = plan
                .targets()
                .iter()
                .find(|target| target.id == request.target.id)
                .ok_or_else(|| "operation target is absent from the applied recipe".to_owned())?;
            if serde_json::to_value(target).map_err(|error| error.to_string())?
                != serde_json::to_value(&request.target).map_err(|error| error.to_string())?
            {
                return Err("operation target differs from the applied recipe".into());
            }
            if !context
                .store
                .operations()?
                .dependencies_succeeded(&request)?
            {
                return Ok(pending_receipt(
                    &request.subject.operation_id,
                    "waiting_for_dependencies",
                    "dependent operations have not all succeeded",
                ));
            }
            let approval = if let Some(request_id) = &request.approval_request_id {
                let request_id = HumanRequestId::parse(request_id.clone())?;
                let Some(human_record) = context.store.current_human_request(&request_id)? else {
                    return Ok(pending_receipt(
                        &request.subject.operation_id,
                        "waiting_for_human_request",
                        "operation review request has not been presented yet",
                    ));
                };
                let lifecycle = human_record.lifecycle;
                let human_request = human_record.request;
                let current_bundle = operation_review_bundle(applied, &request)?;
                let binding =
                    operation_human_subject_binding(applied, &request.subject, &current_bundle)?;
                let now = u64::try_from(context.now_unix)
                    .map_err(|_| "controller time is invalid".to_owned())?;
                let receipt = context.store.accepted_human_approval(
                    &request_id,
                    &binding.digest()?,
                    &binding.configuration_digest,
                    &binding.policy_digest,
                    now,
                )?;
                let Some(receipt) = receipt else {
                    if matches!(
                        lifecycle,
                        crate::human_runtime::HumanRequestLifecycle::Decided
                            | crate::human_runtime::HumanRequestLifecycle::Stale
                            | crate::human_runtime::HumanRequestLifecycle::Expired
                            | crate::human_runtime::HumanRequestLifecycle::Cancelled
                    ) {
                        let rejection = serde_json::json!({
                            "operation_id": request.subject.operation_id,
                            "state": "human_approval_rejected_or_stale",
                            "lifecycle": format!("{lifecycle:?}"),
                        })
                        .to_string();
                        let outcome = OperationExecutionOutcome::Rejected {
                            receipt_json: rejection.clone(),
                        };
                        let terminal = store_terminal_receipt(effect, &outcome)?;
                        context.store.operations()?.record_approval_rejected(
                            context.owner_generation,
                            &request.subject.operation_id,
                            &rejection,
                            &terminal,
                            context.now_unix,
                        )?;
                        return Ok(outcome);
                    }
                    return Ok(pending_receipt(
                        &request.subject.operation_id,
                        "waiting_for_human_approval",
                        "operation requires an exact, unexpired human approval",
                    ));
                };
                let capability = verify_operation_approval(
                    applied,
                    &request.subject,
                    &request.target,
                    &request_id,
                    &human_request,
                    &current_bundle,
                    &receipt,
                    now,
                )?;
                if record.state == DurableOperationState::AwaitingApproval {
                    context.store.operations()?.accept_approval(
                        context.owner_generation,
                        &request.subject.operation_id,
                        &capability,
                        context.now_unix,
                    )?;
                }
                Some(capability)
            } else {
                None
            };
            let _approval_audit = record.approval_json;
            let permit = authorize_operation(
                applied,
                &request.delivery_facts,
                &plan,
                target,
                request.subject.clone(),
                approval.as_ref(),
            )
            .map_err(|error| error.to_string())?;
            (request, applied.clone(), target.clone(), permit)
        };
        match mode {
            OperationExecutionMode::Submit => self.submit(
                context,
                effect,
                &request,
                &applied,
                &target,
                &permit,
                attempt_count,
            ),
            OperationExecutionMode::Reconcile => self.reconcile(
                context,
                effect,
                &request,
                &applied,
                &target,
                &permit,
                attempt_count,
            ),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn submit(
        &self,
        context: &mut EffectContext<'_>,
        effect: &EffectIntent,
        request: &OperationEffectRequest,
        applied: &AppliedConfig,
        target: &crate::config::OperationTarget,
        permit: &OperationPermit,
        attempt_count: u32,
    ) -> Result<OperationExecutionOutcome, String> {
        let operation_id = &request.subject.operation_id;
        let now = unix_now()?;
        {
            let mut store = context.store.operations()?;
            let record = store
                .operation(operation_id)?
                .ok_or_else(|| "durable operation row is missing".to_owned())?;
            if !matches!(
                record.state,
                DurableOperationState::Ready | DurableOperationState::Unknown
            ) {
                return Err("operation is not ready for a submission attempt".into());
            }
            // Unknown can reach Submit only after the shared dispatcher accepted a
            // matching authoritative absence proof and reset the same outbox row.
            if record.state == DurableOperationState::Unknown && attempt_count < 2 {
                return Err("unknown operation requires reconciliation before retry".into());
            }
            store.record_invoking(
                context.owner_generation,
                operation_id,
                &request.project_id,
                &request.ticket_run_id,
                request.config_revision,
                &request.config_digest,
                context.now_unix.max(now),
            )?;
        }

        let mut runner = ProcessCommandRunner::new(self.process_shutdown_grace)?;
        let timeout = Duration::from_secs(target.timeout_seconds);
        let call = crate::operations::invoke_authorized_command(
            &mut runner,
            applied,
            permit,
            request_id(operation_id, "invoke", attempt_count),
            timeout,
        );
        match call {
            Ok(AdapterCall::Uncertain(reason)) => {
                let mut store = context.store.operations()?;
                store.record_unknown(context.owner_generation, operation_id, unix_now()?)?;
                Ok(pending_receipt(operation_id, "invoke_uncertain", &reason))
            }
            Err(error) => {
                let mut store = context.store.operations()?;
                store.record_handler_failure(
                    context.owner_generation,
                    operation_id,
                    unix_now()?,
                )?;
                Ok(pending_receipt(
                    operation_id,
                    "invoke_unknown",
                    &error.to_string(),
                ))
            }
            Ok(AdapterCall::Response(response)) => {
                let Some(value) = response.result else {
                    let mut store = context.store.operations()?;
                    store.record_unknown(context.owner_generation, operation_id, unix_now()?)?;
                    return Ok(pending_receipt(
                        operation_id,
                        "invoke_unknown",
                        "empty adapter result",
                    ));
                };
                let result: InvokeResult = serde_json::from_value(value)
                    .map_err(|_| "operation.invoke result is invalid".to_owned())?;
                match result.outcome {
                    InvokeOutcome::Rejected => {
                        let receipt = serde_json::json!({"operation_id":operation_id,"state":"failed","stage":"invoke_rejected"}).to_string();
                        let outcome = OperationExecutionOutcome::Rejected {
                            receipt_json: receipt.clone(),
                        };
                        let terminal_receipt = store_terminal_receipt(effect, &outcome)?;
                        let mut store = context.store.operations()?;
                        store.record_observation(
                            context.owner_generation,
                            operation_id,
                            &receipt,
                            Some(&terminal_receipt),
                            DurableOperationState::Failed,
                            context.now_unix.max(unix_now()?),
                        )?;
                        Ok(outcome)
                    }
                    InvokeOutcome::Accepted | InvokeOutcome::Completed => {
                        let Some(external_reference) = result.external_reference else {
                            let mut store = context.store.operations()?;
                            store.record_unknown(
                                context.owner_generation,
                                operation_id,
                                unix_now()?,
                            )?;
                            return Ok(pending_receipt(
                                operation_id,
                                "invoke_missing_reference",
                                "adapter omitted external reference",
                            ));
                        };
                        context.store.operations()?.record_running(
                            context.owner_generation,
                            operation_id,
                            &external_reference,
                            unix_now()?,
                        )?;
                        self.observe(
                            context,
                            effect,
                            request,
                            applied,
                            target,
                            permit,
                            &external_reference,
                            attempt_count,
                        )
                    }
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn reconcile(
        &self,
        context: &mut EffectContext<'_>,
        effect: &EffectIntent,
        request: &OperationEffectRequest,
        applied: &AppliedConfig,
        target: &crate::config::OperationTarget,
        permit: &OperationPermit,
        attempt_count: u32,
    ) -> Result<OperationExecutionOutcome, String> {
        let record = context
            .store
            .operations()?
            .operation(&request.subject.operation_id)?
            .ok_or_else(|| "durable operation row is missing".to_owned())?;
        if let Some(external_reference) = record.external_reference {
            return self.observe(
                context,
                effect,
                request,
                applied,
                target,
                permit,
                &external_reference,
                attempt_count,
            );
        }
        let action = applied
            .config
            .operation_actions
            .get(&target.action)
            .ok_or_else(|| "operation action is not configured".to_owned())?;
        let mut runner = ProcessCommandRunner::new(self.process_shutdown_grace)?;
        let correlation_key = permit.stable_correlation_key()?;
        let find = FindParams {
            operation_id: request.subject.operation_id.clone(),
            correlation_key: correlation_key.clone(),
            action_id: target.action.clone(),
            target_id: target.id.clone(),
            repository_id: target.repository.clone(),
            environment: target.environment.clone(),
            source_sha: request.subject.source_sha.clone(),
        };
        let envelope = new_request(
            request_id(&request.subject.operation_id, "find", attempt_count),
            Some(request.subject.operation_id.clone()),
            Some(request.project_id.clone()),
            "operation.find",
            find,
        )?;
        let call = call_command_adapter(
            &mut runner,
            action,
            &envelope,
            Duration::from_secs(target.timeout_seconds),
        );
        let call = match call {
            Ok(call) => call,
            Err(error) => {
                return Ok(pending_receipt(
                    &request.subject.operation_id,
                    "find_unknown",
                    &error.to_string(),
                ));
            }
        };
        let AdapterCall::Response(response) = call else {
            return Ok(pending_receipt(
                &request.subject.operation_id,
                "find_unknown",
                "find reply is uncertain",
            ));
        };
        let Some(value) = response.result else {
            return Ok(pending_receipt(
                &request.subject.operation_id,
                "find_unknown",
                "find reply omitted result",
            ));
        };
        let result: crate::operations::FindResult = serde_json::from_value(value)
            .map_err(|_| "operation.find result is invalid".to_owned())?;
        match result.outcome {
            FindOutcome::Unknown => Ok(pending_receipt(
                &request.subject.operation_id,
                "find_pending",
                "adapter cannot establish operation presence or absence",
            )),
            FindOutcome::Absent => {
                let evidence = serde_json::json!({"observed_at":result.observed_at,"proof_scope":result.proof_scope,"receipt":result.receipt});
                Ok(OperationExecutionOutcome::AuthoritativelyAbsent {
                    handler_kind: "operation".into(),
                    operation_id: effect.operation_id.clone(),
                    request_digest: effect.request_digest.clone(),
                    project_id: effect.project_id.to_string(),
                    subject_type: effect.subject_type.clone(),
                    subject_id: effect.subject_id.clone(),
                    authority: request.subject.digest()?.to_string(),
                    evidence: evidence.to_string(),
                })
            }
            FindOutcome::Found => {
                let reference = result
                    .external_reference
                    .ok_or_else(|| "found operation omitted its external reference".to_owned())?;
                context.store.operations()?.record_running(
                    context.owner_generation,
                    &request.subject.operation_id,
                    &reference,
                    unix_now()?,
                )?;
                self.observe(
                    context,
                    effect,
                    request,
                    applied,
                    target,
                    permit,
                    &reference,
                    attempt_count,
                )
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn observe(
        &self,
        context: &mut EffectContext<'_>,
        effect: &EffectIntent,
        request: &OperationEffectRequest,
        applied: &AppliedConfig,
        target: &crate::config::OperationTarget,
        permit: &OperationPermit,
        external_reference: &str,
        attempt_count: u32,
    ) -> Result<OperationExecutionOutcome, String> {
        let action = applied
            .config
            .operation_actions
            .get(&target.action)
            .ok_or_else(|| "operation action is not configured".to_owned())?;
        let params = crate::operations::ObserveParams {
            operation_id: request.subject.operation_id.clone(),
            correlation_key: permit.stable_correlation_key()?,
            action_id: target.action.clone(),
            target_id: target.id.clone(),
            repository_id: target.repository.clone(),
            environment: target.environment.clone(),
            source_sha: request.subject.source_sha.clone(),
            external_reference: Some(external_reference.to_owned()),
            cursor: None,
        };
        let envelope = new_request(
            request_id(&request.subject.operation_id, "observe", attempt_count),
            Some(request.subject.operation_id.clone()),
            Some(request.project_id.clone()),
            "operation.observe",
            params,
        )?;
        let mut runner = ProcessCommandRunner::new(self.process_shutdown_grace)?;
        let call = call_command_adapter(
            &mut runner,
            action,
            &envelope,
            Duration::from_secs(target.timeout_seconds),
        );
        let call = match call {
            Ok(call) => call,
            Err(error) => {
                return Ok(pending_receipt(
                    &request.subject.operation_id,
                    "observe_pending",
                    &error.to_string(),
                ));
            }
        };
        let AdapterCall::Response(response) = call else {
            return Ok(pending_receipt(
                &request.subject.operation_id,
                "observe_pending",
                "observation reply is uncertain",
            ));
        };
        let Some(value) = response.result else {
            return Ok(pending_receipt(
                &request.subject.operation_id,
                "observe_pending",
                "observation reply omitted result",
            ));
        };
        let observation: OperationObservation = serde_json::from_value(value)
            .map_err(|_| "operation.observe result is invalid".to_owned())?;
        if observation.validate_for_request(&envelope.params).is_err() {
            return Err("operation observation does not match the exact persisted run".into());
        }
        let plan = validate_recipe(&applied.config, &request.recipe_id)
            .map_err(|error| error.to_string())?;
        let predicate = observation.satisfies(&target.success_predicate);
        let state = match predicate {
            PredicateResult::Satisfied => DurableOperationState::Succeeded,
            PredicateResult::Pending => DurableOperationState::Running,
            PredicateResult::Failed => DurableOperationState::Failed,
        };
        let observation_json =
            serde_json::to_string(&observation).map_err(|error| error.to_string())?;
        let receipt = serde_json::json!({
            "operation_id": request.subject.operation_id,
            "correlation_key": permit.stable_correlation_key()?,
            "source_sha": request.subject.source_sha,
            "target_id": target.id,
            "recipe_id": plan.recipe_id(),
            "plan_digest": plan.digest(),
            "predicate": format!("{predicate:?}"),
            "external_reference": external_reference,
            "observation": observation,
        })
        .to_string();
        let outcome = match predicate {
            PredicateResult::Satisfied => OperationExecutionOutcome::Applied {
                receipt_json: receipt,
            },
            PredicateResult::Pending => OperationExecutionOutcome::Pending {
                receipt_json: receipt,
            },
            PredicateResult::Failed => OperationExecutionOutcome::Rejected {
                receipt_json: receipt,
            },
        };
        let terminal_receipt = if state == DurableOperationState::Running {
            None
        } else {
            Some(store_terminal_receipt(effect, &outcome)?)
        };
        context.store.operations()?.record_observation(
            context.owner_generation,
            &request.subject.operation_id,
            &observation_json,
            terminal_receipt.as_deref(),
            state,
            context.now_unix.max(unix_now()?),
        )?;
        Ok(outcome)
    }
}

fn validate_request_config(
    request: &OperationEffectRequest,
    applied: &AppliedConfig,
) -> Result<(), String> {
    if request.config_digest != applied.digest
        || request.subject.config_digest != request.config_digest
        || request.subject.project_id != request.project_id
        || request.subject.ticket_id != request.ticket_id
        || request.subject.ticket_run_id != request.ticket_run_id
        || request.subject.ticket_revision != request.ticket_revision
        || request.subject.recipe_id != request.recipe_id
        || request.subject.plan_digest != request.plan_digest
    {
        return Err("operation request does not match its applied config and subject".into());
    }
    Ok(())
}

fn pending_receipt(
    operation_id: &OperationId,
    state: &str,
    detail: &str,
) -> OperationExecutionOutcome {
    OperationExecutionOutcome::Pending {
        receipt_json:
            serde_json::json!({"operation_id":operation_id,"state":state,"detail":detail})
                .to_string(),
    }
}

fn store_terminal_receipt(
    effect: &EffectIntent,
    outcome: &OperationExecutionOutcome,
) -> Result<String, String> {
    serde_json::to_string(&StoredTerminalReceipt {
        operation_id: OperationId::parse(effect.operation_id.clone())?,
        request_digest: Digest::parse(effect.request_digest.clone())?,
        outcome: outcome.clone(),
    })
    .map_err(|error| error.to_string())
}

fn request_id(operation_id: &OperationId, stage: &str, attempt: u32) -> String {
    format!("{}-{stage}-{attempt}", operation_id.as_str())
}

fn unix_now() -> Result<i64, String> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_secs() as i64)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::Path;

    use tempfile::tempdir;

    use super::*;
    use crate::config::{
        AppliedConfig, Config, OperationActionConfig, OperationTarget, RepositoryOperationsConfig,
        SuccessPredicate,
    };
    use crate::domain::ids::{
        ProjectId, RepositoryId, Revision, TicketId, TicketNamespace, TicketRunId,
    };
    use crate::domain::types::{ApprovalMode, OperationSource};
    use crate::effects::{
        DispatchTick, EffectContext, EffectDispatcher, EffectLimits, EffectMode, EffectRequest,
    };
    use crate::human::review_bundle_digest;
    use crate::operations::{DeliveryFacts, validate_recipe};
    use crate::store::operations::CompletionGate;
    use crate::store::{ExpectedRevision, OwnerMetadata, ProjectRecord};

    const SOURCE_SHA: &str = "0123456789abcdef0123456789abcdef01234567";

    fn applied_config(state_path: &Path) -> AppliedConfig {
        let mut config: Config = toml::from_str(include_str!("../examples/fixture/config.toml"))
            .expect("public fixture configuration parses");
        let fixture = concat!(env!("CARGO_MANIFEST_DIR"), "/target/debug/xtask");
        config.operation_actions.insert(
            "deploy".into(),
            OperationActionConfig::Command {
                command: vec![
                    fixture.into(),
                    "fixture".into(),
                    "operations".into(),
                    "--state-dir".into(),
                    state_path.to_string_lossy().into_owned(),
                ],
            },
        );
        config
            .repositories
            .get_mut(&RepositoryId::parse("example").unwrap())
            .unwrap()
            .operations = Some(RepositoryOperationsConfig {
            recipe: "rollout".into(),
            allowed_actions: vec!["deploy".into()],
            human_approval_environments: vec![],
            instruction_files: vec![],
        });
        config.operation_recipes.insert(
            "rollout".into(),
            crate::config::OperationRecipe {
                roles: BTreeMap::new(),
                required_stages: vec![],
                required_evidence: vec![],
                targets: vec![OperationTarget {
                    id: "deploy_fixture".into(),
                    repository: RepositoryId::parse("example").unwrap(),
                    environment: "test".into(),
                    action: "deploy".into(),
                    depends_on: vec![],
                    source: OperationSource::parse("merge_commit").unwrap(),
                    selector: BTreeMap::new(),
                    success_predicate: SuccessPredicate::TargetSucceeded,
                    timeout_seconds: 20,
                    approval: ApprovalMode::NotRequired,
                }],
                not_required_reason: None,
            },
        );
        AppliedConfig {
            config,
            profiles: BTreeMap::new(),
            source_root: "/fixture".into(),
            source_files: vec![],
            digest: Digest::parse("a".repeat(64)).unwrap(),
        }
    }

    #[test]
    fn operation_approval_bundle_is_recomputed_from_bound_config_and_subject() {
        let temp = tempdir().unwrap();
        let applied = applied_config(&temp.path().join("adapter-state.json"));
        let plan = validate_recipe(&applied.config, "rollout").unwrap();
        let target = plan.targets()[0].clone();
        let project_id = ProjectId::parse("operations_project").unwrap();
        let ticket_id = TicketId::parse("ticket-1").unwrap();
        let ticket_run_id = TicketRunId::parse("run-1").unwrap();
        let operation_id = OperationId::parse("operation-1").unwrap();
        let delivery_facts = DeliveryFacts {
            merge_commits: BTreeMap::from([(target.repository.clone(), SOURCE_SHA.into())]),
            planned_revisions: BTreeMap::new(),
        };
        let subject = crate::operations::OperationSubject {
            project_id: project_id.clone(),
            ticket_id: ticket_id.clone(),
            ticket_run_id: ticket_run_id.clone(),
            ticket_revision: Revision(4),
            operation_id: operation_id.clone(),
            recipe_id: plan.recipe_id().to_owned(),
            plan_digest: plan.digest().clone(),
            config_digest: applied.digest.clone(),
            target_id: target.id.clone(),
            action_id: target.action.clone(),
            repository_id: target.repository.clone(),
            environment: target.environment.clone(),
            source_sha: SOURCE_SHA.into(),
            expected_preconditions: BTreeMap::new(),
        };
        let request = OperationEffectRequest {
            project_id,
            ticket_id,
            ticket_run_id,
            ticket_revision: Revision(4),
            config_revision: Revision(3),
            config_digest: applied.digest.clone(),
            recipe_id: plan.recipe_id().to_owned(),
            plan_digest: plan.digest().clone(),
            delivery_facts,
            subject,
            target,
            approval_request_id: Some("human-operation-1".into()),
        };
        let bundle = operation_review_bundle(&applied, &request).unwrap();
        assert!(bundle.summary.contains(SOURCE_SHA));
        assert!(bundle.evidence[0].body.contains("xtask fixture operations"));
        assert!(
            bundle.evidence[2]
                .body
                .contains(&request.subject.digest().unwrap().to_string())
        );
        assert_eq!(
            review_bundle_digest(&bundle).unwrap(),
            review_bundle_digest(&bundle).unwrap()
        );

        let mut changed = applied;
        changed.digest = Digest::parse("f".repeat(64)).unwrap();
        assert!(operation_review_bundle(&changed, &request).is_err());
    }

    #[test]
    fn durable_operator_effect_reconciles_after_restart_and_checks_current_config() {
        let temp = tempdir().unwrap();
        let remote_state = temp.path().join("fixture-remote.json");
        let mut store = crate::store::ConfigStore::open_test(temp.path()).unwrap();

        let project_id = ProjectId::parse("operations_project").unwrap();
        let ticket_id = TicketId::parse("PAY-12").unwrap();
        let ticket_run_id = TicketRunId::parse("run-1").unwrap();
        let applied = applied_config(&remote_state);
        let applied_revision = store
            .apply_snapshot("factory", &applied, ExpectedRevision::Bootstrap)
            .unwrap();
        store
            .insert_project(&ProjectRecord {
                id: project_id.clone(),
                config_source: "factory".into(),
                config_revision: applied_revision.revision,
                config_digest: applied_revision.digest.clone(),
                mode: "operations".into(),
                goal_revision: 0,
                desired_lifecycle: "running".into(),
                state_revision: Revision(0),
            })
            .unwrap();
        let owner = |nonce: &str| OwnerMetadata {
            owner_nonce: nonce.into(),
            state_root: temp.path().to_string_lossy().into_owned(),
            config_source: "factory".into(),
            process_start_identity: nonce.into(),
            executable_path: "/tmp/rex-projects-fixture".into(),
            executable_digest: "b".repeat(64),
            rex_endpoint: None,
            rex_server_identity: None,
            rex_session_id: None,
            rex_block_id: None,
        };
        let generation = store.start_owner(&owner("first-owner")).unwrap();
        store
            .create_ticket_run(
                generation,
                &project_id,
                &TicketNamespace::parse("github:org/repo").unwrap(),
                &ticket_id,
                &ticket_run_id,
                1,
                "operating",
                "In Progress",
            )
            .unwrap();

        let plan = validate_recipe(&applied.config, "rollout").unwrap();
        let target = &plan.targets()[0];
        let delivery = DeliveryFacts {
            merge_commits: BTreeMap::from([(target.repository.clone(), SOURCE_SHA.into())]),
            planned_revisions: BTreeMap::new(),
        };
        let operation_id = store
            .operations()
            .unwrap()
            .persist_plan(
                generation,
                &project_id,
                &ticket_id,
                &ticket_run_id,
                Revision(0),
                applied_revision.revision,
                &applied,
                &plan,
                &delivery,
                100,
            )
            .unwrap()[0]
            .clone();
        let handler =
            OperationEffectHandler::new([applied.clone()], Duration::from_secs(2)).unwrap();
        let limits = EffectLimits {
            max_attempts: 3,
            max_age: Duration::from_secs(3600),
            retry_base: Duration::from_secs(1),
            retry_max: Duration::from_secs(2),
        };
        assert!(matches!(
            EffectDispatcher::tick(&mut store, generation, 100, &[&handler], limits).unwrap(),
            DispatchTick::WaitingForReconciliation { .. }
        ));
        let state: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&remote_state).unwrap()).unwrap();
        assert_eq!(state["invoke_calls"], 1);
        assert_eq!(state["duplicate_invoke_calls"], 0);

        // A config change must not prevent exact reconciliation of an already
        // started historical operation.
        let mut changed_config = applied.clone();
        changed_config.digest = Digest::parse("f".repeat(64)).unwrap();
        let changed_revision = store
            .apply_snapshot(
                "factory",
                &changed_config,
                ExpectedRevision::Current(applied_revision.revision),
            )
            .unwrap();
        let claimed = store
            .claim_next_due_effect(generation, 200, &["operation".into()])
            .unwrap()
            .unwrap();
        let request = EffectRequest::from(claimed);
        let historical_reconcile = {
            let mut context = EffectContext {
                store: &mut store,
                owner_generation: generation,
                now_unix: 200,
            };
            EffectHandler::handle(&handler, EffectMode::Reconcile, &request, &mut context).unwrap()
        };
        assert!(matches!(
            historical_reconcile,
            crate::effects::EffectObservation::Applied { .. }
        ));

        // Simulate a crash after operation state was recorded but before the
        // outbox dispatcher stored the receipt. Restart must replay the exact
        // terminal receipt without re-invoking the fixture adapter.
        let restarted_generation = store.start_owner(&owner("second-owner")).unwrap();
        let restarted = OperationEffectHandler::new(
            [applied.clone(), changed_config.clone()],
            Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(restarted_generation, generation + 1);
        assert!(matches!(
            EffectDispatcher::tick(&mut store, restarted_generation, 300, &[&restarted], limits)
                .unwrap(),
            DispatchTick::Completed { .. }
        ));
        let state: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&remote_state).unwrap()).unwrap();
        assert_eq!(state["invoke_calls"], 1);
        assert_eq!(state["duplicate_invoke_calls"], 0);

        assert_eq!(
            store
                .operations()
                .unwrap()
                .completion_gate(&project_id, &ticket_run_id)
                .unwrap(),
            CompletionGate::WaitingForPostmortem
        );
        // A former controller may still hold request state after a restart,
        // but stale writes cannot update operation or postmortem state.
        assert!(
            store
                .operations()
                .unwrap()
                .record_postmortem_receipt(
                    1,
                    &project_id,
                    &ticket_run_id,
                    &Digest::parse("c".repeat(64)).unwrap(),
                    101
                )
                .is_err()
        );
        assert!(
            store
                .operations()
                .unwrap()
                .record_observation(
                    1,
                    &operation_id,
                    "{}",
                    None,
                    DurableOperationState::Succeeded,
                    101
                )
                .is_err()
        );
        assert!(
            store
                .operations()
                .unwrap()
                .record_unknown(1, &operation_id, 101)
                .is_err()
        );
        assert_eq!(
            store
                .operations()
                .unwrap()
                .completion_gate(&project_id, &ticket_run_id)
                .unwrap(),
            CompletionGate::WaitingForPostmortem
        );
        let receipt = Digest::parse("b".repeat(64)).unwrap();
        store
            .operations()
            .unwrap()
            .record_postmortem_receipt(2, &project_id, &ticket_run_id, &receipt, 101)
            .unwrap();
        assert_eq!(
            store
                .operations()
                .unwrap()
                .completion_gate(&project_id, &ticket_run_id)
                .unwrap(),
            CompletionGate::Complete
        );

        // A new operation intent created under config v2 cannot invoke after
        // config v3 is applied. The historical v1 operation above could still
        // reconcile because it already had a durable external run reference.
        let second_ticket = TicketId::parse("PAY-13").unwrap();
        let second_run = TicketRunId::parse("run-2").unwrap();
        store
            .create_ticket_run(
                restarted_generation,
                &project_id,
                &TicketNamespace::parse("github:org/repo").unwrap(),
                &second_ticket,
                &second_run,
                1,
                "operating",
                "In Progress",
            )
            .unwrap();
        let second_plan = validate_recipe(&changed_config.config, "rollout").unwrap();
        let second_target = &second_plan.targets()[0];
        let second_delivery = DeliveryFacts {
            merge_commits: BTreeMap::from([(second_target.repository.clone(), SOURCE_SHA.into())]),
            planned_revisions: BTreeMap::new(),
        };
        store
            .operations()
            .unwrap()
            .persist_plan(
                restarted_generation,
                &project_id,
                &second_ticket,
                &second_run,
                Revision(0),
                changed_revision.revision,
                &changed_config,
                &second_plan,
                &second_delivery,
                350,
            )
            .unwrap();
        let mut revoked_config = changed_config.clone();
        revoked_config.digest = Digest::parse("e".repeat(64)).unwrap();
        store
            .apply_snapshot(
                "factory",
                &revoked_config,
                ExpectedRevision::Current(changed_revision.revision),
            )
            .unwrap();
        let revoked_handler =
            OperationEffectHandler::new([applied, changed_config], Duration::from_secs(2)).unwrap();
        assert!(matches!(
            EffectDispatcher::tick(
                &mut store,
                restarted_generation,
                400,
                &[&revoked_handler],
                limits
            )
            .unwrap(),
            DispatchTick::WaitingForReconciliation { .. }
        ));
        let state: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&remote_state).unwrap()).unwrap();
        assert_eq!(state["invoke_calls"], 1);
        assert_eq!(state["duplicate_invoke_calls"], 0);
    }
}
