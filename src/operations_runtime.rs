//! Host-side Operator effect execution and reconciliation.
//!
//! The shared outbox dispatcher invokes this handler outside its SQLite
//! transaction. Each operation has one immutable effect identity for its
//! entire invoke/find/observe lifecycle. `Unknown` is reconciled by exact
//! operation identity before any retry can be considered.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::config::AppliedConfig;
use crate::domain::ids::{Digest, HumanRequestId, OperationId};
use crate::effects::{
    AbsentProof, EffectContext, EffectHandler, EffectKind, EffectMode, EffectObservation,
    EffectRequest,
};
use crate::host_jobs::{
    HostJobEnvironmentBinding, HostJobPool, HostJobProgress, environment_policy_digest,
    process_request_digest, stable_host_job_id,
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
    operations::{DurableOperationState, OperationEffectRequest, RecordInvoking},
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
    host_jobs: Option<Arc<Mutex<HostJobPool>>>,
    host_environment: BTreeMap<OsString, OsString>,
    environment_binding: Option<HostJobEnvironmentBinding>,
}

enum OperationCommandRunner<'a> {
    Direct(ProcessCommandRunner),
    Pooled(PooledOperationCommandRunner<'a>),
}

struct PooledOperationCommandRunner<'a> {
    store: &'a mut crate::store::ConfigStore,
    owner_generation: u64,
    pool: Arc<Mutex<HostJobPool>>,
    host_environment: &'a BTreeMap<OsString, OsString>,
    environment: &'a HostJobEnvironmentBinding,
    operation: &'a OperationEffectRequest,
    effect: &'a EffectIntent,
    round: u32,
    shutdown_grace: Duration,
}

impl crate::operations::BoundedCommandRunner for OperationCommandRunner<'_> {
    fn run_argv(
        &mut self,
        command: &[String],
        stdin: &[u8],
        timeout: Duration,
        stdout_limit: usize,
        stderr_tail_limit: usize,
    ) -> Result<crate::operations::CommandRunResult, String> {
        match self {
            Self::Direct(runner) => {
                runner.run_argv(command, stdin, timeout, stdout_limit, stderr_tail_limit)
            }
            Self::Pooled(runner) => {
                runner.run_argv(command, stdin, timeout, stdout_limit, stderr_tail_limit)
            }
        }
    }
}

impl crate::operations::BoundedCommandRunner for PooledOperationCommandRunner<'_> {
    fn run_argv(
        &mut self,
        command: &[String],
        stdin: &[u8],
        timeout: Duration,
        stdout_limit: usize,
        stderr_tail_limit: usize,
    ) -> Result<crate::operations::CommandRunResult, String> {
        let Some((executable, arguments)) = command.split_first() else {
            return Err("configured operation command is empty".into());
        };
        let path = self
            .host_environment
            .get(OsStr::new("PATH"))
            .map(std::env::split_paths)
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        let executable = crate::process::resolve_executable(Path::new(executable), &path)
            .ok_or_else(|| {
                "configured operation executable is unavailable in captured PATH".to_owned()
            })?;
        let process_request = crate::process::ProcessRequest {
            executable,
            args: arguments.iter().map(OsString::from).collect(),
            stdin: stdin.to_vec(),
            cwd: None,
            clear_environment: true,
            environment: self.host_environment.clone(),
            timeout,
            shutdown_grace: self.shutdown_grace,
            stdout_limit,
            stderr_tail_limit,
        };
        let envelope: serde_json::Value = crate::protocol::parse_unique(stdin)?;
        let method = envelope
            .get("method")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "operation adapter request has no method".to_owned())?;
        let operation_method = match method {
            "operation.invoke" => crate::store::host_jobs::OperationMethod::Invoke,
            "operation.find" => crate::store::host_jobs::OperationMethod::Find,
            "operation.observe" => crate::store::host_jobs::OperationMethod::Observe,
            _ => return Err("operation adapter method is unsupported".into()),
        };
        let operation_id = self.operation.subject.operation_id.as_str();
        let round = self.round.max(1);
        let job_id = stable_host_job_id(operation_id, method, round);
        let intent = crate::store::host_jobs::HostJobIntent {
            job_id: job_id.clone(),
            effect_operation_id: format!("operation:{operation_id}:{method}:{round}"),
            project_id: self.operation.project_id.to_string(),
            subject_id: operation_id.to_owned(),
            lane_id: operation_id.to_owned(),
            kind: crate::store::host_jobs::HostJobKind::OperationAdapter,
            operation_method: Some(operation_method),
            request_digest: process_request_digest(&process_request, self.environment),
            configuration_digest: self.operation.config_digest.to_string(),
            environment_snapshot_id: self.environment.snapshot_id.clone(),
            environment_policy_digest: self.environment.policy_digest.clone(),
            head: self.operation.subject.source_sha.clone(),
            source_digest: self.effect.request_digest.clone(),
            max_attempts: if method == "operation.invoke" { 1 } else { 2 },
            retry_when_absent: method != "operation.invoke",
        };
        let progress = self
            .pool
            .lock()
            .map_err(|_| "host job pool lock is poisoned".to_owned())?
            .submit_or_poll(
                self.store,
                self.owner_generation,
                &intent,
                process_request,
                None,
                unix_now()?,
            )?;
        match progress {
            HostJobProgress::ProcessCompleted(receipt) => {
                let safe_receipt = serde_json::json!({
                    "operation_id": operation_id,
                    "method": method,
                    "request_digest": intent.request_digest,
                    "status_code": receipt.status_code,
                    "stdout_truncated": receipt.stdout_truncated,
                    "stderr_truncated": receipt.stderr_truncated,
                    "timed_out": receipt.timed_out,
                    "cleanup_confirmed": receipt.cleanup_confirmed,
                })
                .to_string();
                self.pool
                    .lock()
                    .map_err(|_| "host job pool lock is poisoned".to_owned())?
                    .finish(
                        self.store,
                        self.owner_generation,
                        &job_id,
                        receipt.status_code == Some(0)
                            && !receipt.timed_out
                            && receipt.cleanup_confirmed,
                        &safe_receipt,
                        unix_now()?,
                    )?;
                Ok(crate::operations::CommandRunResult::Completed(
                    crate::operations::CommandCompletion {
                        exit_code: receipt.status_code,
                        timed_out: receipt.timed_out,
                        cleanup_confirmed: receipt.cleanup_confirmed,
                        stdout: receipt.stdout,
                        stdout_truncated: receipt.stdout_truncated,
                        stderr_tail: receipt.stderr_tail,
                        stderr_truncated: receipt.stderr_truncated,
                    },
                ))
            }
            HostJobProgress::ProcessAbsentNoRetry
            | HostJobProgress::ProcessFailed(_)
            | HostJobProgress::Succeeded(_)
            | HostJobProgress::Failed(_) => Ok(crate::operations::CommandRunResult::ProcessAbsent),
            HostJobProgress::Pending | HostJobProgress::Running | HostJobProgress::Unknown => {
                Ok(crate::operations::CommandRunResult::Pending)
            }
        }
    }
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
            host_jobs: None,
            host_environment: BTreeMap::new(),
            environment_binding: None,
        })
    }

    pub fn with_host_jobs(
        snapshots: impl IntoIterator<Item = AppliedConfig>,
        process_shutdown_grace: Duration,
        host_jobs: Arc<Mutex<HostJobPool>>,
        host_environment: BTreeMap<OsString, OsString>,
        environment_snapshot_id: Digest,
    ) -> Result<Self, String> {
        let mut handler = Self::new(snapshots, process_shutdown_grace)?;
        let policy_digest =
            environment_policy_digest("rex-projects-host-operation-v1", &host_environment)?;
        handler.host_jobs = Some(host_jobs);
        handler.host_environment = host_environment;
        handler.environment_binding = Some(HostJobEnvironmentBinding {
            snapshot_id: environment_snapshot_id,
            policy_digest,
        });
        Ok(handler)
    }

    fn command_runner<'a>(
        &'a self,
        context: &'a mut EffectContext<'_>,
        effect: &'a EffectIntent,
        operation: &'a OperationEffectRequest,
        round: u32,
    ) -> Result<OperationCommandRunner<'a>, String> {
        if let (Some(pool), Some(environment)) = (&self.host_jobs, &self.environment_binding) {
            Ok(OperationCommandRunner::Pooled(
                PooledOperationCommandRunner {
                    store: context.store,
                    owner_generation: context.owner_generation,
                    pool: Arc::clone(pool),
                    host_environment: &self.host_environment,
                    environment,
                    operation,
                    effect,
                    round,
                    shutdown_grace: self.process_shutdown_grace,
                },
            ))
        } else {
            Ok(OperationCommandRunner::Direct(ProcessCommandRunner::new(
                self.process_shutdown_grace,
            )?))
        }
    }

    pub fn handle(
        &self,
        mode: OperationExecutionMode,
        effect: &EffectIntent,
        attempt_count: u32,
        context: &mut EffectContext<'_>,
    ) -> Result<OperationExecutionOutcome, String> {
        let (request, record) = {
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
            (request, record)
        };
        let (applied, target, permit) = {
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
            (applied.clone(), target.clone(), permit)
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
        let invocation_attempt = {
            let mut store = context.store.operations()?;
            let record = store
                .operation(operation_id)?
                .ok_or_else(|| "durable operation row is missing".to_owned())?;
            if !matches!(
                record.state,
                DurableOperationState::Ready
                    | DurableOperationState::Unknown
                    | DurableOperationState::Invoking
            ) {
                return Err("operation is not ready for a submission attempt".into());
            }
            // Unknown can reach Submit only after the shared dispatcher accepted a
            // matching authoritative absence proof and reset the same outbox row.
            if record.state == DurableOperationState::Unknown && attempt_count < 2 {
                return Err("unknown operation requires reconciliation before retry".into());
            }
            let invocation_attempt = if record.state == DurableOperationState::Invoking {
                store
                    .latest_operation_invocation(operation_id)?
                    .ok_or_else(|| {
                        "invoking operation has no durable host job identity".to_owned()
                    })?
                    .attempt
            } else {
                attempt_count.max(1)
            };
            let invocation = crate::store::operations::OperationInvocation {
                operation_id: operation_id.clone(),
                attempt: invocation_attempt,
                host_job_id: stable_host_job_id(
                    operation_id.as_str(),
                    "operation.invoke",
                    invocation_attempt,
                ),
                request_digest: Digest::parse(effect.request_digest.clone())?,
                subject_digest: request.subject.digest()?,
            };
            store.record_invoking(
                context.owner_generation,
                RecordInvoking {
                    operation_id,
                    project_id: &request.project_id,
                    ticket_run_id: &request.ticket_run_id,
                    ticket_revision: request.ticket_revision,
                    config_revision: request.config_revision,
                    config_digest: &request.config_digest,
                    attempt_count,
                    invocation: &invocation,
                    now: context.now_unix.max(now),
                },
            )?;
            invocation_attempt
        };

        let timeout = Duration::from_secs(target.timeout_seconds);
        let call = {
            let mut runner = self.command_runner(context, effect, request, invocation_attempt)?;
            crate::operations::invoke_authorized_command(
                &mut runner,
                applied,
                permit,
                request_id(operation_id, "invoke", invocation_attempt),
                timeout,
            )
        };
        match call {
            Ok(AdapterCall::Pending(reason)) => Ok(pending_receipt(
                operation_id,
                "invoke_host_process_pending",
                &reason,
            )),
            Ok(AdapterCall::ProcessAbsent(reason)) => {
                context.store.operations()?.record_unknown(
                    context.owner_generation,
                    operation_id,
                    context.now_unix.max(unix_now()?),
                )?;
                Ok(pending_receipt(
                    operation_id,
                    "invoke_process_absent",
                    &reason,
                ))
            }
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
        let call = {
            let mut runner = self.command_runner(context, effect, request, attempt_count)?;
            call_command_adapter(
                &mut runner,
                action,
                &envelope,
                Duration::from_secs(target.timeout_seconds),
            )
        };
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
        let call = {
            let mut runner = self.command_runner(context, effect, request, attempt_count)?;
            call_command_adapter(
                &mut runner,
                action,
                &envelope,
                Duration::from_secs(target.timeout_seconds),
            )
        };
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
    use crate::domain::ids::{ProjectId, RepositoryId, Revision, TicketId, TicketRunId};
    use crate::domain::types::{ApprovalMode, OperationSource};
    use crate::effects::{AbsentProof, EffectRequest};
    use crate::human::review_bundle_digest;
    use crate::operations::{DeliveryFacts, validate_recipe};
    use crate::store::{ConfigStore, ExpectedRevision, OwnerMetadata, ProjectRecord};

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
        config
            .projects
            .get_mut(&ProjectId::parse("operations_project").unwrap())
            .unwrap()
            .operation_matches = vec![crate::config::OperationMatch {
            labels_all: vec!["docs".into()],
            recipe: "rollout".into(),
        }];
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
        assert!(
            bundle.evidence[0]
                .body
                .contains("Configured argv (direct execution, no shell)")
        );
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
    fn operation_invocation_retry_requires_claimed_effect_and_exact_find_absence() {
        let temp = tempdir().unwrap();
        let state_path = temp.path().join("controller");
        let mut store = ConfigStore::open_test(&state_path).unwrap();
        let applied = applied_config(&state_path);
        let config_snapshot = store
            .apply_snapshot("factory", &applied, ExpectedRevision::Bootstrap)
            .unwrap();
        let project_id = ProjectId::parse("operations_project").unwrap();
        let ticket_id = TicketId::parse("ticket-retry").unwrap();
        let ticket_run_id = TicketRunId::parse("run-retry").unwrap();
        let namespace = crate::domain::ids::TicketNamespace::parse("github:org/repo").unwrap();
        store
            .insert_project(&ProjectRecord {
                id: project_id.clone(),
                config_source: "factory".into(),
                config_revision: config_snapshot.revision,
                config_digest: config_snapshot.digest.clone(),
                mode: "operations".into(),
                goal_revision: 0,
                desired_lifecycle: "running".into(),
                state_revision: Revision(0),
            })
            .unwrap();
        let generation = store
            .start_owner(&OwnerMetadata {
                owner_nonce: "operations-retry-owner".into(),
                state_root: state_path.to_string_lossy().into_owned(),
                config_source: "factory".into(),
                process_start_identity: "operations-retry-owner".into(),
                executable_path: "/tmp/rex-projects-test".into(),
                executable_digest: "b".repeat(64),
                rex_endpoint: None,
                rex_server_identity: None,
                rex_session_id: None,
                rex_block_id: None,
            })
            .unwrap();
        store
            .create_ticket_run(
                generation,
                &project_id,
                &namespace,
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
                config_snapshot.revision,
                &applied,
                &plan,
                &delivery,
                100,
            )
            .unwrap()[0]
            .clone();
        let first_claim = store
            .claim_next_due_effect(generation, 100, &["operation".into()])
            .unwrap()
            .expect("first operation claim");
        let first_effect = EffectRequest::from(first_claim);
        let request = store
            .operations()
            .unwrap()
            .effect_request(&first_effect.intent)
            .unwrap();
        let invocation = |attempt: u32| crate::store::operations::OperationInvocation {
            operation_id: operation_id.clone(),
            attempt,
            host_job_id: stable_host_job_id(operation_id.as_str(), "operation.invoke", attempt),
            request_digest: Digest::parse(first_effect.intent.request_digest.clone()).unwrap(),
            subject_digest: request.subject.digest().unwrap(),
        };
        {
            let mut operations = store.operations().unwrap();
            operations
                .record_invoking(
                    generation,
                    RecordInvoking {
                        operation_id: &operation_id,
                        project_id: &project_id,
                        ticket_run_id: &ticket_run_id,
                        ticket_revision: request.ticket_revision,
                        config_revision: request.config_revision,
                        config_digest: &request.config_digest,
                        attempt_count: first_effect.attempt_count,
                        invocation: &invocation(1),
                        now: 101,
                    },
                )
                .unwrap();
            operations
                .record_unknown(generation, &operation_id, 102)
                .unwrap();
            assert!(
                operations
                    .record_invoking(
                        generation,
                        RecordInvoking {
                            operation_id: &operation_id,
                            project_id: &project_id,
                            ticket_run_id: &ticket_run_id,
                            ticket_revision: request.ticket_revision,
                            config_revision: request.config_revision,
                            config_digest: &request.config_digest,
                            attempt_count: first_effect.attempt_count,
                            invocation: &invocation(2),
                            now: 103,
                        },
                    )
                    .is_err(),
                "a caller cannot create a second invoke without an accepted Find absence"
            );
        }

        let proof = AbsentProof::from_authoritative_lookup(
            EffectKind::Operation,
            &first_effect,
            "fixture-operation-adapter",
            "exact operation key was absent",
        )
        .unwrap();
        let proof_json = serde_json::to_string(&proof).unwrap();
        store
            .retry_effect_after_absence(
                &first_effect.intent.operation_id,
                generation,
                &first_effect.intent.request_digest,
                &proof_json,
                200,
            )
            .unwrap();
        let second_claim = store
            .claim_next_due_effect(generation, 200, &["operation".into()])
            .unwrap()
            .expect("authoritatively absent operation is claimed for bounded retry");
        let second_effect = EffectRequest::from(second_claim);
        assert_eq!(second_effect.attempt_count, 2);
        store
            .operations()
            .unwrap()
            .record_invoking(
                generation,
                RecordInvoking {
                    operation_id: &operation_id,
                    project_id: &project_id,
                    ticket_run_id: &ticket_run_id,
                    ticket_revision: request.ticket_revision,
                    config_revision: request.config_revision,
                    config_digest: &request.config_digest,
                    attempt_count: second_effect.attempt_count,
                    invocation: &invocation(2),
                    now: 201,
                },
            )
            .unwrap();
        assert_eq!(
            store
                .operations()
                .unwrap()
                .latest_operation_invocation(&operation_id)
                .unwrap()
                .unwrap()
                .attempt,
            2
        );
    }
}
