//! Host-side Operator effect execution and reconciliation.
//!
//! The shared outbox dispatcher invokes this handler outside its SQLite
//! transaction. Each operation has one immutable effect identity for its
//! entire invoke/find/observe lifecycle. `Unknown` is reconciled by exact
//! operation identity before any retry can be considered.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use crate::config::AppliedConfig;
use crate::domain::ids::{Digest, OperationId};
use crate::effects::{
    AbsentProof, EffectHandler, EffectKind, EffectMode, EffectObservation, EffectRequest,
};
use crate::operations::{
    AdapterCall, FindOutcome, FindParams, HumanApprovalReceipt, InvokeOutcome, InvokeResult,
    OperationObservation, OperationPermit, PredicateResult, ProcessCommandRunner,
    authorize_operation, call_command_adapter, new_request, validate_recipe,
};
use crate::store::{
    EffectIntent,
    operations::{DurableOperationState, OperationEffectRequest, OperationsStore},
};

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

impl EffectHandler for OperationEffectHandler {
    fn kind(&self) -> EffectKind {
        EffectKind::Operation
    }

    fn handle(
        &self,
        mode: EffectMode,
        request: &EffectRequest,
    ) -> Result<EffectObservation, String> {
        let mode = match mode {
            EffectMode::Submit => OperationExecutionMode::Submit,
            EffectMode::Reconcile => OperationExecutionMode::Reconcile,
        };
        match self.handle(mode, &request.intent, request.attempt_count)? {
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
    database_path: PathBuf,
    snapshots: BTreeMap<String, AppliedConfig>,
    process_shutdown_grace: Duration,
}

impl OperationEffectHandler {
    pub fn new(
        database_path: impl Into<PathBuf>,
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
            database_path: database_path.into(),
            snapshots: by_digest,
            process_shutdown_grace,
        })
    }

    pub fn handle(
        &self,
        mode: OperationExecutionMode,
        effect: &EffectIntent,
        attempt_count: u32,
    ) -> Result<OperationExecutionOutcome, String> {
        let mut connection = open_database(&self.database_path)?;
        let (request, applied, target, permit) = {
            let store = OperationsStore::new(&mut connection)?;
            let request = store.effect_request(effect)?;
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
            let record = store
                .operation(&request.subject.operation_id)?
                .ok_or_else(|| "durable operation row is missing".to_owned())?;
            if record.request_digest != Digest::parse(effect.request_digest.clone())?
                || record.subject_digest != request.subject.digest().map_err(|e| e.to_string())?
            {
                return Err("operation row is not bound to the immutable effect subject".into());
            }
            let stored_approval = record
                .approval_json
                .as_deref()
                .map(serde_json::from_str::<HumanApprovalReceipt>)
                .transpose()
                .map_err(|_| "stored approval receipt is invalid".to_owned())?;
            if stored_approval != request.approval {
                return Err("operation approval differs from its accepted durable receipt".into());
            }
            let permit = authorize_operation(
                applied,
                &request.delivery_facts,
                &plan,
                target,
                request.subject.clone(),
                request.approval.as_ref(),
            )
            .map_err(|error| error.to_string())?;
            (request, applied.clone(), target.clone(), permit)
        };
        match mode {
            OperationExecutionMode::Submit => self.submit(
                &mut connection,
                effect,
                &request,
                &applied,
                &target,
                &permit,
                attempt_count,
            ),
            OperationExecutionMode::Reconcile => self.reconcile(
                &mut connection,
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
        connection: &mut Connection,
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
            let mut store = OperationsStore::new(connection)?;
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
            store.record_invoking(operation_id, now)?;
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
                let mut store = OperationsStore::new(connection)?;
                store.record_unknown(operation_id, unix_now()?)?;
                Ok(pending_receipt(operation_id, "invoke_uncertain", &reason))
            }
            Err(error) => {
                let mut store = OperationsStore::new(connection)?;
                store.record_handler_failure(operation_id, unix_now()?)?;
                Ok(pending_receipt(
                    operation_id,
                    "invoke_unknown",
                    &error.to_string(),
                ))
            }
            Ok(AdapterCall::Response(response)) => {
                let Some(value) = response.result else {
                    let mut store = OperationsStore::new(connection)?;
                    store.record_unknown(operation_id, unix_now()?)?;
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
                        let mut store = OperationsStore::new(connection)?;
                        store.record_observation(
                            operation_id,
                            &receipt,
                            DurableOperationState::Failed,
                            unix_now()?,
                        )?;
                        Ok(OperationExecutionOutcome::Rejected {
                            receipt_json: receipt,
                        })
                    }
                    InvokeOutcome::Accepted | InvokeOutcome::Completed => {
                        let Some(external_reference) = result.external_reference else {
                            let mut store = OperationsStore::new(connection)?;
                            store.record_unknown(operation_id, unix_now()?)?;
                            return Ok(pending_receipt(
                                operation_id,
                                "invoke_missing_reference",
                                "adapter omitted external reference",
                            ));
                        };
                        OperationsStore::new(connection)?.record_running(
                            operation_id,
                            &external_reference,
                            unix_now()?,
                        )?;
                        self.observe(
                            connection,
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
        connection: &mut Connection,
        effect: &EffectIntent,
        request: &OperationEffectRequest,
        applied: &AppliedConfig,
        target: &crate::config::OperationTarget,
        permit: &OperationPermit,
        attempt_count: u32,
    ) -> Result<OperationExecutionOutcome, String> {
        let record = OperationsStore::new(connection)?
            .operation(&request.subject.operation_id)?
            .ok_or_else(|| "durable operation row is missing".to_owned())?;
        if let Some(external_reference) = record.external_reference {
            return self.observe(
                connection,
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
                OperationsStore::new(connection)?.record_running(
                    &request.subject.operation_id,
                    &reference,
                    unix_now()?,
                )?;
                self.observe(
                    connection,
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
        connection: &mut Connection,
        _effect: &EffectIntent,
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
        OperationsStore::new(connection)?.record_observation(
            &request.subject.operation_id,
            &observation_json,
            state,
            unix_now()?,
        )?;
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
        Ok(match predicate {
            PredicateResult::Satisfied => OperationExecutionOutcome::Applied {
                receipt_json: receipt,
            },
            PredicateResult::Pending => OperationExecutionOutcome::Pending {
                receipt_json: receipt,
            },
            PredicateResult::Failed => OperationExecutionOutcome::Rejected {
                receipt_json: receipt,
            },
        })
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

fn request_id(operation_id: &OperationId, stage: &str, attempt: u32) -> String {
    format!("{}-{stage}-{attempt}", operation_id.as_str())
}

fn open_database(path: &Path) -> Result<Connection, String> {
    let connection = Connection::open(path).map_err(|error| error.to_string())?;
    connection
        .busy_timeout(Duration::from_secs(5))
        .map_err(|error| error.to_string())?;
    connection
        .execute_batch("PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL;")
        .map_err(|error| error.to_string())?;
    Ok(connection)
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

    use tempfile::tempdir;

    use super::*;
    use crate::config::{
        AppliedConfig, Config, OperationActionConfig, OperationTarget, RepositoryOperationsConfig,
        SuccessPredicate,
    };
    use crate::domain::ids::{ProjectId, RepositoryId, Revision, TicketId, TicketRunId};
    use crate::domain::types::{ApprovalMode, OperationSource};
    use crate::operations::{DeliveryFacts, validate_recipe};
    use crate::store::operations::{CompletionGate, migrate_v11};

    const SOURCE_SHA: &str = "0123456789abcdef0123456789abcdef01234567";

    fn applied_config(state_path: &Path) -> AppliedConfig {
        let mut config: Config = toml::from_str(include_str!("../examples/fixture/config.toml"))
            .expect("public fixture configuration parses");
        let fixture = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/operations/lost_reply_adapter.py"
        );
        config.operation_actions.insert(
            "deploy".into(),
            OperationActionConfig::Command {
                command: vec![
                    "python3".into(),
                    fixture.into(),
                    state_path.to_string_lossy().into_owned(),
                    "--drop-first-invoke-reply".into(),
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

    fn v10_database(path: &Path) -> Connection {
        let connection = Connection::open(path).unwrap();
        connection.execute_batch(
            "CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at_unix INTEGER NOT NULL);
             INSERT INTO schema_migrations VALUES (10, 1);
             CREATE TABLE config_snapshots(source_identity TEXT, revision INTEGER, digest TEXT);
             CREATE TABLE projects(project_id TEXT PRIMARY KEY, config_source TEXT);
             CREATE TABLE ticket_runs(ticket_run_id TEXT PRIMARY KEY, project_id TEXT, config_source TEXT, config_revision INTEGER, config_digest TEXT, revision INTEGER);
             CREATE TABLE controller_owners(singleton INTEGER PRIMARY KEY, generation INTEGER, stopped_at_unix INTEGER);
             INSERT INTO controller_owners VALUES (1, 1, NULL);
             CREATE TABLE effects(operation_id TEXT PRIMARY KEY, project_id TEXT, subject_type TEXT, subject_id TEXT, logical_key TEXT, kind TEXT, request_json TEXT, request_digest TEXT, expected_revision INTEGER, status TEXT, attempt_count INTEGER, next_attempt_at_unix INTEGER, owner_generation INTEGER, receipt_json TEXT, last_error TEXT, created_at_unix INTEGER);
             PRAGMA user_version=10;",
        ).unwrap();
        connection
    }

    #[test]
    fn lost_invoke_reply_reconciles_exact_run_without_duplicate_deploy() {
        let temp = tempdir().unwrap();
        let db = temp.path().join("state.sqlite3");
        let remote_state = temp.path().join("fixture-remote.json");
        let mut connection = v10_database(&db);
        migrate_v11(&connection).unwrap();

        let project_id = ProjectId::parse("operations_project").unwrap();
        let ticket_id = TicketId::parse("PAY-12").unwrap();
        let ticket_run_id = TicketRunId::parse("run-1").unwrap();
        let applied = applied_config(&remote_state);
        connection
            .execute(
                "INSERT INTO config_snapshots VALUES ('factory', 1, ?1)",
                [applied.digest.as_str()],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO projects VALUES ('operations_project', 'factory')",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO ticket_runs VALUES ('run-1','operations_project','factory',1,?1,5)",
                [applied.digest.as_str()],
            )
            .unwrap();

        let plan = validate_recipe(&applied.config, "rollout").unwrap();
        let target = &plan.targets()[0];
        let delivery = DeliveryFacts {
            merge_commits: BTreeMap::from([(target.repository.clone(), SOURCE_SHA.into())]),
            planned_revisions: BTreeMap::new(),
        };
        let operation_id = OperationsStore::new(&mut connection)
            .unwrap()
            .persist_plan(
                1,
                &project_id,
                &ticket_id,
                &ticket_run_id,
                Revision(5),
                Revision(1),
                &applied,
                &plan,
                &delivery,
                100,
            )
            .unwrap()[0]
            .clone();
        let effect = connection.query_row(
            "SELECT operation_id,project_id,subject_type,subject_id,logical_key,kind,request_json,request_digest,expected_revision FROM effects WHERE operation_id=?1",
            [operation_id.as_str()],
            |row| Ok(EffectIntent {
                operation_id: row.get(0)?,
                project_id: ProjectId::parse(row.get::<_,String>(1)?).map_err(|e| rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Text, Box::new(std::io::Error::other(e))))?,
                subject_type: row.get(2)?, subject_id: row.get(3)?, logical_key: row.get(4)?, kind: row.get(5)?,
                request_json: row.get(6)?, request_digest: row.get(7)?, expected_revision: row.get(8)?,
            }),
        ).unwrap();
        let handler = OperationEffectHandler::new(&db, [applied], Duration::from_secs(2)).unwrap();

        let first = handler
            .handle(OperationExecutionMode::Submit, &effect, 1)
            .unwrap();
        assert!(matches!(first, OperationExecutionOutcome::Pending { .. }));
        let state: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&remote_state).unwrap()).unwrap();
        assert_eq!(state["invoke_calls"], 1);
        assert_eq!(state["duplicate_invoke_calls"], 0);

        let reconciled = handler
            .handle(OperationExecutionMode::Reconcile, &effect, 1)
            .unwrap();
        assert!(matches!(
            reconciled,
            OperationExecutionOutcome::Applied { .. }
        ));
        let state: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&remote_state).unwrap()).unwrap();
        assert_eq!(state["invoke_calls"], 1);
        assert_eq!(state["duplicate_invoke_calls"], 0);

        assert_eq!(
            OperationsStore::new(&mut connection)
                .unwrap()
                .completion_gate(&project_id, &ticket_run_id)
                .unwrap(),
            CompletionGate::WaitingForPostmortem
        );
        let receipt = Digest::parse("b".repeat(64)).unwrap();
        OperationsStore::new(&mut connection)
            .unwrap()
            .record_postmortem_receipt(&project_id, &ticket_run_id, &receipt, 101)
            .unwrap();
        assert_eq!(
            OperationsStore::new(&mut connection)
                .unwrap()
                .completion_gate(&project_id, &ticket_run_id)
                .unwrap(),
            CompletionGate::Complete
        );
    }
}
