//! Durable Operator plan and execution state, stored beside the controller outbox.
//!
//! This module owns schema migration 11. The host controller calls
//! `migrate_v11` only after migrations 1 through 10 have completed.

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::config::{AppliedConfig, OperationTarget};
use crate::domain::ids::{Digest, OperationId, ProjectId, Revision, TicketId, TicketRunId};
use crate::human_runtime::{
    HumanDecisionChoice, HumanPresentationEffect, HumanPurpose, HumanRuntimeRequest,
};
use crate::operations::{
    DeliveryFacts, OperationApprovalCapability, OperationSubject, ValidatedOperationPlan,
    resolve_source,
};

pub const OPERATIONS_SCHEMA_VERSION: i64 = 11;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DurableOperationState {
    AwaitingApproval,
    Ready,
    Invoking,
    Unknown,
    Running,
    Succeeded,
    Failed,
    Skipped,
}

impl DurableOperationState {
    fn as_str(self) -> &'static str {
        match self {
            Self::AwaitingApproval => "awaiting_approval",
            Self::Ready => "ready",
            Self::Invoking => "invoking",
            Self::Unknown => "unknown",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Skipped => "skipped",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationEffectRequest {
    pub project_id: ProjectId,
    pub ticket_id: TicketId,
    pub ticket_run_id: TicketRunId,
    pub ticket_revision: Revision,
    pub config_revision: Revision,
    pub config_digest: Digest,
    pub recipe_id: String,
    pub plan_digest: Digest,
    pub delivery_facts: DeliveryFacts,
    pub subject: OperationSubject,
    pub target: OperationTarget,
    pub approval_request_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationPlanState {
    pub project_id: ProjectId,
    pub ticket_run_id: TicketRunId,
    pub recipe_id: String,
    pub plan_digest: Digest,
    pub config_digest: Digest,
    pub state: String,
    pub not_required_reason: Option<String>,
    pub postmortem_receipt_digest: Option<Digest>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationRecord {
    pub operation_id: OperationId,
    pub project_id: ProjectId,
    pub ticket_run_id: TicketRunId,
    pub target_id: String,
    pub state: DurableOperationState,
    pub subject_digest: Digest,
    pub request_digest: Digest,
    pub external_reference: Option<String>,
    pub observation_json: Option<String>,
    pub terminal_receipt_json: Option<String>,
    pub approval_json: Option<String>,
}

/// Apply migration 11 only to a database whose predecessor migrations have
/// reached version 10. This lets each feature branch own its migration without
/// skipping migrations owned by the controller, human, pipeline, or learning
/// modules.
pub fn migrate_v11(connection: &Connection) -> Result<(), String> {
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| error.to_string())?;
    if version == OPERATIONS_SCHEMA_VERSION {
        return Ok(());
    }
    if version != 10 {
        return Err(format!(
            "operations migration 11 requires schema 10, found {version}"
        ));
    }
    let tx = connection
        .unchecked_transaction()
        .map_err(|error| error.to_string())?;
    tx.execute_batch(
        "CREATE TABLE operation_plans (
            project_id TEXT NOT NULL REFERENCES projects(project_id) ON DELETE CASCADE,
            ticket_run_id TEXT NOT NULL REFERENCES ticket_runs(ticket_run_id) ON DELETE CASCADE,
            recipe_id TEXT NOT NULL,
            plan_digest TEXT NOT NULL CHECK(length(plan_digest)=64),
            config_revision INTEGER NOT NULL,
            config_digest TEXT NOT NULL CHECK(length(config_digest)=64),
            state TEXT NOT NULL CHECK(state IN ('required','not_required','succeeded','blocked')),
            not_required_reason TEXT,
            postmortem_receipt_digest TEXT CHECK(postmortem_receipt_digest IS NULL OR length(postmortem_receipt_digest)=64),
            created_at_unix INTEGER NOT NULL,
            updated_at_unix INTEGER NOT NULL,
            PRIMARY KEY(project_id,ticket_run_id),
            CHECK((state='not_required' AND not_required_reason IS NOT NULL AND length(trim(not_required_reason))>0) OR state!='not_required')
        );
        CREATE TABLE operation_runs (
            operation_id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL,
            ticket_run_id TEXT NOT NULL,
            target_id TEXT NOT NULL,
            action_id TEXT NOT NULL,
            repository_id TEXT NOT NULL,
            environment TEXT NOT NULL,
            source_sha TEXT NOT NULL CHECK(length(source_sha) IN (40,64)),
            subject_json TEXT NOT NULL,
            subject_digest TEXT NOT NULL CHECK(length(subject_digest)=64),
            request_json TEXT NOT NULL,
            request_digest TEXT NOT NULL CHECK(length(request_digest)=64),
            state TEXT NOT NULL CHECK(state IN ('awaiting_approval','ready','invoking','unknown','running','succeeded','failed','skipped')),
            approval_json TEXT,
            external_reference TEXT,
            observation_json TEXT,
            terminal_receipt_json TEXT,
            updated_at_unix INTEGER NOT NULL,
            UNIQUE(project_id,ticket_run_id,target_id),
            FOREIGN KEY(project_id,ticket_run_id) REFERENCES operation_plans(project_id,ticket_run_id) ON DELETE CASCADE
        );
        CREATE INDEX operation_runs_by_ticket ON operation_runs(project_id,ticket_run_id,state,target_id);
        CREATE TABLE operation_postmortems (
            project_id TEXT NOT NULL,
            ticket_run_id TEXT NOT NULL,
            receipt_digest TEXT NOT NULL CHECK(length(receipt_digest)=64),
            recorded_at_unix INTEGER NOT NULL,
            PRIMARY KEY(project_id,ticket_run_id),
            FOREIGN KEY(project_id,ticket_run_id) REFERENCES operation_plans(project_id,ticket_run_id) ON DELETE CASCADE
        );",
    )
    .map_err(|error| error.to_string())?;
    let now = unix_now()?;
    tx.execute(
        "INSERT INTO schema_migrations(version,applied_at_unix) VALUES (?1,?2)",
        params![OPERATIONS_SCHEMA_VERSION, now],
    )
    .map_err(|error| error.to_string())?;
    tx.pragma_update(None, "user_version", OPERATIONS_SCHEMA_VERSION)
        .map_err(|error| error.to_string())?;
    tx.commit().map_err(|error| error.to_string())
}

pub struct OperationsStore<'a> {
    connection: &'a mut Connection,
}

impl<'a> OperationsStore<'a> {
    pub fn new(connection: &'a mut Connection) -> Result<Self, String> {
        let version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(|error| error.to_string())?;
        if version != OPERATIONS_SCHEMA_VERSION {
            return Err(format!(
                "operations store requires schema {OPERATIONS_SCHEMA_VERSION}, found {version}"
            ));
        }
        Ok(Self { connection })
    }

    /// Persist the complete plan and every target before dispatching any
    /// operation effect. The target intent and shared `effects` outbox row are
    /// inserted in the same SQLite transaction.
    #[allow(clippy::too_many_arguments)]
    pub fn persist_plan(
        &mut self,
        owner_generation: u64,
        project_id: &ProjectId,
        ticket_id: &TicketId,
        ticket_run_id: &TicketRunId,
        ticket_revision: Revision,
        config_revision: Revision,
        applied: &AppliedConfig,
        plan: &ValidatedOperationPlan,
        delivery_facts: &DeliveryFacts,
        now: i64,
    ) -> Result<Vec<OperationId>, String> {
        if applied.digest.as_str().len() != 64 {
            return Err("applied config digest is invalid".into());
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_owner(&tx, owner_generation)?;
        let config_matches: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM projects p JOIN config_snapshots s ON s.source_identity=p.config_source WHERE p.project_id=?1 AND s.revision=?2 AND s.digest=?3)",
                params![project_id.as_str(), config_revision.0, applied.digest.as_str()],
                |row| row.get(0),
            )
            .map_err(|_| "operation plan config snapshot is not applied".to_owned())?;
        let ticket_run_matches: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM ticket_runs WHERE ticket_run_id=?1 AND project_id=?2 AND config_revision=?3 AND config_digest=?4 AND revision=?5 AND config_source=(SELECT config_source FROM projects WHERE project_id=?2))",
                params![ticket_run_id.as_str(),project_id.as_str(),config_revision.0,applied.digest.as_str(),ticket_revision.0],
                |row| row.get(0),
            )
            .map_err(|_| "ticket run is missing from durable state".to_owned())?;
        if !config_matches || !ticket_run_matches {
            return Err("operation plan config snapshot digest changed".into());
        }
        let existing: Option<(String, String)> = tx
            .query_row(
                "SELECT plan_digest,config_digest FROM operation_plans WHERE project_id=?1 AND ticket_run_id=?2",
                params![project_id.as_str(), ticket_run_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if let Some((plan_digest, config_digest)) = existing {
            if plan_digest != plan.digest().as_str() || config_digest != applied.digest.as_str() {
                return Err("ticket run already has a different immutable operation plan".into());
            }
            tx.commit().map_err(|error| error.to_string())?;
            return self.list_operation_ids(project_id, ticket_run_id);
        }
        let plan_state = if plan.targets().is_empty() {
            "not_required"
        } else {
            "required"
        };
        tx.execute(
            "INSERT INTO operation_plans(project_id,ticket_run_id,recipe_id,plan_digest,config_revision,config_digest,state,not_required_reason,created_at_unix,updated_at_unix) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?9)",
            params![project_id.as_str(),ticket_run_id.as_str(),plan.recipe_id(),plan.digest().as_str(),config_revision.0,applied.digest.as_str(),plan_state,plan.not_required_reason(),now],
        ).map_err(|error| error.to_string())?;
        let mut operation_ids = Vec::new();
        for target in plan.targets() {
            let source_sha = resolve_source(&target.source, &target.repository, delivery_facts)
                .map_err(|error| error.to_string())?;
            let operation_id =
                stable_operation_id(project_id, ticket_run_id, target, plan.digest())?;
            let subject = OperationSubject {
                project_id: project_id.clone(),
                ticket_id: ticket_id.clone(),
                ticket_run_id: ticket_run_id.clone(),
                ticket_revision,
                operation_id: operation_id.clone(),
                recipe_id: plan.recipe_id().to_owned(),
                plan_digest: plan.digest().clone(),
                config_digest: applied.digest.clone(),
                target_id: target.id.clone(),
                action_id: target.action.clone(),
                repository_id: target.repository.clone(),
                environment: target.environment.clone(),
                source_sha,
                expected_preconditions: std::collections::BTreeMap::new(),
            };
            let subject_digest = subject.digest()?;
            let required_approval = requires_approval(&applied.config, project_id, target)?;
            let approval_status = if required_approval {
                super::operations::DurableOperationState::AwaitingApproval
            } else {
                super::operations::DurableOperationState::Ready
            };
            let payload = OperationEffectRequest {
                project_id: project_id.clone(),
                ticket_id: ticket_id.clone(),
                ticket_run_id: ticket_run_id.clone(),
                ticket_revision,
                config_revision,
                config_digest: applied.digest.clone(),
                recipe_id: plan.recipe_id().to_owned(),
                plan_digest: plan.digest().clone(),
                delivery_facts: delivery_facts.clone(),
                subject: subject.clone(),
                target: target.clone(),
                approval_request_id: required_approval
                    .then(|| format!("human-{}", operation_id.as_str())),
            };
            let request_json = canonical_json(&payload)?;
            let request_digest = digest(&request_json)?;
            let subject_json = canonical_json(&subject)?;
            tx.execute(
                "INSERT INTO operation_runs(operation_id,project_id,ticket_run_id,target_id,action_id,repository_id,environment,source_sha,subject_json,subject_digest,request_json,request_digest,state,updated_at_unix) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
                params![operation_id.as_str(),project_id.as_str(),ticket_run_id.as_str(),target.id,target.action,target.repository.as_str(),target.environment,subject.source_sha,subject_json,subject_digest.as_str(),request_json,request_digest.as_str(),approval_status.as_str(),now],
            ).map_err(|error| error.to_string())?;
            if required_approval {
                let rex_view_id: String = tx.query_row(
                    "SELECT v.view_id FROM rex_views v JOIN ticket_runs t ON t.project_id=v.project_id AND t.namespace=v.ticket_namespace AND t.ticket_id=v.ticket_id WHERE t.ticket_run_id=?1 AND v.view_kind='ticket' AND v.lifecycle='active' ORDER BY v.view_epoch DESC LIMIT 1",
                    [ticket_run_id.as_str()],
                    |row| row.get(0),
                ).map_err(|_| "operation approval requires an active ticket Rex view".to_owned())?;
                let bundle = crate::operations::operation_review_bundle(
                    applied, &subject, target, ticket_id,
                )?;
                let binding =
                    crate::operations::operation_human_subject_binding(applied, &subject, &bundle)?;
                let request_id = crate::domain::ids::HumanRequestId::parse(
                    payload
                        .approval_request_id
                        .clone()
                        .ok_or("operation approval request ID is missing")?,
                )?;
                let request = HumanRuntimeRequest {
                    request_id,
                    purpose: HumanPurpose::OperationApproval,
                    subject: binding,
                    question: format!(
                        "Approve the configured operation `{}` for repository `{}` in environment `{}`?",
                        target.id, target.repository, target.environment,
                    ),
                    choices: vec![HumanDecisionChoice::Approve, HumanDecisionChoice::Refuse],
                    expires_at_unix: u64::try_from(now)
                        .unwrap_or(0)
                        .saturating_add(7 * 24 * 60 * 60),
                    review_bundle: bundle,
                };
                enqueue_human_presentation(&tx, &request, &Digest::parse(rex_view_id)?, now)?;
            }
            // The operation effect waits durably for dependencies and, when
            // required, an exact active human approval before invoking anything.
            enqueue_effect(&tx, &payload, now)?;
            operation_ids.push(operation_id);
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(operation_ids)
    }

    /// Persist a host-minted approval capability and enqueue the same immutable
    /// operation intent. The capability itself is never serialized or sent to an Agent.
    pub(crate) fn accept_approval(
        &mut self,
        owner_generation: u64,
        operation_id: &OperationId,
        capability: &OperationApprovalCapability,
        now: i64,
    ) -> Result<(), String> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_owner(&tx, owner_generation)?;
        let row: Option<(String, String, String)> = tx.query_row(
            "SELECT request_json,subject_digest,state FROM operation_runs WHERE operation_id=?1",
            [operation_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).optional().map_err(|error| error.to_string())?;
        let Some((request_json, subject_digest, state)) = row else {
            return Err("operation approval target was not found".into());
        };
        let payload: OperationEffectRequest =
            crate::protocol::parse_unique(request_json.as_bytes())?;
        if canonical_json(&payload)? != request_json
            || state != "awaiting_approval"
            || subject_digest != capability.material_digest().as_str()
            || payload.subject.operation_id != *operation_id
            || capability.operation_id() != operation_id
            || payload.subject.digest()? != *capability.material_digest()
            || payload.config_digest != *capability.configuration_digest()
            || payload.approval_request_id.as_deref() != Some(capability.request_id().as_str())
            || capability.decided_at_unix() > now.max(0) as u64
        {
            return Err(
                "human approval capability is stale or bound to a different operation".into(),
            );
        }
        let approval_audit = serde_json::json!({
            "request_id": capability.request_id().as_str(),
            "operation_id": capability.operation_id().as_str(),
            "material_digest": capability.material_digest().as_str(),
            "binding_digest": capability.binding_digest().as_str(),
            "configuration_digest": capability.configuration_digest().as_str(),
            "policy_digest": capability.policy_digest().as_str(),
            "decided_at_unix": capability.decided_at_unix(),
        });
        tx.execute(
            "UPDATE operation_runs SET approval_json=?2,state='ready',updated_at_unix=?3 WHERE operation_id=?1 AND state='awaiting_approval'",
            params![operation_id.as_str(),canonical_json(&approval_audit)?,now],
        ).map_err(|error| error.to_string())?;
        if dependencies_succeeded(&tx, &payload)? {
            enqueue_effect(&tx, &payload, now)?;
        }
        tx.commit().map_err(|error| error.to_string())
    }

    pub fn record_invoking(
        &mut self,
        owner_generation: u64,
        operation_id: &OperationId,
        project_id: &ProjectId,
        ticket_run_id: &TicketRunId,
        config_revision: Revision,
        config_digest: &Digest,
        now: i64,
    ) -> Result<(), String> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_owner(&tx, owner_generation)?;
        let config_is_current: bool = tx
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM operation_runs r
                    JOIN operation_plans op ON op.project_id=r.project_id AND op.ticket_run_id=r.ticket_run_id
                    JOIN projects p ON p.project_id=op.project_id
                    JOIN config_current current ON current.source_identity=p.config_source
                    JOIN config_snapshots snapshot ON snapshot.source_identity=current.source_identity AND snapshot.revision=current.revision
                    WHERE r.operation_id=?1 AND r.project_id=?2 AND r.ticket_run_id=?3
                      AND op.config_revision=?4 AND op.config_digest=?5
                      AND current.revision=?4 AND snapshot.digest=?5
                )",
                params![operation_id.as_str(), project_id.as_str(), ticket_run_id.as_str(), config_revision.0, config_digest.as_str()],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        if !config_is_current {
            return Err("operation config is no longer the applied project revision".into());
        }
        update_state_in_transaction(&tx, operation_id, &["ready", "unknown"], "invoking", now)?;
        tx.commit().map_err(|error| error.to_string())
    }

    pub fn record_unknown(
        &mut self,
        owner_generation: u64,
        operation_id: &OperationId,
        now: i64,
    ) -> Result<(), String> {
        update_state(
            self.connection,
            owner_generation,
            operation_id,
            &["invoking", "unknown"],
            "unknown",
            now,
        )
    }

    pub fn record_running(
        &mut self,
        owner_generation: u64,
        operation_id: &OperationId,
        external_reference: &str,
        now: i64,
    ) -> Result<(), String> {
        if external_reference.trim().is_empty() {
            return Err("external operation reference must not be empty".into());
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_owner(&tx, owner_generation)?;
        let changed = tx.execute(
            "UPDATE operation_runs SET state='running',external_reference=?2,updated_at_unix=?3 WHERE operation_id=?1 AND state IN ('invoking','unknown','running') AND (external_reference IS NULL OR external_reference=?2)",
            params![operation_id.as_str(),external_reference,now],
        ).map_err(|error| error.to_string())?;
        if changed != 1 {
            return Err("operation run is stale or has a different external reference".into());
        }
        tx.commit().map_err(|error| error.to_string())
    }

    pub fn record_observation(
        &mut self,
        owner_generation: u64,
        operation_id: &OperationId,
        observation_json: &str,
        terminal_receipt_json: Option<&str>,
        state: DurableOperationState,
        now: i64,
    ) -> Result<(), String> {
        if !matches!(
            state,
            DurableOperationState::Running
                | DurableOperationState::Succeeded
                | DurableOperationState::Failed
                | DurableOperationState::Skipped
        ) {
            return Err("observation cannot set a non-observation operation state".into());
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_owner(&tx, owner_generation)?;
        let changed = tx.execute(
            "UPDATE operation_runs SET state=?2,observation_json=?3,terminal_receipt_json=?4,updated_at_unix=?5 WHERE operation_id=?1 AND state IN ('invoking','running','unknown')",
            params![operation_id.as_str(),state.as_str(),observation_json,terminal_receipt_json,now],
        ).map_err(|error| error.to_string())?;
        if changed != 1 {
            return Err("operation observation is stale or operation is not running".into());
        }
        let (project_id, ticket_run_id): (String, String) = tx
            .query_row(
                "SELECT project_id,ticket_run_id FROM operation_runs WHERE operation_id=?1",
                [operation_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|error| error.to_string())?;
        if matches!(
            state,
            DurableOperationState::Succeeded | DurableOperationState::Skipped
        ) {
            schedule_ready_targets(&tx, &project_id, &ticket_run_id, now)?;
            let unfinished: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM operation_runs WHERE project_id=?1 AND ticket_run_id=?2 AND state NOT IN ('succeeded','skipped'))",
                params![project_id,ticket_run_id],
                |row| row.get(0),
            ).map_err(|error| error.to_string())?;
            if !unfinished {
                tx.execute(
                    "UPDATE operation_plans SET state='succeeded',updated_at_unix=?3 WHERE project_id=?1 AND ticket_run_id=?2 AND state='required'",
                    params![project_id,ticket_run_id,now],
                ).map_err(|error| error.to_string())?;
            }
        } else if state == DurableOperationState::Failed {
            tx.execute(
                "UPDATE operation_plans SET state='blocked',updated_at_unix=?3 WHERE project_id=?1 AND ticket_run_id=?2 AND state='required'",
                params![project_id,ticket_run_id,now],
            ).map_err(|error| error.to_string())?;
        }
        tx.commit().map_err(|error| error.to_string())
    }

    pub fn operation(&self, operation_id: &OperationId) -> Result<Option<OperationRecord>, String> {
        self.connection.query_row(
            "SELECT operation_id,project_id,ticket_run_id,target_id,state,subject_digest,request_digest,external_reference,observation_json,terminal_receipt_json,approval_json FROM operation_runs WHERE operation_id=?1",
            [operation_id.as_str()],
            |row| {
                let state: String = row.get(4)?;
                Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?,row.get::<_,String>(3)?,state,row.get::<_,String>(5)?,row.get::<_,String>(6)?,row.get::<_,Option<String>>(7)?,row.get::<_,Option<String>>(8)?,row.get::<_,Option<String>>(9)?,row.get::<_,Option<String>>(10)?))
            },
        ).optional().map_err(|error| error.to_string())?.map(|(id,project,ticket_run,target,state,subject_digest,request_digest,external_reference,observation_json,terminal_receipt_json,approval_json)| {
            Ok(OperationRecord {
                operation_id: OperationId::parse(id)?,
                project_id: ProjectId::parse(project)?,
                ticket_run_id: TicketRunId::parse(ticket_run)?,
                target_id: target,
                state: parse_state(&state)?,
                subject_digest: Digest::parse(subject_digest)?,
                request_digest: Digest::parse(request_digest)?,
                external_reference,
                observation_json,
                terminal_receipt_json,
                approval_json,
            })
        }).transpose()
    }

    pub fn effect_request(
        &self,
        effect: &super::EffectIntent,
    ) -> Result<OperationEffectRequest, String> {
        if effect.kind != "operation" || effect.subject_type != "ticket_run" {
            return Err("effect is not an Operator lifecycle intent".into());
        }
        let request: OperationEffectRequest = serde_json::from_str(&effect.request_json)
            .map_err(|error| format!("operation effect payload is invalid: {error}"))?;
        if canonical_json(&request)? != effect.request_json
            || digest(&effect.request_json)?.as_str() != effect.request_digest
            || request.subject.operation_id.as_str() != effect.operation_id
            || request.project_id != effect.project_id
            || request.ticket_run_id.as_str() != effect.subject_id
            || request.ticket_revision.0 != effect.expected_revision.unwrap_or_default()
            || effect.logical_key != format!("operator:{}", request.target.id)
        {
            return Err("operation effect does not match its immutable outbox identity".into());
        }
        let stored: Option<(String, String, String)> = self.connection.query_row(
            "SELECT request_json,request_digest,state FROM operation_runs WHERE operation_id=?1",
            [effect.operation_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).optional().map_err(|error| error.to_string())?;
        let Some((request_json, request_digest, state)) = stored else {
            return Err("operation effect has no durable operation run".into());
        };
        if request_json != effect.request_json || request_digest != effect.request_digest {
            return Err("operation effect differs from its durable operation intent".into());
        }
        if state == "awaiting_approval" && request.approval_request_id.is_none() {
            return Err("approval-required operation has no human request identity".into());
        }
        Ok(request)
    }

    pub fn dependencies_succeeded(&self, request: &OperationEffectRequest) -> Result<bool, String> {
        for dependency in &request.target.depends_on {
            let succeeded: bool = self.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM operation_runs WHERE project_id=?1 AND ticket_run_id=?2 AND target_id=?3 AND state IN ('succeeded','skipped'))",
                params![request.project_id.as_str(),request.ticket_run_id.as_str(),dependency],
                |row| row.get(0),
            ).map_err(|error| error.to_string())?;
            if !succeeded {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub fn record_handler_failure(
        &mut self,
        owner_generation: u64,
        operation_id: &OperationId,
        now: i64,
    ) -> Result<(), String> {
        update_state(
            self.connection,
            owner_generation,
            operation_id,
            &["invoking"],
            "unknown",
            now,
        )
    }

    pub fn record_approval_rejected(
        &mut self,
        owner_generation: u64,
        operation_id: &OperationId,
        observation_json: &str,
        terminal_receipt_json: &str,
        now: i64,
    ) -> Result<(), String> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_owner(&tx, owner_generation)?;
        let changed = tx.execute(
            "UPDATE operation_runs SET state='failed',observation_json=?2,terminal_receipt_json=?3,updated_at_unix=?4 WHERE operation_id=?1 AND state='awaiting_approval'",
            params![operation_id.as_str(),observation_json,terminal_receipt_json,now],
        ).map_err(|error| error.to_string())?;
        if changed != 1 {
            return Err("operation approval rejection is stale or no longer pending".into());
        }
        tx.execute(
            "UPDATE operation_plans SET state='blocked',updated_at_unix=?2 WHERE project_id=(SELECT project_id FROM operation_runs WHERE operation_id=?1) AND ticket_run_id=(SELECT ticket_run_id FROM operation_runs WHERE operation_id=?1) AND state='required'",
            params![operation_id.as_str(), now],
        ).map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())
    }

    pub fn plan_state(
        &self,
        project_id: &ProjectId,
        ticket_run_id: &TicketRunId,
    ) -> Result<Option<OperationPlanState>, String> {
        self.connection.query_row(
            "SELECT project_id,ticket_run_id,recipe_id,plan_digest,config_digest,state,not_required_reason,postmortem_receipt_digest FROM operation_plans WHERE project_id=?1 AND ticket_run_id=?2",
            params![project_id.as_str(),ticket_run_id.as_str()],
            |row| Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?,row.get::<_,String>(3)?,row.get::<_,String>(4)?,row.get::<_,String>(5)?,row.get::<_,Option<String>>(6)?,row.get::<_,Option<String>>(7)?)),
        ).optional().map_err(|error| error.to_string())?.map(|(project,ticket_run,recipe,plan,config,state,reason,postmortem)| {
            Ok(OperationPlanState {
                project_id: ProjectId::parse(project)?,
                ticket_run_id: TicketRunId::parse(ticket_run)?,
                recipe_id: recipe,
                plan_digest: Digest::parse(plan)?,
                config_digest: Digest::parse(config)?,
                state,
                not_required_reason: reason,
                postmortem_receipt_digest: postmortem.map(Digest::parse).transpose()?,
            })
        }).transpose()
    }

    pub fn record_postmortem_receipt(
        &mut self,
        owner_generation: u64,
        project_id: &ProjectId,
        ticket_run_id: &TicketRunId,
        receipt_digest: &Digest,
        now: i64,
    ) -> Result<(), String> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_owner(&tx, owner_generation)?;
        let plan_state: String = tx
            .query_row(
                "SELECT state FROM operation_plans WHERE project_id=?1 AND ticket_run_id=?2",
                params![project_id.as_str(), ticket_run_id.as_str()],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        if !matches!(plan_state.as_str(), "not_required" | "succeeded") {
            return Err(
                "postmortem cannot be recorded before all required operations succeed".into(),
            );
        }
        tx.execute(
            "INSERT INTO operation_postmortems(project_id,ticket_run_id,receipt_digest,recorded_at_unix) VALUES (?1,?2,?3,?4) ON CONFLICT(project_id,ticket_run_id) DO UPDATE SET receipt_digest=excluded.receipt_digest,recorded_at_unix=excluded.recorded_at_unix",
            params![project_id.as_str(),ticket_run_id.as_str(),receipt_digest.as_str(),now],
        ).map_err(|error| error.to_string())?;
        tx.execute(
            "UPDATE operation_plans SET postmortem_receipt_digest=?3,updated_at_unix=?4 WHERE project_id=?1 AND ticket_run_id=?2",
            params![project_id.as_str(),ticket_run_id.as_str(),receipt_digest.as_str(),now],
        ).map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())
    }

    pub fn completion_gate(
        &self,
        project_id: &ProjectId,
        ticket_run_id: &TicketRunId,
    ) -> Result<CompletionGate, String> {
        let plan = self
            .plan_state(project_id, ticket_run_id)?
            .ok_or_else(|| "operation plan is missing".to_owned())?;
        let failed_effect: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM effects WHERE project_id=?1 AND subject_type='ticket_run' AND subject_id=?2 AND kind='operation' AND status='failed')",
            params![project_id.as_str(),ticket_run_id.as_str()],
            |row| row.get(0),
        ).map_err(|error| error.to_string())?;
        if plan.state == "blocked" || failed_effect {
            return Ok(CompletionGate::Blocked);
        }
        if !matches!(plan.state.as_str(), "not_required" | "succeeded") {
            return Ok(CompletionGate::WaitingForOperations);
        }
        if plan.postmortem_receipt_digest.is_none() {
            return Ok(CompletionGate::WaitingForPostmortem);
        }
        Ok(CompletionGate::Complete)
    }

    fn list_operation_ids(
        &self,
        project_id: &ProjectId,
        ticket_run_id: &TicketRunId,
    ) -> Result<Vec<OperationId>, String> {
        let mut statement = self.connection.prepare(
            "SELECT operation_id FROM operation_runs WHERE project_id=?1 AND ticket_run_id=?2 ORDER BY target_id",
        ).map_err(|error| error.to_string())?;
        statement
            .query_map(
                params![project_id.as_str(), ticket_run_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .map_err(|error| error.to_string())?
            .map(|row| {
                row.map_err(|error| error.to_string())
                    .and_then(OperationId::parse)
            })
            .collect()
    }
}

impl super::ConfigStore {
    pub fn operations(&mut self) -> Result<OperationsStore<'_>, String> {
        OperationsStore::new(&mut self.connection)
    }

    /// Read the immutable operation material behind a pending human approval.
    /// This is intentionally available through `&ConfigStore` for fresh human
    /// subject observers; it cannot create or accept an approval.
    pub fn operation_approval_intent(
        &self,
        operation_id: &OperationId,
    ) -> Result<Option<OperationEffectRequest>, String> {
        let row: Option<(String, String)> = self
            .connection
            .query_row(
                "SELECT request_json,state FROM operation_runs WHERE operation_id=?1",
                [operation_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let Some((json, state)) = row else {
            return Ok(None);
        };
        let request: OperationEffectRequest = crate::protocol::parse_unique(json.as_bytes())?;
        if state != "awaiting_approval" || request.approval_request_id.is_none() {
            return Ok(None);
        }
        if canonical_json(&request)? != json || &request.subject.operation_id != operation_id {
            return Err("stored operation approval intent is not canonically bound".into());
        }
        Ok(Some(request))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletionGate {
    Blocked,
    WaitingForOperations,
    WaitingForPostmortem,
    Complete,
}

fn enqueue_effect(
    tx: &rusqlite::Transaction<'_>,
    payload: &OperationEffectRequest,
    now: i64,
) -> Result<(), String> {
    let request_json = canonical_json(payload)?;
    let request_digest = digest(&request_json)?;
    let operation_id = payload.subject.operation_id.as_str();
    tx.execute(
        "INSERT INTO effects(operation_id,project_id,subject_type,subject_id,logical_key,kind,request_json,request_digest,expected_revision,status,attempt_count,next_attempt_at_unix,owner_generation,receipt_json,last_error,created_at_unix) VALUES (?1,?2,'ticket_run',?3,?4,'operation',?5,?6,?7,'pending',0,?8,NULL,NULL,NULL,?8) ON CONFLICT(operation_id) DO NOTHING",
        params![operation_id,payload.project_id.as_str(),payload.ticket_run_id.as_str(),format!("operator:{}",payload.target.id),request_json,request_digest.as_str(),payload.subject.ticket_revision.0,now],
    ).map_err(|error| error.to_string())?;
    let persisted: (String, String) = tx
        .query_row(
            "SELECT request_json,request_digest FROM effects WHERE operation_id=?1",
            [operation_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|error| error.to_string())?;
    if persisted.1 != request_digest.as_str() || persisted.0 != canonical_json(payload)? {
        return Err("operation ID is already bound to a different outbox intent".into());
    }
    Ok(())
}

fn enqueue_human_presentation(
    tx: &rusqlite::Transaction<'_>,
    request: &HumanRuntimeRequest,
    rex_view_id: &Digest,
    now: i64,
) -> Result<(), String> {
    let effect = HumanPresentationEffect {
        request: request.clone(),
        rex_view_id: rex_view_id.clone(),
    };
    let request_json = canonical_json(&effect)?;
    let request_digest = digest(&request_json)?;
    let operation_id = format!("present-{}", request.request_id.as_str());
    let logical_key = format!(
        "{}:{}:operation-approval:{}",
        request
            .subject
            .ticket_run_id
            .as_ref()
            .ok_or("operation approval is missing ticket run")?,
        request.subject.revision.0,
        request.subject.subject_id,
    );
    tx.execute(
        "INSERT INTO effects(operation_id,project_id,subject_type,subject_id,logical_key,kind,request_json,request_digest,expected_revision,status,attempt_count,next_attempt_at_unix,owner_generation,receipt_json,last_error,created_at_unix) VALUES (?1,?2,'ticket_run',?3,?4,'request_human_review',?5,?6,?7,'pending',0,?8,NULL,NULL,NULL,?8) ON CONFLICT(operation_id) DO NOTHING",
        params![operation_id,request.subject.project_id.as_str(),request.subject.ticket_run_id.as_ref().unwrap().as_str(),logical_key,request_json,request_digest.as_str(),request.subject.revision.0,now],
    ).map_err(|error| error.to_string())?;
    let stored: (String, String) = tx
        .query_row(
            "SELECT request_json,request_digest FROM effects WHERE operation_id=?1",
            [&operation_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|error| error.to_string())?;
    if stored.0 != request_json || stored.1 != request_digest.as_str() {
        return Err("human operation approval ID is already bound to another request".into());
    }
    Ok(())
}

fn dependencies_succeeded(
    tx: &rusqlite::Transaction<'_>,
    request: &OperationEffectRequest,
) -> Result<bool, String> {
    for dependency in &request.target.depends_on {
        let succeeded: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM operation_runs WHERE project_id=?1 AND ticket_run_id=?2 AND target_id=?3 AND state IN ('succeeded','skipped'))",
                params![request.project_id.as_str(),request.ticket_run_id.as_str(),dependency],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        if !succeeded {
            return Ok(false);
        }
    }
    Ok(true)
}

fn schedule_ready_targets(
    tx: &rusqlite::Transaction<'_>,
    project_id: &str,
    ticket_run_id: &str,
    now: i64,
) -> Result<(), String> {
    let rows = {
        let mut statement = tx
            .prepare(
                "SELECT request_json FROM operation_runs WHERE project_id=?1 AND ticket_run_id=?2 AND state='ready' ORDER BY target_id",
            )
            .map_err(|error| error.to_string())?;
        statement
            .query_map(params![project_id, ticket_run_id], |row| {
                row.get::<_, String>(0)
            })
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?
    };
    for request_json in rows {
        let request: OperationEffectRequest = serde_json::from_str(&request_json)
            .map_err(|error| format!("stored operation intent is invalid: {error}"))?;
        if dependencies_succeeded(tx, &request)? {
            enqueue_effect(tx, &request, now)?;
        }
    }
    Ok(())
}

fn stable_operation_id(
    project_id: &ProjectId,
    ticket_run_id: &TicketRunId,
    target: &OperationTarget,
    plan_digest: &Digest,
) -> Result<OperationId, String> {
    let bytes = serde_json::to_vec(&(
        project_id,
        ticket_run_id,
        &target.id,
        &target.action,
        &target.repository,
        &target.environment,
        plan_digest,
    ))
    .map_err(|error| error.to_string())?;
    OperationId::parse(format!("op-{:x}", Sha256::digest(bytes)))
}

fn requires_approval(
    config: &crate::config::Config,
    project_id: &ProjectId,
    target: &OperationTarget,
) -> Result<bool, String> {
    let repo = config
        .repositories
        .get(&target.repository)
        .ok_or_else(|| "operation repository is not configured".to_owned())?;
    let policy = repo
        .operations
        .as_ref()
        .ok_or_else(|| "repository operation policy is missing".to_owned())?;
    let project = config
        .projects
        .get(project_id)
        .ok_or_else(|| "operation project is not configured".to_owned())?;
    if !project.repositories.contains(&target.repository)
        || !policy
            .allowed_actions
            .iter()
            .any(|action| action == &target.action)
    {
        return Err("operation target exceeds project or repository action authority".into());
    }
    Ok(
        matches!(target.approval, crate::domain::types::ApprovalMode::Always)
            || policy
                .human_approval_environments
                .iter()
                .any(|env| env == &target.environment),
    )
}

fn validate_owner(tx: &rusqlite::Transaction<'_>, generation: u64) -> Result<(), String> {
    let active: Option<u64> = tx
        .query_row(
            "SELECT generation FROM controller_owners WHERE singleton=1 AND stopped_at_unix IS NULL",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    if active != Some(generation) {
        return Err("controller owner generation is stale".into());
    }
    Ok(())
}

fn update_state(
    connection: &mut Connection,
    owner_generation: u64,
    operation_id: &OperationId,
    from: &[&str],
    to: &str,
    now: i64,
) -> Result<(), String> {
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| error.to_string())?;
    validate_owner(&tx, owner_generation)?;
    update_state_in_transaction(&tx, operation_id, from, to, now)?;
    tx.commit().map_err(|error| error.to_string())
}

fn update_state_in_transaction(
    tx: &rusqlite::Transaction<'_>,
    operation_id: &OperationId,
    from: &[&str],
    to: &str,
    now: i64,
) -> Result<(), String> {
    let placeholders = from.iter().map(|_| "?").collect::<Vec<_>>().join(",");
    let sql = format!(
        "UPDATE operation_runs SET state=?2,updated_at_unix=?3 WHERE operation_id=?1 AND state IN ({placeholders})"
    );
    let mut values = vec![
        rusqlite::types::Value::Text(operation_id.to_string()),
        rusqlite::types::Value::Text(to.to_owned()),
        rusqlite::types::Value::Integer(now),
    ];
    values.extend(
        from.iter()
            .map(|value| rusqlite::types::Value::Text((*value).to_owned())),
    );
    let changed = tx
        .execute(&sql, rusqlite::params_from_iter(values))
        .map_err(|error| error.to_string())?;
    if changed != 1 {
        return Err("operation state transition is stale or invalid".into());
    }
    Ok(())
}

fn parse_state(value: &str) -> Result<DurableOperationState, String> {
    match value {
        "awaiting_approval" => Ok(DurableOperationState::AwaitingApproval),
        "ready" => Ok(DurableOperationState::Ready),
        "invoking" => Ok(DurableOperationState::Invoking),
        "unknown" => Ok(DurableOperationState::Unknown),
        "running" => Ok(DurableOperationState::Running),
        "succeeded" => Ok(DurableOperationState::Succeeded),
        "failed" => Ok(DurableOperationState::Failed),
        "skipped" => Ok(DurableOperationState::Skipped),
        _ => Err("stored operation state is invalid".into()),
    }
}

fn canonical_json<T: Serialize>(value: &T) -> Result<String, String> {
    let value = serde_json::to_value(value).map_err(|error| error.to_string())?;
    serde_json::to_string(&value).map_err(|error| error.to_string())
}

fn digest(value: &str) -> Result<Digest, String> {
    Digest::parse(format!("{:x}", Sha256::digest(value.as_bytes())))
}

fn unix_now() -> Result<i64, String> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_secs() as i64)
}
