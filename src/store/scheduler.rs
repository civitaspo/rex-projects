//! Durable Project scan state and TicketRun creation helpers.
//!
//! Network observations are obtained by the caller before these methods run.
//! Each page is committed with a cursor compare-and-swap so a crash can safely
//! replay a page without skipping tickets.

use rusqlite::{Connection, OptionalExtension, params};
use sha2::Digest as _;

use super::{
    ConfigStore, EffectIntent, content_digest, enum_string, insert_effect,
    validate_active_generation,
};
use crate::domain::ids::{
    AdapterId, Digest, OperationId, ProjectId, TicketId, TicketNamespace, TicketRunId,
};
use crate::domain::types::{Role, TicketStatus};
use crate::engine::orchestration::WorkNodeId;
use crate::engine::reducer::{Activity, Input, Phase, TicketRun, bind_effects, reduce};

/// Cursor and timing information for one Project/status scan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TicketScanCursor {
    pub cursor: Option<String>,
    pub generation: u64,
    pub page_count: u64,
    pub started_at_unix: i64,
    pub last_page_at_unix: Option<i64>,
    pub completed_at_unix: Option<i64>,
    pub next_due_at_unix: i64,
    pub last_served_sequence: u64,
}

/// A normalized ticket snapshot that has already passed adapter namespace and
/// configured Project scope checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedTicket {
    pub id: TicketId,
    pub revision: Option<String>,
    pub status: TicketStatus,
    pub title: String,
    pub labels: Vec<String>,
    pub created_at: Option<String>,
    pub observed_at_unix: i64,
}

/// Stable key separating Projects, namespaces, scopes, filters, and statuses.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TicketScanKey {
    pub project_id: ProjectId,
    pub adapter_id: AdapterId,
    pub namespace: TicketNamespace,
    pub scope_digest: Digest,
    pub filter_digest: Digest,
    pub status: TicketStatus,
}

/// Ticket candidate durable in the local scan ledger, before it is claimed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingTicketObservation {
    pub ticket_id: TicketId,
    pub revision: Option<String>,
    pub status: TicketStatus,
    pub title: String,
    pub labels: Vec<String>,
    pub observed_at_unix: i64,
}

/// A stable goal proposal has one durable external create operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GoalTicketReservation {
    pub request_key: String,
    pub request_digest: String,
    pub operation_id: OperationId,
    pub reused: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GoalTicketCandidateRecord {
    pub namespace: TicketNamespace,
    pub ticket_id: TicketId,
    pub match_basis: crate::engine::factory_runtime::GoalTicketMatchBasis,
    pub created_at: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GoalTicketCandidateReceipt {
    pub canonical_namespace: TicketNamespace,
    pub canonical_ticket_id: TicketId,
    pub duplicate_ticket_ids: Vec<TicketId>,
}

/// Immutable external ticket identity and revision for one host-owned TicketRun effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TicketRunStatusTarget {
    pub namespace: TicketNamespace,
    pub ticket_id: TicketId,
    pub external_revision: Option<String>,
}

/// One nonterminal TicketRun snapshot for bounded host transition processing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveTicketRun {
    pub project_id: ProjectId,
    pub ticket_run_id: TicketRunId,
    pub namespace: TicketNamespace,
    pub ticket_id: TicketId,
    pub revision: u64,
    pub phase: Phase,
    pub activity: Activity,
    pub external_status: TicketStatus,
    pub required_review_revision: Option<u64>,
    pub project_epoch: u64,
    pub recipe_id: Option<String>,
}

/// A role session with at least one unassigned wake input. This is a scheduling
/// hint only: `prepare_agent_launch` must recheck eligibility and assign the
/// inputs transactionally before it starts any provider process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingRoleWakeSession {
    pub project_id: ProjectId,
    pub role_session_id: String,
    pub role: Role,
    pub ticket_run_id: Option<TicketRunId>,
    /// Set only for the canonical per-node Worker session.
    pub work_node_id: Option<WorkNodeId>,
    pub highest_priority: i64,
    pub oldest_created_at_unix: i64,
    pub pending_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupervisorDispatchAuthority {
    pub evidence_id: String,
    pub priority: i32,
    pub expected_external_revision: String,
}

/// Receipt for a durable human instruction routed to one exact Coordinator run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoordinatorInstructionReceipt {
    pub wake_input_id: u64,
    pub supervisor_wake_input_id: u64,
    pub project_id: ProjectId,
    pub ticket_run_id: TicketRunId,
    pub revision: u64,
    pub body_digest: Digest,
    pub replayed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunnableProject {
    pub record: super::ProjectRecord,
    pub project_epoch: u64,
}

/// Install the Project scheduling and goal creation ledger after schema v8.
pub(super) fn migrate_v9(connection: &Connection) -> Result<(), String> {
    let previous_version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| error.to_string())?;
    if previous_version != 8 {
        return Err(format!(
            "schema v9 migration requires schema v8, found {previous_version}"
        ));
    }
    let tx = connection
        .unchecked_transaction()
        .map_err(|error| error.to_string())?;
    tx.execute_batch(
        "CREATE TABLE ticket_scan_cursors (
            project_id TEXT NOT NULL REFERENCES projects(project_id),
            adapter_id TEXT NOT NULL,
            namespace TEXT NOT NULL,
            scope_digest TEXT NOT NULL CHECK(length(scope_digest)=64),
            filter_digest TEXT NOT NULL CHECK(length(filter_digest)=64),
            status TEXT NOT NULL CHECK(status IN ('triage','backlog','ready')),
            cursor TEXT,
            scan_generation INTEGER NOT NULL CHECK(scan_generation >= 1),
            page_count INTEGER NOT NULL CHECK(page_count >= 1),
            started_at_unix INTEGER NOT NULL,
            last_page_at_unix INTEGER,
            completed_at_unix INTEGER,
            next_due_at_unix INTEGER NOT NULL,
            last_served_sequence INTEGER NOT NULL DEFAULT 0 CHECK(last_served_sequence >= 0),
            PRIMARY KEY(project_id,adapter_id,namespace,scope_digest,filter_digest,status)
        );
        CREATE TABLE ticket_observations (
            project_id TEXT NOT NULL REFERENCES projects(project_id),
            adapter_id TEXT NOT NULL,
            namespace TEXT NOT NULL,
            ticket_id TEXT NOT NULL,
            scope_digest TEXT NOT NULL CHECK(length(scope_digest)=64),
            filter_digest TEXT NOT NULL CHECK(length(filter_digest)=64),
            external_revision TEXT,
            status TEXT NOT NULL CHECK(status IN ('triage','backlog','ready','in_progress','in_review','done','canceled')),
            title TEXT NOT NULL CHECK(length(title) BETWEEN 1 AND 512),
            labels_json TEXT NOT NULL CHECK(length(labels_json) <= 65536),
            created_at TEXT,
            last_seen_at_unix INTEGER NOT NULL,
            scan_generation INTEGER NOT NULL CHECK(scan_generation >= 1),
            ticket_run_id TEXT REFERENCES ticket_runs(ticket_run_id),
            dispatch_state TEXT NOT NULL DEFAULT 'pending' CHECK(dispatch_state IN ('pending','claimed','ignored','human','started')),
            PRIMARY KEY(project_id,adapter_id,namespace,ticket_id)
        );
        CREATE INDEX ticket_observations_pending ON ticket_observations(project_id,dispatch_state,status,last_seen_at_unix);
        CREATE TABLE scheduler_audit (
            audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id TEXT NOT NULL REFERENCES projects(project_id),
            subject_type TEXT NOT NULL,
            subject_id TEXT NOT NULL,
            action TEXT NOT NULL,
            detail TEXT NOT NULL CHECK(length(detail) <= 4096),
            created_at_unix INTEGER NOT NULL
        );
        CREATE TABLE ticket_run_context (
            ticket_run_id TEXT PRIMARY KEY REFERENCES ticket_runs(ticket_run_id),
            project_id TEXT NOT NULL REFERENCES projects(project_id),
            project_epoch INTEGER NOT NULL CHECK(project_epoch >= 1),
            recipe_id TEXT,
            goal_revision INTEGER NOT NULL CHECK(goal_revision >= 0),
            created_at_unix INTEGER NOT NULL
        );
        CREATE TABLE ticket_scan_sequence (
            singleton INTEGER PRIMARY KEY CHECK(singleton=1),
            sequence INTEGER NOT NULL CHECK(sequence >= 0)
        );
        INSERT INTO ticket_scan_sequence(singleton,sequence) VALUES (1,0);
        CREATE TABLE goal_runtime (
            project_id TEXT PRIMARY KEY REFERENCES projects(project_id),
            goal_revision INTEGER NOT NULL CHECK(goal_revision >= 1),
            state TEXT NOT NULL CHECK(state IN ('active','awaiting_human','complete','changes_requested')),
            completion_request_id TEXT,
            completion_subject_digest TEXT,
            updated_at_unix INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS agent_wake_context (
            agent_run_id TEXT PRIMARY KEY REFERENCES agent_runs(agent_run_id),
            context_json TEXT NOT NULL CHECK(length(context_json) <= 1048576),
            context_digest TEXT NOT NULL CHECK(length(context_digest)=64),
            assigned_at_unix INTEGER NOT NULL
        );
        CREATE TABLE goal_ticket_requests (
            project_id TEXT NOT NULL REFERENCES projects(project_id),
            goal_revision INTEGER NOT NULL CHECK(goal_revision >= 1),
            request_key TEXT NOT NULL,
            request_digest TEXT NOT NULL CHECK(length(request_digest)=64),
            operation_id TEXT NOT NULL UNIQUE,
            proposal_json TEXT NOT NULL CHECK(length(proposal_json) <= 131072),
            state TEXT NOT NULL CHECK(state IN ('reserved','created','duplicate_pending','duplicate_resolved','ambiguous','rejected')),
            canonical_namespace TEXT,
            canonical_ticket_id TEXT,
            created_at_unix INTEGER NOT NULL,
            updated_at_unix INTEGER NOT NULL,
            PRIMARY KEY(project_id,goal_revision,request_key)
        );
        CREATE INDEX goal_ticket_budget ON goal_ticket_requests(project_id,goal_revision,state);
        CREATE TABLE goal_ticket_candidates (
            project_id TEXT NOT NULL,
            goal_revision INTEGER NOT NULL,
            request_key TEXT NOT NULL,
            namespace TEXT NOT NULL,
            ticket_id TEXT NOT NULL,
            match_basis TEXT NOT NULL CHECK(match_basis IN ('operation_id','stable_external_key')),
            created_at TEXT,
            state TEXT NOT NULL CHECK(state IN ('candidate','canonical','duplicate_pending','duplicate_resolved','ambiguous')),
            observed_at_unix INTEGER NOT NULL,
            PRIMARY KEY(project_id,goal_revision,request_key,namespace,ticket_id),
            FOREIGN KEY(project_id,goal_revision,request_key) REFERENCES goal_ticket_requests(project_id,goal_revision,request_key)
        );
        CREATE TABLE effect_progress (
            operation_id TEXT PRIMARY KEY REFERENCES effects(operation_id) ON DELETE CASCADE,
            request_digest TEXT NOT NULL CHECK(length(request_digest)=64),
            progress_json TEXT NOT NULL CHECK(length(progress_json) <= 262144),
            updated_at_unix INTEGER NOT NULL
        );
        INSERT INTO schema_migrations(version,applied_at_unix) VALUES (9,unixepoch());
        PRAGMA user_version=9;"
    ).map_err(|error| error.to_string())?;
    tx.commit().map_err(|error| error.to_string())
}

impl TicketScanKey {
    pub fn for_project(
        project_id: &ProjectId,
        adapter_id: &AdapterId,
        namespace: &TicketNamespace,
        project: &crate::config::ProjectConfig,
        status: TicketStatus,
    ) -> Result<Self, String> {
        if project.ticket_adapter != *adapter_id {
            return Err("ticket scan adapter does not match Project configuration".into());
        }
        let scope_json =
            serde_json::to_string(&project.ticket_scope).map_err(|error| error.to_string())?;
        let filter_json = serde_json::to_string(&serde_json::json!({
            "status": status_key(status),
            "page_size": 100,
        }))
        .map_err(|error| error.to_string())?;
        Ok(Self {
            project_id: project_id.clone(),
            adapter_id: adapter_id.clone(),
            namespace: namespace.clone(),
            scope_digest: Digest::parse(content_digest(&scope_json))?,
            filter_digest: Digest::parse(content_digest(&filter_json))?,
            status,
        })
    }

    fn validate(&self) -> Result<(), String> {
        for value in [self.scope_digest.as_str(), self.filter_digest.as_str()] {
            Digest::parse(value.to_owned())?;
        }
        Ok(())
    }
}

impl ConfigStore {
    pub fn coordinator_instruction_scope(
        &self,
        owner_generation: u64,
        ticket_run_id: &TicketRunId,
    ) -> Result<(ProjectId, TicketNamespace, TicketId), String> {
        let tx = self
            .connection
            .unchecked_transaction()
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let row: Option<(String, String, String)> = tx.query_row(
            "SELECT project_id,namespace,ticket_id FROM ticket_runs WHERE ticket_run_id=?1 AND internal_phase NOT IN ('done','canceled')",
            [ticket_run_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).optional().map_err(|error| error.to_string())?;
        let Some((project, namespace, ticket)) = row else {
            return Err("instruction target TicketRun does not exist or is terminal".into());
        };
        Ok((
            ProjectId::parse(project)?,
            TicketNamespace::parse(namespace)?,
            TicketId::parse(ticket)?,
        ))
    }

    pub fn queue_due_supervisor_reviews(
        &mut self,
        owner_generation: u64,
        projects: &[ProjectId],
        now_unix: i64,
        interval_seconds: i64,
    ) -> Result<usize, String> {
        if interval_seconds <= 0 {
            return Err("Supervisor review interval must be positive".into());
        }
        let mut queued = 0;
        for project in projects {
            let tx = self
                .connection
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|error| error.to_string())?;
            validate_active_generation(&tx, owner_generation)?;
            let row: Option<(u64, String, String, i64)> = tx.query_row(
                "SELECT p.goal_revision,p.desired_lifecycle,r.observed_lifecycle,r.next_due_at_unix FROM projects p JOIN project_runtimes r USING(project_id) WHERE p.project_id=?1",
                [project.as_str()],
                |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
            ).optional().map_err(|error| error.to_string())?;
            let Some((goal_revision, desired, observed, next_due)) = row else {
                tx.commit().map_err(|error| error.to_string())?;
                continue;
            };
            if desired != "running" || observed != "running" || next_due > now_unix {
                tx.commit().map_err(|error| error.to_string())?;
                continue;
            }
            let role_session = format!("project:{}:supervisor", project.as_str());
            let active: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM agent_runs WHERE role_session_id=?1 AND state IN ('launch_pending','running','unknown'))",
                [&role_session],
                |row| row.get(0),
            ).map_err(|error| error.to_string())?;
            let pending: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM role_wake_inputs WHERE role_session_id=?1 AND lifecycle='pending')",
                [&role_session],
                |row| row.get(0),
            ).map_err(|error| error.to_string())?;
            if active || pending {
                tx.commit().map_err(|error| error.to_string())?;
                continue;
            }
            let due = now_unix.saturating_add(interval_seconds);
            let payload = serde_json::json!({
                "schema_version": 1,
                "kind": "periodic_supervisor_review",
                "goal_revision": goal_revision,
                "observed_at_unix": now_unix,
            })
            .to_string();
            let inserted = tx.execute(
                "INSERT INTO role_wake_inputs(project_id,role_session_id,source_type,source_id,source_revision,priority,payload_json,lifecycle,created_at_unix) VALUES (?1,?2,'periodic_supervisor_review','project-review',?3,10,?4,'pending',?5)",
                params![project.as_str(),role_session,now_unix.max(1) as u64,payload,now_unix],
            ).map_err(|error| error.to_string())?;
            if inserted == 1 {
                queued += 1;
            }
            tx.execute(
                "UPDATE project_runtimes SET next_due_at_unix=?1 WHERE project_id=?2 AND next_due_at_unix<=?3",
                params![due,project.as_str(),now_unix],
            ).map_err(|error| error.to_string())?;
            tx.commit().map_err(|error| error.to_string())?;
        }
        Ok(queued)
    }

    pub fn enqueue_supervisor_ticket_observation(
        &mut self,
        owner_generation: u64,
        key: &TicketScanKey,
        ticket: &PendingTicketObservation,
        now_unix: i64,
    ) -> Result<bool, String> {
        key.validate()?;
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let project_state: Option<(String,String,u64)> = tx.query_row(
            "SELECT p.desired_lifecycle,r.observed_lifecycle,p.goal_revision FROM projects p JOIN project_runtimes r USING(project_id) WHERE p.project_id=?1",
            [key.project_id.as_str()],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
        ).optional().map_err(|error| error.to_string())?;
        let Some((desired, observed, goal_revision)) = project_state else {
            return Err("Supervisor observation references an unknown Project".into());
        };
        if desired != "running" || observed != "running" {
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(false);
        }
        let role_session = format!("project:{}:supervisor", key.project_id.as_str());
        let payload = serde_json::json!({
            "schema_version": 1,
            "kind": "ticket_observation",
            "ticket_namespace": key.namespace.as_str(),
            "ticket_id": ticket.ticket_id.as_str(),
            "status": status_key(ticket.status),
            "title": ticket.title,
            "labels": ticket.labels,
            "external_revision": ticket.revision,
            "goal_revision": goal_revision,
        })
        .to_string();
        let source_id = format!(
            "{}:{}:{}",
            key.namespace.as_str(),
            ticket.ticket_id.as_str(),
            status_key(ticket.status)
        );
        let revision_digest = content_digest(&payload);
        let source_revision =
            u64::from_str_radix(&revision_digest[..16], 16).map_err(|error| error.to_string())?;
        let inserted = tx.execute(
            "INSERT INTO role_wake_inputs(project_id,role_session_id,source_type,source_id,source_revision,priority,payload_json,lifecycle,created_at_unix) VALUES (?1,?2,'ticket_observation',?3,?4,30,?5,'pending',?6) ON CONFLICT(role_session_id,source_type,source_id,source_revision) DO NOTHING",
            params![key.project_id.as_str(),role_session,source_id,source_revision.max(1),payload,now_unix],
        ).map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(inserted == 1)
    }

    pub fn goal_ticket_reservation_count(
        &self,
        owner_generation: u64,
        project_id: &ProjectId,
        goal_revision: u64,
    ) -> Result<usize, String> {
        let active_generation: Option<u64> = self.connection.query_row(
            "SELECT generation FROM controller_owners WHERE singleton=1 AND stopped_at_unix IS NULL",
            [],
            |row| row.get(0),
        ).optional().map_err(|error| error.to_string())?;
        if active_generation != Some(owner_generation) {
            return Err("controller generation is not active".into());
        }
        self.connection
            .query_row(
                "SELECT COUNT(*) FROM goal_ticket_requests WHERE project_id=?1 AND goal_revision=?2",
                params![project_id.as_str(), goal_revision],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())
    }

    /// Return the digest for an existing Goal ticket reservation. This is used
    /// before admission limits on replay so a result whose reservation already
    /// committed can be acknowledged after a crash without consuming capacity a
    /// second time.
    pub fn goal_ticket_reservation_digest(
        &self,
        owner_generation: u64,
        project_id: &ProjectId,
        goal_revision: u64,
        request_key: &str,
    ) -> Result<Option<String>, String> {
        let active_generation: Option<u64> = self.connection.query_row(
            "SELECT generation FROM controller_owners WHERE singleton=1 AND stopped_at_unix IS NULL",
            [],
            |row| row.get(0),
        ).optional().map_err(|error| error.to_string())?;
        if active_generation != Some(owner_generation) {
            return Err("controller generation is not active".into());
        }
        self.connection.query_row(
            "SELECT request_digest FROM goal_ticket_requests WHERE project_id=?1 AND goal_revision=?2 AND request_key=?3",
            params![project_id.as_str(), goal_revision, request_key],
            |row| row.get(0),
        ).optional().map_err(|error| error.to_string())
    }

    /// Read a bounded, stable page of nonterminal TicketRuns for host-side
    /// receipt consumption. This is a hint; transition commits still CAS the
    /// exact revision and validate the owner generation.
    pub fn active_ticket_runs(
        &self,
        owner_generation: u64,
        limit: usize,
    ) -> Result<Vec<ActiveTicketRun>, String> {
        if limit == 0 || limit > 256 {
            return Err("active TicketRun query limit must be between 1 and 256".into());
        }
        let active_owner: Option<u64> = self
            .connection
            .query_row(
                "SELECT generation FROM controller_owners WHERE singleton=1 AND stopped_at_unix IS NULL",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if active_owner != Some(owner_generation) {
            return Err("controller owner generation is stale".into());
        }
        let mut statement = self.connection.prepare(
            "SELECT t.project_id,t.ticket_run_id,t.namespace,t.ticket_id,t.revision,t.internal_phase,t.activity,t.external_status,t.required_review_revision,c.project_epoch,c.recipe_id FROM ticket_runs t LEFT JOIN ticket_run_context c USING(ticket_run_id) WHERE t.internal_phase NOT IN ('done','canceled') ORDER BY t.project_id,t.ticket_run_id LIMIT ?1",
        ).map_err(|error| error.to_string())?;
        let rows = statement
            .query_map([limit as u64], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, u64>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, Option<u64>>(8)?,
                    row.get::<_, u64>(9)?,
                    row.get::<_, Option<String>>(10)?,
                ))
            })
            .map_err(|error| error.to_string())?;
        rows.map(|row| {
            let (
                project,
                run,
                namespace,
                ticket,
                revision,
                phase,
                activity,
                external_status,
                required_review_revision,
                project_epoch,
                recipe_id,
            ) = row.map_err(|error| error.to_string())?;
            Ok(ActiveTicketRun {
                project_id: ProjectId::parse(project)?,
                ticket_run_id: TicketRunId::parse(run)?,
                namespace: TicketNamespace::parse(namespace)?,
                ticket_id: TicketId::parse(ticket)?,
                revision,
                phase: serde_json::from_str(&format!("\"{phase}\""))
                    .map_err(|error| format!("stored TicketRun phase is invalid: {error}"))?,
                activity: serde_json::from_str(&format!("\"{activity}\""))
                    .map_err(|error| format!("stored TicketRun activity is invalid: {error}"))?,
                external_status: serde_json::from_str(&format!("\"{external_status}\""))
                    .map_err(|error| format!("stored TicketRun status is invalid: {error}"))?,
                required_review_revision,
                project_epoch,
                recipe_id,
            })
        })
        .collect()
    }

    /// Return the active Rex view currently bound to a TicketRun.
    pub fn active_ticket_view_id(
        &self,
        owner_generation: u64,
        project_id: &ProjectId,
        ticket_run_id: &TicketRunId,
    ) -> Result<Option<Digest>, String> {
        let active_owner: Option<u64> = self
            .connection
            .query_row(
                "SELECT generation FROM controller_owners WHERE singleton=1 AND stopped_at_unix IS NULL",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if active_owner != Some(owner_generation) {
            return Err("controller owner generation is stale".into());
        }
        let view_id: Option<String> = self
            .connection
            .query_row(
                "SELECT v.view_id FROM rex_views v JOIN ticket_runs t ON t.project_id=v.project_id AND t.namespace=v.ticket_namespace AND t.ticket_id=v.ticket_id WHERE t.project_id=?1 AND t.ticket_run_id=?2 AND v.view_kind='ticket' AND v.lifecycle='active' ORDER BY v.view_epoch DESC LIMIT 1",
                params![project_id.as_str(), ticket_run_id.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        view_id.map(Digest::parse).transpose()
    }

    /// Return bounded role sessions that can be considered for another finite
    /// Agent turn. Active or unknown AgentRuns suppress duplicate scheduling;
    /// a future transactional launch-preparation call still owns the claim.
    pub fn pending_role_wake_sessions(
        &self,
        owner_generation: u64,
        limit: usize,
    ) -> Result<Vec<PendingRoleWakeSession>, String> {
        if limit == 0 || limit > 256 {
            return Err("pending role wake query limit must be between 1 and 256".into());
        }
        let owner_is_active: bool = self
            .connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM controller_owners WHERE generation=?1 AND stopped_at_unix IS NULL)",
                [owner_generation],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        if !owner_is_active {
            return Err("controller generation is not active".into());
        }
        let mut statement = self.connection.prepare(
            "SELECT w.project_id,w.role_session_id,MAX(w.priority),MIN(w.created_at_unix),COUNT(*) \
             FROM role_wake_inputs w \
             JOIN projects p USING(project_id) \
             JOIN project_runtimes r USING(project_id) \
             WHERE w.lifecycle='pending' AND p.desired_lifecycle='running' \
               AND r.observed_lifecycle='running' AND r.controller_generation=?1 \
               AND NOT EXISTS(SELECT 1 FROM agent_runs a WHERE a.role_session_id=w.role_session_id \
                 AND a.state IN ('launch_pending','running','unknown')) \
             GROUP BY w.project_id,w.role_session_id \
             ORDER BY MAX(w.priority) DESC,MIN(w.created_at_unix),w.project_id,w.role_session_id \
             LIMIT ?2",
        ).map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(params![owner_generation, limit as u64], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, u64>(4)?,
                ))
            })
            .map_err(|error| error.to_string())?;
        rows.map(|row| {
            let (project, role_session_id, highest_priority, oldest_created_at_unix, pending_count) =
                row.map_err(|error| error.to_string())?;
            let (role, ticket_run_id, work_node_id) = parse_role_session_id(&role_session_id)?;
            Ok(PendingRoleWakeSession {
                project_id: ProjectId::parse(project)?,
                role_session_id,
                role,
                ticket_run_id,
                work_node_id,
                highest_priority,
                oldest_created_at_unix,
                pending_count,
            })
        })
        .collect()
    }

    /// Verify a host status publication against the current persisted TicketRun state.
    /// External adapters call this immediately before mutation and again when reconciling.
    pub fn validate_ticket_status_publication(
        &self,
        owner_generation: u64,
        payload: &crate::engine::ticket_effects::PublishTicketStatus,
    ) -> Result<(), String> {
        payload.validate()?;
        let active_owner: Option<u64> = self
            .connection
            .query_row(
                "SELECT generation FROM controller_owners WHERE singleton=1 AND stopped_at_unix IS NULL",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if active_owner != Some(owner_generation) {
            return Err("controller owner generation is stale".into());
        }
        let stored: Option<(String, String, String, u64, Option<String>)> = self
            .connection
            .query_row(
                "SELECT namespace,ticket_id,internal_phase,revision,external_revision FROM ticket_runs WHERE ticket_run_id=?1 AND project_id=?2",
                params![payload.ticket_run_id.as_str(), payload.project_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let Some((namespace, ticket_id, phase, revision, external_revision)) = stored else {
            return Err("ticket status effect references an unknown TicketRun".into());
        };
        if namespace != payload.namespace.as_str()
            || ticket_id != payload.ticket_id.as_str()
            || revision != payload.ticket_run_revision
            || external_revision != payload.expected_external_revision
        {
            return Err("ticket status effect is stale or has mismatched scope".into());
        }
        let status: String = self
            .connection
            .query_row(
                "SELECT external_status FROM ticket_runs WHERE ticket_run_id=?1",
                [payload.ticket_run_id.as_str()],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        if super::parse_ticket_status(&status)? != payload.desired_status {
            return Err("ticket status effect does not match persisted TicketRun status".into());
        }
        let phase_allows_status = match payload.desired_status {
            TicketStatus::InReview => phase == "waiting_human",
            TicketStatus::Done => phase == "done",
            TicketStatus::Canceled => phase == "canceled",
            TicketStatus::InProgress => {
                !matches!(phase.as_str(), "done" | "canceled" | "waiting_human")
            }
            TicketStatus::Triage | TicketStatus::Backlog | TicketStatus::Ready => false,
        };
        if !phase_allows_status {
            return Err("ticket status is not authorized by the persisted TicketRun phase".into());
        }
        Ok(())
    }

    /// Produce the opaque final-completion proof only after the persisted operations gate and
    /// Postmortem publication receipts both validate for this exact TicketRun revision.
    pub fn ticket_completion_proof(
        &mut self,
        owner_generation: u64,
        project_id: &ProjectId,
        ticket_run_id: &TicketRunId,
        expected_revision: u64,
    ) -> Result<Option<crate::engine::ticket_effects::TicketCompletionProof>, String> {
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let run: Option<(String, u64)> = tx
            .query_row(
                "SELECT internal_phase,revision FROM ticket_runs WHERE ticket_run_id=?1 AND project_id=?2",
                params![ticket_run_id.as_str(), project_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let Some(completed_revision) = expected_revision.checked_add(1) else {
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(None);
        };
        if !matches!(run, Some((ref phase, revision)) if (phase == "completing" && revision == expected_revision) || (phase == "done" && revision == completed_revision))
        {
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(None);
        }
        let plan: Option<(String, Option<String>)> = tx
            .query_row(
                "SELECT plan_digest,postmortem_receipt_digest FROM operation_plans WHERE project_id=?1 AND ticket_run_id=?2 AND state IN ('not_required','succeeded')",
                params![project_id.as_str(), ticket_run_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let Some((plan_digest, Some(postmortem_digest))) = plan else {
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(None);
        };
        let operation_receipt: Option<String> = tx
            .query_row(
                "SELECT receipt_digest FROM operation_postmortems WHERE project_id=?1 AND ticket_run_id=?2",
                params![project_id.as_str(), ticket_run_id.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if operation_receipt.as_deref() != Some(postmortem_digest.as_str()) {
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(None);
        }
        let publication: Option<(String, String, String)> = tx
            .query_row(
                "SELECT operation_id,manifest_digest,manifest_json FROM knowledge_publications WHERE project_id=?1 AND ticket_run_id=?2 AND state='published'",
                params![project_id.as_str(), ticket_run_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let Some((knowledge_operation_id, manifest_digest, manifest_json)) = publication else {
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(None);
        };
        let manifest: crate::knowledge::PublicationManifest =
            crate::protocol::parse_unique(manifest_json.as_bytes())
                .map_err(|error| format!("stored Postmortem manifest is invalid: {error}"))?;
        if manifest.operation_id.as_str() != knowledge_operation_id
            || manifest.project_id.as_str() != project_id.as_str()
            || manifest.ticket_run_id.as_str() != ticket_run_id.as_str()
            || serde_json::to_string(&manifest).map_err(|error| error.to_string())? != manifest_json
        {
            return Err("stored Postmortem manifest identity or encoding is invalid".into());
        }
        let verified_manifest_digest = Digest::parse(super::content_digest(&manifest_json))?;
        let manifest_digest = Digest::parse(manifest_digest)?;
        if verified_manifest_digest != manifest_digest {
            return Err("stored Postmortem manifest digest is invalid".into());
        }
        let proof =
            crate::engine::ticket_effects::TicketCompletionProof::from_validated_host_receipts(
                project_id.clone(),
                ticket_run_id.clone(),
                expected_revision,
                Digest::parse(plan_digest)?,
                Digest::parse(postmortem_digest)?,
                knowledge_operation_id,
                manifest_digest,
            );
        tx.commit().map_err(|error| error.to_string())?;
        Ok(Some(proof))
    }

    /// Read the external ticket coordinates pinned when this TicketRun was created.
    /// Completion handlers use it to build the next reducer-owned publication intent.
    pub fn ticket_run_status_target(
        &self,
        owner_generation: u64,
        project_id: &ProjectId,
        ticket_run_id: &TicketRunId,
        expected_revision: u64,
    ) -> Result<TicketRunStatusTarget, String> {
        let active_owner: Option<u64> = self.connection.query_row(
            "SELECT generation FROM controller_owners WHERE singleton=1 AND stopped_at_unix IS NULL",
            [],
            |row| row.get(0),
        ).optional().map_err(|error| error.to_string())?;
        if active_owner != Some(owner_generation) {
            return Err("controller owner generation is stale".into());
        }
        let row: Option<(String, String, String, u64, Option<String>)> = self.connection.query_row(
            "SELECT namespace,ticket_id,internal_phase,revision,external_revision FROM ticket_runs WHERE ticket_run_id=?1 AND project_id=?2",
            params![ticket_run_id.as_str(), project_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        ).optional().map_err(|error| error.to_string())?;
        let Some((namespace, ticket_id, phase, revision, external_revision)) = row else {
            return Err("TicketRun completion references an unknown subject".into());
        };
        let completed_revision = expected_revision
            .checked_add(1)
            .ok_or_else(|| "TicketRun revision is exhausted".to_owned())?;
        if !((phase == "completing" && revision == expected_revision)
            || (phase == "done" && revision == completed_revision))
        {
            return Err("TicketRun completion effect is stale".into());
        }
        Ok(TicketRunStatusTarget {
            namespace: TicketNamespace::parse(namespace)?,
            ticket_id: TicketId::parse(ticket_id)?,
            external_revision,
        })
    }

    /// Enqueue a dashboard instruction as a high-priority Coordinator wake. The request is
    /// bound to an exact TicketRun revision so stale dashboard views cannot redirect input.
    #[allow(clippy::too_many_arguments)]
    pub fn enqueue_coordinator_instruction(
        &mut self,
        owner_generation: u64,
        project_id: &ProjectId,
        ticket_run_id: &TicketRunId,
        namespace: &TicketNamespace,
        ticket_id: &TicketId,
        expected_revision: u64,
        request_id: &str,
        body: &str,
        now_unix: i64,
    ) -> Result<CoordinatorInstructionReceipt, String> {
        if request_id.is_empty()
            || request_id.len() > 128
            || !request_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
        {
            return Err("invalid dashboard request ID".into());
        }
        if body.is_empty() || body.len() > 64 * 1024 || body.contains('\0') {
            return Err(
                "Coordinator instruction must be nonempty UTF-8 text no larger than 64 KiB".into(),
            );
        }
        let body_digest = Digest::parse(content_digest(body))?;
        let role_session_id = format!("ticket_run:{}:coordinator", ticket_run_id.as_str());
        let payload = serde_json::json!({
            "schema_version": 1,
            "request_id": request_id,
            "project_id": project_id.as_str(),
            "ticket_run_id": ticket_run_id.as_str(),
            "namespace": namespace.as_str(),
            "ticket_id": ticket_id.as_str(),
            "expected_revision": expected_revision,
            "body": body,
            "body_digest": body_digest.as_str(),
        });
        let payload_json = serde_json::to_string(&payload).map_err(|error| error.to_string())?;

        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let run: Option<(String, String, u64, String)> = tx
            .query_row(
                "SELECT namespace,ticket_id,revision,internal_phase FROM ticket_runs WHERE ticket_run_id=?1 AND project_id=?2",
                params![ticket_run_id.as_str(), project_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let Some((stored_namespace, stored_ticket, revision, phase)) = run else {
            return Err("Coordinator instruction target TicketRun does not exist".into());
        };
        if stored_namespace != namespace.as_str() || stored_ticket != ticket_id.as_str() {
            return Err("Coordinator instruction target scope does not match the TicketRun".into());
        }
        let supervisor_role_session = format!("project:{}:supervisor", project_id.as_str());
        let supervisor_payload = serde_json::json!({
            "schema_version": 1,
            "kind": "human_instruction_notice",
            "ticket_run_id": ticket_run_id.as_str(),
            "revision": expected_revision,
            "request_id": request_id,
            "body_digest": body_digest.as_str(),
        });
        let supervisor_payload_json = supervisor_payload.to_string();

        let existing: Option<(u64, String)> = tx
            .query_row(
                "SELECT wake_input_id,payload_json FROM role_wake_inputs WHERE project_id=?1 AND role_session_id=?2 AND source_type='human_instruction' AND source_id=?3 AND source_revision=?4",
                params![project_id.as_str(), role_session_id, request_id, expected_revision],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if let Some((wake_input_id, stored_payload)) = existing {
            if stored_payload != payload_json {
                return Err(
                    "dashboard request ID was already used for different instruction content"
                        .into(),
                );
            }
            let supervisor_role_session = format!("project:{}:supervisor", project_id.as_str());
            let supervisor_row: (u64, String) = tx.query_row(
                "SELECT wake_input_id,payload_json FROM role_wake_inputs WHERE project_id=?1 AND role_session_id=?2 AND source_type='human_instruction_notice' AND source_id=?3 AND source_revision=?4",
                params![project_id.as_str(), supervisor_role_session, request_id, expected_revision],
                |row| Ok((row.get(0)?, row.get(1)?)),
            ).optional().map_err(|error| error.to_string())?
                .ok_or("replayed instruction has no matching Supervisor notification")?;
            if supervisor_row.1 != supervisor_payload_json {
                return Err(
                    "replayed instruction has a conflicting Supervisor notification".into(),
                );
            }
            let supervisor_wake_input_id = supervisor_row.0;
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(CoordinatorInstructionReceipt {
                wake_input_id,
                supervisor_wake_input_id,
                project_id: project_id.clone(),
                ticket_run_id: ticket_run_id.clone(),
                revision: expected_revision,
                body_digest,
                replayed: true,
            });
        }
        if revision != expected_revision || matches!(phase.as_str(), "done" | "canceled") {
            return Err("Coordinator instruction is stale or the TicketRun is terminal".into());
        }
        tx.execute(
            "INSERT INTO role_wake_inputs(project_id,role_session_id,source_type,source_id,source_revision,priority,payload_json,lifecycle,created_at_unix) VALUES (?1,?2,'human_instruction',?3,?4,100,?5,'pending',?6)",
            params![project_id.as_str(), role_session_id, request_id, expected_revision, payload_json, now_unix],
        )
        .map_err(|error| error.to_string())?;
        let wake_input_id = tx.last_insert_rowid() as u64;
        tx.execute(
            "INSERT INTO role_wake_inputs(project_id,role_session_id,source_type,source_id,source_revision,priority,payload_json,lifecycle,created_at_unix) VALUES (?1,?2,'human_instruction_notice',?3,?4,80,?5,'pending',?6)",
            params![project_id.as_str(), supervisor_role_session, request_id, expected_revision, supervisor_payload_json, now_unix],
        ).map_err(|error| error.to_string())?;
        let supervisor_wake_input_id = tx.last_insert_rowid() as u64;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(CoordinatorInstructionReceipt {
            wake_input_id,
            supervisor_wake_input_id,
            project_id: project_id.clone(),
            ticket_run_id: ticket_run_id.clone(),
            revision: expected_revision,
            body_digest,
            replayed: false,
        })
    }

    pub fn runnable_projects(&self, owner_generation: u64) -> Result<Vec<RunnableProject>, String> {
        let mut statement = self.connection.prepare(
            "SELECT p.project_id,p.config_source,p.config_revision,p.config_digest,p.mode,p.goal_revision,p.desired_lifecycle,p.state_revision,r.project_epoch FROM projects p JOIN project_runtimes r USING(project_id) WHERE p.desired_lifecycle='running' AND r.observed_lifecycle='running' AND r.controller_generation=?1 ORDER BY p.project_id",
        ).map_err(|error| error.to_string())?;
        let rows = statement
            .query_map([owner_generation], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, u64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, u64>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, u64>(7)?,
                    row.get::<_, u64>(8)?,
                ))
            })
            .map_err(|error| error.to_string())?;
        rows.map(|row| {
            let (
                id,
                config_source,
                config_revision,
                config_digest,
                mode,
                goal_revision,
                desired_lifecycle,
                state_revision,
                project_epoch,
            ) = row.map_err(|error| error.to_string())?;
            Ok(RunnableProject {
                record: super::ProjectRecord {
                    id: ProjectId::parse(id)?,
                    config_source,
                    config_revision: crate::domain::ids::Revision(config_revision),
                    config_digest: Digest::parse(config_digest)?,
                    mode,
                    goal_revision,
                    desired_lifecycle,
                    state_revision: crate::domain::ids::Revision(state_revision),
                },
                project_epoch,
            })
        })
        .collect()
    }

    pub fn project_has_ticket_capacity(
        &self,
        project_id: &ProjectId,
        maximum: usize,
    ) -> Result<bool, String> {
        if maximum == 0 {
            return Ok(false);
        }
        let active: usize = self.connection.query_row(
            "SELECT COUNT(*) FROM ticket_runs WHERE project_id=?1 AND internal_phase NOT IN ('done','canceled')",
            [project_id.as_str()],
            |row| row.get(0),
        ).map_err(|error| error.to_string())?;
        Ok(active < maximum)
    }

    /// Update a scan's persisted fairness sequence after it services a page or
    /// candidate. This lets other Projects and statuses rotate ahead of it.
    pub fn mark_ticket_scan_served(
        &mut self,
        owner_generation: u64,
        key: &TicketScanKey,
    ) -> Result<u64, String> {
        key.validate()?;
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let changed = tx
            .execute(
                "UPDATE ticket_scan_sequence SET sequence=sequence+1 WHERE singleton=1",
                [],
            )
            .map_err(|error| error.to_string())?;
        if changed != 1 {
            return Err("ticket scan sequence row is missing".into());
        }
        let sequence: u64 = tx
            .query_row(
                "SELECT sequence FROM ticket_scan_sequence WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        let changed = tx.execute(
            "UPDATE ticket_scan_cursors SET last_served_sequence=?1 WHERE project_id=?2 AND adapter_id=?3 AND namespace=?4 AND scope_digest=?5 AND filter_digest=?6 AND status=?7",
            params![sequence,key.project_id.as_str(),key.adapter_id.as_str(),key.namespace.as_str(),key.scope_digest.as_str(),key.filter_digest.as_str(),status_key(key.status)],
        ).map_err(|error| error.to_string())?;
        if changed != 1 {
            return Err("ticket scan cursor disappeared before fairness update".into());
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(sequence)
    }

    /// Defer only the currently claimed page after a transient adapter failure. The cursor and
    /// page generation remain unchanged, so retrying cannot skip external tickets.
    pub fn defer_ticket_scan_after_error(
        &mut self,
        owner_generation: u64,
        key: &TicketScanKey,
        expected_cursor: Option<&str>,
        expected_generation: u64,
        expected_page_count: u64,
        now_unix: i64,
        retry_after_seconds: u64,
    ) -> Result<(), String> {
        key.validate()?;
        if retry_after_seconds == 0 || retry_after_seconds > 3600 {
            return Err("ticket scan error backoff is outside bounds".into());
        }
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let changed = tx.execute(
            "UPDATE ticket_scan_cursors SET next_due_at_unix=?1 WHERE project_id=?2 AND adapter_id=?3 AND namespace=?4 AND scope_digest=?5 AND filter_digest=?6 AND status=?7 AND scan_generation=?8 AND page_count=?9 AND cursor IS ?10",
            params![now_unix.saturating_add(retry_after_seconds.min(i64::MAX as u64) as i64),key.project_id.as_str(),key.adapter_id.as_str(),key.namespace.as_str(),key.scope_digest.as_str(),key.filter_digest.as_str(),status_key(key.status),expected_generation,expected_page_count,expected_cursor],
        ).map_err(|error| error.to_string())?;
        if changed != 1 {
            return Err("ticket scan changed before error backoff could be committed".into());
        }
        tx.commit().map_err(|error| error.to_string())
    }

    /// Mark a snapshotted wake set consumed only after validated result
    /// evidence for the same AgentRun has been persisted.
    pub fn consume_agent_wakes(
        &mut self,
        owner_generation: u64,
        agent_run_id: &crate::domain::ids::AgentRunId,
    ) -> Result<usize, String> {
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let has_result: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM agent_result_evidence e JOIN agent_runs r USING(agent_run_id) WHERE e.agent_run_id=?1 AND e.outcome='completed' AND r.controller_generation=?2)",
            params![agent_run_id.as_str(),owner_generation],
            |row| row.get(0),
        ).map_err(|error| error.to_string())?;
        if !has_result {
            return Err(
                "Agent wake inputs cannot be consumed before validated completed result evidence"
                    .into(),
            );
        }
        let changed = tx.execute(
            "UPDATE role_wake_inputs SET lifecycle='consumed' WHERE consuming_agent_run_id=?1 AND lifecycle='assigned'",
            [agent_run_id.as_str()],
        ).map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(changed)
    }

    /// Return assigned inputs to pending when a provider ended without a
    /// completed result, so a later finite turn can receive them.
    pub fn retry_agent_wakes(
        &mut self,
        owner_generation: u64,
        agent_run_id: &crate::domain::ids::AgentRunId,
    ) -> Result<usize, String> {
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let outcome: Option<String> = tx.query_row(
            "SELECT outcome FROM agent_result_evidence WHERE agent_run_id=?1 ORDER BY received_at_unix DESC LIMIT 1",
            [agent_run_id.as_str()],
            |row| row.get(0),
        ).optional().map_err(|error| error.to_string())?;
        if !matches!(
            outcome.as_deref(),
            Some("provider_failed" | "timed_out" | "cancelled" | "missing_result")
        ) {
            return Err(
                "wakes can be retried only after host-recorded non-completed Agent evidence".into(),
            );
        }
        let changed = tx.execute(
            "UPDATE role_wake_inputs SET lifecycle='pending',consuming_agent_run_id=NULL WHERE consuming_agent_run_id=?1 AND lifecycle='assigned'",
            [agent_run_id.as_str()],
        ).map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(changed)
    }

    /// Persist every candidate returned by the adapter's authoritative
    /// `operation.find`. Multiple stable-key matches are all retained, one is
    /// selected deterministically, and each duplicate gets its own durable
    /// comment-and-Canceled effect.
    pub fn record_goal_ticket_candidates(
        &mut self,
        owner_generation: u64,
        operation_id: &OperationId,
        candidates: &[GoalTicketCandidateRecord],
        now_unix: i64,
    ) -> Result<GoalTicketCandidateReceipt, String> {
        if candidates.is_empty() || candidates.len() > 100 {
            return Err("goal ticket lookup must return between 1 and 100 candidates".into());
        }
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let (project, goal_revision, request_key): (String,u64,String) = tx.query_row(
            "SELECT project_id,goal_revision,request_key FROM goal_ticket_requests WHERE operation_id=?1",
            [operation_id.as_str()],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
        ).map_err(|error| error.to_string())?;
        let canonical_namespace = candidates[0].namespace.clone();
        if candidates
            .iter()
            .any(|candidate| candidate.namespace != canonical_namespace)
        {
            return Err("ticket adapter returned a candidate from another namespace".into());
        }
        let candidate_ids = candidates
            .iter()
            .map(|candidate| candidate.ticket_id.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        if candidate_ids.len() != candidates.len() {
            return Err("ticket adapter returned duplicate candidate identities".into());
        }
        let candidates_for_sort = candidates
            .iter()
            .map(
                |candidate| crate::engine::factory_runtime::GoalTicketCandidate {
                    ticket_id: candidate.ticket_id.as_str().to_owned(),
                    match_basis: candidate.match_basis,
                    created_at: candidate.created_at.clone(),
                },
            )
            .collect::<Vec<_>>();
        let canonical = crate::engine::factory_runtime::canonicalize_goal_ticket_candidates(
            &candidates_for_sort,
        )?;
        let canonical_ticket_id = TicketId::parse(canonical.canonical_ticket_id.clone())?;
        let mut duplicate_ticket_ids = Vec::new();
        for candidate in candidates {
            let is_canonical = candidate.ticket_id.as_str() == canonical.canonical_ticket_id;
            let state = if is_canonical {
                "canonical"
            } else {
                "duplicate_pending"
            };
            let basis = match candidate.match_basis {
                crate::engine::factory_runtime::GoalTicketMatchBasis::OperationId => "operation_id",
                crate::engine::factory_runtime::GoalTicketMatchBasis::StableExternalKey => {
                    "stable_external_key"
                }
            };
            tx.execute(
                "INSERT INTO goal_ticket_candidates(project_id,goal_revision,request_key,namespace,ticket_id,match_basis,created_at,state,observed_at_unix) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9) ON CONFLICT(project_id,goal_revision,request_key,namespace,ticket_id) DO UPDATE SET match_basis=excluded.match_basis,created_at=COALESCE(goal_ticket_candidates.created_at,excluded.created_at),state=CASE WHEN excluded.state='canonical' THEN 'canonical' WHEN goal_ticket_candidates.state='duplicate_resolved' THEN goal_ticket_candidates.state ELSE excluded.state END,observed_at_unix=MAX(goal_ticket_candidates.observed_at_unix,excluded.observed_at_unix)",
                params![project,goal_revision,request_key,candidate.namespace.as_str(),candidate.ticket_id.as_str(),basis,candidate.created_at,state,now_unix],
            ).map_err(|error| error.to_string())?;
            if !is_canonical {
                let prior_state: String = tx.query_row(
                    "SELECT state FROM goal_ticket_candidates WHERE project_id=?1 AND goal_revision=?2 AND request_key=?3 AND namespace=?4 AND ticket_id=?5",
                    params![project,goal_revision,request_key,candidate.namespace.as_str(),candidate.ticket_id.as_str()],
                    |row| row.get(0),
                ).map_err(|error| error.to_string())?;
                if prior_state == "duplicate_resolved" {
                    continue;
                }
                duplicate_ticket_ids.push(candidate.ticket_id.clone());
                let duplicate_operation = stable_duplicate_operation_id(
                    operation_id,
                    &candidate.namespace,
                    &candidate.ticket_id,
                )?;
                let request = crate::engine::ticket_effects::ResolveDuplicateTicket {
                    schema_version: 1,
                    project_id: ProjectId::parse(project.clone())?,
                    namespace: candidate.namespace.clone(),
                    goal_revision,
                    request_key: request_key.clone(),
                    duplicate_ticket_id: candidate.ticket_id.clone(),
                    canonical_ticket_id: canonical_ticket_id.clone(),
                    expected_external_revision: None,
                    comment_body: format!(
                        "Duplicate of {}. This ticket was created from the same stable goal proposal.",
                        canonical_ticket_id.as_str()
                    ),
                };
                request.validate()?;
                let request_json = serde_json::to_string(
                    &serde_json::to_value(&request).map_err(|error| error.to_string())?,
                )
                .map_err(|error| error.to_string())?;
                tx.execute(
                    "UPDATE goal_ticket_candidates SET state='duplicate_pending' WHERE project_id=?1 AND goal_revision=?2 AND request_key=?3 AND namespace=?4 AND ticket_id=?5 AND state!='duplicate_resolved'",
                    params![project,goal_revision,request_key,candidate.namespace.as_str(),candidate.ticket_id.as_str()],
                ).map_err(|error| error.to_string())?;
                let state_revision: u64 = tx
                    .query_row(
                        "SELECT state_revision FROM projects WHERE project_id=?1",
                        [&project],
                        |row| row.get(0),
                    )
                    .map_err(|error| error.to_string())?;
                insert_effect(
                    &tx,
                    &EffectIntent {
                        project_id: ProjectId::parse(project.clone())?,
                        subject_type: "project".into(),
                        subject_id: project.clone(),
                        operation_id: duplicate_operation.as_str().into(),
                        logical_key: format!(
                            "goal-ticket-duplicate:{}:{}:{}",
                            operation_id.as_str(),
                            candidate.namespace.as_str(),
                            candidate.ticket_id.as_str()
                        ),
                        kind: "ticket_resolve_duplicate".into(),
                        request_digest: content_digest(&request_json),
                        request_json,
                        expected_revision: Some(state_revision),
                    },
                    now_unix,
                )?;
            }
        }
        let request_state = if duplicate_ticket_ids.is_empty() {
            "created"
        } else {
            "duplicate_pending"
        };
        tx.execute(
            "UPDATE goal_ticket_requests SET state=?1,canonical_namespace=?2,canonical_ticket_id=?3,updated_at_unix=?4 WHERE operation_id=?5",
            params![request_state,canonical_namespace.as_str(),canonical_ticket_id.as_str(),now_unix,operation_id.as_str()],
        ).map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(GoalTicketCandidateReceipt {
            canonical_namespace,
            canonical_ticket_id,
            duplicate_ticket_ids,
        })
    }

    /// Record one duplicate's atomic adapter resolution receipt. Completion is
    /// exposed only after every duplicate candidate is resolved.
    pub fn mark_goal_ticket_duplicate_resolved(
        &mut self,
        owner_generation: u64,
        project_id: &ProjectId,
        goal_revision: u64,
        request_key: &str,
        namespace: &TicketNamespace,
        duplicate: &TicketId,
        now_unix: i64,
    ) -> Result<bool, String> {
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let changed = tx.execute(
            "UPDATE goal_ticket_candidates SET state='duplicate_resolved',observed_at_unix=?1 WHERE project_id=?2 AND goal_revision=?3 AND request_key=?4 AND namespace=?5 AND ticket_id=?6 AND state='duplicate_pending'",
            params![now_unix,project_id.as_str(),goal_revision,request_key,namespace.as_str(),duplicate.as_str()],
        ).map_err(|error| error.to_string())?;
        if changed == 1 {
            tx.execute(
                "UPDATE goal_ticket_requests SET state='duplicate_resolved',updated_at_unix=?1 WHERE project_id=?2 AND goal_revision=?3 AND request_key=?4 AND NOT EXISTS(SELECT 1 FROM goal_ticket_candidates WHERE project_id=?2 AND goal_revision=?3 AND request_key=?4 AND state='duplicate_pending')",
                params![now_unix,project_id.as_str(),goal_revision,request_key],
            ).map_err(|error| error.to_string())?;
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(changed == 1)
    }

    /// Reserve one goal-generated ticket and enqueue its CLI-backed create
    /// operation atomically. The request budget is counted transactionally and
    /// a retry with the same key/content reuses the same operation identity.
    pub fn reserve_goal_ticket_creation(
        &mut self,
        owner_generation: u64,
        project_id: &ProjectId,
        namespace: &TicketNamespace,
        request_key: &str,
        request_digest: &str,
        proposal_json: &str,
        ticket_request: &crate::engine::ticket_effects::CreateGoalTicket,
        maximum: usize,
        now_unix: i64,
    ) -> Result<GoalTicketReservation, String> {
        if request_key.is_empty()
            || request_key.len() > 255
            || maximum == 0
            || proposal_json.is_empty()
            || proposal_json.len() > 131_072
        {
            return Err("goal ticket reservation is outside configured limits".into());
        }
        Digest::parse(request_digest.to_owned())?;
        let proposal: serde_json::Value =
            crate::protocol::parse_unique(proposal_json.as_bytes())
                .map_err(|error| format!("goal ticket proposal is invalid: {error}"))?;
        let canonical_proposal =
            serde_json::to_string(&proposal).map_err(|error| error.to_string())?;
        if canonical_proposal != proposal_json
            || content_digest(&canonical_proposal) != request_digest
        {
            return Err("goal ticket proposal must be canonical and match its digest".into());
        }
        ticket_request.validate()?;
        let ticket_proposal =
            serde_json::to_value(&ticket_request.proposal).map_err(|error| error.to_string())?;
        if ticket_request.project_id != *project_id
            || ticket_request.namespace != *namespace
            || ticket_request.request_key != request_key
            || ticket_request.request_digest.as_str() != request_digest
            || ticket_proposal != proposal
        {
            return Err("goal ticket effect does not match its reserved proposal".into());
        }

        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let (goal_revision, state_revision, mode): (u64, u64, String) = tx
            .query_row(
                "SELECT goal_revision,state_revision,mode FROM projects WHERE project_id=?1",
                [project_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(|error| error.to_string())?;
        if mode != "goal" || goal_revision == 0 {
            return Err(
                "goal ticket creation is only available for a configured Goal Project".into(),
            );
        }
        let prior: Option<(String,String)> = tx.query_row(
            "SELECT request_digest,operation_id FROM goal_ticket_requests WHERE project_id=?1 AND goal_revision=?2 AND request_key=?3",
            params![project_id.as_str(),goal_revision,request_key],
            |row| Ok((row.get(0)?,row.get(1)?)),
        ).optional().map_err(|error| error.to_string())?;
        if let Some((prior_digest, operation_id)) = prior {
            if prior_digest != request_digest {
                return Err(
                    "goal request key is already bound to different proposal content".into(),
                );
            }
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(GoalTicketReservation {
                request_key: request_key.to_owned(),
                request_digest: request_digest.to_owned(),
                operation_id: OperationId::parse(operation_id)?,
                reused: true,
            });
        }
        let reserved: usize = tx.query_row(
            "SELECT COUNT(*) FROM goal_ticket_requests WHERE project_id=?1 AND goal_revision=?2",
            params![project_id.as_str(),goal_revision],
            |row| row.get(0),
        ).map_err(|error| error.to_string())?;
        if reserved >= maximum {
            return Err(
                "Goal Project ticket creation budget is exhausted for this goal revision".into(),
            );
        }
        let operation_id = stable_goal_operation_id(project_id, goal_revision, request_key)?;
        let request = serde_json::json!({
            "schema_version": 1,
            "project_id": project_id.as_str(),
            "namespace": namespace.as_str(),
            "goal_revision": goal_revision,
            "request_key": request_key,
            "request_digest": request_digest,
            "proposal": proposal,
            "request": ticket_request.request,
        });
        let request_json = serde_json::to_string(&request).map_err(|error| error.to_string())?;
        let effect_digest = content_digest(&request_json);
        tx.execute(
            "INSERT INTO goal_ticket_requests(project_id,goal_revision,request_key,request_digest,operation_id,proposal_json,state,created_at_unix,updated_at_unix) VALUES (?1,?2,?3,?4,?5,?6,'reserved',?7,?7)",
            params![project_id.as_str(),goal_revision,request_key,request_digest,operation_id.as_str(),canonical_proposal,now_unix],
        ).map_err(|error| error.to_string())?;
        insert_effect(
            &tx,
            &EffectIntent {
                project_id: project_id.clone(),
                subject_type: "project".into(),
                subject_id: project_id.as_str().into(),
                operation_id: operation_id.as_str().into(),
                logical_key: format!(
                    "goal-ticket:{}:{}:{}",
                    project_id.as_str(),
                    goal_revision,
                    request_key
                ),
                kind: "ticket_create".into(),
                request_json,
                request_digest: effect_digest,
                expected_revision: Some(state_revision),
            },
            now_unix,
        )?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(GoalTicketReservation {
            request_key: request_key.to_owned(),
            request_digest: request_digest.to_owned(),
            operation_id,
            reused: false,
        })
    }

    /// Choose at most one due Project/status scan. Persisted service sequence
    /// wins over due-time ties, so restarts do not reset Project fairness.
    pub fn next_due_ticket_scan(
        &self,
        keys: &[TicketScanKey],
        now_unix: i64,
    ) -> Result<Option<(TicketScanKey, TicketScanCursor)>, String> {
        let mut due = Vec::new();
        for key in keys {
            let cursor = self.ticket_scan_cursor(key)?;
            if cursor.next_due_at_unix <= now_unix {
                due.push((key.clone(), cursor));
            }
        }
        due.sort_by(|(left_key, left), (right_key, right)| {
            (
                left.last_served_sequence,
                left.next_due_at_unix,
                left_key.project_id.as_str(),
                left_key.adapter_id.as_str(),
                left_key.namespace.as_str(),
                left_key.scope_digest.as_str(),
                left_key.filter_digest.as_str(),
                status_key(left_key.status),
            )
                .cmp(&(
                    right.last_served_sequence,
                    right.next_due_at_unix,
                    right_key.project_id.as_str(),
                    right_key.adapter_id.as_str(),
                    right_key.namespace.as_str(),
                    right_key.scope_digest.as_str(),
                    right_key.filter_digest.as_str(),
                    status_key(right_key.status),
                ))
        });
        Ok(due.into_iter().next())
    }

    /// Read one status scan cursor. An absent row is due immediately with no
    /// continuation cursor.
    pub fn ticket_scan_cursor(&self, key: &TicketScanKey) -> Result<TicketScanCursor, String> {
        key.validate()?;
        let row: Option<(Option<String>, u64, u64, i64, Option<i64>, Option<i64>, i64, u64)> = self
            .connection
            .query_row(
                "SELECT cursor,scan_generation,page_count,started_at_unix,last_page_at_unix,completed_at_unix,next_due_at_unix,last_served_sequence FROM ticket_scan_cursors WHERE project_id=?1 AND adapter_id=?2 AND namespace=?3 AND scope_digest=?4 AND filter_digest=?5 AND status=?6",
                params![key.project_id.as_str(),key.adapter_id.as_str(),key.namespace.as_str(),key.scope_digest.as_str(),key.filter_digest.as_str(),status_key(key.status)],
                |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        Ok(row.map_or(
            TicketScanCursor {
                cursor: None,
                generation: 0,
                page_count: 0,
                started_at_unix: 0,
                last_page_at_unix: None,
                completed_at_unix: None,
                next_due_at_unix: 0,
                last_served_sequence: 0,
            },
            |(
                cursor,
                generation,
                page_count,
                started,
                last,
                completed,
                next_due,
                served_sequence,
            )| {
                TicketScanCursor {
                    cursor,
                    generation,
                    page_count,
                    started_at_unix: started,
                    last_page_at_unix: last,
                    completed_at_unix: completed,
                    next_due_at_unix: next_due,
                    last_served_sequence: served_sequence,
                }
            },
        ))
    }

    /// Return bounded pending candidates from a Project's persisted scan.
    /// Ordering is stable across restarts and independent of adapter output order.
    pub fn pending_ticket_observations(
        &self,
        key: &TicketScanKey,
        limit: usize,
    ) -> Result<Vec<PendingTicketObservation>, String> {
        key.validate()?;
        if limit == 0 || limit > 100 {
            return Err("pending ticket page size must be between 1 and 100".into());
        }
        let mut statement = self.connection.prepare(
            "SELECT o.ticket_id,o.external_revision,o.status,o.title,o.labels_json,o.last_seen_at_unix
             FROM ticket_observations o
             LEFT JOIN ticket_claims c ON c.namespace=o.namespace AND c.ticket_id=o.ticket_id
             WHERE o.project_id=?1 AND o.adapter_id=?2 AND o.namespace=?3 AND o.scope_digest=?4 AND o.filter_digest=?5
               AND o.status=?6 AND o.dispatch_state='pending' AND c.ticket_run_id IS NULL
             ORDER BY o.last_seen_at_unix ASC,o.ticket_id ASC LIMIT ?7",
        ).map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(
                params![
                    key.project_id.as_str(),
                    key.adapter_id.as_str(),
                    key.namespace.as_str(),
                    key.scope_digest.as_str(),
                    key.filter_digest.as_str(),
                    status_key(key.status),
                    limit as u64
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, i64>(5)?,
                    ))
                },
            )
            .map_err(|error| error.to_string())?;
        rows.map(|row| {
            let (ticket, revision, status, title, labels_json, observed_at_unix) =
                row.map_err(|error| error.to_string())?;
            let labels = serde_json::from_str(&labels_json)
                .map_err(|error| format!("stored ticket labels are invalid: {error}"))?;
            Ok(PendingTicketObservation {
                ticket_id: TicketId::parse(ticket)?,
                revision,
                status: parse_status_key(&status)?,
                title,
                labels,
                observed_at_unix,
            })
        })
        .collect()
    }

    /// Terminally classify a ticket observation without starting work.
    /// `human` means policy needs a person; `ignored` means the configured
    /// recipe intentionally excludes it. A future scan may make it pending
    /// again only if the external status/revision changed.
    pub fn classify_ticket_observation(
        &mut self,
        owner_generation: u64,
        key: &TicketScanKey,
        ticket: &TicketId,
        classification: TicketObservationClassification,
        reason: &str,
        now_unix: i64,
    ) -> Result<(), String> {
        key.validate()?;
        if reason.is_empty() || reason.len() > 4096 {
            return Err("ticket observation classification requires a bounded reason".into());
        }
        let target = match classification {
            TicketObservationClassification::Human => "human",
            TicketObservationClassification::Ignored => "ignored",
        };
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let changed = tx.execute(
            "UPDATE ticket_observations SET dispatch_state=?1 WHERE project_id=?2 AND adapter_id=?3 AND namespace=?4 AND ticket_id=?5 AND scope_digest=?6 AND filter_digest=?7 AND dispatch_state='pending'",
            params![target, key.project_id.as_str(), key.adapter_id.as_str(), key.namespace.as_str(), ticket.as_str(), key.scope_digest.as_str(),key.filter_digest.as_str()],
        ).map_err(|error| error.to_string())?;
        if changed == 1 {
            tx.execute("INSERT INTO scheduler_audit(project_id,subject_type,subject_id,action,detail,created_at_unix) VALUES (?1,'ticket',?2,?3,?4,?5)", params![key.project_id.as_str(),ticket.as_str(),target,reason,now_unix]).map_err(|error| error.to_string())?;
        }
        tx.commit().map_err(|error| error.to_string())
    }

    /// Commit one adapter page and advance its cursor atomically. Replaying the
    /// same request after a crash is harmless. A lost/changed cursor is a
    /// conflict; it never skips ahead.
    pub fn record_ticket_scan_page(
        &mut self,
        owner_generation: u64,
        key: &TicketScanKey,
        expected_cursor: Option<&str>,
        expected_generation: u64,
        expected_page_count: u64,
        next_cursor: Option<&str>,
        tickets: &[ObservedTicket],
        now_unix: i64,
        poll_seconds: u64,
    ) -> Result<TicketScanCursor, String> {
        key.validate()?;
        if tickets.len() > 100 || poll_seconds == 0 {
            return Err("ticket page or poll interval exceeds configured limits".into());
        }
        for ticket in tickets {
            if ticket.id.as_str().is_empty()
                || ticket.title.trim().is_empty()
                || ticket.labels.len() > 256
                || ticket.labels.iter().any(|label| label.len() > 255)
            {
                return Err("ticket observation is invalid".into());
            }
        }

        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, owner_generation)?;

        let current: Option<(Option<String>, u64, u64, i64)> = tx
            .query_row(
                "SELECT cursor,scan_generation,page_count,started_at_unix FROM ticket_scan_cursors WHERE project_id=?1 AND adapter_id=?2 AND namespace=?3 AND scope_digest=?4 AND filter_digest=?5 AND status=?6",
                params![key.project_id.as_str(),key.adapter_id.as_str(),key.namespace.as_str(),key.scope_digest.as_str(),key.filter_digest.as_str(),status_key(key.status)],
                |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if current.as_ref().and_then(|row| row.0.as_deref()) != expected_cursor
            || current.as_ref().map_or(0, |row| row.1) != expected_generation
            || current.as_ref().map_or(0, |row| row.2) != expected_page_count
        {
            return Err("ticket scan cursor changed before page commit".into());
        }
        let (generation, page_count, started_at) = match current.as_ref() {
            None => (1, 1, now_unix),
            Some((Some(_), generation, page_count, started_at)) => {
                (*generation, page_count.saturating_add(1), *started_at)
            }
            Some((None, generation, _, _)) => (
                generation
                    .checked_add(1)
                    .ok_or_else(|| "ticket scan generation is exhausted".to_owned())?,
                1,
                now_unix,
            ),
        };

        for ticket in tickets {
            if ticket.status != key.status {
                return Err(
                    "ticket page contains a status outside the requested scan filter".into(),
                );
            }
            let labels =
                serde_json::to_string(&ticket.labels).map_err(|error| error.to_string())?;
            tx.execute(
                "INSERT INTO ticket_observations(project_id,adapter_id,namespace,ticket_id,scope_digest,filter_digest,external_revision,status,title,labels_json,created_at,last_seen_at_unix,scan_generation) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13) ON CONFLICT(project_id,adapter_id,namespace,ticket_id) DO UPDATE SET scope_digest=excluded.scope_digest,filter_digest=excluded.filter_digest,external_revision=excluded.external_revision,status=excluded.status,title=excluded.title,labels_json=excluded.labels_json,created_at=COALESCE(ticket_observations.created_at,excluded.created_at),last_seen_at_unix=excluded.last_seen_at_unix,scan_generation=excluded.scan_generation,dispatch_state=CASE WHEN ticket_observations.scope_digest != excluded.scope_digest OR ticket_observations.filter_digest != excluded.filter_digest OR ticket_observations.external_revision IS NOT excluded.external_revision OR ticket_observations.status != excluded.status OR ticket_observations.title != excluded.title OR ticket_observations.labels_json != excluded.labels_json THEN 'pending' ELSE ticket_observations.dispatch_state END,ticket_run_id=CASE WHEN ticket_observations.scope_digest != excluded.scope_digest OR ticket_observations.filter_digest != excluded.filter_digest OR ticket_observations.external_revision IS NOT excluded.external_revision OR ticket_observations.status != excluded.status OR ticket_observations.title != excluded.title OR ticket_observations.labels_json != excluded.labels_json THEN NULL ELSE ticket_observations.ticket_run_id END",
                params![key.project_id.as_str(),key.adapter_id.as_str(),key.namespace.as_str(),ticket.id.as_str(),key.scope_digest.as_str(),key.filter_digest.as_str(),ticket.revision,status_key(ticket.status),ticket.title,labels,ticket.created_at,ticket.observed_at_unix,generation],
            ).map_err(|error| error.to_string())?;
        }

        let complete = next_cursor.is_none();
        let next_due = if complete {
            now_unix.saturating_add(i64::try_from(poll_seconds).unwrap_or(i64::MAX))
        } else {
            now_unix
        };
        tx.execute(
            "UPDATE ticket_scan_sequence SET sequence=sequence+1 WHERE singleton=1",
            [],
        )
        .map_err(|error| error.to_string())?;
        let served_sequence: u64 = tx
            .query_row(
                "SELECT sequence FROM ticket_scan_sequence WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        tx.execute(
            "INSERT INTO ticket_scan_cursors(project_id,adapter_id,namespace,scope_digest,filter_digest,status,cursor,scan_generation,page_count,started_at_unix,last_page_at_unix,completed_at_unix,next_due_at_unix,last_served_sequence) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14) ON CONFLICT(project_id,adapter_id,namespace,scope_digest,filter_digest,status) DO UPDATE SET cursor=excluded.cursor,scan_generation=excluded.scan_generation,page_count=excluded.page_count,started_at_unix=excluded.started_at_unix,last_page_at_unix=excluded.last_page_at_unix,completed_at_unix=excluded.completed_at_unix,next_due_at_unix=excluded.next_due_at_unix,last_served_sequence=excluded.last_served_sequence",
            params![key.project_id.as_str(),key.adapter_id.as_str(),key.namespace.as_str(),key.scope_digest.as_str(),key.filter_digest.as_str(),status_key(key.status),next_cursor,generation,page_count,started_at,now_unix,if complete {Some(now_unix)} else {None},next_due,served_sequence],
        ).map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(TicketScanCursor {
            cursor: next_cursor.map(str::to_owned),
            generation,
            page_count,
            started_at_unix: started_at,
            last_page_at_unix: Some(now_unix),
            completed_at_unix: complete.then_some(now_unix),
            next_due_at_unix: next_due,
            last_served_sequence: served_sequence,
        })
    }

    /// Atomically persist a TicketRun, claim, initial reducer transition, and
    /// its start/status effects. The stable ID makes retry after a lost local
    /// response converge on the same claim.
    #[allow(clippy::too_many_arguments)]
    pub fn create_dispatched_ticket_run(
        &mut self,
        owner_generation: u64,
        key: &TicketScanKey,
        ticket: &TicketId,
        recipe_id: Option<&str>,
        eligible_statuses: &[TicketStatus],
        max_active_tickets: usize,
        supervisor_dispatch: &SupervisorDispatchAuthority,
        now_unix: i64,
    ) -> Result<Option<TicketRunId>, String> {
        key.validate()?;
        if max_active_tickets == 0 {
            return Err("Project max_active_tickets must be positive".into());
        }
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let replay: Option<(String, i64)> = tx.query_row(
            "SELECT r.ticket_run_id,w.priority FROM role_wake_inputs w JOIN ticket_runs r ON r.ticket_run_id=json_extract(w.payload_json,'$.ticket_run_id') WHERE w.project_id=?1 AND w.source_type='ticket_run_dispatch' AND json_extract(w.payload_json,'$.supervisor_evidence_id')=?2 AND r.namespace=?3 AND r.ticket_id=?4",
            params![key.project_id.as_str(), supervisor_dispatch.evidence_id, key.namespace.as_str(), ticket.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional().map_err(|error| error.to_string())?;
        if let Some((ticket_run_id, priority)) = replay {
            if priority != i64::from(supervisor_dispatch.priority) {
                return Err(
                    "Supervisor dispatch evidence was replayed with a different priority".into(),
                );
            }
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(Some(TicketRunId::parse(ticket_run_id)?));
        }
        let existing: Option<String> = tx
            .query_row(
                "SELECT ticket_run_id FROM ticket_claims WHERE namespace=?1 AND ticket_id=?2",
                params![key.namespace.as_str(), ticket.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if existing.is_some() {
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(None);
        }
        let observation: Option<(Option<String>, String)> = tx.query_row(
            "SELECT external_revision,status FROM ticket_observations WHERE project_id=?1 AND adapter_id=?2 AND namespace=?3 AND ticket_id=?4 AND scope_digest=?5 AND filter_digest=?6 AND dispatch_state='pending'",
            params![key.project_id.as_str(),key.adapter_id.as_str(),key.namespace.as_str(),ticket.as_str(),key.scope_digest.as_str(),key.filter_digest.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional().map_err(|error| error.to_string())?;
        let Some((observed_revision, stored_status)) = observation else {
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(None);
        };
        if supervisor_dispatch.evidence_id.trim().is_empty()
            || supervisor_dispatch
                .expected_external_revision
                .trim()
                .is_empty()
            || observed_revision.as_deref()
                != Some(supervisor_dispatch.expected_external_revision.as_str())
        {
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(None);
        }
        let external_status = parse_status_key(&stored_status)?;
        if external_status != key.status || !eligible_statuses.contains(&external_status) {
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(None);
        }
        let status = enum_string(&external_status)?;
        let (
            config_source,
            config_revision,
            config_digest,
            project_epoch,
            desired_lifecycle,
            observed_lifecycle,
        ): (String, u64, String, u64, String, String) = tx
            .query_row(
                "SELECT p.config_source,p.config_revision,p.config_digest,r.project_epoch,p.desired_lifecycle,r.observed_lifecycle FROM projects p JOIN project_runtimes r USING(project_id) WHERE p.project_id=?1",
                [key.project_id.as_str()],
                |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?)),
            )
            .map_err(|error| error.to_string())?;
        if desired_lifecycle != "running" || observed_lifecycle != "running" {
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(None);
        }
        let active_count: usize = tx
            .query_row(
                "SELECT COUNT(*) FROM ticket_runs WHERE project_id=?1 AND internal_phase NOT IN ('done','canceled')",
                [key.project_id.as_str()],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        if active_count >= max_active_tickets {
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(None);
        }
        let generation: u64 = tx
            .query_row(
                "SELECT COALESCE(MAX(generation),0)+1 FROM ticket_runs WHERE project_id=?1 AND namespace=?2 AND ticket_id=?3",
                params![key.project_id.as_str(),key.namespace.as_str(),ticket.as_str()],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        let ticket_run_id =
            stable_ticket_run_id(&key.project_id, &key.namespace, ticket, generation)?;
        let queued = TicketRun {
            project_id: key.project_id.clone(),
            ticket_run_id: ticket_run_id.clone(),
            revision: crate::domain::ids::Revision(0),
            phase: Phase::Queued,
            activity: Activity::Ready,
            external_status,
            required_review_revision: None,
        };
        tx.execute(
            "INSERT INTO ticket_runs(ticket_run_id,project_id,config_source,config_revision,config_digest,namespace,ticket_id,generation,internal_phase,activity,external_status,observed_status,revision,external_revision) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,'queued','ready',?9,?9,0,?10)",
            params![ticket_run_id.as_str(),key.project_id.as_str(),config_source,config_revision,config_digest,key.namespace.as_str(),ticket.as_str(),generation,status,observed_revision],
        ).map_err(|error| error.to_string())?;
        tx.execute(
            "INSERT INTO ticket_claims(namespace,ticket_id,project_id,ticket_run_id,generation,claimed_at_unix) VALUES (?1,?2,?3,?4,?5,?6)",
            params![key.namespace.as_str(),ticket.as_str(),key.project_id.as_str(),ticket_run_id.as_str(),generation,now_unix],
        ).map_err(|error| error.to_string())?;
        tx.execute(
            "INSERT INTO ticket_run_context(ticket_run_id,project_id,project_epoch,recipe_id,goal_revision,created_at_unix) VALUES (?1,?2,?3,?4,(SELECT goal_revision FROM projects WHERE project_id=?2),?5)",
            params![ticket_run_id.as_str(),key.project_id.as_str(),project_epoch,recipe_id,now_unix],
        ).map_err(|error| error.to_string())?;

        let decision = reduce(&queued, queued.revision, Input::Dispatch)?;
        let operation_ids = decision
            .effects
            .iter()
            .map(|kind| stable_operation_id(&ticket_run_id, 1, &format!("{kind:?}")))
            .collect::<Result<Vec<_>, _>>()?;
        let reducer_effects = bind_effects(&decision, &operation_ids)?;
        tx.execute(
            "UPDATE ticket_runs SET internal_phase='planning',activity='running',external_status='in_progress',observed_status='in_progress',revision=1 WHERE ticket_run_id=?1 AND revision=0",
            [ticket_run_id.as_str()],
        ).map_err(|error| error.to_string())?;
        for effect in reducer_effects {
            let serialized_kind = serde_json::to_value(effect.kind)
                .map_err(|error| error.to_string())?
                .as_str()
                .ok_or_else(|| "reducer effect kind was not a string".to_owned())?
                .to_owned();
            let request = serde_json::json!({
                "schema_version": 1,
                "project_id": key.project_id.as_str(),
                "ticket_run_id": ticket_run_id.as_str(),
                "role": "coordinator",
                "recipe_id": recipe_id,
                "project_epoch": project_epoch,
                "observed_revision": observed_revision,
            });
            let request_json =
                serde_json::to_string(&request).map_err(|error| error.to_string())?;
            let digest = format!("{:x}", sha2::Sha256::digest(request_json.as_bytes()));
            insert_effect(
                &tx,
                &EffectIntent {
                    project_id: key.project_id.clone(),
                    subject_type: "ticket_run".into(),
                    subject_id: ticket_run_id.as_str().into(),
                    operation_id: effect.operation_id.as_str().to_owned(),
                    logical_key: effect.logical_key,
                    kind: serialized_kind,
                    request_json,
                    request_digest: digest,
                    expected_revision: Some(1),
                },
                now_unix,
            )?;
        }
        tx.execute(
            "INSERT INTO transitions(project_id,entity_type,entity_id,old_revision,new_revision,input_id,decision_reason,evidence_json,created_at_unix) VALUES (?1,'ticket_run',?2,0,1,?3,'ticket discovered by bounded Project scan',?4,?5)",
            params![key.project_id.as_str(),ticket_run_id.as_str(),format!("dispatch:{}:{}",key.namespace.as_str(),ticket.as_str()),serde_json::json!({"namespace":key.namespace.as_str(),"ticket_id":ticket.as_str(),"generation":generation,"recipe_id":recipe_id,"observed_revision":observed_revision}).to_string(),now_unix],
        ).map_err(|error| error.to_string())?;
        tx.execute(
            "INSERT INTO role_wake_inputs(project_id,role_session_id,source_type,source_id,source_revision,priority,payload_json,lifecycle,created_at_unix) VALUES (?1,?2,'ticket_run_dispatch',?3,1,?4,?5,'pending',?6)",
            params![key.project_id.as_str(),format!("ticket_run:{}:coordinator",ticket_run_id.as_str()),ticket_run_id.as_str(),i64::from(supervisor_dispatch.priority),serde_json::json!({"ticket_run_id":ticket_run_id.as_str(),"target":"coordinator","revision":1,"supervisor_evidence_id":supervisor_dispatch.evidence_id}).to_string(),now_unix],
        ).map_err(|error| error.to_string())?;
        let classified = tx.execute(
            "UPDATE ticket_observations SET dispatch_state='started',ticket_run_id=?1 WHERE project_id=?2 AND adapter_id=?3 AND namespace=?4 AND ticket_id=?5 AND scope_digest=?6 AND filter_digest=?7 AND dispatch_state='pending'",
            params![ticket_run_id.as_str(),key.project_id.as_str(),key.adapter_id.as_str(),key.namespace.as_str(),ticket.as_str(),key.scope_digest.as_str(),key.filter_digest.as_str()],
        ).map_err(|error| error.to_string())?;
        if classified != 1 {
            return Err("ticket observation changed during TicketRun creation".into());
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(Some(ticket_run_id))
    }
}

fn parse_role_session_id(
    value: &str,
) -> Result<(Role, Option<TicketRunId>, Option<WorkNodeId>), String> {
    if let Some(project) = value.strip_prefix("project:")
        && project.ends_with(":supervisor")
    {
        return Ok((Role::Supervisor, None, None));
    }
    if let Some(worker) = value.strip_prefix("ticket:") {
        if let Some((ticket_run, node)) = worker.split_once(":worker:") {
            return Ok((
                Role::Worker,
                Some(TicketRunId::parse(ticket_run.to_owned())?),
                Some(WorkNodeId::parse(node.to_owned())?),
            ));
        }
        return Err("per-node Worker session is malformed".into());
    }
    let ticket = value
        .strip_prefix("ticket_run:")
        .ok_or_else(|| "pending wake session has an unknown scope".to_owned())?;
    const ROLES: [(Role, &str); 7] = [
        (Role::Coordinator, "coordinator"),
        (Role::Planner, "planner"),
        (Role::Worker, "worker"),
        (Role::Reviewer, "reviewer"),
        (Role::MergeDecision, "merge_decision"),
        (Role::Operator, "operator"),
        (Role::Postmortem, "postmortem"),
    ];
    for (role, name) in ROLES {
        if let Some(ticket_run_id) = ticket.strip_suffix(&format!(":{name}")) {
            // Legacy/generic Worker wakes may exist in an upgraded database.
            // They remain visible for dashboard repair but have no node token,
            // so the launch service must reject them.
            return Ok((
                role,
                Some(TicketRunId::parse(ticket_run_id.to_owned())?),
                None,
            ));
        }
    }
    Err("pending wake session has an unknown ticket role".into())
}

fn stable_ticket_run_id(
    project: &ProjectId,
    namespace: &TicketNamespace,
    ticket: &TicketId,
    generation: u64,
) -> Result<TicketRunId, String> {
    let identity = format!(
        "{}\0{}\0{}\0{generation}",
        project.as_str(),
        namespace.as_str(),
        ticket.as_str()
    );
    let digest = format!("{:x}", sha2::Sha256::digest(identity.as_bytes()));
    TicketRunId::parse(format!("run-{}", &digest[..48]))
}

fn stable_operation_id(
    ticket_run_id: &TicketRunId,
    revision: u64,
    kind: &str,
) -> Result<OperationId, String> {
    let identity = format!("{}\0{revision}\0{kind}", ticket_run_id.as_str());
    let digest = format!("{:x}", sha2::Sha256::digest(identity.as_bytes()));
    OperationId::parse(format!("op-{}", &digest[..48]))
}

fn stable_goal_operation_id(
    project: &ProjectId,
    goal_revision: u64,
    request_key: &str,
) -> Result<OperationId, String> {
    let identity = format!(
        "goal-ticket\0{}\0{goal_revision}\0{request_key}",
        project.as_str()
    );
    let digest = format!("{:x}", sha2::Sha256::digest(identity.as_bytes()));
    OperationId::parse(format!("op-{}", &digest[..48]))
}

fn stable_duplicate_operation_id(
    create_operation: &OperationId,
    namespace: &TicketNamespace,
    duplicate: &TicketId,
) -> Result<OperationId, String> {
    let identity = format!(
        "goal-ticket-duplicate\0{}\0{}\0{}",
        create_operation.as_str(),
        namespace.as_str(),
        duplicate.as_str()
    );
    let digest = format!("{:x}", sha2::Sha256::digest(identity.as_bytes()));
    OperationId::parse(format!("op-{}", &digest[..48]))
}

fn status_key(status: TicketStatus) -> &'static str {
    match status {
        TicketStatus::Triage => "triage",
        TicketStatus::Backlog => "backlog",
        TicketStatus::Ready => "ready",
        TicketStatus::InProgress => "in_progress",
        TicketStatus::InReview => "in_review",
        TicketStatus::Done => "done",
        TicketStatus::Canceled => "canceled",
    }
}

fn parse_status_key(status: &str) -> Result<TicketStatus, String> {
    match status {
        "triage" => Ok(TicketStatus::Triage),
        "backlog" => Ok(TicketStatus::Backlog),
        "ready" => Ok(TicketStatus::Ready),
        "in_progress" => Ok(TicketStatus::InProgress),
        "in_review" => Ok(TicketStatus::InReview),
        "done" => Ok(TicketStatus::Done),
        "canceled" => Ok(TicketStatus::Canceled),
        other => Err(format!("unknown stored ticket status `{other}`")),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TicketObservationClassification {
    Human,
    Ignored,
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;

    use super::{PendingRoleWakeSession, TicketScanCursor, TicketScanKey, migrate_v9, status_key};
    use crate::domain::types::{Role, TicketStatus};
    use crate::engine::orchestration::WorkNodeId;

    #[test]
    fn scan_keys_are_namespaced_by_status_and_digests_are_validated() {
        let key = TicketScanKey {
            project_id: crate::domain::ids::ProjectId::parse("project-a").unwrap(),
            adapter_id: crate::domain::ids::AdapterId::parse("tickets").unwrap(),
            namespace: crate::domain::ids::TicketNamespace::parse("fixture-v1").unwrap(),
            scope_digest: crate::domain::ids::Digest::parse("a".repeat(64)).unwrap(),
            filter_digest: crate::domain::ids::Digest::parse("b".repeat(64)).unwrap(),
            status: TicketStatus::Ready,
        };
        assert!(key.validate().is_ok());
        assert_eq!(status_key(TicketStatus::InReview), "in_review");
        assert_eq!(
            TicketScanCursor {
                cursor: None,
                generation: 0,
                page_count: 0,
                started_at_unix: 0,
                last_page_at_unix: None,
                completed_at_unix: None,
                next_due_at_unix: 0,
                last_served_sequence: 0,
            }
            .page_count,
            0
        );
    }

    #[test]
    fn pending_ticket_observations_filter_and_bound_in_stable_order() {
        use super::ConfigStore;
        use crate::store::MachineLock;

        let path = std::env::temp_dir().join(format!(
            "rex-ticket-observations-{}.sqlite",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let connection = Connection::open(&path).unwrap();
        connection.execute_batch(
            "CREATE TABLE ticket_observations(project_id TEXT,adapter_id TEXT,namespace TEXT,ticket_id TEXT,scope_digest TEXT,filter_digest TEXT,external_revision TEXT,status TEXT,title TEXT,labels_json TEXT,last_seen_at_unix INTEGER,dispatch_state TEXT);
             CREATE TABLE ticket_claims(namespace TEXT,ticket_id TEXT,ticket_run_id TEXT);
             INSERT INTO ticket_observations VALUES
               ('project-a','tickets','fixture-v1','later','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',NULL,'ready','Later','[]',20,'pending'),
               ('project-a','tickets','fixture-v1','first-b','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',NULL,'ready','First B','[]',10,'pending'),
               ('project-a','tickets','fixture-v1','first-a','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',NULL,'ready','First A','[]',10,'pending'),
               ('project-a','tickets','fixture-v1','wrong-status','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',NULL,'done','Done','[]',1,'pending');",
        ).unwrap();
        drop(connection);
        let store = ConfigStore {
            connection: Connection::open(&path).unwrap(),
            _machine_lock: MachineLock { _file: None },
        };
        let key = TicketScanKey {
            project_id: crate::domain::ids::ProjectId::parse("project-a").unwrap(),
            adapter_id: crate::domain::ids::AdapterId::parse("tickets").unwrap(),
            namespace: crate::domain::ids::TicketNamespace::parse("fixture-v1").unwrap(),
            scope_digest: crate::domain::ids::Digest::parse("a".repeat(64)).unwrap(),
            filter_digest: crate::domain::ids::Digest::parse("b".repeat(64)).unwrap(),
            status: TicketStatus::Ready,
        };
        let page = store.pending_ticket_observations(&key, 2).unwrap();
        assert_eq!(
            page.iter()
                .map(|item| item.ticket_id.as_str())
                .collect::<Vec<_>>(),
            ["first-a", "first-b"]
        );
        drop(store);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn schema_v9_adds_project_scoped_scheduler_and_goal_ledgers() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at_unix INTEGER NOT NULL);
                 CREATE TABLE projects(project_id TEXT PRIMARY KEY);
                 CREATE TABLE ticket_runs(ticket_run_id TEXT PRIMARY KEY);
                 PRAGMA user_version=8;",
            )
            .unwrap();
        migrate_v9(&connection).unwrap();
        let version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, 9);
        let tables: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('ticket_scan_cursors','ticket_observations','ticket_run_context','ticket_scan_sequence','goal_runtime','goal_ticket_requests','goal_ticket_candidates')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(tables, 7);
        assert!(migrate_v9(&connection).is_err());
    }

    #[test]
    fn pending_wake_scheduling_orders_priority_and_suppresses_active_runs() {
        use super::ConfigStore;
        use crate::store::MachineLock;

        let connection = Connection::open_in_memory().unwrap();
        connection.execute_batch(
            "CREATE TABLE controller_owners(generation INTEGER PRIMARY KEY, stopped_at_unix INTEGER);
             CREATE TABLE projects(project_id TEXT PRIMARY KEY, desired_lifecycle TEXT NOT NULL);
             CREATE TABLE project_runtimes(project_id TEXT PRIMARY KEY, observed_lifecycle TEXT NOT NULL, controller_generation INTEGER NOT NULL);
             CREATE TABLE agent_runs(agent_run_id TEXT PRIMARY KEY, role_session_id TEXT NOT NULL, state TEXT NOT NULL);
             CREATE TABLE role_wake_inputs(project_id TEXT NOT NULL, role_session_id TEXT NOT NULL, lifecycle TEXT NOT NULL, priority INTEGER NOT NULL, created_at_unix INTEGER NOT NULL);
             INSERT INTO controller_owners VALUES (7,NULL);
             INSERT INTO projects VALUES ('p-a','running'),('p-b','running');
             INSERT INTO project_runtimes VALUES ('p-a','running',7),('p-b','running',7);
             INSERT INTO role_wake_inputs VALUES ('p-a','ticket_run:r-a:coordinator','pending',2,10),('p-a','ticket_run:r-a:coordinator','pending',8,20),('p-b','project:p-b:supervisor','pending',9,15);
             INSERT INTO agent_runs VALUES ('run-active','project:p-b:supervisor','running');",
        ).unwrap();
        let store = ConfigStore {
            connection,
            _machine_lock: MachineLock { _file: None },
        };

        let wakes = store.pending_role_wake_sessions(7, 10).unwrap();
        assert_eq!(wakes.len(), 1);
        assert_eq!(
            wakes[0],
            PendingRoleWakeSession {
                project_id: crate::domain::ids::ProjectId::parse("p-a").unwrap(),
                role_session_id: "ticket_run:r-a:coordinator".into(),
                role: Role::Coordinator,
                ticket_run_id: Some(crate::domain::ids::TicketRunId::parse("r-a").unwrap()),
                work_node_id: None,
                highest_priority: 8,
                oldest_created_at_unix: 10,
                pending_count: 2,
            }
        );
        assert!(store.pending_role_wake_sessions(8, 10).is_err());
    }

    #[test]
    fn role_session_ids_bind_their_project_or_ticket_scope() {
        use super::parse_role_session_id;
        use crate::domain::types::Role;

        assert_eq!(
            parse_role_session_id("project:p-a:supervisor").unwrap(),
            (Role::Supervisor, None, None)
        );
        assert_eq!(
            parse_role_session_id("ticket_run:run:with:colon:merge_decision").unwrap(),
            (
                Role::MergeDecision,
                Some(crate::domain::ids::TicketRunId::parse("run:with:colon").unwrap()),
                None,
            )
        );
        assert_eq!(
            parse_role_session_id("ticket:run-1:worker:node-a").unwrap(),
            (
                Role::Worker,
                Some(crate::domain::ids::TicketRunId::parse("run-1").unwrap()),
                Some(WorkNodeId::parse("node-a").unwrap()),
            )
        );
        assert_eq!(
            parse_role_session_id("ticket_run:run:worker").unwrap(),
            (
                Role::Worker,
                Some(crate::domain::ids::TicketRunId::parse("run").unwrap()),
                None,
            )
        );
        assert!(parse_role_session_id("project:p-a:worker").is_err());
        assert!(parse_role_session_id("ticket_run:run:unknown").is_err());
    }
}
