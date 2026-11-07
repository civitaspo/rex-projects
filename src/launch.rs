//! Typed host/provider handoff records for finite Agent runs.
//!
//! These records cross the run-local mailbox boundary. They never contain the
//! environment snapshot itself or grant authority on their own: the controller
//! matches each request against its SQLite AgentRun and qualification records.

use std::collections::BTreeSet;
use std::path::PathBuf;

use rusqlite::{Connection, Transaction, TransactionBehavior};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::domain::ids::{
    AgentRunId, Digest as ContentDigest, OperationId, ProfileId, ProjectId, Revision, TicketId,
    TicketNamespace, TicketRunId,
};
use crate::domain::types::{AgentAdapter, CommitMode, Role};

pub const QUALIFICATION_SCHEMA_VERSION: u32 = 1;
pub const LAUNCH_SCHEMA_VERSION: u32 = 1;
pub const LAUNCH_DATABASE_SCHEMA_VERSION: i64 = 7;

/// Minimal durable StartAgent intent. Handlers resolve authority from controller-owned state.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartAgentEffectPayload {
    pub schema_version: u32,
    pub agent_run_id: AgentRunId,
    pub launch_reservation_digest: ContentDigest,
}

impl StartAgentEffectPayload {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != LAUNCH_SCHEMA_VERSION {
            return Err("unsupported StartAgent effect payload schema".into());
        }
        Ok(())
    }
}

/// Host-owned phase-one launch identity. Rex block identity is bound only after it is observed.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentLaunchReservation {
    pub schema_version: u32,
    pub agent_run_id: AgentRunId,
    pub project_id: ProjectId,
    pub role: Role,
    pub role_session_id: String,
    pub parent_run_id: Option<AgentRunId>,
    pub parent_role: Option<Role>,
    pub ticket_run_id: Option<TicketRunId>,
    pub ticket_revision: Option<Revision>,
    pub config_revision: Revision,
    pub config_digest: ContentDigest,
    pub attempt: u32,
    pub run_epoch: u64,
    pub controller_generation: u64,
    pub project_epoch: u64,
    pub operation_id: OperationId,
    pub operation_recipe_id: Option<String>,
    pub rex_view_id: ContentDigest,
    pub runtime_binary_digest: ContentDigest,
    pub environment_snapshot_id: ContentDigest,
    pub profile_id: ProfileId,
    pub profile_digest: ContentDigest,
    pub instruction_digest: ContentDigest,
    pub result_schema_digest: ContentDigest,
    pub wake_snapshot: crate::agent_api::AgentWakeSnapshot,
    pub qualification_receipt_digest: ContentDigest,
    pub descriptor_path: PathBuf,
    pub workspace_path: PathBuf,
    pub control_dir: PathBuf,
    pub mailbox_directory: PathBuf,
    pub mailbox_capability_digest: ContentDigest,
    pub mailbox_expires_at_unix: u64,
    pub mailbox_max_request_bytes: u64,
    pub mailbox_max_pending_requests: u32,
    pub pool: String,
    pub slot_index: u32,
    pub global_capacity: u32,
    pub project_capacity: u32,
}

impl AgentLaunchReservation {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != LAUNCH_SCHEMA_VERSION
            || self.attempt == 0
            || self.run_epoch == 0
            || self.controller_generation == 0
            || self.project_epoch == 0
            || self.mailbox_expires_at_unix == 0
            || self.mailbox_max_request_bytes == 0
            || self.mailbox_max_pending_requests == 0
            || self.global_capacity == 0
            || self.project_capacity == 0
            || !matches!(self.pool.as_str(), "agent" | "rex_projects_hook")
        {
            return Err("Agent launch reservation has an invalid schema, counter, or limit".into());
        }
        if self.parent_run_id.is_some() != self.parent_role.is_some() {
            return Err("reservation parent AgentRun ID and role must be present together".into());
        }
        if self.role == Role::Supervisor {
            if self.ticket_run_id.is_some() || self.ticket_revision.is_some() {
                return Err("Project Supervisor reservation cannot have a TicketRun".into());
            }
        } else if self.ticket_run_id.is_none() || self.ticket_revision.is_none() {
            return Err("ticket role reservation requires a TicketRun and revision".into());
        }
        for path in [
            &self.descriptor_path,
            &self.workspace_path,
            &self.control_dir,
            &self.mailbox_directory,
        ] {
            if !path.is_absolute() {
                return Err("reservation paths must be absolute".into());
            }
        }
        if self.wake_snapshot.project_id != self.project_id
            || self.wake_snapshot.agent_run_id != self.agent_run_id.as_str()
            || self.wake_snapshot.role_session_id != self.role_session_id
        {
            return Err("wake snapshot scope does not match launch reservation".into());
        }
        self.wake_snapshot.validate()
    }

    pub fn digest(&self) -> Result<ContentDigest, String> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        ContentDigest::parse(format!("{:x}", Sha256::digest(bytes)))
    }
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RexViewKind {
    Supervisor,
    Ticket,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RexView {
    pub view_id: ContentDigest,
    pub project_id: ProjectId,
    pub kind: RexViewKind,
    pub ticket_namespace: Option<String>,
    pub ticket_id: Option<String>,
    pub view_epoch: u64,
    pub rex_server_identity: String,
    pub rex_session_id: String,
    pub rex_window_id: String,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RexViewRecord {
    pub view: RexView,
    pub pinned: bool,
    pub lifecycle: String,
    pub created_at_unix: u64,
    pub updated_at_unix: u64,
    pub closed_at_unix: Option<u64>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RexViewCleanupCandidate {
    pub view: RexView,
    pub close_after_unix: u64,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RexFocusTarget {
    pub view_id: ContentDigest,
    pub rex_server_identity: String,
    pub rex_session_id: String,
    pub rex_window_id: String,
    pub rex_block_id: String,
}

impl RexView {
    pub fn derive_id(
        project_id: &ProjectId,
        kind: RexViewKind,
        ticket_namespace: Option<&str>,
        ticket_id: Option<&str>,
        view_epoch: u64,
    ) -> Result<ContentDigest, String> {
        let bytes = serde_json::to_vec(&(
            "rex-projects-view-v1",
            project_id,
            kind,
            ticket_namespace,
            ticket_id,
            view_epoch,
        ))
        .map_err(|error| error.to_string())?;
        ContentDigest::parse(format!("{:x}", Sha256::digest(bytes)))
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.view_epoch == 0
            || self.rex_server_identity.trim().is_empty()
            || self.rex_session_id.trim().is_empty()
            || self.rex_window_id.trim().is_empty()
            || self.rex_server_identity.chars().any(char::is_control)
            || self.rex_session_id.chars().any(char::is_control)
            || self.rex_window_id.chars().any(char::is_control)
        {
            return Err("Rex view identity is incomplete".into());
        }
        let ticket_scoped = self.ticket_namespace.is_some() && self.ticket_id.is_some();
        if (self.kind == RexViewKind::Ticket) != ticket_scoped {
            return Err("Rex view kind and ticket scope do not match".into());
        }
        if self
            .ticket_namespace
            .as_ref()
            .is_some_and(|value| value.trim().is_empty())
            || self
                .ticket_id
                .as_ref()
                .is_some_and(|value| value.trim().is_empty())
        {
            return Err("Rex view ticket scope is empty".into());
        }
        if let (Some(namespace), Some(ticket)) = (&self.ticket_namespace, &self.ticket_id) {
            TicketNamespace::parse(namespace.clone())?;
            TicketId::parse(ticket.clone())?;
        }
        if self.view_id
            != Self::derive_id(
                &self.project_id,
                self.kind,
                self.ticket_namespace.as_deref(),
                self.ticket_id.as_deref(),
                self.view_epoch,
            )?
        {
            return Err("Rex view ID does not match its stable scope and epoch".into());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RexBlockOwnership {
    Factory,
    User,
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RexBlockLifecycle {
    Active,
    Completed,
    Failed,
    Unknown,
    Closed,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RexViewBlock {
    pub view_id: ContentDigest,
    pub block_id: String,
    pub agent_run_id: Option<AgentRunId>,
    pub role: Option<Role>,
    pub ownership: RexBlockOwnership,
    pub lifecycle: RexBlockLifecycle,
    pub process_absent_confirmed: bool,
    pub retained_until_unix: Option<u64>,
}

impl RexViewBlock {
    pub fn validate(&self) -> Result<(), String> {
        if self.block_id.trim().is_empty() || self.block_id.chars().any(char::is_control) {
            return Err("Rex block identity is malformed".into());
        }
        let factory_scope = self.agent_run_id.is_some() && self.role.is_some();
        if (self.ownership == RexBlockOwnership::Factory) != factory_scope {
            return Err("Rex block ownership and AgentRun scope do not match".into());
        }
        if self.lifecycle == RexBlockLifecycle::Unknown && self.process_absent_confirmed {
            return Err("unknown Rex block cannot be marked process-absent confirmed".into());
        }
        Ok(())
    }
}

/// Apply the PR3 launch-authority migration after the PR2 controller migrations. The caller
/// must create its normal pre-migration backup before invoking this function.
pub fn migrate_v7(connection: &mut Connection) -> Result<(), String> {
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| error.to_string())?;
    if version == LAUNCH_DATABASE_SCHEMA_VERSION {
        return Ok(());
    }
    if version != 6 {
        return Err(format!(
            "PR3 launch migration requires schema 6, found {version}"
        ));
    }

    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| error.to_string())?;
    tx.execute_batch(
        "CREATE TABLE provider_qualifications (
            receipt_digest TEXT PRIMARY KEY CHECK(length(receipt_digest) = 64),
            project_id TEXT NOT NULL REFERENCES projects(project_id),
            profile_id TEXT NOT NULL,
            profile_digest TEXT NOT NULL CHECK(length(profile_digest) = 64),
            adapter TEXT NOT NULL CHECK(adapter IN ('codex','claude_code')),
            executable_path TEXT NOT NULL,
            executable_digest TEXT NOT NULL CHECK(length(executable_digest) = 64),
            provider_version TEXT NOT NULL,
            permission_mode TEXT NOT NULL,
            invocation_options_digest TEXT NOT NULL CHECK(length(invocation_options_digest) = 64),
            commit_mode TEXT NOT NULL CHECK(commit_mode IN ('auto','native','host')),
            status TEXT NOT NULL CHECK(status IN ('verified','fixture_only','unknown')),
            receipt_json TEXT NOT NULL CHECK(length(receipt_json) <= 1048576),
            created_by_generation INTEGER NOT NULL,
            created_at_unix INTEGER NOT NULL
        );
        CREATE TRIGGER provider_qualifications_immutable_update
        BEFORE UPDATE ON provider_qualifications
        BEGIN SELECT RAISE(ABORT, 'provider qualification receipts are immutable'); END;
        CREATE TRIGGER provider_qualifications_immutable_delete
        BEFORE DELETE ON provider_qualifications
        BEGIN SELECT RAISE(ABORT, 'provider qualification receipts are retained'); END;

        CREATE TABLE rex_views (
            view_id TEXT PRIMARY KEY CHECK(length(view_id) = 64),
            project_id TEXT NOT NULL REFERENCES projects(project_id),
            view_kind TEXT NOT NULL CHECK(view_kind IN ('supervisor','ticket')),
            ticket_namespace TEXT,
            ticket_id TEXT,
            view_epoch INTEGER NOT NULL CHECK(view_epoch > 0),
            rex_server_identity TEXT NOT NULL,
            rex_session_id TEXT NOT NULL,
            rex_window_id TEXT NOT NULL,
            pinned INTEGER NOT NULL DEFAULT 0 CHECK(pinned IN (0,1)),
            lifecycle TEXT NOT NULL CHECK(lifecycle IN ('active','close_pending','closed','unknown')),
            created_at_unix INTEGER NOT NULL,
            updated_at_unix INTEGER NOT NULL,
            closed_at_unix INTEGER,
            CHECK((view_kind='supervisor' AND ticket_namespace IS NULL AND ticket_id IS NULL) OR
                  (view_kind='ticket' AND ticket_namespace IS NOT NULL AND ticket_id IS NOT NULL))
        );
        CREATE UNIQUE INDEX rex_views_one_open_supervisor
            ON rex_views(project_id) WHERE view_kind='supervisor' AND lifecycle IN ('active','close_pending','unknown');
        CREATE UNIQUE INDEX rex_views_one_open_ticket
            ON rex_views(project_id,ticket_namespace,ticket_id) WHERE view_kind='ticket' AND lifecycle IN ('active','close_pending','unknown');
        CREATE INDEX rex_views_cleanup ON rex_views(lifecycle,pinned,updated_at_unix);

        CREATE TABLE rex_view_blocks (
            view_id TEXT NOT NULL REFERENCES rex_views(view_id),
            block_id TEXT NOT NULL,
            agent_run_id TEXT REFERENCES agent_runs(agent_run_id),
            role TEXT CHECK(role IS NULL OR role IN ('supervisor','coordinator','planner','worker','reviewer','merge_decision','operator','postmortem')),
            ownership TEXT NOT NULL CHECK(ownership IN ('factory','user')),
            lifecycle TEXT NOT NULL CHECK(lifecycle IN ('active','completed','failed','unknown','closed')),
            process_absent_confirmed INTEGER NOT NULL DEFAULT 0 CHECK(process_absent_confirmed IN (0,1)),
            created_at_unix INTEGER NOT NULL,
            last_observed_at_unix INTEGER NOT NULL,
            terminal_at_unix INTEGER,
            retained_until_unix INTEGER,
            PRIMARY KEY(view_id,block_id),
            CHECK((ownership='user' AND agent_run_id IS NULL AND role IS NULL) OR
                  (ownership='factory' AND agent_run_id IS NOT NULL AND role IS NOT NULL))
        );
        CREATE INDEX rex_view_blocks_lifecycle ON rex_view_blocks(view_id,lifecycle,ownership);
        CREATE TRIGGER rex_view_block_identity_guard
        BEFORE UPDATE ON rex_view_blocks
        WHEN OLD.view_id IS NOT NEW.view_id
          OR OLD.block_id IS NOT NEW.block_id
          OR OLD.agent_run_id IS NOT NEW.agent_run_id
          OR OLD.role IS NOT NEW.role
          OR OLD.ownership IS NOT NEW.ownership
        BEGIN SELECT RAISE(ABORT, 'Rex view block identity is immutable'); END;

        CREATE TABLE agent_launch_authority (
            agent_run_id TEXT PRIMARY KEY REFERENCES agent_runs(agent_run_id),
            project_id TEXT NOT NULL REFERENCES projects(project_id),
            role TEXT NOT NULL CHECK(role IN ('supervisor','coordinator','planner','worker','reviewer','merge_decision','operator','postmortem')),
            role_session_id TEXT NOT NULL,
            parent_run_id TEXT REFERENCES agent_runs(agent_run_id),
            parent_role TEXT CHECK(parent_role IS NULL OR parent_role IN ('supervisor','coordinator','planner','worker','reviewer','merge_decision','operator','postmortem')),
            ticket_run_id TEXT REFERENCES ticket_runs(ticket_run_id),
            ticket_revision INTEGER CHECK(ticket_revision IS NULL OR ticket_revision >= 0),
            config_revision INTEGER NOT NULL CHECK(config_revision > 0),
            config_digest TEXT NOT NULL CHECK(length(config_digest) = 64),
            attempt INTEGER NOT NULL CHECK(attempt > 0),
            run_epoch INTEGER NOT NULL CHECK(run_epoch > 0),
            controller_generation INTEGER NOT NULL CHECK(controller_generation > 0),
            launch_operation_id TEXT NOT NULL UNIQUE,
            operation_recipe_id TEXT,
            rex_view_id TEXT NOT NULL REFERENCES rex_views(view_id),
            descriptor_digest TEXT NOT NULL CHECK(length(descriptor_digest) = 64),
            runtime_binary_digest TEXT NOT NULL CHECK(length(runtime_binary_digest) = 64),
            descriptor_path TEXT NOT NULL,
            environment_snapshot_id TEXT NOT NULL CHECK(length(environment_snapshot_id) = 64),
            profile_id TEXT NOT NULL,
            profile_digest TEXT NOT NULL CHECK(length(profile_digest) = 64),
            instruction_digest TEXT NOT NULL CHECK(length(instruction_digest) = 64),
            result_schema_digest TEXT NOT NULL CHECK(length(result_schema_digest) = 64),
            qualification_receipt_digest TEXT NOT NULL REFERENCES provider_qualifications(receipt_digest),
            rex_server_identity TEXT NOT NULL,
            rex_session_id TEXT NOT NULL,
            rex_window_id TEXT NOT NULL,
            rex_block_id TEXT NOT NULL,
            workspace_path TEXT NOT NULL,
            control_dir TEXT NOT NULL,
            mailbox_capability_digest TEXT NOT NULL CHECK(length(mailbox_capability_digest) = 64),
            authority_json TEXT NOT NULL CHECK(length(authority_json) <= 1048576),
            authority_digest TEXT NOT NULL CHECK(length(authority_digest) = 64),
            created_at_unix INTEGER NOT NULL,
            CHECK((parent_run_id IS NULL) = (parent_role IS NULL)),
            CHECK((role = 'supervisor' AND ticket_run_id IS NULL AND ticket_revision IS NULL) OR (role != 'supervisor' AND ticket_run_id IS NOT NULL AND ticket_revision IS NOT NULL))
        );
        CREATE TRIGGER agent_launch_authority_immutable_update
        BEFORE UPDATE ON agent_launch_authority
        BEGIN SELECT RAISE(ABORT, 'Agent launch authority is immutable'); END;
        CREATE TRIGGER agent_launch_authority_immutable_delete
        BEFORE DELETE ON agent_launch_authority
        BEGIN SELECT RAISE(ABORT, 'Agent launch authority is retained'); END;
        CREATE INDEX agent_launch_authority_project_ticket
            ON agent_launch_authority(project_id,ticket_run_id,role,created_at_unix);

        CREATE TABLE agent_launch_state (
            agent_run_id TEXT PRIMARY KEY REFERENCES agent_launch_authority(agent_run_id),
            state TEXT NOT NULL CHECK(state IN ('prepared','block_created','awaiting_provider','running','completed','failed','cancelled','unknown')),
            start_request_id TEXT,
            start_request_digest TEXT CHECK(start_request_digest IS NULL OR length(start_request_digest) = 64),
            wrapper_process_identity_json TEXT,
            launch_receipt_json TEXT,
            provider_process_tree_json TEXT,
            terminal_request_id TEXT,
            terminal_request_digest TEXT CHECK(terminal_request_digest IS NULL OR length(terminal_request_digest) = 64),
            result_digest TEXT CHECK(result_digest IS NULL OR length(result_digest) = 64),
            result_receipt_json TEXT,
            last_observed_at_unix INTEGER NOT NULL,
            updated_at_unix INTEGER NOT NULL
        );
        CREATE TRIGGER agent_launch_state_transition_guard
        BEFORE UPDATE OF state ON agent_launch_state
        WHEN OLD.state <> NEW.state AND NOT (
            (OLD.state = 'prepared' AND NEW.state IN ('block_created','unknown','cancelled')) OR
            (OLD.state = 'block_created' AND NEW.state IN ('awaiting_provider','unknown','cancelled')) OR
            (OLD.state = 'awaiting_provider' AND NEW.state IN ('running','failed','unknown','cancelled')) OR
            (OLD.state = 'running' AND NEW.state IN ('completed','failed','unknown','cancelled')) OR
            (OLD.state = 'unknown' AND NEW.state IN ('awaiting_provider','running','completed','failed','cancelled'))
        )
        BEGIN SELECT RAISE(ABORT, 'invalid Agent launch state transition'); END;
        CREATE TRIGGER agent_launch_state_identity_guard
        BEFORE UPDATE ON agent_launch_state
        WHEN (OLD.start_request_id IS NOT NULL AND NEW.start_request_id IS NOT OLD.start_request_id)
          OR (OLD.start_request_digest IS NOT NULL AND NEW.start_request_digest IS NOT OLD.start_request_digest)
          OR (OLD.wrapper_process_identity_json IS NOT NULL AND NEW.wrapper_process_identity_json IS NOT OLD.wrapper_process_identity_json)
          OR (OLD.launch_receipt_json IS NOT NULL AND NEW.launch_receipt_json IS NOT OLD.launch_receipt_json)
          OR (OLD.terminal_request_id IS NOT NULL AND NEW.terminal_request_id IS NOT OLD.terminal_request_id)
          OR (OLD.terminal_request_digest IS NOT NULL AND NEW.terminal_request_digest IS NOT OLD.terminal_request_digest)
          OR (OLD.result_digest IS NOT NULL AND NEW.result_digest IS NOT OLD.result_digest)
          OR (OLD.result_receipt_json IS NOT NULL AND NEW.result_receipt_json IS NOT OLD.result_receipt_json)
        BEGIN SELECT RAISE(ABORT, 'Agent launch receipt identity is immutable'); END;

        CREATE TABLE agent_result_evidence (
            evidence_id TEXT PRIMARY KEY,
            agent_run_id TEXT NOT NULL REFERENCES agent_launch_authority(agent_run_id),
            project_id TEXT NOT NULL REFERENCES projects(project_id),
            role TEXT NOT NULL CHECK(role IN ('supervisor','coordinator','planner','worker','reviewer','merge_decision','operator','postmortem')),
            ticket_run_id TEXT REFERENCES ticket_runs(ticket_run_id),
            attempt INTEGER NOT NULL CHECK(attempt > 0),
            run_epoch INTEGER NOT NULL CHECK(run_epoch > 0),
            message_id TEXT NOT NULL,
            content_digest TEXT NOT NULL CHECK(length(content_digest) = 64),
            outcome TEXT NOT NULL CHECK(outcome IN ('completed','provider_failed','timed_out','cancelled','missing_result')),
            result_digest TEXT CHECK(result_digest IS NULL OR length(result_digest) = 64),
            result_json TEXT CHECK(result_json IS NULL OR length(result_json) <= 1048576),
            artifact_refs_json TEXT NOT NULL CHECK(length(artifact_refs_json) <= 262144),
            received_at_unix INTEGER NOT NULL,
            UNIQUE(agent_run_id,message_id)
        );
        CREATE TABLE agent_result_wakes (
            evidence_id TEXT PRIMARY KEY REFERENCES agent_result_evidence(evidence_id),
            recipient_type TEXT NOT NULL CHECK(recipient_type IN ('coordinator','supervisor')),
            recipient_id TEXT NOT NULL,
            wake_input_id INTEGER REFERENCES role_wake_inputs(wake_input_id),
            queued_at_unix INTEGER NOT NULL
        );
        CREATE TRIGGER agent_result_evidence_immutable_update
        BEFORE UPDATE ON agent_result_evidence
        BEGIN SELECT RAISE(ABORT, 'Agent result evidence is immutable'); END;
        CREATE TRIGGER agent_result_evidence_immutable_delete
        BEFORE DELETE ON agent_result_evidence
        BEGIN SELECT RAISE(ABORT, 'Agent result evidence is retained'); END;

        INSERT INTO schema_migrations(version, applied_at_unix) VALUES (7, unixepoch());
        PRAGMA user_version = 7;",
    )
    .map_err(|error| error.to_string())?;
    migrate_launch_reservation_tables(&tx)?;
    tx.commit().map_err(|error| error.to_string())
}

/// Ensure the durable StartAgent reservation projection exists. Schema-v7 uses this in its
/// migration transaction; the central v12 upgrade also repairs databases whose recorded v7
/// layout predates the table. Layout validation rejects incompatible pre-existing tables.
pub(crate) fn migrate_launch_reservation_tables(tx: &Transaction<'_>) -> Result<(), String> {
    tx.execute_batch(
        "CREATE TABLE IF NOT EXISTS agent_launch_reservations (
            agent_run_id TEXT PRIMARY KEY REFERENCES agent_runs(agent_run_id),
            project_id TEXT NOT NULL REFERENCES projects(project_id),
            operation_id TEXT NOT NULL UNIQUE,
            controller_generation INTEGER NOT NULL CHECK(controller_generation > 0),
            project_epoch INTEGER NOT NULL CHECK(project_epoch > 0),
            reservation_digest TEXT NOT NULL CHECK(length(reservation_digest) = 64),
            reservation_json TEXT NOT NULL CHECK(length(reservation_json) <= 1048576),
            lifecycle TEXT NOT NULL CHECK(lifecycle IN ('reserved','block_created','authorized','unknown','cancelled')),
            created_at_unix INTEGER NOT NULL,
            updated_at_unix INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS agent_launch_reservations_project
            ON agent_launch_reservations(project_id,lifecycle,created_at_unix);
        CREATE TRIGGER IF NOT EXISTS agent_launch_reservation_identity_guard
        BEFORE UPDATE ON agent_launch_reservations
        WHEN OLD.agent_run_id IS NOT NEW.agent_run_id
          OR OLD.project_id IS NOT NEW.project_id
          OR OLD.operation_id IS NOT NEW.operation_id
          OR OLD.controller_generation IS NOT NEW.controller_generation
          OR OLD.project_epoch IS NOT NEW.project_epoch
          OR OLD.reservation_digest IS NOT NEW.reservation_digest
          OR OLD.reservation_json IS NOT NEW.reservation_json
          OR OLD.created_at_unix IS NOT NEW.created_at_unix
        BEGIN SELECT RAISE(ABORT, 'Agent launch reservation identity is immutable'); END;
        CREATE TRIGGER IF NOT EXISTS agent_launch_reservation_no_delete
        BEFORE DELETE ON agent_launch_reservations
        BEGIN SELECT RAISE(ABORT, 'Agent launch reservations are retained'); END;",
    )
    .map_err(|error| error.to_string())
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualificationStatus {
    Verified,
    FixtureOnly,
    Unknown,
}

/// Facts from a disposable provider qualification run, without environment values.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationProof {
    pub schema_version: u32,
    pub probe_id: String,
    pub fixture_digest: ContentDigest,
    pub rex_instance_id: String,
    pub tool_shell_marker_digest: ContentDigest,
    pub tool_shell_markers_present: BTreeSet<String>,
    pub descendant_marker_digest: ContentDigest,
    pub descendant_markers_present: BTreeSet<String>,
    pub automatic_turn_result_digest: ContentDigest,
    pub automatic_turn_completed: bool,
    pub structured_result_valid: bool,
    pub observed_permission_mode: String,
    pub permission_prompt_count: u32,
    pub cleanup_process_tree_digest: ContentDigest,
    pub process_tree_absent: bool,
    pub cleanup_confirmed: bool,
}

impl QualificationProof {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != QUALIFICATION_SCHEMA_VERSION {
            return Err("unsupported qualification proof schema".into());
        }
        for (name, value) in [
            ("probe_id", self.probe_id.as_str()),
            ("rex_instance_id", self.rex_instance_id.as_str()),
            (
                "observed_permission_mode",
                self.observed_permission_mode.as_str(),
            ),
        ] {
            if value.trim().is_empty() || value.chars().any(char::is_control) {
                return Err(format!("qualification proof has invalid {name}"));
            }
        }
        let required_markers = [
            "REX_PROJECTS_AGENT",
            "REX_PROJECTS_CONTEXT",
            "REX_PROJECTS_PROJECT_ID",
            "REX_PROJECTS_ROLE",
            "REX_PROJECTS_RUN_ID",
        ];
        if required_markers
            .iter()
            .any(|marker| !self.tool_shell_markers_present.contains(*marker))
            || required_markers
                .iter()
                .any(|marker| !self.descendant_markers_present.contains(*marker))
        {
            return Err("qualification did not verify all required factory markers".into());
        }
        if !self.automatic_turn_completed || !self.structured_result_valid {
            return Err("qualification did not complete a valid structured automatic turn".into());
        }
        if self.permission_prompt_count != 0 {
            return Err("qualification encountered an unhandled permission prompt".into());
        }
        if !self.process_tree_absent || !self.cleanup_confirmed {
            return Err("qualification did not confirm provider process cleanup".into());
        }
        Ok(())
    }
}

/// Immutable identity against which a launch request is checked by the host.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderQualification {
    pub schema_version: u32,
    pub project_id: ProjectId,
    pub profile_id: ProfileId,
    pub profile_digest: ContentDigest,
    pub adapter: AgentAdapter,
    pub executable_path: String,
    pub executable_digest: ContentDigest,
    pub provider_version: String,
    pub permission_mode: String,
    pub invocation_options_digest: ContentDigest,
    pub commit_mode: CommitMode,
    pub proof: QualificationProof,
    pub status: QualificationStatus,
}

impl ProviderQualification {
    /// Hashes the canonical serialized qualification. The receipt digest is stored separately
    /// and is never trusted when supplied by an Agent or run-local descriptor.
    pub fn canonical_digest(&self) -> Result<ContentDigest, String> {
        let bytes = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        let digest = format!("{:x}", Sha256::digest(bytes));
        ContentDigest::parse(digest)
    }

    pub fn validate_for_unattended_launch(&self) -> Result<(), String> {
        if self.schema_version != QUALIFICATION_SCHEMA_VERSION {
            return Err("unsupported provider qualification schema".into());
        }
        if self.status != QualificationStatus::Verified {
            return Err(format!(
                "provider qualification status is {:?}; unattended launch requires verified",
                self.status
            ));
        }
        if !std::path::Path::new(&self.executable_path).is_absolute() {
            return Err("qualified provider executable path must be absolute".into());
        }
        if self.provider_version.trim().is_empty()
            || self.permission_mode.trim().is_empty()
            || self.executable_path.chars().any(char::is_control)
        {
            return Err("provider qualification identity is incomplete".into());
        }
        self.proof.validate()
    }

    pub fn validate_for_storage(&self) -> Result<(), String> {
        if self.schema_version != QUALIFICATION_SCHEMA_VERSION {
            return Err("unsupported provider qualification schema".into());
        }
        if !std::path::Path::new(&self.executable_path).is_absolute()
            || self.provider_version.trim().is_empty()
            || self.permission_mode.trim().is_empty()
            || self.executable_path.chars().any(char::is_control)
        {
            return Err("provider qualification identity is incomplete".into());
        }
        self.proof.validate()?;
        if self.status == QualificationStatus::Verified {
            self.validate_for_unattended_launch()?;
        }
        Ok(())
    }

    pub fn matches_launch(&self, expected: &QualificationIdentity) -> Result<(), String> {
        self.validate_for_unattended_launch()?;
        if self.project_id != expected.project_id
            || self.profile_id != expected.profile_id
            || self.profile_digest != expected.profile_digest
            || self.adapter != expected.adapter
            || self.executable_path != expected.executable_path
            || self.executable_digest != expected.executable_digest
            || self.provider_version != expected.provider_version
            || self.permission_mode != expected.permission_mode
            || self.invocation_options_digest != expected.invocation_options_digest
            || self.commit_mode != expected.commit_mode
            || self.proof.observed_permission_mode != self.permission_mode
        {
            return Err(
                "stored provider qualification does not match the applied launch profile".into(),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq)]
pub struct QualificationIdentity {
    pub project_id: ProjectId,
    pub profile_id: ProfileId,
    pub profile_digest: ContentDigest,
    pub adapter: AgentAdapter,
    pub executable_path: String,
    pub executable_digest: ContentDigest,
    pub provider_version: String,
    pub permission_mode: String,
    pub invocation_options_digest: ContentDigest,
    pub commit_mode: CommitMode,
}

/// Immutable host-owned descriptor binding stored before the provider is allowed to start.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentLaunchAuthority {
    pub agent_run_id: AgentRunId,
    pub project_id: ProjectId,
    pub role: Role,
    pub role_session_id: String,
    pub parent_run_id: Option<AgentRunId>,
    pub parent_role: Option<Role>,
    pub ticket_run_id: Option<TicketRunId>,
    pub ticket_revision: Option<Revision>,
    pub config_revision: Revision,
    pub config_digest: ContentDigest,
    pub attempt: u32,
    pub run_epoch: u64,
    pub controller_generation: u64,
    pub operation_id: OperationId,
    pub operation_recipe_id: Option<String>,
    pub rex_view_id: ContentDigest,
    pub descriptor_digest: ContentDigest,
    pub runtime_binary_digest: ContentDigest,
    pub descriptor_path: PathBuf,
    pub environment_snapshot_id: ContentDigest,
    pub profile_id: ProfileId,
    pub profile_digest: ContentDigest,
    pub instruction_digest: ContentDigest,
    pub result_schema_digest: ContentDigest,
    pub wake_snapshot_digest: ContentDigest,
    pub qualification_receipt_digest: ContentDigest,
    pub rex_server_identity: String,
    pub rex_session_id: String,
    pub rex_window_id: String,
    pub rex_block_id: String,
    pub workspace_path: PathBuf,
    pub control_dir: PathBuf,
    pub mailbox_capability_digest: ContentDigest,
}

impl AgentLaunchAuthority {
    pub fn validate(&self) -> Result<(), String> {
        if self.config_revision.0 == 0
            || self.attempt == 0
            || self.run_epoch == 0
            || self.controller_generation == 0
        {
            return Err("Agent launch authority has a zero revision or run counter".into());
        }
        if self.parent_run_id.is_some() != self.parent_role.is_some() {
            return Err("parent AgentRun ID and role must be present together".into());
        }
        if self
            .operation_recipe_id
            .as_ref()
            .is_some_and(|value| value.trim().is_empty() || value.chars().any(char::is_control))
        {
            return Err("Agent launch operation recipe ID is malformed".into());
        }
        if self.role == Role::Supervisor {
            if self.ticket_run_id.is_some() || self.ticket_revision.is_some() {
                return Err("Project Supervisor launch authority cannot have a TicketRun".into());
            }
        } else if self.ticket_run_id.is_none() || self.ticket_revision.is_none() {
            return Err(
                "ticket-scoped Agent launch authority requires a TicketRun and revision".into(),
            );
        }
        if self.descriptor_path.as_os_str().is_empty()
            || self.workspace_path.as_os_str().is_empty()
            || self.control_dir.as_os_str().is_empty()
            || !self.descriptor_path.is_absolute()
            || !self.workspace_path.is_absolute()
            || !self.control_dir.is_absolute()
        {
            return Err("Agent launch paths must be nonempty and absolute".into());
        }
        for (field, value) in [
            ("role_session_id", self.role_session_id.as_str()),
            ("rex_server_identity", self.rex_server_identity.as_str()),
            ("rex_session_id", self.rex_session_id.as_str()),
            ("rex_window_id", self.rex_window_id.as_str()),
            ("rex_block_id", self.rex_block_id.as_str()),
        ] {
            if value.trim().is_empty() || value.chars().any(char::is_control) {
                return Err(format!("Agent launch authority has invalid {field}"));
            }
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<ContentDigest, String> {
        let bytes = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        ContentDigest::parse(format!("{:x}", Sha256::digest(bytes)))
    }

    pub fn expectation(&self, qualification: &ProviderQualification) -> LaunchExpectation {
        LaunchExpectation {
            operation_id: self.operation_id.clone(),
            agent_run_id: self.agent_run_id.clone(),
            project_id: self.project_id.clone(),
            controller_generation: self.controller_generation,
            descriptor_digest: self.descriptor_digest.clone(),
            runtime_binary_digest: self.runtime_binary_digest.clone(),
            environment_snapshot_id: self.environment_snapshot_id.clone(),
            qualification_receipt_digest: self.qualification_receipt_digest.clone(),
            rex_session_id: self.rex_session_id.clone(),
            rex_block_id: self.rex_block_id.clone(),
            qualification_identity: QualificationIdentity {
                project_id: qualification.project_id.clone(),
                profile_id: qualification.profile_id.clone(),
                profile_digest: qualification.profile_digest.clone(),
                adapter: qualification.adapter,
                executable_path: qualification.executable_path.clone(),
                executable_digest: qualification.executable_digest.clone(),
                provider_version: qualification.provider_version.clone(),
                permission_mode: qualification.permission_mode.clone(),
                invocation_options_digest: qualification.invocation_options_digest.clone(),
                commit_mode: qualification.commit_mode,
            },
        }
    }
}

/// The process wrapper's start observation. It contains identity facts only, never environment
/// values, provider stdout, prompts, or SQLite paths.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentStartRequest {
    pub schema_version: u32,
    pub operation_id: OperationId,
    pub agent_run_id: AgentRunId,
    pub project_id: ProjectId,
    pub controller_generation: u64,
    pub descriptor_digest: ContentDigest,
    pub runtime_binary_digest: ContentDigest,
    pub environment_snapshot_id: ContentDigest,
    pub qualification_receipt_digest: ContentDigest,
    pub wrapper_pid: u32,
    pub wrapper_start_identity: String,
    pub rex_session_id: String,
    pub rex_block_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedWrapperIdentity {
    pub pid: u32,
    pub start_identity: String,
    pub rex_session_id: String,
    pub rex_block_id: String,
    pub runtime_binary_digest: ContentDigest,
}

/// Host process observation taken after provider spawn. Unknown tree state must remain
/// unresolved and retain the execution slot.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedProviderStart {
    pub agent_run_id: AgentRunId,
    pub operation_id: OperationId,
    pub provider_pid: u32,
    pub provider_start_identity: String,
    pub executable_digest: ContentDigest,
    pub process_tree_digest: ContentDigest,
    pub process_tree_confirmed: bool,
}

impl ObservedProviderStart {
    pub fn validate(&self, qualification: &ProviderQualification) -> Result<(), String> {
        if self.provider_pid == 0
            || self.provider_start_identity.trim().is_empty()
            || self.provider_start_identity.chars().any(char::is_control)
            || self.executable_digest != qualification.executable_digest
            || !self.process_tree_confirmed
        {
            return Err("provider process start observation is incomplete or mismatched".into());
        }
        Ok(())
    }
}

impl ObservedWrapperIdentity {
    pub fn matches_start_request(&self, request: &AgentStartRequest) -> Result<(), String> {
        if self.pid != request.wrapper_pid
            || self.start_identity != request.wrapper_start_identity
            || self.rex_session_id != request.rex_session_id
            || self.rex_block_id != request.rex_block_id
            || self.runtime_binary_digest != request.runtime_binary_digest
            || self.start_identity.trim().is_empty()
        {
            return Err("observed Rex wrapper does not match the Agent start request".into());
        }
        Ok(())
    }
}

impl AgentStartRequest {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != LAUNCH_SCHEMA_VERSION {
            return Err("unsupported Agent start request schema".into());
        }
        if self.wrapper_pid == 0 || self.controller_generation == 0 {
            return Err("Agent start request lacks process or controller identity".into());
        }
        for (field, value) in [
            (
                "wrapper_start_identity",
                self.wrapper_start_identity.as_str(),
            ),
            ("rex_session_id", self.rex_session_id.as_str()),
            ("rex_block_id", self.rex_block_id.as_str()),
        ] {
            if value.trim().is_empty() || value.chars().any(char::is_control) {
                return Err(format!("Agent start request has invalid {field}"));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaunchDecision {
    Accepted,
    Cancelled,
    Rejected,
}

/// Host-issued acknowledgement. An Accepted value is written only after the controller has
/// matched the request to persisted run, owner, Rex, environment, and qualification records.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentLaunchReceipt {
    pub schema_version: u32,
    pub operation_id: OperationId,
    pub agent_run_id: AgentRunId,
    pub controller_generation: u64,
    pub descriptor_digest: ContentDigest,
    pub runtime_binary_digest: ContentDigest,
    pub qualification_receipt_digest: ContentDigest,
    pub decision: LaunchDecision,
    pub reason: Option<String>,
}

/// Identity fetched by the host from its applied snapshot and durable AgentRun row. This type is
/// intentionally not deserialized from a run-local file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaunchExpectation {
    pub operation_id: OperationId,
    pub agent_run_id: AgentRunId,
    pub project_id: ProjectId,
    pub controller_generation: u64,
    pub descriptor_digest: ContentDigest,
    pub runtime_binary_digest: ContentDigest,
    pub environment_snapshot_id: ContentDigest,
    pub qualification_receipt_digest: ContentDigest,
    pub rex_session_id: String,
    pub rex_block_id: String,
    pub qualification_identity: QualificationIdentity,
}

/// Authorize the wrapper to start its provider only when the host's persisted receipt and
/// durable run identity match every field in the wrapper's start request.
pub fn authorize_start(
    current_owner_generation: u64,
    expected: &LaunchExpectation,
    stored_qualification: &ProviderQualification,
    request: &AgentStartRequest,
) -> Result<AgentLaunchReceipt, String> {
    request.validate()?;
    if expected.controller_generation != current_owner_generation {
        return Err(
            "provider start acknowledgement is fenced to a stale controller generation".into(),
        );
    }
    let stored_digest = stored_qualification.canonical_digest()?;
    if stored_digest != expected.qualification_receipt_digest
        || request.qualification_receipt_digest != expected.qualification_receipt_digest
    {
        return Err("provider qualification receipt digest does not match host state".into());
    }
    stored_qualification.matches_launch(&expected.qualification_identity)?;
    if request.operation_id != expected.operation_id
        || request.agent_run_id != expected.agent_run_id
        || request.project_id != expected.project_id
        || request.controller_generation != expected.controller_generation
        || request.descriptor_digest != expected.descriptor_digest
        || request.runtime_binary_digest != expected.runtime_binary_digest
        || request.environment_snapshot_id != expected.environment_snapshot_id
        || request.rex_session_id != expected.rex_session_id
        || request.rex_block_id != expected.rex_block_id
    {
        return Err("Agent start request does not match the host's durable launch identity".into());
    }
    let receipt = AgentLaunchReceipt {
        schema_version: LAUNCH_SCHEMA_VERSION,
        operation_id: expected.operation_id.clone(),
        agent_run_id: expected.agent_run_id.clone(),
        controller_generation: expected.controller_generation,
        descriptor_digest: expected.descriptor_digest.clone(),
        runtime_binary_digest: expected.runtime_binary_digest.clone(),
        qualification_receipt_digest: expected.qualification_receipt_digest.clone(),
        decision: LaunchDecision::Accepted,
        reason: None,
    };
    receipt.validate_for(request)?;
    Ok(receipt)
}

impl AgentLaunchReceipt {
    pub fn validate_for(&self, request: &AgentStartRequest) -> Result<(), String> {
        if self.schema_version != LAUNCH_SCHEMA_VERSION
            || self.operation_id != request.operation_id
            || self.agent_run_id != request.agent_run_id
            || self.controller_generation != request.controller_generation
            || self.descriptor_digest != request.descriptor_digest
            || self.runtime_binary_digest != request.runtime_binary_digest
            || self.qualification_receipt_digest != request.qualification_receipt_digest
        {
            return Err("host launch receipt does not match the start request".into());
        }
        match self.decision {
            LaunchDecision::Accepted if self.reason.is_some() => {
                Err("accepted launch receipt must not include a rejection reason".into())
            }
            LaunchDecision::Rejected | LaunchDecision::Cancelled
                if self.reason.as_deref().is_none_or(str::is_empty) =>
            {
                Err("rejected launch receipt must include a reason".into())
            }
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AgentLaunchAuthority, AgentLaunchReceipt, AgentStartRequest, LaunchDecision,
        LaunchExpectation, ObservedProviderStart, ProviderQualification, QualificationIdentity,
        QualificationProof, QualificationStatus, authorize_start, migrate_v7,
    };
    use crate::domain::ids::{
        AgentRunId, Digest, OperationId, ProfileId, ProjectId, Revision, TicketRunId,
    };
    use crate::domain::types::{AgentAdapter, CommitMode, Role};

    fn digest(byte: char) -> Digest {
        Digest::parse(byte.to_string().repeat(64)).unwrap()
    }

    fn qualification(status: QualificationStatus) -> ProviderQualification {
        ProviderQualification {
            schema_version: 1,
            project_id: ProjectId::parse("project-a").unwrap(),
            profile_id: ProfileId::parse("worker").unwrap(),
            profile_digest: digest('a'),
            adapter: AgentAdapter::Codex,
            executable_path: "/opt/codex".into(),
            executable_digest: digest('b'),
            provider_version: "1.2.3".into(),
            permission_mode: "workspace_write".into(),
            invocation_options_digest: digest('c'),
            commit_mode: CommitMode::Host,
            proof: QualificationProof {
                schema_version: 1,
                probe_id: "probe-1".into(),
                fixture_digest: digest('d'),
                rex_instance_id: "fixture-instance".into(),
                tool_shell_marker_digest: digest('e'),
                tool_shell_markers_present: required_markers(),
                descendant_marker_digest: digest('f'),
                descendant_markers_present: required_markers(),
                automatic_turn_result_digest: digest('1'),
                automatic_turn_completed: true,
                structured_result_valid: true,
                observed_permission_mode: "workspace_write".into(),
                permission_prompt_count: 0,
                cleanup_process_tree_digest: digest('2'),
                process_tree_absent: true,
                cleanup_confirmed: true,
            },
            status,
        }
    }

    fn start_request() -> AgentStartRequest {
        AgentStartRequest {
            schema_version: 1,
            operation_id: OperationId::parse("op-1").unwrap(),
            agent_run_id: AgentRunId::parse("run-1").unwrap(),
            project_id: ProjectId::parse("project-a").unwrap(),
            controller_generation: 4,
            descriptor_digest: digest('3'),
            runtime_binary_digest: digest('a'),
            environment_snapshot_id: digest('4'),
            qualification_receipt_digest: digest('5'),
            wrapper_pid: 321,
            wrapper_start_identity: "pid-start-identity".into(),
            rex_session_id: "session-1".into(),
            rex_block_id: "block-1".into(),
        }
    }

    fn authority() -> AgentLaunchAuthority {
        AgentLaunchAuthority {
            agent_run_id: AgentRunId::parse("run-1").unwrap(),
            project_id: ProjectId::parse("project-a").unwrap(),
            role: Role::Worker,
            role_session_id: "worker-session".into(),
            parent_run_id: Some(AgentRunId::parse("coordinator-run").unwrap()),
            parent_role: Some(Role::Coordinator),
            ticket_run_id: Some(TicketRunId::parse("ticket-run-1").unwrap()),
            ticket_revision: Some(Revision(8)),
            config_revision: Revision(3),
            config_digest: digest('6'),
            attempt: 1,
            run_epoch: 2,
            controller_generation: 4,
            operation_id: OperationId::parse("op-1").unwrap(),
            operation_recipe_id: None,
            rex_view_id: digest('b'),
            descriptor_digest: digest('3'),
            runtime_binary_digest: digest('a'),
            descriptor_path: "/state/agents/run-1/descriptor.json".into(),
            environment_snapshot_id: digest('4'),
            profile_id: ProfileId::parse("worker").unwrap(),
            profile_digest: digest('a'),
            instruction_digest: digest('7'),
            result_schema_digest: digest('8'),
            wake_snapshot_digest: digest('d'),
            qualification_receipt_digest: digest('5'),
            rex_server_identity: "rex-instance-1".into(),
            rex_session_id: "session-1".into(),
            rex_window_id: "window-1".into(),
            rex_block_id: "block-1".into(),
            workspace_path: "/state/repos/project-a/worktree".into(),
            control_dir: "/state/repos/project-a/worktree/.rex-projects-control/run-1".into(),
            mailbox_capability_digest: digest('9'),
        }
    }

    fn required_markers() -> std::collections::BTreeSet<String> {
        [
            "REX_PROJECTS_AGENT",
            "REX_PROJECTS_CONTEXT",
            "REX_PROJECTS_PROJECT_ID",
            "REX_PROJECTS_ROLE",
            "REX_PROJECTS_RUN_ID",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }

    #[test]
    fn unattended_launch_rejects_fixture_only_and_unsupported_qualification() {
        assert!(
            qualification(QualificationStatus::FixtureOnly)
                .validate_for_unattended_launch()
                .is_err()
        );
        assert!(
            qualification(QualificationStatus::Unknown)
                .validate_for_unattended_launch()
                .is_err()
        );
        assert!(
            qualification(QualificationStatus::Verified)
                .validate_for_unattended_launch()
                .is_ok()
        );
    }

    #[test]
    fn unconfirmed_cleanup_never_becomes_a_verified_qualification() {
        let mut evidence = qualification(QualificationStatus::Verified);
        evidence.proof.cleanup_confirmed = false;
        assert!(evidence.validate_for_unattended_launch().is_err());
    }

    #[test]
    fn missing_tool_marker_or_permission_prompt_invalidates_qualification() {
        let mut evidence = qualification(QualificationStatus::Verified);
        evidence
            .proof
            .tool_shell_markers_present
            .remove("REX_PROJECTS_ROLE");
        assert!(evidence.validate_for_unattended_launch().is_err());

        let mut evidence = qualification(QualificationStatus::Verified);
        evidence.proof.permission_prompt_count = 1;
        assert!(evidence.validate_for_unattended_launch().is_err());
    }

    #[test]
    fn provider_start_requires_host_confirmed_matching_executable_tree() {
        let qualification = qualification(QualificationStatus::Verified);
        let mut observation = ObservedProviderStart {
            agent_run_id: AgentRunId::parse("run-1").unwrap(),
            operation_id: OperationId::parse("op-1").unwrap(),
            provider_pid: 44,
            provider_start_identity: "pid-start-44".into(),
            executable_digest: qualification.executable_digest.clone(),
            process_tree_digest: digest('4'),
            process_tree_confirmed: true,
        };
        assert!(observation.validate(&qualification).is_ok());
        observation.process_tree_confirmed = false;
        assert!(observation.validate(&qualification).is_err());
        observation.process_tree_confirmed = true;
        observation.executable_digest = digest('5');
        assert!(observation.validate(&qualification).is_err());
    }

    #[test]
    fn launch_receipt_must_match_all_persisted_identity_fields() {
        let request = start_request();
        let mut receipt = AgentLaunchReceipt {
            schema_version: 1,
            operation_id: request.operation_id.clone(),
            agent_run_id: request.agent_run_id.clone(),
            controller_generation: request.controller_generation,
            descriptor_digest: request.descriptor_digest.clone(),
            runtime_binary_digest: request.runtime_binary_digest.clone(),
            qualification_receipt_digest: request.qualification_receipt_digest.clone(),
            decision: LaunchDecision::Accepted,
            reason: None,
        };
        assert!(receipt.validate_for(&request).is_ok());
        receipt.controller_generation += 1;
        assert!(receipt.validate_for(&request).is_err());
    }

    #[test]
    fn wrapper_start_request_rejects_missing_process_or_rex_identity() {
        let mut request = start_request();
        assert!(request.validate().is_ok());
        request.wrapper_pid = 0;
        assert!(request.validate().is_err());
    }

    #[test]
    fn launch_authority_requires_ticket_scope_and_absolute_host_paths() {
        let record = authority();
        assert!(record.validate().is_ok());
        assert!(record.digest().is_ok());

        let mut supervisor = record.clone();
        supervisor.role = Role::Supervisor;
        assert!(supervisor.validate().is_err());

        let mut relative = record;
        relative.control_dir = "relative/control".into();
        assert!(relative.validate().is_err());
    }

    #[test]
    fn run_local_verified_claim_cannot_replace_host_persisted_qualification() {
        let stored = qualification(QualificationStatus::Verified);
        let qualification_digest = stored.canonical_digest().unwrap();
        let expected = LaunchExpectation {
            operation_id: OperationId::parse("op-1").unwrap(),
            agent_run_id: AgentRunId::parse("run-1").unwrap(),
            project_id: ProjectId::parse("project-a").unwrap(),
            controller_generation: 4,
            descriptor_digest: digest('3'),
            runtime_binary_digest: digest('a'),
            environment_snapshot_id: digest('4'),
            qualification_receipt_digest: qualification_digest,
            rex_session_id: "session-1".into(),
            rex_block_id: "block-1".into(),
            qualification_identity: QualificationIdentity {
                project_id: stored.project_id.clone(),
                profile_id: stored.profile_id.clone(),
                profile_digest: stored.profile_digest.clone(),
                adapter: stored.adapter,
                executable_path: stored.executable_path.clone(),
                executable_digest: stored.executable_digest.clone(),
                provider_version: stored.provider_version.clone(),
                permission_mode: stored.permission_mode.clone(),
                invocation_options_digest: stored.invocation_options_digest.clone(),
                commit_mode: stored.commit_mode,
            },
        };
        let mut request = start_request();
        request.qualification_receipt_digest = expected.qualification_receipt_digest.clone();
        assert!(authorize_start(4, &expected, &stored, &request).is_ok());

        let self_asserted = qualification(QualificationStatus::FixtureOnly);
        assert!(authorize_start(4, &expected, &self_asserted, &request).is_err());
        assert!(authorize_start(5, &expected, &stored, &request).is_err());
    }

    #[test]
    fn schema_v7_adds_immutable_launch_and_result_authority_tables() {
        let connection = rusqlite::Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "PRAGMA foreign_keys=ON;
                CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at_unix INTEGER NOT NULL);
                CREATE TABLE projects(project_id TEXT PRIMARY KEY);
                CREATE TABLE ticket_runs(ticket_run_id TEXT PRIMARY KEY);
                CREATE TABLE agent_runs(agent_run_id TEXT PRIMARY KEY);
                CREATE TABLE role_wake_inputs(wake_input_id INTEGER PRIMARY KEY);
                PRAGMA user_version=6;",
            )
            .unwrap();

        let mut connection = connection;
        migrate_v7(&mut connection).unwrap();
        migrate_v7(&mut connection).unwrap();
        let version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, 7);
        let tables: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('provider_qualifications','agent_launch_authority','agent_launch_state','agent_result_evidence','agent_result_wakes')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(tables, 5);
        connection
            .execute("INSERT INTO projects(project_id) VALUES ('project-a')", [])
            .unwrap();
        connection.execute(
            "INSERT INTO provider_qualifications(receipt_digest,project_id,profile_id,profile_digest,adapter,executable_path,executable_digest,provider_version,permission_mode,invocation_options_digest,commit_mode,status,receipt_json,created_by_generation,created_at_unix) VALUES (?1,'project-a','worker',?2,'codex','/opt/codex',?3,'1.2.3','workspace_write',?4,'host','verified','{}',1,1)",
            rusqlite::params!["a".repeat(64), "b".repeat(64), "c".repeat(64), "d".repeat(64)],
        ).unwrap();
        assert!(
            connection
                .execute(
                    "UPDATE provider_qualifications SET status='unsupported'",
                    []
                )
                .is_err()
        );
    }
}
