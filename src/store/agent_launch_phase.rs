//! Durable boundaries around the external Rex block creation call.

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

use crate::launch::AgentLaunchReservation;

type LaunchSlotRow = (
    String,
    u32,
    String,
    Option<String>,
    String,
    String,
    u64,
    u64,
    String,
);

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Admission {
    Proceed,
    Rejected { receipt: String },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Phase {
    LegacyUnknown,
    NotStarted,
    PrecreateRejected,
    CreateAttempted,
    Ambiguous,
}

impl Phase {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "legacy_unknown" => Ok(Self::LegacyUnknown),
            "not_started" => Ok(Self::NotStarted),
            "precreate_rejected" => Ok(Self::PrecreateRejected),
            "create_attempted" => Ok(Self::CreateAttempted),
            "ambiguous" => Ok(Self::Ambiguous),
            _ => Err("Agent launch phase is invalid".into()),
        }
    }
}

fn rejection_receipt(reservation: &AgentLaunchReservation) -> Result<String, String> {
    serde_json::to_string(&serde_json::json!({
        "schema_version": 1,
        "outcome": "rejected",
        "reason": "ticket_run_stale_before_rex_create",
        "agent_run_id": reservation.agent_run_id.as_str(),
        "operation_id": reservation.operation_id.as_str(),
        "reservation_digest": reservation.digest()?.as_str(),
        "ticket_run_id": reservation.ticket_run_id.as_ref().map(|id| id.as_str()),
        "ticket_revision": reservation.ticket_revision.map(|revision| revision.0),
    }))
    .map_err(|error| error.to_string())
}

fn validate_reservation_scope(
    tx: &Transaction<'_>,
    owner_generation: u64,
    reservation: &AgentLaunchReservation,
) -> Result<(String, String), String> {
    crate::store::validate_active_generation(tx, owner_generation)?;
    if reservation.controller_generation != owner_generation {
        return Err("launch reservation belongs to a stale controller generation".into());
    }
    let digest = reservation.digest()?;
    let stored: Option<(String, String, String, u64, u64, String)> = tx
        .query_row(
            "SELECT reservation_digest,reservation_json,operation_id,controller_generation,project_epoch,lifecycle FROM agent_launch_reservations WHERE agent_run_id=?1 AND project_id=?2",
            params![reservation.agent_run_id.as_str(), reservation.project_id.as_str()],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?)),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    let Some((stored_digest, stored_json, operation, generation, epoch, lifecycle)) = stored else {
        return Err("launch reservation scope is missing".into());
    };
    let parsed: AgentLaunchReservation = crate::protocol::parse_unique(stored_json.as_bytes())
        .map_err(|error| format!("stored launch reservation is invalid: {error}"))?;
    if parsed != *reservation
        || stored_digest != digest.as_str()
        || operation != reservation.operation_id.as_str()
        || generation != reservation.controller_generation
        || epoch != reservation.project_epoch
        || !matches!(lifecycle.as_str(), "reserved" | "authorized")
    {
        return Err("launch reservation identity or lifecycle changed".into());
    }
    crate::store::agent_runtime::validate_project_launch_identity(
        tx,
        &reservation.project_id,
        reservation.project_epoch,
        reservation.config_revision.0,
        &reservation.config_digest,
    )?;
    let run: Option<(String, Option<String>, u64, String)> = tx
        .query_row(
            "SELECT project_id,launch_operation_id,controller_generation,state FROM agent_runs WHERE agent_run_id=?1",
            [reservation.agent_run_id.as_str()],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    if !matches!(run, Some((ref project, Some(ref operation), generation, ref state))
        if project == reservation.project_id.as_str()
            && operation == reservation.operation_id.as_str()
            && generation == owner_generation
            && state == "launch_pending")
    {
        return Err("AgentRun no longer matches its launch reservation".into());
    }
    if lifecycle == "authorized" {
        let authority: Option<(String, String)> = tx.query_row(
            "SELECT authority_json,authority_digest FROM agent_launch_authority WHERE agent_run_id=?1",
            [reservation.agent_run_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional().map_err(|error| error.to_string())?;
        let Some((authority_json, authority_digest)) = authority else {
            return Err("authorized launch reservation has no persisted authority".into());
        };
        let authority: crate::launch::AgentLaunchAuthority =
            crate::protocol::parse_unique(authority_json.as_bytes())
                .map_err(|error| format!("stored Agent launch authority is invalid: {error}"))?;
        authority.validate()?;
        if authority.agent_run_id != reservation.agent_run_id
            || authority.project_id != reservation.project_id
            || authority.role != reservation.role
            || authority.role_session_id != reservation.role_session_id
            || authority.parent_run_id != reservation.parent_run_id
            || authority.parent_role != reservation.parent_role
            || authority.ticket_run_id != reservation.ticket_run_id
            || authority.ticket_revision != reservation.ticket_revision
            || authority.config_revision != reservation.config_revision
            || authority.config_digest != reservation.config_digest
            || authority.attempt != reservation.attempt
            || authority.run_epoch != reservation.run_epoch
            || authority.controller_generation != owner_generation
            || authority.operation_id != reservation.operation_id
            || authority.operation_recipe_id != reservation.operation_recipe_id
            || authority.rex_view_id != reservation.rex_view_id
            || authority.runtime_binary_digest != reservation.runtime_binary_digest
            || authority.environment_snapshot_id != reservation.environment_snapshot_id
            || authority.profile_id != reservation.profile_id
            || authority.profile_digest != reservation.profile_digest
            || authority.instruction_digest != reservation.instruction_digest
            || authority.result_schema_digest != reservation.result_schema_digest
            || authority.wake_snapshot_digest != reservation.wake_snapshot.digest
            || authority.qualification_receipt_digest != reservation.qualification_receipt_digest
            || authority.descriptor_path != reservation.descriptor_path
            || authority.workspace_path != reservation.workspace_path
            || authority.control_dir != reservation.control_dir
            || authority.mailbox_capability_digest != reservation.mailbox_capability_digest
            || authority.digest()?.as_str() != authority_digest
        {
            return Err("authorized launch authority does not match its reservation".into());
        }
        let block: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM rex_view_blocks WHERE view_id=?1 AND block_id=?2 AND agent_run_id=?3 AND ownership='factory' AND lifecycle='active')",
            params![authority.rex_view_id.as_str(), authority.rex_block_id, reservation.agent_run_id.as_str()],
            |row| row.get(0),
        ).map_err(|error| error.to_string())?;
        if !block {
            return Err("authorized launch has no matching active Rex block record".into());
        }
    }
    let slot: Option<LaunchSlotRow> = tx
        .query_row(
            "SELECT pool,slot_index,project_id,ticket_run_id,owner_kind,owner_id,reservation_epoch,controller_generation,disposition FROM execution_slots WHERE pool=?1 AND slot_index=?2",
            params![reservation.pool, reservation.slot_index],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?)),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    if !matches!(slot, Some((ref pool, index, ref project, ref ticket, ref owner_kind, ref owner, epoch, generation, ref disposition))
        if pool == &reservation.pool
            && index == reservation.slot_index
            && project == reservation.project_id.as_str()
            && ticket.as_deref() == reservation.ticket_run_id.as_ref().map(|id| id.as_str())
            && owner_kind == "agent_run"
            && owner == reservation.agent_run_id.as_str()
            && epoch == reservation.project_epoch
            && generation == owner_generation
            && disposition == "launch_pending")
    {
        return Err("execution slot no longer matches its launch reservation".into());
    }
    Ok((digest.as_str().to_owned(), lifecycle))
}

fn ticket_is_stale(
    tx: &Transaction<'_>,
    reservation: &AgentLaunchReservation,
) -> Result<bool, String> {
    let (Some(ticket_run_id), Some(ticket_revision)) =
        (&reservation.ticket_run_id, reservation.ticket_revision)
    else {
        return Ok(reservation.role != crate::domain::types::Role::Supervisor);
    };
    let current: Option<(String, u64, String)> = tx
        .query_row(
            "SELECT project_id,revision,internal_phase FROM ticket_runs WHERE ticket_run_id=?1",
            [ticket_run_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    Ok(!matches!(current, Some((ref project, revision, ref phase))
        if project == reservation.project_id.as_str()
            && revision == ticket_revision.0
            && !matches!(phase.as_str(), "done" | "canceled")))
}

fn phase_for(
    tx: &Transaction<'_>,
    reservation: &AgentLaunchReservation,
    digest: &str,
) -> Result<Phase, String> {
    let value: String = tx.query_row(
        "SELECT launch_phase FROM agent_launch_reservations WHERE agent_run_id=?1 AND reservation_digest=?2",
        params![reservation.agent_run_id.as_str(), digest],
        |row| row.get(0),
    ).map_err(|error| error.to_string())?;
    Phase::parse(&value)
}

pub(crate) fn pre_handoff_admission(
    connection: &mut Connection,
    owner_generation: u64,
    reservation: &AgentLaunchReservation,
) -> Result<Admission, String> {
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| error.to_string())?;
    let (digest, lifecycle) = validate_reservation_scope(&tx, owner_generation, reservation)?;
    let phase = phase_for(&tx, reservation, &digest)?;
    if matches!(phase, Phase::NotStarted | Phase::PrecreateRejected) && lifecycle != "reserved" {
        return Err("launch phase conflicts with reservation lifecycle".into());
    }
    if phase == Phase::PrecreateRejected {
        let receipt = rejection_receipt(reservation)?;
        tx.commit().map_err(|error| error.to_string())?;
        return Ok(Admission::Rejected { receipt });
    }
    if phase != Phase::NotStarted
        && phase != Phase::CreateAttempted
        && phase != Phase::LegacyUnknown
    {
        return Err("Agent launch phase does not permit unattended handoff".into());
    }
    if ticket_is_stale(&tx, reservation)? {
        if phase != Phase::NotStarted {
            return Err(match phase {
                Phase::CreateAttempted => {
                    "TicketRun became stale after the Rex create boundary".into()
                }
                _ => "TicketRun is stale for a launch whose no-create state is unproven".into(),
            });
        }
        let receipt = rejection_receipt(reservation)?;
        let changed = tx.execute(
            "UPDATE agent_launch_reservations SET launch_phase='precreate_rejected',updated_at_unix=?2 WHERE agent_run_id=?1 AND reservation_digest=?3 AND launch_phase='not_started'",
            params![reservation.agent_run_id.as_str(), crate::store::now_unix()?, digest],
        ).map_err(|error| error.to_string())?;
        if changed != 1 {
            return Err("launch phase changed during stale TicketRun rejection".into());
        }
        tx.commit().map_err(|error| error.to_string())?;
        return Ok(Admission::Rejected { receipt });
    }
    tx.commit().map_err(|error| error.to_string())?;
    Ok(Admission::Proceed)
}

pub(crate) fn mark_create_attempted(
    connection: &mut Connection,
    owner_generation: u64,
    reservation: &AgentLaunchReservation,
) -> Result<Admission, String> {
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| error.to_string())?;
    let (digest, lifecycle) = validate_reservation_scope(&tx, owner_generation, reservation)?;
    if lifecycle != "reserved" {
        return Err("Rex create boundary requires a still-reserved launch".into());
    }
    let phase = phase_for(&tx, reservation, &digest)?;
    if phase != Phase::NotStarted {
        return Err(format!("Rex create is forbidden in launch phase {phase:?}"));
    }
    if ticket_is_stale(&tx, reservation)? {
        let receipt = rejection_receipt(reservation)?;
        let changed = tx.execute(
            "UPDATE agent_launch_reservations SET launch_phase='precreate_rejected',updated_at_unix=?2 WHERE agent_run_id=?1 AND reservation_digest=?3 AND launch_phase='not_started'",
            params![reservation.agent_run_id.as_str(), crate::store::now_unix()?, digest],
        ).map_err(|error| error.to_string())?;
        if changed != 1 {
            return Err("launch phase changed during stale TicketRun rejection".into());
        }
        tx.commit().map_err(|error| error.to_string())?;
        return Ok(Admission::Rejected { receipt });
    }
    let changed = tx.execute(
        "UPDATE agent_launch_reservations SET launch_phase='create_attempted',updated_at_unix=?2 WHERE agent_run_id=?1 AND reservation_digest=?3 AND launch_phase='not_started'",
        params![reservation.agent_run_id.as_str(), crate::store::now_unix()?, digest],
    ).map_err(|error| error.to_string())?;
    if changed != 1 {
        return Err("launch phase compare-and-swap did not win".into());
    }
    tx.commit().map_err(|error| error.to_string())?;
    Ok(Admission::Proceed)
}

pub(crate) fn current_phase(
    connection: &Connection,
    reservation: &AgentLaunchReservation,
) -> Result<Phase, String> {
    let digest = reservation.digest()?;
    let value: String = connection.query_row(
        "SELECT launch_phase FROM agent_launch_reservations WHERE agent_run_id=?1 AND reservation_digest=?2",
        params![reservation.agent_run_id.as_str(), digest.as_str()],
        |row| row.get(0),
    ).map_err(|error| error.to_string())?;
    Phase::parse(&value)
}

pub(crate) fn mark_ambiguous(
    connection: &mut Connection,
    owner_generation: u64,
    reservation: &AgentLaunchReservation,
) -> Result<(), String> {
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| error.to_string())?;
    let (digest, lifecycle) = validate_reservation_scope(&tx, owner_generation, reservation)?;
    if lifecycle != "reserved" {
        return Err("contradictory block observation requires a still-reserved launch".into());
    }
    let changed = tx.execute(
        "UPDATE agent_launch_reservations SET launch_phase='ambiguous',updated_at_unix=?2 WHERE agent_run_id=?1 AND reservation_digest=?3 AND launch_phase='not_started'",
        params![reservation.agent_run_id.as_str(), crate::store::now_unix()?, digest],
    ).map_err(|error| error.to_string())?;
    if changed != 1 {
        return Err("contradictory block observation could not mark launch ambiguous".into());
    }
    tx.commit().map_err(|error| error.to_string())
}

const PHASE_TRANSITIONS: &str = "CREATE TRIGGER agent_launch_phase_transitions
BEFORE UPDATE OF launch_phase ON agent_launch_reservations
WHEN NOT (OLD.launch_phase=NEW.launch_phase
 OR (OLD.launch_phase='not_started' AND NEW.launch_phase IN ('precreate_rejected','create_attempted','ambiguous')))
BEGIN SELECT RAISE(ABORT, 'Agent launch phase transition is invalid'); END;";

pub(crate) fn migrate_v18(connection: &Connection) -> Result<(), String> {
    let tx = connection
        .unchecked_transaction()
        .map_err(|error| error.to_string())?;
    let version: i64 = tx
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| error.to_string())?;
    if version == 18 {
        tx.commit().map_err(|error| error.to_string())?;
        return Ok(());
    }
    if version != 17 {
        return Err(format!(
            "Agent launch phase migration requires schema 17, found {version}"
        ));
    }
    apply_v18_layout(&tx)?;
    tx.execute_batch(
        "INSERT INTO schema_migrations(version,applied_at_unix) VALUES (18,unixepoch());
         PRAGMA user_version=18;",
    )
    .map_err(|error| error.to_string())?;
    tx.commit().map_err(|error| error.to_string())
}

pub(crate) fn apply_v18_layout(connection: &Connection) -> Result<(), String> {
    connection
        .execute_batch(&format!(
            "ALTER TABLE agent_launch_reservations ADD COLUMN launch_phase TEXT NOT NULL DEFAULT 'legacy_unknown' CHECK(launch_phase IN ('legacy_unknown','not_started','precreate_rejected','create_attempted','ambiguous'));
             {PHASE_TRANSITIONS}"
        ))
        .map_err(|error| error.to_string())
}

pub(crate) fn validate_v18_schema(connection: &Connection) -> Result<(), String> {
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| error.to_string())?;
    if version != 18 {
        return Err(format!(
            "Agent launch phase schema version mismatch: {version}"
        ));
    }
    let recorded: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=18)",
            [],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    if !recorded {
        return Err("schema 18 migration record is missing".into());
    }
    let canonical = crate::store::artifact_registry::canonical_v18_schema()?;
    crate::store::artifact_registry::validate_table_layout_against(
        connection,
        &canonical,
        "agent_launch_reservations",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_18_adds_conservative_launch_phase_and_monotonic_transitions() {
        let state = tempfile::tempdir().unwrap();
        let store = crate::store::ConfigStore::open_test(state.path()).unwrap();
        assert_eq!(crate::store::SCHEMA_VERSION, 18);
        validate_v18_schema(&store.connection).unwrap();
        let legacy_default: String = store
            .connection
            .query_row(
                "SELECT dflt_value FROM pragma_table_info('agent_launch_reservations') WHERE name='launch_phase'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(legacy_default, "'legacy_unknown'");
        assert!(
            store
                .connection
                .execute_batch("DROP TRIGGER agent_launch_phase_transitions")
                .is_ok()
        );
        assert!(validate_v18_schema(&store.connection).is_err());
    }

    #[test]
    fn migration_18_preserves_every_preexisting_reservation_as_legacy_unknown() {
        let state = tempfile::tempdir().unwrap();
        let store = crate::store::ConfigStore::open_test(state.path()).unwrap();
        store
            .connection
            .execute_batch(
                "DROP TRIGGER agent_launch_phase_transitions;
             ALTER TABLE agent_launch_reservations DROP COLUMN launch_phase;
             DELETE FROM schema_migrations WHERE version=18;
             PRAGMA user_version=17;
             PRAGMA foreign_keys=OFF;",
            )
            .unwrap();
        for (index, lifecycle) in [
            "reserved",
            "block_created",
            "authorized",
            "unknown",
            "cancelled",
        ]
        .iter()
        .enumerate()
        {
            let agent_run_id = format!("migration-agent-{index}");
            store.connection.execute(
                "INSERT INTO agent_launch_reservations(agent_run_id,project_id,operation_id,controller_generation,project_epoch,reservation_digest,reservation_json,lifecycle,created_at_unix,updated_at_unix) VALUES (?1,'legacy-project',?2,1,1,?3,'{}',?4,1,1)",
                params![agent_run_id, format!("migration-operation-{index}"), format!("{:064x}", index + 1), lifecycle],
            ).unwrap();
        }
        migrate_v18(&store.connection).unwrap();
        validate_v18_schema(&store.connection).unwrap();
        let phases = store
            .connection
            .prepare(
                "SELECT lifecycle,launch_phase FROM agent_launch_reservations ORDER BY lifecycle",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(phases.len(), 5);
        assert!(phases.iter().all(|(_, phase)| phase == "legacy_unknown"));
        assert!(store.connection.execute(
            "UPDATE agent_launch_reservations SET launch_phase='create_attempted' WHERE lifecycle='reserved'",
            [],
        ).is_err());
        drop(store);
        let reopened = crate::store::ConfigStore::open_test(state.path()).unwrap();
        validate_v18_schema(&reopened.connection).unwrap();
        let reopened_legacy_count: u64 = reopened.connection.query_row(
            "SELECT COUNT(*) FROM agent_launch_reservations WHERE launch_phase='legacy_unknown'",
            [],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(reopened_legacy_count, 5);
    }
}
