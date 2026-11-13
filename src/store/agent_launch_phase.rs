//! Durable boundaries around the external Rex block creation call.

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

use crate::launch::AgentLaunchReservation;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RejectedStartReceipt {
    schema_version: u32,
    outcome: String,
    reason: String,
    agent_run_id: String,
    operation_id: String,
    reservation_digest: String,
    ticket_run_id: Option<String>,
    ticket_revision: Option<u64>,
}

type FailedStartEffectRow = (
    String,
    String,
    String,
    String,
    String,
    String,
    Option<String>,
);
type RejectedAgentRunRow = (String, String, u64, String, String, String, String, u64);
type RejectedAgentSlotRow = (
    String,
    u32,
    Option<String>,
    String,
    String,
    Option<String>,
    u64,
    u64,
    Option<String>,
    String,
);

/// Finalize only the post-restart shape produced by start_owner after the real
/// StartAgent handler persisted its typed, pre-create rejection. Every proof
/// and transition lives in this one immediate transaction.
pub(crate) fn finalize_rejected_unstarted_runs(
    connection: &mut Connection,
    owner_generation: u64,
    inventory: &crate::adapters::rex::CompleteRexSessionInventory,
    now_unix: i64,
) -> Result<usize, String> {
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| error.to_string())?;
    crate::store::validate_active_generation(&tx, owner_generation)?;
    let candidates = {
        let mut statement = tx
            .prepare("SELECT agent_run_id,project_id,reservation_digest,reservation_json,operation_id,controller_generation,project_epoch FROM agent_launch_reservations WHERE lifecycle='reserved' AND launch_phase='precreate_rejected'")
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, u64>(5)?,
                    row.get::<_, u64>(6)?,
                ))
            })
            .map_err(|error| error.to_string())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?
    };
    let mut finalized = 0;
    for (run_id, project_id, digest, json, operation_id, original_generation, project_epoch) in
        candidates
    {
        if owner_generation <= original_generation {
            continue;
        }
        let Ok(reservation) =
            crate::protocol::parse_unique::<AgentLaunchReservation>(json.as_bytes())
        else {
            continue;
        };
        if crate::store::canonical_json(&reservation).as_deref() != Ok(json.as_str())
            || reservation.validate().is_err()
            || reservation.agent_run_id.as_str() != run_id
            || reservation.project_id.as_str() != project_id
            || reservation.operation_id.as_str() != operation_id
            || reservation.controller_generation != original_generation
            || reservation.project_epoch != project_epoch
            || reservation
                .digest()
                .map(|value| value.as_str().to_owned())
                .as_deref()
                != Ok(digest.as_str())
        {
            continue;
        }
        let Ok(Phase::PrecreateRejected) = phase_for(&tx, &reservation, &digest) else {
            continue;
        };
        let expected_receipt = match rejection_receipt(&reservation) {
            Ok(receipt) => receipt,
            Err(_) => continue,
        };
        let effect: Option<FailedStartEffectRow> = tx
            .query_row(
                "SELECT project_id,subject_type,subject_id,kind,request_json,request_digest,receipt_json FROM effects WHERE operation_id=?1 AND status='failed'",
                [&operation_id],
                |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let Some((
            effect_project,
            subject_type,
            subject_id,
            kind,
            request_json,
            request_digest,
            receipt_json,
        )) = effect
        else {
            continue;
        };
        let payload: crate::launch::StartAgentEffectPayload =
            match crate::protocol::parse_unique(request_json.as_bytes()) {
                Ok(value) => value,
                Err(_) => continue,
            };
        if effect_project != project_id
            || subject_type != "agent_run"
            || subject_id != run_id
            || tx
                .query_row::<String, _, _>(
                    "SELECT logical_key FROM effects WHERE operation_id=?1",
                    [&operation_id],
                    |row| row.get(0),
                )
                .map_err(|error| error.to_string())?
                != format!("start-agent:{run_id}")
            || kind != "start_agent"
            || crate::store::canonical_json(&payload).as_deref() != Ok(request_json.as_str())
            || crate::store::content_digest(&request_json) != request_digest
            || payload.agent_run_id.as_str() != run_id
            || payload.launch_reservation_digest.as_str() != digest
        {
            continue;
        }
        if payload.validate().is_err() {
            continue;
        }
        let Some(receipt_json) = receipt_json else {
            continue;
        };
        let Ok(receipt) =
            crate::protocol::parse_unique::<RejectedStartReceipt>(receipt_json.as_bytes())
        else {
            continue;
        };
        if receipt.schema_version != 1
            || receipt.outcome != "rejected"
            || receipt.reason != "ticket_run_stale_before_rex_create"
            || receipt.agent_run_id != run_id
            || receipt.operation_id != operation_id
            || receipt.reservation_digest != digest
            || receipt.ticket_run_id.as_deref()
                != reservation.ticket_run_id.as_ref().map(|id| id.as_str())
            || receipt.ticket_revision != reservation.ticket_revision.map(|revision| revision.0)
            || receipt_json != expected_receipt
        {
            continue;
        }
        let run: Option<RejectedAgentRunRow> = tx
            .query_row(
                "SELECT project_id,role,config_revision,config_digest,role_session_id,launch_operation_id,state,controller_generation FROM agent_runs WHERE agent_run_id=?1",
                [&run_id],
                |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let role_json =
            serde_json::to_value(reservation.role).map_err(|error| error.to_string())?;
        let Some((
            run_project,
            run_role,
            run_config_revision,
            run_config_digest,
            role_session,
            run_operation,
            run_state,
            run_generation,
        )) = run
        else {
            continue;
        };
        if run_project != project_id
            || run_role != role_json.as_str().unwrap_or_default()
            || run_config_revision != reservation.config_revision.0
            || run_config_digest != reservation.config_digest.as_str()
            || role_session != reservation.role_session_id
            || run_operation != operation_id
            || run_state != "unknown"
            || run_generation != owner_generation
        {
            continue;
        }
        let slot: Option<RejectedAgentSlotRow> = tx
            .query_row(
                "SELECT pool,slot_index,project_id,owner_kind,owner_id,ticket_run_id,reservation_epoch,controller_generation,process_identity_json,disposition FROM execution_slots WHERE pool=?1 AND slot_index=?2",
                params![reservation.pool,reservation.slot_index],
                |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?,row.get(9)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if !matches!(slot, Some((ref pool,index,Some(ref project),ref owner_kind,ref owner_id,ref ticket,epoch,generation,None,ref disposition))
            if pool == &reservation.pool && index == reservation.slot_index
                && project == &project_id && owner_kind == "agent_run" && owner_id == &run_id
                && ticket.as_deref() == reservation.ticket_run_id.as_ref().map(|id| id.as_str())
                && epoch == reservation.project_epoch && generation == original_generation
                && disposition == "unknown")
        {
            continue;
        }
        let view: Option<(String,String,String,String,String,String)> = tx
            .query_row(
                "SELECT project_id,view_kind,rex_server_identity,rex_session_id,rex_window_id,lifecycle FROM rex_views WHERE view_id=?1",
                [reservation.rex_view_id.as_str()],
                |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let Some((view_project, view_kind, server, session, window, view_lifecycle)) = view else {
            continue;
        };
        let expected_view_kind = if reservation.role == crate::domain::types::Role::Supervisor {
            "supervisor"
        } else {
            "ticket"
        };
        if view_project != project_id || view_kind != expected_view_kind || view_lifecycle != "active"
            || !inventory.matches_view(&server, &session, &window)
            || tx.query_row::<u64, _, _>(
                "SELECT COUNT(*) FROM rex_views WHERE rex_server_identity=?1 AND rex_session_id=?2 AND rex_window_id=?3 AND lifecycle IN ('active','close_pending','unknown')",
                params![server,session,window],
                |row| row.get(0),
            ).map_err(|error| error.to_string())? != 1
            || inventory.contains_block_label(&crate::adapters::rex::owned_agent_block_label(&run_id).map_err(|e| e.to_string())?)
        {
            continue;
        }
        let prohibited: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM agent_launch_authority WHERE agent_run_id=?1) OR EXISTS(SELECT 1 FROM agent_launch_state WHERE agent_run_id=?1) OR EXISTS(SELECT 1 FROM rex_view_blocks WHERE agent_run_id=?1)",
            [&run_id], |row| row.get(0),
        ).map_err(|error| error.to_string())?;
        if prohibited {
            continue;
        }
        let wakes = {
            let mut statement = tx.prepare("SELECT wake_input_id,project_id,role_session_id,source_type,source_id,source_revision,priority,payload_json,lifecycle,consuming_agent_run_id FROM role_wake_inputs WHERE consuming_agent_run_id=?1 ORDER BY wake_input_id").map_err(|e| e.to_string())?;
            let rows = statement
                .query_map([&run_id], |row| {
                    Ok((
                        row.get::<_, u64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, u64>(5)?,
                        row.get::<_, i32>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, String>(8)?,
                        row.get::<_, Option<String>>(9)?,
                    ))
                })
                .map_err(|e| e.to_string())?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|e| e.to_string())?
        };
        if wakes.len() != reservation.wake_snapshot.inputs.len() {
            continue;
        }
        let mut wakes_match = true;
        for (row, item) in wakes.iter().zip(&reservation.wake_snapshot.inputs) {
            let payload = crate::store::canonical_json(&item.payload_json)?;
            if row.0 != item.wake_input_id
                || row.1 != project_id
                || row.2 != reservation.role_session_id
                || row.3 != item.source_type
                || row.4 != item.source_id
                || row.5 != item.source_revision
                || row.6 != item.priority
                || row.7 != payload
                || row.8 != "assigned"
                || row.9.as_deref() != Some(run_id.as_str())
            {
                wakes_match = false;
                break;
            }
        }
        if !wakes_match {
            continue;
        }

        let changed = tx.execute(
            "UPDATE agent_runs SET state='cancelled',finished_at_unix=COALESCE(finished_at_unix,?3) WHERE agent_run_id=?1 AND project_id=?2 AND state='unknown' AND controller_generation=?4",
            params![run_id,project_id,now_unix,owner_generation],
        ).map_err(|error| error.to_string())?;
        if changed != 1 {
            continue;
        }
        let changed = tx.execute(
            "UPDATE agent_launch_reservations SET lifecycle='cancelled',updated_at_unix=?3 WHERE agent_run_id=?1 AND project_id=?2 AND reservation_digest=?4 AND lifecycle='reserved' AND launch_phase='precreate_rejected'",
            params![run_id,project_id,now_unix,digest],
        ).map_err(|error| error.to_string())?;
        if changed != 1 {
            return Err("rejected launch reservation changed during finalization".into());
        }
        let changed = tx.execute(
            "UPDATE execution_slots SET disposition='released' WHERE pool=?1 AND slot_index=?2 AND project_id=?3 AND ticket_run_id IS ?4 AND owner_kind='agent_run' AND owner_id=?5 AND reservation_epoch=?6 AND controller_generation=?7 AND disposition='unknown'",
            params![reservation.pool,reservation.slot_index,project_id,reservation.ticket_run_id.as_ref().map(|id| id.as_str()),run_id,reservation.project_epoch,original_generation],
        ).map_err(|error| error.to_string())?;
        if changed != 1 {
            return Err("rejected launch slot changed during finalization".into());
        }
        for item in &reservation.wake_snapshot.inputs {
            let changed = tx.execute(
                "UPDATE role_wake_inputs SET lifecycle='superseded' WHERE wake_input_id=?1 AND project_id=?2 AND role_session_id=?3 AND consuming_agent_run_id=?4 AND lifecycle='assigned'",
                params![item.wake_input_id,project_id,reservation.role_session_id,run_id],
            ).map_err(|error| error.to_string())?;
            if changed != 1 {
                return Err("assigned wake changed during rejected launch finalization".into());
            }
        }
        finalized += 1;
    }
    tx.commit().map_err(|error| error.to_string())?;
    Ok(finalized)
}

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

fn validate_reservation_identity(
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
    Ok((digest.as_str().to_owned(), lifecycle))
}

fn validate_live_reservation_scope(
    tx: &Transaction<'_>,
    owner_generation: u64,
    reservation: &AgentLaunchReservation,
    lifecycle: &str,
) -> Result<(), String> {
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
    Ok(())
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
    let (digest, lifecycle) = validate_reservation_identity(&tx, owner_generation, reservation)?;
    let phase = phase_for(&tx, reservation, &digest)?;
    if phase == Phase::PrecreateRejected {
        if lifecycle != "reserved" {
            return Err("pre-create rejection conflicts with reservation lifecycle".into());
        }
        let receipt = rejection_receipt(reservation)?;
        tx.commit().map_err(|error| error.to_string())?;
        return Ok(Admission::Rejected { receipt });
    }
    validate_live_reservation_scope(&tx, owner_generation, reservation, &lifecycle)?;
    if phase == Phase::NotStarted && lifecycle != "reserved" {
        return Err("launch phase conflicts with reservation lifecycle".into());
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
    let (digest, lifecycle) = validate_reservation_identity(&tx, owner_generation, reservation)?;
    validate_live_reservation_scope(&tx, owner_generation, reservation, &lifecycle)?;
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
    let (digest, lifecycle) = validate_reservation_identity(&tx, owner_generation, reservation)?;
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
    if !(18..=crate::store::SCHEMA_VERSION).contains(&version) {
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
        assert_eq!(crate::store::SCHEMA_VERSION, 21);
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
             DROP TABLE learning_decisions;
             DROP TABLE learning_findings;
             DROP TABLE learning_batches;
             DROP TABLE supervisor_topic_publications;
             DELETE FROM schema_migrations WHERE version=21;
             DELETE FROM schema_migrations WHERE version=20;
             DELETE FROM schema_migrations WHERE version=19;
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
