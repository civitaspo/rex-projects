//! Typed dashboard reads and write intents. SQL for the dashboard stays behind
//! this store boundary; consumers receive validated IDs and immutable runtime
//! authority instead of inspecting or guessing at schema details.

use std::path::Path;

use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};

use crate::dashboard::{
    AgentRow, DashboardSnapshot, FocusTarget, HumanInboxRow, ProjectRow, TicketRow, WaitRow,
};
use crate::domain::ids::{AgentRunId, Digest, TicketRunId};
use crate::launch::{AgentLaunchAuthority, RexFocusTarget, StartAgentEffectPayload};
use crate::store::ConfigStore;

/// Build one schema-versioned snapshot without acquiring the machine-owner
/// lock. The projection uses the v8 schema directly and does not migrate it.
pub fn read_projection(state_root: &Path) -> Result<DashboardSnapshot, String> {
    let path = state_root.join("state.sqlite3");
    let db = Connection::open_with_flags(
        &path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|error| format!("{}: {error}", path.display()))?;
    db.busy_timeout(std::time::Duration::from_secs(2))
        .map_err(|error| error.to_string())?;
    let version: i64 = db
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| error.to_string())?;
    if version < 8 {
        return Err(format!(
            "dashboard requires runtime schema version 8 or newer (found {version})"
        ));
    }

    let projects = {
        let mut statement = db.prepare("SELECT p.project_id,p.mode,r.observed_lifecycle FROM projects p JOIN project_runtimes r USING(project_id) ORDER BY p.project_id").map_err(|error| error.to_string())?;
        statement
            .query_map([], |row| {
                Ok(ProjectRow {
                    project_id: row.get(0)?,
                    mode: row.get(1)?,
                    lifecycle: row.get(2)?,
                })
            })
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?
    };

    let tickets = {
        let mut statement = db.prepare("SELECT t.ticket_run_id,t.project_id,t.namespace,t.ticket_id,t.internal_phase,t.activity,t.external_status,t.revision FROM ticket_runs t WHERE t.generation=(SELECT MAX(latest.generation) FROM ticket_runs latest WHERE latest.project_id=t.project_id AND latest.namespace=t.namespace AND latest.ticket_id=t.ticket_id) ORDER BY t.project_id,t.ticket_id").map_err(|error| error.to_string())?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, u64>(7)?,
                ))
            })
            .map_err(|error| error.to_string())?;
        rows.map(|row| {
            let (run_id, project_id, namespace, ticket_id, phase, activity, status, revision) =
                row.map_err(|error| error.to_string())?;
            let view: Option<(String, bool)> = db
                .query_row(
                    "SELECT view_id,pinned FROM rex_views WHERE project_id=?1 AND view_kind='ticket' AND ticket_namespace=?2 AND ticket_id=?3 AND lifecycle='active' ORDER BY view_epoch DESC LIMIT 1",
                    params![project_id, namespace, ticket_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(|error| error.to_string())?;
            Ok(TicketRow {
                ticket_run_id: TicketRunId::parse(run_id)?,
                project_id,
                namespace,
                ticket_id,
                phase,
                activity,
                external_status: status,
                revision,
                pinned: view.as_ref().map(|(_, pinned)| *pinned),
                rex_view_id: view.map(|(id, _)| Digest::parse(id)).transpose()?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?
    };

    let agents = {
        let mut statement = db.prepare("SELECT agent_run_id,project_id,logical_owner,state,rex_session_id,rex_window_id,rex_block_id FROM agent_runs ORDER BY started_at_unix DESC,agent_run_id").map_err(|error| error.to_string())?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                ))
            })
            .map_err(|error| error.to_string())?;
        rows.map(|row| {
            let (raw_id, project_id, logical_owner, state, session, window, block) =
                row.map_err(|error| error.to_string())?;
            let run_id = AgentRunId::parse(raw_id)?;
            let authority = read_authority(&db, &run_id)?;
            Ok(AgentRow {
                agent_run_id: run_id.to_string(),
                project_id,
                ticket_run_id: authority
                    .as_ref()
                    .and_then(|authority| authority.ticket_run_id.clone()),
                role: authority
                    .as_ref()
                    .map(|authority| format!("{:?}", authority.role).to_lowercase())
                    .unwrap_or(logical_owner),
                state,
                rex_session_id: authority
                    .as_ref()
                    .map(|authority| authority.rex_session_id.clone())
                    .or(session),
                rex_window_id: authority
                    .as_ref()
                    .map(|authority| authority.rex_window_id.clone())
                    .or(window),
                rex_block_id: authority
                    .as_ref()
                    .map(|authority| authority.rex_block_id.clone())
                    .or(block),
                rex_view_id: authority.map(|authority| authority.rex_view_id),
            })
        })
        .collect::<Result<Vec<_>, String>>()?
    };

    let effect_waits = {
        let mut statement = db.prepare("SELECT operation_id,project_id,subject_type,subject_id,kind,status,last_error FROM effects WHERE status IN ('pending','claimed','uncertain','failed') ORDER BY created_at_unix").map_err(|error| error.to_string())?;
        statement
            .query_map([], |row| {
                let ticket = match (row.get::<_, String>(2)?.as_str(), row.get::<_, String>(3)?) {
                    ("ticket_run", id) => TicketRunId::parse(id).ok(),
                    _ => None,
                };
                Ok((
                    row.get::<_, String>(0)?,
                    WaitRow {
                        project_id: row.get(1)?,
                        ticket_run_id: ticket,
                        kind: row.get(4)?,
                        detail: format!(
                            "{} {}",
                            row.get::<_, String>(5)?,
                            row.get::<_, Option<String>>(6)?.unwrap_or_default()
                        ),
                    },
                ))
            })
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?
    };
    let handoff_waits = if version >= 18 {
        read_ambiguous_launch_waits(&db)?
    } else {
        Vec::new()
    };
    let handoff_operations = handoff_waits
        .iter()
        .map(|(operation, _)| operation.as_str())
        .collect::<std::collections::HashSet<_>>();
    let mut waits = effect_waits
        .into_iter()
        .filter_map(|(operation, wait)| {
            (!handoff_operations.contains(operation.as_str())).then_some(wait)
        })
        .collect::<Vec<_>>();
    if version >= 15 {
        let mut statement = db.prepare(
            "SELECT d.project_id,d.ticket_run_id,d.state,d.failure_code,d.attempt_count,d.next_attempt_at_unix FROM merge_observation_deferrals d JOIN agent_result_evidence e ON e.evidence_id=d.source_evidence_id LEFT JOIN agent_result_reducer_ack a ON a.evidence_id=d.source_evidence_id WHERE a.evidence_id IS NULL ORDER BY d.created_at_unix,d.source_evidence_id",
        ).map_err(|error| error.to_string())?;
        let deferrals = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, u32>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            })
            .map_err(|error| error.to_string())?;
        for deferral in deferrals {
            let (project_id, ticket_run_id, state, failure_code, attempts, next_attempt) =
                deferral.map_err(|error| error.to_string())?;
            if !matches!(
                state.as_str(),
                "waiting" | "exhausted" | "permanently_invalid"
            ) {
                return Err("stored MergeAssessment observation state is invalid".into());
            }
            waits.push(WaitRow {
                project_id,
                ticket_run_id: Some(TicketRunId::parse(ticket_run_id)?),
                kind: "merge_observation".into(),
                detail: format!(
                    "{state}; failure={failure_code}; attempts={attempts}; next_attempt_at_unix={next_attempt}"
                ),
            });
        }
    }
    waits.extend(handoff_waits.into_iter().map(|(_, wait)| wait));

    let human_requests = ConfigStore::list_human_requests(state_root, None)?
        .into_iter()
        .map(|summary| {
            let lifecycle = serde_json::to_value(summary.lifecycle)
                .map_err(|error| error.to_string())?
                .as_str()
                .unwrap_or("unknown")
                .to_owned();
            let request = summary.request;
            let choices = request
                .choices
                .iter()
                .map(|choice| {
                    serde_json::to_value(choice)
                        .ok()
                        .and_then(|value| value.as_str().map(str::to_owned))
                        .unwrap_or_else(|| format!("{choice:?}").to_lowercase())
                })
                .collect();
            Ok(HumanInboxRow {
                request_id: request.request_id,
                project_id: request.subject.project_id.to_string(),
                question: request.question,
                choices,
                subject_digest: request.subject.digest()?.to_string(),
                expires_at_unix: request.expires_at_unix as i64,
                lifecycle,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

    Ok(DashboardSnapshot {
        observed_at_unix: unix_now(),
        projects,
        tickets,
        agents,
        waits,
        human_requests,
    })
}

fn read_ambiguous_launch_waits(db: &Connection) -> Result<Vec<(String, WaitRow)>, String> {
    let mut statement = db
        .prepare(
            "SELECT a.agent_run_id,a.project_id,a.operation_id,a.reservation_digest,a.reservation_json,a.launch_phase,r.state,r.launch_operation_id,s.project_id,s.ticket_run_id,s.owner_kind,s.owner_id,s.disposition,e.project_id,e.subject_type,e.subject_id,e.kind,e.request_json,e.request_digest,e.status,s.pool,s.slot_index
             FROM agent_launch_reservations a
             JOIN agent_runs r ON r.agent_run_id=a.agent_run_id AND r.project_id=a.project_id
             JOIN execution_slots s ON s.owner_kind='agent_run' AND s.owner_id=a.agent_run_id AND s.project_id=a.project_id
             LEFT JOIN effects e ON e.operation_id=a.operation_id
             WHERE a.lifecycle='reserved' AND a.launch_phase IN ('ambiguous','create_attempted','legacy_unknown')
               AND r.state IN ('launch_pending','unknown') AND r.launch_operation_id=a.operation_id
               AND s.disposition IN ('launch_pending','unknown')
             ORDER BY a.created_at_unix,a.agent_run_id",
        )
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, Option<String>>(9)?,
                row.get::<_, String>(10)?,
                row.get::<_, String>(11)?,
                row.get::<_, String>(12)?,
                row.get::<_, Option<String>>(13)?,
                row.get::<_, Option<String>>(14)?,
                row.get::<_, Option<String>>(15)?,
                row.get::<_, Option<String>>(16)?,
                row.get::<_, Option<String>>(17)?,
                row.get::<_, Option<String>>(18)?,
                row.get::<_, Option<String>>(19)?,
                row.get::<_, String>(20)?,
                row.get::<_, u32>(21)?,
            ))
        })
        .map_err(|error| error.to_string())?;
    let mut waits = Vec::new();
    for row in rows {
        let (
            run_id,
            project_id,
            operation_id,
            reservation_digest,
            reservation_json,
            phase,
            run_state,
            run_operation,
            slot_project,
            slot_ticket,
            owner_kind,
            owner_id,
            disposition,
            effect_project,
            subject_type,
            subject_id,
            effect_kind,
            request_json,
            request_digest,
            effect_status,
            slot_pool,
            slot_index,
        ) = row.map_err(|error| error.to_string())?;
        let Ok(run_id) = AgentRunId::parse(run_id) else {
            continue;
        };
        let Ok(reservation) =
            crate::protocol::parse_unique::<serde_json::Value>(reservation_json.as_bytes())
        else {
            continue;
        };
        if crate::store::content_digest(&reservation_json) != reservation_digest
            || reservation["schema_version"] != 1
            || reservation["agent_run_id"].as_str() != Some(run_id.as_str())
            || reservation["project_id"].as_str() != Some(project_id.as_str())
            || reservation["operation_id"].as_str() != Some(operation_id.as_str())
            || reservation.get("ticket_run_id").is_none()
            || run_operation != operation_id
            || slot_project != project_id
            || owner_kind != "agent_run"
            || owner_id != run_id.as_str()
            || !matches!(run_state.as_str(), "launch_pending" | "unknown")
            || !matches!(disposition.as_str(), "launch_pending" | "unknown")
            || reservation["ticket_run_id"].as_str() != slot_ticket.as_deref()
            || reservation["pool"].as_str() != Some(slot_pool.as_str())
            || reservation["slot_index"].as_u64() != Some(u64::from(slot_index))
        {
            continue;
        }
        let effect = match (
            effect_project,
            subject_type,
            subject_id,
            effect_kind,
            request_json,
            request_digest,
            effect_status,
        ) {
            (
                Some(effect_project),
                Some(subject_type),
                Some(subject_id),
                Some(effect_kind),
                Some(request_json),
                Some(request_digest),
                Some(status),
            ) if effect_project == project_id
                && subject_type == "agent_run"
                && subject_id == run_id.as_str()
                && effect_kind == "start_agent" =>
            {
                let Ok(payload) = crate::protocol::parse_unique::<StartAgentEffectPayload>(
                    request_json.as_bytes(),
                ) else {
                    continue;
                };
                if payload.validate().is_err()
                    || payload.agent_run_id != run_id
                    || payload.launch_reservation_digest.as_str() != reservation_digest
                    || crate::store::content_digest(&request_json) != request_digest
                {
                    continue;
                }
                Some(status)
            }
            _ => None,
        };
        if effect.is_none()
            || (phase != "ambiguous"
                && !effect
                    .as_deref()
                    .is_some_and(|status| matches!(status, "uncertain" | "failed")))
        {
            continue;
        }
        let ticket_run_id = reservation["ticket_run_id"].as_str().map(str::to_owned);
        let ticket_scope = ticket_run_id
            .as_deref()
            .map(|id| format!(" for TicketRun {id}"))
            .unwrap_or_default();
        let detail = format!(
            "AgentRun {}{} has an unresolved {} launch; a process may still exist. Inspect this AgentRun's Rex session and any recorded PID/start identity; missing identity remains unresolved. Keep its execution slot and worktree reserved until exit is verified.",
            run_id, ticket_scope, phase
        );
        let ticket_run_id = ticket_run_id.map(TicketRunId::parse).transpose()?;
        waits.push((
            operation_id,
            WaitRow {
                project_id,
                ticket_run_id,
                kind: "agent_launch_handoff".into(),
                detail,
            },
        ));
    }
    Ok(waits)
}

/// Resolve a focus request through immutable Agent launch authority and the
/// active Rex view/block tables. A caller cannot choose an unrelated block.
pub fn read_focus_target(
    state_root: &Path,
    owner_generation: u64,
    agent_run_id: &AgentRunId,
) -> Result<FocusTarget, String> {
    let path = state_root.join("state.sqlite3");
    let db = Connection::open_with_flags(
        &path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|error| format!("{}: {error}", path.display()))?;
    db.busy_timeout(std::time::Duration::from_secs(2))
        .map_err(|error| error.to_string())?;
    let authority = read_authority(&db, agent_run_id)?
        .ok_or_else(|| "AgentRun has no launch authority".to_owned())?;
    if authority.controller_generation != owner_generation {
        return Err("Agent launch authority belongs to a stale controller generation".into());
    }
    let target = read_authorized_focus_target(&db, &authority)?;
    Ok(FocusTarget {
        view_id: target.view_id,
        rex_server_identity: target.rex_server_identity,
        session_id: target.rex_session_id,
        window_id: target.rex_window_id,
        block_id: target.rex_block_id,
    })
}

/// Return the currently active owner generation, if a controller is running.
pub fn active_owner_generation(state_root: &Path) -> Result<Option<u64>, String> {
    let status = ConfigStore::status(state_root)?;
    Ok(status
        .owner_is_live()
        .then_some(status.owner_generation)
        .flatten())
}

/// Pin the active Rex view for an exact TicketRun revision. This write is a
/// small controller-fenced state update; the UI never receives a DB handle.
pub fn set_ticket_pin(
    state_root: &Path,
    owner_generation: u64,
    ticket_run_id: &TicketRunId,
    expected_revision: u64,
    expected_view_id: &Digest,
    pinned: bool,
) -> Result<(), String> {
    let path = state_root.join("state.sqlite3");
    let mut db = Connection::open_with_flags(
        &path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|error| format!("{}: {error}", path.display()))?;
    db.busy_timeout(std::time::Duration::from_secs(2))
        .map_err(|error| error.to_string())?;
    let tx = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| error.to_string())?;
    let current_generation: Option<u64> = tx
        .query_row(
            "SELECT generation FROM controller_owners WHERE singleton=1 AND stopped_at_unix IS NULL",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    if current_generation != Some(owner_generation) {
        return Err("pin request is fenced to a stale controller generation".into());
    }
    let ticket: Option<(String, String, String, u64)> = tx
        .query_row(
            "SELECT project_id,namespace,ticket_id,revision FROM ticket_runs WHERE ticket_run_id=?1",
            [ticket_run_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    let Some((project_id, namespace, ticket_id, revision)) = ticket else {
        return Err("TicketRun not found".into());
    };
    if revision != expected_revision {
        return Err("TicketRun revision changed; refresh the dashboard".into());
    }
    let view_id: String = tx
        .query_row(
            "SELECT view_id FROM rex_views WHERE project_id=?1 AND view_kind='ticket' AND ticket_namespace=?2 AND ticket_id=?3 AND lifecycle='active' ORDER BY view_epoch DESC LIMIT 1",
            params![project_id, namespace, ticket_id],
            |row| row.get(0),
        )
        .map_err(|_| "active Rex ticket view not found".to_owned())?;
    if view_id != expected_view_id.as_str() {
        return Err("active Rex ticket view changed; refresh the dashboard".into());
    }
    let changed = tx
        .execute(
            "UPDATE rex_views SET pinned=?4,updated_at_unix=?5 WHERE view_id=?1 AND project_id=?2 AND ticket_namespace=?3 AND ticket_id=?6 AND lifecycle='active'",
            params![view_id, project_id, namespace, pinned, unix_now(), ticket_id],
        )
        .map_err(|error| error.to_string())?;
    if changed != 1 {
        return Err("active Rex ticket view not found".into());
    }
    tx.commit().map_err(|error| error.to_string())
}

fn read_authority(
    db: &Connection,
    agent_run_id: &AgentRunId,
) -> Result<Option<AgentLaunchAuthority>, String> {
    let stored: Option<(String, String, String)> = db
        .query_row(
            "SELECT authority_json,descriptor_digest,authority_digest FROM agent_launch_authority WHERE agent_run_id=?1",
            [agent_run_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    stored
        .map(|(json, descriptor_digest, authority_digest)| {
            let authority: AgentLaunchAuthority = crate::protocol::parse_unique(json.as_bytes())
                .map_err(|error| format!("stored Agent launch authority is invalid: {error}"))?;
            authority.validate()?;
            if authority.agent_run_id != *agent_run_id
                || authority.descriptor_digest.as_str() != descriptor_digest
                || authority.digest()?.as_str() != authority_digest
            {
                return Err("stored Agent launch authority digest fields do not match".into());
            }
            Ok(authority)
        })
        .transpose()
}

fn read_authorized_focus_target(
    db: &Connection,
    authority: &AgentLaunchAuthority,
) -> Result<RexFocusTarget, String> {
    let target: Option<(String, String, String)> = db
        .query_row(
            "SELECT v.rex_server_identity,v.rex_session_id,v.rex_window_id FROM rex_views v JOIN rex_view_blocks b USING(view_id) WHERE v.view_id=?1 AND b.block_id=?2 AND v.lifecycle='active' AND b.lifecycle!='closed'",
            params![authority.rex_view_id.as_str(), authority.rex_block_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    let (server, session, window) =
        target.ok_or_else(|| "active Rex focus target not found".to_owned())?;
    if server != authority.rex_server_identity
        || session != authority.rex_session_id
        || window != authority.rex_window_id
    {
        return Err("Rex focus target differs from immutable launch authority".into());
    }
    Ok(RexFocusTarget {
        view_id: authority.rex_view_id.clone(),
        rex_server_identity: server,
        rex_session_id: session,
        rex_window_id: window,
        rex_block_id: authority.rex_block_id.clone(),
    })
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_snapshot_reads_the_current_schema_without_migrating() {
        let temp = tempfile::tempdir().unwrap();
        drop(ConfigStore::open_test(temp.path()).unwrap());
        let path = temp.path().join("state.sqlite3");
        let before = std::fs::metadata(&path).unwrap().len();
        let snapshot = read_projection(temp.path()).unwrap();
        let after = std::fs::metadata(&path).unwrap().len();
        assert_eq!(before, after);
        assert!(snapshot.projects.is_empty());
        assert!(snapshot.tickets.is_empty());
        assert!(snapshot.agents.is_empty());
        assert!(snapshot.waits.is_empty());
        assert!(snapshot.human_requests.is_empty());
    }

    #[test]
    fn merge_observation_deferrals_are_visible_and_acknowledged_rows_are_hidden() {
        let temp = tempfile::tempdir().unwrap();
        let store = ConfigStore::open_test(temp.path()).unwrap();
        let db = store.test_connection();
        db.execute_batch("PRAGMA foreign_keys=OFF;").unwrap();
        for (evidence_id, state, failure, attempt, next_at) in [
            ("waiting-evidence", "waiting", "timed_out", 1, 105_i64),
            ("exhausted-evidence", "exhausted", "timed_out", 5, 100_i64),
            (
                "invalid-evidence",
                "permanently_invalid",
                "permanent_invalid",
                1,
                100_i64,
            ),
            ("resolved-evidence", "waiting", "timed_out", 1, 105_i64),
        ] {
            db.execute(
                "INSERT INTO agent_result_evidence(evidence_id,agent_run_id,project_id,role,ticket_run_id,attempt,run_epoch,message_id,content_digest,outcome,result_digest,result_json,artifact_refs_json,received_at_unix) VALUES (?1,'fixture-agent','project-a','merge_decision','ticket-run-a',1,1,?1,?2,'completed',?2,'{}','[]',1)",
                rusqlite::params![evidence_id, "a".repeat(64)],
            )
            .unwrap();
            db.execute(
                "INSERT INTO merge_observation_deferrals(source_evidence_id,binding_digest,source_result_digest,project_id,config_revision,config_digest,ticket_run_id,ticket_run_revision,publication_set_digest,attempt_count,next_attempt_at_unix,state,failure_code,created_at_unix,updated_at_unix) VALUES (?1,?2,?2,'project-a',1,?2,'ticket-run-a',4,?2,?3,?4,?5,?6,1,1)",
                rusqlite::params![evidence_id, "a".repeat(64), attempt, next_at, state, failure],
            )
            .unwrap();
        }
        db.execute(
            "INSERT INTO agent_result_reducer_ack(evidence_id,reducer_revision,disposition,acknowledged_at_unix) VALUES ('resolved-evidence',4,'applied',2)",
            [],
        )
        .unwrap();
        drop(store);

        let snapshot = read_projection(temp.path()).unwrap();
        let deferrals = snapshot
            .waits
            .iter()
            .filter(|wait| wait.kind == "merge_observation")
            .collect::<Vec<_>>();
        assert_eq!(deferrals.len(), 3);
        assert!(deferrals.iter().any(|wait| {
            wait.detail
                .starts_with("waiting; failure=timed_out; attempts=1; next_attempt_at_unix=105")
        }));
        assert!(deferrals.iter().any(|wait| {
            wait.detail
                .starts_with("exhausted; failure=timed_out; attempts=5;")
        }));
        assert!(deferrals.iter().any(|wait| {
            wait.detail
                .starts_with("permanently_invalid; failure=permanent_invalid;")
        }));
        assert!(deferrals.iter().all(|wait| {
            wait.ticket_run_id
                .as_ref()
                .is_some_and(|id| id.as_str() == "ticket-run-a")
        }));
    }

    #[test]
    fn schema_v14_dashboard_does_not_query_v15_deferrals() {
        let temp = tempfile::tempdir().unwrap();
        let store = ConfigStore::open_test(temp.path()).unwrap();
        store
            .test_connection()
            .execute_batch("DROP TABLE merge_observation_deferrals; PRAGMA user_version=14;")
            .unwrap();
        drop(store);

        let snapshot = read_projection(temp.path()).unwrap();
        assert!(snapshot.waits.is_empty());
    }

    #[test]
    fn stale_database_is_rejected_without_schema_probing() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("state.sqlite3");
        let db = Connection::open(&path).unwrap();
        db.pragma_update(None, "user_version", 7).unwrap();
        drop(db);
        assert_eq!(
            read_projection(temp.path()).unwrap_err(),
            "dashboard requires runtime schema version 8 or newer (found 7)"
        );
    }

    #[test]
    fn agent_locations_prefer_registered_authority_and_fall_back_to_legacy_columns() {
        use crate::domain::types::Role;
        use crate::engine::orchestration::{AgentAssertion, RoleOutputKind};
        use crate::roles::RoleResultMessage;
        use sha2::Digest as _;

        let payload = serde_json::json!({
            "ticket_reference": "fixture:T-1",
            "expected_ticket_revision": "4",
            "coordinator_profile": "judgment_claude",
            "priority": 3,
            "rationale": "dashboard location fixture"
        });
        let fixture = crate::store::agent_results::host_validation_fixture::host_validated_result(
            Role::Supervisor,
            RoleResultMessage {
                schema_version: crate::engine::orchestration::ROLE_RESULT_SCHEMA_VERSION,
                message_id: "dashboard-location-fixture".into(),
                kind: RoleOutputKind::DispatchRequest,
                assertion: AgentAssertion::Succeeded,
                structured_result: payload.clone(),
                result_digest: Some(
                    Digest::parse(format!(
                        "{:x}",
                        sha2::Sha256::digest(serde_json::to_vec(&payload).unwrap())
                    ))
                    .unwrap(),
                ),
                artifact_refs: Vec::new(),
            },
        )
        .unwrap();
        let agent_run_id = fixture.ingested.validated.binding.agent_run_id.clone();
        fixture.store.connection.execute(
            "UPDATE agent_runs SET rex_session_id=NULL,rex_window_id=NULL,rex_block_id=NULL WHERE agent_run_id=?1",
            [agent_run_id.as_str()],
        ).unwrap();

        let row = &read_projection(fixture._temp.path()).unwrap().agents[0];
        let serialized = serde_json::to_value(row).unwrap();
        assert_eq!(serialized["rex_session_id"], "fixture-session");
        assert_eq!(serialized["rex_window_id"], "fixture-window");
        assert_eq!(serialized["rex_block_id"], "fixture-block");

        fixture.store.connection.execute(
            "INSERT INTO agent_runs(agent_run_id,project_id,config_source,config_revision,config_digest,logical_owner,finite_turn,launch_operation_id,rex_session_id,rex_window_id,rex_block_id,state,controller_generation) SELECT 'legacy-agent-run',project_id,config_source,config_revision,config_digest,'legacy',1,'legacy-operation','legacy-session','legacy-window','legacy-block','running',controller_generation FROM agent_runs WHERE agent_run_id=?1",
            [agent_run_id.as_str()],
        ).unwrap();
        let snapshot = read_projection(fixture._temp.path()).unwrap();
        let row = snapshot
            .agents
            .iter()
            .find(|row| row.agent_run_id == "legacy-agent-run")
            .unwrap();
        let serialized = serde_json::to_value(row).unwrap();
        assert_eq!(serialized["rex_session_id"], "legacy-session");
        assert_eq!(serialized["rex_window_id"], "legacy-window");
        assert_eq!(serialized["rex_block_id"], "legacy-block");
    }
}
