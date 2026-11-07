use std::path::Path;

use rusqlite::{Connection, OpenFlags, OptionalExtension};

use crate::dashboard::{
    AgentRow, DashboardSnapshot, HumanInboxRow, ProjectRow, TicketRow, WaitRow,
};
use crate::domain::ids::{HumanRequestId, TicketRunId};

/// Read-only, lock-free dashboard projection. Older schemas return the rows
/// they can represent and an empty human inbox; the human runtime adapter
/// supplies requests when its versioned table is present.
pub fn read_projection(state_root: &Path) -> Result<DashboardSnapshot, String> {
    let path = state_root.join("state.sqlite3");
    let db = Connection::open_with_flags(
        &path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| format!("{}: {e}", path.display()))?;
    db.busy_timeout(std::time::Duration::from_secs(2))
        .map_err(|e| e.to_string())?;
    let version: i64 = db
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .map_err(|e| e.to_string())?;
    if version < 6 {
        return Err(format!(
            "dashboard requires runtime schema version 6 or newer (found {version})"
        ));
    }
    let mut projects = Vec::new();
    {
        let mut q = db.prepare("SELECT p.project_id,p.mode,r.observed_lifecycle FROM projects p LEFT JOIN project_runtimes r USING(project_id) ORDER BY p.project_id").map_err(|e| e.to_string())?;
        for row in q
            .query_map([], |r| {
                Ok(ProjectRow {
                    project_id: r.get(0)?,
                    mode: r.get(1)?,
                    lifecycle: r
                        .get::<_, Option<String>>(2)?
                        .unwrap_or_else(|| "unknown".into()),
                })
            })
            .map_err(|e| e.to_string())?
        {
            projects.push(row.map_err(|e| e.to_string())?);
        }
    }
    let pin_supported = table_exists(&db, "ticket_view_pins")?;
    let ticket_sql = if pin_supported {
        "SELECT t.ticket_run_id,t.project_id,t.namespace,t.ticket_id,t.internal_phase,t.activity,t.external_status,t.revision,COALESCE(v.pinned,0) FROM ticket_runs t LEFT JOIN ticket_view_pins v USING(ticket_run_id) ORDER BY t.project_id,t.ticket_id,t.generation DESC"
    } else {
        "SELECT ticket_run_id,project_id,namespace,ticket_id,internal_phase,activity,external_status,revision,0 FROM ticket_runs ORDER BY project_id,ticket_id,generation DESC"
    };
    let mut tickets = Vec::new();
    {
        let mut q = db.prepare(ticket_sql).map_err(|e| e.to_string())?;
        for row in q
            .query_map([], |r| {
                let id: String = r.get(0)?;
                Ok((
                    id,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, String>(6)?,
                    r.get::<_, u64>(7)?,
                    r.get::<_, bool>(8)?,
                ))
            })
            .map_err(|e| e.to_string())?
        {
            let (id, p, n, t, phase, activity, status, revision, pinned) =
                row.map_err(|e| e.to_string())?;
            tickets.push(TicketRow {
                ticket_run_id: TicketRunId::parse(id)?,
                project_id: p,
                namespace: n,
                ticket_id: t,
                phase,
                activity,
                external_status: status,
                revision,
                pinned,
            });
        }
    }
    let mut agents = Vec::new();
    {
        let mut q=db.prepare("SELECT agent_run_id,project_id,role_session_id,logical_owner,state,rex_session_id,rex_window_id,rex_block_id FROM agent_runs ORDER BY started_at_unix DESC,agent_run_id").map_err(|e|e.to_string())?;
        for row in q
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, Option<String>>(5)?,
                    r.get::<_, Option<String>>(6)?,
                    r.get::<_, Option<String>>(7)?,
                ))
            })
            .map_err(|e| e.to_string())?
        {
            let (id, p, role_session, owner, state, session, window, block) =
                row.map_err(|e| e.to_string())?;
            let ticket_run_id = role_session.as_deref().and_then(|s| {
                s.split_once("ticket_run:")
                    .and_then(|(_, id)| TicketRunId::parse(id.to_owned()).ok())
            });
            let role = owner.rsplit(':').next().unwrap_or(&owner).to_owned();
            agents.push(AgentRow {
                agent_run_id: id,
                project_id: p,
                ticket_run_id,
                role,
                state,
                rex_session_id: session,
                rex_window_id: window,
                rex_block_id: block,
            });
        }
    }
    let mut waits = Vec::new();
    {
        let mut q=db.prepare("SELECT project_id,subject_id,kind,status,last_error FROM effects WHERE status IN ('pending','claimed','uncertain','failed') ORDER BY created_at_unix").map_err(|e|e.to_string())?;
        for row in q
            .query_map([], |r| {
                Ok(WaitRow {
                    project_id: r.get(0)?,
                    ticket_run_id: None,
                    kind: r.get(2)?,
                    detail: format!(
                        "{} {}",
                        r.get::<_, String>(3)?,
                        r.get::<_, Option<String>>(4)?.unwrap_or_default()
                    ),
                })
            })
            .map_err(|e| e.to_string())?
        {
            waits.push(row.map_err(|e| e.to_string())?);
        }
    }
    let mut human_requests = Vec::new();
    if table_exists(&db, "human_requests")? {
        let mut q=db.prepare("SELECT request_id,project_id,question,choices_json,subject_digest,expires_at_unix FROM human_requests WHERE lifecycle IN ('pending','queued') ORDER BY created_at_unix").map_err(|e|e.to_string())?;
        for row in q
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, i64>(5)?,
                ))
            })
            .map_err(|e| e.to_string())?
        {
            let (id, project_id, question, choices, digest, expiry) =
                row.map_err(|e| e.to_string())?;
            human_requests.push(HumanInboxRow {
                request_id: HumanRequestId::parse(id)?,
                project_id,
                question,
                choices: serde_json::from_str(&choices).unwrap_or_default(),
                subject_digest: digest,
                expires_at_unix: expiry,
            });
        }
    }
    Ok(DashboardSnapshot {
        observed_at_unix: unix_now(),
        projects,
        tickets,
        agents,
        waits,
        human_requests,
    })
}
fn table_exists(db: &Connection, name: &str) -> Result<bool, String> {
    db.query_row(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
        [name],
        |r| r.get::<_, i64>(0),
    )
    .optional()
    .map(|v| v.is_some())
    .map_err(|e| e.to_string())
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
    use tempfile::tempdir;

    #[test]
    fn empty_runtime_projection_is_read_only_and_complete() {
        let root = tempdir().unwrap();
        let store = crate::store::ConfigStore::open_test(root.path()).unwrap();
        drop(store);
        let before = std::fs::metadata(root.path().join("state.sqlite3"))
            .unwrap()
            .len();
        let view = read_projection(root.path()).unwrap();
        let after = std::fs::metadata(root.path().join("state.sqlite3"))
            .unwrap()
            .len();
        assert_eq!(before, after);
        assert!(view.projects.is_empty());
        assert!(view.tickets.is_empty());
        assert!(view.agents.is_empty());
        assert!(view.waits.is_empty());
        assert!(view.human_requests.is_empty());
    }

    #[test]
    fn stale_schema_is_reported_without_migration() {
        let root = tempdir().unwrap();
        let path = root.path().join("state.sqlite3");
        let db = Connection::open(&path).unwrap();
        db.pragma_update(None, "user_version", 5).unwrap();
        drop(db);
        assert_eq!(
            read_projection(root.path()).unwrap_err(),
            "dashboard requires runtime schema version 6 or newer (found 5)"
        );
        let db = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        let version: i64 = db
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(version, 5);
    }
}
