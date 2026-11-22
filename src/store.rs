use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, Row, Transaction, TransactionBehavior, params};
use serde::Serialize;

use crate::domain::{
    Agent, Event, ExternalRef, Message, Outcome, Ticket, TicketState, is_closed_status, ticket_id,
};

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS events (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  at TEXT NOT NULL,
  actor TEXT NOT NULL,
  project_id TEXT,
  ticket_id TEXT,
  agent_id TEXT,
  kind TEXT NOT NULL,
  payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_by_ticket ON events (ticket_id, seq);
CREATE TABLE IF NOT EXISTS tickets (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  number INTEGER NOT NULL,
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  state TEXT NOT NULL,
  stage TEXT,
  summary TEXT,
  progress INTEGER,
  next TEXT,
  question TEXT,
  priority INTEGER NOT NULL,
  playbook TEXT,
  blocked_by TEXT NOT NULL,
  external_refs TEXT NOT NULL,
  artifacts TEXT NOT NULL,
  outcome TEXT,
  coordinator_id TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (project_id, number)
);
CREATE TABLE IF NOT EXISTS agents (
  id TEXT PRIMARY KEY,
  ticket_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  role TEXT NOT NULL,
  provider TEXT NOT NULL,
  cwd TEXT NOT NULL,
  state TEXT NOT NULL,
  harness_session_id TEXT,
  rex_session_id TEXT,
  rex_window_id TEXT,
  rex_block_id TEXT,
  launches INTEGER NOT NULL,
  activity TEXT,
  activity_message TEXT,
  exit_reason TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ticket_preparations (
  ticket_id TEXT PRIMARY KEY REFERENCES tickets(id),
  payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS pending_approvals (
  ticket_id TEXT PRIMARY KEY REFERENCES tickets(id),
  kind TEXT NOT NULL,
  summary TEXT NOT NULL,
  artifacts TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS approval_decisions (
  ticket_id TEXT NOT NULL REFERENCES tickets(id),
  kind TEXT NOT NULL,
  approved INTEGER NOT NULL,
  note TEXT,
  actor TEXT NOT NULL,
  at TEXT NOT NULL,
  PRIMARY KEY (ticket_id, kind)
);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY,
  ticket_id TEXT NOT NULL,
  sender TEXT NOT NULL,
  recipient TEXT NOT NULL,
  body TEXT NOT NULL,
  sent_at TEXT NOT NULL,
  read_at TEXT
);
CREATE INDEX IF NOT EXISTS messages_by_recipient ON messages (recipient, id);
"#;

/// One row of the event log.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct StoredEvent {
    pub seq: i64,
    pub at: String,
    pub actor: String,
    pub project_id: Option<String>,
    pub ticket_id: Option<String>,
    pub agent_id: Option<String>,
    pub event: Event,
}

/// Fields for a new Ticket. The store assigns its number and id.
#[derive(Clone, Debug, Default)]
pub struct NewTicket {
    pub project_id: String,
    pub title: String,
    pub body: String,
    pub priority: i64,
    pub playbook: Option<String>,
    pub blocked_by: Vec<String>,
    pub external_refs: Vec<ExternalRef>,
    pub ready: bool,
}

/// The SQLite event log and the projections built from it (ADR-0008).
pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        let conn = Connection::open(path)
            .with_context(|| format!("failed to open database {}", path.display()))?;
        Self::init(conn)
    }

    pub fn open_in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.busy_timeout(Duration::from_secs(10))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn })
    }

    /// Validates `event` against the current projections, then records it and
    /// updates the projections in one transaction.
    pub fn append(&mut self, actor: &str, event: Event) -> Result<i64> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let seq = append_in(&tx, actor, &event)?;
        tx.commit()?;
        Ok(seq)
    }

    /// Records several events in one transaction: all of them or none.
    pub fn append_all(&mut self, actor: &str, events: &[Event]) -> Result<()> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        for event in events {
            append_in(&tx, actor, event)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Records a human answer and any matching time-budget extension atomically.
    pub fn answer(
        &mut self,
        actor: &str,
        ticket_id: &str,
        answer: Option<String>,
        question: Option<String>,
    ) -> Result<()> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        append_in(
            &tx,
            actor,
            &Event::TicketAnswered {
                ticket_id: ticket_id.to_owned(),
                answer,
                question: question.clone(),
            },
        )?;
        if actor == "human"
            && let Some(question) = question
        {
            let exceeded: Option<(String, String)> = tx.query_row(
                    "SELECT json_extract(payload, '$.budget'), json_extract(payload, '$.resume_state') FROM events WHERE ticket_id = ?1 AND kind = 'budget_exceeded' AND json_extract(payload, '$.question') = ?2 ORDER BY seq DESC LIMIT 1",
                    params![ticket_id, question], |r| Ok((r.get(0)?, r.get(1)?))
                ).optional()?;
            if let Some((budget, resume_state)) = exceeded {
                let already_extended: bool = tx.query_row(
                        "SELECT EXISTS(SELECT 1 FROM events WHERE ticket_id = ?1 AND kind = 'budget_extended' AND json_extract(payload, '$.question') = ?2)",
                        params![ticket_id, question], |r| r.get(0)
                    )?;
                if !already_extended {
                    let budget: crate::domain::BudgetKind =
                        serde_json::from_value(serde_json::Value::String(budget))?;
                    let resume_state = resume_state.parse::<TicketState>()?;
                    append_in(
                        &tx,
                        actor,
                        &Event::BudgetExtended {
                            ticket_id: ticket_id.to_owned(),
                            budget,
                            resume_state,
                            question,
                        },
                    )?;
                }
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Records `events` only if fewer than `max` Agent slots are in use, in
    /// one transaction, so two admissions cannot both take the last slot.
    /// Returns whether they were recorded.
    pub fn append_within_slots(
        &mut self,
        actor: &str,
        events: &[Event],
        max: usize,
    ) -> Result<bool> {
        self.with_tx(|tx| {
            if slots_in_use_in(tx)? >= max {
                return Ok(false);
            }
            for event in events {
                append_in(tx, actor, event)?;
            }
            Ok(true)
        })
    }

    /// Runs `f` in one write transaction, committing only if it succeeds.
    pub fn with_tx<T>(&mut self, f: impl FnOnce(&Transaction<'_>) -> Result<T>) -> Result<T> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let value = f(&tx)?;
        tx.commit()?;
        Ok(value)
    }

    /// How many Agent slots under `limits.max_agents` are in use.
    pub fn slots_in_use(&self) -> Result<usize> {
        slots_in_use_in(&self.conn)
    }

    /// Creates a Ticket, allocating the next number in its Project.
    pub fn create_ticket(&mut self, actor: &str, new: NewTicket) -> Result<Ticket> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let number: i64 = tx.query_row(
            "SELECT COALESCE(MAX(number), 0) + 1 FROM tickets WHERE project_id = ?1",
            params![new.project_id],
            |row| row.get(0),
        )?;
        let id = ticket_id(&new.project_id, number);
        append_in(
            &tx,
            actor,
            &Event::TicketCreated {
                ticket_id: id.clone(),
                project_id: new.project_id,
                number,
                title: new.title,
                body: new.body,
                priority: new.priority,
                playbook: new.playbook,
                blocked_by: new.blocked_by,
                external_refs: new.external_refs,
                ready: new.ready,
            },
        )?;
        tx.commit()?;
        self.ticket(&id)?
            .context("created ticket is missing from the projection")
    }

    pub fn ticket(&self, id: &str) -> Result<Option<Ticket>> {
        let mut ticket = self
            .conn
            .query_row(
                &format!("SELECT {TICKET_COLUMNS} FROM tickets WHERE id = ?1"),
                params![id],
                ticket_from_row,
            )
            .optional()?;
        if let Some(ticket) = &mut ticket {
            ticket.pending_approval = pending_approval_in(&self.conn, id)?;
        }
        Ok(ticket)
    }

    /// Lists Tickets, optionally for one Project, ordered by Project and number.
    pub fn tickets(&self, project_id: Option<&str>) -> Result<Vec<Ticket>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {TICKET_COLUMNS} FROM tickets
             WHERE ?1 IS NULL OR project_id = ?1
             ORDER BY project_id, number"
        ))?;
        let rows = stmt.query_map(params![project_id], ticket_from_row)?;
        let mut tickets = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        for ticket in &mut tickets {
            ticket.pending_approval = pending_approval_in(&self.conn, &ticket.id)?;
        }
        Ok(tickets)
    }

    pub fn agent(&self, id: &str) -> Result<Option<Agent>> {
        Ok(self
            .conn
            .query_row(
                &format!("SELECT {AGENT_COLUMNS} FROM agents WHERE id = ?1"),
                params![id],
                agent_from_row,
            )
            .optional()?)
    }

    /// Lists Agents, optionally only those not yet exited.
    pub fn agents(&self, live_only: bool) -> Result<Vec<Agent>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {AGENT_COLUMNS} FROM agents
             WHERE ?1 = 0 OR state != 'exited'
             ORDER BY created_at, id"
        ))?;
        let rows = stmt.query_map(params![live_only], agent_from_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn agents_for_ticket(&self, ticket_id: &str) -> Result<Vec<Agent>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {AGENT_COLUMNS} FROM agents WHERE ticket_id = ?1 ORDER BY created_at, id"
        ))?;
        let rows = stmt.query_map(params![ticket_id], agent_from_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Returns events after `after_seq`, oldest first, at most `limit`.
    pub fn events_since(&self, after_seq: i64, limit: i64) -> Result<Vec<StoredEvent>> {
        self.query_events(
            "SELECT seq, at, actor, project_id, ticket_id, agent_id, payload
             FROM events WHERE seq > ?1 ORDER BY seq LIMIT ?2",
            params![after_seq, limit],
        )
    }

    /// Every event about one Ticket or its Agents, oldest first.
    pub fn ticket_events(&self, ticket_id: &str) -> Result<Vec<StoredEvent>> {
        self.query_events(
            "SELECT seq, at, actor, project_id, ticket_id, agent_id, payload
             FROM events WHERE ticket_id = ?1 ORDER BY seq",
            params![ticket_id],
        )
    }

    fn query_events(&self, sql: &str, args: impl rusqlite::Params) -> Result<Vec<StoredEvent>> {
        let mut stmt = self.conn.prepare(sql)?;
        let rows = stmt.query_map(args, |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, String>(6)?,
            ))
        })?;
        let mut events = Vec::new();
        for row in rows {
            let (seq, at, actor, project_id, ticket_id, agent_id, payload) = row?;
            let event = serde_json::from_str(&payload)
                .with_context(|| format!("event {seq} has an unreadable payload"))?;
            events.push(StoredEvent {
                seq,
                at,
                actor,
                project_id,
                ticket_id,
                agent_id,
                event,
            });
        }
        Ok(events)
    }

    /// The underlying connection, for modules that keep their own tables.
    /// The messages `agent_id` has not read yet, oldest first.
    pub fn unread(&self, agent_id: &str) -> Result<Vec<Message>> {
        unread_in(&self.conn, agent_id)
    }

    /// Every message about a Ticket, oldest first.
    pub fn ticket_messages(&self, ticket_id: &str) -> Result<Vec<Message>> {
        query_messages(
            &self.conn,
            "WHERE ticket_id = ?1 ORDER BY id",
            params![ticket_id],
        )
    }

    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    pub fn preparation(
        &self,
        ticket_id: &str,
    ) -> Result<Option<crate::playbook::TicketPreparation>> {
        let payload: Option<String> = self
            .conn
            .query_row(
                "SELECT payload FROM ticket_preparations WHERE ticket_id = ?1",
                params![ticket_id],
                |row| row.get(0),
            )
            .optional()?;
        payload
            .map(|text| serde_json::from_str(&text).context("invalid Ticket preparation snapshot"))
            .transpose()
    }

    pub fn budget_remaining(
        &self,
        ticket_id: &str,
    ) -> Result<Option<crate::budget::BudgetRemaining>> {
        let preparation = self.preparation(ticket_id)?;
        let events = self.ticket_events(ticket_id)?;
        if preparation.is_none() {
            return Ok(None);
        }
        let remaining = crate::budget::remaining(preparation.as_ref(), &events)?;
        if remaining.helpers.is_none() && remaining.minutes.is_none() {
            return Ok(None);
        }
        Ok(Some(remaining))
    }

    pub fn pending_approval(
        &self,
        ticket_id: &str,
    ) -> Result<Option<crate::domain::ApprovalRequest>> {
        pending_approval_in(&self.conn, ticket_id)
    }

    pub fn budget_question_pending(&self, ticket_id: &str) -> Result<bool> {
        budget_question_pending_in(&self.conn, ticket_id)
    }

    pub fn decide_approval(
        &mut self,
        actor: &str,
        ticket_id: &str,
        kind: &str,
        approved: bool,
        note: Option<String>,
    ) -> Result<()> {
        if actor != "human" {
            bail!("only a human may decide an Approval");
        }
        if !approved && note.as_deref().is_none_or(|note| note.trim().is_empty()) {
            bail!("a rejection needs a note");
        }
        self.append(
            actor,
            Event::ApprovalDecided {
                ticket_id: ticket_id.to_owned(),
                approval_kind: kind.to_owned(),
                approved,
                note,
            },
        )?;
        Ok(())
    }

    /// Drops the projections and rebuilds them by replaying every event.
    pub fn rebuild(&mut self) -> Result<()> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch("DELETE FROM pending_approvals; DELETE FROM approval_decisions; DELETE FROM ticket_preparations; DELETE FROM tickets; DELETE FROM agents; DELETE FROM messages;")?;
        let events: Vec<(String, String, String)> = {
            let mut stmt = tx.prepare("SELECT at, payload, actor FROM events ORDER BY seq")?;
            let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        for (at, payload, actor) in events {
            let event: Event = serde_json::from_str(&payload)?;
            project(&tx, &at, &actor, &event, Replay::Yes)?;
        }
        tx.commit()?;
        Ok(())
    }
}

fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

pub(crate) fn append_in(tx: &Transaction<'_>, actor: &str, event: &Event) -> Result<i64> {
    let at = now();
    project(tx, &at, actor, event, Replay::No)?;
    let project_id = match event {
        Event::TicketCreated { project_id, .. } | Event::AgentCreated { project_id, .. } => {
            Some(project_id.clone())
        }
        _ => match (event.ticket_id(), event.agent_id()) {
            (Some(ticket), _) => lookup(tx, "tickets", ticket)?,
            (None, Some(agent)) => lookup(tx, "agents", agent)?,
            (None, None) => None,
        },
    };
    let ticket_id = match (event.ticket_id(), event.agent_id()) {
        (Some(ticket), _) => Some(ticket.to_owned()),
        (None, Some(agent)) => tx
            .query_row(
                "SELECT ticket_id FROM agents WHERE id = ?1",
                params![agent],
                |row| row.get(0),
            )
            .optional()?,
        (None, None) => None,
    };
    tx.execute(
        "INSERT INTO events (at, actor, project_id, ticket_id, agent_id, kind, payload)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            at,
            actor,
            project_id,
            ticket_id,
            event.agent_id(),
            event.kind(),
            serde_json::to_string(event)?
        ],
    )?;
    Ok(tx.last_insert_rowid())
}

/// The messages `agent_id` has not read yet, oldest first.
pub(crate) fn unread_in(conn: &Connection, agent_id: &str) -> Result<Vec<Message>> {
    query_messages(
        conn,
        "WHERE recipient = ?1 AND read_at IS NULL ORDER BY id",
        params![agent_id],
    )
}

fn query_messages(
    conn: &Connection,
    filter: &str,
    args: impl rusqlite::Params,
) -> Result<Vec<Message>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT id, ticket_id, sender, recipient, body, sent_at FROM messages {filter}"
    ))?;
    let rows = stmt.query_map(args, |row| {
        Ok(Message {
            id: row.get(0)?,
            ticket_id: row.get(1)?,
            from: row.get(2)?,
            to: row.get(3)?,
            body: row.get(4)?,
            sent_at: row.get(5)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// Agent slots in use: every Agent that has not exited, except on a done
/// Ticket, whose pane stays only for the human to read, plus a slot reserved
/// for each active Ticket whose Coordinator has exited and will be relaunched.
pub(crate) fn slots_in_use_in(conn: &Connection) -> Result<usize> {
    let count: i64 = conn.query_row(
        "SELECT
           (SELECT COUNT(*) FROM agents a JOIN tickets t ON t.id = a.ticket_id
             WHERE a.state != 'exited' AND t.state != 'done')
         + (SELECT COUNT(*) FROM tickets t JOIN agents a ON a.id = t.coordinator_id
             WHERE t.state IN ('running', 'waiting', 'verifying') AND a.state = 'exited')",
        [],
        |row| row.get(0),
    )?;
    Ok(count as usize)
}

fn lookup(tx: &Transaction<'_>, table: &str, id: &str) -> Result<Option<String>> {
    Ok(tx
        .query_row(
            &format!("SELECT project_id FROM {table} WHERE id = ?1"),
            params![id],
            |row| row.get(0),
        )
        .optional()?)
}

fn ticket_state(tx: &Transaction<'_>, id: &str) -> Result<TicketState> {
    let state: Option<String> = tx
        .query_row(
            "SELECT state FROM tickets WHERE id = ?1",
            params![id],
            |row| row.get(0),
        )
        .optional()?;
    match state {
        Some(state) => state.parse(),
        None => bail!("ticket {id} does not exist"),
    }
}

fn require(id: &str, current: TicketState, allowed: &[TicketState], action: &str) -> Result<()> {
    if !allowed.contains(&current) {
        bail!("cannot {action} ticket {id} while it is {current}");
    }
    Ok(())
}

fn set_ticket_state(tx: &Transaction<'_>, id: &str, state: TicketState, at: &str) -> Result<()> {
    tx.execute(
        "UPDATE tickets SET state = ?2, updated_at = ?3 WHERE id = ?1",
        params![id, state.as_str(), at],
    )?;
    Ok(())
}

fn require_agent(tx: &Transaction<'_>, id: &str) -> Result<()> {
    let exists: Option<i64> = tx
        .query_row("SELECT 1 FROM agents WHERE id = ?1", params![id], |row| {
            row.get(0)
        })
        .optional()?;
    if exists.is_none() {
        bail!("agent {id} does not exist");
    }
    Ok(())
}

fn merge_artifacts(tx: &Transaction<'_>, id: &str, artifacts: &[String]) -> Result<()> {
    if artifacts.is_empty() {
        return Ok(());
    }
    let existing: String = tx.query_row(
        "SELECT artifacts FROM tickets WHERE id = ?1",
        params![id],
        |row| row.get(0),
    )?;
    let mut list: Vec<String> = serde_json::from_str(&existing)?;
    for artifact in artifacts {
        if !list.contains(artifact) {
            list.push(artifact.clone());
        }
    }
    tx.execute(
        "UPDATE tickets SET artifacts = ?2 WHERE id = ?1",
        params![id, serde_json::to_string(&list)?],
    )?;
    Ok(())
}

/// Applies one event to the projections, rejecting invalid transitions.
/// Rewrites a Ticket's external refs with `change`.
fn update_refs(
    tx: &Transaction<'_>,
    ticket_id: &str,
    at: &str,
    change: impl Fn(&mut ExternalRef),
) -> Result<()> {
    let refs: String = tx.query_row(
        "SELECT external_refs FROM tickets WHERE id = ?1",
        params![ticket_id],
        |row| row.get(0),
    )?;
    let mut refs: Vec<ExternalRef> = serde_json::from_str(&refs)?;
    if refs.is_empty() {
        return Ok(());
    }
    refs.iter_mut().for_each(change);
    tx.execute(
        "UPDATE tickets SET external_refs = ?2, updated_at = ?3 WHERE id = ?1",
        params![ticket_id, serde_json::to_string(&refs)?, at],
    )?;
    Ok(())
}

fn pending_approval_in(
    conn: &Connection,
    ticket_id: &str,
) -> Result<Option<crate::domain::ApprovalRequest>> {
    let value = conn
        .query_row(
            "SELECT kind, summary, artifacts FROM pending_approvals WHERE ticket_id = ?1",
            params![ticket_id],
            |row| {
                let artifacts: String = row.get(2)?;
                Ok(crate::domain::ApprovalRequest {
                    kind: row.get(0)?,
                    summary: row.get(1)?,
                    artifacts: serde_json::from_str(&artifacts).map_err(|err| {
                        rusqlite::Error::FromSqlConversionFailure(
                            2,
                            rusqlite::types::Type::Text,
                            Box::new(err),
                        )
                    })?,
                })
            },
        )
        .optional()?;
    Ok(value)
}

fn preparation_in(
    conn: &Connection,
    ticket_id: &str,
) -> Result<Option<crate::playbook::TicketPreparation>> {
    let payload: Option<String> = conn
        .query_row(
            "SELECT payload FROM ticket_preparations WHERE ticket_id = ?1",
            params![ticket_id],
            |row| row.get(0),
        )
        .optional()?;
    payload
        .map(|text| serde_json::from_str(&text).context("invalid Ticket preparation snapshot"))
        .transpose()
}

pub(crate) fn budget_question_pending_in(tx: &Connection, ticket_id: &str) -> Result<bool> {
    let open: Option<String> = tx.query_row(
        "SELECT question FROM tickets WHERE id = ?1",
        params![ticket_id],
        |r| r.get(0),
    )?;
    let Some(open) = open else { return Ok(false) };
    let question: Option<String> = tx.query_row(
        "SELECT json_extract(payload, '$.question') FROM events WHERE ticket_id = ?1 AND kind = 'budget_exceeded' AND NOT EXISTS (SELECT 1 FROM events x WHERE x.ticket_id = events.ticket_id AND x.kind = 'budget_extended' AND json_extract(x.payload, '$.question') = json_extract(events.payload, '$.question')) ORDER BY seq DESC LIMIT 1",
        params![ticket_id], |r| r.get(0)
    ).optional()?;
    Ok(question.as_deref() == Some(open.as_str()))
}

fn require_attempt_in(
    tx: &Transaction<'_>,
    ticket_id: &str,
    attempt: u32,
    admit: bool,
) -> Result<()> {
    if !admit {
        return Ok(());
    }
    let failures: i64 = tx.query_row(
        "SELECT COUNT(*) FROM events WHERE ticket_id = ?1 AND kind = 'verification_failed'",
        params![ticket_id],
        |row| row.get(0),
    )?;
    if attempt == 0 || i64::from(attempt) != failures + 1 {
        bail!("stale or invalid verification attempt {attempt} for Ticket {ticket_id}");
    }
    Ok(())
}

fn validate_check_in(
    tx: &Transaction<'_>,
    ticket_id: &str,
    attempt: u32,
    name: &str,
    admit: bool,
) -> Result<()> {
    require_attempt_in(tx, ticket_id, attempt, admit)?;
    let prep = preparation_in(tx, ticket_id)?.context("Ticket has no preparation")?;
    let names = prep
        .playbook
        .and_then(|p| p.spec)
        .and_then(|s| s.verification)
        .map(|v| v.checks.into_iter().map(|c| c.name).collect::<Vec<_>>())
        .unwrap_or_default();
    if !names.iter().any(|declared| declared == name) {
        bail!("verification check {name:?} is not declared by the Ticket's Playbook");
    }
    Ok(())
}

fn ensure_checks_passed_in(tx: &Transaction<'_>, ticket_id: &str, attempt: u32) -> Result<()> {
    let prep = preparation_in(tx, ticket_id)?.context("Ticket has no preparation")?;
    let checks = prep
        .playbook
        .and_then(|p| p.spec)
        .and_then(|s| s.verification)
        .map(|v| v.checks)
        .unwrap_or_default();
    for check in checks {
        let passed: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM events WHERE ticket_id = ?1 AND kind = 'verification_check_finished' AND json_extract(payload, '$.attempt') = ?2 AND json_extract(payload, '$.name') = ?3 AND json_extract(payload, '$.passed') = 1)",
            params![ticket_id, attempt, check.name], |row| row.get(0),
        )?;
        if !passed {
            bail!(
                "verification check {:?} has not passed in attempt {attempt}",
                check.name
            );
        }
    }
    Ok(())
}

fn ensure_verification_complete_in(
    tx: &Transaction<'_>,
    ticket_id: &str,
    attempt: u32,
) -> Result<()> {
    ensure_checks_passed_in(tx, ticket_id, attempt)?;
    let prep = preparation_in(tx, ticket_id)?.context("Ticket has no preparation")?;
    let verifier = prep
        .playbook
        .and_then(|p| p.spec)
        .and_then(|s| s.verification)
        .and_then(|v| v.verifier);
    if let Some(verifier) = verifier {
        let Some(agent_id) = assigned_verifier_in(tx, ticket_id, attempt)? else {
            bail!("the declared verifier has not reported for attempt {attempt}");
        };
        let role: String = tx.query_row(
            "SELECT role FROM agents WHERE id = ?1",
            params![agent_id],
            |r| r.get(0),
        )?;
        if role != verifier.role {
            bail!("verifier assignment does not match the declared Role");
        }
    }
    Ok(())
}

fn assigned_verifier_in(
    tx: &Transaction<'_>,
    ticket_id: &str,
    attempt: u32,
) -> Result<Option<String>> {
    Ok(tx.query_row(
        "SELECT json_extract(payload, '$.agent_id') FROM events WHERE ticket_id = ?1 AND kind = 'verification_verifier_assigned' AND json_extract(payload, '$.attempt') = ?2 ORDER BY seq DESC LIMIT 1",
        params![ticket_id, attempt], |row| row.get(0),
    ).optional()?)
}

fn require_approval(conn: &Connection, ticket_id: &str, kind: &str) -> Result<()> {
    let approved: bool = conn.query_row(
        "SELECT COALESCE((SELECT approved FROM approval_decisions WHERE ticket_id = ?1 AND kind = ?2), 0)",
        params![ticket_id, kind],
        |row| row.get(0),
    )?;
    if !approved {
        bail!("Approval {kind:?} is required; call request_approval for this Gate first");
    }
    Ok(())
}

/// Whether `project` replays a stored event or admits a new one. Checks
/// added after events were first stored apply only to new events, so a
/// rebuild still accepts the history an earlier version committed.
#[derive(Clone, Copy, PartialEq)]
enum Replay {
    Yes,
    No,
}

fn project(
    tx: &Transaction<'_>,
    at: &str,
    actor: &str,
    event: &Event,
    replay: Replay,
) -> Result<()> {
    let admit = replay == Replay::No;
    use TicketState::*;
    match event {
        Event::TicketCreated {
            ticket_id,
            project_id,
            number,
            title,
            body,
            priority,
            playbook,
            blocked_by,
            external_refs,
            ready,
        } => {
            if title.trim().is_empty() {
                bail!("ticket title must not be empty");
            }
            let state = if *ready { Ready } else { Backlog };
            tx.execute(
                "INSERT INTO tickets (id, project_id, number, title, body, state, priority,
                   playbook, blocked_by, external_refs, artifacts, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, '[]', ?11, ?11)",
                params![
                    ticket_id,
                    project_id,
                    number,
                    title,
                    body,
                    state.as_str(),
                    priority,
                    playbook,
                    serde_json::to_string(blocked_by)?,
                    serde_json::to_string(external_refs)?,
                    at
                ],
            )
            .with_context(|| format!("ticket {ticket_id} already exists"))?;
        }
        Event::TicketReadied { ticket_id } => {
            let state = ticket_state(tx, ticket_id)?;
            require(ticket_id, state, &[Backlog], "ready")?;
            set_ticket_state(tx, ticket_id, Ready, at)?;
        }
        Event::TicketDispatched {
            ticket_id,
            agent_id,
        } => {
            let state = ticket_state(tx, ticket_id)?;
            require(ticket_id, state, &[Ready], "dispatch")?;
            require_agent(tx, agent_id)?;
            set_ticket_state(tx, ticket_id, Running, at)?;
            tx.execute(
                "UPDATE tickets SET coordinator_id = ?2 WHERE id = ?1",
                params![ticket_id, agent_id],
            )?;
        }
        Event::TicketPrepared {
            ticket_id,
            base_commit,
            playbook,
            policy,
        } => {
            let state = ticket_state(tx, ticket_id)?;
            require(ticket_id, state, &[Running], "prepare")?;
            if base_commit.trim().is_empty() {
                bail!("ticket {ticket_id} preparation requires a base commit");
            }
            if admit
                && tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM ticket_preparations WHERE ticket_id = ?1)",
                    params![ticket_id],
                    |row| row.get::<_, bool>(0),
                )?
            {
                bail!("ticket {ticket_id} already has a preparation snapshot");
            }
            let preparation = crate::playbook::TicketPreparation {
                base_commit: base_commit.clone(),
                playbook: playbook.clone(),
                policy: policy.clone(),
            };
            tx.execute(
                "INSERT INTO ticket_preparations (ticket_id, payload) VALUES (?1, ?2)",
                params![ticket_id, serde_json::to_string(&preparation)?],
            )?;
        }
        Event::TicketReported {
            ticket_id,
            stage,
            summary,
            progress,
            next,
            artifacts,
        } => {
            let state = ticket_state(tx, ticket_id)?;
            require(ticket_id, state, &[Running, Waiting], "report on")?;
            if pending_approval_in(tx, ticket_id)?.is_some() {
                bail!("ticket {ticket_id} is waiting for an Approval");
            }
            if admit && let Some(stage) = stage {
                let preparation = preparation_in(tx, ticket_id)?;
                if let Some(kind) = preparation
                    .and_then(|p| p.playbook)
                    .and_then(|p| p.spec)
                    .and_then(|spec| spec.gates.get(stage).cloned())
                {
                    require_approval(tx, ticket_id, &kind)?;
                }
            }
            set_ticket_state(tx, ticket_id, Running, at)?;
            tx.execute(
                "UPDATE tickets SET stage = COALESCE(?2, stage), summary = COALESCE(?3, summary),
                   progress = COALESCE(?4, progress), next = COALESCE(?5, next), question = NULL
                 WHERE id = ?1",
                params![ticket_id, stage, summary, progress, next],
            )?;
            merge_artifacts(tx, ticket_id, artifacts)?;
        }
        Event::TicketAsked {
            ticket_id,
            question,
        } => {
            let state = ticket_state(tx, ticket_id)?;
            require(ticket_id, state, &[Running, Waiting, Verifying], "ask on")?;
            if admit && state == Verifying {
                let is_budget_question: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM events WHERE ticket_id = ?1 AND kind = 'budget_exceeded' AND json_extract(payload, '$.question') = ?2)",
                    params![ticket_id, question], |r| r.get(0)
                )?;
                if actor != "serve" || !is_budget_question {
                    bail!("only serve may pause verification for an elapsed time budget");
                }
            }
            if pending_approval_in(tx, ticket_id)?.is_some() {
                bail!("ticket {ticket_id} is waiting for an Approval");
            }
            set_ticket_state(tx, ticket_id, Waiting, at)?;
            tx.execute(
                "UPDATE tickets SET question = ?2 WHERE id = ?1",
                params![ticket_id, question],
            )?;
        }
        Event::TicketAnswered {
            ticket_id,
            question,
            ..
        } => {
            let state = ticket_state(tx, ticket_id)?;
            require(ticket_id, state, &[Waiting], "answer")?;
            if pending_approval_in(tx, ticket_id)?.is_some() {
                bail!("ticket {ticket_id} is waiting for an Approval, not an answer");
            }
            if let Some(question) = question {
                let open: Option<String> = tx.query_row(
                    "SELECT question FROM tickets WHERE id = ?1",
                    params![ticket_id],
                    |row| row.get(0),
                )?;
                if open.as_deref() != Some(question.as_str()) {
                    bail!("the answer to ticket {ticket_id} is for an earlier question");
                }
            }
            set_ticket_state(tx, ticket_id, Running, at)?;
            tx.execute(
                "UPDATE tickets SET question = NULL WHERE id = ?1",
                params![ticket_id],
            )?;
            // The human has seen any external close by now.
            update_refs(tx, ticket_id, at, |r| {
                if r.closed_externally.is_some() {
                    r.close_acknowledged = true;
                }
            })?;
        }
        Event::BudgetExceeded {
            ticket_id,
            budget,
            limit,
            round,
            resume_state,
            question,
        } => {
            require(
                ticket_id,
                ticket_state(tx, ticket_id)?,
                &[Running, Waiting, Verifying],
                "record budget overrun",
            )?;
            if admit && actor != "serve" {
                bail!("only serve may record a budget overrun");
            }
            if *budget != crate::domain::BudgetKind::Minutes
                || *limit == 0
                || *round == 0
                || !matches!(resume_state, TicketState::Running | TicketState::Verifying)
                || question.trim().is_empty()
            {
                bail!("invalid budget overrun");
            }
            if pending_approval_in(tx, ticket_id)?.is_some() {
                bail!("ticket {ticket_id} is waiting for an Approval");
            }
            let open: Option<String> = tx.query_row(
                "SELECT question FROM tickets WHERE id = ?1",
                params![ticket_id],
                |r| r.get(0),
            )?;
            if open.is_some() {
                bail!("ticket {ticket_id} already has an open question");
            }
            let exceeded: i64 = tx.query_row(
                "SELECT COUNT(*) FROM events WHERE ticket_id = ?1 AND kind = 'budget_exceeded'",
                params![ticket_id],
                |r| r.get(0),
            )?;
            let extended: i64 = tx.query_row(
                "SELECT COUNT(*) FROM events WHERE ticket_id = ?1 AND kind = 'budget_extended'",
                params![ticket_id],
                |r| r.get(0),
            )?;
            if exceeded != extended {
                bail!("ticket {ticket_id} already has an unanswered budget overrun");
            }
            if admit && i64::from(*round) != exceeded + 1 {
                bail!("budget overrun round is stale or invalid");
            }
        }
        Event::BudgetExtended {
            ticket_id,
            budget,
            resume_state,
            question,
        } => {
            require(
                ticket_id,
                ticket_state(tx, ticket_id)?,
                &[Running],
                "extend budget",
            )?;
            if admit && actor != "human" {
                bail!("only a human answer may extend a budget");
            }
            if *budget != crate::domain::BudgetKind::Minutes {
                bail!("unsupported budget extension");
            }
            let answered: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM events WHERE ticket_id = ?1 AND kind = 'ticket_answered' AND json_extract(payload, '$.question') = ?2 AND actor = 'human')", params![ticket_id, question], |r| r.get(0))?;
            let overrun: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM events WHERE ticket_id = ?1 AND kind = 'budget_exceeded' AND json_extract(payload, '$.budget') = 'minutes' AND json_extract(payload, '$.question') = ?2)", params![ticket_id, question], |r| r.get(0))?;
            let extended: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM events WHERE ticket_id = ?1 AND kind = 'budget_extended' AND json_extract(payload, '$.question') = ?2)", params![ticket_id, question], |r| r.get(0))?;
            if admit && (!answered || !overrun || extended) {
                bail!("budget extension does not match one unanswered budget question");
            }
            set_ticket_state(tx, ticket_id, *resume_state, at)?;
        }
        Event::ApprovalRequested {
            ticket_id,
            approval_kind,
            summary,
            artifacts,
        } => {
            let state = ticket_state(tx, ticket_id)?;
            require(
                ticket_id,
                state,
                &[Running, Waiting],
                "request an Approval on",
            )?;
            if approval_kind.trim().is_empty() || summary.trim().is_empty() {
                bail!("Approval kind and summary must not be empty");
            }
            if pending_approval_in(tx, ticket_id)?.is_some() {
                bail!("ticket {ticket_id} already has a pending Approval");
            }
            let question: Option<String> = tx.query_row(
                "SELECT question FROM tickets WHERE id = ?1",
                params![ticket_id],
                |row| row.get(0),
            )?;
            if question.is_some() {
                bail!("ticket {ticket_id} already has an open question");
            }
            set_ticket_state(tx, ticket_id, Waiting, at)?;
            tx.execute(
                "UPDATE tickets SET question = NULL WHERE id = ?1",
                params![ticket_id],
            )?;
            tx.execute(
                "INSERT INTO pending_approvals (ticket_id, kind, summary, artifacts) VALUES (?1, ?2, ?3, ?4)",
                params![ticket_id, approval_kind, summary, serde_json::to_string(artifacts)?],
            )?;
        }
        Event::ApprovalDecided {
            ticket_id,
            approval_kind,
            approved,
            note,
        } => {
            let state = ticket_state(tx, ticket_id)?;
            require(ticket_id, state, &[Waiting], "decide an Approval on")?;
            let pending = pending_approval_in(tx, ticket_id)?
                .with_context(|| format!("ticket {ticket_id} has no pending Approval"))?;
            if pending.kind != *approval_kind {
                bail!(
                    "ticket {ticket_id} is waiting for {:?}, not {approval_kind:?}",
                    pending.kind
                );
            }
            if !approved && note.as_deref().is_none_or(|note| note.trim().is_empty()) {
                bail!("a rejection needs a note");
            }
            tx.execute(
                "DELETE FROM pending_approvals WHERE ticket_id = ?1",
                params![ticket_id],
            )?;
            tx.execute(
                "INSERT INTO approval_decisions (ticket_id, kind, approved, note, actor, at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(ticket_id, kind) DO UPDATE SET approved=excluded.approved, note=excluded.note, actor=excluded.actor, at=excluded.at",
                params![ticket_id, approval_kind, approved, note, actor, at],
            )?;
            set_ticket_state(tx, ticket_id, Running, at)?;
            if let Some(coordinator_id) = tx.query_row(
                "SELECT coordinator_id FROM tickets WHERE id = ?1",
                params![ticket_id],
                |row| row.get::<_, Option<String>>(0),
            )? {
                let decision = if *approved { "approved" } else { "rejected" };
                let decider = if actor == "policy" { "Policy" } else { "Human" };
                let mut body = format!("{decider} {decision} the {approval_kind} Approval.");
                if let Some(note) = note {
                    body.push_str(&format!(" Note: {note}"));
                }
                tx.execute(
                    "INSERT INTO messages (ticket_id, sender, recipient, body, sent_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![ticket_id, actor, coordinator_id, body, at],
                )?;
            }
        }
        Event::TicketCompleted {
            ticket_id,
            outcome,
            summary,
            artifacts,
        } => {
            let state = ticket_state(tx, ticket_id)?;
            require(ticket_id, state, &[Running, Waiting], "complete")?;
            if admit && *outcome == Outcome::Delivered {
                if pending_approval_in(tx, ticket_id)?.is_some() {
                    bail!("ticket {ticket_id} is waiting for an Approval");
                }
                let required = preparation_in(tx, ticket_id)?
                    .and_then(|p| p.policy)
                    .map(|policy| policy.required_approvals)
                    .unwrap_or_default();
                for kind in required {
                    require_approval(tx, ticket_id, &kind)?;
                }
            }
            let verify = *outcome == Outcome::Delivered
                && preparation_in(tx, ticket_id)?
                    .and_then(|p| p.playbook)
                    .and_then(|p| p.spec)
                    .and_then(|s| s.verification)
                    .is_some();
            let next = match outcome {
                Outcome::Delivered if verify => TicketState::Verifying,
                Outcome::Delivered => Done,
                Outcome::Abandoned => Abandoned,
                Outcome::Failed => Failed,
            };
            set_ticket_state(tx, ticket_id, next, at)?;
            // An ended Ticket has no next step, and a delivered one is complete.
            tx.execute(
                "UPDATE tickets SET summary = ?2, outcome = ?3, question = NULL, next = NULL,
                   stage = CASE WHEN ?3 = 'delivered' AND ?4 = 1 THEN 'verification' ELSE stage END,
                   progress = CASE WHEN ?3 = 'delivered' AND ?4 = 0 THEN 100 ELSE progress END
                 WHERE id = ?1",
                params![
                    ticket_id,
                    summary,
                    serde_json::to_value(outcome)?.as_str(),
                    verify
                ],
            )?;
            tx.execute(
                "DELETE FROM pending_approvals WHERE ticket_id = ?1",
                params![ticket_id],
            )?;
            merge_artifacts(tx, ticket_id, artifacts)?;
            if verify {
                tx.execute("UPDATE agents SET state = 'finished', exit_reason = 'verification started', updated_at = ?2 WHERE ticket_id = ?1 AND role != 'coordinator' AND state IN ('created', 'running')", params![ticket_id, at])?;
            }
        }
        Event::VerificationCheckStarted {
            ticket_id,
            attempt,
            name,
        } => {
            require(
                ticket_id,
                ticket_state(tx, ticket_id)?,
                &[Verifying],
                "record verification",
            )?;
            if admit && actor != "serve" {
                bail!("only serve may start verification checks");
            }
            validate_check_in(tx, ticket_id, *attempt, name, admit)?;
            tx.execute(
                "UPDATE tickets SET stage = ?2 WHERE id = ?1",
                params![ticket_id, format!("verification attempt {attempt}: {name}")],
            )?;
        }
        Event::VerificationCheckFinished {
            ticket_id,
            attempt,
            name,
            ..
        } => {
            require(
                ticket_id,
                ticket_state(tx, ticket_id)?,
                &[Verifying],
                "record verification",
            )?;
            if admit && actor != "serve" {
                bail!("only serve may finish verification checks");
            }
            validate_check_in(tx, ticket_id, *attempt, name, admit)?;
            if admit {
                let started: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM events WHERE ticket_id = ?1 AND kind = 'verification_check_started' AND json_extract(payload, '$.attempt') = ?2 AND json_extract(payload, '$.name') = ?3)", params![ticket_id, attempt, name], |r| r.get(0))?;
                let finished: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM events WHERE ticket_id = ?1 AND kind = 'verification_check_finished' AND json_extract(payload, '$.attempt') = ?2 AND json_extract(payload, '$.name') = ?3)", params![ticket_id, attempt, name], |r| r.get(0))?;
                if !started || finished {
                    bail!("verification check was not pending or already finished");
                }
            }
        }
        Event::VerificationFailed {
            ticket_id,
            attempt,
            reason,
        } => {
            require(
                ticket_id,
                ticket_state(tx, ticket_id)?,
                &[Verifying],
                "fail verification",
            )?;
            require_attempt_in(tx, ticket_id, *attempt, admit)?;
            if admit && actor != "serve" {
                let assigned = assigned_verifier_in(tx, ticket_id, *attempt)?;
                if assigned.as_deref() != Some(actor) {
                    bail!("only serve or the current assigned verifier may fail verification");
                }
                let state: String = tx.query_row(
                    "SELECT state FROM agents WHERE id = ?1",
                    params![actor],
                    |r| r.get(0),
                )?;
                if state != "running" {
                    bail!("the assigned verifier is not running");
                }
            }
            if reason.trim().is_empty() {
                bail!("verification failure reason must not be empty");
            }
            let preparation = preparation_in(tx, ticket_id)?;
            let limit = preparation
                .and_then(|p| p.policy)
                .map(|p| p.verification_attempts)
                .unwrap_or(3);
            let next = Running;
            set_ticket_state(tx, ticket_id, next, at)?;
            tx.execute(
                "UPDATE tickets SET stage = 'implementation', question = NULL, next = NULL, summary = ?2 WHERE id = ?1",
                params![ticket_id, reason],
            )?;
            if let Some(coordinator_id) = tx.query_row(
                "SELECT coordinator_id FROM tickets WHERE id = ?1",
                params![ticket_id],
                |row| row.get::<_, Option<String>>(0),
            )? {
                tx.execute(
                    "INSERT INTO messages (ticket_id, sender, recipient, body, sent_at) VALUES (?1, 'rex-projects', ?2, ?3, ?4)",
                    params![ticket_id, coordinator_id, reason, at],
                )?;
            }
            if *attempt >= limit {
                // The next TicketAsked event records a human decision point.
                // Keep the failure transition in this projection replay-safe.
            }
        }
        Event::TicketVerified { ticket_id, attempt } => {
            require(
                ticket_id,
                ticket_state(tx, ticket_id)?,
                &[Verifying],
                "finish verification",
            )?;
            require_attempt_in(tx, ticket_id, *attempt, admit)?;
            ensure_verification_complete_in(tx, ticket_id, *attempt)?;
            if admit {
                let verifier_declared = preparation_in(tx, ticket_id)?
                    .and_then(|p| p.playbook)
                    .and_then(|p| p.spec)
                    .and_then(|s| s.verification)
                    .and_then(|v| v.verifier)
                    .is_some();
                let authorized = if verifier_declared {
                    let assigned = assigned_verifier_in(tx, ticket_id, *attempt)?;
                    if assigned.as_deref() != Some(actor) {
                        false
                    } else {
                        let state: String = tx.query_row(
                            "SELECT state FROM agents WHERE id = ?1",
                            params![actor],
                            |r| r.get(0),
                        )?;
                        state == "running"
                    }
                } else {
                    actor == "serve"
                };
                if !authorized {
                    bail!("only the assigned verifier or serve may finish verification");
                }
            }
            set_ticket_state(tx, ticket_id, Done, at)?;
            tx.execute(
                "UPDATE tickets SET stage = NULL, question = NULL, next = NULL, progress = 100 WHERE id = ?1",
                params![ticket_id],
            )?;
        }
        Event::VerificationVerifierAssigned {
            ticket_id,
            attempt,
            agent_id,
        } => {
            require(
                ticket_id,
                ticket_state(tx, ticket_id)?,
                &[Verifying],
                "assign verifier",
            )?;
            require_attempt_in(tx, ticket_id, *attempt, admit)?;
            if admit && actor != "serve" {
                bail!("only serve may assign a verifier");
            }
            ensure_checks_passed_in(tx, ticket_id, *attempt)?;
            let prep = preparation_in(tx, ticket_id)?.context("Ticket has no preparation")?;
            let role = prep
                .playbook
                .and_then(|p| p.spec)
                .and_then(|s| s.verification)
                .and_then(|v| v.verifier)
                .map(|v| v.role)
                .context("Ticket has no verifier role")?;
            let matches: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM agents WHERE id = ?1 AND ticket_id = ?2 AND role = ?3)", params![agent_id, ticket_id, role], |r| r.get(0))?;
            if !matches {
                bail!("assigned Agent is not the declared verifier");
            }
            tx.execute(
                "UPDATE tickets SET stage = ?2 WHERE id = ?1",
                params![
                    ticket_id,
                    format!("verification attempt {attempt}: verifier")
                ],
            )?;
        }
        Event::TicketCancelled { ticket_id, reason }
        | Event::TicketFailed { ticket_id, reason } => {
            let state = ticket_state(tx, ticket_id)?;
            let (next, outcome, action) = match event {
                Event::TicketCancelled { .. } => (Abandoned, Outcome::Abandoned, "cancel"),
                _ => (Failed, Outcome::Failed, "fail"),
            };
            if state.is_terminal() {
                bail!("cannot {action} ticket {ticket_id} while it is {state}");
            }
            set_ticket_state(tx, ticket_id, next, at)?;
            tx.execute(
                "UPDATE tickets SET summary = ?2, outcome = ?3, question = NULL, next = NULL
                 WHERE id = ?1",
                params![ticket_id, reason, serde_json::to_value(outcome)?.as_str()],
            )?;
            tx.execute(
                "DELETE FROM pending_approvals WHERE ticket_id = ?1",
                params![ticket_id],
            )?;
        }
        Event::ExternalChanged {
            ticket_id,
            tracker,
            reference,
            status,
        } => {
            ticket_state(tx, ticket_id)?;
            update_refs(tx, ticket_id, at, |r| {
                if &r.tracker == tracker && &r.reference == reference {
                    r.closed_externally = is_closed_status(status).then(|| status.clone());
                    r.close_acknowledged = false;
                }
            })?;
        }
        Event::MessageSent {
            ticket_id,
            from,
            to,
            body,
        } => {
            let state: Option<String> = tx
                .query_row(
                    "SELECT state FROM tickets WHERE id = ?1",
                    params![ticket_id],
                    |row| row.get(0),
                )
                .optional()?;
            if admit && state.as_deref() == Some("verifying") && from != "rex-projects" {
                bail!("Verification is running; Agents cannot send ordinary messages");
            }
            let agent = |id: &str| {
                tx.query_row(
                    "SELECT ticket_id, role, state FROM agents WHERE id = ?1",
                    params![id],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                        ))
                    },
                )
                .optional()
            };
            match agent(to)? {
                None => bail!("agent {to} does not exist"),
                Some((t, _, _)) if t != *ticket_id => {
                    bail!("agent {to} works on ticket {t}, not {ticket_id}")
                }
                // A helper is never resumed, so nothing would read it. An
                // exited Coordinator reads it once relaunched.
                Some((_, role, state))
                    if admit
                        && role != "coordinator"
                        && matches!(state.as_str(), "finished" | "exited") =>
                {
                    bail!("agent {to} has {state}; spawn a new helper instead")
                }
                Some(_) => {}
            }
            // A helper that finished or was stopped can no longer report.
            if admit
                && let Some((_, _, state)) = agent(from)?
                && matches!(state.as_str(), "finished" | "exited")
            {
                bail!("agent {from} has {state} and can no longer send messages; stop working");
            }
            if body.trim().is_empty() {
                bail!("a message must not be empty");
            }
            tx.execute(
                "INSERT INTO messages (ticket_id, sender, recipient, body, sent_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![ticket_id, from, to, body, at],
            )?;
        }
        Event::MessagesRead { agent_id, through } => {
            require_agent(tx, agent_id)?;
            tx.execute(
                "UPDATE messages SET read_at = ?3
                 WHERE recipient = ?1 AND id <= ?2 AND read_at IS NULL",
                params![agent_id, through, at],
            )?;
        }
        Event::AgentCreated {
            agent_id,
            ticket_id,
            project_id,
            role,
            provider,
            cwd,
        } => {
            let state = ticket_state(tx, ticket_id)?;
            // A helper joins only a Ticket that is still being worked on.
            let is_declared_verifier = role != "coordinator"
                && preparation_in(tx, ticket_id)?
                    .and_then(|p| p.playbook)
                    .and_then(|p| p.spec)
                    .and_then(|s| s.verification)
                    .and_then(|v| v.verifier)
                    .is_some_and(|v| v.role == *role);
            if admit
                && role != "coordinator"
                && !(matches!(state, Running | Waiting) && !is_declared_verifier)
                && !(state == Verifying && is_declared_verifier && actor == "serve")
            {
                bail!("ticket {ticket_id} is {state}; helpers run only on a running Ticket");
            }
            if admit && state == Verifying && is_declared_verifier {
                let failures: i64 = tx.query_row(
                    "SELECT COUNT(*) FROM events WHERE ticket_id = ?1 AND kind = 'verification_failed'",
                    params![ticket_id],
                    |r| r.get(0),
                )?;
                ensure_checks_passed_in(tx, ticket_id, failures as u32 + 1)?;
            }
            if admit && role != "coordinator" && pending_approval_in(tx, ticket_id)?.is_some() {
                bail!("ticket {ticket_id} is waiting for Approval; helpers cannot be spawned");
            }
            tx.execute(
                "INSERT INTO agents (id, ticket_id, project_id, role, provider, cwd, state,
                   launches, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'created', 0, ?7, ?7)",
                params![agent_id, ticket_id, project_id, role, provider, cwd, at],
            )
            .with_context(|| format!("agent {agent_id} already exists"))?;
        }
        Event::AgentLaunched {
            agent_id,
            rex_session_id,
            rex_window_id,
            rex_block_id,
            ..
        } => {
            require_agent(tx, agent_id)?;
            let (state, ticket_id, role): (String, String, String) = tx.query_row(
                "SELECT state, ticket_id, role FROM agents WHERE id = ?1",
                params![agent_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?;
            if admit && state == "finished" {
                bail!("agent {agent_id} was stopped before it launched");
            }
            let ticket = ticket_state(tx, &ticket_id)?;
            if admit && ticket.is_terminal() {
                bail!("ticket {ticket_id} is {ticket}; agent {agent_id} cannot launch");
            }
            if admit && ticket == Verifying && role != "coordinator" {
                let failures: i64 = tx.query_row(
                    "SELECT COUNT(*) FROM events WHERE ticket_id = ?1 AND kind = 'verification_failed'",
                    params![ticket_id],
                    |r| r.get(0),
                )?;
                if assigned_verifier_in(tx, &ticket_id, failures as u32 + 1)?.as_deref()
                    != Some(agent_id)
                {
                    bail!("Verification is running; only the assigned verifier may launch");
                }
            }
            tx.execute(
                "UPDATE agents SET state = 'running', rex_session_id = ?2, rex_window_id = ?3,
                   rex_block_id = ?4, launches = launches + 1, activity = NULL,
                   activity_message = NULL, exit_reason = NULL, updated_at = ?5
                 WHERE id = ?1",
                params![agent_id, rex_session_id, rex_window_id, rex_block_id, at],
            )?;
        }
        Event::AgentSessionBound {
            agent_id,
            harness_session_id,
        } => {
            require_agent(tx, agent_id)?;
            tx.execute(
                "UPDATE agents SET harness_session_id = ?2, updated_at = ?3 WHERE id = ?1",
                params![agent_id, harness_session_id, at],
            )?;
        }
        Event::AgentActivity {
            agent_id,
            activity,
            message,
        } => {
            require_agent(tx, agent_id)?;
            tx.execute(
                "UPDATE agents SET activity = ?2, activity_message = ?3, updated_at = ?4
                 WHERE id = ?1",
                params![agent_id, activity, message, at],
            )?;
        }
        Event::AgentFinished { agent_id, reason } => {
            require_agent(tx, agent_id)?;
            let ticket_id: String = tx.query_row(
                "SELECT ticket_id FROM agents WHERE id = ?1",
                params![agent_id],
                |row| row.get(0),
            )?;
            if admit && ticket_state(tx, &ticket_id)? == Verifying && actor != "serve" {
                bail!("Verification is running; an Agent must report with verify");
            }
            let changed = tx.execute(
                "UPDATE agents SET state = 'finished', exit_reason = ?2, updated_at = ?3
                 WHERE id = ?1 AND state IN ('created', 'running')",
                params![agent_id, reason, at],
            )?;
            if changed == 0 {
                bail!("agent {agent_id} has already finished or exited");
            }
        }
        Event::AgentExited { agent_id, reason } => {
            require_agent(tx, agent_id)?;
            tx.execute(
                "UPDATE agents SET state = 'exited', exit_reason = ?2, activity = NULL,
                   activity_message = NULL, updated_at = ?3
                 WHERE id = ?1",
                params![agent_id, reason, at],
            )?;
        }
    }
    Ok(())
}

const TICKET_COLUMNS: &str = "id, project_id, number, title, body, state, stage, summary, \
    progress, next, question, priority, playbook, blocked_by, external_refs, artifacts, \
    outcome, coordinator_id, created_at, updated_at";

fn json_column<T: serde::de::DeserializeOwned>(row: &Row<'_>, index: usize) -> rusqlite::Result<T> {
    let text: String = row.get(index)?;
    serde_json::from_str(&text).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(index, rusqlite::types::Type::Text, Box::new(err))
    })
}

fn ticket_from_row(row: &Row<'_>) -> rusqlite::Result<Ticket> {
    let state: String = row.get(5)?;
    let outcome: Option<String> = row.get(16)?;
    let invalid = |index: usize, err: anyhow::Error| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Text,
            err.into_boxed_dyn_error(),
        )
    };
    Ok(Ticket {
        id: row.get(0)?,
        project_id: row.get(1)?,
        number: row.get(2)?,
        title: row.get(3)?,
        body: row.get(4)?,
        state: state.parse().map_err(|err| invalid(5, err))?,
        stage: row.get(6)?,
        summary: row.get(7)?,
        progress: row.get(8)?,
        next: row.get(9)?,
        question: row.get(10)?,
        pending_approval: None,
        priority: row.get(11)?,
        playbook: row.get(12)?,
        blocked_by: json_column(row, 13)?,
        external_refs: json_column(row, 14)?,
        artifacts: json_column(row, 15)?,
        outcome: outcome
            .map(|o| serde_json::from_value(serde_json::Value::String(o)))
            .transpose()
            .map_err(|err| invalid(16, err.into()))?,
        coordinator_id: row.get(17)?,
        created_at: row.get(18)?,
        updated_at: row.get(19)?,
    })
}

const AGENT_COLUMNS: &str = "id, ticket_id, project_id, role, provider, cwd, state, \
    harness_session_id, rex_session_id, rex_window_id, rex_block_id, launches, activity, \
    activity_message, exit_reason, created_at, updated_at";

fn agent_from_row(row: &Row<'_>) -> rusqlite::Result<Agent> {
    Ok(Agent {
        id: row.get(0)?,
        ticket_id: row.get(1)?,
        project_id: row.get(2)?,
        role: row.get(3)?,
        provider: row.get(4)?,
        cwd: row.get(5)?,
        state: row.get(6)?,
        harness_session_id: row.get(7)?,
        rex_session_id: row.get(8)?,
        rex_window_id: row.get(9)?,
        rex_block_id: row.get(10)?,
        launches: row.get(11)?,
        activity: row.get(12)?,
        activity_message: row.get(13)?,
        exit_reason: row.get(14)?,
        created_at: row.get(15)?,
        updated_at: row.get(16)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_ticket(store: &mut Store, ready: bool) -> Ticket {
        store
            .create_ticket(
                "human",
                NewTicket {
                    project_id: "demo".into(),
                    title: "Add a feature".into(),
                    ready,
                    ..Default::default()
                },
            )
            .unwrap()
    }

    fn agent(store: &mut Store, ticket: &str) -> String {
        let agent_id = format!("{ticket}-coordinator");
        store
            .append(
                "serve",
                Event::AgentCreated {
                    agent_id: agent_id.clone(),
                    ticket_id: ticket.into(),
                    project_id: "demo".into(),
                    role: "coordinator".into(),
                    provider: "claude".into(),
                    cwd: "/tmp".into(),
                },
            )
            .unwrap();
        agent_id
    }

    #[test]
    fn answering_a_budget_question_extends_once_and_replays() {
        let mut store = Store::open_in_memory().unwrap();
        let ticket = new_ticket(&mut store, true);
        let id = ticket.id.clone();
        let coordinator = agent(&mut store, &id);
        store
            .append(
                "serve",
                Event::TicketDispatched {
                    ticket_id: id.clone(),
                    agent_id: coordinator.clone(),
                },
            )
            .unwrap();
        store
            .append(
                "serve",
                Event::TicketPrepared {
                    ticket_id: id.clone(),
                    base_commit: "abc123".into(),
                    playbook: None,
                    policy: Some(crate::policy::Policy {
                        autonomy: crate::policy::Autonomy::A1,
                        required_approvals: vec![],
                        verification_attempts: 3,
                        approvers: Default::default(),
                        budgets: crate::policy::PolicyBudgets {
                            helpers: None,
                            minutes: Some(1),
                        },
                    }),
                },
            )
            .unwrap();
        let question = crate::budget::exceeded_question(1, 1);
        store
            .append_all(
                "serve",
                &[
                    Event::BudgetExceeded {
                        ticket_id: id.clone(),
                        budget: crate::domain::BudgetKind::Minutes,
                        limit: 1,
                        round: 1,
                        resume_state: TicketState::Running,
                        question: question.clone(),
                    },
                    Event::TicketAsked {
                        ticket_id: id.clone(),
                        question: question.clone(),
                    },
                    Event::MessageSent {
                        ticket_id: id.clone(),
                        from: "rex-projects".into(),
                        to: coordinator,
                        body: question.clone(),
                    },
                ],
            )
            .unwrap();
        store
            .answer(
                "human",
                &id,
                Some("Continue".into()),
                Some(question.clone()),
            )
            .unwrap();
        assert!(matches!(
            store.ticket_events(&id).unwrap().last().unwrap().event,
            Event::BudgetExtended { .. }
        ));
        assert_eq!(
            store.budget_remaining(&id).unwrap().unwrap().minutes,
            Some(2)
        );
        assert!(
            store
                .answer("human", &id, None, Some(question.clone()))
                .is_err(),
            "stale duplicate answer must not add another extension"
        );
        assert_eq!(
            store
                .ticket_events(&id)
                .unwrap()
                .iter()
                .filter(|e| matches!(e.event, Event::BudgetExtended { .. }))
                .count(),
            1
        );
        store.rebuild().unwrap();
        assert_eq!(
            store.ticket(&id).unwrap().unwrap().state,
            TicketState::Running
        );
        assert_eq!(
            store
                .ticket_events(&id)
                .unwrap()
                .iter()
                .filter(|e| matches!(e.event, Event::BudgetExtended { .. }))
                .count(),
            1
        );
        let next_question = crate::budget::exceeded_question(1, 2);
        assert_ne!(question, next_question);
        store
            .append_all(
                "serve",
                &[
                    Event::BudgetExceeded {
                        ticket_id: id.clone(),
                        budget: crate::domain::BudgetKind::Minutes,
                        limit: 1,
                        round: 2,
                        resume_state: TicketState::Running,
                        question: next_question.clone(),
                    },
                    Event::TicketAsked {
                        ticket_id: id.clone(),
                        question: next_question.clone(),
                    },
                    Event::MessageSent {
                        ticket_id: id.clone(),
                        from: "rex-projects".into(),
                        to: "demo-1-coordinator".into(),
                        body: next_question.clone(),
                    },
                ],
            )
            .unwrap();
        store
            .answer(
                "human",
                &id,
                Some("Continue again".into()),
                Some(next_question),
            )
            .unwrap();
        assert_eq!(
            store
                .ticket_events(&id)
                .unwrap()
                .iter()
                .filter(|e| matches!(e.event, Event::BudgetExtended { .. }))
                .count(),
            2
        );
        store.rebuild().unwrap();
        assert_eq!(
            store
                .ticket_events(&id)
                .unwrap()
                .iter()
                .filter(|e| matches!(e.event, Event::BudgetExtended { .. }))
                .count(),
            2
        );
    }

    #[test]
    fn approval_gates_reject_reopen_and_replay_with_inbox() {
        let mut store = Store::open_in_memory().unwrap();
        let ticket = new_ticket(&mut store, true);
        let id = ticket.id.clone();
        let coordinator = agent(&mut store, &id);
        store
            .append(
                "serve",
                Event::TicketDispatched {
                    ticket_id: id.clone(),
                    agent_id: coordinator.clone(),
                },
            )
            .unwrap();
        store
            .append(
                "serve",
                Event::TicketPrepared {
                    ticket_id: id.clone(),
                    base_commit: "abc123".into(),
                    playbook: Some(crate::playbook::PlaybookSnapshot {
                        name: "feature".into(),
                        sha256: "a".repeat(64),
                        body: String::new(),
                        spec: Some(crate::playbook::PlaybookSpec {
                            stages: vec!["plan".into(), "implement".into()],
                            roles: None,
                            gates: [("implement".into(), "plan".into())].into(),
                            verification: None,
                            budgets: None,
                        }),
                    }),
                    policy: Some(crate::policy::Policy {
                        autonomy: crate::policy::Autonomy::A1,
                        required_approvals: vec!["plan".into()],
                        verification_attempts: 3,
                        approvers: Default::default(),
                        budgets: Default::default(),
                    }),
                },
            )
            .unwrap();
        let report = Event::TicketReported {
            ticket_id: id.clone(),
            stage: Some("implement".into()),
            summary: None,
            progress: None,
            next: None,
            artifacts: vec![],
        };
        assert!(
            store
                .append(&coordinator, report.clone())
                .unwrap_err()
                .to_string()
                .contains("Approval")
        );
        store
            .append(
                &coordinator,
                Event::ApprovalRequested {
                    ticket_id: id.clone(),
                    approval_kind: "plan".into(),
                    summary: "Review the plan".into(),
                    artifacts: vec!["plan.md".into()],
                },
            )
            .unwrap();
        assert_eq!(
            store
                .ticket(&id)
                .unwrap()
                .unwrap()
                .pending_approval
                .unwrap()
                .summary,
            "Review the plan"
        );
        let spawn_error = store
            .append(
                &coordinator,
                Event::AgentCreated {
                    agent_id: format!("{id}-worker-1"),
                    ticket_id: id.clone(),
                    project_id: "demo".into(),
                    role: "worker".into(),
                    provider: "codex".into(),
                    cwd: "/tmp".into(),
                },
            )
            .unwrap_err();
        assert!(spawn_error.to_string().contains("waiting for Approval"));
        assert!(
            store
                .append(
                    "human",
                    Event::TicketAnswered {
                        ticket_id: id.clone(),
                        answer: Some("yes".into()),
                        question: None
                    }
                )
                .unwrap_err()
                .to_string()
                .contains("Approval")
        );
        assert!(
            store
                .append(&coordinator, report.clone())
                .unwrap_err()
                .to_string()
                .contains("Approval")
        );
        assert!(
            store
                .append(
                    &coordinator,
                    Event::TicketCompleted {
                        ticket_id: id.clone(),
                        outcome: Outcome::Delivered,
                        summary: "done".into(),
                        artifacts: vec![]
                    }
                )
                .unwrap_err()
                .to_string()
                .contains("Approval")
        );
        store
            .decide_approval(
                "human",
                &id,
                "plan",
                false,
                Some("Add a migration plan".into()),
            )
            .unwrap();
        assert_eq!(
            store.ticket(&id).unwrap().unwrap().state,
            TicketState::Running
        );
        assert!(
            store.unread(&coordinator).unwrap()[0]
                .body
                .contains("rejected")
        );
        let rejected_message = store.unread(&coordinator).unwrap()[0].id;
        store
            .append(
                &coordinator,
                Event::MessagesRead {
                    agent_id: coordinator.clone(),
                    through: rejected_message,
                },
            )
            .unwrap();
        assert!(
            store
                .append(&coordinator, report.clone())
                .unwrap_err()
                .to_string()
                .contains("Approval")
        );
        store
            .append(
                &coordinator,
                Event::ApprovalRequested {
                    ticket_id: id.clone(),
                    approval_kind: "plan".into(),
                    summary: "Updated plan".into(),
                    artifacts: vec![],
                },
            )
            .unwrap();
        store
            .decide_approval("human", &id, "plan", true, Some("Approved".into()))
            .unwrap();
        store.append(&coordinator, report).unwrap();
        store
            .append(
                &coordinator,
                Event::TicketCompleted {
                    ticket_id: id.clone(),
                    outcome: Outcome::Delivered,
                    summary: "done".into(),
                    artifacts: vec![],
                },
            )
            .unwrap();
        store.rebuild().unwrap();
        assert_eq!(store.ticket(&id).unwrap().unwrap().state, TicketState::Done);
        assert_eq!(store.unread(&coordinator).unwrap().len(), 1);
        assert!(
            store.unread(&coordinator).unwrap()[0]
                .body
                .contains("approved")
        );
    }

    #[test]
    fn numbers_tickets_per_project() {
        let mut store = Store::open_in_memory().unwrap();
        assert_eq!(new_ticket(&mut store, false).id, "demo-1");
        let second = new_ticket(&mut store, true);
        assert_eq!(second.id, "demo-2");
        assert_eq!(second.state, TicketState::Ready);
    }

    #[test]
    fn walks_a_ticket_through_its_lifecycle() {
        let mut store = Store::open_in_memory().unwrap();
        let ticket = new_ticket(&mut store, false);
        let id = ticket.id.clone();
        assert_eq!(ticket.state, TicketState::Backlog);

        store
            .append(
                "human",
                Event::TicketReadied {
                    ticket_id: id.clone(),
                },
            )
            .unwrap();
        let agent_id = agent(&mut store, &id);
        store
            .append(
                "serve",
                Event::TicketDispatched {
                    ticket_id: id.clone(),
                    agent_id: agent_id.clone(),
                },
            )
            .unwrap();
        store
            .append(
                &agent_id,
                Event::TicketReported {
                    ticket_id: id.clone(),
                    stage: Some("plan".into()),
                    summary: Some("Reading the code".into()),
                    progress: None,
                    next: None,
                    artifacts: vec!["https://example.com/pr/1".into()],
                },
            )
            .unwrap();
        store
            .append(
                &agent_id,
                Event::TicketAsked {
                    ticket_id: id.clone(),
                    question: "Which API?".into(),
                },
            )
            .unwrap();
        let waiting = store.ticket(&id).unwrap().unwrap();
        assert_eq!(waiting.state, TicketState::Waiting);
        assert_eq!(waiting.question.as_deref(), Some("Which API?"));

        // An answer to an earlier question does not close this one.
        let stale = store.append(
            "human",
            Event::TicketAnswered {
                ticket_id: id.clone(),
                answer: Some("v1".into()),
                question: Some("Which version?".into()),
            },
        );
        assert!(stale.unwrap_err().to_string().contains("earlier question"));
        assert_eq!(
            store.ticket(&id).unwrap().unwrap().state,
            TicketState::Waiting
        );

        store
            .append(
                "human",
                Event::TicketAnswered {
                    ticket_id: id.clone(),
                    answer: Some("v2".into()),
                    question: Some("Which API?".into()),
                },
            )
            .unwrap();
        store
            .append(
                &agent_id,
                Event::TicketCompleted {
                    ticket_id: id.clone(),
                    outcome: Outcome::Delivered,
                    summary: "Shipped".into(),
                    artifacts: vec!["https://example.com/pr/1".into()],
                },
            )
            .unwrap();
        let done = store.ticket(&id).unwrap().unwrap();
        assert_eq!(done.state, TicketState::Done);
        assert_eq!(done.stage.as_deref(), Some("plan"));
        assert_eq!(done.artifacts, vec!["https://example.com/pr/1"]);
        assert_eq!(done.outcome, Some(Outcome::Delivered));
        assert_eq!(done.coordinator_id.as_deref(), Some(agent_id.as_str()));
        assert_eq!(done.next, None, "an ended Ticket has no next step");
        assert_eq!(done.progress, Some(100));
    }

    #[test]
    fn stores_and_replays_dispatch_preparation_atomically() {
        let mut store = Store::open_in_memory().unwrap();
        let ticket = new_ticket(&mut store, true);
        let id = ticket.id.clone();
        let coordinator = agent(&mut store, &id);
        store
            .append_all(
                "serve",
                &[
                    Event::TicketDispatched {
                        ticket_id: id.clone(),
                        agent_id: coordinator,
                    },
                    Event::TicketPrepared {
                        ticket_id: id.clone(),
                        base_commit: "abc123".into(),
                        playbook: Some(crate::playbook::PlaybookSnapshot {
                            name: "feature".into(),
                            sha256: "a".repeat(64),
                            body: "old body".into(),
                            spec: None,
                        }),
                        policy: None,
                    },
                ],
            )
            .unwrap();
        let before = store.preparation(&id).unwrap().unwrap();
        assert_eq!(before.base_commit, "abc123");
        assert_eq!(before.playbook.as_ref().unwrap().body, "old body");
        store.rebuild().unwrap();
        assert_eq!(store.preparation(&id).unwrap().unwrap(), before);
    }

    #[test]
    fn verification_requires_declared_checks_and_assigned_verifier_then_replays() {
        let mut store = Store::open_in_memory().unwrap();
        let ticket = new_ticket(&mut store, true);
        let id = ticket.id.clone();
        let coordinator = agent(&mut store, &id);
        store
            .append_all(
                "serve",
                &[
                    Event::TicketDispatched {
                        ticket_id: id.clone(),
                        agent_id: coordinator.clone(),
                    },
                    Event::TicketPrepared {
                        ticket_id: id.clone(),
                        base_commit: "base".into(),
                        playbook: Some(crate::playbook::PlaybookSnapshot {
                            name: "feature".into(),
                            sha256: "a".repeat(64),
                            body: String::new(),
                            spec: Some(crate::playbook::PlaybookSpec {
                                stages: vec![],
                                roles: None,
                                gates: Default::default(),
                                verification: Some(crate::playbook::VerificationSpec {
                                    checks: vec![crate::playbook::CheckSpec {
                                        name: "test".into(),
                                        argv: vec!["true".into()],
                                        timeout_minutes: None,
                                    }],
                                    verifier: Some(crate::playbook::VerifierSpec {
                                        role: "verifier".into(),
                                    }),
                                }),
                                budgets: None,
                            }),
                        }),
                        policy: None,
                    },
                ],
            )
            .unwrap();
        store
            .append(
                &coordinator,
                Event::TicketCompleted {
                    ticket_id: id.clone(),
                    outcome: Outcome::Delivered,
                    summary: "done".into(),
                    artifacts: vec![],
                },
            )
            .unwrap();
        assert_eq!(
            store.ticket(&id).unwrap().unwrap().state,
            TicketState::Verifying
        );
        assert!(
            store
                .append(
                    "serve",
                    Event::TicketVerified {
                        ticket_id: id.clone(),
                        attempt: 1
                    }
                )
                .is_err(),
            "checks and verifier cannot be skipped"
        );
        store
            .append(
                "serve",
                Event::VerificationCheckStarted {
                    ticket_id: id.clone(),
                    attempt: 1,
                    name: "test".into(),
                },
            )
            .unwrap();
        store
            .append(
                "serve",
                Event::VerificationCheckFinished {
                    ticket_id: id.clone(),
                    attempt: 1,
                    name: "test".into(),
                    passed: true,
                    timed_out: false,
                    exit_code: Some(0),
                    output_tail: String::new(),
                },
            )
            .unwrap();
        assert!(
            store
                .append(
                    "serve",
                    Event::TicketVerified {
                        ticket_id: id.clone(),
                        attempt: 1
                    }
                )
                .is_err(),
            "declared verifier must report"
        );
        let verifier_id = format!("{id}-verifier-1");
        let replacement_id = format!("{id}-verifier-2");
        let launched = |agent_id: &str| Event::AgentLaunched {
            agent_id: agent_id.into(),
            rex_session_id: "s".into(),
            rex_window_id: "w".into(),
            rex_block_id: agent_id.into(),
            resume: false,
        };
        store
            .append_all(
                "serve",
                &[
                    Event::AgentCreated {
                        agent_id: verifier_id.clone(),
                        ticket_id: id.clone(),
                        project_id: "demo".into(),
                        role: "verifier".into(),
                        provider: "claude".into(),
                        cwd: "/tmp".into(),
                    },
                    Event::VerificationVerifierAssigned {
                        ticket_id: id.clone(),
                        attempt: 1,
                        agent_id: verifier_id.clone(),
                    },
                    launched(&verifier_id),
                    Event::AgentCreated {
                        agent_id: replacement_id.clone(),
                        ticket_id: id.clone(),
                        project_id: "demo".into(),
                        role: "verifier".into(),
                        provider: "claude".into(),
                        cwd: "/tmp".into(),
                    },
                    Event::VerificationVerifierAssigned {
                        ticket_id: id.clone(),
                        attempt: 1,
                        agent_id: replacement_id.clone(),
                    },
                    launched(&replacement_id),
                ],
            )
            .unwrap();
        assert!(
            store
                .append(
                    &verifier_id,
                    Event::TicketVerified {
                        ticket_id: id.clone(),
                        attempt: 1
                    }
                )
                .is_err(),
            "superseded verifier cannot finish"
        );
        assert!(
            store
                .append(
                    &verifier_id,
                    Event::VerificationFailed {
                        ticket_id: id.clone(),
                        attempt: 1,
                        reason: "stale".into()
                    }
                )
                .is_err(),
            "superseded verifier cannot fail"
        );
        store
            .append(
                &replacement_id,
                Event::TicketVerified {
                    ticket_id: id.clone(),
                    attempt: 1,
                },
            )
            .unwrap();
        assert_eq!(store.ticket(&id).unwrap().unwrap().state, TicketState::Done);
        store.rebuild().unwrap();
        assert_eq!(store.ticket(&id).unwrap().unwrap().state, TicketState::Done);
    }

    #[test]
    fn failed_verification_can_be_retried_with_a_new_attempt() {
        let mut store = Store::open_in_memory().unwrap();
        let ticket = new_ticket(&mut store, true);
        let id = ticket.id.clone();
        let coordinator = agent(&mut store, &id);
        store
            .append_all(
                "serve",
                &[
                    Event::TicketDispatched {
                        ticket_id: id.clone(),
                        agent_id: coordinator.clone(),
                    },
                    Event::TicketPrepared {
                        ticket_id: id.clone(),
                        base_commit: "base".into(),
                        playbook: Some(crate::playbook::PlaybookSnapshot {
                            name: "feature".into(),
                            sha256: "a".repeat(64),
                            body: String::new(),
                            spec: Some(crate::playbook::PlaybookSpec {
                                stages: vec![],
                                roles: None,
                                gates: Default::default(),
                                verification: Some(crate::playbook::VerificationSpec {
                                    checks: vec![crate::playbook::CheckSpec {
                                        name: "test".into(),
                                        argv: vec!["false".into()],
                                        timeout_minutes: None,
                                    }],
                                    verifier: None,
                                }),
                                budgets: None,
                            }),
                        }),
                        policy: None,
                    },
                ],
            )
            .unwrap();
        store
            .append(
                &coordinator,
                Event::TicketCompleted {
                    ticket_id: id.clone(),
                    outcome: Outcome::Delivered,
                    summary: "done".into(),
                    artifacts: vec![],
                },
            )
            .unwrap();
        store
            .append_all(
                "serve",
                &[
                    Event::VerificationCheckStarted {
                        ticket_id: id.clone(),
                        attempt: 1,
                        name: "test".into(),
                    },
                    Event::VerificationCheckFinished {
                        ticket_id: id.clone(),
                        attempt: 1,
                        name: "test".into(),
                        passed: false,
                        timed_out: false,
                        exit_code: Some(1),
                        output_tail: "failed".into(),
                    },
                    Event::VerificationFailed {
                        ticket_id: id.clone(),
                        attempt: 1,
                        reason: "test failed".into(),
                    },
                ],
            )
            .unwrap();
        assert_eq!(
            store.ticket(&id).unwrap().unwrap().state,
            TicketState::Running
        );
        store
            .append(
                &coordinator,
                Event::TicketCompleted {
                    ticket_id: id.clone(),
                    outcome: Outcome::Delivered,
                    summary: "fixed".into(),
                    artifacts: vec![],
                },
            )
            .unwrap();
        assert!(
            store
                .append(
                    "serve",
                    Event::VerificationCheckStarted {
                        ticket_id: id.clone(),
                        attempt: 1,
                        name: "test".into()
                    }
                )
                .is_err()
        );
        store
            .append(
                "serve",
                Event::VerificationCheckStarted {
                    ticket_id: id.clone(),
                    attempt: 2,
                    name: "test".into(),
                },
            )
            .unwrap();
        store.rebuild().unwrap();
        assert_eq!(
            store.ticket(&id).unwrap().unwrap().state,
            TicketState::Verifying
        );
    }

    #[test]
    fn verification_failure_limit_opens_a_human_question() {
        let mut store = Store::open_in_memory().unwrap();
        let ticket = new_ticket(&mut store, true);
        let id = ticket.id.clone();
        let coordinator = agent(&mut store, &id);
        store
            .append_all(
                "serve",
                &[
                    Event::TicketDispatched {
                        ticket_id: id.clone(),
                        agent_id: coordinator.clone(),
                    },
                    Event::TicketPrepared {
                        ticket_id: id.clone(),
                        base_commit: "base".into(),
                        playbook: Some(crate::playbook::PlaybookSnapshot {
                            name: "feature".into(),
                            sha256: "a".repeat(64),
                            body: String::new(),
                            spec: Some(crate::playbook::PlaybookSpec {
                                stages: vec![],
                                roles: None,
                                gates: Default::default(),
                                verification: Some(crate::playbook::VerificationSpec {
                                    checks: vec![crate::playbook::CheckSpec {
                                        name: "test".into(),
                                        argv: vec!["false".into()],
                                        timeout_minutes: None,
                                    }],
                                    verifier: None,
                                }),
                                budgets: None,
                            }),
                        }),
                        policy: Some(crate::policy::Policy {
                            autonomy: crate::policy::Autonomy::A1,
                            required_approvals: vec![],
                            verification_attempts: 1,
                            approvers: Default::default(),
                            budgets: Default::default(),
                        }),
                    },
                ],
            )
            .unwrap();
        store
            .append(
                &coordinator,
                Event::TicketCompleted {
                    ticket_id: id.clone(),
                    outcome: Outcome::Delivered,
                    summary: "done".into(),
                    artifacts: vec![],
                },
            )
            .unwrap();
        store
            .append_all(
                "serve",
                &[
                    Event::VerificationCheckStarted {
                        ticket_id: id.clone(),
                        attempt: 1,
                        name: "test".into(),
                    },
                    Event::VerificationCheckFinished {
                        ticket_id: id.clone(),
                        attempt: 1,
                        name: "test".into(),
                        passed: false,
                        timed_out: false,
                        exit_code: Some(1),
                        output_tail: "failed".into(),
                    },
                    Event::VerificationFailed {
                        ticket_id: id.clone(),
                        attempt: 1,
                        reason: "test failed".into(),
                    },
                    Event::TicketAsked {
                        ticket_id: id.clone(),
                        question: "Verification failed once. Continue?".into(),
                    },
                ],
            )
            .unwrap();
        let waiting = store.ticket(&id).unwrap().unwrap();
        assert_eq!(waiting.state, TicketState::Waiting);
        assert_eq!(
            waiting.question.as_deref(),
            Some("Verification failed once. Continue?")
        );
        assert_eq!(store.unread(&coordinator).unwrap().len(), 1);
        store.rebuild().unwrap();
        assert_eq!(
            store.ticket(&id).unwrap().unwrap().state,
            TicketState::Waiting
        );
    }

    #[test]
    fn rejects_invalid_transitions_without_recording_them() {
        let mut store = Store::open_in_memory().unwrap();
        let id = new_ticket(&mut store, false).id;
        let report = Event::TicketReported {
            ticket_id: id.clone(),
            stage: Some("plan".into()),
            summary: None,
            progress: None,
            next: None,
            artifacts: vec![],
        };
        assert!(store.append("agent", report).is_err());
        store
            .append(
                "human",
                Event::TicketCancelled {
                    ticket_id: id.clone(),
                    reason: "not needed".into(),
                },
            )
            .unwrap();
        assert!(
            store
                .append(
                    "human",
                    Event::TicketReadied {
                        ticket_id: id.clone()
                    }
                )
                .is_err()
        );
        let kinds: Vec<_> = store
            .events_since(0, 100)
            .unwrap()
            .into_iter()
            .map(|e| e.event.kind())
            .collect();
        assert_eq!(kinds, vec!["ticket_created", "ticket_cancelled"]);
    }

    #[test]
    fn rebuild_accepts_history_that_newer_checks_reject() {
        let mut store = Store::open_in_memory().unwrap();
        let id = new_ticket(&mut store, true).id;
        let agent_id = agent(&mut store, &id);
        store
            .append(
                "human",
                Event::TicketCancelled {
                    ticket_id: id.clone(),
                    reason: "not needed".into(),
                },
            )
            .unwrap();
        // An earlier version stored these events; this one refuses new ones.
        let late = [
            Event::AgentLaunched {
                agent_id: agent_id.clone(),
                rex_session_id: "session:1".into(),
                rex_window_id: "window:1".into(),
                rex_block_id: "block:1".into(),
                resume: false,
            },
            Event::AgentExited {
                agent_id: agent_id.clone(),
                reason: "block closed".into(),
            },
            Event::MessageSent {
                ticket_id: id.clone(),
                from: agent_id.clone(),
                to: agent_id.clone(),
                body: "late".into(),
            },
        ];
        assert!(store.append("serve", late[0].clone()).is_err());
        for event in &late {
            store
                .conn
                .execute(
                    "INSERT INTO events (at, actor, kind, payload) VALUES (?1, 'serve', ?2, ?3)",
                    params![now(), event.kind(), serde_json::to_string(event).unwrap()],
                )
                .unwrap();
        }
        store.rebuild().unwrap();
        assert_eq!(store.ticket_messages(&id).unwrap().len(), 1);
        assert!(store.append("serve", late[2].clone()).is_err());
    }

    #[test]
    fn tracks_agents_and_rebuilds_projections() {
        let mut store = Store::open_in_memory().unwrap();
        let id = new_ticket(&mut store, true).id;
        let agent_id = agent(&mut store, &id);
        store
            .append(
                "serve",
                Event::AgentLaunched {
                    agent_id: agent_id.clone(),
                    rex_session_id: "session:1".into(),
                    rex_window_id: "window:1".into(),
                    rex_block_id: "block:1".into(),
                    resume: false,
                },
            )
            .unwrap();
        store
            .append(
                "hook",
                Event::AgentSessionBound {
                    agent_id: agent_id.clone(),
                    harness_session_id: "abc".into(),
                },
            )
            .unwrap();
        store
            .append(
                "serve",
                Event::AgentActivity {
                    agent_id: agent_id.clone(),
                    activity: "working".into(),
                    message: Some("Editing".into()),
                },
            )
            .unwrap();
        assert_eq!(store.agents(true).unwrap().len(), 1);
        store
            .append(
                "serve",
                Event::AgentExited {
                    agent_id: agent_id.clone(),
                    reason: "block closed".into(),
                },
            )
            .unwrap();
        assert!(store.agents(true).unwrap().is_empty());

        let before_ticket = store.ticket(&id).unwrap();
        let before_agent = store.agent(&agent_id).unwrap().unwrap();
        assert_eq!(before_agent.launches, 1);
        assert_eq!(before_agent.harness_session_id.as_deref(), Some("abc"));
        store.rebuild().unwrap();
        assert_eq!(store.ticket(&id).unwrap(), before_ticket);
        assert_eq!(store.agent(&agent_id).unwrap().unwrap(), before_agent);

        let events = store.events_since(0, 100).unwrap();
        let launched = events
            .iter()
            .find(|e| e.event.kind() == "agent_launched")
            .unwrap();
        assert_eq!(launched.project_id.as_deref(), Some("demo"));
        assert_eq!(launched.ticket_id.as_deref(), Some(id.as_str()));
    }
}
