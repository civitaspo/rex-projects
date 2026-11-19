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
        Ok(self
            .conn
            .query_row(
                &format!("SELECT {TICKET_COLUMNS} FROM tickets WHERE id = ?1"),
                params![id],
                ticket_from_row,
            )
            .optional()?)
    }

    /// Lists Tickets, optionally for one Project, ordered by Project and number.
    pub fn tickets(&self, project_id: Option<&str>) -> Result<Vec<Ticket>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {TICKET_COLUMNS} FROM tickets
             WHERE ?1 IS NULL OR project_id = ?1
             ORDER BY project_id, number"
        ))?;
        let rows = stmt.query_map(params![project_id], ticket_from_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
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

    /// Drops the projections and rebuilds them by replaying every event.
    pub fn rebuild(&mut self) -> Result<()> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch("DELETE FROM tickets; DELETE FROM agents; DELETE FROM messages;")?;
        let events: Vec<(String, String)> = {
            let mut stmt = tx.prepare("SELECT at, payload FROM events ORDER BY seq")?;
            let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        for (at, payload) in events {
            let event: Event = serde_json::from_str(&payload)?;
            project(&tx, &at, &event)?;
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
    project(tx, &at, event)?;
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

fn project(tx: &Transaction<'_>, at: &str, event: &Event) -> Result<()> {
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
            require(ticket_id, state, &[Running, Waiting], "ask on")?;
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
        Event::TicketCompleted {
            ticket_id,
            outcome,
            summary,
            artifacts,
        } => {
            let state = ticket_state(tx, ticket_id)?;
            require(ticket_id, state, &[Running, Waiting], "complete")?;
            let next = match outcome {
                Outcome::Delivered => Done,
                Outcome::Abandoned => Abandoned,
                Outcome::Failed => Failed,
            };
            set_ticket_state(tx, ticket_id, next, at)?;
            // An ended Ticket has no next step, and a delivered one is complete.
            tx.execute(
                "UPDATE tickets SET summary = ?2, outcome = ?3, question = NULL, next = NULL,
                   progress = CASE WHEN ?3 = 'delivered' THEN 100 ELSE progress END
                 WHERE id = ?1",
                params![ticket_id, summary, serde_json::to_value(outcome)?.as_str()],
            )?;
            merge_artifacts(tx, ticket_id, artifacts)?;
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
                    if role != "coordinator" && matches!(state.as_str(), "finished" | "exited") =>
                {
                    bail!("agent {to} has {state}; spawn a new helper instead")
                }
                Some(_) => {}
            }
            // A helper that finished or was stopped can no longer report.
            if let Some((_, _, state)) = agent(from)?
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
            if role != "coordinator" && !matches!(state, Running | Waiting) {
                bail!("ticket {ticket_id} is {state}; helpers run only on a running Ticket");
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
            let (state, ticket_id): (String, String) = tx.query_row(
                "SELECT state, ticket_id FROM agents WHERE id = ?1",
                params![agent_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            if state == "finished" {
                bail!("agent {agent_id} was stopped before it launched");
            }
            let ticket = ticket_state(tx, &ticket_id)?;
            if ticket.is_terminal() {
                bail!("ticket {ticket_id} is {ticket}; agent {agent_id} cannot launch");
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
