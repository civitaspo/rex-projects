//! External trackers through CLI adapters (ADR-0010).
//!
//! Each `[trackers.<name>]` table describes how to call a tracker's own CLI:
//! argv templates substituted element by element (no shell), and jq
//! expressions, evaluated in-process with jaq, that map the CLI's JSON output
//! to [`ExternalItem`]s. [`TrackerSync`] writes Ticket state back through an
//! outbox of jobs and notices items closed outside rex-projects.

use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, SecondsFormat, Utc};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::config::{Config, ProjectConfig};
use crate::domain::{Event, ExternalRef, Outcome, Ticket};
use crate::store::{NewTicket, Store};

const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const STDERR_LIMIT: usize = 2000;
const STARTED: &str = "Started by rex-projects.";
const PROGRESS_INTERVAL: chrono::Duration = chrono::Duration::minutes(10);
const MAX_ATTEMPTS: i64 = 10;
const BUILTINS: [&str; 4] = ["ref", "query", "summary", "body"];

/// The status of an external item, as mapped by a tracker's jq expression.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalStatus {
    Open,
    InProgress,
    InReview,
    Done,
    Canceled,
    Other,
}

impl ExternalStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::InProgress => "in_progress",
            Self::InReview => "in_review",
            Self::Done => "done",
            Self::Canceled => "canceled",
            Self::Other => "other",
        }
    }
}

/// An item in an external tracker.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExternalItem {
    #[serde(rename = "ref")]
    pub reference: String,
    #[serde(default)]
    pub url: Option<String>,
    pub title: String,
    #[serde(default)]
    pub body: Option<String>,
    pub status: ExternalStatus,
    #[serde(default)]
    pub labels: Vec<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Query {
    pub argv: Vec<String>,
    pub map: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    pub argv: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transitions {
    pub done: Vec<Step>,
    pub in_progress: Option<Vec<Step>>,
    pub canceled: Option<Vec<Step>>,
}

/// One validated `[trackers.<name>]` table.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tracker {
    #[serde(skip)]
    pub name: String,
    pub get: Query,
    pub list: Option<Query>,
    pub comment: Option<Step>,
    pub transition: Transitions,
}

/// All configured trackers, validated.
#[derive(Clone, Debug, Default)]
pub struct Trackers(BTreeMap<String, Tracker>);

impl Trackers {
    /// Parses and validates every tracker, and checks that each Project using
    /// one supplies the variables its argv templates need.
    pub fn from_config(config: &Config) -> Result<Self> {
        let mut trackers = BTreeMap::new();
        for (name, table) in &config.trackers {
            let tracker =
                Tracker::parse(name, table).with_context(|| format!("tracker {name:?}"))?;
            trackers.insert(name.clone(), tracker);
        }
        for project in &config.projects {
            let Some(pt) = &project.tracker else { continue };
            let Some(tracker) = trackers.get(&pt.name) else {
                continue;
            };
            check_vars(tracker, &pt.vars)
                .with_context(|| format!("project {:?} tracker vars", project.id))?;
        }
        Ok(Self(trackers))
    }

    pub fn get(&self, name: &str) -> Result<&Tracker> {
        self.0
            .get(name)
            .with_context(|| format!("tracker {name:?} is not configured"))
    }
}

fn check_vars(tracker: &Tracker, vars: &BTreeMap<String, String>) -> Result<()> {
    if let Some(name) = vars.keys().find(|k| BUILTINS.contains(&k.as_str())) {
        bail!("{{{{{name}}}}} is built in and cannot be a variable");
    }
    for (label, argv, _) in tracker.commands() {
        for arg in argv {
            for name in placeholders(arg) {
                if !BUILTINS.contains(&name.as_str()) && !vars.contains_key(&name) {
                    bail!("{label} uses {{{{{name}}}}}, which the Project does not set");
                }
            }
        }
    }
    Ok(())
}

impl Tracker {
    fn parse(name: &str, table: &toml::Table) -> Result<Self> {
        let mut tracker: Tracker = toml::Value::Table(table.clone()).try_into()?;
        tracker.name = name.to_owned();
        if tracker.transition.done.is_empty() {
            bail!("transition.done needs at least one step");
        }
        if tracker.comment.is_none()
            && (tracker.transition.in_progress.is_none() || tracker.transition.canceled.is_none())
        {
            bail!(
                "comment is required unless transition.in_progress and transition.canceled are set"
            );
        }
        for (label, argv, allowed) in tracker.commands() {
            if argv.first().is_none_or(|program| program.is_empty()) {
                bail!("{label}.argv must name a program");
            }
            for arg in argv {
                for name in placeholders(arg) {
                    if BUILTINS.contains(&name.as_str()) && !allowed.contains(&name.as_str()) {
                        bail!("{label} cannot use {{{{{name}}}}}");
                    }
                }
            }
        }
        jq(&tracker.get.map, None).context("get.map")?;
        if let Some(list) = &tracker.list {
            jq(&list.map, None).context("list.map")?;
        }
        Ok(tracker)
    }

    /// Every argv template with its label and the built-in placeholders it may use.
    fn commands(&self) -> Vec<(String, &[String], &'static [&'static str])> {
        let mut commands: Vec<(String, &[String], &'static [&'static str])> =
            vec![("get".into(), &self.get.argv, &["ref"])];
        if let Some(list) = &self.list {
            commands.push(("list".into(), &list.argv, &["query"]));
        }
        if let Some(comment) = &self.comment {
            commands.push(("comment".into(), &comment.argv, &["ref", "body"]));
        }
        let t = &self.transition;
        for (status, steps) in [
            ("done", Some(&t.done)),
            ("in_progress", t.in_progress.as_ref()),
            ("canceled", t.canceled.as_ref()),
        ] {
            for (i, step) in steps.into_iter().flatten().enumerate() {
                commands.push((
                    format!("transition.{status}[{i}]"),
                    &step.argv,
                    &["ref", "summary"],
                ));
            }
        }
        commands
    }

    pub fn has_in_progress(&self) -> bool {
        self.transition.in_progress.is_some()
    }

    pub fn has_canceled(&self) -> bool {
        self.transition.canceled.is_some()
    }

    fn run(
        &self,
        argv: &[String],
        builtins: &[(&str, &str)],
        vars: &BTreeMap<String, String>,
    ) -> Result<Vec<u8>> {
        let mut values: HashMap<&str, &str> =
            vars.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        values.extend(builtins.iter().copied());
        let argv = render(argv, &values)?;
        run_command(&argv).with_context(|| format!("tracker {:?}: {}", self.name, argv[0]))
    }

    /// Fetches one item.
    pub fn get(&self, reference: &str, vars: &BTreeMap<String, String>) -> Result<ExternalItem> {
        let out = self.run(&self.get.argv, &[("ref", reference)], vars)?;
        let mut values = jq(&self.get.map, Some(&out)).context("get.map")?;
        if values.len() != 1 {
            bail!("get.map must produce one item, got {}", values.len());
        }
        item(values.remove(0)).context("get.map")
    }

    /// Lists candidate items.
    pub fn list(&self, query: &str, vars: &BTreeMap<String, String>) -> Result<Vec<ExternalItem>> {
        let list = self
            .list
            .as_ref()
            .with_context(|| format!("tracker {:?} has no list command", self.name))?;
        let out = self.run(&list.argv, &[("query", query)], vars)?;
        let mut values = jq(&list.map, Some(&out)).context("list.map")?;
        if let [serde_json::Value::Array(items)] = values.as_mut_slice() {
            values = std::mem::take(items);
        }
        values
            .into_iter()
            .map(|v| item(v).context("list.map"))
            .collect()
    }

    pub fn comment(
        &self,
        reference: &str,
        body: &str,
        vars: &BTreeMap<String, String>,
    ) -> Result<()> {
        let comment = self
            .comment
            .as_ref()
            .with_context(|| format!("tracker {:?} has no comment command", self.name))?;
        self.run(&comment.argv, &[("ref", reference), ("body", body)], vars)?;
        Ok(())
    }

    /// Runs every step of `transition.<status>` in order.
    pub fn transition(
        &self,
        status: &str,
        reference: &str,
        summary: &str,
        vars: &BTreeMap<String, String>,
    ) -> Result<()> {
        let t = &self.transition;
        let steps = match status {
            "done" => Some(&t.done),
            "in_progress" => t.in_progress.as_ref(),
            "canceled" => t.canceled.as_ref(),
            _ => None,
        }
        .with_context(|| format!("tracker {:?} has no transition.{status}", self.name))?;
        for step in steps {
            self.run(
                &step.argv,
                &[("ref", reference), ("summary", summary)],
                vars,
            )?;
        }
        Ok(())
    }
}

fn item(value: serde_json::Value) -> Result<ExternalItem> {
    serde_json::from_value(value.clone()).with_context(|| {
        format!(
            "{value} is not an item {{ref, url, title, body, status, labels}} \
             with status open|in_progress|in_review|done|canceled|other"
        )
    })
}

/// Replaces `{{name}}` in `arg`, asking `lookup` for each value.
fn substitute(arg: &str, mut lookup: impl FnMut(&str) -> Result<String>) -> Result<String> {
    let mut out = String::new();
    let mut rest = arg;
    while let Some(start) = rest.find("{{") {
        let Some(len) = rest[start + 2..].find("}}") else {
            break;
        };
        out.push_str(&rest[..start]);
        out.push_str(&lookup(rest[start + 2..start + 2 + len].trim())?);
        rest = &rest[start + 4 + len..];
    }
    out.push_str(rest);
    Ok(out)
}

fn placeholders(arg: &str) -> Vec<String> {
    let mut names = Vec::new();
    let _ = substitute(arg, |name| {
        names.push(name.to_owned());
        Ok(String::new())
    });
    names
}

/// Substitutes placeholders element by element. An unknown placeholder is an error.
pub fn render(argv: &[String], values: &HashMap<&str, &str>) -> Result<Vec<String>> {
    argv.iter()
        .map(|arg| {
            substitute(arg, |name| match values.get(name) {
                Some(value) => Ok((*value).to_owned()),
                None => bail!("unknown placeholder {{{{{name}}}}}"),
            })
        })
        .collect()
}

/// Runs a command without a shell and returns its stdout.
fn run_command(argv: &[String]) -> Result<Vec<u8>> {
    let mut child = Command::new(&argv[0])
        .args(&argv[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to start {}", argv[0]))?;
    let read = |mut pipe: Box<dyn Read + Send>| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = pipe.read_to_end(&mut buf);
            buf
        })
    };
    let stdout = read(Box::new(child.stdout.take().context("no stdout")?));
    let stderr = read(Box::new(child.stderr.take().context("no stderr")?));
    let deadline = Instant::now() + COMMAND_TIMEOUT;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!("timed out after {}s", COMMAND_TIMEOUT.as_secs());
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let stdout = stdout.join().unwrap_or_default();
    if !status.success() {
        let stderr = stderr.join().unwrap_or_default();
        let stderr = String::from_utf8_lossy(&stderr);
        let stderr: String = stderr.trim().chars().take(STDERR_LIMIT).collect();
        bail!("exited with {status}: {stderr}");
    }
    Ok(stdout)
}

/// Compiles `code`, and when `input` is given runs it on that JSON text.
fn jq(code: &str, input: Option<&[u8]>) -> Result<Vec<serde_json::Value>> {
    use jaq_core::load::{Arena, File, Loader};
    use jaq_core::{Compiler, Ctx, Vars, data};
    use jaq_json::Val;

    let defs = jaq_core::defs()
        .chain(jaq_std::defs())
        .chain(jaq_json::defs());
    let funs = jaq_core::funs()
        .chain(jaq_std::funs())
        .chain(jaq_json::funs());
    let arena = Arena::default();
    let modules = Loader::new(defs)
        .load(&arena, File { code, path: () })
        .map_err(|errs| anyhow!("cannot parse jq expression {code:?}: {errs:?}"))?;
    let filter = Compiler::default()
        .with_funs(funs)
        .compile(modules)
        .map_err(|errs| anyhow!("cannot compile jq expression {code:?}: {errs:?}"))?;
    let Some(input) = input else {
        return Ok(Vec::new());
    };
    let input = jaq_json::read::parse_single(input)
        .map_err(|err| anyhow!("command output is not JSON: {err:?}"))?;
    let ctx = Ctx::<data::JustLut<Val>>::new(&filter.lut, Vars::new([]));
    filter
        .id
        .run((ctx, input))
        .map(|out| match out {
            Ok(value) => serde_json::from_str(&value.to_string())
                .with_context(|| format!("jq produced non-JSON value {value}")),
            Err(exn) => match exn.get_err() {
                Ok(err) => bail!("jq error: {err}"),
                Err(_) => bail!("jq expression halted"),
            },
        })
        .collect()
}

fn project_vars(project: &ProjectConfig) -> BTreeMap<String, String> {
    project
        .tracker
        .as_ref()
        .map(|t| t.vars.clone())
        .unwrap_or_default()
}

fn project_tracker<'a>(project: &'a ProjectConfig, name: Option<&'a str>) -> Result<&'a str> {
    name.or(project.tracker.as_ref().map(|t| t.name.as_str()))
        .with_context(|| format!("project {:?} has no tracker; pass --tracker", project.id))
}

/// Imports an external item as a new Ticket.
pub fn import(
    store: &mut Store,
    config: &Config,
    actor: &str,
    project_id: &str,
    tracker_name: Option<&str>,
    reference: &str,
    ready: bool,
) -> Result<Ticket> {
    let project = config.project(project_id)?;
    let name = project_tracker(project, tracker_name)?;
    let trackers = Trackers::from_config(config)?;
    let item = trackers.get(name)?.get(reference, &project_vars(project))?;
    for ticket in store.tickets(None)? {
        let tracked = ticket.external_refs.iter().any(|r| {
            r.tracker == name && (r.reference == item.reference || r.reference == reference)
        });
        if tracked && !ticket.state.is_terminal() {
            bail!(
                "{} already tracks {name} {} ({})",
                ticket.id,
                item.reference,
                ticket.state
            );
        }
    }
    store.create_ticket(
        actor,
        NewTicket {
            project_id: project_id.to_owned(),
            title: item.title,
            body: item.body.unwrap_or_default(),
            external_refs: vec![ExternalRef {
                tracker: name.to_owned(),
                reference: item.reference,
                url: item.url,
            }],
            ready,
            ..Default::default()
        },
    )
}

/// Lists candidate items from a Project's tracker.
pub fn list(config: &Config, project_id: &str, query: &str) -> Result<Vec<ExternalItem>> {
    let project = config.project(project_id)?;
    let name = project_tracker(project, None)?;
    Trackers::from_config(config)?
        .get(name)?
        .list(query, &project_vars(project))
}

const SYNC_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS tracker_cursor (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  seq INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS tracker_jobs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ticket_id TEXT NOT NULL,
  tracker TEXT NOT NULL,
  ref TEXT NOT NULL,
  action TEXT NOT NULL,
  text TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'pending',
  attempts INTEGER NOT NULL DEFAULT 0,
  next_at TEXT NOT NULL,
  last_error TEXT,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tracker_refs (
  ticket_id TEXT NOT NULL,
  tracker TEXT NOT NULL,
  ref TEXT NOT NULL,
  stage TEXT,
  external_status TEXT,
  PRIMARY KEY (ticket_id, tracker, ref)
);
"#;

/// Actions whose job sets the item's state; a newer one supersedes older ones.
const TRANSITIONS: [&str; 3] = ["in_progress", "done", "canceled"];

/// One queued write-back. `action` is `in_progress`, `done`, or `canceled`
/// (a transition), `comment`, or `progress` (a rate-limited comment).
/// `state` is `pending`, `done`, `failed` (given up), or `superseded`.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct TrackerJob {
    pub id: i64,
    pub ticket_id: String,
    pub tracker: String,
    #[serde(rename = "ref")]
    pub reference: String,
    pub action: String,
    pub text: String,
    pub state: String,
    pub attempts: i64,
    pub next_at: String,
    pub last_error: Option<String>,
}

/// Lists write-back jobs: pending and failed ones, or all with `all`.
pub fn jobs(store: &Store, all: bool) -> Result<Vec<TrackerJob>> {
    let conn = store.conn();
    conn.execute_batch(SYNC_SCHEMA)?;
    let mut stmt = conn.prepare(
        "SELECT id, ticket_id, tracker, ref, action, text, state, attempts, next_at, last_error
         FROM tracker_jobs WHERE ?1 OR state IN ('pending', 'failed') ORDER BY id",
    )?;
    let rows = stmt.query_map(params![all], |row| {
        Ok(TrackerJob {
            id: row.get(0)?,
            ticket_id: row.get(1)?,
            tracker: row.get(2)?,
            reference: row.get(3)?,
            action: row.get(4)?,
            text: row.get(5)?,
            state: row.get(6)?,
            attempts: row.get(7)?,
            next_at: row.get(8)?,
            last_error: row.get(9)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// The delay before retry number `attempts` (1-based).
pub fn backoff(attempts: i64) -> chrono::Duration {
    let secs = [30, 120, 600, 1800];
    chrono::Duration::seconds(
        secs.get(attempts.saturating_sub(1) as usize)
            .copied()
            .unwrap_or(3600),
    )
}

fn ts(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// What a Ticket event means for its external refs.
enum Plan {
    Started,
    Stage(String, String),
    Finished { delivered: bool, text: String },
}

fn plan(event: &Event) -> Option<Plan> {
    let finished = |outcome: &str, reason: &str| Plan::Finished {
        delivered: false,
        text: format!("rex-projects ended this work as {outcome}: {reason}"),
    };
    Some(match event {
        Event::TicketDispatched { .. } => Plan::Started,
        Event::TicketReported {
            stage: Some(stage),
            summary,
            ..
        } => Plan::Stage(
            stage.clone(),
            match summary {
                Some(summary) => format!("Stage: {stage} — {summary}"),
                None => format!("Stage: {stage}"),
            },
        ),
        Event::TicketCompleted {
            outcome: Outcome::Delivered,
            summary,
            artifacts,
            ..
        } => {
            let mut text = summary.clone();
            if !artifacts.is_empty() {
                text = format!("{text}\n\n{}", artifacts.join("\n"));
            }
            Plan::Finished {
                delivered: true,
                text,
            }
        }
        Event::TicketCompleted {
            outcome: Outcome::Abandoned,
            summary,
            ..
        }
        | Event::TicketCancelled {
            reason: summary, ..
        } => finished("abandoned", summary),
        Event::TicketCompleted { summary, .. }
        | Event::TicketFailed {
            reason: summary, ..
        } => finished("failed", summary),
        _ => return None,
    })
}

/// Writes Ticket state back to external trackers. `serve` calls
/// [`TrackerSync::tick`] periodically.
pub struct TrackerSync {
    /// How often active Tickets' external refs are re-read.
    pub poll_interval: chrono::Duration,
    last_poll: Option<DateTime<Utc>>,
}

impl Default for TrackerSync {
    fn default() -> Self {
        Self {
            poll_interval: chrono::Duration::seconds(60),
            last_poll: None,
        }
    }
}

impl TrackerSync {
    /// Queues jobs for new events, runs due jobs, and re-reads external refs
    /// when the poll interval has passed. Tracker CLIs run synchronously.
    pub fn tick(&mut self, store: &mut Store, config: &Config, now: DateTime<Utc>) -> Result<()> {
        let trackers = Trackers::from_config(config)?;
        store.conn().execute_batch(SYNC_SCHEMA)?;
        enqueue(store, &trackers, now)?;
        run_due(store, config, &trackers, now)?;
        if self
            .last_poll
            .is_none_or(|last| now - last >= self.poll_interval)
        {
            self.last_poll = Some(now);
            poll(store, config, &trackers)?;
        }
        Ok(())
    }
}

fn enqueue(store: &Store, trackers: &Trackers, now: DateTime<Utc>) -> Result<()> {
    let conn = store.conn();
    loop {
        let cursor: i64 = conn
            .query_row("SELECT seq FROM tracker_cursor WHERE id = 1", [], |r| {
                r.get(0)
            })
            .optional()?
            .unwrap_or(0);
        let events = store.events_since(cursor, 500)?;
        for stored in &events {
            let tx = conn.unchecked_transaction()?;
            if let (Some(plan), Some(id)) = (plan(&stored.event), stored.event.ticket_id())
                && let Some(ticket) = store.ticket(id)?
            {
                for r in &ticket.external_refs {
                    enqueue_ref(conn, trackers, &ticket.id, r, &plan, now)?;
                }
            }
            tx.execute(
                "INSERT INTO tracker_cursor (id, seq) VALUES (1, ?1)
                 ON CONFLICT (id) DO UPDATE SET seq = excluded.seq",
                params![stored.seq],
            )?;
            tx.commit()?;
        }
        if events.len() < 500 {
            return Ok(());
        }
    }
}

fn enqueue_ref(
    conn: &Connection,
    trackers: &Trackers,
    ticket_id: &str,
    r: &ExternalRef,
    plan: &Plan,
    now: DateTime<Utc>,
) -> Result<()> {
    let key = params![ticket_id, r.tracker, r.reference];
    let insert = |action: &str, text: &str, at: DateTime<Utc>| -> Result<()> {
        if TRANSITIONS.contains(&action) {
            conn.execute(
                "UPDATE tracker_jobs SET state = 'superseded'
                 WHERE tracker = ?1 AND ref = ?2 AND state = 'pending'
                   AND action IN ('in_progress', 'done', 'canceled')",
                params![r.tracker, r.reference],
            )?;
        }
        conn.execute(
            "INSERT INTO tracker_jobs (ticket_id, tracker, ref, action, text, next_at, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                ticket_id,
                r.tracker,
                r.reference,
                action,
                text,
                ts(at),
                ts(now)
            ],
        )?;
        Ok(())
    };
    let tracker = match trackers.get(&r.tracker) {
        Ok(tracker) => tracker,
        Err(err) => {
            insert("comment", "", now)?;
            conn.execute(
                "UPDATE tracker_jobs SET state = 'failed', last_error = ?1
                 WHERE id = last_insert_rowid()",
                params![err.to_string()],
            )?;
            return Ok(());
        }
    };
    match plan {
        Plan::Started if tracker.has_in_progress() => insert("in_progress", STARTED, now),
        Plan::Started => insert("comment", STARTED, now),
        Plan::Stage(stage, text) => {
            let previous: Option<String> = conn
                .query_row(
                    "SELECT stage FROM tracker_refs WHERE ticket_id = ?1 AND tracker = ?2 AND ref = ?3",
                    key,
                    |row| row.get(0),
                )
                .optional()?
                .flatten();
            if previous.as_deref() == Some(stage) {
                return Ok(());
            }
            conn.execute(
                "INSERT INTO tracker_refs (ticket_id, tracker, ref, stage) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT DO UPDATE SET stage = excluded.stage",
                params![ticket_id, r.tracker, r.reference, stage],
            )?;
            if tracker.has_in_progress() {
                return Ok(());
            }
            let coalesced = conn.execute(
                "UPDATE tracker_jobs SET text = ?4
                 WHERE ticket_id = ?1 AND tracker = ?2 AND ref = ?3
                   AND action = 'progress' AND state = 'pending'",
                params![ticket_id, r.tracker, r.reference, text],
            )?;
            if coalesced > 0 {
                return Ok(());
            }
            let last: Option<String> = conn.query_row(
                "SELECT MAX(next_at) FROM tracker_jobs
                 WHERE ticket_id = ?1 AND tracker = ?2 AND ref = ?3 AND action = 'progress'",
                key,
                |row| row.get(0),
            )?;
            let earliest = last
                .and_then(|last| DateTime::parse_from_rfc3339(&last).ok())
                .map(|last| last.with_timezone(&Utc) + PROGRESS_INTERVAL);
            insert("progress", text, earliest.map_or(now, |at| at.max(now)))
        }
        Plan::Finished { delivered, text } => {
            // The rate limit no longer matters once the work has ended.
            conn.execute(
                "UPDATE tracker_jobs SET next_at = ?4
                 WHERE ticket_id = ?1 AND tracker = ?2 AND ref = ?3
                   AND action = 'progress' AND state = 'pending' AND next_at > ?4",
                params![ticket_id, r.tracker, r.reference, ts(now)],
            )?;
            if *delivered {
                insert("done", text, now)
            } else if tracker.has_canceled() {
                insert("canceled", text, now)
            } else {
                insert("comment", text, now)
            }
        }
    }
}

fn run_due(store: &Store, config: &Config, trackers: &Trackers, now: DateTime<Utc>) -> Result<()> {
    let conn = store.conn();
    // A job waits for every earlier pending job on the same external ref.
    let due: Vec<TrackerJob> = jobs(store, false)?
        .into_iter()
        .filter(|job| job.state == "pending")
        .collect();
    let mut blocked = std::collections::HashSet::new();
    for job in due {
        let key = (job.tracker.clone(), job.reference.clone());
        if blocked.contains(&key) {
            continue;
        }
        if job.next_at > ts(now) {
            blocked.insert(key);
            continue;
        }
        match execute(store, config, trackers, &job) {
            Ok(()) => {
                conn.execute(
                    "UPDATE tracker_jobs SET state = 'done', attempts = attempts + 1,
                       last_error = NULL WHERE id = ?1",
                    params![job.id],
                )?;
            }
            Err(err) => {
                blocked.insert(key);
                let attempts = job.attempts + 1;
                let state = if attempts >= MAX_ATTEMPTS {
                    "failed"
                } else {
                    "pending"
                };
                conn.execute(
                    "UPDATE tracker_jobs SET state = ?2, attempts = ?3, next_at = ?4,
                       last_error = ?5 WHERE id = ?1",
                    params![
                        job.id,
                        state,
                        attempts,
                        ts(now + backoff(attempts)),
                        format!("{err:#}")
                    ],
                )?;
            }
        }
    }
    Ok(())
}

fn execute(store: &Store, config: &Config, trackers: &Trackers, job: &TrackerJob) -> Result<()> {
    let tracker = trackers.get(&job.tracker)?;
    let ticket = store
        .ticket(&job.ticket_id)?
        .with_context(|| format!("ticket {} does not exist", job.ticket_id))?;
    let vars = project_vars(config.project(&ticket.project_id)?);
    match job.action.as_str() {
        "comment" | "progress" => tracker.comment(&job.reference, &job.text, &vars),
        status => tracker.transition(status, &job.reference, &job.text, &vars),
    }
}

/// Re-reads active Tickets' external refs and records items closed outside
/// rex-projects as [`Event::ExternalChanged`], once per change.
fn poll(store: &mut Store, config: &Config, trackers: &Trackers) -> Result<()> {
    for ticket in store.tickets(None)? {
        if !ticket.state.is_active() {
            continue;
        }
        let Ok(project) = config.project(&ticket.project_id) else {
            continue;
        };
        for r in &ticket.external_refs {
            // A failed read is retried at the next poll.
            let Ok(item) = trackers
                .get(&r.tracker)
                .and_then(|t| t.get(&r.reference, &project_vars(project)))
            else {
                continue;
            };
            let status = item.status.as_str();
            let previous: Option<String> = store
                .conn()
                .query_row(
                    "SELECT external_status FROM tracker_refs
                     WHERE ticket_id = ?1 AND tracker = ?2 AND ref = ?3",
                    params![ticket.id, r.tracker, r.reference],
                    |row| row.get(0),
                )
                .optional()?
                .flatten();
            if previous.as_deref() == Some(status) {
                continue;
            }
            store.conn().execute(
                "INSERT INTO tracker_refs (ticket_id, tracker, ref, external_status)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT DO UPDATE SET external_status = excluded.external_status",
                params![ticket.id, r.tracker, r.reference, status],
            )?;
            if matches!(item.status, ExternalStatus::Done | ExternalStatus::Canceled) {
                store.append(
                    "tracker",
                    Event::ExternalChanged {
                        ticket_id: ticket.id.clone(),
                        tracker: r.tracker.clone(),
                        reference: r.reference.clone(),
                        status: status.to_owned(),
                    },
                )?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake tracker CLI: logs its argv, fails when `fail-<command>` or
    /// `fail-<ref>` exists, and reads the item status from `status`.
    const SCRIPT: &str = r#"dir=$(dirname "$0")
echo "$*" >> "$dir/log"
if [ -e "$dir/fail-$1" ] || [ -e "$dir/fail-$2" ]; then echo "boom: $1" >&2; exit 3; fi
case "$1" in
  get) status=$(cat "$dir/status" 2>/dev/null || echo Open)
       printf '{"key":"%s","link":"https://acme.example/%s","fields":{"summary":"Title of %s","status":"%s","labels":["bug"]}}\n' "$2" "$2" "$2" "$status" ;;
  list) printf '{"items":[{"key":"A-1","title":"One","state":"Open"},{"key":"A-2","title":"Two","state":"Done"}]}\n' ;;
esac
"#;

    const CONFIG: &str = r#"
[[projects]]
id = "demo"
repo = "/tmp/demo"
tracker = { name = "acme", vars = { space = "ENG" } }

[trackers.acme]
get = { argv = ["/bin/sh", "SH", "get", "{{ref}}", "{{space}}"], map = '{ref: .key, url: .link, title: .fields.summary, status: (.fields.status | ascii_downcase), labels: .fields.labels}' }
list = { argv = ["/bin/sh", "SH", "list", "{{query}}"], map = '.items | map({ref: .key, title, status: (.state | ascii_downcase)})' }
comment = { argv = ["/bin/sh", "SH", "comment", "{{ref}}", "{{body}}"] }
transition.in_progress = [{ argv = ["/bin/sh", "SH", "start", "{{ref}}"] }]
transition.done = [{ argv = ["/bin/sh", "SH", "close", "{{ref}}", "{{summary}}"] }]
transition.canceled = [{ argv = ["/bin/sh", "SH", "cancel", "{{ref}}", "{{summary}}"] }]

[trackers.simple]
get = { argv = ["/bin/sh", "SH", "get", "{{ref}}"], map = '{ref: .key, title: .fields.summary, status: "open"}' }
comment = { argv = ["/bin/sh", "SH", "comment", "{{ref}}", "{{body}}"] }
transition.done = [{ argv = ["/bin/sh", "SH", "close", "{{ref}}", "{{summary}}"] }]
"#;

    struct Fake(tempfile::TempDir);

    impl Fake {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(dir.path().join("fake.sh"), SCRIPT).unwrap();
            Self(dir)
        }

        fn config(&self) -> Config {
            let sh = self.0.path().join("fake.sh");
            Config::parse(&CONFIG.replace("SH", sh.to_str().unwrap())).unwrap()
        }

        fn log(&self) -> Vec<String> {
            std::fs::read_to_string(self.0.path().join("log"))
                .unwrap_or_default()
                .lines()
                .map(str::to_owned)
                .collect()
        }

        fn calls(&self, prefix: &str) -> Vec<String> {
            self.log()
                .into_iter()
                .filter(|line| line.starts_with(prefix))
                .collect()
        }

        fn touch(&self, name: &str, contents: &str) {
            std::fs::write(self.0.path().join(name), contents).unwrap();
        }

        fn remove(&self, name: &str) {
            std::fs::remove_file(self.0.path().join(name)).unwrap();
        }
    }

    fn t(secs: i64) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
            + chrono::Duration::seconds(secs)
    }

    fn running(store: &mut Store, refs: &[(&str, &str)]) -> String {
        let external_refs = refs
            .iter()
            .map(|(tracker, reference)| ExternalRef {
                tracker: (*tracker).into(),
                reference: (*reference).into(),
                url: None,
            })
            .collect();
        let new = NewTicket {
            project_id: "demo".into(),
            title: "Work".into(),
            ready: true,
            external_refs,
            ..Default::default()
        };
        let ticket = store.create_ticket("human", new).unwrap();
        let agent_id = format!("{}-coordinator", ticket.id);
        let created = Event::AgentCreated {
            agent_id: agent_id.clone(),
            ticket_id: ticket.id.clone(),
            project_id: "demo".into(),
            role: "coordinator".into(),
            provider: "claude".into(),
            cwd: "/tmp".into(),
        };
        store.append("serve", created).unwrap();
        let dispatched = Event::TicketDispatched {
            ticket_id: ticket.id.clone(),
            agent_id,
        };
        store.append("serve", dispatched).unwrap();
        ticket.id
    }

    fn report(store: &mut Store, id: &str, stage: &str) {
        let event = Event::TicketReported {
            ticket_id: id.into(),
            stage: Some(stage.into()),
            summary: Some(format!("{stage} summary")),
            progress: None,
            next: None,
            artifacts: vec![],
        };
        store.append("agent", event).unwrap();
    }

    fn complete(store: &mut Store, id: &str) {
        let event = Event::TicketCompleted {
            ticket_id: id.into(),
            outcome: Outcome::Delivered,
            summary: "Shipped".into(),
            artifacts: vec!["https://example.com/pr/1".into()],
        };
        store.append("agent", event).unwrap();
    }

    fn job_states(store: &Store, reference: &str) -> Vec<String> {
        jobs(store, true)
            .unwrap()
            .into_iter()
            .filter(|job| job.reference == reference)
            .map(|job| format!("{} {}", job.action, job.state))
            .collect()
    }

    #[test]
    fn substitutes_placeholders_per_element() {
        let values = HashMap::from([("ref", "A-1; rm -rf /"), ("body", "two words")]);
        let argv: Vec<String> = ["tool", "--id={{ ref }}", "{{body}}", "{{x"]
            .map(String::from)
            .into();
        assert_eq!(
            render(&argv, &values).unwrap(),
            ["tool", "--id=A-1; rm -rf /", "two words", "{{x"]
        );
        let err = render(&["{{nope}}".to_owned()], &values).unwrap_err();
        assert!(err.to_string().contains("unknown placeholder {{nope}}"));
    }

    #[test]
    fn validates_tracker_config() {
        let check = |tracker: &str, vars: &str| {
            let text = format!(
                "[[projects]]\nid = \"a\"\nrepo = \"/a\"\n\
                 tracker = {{ name = \"t\", vars = {{ {vars} }} }}\n[trackers.t]\n{tracker}"
            );
            Config::parse(&text)
                .map(|_| ())
                .map_err(|e| format!("{e:#}"))
        };
        let get = "get = { argv = [\"x\", \"{{ref}}\"], map = \".\" }\n";
        let comment = "comment = { argv = [\"x\", \"{{body}}\"] }\n";
        let done = "transition.done = [{ argv = [\"x\", \"{{summary}}\"] }]\n";
        let in_progress = "transition.in_progress = [{ argv = [\"x\"] }]\n";
        let canceled = "transition.canceled = [{ argv = [\"x\"] }]\n";
        assert!(check(&format!("{get}{comment}{done}"), "").is_ok());
        assert!(check(&format!("{get}{done}{in_progress}{canceled}"), "").is_ok());
        let err = check(&format!("{get}{comment}{in_progress}"), "").unwrap_err();
        assert!(err.contains("done"), "{err}");
        for partial in [in_progress, canceled] {
            let err = check(&format!("{get}{done}{partial}"), "").unwrap_err();
            assert!(err.contains("comment is required"), "{err}");
        }
        let summary_in_get = "get = { argv = [\"x\", \"{{summary}}\"], map = \".\" }\n";
        let err = check(&format!("{summary_in_get}{comment}{done}"), "").unwrap_err();
        assert!(err.contains("get cannot use {{summary}}"), "{err}");
        let with_var = "get = { argv = [\"x\", \"{{repo}}\"], map = \".\" }\n";
        let err = check(&format!("{with_var}{comment}{done}"), "").unwrap_err();
        assert!(err.contains("{{repo}}"), "{err}");
        assert!(check(&format!("{with_var}{comment}{done}"), "repo = \"r\"").is_ok());
        let bad_jq = "get = { argv = [\"x\"], map = \"{ref: \" }\n";
        let err = check(&format!("{bad_jq}{comment}{done}"), "").unwrap_err();
        assert!(err.contains("get.map"), "{err}");
    }

    #[test]
    fn maps_get_and_list_output() {
        let fake = Fake::new();
        let config = fake.config();
        let trackers = Trackers::from_config(&config).unwrap();
        let acme = trackers.get("acme").unwrap();
        let vars = project_vars(config.project("demo").unwrap());
        let item = acme.get("A-7", &vars).unwrap();
        assert_eq!(item.reference, "A-7");
        assert_eq!(item.title, "Title of A-7");
        assert_eq!(item.url.as_deref(), Some("https://acme.example/A-7"));
        assert_eq!(item.status, ExternalStatus::Open);
        assert_eq!(item.labels, ["bug"]);
        assert_eq!(fake.log(), ["get A-7 ENG"]);

        let items = acme.list("open bugs", &vars).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[1].status, ExternalStatus::Done);
        assert_eq!(fake.log()[1], "list open bugs");

        fake.touch("status", "Blocked");
        let err = format!("{:#}", acme.get("A-7", &vars).unwrap_err());
        assert!(err.contains("get.map") && err.contains("status"), "{err}");
        fake.touch("fail-get", "");
        let err = format!("{:#}", acme.get("A-7", &vars).unwrap_err());
        assert!(err.contains("boom: get"), "{err}");
    }

    #[test]
    fn writes_back_with_rate_limited_progress() {
        let fake = Fake::new();
        let config = fake.config();
        let mut store = Store::open_in_memory().unwrap();
        let mut sync = TrackerSync::default();
        let id = running(&mut store, &[("acme", "A-1"), ("simple", "S-1")]);
        sync.tick(&mut store, &config, t(0)).unwrap();
        assert_eq!(fake.calls("start"), ["start A-1"]);
        assert_eq!(
            fake.calls("comment"),
            ["comment S-1 Started by rex-projects."]
        );

        report(&mut store, &id, "plan");
        sync.tick(&mut store, &config, t(1)).unwrap();
        let plan = "comment S-1 Stage: plan — plan summary";
        assert_eq!(fake.calls("comment S-1 Stage"), [plan]);
        // Later Stages within ten minutes coalesce into one comment.
        report(&mut store, &id, "build");
        sync.tick(&mut store, &config, t(60)).unwrap();
        report(&mut store, &id, "verify");
        report(&mut store, &id, "verify");
        sync.tick(&mut store, &config, t(120)).unwrap();
        assert_eq!(fake.calls("comment S-1 Stage").len(), 1);
        sync.tick(&mut store, &config, t(602)).unwrap();
        let verify = "comment S-1 Stage: verify — verify summary";
        assert_eq!(fake.calls("comment S-1 Stage"), [plan, verify]);
        assert!(fake.calls("comment A-1").is_empty());

        complete(&mut store, &id);
        sync.tick(&mut store, &config, t(603)).unwrap();
        let log = fake.log().join("\n");
        assert!(log.contains("close A-1 Shipped\n\nhttps://example.com/pr/1"));
        assert!(log.contains("close S-1 Shipped\n\nhttps://example.com/pr/1"));
        assert!(jobs(&store, false).unwrap().is_empty());
    }

    #[test]
    fn falls_back_to_comment_without_canceled() {
        let fake = Fake::new();
        let config = fake.config();
        let mut store = Store::open_in_memory().unwrap();
        let mut sync = TrackerSync::default();
        let id = running(&mut store, &[("acme", "A-1"), ("simple", "S-1")]);
        let cancelled = Event::TicketCancelled {
            ticket_id: id,
            reason: "not needed".into(),
        };
        store.append("human", cancelled).unwrap();
        sync.tick(&mut store, &config, t(0)).unwrap();
        let text = "rex-projects ended this work as abandoned: not needed";
        assert_eq!(fake.calls("cancel"), [format!("cancel A-1 {text}")]);
        assert_eq!(
            fake.calls("comment S-1 rex"),
            [format!("comment S-1 {text}")]
        );
    }

    #[test]
    fn retries_with_backoff_without_blocking_other_tickets() {
        assert_eq!(backoff(1).num_seconds(), 30);
        assert_eq!(backoff(2).num_seconds(), 120);
        assert_eq!(backoff(3).num_seconds(), 600);
        assert_eq!(backoff(9).num_seconds(), 3600);

        let fake = Fake::new();
        fake.touch("fail-A-1", "");
        let config = fake.config();
        let mut store = Store::open_in_memory().unwrap();
        let mut sync = TrackerSync::default();
        running(&mut store, &[("acme", "A-1")]);
        running(&mut store, &[("acme", "A-2")]);
        sync.tick(&mut store, &config, t(0)).unwrap();
        assert_eq!(fake.calls("start"), ["start A-1", "start A-2"]);
        let failed = &jobs(&store, false).unwrap()[0];
        assert_eq!((failed.reference.as_str(), failed.attempts), ("A-1", 1));
        assert_eq!(failed.next_at, ts(t(30)));
        assert!(
            failed
                .last_error
                .as_deref()
                .unwrap()
                .contains("boom: start")
        );

        sync.tick(&mut store, &config, t(10)).unwrap();
        assert_eq!(fake.calls("start A-1").len(), 1);
        sync.tick(&mut store, &config, t(31)).unwrap();
        assert_eq!(fake.calls("start A-1").len(), 2);
        assert_eq!(jobs(&store, false).unwrap()[0].next_at, ts(t(151)));

        let mut now = 31;
        for _ in 0..8 {
            now += 3600;
            sync.tick(&mut store, &config, t(now)).unwrap();
        }
        let failed = &jobs(&store, false).unwrap()[0];
        assert_eq!((failed.state.as_str(), failed.attempts), ("failed", 10));
        sync.tick(&mut store, &config, t(now + 7200)).unwrap();
        assert_eq!(fake.calls("start A-1").len(), 10);
    }

    #[test]
    fn newer_transition_supersedes_pending_one() {
        let fake = Fake::new();
        fake.touch("fail-start", "");
        let config = fake.config();
        let mut store = Store::open_in_memory().unwrap();
        let mut sync = TrackerSync::default();
        let id = running(&mut store, &[("acme", "A-1")]);
        sync.tick(&mut store, &config, t(0)).unwrap();
        complete(&mut store, &id);
        sync.tick(&mut store, &config, t(1)).unwrap();
        assert_eq!(
            job_states(&store, "A-1"),
            ["in_progress superseded", "done done"]
        );
        // The superseded transition never runs again.
        fake.remove("fail-start");
        sync.tick(&mut store, &config, t(3600)).unwrap();
        assert_eq!(fake.calls("start"), ["start A-1"]);
    }

    #[test]
    fn keeps_per_ref_order_and_does_not_supersede_comments() {
        let fake = Fake::new();
        fake.touch("fail-S-1", "");
        let config = fake.config();
        let mut store = Store::open_in_memory().unwrap();
        let mut sync = TrackerSync::default();
        let id = running(&mut store, &[("simple", "S-1")]);
        sync.tick(&mut store, &config, t(0)).unwrap();
        report(&mut store, &id, "plan");
        complete(&mut store, &id);
        sync.tick(&mut store, &config, t(1)).unwrap();
        // The due progress comment and done wait for the failed comment.
        assert_eq!(fake.calls("comment S-1").len(), 1);
        assert_eq!(
            job_states(&store, "S-1"),
            ["comment pending", "progress pending", "done pending"]
        );
        fake.remove("fail-S-1");
        sync.tick(&mut store, &config, t(31)).unwrap();
        let writes: Vec<String> = fake
            .log()
            .into_iter()
            .filter(|line| !line.starts_with("get"))
            .collect();
        assert_eq!(
            writes,
            [
                "comment S-1 Started by rex-projects.",
                "comment S-1 Started by rex-projects.",
                "comment S-1 Stage: plan — plan summary",
                "close S-1 Shipped",
                "",
                "https://example.com/pr/1",
            ]
        );
    }

    #[test]
    fn records_external_close_once() {
        let fake = Fake::new();
        let config = fake.config();
        let mut store = Store::open_in_memory().unwrap();
        let mut sync = TrackerSync::default();
        running(&mut store, &[("acme", "A-1")]);
        let changes = |store: &Store| {
            store
                .events_since(0, 1000)
                .unwrap()
                .into_iter()
                .filter(|e| matches!(e.event, Event::ExternalChanged { .. }))
                .count()
        };
        sync.tick(&mut store, &config, t(0)).unwrap();
        assert_eq!(fake.calls("get A-1").len(), 1);
        fake.touch("status", "Done");
        sync.tick(&mut store, &config, t(30)).unwrap();
        assert_eq!(changes(&store), 0);
        sync.tick(&mut store, &config, t(61)).unwrap();
        sync.tick(&mut store, &config, t(122)).unwrap();
        assert_eq!(changes(&store), 1);
        let event = store.events_since(0, 1000).unwrap().pop().unwrap().event;
        let expected = Event::ExternalChanged {
            ticket_id: "demo-1".into(),
            tracker: "acme".into(),
            reference: "A-1".into(),
            status: "done".into(),
        };
        assert_eq!(event, expected);
        assert_eq!(fake.calls("get A-1").len(), 3);
    }
}
