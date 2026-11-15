//! `rex-projects ui`: a dashboard of Tickets that refreshes from the Store.
//!
//! Row building, sorting, and the "Needs you" rules are pure functions. The
//! terminal loop only draws them and turns keys into actions.

use std::collections::HashMap;
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{List, ListItem, ListState, Paragraph};
use ratatui::{DefaultTerminal, Frame};

use crate::domain::{Agent, Event as StoreEvent, Ticket, TicketState};
use crate::paths::Paths;
use crate::store::Store;

const NEEDS_YOU: &str = "Needs you";
const REFRESH: Duration = Duration::from_secs(1);
/// Terminal Tickets older than this are hidden unless `a` shows all.
const TERMINAL_RETENTION: chrono::Duration = chrono::Duration::days(1);

/// Where a Ticket's Coordinator runs in Rex.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JumpTarget {
    pub session: String,
    pub window: Option<String>,
    pub block: String,
}

/// One Ticket as the dashboard shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TicketRow {
    pub ticket_id: String,
    pub project_id: String,
    pub number: i64,
    pub state: TicketState,
    pub stage: String,
    /// The Coordinator's Rex `program_status`, `exited`, or `-`.
    pub activity: String,
    /// The question while waiting, else the summary, else the title.
    pub text: String,
    pub needs_you: bool,
    pub target: Option<JumpTarget>,
}

impl TicketRow {
    /// The heading this row is listed under.
    pub fn section(&self) -> &str {
        if self.needs_you {
            NEEDS_YOU
        } else {
            &self.project_id
        }
    }
}

/// Whether a human should look at the Ticket now.
pub fn needs_you(ticket: &Ticket, coordinator: Option<&Agent>) -> bool {
    ticket.state == TicketState::Waiting
        || coordinator
            .is_some_and(|a| a.state != "exited" && a.activity.as_deref() == Some("blocked"))
}

/// Whether a terminal Ticket ended long enough ago to hide by default.
pub fn is_stale(ticket: &Ticket, now: DateTime<Utc>) -> bool {
    ticket.state.is_terminal()
        && DateTime::parse_from_rfc3339(&ticket.updated_at)
            .is_ok_and(|at| now.signed_duration_since(at) > TERMINAL_RETENTION)
}

fn state_rank(state: TicketState) -> u8 {
    match state {
        TicketState::Waiting => 0,
        TicketState::Running => 1,
        TicketState::Verifying => 2,
        TicketState::Ready => 3,
        TicketState::Backlog => 4,
        TicketState::Failed => 5,
        TicketState::Done => 6,
        TicketState::Abandoned => 7,
    }
}

/// Builds the dashboard rows in display order: "Needs you" first, then each
/// Project with active Tickets before queued and finished ones.
pub fn build_rows(
    tickets: &[Ticket],
    agents: &HashMap<String, Agent>,
    now: DateTime<Utc>,
    show_all: bool,
) -> Vec<TicketRow> {
    let mut rows: Vec<TicketRow> = tickets
        .iter()
        .filter(|t| show_all || !is_stale(t, now))
        .map(|t| {
            let coordinator = t.coordinator_id.as_ref().and_then(|id| agents.get(id));
            let activity = match coordinator {
                Some(a) if a.state == "exited" => "exited".to_owned(),
                Some(a) => a.activity.clone().unwrap_or_else(|| "-".to_owned()),
                None => "-".to_owned(),
            };
            let text = match (&t.question, &t.summary) {
                (Some(q), _) if t.state == TicketState::Waiting => format!("? {q}"),
                (_, Some(s)) => s.clone(),
                _ => t.title.clone(),
            };
            let target = coordinator.and_then(|a| {
                Some(JumpTarget {
                    session: a.rex_session_id.clone()?,
                    window: a.rex_window_id.clone(),
                    block: a.rex_block_id.clone()?,
                })
            });
            TicketRow {
                ticket_id: t.id.clone(),
                project_id: t.project_id.clone(),
                number: t.number,
                state: t.state,
                stage: t.stage.clone().unwrap_or_else(|| "-".to_owned()),
                activity,
                text: text.replace('\n', " "),
                needs_you: needs_you(t, coordinator),
                target,
            }
        })
        .collect();
    rows.sort_by(|a, b| {
        (!a.needs_you, &a.project_id, state_rank(a.state), a.number).cmp(&(
            !b.needs_you,
            &b.project_id,
            state_rank(b.state),
            b.number,
        ))
    });
    rows
}

/// The `rex` invocations that show a Coordinator block: zoom it (which also
/// focuses it and activates its window), then, when the block is in another
/// session, ask the app to show that session.
pub fn jump_commands(target: &JumpTarget, current_session: Option<&str>) -> Vec<Vec<String>> {
    let zoom = vec![
        "zoom".to_owned(),
        "-s".to_owned(),
        target.session.clone(),
        "--on".to_owned(),
        target.block.clone(),
    ];
    if current_session == Some(target.session.as_str()) {
        return vec![zoom];
    }
    let mut select = vec![
        "do".to_owned(),
        "session.select".to_owned(),
        format!("session_id={}", target.session),
    ];
    if let Some(window) = &target.window {
        select.push(format!("window_id={window}"));
    }
    vec![zoom, select]
}

/// What a key asks the loop to do.
#[derive(Debug, PartialEq, Eq)]
enum Action {
    None,
    Quit,
    Jump,
    Ready,
}

#[derive(Default)]
struct App {
    rows: Vec<TicketRow>,
    selected: usize,
    show_all: bool,
    status: Option<String>,
}

impl App {
    fn selected_row(&self) -> Option<&TicketRow> {
        self.rows.get(self.selected)
    }

    /// Replaces the rows, keeping the same Ticket selected when it is still shown.
    fn set_rows(&mut self, rows: Vec<TicketRow>) {
        let keep = self.selected_row().map(|r| r.ticket_id.clone());
        self.rows = rows;
        self.selected = keep
            .and_then(|id| self.rows.iter().position(|r| r.ticket_id == id))
            .unwrap_or(self.selected)
            .min(self.rows.len().saturating_sub(1));
    }

    fn key(&mut self, code: KeyCode) -> Action {
        match code {
            KeyCode::Char('q') | KeyCode::Esc => return Action::Quit,
            KeyCode::Char('j') | KeyCode::Down => {
                self.selected = (self.selected + 1).min(self.rows.len().saturating_sub(1));
            }
            KeyCode::Char('k') | KeyCode::Up => self.selected = self.selected.saturating_sub(1),
            KeyCode::Char('a') => self.show_all = !self.show_all,
            KeyCode::Enter => return Action::Jump,
            KeyCode::Char('r') => return Action::Ready,
            _ => {}
        }
        Action::None
    }

    fn refresh(&mut self, store: &Store) {
        match load_rows(store, self.show_all) {
            Ok(rows) => self.set_rows(rows),
            Err(err) => self.status = Some(format!("refresh failed: {err:#}")),
        }
    }
}

fn load_rows(store: &Store, show_all: bool) -> Result<Vec<TicketRow>> {
    let tickets = store.tickets(None)?;
    let agents = store
        .agents(false)?
        .into_iter()
        .map(|a| (a.id.clone(), a))
        .collect();
    Ok(build_rows(&tickets, &agents, Utc::now(), show_all))
}

fn run_rex(args: &[String]) -> Result<()> {
    let output = Command::new("rex")
        .args(args)
        .stdin(Stdio::null())
        .output()
        .context("failed to run rex")?;
    if !output.status.success() {
        anyhow::bail!(
            "rex {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

fn jump(row: &TicketRow) -> Result<()> {
    let target = row
        .target
        .as_ref()
        .with_context(|| format!("{} has no Coordinator block", row.ticket_id))?;
    let current = std::env::var("REX_SESSION").ok();
    for args in jump_commands(target, current.as_deref()) {
        run_rex(&args)?;
    }
    Ok(())
}

/// Runs the dashboard until `q`. With `popup`, it also quits after a jump.
pub fn run(paths: &Paths, popup: bool) -> Result<()> {
    let mut store = Store::open(&paths.db_file())?;
    let mut terminal = ratatui::try_init()?;
    let result = event_loop(&mut terminal, &mut store, popup);
    ratatui::restore();
    result
}

fn event_loop(terminal: &mut DefaultTerminal, store: &mut Store, popup: bool) -> Result<()> {
    let mut app = App::default();
    loop {
        app.refresh(store);
        terminal.draw(|frame| draw(frame, &app))?;
        if !event::poll(REFRESH)? {
            continue;
        }
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        match app.key(key.code) {
            Action::None => {}
            Action::Quit => return Ok(()),
            Action::Jump => {
                let Some(row) = app.selected_row() else {
                    continue;
                };
                match jump(row) {
                    Ok(()) if popup => return Ok(()),
                    Ok(()) => app.status = Some(format!("jumped to {}", row.ticket_id)),
                    Err(err) => app.status = Some(format!("jump failed: {err:#}")),
                }
            }
            Action::Ready => {
                let Some(row) = app.selected_row() else {
                    continue;
                };
                let id = row.ticket_id.clone();
                let event = StoreEvent::TicketReadied {
                    ticket_id: id.clone(),
                };
                app.status = Some(match store.append(&crate::cli::actor(), event) {
                    Ok(_) => format!("{id} is ready"),
                    Err(err) => format!("cannot ready {id}: {err:#}"),
                });
            }
        }
    }
}

fn state_style(row: &TicketRow) -> Style {
    if row.needs_you {
        return Style::new().fg(Color::Yellow);
    }
    match row.state {
        TicketState::Failed => Style::new().fg(Color::Red),
        TicketState::Done | TicketState::Abandoned => Style::new().fg(Color::DarkGray),
        TicketState::Running | TicketState::Verifying => Style::new().fg(Color::Green),
        _ => Style::new(),
    }
}

fn truncate(text: &str, width: usize) -> String {
    let mut out: String = text.chars().take(width).collect();
    if text.chars().count() > width {
        out.pop();
        out.push('…');
    }
    out
}

fn draw(frame: &mut Frame, app: &App) {
    let [header, body, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(1),
        Constraint::Length(1),
    ])
    .areas(frame.area());

    let waiting = app.rows.iter().filter(|r| r.needs_you).count();
    let title = format!(
        "rex-projects  {} ticket(s), {waiting} need you{}",
        app.rows.len(),
        if app.show_all { "  (showing all)" } else { "" }
    );
    frame.render_widget(
        Paragraph::new(title).style(Style::new().add_modifier(Modifier::BOLD)),
        header,
    );

    let id_width = app
        .rows
        .iter()
        .map(|r| r.ticket_id.chars().count())
        .max()
        .unwrap_or(0);
    let mut items = Vec::new();
    let mut selected_item = None;
    let mut section: Option<&str> = None;
    for (index, row) in app.rows.iter().enumerate() {
        if section != Some(row.section()) {
            section = Some(row.section());
            items.push(ListItem::new(Line::from(Span::styled(
                row.section().to_owned(),
                Style::new().add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
            ))));
        }
        if index == app.selected {
            selected_item = Some(items.len());
        }
        let style = state_style(row);
        items.push(ListItem::new(Line::from(vec![
            Span::raw(format!(" {:id_width$}  ", row.ticket_id)),
            Span::styled(format!("{:9} ", row.state.as_str()), style),
            Span::raw(format!("{:12} ", truncate(&row.stage, 12))),
            Span::styled(format!("{:8} ", truncate(&row.activity, 8)), style),
            Span::raw(row.text.clone()),
        ])));
    }
    if items.is_empty() {
        items.push(ListItem::new(
            "No tickets. Create one with `rex-projects ticket new`.",
        ));
    }
    let list = List::new(items).highlight_style(Style::new().add_modifier(Modifier::REVERSED));
    let mut state = ListState::default().with_selected(selected_item);
    frame.render_stateful_widget(list, body, &mut state);

    let keys = "j/k move  enter jump  r ready  a all  q quit";
    let footer_text = match &app.status {
        Some(status) => format!("{status}  |  {keys}"),
        None => keys.to_owned(),
    };
    frame.render_widget(
        Paragraph::new(footer_text).style(Style::new().fg(Color::DarkGray)),
        footer,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ticket(project: &str, number: i64, state: TicketState) -> Ticket {
        Ticket {
            id: format!("{project}-{number}"),
            project_id: project.to_owned(),
            number,
            title: format!("title {number}"),
            body: String::new(),
            state,
            stage: None,
            summary: None,
            progress: None,
            next: None,
            question: None,
            priority: 0,
            playbook: None,
            blocked_by: Vec::new(),
            external_refs: Vec::new(),
            artifacts: Vec::new(),
            outcome: None,
            coordinator_id: None,
            created_at: "2026-11-15T00:00:00.000Z".to_owned(),
            updated_at: "2026-11-15T00:00:00.000Z".to_owned(),
        }
    }

    fn coordinator(id: &str, activity: &str) -> Agent {
        Agent {
            id: id.to_owned(),
            ticket_id: String::new(),
            project_id: String::new(),
            role: "coordinator".to_owned(),
            provider: "claude".to_owned(),
            cwd: String::new(),
            state: "running".to_owned(),
            harness_session_id: None,
            rex_session_id: Some("session:1".to_owned()),
            rex_window_id: Some("window:1".to_owned()),
            rex_block_id: Some("block:1".to_owned()),
            launches: 1,
            activity: Some(activity.to_owned()),
            activity_message: None,
            exit_reason: None,
            created_at: String::new(),
            updated_at: String::new(),
        }
    }

    fn now() -> DateTime<Utc> {
        "2026-11-15T12:00:00Z".parse().unwrap()
    }

    fn ids(rows: &[TicketRow]) -> Vec<&str> {
        rows.iter().map(|r| r.ticket_id.as_str()).collect()
    }

    #[test]
    fn waiting_and_blocked_tickets_need_you() {
        let mut blocked = ticket("b", 1, TicketState::Running);
        blocked.coordinator_id = Some("agent-1".to_owned());
        let mut waiting = ticket("a", 2, TicketState::Waiting);
        waiting.question = Some("Which API?".to_owned());
        waiting.summary = Some("ignored while waiting".to_owned());
        let agents = HashMap::from([("agent-1".to_owned(), coordinator("agent-1", "blocked"))]);

        let rows = build_rows(
            &[ticket("a", 1, TicketState::Running), blocked, waiting],
            &agents,
            now(),
            false,
        );

        assert_eq!(ids(&rows), ["a-2", "b-1", "a-1"]);
        assert!(rows[0].needs_you && rows[1].needs_you && !rows[2].needs_you);
        assert_eq!(rows[0].section(), NEEDS_YOU);
        assert_eq!(rows[2].section(), "a");
        assert_eq!(rows[0].text, "? Which API?");
        assert_eq!(rows[1].activity, "blocked");
        assert_eq!(
            rows[1].target,
            Some(JumpTarget {
                session: "session:1".to_owned(),
                window: Some("window:1".to_owned()),
                block: "block:1".to_owned(),
            })
        );
    }

    #[test]
    fn exited_coordinator_does_not_need_you() {
        let mut t = ticket("a", 1, TicketState::Running);
        t.coordinator_id = Some("agent-1".to_owned());
        let mut agent = coordinator("agent-1", "blocked");
        agent.state = "exited".to_owned();
        let agents = HashMap::from([("agent-1".to_owned(), agent)]);

        let rows = build_rows(&[t], &agents, now(), false);

        assert!(!rows[0].needs_you);
        assert_eq!(rows[0].activity, "exited");
    }

    #[test]
    fn rows_group_by_project_with_active_tickets_first() {
        let tickets = [
            ticket("b", 1, TicketState::Backlog),
            ticket("a", 3, TicketState::Done),
            ticket("a", 1, TicketState::Ready),
            ticket("a", 2, TicketState::Running),
            ticket("b", 2, TicketState::Verifying),
        ];

        let rows = build_rows(&tickets, &HashMap::new(), now(), false);

        assert_eq!(ids(&rows), ["a-2", "a-1", "a-3", "b-2", "b-1"]);
        assert_eq!(rows[0].activity, "-");
        assert_eq!(rows[0].text, "title 2");
        assert_eq!(rows[0].target, None);
    }

    #[test]
    fn old_terminal_tickets_are_hidden_unless_showing_all() {
        let mut old_done = ticket("a", 1, TicketState::Done);
        old_done.updated_at = "2026-11-13T00:00:00.000Z".to_owned();
        let mut old_running = ticket("a", 2, TicketState::Running);
        old_running.updated_at = old_done.updated_at.clone();
        let recent_failed = ticket("a", 3, TicketState::Failed);
        let tickets = [old_done, old_running, recent_failed];

        let rows = build_rows(&tickets, &HashMap::new(), now(), false);
        assert_eq!(ids(&rows), ["a-2", "a-3"]);

        let rows = build_rows(&tickets, &HashMap::new(), now(), true);
        assert_eq!(ids(&rows), ["a-2", "a-3", "a-1"]);
    }

    #[test]
    fn summary_replaces_title_and_newlines_are_flattened() {
        let mut t = ticket("a", 1, TicketState::Running);
        t.summary = Some("line one\nline two".to_owned());

        let rows = build_rows(&[t], &HashMap::new(), now(), false);

        assert_eq!(rows[0].text, "line one line two");
    }

    #[test]
    fn jump_zooms_the_block_then_selects_the_session() {
        let target = JumpTarget {
            session: "session:1".to_owned(),
            window: Some("window:1".to_owned()),
            block: "block:1".to_owned(),
        };

        let zoom = vec!["zoom", "-s", "session:1", "--on", "block:1"];
        assert_eq!(
            jump_commands(&target, Some("session:2")),
            [
                zoom.clone(),
                vec![
                    "do",
                    "session.select",
                    "session_id=session:1",
                    "window_id=window:1"
                ],
            ]
        );
        assert_eq!(jump_commands(&target, Some("session:1")), [zoom]);
    }

    #[test]
    fn selection_follows_the_ticket_across_refreshes() {
        let rows = |ids: &[i64]| -> Vec<TicketRow> {
            let tickets: Vec<_> = ids
                .iter()
                .map(|n| ticket("a", *n, TicketState::Ready))
                .collect();
            build_rows(&tickets, &HashMap::new(), now(), false)
        };
        let mut app = App::default();
        app.set_rows(rows(&[1, 2, 3]));
        assert_eq!(app.key(KeyCode::Char('j')), Action::None);
        assert_eq!(app.selected_row().unwrap().ticket_id, "a-2");

        app.set_rows(rows(&[2, 3]));
        assert_eq!(app.selected_row().unwrap().ticket_id, "a-2");

        app.set_rows(rows(&[3]));
        assert_eq!(app.selected, 0);
        app.key(KeyCode::Down);
        assert_eq!(app.selected, 0);
        assert_eq!(app.key(KeyCode::Char('q')), Action::Quit);
    }
}
