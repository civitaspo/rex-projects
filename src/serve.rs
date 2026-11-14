//! `serve`: dispatches ready Tickets to Coordinators in Rex and keeps their
//! blocks reconciled with the state database.

use std::cmp::Reverse;
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};

use crate::config::{Config, ProviderKind};
use crate::domain::{Agent, Event, Ticket, TicketState};
use crate::paths::Paths;
use crate::provider;
use crate::rex::{Rex, RexCli};
use crate::store::Store;
use crate::tracker::TrackerSync;
use crate::worktree;

/// How many times a Coordinator is resumed after its block disappears.
pub const MAX_RELAUNCHES: i64 = 3;
const ACTOR: &str = "serve";

/// Chooses the Tickets to dispatch now, taking one ready Ticket per Project
/// in turn, starting at Project `rotation`. Returns the Ticket IDs and the
/// Project to start from next time.
pub fn plan(
    config: &Config,
    tickets: &[Ticket],
    live_agents: usize,
    rotation: usize,
) -> (Vec<String>, usize) {
    let states: HashMap<&str, TicketState> =
        tickets.iter().map(|t| (t.id.as_str(), t.state)).collect();
    let mut active = tickets.iter().filter(|t| t.state.is_active()).count();
    let mut agents = live_agents;
    let mut queues: Vec<(Option<u32>, usize, VecDeque<&Ticket>)> = config
        .projects
        .iter()
        .map(|project| {
            let mine = || tickets.iter().filter(|t| t.project_id == project.id);
            let mut ready: Vec<&Ticket> = mine()
                .filter(|t| t.state == TicketState::Ready)
                .filter(|t| {
                    t.blocked_by
                        .iter()
                        .all(|b| states.get(b.as_str()) == Some(&TicketState::Done))
                })
                .collect();
            ready.sort_by_key(|t| (Reverse(t.priority), t.number));
            let running = mine().filter(|t| t.state.is_active()).count();
            (project.max_running_tickets, running, ready.into())
        })
        .collect();
    let n = queues.len();
    let mut picked = Vec::new();
    if n == 0 {
        return (picked, rotation);
    }
    let (mut i, mut next, mut misses) = (rotation % n, rotation % n, 0);
    while misses < n
        && active < config.limits.max_running_tickets as usize
        && agents < config.limits.max_agents as usize
    {
        let (limit, running, queue) = &mut queues[i];
        let fits = limit.is_none_or(|limit| *running < limit as usize);
        match queue.front() {
            Some(ticket) if fits => {
                picked.push(ticket.id.clone());
                queue.pop_front();
                *running += 1;
                active += 1;
                agents += 1;
                misses = 0;
                next = (i + 1) % n;
            }
            _ => misses += 1,
        }
        i = (i + 1) % n;
    }
    (picked, next)
}

pub struct Serve<R: Rex> {
    pub paths: Paths,
    pub store: Store,
    pub rex: R,
    /// The rex-projects executable that blocks run.
    pub exe: PathBuf,
    rotation: usize,
}

impl<R: Rex> Serve<R> {
    pub fn new(paths: Paths, store: Store, rex: R, exe: PathBuf) -> Self {
        Self {
            paths,
            store,
            rex,
            exe,
            rotation: 0,
        }
    }

    pub fn tick(&mut self, config: &Config) -> Result<()> {
        self.keep_session_labels()?;
        for agent in self.store.agents(true)? {
            if agent.state == "running"
                && let Err(err) = self.reconcile(config, &agent)
            {
                println!("{}: reconcile failed: {err:#}", agent.id);
            }
        }
        self.dispatch(config)
    }

    fn append(&mut self, event: Event) -> Result<()> {
        self.store.append(ACTOR, event).map(drop)
    }

    fn reconcile(&mut self, config: &Config, agent: &Agent) -> Result<()> {
        let (Some(session), Some(block)) = (&agent.rex_session_id, &agent.rex_block_id) else {
            return Ok(());
        };
        let ticket = self
            .store
            .ticket(&agent.ticket_id)?
            .with_context(|| format!("ticket {} does not exist", agent.ticket_id))?;
        if !self.rex.block_ids(session)?.contains(block) {
            self.append(Event::AgentExited {
                agent_id: agent.id.clone(),
                reason: "block closed".into(),
            })?;
            println!("{}: block closed", agent.id);
            if !ticket.state.is_active() || agent.role != "coordinator" {
                return Ok(());
            }
            let result = if agent.launches <= MAX_RELAUNCHES {
                self.launch(agent, &ticket, true)
            } else {
                Err(anyhow!(
                    "the Coordinator's block closed after {} launches",
                    agent.launches
                ))
            };
            if let Err(err) = result {
                self.fail(&ticket.id, &format!("{err:#}"))?;
            }
            return Ok(());
        }
        if matches!(ticket.state, TicketState::Abandoned | TicketState::Failed) {
            self.rex.close_block(session, block)?;
            self.append(Event::AgentExited {
                agent_id: agent.id.clone(),
                reason: format!("ticket {}", ticket.state),
            })?;
            println!(
                "{}: closed because {} is {}",
                agent.id, ticket.id, ticket.state
            );
            return Ok(());
        }
        if let Some(status) = self.rex.program_status(session, block)?
            && (agent.activity.as_deref() != Some(&status.state)
                || agent.activity_message != status.message)
        {
            println!("{}: {}", agent.id, status.state);
            self.append(Event::AgentActivity {
                agent_id: agent.id.clone(),
                activity: status.state,
                message: status.message,
            })?;
        }
        if agent.harness_session_id.is_none()
            && config.provider(&agent.provider)?.kind == ProviderKind::Codex
            && let Some(after) = provider::launched_at(&self.paths.agent_dir(&agent.id))
            && let Some(sessions) = provider::codex_sessions_dir()
            && let Some(id) = provider::find_codex_session(&sessions, Path::new(&agent.cwd), after)
        {
            println!("{}: bound Codex session {id}", agent.id);
            self.append(Event::AgentSessionBound {
                agent_id: agent.id.clone(),
                harness_session_id: id,
            })?;
        }
        Ok(())
    }

    fn fail(&mut self, ticket_id: &str, reason: &str) -> Result<()> {
        println!("{ticket_id}: failed: {reason}");
        self.append(Event::TicketFailed {
            ticket_id: ticket_id.to_owned(),
            reason: reason.to_owned(),
        })
    }

    /// Sets each live Project session's label back to `rxp:<project>`, in
    /// case an Agent renamed it.
    fn keep_session_labels(&mut self) -> Result<()> {
        let mut seen = std::collections::BTreeSet::new();
        for agent in self.store.agents(true)? {
            if let Some(session) = agent.rex_session_id
                && seen.insert(session.clone())
            {
                self.rex
                    .ensure_session(&session_label(&agent.project_id), Some(&session))?;
            }
        }
        Ok(())
    }

    /// The session this Project's Agents last ran in, if any.
    fn known_session(&self, project_id: &str) -> Result<Option<String>> {
        Ok(self
            .store
            .agents(false)?
            .into_iter()
            .filter(|a| a.project_id == project_id)
            .filter_map(|a| a.rex_session_id)
            .next_back())
    }

    fn launch(&mut self, agent: &Agent, ticket: &Ticket, resume: bool) -> Result<()> {
        let known = self.known_session(&ticket.project_id)?;
        let session = self
            .rex
            .ensure_session(&session_label(&ticket.project_id), known.as_deref())?;
        let command: Vec<String> = [
            self.exe.as_os_str(),
            "--config-dir".as_ref(),
            self.paths.config_dir.as_os_str(),
            "--state-dir".as_ref(),
            self.paths.state_dir.as_os_str(),
            "agent".as_ref(),
            "exec".as_ref(),
            agent.id.as_ref(),
        ]
        .iter()
        .map(|s| s.to_string_lossy().into_owned())
        .collect();
        let label = format!("{} {}", ticket.id, ticket.title);
        let window = self
            .rex
            .new_window(&session, &label, &command, Path::new(&agent.cwd))?;
        let launched = self.append(Event::AgentLaunched {
            agent_id: agent.id.clone(),
            rex_session_id: session.clone(),
            rex_window_id: window.window_id.clone(),
            rex_block_id: window.block_id.clone(),
            resume,
        });
        if let Err(err) = launched {
            let _ = self.rex.close_block(&session, &window.block_id);
            return Err(err);
        }
        let verb = if resume { "resumed" } else { "launched" };
        println!("{}: {verb} in {}", agent.id, window.block_id);
        Ok(())
    }

    fn dispatch(&mut self, config: &Config) -> Result<()> {
        let tickets = self.store.tickets(None)?;
        let live = self.store.agents(true)?.len();
        let (picked, next) = plan(config, &tickets, live, self.rotation);
        self.rotation = next;
        for ticket in tickets.iter().filter(|t| picked.contains(&t.id)) {
            if let Err(err) = self.dispatch_one(config, ticket) {
                self.fail(&ticket.id, &format!("dispatch failed: {err:#}"))?;
                let agent_id = coordinator_id(&ticket.id);
                if self
                    .store
                    .agent(&agent_id)?
                    .is_some_and(|a| a.state != "exited")
                {
                    self.append(Event::AgentExited {
                        agent_id,
                        reason: "launch failed".into(),
                    })?;
                }
            }
        }
        Ok(())
    }

    fn dispatch_one(&mut self, config: &Config, ticket: &Ticket) -> Result<()> {
        let project = config.project(&ticket.project_id)?;
        let dir = self.paths.worktree_dir(&project.id, &ticket.id);
        worktree::ensure(
            &project.repo,
            &dir,
            &worktree::branch(&ticket.id),
            project.base_branch.as_deref(),
        )?;
        let agent_id = coordinator_id(&ticket.id);
        if self.store.agent(&agent_id)?.is_none() {
            self.append(Event::AgentCreated {
                agent_id: agent_id.clone(),
                ticket_id: ticket.id.clone(),
                project_id: project.id.clone(),
                role: "coordinator".into(),
                provider: project.coordinator.provider.clone(),
                cwd: dir.display().to_string(),
            })?;
        }
        self.append(Event::TicketDispatched {
            ticket_id: ticket.id.clone(),
            agent_id: agent_id.clone(),
        })?;
        println!("{}: dispatched to {agent_id}", ticket.id);
        let agent = self.store.agent(&agent_id)?.context("agent vanished")?;
        self.launch(&agent, ticket, false)
    }
}

fn session_label(project_id: &str) -> String {
    format!("rxp:{project_id}")
}

pub fn coordinator_id(ticket_id: &str) -> String {
    format!("{ticket_id}-coordinator")
}

/// Runs `serve` against the real Rex server until interrupted.
pub fn run(paths: &Paths, interval: Duration, once: bool) -> Result<()> {
    std::fs::create_dir_all(&paths.state_dir)
        .with_context(|| format!("failed to create {}", paths.state_dir.display()))?;
    // Blocks run `agent exec` from other directories, so pass absolute paths.
    let paths = Paths {
        config_dir: std::path::absolute(&paths.config_dir)?,
        state_dir: std::fs::canonicalize(&paths.state_dir)?,
    };
    let lock_path = paths.state_dir.join("serve.lock");
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
        .with_context(|| format!("failed to open {}", lock_path.display()))?;
    lock.try_lock()
        .map_err(|_| anyhow!("another serve is already running ({})", lock_path.display()))?;
    let store = Store::open(&paths.db_file())?;
    let exe = std::env::current_exe().context("failed to locate rex-projects")?;
    let mut serve = Serve::new(paths.clone(), store, RexCli::new(), exe);
    if once {
        let config = Config::load(&paths.config_file())?;
        serve.tick(&config)?;
        return sync_trackers(&paths, &mut TrackerSync::default());
    }
    // Tracker CLIs can take seconds each, so write-backs run on their own
    // thread and database connection instead of delaying reconciliation.
    let tracker_paths = paths.clone();
    std::thread::spawn(move || {
        let mut sync = TrackerSync::default();
        loop {
            if let Err(err) = sync_trackers(&tracker_paths, &mut sync) {
                eprintln!("tracker sync failed: {err:#}");
            }
            std::thread::sleep(interval.max(Duration::from_secs(5)));
        }
    });
    loop {
        let result = Config::load(&paths.config_file()).and_then(|config| serve.tick(&config));
        if let Err(err) = result {
            eprintln!("tick failed: {err:#}");
        }
        std::thread::sleep(interval);
    }
}

fn sync_trackers(paths: &Paths, sync: &mut TrackerSync) -> Result<()> {
    let config = Config::load(&paths.config_file())?;
    if config.trackers.is_empty() {
        return Ok(());
    }
    let mut store = Store::open(&paths.db_file())?;
    sync.tick(&mut store, &config, chrono::Utc::now())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Outcome;
    use crate::rex::Status;
    use crate::rex::fake::FakeRex;
    use crate::store::NewTicket;

    fn ticket(project: &str, number: i64, state: TicketState) -> Ticket {
        Ticket {
            id: format!("{project}-{number}"),
            project_id: project.into(),
            number,
            title: "t".into(),
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
            created_at: String::new(),
            updated_at: String::new(),
        }
    }

    fn config(text: &str) -> Config {
        Config::parse(&format!(
            "{text}\n[[projects]]\nid = \"a\"\nrepo = \"/a\"\n[[projects]]\nid = \"b\"\nrepo = \"/b\"\nmax_running_tickets = 1\n"
        ))
        .unwrap()
    }

    #[test]
    fn plans_round_robin_within_limits() {
        use TicketState::*;
        let config = config("[limits]\nmax_running_tickets = 3");
        let tickets = vec![
            ticket("a", 1, Ready),
            ticket("a", 2, Ready),
            ticket("a", 3, Ready),
            ticket("b", 1, Ready),
            ticket("b", 2, Ready),
        ];
        // `b` allows one running Ticket, so `a` takes the remaining slot.
        assert_eq!(
            plan(&config, &tickets, 0, 0),
            (vec!["a-1".into(), "b-1".into(), "a-2".into()], 1)
        );
        assert_eq!(plan(&config, &tickets, 0, 1).0, ["b-1", "a-1", "a-2"]);
        // Active Tickets and live Agents use up capacity.
        let mut busy = tickets.clone();
        busy[0].state = Running;
        assert_eq!(plan(&config, &busy, 1, 0).0, ["a-2", "b-1"]);
        assert_eq!(plan(&config, &tickets, 10, 0).0, Vec::<String>::new());
    }

    #[test]
    fn plans_by_priority_and_dependencies() {
        use TicketState::*;
        let config = config("");
        let mut tickets = vec![
            ticket("a", 1, Ready),
            ticket("a", 2, Ready),
            ticket("a", 3, Ready),
            ticket("a", 4, Ready),
            ticket("a", 5, Done),
            ticket("a", 6, Running),
        ];
        tickets[1].priority = 5;
        tickets[2].blocked_by = vec!["a-5".into()];
        tickets[3].blocked_by = vec!["a-6".into()];
        tickets[0].blocked_by = vec!["missing".into()];
        assert_eq!(plan(&config, &tickets, 0, 0).0, ["a-2", "a-3"]);
    }

    struct Fixture {
        serve: Serve<FakeRex>,
        config: Config,
        _dirs: (tempfile::TempDir, tempfile::TempDir),
    }

    fn fixture() -> Fixture {
        let repo = crate::worktree::tests::temp_repo();
        let state = tempfile::tempdir().unwrap();
        let config = Config::parse(&format!(
            "[[projects]]\nid = \"demo\"\nrepo = {:?}\n",
            repo.path()
        ))
        .unwrap();
        let paths = Paths {
            config_dir: state.path().join("config"),
            state_dir: state.path().join("state"),
        };
        let mut store = Store::open_in_memory().unwrap();
        store
            .create_ticket(
                "human",
                NewTicket {
                    project_id: "demo".into(),
                    title: "Add a feature".into(),
                    ready: true,
                    ..Default::default()
                },
            )
            .unwrap();
        let serve = Serve::new(paths, store, FakeRex::default(), "/bin/rex-projects".into());
        Fixture {
            serve,
            config,
            _dirs: (repo, state),
        }
    }

    impl Fixture {
        fn tick(&mut self) {
            self.serve.tick(&self.config).unwrap();
        }
        fn agent(&self) -> Agent {
            self.serve
                .store
                .agent("demo-1-coordinator")
                .unwrap()
                .unwrap()
        }
        fn state(&self) -> TicketState {
            self.serve.store.ticket("demo-1").unwrap().unwrap().state
        }
        fn close_block(&mut self) {
            let block = self.agent().rex_block_id.unwrap();
            self.serve.rex.blocks.remove(&block).unwrap();
        }
        fn events(&self) -> usize {
            self.serve.store.events_since(0, 1000).unwrap().len()
        }
    }

    #[test]
    fn keeps_the_project_session_when_an_agent_renames_it() {
        let mut f = fixture();
        f.tick();
        let session = f.agent().rex_session_id.unwrap();
        let id = f.serve.rex.sessions.remove("rxp:demo").unwrap();
        f.serve.rex.sessions.insert("add-a-feature".into(), id);

        f.tick();
        assert_eq!(f.serve.rex.sessions.get("rxp:demo"), Some(&session));
        assert!(!f.serve.rex.sessions.contains_key("add-a-feature"));

        f.serve.rex.sessions.remove("rxp:demo");
        f.serve
            .rex
            .sessions
            .insert("renamed-again".into(), session.clone());
        f.close_block();
        f.tick();
        let resumed = f.agent();
        assert_eq!(resumed.launches, 2);
        assert_eq!(resumed.rex_session_id, Some(session.clone()));
        assert_eq!(f.serve.rex.sessions.len(), 1, "no second session");
    }

    #[test]
    fn dispatches_observes_and_resumes_until_the_limit() {
        let mut f = fixture();
        f.tick();
        assert_eq!(f.state(), TicketState::Running);
        let agent = f.agent();
        assert_eq!((agent.state.as_str(), agent.launches), ("running", 1));
        assert!(Path::new(&agent.cwd).join(".git").exists());
        let block = &f.serve.rex.blocks[agent.rex_block_id.as_ref().unwrap()];
        assert_eq!(block.window_label, "demo-1 Add a feature");
        assert_eq!(block.command[0], "/bin/rex-projects");
        assert_eq!(block.command[5..], ["agent", "exec", "demo-1-coordinator"]);
        assert_eq!(block.cwd, Path::new(&agent.cwd));
        assert_eq!(f.serve.rex.sessions["rxp:demo"], block.session_id);

        let block_id = agent.rex_block_id.clone().unwrap();
        f.serve.rex.blocks.get_mut(&block_id).unwrap().status = Some(Status {
            state: "working".into(),
            message: Some("editing".into()),
        });
        f.tick();
        assert_eq!(f.agent().activity.as_deref(), Some("working"));
        let events = f.events();
        f.tick();
        assert_eq!(f.events(), events, "unchanged activity is not recorded");

        for launches in 2..=4 {
            f.close_block();
            f.tick();
            let agent = f.agent();
            assert_eq!(
                (agent.state.as_str(), agent.launches),
                ("running", launches)
            );
            assert_ne!(agent.rex_block_id.as_ref(), Some(&block_id));
        }
        f.close_block();
        f.tick();
        assert_eq!(f.state(), TicketState::Failed);
        assert_eq!(f.agent().state, "exited");
        assert!(f.serve.rex.blocks.is_empty());
    }

    #[test]
    fn closes_abandoned_tickets_and_keeps_done_ones() {
        let mut f = fixture();
        f.tick();
        f.serve
            .store
            .append(
                "human",
                Event::TicketCancelled {
                    ticket_id: "demo-1".into(),
                    reason: "no".into(),
                },
            )
            .unwrap();
        f.tick();
        assert!(f.serve.rex.blocks.is_empty());
        assert_eq!(f.agent().state, "exited");

        let mut f = fixture();
        f.tick();
        f.serve
            .store
            .append(
                "demo-1-coordinator",
                Event::TicketCompleted {
                    ticket_id: "demo-1".into(),
                    outcome: Outcome::Delivered,
                    summary: "ok".into(),
                    artifacts: Vec::new(),
                },
            )
            .unwrap();
        f.tick();
        assert_eq!(
            f.serve.rex.blocks.len(),
            1,
            "a done Ticket's block stays open"
        );
        f.close_block();
        f.tick();
        assert_eq!(f.agent().state, "exited");
        assert!(
            f.serve.rex.blocks.is_empty(),
            "no relaunch for a done Ticket"
        );
    }

    #[test]
    fn fails_a_ticket_whose_launch_fails() {
        let mut f = fixture();
        f.serve.rex.fail_new_window = true;
        f.tick();
        assert_eq!(f.state(), TicketState::Failed);
        assert_eq!(f.agent().state, "exited");
        f.tick();
        assert_eq!(f.state(), TicketState::Failed);
    }
}
