//! `agent exec`: prepares an Agent's files and environment, then replaces
//! itself with the harness (Claude Code or Codex) inside its Rex block.

use std::io::BufRead;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};

use crate::config::{Config, ProjectConfig, ProviderKind, ResolvedProvider};
use crate::domain::{Agent, Event, Ticket};
use crate::paths::Paths;
use crate::store::Store;

/// The Roles rex-projects ships. `<config dir>/roles/<role>.md` overrides one,
/// or adds a new Role.
const BUILTIN_ROLES: [(&str, &str); 3] = [
    ("coordinator", include_str!("roles/coordinator.md")),
    ("worker", include_str!("roles/worker.md")),
    ("reviewer", include_str!("roles/reviewer.md")),
];

/// How a harness session starts.
#[derive(Clone, Copy, Debug)]
pub enum Start<'a> {
    /// A new conversation. Claude uses `session_id`; Codex picks its own.
    New {
        session_id: &'a str,
    },
    Resume {
        session_id: &'a str,
    },
}

/// Everything needed to build a harness command line.
pub struct Harness<'a> {
    pub provider: &'a ResolvedProvider,
    pub model: Option<&'a str>,
    pub agent_dir: &'a Path,
    pub exe: &'a Path,
    pub env: &'a [(String, String)],
    pub role: &'a str,
    pub start: Start<'a>,
    pub prompt: &'a str,
}

impl Harness<'_> {
    pub fn argv(&self) -> Vec<String> {
        let mut argv = vec![self.provider.command.clone()];
        argv.extend(self.provider.args.iter().cloned());
        let file = |name: &str| self.agent_dir.join(name).display().to_string();
        match self.provider.kind {
            ProviderKind::Claude => {
                if let Some(model) = self.model {
                    argv.extend(["--model".into(), model.into()]);
                }
                argv.extend([
                    "--append-system-prompt-file".into(),
                    file("role.md"),
                    "--mcp-config".into(),
                    file("mcp.json"),
                    "--settings".into(),
                    file("settings.json"),
                ]);
                match self.start {
                    Start::New { session_id } => {
                        argv.extend(["--session-id".into(), session_id.into(), self.prompt.into()])
                    }
                    Start::Resume { session_id } => {
                        argv.extend(["--resume".into(), session_id.into(), self.prompt.into()])
                    }
                }
            }
            ProviderKind::Codex => {
                if let Start::Resume { .. } = self.start {
                    argv.push("resume".into());
                }
                if let Some(model) = self.model {
                    argv.extend(["-m".into(), model.into()]);
                }
                // Codex runs only hooks a human has trusted. The rex-projects
                // hooks are passed below, and the human chose to run them
                // without that step (ADR-0003).
                argv.push("--dangerously-bypass-hook-trust".into());
                let hook = |event: &str, name: &str| {
                    let command = format!(
                        "{} hook codex {name}",
                        shell_quote(&self.exe.display().to_string())
                    );
                    format!(
                        "hooks.{event}=[{{hooks=[{{type=\"command\",command={}}}]}}]",
                        toml_string(&command)
                    )
                };
                let env: Vec<String> = self
                    .env
                    .iter()
                    .map(|(k, v)| format!("{k} = {}", toml_string(v)))
                    .collect();
                for config in [
                    format!("developer_instructions={}", toml_string(self.role)),
                    format!(
                        "mcp_servers.rex_projects.command={}",
                        toml_string(&self.exe.display().to_string())
                    ),
                    r#"mcp_servers.rex_projects.args=["mcp"]"#.to_owned(),
                    // Without this, an interactive Codex asks before every
                    // rex-projects tool call, and `-a never` refuses them.
                    r#"mcp_servers.rex_projects.default_tools_approval_mode="approve""#.to_owned(),
                    format!("mcp_servers.rex_projects.env={{{}}}", env.join(", ")),
                    hook("SessionStart", "session-start"),
                    hook("Stop", "stop"),
                    hook("UserPromptSubmit", "user-prompt-submit"),
                ] {
                    argv.extend(["-c".into(), config]);
                }
                match self.start {
                    Start::New { .. } => argv.push(self.prompt.into()),
                    Start::Resume { session_id } => {
                        argv.extend([session_id.into(), self.prompt.into()])
                    }
                }
            }
        }
        argv
    }
}

fn toml_string(text: &str) -> String {
    toml::Value::String(text.to_owned()).to_string()
}

/// Claude's `--mcp-config` file.
pub fn mcp_json(exe: &Path, env: &[(String, String)]) -> Value {
    let env: serde_json::Map<String, Value> = env
        .iter()
        .map(|(k, v)| (k.clone(), Value::String(v.clone())))
        .collect();
    json!({ "mcpServers": { "rex-projects": {
        "command": exe, "args": ["mcp"], "env": env,
    }}})
}

/// Claude's `--settings` file, registering the rex-projects hooks.
pub fn settings_json(exe: &Path) -> Value {
    let hook = |name: &str| {
        json!([{ "hooks": [{
            "type": "command",
            "command": format!("{} hook claude {name}", shell_quote(&exe.display().to_string())),
        }]}])
    };
    json!({ "hooks": {
        "SessionStart": hook("session-start"),
        "UserPromptSubmit": hook("user-prompt-submit"),
        "Stop": hook("stop"),
    }})
}

fn shell_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', r"'\''"))
}

/// Removes a leading YAML frontmatter block.
pub fn strip_frontmatter(text: &str) -> &str {
    let Some(rest) = text
        .strip_prefix("---\n")
        .or_else(|| text.strip_prefix("---\r\n"))
    else {
        return text;
    };
    let mut offset = 0;
    for line in rest.split_inclusive('\n') {
        offset += line.len();
        if line.trim_end() == "---" {
            return rest[offset..].trim_start_matches(['\n', '\r']);
        }
    }
    text
}

/// The instructions of `role`: the override in the config directory, else
/// the built-in text.
pub fn role_base_text(paths: &Paths, role: &str) -> Result<String> {
    let override_path = paths.config_dir.join("roles").join(format!("{role}.md"));
    match std::fs::read_to_string(&override_path) {
        Ok(text) => Ok(text),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => BUILTIN_ROLES
            .iter()
            .find(|(name, _)| *name == role)
            .map(|(_, text)| (*text).to_owned())
            .with_context(|| {
                format!(
                    "role {role:?} is not built in and {} does not exist",
                    override_path.display()
                )
            }),
        Err(err) => Err(err).with_context(|| format!("failed to read {}", override_path.display())),
    }
}

/// The Agent's instructions: its Role, then, for the Coordinator, the
/// Ticket's Playbook if any.
pub fn role_text(
    paths: &Paths,
    project: &ProjectConfig,
    ticket: &Ticket,
    role: &str,
) -> Result<String> {
    let mut text = role_base_text(paths, role)?;
    if role != "coordinator" {
        return Ok(text);
    }
    let playbook = ticket
        .playbook
        .as_ref()
        .or(project.default_playbook.as_ref());
    if let Some(name) = playbook {
        let candidates = [
            project.repo.join(".rex-projects/playbooks"),
            paths.config_dir.join("playbooks"),
        ]
        .map(|dir| dir.join(name).join("SKILL.md"));
        let path = candidates
            .iter()
            .find(|p| p.is_file())
            .with_context(|| format!("playbook {name:?} not found in {candidates:?}"))?;
        let body = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        text = format!(
            "{}\n\n# Playbook: {name}\n\n{}",
            text.trim_end(),
            strip_frontmatter(&body)
        );
    }
    Ok(text)
}

/// Builds a Role prompt from the dispatch snapshot when one exists. Legacy
/// Tickets dispatched before snapshots retain the previous live-file behavior.
pub fn role_text_with_store(
    paths: &Paths,
    project: &ProjectConfig,
    ticket: &Ticket,
    role: &str,
    store: &Store,
) -> Result<String> {
    let mut text = role_base_text(paths, role)?;
    if role != "coordinator" {
        return Ok(text);
    }
    match store.preparation(&ticket.id)? {
        Some(preparation) => {
            if let Some(playbook) = preparation.playbook {
                text = format!(
                    "{}\n\n# Playbook: {}\n\n{}",
                    text.trim_end(),
                    playbook.name,
                    playbook.body
                );
            }
            Ok(text)
        }
        None => role_text(paths, project, ticket, role),
    }
}

pub fn initial_prompt(ticket: &Ticket) -> String {
    format!(
        "You are the Coordinator for Ticket {}: {}. Start by calling ticket_get.",
        ticket.id, ticket.title
    )
}

/// A helper's first prompt carries the task its Coordinator gave it.
pub fn helper_prompt(agent: &Agent, ticket: &Ticket, task: &str) -> String {
    format!(
        "You are {}, the {} for Ticket {}: {}. Your task from the Coordinator:\n\n{task}\n\n\
         Call ticket_get if you need the Ticket's Brief. When you are finished, call done.",
        agent.id, agent.role, ticket.id, ticket.title
    )
}

/// A resumed harness restores the conversation but waits for input, so a
/// relaunch tells the Coordinator to pick the work back up.
pub fn resume_prompt(ticket: &Ticket) -> String {
    format!(
        "rex-projects restarted you after your pane closed. Call ticket_get, check the \
         worktree for work already done, and continue Ticket {} from where you left off.",
        ticket.id
    )
}

/// Waits until `serve` has recorded the launch of the block this process runs
/// in (`REX_BLOCK`), so that `launches` is this launch's generation.
fn wait_for_launch(store: &Store, agent_id: &str) -> Result<Agent> {
    let block = std::env::var("REX_BLOCK").ok().filter(|b| !b.is_empty());
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let agent = store
            .agent(agent_id)?
            .with_context(|| format!("agent {agent_id} does not exist"))?;
        if block.is_none() || agent.rex_block_id == block {
            return Ok(agent);
        }
        if Instant::now() > deadline {
            bail!("agent {agent_id} was not launched in this block");
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Runs the Agent's harness in place of this process. Returns only on error.
pub fn exec(paths: &Paths, agent_id: &str) -> Result<()> {
    let config = Config::load(&paths.config_file())?;
    let mut store = Store::open(&paths.db_file())?;
    let agent = wait_for_launch(&store, agent_id)?;
    let ticket = store
        .ticket(&agent.ticket_id)?
        .with_context(|| format!("ticket {} does not exist", agent.ticket_id))?;
    let project = config.project(&agent.project_id)?;
    let provider = config.provider(&agent.provider)?;
    let exe = std::env::current_exe().context("failed to locate rex-projects")?;
    let dir = paths.agent_dir(agent_id);
    std::fs::create_dir_all(&dir).with_context(|| format!("failed to create {}", dir.display()))?;

    let env: Vec<(String, String)> = [
        ("REX_PROJECTS_AGENT_ID", agent.id.clone()),
        ("REX_PROJECTS_AGENT_LAUNCH", agent.launches.to_string()),
        ("REX_PROJECTS_TICKET_ID", ticket.id.clone()),
        ("REX_PROJECTS_PROJECT_ID", agent.project_id.clone()),
        ("REX_PROJECTS_ROLE", agent.role.clone()),
        (
            "REX_PROJECTS_STATE_DIR",
            paths.state_dir.display().to_string(),
        ),
        (
            "REX_PROJECTS_CONFIG_DIR",
            paths.config_dir.display().to_string(),
        ),
    ]
    .map(|(k, v)| (k.to_owned(), v))
    .into();
    let role = role_text_with_store(paths, project, &ticket, &agent.role, &store)?;
    let write = |name: &str, text: String| {
        let path = dir.join(name);
        std::fs::write(&path, text).with_context(|| format!("failed to write {}", path.display()))
    };
    write("role.md", role.clone())?;
    write(
        "mcp.json",
        serde_json::to_string_pretty(&mcp_json(&exe, &env))?,
    )?;
    write(
        "settings.json",
        serde_json::to_string_pretty(&settings_json(&exe))?,
    )?;

    let new_id = uuid::Uuid::new_v4().to_string();
    let start = match &agent.harness_session_id {
        Some(id) => Start::Resume { session_id: id },
        None => Start::New {
            session_id: &new_id,
        },
    };
    let prompt = match start {
        Start::New { .. } if agent.role != "coordinator" => {
            // The task waits in the helper's inbox; take it into the prompt.
            let (messages, _) = crate::inbox::take(&mut store, agent_id)?;
            let task: Vec<&str> = messages.iter().map(|m| m.body.as_str()).collect();
            helper_prompt(&agent, &ticket, &task.join("\n\n"))
        }
        Start::New { .. } => initial_prompt(&ticket),
        Start::Resume { .. } => resume_prompt(&ticket),
    };
    // A model belongs to a provider, so a helper started on another provider
    // than its Role's uses that provider's default model.
    let spec = project.agent_spec(&agent.role);
    let model = (spec.provider == agent.provider)
        .then_some(spec.model)
        .flatten();
    let argv = Harness {
        provider: &provider,
        model: model.as_deref(),
        agent_dir: &dir,
        exe: &exe,
        env: &env,
        role: &role,
        start,
        prompt: &prompt,
    }
    .argv();
    if let (ProviderKind::Claude, Start::New { session_id }) = (provider.kind, start) {
        store.append(
            agent_id,
            Event::AgentSessionBound {
                agent_id: agent_id.to_owned(),
                harness_session_id: session_id.to_owned(),
            },
        )?;
    }
    write("launched_at", Utc::now().to_rfc3339())?;

    let err = Command::new(&argv[0])
        .args(&argv[1..])
        .envs(env)
        .current_dir(&agent.cwd)
        .exec();
    Err(err).with_context(|| format!("failed to run {}", argv[0]))
}

/// When the Agent's harness was last started, as written by `exec`.
pub fn launched_at(agent_dir: &Path) -> Option<DateTime<Utc>> {
    let text = std::fs::read_to_string(agent_dir.join("launched_at")).ok()?;
    DateTime::parse_from_rfc3339(text.trim())
        .ok()
        .map(|t| t.with_timezone(&Utc))
}

/// Codex keeps its rollouts in `$CODEX_HOME/sessions`.
pub fn codex_sessions_dir() -> Option<PathBuf> {
    match std::env::var_os("CODEX_HOME").filter(|v| !v.is_empty()) {
        Some(home) => Some(PathBuf::from(home).join("sessions")),
        None => std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".codex/sessions")),
    }
}

/// Finds the newest top-level Codex session started in `cwd` after `after`.
/// Reads only the first line (`session_meta`) of recently modified rollouts.
pub fn find_codex_session(dir: &Path, cwd: &Path, after: DateTime<Utc>) -> Option<String> {
    let cwd = std::fs::canonicalize(cwd).unwrap_or_else(|_| cwd.to_path_buf());
    let mut best: Option<(DateTime<Utc>, String)> = None;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = entry.metadata() else { continue };
            if meta.is_dir() {
                stack.push(path);
                continue;
            }
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let recent = meta
                .modified()
                .is_ok_and(|m| DateTime::<Utc>::from(m) >= after - chrono::Duration::minutes(1));
            if !recent || !name.starts_with("rollout-") || !name.ends_with(".jsonl") {
                continue;
            }
            let Some((at, id)) = session_meta(&path, &cwd) else {
                continue;
            };
            if at >= after && best.as_ref().is_none_or(|(t, _)| at > *t) {
                best = Some((at, id));
            }
        }
    }
    best.map(|(_, id)| id)
}

fn session_meta(path: &Path, cwd: &Path) -> Option<(DateTime<Utc>, String)> {
    let mut line = String::new();
    std::io::BufReader::new(std::fs::File::open(path).ok()?)
        .read_line(&mut line)
        .ok()?;
    let value: Value = serde_json::from_str(&line).ok()?;
    let payload = &value["payload"];
    // Subagent threads share the cwd but name their parent.
    if value["type"] != "session_meta" || payload.get("parent_thread_id").is_some() {
        return None;
    }
    let session_cwd = PathBuf::from(payload["cwd"].as_str()?);
    let session_cwd = std::fs::canonicalize(&session_cwd).unwrap_or(session_cwd);
    if session_cwd != cwd {
        return None;
    }
    let at = DateTime::parse_from_rfc3339(payload["timestamp"].as_str()?).ok()?;
    Some((at.with_timezone(&Utc), payload["id"].as_str()?.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::NewTicket;

    fn provider(kind: ProviderKind) -> ResolvedProvider {
        ResolvedProvider {
            name: "p".into(),
            kind,
            command: "harness".into(),
            args: vec!["--extra".into()],
        }
    }

    #[test]
    fn coordinator_resume_uses_the_dispatch_snapshot_after_playbook_edit() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(repo.join(".rex-projects/playbooks/feature")).unwrap();
        let file = repo.join(".rex-projects/playbooks/feature/SKILL.md");
        std::fs::write(
            &file,
            "---\nname: feature\nrex-projects:\n  roles: [worker]\n---\nnew body\n",
        )
        .unwrap();
        let paths = Paths {
            config_dir: dir.path().join("config"),
            state_dir: dir.path().join("state"),
        };
        let project =
            crate::config::Config::parse(&format!("[[projects]]\nid='demo'\nrepo={:?}\n", repo))
                .unwrap()
                .projects
                .remove(0);
        let mut store = Store::open_in_memory().unwrap();
        let ticket = store
            .create_ticket(
                "human",
                NewTicket {
                    project_id: "demo".into(),
                    title: "T".into(),
                    ready: true,
                    playbook: Some("feature".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        store
            .append(
                "serve",
                Event::AgentCreated {
                    agent_id: "demo-1-coordinator".into(),
                    ticket_id: ticket.id.clone(),
                    project_id: "demo".into(),
                    role: "coordinator".into(),
                    provider: "claude".into(),
                    cwd: repo.display().to_string(),
                },
            )
            .unwrap();
        store
            .append(
                "serve",
                Event::TicketDispatched {
                    ticket_id: ticket.id.clone(),
                    agent_id: "demo-1-coordinator".into(),
                },
            )
            .unwrap();
        let snapshot =
            crate::playbook::resolve_for_ticket(&paths, &project, ticket.playbook.as_deref())
                .unwrap()
                .unwrap();
        store
            .append(
                "serve",
                Event::TicketPrepared {
                    ticket_id: ticket.id.clone(),
                    base_commit: "abc123".into(),
                    playbook: Some(snapshot),
                },
            )
            .unwrap();
        std::fs::write(
            &file,
            "---\nname: feature\nrex-projects:\n  roles: [reviewer]\n---\nchanged body\n",
        )
        .unwrap();
        let ticket = store.ticket(&ticket.id).unwrap().unwrap();
        let role = role_text_with_store(&paths, &project, &ticket, "coordinator", &store).unwrap();
        assert!(role.contains("new body"));
        assert!(!role.contains("changed body"));
    }

    #[test]
    fn replayed_pre_snapshot_dispatch_keeps_legacy_playbook_loading() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(repo.join(".rex-projects/playbooks/feature")).unwrap();
        std::fs::write(
            repo.join(".rex-projects/playbooks/feature/SKILL.md"),
            "---\nname: feature\n---\nlegacy instructions\n",
        )
        .unwrap();
        let paths = Paths {
            config_dir: dir.path().join("config"),
            state_dir: dir.path().join("state"),
        };
        let project =
            crate::config::Config::parse(&format!("[[projects]]\nid='demo'\nrepo={:?}\n", repo))
                .unwrap()
                .projects
                .remove(0);
        let mut store = Store::open_in_memory().unwrap();
        let ticket = store
            .create_ticket(
                "human",
                NewTicket {
                    project_id: "demo".into(),
                    title: "T".into(),
                    ready: true,
                    playbook: Some("feature".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        store
            .append(
                "serve",
                Event::AgentCreated {
                    agent_id: "demo-1-coordinator".into(),
                    ticket_id: ticket.id.clone(),
                    project_id: "demo".into(),
                    role: "coordinator".into(),
                    provider: "claude".into(),
                    cwd: repo.display().to_string(),
                },
            )
            .unwrap();
        store
            .append(
                "serve",
                Event::TicketDispatched {
                    ticket_id: ticket.id.clone(),
                    agent_id: "demo-1-coordinator".into(),
                },
            )
            .unwrap();

        // This is the complete dispatch history written before TicketPrepared existed.
        store.rebuild().unwrap();
        assert!(store.preparation(&ticket.id).unwrap().is_none());
        let ticket = store.ticket(&ticket.id).unwrap().unwrap();
        let role = role_text_with_store(&paths, &project, &ticket, "coordinator", &store).unwrap();
        assert!(role.contains("legacy instructions"));
    }

    fn argv(kind: ProviderKind, start: Start<'_>) -> Vec<String> {
        let env = vec![
            (
                "REX_PROJECTS_AGENT_ID".to_owned(),
                "demo-1-coordinator".to_owned(),
            ),
            ("REX_PROJECTS_AGENT_LAUNCH".to_owned(), "2".to_owned()),
        ];
        Harness {
            provider: &provider(kind),
            model: Some("m1"),
            agent_dir: Path::new("/s/agents/a"),
            exe: Path::new("/bin/rex-projects"),
            env: &env,
            role: "Be \"good\".\nLine two.",
            start,
            prompt: "Start.",
        }
        .argv()
    }

    #[test]
    fn builds_claude_argv() {
        let common = [
            "harness",
            "--extra",
            "--model",
            "m1",
            "--append-system-prompt-file",
            "/s/agents/a/role.md",
            "--mcp-config",
            "/s/agents/a/mcp.json",
            "--settings",
            "/s/agents/a/settings.json",
        ];
        let new = argv(ProviderKind::Claude, Start::New { session_id: "u1" });
        assert_eq!(new[..10], common);
        assert_eq!(new[10..], ["--session-id", "u1", "Start."]);
        let resume = argv(ProviderKind::Claude, Start::Resume { session_id: "u1" });
        assert_eq!(resume[..10], common);
        assert_eq!(resume[10..], ["--resume", "u1", "Start."]);
    }

    #[test]
    fn builds_codex_argv() {
        let new = argv(ProviderKind::Codex, Start::New { session_id: "u1" });
        assert_eq!(
            new[..5],
            [
                "harness",
                "--extra",
                "-m",
                "m1",
                "--dangerously-bypass-hook-trust"
            ]
        );
        assert_eq!(new.last().unwrap(), "Start.");
        let configs: Vec<&str> = new
            .windows(2)
            .filter(|w| w[0] == "-c")
            .map(|w| w[1].as_str())
            .collect();
        assert_eq!(configs.len(), 8);
        // Every override must parse as TOML, as Codex parses it.
        let parsed: toml::Table = toml::from_str(&configs.join("\n")).unwrap();
        assert_eq!(
            parsed["developer_instructions"].as_str(),
            Some("Be \"good\".\nLine two.")
        );
        let server = &parsed["mcp_servers"]["rex_projects"];
        assert_eq!(server["command"].as_str(), Some("/bin/rex-projects"));
        assert_eq!(server["args"][0].as_str(), Some("mcp"));
        assert_eq!(
            server["default_tools_approval_mode"].as_str(),
            Some("approve")
        );
        assert_eq!(
            server["env"]["REX_PROJECTS_AGENT_LAUNCH"].as_str(),
            Some("2")
        );

        let stop = &parsed["hooks"]["Stop"][0]["hooks"][0];
        assert_eq!(stop["type"].as_str(), Some("command"));
        assert_eq!(
            stop["command"].as_str(),
            Some("'/bin/rex-projects' hook codex stop")
        );
        assert_eq!(
            parsed["hooks"]["UserPromptSubmit"][0]["hooks"][0]["command"].as_str(),
            Some("'/bin/rex-projects' hook codex user-prompt-submit")
        );
        assert_eq!(
            parsed["hooks"]["SessionStart"][0]["hooks"][0]["command"].as_str(),
            Some("'/bin/rex-projects' hook codex session-start")
        );

        let resume = argv(ProviderKind::Codex, Start::Resume { session_id: "s9" });
        assert_eq!(resume[..5], ["harness", "--extra", "resume", "-m", "m1"]);
        assert_eq!(resume[resume.len() - 2..], ["s9", "Start."]);
    }

    #[test]
    fn writes_mcp_and_hook_settings() {
        let env = vec![("REX_PROJECTS_AGENT_LAUNCH".to_owned(), "1".to_owned())];
        let mcp = mcp_json(Path::new("/x/rex-projects"), &env);
        let server = &mcp["mcpServers"]["rex-projects"];
        assert_eq!(server["command"], "/x/rex-projects");
        assert_eq!(server["args"], json!(["mcp"]));
        assert_eq!(server["env"]["REX_PROJECTS_AGENT_LAUNCH"], "1");
        let settings = settings_json(Path::new("/a b/rex-projects"));
        assert_eq!(
            settings["hooks"]["SessionStart"][0]["hooks"][0]["command"],
            "'/a b/rex-projects' hook claude session-start"
        );
        assert_eq!(
            settings["hooks"]["UserPromptSubmit"][0]["hooks"][0]["command"],
            "'/a b/rex-projects' hook claude user-prompt-submit"
        );
        assert_eq!(
            settings["hooks"]["Stop"][0]["hooks"][0]["command"],
            "'/a b/rex-projects' hook claude stop"
        );
    }

    #[test]
    fn strips_frontmatter() {
        let text = "---\nname: x\nrex-projects:\n  stages: [a]\n---\n\n# Body\n";
        assert_eq!(strip_frontmatter(text), "# Body\n");
        assert_eq!(
            strip_frontmatter("# No frontmatter\n"),
            "# No frontmatter\n"
        );
        assert_eq!(strip_frontmatter("---\nunclosed\n"), "---\nunclosed\n");
    }

    #[test]
    fn finds_the_newest_codex_session_for_a_cwd() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = tempfile::tempdir().unwrap();
        let day = dir.path().join("2026/11/15");
        std::fs::create_dir_all(&day).unwrap();
        let meta = |id: &str, at: &str, cwd: &Path, parent: bool| {
            let mut payload = json!({ "id": id, "timestamp": at, "cwd": cwd });
            if parent {
                payload["parent_thread_id"] = json!("p");
            }
            format!(
                "{}\n{{\"type\":\"other\"}}\n",
                json!({ "type": "session_meta", "payload": payload })
            )
        };
        let write = |name: &str, text: String| {
            std::fs::write(day.join(format!("rollout-{name}.jsonl")), text).unwrap()
        };
        let now = Utc::now();
        let at = |minutes: i64| (now + chrono::Duration::minutes(minutes)).to_rfc3339();
        write("old", meta("old", &at(-120), cwd.path(), false));
        write("new", meta("new", &at(-30), cwd.path(), false));
        write("sub", meta("sub", &at(-10), cwd.path(), true));
        write("else", meta("else", &at(-5), dir.path(), false));
        let after = now - chrono::Duration::minutes(60);
        assert_eq!(
            find_codex_session(dir.path(), cwd.path(), after).as_deref(),
            Some("new")
        );
        let later = now + chrono::Duration::minutes(60);
        assert_eq!(find_codex_session(dir.path(), cwd.path(), later), None);
    }
}
