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

const DEFAULT_COORDINATOR: &str = include_str!("roles/coordinator.md");

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
                    format!("mcp_servers.rex_projects.env={{{}}}", env.join(", ")),
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

/// The Agent's instructions: its Role, then the Ticket's Playbook if any.
pub fn role_text(
    paths: &Paths,
    project: &ProjectConfig,
    ticket: &Ticket,
    role: &str,
) -> Result<String> {
    let override_path = paths.config_dir.join("roles").join(format!("{role}.md"));
    let mut text = match std::fs::read_to_string(&override_path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound && role == "coordinator" => {
            DEFAULT_COORDINATOR.to_owned()
        }
        Err(err) => {
            return Err(err).with_context(|| format!("failed to read {}", override_path.display()));
        }
    };
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

pub fn initial_prompt(ticket: &Ticket) -> String {
    format!(
        "You are the Coordinator for Ticket {}: {}. Start by calling ticket_get.",
        ticket.id, ticket.title
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
        ("REXP_AGENT_ID", agent.id.clone()),
        ("REXP_AGENT_LAUNCH", agent.launches.to_string()),
        ("REXP_TICKET_ID", ticket.id.clone()),
        ("REXP_PROJECT_ID", agent.project_id.clone()),
        ("REXP_ROLE", agent.role.clone()),
        ("REXP_STATE_DIR", paths.state_dir.display().to_string()),
        ("REXP_CONFIG_DIR", paths.config_dir.display().to_string()),
    ]
    .map(|(k, v)| (k.to_owned(), v))
    .into();
    let role = role_text(paths, project, &ticket, &agent.role)?;
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
        Start::New { .. } => initial_prompt(&ticket),
        Start::Resume { .. } => resume_prompt(&ticket),
    };
    let argv = Harness {
        provider: &provider,
        model: project.coordinator.model.as_deref(),
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

    fn provider(kind: ProviderKind) -> ResolvedProvider {
        ResolvedProvider {
            name: "p".into(),
            kind,
            command: "harness".into(),
            args: vec!["--extra".into()],
        }
    }

    fn argv(kind: ProviderKind, start: Start<'_>) -> Vec<String> {
        let env = vec![
            ("REXP_AGENT_ID".to_owned(), "demo-1-coordinator".to_owned()),
            ("REXP_AGENT_LAUNCH".to_owned(), "2".to_owned()),
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
        assert_eq!(new[..4], ["harness", "--extra", "-m", "m1"]);
        assert_eq!(new.last().unwrap(), "Start.");
        let configs: Vec<&str> = new
            .windows(2)
            .filter(|w| w[0] == "-c")
            .map(|w| w[1].as_str())
            .collect();
        assert_eq!(configs.len(), 4);
        // Every override must parse as TOML, as Codex parses it.
        let parsed: toml::Table = toml::from_str(&configs.join("\n")).unwrap();
        assert_eq!(
            parsed["developer_instructions"].as_str(),
            Some("Be \"good\".\nLine two.")
        );
        let server = &parsed["mcp_servers"]["rex_projects"];
        assert_eq!(server["command"].as_str(), Some("/bin/rex-projects"));
        assert_eq!(server["args"][0].as_str(), Some("mcp"));
        assert_eq!(server["env"]["REXP_AGENT_LAUNCH"].as_str(), Some("2"));

        let resume = argv(ProviderKind::Codex, Start::Resume { session_id: "s9" });
        assert_eq!(resume[..5], ["harness", "--extra", "resume", "-m", "m1"]);
        assert_eq!(resume[resume.len() - 2..], ["s9", "Start."]);
    }

    #[test]
    fn writes_mcp_and_hook_settings() {
        let env = vec![("REXP_AGENT_LAUNCH".to_owned(), "1".to_owned())];
        let mcp = mcp_json(Path::new("/x/rex-projects"), &env);
        let server = &mcp["mcpServers"]["rex-projects"];
        assert_eq!(server["command"], "/x/rex-projects");
        assert_eq!(server["args"], json!(["mcp"]));
        assert_eq!(server["env"]["REXP_AGENT_LAUNCH"], "1");
        let settings = settings_json(Path::new("/a b/rex-projects"));
        assert_eq!(
            settings["hooks"]["SessionStart"][0]["hooks"][0]["command"],
            "'/a b/rex-projects' hook claude session-start"
        );
        assert_eq!(
            settings["hooks"]["UserPromptSubmit"][0]["hooks"][0]["command"],
            "'/a b/rex-projects' hook claude user-prompt-submit"
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
