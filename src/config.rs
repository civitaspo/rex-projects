use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::paths::expand_home;

/// The shared configuration in `config.toml`.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub providers: BTreeMap<String, ProviderConfig>,
    #[serde(default)]
    pub projects: Vec<ProjectConfig>,
    /// External tracker adapters, keyed by name. Each value is interpreted by
    /// the tracker module.
    #[serde(default)]
    pub trackers: BTreeMap<String, toml::Table>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    #[serde(default = "default_max_running_tickets")]
    pub max_running_tickets: u32,
    #[serde(default = "default_max_agents")]
    pub max_agents: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_running_tickets: default_max_running_tickets(),
            max_agents: default_max_agents(),
        }
    }
}

fn default_max_running_tickets() -> u32 {
    4
}

fn default_max_agents() -> u32 {
    10
}

/// The kinds of coding Agent harnesses rex-projects knows how to drive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    Claude,
    Codex,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfig {
    /// Which harness this entry drives. Defaults to the entry's key.
    pub kind: Option<ProviderKind>,
    /// The executable to run. Defaults to `claude` or `codex`.
    pub command: Option<String>,
    /// Extra arguments placed before rex-projects' own arguments.
    #[serde(default)]
    pub args: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectConfig {
    pub id: String,
    pub repo: PathBuf,
    pub goal: Option<String>,
    pub default_playbook: Option<String>,
    pub max_running_tickets: Option<u32>,
    /// The branch new Ticket worktrees start from. Defaults to the
    /// repository's current `HEAD`.
    pub base_branch: Option<String>,
    #[serde(default)]
    pub coordinator: AgentSpec,
    pub tracker: Option<ProjectTracker>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSpec {
    #[serde(default = "default_provider")]
    pub provider: String,
    pub model: Option<String>,
}

impl Default for AgentSpec {
    fn default() -> Self {
        Self {
            provider: default_provider(),
            model: None,
        }
    }
}

fn default_provider() -> String {
    "claude".to_owned()
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectTracker {
    pub name: String,
    #[serde(default)]
    pub vars: BTreeMap<String, String>,
}

/// A provider entry with its defaults filled in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedProvider {
    pub name: String,
    pub kind: ProviderKind,
    pub command: String,
    pub args: Vec<String>,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                bail!("configuration file {} does not exist", path.display())
            }
            Err(err) => {
                return Err(err).with_context(|| format!("failed to read {}", path.display()));
            }
        };
        Self::parse(&text).with_context(|| format!("invalid configuration in {}", path.display()))
    }

    pub fn parse(text: &str) -> Result<Self> {
        let mut config: Config = toml::from_str(text)?;
        for project in &mut config.projects {
            project.repo = expand_home(&project.repo);
        }
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        let mut ids = BTreeSet::new();
        for project in &self.projects {
            validate_id(&project.id).with_context(|| format!("project id {:?}", project.id))?;
            if !ids.insert(project.id.as_str()) {
                bail!("project id {:?} is defined more than once", project.id);
            }
            self.provider(&project.coordinator.provider)
                .with_context(|| format!("project {:?} coordinator", project.id))?;
            if let Some(tracker) = &project.tracker
                && !self.trackers.contains_key(&tracker.name)
            {
                bail!(
                    "project {:?} uses tracker {:?}, which is not defined under [trackers]",
                    project.id,
                    tracker.name
                );
            }
        }
        for name in self.providers.keys() {
            self.provider(name)?;
        }
        crate::tracker::Trackers::from_config(self)?;
        Ok(())
    }

    pub fn project(&self, id: &str) -> Result<&ProjectConfig> {
        self.projects
            .iter()
            .find(|p| p.id == id)
            .with_context(|| format!("project {id:?} is not configured"))
    }

    /// Returns the provider named `name`, applying defaults. `claude` and
    /// `codex` are available without configuration.
    pub fn provider(&self, name: &str) -> Result<ResolvedProvider> {
        let entry = self.providers.get(name);
        let kind = match entry.and_then(|e| e.kind) {
            Some(kind) => kind,
            None => match name {
                "claude" => ProviderKind::Claude,
                "codex" => ProviderKind::Codex,
                _ => bail!("provider {name:?} needs `kind = \"claude\"` or `kind = \"codex\"`"),
            },
        };
        let default_command = match kind {
            ProviderKind::Claude => "claude",
            ProviderKind::Codex => "codex",
        };
        Ok(ResolvedProvider {
            name: name.to_owned(),
            kind,
            command: entry
                .and_then(|e| e.command.clone())
                .unwrap_or_else(|| default_command.to_owned()),
            args: entry.map(|e| e.args.clone()).unwrap_or_default(),
        })
    }
}

/// Project ids appear in Ticket ids, branch names, and Rex labels, so they are
/// limited to lowercase letters, digits, and hyphens.
pub fn validate_id(id: &str) -> Result<()> {
    let valid = !id.is_empty()
        && id.len() <= 48
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !id.starts_with('-')
        && !id.ends_with('-');
    if !valid {
        bail!("must be 1-48 lowercase letters, digits, or inner hyphens");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_project() {
        let config = Config::parse(
            r#"
            [[projects]]
            id = "demo"
            repo = "/tmp/demo"
            "#,
        )
        .unwrap();
        assert_eq!(config.limits.max_running_tickets, 4);
        let project = config.project("demo").unwrap();
        assert_eq!(project.coordinator.provider, "claude");
        assert_eq!(
            config.provider("claude").unwrap().kind,
            ProviderKind::Claude
        );
    }

    #[test]
    fn rejects_duplicate_projects_and_bad_ids() {
        let dup = r#"
            [[projects]]
            id = "a"
            repo = "/a"
            [[projects]]
            id = "a"
            repo = "/b"
        "#;
        assert!(Config::parse(dup).is_err());
        let bad = r#"
            [[projects]]
            id = "Bad_Id"
            repo = "/a"
        "#;
        assert!(Config::parse(bad).is_err());
    }

    #[test]
    fn rejects_unknown_provider_and_tracker() {
        let provider = r#"
            [[projects]]
            id = "a"
            repo = "/a"
            coordinator = { provider = "gemini" }
        "#;
        assert!(Config::parse(provider).is_err());
        let tracker = r#"
            [[projects]]
            id = "a"
            repo = "/a"
            tracker = { name = "missing" }
        "#;
        assert!(Config::parse(tracker).is_err());
    }

    #[test]
    fn custom_provider_needs_kind() {
        let config = Config::parse(
            r#"
            [providers.fast]
            kind = "codex"
            args = ["--no-daemon"]
            "#,
        )
        .unwrap();
        let fast = config.provider("fast").unwrap();
        assert_eq!(fast.kind, ProviderKind::Codex);
        assert_eq!(fast.command, "codex");
        assert_eq!(fast.args, vec!["--no-daemon"]);
    }
}
