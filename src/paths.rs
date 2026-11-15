use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Where rex-projects reads shared configuration and keeps runtime state.
#[derive(Clone, Debug)]
pub struct Paths {
    pub config_dir: PathBuf,
    pub state_dir: PathBuf,
}

impl Paths {
    /// Resolves directories from explicit values, then `XDG_CONFIG_HOME` /
    /// `XDG_STATE_HOME`, then `~/.config` / `~/.local/state`.
    pub fn resolve(config_dir: Option<PathBuf>, state_dir: Option<PathBuf>) -> Result<Self> {
        let home = || {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .context("HOME is not set")
        };
        let config_dir = match config_dir {
            Some(dir) => dir,
            None => match std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
                Some(dir) => PathBuf::from(dir).join("rex-projects"),
                None => home()?.join(".config/rex-projects"),
            },
        };
        let state_dir = match state_dir {
            Some(dir) => dir,
            None => match std::env::var_os("XDG_STATE_HOME").filter(|v| !v.is_empty()) {
                Some(dir) => PathBuf::from(dir).join("rex-projects"),
                None => home()?.join(".local/state/rex-projects"),
            },
        };
        Ok(Self {
            config_dir,
            state_dir,
        })
    }

    pub fn config_file(&self) -> PathBuf {
        self.config_dir.join("config.toml")
    }

    pub fn db_file(&self) -> PathBuf {
        self.state_dir.join("state.db")
    }

    pub fn agent_dir(&self, agent_id: &str) -> PathBuf {
        self.state_dir.join("agents").join(agent_id)
    }

    pub fn worktree_dir(&self, project_id: &str, ticket_id: &str) -> PathBuf {
        self.state_dir
            .join("worktrees")
            .join(project_id)
            .join(ticket_id)
    }
}

/// Expands a leading `~/` with `HOME`.
pub fn expand_home(path: &Path) -> PathBuf {
    match (path.strip_prefix("~"), std::env::var_os("HOME")) {
        (Ok(rest), Some(home)) => PathBuf::from(home).join(rest),
        _ => path.to_path_buf(),
    }
}
