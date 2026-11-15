//! The Rex operations rex-projects needs, through the `rex` CLI.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

const TERMINAL_FLAVOR: &str = "com.superlogical.terminal.shell";

/// A new window holding one terminal block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Window {
    pub window_id: String,
    pub block_id: String,
}

/// The root `program_status` record of a terminal block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    /// `idle`, `working`, `done`, `blocked`, or `error`.
    pub state: String,
    pub message: Option<String>,
}

pub trait Rex {
    /// Returns the Project's session: `known` if it still exists, else the
    /// session labelled `label`, else a new one. Agents sometimes rename
    /// their session, so the label of `known` is set back to `label`.
    fn ensure_session(&mut self, label: &str, known: Option<&str>) -> Result<String>;
    /// Opens a background window with one terminal block running `command`.
    fn new_window(
        &mut self,
        session_id: &str,
        label: &str,
        command: &[String],
        cwd: &Path,
    ) -> Result<Window>;
    /// Lists the block IDs of a session; empty if the session is gone.
    fn block_ids(&mut self, session_id: &str) -> Result<Vec<String>>;
    /// Returns the root `program_status` record, if the program reported one.
    fn program_status(&mut self, session_id: &str, block_id: &str) -> Result<Option<Status>>;
    fn close_block(&mut self, session_id: &str, block_id: &str) -> Result<()>;
}

/// Calls the Rex server through `rex api call`.
pub struct RexCli {
    bin: PathBuf,
}

impl RexCli {
    /// Uses `$REX_BIN_DIR/rex` when it exists, else `rex` from `PATH`.
    pub fn new() -> Self {
        let bin = std::env::var_os("REX_BIN_DIR")
            .map(|dir| PathBuf::from(dir).join("rex"))
            .filter(|path| path.is_file())
            .unwrap_or_else(|| PathBuf::from("rex"));
        Self { bin }
    }

    fn call(&self, method: &str, args: Value) -> Result<Value> {
        let output = Command::new(&self.bin)
            .args(["api", "call", method, &args.to_string()])
            .output()
            .with_context(|| format!("failed to run {}", self.bin.display()))?;
        if !output.status.success() {
            bail!(
                "rex api call {method} failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        serde_json::from_slice(&output.stdout)
            .with_context(|| format!("rex api call {method} returned invalid JSON"))
    }
}

impl Default for RexCli {
    fn default() -> Self {
        Self::new()
    }
}

fn string(value: &Value, pointer: &str) -> Result<String> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .with_context(|| format!("rex response has no {pointer}: {value}"))
}

impl Rex for RexCli {
    fn ensure_session(&mut self, label: &str, known: Option<&str>) -> Result<String> {
        let list = self.call("session.list", json!({}))?;
        let sessions = list["sessions"].as_array().cloned().unwrap_or_default();
        if let Some(known) = known
            && let Some(session) = sessions.iter().find(|s| s["session_id"] == known)
        {
            if session["label"] != label {
                self.call(
                    "session.set_label",
                    json!({ "session_id": known, "label": label }),
                )?;
            }
            return Ok(known.to_owned());
        }
        let found = sessions
            .iter()
            .find(|s| s["label"] == label)
            .and_then(|s| s["session_id"].as_str());
        if let Some(id) = found {
            return Ok(id.to_owned());
        }
        let created = self.call("session.create", json!({ "label": label }))?;
        string(&created, "/session_id")
    }

    fn new_window(
        &mut self,
        session_id: &str,
        label: &str,
        command: &[String],
        cwd: &Path,
    ) -> Result<Window> {
        let result = self.call(
            "session.new_window",
            json!({
                "session_id": session_id,
                "window_label": truncate(label, 128),
                "focus": false,
                "layout": { "block": {
                    "flavor": TERMINAL_FLAVOR,
                    "options": { "command": command, "cwd": cwd },
                }},
            }),
        )?;
        Ok(Window {
            window_id: string(&result, "/window_id")?,
            block_id: string(&result, "/block_ids/0")?,
        })
    }

    fn block_ids(&mut self, session_id: &str) -> Result<Vec<String>> {
        match self.call("session.list_blocks", json!({ "session_id": session_id })) {
            Ok(result) => Ok(result["blocks"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|b| b["block_id"].as_str().map(str::to_owned))
                .collect()),
            Err(err) if format!("{err:#}").contains("session_not_found") => Ok(Vec::new()),
            Err(err) => Err(err),
        }
    }

    fn program_status(&mut self, session_id: &str, block_id: &str) -> Result<Option<Status>> {
        let result = self.call(
            "block.method",
            json!({ "session_id": session_id, "block_id": block_id, "method": "program_status" }),
        )?;
        let root = result["records"]
            .as_array()
            .and_then(|records| records.iter().find(|r| r.get("id").is_none()));
        Ok(root.map(|r| Status {
            state: r["state"].as_str().unwrap_or("idle").to_owned(),
            message: r["msg"].as_str().map(str::to_owned),
        }))
    }

    fn close_block(&mut self, session_id: &str, block_id: &str) -> Result<()> {
        self.call(
            "block.close",
            json!({ "session_id": session_id, "block_id": block_id }),
        )?;
        Ok(())
    }
}

/// Shortens `text` to at most `max` characters.
pub fn truncate(text: &str, max: usize) -> String {
    text.chars().take(max).collect()
}

/// An in-memory Rex for tests.
#[cfg(test)]
pub mod fake {
    use std::collections::BTreeMap;

    use super::*;

    #[derive(Clone, Debug)]
    pub struct Block {
        pub session_id: String,
        pub window_label: String,
        pub command: Vec<String>,
        pub cwd: PathBuf,
        pub status: Option<Status>,
    }

    #[derive(Default)]
    pub struct FakeRex {
        /// Session label to ID.
        pub sessions: BTreeMap<String, String>,
        pub blocks: BTreeMap<String, Block>,
        pub fail_new_window: bool,
        next: u32,
    }

    impl FakeRex {
        fn id(&mut self, kind: &str) -> String {
            self.next += 1;
            format!("{kind}:{}", self.next)
        }
    }

    impl Rex for FakeRex {
        fn ensure_session(&mut self, label: &str, known: Option<&str>) -> Result<String> {
            let renamed = self
                .sessions
                .iter()
                .find(|(_, id)| Some(id.as_str()) == known)
                .map(|(old, id)| (old.clone(), id.clone()));
            if let Some((old, id)) = renamed {
                self.sessions.remove(&old);
                self.sessions.insert(label.to_owned(), id.clone());
                return Ok(id);
            }
            if let Some(id) = self.sessions.get(label) {
                return Ok(id.clone());
            }
            let id = self.id("session");
            self.sessions.insert(label.to_owned(), id.clone());
            Ok(id)
        }

        fn new_window(
            &mut self,
            session_id: &str,
            label: &str,
            command: &[String],
            cwd: &Path,
        ) -> Result<Window> {
            if self.fail_new_window {
                bail!("new_window failed");
            }
            let window_id = self.id("window");
            let block_id = self.id("block");
            self.blocks.insert(
                block_id.clone(),
                Block {
                    session_id: session_id.to_owned(),
                    window_label: truncate(label, 128),
                    command: command.to_vec(),
                    cwd: cwd.to_path_buf(),
                    status: None,
                },
            );
            Ok(Window {
                window_id,
                block_id,
            })
        }

        fn block_ids(&mut self, session_id: &str) -> Result<Vec<String>> {
            Ok(self
                .blocks
                .iter()
                .filter(|(_, b)| b.session_id == session_id)
                .map(|(id, _)| id.clone())
                .collect())
        }

        fn program_status(&mut self, _session_id: &str, block_id: &str) -> Result<Option<Status>> {
            Ok(self.blocks.get(block_id).and_then(|b| b.status.clone()))
        }

        fn close_block(&mut self, _session_id: &str, block_id: &str) -> Result<()> {
            self.blocks.remove(block_id);
            Ok(())
        }
    }
}
