//! The Rex operations rex-projects needs, through the `rex` CLI.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

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
    /// Splits `anchor_block` without taking focus and runs `command` in the new
    /// block: beside it when `beside`, else below it. Returns the new block.
    fn split(
        &mut self,
        session_id: &str,
        anchor_block: &str,
        beside: bool,
        command: &[String],
        cwd: &Path,
    ) -> Result<String>;
    /// Lists the block IDs of a session; empty if the session is gone.
    fn block_ids(&mut self, session_id: &str) -> Result<Vec<String>>;
    /// Returns the root `program_status` record, if the program reported one.
    fn program_status(&mut self, session_id: &str, block_id: &str) -> Result<Option<Status>>;
    fn close_block(&mut self, session_id: &str, block_id: &str) -> Result<()>;
    /// Destroys a session and every block left in it.
    fn destroy_session(&mut self, session_id: &str) -> Result<()>;
    /// Whether the input line under the terminal's cursor holds no typed text:
    /// nothing but a prompt mark, such as `❯` or `›`, before the cursor.
    fn input_is_empty(&mut self, session_id: &str, block_id: &str) -> Result<bool>;
    /// Types `text` into the block's program and presses Return.
    fn submit(&mut self, session_id: &str, block_id: &str, text: &str) -> Result<()>;
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

    fn run(&self, args: &[&str], stdin: &str) -> Result<()> {
        let mut child = Command::new(&self.bin)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("failed to run {}", self.bin.display()))?;
        child
            .stdin
            .take()
            .context("rex has no stdin")?
            .write_all(stdin.as_bytes())?;
        let output = child.wait_with_output()?;
        if !output.status.success() {
            bail!(
                "rex {} failed: {}",
                args[0],
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(())
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

    fn split(
        &mut self,
        session_id: &str,
        anchor_block: &str,
        beside: bool,
        command: &[String],
        cwd: &Path,
    ) -> Result<String> {
        let result = self.call(
            "session.new_split",
            json!({
                "session_id": session_id,
                "anchor_id": anchor_block,
                "direction": if beside { "horizontal" } else { "vertical" },
                "side": "after",
                "focus": false,
                "layout": { "block": {
                    "flavor": TERMINAL_FLAVOR,
                    "options": { "command": command, "cwd": cwd },
                }},
            }),
        )?;
        string(&result, "/block_ids/0")
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

    fn destroy_session(&mut self, session_id: &str) -> Result<()> {
        self.call("session.destroy", json!({ "session_id": session_id }))?;
        Ok(())
    }

    fn input_is_empty(&mut self, session_id: &str, block_id: &str) -> Result<bool> {
        let call = |method: &str, args: Value| {
            self.call(
                &format!("com.superlogical.terminal.{method}"),
                json!({ "session_id": session_id, "block_id": block_id, "args": args }),
            )
        };
        let rows = call("size", json!({}))?["rows"]
            .as_u64()
            .context("terminal size has no rows")? as usize;
        let vt = call("format", json!({ "format": "vt", "extra_cursor": true }))?;
        let text = call("format", json!({ "format": "text" }))?;
        let cursor = cursor_position(vt["content"].as_str().unwrap_or_default())
            .context("terminal screen has no cursor position")?;
        Ok(input_line_is_empty(
            text["content"].as_str().unwrap_or_default(),
            rows,
            cursor,
        ))
    }

    fn submit(&mut self, session_id: &str, block_id: &str, text: &str) -> Result<()> {
        // The text goes through stdin so that a leading `-` is not a flag.
        self.run(&["send", "-s", session_id, "-b", block_id], text)?;
        self.run(&["send-key", "-s", session_id, "-b", block_id, "enter"], "")
    }
}

/// The 1-based (row, column) of the last cursor position sequence,
/// `ESC [ row ; col H`, in a `vt` screen dump.
fn cursor_position(vt: &str) -> Option<(usize, usize)> {
    let start = vt.rfind("\x1b[")? + 2;
    let end = start + vt[start..].find('H')?;
    let (row, col) = vt[start..end].split_once(';')?;
    Some((row.parse().ok()?, col.parse().ok()?))
}

/// Whether the cursor's row of the screen, the last `rows` lines of `text`,
/// shows only a prompt mark before the cursor. A TUI's empty input box may
/// show placeholder text after the cursor, which does not count.
fn input_line_is_empty(text: &str, rows: usize, (row, col): (usize, usize)) -> bool {
    let lines: Vec<&str> = text.lines().collect();
    let top = lines.len().saturating_sub(rows);
    let Some(line) = lines.get(top + row.saturating_sub(1)) else {
        return false;
    };
    let before: String = line.chars().take(col.saturating_sub(1)).collect();
    let mut marks = before.split_whitespace();
    matches!(
        (marks.next(), marks.next()),
        (Some(mark), None) if mark.chars().count() == 1 && !mark.chars().all(char::is_alphanumeric)
    )
}

/// Shortens `text` to at most `max` characters.
pub fn truncate(text: &str, max: usize) -> String {
    text.chars().take(max).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_cursor() {
        assert_eq!(cursor_position("x\x1b[0m\x1b[22;3H\n"), Some((22, 3)));
        assert_eq!(cursor_position("no cursor"), None);
    }

    #[test]
    fn tells_an_empty_input_line_from_typed_text() {
        // Captured from Claude Code and Codex in a 24-row terminal.
        let mut screen: Vec<String> = (0..21).map(|i| format!("scrollback {i}")).collect();
        screen.extend((0..20).map(|_| String::new()));
        screen.push("────".into());
        screen.push("❯ Try \"fix lint errors\"".into());
        screen.push("  ⏵⏵ auto mode on".into());
        let text = screen.join("\n");
        // The visible screen is the last 24 lines; the prompt is on row 23.
        assert!(input_line_is_empty(&text, 24, (23, 3)));
        assert!(!input_line_is_empty(&text, 24, (23, 6)));
        assert!(!input_line_is_empty(&text, 24, (22, 3)));
        assert!(!input_line_is_empty(&text, 24, (40, 3)));
        assert!(input_line_is_empty(
            "› Ask Codex to do anything",
            24,
            (1, 3)
        ));
        assert!(!input_line_is_empty("› abc", 24, (1, 6)));
        assert!(!input_line_is_empty("ab", 24, (1, 3)));
    }
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
        /// Lines submitted with [`Rex::submit`].
        pub input: Vec<String>,
        /// The block this one was split from, and whether beside it.
        pub split_from: Option<(String, bool)>,
        /// Whether a human has typed into the input line.
        pub typing: bool,
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
                    input: Vec::new(),
                    split_from: None,
                    typing: false,
                },
            );
            Ok(Window {
                window_id,
                block_id,
            })
        }

        fn split(
            &mut self,
            session_id: &str,
            anchor_block: &str,
            beside: bool,
            command: &[String],
            cwd: &Path,
        ) -> Result<String> {
            let anchor = self.blocks.get(anchor_block).context("no such block")?;
            if anchor.session_id != session_id {
                bail!("block {anchor_block} is not in {session_id}");
            }
            let window_label = anchor.window_label.clone();
            let block_id = self.id("block");
            self.blocks.insert(
                block_id.clone(),
                Block {
                    session_id: session_id.to_owned(),
                    window_label,
                    command: command.to_vec(),
                    cwd: cwd.to_path_buf(),
                    status: None,
                    input: Vec::new(),
                    split_from: Some((anchor_block.to_owned(), beside)),
                    typing: false,
                },
            );
            Ok(block_id)
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

        fn destroy_session(&mut self, session_id: &str) -> Result<()> {
            self.sessions.retain(|_, id| id != session_id);
            self.blocks.retain(|_, b| b.session_id != session_id);
            Ok(())
        }

        fn input_is_empty(&mut self, _session_id: &str, block_id: &str) -> Result<bool> {
            Ok(!self.blocks.get(block_id).context("no such block")?.typing)
        }

        fn submit(&mut self, _session_id: &str, block_id: &str, text: &str) -> Result<()> {
            self.blocks
                .get_mut(block_id)
                .context("no such block")?
                .input
                .push(text.to_owned());
            Ok(())
        }
    }
}
