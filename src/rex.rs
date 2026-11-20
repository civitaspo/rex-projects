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
            // A reply without a block list is an error, not an empty session:
            // treating it as empty would relaunch Agents that still run.
            Ok(result) => result["blocks"]
                .as_array()
                .with_context(|| format!("rex session.list_blocks returned no blocks: {result}"))?
                .iter()
                .map(|b| {
                    b["block_id"]
                        .as_str()
                        .map(str::to_owned)
                        .with_context(|| format!("rex block has no block_id: {b}"))
                })
                .collect(),
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
        // A record without a state is unknown, never idle.
        Ok(root.and_then(|r| {
            Some(Status {
                state: r["state"].as_str()?.to_owned(),
                message: r["msg"].as_str().map(str::to_owned),
            })
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
        let vt = vt["content"].as_str().unwrap_or_default();
        let cursor = cursor_position(vt).context("terminal screen has no cursor position")?;
        Ok(input_line_is_empty(vt, rows, cursor))
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

/// Whether the input box under the cursor of a `vt` screen dump, whose last
/// `rows` lines are the screen, is empty: one prompt mark before the cursor,
/// and nothing but dim text after it, on its row and on the box's further
/// rows. Claude Code and Codex draw an empty box's placeholder dim and typed
/// text in normal style, so a draft anywhere in the box counts as input.
///
/// Claude ends the box with a rule (`────`), Codex with a blank row. A blank
/// row followed, before the next rule, by a row of plain text with no color
/// could also be a blank line inside a draft, so that counts as input: when
/// in doubt, not empty.
fn input_line_is_empty(vt: &str, rows: usize, (row, col): (usize, usize)) -> bool {
    let lines: Vec<&str> = vt.strip_suffix('\n').unwrap_or(vt).split('\n').collect();
    let top = lines.len().saturating_sub(rows);
    let start = top + row.saturating_sub(1);
    let Some(line) = lines.get(start) else {
        return false;
    };
    let row_cells = cells(line);
    let split = col.saturating_sub(1).min(row_cells.len());
    let (before, after) = row_cells.split_at(split);
    let marks: Vec<char> = before
        .iter()
        .map(|cell| cell.c)
        .filter(|c| !c.is_whitespace())
        .collect();
    let one_mark = matches!(marks.as_slice(), [mark] if !mark.is_alphanumeric());
    let typed = |cells: &[Cell]| {
        cells
            .iter()
            .any(|cell| !cell.c.is_whitespace() && !cell.dim)
    };
    if !one_mark || typed(after) {
        return false;
    }
    // The box's further rows, such as the rest of a multi-line draft.
    let rest: Vec<Vec<Cell>> = lines[start + 1..].iter().map(|l| cells(l)).collect();
    let is_rule = |cells: &[Cell]| {
        let mut visible = cells
            .iter()
            .map(|cell| cell.c)
            .filter(|c| !c.is_whitespace());
        visible.clone().next().is_some() && visible.all(|c| ('\u{2500}'..='\u{257f}').contains(&c))
    };
    for (i, cells) in rest.iter().enumerate() {
        if is_rule(cells) {
            return true;
        }
        if cells.iter().all(|cell| cell.c.is_whitespace()) {
            // Past a blank row, a row of plain text before the next rule may
            // be more of the draft. Codex's status row below its box is
            // partly colored, and typed text never is.
            let plain_text_follows =
                rest[i + 1..]
                    .iter()
                    .take_while(|row| !is_rule(row))
                    .any(|row| {
                        row.iter().all(|cell| !cell.colored)
                            && row.iter().any(|cell| !cell.c.is_whitespace() && !cell.dim)
                    });
            return !plain_text_follows;
        }
        if typed(cells) {
            return false;
        }
    }
    true
}

/// One cell of a `vt` row: its character, whether it is drawn dim (SGR 2),
/// and whether it has a foreground color other than the default.
#[derive(Clone, Copy)]
struct Cell {
    c: char,
    dim: bool,
    colored: bool,
}

/// The cells of one row of a `vt` dump. Cursor-forward moves become spaces;
/// other escape sequences are skipped.
fn cells(line: &str) -> Vec<Cell> {
    let mut cells = Vec::new();
    let mut style = Cell {
        c: ' ',
        dim: false,
        colored: false,
    };
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\x1b' => match chars.next() {
                Some('[') => {
                    let mut params = String::new();
                    let mut last = None;
                    for c in chars.by_ref() {
                        if ('\x40'..='\x7e').contains(&c) {
                            last = Some(c);
                            break;
                        }
                        params.push(c);
                    }
                    match last {
                        Some('m') => sgr(&params, &mut style),
                        Some('C') => {
                            let n = params.parse().unwrap_or(1);
                            cells.extend(std::iter::repeat_n(Cell { c: ' ', ..style }, n));
                        }
                        _ => {}
                    }
                }
                // OSC: up to BEL or ESC \.
                Some(']') => {
                    while let Some(c) = chars.next() {
                        if c == '\x07' || (c == '\x1b' && chars.next_if_eq(&'\\').is_some()) {
                            break;
                        }
                    }
                }
                _ => {}
            },
            c if c.is_control() => {}
            c => cells.push(Cell { c, ..style }),
        }
    }
    cells
}

/// Applies an SGR parameter list to the dim and foreground attributes.
fn sgr(params: &str, style: &mut Cell) {
    let mut params = params.split(';');
    while let Some(p) = params.next() {
        match p {
            "" | "0" => {
                style.dim = false;
                style.colored = false;
            }
            "2" => style.dim = true,
            "22" => style.dim = false,
            "39" => style.colored = false,
            // Extended colors carry their own numbers, which are not styles.
            "38" | "48" | "58" => {
                style.colored |= p == "38";
                match params.next() {
                    Some("2") => drop(params.nth(2)),
                    Some("5") => drop(params.next()),
                    _ => {}
                }
            }
            p => {
                if let Ok(n) = p.parse::<u8>()
                    && matches!(n, 30..=37 | 90..=97)
                {
                    style.colored = true;
                }
            }
        }
    }
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

    /// Rows as Claude Code and Codex draw them, from `vt` dumps.
    const CLAUDE_EMPTY: &str = "\u{276f}\u{a0}\x1b[0m\x1b[2mTry \"edit store.rs\"\x1b[0m\r";
    const CLAUDE_DRAFT: &str = "\u{276f}\u{a0}abc\r";
    const CODEX_EMPTY: &str =
        "\x1b[0m\x1b[1m\u{203a}\x1b[1C\x1b[0m\x1b[2mAsk Codex to do anything\x1b[0m\r";
    const CODEX_DRAFT: &str = "\x1b[0m\x1b[1m\u{203a}\x1b[1C\x1b[0mabc\r";

    /// A 5-row screen under two lines of scrollback, with `prompt` on row 3
    /// and a rule and a status row below it, then the cursor sequence, as
    /// `format` returns it.
    fn screen(prompt: &str, cursor: (usize, usize)) -> String {
        format!(
            "old 1\r\nold 2\r\n\x1b[38;2;153;153;153mtitle\x1b[0m\r\n\r\n{prompt}\n\x1b[38;2;136;136;136m\u{2500}\u{2500}\u{2500}\x1b[0m\r\n\x1b[38;2;255;193;7mauto mode on\x1b[0m\x1b[{};{}H\n",
            cursor.0, cursor.1
        )
    }

    #[test]
    fn tells_an_empty_input_line_from_typed_text() {
        for empty in [CLAUDE_EMPTY, CODEX_EMPTY] {
            let vt = screen(empty, (3, 3));
            assert_eq!(cursor_position(&vt), Some((3, 3)));
            assert!(input_line_is_empty(&vt, 5, (3, 3)), "{vt:?}");
            // Another row, or a cursor off the screen, is not the input line.
            assert!(!input_line_is_empty(&vt, 5, (2, 3)));
            assert!(!input_line_is_empty(&vt, 5, (9, 3)));
        }
        for draft in [CLAUDE_DRAFT, CODEX_DRAFT] {
            // The cursor after the draft, or at its start.
            assert!(!input_line_is_empty(&screen(draft, (3, 6)), 5, (3, 6)));
            assert!(!input_line_is_empty(&screen(draft, (3, 3)), 5, (3, 3)));
        }
        // The cursor on the blank first row of a multi-line draft: the box's
        // next row holds typed text (Claude's rule and Codex's blank row end
        // the box, so the status rows below do not count).
        let multi = "\u{276f}\u{a0}\r\r\n  second line\r";
        let vt = format!(
            "old\r\n\r\n{multi}\r\n\x1b[38;2;136;136;136m\u{2500}\u{2500}\x1b[0m\r\n\x1b[38;2;255;193;7mauto\x1b[0m\x1b[2;3H\n"
        );
        assert!(!input_line_is_empty(&vt, 5, (2, 3)), "{vt:?}");
        let codex = "\x1b[1m\u{203a}\x1b[1C\x1b[0m\r\r\n \x1b[1Csecond\r\r\n \r\r\n \x1b[1C\x1b[38;2;246;226;183mGPT\x1b[0m\x1b[1;3H\n";
        assert!(!input_line_is_empty(codex, 4, (1, 3)), "{codex:?}");
        let codex_empty = "\x1b[1m\u{203a}\x1b[1C\x1b[0m\x1b[2mAsk Codex\x1b[0m\r\r\n \r\r\n \x1b[1C\x1b[38;2;246;226;183mGPT\x1b[0m\x1b[1;3H\n";
        assert!(
            input_line_is_empty(codex_empty, 3, (1, 3)),
            "{codex_empty:?}"
        );
        // A blank line inside a draft, with the cursor on the first row.
        let gap = "\u{276f}\u{a0}\r\r\n\r\r\n  after a blank line\r\r\n\x1b[38;2;136;136;136m\u{2500}\u{2500}\x1b[0m\x1b[1;3H\n";
        assert!(!input_line_is_empty(gap, 4, (1, 3)), "{gap:?}");
        let codex_gap = "\x1b[1m\u{203a}\x1b[1C\x1b[0m\r\r\n \r\r\n \x1b[1Clater\r\r\n \r\r\n \x1b[1C\x1b[38;2;246;226;183mGPT\x1b[0m \u{b7} \x1b[38;2;171;223;167m~/src\x1b[0m\x1b[1;3H\n";
        assert!(!input_line_is_empty(codex_gap, 5, (1, 3)), "{codex_gap:?}");
        // Two blank lines, or only punctuation, after the blank line.
        let two_gaps = "\u{276f}\u{a0}\r\r\n\r\r\n\r\r\n  later\r\r\n\x1b[38;2;136;136;136m\u{2500}\u{2500}\x1b[0m\x1b[1;3H\n";
        assert!(!input_line_is_empty(two_gaps, 5, (1, 3)), "{two_gaps:?}");
        let codex_two_gaps = "\x1b[1m\u{203a}\x1b[1C\x1b[0m\r\r\n \r\r\n \r\r\n \x1b[1Clater\r\r\n \r\r\n \x1b[1C\x1b[38;2;246;226;183mGPT\x1b[0m \u{b7} \x1b[38;2;171;223;167m~/src\x1b[0m\x1b[1;3H\n";
        assert!(
            !input_line_is_empty(codex_two_gaps, 6, (1, 3)),
            "{codex_two_gaps:?}"
        );
        let codex_marks = "\x1b[1m\u{203a}\x1b[1C\x1b[0m\r\r\n \r\r\n \x1b[1C!!!\r\r\n \r\r\n \x1b[1C\x1b[38;2;246;226;183mGPT\x1b[0m \u{b7} \x1b[38;2;171;223;167m~/src\x1b[0m\x1b[1;3H\n";
        assert!(
            !input_line_is_empty(codex_marks, 5, (1, 3)),
            "{codex_marks:?}"
        );
        // As captured from both TUIs: the draft "\n\nthird line", with the
        // cursor on its blank first row (paths shortened).
        let claude_real = "\u{276f}\u{a0}\r\r\n\r\r\n  third line\r\r\n\x1b[0m\x1b[38;2;136;136;136m\u{2500}\u{2500}\u{2500}\r\r\n\x1b[2C\x1b[0m\x1b[38;2;255;193;7m\u{23f5}\u{23f5} auto mode on\x1b[0m\x1b[38;2;153;153;153m (shift+tab to cycle)\x1b[0m\x1b[1;3H\n";
        assert!(!input_line_is_empty(claude_real, 5, (1, 3)));
        let codex_real = "\x1b[0m\x1b[1m\u{203a}\x1b[0m\r\r\n \r\r\n \x1b[1Cthird\x1b[1Cline\r\r\n \r\r\n \x1b[1C\x1b[0m\x1b[38;2;246;226;183mGPT-6.2-Sol low\x1b[0m \u{b7} \x1b[0m\x1b[38;2;171;223;167m~/src/demo\x1b[0m\x1b[1;3H\n";
        assert!(!input_line_is_empty(codex_real, 5, (1, 3)));
        // Codex's own blank row before its colored status row ends the box.
        let codex_status = "\x1b[1m\u{203a}\x1b[1C\x1b[0m\x1b[2mAsk Codex\x1b[0m\r\r\n \r\r\n \x1b[1C\x1b[38;2;246;226;183mGPT-6.2\x1b[0m \u{b7} \x1b[38;2;171;223;167m~/src\x1b[0m\x1b[1;3H\n";
        assert!(
            input_line_is_empty(codex_status, 3, (1, 3)),
            "{codex_status:?}"
        );
        // A 24-bit color whose numbers include 2 is not dim.
        let gray = "\u{203a} \x1b[38;2;2;2;2mtyped\x1b[0m\r";
        assert!(!input_line_is_empty(&screen(gray, (3, 3)), 5, (3, 3)));
        // OSC sequences, such as hyperlinks, take no cells.
        let link = "\u{276f} \x1b]8;;https://x\x1b\\\x1b[2mhint\x1b[0m\x1b]8;;\x1b\\\r";
        assert!(input_line_is_empty(&screen(link, (3, 3)), 5, (3, 3)));
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
