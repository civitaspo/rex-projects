# Rex capability observations

This report records the installed local Rex CLI and server used to prepare PR0 fixtures. It is an observation record, not a compatibility promise for other Rex releases. The checked-in schema facts below came from `rex api describe` and `rex block types`; local identifiers and endpoint paths are omitted.

## Observed CLI and API

- `rex whoami --json` identifies a connected local Unix server and reports Rex version `0.0.1793377904-ge6592f`, plus session/window/block IDs and a server instance ID. These identifiers are deliberately not copied here.
- `rex --version` is unsupported; use the Rex version returned by `rex whoami --json`.
- `rex new LABEL -- COMMAND... --json` is documented by the installed CLI. Its JSON result includes the created session ID and initial window/block IDs. Use command and argument array elements after `--` to preserve argument boundaries.
- Terminal flavor `com.superlogical.terminal.shell` accepts a `command` array and `shell: "none"` to start a program directly. Its options also include `cwd`, `path_prepend`, initial size, `login`, and exit handling. For a direct foreground program, set both `shell: "none"` and `login: false`: leaving `login` out defaults it to true and a macOS login wrapper can report a successful exit when the child exits nonzero. The `rex new` CLI exposes `--shell`, but has no `--login` option; use `session.create` or `session.new_window` when the caller must set `login: false` explicitly.
- `session.new_window` requires `session_id` and a `layout`; an optional `window_label` and `focus` are accepted. An all-or-none layout can create terminal blocks. Its result returns the new window ID and block IDs.
- `session.new_split` is available. The exact input schema is in the sanitized capability receipt for this tested version.
- `com.superlogical.terminal.process` reports the child process and `last_exit`; `com.superlogical.terminal.write` accepts text; `com.superlogical.terminal.resize` sets terminal dimensions.
- The terminal block advertises events `bell`, `child_exited`, `clipboard_written`, `desktop_notification`, `process_changed`, `program_status_changed`, `program_status_removed`, `progress_report`, `pwd_changed`, `selection_copied`, `size_changed`, `title_changed`, and `url_clicked`.
- `session.view` reports the active window, every window and its focused/zoomed block, layer layout, and ordered tabs. Its revision increases when the view changes. The API documentation says session-level events such as `window_created`, `window_closed`, `window_label_changed`, `active_window_changed`, and `session_label_changed` precede the corresponding `session_view_changed` event.
- `session.new_split` creates a layout next to an anchor block; the result contains created block IDs and a revision. `session.focus_block` and `session.zoom_block` operate on full block IDs.
- `block.close` closes one block and ends its program. The `block_closed` event follows; closing the final block can close its window.
- `session.destroy` is the API method to destroy a session. `rex kill` is the installed CLI command to destroy a session. There is no `session.close` or `session.new` API method on this server.
- Describing an unknown API method prints a CLI error naming that method and directs the caller to `rex api list`. Known method errors are described by each method's validation notes in the checked-in sanitized receipt.
- The API catalogue includes session/window/block lifecycle, focus, zoom, listing, describe, and event methods. Exact inputs must be read from this server with `rex api describe` rather than guessed.

The checked-in capability fixture is a sanitized snapshot of the relevant terminal flavor options, events, and method schemas for this Rex version. It excludes user, host, and session identifiers. Regenerate it from the installed server when verifying a different version; do not use it as a runtime contract without checking the live server.

## Live observations and remaining checks

An initial lifecycle fixture run against an isolated local Rex server passed exact argv delivery (including quotes and shell metacharacters), preservation of exit code 37, two blocks in one window, focus and zoom, bounded child exit, block-close termination, session-destroy termination, and removal of the generated session. It used an uncommitted worktree, so its private temporary receipt is debugging evidence only, not a PR verification receipt. Rerun at the final PR SHA before marking these rows complete.

The isolated config-load probe also observed argv preservation through `rex.exec`, a configured 200 ms child timeout reported with `timed_out: true` and `SIGTERM`, and bounded capture of 32,768 bytes. Its deferred Action created a terminal block with `shell = "none"`, `login = false`, and retained a child exit status of 23. A second Action returned while its long-running child remained alive; closing the generated block then ended that child. These observations apply only to the tested Rex release and macOS ARM host.

The outer deadline differs by execution path. A config reload containing `rex.exec({"/bin/sleep", "3"}, {timeout = 60})` completed in about 3.17 seconds. The same reload with a five-second sleep failed with `context deadline exceeded` at about 5.02 seconds even though the exec timeout was 60 seconds and the CLI request timeout was 15 seconds. Separately, the official Actions documentation says an Action has a 30-second deadline; an Action waiting for a six-second sleep completed in about 6.1 seconds. The latter is one observed duration, not a proof of the maximum. The implementation plan uses a sub-five-second config setup bound and a bounded retry Action below the documented Action deadline.

The transport-recovery fixture also exercised a deliberately truncated successful `session.create` reply: it reconciled one session by its unique generated label without retrying creation, then recovered the created block from a correlated event after stopping the event command and querying fresh block state. This was a dirty-worktree debug receipt and needs exact-PR-SHA repetition before it counts as final verification.

The provider-launcher fixture now has bounded self-tests for SIGINT, SIGTERM, and SIGHUP, including a fake tool child in a separate process group and an injected process-table failure after the initial sample. It proves the wrapper signals its still-owned provider process and reports cleanup as unverified when it cannot inspect tool identities. It does not prove Rex delivers a particular signal to the wrapper. An earlier direct block-close probe without this wrapper left a tool child alive; actual Rex block-close with the wrapper remains a final-SHA live gate. Provider continuation, marker propagation, configuration reload recovery, tab reuse/retention, interrupted API reconciliation, real Rex app screenshots/video, and the supported minimum Rex version also remain pending final-SHA receipts.

## Reproduction

Run `python3 tests/fixtures/rex/run_lifecycle.py --help` for the bounded fixture driver. It records the tested source SHA, Rex version/server identity, full generated IDs, exact argv, exit observations, and cleanup result. It requires an explicit server endpoint, disables server auto-start for every call, and optionally requires an expected instance ID. It creates and cleans up only its own session by full ID. See the per-lane receipts under `/tmp/rex-projects-pr0/` for final-head live results.
