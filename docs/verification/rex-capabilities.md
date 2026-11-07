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
- `block.close` closes one block. The `block_closed` event follows; closing the final block can close its window. This is not proof that all provider descendants exited; see the cancellation observation below.
- `session.destroy` is the API method to destroy a session. `rex kill` is the installed CLI command to destroy a session. There is no `session.close` or `session.new` API method on this server.
- Describing an unknown API method prints a CLI error naming that method and directs the caller to `rex api list`. Known method errors are described by each method's validation notes in the checked-in sanitized receipt.
- The API catalogue includes session/window/block lifecycle, focus, zoom, listing, describe, and event methods. Exact inputs must be read from this server with `rex api describe` rather than guessed.

The checked-in capability fixture is a sanitized snapshot of the relevant terminal flavor options, events, and method schemas for this Rex version. It excludes user, host, and session identifiers. Regenerate it from the installed server when verifying a different version; do not use it as a runtime contract without checking the live server.

## Live observations

Live probes used a disposable foreground server running the version above on macOS ARM. Private receipts record the endpoint, server instance, generated resource IDs, source revision, executable digests, timestamps, and cleanup observations. No user Rex session or configuration was changed.

The lifecycle fixture observed exact argv delivery, including quotes and shell metacharacters, exit code 37, two blocks in one window, focus and zoom, bounded child exit, simple-child termination after block close and session destroy, and removal of its generated session. The visual-hold regression also completed with a 21-second hold. These are API and disposable-process checks. Actual Rust ticket-view retention, ownership, and archiving remain PR3 integration checks.

The config-load probe preserved argv, reported a 200 ms timeout with `timed_out: true` and `SIGTERM`, and captured 32,768 bytes. Its deferred Action created a terminal block with `shell = "none"`, `login = false`, preserving exit code 23. A long-running child remained alive after the Action returned and exited after its block closed. Reloading the same configuration twice retained one Action registration and the same live child. An intentional failed reload retained the last successful Action. The original disposable server configuration was restored.

The outer deadline differs by execution path. A config reload containing `rex.exec({"/bin/sleep", "3"}, {timeout = 60})` completed in about 3.17 seconds. A five-second sleep failed with `context deadline exceeded` at about 5.02 seconds, despite a 60-second child timeout and 15-second CLI timeout. The official Actions documentation specifies a 30-second Action deadline; a separate Action waiting six seconds completed in about 6.1 seconds. This is one observed duration, not a maximum-duration proof. Appendix O consequently budgets four seconds for setup and 25 seconds for its explicit retry Action.

The config environment successfully invoked `curl`, `shasum`, `mkdir`, and `chmod` as argv arrays. A mock CLI on PATH and a copied mock executable under paths containing spaces passed digest and JSON metadata checks. This verifies bootstrap prerequisites, not HTTP transfer or a production Rust asset. Cold download, release pins, and real development-binary snapshots remain PR3 checks.

The transport-recovery fixture deliberately truncated a successful create response at the CLI output boundary. A fresh listing found exactly one session by its nonce label without another create. After a positive event-subscription handshake and correlated creation event, disconnecting the event CLI still allowed fresh-state recovery. This does not simulate interruption of the underlying request transport. The fixture reaps its event reader and reconciles its generated session during cleanup.

## Cancellation boundary

The retired PR0 wrapper's local self-tests covered SIGINT, SIGTERM, SIGHUP, independent tool process groups, and unavailable process observations. Actual provider probes separately confirmed finite turns, continuation, and graceful interruption; see [Coding Agent observations](agent-capabilities.md).

Direct Rex block closure is an abrupt-loss path. In one busy Codex probe, the native provider process survived after its wrapper's block closed. A missing wrapper receipt or block therefore cannot release a slot. Planned cancellation must interrupt the wrapper first, wait for bounded cleanup, and independently confirm process absence before closing the block. Abrupt block loss requires the host-owned process manifest and reconciliation in Appendix G. Unknown identities retain capacity and worktree ownership.

## Measurement and visual evidence

A 20-sample read-only `session.new_window` capability query completed with zero errors and approximately 37 ms p95, below the proposed 2,000 ms budget. The fixture verifies the same server instance and version before and after each sample. This measures local CLI/API latency, not factory throughput or an improvement over trunk. Receipts include CPU count, load, sample timings, and total CLI calls.

The retained 34-second video renders timestamped actual CLI output for an unsupported API error, recovery with a supported API, a bounded foreground process, and verified session cleanup. It is a CLI transcript video, not a Rex GUI recording. A Rex application visual check and the minimum supported Rex release remain separate integration evidence.

## Evidence retention

The disposable PR0 drivers that produced these observations have been retired. This report and the sanitized capability snapshot are retained as historical, version-specific evidence. Private live receipts remain outside the repository; raw provider output and environment values must remain private. Repeat live verification with a separately reviewed, bounded fixture before treating these observations as current compatibility guarantees.
