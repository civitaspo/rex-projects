# Dashboard

## User flow

`rex-projects dashboard` reads a local runtime snapshot and stays in a raw-mode terminal view. Arrow keys move the selection; Tab switches among tickets, Agents, and human requests. Enter focuses and zooms the selected Agent block. On a ticket it focuses the Coordinator block, or the first available Agent block. `p` pins or unpins the active ticket view; `i` reads a bounded UTF-8 instruction file and queues a Coordinator instruction; `h` submits only a choice offered by the selected, unexpired human request using its exact subject digest and expiry. `q` exits. `--json` works without a TTY and returns the same read-only snapshot.

Action failures stay in the dashboard status line. A stale TicketRun revision, missing Rex target, unavailable controller, or expired human request does not close the view. The terminal guard restores raw mode and the alternate screen on normal exit, I/O failure, Ctrl-C, SIGTERM, and unwind.

## Rex connection

When a runtime starts inside a Rex block, it reads `REX_SESSION` and `REX_BLOCK`. It resolves the current Rex endpoint and instance with bounded `rex --autostart=false whoami --json`, unless `runtime run --rex-server <URL>` supplies an explicit server. The controller validates the selected session and block before claiming machine ownership, then writes endpoint, instance, session, and block to the mode-0600 `runtime-owner.json` projection. Dashboard focus uses that pinned endpoint and the selected target's persisted session/window/block IDs; it rejects a target whose instance differs from the owner projection. It never guesses the endpoint from an environment variable.

Running the CLI directly outside Rex remains supported for local runtime tests; in that case it has no pinned Rex connection and cannot focus a Rex block. A `REX_BLOCK` without `REX_SESSION` is rejected.

## Boundaries

`dashboard` owns rendering, keyboard dispatch, selection, and host action routing. It does not open SQLite, build shell commands, type into a provider terminal, or treat display text as authorization. Marked Agent contexts can inspect and focus but cannot pin views, send instructions, or respond to human requests; mutation keys return exit code 77 before calling the backend.

SQL remains inside `store::dashboard_projection`, which checks the expected schema version and emits typed Project, TicketRun, AgentRun, wait, and human-inbox rows. Agent focus is resolved through validated immutable `AgentLaunchAuthority` and the active Rex view/block binding. Pin updates use a bounded transaction fenced by active controller generation and exact TicketRun revision, then update the active view. Human rows use `ConfigStore::list_human_requests`; responses use the v8 `ConfigStore::enqueue_human_decision` queue and remain pending until controller validation.

`DashboardBackend` is the terminal's host port for snapshot, Rex focus/zoom, pin, durable Coordinator instruction, and exact-subject human response. The real Rex path uses `RexCliTransport`; the instruction path uses the PR4 host-owned durable input API and never injects text into a Rex TUI. The dashboard receives queued receipts, not claims that a controller has already accepted an instruction or human decision.

## Verification lanes

- PTY tests exercise navigation, focus, zoom, pin, instruction, human response, marked-Agent rejection, Ctrl-C, SIGTERM, alternate-screen setup failure, and terminal restoration.
- The Rex adapter lane uses a fixture CLI that returns `whoami`, API capabilities, and session view responses, then checks that focus and zoom target the selected block.
- The CLI lane starts a controller with a fixture Rex CLI, validates `REX_SESSION`/`REX_BLOCK`, and checks that the endpoint/instance/session binding is persisted. A separate non-TTY lane runs `--json dashboard` after applying config and starting the foreground controller.
- A live Rex run remains necessary at release qualification to verify the deployed Rex version's `whoami` and session-view response shapes against the actual server.
