---
status: accepted
---

# Rust core with a thin Lua integration

rex-projects is one Rust binary that serves as the controller (`serve`), the Agent-facing MCP server, the hook handler, the CLI, and the terminal UI. Lua only registers Rex actions and key bindings, opens panes, and calls the CLI through `rex.exec`. Users extend rex-projects through configuration, Playbooks, Roles, and Verification commands, not Lua callbacks, so that behavior stays in typed, tested Rust and no extension point crosses languages.

`serve` runs in the foreground in a Rex block, not as a daemon, so that Rex owns its lifetime. If `serve` stops, Agents keep working and reporting. Only dispatch, message delivery, and Verification pause until it restarts.

## Considered Options

- **Lua only.** Rejected: hard to extend and test as the scheduler, state, and integrations grow.
- **A daemon or installed service.** Rejected: a process outside Rex is invisible to the user and outlives the session that started it.
