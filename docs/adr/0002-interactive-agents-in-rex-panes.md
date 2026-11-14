---
status: accepted
---

# Interactive Agents in Rex panes

Every Agent runs as an interactive Claude Code or Codex TUI in its own Rex block. A human can talk to any Agent directly. rex-projects passes identity through environment variables (`REXP_AGENT_ID`, `REXP_TICKET_ID`, and so on), and the MCP server and hooks use them to identify the caller. They never rely on a hook configuration shared across a workspace.

rex-projects observes Agents through three structured channels and never scrapes the screen:

- the Coordinator's own reports through MCP (`report`, `ask`, `complete`);
- Rex `program_status` (OSC 7501), which the harness emits as `working`, `idle`, or `blocked`;
- harness hooks: SessionStart records the resumable session ID and transcript path, Stop marks a turn's end, and UserPromptSubmit records human interventions.

When an Agent's block disappears, rex-projects resumes a Coordinator with the harness's resume command in the same tab, a bounded number of times. For a helper Agent, it only notifies the Coordinator. It does not try to prove that the process has exited before releasing capacity. It records the process IDs it saw and shows anomalies to the human.

## Considered Options

- **Finite headless turns** (`claude --print`, `codex exec`) chained by the controller. This was the previous prototype's approach. Rejected because it requires durable parked Agents, file mailboxes, interrupt receipts, and process reconciliation, which made up most of that prototype's code.
- **A managed runtime** that drives the harness over its structured protocol (stream-json, `codex app-server`, ACP). Rejected for now because of its cost; see ADR-0003.

## Consequences

The following must be verified on the target harness versions before M1:

- whether Codex emits `program_status`. If it does not, hooks emit OSC 7501 instead;
- whether Codex runs MCP servers and hooks outside its sandbox, so that they can write the state database;
- whether resuming in the same tab continues the work.
