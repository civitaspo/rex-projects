---
status: accepted
---

# A single event log in SQLite

All state is one append-only `events` table in SQLite (WAL) plus projections that can be rebuilt from it. Each event has `seq`, `at`, `actor`, `project_id`, `ticket_id`, `agent_id`, `kind`, and `payload`. The CLI, the MCP server, hooks, and `serve` all write to it, using SQLite's busy timeout for concurrency. `seq` is the cursor that the outer loop uses to follow events.

There are no signed envelopes and no intent or receipt tables for external effects, because rex-projects performs almost no external effects (ADR-0009). Shared configuration lives in a Git-managed directory (`~/.config/rex-projects`), so changes to Playbooks and Roles are reviewable and reversible.

## Considered Options

- **Current-state tables with intent, receipt, and reconcile flows for every effect**, as in the previous prototype. Rejected as far heavier than a single-user plugin needs.
