---
status: accepted
---

# External trackers through CLI adapters

The local Ticket is the source of truth. rex-projects imports items from external trackers and writes Ticket state back to them only through each tracker's CLI, so that authentication stays with that CLI. Each tracker is described by configuration, not code:

- `get` and, optionally, `list` (for intake), as argv templates whose JSON output is mapped by a jq expression evaluated in-process (for example with the `jaq` crate) into `{ ref, url, title, body, status, labels, updated_at }`;
- `transition.<status>` steps, where `done` is required and `in_progress` and `canceled` are optional;
- an optional `comment` command, which is required when `in_progress` or `canceled` is not configured.

Argv templates are substituted element by element without a shell, so Ticket text cannot inject commands.

`serve` writes back mechanically:

- `running` sets `in_progress`, or posts a "started" comment if the tracker has no such state;
- a Stage change posts a rate-limited progress comment on trackers without `in_progress`;
- `done` sets `done` with a summary and artifact URLs;
- `abandoned` and `failed` set `canceled` if configured, or post a comment otherwise.

Write-backs are idempotent ("set state X"), retried with backoff, and shown in the UI on failure. They are not exactly-once. Write-backs for one external ref run in order: a later write-back waits for earlier ones, and a pending state transition is dropped once a newer state transition for the same ref is queued, so a delayed retry can never move an item back to an older state. `serve` periodically re-reads running Tickets' external refs. If a human closes an item externally, it notifies the UI and the Coordinator but does not stop the work.

A Ticket may have several external refs, for example when the Supervisor batches related reports, and every ref receives write-backs. In v1, a human imports items. From M6, the Supervisor uses `list` to find candidates and hands them to the inner loop.

rex-projects is open source. It ships configuration examples only for public CLIs, verified against the real CLI when written. Configuration for private or company tools lives only in the user's own configuration and never in this repository. GitHub Issues is out of scope.

## Considered Options

- **Links only, with no write-back.** Rejected: people tracking work externally need to see it start and finish.
- **A fixed state map for every tracker.** Rejected: many trackers cannot express arbitrary states, so only `done` is mandatory.
