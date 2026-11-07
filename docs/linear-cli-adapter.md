# Linear CLI ticket adapter

The `linear_cli` ticket adapter translates rex-projects' typed ticket operations to the public
[`schpet/linear-cli`](https://github.com/schpet/linear-cli) command. It uses the CLI's documented
`linear api` GraphQL command and supports the CLI contract verified against v3.1.0. `describe`
checks `linear --version` and stops on any other version so an unverified command contract cannot
silently run.

rex-projects does not implement Linear HTTP, GraphQL networking, SDK access, credential storage,
login, or token refresh. The configured CLI owns those concerns and may use its existing user
configuration. rex-projects passes only environment variables named in
`adapters.tickets.environment_allow`; it never reads their values for logging or stores credentials
in its state database. `HOME`, `PATH`, and `XDG_CONFIG_HOME` must be allowlisted for this adapter.
Add any CLI-specific environment variable only when the user's CLI setup requires it.

```toml
[adapters.tickets]
kind = "linear_cli"
command = ["linear"]
environment_allow = ["HOME", "PATH", "XDG_CONFIG_HOME"]
read_timeout_seconds = 30
write_timeout_seconds = 120

[adapters.tickets.status_values]
triage = "Triage"
backlog = "Backlog"
ready = "To Do"
in_progress = "In Progress"
in_review = "In Review"
done = "Done"
canceled = "Canceled"

[projects.example]
mode = "goal"
ticket_adapter = "tickets"
ticket_scope = { team_id = "<Linear team UUID>" }
repositories = ["app"]
```

The first successful `adapter.describe` call pins the Linear workspace namespace for the
controller run. Ticket operations require the configured `team_id`; returned tickets are rejected
if they escape that team. Workflow status names are mapped using the values above. List requests
use bounded cursor pagination and explicit team scope. Free-text and release filters are not
advertised or silently widened. Pages are not claimed to be snapshot-consistent.

The adapter supports issue reads, comments, creation, and updates. Duplicate resolution is a host
workflow of two separately journaled effects: add a comment naming the canonical issue, then set
the duplicate's status to Canceled. The adapter does not combine those steps into one mutation. It rejects
templates and dependency changes in ticket creation/update until those operations are represented
as separate typed effects. Ticket creation and comments use deterministic caller-key-derived UUIDv4
identifiers supported by the v3.1.0 GraphQL inputs. A direct lookup can confirm a matching
identifier; an absent lookup is `unknown`, never proof that a prior mutation did not happen.
Update revisions are checked immediately before mutation and read back afterwards, but Linear does
not provide a conditional revision write here. `conditional_revision_mutation` is therefore false;
concurrent human edits can race between the preflight read and write.

An authentication exit status becomes a typed `unauthorized` error and requires the CLI owner to
repair authentication before the Project resumes. A mutation with a lost response, timeout, or
uncertain CLI result is kept unknown for reconciliation; rex-projects does not blindly repeat it.
CLI stderr is not included in persisted errors or user-facing adapter messages.

## Verified upstream contract

The implementation targets schpet/linear-cli v3.1.0, published 2026-10-22 at commit
[`02571d34be662e5487204841fb80bf23ed79b4f0`](https://github.com/schpet/linear-cli/commit/02571d34be662e5487204841fb80bf23ed79b4f0).
Its source documents `linear api --variables-json`, `--no-input`, cursor pagination, and exit codes
including 4 for authentication failure and 5 for unavailable/network outcomes. Its bundled schema
defines caller-supplied UUIDv4 IDs for issue, comment, and issue-relation creation, but does not
define a conditional revision field for `IssueUpdateInput`.
