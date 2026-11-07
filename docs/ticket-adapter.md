# External ticket adapters

rex-projects speaks a versioned JSON protocol to one configured command. A wrapper you own translates that protocol into the commands or SDK calls used by any ticket tracker, applies tracker-specific queries and authentication, and converts the result into normalized ticket JSON. The core has no tracker-specific query, status, API, or credential implementation.

```toml
[adapters.tickets]
kind = "command"
command = ["/absolute/path/to/your-ticket-wrapper"]
environment_allow = ["PATH"]
read_timeout_seconds = 30
write_timeout_seconds = 120

[adapters.tickets.status_values]
triage = "Needs sorting"
backlog = "Queued"
ready = "Open"
in_progress = "Doing"
in_review = "Review"
done = "Complete"
canceled = "Dropped"

[projects.example]
mode = "goal"
ticket_adapter = "tickets"
ticket_scope = { workspace = "your-workspace", project = "your-project" }
repositories = ["app"]
```

The configured command is an argv vector, not a shell expression. rex-projects sends one JSON request on stdin and expects one JSON response on stdout for each invocation. Stderr is diagnostic output; a nonzero process exit is a transport failure. The wrapper is responsible for its own service authentication and private configuration. Only explicitly allowlisted environment variables reach it.

## Contract

The canonical contract is the public Rust DTOs in `rex_projects::adapters::tickets`, the envelope in `rex_projects::protocol`, and the generated [version 1 JSON Schema](../schemas/ticket-adapter/v1.json). Regenerate the schema after changing these types:

```sh
cargo run --example export_ticket_adapter_schema
```

Every request and response has `schema_version: 1` and the same `request_id`. A response contains exactly one of `result` or `error`. Errors use normalized codes such as `not_found`, `unauthorized`, `forbidden`, `conflict`, `rate_limited`, `unavailable`, `unsupported`, and `invalid_request`. Provider-specific details belong in `extensions` or structured error details.

The wrapper must implement `adapter.describe` and declare its stable `ticket_namespace`, supported schema versions, normalized status mapping, and actual capabilities. rex-projects pins the namespace after the first successful description and rejects results from another namespace. Ticket `scope` values are opaque string key/value pairs. The wrapper interprets them for its tracker and must apply them to every read and write; the core does not assume fields such as team, board, or project.

The protocol's normalized status values are `triage`, `backlog`, `ready`, `in_progress`, `in_review`, `done`, and `canceled`. `status_values` maps these names to the wrapper's native status labels. Unknown native statuses must not be guessed into a normalized state.

The wrapper reports revision support and whether writes are conditional. Revisions are opaque strings. If the tracker lacks compare-and-set, the wrapper can re-read before mutation, but must report `conditional_revision_mutation: false`; that read does not prevent a concurrent update.

`operation.find` must validate the lookup scope, requested method, and subject before returning `found`. Each receipt must bind to the requested operation ID or stable external key and the affected ticket ID. Return `absent` only when the tracker can prove absence within the declared scope. If visibility is delayed or evidence is incomplete, return `unknown` with a reason. rex-projects validates every receipt against the requested operation and subject.

An existing vendor CLI does not automatically implement this contract. Put a wrapper at the configured command boundary to translate this protocol into its flags, request body, or SDK, then normalize its structured output. Do not make the core parse tracker-specific tables or vendor output formats.
