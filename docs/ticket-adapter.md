# External ticket adapters

rex-projects speaks a versioned JSON protocol to one configured command. A wrapper you own translates that protocol into the commands or SDK calls used by any ticket tracker, applies tracker-specific queries and authentication, and converts the result into normalized ticket JSON. You can write that wrapper in any language. The core has no tracker-specific query, status, API, or credential implementation.

```toml
[adapters.tickets]
kind = "command"
command = ["/absolute/path/to/your-ticket-wrapper"]
environment_allow = ["PATH"]
read_timeout_seconds = 30
write_timeout_seconds = 120

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

The wrapper must implement `adapter.describe` and declare its stable `ticket_namespace`, supported schema versions, native labels for the seven normalized statuses, and actual capabilities. Keep native status mappings in the wrapper's own config or argv; rex-projects does not collect or pass them. rex-projects pins the namespace after the first successful description and rejects results from another namespace. Ticket `scope` values are opaque string key/value pairs. The wrapper interprets them for its tracker and must apply them to every read and write; the core does not assume fields such as team, board, or project.

The protocol's normalized status values are `triage`, `backlog`, `ready`, `in_progress`, `in_review`, `done`, and `canceled`. The wrapper maps these names to its native status labels and returns the map from `adapter.describe`. Unknown native statuses must not be guessed into a normalized state.

The wrapper reports revision support and whether writes are conditional. Revisions are opaque strings. If the tracker lacks compare-and-set, the wrapper can re-read before mutation, but must report `conditional_revision_mutation: false`; that read does not prevent a concurrent update.

`operation.find` must validate the lookup scope, requested method, and subject before returning `found`. Each receipt must bind to the requested operation ID or stable external key and the affected ticket ID. Return `absent` only when the tracker can prove absence within the declared scope. If visibility is delayed or evidence is incomplete, return `unknown` with a reason. rex-projects validates every receipt against the requested operation and subject.

An existing vendor CLI does not automatically implement this contract. Put a wrapper at the configured command boundary to translate this protocol into its flags, request body, or SDK, then normalize its structured output. Do not make the core parse tracker-specific tables or vendor output formats.

## Troubleshooting

Use an explicit configuration that points to your own normalized wrapper. From a
checkout, inspect the public envelope schema and the ticket-specific contract,
then exercise the adapter through supported read commands (replace the config,
project, and ticket ID with your own):

```sh
rex-projects schema response | jq .
jq . schemas/ticket-adapter/v1.json
rex-projects ticket list --config /path/to/rex.yml --project example --limit 10 --json
rex-projects ticket show --config /path/to/rex.yml --project example --id TICKET-1 --json
```

- **Process failure:** The wrapper's stderr is for diagnostics, not protocol
  output. A nonzero exit, timeout, or failed process cleanup is a transport
  failure, even if stdout contains JSON. Check the wrapper's executable,
  allowlisted environment, and its own tracker authentication and logs. Keep
  tracker commands, credentials, and authentication inside the wrapper.
- **Invalid response:** On a successful exit, stdout must contain one JSON
  response envelope with `schema_version: 1`, the exact incoming `request_id`,
  and exactly one non-null `result` or `error`. Send logs to stderr instead of
  stdout. Copy the ID from each request rather than generating a new one, and
  check the result against the ticket schema. A namespace mismatch is also a
  protocol failure: return the same stable `ticket_namespace` from
  `adapter.describe`, operation results, and nested tickets. The first
  successful description pins it for that adapter instance.
- **Normalized error:** For a tracker error that the wrapper can classify,
  exit successfully and return an `error` envelope with the request ID and a
  supported code, message, and `retryable` flag. This is distinct from a
  process failure or malformed response. Investigate the reported code and
  wrapper diagnostics; for example, `unauthorized` points to the wrapper's
  tracker authentication.
- **Unknown native status:** Add an explicit mapping in the wrapper to the
  correct normalized status after checking the tracker's semantics, and keep
  its `adapter.describe` status labels consistent. If no mapping is known,
  return a normalized error instead of inventing a default status.
