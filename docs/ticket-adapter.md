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

## Example: GitHub CLI read-only adapter

This example uses Bash, `jq`, and `gh` on `PATH`. Authenticate `gh` in your
existing user configuration before running it (for example, `gh auth login`).
The wrapper uses that configuration; it does not accept or store credentials.
Save the following as an executable file, such as `/absolute/path/github-tickets`.
Replace `OWNER` and `REPO` with the repository you own or can access. The scope
and namespace are deliberately fixed; requests for any other scope are rejected.

```bash
#!/usr/bin/env bash
set -euo pipefail

repo='OWNER/REPO'
namespace="github:$repo"
request=$(cat)
id=$(jq -r '.request_id' <<<"$request")
method=$(jq -r '.method' <<<"$request")
params=$(jq -c '.params' <<<"$request")

error() {
  jq -n --arg id "$id" --arg code "$1" --arg message "$2" \
    '{schema_version:1, request_id:$id, error:{code:$code, message:$message, retryable:false}}'
  exit 0
}
respond() {
  jq -n --arg id "$id" --argjson result "$1" \
    '{schema_version:1, request_id:$id, result:$result}'
}

if [[ $(jq -r '.schema_version' <<<"$request") != 1 ]]; then
  error invalid_request 'Expected schema version 1'
fi
if [[ $method == adapter.describe ]]; then
  respond "$(jq -n --arg ns "$namespace" '{
    ticket_namespace:$ns, identity:{}, supported_schema_versions:[1],
    native_value_convention:"GitHub issue state and state_reason; unsupported values are placeholders",
    status_values:{triage:"unsupported:triage", backlog:"open", ready:"unsupported:ready",
      in_progress:"unsupported:in_progress", in_review:"unsupported:in_review",
      done:"closed:completed", canceled:"closed:not_planned"},
    capabilities:{pagination:true, filters:["status"], revision_support:true,
      conditional_revision_mutation:false, atomic_scope_mutation:false,
      remote_idempotency:[], reconciliation:{}, visibility_grace_seconds:0,
      supported_optional_methods:[]}}')"
  exit 0
fi
case "$method" in
  ticket.list|ticket.get) ;;
  *) error unsupported 'Method is not supported by this read-only adapter' ;;
esac
if ! jq -e --arg repo "$repo" '.scope == {repository:$repo}' <<<"$params" >/dev/null; then
  error invalid_request 'Scope must match the configured repository'
fi

# Normalize only known states; fail the whole response on an unknown state.
normalize='def ticket:
  (if .state == "open" then "backlog"
   elif .state == "closed" and .state_reason == "completed" then "done"
   elif .state == "closed" and .state_reason == "not_planned" then "canceled"
   else error("unknown GitHub issue state") end) as $status |
  {ticket_namespace:$ns, scope:{repository:$repo}, id:(.number|tostring),
   key:(.number|tostring), url:.html_url, revision:.updated_at,
   title:.title, body:(.body // ""),
   status:{value:$status, native_value:(if .state == "open" then "open" else "closed:" + .state_reason end)},
   labels:[.labels[].name], created_at:.created_at, updated_at:.updated_at};'

if [[ $method == ticket.get ]]; then
  ticket_id=$(jq -r '.ticket_id' <<<"$params")
  [[ $ticket_id =~ ^[1-9][0-9]*$ ]] || error invalid_request 'Ticket ID must be an issue number'
  if ! issue=$(gh api "repos/$repo/issues/$ticket_id"); then
    error unavailable 'GitHub issue request failed; see stderr'
  fi
  if ! result=$(jq -ce --arg ns "$namespace" --arg repo "$repo" \
    "$normalize if .pull_request then error(\"not an issue\") else {ticket_namespace:\$ns, ticket:ticket, timeline:[]} end" <<<"$issue"); then
    error invalid_request 'GitHub returned a pull request or an unknown issue state'
  fi
else
  if ! jq -e 'keys - ["scope", "status", "cursor", "page_size"] | length == 0' <<<"$params" >/dev/null; then
    error unsupported 'Only the status filter is supported'
  fi
  status=$(jq -r '.status // "all"' <<<"$params")
  case "$status" in
    all) state=all ;;
    backlog) state=open ;;
    done|canceled) state=closed ;;
    *) error unsupported 'Status filter is not supported' ;;
  esac
  page=$(jq -r '.cursor // "1"' <<<"$params")
  size=$(jq -r '.page_size // 30' <<<"$params")
  [[ $page =~ ^[1-9][0-9]*$ && $size =~ ^([1-9]|[1-9][0-9]|100)$ ]] || error invalid_request 'Invalid page or page size'
  if ! issues=$(gh api --method GET "repos/$repo/issues" -f state="$state" -f per_page="$size" -f page="$page"); then
    error unavailable 'GitHub issue request failed; see stderr'
  fi
  if ! result=$(jq -ce --arg ns "$namespace" --arg repo "$repo" --arg status "$status" \
    --argjson params "$params" --argjson size "$size" --arg page "$page" \
    --arg observed "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    "$normalize {ticket_namespace:\$ns,
      tickets:[.[] | select(.pull_request == null) | ticket | select(\$status == \"all\" or .status.value == \$status)],
      applied_filters:(\$params | del(.scope, .cursor, .page_size)),
      next_cursor:(if length == \$size then ((\$page | tonumber) + 1 | tostring) else null end),
      observed_at:\$observed, scan:{}}" <<<"$issues"); then
    error invalid_request 'GitHub returned an unknown issue state'
  fi
fi
respond "$result"
```

The `status_values` placeholders satisfy the protocol's required seven distinct
labels; they do not claim that GitHub supports those states. This example maps
open to `backlog`, closed/completed to `done`, and closed/not_planned to
`canceled`; any other native state fails instead of being guessed. Only the
status filter is supported. Pagination uses GitHub page numbers as opaque
cursors, and a full last page may lead to one extra empty page. Pull requests
are excluded after fetching, so a page can contain fewer issues than requested.
The `updated_at` timestamp is an opaque revision, not a compare-and-set token.
The example returns no timeline and treats GitHub CLI failures as `unavailable`;
a production adapter may distinguish HTTP errors and implement more methods.

In your existing configuration, allow the environment needed by your `gh`
installation and use the same fixed scope (adjust the paths and repository):

```toml
[adapters.tickets]
kind = "command"
command = ["/absolute/path/github-tickets"]
environment_allow = ["PATH", "HOME"]
read_timeout_seconds = 30
write_timeout_seconds = 120

[projects.example]
mode = "goal"
ticket_adapter = "tickets"
ticket_scope = { repository = "OWNER/REPO" }
repositories = ["app"]
```

With `app` configured as a repository in that configuration, run:

```sh
rex-projects ticket list --project example --limit 20
rex-projects ticket list --project example --status backlog --limit 20
rex-projects ticket show --project example --id 123
```

Follow the printed next-page command to continue a scan; if you supplied
`--status`, add the same filter to that command. `gh` uses its existing
configuration under `HOME`; if your installation uses `GH_CONFIG_DIR` or another
credential-related environment variable, explicitly allow it as needed.
