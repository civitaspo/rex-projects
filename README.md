# rex-projects

A Rex plugin that runs cooperating coding Agents on many Projects at once. A Rust binary, `rex-projects`, holds the logic; a thin Lua layer integrates it with Rex. See [the ADRs](docs/adr/) for the design and [GLOSSARY.md](GLOSSARY.md) for the vocabulary.

## Usage

Configuration lives in `${XDG_CONFIG_HOME:-~/.config}/rex-projects/config.toml`, and state lives in `${XDG_STATE_HOME:-~/.local/state}/rex-projects/`. Override them with `--config-dir` / `REXP_CONFIG_DIR` and `--state-dir` / `REXP_STATE_DIR`.

```toml
[[projects]]
id = "demo"
repo = "~/src/github.com/example/demo"
```

```sh
rex-projects config check
rex-projects ticket new --project demo --title "Add a health check" --ready
rex-projects ticket list
rex-projects events --follow
```

Run `rex-projects ui` for the Ticket dashboard. It lists Tickets by Project with the ones that need you first. Press Enter to jump to a Ticket's Coordinator, `r` to ready a backlog Ticket, `a` to show old finished Tickets, and `q` to quit.

## Rex plugin

Put `rex-projects` on the `PATH` of your login shell, then load the plugin from `~/.config/rex/init.lua`:

```lua
package.path = os.getenv("HOME") .. "/src/github.com/civitaspo/rex-projects/lua/?/init.lua;" .. package.path
require("rex_projects").setup({
  bin = "rex-projects",
  keys = { dashboard = "ctrl+a>p", serve = "ctrl+a>shift+p" },
})
```

Adjust the path to your clone. The plugin adds two actions: `rex_projects_dashboard` opens the dashboard as a floating layer, and `rex_projects_serve` shows the control session `rxp`, creating it with `rex-projects serve` when it is missing. Keys are bound only when given.

## External trackers

rex-projects imports items from external trackers and writes Ticket state back only through each tracker's own CLI, so authentication stays with that CLI ([ADR-0010](docs/adr/)). Describe a tracker under `[trackers.<name>]` and point a Project at it. The tool below, `acme-tracker`, is made up:

```toml
[[projects]]
id = "demo"
repo = "~/src/github.com/example/demo"
tracker = { name = "acme", vars = { board = "core" } }

[trackers.acme]
# Required. The jq expression maps the CLI's JSON output to
# { ref, url, title, body, status, labels }, where status is one of
# open, in_progress, in_review, done, canceled, or other.
get = { argv = ["acme-tracker", "show", "{{ref}}", "--board", "{{board}}", "--json"], map = '{ref: .key, url: .url, title: .title, body: .description, status: (.state | ascii_downcase), labels: .labels}' }
# Optional. Maps the output to an array of items.
list = { argv = ["acme-tracker", "search", "{{query}}", "--json"], map = 'map({ref: .key, title: .title, status: "open"})' }
# Required unless both in_progress and canceled transitions are set.
comment = { argv = ["acme-tracker", "comment", "{{ref}}", "--body", "{{body}}"] }
# done is required; in_progress and canceled are optional.
transition.done = [{ argv = ["acme-tracker", "close", "{{ref}}", "--note", "{{summary}}"] }]
transition.in_progress = [{ argv = ["acme-tracker", "move", "{{ref}}", "doing"] }]
```

Each argv element is substituted on its own, without a shell. Templates may use `{{ref}}` (`get`, `comment`, transitions), `{{query}}` (`list`), `{{body}}` (`comment`), `{{summary}}` (transitions), and the Project's `tracker.vars`; any other placeholder is a configuration error. Commands time out after 30 seconds.

```sh
rex-projects tracker list --project demo --query "label:bug"
rex-projects ticket import ACME-12 --project demo --ready
rex-projects tracker jobs
```

`serve` writes back in order per external ref, retrying failures with backoff: dispatching a Ticket sets `in_progress` (or comments that work started), Stage changes post a progress comment at most every 10 minutes on trackers without `in_progress`, delivery sets `done` with the summary and artifact URLs, and abandoned or failed Tickets set `canceled` (or get a comment). `tracker jobs` shows pending and failed write-backs.

## Development

Install the pinned tools with `mise install`. Run `mise run lint` and `mise run test` to check changes. Run `mise run fix` to apply supported automatic fixes.
