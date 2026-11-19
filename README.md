# rex-projects

A Rex plugin that runs cooperating coding Agents on many Projects at once. A Rust binary, `rex-projects`, holds the logic; a thin Lua layer integrates it with Rex. See [the ADRs](docs/adr/) for the design and [GLOSSARY.md](GLOSSARY.md) for the vocabulary.

## Usage

Configuration lives in `${XDG_CONFIG_HOME:-~/.config}/rex-projects/config.toml`, and state lives in `${XDG_STATE_HOME:-~/.local/state}/rex-projects/`. Override them with `--config-dir` / `REX_PROJECTS_CONFIG_DIR` and `--state-dir` / `REX_PROJECTS_STATE_DIR`.

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

Run `rex-projects ui` for the Ticket dashboard. It lists Tickets by Project with the ones that need you first, and shows the selected Ticket's history below the list: Coordinator launches and exits, reports with their stage and progress, questions and answers, and how the Ticket ended. `ticket show <id>` prints the same history in full. Press Enter to jump to a Ticket's Coordinator, `r` to ready a backlog Ticket, `a` to show old finished Tickets, and `q` to quit.

## Running Tickets

`rex-projects serve` dispatches ready Tickets. Each one gets a git worktree under `${XDG_STATE_HOME:-~/.local/state}/rex-projects/worktrees/` and a Coordinator Agent in a Rex tab of the session `rex-projects:<project>`, which `serve` creates when needed. Start it from the plugin's controller action, or run it in any Rex terminal.

A done Ticket's pane stays open for 10 minutes so you can read it, and an abandoned or failed Ticket's pane closes right away. When the last pane in a Project's session closes, `serve` closes the session too, unless you opened a tab of your own there. The session where you run `serve` is yours to close.

Agents run unattended, so give the provider the permission mode you want, for example:

```toml
[providers.claude]
args = ["--permission-mode", "auto"]

[providers.codex]
# A Ticket worktree commits into its repository's .git, outside the sandbox's workspace.
args = ["-a", "never", "-s", "workspace-write", "-c", "sandbox_workspace_write.writable_roots=[\"/path/to/repo/.git\"]"]
```

rex-projects lets Codex call its own MCP tools without asking, so `-a never` does not block a Coordinator's reports.

rex-projects also gives Codex its hooks, which deliver messages between Agents, and starts Codex with `--dangerously-bypass-hook-trust`. Without that flag, Codex runs only hooks a human has trusted under `/hooks`. The flag skips that check for every enabled hook in that Codex process, including hooks in your own `~/.codex`.

Claude Code asks whether to trust a new folder, and that prompt stops a Coordinator until you answer it. In our runs, a Ticket worktree was trusted once its Project repository had been trusted, so open `claude` once in each Project repository if you have not already. A Coordinator that reports no status for a minute, as when it waits on this prompt, appears under "Needs you" in the dashboard. Codex asks the same question and says that trusting a worktree applies to its repository root.

When a Coordinator asks a question, its Ticket waits under "Needs you". Answer in the Coordinator's pane, or from any terminal:

```sh
rex-projects ticket answer demo-1 --text "Use the v2 API"
```

`--text` types the answer into the Coordinator's pane and presses Return, and only does so while the Coordinator is idle. If you already replied in the pane and the Ticket still shows waiting, run `ticket answer demo-1` without `--text`.

To tell a Coordinator something without interrupting it, leave a message in its inbox. It reaches the Coordinator when its current turn ends. If the Coordinator is already idle, `serve` wakes it once it has been idle for 30 seconds with an empty input line, by typing one fixed line that says it has new messages; the messages themselves never go through the terminal. A Coordinator waiting on your answer is not woken: answer it, in its pane or with `ticket answer`, and the messages arrive with your answer:

```sh
rex-projects ticket message demo-1 "Also update the changelog"
```

A Coordinator can start helper Agents with the MCP tool `spawn_agent`: a `worker` changes code and a `reviewer` reviews without editing. Each helper runs in its own pane in the Ticket's tab, beside the Coordinator, and works in the same worktree. When it calls `done`, its summary goes to the Coordinator's inbox and its pane closes. Helpers count toward `limits.max_agents`. Choose each Role's provider and model per Project; a Role not listed uses the Coordinator's provider:

```toml
[[projects]]
id = "demo"
repo = "~/src/github.com/example/demo"
coordinator = { provider = "claude" }
roles.worker = { provider = "codex" }
roles.reviewer = { provider = "claude", model = "opus" }
```

Put `<config dir>/roles/<role>.md` to replace a built-in Role's instructions (`coordinator`, `worker`, `reviewer`) or to add a Role.

`ticket cleanup <id>` removes an ended Ticket's worktree and its `rex-projects/<id>` branch (or `rxp/<id>` from before the rename). Any other branch checked out in the worktree is kept. It refuses while the worktree holds uncommitted changes, commits that are on no remote, or ignored files such as `.env` or build output. Move anything you need out of the worktree, then pass `--discard-ignored` to delete the ignored files with it.

## Rex plugin

Put `rex-projects` on the `PATH` of your login shell, then load the plugin from `~/.config/rex/init.lua`:

```lua
package.path = os.getenv("HOME") .. "/src/github.com/civitaspo/rex-projects/lua/?/init.lua;" .. package.path
require("rex_projects").setup({
  bin = "rex-projects",
  keys = { dashboard = "ctrl+a>p", serve = "ctrl+a>shift+p" },
})
```

Adjust the path to your clone. Jumping from the dashboard to a Ticket in another session asks the Rex app to switch sessions, which needs Remote Control turned on in Rex Settings under Rex Server. Without it, the dashboard still zooms the Coordinator's pane in its session and says that the app did not switch. The plugin adds two actions: `rex_projects_dashboard` opens the dashboard as a floating layer, and `rex_projects_serve` shows the control session `rex-projects`, creating it with `rex-projects serve` when it is missing. Keys are bound only when given.

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

`serve` also re-reads the external items of active Tickets. When someone closes one outside rex-projects, the Ticket keeps running, but it moves under "Needs you" in the dashboard, `ticket_get` marks the ref with `closed_externally`, and the Coordinator's next tool result carries a notice asking it to confirm whether to continue. Cancel the Ticket, or tell the Coordinator to go on: once you answer it, the Ticket leaves "Needs you" and the notice stops, while `closed_externally` stays as a record. Reopening the item clears `closed_externally`.

## Development

Install the pinned tools with `mise install`. Run `mise run lint` and `mise run test` to check changes. Run `mise run fix` to apply supported automatic fixes.
