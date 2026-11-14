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

## Development

Install the pinned tools with `mise install`. Run `mise run lint` and `mise run test` to check changes. Run `mise run fix` to apply supported automatic fixes.
