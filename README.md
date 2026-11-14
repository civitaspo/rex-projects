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

## Development

Install the pinned tools with `mise install`. Run `mise run lint` and `mise run test` to check changes. Run `mise run fix` to apply supported automatic fixes.
