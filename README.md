# rex-projects

A Rex plugin with a Lua integration layer and a Rust core. Rust owns typed
configuration, protocol and state boundaries; Lua is the Rex integration layer.

The current Rust slice provides strict configuration/profile validation,
generated JSON Schemas, read-only dependency discovery, protocol envelope
validation, build metadata, and transactional configuration snapshots. The
Agent runtime and ticket-processing controller are implemented in later slices.

The default configuration path is `${XDG_CONFIG_HOME:-$HOME/.config}/rex-projects/config.toml`.
Agent profiles live in sibling `profiles/<profile-id>/` directories. Validate
the checked-in public example with:

```sh
cargo run -- --config examples/fixture/config.toml config validate
```

`config apply --bootstrap` creates the first snapshot in
`${XDG_STATE_HOME:-$HOME/.local/state}/rex-projects/`; subsequent applies use
`--expected-revision`. Run `rex-projects schema config` for the authoritative
configuration schema and `rex-projects doctor --json` for read-only executable
resolution. `rex-projects --version` reports the Cargo package version for
release probes.

See [Release assets](docs/release-assets.md) for versioned target builds.

The ticket adapter protocol is implemented by a configured external command. See
[External ticket adapters](docs/ticket-adapter.md) for its normalization and schema contract.

See [Recover an exhausted MergeDecision claim](docs/ticket-recovery.md) for the
human-controlled recovery commands and their one-use limit.

## Development

Install the pinned tools with `mise install`. Run `mise run lint`, `mise run test`, and `mise run build` to check changes. Run `mise run fix` to apply supported automatic fixes.
