# rex-projects

A Rex plugin with a Lua integration layer and a Rust core. Rust owns typed
configuration, protocol and state boundaries; Lua is the Rex integration layer.

The prototype includes the Rust Agent runtime and ticket-processing controller,
with persistent orchestration and configured ticket and repository adapters.
One GitHub documentation ticket completed with human intervention and an
explicit Operator skip. Full prototype acceptance, including goal projects and
multiple repositories, remains incomplete.

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

See [Reconcile an interrupted provider qualification](docs/provider-recovery.md)
for exact-request recovery and retained execution-slot ownership.

See [Request a frozen profile trial](docs/profile-trial-request.md) for the
human-only matrix submission command and an example input file.

Generic comment-triggered `Request` merge execution is currently unsupported and
is blocked before human approval or any merge-procedure mutation, even when a
human approves the proposed procedure. `Direct` merge continues to use the
repository's configured checks and execution guards. Legacy `Request` work with
an uncertain external outcome is held for human reconciliation. See [issue
#73](https://github.com/civitaspo/rex-projects/issues/73) and [issue
#67](https://github.com/civitaspo/rex-projects/issues/67).

## Development

Install the pinned tools with `mise install`. Run `mise run lint`, `mise run test`, and `mise run build` to check changes. Run `mise run fix` to apply supported automatic fixes.
