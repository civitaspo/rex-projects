# rex-projects

A Rex plugin with a Lua integration layer and a Rust core.

The Rust package currently provides only a CI/build scaffold. Its executable
supports `--version` and reports the Cargo package version for release checks.
Other invocations print that the runtime is not implemented yet and exit with
an error; no rex-projects runtime behavior is available yet.

## Development

Install the pinned tools with `mise install`. Run `mise run lint`, `mise run test`, and `mise run build` to check changes. Run `mise run fix` to apply supported automatic fixes.
