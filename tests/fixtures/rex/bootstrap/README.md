# Rex config and Action fixtures

These are disposable PR0 probes, not production bootstrap code. They do not read or edit the user's normal Rex configuration. Run them only against an explicitly selected temporary Rex server and session. The Lua file executes bounded `rex.exec` calls at config-load time and registers Actions without invoking them.

Set `REX_PR0_FIXTURE_ROOT` to an existing absolute temporary directory. The config-load probe records argv round-trip behavior, a 200 ms timeout, and bounded output size there. It uses `/usr/bin/python3` and `/bin/sleep`, so run only on a compatible test host. Do not point it at the user's normal state/config directories.

The `rex_projects_pr0_lifecycle` Action creates an unfocused window and a direct-exec child that exits 23. Both `shell = "none"` and `login = false` are set so a macOS login wrapper cannot replace the child's exit status. The terminal is retained for process inspection. The `rex_projects_pr0_long_lifecycle` Action creates a child that remains alive for at most 30 seconds; close only its returned block or the generated session and check the PID exits.

The Rust integration tests exercise hard-link publication against the host filesystem and copy the built CLI to an absolute path containing spaces before checking its digest and `version --json` response. The Lua 5.1 integration test runs the bootstrap contract scripts through the vendored mlua runtime.

All receipts from live runs belong in a private per-lane artifact directory. Do not commit raw receipts containing local paths, account names, or IDs.
