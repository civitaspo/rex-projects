---
status: accepted
---

# Keep orchestration in Rust under Rex process ownership

The user requires a Rust `rex-projects` CLI with Lua limited to Rex integration and no detached daemon. Run one machine controller for all Projects as a foreground program in a Rex terminal block, and launch finite Agent turns through Rex. Each Project retains one logical Supervisor. This preserves Rex lifecycle control while keeping scheduling, external adapters, and recovery in one testable Rust core. Lua Action-scoped child execution is unsuitable for the controller because the child can end when the Action returns. Verify block and server shutdown behavior before implementation depends on it. The sandbox and interaction boundary is defined in [ADR 0004](0004-host-controller-and-agent-transport.md).

Lua also owns setup-time runtime distribution. Embed the compatible Rust release and asset hashes in Lua, download and verify that release during `setup()`, and invoke its absolute cached path. Allow a local Lua `cli` option to select an absolute development executable or a PATH command without introducing a second TOML loader before Rust is available. Resolve it once and snapshot the binary by digest. This is integration logic; scheduling and factory behavior remain in Rust. A cached release needs no network. Changing the pin or developer digest requires a controlled runtime restart rather than replacing live processes. Appendix O of the prototype plan defines the bootstrap and release sequence.

Keep one active Rex tab per external ticket and place its role turns in blocks inside that tab. The logical view outlives Agent attempts and TicketRun generations. The dashboard focuses and zooms the relevant block, archived completed blocks are reclaimed promptly, and eligible unpinned terminal tabs close after a retention interval. Reopening an archived ticket shows history without starting an Agent. Cleanup preserves live, unknown, user-created, pinned, and pending-decision resources.
