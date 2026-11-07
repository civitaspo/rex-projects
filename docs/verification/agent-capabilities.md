# Coding Agent capability observations

These observations qualify disposable lifecycle fixtures, not the complete prototype runtime. Live receipts are retained privately with exact source revision, provider executable digest, fixture file digests, Rex instance, generated IDs, process observations, and timestamps. Raw model output, credential-bearing configuration, and environment values are excluded from this repository.

## Verified launch paths

The reviewed fixture revision `e441784d838be366294f0d999ae35c1bd6a86f2f` ran through disposable blocks on Rex `0.0.1793377904-ge6592f`, macOS ARM. Both providers inherited the ordinary user HOME and provider integrations; no personal configuration was changed.

| Capability | Claude Code 2.1.318 | Codex 0.166.0 |
| --- | --- | --- |
| Finite noninteractive turn and exit | Exit 0 | Exit 0 |
| Machine-readable response matching the fixture's closed schema | Observed | Observed |
| Follow-up with explicit new input under the same conversation ID | Observed | Observed |
| All six factory markers in the actual tool shell and a descendant, including the follow-up | Observed | Observed |
| Atomic run-local mailbox request and receipt, without SQLite access | Observed | Observed |
| Marked human-decision CLI rejected without decision-state mutation | Observed | Observed |
| Fixture asks for push, PR creation, and `/merge`; no guard-recorded publication attempt | Observed | Observed |
| Graceful host interruption before Rex block closure | Exit 130, cleanup verified | Exit 130, cleanup verified |
| External DB-like, WAL, and SHM sentinel write handles | Allowed under same-user permissions | Denied by workspace-write |

Claude used `--print --output-format json --json-schema`, automatic permission mode, disabled interactive permission prompts, and appended role instructions. Continuation used `--resume` with the recorded conversation ID. Codex used `--no-daemon --sandbox workspace-write --ask-for-approval never exec --json --output-schema`, with the role contract supplied through `developer_instructions`. Its continuation used `exec resume` with the recorded ID. The fixture initializes a local Git repository without a remote for Codex. No provider-native subagent was used.

The publication guard log is inside the writable fixture workspace and copied into private artifacts after exit. Guard self-tests verify push detection after Git global options and preservation of those options for permitted commands. No actual ticket or remote repository was configured. The observation establishes cooperative behavior for this prompt and launch path, not isolation against same-user commands, marker removal, absolute executable paths, or MCP capabilities.

## Interruption and abrupt loss

For each provider, the host first observed the wrapper, native provider, and busy tool identities. It sent SIGINT to the still-running wrapper, waited for a structured cleanup receipt, and independently confirmed that every tracked PID/group/start-time identity was absent. Only then did it close the Rex block. Both receipts reported `cancelled=true`, exit 130, and `cleanup_verified=true`. Both also reported `forced_kill=true`: cleanup escalated beyond the initial SIGINT grace period. This fixture flag records escalation and does not distinguish a successful SIGTERM from a later SIGKILL. The external absence checks establish termination after bounded cleanup, not interruption by SIGINT alone.

Direct block closure is a separate crash path. A busy Codex provider survived after its wrapper's Rex block closed. The host stopped those fixture-owned processes and confirmed absence. The controller must retain capacity and worktree ownership after abrupt block loss until process reconciliation succeeds. Missing blocks and missing receipts are not termination evidence.

The retired PR0 fixture sampled `ps` metadata every 200 ms. Start time was displayed at second precision, not a kernel birth token. Short-lived or detached children could escape sampling. Production process ownership therefore requires platform start identities and host reconciliation; these receipts do not claim a complete OS process audit. The retired local self-tests covered INT/TERM/HUP forwarding, unavailable process observations, receipt-write failure cleanup, and bounded fixture lifetime.

## Remaining integration qualification

Rex's SessionStart naming option was separately observed to remove the naming instruction while retaining other hook output. A fixture alone does not establish that every personal hook, skill, MCP server, repository tool, or Rex event integration executed successfully. Login-shell environment capture and repository mise resolution remain PR3 checks. Unsupported provider versions or profile options require fresh qualification rather than inheriting this result.

The actual Rust mailbox, runtime ownership, run descriptors, permission-event handling, worktree leases, and recovered execution slots are later integration gates. Malformed or schema-invalid responses must be rejected by the adapter; a successful structured response here does not prove all rejection paths. Keep raw receipts private, and repeat affected live lanes when the provider invocation, role contract, schema, or process runner changes.
