# Coding Agent capability observations

This report is deliberately limited to installed-command facts and tested behavior. The plan depends on Claude Code and Codex; neither provider should be enabled for unattended Project work until its own live checks below have receipts. A Rex process fixture alone does not prove a Coding Agent lifecycle.

## Required live checks

| Capability | Claude Code | Codex |
| --- | --- | --- |
| Installed CLI version and executable digest | Observed; final SHA pending | Observed; final SHA pending |
| Finite noninteractive turn and process exit | Observed; final SHA pending | Observed; final SHA pending |
| Machine-readable final response and schema failure behavior | Structured response observed; schema failure pending | Structured response observed; schema failure pending |
| Explicit input continuation starts a new turn | Observed; final SHA pending | Observed; final SHA pending |
| Busy turn cancellation without terminal input | Pending | Native SIGINT observed; Rex block-close with wrapper pending |
| Automatic permissions for the configured profile | Observed; final SHA pending | Observed with workspace-write/approval-never; final SHA pending |
| `REX_PROJECTS_*` markers reach the tool shell and a descendant | Observed; final SHA pending | Observed; final SHA pending |
| Markers and continuation identity survive the next turn | Observed; final SHA pending | Observed; final SHA pending |
| Login environment, repository tool resolution, inherited hooks, skills, and MCP | Pending | Pending |
| Rex event availability and correlation with block/process | Pending | Pending |
| Worker follows the role contract when fixture AGENTS.md asks it to push, open a PR, or request `/merge` | Role instruction observed; guard stayed unused; final SHA pending | Role instruction observed; guard stayed unused; final SHA pending |
| Codex workspace-write fixture can exchange a run-local request and receipt without opening SQLite, WAL, or SHM | N/A | Observed; final SHA pending |

## Acceptance rule

Each provider report must name the exact CLI version, argv with secret values removed, environment marker names (never token values), profile/config digest, fixture repository revision, Rex instance, block ID, process ID, start/end times, exit code, and output-schema result. Keep raw transcripts and screenshots in the private per-lane artifact directory. Do not store user prompts, credential-bearing configuration, MCP payloads, or personal data in the repository.

A missing or unverified marker, automatic permission, process-exit, continuation, or output guarantee blocks unattended use of that provider. This is a compatibility gate, not an OS security boundary. The design treats agents as fallible collaborators running under the user's account.

## Current status

Initial live probes ran against disposable Rex blocks and a fixture-only local workspace. They used an uncommitted PR0 worktree, so these results are debugging observations rather than final PR evidence. Rerun and record exact-head receipts after the PR0 commit; keep the private receipts outside the repository:

- Claude Code `2.1.318`, automatic permission mode: one finite structured-output turn exited 0. The actual tool shell and a descendant observed all six factory marker names. It wrote an atomic local mailbox receipt, and the marked human-decision command returned its rejection code without creating decision state. As expected for a same-user provider without a filesystem sandbox, opening a write handle to the external sentinel files was allowed.
- Codex `0.166.0`, `--no-daemon --sandbox workspace-write --ask-for-approval never`: one finite strict-schema turn exited 0. The actual tool shell and a descendant observed all six factory marker names. It wrote the local mailbox receipt, rejected the marked human-decision command without creating decision state, and could not open the external DB-like, WAL, or SHM sentinels for writing. The disposable Codex workspace must be a local Git repository; initialize it without adding a remote.
- The installed Rex SessionStart naming feature was probed both ways: with naming enabled, the startup output contains a rename instruction; with `--feature-session-naming=false`, that instruction is absent. This verifies that the specific naming instruction can be suppressed while preserving the rest of the hook output. The source checkout of user settings was not changed.

- Both providers completed a follow-up turn under the same conversation identity, accepted the persisted wake input, retained all six factory marker names, wrote the expected atomic mailbox result, and rejected the marked human-decision command without creating decision state. The fixture's `gh` and `git push` guards remained unused. This checks the role contract on the disposable prompt; it does not establish that personal hooks, Skills, MCP servers, or Rex event integrations all execute correctly.
- A native Codex SIGINT observation ended the provider and all six tracked process IDs within a two-second grace. A separate direct Rex block-close attempt left a tool child running. The provider launcher now owns and signals the provider process group, observes child groups, and has bounded local self-tests for SIGINT/SIGTERM/SIGHUP plus an injected process-table failure. Rex block-close with this wrapper remains a live exact-head gate; the self-tests are not a substitute for it.

The observations above are preliminary and do not count as release readiness until repeated at the exact PR SHA. Actual inherited user hooks/skills/MCP/Rex event behavior and Rex block-close delivery to the wrapper remain unverified. No result should be inferred from CLI help or the model's own summary. Update this report only from private live receipts at the final tested SHA; keep raw model output and environment values out of the repository.
