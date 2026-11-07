# Dashboard implementation sketch

## User flow

`rex-projects dashboard` reads one controller-owned projection, then stays in a raw-mode terminal view. Arrow keys move selection; Enter focuses and zooms the selected owned Rex block; `p` pins or unpins a selected ticket view; `i` reads a bounded message file and submits a revision-bound Coordinator instruction; `h` submits only a choice offered by the selected, unexpired HumanRequest using its exact subject digest. `q` exits. `--json` and non-TTY output return a read-only snapshot and never enter raw mode.

## Boundaries

`dashboard` owns display, keyboard dispatch, selection and validated action intent. It never opens SQLite, builds a shell command, types into a provider terminal, or interprets display text as authority.

`store::dashboard_projection` opens the local state database read-only and joins existing Project, TicketRun, AgentRun, execution-slot, ready-queue and pending-wake records into bounded typed rows. Human request rows are added through the human runtime's public read API once schema v8 is integrated; Rex IDs come only from persisted host records. The projection labels absent or stale data as unavailable rather than inferring a live process from a missing block.

`DashboardBackend` is the narrow host port for snapshot, Rex focus/zoom, ticket-view pin, revision-bound instruction submission, and exact-subject human response. Its real implementation delegates to the ConfigStore projection, PR3 `RexCliTransport`, PR4 `ticket instruct` command path and PR5 human decision queue. Tests use a fake backend to prove keyboard dispatch and receipts without a Rex or remote service.

## Core types

```rust
pub struct DashboardSnapshot { pub observed_at_unix: i64, pub projects: Vec<ProjectRow>, pub tickets: Vec<TicketRow>, pub agents: Vec<AgentRow>, pub waits: Vec<WaitRow>, pub human_requests: Vec<HumanInboxRow> }
pub struct FocusTarget { pub server_identity: String, pub session_id: String, pub window_id: String, pub block_id: Option<String> }
pub struct HumanInboxRow { pub request_id: HumanRequestId, pub subject_digest: Digest, pub expires_at_unix: i64, pub choices: Vec<HumanChoice>, pub question: String }
pub trait DashboardBackend {
    fn snapshot(&mut self) -> Result<DashboardSnapshot, DashboardError>;
    fn focus(&mut self, target: &FocusTarget) -> Result<FocusReceipt, DashboardError>;
    fn set_ticket_pinned(&mut self, ticket_run: &TicketRunId, expected_revision: Revision, pinned: bool) -> Result<(), DashboardError>;
    fn instruct_coordinator(&mut self, ticket_run: &TicketRunId, expected_revision: Revision, message: &[u8]) -> Result<QueuedInputReceipt, DashboardError>;
    fn respond(&mut self, request_id: &HumanRequestId, subject_digest: &Digest, expires_at_unix: i64, choice: HumanChoice) -> Result<QueuedDecisionReceipt, DashboardError>;
}
```

## Integration sequence

1. Implement and test DTO validation, projection read, deterministic rendering and keyboard-to-intent mapping.
2. Add raw-mode RAII guard and event loop. Restore terminal state on `q`, I/O error, Ctrl-C and panic unwind.
3. Implement the host adapter after the PR3 Rex and PR4/PR5 input APIs are available; keep unsupported mutation visibly unavailable until then.
4. Wire CLI and verify JSON/non-TTY snapshots, `REX_PROJECTS_AGENT`/`REX_PROJECTS_CONTEXT` mutation rejection, focus IDs and exact request digest/expiry at the service boundary.
5. Run a real isolated Rex dashboard lane for one persisted ticket and one human request; verify actual window/block focus and terminal restoration.
