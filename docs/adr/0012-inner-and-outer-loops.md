---
status: accepted
---

# Inner and outer loops

rex-projects is the inner loop: it turns intent into verified results and reports signals back. A Supervisor runs the outer loop for each Project. It handles intake and batching of external reports, keeps running Tickets' intent current by amending Briefs, schedules gardening, gives delegated Approvals, synthesizes Findings into Improvements, proposes removing scaffolding that newer models no longer need, maintains the verification skill, and writes the Digest. It never implements.

The inner loop exposes this contract from v1 through the CLI and MCP. Humans use the same operations until the Supervisor exists:

- outer to inner: `project_create`, `project_update`, `ticket_create` (with origins), `ticket_update`, `ticket_amend`, `approval_decide`;
- inner to outer: `events` with a cursor, `ticket_get`, `findings`, `metrics`, `history`.

A Supervisor is an ordinary Agent with role `supervisor` in its own tab in its Project's Rex session. `serve` wakes it on subscribed events and schedules. It keeps a dated wiki and can restart at any time.

There is one Supervisor per Project and no agent above them:

- capacity across Projects is allocated mechanically by `serve`;
- Rust merges the per-Project sections into one Digest;
- shared Playbooks, Roles, and Skills belong to the Factory Project, whose repository is the shared configuration. Other Supervisors file Tickets there.

If that proves insufficient, the Factory Project's Supervisor takes on cross-Project prioritization instead of a new kind of Agent.

The inner loop is built first (M0–M4). The Supervisor follows in stages: observation only, then intake and delegation, then autonomy.

## Considered Options

- **One Supervisor for all Projects.** Rejected: its responsibilities and context grow with every Project.
- **A Hypervisor above per-Project Supervisors.** Rejected: the cross-Project concerns are either mechanical or belong to the Factory Project.
