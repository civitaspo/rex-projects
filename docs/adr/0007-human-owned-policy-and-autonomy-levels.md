---
status: accepted
---

# Human-owned policy and autonomy levels

Each Project has an autonomy level, approvers for each kind of Approval, the kinds of Approval every Ticket requires before it can complete, and budgets. These live in `policy.toml`, which only humans edit. They are kept separate from configuration that Improvements may change.

| Level | Human | Delegated to the Supervisor or automation |
| --- | --- | --- |
| A0 Manual | Creates and readies Tickets, approves all Gates, merges | Nothing |
| A1 Verified | Approves plans and merges | Verification, returning work, low-risk answers |
| A2 Autopilot | Samples the Digest and fixes the environment | Plan approval, merge through forge auto-merge after Verification |
| A3 Self-directing | Sets goals and Policy, samples the Digest | Intake, gardening, priorities, readying Tickets within budgets |

Projects start at A0. rex-projects itself moves to A1 once Verification exists (M3). As autonomy rises, review moves from a gate before merge to sampling after merge, and problems are fixed in the environment rather than in individual outputs.

Rust enforces the following on the Supervisor:

- it cannot change Policy;
- it cannot approve its own playbook, Role, or configuration Improvements;
- it is limited in how many Tickets it can create per day;
- every operation records its actor;
- a human can pause a Project at any time.
