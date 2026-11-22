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

Projects without an explicit `policy.toml` entry keep the existing behavior. M3 supports both A0 and A1; it does not silently change a Project's autonomy. This repository's example policy can set rex-projects to A1 with a required human `plan` Approval, bounded verification attempts, and helper and time budgets. A1 still requires a human approver for `plan`; Policy can decide other Approval kinds automatically when configured as `nobody`.

Policy is protected by convention and the per-Ticket dispatch snapshot, not by file permissions. An Agent that can edit `policy.toml` or the state database can still change its own effective authority. Approval identity is likewise a convention when Agents share the human's credentials (see ADR-0009).

Merges follow ADR-0009 at every supported level. A Coordinator requests a merge when the repository's instructions say to, and the forge's required checks and approvals decide whether it happens. A Project that wants a human to merge says so in its forge rules or its own instructions. Agents run with the human's forge credentials, so an approval from an Agent would count as the human's. Agents therefore never approve pull requests. The Coordinator Role says so, but a prompt is not a boundary (ADR-0009). Giving Agents their own forge identity, which forge rules can tell apart from a human, is the lasting fix. As autonomy rises, review moves from a gate before merge to sampling after merge, and problems are fixed in the environment rather than in individual outputs.

Rust enforces the following on the Supervisor:

- it cannot change Policy;
- it cannot approve its own playbook, Role, or configuration Improvements;
- it is limited in how many Tickets it can create per day;
- every operation records its actor;
- a human can pause a Project at any time.
