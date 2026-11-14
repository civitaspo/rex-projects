---
status: accepted
---

# Retrospectives improve the Harness

Results depend on the model and the Harness. Models improve on their own, so the work is to improve the Harness. Adding instructions for Agents is the least reliable fix: instructions grow without bound and constrain later models.

Rust records metrics for every Ticket and stamps them with the Harness version (the shared configuration's commit, the Playbook hash, the target base commit, and harness and model versions). A Postmortem Agent runs only for sampled Tickets:

- failed or abandoned Tickets;
- Tickets with a human intervention;
- Tickets with a Verification failure, a Stage regression, or a budget overrun;
- a random fraction of the rest (default one in five).

A Postmortem records Findings with evidence. The categories follow the `retro` skill (navigation, automated checks, coding standards, AGENTS.md, tool economy, no-ops, information access), plus verification and playbook. A Postmortem proposes Improvements by the fix ladder:

| Layer | Example | Route |
| --- | --- | --- |
| L1 Mechanical checks in the repository | Lint rules, tests, types, CI, scripts | A Ticket in that Project |
| L2 Repository documents | AGENTS.md pointers, coding standards, ADRs | A Ticket in that Project |
| L3 Playbooks and Skills | Steps, Stages, Verification | A patch to the shared configuration |
| L4 Roles and configuration | Model, provider, budgets | A patch; budgets and Gates only by humans |
| L5 rex-projects itself | Missing observation or features | A Ticket in rex-projects |
| L6 Notes (last resort) | Tacit knowledge | A time-limited Project note, then promoted or deleted |

A single Finding may justify only L1 or L2. Higher layers need the same recurrence key at least twice. Nothing is applied automatically: Improvements become Tickets or configuration patches that pass normal review.

## Considered Options

- **Growing Agent profiles from every Ticket with trials and promotion**, as in the previous prototype. Rejected: most of those Improvements were instructions, and the trial machinery was large.
