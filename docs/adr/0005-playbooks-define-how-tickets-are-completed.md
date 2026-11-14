---
status: accepted
---

# Playbooks define how Tickets are completed

A Playbook is an Agent Skills `SKILL.md` with a `rex-projects` frontmatter block. Its body tells the Coordinator how to work. Its frontmatter declares Stages, the Roles that may be spawned, Gates, Verification, and budgets. The Coordinator can load it as an ordinary skill, and humans can read it as ordinary Markdown.

Rust enforces only what the frontmatter declares:

- **Gates**: entering a gated Stage waits for an Approval.
- **Verification**: runs after `complete(delivered)`; failure returns the Ticket to the Coordinator.
- **Budgets**: limits on Agents and wall-clock time; exceeding one forces an `ask`.
- **Roles**: spawning an undeclared Role is refused.

Everything else, including Stage order, which Roles to use and how often, and built-in subagents, is the Coordinator's choice.

Playbooks are selected in this order: explicit choice on the Ticket, the Project's label rules, then the Project's default. A repository's `.rex-projects/playbooks/` overrides shared Playbooks. The content hash is recorded at dispatch, so later edits do not affect running Tickets and metrics can be compared across Playbook versions.

A Playbook says where an Approval is needed but never who gives it. That comes from Policy (ADR-0007), because Playbooks are subject to Improvements and an Agent must not be able to widen its own authority by editing one.
