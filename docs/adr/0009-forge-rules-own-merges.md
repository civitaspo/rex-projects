---
status: accepted
---

# Forge rules own merges

Agents push, open pull requests, and request merges by following the target repository's own instructions. Branch protection, required reviews, and CI on the forge are the safety boundary. Prompts are not a boundary. Rust never pushes or merges. At autonomy A2 and above, a verified pull request is put on the forge's auto-merge, and the forge still performs the merge.

The only external effect Rust performs is writing Ticket state back to external trackers (ADR-0010).

## Considered Options

- **Typed merge, push, and release effects executed by Rust**, as in the previous prototype. Rejected: they duplicated rules the forge already enforces and required intent and reconcile machinery for each effect.
