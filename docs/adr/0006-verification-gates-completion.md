---
status: accepted
---

# Verification gates completion

A Ticket is `done` only after Verification passes. An Agent saying it is done is not enough. Verification has two parts:

1. Deterministic checks: commands Rust runs, such as required CI checks.
2. A Verifier: a helper Agent that did not write the change. It checks the diff against an immutable base, using the Project's verification skill, which describes how to run the application and check it like a user.

Verification is the first rung of trust. Without it, a human must stay in the middle of every Ticket. Autonomy levels (ADR-0007) are raised only as Verification gets stronger.

## Considered Options

- **Worker self-checks.** Rejected: a Worker can grade itself generously, and a Worker can hide changes from a review that compares against its current `HEAD`.
