---
status: accepted
---

# Minimal Ticket states with free-form Stages

Rust tracks only eight Ticket states: `backlog`, `ready`, `running`, `waiting`, `verifying`, `done`, `abandoned`, and `failed`. Phases such as plan, implement, and review are Stages: free-form strings that the Coordinator reports while a Ticket is `running`. Rust records Stage transitions for Gates and metrics but does not enforce their order. Development practices change faster than code, and a phase machine in Rust gets in the way as models improve.

A Postmortem never blocks completion; a Ticket carries `retro: pending | done | skipped` alongside its state. Amending a Brief does not change the state.

## Considered Options

- **A fixed phase machine** (Planning → Implementing → Reviewing → … in Rust), as in the previous prototype. Rejected because every change to the way of working required a code change, and Coordinator prompts became procedural contracts with the host.
