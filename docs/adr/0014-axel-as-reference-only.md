---
status: accepted
---

# axel as a reference only

[axel](https://github.com/lgalabru/axel) is the closest prior art: a Rust Agent orchestrator built on Rex. rex-projects borrows its patterns but does not depend on it:

- calling `rex api call` and `rex events` through the CLI;
- OSC 7501 status;
- identity through environment variables, with all hooks routed to one CLI;
- replies that never trigger replies;
- bounded spawn depth;
- learning that proposes from classified history and keeps lessons separate from permissions.

axel centers on threads and named Agents. It has no Projects, Tickets, Playbooks, retrospectives, or outer loop, and it carries signed envelopes, remote sync, and its own ACP host, which a single-user plugin does not need. Depending on it would tie rex-projects to another project's design choices, such as its ban on typing into terminals (compare ADR-0003).
