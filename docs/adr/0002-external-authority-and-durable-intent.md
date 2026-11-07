---
status: accepted
---

# Persist orchestration intent without mirroring external truth

Human waits and uncertain external writes must survive a controller restart, while tickets, Git history, merge state, and deployment outcomes remain authoritative externally. Use one local SQLite database for all Projects' ownership, continuations, deduplicated input, and transactional effect intent. Agent commands exchange scoped requests with the host instead of opening SQLite or its WAL and SHM files, irrespective of the provider's automatic permissions. Reconcile external outcomes after interruption instead of claiming exactly-once execution or rebuilding a complete local copy of external services. This introduces a small durable scheduler but avoids both duplicate side effects and service mirroring. Eventually consistent ticket search may expose duplicates; retain their identities and resolve them explicitly rather than promising exactly-once creation.
