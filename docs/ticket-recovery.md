# Recover an exhausted MergeDecision claim

A repeated PR-reference mismatch blocks the TicketRun. These commands recover
only that blocker. They do not approve a merge or release execution resources.

Run the foreground controller with the same binary version first. The
controller initializes or migrates the state database; these commands do not.
Use a human host terminal and the same state directory as the controller.

Inspect the exact blocked subject:

```sh
rex-projects --state-root /path/to/state ticket blocked-reason \
  --project example --run RUN_ID --json
```

Check the reason, expected PR reference, configuration and publication digests,
blocked revision, and `recovery_budget`. Correct the underlying input before
requesting recovery. Copy `subject_digest` from the output:

```sh
rex-projects --state-root /path/to/state ticket resume-merge-decision \
  --project example --run RUN_ID \
  --expected-subject-digest SUBJECT_DIGEST --request-id human-recovery-001 --json

rex-projects --state-root /path/to/state ticket recovery-status \
  --request-id human-recovery-001 --json
```

The first command queues intent. It does not immediately wake an Agent. The
controller reads the current ticket through the configured external CLI,
observes the PR, and revalidates the stored revision, configuration, accepted
plan, publication, and original result. It then authorizes one canonical
Coordinator turn and one new MergeDecision assessment. The resulting intent
follows the usual checks, required human approval, and configured merge
procedure.

Repeating an identical request ID and subject returns its stored status without
scheduling another attempt. Reusing an ID with different content is rejected.
The one-use budget stays consumed if the resumed attempt fails. Changing the
request ID does not renew it. A stale subject requires a fresh blocker
inspection. Unavailable external observations leave the request pending;
rejected or failed attempts remain visible in `recovery-status`. Preserve the
blocked evidence and investigate the reported reason instead of editing the
database.
