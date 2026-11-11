# Reconcile an interrupted provider qualification

Provider qualification runs under the foreground machine controller. If the
controller stops during a launch, the saved request and its execution slot can
remain `unknown`. A missing Rex block does not prove that its process exited.

Use the same configuration and state directory as the interrupted request:

```sh
rex-projects --config /path/to/config.toml --state-root /path/to/state \
  provider status --request-id qualification-request --json
```

The response includes the saved launch phase, controller generation, slot,
hold reason, and next safe action. Start the foreground controller with
`runtime run` if it is not running. Then request reconciliation of that exact
qualification:

```sh
rex-projects --config /path/to/config.toml --state-root /path/to/state \
  provider reconcile --request-id qualification-request --json
```

This human-only command queues an intent. It does not launch an Agent or release
a slot itself. Read `provider status` again to observe the controller's result.
Repeating the request coalesces the pending intent; it does not allocate another
execution slot.

| Saved launch phase | Controller behavior |
| --- | --- |
| `not_started` | Retry only when the deterministic preparation directory is absent and the request, configuration, profile, generation, and held slot still match. |
| `prepared` | Validate the saved private workspace and original environment handoff before retrying creation in the same slot. A consumed or missing handoff prevents retry. |
| `create_attempted` | Observe the exact Rex operation label. Never create a second block merely because no match is visible. |
| `bound` | Reconcile the saved Rex identity through the existing result, process, and cleanup checks. |
| `legacy_unknown` | Retain the slot. Older requests have no durable proof of the launch boundary, so automatic creation is forbidden. |

An absent, ambiguous, or unavailable Rex observation leaves ownership held.
Inspect the retained evidence and resolve the underlying problem; do not delete
state, edit receipts, or create a new request to bypass an unknown reservation.
Qualification succeeds only through the ordinary verified result and cleanup
path. An accepted reconciliation request is not a successful qualification.

Schema 17 records these launch boundaries. Existing requests migrate to
`legacy_unknown`; upgrading does not establish that they never launched. Older
binaries cannot open the upgraded state directory.
