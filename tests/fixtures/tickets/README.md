# Fixture ticket command

This stdlib Python CLI is a local reference for the version 1 ticket adapter contract in Appendix H. It is not a Linear, GitHub, Forgejo, or company integration. It does not invoke a shell or access a network service.

Run one request per process. Send the JSON envelope on standard input. Read one JSON result or normalized error from standard output. The database path and tenant namespace are fixed in the configured argv:

```sh
python3 /path/to/ticket_fixture.py --database /tmp/ticket-fixture.sqlite --namespace fixture/tenant-a --visibility-delay-seconds 0.25
```

Use a private, disposable database. `--drop-create-response-once OPERATION_ID` commits one matching create, then returns an empty response exactly once. Re-run the same invocation to observe the recorded effect. `operation.find` declares `match_basis: "operation_id"` when it returns the exact durable receipt, and `match_basis: "stable_external_key"` when it returns key-search candidates. Lookup by creation key remains `unknown` until the configured visibility delay expires. A matching creation key may have multiple results, which the caller must resolve explicitly; the adapter preserves all candidates rather than treating one as an exact operation match.

The fixture implements `adapter.describe`, `ticket.list`, `ticket.get`, `ticket.create`, `ticket.update`, `ticket.comment`, `ticket.resolve_duplicate`, and `operation.find`. Found operation receipts echo the operation ID, method, stable creation key when present, and affected ticket ID so the caller can verify that the receipt belongs to the requested effect. Duplicate resolution records the requested stable operation key as its comment key, records the relation, and sets the duplicate to `canceled` in one local transaction. Scope and namespace constrain every ticket lookup and mutation. Cursors bind to their namespace, scope, and filters; the scan metadata declares that the pages are not a consistent snapshot.

Run the behavior checks with `python3 -m unittest -v` from this directory. They start each CLI command with a fresh temporary database.
