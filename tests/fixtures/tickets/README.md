# Fixture ticket command

This stdlib Python CLI is a local reference for the version 1 ticket adapter contract in Appendix H. It is not a Linear, GitHub, Forgejo, or company integration. It does not invoke a shell or access a network service.

Run one request per process. Send the JSON envelope on standard input. Read one JSON result or normalized error from standard output. The database path and tenant namespace are fixed in the configured argv:

```sh
python3 /path/to/ticket_fixture.py --database /tmp/ticket-fixture.sqlite --namespace fixture/tenant-a --visibility-delay-seconds 0.25
```

Use a private, disposable database. `--drop-create-response-once OPERATION_ID` commits one matching create, then returns an empty response exactly once. Re-run the same invocation to observe the recorded effect. `operation.find` by exact operation ID returns that durable receipt; lookup by creation key remains `unknown` until the configured visibility delay expires. A matching creation key may have multiple results, which the caller must resolve explicitly.

The fixture implements `adapter.describe`, `ticket.list`, `ticket.get`, `ticket.create`, `ticket.update`, `ticket.comment`, `ticket.resolve_duplicate`, and `operation.find`. Duplicate resolution records a comment and relation and sets the duplicate to `canceled` in one local transaction. Scope and namespace constrain every ticket lookup and mutation. Cursors bind to their namespace, scope, and filters; the scan metadata declares that the pages are not a consistent snapshot.

Run the behavior checks with `python3 -m unittest -v` from this directory. They start each CLI command with a fresh temporary database.
