# Local protocol fixtures

The Rust `xtask` binary provides deterministic command-protocol fixtures for ticket and operation adapter tests. These fixtures exercise adapter serialization, durable state, and selected lost-reply or delayed-index cases. They do not launch a Rex Agent or prove a complete Project lifecycle.

Build and run the focused fixture tests with:

```sh
cargo test --locked -p rex-projects-xtask --test ticket_adapter --test operations
```

To invoke a fixture directly, send one version 1 JSON request on stdin. Ticket state is stored in the caller-selected SQLite database; operation state is stored in the caller-selected directory. Use fresh paths under a temporary directory:

```sh
cargo xtask fixture ticket \
  --database /tmp/rex-projects-ticket-fixture.sqlite \
  --namespace fixture/tenant-a \
  --native-shape record

cargo xtask fixture operations \
  --state-dir /tmp/rex-projects-operation-fixture
```

The ticket fixture can emulate two unrelated native response shapes (`record` and `edges`), lose one create response, delay stable-key index visibility, delay a selected protocol method with `--delay-method` and `--delay-ms`, or mutate selected responses for rejection tests. The operations fixture persists invocation state so a lost reply can be reconciled by a later lookup.

The JSON manifest retains the intended goal and operations Project acceptance story and required runtime capabilities. There is not yet a Rust driver that runs that complete story through the public CLI, Rex, Git, merge, deployment, knowledge publication, and restart recovery. Do not treat the protocol fixture tests as end-to-end acceptance or report a full-flow pass. Add that driver once every production runtime transition is callable, then record the actual verification boundary in its results.
