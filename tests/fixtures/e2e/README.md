# End-to-end acceptance fixtures

This directory supplies disposable local dependencies for the Appendix M user-path story. It does not claim that the product runtime currently completes that story. `preflight.py` checks the public CLI surface and exits with status 4 plus a JSON `UNSUPPORTED` receipt when required commands or runtime hooks are not present. It never substitutes a mock runtime for a missing product command.

The scripts use only Python's standard library and Git. Adapter database and worktree paths are caller-supplied, so acceptance runs must pass paths beneath a fresh temporary fixture root. The unit tests create and remove their own temporary roots. No script starts an HTTP service or opens a network connection.

The ticket command fixture is the development-only Rust command `cargo run --package rex-projects-xtask -- fixture ticket`; it supports durable state and lost-create-reply injection. `create_local_git.py` creates an isolated clone and bare remote below a caller-selected new root. `forge_fixture.py` and `operations_fixture.py` are local, durable command adapter fixtures. `deterministic_agent.py` is a finite Rex block payload that writes a fixed change and a result receipt in a caller-selected worktree; it contains no provider invocation and does not establish that the product launches or reconciles it correctly.

## Create local Git resources

Pass a path that does not exist. The script refuses an existing path, creates a bare remote and a disposable seed clone under it, and prints a JSON receipt with the remote URL, initial commit, and worktree path. It does not touch a user's existing clone or contact a network service.

```sh
python3 tests/fixtures/e2e/create_local_git.py --root /tmp/rex-projects-e2e/git
```

The generated remote is a local `file://` Git remote. Use only the paths returned in its receipt.

## Check product support

```sh
python3 tests/fixtures/e2e/preflight.py --cli target/debug/rex-projects --json
```

Exit 0 means only that the listed public CLI commands and required switches are discoverable. It is not an end-to-end pass. Exit 4 means one or more required commands or switches are unavailable and prints the missing surface and exact help probe. The manifest marks runtime behavior that must additionally be observed before the acceptance story can pass.

## Invoke the forge fixture

The adapter reads one version 1 JSON request from stdin and writes one JSON response to stdout. Each call is a new process; SQLite state persists under `--database`. Configure the executable and fixed arguments as an argv array, not a shell string:

```sh
python3 tests/fixtures/e2e/forge_fixture.py \
  --database /tmp/rex-projects-e2e/forge.sqlite \
  --repository fixture/service \
  --remote /tmp/rex-projects-e2e/git/service.git \
  --required-check required-tests \
  --required-approval-count 1
```

`--drop-response-once OPERATION_ID` records a matching mutation before returning an empty response once. Retry/reconciliation can then be checked against durable state. The fixture implements only guarded local fast-forward merge into the configured bare remote; it checks the exact head, configured check names, and requested approval count before updating the target ref. It never claims a real hosting provider's review, branch protection, or check semantics.

`operations_fixture.py` accepts Appendix J `operation.invoke`, `operation.find`, and `operation.observe` methods. An invocation creates one durable local run; observation deterministically completes it as `succeeded`. This proves local effect reconciliation only, not an actual deployment.

## Run the deterministic block payload

`run_rex_agent.py` creates a new uniquely named Rex session only after checking the explicit local Unix endpoint and expected instance ID. It starts the payload as a foreground, shell-free Rex block, records the full session/window/block IDs, verifies the process result and worktree change, then kills only the session with its generated unique label. It requires a fresh artifact directory beneath `--fixture-root` and refuses a dirty worktree. Use an explicit disposable Rex server; never point a CI job at a personal session.

```sh
python3 tests/fixtures/e2e/run_rex_agent.py \
  --server unix:///path/to/disposable/rex.sock \
  --expected-instance-id <fixture-server-instance-id> \
  --fixture-root /tmp/rex-projects-e2e \
  --worktree /tmp/rex-projects-e2e/git/service-seed \
  --ticket-id fixture-42 \
  --source-sha <tested-source-sha> \
  --source-dirty
```

This verifies only that the deterministic payload traversed a real Rex-owned block. Running `deterministic_agent.py` directly is only a fixture self-check, not Rex transport evidence.

```sh
python3 tests/fixtures/e2e/deterministic_agent.py \
  --worktree /tmp/rex-projects-e2e/worktree \
  --receipt /tmp/rex-projects-e2e/agent-result.json
```

The implementation deliberately keeps the full Project flow in the acceptance driver. Do not report a full-flow PASS until the public CLI starts the machine controller and independently observed ticket, Git, forge, operation, knowledge, and restart state all satisfy Appendix M.
