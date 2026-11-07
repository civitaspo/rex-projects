# Rex lifecycle fixtures

These programs are inert children for live checks against an installed Rex server. They do not call the network, read user configuration, or mutate a repository. `argv_exit_probe.py` writes its exact received arguments and chosen exit code atomically to a receipt path passed as argv, then prints the same JSON for a readable terminal transcript. The harness compares the receipt file rather than parsing a wrapped terminal line. `wait_probe.py` writes its PID under an explicit temporary directory and waits for an explicit stop marker, with a bounded timeout.

Use them only from a disposable session created for the test. Record the full session and block IDs returned by Rex before cleanup. Cleanup must address those recorded IDs only. Do not close a current or user-created session. The Rex CLI itself owns child process termination when a test session is destroyed; verify the PID outcome from the fixture's ready file and process listing before reporting success.

`run_lifecycle.py --help` describes the bounded lifecycle driver. It requires an explicit server endpoint, disables auto-start, verifies the endpoint and optional instance ID before mutation, and cleans only its own generated session.

`run_transport_recovery.py --help` exercises interrupted API acknowledgments against an explicitly selected disposable server. It reconciles a simulated truncated successful session-creation reply by a unique label without retrying creation, then correlates a block-created event and queries fresh state after an interrupted acknowledgment. It owns and removes only the generated test session. The checked-in report must distinguish debug receipts from final-PR-SHA evidence.
