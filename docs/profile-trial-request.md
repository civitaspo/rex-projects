# Request a frozen profile trial

Use this human-only command from the foreground controller's Rex session.
The controller must be running with an applied configuration and an active
Supervisor view for the Project. Qualify both the applied base profile and the
exact proposed candidate in that Rex instance before staging a trial. See
[Provider qualification](provider-recovery.md) for the qualification commands.
Profiles with `skill_paths` are not yet supported for frozen trials.

Copy [the example matrix](../examples/profile-trial-matrix.json) and replace
its tasks and expected results with representative cases for the candidate.
Each input has a unique `input_id`, task JSON in `input`, and host assertions
that compare JSON pointers against the Agent's structured result. An optional
`fixture` contains `{"schema_version":1,"files":{"path":"UTF-8 contents"}}`
for the disposable workspace. Omitting it creates an empty workspace.

The standard matrix has ten pairs over five inputs, with two pairs per input.
Pair indexes must be unique integers from zero through nine. Other coverage
requires a `scoped_exception` rationale of 20 to 4,096 bytes. The configured
pair budget and distinct-input minimum still apply. The matrix must be a
regular file no larger than 512 KiB. Do not include credentials or live-service
instructions in trial inputs or fixtures.

Submit the matrix with a stable request key for this Project:

```sh
rex-projects --config /path/to/config.toml --state-root /path/to/state \
  learning trial request --project project-id --candidate candidate-id \
  --candidate-digest 64-character-sha256 --request-key comparison-1 \
  --matrix-file /path/to/matrix.json --json
```

The response identifies the saved authorization and human request. Inspect the
request with `rex-projects human show REQUEST_ID --json`, using the same
configuration and state options. Staging creates no Agent run or execution
slot. Existing human approval and controller launch checks remain mandatory.
Approval expires after 24 hours, with one attempt per side of each pair.

Repeat the same request key and content to read the saved authorization without
extending its lifetime or reserving another batch. Changed content under the
same key conflicts. A saved request is not evidence that a native trial ran or
that the candidate qualifies for promotion.
