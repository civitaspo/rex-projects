---
name: rex-projects-verification
description: Verify rex-projects changes by exercising the CLI, Ticket lifecycle, and dashboard in an isolated Rex session.
---

# Verify rex-projects as a user

Use this procedure for changes to Ticket lifecycle, dispatch, approvals, verification, budgets, the dashboard, or Rex integration. It uses a temporary config directory, state directory, and repository. Never point it at a personal config or state directory.

## Prepare an isolated run

1. Build the binary from the worktree under test and record its absolute path. Run the verification commands from that repository root:

   ```sh
   cargo build --locked
   BIN="$PWD/target/debug/rex-projects"
   ```

2. Create isolated config, state, and repository directories. The Git repository must be a clone of the committed and pushed source branch under test. This gives the Ticket worktree the repository's real code, `mise.toml`, and Playbooks, while keeping its state isolated. For example:

   ```sh
   TMP="$(mktemp -d)"
   SOURCE_REPO="$PWD"
   SOURCE_BRANCH="$(git -C "$SOURCE_REPO" branch --show-current)"
   ORIGIN_URL="$(git -C "$SOURCE_REPO" remote get-url origin)"
   mkdir -p "$TMP/config" "$TMP/state"
   git clone --no-hardlinks --branch "$SOURCE_BRANCH" "$ORIGIN_URL" "$TMP/repo"
   ```

   The source branch must already contain the committed Playbook and verification guide. Copying those files after dispatch does not work: the Ticket worktree is created from the repository's current commit. Do not override Git's configured author or signing settings. Choose a unique project id such as `verification-demo`, and point the test Project at `$TMP/repo`:

   ```toml
   [[projects]]
   id = "verification-demo"
   repo = "/absolute/path/to/disposable-repo"
   default_playbook = "default"
   ```

   Put the test policy in `$TMP/config/policy.toml`, separately from `config.toml`. These files are disposable test fixtures; this procedure does not read or change a personal `config.toml` or `policy.toml`:

   ```toml
   [projects.verification-demo]
   autonomy = "A1"
   required_approvals = ["plan"]

   [projects.verification-demo.approvers]
   plan = "human"
   ```

   This matches the current `policy.toml` schema. Policy sections are keyed by Project id. Keep both directories empty of personal settings.

   The default Playbook runs `mise run lint`, `mise run test`, and `gh pr checks --required --watch`. The first two need the committed project checkout. The last command runs in the Ticket worktree, on its `rex-projects/<ticket-id>` branch. It requires an open pull request for that Ticket branch and an authenticated `gh` CLI; an existing PR for the cloned source branch does not satisfy it. The Coordinator must open the Ticket's PR before verification reaches this check. Do not expect an empty scratch Git repository or a Ticket branch without a PR to pass it.

   For an isolated lifecycle test without a pull request, use a separate test Playbook under `$TMP/config/playbooks/lifecycle/SKILL.md`, and set `default_playbook = "lifecycle"` in the temporary `config.toml`. The repository's `.rex-projects/playbooks/lifecycle/SKILL.md` must not exist, because repository Playbooks take precedence over config Playbooks. Give the test Playbook checks that can run in the committed clone, such as `cargo test --all-features --locked`, and omit the required-PR check. Keep the repository's default Playbook unchanged.

   For example, the temporary Playbook can use this frontmatter:

   ```yaml
   ---
   name: lifecycle
   description: Exercise the Ticket lifecycle without a pull request.
   rex-projects:
     stages: [plan, implement]
     gates:
       implement: plan
     verification:
       checks:
         - name: tests
           argv: [cargo, test, --all-features, --locked]
   ---
   Before editing files, inspect the task and request a human plan approval with a short plan and the files you expect to change. Wait for approval before reporting entry into `implement` or changing files. Then make the requested change and report the result.
   ```
3. Prefix every binary invocation with the temporary paths, for example:

   ```sh
   REX_PROJECTS_CONFIG_DIR="$TMP/config" REX_PROJECTS_STATE_DIR="$TMP/state" "$BIN" config check
   REX_PROJECTS_CONFIG_DIR="$TMP/config" REX_PROJECTS_STATE_DIR="$TMP/state" "$BIN" ticket new --project verification-demo --title "Exercise the lifecycle" --body "Make a small reversible change." --ready
   ```

   `ticket new --ready` is supported. Save the printed Ticket id. Run `config check` first and stop if it reports an error; fix the temporary fixture rather than changing personal configuration.

## Exercise the lifecycle

1. Open a dedicated, uniquely labelled session in Rex. In one of its terminals, run `GITHUB_TOKEN="$(gh auth token)" REX_PROJECTS_CONFIG_DIR="$TMP/config" REX_PROJECTS_STATE_DIR="$TMP/state" "$BIN" serve` and keep the session identifier for cleanup. This passes the token only to this `serve` process, which runs the repository's lint check. Keep the CLI monitoring commands in a second terminal in that same session.
2. Observe `events --follow`, `ticket show <id>`, and `ui` with the same temporary environment. For a pending plan Approval, approve it with `ticket approve <id> --kind plan` or press `y` in the dashboard. Reject with `ticket reject <id> --note "Reason"`. Do not answer an Approval with `ticket answer`; that command only answers ordinary questions.
3. Confirm the externally visible transitions and messages match the behavior under test. For verification, observe `verifying`, each check result, and the final state. For a failure scenario, confirm the findings reach the Coordinator before it resumes. The required PR check uses the open PR for the Ticket's `rex-projects/<ticket-id>` branch; for a lifecycle run without a PR, select the separate test Playbook described above.
4. Capture only the event lines and CLI output needed to establish the result. Remove temporary paths and credentials from any shared report.

## Clean up

Stop the test `serve` process, close only the Rex session created for this run, and remove the temporary config, state, and scratch repository. Do not close a session that existed before the test. Confirm the test session is gone before reporting completion.

If Rex is unavailable, report the live check as not run. Unit tests or mocked Rex behavior do not count as a live Rex verification.
