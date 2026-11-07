# GitHub Actions

Follow this structure when changing repository-owned workflows. It follows
[GitHub Actions Best Practice 2025](https://suzuki-shunsuke.github.io/slides/github-actions-best-practice-2025).
The `csm-ci-*.yml` workflows are distributed by csm-ci and are not maintained
here. The Securefix caller is part of this repository's PR workflow.

## Workflow structure

- `pull_request.yml` is the single PR entry point. It calls
  `workflow_call_pr.yml` and exposes the required `status-check`.
- Put every PR check under `workflow_call_pr.yml`. The outer `status-check`
  must fail unless the called workflow succeeds. This includes Securefix for
  eligible PRs. Update the aggregator whenever adding a check.
- Keep `push.yml` and `workflow_call_push.yml` separate from PR checks. The
  push status is named `push-status-check` so it cannot satisfy the PR's
  required check. Run lint and tests on both paths.
- Place reusable jobs in `wc-*.yml`. Keep title validation on PRs and run
  `mise run lint` in the shared checks workflow and `mise run test` in the
  shared tests workflow. Run `mise run build` in a shared build workflow called
  by both PR and push workflows. Do not
  use workflow-level path filters for required PR checks. If a check needs
  filtering, skip that job inside the reusable workflow instead.
- Run Securefix only for a PR authored by the repository owner whose head repository is this repository. Check
  out the PR head SHA, run `mise run fix`, then request the signed fix through
  the csm-ci Securefix client. Do not expose the Client App key to fork PRs.
  Forks still run the ordinary checks and title validation.
- Group concurrency by workflow and PR number or ref. Cancel superseded runs.
  Run the full PR checks on title edits as well as code changes.

## Security and dependencies

- Set workflow permissions to `{}` and grant each job only its required
  permissions. Pass secrets explicitly through reusable workflow declarations
  and only to the step that needs them. Never inherit all secrets.
- Pin third-party actions and remote reusable workflows to full commit SHAs.
  Keep checkout credentials disabled. Use a step environment variable for
  untrusted event values instead of embedding expressions in shell scripts.
- Set a timeout on each runner job. Use `bash -euo pipefail` for shell steps.
  Pin the mise version, install from `mise.lock`, and disable the mise cache in
  CI so PR runs cannot populate a cache later used by trusted workflows.
- Before mise setup, run
  `scripts/ci/install-lua-system-dependencies.sh` in each Ubuntu workflow. It
  installs `libreadline-dev`, required when the pinned Lua 5.1 mise plugin builds
  Lua from source. Keep this system prerequisite in the shared script instead of
  duplicating package-manager commands across workflows.
- `mise run lint` checks workflow syntax, shell code, action pins, security
  policies, and local action-lock coverage. `mise run test` runs project tests.
- After changing actions or workflow files, run `mise run actions-lock` and
  commit `.github/workflows/actions.lock`; do not edit that file by hand. Run
  `mise run actions-lock-verify` with GitHub authentication before opening a
  PR. CI runs the same remote verification. The lock includes transitive
  composite-action dependencies; it does not lock remote reusable workflows,
  whose SHA pins must be reviewed separately.
- After csm-ci distributes new caller workflows, regenerate the action lock
  and include it in a follow-up PR. The server does not generate this lock.
- `mise run fix` updates action pins, checkout settings, and the action lock.
  Review the changes before committing. Keep csm-ci-generated callers managed
  by csm-ci rather than applying repository-specific workflow structure to them.

When adding or changing CI, run `mise run lint`, `mise run test`, and the
relevant workflow checks. Verify that `status-check` fails when an included
check fails and succeeds only after all applicable checks pass.
