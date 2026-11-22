---
name: default
description: Plan, implement, verify, and review changes to this repository.
rex-projects:
  stages: [plan, implement, verify, review]
  roles: [worker, reviewer, verifier]
  gates:
    implement: plan
  verification:
    checks:
      - name: lint
        argv: [mise, run, lint]
        timeout_minutes: 15
      - name: test
        argv: [mise, run, test]
        timeout_minutes: 15
      - name: required PR checks
        argv: [gh, pr, checks, --required, --watch]
        timeout_minutes: 30
    verifier:
      role: verifier
  budgets:
    helpers: 6
    minutes: 240
---

# Working in rex-projects

Read `AGENTS.md` before changing the repository. It defines the project’s language, Git, review, and validation rules. Read the relevant ADRs and existing code before changing behavior, and keep each change focused on the Ticket’s Brief.

## Plan

Before implementation, inspect the affected paths and write a short plan that names the behavior to change, the files involved, and how you will verify it. Request the `plan` approval with the plan and relevant paths. Wait for the human’s decision before entering `implement` or changing repository files.

## Implement

Follow `AGENTS.md`. Preserve event replay compatibility when changing persisted events. Keep personal configuration and policy outside the repository. Do not merge pull requests. If a decision materially changes the requested behavior, ask the human before proceeding.

## Verify

Run the declared lint, test, and required pull request checks. Open the pull request before the required checks step so `gh pr checks --required --watch` has a current pull request to inspect. Also exercise the changed behavior through the CLI or UI when practical, and include the observed result in your completion summary. Report failures and limitations clearly.

## Review

Inspect the full diff for correctness, compatibility, and accidental changes. Address actionable review findings. Open a pull request when the repository instructions require one, then report its URL and status to the human.
