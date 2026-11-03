# AGENTS.md

- Write all repository text and public repository communication, including issues, pull requests, reviews, and comments, in English.
- Use signed commits and Conventional Commit pull request titles.
- End each commit message with a `Co-authored-by` trailer for the agent that wrote it, such as `Co-authored-by: Codex <noreply@openai.com>` or `Co-authored-by: Claude <noreply@anthropic.com>`. These addresses link to the agents' GitHub accounts.
- Squash merges use the pull request description as the commit message. End the description with one such trailer for every agent that has committed to the pull request, and add trailers as new agents commit.
- Use pull requests for changes to the default branch.
- Request a squash merge with `/merge` after required checks and approval pass.
- Add project checks to CI when the project gains tooling or source code.
- Install tools with `mise install`; run `mise run lint` and `mise run test` before submitting changes.
- Run `mise run fix` to apply supported automatic fixes.
- Before creating or changing GitHub Actions workflows, composite actions, CI scripts, or CI configuration, read and follow [docs/github-actions.md](docs/github-actions.md).
- Verify each commit trailer before pushing. After automated PR body updates finish and immediately before requesting a squash merge, put every contributing agent trailer at the end of the PR body, separated by a blank line, with no text after it. Verify the merged commit trailers with `git show -s --format=%B <merge-sha> | git interpret-trailers --parse`.
