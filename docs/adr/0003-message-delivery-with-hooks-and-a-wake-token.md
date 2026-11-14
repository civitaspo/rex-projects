---
status: accepted
---

# Message delivery with hooks and a wake token

Messages to an Agent go into its inbox in the state database, and the Agent reads them with `inbox_read`. rex-projects makes an interactive Agent notice new messages in this order:

1. When a turn ends with unread messages, the Stop hook returns `decision: block` with the messages, so the turn continues.
2. When a human submits a prompt, the UserPromptSubmit hook adds unread messages as context.
3. When the Agent is `idle` and has unread messages, `serve` types one fixed line, the wake token (for example `/rxp-inbox`), into its terminal.

`serve` never types a message body, and it never types while the Agent is `blocked`, for example on a permission prompt. Replies never trigger further replies.

## Considered Options

- **Never type into a terminal.** This would require a managed runtime that drives each harness over its structured protocol. Rejected because it costs far more to build and keep current, and the fixed token limits what a misdelivered keystroke can do.

## Consequences

Whether Codex supports a Stop hook that can continue a turn is unverified. If it does not, Codex Agents rely on the wake token alone.
