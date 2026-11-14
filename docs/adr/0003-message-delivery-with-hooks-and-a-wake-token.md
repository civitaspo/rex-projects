---
status: accepted
---

# Message delivery with hooks and a wake token

Messages to an Agent go into its inbox in the state database, and the Agent reads them with `inbox_read`. rex-projects makes an interactive Agent notice new messages in this order:

1. When a turn ends with unread messages, the Stop hook returns `decision: block` with the messages, so the turn continues.
2. When a human submits a prompt, the UserPromptSubmit hook adds unread messages as context.
3. When the Agent is `idle` and has unread messages, `serve` types one fixed line, the wake token (for example `/rxp-inbox`), into its terminal.

`serve` never types a message body. It types the wake token only when all of these hold, rechecking them immediately before typing:

- the Agent's status is `idle`, not `blocked` (for example on a permission prompt);
- the Agent has been `idle` for at least 30 seconds, so a human who is mid-reply has time to submit;
- the terminal's current input line is empty, read from the terminal screen right before typing.

The check and the keystrokes are not atomic, so a short race window remains. If the token lands in a permission prompt or in a human's partial input, it is harmless text: the harness rejects it or the human sees it and deletes it, and the messages stay unread for the next attempt. Replies never trigger further replies.

## Considered Options

- **Never type into a terminal.** This would require a managed runtime that drives each harness over its structured protocol. Rejected because it costs far more to build and keep current, and the fixed token limits what a misdelivered keystroke can do.

## Consequences

Whether Codex supports a Stop hook that can continue a turn is unverified. If it does not, Codex Agents rely on the wake token alone.
