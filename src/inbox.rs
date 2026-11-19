//! Agent inboxes (ADR-0003). Messages wait in the state database until the
//! Agent reads them with `inbox_read` or a hook hands them to the harness.

use anyhow::Result;

use crate::domain::{Event, Message};
use crate::store::Store;

/// The longest message body accepted, in characters.
pub const MAX_BODY_CHARS: usize = 20_000;
/// Roughly how much message text one read or hook hands over, in characters.
/// The first unread message is always included, so a read always progresses.
const MAX_BATCH_CHARS: usize = 24_000;

/// Marks the oldest unread messages of `agent_id` as read and returns them,
/// with the number still unread after them.
pub fn take(store: &mut Store, agent_id: &str) -> Result<(Vec<Message>, usize)> {
    let unread = store.unread(agent_id)?;
    let mut size = 0;
    let count = unread
        .iter()
        .take_while(|m| {
            // Count what `render` prints for the message, not just its body.
            size += m.body.chars().count() + m.from.chars().count() + m.sent_at.len() + 16;
            size <= MAX_BATCH_CHARS
        })
        .count()
        .max(1)
        .min(unread.len());
    let (taken, rest) = unread.split_at(count);
    if let Some(last) = taken.last() {
        store.append(
            agent_id,
            Event::MessagesRead {
                agent_id: agent_id.to_owned(),
                through: last.id,
            },
        )?;
    }
    Ok((taken.to_vec(), rest.len()))
}

/// Formats messages for a harness hook, or `None` when there are none.
pub fn render(messages: &[Message], remaining: usize) -> Option<String> {
    if messages.is_empty() {
        return None;
    }
    let mut text = format!(
        "rex-projects delivered {} new message(s) to your inbox:\n",
        messages.len()
    );
    for m in messages {
        text.push_str(&format!(
            "\nFrom {} at {}:\n{}\n",
            m.from, m.sent_at, m.body
        ));
    }
    if remaining > 0 {
        text.push_str(&format!(
            "\n{remaining} more unread message(s); call `inbox_read` to read them.\n"
        ));
    }
    Some(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Event;

    fn store_with_agent() -> Store {
        let mut store = Store::open_in_memory().unwrap();
        store
            .create_ticket(
                "human",
                crate::store::NewTicket {
                    project_id: "demo".into(),
                    title: "t".into(),
                    ..Default::default()
                },
            )
            .unwrap();
        store
            .append(
                "serve",
                Event::AgentCreated {
                    agent_id: "demo-1-coordinator".into(),
                    ticket_id: "demo-1".into(),
                    project_id: "demo".into(),
                    role: "coordinator".into(),
                    provider: "claude".into(),
                    cwd: "/tmp".into(),
                },
            )
            .unwrap();
        store
    }

    fn send(store: &mut Store, body: &str) {
        store
            .append(
                "demo-1-worker-1",
                Event::MessageSent {
                    ticket_id: "demo-1".into(),
                    from: "demo-1-worker-1".into(),
                    to: "demo-1-coordinator".into(),
                    body: body.into(),
                },
            )
            .unwrap();
    }

    #[test]
    fn takes_unread_messages_once() {
        let mut store = store_with_agent();
        assert_eq!(take(&mut store, "demo-1-coordinator").unwrap().0, vec![]);
        send(&mut store, "first");
        send(&mut store, "second");
        let (messages, remaining) = take(&mut store, "demo-1-coordinator").unwrap();
        let bodies: Vec<_> = messages.iter().map(|m| m.body.as_str()).collect();
        assert_eq!(bodies, ["first", "second"]);
        assert_eq!(remaining, 0);
        let text = render(&messages, remaining).unwrap();
        assert!(text.contains("From demo-1-worker-1"), "{text}");
        assert!(text.contains("second"), "{text}");
        assert!(take(&mut store, "demo-1-coordinator").unwrap().0.is_empty());

        // Rebuilding the projections keeps messages read.
        store.rebuild().unwrap();
        assert!(store.unread("demo-1-coordinator").unwrap().is_empty());
        assert_eq!(store.ticket_messages("demo-1").unwrap().len(), 2);
    }

    #[test]
    fn hands_over_large_inboxes_in_batches() {
        let mut store = store_with_agent();
        let big = "x".repeat(MAX_BATCH_CHARS - 10);
        send(&mut store, &big);
        send(&mut store, &big);
        let (messages, remaining) = take(&mut store, "demo-1-coordinator").unwrap();
        assert_eq!((messages.len(), remaining), (1, 1));
        assert!(
            render(&messages, remaining)
                .unwrap()
                .contains("1 more unread")
        );
        let (messages, remaining) = take(&mut store, "demo-1-coordinator").unwrap();
        assert_eq!((messages.len(), remaining), (1, 0));
    }

    #[test]
    fn counts_each_message_header_toward_a_batch() {
        let mut store = store_with_agent();
        for _ in 0..2000 {
            send(&mut store, "x");
        }
        let (messages, remaining) = take(&mut store, "demo-1-coordinator").unwrap();
        assert!(messages.len() < 2000 && remaining > 0, "{}", messages.len());
        let text = render(&messages, remaining).unwrap();
        assert!(
            text.chars().count() <= MAX_BATCH_CHARS + 200,
            "{}",
            text.len()
        );
    }

    #[test]
    fn rejects_messages_to_other_tickets_agents() {
        let mut store = store_with_agent();
        let err = store
            .append(
                "x",
                Event::MessageSent {
                    ticket_id: "demo-2".into(),
                    from: "x".into(),
                    to: "demo-1-coordinator".into(),
                    body: "hi".into(),
                },
            )
            .unwrap_err();
        assert!(err.to_string().contains("not demo-2"), "{err}");
        let err = store
            .append(
                "x",
                Event::MessageSent {
                    ticket_id: "demo-1".into(),
                    from: "x".into(),
                    to: "nobody".into(),
                    body: "hi".into(),
                },
            )
            .unwrap_err();
        assert!(err.to_string().contains("does not exist"), "{err}");
    }
}
