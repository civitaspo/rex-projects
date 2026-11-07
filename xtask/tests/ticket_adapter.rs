use std::{collections::BTreeMap, ffi::OsString, time::Duration};

use rex_projects::adapters::tickets::{
    DuplicateResolutionRequest, NormalizedTicketStatus, OperationFindRequest,
    ReconciliationOutcome, TicketAdapterError, TicketCommandAdapter, TicketCommentRequest,
    TicketCreateRequest, TicketGetRequest, TicketListRequest, TicketScope, TicketUpdateRequest,
};
use rex_projects::domain::ids::{OperationId, ProjectId};
use rex_projects::protocol::RequestId;
use serde_json::json;
use tempfile::TempDir;

fn adapter(
    dir: &TempDir,
    shape: &str,
    drop_once: Option<&str>,
    delay: u64,
    mutation: Option<&str>,
) -> TicketCommandAdapter {
    let mut command = vec![
        env!("CARGO_BIN_EXE_xtask").into(),
        "fixture".into(),
        "ticket".into(),
        "--database".into(),
        dir.path().join("tickets.sqlite").display().to_string(),
        "--namespace".into(),
        "fixture/tenant-a".into(),
        "--index-delay-ms".into(),
        delay.to_string(),
        "--native-shape".into(),
        shape.into(),
    ];
    if let Some(value) = drop_once {
        command.extend(["--drop-create-response-once".into(), value.into()]);
    }
    if let Some(value) = mutation {
        command.extend(["--mutate-response".into(), value.into()]);
    }
    let snapshot = BTreeMap::from([(
        OsString::from("PATH"),
        std::env::var_os("PATH").unwrap_or_default(),
    )]);
    TicketCommandAdapter::new_discovering_namespace(
        &command,
        &snapshot,
        &[],
        dir.path(),
        Duration::from_secs(5),
        Duration::from_millis(100),
    )
    .unwrap()
}
fn req(value: &str) -> RequestId {
    RequestId::new(value).unwrap()
}
fn op(value: &str) -> OperationId {
    OperationId::parse(value).unwrap()
}
fn project() -> Option<ProjectId> {
    Some(ProjectId::parse("project-1").unwrap())
}
fn scope(value: &str) -> TicketScope {
    TicketScope::new(BTreeMap::from([("project".into(), value.into())])).unwrap()
}
fn create(scope: TicketScope, key: &str, title: &str) -> TicketCreateRequest {
    TicketCreateRequest {
        scope,
        creation_key: key.into(),
        title: title.into(),
        body: "Body".into(),
        status: Some(NormalizedTicketStatus::Ready),
        template: None,
        parent: None,
        dependencies: None,
        project: None,
        milestone: None,
        assignee: None,
        priority: None,
        due_date: None,
        labels: Some(vec!["fixture".into()]),
    }
}
fn list(scope: TicketScope, size: u32, cursor: Option<String>) -> TicketListRequest {
    TicketListRequest {
        scope,
        status: None,
        assignee: None,
        project: None,
        milestone: None,
        release: None,
        labels: Some(vec!["fixture".into()]),
        query: None,
        cursor,
        page_size: Some(size),
        updated_since: None,
    }
}

#[test]
fn unrelated_native_shapes_normalize_through_the_external_command() {
    for shape in ["record", "edges"] {
        let dir = tempfile::tempdir().unwrap();
        let adapter = adapter(&dir, shape, None, 0, None);
        assert_eq!(
            adapter.describe(req("describe")).unwrap().ticket_namespace,
            "fixture/tenant-a"
        );
        let ticket = adapter
            .create(
                req("create"),
                op("create"),
                project(),
                create(scope("external-project"), "key", "Normalized title"),
            )
            .unwrap()
            .ticket;
        let got = adapter
            .get(
                req("get"),
                project(),
                TicketGetRequest {
                    scope: scope("external-project"),
                    ticket_id: ticket.id,
                    timeline_limit: None,
                },
            )
            .unwrap();
        assert_eq!(got.ticket.title, "Normalized title");
        assert_eq!(got.ticket.status.value, NormalizedTicketStatus::Ready);
        assert_eq!(got.ticket.revision.as_deref(), Some("rev-1"));
    }
}

#[test]
fn typed_operations_enforce_scope_revision_pagination_and_duplicate_receipts() {
    let dir = tempfile::tempdir().unwrap();
    let adapter = adapter(&dir, "record", None, 0, None);
    assert!(
        adapter
            .describe(req("describe"))
            .unwrap()
            .capabilities
            .conditional_revision_mutation
    );
    let ticket_scope = scope("external-project");
    let first = adapter
        .create(
            req("create-a"),
            op("create-a"),
            project(),
            create(ticket_scope.clone(), "key-a", "A"),
        )
        .unwrap();
    let second = adapter
        .create(
            req("create-b"),
            op("create-b"),
            project(),
            create(ticket_scope.clone(), "key-b", "B"),
        )
        .unwrap();
    let page = adapter
        .list(
            req("page-a"),
            project(),
            list(ticket_scope.clone(), 1, None),
        )
        .unwrap();
    assert_eq!(page.tickets.len(), 1);
    let cursor = page.next_cursor.unwrap();
    assert_eq!(
        adapter
            .list(
                req("page-b"),
                project(),
                list(ticket_scope.clone(), 1, Some(cursor.clone()))
            )
            .unwrap()
            .tickets
            .len(),
        1
    );
    assert!(
        matches!(adapter.list(req("bad-cursor"), project(), list(scope("other"), 1, Some(cursor))), Err(TicketAdapterError::Application(error)) if matches!(error.code, rex_projects::protocol::ErrorCode::Conflict))
    );
    assert!(
        matches!(adapter.update(req("stale"), op("stale"), project(), TicketUpdateRequest { scope: ticket_scope.clone(), ticket_id: first.ticket.id.clone(), expected_revision: "rev-0".into(), patch: BTreeMap::from([("title".into(), json!("stale"))]) }), Err(TicketAdapterError::Application(error)) if matches!(error.code, rex_projects::protocol::ErrorCode::Conflict))
    );
    adapter
        .comment(
            req("comment"),
            op("comment"),
            project(),
            TicketCommentRequest {
                scope: ticket_scope.clone(),
                ticket_id: first.ticket.id.clone(),
                comment_key: "comment-key".into(),
                body: "Progress".into(),
                references: vec![],
            },
        )
        .unwrap();
    let resolved = adapter
        .resolve_duplicate(
            req("duplicate"),
            op("duplicate"),
            project(),
            DuplicateResolutionRequest {
                scope: ticket_scope,
                duplicate_ticket_id: second.ticket.id,
                canonical_ticket_id: first.ticket.id,
                operation_key: "duplicate-key".into(),
                reason: "same work".into(),
            },
        )
        .unwrap();
    assert_eq!(
        resolved.duplicate.status.value,
        NormalizedTicketStatus::Canceled
    );
}

#[test]
fn uncertain_create_and_delayed_index_are_reconciled_without_retry() {
    let dir = tempfile::tempdir().unwrap();
    let adapter = adapter(&dir, "edges", Some("create-lost"), 250, None);
    let ticket_scope = scope("external-project");
    assert!(matches!(
        adapter.create(
            req("lost"),
            op("create-lost"),
            project(),
            create(ticket_scope.clone(), "lost-key", "Lost")
        ),
        Err(TicketAdapterError::Uncertain)
    ));
    let exact = adapter
        .find_operation(
            req("exact"),
            project(),
            OperationFindRequest {
                scope: ticket_scope.clone(),
                operation_id: "create-lost".into(),
                method: "ticket.create".into(),
                stable_external_key: "lost-key".into(),
                subject: BTreeMap::from([("creation_key".into(), "lost-key".into())]),
            },
        )
        .unwrap();
    assert!(matches!(exact.outcome, ReconciliationOutcome::Found));
    adapter
        .create(
            req("delayed-create"),
            op("delayed-create"),
            project(),
            create(ticket_scope.clone(), "delayed-key", "Delayed"),
        )
        .unwrap();
    let find = || {
        adapter
            .find_operation(
                req("delayed-find"),
                project(),
                OperationFindRequest {
                    scope: ticket_scope.clone(),
                    operation_id: "not-indexed-yet".into(),
                    method: "ticket.create".into(),
                    stable_external_key: "delayed-key".into(),
                    subject: BTreeMap::from([("creation_key".into(), "delayed-key".into())]),
                },
            )
            .unwrap()
    };
    assert!(matches!(find().outcome, ReconciliationOutcome::Unknown));
    std::thread::sleep(Duration::from_millis(300));
    let visible = find();
    assert!(matches!(visible.outcome, ReconciliationOutcome::Found));
    assert_eq!(visible.matches.len(), 1);
}

#[test]
fn receipts_for_another_requested_identity_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let ticket_scope = scope("external-project");
    let base = adapter(&dir, "record", None, 0, None);
    let first = base
        .create(
            req("seed"),
            op("seed"),
            project(),
            create(ticket_scope.clone(), "seed-key", "Seed"),
        )
        .unwrap();
    let second = base
        .create(
            req("second"),
            op("second"),
            project(),
            create(ticket_scope.clone(), "second-key", "Second"),
        )
        .unwrap();
    let settings = TicketUpdateRequest {
        scope: ticket_scope.clone(),
        ticket_id: first.ticket.id.clone(),
        expected_revision: "rev-1".into(),
        patch: BTreeMap::from([("title".into(), json!("Updated"))]),
    };
    base.update(req("update"), op("update"), project(), settings.clone())
        .unwrap();
    assert!(matches!(
        adapter(&dir, "record", None, 0, Some("get-ticket-id")).get(
            req("bad-get"),
            project(),
            TicketGetRequest {
                scope: ticket_scope.clone(),
                ticket_id: first.ticket.id.clone(),
                timeline_limit: None
            }
        ),
        Err(TicketAdapterError::Protocol(_))
    ));
    let mut update = settings;
    update.expected_revision = "rev-2".into();
    assert!(matches!(
        adapter(&dir, "record", None, 0, Some("update-ticket-id")).update(
            req("bad-update"),
            op("bad-update"),
            project(),
            update
        ),
        Err(TicketAdapterError::Protocol(_))
    ));
    assert!(matches!(
        adapter(&dir, "record", None, 0, Some("comment-key")).comment(
            req("bad-comment"),
            op("bad-comment"),
            project(),
            TicketCommentRequest {
                scope: ticket_scope.clone(),
                ticket_id: first.ticket.id.clone(),
                comment_key: "requested-key".into(),
                body: "body".into(),
                references: vec![]
            }
        ),
        Err(TicketAdapterError::Protocol(_))
    ));
    assert!(matches!(
        adapter(&dir, "record", None, 0, Some("duplicate-key")).resolve_duplicate(
            req("bad-duplicate"),
            op("bad-duplicate"),
            project(),
            DuplicateResolutionRequest {
                scope: ticket_scope.clone(),
                duplicate_ticket_id: second.ticket.id.clone(),
                canonical_ticket_id: first.ticket.id.clone(),
                operation_key: "requested-key".into(),
                reason: "same".into()
            }
        ),
        Err(TicketAdapterError::Protocol(_))
    ));
    assert!(matches!(
        adapter(&dir, "record", None, 0, Some("operation-id")).find_operation(
            req("bad-op"),
            project(),
            OperationFindRequest {
                scope: ticket_scope.clone(),
                operation_id: "seed".into(),
                method: "ticket.create".into(),
                stable_external_key: "seed-key".into(),
                subject: BTreeMap::from([("creation_key".into(), "seed-key".into())])
            }
        ),
        Err(TicketAdapterError::Protocol(_))
    ));
    assert!(matches!(
        adapter(&dir, "record", None, 0, Some("operation-ticket-id")).find_operation(
            req("bad-subject"),
            project(),
            OperationFindRequest {
                scope: ticket_scope,
                operation_id: "update".into(),
                method: "ticket.update".into(),
                stable_external_key: "update-key".into(),
                subject: BTreeMap::from([("ticket_id".into(), first.ticket.id)])
            }
        ),
        Err(TicketAdapterError::Protocol(_))
    ));
}
