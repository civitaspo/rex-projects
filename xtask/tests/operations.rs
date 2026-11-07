use std::time::Duration;

use rex_projects::config::OperationActionConfig;
use rex_projects::domain::ids::{Digest, OperationId, ProjectId, RepositoryId};
use rex_projects::operations::{
    AdapterCall, FindOutcome, FindParams, FindResult, InvokeParams, ProcessCommandRunner,
    call_command_adapter, new_request,
};
use std::collections::BTreeMap;

const SOURCE_SHA: &str = "0123456789abcdef0123456789abcdef01234567";

fn fixture_action(state_dir: &std::path::Path) -> OperationActionConfig {
    OperationActionConfig::Command {
        command: vec![
            env!("CARGO_BIN_EXE_xtask").into(),
            "fixture".into(),
            "operations".into(),
            "--state-dir".into(),
            state_dir.display().to_string(),
        ],
    }
}

#[test]
fn lost_invoke_reply_is_reconciled_from_persisted_operation_state() {
    let state_dir = tempfile::tempdir().expect("temporary fixture state");
    let action = fixture_action(state_dir.path());
    let mut runner = ProcessCommandRunner::new(Duration::from_secs(1)).unwrap();
    let invoke = new_request(
        "fixture-invoke",
        Some(OperationId::parse("fixture-lost-reply").unwrap()),
        Some(ProjectId::parse("operations_project").unwrap()),
        "operation.invoke",
        InvokeParams {
            action_id: "fixture_lost_reply".into(),
            target_id: "fixture-target".into(),
            repository_id: RepositoryId::parse("example").unwrap(),
            environment: "test".into(),
            source_sha: SOURCE_SHA.into(),
            plan_digest: Digest::parse("d".repeat(64)).unwrap(),
            correlation_key: "fixture-lost-reply-correlation".into(),
            selector: BTreeMap::new(),
            parameters: BTreeMap::new(),
            expected_preconditions: BTreeMap::new(),
            approval_digest: None,
        },
    )
    .unwrap();

    let first = call_command_adapter(&mut runner, &action, &invoke, Duration::from_secs(5))
        .expect("invoke transport returns uncertainty for dropped reply");
    assert!(matches!(first, AdapterCall::Uncertain(_)));

    let find = new_request(
        "fixture-find",
        Some(OperationId::parse("fixture-lost-reply").unwrap()),
        Some(ProjectId::parse("operations_project").unwrap()),
        "operation.find",
        FindParams {
            operation_id: OperationId::parse("fixture-lost-reply").unwrap(),
            correlation_key: "fixture-lost-reply-correlation".into(),
            action_id: "fixture_lost_reply".into(),
            target_id: "fixture-target".into(),
            repository_id: RepositoryId::parse("example").unwrap(),
            environment: "test".into(),
            source_sha: SOURCE_SHA.into(),
        },
    )
    .unwrap();
    let response = call_command_adapter(&mut runner, &action, &find, Duration::from_secs(5))
        .expect("find protocol response");
    let AdapterCall::Response(response) = response else {
        panic!("find response should not be uncertain");
    };
    let found: FindResult = serde_json::from_value(response.result.expect("find result payload"))
        .expect("find result schema");
    assert_eq!(found.outcome, FindOutcome::Found);
    found
        .validate_for(&find.params)
        .expect("exact operation binding");
    assert_eq!(
        found.external_reference.as_deref(),
        Some("fixture-run:fixture-lost-reply")
    );
}
