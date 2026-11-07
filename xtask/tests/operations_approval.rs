use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rex_projects::config::{
    AppliedConfig, Config, OperationActionConfig, OperationRecipe, OperationTarget,
    RepositoryOperationsConfig, SuccessPredicate,
};
use rex_projects::domain::ids::{
    Digest, HumanRequestId, ProjectId, RepositoryId, Revision, TicketId, TicketNamespace,
    TicketRunId,
};
use rex_projects::domain::types::{ApprovalMode, OperationSource};
use rex_projects::effects::{
    EffectContext, EffectHandler, EffectMode, EffectObservation, EffectRequest,
};
use rex_projects::human_runtime::{
    DurableHumanSubjectObserver, HumanDecisionChoice, HumanDecisionIntent,
    HumanPresenterEffectHandler, HumanPurpose, HumanSubjectKind, HumanSubjectObserver,
    process_queued_human_responses,
};
use rex_projects::launch::{RexView, RexViewKind};
use rex_projects::operations::{DeliveryFacts, validate_recipe};
use rex_projects::operations_runtime::{OperationEffectHandler, OperationExecutionMode};
use rex_projects::store::host_jobs::{HostJobState, OperationMethod};
use rex_projects::store::operations::DurableOperationState;
use rex_projects::store::{ConfigStore, ExpectedRevision, OwnerMetadata, ProjectRecord};

const SOURCE_SHA: &str = "0123456789abcdef0123456789abcdef01234567";

struct XdgStateHomeGuard(Option<std::ffi::OsString>);

impl XdgStateHomeGuard {
    fn set(path: &std::path::Path) -> Self {
        let prior = std::env::var_os("XDG_STATE_HOME");
        unsafe { std::env::set_var("XDG_STATE_HOME", path) };
        Self(prior)
    }
}

impl Drop for XdgStateHomeGuard {
    fn drop(&mut self) {
        match self.0.take() {
            Some(previous) => unsafe { std::env::set_var("XDG_STATE_HOME", previous) },
            None => unsafe { std::env::remove_var("XDG_STATE_HOME") },
        }
    }
}

#[test]
fn queued_human_approval_gates_operation_fixture_invoke_and_reconcile() {
    let temp = tempfile::tempdir().expect("temporary operation state");
    let isolated_xdg = temp.path().join("xdg-state");
    let _xdg_state_home = XdgStateHomeGuard::set(&isolated_xdg);
    let fixture_state = temp.path().join("fixture-state");
    let mut config: Config = toml::from_str(include_str!("../../examples/fixture/config.toml"))
        .expect("public fixture configuration parses");
    config.operation_actions.insert(
        "fixture_lost_reply".into(),
        OperationActionConfig::Command {
            command: vec![
                env!("CARGO_BIN_EXE_xtask").into(),
                "fixture".into(),
                "operations".into(),
                "--state-dir".into(),
                fixture_state.display().to_string(),
            ],
        },
    );
    let repository_id = RepositoryId::parse("example").unwrap();
    config
        .repositories
        .get_mut(&repository_id)
        .expect("fixture repository")
        .operations = Some(RepositoryOperationsConfig {
        recipe: "rollout".into(),
        allowed_actions: vec!["fixture_lost_reply".into()],
        human_approval_environments: vec![],
        instruction_files: vec![],
    });
    config.operation_recipes.insert(
        "rollout".into(),
        OperationRecipe {
            roles: BTreeMap::new(),
            required_stages: vec![],
            required_evidence: vec![],
            targets: vec![OperationTarget {
                id: "deploy_fixture".into(),
                repository: repository_id.clone(),
                environment: "test".into(),
                action: "fixture_lost_reply".into(),
                depends_on: vec![],
                source: OperationSource::parse("merge_commit").unwrap(),
                selector: BTreeMap::new(),
                success_predicate: SuccessPredicate::TargetSucceeded,
                timeout_seconds: 20,
                approval: ApprovalMode::Always,
            }],
            not_required_reason: None,
        },
    );
    let applied = AppliedConfig {
        config,
        profiles: BTreeMap::new(),
        source_root: "/fixture".into(),
        source_files: vec![],
        digest: Digest::parse("a".repeat(64)).unwrap(),
    };

    let state_root = temp.path().join("controller-state");
    let mut store = ConfigStore::open(&state_root).expect("open isolated state store");
    let project_id = ProjectId::parse("operations_project").unwrap();
    let ticket_id = TicketId::parse("PAY-approval").unwrap();
    let ticket_run_id = TicketRunId::parse("approval-run").unwrap();
    let ticket_namespace = TicketNamespace::parse("github:org/repo").unwrap();
    let config_revision = store
        .apply_snapshot("factory", &applied, ExpectedRevision::Bootstrap)
        .unwrap();
    store
        .insert_project(&ProjectRecord {
            id: project_id.clone(),
            config_source: "factory".into(),
            config_revision: config_revision.revision,
            config_digest: config_revision.digest.clone(),
            mode: "operations".into(),
            goal_revision: 0,
            desired_lifecycle: "running".into(),
            state_revision: Revision(0),
        })
        .unwrap();
    let owner = OwnerMetadata {
        owner_nonce: "approval-owner".into(),
        state_root: temp.path().to_string_lossy().into_owned(),
        config_source: "factory".into(),
        process_start_identity: "approval-owner".into(),
        executable_path: "/tmp/rex-projects-fixture".into(),
        executable_digest: "b".repeat(64),
        rex_endpoint: None,
        rex_server_identity: None,
        rex_session_id: None,
        rex_block_id: None,
    };
    let generation = store.start_owner(&owner).unwrap();
    store
        .create_ticket_run(
            generation,
            &project_id,
            &ticket_namespace,
            &ticket_id,
            &ticket_run_id,
            1,
            "operating",
            "In Progress",
        )
        .unwrap();
    let rex_view = RexView {
        view_id: RexView::derive_id(
            &project_id,
            RexViewKind::Ticket,
            Some(ticket_namespace.as_str()),
            Some(ticket_id.as_str()),
            1,
        )
        .unwrap(),
        project_id: project_id.clone(),
        kind: RexViewKind::Ticket,
        ticket_namespace: Some(ticket_namespace.to_string()),
        ticket_id: Some(ticket_id.to_string()),
        view_epoch: 1,
        rex_server_identity: "fixture-server".into(),
        rex_session_id: "fixture-session".into(),
        rex_window_id: "ticket-window".into(),
    };
    store.register_rex_view(generation, &rex_view).unwrap();

    let plan = validate_recipe(&applied.config, "rollout").unwrap();
    let target = &plan.targets()[0];
    let delivery = DeliveryFacts {
        merge_commits: BTreeMap::from([(target.repository.clone(), SOURCE_SHA.into())]),
        planned_revisions: BTreeMap::new(),
    };
    let operation_id = store
        .operations()
        .unwrap()
        .persist_plan(
            generation,
            &project_id,
            &ticket_id,
            &ticket_run_id,
            Revision(0),
            config_revision.revision,
            &applied,
            &plan,
            &delivery,
            100,
        )
        .unwrap()[0]
        .clone();
    let intent = store
        .operation_approval_intent(&operation_id)
        .unwrap()
        .expect("approval-required operation has a typed human review request");
    let approval_id = HumanRequestId::parse(intent.approval_request_id.unwrap()).unwrap();
    let host_jobs = Arc::new(Mutex::new(
        rex_projects::host_jobs::HostJobPool::new(4, 1).unwrap(),
    ));
    let host_environment = [
        (
            std::ffi::OsString::from("PATH"),
            std::env::var_os("PATH").unwrap(),
        ),
        (
            std::ffi::OsString::from("XDG_STATE_HOME"),
            isolated_xdg.as_os_str().to_owned(),
        ),
    ]
    .into_iter()
    .collect();
    let operation_handler = OperationEffectHandler::with_host_jobs(
        [applied.clone()],
        Duration::from_secs(2),
        Arc::clone(&host_jobs),
        host_environment,
        Digest::parse("c".repeat(64)).unwrap(),
    )
    .unwrap();

    let operation_claim = store
        .claim_next_due_effect(generation, 100, &["operation".into()])
        .unwrap()
        .expect("operation remains durably queued");
    let operation_effect = EffectRequest::from(operation_claim);
    let before_approval = {
        let mut context = EffectContext {
            store: &mut store,
            owner_generation: generation,
            now_unix: 100,
        };
        EffectHandler::handle(
            &operation_handler,
            EffectMode::Submit,
            &operation_effect,
            &mut context,
        )
        .unwrap()
    };
    assert!(matches!(before_approval, EffectObservation::Pending { .. }));
    assert!(
        !fixture_state.exists(),
        "approval must precede external invocation"
    );

    let human_claim = store
        .claim_next_due_effect(generation, 100, &["request_human_review".into()])
        .unwrap()
        .expect("plan enqueues the typed human review effect");
    let human_effect = EffectRequest::from(human_claim);
    let artifact_root = temp.path().join("human-artifacts");
    std::fs::create_dir_all(&artifact_root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&artifact_root, std::fs::Permissions::from_mode(0o700))
            .expect("private human artifact directory");
    }
    let observer = Arc::new(
        DurableHumanSubjectObserver::new(temp.path().join("declarative-config"))
            .expect("durable operation observer"),
    );
    let presenter = HumanPresenterEffectHandler::new(
        "local_html",
        vec!["/usr/bin/true".into()],
        BTreeMap::new(),
        artifact_root,
        observer.clone(),
    )
    .unwrap();
    let presented = {
        let mut context = EffectContext {
            store: &mut store,
            owner_generation: generation,
            now_unix: 100,
        };
        presenter
            .handle(EffectMode::Submit, &human_effect, &mut context)
            .unwrap()
    };
    assert!(matches!(presented, EffectObservation::Pending { .. }));
    let request = store
        .current_human_request(&approval_id)
        .unwrap()
        .expect("presenter registered request in durable inbox")
        .request;
    assert_eq!(request.purpose, HumanPurpose::OperationApproval);
    assert_eq!(request.subject.kind, HumanSubjectKind::Operation);
    assert_eq!(request.subject.ticket_run_id.as_ref(), Some(&ticket_run_id));

    let decision = HumanDecisionIntent {
        request_id: approval_id.clone(),
        response_id: "operation-approval-response".into(),
        expected_subject_digest: request.subject.digest().unwrap(),
        choice: HumanDecisionChoice::Approve,
        explanation: Some("Approve this exact fixture operation.".into()),
    };
    ConfigStore::enqueue_human_decision(&state_root, &decision, 101).unwrap();
    let processed =
        process_queued_human_responses(&mut store, generation, 10, 102, |store, request| {
            observer.observe_current_subject(store, request)
        })
        .unwrap();
    assert_eq!(processed.len(), 1);
    assert!(matches!(
        processed[0].result,
        rex_projects::store::human::HumanDecisionResult::Applied
    ));

    let fixture_receipt = fixture_state.join(format!("{operation_id}.json"));
    let invoke_job =
        rex_projects::host_jobs::stable_host_job_id(operation_id.as_str(), "operation.invoke", 1);
    let invoke_deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let mut context = EffectContext {
            store: &mut store,
            owner_generation: generation,
            now_unix: 103,
        };
        let outcome = EffectHandler::handle(
            &operation_handler,
            EffectMode::Submit,
            &operation_effect,
            &mut context,
        )
        .unwrap();
        assert!(matches!(outcome, EffectObservation::Pending { .. }));
        if fixture_receipt.exists()
            && store
                .operations()
                .unwrap()
                .operation(&operation_id)
                .unwrap()
                .unwrap()
                .state
                == DurableOperationState::Unknown
        {
            break;
        }
        assert!(
            Instant::now() < invoke_deadline,
            "pooled invoke did not settle"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        fixture_receipt.exists(),
        "approved operation reached fixture adapter"
    );
    assert_eq!(
        store
            .operations()
            .unwrap()
            .operation(&operation_id)
            .unwrap()
            .unwrap()
            .state,
        DurableOperationState::Unknown,
        "lost invoke response must remain uncertain until exact reconciliation"
    );

    let reconcile_deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let mut context = EffectContext {
            store: &mut store,
            owner_generation: generation,
            now_unix: 104,
        };
        let reconciled = operation_handler
            .handle(
                OperationExecutionMode::Reconcile,
                &operation_effect.intent,
                operation_effect.attempt_count,
                &mut context,
            )
            .unwrap();
        if matches!(
            reconciled,
            rex_projects::operations_runtime::OperationExecutionOutcome::Applied { .. }
        ) {
            break;
        }
        assert!(
            matches!(
                reconciled,
                rex_projects::operations_runtime::OperationExecutionOutcome::Pending { .. }
            ),
            "reconciliation returned: {reconciled:?}"
        );
        assert!(
            Instant::now() < reconcile_deadline,
            "pooled reconciliation did not settle"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        store
            .operations()
            .unwrap()
            .operation(&operation_id)
            .unwrap()
            .unwrap()
            .state,
        DurableOperationState::Succeeded
    );
    let fixture_json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(fixture_receipt).unwrap()).unwrap();
    assert_eq!(
        fixture_json["external_reference"],
        format!("fixture-run:{operation_id}")
    );
    let operation_jobs = [
        (invoke_job, OperationMethod::Invoke),
        (
            rex_projects::host_jobs::stable_host_job_id(operation_id.as_str(), "operation.find", 1),
            OperationMethod::Find,
        ),
        (
            rex_projects::host_jobs::stable_host_job_id(
                operation_id.as_str(),
                "operation.observe",
                1,
            ),
            OperationMethod::Observe,
        ),
    ];
    for (job_id, method) in operation_jobs {
        let job = store
            .host_job(&job_id)
            .unwrap()
            .expect("pooled host job persisted");
        assert_eq!(job.intent.operation_method, Some(method));
        assert!(matches!(
            job.state,
            HostJobState::Succeeded | HostJobState::Failed
        ));
    }
}
