use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::domain::ids::{Digest, ProjectId, RepositoryId, TicketId, TicketNamespace, TicketRunId};
use crate::domain::types::CommitMode;
use crate::engine::factory_runtime::{FactoryRuntimeObservationServices, FactoryRuntimeServices};
use crate::engine::orchestration::{AgentAssertion, PlannedWorkNode, RoleOutputKind, WorkPlan};
use crate::human_runtime::{
    DurableHumanSubjectObserver, HumanPresenterEffectHandler, MergeWorkReviewSource,
};
use crate::launch::{RexView, RexViewKind};
use crate::store::{ConfigStore, ExpectedRevision, OwnerMetadata, ProjectRecord};

const CHILD_ROOT: &str = "REX_PROJECTS_ADOPTION_FIXTURE_ROOT";
const CHILD_MODE: &str = "REX_PROJECTS_ADOPTION_FIXTURE_CHILD";

fn executable(path: &Path, contents: &str) {
    fs::write(path, contents).unwrap();
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).unwrap();
}

fn digest(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    sha2::Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

struct NoMergeEvidence;

impl MergeWorkReviewSource for NoMergeEvidence {
    fn observe_merge_evidence(
        &self,
        _work_item: &crate::store::merge_work::MergeWorkItem,
    ) -> Result<crate::merge_policy::MergeEvidenceSnapshot, String> {
        Err("merge review is outside this fixture".into())
    }
}

#[test]
fn publication_adoption_connection() {
    if std::env::var_os(CHILD_MODE).is_none() {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        let bin = root.join("bin");
        fs::create_dir_all(&bin).unwrap();
        let real_git = std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .map(|directory| directory.join("git"))
            .find(|path| path.is_file())
            .expect("system git is installed");
        let escaped_git = real_git.to_string_lossy().replace('\'', "'\\''");
        let head = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        executable(
            &bin.join("git"),
            &format!(
                "#!/bin/sh\ncase \"$1\" in ls-remote) for ref do :; done; printf '{head}\\t%s\\n' \"$ref\"; exit 0;; esac\nexec '{escaped_git}' \"$@\"\n"
            ),
        );
        executable(&bin.join("gh"), "#!/bin/sh\nprintf '[]\\n'\n");
        executable(
            &bin.join("rex"),
            r##"#!/bin/sh
case "$*" in
  *whoami*) printf '%s\n' '{"endpoint":"http://fixture","instance_id":"fixture-server","host_id":"fixture-host","rex_version":"test"}' ;;
  *"api list"*) printf '%s\n' '{"methods":{"session.view":{},"session.new_window":{},"session.new_split":{},"session.focus_block":{},"session.zoom_block":{},"block.close":{}}}' ;;
  *"api call session.view"*) printf '%s\n' '{"windows":[{"layers":[{"blocks":[{"block_id":"fixture-block"}]}]}]}' ;;
  *"events -s fixture-session --json"*) exit 0 ;;
  *) exit 91 ;;
esac
"##,
        );
        let path = std::iter::once(bin.clone())
            .chain(std::env::split_paths(
                &std::env::var_os("PATH").unwrap_or_default(),
            ))
            .collect::<Vec<_>>();
        let path = std::env::join_paths(path).unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap());
        child
            .arg("--exact")
            .arg("runtime_delivery::adoption_tests::publication_adoption_connection")
            .arg("--nocapture")
            .env(CHILD_MODE, "1")
            .env(CHILD_ROOT, &root)
            .env("PATH", path)
            .env("HOME", root.join("home"))
            .env("XDG_CONFIG_HOME", root.join("config"))
            .env("XDG_STATE_HOME", root.join("xdg-state"));
        fs::create_dir_all(root.join("home")).unwrap();
        let status = child.status().unwrap();
        assert!(status.success(), "isolated adoption child failed: {status}");
        return;
    }

    run_connected_adoption(PathBuf::from(std::env::var_os(CHILD_ROOT).unwrap()));
}

fn run_connected_adoption(root: PathBuf) {
    let bin = root.join("bin");
    let state_root = root.join("state");
    fs::create_dir_all(&state_root).unwrap();
    let artifact_root = state_root.join("artifacts");
    fs::create_dir_all(&artifact_root).unwrap();
    let mut shared_artifact_permissions = fs::metadata(&artifact_root).unwrap().permissions();
    shared_artifact_permissions.set_mode(0o755);
    fs::set_permissions(&artifact_root, shared_artifact_permissions).unwrap();
    assert_ne!(
        fs::metadata(&artifact_root).unwrap().permissions().mode() & 0o077,
        0,
        "shared artifact root is normally created without private permissions"
    );
    let human_artifact_root = state_root.join("human-review-artifacts");
    let config_file = root.join("factory.toml");
    let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/fixture/config.toml");
    let fixture_config = fs::read_to_string(example).unwrap();
    let config_text = fixture_config
        .replace(
            "https://example.invalid/team/example.git",
            "https://github.com/acme/demo.git",
        )
        .replace(
            "schema_version = 1",
            &format!(
                "schema_version = 1\nstate_root = {:?}\n\n[runtime]\nrex_binary = {:?}\n\n[runtime.environment]\nsource = \"inherit\"\n\n[human]\nkind = \"local_html\"\ncommand = [\"/usr/bin/true\"]\n",
                state_root.display().to_string(),
                bin.join("rex").display().to_string()
            ),
        )
        .replace(
            "command = [\"/absolute/path/to/ticket-adapter\"]",
            "command = [\"/usr/bin/true\"]",
        );
    fs::write(&config_file, config_text).unwrap();
    let profile_source = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/fixture/profiles");
    for profile in ["judgment_claude", "worker_codex"] {
        let destination = root.join("profiles").join(profile);
        fs::create_dir_all(&destination).unwrap();
        let profile_config = fs::read_to_string(profile_source.join(profile).join("config.toml"))
            .unwrap()
            .replace("/absolute/path/to/claude", "/usr/bin/true")
            .replace("/absolute/path/to/codex", "/usr/bin/true");
        fs::write(destination.join("config.toml"), profile_config).unwrap();
        fs::copy(
            profile_source.join(profile).join("instructions.md"),
            destination.join("instructions.md"),
        )
        .unwrap();
    }
    let applied = crate::config::load(&config_file).unwrap();
    assert!(
        applied.config.human.is_some(),
        "fixture must configure a presenter"
    );
    let mut store = ConfigStore::open_test(&state_root).unwrap();
    let applied_revision = store
        .apply_snapshot("fixture", &applied, ExpectedRevision::Bootstrap)
        .unwrap();
    let project_id = ProjectId::parse("goal_project").unwrap();
    let ticket_run_id = TicketRunId::parse("fixture-ticket-run").unwrap();
    let namespace = TicketNamespace::parse("fixture/cli").unwrap();
    let ticket_id = TicketId::parse("T-1").unwrap();
    store
        .insert_project(&ProjectRecord {
            id: project_id.clone(),
            config_source: "fixture".into(),
            config_revision: applied_revision.revision,
            config_digest: applied.digest.clone(),
            mode: "goal".into(),
            goal_revision: 1,
            desired_lifecycle: "running".into(),
            state_revision: crate::domain::ids::Revision(0),
        })
        .unwrap();
    let owner_generation = store
        .start_owner(&OwnerMetadata {
            owner_nonce: "publication-adoption-fixture-owner".into(),
            state_root: root.display().to_string(),
            config_source: "fixture".into(),
            process_start_identity: "fixture-owner-process".into(),
            executable_path: "/fixture/rex-projects".into(),
            executable_digest: "b".repeat(64),
            rex_endpoint: Some("http://fixture".into()),
            rex_server_identity: Some("fixture-server".into()),
            rex_session_id: Some("fixture-session".into()),
            rex_block_id: Some("fixture-block".into()),
        })
        .unwrap();
    store
        .set_project_lifecycle(owner_generation, &project_id, "running")
        .unwrap();
    store
        .create_ticket_run(
            owner_generation,
            &project_id,
            &namespace,
            &ticket_id,
            &ticket_run_id,
            1,
            "implementing",
            "in_progress",
        )
        .unwrap();
    store
        .test_connection()
        .execute(
            "UPDATE ticket_runs SET revision=1 WHERE ticket_run_id=?1",
            [ticket_run_id.as_str()],
        )
        .unwrap();
    store.test_connection().execute(
        "INSERT INTO ticket_run_context(ticket_run_id,project_id,project_epoch,recipe_id,goal_revision,created_at_unix) VALUES (?1,?2,1,NULL,1,1)",
        rusqlite::params![ticket_run_id.as_str(),project_id.as_str()],
    ).unwrap();
    let view = RexView {
        view_id: RexView::derive_id(
            &project_id,
            RexViewKind::Ticket,
            Some(namespace.as_str()),
            Some(ticket_id.as_str()),
            1,
        )
        .unwrap(),
        project_id: project_id.clone(),
        kind: RexViewKind::Ticket,
        ticket_namespace: Some(namespace.as_str().into()),
        ticket_id: Some(ticket_id.as_str().into()),
        view_epoch: 1,
        rex_server_identity: "fixture-server".into(),
        rex_session_id: "fixture-session".into(),
        rex_window_id: "ticket-window".into(),
    };
    store.register_rex_view(owner_generation, &view).unwrap();

    let repository = RepositoryId::parse("example").unwrap();
    let node_id = crate::engine::orchestration::WorkNodeId::parse("node-a").unwrap();
    let proposal = WorkPlan {
        nodes: vec![PlannedWorkNode {
            id: node_id.clone(),
            repository: repository.clone(),
            task: "implement fixture request".into(),
            depends_on: Vec::new(),
            required_evidence: vec!["tests pass".into()],
            investigation: false,
        }],
        requested_investigation_children: 0,
    };
    let claim = serde_json::json!({"plan":proposal,"unresolved_questions":[]});
    let source_result =
        crate::store::agent_results::host_validation_fixture::host_validated_result_in(
            &mut store,
            &root,
            owner_generation,
            project_id.clone(),
            ticket_run_id.clone(),
            crate::domain::types::Role::Coordinator,
            crate::roles::RoleResultMessage {
                schema_version: 1,
                message_id: "coordinator-plan".into(),
                kind: RoleOutputKind::PlanReady,
                assertion: AgentAssertion::Succeeded,
                result_digest: Some(
                    Digest::parse(digest(&serde_json::to_vec(&claim).unwrap())).unwrap(),
                ),
                structured_result: claim,
                artifact_refs: Vec::new(),
            },
        )
        .unwrap();
    let authority = store
        .agent_launch_authority(&source_result.ingested.validated.binding.agent_run_id)
        .unwrap()
        .unwrap();
    let head = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let persisted = serde_json::json!({
        "schema_version":1,
        "proposal":proposal,
        "observed_base_shas":{"example":head}
    });
    let plan_json = serde_json::to_string(&persisted).unwrap();
    let plan_digest = digest(plan_json.as_bytes());
    store.test_connection().execute(
        "INSERT INTO accepted_work_plans(project_id,ticket_run_id,accepted_revision,configuration_digest,plan_digest,plan_json,source_evidence_id,source_agent_run_id,source_message_id,source_result_digest,coordinator_agent_run_id,coordinator_role_session_id,coordinator_authority_digest,created_at_unix) VALUES (?1,?2,1,?3,?4,?5,?6,?7,?8,?9,?7,?10,?11,1)",
        rusqlite::params![project_id.as_str(),ticket_run_id.as_str(),applied.digest.as_str(),plan_digest,plan_json,source_result.ingested.receipt.evidence_id(),authority.agent_run_id.as_str(),source_result.ingested.receipt.message_id(),source_result.ingested.receipt.content_digest().as_str(),authority.role_session_id,authority.digest().unwrap().as_str()],
    ).unwrap();
    let prepare = crate::delivery_runtime::PrepareWorktreesEffectPayload {
        schema_version: 1,
        source_revision: 1,
        configuration_digest: applied.digest.clone(),
        ticket_namespace: namespace.clone(),
        ticket_id: ticket_id.clone(),
        ticket_run_id: ticket_run_id.clone(),
        work_nodes: vec![crate::delivery_runtime::PreparedWorktreeNodeRequest {
            work_node_id: node_id.clone(),
            repository_id: repository.clone(),
            expected_base_sha: head.into(),
            commit_mode: CommitMode::Native,
        }],
    };
    let request_value = serde_json::to_value(&prepare).unwrap();
    let request_json = serde_json::to_string(&request_value).unwrap();
    let request_digest = digest(request_json.as_bytes());
    let receipt = crate::delivery_runtime::PreparedWorktreesEffectReceipt {
        schema_version: 1,
        ticket_run_id: ticket_run_id.clone(),
        work_nodes: vec![crate::delivery_runtime::PreparedWorktreeReceiptNode {
            work_node_id: node_id,
            repository_id: repository.clone(),
            worktree_path: root.join("worker-worktree"),
            branch: "rex-projects/t-1".into(),
            base_sha: head.into(),
            commit_mode: CommitMode::Native,
        }],
    };
    store.test_connection().execute(
        "INSERT INTO effects(operation_id,project_id,subject_type,subject_id,logical_key,kind,request_json,request_digest,expected_revision,status,attempt_count,next_attempt_at_unix,owner_generation,receipt_json,created_at_unix) VALUES ('prepare-worktrees',?1,'ticket_run',?2,'prepare-worktrees','prepare_worktrees',?3,?4,1,'succeeded',1,0,NULL,?5,1)",
        rusqlite::params![project_id.as_str(),ticket_run_id.as_str(),request_json,request_digest,serde_json::to_string(&receipt).unwrap()],
    ).unwrap();
    let prepared_effects = store
        .list_succeeded_effect_receipts(
            owner_generation,
            &project_id,
            "ticket_run",
            ticket_run_id.as_str(),
            16,
        )
        .unwrap();
    let prepare_effect = prepared_effects
        .iter()
        .find(|effect| effect.intent().kind == "prepare_worktrees")
        .expect("fixture prepare receipt is durable");
    let project_config = applied.config.projects.get(&project_id).unwrap();
    let resource = crate::store::publication_monitor::PublicationResource {
        project_id: project_id.clone(),
        ticket_run_id: ticket_run_id.clone(),
        repository_id: repository.clone(),
        branch: "rex-projects/t-1".into(),
    };
    assert!(
        store
            .prepared_worker_launch(
                owner_generation,
                1,
                &crate::engine::orchestration::WorkNodeId::parse("node-a").unwrap(),
                prepare_effect,
                project_config,
                &applied.digest,
            )
            .unwrap()
            .is_some(),
        "implementing phase must retain Worker launch authority"
    );
    let implementing_observation = store
        .prepared_worktree_observation(
            owner_generation,
            1,
            &crate::engine::orchestration::WorkNodeId::parse("node-a").unwrap(),
            prepare_effect,
            project_config,
            &applied.digest,
        )
        .unwrap()
        .expect("implementing-phase prepared worktree remains observable");
    assert_eq!(implementing_observation.resource, resource);
    store
        .test_connection()
        .execute(
            "UPDATE ticket_runs SET revision=7,internal_phase='publishing',activity='running' WHERE ticket_run_id=?1",
            [ticket_run_id.as_str()],
        )
        .unwrap();
    assert!(
        store
            .prepared_worker_launch(
                owner_generation,
                1,
                &crate::engine::orchestration::WorkNodeId::parse("node-a").unwrap(),
                prepare_effect,
                project_config,
                &applied.digest,
            )
            .unwrap()
            .is_none(),
        "publication phase must not retain Worker launch authority"
    );
    let observation_proof = store
        .prepared_worktree_observation(
            owner_generation,
            1,
            &crate::engine::orchestration::WorkNodeId::parse("node-a").unwrap(),
            prepare_effect,
            project_config,
            &applied.digest,
        )
        .unwrap()
        .expect("publishing-phase prepared worktree remains observable");
    assert_eq!(observation_proof.resource, resource);
    let mut altered_receipt: serde_json::Value =
        serde_json::from_str(prepare_effect.receipt_json()).unwrap();
    altered_receipt["work_nodes"][0]["worktree_path"] = serde_json::json!("relative/path");
    let altered_receipt = crate::store::SucceededEffectReceipt::for_test(
        &crate::effects::EffectRequest {
            intent: prepare_effect.intent().clone(),
            attempt_count: prepare_effect.attempt_count(),
            created_at_unix: prepare_effect.created_at_unix(),
        },
        serde_json::to_string(&altered_receipt).unwrap(),
    );
    assert!(
        store
            .prepared_worktree_observation(
                owner_generation,
                1,
                &crate::engine::orchestration::WorkNodeId::parse("node-a").unwrap(),
                &altered_receipt,
                project_config,
                &applied.digest,
            )
            .is_err(),
        "publication observation must reject a tampered prepare receipt"
    );
    store
        .record_publication_irregularity(
            owner_generation,
            &crate::store::publication_monitor::PublicationIrregularity {
                resource: resource.clone(),
                observation_digest: "c".repeat(64),
                observed_at_unix: 10,
                facts: serde_json::json!({"reason":"fixture external publication"}),
            },
        )
        .unwrap();

    let environment = crate::environment::capture(&applied.config.runtime.environment).unwrap();
    let rex_identity = crate::adapters::rex::RexIdentity {
        endpoint: "http://fixture".into(),
        instance_id: "fixture-server".into(),
        session_id: "fixture-session".into(),
        block_id: Some("fixture-block".into()),
    };
    let binary = rex_projects_binary();
    let runtime_digest = Digest::parse("d".repeat(64)).unwrap();
    let mut services = crate::runtime_services::RuntimeServices::new(
        &applied,
        &environment,
        &config_file,
        &state_root,
        owner_generation,
        &rex_identity,
        crate::runtime_services::RuntimeExecutable {
            path: &binary,
            digest: &runtime_digest,
        },
    )
    .unwrap();
    store
        .latest_accepted_work_plan(&project_id, &ticket_run_id)
        .unwrap()
        .unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    assert!(
        store
            .latest_unresolved_publication(&resource)
            .unwrap()
            .is_some()
    );
    let first = FactoryRuntimeObservationServices::observe_publications(
        &mut services,
        &mut store,
        owner_generation,
        now,
    )
    .unwrap();
    let request_id = match first {
        super::PublicationMonitorTick::HumanReviewPending { request_id } => request_id,
        other => panic!("monitor did not enqueue human adoption review: {other:?}"),
    };
    let effect = store
        .claim_next_due_effect(owner_generation, now + 10, &["request_human_review".into()])
        .unwrap()
        .expect("monitor-generated presenter effect");
    let host_environment = environment.child_environment(
        crate::environment::ChildContext::HostOperation,
        &BTreeMap::from([
            ("REX_SESSION".into(), "fixture-session".into()),
            ("REX_BLOCK_ID".into(), "fixture-block".into()),
        ]),
    );
    let presenter_delivery = super::build(
        &applied,
        &root.join("presenter-state"),
        &host_environment,
        &environment.metadata().id,
    )
    .unwrap();
    let request: crate::human_runtime::HumanPresentationEffect =
        crate::protocol::parse_unique(effect.intent.request_json.as_bytes()).unwrap();
    assert_eq!(request.request.subject.revision.0, 1);
    assert_eq!(effect.intent.expected_revision, Some(7));
    let effects = presenter_delivery.shared_effects();
    let observer = DurableHumanSubjectObserver::with_merge_work_review_and_publication_adoption(
        root.join("config/rex-projects"),
        owner_generation,
        effects,
        std::sync::Arc::new(NoMergeEvidence),
        presenter_delivery.publication_adoption_source(),
    )
    .unwrap();
    let presenter = HumanPresenterEffectHandler::new(
        "local_html",
        vec!["/usr/bin/true".into()],
        environment.child_environment(
            crate::environment::ChildContext::HostOperation,
            &BTreeMap::new(),
        ),
        human_artifact_root.clone(),
        std::sync::Arc::new(observer),
    )
    .unwrap();
    let request_effect = crate::effects::EffectRequest::from(effect);
    let presentation = {
        let mut context = crate::effects::EffectContext {
            store: &mut store,
            owner_generation,
            now_unix: now,
        };
        crate::effects::EffectHandler::handle(
            &presenter,
            // The first Submit may have failed before registering a request; exercise the actual
            // dispatcher retry mode against the exact durable presentation intent.
            crate::effects::EffectMode::Reconcile,
            &request_effect,
            &mut context,
        )
        .unwrap()
    };
    assert!(matches!(
        presentation,
        crate::effects::EffectObservation::Pending { .. }
    ));
    assert_eq!(
        fs::metadata(&human_artifact_root)
            .unwrap()
            .permissions()
            .mode()
            & 0o077,
        0,
        "presenter creates a private review-only directory"
    );
    // Simulate a request persisted by an older runtime under the shared ArtifactStore root.
    // The retry must keep that exact path from the previously valid private root.
    let mut artifact_root_permissions = fs::metadata(&artifact_root).unwrap().permissions();
    artifact_root_permissions.set_mode(0o700);
    fs::set_permissions(&artifact_root, artifact_root_permissions).unwrap();
    let legacy_path =
        crate::human_runtime::write_runtime_review_artifact(&artifact_root, &request.request)
            .unwrap();
    store
        .test_connection()
        .execute(
            "UPDATE human_requests SET artifact_path=?1 WHERE request_id=?2",
            rusqlite::params![
                legacy_path.to_string_lossy(),
                request.request.request_id.as_str()
            ],
        )
        .unwrap();
    let retry_presentation = {
        let mut retry_context = crate::effects::EffectContext {
            store: &mut store,
            owner_generation,
            now_unix: now + 1,
        };
        crate::effects::EffectHandler::handle(
            &presenter,
            crate::effects::EffectMode::Reconcile,
            &request_effect,
            &mut retry_context,
        )
        .unwrap()
    };
    assert!(matches!(
        retry_presentation,
        crate::effects::EffectObservation::Pending { .. }
    ));
    assert_eq!(
        store
            .current_human_request(&request.request.request_id)
            .unwrap()
            .unwrap()
            .bundle_path,
        legacy_path,
        "retry preserves the previously persisted artifact path"
    );
    let request = store
        .current_human_request(&request.request.request_id)
        .unwrap()
        .expect("presenter persists request")
        .request;
    let html = fs::read_to_string(
        store
            .current_human_request(&request.request_id)
            .unwrap()
            .unwrap()
            .bundle_path,
    )
    .unwrap();
    assert!(html.contains("Adopt the selected external resource"));
    assert!(
        store
            .latest_unresolved_publication(&resource)
            .unwrap()
            .is_some(),
        "external publication remains held until human approval"
    );

    let subject_digest = request.subject.digest().unwrap();
    let output = Command::new(binary)
        .args(["--config"])
        .arg(&config_file)
        .args(["--state-root"])
        .arg(&state_root)
        .args(["human", "respond", &request_id, "--subject-digest"])
        .arg(subject_digest.as_str())
        .args([
            "--choice",
            "approve",
            "--explanation",
            "Exact fixture branch approved.",
        ])
        .env_remove("REX_PROJECTS_AGENT")
        .env_remove("REX_PROJECTS_CONTEXT")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "human respond failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        FactoryRuntimeServices::process_one_merge_human_response(
            &mut services,
            &mut store,
            owner_generation,
            now + 1,
        )
        .unwrap()
    );
    let adopted = FactoryRuntimeObservationServices::observe_publications(
        &mut services,
        &mut store,
        owner_generation,
        now + 2,
    )
    .unwrap();
    assert!(
        matches!(
            adopted,
            super::PublicationMonitorTick::HumanReviewApplied { .. }
        ),
        "{adopted:?}"
    );
    assert!(
        store
            .latest_unresolved_publication(&resource)
            .unwrap()
            .is_none()
    );
    let baseline = store.load_publication_baseline(&resource).unwrap().unwrap();
    assert_eq!(baseline.observation.remote_head.as_deref(), Some(head));

    let retry = FactoryRuntimeObservationServices::observe_publications(
        &mut services,
        &mut store,
        owner_generation,
        now + 3,
    )
    .unwrap();
    assert!(
        matches!(
            retry,
            super::PublicationMonitorTick::Unchanged | super::PublicationMonitorTick::Idle
        ),
        "{retry:?}"
    );
    let after_retry = store.load_publication_baseline(&resource).unwrap().unwrap();
    assert_eq!(after_retry.revision, baseline.revision);
    let wake_count: u64 = store
        .test_connection()
        .query_row(
            "SELECT COUNT(*) FROM role_wake_inputs WHERE source_type='publication_adoption'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(wake_count, 1);
}

fn rex_projects_binary() -> PathBuf {
    std::env::current_exe()
        .unwrap()
        .parent()
        .and_then(Path::parent)
        .expect("test binary is nested under target/debug/deps")
        .join(if cfg!(windows) {
            "rex-projects.exe"
        } else {
            "rex-projects"
        })
}
