//! Connected regression coverage for operational Supervisor wake delivery.
//!
//! The fixture seeds durable rows and host prerecords. It then exercises the production wake
//! query, package and inbox parser, result validation, and dispatch reducer. It does not claim
//! native Rex or Coding Agent execution.

use crate::domain::ids::{Digest, ProjectId, TicketId, TicketNamespace};
use crate::domain::types::{Role, TicketStatus};
use crate::engine::orchestration::{AgentAssertion, RoleOutputKind};
use crate::roles::RoleResultMessage;
use crate::store::scheduler::{
    ObservedTicket, PendingTicketObservation, TicketScanKey, TicketScanPage,
};
use rusqlite::params;
use serde_json::json;
use sha2::Digest as _;

fn dispatch_message(ticket_reference: &str, revision: &str) -> RoleResultMessage {
    let payload = json!({
        "ticket_reference": ticket_reference,
        "expected_ticket_revision": revision,
        "coordinator_profile": "judgment_claude",
        "priority": 3,
        "rationale": "dispatch the exact observed ticket revision"
    });
    let result_digest = Digest::parse(format!(
        "{:x}",
        sha2::Sha256::digest(serde_json::to_vec(&payload).unwrap())
    ))
    .unwrap();
    RoleResultMessage {
        schema_version: crate::engine::orchestration::ROLE_RESULT_SCHEMA_VERSION,
        message_id: "supervisor-operational-wake-dispatch".into(),
        kind: RoleOutputKind::DispatchRequest,
        assertion: AgentAssertion::Succeeded,
        structured_result: payload,
        result_digest: Some(result_digest),
        artifact_refs: Vec::new(),
    }
}

#[test]
fn operational_supervisor_wakes_reach_inbox_and_dispatch_while_learning_stays_pending() {
    let project_id = ProjectId::parse("fixture-project").unwrap();
    let ticket_namespace = TicketNamespace::parse("fixture").unwrap();
    let ticket_revision = "revision-43-observed";
    let learning_payload = json!({
        "type": "supervisor_learning_batch",
        "batch_id": "learning-issued-fixture",
        "project_id": project_id.as_str()
    });
    let mut fixture = crate::store::agent_results::host_validation_fixture::host_validated_result(
        Role::Supervisor,
        dispatch_message("43", ticket_revision),
    )
    .unwrap();
    fixture
        .store
        .set_project_lifecycle(fixture.owner_generation, &project_id, "running")
        .unwrap();

    let mut config: crate::config::Config =
        toml::from_str(include_str!("../../../examples/fixture/config.toml")).unwrap();
    let mut project = config
        .projects
        .remove(&ProjectId::parse("goal_project").unwrap())
        .unwrap();
    project.dispatch_states = vec![TicketStatus::Ready];
    config.projects.insert(project_id.clone(), project);
    let project = config.projects.get(&project_id).unwrap();
    let scan_key = TicketScanKey::for_project(
        &project_id,
        &project.ticket_adapter,
        &ticket_namespace,
        project,
        TicketStatus::Ready,
    )
    .unwrap();
    let tickets = [
        ObservedTicket {
            id: TicketId::parse("43").unwrap(),
            revision: Some(ticket_revision.into()),
            status: TicketStatus::Ready,
            title: "First fixture ticket".into(),
            labels: Vec::new(),
            created_at: None,
            observed_at_unix: 1,
        },
        ObservedTicket {
            id: TicketId::parse("44").unwrap(),
            revision: Some("revision-44-observed".into()),
            status: TicketStatus::Ready,
            title: "Second fixture ticket".into(),
            labels: Vec::new(),
            created_at: None,
            observed_at_unix: 1,
        },
    ];
    fixture
        .store
        .record_ticket_scan_page(
            fixture.owner_generation,
            TicketScanPage {
                key: &scan_key,
                expected_cursor: None,
                expected_generation: 0,
                expected_page_count: 0,
                next_cursor: None,
                tickets: &tickets,
                now_unix: 1,
                poll_seconds: 60,
            },
        )
        .unwrap();

    // Seed one issued learning batch and wake using the durable schema used by the issuer.
    let learning_wake_id: i64 = fixture
        .store
        .test_connection()
        .query_row(
            "INSERT INTO role_wake_inputs(project_id,role_session_id,source_type,source_id,source_revision,priority,payload_json,lifecycle,created_at_unix) \
             VALUES (?1,?2,'learning_batch','learning-issued-fixture',1,1,?3,'pending',1) RETURNING wake_input_id",
            params![
                project_id.as_str(),
                format!("project:{project_id}:supervisor"),
                learning_payload.to_string(),
            ],
            |row| row.get(0),
        )
        .unwrap();
    fixture
        .store
        .test_connection()
        .execute(
            "INSERT INTO learning_batches(batch_id,project_id,batch_digest,config_revision,config_digest,owner_generation,wake_input_id,findings_json,snapshot_json,status,created_at_unix) \
             VALUES ('learning-issued-fixture',?1,?2,1,?3,?4,?5,'[]',?6,'issued',1)",
            params![
                project_id.as_str(),
                "c".repeat(64),
                "d".repeat(64),
                fixture.owner_generation,
                learning_wake_id,
                "{}",
            ],
        )
        .unwrap();

    let learning_only = fixture
        .store
        .pending_supervisor_wake_inputs(&project_id, 32)
        .unwrap();
    assert_eq!(learning_only.len(), 1);
    assert_eq!(learning_only[0].source_type, "learning_batch");

    for ticket in &tickets {
        assert!(
            fixture
                .store
                .enqueue_supervisor_ticket_observation(
                    fixture.owner_generation,
                    &scan_key,
                    &PendingTicketObservation {
                        ticket_id: ticket.id.clone(),
                        revision: ticket.revision.clone(),
                        status: ticket.status,
                        title: ticket.title.clone(),
                        labels: ticket.labels.clone(),
                        observed_at_unix: ticket.observed_at_unix,
                    },
                    2,
                )
                .unwrap()
        );
    }

    let selected = fixture
        .store
        .pending_supervisor_wake_inputs(&project_id, 32)
        .unwrap();
    assert_eq!(
        selected
            .iter()
            .filter(|wake| wake.source_type == "ticket_observation")
            .count(),
        2,
        "Supervisor must retain all operational ticket choices"
    );
    assert!(
        selected
            .iter()
            .all(|wake| wake.source_type != "learning_batch")
    );
    let selected_items = selected
        .iter()
        .map(|wake| crate::agent_api::AgentWakeItem {
            wake_input_id: wake.wake_input_id,
            source_type: wake.source_type.clone(),
            source_id: wake.source_id.clone(),
            source_revision: wake.source_revision,
            priority: wake.priority,
            payload_json: wake.payload_json.clone(),
            host_artifact_source_evidence_ids: Vec::new(),
            host_artifacts: Vec::new(),
            host_completion_context: None,
        })
        .collect();
    let supervisor_run_id =
        crate::domain::ids::AgentRunId::parse("agent-supervisor-operational-wake-test").unwrap();
    let result_fixture =
        crate::store::agent_results::host_validation_fixture::host_validated_supervisor_result_in_with_wake_inputs(
            &mut fixture.store,
            fixture._temp.path(),
            fixture.owner_generation,
            project_id.clone(),
            dispatch_message("43", ticket_revision),
            supervisor_run_id,
            selected_items,
        )
        .unwrap();
    let binding = &result_fixture.ingested.validated.binding;
    let control_dir: String = fixture
        .store
        .test_connection()
        .query_row(
            "SELECT control_dir FROM agent_launch_authority WHERE agent_run_id=?1",
            [binding.agent_run_id.as_str()],
            |row| row.get(0),
        )
        .unwrap();
    let inbox_bytes = crate::cli::dispatch_agent_inbox_for_test(&[
        "rex-projects",
        "agent",
        "inbox",
        "--control-dir",
        &control_dir,
        "--run",
        binding.agent_run_id.as_str(),
        "--json",
    ])
    .unwrap();
    let inbox: serde_json::Value = serde_json::from_slice(&inbox_bytes).unwrap();
    let inbox_inputs = inbox["inputs"].as_array().unwrap();
    assert_eq!(inbox_inputs.len(), 2);
    assert!(
        inbox_inputs
            .iter()
            .all(|input| input["source_type"] == "ticket_observation")
    );
    assert!(
        inbox_inputs
            .iter()
            .any(|input| input["payload_json"]["ticket_id"] == "43")
    );
    assert!(
        inbox_inputs
            .iter()
            .any(|input| input["payload_json"]["ticket_id"] == "44")
    );
    let mut selected_ids = selected
        .iter()
        .map(|wake| wake.wake_input_id)
        .collect::<Vec<_>>();
    selected_ids.sort_unstable();
    let mut inbox_ids = inbox_inputs
        .iter()
        .map(|input| input["wake_input_id"].as_u64().unwrap())
        .collect::<Vec<_>>();
    inbox_ids.sort_unstable();
    assert_eq!(inbox_ids, selected_ids);

    let configuration_digest = Digest::parse("a".repeat(64)).unwrap();
    assert!(
        crate::engine::factory_runtime::tests::apply_agent_result_for_test(
            &mut fixture.store,
            fixture.owner_generation,
            2,
            &config,
            configuration_digest,
            &result_fixture.ingested,
        )
        .unwrap()
    );
    let learning_lifecycle: String = fixture
        .store
        .test_connection()
        .query_row(
            "SELECT lifecycle FROM role_wake_inputs WHERE wake_input_id=?1",
            [learning_wake_id],
            |row| row.get(0),
        )
        .unwrap();
    let learning_status: String = fixture
        .store
        .test_connection()
        .query_row(
            "SELECT status FROM learning_batches WHERE batch_id='learning-issued-fixture'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(learning_lifecycle, "pending");
    assert_eq!(learning_status, "issued");
    let (ticket_run_id, ticket_revision): (String, u64) = fixture
        .store
        .test_connection()
        .query_row(
            "SELECT ticket_run_id,ticket_revision FROM ticket_runs WHERE project_id=?1 AND ticket_id='43'",
            [project_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(ticket_revision, 1);
    let coordinator_session = format!("ticket_run:{ticket_run_id}:coordinator");
    let coordinator_wakes = fixture
        .store
        .pending_role_wake_inputs(&project_id, &coordinator_session, 8)
        .unwrap();
    assert!(coordinator_wakes.iter().any(|wake| {
        wake.source_type == "ticket_run_dispatch" && wake.source_id == ticket_run_id
    }));
}
