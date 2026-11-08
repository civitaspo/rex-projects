use rex_projects::domain::types::Role;
use rex_projects::engine::orchestration::{AgentAssertion, RoleOutputKind};
use rex_projects::roles::{allowed_output_kinds, result_schema, role_name};
use serde_json::{Value, json};

#[test]
fn checked_in_role_schemas_match_rust_contracts() {
    for role in Role::ALL {
        let generated = format!(
            "{}\n",
            serde_json::to_string_pretty(&result_schema(role)).unwrap()
        );
        let checked_in = match role {
            Role::Supervisor => include_str!("../schemas/agent-results/supervisor-v1.json"),
            Role::Coordinator => include_str!("../schemas/agent-results/coordinator-v1.json"),
            Role::Planner => include_str!("../schemas/agent-results/planner-v1.json"),
            Role::Worker => include_str!("../schemas/agent-results/worker-v1.json"),
            Role::Reviewer => include_str!("../schemas/agent-results/reviewer-v1.json"),
            Role::MergeDecision => include_str!("../schemas/agent-results/merge_decision-v1.json"),
            Role::Operator => include_str!("../schemas/agent-results/operator-v1.json"),
            Role::Postmortem => include_str!("../schemas/agent-results/postmortem-v1.json"),
        };
        assert_eq!(
            generated,
            checked_in,
            "stale {} result schema",
            role_name(role)
        );
    }
}

#[test]
fn every_role_schema_is_valid_offline_draft_2020_12() {
    for role in Role::ALL {
        let schema = result_schema(role);
        jsonschema::validator_for(&schema)
            .unwrap_or_else(|error| panic!("invalid {} result schema: {error}", role_name(role)));
    }
}

#[test]
fn complete_role_messages_validate_for_every_allowed_role_and_kind() {
    let payloads = valid_payloads();
    let digest = "a".repeat(64);
    for role in Role::ALL {
        let schema = result_schema(role);
        let validator = jsonschema::validator_for(&schema).unwrap();
        for kind in allowed_output_kinds(role) {
            let payload = payloads
                .iter()
                .find_map(|(candidate, payload)| (*candidate == kind).then_some(payload))
                .unwrap_or_else(|| panic!("missing valid fixture for {kind:?}"));
            let message = json!({
                "schema_version": 1,
                "message_id": "fixture-message-1",
                "kind": kind,
                "assertion": serde_json::to_value(AgentAssertion::Succeeded).unwrap(),
                "structured_result": payload,
                "result_digest": digest,
                "artifact_refs": match kind {
                    RoleOutputKind::MergeAssessment => json!([merge_assessment_reference()]),
                    RoleOutputKind::PostmortemReady
                    | RoleOutputKind::ProfileTrialResult
                    | RoleOutputKind::ProfilePromotionProposal => json!([general_reference()]),
                    _ => json!([])
                }
            });
            assert!(
                validator.is_valid(&message),
                "complete {role:?} message with {kind:?} payload was rejected: {}",
                validator
                    .iter_errors(&message)
                    .map(|error| error.to_string())
                    .collect::<Vec<_>>()
                    .join("; ")
            );

            let mut invalid_kind = message.clone();
            invalid_kind["kind"] = json!("not_a_role_output");
            assert!(
                !validator.is_valid(&invalid_kind),
                "invalid kind for {role:?}/{kind:?}"
            );

            let mut unknown_field = message.clone();
            unknown_field["unknown"] = json!(true);
            assert!(
                !validator.is_valid(&unknown_field),
                "unknown root field for {role:?}/{kind:?}"
            );

            let mut invalid_payload = message;
            invalid_payload["structured_result"] = json!({"unknown":"invalid"});
            assert!(
                !validator.is_valid(&invalid_payload),
                "invalid payload for {role:?}/{kind:?}"
            );
        }
    }
}

fn valid_payloads() -> Vec<(RoleOutputKind, Value)> {
    let digest = "a".repeat(64);
    let reference = general_reference();
    let merge_ref = merge_assessment_reference();
    let change = json!({
        "change_references":[{
            "repository":"repo-a", "worktree_id":"node-a", "commit_mode":"native",
            "base_commit":"0000000000000000000000000000000000000000",
            "previous_head":"1111111111111111111111111111111111111111",
            "branch_head":"2222222222222222222222222222222222222222",
            "commit_shas":["2222222222222222222222222222222222222222"]
        }],
        "completed_acceptance_items":[], "unresolved_items":[], "irregularity_references":[]
    });
    let risk = json!({"rating":1,"source":"checks","rationale":"covered","evidence_references":[merge_ref]});
    vec![
        (
            RoleOutputKind::Progress,
            json!({"summary":"working","completed_node_keys":[],"pending_node_keys":[],"evidence":[],"next_observation_at":null}),
        ),
        (
            RoleOutputKind::Irregularity,
            json!({"severity":"high","observed_facts":["unexpected state"],"source_references":[],"affected_node_keys":[],"requested_pause_scope":"ticket_run","proposed_options":["pause and ask Coordinator"]}),
        ),
        (
            RoleOutputKind::HumanRequest,
            json!({"kind":"clarification","question":"Which option?","choices":["a"],"evidence_references":[],"subject_digest":digest,"requested_continuation":null}),
        ),
        (
            RoleOutputKind::TicketProposal,
            json!({"goal_revision":1,"gap_key":"gap-1","title":"A ticket","body":"Details","acceptance":["condition"],"priority_rationale":"unblocks work","parent":null,"dependencies":[]}),
        ),
        (
            RoleOutputKind::DispatchRequest,
            json!({"ticket_reference":"TICKET-1","expected_ticket_revision":"rev-1","coordinator_profile":"default","priority":1,"rationale":"unblocks work"}),
        ),
        (
            RoleOutputKind::Intervention,
            json!({"coordinator_role_session_id":"coord-session_1","ticket_run_revision":1,"reason":"need a decision","evidence":[],"proposed_plan_change":"pause the node"}),
        ),
        (
            RoleOutputKind::SpawnRequest,
            json!({"work_node":"node-a","role":"worker","profile_id":"worker-default","plan_digest":digest,"allowed_repositories":["repo-a"],"artifact_inputs":[],"parent_run_id":null}),
        ),
        (
            RoleOutputKind::InvestigationRequest,
            json!({"question":"Inspect dependency","allowed_repositories":["repo-a"],"required_evidence":["read-only findings"],"parent_run_id":null}),
        ),
        (
            RoleOutputKind::PrepareWorktrees,
            json!({"accepted_plan_digest":digest,"worker_nodes":["node-a"]}),
        ),
        (
            RoleOutputKind::PlanReady,
            json!({"plan":{"nodes":[{"id":"node-a","repository":"repo-a","task":"implement acceptance","depends_on":[],"required_evidence":[],"investigation":false}],"requested_investigation_children":0},"unresolved_questions":[]}),
        ),
        (RoleOutputKind::ImplementationReady, change),
        (
            RoleOutputKind::ReviewReady,
            json!({"subject_kind":"patch","subject_digest":digest,"findings":[],"evidence_coverage":["all acceptance items"],"disposition":"approved","unknowns":[]}),
        ),
        (
            RoleOutputKind::MergeAssessment,
            json!({
                "pr_references":["https://example.invalid/pr/1"],"subject_digest":"b".repeat(64),
                "deterministic_gate_evidence":[{"gate_id":"required-checks","outcome":"pass","evidence_references":[merge_ref]}],
                "ratings":{"change_impact":risk,"complexity":risk,"verification_gaps":risk,"review_uncertainty":risk,"operational_exposure":risk},
                "confidence":"high","rationale":"all required evidence is present","disposition":"merge"
            }),
        ),
        (
            RoleOutputKind::MergeIntent,
            json!({"assessment_id":"assessment-1","pr_identities":["repo-a#42"],"policy_digest":digest,"prepared_body_digest":digest,"steps":[{"kind":"direct_merge","instruction_reference":"merge.instructions#merge","rationale":"policy requires direct merge"},{"kind":"verify_merge_commit","instruction_reference":"merge.instructions#verify","rationale":"confirm resulting commit"}],"post_merge_verification":[{"kind":"merge_commit_recorded","instruction_reference":"merge.instructions#verify","rationale":"ensure remote records the merge commit"}]}),
        ),
        (
            RoleOutputKind::OperationAction,
            json!({"operation_plan_digest":digest,"node_key":"node-a","action_id":"deploy","parameters":{},"preconditions":[],"approval_receipt":"approved"}),
        ),
        (
            RoleOutputKind::OperationResult,
            json!({"node_key":"node-a","outcome":"succeeded","remote_receipt":{},"source_commit":"1111111111111111111111111111111111111111","environment":"staging","evidence_references":[]}),
        ),
        (
            RoleOutputKind::PostmortemReady,
            json!({"candidate_publication_manifest":{},"findings":["improve test coverage"],"source_references":[reference],"unresolved_provenance":[]}),
        ),
        (
            RoleOutputKind::LearningDecision,
            json!({"batch_id":"batch-1","batch_digest":digest,"config_revision":1,"observations":[],"topic_changes":[],"checkpoint":{},"improvements":[],"candidate_change":null}),
        ),
        (
            RoleOutputKind::ProfileTrialResult,
            json!({"candidate_digest":digest,"base_digest":digest,"authorization_receipt":"authorized","run_ids":[],"frozen_inputs":[],"evidence_references":[reference],"outcome":"effective"}),
        ),
        (
            RoleOutputKind::ProfilePromotionProposal,
            json!({"candidate_revision":1,"efficacy_outcome":"effective","evidence_references":[reference],"managed_slot":"project/worker","profile_diff":{},"expected_target_digests":{},"uncertain_efficacy_exception":null}),
        ),
    ]
}

fn general_reference() -> Value {
    json!({
        "kind":"general", "artifact_id":"a".repeat(64), "schema_version":1,
        "path":"evidence/result.json", "digest":"a".repeat(64), "bytes":10
    })
}

fn merge_assessment_reference() -> Value {
    json!({
        "kind":"merge_assessment", "artifact_id":"a".repeat(64), "schema_version":1,
        "path":"evidence/gate.json", "digest":"a".repeat(64), "bytes":20
    })
}
