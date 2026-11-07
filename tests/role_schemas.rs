use rex_projects::domain::types::Role;
use rex_projects::roles::{result_schema, role_name};

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
