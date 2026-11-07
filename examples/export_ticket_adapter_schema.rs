//! Regenerate the versioned public ticket adapter JSON Schema.
use std::collections::BTreeMap;
use std::path::PathBuf;

use rex_projects::adapters::tickets::{
    AdapterDescription, CommentResult, DuplicateResolutionRequest, DuplicateResolutionResult,
    OperationFindRequest, OperationLookup, ScopedTicketResult, TicketCreateRequest,
    TicketGetRequest, TicketGetResult, TicketListRequest, TicketPage, TicketUpdateRequest,
};
use rex_projects::protocol::{RequestEnvelope, ResponseEnvelope};
use schemars::schema_for;
use serde_json::{Value, json};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("schemas/ticket-adapter/v1.json"));
    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut methods = BTreeMap::new();
    methods.insert("adapter.describe", json!({
        "params": {"type": "object", "properties": {"schema_version": {"const": 1}}, "required": ["schema_version"]},
        "result": schema_for!(AdapterDescription)
    }));
    methods.insert(
        "ticket.list",
        json!({"params": schema_for!(TicketListRequest), "result": schema_for!(TicketPage)}),
    );
    methods.insert(
        "ticket.get",
        json!({"params": schema_for!(TicketGetRequest), "result": schema_for!(TicketGetResult)}),
    );
    methods.insert("ticket.create", json!({"params": schema_for!(TicketCreateRequest), "result": schema_for!(ScopedTicketResult)}));
    methods.insert("ticket.update", json!({"params": schema_for!(TicketUpdateRequest), "result": schema_for!(ScopedTicketResult)}));
    methods.insert("ticket.comment", json!({"params": schema_for!(rex_projects::adapters::tickets::TicketCommentRequest), "result": schema_for!(CommentResult)}));
    methods.insert("ticket.resolve_duplicate", json!({"params": schema_for!(DuplicateResolutionRequest), "result": schema_for!(DuplicateResolutionResult)}));
    methods.insert("operation.find", json!({"params": schema_for!(OperationFindRequest), "result": schema_for!(OperationLookup)}));

    let contract: Value = json!({
        "schema_version": 1,
        "request_envelope": schema_for!(RequestEnvelope<Value>),
        "response_envelope": schema_for!(ResponseEnvelope<Value>),
        "methods": methods,
        "notes": [
            "ticket.triage is optional and is advertised by adapter.describe.supported_optional_methods",
            "An adapter may reject an unsupported method with the normalized unsupported error code."
        ]
    });
    let mut encoded = serde_json::to_string_pretty(&contract)?;
    encoded.push('\n');
    std::fs::write(output, encoded)?;
    Ok(())
}
