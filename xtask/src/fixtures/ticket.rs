use std::io::{Read, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Map, Value, json};

const SCHEMA_VERSION: u32 = 1;

/// Exercise the public normalized ticket protocol through the real bounded CLI boundary.
pub fn run(
    database: &Path,
    namespace: &str,
    drop_create_response_once: Option<&str>,
    mutate_response: Option<&str>,
    index_delay_ms: u64,
    native_shape: &str,
) -> Result<(), String> {
    let mut input = Vec::new();
    std::io::stdin()
        .read_to_end(&mut input)
        .map_err(|error| error.to_string())?;
    let request: Value = serde_json::from_slice(&input).map_err(|error| error.to_string())?;
    let connection = Connection::open(database).map_err(|error| error.to_string())?;
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS tickets (id TEXT PRIMARY KEY, scope TEXT NOT NULL, native TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS operations (operation_id TEXT NOT NULL, method TEXT NOT NULL, external_key TEXT NOT NULL, ticket_id TEXT NOT NULL, scope TEXT NOT NULL, visible_at_ms INTEGER NOT NULL, receipt TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS dropped (operation_id TEXT PRIMARY KEY);",
        )
        .map_err(|error| error.to_string())?;

    let response = handle(
        &connection,
        &request,
        namespace,
        drop_create_response_once,
        mutate_response,
        index_delay_ms,
        native_shape,
    )?;
    if let Some(response) = response {
        let mut stdout = std::io::stdout().lock();
        serde_json::to_writer(&mut stdout, &response).map_err(|error| error.to_string())?;
        stdout.flush().map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn handle(
    connection: &Connection,
    request: &Value,
    namespace: &str,
    drop_once: Option<&str>,
    mutation: Option<&str>,
    index_delay_ms: u64,
    native_shape: &str,
) -> Result<Option<Value>, String> {
    let params = &request["params"];
    let scope = params["scope"].clone();
    let scope_key = serde_json::to_string(&scope).map_err(|error| error.to_string())?;
    let method = request["method"].as_str().unwrap_or_default();
    let request_id = request["request_id"].clone();
    let mut result = match method {
        "adapter.describe" => json!({
            "ticket_namespace": namespace,
            "identity": {"adapter": "reference-fixture"},
            "supported_schema_versions": [SCHEMA_VERSION],
            "native_value_convention": "The wrapper normalizes native tracker values.",
            "status_values": {"triage":"Triage","backlog":"Backlog","ready":"Ready","in_progress":"In Progress","in_review":"In Review","done":"Done","canceled":"Canceled"},
            "capabilities": {"pagination":true,"filters":["status","labels","query","updated_since"],"revision_support":true,"conditional_revision_mutation":true,"atomic_scope_mutation":true,"remote_idempotency":["ticket.create","ticket.comment"],"reconciliation":{"ticket.create":"operation_id_or_creation_key","ticket.update":"operation_id","ticket.comment":"operation_id"},"visibility_grace_seconds":(index_delay_ms as f64)/1000.0,"supported_optional_methods":[]}
        }),
        "ticket.list" => match list(connection, params, &scope_key, namespace, native_shape) {
            Ok(result) => result,
            Err(message) => return Ok(Some(error_response(&request_id, "conflict", &message))),
        },
        "ticket.get" => {
            let id = string(&params["ticket_id"], "ticket_id")?;
            let native = ticket_native(connection, id, &scope_key)?;
            let Some(native) = native else {
                return Ok(Some(error_response(&request_id, "not_found", "ticket not found in scope")));
            };
            json!({"ticket_namespace":namespace,"ticket":normalize(&native, &scope, namespace, native_shape),"timeline":[]})
        }
        "ticket.create" => {
            let key = string(&params["creation_key"], "creation_key")?;
            let id = format!("ticket-{}", count_tickets(connection)? + 1);
            let status = params["status"].as_str().unwrap_or("ready");
            let native = make_native(&id, key, &params["title"], &params["body"], status, 1, &scope, native_shape);
            store_ticket(connection, &id, &scope_key, &native)?;
            let ticket = normalize(&native, &scope, namespace, native_shape);
            let receipt = json!({"ticket_namespace":namespace,"ticket":ticket});
            store_operation(connection, request, "ticket.create", key, &id, &scope_key, index_delay_ms, &json!({"ticket":ticket}))?;
            if request["operation_id"].as_str() == drop_once {
                let operation_id = string(&request["operation_id"], "operation_id")?;
                let inserted = connection.execute("INSERT OR IGNORE INTO dropped(operation_id) VALUES (?1)", [operation_id]).map_err(|error| error.to_string())?;
                if inserted > 0 {
                    return Ok(None);
                }
            }
            receipt
        }
        "ticket.update" => {
            let id = string(&params["ticket_id"], "ticket_id")?;
            let Some(mut native) = ticket_native(connection, id, &scope_key)? else {
                return Ok(Some(error_response(&request_id, "not_found", "ticket not found in scope")));
            };
            let current = normalize(&native, &scope, namespace, native_shape);
            if current["revision"] != params["expected_revision"] {
                return Ok(Some(error_response(&request_id, "conflict", "ticket revision changed")));
            }
            apply_patch(&mut native, &params["patch"], native_shape)?;
            let revision = current["revision"].as_str().unwrap_or("rev-0").trim_start_matches("rev-").parse::<u64>().unwrap_or_default() + 1;
            set_revision(&mut native, revision, native_shape);
            store_ticket(connection, id, &scope_key, &native)?;
            let ticket = normalize(&native, &scope, namespace, native_shape);
            let receipt = json!({"ticket_namespace":namespace,"ticket":ticket});
            store_operation(connection, request, "ticket.update", "", id, &scope_key, index_delay_ms, &json!({"ticket":ticket}))?;
            receipt
        }
        "ticket.comment" => {
            let id = string(&params["ticket_id"], "ticket_id")?;
            if ticket_native(connection, id, &scope_key)?.is_none() {
                return Ok(Some(error_response(&request_id, "not_found", "ticket not found in scope")));
            }
            let key = string(&params["comment_key"], "comment_key")?;
            let comment = json!({"reference":format!("comment-{key}"),"ticket_id":id,"key":key,"created_at":"2026-11-07T00:00:00Z"});
            let receipt = json!({"ticket_namespace":namespace,"comment":comment});
            store_operation(connection, request, "ticket.comment", key, id, &scope_key, index_delay_ms, &json!({"comment":comment}))?;
            receipt
        }
        "ticket.resolve_duplicate" => {
            let duplicate_id = string(&params["duplicate_ticket_id"], "duplicate_ticket_id")?;
            let canonical_id = string(&params["canonical_ticket_id"], "canonical_ticket_id")?;
            let Some(mut native) = ticket_native(connection, duplicate_id, &scope_key)? else {
                return Ok(Some(error_response(&request_id, "not_found", "duplicate ticket not found in scope")));
            };
            set_status(&mut native, "canceled", native_shape);
            let duplicate = normalize(&native, &scope, namespace, native_shape);
            store_ticket(connection, duplicate_id, &scope_key, &native)?;
            let key = string(&params["operation_key"], "operation_key")?;
            let receipt = json!({"ticket_namespace":namespace,"duplicate":duplicate,"canonical_ticket_id":canonical_id,"comment_key":key,"outcome":"resolved"});
            store_operation(connection, request, "ticket.resolve_duplicate", key, duplicate_id, &scope_key, index_delay_ms, &json!({"duplicate":duplicate}))?;
            receipt
        }
        "operation.find" => return find_operation(connection, request, namespace),
        _ => return Ok(Some(error_response(&request_id, "unsupported", "method is not supported by fixture"))),
    };

    if let Some(mutation) = mutation {
        mutate(&mut result, mutation);
    }
    Ok(Some(json!({"schema_version":SCHEMA_VERSION,"request_id":request_id,"result":result})))
}

fn list(connection: &Connection, params: &Value, scope_key: &str, namespace: &str, shape: &str) -> Result<Value, String> {
    let (offset, cursor_scope) = if let Some(cursor) = params["cursor"].as_str() {
        let cursor: Value = serde_json::from_str(cursor).map_err(|error| error.to_string())?;
        (cursor["offset"].as_u64().unwrap_or_default() as usize, cursor["scope"].as_str().unwrap_or_default().to_owned())
    } else { (0, scope_key.to_owned()) };
    if cursor_scope != scope_key { return Err("cursor scope changed".into()); }
    let mut statement = connection.prepare("SELECT native FROM tickets WHERE scope = ?1 ORDER BY id").map_err(|error| error.to_string())?;
    let all = statement.query_map([scope_key], |row| row.get::<_, String>(0)).map_err(|error| error.to_string())?
        .map(|row| serde_json::from_str::<Value>(&row.unwrap()).unwrap()).collect::<Vec<_>>();
    let size = params["page_size"].as_u64().unwrap_or(20) as usize;
    let end = (offset + size).min(all.len());
    let tickets = all[offset.min(all.len())..end].iter().map(|native| normalize(native, &params["scope"], namespace, shape)).collect::<Vec<_>>();
    let filters = params.as_object().into_iter().flatten()
        .filter(|(key, _)| !matches!(key.as_str(), "scope" | "cursor" | "page_size"))
        .map(|(key, value)| (key.clone(), value.clone())).collect::<Map<_, _>>();
    Ok(json!({"ticket_namespace":namespace,"tickets":tickets,"applied_filters":filters,"next_cursor":(end < all.len()).then(|| json!({"offset":end,"scope":scope_key}).to_string()),"observed_at":"2026-11-07T00:00:00Z","scan":{"snapshot_consistent":false}}))
}

fn find_operation(connection: &Connection, request: &Value, namespace: &str) -> Result<Option<Value>, String> {
    let params = &request["params"];
    let scope = serde_json::to_string(&params["scope"]).map_err(|error| error.to_string())?;
    let operation_id = string(&params["operation_id"], "operation_id")?;
    let method = string(&params["method"], "method")?;
    let stable_key = string(&params["stable_external_key"], "stable_external_key")?;
    let subject = &params["subject"];
    let exact = connection.query_row("SELECT operation_id, method, external_key, ticket_id, receipt FROM operations WHERE scope=?1 AND operation_id=?2 AND method=?3", params![scope, operation_id, method], operation_row).optional().map_err(|error| error.to_string())?;
    let mut rows = Vec::new();
    if let Some(row) = exact {
        rows.push(row);
    } else {
        let now = now_ms();
        let mut statement = connection.prepare("SELECT operation_id, method, external_key, ticket_id, receipt FROM operations WHERE scope=?1 AND method=?2 AND external_key=?3 AND visible_at_ms<=?4 ORDER BY rowid").map_err(|error| error.to_string())?;
        let candidates = statement.query_map(params![scope, method, stable_key, now], operation_row).map_err(|error| error.to_string())?;
        for row in candidates { rows.push(row.map_err(|error| error.to_string())?); }
    }
    let mut matches = Vec::new();
    for (id, method, key, ticket_id, receipt) in rows {
        if subject.get("creation_key").and_then(Value::as_str).is_some_and(|wanted| wanted != key) { continue; }
        if subject.get("ticket_id").and_then(Value::as_str).is_some_and(|wanted| wanted != ticket_id) { continue; }
        matches.push(json!({"operation_id":id,"method":method,"ticket_id":ticket_id,"stable_external_key":key,"receipt":serde_json::from_str::<Value>(&receipt).map_err(|error|error.to_string())?}));
    }
    let request_id = request["request_id"].clone();
    let result = if matches.is_empty() {
        let delayed: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM operations WHERE scope=?1 AND method=?2 AND external_key=?3 AND visible_at_ms>?4)", params![scope, method, stable_key, now_ms()], |row| row.get(0)).map_err(|error|error.to_string())?;
        if delayed {
            json!({"ticket_namespace":namespace,"outcome":"unknown","match_basis":null,"reason":"external index has not exposed the operation yet","matches":[],"proof":null})
        } else {
            json!({"ticket_namespace":namespace,"outcome":"absent","match_basis":null,"reason":null,"matches":[],"proof":{"scope":params["scope"]}})
        }
    } else {
        let basis = if matches.iter().any(|item| item["operation_id"] == operation_id) { "operation_id" } else { "stable_external_key" };
        json!({"ticket_namespace":namespace,"outcome":"found","match_basis":basis,"reason":null,"matches":matches,"proof":null})
    };
    Ok(Some(json!({"schema_version":SCHEMA_VERSION,"request_id":request_id,"result":result})))
}

fn operation_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<(String, String, String, String, String)> {
    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?))
}

fn store_operation(connection: &Connection, request: &Value, method: &str, key: &str, ticket_id: &str, scope: &str, delay_ms: u64, receipt: &Value) -> Result<(), String> {
    let operation_id = string(&request["operation_id"], "operation_id")?;
    connection.execute("INSERT INTO operations(operation_id,method,external_key,ticket_id,scope,visible_at_ms,receipt) VALUES(?1,?2,?3,?4,?5,?6,?7)", params![operation_id,method,key,ticket_id,scope,now_ms().saturating_add(delay_ms as i64),serde_json::to_string(receipt).map_err(|error|error.to_string())?]).map_err(|error|error.to_string())?;
    Ok(())
}

fn ticket_native(connection: &Connection, id: &str, scope: &str) -> Result<Option<Value>, String> {
    let raw = connection.query_row("SELECT native FROM tickets WHERE id=?1 AND scope=?2", params![id,scope], |row| row.get::<_, String>(0)).optional().map_err(|error|error.to_string())?;
    raw.map(|value| serde_json::from_str(&value).map_err(|error|error.to_string())).transpose()
}

fn store_ticket(connection: &Connection, id: &str, scope: &str, native: &Value) -> Result<(), String> {
    connection.execute("INSERT OR REPLACE INTO tickets(id,scope,native) VALUES(?1,?2,?3)", params![id,scope,serde_json::to_string(native).map_err(|error|error.to_string())?]).map_err(|error|error.to_string())?;
    Ok(())
}

fn count_tickets(connection: &Connection) -> Result<u64, String> {
    connection.query_row("SELECT count(*) FROM tickets", [], |row| row.get(0)).map_err(|error|error.to_string())
}

fn make_native(id: &str, key: &str, title: &Value, body: &Value, status: &str, revision: u64, scope: &Value, shape: &str) -> Value {
    if shape == "edges" {
        json!({"node":{"uid":id,"identifier":key,"name":title,"description":body,"workflow":{"name":status},"revision":revision,"scope":scope,"labels":[]}})
    } else {
        json!({"id":id,"key":key,"title":title,"body":body,"status":status,"version":revision,"scope":scope,"labels":[]})
    }
}

fn normalize(native: &Value, scope: &Value, namespace: &str, shape: &str) -> Value {
    let (record, id, key, title, body, status, revision, labels) = if shape == "edges" {
        let node = &native["node"];
        (node, &node["uid"], &node["identifier"], &node["name"], &node["description"], &node["workflow"]["name"], node["revision"].as_u64().unwrap_or_default(), &node["labels"])
    } else {
        (native, &native["id"], &native["key"], &native["title"], &native["body"], &native["status"], native["version"].as_u64().unwrap_or_default(), &native["labels"])
    };
    let _ = record;
    json!({"ticket_namespace":namespace,"scope":scope,"id":id,"key":key,"url":null,"revision":format!("rev-{revision}"),"title":title,"body":body,"status":{"value":status,"native_value":status,"provider_id":null,"label":status},"priority":null,"labels":labels,"dependencies":[],"created_at":"2026-11-07T00:00:00Z","updated_at":"2026-11-07T00:00:00Z","extensions":{}})
}

fn apply_patch(native: &mut Value, patch: &Value, shape: &str) -> Result<(), String> {
    let entries = patch.as_object().ok_or("patch must be an object")?;
    for (key, value) in entries {
        match (shape, key.as_str()) {
            ("edges", "title") => native["node"]["name"] = value.clone(),
            ("edges", "body") => native["node"]["description"] = value.clone(),
            ("edges", "status") => native["node"]["workflow"]["name"] = value.clone(),
            (_, "title") => native["title"] = value.clone(),
            (_, "body") => native["body"] = value.clone(),
            (_, "status") => native["status"] = value.clone(),
            _ => {}
        }
    }
    Ok(())
}

fn set_revision(native: &mut Value, revision: u64, shape: &str) {
    if shape == "edges" { native["node"]["revision"] = revision.into(); }
    else { native["version"] = revision.into(); }
}

fn set_status(native: &mut Value, status: &str, shape: &str) {
    if shape == "edges" { native["node"]["workflow"]["name"] = status.into(); }
    else { native["status"] = status.into(); }
}

fn mutate(result: &mut Value, mutation: &str) {
    match mutation {
        "get-ticket-id" | "update-ticket-id" => result["ticket"]["id"] = "unrelated-ticket".into(),
        "comment-key" => result["comment"]["key"] = "unrelated-comment-key".into(),
        "duplicate-key" => result["comment_key"] = "unrelated-duplicate-key".into(),
        "operation-id" => result["matches"][0]["operation_id"] = "UNRELATED-OP".into(),
        "operation-ticket-id" => result["matches"][0]["ticket_id"] = "UNRELATED-TICKET".into(),
        _ => {}
    }
}

fn string<'a>(value: &'a Value, name: &str) -> Result<&'a str, String> {
    value.as_str().ok_or_else(|| format!("missing string field {name}"))
}

fn error_response(request_id: &Value, code: &str, message: &str) -> Value {
    json!({"schema_version":SCHEMA_VERSION,"request_id":request_id,"error":{"code":code,"message":message,"retryable":false,"details":{}}})
}

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as i64
}
