#!/usr/bin/env python3
"""A local reference ticket CLI for the rex-projects adapter contract."""

import argparse
import hashlib
import json
import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

STATUSES = {
    "triage": "Triage",
    "backlog": "Backlog",
    "ready": "ToDo",
    "in_progress": "In Progress",
    "in_review": "In Review",
    "done": "Done",
    "canceled": "Canceled",
}
STATUS_SET = set(STATUSES)
FILTERS = {"status", "assignee", "project", "milestone", "release", "labels", "q", "updated_since"}
PATCH_FIELDS = {
    "title", "body", "status", "priority", "labels", "assignee", "project", "milestone",
    "release", "due_date", "parent", "dependencies",
}
MAX_REQUEST = 4 * 1024 * 1024


class AdapterError(Exception):
    def __init__(self, code, message, retryable=False, details=None):
        super().__init__(message)
        self.code = code
        self.retryable = retryable
        self.details = details


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def db_open(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path, timeout=5)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    db.execute("PRAGMA journal_mode = WAL")
    db.execute("PRAGMA busy_timeout = 5000")
    db.executescript("""
        CREATE TABLE IF NOT EXISTS tickets (
            namespace TEXT NOT NULL, scope TEXT NOT NULL, id TEXT NOT NULL,
            ticket_key TEXT NOT NULL, title TEXT NOT NULL, body TEXT NOT NULL,
            status TEXT NOT NULL, priority INTEGER, labels TEXT NOT NULL,
            assignee TEXT, project TEXT, milestone TEXT, release TEXT, due_date TEXT,
            parent TEXT, dependencies TEXT NOT NULL, revision INTEGER NOT NULL,
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL, creation_key TEXT NOT NULL,
            visible_at REAL NOT NULL,
            PRIMARY KEY(namespace, scope, id)
        );
        CREATE INDEX IF NOT EXISTS tickets_creation_key
            ON tickets(namespace, scope, creation_key);
        CREATE TABLE IF NOT EXISTS operations (
            namespace TEXT NOT NULL, scope TEXT NOT NULL, operation_id TEXT NOT NULL,
            method TEXT NOT NULL, external_key TEXT, ticket_id TEXT,
            request_digest TEXT NOT NULL, result_json TEXT NOT NULL, created_at TEXT NOT NULL,
            visible_at REAL NOT NULL,
            PRIMARY KEY(namespace, scope, operation_id, method)
        );
        CREATE INDEX IF NOT EXISTS operations_external_key
            ON operations(namespace, scope, external_key);
        CREATE TABLE IF NOT EXISTS comments (
            namespace TEXT NOT NULL, scope TEXT NOT NULL, ticket_id TEXT NOT NULL,
            comment_key TEXT NOT NULL, body TEXT NOT NULL, refs TEXT NOT NULL,
            created_at TEXT NOT NULL, PRIMARY KEY(namespace, scope, ticket_id, comment_key),
            FOREIGN KEY(namespace, scope, ticket_id) REFERENCES tickets(namespace, scope, id)
        );
        CREATE TABLE IF NOT EXISTS duplicate_relations (
            namespace TEXT NOT NULL, scope TEXT NOT NULL, duplicate_id TEXT NOT NULL,
            canonical_id TEXT NOT NULL, operation_id TEXT NOT NULL, reason TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY(namespace, scope, duplicate_id),
            FOREIGN KEY(namespace, scope, duplicate_id) REFERENCES tickets(namespace, scope, id),
            FOREIGN KEY(namespace, scope, canonical_id) REFERENCES tickets(namespace, scope, id)
        );
        CREATE TABLE IF NOT EXISTS cursors (
            token TEXT PRIMARY KEY, namespace TEXT NOT NULL, scope TEXT NOT NULL,
            filter_digest TEXT NOT NULL, offset INTEGER NOT NULL, created REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS fault_once (
            name TEXT PRIMARY KEY, value TEXT NOT NULL, consumed INTEGER NOT NULL DEFAULT 0
        );
    """)
    return db


def fail(code, message, retryable=False, details=None):
    raise AdapterError(code, message, retryable, details)


def checked_scope(params):
    scope = params.get("scope")
    if not isinstance(scope, dict) or not scope or any(
        not isinstance(k, str) or not isinstance(v, (str, int)) or isinstance(v, bool) or not str(v)
        for k, v in scope.items()
    ):
        fail("invalid_request", "scope must be a nonempty object of scalar identifiers")
    return canonical(scope)


def validate_keys(obj, required, allowed, label):
    if not isinstance(obj, dict):
        fail("invalid_request", f"{label} must be an object")
    missing = sorted(required - obj.keys())
    extra = sorted(obj.keys() - allowed)
    if missing:
        fail("invalid_request", f"{label} is missing required fields", details={"fields": missing})
    if extra:
        fail("invalid_request", f"{label} contains unsupported fields", details={"fields": extra})


def request_parse(raw):
    if len(raw) > MAX_REQUEST:
        fail("invalid_request", f"request exceeds {MAX_REQUEST} bytes")
    try:
        request = json.loads(
            raw,
            object_pairs_hook=unique_object,
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError(f"invalid JSON number: {value}")),
        )
    except (json.JSONDecodeError, ValueError) as error:
        fail("invalid_request", f"request JSON is invalid: {error}")
    validate_keys(request, {"schema_version", "request_id", "method", "params"},
                  {"schema_version", "request_id", "operation_id", "method", "project_id", "params"}, "request")
    if not isinstance(request["schema_version"], int) or isinstance(request["schema_version"], bool) or request["schema_version"] != 1:
        fail("unsupported", "only adapter schema version 1 is supported")
    if not isinstance(request["request_id"], str) or not request["request_id"]:
        fail("invalid_request", "request_id must be a nonempty string")
    if "operation_id" in request and (not isinstance(request["operation_id"], str) or not request["operation_id"]):
        fail("invalid_request", "operation_id must be a nonempty string")
    if not isinstance(request["method"], str):
        fail("invalid_request", "method must be a string")
    if not isinstance(request["params"], dict):
        fail("invalid_request", "params must be an object")
    return request


def namespace_of_ticket(db, namespace, scope, ticket_id):
    if not isinstance(ticket_id, str) or not ticket_id:
        fail("invalid_request", "ticket_id must be a nonempty string")
    row = db.execute("SELECT * FROM tickets WHERE namespace=? AND scope=? AND id=?", (namespace, scope, ticket_id)).fetchone()
    if row is None:
        fail("not_found", f"ticket {ticket_id!r} was not found in this scope")
    return row


def ticket_json(row, scope):
    labels = json.loads(row["labels"])
    dependencies = json.loads(row["dependencies"])
    status = row["status"]
    result = {
        "ticket_namespace": row["namespace"], "scope": json.loads(scope),
        "id": row["id"], "key": row["ticket_key"],
        "url": f"https://tickets.example/{row['ticket_key']}",
        "revision": f"rev-{row['revision']}", "title": row["title"], "body": row["body"],
        "status": {"value": status, "native_value": STATUSES[status], "label": STATUSES[status]},
        "priority": row["priority"], "labels": labels, "dependencies": dependencies,
        "created_at": row["created_at"], "updated_at": row["updated_at"],
        "extensions": {"assignee": row["assignee"], "project": row["project"],
                        "milestone": row["milestone"], "release": row["release"],
                        "due_date": row["due_date"], "parent": row["parent"]},
    }
    return result


def operation_replay(db, namespace, scope, operation_id, method, params):
    if operation_id is None:
        return None
    row = db.execute("SELECT request_digest,result_json FROM operations WHERE namespace=? AND scope=? AND operation_id=? AND method=?",
                     (namespace, scope, operation_id, method)).fetchone()
    if row is None:
        return None
    if row["request_digest"] != digest(params):
        fail("conflict", "operation_id was already used with different parameters")
    return json.loads(row["result_json"])


def record_operation(db, namespace, scope, operation_id, method, external_key, ticket_id, params, result, visible_at):
    if operation_id:
        db.execute("INSERT INTO operations VALUES(?,?,?,?,?,?,?,?,?,?)",
                   (namespace, scope, operation_id, method, external_key, ticket_id,
                    digest(params), canonical(result), now(), visible_at))


def maybe_drop_response(db, operation_id):
    if operation_id is None:
        return False
    row = db.execute("SELECT value,consumed FROM fault_once WHERE name='drop_create_response'").fetchone()
    if row and row["value"] == operation_id and not row["consumed"]:
        db.execute("UPDATE fault_once SET consumed=1 WHERE name='drop_create_response'")
        return True
    return False


def dispatch(db, namespace, delay, request):
    method, params = request["method"], request["params"]
    if method == "adapter.describe":
        validate_keys(params, {"schema_version"}, {"schema_version"}, "params")
        if params["schema_version"] != 1:
            fail("unsupported", "requested adapter schema version is unsupported")
        return {"ticket_namespace": namespace, "identity": {"service": "fixture", "tenant": namespace},
                "supported_schema_versions": [1], "native_value_convention": "status name",
                "status_values": STATUSES, "capabilities": {
                    "pagination": True, "filters": sorted(FILTERS), "revision_support": True,
                    "conditional_revision_mutation": True, "atomic_scope_mutation": True,
                    "remote_idempotency": ["operation_id", "comment_key"],
                    "reconciliation": {"operation_id": "authoritative", "creation_key": "eventually_consistent"},
                    "visibility_grace_seconds": delay,
                    "supported_optional_methods": ["ticket.resolve_duplicate", "operation.find"]}}
    if method == "ticket.list":
        allowed = {"scope", "status", "assignee", "project", "milestone", "release", "labels", "q", "cursor", "page_size", "updated_since"}
        validate_keys(params, {"scope"}, allowed, "params")
        scope = checked_scope(params)
        for field in FILTERS - {"status", "labels"}:
            if field in params and not isinstance(params[field], str):
                fail("invalid_request", f"{field} filter must be a string")
        filters = {key: params[key] for key in sorted(params.keys() & FILTERS) if key not in {"status", "labels"}}
        if "status" in params:
            status = params["status"]
            if not isinstance(status, str) or status not in STATUS_SET:
                fail("invalid_request", "status filter must be one normalized status")
            filters["status"] = status
        if "labels" in params:
            labels = params["labels"]
            if not isinstance(labels, list) or any(not isinstance(label, str) for label in labels):
                fail("invalid_request", "labels filter must be an array of strings")
            filters["labels"] = sorted(set(labels))
        filters_digest = digest(filters)
        page_size = params.get("page_size", 50)
        if not isinstance(page_size, int) or isinstance(page_size, bool) or not 1 <= page_size <= 100:
            fail("invalid_request", "page_size must be between 1 and 100")
        offset = 0
        if "cursor" in params:
            token = params["cursor"]
            if not isinstance(token, str):
                fail("invalid_request", "cursor must be a string")
            cursor = db.execute("SELECT * FROM cursors WHERE token=?", (token,)).fetchone()
            if cursor is None or cursor["created"] + 600 < time.time():
                fail("invalid_request", "cursor is unknown or expired", details={"restart_scan": True})
            if cursor["scope"] != scope or cursor["filter_digest"] != filters_digest or cursor["namespace"] != namespace:
                fail("conflict", "cursor belongs to a different scope or filter set")
            offset = cursor["offset"]
        rows = db.execute("SELECT * FROM tickets WHERE namespace=? AND scope=? ORDER BY created_at,id", (namespace, scope)).fetchall()
        selected = []
        for row in rows:
            item = ticket_json(row, scope)
            if "status" in filters and row["status"] != filters["status"]:
                continue
            if "assignee" in filters and row["assignee"] != filters["assignee"]:
                continue
            if "project" in filters and row["project"] != filters["project"]:
                continue
            if "milestone" in filters and row["milestone"] != filters["milestone"]:
                continue
            if "release" in filters and row["release"] != filters["release"]:
                continue
            if "labels" in filters and not set(filters["labels"]).issubset(item["labels"]):
                continue
            if "q" in filters and filters["q"].casefold() not in (row["title"] + "\n" + row["body"]).casefold():
                continue
            if "updated_since" in filters and row["updated_at"] < filters["updated_since"]:
                continue
            selected.append(item)
        page = selected[offset:offset + page_size]
        next_cursor = None
        if offset + page_size < len(selected):
            next_cursor = "cur_" + hashlib.sha256(f"{namespace}\0{scope}\0{filters_digest}\0{offset + page_size}".encode()).hexdigest()[:24]
            db.execute("INSERT OR REPLACE INTO cursors VALUES(?,?,?,?,?,?)",
                       (next_cursor, namespace, scope, filters_digest, offset + page_size, time.time()))
        return {"ticket_namespace": namespace, "tickets": page, "applied_filters": filters,
                "next_cursor": next_cursor, "observed_at": now(),
                "scan": {"page_offset": offset, "total_observed": len(selected), "consistent_snapshot": False}}
    if method == "ticket.get":
        validate_keys(params, {"scope", "ticket_id"}, {"scope", "ticket_id", "timeline_limit"}, "params")
        scope = checked_scope(params)
        if "timeline_limit" in params and (
            not isinstance(params["timeline_limit"], int) or isinstance(params["timeline_limit"], bool)
            or not 1 <= params["timeline_limit"] <= 100
        ):
            fail("invalid_request", "timeline_limit must be between 1 and 100")
        row = namespace_of_ticket(db, namespace, scope, params["ticket_id"])
        comments = db.execute("SELECT comment_key,body,created_at FROM comments WHERE namespace=? AND scope=? AND ticket_id=? ORDER BY created_at LIMIT ?",
                              (namespace, scope, row["id"], params.get("timeline_limit", 20))).fetchall()
        return {"ticket_namespace": namespace, "ticket": ticket_json(row, scope),
                "timeline": [{"actor": "fixture", "time": x["created_at"], "event": "comment", "summary": x["body"], "reference": x["comment_key"]} for x in comments]}
    if method == "ticket.create":
        allowed = {"scope", "creation_key", "title", "body", "status", "template", "parent", "dependencies", "project", "milestone", "assignee", "priority", "due_date", "labels"}
        validate_keys(params, {"scope", "creation_key", "title", "body"}, allowed, "params")
        scope = checked_scope(params)
        operation_id = request.get("operation_id")
        if not operation_id:
            fail("invalid_request", "ticket.create requires a stable operation_id")
        replay = operation_replay(db, namespace, scope, operation_id, method, params)
        if replay is not None:
            return replay
        key, title, body = params["creation_key"], params["title"], params["body"]
        if not all(isinstance(x, str) and x for x in (key, title)) or not isinstance(body, str):
            fail("invalid_request", "creation_key and title must be nonempty strings; body must be a string")
        status = params.get("status", "ready")
        if not isinstance(status, str) or status not in STATUS_SET:
            fail("invalid_request", "status must be one of the seven normalized values")
        labels = params.get("labels", [])
        deps = params.get("dependencies", [])
        if not isinstance(labels, list) or any(not isinstance(x, str) for x in labels):
            fail("invalid_request", "labels must be an array of strings")
        if not isinstance(deps, list) or any(not isinstance(x, str) for x in deps):
            fail("invalid_request", "dependencies must be an array of ticket IDs")
        for field in ("template", "parent", "project", "milestone", "assignee", "due_date"):
            if params.get(field) is not None and not isinstance(params[field], str):
                fail("invalid_request", f"{field} must be a string")
        if "priority" in params and params["priority"] is not None and (
            not isinstance(params["priority"], int) or isinstance(params["priority"], bool)
        ):
            fail("invalid_request", "priority must be an integer or null")
        if params.get("parent") is not None:
            namespace_of_ticket(db, namespace, scope, params["parent"])
        for dependency in deps:
            namespace_of_ticket(db, namespace, scope, dependency)
        created = now()
        suffix = hashlib.sha256(f"{namespace}\0{scope}\0{operation_id}".encode()).hexdigest()[:16]
        ticket_id = f"ticket-{suffix}"
        ticket_key = f"FIX-{suffix[:8].upper()}"
        visible_at = time.time() + delay
        db.execute("INSERT INTO tickets VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                   (namespace, scope, ticket_id, ticket_key, title, body, status, params.get("priority"), canonical(labels),
                    params.get("assignee"), params.get("project"), params.get("milestone"), params.get("release"),
                    params.get("due_date"), params.get("parent"), canonical(deps), 1, created, created, key, visible_at))
        result = {"ticket_namespace": namespace, "ticket": ticket_json(namespace_of_ticket(db, namespace, scope, ticket_id), scope)}
        record_operation(db, namespace, scope, operation_id, method, key, ticket_id, params, result, visible_at)
        return result
    if method == "ticket.update":
        validate_keys(params, {"scope", "ticket_id", "patch"}, {"scope", "ticket_id", "expected_revision", "patch"}, "params")
        scope = checked_scope(params)
        patch = params["patch"]
        if not isinstance(patch, dict) or not patch or patch.keys() - PATCH_FIELDS:
            fail("invalid_request", "patch must be a nonempty object of whitelisted fields", details={"allowed": sorted(PATCH_FIELDS)})
        op_id = request.get("operation_id") or "update_" + digest({"scope": scope, "id": params["ticket_id"], "expected": params.get("expected_revision"), "patch": patch})
        replay = operation_replay(db, namespace, scope, op_id, method, params)
        if replay is not None:
            return replay
        row = namespace_of_ticket(db, namespace, scope, params["ticket_id"])
        expected = params.get("expected_revision")
        revision = f"rev-{row['revision']}"
        if expected is not None and expected != revision:
            fail("conflict", "ticket revision changed", details={"current_revision": revision})
        if "status" in patch and (not isinstance(patch["status"], str) or patch["status"] not in STATUS_SET):
            fail("invalid_request", "status must be one of the seven normalized values")
        updates = {}
        columns = {"title": "title", "body": "body", "status": "status", "priority": "priority",
                   "assignee": "assignee", "project": "project", "milestone": "milestone", "release": "release",
                   "due_date": "due_date", "parent": "parent"}
        for field, column in columns.items():
            if field in patch:
                if field != "priority" and patch[field] is not None and not isinstance(patch[field], str):
                    fail("invalid_request", f"{field} must be a string or null")
                if field == "priority" and patch[field] is not None and (
                    not isinstance(patch[field], int) or isinstance(patch[field], bool)
                ):
                    fail("invalid_request", "priority must be an integer or null")
                updates[column] = patch[field]
        if "labels" in patch:
            if not isinstance(patch["labels"], list) or any(not isinstance(x, str) for x in patch["labels"]):
                fail("invalid_request", "labels must be an array of strings")
            updates["labels"] = canonical(patch["labels"])
        if "dependencies" in patch:
            if not isinstance(patch["dependencies"], list) or any(not isinstance(x, str) for x in patch["dependencies"]):
                fail("invalid_request", "dependencies must be an array of ticket IDs")
            updates["dependencies"] = canonical(patch["dependencies"])
        updates.update(revision=row["revision"] + 1, updated_at=now())
        sql = ",".join(f"{column}=?" for column in updates)
        db.execute(f"UPDATE tickets SET {sql} WHERE namespace=? AND scope=? AND id=?",
                   (*updates.values(), namespace, scope, row["id"]))
        result = {"ticket_namespace": namespace,
                  "ticket": ticket_json(namespace_of_ticket(db, namespace, scope, row["id"]), scope)}
        record_operation(db, namespace, scope, op_id, method, None, row["id"], params, result, time.time())
        return result
    if method == "ticket.comment":
        validate_keys(params, {"scope", "ticket_id", "comment_key", "body"}, {"scope", "ticket_id", "comment_key", "body", "references"}, "params")
        scope = checked_scope(params)
        op_id = request.get("operation_id") or params["comment_key"]
        replay = operation_replay(db, namespace, scope, op_id, method, params)
        if replay is not None:
            return replay
        namespace_of_ticket(db, namespace, scope, params["ticket_id"])
        if not all(isinstance(params[x], str) and params[x] for x in ("comment_key", "body")):
            fail("invalid_request", "comment_key and body must be nonempty strings")
        refs = params.get("references", [])
        if not isinstance(refs, list) or any(not isinstance(x, str) for x in refs):
            fail("invalid_request", "references must be an array of URLs")
        created = now()
        existing_comment = db.execute(
            "SELECT body,refs,created_at FROM comments WHERE namespace=? AND scope=? AND ticket_id=? AND comment_key=?",
            (namespace, scope, params["ticket_id"], params["comment_key"]),
        ).fetchone()
        if existing_comment and (
            existing_comment["body"] != params["body"] or existing_comment["refs"] != canonical(refs)
        ):
            fail("conflict", "comment_key was already used with different content")
        db.execute("INSERT OR IGNORE INTO comments VALUES(?,?,?,?,?,?,?)",
                   (namespace, scope, params["ticket_id"], params["comment_key"], params["body"], canonical(refs), created))
        result = {"ticket_namespace": namespace,
                  "comment": {"reference": f"comment-{digest([namespace, scope, params['ticket_id'], params['comment_key']])[:16]}",
                              "ticket_id": params["ticket_id"], "key": params["comment_key"],
                              "created_at": existing_comment["created_at"] if existing_comment else created}}
        record_operation(db, namespace, scope, op_id, method, params["comment_key"], params["ticket_id"], params, result, time.time())
        return result
    if method == "ticket.resolve_duplicate":
        validate_keys(params, {"scope", "duplicate_ticket_id", "canonical_ticket_id", "operation_key", "reason"},
                      {"scope", "duplicate_ticket_id", "canonical_ticket_id", "operation_key", "reason"}, "params")
        scope = checked_scope(params)
        op_id = request.get("operation_id") or params["operation_key"]
        replay = operation_replay(db, namespace, scope, op_id, method, params)
        if replay is not None:
            return replay
        duplicate = namespace_of_ticket(db, namespace, scope, params["duplicate_ticket_id"])
        canonical_ticket = namespace_of_ticket(db, namespace, scope, params["canonical_ticket_id"])
        if duplicate["id"] == canonical_ticket["id"]:
            fail("invalid_request", "a ticket cannot be a duplicate of itself")
        key = params["operation_key"]
        comment = f"Duplicate of {canonical_ticket['ticket_key']}. {params['reason']}"
        created = now()
        db.execute("INSERT OR IGNORE INTO comments VALUES(?,?,?,?,?,?,?)",
                   (namespace, scope, duplicate["id"], key, comment, "[]", created))
        db.execute("INSERT OR IGNORE INTO duplicate_relations VALUES(?,?,?,?,?,?,?)",
                   (namespace, scope, duplicate["id"], canonical_ticket["id"], op_id, params["reason"], created))
        db.execute("UPDATE tickets SET status='canceled',revision=revision+1,updated_at=? WHERE namespace=? AND scope=? AND id=?",
                   (created, namespace, scope, duplicate["id"]))
        final = namespace_of_ticket(db, namespace, scope, duplicate["id"])
        result = {"ticket_namespace": namespace, "duplicate": ticket_json(final, scope),
                  "canonical_ticket_id": canonical_ticket["id"], "comment_key": key, "outcome": "resolved"}
        record_operation(db, namespace, scope, op_id, method, params["operation_key"], duplicate["id"], params, result, time.time())
        return result
    if method == "operation.find":
        validate_keys(params, {"scope", "operation_id", "method", "stable_external_key", "subject"},
                      {"scope", "operation_id", "method", "stable_external_key", "subject"}, "params")
        scope = checked_scope(params)
        if not all(isinstance(params[x], str) and params[x] for x in ("operation_id", "method", "stable_external_key")):
            fail("invalid_request", "operation_id, method, and stable_external_key must be nonempty strings")
        subject = params["subject"]
        if not isinstance(subject, dict) or len(subject) != 1 or not ("ticket_id" in subject or "creation_key" in subject):
            fail("invalid_request", "subject must identify one ticket_id or creation_key")
        if "creation_key" in subject and subject["creation_key"] != params["stable_external_key"]:
            fail("invalid_request", "stable_external_key must match the creation_key subject")
        rows = db.execute("SELECT * FROM operations WHERE namespace=? AND scope=? AND (operation_id=? OR external_key=?)",
                          (namespace, scope, params["operation_id"], params["stable_external_key"])).fetchall()
        matching_method = [row for row in rows if row["method"] == params["method"]]
        exact_operation = [row for row in matching_method if row["operation_id"] == params["operation_id"]]
        if "ticket_id" in subject:
            candidates = [row for row in matching_method if row["ticket_id"] == subject["ticket_id"]]
            if exact_operation and exact_operation[0]["ticket_id"] != subject["ticket_id"]:
                fail("conflict", "operation_id identifies a different ticket")
        else:
            candidates = [row for row in matching_method if row["external_key"] == subject["creation_key"]]
            if exact_operation and exact_operation[0]["external_key"] != subject["creation_key"]:
                fail("conflict", "operation_id identifies a different creation key")
        match_basis = "operation_id" if exact_operation else "stable_external_key"
        if exact_operation:
            candidates = [exact_operation[0]]
        if candidates:
            invisible = [] if exact_operation else [row for row in candidates if row["visible_at"] > time.time()]
            if invisible:
                return {"ticket_namespace": namespace, "outcome": "unknown", "reason": "search index has not reached the creation key"}
            matches = [{"operation_id": row["operation_id"], "method": row["method"],
                        "ticket_id": row["ticket_id"], "stable_external_key": row["external_key"],
                        "receipt": json.loads(row["result_json"])} for row in candidates]
            return {"ticket_namespace": namespace, "outcome": "found", "match_basis": match_basis,
                    "matches": matches}
        return {"ticket_namespace": namespace, "outcome": "absent",
                "proof": {"kind": "fixture-operation-ledger", "scope": json.loads(scope), "observed_at": now()}}
    fail("unsupported", f"unsupported method: {method}", details={"supported_methods": [
        "adapter.describe", "ticket.list", "ticket.get", "ticket.create", "ticket.update",
        "ticket.comment", "ticket.resolve_duplicate", "operation.find"]})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--namespace", default="fixture/tenant-a")
    parser.add_argument("--visibility-delay-seconds", type=float, default=0.25)
    parser.add_argument("--drop-create-response-once", metavar="OPERATION_ID")
    args = parser.parse_args()
    if not args.namespace or args.visibility_delay_seconds < 0:
        parser.error("namespace must be nonempty and visibility delay nonnegative")
    request = None
    try:
        raw = sys.stdin.buffer.read(MAX_REQUEST + 1)
        request = request_parse(raw)
        db = db_open(args.database)
        with db:
            if args.drop_create_response_once:
                db.execute("INSERT OR IGNORE INTO fault_once(name,value,consumed) VALUES('drop_create_response',?,0)",
                           (args.drop_create_response_once,))
            result = dispatch(db, args.namespace, args.visibility_delay_seconds, request)
            if request["method"] == "ticket.create" and maybe_drop_response(db, request.get("operation_id")):
                db.commit()
                return 0
        sys.stdout.write(canonical({"schema_version": 1, "request_id": request["request_id"], "result": result}) + "\n")
        return 0
    except AdapterError as error:
        response = {"schema_version": 1, "request_id": request["request_id"] if request else "unknown", "error": {
            "code": error.code, "message": str(error), "retryable": error.retryable}}
        if error.details is not None:
            response["error"]["details"] = error.details
        sys.stdout.write(canonical(response) + "\n")
        return 0
    except (OSError, sqlite3.Error) as error:
        sys.stderr.write(f"fixture adapter transport failure: {type(error).__name__}: {error}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
