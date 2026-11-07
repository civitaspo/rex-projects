//! Durable aggregate merge work storage schema.

use rusqlite::Transaction;

/// Called by the single central v12 migration transaction.
pub fn migrate_v12_merge_work_items(tx: &Transaction<'_>) -> Result<(), String> {
    tx.execute_batch(
        "CREATE TABLE merge_work_items (
            work_id TEXT PRIMARY KEY CHECK(length(work_id)=64),
            project_id TEXT NOT NULL,
            ticket_run_id TEXT NOT NULL,
            assessed_revision INTEGER NOT NULL CHECK(assessed_revision > 0),
            awaiting_merge_revision INTEGER NOT NULL CHECK(awaiting_merge_revision > assessed_revision),
            configuration_digest TEXT NOT NULL CHECK(length(configuration_digest)=64),
            accepted_plan_digest TEXT NOT NULL CHECK(length(accepted_plan_digest)=64),
            prepared_receipt_digest TEXT NOT NULL CHECK(length(prepared_receipt_digest)=64),
            publication_set_digest TEXT NOT NULL CHECK(length(publication_set_digest)=64),
            work_digest TEXT NOT NULL CHECK(length(work_digest)=64),
            work_json TEXT NOT NULL CHECK(length(work_json)<=1048576),
            created_at_unix INTEGER NOT NULL,
            UNIQUE(project_id,ticket_run_id,awaiting_merge_revision)
        );
        CREATE INDEX merge_work_items_run ON merge_work_items(project_id,ticket_run_id,awaiting_merge_revision DESC);",
    )
    .map_err(|error| error.to_string())
}
