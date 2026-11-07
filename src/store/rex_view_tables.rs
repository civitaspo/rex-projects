//! Schema v12 additions owned by the Rex view lifecycle storage.

use rusqlite::Transaction;

pub(crate) fn migrate_v12_view_tables(tx: &Transaction<'_>) -> Result<(), String> {
    tx.execute_batch(
        "ALTER TABLE rex_views ADD COLUMN terminal_at_unix INTEGER;
        CREATE TABLE rex_block_archives (
            view_id TEXT NOT NULL,
            block_id TEXT NOT NULL,
            content_digest TEXT NOT NULL CHECK(length(content_digest)=64),
            output TEXT NOT NULL CHECK(length(output)<=1048576),
            created_at_unix INTEGER NOT NULL,
            PRIMARY KEY(view_id,block_id),
            FOREIGN KEY(view_id,block_id) REFERENCES rex_view_blocks(view_id,block_id)
        );
        CREATE TRIGGER rex_block_archives_immutable_update
        BEFORE UPDATE ON rex_block_archives
        BEGIN SELECT RAISE(ABORT, 'Rex block archives are immutable'); END;
        CREATE TRIGGER rex_block_archives_immutable_delete
        BEFORE DELETE ON rex_block_archives
        BEGIN SELECT RAISE(ABORT, 'Rex block archives are retained'); END;",
    )
    .map_err(|error| error.to_string())
}
