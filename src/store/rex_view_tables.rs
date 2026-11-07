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
        BEGIN SELECT RAISE(ABORT, 'Rex block archives are retained'); END;
        CREATE TABLE rex_view_anchors (
            view_id TEXT PRIMARY KEY REFERENCES rex_views(view_id),
            block_id TEXT NOT NULL,
            run_id TEXT NOT NULL,
            owned_label TEXT NOT NULL,
            command_digest TEXT NOT NULL CHECK(length(command_digest)=64),
            lifecycle TEXT NOT NULL CHECK(lifecycle IN ('active','completed','failed','unknown','closed')),
            process_absent_confirmed INTEGER NOT NULL DEFAULT 0 CHECK(process_absent_confirmed IN (0,1)),
            terminal_at_unix INTEGER,
            created_at_unix INTEGER NOT NULL,
            UNIQUE(view_id,block_id)
        );
        CREATE TRIGGER rex_view_anchors_identity_guard
        BEFORE UPDATE ON rex_view_anchors
        WHEN OLD.view_id IS NOT NEW.view_id OR OLD.block_id IS NOT NEW.block_id
          OR OLD.run_id IS NOT NEW.run_id OR OLD.owned_label IS NOT NEW.owned_label
          OR OLD.command_digest IS NOT NEW.command_digest OR OLD.created_at_unix IS NOT NEW.created_at_unix
        BEGIN SELECT RAISE(ABORT, 'Rex view anchor identity is immutable'); END;
        CREATE TRIGGER rex_view_anchors_immutable_delete
        BEFORE DELETE ON rex_view_anchors
        BEGIN SELECT RAISE(ABORT, 'Rex view anchors are retained'); END;
        CREATE TABLE rex_view_anchor_archives (
            view_id TEXT NOT NULL,
            block_id TEXT NOT NULL,
            content_digest TEXT NOT NULL CHECK(length(content_digest)=64),
            output TEXT NOT NULL CHECK(length(output)<=1048576),
            created_at_unix INTEGER NOT NULL,
            PRIMARY KEY(view_id,block_id),
            FOREIGN KEY(view_id,block_id) REFERENCES rex_view_anchors(view_id,block_id)
        );
        CREATE TRIGGER rex_view_anchor_archives_immutable_update
        BEFORE UPDATE ON rex_view_anchor_archives
        BEGIN SELECT RAISE(ABORT, 'Rex view anchor archives are immutable'); END;
        CREATE TRIGGER rex_view_anchor_archives_immutable_delete
        BEFORE DELETE ON rex_view_anchor_archives
        BEGIN SELECT RAISE(ABORT, 'Rex view anchor archives are retained'); END;",
    )
    .map_err(|error| error.to_string())
}
