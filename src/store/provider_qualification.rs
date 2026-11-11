//! Durable host execution state for Agent provider qualification.

use rusqlite::Transaction;

/// Called by the single central v12 migration transaction.
pub(crate) fn migrate_v12_provider_qualification_jobs(tx: &Transaction<'_>) -> Result<(), String> {
    tx.execute_batch(
        "CREATE TABLE provider_qualification_jobs (
            request_id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(project_id),
            role TEXT NOT NULL CHECK(role IN ('supervisor','coordinator','planner','worker','reviewer','merge_decision','operator','postmortem')),
            profile_id TEXT NOT NULL,
            profile_digest TEXT NOT NULL CHECK(length(profile_digest)=64),
            config_revision INTEGER NOT NULL CHECK(config_revision>0),
            config_digest TEXT NOT NULL CHECK(length(config_digest)=64),
            request_digest TEXT NOT NULL CHECK(length(request_digest)=64),
            status TEXT NOT NULL CHECK(status IN ('queued','running','unknown','verified','failed')),
            controller_generation INTEGER NOT NULL CHECK(controller_generation>0),
            rex_session_id TEXT,
            rex_window_id TEXT,
            rex_block_id TEXT,
            result_json TEXT CHECK(result_json IS NULL OR length(result_json)<=1048576),
            evidence_digest TEXT CHECK(evidence_digest IS NULL OR length(evidence_digest)=64),
            created_at_unix INTEGER NOT NULL,
            updated_at_unix INTEGER NOT NULL,
            CHECK((status IN ('verified','failed') AND result_json IS NOT NULL AND evidence_digest IS NOT NULL)
               OR status NOT IN ('verified','failed'))
        );
        CREATE TRIGGER provider_qualification_request_identity_immutable
        BEFORE UPDATE OF request_id,project_id,role,profile_id,profile_digest,config_revision,config_digest,request_digest,created_at_unix
        ON provider_qualification_jobs
        BEGIN SELECT RAISE(ABORT, 'provider qualification request identity is immutable'); END;
        CREATE TRIGGER provider_qualification_status_transitions
        BEFORE UPDATE OF status ON provider_qualification_jobs
        WHEN NOT (
            OLD.status = NEW.status
            OR (OLD.status = 'queued' AND NEW.status IN ('running','failed'))
            OR (OLD.status = 'running' AND NEW.status IN ('unknown','verified','failed'))
            OR (OLD.status = 'unknown' AND NEW.status IN ('verified','failed'))
        )
        BEGIN SELECT RAISE(ABORT, 'provider qualification status transition is invalid'); END;
        CREATE TRIGGER provider_qualification_terminal_immutable
        BEFORE UPDATE ON provider_qualification_jobs
        WHEN OLD.status IN ('verified','failed')
        BEGIN SELECT RAISE(ABORT, 'terminal provider qualification jobs are immutable'); END;
        CREATE TRIGGER provider_qualification_jobs_immutable_delete
        BEFORE DELETE ON provider_qualification_jobs
        BEGIN SELECT RAISE(ABORT, 'provider qualification jobs are retained'); END;
        CREATE INDEX provider_qualification_jobs_pending
            ON provider_qualification_jobs(status,controller_generation,created_at_unix);
        CREATE INDEX provider_qualification_jobs_project
            ON provider_qualification_jobs(project_id,created_at_unix DESC);",
    )
    .map_err(|error| error.to_string())
}
