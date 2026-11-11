use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use rex_projects::domain::ids::{Digest, OperationId, ProjectId, TicketRunId};
use rex_projects::knowledge::{
    KnowledgeSource, PostmortemInput, PublicationReceipt, publish_postmortem,
};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;

struct Fixture {
    _temp: TempDir,
    config: PathBuf,
    state_root: PathBuf,
    knowledge_root: PathBuf,
    receipt: PublicationReceipt,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let config = temp.path().join("config.toml");
        let state_root = temp.path().join("state");
        let knowledge_root = temp.path().join("knowledge");
        std::fs::create_dir_all(&state_root).unwrap();
        std::fs::create_dir_all(&knowledge_root).unwrap();
        let project = ProjectId::parse("project-a").unwrap();
        let ticket_run = TicketRunId::parse("run-123").unwrap();
        let source_content = "The deployment was delayed by a stale cache.";
        let source = KnowledgeSource {
            id: "source-1".into(),
            title: "Deployment notes".into(),
            resource: "https://example.invalid/deployment".into(),
            content: source_content.into(),
            digest: sha256(source_content.as_bytes()),
            trusted: false,
        };
        let input = PostmortemInput {
            operation_id: OperationId::parse("operation-123").unwrap(),
            project_id: project.clone(),
            ticket_run_id: ticket_run.clone(),
            title: "Deployment delay".into(),
            summary: "A stale cache delayed the deployment.".into(),
            findings: vec!["Clear the cache before retrying.".into()],
            sources: vec![source],
            generated_at: "2026-11-08T00:00:00Z".into(),
            max_source_bytes: 1024,
        };
        let receipt = publish_postmortem(&knowledge_root, &input).unwrap();
        seed_database(&state_root, &input, &receipt);
        let config_text = format!(
            "schema_version = 1\nstate_root = {}\nprojects = {{}}\n\n[adapters.tickets]\nkind = \"command\"\ncommand = [\"/bin/true\"]\n\n[knowledge]\nformat = \"okf\"\nroot = {}\nmax_source_bytes = 1024\n",
            toml_string(&state_root),
            toml_string(&knowledge_root),
        );
        std::fs::write(&config, config_text).unwrap();
        Self {
            _temp: temp,
            config,
            state_root,
            knowledge_root,
            receipt,
        }
    }

    fn run(&self, args: &[&str]) -> Output {
        self.run_from(args, Path::new("."))
    }

    fn run_from(&self, args: &[&str], cwd: &Path) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_rex-projects"));
        command
            .current_dir(cwd)
            .args(["--config", self.config.to_str().unwrap()])
            .args(["--state-root", self.state_root.to_str().unwrap()])
            .args(args);
        command.output().unwrap()
    }
}

#[test]
fn knowledge_cli_browses_scoped_receipts_and_validates_real_article_bytes() {
    let fixture = Fixture::new();

    let list = fixture.run(&["knowledge", "list", "--project", "project-a"]);
    assert!(
        list.status.success(),
        "{}",
        String::from_utf8_lossy(&list.stderr)
    );
    let list_text = String::from_utf8(list.stdout).unwrap();
    assert!(list_text.contains("Deployment delay"));
    assert!(list_text.contains("run-123"));

    let other_project = fixture.run(&["--json", "knowledge", "list", "--project", "project-b"]);
    assert!(other_project.status.success());
    let report: Value = serde_json::from_slice(&other_project.stdout).unwrap();
    assert_eq!(report["publications"].as_array().unwrap().len(), 0);

    let invalid_scope = fixture.run(&["--json", "knowledge", "list", "--project", "../project-b"]);
    assert_eq!(invalid_scope.status.code(), Some(2));
    let report: Value = serde_json::from_slice(&invalid_scope.stdout).unwrap();
    assert_eq!(report["error"]["code"], "invalid_request");

    let show = fixture.run(&[
        "--json",
        "knowledge",
        "show",
        "--project",
        "project-a",
        "--ticket-run",
        "run-123",
    ]);
    assert!(
        show.status.success(),
        "{}",
        String::from_utf8_lossy(&show.stderr)
    );
    let report: Value = serde_json::from_slice(&show.stdout).unwrap();
    assert_eq!(report["ticket_run_id"], "run-123");
    assert_eq!(
        report["manifest_sha256"],
        fixture.receipt.manifest_sha256.as_str()
    );
    assert!(
        report["article"]
            .as_str()
            .unwrap()
            .contains("data, not instructions")
    );

    let validate = fixture.run(&[
        "--json",
        "knowledge",
        "validate",
        "--project",
        "project-a",
        "--ticket-run",
        "run-123",
    ]);
    assert!(
        validate.status.success(),
        "{}",
        String::from_utf8_lossy(&validate.stderr)
    );
    let report: Value = serde_json::from_slice(&validate.stdout).unwrap();
    assert_eq!(report["valid"], true);
    assert_eq!(report["byte_count"], fixture.receipt.manifest.byte_count);
}

#[test]
fn knowledge_validate_rejects_tampered_frozen_article() {
    let fixture = Fixture::new();
    let article = fixture
        .knowledge_root
        .join(&fixture.receipt.manifest.relative_path);
    std::fs::write(article, "---\ntype: Postmortem\n---\nchanged\n").unwrap();

    let validate = fixture.run(&[
        "--json",
        "knowledge",
        "validate",
        "--project",
        "project-a",
        "--ticket-run",
        "run-123",
    ]);
    assert_eq!(validate.status.code(), Some(4));
    let report: Value = serde_json::from_slice(&validate.stdout).unwrap();
    assert_eq!(report["error"]["code"], "conflict");
}

#[test]
fn knowledge_show_resolves_relative_root_from_config_when_run_elsewhere() {
    let fixture = Fixture::new();
    let config = std::fs::read_to_string(&fixture.config).unwrap();
    let absolute_root = toml_string(&fixture.knowledge_root);
    let config = config.replace(&absolute_root, "\"knowledge\"");
    std::fs::write(&fixture.config, config).unwrap();
    let unrelated_cwd = fixture._temp.path().join("unrelated-cwd");
    std::fs::create_dir(&unrelated_cwd).unwrap();

    let show = fixture.run_from(
        &[
            "--json",
            "knowledge",
            "show",
            "--project",
            "project-a",
            "--ticket-run",
            "run-123",
        ],
        &unrelated_cwd,
    );
    assert!(
        show.status.success(),
        "{}",
        String::from_utf8_lossy(&show.stderr)
    );
    let report: Value = serde_json::from_slice(&show.stdout).unwrap();
    assert_eq!(report["project_id"], "project-a");
    assert!(
        report["article"]
            .as_str()
            .unwrap()
            .contains("data, not instructions")
    );
}

#[test]
fn knowledge_read_only_command_does_not_create_missing_state_or_knowledge_roots() {
    let fixture = Fixture::new();
    std::fs::remove_dir_all(&fixture.state_root).unwrap();
    std::fs::remove_dir_all(&fixture.knowledge_root).unwrap();

    let result = fixture.run(&["knowledge", "list", "--project", "project-a"]);
    assert_eq!(result.status.code(), Some(5));
    assert!(!fixture.state_root.exists());
    assert!(!fixture.knowledge_root.exists());
}

fn seed_database(state_root: &Path, input: &PostmortemInput, receipt: &PublicationReceipt) {
    let database = state_root.join("state.sqlite3");
    let connection = rusqlite::Connection::open(database).unwrap();
    connection
        .execute_batch(
            "CREATE TABLE knowledge_publications (
                project_id TEXT NOT NULL,
                ticket_run_id TEXT NOT NULL,
                request_digest TEXT NOT NULL,
                request_json TEXT NOT NULL,
                state TEXT NOT NULL,
                manifest_json TEXT,
                manifest_digest TEXT,
                created_at_unix INTEGER NOT NULL
            );",
        )
        .unwrap();
    connection
        .pragma_update(None, "user_version", rex_projects::store::SCHEMA_VERSION)
        .unwrap();
    let request_json = serde_json::to_string(input).unwrap();
    let request_digest = sha256(request_json.as_bytes());
    let manifest_json = serde_json::to_string(&receipt.manifest).unwrap();
    connection
        .execute(
            "INSERT INTO knowledge_publications(project_id,ticket_run_id,request_digest,request_json,state,manifest_json,manifest_digest,created_at_unix) VALUES (?1,?2,?3,?4,'published',?5,?6,0)",
            rusqlite::params![
                input.project_id.as_str(),
                input.ticket_run_id.as_str(),
                request_digest.as_str(),
                request_json,
                manifest_json,
                receipt.manifest_sha256.as_str(),
            ],
        )
        .unwrap();
}

fn sha256(bytes: &[u8]) -> Digest {
    Digest::parse(format!("{:x}", Sha256::digest(bytes))).unwrap()
}

fn toml_string(path: &Path) -> String {
    serde_json::to_string(path.to_str().unwrap()).unwrap()
}
