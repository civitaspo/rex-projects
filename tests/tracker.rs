use std::path::Path;
use std::process::{Command, Output};

const SCRIPT: &str = r#"echo "$*" >> "$(dirname "$0")/log"
case "$1" in
  get) printf '{"id":"%s","name":"Fix the %s bug","text":"Steps to reproduce","state":"todo"}\n' "$2" "$2" ;;
  search) printf '[{"id":"T-1","name":"One","state":"todo"},{"id":"T-2","name":"Two","state":"doing"}]\n' ;;
esac
"#;

const CONFIG: &str = r#"
[[projects]]
id = "demo"
repo = "/tmp/demo"
tracker = { name = "simple-tracker", vars = { board = "core" } }

[trackers.simple-tracker]
get = { argv = ["/bin/sh", "SH", "get", "{{ref}}", "--board", "{{board}}"], map = '{ref: .id, url: "https://tracker.example/\(.id)", title: .name, body: .text, status: (if .state == "doing" then "in_progress" else "open" end)}' }
list = { argv = ["/bin/sh", "SH", "search", "{{query}}"], map = 'map({ref: .id, title: .name, status: (if .state == "doing" then "in_progress" else "open" end)})' }
comment = { argv = ["/bin/sh", "SH", "comment", "{{ref}}", "{{body}}"] }
transition.done = [{ argv = ["/bin/sh", "SH", "close", "{{ref}}"] }]
"#;

fn run(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rex-projects"))
        .args(args)
        .env("REXP_CONFIG_DIR", dir.join("config"))
        .env("REXP_STATE_DIR", dir.join("state"))
        .env_remove("REXP_AGENT_ID")
        .output()
        .expect("failed to run rex-projects")
}

fn stdout(output: &Output) -> String {
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout.clone()).unwrap()
}

#[test]
fn imports_and_lists_items_through_a_fake_tracker() {
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("tracker.sh");
    std::fs::write(&script, SCRIPT).unwrap();
    std::fs::create_dir_all(dir.path().join("config")).unwrap();
    std::fs::write(
        dir.path().join("config/config.toml"),
        CONFIG.replace("SH", script.to_str().unwrap()),
    )
    .unwrap();

    let id = stdout(&run(
        dir.path(),
        &["ticket", "import", "T-9", "--project", "demo", "--ready"],
    ));
    assert_eq!(id.trim(), "demo-1");
    let ticket: serde_json::Value = serde_json::from_str(&stdout(&run(
        dir.path(),
        &["ticket", "show", "demo-1", "--json"],
    )))
    .unwrap();
    assert_eq!(ticket["title"], "Fix the T-9 bug");
    assert_eq!(ticket["body"], "Steps to reproduce");
    assert_eq!(ticket["state"], "ready");
    assert_eq!(
        ticket["external_refs"],
        serde_json::json!([{
            "tracker": "simple-tracker",
            "ref": "T-9",
            "url": "https://tracker.example/T-9"
        }])
    );

    let again = run(
        dir.path(),
        &["ticket", "import", "T-9", "--project", "demo"],
    );
    assert!(!again.status.success());
    assert!(String::from_utf8_lossy(&again.stderr).contains("demo-1 already tracks"));

    let listed = stdout(&run(
        dir.path(),
        &["tracker", "list", "--project", "demo", "--query", "is:open"],
    ));
    assert_eq!(listed, "T-1\topen\tOne\nT-2\tin_progress\tTwo\n");
    assert_eq!(stdout(&run(dir.path(), &["tracker", "jobs"])), "");

    let log = std::fs::read_to_string(dir.path().join("log")).unwrap();
    assert_eq!(
        log,
        "get T-9 --board core\nget T-9 --board core\nsearch is:open\n"
    );
}
