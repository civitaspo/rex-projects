use std::path::Path;
use std::process::{Command, Output};

fn run(config_dir: &Path, state_dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rex-projects"))
        .args(args)
        .env("REXP_CONFIG_DIR", config_dir)
        .env("REXP_STATE_DIR", state_dir)
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
fn creates_lists_and_cancels_tickets() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config");
    let state = dir.path().join("state");
    std::fs::create_dir_all(&config).unwrap();
    std::fs::write(
        config.join("config.toml"),
        "[[projects]]\nid = \"demo\"\nrepo = \"/tmp/demo\"\n",
    )
    .unwrap();

    assert!(stdout(&run(&config, &state, &["config", "check"])).contains("1 project(s)"));
    assert_eq!(
        stdout(&run(&config, &state, &["project", "list"])).trim(),
        "demo\t/tmp/demo"
    );

    let first = stdout(&run(
        &config,
        &state,
        &["ticket", "new", "--project", "demo", "--title", "First"],
    ));
    assert_eq!(first.trim(), "demo-1");
    let second = stdout(&run(
        &config,
        &state,
        &[
            "ticket",
            "new",
            "--project",
            "demo",
            "--title",
            "Second",
            "--blocked-by",
            "demo-1",
            "--ready",
        ],
    ));
    assert_eq!(second.trim(), "demo-2");

    let unknown = run(
        &config,
        &state,
        &["ticket", "new", "--project", "nope", "--title", "X"],
    );
    assert!(!unknown.status.success());

    stdout(&run(&config, &state, &["ticket", "ready", "demo-1"]));
    let ready = stdout(&run(
        &config,
        &state,
        &["ticket", "list", "--state", "ready"],
    ));
    assert!(ready.contains("demo-1\tready"));
    assert!(ready.contains("demo-2\tready"));

    stdout(&run(&config, &state, &["ticket", "cancel", "demo-2"]));
    let shown: serde_json::Value = serde_json::from_str(&stdout(&run(
        &config,
        &state,
        &["ticket", "show", "demo-2", "--json"],
    )))
    .unwrap();
    assert_eq!(shown["state"], "abandoned");
    assert_eq!(shown["blocked_by"][0], "demo-1");

    let events = stdout(&run(&config, &state, &["events"]));
    let kinds: Vec<String> = events
        .lines()
        .map(|line| {
            let value: serde_json::Value = serde_json::from_str(line).unwrap();
            value["event"]["kind"].as_str().unwrap().to_owned()
        })
        .collect();
    assert_eq!(
        kinds,
        vec![
            "ticket_created",
            "ticket_created",
            "ticket_readied",
            "ticket_cancelled"
        ]
    );
}
