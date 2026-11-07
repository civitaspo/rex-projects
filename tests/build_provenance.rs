use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

struct Fixture {
    root: tempfile::TempDir,
    cargo_target: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let root = tempfile::Builder::new()
            .prefix(&format!("rex-projects provenance {label} "))
            .tempdir()
            .unwrap();
        let package = root.path();
        fs::create_dir(package.join("src")).unwrap();
        fs::write(
            package.join("Cargo.toml"),
            "[package]\nname = \"provenance-probe\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .unwrap();
        fs::write(package.join(".gitignore"), "/cargo-target/\n/Cargo.lock\n").unwrap();
        fs::copy(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("build.rs"),
            package.join("build.rs"),
        )
        .unwrap();
        fs::write(package.join("src/main.rs"), fixture_main()).unwrap();
        git(package, &["init", "-q"]);
        git(package, &["config", "user.name", "Build Provenance Test"]);
        git(
            package,
            &["config", "user.email", "build-provenance@example.invalid"],
        );
        git(
            package,
            &["add", "Cargo.toml", ".gitignore", "build.rs", "src/main.rs"],
        );
        git(
            package,
            &["-c", "commit.gpgsign=false", "commit", "-m", "initial"],
        );
        Self {
            cargo_target: root.path().join("cargo-target"),
            root,
        }
    }

    fn build_and_report(&self, package: &Path) -> Value {
        let output = cargo()
            .args([
                "build",
                "--quiet",
                "--offline",
                "--manifest-path",
                package.join("Cargo.toml").to_str().unwrap(),
            ])
            .env("CARGO_TARGET_DIR", &self.cargo_target)
            .env_remove("CSM_CI_SOURCE_REVISION")
            .env_remove("CSM_CI_SOURCE_CLEAN")
            .output()
            .unwrap();
        assert_success(&output, "cargo build provenance fixture");
        let executable = self.cargo_target.join("debug/provenance-probe");
        let output = Command::new(executable).output().unwrap();
        assert_success(&output, "run provenance fixture");
        serde_json::from_slice(&output.stdout).unwrap()
    }
}

fn cargo() -> Command {
    if let Some(path) = std::env::var_os("CARGO") {
        return Command::new(path);
    }
    let path = std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .map(|directory| directory.join("cargo"))
        .find(|candidate| candidate.is_file())
        .expect("cargo executable is available on PATH");
    Command::new(path)
}

fn git(directory: &Path, arguments: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(arguments)
        .output()
        .unwrap();
    assert_success(&output, &format!("git {}", arguments.join(" ")));
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn assert_success(output: &Output, command: &str) {
    assert!(
        output.status.success(),
        "{command} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_identity(report: &Value, revision: &str, dirty: bool) {
    assert_eq!(report["revision"], revision);
    assert_eq!(report["dirty"], dirty);
}

fn fixture_main() -> &'static str {
    r##"fn main() {
        let revision = option_env!("REX_PROJECTS_SOURCE_REVISION")
            .map(|value| format!("{value:?}"))
            .unwrap_or_else(|| "null".into());
        println!(r#"{{"revision":{revision},"dirty":{}}}"#, option_env!("REX_PROJECTS_BUILD_DIRTY").unwrap_or("unknown"));
    }
    "##
}

#[test]
fn build_metadata_tracks_source_edits_commits_and_linked_worktree_head() {
    let fixture = Fixture::new("main");
    let package = fixture.root.path();
    let initial = git(package, &["rev-parse", "HEAD"]);
    assert_identity(&fixture.build_and_report(package), &initial, false);

    fs::OpenOptions::new()
        .append(true)
        .open(package.join("src/main.rs"))
        .unwrap()
        .write_all(b"// tracked edit\n")
        .unwrap();
    assert_identity(&fixture.build_and_report(package), &initial, true);

    git(package, &["add", "src/main.rs"]);
    git(
        package,
        &["-c", "commit.gpgsign=false", "commit", "-m", "source edit"],
    );
    let committed = git(package, &["rev-parse", "HEAD"]);
    assert_ne!(committed, initial);
    assert_identity(&fixture.build_and_report(package), &committed, false);

    git(
        package,
        &[
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--allow-empty",
            "-m",
            "metadata-only commit",
        ],
    );
    let metadata_only = git(package, &["rev-parse", "HEAD"]);
    assert_ne!(metadata_only, committed);
    assert_identity(&fixture.build_and_report(package), &metadata_only, false);

    let linked = fixture.root.path().join("linked-worktree");
    git(
        package,
        &[
            "worktree",
            "add",
            "--detach",
            linked.to_str().unwrap(),
            &metadata_only,
        ],
    );
    assert!(
        linked.join(".git").is_file(),
        "fixture must use linked-worktree metadata"
    );
    assert_identity(&fixture.build_and_report(&linked), &metadata_only, false);

    git(
        &linked,
        &[
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--allow-empty",
            "-m",
            "linked metadata-only commit",
        ],
    );
    let linked_metadata_only = git(&linked, &["rev-parse", "HEAD"]);
    assert_ne!(linked_metadata_only, metadata_only);
    assert_identity(
        &fixture.build_and_report(&linked),
        &linked_metadata_only,
        false,
    );

    fs::OpenOptions::new()
        .append(true)
        .open(linked.join("src/main.rs"))
        .unwrap()
        .write_all(b"// linked edit\n")
        .unwrap();
    assert_identity(
        &fixture.build_and_report(&linked),
        &linked_metadata_only,
        true,
    );
    git(&linked, &["add", "src/main.rs"]);
    git(
        &linked,
        &[
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-m",
            "linked source edit",
        ],
    );
    let linked_revision = git(&linked, &["rev-parse", "HEAD"]);
    assert_ne!(linked_revision, linked_metadata_only);
    assert_identity(&fixture.build_and_report(&linked), &linked_revision, false);
}
