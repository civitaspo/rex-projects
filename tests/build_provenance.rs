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
        let signing_key = package.join(".git/build-provenance-signing-key");
        let key_generation = Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", ""])
            .arg("-f")
            .arg(&signing_key)
            .output()
            .unwrap();
        assert_success(&key_generation, "generate isolated fixture signing key");
        let public_key = Command::new("ssh-keygen")
            .arg("-y")
            .arg("-f")
            .arg(&signing_key)
            .output()
            .unwrap();
        assert_success(&public_key, "read isolated fixture signing key");
        let public_key = String::from_utf8(public_key.stdout).unwrap();
        let (key_type, key_data) = public_key.split_once(' ').unwrap();
        let allowed_signers = package.join(".git/build-provenance-allowed-signers");
        fs::write(
            &allowed_signers,
            format!("build-provenance@example.invalid namespaces=\"git\" {key_type} {key_data}"),
        )
        .unwrap();
        git(package, &["config", "user.name", "Build Provenance Test"]);
        git(
            package,
            &["config", "user.email", "build-provenance@example.invalid"],
        );
        git(package, &["config", "gpg.format", "ssh"]);
        git(
            package,
            &["config", "user.signingkey", signing_key.to_str().unwrap()],
        );
        git(
            package,
            &[
                "config",
                "gpg.ssh.allowedSignersFile",
                allowed_signers.to_str().unwrap(),
            ],
        );
        git(package, &["config", "commit.gpgsign", "true"]);
        git(
            package,
            &["add", "Cargo.toml", ".gitignore", "build.rs", "src/main.rs"],
        );
        git(package, &["commit", "-m", "initial"]);
        git(package, &["verify-commit", "HEAD"]);
        Self {
            cargo_target: root.path().join("cargo-target"),
            root,
        }
    }

    fn build_and_report(&self, package: &Path) -> Value {
        let output = self.build(package, true);
        assert_success(&output, "cargo build provenance fixture");
        let executable = self.cargo_target.join("debug/provenance-probe");
        let output = Command::new(executable).output().unwrap();
        assert_success(&output, "run provenance fixture");
        serde_json::from_slice(&output.stdout).unwrap()
    }

    fn build(&self, package: &Path, quiet: bool) -> Output {
        let mut command = cargo();
        command.arg("build").arg("--offline");
        if quiet {
            command.arg("--quiet");
        } else {
            command.arg("-vv");
        }
        command
            .arg("--manifest-path")
            .arg(package.join("Cargo.toml"))
            .env("CARGO_TARGET_DIR", &self.cargo_target)
            .env_remove("CSM_CI_SOURCE_REVISION")
            .env_remove("CSM_CI_SOURCE_CLEAN")
            .output()
            .unwrap()
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
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_COUNT", "0")
        .env_remove("GIT_CONFIG_PARAMETERS")
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
    git(package, &["verify-commit", "HEAD"]);
    let noop_build = fixture.build(package, false);
    assert_success(&noop_build, "no-op cargo build provenance fixture");
    let noop_output = format!(
        "{}{}",
        String::from_utf8_lossy(&noop_build.stdout),
        String::from_utf8_lossy(&noop_build.stderr)
    );
    assert!(
        noop_output.contains("Fresh provenance-probe"),
        "unchanged build recompiled unexpectedly:\n{noop_output}"
    );

    let untracked_source = package.join("src/untracked.rs");
    fs::write(&untracked_source, "pub const UNTRACKED: bool = true;\n").unwrap();
    assert_identity(&fixture.build_and_report(package), &initial, true);
    fs::remove_file(untracked_source).unwrap();
    assert_identity(&fixture.build_and_report(package), &initial, false);

    fs::OpenOptions::new()
        .append(true)
        .open(package.join("src/main.rs"))
        .unwrap()
        .write_all(b"// tracked edit\n")
        .unwrap();
    assert_identity(&fixture.build_and_report(package), &initial, true);

    git(package, &["add", "src/main.rs"]);
    git(package, &["commit", "-m", "source edit"]);
    git(package, &["verify-commit", "HEAD"]);
    let committed = git(package, &["rev-parse", "HEAD"]);
    assert_ne!(committed, initial);
    assert_identity(&fixture.build_and_report(package), &committed, false);

    git(
        package,
        &["commit", "--allow-empty", "-m", "metadata-only commit"],
    );
    git(package, &["verify-commit", "HEAD"]);
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
            "commit",
            "--allow-empty",
            "-m",
            "linked metadata-only commit",
        ],
    );
    git(&linked, &["verify-commit", "HEAD"]);
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
    git(&linked, &["commit", "-m", "linked source edit"]);
    git(&linked, &["verify-commit", "HEAD"]);
    let linked_revision = git(&linked, &["rev-parse", "HEAD"]);
    assert_ne!(linked_revision, linked_metadata_only);
    assert_identity(&fixture.build_and_report(&linked), &linked_revision, false);
}
