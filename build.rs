use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=TARGET");
    println!("cargo:rerun-if-env-changed=CSM_CI_SOURCE_REVISION");
    println!("cargo:rerun-if-env-changed=CSM_CI_SOURCE_CLEAN");
    emit_source_watch_paths();
    emit_git_watch_paths();
    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".into());
    println!("cargo:rustc-env=REX_PROJECTS_BUILD_TARGET={target}");

    let (revision, dirty) = ci_source_identity().unwrap_or_else(|error| panic!("{error}"));
    if let Some(revision) = revision {
        println!("cargo:rustc-env=REX_PROJECTS_SOURCE_REVISION={revision}");
    }
    if let Some(dirty) = dirty {
        println!("cargo:rustc-env=REX_PROJECTS_BUILD_DIRTY={dirty}");
    }
}

fn emit_source_watch_paths() {
    let manifest_dir = std::env::var_os("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().expect("current directory is available"));
    let root = manifest_dir
        .canonicalize()
        .unwrap_or_else(|error| panic!("cannot resolve package directory: {error}"));
    let target_dir = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .map(|path| {
            if path.is_absolute() {
                path
            } else {
                root.join(path)
            }
        })
        .or_else(|| {
            std::env::var_os("OUT_DIR")
                .map(PathBuf::from)
                .and_then(|path| path.ancestors().nth(4).map(Path::to_path_buf))
        })
        .and_then(|path| path.canonicalize().ok());

    let mut pending = vec![root.clone()];
    while let Some(directory) = pending.pop() {
        if is_inside(&directory, &root.join(".git"))
            || target_dir
                .as_ref()
                .is_some_and(|target| is_inside(&directory, target))
        {
            continue;
        }
        emit_changed_path(&directory);
        let entries = match std::fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                pending.push(path);
            } else if entry.file_type().is_ok_and(|kind| kind.is_file()) {
                emit_changed_path(&path);
            }
        }
    }
}

fn emit_git_watch_paths() {
    for git_path in ["HEAD", "index", "packed-refs"] {
        if let Some(path) = git(&[
            "rev-parse",
            "--path-format=absolute",
            "--git-path",
            git_path,
        ]) {
            emit_changed_path(Path::new(&path));
        }
    }
    if let Some(reference) = git(&["symbolic-ref", "--quiet", "HEAD"]) {
        if let Some(path) = git(&[
            "rev-parse",
            "--path-format=absolute",
            "--git-path",
            &reference,
        ]) {
            emit_changed_path(Path::new(&path));
            if let Some(parent) = Path::new(&path).parent() {
                emit_changed_path(parent);
            }
        }
    }
}

fn emit_changed_path(path: &Path) {
    println!("cargo:rerun-if-changed={}", path.display());
}

fn is_inside(path: &Path, parent: &Path) -> bool {
    path == parent || path.starts_with(parent)
}

fn ci_source_identity() -> Result<(Option<String>, Option<bool>), String> {
    let revision = environment_value("CSM_CI_SOURCE_REVISION")?;
    let clean = environment_value("CSM_CI_SOURCE_CLEAN")?;
    match (revision, clean) {
        (None, None) => {
            let revision =
                git(&["rev-parse", "--verify", "HEAD"]).filter(|value| valid_revision(value));
            let dirty = git(&["status", "--porcelain"]).map(|status| !status.trim().is_empty());
            Ok((revision, dirty))
        }
        (Some(revision), Some(clean)) => {
            if !valid_revision(&revision) {
                return Err(
                    "CSM_CI_SOURCE_REVISION must be a full lowercase 40-character Git SHA".into(),
                );
            }
            let dirty = match clean.as_str() {
                "true" => false,
                "false" => true,
                _ => return Err("CSM_CI_SOURCE_CLEAN must be exactly true or false".into()),
            };
            Ok((Some(revision), Some(dirty)))
        }
        _ => Err("CSM_CI_SOURCE_REVISION and CSM_CI_SOURCE_CLEAN must be set together".into()),
    }
}

fn environment_value(name: &str) -> Result<Option<String>, String> {
    std::env::var_os(name)
        .map(|value| {
            value
                .into_string()
                .map_err(|_| format!("{name} must contain valid UTF-8"))
        })
        .transpose()
}

fn valid_revision(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn git(arguments: &[&str]) -> Option<String> {
    let output = Command::new("git").args(arguments).output().ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout)
        .ok()
        .map(|value| value.trim().to_owned())
}
