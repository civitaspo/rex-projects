use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=TARGET");
    println!("cargo:rerun-if-env-changed=CSM_CI_SOURCE_REVISION");
    println!("cargo:rerun-if-env-changed=CSM_CI_SOURCE_CLEAN");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/index");
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
