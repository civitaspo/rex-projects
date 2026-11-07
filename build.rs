use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=TARGET");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/index");
    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".into());
    println!("cargo:rustc-env=REX_PROJECTS_BUILD_TARGET={target}");

    let revision = git(&["rev-parse", "--verify", "HEAD"]);
    let dirty = git(&["status", "--porcelain"]).map(|status| !status.trim().is_empty());
    if let Some(revision) = revision
        .filter(|value| value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        println!("cargo:rustc-env=REX_PROJECTS_SOURCE_REVISION={revision}");
    }
    if let Some(dirty) = dirty {
        println!("cargo:rustc-env=REX_PROJECTS_BUILD_DIRTY={dirty}");
    }
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
