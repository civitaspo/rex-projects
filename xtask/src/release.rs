use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::time::Duration;

use rex_projects::process::{ProcessRequest, resolve_executable, run};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

const RELEASE_PREDICATE: &str =
    "https://github.com/civitaspo/csm-ci-actions/attestation/release/v1";
const RELEASE_SIGNER: &str = "civitaspo/csm-ci-actions/.github/workflows/server.yml";
const TARGETS: [Target; 4] = [
    Target {
        normalized: "macos-aarch64",
        rust: "aarch64-apple-darwin",
        floor: FloorKind::Os,
    },
    Target {
        normalized: "macos-x86_64",
        rust: "x86_64-apple-darwin",
        floor: FloorKind::Os,
    },
    Target {
        normalized: "linux-aarch64",
        rust: "aarch64-unknown-linux-gnu",
        floor: FloorKind::Libc,
    },
    Target {
        normalized: "linux-x86_64",
        rust: "x86_64-unknown-linux-gnu",
        floor: FloorKind::Libc,
    },
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Target {
    normalized: &'static str,
    rust: &'static str,
    floor: FloorKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FloorKind {
    Os,
    Libc,
}

impl Target {
    fn binary_name(self) -> String {
        format!("rex-projects-{}", self.rust)
    }
    fn floor_key(self) -> &'static str {
        match self.floor {
            FloorKind::Os => "minimum_os",
            FloorKind::Libc => "minimum_libc",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct VersionInfo {
    name: String,
    version: String,
    target: String,
    cli_protocol: u32,
    database_schema: u32,
    source_revision: String,
    dirty: bool,
}

#[derive(Clone, Debug)]
struct AssetPin {
    target: Target,
    runtime_minimum: String,
    sha256: String,
}

#[derive(Clone, Debug)]
struct PackageInfo {
    version: String,
    repository: String,
}

fn valid_semver(value: &str) -> bool {
    // Cargo's version is already parsed by Cargo; this checks the release tag
    // shape and excludes whitespace/URL-sensitive values before interpolation.
    let core = value.split(['-', '+']).next().unwrap_or_default();
    let mut parts = core.split('.');
    let numeric = |part: Option<&str>| {
        part.is_some_and(|p| {
            !p.is_empty()
                && p.bytes().all(|b| b.is_ascii_digit())
                && (p == "0" || !p.starts_with('0'))
        })
    };
    numeric(parts.next())
        && numeric(parts.next())
        && numeric(parts.next())
        && parts.next().is_none()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".+-".contains(&b))
}

fn valid_sha(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn package_info(root: &Path) -> Result<PackageInfo, String> {
    let path = root.join("Cargo.toml");
    let source =
        fs::read_to_string(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let doc: toml::Value =
        toml::from_str(&source).map_err(|e| format!("cannot parse Cargo.toml: {e}"))?;
    let package = doc
        .get("package")
        .and_then(toml::Value::as_table)
        .ok_or("root Cargo.toml has no [package]")?;
    if package.get("name").and_then(toml::Value::as_str) != Some("rex-projects") {
        return Err("root Cargo package must be rex-projects".into());
    }
    let version = package
        .get("version")
        .and_then(toml::Value::as_str)
        .ok_or("Cargo package version is missing")?
        .to_owned();
    if !valid_semver(&version) {
        return Err("Cargo package version is not a stable SemVer release version".into());
    }
    let repository = package
        .get("repository")
        .and_then(toml::Value::as_str)
        .ok_or("Cargo package repository is missing")?;
    let suffix = repository
        .strip_prefix("https://github.com/")
        .ok_or("Cargo repository must be an HTTPS GitHub URL")?;
    let parts: Vec<_> = suffix.trim_end_matches('/').split('/').collect();
    if parts.len() != 2 || parts.iter().any(|part| !valid_component(part)) {
        return Err("Cargo repository must name exactly one GitHub owner/repository".into());
    }
    Ok(PackageInfo {
        version,
        repository: format!("https://github.com/{}/{}", parts[0], parts[1]),
    })
}

fn valid_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn current_protocol(pin_path: &Path) -> Result<u32, String> {
    let text = fs::read_to_string(pin_path).map_err(|e| {
        format!(
            "cannot read current Lua runtime pin {}: {e}",
            pin_path.display()
        )
    })?;
    let matches: Vec<_> = text
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let rhs = line
                .strip_prefix("protocol =")?
                .trim()
                .trim_end_matches(',')
                .trim();
            rhs.parse::<u32>().ok().filter(|n| *n > 0)
        })
        .collect();
    if matches.len() != 1 {
        return Err("current Lua runtime pin must declare exactly one positive protocol".into());
    }
    Ok(matches[0])
}

fn digest(path: &Path) -> Result<String, String> {
    let mut file = File::open(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let mut sha = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        use std::io::Read;
        let count = file
            .read(&mut buffer)
            .map_err(|e| format!("cannot hash {}: {e}", path.display()))?;
        if count == 0 {
            break;
        }
        sha.update(&buffer[..count]);
    }
    Ok(format!("{:x}", sha.finalize()))
}

fn regular_file(path: &Path) -> Result<fs::Metadata, String> {
    let meta = fs::symlink_metadata(path)
        .map_err(|e| format!("cannot inspect {}: {e}", path.display()))?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err(format!(
            "{} must be a regular non-symlink file",
            path.display()
        ));
    }
    Ok(meta)
}

fn executable(path: &Path) -> Result<(), String> {
    let meta = regular_file(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o111 == 0 {
            return Err(format!("{} is not executable", path.display()));
        }
    }
    if meta.len() == 0 {
        return Err(format!("{} is empty", path.display()));
    }
    Ok(())
}

fn parse_version_info(value: &Value, version: &str, target: Target) -> Result<VersionInfo, String> {
    let info: VersionInfo = serde_json::from_value(value.clone())
        .map_err(|e| format!("version_json does not match the CLI metadata schema: {e}"))?;
    if info.name != "rex-projects" || info.version != version || info.target != target.rust {
        return Err(format!(
            "{} version_json identity differs from Cargo version/target",
            target.normalized
        ));
    }
    if info.cli_protocol == 0 || info.database_schema == 0 {
        return Err("CLI protocol and database schema must be positive integers".into());
    }
    if !valid_sha(&info.source_revision) {
        return Err("version_json source_revision must be a lowercase 40-character Git SHA".into());
    }
    if info.dirty {
        return Err("release build must report dirty=false".into());
    }
    Ok(info)
}

fn validate_floor(target: Target, value: &str) -> Result<(), String> {
    match target.floor {
        FloorKind::Os => {
            let mut parts = value.split('.');
            if !parts
                .next()
                .is_some_and(|x| !x.is_empty() && x.bytes().all(|b| b.is_ascii_digit()))
                || !parts
                    .next()
                    .is_some_and(|x| !x.is_empty() && x.bytes().all(|b| b.is_ascii_digit()))
                || parts
                    .next()
                    .is_some_and(|x| x.is_empty() || !x.bytes().all(|b| b.is_ascii_digit()))
                || parts.next().is_some()
            {
                return Err(format!(
                    "{} minimum_os must be a measured dotted version",
                    target.normalized
                ));
            }
        }
        FloorKind::Libc => {
            let Some(version) = value.strip_prefix("glibc ") else {
                return Err("minimum_libc must use `glibc X.Y`".into());
            };
            let mut parts = version.split('.');
            let major = parts
                .next()
                .and_then(|x| x.parse::<u32>().ok())
                .ok_or("minimum_libc has an invalid glibc version")?;
            let minor = parts
                .next()
                .and_then(|x| x.parse::<u32>().ok())
                .ok_or("minimum_libc has an invalid glibc version")?;
            if parts.next().is_some() || (major, minor) < (2, 39) {
                return Err("Linux GNU assets require glibc 2.39 or newer".into());
            }
        }
    }
    Ok(())
}

fn asset_records(
    directory: &Path,
    version: &str,
    protocol: u32,
    expected_revision: Option<&str>,
) -> Result<Vec<AssetPin>, String> {
    let entries = fs::read_dir(directory)
        .map_err(|e| {
            format!(
                "cannot list release asset directory {}: {e}",
                directory.display()
            )
        })?
        .map(|entry| entry.map(|e| e.path()).map_err(|e| e.to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    let root_names: BTreeSet<_> = entries
        .iter()
        .map(|p| {
            p.file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    let normalized_names: BTreeSet<_> = TARGETS.iter().map(|t| t.normalized.to_owned()).collect();
    let flat_expected: BTreeSet<_> = std::iter::once("SHA256SUMS".to_owned())
        .chain(TARGETS.iter().flat_map(|t| {
            let binary = t.binary_name();
            [
                binary.clone(),
                format!("{binary}.artifact.json"),
                format!("{binary}.sha256"),
            ]
        }))
        .collect();
    let flat = if root_names == normalized_names {
        false
    } else if root_names == flat_expected {
        true
    } else {
        return Err("release asset set is incomplete or has unexpected files".into());
    };
    if flat {
        validate_flat_sums(directory)?;
    }
    let mut assets = Vec::with_capacity(TARGETS.len());
    let mut revisions = BTreeSet::new();
    let mut schemas = BTreeSet::new();
    for target in TARGETS {
        let (binary, sidecar) = if flat {
            let name = target.binary_name();
            (
                directory.join(&name),
                directory.join(format!("{name}.artifact.json")),
            )
        } else {
            let target_dir = directory.join(target.normalized);
            let metadata = fs::symlink_metadata(&target_dir)
                .map_err(|e| format!("cannot inspect target directory: {e}"))?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(format!("{} must be a regular directory", target.normalized));
            }
            let children = fs::read_dir(&target_dir)
                .map_err(|e| e.to_string())?
                .map(|entry| {
                    entry
                        .map(|e| e.file_name().to_string_lossy().into_owned())
                        .map_err(|e| e.to_string())
                })
                .collect::<Result<BTreeSet<_>, _>>()?;
            if children != BTreeSet::from(["artifact.json".to_owned(), "rex-projects".to_owned()]) {
                return Err(format!(
                    "{} must contain only rex-projects and artifact.json",
                    target.normalized
                ));
            }
            (
                target_dir.join("rex-projects"),
                target_dir.join("artifact.json"),
            )
        };
        executable(&binary)?;
        regular_file(&sidecar)?;
        let value: Value = serde_json::from_slice(
            &fs::read(&sidecar).map_err(|e| format!("cannot read {}: {e}", sidecar.display()))?,
        )
        .map_err(|e| format!("cannot parse {}: {e}", sidecar.display()))?;
        let object = value
            .as_object()
            .ok_or("artifact manifest must be a JSON object")?;
        let expected_keys = BTreeSet::from([
            "version",
            "target",
            "rust_target",
            target.floor_key(),
            "source_revision",
            "dirty",
            "version_json",
            "sha256",
        ]);
        if object.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected_keys {
            return Err(format!(
                "{} artifact manifest fields are invalid",
                target.normalized
            ));
        }
        if object.get("version").and_then(Value::as_str) != Some(version)
            || object.get("target").and_then(Value::as_str) != Some(target.normalized)
            || object.get("rust_target").and_then(Value::as_str) != Some(target.rust)
        {
            return Err(format!(
                "{} artifact identity differs from Cargo metadata",
                target.normalized
            ));
        }
        let runtime_minimum = object
            .get(target.floor_key())
            .and_then(Value::as_str)
            .ok_or("runtime floor must be a string")?
            .to_owned();
        validate_floor(target, &runtime_minimum)?;
        let info = parse_version_info(
            object
                .get("version_json")
                .ok_or("version_json is missing")?,
            version,
            target,
        )?;
        if info.cli_protocol != protocol {
            return Err(format!(
                "{} CLI protocol differs from the requested pin",
                target.normalized
            ));
        }
        if object.get("source_revision").and_then(Value::as_str)
            != Some(info.source_revision.as_str())
            || object.get("dirty").and_then(Value::as_bool) != Some(false)
        {
            return Err(format!(
                "{} artifact metadata disagrees with version_json",
                target.normalized
            ));
        }
        if let Some(expected) = expected_revision {
            if !valid_sha(expected) {
                return Err("expected source revision must be a lowercase 40-character SHA".into());
            }
            if expected != info.source_revision {
                return Err("release artifacts differ from the verified tag commit".into());
            }
        }
        let claimed = object
            .get("sha256")
            .and_then(Value::as_str)
            .ok_or("artifact SHA-256 is missing")?;
        if !valid_sha256(claimed) {
            return Err("artifact SHA-256 must be lowercase hexadecimal".into());
        }
        let actual = digest(&binary)?;
        if claimed != actual {
            return Err(format!(
                "{} executable SHA-256 differs from artifact.json",
                target.normalized
            ));
        }
        if flat {
            let checksum_name = format!("{}.sha256", target.binary_name());
            let checksum = fs::read_to_string(directory.join(&checksum_name))
                .map_err(|e| format!("cannot read {checksum_name}: {e}"))?;
            if checksum != format!("{actual}  {}\n", target.binary_name()) {
                return Err(format!(
                    "{} binary checksum sidecar differs from its bytes",
                    target.normalized
                ));
            }
        }
        revisions.insert(info.source_revision);
        schemas.insert(info.database_schema);
        assets.push(AssetPin {
            target,
            runtime_minimum,
            sha256: actual,
        });
    }
    if revisions.len() != 1 {
        return Err("release assets were not built from one source revision".into());
    }
    if schemas.len() != 1 {
        return Err("release assets report different database schema versions".into());
    }
    Ok(assets)
}

fn validate_flat_sums(directory: &Path) -> Result<(), String> {
    regular_file(&directory.join("SHA256SUMS"))?;
    let mut expected = BTreeMap::new();
    for target in TARGETS {
        let name = target.binary_name();
        for asset_name in [
            &name,
            &format!("{name}.artifact.json"),
            &format!("{name}.sha256"),
        ] {
            let path = directory.join(asset_name);
            regular_file(&path)?;
            expected.insert(asset_name.to_string(), digest(&path)?);
        }
    }
    let content = fs::read_to_string(directory.join("SHA256SUMS"))
        .map_err(|e| format!("cannot read SHA256SUMS: {e}"))?;
    let mut found = BTreeMap::new();
    for line in content.lines() {
        let Some((sha, name)) = line.split_once("  ") else {
            return Err("SHA256SUMS contains a malformed line".into());
        };
        if !valid_sha256(sha)
            || name.is_empty()
            || name.contains('/')
            || found.insert(name.to_owned(), sha.to_owned()).is_some()
        {
            return Err("SHA256SUMS contains an invalid or duplicate entry".into());
        }
    }
    if found != expected {
        return Err("SHA256SUMS differs from the downloaded asset set".into());
    }
    Ok(())
}

fn render_pin(package: &PackageInfo, protocol: u32, assets: &[AssetPin]) -> String {
    let mut output = format!(
        "return {{\n  status = \"released\",\n  version = \"{}\",\n  protocol = {},\n  targets = {{\n",
        package.version, protocol
    );
    let base = format!(
        "{}/releases/download/v{}",
        package.repository, package.version
    );
    for asset in assets {
        output.push_str(&format!("    [\"{}\"] = {{\n      rust_target = \"{}\",\n      url = \"{}/{}\",\n      sha256 = \"{}\",\n      {} = \"{}\",\n    }},\n", asset.target.normalized, asset.target.rust, base, asset.target.binary_name(), asset.sha256, asset.target.floor_key(), asset.runtime_minimum));
    }
    output.push_str("  },\n}\n");
    output
}

fn atomic_replace(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path.parent().ok_or("pin path has no parent directory")?;
    if !parent.is_dir() {
        return Err(format!(
            "Lua pin directory {} does not exist",
            parent.display()
        ));
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err("refusing to replace a symlinked Lua pin".into());
        }
        Ok(metadata) if !metadata.is_file() => {
            return Err("Lua pin target must be a regular file".into());
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("cannot inspect Lua pin target: {error}")),
    }
    let mut temporary = None;
    for attempt in 0..16_u8 {
        let name = format!(
            ".runtime_version.lua.{}.{}.tmp",
            std::process::id(),
            attempt
        );
        let candidate = parent.join(name);
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(mut file) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    file.set_permissions(fs::Permissions::from_mode(0o644))
                        .map_err(|e| format!("cannot set temporary Lua pin permissions: {e}"))?;
                }
                if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
                    drop(file);
                    let _ = fs::remove_file(&candidate);
                    return Err(format!("cannot write temporary Lua pin: {error}"));
                }
                drop(file);
                temporary = Some(candidate);
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(format!("cannot create temporary Lua pin: {error}")),
        }
    }
    let temporary = temporary.ok_or("could not allocate a temporary Lua pin path")?;
    let result =
        fs::rename(&temporary, path).map_err(|e| format!("cannot atomically replace Lua pin: {e}"));
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|e| format!("cannot sync Lua pin directory: {e}"))?;
    Ok(())
}

fn show_or_write_pin(pin_path: &Path, generated: &str, write: bool) -> Result<(), String> {
    if write {
        atomic_replace(pin_path, generated.as_bytes())?;
        println!("wrote verified Lua runtime pin {}", pin_path.display());
        return Ok(());
    }
    let current =
        fs::read_to_string(pin_path).map_err(|e| format!("cannot read Lua runtime pin: {e}"))?;
    if current == generated {
        println!("Lua runtime pin matches all four verified artifacts");
        return Ok(());
    }
    let diff = simple_diff(&current, generated);
    print!("{diff}");
    Err("Lua runtime pin differs; review the diff and rerun with --write".into())
}

fn simple_diff(current: &str, generated: &str) -> String {
    let mut output =
        String::from("--- current runtime_version.lua\n+++ generated runtime_version.lua\n");
    for line in current.lines() {
        output.push('-');
        output.push_str(line);
        output.push('\n');
    }
    for line in generated.lines() {
        output.push('+');
        output.push_str(line);
        output.push('\n');
    }
    output
}

fn absolute_lexical_path(path: &Path) -> Result<PathBuf, String> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        env::current_dir()
            .map(|current| current.join(path))
            .map_err(|e| format!("cannot resolve current directory: {e}"))
    }
}

pub fn pin_from_artifacts(
    root: &Path,
    artifact_root: &Path,
    pin_path: &Path,
    protocol: Option<u32>,
    expected_revision: Option<&str>,
    write: bool,
) -> Result<(), String> {
    let package = package_info(root)?;
    let pin_path = absolute_lexical_path(pin_path)?;
    let protocol = protocol
        .map(Ok)
        .unwrap_or_else(|| current_protocol(&pin_path))?;
    if protocol == 0 {
        return Err("CLI protocol must be positive".into());
    }
    let artifact_root = artifact_root
        .canonicalize()
        .map_err(|e| format!("cannot resolve asset directory: {e}"))?;
    let version_dir = artifact_root.join(&package.version);
    let directory = match fs::symlink_metadata(&version_dir) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err("versioned artifact directory must not be a symlink".into());
        }
        Ok(metadata) if metadata.is_dir() => version_dir,
        Ok(_) => artifact_root,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => artifact_root,
        Err(error) => {
            return Err(format!(
                "cannot inspect versioned artifact directory: {error}"
            ));
        }
    };
    let assets = asset_records(&directory, &package.version, protocol, expected_revision)?;
    show_or_write_pin(&pin_path, &render_pin(&package, protocol, &assets), write)
}

trait GhCommandRunner {
    fn run(&self, args: &[String], timeout: Duration) -> Result<String, String>;
}

struct ProcessGh {
    executable: PathBuf,
}

impl GhCommandRunner for ProcessGh {
    fn run(&self, args: &[String], timeout: Duration) -> Result<String, String> {
        let search_path: Vec<PathBuf> = env::var_os("PATH")
            .map(|path| env::split_paths(&path).collect())
            .unwrap_or_default();
        let executable = resolve_executable(&self.executable, &search_path).ok_or_else(|| {
            format!(
                "gh executable is unavailable: {}",
                self.executable.display()
            )
        })?;
        let output = run(ProcessRequest {
            executable,
            args: args.iter().map(Into::into).collect(),
            stdin: Vec::new(),
            cwd: None,
            clear_environment: false,
            environment: BTreeMap::new(),
            timeout,
            shutdown_grace: Duration::from_secs(3),
            stdout_limit: 8 * 1024 * 1024,
            stderr_tail_limit: 16 * 1024,
        })
        .map_err(|e| format!("gh invocation failed: {e}"))?;
        if output.timed_out
            || !output.cleanup_confirmed
            || output.stdout_truncated
            || output.stderr_truncated
            || !output.status.as_ref().is_some_and(ExitStatus::success)
        {
            return Err("gh command failed, timed out, or returned incomplete output".into());
        }
        String::from_utf8(output.stdout).map_err(|_| "gh output was not UTF-8".into())
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseInfo {
    #[serde(rename = "tagName")]
    tag_name: String,
    #[serde(rename = "isDraft")]
    is_draft: bool,
    #[serde(rename = "isPrerelease")]
    is_prerelease: bool,
}

fn expected_attestation(
    repository: &str,
    tag: &str,
    revision: &str,
    value: &Value,
) -> Result<(), String> {
    let rows = value
        .as_array()
        .filter(|rows| !rows.is_empty())
        .ok_or("gh returned no verified release attestations")?;
    for row in rows {
        let statement = row
            .pointer("/verificationResult/statement")
            .ok_or("attestation statement is incomplete")?;
        if statement.get("predicateType").and_then(Value::as_str) != Some(RELEASE_PREDICATE) {
            return Err("attestation type differs from the csm-ci release predicate".into());
        }
        let predicate = statement
            .get("predicate")
            .and_then(Value::as_object)
            .ok_or("attestation predicate is not an object")?;
        if predicate.get("client_repository").and_then(Value::as_str) != Some(repository)
            || predicate.get("merge_sha").and_then(Value::as_str) != Some(revision)
            || predicate.get("tag").and_then(Value::as_str) != Some(tag)
        {
            return Err("attestation source repository, merge SHA, or tag differs".into());
        }
    }
    Ok(())
}

fn release_asset_names() -> Vec<String> {
    let mut names = vec!["SHA256SUMS".to_owned()];
    for target in TARGETS {
        let binary = target.binary_name();
        names.extend([
            binary.clone(),
            format!("{binary}.artifact.json"),
            format!("{binary}.sha256"),
        ]);
    }
    names
}

fn refresh_with(
    root: &Path,
    pin_path: &Path,
    write: bool,
    gh: &impl GhCommandRunner,
) -> Result<(), String> {
    let package = package_info(root)?;
    let pin_path = absolute_lexical_path(pin_path)?;
    let protocol = current_protocol(&pin_path)?;
    let repository = package.repository.trim_start_matches("https://github.com/");
    let tag = format!("v{}", package.version);
    let release_output = gh.run(
        &[
            "release".into(),
            "view".into(),
            tag.clone(),
            "--repo".into(),
            repository.into(),
            "--json".into(),
            "tagName,isDraft,isPrerelease".into(),
        ],
        Duration::from_secs(60),
    )?;
    let release: ReleaseInfo = serde_json::from_str(&release_output)
        .map_err(|_| "gh returned invalid release metadata".to_owned())?;
    if release.tag_name != tag || release.is_draft || release.is_prerelease {
        return Err(format!("{tag} must be a published stable release"));
    }
    let revision = gh
        .run(
            &[
                "api".into(),
                format!("repos/{repository}/commits/{tag}"),
                "--jq".into(),
                ".sha".into(),
            ],
            Duration::from_secs(60),
        )?
        .trim()
        .to_owned();
    if !valid_sha(&revision) {
        return Err("gh returned an invalid source commit for the release tag".into());
    }
    let temporary = tempfile::tempdir()
        .map_err(|e| format!("cannot allocate a private release download directory: {e}"))?;
    gh.run(
        &[
            "release".into(),
            "download".into(),
            tag.clone(),
            "--repo".into(),
            repository.into(),
            "--dir".into(),
            temporary.path().display().to_string(),
        ],
        Duration::from_secs(120),
    )?;
    for name in release_asset_names() {
        let path = temporary.path().join(&name);
        regular_file(&path)?;
        let output = gh.run(
            &[
                "attestation".into(),
                "verify".into(),
                path.display().to_string(),
                "--owner".into(),
                repository.split('/').next().unwrap_or_default().into(),
                "--signer-workflow".into(),
                RELEASE_SIGNER.into(),
                "--predicate-type".into(),
                RELEASE_PREDICATE.into(),
                "--deny-self-hosted-runners".into(),
                "--format".into(),
                "json".into(),
            ],
            Duration::from_secs(120),
        )?;
        let attestation: Value = serde_json::from_str(&output)
            .map_err(|_| format!("attestation verification for {name} returned invalid JSON"))?;
        expected_attestation(repository, &tag, &revision, &attestation)
            .map_err(|e| format!("{name}: {e}"))?;
    }
    let assets = asset_records(
        temporary.path(),
        &package.version,
        protocol,
        Some(&revision),
    )?;
    show_or_write_pin(&pin_path, &render_pin(&package, protocol, &assets), write)
}

pub fn refresh_pin(
    root: &Path,
    pin_path: &Path,
    gh_path: &Path,
    write: bool,
) -> Result<(), String> {
    let runner = ProcessGh {
        executable: gh_path.to_path_buf(),
    };
    refresh_with(root, pin_path, write, &runner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Mutex;

    fn flat_bundle(root: &Path, version: &str, revision: &str) -> PathBuf {
        let directory = root.join("downloaded");
        fs::create_dir_all(&directory).unwrap();
        for target in TARGETS {
            let binary_name = target.binary_name();
            let binary = directory.join(&binary_name);
            fs::write(&binary, format!("asset-{}", target.normalized)).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).unwrap();
            }
            let floor = match target.floor {
                FloorKind::Os => "11.0",
                FloorKind::Libc => "glibc 2.39",
            };
            let info = VersionInfo {
                name: "rex-projects".into(),
                version: version.into(),
                target: target.rust.into(),
                cli_protocol: 1,
                database_schema: 4,
                source_revision: revision.into(),
                dirty: false,
            };
            let manifest = json!({
                "version": version,
                "target": target.normalized,
                "rust_target": target.rust,
                target.floor_key(): floor,
                "source_revision": revision,
                "dirty": false,
                "version_json": info,
                "sha256": digest(&binary).unwrap()
            });
            fs::write(
                directory.join(format!("{binary_name}.artifact.json")),
                serde_json::to_vec_pretty(&manifest).unwrap(),
            )
            .unwrap();
            fs::write(
                directory.join(format!("{binary_name}.sha256")),
                format!("{}  {binary_name}\n", digest(&binary).unwrap()),
            )
            .unwrap();
        }
        let mut names: Vec<_> = fs::read_dir(&directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        let sums = names
            .iter()
            .map(|name| format!("{}  {name}\n", digest(&directory.join(name)).unwrap()))
            .collect::<String>();
        fs::write(directory.join("SHA256SUMS"), sums).unwrap();
        directory
    }

    struct FakeGh {
        assets: PathBuf,
        revision: String,
        wrong_attestation: bool,
        calls: Mutex<Vec<Vec<String>>>,
    }

    impl GhCommandRunner for FakeGh {
        fn run(&self, args: &[String], _timeout: Duration) -> Result<String, String> {
            self.calls.lock().unwrap().push(args.to_vec());
            match args.first().map(String::as_str) {
                Some("release") if args.get(1).map(String::as_str) == Some("view") => Ok(
                    json!({"tagName":"v0.1.0","isDraft":false,"isPrerelease":false}).to_string(),
                ),
                Some("api") => Ok(format!("{}\n", self.revision)),
                Some("release") if args.get(1).map(String::as_str) == Some("download") => {
                    let destination = PathBuf::from(
                        args[args.iter().position(|arg| arg == "--dir").unwrap() + 1].clone(),
                    );
                    fs::create_dir_all(&destination).map_err(|error| error.to_string())?;
                    for entry in fs::read_dir(&self.assets).map_err(|error| error.to_string())? {
                        let entry = entry.map_err(|error| error.to_string())?;
                        fs::copy(entry.path(), destination.join(entry.file_name()))
                            .map_err(|error| error.to_string())?;
                    }
                    Ok(String::new())
                }
                Some("attestation") if args.get(1).map(String::as_str) == Some("verify") => {
                    let revision = if self.wrong_attestation {
                        "b".repeat(40)
                    } else {
                        self.revision.clone()
                    };
                    Ok(json!([{"verificationResult":{"statement":{"predicateType":RELEASE_PREDICATE,"predicate":{"client_repository":"civitaspo/rex-projects","merge_sha":revision,"tag":"v0.1.0"}}}}]).to_string())
                }
                _ => Err(format!("unexpected gh arguments: {args:?}")),
            }
        }
    }

    fn refresh_root(path: &Path) -> (PathBuf, PathBuf) {
        fs::create_dir_all(path.join("lua/rex_projects")).unwrap();
        fs::write(path.join("Cargo.toml"), "[package]\nname='rex-projects'\nversion='0.1.0'\nrepository='https://github.com/civitaspo/rex-projects'\n").unwrap();
        let pin = path.join("lua/rex_projects/runtime_version.lua");
        fs::write(&pin, "return {\n  status = \"unreleased\",\n  version = \"0.1.0\",\n  protocol = 1,\n  targets = {},\n}\n").unwrap();
        (path.to_path_buf(), pin)
    }

    #[test]
    fn release_assets_and_pin_round_trip_for_four_targets() {
        let temp = tempfile::tempdir().unwrap();
        let version = "0.1.0";
        let revision = "a".repeat(40);
        let version_root = temp.path().join(version);
        for target in TARGETS {
            let dir = version_root.join(target.normalized);
            fs::create_dir_all(&dir).unwrap();
            let binary = dir.join("rex-projects");
            fs::write(&binary, format!("fixture-{}", target.normalized)).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).unwrap();
            }
            let floor = match target.floor {
                FloorKind::Os => "11.0",
                FloorKind::Libc => "glibc 2.39",
            };
            let info = VersionInfo {
                name: "rex-projects".into(),
                version: version.into(),
                target: target.rust.into(),
                cli_protocol: 1,
                database_schema: 4,
                source_revision: revision.clone(),
                dirty: false,
            };
            let manifest = json!({"version":version,"target":target.normalized,"rust_target":target.rust,target.floor_key():floor,"source_revision":revision,"dirty":false,"version_json":info,"sha256":digest(&binary).unwrap()});
            fs::write(
                dir.join("artifact.json"),
                serde_json::to_vec_pretty(&manifest).unwrap(),
            )
            .unwrap();
        }
        let assets = asset_records(&version_root, version, 1, Some(&revision)).unwrap();
        let pin = render_pin(
            &PackageInfo {
                version: version.into(),
                repository: "https://github.com/civitaspo/rex-projects".into(),
            },
            1,
            &assets,
        );
        assert!(pin.contains("https://github.com/civitaspo/rex-projects/releases/download/v0.1.0/rex-projects-aarch64-apple-darwin"));
        assert_eq!(assets.len(), 4);
    }

    #[test]
    fn flat_release_checks_all_asset_digests_and_exact_target_set() {
        let temp = tempfile::tempdir().unwrap();
        let revision = "a".repeat(40);
        let directory = flat_bundle(temp.path(), "0.1.0", &revision);
        assert_eq!(
            asset_records(&directory, "0.1.0", 1, Some(&revision))
                .unwrap()
                .len(),
            4
        );
        fs::write(
            directory.join("rex-projects-aarch64-apple-darwin"),
            b"tampered",
        )
        .unwrap();
        assert!(
            asset_records(&directory, "0.1.0", 1, Some(&revision))
                .unwrap_err()
                .contains("SHA256SUMS")
        );
    }

    #[test]
    fn refresh_verifies_every_attested_asset_before_writing_pin() {
        let temp = tempfile::tempdir().unwrap();
        let (root, pin) = refresh_root(temp.path());
        let revision = "a".repeat(40);
        let assets = flat_bundle(temp.path(), "0.1.0", &revision);
        let gh = FakeGh {
            assets,
            revision: revision.clone(),
            wrong_attestation: false,
            calls: Mutex::new(Vec::new()),
        };
        refresh_with(&root, &pin, true, &gh).unwrap();
        let generated = fs::read_to_string(&pin).unwrap();
        assert!(generated.contains("status = \"released\""));
        assert_eq!(
            gh.calls
                .lock()
                .unwrap()
                .iter()
                .filter(|call| call.first().is_some_and(|arg| arg == "attestation"))
                .count(),
            13
        );
        assert!(
            gh.calls
                .lock()
                .unwrap()
                .iter()
                .filter(|call| call.first().is_some_and(|arg| arg == "attestation"))
                .all(|call| {
                    call.windows(2)
                        .any(|pair| pair == ["--signer-workflow", RELEASE_SIGNER])
                        && call
                            .windows(2)
                            .any(|pair| pair == ["--deny-self-hosted-runners", "--format"])
                        && call
                            .windows(2)
                            .any(|pair| pair == ["--predicate-type", RELEASE_PREDICATE])
                })
        );
    }

    #[test]
    fn untrusted_attestation_leaves_the_existing_pin_untouched() {
        let temp = tempfile::tempdir().unwrap();
        let (root, pin) = refresh_root(temp.path());
        let original = fs::read_to_string(&pin).unwrap();
        let revision = "a".repeat(40);
        let assets = flat_bundle(temp.path(), "0.1.0", &revision);
        let gh = FakeGh {
            assets,
            revision,
            wrong_attestation: true,
            calls: Mutex::new(Vec::new()),
        };
        assert!(
            refresh_with(&root, &pin, true, &gh)
                .unwrap_err()
                .contains("attestation source")
        );
        assert_eq!(fs::read_to_string(&pin).unwrap(), original);
    }

    #[test]
    fn tampered_or_missing_target_fails_closed() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("assets");
        fs::create_dir_all(&root).unwrap();
        let error = asset_records(&root, "0.1.0", 1, None).unwrap_err();
        assert!(error.contains("incomplete"));
    }

    #[test]
    fn attestation_binds_repository_tag_revision_and_predicate_type() {
        let revision = "a".repeat(40);
        let attestation = json!([{"verificationResult":{"statement":{"predicateType":RELEASE_PREDICATE,"predicate":{"client_repository":"civitaspo/rex-projects","merge_sha":revision,"tag":"v0.1.0"}}}}]);
        expected_attestation("civitaspo/rex-projects", "v0.1.0", &revision, &attestation).unwrap();
        let mut tampered = attestation;
        tampered[0]["verificationResult"]["statement"]["predicate"]["merge_sha"] =
            json!("b".repeat(40));
        assert!(
            expected_attestation("civitaspo/rex-projects", "v0.1.0", &revision, &tampered).is_err()
        );
    }

    #[test]
    fn glibc_floor_cannot_claim_older_linux_runtime() {
        let target = TARGETS
            .into_iter()
            .find(|target| target.normalized == "linux-x86_64")
            .unwrap();
        assert!(validate_floor(target, "glibc 2.38").is_err());
        assert!(validate_floor(target, "glibc 2.39").is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn pin_write_refuses_symlink_and_preserves_target() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let actual = temp.path().join("actual.lua");
        let link = temp.path().join("runtime_version.lua");
        fs::write(&actual, "original").unwrap();
        symlink(&actual, &link).unwrap();
        assert!(
            atomic_replace(&link, b"replacement")
                .unwrap_err()
                .contains("symlink")
        );
        assert_eq!(fs::read(&actual).unwrap(), b"original");
    }
}
