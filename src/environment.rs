//! Captures a user shell environment once per host controller lifetime.
//!
//! Values in `EnvironmentSnapshot` are intentionally omitted from `Debug`, serde, and all
//! durable state. They are only copied into the process environment of an explicitly selected
//! child or a short-lived, mode-0600 launch handoff.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::hash::{BuildHasher, Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sha2::{Digest as _, Sha256};

use crate::config::{EnvironmentConfig, EnvironmentSource};
use crate::domain::ids::Digest;
use crate::process::{ProcessRequest, resolve_executable, run};

const FRAME_MAGIC: &[u8] = b"\0REX-PROJECTS-ENV\0\x01";
const HANDOFF_MAGIC: &[u8] = b"\0REX-PROJECTS-HANDOFF\0\x01";
const MAX_ENVIRONMENT_BYTES: usize = 2 * 1024 * 1024;
const MAX_STARTUP_OUTPUT_BYTES: usize = 256 * 1024;
const MAX_SNAPSHOT_BYTES: usize = MAX_ENVIRONMENT_BYTES + 128;
const CAPTURE_MARKER: &str = "environment_capture";
const CAPTURE_PROGRAM: &str = r#"exec "$1" __internal env-capture "$2" "$3""#;
const CAPTURE_SHUTDOWN_GRACE: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChildContext {
    Agent,
    RexProjectsHook,
    HostOperation,
}

impl ChildContext {
    fn marker(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::RexProjectsHook => "rex_projects_hook",
            Self::HostOperation => "host_operation",
        }
    }
}

/// Non-secret metadata suitable for a controller status or durable snapshot reference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvironmentSnapshotMetadata {
    pub id: Digest,
    pub source: EnvironmentSource,
    pub shell: Option<PathBuf>,
}

/// In-memory child environment. Its debug representation never includes variable values.
#[derive(Clone)]
pub struct EnvironmentSnapshot {
    metadata: EnvironmentSnapshotMetadata,
    variables: Arc<BTreeMap<OsString, OsString>>,
}

impl std::fmt::Debug for EnvironmentSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnvironmentSnapshot")
            .field("metadata", &self.metadata)
            .field("variable_count", &self.variables.len())
            .finish()
    }
}

impl EnvironmentSnapshot {
    pub fn metadata(&self) -> &EnvironmentSnapshotMetadata {
        &self.metadata
    }

    pub fn variable_count(&self) -> usize {
        self.variables.len()
    }

    /// Build a fresh marked child environment, preserving only Rex's active session identity
    /// from the current launch context rather than a potentially stale captured value.
    pub fn child_environment(
        &self,
        context: ChildContext,
        active_rex_environment: &BTreeMap<OsString, OsString>,
    ) -> BTreeMap<OsString, OsString> {
        let mut values = self
            .variables
            .iter()
            .filter(|(key, _)| !is_factory_context_key(key) && !is_rex_session_key(key))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<BTreeMap<_, _>>();
        for name in ["REX_SESSION", "REX_BLOCK_ID"] {
            let name = OsStr::new(name);
            if let Some(value) = active_rex_environment.get(name) {
                values.insert(name.to_os_string(), value.clone());
            }
        }
        values.insert(
            OsString::from("REX_PROJECTS_CONTEXT"),
            OsString::from(context.marker()),
        );
        values.insert(
            OsString::from("REX_PROJECTS_AGENT"),
            OsString::from(if context == ChildContext::Agent {
                "1"
            } else {
                "0"
            }),
        );
        values
    }

    /// Create a one-use file outside a provider workspace. Its path and nonce can be retained
    /// by the controller so a restarted launcher can consume the same handoff.
    pub fn create_handoff(
        &self,
        state_root: &Path,
        operation_id: &str,
    ) -> Result<EnvironmentHandoff, EnvironmentError> {
        if operation_id.is_empty() || operation_id.len() > 128 || operation_id.contains('\0') {
            return Err(EnvironmentError::Invalid(
                "invalid launch operation identity",
            ));
        }
        let nonce = fresh_nonce();
        let directory = state_root.join("environment-handoffs");
        create_private_directory(&directory)?;
        let path = directory.join(format!("{}.env", nonce.as_str()));
        let mut file = private_create_new(&path)?;
        use std::io::Write;
        let result = file
            .write_all(HANDOFF_MAGIC)
            .and_then(|()| file.write_all(self.metadata.id.as_str().as_bytes()))
            .and_then(|()| file.write_all(&[0]))
            .and_then(|()| file.write_all(operation_id.as_bytes()))
            .and_then(|()| file.write_all(&[0]))
            .and_then(|()| file.write_all(nonce.as_str().as_bytes()))
            .and_then(|()| file.write_all(&[0]))
            .and_then(|()| write_variables(&mut file, &self.variables))
            .and_then(|()| file.sync_all());
        if result.is_err() {
            let _ = std::fs::remove_file(&path);
            return Err(EnvironmentError::Handoff);
        }
        Ok(EnvironmentHandoff {
            path,
            snapshot_id: self.metadata.id.clone(),
            operation_id: operation_id.to_owned(),
            nonce,
            consumed: false,
            retained: false,
        })
    }

    /// Create or reopen the same operation-scoped handoff across an uncertain launch retry.
    /// Its durable claim marker prevents creating a replacement after consumption starts.
    pub fn create_handoff_for_operation(
        &self,
        state_root: &Path,
        operation_id: &str,
    ) -> Result<EnvironmentHandoff, EnvironmentError> {
        if operation_id.is_empty() || operation_id.len() > 128 || operation_id.contains('\0') {
            return Err(EnvironmentError::Invalid(
                "invalid launch operation identity",
            ));
        }
        let directory = state_root.join("environment-handoffs");
        create_private_directory(&directory)?;
        let identity = [
            self.metadata.id.as_str().as_bytes(),
            b"\0",
            operation_id.as_bytes(),
        ]
        .concat();
        let path = directory.join(format!("{:x}.env", Sha256::digest(identity)));
        if path.with_extension("env.claim").exists() {
            return Err(EnvironmentError::Handoff);
        }
        if path.exists() {
            let bytes = read_handoff_bytes(&path)?;
            let nonce = handoff_nonce(&bytes, &self.metadata.id, operation_id)?;
            if read_handoff(&path, &self.metadata.id, operation_id, &nonce)? != *self.variables {
                return Err(EnvironmentError::Handoff);
            }
            return Ok(EnvironmentHandoff {
                path,
                snapshot_id: self.metadata.id.clone(),
                operation_id: operation_id.to_owned(),
                nonce,
                consumed: false,
                retained: true,
            });
        }
        let nonce = fresh_nonce();
        let mut file = private_create_new(&path)?;
        use std::io::Write;
        let result = file
            .write_all(HANDOFF_MAGIC)
            .and_then(|()| file.write_all(self.metadata.id.as_str().as_bytes()))
            .and_then(|()| file.write_all(&[0]))
            .and_then(|()| file.write_all(operation_id.as_bytes()))
            .and_then(|()| file.write_all(&[0]))
            .and_then(|()| file.write_all(nonce.as_str().as_bytes()))
            .and_then(|()| file.write_all(&[0]))
            .and_then(|()| write_variables(&mut file, &self.variables))
            .and_then(|()| file.sync_all());
        if result.is_err() {
            let _ = std::fs::remove_file(&path);
            return Err(EnvironmentError::Handoff);
        }
        Ok(EnvironmentHandoff {
            path,
            snapshot_id: self.metadata.id.clone(),
            operation_id: operation_id.to_owned(),
            nonce,
            consumed: false,
            retained: true,
        })
    }
}

/// A reference to one launch handoff. Debug deliberately omits the nonce and path.
pub struct EnvironmentHandoff {
    path: PathBuf,
    snapshot_id: Digest,
    operation_id: String,
    nonce: Digest,
    consumed: bool,
    retained: bool,
}

impl EnvironmentHandoff {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn snapshot_id(&self) -> &Digest {
        &self.snapshot_id
    }

    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub fn nonce(&self) -> &Digest {
        &self.nonce
    }

    /// Read and remove the handoff before provider launch. The file is tied to the exact launch
    /// operation and snapshot; it cannot silently supply an empty or different environment.
    pub fn consume(mut self) -> Result<BTreeMap<OsString, OsString>, EnvironmentError> {
        let claim_path = self.path.with_extension("env.claim");
        let _claim = private_create_new(&claim_path)?;
        let result = read_handoff(
            &self.path,
            &self.snapshot_id,
            &self.operation_id,
            &self.nonce,
        );
        let _ = std::fs::remove_file(&self.path);
        self.consumed = true;
        result
    }

    /// Reopen the exact handoff after a controller restart. Claiming is permanent, even when
    /// identity or file validation fails, so a retry can never replace a claimed handoff.
    pub fn consume_file(
        path: &Path,
        expected_snapshot: &Digest,
        operation_id: &str,
    ) -> Result<BTreeMap<OsString, OsString>, EnvironmentError> {
        if path
            .file_name()
            .and_then(OsStr::to_str)
            .is_none_or(|name| !name.ends_with(".env"))
            || !has_private_parent(path)
        {
            return Err(EnvironmentError::Handoff);
        }
        let claim = private_create_new(&path.with_extension("env.claim"))?;
        drop(claim);
        let result = (|| {
            let bytes = read_handoff_bytes(path)?;
            let nonce = handoff_nonce(&bytes, expected_snapshot, operation_id)?;
            read_handoff(path, expected_snapshot, operation_id, &nonce)
        })();
        let _ = std::fs::remove_file(path);
        result
    }
}

impl Drop for EnvironmentHandoff {
    fn drop(&mut self) {
        if !self.consumed && !self.retained {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

impl std::fmt::Debug for EnvironmentHandoff {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnvironmentHandoff")
            .field("snapshot_id", &self.snapshot_id)
            .field("operation_id", &self.operation_id)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub enum EnvironmentError {
    Invalid(&'static str),
    ShellNotFound,
    UnsupportedShell,
    CaptureTimedOut,
    CaptureFailed,
    InvalidFrame,
    Handoff,
}

impl std::fmt::Display for EnvironmentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(message) => f.write_str(message),
            Self::ShellNotFound => f.write_str("the configured login shell could not be resolved"),
            Self::UnsupportedShell => f.write_str("environment capture supports Bash and Zsh only"),
            Self::CaptureTimedOut => {
                f.write_str("login-shell environment capture exceeded its deadline")
            }
            Self::CaptureFailed => f.write_str(
                "login-shell environment capture failed; inspect the shell configuration and retry",
            ),
            Self::InvalidFrame => {
                f.write_str("login-shell environment protocol was missing or invalid")
            }
            Self::Handoff => {
                f.write_str("could not create or consume the private one-use environment handoff")
            }
        }
    }
}

impl std::error::Error for EnvironmentError {}

/// Capture the environment once at controller startup. The shell command body is constant; all
/// executable, nonce, and user paths are argv values.
pub fn capture(config: &EnvironmentConfig) -> Result<EnvironmentSnapshot, EnvironmentError> {
    match config.source {
        EnvironmentSource::Inherit => {
            snapshot_from_variables(EnvironmentSource::Inherit, None, current_user_environment())
        }
        EnvironmentSource::LoginShell => capture_login_shell(config),
    }
}

fn capture_login_shell(
    config: &EnvironmentConfig,
) -> Result<EnvironmentSnapshot, EnvironmentError> {
    let requested_shell = config
        .shell
        .as_deref()
        .map(Path::new)
        .map(Path::to_path_buf)
        .or_else(|| std::env::var_os("SHELL").map(PathBuf::from))
        .ok_or(EnvironmentError::ShellNotFound)?;
    let search_path = std::env::var_os("PATH")
        .map(|path| std::env::split_paths(&path).collect::<Vec<_>>())
        .unwrap_or_default();
    let shell = resolve_executable(&requested_shell, &search_path)
        .ok_or(EnvironmentError::ShellNotFound)?;
    let basename = shell
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or_default();
    let shell_kind = match basename {
        "bash" => ShellKind::Bash,
        "zsh" => ShellKind::Zsh,
        _ => return Err(EnvironmentError::UnsupportedShell),
    };
    let executable = std::env::current_exe().map_err(|_| EnvironmentError::CaptureFailed)?;
    let nonce = fresh_nonce();
    let capture_output = CaptureOutput::create(&nonce)?;
    let started = Instant::now();
    let deadline = started
        .checked_add(Duration::from_secs(config.timeout_seconds))
        .ok_or(EnvironmentError::Invalid(
            "environment timeout is too large",
        ))?;
    let grace = CAPTURE_SHUTDOWN_GRACE;
    let reserve = grace.saturating_mul(3);
    let child_timeout = Duration::from_secs(config.timeout_seconds)
        .checked_sub(reserve)
        .filter(|timeout| !timeout.is_zero())
        .ok_or(EnvironmentError::Invalid(
            "environment timeout must exceed the process cleanup reserve",
        ))?;
    let mut environment = current_user_environment();
    environment.insert(
        OsString::from("REX_PROJECTS_CONTEXT"),
        OsString::from(CAPTURE_MARKER),
    );
    environment.insert(OsString::from("TERM"), OsString::from("dumb"));
    let request = ProcessRequest {
        executable: shell.clone(),
        args: shell_kind.arguments(
            &executable,
            capture_output.path(),
            &nonce,
            config.interactive,
        ),
        stdin: Vec::new(),
        cwd: None,
        clear_environment: true,
        environment,
        timeout: child_timeout,
        shutdown_grace: grace,
        stdout_limit: MAX_STARTUP_OUTPUT_BYTES,
        stderr_tail_limit: MAX_STARTUP_OUTPUT_BYTES,
    };
    let output = run(request).map_err(|_| EnvironmentError::CaptureFailed)?;
    if Instant::now() > deadline {
        return Err(EnvironmentError::CaptureTimedOut);
    }
    if output.timed_out {
        return Err(EnvironmentError::CaptureTimedOut);
    }
    if output.stdout_truncated || output.stderr_truncated || !output.cleanup_confirmed {
        return Err(EnvironmentError::CaptureFailed);
    }
    if !output.status.is_some_and(|status| status.success()) {
        return Err(EnvironmentError::CaptureFailed);
    }
    let variables = capture_output.read(&nonce)?;
    snapshot_from_variables(EnvironmentSource::LoginShell, Some(shell), variables)
}

struct CaptureOutput {
    directory: PathBuf,
    path: PathBuf,
}

impl CaptureOutput {
    fn create(nonce: &Digest) -> Result<Self, EnvironmentError> {
        let directory = std::env::temp_dir().join(format!(
            "rex-projects-environment-{}-{}",
            std::process::id(),
            nonce.as_str()
        ));
        create_private_directory(&directory)?;
        let path = directory.join("capture.bin");
        private_create_new(&path)?;
        Ok(Self { directory, path })
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn read(&self, nonce: &Digest) -> Result<BTreeMap<OsString, OsString>, EnvironmentError> {
        let bytes = read_private_output(&self.path)?;
        parse_frame(&bytes, nonce)
    }
}

impl Drop for CaptureOutput {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
        let _ = std::fs::remove_dir(&self.directory);
    }
}

#[derive(Clone, Copy)]
enum ShellKind {
    Bash,
    Zsh,
}

impl ShellKind {
    fn arguments(
        self,
        helper: &Path,
        output: &Path,
        nonce: &Digest,
        interactive: bool,
    ) -> Vec<OsString> {
        let mut args = match self {
            Self::Bash if interactive => vec!["--login", "-i", "-c", CAPTURE_PROGRAM],
            Self::Bash => vec!["--login", "-c", CAPTURE_PROGRAM],
            Self::Zsh if interactive => vec!["-l", "-i", "-c", CAPTURE_PROGRAM],
            Self::Zsh => vec!["-l", "-c", CAPTURE_PROGRAM],
        }
        .into_iter()
        .map(OsString::from)
        .collect::<Vec<_>>();
        args.push(OsString::from("rex-projects-environment-capture"));
        args.push(helper.as_os_str().to_os_string());
        args.push(output.as_os_str().to_os_string());
        args.push(OsString::from(nonce.as_str()));
        args
    }
}

/// The private CLI helper called at the end of the login-shell command.
/// Writes the framed protocol only to the host-created private output file. It never writes
/// captured values to stdout, stderr, logs, or error messages.
pub fn write_capture_frame(output_path: &Path, nonce: &str) -> Result<(), EnvironmentError> {
    if std::env::var_os("REX_PROJECTS_CONTEXT").as_deref() != Some(OsStr::new(CAPTURE_MARKER))
        || std::env::var_os("REX_PROJECTS_AGENT").is_some()
    {
        return Err(EnvironmentError::Invalid(
            "environment capture helper requires its host marker",
        ));
    }
    let nonce = Digest::parse(nonce.to_owned()).map_err(|_| EnvironmentError::InvalidFrame)?;
    let variables = current_user_environment();
    let mut output = open_private_output(output_path)?;
    use std::io::Write;
    output
        .write_all(FRAME_MAGIC)
        .and_then(|()| output.write_all(nonce.as_str().as_bytes()))
        .and_then(|()| output.write_all(&[0]))
        .and_then(|()| write_variables(&mut output, &variables))
        .and_then(|()| output.flush())
        .and_then(|()| output.sync_all())
        .map_err(|_| EnvironmentError::CaptureFailed)
}

fn current_user_environment() -> BTreeMap<OsString, OsString> {
    std::env::vars_os()
        .filter(|(key, _)| !is_factory_context_key(key) && !is_rex_session_key(key))
        .collect()
}

fn is_factory_context_key(key: &OsStr) -> bool {
    key.to_string_lossy().starts_with("REX_PROJECTS_")
}

fn is_rex_session_key(key: &OsStr) -> bool {
    matches!(key, value if value == OsStr::new("REX_SESSION") || value == OsStr::new("REX_BLOCK_ID"))
}

fn snapshot_from_variables(
    source: EnvironmentSource,
    shell: Option<PathBuf>,
    variables: BTreeMap<OsString, OsString>,
) -> Result<EnvironmentSnapshot, EnvironmentError> {
    validate_variables(&variables)?;
    let id = fresh_nonce();
    Ok(EnvironmentSnapshot {
        metadata: EnvironmentSnapshotMetadata { id, source, shell },
        variables: Arc::new(variables),
    })
}

fn parse_frame(
    stdout: &[u8],
    expected_nonce: &Digest,
) -> Result<BTreeMap<OsString, OsString>, EnvironmentError> {
    if stdout.len() > MAX_SNAPSHOT_BYTES {
        return Err(EnvironmentError::InvalidFrame);
    }
    let offset = stdout
        .windows(FRAME_MAGIC.len())
        .rposition(|window| window == FRAME_MAGIC)
        .ok_or(EnvironmentError::InvalidFrame)?;
    let mut frame = &stdout[offset + FRAME_MAGIC.len()..];
    let (nonce, rest) = take_nul_terminated(frame)?;
    if nonce != expected_nonce.as_str().as_bytes() {
        return Err(EnvironmentError::InvalidFrame);
    }
    frame = rest;
    let mut variables = BTreeMap::new();
    while !frame.is_empty() {
        let (key, rest) = take_nul_terminated(frame)?;
        let (value, rest) = take_nul_terminated(rest)?;
        let key = os_string_from_bytes(key)?;
        let value = os_string_from_bytes(value)?;
        if variables.insert(key, value).is_some() {
            return Err(EnvironmentError::InvalidFrame);
        }
        frame = rest;
    }
    validate_variables(&variables)?;
    Ok(variables)
}

fn take_nul_terminated(bytes: &[u8]) -> Result<(&[u8], &[u8]), EnvironmentError> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(EnvironmentError::InvalidFrame)?;
    Ok((&bytes[..end], &bytes[end + 1..]))
}

fn validate_variables(variables: &BTreeMap<OsString, OsString>) -> Result<(), EnvironmentError> {
    let mut total = 0usize;
    for (key, value) in variables {
        let key_bytes = os_bytes(key);
        let value_bytes = os_bytes(value);
        if key_bytes.is_empty()
            || key_bytes.contains(&0)
            || key_bytes.contains(&b'=')
            || value_bytes.contains(&0)
        {
            return Err(EnvironmentError::InvalidFrame);
        }
        total = total
            .checked_add(key_bytes.len() + value_bytes.len() + 2)
            .ok_or(EnvironmentError::InvalidFrame)?;
        if total > MAX_ENVIRONMENT_BYTES {
            return Err(EnvironmentError::InvalidFrame);
        }
    }
    Ok(())
}

fn write_variables(
    output: &mut impl std::io::Write,
    variables: &BTreeMap<OsString, OsString>,
) -> std::io::Result<()> {
    for (key, value) in variables {
        output.write_all(&os_bytes(key))?;
        output.write_all(&[0])?;
        output.write_all(&os_bytes(value))?;
        output.write_all(&[0])?;
    }
    Ok(())
}

#[cfg(unix)]
fn os_bytes(value: &OsStr) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    value.as_bytes().to_vec()
}

#[cfg(not(unix))]
fn os_bytes(value: &OsStr) -> Vec<u8> {
    value.to_string_lossy().as_bytes().to_vec()
}

#[cfg(unix)]
fn os_string_from_bytes(value: &[u8]) -> Result<OsString, EnvironmentError> {
    use std::os::unix::ffi::OsStringExt;
    Ok(OsString::from_vec(value.to_vec()))
}

#[cfg(not(unix))]
fn os_string_from_bytes(value: &[u8]) -> Result<OsString, EnvironmentError> {
    String::from_utf8(value.to_vec())
        .map(OsString::from)
        .map_err(|_| EnvironmentError::InvalidFrame)
}

fn fresh_nonce() -> Digest {
    static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let random = std::collections::hash_map::RandomState::new();
    let mut hasher = random.build_hasher();
    std::process::id().hash(&mut hasher);
    SEQUENCE
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        .hash(&mut hasher);
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .hash(&mut hasher);
    let seed = hasher.finish();
    let bytes = Sha256::digest(seed.to_le_bytes());
    Digest::parse(format!("{bytes:x}")).expect("SHA-256 is a lowercase digest")
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> Result<(), EnvironmentError> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    match builder.create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(EnvironmentError::Handoff),
    }
    let metadata = std::fs::symlink_metadata(path).map_err(|_| EnvironmentError::Handoff)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(EnvironmentError::Handoff);
    }
    Ok(())
}

#[cfg(not(unix))]
fn create_private_directory(path: &Path) -> Result<(), EnvironmentError> {
    std::fs::create_dir_all(path).map_err(|_| EnvironmentError::Handoff)?;
    if !std::fs::symlink_metadata(path)
        .is_ok_and(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
    {
        return Err(EnvironmentError::Handoff);
    }
    Ok(())
}

#[cfg(unix)]
fn private_create_new(path: &Path) -> Result<std::fs::File, EnvironmentError> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| EnvironmentError::Handoff)
}

#[cfg(not(unix))]
fn private_create_new(path: &Path) -> Result<std::fs::File, EnvironmentError> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| EnvironmentError::Handoff)
}

fn open_private_output(path: &Path) -> Result<std::fs::File, EnvironmentError> {
    #[cfg(unix)]
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    let file = options.open(path).map_err(|_| EnvironmentError::Handoff)?;
    let metadata = file.metadata().map_err(|_| EnvironmentError::Handoff)?;
    if !metadata.is_file() || metadata.len() != 0 || !has_private_parent(path) {
        return Err(EnvironmentError::Handoff);
    }
    #[cfg(unix)]
    if metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err(EnvironmentError::Handoff);
    }
    Ok(file)
}

fn read_private_output(path: &Path) -> Result<Vec<u8>, EnvironmentError> {
    use std::io::Read;
    #[cfg(unix)]
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    let file = options.open(path).map_err(|_| EnvironmentError::Handoff)?;
    let metadata = file.metadata().map_err(|_| EnvironmentError::Handoff)?;
    if !metadata.is_file()
        || metadata.len() as usize > MAX_SNAPSHOT_BYTES
        || !has_private_parent(path)
    {
        return Err(EnvironmentError::Handoff);
    }
    #[cfg(unix)]
    if metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err(EnvironmentError::Handoff);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take((MAX_SNAPSHOT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| EnvironmentError::Handoff)?;
    if bytes.len() > MAX_SNAPSHOT_BYTES {
        return Err(EnvironmentError::Handoff);
    }
    Ok(bytes)
}

#[cfg(unix)]
fn has_private_parent(path: &Path) -> bool {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    path.parent().is_some_and(|parent| {
        std::fs::symlink_metadata(parent).is_ok_and(|metadata| {
            metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.permissions().mode() & 0o777 == 0o700
        })
    })
}

#[cfg(not(unix))]
fn has_private_parent(path: &Path) -> bool {
    path.parent().is_some_and(|parent| {
        std::fs::symlink_metadata(parent)
            .is_ok_and(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
    })
}

fn read_handoff(
    path: &Path,
    expected_snapshot: &Digest,
    expected_operation: &str,
    expected_nonce: &Digest,
) -> Result<BTreeMap<OsString, OsString>, EnvironmentError> {
    use std::io::Read;
    #[cfg(unix)]
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    let file = options.open(path).map_err(|_| EnvironmentError::Handoff)?;
    let metadata = file.metadata().map_err(|_| EnvironmentError::Handoff)?;
    if !metadata.is_file() || metadata.len() as usize > MAX_ENVIRONMENT_BYTES + 512 {
        return Err(EnvironmentError::Handoff);
    }
    #[cfg(unix)]
    if metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o777 != 0o600
        || !has_private_parent(path)
    {
        return Err(EnvironmentError::Handoff);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take((MAX_ENVIRONMENT_BYTES + 513) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| EnvironmentError::Handoff)?;
    if bytes.len() > MAX_ENVIRONMENT_BYTES + 512 {
        return Err(EnvironmentError::Handoff);
    }
    let mut frame = bytes
        .strip_prefix(HANDOFF_MAGIC)
        .ok_or(EnvironmentError::Handoff)?;
    let (snapshot, rest) = take_nul_terminated(frame).map_err(|_| EnvironmentError::Handoff)?;
    let (operation, rest) = take_nul_terminated(rest).map_err(|_| EnvironmentError::Handoff)?;
    let (nonce, rest) = take_nul_terminated(rest).map_err(|_| EnvironmentError::Handoff)?;
    if snapshot != expected_snapshot.as_str().as_bytes()
        || operation != expected_operation.as_bytes()
        || nonce != expected_nonce.as_str().as_bytes()
    {
        return Err(EnvironmentError::Handoff);
    }
    frame = rest;
    let mut variables = BTreeMap::new();
    while !frame.is_empty() {
        let (key, rest) = take_nul_terminated(frame).map_err(|_| EnvironmentError::Handoff)?;
        let (value, rest) = take_nul_terminated(rest).map_err(|_| EnvironmentError::Handoff)?;
        if variables
            .insert(
                os_string_from_bytes(key).map_err(|_| EnvironmentError::Handoff)?,
                os_string_from_bytes(value).map_err(|_| EnvironmentError::Handoff)?,
            )
            .is_some()
        {
            return Err(EnvironmentError::Handoff);
        }
        frame = rest;
    }
    validate_variables(&variables).map_err(|_| EnvironmentError::Handoff)?;
    Ok(variables)
}

fn read_handoff_bytes(path: &Path) -> Result<Vec<u8>, EnvironmentError> {
    use std::io::Read;
    #[cfg(unix)]
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    let file = options.open(path).map_err(|_| EnvironmentError::Handoff)?;
    let metadata = file.metadata().map_err(|_| EnvironmentError::Handoff)?;
    if !metadata.is_file()
        || metadata.len() as usize > MAX_ENVIRONMENT_BYTES + 512
        || !has_private_parent(path)
    {
        return Err(EnvironmentError::Handoff);
    }
    #[cfg(unix)]
    if metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err(EnvironmentError::Handoff);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take((MAX_ENVIRONMENT_BYTES + 513) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| EnvironmentError::Handoff)?;
    if bytes.len() > MAX_ENVIRONMENT_BYTES + 512 {
        return Err(EnvironmentError::Handoff);
    }
    Ok(bytes)
}

fn handoff_nonce(
    bytes: &[u8],
    snapshot: &Digest,
    operation: &str,
) -> Result<Digest, EnvironmentError> {
    let frame = bytes
        .strip_prefix(HANDOFF_MAGIC)
        .ok_or(EnvironmentError::Handoff)?;
    let (stored_snapshot, rest) =
        take_nul_terminated(frame).map_err(|_| EnvironmentError::Handoff)?;
    let (stored_operation, rest) =
        take_nul_terminated(rest).map_err(|_| EnvironmentError::Handoff)?;
    let (nonce, _) = take_nul_terminated(rest).map_err(|_| EnvironmentError::Handoff)?;
    if stored_snapshot != snapshot.as_str().as_bytes() || stored_operation != operation.as_bytes() {
        return Err(EnvironmentError::Handoff);
    }
    let nonce = std::str::from_utf8(nonce).map_err(|_| EnvironmentError::Handoff)?;
    Digest::parse(nonce.to_owned()).map_err(|_| EnvironmentError::Handoff)
}

#[cfg(test)]
mod tests {
    use super::{
        ChildContext, EnvironmentConfig, EnvironmentError, EnvironmentSource, FRAME_MAGIC,
        ShellKind, fresh_nonce, parse_frame, snapshot_from_variables,
    };
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::path::Path;

    fn get<'a>(values: &'a BTreeMap<OsString, OsString>, key: &str) -> Option<&'a OsString> {
        values.get(std::ffi::OsStr::new(key))
    }

    #[test]
    fn inherit_snapshot_redacts_debug_and_child_context_replaces_stale_markers() {
        let mut variables = BTreeMap::new();
        variables.insert("PATH".into(), "/usr/bin".into());
        variables.insert("API_TOKEN".into(), "do-not-print".into());
        variables.insert("REX_PROJECTS_ROLE".into(), "old-role".into());
        variables.insert("REX_SESSION".into(), "old-session".into());
        let snapshot =
            snapshot_from_variables(EnvironmentSource::Inherit, None, variables).unwrap();
        assert!(!format!("{snapshot:?}").contains("do-not-print"));
        let mut current_rex = BTreeMap::new();
        current_rex.insert(
            OsString::from("REX_SESSION"),
            OsString::from("active-session"),
        );
        current_rex.insert(
            OsString::from("REX_BLOCK_ID"),
            OsString::from("active-block"),
        );
        let child = snapshot.child_environment(ChildContext::Agent, &current_rex);
        assert_eq!(get(&child, "API_TOKEN").unwrap(), "do-not-print");
        assert_eq!(get(&child, "REX_PROJECTS_CONTEXT").unwrap(), "agent");
        assert_eq!(get(&child, "REX_PROJECTS_AGENT").unwrap(), "1");
        assert_eq!(get(&child, "REX_SESSION").unwrap(), "active-session");
        assert!(!child.contains_key(std::ffi::OsStr::new("REX_PROJECTS_ROLE")));
    }

    #[test]
    fn capture_protocol_ignores_startup_output_and_checks_nonce_and_pairs() {
        let nonce = fresh_nonce();
        let mut stdout = b"shell startup banner\n".to_vec();
        stdout.extend_from_slice(FRAME_MAGIC);
        stdout.extend_from_slice(nonce.as_str().as_bytes());
        stdout.push(0);
        stdout.extend_from_slice(b"HOME\0/safe\0PATH\0/usr/bin\0");
        let values = parse_frame(&stdout, &nonce).unwrap();
        assert_eq!(get(&values, "HOME").unwrap(), "/safe");
        assert_eq!(get(&values, "PATH").unwrap(), "/usr/bin");
        assert!(matches!(
            parse_frame(&stdout, &fresh_nonce()),
            Err(EnvironmentError::InvalidFrame)
        ));
        stdout.pop();
        assert!(matches!(
            parse_frame(&stdout, &nonce),
            Err(EnvironmentError::InvalidFrame)
        ));
    }

    #[test]
    fn one_use_handoff_is_private_bound_and_removed_when_consumed() {
        let root = tempfile::tempdir().unwrap();
        let mut values = BTreeMap::new();
        values.insert("PATH".into(), "/usr/bin".into());
        values.insert("API_TOKEN".into(), "ephemeral".into());
        let snapshot = snapshot_from_variables(EnvironmentSource::Inherit, None, values).unwrap();
        let handoff = snapshot.create_handoff(root.path(), "run-1").unwrap();
        let path = handoff.path().to_path_buf();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                std::fs::metadata(path.parent().unwrap())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
        let values = handoff.consume().unwrap();
        assert_eq!(get(&values, "API_TOKEN").unwrap(), "ephemeral");
        assert!(!path.exists());
    }

    #[test]
    fn handoff_refuses_symlink_and_does_not_delete_its_target() {
        let root = tempfile::tempdir().unwrap();
        let mut values = BTreeMap::new();
        values.insert("PATH".into(), "/usr/bin".into());
        let snapshot = snapshot_from_variables(EnvironmentSource::Inherit, None, values).unwrap();
        let handoff = snapshot.create_handoff(root.path(), "run-2").unwrap();
        let original = handoff.path().to_path_buf();
        drop(handoff);
        let target = root.path().join("target");
        std::fs::write(&target, b"untouched").unwrap();
        let link = root.path().join("link.env");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &link).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            assert!(
                std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(&link)
                    .is_err()
            );
            assert_eq!(std::fs::read(&target).unwrap(), b"untouched");
        }
        assert!(!original.exists());
    }

    #[test]
    fn retained_handoff_can_be_reopened_once_after_handle_drop() {
        let root = tempfile::tempdir().unwrap();
        let snapshot = snapshot_from_variables(
            EnvironmentSource::Inherit,
            None,
            BTreeMap::from([("API_TOKEN".into(), "ephemeral".into())]),
        )
        .unwrap();
        let handoff = snapshot
            .create_handoff_for_operation(root.path(), "run-restart")
            .unwrap();
        let path = handoff.path().to_path_buf();
        let snapshot_id = handoff.snapshot_id().clone();
        drop(handoff);
        assert!(path.exists());
        assert_eq!(
            snapshot
                .create_handoff_for_operation(root.path(), "run-restart")
                .unwrap()
                .path(),
            path
        );
        assert!(matches!(
            super::EnvironmentHandoff::consume_file(&path, &snapshot_id, "wrong-op"),
            Err(EnvironmentError::Handoff)
        ));
        assert!(!path.exists());
        assert!(matches!(
            snapshot.create_handoff_for_operation(root.path(), "run-restart"),
            Err(EnvironmentError::Handoff)
        ));
        // A failed claim is permanent; use a separate operation for the successful retry path.
        let handoff = snapshot
            .create_handoff_for_operation(root.path(), "run-success")
            .unwrap();
        let path = handoff.path().to_path_buf();
        drop(handoff);
        let values =
            super::EnvironmentHandoff::consume_file(&path, &snapshot_id, "run-success").unwrap();
        assert_eq!(get(&values, "API_TOKEN").unwrap(), "ephemeral");
        assert!(!path.exists());
        assert!(matches!(
            snapshot.create_handoff_for_operation(root.path(), "run-success"),
            Err(EnvironmentError::Handoff)
        ));
    }

    #[test]
    fn concurrent_consumers_claim_operation_handoff_once() {
        let root = tempfile::tempdir().unwrap();
        let snapshot = snapshot_from_variables(
            EnvironmentSource::Inherit,
            None,
            BTreeMap::from([("TOKEN".into(), "once".into())]),
        )
        .unwrap();
        let id = snapshot.metadata().id.clone();
        let handoff = snapshot
            .create_handoff_for_operation(root.path(), "concurrent")
            .unwrap();
        let path = handoff.path().to_path_buf();
        drop(handoff);
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let consumers = (0..2)
            .map(|_| {
                let barrier = barrier.clone();
                let path = path.clone();
                let id = id.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    super::EnvironmentHandoff::consume_file(&path, &id, "concurrent")
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        let results = consumers
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);
        assert!(!path.exists());
        assert!(path.with_extension("env.claim").exists());
    }

    #[cfg(unix)]
    #[test]
    fn operation_handoff_rejects_symlink_and_broad_file_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let snapshot = snapshot_from_variables(
            EnvironmentSource::Inherit,
            None,
            BTreeMap::from([("TOKEN".into(), "secret".into())]),
        )
        .unwrap();
        let id = snapshot.metadata().id.clone();
        let handoff = snapshot
            .create_handoff_for_operation(root.path(), "unsafe-link")
            .unwrap();
        let path = handoff.path().to_path_buf();
        drop(handoff);
        let target = root.path().join("target");
        std::fs::write(&target, b"untouched").unwrap();
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(super::EnvironmentHandoff::consume_file(&path, &id, "unsafe-link").is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"untouched");

        let handoff = snapshot
            .create_handoff_for_operation(root.path(), "unsafe-mode")
            .unwrap();
        let path = handoff.path().to_path_buf();
        drop(handoff);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(super::EnvironmentHandoff::consume_file(&path, &id, "unsafe-mode").is_err());
    }

    #[test]
    fn login_capture_rejects_too_short_a_deadline() {
        let config = EnvironmentConfig {
            source: EnvironmentSource::LoginShell,
            shell: None,
            interactive: true,
            timeout_seconds: 3,
        };
        if std::env::var_os("SHELL").is_some() {
            assert!(matches!(
                super::capture(&config),
                Err(EnvironmentError::Invalid(_))
            ));
        }
    }

    #[test]
    fn bash_login_shell_uses_supported_short_interactive_option() {
        let args = ShellKind::Bash.arguments(
            Path::new("/usr/bin/rex-projects"),
            Path::new("/tmp/capture.bin"),
            &fresh_nonce(),
            true,
        );
        assert_eq!(args[0], "--login");
        assert_eq!(args[1], "-i");
        assert_eq!(args[2], "-c");
    }
}
