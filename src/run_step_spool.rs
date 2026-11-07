//! Bounded file protocol between a Rex block wrapper and the foreground host controller.
//!
//! The wrapper never opens SQLite. It publishes its start observation once, waits for the
//! controller's durable decision, then may publish a bounded result envelope. These files carry
//! evidence only; the controller must still validate them against persisted launch authority.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::launch::{AgentLaunchReceipt, AgentStartRequest};
use crate::run_step::{RunReceipt, TurnResult};

const PROTOCOL_VERSION: u32 = 1;
const MAX_START_BYTES: usize = 32 * 1024;
const MAX_RESULT_BYTES: usize = 1024 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(50);

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StartRequestEnvelope {
    pub schema_version: u32,
    pub request_digest: String,
    pub request: AgentStartRequest,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StartReceiptEnvelope {
    pub schema_version: u32,
    pub request_digest: String,
    pub receipt: AgentLaunchReceipt,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentTurnResult {
    pub schema_version: u32,
    pub start_request_digest: String,
    pub receipt: RunReceipt,
    pub structured_result: Option<serde_json::Value>,
    pub result_digest: String,
}

/// Files scoped to one immutable launch authority's control directory.
#[derive(Clone, Debug)]
pub struct RunStepSpool {
    directory: PathBuf,
    #[cfg(unix)]
    directory_handle: Arc<File>,
}

impl RunStepSpool {
    /// Opens or creates the `run-step` child of an already registered control directory.
    pub fn open(control_dir: &Path) -> Result<Self, String> {
        let metadata = fs::symlink_metadata(control_dir)
            .map_err(|error| format!("control directory: {error}"))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err("control directory must be a real directory".into());
        }
        let canonical_parent = fs::canonicalize(control_dir)
            .map_err(|error| format!("canonicalize control directory: {error}"))?;
        let directory = canonical_parent.join("run-step");
        match fs::create_dir(&directory) {
            Ok(()) => set_private_dir(&directory)?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(format!("create run-step spool: {error}")),
        }
        let metadata =
            fs::symlink_metadata(&directory).map_err(|error| format!("run-step spool: {error}"))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err("run-step spool must be a real directory".into());
        }
        let canonical = fs::canonicalize(&directory)
            .map_err(|error| format!("canonicalize run-step spool: {error}"))?;
        if canonical != directory {
            return Err("run-step spool path changed during canonicalization".into());
        }
        #[cfg(unix)]
        let directory_handle = Arc::new(
            open_dir(&directory)
                .map_err(|error| format!("open run-step spool directory: {error}"))?,
        );
        sync_directory(&canonical_parent)?;
        #[cfg(unix)]
        directory_handle
            .sync_all()
            .map_err(|error| format!("sync run-step spool directory: {error}"))?;
        Ok(Self {
            directory,
            #[cfg(unix)]
            directory_handle,
        })
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// Publishes the wrapper observation exactly once and returns its canonical content digest.
    pub fn publish_start_once(
        &self,
        request: AgentStartRequest,
    ) -> Result<StartRequestEnvelope, String> {
        request.validate()?;
        let request_bytes = crate::protocol::serialize_bounded(&request, MAX_START_BYTES)
            .map_err(|error| error.to_string())?;
        let envelope = StartRequestEnvelope {
            schema_version: PROTOCOL_VERSION,
            request_digest: sha256(&request_bytes),
            request,
        };
        let bytes = crate::protocol::serialize_bounded(&envelope, MAX_START_BYTES)
            .map_err(|error| error.to_string())?;
        self.publish_file("start.request.json", &bytes, MAX_START_BYTES)?;
        Ok(envelope)
    }

    /// Host-side read. The caller must authorize this request against durable store state.
    pub fn read_start_request(&self) -> Result<StartRequestEnvelope, String> {
        let bytes = self.read_file("start.request.json", MAX_START_BYTES)?;
        let envelope: StartRequestEnvelope = parse_unique(&bytes)?;
        envelope.validate()?;
        Ok(envelope)
    }

    /// Host-side single publication after `ConfigStore::authorize_agent_start` succeeds.
    pub fn publish_start_receipt(
        &self,
        request: &StartRequestEnvelope,
        receipt: AgentLaunchReceipt,
    ) -> Result<(), String> {
        request.validate()?;
        receipt.validate_for(&request.request)?;
        let envelope = StartReceiptEnvelope {
            schema_version: PROTOCOL_VERSION,
            request_digest: request.request_digest.clone(),
            receipt,
        };
        let bytes = crate::protocol::serialize_bounded(&envelope, MAX_START_BYTES)
            .map_err(|error| error.to_string())?;
        self.publish_file("start.receipt.json", &bytes, MAX_START_BYTES)
    }

    /// Host-side read of an already published start receipt. Existing receipts remain
    /// immutable; callers compare them with the durable host decision before replaying.
    pub fn read_start_receipt(
        &self,
        request: &StartRequestEnvelope,
    ) -> Result<Option<AgentLaunchReceipt>, String> {
        request.validate()?;
        match self.read_file("start.receipt.json", MAX_START_BYTES) {
            Ok(bytes) => {
                let envelope: StartReceiptEnvelope = parse_unique(&bytes)?;
                envelope.validate_for(request)?;
                Ok(Some(envelope.receipt))
            }
            Err(error) if error == "run-step spool file is not present" => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Wrapper-side bounded wait. Timeout is an unresolved start, never permission to proceed.
    pub fn wait_start_receipt(
        &self,
        request: &StartRequestEnvelope,
        timeout: Duration,
    ) -> Result<AgentLaunchReceipt, String> {
        request.validate()?;
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| "start receipt deadline overflow".to_owned())?;
        loop {
            if let Some(receipt) = self.read_start_receipt(request)? {
                return Ok(receipt);
            }
            if Instant::now() >= deadline {
                return Err("timed out waiting for the host start decision".into());
            }
            thread::sleep(POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())));
        }
    }

    /// Publishes already bounded, serialized result evidence exactly once.
    /// The controller owns deserialization into its strict role-result and process evidence types.
    pub fn publish_result_once(&self, bytes: &[u8]) -> Result<String, String> {
        if bytes.len() > MAX_RESULT_BYTES {
            return Err("Agent turn result exceeds the 1 MiB limit".into());
        }
        let _: serde_json::Value = parse_unique(bytes)?;
        let digest = sha256(bytes);
        self.publish_file("turn.result.json", bytes, MAX_RESULT_BYTES)?;
        Ok(digest)
    }

    pub fn publish_turn_result_once(
        &self,
        request: &StartRequestEnvelope,
        result: TurnResult,
    ) -> Result<AgentTurnResult, String> {
        request.validate()?;
        let mut envelope = AgentTurnResult {
            schema_version: PROTOCOL_VERSION,
            start_request_digest: request.request_digest.clone(),
            receipt: result.receipt,
            structured_result: result.structured_result,
            result_digest: String::new(),
        };
        if envelope.receipt.run_id != request.request.agent_run_id {
            return Err("provider result belongs to a different AgentRun".into());
        }
        envelope.result_digest = envelope.payload_digest()?;
        let bytes = crate::protocol::serialize_bounded(&envelope, MAX_RESULT_BYTES)
            .map_err(|error| error.to_string())?;
        let _: AgentTurnResult = parse_unique(&bytes)?;
        self.publish_file("turn.result.json", &bytes, MAX_RESULT_BYTES)?;
        Ok(envelope)
    }

    /// Host-side bounded read; callers must validate the envelope and treat its claims as evidence.
    pub fn read_result(&self) -> Result<Vec<u8>, String> {
        self.read_file("turn.result.json", MAX_RESULT_BYTES)
    }

    pub fn read_turn_result(
        &self,
        request: &StartRequestEnvelope,
    ) -> Result<AgentTurnResult, String> {
        request.validate()?;
        let bytes = self.read_result()?;
        let envelope: AgentTurnResult = parse_unique(&bytes)?;
        envelope.validate_for(request)?;
        Ok(envelope)
    }

    fn publish_file(&self, name: &str, bytes: &[u8], limit: usize) -> Result<(), String> {
        #[cfg(unix)]
        {
            publish_once_at(&self.directory_handle, name, bytes, limit)
        }
        #[cfg(not(unix))]
        {
            publish_once(&self.directory, name, bytes, limit)
        }
    }

    fn read_file(&self, name: &str, limit: usize) -> Result<Vec<u8>, String> {
        #[cfg(unix)]
        {
            read_bounded_at(&self.directory_handle, name, limit).map_err(|error| {
                match error.kind() {
                    std::io::ErrorKind::NotFound => "run-step spool file is not present".into(),
                    _ => format!("read run-step spool file: {error}"),
                }
            })
        }
        #[cfg(not(unix))]
        {
            read_bounded(&self.directory.join(name), limit)
        }
    }
}

impl StartRequestEnvelope {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != PROTOCOL_VERSION {
            return Err("unsupported run-step start request schema".into());
        }
        self.request.validate()?;
        let bytes = crate::protocol::serialize_bounded(&self.request, MAX_START_BYTES)
            .map_err(|error| error.to_string())?;
        if self.request_digest != sha256(&bytes) {
            return Err("run-step start request digest does not match its payload".into());
        }
        Ok(())
    }
}

impl StartReceiptEnvelope {
    pub fn validate_for(&self, request: &StartRequestEnvelope) -> Result<(), String> {
        request.validate()?;
        if self.schema_version != PROTOCOL_VERSION || self.request_digest != request.request_digest
        {
            return Err("host start receipt is not bound to this start request".into());
        }
        self.receipt.validate_for(&request.request)
    }
}

impl AgentTurnResult {
    pub fn validate_for(&self, request: &StartRequestEnvelope) -> Result<(), String> {
        request.validate()?;
        if self.schema_version != PROTOCOL_VERSION
            || self.start_request_digest != request.request_digest
            || self.receipt.run_id != request.request.agent_run_id
        {
            return Err("Agent result is not bound to this acknowledged launch".into());
        }
        if self.result_digest != self.payload_digest()? {
            return Err("Agent result digest does not match its payload".into());
        }
        Ok(())
    }

    fn payload_digest(&self) -> Result<String, String> {
        #[derive(Serialize)]
        struct Payload<'a> {
            schema_version: u32,
            start_request_digest: &'a str,
            receipt: &'a RunReceipt,
            structured_result: &'a Option<serde_json::Value>,
        }
        let bytes = crate::protocol::serialize_bounded(
            &Payload {
                schema_version: self.schema_version,
                start_request_digest: &self.start_request_digest,
                receipt: &self.receipt,
                structured_result: &self.structured_result,
            },
            MAX_RESULT_BYTES,
        )
        .map_err(|error| error.to_string())?;
        Ok(sha256(&bytes))
    }
}

#[cfg(not(unix))]
fn publish_once(directory: &Path, name: &str, bytes: &[u8], limit: usize) -> Result<(), String> {
    if bytes.len() > limit {
        return Err("run-step spool payload exceeds its byte limit".into());
    }
    let temporary = directory.join(format!(".{name}.{}.tmp", nonce()));
    let destination = directory.join(name);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    set_private_file_options(&mut options);
    let mut file = options
        .open(&temporary)
        .map_err(|error| format!("create run-step temporary file: {error}"))?;
    let result = file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("write run-step spool file: {error}"));
    drop(file);
    if let Err(error) = result {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    match fs::hard_link(&temporary, &destination) {
        Ok(()) => {
            fs::remove_file(&temporary)
                .map_err(|error| format!("remove run-step temporary file: {error}"))?;
            sync_directory(directory)?;
            Ok(())
        }
        Err(error) => {
            let _ = fs::remove_file(&temporary);
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                Err(format!(
                    "run-step spool file `{name}` was already published"
                ))
            } else {
                Err(format!("publish run-step spool file: {error}"))
            }
        }
    }
}

#[cfg(not(unix))]
fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err("run-step spool file is not present".into());
        }
        Err(error) => return Err(format!("open run-step spool file: {error}")),
    };
    let metadata = file
        .metadata()
        .map_err(|error| format!("inspect run-step spool file: {error}"))?;
    if !metadata.is_file() || metadata.len() > limit as u64 {
        return Err("run-step spool file is not regular or exceeds its byte limit".into());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read run-step spool file: {error}"))?;
    if bytes.len() > limit {
        return Err("run-step spool file exceeds its byte limit".into());
    }
    Ok(bytes)
}

fn parse_unique<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, String> {
    crate::protocol::parse_unique(bytes)
        .map_err(|error| format!("invalid run-step spool JSON: {error}"))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn nonce() -> String {
    let mut bytes = [0_u8; 16];
    use std::io::Read as _;
    if File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .is_err()
    {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        bytes.copy_from_slice(&now.to_le_bytes()[..16]);
    }
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(unix)]
fn open_dir(path: &Path) -> Result<File, std::io::Error> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

#[cfg(unix)]
fn read_bounded_at(directory: &File, name: &str, limit: usize) -> Result<Vec<u8>, std::io::Error> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let name = std::ffi::CString::new(name).expect("internal spool filename has no nul");
    // SAFETY: directory is a retained directory descriptor and name is a fixed basename.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: openat returned a new owned descriptor.
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > limit as u64 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "run-step spool entry is not a bounded regular file",
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "run-step spool entry exceeds its byte limit",
        ));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn publish_once_at(directory: &File, name: &str, bytes: &[u8], limit: usize) -> Result<(), String> {
    use std::os::fd::{AsRawFd, FromRawFd};
    if bytes.len() > limit {
        return Err("run-step spool payload exceeds its byte limit".into());
    }
    let temporary = std::ffi::CString::new(format!(".{name}.{}.tmp", nonce()))
        .expect("internal spool filename has no nul");
    let destination = std::ffi::CString::new(name).expect("internal spool destination has no nul");
    // SAFETY: directory is an open directory and temporary is a unique internal basename.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            temporary.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(format!(
            "create run-step temporary file: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: openat returned a new owned descriptor.
    let mut file = unsafe { File::from_raw_fd(fd) };
    let result = (|| {
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| format!("write run-step spool file: {error}"))?;
        drop(file);
        // SAFETY: both names are internal basenames under the retained directory descriptor.
        let linked = unsafe {
            libc::linkat(
                directory.as_raw_fd(),
                temporary.as_ptr(),
                directory.as_raw_fd(),
                destination.as_ptr(),
                0,
            )
        };
        if linked < 0 {
            let error = std::io::Error::last_os_error();
            return Err(if error.kind() == std::io::ErrorKind::AlreadyExists {
                format!("run-step spool file `{name}` was already published")
            } else {
                format!("publish run-step spool file: {error}")
            });
        }
        // SAFETY: temporary is the private file created by this call.
        if unsafe { libc::unlinkat(directory.as_raw_fd(), temporary.as_ptr(), 0) } < 0 {
            return Err(format!(
                "remove run-step temporary file: {}",
                std::io::Error::last_os_error()
            ));
        }
        directory
            .sync_all()
            .map_err(|error| format!("sync run-step spool directory: {error}"))
    })();
    if result.is_err() {
        // SAFETY: temporary is owned by this call and removed beneath its pinned directory.
        unsafe { libc::unlinkat(directory.as_raw_fd(), temporary.as_ptr(), 0) };
    }
    result
}

#[cfg(unix)]
fn set_private_dir(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("secure run-step spool: {error}"))
}

#[cfg(not(unix))]
fn set_private_dir(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(not(unix))]
fn set_private_file_options(_options: &mut OpenOptions) {}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("sync run-step spool directory: {error}"))
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{AgentTurnResult, RunStepSpool, StartReceiptEnvelope, StartRequestEnvelope};
    use crate::domain::ids::{AgentRunId, Digest, OperationId, ProjectId};
    use crate::launch::{AgentLaunchReceipt, AgentStartRequest, LaunchDecision};
    use crate::run_step::{CleanupState, RunReceipt, TurnOutcome, TurnResult};
    use sha2::Digest as _;
    use std::time::Duration;
    use tempfile::tempdir;

    fn request() -> AgentStartRequest {
        AgentStartRequest {
            schema_version: 1,
            operation_id: OperationId::parse("op-1").unwrap(),
            agent_run_id: AgentRunId::parse("run-1").unwrap(),
            project_id: ProjectId::parse("project-a").unwrap(),
            controller_generation: 1,
            descriptor_digest: digest('a'),
            runtime_binary_digest: digest('b'),
            environment_snapshot_id: digest('c'),
            qualification_receipt_digest: digest('d'),
            wrapper_pid: 100,
            wrapper_start_identity: "birth-100".into(),
            rex_session_id: "session-1".into(),
            rex_block_id: "block-1".into(),
        }
    }

    fn digest(c: char) -> Digest {
        Digest::parse(c.to_string().repeat(64)).unwrap()
    }

    fn receipt(request: &AgentStartRequest) -> AgentLaunchReceipt {
        AgentLaunchReceipt {
            schema_version: 1,
            operation_id: request.operation_id.clone(),
            agent_run_id: request.agent_run_id.clone(),
            controller_generation: request.controller_generation,
            descriptor_digest: request.descriptor_digest.clone(),
            runtime_binary_digest: request.runtime_binary_digest.clone(),
            qualification_receipt_digest: request.qualification_receipt_digest.clone(),
            decision: LaunchDecision::Accepted,
            reason: None,
        }
    }

    fn turn_result(request: &AgentStartRequest) -> TurnResult {
        TurnResult {
            receipt: RunReceipt {
                run_id: request.agent_run_id.clone(),
                attempt: 1,
                provider: crate::domain::types::AgentAdapter::Codex,
                effective_permission_mode: "workspace_write".into(),
                conversation_id: None,
                provider_version: Some("test-version".into()),
                capability_receipt_digest: Some(request.qualification_receipt_digest.clone()),
                schema_projection: crate::providers::project_result_schema(
                    &serde_json::json!({"type":"object"}),
                )
                .unwrap()
                .identity,
                launch_pid_hint: Some(100),
                exit_code: Some(0),
                timed_out: false,
                cancellation_signal: None,
                cleanup: CleanupState::Confirmed,
                cleanup_detail: None,
                processes: vec![],
                result_digest: None,
                provider_result_failure: None,
                provider_process_failure: None,
                outcome: TurnOutcome::MissingResult,
            },
            structured_result: None,
        }
    }

    #[test]
    fn host_ack_is_bound_to_exact_published_request_and_is_single_publish() {
        let temp = tempdir().unwrap();
        let spool = RunStepSpool::open(temp.path()).unwrap();
        let envelope = spool.publish_start_once(request()).unwrap();
        let host_read = spool.read_start_request().unwrap();
        assert_eq!(host_read.request_digest, envelope.request_digest);
        spool
            .publish_start_receipt(&host_read, receipt(&host_read.request))
            .unwrap();
        assert!(
            spool
                .publish_start_receipt(&host_read, receipt(&host_read.request))
                .is_err()
        );
        assert_eq!(
            spool.wait_start_receipt(&envelope, Duration::ZERO).unwrap(),
            receipt(&envelope.request)
        );
    }

    #[test]
    fn start_request_and_receipt_reject_tampering_and_wrong_request_digest() {
        let mut envelope = StartRequestEnvelope {
            schema_version: 1,
            request_digest: "0".repeat(64),
            request: request(),
        };
        assert!(envelope.validate().is_err());
        envelope.request_digest = {
            let bytes = serde_json::to_vec(&envelope.request).unwrap();
            format!("{:x}", sha2::Sha256::digest(bytes))
        };
        envelope.validate().unwrap();
        let ack = StartReceiptEnvelope {
            schema_version: 1,
            request_digest: "f".repeat(64),
            receipt: receipt(&envelope.request),
        };
        assert!(ack.validate_for(&envelope).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn reader_rejects_symlinked_start_receipt() {
        let temp = tempdir().unwrap();
        let spool = RunStepSpool::open(temp.path()).unwrap();
        let envelope = spool.publish_start_once(request()).unwrap();
        let target = temp.path().join("outside.json");
        std::fs::write(&target, b"{}").unwrap();
        std::os::unix::fs::symlink(target, spool.directory().join("start.receipt.json")).unwrap();
        assert!(spool.wait_start_receipt(&envelope, Duration::ZERO).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn readers_reject_fifo_spool_files_without_blocking() {
        use std::os::unix::ffi::OsStrExt;
        use std::sync::mpsc;

        fn fifo(path: &std::path::Path) {
            let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
            // SAFETY: `path` is a valid NUL-terminated path and mode is an ordinary permission mask.
            assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        }

        fn completes_without_blocking<T: Send + 'static>(
            read: impl FnOnce() -> T + Send + 'static,
        ) -> T {
            let (sender, receiver) = mpsc::channel();
            std::thread::spawn(move || sender.send(read()).unwrap());
            receiver
                .recv_timeout(Duration::from_secs(1))
                .expect("FIFO read blocked instead of rejecting the non-regular file")
        }

        let temp = tempdir().unwrap();
        let spool = RunStepSpool::open(temp.path()).unwrap();
        let request = spool.publish_start_once(request()).unwrap();

        let request_path = spool.directory().join("start.request.json");
        std::fs::remove_file(&request_path).unwrap();
        fifo(&request_path);
        let request_spool = spool.clone();
        assert!(completes_without_blocking(move || request_spool.read_start_request()).is_err());

        let receipt_path = spool.directory().join("start.receipt.json");
        fifo(&receipt_path);
        let receipt_spool = spool.clone();
        assert!(
            completes_without_blocking(move || receipt_spool.read_start_receipt(&request)).is_err()
        );

        let result_path = spool.directory().join("turn.result.json");
        fifo(&result_path);
        let result_spool = spool.clone();
        assert!(completes_without_blocking(move || result_spool.read_result()).is_err());
    }

    #[test]
    fn bounded_turn_result_is_bound_to_start_and_detects_tampering() {
        let temp = tempdir().unwrap();
        let spool = RunStepSpool::open(temp.path()).unwrap();
        let request = spool.publish_start_once(request()).unwrap();
        let mut original = turn_result(&request.request);
        original.structured_result = Some(serde_json::json!({"answer":"ok"}));
        spool.publish_turn_result_once(&request, original).unwrap();
        let read = spool.read_turn_result(&request).unwrap();
        read.validate_for(&request).unwrap();

        let mut forged: AgentTurnResult =
            serde_json::from_slice(&spool.read_result().unwrap()).unwrap();
        forged.structured_result = Some(serde_json::json!({"answer":"changed"}));
        assert!(forged.validate_for(&request).is_err());
        assert!(
            spool
                .publish_turn_result_once(&request, turn_result(&request.request))
                .is_err()
        );
    }

    #[test]
    fn typed_result_rejects_oversize_and_unreadable_payloads_before_publication() {
        let temp = tempdir().unwrap();
        let spool = RunStepSpool::open(temp.path()).unwrap();
        let request = spool.publish_start_once(request()).unwrap();

        let mut oversized = turn_result(&request.request);
        oversized.structured_result = Some(serde_json::json!({
            "payload": "x".repeat(1024 * 1024)
        }));
        assert!(spool.publish_turn_result_once(&request, oversized).is_err());
        assert!(!spool.directory().join("turn.result.json").exists());

        let mut deeply_nested = serde_json::Value::String("leaf".into());
        for _ in 0..160 {
            deeply_nested = serde_json::Value::Array(vec![deeply_nested]);
        }
        let mut unreadable = turn_result(&request.request);
        unreadable.structured_result = Some(deeply_nested);
        assert!(
            spool
                .publish_turn_result_once(&request, unreadable)
                .is_err()
        );
        assert!(!spool.directory().join("turn.result.json").exists());
    }

    #[test]
    fn response_validators_reject_an_invalid_start_request_even_with_matching_digest() {
        let mut request_envelope = StartRequestEnvelope {
            schema_version: 1,
            request_digest: String::new(),
            request: request(),
        };
        request_envelope.request.schema_version = 2;
        request_envelope.request_digest =
            super::sha256(&serde_json::to_vec(&request_envelope.request).unwrap());

        let receipt = StartReceiptEnvelope {
            schema_version: 1,
            request_digest: request_envelope.request_digest.clone(),
            receipt: receipt(&request_envelope.request),
        };
        assert!(receipt.validate_for(&request_envelope).is_err());

        let result = turn_result(&request_envelope.request);
        let mut result = AgentTurnResult {
            schema_version: 1,
            start_request_digest: request_envelope.request_digest.clone(),
            receipt: result.receipt,
            structured_result: result.structured_result,
            result_digest: String::new(),
        };
        result.result_digest = result.payload_digest().unwrap();
        assert!(result.validate_for(&request_envelope).is_err());
    }

    #[test]
    fn result_cannot_be_replayed_for_a_different_valid_wrapper_binding() {
        let original_request = request();
        let mut result = turn_result(&original_request);
        result.structured_result = Some(serde_json::json!({"answer":"ok"}));
        let mut envelope = AgentTurnResult {
            schema_version: 1,
            start_request_digest: "0".repeat(64),
            receipt: result.receipt,
            structured_result: result.structured_result,
            result_digest: String::new(),
        };
        let original = StartRequestEnvelope {
            schema_version: 1,
            request_digest: super::sha256(&serde_json::to_vec(&original_request).unwrap()),
            request: original_request,
        };
        envelope.start_request_digest = original.request_digest.clone();
        envelope.result_digest = envelope.payload_digest().unwrap();
        envelope.validate_for(&original).unwrap();

        let mut changed_request = original.request.clone();
        changed_request.wrapper_start_identity = "different-kernel-birth".into();
        let changed = StartRequestEnvelope {
            schema_version: 1,
            request_digest: super::sha256(&serde_json::to_vec(&changed_request).unwrap()),
            request: changed_request,
        };

        assert!(envelope.validate_for(&changed).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn spool_reads_and_writes_remain_bound_to_opened_directory() {
        let temp = tempdir().unwrap();
        let spool = RunStepSpool::open(temp.path()).unwrap();
        let pinned = temp.path().join("pinned-run-step");
        std::fs::rename(spool.directory(), &pinned).unwrap();
        std::fs::create_dir(spool.directory()).unwrap();

        spool.publish_result_once(br#"{"result":1}"#).unwrap();

        assert_eq!(spool.read_result().unwrap(), br#"{"result":1}"#);
        assert!(!spool.directory().join("turn.result.json").exists());
        assert_eq!(
            std::fs::read(pinned.join("turn.result.json")).unwrap(),
            br#"{"result":1}"#
        );
    }

    #[test]
    fn raw_result_rejects_duplicate_keys_in_nested_objects() {
        let temp = tempdir().unwrap();
        let spool = RunStepSpool::open(temp.path()).unwrap();
        let bytes = br#"{"outer":{"result":1,"result":2}}"#;

        assert!(spool.publish_result_once(bytes).is_err());
        assert!(spool.read_result().is_err());
    }

    #[test]
    fn raw_result_rejects_oversize_payload_and_conflicting_replay() {
        let temp = tempdir().unwrap();
        let spool = RunStepSpool::open(temp.path()).unwrap();
        let bytes = br#"{"result":1}"#;
        spool.publish_result_once(bytes).unwrap();
        assert_eq!(spool.read_result().unwrap(), bytes);
        assert!(spool.publish_result_once(bytes).is_err());
        assert!(
            spool
                .publish_result_once(&vec![b' '; 1024 * 1024 + 1])
                .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn open_rejects_symlinked_control_directory() {
        use std::os::unix::fs::symlink;

        let temp = tempdir().unwrap();
        let actual = temp.path().join("actual");
        std::fs::create_dir(&actual).unwrap();
        let alias = temp.path().join("alias");
        symlink(&actual, &alias).unwrap();
        assert!(RunStepSpool::open(&alias).is_err());
    }
}
