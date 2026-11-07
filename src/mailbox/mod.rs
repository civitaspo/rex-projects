use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use fs2::FileExt;
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::protocol::{RequestEnvelope, RequestId, ResponseEnvelope, parse_unique};

const REQUEST_PREFIX: &str = "request-";
const RECEIPT_PREFIX: &str = "receipt-";
const MAX_ID_BYTES: usize = 255;
const MAX_REGISTERED_REQUEST_BYTES: usize = 1024 * 1024;
const MAX_REGISTERED_PENDING_REQUESTS: usize = 256;

#[derive(Clone, Copy, Debug)]
pub struct MailboxLimits {
    pub max_request_bytes: usize,
    pub max_pending_requests: usize,
}

impl Default for MailboxLimits {
    fn default() -> Self {
        Self {
            max_request_bytes: 256 * 1024,
            max_pending_requests: 32,
        }
    }
}

#[derive(Clone, Debug)]
pub struct MailboxRequest {
    pub request_id: String,
    pub digest: String,
    pub envelope: RequestEnvelope<Value>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxDescriptor {
    pub schema_version: u32,
    pub run_id: String,
    pub expires_at_unix: u64,
    pub max_request_bytes: usize,
    pub max_pending_requests: usize,
}

#[derive(Clone, Debug)]
pub enum QueueResult {
    Queued { digest: String },
    Duplicate { digest: String },
}

pub struct MailboxCapability {
    run_id: String,
    directory: PathBuf,
    expires_at: u64,
    limits: MailboxLimits,
    #[cfg(unix)]
    directory_handle: File,
}

impl MailboxCapability {
    pub fn create(
        run_id: impl Into<String>,
        directory: &Path,
        expires_at: u64,
        limits: MailboxLimits,
    ) -> Result<Self, String> {
        let run_id = run_id.into();
        validate_run_id(&run_id, limits)?;
        fs::create_dir_all(directory)
            .map_err(|error| format!("{}: {error}", directory.display()))?;
        let capability = Self::open_unregistered(run_id, directory, expires_at, limits)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            capability
                .directory_handle
                .set_permissions(std::fs::Permissions::from_mode(0o700))
                .map_err(|error| format!("secure mailbox root: {error}"))?;
        }
        #[cfg(not(unix))]
        set_private_directory_permissions(&capability.directory)?;
        let descriptor = MailboxDescriptor {
            schema_version: 1,
            run_id: capability.run_id.clone(),
            expires_at_unix: expires_at,
            max_request_bytes: limits.max_request_bytes,
            max_pending_requests: limits.max_pending_requests,
        };
        let descriptor = serde_json::to_vec(&descriptor).map_err(|error| error.to_string())?;
        match capability.atomic_publish("descriptor.json", &descriptor) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing =
                    capability
                        .read_bounded("descriptor.json", 4096)
                        .map_err(|read_error| {
                            format!("read existing mailbox descriptor: {read_error}")
                        })?;
                if existing != descriptor {
                    return Err(
                        "mailbox directory is already registered with a different capability"
                            .into(),
                    );
                }
            }
            Err(error) => return Err(format!("publish mailbox descriptor: {error}")),
        }
        Ok(capability)
    }

    pub fn open_existing(
        run_id: impl Into<String>,
        directory: &Path,
        expires_at: u64,
        limits: MailboxLimits,
    ) -> Result<Self, String> {
        let capability = Self::open_unregistered(run_id, directory, expires_at, limits)?;
        let bytes = capability
            .read_bounded("descriptor.json", 4096)
            .map_err(|error| format!("read mailbox descriptor: {error}"))?;
        let descriptor: MailboxDescriptor = parse_unique(&bytes)?;
        if descriptor.schema_version != 1
            || descriptor.run_id != capability.run_id
            || descriptor.expires_at_unix != expires_at
            || descriptor.max_request_bytes != limits.max_request_bytes
            || descriptor.max_pending_requests != limits.max_pending_requests
        {
            return Err("mailbox descriptor does not match its run-scoped capability".into());
        }
        Ok(capability)
    }

    pub fn open_registered(
        run_id: impl Into<String>,
        directory: &Path,
        limits: MailboxLimits,
    ) -> Result<Self, String> {
        let mut capability = Self::open_unregistered(run_id, directory, u64::MAX, limits)?;
        let bytes = capability
            .read_bounded("descriptor.json", 4096)
            .map_err(|error| format!("read mailbox descriptor: {error}"))?;
        let descriptor: MailboxDescriptor = parse_unique(&bytes)?;
        if descriptor.schema_version != 1
            || descriptor.run_id != capability.run_id
            || descriptor.max_request_bytes != limits.max_request_bytes
            || descriptor.max_pending_requests != limits.max_pending_requests
        {
            return Err("mailbox descriptor does not match its run-scoped capability".into());
        }
        capability.expires_at = descriptor.expires_at_unix;
        Ok(capability)
    }

    /// Opens an existing Agent mailbox using the limits recorded in its run-scoped descriptor.
    /// This is useful to read Agent-owned control data without SQLite or changing the registered
    /// limits expected by the host.
    pub fn open_registered_for_run(
        run_id: impl Into<String>,
        directory: &Path,
    ) -> Result<Self, String> {
        let mut capability =
            Self::open_unregistered(run_id, directory, u64::MAX, MailboxLimits::default())?;
        let bytes = capability
            .read_bounded("descriptor.json", 4096)
            .map_err(|error| format!("read mailbox descriptor: {error}"))?;
        let descriptor: MailboxDescriptor = parse_unique(&bytes)?;
        if descriptor.schema_version != 1
            || descriptor.run_id != capability.run_id
            || descriptor.max_request_bytes == 0
            || descriptor.max_request_bytes > MAX_REGISTERED_REQUEST_BYTES
            || descriptor.max_pending_requests == 0
            || descriptor.max_pending_requests > MAX_REGISTERED_PENDING_REQUESTS
        {
            return Err("mailbox descriptor is not a bounded capability for this AgentRun".into());
        }
        capability.limits = MailboxLimits {
            max_request_bytes: descriptor.max_request_bytes,
            max_pending_requests: descriptor.max_pending_requests,
        };
        capability.expires_at = descriptor.expires_at_unix;
        Ok(capability)
    }

    pub fn open_registered_verified(
        run_id: impl Into<String>,
        directory: &Path,
        limits: MailboxLimits,
        expected_digest: &str,
    ) -> Result<Self, String> {
        let capability = Self::open_registered(run_id, directory, limits)?;
        let bytes = capability
            .read_bounded("descriptor.json", 4096)
            .map_err(|error| format!("read mailbox descriptor: {error}"))?;
        let digest = format!("{:x}", sha2::Sha256::digest(&bytes));
        if digest != expected_digest {
            return Err(
                "registered mailbox descriptor digest does not match durable host registration"
                    .into(),
            );
        }
        let canonical = fs::canonicalize(directory).map_err(|error| error.to_string())?;
        if canonical != capability.directory {
            return Err("registered mailbox path changed after canonicalization".into());
        }
        Ok(capability)
    }

    fn open_unregistered(
        run_id: impl Into<String>,
        directory: &Path,
        expires_at: u64,
        limits: MailboxLimits,
    ) -> Result<Self, String> {
        let run_id = run_id.into();
        validate_run_id(&run_id, limits)?;
        let root_metadata = fs::symlink_metadata(directory)
            .map_err(|error| format!("{}: {error}", directory.display()))?;
        if !root_metadata.is_dir() || root_metadata.file_type().is_symlink() {
            return Err("mailbox root must be a real directory, not a symlink".into());
        }
        let canonical = fs::canonicalize(directory)
            .map_err(|error| format!("{}: {error}", directory.display()))?;
        let metadata = fs::symlink_metadata(&canonical)
            .map_err(|error| format!("{}: {error}", canonical.display()))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err("mailbox root must be a real directory".into());
        }
        #[cfg(unix)]
        let directory_handle =
            open_dir(&canonical).map_err(|error| format!("open mailbox root: {error}"))?;
        Ok(Self {
            run_id,
            directory: canonical,
            expires_at,
            limits,
            #[cfg(unix)]
            directory_handle,
        })
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    pub fn queue(&self, request_id: &str, bytes: &[u8], now: u64) -> Result<QueueResult, String> {
        self.check_live(now)?;
        if !valid_request_id(request_id) {
            return Err("invalid mailbox request id".into());
        }
        if bytes.len() > self.limits.max_request_bytes {
            return Err("mailbox request exceeds configured byte limit".into());
        }
        let envelope: RequestEnvelope<Value> = parse_unique(bytes)?;
        envelope.validate()?;
        if envelope.request_id.as_str() != request_id {
            return Err("request id does not match the mailbox filename key".into());
        }
        let request_digest = digest(bytes);
        let name = format!("{REQUEST_PREFIX}{}.json", key(request_id));
        let _guard = self.lock_mailbox()?;
        match self.read_bounded(&name, self.limits.max_request_bytes) {
            Ok(existing) if digest(&existing) == request_digest => {
                return Ok(QueueResult::Duplicate {
                    digest: request_digest,
                });
            }
            Ok(_) => return Err("request id was already queued with different content".into()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("inspect mailbox request: {error}")),
        }
        let count = self.unacknowledged_request_names()?.len();
        if count >= self.limits.max_pending_requests {
            return Err("mailbox pending request count reached configured limit".into());
        }
        match self.create_new(&name, bytes) {
            Ok(()) => Ok(QueueResult::Queued {
                digest: request_digest,
            }),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing = self
                    .read_bounded(&name, self.limits.max_request_bytes)
                    .map_err(|error| format!("inspect mailbox request: {error}"))?;
                if digest(&existing) == request_digest {
                    Ok(QueueResult::Duplicate {
                        digest: request_digest,
                    })
                } else {
                    Err("request id was already queued with different content".into())
                }
            }
            Err(error) => Err(format!("write mailbox request: {error}")),
        }
    }

    pub fn pending(&self, now: u64) -> Result<Vec<MailboxRequest>, String> {
        self.check_live(now)?;
        let mut paths = self
            .directory_file_names()
            .map_err(|error| format!("{}: {error}", self.directory.display()))?;
        paths.sort();
        let mut requests = Vec::new();
        for file_name in paths {
            let Some(name) = file_name.to_str() else {
                continue;
            };
            if !name.starts_with(REQUEST_PREFIX) || !name.ends_with(".json") {
                continue;
            }
            if self.has_receipt_for_request_file(name)? {
                continue;
            }
            let bytes = self
                .read_bounded(name, self.limits.max_request_bytes)
                .map_err(|error| format!("read mailbox request: {error}"))?;
            let envelope: RequestEnvelope<Value> = parse_unique(&bytes)?;
            envelope.validate()?;
            requests.push(MailboxRequest {
                request_id: envelope.request_id.as_str().to_owned(),
                digest: digest(&bytes),
                envelope,
            });
            if requests.len() > self.limits.max_pending_requests {
                return Err("mailbox pending request count exceeds configured limit".into());
            }
        }
        Ok(requests)
    }

    fn unacknowledged_request_names(&self) -> Result<Vec<String>, String> {
        let entries = self
            .directory_file_names()
            .map_err(|error| format!("{}: {error}", self.directory.display()))?;
        let mut pending = Vec::new();
        for entry in entries {
            let Some(name) = entry.to_str().map(str::to_owned) else {
                continue;
            };
            if name.starts_with(REQUEST_PREFIX)
                && name.ends_with(".json")
                && !self.has_receipt_for_request_file(&name)?
            {
                pending.push(name);
            }
        }
        Ok(pending)
    }

    fn has_receipt_for_request_file(&self, request_name: &str) -> Result<bool, String> {
        let Some(key) = request_name
            .strip_prefix(REQUEST_PREFIX)
            .and_then(|name| name.strip_suffix(".json"))
        else {
            return Err("invalid internal request filename".into());
        };
        let receipt_name = format!("{RECEIPT_PREFIX}{key}.json");
        match self.read_bounded(&receipt_name, self.limits.max_request_bytes) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(format!("inspect mailbox receipt: {error}")),
        }
    }

    #[cfg(unix)]
    fn directory_file_names(&self) -> Result<Vec<std::ffi::OsString>, std::io::Error> {
        use std::os::fd::AsRawFd;
        use std::os::unix::ffi::OsStringExt;
        // Opening "." relative to the pinned directory creates an independent open file
        // description with its own directory cursor.
        // SAFETY: the retained descriptor is a verified directory; "." is a fixed basename.
        let duplicate = unsafe {
            libc::openat(
                self.directory_handle.as_raw_fd(),
                c".".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if duplicate < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: fdopendir takes ownership of duplicate on success.
        let stream = unsafe { libc::fdopendir(duplicate) };
        if stream.is_null() {
            let error = std::io::Error::last_os_error();
            // SAFETY: fdopendir failed and did not take ownership.
            unsafe { libc::close(duplicate) };
            return Err(error);
        }
        let mut names = Vec::new();
        loop {
            // SAFETY: stream remains live until closedir below; readdir returns an entry owned by it.
            let entry = unsafe { libc::readdir(stream) };
            if entry.is_null() {
                break;
            }
            // SAFETY: dirent.d_name is a nul-terminated array provided by readdir.
            let bytes = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if bytes != b"." && bytes != b".." {
                names.push(std::ffi::OsString::from_vec(bytes.to_vec()));
            }
        }
        // SAFETY: closes the stream and its owned duplicated descriptor.
        if unsafe { libc::closedir(stream) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(names)
    }
    #[cfg(not(unix))]
    fn directory_file_names(&self) -> Result<Vec<std::ffi::OsString>, std::io::Error> {
        fs::read_dir(&self.directory)?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect()
    }

    pub fn publish_receipt(&self, request_id: &str, bytes: &[u8], now: u64) -> Result<(), String> {
        self.check_live(now)?;
        if !valid_request_id(request_id) {
            return Err("invalid mailbox request id".into());
        }
        if bytes.len() > self.limits.max_request_bytes {
            return Err("mailbox receipt exceeds configured byte limit".into());
        }
        let receipt: ResponseEnvelope<Value> = parse_unique(bytes)?;
        receipt.validate_for(&RequestId::new(request_id)?)?;
        let _guard = self.lock_mailbox()?;
        let name = format!("{RECEIPT_PREFIX}{}.json", key(request_id));
        match self.read_bounded(&name, self.limits.max_request_bytes) {
            Ok(existing) if existing == bytes => return Ok(()),
            Ok(_) => return Err("mailbox receipt already exists with different content".into()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("inspect mailbox receipt: {error}")),
        }
        match self.atomic_publish(&name, bytes) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing = self
                    .read_bounded(&name, self.limits.max_request_bytes)
                    .map_err(|error| format!("inspect mailbox receipt: {error}"))?;
                if existing == bytes {
                    Ok(())
                } else {
                    Err("mailbox receipt already exists with different content".into())
                }
            }
            Err(error) => Err(format!("publish mailbox receipt: {error}")),
        }
    }

    pub fn read_receipt(&self, request_id: &str, now: u64) -> Result<Option<Vec<u8>>, String> {
        self.check_live(now)?;
        let name = format!("{RECEIPT_PREFIX}{}.json", key(request_id));
        match self.read_bounded(&name, self.limits.max_request_bytes) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(format!("read mailbox receipt: {error}")),
        }
    }

    fn check_live(&self, now: u64) -> Result<(), String> {
        if now >= self.expires_at {
            Err("mailbox capability has expired".into())
        } else {
            Ok(())
        }
    }

    #[cfg(unix)]
    fn lock_mailbox(&self) -> Result<File, String> {
        use std::os::fd::{AsRawFd, FromRawFd};
        // Open a fresh file description for the pinned directory so flock serializes separate
        // queue/publish calls, including separate processes, without a mutable lock-file path.
        // SAFETY: the retained descriptor is a verified directory; "\." is a fixed basename.
        let fd = unsafe {
            libc::openat(
                self.directory_handle.as_raw_fd(),
                c".".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(format!(
                "open mailbox lock handle: {}",
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: openat returned a new owned descriptor.
        let file = unsafe { File::from_raw_fd(fd) };
        lock_with_timeout(file)
    }
    #[cfg(not(unix))]
    fn lock_mailbox(&self) -> Result<File, String> {
        let lock_path = self.directory.join(".mailbox.lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(lock_path)
            .map_err(|e| e.to_string())?;
        lock_with_timeout(file)
    }

    #[cfg(unix)]
    fn read_bounded(&self, name: &str, maximum: usize) -> Result<Vec<u8>, std::io::Error> {
        read_bounded_at(&self.directory_handle, name, maximum)
    }
    #[cfg(not(unix))]
    fn read_bounded(&self, name: &str, maximum: usize) -> Result<Vec<u8>, std::io::Error> {
        read_bounded_at(&self.directory, name, maximum)
    }
    #[cfg(unix)]
    fn create_new(&self, name: &str, bytes: &[u8]) -> Result<(), std::io::Error> {
        atomic_publish_at(&self.directory_handle, name, bytes)
    }
    #[cfg(not(unix))]
    fn create_new(&self, name: &str, bytes: &[u8]) -> Result<(), std::io::Error> {
        create_new_at(&self.directory, name, bytes)
    }
    #[cfg(unix)]
    fn atomic_publish(&self, name: &str, bytes: &[u8]) -> Result<(), std::io::Error> {
        atomic_publish_at(&self.directory_handle, name, bytes)
    }
    #[cfg(not(unix))]
    fn atomic_publish(&self, name: &str, bytes: &[u8]) -> Result<(), std::io::Error> {
        atomic_publish_at(&self.directory, name, bytes)
    }
}

fn validate_run_id(run_id: &str, limits: MailboxLimits) -> Result<(), String> {
    if run_id.is_empty() || run_id.len() > MAX_ID_BYTES || run_id.chars().any(char::is_control) {
        return Err("invalid mailbox run id".into());
    }
    if limits.max_request_bytes == 0 || limits.max_pending_requests == 0 {
        return Err("mailbox limits must be positive".into());
    }
    Ok(())
}

pub fn unix_time_now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| error.to_string())
}

fn lock_with_timeout(file: File) -> Result<File, String> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        match file.try_lock_exclusive() {
            Ok(()) => return Ok(file),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if std::time::Instant::now() >= deadline {
                    return Err("mailbox is busy; retry shortly".into());
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(error) => return Err(format!("lock mailbox: {error}")),
        }
    }
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn key(value: &str) -> String {
    digest(value.as_bytes())
}

fn valid_request_id(value: &str) -> bool {
    let mut chars = value.chars();
    matches!(chars.next(), Some(first) if first.is_ascii_alphanumeric())
        && value.len() <= MAX_ID_BYTES
        && chars.all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
        })
}

#[cfg(not(unix))]
fn set_private_directory_permissions(_path: &Path) -> Result<(), String> {
    Ok(())
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
fn read_bounded_at(
    directory: &File,
    name: &str,
    maximum: usize,
) -> Result<Vec<u8>, std::io::Error> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let name_c = std::ffi::CString::new(name).expect("internal filename has no nul");
    // SAFETY: `dir` is an open directory descriptor and name_c is an internal basename.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name_c.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: openat returned a new owned file descriptor.
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > maximum as u64 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "mailbox entry is not a bounded regular file",
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "mailbox entry exceeds configured byte limit",
        ));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn atomic_publish_at(directory: &File, name: &str, bytes: &[u8]) -> Result<(), std::io::Error> {
    use std::os::fd::AsRawFd;
    let temporary = format!(
        ".mailbox-{}-{}-{}-{}",
        key(name),
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
        unique_temp_counter(),
    );
    let temporary_c = std::ffi::CString::new(temporary.clone()).expect("internal filename");
    let target_c = std::ffi::CString::new(name).expect("internal filename");
    // SAFETY: `dir` is an open directory descriptor, temporary_c and target_c are internal
    // basenames, and O_NOFOLLOW/O_EXCL prevents path substitution.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            temporary_c.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: openat returned a new owned file descriptor.
    let mut file = unsafe { File::from_raw_fd(fd) };
    let result = file.write_all(bytes).and_then(|()| file.sync_all());
    if let Err(error) = result {
        // SAFETY: temporary_c is the private temporary basename beneath the open directory.
        unsafe { libc::unlinkat(directory.as_raw_fd(), temporary_c.as_ptr(), 0) };
        return Err(error);
    }
    // SAFETY: linkat uses two internal basenames relative to the open directory. It creates the
    // destination only if absent and cannot follow either final component as a symlink.
    let result = unsafe {
        libc::linkat(
            directory.as_raw_fd(),
            temporary_c.as_ptr(),
            directory.as_raw_fd(),
            target_c.as_ptr(),
            0,
        )
    };
    if result < 0 {
        let error = std::io::Error::last_os_error();
        // SAFETY: temporary_c is the private temporary basename beneath the open directory.
        unsafe { libc::unlinkat(directory.as_raw_fd(), temporary_c.as_ptr(), 0) };
        return Err(error);
    }
    // SAFETY: temporary_c is the private temporary basename beneath the open directory.
    unsafe { libc::unlinkat(directory.as_raw_fd(), temporary_c.as_ptr(), 0) };
    directory.sync_all()
}

#[cfg(unix)]
fn unique_temp_counter() -> u64 {
    static NEXT_TEMP: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    NEXT_TEMP.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

#[cfg(unix)]
use std::os::fd::FromRawFd;

#[cfg(not(unix))]
fn create_new_at(directory: &Path, name: &str, bytes: &[u8]) -> Result<(), std::io::Error> {
    let path = directory.join(name);
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(not(unix))]
fn read_bounded_at(
    directory: &Path,
    name: &str,
    maximum: usize,
) -> Result<Vec<u8>, std::io::Error> {
    let path = directory.join(name);
    let mut file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > maximum as u64 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid mailbox entry",
        ));
    }
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
    Ok(bytes)
}

#[cfg(not(unix))]
fn atomic_publish_at(directory: &Path, name: &str, bytes: &[u8]) -> Result<(), std::io::Error> {
    let temporary = directory.join(format!(".receipt-{}-{}", key(name), std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::hard_link(&temporary, directory.join(name))?;
    fs::remove_file(temporary)
}

#[cfg(test)]
mod tests {
    use super::{MailboxCapability, MailboxLimits, QueueResult};
    use std::fs;

    fn request(id: &str, value: &str) -> Vec<u8> {
        format!(r#"{{"schema_version":1,"request_id":"{id}","method":"agent.submit","params":{{"value":"{value}"}}}}"#).into_bytes()
    }

    fn capability(path: &std::path::Path) -> MailboxCapability {
        MailboxCapability::create("agent-run-1", path, 10, MailboxLimits::default()).unwrap()
    }

    #[test]
    fn opening_agent_capability_never_creates_a_directory() {
        let temp = tempfile::tempdir().unwrap();
        let missing = temp.path().join("not-registered");
        assert!(
            MailboxCapability::open_existing("agent-run-1", &missing, 10, MailboxLimits::default())
                .is_err()
        );
        assert!(!missing.exists());
    }

    #[test]
    fn queues_valid_request_and_replays_same_receipt_key() {
        let root = tempfile::tempdir().unwrap();
        let mailbox = capability(root.path());
        let bytes = request("r-1", "same");
        assert!(matches!(
            mailbox.queue("r-1", &bytes, 1).unwrap(),
            QueueResult::Queued { .. }
        ));
        assert!(matches!(
            mailbox.queue("r-1", &bytes, 1).unwrap(),
            QueueResult::Duplicate { .. }
        ));
        assert_eq!(mailbox.pending(1).unwrap().len(), 1);
        let receipt = br#"{"schema_version":1,"request_id":"r-1","result":{"accepted":true}}"#;
        mailbox.publish_receipt("r-1", receipt, 1).unwrap();
        assert_eq!(mailbox.read_receipt("r-1", 1).unwrap().unwrap(), receipt);
    }

    #[test]
    fn rejects_reused_id_with_changed_content() {
        let root = tempfile::tempdir().unwrap();
        let mailbox = capability(root.path());
        mailbox.queue("r-1", &request("r-1", "first"), 1).unwrap();
        assert!(mailbox.queue("r-1", &request("r-1", "changed"), 1).is_err());
    }

    #[test]
    fn rejects_traversal_and_expired_or_oversized_requests() {
        let root = tempfile::tempdir().unwrap();
        let mailbox = capability(root.path());
        assert!(
            mailbox
                .queue("../outside", &request("../outside", "x"), 1)
                .is_err()
        );
        assert!(mailbox.queue("r-1", &request("r-1", "x"), 11).is_err());
        let limited_root = tempfile::tempdir().unwrap();
        let limited = MailboxCapability::create(
            "agent-run-1",
            limited_root.path(),
            10,
            MailboxLimits {
                max_request_bytes: 4096,
                max_pending_requests: 1,
            },
        )
        .unwrap();
        limited.queue("r-1", &request("r-1", "x"), 1).unwrap();
        assert!(limited.queue("r-2", &request("r-2", "x"), 1).is_err());
        let second_root = tempfile::tempdir().unwrap();
        let small = MailboxCapability::create(
            "agent-run-1",
            second_root.path(),
            10,
            MailboxLimits {
                max_request_bytes: 8,
                max_pending_requests: 2,
            },
        )
        .unwrap();
        assert!(small.queue("r-1", &request("r-1", "x"), 1).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_request_and_receipt_entries() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let mailbox = capability(root.path());
        let outside = root.path().join("outside");
        fs::write(&outside, request("r-1", "x")).unwrap();
        let file_name = format!("request-{}.json", super::key("r-1"));
        symlink(&outside, root.path().join(file_name)).unwrap();
        assert!(mailbox.pending(1).is_err());
        assert!(mailbox.queue("r-1", &request("r-1", "x"), 1).is_err());
        fs::remove_file(
            root.path()
                .join(format!("request-{}.json", super::key("r-1"))),
        )
        .unwrap();
        let receipt_name = format!("receipt-{}.json", super::key("r-1"));
        symlink(&outside, root.path().join(receipt_name)).unwrap();
        assert!(mailbox.read_receipt("r-1", 1).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn directory_replacement_does_not_redirect_capability_writes() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let mailbox_path = root.path().join("mailbox");
        let outside = root.path().join("outside");
        fs::create_dir(&mailbox_path).unwrap();
        fs::create_dir(&outside).unwrap();
        let mailbox = capability(&mailbox_path);
        let moved = root.path().join("mailbox-original");
        fs::rename(&mailbox_path, &moved).unwrap();
        symlink(&outside, &mailbox_path).unwrap();
        mailbox.queue("r-1", &request("r-1", "safe"), 1).unwrap();
        assert!(fs::read_dir(&outside).unwrap().next().is_none());
        assert_eq!(fs::read_dir(&moved).unwrap().count(), 2);
    }

    #[test]
    fn acknowledged_requests_leave_capacity_available_and_retry_returns_receipt() {
        let root = tempfile::tempdir().unwrap();
        let mailbox = MailboxCapability::create(
            "agent-run-1",
            root.path(),
            100,
            MailboxLimits {
                max_request_bytes: 4096,
                max_pending_requests: 1,
            },
        )
        .unwrap();
        for index in 0..4 {
            let request_id = format!("r-{index}");
            let bytes = request(&request_id, "value");
            mailbox.queue(&request_id, &bytes, 1).unwrap();
            assert_eq!(mailbox.pending(1).unwrap().len(), 1);
            let receipt = format!(
                r#"{{"schema_version":1,"request_id":"{request_id}","result":{{"accepted":true}}}}"#
            );
            mailbox
                .publish_receipt(&request_id, receipt.as_bytes(), 1)
                .unwrap();
            assert!(mailbox.pending(1).unwrap().is_empty());
            assert!(matches!(
                mailbox.queue(&request_id, &bytes, 1).unwrap(),
                QueueResult::Duplicate { .. }
            ));
            assert_eq!(
                mailbox.read_receipt(&request_id, 1).unwrap().unwrap(),
                receipt.as_bytes()
            );
        }
    }

    #[test]
    fn concurrent_queue_calls_cannot_exceed_pending_limit() {
        let root = tempfile::tempdir().unwrap();
        let mailbox = MailboxCapability::create(
            "agent-run-1",
            root.path(),
            100,
            MailboxLimits {
                max_request_bytes: 4096,
                max_pending_requests: 1,
            },
        )
        .unwrap();
        let outcomes = std::thread::scope(|scope| {
            let first = scope.spawn(|| mailbox.queue("r-1", &request("r-1", "one"), 1));
            let second = scope.spawn(|| mailbox.queue("r-2", &request("r-2", "two"), 1));
            [first.join().unwrap(), second.join().unwrap()]
        });
        assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
        assert_eq!(
            outcomes.iter().filter(|outcome| outcome.is_err()).count(),
            1
        );
        assert_eq!(mailbox.pending(1).unwrap().len(), 1);
    }
}
