use std::collections::{BTreeMap, VecDeque};
use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

fn is_process_gone(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::NotFound || error.raw_os_error() == Some(3)
}

#[derive(Clone, Debug)]
pub struct ProcessRequest {
    pub executable: PathBuf,
    pub args: Vec<OsString>,
    pub stdin: Vec<u8>,
    pub cwd: Option<PathBuf>,
    pub clear_environment: bool,
    pub environment: BTreeMap<OsString, OsString>,
    pub timeout: Duration,
    pub shutdown_grace: Duration,
    pub stdout_limit: usize,
    pub stderr_tail_limit: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessOutput {
    pub status: Option<ExitStatus>,
    pub stdout: Vec<u8>,
    pub stderr_tail: Vec<u8>,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub timed_out: bool,
    pub cleanup_confirmed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessIdentityQuality {
    KernelBirthToken,
    SecondPrecision,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub parent_pid: u32,
    pub process_group_id: u32,
    pub start_identity: String,
    pub command: String,
    pub quality: ProcessIdentityQuality,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessSignal {
    Interrupt,
    Terminate,
    Kill,
}

#[derive(Debug)]
pub enum ProcessError {
    Invalid(String),
    Start(std::io::Error),
    Io(std::io::Error),
    Inspection(String),
    CleanupUnconfirmed,
}

impl std::fmt::Display for ProcessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(message) => write!(f, "invalid process request: {message}"),
            Self::Start(_) => f.write_str("cannot start configured executable"),
            Self::Io(_) => f.write_str("process I/O failed"),
            Self::Inspection(_) => f.write_str("process identity inspection failed"),
            Self::CleanupUnconfirmed => {
                f.write_str("process did not stop within its bounded shutdown grace")
            }
        }
    }
}

impl std::error::Error for ProcessError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Start(error) | Self::Io(error) => Some(error),
            Self::Invalid(_) | Self::Inspection(_) | Self::CleanupUnconfirmed => None,
        }
    }
}

pub fn run(mut request: ProcessRequest) -> Result<ProcessOutput, ProcessError> {
    validate(&request)?;
    let mut command = Command::new(&request.executable);
    command
        .args(&request.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(cwd) = request.cwd.as_deref() {
        command.current_dir(cwd);
    }
    if request.clear_environment {
        command.env_clear();
    }
    command.envs(&request.environment);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command.spawn().map_err(ProcessError::Start)?;
    let stdout = child.stdout.take().expect("stdout was piped");
    let stderr = child.stderr.take().expect("stderr was piped");
    let mut stdin = child.stdin.take().expect("stdin was piped");
    let stdout_limit = request.stdout_limit;
    let stderr_limit = request.stderr_tail_limit;
    let (out_tx, out_rx) = mpsc::sync_channel(1);
    let (err_tx, err_rx) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let _ = out_tx.send(read_bounded(stdout, stdout_limit));
    });
    thread::spawn(move || {
        let _ = err_tx.send(read_tail(stderr, stderr_limit));
    });
    let input = std::mem::take(&mut request.stdin);
    let (input_tx, input_rx) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let _ = stdin.write_all(&input);
        let _ = stdin.flush();
        let _ = input_tx.send(());
    });

    let deadline = Instant::now() + request.timeout;
    let mut timed_out = false;
    let mut status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {}
            Err(error) => {
                // The child PID still belongs to this Child handle. Attempt
                // bounded cleanup before returning the inspection failure.
                signal_group(child.id(), "TERM");
                let stopped = wait_until(&mut child, request.shutdown_grace)?;
                if stopped.is_none() {
                    signal_group(child.id(), "KILL");
                    let _ = wait_until(&mut child, request.shutdown_grace)?;
                }
                return Err(ProcessError::Io(error));
            }
        }
        if Instant::now() >= deadline {
            timed_out = true;
            break None;
        }
        thread::sleep(Duration::from_millis(10));
    };
    let mut cleanup_confirmed = true;
    if timed_out {
        // The root Child is still unreaped while its process group is signalled,
        // so this PGID cannot have been recycled for an unrelated process.
        signal_group(child.id(), "TERM");
        status = wait_until(&mut child, request.shutdown_grace)?;
        if status.is_none() {
            signal_group(child.id(), "KILL");
            status = wait_until(&mut child, request.shutdown_grace)?;
        }
        cleanup_confirmed = status.is_some();
    }
    let io_deadline = Instant::now() + request.shutdown_grace;
    let input_done = input_rx.recv_timeout(remaining(io_deadline)).is_ok();
    let stdout_result = out_rx.recv_timeout(remaining(io_deadline));
    let stderr_result = err_rx.recv_timeout(remaining(io_deadline));
    let (stdout, stdout_truncated) = stdout_result
        .map_err(|_| ProcessError::CleanupUnconfirmed)?
        .map_err(ProcessError::Io)?;
    let (stderr_tail, stderr_truncated) = stderr_result
        .map_err(|_| ProcessError::CleanupUnconfirmed)?
        .map_err(ProcessError::Io)?;
    cleanup_confirmed &= input_done;
    if !cleanup_confirmed {
        return Err(ProcessError::CleanupUnconfirmed);
    }
    Ok(ProcessOutput {
        status,
        stdout,
        stderr_tail,
        stdout_truncated,
        stderr_truncated,
        timed_out,
        cleanup_confirmed,
    })
}

fn remaining(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}

/// Return the current process table without reading command arguments or
/// environment variables. Inspection failure is distinct from an empty table.
pub fn inspect_process_table() -> Result<Vec<ProcessIdentity>, ProcessError> {
    #[cfg(target_os = "linux")]
    {
        inspect_linux_process_table()
    }
    #[cfg(target_os = "macos")]
    {
        inspect_macos_process_table()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Err(ProcessError::Inspection(
            "kernel birth-token inspection is unsupported on this platform".into(),
        ))
    }
}

pub fn capture_process_tree(
    root_pid: u32,
    initial_table: &[ProcessIdentity],
) -> Vec<ProcessIdentity> {
    let Some(root) = initial_table.iter().find(|item| item.pid == root_pid) else {
        return Vec::new();
    };
    let group_id = root.process_group_id;
    let mut included = std::collections::BTreeSet::from([root_pid]);
    loop {
        let before = included.len();
        for item in initial_table {
            if item.process_group_id == group_id || included.contains(&item.parent_pid) {
                included.insert(item.pid);
            }
        }
        if included.len() == before {
            break;
        }
    }
    let mut result = initial_table
        .iter()
        .filter(|item| included.contains(&item.pid))
        .cloned()
        .collect::<Vec<_>>();
    result.sort_by_key(|item| item.pid);
    result
}

pub fn matching_processes(
    observed: &[ProcessIdentity],
    current: &[ProcessIdentity],
) -> Vec<ProcessIdentity> {
    current
        .iter()
        .filter(|candidate| observed.iter().any(|known| known == *candidate))
        .cloned()
        .collect()
}

/// Signal only a still-running, previously observed group leader. Keeping the
/// original leader alive prevents its PID/PGID from being recycled between
/// identity validation and the group signal. A surviving descendant alone is
/// insufficient proof to signal a reused group number.
pub fn signal_process_group_if_observed(
    process_group_id: u32,
    observed: &[ProcessIdentity],
    current: &[ProcessIdentity],
    signal: ProcessSignal,
) -> Result<bool, ProcessError> {
    let matched = matching_processes(observed, current);
    let Some(leader) = matched
        .iter()
        .find(|item| item.pid == process_group_id && item.process_group_id == process_group_id)
    else {
        return if matched
            .iter()
            .any(|item| item.process_group_id == process_group_id)
        {
            Err(ProcessError::Inspection(
                "cannot safely signal a group after its verified leader exited".into(),
            ))
        } else {
            Ok(false)
        };
    };
    if leader.quality != ProcessIdentityQuality::KernelBirthToken
        || process_group_id > i32::MAX as u32
    {
        return Err(ProcessError::Inspection(
            "second-precision identity cannot authorize process signalling".into(),
        ));
    }
    #[cfg(unix)]
    {
        let signal_number = match signal {
            ProcessSignal::Interrupt => 2,
            ProcessSignal::Terminate => 15,
            ProcessSignal::Kill => 9,
        };
        // The leader is still present and identity-matched, so the PGID remains
        // attached to this run while killpg executes.
        let result = unsafe { kill_process_group(-(process_group_id as i32), signal_number) };
        if result == 0 {
            Ok(true)
        } else if is_process_gone(&std::io::Error::last_os_error()) {
            Ok(false)
        } else {
            Err(ProcessError::Inspection(
                "operating system rejected the verified process-group signal".into(),
            ))
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (process_group_id, signal);
        Err(ProcessError::Inspection(
            "process-group signalling is unsupported on this platform".into(),
        ))
    }
}

#[cfg(unix)]
unsafe extern "C" {
    #[link_name = "kill"]
    fn kill_process_group(pid: i32, signal: i32) -> i32;
}

#[cfg(target_os = "linux")]
fn inspect_linux_process_table() -> Result<Vec<ProcessIdentity>, ProcessError> {
    let entries = std::fs::read_dir("/proc").map_err(ProcessError::Io)?;
    let mut processes = Vec::new();
    for entry in entries {
        let entry = entry.map_err(ProcessError::Io)?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let stat_path = entry.path().join("stat");
        let stat = match std::fs::read_to_string(&stat_path) {
            Ok(stat) => stat,
            Err(error) if is_process_gone(&error) => continue,
            Err(error) => return Err(ProcessError::Inspection(error.to_string())),
        };
        let Some((command, fields)) = parse_linux_stat(&stat) else {
            return Err(ProcessError::Inspection(
                "kernel returned an invalid process stat record".into(),
            ));
        };
        processes.push(ProcessIdentity {
            pid,
            parent_pid: parse_field(fields, 1)?,
            process_group_id: parse_field(fields, 2)?,
            start_identity: format!(
                "linux-start-ticks:{}",
                fields.get(19).ok_or_else(|| {
                    ProcessError::Inspection("process stat omitted start ticks".into())
                })?
            ),
            command,
            quality: ProcessIdentityQuality::KernelBirthToken,
        });
    }
    processes.sort_by_key(|item| item.pid);
    Ok(processes)
}

#[cfg(target_os = "linux")]
fn parse_linux_stat(stat: &str) -> Option<(String, Vec<&str>)> {
    let start = stat.find('(')?;
    let end = stat.rfind(')')?;
    if end <= start {
        return None;
    }
    let command = stat[start + 1..end].to_owned();
    Some((command, stat[end + 1..].split_whitespace().collect()))
}

#[cfg(target_os = "linux")]
fn parse_field<T: std::str::FromStr>(fields: &[&str], index: usize) -> Result<T, ProcessError> {
    fields
        .get(index)
        .ok_or_else(|| ProcessError::Inspection("process stat omitted required fields".into()))?
        .parse()
        .map_err(|_| ProcessError::Inspection("process stat contained invalid numeric data".into()))
}

#[cfg(target_os = "macos")]
fn inspect_macos_process_table() -> Result<Vec<ProcessIdentity>, ProcessError> {
    use std::ffi::{CStr, c_char, c_int, c_void};

    #[repr(C)]
    struct ProcBsdInfo {
        flags: u32,
        status: u32,
        exit_status: u32,
        pid: u32,
        parent_pid: u32,
        uid: u32,
        gid: u32,
        real_uid: u32,
        real_gid: u32,
        saved_uid: u32,
        saved_gid: u32,
        reserved: u32,
        command: [c_char; 16],
        name: [c_char; 32],
        files: u32,
        process_group_id: u32,
        process_group_jobs: u32,
        device: u32,
        foreground_group: u32,
        nice: i32,
        start_seconds: u64,
        start_microseconds: u64,
    }

    unsafe extern "C" {
        fn proc_listpids(kind: u32, typeinfo: u32, buffer: *mut c_void, buffersize: c_int)
        -> c_int;
        fn proc_pidinfo(
            pid: c_int,
            flavor: c_int,
            arg: u64,
            buffer: *mut c_void,
            buffersize: c_int,
        ) -> c_int;
        fn getuid() -> u32;
    }

    const PROC_PIDTBSDINFO: c_int = 3;
    const PROC_UID_ONLY: u32 = 4;
    let max_pids = 65_536_usize;
    let mut pids = vec![0_i32; max_pids];
    let uid = unsafe { getuid() };
    let bytes = unsafe {
        proc_listpids(
            PROC_UID_ONLY,
            uid,
            pids.as_mut_ptr().cast(),
            std::mem::size_of_val(pids.as_slice()) as c_int,
        )
    };
    if bytes < 0 {
        return Err(ProcessError::Inspection(
            "kernel process enumeration failed".into(),
        ));
    }
    if bytes as usize >= std::mem::size_of_val(pids.as_slice()) {
        return Err(ProcessError::Inspection(
            "process table exceeded the bounded identity buffer".into(),
        ));
    }
    let count = (bytes as usize / std::mem::size_of::<i32>()).min(pids.len());
    let mut processes = Vec::new();
    for pid in pids.into_iter().take(count).filter(|pid| *pid > 0) {
        let mut info = std::mem::MaybeUninit::<ProcBsdInfo>::zeroed();
        let read = unsafe {
            proc_pidinfo(
                pid,
                PROC_PIDTBSDINFO,
                0,
                info.as_mut_ptr().cast(),
                std::mem::size_of::<ProcBsdInfo>() as c_int,
            )
        };
        if read == 0 {
            // The PID may have exited between enumeration and inspection. A
            // failed non-ESRCH query is not safe to present as an empty table.
            let error = std::io::Error::last_os_error();
            if is_process_gone(&error) {
                continue;
            }
            return Err(ProcessError::Inspection(error.to_string()));
        }
        if read as usize != std::mem::size_of::<ProcBsdInfo>() {
            return Err(ProcessError::Inspection(
                "kernel returned a truncated process identity".into(),
            ));
        }
        let info = unsafe { info.assume_init() };
        let command = CStr::from_bytes_until_nul(unsafe {
            std::slice::from_raw_parts(info.command.as_ptr().cast::<u8>(), info.command.len())
        })
        .map_err(|_| ProcessError::Inspection("kernel command identity was not terminated".into()))?
        .to_string_lossy()
        .into_owned();
        processes.push(ProcessIdentity {
            pid: info.pid,
            parent_pid: info.parent_pid,
            process_group_id: info.process_group_id,
            start_identity: format!(
                "macos-start:{}:{}",
                info.start_seconds, info.start_microseconds
            ),
            command,
            quality: ProcessIdentityQuality::KernelBirthToken,
        });
    }
    processes.sort_by_key(|item| item.pid);
    Ok(processes)
}

fn validate(request: &ProcessRequest) -> Result<(), ProcessError> {
    if !request.executable.is_absolute() {
        return Err(ProcessError::Invalid(
            "executable must be an absolute path".into(),
        ));
    }
    if request.timeout.is_zero()
        || request.shutdown_grace.is_zero()
        || request.stdout_limit == 0
        || request.stderr_tail_limit == 0
        || request.stdin.len() > 4 * 1024 * 1024
    {
        return Err(ProcessError::Invalid(
            "limits must be positive and stdin at most 4 MiB".into(),
        ));
    }
    if let Some(cwd) = request.cwd.as_deref()
        && !cwd.is_absolute()
    {
        return Err(ProcessError::Invalid(
            "working directory must be absolute".into(),
        ));
    }
    Ok(())
}

fn read_bounded(mut reader: impl Read, limit: usize) -> std::io::Result<(Vec<u8>, bool)> {
    let mut retained = Vec::with_capacity(limit.min(8192));
    let mut buf = [0_u8; 8192];
    let mut truncated = false;
    loop {
        let read = reader.read(&mut buf)?;
        if read == 0 {
            return Ok((retained, truncated));
        }
        let remaining = limit.saturating_sub(retained.len());
        retained.extend_from_slice(&buf[..read.min(remaining)]);
        truncated |= read > remaining;
    }
}

fn read_tail(mut reader: impl Read, limit: usize) -> std::io::Result<(Vec<u8>, bool)> {
    let mut tail = VecDeque::with_capacity(limit);
    let mut buf = [0_u8; 8192];
    let mut truncated = false;
    loop {
        let read = reader.read(&mut buf)?;
        if read == 0 {
            return Ok((tail.into_iter().collect(), truncated));
        }
        for byte in &buf[..read] {
            if tail.len() == limit {
                tail.pop_front();
                truncated = true;
            }
            tail.push_back(*byte);
        }
    }
}

fn wait_until(
    child: &mut std::process::Child,
    grace: Duration,
) -> Result<Option<ExitStatus>, ProcessError> {
    let deadline = Instant::now() + grace;
    loop {
        if let Some(status) = child.try_wait().map_err(ProcessError::Io)? {
            return Ok(Some(status));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(unix)]
fn signal_group(pid: u32, signal: &str) {
    let _ = Command::new("/bin/kill")
        .arg(format!("-{signal}"))
        .arg("--")
        .arg(format!("-{pid}"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

#[cfg(not(unix))]
fn signal_group(pid: u32, signal: &str) {
    if signal == "KILL" {
        let _ = std::process::Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .status();
    } else {
        let _ = pid;
    }
}

pub fn resolve_executable(path: &Path, search_path: &[PathBuf]) -> Option<PathBuf> {
    if path.is_absolute() || path.components().count() > 1 {
        return executable(path).then(|| path.canonicalize().ok()).flatten();
    }
    search_path.iter().find_map(|directory| {
        let candidate = directory.join(path);
        executable(&candidate)
            .then(|| candidate.canonicalize().ok())
            .flatten()
    })
}

fn executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path)
            .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        std::fs::metadata(path).is_ok_and(|metadata| metadata.is_file())
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::PathBuf;
    use std::time::Duration;

    use super::{ProcessRequest, resolve_executable, run};
    use std::path::Path;

    fn request(executable: &str, args: &[&str]) -> ProcessRequest {
        ProcessRequest {
            executable: PathBuf::from(executable),
            args: args.iter().map(OsString::from).collect(),
            stdin: Vec::new(),
            cwd: None,
            clear_environment: true,
            environment: Default::default(),
            timeout: Duration::from_secs(2),
            shutdown_grace: Duration::from_millis(100),
            stdout_limit: 8,
            stderr_tail_limit: 8,
        }
    }

    #[cfg(unix)]
    #[test]
    fn bounds_output_and_preserves_nonzero_exit() {
        let output = run(request(
            "/bin/sh",
            &["-c", "printf 123456789; printf abcdefghi >&2; exit 7"],
        ))
        .unwrap();
        assert_eq!(output.stdout, b"12345678");
        assert!(output.stdout_truncated);
        assert_eq!(output.stderr_tail, b"bcdefghi");
        assert!(output.stderr_truncated);
        assert_eq!(output.status.unwrap().code(), Some(7));
    }

    #[cfg(unix)]
    #[test]
    fn times_out_and_reaps_the_owned_process_group() {
        let mut request = request("/bin/sh", &["-c", "sleep 5"]);
        request.timeout = Duration::from_millis(30);
        let output = run(request).unwrap();
        assert!(output.timed_out);
        assert!(output.cleanup_confirmed);
        assert!(output.status.is_some());
    }

    #[cfg(unix)]
    #[test]
    fn returns_bounded_unknown_when_a_setsid_child_keeps_inherited_pipes_open() {
        use std::time::Instant;

        let temp = tempfile::tempdir().unwrap();
        let ready = temp.path().join("child-ready");
        let release = temp.path().join("release-child");
        let python = resolve_executable(
            Path::new("python3"),
            &std::env::split_paths(&std::env::var_os("PATH").unwrap()).collect::<Vec<_>>(),
        )
        .unwrap();
        let program = format!(
            "import os,time,pathlib; pid=os.fork();\nif pid: raise SystemExit(0)\nos.setsid(); pathlib.Path({:?}).touch();\nwhile not pathlib.Path({:?}).exists(): time.sleep(0.01)",
            ready, release
        );
        let mut req = request(python.to_str().unwrap(), &["-c", &program]);
        req.executable = python;
        req.timeout = Duration::from_secs(2);
        req.shutdown_grace = Duration::from_millis(100);
        let started = Instant::now();
        let result = run(req);
        assert!(matches!(
            result,
            Err(super::ProcessError::CleanupUnconfirmed)
        ));
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(ready.exists());
        std::fs::write(&release, b"release").unwrap();
    }

    #[test]
    fn process_identity_matching_requires_full_fingerprint_and_verified_group_leader() {
        use super::{
            ProcessIdentity, ProcessIdentityQuality, ProcessSignal, capture_process_tree,
            matching_processes, signal_process_group_if_observed,
        };

        let identity = |pid, parent_pid, process_group_id, start_identity: &str, command: &str| {
            ProcessIdentity {
                pid,
                parent_pid,
                process_group_id,
                start_identity: start_identity.into(),
                command: command.into(),
                quality: ProcessIdentityQuality::KernelBirthToken,
            }
        };
        let leader = identity(10, 1, 10, "start-10", "worker");
        let child = identity(20, 10, 10, "start-20", "tool");
        let reparented = identity(30, 1, 10, "start-30", "shell");
        let unrelated = identity(40, 1, 40, "start-40", "other");
        let captured = capture_process_tree(
            10,
            &[leader.clone(), child.clone(), reparented.clone(), unrelated],
        );
        assert_eq!(
            captured,
            vec![leader.clone(), child.clone(), reparented.clone()]
        );
        assert_eq!(
            matching_processes(&captured, &[leader.clone(), child.clone()]),
            vec![leader.clone(), child.clone()]
        );
        assert!(
            matching_processes(&captured, &[identity(20, 10, 10, "reused", "tool")]).is_empty()
        );
        assert!(
            !signal_process_group_if_observed(10, &captured, &[], ProcessSignal::Interrupt)
                .unwrap()
        );
        assert!(
            signal_process_group_if_observed(
                10,
                std::slice::from_ref(&reparented),
                std::slice::from_ref(&reparented),
                ProcessSignal::Terminate
            )
            .is_err()
        );
    }

    #[test]
    fn live_process_table_reports_a_kernel_birth_token_for_this_process() {
        let current_pid = std::process::id();
        let table = super::inspect_process_table().unwrap();
        let current = table
            .iter()
            .find(|process| process.pid == current_pid)
            .unwrap();
        assert_eq!(
            current.quality,
            super::ProcessIdentityQuality::KernelBirthToken
        );
        assert!(!current.start_identity.is_empty());
        assert!(!current.command.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_stat_parser_handles_parentheses_in_command_names() {
        let stat = "12 (tool ) name) S 1 12 12 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 7654 0";
        let (command, fields) = super::parse_linux_stat(stat).unwrap();
        assert_eq!(command, "tool ) name");
        assert_eq!(super::parse_field::<u32>(&fields, 19).unwrap(), 7654);
    }

    #[cfg(unix)]
    #[test]
    fn executable_resolution_accepts_paths_with_spaces() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("path with spaces");
        std::fs::create_dir(&dir).unwrap();
        let bin = dir.join("agent");
        std::fs::write(&bin, "#!/bin/sh\nexit 0\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            resolve_executable(Path::new("agent"), &[dir]),
            Some(bin.canonicalize().unwrap())
        );
    }
}
