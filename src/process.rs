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

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessIdentityQuality {
    KernelBirthToken,
    SecondPrecision,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
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

pub fn run(request: ProcessRequest) -> Result<ProcessOutput, ProcessError> {
    run_with_started_identity(request, |_| {})
}

/// Run a child while reporting its kernel identity before waiting for completion.
/// The callback runs on the calling thread and must return promptly.
pub fn run_with_started_identity(
    mut request: ProcessRequest,
    on_started: impl FnOnce(ProcessIdentity),
) -> Result<ProcessOutput, ProcessError> {
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
    let root_pid = child.id();
    let mut observed_processes = Vec::new();
    if collect_tree(root_pid, &mut observed_processes).is_err() {
        let cleaned = cleanup_child_tree(
            &mut child,
            root_pid,
            &mut observed_processes,
            request.shutdown_grace,
        );
        return Err(if cleaned {
            ProcessError::Inspection("cannot record the started process identity".into())
        } else {
            ProcessError::CleanupUnconfirmed
        });
    }
    let Some(root_identity) = observed_processes
        .iter()
        .find(|identity| identity.pid == root_pid)
        .cloned()
    else {
        let cleaned = cleanup_child_tree(
            &mut child,
            root_pid,
            &mut observed_processes,
            request.shutdown_grace,
        );
        return Err(if cleaned {
            ProcessError::Inspection("started process is absent from the process table".into())
        } else {
            ProcessError::CleanupUnconfirmed
        });
    };
    on_started(root_identity);
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
    let mut observation_failed = false;
    let mut next_process_scan = Instant::now() + Duration::from_millis(20);
    let mut status = loop {
        if Instant::now() >= next_process_scan {
            observation_failed |= collect_tree(root_pid, &mut observed_processes).is_err();
            next_process_scan = Instant::now() + Duration::from_millis(20);
        }
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {}
            Err(error) => {
                let cleaned = cleanup_child_tree(
                    &mut child,
                    root_pid,
                    &mut observed_processes,
                    request.shutdown_grace,
                );
                return Err(if cleaned && !observation_failed {
                    ProcessError::Io(error)
                } else {
                    ProcessError::CleanupUnconfirmed
                });
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
        cleanup_confirmed = cleanup_child_tree(
            &mut child,
            root_pid,
            &mut observed_processes,
            request.shutdown_grace,
        ) && !observation_failed;
        status = child.try_wait().ok().flatten();
    } else if status.is_some() {
        // A command can exit after forking helpers that close all three
        // standard streams. EOF alone does not prove those helpers stopped.
        observation_failed |= collect_tree(root_pid, &mut observed_processes).is_err();
        cleanup_confirmed = !observation_failed
            && observed_processes.iter().any(|item| item.pid == root_pid)
            && cleanup_survivors(root_pid, &observed_processes, request.shutdown_grace);
    }
    let io_deadline = Instant::now() + request.shutdown_grace;
    let input_done = input_rx.recv_timeout(remaining(io_deadline)).is_ok();
    let mut stdout_result = out_rx.recv_timeout(remaining(io_deadline));
    let mut stderr_result = err_rx.recv_timeout(remaining(io_deadline));
    cleanup_confirmed &= input_done && stdout_result.is_ok() && stderr_result.is_ok();
    if !cleanup_confirmed {
        cleanup_confirmed =
            cleanup_survivors(root_pid, &observed_processes, request.shutdown_grace);
        let retry_deadline = Instant::now() + request.shutdown_grace;
        if stdout_result.is_err() {
            stdout_result = out_rx.recv_timeout(remaining(retry_deadline));
        }
        if stderr_result.is_err() {
            stderr_result = err_rx.recv_timeout(remaining(retry_deadline));
        }
    }
    let (stdout, stdout_truncated) = match stdout_result {
        Ok(Ok(output)) => output,
        Ok(Err(error)) => {
            return Err(if cleanup_confirmed {
                ProcessError::Io(error)
            } else {
                ProcessError::CleanupUnconfirmed
            });
        }
        Err(_) => return Err(ProcessError::CleanupUnconfirmed),
    };
    let (stderr_tail, stderr_truncated) = match stderr_result {
        Ok(Ok(output)) => output,
        Ok(Err(error)) => {
            return Err(if cleanup_confirmed {
                ProcessError::Io(error)
            } else {
                ProcessError::CleanupUnconfirmed
            });
        }
        Err(_) => return Err(ProcessError::CleanupUnconfirmed),
    };
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
        .filter(|candidate| {
            observed
                .iter()
                .any(|known| same_process_identity(known, candidate))
        })
        .cloned()
        .collect()
}

fn same_process_identity(left: &ProcessIdentity, right: &ProcessIdentity) -> bool {
    // Parent PID, process group, and command can change after fork, setpgid,
    // exec, or reparenting. PID plus kernel birth token remains the stable
    // identity across those transitions.
    left.pid == right.pid
        && left.start_identity == right.start_identity
        && left.quality == right.quality
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

/// Signal one process only when its complete kernel identity still matches.
/// This is used after the original group leader has exited; callers must never
/// infer process identity from a PID alone.
pub fn signal_process_if_observed(
    observed: &ProcessIdentity,
    current: &[ProcessIdentity],
    signal: ProcessSignal,
) -> Result<bool, ProcessError> {
    let Some(matched) = matching_processes(std::slice::from_ref(observed), current)
        .into_iter()
        .next()
    else {
        return Ok(false);
    };
    if matched.quality != ProcessIdentityQuality::KernelBirthToken || matched.pid > i32::MAX as u32
    {
        return Err(ProcessError::Inspection(
            "kernel birth-token identity is required for process signalling".into(),
        ));
    }
    #[cfg(unix)]
    {
        let signal_number = match signal {
            ProcessSignal::Interrupt => 2,
            ProcessSignal::Terminate => 15,
            ProcessSignal::Kill => 9,
        };
        let result = unsafe { kill_process_group(matched.pid as i32, signal_number) };
        if result == 0 {
            Ok(true)
        } else if is_process_gone(&std::io::Error::last_os_error()) {
            Ok(false)
        } else {
            Err(ProcessError::Inspection(
                "operating system rejected the verified process signal".into(),
            ))
        }
    }
    #[cfg(not(unix))]
    {
        let _ = signal;
        Err(ProcessError::Inspection(
            "process signalling is unsupported on this platform".into(),
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
            parent_pid: parse_field(&fields, 1)?,
            process_group_id: parse_field(&fields, 2)?,
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

fn collect_tree(
    root_pid: u32,
    observed: &mut Vec<ProcessIdentity>,
) -> Result<Vec<ProcessIdentity>, ProcessError> {
    let current = inspect_process_table()?;
    if let Some(root) = current.iter().find(|item| item.pid == root_pid) {
        if root.process_group_id != root_pid
            || root.quality != ProcessIdentityQuality::KernelBirthToken
            || observed
                .iter()
                .find(|item| item.pid == root_pid)
                .is_some_and(|known| !same_process_identity(known, root))
        {
            return Err(ProcessError::Inspection(
                "root process identity changed during observation".into(),
            ));
        }
        for item in capture_process_tree(root_pid, &current) {
            if !observed.iter().any(|known| known == &item) {
                observed.push(item);
            }
        }
    } else {
        for member in current
            .iter()
            .filter(|item| item.process_group_id == root_pid)
        {
            if !observed.iter().any(|known| known == member) {
                return Err(ProcessError::Inspection(
                    "unobserved process appeared after its group leader exited".into(),
                ));
            }
        }
    }
    Ok(current)
}

fn wait_child_and_collect(
    child: &mut std::process::Child,
    root_pid: u32,
    observed: &mut Vec<ProcessIdentity>,
    grace: Duration,
) -> (Option<ExitStatus>, bool) {
    let deadline = Instant::now() + grace;
    let mut complete = true;
    loop {
        if collect_tree(root_pid, observed).is_err() {
            complete = false;
        }
        match child.try_wait() {
            Ok(Some(status)) => return (Some(status), complete),
            Ok(None) => {}
            Err(_) => return (None, false),
        }
        if Instant::now() >= deadline {
            return (None, complete);
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn cleanup_survivors(root_pid: u32, observed: &[ProcessIdentity], grace: Duration) -> bool {
    let deadline = Instant::now() + grace;
    loop {
        let Ok(current) = inspect_process_table() else {
            return false;
        };
        let survivors = matching_processes(observed, &current);
        if current.iter().any(|member| {
            member.process_group_id == root_pid
                && !observed
                    .iter()
                    .any(|known| same_process_identity(known, member))
        }) {
            return false;
        }
        if survivors.is_empty() {
            return true;
        }
        for survivor in &survivors {
            if survivor.pid == root_pid {
                return false;
            }
            if signal_process_if_observed(survivor, &current, ProcessSignal::Kill).is_err() {
                return false;
            }
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn cleanup_child_tree(
    child: &mut std::process::Child,
    root_pid: u32,
    observed: &mut Vec<ProcessIdentity>,
    grace: Duration,
) -> bool {
    let Ok(current) = collect_tree(root_pid, observed) else {
        let _ = child.kill();
        let _ = wait_until(child, grace);
        return false;
    };
    let Some(root) = observed.iter().find(|item| item.pid == root_pid) else {
        let _ = child.kill();
        let _ = wait_until(child, grace);
        return false;
    };
    if signal_process_group_if_observed(
        root_pid,
        std::slice::from_ref(root),
        &current,
        ProcessSignal::Terminate,
    )
    .is_err()
    {
        let _ = child.kill();
        let (status, _) = wait_child_and_collect(child, root_pid, observed, grace);
        let _ = status;
        return false;
    }
    let (mut status, mut observation_complete) =
        wait_child_and_collect(child, root_pid, observed, grace);
    if status.is_none() {
        let current = match collect_tree(root_pid, observed) {
            Ok(current) => current,
            Err(_) => {
                let _ = child.kill();
                let _ = wait_until(child, grace);
                return false;
            }
        };
        if let Some(root) = observed.iter().find(|item| item.pid == root_pid) {
            if signal_process_group_if_observed(
                root_pid,
                std::slice::from_ref(root),
                &current,
                ProcessSignal::Kill,
            )
            .is_err()
            {
                observation_complete = false;
            }
        } else {
            observation_complete = false;
        }
        let waited = wait_child_and_collect(child, root_pid, observed, grace);
        status = waited.0;
        observation_complete &= waited.1;
    }
    let survivors_stopped = cleanup_survivors(root_pid, observed, grace);
    status.is_some() && observation_complete && survivors_stopped
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
    fn timeout_does_not_report_success_while_an_observed_child_survives() {
        use super::{
            ProcessIdentity, ProcessSignal, inspect_process_table, matching_processes,
            signal_process_if_observed,
        };
        use std::sync::{Arc, Mutex};
        use std::thread;
        use std::time::Instant;

        struct ChildGuard {
            release: PathBuf,
            identity: Arc<Mutex<Option<ProcessIdentity>>>,
        }

        impl Drop for ChildGuard {
            fn drop(&mut self) {
                let _ = std::fs::write(&self.release, b"release");
                let Some(identity) = self.identity.lock().ok().and_then(|item| item.clone()) else {
                    return;
                };
                let deadline = Instant::now() + Duration::from_millis(500);
                while Instant::now() < deadline {
                    let Ok(current) = inspect_process_table() else {
                        thread::sleep(Duration::from_millis(10));
                        continue;
                    };
                    if matching_processes(std::slice::from_ref(&identity), &current).is_empty() {
                        return;
                    }
                    let _ = signal_process_if_observed(&identity, &current, ProcessSignal::Kill);
                    thread::sleep(Duration::from_millis(10));
                }
            }
        }

        let temp = tempfile::tempdir().unwrap();
        let ready = temp.path().join("child-ready");
        let start = temp.path().join("allow-parent-exit");
        let release = temp.path().join("release-child");
        let observed = Arc::new(Mutex::new(None));
        let _guard = ChildGuard {
            release: release.clone(),
            identity: Arc::clone(&observed),
        };
        let python = resolve_executable(
            Path::new("python3"),
            &std::env::split_paths(&std::env::var_os("PATH").unwrap()).collect::<Vec<_>>(),
        )
        .unwrap();
        let program = format!(
            "import os,signal,time,pathlib; ready=pathlib.Path({:?}); start=pathlib.Path({:?}); release=pathlib.Path({:?}); pid=os.fork();\nif pid:\n deadline=time.monotonic()+3\n while not start.exists() and time.monotonic()<deadline: time.sleep(0.005)\n time.sleep(8)\nelse:\n signal.signal(signal.SIGTERM, signal.SIG_IGN)\n [os.close(fd) for fd in (0,1,2)]\n ready.write_text(str(os.getpid()))\n deadline=time.monotonic()+3\n while not start.exists() and time.monotonic()<deadline: time.sleep(0.005)\n while not release.exists() and time.monotonic()<deadline+5: time.sleep(0.01)",
            ready, start, release
        );
        let mut req = request(python.to_str().unwrap(), &["-c", &program]);
        req.executable = python;
        // Leave enough time for a loaded CI host to schedule the observer and
        // capture the child's kernel start identity before timeout cleanup.
        req.timeout = Duration::from_secs(1);
        req.shutdown_grace = Duration::from_secs(1);
        let child_identity = Arc::clone(&observed);
        let marker_start = start.clone();
        let marker_ready = ready.clone();
        let observer = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline {
                if let Ok(pid_text) = std::fs::read_to_string(&marker_ready)
                    && let Ok(pid) = pid_text.parse::<u32>()
                    && let Ok(table) = inspect_process_table()
                    && let Some(identity) = table.into_iter().find(|item| item.pid == pid)
                {
                    if let Ok(mut slot) = child_identity.lock() {
                        *slot = Some(identity);
                    }
                    let _ = std::fs::write(&marker_start, b"start");
                    return;
                }
                thread::sleep(Duration::from_millis(5));
            }
        });
        let output = run(req);
        observer.join().unwrap();
        let identity = observed.lock().unwrap().clone();
        assert!(
            identity.is_some(),
            "fixture must capture PID and start identity before allowing the parent to exit"
        );
        let identity = identity.unwrap();
        assert!(
            output.is_ok(),
            "verified child should be killed and cleanup confirmed: {output:?}"
        );
        let output = output.unwrap();
        assert!(output.timed_out);
        assert!(output.cleanup_confirmed);
        assert!(
            matching_processes(
                std::slice::from_ref(&identity),
                &inspect_process_table().unwrap()
            )
            .is_empty(),
            "the observed child must be gone before cleanup is reported"
        );
    }

    #[cfg(unix)]
    #[test]
    fn setsid_child_with_inherited_pipes_is_bounded_and_not_misreported() {
        use super::{
            ProcessIdentity, ProcessSignal, inspect_process_table, matching_processes,
            signal_process_group_if_observed,
        };
        use std::thread;
        use std::time::Instant;

        struct EscapedChildGuard {
            release: PathBuf,
            observed: Option<ProcessIdentity>,
        }

        impl EscapedChildGuard {
            fn release_and_reap(&mut self) -> bool {
                // The fixture also exits itself after five seconds. This marker
                // releases it immediately on success and during panic cleanup.
                let _ = std::fs::write(&self.release, b"release");
                let Some(observed) = self.observed.as_ref() else {
                    return true;
                };
                let deadline = Instant::now() + Duration::from_millis(500);
                let mut sent_kill = false;
                while Instant::now() < deadline {
                    let Ok(current) = inspect_process_table() else {
                        thread::sleep(Duration::from_millis(10));
                        continue;
                    };
                    let still_matches =
                        !matching_processes(std::slice::from_ref(observed), &current).is_empty();
                    if !still_matches {
                        return true;
                    }
                    let signal = if sent_kill {
                        ProcessSignal::Kill
                    } else {
                        ProcessSignal::Terminate
                    };
                    let signalled = signal_process_group_if_observed(
                        observed.process_group_id,
                        std::slice::from_ref(observed),
                        &current,
                        signal,
                    )
                    .unwrap_or(false);
                    sent_kill |= !signalled || signal == ProcessSignal::Terminate;
                    thread::sleep(Duration::from_millis(20));
                }
                false
            }
        }

        impl Drop for EscapedChildGuard {
            fn drop(&mut self) {
                let _ = self.release_and_reap();
            }
        }

        let temp = tempfile::tempdir().unwrap();
        let ready = temp.path().join("child-ready");
        let release = temp.path().join("release-child");
        let mut child_guard = EscapedChildGuard {
            release: release.clone(),
            observed: None,
        };
        let python = resolve_executable(
            Path::new("python3"),
            &std::env::split_paths(&std::env::var_os("PATH").unwrap()).collect::<Vec<_>>(),
        )
        .unwrap();
        let program = format!(
            "import os,time,pathlib; ready=pathlib.Path({:?}); release=pathlib.Path({:?}); pid=os.fork();\nif pid:\n deadline=time.monotonic()+3\n while not ready.exists() and time.monotonic()<deadline: time.sleep(0.005)\n time.sleep(0.25)\n raise SystemExit(0 if ready.exists() else 2)\nos.setsid(); ready.write_text(str(os.getpid())); deadline=time.monotonic()+5\nwhile not release.exists() and time.monotonic()<deadline: time.sleep(0.01)",
            ready, release,
        );
        let mut req = request(python.to_str().unwrap(), &["-c", &program]);
        req.executable = python;
        req.timeout = Duration::from_secs(2);
        req.shutdown_grace = Duration::from_millis(100);
        let started = Instant::now();
        let result = run(req);
        let ready_pid = std::fs::read_to_string(&ready)
            .expect("child startup barrier must publish its PID")
            .parse::<u32>()
            .unwrap();
        let process_table = inspect_process_table().unwrap();
        child_guard.observed = process_table
            .iter()
            .find(|process| process.pid == ready_pid)
            .cloned();
        if let Some(observed) = child_guard.observed.as_ref() {
            assert_eq!(observed.process_group_id, ready_pid);
            assert!(!observed.start_identity.is_empty());
            assert!(observed.quality == super::ProcessIdentityQuality::KernelBirthToken);
        }
        match &result {
            Err(super::ProcessError::CleanupUnconfirmed) => {}
            Ok(output) if output.cleanup_confirmed => {
                assert!(
                    child_guard.observed.is_none(),
                    "a surviving escaped process cannot be reported as cleaned"
                );
            }
            _ => panic!("unexpected process result: {result:?}"),
        }
        assert!(started.elapsed() < Duration::from_secs(4));
        assert!(ready.exists());
        assert!(
            child_guard.release_and_reap(),
            "escaped fixture must be reaped"
        );
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
        let reparented_after_term = identity(30, 1, 10, "start-30", "renamed-shell");
        assert_eq!(
            matching_processes(
                std::slice::from_ref(&reparented),
                std::slice::from_ref(&reparented_after_term)
            ),
            vec![reparented_after_term]
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
        let mut fields = vec!["0"; 22];
        fields[0] = "S";
        fields[1] = "1";
        fields[2] = "12";
        fields[3] = "12";
        fields[19] = "7654";
        let stat = format!("12 (tool ) name) {}", fields.join(" "));
        let (command, fields) = super::parse_linux_stat(&stat).unwrap();
        assert_eq!(command, "tool ) name");
        assert_eq!(super::parse_field::<u32>(&fields, 1).unwrap(), 1);
        assert_eq!(super::parse_field::<u32>(&fields, 2).unwrap(), 12);
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
