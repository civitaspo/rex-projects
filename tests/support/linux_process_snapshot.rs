use std::io::{self, Read};
use std::path::Path;

const MAX_THREADS: usize = 8;
const MAX_TASK_ENTRIES: usize = 128;
const MAX_CHILDREN: usize = 4;
const MAX_FILE_BYTES: u64 = 1024;

struct ProcStat {
    state: String,
    parent_pid: u32,
    start_ticks: u64,
}

fn read_bounded(path: &Path, limit: u64) -> Result<String, &'static str> {
    let file = std::fs::File::open(path).map_err(|error| match error.kind() {
        io::ErrorKind::PermissionDenied => "denied",
        io::ErrorKind::NotFound => "gone",
        _ => "unavailable",
    })?;
    let mut text = String::new();
    file.take(limit)
        .read_to_string(&mut text)
        .map_err(|_| "unavailable")?;
    Ok(text)
}

fn proc_stat(path: &Path) -> Result<ProcStat, &'static str> {
    let value = read_bounded(path, MAX_FILE_BYTES)?;
    let fields = value
        .rfind(')')
        .and_then(|end| value.get(end + 1..))
        .ok_or("invalid")?
        .split_whitespace()
        .collect::<Vec<_>>();
    Ok(ProcStat {
        state: fields.first().ok_or("invalid")?.to_string(),
        parent_pid: fields
            .get(1)
            .ok_or("invalid")?
            .parse()
            .map_err(|_| "invalid")?,
        start_ticks: fields
            .get(19)
            .ok_or("invalid")?
            .parse()
            .map_err(|_| "invalid")?,
    })
}

fn token(value: &str, limit: usize) -> String {
    value
        .trim()
        .chars()
        .take(limit)
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '<' | '>' | '.')
            {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn thread_snapshot(proc_root: &Path, pid: u32, tid: u32, role: &str) -> String {
    let thread_dir = proc_root
        .join(pid.to_string())
        .join("task")
        .join(tid.to_string());
    let state = proc_stat(&thread_dir.join("stat"))
        .map(|value| token(&value.state, 8))
        .unwrap_or_else(|error| error.into());
    let wchan = read_bounded(&thread_dir.join("wchan"), 128)
        .map(|value| token(&value, 80))
        .unwrap_or_else(|error| error.into());
    let syscall = read_bounded(&thread_dir.join("syscall"), 128)
        .map(|value| {
            value
                .split_whitespace()
                .next()
                .map(|number| token(number, 24))
                .filter(|number| !number.is_empty())
                .unwrap_or_else(|| "unavailable".into())
        })
        .unwrap_or_else(|error| error.into());
    format!("tid={tid},role={role},state={state},wchan={wchan},syscall={syscall}")
}

pub fn snapshot_at_with_thread_limit(
    proc_root: &Path,
    pid: u32,
    expected_start_identity: Option<&str>,
    expected_parent_pid: Option<u32>,
    include_children: bool,
    thread_limit: usize,
) -> String {
    let thread_limit = thread_limit.min(MAX_THREADS);
    let process_dir = proc_root.join(pid.to_string());
    let process = match proc_stat(&process_dir.join("stat")) {
        Ok(process) => process,
        Err(error) => return format!("pid={pid},stat={error}"),
    };
    let birth = format!("linux-start-ticks:{}", process.start_ticks);
    if expected_start_identity.is_some_and(|expected| expected != birth)
        || expected_parent_pid.is_some_and(|expected| expected != process.parent_pid)
    {
        return format!("pid={pid},identity_changed=true");
    }

    let reserved_child_threads = usize::from(include_children && thread_limit > 0);
    let process_thread_limit = thread_limit.saturating_sub(reserved_child_threads);
    let task_dir = process_dir.join("task");
    let entries = match std::fs::read_dir(&task_dir) {
        Ok(entries) => entries,
        Err(error) => {
            let reason = match error.kind() {
                io::ErrorKind::PermissionDenied => "denied",
                io::ErrorKind::NotFound => "gone",
                _ => "unavailable",
            };
            return format!(
                "pid={pid},ppid={},start_ticks={},threads={reason}",
                process.parent_pid, process.start_ticks
            );
        }
    };
    let mut tids = Vec::new();
    let mut task_scan_truncated = false;
    for (entries_seen, entry) in entries.take(MAX_TASK_ENTRIES + 1).enumerate() {
        if entries_seen == MAX_TASK_ENTRIES {
            task_scan_truncated = true;
            break;
        }
        let Ok(entry) = entry else { continue };
        let name = entry.file_name();
        let Some(tid) = name.to_str().and_then(|value| value.parse::<u32>().ok()) else {
            continue;
        };
        let role = if tid == pid {
            "leader"
        } else if read_bounded(&entry.path().join("comm"), 32)
            .is_ok_and(|comm| comm.starts_with("rex-host-job-"))
        {
            "host_job"
        } else {
            "other"
        };
        tids.push((tid, role));
    }
    if !tids.iter().any(|(tid, _)| *tid == pid) {
        tids.push((pid, "leader"));
    }
    tids.sort_unstable_by_key(|(tid, role)| match *role {
        "host_job" => (0, *tid),
        "leader" => (1, *tid),
        _ => (2, *tid),
    });
    let threads_truncated = task_scan_truncated || tids.len() > process_thread_limit;
    let threads = tids
        .into_iter()
        .take(process_thread_limit)
        .map(|(tid, role)| thread_snapshot(proc_root, pid, tid, role))
        .collect::<Vec<_>>();

    let children = if include_children {
        let path = task_dir.join(pid.to_string()).join("children");
        match read_bounded(&path, 128) {
            Ok(value) => {
                let child_thread_limit =
                    MAX_CHILDREN.min(thread_limit.saturating_sub(threads.len()));
                let mut child_pids = value
                    .split_whitespace()
                    .filter_map(|value| value.parse::<u32>().ok())
                    .take(child_thread_limit + 1)
                    .collect::<Vec<_>>();
                let truncated = child_pids.len() > child_thread_limit || value.len() == 128;
                child_pids.truncate(child_thread_limit);
                let snapshots = child_pids
                    .into_iter()
                    .map(|child_pid| {
                        match proc_stat(&proc_root.join(child_pid.to_string()).join("stat")) {
                            Ok(child) if child.parent_pid == pid => format!(
                                "pid={child_pid},start_ticks={},{}",
                                child.start_ticks,
                                thread_snapshot(proc_root, child_pid, child_pid, "leader")
                            ),
                            Ok(_) => format!("pid={child_pid},identity_changed=true"),
                            Err(error) => format!("pid={child_pid},stat={error}"),
                        }
                    })
                    .collect::<Vec<_>>();
                format!("[{}],truncated={truncated}", snapshots.join(";"))
            }
            Err(error) => error.into(),
        }
    } else {
        "not_requested".into()
    };
    format!(
        "pid={pid},ppid={},state={},start_ticks={},threads=[{}],threads_truncated={threads_truncated},task_scan_truncated={task_scan_truncated},children={children}",
        process.parent_pid,
        token(&process.state, 8),
        process.start_ticks,
        threads.join(";")
    )
}

#[allow(dead_code)]
pub fn snapshot(
    pid: u32,
    expected_start_identity: Option<&str>,
    expected_parent_pid: Option<u32>,
    include_children: bool,
) -> String {
    snapshot_with_thread_limit(
        pid,
        expected_start_identity,
        expected_parent_pid,
        include_children,
        MAX_THREADS,
    )
}

#[allow(dead_code)]
pub fn snapshot_with_thread_limit(
    pid: u32,
    expected_start_identity: Option<&str>,
    expected_parent_pid: Option<u32>,
    include_children: bool,
    thread_limit: usize,
) -> String {
    #[cfg(target_os = "linux")]
    {
        snapshot_at_with_thread_limit(
            Path::new("/proc"),
            pid,
            expected_start_identity,
            expected_parent_pid,
            include_children,
            thread_limit,
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (
            pid,
            expected_start_identity,
            expected_parent_pid,
            include_children,
            thread_limit,
        );
        "unsupported_platform".into()
    }
}
