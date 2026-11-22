//! Execution of declared verification commands.

use std::{
    collections::VecDeque,
    io::Read,
    path::Path,
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};

#[cfg(unix)]
use std::os::unix::process::CommandExt;

use crate::playbook::CheckSpec;

const OUTPUT_LIMIT: usize = 4 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(20);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckResult {
    pub passed: bool,
    pub timed_out: bool,
    pub exit_code: Option<i32>,
    pub output_tail: String,
}

/// Executes a check directly (without a shell), from `cwd`, and retains the
/// last 4 KiB emitted to either output stream. A check-specific timeout takes
/// precedence over `default_timeout`.
pub fn execute(spec: &CheckSpec, cwd: &Path, default_timeout: Duration) -> Result<CheckResult> {
    let Some(program) = spec.argv.first().filter(|arg| !arg.trim().is_empty()) else {
        bail!("verification check {:?} has no executable", spec.name);
    };
    let timeout = spec
        .timeout_minutes
        .map(|minutes| Duration::from_secs(u64::from(minutes) * 60))
        .unwrap_or(default_timeout);
    if timeout.is_zero() {
        bail!("verification check {:?} has a zero timeout", spec.name);
    }

    let mut command = Command::new(program);
    command
        .args(&spec.argv[1..])
        .current_dir(cwd)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    command.process_group(0);
    let mut child = command.spawn().with_context(|| {
        format!(
            "failed to start verification check {:?} ({program:?})",
            spec.name
        )
    })?;

    let output = Arc::new(Mutex::new(VecDeque::with_capacity(OUTPUT_LIMIT)));
    let stdout = child
        .stdout
        .take()
        .context("verification stdout was not captured")?;
    let stderr = child
        .stderr
        .take()
        .context("verification stderr was not captured")?;
    let stdout_reader = drain(stdout, Arc::clone(&output));
    let stderr_reader = drain(stderr, Arc::clone(&output));

    let started = Instant::now();
    let (status, mut timed_out) = loop {
        if let Some(status) = child
            .try_wait()
            .context("failed while waiting for verification check")?
        {
            break (status, false);
        }
        if started.elapsed() >= timeout {
            #[cfg(unix)]
            kill_process_group(child.id())?;
            #[cfg(not(unix))]
            child
                .kill()
                .context("failed to stop timed-out verification check")?;
            break (
                child
                    .wait()
                    .context("failed to reap timed-out verification check")?,
                true,
            );
        }
        thread::sleep(POLL_INTERVAL);
    };

    // A command can exit while a background descendant still holds a captured
    // pipe open. Include draining those pipes in the same timeout budget.
    while !timed_out && (!stdout_reader.is_finished() || !stderr_reader.is_finished()) {
        if started.elapsed() >= timeout {
            #[cfg(unix)]
            kill_process_group(child.id())?;
            timed_out = true;
            break;
        }
        thread::sleep(POLL_INTERVAL);
    }

    // Each reader drains its pipe concurrently with the child, preventing a
    // full pipe from blocking the process. Join only after the process exits.
    if stdout_reader.is_finished() {
        stdout_reader
            .join()
            .map_err(|_| anyhow::anyhow!("verification stdout reader panicked"))??;
    } else {
        // On platforms without process-group termination, a descendant may
        // keep the pipe open. Detach its drain rather than blocking forever.
        drop(stdout_reader);
    }
    if stderr_reader.is_finished() {
        stderr_reader
            .join()
            .map_err(|_| anyhow::anyhow!("verification stderr reader panicked"))??;
    } else {
        drop(stderr_reader);
    }
    let bytes = output
        .lock()
        .map_err(|_| anyhow::anyhow!("verification output buffer poisoned"))?;
    let output_tail =
        String::from_utf8_lossy(&bytes.iter().copied().collect::<Vec<_>>()).into_owned();
    let exit_code = status.code();

    Ok(CheckResult {
        passed: !timed_out && status.success(),
        timed_out,
        exit_code,
        output_tail,
    })
}

/// Kills the check's process group so descendants cannot keep captured pipes
/// open and hold up completion after the check times out.
#[cfg(unix)]
fn kill_process_group(pid: u32) -> Result<()> {
    // `CommandExt::process_group(0)` makes the child its own process-group
    // leader, so its pid is also the group id. A direct FFI call avoids adding
    // a runtime dependency solely for this one Unix syscall.
    unsafe extern "C" {
        fn kill(pid: i32, signal: i32) -> i32;
    }
    const SIGKILL: i32 = 9;
    // SAFETY: `pid` is the live child process id returned by std::process; a
    // negative id targets only its isolated process group.
    let result = unsafe { kill(-(pid as i32), SIGKILL) };
    if result == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    // A process may exit between try_wait and the group kill. That is already
    // the desired outcome; otherwise surface the OS error.
    if error.raw_os_error() == Some(3) {
        return Ok(());
    }
    Err(error).context("failed to stop timed-out verification process group")
}

fn drain<R: Read + Send + 'static>(
    mut reader: R,
    output: Arc<Mutex<VecDeque<u8>>>,
) -> thread::JoinHandle<Result<()>> {
    thread::spawn(move || {
        let mut chunk = [0; 1024];
        loop {
            let count = reader
                .read(&mut chunk)
                .context("failed to read verification output")?;
            if count == 0 {
                return Ok(());
            }
            let mut tail = output
                .lock()
                .map_err(|_| anyhow::anyhow!("verification output buffer poisoned"))?;
            for byte in &chunk[..count] {
                if tail.len() == OUTPUT_LIMIT {
                    tail.pop_front();
                }
                tail.push_back(*byte);
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(argv: Vec<String>, timeout_minutes: Option<u32>) -> CheckSpec {
        CheckSpec {
            name: "test".into(),
            argv,
            timeout_minutes,
        }
    }

    #[cfg(unix)]
    fn command(script: &str) -> Vec<String> {
        vec!["sh".into(), "-c".into(), script.into()]
    }

    #[cfg(windows)]
    fn command(script: &str) -> Vec<String> {
        vec!["cmd".into(), "/C".into(), script.into()]
    }

    #[test]
    fn reports_success_and_captures_both_streams() {
        let result = execute(
            &check(command("echo out; echo err >&2"), None),
            Path::new("."),
            Duration::from_secs(2),
        )
        .unwrap();
        assert!(result.passed);
        assert_eq!(result.exit_code, Some(0));
        assert!(result.output_tail.contains("out"));
        assert!(result.output_tail.contains("err"));
    }

    #[test]
    fn reports_nonzero_exit_as_failure() {
        let result = execute(
            &check(command("echo failed; exit 7"), None),
            Path::new("."),
            Duration::from_secs(2),
        )
        .unwrap();
        assert!(!result.passed);
        assert_eq!(result.exit_code, Some(7));
        assert!(result.output_tail.contains("failed"));
    }

    #[cfg(unix)]
    #[test]
    fn kills_a_check_after_the_timeout() {
        let spec = check(command("exec sleep 5"), None);
        let start = Instant::now();
        let result = execute(&spec, Path::new("."), Duration::from_millis(60)).unwrap();
        assert!(!result.passed);
        assert!(result.timed_out);
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[cfg(unix)]
    #[test]
    fn timeout_kills_descendants_holding_captured_pipes() {
        let spec = check(command("sleep 30 & wait"), None);
        let start = Instant::now();
        let result = execute(&spec, Path::new("."), Duration::from_millis(80)).unwrap();
        assert!(!result.passed);
        assert!(result.timed_out);
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[cfg(unix)]
    #[test]
    fn timeout_covers_descendants_that_keep_pipes_open_after_parent_exit() {
        let spec = check(command("sleep 30 &"), None);
        let start = Instant::now();
        let result = execute(&spec, Path::new("."), Duration::from_millis(80)).unwrap();
        assert!(!result.passed);
        assert!(result.timed_out);
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn keeps_only_the_last_four_kib_of_output() {
        let result = execute(
            &check(command("yes x | head -c 10000"), None),
            Path::new("."),
            Duration::from_secs(2),
        )
        .unwrap();
        assert!(result.passed);
        assert_eq!(result.output_tail.len(), OUTPUT_LIMIT);
        assert!(
            result
                .output_tail
                .bytes()
                .all(|byte| byte == b'x' || byte == b'\n')
        );
    }
}
