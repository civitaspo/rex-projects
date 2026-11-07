use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::config::HookConfig;
use crate::domain::ids::{Digest, ProjectId, RepositoryId, TicketRunId};
use crate::process::{self, ProcessError, ProcessRequest};
use crate::worktrees::GitOptions;

const DEFAULT_STDOUT_LIMIT: usize = 1024 * 1024;
const STDERR_TAIL_LIMIT: usize = 32 * 1024;
const HOOK_SHUTDOWN_GRACE: Duration = Duration::from_secs(10);
const GIT_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HookReceipt {
    pub schema_version: u32,
    pub hook_id: String,
    pub project_id: ProjectId,
    pub repository_id: RepositoryId,
    pub ticket_run_id: TicketRunId,
    pub head: String,
    pub configuration_digest: Digest,
    pub source_before: Digest,
    pub source_after: Digest,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub cleanup_confirmed: bool,
    pub stdout_digest: Digest,
    pub stdout_bytes: usize,
    pub stdout_truncated: bool,
    pub stderr_tail_digest: Digest,
    pub stderr_bytes: usize,
    pub stderr_truncated: bool,
    pub succeeded: bool,
    pub recorded_at_unix: u64,
}

#[derive(Debug)]
pub enum HookError {
    Invalid(String),
    Io(String),
    Process(String),
    SourceChanged { hook_id: String },
    Failed(Box<HookReceipt>),
}

impl std::fmt::Display for HookError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(message) | Self::Io(message) | Self::Process(message) => {
                f.write_str(message)
            }
            Self::SourceChanged { hook_id } => {
                write!(f, "repository check `{hook_id}` changed its source tree")
            }
            Self::Failed(receipt) => write!(
                f,
                "repository check `{}` failed with exit {:?}",
                receipt.hook_id, receipt.exit_code
            ),
        }
    }
}

impl std::error::Error for HookError {}

pub struct HookRunner {
    git: GitOptions,
    inherited_environment: BTreeMap<OsString, OsString>,
    stdout_limit: usize,
}

pub struct HookRunContext<'a> {
    pub repository_id: &'a RepositoryId,
    pub worktree: &'a Path,
    pub expected_head: &'a str,
    pub project_id: &'a ProjectId,
    pub ticket_run_id: &'a TicketRunId,
    pub configuration_digest: &'a Digest,
    pub state_root: &'a Path,
}

impl HookRunner {
    pub fn new(git: GitOptions, inherited_environment: BTreeMap<OsString, OsString>) -> Self {
        Self {
            git,
            inherited_environment,
            stdout_limit: DEFAULT_STDOUT_LIMIT,
        }
    }

    pub fn with_stdout_limit(mut self, limit: usize) -> Result<Self, HookError> {
        if limit == 0 {
            return Err(HookError::Invalid(
                "hook output limit must be positive".into(),
            ));
        }
        self.stdout_limit = limit;
        Ok(self)
    }

    pub fn run_required(
        &self,
        hooks: &[HookConfig],
        context: HookRunContext<'_>,
    ) -> Result<Vec<HookReceipt>, HookError> {
        if hooks.is_empty() {
            return Ok(Vec::new());
        }
        let HookRunContext {
            repository_id,
            worktree,
            expected_head,
            project_id,
            ticket_run_id,
            configuration_digest,
            state_root,
        } = context;
        let root = state_root.canonicalize().map_err(io_error)?;
        let receipts_root = root
            .join("hook-receipts")
            .join(project_id.as_str())
            .join(ticket_run_id.as_str());
        create_private_directory(&root)?;
        create_private_directory(&root.join("hook-receipts"))?;
        create_private_directory(&root.join("hook-receipts").join(project_id.as_str()))?;
        create_private_directory(&receipts_root)?;
        let repo = worktree.canonicalize().map_err(io_error)?;
        ensure_real_directory(&repo)?;
        let managed_worktrees = root.join("worktrees").canonicalize().map_err(io_error)?;
        if !repo.starts_with(&managed_worktrees) {
            return Err(HookError::Invalid(
                "repository checks may run only inside a managed worktree".into(),
            ));
        }
        let actual_head = self.git_text(&repo, ["rev-parse", "--verify", "HEAD"])?;
        if actual_head.trim() != expected_head {
            return Err(HookError::Invalid(
                "repository hook head differs from the expected revision".into(),
            ));
        }

        let mut receipts = Vec::with_capacity(hooks.len());
        for hook in hooks {
            validate_hook(hook)?;
            let before = self.source_fingerprint(&repo)?;
            let executable = self.resolve_command(&hook.command[0]).ok_or_else(|| {
                HookError::Invalid(format!(
                    "configured repository check `{}` executable is unavailable",
                    hook.id
                ))
            })?;
            let timeout = Duration::from_secs(hook.timeout_seconds);
            if timeout.is_zero() {
                return Err(HookError::Invalid(format!(
                    "repository check `{}` timeout must be positive",
                    hook.id
                )));
            }
            let mut environment = self.inherited_environment.clone();
            environment.retain(|key, _| {
                let key = key.to_string_lossy();
                !key.starts_with("GIT_")
                    && !matches!(
                        key.as_ref(),
                        "REX_PROJECTS_CONTEXT"
                            | "REX_PROJECTS_AGENT"
                            | "REX_PROJECTS_PROJECT_ID"
                            | "REX_PROJECTS_ROLE"
                            | "REX_PROJECTS_RUN_ID"
                            | "REX_PROJECTS_TICKET_RUN_ID"
                    )
            });
            environment.insert("REX_PROJECTS_CONTEXT".into(), "rex_projects_hook".into());
            environment.insert("REX_PROJECTS_AGENT".into(), "1".into());
            environment.insert("REX_PROJECTS_PROJECT_ID".into(), project_id.as_str().into());
            environment.insert("REX_PROJECTS_ROLE".into(), "rex_projects_hook".into());
            environment.insert("REX_PROJECTS_RUN_ID".into(), hook.id.as_str().into());
            environment.insert(
                "REX_PROJECTS_TICKET_RUN_ID".into(),
                ticket_run_id.as_str().into(),
            );
            environment.insert("GIT_TERMINAL_PROMPT".into(), "0".into());
            let output = process::run(ProcessRequest {
                executable,
                args: hook.command[1..].iter().map(OsString::from).collect(),
                stdin: Vec::new(),
                cwd: Some(repo.clone()),
                clear_environment: true,
                environment,
                timeout,
                shutdown_grace: HOOK_SHUTDOWN_GRACE,
                stdout_limit: self.stdout_limit,
                stderr_tail_limit: STDERR_TAIL_LIMIT,
            });
            let output = match output {
                Ok(output) => output,
                Err(_) => {
                    let after_head = self.git_text(&repo, ["rev-parse", "--verify", "HEAD"])?;
                    let after = self.source_fingerprint(&repo)?;
                    let empty_digest = digest_bytes(&[]);
                    let receipt = HookReceipt {
                        schema_version: 1,
                        hook_id: hook.id.clone(),
                        project_id: project_id.clone(),
                        repository_id: repository_id.clone(),
                        ticket_run_id: ticket_run_id.clone(),
                        head: expected_head.to_owned(),
                        configuration_digest: configuration_digest.clone(),
                        source_before: before,
                        source_after: after,
                        exit_code: None,
                        timed_out: false,
                        cleanup_confirmed: false,
                        stdout_digest: empty_digest.clone(),
                        stdout_bytes: 0,
                        stdout_truncated: false,
                        stderr_tail_digest: empty_digest,
                        stderr_bytes: 0,
                        stderr_truncated: false,
                        succeeded: false,
                        recorded_at_unix: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs(),
                    };
                    write_receipt(&receipts_root.join(format!("{}.json", hook.id)), &receipt)?;
                    if after_head.trim() != expected_head
                        || receipt.source_before != receipt.source_after
                    {
                        return Err(HookError::SourceChanged {
                            hook_id: hook.id.clone(),
                        });
                    }
                    return Err(HookError::Failed(Box::new(receipt)));
                }
            };
            let after_head = self.git_text(&repo, ["rev-parse", "--verify", "HEAD"])?;
            let after = self.source_fingerprint(&repo)?;
            let source_changed = before != after;
            let status_code = output.status.and_then(|status| status.code());
            let succeeded = status_code == Some(0)
                && !output.timed_out
                && output.cleanup_confirmed
                && !output.stdout_truncated
                && after_head.trim() == expected_head
                && before == after;
            let receipt = HookReceipt {
                schema_version: 1,
                hook_id: hook.id.clone(),
                project_id: project_id.clone(),
                repository_id: repository_id.clone(),
                ticket_run_id: ticket_run_id.clone(),
                head: expected_head.to_owned(),
                configuration_digest: configuration_digest.clone(),
                source_before: before,
                source_after: after,
                exit_code: status_code,
                timed_out: output.timed_out,
                cleanup_confirmed: output.cleanup_confirmed,
                stdout_digest: digest_bytes(&output.stdout),
                stdout_bytes: output.stdout.len(),
                stdout_truncated: output.stdout_truncated,
                stderr_tail_digest: digest_bytes(&output.stderr_tail),
                stderr_bytes: output.stderr_tail.len(),
                stderr_truncated: output.stderr_truncated,
                succeeded,
                recorded_at_unix: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            };
            write_receipt(&receipts_root.join(format!("{}.json", hook.id)), &receipt)?;
            if after_head.trim() != expected_head || source_changed {
                return Err(HookError::SourceChanged {
                    hook_id: hook.id.clone(),
                });
            }
            if !succeeded {
                return Err(HookError::Failed(Box::new(receipt)));
            }
            receipts.push(receipt);
        }
        Ok(receipts)
    }

    fn resolve_command(&self, executable: &str) -> Option<PathBuf> {
        let path = Path::new(executable);
        let search_path = self
            .inherited_environment
            .iter()
            .find(|(key, _)| key.as_os_str() == OsStr::new("PATH"))
            .map(|(_, value)| std::env::split_paths(value).collect::<Vec<_>>())
            .unwrap_or_default();
        process::resolve_executable(path, &search_path)
    }

    fn git_text<const N: usize>(&self, cwd: &Path, args: [&str; N]) -> Result<String, HookError> {
        let mut environment = self.git.environment.clone();
        for key in ["GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"] {
            environment.remove(OsStr::new(key));
        }
        environment.insert("GIT_TERMINAL_PROMPT".into(), "0".into());
        let output = process::run(ProcessRequest {
            executable: self.git.executable.clone(),
            args: args.into_iter().map(OsString::from).collect(),
            stdin: Vec::new(),
            cwd: Some(cwd.to_owned()),
            clear_environment: true,
            environment,
            timeout: self.git.timeout.min(GIT_TIMEOUT),
            shutdown_grace: HOOK_SHUTDOWN_GRACE,
            stdout_limit: 8 * 1024 * 1024,
            stderr_tail_limit: STDERR_TAIL_LIMIT,
        })
        .map_err(process_error)?;
        if output.timed_out
            || !output.cleanup_confirmed
            || output.status.is_none_or(|status| !status.success())
            || output.stdout_truncated
        {
            return Err(HookError::Process(
                "cannot inspect repository state for local checks".into(),
            ));
        }
        String::from_utf8(output.stdout)
            .map_err(|_| HookError::Process("repository metadata is not UTF-8".into()))
    }

    fn source_fingerprint(&self, repo: &Path) -> Result<Digest, HookError> {
        let tracked = self.git_text(
            repo,
            ["diff", "--name-only", "-z", "--no-renames", "HEAD", "--"],
        )?;
        let untracked =
            self.git_text(repo, ["ls-files", "--others", "--exclude-standard", "-z"])?;
        let mut paths = tracked
            .into_bytes()
            .split(|byte| *byte == 0)
            .filter(|path| !path.is_empty())
            .map(path_from_git_bytes)
            .collect::<Result<Vec<_>, _>>()?;
        paths.extend(
            untracked
                .into_bytes()
                .split(|byte| *byte == 0)
                .filter(|path| !path.is_empty())
                .map(path_from_git_bytes)
                .collect::<Result<Vec<_>, _>>()?,
        );
        paths.sort();
        paths.dedup();
        let mut digest = Sha256::new();
        let head = self.git_text(repo, ["rev-parse", "--verify", "HEAD"])?;
        digest.update(head.trim().as_bytes());
        for relative in paths {
            if relative.is_absolute()
                || relative.components().any(|component| {
                    matches!(
                        component,
                        Component::ParentDir | Component::RootDir | Component::Prefix(_)
                    )
                })
            {
                return Err(HookError::Process(
                    "Git returned a path outside the worktree".into(),
                ));
            }
            let path = repo.join(&relative);
            digest.update(path_bytes(&relative));
            match fs::symlink_metadata(&path) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    digest.update(b"symlink\0");
                    digest.update(path_bytes(&fs::read_link(&path).map_err(io_error)?));
                }
                Ok(metadata) if metadata.is_file() => {
                    digest.update(b"file\0");
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::MetadataExt;
                        digest.update(metadata.mode().to_be_bytes());
                    }
                    let mut file = File::open(&path).map_err(io_error)?;
                    let opened = file.metadata().map_err(io_error)?;
                    if !opened.is_file() || opened.len() != metadata.len() {
                        return Err(HookError::Process(
                            "source file changed while computing the hook receipt".into(),
                        ));
                    }
                    let mut buffer = [0_u8; 64 * 1024];
                    loop {
                        let read = file.read(&mut buffer).map_err(io_error)?;
                        if read == 0 {
                            break;
                        }
                        digest.update(&buffer[..read]);
                    }
                }
                Ok(_) => {
                    return Err(HookError::Process(
                        "changed source path is not a regular file or symlink".into(),
                    ));
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    digest.update(b"deleted\0")
                }
                Err(error) => return Err(io_error(error)),
            }
        }
        Ok(digest_bytes(&digest.finalize()))
    }
}

fn validate_hook(hook: &HookConfig) -> Result<(), HookError> {
    if hook.id.is_empty()
        || hook.id.len() > 96
        || !hook
            .id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        || hook.command.is_empty()
        || hook.command[0].is_empty()
        || hook.command.iter().any(|part| part.contains('\0'))
    {
        return Err(HookError::Invalid(
            "repository check needs a safe ID and nonempty argv".into(),
        ));
    }
    Ok(())
}

fn write_receipt(path: &Path, receipt: &HookReceipt) -> Result<(), HookError> {
    let bytes =
        serde_json::to_vec_pretty(receipt).map_err(|error| HookError::Io(error.to_string()))?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temporary = path.with_extension(format!("json.tmp-{}-{nonce}", std::process::id()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary).map_err(io_error)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(io_error)?;
    }
    file.write_all(&bytes).map_err(io_error)?;
    file.sync_all().map_err(io_error)?;
    fs::rename(&temporary, path).map_err(io_error)?;
    Ok(())
}

fn create_private_directory(path: &Path) -> Result<(), HookError> {
    fs::create_dir_all(path).map_err(io_error)?;
    let metadata = fs::symlink_metadata(path).map_err(io_error)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(HookError::Invalid(format!(
            "receipt path is not a real directory: {}",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(io_error)?;
    }
    Ok(())
}

fn ensure_real_directory(path: &Path) -> Result<(), HookError> {
    let metadata = fs::symlink_metadata(path).map_err(io_error)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(HookError::Invalid(
            "hook worktree is not a real directory".into(),
        ));
    }
    Ok(())
}

fn path_from_git_bytes(bytes: &[u8]) -> Result<PathBuf, HookError> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        Ok(PathBuf::from(OsString::from_vec(bytes.to_vec())))
    }
    #[cfg(not(unix))]
    {
        String::from_utf8(bytes.to_vec())
            .map(PathBuf::from)
            .map_err(|_| HookError::Process("Git returned a non-UTF-8 source path".into()))
    }
}

fn path_bytes(path: &Path) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        path.as_os_str().as_bytes().to_vec()
    }
    #[cfg(not(unix))]
    {
        path.to_string_lossy().as_bytes().to_vec()
    }
}

fn digest_bytes(bytes: &[u8]) -> Digest {
    Digest::parse(hex_bytes(&Sha256::digest(bytes))).expect("SHA-256 is a valid digest")
}

fn hex_bytes(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(TABLE[(byte >> 4) as usize]));
        output.push(char::from(TABLE[(byte & 15) as usize]));
    }
    output
}

fn process_error(error: ProcessError) -> HookError {
    HookError::Process(error.to_string())
}

fn io_error(error: std::io::Error) -> HookError {
    HookError::Io(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_git(cwd: &Path, args: &[&str]) {
        let output = process::run(ProcessRequest {
            executable: PathBuf::from("/usr/bin/git"),
            args: args.iter().map(OsString::from).collect(),
            stdin: Vec::new(),
            cwd: Some(cwd.to_owned()),
            clear_environment: true,
            environment: BTreeMap::new(),
            timeout: Duration::from_secs(10),
            shutdown_grace: Duration::from_secs(2),
            stdout_limit: 1024 * 1024,
            stderr_tail_limit: 8192,
        })
        .unwrap();
        assert!(output.status.is_some_and(|status| status.success()));
    }

    fn fixture() -> (tempfile::TempDir, PathBuf, Digest) {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp
            .path()
            .join("worktrees/fixture-repo/0123456789abcdef0123456789abcdef");
        fs::create_dir_all(repo.parent().unwrap()).unwrap();
        fs::create_dir(&repo).unwrap();
        fixture_git(&repo, &["init", "-b", "main"]);
        fs::write(repo.join("README.md"), "stable\n").unwrap();
        fixture_git(
            &repo,
            &[
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "add",
                "README.md",
            ],
        );
        fixture_git(
            &repo,
            &[
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-m",
                "fixture",
            ],
        );
        (temp, repo, Digest::parse("a".repeat(64)).unwrap())
    }

    fn hook(command: &[&str]) -> HookConfig {
        HookConfig {
            id: "check".into(),
            command: command.iter().map(|value| (*value).into()).collect(),
            timeout_seconds: 10,
        }
    }

    #[test]
    fn records_success_bound_to_head_configuration_and_source() {
        let (temp, repo, config_digest) = fixture();
        let head = std::fs::read_to_string(repo.join(".git/HEAD")).unwrap();
        let head = head.trim();
        let output = process::run(ProcessRequest {
            executable: PathBuf::from("/usr/bin/git"),
            args: ["rev-parse", "HEAD"]
                .into_iter()
                .map(OsString::from)
                .collect(),
            stdin: Vec::new(),
            cwd: Some(repo.clone()),
            clear_environment: true,
            environment: BTreeMap::new(),
            timeout: Duration::from_secs(10),
            shutdown_grace: Duration::from_secs(2),
            stdout_limit: 1024,
            stderr_tail_limit: 1024,
        })
        .unwrap();
        let expected_head = String::from_utf8(output.stdout).unwrap().trim().to_owned();
        assert!(head.starts_with("ref:"));
        let runner = HookRunner::new(
            GitOptions {
                executable: PathBuf::from("/usr/bin/git"),
                environment: BTreeMap::new(),
                timeout: Duration::from_secs(10),
            },
            [(OsString::from("PATH"), OsString::from("/bin:/usr/bin"))].into(),
        );
        let receipts = runner
            .run_required(
                &[hook(&["sh", "-c", "test -f README.md"])],
                HookRunContext {
                    repository_id: &RepositoryId::parse("fixture-repo").unwrap(),
                    worktree: &repo,
                    expected_head: &expected_head,
                    project_id: &ProjectId::parse("fixture-project").unwrap(),
                    ticket_run_id: &TicketRunId::parse("run-1").unwrap(),
                    configuration_digest: &config_digest,
                    state_root: temp.path(),
                },
            )
            .unwrap();
        assert_eq!(receipts.len(), 1);
        assert!(receipts[0].succeeded);
        assert_eq!(receipts[0].head, expected_head);
        assert!(
            temp.path()
                .join("hook-receipts/fixture-project/run-1/check.json")
                .is_file()
        );
    }

    #[test]
    fn rejects_hook_that_mutates_source_and_persists_failed_receipt() {
        let (temp, repo, config_digest) = fixture();
        let output = process::run(ProcessRequest {
            executable: PathBuf::from("/usr/bin/git"),
            args: ["rev-parse", "HEAD"]
                .into_iter()
                .map(OsString::from)
                .collect(),
            stdin: Vec::new(),
            cwd: Some(repo.clone()),
            clear_environment: true,
            environment: BTreeMap::new(),
            timeout: Duration::from_secs(10),
            shutdown_grace: Duration::from_secs(2),
            stdout_limit: 1024,
            stderr_tail_limit: 1024,
        })
        .unwrap();
        let head = String::from_utf8(output.stdout).unwrap().trim().to_owned();
        let runner = HookRunner::new(
            GitOptions {
                executable: PathBuf::from("/usr/bin/git"),
                environment: BTreeMap::new(),
                timeout: Duration::from_secs(10),
            },
            [(OsString::from("PATH"), OsString::from("/bin:/usr/bin"))].into(),
        );
        let result = runner.run_required(
            &[hook(&["sh", "-c", "printf changed > README.md"])],
            HookRunContext {
                repository_id: &RepositoryId::parse("fixture-repo").unwrap(),
                worktree: &repo,
                expected_head: &head,
                project_id: &ProjectId::parse("fixture-project").unwrap(),
                ticket_run_id: &TicketRunId::parse("run-2").unwrap(),
                configuration_digest: &config_digest,
                state_root: temp.path(),
            },
        );
        assert!(matches!(result, Err(HookError::SourceChanged { .. })));
        let receipt = fs::read_to_string(
            temp.path()
                .join("hook-receipts/fixture-project/run-2/check.json"),
        )
        .unwrap();
        assert!(receipt.contains("\"succeeded\": false"));
    }
}
