use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::time::Duration;

use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::domain::ids::{RepositoryId, TicketId, TicketNamespace};
use crate::process::{self, ProcessError, ProcessOutput, ProcessRequest};

const GIT_OUTPUT_LIMIT: usize = 4 * 1024 * 1024;
const GIT_STDERR_LIMIT: usize = 64 * 1024;
const GIT_TIMEOUT: Duration = Duration::from_secs(120);
const GIT_SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TicketKey {
    pub namespace: TicketNamespace,
    pub ticket_id: TicketId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedRepository {
    pub id: RepositoryId,
    pub path: PathBuf,
    pub clone_url: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedWorktree {
    pub repository_id: RepositoryId,
    pub path: PathBuf,
    pub branch: String,
    pub base_sha: String,
}

#[derive(Clone, Debug)]
pub struct GitOptions {
    pub executable: PathBuf,
    pub environment: BTreeMap<OsString, OsString>,
    pub timeout: Duration,
}

pub struct WorktreeManager {
    state_root: PathBuf,
    repos_root: PathBuf,
    worktrees_root: PathBuf,
    locks_root: PathBuf,
    git: GitOptions,
}

pub struct WorktreeLease {
    worktree: ManagedWorktree,
    _lock: File,
}

impl WorktreeLease {
    pub fn worktree(&self) -> &ManagedWorktree {
        &self.worktree
    }
}

#[derive(Debug)]
pub enum WorktreeError {
    Invalid(String),
    Io(String),
    Git {
        operation: &'static str,
        detail: String,
    },
    Conflict(String),
}

impl std::fmt::Display for WorktreeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(message) => write!(f, "invalid repository operation: {message}"),
            Self::Io(message) => f.write_str(message),
            Self::Git { operation, detail } => write!(f, "git {operation} failed: {detail}"),
            Self::Conflict(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for WorktreeError {}

impl WorktreeManager {
    pub fn new(state_root: &Path, git: GitOptions) -> Result<Self, WorktreeError> {
        if !git.executable.is_absolute() || !git.executable.is_file() {
            return Err(WorktreeError::Invalid(
                "git executable must be an existing absolute file".into(),
            ));
        }
        if git.timeout.is_zero() {
            return Err(WorktreeError::Invalid(
                "git timeout must be positive".into(),
            ));
        }
        let state_root = absolute_directory(state_root)?;
        let repos_root = state_root.join("repos");
        let worktrees_root = state_root.join("worktrees");
        let locks_root = state_root.join("locks");
        for directory in [&repos_root, &worktrees_root, &locks_root] {
            create_private_directory(directory)?;
        }
        Ok(Self {
            state_root,
            repos_root,
            worktrees_root,
            locks_root,
            git,
        })
    }

    pub fn ensure_repository(
        &self,
        id: &RepositoryId,
        clone_url: &str,
    ) -> Result<ManagedRepository, WorktreeError> {
        validate_clone_url(clone_url)?;
        let lock = self.repository_lock(id)?;
        let path = self.repos_root.join(id.as_str());
        if !path.exists() {
            self.clone_repository(id, clone_url, &path)?;
        }
        ensure_real_directory(&path)?;
        let canonical_path = path.canonicalize().map_err(io_error)?;
        let actual_top = self.git_output(
            &canonical_path,
            "rev-parse --show-toplevel",
            ["rev-parse", "--show-toplevel"],
        )?;
        let actual_top = PathBuf::from(actual_top.trim());
        if actual_top != canonical_path {
            return Err(WorktreeError::Conflict(format!(
                "managed repository {} resolves to an unexpected Git root",
                id
            )));
        }
        let remote = self.git_output(
            &canonical_path,
            "read configured origin URL",
            ["config", "--get-all", "remote.origin.url"],
        )?;
        if remote.trim() != clone_url {
            return Err(WorktreeError::Conflict(format!(
                "managed repository {id} has a different origin URL; preserving it for reconciliation"
            )));
        }
        self.git_status_ok(
            &canonical_path,
            "config gc.auto 0",
            ["config", "gc.auto", "0"],
        )?;
        self.git_status_ok(
            &canonical_path,
            "config maintenance.auto false",
            ["config", "maintenance.auto", "false"],
        )?;
        self.git_status_ok(
            &canonical_path,
            "fetch origin",
            ["fetch", "--prune", "origin"],
        )?;
        drop(lock);
        Ok(ManagedRepository {
            id: id.clone(),
            path: canonical_path,
            clone_url: clone_url.to_owned(),
        })
    }

    pub fn prepare_worktree(
        &self,
        repository: &ManagedRepository,
        base_branch: &str,
        key: &TicketKey,
    ) -> Result<ManagedWorktree, WorktreeError> {
        validate_git_ref(base_branch)?;
        let _lock = self.repository_lock(&repository.id)?;
        ensure_real_directory(&repository.path)?;
        let expected_repository_path = self.repos_root.join(repository.id.as_str());
        let expected_repository_path = expected_repository_path.canonicalize().map_err(io_error)?;
        if repository.path.canonicalize().map_err(io_error)? != expected_repository_path {
            return Err(WorktreeError::Invalid(
                "repository path is not the configured managed clone".into(),
            ));
        }
        self.git_status_ok(
            &repository.path,
            "fetch repository",
            ["fetch", "--prune", "origin"],
        )?;
        let base_ref = format!("refs/remotes/origin/{base_branch}");
        let fetched_base_sha = self
            .git_output(
                &repository.path,
                "resolve fetched base",
                ["rev-parse", "--verify", &format!("{base_ref}^{{commit}}")],
            )?
            .trim()
            .to_owned();
        validate_sha(&fetched_base_sha)?;
        let branch = ticket_branch(key);
        let path = self
            .worktrees_root
            .join(repository.id.as_str())
            .join(&branch["rex-projects/".len()..]);
        create_private_directory(path.parent().expect("worktree parent exists"))?;
        let canonical_parent = path
            .parent()
            .expect("worktree parent exists")
            .canonicalize()
            .map_err(io_error)?;
        if !path.starts_with(canonical_parent) {
            return Err(WorktreeError::Invalid(
                "worktree path escapes the managed root".into(),
            ));
        }
        if path.exists() {
            ensure_real_directory(&path)?;
            let top = self.git_output(
                &path,
                "rev-parse --show-toplevel",
                ["rev-parse", "--show-toplevel"],
            )?;
            if Path::new(top.trim()) != path.as_path() {
                return Err(WorktreeError::Conflict(
                    "existing worktree has a different Git root".into(),
                ));
            }
            let current_branch = self.git_output(
                &path,
                "symbolic-ref",
                ["symbolic-ref", "--quiet", "--short", "HEAD"],
            )?;
            if current_branch.trim() != branch {
                return Err(WorktreeError::Conflict(
                    "existing worktree has a different branch".into(),
                ));
            }
            let base_sha = self
                .git_output(
                    &repository.path,
                    "resolve stable worktree base",
                    ["merge-base", &branch, &base_ref],
                )?
                .trim()
                .to_owned();
            validate_sha(&base_sha)?;
            return Ok(ManagedWorktree {
                repository_id: repository.id.clone(),
                path,
                branch,
                base_sha,
            });
        } else {
            let branch_exists = self.git_status(
                &repository.path,
                [
                    "show-ref",
                    "--verify",
                    "--quiet",
                    &format!("refs/heads/{branch}"),
                ],
            )?;
            if branch_exists.status.and_then(|status| status.code()) == Some(0) {
                self.git_status_ok(
                    &repository.path,
                    "attach existing topic branch",
                    ["worktree", "add", &path.to_string_lossy(), &branch],
                )?;
                let base_sha = self
                    .git_output(
                        &repository.path,
                        "resolve stable worktree base",
                        ["merge-base", &branch, &base_ref],
                    )?
                    .trim()
                    .to_owned();
                validate_sha(&base_sha)?;
                return Ok(ManagedWorktree {
                    repository_id: repository.id.clone(),
                    path,
                    branch,
                    base_sha,
                });
            } else {
                self.git_status_ok(
                    &repository.path,
                    "create topic worktree",
                    [
                        "worktree",
                        "add",
                        "--no-track",
                        "-b",
                        &branch,
                        &path.to_string_lossy(),
                        &fetched_base_sha,
                    ],
                )?;
            }
        }
        Ok(ManagedWorktree {
            repository_id: repository.id.clone(),
            path,
            branch,
            base_sha: fetched_base_sha,
        })
    }

    pub fn acquire_writer_lease(
        &self,
        worktree: ManagedWorktree,
    ) -> Result<WorktreeLease, WorktreeError> {
        validate_managed_worktree(&self.worktrees_root, &worktree)?;
        let suffix = worktree
            .branch
            .strip_prefix("rex-projects/")
            .expect("validated worktree branch prefix");
        let path = self
            .locks_root
            .join(format!("worktree-{}-{suffix}.lock", worktree.repository_id));
        let mut options = OpenOptions::new();
        options.create(true).truncate(false).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = options.open(path).map_err(io_error)?;
        set_private_file(&lock)?;
        lock.try_lock_exclusive().map_err(|_| {
            WorktreeError::Conflict("another run already owns this managed worktree".into())
        })?;
        Ok(WorktreeLease {
            worktree,
            _lock: lock,
        })
    }

    pub fn verify_native_commits(
        &self,
        worktree: &ManagedWorktree,
        required_trailer: &str,
    ) -> Result<NativeCommitReceipt, WorktreeError> {
        if required_trailer.is_empty() || required_trailer.contains(['\n', '\r']) {
            return Err(WorktreeError::Invalid(
                "required authorship trailer must be one nonempty line".into(),
            ));
        }
        validate_managed_worktree(&self.worktrees_root, worktree)?;
        let _lock = self.repository_lock(&worktree.repository_id)?;
        let head = self
            .git_output(
                &worktree.path,
                "resolve HEAD",
                ["rev-parse", "--verify", "HEAD"],
            )?
            .trim()
            .to_owned();
        validate_sha(&head)?;
        let base = self
            .git_output(
                &worktree.path,
                "resolve recorded base",
                [
                    "rev-parse",
                    "--verify",
                    &format!("{}^{{commit}}", worktree.base_sha),
                ],
            )?
            .trim()
            .to_owned();
        if base != worktree.base_sha {
            return Err(WorktreeError::Conflict(
                "recorded base no longer resolves to the same commit".into(),
            ));
        }
        if head == base {
            return Err(WorktreeError::Conflict(
                "Worker produced no commit after its base".into(),
            ));
        }
        self.git_status_ok(
            &worktree.path,
            "check base ancestry",
            ["merge-base", "--is-ancestor", &base, &head],
        )?;
        let state = self.git_output(
            &worktree.path,
            "inspect worktree state",
            ["status", "--porcelain=v2", "--untracked-files=all"],
        )?;
        if !state.is_empty() {
            return Err(WorktreeError::Conflict(
                "native commit has staged, unstaged, or untracked changes".into(),
            ));
        }
        let commits = self.git_output(
            &worktree.path,
            "list commits after base",
            [
                "rev-list",
                "--reverse",
                "--parents",
                &format!("{base}..{head}"),
            ],
        )?;
        let mut verified = Vec::new();
        let mut expected_parent = base.clone();
        for line in commits.lines() {
            let mut fields = line.split_whitespace();
            let commit = fields
                .next()
                .ok_or_else(|| WorktreeError::Conflict("empty commit ancestry entry".into()))?;
            validate_sha(commit)?;
            let parent = fields.next().ok_or_else(|| {
                WorktreeError::Conflict("commit is not based on the expected linear parent".into())
            })?;
            if fields.next().is_some() || parent != expected_parent {
                return Err(WorktreeError::Conflict(
                    "native Worker history is not a linear stack from its recorded base".into(),
                ));
            }
            self.git_status_ok(
                &worktree.path,
                "verify commit signature",
                ["verify-commit", commit],
            )?;
            let message = self.git_output(
                &worktree.path,
                "read commit trailers",
                ["show", "-s", "--format=%B", commit],
            )?;
            let trailers = self.git_output_bytes(
                &worktree.path,
                "parse commit trailers",
                ["interpret-trailers", "--parse"]
                    .into_iter()
                    .map(OsString::from)
                    .collect(),
                message.as_bytes().to_vec(),
            )?;
            if !trailers.lines().any(|line| line == required_trailer) {
                return Err(WorktreeError::Conflict(format!(
                    "commit {commit} is missing the required authorship trailer"
                )));
            }
            verified.push(commit.to_owned());
            expected_parent = commit.to_owned();
        }
        if expected_parent != head || verified.is_empty() {
            return Err(WorktreeError::Conflict(
                "cannot prove every commit from base to HEAD".into(),
            ));
        }
        Ok(NativeCommitReceipt {
            head,
            base_sha: base,
            commits: verified,
        })
    }

    fn clone_repository(
        &self,
        id: &RepositoryId,
        url: &str,
        destination: &Path,
    ) -> Result<(), WorktreeError> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let nonce = format!(".clone-{}-{}-{nanos}", id, std::process::id());
        let temporary = self.repos_root.join(nonce);
        if temporary.exists() {
            return Err(WorktreeError::Conflict(
                "an earlier interrupted clone requires reconciliation".into(),
            ));
        }
        self.git_status_ok(
            &self.state_root,
            "clone repository",
            [
                "clone",
                "--no-checkout",
                "--",
                url,
                temporary
                    .to_str()
                    .ok_or_else(|| WorktreeError::Invalid("managed path is not UTF-8".into()))?,
            ],
        )?;
        if let Err(error) = fs::rename(&temporary, destination) {
            return Err(WorktreeError::Io(format!(
                "cannot publish completed managed clone: {error}"
            )));
        }
        Ok(())
    }

    fn repository_lock(&self, id: &RepositoryId) -> Result<File, WorktreeError> {
        let path = self
            .locks_root
            .join(format!("repository-{}.lock", id.as_str()));
        let mut options = OpenOptions::new();
        options.create(true).truncate(false).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&path).map_err(io_error)?;
        set_private_file(&file)?;
        file.lock_exclusive().map_err(io_error)?;
        Ok(file)
    }

    fn git_output<const N: usize>(
        &self,
        cwd: &Path,
        operation: &'static str,
        args: [&str; N],
    ) -> Result<String, WorktreeError> {
        self.git_output_bytes(
            cwd,
            operation,
            args.into_iter().map(OsString::from).collect(),
            Vec::new(),
        )
    }

    fn git_output_bytes(
        &self,
        cwd: &Path,
        operation: &'static str,
        args: Vec<OsString>,
        stdin: Vec<u8>,
    ) -> Result<String, WorktreeError> {
        let output = self.run_git(cwd, args, stdin)?;
        check_success(operation, &output)?;
        if output.stdout_truncated {
            return Err(WorktreeError::Git {
                operation,
                detail: "bounded output was truncated".into(),
            });
        }
        String::from_utf8(output.stdout).map_err(|_| WorktreeError::Git {
            operation,
            detail: "output was not UTF-8".into(),
        })
    }

    fn git_status_ok<const N: usize>(
        &self,
        cwd: &Path,
        operation: &'static str,
        args: [&str; N],
    ) -> Result<ProcessOutput, WorktreeError> {
        let output = self.git_status(cwd, args)?;
        check_success(operation, &output)?;
        Ok(output)
    }

    fn git_status<const N: usize>(
        &self,
        cwd: &Path,
        args: [&str; N],
    ) -> Result<ProcessOutput, WorktreeError> {
        self.run_git(
            cwd,
            args.into_iter().map(OsString::from).collect(),
            Vec::new(),
        )
    }

    fn run_git(
        &self,
        cwd: &Path,
        args: Vec<OsString>,
        stdin: Vec<u8>,
    ) -> Result<ProcessOutput, WorktreeError> {
        let mut environment = self.git.environment.clone();
        environment.insert("GIT_TERMINAL_PROMPT".into(), "0".into());
        let mut git_args = vec![
            "-c".into(),
            "gc.auto=0".into(),
            "-c".into(),
            "maintenance.auto=false".into(),
        ];
        git_args.extend(args);
        process::run(ProcessRequest {
            executable: self.git.executable.clone(),
            args: git_args,
            stdin,
            cwd: Some(cwd.to_owned()),
            clear_environment: true,
            environment,
            timeout: self.git.timeout.min(GIT_TIMEOUT),
            shutdown_grace: GIT_SHUTDOWN_GRACE,
            stdout_limit: GIT_OUTPUT_LIMIT,
            stderr_tail_limit: GIT_STDERR_LIMIT,
        })
        .map_err(|error| process_error("git", error))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NativeCommitReceipt {
    pub head: String,
    pub base_sha: String,
    pub commits: Vec<String>,
}

fn process_error(operation: &'static str, error: ProcessError) -> WorktreeError {
    WorktreeError::Git {
        operation,
        detail: error.to_string(),
    }
}

fn check_success(operation: &'static str, output: &ProcessOutput) -> Result<(), WorktreeError> {
    if output.timed_out || !output.cleanup_confirmed {
        return Err(WorktreeError::Git {
            operation,
            detail: "process timeout or cleanup outcome is unknown".into(),
        });
    }
    if output.status.is_none_or(|status| !status.success()) {
        return Err(WorktreeError::Git {
            operation,
            detail: format!(
                "Git exited with status {:?}",
                output.status.and_then(|status| status.code())
            ),
        });
    }
    Ok(())
}

fn validate_clone_url(url: &str) -> Result<(), WorktreeError> {
    if url.trim().is_empty() || url.contains(['\n', '\r', '\0']) {
        return Err(WorktreeError::Invalid(
            "clone URL must be nonempty and contain no control line breaks".into(),
        ));
    }
    Ok(())
}

fn validate_managed_worktree(
    worktrees_root: &Path,
    worktree: &ManagedWorktree,
) -> Result<(), WorktreeError> {
    const PREFIX: &str = "rex-projects/";
    let suffix = worktree.branch.strip_prefix(PREFIX).ok_or_else(|| {
        WorktreeError::Invalid("worktree branch is not rex-projects managed".into())
    })?;
    if suffix.len() != 32 || !suffix.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(WorktreeError::Invalid(
            "worktree branch identity is not a stable ticket key".into(),
        ));
    }
    let repository_root = worktrees_root.join(worktree.repository_id.as_str());
    let expected_path = repository_root.join(suffix);
    let canonical_repository = repository_root.canonicalize().map_err(io_error)?;
    if expected_path.canonicalize().map_err(io_error)?.as_path()
        != worktree.path.canonicalize().map_err(io_error)?.as_path()
        || !worktree.path.starts_with(&canonical_repository)
    {
        return Err(WorktreeError::Invalid(
            "worktree path is outside its managed repository directory".into(),
        ));
    }
    ensure_real_directory(&worktree.path)?;
    Ok(())
}

fn validate_git_ref(value: &str) -> Result<(), WorktreeError> {
    if value.is_empty()
        || value.starts_with('-')
        || value.chars().any(char::is_control)
        || value.contains("..")
        || value.ends_with(['.', '/'])
        || value.contains("//")
        || value.contains('@') && value.ends_with('@')
        || value.contains('\\')
        || value.contains(' ')
        || value.contains('~')
        || value.contains('^')
        || value.contains(':')
        || value.contains('?')
        || value.contains('*')
        || value.contains('[')
    {
        return Err(WorktreeError::Invalid(
            "base branch is not a safe Git ref name".into(),
        ));
    }
    Ok(())
}

fn validate_sha(value: &str) -> Result<(), WorktreeError> {
    if !matches!(value.len(), 40 | 64) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(WorktreeError::Conflict(
            "Git returned an invalid object ID".into(),
        ));
    }
    Ok(())
}

fn ticket_branch(key: &TicketKey) -> String {
    let mut digest = Sha256::new();
    digest.update(key.namespace.as_str());
    digest.update([0]);
    digest.update(key.ticket_id.as_str());
    format!("rex-projects/{}", encode_hex(&digest.finalize()[..16]))
}

fn encode_hex(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(TABLE[(byte >> 4) as usize]));
        output.push(char::from(TABLE[(byte & 15) as usize]));
    }
    output
}

fn absolute_directory(path: &Path) -> Result<PathBuf, WorktreeError> {
    if !path.is_absolute() {
        return Err(WorktreeError::Invalid("state root must be absolute".into()));
    }
    create_private_directory(path)?;
    ensure_real_directory(path)?;
    path.canonicalize().map_err(io_error)
}

fn create_private_directory(path: &Path) -> Result<(), WorktreeError> {
    fs::create_dir_all(path).map_err(io_error)?;
    ensure_real_directory(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(io_error)?;
    }
    Ok(())
}

fn ensure_real_directory(path: &Path) -> Result<(), WorktreeError> {
    let metadata = fs::symlink_metadata(path).map_err(io_error)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(WorktreeError::Invalid(format!(
            "managed path is not a real directory: {}",
            path.display()
        )));
    }
    Ok(())
}

fn set_private_file(file: &File) -> Result<(), WorktreeError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(io_error)?;
    }
    Ok(())
}

fn io_error(error: std::io::Error) -> WorktreeError {
    WorktreeError::Io(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    fn manager(root: &Path) -> WorktreeManager {
        let git = which_git().unwrap();
        WorktreeManager::new(
            root,
            GitOptions {
                executable: git,
                environment: BTreeMap::new(),
                timeout: Duration::from_secs(20),
            },
        )
        .unwrap()
    }

    fn which_git() -> Option<PathBuf> {
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .map(|directory| directory.join("git"))
            .find(|path| path.is_file())
            .or_else(|| {
                [
                    "/usr/bin/git",
                    "/opt/homebrew/bin/git",
                    "/usr/local/bin/git",
                ]
                .into_iter()
                .map(PathBuf::from)
                .find(|path| path.is_file())
            })
    }

    fn git(executable: &Path, cwd: &Path, args: &[&str]) {
        let output = process::run(ProcessRequest {
            executable: executable.to_owned(),
            args: args.iter().map(OsString::from).collect(),
            stdin: Vec::new(),
            cwd: Some(cwd.to_owned()),
            clear_environment: true,
            environment: BTreeMap::new(),
            timeout: Duration::from_secs(20),
            shutdown_grace: Duration::from_secs(2),
            stdout_limit: 1024 * 1024,
            stderr_tail_limit: 8192,
        })
        .unwrap();
        assert!(
            output.status.is_some_and(|status| status.success()),
            "fixture git command failed: {args:?}"
        );
    }

    #[test]
    fn clones_to_managed_root_fetches_and_reuses_stable_ticket_worktree() {
        let temp = tempfile::tempdir().unwrap();
        let remote = temp.path().join("remote.git");
        let executable = which_git().unwrap();
        fs::create_dir_all(&remote).unwrap();
        git(
            &executable,
            temp.path(),
            &["init", "--bare", remote.to_str().unwrap()],
        );
        let seed = temp.path().join("seed");
        fs::create_dir_all(&seed).unwrap();
        git(
            &executable,
            temp.path(),
            &["init", "-b", "main", seed.to_str().unwrap()],
        );
        std::fs::write(seed.join("README.md"), "fixture\n").unwrap();
        git(
            &executable,
            &seed,
            &[
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "add",
                "README.md",
            ],
        );
        git(
            &executable,
            &seed,
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
        git(
            &executable,
            &seed,
            &["remote", "add", "origin", remote.to_str().unwrap()],
        );
        git(&executable, &seed, &["push", "-u", "origin", "main"]);
        let state = temp.path().join("state");
        let manager = manager(&state);
        let id = RepositoryId::parse("sample-repo").unwrap();
        let repository = manager
            .ensure_repository(&id, remote.to_str().unwrap())
            .unwrap();
        assert!(
            repository
                .path
                .starts_with(state.join("repos").canonicalize().unwrap())
        );
        let key = TicketKey {
            namespace: TicketNamespace::parse("fixture").unwrap(),
            ticket_id: TicketId::parse("T-1").unwrap(),
        };
        let first = manager.prepare_worktree(&repository, "main", &key).unwrap();
        let lease = manager.acquire_writer_lease(first.clone()).unwrap();
        assert!(manager.acquire_writer_lease(first.clone()).is_err());
        drop(lease);
        assert!(manager.acquire_writer_lease(first.clone()).is_ok());
        fs::write(seed.join("REMOTE.md"), "advanced\n").unwrap();
        git(&executable, &seed, &["add", "REMOTE.md"]);
        git(
            &executable,
            &seed,
            &[
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-m",
                "advance remote",
            ],
        );
        git(&executable, &seed, &["push", "origin", "main"]);
        let again = manager.prepare_worktree(&repository, "main", &key).unwrap();
        assert_eq!(first.path, again.path);
        assert_eq!(first.branch, again.branch);
        assert_eq!(first.base_sha, again.base_sha);
        assert_eq!(first.base_sha, again.base_sha);
    }

    #[test]
    fn rejects_changed_clone_origin_and_symlinked_repository() {
        let temp = tempfile::tempdir().unwrap();
        let remote = temp.path().join("remote.git");
        let executable = which_git().unwrap();
        fs::create_dir_all(&remote).unwrap();
        git(
            &executable,
            temp.path(),
            &["init", "--bare", remote.to_str().unwrap()],
        );
        let state = temp.path().join("state");
        let manager = manager(&state);
        let id = RepositoryId::parse("sample-repo").unwrap();
        manager
            .ensure_repository(&id, remote.to_str().unwrap())
            .unwrap();
        assert!(
            manager
                .ensure_repository(&id, "https://invalid.example/changed.git")
                .is_err()
        );
        let managed = state.join("repos/sample-repo");
        let outside = temp.path().join("outside");
        fs::rename(&managed, &outside).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, &managed).unwrap();
        assert!(
            manager
                .ensure_repository(&id, remote.to_str().unwrap())
                .is_err()
        );
    }

    #[test]
    fn clone_url_rewrite_does_not_change_managed_origin_identity() {
        let temp = tempfile::tempdir().unwrap();
        let remote = temp.path().join("remote.git");
        let executable = which_git().unwrap();
        fs::create_dir_all(&remote).unwrap();
        git(
            &executable,
            temp.path(),
            &["init", "--bare", remote.to_str().unwrap()],
        );

        let clone_url = "https://github.com/fixture/repository.git";
        let mut environment = BTreeMap::new();
        environment.insert(OsString::from("GIT_CONFIG_COUNT"), OsString::from("1"));
        environment.insert(
            OsString::from("GIT_CONFIG_KEY_0"),
            OsString::from(format!("url.file://{}.insteadOf", remote.display())),
        );
        environment.insert(
            OsString::from("GIT_CONFIG_VALUE_0"),
            OsString::from(clone_url),
        );
        let state = temp.path().join("state");
        let manager = WorktreeManager::new(
            &state,
            GitOptions {
                executable: executable.clone(),
                environment,
                timeout: Duration::from_secs(20),
            },
        )
        .unwrap();
        let id = RepositoryId::parse("fixture").unwrap();
        let repository = manager.ensure_repository(&id, clone_url).unwrap();
        let key = TicketKey {
            namespace: TicketNamespace::parse("fixture/acceptance").unwrap(),
            ticket_id: TicketId::parse("ticket-1").unwrap(),
        };
        let worktree = manager.prepare_worktree(&repository, "main", &key);

        // The empty remote intentionally has no main branch, so preparation must reach base
        // resolution after the successful fetch instead of rejecting HTTPS as a changed origin.
        assert!(matches!(
            worktree,
            Err(WorktreeError::Git {
                operation: "resolve fetched base",
                ..
            })
        ));

        let raw_origin = manager
            .git_output(
                &repository.path,
                "read configured origin URL",
                ["config", "--get-all", "remote.origin.url"],
            )
            .unwrap();
        assert_eq!(raw_origin.trim(), clone_url);
        let rewritten_origin = manager
            .git_output(
                &repository.path,
                "resolve rewritten origin URL",
                ["remote", "get-url", "origin"],
            )
            .unwrap();
        assert_eq!(
            rewritten_origin.trim(),
            format!("file://{}", remote.display())
        );

        let mut conflicting_environment = manager.git.environment.clone();
        conflicting_environment.insert(OsString::from("GIT_CONFIG_COUNT"), OsString::from("2"));
        conflicting_environment.insert(
            OsString::from("GIT_CONFIG_KEY_1"),
            OsString::from("remote.origin.url"),
        );
        conflicting_environment.insert(
            OsString::from("GIT_CONFIG_VALUE_1"),
            OsString::from("https://invalid.example/global-origin.git"),
        );
        let conflicting_manager = WorktreeManager::new(
            &state,
            GitOptions {
                executable: executable.clone(),
                environment: conflicting_environment,
                timeout: Duration::from_secs(20),
            },
        )
        .unwrap();
        assert!(matches!(
            conflicting_manager.ensure_repository(&id, clone_url),
            Err(WorktreeError::Conflict(_))
        ));

        git(
            &executable,
            &repository.path,
            &[
                "config",
                "--local",
                "--add",
                "remote.origin.url",
                "https://invalid.example/second-origin.git",
            ],
        );
        assert!(matches!(
            manager.ensure_repository(&id, clone_url),
            Err(WorktreeError::Conflict(_))
        ));
    }
}
