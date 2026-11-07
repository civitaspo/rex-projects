use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::domain::ids::{Digest, OperationId, RepositoryId};
use crate::process::{self, ProcessOutput, ProcessRequest};
use crate::worktrees::ManagedWorktree;

const MAX_MANIFEST_ENTRIES: usize = 10_000;
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
const GIT_TIMEOUT: Duration = Duration::from_secs(120);
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeManifest {
    pub schema_version: u32,
    pub entries: Vec<ManifestEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ManifestEntry {
    Write {
        path: String,
        mode: FileMode,
        sha256: Digest,
        byte_count: u64,
    },
    Symlink {
        path: String,
        target_sha256: Digest,
        target_byte_count: u64,
    },
    Delete {
        path: String,
    },
}

impl ManifestEntry {
    fn path(&self) -> &str {
        match self {
            Self::Write { path, .. } | Self::Symlink { path, .. } | Self::Delete { path } => path,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileMode {
    Regular0644,
    Executable0755,
}

impl FileMode {
    fn git_mode(self) -> &'static str {
        match self {
            Self::Regular0644 => "100644",
            Self::Executable0755 => "100755",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostCommitIntent {
    pub schema_version: u32,
    pub operation_id: OperationId,
    pub repository_id: RepositoryId,
    pub worktree_branch: String,
    pub expected_head: String,
    pub manifest_digest: Digest,
    pub manifest: ChangeManifest,
    pub message: String,
    pub normal_index: IndexIdentity,
    pub normal_index_backup: PathBuf,
    pub staging_directory: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndexIdentity {
    pub canonical_path: PathBuf,
    pub device: u64,
    pub inode: u64,
    pub byte_count: u64,
    pub digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedHostCommit {
    pub intent: HostCommitIntent,
    pub isolated_index: PathBuf,
    pub expected_tree: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostCommitReceipt {
    pub operation_id: OperationId,
    pub repository_id: RepositoryId,
    pub expected_head: String,
    pub observed_head: String,
    pub tree: String,
    pub manifest_digest: Digest,
    pub signature_verified: bool,
    pub hooks_completed: bool,
    pub index_synchronized: bool,
    pub index_sync_conflict: bool,
}

#[derive(Debug)]
pub enum HostCommitError {
    Invalid(String),
    Io(String),
    Git(&'static str, String),
    Conflict(String),
    UnexpectedCommit {
        head: String,
        expected_tree: String,
        actual_tree: String,
    },
}

impl std::fmt::Display for HostCommitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(message) | Self::Io(message) | Self::Conflict(message) => {
                f.write_str(message)
            }
            Self::Git(operation, message) => write!(f, "git {operation} failed: {message}"),
            Self::UnexpectedCommit { head, .. } => {
                write!(f, "commit {head} differs from the requested tree")
            }
        }
    }
}

impl std::error::Error for HostCommitError {}

#[derive(Clone, Debug)]
pub struct HostCommitOptions {
    pub git_executable: PathBuf,
    pub git_environment: BTreeMap<OsString, OsString>,
    pub state_root: PathBuf,
    pub timeout: Duration,
}

pub struct HostCommitter {
    options: HostCommitOptions,
    state_root: PathBuf,
}

impl HostCommitter {
    pub fn new(options: HostCommitOptions) -> Result<Self, HostCommitError> {
        if !options.git_executable.is_absolute() || !options.git_executable.is_file() {
            return Err(HostCommitError::Invalid(
                "Git executable must be an existing absolute path".into(),
            ));
        }
        if !options.state_root.is_absolute() || options.timeout.is_zero() {
            return Err(HostCommitError::Invalid(
                "state root must be absolute and Git timeout positive".into(),
            ));
        }
        create_private_directory(&options.state_root)?;
        let state_root = options.state_root.canonicalize().map_err(io_error)?;
        Ok(Self {
            options,
            state_root,
        })
    }

    pub fn prepare(
        &self,
        worktree: &ManagedWorktree,
        operation_id: OperationId,
        manifest: ChangeManifest,
        manifest_root: &Path,
        message: String,
    ) -> Result<PreparedHostCommit, HostCommitError> {
        validate_manifest(&manifest)?;
        if message.trim().is_empty() || message.contains('\0') {
            return Err(HostCommitError::Invalid(
                "commit message must be nonempty and contain no NUL".into(),
            ));
        }
        let repo = worktree.path.canonicalize().map_err(io_error)?;
        let managed_root = self
            .state_root
            .join("worktrees")
            .canonicalize()
            .map_err(io_error)?;
        if !repo.starts_with(managed_root) || !repo.is_dir() {
            return Err(HostCommitError::Invalid(
                "host commits are limited to managed worktrees".into(),
            ));
        }
        self.validate_worktree_path(worktree, &repo)?;
        if manifest_root.canonicalize().map_err(io_error)? != repo {
            return Err(HostCommitError::Invalid(
                "manifest source must be the verified managed worktree".into(),
            ));
        }
        let _lock = self.repository_lock(&worktree.repository_id)?;
        let head = self.git_text(
            &repo,
            "resolve expected HEAD",
            ["rev-parse", "--verify", "HEAD"],
            None,
            None,
        )?;
        let head = head.trim().to_owned();
        if head != worktree.base_sha {
            return Err(HostCommitError::Conflict(
                "host manifest commits require a clean worktree at its recorded base".into(),
            ));
        }
        self.require_clean_index_and_manifest(&repo, &head, &manifest)?;
        let normal_index = self.index_identity(&repo)?;
        let manifest_digest = manifest_digest(&manifest)?;
        let staging_directory = self
            .state_root
            .join("host-commits")
            .join(operation_id.as_str());
        let isolated_index = staging_directory.join("index");
        if staging_directory.exists() {
            let stage_metadata = fs::symlink_metadata(&staging_directory).map_err(io_error)?;
            if stage_metadata.file_type().is_symlink() || !stage_metadata.is_dir() {
                return Err(HostCommitError::Conflict(
                    "host-commit staging path is not a private directory".into(),
                ));
            }
            let intent_path = staging_directory.join("intent.json");
            let metadata = fs::symlink_metadata(&intent_path).map_err(io_error)?;
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.len() > 32 * 1024 * 1024
            {
                return Err(HostCommitError::Conflict(
                    "interrupted host-commit staging requires reconciliation".into(),
                ));
            }
            let intent_file = open_read_nofollow(&intent_path)?;
            let mut intent_bytes = Vec::new();
            intent_file
                .take(32 * 1024 * 1024 + 1)
                .read_to_end(&mut intent_bytes)
                .map_err(io_error)?;
            let intent: HostCommitIntent = serde_json::from_slice(&intent_bytes).map_err(|_| {
                HostCommitError::Conflict("interrupted host-commit intent is invalid".into())
            })?;
            if intent.operation_id != operation_id
                || intent.repository_id != worktree.repository_id
                || intent.worktree_branch != worktree.branch
                || intent.expected_head != head
                || intent.manifest_digest != manifest_digest
                || intent.manifest != manifest
                || intent.message != message
                || intent.normal_index != normal_index
                || intent.staging_directory != staging_directory
                || intent.normal_index_backup != staging_directory.join("normal-index.backup")
                || !isolated_index.is_file()
            {
                return Err(HostCommitError::Conflict(
                    "operation ID already has different prepared commit content".into(),
                ));
            }
            let expected_tree = self
                .git_text(
                    &repo,
                    "recover prepared host-commit tree",
                    ["write-tree"],
                    None,
                    Some(&mut IndexEnvironment::new(isolated_index.clone())),
                )?
                .trim()
                .to_owned();
            validate_object_id(&expected_tree)?;
            let prepared = PreparedHostCommit {
                intent,
                isolated_index,
                expected_tree,
            };
            self.validate_prepared(worktree, &prepared, &repo)?;
            return Ok(prepared);
        }
        create_private_directory(&staging_directory)?;
        let normal_index_backup = staging_directory.join("normal-index.backup");
        let index_bytes = fs::read(&normal_index.canonical_path).map_err(io_error)?;
        write_private_file(&normal_index_backup, &index_bytes)?;
        let manifest_bytes = serde_json::to_vec(&manifest)
            .map_err(|error| HostCommitError::Io(error.to_string()))?;
        write_private_file(&staging_directory.join("manifest.json"), &manifest_bytes)?;

        let mut index = IndexEnvironment::new(isolated_index.clone());
        self.git_status(
            &repo,
            "initialize isolated commit index",
            ["read-tree", &head],
            None,
            Some(&mut index),
        )?;
        self.reject_submodule_paths(&repo, &manifest)?;
        for (number, entry) in manifest.entries.iter().enumerate() {
            let path = Path::new(entry.path());
            let snapshot = snapshot_entry(manifest_root, path, entry, &staging_directory, number)?;
            match entry {
                ManifestEntry::Delete { .. } => {
                    self.git_status(
                        &repo,
                        "stage manifested deletion",
                        ["update-index", "--force-remove", "--", entry.path()],
                        None,
                        Some(&mut index),
                    )?;
                }
                ManifestEntry::Write { .. } | ManifestEntry::Symlink { .. } => {
                    let snapshot_bytes = fs::read(&snapshot).map_err(io_error)?;
                    let blob = self.git_text(
                        &repo,
                        "write manifest blob",
                        ["hash-object", "-w", "--stdin"],
                        Some(&snapshot_bytes),
                        Some(&mut index),
                    )?;
                    let mode = match entry {
                        ManifestEntry::Write { mode, .. } => mode.git_mode(),
                        ManifestEntry::Symlink { .. } => "120000",
                        _ => unreachable!(),
                    };
                    self.git_status(
                        &repo,
                        "stage manifested file",
                        [
                            "update-index",
                            "--add",
                            "--cacheinfo",
                            mode,
                            blob.trim(),
                            entry.path(),
                        ],
                        None,
                        Some(&mut index),
                    )?;
                }
            }
        }
        let expected_tree = self
            .git_text(
                &repo,
                "write requested tree",
                ["write-tree"],
                None,
                Some(&mut index),
            )?
            .trim()
            .to_owned();
        validate_object_id(&expected_tree)?;
        let intent = HostCommitIntent {
            schema_version: 1,
            operation_id,
            repository_id: worktree.repository_id.clone(),
            worktree_branch: worktree.branch.clone(),
            expected_head: head,
            manifest_digest,
            manifest,
            message,
            normal_index,
            normal_index_backup,
            staging_directory,
        };
        write_private_file(
            &intent.staging_directory.join("intent.json"),
            &serde_json::to_vec_pretty(&intent)
                .map_err(|error| HostCommitError::Io(error.to_string()))?,
        )?;
        Ok(PreparedHostCommit {
            intent,
            isolated_index,
            expected_tree,
        })
    }

    pub fn execute(
        &self,
        worktree: &ManagedWorktree,
        prepared: &PreparedHostCommit,
    ) -> Result<HostCommitReceipt, HostCommitError> {
        let repo = worktree.path.canonicalize().map_err(io_error)?;
        self.validate_prepared(worktree, prepared, &repo)?;
        let _lock = self.repository_lock(&worktree.repository_id)?;
        self.require_same_head(&repo, &prepared.intent.expected_head)?;
        self.require_same_index(&repo, &prepared.intent.normal_index)?;
        self.verify_prepared_tree(&repo, prepared)?;
        let mut environment = IndexEnvironment::new(prepared.isolated_index.clone());
        let _commit_output = self.git_text(
            &repo,
            "commit manifested tree",
            ["commit", "-S", "--file", "-"],
            Some(prepared.intent.message.as_bytes()),
            Some(&mut environment),
        )?;
        let observed_head = self
            .git_text(
                &repo,
                "resolve created commit",
                ["rev-parse", "--verify", "HEAD"],
                None,
                None,
            )?
            .trim()
            .to_owned();
        let actual_tree = self
            .git_text(
                &repo,
                "resolve created tree",
                [
                    "rev-parse",
                    "--verify",
                    &format!("{observed_head}^{{tree}}"),
                ],
                None,
                None,
            )?
            .trim()
            .to_owned();
        if actual_tree != prepared.expected_tree {
            return Err(HostCommitError::UnexpectedCommit {
                head: observed_head,
                expected_tree: prepared.expected_tree.clone(),
                actual_tree,
            });
        }
        let post_hook_status = self.git_status(
            &repo,
            "verify post-commit worktree",
            ["status", "--porcelain=v1", "--untracked-files=all"],
            None,
            Some(&mut IndexEnvironment::new(prepared.isolated_index.clone())),
        )?;
        if !post_hook_status.stdout.is_empty() {
            return Err(HostCommitError::Conflict(
                "Git hooks changed the worktree outside the requested tree".into(),
            ));
        }
        self.git_status(
            &repo,
            "verify host commit signature",
            ["verify-commit", &observed_head],
            None,
            None,
        )?;
        let index_synchronized = self
            .sync_normal_index(&repo, &observed_head, &prepared.intent.normal_index)
            .is_ok();
        Ok(HostCommitReceipt {
            operation_id: prepared.intent.operation_id.clone(),
            repository_id: prepared.intent.repository_id.clone(),
            expected_head: prepared.intent.expected_head.clone(),
            observed_head,
            tree: actual_tree,
            manifest_digest: prepared.intent.manifest_digest.clone(),
            signature_verified: true,
            hooks_completed: true,
            index_synchronized,
            index_sync_conflict: !index_synchronized,
        })
    }

    pub fn reconcile(
        &self,
        worktree: &ManagedWorktree,
        prepared: &PreparedHostCommit,
    ) -> Result<Option<HostCommitReceipt>, HostCommitError> {
        let repo = worktree.path.canonicalize().map_err(io_error)?;
        self.validate_prepared(worktree, prepared, &repo)?;
        let _lock = self.repository_lock(&worktree.repository_id)?;
        self.verify_prepared_tree(&repo, prepared)?;
        let head = self
            .git_text(
                &repo,
                "resolve current HEAD",
                ["rev-parse", "--verify", "HEAD"],
                None,
                None,
            )?
            .trim()
            .to_owned();
        if head == prepared.intent.expected_head {
            return Ok(None);
        }
        let parent = self
            .git_text(
                &repo,
                "resolve current commit parent",
                ["rev-parse", "--verify", &format!("{head}^{{commit}}")],
                None,
                None,
            )?
            .trim()
            .to_owned();
        let tree = self
            .git_text(
                &repo,
                "resolve current commit tree",
                ["rev-parse", "--verify", &format!("{head}^{{tree}}")],
                None,
                None,
            )?
            .trim()
            .to_owned();
        let message = self.git_text(
            &repo,
            "read current commit message",
            ["show", "-s", "--format=%B", &head],
            None,
            None,
        )?;
        if parent != prepared.intent.expected_head
            || tree != prepared.expected_tree
            || message != prepared.intent.message
        {
            return Err(HostCommitError::Conflict(
                "current HEAD is not the exact interrupted host commit".into(),
            ));
        }
        let worktree_status = self.git_status(
            &repo,
            "verify reconciled worktree",
            ["status", "--porcelain=v1", "--untracked-files=all"],
            None,
            Some(&mut IndexEnvironment::new(prepared.isolated_index.clone())),
        )?;
        if !worktree_status.stdout.is_empty() {
            return Err(HostCommitError::Conflict(
                "interrupted Git hooks left uncommitted worktree changes".into(),
            ));
        }
        self.git_status(
            &repo,
            "verify reconciled commit signature",
            ["verify-commit", &head],
            None,
            None,
        )?;
        let index_synchronized = self
            .sync_normal_index(&repo, &head, &prepared.intent.normal_index)
            .is_ok();
        Ok(Some(HostCommitReceipt {
            operation_id: prepared.intent.operation_id.clone(),
            repository_id: prepared.intent.repository_id.clone(),
            expected_head: prepared.intent.expected_head.clone(),
            observed_head: head,
            tree,
            manifest_digest: prepared.intent.manifest_digest.clone(),
            signature_verified: true,
            hooks_completed: true,
            index_synchronized,
            index_sync_conflict: !index_synchronized,
        }))
    }

    fn git_text<const N: usize>(
        &self,
        cwd: &Path,
        operation: &'static str,
        args: [&str; N],
        stdin: Option<&[u8]>,
        index: Option<&mut IndexEnvironment>,
    ) -> Result<String, HostCommitError> {
        let output = self.run_git(
            cwd,
            args.into_iter().map(OsString::from).collect(),
            stdin.unwrap_or_default().to_vec(),
            index,
        )?;
        check_output(operation, &output)?;
        if output.stdout_truncated {
            return Err(HostCommitError::Git(
                operation,
                "bounded output was truncated".into(),
            ));
        }
        String::from_utf8(output.stdout)
            .map_err(|_| HostCommitError::Git(operation, "Git output was not UTF-8".into()))
    }

    fn git_status<const N: usize>(
        &self,
        cwd: &Path,
        operation: &'static str,
        args: [&str; N],
        stdin: Option<&[u8]>,
        index: Option<&mut IndexEnvironment>,
    ) -> Result<ProcessOutput, HostCommitError> {
        let output = self.run_git(
            cwd,
            args.into_iter().map(OsString::from).collect(),
            stdin.unwrap_or_default().to_vec(),
            index,
        )?;
        check_output(operation, &output)?;
        Ok(output)
    }

    fn run_git(
        &self,
        cwd: &Path,
        args: Vec<OsString>,
        stdin: Vec<u8>,
        mut index: Option<&mut IndexEnvironment>,
    ) -> Result<ProcessOutput, HostCommitError> {
        let mut environment = self.options.git_environment.clone();
        environment.retain(|key, _| !key.to_string_lossy().starts_with("GIT_"));
        environment.insert("GIT_TERMINAL_PROMPT".into(), "0".into());
        if let Some(index) = index.as_mut() {
            environment.insert("GIT_INDEX_FILE".into(), index.path.clone().into_os_string());
        }
        process::run(ProcessRequest {
            executable: self.options.git_executable.clone(),
            args,
            stdin,
            cwd: Some(cwd.to_owned()),
            clear_environment: true,
            environment,
            timeout: self.options.timeout.min(GIT_TIMEOUT),
            shutdown_grace: SHUTDOWN_GRACE,
            stdout_limit: 4 * 1024 * 1024,
            stderr_tail_limit: 32 * 1024,
        })
        .map_err(|_| {
            HostCommitError::Git(
                "process",
                "Git process could not be completed safely".into(),
            )
        })
    }

    fn require_clean_index_and_manifest(
        &self,
        repo: &Path,
        head: &str,
        manifest: &ChangeManifest,
    ) -> Result<(), HostCommitError> {
        let index_result = self.git_status(
            repo,
            "check clean index",
            ["diff", "--cached", "--quiet", head],
            None,
            None,
        );
        if index_result.is_err() {
            return Err(HostCommitError::Conflict(
                "existing staged changes must be preserved; host commit stopped".into(),
            ));
        }
        let tracked = self.git_text(
            repo,
            "inspect changed tracked paths",
            ["diff", "--name-only", "-z", "HEAD", "--"],
            None,
            None,
        )?;
        let untracked = self.git_text(
            repo,
            "inspect untracked paths",
            ["ls-files", "--others", "--exclude-standard", "-z"],
            None,
            None,
        )?;
        let mut changed = tracked
            .as_bytes()
            .split(|byte| *byte == 0)
            .filter(|path| !path.is_empty())
            .map(|path| String::from_utf8_lossy(path).into_owned())
            .chain(
                untracked
                    .as_bytes()
                    .split(|byte| *byte == 0)
                    .filter(|path| !path.is_empty())
                    .map(|path| String::from_utf8_lossy(path).into_owned()),
            )
            .collect::<Vec<_>>();
        changed.sort();
        changed.dedup();
        let expected = manifest
            .entries
            .iter()
            .map(|entry| entry.path().to_owned())
            .collect::<Vec<_>>();
        if changed != expected {
            return Err(HostCommitError::Conflict(
                "manifest paths must cover every tracked and nonignored untracked change exactly"
                    .into(),
            ));
        }
        Ok(())
    }

    fn index_path(&self, repo: &Path) -> Result<PathBuf, HostCommitError> {
        let value = self.git_text(
            repo,
            "resolve normal index",
            ["rev-parse", "--git-path", "index"],
            None,
            None,
        )?;
        let path = PathBuf::from(value.trim());
        let path = if path.is_absolute() {
            path
        } else {
            repo.join(path)
        };
        let metadata = fs::symlink_metadata(&path).map_err(io_error)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(HostCommitError::Invalid(
                "normal Git index is not a regular file".into(),
            ));
        }
        path.canonicalize().map_err(io_error)
    }

    fn index_identity(&self, repo: &Path) -> Result<IndexIdentity, HostCommitError> {
        let path = self.index_path(repo)?;
        let before = fs::symlink_metadata(&path).map_err(io_error)?;
        let mut file = open_read_nofollow(&path)?;
        let metadata = file.metadata().map_err(io_error)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if before.dev() != metadata.dev() || before.ino() != metadata.ino() {
                return Err(HostCommitError::Conflict(
                    "normal Git index changed while opening".into(),
                ));
            }
        }
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(io_error)?;
        let after = fs::symlink_metadata(&path).map_err(io_error)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if after.dev() != metadata.dev() || after.ino() != metadata.ino() {
                return Err(HostCommitError::Conflict(
                    "normal Git index changed while reading".into(),
                ));
            }
        }
        #[cfg(unix)]
        let (device, inode) = {
            use std::os::unix::fs::MetadataExt;
            (metadata.dev(), metadata.ino())
        };
        #[cfg(not(unix))]
        let (device, inode) = (0, 0);
        Ok(IndexIdentity {
            canonical_path: path,
            device,
            inode,
            byte_count: bytes.len() as u64,
            digest: digest(&bytes),
        })
    }

    fn require_same_index(
        &self,
        repo: &Path,
        expected: &IndexIdentity,
    ) -> Result<(), HostCommitError> {
        let actual = self.index_identity(repo)?;
        if &actual != expected {
            return Err(HostCommitError::Conflict(
                "normal Git index changed after preparation".into(),
            ));
        }
        Ok(())
    }

    fn require_same_head(&self, repo: &Path, expected: &str) -> Result<(), HostCommitError> {
        let current = self.git_text(
            repo,
            "recheck HEAD",
            ["rev-parse", "--verify", "HEAD"],
            None,
            None,
        )?;
        if current.trim() != expected {
            return Err(HostCommitError::Conflict(
                "HEAD changed after host-commit preparation".into(),
            ));
        }
        Ok(())
    }

    fn validate_worktree_path(
        &self,
        worktree: &ManagedWorktree,
        canonical_path: &Path,
    ) -> Result<(), HostCommitError> {
        let suffix = worktree
            .branch
            .strip_prefix("rex-projects/")
            .ok_or_else(|| {
                HostCommitError::Invalid("worktree branch is not factory-managed".into())
            })?;
        if suffix.len() != 32 || !suffix.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(HostCommitError::Invalid(
                "worktree branch has an invalid stable identity".into(),
            ));
        }
        let expected = self
            .state_root
            .join("worktrees")
            .join(worktree.repository_id.as_str())
            .join(suffix)
            .canonicalize()
            .map_err(io_error)?;
        if expected != canonical_path {
            return Err(HostCommitError::Invalid(
                "worktree path does not match its repository and branch identity".into(),
            ));
        }
        Ok(())
    }

    fn validate_prepared(
        &self,
        worktree: &ManagedWorktree,
        prepared: &PreparedHostCommit,
        repo: &Path,
    ) -> Result<(), HostCommitError> {
        self.validate_worktree_path(worktree, repo)?;
        validate_prepared(worktree, prepared)?;
        let expected_directory = self
            .state_root
            .join("host-commits")
            .join(prepared.intent.operation_id.as_str());
        if prepared.intent.staging_directory != expected_directory
            || prepared.isolated_index != expected_directory.join("index")
        {
            return Err(HostCommitError::Invalid(
                "prepared host-commit paths are outside their operation staging directory".into(),
            ));
        }
        let canonical_stage = expected_directory.canonicalize().map_err(io_error)?;
        let stage_metadata = fs::symlink_metadata(&expected_directory).map_err(io_error)?;
        if !canonical_stage.starts_with(self.state_root.join("host-commits"))
            || stage_metadata.file_type().is_symlink()
            || !stage_metadata.is_dir()
        {
            return Err(HostCommitError::Invalid(
                "prepared host-commit staging directory is not private state".into(),
            ));
        }
        if prepared.intent.normal_index_backup != expected_directory.join("normal-index.backup") {
            return Err(HostCommitError::Invalid(
                "prepared index backup path is outside its operation staging directory".into(),
            ));
        }
        let backup_metadata =
            fs::symlink_metadata(&prepared.intent.normal_index_backup).map_err(io_error)?;
        if backup_metadata.file_type().is_symlink() || !backup_metadata.is_file() {
            return Err(HostCommitError::Invalid(
                "normal index backup is not a regular private file".into(),
            ));
        }
        let backup = fs::read(&prepared.intent.normal_index_backup).map_err(io_error)?;
        if backup.len() as u64 != prepared.intent.normal_index.byte_count
            || digest(&backup) != prepared.intent.normal_index.digest
        {
            return Err(HostCommitError::Conflict(
                "normal index backup does not match its prepared identity".into(),
            ));
        }
        Ok(())
    }

    fn verify_prepared_tree(
        &self,
        repo: &Path,
        prepared: &PreparedHostCommit,
    ) -> Result<(), HostCommitError> {
        let current_tree = self.git_text(
            repo,
            "verify isolated index tree",
            ["write-tree"],
            None,
            Some(&mut IndexEnvironment::new(prepared.isolated_index.clone())),
        )?;
        if current_tree.trim() != prepared.expected_tree {
            return Err(HostCommitError::Conflict(
                "prepared isolated index no longer matches its recorded tree".into(),
            ));
        }
        Ok(())
    }

    fn sync_normal_index(
        &self,
        repo: &Path,
        new_head: &str,
        expected: &IndexIdentity,
    ) -> Result<(), HostCommitError> {
        self.require_same_index(repo, expected)?;
        let normal_index = self.index_path(repo)?;
        let replacement = expected
            .canonical_path
            .with_extension(format!("index.rex-projects-{}", std::process::id()));
        let mut index = IndexEnvironment::new(replacement.clone());
        self.git_status(
            repo,
            "prepare synchronized index",
            ["read-tree", new_head],
            None,
            Some(&mut index),
        )?;
        self.require_same_index(repo, expected)?;
        fs::rename(&replacement, &normal_index).map_err(io_error)?;
        Ok(())
    }

    fn reject_submodule_paths(
        &self,
        repo: &Path,
        manifest: &ChangeManifest,
    ) -> Result<(), HostCommitError> {
        let output = self.git_text(
            repo,
            "inspect index entries",
            ["ls-files", "--stage", "-z"],
            None,
            None,
        )?;
        let mut submodules = Vec::new();
        for record in output
            .as_bytes()
            .split(|byte| *byte == 0)
            .filter(|record| !record.is_empty())
        {
            let Some(separator) = record.iter().position(|byte| *byte == b'\t') else {
                continue;
            };
            let (metadata, path_with_tab) = record.split_at(separator);
            let path = &path_with_tab[1..];
            if metadata.starts_with(b"160000 ") {
                submodules.push(String::from_utf8_lossy(path).into_owned());
            }
        }
        for entry in &manifest.entries {
            if submodules
                .iter()
                .any(|path| entry.path() == path || entry.path().starts_with(&format!("{path}/")))
            {
                return Err(HostCommitError::Invalid(
                    "manifest may not modify a submodule or its contents".into(),
                ));
            }
        }
        Ok(())
    }

    fn repository_lock(&self, id: &RepositoryId) -> Result<File, HostCommitError> {
        let locks = self.state_root.join("locks");
        create_private_directory(&locks)?;
        let path = locks.join(format!("repository-{id}.lock"));
        let mut options = OpenOptions::new();
        options.create(true).truncate(false).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(path).map_err(io_error)?;
        file.lock_exclusive().map_err(io_error)?;
        Ok(file)
    }
}

struct IndexEnvironment {
    path: PathBuf,
}
impl IndexEnvironment {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

fn validate_prepared(
    worktree: &ManagedWorktree,
    prepared: &PreparedHostCommit,
) -> Result<(), HostCommitError> {
    if prepared.intent.repository_id != worktree.repository_id
        || prepared.intent.worktree_branch != worktree.branch
        || prepared.intent.expected_head != worktree.base_sha
        || prepared.intent.schema_version != 1
        || prepared.intent.manifest.schema_version != 1
        || prepared.intent.message.trim().is_empty()
        || prepared.intent.message.contains('\0')
    {
        return Err(HostCommitError::Invalid(
            "prepared host-commit identity does not match the worktree".into(),
        ));
    }
    validate_object_id(&prepared.intent.expected_head)?;
    validate_object_id(&prepared.expected_tree)?;
    validate_manifest(&prepared.intent.manifest)?;
    if manifest_digest(&prepared.intent.manifest)? != prepared.intent.manifest_digest {
        return Err(HostCommitError::Invalid(
            "prepared manifest digest is inconsistent".into(),
        ));
    }
    Ok(())
}

fn validate_manifest(manifest: &ChangeManifest) -> Result<(), HostCommitError> {
    if manifest.schema_version != 1
        || manifest.entries.is_empty()
        || manifest.entries.len() > MAX_MANIFEST_ENTRIES
    {
        return Err(HostCommitError::Invalid(
            "unsupported manifest version or entry count".into(),
        ));
    }
    let mut previous: Option<&str> = None;
    for entry in &manifest.entries {
        validate_relative_path(entry.path())?;
        if previous.is_some_and(|old| old >= entry.path()) {
            return Err(HostCommitError::Invalid(
                "manifest entries must be uniquely sorted by path".into(),
            ));
        }
        previous = Some(entry.path());
        match entry {
            ManifestEntry::Write { byte_count, .. }
            | ManifestEntry::Symlink {
                target_byte_count: byte_count,
                ..
            } if *byte_count > MAX_FILE_BYTES => {
                return Err(HostCommitError::Invalid(
                    "manifest file exceeds the configured size limit".into(),
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

fn validate_relative_path(value: &str) -> Result<(), HostCommitError> {
    let path = Path::new(value);
    if value.is_empty()
        || value.contains('\0')
        || value.contains('\\')
        || path.is_absolute()
        || value
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(HostCommitError::Invalid(
            "manifest path must be a clean relative path".into(),
        ));
    }
    for component in path.components() {
        let Component::Normal(part) = component else {
            unreachable!()
        };
        let part = part.to_string_lossy();
        if part.eq_ignore_ascii_case(".git")
            || part.eq_ignore_ascii_case(".rex-projects-mailbox")
            || part.eq_ignore_ascii_case(".rex-projects")
        {
            return Err(HostCommitError::Invalid(
                "manifest path names a reserved Git or mailbox location".into(),
            ));
        }
    }
    Ok(())
}

fn snapshot_entry(
    root: &Path,
    relative: &Path,
    entry: &ManifestEntry,
    staging: &Path,
    number: usize,
) -> Result<PathBuf, HostCommitError> {
    let root = root.canonicalize().map_err(io_error)?;
    let mut path = root.clone();
    let components = relative.components().collect::<Vec<_>>();
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(part) = component else {
            return Err(HostCommitError::Invalid(
                "manifest path escapes worker workspace".into(),
            ));
        };
        path.push(part);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if index + 1 < components.len() && metadata.file_type().is_symlink() => {
                return Err(HostCommitError::Invalid(
                    "manifest path traverses a symlink parent".into(),
                ));
            }
            Ok(_) => {}
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound
                    && index + 1 == components.len() =>
            {
                break;
            }
            Err(error) => return Err(io_error(error)),
        }
    }
    let bytes = match entry {
        ManifestEntry::Write {
            mode,
            sha256,
            byte_count,
            ..
        } => {
            let bytes = read_regular_nofollow(&path, *byte_count, *mode)?;
            if digest(&bytes) != *sha256 {
                return Err(HostCommitError::Conflict(
                    "manifest file digest does not match its snapshot".into(),
                ));
            }
            bytes
        }
        ManifestEntry::Symlink {
            target_sha256,
            target_byte_count,
            ..
        } => {
            let metadata = fs::symlink_metadata(&path).map_err(io_error)?;
            if !metadata.file_type().is_symlink() {
                return Err(HostCommitError::Conflict(
                    "manifest symlink entry is not a symlink".into(),
                ));
            }
            let target = fs::read_link(&path).map_err(io_error)?;
            let after = fs::symlink_metadata(&path).map_err(io_error)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if metadata.dev() != after.dev() || metadata.ino() != after.ino() {
                    return Err(HostCommitError::Conflict(
                        "manifest symlink changed while reading".into(),
                    ));
                }
            }
            if target.is_absolute()
                || target.components().any(|component| {
                    matches!(
                        component,
                        Component::ParentDir | Component::RootDir | Component::Prefix(_)
                    )
                })
            {
                return Err(HostCommitError::Invalid(
                    "symlink target must stay within the worktree".into(),
                ));
            }
            let bytes = os_path_bytes(&target);
            if bytes.len() as u64 != *target_byte_count || digest(&bytes) != *target_sha256 {
                return Err(HostCommitError::Conflict(
                    "manifest symlink target digest does not match its snapshot".into(),
                ));
            }
            bytes
        }
        ManifestEntry::Delete { .. } => {
            if path.exists() || fs::symlink_metadata(&path).is_ok() {
                return Err(HostCommitError::Conflict(
                    "manifest deletion path still exists in worker workspace".into(),
                ));
            }
            return Ok(staging.join(format!("snapshot-{number}")));
        }
    };
    let snapshot = staging.join(format!("snapshot-{number}"));
    write_private_file(&snapshot, &bytes)?;
    Ok(snapshot)
}

fn read_regular_nofollow(
    path: &Path,
    expected_len: u64,
    expected_mode: FileMode,
) -> Result<Vec<u8>, HostCommitError> {
    let before = fs::symlink_metadata(path).map_err(io_error)?;
    if !before.is_file() || before.file_type().is_symlink() || before.len() != expected_len {
        return Err(HostCommitError::Invalid(
            "manifest write path must be a regular file with matching size".into(),
        ));
    }
    let file = open_read_nofollow(path)?;
    let opened = file.metadata().map_err(io_error)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if opened.dev() != before.dev() || opened.ino() != before.ino() {
            return Err(HostCommitError::Conflict(
                "manifest path changed while opening".into(),
            ));
        }
        let executable = opened.mode() & 0o111 != 0;
        if executable != matches!(expected_mode, FileMode::Executable0755) {
            return Err(HostCommitError::Conflict(
                "manifest file mode does not match its executable-bit declaration".into(),
            ));
        }
    }
    let mut bytes = Vec::with_capacity(expected_len.min(MAX_FILE_BYTES) as usize);
    file.take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if bytes.len() as u64 != expected_len || bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(HostCommitError::Conflict(
            "manifest file size changed while reading".into(),
        ));
    }
    let after = fs::symlink_metadata(path).map_err(io_error)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if after.dev() != opened.dev() || after.ino() != opened.ino() {
            return Err(HostCommitError::Conflict(
                "manifest path changed while reading".into(),
            ));
        }
    }
    Ok(bytes)
}

fn open_read_nofollow(path: &Path) -> Result<File, HostCommitError> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(target_os = "macos")]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(0x100);
        }
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(0x20000);
        }
        options.open(path).map_err(io_error)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = path;
        Err(HostCommitError::Invalid(
            "no-follow file opening is unsupported on this platform".into(),
        ))
    }
}

fn manifest_digest(manifest: &ChangeManifest) -> Result<Digest, HostCommitError> {
    let bytes =
        serde_json::to_vec(manifest).map_err(|error| HostCommitError::Io(error.to_string()))?;
    Ok(digest(&bytes))
}

fn digest(bytes: &[u8]) -> Digest {
    let hash = Sha256::digest(bytes);
    let mut text = String::with_capacity(64);
    for byte in hash {
        text.push(char::from(b"0123456789abcdef"[(byte >> 4) as usize]));
        text.push(char::from(b"0123456789abcdef"[(byte & 15) as usize]));
    }
    Digest::parse(text).expect("SHA-256 is valid")
}

fn validate_object_id(value: &str) -> Result<(), HostCommitError> {
    if !matches!(value.len(), 40 | 64) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(HostCommitError::Conflict(
            "Git returned invalid object ID".into(),
        ));
    }
    Ok(())
}

fn check_output(operation: &'static str, output: &ProcessOutput) -> Result<(), HostCommitError> {
    if output.timed_out
        || !output.cleanup_confirmed
        || output.status.is_none_or(|status| !status.success())
    {
        return Err(HostCommitError::Git(
            operation,
            "command failed or its cleanup outcome is unknown".into(),
        ));
    }
    Ok(())
}

fn create_private_directory(path: &Path) -> Result<(), HostCommitError> {
    fs::create_dir_all(path).map_err(io_error)?;
    let metadata = fs::symlink_metadata(path).map_err(io_error)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(HostCommitError::Invalid(
            "private staging path is not a real directory".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(io_error)?;
    }
    Ok(())
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), HostCommitError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(io_error)?;
    file.write_all(bytes).map_err(io_error)?;
    file.sync_all().map_err(io_error)
}

fn os_path_bytes(path: &Path) -> Vec<u8> {
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

fn io_error(error: std::io::Error) -> HostCommitError {
    HostCommitError::Io(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        _temp: tempfile::TempDir,
        worktree: ManagedWorktree,
        committer: HostCommitter,
        environment: BTreeMap<OsString, OsString>,
    }

    fn run(
        executable: &Path,
        cwd: &Path,
        args: &[&str],
        input: &[u8],
        env: &BTreeMap<OsString, OsString>,
    ) -> ProcessOutput {
        process::run(ProcessRequest {
            executable: executable.to_owned(),
            args: args.iter().map(OsString::from).collect(),
            stdin: input.to_vec(),
            cwd: Some(cwd.to_owned()),
            clear_environment: true,
            environment: env.clone(),
            timeout: Duration::from_secs(45),
            shutdown_grace: Duration::from_secs(3),
            stdout_limit: 1024 * 1024,
            stderr_tail_limit: 32 * 1024,
        })
        .unwrap()
    }

    fn successful_git(cwd: &Path, args: &[&str], env: &BTreeMap<OsString, OsString>) -> String {
        let result = run(Path::new("/usr/bin/git"), cwd, args, &[], env);
        assert!(
            result.status.is_some_and(|status| status.success()),
            "fixture Git operation failed: {args:?}"
        );
        String::from_utf8(result.stdout).unwrap()
    }

    fn fixture() -> Fixture {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let gpg_home = home.join("gnupg");
        let state = temp.path().join("state");
        let repo = state.join("worktrees/sample-repo/0123456789abcdef0123456789abcdef");
        fs::create_dir_all(&repo).unwrap();
        fs::create_dir_all(&home).unwrap();
        create_private_directory(&gpg_home).unwrap();
        let path_environment = std::env::var_os("PATH").unwrap_or_default();
        let environment: BTreeMap<OsString, OsString> = [
            (OsString::from("HOME"), home.clone().into_os_string()),
            (
                OsString::from("GNUPGHOME"),
                gpg_home.clone().into_os_string(),
            ),
            (OsString::from("PATH"), path_environment.clone()),
        ]
        .into_iter()
        .collect();
        let gpg = process::resolve_executable(
            Path::new("gpg"),
            &std::env::split_paths(&path_environment).collect::<Vec<_>>(),
        );
        let Some(gpg) = gpg else {
            panic!("gpg is required for the signed host-commit fixture")
        };
        let generated = run(
            &gpg,
            &home,
            &[
                "--batch",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--quick-generate-key",
                "Rex Projects Fixture <rex-projects-fixture@example.invalid>",
                "ed25519",
                "sign",
                "1d",
            ],
            &[],
            &environment,
        );
        assert!(
            generated.status.is_some_and(|status| status.success()),
            "fixture GPG key generation failed"
        );
        let keys = run(
            &gpg,
            &home,
            &["--batch", "--with-colons", "--list-secret-keys"],
            &[],
            &environment,
        );
        assert!(keys.status.is_some_and(|status| status.success()));
        let fingerprint = String::from_utf8(keys.stdout)
            .unwrap()
            .lines()
            .find_map(|line| {
                let mut fields = line.split(':');
                (fields.next() == Some("fpr")).then(|| fields.nth(8).unwrap_or_default().to_owned())
            })
            .filter(|value| !value.is_empty())
            .unwrap();
        successful_git(
            &home,
            &["config", "--global", "user.name", "Rex Projects Fixture"],
            &environment,
        );
        successful_git(
            &home,
            &[
                "config",
                "--global",
                "user.email",
                "rex-projects-fixture@example.invalid",
            ],
            &environment,
        );
        successful_git(
            &home,
            &["config", "--global", "user.signingkey", &fingerprint],
            &environment,
        );
        successful_git(
            &home,
            &["config", "--global", "commit.gpgsign", "false"],
            &environment,
        );
        successful_git(&repo, &["init", "-b", "main"], &environment);
        fs::write(repo.join("README.md"), b"initial\n").unwrap();
        successful_git(&repo, &["add", "README.md"], &environment);
        successful_git(
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
                "base",
            ],
            &environment,
        );
        let head = successful_git(&repo, &["rev-parse", "HEAD"], &environment)
            .trim()
            .to_owned();
        let git = PathBuf::from("/usr/bin/git");
        let committer = HostCommitter::new(HostCommitOptions {
            git_executable: git,
            git_environment: environment.clone(),
            state_root: state,
            timeout: Duration::from_secs(45),
        })
        .unwrap();
        Fixture {
            _temp: temp,
            worktree: ManagedWorktree {
                repository_id: RepositoryId::parse("sample-repo").unwrap(),
                path: repo,
                branch: "rex-projects/0123456789abcdef0123456789abcdef".into(),
                base_sha: head,
            },
            committer,
            environment,
        }
    }

    fn write_entry(path: &str, bytes: &[u8], mode: FileMode) -> ManifestEntry {
        ManifestEntry::Write {
            path: path.into(),
            mode,
            sha256: digest(bytes),
            byte_count: bytes.len() as u64,
        }
    }

    fn manifest(entries: Vec<ManifestEntry>) -> ChangeManifest {
        ChangeManifest {
            schema_version: 1,
            entries,
        }
    }

    #[cfg(unix)]
    #[test]
    fn host_commit_snapshots_write_delete_executable_and_symlink_and_signs_commit() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let fixture = fixture();
        let repo = &fixture.worktree.path;
        fs::remove_file(repo.join("README.md")).unwrap();
        fs::create_dir_all(repo.join("bin")).unwrap();
        fs::write(repo.join("new.txt"), b"new contents\n").unwrap();
        fs::write(repo.join("bin/tool"), b"#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(repo.join("bin/tool"), fs::Permissions::from_mode(0o755)).unwrap();
        symlink("new.txt", repo.join("link")).unwrap();
        let link_bytes = b"new.txt";
        let manifest = manifest(vec![
            ManifestEntry::Delete {
                path: "README.md".into(),
            },
            write_entry("bin/tool", b"#!/bin/sh\nexit 0\n", FileMode::Executable0755),
            ManifestEntry::Symlink {
                path: "link".into(),
                target_sha256: digest(link_bytes),
                target_byte_count: link_bytes.len() as u64,
            },
            write_entry("new.txt", b"new contents\n", FileMode::Regular0644),
        ]);
        let prepared = fixture
            .committer
            .prepare(
                &fixture.worktree,
                OperationId::parse("op-1").unwrap(),
                manifest,
                repo,
                "feat: apply manifest\n\nCo-authored-by: Codex <noreply@openai.com>\n".into(),
            )
            .unwrap();
        let recovered = fixture
            .committer
            .prepare(
                &fixture.worktree,
                OperationId::parse("op-1").unwrap(),
                prepared.intent.manifest.clone(),
                repo,
                prepared.intent.message.clone(),
            )
            .unwrap();
        assert_eq!(recovered.expected_tree, prepared.expected_tree);
        let receipt = fixture
            .committer
            .execute(&fixture.worktree, &recovered)
            .unwrap();
        assert!(receipt.signature_verified);
        assert!(receipt.index_synchronized);
        assert_eq!(receipt.tree, prepared.expected_tree);
        assert!(
            fs::symlink_metadata(repo.join("link"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(!repo.join("README.md").exists());
    }

    #[test]
    fn refuses_existing_staged_changes_and_index_change_after_prepare() {
        let fixture = fixture();
        let repo = &fixture.worktree.path;
        fs::write(repo.join("new.txt"), b"new\n").unwrap();
        let manifest = manifest(vec![write_entry(
            "new.txt",
            b"new\n",
            FileMode::Regular0644,
        )]);
        successful_git(repo, &["add", "new.txt"], &fixture.environment);
        assert!(
            fixture
                .committer
                .prepare(
                    &fixture.worktree,
                    OperationId::parse("op-2").unwrap(),
                    manifest.clone(),
                    repo,
                    "feat: apply manifest".into()
                )
                .is_err()
        );
        successful_git(repo, &["reset", "--", "new.txt"], &fixture.environment);
        let prepared = fixture
            .committer
            .prepare(
                &fixture.worktree,
                OperationId::parse("op-3").unwrap(),
                manifest,
                repo,
                "feat: apply manifest".into(),
            )
            .unwrap();
        fs::write(repo.join("other.txt"), b"parallel change\n").unwrap();
        successful_git(repo, &["add", "other.txt"], &fixture.environment);
        assert!(
            fixture
                .committer
                .execute(&fixture.worktree, &prepared)
                .is_err()
        );
        let current = successful_git(repo, &["rev-parse", "HEAD"], &fixture.environment);
        assert_eq!(current.trim(), fixture.worktree.base_sha);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_parent_escape_and_reserved_paths() {
        use std::os::unix::fs::symlink;
        let fixture = fixture();
        let repo = &fixture.worktree.path;
        let outside = fixture._temp.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("file"), b"content").unwrap();
        symlink(&outside, repo.join("linked-dir")).unwrap();
        let manifest = manifest(vec![write_entry(
            "linked-dir/file",
            b"content",
            FileMode::Regular0644,
        )]);
        assert!(
            fixture
                .committer
                .prepare(
                    &fixture.worktree,
                    OperationId::parse("op-4").unwrap(),
                    manifest,
                    repo,
                    "feat: apply manifest".into()
                )
                .is_err()
        );
        assert!(validate_relative_path(".Git/config").is_err());
        assert!(validate_relative_path("../escape").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn detects_git_hook_source_mutation_after_signed_commit() {
        use std::os::unix::fs::PermissionsExt;
        let fixture = fixture();
        let repo = &fixture.worktree.path;
        fs::write(repo.join("new.txt"), b"new\n").unwrap();
        let hooks = fixture._temp.path().join("hooks");
        fs::create_dir(&hooks).unwrap();
        let pre_commit = hooks.join("pre-commit");
        fs::write(&pre_commit, "#!/bin/sh\nprintf changed >> new.txt\n").unwrap();
        fs::set_permissions(&pre_commit, fs::Permissions::from_mode(0o755)).unwrap();
        successful_git(
            repo,
            &["config", "core.hooksPath", hooks.to_str().unwrap()],
            &fixture.environment,
        );
        let manifest = manifest(vec![write_entry(
            "new.txt",
            b"new\n",
            FileMode::Regular0644,
        )]);
        let prepared = fixture
            .committer
            .prepare(
                &fixture.worktree,
                OperationId::parse("op-5").unwrap(),
                manifest,
                repo,
                "feat: apply manifest".into(),
            )
            .unwrap();
        assert!(matches!(
            fixture.committer.execute(&fixture.worktree, &prepared),
            Err(HostCommitError::Conflict(_))
        ));
        assert!(
            fixture
                .committer
                .reconcile(&fixture.worktree, &prepared)
                .is_err()
        );
    }
}
