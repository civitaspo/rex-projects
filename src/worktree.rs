//! Git worktrees that give each Ticket its own checkout.

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::config::Config;
use crate::paths::Paths;
use crate::store::Store;

/// The branch a Ticket's worktree is on.
pub fn branch(ticket_id: &str) -> String {
    format!("rxp/{ticket_id}")
}

fn git(repo: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .context("failed to run git")?;
    if !output.status.success() {
        bail!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn branch_exists(repo: &Path, branch: &str) -> bool {
    git(
        repo,
        &[
            "rev-parse",
            "--verify",
            "--quiet",
            &format!("refs/heads/{branch}"),
        ],
    )
    .is_ok()
}

/// Creates the worktree at `dir` on `branch`, starting from `base` or the
/// repository's `HEAD`. Reuses an existing worktree or branch.
pub fn ensure(repo: &Path, dir: &Path, branch: &str, base: Option<&str>) -> Result<()> {
    if dir.join(".git").exists() {
        return Ok(());
    }
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    // Forget worktrees whose directories were deleted by hand.
    git(repo, &["worktree", "prune"])?;
    let dir = dir.to_str().context("worktree path is not UTF-8")?;
    if branch_exists(repo, branch) {
        git(repo, &["worktree", "add", dir, branch])?;
    } else {
        git(
            repo,
            &["worktree", "add", "-b", branch, dir, base.unwrap_or("HEAD")],
        )?;
    }
    Ok(())
}

/// Removes the worktree and its branch, refusing when that would lose work:
/// uncommitted changes, or commits that are neither on a remote nor on `base`.
pub fn remove(repo: &Path, dir: &Path, branch: &str, base: Option<&str>) -> Result<()> {
    if dir.exists() {
        let status = git(dir, &["status", "--porcelain"])?;
        if !status.is_empty() {
            bail!(
                "{} has uncommitted changes; commit or discard them first",
                dir.display()
            );
        }
    }
    if branch_exists(repo, branch) {
        let base = base.unwrap_or("HEAD");
        let unpushed = git(repo, &["rev-list", branch, "--not", "--remotes", base])?;
        if !unpushed.is_empty() {
            bail!(
                "branch {branch} has {} commit(s) that are not on any remote; push them first",
                unpushed.lines().count()
            );
        }
    }
    if dir.exists() {
        let dir = dir.to_str().context("worktree path is not UTF-8")?;
        git(repo, &["worktree", "remove", dir])?;
    }
    if branch_exists(repo, branch) {
        git(repo, &["branch", "-D", branch])?;
    }
    Ok(())
}

/// Removes the worktree of an ended Ticket whose Agents have all exited.
pub fn cleanup_ticket(paths: &Paths, config: &Config, store: &Store, id: &str) -> Result<()> {
    let ticket = store
        .ticket(id)?
        .with_context(|| format!("ticket {id} does not exist"))?;
    if !ticket.state.is_terminal() {
        bail!(
            "ticket {id} is {}; only ended Tickets can be cleaned up",
            ticket.state
        );
    }
    if let Some(agent) = store
        .agents_for_ticket(id)?
        .into_iter()
        .find(|a| a.state != "exited")
    {
        bail!("agent {} is still running; close its block first", agent.id);
    }
    let project = config.project(&ticket.project_id)?;
    remove(
        &project.repo,
        &paths.worktree_dir(&project.id, id),
        &branch(id),
        project.base_branch.as_deref(),
    )
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Creates a repository with one commit.
    pub(crate) fn temp_repo() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        for args in [
            &["init", "-q", "-b", "main"][..],
            &["config", "user.email", "test@example.com"],
            &["config", "user.name", "Test"],
            &["config", "commit.gpgsign", "false"],
            &["commit", "-q", "--allow-empty", "-m", "init"],
        ] {
            git(repo, args).unwrap();
        }
        dir
    }

    #[test]
    fn creates_reuses_and_removes_worktrees() {
        let repo = temp_repo();
        let state = tempfile::tempdir().unwrap();
        let dir = state.path().join("demo/demo-1");
        let branch = branch("demo-1");

        ensure(repo.path(), &dir, &branch, None).unwrap();
        assert!(dir.join(".git").exists());
        assert_eq!(git(&dir, &["branch", "--show-current"]).unwrap(), branch);
        ensure(repo.path(), &dir, &branch, Some("main")).unwrap();

        // A deleted directory is recreated from the existing branch.
        std::fs::remove_dir_all(&dir).unwrap();
        ensure(repo.path(), &dir, &branch, None).unwrap();
        assert!(dir.join(".git").exists());

        std::fs::write(dir.join("file"), "x").unwrap();
        assert!(remove(repo.path(), &dir, &branch, None).is_err());
        git(&dir, &["add", "file"]).unwrap();
        git(&dir, &["commit", "-q", "-m", "work"]).unwrap();
        let err = remove(repo.path(), &dir, &branch, None).unwrap_err();
        assert!(err.to_string().contains("not on any remote"), "{err}");

        git(&dir, &["reset", "-q", "--hard", "main"]).unwrap();
        remove(repo.path(), &dir, &branch, None).unwrap();
        assert!(!dir.exists());
        assert!(!branch_exists(repo.path(), &branch));
    }
}
