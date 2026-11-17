//! Git worktrees that give each Ticket its own checkout.

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::config::Config;
use crate::paths::Paths;
use crate::store::Store;

/// The branch a Ticket's worktree is on.
pub fn branch(ticket_id: &str) -> String {
    format!("rex-projects/{ticket_id}")
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
/// uncommitted changes, commits that are neither on a remote nor on `base`,
/// or ignored files such as `.env`, unless `discard_ignored` is set.
pub fn remove(
    repo: &Path,
    dir: &Path,
    branch: &str,
    base: Option<&str>,
    discard_ignored: bool,
) -> Result<()> {
    if dir.exists() {
        let status = git(dir, &["status", "--porcelain"])?;
        if !status.is_empty() {
            bail!(
                "{} has uncommitted changes; commit or discard them first",
                dir.display()
            );
        }
        let ignored = git(dir, &["status", "--porcelain", "--ignored"])?;
        let ignored: Vec<&str> = ignored
            .lines()
            .filter_map(|l| l.strip_prefix("!! "))
            .collect();
        if !ignored.is_empty() && !discard_ignored {
            let shown = ignored
                .iter()
                .take(10)
                .copied()
                .collect::<Vec<_>>()
                .join(", ");
            let more = ignored.len().saturating_sub(10);
            let more = if more > 0 {
                format!(" and {more} more")
            } else {
                String::new()
            };
            bail!(
                "{} has ignored files that cleanup would delete: {shown}{more}; \
                 move anything you need out of it, then rerun with --discard-ignored",
                dir.display()
            );
        }
    }
    let base = base.unwrap_or("HEAD");
    // Check what the worktree actually has checked out, which may be another
    // branch than `branch` (one named before a rename) or a detached HEAD.
    let mut branches = vec![branch.to_owned()];
    if dir.exists() {
        let head = git(dir, &["rev-parse", "HEAD"])?;
        refuse_unpushed(repo, &head, &format!("the HEAD of {}", dir.display()), base)?;
        if let Ok(current) = git(dir, &["symbolic-ref", "--short", "-q", "HEAD"])
            && !current.is_empty()
            && current != branch
        {
            branches.push(current);
        }
    }
    for b in &branches {
        if branch_exists(repo, b) {
            refuse_unpushed(repo, b, &format!("branch {b}"), base)?;
        }
    }
    if dir.exists() {
        let dir = dir.to_str().context("worktree path is not UTF-8")?;
        git(repo, &["worktree", "remove", dir])?;
    }
    for b in &branches {
        if branch_exists(repo, b) {
            git(repo, &["branch", "-D", b])?;
        }
    }
    Ok(())
}

fn refuse_unpushed(repo: &Path, rev: &str, what: &str, base: &str) -> Result<()> {
    let unpushed = git(repo, &["rev-list", rev, "--not", "--remotes", base])?;
    if !unpushed.is_empty() {
        bail!(
            "{what} has {} commit(s) that are not on any remote; push them first",
            unpushed.lines().count()
        );
    }
    Ok(())
}

/// Removes the worktree of an ended Ticket whose Agents have all exited.
pub fn cleanup_ticket(
    paths: &Paths,
    config: &Config,
    store: &Store,
    id: &str,
    discard_ignored: bool,
) -> Result<()> {
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
        discard_ignored,
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
    fn checks_the_branch_the_worktree_is_on() {
        let repo = temp_repo();
        let state = tempfile::tempdir().unwrap();
        let dir = state.path().join("demo/demo-1");
        // A worktree created under the old branch name, before the rename.
        ensure(repo.path(), &dir, "rxp/demo-1", None).unwrap();
        git(&dir, &["commit", "-q", "--allow-empty", "-m", "work"]).unwrap();

        let err = remove(repo.path(), &dir, &branch("demo-1"), None, false).unwrap_err();
        assert!(err.to_string().contains("not on any remote"), "{err}");
        assert!(dir.exists());

        git(&dir, &["update-ref", "refs/remotes/origin/x", "HEAD"]).unwrap();
        remove(repo.path(), &dir, &branch("demo-1"), None, false).unwrap();
        assert!(!dir.exists());
        assert!(!branch_exists(repo.path(), "rxp/demo-1"));
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
        assert!(remove(repo.path(), &dir, &branch, None, false).is_err());
        git(&dir, &["add", "file"]).unwrap();
        git(&dir, &["commit", "-q", "-m", "work"]).unwrap();
        let err = remove(repo.path(), &dir, &branch, None, false).unwrap_err();
        assert!(err.to_string().contains("not on any remote"), "{err}");

        git(&dir, &["reset", "-q", "--hard", "main"]).unwrap();
        std::fs::write(dir.join(".gitignore"), ".env\n").unwrap();
        git(&dir, &["add", ".gitignore"]).unwrap();
        git(&dir, &["commit", "-q", "-m", "ignore"]).unwrap();
        git(&dir, &["update-ref", "refs/remotes/origin/x", "HEAD"]).unwrap();
        std::fs::write(dir.join(".env"), "SECRET=1").unwrap();
        let err = remove(repo.path(), &dir, &branch, None, false).unwrap_err();
        assert!(err.to_string().contains("ignored files"), "{err}");
        assert!(err.to_string().contains(".env"), "{err}");
        assert!(dir.join(".env").exists());
        remove(repo.path(), &dir, &branch, None, true).unwrap();
        assert!(!dir.exists());
        assert!(!branch_exists(repo.path(), &branch));
    }
}
