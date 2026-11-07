#!/usr/bin/env python3
"""Create one disposable local bare remote and seed clone under a new root."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


class FixtureError(RuntimeError):
    pass


def git(*args: str, cwd: Path | None = None, input_text: str | None = None,
        env: dict[str, str] | None = None) -> str:
    result = subprocess.run(
        ["git", *args], cwd=cwd, text=True, input=input_text, capture_output=True,
        check=False, timeout=20, env=env
    )
    if result.returncode:
        raise FixtureError(f"git {args[0]} failed ({result.returncode}): {result.stderr.strip()}")
    return result.stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path, help="New disposable directory; must not exist")
    parser.add_argument("--repository", default="service", help="Safe repository directory name")
    args = parser.parse_args()

    if not args.repository or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for ch in args.repository):
        parser.error("--repository may contain only ASCII letters, digits, '-' and '_'")
    root = args.root.expanduser().absolute()
    if root.exists() or root.is_symlink():
        parser.error(f"refusing to reuse existing fixture root: {root}")
    if not root.parent.is_dir():
        parser.error(f"fixture parent must already exist: {root.parent}")

    try:
        root.mkdir(mode=0o700)
        remote = root / f"{args.repository}.git"
        seed = root / f"{args.repository}-seed"
        git("init", "--bare", str(remote))
        with tempfile.NamedTemporaryFile(prefix="rex-projects-fixture-index-", dir=root, delete=False) as index_file:
            index_path = Path(index_file.name)
        env = {**os.environ, "GIT_INDEX_FILE": os.fspath(index_path)}
        try:
            git(f"--git-dir={remote}", "read-tree", "--empty", env=env)
            for name, content in (("README.md", "# Disposable rex-projects fixture\n"),
                                  ("CHANGELOG.md", "# Changelog\n")):
                blob = git(f"--git-dir={remote}", "hash-object", "-w", "--stdin", input_text=content)
                git(f"--git-dir={remote}", "update-index", "--add", "--cacheinfo", f"100644,{blob},{name}", env=env)
            tree = git(f"--git-dir={remote}", "write-tree", env=env)
            commit_env = {**os.environ, "GIT_AUTHOR_NAME": "rex-projects fixture",
                          "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
                          "GIT_COMMITTER_NAME": "rex-projects fixture",
                          "GIT_COMMITTER_EMAIL": "fixture@example.invalid"}
            sha = git(f"--git-dir={remote}", "commit-tree", tree, "-m", "chore: seed local acceptance fixture", env=commit_env)
            git(f"--git-dir={remote}", "update-ref", "refs/heads/main", sha)
            git(f"--git-dir={remote}", "symbolic-ref", "HEAD", "refs/heads/main")
        finally:
            index_path.unlink(missing_ok=True)
        git("clone", "--branch", "main", os.fspath(remote), os.fspath(seed))
        print(json.dumps({
            "schema_version": 1,
            "root": os.fspath(root),
            "repository": args.repository,
            "remote": os.fspath(remote),
            "seed_clone": os.fspath(seed),
            "base_branch": "main",
            "initial_commit": sha,
        }, sort_keys=True))
    except (OSError, FixtureError) as error:
        print(f"create_local_git: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
