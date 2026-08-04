"""Git worktree management for parallel agent execution isolation."""

from __future__ import annotations

import logging
import subprocess
import shutil
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class WorktreeError(Exception):
    """Raised when a git worktree operation fails."""


class WorktreeManager:
    """Manage git worktrees for isolated agent workstreams."""

    def __init__(self, repo_path: str | Path = ".") -> None:
        self.repo_path = Path(repo_path).resolve()
        self._git_dir = self.repo_path / ".git"
        if not self._git_dir.exists():
            raise WorktreeError(f"Not a git repository: {self.repo_path}")

    def create_worktree(self, branch: str, base_branch: str = "main") -> Path:
        worktree_path = self.repo_path.parent / f"{self.repo_path.name}-{branch}"

        existing = self._run_git(["worktree", "list"])
        if str(worktree_path) in existing:
            logger.info("Worktree '%s' already exists at %s", branch, worktree_path)
            return worktree_path

        if not self._branch_exists(branch):
            self._run_git(["branch", "-f", branch, base_branch])

        self._run_git(["worktree", "add", str(worktree_path), branch])
        logger.info("Created worktree '%s' at %s (base: %s)", branch, worktree_path, base_branch)
        return worktree_path

    def switch_worktree(self, branch: str) -> None:
        worktree_path = self.repo_path.parent / f"{self.repo_path.name}-{branch}"
        if not worktree_path.exists():
            self.create_worktree(branch)
        logger.info("Switched to worktree '%s' at %s", branch, worktree_path)

    def merge_worktree(self, source_branch: str, target_branch: str = "main") -> None:
        self._run_git(["checkout", target_branch])
        self._run_git(["merge", source_branch, "--no-edit"])
        logger.info("Merged '%s' into '%s'", source_branch, target_branch)

    def remove_worktree(self, branch: str) -> None:
        worktree_path = self.repo_path.parent / f"{self.repo_path.name}-{branch}"
        if not worktree_path.exists():
            logger.warning("Worktree '%s' does not exist", branch)
            return

        self._run_git(["worktree", "remove", "--force", str(worktree_path)])
        self._run_git(["branch", "-D", branch])
        shutil.rmtree(worktree_path, ignore_errors=True)
        logger.info("Removed worktree '%s'", branch)

    def list_worktrees(self) -> list[dict[str, Any]]:
        output = self._run_git(["worktree", "list", "--porcelain"])
        trees: list[dict[str, Any]] = []
        current: dict[str, Any] = {}
        for line in output.strip().split("\n"):
            if not line.strip():
                if current:
                    trees.append(current)
                    current = {}
                continue
            key, _, value = line.partition(" ")
            if key == "worktree":
                current["path"] = value
            elif key == "HEAD":
                current["head"] = value
            elif key == "branch":
                current["branch"] = value.replace("refs/heads/", "")
        if current:
            trees.append(current)
        return trees

    def _run_git(self, args: list[str]) -> str:
        cmd = ["git"] + args
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
                cwd=str(self.repo_path),
            )
            return result.stdout
        except subprocess.CalledProcessError as exc:
            raise WorktreeError(f"Git command failed: {' '.join(cmd)}\n{exc.stderr}") from exc

    def _branch_exists(self, branch: str) -> bool:
        try:
            self._run_git(["rev-parse", "--verify", f"refs/heads/{branch}"])
            return True
        except WorktreeError:
            return False
