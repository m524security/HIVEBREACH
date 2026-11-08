"""Parallel package — ECC concurrent execution and worktree management."""

from parallel.worktree_manager import WorktreeManager
from parallel.cascade_orchestrator import CascadeOrchestrator

__all__ = ["WorktreeManager", "CascadeOrchestrator"]
