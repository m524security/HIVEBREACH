"""
sanity-check-layer — Pre-Execution Invariant Validation

Deterministic (non-LLM) checks that run BEFORE an agent receives a
delegated task. Catches type mismatches, authorization gaps, budget
overruns, and configuration errors that the LLM might miss.

All logic is rule-based and fully deterministic.
"""

from __future__ import annotations

import importlib.util
import logging
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set


# ---------------------------------------------------------------------------
# Import helper
# ---------------------------------------------------------------------------

_SANITY_DIR = os.path.dirname(os.path.abspath(__file__))
_ORCH_DIR = os.path.dirname(_SANITY_DIR)


def _load_module(module_name: str, file_subpath: str):
    path = os.path.join(_ORCH_DIR, file_subpath)
    if not os.path.isfile(path):
        raise ImportError(f"Cannot find module at {path}")
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


_gate_mod = _load_module("_scope_gate", "scope-auth-gate/gate.py")
ScopeEnforcer = _gate_mod.ScopeEnforcer
ActionType = _gate_mod.ActionType

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class SanityStatus(Enum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"
    BLOCK = "block"


class AgentType(Enum):
    RECON = "recon-agent"
    WEB_EXPERT = "web-expert-agent"
    API_TESTING = "api-testing-agent"
    ACTIVE_TESTING = "active-testing-agent"
    CLOUD_EXPERT = "cloud-expert-agent"
    NETWORK_EXPERT = "network-expert-agent"
    SERVER_SIDE = "server-side-agent"
    CLIENT_SIDE = "client-side-agent"
    MOBILE_APP = "mobile-app-agent"
    PASSWORD_CREDENTIAL = "password-credential-agent"
    WIRELESS = "wireless-agent"
    EXPLOIT_POC = "exploit-poc-agent"
    VERIFICATION_CORRELATION = "verification-correlation-agent"
    CLEANUP_TEARDOWN = "cleanup-teardown-agent"
    REPORT = "report-agent"
    THREAT_MODELING = "threat-modeling-agent"
    COMPLIANCE_AUDIT = "compliance-audit-agent"
    SCA_SBOM = "sca-sbom-agent"
    SECRETS_SCANNING = "secrets-scanning-agent"


# ---------------------------------------------------------------------------
# Agent capability matrix (deterministic, data-driven)
# Uses string values to avoid enum identity issues across module reloads.
# ---------------------------------------------------------------------------

# Maps agent types to the action types they are competent to perform.
AGENT_CAPABILITIES: Dict[str, Set[str]] = {
    "recon-agent": {"recon", "fingerprint", "scan"},
    "web-expert-agent": {"scan", "fingerprint", "exploit"},
    "api-testing-agent": {"scan", "fingerprint"},
    "active-testing-agent": {"scan", "exploit", "post_exploit"},
    "cloud-expert-agent": {"scan", "fingerprint", "exploit"},
    "network-expert-agent": {"scan", "fingerprint", "exploit", "post_exploit"},
    "server-side-agent": {"scan", "fingerprint", "exploit"},
    "client-side-agent": {"scan", "fingerprint", "exploit"},
    "mobile-app-agent": {"scan", "fingerprint", "exploit"},
    "password-credential-agent": {"credential_attack"},
    "wireless-agent": {"wireless", "recon"},
    "exploit-poc-agent": {"exploit", "post_exploit"},
    "verification-correlation-agent": {"reporting"},
    "cleanup-teardown-agent": {"cleanup"},
    "report-agent": {"reporting"},
    "threat-modeling-agent": {"reporting"},
    "compliance-audit-agent": {"reporting"},
    "sca-sbom-agent": {"scan", "fingerprint"},
    "secrets-scanning-agent": {"scan"},
}

# Agent dependency graph: key must run before value
AGENT_DEPENDENCIES: Dict[str, Set[str]] = {
    "web-expert-agent": {"recon-agent"},
    "api-testing-agent": {"recon-agent"},
    "active-testing-agent": {"recon-agent", "web-expert-agent"},
    "server-side-agent": {"recon-agent", "network-expert-agent"},
    "exploit-poc-agent": {"recon-agent", "web-expert-agent", "server-side-agent"},
    "password-credential-agent": {"recon-agent", "network-expert-agent"},
    "verification-correlation-agent": {
        "web-expert-agent", "api-testing-agent", "active-testing-agent",
        "exploit-poc-agent", "password-credential-agent",
    },
    "cleanup-teardown-agent": {
        "exploit-poc-agent", "password-credential-agent",
        "active-testing-agent", "network-expert-agent",
    },
    "report-agent": {
        "verification-correlation-agent", "cleanup-teardown-agent",
    },
}

# Agents that require sandbox execution
SANDBOX_REQUIRED_AGENTS: Set[str] = {
    "network-expert-agent",
    "password-credential-agent",
    "exploit-poc-agent",
    "wireless-agent",
}

# Agents that require explicit RoE authorization flag
ROE_AUTHORIZATION_REQUIRED: Set[str] = {
    "password-credential-agent",
    "wireless-agent",
    "network-expert-agent",
    "exploit-poc-agent",
}


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class DelegationTask:
    """A task to be delegated to an agent."""

    task_id: str
    agent_type: AgentType
    action_type: ActionType
    target: str
    technique_id: Optional[str] = None
    port: Optional[int] = None
    params: Dict[str, Any] = field(default_factory=dict)
    priority: int = 5
    time_budget_seconds: Optional[int] = None
    requires_sandbox: bool = False
    roe_authorization_flag: str = ""


@dataclass
class SanityCheckResult:
    """Result of a sanity check on a delegation task."""

    status: SanityStatus
    check_name: str
    message: str = ""
    task_id: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def is_blocking(self) -> bool:
        return self.status in (SanityStatus.FAIL, SanityStatus.BLOCK)


# ---------------------------------------------------------------------------
# DelegationSanityChecker
# ---------------------------------------------------------------------------

class DelegationSanityChecker:
    """
    Pre-execution invariant validator for agent delegation.

    Runs BEFORE the orchestrator hands a task to an agent. All checks
    are deterministic — no LLM calls.
    """

    def __init__(self, scope_enforcer: Optional[ScopeEnforcer] = None):
        self.scope_enforcer = scope_enforcer or ScopeEnforcer()
        self._results: List[SanityCheckResult] = []
        self._active_connections: int = 0
        self._elapsed_seconds: float = 0.0
        self._running_agents: Set[str] = set()
        self._completed_agents: Set[str] = set()
        self._sandbox_mode: bool = True  # default to safe
        self._session_start: datetime = datetime.now(timezone.utc)

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def set_sandbox_mode(self, enabled: bool) -> None:
        self._sandbox_mode = enabled

    def set_active_connections(self, count: int) -> None:
        self._active_connections = count

    def set_running_agents(self, agent_types: Set[str]) -> None:
        self._running_agents = agent_types

    def add_completed_agent(self, agent_type) -> None:
        val = agent_type.value if hasattr(agent_type, 'value') else str(agent_type)
        self._completed_agents.add(val)

    def update_elapsed_time(self) -> None:
        self._elapsed_seconds = (
            datetime.now(timezone.utc) - self._session_start
        ).total_seconds()

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    def check_type_mismatch(self, task: DelegationTask) -> SanityCheckResult:
        """
        Check that the agent type is competent for the requested action type.

        Catches: "mobile task -> network agent" type mismatches.
        """
        capabilities = AGENT_CAPABILITIES.get(task.agent_type.value, set())
        action_val = task.action_type.value if hasattr(task.action_type, 'value') else str(task.action_type)
        if action_val not in capabilities:
            return SanityCheckResult(
                status=SanityStatus.BLOCK,
                check_name="type_mismatch",
                task_id=task.task_id,
                message=(
                    f"Agent {task.agent_type.value} cannot perform "
                    f"action {action_val}. "
                    f"Capabilities: {sorted(capabilities)}"
                ),
                details={
                    "agent_type": task.agent_type.value,
                    "action_type": action_val,
                    "capabilities": sorted(capabilities),
                },
            )
        return SanityCheckResult(
            status=SanityStatus.PASS,
            check_name="type_mismatch",
            task_id=task.task_id,
            message=f"Agent {task.agent_type.value} can perform {action_val}",
        )

    def check_roe_authorization(self, task: DelegationTask) -> SanityCheckResult:
        """
        Check that tasks requiring RoE authorization have the flag set.
        """
        agent_val = task.agent_type.value if hasattr(task.agent_type, 'value') else str(task.agent_type)
        if agent_val in ROE_AUTHORIZATION_REQUIRED:
            if not task.roe_authorization_flag:
                return SanityCheckResult(
                    status=SanityStatus.BLOCK,
                    check_name="roe_authorization",
                    task_id=task.task_id,
                    message=(
                        f"Agent {agent_val} requires an RoE "
                        f"authorization flag in the delegation task"
                    ),
                    details={
                        "agent_type": agent_val,
                        "roe_authorization_flag": task.roe_authorization_flag,
                    },
                )
        return SanityCheckResult(
            status=SanityStatus.PASS,
            check_name="roe_authorization",
            task_id=task.task_id,
        )

    def check_sandbox_requirement(self, task: DelegationTask) -> SanityCheckResult:
        """
        Check that agents requiring sandbox execution have it enabled.
        """
        agent_val = task.agent_type.value if hasattr(task.agent_type, 'value') else str(task.agent_type)
        if agent_val in SANDBOX_REQUIRED_AGENTS:
            if not self._sandbox_mode and not task.requires_sandbox:
                return SanityCheckResult(
                    status=SanityStatus.BLOCK,
                    check_name="sandbox_requirement",
                    task_id=task.task_id,
                    message=(
                        f"Agent {agent_val} requires sandbox "
                        f"execution but sandbox mode is disabled"
                    ),
                    details={
                        "agent_type": agent_val,
                        "sandbox_mode": self._sandbox_mode,
                    },
                )
        return SanityCheckResult(
            status=SanityStatus.PASS,
            check_name="sandbox_requirement",
            task_id=task.task_id,
        )

    def check_dependencies(self, task: DelegationTask) -> SanityCheckResult:
        """
        Check that all dependencies for this agent have completed.
        """
        agent_val = task.agent_type.value if hasattr(task.agent_type, 'value') else str(task.agent_type)
        deps = AGENT_DEPENDENCIES.get(agent_val, set())
        missing = deps - self._completed_agents
        if missing:
            return SanityCheckResult(
                status=SanityStatus.WARN,
                check_name="dependencies",
                task_id=task.task_id,
                message=(
                    f"Agent {agent_val} has unmet dependencies: "
                    f"{sorted(missing)}"
                ),
                details={
                    "agent_type": agent_val,
                    "missing_dependencies": sorted(missing),
                },
            )
        return SanityCheckResult(
            status=SanityStatus.PASS,
            check_name="dependencies",
            task_id=task.task_id,
        )

    def check_time_budget(self, task: DelegationTask) -> SanityCheckResult:
        """
        Check that the task's time budget won't be exceeded.
        """
        self.update_elapsed_time()
        if self.scope_enforcer and self.scope_enforcer.roe:
            budget_hours = self.scope_enforcer.roe.time_budget_hours
            if budget_hours is not None:
                elapsed_hours = self._elapsed_seconds / 3600.0
                if elapsed_hours >= budget_hours:
                    return SanityCheckResult(
                        status=SanityStatus.FAIL,
                        check_name="time_budget",
                        task_id=task.task_id,
                        message=(
                            f"Engagement time budget of {budget_hours}h "
                            f"has been exceeded ({elapsed_hours:.1f}h elapsed)"
                        ),
                        details={
                            "budget_hours": budget_hours,
                            "elapsed_hours": round(elapsed_hours, 2),
                        },
                    )

        if task.time_budget_seconds is not None and task.time_budget_seconds <= 0:
            return SanityCheckResult(
                status=SanityStatus.WARN,
                check_name="time_budget",
                task_id=task.task_id,
                message=(
                    f"Task {task.task_id} has exhausted its "
                    f"time budget ({task.time_budget_seconds}s)"
                ),
                details={"time_budget_seconds": task.time_budget_seconds},
            )

        return SanityCheckResult(
            status=SanityStatus.PASS,
            check_name="time_budget",
            task_id=task.task_id,
        )

    def check_concurrent_connections(self, task: DelegationTask) -> SanityCheckResult:
        """
        Check that the concurrent connection limit won't be exceeded.
        """
        if self.scope_enforcer and self.scope_enforcer.roe:
            max_conn = self.scope_enforcer.roe.concurrent_connections_max
            if max_conn is not None and self._active_connections >= max_conn:
                return SanityCheckResult(
                    status=SanityStatus.FAIL,
                    check_name="concurrent_connections",
                    task_id=task.task_id,
                    message=(
                        f"Connection limit of {max_conn} reached "
                        f"({self._active_connections} active)"
                    ),
                    details={
                        "max_connections": max_conn,
                        "active_connections": self._active_connections,
                    },
                )
        return SanityCheckResult(
            status=SanityStatus.PASS,
            check_name="concurrent_connections",
            task_id=task.task_id,
        )

    def check_duplicate_running(self, task: DelegationTask) -> SanityCheckResult:
        """
        Check that an agent of this type isn't already running.
        """
        agent_val = task.agent_type.value if hasattr(task.agent_type, 'value') else str(task.agent_type)
        if agent_val in self._running_agents:
            return SanityCheckResult(
                status=SanityStatus.WARN,
                check_name="duplicate_running",
                task_id=task.task_id,
                message=(
                    f"Agent {agent_val} is already running. "
                    f"Duplicate instances may cause conflicts."
                ),
                details={
                    "agent_type": agent_val,
                    "running_agents": sorted(self._running_agents),
                },
            )
        return SanityCheckResult(
            status=SanityStatus.PASS,
            check_name="duplicate_running",
            task_id=task.task_id,
        )

    def check_target_in_scope(self, task: DelegationTask) -> SanityCheckResult:
        """
        Check that the task's target is within the authorized scope.
        """
        if not self.scope_enforcer:
            return SanityCheckResult(
                status=SanityStatus.WARN,
                check_name="target_in_scope",
                task_id=task.task_id,
                message="No scope enforcer configured — scope check skipped",
            )

        in_scope, reason = self.scope_enforcer.check_target(task.target)
        if not in_scope:
            return SanityCheckResult(
                status=SanityStatus.BLOCK,
                check_name="target_in_scope",
                task_id=task.task_id,
                message=reason,
                details={"target": task.target},
            )
        return SanityCheckResult(
            status=SanityStatus.PASS,
            check_name="target_in_scope",
            task_id=task.task_id,
            message=reason,
        )

    # ------------------------------------------------------------------
    # Full suite
    # ------------------------------------------------------------------

    def run_all(self, task: DelegationTask) -> List[SanityCheckResult]:
        """
        Run ALL sanity checks against a delegation task.

        Returns a list of results. If any result has status FAIL or BLOCK,
        the task should NOT be delegated.
        """
        self._results.clear()

        checks = [
            self.check_target_in_scope,
            self.check_type_mismatch,
            self.check_roe_authorization,
            self.check_sandbox_requirement,
            self.check_dependencies,
            self.check_time_budget,
            self.check_concurrent_connections,
            self.check_duplicate_running,
        ]

        for check in checks:
            result = check(task)
            self._results.append(result)

        return self._results.copy()

    def is_task_safe_to_delegate(self, task: DelegationTask) -> Tuple[bool, List[SanityCheckResult]]:
        """
        Convenience method: runs all checks and returns (safe, results).

        Safe = True only if NO check returned FAIL or BLOCK.
        """
        results = self.run_all(task)
        blocking = [r for r in results if r.is_blocking()]
        return (len(blocking) == 0, results)

    @property
    def last_results(self) -> List[SanityCheckResult]:
        return self._results.copy()

    def get_blocking_results(self) -> List[SanityCheckResult]:
        return [r for r in self._results if r.is_blocking()]

    # ------------------------------------------------------------------
    # Session tracking
    # ------------------------------------------------------------------

    def reset_session(self) -> None:
        """Reset session-level tracking data."""
        self._session_start = datetime.now(timezone.utc)
        self._elapsed_seconds = 0.0
        self._active_connections = 0
        self._running_agents.clear()
        self._completed_agents.clear()
        self._results.clear()
