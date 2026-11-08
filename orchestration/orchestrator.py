"""
orchestrator — HiveBreach AI Orchestrator

The central Plan → Delegate → Monitor → Replan loop that manages the
entire multi-agent penetration testing engagement.

Integrates with:
  - llm-router for model routing
  - scope-auth-gate for deterministic scope enforcement
  - sanity-check-layer for pre-delegation invariant validation
  - communication-bus for agent-to-agent messaging

Agent lifecycle: spawn → delegate → monitor → retire
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import logging
import os
import pickle
import sys
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Import helper — loads modules from directories with hyphens in their names
# ---------------------------------------------------------------------------

_ORCH_DIR = os.path.dirname(os.path.abspath(__file__))


def _load_module(module_name: str, file_subpath: str):
    """Load a Python module from a path that may contain hyphens."""
    path = os.path.join(_ORCH_DIR, file_subpath)
    if not os.path.isfile(path):
        raise ImportError(f"Cannot find module at {path}")
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


_router_mod = _load_module("_llm_router", "llm-router/router.py")
_gate_mod = _load_module("_scope_gate", "scope-auth-gate/gate.py")
_sanity_mod = _load_module("_sanity_layer", "sanity-check-layer/sanity.py")
_bus_mod = _load_module("_comm_bus", "communication-bus/message_bus.py")

ModelRouter = _router_mod.ModelRouter
LLMResponse = _router_mod.LLMResponse
TaskDifficulty = _router_mod.TaskDifficulty

ScopeEnforcer = _gate_mod.ScopeEnforcer
ScopeCheckReport = _gate_mod.ScopeCheckReport
ScopeCheckResult = _gate_mod.ScopeCheckResult
ActionType = _gate_mod.ActionType

DelegationSanityChecker = _sanity_mod.DelegationSanityChecker
DelegationTask = _sanity_mod.DelegationTask
SanityCheckResult = _sanity_mod.SanityCheckResult
SanityStatus = _sanity_mod.SanityStatus
AgentType = _sanity_mod.AgentType

MessageBus = _bus_mod.MessageBus
Message = _bus_mod.Message
MessageType = _bus_mod.MessageType
Finding = _bus_mod.Finding
FindingSeverity = _bus_mod.FindingSeverity
AgentStatus = _bus_mod.AgentStatus

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class EngagementPhase(Enum):
    INITIALISING = "initialising"
    PLANNING = "planning"
    RECON = "recon"
    EXPLOITATION = "exploitation"
    ANALYSIS = "analysis"
    REPORTING = "reporting"
    CLEANUP = "cleanup"
    COMPLETED = "completed"
    ABORTED = "aborted"


class AgentLifecycleState(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    RETIRED = "retired"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class AgentInstance:
    """Runtime record of an agent instance managed by the orchestrator."""

    instance_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    agent_type: str = ""
    lifecycle_state: AgentLifecycleState = AgentLifecycleState.PENDING
    task_id: str = ""
    assigned_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    findings: List[str] = field(default_factory=list)  # finding IDs


@dataclass
class EngagementPlan:
    """The current plan for the engagement."""

    plan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    phase: EngagementPhase = EngagementPhase.INITIALISING
    targets: List[str] = field(default_factory=list)
    agent_assignments: Dict[str, List[str]] = field(default_factory=dict)
    priority_matrix: Dict[str, int] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class SessionMemory:
    """Persistent session state for save/load."""

    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    engagement_plan: Optional[EngagementPlan] = None
    agent_instances: Dict[str, AgentInstance] = field(default_factory=dict)
    scope_violations: List[ScopeCheckReport] = field(default_factory=list)
    completed_tasks: List[Dict[str, Any]] = field(default_factory=list)
    start_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_save_time: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# HiveOrchestrator
# ---------------------------------------------------------------------------

class HiveOrchestrator:
    """
    Main AI Orchestrator for HiveBreach.

    Implements the Plan → Delegate → Monitor → Replan loop:
      1. PLAN: Analyse targets and generate an engagement plan
      2. DELEGATE: Assign tasks to agents through scope gate + sanity checks
      3. MONITOR: Track agent progress, handle messages, detect conflicts
      4. REPLAN: Adjust plan based on findings and agent results

    Example usage:

        orchestrator = HiveOrchestrator(
            roe_path="scope_rules.yaml",
            llm_config="config.yaml",
        )
        asyncio.run(orchestrator.run_engagement(
            targets=["api.acme.com", "*.acme.com"],
        ))
    """

    def __init__(
        self,
        roe_path: Optional[str] = None,
        llm_config: Optional[str] = None,
        session_dir: Optional[str] = None,
    ):
        self.orchestrator_id = f"orchestrator-{uuid.uuid4().hex[:8]}"

        # Core components
        self.scope_gate = ScopeEnforcer(roe_path)
        self.sanity_checker = DelegationSanityChecker(self.scope_gate)
        self.model_router = ModelRouter(llm_config)
        self.message_bus = MessageBus()

        # Session state
        self.session = SessionMemory()
        self.engagement_plan: Optional[EngagementPlan] = None
        self.agent_instances: Dict[str, AgentInstance] = {}
        self._running_tasks: Dict[str, asyncio.Task] = {}
        self._phase_handlers: Dict[EngagementPhase, Callable] = {}
        self._shutdown_requested = False

        # Directories
        self.session_dir = Path(session_dir or "sessions")
        self.session_dir.mkdir(parents=True, exist_ok=True)

        # Conflict detection
        self._conflicting_agents: Set[Tuple[str, str]] = set()

        self._register_phase_handlers()
        logger.info(
            "HiveOrchestrator initialised (id=%s)", self.orchestrator_id
        )

    def _register_phase_handlers(self) -> None:
        self._phase_handlers = {
            EngagementPhase.PLANNING: self._phase_planning,
            EngagementPhase.RECON: self._phase_recon,
            EngagementPhase.EXPLOITATION: self._phase_exploitation,
            EngagementPhase.ANALYSIS: self._phase_analysis,
            EngagementPhase.REPORTING: self._phase_reporting,
            EngagementPhase.CLEANUP: self._phase_cleanup,
        }

    # ==================================================================
    # Main engagement loop
    # ==================================================================

    async def run_engagement(
        self,
        targets: List[str],
        roe_path: Optional[str] = None,
        sandbox_mode: bool = True,
    ) -> SessionMemory:
        """
        Run a full penetration testing engagement.

        Args:
            targets: List of target domains/IPs/repos.
            roe_path: Optional path to RoE YAML file.
            sandbox_mode: Whether to enforce sandbox for high-risk agents.

        Returns:
            SessionMemory with all findings and results.
        """
        if roe_path:
            self.scope_gate.load_roe(roe_path)

        self.sanity_checker.set_sandbox_mode(sandbox_mode)

        logger.info(
            "Engagement started — %d targets, sandbox=%s",
            len(targets), sandbox_mode,
        )

        self.engagement_plan = EngagementPlan(
            phase=EngagementPhase.PLANNING,
            targets=targets,
        )
        self.session.engagement_plan = self.engagement_plan
        self.session.start_time = datetime.now(timezone.utc)

        # Main loop
        try:
            while self.engagement_plan.phase not in (
                EngagementPhase.COMPLETED,
                EngagementPhase.ABORTED,
            ):
                if self._shutdown_requested:
                    self.engagement_plan.phase = EngagementPhase.ABORTED
                    break

                phase = self.engagement_plan.phase
                handler = self._phase_handlers.get(phase)
                if handler:
                    await handler()
                else:
                    logger.warning("No handler for phase %s", phase.value)
                    self.advance_phase()

                await asyncio.sleep(0.1)

        except Exception as exc:
            logger.critical("Engagement loop crashed: %s", exc)
            self.engagement_plan.phase = EngagementPhase.ABORTED
            raise
        finally:
            await self._cleanup_engagement()

        logger.info(
            "Engagement completed — phase=%s, findings=%d",
            self.engagement_plan.phase.value,
            self.message_bus.finding_count,
        )
        return self.session

    def advance_phase(self, next_phase: Optional[EngagementPhase] = None) -> None:
        """Advance to the next engagement phase."""
        if not self.engagement_plan:
            return

        phase_order = [
            EngagementPhase.PLANNING,
            EngagementPhase.RECON,
            EngagementPhase.EXPLOITATION,
            EngagementPhase.ANALYSIS,
            EngagementPhase.REPORTING,
            EngagementPhase.CLEANUP,
            EngagementPhase.COMPLETED,
        ]

        if next_phase:
            self.engagement_plan.phase = next_phase
        else:
            current_idx = phase_order.index(self.engagement_plan.phase)
            if current_idx + 1 < len(phase_order):
                self.engagement_plan.phase = phase_order[current_idx + 1]

        self.engagement_plan.updated_at = datetime.now(timezone.utc)
        logger.info("Phase advance → %s", self.engagement_plan.phase.value)

    # ==================================================================
    # Phase handlers
    # ==================================================================

    async def _phase_planning(self) -> None:
        """PLANNING: Generate engagement plan using LLM or deterministic rules."""
        if not self.engagement_plan:
            return

        targets = self.engagement_plan.targets
        logger.info("Planning engagement for %d targets", len(targets))

        # Deterministic target prioritisation (non-LLM)
        self.engagement_plan.priority_matrix = {
            t: self._score_target_priority(t) for t in targets
        }

        sorted_targets = sorted(
            targets,
            key=lambda t: self.engagement_plan.priority_matrix.get(t, 5),
            reverse=True,
        )

        # Build agent assignment plan
        self.engagement_plan.agent_assignments["recon-agent"] = sorted_targets
        self.engagement_plan.agent_assignments["network-expert-agent"] = sorted_targets

        for t in sorted_targets:
            if "api" in t.lower():
                self.engagement_plan.agent_assignments.setdefault(
                    "api-testing-agent", []
                ).append(t)
            if not t.startswith("10.") and not t.startswith("192.168"):
                self.engagement_plan.agent_assignments.setdefault(
                    "web-expert-agent", []
                ).append(t)

        self.engagement_plan.agent_assignments.setdefault(
            "cleanup-teardown-agent", sorted_targets
        )
        self.engagement_plan.agent_assignments.setdefault(
            "report-agent", sorted_targets
        )

        logger.info(
            "Plan generated — %d agents assigned",
            len(self.engagement_plan.agent_assignments),
        )
        self.advance_phase(EngagementPhase.RECON)

    def _score_target_priority(self, target: str) -> int:
        """Score a target's priority (deterministic, no LLM)."""
        score = 5
        if "api" in target.lower():
            score += 2
        if "prod" in target.lower():
            score += 3
        if "admin" in target.lower():
            score += 2
        if "dev" in target.lower() or "staging" in target.lower():
            score -= 1
        return score

    async def _phase_recon(self) -> None:
        """RECON: Deploy recon agents."""
        await self._deploy_agents_for_phase(
            ["recon-agent", "network-expert-agent"],
            EngagementPhase.EXPLOITATION,
        )

    async def _phase_exploitation(self) -> None:
        """EXPLOITATION: Deploy exploitation agents."""
        await self._deploy_agents_for_phase(
            [
                "web-expert-agent", "api-testing-agent",
                "server-side-agent", "client-side-agent",
                "mobile-app-agent", "cloud-expert-agent",
                "password-credential-agent", "exploit-poc-agent",
            ],
            EngagementPhase.ANALYSIS,
        )

    async def _phase_analysis(self) -> None:
        """ANALYSIS: Deploy verification and correlation agents."""
        await self._deploy_agents_for_phase(
            ["verification-correlation-agent"],
            EngagementPhase.REPORTING,
        )

    async def _phase_reporting(self) -> None:
        """REPORTING: Deploy report agent."""
        await self._deploy_agents_for_phase(
            ["report-agent"],
            EngagementPhase.CLEANUP,
        )

    async def _phase_cleanup(self) -> None:
        """CLEANUP: Deploy cleanup agent."""
        await self._deploy_agents_for_phase(
            ["cleanup-teardown-agent"],
            EngagementPhase.COMPLETED,
        )

    async def _deploy_agents_for_phase(
        self,
        agent_types: List[str],
        next_phase: EngagementPhase,
    ) -> None:
        """Deploy a set of agents for the current phase."""
        if not self.engagement_plan:
            self.advance_phase(next_phase)
            return

        tasks: List[asyncio.Task] = []
        for agent_type in agent_types:
            targets = self.engagement_plan.agent_assignments.get(agent_type, [])
            if not targets:
                targets = self.engagement_plan.targets
            for target in targets:
                task = asyncio.create_task(
                    self.delegate_to_agent(agent_type, target)
                )
                tasks.append(task)

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, Exception):
                    logger.error("Agent deployment failed: %s", result)

        self.advance_phase(next_phase)

    # ==================================================================
    # Agent lifecycle
    # ==================================================================

    async def delegate_to_agent(
        self,
        agent_type: str,
        target: str,
        technique_id: Optional[str] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Optional[AgentInstance]:
        """
        Delegate a task to an agent through the full gate + sanity pipeline.

        Steps:
          1. Create delegation task
          2. Run sanity checks (deterministic)
          3. Run scope gate check (deterministic)
          4. Spawn agent instance
          5. LLM-routed prompt generation
          6. Register on message bus
          7. Monitor execution
        """
        agent_type_enum = self._resolve_agent_type(agent_type)
        if not agent_type_enum:
            logger.error("Unknown agent type: %s", agent_type)
            return None

        action_type = self._infer_action_type(agent_type_enum)

        task = DelegationTask(
            task_id=str(uuid.uuid4()),
            agent_type=agent_type_enum,
            action_type=action_type,
            target=target,
            technique_id=technique_id,
            params=params or {},
        )

        # Step 1: Scope gate
        scope_report = self.scope_gate.authorize(
            target=target,
            action_type=action_type,
            technique_id=technique_id,
            current_connections=self.sanity_checker._active_connections,
        )
        if not scope_report.is_allowed():
            logger.warning(
                "Scope gate BLOCKED %s → %s: %s",
                agent_type, target, scope_report.reason,
            )
            self.session.scope_violations.append(scope_report)
            return None

        # Step 2: Sanity checks
        safe, sanity_results = self.sanity_checker.is_task_safe_to_delegate(task)
        if not safe:
            blocking = [
                r for r in sanity_results if r.is_blocking()
            ]
            logger.warning(
                "Sanity checks BLOCKED %s → %s: %d failures",
                agent_type, target, len(blocking),
            )
            return None

        # Step 3: Spawn agent instance
        instance = AgentInstance(
            agent_type=agent_type,
            task_id=task.task_id,
        )
        self.agent_instances[instance.instance_id] = instance
        self._running_tasks[instance.instance_id] = asyncio.create_task(
            self._run_agent(instance, task)
        )

        logger.info(
            "Delegated %s → %s (instance=%s)",
            agent_type, target, instance.instance_id[:8],
        )
        return instance

    async def _run_agent(
        self, instance: AgentInstance, task: DelegationTask
    ) -> None:
        """Internal: execute an agent's task."""
        instance.lifecycle_state = AgentLifecycleState.RUNNING
        instance.assigned_at = datetime.now(timezone.utc)

        # Register on message bus
        self.message_bus.register_agent(
            agent_id=instance.instance_id,
            agent_type=task.agent_type.value,
        )
        self.message_bus.update_agent_status(
            instance.instance_id, AgentStatus.BUSY
        )

        try:
            # Generate agent prompt via LLM router
            response = await self._generate_agent_prompt(task)
            if response.error:
                instance.error = response.error
                instance.lifecycle_state = AgentLifecycleState.FAILED
                return

            # Parse agent response
            result = self._parse_agent_output(response.content, task)

            if result.get("findings"):
                for finding_data in result["findings"]:
                    finding = self._create_finding(finding_data, task)
                    self.message_bus.publish_finding(finding)
                    instance.findings.append(finding.finding_id)

            # Report status
            self.message_bus.send_message_sync(Message(
                message_type=MessageType.STATUS,
                sender=instance.instance_id,
                payload={
                    "status": "completed",
                    "agent_type": task.agent_type.value,
                    "target": task.target,
                    "findings_count": len(instance.findings),
                },
            ))

            instance.result = result
            instance.lifecycle_state = AgentLifecycleState.COMPLETED
            instance.completed_at = datetime.now(timezone.utc)

            self.session.completed_tasks.append({
                "instance_id": instance.instance_id,
                "agent_type": task.agent_type.value,
                "target": task.target,
                "findings": instance.findings,
                "completed_at": instance.completed_at.isoformat(),
            })

            self.sanity_checker.add_completed_agent(task.agent_type)

        except Exception as exc:
            logger.error("Agent %s failed: %s", instance.instance_id, exc)
            instance.error = str(exc)
            instance.lifecycle_state = AgentLifecycleState.FAILED
        finally:
            self.message_bus.update_agent_status(
                instance.instance_id, AgentStatus.COMPLETED
            )

    async def _generate_agent_prompt(self, task: DelegationTask) -> LLMResponse:
        """Generate an LLM prompt for the agent using the model router."""
        system_prompt = (
            f"You are the {task.agent_type.value} in the HiveBreach "
            f"penetration testing framework. Your role is to perform "
            f"{task.action_type.value} against {task.target}. "
            f"Stay within the authorized scope."
        )

        user_prompt = (
            f"Target: {task.target}\n"
            f"Action: {task.action_type.value}\n"
        )
        if task.technique_id:
            user_prompt += f"Technique: {task.technique_id}\n"
        if task.params:
            user_prompt += f"Parameters: {json.dumps(task.params, indent=2)}\n"

        user_prompt += (
            "\nProvide your findings in JSON format with keys: "
            "title, description, severity, evidence, commands_run, output"
        )

        return await self.model_router.route(
            prompt=user_prompt,
            task_difficulty=self._infer_difficulty(task),
            agent_type=task.agent_type.value,
            system_prompt=system_prompt,
        )

    def _parse_agent_output(
        self, content: str, task: DelegationTask
    ) -> Dict[str, Any]:
        """Parse agent LLM output into structured results."""
        result: Dict[str, Any] = {
            "findings": [],
            "commands": [],
            "output": content,
        }

        try:
            parsed = json.loads(content)
            if isinstance(parsed, list):
                result["findings"] = parsed
            elif isinstance(parsed, dict):
                result.update(parsed)
                if "findings" not in parsed:
                    result["findings"] = [parsed]
        except json.JSONDecodeError:
            import re
            json_blocks = re.findall(
                r'```(?:json)?\s*([\s\S]*?)```', content
            )
            for block in json_blocks:
                try:
                    parsed = json.loads(block)
                    if isinstance(parsed, list):
                        result["findings"].extend(parsed)
                    elif isinstance(parsed, dict):
                        result["findings"].append(parsed)
                except json.JSONDecodeError:
                    pass

        return result

    def _create_finding(
        self, data: Dict[str, Any], task: DelegationTask
    ) -> Finding:
        """Create a Finding from parsed agent output."""
        severity_map = {
            "critical": FindingSeverity.CRITICAL,
            "high": FindingSeverity.HIGH,
            "medium": FindingSeverity.MEDIUM,
            "low": FindingSeverity.LOW,
            "info": FindingSeverity.INFO,
        }
        return Finding(
            agent_type=task.agent_type.value,
            title=data.get("title", "Untitled Finding"),
            description=data.get("description", ""),
            severity=severity_map.get(
                data.get("severity", "").lower(), FindingSeverity.INFO
            ),
            target=task.target,
            technique_id=task.technique_id or data.get("technique_id"),
            evidence=data.get("evidence", {}),
            raw_output=data.get("output", ""),
        )

    # ==================================================================
    # Conflict resolution
    # ==================================================================

    def detect_conflicts(self) -> List[Dict[str, Any]]:
        """
        Detect conflicts between running agents.

        Conflicts include:
        - Two agents targeting the same host with incompatible techniques
        - An exploit agent running before recon completes
        - Duplicate credential attacks on the same target
        """
        conflicts: List[Dict[str, Any]] = []
        running = [
            inst for inst in self.agent_instances.values()
            if inst.lifecycle_state == AgentLifecycleState.RUNNING
        ]

        # Check for duplicate targets
        target_map: Dict[str, List[str]] = {}
        for inst in running:
            for task_entry in self.session.completed_tasks:
                if task_entry["instance_id"] == inst.instance_id:
                    target = task_entry["target"]
                    target_map.setdefault(target, []).append(inst.agent_type)

        for target, agents in target_map.items():
            if len(agents) > 1 and len(set(agents)) > 1:
                conflicts.append({
                    "type": "duplicate_target",
                    "target": target,
                    "agents": agents,
                    "severity": "medium",
                })

        return conflicts

    def resolve_conflict(self, conflict: Dict[str, Any]) -> Optional[str]:
        """
        Resolve a detected conflict. Returns the agent_id that should
        proceed, or None to abort both.
        """
        if conflict.get("type") == "duplicate_target":
            agents = conflict.get("agents", [])
            priority = {
                "recon-agent": 1,
                "network-expert-agent": 2,
                "web-expert-agent": 3,
                "api-testing-agent": 3,
                "server-side-agent": 4,
                "exploit-poc-agent": 5,
                "password-credential-agent": 6,
            }
            sorted_agents = sorted(
                agents,
                key=lambda a: priority.get(a, 10),
            )
            return sorted_agents[0] if sorted_agents else None

        return None

    # ==================================================================
    # Session persistence
    # ==================================================================

    def save_session(self, path: Optional[str] = None) -> str:
        """Save the current session to disk."""
        save_path = Path(path or (
            self.session_dir / f"session_{self.session.session_id[:8]}.pkl"
        ))
        self.session.last_save_time = datetime.now(timezone.utc)

        with open(save_path, "wb") as fh:
            pickle.dump(self.session, fh)

        logger.info("Session saved to %s", save_path)
        return str(save_path)

    def load_session(self, path: str) -> SessionMemory:
        """Load a session from disk."""
        with open(path, "rb") as fh:
            self.session = pickle.load(fh)

        self.engagement_plan = self.session.engagement_plan
        self.agent_instances = self.session.agent_instances

        logger.info(
            "Session loaded: %s (phase=%s)",
            self.session.session_id,
            self.engagement_plan.phase.value if self.engagement_plan else "N/A",
        )
        return self.session

    def export_findings(self, format: str = "json") -> Dict[str, Any]:
        """Export all findings as a serialisable structure."""
        findings = self.message_bus.get_all_findings()
        return {
            "session_id": self.session.session_id,
            "engagement_phase": (
                self.engagement_plan.phase.value
                if self.engagement_plan else "unknown"
            ),
            "findings": [
                f.to_dict() for f in findings.values()
            ],
            "summary": {
                "total_findings": len(findings),
                "by_severity": {
                    sev.value: len([
                        f for f in findings.values()
                        if f.severity.value == sev.value
                    ])
                    for sev in FindingSeverity
                },
            },
        }

    # ==================================================================
    # Helpers
    # ==================================================================

    @staticmethod
    def _resolve_agent_type(name: str) -> Optional[AgentType]:
        """Resolve an agent type string to an AgentType enum."""
        try:
            return AgentType(name)
        except ValueError:
            for at in AgentType:
                if at.value == name:
                    return at
            return None

    @staticmethod
    def _infer_action_type(agent_type: AgentType) -> ActionType:
        """Infer the primary action type for an agent type."""
        mapping: Dict[AgentType, ActionType] = {
            AgentType.RECON: ActionType.RECON,
            AgentType.WEB_EXPERT: ActionType.EXPLOIT,
            AgentType.API_TESTING: ActionType.SCAN,
            AgentType.ACTIVE_TESTING: ActionType.EXPLOIT,
            AgentType.CLOUD_EXPERT: ActionType.SCAN,
            AgentType.NETWORK_EXPERT: ActionType.SCAN,
            AgentType.SERVER_SIDE: ActionType.SCAN,
            AgentType.CLIENT_SIDE: ActionType.EXPLOIT,
            AgentType.MOBILE_APP: ActionType.EXPLOIT,
            AgentType.PASSWORD_CREDENTIAL: ActionType.CREDENTIAL_ATTACK,
            AgentType.WIRELESS: ActionType.WIRELESS,
            AgentType.EXPLOIT_POC: ActionType.EXPLOIT,
            AgentType.VERIFICATION_CORRELATION: ActionType.REPORTING,
            AgentType.CLEANUP_TEARDOWN: ActionType.CLEANUP,
            AgentType.REPORT: ActionType.REPORTING,
        }
        return mapping.get(agent_type, ActionType.SCAN)

    @staticmethod
    def _infer_difficulty(task: DelegationTask) -> TaskDifficulty:
        """Infer task difficulty based on agent type and action."""
        hard_agents = {
            AgentType.EXPLOIT_POC,
            AgentType.PASSWORD_CREDENTIAL,
            AgentType.NETWORK_EXPERT,
        }
        if task.agent_type in hard_agents:
            return TaskDifficulty.HARD
        if task.action_type in (
            ActionType.EXPLOIT, ActionType.POST_EXPLOIT, ActionType.CREDENTIAL_ATTACK,
        ):
            return TaskDifficulty.HARD
        if task.action_type == ActionType.RECON:
            return TaskDifficulty.EASY
        return TaskDifficulty.MEDIUM

    async def _cleanup_engagement(self) -> None:
        """Clean up after engagement completes or aborts."""
        logger.info("Engagement cleanup")
        for task in self._running_tasks.values():
            task.cancel()
        await self.model_router.close_all()
        self._running_tasks.clear()

    def request_shutdown(self) -> None:
        """Request graceful shutdown of the engagement loop."""
        self._shutdown_requested = True
        logger.info("Shutdown requested")
