"""
harness — HiveBreach ECC Harness (Plan → Execute → Verify → Learn → Persist)

Implements the ECC lifecycle loop with scope gate, sanity checks, model
routing, message bus, hook profiles, and memory persistence integration.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import logging
import os
import pickle
import re
import sys
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

_ORCH_DIR = os.path.dirname(os.path.abspath(__file__))


def _load_module(module_name: str, file_subpath: str):
    path = os.path.join(_ORCH_DIR, file_subpath)
    if not os.path.isfile(path):
        raise ImportError(f"Cannot find module at {path}")
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


_router_mod = _load_module("_h_router", os.path.join("llm-router", "router.py"))
_gate_mod = _load_module("_h_gate", os.path.join("scope-auth-gate", "gate.py"))
_sanity_mod = _load_module("_h_sanity", os.path.join("sanity-check-layer", "sanity.py"))
_bus_mod = _load_module("_h_bus", os.path.join("communication-bus", "message_bus.py"))
_orch_mod = _load_module("_h_orch", "orchestrator.py")

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
EngagementPlan = _orch_mod.EngagementPlan
AgentInstance = _orch_mod.AgentInstance
SessionMemory = _orch_mod.SessionMemory

logger = logging.getLogger(__name__)


class HookPoint(Enum):
    PRE_SCAN = "pre-scan"
    POST_SCAN = "post-scan"
    ON_FINDING = "on-finding"
    PRE_EXECUTE = "pre-execute"
    POST_EXECUTE = "post-execute"
    PRE_VERIFY = "pre-verify"
    POST_VERIFY = "post-verify"
    ON_LEARN = "on-learn"
    ON_PERSIST = "on-persist"
    ON_ERROR = "on-error"


class HookProfile(Enum):
    MINIMAL = "minimal"
    STANDARD = "standard"
    STRICT = "strict"


class VerificationStatus(Enum):
    PASSED = "passed"
    FAILED = "failed"
    INCONCLUSIVE = "inconclusive"
    NOT_RUN = "not_run"


class LearnStatus(Enum):
    EXTRACTED = "extracted"
    NO_PATTERNS = "no_patterns"
    ERROR = "error"


@dataclass
class VerificationReport:
    finding_id: str
    title: str
    status: VerificationStatus = VerificationStatus.NOT_RUN
    confidence_score: float = 0.0
    replayed: bool = False
    matched_expected: bool = False
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class LearnSummary:
    session_id: str
    status: LearnStatus = LearnStatus.NO_PATTERNS
    patterns_extracted: int = 0
    skills_generated: int = 0
    instinct_updates: int = 0
    lessons: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class HookRegistry:
    pre_scan: List[Callable] = field(default_factory=list)
    post_scan: List[Callable] = field(default_factory=list)
    on_finding: List[Callable] = field(default_factory=list)
    pre_execute: List[Callable] = field(default_factory=list)
    post_execute: List[Callable] = field(default_factory=list)
    pre_verify: List[Callable] = field(default_factory=list)
    post_verify: List[Callable] = field(default_factory=list)
    on_learn: List[Callable] = field(default_factory=list)
    on_persist: List[Callable] = field(default_factory=list)
    on_error: List[Callable] = field(default_factory=list)

    def get(self, point: HookPoint) -> List[Callable]:
        return getattr(self, point.value.replace("-", "_"), [])


class HiveBreachHarness:
    """
    ECC-style orchestration harness: Plan → Execute → Verify → Learn → Persist.

    Delegates to agents through the scope gate, sanity checker, model router,
    and message bus. Calls hooks at lifecycle points controlled by the
    ECC_HOOK_PROFILE env var (minimal|standard|strict).
    """

    def __init__(
        self,
        roe_path: Optional[str] = None,
        llm_config: Optional[str] = None,
        session_dir: Optional[str] = None,
        hook_profile: Optional[str] = None,
    ):
        self.harness_id = f"harness-{uuid.uuid4().hex[:8]}"
        self.scope_gate = ScopeEnforcer(roe_path)
        self.sanity_checker = DelegationSanityChecker(self.scope_gate)
        self.model_router = ModelRouter(llm_config)
        self.message_bus = MessageBus()

        raw = hook_profile or os.environ.get("ECC_HOOK_PROFILE", "standard")
        try:
            self.hook_profile = HookProfile(raw.lower())
        except ValueError:
            self.hook_profile = HookProfile.STANDARD

        self.hooks = HookRegistry()
        self._register_default_hooks()

        self.session = SessionMemory()
        self.engagement_plan: Optional[EngagementPlan] = None
        self.agent_instances: Dict[str, AgentInstance] = {}
        self._running_tasks: Dict[str, asyncio.Task] = {}
        self._verification_reports: Dict[str, VerificationReport] = {}
        self._learn_summary: Optional[LearnSummary] = None
        self._shutdown_requested = False

        self.session_dir = Path(session_dir or "sessions")
        self.session_dir.mkdir(parents=True, exist_ok=True)
        self._instinct_store = Path(
            os.environ.get("ECC_INSTINCT_STORE", "instinct/patterns.json")
        )
        self._memory_path = Path(
            os.environ.get("ECC_MEMORY_PATH", "memory/persistence-hooks")
        )
        if self._memory_path:
            self._memory_path.mkdir(parents=True, exist_ok=True)

        logger.info(
            "Harness initialised (id=%s, profile=%s)",
            self.harness_id, self.hook_profile.value,
        )

    def _register_default_hooks(self) -> None:
        if self.hook_profile in (HookProfile.STANDARD, HookProfile.STRICT):
            self.hooks.pre_execute.append(
                lambda h, d: logger.debug("HOOK pre-execute: %s \u2192 %s", d.get("agent_type"), d.get("target"))
            )
            self.hooks.post_execute.append(
                lambda h, d: logger.info("HOOK post-execute: agent_type=%s, findings=%d", d.get("agent_type"), d.get("findings", 0))
            )
            self.hooks.on_finding.append(
                lambda h, d: logger.warning("HOOK on-finding: %s %s", d.get("severity"), d.get("title"))
                if d.get("severity") in ("critical", "high") else None
            )
            self.hooks.on_persist.append(
                lambda h, d: logger.info("HOOK on-persist: saved to %s", d.get("path"))
            )
        if self.hook_profile == HookProfile.STRICT:
            self.hooks.on_learn.append(
                lambda h, d: logger.info("HOOK on-learn: %d patterns", d.get("patterns_extracted", 0))
            )
            self.hooks.on_error.append(
                lambda h, d: logger.error("HOOK on-error: %s \u2014 %s", d.get("phase"), d.get("error"))
            )

    def register_hook(self, point: HookPoint, fn: Callable) -> None:
        getattr(self.hooks, point.value.replace("-", "_"), []).append(fn)

    async def _run_hooks(self, point: HookPoint, data: Dict[str, Any]) -> None:
        for hook in self.hooks.get(point):
            try:
                if asyncio.iscoroutinefunction(hook):
                    await hook(self, data)
                else:
                    hook(self, data)
            except Exception as exc:
                logger.warning("Hook %s failed: %s", point.value, exc)

    # ------------------------------------------------------------------
    # 1. PLAN
    # ------------------------------------------------------------------

    async def plan(
        self,
        targets: List[str],
        roe_path: Optional[str] = None,
    ) -> EngagementPlan:
        """Analyse targets, build engagement plan, and assign agents."""
        if roe_path:
            self.scope_gate.load_roe(roe_path)
            self.sanity_checker.scope_enforcer = self.scope_gate

        priority: Dict[str, int] = {}
        for t in targets:
            tl = t.lower()
            score = 5
            if "api" in tl:
                score += 2
            if "prod" in tl:
                score += 3
            if "admin" in tl or "auth" in tl:
                score += 2
            if "dev" in tl or "staging" in tl:
                score -= 1
            if "test" in tl:
                score -= 2
            priority[t] = score

        sorted_targets = sorted(targets, key=lambda t: priority.get(t, 5), reverse=True)

        agent_assignments: Dict[str, List[str]] = {
            "recon-agent": sorted_targets,
            "dns-agent": sorted_targets,
            "exploit-agent": [],
            "web-exploit-agent": [],
            "creed-creds-agent": [],
        }
        for t in sorted_targets:
            agent_assignments.setdefault("web-discover-agent", []).append(t)
            agent_assignments.setdefault("vuln-scan-agent", []).append(t)
            if "api" in t.lower():
                agent_assignments["web-exploit-agent"].append(t)
            if "admin" in t.lower() or "auth" in t.lower():
                agent_assignments["creed-creds-agent"].append(t)

        agent_assignments.setdefault("pivot-agent", sorted_targets)
        agent_assignments.setdefault("analyzer-agent", sorted_targets)
        agent_assignments.setdefault("state-agent", sorted_targets)
        agent_assignments.setdefault("risk-agent", sorted_targets)
        agent_assignments.setdefault("report-agent", sorted_targets)

        self.engagement_plan = EngagementPlan(
            phase=_orch_mod.EngagementPhase.PLANNING,
            targets=targets,
            agent_assignments=agent_assignments,
            priority_matrix=priority,
        )
        self.session.engagement_plan = self.engagement_plan
        return self.engagement_plan

    # ------------------------------------------------------------------
    # 2. EXECUTE
    # ------------------------------------------------------------------

    async def execute(self) -> SessionMemory:
        """Deploy agents through scope gate and sanity checks via the message bus."""
        if not self.engagement_plan:
            return self.session

        self.engagement_plan.phase = _orch_mod.EngagementPhase.RECON
        await self._run_hooks(HookPoint.PRE_EXECUTE, {
            "phase": "execute", "targets": self.engagement_plan.targets,
        })

        phases = [
            (["recon-agent", "dns-agent", "web-discover-agent", "vuln-scan-agent"],
             _orch_mod.EngagementPhase.EXPLOITATION),
            (["exploit-agent", "web-exploit-agent", "creed-creds-agent", "pivot-agent"],
             _orch_mod.EngagementPhase.ANALYSIS),
            (["analyzer-agent", "state-agent", "risk-agent"],
             _orch_mod.EngagementPhase.REPORTING),
            (["report-agent"],
             _orch_mod.EngagementPhase.CLEANUP),
        ]

        for agent_types, next_phase in phases:
            if self._shutdown_requested:
                self.engagement_plan.phase = _orch_mod.EngagementPhase.ABORTED
                break
            tasks = []
            for agent_type in agent_types:
                targets = self.engagement_plan.agent_assignments.get(agent_type, self.engagement_plan.targets)
                for target in targets:
                    tasks.append(asyncio.create_task(self._delegate(agent_type, target)))
            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for r in results:
                    if isinstance(r, Exception):
                        logger.error("Agent deployment failed: %s", r)
            self.engagement_plan.phase = next_phase

        self.engagement_plan.phase = _orch_mod.EngagementPhase.COMPLETED
        await self._run_hooks(HookPoint.POST_EXECUTE, {
            "phase": "execute", "instances": len(self.agent_instances),
            "findings": self.message_bus.finding_count,
        })
        return self.session

    async def _delegate(
        self,
        agent_type: str,
        target: str,
        technique_id: Optional[str] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Optional[AgentInstance]:
        agent_type_enum = self._resolve_agent_type(agent_type)
        if not agent_type_enum:
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

        scope_report = self.scope_gate.authorize(
            target=target, action_type=action_type,
            technique_id=technique_id,
            current_connections=self.sanity_checker._active_connections,
        )
        if not scope_report.is_allowed():
            self.session.scope_violations.append(scope_report)
            return None

        safe, sanity_results = self.sanity_checker.is_task_safe_to_delegate(task)
        if not safe:
            return None

        await self._run_hooks(HookPoint.PRE_SCAN, {
            "agent_type": agent_type, "target": target, "task_id": task.task_id,
        })

        instance = AgentInstance(agent_type=agent_type, task_id=task.task_id)
        self.agent_instances[instance.instance_id] = instance
        self._running_tasks[instance.instance_id] = asyncio.create_task(
            self._run_agent(instance, task)
        )
        return instance

    async def _run_agent(self, instance: AgentInstance, task: DelegationTask) -> None:
        instance.lifecycle_state = _orch_mod.AgentLifecycleState.RUNNING
        instance.assigned_at = datetime.now(timezone.utc)
        self.message_bus.register_agent(instance.instance_id, task.agent_type.value)
        self.message_bus.update_agent_status(instance.instance_id, AgentStatus.BUSY)

        try:
            response = await self._generate_prompt(task)
            if response.error:
                instance.error = response.error
                instance.lifecycle_state = _orch_mod.AgentLifecycleState.FAILED
                await self._run_hooks(HookPoint.ON_ERROR, {
                    "phase": "run_agent", "agent_type": task.agent_type.value,
                    "target": task.target, "error": response.error,
                })
                return

            result = self._parse_output(response.content)
            for fd in result.get("findings", []):
                finding = self._make_finding(fd, task)
                self.message_bus.publish_finding(finding)
                instance.findings.append(finding.finding_id)
                await self._run_hooks(HookPoint.ON_FINDING, {
                    "finding_id": finding.finding_id, "title": finding.title,
                    "severity": finding.severity.value,
                    "agent_type": task.agent_type.value, "target": task.target,
                })

            await self._run_hooks(HookPoint.POST_SCAN, {
                "agent_type": task.agent_type.value, "target": task.target,
                "findings": instance.findings,
            })

            self.message_bus.send_message_sync(Message(
                message_type=MessageType.STATUS,
                sender=instance.instance_id,
                payload={"status": "completed", "agent_type": task.agent_type.value,
                         "target": task.target, "findings_count": len(instance.findings)},
            ))

            instance.result = result
            instance.lifecycle_state = _orch_mod.AgentLifecycleState.COMPLETED
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
            instance.error = str(exc)
            instance.lifecycle_state = _orch_mod.AgentLifecycleState.FAILED
            await self._run_hooks(HookPoint.ON_ERROR, {
                "phase": "run_agent", "agent_type": task.agent_type.value,
                "target": task.target, "error": str(exc),
            })
        finally:
            self.message_bus.update_agent_status(instance.instance_id, AgentStatus.COMPLETED)

    async def _generate_prompt(self, task: DelegationTask) -> LLMResponse:
        system = (
            f"You are the {task.agent_type.value} in the HiveBreach "
            f"penetration testing framework. Your role is to perform "
            f"{task.action_type.value} against {task.target}. "
            f"Stay within the authorized scope."
        )
        user = f"Target: {task.target}\nAction: {task.action_type.value}\n"
        if task.technique_id:
            user += f"Technique: {task.technique_id}\n"
        if task.params:
            user += f"Parameters: {json.dumps(task.params, indent=2)}\n"
        user += ("\nProvide your findings in JSON format with keys: "
                 "title, description, severity, evidence, commands_run, output")

        return await self.model_router.route(
            prompt=user, task_difficulty=self._infer_difficulty(task),
            agent_type=task.agent_type.value, system_prompt=system,
        )

    @staticmethod
    def _parse_output(content: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {"findings": [], "commands": [], "output": content}
        try:
            p = json.loads(content)
            if isinstance(p, list):
                result["findings"] = p
            elif isinstance(p, dict):
                result.update(p)
                result.setdefault("findings", [p])
        except json.JSONDecodeError:
            for block in re.findall(r'```(?:json)?\s*([\s\S]*?)```', content):
                try:
                    p = json.loads(block)
                    if isinstance(p, list):
                        result["findings"].extend(p)
                    elif isinstance(p, dict):
                        result["findings"].append(p)
                except json.JSONDecodeError:
                    pass
        return result

    @staticmethod
    def _make_finding(data: Dict[str, Any], task: DelegationTask) -> Finding:
        severity_map = {
            "critical": FindingSeverity.CRITICAL, "high": FindingSeverity.HIGH,
            "medium": FindingSeverity.MEDIUM, "low": FindingSeverity.LOW,
            "info": FindingSeverity.INFO,
        }
        return Finding(
            agent_type=task.agent_type.value,
            title=data.get("title", "Untitled Finding"),
            description=data.get("description", ""),
            severity=severity_map.get(data.get("severity", "").lower(), FindingSeverity.INFO),
            target=task.target,
            technique_id=task.technique_id or data.get("technique_id"),
            evidence=data.get("evidence", {}),
            raw_output=data.get("output", ""),
        )

    # ------------------------------------------------------------------
    # 3. VERIFY
    # ------------------------------------------------------------------

    async def verify(self) -> List[VerificationReport]:
        """Validate findings from execute phase — evidence, confidence, duplication checks."""
        logger.info("VERIFY: checking %d findings", self.message_bus.finding_count)
        await self._run_hooks(HookPoint.PRE_VERIFY, {"finding_count": self.message_bus.finding_count})

        self._verification_reports.clear()
        for finding_id, finding in self.message_bus.get_all_findings().items():
            score = 0.0
            if finding.evidence:
                score += 0.4
            if finding.raw_output:
                score += 0.3
            if finding.description:
                score += 0.2
            if finding.technique_id:
                score += 0.1
            score = round(min(score, 1.0), 2)

            if score >= 0.7:
                status = VerificationStatus.PASSED
            elif score >= 0.3:
                status = VerificationStatus.INCONCLUSIVE
            else:
                status = VerificationStatus.FAILED

            report = VerificationReport(
                finding_id=finding_id, title=finding.title, status=status,
                confidence_score=score,
                details={"has_evidence": bool(finding.evidence),
                         "has_output": bool(finding.raw_output),
                         "has_description": bool(finding.description),
                         "severity": finding.severity.value},
            )
            self._verification_reports[finding_id] = report
            self.message_bus.update_finding_verification(finding_id, status == VerificationStatus.PASSED)

        status_counts: Dict[str, int] = {}
        for r in self._verification_reports.values():
            status_counts[r.status.value] = status_counts.get(r.status.value, 0) + 1

        await self._run_hooks(HookPoint.POST_VERIFY, {
            "total": len(self._verification_reports), "status_counts": status_counts,
        })
        return list(self._verification_reports.values())

    # ------------------------------------------------------------------
    # 4. LEARN
    # ------------------------------------------------------------------

    async def learn(self) -> LearnSummary:
        """Extract patterns from the session and persist to the instinct store."""
        self._learn_summary = LearnSummary(session_id=self.session.session_id)
        verified = [
            f for f in self.message_bus.get_all_findings().values()
            if self._verification_reports.get(f.finding_id, VerificationReport("", "")).status == VerificationStatus.PASSED
        ]
        if not verified:
            self._learn_summary.status = LearnStatus.NO_PATTERNS
            return self._learn_summary

        technique_counts: Dict[str, int] = {}
        agent_type_counts: Dict[str, int] = {}
        for f in verified:
            tid = f.technique_id or "unknown"
            technique_counts[tid] = technique_counts.get(tid, 0) + 1
            agent_type_counts[f.agent_type] = agent_type_counts.get(f.agent_type, 0) + 1

        self._learn_summary.patterns_extracted = len(technique_counts)
        sev_counts: Dict[str, int] = {}
        for f in verified:
            sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1

        lessons: List[str] = []
        if sev_counts.get("critical", 0) > 0:
            lessons.append(f"Found {sev_counts['critical']} critical-severity findings")
        for tid, cnt in sorted(technique_counts.items(), key=lambda x: -x[1])[:3]:
            lessons.append(f"Technique {tid} appeared {cnt} time(s)")
        self._learn_summary.lessons = lessons

        patterns = {
            "session_id": self.session.session_id,
            "technique_counts": technique_counts,
            "agent_type_counts": agent_type_counts,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        try:
            self._instinct_store.parent.mkdir(parents=True, exist_ok=True)
            existing: Dict[str, Any] = {}
            if self._instinct_store.exists():
                existing = json.loads(self._instinct_store.read_text(encoding="utf-8"))
            sessions = existing.get("session_patterns", [])
            sessions.append(patterns)
            existing["session_patterns"] = sessions[-100:]
            existing["last_updated"] = datetime.now(timezone.utc).isoformat()
            self._instinct_store.write_text(json.dumps(existing, indent=2), encoding="utf-8")
            self._learn_summary.instinct_updates = 1
        except OSError as exc:
            logger.warning("Could not persist patterns: %s", exc)

        self._learn_summary.status = LearnStatus.EXTRACTED
        await self._run_hooks(HookPoint.ON_LEARN, {
            "patterns_extracted": self._learn_summary.patterns_extracted,
            "status": "extracted",
        })
        return self._learn_summary

    # ------------------------------------------------------------------
    # 5. PERSIST
    # ------------------------------------------------------------------

    async def persist(self, path: Optional[str] = None) -> str:
        """Save session state to disk with JSON export for audit."""
        self.session.last_save_time = datetime.now(timezone.utc)
        save_path = Path(path or (self.session_dir / f"session_{self.session.session_id[:8]}.pkl"))

        export = {
            "session_id": self.session.session_id,
            "session": self.session,
            "findings": self.message_bus.get_all_findings(),
            "verification_reports": self._verification_reports,
            "learn_summary": self._learn_summary,
            "harness_id": self.harness_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        with open(save_path, "wb") as fh:
            pickle.dump(export, fh)

        json_path = save_path.with_suffix(".json")
        json_export = {
            "session_id": self.session.session_id,
            "findings": [f.to_dict() for f in self.message_bus.get_all_findings().values()],
            "verification_reports": {
                rid: {"finding_id": r.finding_id, "title": r.title,
                      "status": r.status.value, "confidence_score": r.confidence_score}
                for rid, r in self._verification_reports.items()
            },
            "learn_summary": {
                "status": self._learn_summary.status.value if self._learn_summary else "not_run",
                "patterns_extracted": self._learn_summary.patterns_extracted if self._learn_summary else 0,
                "lessons": self._learn_summary.lessons if self._learn_summary else [],
            } if self._learn_summary else {},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump(json_export, fh, indent=2, default=str)

        await self._run_hooks(HookPoint.ON_PERSIST, {
            "path": str(save_path), "json_path": str(json_path),
            "findings_count": len(export["findings"]),
        })
        return str(save_path)

    # ------------------------------------------------------------------
    # Full lifecycle
    # ------------------------------------------------------------------

    async def run(self, targets: List[str], roe_path: Optional[str] = None) -> SessionMemory:
        """Run the full ECC lifecycle: Plan → Execute → Verify → Learn → Persist."""
        try:
            await self.plan(targets, roe_path=roe_path)
            await self.execute()
            await self.verify()
            await self.learn()
            save_path = await self.persist()
            logger.info(
                "ECC lifecycle complete: findings=%d, verifications=%d, saved=%s",
                self.message_bus.finding_count, len(self._verification_reports), save_path,
            )
        except Exception as exc:
            await self._run_hooks(HookPoint.ON_ERROR, {"phase": "run", "error": str(exc)})
            raise
        return self.session

    async def cleanup(self) -> None:
        """Cancel running tasks and close backends."""
        for task in self._running_tasks.values():
            task.cancel()
        await self.model_router.close_all()
        self._running_tasks.clear()

    def request_shutdown(self) -> None:
        self._shutdown_requested = True

    def load_session(self, path: str) -> Dict[str, Any]:
        """Load a previously persisted session from disk."""
        with open(path, "rb") as fh:
            export = pickle.load(fh)
        self.session = export.get("session", self.session)
        self.engagement_plan = self.session.engagement_plan
        self.agent_instances = getattr(self.session, "agent_instances", {})
        self._verification_reports = export.get("verification_reports", {})
        self._learn_summary = export.get("learn_summary")
        for finding_id, finding in export.get("findings", {}).items():
            self.message_bus.publish_finding(finding)
        return export

    def export_json(self) -> Dict[str, Any]:
        """Export all findings and reports as a JSON-safe dict."""
        return {
            "session_id": self.session.session_id,
            "harness_id": self.harness_id,
            "findings": [f.to_dict() for f in self.message_bus.get_all_findings().values()],
            "verification_reports": {
                rid: {"finding_id": r.finding_id, "title": r.title,
                      "status": r.status.value, "confidence_score": r.confidence_score}
                for rid, r in self._verification_reports.items()
            },
            "scope_violations": [
                {"target": v.target, "reason": v.reason, "result": v.result.value}
                for v in self.session.scope_violations
            ],
            "agent_summary": {
                iid: {"agent_type": inst.agent_type, "state": inst.lifecycle_state.value,
                      "findings": len(inst.findings)}
                for iid, inst in self.agent_instances.items()
            },
            "learn_summary": {
                "status": self._learn_summary.status.value if self._learn_summary else "not_run",
                "patterns_extracted": self._learn_summary.patterns_extracted if self._learn_summary else 0,
                "lessons": self._learn_summary.lessons if self._learn_summary else [],
            } if self._learn_summary else {},
        }

    @staticmethod
    def _resolve_agent_type(name: str) -> Optional[AgentType]:
        try:
            return AgentType(name)
        except ValueError:
            for at in AgentType:
                if at.value == name:
                    return at
            return None

    @staticmethod
    def _infer_action_type(agent_type: AgentType) -> ActionType:
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
        hard = {AgentType.EXPLOIT_POC, AgentType.PASSWORD_CREDENTIAL, AgentType.NETWORK_EXPERT}
        if task.agent_type in hard:
            return TaskDifficulty.HARD
        if task.action_type in (ActionType.EXPLOIT, ActionType.POST_EXPLOIT, ActionType.CREDENTIAL_ATTACK):
            return TaskDifficulty.HARD
        if task.action_type == ActionType.RECON:
            return TaskDifficulty.EASY
        return TaskDifficulty.MEDIUM
