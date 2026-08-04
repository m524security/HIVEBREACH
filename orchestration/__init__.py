"""HiveBreach Orchestration Layer — ECC-style Plan→Execute→Verify→Learn→Persist engine."""

from __future__ import annotations

import importlib.util
import os
import sys

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


_router_mod = _load_module("_router", os.path.join("llm-router", "router.py"))
_gate_mod = _load_module("_gate", os.path.join("scope-auth-gate", "gate.py"))
_sanity_mod = _load_module("_sanity", os.path.join("sanity-check-layer", "sanity.py"))
_bus_mod = _load_module("_bus", os.path.join("communication-bus", "message_bus.py"))
_harness_mod = _load_module("_harness", "harness.py")
_orch_mod = _load_module("_orchestrator", "orchestrator.py")

from .harness import HiveBreachHarness
from .orchestrator import HiveOrchestrator, EngagementPhase, AgentLifecycleState

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

__all__ = [
    "HiveBreachHarness",
    "HiveOrchestrator",
    "EngagementPhase",
    "AgentLifecycleState",
    "ModelRouter",
    "LLMResponse",
    "TaskDifficulty",
    "ScopeEnforcer",
    "ScopeCheckReport",
    "ScopeCheckResult",
    "ActionType",
    "DelegationSanityChecker",
    "DelegationTask",
    "SanityCheckResult",
    "SanityStatus",
    "AgentType",
    "MessageBus",
    "Message",
    "MessageType",
    "Finding",
    "FindingSeverity",
    "AgentStatus",
    "EngagementPlan",
    "AgentInstance",
    "SessionMemory",
]
