from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
# Ensure conftest is also reachable via bare name (not just tests.conftest)
_this_mod = sys.modules.get(__name__)
if _this_mod and __name__ != "conftest":
    sys.modules["conftest"] = _this_mod

BASE = Path(__file__).resolve().parent.parent


def _load_module(path_str: str):
    path = BASE / path_str
    if not path.is_file():
        raise ImportError(f"Cannot find module at {path}")
    name = path.stem.replace("-", "_")
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


# Load orchestrator first — all orchestration-layer types come from it
# to ensure enum identity matches (same module instance).
orch_mod = _load_module("orchestration/orchestrator.py")
HiveOrchestrator = orch_mod.HiveOrchestrator
EngagementPhase = orch_mod.EngagementPhase
AgentLifecycleState = orch_mod.AgentLifecycleState
EngagementPlan = orch_mod.EngagementPlan
SessionMemory = orch_mod.SessionMemory
AgentInstance = orch_mod.AgentInstance

ScopeEnforcer = orch_mod.ScopeEnforcer
ActionType = orch_mod.ActionType
ScopeCheckResult = orch_mod.ScopeCheckResult
DelegationSanityChecker = orch_mod.DelegationSanityChecker
DelegationTask = orch_mod.DelegationTask
SanityStatus = orch_mod.SanityStatus
SanityCheckResult = orch_mod.SanityCheckResult
AgentType = orch_mod.AgentType
MessageBus = orch_mod.MessageBus
Message = orch_mod.Message
MessageType = orch_mod.MessageType
Finding = orch_mod.Finding
FindingSeverity = orch_mod.FindingSeverity
AgentStatus = orch_mod.AgentStatus

# RoEDocument is a dataclass (not enum) — load separately, no identity issue
gate_mod_src = _load_module("orchestration/scope-auth-gate/gate.py")
RoEDocument = gate_mod_src.RoEDocument
ScopeCheckReport = gate_mod_src.ScopeCheckReport

# Non-orchestration modules — loaded separately
audit_mod = _load_module("governance/audit-trail/audit-logger.py")
AuditLogger = audit_mod.AuditLogger

poc_mod = _load_module("execution-engine/poc-validator.py")
PoCValidator = poc_mod.PoCValidator
VerificationTrack = poc_mod.VerificationTrack
ConfidenceLevel = poc_mod.ConfidenceLevel
VerificationResult = poc_mod.VerificationResult

vault_mod = _load_module("execution-engine/secrets-vault/vault_manager.py")
SecretsVault = vault_mod.SecretsVault

hooks_mod = _load_module("hooks/registry.py")
HookRegistry = hooks_mod.HookRegistry
register_hook = hooks_mod.register_hook
execute = hooks_mod.execute


SAMPLE_ROE_YAML = """
title: Test Engagement
client_name: Test Client
engagement_id: ENG-001
effective_date: "2024-01-01T00:00:00"
expiration_date: "2030-12-31T23:59:59"
scope:
  authorized_domains:
    - "*.acme.com"
    - "api.acme.com"
  authorized_ip_ranges:
    - "10.0.0.0/24"
    - "192.168.1.0/24"
  excluded_domains:
    - "admin.acme.com"
  excluded_ip_ranges:
    - "10.0.0.100/32"
  authorized_repos:
    - "github.com/acme/*"
rules:
  authorized_action_types:
    - recon
    - scan
    - exploit
  prohibited_techniques:
    - T1499
  max_severity: high
  time_budget_hours: 24
  concurrent_connections_max: 10
  allowed_ports:
    - 80
    - 443
    - 22
  prohibited_ports:
    - 3389
"""


@pytest.fixture
def tmp_engagement():
    with tempfile.TemporaryDirectory() as tmpdir:
        roe_path = os.path.join(tmpdir, "roe.yaml")
        with open(roe_path, "w") as f:
            f.write(SAMPLE_ROE_YAML)
        yield tmpdir


@pytest.fixture
def roe_path(tmp_engagement):
    return os.path.join(tmp_engagement, "roe.yaml")


@pytest.fixture
def mock_scope_gate(roe_path):
    gate = ScopeEnforcer(roe_path)
    return gate


@pytest.fixture
def scope_enforcer():
    return ScopeEnforcer()


@pytest.fixture
def sample_finding():
    return {
        "finding_id": "find-001",
        "agent_type": "recon-agent",
        "title": "Open port 22",
        "description": "SSH port is open on target",
        "severity": "medium",
        "target": "10.0.0.5",
        "technique_id": "T1046",
        "evidence": {"port": 22, "service": "ssh"},
        "raw_output": "22/tcp open ssh",
    }


@pytest.fixture
def harness_instance(monkeypatch, roe_path):
    monkeypatch.setenv("LLM_ROUTER_CONFIG", "")
    monkeypatch.setenv("OLLAMA_HOST", "http://127.0.0.1:11434")
    monkeypatch.setenv("OPENAI_API_KEY", "")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "")
    MessageBus._instance = None
    orch = HiveOrchestrator(roe_path=roe_path, session_dir=tempfile.mkdtemp())
    yield orch
    orch.message_bus.reset()


@pytest.fixture
def message_bus():
    bus = MessageBus()
    bus.reset()
    return bus


@pytest.fixture
def audit_logger():
    with tempfile.TemporaryDirectory() as tmpdir:
        key = b"test-hmac-key-32-bytes-long!!!"
        logger = AuditLogger(tmpdir, hmac_key=key, max_file_size_mb=1)
        yield logger


@pytest.fixture
def vault_instance(monkeypatch):
    monkeypatch.setenv("SECRETS_VAULT_KEY", "test-vault-key-16chr")
    return SecretsVault()
