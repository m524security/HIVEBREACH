from __future__ import annotations

import asyncio
import os
import tempfile
from unittest.mock import patch

import pytest

from conftest import (
    HiveOrchestrator,
    EngagementPhase,
    AgentLifecycleState,
    EngagementPlan,
    SessionMemory,
    AgentInstance,
    FindingSeverity,
    ActionType,
    AgentType,
    DelegationTask,
)


class TestHiveOrchestratorInit:
    def test_harness_initialization(self, roe_path):
        orch = HiveOrchestrator(roe_path=roe_path)
        assert orch.orchestrator_id.startswith("orchestrator-")
        assert orch.scope_gate is not None
        assert orch.sanity_checker is not None
        assert orch.session is not None
        assert orch.engagement_plan is None

    def test_harness_with_defaults(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            orch = HiveOrchestrator(session_dir=tmpdir)
            assert orch.session_dir.exists()
            assert orch.scope_gate.roe is None


class TestEngagementPlan:
    def test_plan_creation(self, harness_instance):
        plan = harness_instance.engagement_plan
        assert plan is None
        targets = ["10.0.0.1", "api.acme.com"]

        async def run():
            harness_instance.engagement_plan = EngagementPlan(
                phase=EngagementPhase.PLANNING, targets=targets
            )
            harness_instance.session.engagement_plan = harness_instance.engagement_plan
            await harness_instance._phase_planning()
            return harness_instance.engagement_plan

        plan = asyncio.run(run())
        assert plan is not None
        assert "recon-agent" in plan.agent_assignments
        assert "network-expert-agent" in plan.agent_assignments
        assert "api.acme.com" in plan.priority_matrix

    def test_target_priority_scoring(self, harness_instance):
        assert harness_instance._score_target_priority("api.prod.com") == 10
        assert harness_instance._score_target_priority("api.admin.com") == 9
        assert harness_instance._score_target_priority("dev.test.com") == 4
        assert harness_instance._score_target_priority("unknown.com") == 5


class TestPhaseHandlers:
    def test_advance_phase(self, harness_instance):
        from conftest import EngagementPlan, EngagementPhase
        plan = EngagementPlan(phase=EngagementPhase.PLANNING)
        harness_instance.engagement_plan = plan
        harness_instance.advance_phase()
        assert harness_instance.engagement_plan.phase.value == "recon"
        harness_instance.advance_phase()
        assert harness_instance.engagement_plan.phase.value == "exploitation"

    def test_advance_to_specific_phase(self, harness_instance):
        harness_instance.engagement_plan = EngagementPlan()
        harness_instance.advance_phase(EngagementPhase.REPORTING)
        assert harness_instance.engagement_plan.phase == EngagementPhase.REPORTING

    def test_phase_planning_sets_next_phase(self, harness_instance):
        from conftest import EngagementPlan, EngagementPhase, ActionType
        async def go():
            harness_instance.engagement_plan = EngagementPlan(
                phase=EngagementPhase.PLANNING, targets=["10.0.0.1"]
            )
            harness_instance.session.engagement_plan = harness_instance.engagement_plan
            await harness_instance._phase_planning()
            return harness_instance.engagement_plan.phase

        phase = asyncio.run(go())
        assert phase.value == "recon"


class TestAgentDelegation:
    def test_resolve_agent_type(self, harness_instance):
        from conftest import orch_mod
        at = harness_instance._resolve_agent_type("recon-agent")
        assert at is not None
        assert at.value == "recon-agent"
        assert harness_instance._resolve_agent_type("invalid-agent") is None

    def test_infer_action_type(self, harness_instance):
        from conftest import AgentType, ActionType
        assert harness_instance._infer_action_type(
            AgentType.RECON
        ).value == "recon"
        assert harness_instance._infer_action_type(
            AgentType.WEB_EXPERT
        ).value == "exploit"

    def test_infer_difficulty(self, harness_instance):
        from conftest import DelegationTask, AgentType, ActionType

        task = DelegationTask(
            task_id="t1",
            agent_type=AgentType.RECON,
            action_type=ActionType.RECON,
            target="10.0.0.1",
        )
        assert harness_instance._infer_difficulty(task).value == "easy"

        task2 = DelegationTask(
            task_id="t2",
            agent_type=AgentType.EXPLOIT_POC,
            action_type=ActionType.EXPLOIT,
            target="10.0.0.1",
        )
        assert harness_instance._infer_difficulty(task2).value == "hard"


class TestVerifyStep:
    def test_verify_step_scope_blocked(self, harness_instance):
        async def go():
            result = await harness_instance.delegate_to_agent(
                "recon-agent", "admin.acme.com"
            )
            return result

        result = asyncio.run(go())
        assert result is None
        assert len(harness_instance.session.scope_violations) > 0

    def test_verify_step_unknown_agent(self, harness_instance):
        async def go():
            result = await harness_instance.delegate_to_agent(
                "ghost-agent", "10.0.0.1"
            )
            return result

        result = asyncio.run(go())
        assert result is None


class TestLearnStep:
    def test_learn_step_completed_tasks(self, harness_instance):
        harness_instance.engagement_plan = EngagementPlan(
            targets=["10.0.0.1"], phase=EngagementPhase.EXPLOITATION
        )
        assert len(harness_instance.session.completed_tasks) == 0

    def test_detect_conflicts(self, harness_instance):
        harness_instance.agent_instances = {
            "inst-1": AgentInstance(
                instance_id="inst-1",
                agent_type="recon-agent",
                lifecycle_state=AgentLifecycleState.RUNNING,
            ),
            "inst-2": AgentInstance(
                instance_id="inst-2",
                agent_type="exploit-poc-agent",
                lifecycle_state=AgentLifecycleState.RUNNING,
            ),
        }
        harness_instance.session.completed_tasks = [
            {
                "instance_id": "inst-1",
                "agent_type": "recon-agent",
                "target": "10.0.0.1",
                "findings": [],
                "completed_at": "2024-01-01T00:00:00",
            },
            {
                "instance_id": "inst-2",
                "agent_type": "exploit-poc-agent",
                "target": "10.0.0.1",
                "findings": [],
                "completed_at": "2024-01-01T00:00:00",
            },
        ]
        conflicts = harness_instance.detect_conflicts()
        assert len(conflicts) >= 1
        assert conflicts[0]["type"] == "duplicate_target"

    def test_resolve_conflict(self, harness_instance):
        conflict = {
            "type": "duplicate_target",
            "target": "10.0.0.1",
            "agents": ["exploit-poc-agent", "recon-agent"],
            "severity": "medium",
        }
        winner = harness_instance.resolve_conflict(conflict)
        assert winner == "recon-agent"


class TestPersistStep:
    def test_persist_step_save_session(self, harness_instance):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "test_session.pkl")
            harness_instance.session = SessionMemory()
            saved = harness_instance.save_session(path)
            assert saved == path
            assert os.path.isfile(path)

    def test_persist_step_load_session(self, harness_instance):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "test_session.pkl")
            harness_instance.session.session_id = "test-session-123"
            harness_instance.save_session(path)
            harness_instance.load_session(path)
            assert harness_instance.session.session_id == "test-session-123"

    def test_export_findings(self, harness_instance):
        from conftest import Finding, FindingSeverity

        finding = Finding(
            agent_type="recon-agent",
            title="Test Finding",
            severity=FindingSeverity.HIGH,
            target="10.0.0.1",
        )
        harness_instance.message_bus.publish_finding(finding)
        exported = harness_instance.export_findings()
        assert exported["session_id"] == harness_instance.session.session_id
        assert len(exported["findings"]) == 1
        assert exported["findings"][0]["title"] == "Test Finding"


class TestEmptyPlan:
    def test_empty_plan_handling(self, harness_instance):
        assert harness_instance.engagement_plan is None

        async def go():
            harness_instance.engagement_plan = EngagementPlan(
                phase=EngagementPhase.PLANNING, targets=[]
            )
            harness_instance.session.engagement_plan = harness_instance.engagement_plan
            await harness_instance._phase_planning()
            return harness_instance.engagement_plan.agent_assignments

        assignments = asyncio.run(go())
        assert isinstance(assignments, dict)

    def test_no_handler_for_unknown_phase(self, harness_instance, caplog):
        harness_instance.engagement_plan = EngagementPlan(
            phase=EngagementPhase.COMPLETED
        )
        async def go():
            handler = harness_instance._phase_handlers.get(
                harness_instance.engagement_plan.phase
            )
            return handler

        handler = asyncio.run(go())
        assert handler is None


class TestShutdown:
    def test_request_shutdown(self, harness_instance):
        harness_instance.request_shutdown()
        assert harness_instance._shutdown_requested is True

    def test_parse_agent_output(self, harness_instance):
        json_content = '{"findings": [{"title": "XSS", "severity": "high"}]}'
        result = harness_instance._parse_agent_output(json_content, None)
        assert len(result["findings"]) == 1
        assert result["findings"][0]["title"] == "XSS"

    def test_parse_agent_output_with_code_blocks(self, harness_instance):
        content = 'Some text ```json\n{"title": "SQLI", "severity": "critical"}\n``` more'
        result = harness_instance._parse_agent_output(content, None)
        assert len(result["findings"]) == 1
        assert result["findings"][0]["title"] == "SQLI"

    def test_create_finding(self, harness_instance):
        from conftest import DelegationTask, AgentType, ActionType

        data = {"title": "Vuln", "severity": "high", "description": "Test"}
        task = DelegationTask(
            task_id="t1",
            agent_type=AgentType.RECON,
            action_type=ActionType.RECON,
            target="10.0.0.1",
        )
        finding = harness_instance._create_finding(data, task)
        assert finding.title == "Vuln"
        assert finding.severity.value == "high"
        assert finding.target == "10.0.0.1"
