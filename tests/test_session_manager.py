from __future__ import annotations

import os
import pickle
import tempfile

import pytest

from conftest import (
    HiveOrchestrator,
    EngagementPhase,
    EngagementPlan,
    SessionMemory,
    AgentInstance,
    MessageBus,
    Finding,
    FindingSeverity,
)


class TestSessionSave:
    def test_save_session(self, harness_instance):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "session.pkl")
            harness_instance.session = SessionMemory()
            saved = harness_instance.save_session(path)
            assert os.path.isfile(saved)
            with open(saved, "rb") as f:
                loaded = pickle.load(f)
            assert isinstance(loaded, SessionMemory)

    def test_save_session_with_plan(self, harness_instance):
        with tempfile.TemporaryDirectory() as tmpdir:
            harness_instance.engagement_plan = EngagementPlan(
                phase=EngagementPhase.RECON,
                targets=["10.0.0.1", "10.0.0.2"],
            )
            harness_instance.session.engagement_plan = harness_instance.engagement_plan
            path = os.path.join(tmpdir, "session.pkl")
            harness_instance.save_session(path)
            loaded = harness_instance.load_session(path)
            assert loaded.engagement_plan is not None
            assert len(loaded.engagement_plan.targets) == 2

    def test_save_session_with_findings(self, harness_instance):
        with tempfile.TemporaryDirectory() as tmpdir:
            finding = Finding(
                agent_type="recon-agent",
                title="Open Port",
                severity=FindingSeverity.HIGH,
                target="10.0.0.1",
            )
            harness_instance.message_bus.publish_finding(finding)
            path = os.path.join(tmpdir, "session.pkl")
            harness_instance.save_session(path)
            loaded = harness_instance.load_session(path)
            assert loaded.session_id == harness_instance.session.session_id


class TestSessionLoad:
    def test_load_session(self, harness_instance):
        with tempfile.TemporaryDirectory() as tmpdir:
            original_id = "test-load-session"
            harness_instance.session.session_id = original_id
            path = os.path.join(tmpdir, "session.pkl")
            harness_instance.save_session(path)
            harness_instance.load_session(path)
            assert harness_instance.session.session_id == original_id

    def test_load_session_restores_plan(self, harness_instance):
        with tempfile.TemporaryDirectory() as tmpdir:
            plan = EngagementPlan(
                phase=EngagementPhase.EXPLOITATION,
                targets=["api.acme.com"],
            )
            harness_instance.session.engagement_plan = plan
            harness_instance.engagement_plan = plan
            path = os.path.join(tmpdir, "session.pkl")
            harness_instance.save_session(path)
            new_orch = HiveOrchestrator(session_dir=tmpdir)
            new_orch.load_session(path)
            assert new_orch.engagement_plan is not None
            assert new_orch.engagement_plan.phase == EngagementPhase.EXPLOITATION
            assert "api.acme.com" in new_orch.engagement_plan.targets

    def test_load_session_restores_agent_instances(self, harness_instance):
        with tempfile.TemporaryDirectory() as tmpdir:
            instance = AgentInstance(
                instance_id="inst-001",
                agent_type="recon-agent",
                task_id="task-001",
            )
            harness_instance.agent_instances["inst-001"] = instance
            harness_instance.session.agent_instances["inst-001"] = instance
            path = os.path.join(tmpdir, "session.pkl")
            harness_instance.save_session(path)
            harness_instance.load_session(path)
            assert "inst-001" in harness_instance.agent_instances
            assert harness_instance.agent_instances["inst-001"].agent_type == "recon-agent"

    def test_load_nonexistent_file_raises(self, harness_instance):
        with pytest.raises(FileNotFoundError):
            harness_instance.load_session("/nonexistent/path/session.pkl")


class TestCrossSessionContext:
    def test_cross_session_context(self, harness_instance):
        with tempfile.TemporaryDirectory() as tmpdir:
            finding1 = Finding(
                agent_type="recon-agent",
                title="Finding from Session 1",
                severity=FindingSeverity.HIGH,
                target="10.0.0.1",
            )
            harness_instance.message_bus.publish_finding(finding1)
            path1 = os.path.join(tmpdir, "session1.pkl")
            harness_instance.save_session(path1)

            harness_instance2 = HiveOrchestrator(session_dir=tmpdir)
            harness_instance2.load_session(path1)
            assert harness_instance2.message_bus.finding_count >= 1
            findings = harness_instance2.message_bus.get_findings()
            assert any(f.title == "Finding from Session 1" for f in findings)

    def test_session_export_findings(self, harness_instance):
        with tempfile.TemporaryDirectory() as tmpdir:
            f1 = Finding(agent_type="recon", title="F1", severity=FindingSeverity.CRITICAL, target="t1")
            f2 = Finding(agent_type="exploit", title="F2", severity=FindingSeverity.LOW, target="t2")
            harness_instance.message_bus.publish_finding(f1)
            harness_instance.message_bus.publish_finding(f2)
            exported = harness_instance.export_findings()
            assert exported["summary"]["total_findings"] == 2
            assert exported["summary"]["by_severity"]["critical"] == 1
            assert exported["summary"]["by_severity"]["low"] == 1


class TestEmptySession:
    def test_empty_session_handling(self, harness_instance):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "empty.pkl")
            harness_instance.save_session(path)
            assert os.path.isfile(path)
            loaded = harness_instance.load_session(path)
            assert loaded is not None
            assert loaded.scope_violations == []
            assert loaded.completed_tasks == []

    def test_session_with_no_plan(self, harness_instance):
        assert harness_instance.engagement_plan is None
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "no_plan.pkl")
            harness_instance.session.engagement_plan = None
            harness_instance.save_session(path)
            loaded = harness_instance.load_session(path)
            assert loaded.engagement_plan is None

    def test_agent_instances_empty_after_load(self, harness_instance):
        with tempfile.TemporaryDirectory() as tmpdir:
            harness_instance.agent_instances = {}
            path = os.path.join(tmpdir, "no_agents.pkl")
            harness_instance.save_session(path)
            harness_instance.load_session(path)
            assert harness_instance.agent_instances == {}
