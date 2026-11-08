from __future__ import annotations

import asyncio

import pytest

from conftest import (
    MessageBus,
    Message,
    MessageType,
    Finding,
    FindingSeverity,
    AgentStatus,
)


class TestMessageBus:
    @pytest.fixture(autouse=True)
    def reset_bus(self):
        MessageBus._instance = None
        yield
        bus = MessageBus()
        bus.reset()

    def test_singleton(self):
        bus1 = MessageBus()
        bus2 = MessageBus()
        assert bus1 is bus2

    def test_register_agent(self):
        bus = MessageBus()
        reg = bus.register_agent("agent-1", "recon-agent")
        assert reg.agent_id == "agent-1"
        assert reg.agent_type == "recon-agent"
        assert reg.status == AgentStatus.IDLE
        assert bus.agent_count == 1

    def test_register_multiple_agents(self):
        bus = MessageBus()
        bus.register_agent("a1", "recon")
        bus.register_agent("a2", "exploit")
        assert bus.agent_count == 2

    def test_deregister_agent(self):
        bus = MessageBus()
        bus.register_agent("agent-1", "recon")
        assert bus.deregister_agent("agent-1") is True
        assert bus.agent_count == 0

    def test_deregister_nonexistent(self):
        bus = MessageBus()
        assert bus.deregister_agent("ghost") is False

    def test_update_agent_status(self):
        bus = MessageBus()
        bus.register_agent("agent-1", "recon")
        bus.update_agent_status("agent-1", AgentStatus.BUSY)
        reg = bus.get_agent("agent-1")
        assert reg.status == AgentStatus.BUSY

    def test_heartbeat(self):
        bus = MessageBus()
        bus.register_agent("agent-1", "recon")
        assert bus.heartbeat("agent-1") is True
        assert bus.heartbeat("ghost") is False

    def test_get_agents_by_type(self):
        bus = MessageBus()
        bus.register_agent("a1", "recon")
        bus.register_agent("a2", "recon")
        bus.register_agent("a3", "exploit")
        agents = bus.get_agents_by_type("recon")
        assert len(agents) == 2


class TestMessagePublishing:
    @pytest.fixture(autouse=True)
    def reset_bus(self):
        MessageBus._instance = None
        yield
        bus = MessageBus()
        bus.reset()

    def test_publish_message(self):
        bus = MessageBus()
        bus.register_agent("agent-1", "recon")
        msg = Message(
            message_type=MessageType.STATUS,
            sender="agent-1",
            payload={"status": "running"},
        )
        sent = bus.send_message_sync(msg)
        assert sent is True
        assert bus.message_count == 1

    def test_subscribe_to_topic(self):
        bus = MessageBus()
        bus.register_agent("agent-1", "recon")
        bus.subscribe("agent-1", MessageType.FINDING)
        msg = Message(
            message_type=MessageType.FINDING,
            sender="test",
            payload={"finding": "test"},
        )
        bus.send_message_sync(msg)
        assert bus.message_count == 1

    def test_message_routing_to_recipient(self):
        bus = MessageBus()
        bus.register_agent("sender", "recon")
        bus.register_agent("recipient", "exploit")
        msg = Message(
            message_type=MessageType.HANDOFF,
            sender="sender",
            recipient="recipient",
            payload={"data": "handoff"},
        )
        bus.send_message_sync(msg)
        assert bus.message_count == 1

    def test_message_not_routed_to_wrong_agent(self):
        bus = MessageBus()
        bus.register_agent("sender", "recon")
        bus.register_agent("other", "exploit")
        msg = Message(
            message_type=MessageType.HANDOFF,
            sender="sender",
            recipient="nonexistent",
            payload={"data": "lost"},
        )
        sent = bus.send_message_sync(msg)
        assert sent is False

    def test_publish_to_multiple_subscribers(self):
        bus = MessageBus()
        bus.register_agent("sub1", "verification-correlation-agent")
        bus.register_agent("sub2", "report-agent")
        msg = Message(
            message_type=MessageType.STATUS,
            sender="test",
        )
        bus.send_message_sync(msg)
        assert bus.message_count == 1

    def test_broadcast_message(self):
        bus = MessageBus()
        bus.register_agent("a1", "recon")
        bus.register_agent("a2", "exploit")
        bus.subscribe("a1", MessageType.FINDING)
        bus.subscribe("a2", MessageType.FINDING)
        msg = Message(message_type=MessageType.FINDING, sender="test")
        bus.send_message_sync(msg)
        assert bus.message_count == 1


class TestBlackboard:
    @pytest.fixture(autouse=True)
    def reset_bus(self):
        MessageBus._instance = None
        yield
        bus = MessageBus()
        bus.reset()

    def test_blackboard_shared_findings(self):
        bus = MessageBus()
        finding = Finding(
            agent_type="recon-agent",
            title="Open Port",
            severity=FindingSeverity.HIGH,
            target="10.0.0.1",
        )
        bus.publish_finding(finding)
        assert bus.finding_count == 1
        retrieved = bus.get_finding(finding.finding_id)
        assert retrieved is not None
        assert retrieved.title == "Open Port"

    def test_get_all_findings(self):
        bus = MessageBus()
        f1 = Finding(agent_type="recon", title="F1")
        f2 = Finding(agent_type="exploit", title="F2")
        bus.publish_finding(f1)
        bus.publish_finding(f2)
        all_f = bus.get_all_findings()
        assert len(all_f) == 2

    def test_get_findings_with_filters(self):
        bus = MessageBus()
        bus.publish_finding(Finding(agent_type="recon", title="F1", severity=FindingSeverity.HIGH))
        bus.publish_finding(Finding(agent_type="exploit", title="F2", severity=FindingSeverity.LOW))
        results = bus.get_findings(agent_type="recon")
        assert len(results) == 1
        results = bus.get_findings(severity=FindingSeverity.LOW)
        assert len(results) == 1

    def test_update_finding_verification(self):
        bus = MessageBus()
        finding = Finding(agent_type="recon", title="Test")
        bus.publish_finding(finding)
        assert finding.verified is False
        bus.update_finding_verification(finding.finding_id, True)
        updated = bus.get_finding(finding.finding_id)
        assert updated.verified is True

    def test_subscribe_to_finding_type(self):
        bus = MessageBus()
        bus.register_agent("agent-1", "recon")
        bus.subscribe_to_finding_type("agent-1", "T1046")
        assert bus._finding_subscribers.get("T1046") == {"agent-1"}


class TestCorrelationId:
    @pytest.fixture(autouse=True)
    def reset_bus(self):
        MessageBus._instance = None
        yield
        bus = MessageBus()
        bus.reset()

    def test_correlation_id_traceability(self):
        bus = MessageBus()
        bus.register_agent("a1", "recon")
        bus.register_agent("a2", "exploit")
        corr_id = "corr-001"
        msg1 = Message(
            message_type=MessageType.STATUS,
            sender="a1",
            correlation_id=corr_id,
            payload={"step": 1},
        )
        msg2 = Message(
            message_type=MessageType.STATUS,
            sender="a2",
            correlation_id=corr_id,
            payload={"step": 2},
        )
        bus.send_message_sync(msg1)
        bus.send_message_sync(msg2)
        all_history = bus.get_message_history()
        matched = [m for m in all_history if m.correlation_id == corr_id]
        assert len(matched) == 2


class TestMessageHistory:
    @pytest.fixture(autouse=True)
    def reset_bus(self):
        MessageBus._instance = None
        yield
        bus = MessageBus()
        bus.reset()

    def test_get_message_history(self):
        bus = MessageBus()
        bus.register_agent("a1", "recon")
        bus.send_message_sync(Message(message_type=MessageType.STATUS, sender="a1"))
        history = bus.get_message_history(sender="a1")
        assert len(history) == 1

    def test_get_audit_log(self):
        bus = MessageBus()
        bus.register_agent("a1", "recon")
        bus.send_message_sync(Message(message_type=MessageType.STATUS, sender="a1"))
        log = bus.get_audit_log()
        assert len(log) == 1
        assert log[0]["sender"] == "a1"

    def test_clear_history(self):
        bus = MessageBus()
        bus.register_agent("a1", "recon")
        bus.send_message_sync(Message(message_type=MessageType.STATUS, sender="a1"))
        assert bus.message_count == 1
        bus.clear_history()
        assert bus.message_count == 0


class TestCallbacks:
    @pytest.fixture(autouse=True)
    def reset_bus(self):
        MessageBus._instance = None
        yield
        bus = MessageBus()
        bus.reset()

    def test_add_callback(self):
        bus = MessageBus()
        received = []
        def cb(msg):
            received.append(msg)
        bus.add_callback(cb)
        bus.register_agent("a1", "recon")
        bus.send_message_sync(Message(message_type=MessageType.STATUS, sender="a1"))
        assert len(received) == 1

    def test_remove_callback(self):
        bus = MessageBus()
        received = []
        def cb(msg):
            received.append(msg)
        bus.add_callback(cb)
        bus.remove_callback(cb)
        bus.register_agent("a1", "recon")
        bus.send_message_sync(Message(message_type=MessageType.STATUS, sender="a1"))
        assert len(received) == 0


class TestStats:
    @pytest.fixture(autouse=True)
    def reset_bus(self):
        MessageBus._instance = None
        yield
        bus = MessageBus()
        bus.reset()

    def test_get_stats(self):
        bus = MessageBus()
        bus.register_agent("a1", "recon")
        bus.publish_finding(Finding(agent_type="recon", title="T1"))
        stats = bus.get_stats()
        assert stats["agents"] == 1
        assert stats["findings"] == 1
