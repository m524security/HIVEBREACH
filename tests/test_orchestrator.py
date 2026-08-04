import json
import pytest


class MockAgent:
    def __init__(self, name: str, role: str):
        self.name = name
        self.role = role
        self.tasks: list = []

    def assign(self, task: dict) -> None:
        self.tasks.append(task)

    def execute(self) -> dict:
        return {"agent": self.name, "status": "done", "result": {}}


class MockOrchestrator:
    def __init__(self):
        self.agents: dict[str, MockAgent] = {}
        self.pipeline: list = []
        self.scope: dict = {}
        self.audit_log: list = []

    def register_agent(self, name: str, role: str) -> MockAgent:
        agent = MockAgent(name, role)
        self.agents[name] = agent
        return agent

    def set_scope(self, scope: dict) -> None:
        self.scope = scope

    def build_pipeline(self, steps: list) -> None:
        self.pipeline = steps

    def run_pipeline(self) -> list:
        results = []
        for step in self.pipeline:
            agent_name = step.get("agent")
            agent = self.agents.get(agent_name)
            if not agent:
                continue
            agent.assign(step)
            result = agent.execute()
            self.audit_log.append({"step": step, "result": result})
            results.append(result)
        return results

    def get_audit_log(self) -> list:
        return self.audit_log


@pytest.fixture
def orchestrator():
    return MockOrchestrator()


class TestMockOrchestrator:
    def test_register_agent(self, orchestrator):
        agent = orchestrator.register_agent("recon-1", "reconnaissance")
        assert agent.name == "recon-1"
        assert agent.role == "reconnaissance"

    def test_set_scope(self, orchestrator):
        scope = {"target": "10.0.0.1/24", "rules": ["no-dos"]}
        orchestrator.set_scope(scope)
        assert orchestrator.scope == scope

    def test_build_pipeline(self, orchestrator):
        steps = [
            {"agent": "recon-1", "action": "scan", "target": "10.0.0.1"},
            {"agent": "exploit-1", "action": "exploit", "target": "10.0.0.1"},
        ]
        orchestrator.build_pipeline(steps)
        assert len(orchestrator.pipeline) == 2

    def test_run_pipeline(self, orchestrator):
        orchestrator.register_agent("recon-1", "reconnaissance")
        orchestrator.register_agent("exploit-1", "exploitation")
        steps = [
            {"agent": "recon-1", "action": "scan"},
            {"agent": "exploit-1", "action": "exploit"},
        ]
        orchestrator.build_pipeline(steps)
        results = orchestrator.run_pipeline()
        assert len(results) == 2
        for r in results:
            assert r["status"] == "done"

    def test_audit_log(self, orchestrator):
        orchestrator.register_agent("recon-1", "reconnaissance")
        orchestrator.build_pipeline([{"agent": "recon-1", "action": "scan"}])
        orchestrator.run_pipeline()
        log = orchestrator.get_audit_log()
        assert len(log) == 1
        entry = log[0]
        assert "step" in entry
        assert "result" in entry

    def test_run_empty_pipeline(self, orchestrator):
        orchestrator.build_pipeline([])
        results = orchestrator.run_pipeline()
        assert results == []

    def test_run_pipeline_missing_agent(self, orchestrator):
        orchestrator.build_pipeline([{"agent": "nonexistent", "action": "scan"}])
        results = orchestrator.run_pipeline()
        assert results == []

    def test_pipeline_order(self, orchestrator):
        orchestrator.register_agent("a1", "recon")
        orchestrator.register_agent("a2", "exploit")
        steps = [
            {"agent": "a1", "action": "phase-1"},
            {"agent": "a2", "action": "phase-2"},
            {"agent": "a1", "action": "phase-3"},
        ]
        orchestrator.build_pipeline(steps)
        results = orchestrator.run_pipeline()
        executed_agents = [r["agent"] for r in results]
        assert executed_agents == ["a1", "a2", "a1"]

    def test_audit_log_serializable(self, orchestrator):
        orchestrator.register_agent("recon-1", "reconnaissance")
        orchestrator.build_pipeline([{"agent": "recon-1", "action": "scan"}])
        orchestrator.run_pipeline()
        log = orchestrator.get_audit_log()
        json_str = json.dumps(log, default=str)
        assert isinstance(json_str, str)
        assert len(json_str) > 0
