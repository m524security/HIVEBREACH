from __future__ import annotations

import pytest

from conftest import (
    DelegationSanityChecker,
    DelegationTask,
    SanityStatus,
    AgentType,
    ActionType,
    ScopeEnforcer,
)


class TestDelegationSanityChecker:
    @pytest.fixture
    def checker(self, mock_scope_gate):
        return DelegationSanityChecker(scope_enforcer=mock_scope_gate)

    @pytest.fixture
    def valid_task(self):
        return DelegationTask(
            task_id="task-001",
            agent_type=AgentType.RECON,
            action_type=ActionType.RECON,
            target="10.0.0.5",
        )

    def test_all_checks_pass(self, checker, valid_task):
        safe, results = checker.is_task_safe_to_delegate(valid_task)
        assert safe is True
        assert all(r.status == SanityStatus.PASS for r in results)

    def test_target_valid_fails_bad_target(self, checker):
        task = DelegationTask(
            task_id="task-002",
            agent_type=AgentType.RECON,
            action_type=ActionType.RECON,
            target="evil.com",
        )
        safe, results = checker.is_task_safe_to_delegate(task)
        assert safe is False
        blocking = [r for r in results if r.is_blocking()]
        assert any("target_in_scope" in r.check_name for r in blocking)

    def test_type_mismatch_fails(self, checker):
        task = DelegationTask(
            task_id="task-003",
            agent_type=AgentType.RECON,
            action_type=ActionType.CREDENTIAL_ATTACK,
            target="10.0.0.5",
        )
        result = checker.check_type_mismatch(task)
        assert result.is_blocking() is True
        assert result.check_name == "type_mismatch"

    def test_scope_compliant_fails(self, checker, valid_task):
        checker.scope_enforcer.engage_kill_switch("Emergency")
        safe, results = checker.is_task_safe_to_delegate(valid_task)
        assert safe is False
        blocking = [r for r in results if r.is_blocking()]
        assert len(blocking) >= 1

    def test_roe_authorization_required(self, checker):
        task = DelegationTask(
            task_id="task-004",
            agent_type=AgentType.PASSWORD_CREDENTIAL,
            action_type=ActionType.CREDENTIAL_ATTACK,
            target="10.0.0.5",
            roe_authorization_flag="",
        )
        result = checker.check_roe_authorization(task)
        assert result.is_blocking() is True
        assert result.check_name == "roe_authorization"

    def test_roe_authorization_passes_with_flag(self, checker):
        task = DelegationTask(
            task_id="task-005",
            agent_type=AgentType.PASSWORD_CREDENTIAL,
            action_type=ActionType.CREDENTIAL_ATTACK,
            target="10.0.0.5",
            roe_authorization_flag="AUTH-2024-001",
        )
        result = checker.check_roe_authorization(task)
        assert result.is_blocking() is False

    def test_sandbox_requirement_fails(self, checker):
        checker.set_sandbox_mode(False)
        task = DelegationTask(
            task_id="task-006",
            agent_type=AgentType.EXPLOIT_POC,
            action_type=ActionType.EXPLOIT,
            target="10.0.0.5",
            requires_sandbox=False,
        )
        result = checker.check_sandbox_requirement(task)
        assert result.is_blocking() is True

    def test_sandbox_requirement_passes_in_mode(self, checker):
        checker.set_sandbox_mode(True)
        task = DelegationTask(
            task_id="task-007",
            agent_type=AgentType.EXPLOIT_POC,
            action_type=ActionType.EXPLOIT,
            target="10.0.0.5",
        )
        result = checker.check_sandbox_requirement(task)
        assert result.is_blocking() is False

    def test_dependency_warning(self, checker):
        task = DelegationTask(
            task_id="task-008",
            agent_type=AgentType.WEB_EXPERT,
            action_type=ActionType.SCAN,
            target="10.0.0.5",
        )
        result = checker.check_dependencies(task)
        assert result.status == SanityStatus.WARN
        assert "recon-agent" in result.message

    def test_dependencies_met(self, checker):
        checker.add_completed_agent("recon-agent")
        task = DelegationTask(
            task_id="task-009",
            agent_type=AgentType.WEB_EXPERT,
            action_type=ActionType.SCAN,
            target="10.0.0.5",
        )
        result = checker.check_dependencies(task)
        assert result.status == SanityStatus.PASS

    def test_duplicate_running_warning(self, checker):
        checker.set_running_agents({"recon-agent"})
        task = DelegationTask(
            task_id="task-010",
            agent_type=AgentType.RECON,
            action_type=ActionType.RECON,
            target="10.0.0.5",
        )
        result = checker.check_duplicate_running(task)
        assert result.status == SanityStatus.WARN

    def test_not_duplicate_passes(self, checker):
        task = DelegationTask(
            task_id="task-011",
            agent_type=AgentType.RECON,
            action_type=ActionType.RECON,
            target="10.0.0.5",
        )
        result = checker.check_duplicate_running(task)
        assert result.status == SanityStatus.PASS

    def test_concurrent_connections_fails(self, checker):
        checker.set_active_connections(999)
        task = DelegationTask(
            task_id="task-012",
            agent_type=AgentType.RECON,
            action_type=ActionType.RECON,
            target="10.0.0.5",
        )
        result = checker.check_concurrent_connections(task)
        assert result.status == SanityStatus.FAIL

    def test_time_budget_exceeded(self, checker, monkeypatch):
        from datetime import datetime, timezone, timedelta
        from conftest import RoEDocument

        checker.scope_enforcer.roe = RoEDocument()
        checker.scope_enforcer.roe.time_budget_hours = 0.001
        checker._session_start = datetime.now(timezone.utc) - timedelta(hours=1)
        task = DelegationTask(
            task_id="task-013",
            agent_type=AgentType.RECON,
            action_type=ActionType.RECON,
            target="10.0.0.5",
        )
        result = checker.check_time_budget(task)
        assert result.status == SanityStatus.FAIL

    def test_run_all_returns_all_results(self, checker, valid_task):
        results = checker.run_all(valid_task)
        assert len(results) == 8

    def test_get_blocking_results(self, checker):
        task = DelegationTask(
            task_id="task-014",
            agent_type=AgentType.RECON,
            action_type=ActionType.CREDENTIAL_ATTACK,
            target="10.0.0.5",
        )
        results = checker.run_all(task)
        blocking = checker.get_blocking_results()
        assert len(blocking) >= 1

    def test_reset_session(self, checker):
        checker.set_active_connections(50)
        checker.reset_session()
        assert checker._active_connections == 0
        assert len(checker._completed_agents) == 0
