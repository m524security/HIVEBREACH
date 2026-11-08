from __future__ import annotations

import os
import tempfile
from datetime import datetime, timezone, timedelta

import pytest
import yaml

from conftest import ScopeEnforcer, ActionType, ScopeCheckResult, RoEDocument, SAMPLE_ROE_YAML


class TestScopeGateInit:
    def test_init_without_roe(self):
        gate = ScopeEnforcer()
        assert gate.roe is None
        assert gate.is_kill_switched is False

    def test_init_with_roe(self, roe_path):
        gate = ScopeEnforcer(roe_path)
        assert gate.roe is not None
        assert gate.roe.title == "Test Engagement"


class TestCheckTarget:
    def test_allows_valid_target(self, mock_scope_gate):
        allowed, reason = mock_scope_gate.check_target("10.0.0.5")
        assert allowed is True
        assert "authorized range" in reason

    def test_allows_domain_match(self, mock_scope_gate):
        allowed, reason = mock_scope_gate.check_target("api.acme.com")
        assert allowed is True

    def test_allows_wildcard_domain(self, mock_scope_gate):
        allowed, reason = mock_scope_gate.check_target("app.acme.com")
        assert allowed is True

    def test_denies_out_of_scope_domain(self, mock_scope_gate):
        allowed, reason = mock_scope_gate.check_target("evil.com")
        assert allowed is False

    def test_denies_out_of_scope_ip(self, mock_scope_gate):
        allowed, reason = mock_scope_gate.check_target("1.2.3.4")
        assert allowed is False

    def test_denies_excluded_domain(self, mock_scope_gate):
        allowed, reason = mock_scope_gate.check_target("admin.acme.com")
        assert allowed is False
        assert "excluded" in reason

    def test_denies_excluded_ip(self, mock_scope_gate):
        allowed, reason = mock_scope_gate.check_target("10.0.0.100")
        assert allowed is False
        assert "excluded" in reason


class TestCIDRMatching:
    def test_cidr_matching(self, scope_enforcer, roe_path):
        scope_enforcer.load_roe(roe_path)
        assert scope_enforcer.check_target("10.0.0.50")[0] is True
        assert scope_enforcer.check_target("10.0.1.1")[0] is False
        assert scope_enforcer.check_target("192.168.1.50")[0] is True
        assert scope_enforcer.check_target("192.168.2.1")[0] is False

    def test_invalid_cidr_handling(self):
        gate = ScopeEnforcer()
        gate.roe = RoEDocument()
        gate.roe.authorized_ip_ranges = ["not-a-cidr"]
        gate._precompute_networks()
        assert len(gate._ip_networks) == 0


class TestDomainSuffixMatching:
    def test_domain_suffix_matching(self, mock_scope_gate):
        assert mock_scope_gate.check_target("anything.acme.com")[0] is True
        assert mock_scope_gate.check_target("deep.sub.acme.com")[0] is True

    def test_no_false_positive_similar_domain(self, mock_scope_gate):
        assert mock_scope_gate.check_target("acme.com.evil.com")[0] is False


class TestTargetParsing:
    def test_parse_url(self):
        parsed = ScopeEnforcer.parse_target("https://api.acme.com/path")
        assert parsed["domain"] == "api.acme.com"
        assert parsed["path"] == "/path"
        assert parsed["scheme"] == "https"

    def test_parse_plain_domain(self):
        parsed = ScopeEnforcer.parse_target("api.acme.com")
        assert parsed["domain"] == "api.acme.com"

    def test_parse_ip_address(self):
        parsed = ScopeEnforcer.parse_target("10.0.0.1")
        assert parsed["ip"] == "10.0.0.1"

    def test_parse_with_port(self):
        parsed = ScopeEnforcer.parse_target("https://api.acme.com:8443/admin")
        assert parsed["domain"] == "api.acme.com"


class TestActionTypeCheck:
    def test_allows_authorized_action(self, mock_scope_gate):
        allowed, reason = mock_scope_gate.check_action(ActionType.RECON)
        assert allowed is True

    def test_allows_scan_action(self, mock_scope_gate):
        allowed, reason = mock_scope_gate.check_action(ActionType.SCAN)
        assert allowed is True

    def test_blocks_denial_of_service(self, mock_scope_gate):
        allowed, reason = mock_scope_gate.check_action(ActionType.DENIAL_OF_SERVICE)
        assert allowed is False

    def test_blocks_prohibited_technique(self, mock_scope_gate):
        allowed, reason = mock_scope_gate.check_action(ActionType.EXPLOIT, "T1499")
        assert allowed is False
        assert "prohibited" in reason


class TestPortCheck:
    def test_allows_allowed_port(self, mock_scope_gate):
        allowed, reason = mock_scope_gate.check_port(443)
        assert allowed is True

    def test_blocks_prohibited_port(self, mock_scope_gate):
        allowed, reason = mock_scope_gate.check_port(3389)
        assert allowed is False

    def test_blocks_unlisted_port(self, mock_scope_gate):
        allowed, reason = mock_scope_gate.check_port(8080)
        assert allowed is False


class TestTimeWindow:
    def test_time_window_enforcement(self, mock_scope_gate):
        allowed, reason = mock_scope_gate.check_time_budget(0.0)
        assert allowed is True

    def test_time_window_exceeded(self, mock_scope_gate):
        allowed, reason = mock_scope_gate.check_time_budget(48.0)
        assert allowed is False

    def test_time_budget_no_limit(self, scope_enforcer):
        allowed, reason = scope_enforcer.check_time_budget(999.0)
        assert allowed is True


class TestConnectionLimit:
    def test_connection_limit_allows(self, mock_scope_gate):
        allowed, reason = mock_scope_gate.check_connection_limit(5)
        assert allowed is True

    def test_connection_limit_reached(self, mock_scope_gate):
        allowed, reason = mock_scope_gate.check_connection_limit(10)
        assert allowed is False

    def test_connection_limit_no_limit(self, scope_enforcer):
        allowed, reason = scope_enforcer.check_connection_limit(999)
        assert allowed is True


class TestAuthorize:
    def test_authorize_passes_all(self, mock_scope_gate):
        report = mock_scope_gate.authorize("10.0.0.5", ActionType.RECON)
        assert report.is_allowed() is True
        assert report.reason == "All scope checks passed"

    def test_authorize_denies_out_of_scope_target(self, mock_scope_gate):
        report = mock_scope_gate.authorize("evil.com", ActionType.RECON)
        assert report.is_allowed() is False
        assert report.result == ScopeCheckResult.OUT_OF_SCOPE

    def test_authorize_blocks_on_port(self, mock_scope_gate):
        report = mock_scope_gate.authorize(
            "10.0.0.5", ActionType.SCAN, port=3389
        )
        assert report.is_allowed() is False


class TestKillSwitch:
    def test_engage_kill_switch(self, mock_scope_gate):
        mock_scope_gate.engage_kill_switch("Emergency stop")
        assert mock_scope_gate.is_kill_switched is True
        allowed, reason = mock_scope_gate.check_target("10.0.0.5")
        assert allowed is False
        assert "emergency" in reason.lower()

    def test_disengage_kill_switch(self, mock_scope_gate):
        mock_scope_gate.engage_kill_switch("Stop")
        mock_scope_gate.disengage_kill_switch()
        assert mock_scope_gate.is_kill_switched is False
        allowed, reason = mock_scope_gate.check_target("10.0.0.5")
        assert allowed is True


class TestRoEParsing:
    def test_roe_parsing(self, roe_path):
        doc = RoEDocument.from_yaml(roe_path)
        assert doc.title == "Test Engagement"
        assert "*.acme.com" in doc.authorized_domains
        assert "10.0.0.0/24" in doc.authorized_ip_ranges
        type_names = [at.value for at in doc.authorized_action_types]
        assert "recon" in type_names
        assert doc.concurrent_connections_max == 10

    def test_roe_without_expiration(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump({"title": "No Expiry"}, f)
            path = f.name
        try:
            doc = RoEDocument.from_yaml(path)
            assert doc.expiration_date is None
        finally:
            os.unlink(path)


class TestViolations:
    def test_violations_tracking(self, mock_scope_gate):
        mock_scope_gate.authorize("evil.com", ActionType.RECON)
        mock_scope_gate.authorize("10.0.0.5", ActionType.SCAN)
        violations = mock_scope_gate.get_violations()
        assert len(violations) == 1
        assert violations[0].target == "evil.com"

    def test_violations_clear(self, mock_scope_gate):
        mock_scope_gate.authorize("evil.com", ActionType.RECON)
        v1 = mock_scope_gate.get_violations(clear=True)
        assert len(v1) == 1
        assert len(mock_scope_gate.get_violations()) == 0


class TestAuthHeaders:
    def test_inject_auth_header(self, mock_scope_gate):
        mock_scope_gate.inject_auth_header("Authorization", "Bearer token123")
        headers = mock_scope_gate.get_authorization_headers()
        assert len(headers) == 1
        assert headers[0].value == "Bearer token123"
        assert mock_scope_gate.get_auth_header_dict()["Authorization"] == "Bearer token123"
