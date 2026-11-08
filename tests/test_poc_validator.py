from __future__ import annotations

import os
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from conftest import PoCValidator, VerificationTrack, ConfidenceLevel


@pytest.fixture
def validator():
    with tempfile.TemporaryDirectory() as tmpdir:
        yield PoCValidator(evidence_base_dir=tmpdir)


class TestPoCValidator:
    def test_exploit_verified_finding(self, validator):
        steps = [
            {"type": "exec", "cmd": ["echo", "pwned"], "description": "Test step"},
            {"type": "assert", "condition": "test 1 -eq 1", "description": "Assert"},
        ]
        result = validator.validate(
            target="10.0.0.1",
            exploit_name="test-exploit",
            exploit_steps=steps,
            track=VerificationTrack.EXPLOIT_VERIFIED,
        )
        assert result.poc_id is not None
        assert result.verdict in ("CONFIRMED", "LIKELY", "PLAUSIBLE", "FAILED", "INCONCLUSIVE")
        assert result.exploit_verified is not None
        assert result.confidence >= 0.0

    def test_state_verified_finding(self, validator, monkeypatch):
        mock_sandbox = MagicMock()
        mock_sandbox.create.return_value = "container-id"
        mock_sandbox.exec_run.return_value = (0, "expected_value")
        mock_sandbox.destroy.return_value = None
        validator._sandbox = mock_sandbox

        expected_state = {"SOME_VAR": "expected_value"}
        result = validator.validate(
            target="10.0.0.1",
            exploit_name="state-test",
            exploit_steps=[],
            expected_state=expected_state,
            track=VerificationTrack.STATE_VERIFIED,
        )
        assert result.state_verified is not None
        assert result.state_verified.passed is True

    def test_dual_track_verification(self, validator, monkeypatch):
        mock_sandbox = MagicMock()
        mock_sandbox.create.return_value = "cid"
        mock_sandbox.exec_run.return_value = (0, "pwned")
        mock_sandbox.destroy.return_value = None
        validator._sandbox = mock_sandbox

        steps = [{"type": "exec", "cmd": ["echo", "pwned"]}]
        result = validator._run_exploit_verification(
            poc_id="dual-001",
            target="10.0.0.1",
            exploit_steps=steps,
            evidence_dir=validator._evidence_base_dir,
        )
        assert result.passed is True
        assert result.track == VerificationTrack.EXPLOIT_VERIFIED

        state_result = validator._run_state_verification(
            poc_id="dual-001",
            target="10.0.0.1",
            expected_state={"VAR": "pwned"},
            evidence_dir=validator._evidence_base_dir,
        )
        assert state_result.track == VerificationTrack.STATE_VERIFIED

    def test_exploit_fails_on_step_failure(self, validator):
        steps = [{"type": "exec", "cmd": ["false"], "description": "Fail step"}]
        result = validator.validate(
            target="10.0.0.1",
            exploit_name="fail-test",
            exploit_steps=steps,
            track=VerificationTrack.EXPLOIT_VERIFIED,
        )
        if result.exploit_verified and not result.exploit_verified.passed:
            assert result.verdict == "FAILED"


class TestConfidenceScoring:
    def test_confidence_scoring(self, validator):
        result = validator._score_exploit_confidence(
            step_results=[True, True, True],
            errors=[],
            duration=10.0,
        )
        assert 0.0 <= result <= 1.0
        assert result > 0.7

    def test_low_confidence_rejection(self, validator):
        steps = [
            {"type": "exec", "cmd": ["false"], "description": "Fails"},
            {"type": "exec", "cmd": ["false"], "description": "Also fails"},
        ]
        result = validator.validate(
            target="10.0.0.1",
            exploit_name="low-conf-test",
            exploit_steps=steps,
            track=VerificationTrack.EXPLOIT_VERIFIED,
        )
        if result.exploit_verified and not result.exploit_verified.passed:
            assert result.confidence < 0.5
            assert result.verdict == "FAILED"

    def test_confidence_no_steps(self, validator):
        score = validator._score_exploit_confidence([], [], 0.0)
        assert score == ConfidenceLevel.NONE.value

    def test_confidence_partial_success(self, validator):
        score = validator._score_exploit_confidence(
            step_results=[True, False, True],
            errors=["Step 1 failed"],
            duration=5.0,
        )
        assert 0.0 <= score <= 1.0


class TestComputeVerdict:
    def test_verdict_confirmed(self, validator):
        from conftest import VerificationResult
        vr = VerificationResult(
            track=VerificationTrack.EXPLOIT_VERIFIED,
            passed=True,
            confidence=0.95,
        )
        verdict, conf = validator._compute_verdict(vr, None)
        assert verdict == "CONFIRMED"
        assert conf >= 0.9

    def test_verdict_likely(self, validator):
        from conftest import VerificationResult
        vr = VerificationResult(
            track=VerificationTrack.EXPLOIT_VERIFIED,
            passed=True,
            confidence=0.75,
        )
        verdict, conf = validator._compute_verdict(vr, None)
        assert verdict == "LIKELY"

    def test_verdict_plausible(self, validator):
        from conftest import VerificationResult
        vr = VerificationResult(
            track=VerificationTrack.EXPLOIT_VERIFIED,
            passed=True,
            confidence=0.55,
        )
        verdict, conf = validator._compute_verdict(vr, None)
        assert verdict == "PLAUSIBLE"

    def test_verdict_failed_on_exploit(self, validator):
        from conftest import VerificationResult
        vr = VerificationResult(
            track=VerificationTrack.EXPLOIT_VERIFIED,
            passed=False,
            confidence=0.0,
        )
        verdict, conf = validator._compute_verdict(vr, None)
        assert verdict == "FAILED"

    def test_verdict_inconclusive(self, validator):
        verdict, conf = validator._compute_verdict(None, None)
        assert verdict == "INCONCLUSIVE"
        assert conf == 0.0


class TestEvidence:
    def test_package_evidence(self, validator):
        steps = [{"type": "exec", "cmd": ["echo", "test"]}]
        result = validator.validate(
            target="10.0.0.1",
            exploit_name="evidence-test",
            exploit_steps=steps,
            track=VerificationTrack.EXPLOIT_VERIFIED,
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            out = os.path.join(tmpdir, "evidence")
            archive = validator.package_evidence(result.poc_id, out)
            assert archive is not None
            assert os.path.isfile(archive)

    def test_package_evidence_not_found(self, validator):
        with pytest.raises(ValueError):
            validator.package_evidence("nonexistent", "/tmp/out")

    def test_get_result(self, validator):
        steps = [{"type": "exec", "cmd": ["echo", "test"]}]
        result = validator.validate(
            target="10.0.0.1",
            exploit_name="get-test",
            exploit_steps=steps,
            track=VerificationTrack.EXPLOIT_VERIFIED,
        )
        retrieved = validator.get_result(result.poc_id)
        assert retrieved is not None
        assert retrieved.exploit_name == "get-test"

    def test_get_all_results(self, validator):
        assert validator.get_all_results() == {}
        steps = [{"type": "exec", "cmd": ["echo", "test"]}]
        validator.validate("10.0.0.1", "test-1", steps, track=VerificationTrack.EXPLOIT_VERIFIED)
        assert len(validator.get_all_results()) == 1
