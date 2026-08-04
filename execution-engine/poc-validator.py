import json
import logging
import os
import shutil
import tempfile
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class VerificationTrack(Enum):
    EXPLOIT_VERIFIED = "exploit-verified"
    STATE_VERIFIED = "state-verified"


class ConfidenceLevel(Enum):
    NONE = 0.0
    LOW = 0.25
    MEDIUM = 0.5
    HIGH = 0.75
    CONFIRMED = 1.0


@dataclass
class VerificationResult:
    track: VerificationTrack
    passed: bool
    confidence: float
    evidence_paths: List[str] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PoCResult:
    poc_id: str
    target: str
    exploit_name: str
    verdict: str
    confidence: float
    exploit_verified: Optional[VerificationResult] = None
    state_verified: Optional[VerificationResult] = None
    evidence_dir: str = ""
    created_at: str = ""
    summary: str = ""


class PoCValidator:
    def __init__(
        self,
        sandbox_manager=None,
        evidence_base_dir: str = "",
        min_confidence: float = 0.5,
    ):
        self._sandbox = sandbox_manager
        self._evidence_base_dir = evidence_base_dir or os.path.join(
            os.getcwd(), "evidence"
        )
        self._min_confidence = min_confidence
        self._results: Dict[str, PoCResult] = {}

    def validate(
        self,
        target: str,
        exploit_name: str,
        exploit_steps: List[Dict[str, Any]],
        expected_state: Optional[Dict[str, Any]] = None,
        track: VerificationTrack = VerificationTrack.EXPLOIT_VERIFIED,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> PoCResult:
        poc_id = str(uuid.uuid4())[:8]
        evidence_dir = os.path.join(self._evidence_base_dir, poc_id)
        os.makedirs(evidence_dir, exist_ok=True)

        logger.info("Validating PoC %s: %s on %s (%s)", poc_id, exploit_name, target, track.value)

        exploit_result: Optional[VerificationResult] = None
        state_result: Optional[VerificationResult] = None

        t_start = time.time()

        if track in (VerificationTrack.EXPLOIT_VERIFIED,):
            exploit_result = self._run_exploit_verification(
                poc_id, target, exploit_steps, evidence_dir, metadata
            )

        if track in (VerificationTrack.STATE_VERIFIED,) and expected_state:
            state_result = self._run_state_verification(
                poc_id, target, expected_state, evidence_dir, metadata
            )

        t_total = time.time() - t_start

        verdict, confidence = self._compute_verdict(exploit_result, state_result)

        result = PoCResult(
            poc_id=poc_id,
            target=target,
            exploit_name=exploit_name,
            verdict=verdict,
            confidence=confidence,
            exploit_verified=exploit_result,
            state_verified=state_result,
            evidence_dir=evidence_dir,
            created_at=datetime.now(timezone.utc).isoformat(),
            summary=self._build_summary(exploit_name, verdict, confidence),
        )

        self._results[poc_id] = result
        self._write_evidence(result, evidence_dir)
        return result

    def _run_exploit_verification(
        self,
        poc_id: str,
        target: str,
        exploit_steps: List[Dict[str, Any]],
        evidence_dir: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> VerificationResult:
        t_start = time.time()
        findings: List[str] = []
        errors: List[str] = []
        evidence_paths: List[str] = []
        step_results: List[bool] = []

        if self._sandbox:
            tag = f"validate-{poc_id}"
            try:
                self._sandbox.create(tag=tag)
                self._exec_steps(tag, exploit_steps, findings, errors, step_results, evidence_paths, evidence_dir)
            except Exception as e:
                errors.append(f"Sandbox error: {e}")
            finally:
                try:
                    self._sandbox.destroy(tag=tag)
                except Exception:
                    pass
        else:
            logger.warning("No sandbox manager available; running steps locally")
            self._exec_steps(None, exploit_steps, findings, errors, step_results, evidence_paths, evidence_dir)

        duration = time.time() - t_start
        passed = len(errors) == 0 and all(step_results)
        confidence = self._score_exploit_confidence(step_results, errors, duration)

        return VerificationResult(
            track=VerificationTrack.EXPLOIT_VERIFIED,
            passed=passed,
            confidence=confidence,
            evidence_paths=evidence_paths,
            findings=findings,
            errors=errors,
            duration_seconds=duration,
        )

    def _run_state_verification(
        self,
        poc_id: str,
        target: str,
        expected_state: Dict[str, Any],
        evidence_dir: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> VerificationResult:
        t_start = time.time()
        findings: List[str] = []
        errors: List[str] = []
        evidence_paths: List[str] = []

        state_log = os.path.join(evidence_dir, "state-verification.json")
        matched = 0
        total = len(expected_state)

        if self._sandbox:
            tag = f"state-{poc_id}"
            try:
                self._sandbox.create(tag=tag)
                for key, expected_val in expected_state.items():
                    try:
                        exit_code, output = self._sandbox.exec_run(
                            tag=tag,
                            cmd=["sh", "-c", f"echo '$({key})'"],
                        )
                        actual = output.strip()
                        if actual == str(expected_val):
                            matched += 1
                            findings.append(f"State check passed: {key}={actual}")
                        else:
                            errors.append(f"State mismatch: {key} expected={expected_val} actual={actual}")
                    except Exception as e:
                        errors.append(f"State check failed for {key}: {e}")
            except Exception as e:
                errors.append(f"Sandbox error during state verification: {e}")
            finally:
                try:
                    self._sandbox.destroy(tag=tag)
                except Exception:
                    pass
        else:
            total = 0

        state_record = {
            "expected": expected_state,
            "matched": matched,
            "total": total,
            "findings": findings,
            "errors": errors,
        }
        with open(state_log, "w") as f:
            json.dump(state_record, f, indent=2)
        evidence_paths.append(state_log)

        duration = time.time() - t_start
        passed = len(errors) == 0 and (total == 0 or matched == total)
        confidence = (matched / total) if total > 0 else 0.5

        return VerificationResult(
            track=VerificationTrack.STATE_VERIFIED,
            passed=passed,
            confidence=confidence,
            evidence_paths=evidence_paths,
            findings=findings,
            errors=errors,
            duration_seconds=duration,
        )

    def _exec_steps(
        self,
        tag: Optional[str],
        steps: List[Dict[str, Any]],
        findings: List[str],
        errors: List[str],
        step_results: List[bool],
        evidence_paths: List[str],
        evidence_dir: str,
    ) -> None:
        for i, step in enumerate(steps):
            step_type = step.get("type", "exec")
            description = step.get("description", f"step-{i}")
            try:
                if step_type == "exec":
                    cmd = step.get("cmd", [])
                    if tag and self._sandbox:
                        exit_code, output = self._sandbox.exec_run(tag=tag, cmd=cmd)
                    else:
                        import subprocess
                        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                        exit_code, output = proc.returncode, proc.stdout + proc.stderr

                    passed = exit_code == 0
                    step_results.append(passed)

                    if passed:
                        findings.append(f"Step {i} passed: {description}")
                    else:
                        errors.append(f"Step {i} failed ({exit_code}): {description}")

                    log_path = os.path.join(evidence_dir, f"step-{i:03d}.log")
                    with open(log_path, "w") as f:
                        f.write(json.dumps({"step": i, "cmd": cmd, "exit_code": exit_code, "output": output}, indent=2))
                    evidence_paths.append(log_path)

                elif step_type == "assert":
                    condition = step.get("condition", "")
                    if tag and self._sandbox:
                        exit_code, output = self._sandbox.exec_run(
                            tag=tag,
                            cmd=["sh", "-c", condition],
                        )
                    else:
                        import subprocess
                        proc = subprocess.run(["sh", "-c", condition], capture_output=True, text=True, timeout=30)
                        exit_code = proc.returncode

                    passed = exit_code == 0
                    step_results.append(passed)
                    if passed:
                        findings.append(f"Assertion {i} passed: {condition}")
                    else:
                        errors.append(f"Assertion {i} failed: {condition}")

                elif step_type == "collect":
                    source = step.get("source", "")
                    dest = os.path.join(evidence_dir, step.get("dest", f"evidence-{i}"))
                    if tag and self._sandbox:
                        exit_code, output = self._sandbox.exec_run(
                            tag=tag,
                            cmd=["cat", source],
                        )
                        if exit_code == 0:
                            with open(dest, "w") as f:
                                f.write(output)
                            evidence_paths.append(dest)
                            findings.append(f"Collected evidence: {source} -> {dest}")
                    step_results.append(True)

            except Exception as e:
                errors.append(f"Step {i} exception: {e}")
                step_results.append(False)

    def _score_exploit_confidence(
        self, step_results: List[bool], errors: List[str], duration: float
    ) -> float:
        if not step_results:
            return ConfidenceLevel.NONE.value
        pass_rate = sum(step_results) / len(step_results)
        penalty = len(errors) * 0.1
        duration_factor = min(1.0, 300.0 / max(duration, 1.0))
        raw = (pass_rate * 0.7 + duration_factor * 0.3) - penalty
        return max(0.0, min(1.0, raw))

    def _compute_verdict(
        self,
        exploit_result: Optional[VerificationResult],
        state_result: Optional[VerificationResult],
    ) -> Tuple[str, float]:
        scores: List[float] = []

        if exploit_result:
            if not exploit_result.passed:
                return ("FAILED", 0.0)
            scores.append(exploit_result.confidence)

        if state_result:
            if not state_result.passed:
                return ("FAILED", 0.0)
            scores.append(state_result.confidence)

        if not scores:
            return ("INCONCLUSIVE", 0.0)

        avg_conf = sum(scores) / len(scores)

        if avg_conf >= 0.9:
            return ("CONFIRMED", avg_conf)
        elif avg_conf >= 0.7:
            return ("LIKELY", avg_conf)
        elif avg_conf >= self._min_confidence:
            return ("PLAUSIBLE", avg_conf)
        else:
            return ("INCONCLUSIVE", avg_conf)

    def _build_summary(self, exploit_name: str, verdict: str, confidence: float) -> str:
        return f"[{verdict}] {exploit_name} — confidence {confidence:.0%}"

    def _write_evidence(self, result: PoCResult, evidence_dir: str) -> None:
        manifest = asdict(result)
        manifest_path = os.path.join(evidence_dir, "poc-manifest.json")
        with open(manifest_path, "w") as f:
            json.dump(manifest, f, indent=2, default=str)
        logger.info("Evidence written to %s", evidence_dir)

    def get_result(self, poc_id: str) -> Optional[PoCResult]:
        return self._results.get(poc_id)

    def get_all_results(self) -> Dict[str, PoCResult]:
        return dict(self._results)

    def package_evidence(self, poc_id: str, output_path: str) -> str:
        result = self._results.get(poc_id)
        if not result:
            raise ValueError(f"No result found for poc_id={poc_id}")

        evidence_dir = result.evidence_dir
        if not os.path.isdir(evidence_dir):
            raise FileNotFoundError(f"Evidence directory not found: {evidence_dir}")

        archive_name = shutil.make_archive(
            base_name=output_path,
            format="zip",
            root_dir=evidence_dir,
        )
        logger.info("Packaged evidence: %s -> %s", evidence_dir, archive_name)
        return archive_name
