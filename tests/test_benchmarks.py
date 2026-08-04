"""Unit tests for the detection benchmark scoring engine (benchmarks/scoring.py)."""
import json
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from benchmarks.scoring import BenchmarkResult, Finding, ScoringEngine

ROOT = Path(__file__).resolve().parent.parent
GT_DIR = ROOT / "benchmarks" / "ground-truth"


def _findings(classes_severities, exploit=True, detected_at=None):
    return [
        Finding(target="t", check_id=cls, endpoint="/", method="GET",
                detected=True, vuln_class=cls, severity=sev,
                exploit_success=exploit,
                detected_at=detected_at or time.time())
        for cls, sev in classes_severities
    ]


def _load_gt(target):
    with open(GT_DIR / f"{target}.json") as f:
        return json.load(f)["vulnerabilities"]


def test_ground_truth_files_valid():
    """Every configured target has a loadable ground-truth manifest."""
    import yaml
    with open(ROOT / "benchmarks" / "config.yaml") as f:
        cfg = yaml.safe_load(f)
    for t in cfg["targets"]:
        assert (GT_DIR / f"{t}.json").exists(), f"missing GT for {t}"
        vulns = _load_gt(t)
        assert vulns, f"empty GT for {t}"
        for v in vulns:
            assert v["id"] and v["class"] and v["severity"] and v["detectable_by"]


def test_floor_score_is_zero_when_no_detections():
    r = BenchmarkResult(target="dvwa")
    r.ended_at = time.time()
    rep = ScoringEngine().score([r], _load_gt("dvwa"))
    assert rep["score"] == 0.0
    assert rep["confusion"]["tp"] == 0
    assert rep["confusion"]["fn"] == len(_load_gt("dvwa"))


def test_precision_recall_f1():
    gt = _load_gt("vampi")
    r = BenchmarkResult(target="vampi")
    r.findings = _findings([
        ("unauth_api", "critical"), ("sqli", "critical"), ("auth_bypass", "high"),
    ])
    r.ended_at = time.time()
    rep = ScoringEngine().score([r], gt)
    assert rep["confusion"]["tp"] == 3
    assert rep["confusion"]["fp"] == 0
    assert rep["metrics"]["precision"] == 1.0
    assert rep["metrics"]["recall"] == pytest.approx(3 / 4, abs=1e-4)
    # F1 = 2PR/(P+R)
    exp_f1 = 2 * 1.0 * 0.75 / 1.75
    assert rep["metrics"]["f1"] == pytest.approx(exp_f1, abs=1e-4)


def test_false_positive_detection():
    gt = _load_gt("vampi")
    r = BenchmarkResult(target="vampi")
    r.findings = _findings([("unauth_api", "critical")])
    r.findings.append(Finding(
        target="vampi", check_id="misconfiguration", endpoint="/", method="GET",
        detected=True, vuln_class="misconfiguration", severity="medium",
        exploit_success=False, detected_at=time.time()))
    r.ended_at = time.time()
    rep = ScoringEngine().score([r], gt)
    assert rep["confusion"]["tp"] == 1
    assert rep["confusion"]["fp"] == 1
    assert rep["metrics"]["precision"] == 0.5
    assert len(rep["false_positives"]) == 1


def test_multiplicity_same_class():
    """Two separate XSS vulns require two XSS findings to claim both."""
    gt = _load_gt("juice-shop")
    r = BenchmarkResult(target="juice-shop")
    r.findings = _findings([
        ("sqli", "critical"), ("xss", "high"), ("xss", "high"),
        ("unauth_api", "high"),
    ])
    r.ended_at = time.time()
    rep = ScoringEngine().score([r], gt)
    assert rep["confusion"]["tp"] == 4
    assert rep["confusion"]["fp"] == 0
    assert rep["confusion"]["fn"] == 1


def test_severity_weighted_recall():
    gt = _load_gt("vampi")
    # Detect only the critical unauth API; miss critical SQLi, high IDOR, medium PII
    r = BenchmarkResult(target="vampi")
    r.findings = _findings([("unauth_api", "critical")])
    r.ended_at = time.time()
    rep = ScoringEngine().score([r], gt)
    # weighted: 1.0 / (1.0+1.0+0.9+0.7)
    assert rep["metrics"]["recall_weighted"] == pytest.approx(1.0 / 3.6, abs=1e-4)


def test_time_bonus_only_with_detections():
    gt = _load_gt("dvwa")
    r = BenchmarkResult(target="dvwa")
    r.findings = _findings([("sqli", "critical")], detected_at=1.0)
    r.ended_at = time.time()
    rep = ScoringEngine().score([r], gt)
    assert rep["metrics"]["time_bonus"] == 1.0
    assert rep["metrics"]["time_to_find_avg_s"] == 1.0
    # penalize past budget
    r2 = BenchmarkResult(target="dvwa")
    r2.findings = _findings([("sqli", "critical")], detected_at=700.0)
    r2.ended_at = time.time()
    rep2 = ScoringEngine().score([r2], gt)
    assert rep2["metrics"]["time_bonus"] < 1.0


def test_chain_depth():
    gt = _load_gt("dvwa")
    r = BenchmarkResult(target="dvwa")
    r.findings = _findings([
        ("sqli", "critical"), ("xss", "high"), ("command_injection", "critical"),
    ])
    r.ended_at = time.time()
    rep = ScoringEngine().score([r], gt)
    assert rep["metrics"]["max_chain_depth"] == 3


def test_all_checks_importable():
    """Every check module in the registry imports and exposes CHECK_CLASS."""
    from benchmarks.checks import CHECK_REGISTRY, load_check
    for check_id, reg in CHECK_REGISTRY.items():
        assert reg["skill"], f"{check_id} missing skill mapping"
        assert (ROOT / reg["skill"]).exists(), f"skill missing: {reg['skill']}"
        check = load_check(reg["module"], "t", "http://127.0.0.1", None)
        assert check is not None, f"{check_id} failed to load"
        assert hasattr(check, "run")
