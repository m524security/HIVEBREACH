"""Detection benchmark scoring engine.

Computes a confusion matrix and derived metrics for detection/exploitation
benchmarks run against known-vulnerable targets.

Metric definitions
------------------
- TP : expected vulnerability detected by at least one check
- FN : expected vulnerability missed by all checks
- FP : check fired a positive where no expected vulnerability exists
- TN : a check that did not fire on a clean endpoint (implicitly counted)

Derived metrics
---------------
- precision = TP / (TP + FP)
- recall    = TP / (TP + FN)   (severity-weighted when configured)
- f1        = 2 * P * R / (P + R)
- time_to_find: seconds per detected vuln, penalized past a budget
- exploit_success: fraction of detected vulns with a working exploit PoC
- chain_depth: max number of distinct vuln classes detected on one target

The final 0-100 benchmark score is a weighted blend (see config).
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class Finding:
    """A single check result attached to one benchmark target."""

    target: str
    check_id: str            # e.g. "sqli"
    endpoint: str
    method: str
    detected: bool
    vuln_class: str          # expected class from ground truth if matched
    severity: str = "medium"
    exploit_success: bool = False
    detected_at: float = 0.0
    notes: str = ""
    matched_ground_truth_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class BenchmarkResult:
    target: str
    findings: list[Finding] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    ended_at: float = 0.0

    def duration(self) -> float:
        return self.ended_at - self.started_at


class ScoringEngine:
    """Computes confusion matrix + metrics for a set of BenchmarkResults."""

    def __init__(self, weights: dict | None = None,
                 severity_weight: dict | None = None,
                 time_budget_s: float = 600.0) -> None:
        self.weights = weights or {
            "precision": 0.30,
            "recall": 0.35,
            "f1": 0.15,
            "exploit_success": 0.15,
            "time_bonus": 0.05,
        }
        self.severity_weight = severity_weight or {
            "critical": 1.0, "high": 0.9, "medium": 0.7, "low": 0.5,
        }
        self.time_budget_s = time_budget_s

    # ------------------------------------------------------------------
    def _match_findings(self, results: list[BenchmarkResult],
                        expected: list[dict]) -> tuple[set[str], int]:
        """Match findings to expected vulns by class, then compute FP count.

        Returns (claimed_ids, fp_count). Matching handles multiplicity: one
        finding claims one expected vuln of the same class (a finding cannot
        prove two separate vulns of one class on its own).
        """
        pool: dict[str, list[str]] = {}
        for v in expected:
            pool.setdefault(v["class"], []).append(v["id"])

        claimed: set[str] = set()
        fps = 0
        for res in results:
            for f in res.findings:
                if not f.detected:
                    continue
                target_id = f.matched_ground_truth_id
                if target_id and target_id in pool.get(f.vuln_class, []) \
                        and target_id not in claimed:
                    claimed.add(target_id)
                    continue
                # class-based match against an unclaimed vuln of same class
                candidate = next(
                    (vid for vid in pool.get(f.vuln_class, []) if vid not in claimed),
                    None)
                if candidate:
                    claimed.add(candidate)
                    f.matched_ground_truth_id = candidate
                else:
                    fps += 1
        return claimed, fps

    # ------------------------------------------------------------------
    def _confusion_matrix(self, results: list[BenchmarkResult],
                          expected: list[dict]) -> tuple[int, int, int, int]:
        """Compute TP, FN, FP across all results.

        expected: list of ground-truth vulnerability dicts with 'class',
                  'severity', 'id'.
        """
        claimed, fps = self._match_findings(results, expected)
        tp = len(claimed)
        fn = len(expected) - tp
        return tp, fn, fps, 0  # TN is not directly observable in active scans

    # ------------------------------------------------------------------
    def _recall_weighted(self, expected: list[dict],
                         detected_ids: set[str]) -> float:
        """Severity-weighted recall: missing a critical vuln hurts more."""
        total_weight = 0.0
        detected_weight = 0.0
        for v in expected:
            w = self.severity_weight.get(v.get("severity", "medium"), 0.7)
            total_weight += w
            if v["id"] in detected_ids:
                detected_weight += w
        if total_weight == 0:
            return 0.0
        return detected_weight / total_weight

    # ------------------------------------------------------------------
    def score(self, results: list[BenchmarkResult],
              expected: list[dict]) -> dict[str, Any]:
        """Return the full scoring report for a set of results."""
        detected_ids, fps = self._match_findings(results, expected)
        tp, fn, fp, _ = self._confusion_matrix(results, expected)
        assert fps == fp

        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        recall_w = self._recall_weighted(expected, detected_ids)
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

        # Time-to-find: average seconds for detected vulns; penalize past budget
        det_times = [
            f.detected_at for res in results for f in res.findings
            if f.detected and f.detected_at > 0
        ]
        # No detections -> no time credit (floor of 0, not the time bonus)
        time_bonus = 0.0
        if det_times:
            avg_time = sum(det_times) / len(det_times)
            over = max(0.0, (avg_time - self.time_budget_s) / self.time_budget_s)
            time_bonus = max(0.0, 1.0 - over)

        # Exploit success: of all detected findings, how many PoCs worked
        detected = [f for res in results for f in res.findings if f.detected]
        exploit_success = (
            sum(1 for f in detected if f.exploit_success) / len(detected)
            if detected else 0.0
        )

        # Chain depth: max distinct vuln classes detected on a single target
        max_chain = 0
        for res in results:
            classes = {f.vuln_class for f in res.findings if f.detected}
            max_chain = max(max_chain, len(classes))

        score = (
            self.weights["precision"] * precision
            + self.weights["recall"] * recall_w
            + self.weights["f1"] * f1
            + self.weights["exploit_success"] * exploit_success
            + self.weights["time_bonus"] * time_bonus
        ) * 100.0

        return {
            "score": round(score, 2),
            "confusion": {"tp": tp, "fn": fn, "fp": fp, "tn": None},
            "metrics": {
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "recall_weighted": round(recall_w, 4),
                "f1": round(f1, 4),
                "time_to_find_avg_s": round(avg_time, 1) if det_times else None,
                "time_bonus": round(time_bonus, 4),
                "exploit_success": round(exploit_success, 4),
                "max_chain_depth": max_chain,
            },
            "detected": sorted(detected_ids),
            "missed": sorted({v["id"] for v in expected} - detected_ids),
            "false_positives": [
                {
                    "target": f.target,
                    "check": f.check_id,
                    "endpoint": f.endpoint,
                    "notes": f.notes,
                }
                for res in results for f in res.findings
                if f.detected and not f.matched_ground_truth_id
            ],
        }
