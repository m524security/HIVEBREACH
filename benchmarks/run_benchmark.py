#!/usr/bin/env python3
"""HIVEBREACH detection benchmark orchestrator.

Usage:
    python benchmarks/run_benchmark.py [--config benchmarks/config.yaml]
                                      [--targets dvwa,juice-shop]
                                      [--dry-run]
                                      [--no-containers]

Starts the vulnerable-target Docker compose stack (unless --no-containers),
runs the configured detection checks per target, matches findings against the
ground-truth manifests, scores the run with the ScoringEngine, and writes a
Markdown + JSON report to reports/benchmarks/.

Exit codes:
    0  benchmark completed and report written
    1  configuration / ground-truth error
    2  targets unreachable
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

try:
    import requests
    import yaml
except ImportError as e:
    print(f"[benchmark] missing dependency: {e}")
    print("[benchmark] install with: pip install requests pyyaml")
    sys.exit(1)

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from benchmarks.checks import CHECK_REGISTRY, load_check
from benchmarks.scoring import BenchmarkResult, ScoringEngine

BENCH_DIR = Path(__file__).resolve().parent


# --------------------------------------------------------------------------
# Docker / container management
# --------------------------------------------------------------------------
def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True)


def docker_available() -> bool:
    r = _run(["docker", "--version"])
    return r.returncode == 0


def start_containers(compose_file: Path) -> None:
    print("[benchmark] starting vulnerable targets (docker compose up -d) ...")
    r = _run(["docker", "compose", "-f", str(compose_file), "up", "-d"])
    if r.returncode != 0:
        print("[benchmark] docker compose failed:\n" + r.stderr)
        sys.exit(1)
    print("[benchmark] containers started")


def wait_for_health(health_urls: dict[str, tuple[str, int]],
                    timeout_s: float = 180.0) -> None:
    deadline = time.time() + timeout_s
    remaining = set(health_urls)
    while remaining and time.time() < deadline:
        for target in list(remaining):
            host, port = health_urls[target]
            try:
                with urllib.request.urlopen(
                    f"http://{host}:{port}/", timeout=3
                ) as resp:
                    if resp.status < 500:
                        remaining.discard(target)
                        print(f"[benchmark] {target} healthy ({host}:{port})")
            except Exception:
                pass
        if remaining:
            time.sleep(2)
    if remaining:
        print("[benchmark] ERROR: targets not healthy within %ss: %s"
              % (timeout_s, ", ".join(sorted(remaining))))
        sys.exit(2)


# --------------------------------------------------------------------------
# Ground truth + config loading
# --------------------------------------------------------------------------
def load_ground_truth(target: str) -> list[dict]:
    path = BENCH_DIR / "ground-truth" / f"{target}.json"
    if not path.exists():
        return []
    with open(path) as f:
        return json.load(f).get("vulnerabilities", [])


def load_config(path: Path) -> dict[str, Any]:
    if not path.exists():
        print(f"[benchmark] config not found: {path}")
        sys.exit(1)
    with open(path) as f:
        return yaml.safe_load(f)


# --------------------------------------------------------------------------
# Session helpers
# --------------------------------------------------------------------------
def make_session(base_url: str, auth: dict | None = None) -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": "HIVEBREACH-benchmark/1.1.0"})
    if auth and auth.get("login_url"):
        try:
            s.post(base_url + auth["login_url"],
                   data=auth.get("data", {}), timeout=30)
        except Exception:
            pass
    return s


# --------------------------------------------------------------------------
# Core run
# --------------------------------------------------------------------------
def run_target(cfg: dict, target: str, dry_run: bool = False) -> BenchmarkResult:
    tcfg = cfg["targets"][target]
    base_url = tcfg["base_url"]
    gt = load_ground_truth(target)
    gt_by_class = {v["class"]: v for v in gt}

    res = BenchmarkResult(target=target)
    enabled = cfg.get("checks", {}).get("enabled", list(CHECK_REGISTRY))
    session = make_session(base_url, tcfg.get("auth"))

    print(f"\n[benchmark] == target: {target} ({base_url}) ==")
    print(f"[benchmark]    ground truth: {len(gt)} vulns, enabled checks: {enabled}")

    for check_id in enabled:
        reg = CHECK_REGISTRY.get(check_id)
        if not reg:
            print(f"[benchmark]    [skip] unknown check {check_id}")
            continue
        # Only run checks relevant to this target's ground truth
        if gt and not any(check_id in v["detectable_by"] for v in gt):
            print(f"[benchmark]    [skip] {check_id} not in {target} ground truth")
            continue

        print(f"[benchmark]    [run ] {check_id} ({reg['name']}) ...", flush=True)
        check = load_check(reg["module"], target, base_url, session,
                           auth=tcfg.get("auth"))
        if check is None:
            continue
        try:
            findings = check.run() if not dry_run else []
        except Exception as e:
            print(f"[benchmark]    [err ] {check_id}: {e}")
            continue
        for f in findings:
            # match finding to ground truth by class
            gt_match = gt_by_class.get(f.vuln_class)
            if gt_match:
                f.matched_ground_truth_id = gt_match["id"]
            res.findings.append(f)
            tag = "TP" if f.matched_ground_truth_id else "FP?"
            print(f"[benchmark]    [hit ] {tag} {f.vuln_class} on {f.endpoint} "
                  f"({f.notes})")

    res.ended_at = time.time()
    return res


def main() -> int:
    ap = argparse.ArgumentParser(description="HIVEBREACH detection benchmark")
    ap.add_argument("--config", default=str(BENCH_DIR / "config.yaml"))
    ap.add_argument("--targets", default="", help="comma-separated target names")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--no-containers", action="store_true",
                    help="skip docker compose up (assume already running)")
    args = ap.parse_args()

    cfg = load_config(Path(args.config))
    targets = (args.targets.split(",") if args.targets
               else list(cfg["targets"].keys()))

    # Sanity check targets against config
    unknown = [t for t in targets if t not in cfg["targets"]]
    if unknown:
        print(f"[benchmark] ERROR: unknown targets {unknown}")
        return 1

    if not args.no_containers:
        if not docker_available():
            print("[benchmark] ERROR: docker not available (or --no-containers)")
            return 1
        compose_file = BENCH_DIR / "docker-compose.yml"
        start_containers(compose_file)
        wait_for_health({t: (cfg["targets"][t]["host"], cfg["targets"][t]["port"])
                         for t in targets})

    all_results: list[BenchmarkResult] = []
    for t in targets:
        res = run_target(cfg, t, dry_run=args.dry_run)
        all_results.append(res)

    # Score the whole run
    expected = [v for t in targets for v in load_ground_truth(t)]
    engine = ScoringEngine(weights=cfg.get("scoring", {}).get("weights", {}),
                           severity_weight=cfg.get("scoring", {}).get("severity_weight"),
                           time_budget_s=cfg.get("scoring", {}).get(
                               "time_to_find_budget_s", 600))
    report = engine.score(all_results, expected)
    report["targets"] = [r.target for r in all_results]
    report["config"] = {
        "targets": targets,
        "enabled_checks": cfg.get("checks", {}).get("enabled", list(CHECK_REGISTRY)),
        "time_budget_s": cfg.get("scoring", {}).get("time_to_find_budget_s", 600),
        "dry_run": args.dry_run,
    }

    out_dir = ROOT / "reports" / "benchmarks"
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "benchmark-report.json"
    md_path = out_dir / "benchmark-report.md"
    json_path.write_text(json.dumps(report, indent=2))
    md_path.write_text(render_markdown(report))

    print("\n[benchmark] ================= SCORE =================")
    print(f"[benchmark]   score        : {report['score']} / 100")
    print(f"[benchmark]   precision    : {report['metrics']['precision']}")
    print(f"[benchmark]   recall       : {report['metrics']['recall']} "
          f"(weighted {report['metrics']['recall_weighted']})")
    print(f"[benchmark]   F1           : {report['metrics']['f1']}")
    print(f"[benchmark]   exploit succ : {report['metrics']['exploit_success']}")
    print(f"[benchmark]   max chain    : {report['metrics']['max_chain_depth']}")
    print(f"[benchmark]   TP={report['confusion']['tp']} FN={report['confusion']['fn']} "
          f"FP={report['confusion']['fp']}")
    print(f"[benchmark]   report       : {md_path}")
    return 0


# --------------------------------------------------------------------------
# Markdown rendering
# --------------------------------------------------------------------------
def render_markdown(report: dict) -> str:
    m = report["metrics"]
    lines = [
        "# HIVEBREACH Detection Benchmark Report",
        "",
        f"- **Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"- **Score:** **{report['score']} / 100**",
        f"- **Targets:** {', '.join(report['targets'])}",
        "",
        "## Metrics",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Precision | {m['precision']} |",
        f"| Recall | {m['recall']} |",
        f"| Recall (severity-weighted) | {m['recall_weighted']} |",
        f"| F1 | {m['f1']} |",
        f"| Time-to-find (avg s) | {m['time_to_find_avg_s'] or 'n/a'} |",
        f"| Exploit success | {m['exploit_success']} |",
        f"| Max chain depth | {m['max_chain_depth']} |",
        "",
        "## Confusion Matrix",
        "",
        f"- **TP:** {report['confusion']['tp']}",
        f"- **FN:** {report['confusion']['fn']}",
        f"- **FP:** {report['confusion']['fp']}",
        "",
        "## Detected",
        "",
    ]
    for vid in report.get("detected", []):
        lines.append(f"- `{vid}`")
    lines += ["", "## Missed", ""]
    for vid in report.get("missed", []):
        lines.append(f"- `{vid}`")
    if report.get("false_positives"):
        lines += ["", "## False Positives", ""]
        for fp in report["false_positives"]:
            lines.append(f"- {fp['target']}/{fp['check']} on {fp['endpoint']} — {fp['notes']}")
    lines += ["", "---", "*Generated by `benchmarks/run_benchmark.py`.*"]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    sys.exit(main())
