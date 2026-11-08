#!/usr/bin/env python3
"""Generate a MITRE ATT&CK coverage gap report.

Compares all ATT&CK technique IDs referenced in HIVEBREACH skills/
(and agent playbooks) against the master technique-index.json and
reports:
  - techniques with NO skill coverage (gaps -> candidates for new playbooks)
  - techniques WITH coverage and which skill covers them
  - duplicate/unused technique IDs

Usage:
    python3 tools/gap-report.py [--json] [--threshold N]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SKILLS_DIR = REPO / "skills"
AGENTS_DIR = REPO / "agents"
INDEX = SKILLS_DIR / "_knowledge" / "mitre-attack" / "technique-index.json"

MITRE_ID_RE = re.compile(r"T\d{4}(?:\.\d{3})?")

OUTPUT_JSON = False
THRESHOLD = 80


def load_technique_index() -> dict:
    data = json.loads(INDEX.read_text())
    techniques = {}
    if isinstance(data, dict):
        data = data.get("techniques", data)
    for entry in data if isinstance(data, list) else data.values():
        tid = entry.get("id") or entry.get("technique_id")
        name = entry.get("name") or entry.get("technique_name")
        if tid:
            techniques[tid] = name or tid
    return techniques


def scan_files(directory: Path) -> dict[str, set[str]]:
    """Map technique ID -> set of files referencing it."""
    mapping: dict[str, set[str]] = defaultdict(set)
    for path in sorted(directory.rglob("*.md")):
        text = path.read_text(errors="ignore")
        for tid in set(MITRE_ID_RE.findall(text)):
            mapping[tid].add(str(path.relative_to(REPO)))
    return mapping


def main() -> int:
    global OUTPUT_JSON, THRESHOLD
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true", help="emit JSON output")
    parser.add_argument("--threshold", type=int, default=THRESHOLD,
                        help="% coverage considered acceptable (default 80)")
    args = parser.parse_args()

    OUTPUT_JSON = args.json
    THRESHOLD = args.threshold

    if not INDEX.exists():
        print(f"[!] technique index not found: {INDEX}", file=sys.stderr)
        return 1

    index = load_technique_index()
    skill_map = scan_files(SKILLS_DIR)
    agent_map = scan_files(AGENTS_DIR)

    all_covered = set(skill_map) | set(agent_map)
    all_techniques = set(index)

    # parent ID coverage: T1190 covers T1190.001, T1190.002 ...
    parents = {t.split(".")[0] for t in all_techniques}
    covered_parents = {t.split(".")[0] for t in all_covered}
    sub_covered = {t for t in all_techniques if t.split(".")[0] in covered_parents}
    effective_covered = all_covered | sub_covered

    gaps = sorted(all_techniques - effective_covered)
    covered = sorted(effective_covered & all_techniques)

    if OUTPUT_JSON:
        report = {
            "total_techniques": len(all_techniques),
            "explicitly_covered": len(all_covered & all_techniques),
            "effectively_covered": len(covered),
            "coverage_pct": round(len(covered) / max(len(all_techniques), 1) * 100, 1),
            "gaps": [{"id": tid, "name": index.get(tid, "?")} for tid in gaps],
            "skills_by_technique": {
                tid: sorted(files) for tid, files in skill_map.items()
            },
        }
        print(json.dumps(report, indent=2))
        return 0

    total = len(all_techniques)
    cov = len(covered)
    pct = round(cov / max(total, 1) * 100, 1)
    print(f"HIVEBREACH MITRE ATT&CK coverage gap report")
    print(f"=============================================")
    print(f"techniques in index     : {total}")
    print(f"effectively covered     : {cov} ({pct}%)")
    print(f"explicit technique IDs  : {len(all_covered & all_techniques)}")
    print(f"gaps (no skill/playbook): {len(gaps)}")
    print()

    if gaps:
        print("TOP GAPS (no coverage):")
        for tid in gaps:
            print(f"  - {tid:10s} {index.get(tid, '?')}")
    else:
        print("No gaps. Full ATT&CK coverage.")

    print()
    print("SKILLS WITH TECHNIQUE IDs (coverage map):")
    for tid, files in sorted(skill_map.items()):
        print(f"  {tid:10s} <- {', '.join(files)}")

    return 0 if pct >= THRESHOLD else 2


if __name__ == "__main__":
    sys.exit(main())
