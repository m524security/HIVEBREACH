#!/usr/bin/env python3
"""Self-learning pipeline: scan findings for confirmed techniques -> propose lessons.

Reads a findings file (JSON/YAML/Markdown) and appends proposed lessons to
skills/_knowledge/lessons/lessons.md between the LESSONS START/END markers.

Usage:
    python3 tools/self-learn.py --findings <findings.json|findings.yaml> [--preview] [--apply]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
LESSONS_FILE = REPO / "skills" / "_knowledge" / "lessons" / "lessons.md"
START = "<!-- LESSONS START -->"
END = "<!-- LESSONS END -->"

CONFIDENCE_GOOD = {"confirmed", "high", "verified"}


def load_findings(path: Path) -> list[dict]:
    text = path.read_text(errors="ignore")
    suffix = path.suffix.lower()
    if suffix in (".json", ".jsonl"):
        if suffix == ".jsonl":
            return [json.loads(line) for line in text.splitlines() if line.strip()]
        data = json.loads(text)
        if isinstance(data, dict):
            data = data.get("findings", data.get("results", []))
        return data
    if suffix in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore

            data = yaml.safe_load(text)
            if isinstance(data, dict):
                data = data.get("findings", data.get("results", []))
            return data or []
        except ImportError:
            print("[!] PyYAML not installed; install with: pip install pyyaml", file=sys.stderr)
            return []
    # markdown: naive split on ### findings
    findings = []
    for block in re.split(r"(?m)^### ", text):
        if not block.strip():
            continue
        title = block.splitlines()[0].strip()
        body = block
        findings.append({
            "title": title,
            "raw": body,
            "mitre_id": _first_id(body),
            "confidence": "confirmed" if "confirmed" in body.lower() else "tentative",
        })
    return findings


def _first_id(text: str) -> str:
    m = re.search(r"T\d{4}(?:\.\d{3})?", text)
    return m.group(0) if m else "T0000"


def build_lesson(f: dict, engagement_id: str) -> str:
    title = f.get("title") or f.get("name") or "Untitled technique"
    mitre = f.get("mitre_id") or _first_id(str(f))
    env = f.get("environment") or f.get("env") or "web"
    poc = f.get("poc") or f.get("evidence") or f.get("raw") or ""
    poc = str(poc).replace("|", "\\|").strip()[:600]
    date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return (
        f"### {title} — {engagement_id}\n"
        f"- **Date:** {date}\n"
        f"- **Environment:** {env}\n"
        f"- **MITRE ATT&CK:** {mitre}\n"
        f"- **Skill Playbook:** _(map to skills/ during review)_\n"
        f"- **How it was found:** _(operator to fill)_\n"
        f"- **Payload/PoC (redacted):**\n"
        f"  ```\n{poc}\n  ```\n"
        f"- **Observable evidence:** _(operator to fill)_\n"
        f"- **Lessons learned:** _(operator to fill)_\n\n"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--findings", required=True, help="findings file (json/jsonl/yaml/md)")
    parser.add_argument("--engagement", default="ENG-UNSPECIFIED", help="engagement id")
    parser.add_argument("--preview", action="store_true", help="print proposed lessons, don't write")
    parser.add_argument("--apply", action="store_true", help="append to lessons.md")
    args = parser.parse_args()

    findings_path = Path(args.findings)
    if not findings_path.exists():
        print(f"[!] findings file not found: {findings_path}", file=sys.stderr)
        return 1

    findings = load_findings(findings_path)
    confirmed = [
        f for f in findings
        if str(f.get("confidence", "")).lower() in CONFIDENCE_GOOD
    ]
    proposed = [build_lesson(f, args.engagement) for f in confirmed]

    if not proposed:
        print("[i] No confirmed findings to self-learn from.")
        return 0

    block = "\n" + "".join(proposed)
    if args.preview:
        print("PROPOSED LESSONS:")
        print(block)
        return 0

    if not args.apply:
        print("[i] Preview mode. Run with --apply to append.")
        print(block)
        return 0

    text = LESSONS_FILE.read_text()
    if START not in text or END not in text:
        print("[!] lessons.md markers missing.", file=sys.stderr)
        return 1
    text = text.replace(START + "\n" + END, START + block + END)
    LESSONS_FILE.write_text(text)
    print(f"[+] Appended {len(proposed)} lessons to {LESSONS_FILE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
