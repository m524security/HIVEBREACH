"""Generate ECC-format skill playbooks from extracted instinct lessons."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from instinct.pattern_extractor import PatternExtractor

logger = logging.getLogger(__name__)

SKILL_TEMPLATE = """---
skill: {skill_name}
mitre_attack_id: {mitre_id}
owasp_mapping: {owasp_mapping}
difficulty: {difficulty}
tags: {tags}
---

## Summary
{summary}

## Steps
{steps}

## Verification
{verification}

## References
- Extracted from instinct lesson: `{lesson_id}`
"""


class SkillGenerator:
    """Convert extracted instinct lessons into reusable ECC skill playbooks."""

    def __init__(self, output_dir: str | Path = "skills/instinct") -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._extractor = PatternExtractor()

    def generate_from_lesson(self, lesson: dict[str, Any]) -> str | None:
        technique = lesson.get("technique", "unknown").lower().replace(" ", "-")
        skill_name = f"instinct-{technique}"
        lesson_id = lesson.get("lesson_id", "unknown")

        mapping = self._resolve_mapping(technique)

        steps = self._generate_steps(technique)
        verification = self._generate_verification(technique)

        playbook = SKILL_TEMPLATE.format(
            skill_name=skill_name,
            mitre_id=mapping["mitre"],
            owasp_mapping=json.dumps(mapping["owasp"]),
            difficulty=mapping["difficulty"],
            tags=json.dumps([technique, "instinct-generated"]),
            summary=f"Auto-generated skill from instinct: {lesson.get('technique', '')} detected {lesson.get('occurrences', 0)} times across sessions.",
            steps=steps,
            verification=verification,
            lesson_id=lesson_id,
        )

        path = self.output_dir / f"{skill_name}.md"
        path.write_text(playbook, encoding="utf-8")
        logger.info("Generated skill playbook: %s", path)

        lesson.setdefault("skills_generated", []).append(str(path))
        self._update_lesson(lesson_id, lesson)

        return str(path)

    def generate_all_from_store(self) -> list[str]:
        paths: list[str] = []
        for lesson in self._extractor.list_lessons():
            if not lesson.get("skills_generated"):
                result = self.generate_from_lesson(lesson)
                if result:
                    paths.append(result)
        logger.info("Generated %d skill playbooks from lesson store", len(paths))
        return paths

    def _resolve_mapping(self, technique: str) -> dict[str, Any]:
        mapping: dict[str, Any] = {
            "sql-injection": {"mitre": "T1190", "owasp": ["A03"], "difficulty": "intermediate"},
            "cross-site-scripting": {"mitre": "T1059", "owasp": ["A07"], "difficulty": "intermediate"},
            "remote-code-execution": {"mitre": "T1203", "owasp": ["A01"], "difficulty": "advanced"},
            "ssrf": {"mitre": "T1190", "owasp": ["A10"], "difficulty": "advanced"},
            "path-traversal": {"mitre": "T1083", "owasp": ["A01"], "difficulty": "beginner"},
            "idor": {"mitre": "T1210", "owasp": ["A01"], "difficulty": "beginner"},
            "authentication-bypass": {"mitre": "T1078", "owasp": ["A07"], "difficulty": "intermediate"},
            "subdomain-takeover": {"mitre": "T1584", "owasp": ["A05"], "difficulty": "beginner"},
            "known-cve": {"mitre": "T1190", "owasp": ["A06"], "difficulty": "intermediate"},
        }
        return mapping.get(technique, {"mitre": "T1200", "owasp": ["A01"], "difficulty": "intermediate"})

    def _generate_steps(self, technique: str) -> str:
        return f"""1. Identify targets vulnerable to {technique}
2. Deploy appropriate tooling
3. Execute {technique} with safety checks
4. Verify exploitation success
5. Document findings with evidence"""

    def _generate_verification(self, technique: str) -> str:
        return f"1. Confirm {technique} via out-of-band callback\n2. Replay with different payload to eliminate false positive\n3. Validate impact severity"

    def _update_lesson(self, lesson_id: str, lesson: dict[str, Any]) -> None:
        path = self._extractor.lesson_dir / f"{lesson_id}.json"
        path.write_text(json.dumps(lesson, indent=2), encoding="utf-8")
