"""ECC instinct system — auto-extract patterns from session logs into reusable lessons."""

from __future__ import annotations

import json
import logging
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

LESSON_STORE = Path("instinct/lesson-store")
FINDING_PATTERNS: list[dict[str, Any]] = [
    {"regex": r"(?i)(SQL injection|SQLi)", "category": "injection", "technique": "SQL injection"},
    {"regex": r"(?i)(XSS|cross.?site)", "category": "injection", "technique": "Cross-site scripting"},
    {"regex": r"(?i)(path traversal|directory traversal)", "category": "injection", "technique": "Path traversal"},
    {"regex": r"(?i)(RCE|remote code|command injection)", "category": "execution", "technique": "Remote code execution"},
    {"regex": r"(?i)(SSRF|server.?side request)", "category": "injection", "technique": "SSRF"},
    {"regex": r"(?i)(open.?redirect)", "category": "injection", "technique": "Open redirect"},
    {"regex": r"(?i)(IDOR|insecure direct)", "category": "access_control", "technique": "IDOR"},
    {"regex": r"(?i)(broken auth|authentication bypass)", "category": "auth", "technique": "Authentication bypass"},
    {"regex": r"(?i)(subdomain takeover)", "category": "infra", "technique": "Subdomain takeover"},
    {"regex": r"(?i)(CVE-\d{4}-\d{4,7})", "category": "cve", "technique": "Known CVE"},
]


class PatternExtractor:
    """Parse session logs to extract repeated patterns and generate structured lessons."""

    def __init__(self, lesson_dir: str | Path | None = None) -> None:
        self.lesson_dir = Path(lesson_dir) if lesson_dir else LESSON_STORE
        self.lesson_dir.mkdir(parents=True, exist_ok=True)

    def extract_from_logs(self, log_paths: list[str | Path]) -> list[dict[str, Any]]:
        lessons: list[dict[str, Any]] = []
        finding_counter: Counter = Counter()

        for log_path in log_paths:
            path = Path(log_path)
            if not path.exists():
                logger.warning("Log file not found: %s", path)
                continue

            try:
                text = path.read_text(encoding="utf-8")
            except OSError as exc:
                logger.warning("Cannot read %s: %s", path, exc)
                continue

            for pattern_def in FINDING_PATTERNS:
                matches = re.findall(pattern_def["regex"], text)
                if matches:
                    key = pattern_def["technique"]
                    finding_counter[key] += len(matches)

        if not finding_counter:
            logger.info("No patterns extracted from logs")
            return []

        total = sum(finding_counter.values())
        for technique, count in finding_counter.most_common():
            frequency = round(count / total * 100, 1)
            lesson = self._build_lesson(technique, count, frequency)
            self._save_lesson(lesson)
            lessons.append(lesson)

        logger.info("Extracted %d patterns from logs", len(lessons))
        return lessons

    def _build_lesson(self, technique: str, count: int, frequency: float) -> dict[str, Any]:
        lesson_id = technique.lower().replace(" ", "_").replace("-", "_")
        return {
            "lesson_id": lesson_id,
            "technique": technique,
            "occurrences": count,
            "frequency_pct": frequency,
            "extracted_at": datetime.now(timezone.utc).isoformat(),
            "tags": [technique.lower().replace(" ", "-")],
            "notes": [],
            "skills_generated": [],
        }

    def _save_lesson(self, lesson: dict[str, Any]) -> Path:
        path = self.lesson_dir / f"{lesson['lesson_id']}.json"
        path.write_text(json.dumps(lesson, indent=2), encoding="utf-8")
        logger.info("Lesson saved: %s", path)
        return path

    def list_lessons(self) -> list[dict[str, Any]]:
        lessons: list[dict[str, Any]] = []
        for p in self.lesson_dir.glob("*.json"):
            try:
                lessons.append(json.loads(p.read_text(encoding="utf-8")))
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Failed to read lesson %s: %s", p.name, exc)
        return lessons

    def get_lesson(self, lesson_id: str) -> dict[str, Any] | None:
        path = self.lesson_dir / f"{lesson_id}.json"
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None
