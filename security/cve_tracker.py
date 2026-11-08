"""ECC CVE tracking and alerting for target tech stack dependencies."""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

CVE_STORE = Path("security/cve_cache.json")

CRITICALITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 4}
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


@dataclass
class CVE:
    id: str
    published: str
    severity: str
    description: str
    affected_packages: list[str] = field(default_factory=list)
    matched: bool = False


class CVETracker:
    """Monitor CVEs relevant to target tech stack and alert on matches."""

    def __init__(self, cache_file: str | Path | None = None) -> None:
        self.cache_file = Path(cache_file) if cache_file else CVE_STORE
        self.cves: list[CVE] = self._load_cache()

    def _load_cache(self) -> list[CVE]:
        if not self.cache_file.exists():
            return []
        try:
            raw = self.cache_file.read_text(encoding="utf-8")
            data: list[dict[str, Any]] = json.loads(raw)
            return [CVE(**item) for item in data]
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Failed to load CVE cache: %s", exc)
            return []

    def _save_cache(self) -> None:
        self.cache_file.parent.mkdir(parents=True, exist_ok=True)
        data = [
            {
                "id": c.id,
                "published": c.published,
                "severity": c.severity,
                "description": c.description,
                "affected_packages": c.affected_packages,
            }
            for c in self.cves
        ]
        self.cache_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def ingest_cve_list(self, cve_data: list[dict[str, Any]]) -> int:
        ingested = 0
        for item in cve_data:
            cve_id = item.get("id", "")
            if not cve_id or not CVE_PATTERN.match(cve_id):
                continue
            if any(c.id == cve_id for c in self.cves):
                continue
            self.cves.append(CVE(
                id=cve_id,
                published=item.get("published", ""),
                severity=item.get("severity", "unknown"),
                description=item.get("description", ""),
                affected_packages=item.get("affected_packages", []),
            ))
            ingested += 1

        if ingested:
            self._save_cache()
            logger.info("Ingested %d new CVEs (total: %d)", ingested, len(self.cves))
        return ingested

    def match_against_stack(self, packages: list[str]) -> list[CVE]:
        matched: list[CVE] = []
        for cve in self.cves:
            if cve.matched:
                continue
            for pkg in packages:
                if any(pkg.lower() in ap.lower() for ap in cve.affected_packages):
                    cve.matched = True
                    matched.append(cve)
                    logger.warning("CVE match: %s affects %s (%s)", cve.id, pkg, cve.severity)
                    break
        return matched

    def get_critical_alerts(self, min_severity: str = "high") -> list[CVE]:
        min_order = CRITICALITY_ORDER.get(min_severity, 1)
        return [
            c for c in self.cves
            if c.matched and CRITICALITY_ORDER.get(c.severity, 99) <= min_order
        ]

    def alert_if_critical(self, packages: list[str]) -> dict[str, Any]:
        matched = self.match_against_stack(packages)
        critical = self.get_critical_alerts("high")

        if critical:
            logger.critical("=== CRITICAL CVE ALERT ===")
            for cve in critical:
                logger.critical("  %s (%s): %s", cve.id, cve.severity.upper(), cve.description[:120])

        return {
            "total_cves_in_db": len(self.cves),
            "matched_this_scan": len(matched),
            "critical_alerts": len(critical),
            "alerts": [
                {
                    "id": c.id,
                    "severity": c.severity,
                    "description": c.description[:200],
                    "packages": c.affected_packages,
                }
                for c in critical
            ],
        }

    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for c in self.cves:
            sev = c.severity.lower()
            counts[sev] = counts.get(sev, 0) + 1
        return {
            "total": len(self.cves),
            "matched": sum(1 for c in self.cves if c.matched),
            "by_severity": counts,
        }
