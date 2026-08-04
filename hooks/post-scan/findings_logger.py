"""Hook that logs all findings after a scan completes."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from hooks.registry import register_hook

logger = logging.getLogger(__name__)


def findings_logger_hook(context: dict[str, Any]) -> dict[str, Any]:
    findings = context.get("findings", [])
    target = context.get("target", "unknown")
    scan_id = context.get("scan_id", "unknown")

    summary = {
        "scan_id": scan_id,
        "target": target,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_findings": len(findings),
        "severity_counts": {},
        "findings": [],
    }

    for finding in findings:
        severity = finding.get("severity", "info")
        summary["severity_counts"][severity] = summary["severity_counts"].get(severity, 0) + 1
        summary["findings"].append({
            "id": finding.get("id"),
            "name": finding.get("name"),
            "severity": severity,
            "confidence": finding.get("confidence"),
        })

    log_line = json.dumps(summary)
    logger.info("Scan complete — %s", log_line)

    context["findings_summary"] = summary
    context["findings_logged"] = True
    return context


register_hook(
    name="findings_logger",
    lifecycle_point="post_scan",
    handler=findings_logger_hook,
    priority=50,
    profile="standard",
)
