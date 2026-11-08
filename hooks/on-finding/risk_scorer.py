"""Hook that scores findings for risk on discovery."""

from __future__ import annotations

import logging
from typing import Any

from hooks.registry import register_hook

logger = logging.getLogger(__name__)

SEVERITY_WEIGHTS = {
    "critical": 10.0,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "info": 0.5,
}

CONFIDENCE_WEIGHTS = {
    "confirmed": 1.0,
    "high": 0.85,
    "medium": 0.65,
    "low": 0.4,
    "speculative": 0.15,
}


def _compute_risk_score(finding: dict[str, Any]) -> float:
    severity = finding.get("severity", "info")
    confidence = finding.get("confidence", "low")

    base = SEVERITY_WEIGHTS.get(severity, 0.5)
    modifier = CONFIDENCE_WEIGHTS.get(confidence, 0.4)

    exploitability = min(finding.get("exploitability", 0.5), 1.0)
    impact = min(finding.get("impact", 0.5), 1.0)

    raw = base * modifier + (exploitability * impact * 5.0)
    return round(min(raw, 10.0), 2)


def risk_scorer_hook(context: dict[str, Any]) -> dict[str, Any]:
    finding = context.get("finding", {})
    finding_id = finding.get("id", "unknown")

    risk_score = _compute_risk_score(finding)
    finding["risk_score"] = risk_score

    if risk_score >= 8.0:
        finding["priority"] = "immediate"
    elif risk_score >= 5.0:
        finding["priority"] = "high"
    elif risk_score >= 2.5:
        finding["priority"] = "medium"
    else:
        finding["priority"] = "low"

    logger.info(
        "Finding '%s' scored: risk=%.2f, priority=%s",
        finding_id, risk_score, finding["priority"],
    )

    context["finding"] = finding
    context["risk_scored"] = True
    return context


register_hook(
    name="risk_scorer",
    lifecycle_point="on_finding",
    handler=risk_scorer_hook,
    priority=30,
    profile="standard",
)
