"""Hook that saves session state on scan completion."""

from __future__ import annotations

import logging
from typing import Any

from hooks.registry import register_hook
from memory.session_manager import SessionManager

logger = logging.getLogger(__name__)

_session_manager = SessionManager()


def save_session_hook(context: dict[str, Any]) -> dict[str, Any]:
    scan_id = context.get("scan_id", "unknown")
    target = context.get("target", "unknown")
    findings = context.get("findings", [])

    session = _session_manager.create_session(
        session_id=scan_id,
        agents_used=[context.get("agent", "unknown")],
        targets=[target],
    )
    session.finding_count = len(findings)
    session.data = {
        "summary": context.get("findings_summary"),
        "scan_metadata": {
            "duration": context.get("duration"),
            "tool": context.get("tool"),
            "status": context.get("status"),
        },
    }

    path = _session_manager.save_session(session)
    context["session_path"] = str(path)
    context["session_saved"] = True
    logger.info("Session '%s' persisted to %s", scan_id, path)
    return context


register_hook(
    name="save_session",
    lifecycle_point="post_scan",
    handler=save_session_hook,
    priority=80,
    profile="standard",
)
