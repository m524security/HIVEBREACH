"""Hook that loads context from previous sessions on harness startup."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from hooks.registry import register_hook

logger = logging.getLogger(__name__)

CONTEXT_FILE = Path("sessions/context_cache.json")


def _load_context_cache() -> dict[str, Any]:
    if not CONTEXT_FILE.exists():
        return {}
    try:
        raw = CONTEXT_FILE.read_bytes()
        data: dict[str, Any] = json.loads(raw)
        logger.info("Loaded context cache from %s (%d keys)", CONTEXT_FILE, len(data))
        return data
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to load context cache: %s", exc)
        return {}


def load_context_hook(context: dict[str, Any]) -> dict[str, Any]:
    cached = _load_context_cache()
    if not cached:
        logger.info("No previous context found — starting fresh")
        context["previous_sessions"] = []
        return context

    previous_sessions = [
        {
            "session_id": sid,
            "timestamp": meta.get("timestamp"),
            "targets": meta.get("targets", []),
            "finding_count": meta.get("finding_count", 0),
        }
        for sid, meta in cached.get("sessions", {}).items()
    ]

    context["previous_sessions"] = previous_sessions
    context["cross_session_context"] = cached.get("shared_context", {})

    logger.info(
        "Loaded %d previous sessions and shared context into harness",
        len(previous_sessions),
    )
    return context


register_hook(
    name="load_context",
    lifecycle_point="pre_scan",
    handler=load_context_hook,
    priority=90,
    profile="standard",
)
