"""ECC-style hook registry with profile-based lifecycle gating.

Profiles controlled via ECC_HOOK_PROFILE env var:
    - minimal: only critical hooks
    - standard: common hooks (default)
    - strict: all hooks including audit/verbose
"""

from __future__ import annotations

import os
import logging
from dataclasses import dataclass, field
from typing import Any, Callable

logger = logging.getLogger(__name__)

HOOK_PROFILE = os.getenv("ECC_HOOK_PROFILE", "standard")

LIFECYCLE_POINTS = ("pre_scan", "post_scan", "on_finding")


@dataclass(order=True)
class Hook:
    name: str
    lifecycle_point: str
    handler: Callable[[dict[str, Any]], dict[str, Any]] = field(compare=False)
    priority: int = 100
    profile: str = "standard"


_registry: dict[str, list[Hook]] = {point: [] for point in LIFECYCLE_POINTS}


def register_hook(
    name: str,
    lifecycle_point: str,
    handler: Callable[[dict[str, Any]], dict[str, Any]],
    priority: int = 100,
    profile: str = "standard",
) -> None:
    if lifecycle_point not in _registry:
        raise ValueError(f"Unknown lifecycle point: {lifecycle_point}")
    hook = Hook(
        name=name,
        lifecycle_point=lifecycle_point,
        handler=handler,
        priority=priority,
        profile=profile,
    )
    _registry[lifecycle_point].append(hook)
    _registry[lifecycle_point].sort(key=lambda h: h.priority)
    logger.debug("Registered hook '%s' at %s (profile=%s, priority=%d)", name, lifecycle_point, profile, priority)


def _is_hook_active(hook: Hook) -> bool:
    profile_order = {"strict": 0, "standard": 1, "minimal": 2}
    hook_order = profile_order.get(hook.profile, 1)
    current_order = profile_order.get(HOOK_PROFILE, 1)
    return hook_order >= current_order


def execute(lifecycle_point: str, context: dict[str, Any]) -> dict[str, Any]:
    if lifecycle_point not in _registry:
        raise ValueError(f"Unknown lifecycle point: {lifecycle_point}")

    hooks = _registry[lifecycle_point]
    active = [h for h in hooks if _is_hook_active(h)]
    logger.info(
        "Executing %d/%d hooks at '%s' (profile=%s)",
        len(active), len(hooks), lifecycle_point, HOOK_PROFILE,
    )

    result = dict(context)
    for hook in active:
        try:
            result = hook.handler(result)
        except Exception:
            logger.exception("Hook '%s' failed at %s", hook.name, lifecycle_point)
            if HOOK_PROFILE == "strict":
                raise
    return result


class HookRegistry:
    """Convenience wrapper around module-level registry."""

    @staticmethod
    def register(
        name: str,
        lifecycle_point: str,
        handler: Callable[[dict[str, Any]], dict[str, Any]],
        priority: int = 100,
        profile: str = "standard",
    ) -> None:
        register_hook(name, lifecycle_point, handler, priority, profile)

    @staticmethod
    def run(lifecycle_point: str, context: dict[str, Any]) -> dict[str, Any]:
        return execute(lifecycle_point, context)

    @staticmethod
    def list_hooks(lifecycle_point: str | None = None) -> list[Hook]:
        if lifecycle_point:
            return list(_registry.get(lifecycle_point, []))
        return [h for hooks in _registry.values() for h in hooks]
