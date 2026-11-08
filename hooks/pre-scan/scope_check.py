"""Hook that validates scan targets are within authorised scope."""

from __future__ import annotations

import ipaddress
import logging
from typing import Any

from hooks.registry import register_hook

logger = logging.getLogger(__name__)

AUTHORISED_RANGES: list[str] = []


def set_authorised_ranges(ranges: list[str]) -> None:
    global AUTHORISED_RANGES
    AUTHORISED_RANGES = list(ranges)


def _is_in_scope(target: str) -> bool:
    if not AUTHORISED_RANGES:
        return False
    try:
        addr = ipaddress.ip_address(target)
        for cidr in AUTHORISED_RANGES:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
        return False
    except ValueError:
        return any(target.endswith(domain.lstrip(".")) for domain in AUTHORISED_RANGES)


def scope_check_hook(context: dict[str, Any]) -> dict[str, Any]:
    target = context.get("target", "")
    if not target:
        logger.error("No target provided in context")
        context["scope_valid"] = False
        return context

    in_scope = _is_in_scope(target)
    context["scope_valid"] = in_scope
    if not in_scope:
        logger.warning("Target '%s' is OUT OF SCOPE — blocking scan", target)
    else:
        logger.info("Target '%s' is IN SCOPE — proceeding", target)
    return context


register_hook(
    name="scope_check",
    lifecycle_point="pre_scan",
    handler=scope_check_hook,
    priority=10,
    profile="minimal",
)
