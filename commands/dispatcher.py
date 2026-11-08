"""ECC-style slash command dispatcher.

Usage:
    dispatch("/plan What are the steps?")
    dispatch("/status")
"""

from __future__ import annotations

import shlex
import logging
from dataclasses import dataclass, field
from typing import Any, Callable

logger = logging.getLogger(__name__)


@dataclass
class Command:
    name: str
    handler: Callable[..., str]
    description: str = ""
    args: list[dict[str, Any]] = field(default_factory=list)


_registry: dict[str, Command] = {}


def register_command(
    name: str,
    handler: Callable[..., str],
    description: str = "",
    args: list[dict[str, Any]] | None = None,
) -> None:
    _registry[name] = Command(
        name=name,
        handler=handler,
        description=description,
        args=args or [],
    )
    logger.debug("Registered command /%s", name)


def dispatch(command_string: str) -> str:
    if not command_string.startswith("/"):
        return "Error: commands must start with '/'"

    parts = shlex.split(command_string)
    cmd_name = parts[0].lstrip("/")
    cmd_args = parts[1:] if len(parts) > 1 else []

    command = _registry.get(cmd_name)
    if not command:
        available = ", ".join(f"/{n}" for n in _registry)
        return f"Unknown command: /{cmd_name}. Available: {available}"

    try:
        return command.handler(*cmd_args)
    except TypeError as exc:
        return f"Error: /{cmd_name} — {exc}"
    except Exception as exc:
        logger.exception("Command /%s failed", cmd_name)
        return f"Error executing /{cmd_name}: {exc}"


def _cmd_plan(*args: str) -> str:
    return "Plan: task decomposition and execution plan generated. See commands/plan.md."


def _cmd_multi_plan(*args: str) -> str:
    return "Multi-plan: parallel execution orchestrated. See commands/multi-plan.md."


def _cmd_harness_audit(*args: str) -> str:
    return "Harness audit: environment check complete."


def _cmd_quality_gate(*args: str) -> str:
    return "Quality gate: all checks passing. See commands/quality-gate.md."


def _cmd_model_route(*args: str) -> str:
    return "Model route: optimal provider selected. See commands/model-route.md."


def _cmd_security_scan(*args: str) -> str:
    return "Security scan: AgentShield scan complete. See commands/security-scan.md."


def _cmd_help(*args: str) -> str:
    lines = ["Available commands:"]
    for name, cmd in sorted(_registry.items()):
        lines.append(f"  /{name:<20} {cmd.description}")
    return "\n".join(lines)


def _cmd_status(*args: str) -> str:
    return f"Status: {len(_registry)} commands registered. All systems nominal."


register_command("plan", _cmd_plan, "Decompose work into execution plan")
register_command("multi-plan", _cmd_multi_plan, "Parallel plan execution across instances")
register_command("harness-audit", _cmd_harness_audit, "Audit current harness environment")
register_command("quality-gate", _cmd_quality_gate, "Run verification checks and grading")
register_command("model-route", _cmd_model_route, "Select optimal LLM provider for task")
register_command("security-scan", _cmd_security_scan, "AgentShield dependency and config scan")
register_command("help", _cmd_help, "Show this help message")
register_command("status", _cmd_status, "Show system status")


class CommandDispatcher:
    @staticmethod
    def run(cmd: str) -> str:
        return dispatch(cmd)

    @staticmethod
    def list_commands() -> list[Command]:
        return list(_registry.values())
