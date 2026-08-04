"""ECC AgentShield: runtime security monitoring for agent operations."""

from __future__ import annotations

import logging
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

DANGEROUS_PATTERNS: list[tuple[str, str, str]] = [
    # (pattern, severity, description)
    (r"(?i)\brm\s+-rf\s+(?:/|\.|~)", "critical", "Recursive delete of root/home"),
    (r"(?i)\bdd\s+if=", "critical", "Direct disk write operation"),
    (r"(?i)\bmkfs\.", "critical", "Filesystem creation"),
    (r"(?i)\b>:?\s*/dev/", "high", "Direct device write"),
    (r"(?i)\bchmod\s+777\b", "high", "Overly permissive chmod"),
    (r"(?i)\bcurl\s+.*\|\s*bash", "high", "Pipe curl to shell"),
    (r"(?i)\bwget\s+.*\|\s*bash", "high", "Pipe wget to shell"),
    (r"(?i)\beval\b", "high", "Eval command execution"),
    (r"(?i)\bexec\b", "medium", "Exec call"),
    (r"(?i)\bshutdown\b", "high", "System shutdown"),
    (r"(?i)\breboot\b", "high", "System reboot"),
    (r"(?i)\bpasswd\b", "medium", "Password change operation"),
    (r"(?i)\buseradd\b", "medium", "User creation"),
]

ALLOWED_BASE_DIRS: list[str] = []


def whitelist_directory(path: str) -> None:
    ALLOWED_BASE_DIRS.append(str(Path(path).resolve()))


@dataclass
class ShieldAlert:
    pattern: str
    severity: str
    description: str
    command: str
    source: str = ""


class AgentShield:
    """Runtime security monitor that detects dangerous agent behaviour."""

    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled
        self.alerts: list[ShieldAlert] = field(default_factory=list)

    def inspect_command(self, command: str, source: str = "") -> list[ShieldAlert]:
        if not self.enabled:
            return []

        found: list[ShieldAlert] = []
        for pattern, severity, description in DANGEROUS_PATTERNS:
            if re.search(pattern, command):
                alert = ShieldAlert(
                    pattern=pattern,
                    severity=severity,
                    description=description,
                    command=command[:200],
                    source=source,
                )
                found.append(alert)
                log_method = logger.critical if severity == "critical" else logger.warning
                log_method("[AgentShield] %s: %s — '%s'", severity.upper(), description, command[:120])

        self.alerts.extend(found)
        return found

    def validate_file_access(self, path: str) -> bool:
        resolved = Path(path).resolve()
        if not ALLOWED_BASE_DIRS:
            return True

        for allowed in ALLOWED_BASE_DIRS:
            try:
                resolved.relative_to(Path(allowed).resolve())
                return True
            except ValueError:
                continue

        logger.warning("[AgentShield] File access denied: '%s' (outside allowed dirs)", path)
        return False

    def inspect_arguments(self, args: list[str]) -> list[dict[str, Any]]:
        issues: list[dict[str, Any]] = []
        for arg in args:
            if arg.startswith(("--password=", "--token=", "--key=", "--secret=")):
                issues.append({"arg": arg.split("=")[0], "issue": "Potential secret in argument"})
                logger.warning("[AgentShield] Secret detected in argument: %s", arg.split("=")[0])
            if ".." in arg and arg != "..":
                issues.append({"arg": arg, "issue": "Potential path traversal"})
        return issues

    def monitor(self, command_string: str, source: str = "") -> dict[str, Any]:
        alerts = self.inspect_command(command_string, source)
        try:
            args = shlex.split(command_string)
        except ValueError:
            args = command_string.split()

        arg_issues = self.inspect_arguments(args)

        blocked = any(a.severity == "critical" for a in alerts)
        return {
            "blocked": blocked,
            "alerts": [{"severity": a.severity, "description": a.description} for a in alerts],
            "arg_issues": arg_issues,
            "command": command_string[:200],
        }

    def get_alerts(self, min_severity: str = "medium") -> list[ShieldAlert]:
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        min_order = severity_order.get(min_severity, 2)
        return [a for a in self.alerts if severity_order.get(a.severity, 99) >= min_order]

    def clear_alerts(self) -> None:
        self.alerts.clear()
