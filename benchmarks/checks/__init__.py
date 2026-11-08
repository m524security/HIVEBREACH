"""Detection check registry for the HIVEBREACH benchmark suite.

Each check implements a detection technique from the corresponding skill
playbook and returns a list of `Finding`s. Checks are intentionally
conservative: they fire only on deterministic, evidence-backed positives
(R2) to keep the false-positive rate measurable and honest.

Adding a new check:
    1. Create a module under benchmarks/checks/
    2. Define a `check` class/function returning list[Finding]
    3. Register it in CHECKS below with its display name and skill mapping
"""
from __future__ import annotations

import importlib
import logging
from typing import Callable

from ..scoring import Finding

logger = logging.getLogger(__name__)


class BaseCheck:
    """Base class for a single vulnerability-class detection check."""

    name: str = "base"
    skill_playbook: str = ""
    mitre: str = ""
    owasp: str = ""

    def __init__(self, target_name: str, base_url: str, session: object,
                 auth: dict | None = None, timeout: float = 300.0) -> None:
        self.target_name = target_name
        self.base_url = base_url.rstrip("/")
        self.session = session
        self.auth = auth or {}
        self.timeout = timeout
        self._findings: list[Finding] = []

    def run(self) -> list[Finding]:
        raise NotImplementedError

    def _finding(self, check_id: str, endpoint: str, method: str,
                 vuln_class: str, severity: str = "medium",
                 exploit_success: bool = False,
                 detected_at: float = 0.0, notes: str = "",
                 matched_gt_id: str | None = None) -> Finding:
        return Finding(
            target=self.target_name,
            check_id=check_id,
            endpoint=endpoint,
            method=method,
            detected=True,
            vuln_class=vuln_class,
            severity=severity,
            exploit_success=exploit_success,
            detected_at=detected_at,
            notes=notes,
            matched_ground_truth_id=matched_gt_id,
        )


def load_check(module_name: str, *args, **kwargs) -> BaseCheck | None:
    """Instantiate a check by module/class name, e.g. 'sqli:SQLiCheck'."""
    try:
        mod = importlib.import_module(f"benchmarks.checks.{module_name}")
    except ImportError as e:
        logger.warning("check module %s not importable: %s", module_name, e)
        return None
    cls = getattr(mod, "CHECK_CLASS", None)
    if isinstance(cls, str):
        cls = getattr(mod, cls, None)
    if cls is None:
        logger.warning("check module %s has no CHECK_CLASS", module_name)
        return None
    return cls(*args, **kwargs)


# Registry: check_id -> (module, display name, mitre, owasp)
CHECK_REGISTRY: dict[str, dict] = {
    "sqli": {
        "module": "sqli",
        "name": "SQL Injection",
        "mitre": "T1190",
        "owasp": "A03:2021",
        "skill": "skills/penetration-testing/sql-injection.md",
    },
    "xss": {
        "module": "xss",
        "name": "Cross-Site Scripting",
        "mitre": "T1059.007",
        "owasp": "A03:2021",
        "skill": "skills/penetration-testing/xss.md",
    },
    "ssrf": {
        "module": "ssrf",
        "name": "Server-Side Request Forgery",
        "mitre": "T1190",
        "owasp": "A10:2021",
        "skill": "skills/penetration-testing/ssrf.md",
    },
    "command_injection": {
        "module": "command_injection",
        "name": "Command Injection",
        "mitre": "T1059",
        "owasp": "A03:2021",
        "skill": "skills/penetration-testing/command-injection.md",
    },
    "file_inclusion": {
        "module": "file_inclusion",
        "name": "File Inclusion (LFI/RFI)",
        "mitre": "T1083",
        "owasp": "A01:2021",
        "skill": "skills/penetration-testing/file-inclusion.md",
    },
    "xxe": {
        "module": "xxe",
        "name": "XML External Entity",
        "mitre": "T1190",
        "owasp": "A03:2021",
        "skill": "skills/penetration-testing/xxe.md",
    },
    "auth_bypass": {
        "module": "auth_bypass",
        "name": "Authentication / Authorization Bypass",
        "mitre": "T1078",
        "owasp": "A01:2021",
        "skill": "skills/api-security/bola-bfla.md",
    },
    "unauth_api": {
        "module": "unauth_api",
        "name": "Unauthenticated API Access",
        "mitre": "T1595",
        "owasp": "A01:2021",
        "skill": "skills/api-security/bola-bfla.md",
    },
    "misconfiguration": {
        "module": "misconfiguration",
        "name": "Security Misconfiguration",
        "mitre": "T1195",
        "owasp": "A05:2021",
        "skill": "skills/server-security/server-detection.md",
    },
}
