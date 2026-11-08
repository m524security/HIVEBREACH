"""Reflected XSS detection check (from skills/penetration-testing/xss.md).

Strategy: inject a non-destructive marker payload and look for reflection in
the response body. The payload is benign (no script execution on the target;
it only proves reflection of attacker-controlled input).
"""
from __future__ import annotations

import time
import urllib.parse

from ..scoring import Finding
from . import BaseCheck

CHECK_CLASS = "XSSCheck"

MARKER = "hivebreachxssmarker1234"
PAYLOADS = [
    f"<b>{MARKER}</b>",
    f'"><svg/onload=alert({MARKER})>',
    f"<script>{MARKER}</script>",
    f'<img src=x onerror="alert({MARKER})">',
]


class XSSCheck(BaseCheck):
    name = "xss"
    skill_playbook = "skills/penetration-testing/xss.md"
    mitre = "T1059.007"
    owasp = "A03:2021"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.paths = [
            "/vulnerabilities/xss_r/?name={P}",
            "/rest/products/search?q={P}",
        ]

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        for path in self.paths:
            for payload in PAYLOADS:
                enc = urllib.parse.quote(payload)
                url = self.base_url + path.replace("{P}", enc)
                try:
                    r = self.session.get(url, timeout=self.timeout)
                except Exception:
                    continue
                if r is None or r.status_code >= 500:
                    continue
                # reflected unescaped marker => XSS
                if MARKER in r.text:
                    findings.append(self._finding(
                        "xss", path, "GET", "xss",
                        severity="high",
                        detected_at=time.time(),
                        notes="marker %s reflected in response" % MARKER,
                    ))
                    break
        return findings
