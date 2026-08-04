"""Unauthenticated API access detection check.

Strategy (from skills/api-security/bola-bfla.md):
- Request API endpoints with no session token and evaluate whether sensitive
  data is returned without authentication.
- Checks /users/v1 (VAmPI) and Juice Shop profile endpoints.
"""
from __future__ import annotations

import time

from ..scoring import Finding
from . import BaseCheck

CHECK_CLASS = "UnauthAPICheck"

SENSITIVE_PATTERNS = [
    "admin",
    "root",
    "password",
    "token",
    "sessionId",
]


class UnauthAPICheck(BaseCheck):
    name = "unauth_api"
    skill_playbook = "skills/api-security/bola-bfla.md"
    mitre = "T1595"
    owasp = "A01:2021"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.probes = [
            "/users/v1",
            "/users/v2",
            "/rest/user/current",
            "/rest/products",
        ]

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        for path in self.probes:
            url = self.base_url + path
            try:
                r = self.session.get(url, timeout=self.timeout)
            except Exception:
                continue
            if r is None:
                continue
            # Any of the sensitive-pattern markers in an *unauthenticated*
            # response is a deterministic proof of missing authz.
            if 200 <= r.status_code < 300 and any(
                p in r.text for p in SENSITIVE_PATTERNS
            ):
                findings.append(self._finding(
                    "unauth_api", path, "GET", "unauth_api",
                    severity="critical",
                    detected_at=time.time(),
                    notes="sensitive data returned without auth (2xx, %d bytes)" % len(r.text),
                ))
        return findings
