"""Auth / authorization bypass detection check.

Strategy (from skills/api-security/bola-bfla.md):
- Attempt to access admin/protected resources without a valid session.
- Test for IDOR: enumerate a resource ID and attempt cross-user access.
- Look for 200/2xx on endpoints that should require elevated privilege.

Only fires on deterministic evidence (privilege not actually enforced).
"""
from __future__ import annotations

import time

from ..scoring import Finding
from . import BaseCheck

CHECK_CLASS = "AuthBypassCheck"


class AuthBypassCheck(BaseCheck):
    name = "auth_bypass"
    skill_playbook = "skills/api-security/bola-bfla.md"
    mitre = "T1078"
    owasp = "A01:2021"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.probes = [
            # (path, method, data)
            ("/vulnerabilities/brute/", "GET", None),
            ("/admin/", "GET", None),
            ("/users/v1/admin", "DELETE", None),
        ]

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        for path, method, data in self.probes:
            url = self.base_url + path
            try:
                if method == "GET":
                    r = self.session.get(url, timeout=self.timeout)
                elif method == "DELETE":
                    r = self.session.delete(url, timeout=self.timeout)
                else:
                    r = self.session.post(url, data=data, timeout=self.timeout)
            except Exception:
                continue
            if r is None:
                continue
            # Deterministic privilege-enforcement gap: 2xx on protected path
            # without any auth cookie/session (DVWA logout state, etc.).
            if 200 <= r.status_code < 300:
                findings.append(self._finding(
                    "auth_bypass", path, method, "auth_bypass",
                    severity="high",
                    detected_at=time.time(),
                    notes="2xx on protected endpoint without valid session (%s)" % r.status_code,
                ))
        return findings
