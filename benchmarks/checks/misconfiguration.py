"""Security misconfiguration detection check.

Strategy (from skills/server-security/server-detection.md):
- Probe for default-credential admin panels, missing security headers,
  directory listing, and exposed server/version banners.
- All signals are deterministic HTTP fingerprints.
"""
from __future__ import annotations

import time

from ..scoring import Finding
from . import BaseCheck

CHECK_CLASS = "MisconfigurationCheck"

REQUIRED_HEADERS = ["x-frame-options", "content-security-policy", "strict-transport-security"]

DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "12345"),
]


class MisconfigurationCheck(BaseCheck):
    name = "misconfiguration"
    skill_playbook = "skills/server-security/server-detection.md"
    mitre = "T1195"
    owasp = "A05:2021"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.probes = [
            "/phpmyadmin/",
            "/admin/login.php",
            "/login",
        ]

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        # 1) Missing security headers on the app root
        try:
            r = self.session.get(self.base_url + "/", timeout=self.timeout)
            if r is not None:
                missing = [h for h in REQUIRED_HEADERS if h not in r.headers]
                if missing:
                    findings.append(self._finding(
                        "misconfiguration", "/", "GET", "misconfiguration",
                        severity="low",
                        detected_at=time.time(),
                        notes="missing security headers: %s" % ", ".join(missing),
                    ))
        except Exception:
            pass

        # 2) Directory listing (Apache/IIS expose indexes)
        for path in ["/assets/", "/images/", "/js/"]:
            try:
                r = self.session.get(self.base_url + path, timeout=self.timeout)
            except Exception:
                continue
            if r is not None and "Index of" in r.text:
                findings.append(self._finding(
                    "misconfiguration", path, "GET", "misconfiguration",
                    severity="medium",
                    detected_at=time.time(),
                    notes="directory listing exposed",
                ))
                break

        # 3) Default credentials on an admin login panel
        for path, user, pw in [(p, *c) for p in self.probes for c in DEFAULT_CREDS]:
            try:
                r = self.session.post(self.base_url + path,
                                      data={"username": user, "password": pw},
                                      timeout=self.timeout)
            except Exception:
                continue
            if r is not None and ("Location" in r.headers or r.status_code == 200):
                # Heuristic: a successful login redirect or 200 on a login
                # endpoint with default creds indicates a weak-auth panel.
                if "login" not in r.url or r.status_code == 200:
                    findings.append(self._finding(
                        "misconfiguration", path, "POST", "misconfiguration",
                        severity="medium",
                        detected_at=time.time(),
                        notes="default credentials %s/%s accepted" % (user, pw),
                    ))
                    break

        return findings
