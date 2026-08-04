"""SSRF detection check (from skills/penetration-testing/ssrf.md).

Design note (honesty per R2 / no-PoC-no-finding):
A reliable SSRF proof requires an out-of-band (OOB) callback listener the
*container* can reach. The benchmark stack runs containers on a bridge
network with only published ports exposed, so a host-bound listener is not
reachable from inside the target container.

Until an OOB listener image is added to docker-compose.yml (service
`bench-oob` with a published port), this check intentionally returns no
findings. Adding a false positive here would corrupt the precision metric.

Extension point:
    1. Add an `bench-oob` service exposing e.g. port 9999 on the bridge net.
    2. Configure `callback_url: "http://bench-oob:9999/probe/<token>"`.
    3. In `run()`, inject `callback_url` into candidate URL parameters and
       mark `exploit_success=True` when the listener records a hit.
"""
from __future__ import annotations

from ..scoring import Finding
from . import BaseCheck

CHECK_CLASS = "SSRFCheck"


class SSRFCheck(BaseCheck):
    name = "ssrf"
    skill_playbook = "skills/penetration-testing/ssrf.md"
    mitre = "T1190"
    owasp = "A10:2021"

    # e.g. callback_url = "http://bench-oob:9999/probe" set by the harness
    # once the OOB service exists.
    callback_url: str = ""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.params = ["url", "uri", "path", "redirect", "next"]

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        if not self.callback_url:
            # No OOB capability configured -> cannot produce a valid finding.
            return findings
        for param in self.params:
            url = f"{self.base_url}/?{param}={self.callback_url}"
            try:
                r = self.session.get(url, timeout=self.timeout)
            except Exception:
                continue
            # Detection of a confirmed OOB hit is handled by the harness via
            # the listener log; this stub leaves the hook for that integration.
            if r is not None and self.callback_url in r.text:
                findings.append(self._finding(
                    "ssrf", "/", "GET", "ssrf",
                    severity="high",
                    detected_at=0.0,
                    notes="SSRF callback URL reflected/requested",
                ))
        return findings
