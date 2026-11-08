"""SQL injection detection check (from skills/penetration-testing/sql-injection.md).

Strategy: probe candidate endpoints with boolean and time-based payloads and
look for deterministic differentials (page change on 1=1 vs 1=2, or a
measurable sleep delay). Requires a requests.Session that may carry auth
cookies (e.g. DVWA login).
"""
from __future__ import annotations

import time
from typing import Any

from ..scoring import Finding
from . import BaseCheck

CHECK_CLASS = "SQLiCheck"

# (label, payload) pairs. Boolean comparison first, error/time probes second.
BOOLEAN_PROBES = [
    ("true", "' AND 1=1 -- "),
    ("false", "' AND 1=2 -- "),
    ("true2", "1 AND 1=1"),
    ("false2", "1 AND 1=2"),
]

TIME_PAYLOADS = [
    ("' OR SLEEP(3) -- ", "SLEEP"),
    ("' OR pg_sleep(3) -- ", "pg_sleep"),
    ("1 AND SLEEP(3)", "SLEEP"),
]


class SQLiCheck(BaseCheck):
    name = "sqli"
    skill_playbook = "skills/penetration-testing/sql-injection.md"
    mitre = "T1190"
    owasp = "A03:2021"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.params = ["id", "q", "search", "name", "page", "column", "username"]
        self.paths = [
            "/vulnerabilities/sqli/",
            "/rest/products/search?q={P}",
            "/users/v1/{P}",
            "/vulnerabilities/sqli_blind/",
        ]

    # ------------------------------------------------------------------
    def _get(self, url: str) -> Any:
        try:
            return self.session.get(url, timeout=self.timeout)
        except Exception:
            return None

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        # 1) Endpoint-specific boolean tests
        for path in self.paths:
            for param in self.params:
                if "{P}" in path:
                    url_true = self.base_url + path.replace("{P}", param + BOOLEAN_PROBES[0][1])
                    url_false = self.base_url + path.replace("{P}", param + BOOLEAN_PROBES[1][1])
                else:
                    url_true = f"{self.base_url}{path}?{param}={BOOLEAN_PROBES[0][1]}"
                    url_false = f"{self.base_url}{path}?{param}={BOOLEAN_PROBES[1][1]}"
                r_true = self._get(url_true)
                r_false = self._get(url_false)
                if r_true and r_false and r_true.status_code == r_false.status_code:
                    if len(r_true.text) != len(r_false.text):
                        findings.append(self._finding(
                            "sqli", path, "GET", "sqli",
                            severity="critical",
                            detected_at=time.time(),
                            notes="boolean-based differential on parameter %s" % param,
                        ))
                        break

        # 2) Time-based probe against a known injectable-looking endpoint
        t0 = time.time()
        probe_url = f"{self.base_url}/vulnerabilities/sqli/?id={TIME_PAYLOADS[0][0]}&Submit=Submit"
        r = self._get(probe_url)
        elapsed = time.time() - t0
        if r is not None and elapsed >= 2.5:
            findings.append(self._finding(
                "sqli", "/vulnerabilities/sqli/", "GET", "sqli",
                severity="critical",
                detected_at=time.time(),
                notes="time-based SQLi (elapsed %.1fs)" % elapsed,
            ))

        return findings
