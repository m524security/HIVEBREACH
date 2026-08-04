# HIVEBREACH Detection Benchmark

Measures the framework's **detection / exploitation performance** against a
stack of known-vulnerable Docker targets. Produces a scored report (0–100)
built from a per-vulnerability confusion matrix and derived metrics.

## Quick Start

```bash
# Prerequisites: Python >= 3.10, Docker, pip install requests pyyaml
python benchmarks/run_benchmark.py

# Run a single target without touching Docker (assume already up)
docker compose -f benchmarks/docker-compose.yml up -d
python benchmarks/run_benchmark.py --targets dvwa --no-containers

# Dry run (validates config + wiring without sending traffic)
python benchmarks/run_benchmark.py --dry-run --no-containers
```

Reports are written to `reports/benchmarks/benchmark-report.{md,json}`.

## Targets

| Target | Container | URL | Purpose |
|--------|-----------|-----|---------|
| dvwa | `bench-dvwa` | http://127.0.0.1:8080 | PHP/MySQL web app (SQLi, XSS, CMDi, LFI, auth) |
| juice-shop | `bench-juice-shop` | http://127.0.0.1:3000 | Node.js storefront (SQLi, XSS, unauth API) |
| webgoat | `bench-webgoat` | http://127.0.0.1:8081/WebGoat | Java lessons (SQLi, XXE, auth bypass) |
| vampi | `bench-vampi` | http://127.0.0.1:5000 | Flask REST API (unauth API, IDOR) |
| metasploitable | `bench-metasploitable` | ssh 2222 / http 8082 / ftp 2121 | network/service target (extension) |

All containers run on the `hivebreach-bench` Docker network. **These are
intentionally vulnerable containers — run them only on an isolated lab host,
never on an exposed network.**

## Ground Truth

`benchmarks/ground-truth/<target>.json` declares the known vulnerabilities per
target: id, class, severity, endpoint, parameter, MITRE ATT&CK id, OWASP 2021
category, and which checks can detect it.

| Target | Vulnerabilities |
|--------|-----------------|
| dvwa | 6 (SQLi, XSS, CMDi, LFI, auth bypass, misconfig) |
| juice-shop | 5 (SQLi, XSS, unauth API, store XSS, misconfig) |
| webgoat | 4 (SQLi, XXE, auth bypass, misconfig) |
| vampi | 4 (unauth API, SQLi, IDOR, PII exposure) |

## Detection Checks

`benchmarks/checks/` implements one module per vulnerability class, mapped to
the corresponding skill playbook in `CHECK_REGISTRY`:

| Check | Skill Playbook | Technique |
|-------|---------------|-----------|
| sqli | `skills/penetration-testing/sql-injection.md` | boolean + time-based differentials |
| xss | `skills/penetration-testing/xss.md` | benign marker reflection |
| command_injection | `skills/penetration-testing/command-injection.md` | marker echo + sleep timing |
| file_inclusion | `skills/penetration-testing/file-inclusion.md` | `/etc/passwd` traversal signature |
| xxe | `skills/penetration-testing/xxe.md` | entity expansion of `/etc/passwd` |
| auth_bypass | `skills/api-security/bola-bfla.md` | 2xx on protected paths w/o session |
| unauth_api | `skills/api-security/bola-bfla.md` | sensitive data without token |
| misconfiguration | `skills/server-security/server-detection.md` | missing headers / listing / default creds |
| ssrf | `skills/penetration-testing/ssrf.md` | OOB callback (stub until OOB image added) |

Checks are conservative by design: they fire only on deterministic evidence
(reflected markers, timing differentials, signature content), matching the
framework's **no-PoC-no-finding** validation rule.

## Scoring Model

`benchmarks/scoring.py` computes, per benchmark run:

- **TP / FN / FP / TN** confusion matrix (TN is not directly observable in
  active scans and is reported as `None`).
- **precision** = TP / (TP + FP)
- **recall** = TP / (TP + FN), plus a **severity-weighted** variant where
  missing a Critical (1.0) hurts more than a Low (0.5).
- **F1** = harmonic mean of precision and recall.
- **time-to-find**: average seconds per detected vuln; penalized past the
  budget (`scoring.time_to_find_budget_s`).
- **exploit_success**: fraction of detected vulns with a working exploit PoC.
- **chain_depth**: max distinct vuln classes detected on a single target
  (measures multi-stage attack chaining).

Final score (0–100) is a weighted blend configured in `config.yaml`:

| Metric | Weight |
|--------|--------|
| precision | 0.30 |
| recall (severity-weighted) | 0.35 |
| F1 | 0.15 |
| exploit_success | 0.15 |
| time bonus | 0.05 |

## Known Limitations

- SSRF requires an OOB callback listener; the check is a documented stub until
  a `bench-oob` service is added to the compose stack.
- Ground truths cover web-app and API classes only; metasploitable is included
  for future network/service extension.
- Checks run sequentially per target (configurable `checks.max_parallel_checks`).
- WebGoat's lesson flow requires login/registration; the current checks target
  its public lesson endpoints.

## Extending

1. Add a ground-truth entry for a new vuln → `benchmarks/ground-truth/<t>.json`.
2. Implement a check → `benchmarks/checks/<class>.py` (subclass `BaseCheck`).
3. Register it in `CHECK_REGISTRY` in `benchmarks/checks/__init__.py`.
4. Run `python benchmarks/run_benchmark.py --dry-run` to validate wiring.

See also `tools/gap-report.py` for MITRE ATT&CK technique coverage and
`tools/self-learn.py` for feeding confirmed findings back into the lessons
library.
