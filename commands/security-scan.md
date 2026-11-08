# /security-scan — ECC Security & Dependency Audit

## Overview

The `/security-scan` command runs AgentShield security checks, dependency CVE scans, and configuration audits against the current project.

## Usage

```
/security-scan [--scope <project|system|all>] [--report <json|markdown|html>]
```

## Scans

| Scan | Description |
|------|-------------|
| AgentShield | Runtime agent behaviour monitoring & dangerous pattern detection |
| Dependency CVE | Check installed packages against known CVEs |
| Config audit | Validate all config files against schema |
| Secret scan | Detect hardcoded secrets, API keys, tokens |
| Permission audit | Check file permissions and access controls |

## Thresholds

| Severity | Action |
|----------|--------|
| CRITICAL | Blocks pipeline |
| HIGH | Blocks pipeline |
| MEDIUM | Warning logged |
| LOW | Informational |

## Output

```
AgentShield scan complete:
  ★ Dependency CVE:  3 alerts (0 critical, 1 high, 2 medium)
  ★ Secret scan:     0 secrets found  CLEAN
  ★ Config audit:    5/5 files valid  PASS
  ★ Permissions:     All nominal       PASS
  Result:            GATE BLOCKED (1 high CVE)
```

## See Also

- `security/agent_shield.py` — Runtime security monitoring
- `security/sanitizer.py` — Input/output sanitisation
- `security/cve_tracker.py` — CVE monitoring engine
