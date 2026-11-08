# /quality-gate — ECC Verification & Grading

## Overview

The `/quality-gate` command runs all configured verification checks against the current work product and produces a pass/fail grade with detailed metrics.

## Usage

```
/quality-gate [--scope <all|changed|targeted>] [--threshold <0.0-1.0>]
```

## Checks Run

| Check | Description | Weight |
|-------|-------------|--------|
| Code review | Static analysis, linting, style conformance | 25% |
| Test coverage | Coverage percentage against configured target | 25% |
| Documentation | Docstrings, README updates, changelog entry | 15% |
| Type safety | TypeScript/Python type check pass | 15% |
| Security scan | AgentShield dependency and secret scan | 10% |
| Integration tests | End-to-end validation suite | 10% |

## Grading

| Grade | Score | Threshold |
|-------|-------|-----------|
| PASS | >= 0.85 | All critical checks pass |
| CONDITIONAL | >= 0.70 | Minor issues, non-blocking |
| FAIL | < 0.70 | Blocking issues found |

## Output

```
Quality gate results: PASS (0.92)
  - Code review:    PASS (0.95)
  - Test coverage:  PASS (0.88)  [target: 80%]
  - Documentation:  PASS (1.00)
  - Type safety:    PASS (1.00)
  - Security scan:  PASS (0.85)
  - Integration:    PASS (0.90)
```

## See Also

- `rules/common/quality-gate.md` — Quality gate criteria definitions
- `hooks/` — Verification hooks run during quality gate
