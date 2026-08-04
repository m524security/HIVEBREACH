# Quality Gate Criteria — ECC Common Rule

## Scope

This rule defines the minimum quality thresholds that all work products must satisfy before being accepted into the codebase.

## Criteria

### 1. Code Review
- All code must be reviewed by at least one agent specialised in the target language
- Zero unresolved review comments
- No `TODO`, `FIXME`, `HACK`, or `XXX` comments in production code
- Linting must pass with zero errors (warnings allowed at discretion)

### 2. Test Coverage
- Minimum line coverage: **80%** for Python, TypeScript, Java
- Minimum line coverage: **75%** for Go, Rust
- All critical paths must have at least one test
- Regression tests for any fixed bugs

### 3. Documentation
- Public API must have docstrings (Python) or TSDoc/JSDoc (TypeScript)
- README must be updated if behaviour or usage changes
- CHANGELOG entry required for user-facing changes

### 4. Type Safety
- Python: mypy strict mode (or pyright) with zero errors
- TypeScript: strict mode with zero errors
- Rust: zero compiler warnings
- Go: zero vet warnings

### 5. Security
- Zero secrets in committed code (pass AgentShield secret scan)
- All user inputs validated and sanitised
- No dependency with known CRITICAL or HIGH CVE

## Enforcement

These criteria are enforced by the `/quality-gate` command. A FAIL grade blocks merging.

## Exceptions

Exceptions require explicit approval documented in the commit message with `QUALITY-EXEMPT: <reason>`.
