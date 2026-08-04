# Security Standards — ECC Common Rule

## Scope

This rule defines mandatory security practices for all code, configurations, and operations within the HiveBreach framework.

## Rules

### 1. No Secrets in Code
- Never commit API keys, tokens, passwords, or private keys to version control
- Use environment variables for all secrets
- Use `.env` files (gitignored) or a vault agent for local development
- Run `security/sanitizer.py` pre-commit to strip any leaked secrets

### 2. Input Validation
- Validate all external inputs at system boundaries
- Use allow-lists over block-lists where possible
- Sanitise file paths to prevent directory traversal
- Validate and quote shell command arguments

### 3. Least Privilege
- Agents operate with the minimum permissions required
- File system access scoped to project directory
- Network access restricted to authorised targets (enforced by scope-agent)
- No persistent elevated privileges

### 4. Audit Logging
- All agent actions logged via audit-agent with HMAC chain
- Logs include: timestamp, agent_id, action, target, result
- Log integrity verifiable via chain-of-custody validation

### 5. Dependency Management
- All dependencies pinned to specific versions
- Weekly CVE scan via `security/cve_tracker.py`
- CRITICAL and HIGH CVEs block pipeline deployment

### 6. Sandboxing
- All exploitation activities run in isolated Docker containers
- Payloads validated in sandbox before operational use
- Sandbox snapshots taken pre- and post-execution

## Enforcement

Violations are detected by AgentShield runtime monitoring and reported to the audit-agent. CRITICAL violations halt all active operations.
