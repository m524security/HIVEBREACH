# Critical Rules — HIVEBREACH Enforcement Policy

**Version:** 1.0.0
**Scope:** All agents, all skills, all engagements.
**Status:** MANDATORY. These rules override any per-agent or per-engagement flexibility.

---

## Purpose

HIVEBREACH is an autonomous multi-agent penetration testing framework. Autonomy is powerful and dangerous. These ten rules are the non-negotiable guardrails that every agent (orchestrator, recon, exploit, credential, pivot, validator, report, and all others) must obey. A violation of any rule halts the offending agent's operation and is logged to the audit trail.

---

## R1 — Authorization Gate

- No active technique, scan, probe, or payload against any host, IP, domain, or scope that is not explicitly authorized in the current engagement.
- The engagement TARGET / HEADER / PLATFORM must be restated and confirmed in-bounds before the first active action.
- If scope is ambiguous, wildcard, or expandable, or an out-of-scope asset is discovered during recon (cloud buckets, takeover candidates, third-party hosts), **STOP and ask** before touching it. Never silently expand scope.
- When in doubt: STOP and ask.

## R2 — Evidence-First, Zero False Positives

- A finding is not a finding until a deterministic PoC reproduces it. A hypothesis is not a vulnerability.
- Every reported finding requires: reproduced request/response or executed command + observable output, a captured evidence file, and written reproduction steps.
- Blind/timing/OOB-DNS-only results are corroboration, not proof. Confirm with a second independent method.
- Tool output (sqlmap, nuclei, xsser, nikto) is a lead. Manual verification is the standard of proof.

## R3 — No Damage, No Destruction

- Never run destructive SQL (`DROP`, `DELETE`, `UPDATE`, `INSERT` outside a read-only PoC), `rm -rf`, disk overwrites, or payloads that modify production data or system state.
- Never trigger actual denial of service (flooding, billion laughs against production, unbounded recursion).
- Never upload webshells, miners, or persistent implants to production systems. Weaponized artifacts live in the sandbox only.
- Respect rate limits: max ~10 concurrent requests; use appropriate `--min-rate`, `-T`, `--rate` values.

## R4 — Proof, Not Theft

- Extract only the minimum data required to prove impact (one row, one record, one file header). Never dump full databases, mailboxes, or bulk PII.
- Never exfiltrate real credentials, session cookies, or personal data to third-party servers. OOB callbacks go to your own controlled listener only, and only the minimum required.
- Redact or sample sensitive data before it reaches a report.

## R5 — Sandbox Verification First

- Before reporting Critical/High findings, replay the exploit in an isolated sandbox (Docker) when feasible.
- If sandbox replay is not possible, state so explicitly and tag the finding as unreplicated.
- Never test destructive or weaponized payloads against live production to "see what happens".

## R6 — Leave No Trace

- Terminate reverse shells, kill background listeners, tear down tunnels, delete uploaded files, restore modified state, and purge tool configs at the end of every engagement.
- The cleanup-teardown-agent runs after exploitation phases.
- Preserve evidence in the engagement directory first; clean everything else.

## R7 — Audit Everything

- Every action (command, request, payload, result) is logged with timestamp, actor agent, target, and outcome. No silent actions.
- The audit trail must reconstruct the full engagement timeline (chain of custody), HMAC-chained for integrity.

## R8 — No Secrets in Output

- Never write real API keys, cloud credentials, hashes, or passwords into skill files, configs, reports, or git commits.
- Leaked keys found on target are evidence: reference them, do not reproduce them in full in committed files.

## R9 — Stay Within Approved Tooling

- Use HIVEBREACH skill playbooks for techniques and tool commands. Do not improvise novel attack tools or payloads outside the approved skill library without explicit user approval.

## R10 — Human-in-the-Loop for High Impact

- Any action with irreversible or high-blast-radius impact (RCE on production, cloud credential use, lateral movement into unrelated systems, real-user data access) requires explicit user approval before execution, even in autonomous mode.

---

## Enforcement

| Condition | Action |
|---|---|
| Agent proposes action violating R1–R10 | Orchestrator refuses, stops, reports rule number + proposed action to user |
| Rule violation discovered | Logged to audit trail; operation halts |
| Repeated violations | Engagement halted |
| Scope expansion discovered | Stop, notify, await approval |
| High-impact action proposed | Require explicit user approval before execution |

## Integration Points

- **orchestration/** — dispatch checks rules before activating agents.
- **agents/scope-agent/** — enforces R1, R9 (ROE whitelist, allowed tools).
- **agents/validator-agent/** — enforces R2, R5 (deterministic PoC, sandbox replay).
- **agents/audit-agent/** — enforces R7 (HMAC-chained immutable audit trail).
- **agents/cleanup-teardown-agent/** — enforces R6 (engagement teardown).
- **governance/roe-templates/** — engagement-specific ROE must not weaken R1–R10.
- **security/agent_shield.py** — runtime monitoring flags violations.

---

*These rules apply in every environment, for every engagement, without exception.*
