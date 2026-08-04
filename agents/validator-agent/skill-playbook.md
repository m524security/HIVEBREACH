---
skill: exploit-poc-verification-deep-aggressive
mitre_attack_id: TA0040
owasp_mapping: []
difficulty: advanced
mode: deep-aggressive
tags: [poc-validation, false-positive-elimination, confidence-scoring, independent-verification, exploit-reliability, evidence-based-verification]
---

# Deep Aggressive Mode Playbook: validator-agent

> Purpose: This playbook is the deep-aggressive operational doctrine for PoC validation and exploit verification. Every claim is replayed in a clean sandbox, every state change independently confirmed, and every failure honestly classified by root cause.

## Phase 1 — Claim Intake and Parsing

1. Receive exploitation claim from exploit-agent, web-exploit-agent, or creed-creds-agent.
2. Parse the claim to extract: target details, exploitation technique, expected outcome, PoC instructions.
3. Identify the vulnerability class and load the matching playbook:
   - skills/penetration-testing/sql-injection.md
   - skills/penetration-testing/xss.md
   - skills/penetration-testing/ssrf.md
   - skills/penetration-testing/ssti.md
   - skills/penetration-testing/xxe.md
   - skills/penetration-testing/command-injection.md
   - skills/penetration-testing/file-inclusion.md
   - skills/penetration-testing/insecure-deserialization.md
   - skills/penetration-testing/idor.md
   - skills/penetration-testing/nosql-injection.md
   - skills/penetration-testing/request-smuggling.md
   - skills/penetration-testing/file-upload.md
   - skills/penetration-testing/csrf.md
   - skills/penetration-testing/cors-misconfiguration.md
   - skills/penetration-testing/open-redirect.md
4. Fetch pre-exploitation state snapshot from state-agent for the target.

## Phase 2 — Sandbox Provisioning

1. Request a clean sandbox environment from sandbox-agent matching the target OS/tooling.
2. Validate the sandbox for tool readiness and network isolation before replay:
   ```bash
   curl -s --max-time 3 http://10.0.2.2   # gateway only, no internet
   ping -c 1 10.0.2.2
   ```
3. Provision the simulated vulnerable service or application (install specific vulnerable version or configure test harness).
4. If the environment cannot match, flag "environment_degraded" in the verification report.

## Phase 3 — PoC Replay

1. Replay the exploitation steps in the sandbox exactly as documented in the PoC. Use the exact commands, payloads, URLs, and parameters.
2. Capture full stdout/stderr and response bodies for evidence:
   ```bash
   ./poc.py > replay.log 2>&1; echo $? >> replay.log
   ```
3. Compare the sandbox exploitation outcome to the original claim:
   - Match: confirm the finding (Track 1 pass)
   - Partial match: flag as likely with notes on discrepancy
   - No match: flag as refuted (Track 1 fail)
4. Apply class-specific success criteria from the skill playbooks:
   - SQLi: data extraction or error differential confirmed
   - XSS: script executes in a real browser context
   - SSRF: internal service reachability or metadata access confirmed
   - SSTI: template evaluation confirmed (7*7=49)
   - XXE: file read or OOB exfiltration confirmed
   - Command injection: command output (id, whoami) or OOB DNS/HTTP callback confirmed

## Phase 4 — Reliability Assessment

1. Run the PoC a minimum of 3 times in clean sandboxes.
2. Compute success rate and output consistency:
   ```python
   import hashlib
   outs = [open(f"replay_{i}.log", "rb").read() for i in range(1, 4)]
   print("deterministic" if len({hashlib.sha256(o).hexdigest() for o in outs}) == 1 else "varying")
   ```
3. Classify each failure by root cause:
   - Environment mismatch: target could not be replicated
   - Missing precondition: PoC requires a condition absent from the target
   - Invalid PoC: instructions incorrect or incomplete
   - Non-determinism: different results per attempt (race/timing)
   - Sandbox evasion: sample detects the sandbox and exits early (apply dynamic-analysis evasion bypass per skills/malware-analysis/dynamic-analysis.md)

## Phase 5 — State-Based Verification (Track 2)

1. After exploitation, request post-exploitation state snapshot from state-agent.
2. Compare pre/post state snapshots to detect state changes:
   - Files created/modified/deleted
   - Processes spawned/terminated
   - Network connections established (listening ports, outbound connections, DNS queries)
   - Registry/configuration changes (Windows)
3. Correlate state changes with the claimed exploitation impact — if state changes match the claim, confidence increases.
4. A file-read exploit must not produce process spawns; an RCE exploit should create files or processes. Inconsistency flags the claim.

## Phase 6 — False Positive Elimination

1. Reject findings whose evidence was manufactured by testing tools:
   - XSS injected via browser devtools, not application input
   - SQLi flagged on response-time noise without data extraction
   - SSRF proven only by DNS artifacts without response evidence
2. Reject version banner manipulation and tool misconfiguration artifacts.
3. Apply compensating-control awareness (WAF/EDR) when a PoC fails in sandbox but claims success in production.

## Phase 7 — Composite Confidence Scoring

Assign the composite confidence score:
- Confirmed: PoC reproduces consistently AND state changes match
- Likely: PoC reproduces but state changes are ambiguous
- Indeterminate: PoC partially reproduces or environment differences prevent clean testing
- Refuted: PoC does not reproduce AND no expected state changes detected

Critical/High findings require deterministic proof: identical outcomes across a minimum of 3 clean replays.

## Phase 8 — Refutation Documentation

For refuted findings, document the reason:
- Environment mismatch
- Missing precondition
- Invalid PoC
- Non-deterministic
Send the refutation notice with detailed reason to the originating agent; never silently drop the finding.

## Phase 9 — Output and Handoff

1. Produce the structured verification report per finding.
2. Send results to report-agent (confirmed findings) and audit-agent (all findings).
3. Send refutation notices to originating agents (exploit-agent, web-exploit-agent, creed-creds-agent).
4. Log every verification decision, sandbox provisioning request, and state comparison result to audit-agent.

## Verification

1. Verification tool itself validated by running against a test suite of known-true and known-false findings.
2. False positive rate below 1%; false negative rate below 5%.
3. Same finding verified twice produces the same confidence score (reproducibility).
4. Sandbox environments validated for tool readiness and network isolation before replay.
5. Critical/High findings backed by deterministic proof (3/3 identical replays).
6. Every refutation documented with an exact root-cause classification.

## Skill Library References
- skills/penetration-testing/sql-injection.md
- skills/penetration-testing/xss.md
- skills/penetration-testing/ssrf.md
- skills/penetration-testing/ssti.md
- skills/penetration-testing/xxe.md
- skills/penetration-testing/command-injection.md
- skills/penetration-testing/file-inclusion.md
- skills/penetration-testing/insecure-deserialization.md
- skills/penetration-testing/idor.md
- skills/penetration-testing/nosql-injection.md
- skills/penetration-testing/request-smuggling.md
- skills/penetration-testing/file-upload.md
- skills/penetration-testing/csrf.md
- skills/penetration-testing/cors-misconfiguration.md
- skills/penetration-testing/open-redirect.md
- skills/malware-analysis/dynamic-analysis.md
