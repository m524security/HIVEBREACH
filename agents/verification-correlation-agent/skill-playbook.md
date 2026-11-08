---
skill: verification-correlation-deep-aggressive
mitre_attack_id: TA0040
owasp_mapping: []
difficulty: advanced
mode: deep-aggressive
tags: [finding-correlation, deduplication, attack-path-chaining, evidence-cross-validation, impact-aggregation, mitre-attack-mapping, adversarial-chaining]
---

# Deep Aggressive Mode Playbook: verification-correlation-agent

> Purpose: This playbook is the deep-aggressive operational doctrine for finding correlation and verification. Every finding is normalized, deduplicated, cross-validated against evidence, and chained into adversarial attack paths with MITRE ATT&CK mapping before it reaches the report.

## Phase 1 — Collection & Normalization

1. **Findings Collection** — Gather all findings from upstream agents. Parse each into a normalized format: finding ID, agent source, target, vulnerability type, severity, raw confidence, evidence.
2. Normalize fields across agents so comparisons are meaningful: consistent target notation, CVE format, and severity bands.
3. Cross-reference the reconnaissance inventory from recon-agent to confirm every finding's target is in scope.

## Phase 2 — Multi-Source Correlation

1. Correlate findings across agents by shared attributes:
   - Same endpoint + same vulnerability class
   - Same host + same CVE
   - Same credential + same target service
2. Correlate exploit results to their parent vulnerability findings to confirm end-to-end chains.
3. Flag single-source findings for the strongest evidence requirement.
4. Reference the artifact-to-technique mapping in skills/dfir/skill-playbook.md when correlating state evidence.

## Phase 3 — Duplicate Detection

1. Identify redundant findings across agents. Use matching criteria: same endpoint + same vulnerability class = probable duplicate. Same host + same CVE = probable duplicate.
2. Merge duplicates, keeping the best evidence from each source.
3. Record merged findings as `duplicate_of` references; never delete the original records.

## Phase 4 — Contradiction Detection

1. Compare findings for logical contradictions. Example: Agent A reports "TLS 1.3 supported" while Agent B reports "Only TLS 1.0 supported." Flag for manual resolution.
2. Investigate both sides independently: re-check configs, versions, and evidence.
3. Determine which is correct and why the error occurred; feed the root cause back to the erring agent.
4. Irresolvable contradictions are flagged `disputed` and escalated to scheduler-agent.

## Phase 5 — Confidence Scoring

1. **Evidence Weighting** — Assign weights to each evidence type:
   - Automated scanner output: 1 point
   - Manual reproduction: 3 points
   - Exploit PoC execution: 5 points
   - Independent verification by multiple agents: +2 points per agent
2. **Confidence Calculation** — Calculate final confidence:
   - 6+ points and no contradictions: `confirmed`
   - 3-5 points: `likely`
   - 1-2 points: `tentative`
   - 0 points or contradiction: `disputed`
3. **Severity Adjustment** — Adjust CVSS score based on:
   - Chained impact (multiple findings together increase severity)
   - Actual exploitability (theoretical vs. practical)
   - Compensating controls (WAF, EDR, segmentation)

## Phase 6 — State Verification

1. **Sandbox Reproduction** — For high-severity findings, provision a sandbox instance and verify the vulnerable state exists. Do not exploit — just verify.
2. **Evidence Inspection** — Manually inspect evidence files, screenshots, and request/response pairs. Verify the evidence matches the claim.
3. **Config Verification** — For configuration findings (open S3 bucket, default credentials), verify the configuration still exists at scan time.
4. Verify evidence integrity per skills/dfir/skill-playbook.md: timestamps within scan window, correct host metadata, hashes matching the audit trail.

## Phase 7 — Exploit Verification

1. **PoC Review** — Review the exploit PoC from exploit-poc-agent. Verify it targets the described vulnerability.
2. **Independence Check** — If possible, run the PoC in a separate environment to verify it works independently of the original developer's setup.
3. **Impact Validation** — Assess whether the exploit actually achieves the claimed impact. A PoC that pops a calculator vs. a PoC that exfiltrates data have different impacts.
4. Apply the class-specific success criteria and false-positive traps from skills/penetration-testing/*.md.

## Phase 8 — Chain Detection & Attack Path Chaining

1. **Chain Detection** — Identify findings that can be chained together. Separate chained findings from standalone findings.
2. **Adversarial ordering** — Order hops as an adversary would execute them, not as agents reported them:
   - Recon finding -> vuln finding -> exploit PoC -> post-exploitation artifact
   - IDOR -> stored XSS -> session theft -> account takeover
3. Verify each hop's prerequisite is satisfied by the prior hop; return any chain with unverified preconditions.
4. Map each hop to MITRE ATT&CK technique/sub-technique IDs.
5. Estimate the end-state impact of the full chain and aggregate it.

## Phase 9 — Impact Aggregation

1. Aggregate impact across the chain: score the chain at its highest end-state impact, not the sum of individual hops.
2. Uplift enabling hops (low-severity findings that unlock critical access).
3. Record the aggregated severity and chained-impact rationale in the master finding.
4. Emit each chain as a distinct master finding with its own chain_id for the report-agent.

## Phase 10 — False Positive Registry

1. Tag and retain every false positive with the exact reason:
   - Version banner manipulation
   - Tool misconfiguration
   - Timeout artifacts
   - WAF interference
   - Tool-manufactured evidence (devtools injection is not application XSS)
2. Never delete a false positive — retain it for reference and regression comparison.
3. If a pattern of false positives from a specific agent/tool emerges, send a quality improvement report to scheduler-agent.

## Phase 11 — Master List Construction

1. **Deduplication** — Merge duplicate findings. Keep the best evidence from each source.
2. **Master List** — Produce the master findings list sorted by severity and confidence.
3. Verify the final count: findings_received - duplicates_removed - false_positives = final_findings_count.
4. Send the master list to report-agent.

## Verification

1. Two-track verification required: state-verified AND exploit-verified for every high-severity finding.
2. Evidence integrity: hashes match audit trail; timestamps within scan window; metadata consistent.
3. False positives tagged and retained with documented reasoning.
4. Attack paths adversarially ordered with verified prerequisites and MITRE ATT&CK mapping.
5. Impact aggregation documented per chain; master list count reconciles exactly.

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
- skills/dfir/skill-playbook.md
- skills/dfir/incident-triage.md
