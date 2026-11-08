---
skill: risk-assessment-and-scoring-deep-aggressive
mitre_attack_id: TA0040
owasp_mapping: [A06, A09]
difficulty: advanced
mode: deep-aggressive
tags: [risk-scoring, cvss, ssvc, epss, impact-assessment, priority-ranking, vulnerability-aggregation, business-impact]
---

# Deep Aggressive Mode Playbook: risk-agent

> Purpose: This playbook is the deep-aggressive operational doctrine for risk scoring and prioritization. Every score is computed from a full CVSS vector, adjusted by SSVC decision logic, EPSS probability, threat intelligence context, and asset criticality — and every input is traceable to source evidence.

## Phase 1 — Load and Validate Input

Reference: skills/cve-staging/cve-analysis.md

1. Load verified findings from analyzer-agent with full technical metadata.
2. Validate the schema: every finding must carry title, target, affected component, CVE (if any), exploit prerequisites, and evidence links.
3. Retrieve asset criticality ratings from scope-agent for each affected host/endpoint; if unavailable, assume medium and flag the gap.
4. Load the current threat intelligence context for the engagement sector.

## Phase 2 — CVE Context Aggregation

For each CVE-mapped finding, gather authoritative context:
```bash
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-XXXX-XXXX" | jq '.vulnerabilities[0].cve.metrics'
curl -s "https://api.first.org/data/v1/epss?cve=CVE-XXXX-XXXX" | jq '.data[0] | {cve, epss, percentile}'
curl -s "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" | jq -r '.vulnerabilities[].cveID' | grep CVE-XXXX
searchsploit -c CVE-XXXX-XXXX
msfconsole -q -x "search cve:XXXX"
```
Record the data date for all external intel; never score with stale KEV/EPSS data.

## Phase 3 — CVSS Base Score Calculation

1. Calculate the CVSS v4.0 base score for each finding (attack vector, complexity, attack requirements, privileges, user interaction, confidentiality/integrity/availability impact).
2. Compute the parallel CVSS v3.1 vector for legacy/compliance consumers.
3. Record the full vector string, never just the numeric score:
   - `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H`
   - `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
4. Map to severity band: None 0.0, Low 0.1-3.9, Medium 4.0-6.9, High 7.0-8.9, Critical 9.0-10.0.

## Phase 4 — Temporal Score Adjustment

1. Apply exploit maturity (E): Unproven -> PoC -> Functional -> High.
   - Public PoC: PoC/Functional
   - Metasploit module: Functional
   - Weaponized exploit kit integration: High
2. Apply remediation level (RL): Official fix > Temporary fix > Workaround > Unavailable.
3. Apply report confidence (RC): reasonable vs confirmed (multi-source).
4. Record the temporal vector and the temporal score.

## Phase 5 — SSVC Decision Tree

Reference: skills/cve-staging/cve-analysis.md section 2.4

Run the SSVC decision tree for every finding:
- Exploitation: None / PoC / Active (KEV-listed findings are Active)
- Technical Impact: Partial / Total
- Automatability: No / Yes
- Mission Prevalence: Minimal / Support / Essential
- Public Well-Being: Minimal / Material / Irreversible

Map to action SLA:
- Track: normal patch cycle (90 days)
- Track*: next patch window (60 days)
- Attend: escalate and accelerate (14 days)
- Act: immediate mitigation (48 hours)

## Phase 6 — EPSS Integration

1. Pull the EPSS score and percentile: `curl -s "https://api.first.org/data/v1/epss?cve=CVE-XXXX" | jq '.data[0] | {cve, epss, percentile}'`.
2. Treat EPSS > 0.5 as high-priority signal when combined with exposure.
3. Record EPSS alongside the score; never use it as standalone severity.

## Phase 7 — Environmental Score Adjustment

1. Apply confidentiality/integrity/availability requirements based on asset criticality from scope-agent.
2. High-CR for PII-bearing databases; high-AR for revenue services.
3. Produce the environmental score; it may exceed or undercut the base score.

## Phase 8 — Threat Intelligence Context Adjustment

1. Adjust likelihood using threat intelligence context — is this vulnerability actively exploited in the wild?
2. Weight factors:
   - Active ransomware campaign use: +0.3 likelihood
   - Mass-scanning on the internet (Shodan/Censys): +0.2
   - APT toolset integration: +0.2
   - Sector-specific elevated threat: +0.1
   - Effective compensating controls: -0.2 to -0.4
3. Cite specific sources (CISA KEV, Mandiant, vendor advisories) for every adjustment.

## Phase 9 — Likelihood/Impact Matrix

Combine likelihood and impact into the final risk rating:
| Impact / Likelihood | Low | Medium | High |
|---|---|---|---|
| Low | Low | Low | Medium |
| Medium | Low | Medium | High |
| High | Medium | High | Critical |

Compute the final risk score: Risk = Likelihood x Impact, normalized and combined with the composite engine output.

## Phase 10 — Vulnerability Aggregation

1. Group findings that chain into a single attack path; score the chain at its highest impact, not the sum of hops.
2. Deduplicate identical findings across agents before scoring.
3. Aggregate multiple CVEs on one asset to the highest chained severity.
4. Adjust low-severity enablers upward when they unlock critical access; document the rationale.

## Phase 11 — Risk Register Construction

1. Map each finding to a risk treatment (accept, mitigate, transfer, avoid) with rationale.
2. Produce prioritized risk register sorted by final risk score descending.
3. Write risk register and scoring evidence to findings archive.
4. Escalate critical-risk findings (score >= 9.0 or SSVC Act) via priority channel to scheduler-agent.

## Phase 12 — Verification

1. Random sample (minimum 10%) validated against the official CVSS v4.0 calculator web interface.
2. Temporal adjustments cross-referenced with current CVE status and exploit-db entries.
3. Environmental adjustments cross-referenced with the asset criticality register.
4. Risk register verified to contain all input findings with no omissions or additions.
5. Scoring rationale auditable — every component traced to a specific input or rule.
6. KEV/EPSS data freshness verified (no stale scores in the register).

## Skill Library References
- skills/cve-staging/cve-analysis.md
- skills/threat-intel/skill-playbook.md
