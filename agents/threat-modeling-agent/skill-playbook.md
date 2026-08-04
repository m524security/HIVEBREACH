---
skill: threat-modeling-deep-aggressive
mitre_attack_id: [T1591, T1593, T1596]
owasp_mapping: [AST-1, AST-2]
difficulty: advanced
mode: deep-aggressive
tags: [stride, dread, threat-dragon, data-flow-diagrams, attack-surface-enumeration, kill-chain-mapping, mitre-attack-navigator, risk-prioritization]
---

# Deep Aggressive Mode Playbook: threat-modeling-agent

> Purpose: This playbook is the deep-aggressive operational doctrine for threat modeling and attack surface mapping. The model assumes the architecture is broken, enumerates every entry point, scores with DREAD, maps to the kill chain and ATT&CK Navigator, and produces a prioritized testing guide for downstream agents.

## Phase 1 — Architecture Deconstruction

Reference: skills/network-security/service-enumeration.md (attack surface context)

1. **Data Flow Diagram Construction** — Read application architecture documentation. Identify external entities, processes, data stores, and data flows. Draw data flow diagram with trust boundaries.
   - Mermaid: `flowchart TD` with `zone` groupings for trust boundaries.
   - Threat Dragon: model each element with attached threat entries.
2. **Component Inventory** — List all application components: web servers, application servers, databases, message queues, caches, third-party services, authentication providers, APIs.
3. **Trust Boundary Identification** — Mark trust boundaries between components. Identify where data crosses from an untrusted zone (internet, user device) to a trusted zone (server, internal network).
4. **Attack Surface Enumeration** — Enumerate every entry point:
   - Exposed ports and protocols (from recon/port scan data)
   - Public web endpoints, APIs, admin consoles
   - Third-party and SSO integrations
   - File import/export and document processing paths
   - Cloud identities, service accounts, and managed identities
   - Supply chain surfaces (dependencies, build pipeline, artifact registry)
5. **Assumption Register** — Log every assumption made from incomplete documentation; flag for downstream verification.

## Phase 2 — STRIDE Threat Analysis

Apply STRIDE per component and per data flow:

1. **Spoofing** — Identify components where identity verification is critical. List threats related to credential theft, session hijacking, authentication bypass, OAuth/SSO confusion, and spoofed identities.
2. **Tampering** — Identify data flows and stores where data integrity is critical. List threats related to request modification, data manipulation, parameter tampering, and signed-data bypass.
3. **Repudiation** — Identify actions that must be non-repudiable. List threats related to logging gaps, missing audit trails, and cryptographic signature weaknesses.
4. **Information Disclosure** — Identify sensitive data flows and stores. List threats related to data leakage, improper access controls, encryption gaps, and cloud metadata exposure.
5. **Denial of Service** — Identify components with resource constraints. List threats related to rate limiting, resource exhaustion, algorithmic complexity attacks, and dependency exhaustion.
6. **Elevation of Privilege** — Identify privilege boundaries. List threats related to privilege escalation, role manipulation, authorization bypass, and IAM misconfiguration.

## Phase 3 — Attack Tree Construction

1. **Root Node** — Define the attacker's ultimate goal (data exfiltration, service disruption, privilege escalation, lateral movement).
2. **Sub-Goals** — Decompose into sub-goals required to achieve the root goal.
3. **Leaf Nodes** — Identify specific techniques that achieve each sub-goal (referencing MITRE ATT&CK technique IDs).
4. **Cost Assignment** — Assign estimated cost (time, skill, resources) to each leaf node attack; low-cost/high-impact leaves are escalated.
5. **OR/AND logic** — Model alternatives (OR) and required combinations (AND) to expose minimal attack paths.

## Phase 4 — DREAD Risk Scoring

1. Score each threat on the DREAD model, 1-10 per dimension:
   - **D**amage potential: how much damage if exploited
   - **R**eproducibility: how reliably it can be reproduced
   - **E**xploitability: how much effort/skill to exploit
   - **A**ffected users: how many users/components affected
   - **D**iscoverability: how easily discovered
2. **Risk Calculation** — `DREAD = (D+R+E+A+D)/5`. Rank threats by score. Map to bands:
   - Critical: 8.5-10
   - High: 7.0-8.4
   - Medium: 4.0-6.9
   - Low: < 4.0
3. Cross-check with likelihood x impact (1-5) from the existing scoring model; report both.
4. Produce the risk-ranked threat list that becomes the testing priority queue.

## Phase 5 — Kill Chain Mapping

Reference: skills/threat-intel/skill-playbook.md

1. Map every critical threat onto the Lockheed Martin kill chain phases:
   - Reconnaissance -> Weaponization -> Delivery -> Exploitation -> Installation -> C2 -> Actions on Objective
2. Map each phase to MITRE ATT&CK technique anchors (see threat-intel playbook section 3.4).
3. Identify phase gaps: threats that span multiple phases imply chainable kill paths (e.g., SSRF -> metadata -> lateral movement).
4. Highlight chains where a single finding unlocks multiple subsequent phases.

## Phase 6 — MITRE ATT&CK Navigator Layer

1. Generate an enterprise-attack layer from the identified TTPs:
   - Build JSON with `"techniques": [{"techniqueID": "T1190", "tactic": "initial-access", "score": 100}]`
   - Include the threat description as the `comment` field per technique
2. Overlay a detection-coverage layer to expose blind spots (covered vs uncovered TTPs).
3. Validate the layer JSON renders in the Navigator (https://mitre-attack.github.io/attack-navigator/).
4. Deliver the layer with the threat model so report-agent can visualize coverage gaps.

## Phase 7 — Intelligence-Driven Prioritization

Reference: skills/cve-staging/cve-analysis.md

1. Query EPSS, CISA KEV, and NVD for CVEs matching the identified technology stack:
   - `curl -s "https://api.first.org/data/v1/epss?cve=CVE-2024-3400"`
   - `curl -s "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"`
2. Apply SSVC-style decisions: KEV-listed or EPSS > 0.5 vulnerabilities move to top-tier regardless of CVSS.
3. Reference industry TTP watchlists from the threat-intel library; an actively exploited technique class in the target's sector is escalated.
4. Document the intelligence date so stale data cannot mislead the model.

## Phase 8 — Risk Prioritization & Testing Guide

1. **Priority Map** — Map high-risk threats (DREAD >= 7.0 or KEV-listed) to specific testing techniques and agents.
2. **Coverage Gap Analysis** — Identify threats that are not covered by the available agent toolset; flag for orchestrator.
3. **Methodology Recommendations** — For each threat category, recommend specific testing approaches, tools, and payloads.
4. **Sequencing** — Order the testing guide so that kill-chain-enabling findings (initial access, auth bypass) are tested first.
5. **Compliance Mapping** — Map threats to GDPR, PCI-DSS, SOC2, or HIPAA controls where applicable.

## Verification

1. Every component in the DFD has at least one STRIDE threat — zero-threat components are flagged as coverage gaps.
2. Every entry point in the attack surface inventory appears in the DFD or is explicitly excluded with a reason.
3. DREAD scores are reproducible: the five dimension values are recorded per threat.
4. Kill chain mapping references real MITRE ATT&CK technique IDs.
5. Navigator layer JSON validates and renders; coverage gaps are explicit.
6. Intelligence (EPSS/KEV) citations carry a data date and are current.
7. Assumptions are logged and distinguishable from documented facts.

## Skill Library References
- skills/threat-intel/skill-playbook.md
- skills/cve-staging/cve-analysis.md
- skills/network-security/service-enumeration.md
