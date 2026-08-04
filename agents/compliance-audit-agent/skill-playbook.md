# Skill Playbook: compliance-audit-agent — DEEP AGGRESSIVE MODE

> **Purpose:** Authoritative deep-aggressive-mode operating procedures for compliance mapping and baseline verification. Embeds threat-intel exploitation context from `skills/threat-intel/skill-playbook.md` and CVE severity/EPSS correlation from `skills/cve-staging/cve-analysis.md`. Read-only verification; no exploitation.

## Phase 1 — Framework & Baseline Definition

1. **Declare Scope** — Confirm the client's compliance frameworks (SOC 2, ISO 27001, PCI DSS, HIPAA, GDPR, NIST SP 800-53/CSF) and any OS/hardening baselines (CIS Benchmarks, vendor guides). Record this in the audit plan.
2. **Control Inventory Build** — Enumerate the control families in scope: access control (AC), encryption (CR), configuration management (CM), vulnerability management (VM), logging/monitoring (LM), incident response (IR), data protection (DP), supply chain (SC). Map each to the framework clauses that will be assessed.
3. **Baseline Snapshot** — Capture current config state from IaC definitions and any existing osquery fleet data; this is the drift reference.
4. **Threat Context Load** — Pull exploitation-in-the-wild and EPSS context from threat-intel for the CVEs affecting the target; actively-exploited vulnerabilities in scope elevate compliance urgency (skills/threat-intel/skill-playbook.md, skills/cve-staging/cve-analysis.md).

## Phase 2 — Baseline Verification (Read-Only)

1. **Host-Level Audit** — `lynis audit system --quick --report-file /tmp/lynis-report` on each in-scope host; `cis-cat -b CIS_Ubuntu_Linux_24.04_Benchmark_v1.0.x.xml --html` for CIS profile checks.
2. **Policy-as-Code** — `inspec exec profile/my-baseline --target ssh://user@host --format json`; treat failures as drift with exact evidence rows.
3. **osquery Deep Dive** — Targeted queries per control:
   - Open ports/services: `SELECT process,local_port FROM listening_ports WHERE local_port NOT IN (22,443);`
   - Users & auth: `SELECT username,uid,shell FROM users WHERE shell != '/usr/sbin/nologin';` `SELECT * FROM crontab;`
   - Installed packages (unapproved/out-of-date): `SELECT name,version FROM deb_packages ORDER BY version;`
   - File permissions: `SELECT path,uid,gid,mode FROM file WHERE path LIKE '/etc/%' AND mode > '0755';`
   - Kernel/OS: `SELECT * FROM os_version;` `SELECT * FROM kernel_info;`
   - Docker: `SELECT * FROM docker_containers;`
4. **Network/TLS Posture** — `sslscan --no-colour --tls-all target:443`; `testssl.sh --severity MEDIUM target:443`; capture weak protocol/cipher output for encryption controls.
5. **Vuln Baseline Cross-Reference** — Run OpenVAS/GVM authenticated scan; merge results with sca-sbom-agent dependency findings to assess the vulnerability-management control family end to end.

## Phase 3 — Finding Intake & Correlation

1. **Collect Findings** — Pull findings YAML from web-hunting-agent, api-testing-agent, mobile-app-agent, secrets-scanning-agent, sca-sbom-agent. Group by: attack vector, impacted asset, weakness class.
2. **ATT&CK & CWE Mapping** — Assign MITRE ATT&CK techniques (e.g., T1213 Credentials from Repositories for a leaked secret) and CWE identifiers (e.g., CWE-639 BOLA, CWE-79 XSS, CWE-798 Hardcoded Credentials) per finding.
3. **OWASP Alignment** — Map web findings to OWASP Top 10 (A01 Broken Access Control, A03 Injection, etc.), mobile findings to Mobile Top 10 (M01-M09), API findings to API Top 10 where applicable.
4. **Framework Clause Resolution** — For each finding, resolve the controlling standard clauses:
   - SOC 2: CC6 (access), CC7 (monitoring), CC8 (change mgmt)
   - ISO 27001: A.5-A.8 (policy/asset/HR/physical), A.9 (access), A.12 (operations), A.16 (incident), A.17 (BC)
   - PCI DSS: Req 1-4 (network/encryption), 5-7 (malware/secure code/access), 10-11 (logging/testing)
   - HIPAA: 164.308 (administrative), 164.312 (technical safeguards)
   - GDPR: Art. 25 (data protection by design), Art. 32 (security of processing)
   - NIST SP 800-53: AC, IA, SC, CM, AU control families
5. **Severity Reconciliation** — Combine CVSS/EPSS + control criticality + wild-exploitation status into the mapped severity; document rationale per finding.

## Phase 4 — Evidence Bundle Construction

1. **Sanitization** — Redact secrets, tokens, session IDs, and personal data from all PoC artifacts before bundling.
2. **Timestamping & Provenance** — Every artifact carries: finding_id, source agent, tool used, exact command, timestamp, and hash of the raw output.
3. **Tie Evidence to Control** — Each bundle links: finding -> PoC artifact -> control clause -> failed baseline check (where applicable).
4. **Integrity Check** — Verify evidence files are unchanged (sha256) and reproducible from the recorded commands.

## Phase 5 — Compliance Gap Analysis & Remediation Tracking

1. **Gap Report** — Produce per-framework tables: control, clause, status (pass/fail/partial/unknown), evidence, severity, and the findings that prove each failure.
2. **Remediation Roadmap** — For every failed control: concrete recommendation (from the originating technical agent), responsible team (development/IT/security/cloud), priority (derived from mapped severity), and target remediation date.
3. **Executive Impact** — Summarize: which compliance certifications are at risk, what business functions are exposed, and the regulatory consequence of each failing control family.

## Phase 6 — Evasion & Deep Aggressive Execution

1. **Read-Only Discipline** — All checks use non-mutating queries and scans; any check that requires a write is skipped and logged as `not-verifiable-readonly`.
2. **Drift vs. Failure** — Distinguish configuration drift (deviation from documented baseline) from absolute failure (violation of the standard); report both, since drift itself is an audit finding (change management control gap).
3. **Evidence-Rich Mapping** — For the highest-value findings, build the full narrative chain: exploit path -> affected data/asset -> failed control -> violated clause -> business consequence. This is what makes a finding actionable to leadership.
4. **Cross-Agent Validation** — Discrepancies between baseline checks and technical findings (e.g., tool reported patched but host runs vulnerable version) are escalated to the originating agent for reconciliation before reporting.
5. **Coverage Gate** — Before closing: all declared framework clauses assessed, every finding mapped to control + clause, baseline checks run per host, TLS posture captured, evidence bundles sanitized and integrity-checked, remediation tracker complete.

## Phase 7 — Verification & Evidence

1. **Independent Confirmation** — High-impact control failures cross-checked with the originating technical agent's raw evidence.
2. **Inconclusive Labeling** — Anything not directly verifiable is labeled `unknown` and explicitly excluded from pass claims.
3. **Severity Rationale** — Each mapped severity records the CVSS/EPSS + control + wild-exploitation reasoning (skills/cve-staging/cve-analysis.md).
4. **Cleanup** — Remove scan output files and config dumps from attacker-controlled storage after bundling into the evidence vault.
5. **Handoff** — Framework mapping + compliance gap analysis + remediation tracker to audit-agent and reporting; baseline drift alerts (authorization-gated) to exploit-poc-agent; threat-context-enriched CVE data to verification-correlation-agent.
