---
skill: report-generation-deep-aggressive
mitre_attack_id: TA0040
owasp_mapping: []
difficulty: advanced
mode: deep-aggressive
tags: [report-generation, executive-summary, finding-templating, evidence-chain-of-custody, pdf, markdown, jinja2, weasyprint, appendices]
---

# Deep Aggressive Mode Playbook: report-agent

> Purpose: This playbook is the deep-aggressive operational doctrine for report generation and evidence packaging. Every report is traceable, every finding templated to the CVE-analysis standard, and every evidence artifact chained to the audit trail.

## Phase 1 — Data Collection & Validation

Reference: skills/cve-staging/cve-analysis.md, skills/dfir/skill-playbook.md

1. **Master Findings** — Load the correlated master findings list from verification-correlation-agent. Verify the file integrity (checksum match, schema validation).
2. **Supporting Evidence** — Collect supporting evidence: PoC scripts, screenshots, request/response pairs, console logs. Compute SHA256 for each artifact.
3. **Compliance Data** — Load compliance mappings from compliance-audit-agent.
4. **Context Data** — Load the threat model for threat context and scan scope documentation.
5. **Integrity check** — Confirm the finding count in the master list matches the number of finding records; halt on mismatch.

## Phase 2 — Finding Templating

For each finding in the master list, build the canonical template:

```
## Finding WEB-001 — SQL Injection in /api/v2/orders/{userId}
- Severity: Critical (CVSS v4.0 9.2, CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H)
- EPSS: 0.71 (82nd percentile) | CISA KEV: Listed | SSVC: Act (48h SLA)
- CWE: CWE-89 | OWASP: A03 | MITRE ATT&CK: T1190
- Affected: https://target.com/api/v2/orders/{userId} (Host 10.0.0.5)
- Evidence: WEB-001_request.txt (sha256:...), WEB-001_response.json (sha256:...)
- PoC: WEB-001_poc.py (Appendix A)
- Reproduction:
  1. Send request: curl -X POST https://target.com/api/v2/orders/1'%20OR%201=1-- -d @body.json
  2. Observe 147-row response dump in WEB-001_response.json
- Remediation: Use parameterized queries via ORM binding for the userId parameter.
  Disclaimer: <verbatim disclaimer>
```

Include for each finding:
- Finding ID and title
- OWASP/MITRE/CWE classification
- CVSS v3.1/v4.0 score with full vector string
- EPSS/KEV/SSVC context from the risk register
- Affected host, endpoint, and parameter
- Technical description
- Reproduction steps (numbered, actionable)
- Proof of concept (curl command, Python script, or screenshot)
- Remediation guidance (with disclaimer)
- Compliance control mappings

## Phase 3 — Executive Summary Writing

1. Write a concise, non-technical summary covering:
   - Scan scope and duration
   - Critical and high-severity finding count
   - Most impactful vulnerabilities (top 3-5) framed by business impact
   - Overall risk rating
   - Recommended actions with priorities and effort estimates
2. Frame numbers by business impact: "2 critical findings expose customer PII" not "2 CVEs at 9.2".
3. Define every acronym on first use; avoid raw vector strings.
4. Write as a narrative of the organization's most critical risks, why they matter, and what to do first.

## Phase 4 — Evidence Chain-of-Custody

1. Verify every evidence file referenced in the report exists in the evidence archive.
2. Compute and record SHA256 hashes for every artifact:
   ```bash
   sha256sum evidence/* > evidence_hashes.txt
   ```
3. Cross-reference evidence hashes with the audit trail per skills/dfir/skill-playbook.md section 2.1.
4. Never reference a missing or unverified artifact; flag gaps to verification-correlation-agent.

## Phase 5 — Multi-Format Generation

1. **PDF Report** — Generate a professionally formatted PDF using Jinja2 templating and WeasyPrint for HTML-to-PDF conversion:
   ```python
   from jinja2 import Environment, FileSystemLoader
   from weasyprint import HTML
   env = Environment(loader=FileSystemLoader("templates/"))
   html = env.get_template("executive.html").render(findings=findings, manifest=manifest)
   HTML(string=html).write_pdf("reports/executive-summary.pdf")
   ```
2. **Markdown Report** — Generate a GitHub/Markdown-formatted report for developer consumption.
3. **HTML Report** — Generate an interactive HTML technical report with severity color-coding and navigation.
4. **JSON Export** — Generate a machine-readable JSON export for integration with ticketing systems, SIEMs, and vulnerability management platforms.
5. **CSV Export** — Generate a spreadsheet-compatible CSV for remediation tracking.

## Phase 6 — Appendix Building

1. Appendix A: full PoC scripts, each with purpose and expected output.
2. Appendix B: methodology description (frameworks, stages, tools).
3. Appendix C: tool versions and configuration (scanner versions, wordlists, payloads).
4. Appendix D: scope documentation (targets, exclusions, ROE boundaries).
5. Appendix E: IOC list in STIX/MISP-compatible format, TLP-classified per skills/threat-intel/skill-playbook.md.
6. Appendix F: YARA rules and detection signatures where applicable (skills/threat-intel/yara-hunting.md).

## Phase 7 — Report Finalization

1. **Disclaimer Insertion** — Add the following disclaimer to every remediation suggestion: "This remediation suggestion is advisory only. The client's security team should review and validate all remediation steps before implementation. HiveBreach assumes no liability for damages resulting from the implementation of remediation recommendations."
2. **Branding** — Apply client branding (logo, colors, headers) if provided.
3. **Digital Signature** — Sign the report with the framework's GPG key for integrity verification:
   ```bash
   gpg --detach-sign --armor --output report.asc reports/HIVE-2026-001.tar.gz
   ```
4. **Versioning** — Save the report with a version number and timestamp.

## Phase 8 — Verification

1. Verify that the number of findings in the report matches the master list count; no drops or duplicates.
2. Validate schema: title, description, severity, CVSS vector, endpoint, remediation, disclaimer present per finding.
3. Scan generated PDFs for the verbatim disclaimer text.
4. Cross-reference every referenced PoC against the evidence archive with matching hashes.
5. Render-check each format: PDF page breaks and fonts, Markdown tables and code blocks, JSON/CSV schema and encoding.
6. Confirm the manifest lists every generated artifact with its SHA256.

## Phase 9 — Distribution

1. Archive the report package in the findings archive.
2. Apply the TLP classification and distribution policy from skills/threat-intel/skill-playbook.md.
3. Notify the scheduler-agent that reporting is complete.
4. Notify the audit-agent to finalize the audit trail.

## Verification

1. Data integrity: finding counts match the master list exactly.
2. Schema validation: every required field present in every finding.
3. Disclaimer present verbatim in every report containing remediation.
4. Evidence artifacts exist and hash-verified; chain-of-custody documented.
5. All report formats render correctly and pass format-specific checks.
6. Manifest complete with hashes, TLP classification, and PGP signature.

## Skill Library References
- skills/cve-staging/cve-analysis.md
- skills/threat-intel/skill-playbook.md
- skills/dfir/skill-playbook.md
- skills/penetration-testing/*.md
- skills/malware-analysis/static-analysis.md
- skills/malware-analysis/dynamic-analysis.md
