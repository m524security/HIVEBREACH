---
skill: vulnerability-scanning-deep-aggressive
mitre_attack_id: T1595.002
owasp_mapping: [A01, A03, A04, A06, A07]
difficulty: advanced
tags: [cve-scanning, misconfiguration-detection, false-positive-filtering, severity-prioritization, nuclei, nikto, cvss, ssvc, epss, kev, metasploit-correlation]
---
## Summary
Deep Aggressive Mode vulnerability scanning to identify CVEs, misconfigurations, and security weaknesses across network services and web applications. Executes template-heavy Nuclei campaigns, Nikto server audits, protocol-level NSE checks, and enterprise scanners (Nessus/OpenVAS). Every finding is triaged against CVSS v4.0, SSVC decision points, EPSS exploitation probability, and CISA KEV, then cross-referenced with searchsploit and Metasploit modules for exploit availability. Findings are deduplicated, false-positive validated, and prioritized before delivery to exploitation and risk assessment agents.

Skill library references:
- skills/cve-staging/cve-analysis.md
- skills/network-security/protocol-exploitation.md

## Phase 0 — Inventory Ingestion
1. Collect target inventory from recon-agent (services:port) and web-discover-agent (endpoints:tech stack)
2. Categorize targets: network service, web application, CMS (WordPress/Joomla/Drupal), API, database, middleware
3. Segment scan batches to avoid scanner crashes and respect rate limits
4. Verify scope and exclusions with scope-agent
5. Update template/plugin/NVT feeds: `nuclei -update-templates`, greenbone-feed-sync

## Phase 1 — Network-Layer Nuclei Campaign
```bash
# Network service templates (SMB, RDP, Redis, MongoDB, Docker, SNMP)
nuclei -l ip_port_list.txt -tags network,smb,rdp,redis,mongodb,docker,snmp -rl 50 -json -o nuclei_network.json
# Generic CVE templates across targets
nuclei -l targets.txt -tags cve -severity critical,high,medium -rl 50 -json -o nuclei_cve.json
# Template family sweeps
nuclei -l targets.txt -tags exposure,config,default-login,backup -json -o nuclei_exposure.json
nuclei -l targets.txt -tags misconfig,cors,open-redirect -json -o nuclei_misconfig.json
```

## Phase 2 — Web-Layer Nuclei + Nikto
```bash
# Web vulnerability classes
nuclei -l web_endpoints.txt -tags sqli,xss,lfi,rfi,ssrf,rce,ssti,xxe -rl 50 -json -o nuclei_web_vuln.json
nuclei -l web_endpoints.txt -tags wordpress,joomla,drupal -json -o nuclei_cms.json
# Nikto server audit
nikto -h https://<target> -ssl -port 443 -Format json -output nikto_report.json
nikto -h http://<target> -Tuning 123bde -Format xml -output nikto.xml
# WPScan if CMS identified
wpscan --url https://<target> --api-token <token> --enumerate vp,vt,u,tt --plugins-detection aggressive
```

## Phase 3 — Protocol-Level NSE Checks
```bash
nmap -p 445 --script smb-vuln-* --script-args=unsafe=1 <target>       # MS17-010, SMBGhost surface
nmap -p 445 --script smb2-capabilities,smb2-security-mode <target>
nmap -p 3389 --script rdp-ntlm-info,rdp-enum-encryption <target>      # NLA state, BlueKeep surface
nmap -p 1433 --script ms-sql-info,ms-sql-ntlm-info,ms-sql-empty-password <target>
nmap -p 6379 --script redis-info -sV <target>
nmap -p 27017 --script mongodb-info,mongodb-databases <target>
nmap -p 2375 --script docker-version-info <target>
nmap -p 161 -sU --script snmp-info,snmp-sysdescr,snmp-processes <target>
nmap -p 2049 --script nfs-showmount,nfs-ls <target>
nmap -sV --script vulners --version-intensity 9 -p <open_ports> <target>
```

## Phase 4 — Enterprise Scanners (Nessus/OpenVAS)
```bash
# OpenVAS Full and Fast via gvm-cli
gvm-cli --gmp-username <user> --gmp-password <pass> socket --xml "<create_task><name>...</name><config id='...'/>..."
# Nessus CLI launch
nessuscli scan new --name <scan> --targets <targets> --policy <policy>
# Fallback: if enterprise scanners unavailable, expand nuclei template set
```

## Phase 5 — CVE Triage (CVSS / SSVC / EPSS / KEV)
```bash
# NVD API v2
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-XXXX-XXXX" | jq '.vulnerabilities[0].cve'
# EPSS
curl -s "https://api.first.org/data/v1/epss?cve=CVE-XXXX-XXXX" | jq '.data[0] | {cve, epss, percentile}'
# CISA KEV
curl -s "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" | jq -r '.vulnerabilities[] | select(.cveID=="CVE-XXXX-XXXX") | .cveID'
# Exploit availability
searchsploit CVE-XXXX-XXXX
msfconsole -q -x "search CVE-XXXX-XXXX"
```
Triage decision flow:
1. KEV listed? -> SSVC Act/Attend window (48h-14d)
2. EPSS > 0.5 -> prioritized research
3. Public PoC? -> searchsploit/metasploit/github
4. In-scope + exploitable -> stage in sandbox
5. Else -> document and re-evaluate weekly

## Phase 6 — Metasploit Auxiliary Module Matching
```bash
# Confirm exploitable protocol states with non-invasive aux modules
msfconsole -q -x 'use auxiliary/scanner/smb/smb_ms17_010; set RHOSTS <target>; run'
msfconsole -q -x 'use auxiliary/scanner/rdp/cve_2019_0708_bluekeep; set RHOSTS <target>; run'
msfconsole -q -x 'use auxiliary/scanner/redis/redis_server; set RHOSTS <target>; run'
msfconsole -q -x 'use auxiliary/scanner/mongodb/mongodb_login; set RHOSTS <target>; run'
msfconsole -q -x 'use auxiliary/scanner/http/docker_version; set RHOSTS <target>; run'
msfconsole -q -x 'use auxiliary/scanner/snmp/snmp_login; set RHOSTS <target>; run'
msfconsole -q -x 'use auxiliary/scanner/nfs/nfsmount; set RHOSTS <target>; run'
# Map confirmed protocol states to exploit modules for exploit-agent (see protocol-exploitation playbook)
```

## Phase 7 — Aggregation, Deduplication, False-Positive Validation
```bash
# Merge all scanner outputs
cat nuclei_*.json nikto_report.json nmap_*.xml | jq -s . > findings_raw.json
# Deduplicate by cve_id + endpoint
jq 'unique_by(.cve_id, .host)' findings_raw.json > findings_dedup.json
```
False-positive validation per finding:
- [ ] Confirmed by at least one secondary scanner or manual probe (curl/wireshark)
- [ ] Nuclei findings re-run with -validate flag
- [ ] Version match against CPE database is exact
- [ ] Public PoC or Metasploit module exists for the claimed CVE
- [ ] Ambiguous findings tagged "unverified" with rationale

## Phase 8 — Scoring & Prioritization
Score each verified finding with CVSS v4.0 vector string (not just number) plus EPSS and KEV context. Apply SSVC decision points: Exploitation (None/PoC/Active), Technical Impact (Partial/Total), Automatability, Mission Prevalence. Produce engagement priority:
1. KEV + CVSS >= 9.0 + internet-exposed + SSVC Act -> immediate
2. EPSS > 0.5 + CVSS >= 7.0 + in-scope -> prioritized
3. CVSS >= 7.0 + authenticated path -> medium
4. CVSS < 7.0 or not exploitable -> document low

## Phase 9 — Deliverables & Handoff
Verification checklist (sandbox):
- [ ] Every finding has CVE ID, CVSS vector, EPSS, KEV state, affected component, evidence
- [ ] Metasploit module or public exploit matched where available
- [ ] Data dates recorded for EPSS/KEV lookups
- [ ] Unverified findings excluded from critical/high categories
- [ ] Remediation guidance provided per finding
- [ ] Output in structured JSON

Handoff:
- Ranked findings (cve_id, cvss_v4, severity, target, type, evidence, exploit_available, metasploit_module, verified) to exploit-agent
- Risk-scored aggregation to risk-agent
- Full scan log with parameters to audit-agent

## References
- Skill library: skills/cve-staging/cve-analysis.md, skills/network-security/protocol-exploitation.md
- MITRE ATT&CK T1595.002 (Vulnerability Scanning): https://attack.mitre.org/techniques/T1595/002/
- MITRE ATT&CK T1190: https://attack.mitre.org/techniques/T1190/
- NVD API: https://nvd.nist.gov/developers/vulnerabilities
- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- FIRST EPSS: https://www.first.org/epss/
- CVSS v4.0 Calculator: https://www.first.org/cvss/calculator/4.0
- nuclei: https://github.com/projectdiscovery/nuclei
- nikto: https://github.com/sullo/nikto
- searchsploit: https://www.exploit-db.com/

Prohibited: launching DoS-capable checks against production, executing unvetted PoCs, reporting unverified findings as confirmed, using stale EPSS/KEV data without date attribution.
