# Version Fingerprinting & Finding — Skill Playbook

**Mitre ATT&CK ID:** T1592.002 (Software) / T1046 (Network Service Discovery)
**OWASP Mapping:** A06:2021 – Vulnerable and Outdated Components
**Severity:** Informational → Critical (when it chains to a known CVE)
**Last Updated:** 2026-08-04

---

## Metadata

```yaml
skill_id: version-enumeration-v1
category: version-enumeration
author: HiveBreach
mitre_attack_id: T1592.002
owasp_mapping:
  - A06:2021-VulnerableandOutdatedComponents
tags:
  - version
  - fingerprinting
  - banner
  - cve
  - osint
  - T1592.002
  - T1046
environments:
  - web
  - network
  - api
  - cloud
verification_required: none
```

---

## 1. Version Fingerprinting Sources

| Source | Method | Reliability |
|---|---|---|
| Service banners | `nc`, `nmap -sV`, banner in response | High |
| HTTP headers | `Server:`, `X-Powered-By:`, `X-AspNet-Version:` | High |
| HTML/JS artifacts | version strings in JS, `generator` meta, build IDs | Med |
| Default error pages | framework version in stack traces | High |
| Favicon hash | identifies app/template version | Med |
| TLS cert | often reveals host, org, sometimes version | Med |
| Robots/sitemap | CMS fingerprints (`wp-content`, `/user/login`) | Med |
| File hashes | compare known version file hashes | High |
| API schema | OpenAPI `info.version` | High |
| Package metadata | `package.json`, `composer.lock`, `Gemfile.lock`, `requirements.txt` (if leaked) | High |

---

## 2. HTTP/Web Version Fingerprinting

### 2.1 Headers

```bash
# Full header inspection
curl -sI https://<target>
# Common response headers to collect
# Server, X-Powered-By, X-AspNet-Version, X-Generator, X-Drupal-Cache, Via, ETag
curl -s -D- -o /dev/null https://<target>/page?x=1
```

### 2.2 Fingerprint Tools

```bash
# whatweb - tech stack fingerprint
whatweb -v https://<target>

# wappalyzer (browser) / Wappalyzer CLI
wappalyzer https://<target>

# nuclei technology templates
nuclei -u https://<target> -tags tech

# httpx - fast tech + title + status
httpx -u <target> -title -tech-detect -status-code -web-server

# WAF detection
wafw00f https://<target>

# CMS specific
wp-scan --url https://<target> --enumerate vp,vt,u,dbe  # WordPress
joomscan -u https://<target>                             # Joomla
drupwn --mode enumerate --target https://<target>        # Drupal
```

### 2.3 Manual Fingerprint Points

```markdown
| Indicator | Location | Tells you |
|---|---|---|
| `wp-content/themes/<theme>/` | HTML | WordPress + theme version |
| `/Umbraco/` | HTML/JS | Umbraco CMS + version |
| `$wgVersion` | /index.php?title=Special:Version | MediaWiki version |
| `django/middleware` | 500 error page | Django version |
| `org.springframework` | stack trace | Spring version |
| `vue@2.6.14` | bundled JS | Frontend framework version |
| `generator": "Hugo 0.101.0` | HTML meta | Static site + version |
| `x-github-request-id` | header | Behind GitHub Pages/CDN |
| `Build info` in `/actuator/info` | endpoint | Spring Boot version |
```

---

## 3. Service Version Fingerprinting

```bash
# nmap version scan (primary)
nmap -sV --version-intensity 7 -p <ports> <target> -oA version-scan

# Banner grab per service
nc -vn <target> 21    # FTP
nc -vn <target> 22    # SSH
nc -vn <target> 25    # SMTP
nc -vn <target> 3306  # MySQL
printf "HEAD / HTTP/1.1\r\nHost: x\r\n\r\n" | nc -vn <target> 80

# TLS details (often exposes version)
openssl s_client -connect <target>:443 -servername <target> 2>/dev/null | openssl x509 -noout -subject -issuer -dates -text | head

# AMQP / Redis / MongoDB / etc via dedicated clients
redis-cli -h <target> INFO server | grep redis_version
mongosh "mongodb://<target>:27017" --eval "db.version()"
psql -h <target> -U <user> -c "SHOW server_version;" 2>/dev/null
```

---

## 4. Version → Finding Pipeline

**This is the critical discipline (R2): version is a lead, NOT a finding.**

```
1. Fingerprint version (multiple independent sources)
2. Correlate to known CVEs
3. Determine exploitability (config-dependent?)
4. Verify in sandbox / PoC
5. Report with version + CVE + confidence
```

### 4.1 CVE Correlation

```bash
# Local exploit-db
searchsploit <software> <version>
searchsploit wordpress core

# NVD API
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=<software>&keywordExactMatch" | jq -r '.vulnerabilities[].cve.id' | head

# CVE feed (authorized)
curl -s "https://cve.circl.lu/api/search/<software>/<version>" | jq -r '.[] | .id + " " + .summary' | head

# Nuclei CVE templates (fast triage)
nuclei -u <target> -t ~/nuclei-templates/cves/ -severity critical,high -jsonl cve-scan.jsonl
```

### 4.2 Exploitability Triage

| Factor | Question |
|---|---|
| Version match | Is the CVE applicable to the EXACT version? |
| Config dependency | Does the CVE require a feature enabled? (e.g., debug, dev mode) |
| Default state | Is the vulnerable feature on by default? |
| Exposure | Is the vulnerable endpoint reachable? |
| WAF/filter | Does anything block the payload? |

**Rules:**
- Version present + CVE known + endpoint reachable = **confirmed** (after PoC)
- Version present + CVE known but endpoint unreachable = **not exploitable** (report as informational)
- CVE known but version NOT confirmed = **tentative**, needs confirmation

---

## 5. Version Finding Template

```markdown
## [FINDING_ID] — [TITLE]
Asset: <host>:<port>
Software: <name>
Fingerprinted version: <version> (source: nmap -sV banner)
Known CVE: <CVE-ID> (<severity>) — <link>
CVE applies to: <affected version range>
Exploitability: confirmed|likely|tentative|not-exploitable
Evidence:
  - banner: `<raw banner>`
  - output: `<CVE lookup result>`
  - PoC: `<proof of exploitability>` (only if confirmed)
Reproduction:
  1. `<step>`
Impact:
Remediation: Upgrade to <fixed version>
```

---

## 6. Verification (Sandbox)

- [ ] Version confirmed from ≥2 independent sources where possible
- [ ] CVE exact-version match verified (not just prefix match)
- [ ] Exploitability PoC executed against sandbox replica
- [ ] No exploitation of production just to "confirm" (R3/R5)
- [ ] Out-of-scope dependency versions (JS libs) not reported as standalone critical

---

## 7. Common Version Maps (quick reference)

| Software | Banner Pattern | Example |
|---|---|---|
| Apache | `Apache/2.4.41 (Ubuntu)` | 2.4.41 |
| Nginx | `nginx/1.18.0` | 1.18.0 |
| OpenSSH | `OpenSSH_8.2p1 Ubuntu-4ubuntu0.5` | 8.2p1 |
| MySQL | `5.7.35-0ubuntu0.18.04.1` | 5.7.35 |
| PostgreSQL | `PostgreSQL 13.3` | 13.3 |
| Microsoft IIS | `Microsoft-IIS/10.0` | 10.0 |
| Exim | `Exim 4.92` | 4.92 |
| WordPress | `WordPress 5.9.3` (meta/readme.html) | 5.9.3 |
| PHP | `X-Powered-By: PHP/7.4.30` | 7.4.30 |
| Tomcat | `Apache-Coyote/1.1` / `Server: Apache/2.4.41 (Ubuntu) ...` | 9.0.x |
| Nginx + PHP-FPM | `X-Powered-By: PHP/7.4` | 7.4 |
| GitLab | `GitLab 15.0.0` (in `/-/help` or headers) | 15.0.0 |

---

## 8. Related Techniques (MITRE ATT&CK Mapping)

| Technique ID | Name | Relation |
|---|---|---|
| T1592.002 | Software | Version fingerprinting |
| T1595 | Active Scanning | Service probing |
| T1046 | Network Service Discovery | Service enumeration |
| T1190 | Exploit Public-Facing Application | CVE exploitation |
| T1082 | System Information Discovery | Post-exploit version info |
| T1592.001 | Hardware | OS/hardware fingerprint |

---

## 9. References

- MITRE ATT&CK T1592.002: https://attack.mitre.org/techniques/T1592/002/
- whatweb: https://github.com/urbanadventurer/WhatWeb
- Wappalyzer: https://www.wappalyzer.com/
- searchsploit: https://www.exploit-db.com/searchsploit
- NVD: https://nvd.nist.gov/
- nuclei templates: https://github.com/projectdiscovery/nuclei-templates

---

*Version enumeration is largely passive/informational (R1-safe). Escalating a version lead to an active exploit requires scope authorization + sandbox verification (R5).*
