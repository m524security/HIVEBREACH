# Web-Based Attack Coverage — Skill Playbook (Expanded)

**Mitre ATT&CK ID:** T1190 (Exploit Public-Facing Application)
**OWASP Mapping:** A01-A10 (full Top 10 coverage)
**Severity:** Low → Critical
**Last Updated:** 2026-08-04

---

## Metadata

```yaml
skill_id: web-attack-coverage-v1
category: penetration-testing
author: HiveBreach
mitre_attack_id: T1190
owasp_mapping:
  - A01:2021-BrokenAccessControl
  - A02:2021-CryptographicFailures
  - A03:2021-Injection
  - A04:2021-InsecureDesign
  - A05:2021-SecurityMisconfiguration
  - A06:2021-VulnerableandOutdatedComponents
  - A07:2021-IdentificationandAuthenticationFailures
  - A08:2021-SoftwareandDataIntegrityFailures
  - A09:2021-SecurityLoggingandMonitoringFailures
  - A10:2021-ServerSideRequestForgery
tags:
  - web
  - owasp-top-10
  - coverage
  - checklist
  - T1190
environments:
  - web
  - api
  - microservice
verification_required: sandbox
```

---

## 1. Full Coverage Checklist (run this per web app)

This is the master checklist. Each item links to the deep playbook. Mark each: `[ ]` untested, `[x]` tested-clean, `[!]` finding.

### A01 — Broken Access Control (check every endpoint)
- [ ] IDOR / BOLA object ID enumeration (see `idor.md`)
- [ ] BFLA — function-level access (user vs admin)
- [ ] HTTP method tampering (GET→POST, method override headers)
- [ ] Path traversal in file access endpoints (`file-inclusion.md`)
- [ ] CORS misconfig (see `cors-misconfiguration.md`)
- [ ] Forceful browsing of admin/backup paths
- [ ] Referer/Origin header trust abuse

### A02 — Cryptographic Failures
- [ ] Sensitive data in cleartext (passwords, tokens in query strings)
- [ ] Weak TLS / cipher suites (see `osi-7-layers.md` L6)
- [ ] Predictable session tokens (Burp Sequencer)
- [ ] Weak password hashing (MD5/SHA1 in DB)
- [ ] Hardcoded keys/certs (`api-key-leaks.md`)
- [ ] JWT weaknesses (`jwt-testing.md`)

### A03 — Injection (see deep playbooks)
- [ ] SQLi (`sql-injection.md`)
- [ ] Command injection (`command-injection.md`)
- [ ] XXE (`xxe.md`)
- [ ] SSTI (`ssti.md`)
- [ ] NoSQLi (`nosql-injection.md`)
- [ ] LDAP injection, XPath injection
- [ ] CRLF injection (response splitting)

### A04 — Insecure Design
- [ ] Business logic flaws (pricing, step-skip, race conditions)
- [ ] Rate-limit bypass on critical flows (login, OTP, password reset)
- [ ] Broken password reset flow (token predictable, no user verification)
- [ ] Account enumeration via error messages / timing
- [ ] Trust boundary flaws (client-side trust)

### A05 — Security Misconfiguration
- [ ] Default creds (admin/admin, root/root)
- [ ] Debug / verbose error pages
- [ ] Directory listing enabled
- [ ] Unnecessary features enabled (webDAV, PUT methods)
- [ ] Security headers missing (HSTS, CSP, XFO, COOP, Referrer-Policy)
- [ ] Admin console exposed (`/admin`, `/console`, `/phpmyadmin`)
- [ ] Backup/source files exposed (`.bak`, `.git`, `.env`, `wp-config.php.bak`)
- [ ] Cloud misconfig (`cloud-detection.md`)

### A06 — Vulnerable/Outdated Components
- [ ] CMS + plugins version check (`version-fingerprinting.md`)
- [ ] Frontend libs with known CVEs (retire.js / nuclei)
- [ ] SCA on leaked manifests (`package.json`, `composer.lock`)
- [ ] Server stack versions → CVE correlation

### A07 — Identification & Auth Failures
- [ ] Weak password policy (test enumeration)
- [ ] No MFA on sensitive actions
- [ ] Session fixation / no invalidation on logout
- [ ] Credential stuffing resistance (rate-limit policy)
- [ ] Brute-force protection bypass (`hash-password-cracking.md`)
- [ ] OAuth/SSO flaws (`oauth-sso.md`)

### A08 — Software & Data Integrity Failures
- [ ] Unsafe deserialization (`insecure-deserialization.md`)
- [ ] File upload → webshell / polyglot (`file-upload.md`)
- [ ] CI/CD pipeline integrity (`supply-chain/ci-cd.md`)
- [ ] Dependency confusion / typosquatting vectors
- [ ] Signature verification gaps (JWT alg confusion)

### A09 — Security Logging & Monitoring Failures
- [ ] Error handling reveals internals (stack traces, DB errors)
- [ ] Failed-login attempts not visible / no lockout logging
- [ ] No audit trail on privileged actions
- [ ] Log injection (CRLF into logs → log poisoning → XSS in log viewer)

### A10 — SSRF
- [ ] URL input → internal services (`ssrf.md`)
- [ ] Cloud metadata access (`cloud-detection.md`)
- [ ] DNS rebinding, gopher, file:// schemes
- [ ] SSRF via redirects / open redirects (`open-redirect.md`)

---

## 2. Web Enumeration & Discovery (do first)

```bash
# Tech fingerprint
whatweb -v <target>
# Content discovery (recursive)
feroxbuster -u <target> -w /usr/share/wordlists/dirb/big.txt -x php,html,bak,txt -r
gobuster dir -u <target> -w /usr/share/wordlists/dirb/common.txt -x php,aspx,html
# Subdomain/parameter discovery
ffuf -u <target> -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt
# Hidden files
curl -s <target>/.git/HEAD
curl -s <target>/.env
curl -s <target>/robots.txt
curl -s <target>/sitemap.xml
curl -s <target>/wp-json/
```

---

## 3. Attack Vectors (cheat sheet)

| Vector | Deep Playbook | Quick Test |
|---|---|---|
| SQLi | `sql-injection.md` | `id=1'` + response diff |
| XSS | `xss.md` | `<script>alert(1)</script>` + reflect |
| SSRF | `ssrf.md` | `url=http://127.0.0.1:22` timing |
| CMDi | `command-injection.md` | `;id` / `$(id)` / `` `id` `` |
| LFI/RFI | `file-inclusion.md` | `?file=/etc/passwd` |
| SSTI | `ssti.md` | `{{7*7}}` in templates |
| XXE | `xxe.md` | `<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a SYSTEM "file:///etc/passwd">]><x>&a;</x>` |
| Deserial | `insecure-deserialization.md` | ysoserial gadget |
| Upload | `file-upload.md` | `.php.jpg` / polyglot |
| CSRF | `csrf.md` | state-changing GET |
| Open redirect | `open-redirect.md` | `?next=//evil.com` |
| Request smuggling | `request-smuggling.md` | CL.TE / TE.CL |

---

## 4. Automated Scanning Suite

```bash
# Quick pass
nuclei -u <target> -severity low,medium,high,critical -jsonl web-scan.jsonl
nikto -h <target> -C all -o nikto.txt

# Deep pass (careful with auth + rate)
nuclei -u <target> -tags cve -severity critical -rl 50
# CMS
wp-scan --url <target> --enumerate ap,at,cb,dbe
# OWASP ZAP full
zap-baseline.py -t https://<target> -r report.html
```

---

## 5. Manual Deep-Dive (highest value)

1. **Map every parameter** (Arjun: `arjun -u <target>/api -m JSON`)
2. **Test auth logic** — sign up, reset, forgot password, role changes
3. **Test every state-changing action** for CSRF + BOLA
4. **Fuzz upload endpoints** for extension/WAF bypass
5. **Check API surface** beyond UI (v1/v2, undocumented)
6. **Business logic** — concurrent requests, negative quantities, step-skip
7. **Test the funky stuff** — WebSocket, gRPC, GraphQL (see `graphql-testing.md`)

---

## 6. Finding Template (Web)

```markdown
## [FINDING_ID] — [TITLE]
OWASP: A###:2021
Mitre: T###
URL: <full URL>
Method: <GET/POST/...>
Parameter: <param>
Type: <e.g. reflected XSS>
Evidence:
  - Request: <curl or Burp request>
  - Response diff / payload effect
  - Two independent confirmations
CVSS: <x.x>
Vector: <CVSS:3.1/...>
Reproduction:
  1. ...
Impact:
Remediation:
Confidence: confirmed|likely|tentative
```

---

## 7. Verification (Sandbox)

- [ ] Each finding has reproduced request/response pair
- [ ] Payload re-tested in sandbox replica
- [ ] No destructive actions on production
- [ ] Rate limits honored (429 backoff)
- [ ] Sensitive data redacted (R4/R8)

---

## 8. Related Techniques (MITRE ATT&CK Mapping)

| Technique ID | Name | Relation |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Primary |
| T1505.003 | Web Shell | Post-exploit persistence |
| T1553.002 | Code Signing (trust) | Integrity abuse |
| T1059.007 | JavaScript/JScript | XSS payloads |
| T1566 | Phishing | Social vectors |
| T1046 | Network Service Discovery | Underlying services |

---

## 9. References

- OWASP Top 10 2021: https://owasp.org/Top10/
- OWASP WSTG: https://owasp.org/www-project-web-security-testing-guide/
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings
- HackTricks Web: https://book.hacktricks.xyz/pentesting-web
- PortSwigger Academy: https://portswigger.net/web-security

---

*This playbook is for authorised security testing only. Follow R1 scope, R2 evidence, R3 no-damage, and rate-limit policy from `hash-password-cracking.md` §3.*
