# Server-Based Detection & Findings — Skill Playbook

**Mitre ATT&CK ID:** T1592 (Gather Victim Host Information) / T1046 (Network Service Discovery)
**OWASP Mapping:** A05:2021 – Security Misconfiguration
**Severity:** Low → Critical (varies)
**Last Updated:** 2026-08-04

---

## Metadata

```yaml
skill_id: server-detection-v1
category: server-security
author: HiveBreach
mitre_attack_id: T1592
owasp_mapping:
  - A05:2021-SecurityMisconfiguration
  - A06:2021-VulnerableandOutdatedComponents
tags:
  - server
  - operating-system
  - service
  - misconfiguration
  - T1592
  - T1046
  - T1190
  - T1059
environments:
  - network
  - cloud
  - on-premise
verification_required: sandbox
```

---

## 1. Server Detection (Host & Service Enumeration)

### 1.1 Host Discovery

| Method | Command | Detection Value |
|---|---|---|
| ICMP ping sweep | `nmap -sn -PE <target>` | Live hosts, ICMP policy |
| TCP SYN sweep | `nmap -sn -PS80,443,22 <target>` | Live hosts when ICMP blocked |
| ARP scan (same subnet) | `arp-scan --localnet` | Live hosts on L2 segment |
| Masscan | `masscan <target> -p1-65535 --rate=1000` | Fast full-port live host map |

### 1.2 Service & Version Enumeration

```bash
# Full service detection with version
nmap -sV -sC -p- <target> --reason -oA findings/host-<target>

# Focused version detection
nmap -sV --version-intensity 9 -p 21,22,23,25,53,80,443,3306,3389,8080,8443 <target>

# Service scripts
nmap --script="default,version,ssl-*,http-*" -p- <target>
```

### 1.3 OS Fingerprinting

```bash
# OS detection
nmap -O <target>
# TTL-based guess
ping -c 1 <target>   # TTL 64=Linux, 128=Windows, 255=Cisco
# TCP stack fingerprint
nmap -O --osscan-guess <target>
```

---

## 2. Server Findings Classes

Every server finding falls into one of these classes. Classify FIRST, then verify.

| Class | Examples | Severity Baseline |
|---|---|---|
| Exposed service | telnet, FTP, SNMP public, Docker API public | High |
| Outdated/EO | Apache 2.2, OpenSSL 1.0, old kernel | High |
| Default creds | root/root, admin/admin, default SNMP community | Critical |
| Misconfig | directory listing, weak permissions, exposed backup files | Medium |
| Info disclosure | version banners, debug mode, stack traces, internal IPs | Low-Med |
| Patch gap | known CVE present per version | High-Critical |

### 2.1 Finding Template (Server)

```markdown
## [FINDING_ID] — [TITLE]
Class: [exposed-service|outdated|default-creds|misconfig|info-disclosure|patch-gap]
Host: <ip>
Port/Service: <port>/<service> (<service-version>)
CVE (if patch gap): <CVE-ID> — <description> — https://nvd.nist.gov/vuln/detail/<CVE-ID>
Mitre: <T###>
Evidence:
  - banner: `<banner string>`
  - output: `<command output proving the issue>`
Reproduction:
  1. `<step>`
Impact:
Remediation:
```

---

## 3. Per-Service Detection Playbooks

### 3.1 SSH (22)

```bash
# Version + auth methods
nmap -sV -p22 --script=ssh2-enum-algos,ssh-hostkey <target>
# Weak auth methods (password allowed?)
nc -vn <target> 22
# Default/weak creds (authorized brute force only, rate-limit aware)
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://<target> -t 4
```
**Findings:** SSH version, supported algorithms (weak MAC/cipher), password auth enabled, root login permitted.

### 3.2 Web (80/443/8080/8443)

```bash
# Server/tech fingerprint
whatweb -v <target>
curl -I <target>   # Server + X-Powered-By headers
# Headers security audit
nuclei -u <target> -tags headers,misconfig
# Directory listing check
curl -s <target>/ | head
```
**Findings:** server software+version (→ CVE lookup), missing security headers (HSTS, CSP, X-Frame-Options), directory listing, backup files, admin panels.

### 3.3 Database (3306/5432/27017/1433)

```bash
# MySQL banner
nc -vn <target> 3306
# MongoDB unauthenticated check
mongosh "mongodb://<target>:27017" --eval "db.runCommand({connectionStatus:1})"
# Redis unauthenticated
redis-cli -h <target> ping    # PONG = no auth
# PostgreSQL
psql -h <target> -U postgres -c "select version();"
```
**Findings:** Unauthenticated access (Critical), DB version → CVE, default accounts.

### 3.4 Remote Access (3389/5900/22)

```bash
# RDP info
nmap -p3389 --script=rdp-ntlm-info <target>
# VNC auth check
nmap -p5900 --script=vnc-info <target>
```
**Findings:** RDP exposed to internet (High), NLA disabled, weak VNC auth.

### 3.5 File/Print (21/445/139/2049)

```bash
# SMB null session
smbclient -L //<target>/ -N
enum4linux -a <target>
# NFS exports
showmount -e <target>
# FTP anonymous
ftp <target>  # try anonymous:anonymous
nmap -p21 --script=ftp-anon <target>
```
**Findings:** Null session (High), anonymous FTP/NFS (High), SMB signing disabled, guest share access.

### 3.6 SNMP (161/udp)

```bash
# Community string guessing (authorized)
onesixtyone <target>
snmpwalk -v2c -c public <target> system
# Full enum with credentials
snmp-check <target>
```
**Findings:** Default community strings (public/private) → full device config disclosure (Critical).

### 3.7 Container / Orchestration (2375/2376/6443/10250)

```bash
# Docker API unauthenticated
curl -s http://<target>:2375/containers/json
# K8s API unauthenticated
curl -sk https://<target>:6443/api/v1/namespaces
# Kubelet read-only
curl -sk https://<target>:10250/pods
```
**Findings:** Docker API without TLS (Critical — container escape path), unauthenticated K8s API/Kubelet (Critical).

---

## 4. Version → CVE Correlation

For every detected service version, run CVE correlation:

```bash
# Use searchsploit locally
searchsploit <software> <version>

# Online (if network access authorized)
curl "https://cve.circl.lu/api/search/<software>/<version>"

# NVD query
curl "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=<software>%20<version>"

# Nuclei with matched template
nuclei -u <target> -t ~/nuclei-templates/cves/ -severity high,critical
```

**Validation rule (R2):** A version finding is NOT a vulnerability finding. You must verify the CVE is:
1. Real for that exact version
2. Exploitable in this deployment (config-dependent CVEs are often false positives)
3. Deterministic PoC produced (or stated as "likely, PoC pending")

---

## 5. Server Hardening & Detection Checks (Misconfig Audit)

```bash
# Linux server posture (authorized assessment on target host)
# SSH hardening
grep -E "PermitRootLogin|PasswordAuthentication|Protocol" /etc/ssh/sshd_config
# Open ports (local)
ss -tulnp
# Unattended services
systemctl list-unit-files | grep enabled
# File permissions
ls -la /etc/shadow /etc/passwd
# World-writable files
find / -xdev -perm -0002 -type f 2>/dev/null
# SUID binaries
find / -xdev -perm -4000 -type f 2>/dev/null
# Cron jobs
ls -la /etc/cron* /var/spool/cron
# Running services as root
ps aux | grep -E "^root"
```

### Windows Server (authorized local assessment)
```powershell
# Security config
Get-HotFix | Sort-Object InstalledOn -Descending
Get-Service | Where-Object {$_.Status -eq "Running"}
Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa" -Name RestrictAnonymous
# Shares
net share
# Users
net user
# Unquoted service paths
wmic service get name,pathname | findstr /v "C:\Windows"
```

---

## 6. Automation & Tooling

```bash
# Server detection suite (one-shot)
nmap -sV -sC -O -p- <target> -oA server-detect
# Vuln scan
nuclei -u <target> -as -severity low,medium,high,critical -jsonl server-findings.jsonl
nikto -h <target> -C all
# OS + service inventory
masscan <target> -p1-65535 --rate=1000 -oG masscan.out
```

### Finding workflow
1. `nmap -sV -sC -O` → service inventory
2. For each service: banner → version → CVE lookup (searchsploit/nuclei/NVD)
3. Classify per §2 classes
4. Verify each candidate (R2) — never report version-only as vulnerability
5. Rate-limit aware credential tests only (see `skills/credential-attacks/hash-password-cracking.md`)

---

## 7. PoC Generation

```markdown
## [FINDING_ID] — Unauthenticated MongoDB
Class: exposed-service / default-creds
Host: 10.0.0.5:27017
Service: MongoDB 4.4 (mongod)
Mitre: T1046
Evidence:
  - redis-cli equivalent: mongosh "mongodb://10.0.0.5:27017" --eval "db.adminCommand({serverStatus:1})" -> SUCCESS (no auth)
  - Reproduced twice
Reproduction:
  1. mongosh "mongodb://10.0.0.5:27017"
  2. show dbs  ->  lists all databases
Impact: Full database read/write without credentials
Remediation: Enable auth (--auth), bind to private interface, firewall 27017
Confidence: confirmed
```

---

## 8. Verification (Sandbox)

- [ ] Service versions verified by independent banner grab
- [ ] CVE applicability confirmed against exact version
- [ ] Unauthenticated access reproduced twice
- [ ] No destructive commands on production (R3)
- [ ] Credential tests followed rate-limit policy (§9 RULE)
- [ ] Credentials, if recovered, hashed/redacted in report (R8)

---

## 9. Rate-Limit & Request Policy

Applies to any server-side credential or enumeration that generates requests:

1. **Detect** rate limiting: send probe, check for 429/TOO_MANY_REQUESTS, connection reset, or login lockout
2. **If rate limited:** honor it. Set request pacing to observed limit or below (e.g. if server allows 5 req/s, use max 4 req/s, never bypass without authorization)
3. **Hard cap:** no more than `--rate=1000` total requests/min against any service unless explicitly authorized
4. **Terminate** the attack if:
   - Lockout risk to real accounts detected
   - `429` responses exceed 5 consecutive
   - Target service degrades (R3 no-DoS)
5. Log observed rate limit thresholds into findings (valuable finding by itself)

---

## 10. Related Techniques (MITRE ATT&CK Mapping)

| Technique ID | Name | Relation |
|---|---|---|
| T1592 | Gather Victim Host Information | Host/OS fingerprint |
| T1592.002 | Software | Service/version detection |
| T1046 | Network Service Discovery | Service enumeration |
| T1190 | Exploit Public-Facing Application | Patch-gap exploitation |
| T1110 | Brute Force | Credential testing |
| T1059 | Command and Scripting Interpreter | Post-auth control |
| T1005 | Data from Local System | Data access findings |
| T1040 | Network Sniffing | Capture of cleartext services |

---

## 11. References

- MITRE ATT&CK T1592: https://attack.mitre.org/techniques/T1592/
- NVD: https://nvd.nist.gov/
- searchsploit: https://www.exploit-db.com/searchsploit
- OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- CIRCL CVE search API: https://cve.circl.lu/

---

*This playbook is for authorised security testing only. All active checks require the target to be in scope per R1. Credential testing must follow §9 rate-limit policy.*
