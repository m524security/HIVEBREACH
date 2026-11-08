# Service Enumeration — Skill Playbook

**Mitre ATT&CK ID:** T1046 (Network Service Scanning), T1018 (Remote System Discovery)
**OWASP Mapping:** WSTG-INFO-01 — Fingerprint Web Server (banner/tech fingerprinting)
**Severity:** Informational (attack-surface intelligence)
**Last Updated:** 2026-08-02

---

## Metadata

```yaml
skill_id: service-enumeration-v2
category: service-enum
author: HiveBreach
mitre_attack_id: T1046
owasp_mapping:
  - WSTG-INFO-01
tags:
  - service-enumeration
  - fingerprinting
  - banner-grabbing
  - smb
  - ssh
  - ftp
  - http
  - dns
  - snmp
  - smtp
  - ldap
  - mysql
  - redis
  - rdp
  - nfs
  - metasploit-scanner
  - T1046
  - T1018
tools:
  - nmap
  - netcat
  - openssl
  - curl
  - whatweb
  - nikto
  - enum4linux
  - crackmapexec
  - smbclient
  - ssh-audit
  - snmpwalk
  - onesixtyone
  - dig
  - dnsrecon
  - smtp-user-enum
  - ldapsearch
  - mysql
  - psql
  - redis-cli
  - showmount
  - metasploit
difficulty: beginner
verification_required: sandbox
```

---

## 1. Detection

### 1.1 From Port Scan to Service Identification

Port scanning (T1046) identifies listening ports; service enumeration answers **what** runs there. Every open port gets:

1. A banner or version signature
2. Protocol-specific enumeration
3. A check for default/empty credentials (sandbox only)
4. A Metasploit auxiliary module where applicable

### 1.2 Service Priority Triage

| Service | Port(s) | Default-Cred Risk | RCE Potential |
|---|---|---|---|
| SMB | 139, 445 | High | EternalBlue, SMBGhost |
| RDP | 3389 | Medium | BlueKeep |
| SSH | 22 | High | Weak keys, backdoors |
| FTP | 21 | High (anon) | Webroot upload |
| Redis | 6379 | High (no auth) | config set dir RCE |
| MongoDB | 27017 | High (no auth) | Full DB dump |
| NFS | 2049 | High | no_root_squash |
| SNMP | 161/udp | High (public) | MIB data leak |
| MySQL/PG | 3306/5432 | Medium | UDF / COPY PROGRAM |
| SMTP | 25 | Low | Relay, user enum |
| LDAP | 389/636 | Low | Anonymous bind |
| DNS | 53 | Low | Zone transfer |
| Docker API | 2375/2376 | Critical | Container escape |

---

## 2. Confirmation

### 2.1 Banner Grabbing (multi-method)

```bash
# TCP banner
nc -nv <target> <port>
echo "" | nc -nv <target> <port>
timeout 5 nc -nv <target> <port>
telnet <target> <port>          # May require CRLF: use nc -C
printf "HEAD / HTTP/1.0\r\n\r\n" | nc -nv <target> 80

# TLS services
openssl s_client -connect <target>:443 -servername <hostname>
openssl s_client -connect <target>:<port> -quiet 2>/dev/null | head -c 500

# HTTP headers
curl -sI https://<target>
curl -s -v https://<target> 2>&1 | grep '< '
```

### 2.2 Automated Version Confirmation

```bash
nmap -sV --version-intensity 9 -p <ports> -oA scan/banners <target>
nmap -sV --script banner -p <ports> <target>
# Cross-check manual banner against nmap result before recording
```

---

## 3. Exploitation

### 3.1 SMB (139, 445) — HackTricks-derived enumeration

```bash
# Version + vuln checks
nmap -p 139,445 -sV -sC <target>
nmap --script smb-vuln-* -p 139,445 <target>
nmap --script smb2-capabilities,smb2-security-mode -p 445 <target>

# Full enum4linux
enum4linux -a <target>
enum4linux-ng -A <target>
enum4linux -U <target>    # Users
enum4linux -S <target>    # Shares
enum4linux -G <target>    # Groups
enum4linux -P <target>    # Password policy

# Shares + null sessions
smbclient -L //<target> -N
smbmap -H <target> -u null -p null
crackmapexec smb <target> -u '' -p '' --shares
crackmapexec smb <target> -u '' -p '' --pass-pol -M spider_plus

# RPC null session
rpcclient -U "" -N <target>
rpcclient> enumdomusers
rpcclient> querydispinfo

# Users / groups / logged-on
crackmapexec smb <target> -u '' -p '' --users --groups --sessions
/usr/share/doc/python3-impacket/examples/samrdump.py -port 445 <target>
/usr/share/doc/python3-impacket/examples/lookupsid.py -no-pass <target>
```

### 3.2 SSH (22)

```bash
nc -nv <target> 22                                # Banner
ssh-audit <target>                                # Algorithm + CVE audit
nmap -p 22 --script ssh2-enum-algos,ssh-hostkey,ssh-auth-methods <target>
ssh-keyscan -t rsa <target>                       # Host key capture
# Weak/backdoored keys noted for later exploitation
nmap -p 22 --script ssh-auth-methods --script-args ssh.user=root <target>
```

### 3.3 FTP (21)

```bash
nc -vn <target> 21                                # Banner
openssl s_client -connect <target>:21 -starttls ftp   # TLS-wrapped FTP
nmap --script ftp-* -p 21 <target>                # anon + bounce checks
# Anonymous login
ftp <target>
> anonymous
> anonymous
> ls -a
# Upload test (anonymous write)
> put /tmp/test.txt
# Full mirror
wget -m ftp://anonymous:anonymous@<target>
```

### 3.4 HTTP/HTTPS (80, 443, 8080, 8443)

```bash
# Fingerprinting
nmap --script http-server-header,http-title,http-tech-detect -p80,443 <target>
whatweb -v https://<target>
curl -sI https://<target> | grep -iE 'server|x-powered-by|set-cookie'
# Certificate
openssl s_client -connect <target>:443 -servername <hostname> </dev/null 2>/dev/null | openssl x509 -text

# Content discovery
gobuster dir -u https://<target> -w /usr/share/wordlists/dirb/common.txt -t 50
ffuf -u https://<target>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -fc 403,404

# Metadata / hidden paths
curl -s https://<target>/robots.txt
curl -s https://<target>/.well-known/security.txt

# Vulnerability scan
nikto -h https://<target>
```

### 3.5 DNS (53)

```bash
# Zone transfer
dig axfr @<target> <domain>
nmap -p 53 --script dns-zone-transfer <target>
# Enumeration
dnsrecon -d <domain> -t axfr
dnsrecon -d <domain> -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t brt
subfinder -d <domain> -o subdomains.txt
nmap -p 53 --script dns-recursion,dns-nsec-enum,dns-brute <target>
# Open resolver check (amplification)
dig @<target> <domain> ANY
```

### 3.6 SNMP (161/udp)

```bash
# Community string discovery
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt <target>
# MIB walks (public community)
snmpwalk -v2c -c public <target>
snmpbulkwalk -c public -v2c <target> .
snmpwalk -v2c -c public <target> 1.3.6.1.2.1.1.5        # Hostname
snmpwalk -v2c -c public <target> 1.3.6.1.2.1.1.1        # System description
snmpwalk -v2c -c public <target> 1.3.6.1.2.1.25.4.2.1.2 # Running processes
snmpwalk -v2c -c public <target> 1.3.6.1.2.1.25.6.3.1.2 # Installed software
snmpwalk -v2c -c public <target> 1.3.6.1.2.1.2.2.1.2    # Network interfaces
# nmap
nmap -sU -p 161 --script snmp-info,snmp-sysdescr,snmp-processes <target>
```

### 3.7 SMTP (25, 465, 587)

```bash
nc -nv <target> 25
EHLO target.com
VRFY root                 # User enumeration
EXPN postmaster           # Alias expansion
# Automated user enumeration
nmap -p 25 --script smtp-enum-users,smtp-commands,smtp-ntlm-info <target>
smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/top-usernames-shortlist.txt -t <target>
# Relay check
nmap -p 25 --script smtp-open-relay <target>
```

### 3.8 LDAP (389, 636)

```bash
nmap --script ldap-rootdse -p389 <target>
ldapsearch -x -H ldap://<target> -b "" -s base namingContexts
ldapsearch -x -H ldap://<target> -b "dc=<domain>,dc=<com>" "(objectclass=*)"
ldapdomaindump ldap://<target> -u '' -p ''    # Anonymous bind dump
```

### 3.9 Databases

**MySQL (3306):**
```bash
nmap --script mysql-enum,mysql-info,mysql-users,mysql-databases -p3306 <target>
mysql -h <target> -u root                          # Empty password
mysql -h <target> -u root -p
```

**MSSQL (1433):**
```bash
nmap --script ms-sql-info,ms-sql-ntlm-info,ms-sql-empty-password -p1433 <target>
sqsh -S <target> -U sa -P ''
```

**PostgreSQL (5432):**
```bash
nmap --script pgsql-brute -p5432 <target>
psql -h <target> -U postgres                        # Empty password
```

**Oracle (1521):**
```bash
nmap --script oracle-sid-brute,oracle-brute-stealth -p1521 <target>
```

### 3.10 Redis (6379)

```bash
nmap --script redis-info -sV -p 6379 <target>
redis-cli -h <target> INFO                          # No-auth check
redis-cli -h <target> CONFIG GET dir                # Find writable path
redis-cli -h <target> KEYS '*'
redis-cli -h <target> ACL WHOAMI                    # Redis 6+ identity
```

### 3.11 MongoDB (27017)

```bash
nmap --script mongodb-databases,mongodb-info -p27017 <target>
mongosh "mongodb://<target>:27017"
show dbs
use admin
db.getUsers()
```

### 3.12 RDP (3389)

```bash
nmap --script rdp-enum-encryption,rdp-ntlm-info,rdp-vuln-ms12-020 -p3389 <target>
# NLA requirement check
nmap --script rdp-ntlm-info -p3389 <target> | grep NLA
# BlueKeep check
msfconsole -q -x 'use auxiliary/scanner/rdp/cve_2019_0708_bluekeep; set RHOSTS <target>; run'
```

### 3.13 NFS (2049)

```bash
nmap --script nfs-ls,nfs-showmount,nfs-statfs -p2049 <target>
showmount -e <target>
mount -t nfs <target>:/<share> /mnt/nfs -o nolock,vers=2
# UID/GID impersonation: create local user with target uid to read files
```

### 3.14 Kerberos (88)

```bash
nmap --script krb5-enum-users -p88 <target>
kerbrute userenum -d <domain> --dc <target> /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```

---

## 4. Tool-Guidance

### 4.1 Metasploit auxiliary/scanner modules per service

```bash
# SMB
msfconsole -q -x 'use auxiliary/scanner/smb/smb_version; set RHOSTS <target>; run'
msfconsole -q -x 'use auxiliary/scanner/smb/smb_enumshares; set RHOSTS <target>; run'
msfconsole -q -x 'use auxiliary/scanner/smb/smb_enumusers; set RHOSTS <target>; run'
msfconsole -q -x 'use auxiliary/scanner/smb/smb_lookupsid; set RHOSTS <target>; run'
msfconsole -q -x 'use auxiliary/scanner/smb/smb_ms17_010; set RHOSTS <target>; run'

# SSH
msfconsole -q -x 'use auxiliary/scanner/ssh/ssh_version; set RHOSTS <target>; run'
msfconsole -q -x 'use auxiliary/scanner/ssh/ssh_enumusers; set RHOSTS <target>; run'

# FTP
msfconsole -q -x 'use auxiliary/scanner/ftp/ftp_version; set RHOSTS <target>; run'
msfconsole -q -x 'use auxiliary/scanner/ftp/ftp_anonymous; set RHOSTS <target>; run'

# SNMP
msfconsole -q -x 'use auxiliary/scanner/snmp/snmp_login; set RHOSTS <target>; run'
msfconsole -q -x 'use auxiliary/scanner/snmp/snmp_enum; set RHOSTS <target>; run'
msfconsole -q -x 'use auxiliary/scanner/snmp/snmp_enumusers; set RHOSTS <target>; run'

# SMTP
msfconsole -q -x 'use auxiliary/scanner/smtp/smtp_version; set RHOSTS <target>; run'
msfconsole -q -x 'use auxiliary/scanner/smtp/smtp_enum; set RHOSTS <target>; run'
msfconsole -q -x 'use auxiliary/scanner/smtp/smtp_relay; set RHOSTS <target>; run'

# LDAP
msfconsole -q -x 'use auxiliary/scanner/ldap/ldap_login; set RHOSTS <target>; run'

# Databases
msfconsole -q -x 'use auxiliary/scanner/mysql/mysql_version; set RHOSTS <target>; run'
msfconsole -q -x 'use auxiliary/scanner/mysql/mysql_login; set RHOSTS <target>; run'
msfconsole -q -x 'use auxiliary/scanner/postgres/postgres_version; set RHOSTS <target>; run'
msfconsole -q -x 'use auxiliary/scanner/postgres/postgres_login; set RHOSTS <target>; run'
msfconsole -q -x 'use auxiliary/scanner/mssql/mssql_version; set RHOSTS <target>; run'

# Redis / MongoDB
msfconsole -q -x 'use auxiliary/scanner/redis/redis_server; set RHOSTS <target>; run'
msfconsole -q -x 'use auxiliary/scanner/redis/redis_login; set RHOSTS <target>; run'
msfconsole -q -x 'use auxiliary/scanner/mongodb/mongodb_login; set RHOSTS <target>; run'

# RDP / NFS / DNS / RPC
msfconsole -q -x 'use auxiliary/scanner/rdp/rdp_scanner; set RHOSTS <target>; run'
msfconsole -q -x 'use auxiliary/scanner/nfs/nfsmount; set RHOSTS <target>; run'
msfconsole -q -x 'use auxiliary/scanner/dns/dns_amp; set RHOSTS <target>; run'
msfconsole -q -x 'use auxiliary/scanner/dcerpc/endpoint_mapper; set RHOSTS <target>; run'
msfconsole -q -x 'use auxiliary/scanner/netbios/nbname; set RHOSTS <target>; run'

# IPMI
msfconsole -q -x 'use auxiliary/scanner/ipmi/ipmi_version; set RHOSTS <target>; run'
msfconsole -q -x 'use auxiliary/scanner/ipmi/ipmi_dumphashes; set RHOSTS <target>; run'

# Telnet / WinRM
msfconsole -q -x 'use auxiliary/scanner/telnet/telnet_version; set RHOSTS <target>; run'
msfconsole -q -x 'use auxiliary/scanner/winrm/winrm_auth_methods; set RHOSTS <target>; run'
```

---

## 5. PoC Generation

### 5.1 Enumeration Output Format

```yaml
# scan/service_enum/<ip>.yaml
host: 10.10.10.50
os: Linux (Ubuntu 22.04)
ports:
  - port: 22
    service: SSH
    version: OpenSSH 8.9p1
    banner: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3
    notes: [ssh-auth-methods ok, no weak algos]
  - port: 80
    service: HTTP
    version: Apache 2.4.52
    tech: [PHP 8.1, Laravel, jQuery 3.6]
    headers:
      Server: Apache/2.4.52 (Ubuntu)
  - port: 445
    service: SMB
    version: Samba 4.15
    shares: [public(R), staff(RW), IPC$(R)]
    users: [admin, backup]
    null_session: true
  - port: 6379
    service: Redis
    version: 5.0.7
    auth_required: false
    keyspaces:
      db0: 12
```

### 5.2 PoC Checklist per service

```markdown
## Service Enum — [HOST:PORT]

- [ ] Banner captured (nc/telnet + nmap -sV agreement)
- [ ] Version mapped to CVE/exploit (searchsploit, NVD)
- [ ] Protocol-specific enumeration performed
- [ ] Default/empty credentials tested (sandbox)
- [ ] Metasploit auxiliary module run
- [ ] Findings written to YAML/JSON
```

---

## 6. Verification (Sandbox)

- [ ] Every service banner confirmed by at least two independent methods
- [ ] SMB shares confirmed by actual connection, not just listing
- [ ] FTP anonymous write verified with create+delete test file
- [ ] SNMP info verified against at least 3 MIB values
- [ ] LDAP attributes match expected directory structure
- [ ] Default credential tests only in sandbox/authorised lab
- [ ] No destructive actions performed during enumeration

**Prohibited:** password brute-force against production accounts, write operations on production shares, zone-transfer abuse beyond scope.

---

## 7. Cheat Sheet Reference

### 7.1 Default Credentials

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

### 7.2 Common SNMP Community Strings

```
public private manager admin monitor community cisco secret
```

### 7.3 High-Value SNMP OIDs

| OID | Data |
|---|---|
| `1.3.6.1.2.1.1.1` | System description |
| `1.3.6.1.2.1.1.5` | Hostname |
| `1.3.6.1.2.1.2.2.1.2` | Interfaces |
| `1.3.6.1.2.1.4.20.1.2` | IP routing table |
| `1.3.6.1.2.1.6.13.1.3` | Open TCP ports |
| `1.3.6.1.2.1.25.4.2.1.2` | Running processes |
| `1.3.6.1.2.1.25.6.3.1.2` | Installed software |

### 7.4 Common SMB Share Names

```
C$ D$ ADMIN$ IPC$ PRINT$ FAX$ SYSVOL NETLOGON
```

---

## 8. Related Techniques (MITRE ATT&CK Mapping)

| Technique ID | Name | Relation |
|---|---|---|
| T1046 | Network Service Scanning | Core technique |
| T1018 | Remote System Discovery | Discover systems/services |
| T1590.005 | Active Scanning: Vulnerability Scanning | Version-to-CVE mapping |
| T1190 | Exploit Public-Facing Application | Handoff to exploitation |
| T1021.002 | Remote Services: SMB/Windows Admin Shares | Post-auth access |

---

## 9. References

- HackTricks network-services-pentesting: https://book.hacktricks.wiki/en/network-services-pentesting/
- enum4linux: https://github.com/CiscoCXSecurity/enum4linux
- Impacket tools: https://github.com/fortra/impacket
- ssh-audit: https://github.com/jtesta/ssh-audit
- Metasploit scanner modules: https://github.com/rapid7/metasploit-framework/tree/master/modules/auxiliary/scanner
- MITRE ATT&CK T1046: https://attack.mitre.org/techniques/T1046/
- MITRE ATT&CK T1018: https://attack.mitre.org/techniques/T1018/
- OWASP WSTG Fingerprint Web Server: https://owasp.org/www-project-web-security-testing-guide/

---

*This playbook is for authorised security testing only. All verification must occur in sandbox environments.*
