# Port Scanning — Skill Playbook

**Mitre ATT&CK ID:** T1046 (Network Service Scanning), T1590.005 (Active Scanning: Vulnerability Scanning)
**OWASP Mapping:** WSTG-INFO-01 — Fingerprint Web Server (reconnaissance analogue)
**Severity:** Informational (reconnaissance enabler)
**Last Updated:** 2026-08-02

---

## Metadata

```yaml
skill_id: port-scanning-v2
category: port-scanning
author: HiveBreach
mitre_attack_id: T1046
owasp_mapping:
  - WSTG-INFO-01
tags:
  - network-recon
  - port-scanning
  - host-discovery
  - nmap
  - masscan
  - naabu
  - rustscan
  - metasploit-portscan
  - T1046
  - T1590.005
tools:
  - nmap
  - masscan
  - naabu
  - rustscan
  - fping
  - arp-scan
  - metasploit
difficulty: beginner
verification_required: sandbox
```

---

## 1. Detection

### 1.1 Scope Definition

Before scanning, define the target scope and validate it against ROE (Rules of Engagement) and the scope-agent whitelist:

| Parameter | Example |
|---|---|
| Target CIDR | `10.10.10.0/24` |
| Target IP ranges | `192.168.1.1-250` |
| Target hostnames | `*.target.com` |
| Excluded IPs | `10.10.10.10` (production WAF) |
| Time window | `22:00-06:00 UTC` |
| Max rate | `500 pkts/sec` |
| Authorisation ref | `ROE-2026-042` |

### 1.2 Attack Surface Mapping

Port scanning answers three questions for every host in scope:

1. Which hosts are alive? (host discovery, T1590.001)
2. Which TCP ports are listening? (T1046)
3. Which UDP services are reachable? (T1046)

Priority services that indicate high-value targets:

| Port | Service | Priority |
|---|---|---|
| 21 | FTP | High |
| 22 | SSH | High |
| 23 | Telnet | Critical |
| 25 | SMTP | Medium |
| 53 | DNS | Medium |
| 80, 443, 8080, 8443 | HTTP/S | High |
| 135, 139, 445 | RPC / NetBIOS / SMB | High |
| 389, 636 | LDAP/S | Medium |
| 1433 | MSSQL | High |
| 1521 | Oracle | High |
| 2049 | NFS | High |
| 3306 | MySQL | High |
| 3389 | RDP | Critical |
| 5432 | PostgreSQL | High |
| 5985, 5986 | WinRM | High |
| 6379 | Redis | High |
| 9200 | Elasticsearch | Medium |
| 27017 | MongoDB | High |

### 1.3 Scan Strategy Selection

| Positioning | Recommended | Rationale |
|---|---|---|
| Internal (trusted) | SYN scan, `-T4`, full ports | Speed, accuracy |
| External (targeted) | SYN, top 1000, `-T3` | Lower noise, rate limits |
| External (HTB/CTF) | Connect scan `-sT` | Unprivileged user |
| Firewalled | FIN/XMAS/NULL + ACK + UDP | Map filtering rules |
| Large ranges | masscan / naabu | 10k+ pkts/sec |

---

## 2. Confirmation

### 2.1 Verify Host Liveness

```bash
nmap -sn -T4 -n <cidr>                 # ICMP + TCP/443,80 + ACK probes
nmap -sn -PS22,80,443 -n <cidr>        # TCP SYN discovery only
fping -a -g 192.168.1.0/24             # Fast ICMP echo sweep
arp-scan --localnet                    # ARP layer-2 discovery (same subnet)
```

### 2.2 Confirm Open Ports (multi-method)

A port found by one technique must be confirmed with a second, independent method:

```bash
# Method 1: SYN scan
sudo nmap -sS -p- -T4 --min-rate 1000 <target>
# Method 2: Connect scan (confirmation)
nmap -sT -p <open_ports> <target>
# Method 3: Manual
nc -zv <target> <port>
```

### 2.3 False Positive Reduction

- UDP: retry with `--max-retries 3`; a service that never answers but is filtered shows `open|filtered`.
- `open|filtered` states require an explicit response (banner, version probe) before acceptance.
- Cross-check firewall-only responses: if `-sA` shows all ports `filtered`, assume an ACL is dropping probes.
- Compare against scope document; drop out-of-scope hosts.

---

## 3. Exploitation

### 3.1 Scan Technique Matrix

| Technique | Flag | Probe | Behaviour | Use Case |
|---|---|---|---|---|
| TCP Connect | `-sT` | Full handshake | Open=SYN-ACK; logged by apps; no root needed | Unprivileged scan |
| SYN (half-open) | `-sS` | SYN, RST on SYN-ACK | Open=SYN-ACK; fast; needs root | Default privileged scan |
| UDP | `-sU` | Empty UDP | No response=open/filtered; ICMP unreachable=closed | DNS, SNMP, TFTP, NTP |
| FIN | `-sF` | FIN only | Closed=RST; open=no reply | Evade stateless firewalls |
| NULL | `-sN` | No flags | Closed=RST; open=no reply | Evade non-RFC filters |
| XMAS | `-sX` | FIN+PSH+URG | Closed=RST; open=no reply | Evade filters |
| ACK | `-sA` | ACK only | RST from unfiltered; no reply=filtered | Map firewall rulesets |
| Window | `-sW` | ACK with window | RST window size distinguishes open/closed | MS-only edge cases |
| Idle | `-sI <zombie>` | Spoofed via zombie | Stealthy blind scan; slow | High-opsec scans |

### 3.2 OS Fingerprinting

```bash
nmap -O --osscan-guess -p <open_ports> <target>   # Active OS detection
nmap -A -Pn -p <open_ports> <target>              # Aggressive (-O -sV -sC + traceroute)
# Passive TTL analysis (see host-discovery playbook for TTL table)
```

### 3.3 Firewall / IDS Evasion

```bash
# Fragmentation
nmap -f <target>                                  # 8-byte fragments
nmap -ff <target>                                 # 16-byte fragments
nmap --mtu 24 <target>                            # Custom MTU

# Decoys
nmap -D RND:10 <target>                           # 10 random decoy source IPs
nmap -D <decoy1>,<decoy2>,ME <target>

# Source port / IP manipulation
nmap -g 53 <target>                               # Use source port 53 (DNS)
nmap -S <spoofed-ip> <target>                     # One-way spoofed source
nmap --spoof-mac 00:11:22:33:44:55 <target>       # MAC spoofing

# Packet padding / timing
nmap --data-length 50 <target>                    # Alters packet fingerprint
nmap --scan-delay 100ms <target>                  # Rate reduction
nmap -T0 <target>                                 # Paranoid timing

# Proxy traversal
nmap --proxies http://proxy:8080 <target>         # SOCKS/HTTP chain
proxychains nmap -sT -Pn -p <ports> <target>
```

### 3.4 T1590.005 — Vulnerability Scanning Handoff

Feed open ports into `nmap -sV -sC`, then match against CVEs and hand off to the vuln-scan-agent:

```bash
nmap -sV -sC --version-intensity 9 -p <ports> -oA scan/service <target>
# Correlate with: searchsploit <service> <version>
#                nuclei -u <target> -t ~/nuclei-templates/
```

---

## 4. Tool-Guidance

### 4.1 nmap Flags Quick Reference

| Flag | Purpose |
|---|---|
| `-sS` / `-sT` / `-sU` / `-sF` / `-sX` / `-sN` / `-sA` / `-sI` | Scan type (SYN/Connect/UDP/FIN/XMAS/NULL/ACK/Idle) |
| `-O` | OS fingerprinting |
| `-sV` | Service version detection |
| `-sC` | Default safe NSE scripts |
| `-A` | Aggressive (`-O -sV -sC --traceroute`) |
| `-Pn` | Skip host discovery (assume alive) |
| `-n` | No DNS resolution |
| `-p-` / `-p <list>` / `--top-ports <n>` | Port selection |
| `--min-rate` / `--max-rate` | Probe rate control |
| `-T0..-T5` | Timing templates (paranoid..insane) |
| `-f` / `--mtu` | Fragmentation |
| `-D` | Decoy sources |
| `-g` | Source port |
| `-oA` / `-oN` / `-oG` / `-oX` / `-oS` | Output all/normal/grepable/XML/script-kiddie |

**Workflow:**
```bash
# Phase 1 — broad sweep
sudo nmap -sS -T4 -Pn -n --top-ports 1000 -oA scan/tcp_quick <cidr>
# Phase 2 — full TCP
sudo nmap -sS -T4 -Pn -n -p- --min-rate 1000 -oA scan/tcp_full <live>
# Phase 3 — UDP sampling
sudo nmap -sU -T4 -Pn -n --top-ports 50 -oA scan/udp_quick <live>
# Phase 4 — service + scripts
nmap -sV -sC -Pn -n -p <open_ports> -oA scan/service <target>
# Phase 5 — deep dive
sudo nmap -A -Pn -n -p <open_ports> -oA scan/deep <target>
```

### 4.2 masscan — High-Speed Scanner

```bash
sudo masscan -p1-65535 --rate=1000 -oL scan/masscan_tcp.txt <target>
sudo masscan -p80,443,22,3389 --rate=500 --excludefile exclude.txt -oL scan/web.txt <target>
# grepable output piped straight into nmap
sudo masscan -p80,443 --rate=1000 -oG scan/masscan.gnmap <target>
nmap -sV -sC -iL <(grep open scan/masscan.gnmap | awk '{print $2}') -p80,443
```

### 4.3 naabu — Fast Subdomain/Port Scanner (ProjectDiscovery)

```bash
naabu -host <target> -top-ports 1000 -o scan/naabu_tcp.txt
naabu -host <target> -p - -o scan/naabu_full.txt        # All 65535 ports
naabu -list targets.txt -top-ports 1000 -silent
naabu -host <target> -p 80,443,8443 -nmap-cli -sV       # Auto-nmap handoff
```

### 4.4 rustscan — Parallel with nmap Integration

```bash
rustscan -a <target> --range 1-65535 -- -sV -sC
rustscan -a <target> --batch-size 1500 -b 1000 -- -Pn -sV
```

### 4.5 Metasploit Portscan Modules

```bash
msfconsole -q -x 'use auxiliary/scanner/portscan/syn; set RHOSTS <target>; set PORTS 1-65535; set THREADS 50; run'
msfconsole -q -x 'use auxiliary/scanner/portscan/tcp; set RHOSTS <target>; set PORTS 22,80,443; run'
msfconsole -q -x 'use auxiliary/scanner/portscan/ack; set RHOSTS <target>; run'
msfconsole -q -x 'use auxiliary/scanner/portscan/xmas; set RHOSTS <target>; run'
# Portmap / RPC endpoint discovery
msfconsole -q -x 'use auxiliary/scanner/portmap/portmap_amp; set RHOSTS <target>; run'
```

---

## 5. PoC Generation

### 5.1 Full Port-Scan Workflow (single PoC)

```bash
# 1. Discovery
nmap -sn -T4 -n 10.10.10.0/24 -oG scan/discover.gnmap
grep -E 'Status: Up' scan/discover.gnmap | awk '{print $2}' > scan/live_hosts.txt

# 2. Full TCP sweep of live hosts
sudo nmap -sS -T4 -Pn -n -p- --min-rate 1000 -iL scan/live_hosts.txt -oG scan/tcp_all.gnmap

# 3. Extract open ports per host
grep -oP '\d+/open/tcp' scan/tcp_all.gnmap | cut -d/ -f1 | sort -un > scan/open_ports.txt

# 4. Service identification on merged port list
nmap -sV -sC -Pn -n -p $(paste -sd, scan/open_ports.txt) -iL scan/live_hosts.txt -oA scan/services

# 5. UDP focused on high-value services
sudo nmap -sU -Pn -n -p 53,69,123,161,162,500,623,1645,1900,5353 -iL scan/live_hosts.txt -oA scan/udp_high

# 6. Machine-readable merge
nmap -oX scan/final.xml scan/services.xml scan/udp_high.xml
```

### 5.2 Findings Template

```yaml
# scan/results.yaml
scan:
  id: PORT-2026-042
  scope: 10.10.10.0/24
  tools: [nmap 7.94, masscan 1.3.2]
hosts:
  - ip: 10.10.10.50
    state: up
    tcp_open: [22, 80, 443, 3306, 6379]
    udp_open: [161]
    os_guess: Linux
    confidence: medium
```

---

## 6. Verification (Sandbox)

- [ ] Every reported open port confirmed by a second scan method or manual connect
- [ ] UDP `open|filtered` states retried with higher retries before acceptance
- [ ] Scope boundaries re-validated (no out-of-scope IP/port in output)
- [ ] Rate limits respected per environment (see Cheat Sheet)
- [ ] Results stored in XML/JSON machine-readable format
- [ ] OS fingerprint consistent with known open ports (e.g., Windows + 135/139/445)

**Prohibited:** scanning out-of-scope infrastructure, spoofing scans into third-party networks, DoS-triggering `-sI` on unowned zombies, `--min-rate` above authorised ceilings.

---

## 7. Cheat Sheet Reference

### 7.1 Timing / Rate by Environment

| Environment | Template | Rate | Notes |
|---|---|---|---|
| Internal lab | `-T4` | 10,000 pkt/s | Unconstrained |
| External (fast) | `-T4` | 1,000 pkt/s | `--max-rate 1000` |
| External (medium) | `-T3` | 500 pkt/s | Default |
| External (slow) | `-T1/-T2` | 100 pkt/s | `--scan-delay 1s` |
| Production / WAF | `-T0/-T1` | 10 pkt/s | `-D` decoys + `-g 53` |

### 7.2 NSE Scripts for Enumeration

```bash
nmap -sC -p <ports> <target>                                  # Default safe set
nmap --script=default,safe -p <ports> <target>
nmap --script="banner,version,*-enum-*" -p <ports> <target>   # Enumeration class
nmap --script=http-title,http-headers,http-methods -p 80,443 <target>
nmap --script=ssh2-enum-algos,ssh-auth-methods -p 22 <target>
nmap --script=smb-enum-shares,smb-enum-users,smb-os-discovery -p 139,445 <target>
nmap --script=smb-vuln-* -p 139,445 <target>                  # Vuln class
nmap --script=dns-zone-transfer,dns-recursion -p 53 <target>
nmap --script=snmp-info,snmp-processes -sU -p 161 <target>
```

### 7.3 Evasion Cheat Sheet

| Goal | Command |
|---|---|
| Fragment | `-f` or `-ff` |
| Decoy | `-D RND:10` |
| Source port | `-g 53` |
| Spoofed source (one-way) | `-S <ip>` |
| Idle scan | `-sI <zombie>` |
| Slow jitter | `-T1 --scan-delay 1000ms` |
| Packet padding | `--data-length 50` |
| Proxy chain | `--proxies <url>` |

---

## 8. Related Techniques (MITRE ATT&CK Mapping)

| Technique ID | Name | Relation |
|---|---|---|
| T1046 | Network Service Scanning | Core technique |
| T1590.001 | Active Scanning: Scanning IP Blocks | Host discovery |
| T1590.005 | Active Scanning: Vulnerability Scanning | Version/CVE handoff |
| T1595.001 | Active Scanning: Scanning IP Blocks | Reconnaissance goal |
| T1018 | Remote System Discovery | Identify reachable systems |
| T1190 | Exploit Public-Facing Application | Post-scan exploitation |

---

## 9. References

- nmap reference guide: https://nmap.org/docs.html
- nmap NSE documentation: https://nmap.org/nsedoc/
- nmap port scanning techniques: https://nmap.org/book/man-port-scanning-techniques.html
- masscan GitHub: https://github.com/robertdavidgraham/masscan
- naabu: https://github.com/projectdiscovery/naabu
- rustscan: https://github.com/RustScan/RustScan
- MITRE ATT&CK T1046: https://attack.mitre.org/techniques/T1046/
- MITRE ATT&CK T1590.005: https://attack.mitre.org/techniques/T1590/005/
- Metasploit scanner/portscan modules: https://github.com/rapid7/metasploit-framework/tree/master/modules/auxiliary/scanner/portscan

---

*This playbook is for authorised security testing only. Review scope and obtain written authorisation before scanning. All verification must occur in sandbox environments.*
