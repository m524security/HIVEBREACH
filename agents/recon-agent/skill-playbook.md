---
skill: network-reconnaissance-deep-aggressive
mitre_attack_id: T1046
owasp_mapping: []
difficulty: advanced
tags: [network-discovery, port-scanning, service-fingerprinting, host-discovery, evasion, deep-aggressive-mode]
---
## Summary
Deep Aggressive Mode network reconnaissance to identify live hosts, open ports, and running services across target IP ranges. Employs full-port scanning, high-throughput tools, decoy-based evasion, fragmented packets, and multi-tool cross-verification to establish the complete network footprint for downstream exploitation agents. Authorized-engagement only; every command must respect the rate ceilings and exclusion lists supplied by scope-agent.

Skill library references:
- skills/port-scanning/skill-playbook.md
- skills/network-security/host-discovery.md
- skills/network-security/port-scanning.md

## Phase 0 — Scope & Environment Prep
1. Receive approved target scope from scope-agent (CIDR ranges, IP lists, exclusions, max rate)
2. Record the ROE authorization reference and time window in the audit trail
3. Identify attacker interface and source address; confirm privileges (SYN requires root)
4. Create working directory structure: `mkdir -p scan/{hosts,tcp,udp,services,os}`
5. Load exclusion list into every tool: `--excludefile exclude.txt` (masscan), `--exclude` (nmap)
6. Confirm the deep-aggressive mode activation flag from scheduler-agent before starting full-port sweeps

## Phase 1 — Aggressive Host Discovery
Layer-2 and layer-3 sweep, ICMP-block bypass, and multi-probe confirmation:
```bash
# ARP (same subnet, ignores ICMP filtering, fastest)
sudo arp-scan -I eth0 10.10.10.0/24 | awk '{print $1}' | grep -E '^[0-9]' > scan/hosts/arp.txt
sudo nmap -PR -sn -n 10.10.10.0/24 -oG scan/hosts/arp.gnmap

# ICMP multi-probe sweep (echo + timestamp + address-mask bypass filters)
nmap -sn -PE -PP -PM -T4 -n 10.10.10.0/24 -oG scan/hosts/icmp.gnmap

# TCP/UDP probe sweep for ICMP-blocked hosts
nmap -sn -PS21,22,25,53,80,110,135,139,443,445,3389 -PA80,443 -PU53,123,161 -T4 -n 10.10.10.0/24 -oG scan/hosts/tcp.gnmap

# Fast fping fallback
fping -a -g 10.10.10.0/24 -r 0 2>/dev/null > scan/hosts/fping.txt

# Merge, deduplicate, sanitize against scope
cat scan/hosts/*.txt | sort -u > scan/hosts/live_raw.txt
comm -12 scan/hosts/live_raw.txt scan/hosts/scope_ips.txt > scan/hosts/live_hosts.txt
```
Every host must be confirmed by at least two independent probe types before it is added to the live list.

## Phase 2 — Full TCP Port Sweep (Deep Aggressive)
Complete 65535-port SYN sweep across all live hosts at high rate:
```bash
# Full range, aggressive rate (respect ROE ceiling)
sudo nmap -sS -T4 -Pn -n -p- --min-rate 1000 -iL scan/hosts/live_hosts.txt -oG scan/tcp/tcp_all.gnmap

# Extract open ports per host
grep -oP '\d+/open/tcp' scan/tcp/tcp_all.gnmap | cut -d/ -f1 | sort -un > scan/tcp/open_ports.txt

# Confirm each open port with a second method
nmap -sT -Pn -p $(paste -sd, scan/tcp/open_ports.txt) -iL scan/hosts/live_hosts.txt -oA scan/tcp/tcp_confirm
nc -zv <target> <port>   # spot-check sample
```
Ports reported by only one technique are flagged low-confidence until confirmed.

## Phase 3 — UDP High-Value Sweep
```bash
# Focused UDP on high-value services
sudo nmap -sU -T4 -Pn -n -p 53,69,123,137,138,161,162,500,514,623,1645,1900,4500,5353 -iL scan/hosts/live_hosts.txt -oA scan/udp/udp_high

# Retry open|filtered states for acceptance
sudo nmap -sU -T4 -Pn -n --max-retries 3 -p <open_filtered_ports> <target>
```
open|filtered UDP requires an explicit service response (banner, version probe) before acceptance.

## Phase 4 — Service Version Detection
```bash
# Deep version probing with default NSE scripts
nmap -sV -sC --version-intensity 9 -Pn -n -p $(paste -sd, scan/tcp/open_ports.txt) -iL scan/hosts/live_hosts.txt -oA scan/services/services

# Extended enumeration NSE classes
nmap --script="banner,version,*-enum-*" -Pn -n -p $(paste -sd, scan/tcp/open_ports.txt) <target>
nmap --script=http-title,http-headers,http-methods,http-tech-detect -p 80,443 <target>
nmap --script=ssh2-enum-algos,ssh-auth-methods -p 22 <target>
nmap --script=smb-enum-shares,smb-enum-users,smb-os-discovery,smb2-capabilities -p 139,445 <target>
nmap --script=dns-zone-transfer,dns-recursion -p 53 <target>
nmap --script=snmp-info,snmp-processes -sU -p 161 <target>
nmap --script=nfs-ls,nfs-showmount,nfs-statfs -p 2049 <target>
nmap --script=ms-sql-info,ms-sql-ntlm-info -p 1433 <target>
nmap --script=mongodb-databases,mongodb-info -p 27017 <target>
```
Cross-check every banner with a manual grab: `nc -nv <target> <port>` and `openssl s_client -connect <target>:443`.

## Phase 5 — OS Fingerprinting
```bash
# Active OS detection
nmap -O --osscan-guess -Pn -n -p $(paste -sd, scan/tcp/open_ports.txt) <target>

# Full aggressive profile (-O -sV -sC + traceroute)
nmap -A -Pn -n -p $(paste -sd, scan/tcp/open_ports.txt) <target>

# Passive TTL analysis
ping -c 1 <target>    # 64=Linux/macOS/BSD, 128=Windows, 255=Cisco/Solaris
```
OS guesses derived only from TTL are low-confidence until -O confirms.

## Phase 6 — Evasion Techniques (Deep Aggressive)
Use against hardened targets, IDS-monitored segments, or WAF-fronted ranges:
```bash
# Fragmented packets to bypass stateless filters
nmap -f -sS -p- <target>                 # 8-byte fragments
nmap -ff -sS -p- <target>                # 16-byte fragments
nmap --mtu 24 -sS -p- <target>           # custom MTU

# Decoy source addresses
nmap -D RND:10 -sS -p- <target>          # 10 random decoys
nmap -D 10.0.0.1,10.0.0.2,ME -sS <target>

# Source port / IP / MAC manipulation
nmap -g 53 -sS <target>                  # source port 53 (DNS)
nmap --spoof-mac 00:11:22:33:44:55 -sS <target>
nmap --data-length 50 -sS <target>       # packet padding alters fingerprint

# Timing-based stealth
nmap -T1 --scan-delay 1000ms -sS <target>
nmap -T0 -sS <target>                    # paranoid

# Proxy traversal
nmap --proxies http://127.0.0.1:8080 -sT -Pn <target>
proxychains nmap -sT -Pn -p- <target>

# Firewall ruleset mapping (pre-exploit)
nmap -sA -Pn <target>                    # ACK: filtered vs unfiltered
nmap -sF -Pn <target>; nmap -sN -Pn <target>; nmap -sX -Pn <target>  # non-RFC filters
```
Idle scan `-sI <zombie>` is permitted only against owned zombies; never against third-party hosts.

## Phase 7 — masscan High-Speed Sweep (Internet-Scale)
```bash
# Full TCP at high rate
sudo masscan -p1-65535 --rate=1000 --excludefile exclude.txt -oL scan/tcp/masscan_tcp.txt <target>

# Targeted ports across large ranges
sudo masscan -p80,443,22,3389,445,3389 --rate=1000 --excludefile exclude.txt -oL scan/tcp/web.txt <target>

# Grepable output piped straight into nmap for service detection
sudo masscan -p1-65535 --rate=1000 -oG scan/tcp/masscan.gnmap <target>
nmap -sV -sC -iL <(grep open scan/tcp/masscan.gnmap | awk '{print $2}') -p80,443
```

## Phase 8 — naabu Automation Pipeline
```bash
naabu -host <target> -top-ports 1000 -o scan/tcp/naabu_tcp.txt
naabu -host <target> -p - -o scan/tcp/naabu_full.txt           # all 65535 ports
naabu -list scan/hosts/live_hosts.txt -top-ports 1000 -silent
naabu -host <target> -p 80,443,8443 -nmap-cli -sV              # auto-nmap handoff
```

## Phase 9 — rustscan Parallel Scanning
```bash
rustscan -a <target> --range 1-65535 -- -sV -sC
rustscan -a <target> --batch-size 1500 -b 1000 -- -Pn -sV
```

## Phase 10 — Consolidation, Verification, Handoff
```bash
# Machine-readable merge
nmap -oX scan/final.xml scan/services/services.xml scan/udp/udp_high.xml

# Produce findings YAML per host
# host, state, tcp_open[], udp_open[], os_guess, confidence
```
Verification checklist (sandbox):
- [ ] Every reported open port confirmed by a second scan method or manual connect
- [ ] UDP open|filtered states retried with --max-retries 3 before acceptance
- [ ] Scope boundaries re-validated (no out-of-scope IP/port in output)
- [ ] Rate limits respected per environment
- [ ] Results stored in XML/grepable machine-readable format
- [ ] OS fingerprint consistent with known open ports (Windows + 135/139/445)
- [ ] Evasion flags logged with rationale for audit trail

Handoff:
- Structured JSON host/port/service/version/confidence report to dns-agent, web-discover-agent, vuln-scan-agent
- Full command log with flags to audit-agent for reproducibility

## References
- Skill library: skills/port-scanning/skill-playbook.md, skills/network-security/host-discovery.md, skills/network-security/port-scanning.md
- MITRE ATT&CK T1046: https://attack.mitre.org/techniques/T1046/
- MITRE ATT&CK T1590.001: https://attack.mitre.org/techniques/T1590/001/
- nmap documentation: https://nmap.org/docs.html
- masscan: https://github.com/robertdavidgraham/masscan
- naabu: https://github.com/projectdiscovery/naabu
- rustscan: https://github.com/RustScan/RustScan

Prohibited: scanning out-of-scope infrastructure, spoofing scans into third-party networks, DoS-triggering -sI on unowned zombies, --min-rate above authorized ceilings.
