# Host Discovery — Skill Playbook

**Mitre ATT&CK ID:** T1590.001 (Active Scanning: Scanning IP Blocks), T1046 (Network Service Scanning)
**OWASP Mapping:** N/A (network-layer reconnaissance)
**Severity:** Informational
**Last Updated:** 2026-08-02

---

## Metadata

```yaml
skill_id: host-discovery-v1
category: network-security
author: HiveBreach
mitre_attack_id: T1590.001
owasp_mapping: []
tags:
  - host-discovery
  - ping-sweep
  - arp-scan
  - icmp
  - ipv6
  - os-fingerprinting
  - metasploit-discovery
  - T1590.001
  - T1046
tools:
  - nmap
  - fping
  - arp-scan
  - alive6
  - netdiscover
  - dig
  - nslookup
  - metasploit
difficulty: beginner
verification_required: sandbox
```

---

## 1. Detection

### 1.1 Goal

Host discovery (T1590.001 — Scanning IP Blocks) converts a CIDR/IP-range scope into a list of live hosts, minimising traffic before port scanning (T1046). It is the first step of the recon pipeline run by the recon-agent.

### 1.2 Inputs

| Input | Example |
|---|---|
| CIDR blocks | `10.10.10.0/24`, `172.16.0.0/12` |
| IP ranges | `192.168.1.1-250` |
| DNS names | `*.target.com` |
| Exclusions | `10.10.10.10` |
| Authorisation | `ROE-2026-042` (scope-agent validated) |

### 1.3 Technique Selection by Position

| Position | Primary Technique | Tool |
|---|---|---|
| Same subnet | ARP discovery | arp-scan, netdiscover, nmap `-PR` |
| Internal routed | ICMP + TCP SYN | nmap `-sn`, fping |
| External | TCP/80,443 + ICMP | nmap `-sn -PS80,443` |
| ICMP-blocked | TCP/UDP probes only | nmap `-PS`/`-PA`/`-PU` |
| IPv6 | ICMPv6 / neighbor discovery | alive6, nmap `-6` |

---

## 2. Confirmation

A host is considered live only after confirmation by a second, independent probe:

```bash
# Method 1: ICMP echo
nmap -sn -PE -n <cidr>
# Method 2: TCP probe
nmap -sn -PS22,80,443 -n <cidr>
# Method 3: Application-level (nmap port scan)
nmap -sS -Pn --top-ports 100 -n <host>
```

If ICMP is filtered but the host answers TCP, it is live. Record the confirming method for the audit trail.

---

## 3. Exploitation

### 3.1 Ping Sweeps

```bash
# nmap ICMP + TCP sweep (default -sn combines ICMP, TCP/443, TCP/80, ICMP timestamp)
nmap -sn -T4 -n <cidr>

# fping (very fast ICMP)
fping -a -g 10.10.10.0/24 2>/dev/null
fping -a -g 10.10.10.1 10.10.10.254 -q

# arp-scan (same subnet, layer 2)
arp-scan --localnet
arp-scan -I eth0 10.10.10.0/24

# netdiscover
netdiscover -r 10.10.10.0/24 -i eth0

# alive6 (IPv6)
alive6 eth0
```

### 3.2 ICMP Probe Types

| Probe | nmap flag | Purpose |
|---|---|---|
| Echo request | `-PE` | Standard liveness (often blocked) |
| Timestamp request | `-PP` | Bypasses filters that drop echo |
| Address-mask request | `-PM` | Legacy filter bypass |

```bash
nmap -sn -PE -PP -PM -T4 -n <cidr>
```

### 3.3 TCP/UDP Port-Based Discovery

When ICMP is blocked, liveness is inferred from TCP/UDP responses:

```bash
# TCP SYN to common ports
nmap -sn -PS21,22,25,80,443,3389 -T4 -n <cidr>
# TCP ACK (unfiltered hosts reply RST)
nmap -sn -PA80,443 -T4 -n <cidr>
# UDP (DNS, SNMP, NTP responders are usually alive)
nmap -sn -PU53,161,123 -T4 -n <cidr>
# SCTP
nmap -sn -PY80 -T4 -n <cidr>
```

### 3.4 ARP Discovery (same subnet)

ARP is the fastest and most reliable method on a directly-connected subnet — hosts cannot ignore ARP requests:

```bash
sudo nmap -PR -sn -n <cidr>
sudo arp-scan -I eth0 10.10.10.0/24
netdiscover -r 10.10.10.0/24 -i eth0 -P   # Persistent scan
```

Metasploit ARP sweep:
```bash
msfconsole -q -x 'use auxiliary/scanner/discovery/arp_sweep; set RHOSTS 10.10.10.0/24; set THREADS 50; run'
```

### 3.5 DNS-Based Discovery

```bash
# Reverse DNS over a range (infers configured hostnames)
nmap -sL -n <cidr> | awk '/NMAP/ {print $5}' | while read ip; do
  nslookup $ip <dns_server>
done

# Forward subdomain enumeration (hostnames likely live)
dnsrecon -d target.com -t brt -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Reverse DNS bulk
dnsrecon -r 10.10.10.0/24 -n <dns_server>
```

### 3.6 Bypassing ICMP Blocks

```bash
# Hosts that ignore ICMP echo
nmap -sn -PS22,80,443 -PA80,443 -PU53 -T4 -n <cidr>
# ARP on local subnet ignores all ICMP filtering
sudo arp-scan -I eth0 10.10.10.0/24
# If only specific ports open, widen the probe set
nmap -sn -PS1-1000 -T4 -n <host>
```

### 3.7 OS Fingerprinting Basics (TTL Analysis)

Passive TTL analysis from ping responses (subtract 1 per hop):

| Initial TTL | OS / Device |
|---|---|
| 64 | Linux / macOS / BSD / Android |
| 128 | Windows (NT-based) |
| 255 | Cisco / Solaris / network gear |
| 60 | AIX |

```bash
ping -c 1 <host>
# Observed TTL + hop count (traceroute) => initial TTL guess
nmap -O --osscan-guess -Pn -p <open_ports> <host>   # Active confirmation
```

### 3.8 IPv6 Discovery

```bash
# ICMPv6 neighbor discovery
alive6 eth0
# nmap IPv6
nmap -6 -sn <ipv6>/64
# Multicast ping (link-local)
nmap -6 -sL -n <ipv6> 
# Metasploit IPv6 modules
msfconsole -q -x 'use auxiliary/scanner/discovery/ipv6_multicast_ping; set INTERFACE eth0; run'
msfconsole -q -x 'use auxiliary/scanner/discovery/ipv6_neighbor; set INTERFACE eth0; set RHOSTS ff02::1; run'
msfconsole -q -x 'use auxiliary/scanner/discovery/ipv6_neighbor_router_advertisement; run'
```

---

## 4. Tool-Guidance

### 4.1 Tool Comparison

| Tool | Method | Speed | Same-Subnet | Notes |
|---|---|---|---|---|
| `nmap -sn` | ICMP+TCP+UDP | Fast | Yes (`-PR`) | Flexible probe selection |
| `fping` | ICMP | Very fast | No | Best for large ICMP sweeps |
| `arp-scan` | ARP | Very fast | Yes | OUI/MAC vendor output |
| `netdiscover` | ARP | Fast | Yes | Live view |
| `alive6` | ICMPv6/ND | Fast | Yes | IPv6 only |
| Metasploit `udp_sweep` | UDP | Slow | No | Service-aware UDP probes |
| Metasploit `udp_probe` | UDP | Slow | No | Detects many UDP services |

### 4.2 Metasploit Discovery Modules

```bash
msfconsole -q -x 'use auxiliary/scanner/discovery/arp_sweep; set RHOSTS 10.10.10.0/24; run'
msfconsole -q -x 'use auxiliary/scanner/discovery/udp_sweep; set RHOSTS 10.10.10.0/24; run'
msfconsole -q -x 'use auxiliary/scanner/discovery/udp_probe; set RHOSTS 10.10.10.0/24; run'
msfconsole -q -x 'use auxiliary/scanner/discovery/empty_udp; set RHOSTS 10.10.10.0/24; run'
```

### 4.3 Rate Control

```bash
nmap -sn --min-hostgroup 256 --max-rtt-timeout 500ms <cidr>   # Faster, lossy
nmap -sn --max-hostgroup 16 --max-retries 2 <cidr>            # Steadier
fping -a -g -r 0 <cidr>                                       # No retries, fast
```

---

## 5. PoC Generation

### 5.1 Live-Host List Pipeline

```bash
# 1. ARP discovery (same subnet)
sudo arp-scan -I eth0 10.10.10.0/24 | awk '{print $1}' | grep -E '^[0-9]' > scan/live_arp.txt

# 2. ICMP sweep
nmap -sn -PE -T4 -n 10.10.10.0/24 -oG scan/live_icmp.gnmap
grep -E 'Status: Up' scan/live_icmp.gnmap | awk '{print $2}' >> scan/live_icmp.txt

# 3. TCP probe sweep (catches ICMP-blocked hosts)
nmap -sn -PS22,80,443 -T4 -n 10.10.10.0/24 -oG scan/live_tcp.gnmap
grep -E 'Status: Up' scan/live_tcp.gnmap | awk '{print $2}' >> scan/live_tcp.txt

# 4. Deduplicate + merge
sort -u scan/live_*.txt > scan/live_hosts.txt

# 5. Sanitize against scope
comm -12 scan/live_hosts.txt scan/scope_ips.txt > scan/live_in_scope.txt

# 6. Handoff to port scanning
sudo nmap -sS -T4 -Pn -n -p- -iL scan/live_in_scope.txt -oA scan/tcp_full
```

### 5.2 Findings Template

```yaml
# scan/host-discovery.yaml
scan:
  id: HD-2026-042
  scope: 10.10.10.0/24
  techniques: [arp, icmp-echo, tcp-syn-80-443]
hosts:
  - ip: 10.10.10.1
    confirmed_by: [arp, tcp/80]
    mac: 00:11:22:33:44:55
    vendor: VMware
    ttl_guess: 128
    os_guess: Windows
```

---

## 6. Verification (Sandbox)

- [ ] Every reported host confirmed by at least two probe types
- [ ] ICMP-only results cross-checked with TCP probe results
- [ ] ARP results limited to same-subnet scope
- [ ] Host list sanitised against ROE scope (no out-of-scope IPs)
- [ ] TTL-based OS guesses flagged as low-confidence until `-O` confirmation
- [ ] Output stored in grepable/machine-readable format for downstream tools

**Prohibited:** scanning unapproved IP blocks, sending discovery probes at rates that trigger IDS/DoS on shared infrastructure, ARP discovery beyond the directly-connected subnet.

---

## 7. Cheat Sheet Reference

### 7.1 nmap -sn Probe Matrix

| Probe | Flag | Response Indicates Alive |
|---|---|---|
| ICMP echo | `-PE` | ICMP echo reply |
| ICMP timestamp | `-PP` | Timestamp reply |
| ICMP address-mask | `-PM` | Address-mask reply |
| TCP SYN | `-PS<ports>` | RST (closed) or SYN-ACK (open) |
| TCP ACK | `-PA<ports>` | RST (unfiltered) |
| UDP | `-PU<ports>` | ICMP port unreachable |
| SCTP | `-PY<ports>` | SCTP init-ack |
| ARP | `-PR` | ARP reply |

### 7.2 TTL Quick Table

```
64   -> Linux/macOS/BSD/Android
128  -> Windows NT+
255  -> Cisco/Solaris/network
60   -> AIX
```

### 7.3 Common Discovery Ports

```
TCP: 22, 80, 443, 445, 3389
UDP: 53, 123, 161
```

---

## 8. Related Techniques (MITRE ATT&CK Mapping)

| Technique ID | Name | Relation |
|---|---|---|
| T1590.001 | Active Scanning: Scanning IP Blocks | Core technique |
| T1046 | Network Service Scanning | Downstream step |
| T1595.001 | Active Scanning: Scanning IP Blocks | External recon goal |
| T1018 | Remote System Discovery | Identify reachable systems |
| T1590 | Gather Victim Network Information | Scope expansion |

---

## 9. References

- nmap host discovery: https://nmap.org/book/man-host-discovery.html
- arp-scan: https://github.com/royhills/arp-scan
- fping: https://github.com/schweikert/fping
- alive6: https://github.com/vanhauser-thc/thc-ipv6
- MITRE ATT&CK T1590.001: https://attack.mitre.org/techniques/T1590/001/
- MITRE ATT&CK T1046: https://attack.mitre.org/techniques/T1046/
- Metasploit discovery modules: https://github.com/rapid7/metasploit-framework/tree/master/modules/auxiliary/scanner/discovery

---

*This playbook is for authorised security testing only. All verification must occur in sandbox environments.*
