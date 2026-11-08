# 7-Layer (OSI) Weakness Analysis — Skill Playbook

**Mitre ATT&CK ID:** T1046 (Network Service Discovery) / T1005 (Data from Local System)
**OWASP Mapping:** A05:2021 – Security Misconfiguration
**Severity:** Informational → Critical (varies by layer)
**Last Updated:** 2026-08-04

---

## Metadata

```yaml
skill_id: osi-7-layers-v1
category: osi-7-layers
author: HiveBreach
mitre_attack_id: T1046
owasp_mapping:
  - A05:2021-SecurityMisconfiguration
  - A01:2021-BrokenAccessControl
tags:
  - osi-model
  - layer-1
  - layer-2
  - layer-3
  - layer-4
  - layer-5
  - layer-6
  - layer-7
  - network
  - protocol
  - T1046
  - T1040
  - T1016
  - T1562
environments:
  - network
  - web
  - api
  - cloud
  - mobile
  - wireless
verification_required: sandbox
```

---

## 1. The 7-Layer Weakness Model

Every penetration test should enumerate weaknesses per OSI layer. A finding is only complete when you know **which layer** the flaw lives at, because mitigation lives at the same layer.

| Layer | Name | Example Weaknesses | Example Tools |
|---|---|---|---|
| L7 | Application | SQLi, XSS, SSRF, auth bypass, business logic | Burp, sqlmap, nuclei, OWASP ZAP |
| L6 | Presentation | TLS downgrade, cert issues, weak ciphers, encoding bugs | sslscan, testssl.sh, openssl |
| L5 | Session | Session fixation, token replay, MITM of session | Burp, tcpdump, Wireshark |
| L4 | Transport | Port exposure, weak services, TCP/IP stack flaws | nmap, masscan, nc |
| L3 | Network | Routing attacks, spoofing, VLAN hopping, weak ACLs | scapy, nmap, tcpdump |
| L2 | Data Link | ARP spoofing, MAC spoofing, STP abuse, VLAN hopping | bettercap, ettercap, yersinia |
| L1 | Physical | Device theft, port access, console access, badge bypass | physical access tools |

### 1.1 Layer-to-Toolchain Mapping

| Layer | Primary Tools | Verification |
|---|---|---|
| L1 | Physical inspection, USB drop, HID injection (rubber ducky) | Manual evidence |
| L2 | bettercap, ettercap, yersinia, macchanger, tcpdump | ARP table capture |
| L3 | nmap, masscan, scapy, hping3, traceroute | Packet captures |
| L4 | nmap -sV, nc, openssl s_client, testssl.sh | Banner/service response |
| L5 | Burp Repeater, Wireshark, SSLsplit, mitmproxy | Session capture/forge |
| L6 | testssl.sh, sslscan, openssl, sslyze | Handshake analysis |
| L7 | Burp, nuclei, sqlmap, ffuf, custom PoC | Response/state evidence |

---

## 2. Layer-by-Layer Detection Methodology

### 2.1 Layer 1 — Physical

**Checks:**
- Unsecured console / debug UART ports on network gear
- Unlocked workstations, no badge/access control on server rooms
- USB drop testing (R2 safety: only on sandbox/or authorized targets)
- Network closet / patch panel access

**Detection commands:**
```bash
# Identify SNMP-enabled network gear that leaks config
snmpwalk -v2c -c public <target> system
# Check for unauthenticated management interfaces
nc -vz <target> 161
```

**Finding format:** L1 findings are physical access findings — confirm with photos/diagrams, never attempt unauthorized physical access.

### 2.2 Layer 2 — Data Link

**Weaknesses to test:**
- ARP spoofing / ARP cache poisoning (MITM on same L2 segment)
- VLAN hopping (Double Tagging / Switch Spoofing)
- STP (Spanning Tree Protocol) BPDU abuse
- MAC flooding (CAM table exhaustion — R3: careful, can DoS)
- Unauthenticated DHCP (rogue DHCP server)

**Commands:**
```bash
# ARP scan to map L2 neighbors
arp-scan --interface=eth0 --localnet

# Bettercap ARP spoofing (MITM test, must be authorized)
sudo bettercap -iface eth0
# inside bettercap:
#   net.probe on
#   arp.spoof on

# VLAN hopping (double tagging PoC with scapy)
# Switch spoofing: send DTP packets, become trunk
yersinia -I

# STP abuse (may destabilize network - R3: sandbox only)
```
**MITRE mapping:** T1040 (Network Sniffing), T1557.002 (ARP Cache Poisoning)

### 2.3 Layer 3 — Network

**Weaknesses to test:**
- ICMP redirect / route manipulation
- IP spoofing (rarely useful but check)
- Source routing
- Weak or misconfigured ACLs / firewalls
- Missing egress filtering
- VPN / IPsec misconfiguration

**Commands:**
```bash
# Host discovery
nmap -sn <target-range>
# Ping sweep with ICMP blocked alternative
nmap -sn -PE --packet-trace <target-range>
# IP spoofing test (one-way, observe responses on capture)
hping3 -S -a <spoofed-ip> <target>

# Traceroute to map routing path
traceroute -T -p 443 <target>

# ICMP redirect (scapy):
#   send ICMP redirect to target telling it to route via attacker
```
**MITRE mapping:** T1016 (System Network Configuration Discovery), T1046 (Network Service Discovery)

### 2.4 Layer 4 — Transport

**Weaknesses to test:**
- Open TCP/UDP ports exposing services
- Weak/legacy protocols (telnet 23, FTP 21, RDP 3389 open to internet)
- TCP/IP stack fingerprinting
- Service version disclosure
- UDP services (TFTP, SNMP, NTP, DNS)

**Commands:**
```bash
# Full port scan with version + OS detection
nmap -sS -sV -O -p- <target> --reason

# UDP scan (slow, be patient)
nmap -sU --top-ports 100 <target>

# Banner grab
nc -vn <target> <port>

# TLS service inspection
openssl s_client -connect <target>:443 -tls1_2
```
**MITRE mapping:** T1046 (Network Service Discovery), T1595.001 (Active Scanning: Scanning IP Blocks)

### 2.5 Layer 5 — Session

**Weaknesses to test:**
- Session fixation
- Predictable session tokens
- Session tokens in URL
- No session timeout / revocation
- MITM session hijacking (when L2 is compromised)

**Commands:**
```bash
# Token entropy analysis via Burp Sequencer
# Session fixation test: 
#   1. Obtain session ID, set it before login
#   2. Log in, check if session ID unchanged

# MITM with mitmproxy
mitmproxy --mode transparent
# SSLsplit for TLS session hijack in authorized MITM scenario
```
**MITRE mapping:** T1535 (Unused/Unsupported Cloud Regions), T1110 (Brute Force)

### 2.6 Layer 6 — Presentation

**Weaknesses to test:**
- TLS versions (SSLv3, TLS1.0/1.1 deprecated)
- Weak cipher suites (RC4, 3DES, CBC)
- Certificate issues (self-signed, expired, wrong hostname)
- TLS interception / downgrade attacks (POODLE, BEAST, CRIME, BREACH)
- Encoding/parser differentials (billion laughs, zip bombs in XML at presentation layer)

**Commands:**
```bash
# Comprehensive TLS audit
testssl.sh <target>
sslscan <target>
sslyze <target>

# Specific checks
openssl s_client -connect <target>:443 -ssl3
openssl s_client -connect <target>:443 -tls1
nmap --script ssl-enum-ciphers -p 443 <target>
nmap --script ssl-cert -p 443 <target>
```
**MITRE mapping:** T1573 (Encrypted Channel), T1573.001 (Symmetric Cryptography)

### 2.7 Layer 7 — Application

The richest attack surface. **Refer to the full web-exploitation skills:**
- `skills/penetration-testing/sql-injection.md`
- `skills/penetration-testing/xss.md`
- `skills/penetration-testing/ssrf.md`
- `skills/penetration-testing/command-injection.md`
- `skills/api-security/*`
- `skills/server-security/server-detection.md`

**Commands (start here):**
```bash
# App fingerprint
whatweb <target>
# Directory fuzz
feroxbuster -u <target> -w /usr/share/wordlists/dirb/common.txt
# Vuln scan
nuclei -u <target> -severity high,critical
```

---

## 3. Layer Confirmation (Evidence Gate — R2)

Every layer finding must answer three questions before it becomes a finding:

1. **Which layer?** State L1-L7 explicitly.
2. **What is the observable?** Captured packet, response body, banner, behavior change.
3. **What is the blast radius?** What can an attacker do from this layer alone, and chained upward?

### Confirmation matrix

| Layer | Minimum Evidence for Confirmation |
|---|---|
| L1 | Photo/diagram of exposed physical interface (authorized access) |
| L2 | Captured ARP table change, spoofed MAC seen on wire |
| L3 | Traceroute showing route change, spoofed packet observed |
| L4 | Banner grab, service version, nmap script output |
| L5 | Session token reused after login, MITM capture showing live token |
| L6 | Handshake capture showing weak cipher, downgrade success |
| L7 | Response diff (200 vs 403), error output, payload effect |

---

## 4. Exploitation Chains (Layer Escalation)

The powerful technique: **start low, escalate up the stack.**

```
L2 (ARP spoof)  ->  L5 (session hijack)  ->  L7 (authenticated app attack)
L3 (route/ACL)  ->  L4 (reach internal-only service)  ->  L6 (weak TLS)  ->  L7 (sniff creds)
L4 (open Redis)  ->  L3 (pivot)  ->  L7 (web app RCE)
```

**Chain documentation format:**
```markdown
## Chain: [NAME]
L2: ARP spoof on segment X (evidence: arp -a shows attacker MAC for gateway)
  -> L5: captured admin session cookie over HTTP
  -> L7: used cookie to access /admin panel -> confirmed auth bypass (HTTP 200 + admin DOM)
Impact: Full admin access on host Y via L2 MITM + session hijack
```

---

## 5. Tool-Specific Guidance

### Layer 2
- **bettercap** — `sudo bettercap -iface eth0`; `net.probe on`, `arp.spoof on`, `http.proxy on`
- **ettercap** — `sudo ettercap -T -M arp:remote /<target>/ /<gateway>/`
- **yersinia** — STP/DTP/HSRP/VLAN abuse; `yersinia -I`
- **macchanger** — spoof MAC before L2 tests

### Layer 3
- **scapy** — custom packets: `from scapy.all import *; send(IP(dst='x')/ICMP(type=5)/... )`
- **hping3** — spoofed SYNs: `hping3 -S -a 1.2.3.4 <target> -p 443`
- **nmap** — `nmap -sS -sV -O <target>`

### Layer 4
- **nc / ncat** — banner grab
- **nmap** — `nmap -p- -sV --script=banner <target>`
- **masscan** — fast: `masscan <target> -p1-65535 --rate=10000`

### Layer 6
- **testssl.sh** — full TLS audit, `--openssl-timeout`, `--sneaky`
- **sslyze** — Python TLS scanner
- **openssl** — manual handshake tests

---

## 6. PoC Generation

Each finding template must include the layer:

```markdown
## [LAYER_X] Finding — [FINDING_ID]
Layer: L6 (Presentation)
Finding: Weak TLS — supports TLS 1.0 with CBC cipher
Evidence:
  - openssl s_client -connect target:443 -tls1_0  (handshake OK)
  - testssl.sh output showing TLS1.0 enabled, CBC cipher
Reproduction:
  1. openssl s_client -connect <target>:443 -tls1_0 </dev/null 2>&1 | grep "Cipher is"
  2. Observe CBC cipher negotiated
Impact: BEAST-style decryption possible; downgrade feasible
Remediation: Disable TLS 1.0/1.1, CBC ciphers; enforce TLS 1.2+ with AEAD
```

---

## 7. Verification (Sandbox)

- [ ] L2 tests (ARP/VLAN) verified in isolated virtual network
- [ ] L3 spoofing verified with controlled captures
- [ ] L6 downgrade verified against sandbox server with matching config
- [ ] Layer chain escalated only against sandbox replica
- [ ] No ARP/STP/CAM attacks against production (R3)

---

## 8. Related Techniques (MITRE ATT&CK Mapping)

| Technique ID | Name | Layer |
|---|---|---|
| T1046 | Network Service Discovery | L3/L4 |
| T1040 | Network Sniffing | L2 |
| T1557.002 | ARP Cache Poisoning | L2 |
| T1557.001 | LLMNR/NBT-NS Poisoning | L2 |
| T1016 | System Network Configuration Discovery | L3 |
| T1043 | Commonly Used Port | L4 |
| T1573 | Encrypted Channel | L6 |
| T1608.002 | Upload Tool | L7 |
| T1190 | Exploit Public-Facing Application | L7 |

---

## 9. References

- MITRE ATT&CK T1046: https://attack.mitre.org/techniques/T1046/
- OSI model (RFC 1122/1123): https://datatracker.ietf.org/doc/html/rfc1122
- OWASP Top 10: https://owasp.org/Top10/
- testssl.sh: https://testssl.sh/
- bettercap: https://www.bettercap.org/
- MITRE ATT&CK Navigator: https://mitre-attack.github.io/attack-navigator/

---

*This playbook is for authorised security testing only. Layer 1-3 attacks (ARP, STP, spoofing) can disrupt production — always sandbox first, per R3.*
