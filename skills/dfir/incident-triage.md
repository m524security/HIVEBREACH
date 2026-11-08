# DFIR Incident Triage — Skill Runbook

**Mitre ATT&CK ID:** T1059 (Command and Scripting Interpreter), T1055 (Process Injection), T1078 (Valid Accounts), T1562 (Impair Defenses)
**OWASP Mapping:** N/A (DFIR Domain)
**Severity:** High / Critical
**Last Updated:** 2026-08-02

---

## Metadata

```yaml
skill_id: incident-triage-v2
category: dfir
author: HiveBreach
mitre_attack_id: [T1059, T1055, T1078, T1562]
owasp_mapping: []
tags: [dfir, incident-response, triage, containment, runbook]
tools: [kape, ez-tools, plaso, volatility, osquery, schedtask, livecd, osiris]
verification_required: sandbox
```

---

## 1. Detection

### 1.1 Triage Entry Points

| Entry | Action |
|---|---|
| EDR alert | Pull process/network/registry telemetry |
| SIEM correlation | Build detection window timeline |
| User complaint | Interview + preserve email/chat/screenshots |
| Ransom note / beacon | Isolate host immediately |

### 1.2 Severity Triage Matrix

| Priority | Indicator Set | Action Window |
|---|---|---|
| P1 | Ransomware encryption, credential dump, admin foothold | < 1h contain |
| P2 | C2 beacon, lateral movement, data staging | < 4h contain |
| P3 | Single host malware, no lateral movement | < 24h investigate |
| P4 | Low-risk alert, benign false positive | 7d review |

---

## 2. Confirmation

### 2.1 Immediate Response Steps

1. Isolate affected host(s) from network (or limit to analyst-only egress).
2. Do NOT delete anything; do NOT reboot if volatile data needed.
3. Acquire volatile data (see 2.2) then image disk.
4. Escalate if P1 criteria met.

### 2.2 Volatile Data Acquisition

```bash
# RAM
winpmem_mini_x64_rc2.exe memdump.raw
avml /evidence/mem.raw        # Linux
# Process/network snapshot before shutdown
tasklist /v > process_list.txt; netstat -ano > netstat.txt
wmic process get name,executablepath,parentprocessid,creationdate /format:csv > procs.csv
# Registry hives
reg save HKLM\SYSTEM /evidence/SYSTEM
reg save HKLM\SAM /evidence/SAM
reg save HKLM\SECURITY /evidence/SECURITY
reg save HKCU\Software\Microsoft\Windows\CurrentVersion\Run /evidence/runkey.hiv
```

---

## 3. Exploitation (Triage Collection & Analysis)

### 3.1 KAPE Triage (speed first)

```bash
kape.exe --tsource C:\ --tdest .\triage\ --target "!CLEAN_MARKERS" --tlog --debug
kape.exe --tsource C:\ --tdest .\triage\ --target "PREFETCH;AMCACHE;SHIMCACHE;JUMPLIST;SRUM;EVTX;REGISTRY;USN"
# Full image if triage is insufficient
dd if=/dev/sdb of=/evidence/disk.raw bs=4M status=progress
```

### 3.2 Hunt Queries (Windows)

```powershell
# Recent process activity
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688} -MaxEvents 5000 |
  Where-Object {$_.Message -match 'powershell|wmic|rundll32|mshta|regsvr32'} |
  Select-Object TimeCreated, @{n='Cmd';e={$_.Properties[8].Value}}
# Failed logons cluster
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} |
  Group-Object -Property {$_.Properties[5].Value} |
  Sort-Object Count -Descending | Select-Object -First 10
# New services / tasks / WMI persistence
Get-WinEvent -FilterHashtable @{LogName='System';Id=7045}
schtasks /query /fo csv /v | findstr /i "public tmp"
```

### 3.3 Hunt Queries (Linux)

```bash
# SSH / credential abuse
grep -E "Failed password|Accepted password" /var/log/auth.log
lastlog; last -f /var/log/wtmp | head -30
# Persistence
find /etc/systemd/system /etc/cron.d /var/spool/cron -type f -mtime -14
ls -la /root/.ssh/ /home/*/.ssh/
# Malicious processes / network
ss -tnp | grep -i "ESTABLISHED"
ps auxf | grep -vE '^\[|systemd|kworker' | head -50
```

### 3.4 Timeline & Pivot

```bash
log2timeline.py --storage-file triage.plaso /evidence/disk.raw
psort.py -o l2tcsv -w timeline.csv "date > '2026-08-01'"
# Pivot on suspicious commands and source IPs
grep -iE "powershell -enc|iwr|schtasks|wmic process|curl" timeline.csv | sort -u
```

### 3.5 Memory & Malware Artifacts

```bash
vol3 -f memdump.raw windows.pslist
vol3 -f memdump.raw windows.malfind --dump
vol3 -f memdump.raw windows.netscan
vol3 -f memdump.raw windows.hashdump --dump
yara family.rules /evidence/triage/ -r 2>/dev/null
```

### 3.6 Containment & Eradication

| Action | Command (Windows) |
|---|---|
| Kill process | `taskkill /F /IM svchost_fake.exe` |
| Disable service | `sc stop FakeSvc; sc config FakeSvc start=disabled` |
| Remove persistence | `reg delete HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v FakeRun /f` |
| Disable task | `schtasks /Delete /TN FakeUpdate /F` |
| Block C2 IP | `netsh advfirewall firewall add rule name="BlockC2" dir=out remoteip=203.0.113.50 action=block` |
| Reset creds | `net user username /domain` + force password change |

### 3.7 Recovery & Lessons Learned

1. Restore from verified clean backup; re-image compromised hosts.
2. Rotate all potentially exposed credentials.
3. Harden: disable legacy protocols, MFA, restrict LSASS access.
4. Document root cause, detection gaps, and prevention controls.

---

## 4. Tool-Specific Guidance

| Tool | Use | Command |
|---|---|---|
| KAPE | Fast triage collection | `kape.exe --tsource C:\ --tdest .\triage\` |
| EZ Tools | Artifact parsing | `PECmd.exe -d ...` |
| Plaso/psort | Timeline | `psort.py -o l2tcsv -w t.csv` |
| Volatility 3 | Memory analysis | `vol3 -f mem.raw windows.pslist` |
| winpmem / AVML | RAM capture | `winpmem mem.raw` |
| osquery | Host state query | `osqueryi --json "select * from processes"` |
| YARA | Signature scan | `yara rules.yar path/` |
| schedtask | Task persistence check | `schtasks /query /fo csv` |

---

## 5. PoC Generation

### Incident Report Template

```markdown
## Incident Report — IR-2026-0001

**Severity:** P1 | **Status:** Contained | **Detection:** 2026-08-02T04:00:00Z

### Executive Summary
Phishing macro on CORP-WIN10 dropped remote access trojan; beacon to
203.0.113.50 over HTTPS; no evidence of lateral movement.

### Timeline
04:00Z phishing email opened (user confirmed)
04:05Z powershell -enc ... spawned by WINWORD.exe (4624/4688)
04:12Z svchost_fake.exe registered as service (System 7045)
04:30Z 203.0.113.50:443 ESTABLISHED beacons (netscan)
05:00Z analyst isolated host

### Affected Hosts & Users
CORP-WIN10 (alice), AD account: alice@corp

### Evidence
/evidence/hashes.txt, /evidence/mem.raw, /evidence/disk.raw, triage.plaso

### IoCs
Process: svchost_fake.exe (sha256 abc...)
Service: FakeSvc ImagePath C:\Windows\svchost_fake.exe
C2: 203.0.113.50:443 (TLS), update-service.xyz
Registry: HKLM\...\Run\WindowsUpdate

### MITRE Techniques
T1204.002, T1059.001, T1547.001, T1071.001, T1105

### Remediation
- Host reimaged, password rotated, MFA enforced
- Firewall rule blocks 203.0.113.50 egress
- EDR detection rule added for WINWORD->powershell chain
```

---

## 6. Verification (Sandbox)

- [ ] Volatile data captured before any destructive action
- [ ] Triage collection verified complete per host
- [ ] Timeline pivots reproducible with raw evidence
- [ ] Hunt queries re-run on clean baseline for comparison
- [ ] Memory artifacts (malfind/netscan) corroborate log findings
- [ ] Containment actions verified (process dead, C2 blocked, creds rotated)
- [ ] Report includes evidence hashes and chain of custody

---

## 7. Cheat Sheet

```bash
kape.exe --tsource C:\ --tdest .\triage\ --target "!CLEAN_MARKERS"
log2timeline.py --storage-file t.plaso disk.raw; psort.py -o l2tcsv -w t.csv
vol3 -f mem.raw windows.pslist; vol3 -f mem.raw windows.netscan
schtasks /query /fo csv /v | findstr /i "public tmp"
netsh advfirewall firewall add rule name="BlockC2" dir=out remoteip=203.0.113.50 action=block
reg delete HKLM\...\Run /v FakeRun /f
```

---

## 8. Related Techniques (MITRE ATT&CK Mapping)

| Technique ID | Name | Relation |
|---|---|---|
| T1059.001 | PowerShell | Primary script execution |
| T1055 | Process Injection | Memory hunts |
| T1078 | Valid Accounts | Logon analysis |
| T1562.001 | Disable/Modify Tools | Log gaps, AV off |
| T1547.001 | Registry Run Keys | Persistence triage |
| T1071.001 | Web Protocols | C2 beaconing |
| T1105 | Ingress Tool Transfer | Second-stage delivery |
| T1486 | Data Encrypted for Impact | Ransomware triage |

---

## 9. References

- NIST SP 800-61: https://csrc.nist.gov/pubs/sp/800/61/r2/final
- SANS Incident Handlers Handbook: https://www.sans.org/
- MITRE ATT&CK for IR: https://attack.mitre.org/
- KAPE: https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape
- Eric Zimmerman Tools: https://ericzimmerman.github.io/

---

*This playbook is for authorised security research only. All response actions require prior authorization and must preserve evidence for chain of custody.*
