# DFIR — Skill Playbook

**Mitre ATT&CK ID:** T1059 (Command and Scripting Interpreter), T1055 (Process Injection), T1078 (Valid Accounts), TA0006 (Credential Access)
**OWASP Mapping:** N/A (DFIR Domain)
**Severity:** High / Critical
**Last Updated:** 2026-08-02

---

## Metadata

```yaml
skill_id: dfir-playbook-v2
category: dfir
author: HiveBreach
mitre_attack_id: [T1059, T1055, T1078, TA0006]
owasp_mapping: []
tags: [dfir, digital-forensics, incident-response, timeline-analysis, artifact-analysis]
tools: [kape, ez-tools, plaso, autopsy, tsks, wintriage, log2timeline, evtx_dump, yara]
verification_required: sandbox
```

---

## 1. Detection

### 1.1 Incident Trigger Sources

| Source | Signal |
|---|---|
| EDR / SIEM alert | Malicious process, beacon, lateral movement |
| User report | Phishing, ransomware, account takeover |
| External notification | ISP/leak/C2 block notice |
| AV / NIDS | Signature hit on host or wire |
| Anomalous auth | Failed logins, off-hours access, impossible travel |

### 1.2 DFIR-Specific Indicators

- PowerShell encoded command invocation in logs
- New scheduled tasks / services / WMI subscriptions
- Accounts logging in from multiple source IPs
- Files with suspicious names/timestamps in user dirs
- Security event ID gaps (logs cleared)

---

## 2. Confirmation

### 2.1 Evidence Preservation & Chain of Custody

```bash
mkdir -p /evidence/{disk,memory,logs,tools}
sha256sum /evidence/disk/image.raw > /evidence/hashes.txt
cat /evidence/evidence_id.json
{
  "case_id": "IR-2026-0001",
  "acquirer": "analyst@hive",
  "host": "CORP-WIN10",
  "acquired_utc": "2026-08-02T04:12:33Z",
  "hash": "sha256:...",
  "chain": ["preserved by analyst@hive 2026-08-02T04:12:33Z"]
}
```

### 2.2 Volatile Data Capture Order

1. Live RAM image (`winpmem`, `avml`)
2. Process list, network connections (`netstat -ano`)
3. Open files, logged-on users
4. Registry hives, event logs (duplicate, do not modify)
5. Only then power down and acquire disk

---

## 3. Exploitation (Forensic Collection & Analysis)

### 3.1 KAPE Triage Collection

```bash
kape.exe --tsource C:\ --tdest .\output\ --target "!CLEAN_MARKERS" --tlog
kape.exe --tsource C:\ --tdest .\output\ --target "PREFETCH;AMCACHE;SHIMCACHE;JUMPLIST;SRUM;USN;EVTX;REGISTRY"
# All output under .\output\{M}\{DateTime} per host
```

### 3.2 Timeline Generation (Plaso / log2timeline)

```bash
log2timeline.py --storage-file timeline.plaso /evidence/disk/image.raw
psort.py -o l2tcsv -w timeline.csv "date > '2026-08-01'"
psort.py -o l2tcsv -w pivot.csv "parser == 'selinux' OR parser == 'syslog'"
# Search for anomalies
grep -iE "powershell|cmd\.exe|schtasks|wmic|rundll32" timeline.csv | head -50
```

### 3.3 Windows Artifact Analysis (Eric Zimmerman Tools)

```bash
PECmd.exe -d C:\output\Prefetch --csv prefetch_out     # executables run
AmcacheParser.exe -f C:\output\Amcache.hve --csv amcache_out
AppCompatCacheParser.exe -f C:\output\SYSTEM --csv shimcache_out
JLECmd.exe -d C:\output\JumpLists --csv jumplist_out
SrumECmd.exe -d C:\output\SRUM --csv srum_out
LECmd.exe -f C:\output\LNK --csv lnk_out
MFTECmd.exe -f C:\output\USNJournal --csv usn_out
```

### 3.4 Event Log Analysis

```bash
# Windows: 4624 logon, 4625 failed logon, 4672 special priv, 4688 process creation
python3 -m oletools --version 2>/dev/null || true
EvtxECmd.exe -d C:\output\Logs --csv evtx_out
grep -i "EventID 4625" evtx_out/*.csv
# Linux: /var/log/auth.log, secure, wtmp, lastlog, auditd
zcat /var/log/auth.log.*.gz | grep -iE "Failed password|Accepted" 
lastlog -t 30; journalctl -u sshd --since "2026-07-30"
```

### 3.5 Linux / macOS Artifacts

```bash
# Linux: bash_history, cron, authorized_keys, /etc/passwd mtime
# macOS: unified logging, .bash_history, LaunchAgents
macOS: log show --start "2026-08-01" --predicate 'processImagePath contains "curl"'
# Auditd
ausearch -ts today -ua analyst -m EXECVE
```

### 3.6 Disk Image Analysis (Autopsy / TSK)

```bash
# Autopsy GUI: ingest modules, timeline, keyword search, hash sets
autopsy --create --base . 2>/dev/null
# TSK CLI
mmls -t dos /evidence/disk/image.raw        # partition table
fls -r -p -o 2048 image.raw > fls.txt       # file list with deleted
icat image.raw 1042 > /evidence/recovered.doc
# Browser history / Outlook / Teams artifacts: Forensic Imager + ZTools parsers
```

### 3.7 Artifact-to-Technique Mapping

| Artifact | ATT&CK | Question Answered |
|---|---|---|
| Prefetch / Amcache / Shimcache | T1070.005, T1555 | What executables ran? |
| Jump Lists / LNK | T1560 | What files were opened? |
| SRUM | T1041, T1071 | Network and app activity |
| USN Journal | T1070 | File deletions/renames |
| 4624/4625 logs | T1078, T1110 | Account compromise, brute-force |
| 4688 process | T1059 | Command execution |
| Registry Run/Services | T1547 | Persistence |
| MFT | T1555 | File existence timeline |
| Prefetch + USN | T1059, T1003 | Ransomware encryption chain |

---

## 4. Tool-Specific Guidance

| Tool | Use | Command |
|---|---|---|
| KAPE | Triage/collection | `kape.exe --tsource C:\ --tdest .\out` |
| EZ Tools (PECmd etc.) | Artifact parsing | `PECmd.exe -d ...` |
| Plaso / log2timeline | Timeline | `log2timeline.py --storage-file t.plaso img.raw` |
| psort | Timeline filter/sort | `psort.py -o l2tcsv -w t.csv` |
| Autopsy | GUI disk forensics | `autopsy` |
| TSK (fls/icat/mmls) | Disk analysis | `fls -r -p -o 2048 image.raw` |
| EvtxECmd | Event log parsing | `EvtxECmd.exe -f ...` |
| YARA | File signature scan | `yara rules.yar C:\output\` |
| WinPmem / AVML | Memory capture | `winpmem mem.raw` |
| Forensic Imager | Disk image verification | GUI |

---

## 5. PoC Generation

### Timeline Pivot

```bash
grep -iE "powershell|cmd\.exe|schtasks|rundll32" timeline.csv | sort -u > pivot_commands.csv
awk -F',' '{print $1, $2, $3}' pivot_commands.csv | head -20
# Cluster by source host, artifact, timestamp
```

### Persistence Discovery

```bash
grep -iE "CurrentVersion\\\\Run|schtasks|\\Services\\" timeline.csv | head -30
```

---

## 6. Verification (Sandbox)

- [ ] Chain of custody recorded; evidence hashes verified
- [ ] Volatile data captured in correct order before shutdown
- [ ] KAPE triage completed for each host; manifests reviewed
- [ ] Timeline generated and pivoted on suspicious commands
- [ ] Prefetch/Amcache/Shimcache indicate only known executables
- [ ] JumpLists/LNK correlate with observed file access
- [ ] Event log analysis matches findings (4624/4625/4688)
- [ ] Linux/macOS artifacts reviewed (auth, cron, launch agents)
- [ ] Disk image verified, deleted files recovered where needed
- [ ] Findings mapped to MITRE ATT&CK techniques

---

## 7. Cheat Sheet

```bash
sha256sum image.raw > hashes.txt
kape.exe --tsource C:\ --tdest .\out --target "!CLEAN_MARKERS"
log2timeline.py --storage-file t.plaso image.raw
psort.py -o l2tcsv -w t.csv "date > '2026-08-01'"
PECmd.exe -d .\out\Prefetch --csv .; AmcacheParser.exe -f .\out\Amcache.hve --csv .
EvtxECmd.exe -d .\out\Logs --csv .; grep -i "4625" evtx_out/*.csv
fls -r -p -o 2048 image.raw; icat image.raw 1042 > recovered.doc
```

---

## 8. Related Techniques (MITRE ATT&CK Mapping)

| Technique ID | Name | Relation |
|---|---|---|
| T1059.001 | PowerShell | Command execution evidence |
| T1055 | Process Injection | Memory/malware artifacts |
| T1078 | Valid Accounts | Logon/anomalous auth |
| T1110 | Brute Force | 4625 failed logons |
| T1547.001 | Registry Run Keys | Persistence artifacts |
| T1070 | Indicator Removal | Cleared/cleared logs |
| T1560 | Archive Collected Data | Exfil staging |
| T1041 | Exfiltration Over C2 | SRUM/network data |

---

## 9. References

- KAPE: https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape
- Eric Zimmerman Tools: https://ericzimmerman.github.io/
- Plaso: https://plaso.readthedocs.io/
- Autopsy: https://www.sleuthkit.org/autopsy/
- TSK: https://www.sleuthkit.org/
- MITRE ATT&CK DFIR: https://attack.mitre.org/

---

*This playbook is for authorised security research only. Forensic collection must follow legal authorization and chain-of-custody requirements.*
