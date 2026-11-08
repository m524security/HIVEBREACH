# YARA Rule Development & Threat Hunting — Skill Playbook

**Mitre ATT&CK ID:** T1027 (Obfuscated Files or Information), T1055 (Process Injection), T1560.001 (Archive via Utility)
**OWASP Mapping:** N/A – Detection & Hunting Discipline
**Severity:** N/A – Detection Engineering
**Last Updated:** 2026-08-02

---

## Metadata

```yaml
skill_id: yara-hunting-v1
category: threat-intel
author: HiveBreach
mitre_attack_id: T1027
owasp_mapping: []
frameworks: [mitre-attack]
tags: [yara, malware-detection, threat-hunting, signature-development, pattern-matching, ioc]
tools: [yara, yara-python, yarGen, loki, pefile, sigcheck]
environments: [endpoint, filesystem, memory, network]
verification_required: sandbox
```

---

## 1. Detection

### 1.1 Rule Structure

A YARA rule has three blocks: `meta` (metadata), `strings` (patterns), and `condition` (logic). String types:

| Type | Syntax | Use |
|---|---|---|
| ASCII text | `"MZ" ascii` | Plain strings |
| Wide text | `"Rundll" wide` | UTF-16LE strings |
| Case-insensitive | `"http" nocase` | Protocol strings |
| Hex pattern | `{ 8B 45 ?? 33 C1 }` | Byte sequences with wildcards |
| Regex | `/https?:\/\/[a-z]+\.(xyz\|top)/` | Variable-length patterns |

### 1.2 Modules (pe / elf / math)

```yara
import "pe"
import "math"

rule Suspicious_Packed_PE {
    meta:
        author = "HiveBreach CTI"
        mitre = "T1027"
    condition:
        pe.is_pe and
        for any section in pe.sections : (
            math.entropy(section.offset, section.size) > 7.2 and
            section.size > 1024
        ) and
        pe.imports("kernel32.dll", "VirtualAlloc")
}
```

`pe` exposes headers, sections, imports, and exports; `elf` exposes ELF headers and sections; `math` provides `entropy` for packing detection. Guard module access with `pe.is_pe` / `elf.is_elf`.### 1.3 Rule Writing for Malware Families

Prioritise unique, recompilation-resistant anchors: hardcoded stack strings, C2 URLs, mutex names, encryption constants, unique API call sequences, and PDB paths. Avoid compiler boilerplate and common library strings.

```yara
rule Emotet_Loader_2026 {
    meta:
        author = "HiveBreach CTI"
        mitre = "T1059.001, T1055.001"
    strings:
        $export1 = "DllRegisterServer" ascii
        $decrypt = { 8B 45 ?? 33 45 ?? 89 45 ?? }
        $ps = /powershell[^\n]{0,50}-e(nc|ncodedcommand)/i
        $uri1 = "/wp-content/uploads/" ascii
        $uri2 = "/wp-admin/css/" ascii
        $mz = "MZ" at 0
    condition:
        $mz and filesize < 2MB and
        (($export1 and $decrypt) or ($ps and any of ($uri*)))
}
```

---

## 2. Confirmation

### 2.1 Compile & Syntax Check

```bash
yara -w rules/emotet.yar /dev/null
python3 -c "import yara; yara.compile(filepath='rules/emotet.yar'); print('compiled')"
```

### 2.2 True Positive / False Positive Validation

```bash
yara rules/emotet.yar /mnt/evidence/malware_samples/emotet_dll.bin
yara rules/emotet.yar /mnt/evidence/goodware_corpus/
```

FP target below 0.1% on a clean corpus of system files. Document any match on benign files and tighten conditions. Verify module assumptions before relying on them (`pe.is_pe` before `pe.sections`, `elf.is_elf` before ELF fields).

---

## 3. Exploitation

### 3.1 Filesystem Hunting (yara-python)
```python
import yara, os, json
from datetime import datetime, timezone

rules = yara.compile(filepaths={"emotet": "rules/emotet.yar",
                                "cobalt": "rules/cobalt.yar"})
for dirpath, _, filenames in os.walk("/mnt/evidence/collected/"):
    for fn in filenames:
        fp = os.path.join(dirpath, fn)
        try:
            for m in rules.match(fp, timeout=60):
                hits = [{"offset": hex(o), "id": i} for o, i, _ in m.strings]
                print(json.dumps({"file": fp, "rule": m.rule, "strings": hits,
                                  "ts": datetime.now(timezone.utc).isoformat()}))
        except yara.TimeoutError:
            pass
```

### 3.2 Memory Hunting

Hunt for in-memory-only payloads in process dumps:
```yara
rule Cobalt_Strike_Beacon_Memory {
    meta:
        description = "Cobalt Strike beacon in process memory"
    strings:
        $cfg = { 2E 2F 2E 2F 2E 2C }
        $pipe = "\\\\.\\pipe\\msagent_" ascii wide
        $mask = { 48 8B 44 24 ?? 48 89 44 24 ?? }
    condition:
        2 of them
}
```

```bash
yara rules/memory.yar /mnt/evidence/lsass_dump.dmp
```

### 3.3 Network Hunting

Scan captured payloads and PCAP exports for C2 artifacts (beacon configs, shellcode blobs, decrypted TLS streams). Pipe through yara for file-like matches and use a timeout to bound scan cost.

### 3.4 YARA + Loki (Filesystem IOC Scanning)

Loki wraps YARA with process/file/registry IOC checks and a signature base:
```bash
git clone https://github.com/Neo23x0/Loki.git && cd Loki
python3 loki.py --update
python3 loki.py -p /mnt/evidence/ -l ./log -r ./report.json --dontwait --nopesieve
```

Loki correlates YARA hits with hash and filename IOCs, useful for rapid IR triage of a drive or share.

### 3.5 Matching Against Threat Intel Samples

Pull samples from VirusTotal, MalwareBazaar, or VX-Underground, hash them, and confirm the rule matches the whole family (not just one variant):
```bash
curl -s "https://mb-api.abuse.ch/api/v1/" -d "get_siginfo&hash=<sha256>" | jq .
curl -s "https://mb-api.abuse.ch/api/v1/" -d "query=get_recent&selector=100" -H "Auth-Key: <key>" | jq .
```

### 3.6 Automated Rule Generation (yarGen)

```bash
git clone https://github.com/Neo23x0/yarGen.git && cd yarGen
python3 yarGen.py -m /mnt/evidence/malware_samples/ -o generated.yar --excludegood --score 50
```

Review every generated rule manually; yarGen output is a starting point, not a final signature.

---

## 4. Tool-Specific Guidance
```bash
yara --version
yara -w rules/*.yar /dev/null
yara --print-strings rules/emotet.yar sample.bin
yara -r rules/ /mnt/evidence/ -m 5
```

```python
import yara
rules = yara.compile(filepaths={"ns": "rules/all.yar"})
rules.match("sample.bin", timeout=120, modules=True)

import pefile
pe = pefile.PE("sample.dll")
print([(e.dll.decode(), i.name.decode() if i.name else "") for e in pe.DIRECTORY_ENTRY_IMPORT for i in e.imports][:20])
```

---

## 5. PoC Generation

### Sample Rule PoC

```yara
rule Example_Stager_Macro {
    meta:
        author = "HiveBreach CTI"
        description = "Detects macro stager with obfuscated PowerShell"
        reference = "https://attack.mitre.org/software/S0367/"
        mitre = "T1059.001"
        severity = "high"
    strings:
        $mz = "MZ" at 0
        $mutex = "Global\\UniqueM4lwareMutex" ascii wide
        $c2 = /https?:\/\/[a-z]{5,10}\.(xyz|top|buzz)\/gate\.php/ nocase
        $valloc = "VirtualAllocEx" ascii
        $dec = { 8B 45 ?? 33 C1 89 45 ?? }
    condition:
        $mz and filesize < 2MB and
        ($mutex or $c2) and $valloc and $dec
}
```

### PoC Test Record

```markdown
## YARA Rule Validation — [RULE_NAME]
Rule: rules/example.yar | Sample: stager.bin (SHA256 e3b0c44...)
Match: true positive (VT detections: 45/72)
FP scan: 0 matches across 12,480 clean files (0.00%) | Benchmark: 1,240 files/sec
Verdict: PASS / FAIL
```

---

## 6. Verification (Sandbox)

- [ ] All rules compile with `yara -w rules/*.yar /dev/null`
- [ ] Rules match all known-good samples of the family (no false negatives)
- [ ] FP rate below 0.1% against a clean system-file corpus
- [ ] Rule performance allows 1000+ files/sec single-threaded
- [ ] Module guards present (pe.is_pe / elf.is_elf) where modules are used

### Prohibited Actions
- Running untested community rules against production endpoints
- Deploying high-severity rules without FP validation
- Scanning live memory of production systems without approval

---

## 7. CheatSheet

### Condition Operators
| Operator | Example | Meaning |
|---|---|---|
| and / or / not | `$a and ($b or $c)` | Boolean logic |
| of | `2 of ($a,$b,$c)` | Any 2 strings |
| at | `$mz at 0` | Fixed offset |
| in | `$x in (0..512)` | Offset range |
| for any/all | `for any s in (1..) : s` | Section iteration |
| filesize | `filesize < 2MB` | Size filter |
| uint16(0) | `uint16(0) == 0x5A4D` | Header check |

### Modules
| Module | Key Data |
|---|---|
| pe | is_pe, sections, imports, exports, version_info, overlay |
| elf | is_elf, type, sections, machine, entry_point |
| math | entropy, mean, dev, hash |

### Performance Rules
1. Cheapest and most discriminating conditions first (short-circuit)
2. Use `filesize` to skip irrelevant files early; prefer hex over regex
3. Set per-file `timeout` to bound worst-case scan cost

---

## 8. Related Techniques (MITRE ATT&CK Mapping)

| Technique ID | Name | Relation |
|---|---|---|
| T1027 | Obfuscated Files or Information | Rule target (packing, encoding) |
| T1055 | Process Injection | Memory-only detection target |
| T1059.001 | PowerShell | Script/loader rule target |
| T1071.001 | Web Protocols | C2 URI rule target |
| T1105 | Ingress Tool Transfer | Payload staging detection |
| T1560.001 | Archive via Utility | Staging/compression detection |

---

## 9. References

- YARA Documentation: https://virustotal.github.io/yara/
- yarGen: https://github.com/Neo23x0/yarGen
- Loki: https://github.com/Neo23x0/Loki
- MalwareBazaar: https://bazaar.abuse.ch/

---

*This playbook is for authorised security testing only. All verification must occur in sandbox environments.*
