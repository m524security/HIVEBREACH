# Cyber Threat Intelligence (CTI) — Skill Playbook

**Mitre ATT&CK ID:** T1591 (Gather Victim Org Information), T1593 (Search Open Websites/Domains), T1596 (Search Open Technical Databases), T1588 (Obtain Capabilities)
**OWASP Mapping:** N/A – Intelligence & Analysis Discipline
**Severity:** N/A – Analytical Discipline
**Last Updated:** 2026-08-02

---

## Metadata

```yaml
skill_id: threat-intel-v2
category: threat-intel
author: HiveBreach
mitre_attack_id: T1591
owasp_mapping: []
frameworks: [mitre-attack, lockheed-martin-kill-chain, diamond-model, stix-taxii]
tags: [threat-intelligence, mitre-attack, misp, stix, taxii, ioc, enrichment, threat-actor-profiling]
tools: [attackcti, mitreattack-python, stix2, taxii2-client, pymisp, shodan, censys, virustotal, otx]
verification_required: n/a
```

---

## 1. Detection

### 1.1 Priority Intelligence Requirements (PIRs)

| Level | Question | Output |
|---|---|---|
| Strategic | What are adversary long-term objectives for our sector? | Executive brief |
| Operational | Which TTPs are active against our industry now? | TTP watchlist |
| Tactical | What IOCs relate to the current incident? | IOC blocklist |
| Technical | What malware, C2 protocols, and CVEs are in use? | Detection rules |

### 1.2 Collection Sources

```bash
shodan search 'product:"Cobalt Strike Beacon"' --fields ip_str,port,org
shodan search 'http.title:"404 Not Found" country:RU' --fields ip_str,port
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq '.[].name_value'
curl -s "https://otx.alienvault.com/api/v1/indicators/ipv4/<ip>/general" -H "X-OTX-API-Key: <key>"
curl -s "https://api.abuseipdb.com/api/v2/check?ipAddress=<ip>" -H "Key: <key>" -H "Accept: application/json"
curl -s "https://www.virustotal.com/api/v3/ip_addresses/<ip>" -H "x-apikey: <key>"
```

### 1.3 Feed Categorization

| Type | Examples | Use |
|---|---|---|
| Commercial | Recorded Future, Mandiant, CrowdStrike | Attribution, actor profiles |
| Government | CISA AIS, MS-ISAC, InfraGard | Sector-aligned CVE/IOC flow |
| OSINT | OTX, abuse.ch, PhishTank | Wide, low-cost coverage |
| Internal | SIEM, EDR, DNS, NetFlow, honeypots | Behavioural TTP validation |

---

## 2. Confirmation

### 2.1 Feed Processing (TAXII 2.0/2.1)

```python
from taxii2client.v21 import Server, as_pages
server = Server("https://cti.example.com/taxii/", user="apiuser", password="apikey")
coll = server.api_roots[0].collections[0]
for bundle in as_pages(coll.get_objects, added_after="2026-01-01T00:00:00Z", per_request=100):
    process_bundle(bundle)
```

### 2.2 STIX Normalization (stix2)

```python
import stix2
for obj in stix2.parse(bundle, allow_custom=True).objects:
    if obj.type == "indicator":
        store_indicator(obj.id, obj.pattern, obj.confidence, obj.labels)
    elif obj.type == "threat-actor":
        store_actor(obj.id, obj.name, obj.aliases)
```

### 2.3 IOC Validation & TTL

| Indicator | TTL | Validation |
|---|---|---|
| IP | 30 days | Cross-source reputation, GreyNoise noise check |
| Domain | 90 days | Passive DNS, WHOIS, CT logs |
| URL | 30 days | urlscan.io render, VT scan |
| Hash | 365 days | VT detections, MalwareBazaar |

Deduplicate by normalized value + type. Confidence: confirmed incident +50, multi-source +30, contextual +20, single feed +10.

---

## 3. Exploitation

### 3.1 MITRE ATT&CK Mapping

```python
from attackcti import attack_client
lift = attack_client()
for t in lift.get_techniques_used_by_group("G0016"):
    tid = next((r.get("external_id", "") for r in t.get("external_references", [])
                if r.get("source_name") == "mitre-attack"), "")
    if tid:
        print(tid, t.get("name"), [p.get("phase_name", "") for p in t.get("kill_chain_phases", [])])
```

Map behaviour to techniques/sub-techniques, then to software (S-codes), groups (G-codes), and mitigations (M-codes) so every detection gap has a named control.

### 3.2 ATT&CK Navigator Layer

```python
import json
def navigator_layer(group, tm, color="#ff6666"):
    techs = [{"techniqueID": tid, "tactic": i["tactics"][0] if i["tactics"] else "",
              "color": color, "comment": i["name"], "score": 100} for tid, i in tm.items()]
    return {"name": f"{group} TTP Coverage", "domain": "enterprise-attack",
            "versions": {"attack": "16.1", "navigator": "5.1.0", "layer": "4.5"},
            "layout": {"layout": "side", "showID": True}, "sorting": 0,
            "techniques": techs,
            "filters": {"platforms": ["Windows", "Linux", "macOS", "Cloud"]},
            "gradient": {"colors": ["#ffffff", color], "minValue": 0, "maxValue": 100}}
json.dump(navigator_layer("APT29", technique_map), open("apt29_layer.json", "w"), indent=2)
```

Load at https://mitre-attack.github.io/attack-navigator/ and overlay a detection-coverage layer to expose gaps.

### 3.3 Threat Actor Profiling

| Dimension | Data Collected |
|---|---|
| Identity | ATT&CK G-code, aliases (APT29 = Cozy Bear = Midnight Blizzard), sponsor |
| Motivation | Espionage, financial, hacktivism, destruction |
| Targeting | Sectors, geographies, IT/OT/cloud, supply chain |
| TTPs | Top 5 techniques per tactic phase |
| Tooling | Malware families, C2 frameworks, custom implants |
| Infrastructure | VPS providers, registrars, cert patterns, JARM/JA3S |

### 3.4 Kill Chain Mapping

| Phase | Intel to Collect | ATT&CK Anchor |
|---|---|---|
| Reconnaissance | Target profiles, tech stack | T1595, T1590 |
| Weaponization | Malware samples, exploit kits | T1587, T1588 |
| Delivery | Phishing URLs, attachment hashes | T1566 |
| Exploitation | CVE details, payloads | T1190, T1203 |
| Installation | Persistence mechanisms | T1547, T1053 |
| C2 | C2 domains, IPs, protocols, beacons | T1071, T1573 |
| Actions on Objective | Exfil methods, lateral movement | T1041, T1021 |

### 3.5 Diamond Model

Adversary -> Capability -> Infrastructure -> Victim. Example: APT29 (G0016) uses SUNBURST/Cobalt Strike via evil.example.com, 203.0.113.50, cert CTL against a software vendor supply chain. Confidence: medium.

### 3.6 Threat Landscape Assessment (MISP)

```python
from pymisp import PyMISP
misp = PyMISP("https://misp.local", "API_KEY", ssl=False)
by_type = {}
for evt in misp.search(controller="events", published=True, last="90d"):
    for a in evt.get("Attribute", []):
        by_type[a["type"]] = by_type.get(a["type"], 0) + 1
print(sorted(by_type.items(), key=lambda kv: kv[1], reverse=True)[:5])
```

---

## 4. Tool-Specific Guidance

### 4.1 attackcti
```python
from attackcti import attack_client
lift = attack_client()
lift.get_enterprise_techniques(); lift.get_groups()
lift.get_techniques_used_by_group("G0016"); lift.get_software(); lift.get_mitigations()
```

### 4.2 MISP Event Creation (PyMISP)
```python
from pymisp import ExpandedPyMISP, MISPEvent
misp = ExpandedPyMISP("https://misp.local", "API_KEY", ssl=False)
event = MISPEvent()
event.info = "TA-2026-001 Finance sector targeting"
event.threat_level_id = 2
event.add_attribute("ip-dst", "203.0.113.50")
event.add_attribute("domain", "evil.example.com")
event.add_attribute("md5", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")
misp.add_event(event, pythonify=True); misp.publish(event)
```

### 4.3 STIX Indicator Creation (stix2)
```python
import stix2
ind = stix2.Indicator(name="Malicious C2 Domain",
    pattern="[domain-name:value = 'evil-c2.example.com']",
    pattern_type="stix", valid_from="2026-01-15T00:00:00Z",
    confidence=80, labels=["malicious-activity"],
    object_marking_refs=[stix2.TLP_GREEN])
print(ind.serialize(pretty=True))
```

### 4.4 IOC Enrichment Pipeline
```python
import requests
def enrich_ip(ip, vt_key):
    r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                     headers={"x-apikey": vt_key})
    stats = r.json()["data"]["attributes"]["last_analysis_stats"]
    return {"ip": ip, "vt_malicious": stats.get("malicious", 0), "vt_total": sum(stats.values())}
```

Respect rate limits (VT free 4/min), cache 24h, and log failed calls rather than returning empty results.

---

## 5. PoC Generation

### Intelligence Report Template

```markdown
# Threat Intelligence Report — [TITLE]
**TLP:** AMBER | **Date:** YYYY-MM-DD | **Tracking ID:** TIR-2026-XXX

## Executive Summary
<2-3 paragraphs: finding, impact, recommended actions>

## IOCs
- Domain evil.example.com (High), SHA256 <hash> (Medium)

## Recommended Actions
1. Block domains/IPs on proxy and DNS
2. Deploy YARA rule for Cobalt Strike
3. Hunt for invoice_*.docm in mail archives
```

---

## 6. Verification (Sandbox)

- [ ] IOC accuracy cross-referenced with at least 2 independent sources
- [ ] STIX bundles parse without schema errors; spec_version checked (2.0 vs 2.1)
- [ ] TAXII pagination handled (no silent data loss); attribution confidence qualified
- [ ] Navigator layer JSON validates and renders in the Navigator
- [ ] TLP marking respected in all exports

### Prohibited Actions
- Acting on unvalidated, single-source IOCs
- Blocking legitimate shared infrastructure (CDNs, hosting IPs)
- Redistributing TLP:RED outside the agreed community

---

## 7. CheatSheet

### TLP Classification
| TLP | Distribution |
|---|---|
| RED | Named individuals only |
| AMBER+STRICT | Organisation only |
| AMBER | Organisation and clients |
| GREEN | Sector/ISAC community |
| CLEAR | Public |

### STIX Object Map
| Object | Routes To |
|---|---|
| indicator | SIEM lookup, firewall blocklist |
| malware | EDR intel library |
| threat-actor / campaign | TIP analyst context |
| course-of-action | SOAR playbook, wiki |

---

## 8. Related Techniques (MITRE ATT&CK Mapping)

| Technique ID | Name | Relation |
|---|---|---|
| T1591 | Gather Victim Org Information | Strategic intel collection |
| T1593 | Search Open Websites/Domains | OSINT collection |
| T1596 | Search Open Technical Databases | Shodan/Censys/CT logs |
| T1588 | Obtain Capabilities | Exploit/C2 acquisition |
| T1588.005 | Obtain Capabilities: Exploits | CVE staging feed |
| T1608 | Stage Capabilities | Weaponisation planning |
| T1190 | Exploit Public-Facing Application | Target of intel |

---

## 9. References

- MITRE ATT&CK: https://attack.mitre.org/
- ATT&CK Navigator: https://mitre-attack.github.io/attack-navigator/
- OASIS STIX 2.1: https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html
- MISP Project: https://www.misp-project.org/
- PyMISP: https://github.com/MISP/PyMISP

---

*This playbook is for authorised threat intelligence operations. Handle all intelligence according to TLP classification and applicable sharing agreements.*
