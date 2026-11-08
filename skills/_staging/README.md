# S̲taging Area — CVE/KEV Auto-Ingested Skills

This directory is a **quarantine / review stage** for skill entries automatically generated from CVE (Common Vulnerabilities and Exposures) and KEV (Known Exploited Vulnerabilities) ingestion pipelines.

---

## Purpose

Automated ingestion from CVE feeds and CISA KEV produces draft skill entries that follow the HiveBreach skill template. These drafts are placed here for human review before promotion to the main `skills/` tree.

---

## Ingestion Sources

| Source | Feed | Update Frequency |
|---|---|---|
| CVE | `https://cve.mitre.org/data/downloads/allitems.html` | Daily |
| CISA KEV | `https://www.cisa.gov/known-exploited-vulnerabilities-catalog` | On CISA update |
| NVD | `https://services.nvd.nist.gov/rest/json/cves/2.0` | Every 2 hours |
| Exploit-DB | `https://gitlab.com/exploit-database/exploitdb` | Weekly |

---

## Ingestion Pipeline (Automated)

```
CVE/KEV Feed
    │
    ▼
Parse → Normalise → Deduplicate
    │
    ▼
Generate Draft Skill (YAML frontmatter + markdown body)
    │
    ▼
Drop into skills/_staging/YYYY-MM/ as CVE-YYYY-NNNN.md
    │
    ▼
[WAITING FOR HUMAN REVIEW]
```

---

## Staging Directory Structure

```
_staging/
├── README.md              ← This file
├── 2026-07/
│   ├── CVE-2026-1234.md   ← Draft skill, not yet reviewed
│   ├── CVE-2026-5678.md
│   └── CVE-2026-9012.md   ← Manually added during triage
├── 2026-06/
│   ├── CVE-2026-0123.md
│   └── CVE-2026-0456.md
└── ARCHIVE/               ← Promoted or rejected entries, moved here
```

---

## Review Process

### Step 1 — Triage (within 24h of ingestion)

- [ ] Duplicate of existing skill? → Reject (move to `ARCHIVE/rejected/`)
- [ ] Within scope of current engagement? → Fast-track
- [ ] Out of date / superceded? → Reject with note
- [ ] Requires sandbox environment? → Tag `verification_required: sandbox`

### Step 2 — Technical Review

- [ ] CVE description accurately summarised
- [ ] MITRE ATT&CK mapping correct
- [ ] OWASP / CWE mapping correct
- [ ] Tools and commands verified
- [ ] Reproduction steps tested (sandbox)
- [ ] Level of effort / impact assessed

### Step 3 — Quality Check

- [ ] Follows skill template (metadata, sections, formatting)
- [ ] No broken commands or typos
- [ ] PoC template included
- [ ] Remediation guidance provided
- [ ] Cross-referenced with existing skills for overlap

### Step 4 — Promotion

Once approved:

```bash
# Move from staging to main skills tree
mv skills/_staging/2026-07/CVE-2026-1234.md skills/penetration-testing/
# Or appropriate category folder

# Tag as reviewed
touch skills/_staging/2026-07/CVE-2026-1234.md.PROMOTED

# Commit with message
git add .
git commit -m "skills: promote CVE-2026-1234 from staging to penetration-testing"
```

---

## Draft Skill Template

Each ingested entry auto-generates from this template:

```markdown
# CVE-YYYY-NNNN — [Vulnerability Title]

**CVE ID:** CVE-YYYY-NNNN
**CVSS:** X.X
**CWE:** CWE-XXX
**Known Exploited:** YYYY-MM-DD (KEV date if applicable)

---

## Metadata

```yaml
skill_id: cve-YYYY-NNNN-v1
source: cve-ingestion / kev-ingestion
ingested: YYYY-MM-DD
mitre_attack_id: <auto-mapped>
cwe: CWE-XXX
tags:
  - cve-YYYY-NNNN
  - <technology>
  - <vulnerability-type>
verification_required: sandbox
---

## Summary

<2–3 sentence description of the vulnerability>

## Affected Versions

| Vendor | Product | Versions |
|---|---|---|
| Vendor | Product | < X.Y.Z |

## Detection

<Commands, nmap scripts, or Burp steps to detect>

## Exploitation

<Step-by-step exploitation guide, tool commands>

## PoC

<Reproducible PoC — code block with curl / Python / Metasploit>

## Mitigation / Remediation

- Upgrade to version > X.Y.Z
- WAF rule: ...
- Configuration fix: ...

## References

- [NVD Entry](https://nvd.nist.gov/vuln/detail/CVE-YYYY-NNNN)
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Exploit-DB](https://www.exploit-db.com/...)
```

---

## Rejection Reasons

| Code | Reason | Action |
|---|---|---|
| R01 | Duplicate of existing skill | Archive with cross-ref to existing |
| R02 | Out of scope for current engagements | Archive, revisit in 90 days |
| R03 | No reproducible PoC available | Archive, tag for monitoring |
| R04 | CVSS < 4.0 (low severity) | Archive or fast-track if in critical infra |
| R05 | Superceded by newer CVE variant | Archive with cross-ref to replacement |

---

## Automation Script (Reference)

```python
#!/usr/bin/env python3
"""
cve_ingest.py — CVE/KEV ingestion pipeline for HiveBreach skills.
Usage: python cve_ingest.py [--source cve|kev] [--days 7]
"""
import json, os, datetime, yaml
from urllib.request import urlopen

STAGING_DIR = "skills/_staging"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def fetch_cisa_kev():
    resp = urlopen(CISA_KEV_URL)
    return json.loads(resp.read())["vulnerabilities"]

def generate_draft(cve_entry):
    date_prefix = datetime.date.today().strftime("%Y-%m")
    cve_id = cve_entry["cveID"]
    filename = f"{STAGING_DIR}/{date_prefix}/{cve_id}.md"
    os.makedirs(os.path.dirname(filename), exist_ok=True)

    with open(filename, "w") as f:
        f.write(f"# {cve_id} — {cve_entry['vulnerabilityName']}\n\n")
        f.write(f"**CVE ID:** {cve_id}\n")
        f.write(f"**KEV Date:** {cve_entry['dateAdded']}\n\n")
        f.write("---\n\n")
        f.write("<!-- AUTO-GENERATED DRAFT — requires human review -->\n")
        f.write("<!-- STAGING only — do not use operationally until reviewed -->\n")
    print(f"  Wrote {filename}")

if __name__ == "__main__":
    print("[cve_ingest] Fetching CISA KEV feed...")
    for entry in fetch_cisa_kev():
        generate_draft(entry)
    print("[cve_ingest] Done.")
```

---

## SLA

| Phase | Target | Owner |
|---|---|---|
| Ingestion to staging | < 1 hour | Automation |
| Triage | < 24 hours | CTI Lead |
| Technical review | < 72 hours | Technical Lead |
| Promotion / rejection | < 1 week | CTI Lead |
| Archive cleanup | Monthly | Automation |

---

*This staging area enforces a review gate between automated ingestion and operational use. Never promote a draft without human review.*
