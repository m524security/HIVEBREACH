---
skill: log-pattern-analysis-deep-aggressive
mitre_attack_id: TA0040
owasp_mapping: []
difficulty: advanced
mode: deep-aggressive
tags: [log-correlation, pattern-detection, ioc-extraction, timeline-analysis, attack-chain-reconstruction, siem-query, anomaly-detection, log-normalization]
---

# Deep Aggressive Mode Playbook: analyzer-agent

> Purpose: This playbook is the deep-aggressive operational doctrine for log analysis, pattern detection, and indicator extraction across the entire HiveBreach engagement. Every event is normalized, every indicator enriched, and every chain reconstructed back to source evidence.

## Phase 1 — Log Ingestion and Normalization

Reference: skills/dfir/skill-playbook.md, skills/dfir/incident-triage.md

1. Collect raw findings from all agents via audit-agent message bus (recon-agent, dns-agent, web-discover-agent, vuln-scan-agent, exploit-agent, web-exploit-agent, creed-creds-agent, pivot-agent, state-agent).
2. Normalize all findings into unified JSON schema with `timestamp`, `source_agent`, `target`, `finding_type`, and `evidence`.
3. Convert every timestamp to UTC ISO8601:
   - `date -u -d "@$(date +%s)" +%Y-%m-%dT%H:%M:%SZ`
   - Flag entries with source-clock skew > 30 seconds.
4. Map fields into Elastic Common Schema (ECS) for ELK indexing:
   - `event.duration`, `source.ip`, `target.host`, `event.code`, `process.name`.
5. Deduplicate identical events; keep the highest-fidelity record and log the merge.
6. Tag normalization failures; never silently drop an unparsable event.

## Phase 2 — Regex Pattern Extraction

1. Extract indicators of compromise with anchored regexes:
   - IP: `\b(?:\d{1,3}\.){3}\d{1,3}\b`
   - Domain: `\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b`
   - SHA256: `\b[0-9a-fA-F]{64}\b`
   - URL: `\bhttps?://[^\s"'<>]+`
   - Registry key: `(?:HKLM|HKCU|HKCR|HKU)\\[^\s]+`
2. Run extraction with Python:
   ```python
   import re, json
   pats = {"ip": r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "domain": r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"}
   for f in files:
       text = open(f, errors="ignore").read()
       hits = {k: set(re.findall(v, text)) for k, v in pats.items()}
   ```
3. Apply a whitelist pass to drop internal/benign matches before promotion.
4. Categorize strings from collected binaries per skills/malware-analysis/static-analysis.md (URLs, IPs, registry, mutex, commands, keys).

## Phase 3 — Indicator Extraction and Enrichment

Reference: skills/threat-intel/skill-playbook.md

1. Classify extracted IOCs by type and apply TTL:
   - IP -> 30 days; cross-source reputation, GreyNoise noise check
   - Domain -> 90 days; passive DNS, WHOIS, CT logs
   - URL -> 30 days; urlscan.io render, VT scan
   - Hash -> 365 days; VT detections, MalwareBazaar
2. Enrich against external feeds:
   - `curl -s "https://api.abuseipdb.com/api/v2/check?ipAddress=<ip>" -H "Key: <key>"`
   - `curl -s "https://www.virustotal.com/api/v3/ip_addresses/<ip>" -H "x-apikey: <key>"`
   - `curl -s "https://otx.alienvault.com/api/v1/indicators/ipv4/<ip>/general" -H "X-OTX-API-Key: <key>"`
3. Score confidence: confirmed incident +50, multi-source +30, contextual +20, single feed +10.
4. Respect rate limits (VT free 4/min), cache 24h, log failed calls rather than returning empty results.
5. Map indicators to MITRE ATT&CK techniques using the artifact-to-technique table in skills/dfir/skill-playbook.md.

## Phase 4 — SIEM Querying (SPL and KQL)

Reference: skills/dfir/incident-triage.md hunt queries

1. Splunk SPL for suspicious login clustering:
   ```
   index=windows EventCode=4625 | stats count by user, src_ip | where count > 10
   ```
2. Splunk SPL for process chain detection:
   ```
   index=windows EventCode=4688 | transaction ParentProcessId | where match(_raw, "powershell|cmd|wmic|rundll32")
   ```
3. Splunk SPL for beacon detection:
   ```
   index=netflow | timechart span=60s count by dst_ip | where count > 5
   ```
4. Elasticsearch KQL for the same:
   ```
   winlog.channel:"Security" and event.code:"4625" | stats count by winlog.event_data.TargetUserName, source.ip
   event.code:"4688" and process.parent.name:"winword.exe"
   ```
5. ELK DSL aggregation for top talkers:
   ```
   curl -s "http://elk:9200/logs-*/_search" -H 'Content-Type: application/json' -d '{"size":0,"aggs":{"src":{"terms":{"field":"source.ip.keyword","size":20}}}}'
   ```

## Phase 5 — Correlation Rules

1. Apply correlation rules to identify relationships:
   - IP-based correlation: same target IP across different agent findings
   - Timeline correlation: events clustering within time windows (e.g., DNS lookup before web scan)
   - Credential correlation: same username across different target services
   - Process correlation: kill chain progression for same target (recon -> exploit -> pivot)
   - CVE correlation: link vuln-scan findings to exploit-agent results via CVE ID
2. Enforce the two-source minimum: never create a correlation from a single data point.
3. Use Python for merge-join correlation:
   ```python
   import pandas as pd
   ips = pd.read_json("findings.json")
   chains = ips.groupby("target").apply(lambda g: sorted(g.timestamp)).reset_index()
   ```
4. Confidence scoring: confirmed (0.95+) requires two independent sources plus logical kill-chain sense; partial chains get a confidence penalty.

## Phase 6 — Timeline Analysis and Attack Chain Reconstruction

Reference: skills/dfir/skill-playbook.md, skills/dfir/incident-triage.md

1. Build a host timeline from all events:
   ```bash
   sort -t, -k1 timeline_raw.csv > timeline_sorted.csv
   grep -iE "powershell|cmd\.exe|schtasks|rundll32" timeline_sorted.csv | sort -u
   ```
2. Reconstruct directed attack chains:
   ```python
   import networkx as nx
   G = nx.DiGraph()
   G.add_edge("scan", "exploit", weight=0.5); G.add_edge("exploit", "creds", weight=0.9)
   for n in nx.dfs_preorder_nodes(G, "scan"): print(n)
   ```
3. Pivot on suspicious commands and source IPs:
   ```bash
   grep -iE "powershell -enc|iwr|schtasks|wmic process|curl" timeline.csv | sort -u
   ```
4. Correlate state-agent deltas into the timeline: file creations/process spawns must match the event sequence.

## Phase 7 — Anomaly Detection

1. Statistical outliers in event volume (z-score, IQR) across hosts and time buckets.
2. Beaconing detection: compute inter-arrival deltas between connections to a candidate C2:
   ```bash
   tshark -r capture.pcap -Y "tcp.port == 443" -T fields -e frame.time_epoch | awk '{print int($1)}' | uniq -d
   ```
3. Impossible-travel login analysis across geographic sources.
4. Event-ID gap analysis in Windows Security logs indicating log clearing:
   - Check for missing 4624/4625/4688 within a session window.
5. Fold YARA hits from skills/threat-intel/yara-hunting.md into the anomaly set.

## Phase 8 — False Positive Elimination

1. Reject correlations that fail logical kill-chain sense (no plausible attack progression).
2. Filter scanner-induced noise: duplicated port hits, benign service banners.
3. Cross-validate high-value chains manually by tracing through raw findings.
4. Retain rejected correlations in the audit trail with the rejection reason — never delete evidence.

## Phase 9 — Output and Handoff

1. Produce structured intelligence output:
   - Attack chain graphs (DOT + JSON)
   - IOC lists (enriched, classified, confidence-scored)
   - Timeline summaries (UTC-normalized)
2. Pass to risk-agent with confidence and criticality for every chain.
3. Pass structured analysis to report-agent for documentation.
4. Send pre/post event logs to state-agent for state-based cross-validation.
5. Log the complete correlation activity with input/output counts to audit-agent.

## Verification

1. Correlation rules validated against a historical true-positive dataset of known attack chains; >90% precision is production-ready.
2. Every chain traced back to raw findings; confidence reflects the number and strength of connecting events.
3. IOCs cross-referenced against at least two independent sources before publication.
4. Timestamps normalized to UTC; skew > 30 seconds flagged.
5. No correlation accepted below a two-source threshold.
6. All rejected correlations retained with reasons in the audit trail.

## Skill Library References
- skills/threat-intel/skill-playbook.md
- skills/threat-intel/yara-hunting.md
- skills/dfir/skill-playbook.md
- skills/dfir/incident-triage.md
- skills/malware-analysis/static-analysis.md
- skills/malware-analysis/dynamic-analysis.md
