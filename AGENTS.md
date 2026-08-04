# HiveBreach Agent Manifest

> 20 specialised autonomous agents operating under the HiveBreach ECC (Evolvable Command & Control) framework.

---

## Agent Cards

### Reconnaissance Agents

---
agent: recon-agent
harnesses: [opencode]
stage: recon
tools: [nmap, masscan, rustscan, naabu]
verification: "Host discovery verified via multi-tool cross-check against target scope"
communicates_with: [vuln-scan-agent, scheduler-agent, audit-agent]
---

---
agent: dns-agent
harnesses: [opencode]
stage: recon
tools: [dnsrecon, subfinder, amass, dig]
verification: "DNS records validated against authoritative name servers"
communicates_with: [web-discover-agent, risk-agent, audit-agent]
---

---
agent: web-discover-agent
harnesses: [opencode]
stage: recon
tools: [ffuf, gobuster, httpx, katana]
verification: "Endpoints validated via HTTP response analysis and screenshot comparison"
communicates_with: [web-exploit-agent, dns-agent, audit-agent]
---

---
agent: vuln-scan-agent
harnesses: [opencode]
stage: recon
tools: [nuclei, nikto, nessus, openvas]
verification: "Findings verified against CVE database and false-positive filter"
communicates_with: [exploit-agent, risk-agent, audit-agent]
---

### Exploitation Agents

---
agent: exploit-agent
harnesses: [opencode]
stage: exploitation
tools: [metasploit, empire, custom-payloads]
verification: "Exploit success verified via callback confirmation and state-agent validation"
communicates_with: [vuln-scan-agent, pivot-agent, validator-agent, audit-agent, sandbox-agent]
---

---
agent: web-exploit-agent
harnesses: [opencode]
stage: exploitation
tools: [sqlmap, xsser, ffuf, burp]
verification: "Injection confirmed via out-of-band callback or response diff analysis"
communicates_with: [web-discover-agent, creed-creds-agent, validator-agent, audit-agent]
---

---
agent: creed-creds-agent
harnesses: [opencode]
stage: exploitation
tools: [hydra, john, hashcat, responder]
verification: "Credentials verified against target service before reporting"
communicates_with: [exploit-agent, pivot-agent, report-agent, audit-agent, vault-agent]
---

---
agent: pivot-agent
harnesses: [opencode]
stage: exploitation
tools: [chisel, sshuttle, ligolo, proxychains]
verification: "Tunnel connectivity verified via ICMP/TCP reachability to target subnet"
communicates_with: [exploit-agent, creed-creds-agent, sandbox-agent, audit-agent]
---

### Analysis Agents

---
agent: analyzer-agent
harnesses: [opencode]
stage: analysis
tools: [elk, splunk, jq, grep]
verification: "Correlation rules validated against historical true-positive dataset"
communicates_with: [state-agent, risk-agent, report-agent, audit-agent]
---

---
agent: state-agent
harnesses: [opencode]
stage: analysis
tools: [ansible, osquery, custom-checks]
verification: "State assertions verified via idempotent re-check with different method"
communicates_with: [analyzer-agent, validator-agent, audit-agent, config-agent]
---

---
agent: risk-agent
harnesses: [opencode]
stage: analysis
tools: [cvss-calc, custom-risk-engine]
verification: "Scores validated against CVSS v4.0 calculator"
communicates_with: [vuln-scan-agent, report-agent, scope-agent, audit-agent]
---

---
agent: report-agent
harnesses: [opencode]
stage: analysis
tools: [jinja2, weasyprint, markdown]
verification: "Report sections validated against finding evidence in audit log"
communicates_with: [risk-agent, validator-agent, audit-agent]
---

### Support Agents

---
agent: scope-agent
harnesses: [opencode]
stage: support
tools: [cidr-calc, custom-scope-engine]
verification: "Target IPs/domains validated against ROE whitelist before any action"
communicates_with: [recon-agent, exploit-agent, scheduler-agent, audit-agent]
---

---
agent: audit-agent
harnesses: [opencode]
stage: support
tools: [hmac-sha256, json-logger]
verification: "Log integrity verified via HMAC chain validation"
communicates_with: [all-agents, report-agent]
---

---
agent: scheduler-agent
harnesses: [opencode]
stage: support
tools: [asyncio, celery, redis]
verification: "Pipeline DAG verified via topological sort and dependency resolution"
communicates_with: [all-agents, audit-agent]
---

---
agent: validator-agent
harnesses: [opencode]
stage: support
tools: [custom-poc-engine, state-agent]
verification: "Exploit PoC replayed in sandbox for independent confirmation"
communicates_with: [exploit-agent, web-exploit-agent, report-agent, sandbox-agent, audit-agent]
---

### Infrastructure Agents

---
agent: sandbox-agent
harnesses: [opencode]
stage: infrastructure
tools: [docker, vagrant, packer]
verification: "Container integrity verified via hash comparison and health check API"
communicates_with: [exploit-agent, pivot-agent, validator-agent, audit-agent]
---

---
agent: vault-agent
harnesses: [opencode]
stage: infrastructure
tools: [cryptography, aead-aes-256-gcm]
verification: "Encryption/decryption verified via KAT vectors before operational use"
communicates_with: [creed-creds-agent, config-agent, audit-agent]
---

---
agent: config-agent
harnesses: [opencode]
stage: infrastructure
tools: [env-template, jsonnet, yaml]
verification: "Config validated against JSON schema before distribution"
communicates_with: [state-agent, vault-agent, scheduler-agent, audit-agent]
---

---
agent: comm-agent
harnesses: [opencode]
stage: infrastructure
tools: [aiohttp, websockets, llm-client]
verification: "Message delivery confirmed via ack/nack protocol with configurable retry"
communicates_with: [scheduler-agent, all-agents, audit-agent]
---

## Agent Routing Table

| Agent | Role | Stage | Communicates With |
|-------|------|-------|-------------------|
| recon-agent | Network reconnaissance, host discovery, port scanning | recon | vuln-scan-agent, scheduler-agent, audit-agent |
| dns-agent | DNS enumeration, subdomain discovery, zone transfer | recon | web-discover-agent, risk-agent, audit-agent |
| web-discover-agent | Web app discovery, directory brute-forcing, endpoint mapping | recon | web-exploit-agent, dns-agent, audit-agent |
| vuln-scan-agent | Vulnerability scanning, CVE matching, misconfiguration detection | recon | exploit-agent, risk-agent, audit-agent |
| exploit-agent | Exploit selection, payload generation, delivery orchestration | exploitation | vuln-scan-agent, pivot-agent, validator-agent, audit-agent |
| web-exploit-agent | Web exploitation (SQLi, XSS, SSRF, RCE, LFI/RFI) | exploitation | web-discover-agent, creed-creds-agent, validator-agent, audit-agent |
| creed-creds-agent | Credential harvesting, password spraying, hash capture | exploitation | exploit-agent, pivot-agent, report-agent, vault-agent, audit-agent |
| pivot-agent | Lateral movement, tunnel establishment, proxy chains | exploitation | exploit-agent, creed-creds-agent, sandbox-agent, audit-agent |
| analyzer-agent | Log analysis, pattern detection, indicator extraction | analysis | state-agent, risk-agent, report-agent, audit-agent |
| state-agent | System state verification, config drift detection | analysis | analyzer-agent, validator-agent, config-agent, audit-agent |
| risk-agent | Risk scoring, impact assessment, priority ranking | analysis | vuln-scan-agent, report-agent, scope-agent, audit-agent |
| report-agent | Report generation, evidence packaging, executive summary | analysis | risk-agent, validator-agent, audit-agent |
| scope-agent | ROE enforcement, target validation, boundary compliance | support | recon-agent, exploit-agent, scheduler-agent, audit-agent |
| audit-agent | Full telemetry capture, chain-of-custody logging, immutable audit trail | support | all agents, report-agent |
| scheduler-agent | Pipeline orchestration, dependency resolution, parallel execution | support | all agents, audit-agent |
| validator-agent | PoC validation, exploit verification, confidence scoring | support | exploit-agent, web-exploit-agent, report-agent, sandbox-agent, audit-agent |
| sandbox-agent | Docker sandbox lifecycle, snapshot/restore, health checks | infrastructure | exploit-agent, pivot-agent, validator-agent, audit-agent |
| vault-agent | Secrets management, AES-256-GCM encryption, key rotation | infrastructure | creed-creds-agent, config-agent, audit-agent |
| config-agent | Configuration distribution, env injection, dynamic parameter resolution | infrastructure | state-agent, vault-agent, scheduler-agent, audit-agent |
| comm-agent | Inter-agent messaging, result routing, LLM abstraction | infrastructure | scheduler-agent, all agents, audit-agent |

## Agent Communication Protocol

Agents communicate via structured JSON messages routed through the scheduler-agent. Each message includes:
- `from_agent` / `to_agent` routing
- `correlation_id` for traceability
- `payload` with action-specific data
- `scope_token` for ROE compliance verification

All agent actions are logged by the audit-agent with full chain-of-custody metadata.
