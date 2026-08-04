<p align="center">
  <img src="./branding/banner.svg" alt="HiveBreach — Autonomous Multi-Agent Penetration Testing Framework" width="100%"/>
</p>

<p align="center">
  <img src="./branding/logo.svg" alt="HiveBreach logo" width="96"/>
</p>

<h1 align="center">HiveBreach</h1>
<p align="center"><b>Version 1.1.0</b> — Autonomous Multi-Agent AI Penetration Testing Framework</p>

<p align="center">
  <a href="#overview">Overview</a> •
  <a href="#features">Features</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#agents">Agents</a> •
  <a href="#skill-library">Skills</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#configuration">Configuration</a> •
  <a href="#governance">Governance</a> •
  <a href="#tools">Tools</a> •
  <a href="#testing">Testing</a> •
  <a href="#extensibility">Extensibility</a> •
  <a href="#roadmap">Roadmap</a> •
  <a href="#legal">Legal</a>
</p>

---

## Overview

HiveBreach is an **autonomous, multi-agent penetration testing framework** built on an ECC (Evolvable Command & Control) architecture. It deploys **41 specialised AI agents** that operate in a coordinated swarm across the full engagement lifecycle — from passive reconnaissance to final report generation.

**Core design principles:**

- **Swarm intelligence** — specialists own distinct attack surfaces (network, web, API, cloud, mobile, credential, container, AI/LLM, supply chain) and communicate through a structured message bus.
- **Deterministic safety** — a non-removable, LLM-free scope gate enforces the Rules of Engagement (ROE) before every action. No ROE → no engagement.
- **Evidence-first findings** — a finding only exists after a deterministic PoC reproduces it (R2). Zero false-positive reporting by design.
- **Self-learning** — the instinct system and lessons library make every engagement improve the next.
- **Provider-agnostic LLM routing** — Ollama (offline), NVIDIA NIM (free hosted), OpenAI and Anthropic (frontier), with automatic fallback.

---

## Features

**Engagement pipeline**
- Five-stage autonomic loop: **Plan → Execute → Verify → Learn → Persist**
- Linear six-phase flow: Planning → Reconnaissance → Exploitation → Analysis → Reporting → Cleanup
- DAG-based scheduling with parallel task execution and dependency resolution

**Intelligence layer**
- 65 deep-aggressive-mode skill playbooks mapped to MITRE ATT&CK (709-technique index) and OWASP Top 10
- Coverage across every modern attack surface: web, API, cloud, mobile, network, container/K8s, AI/LLM, CI/CD supply chain, ICS/OT, Web3, malware/DFIR, threat intel
- MITRE ATT&CK technique index (`skills/_knowledge/mitre-attack/`) — 709 techniques, 15 tactics, 189 groups

**Operational capabilities**
- Docker sandbox for isolated exploit reproduction (R5)
- AES-256-GCM encrypted secrets vault with short retention
- Dual-track PoC validation (exploit-verified / state-verified)
- Immutable HMAC-SHA256 chained audit trail (R7)
- Rate-limit-aware credential testing with auto-termination (R3)
- Token-aware LLM routing for cost control

**Self-learning**
- `tools/self-learn.py` — confirmed findings → lessons library (`skills/_knowledge/lessons/lessons.md`)
- `tools/gap-report.py` — live MITRE ATT&CK coverage tracking
- `instinct/` — pattern extraction + automated skill generation from recurring techniques

---

## Architecture

Six vertically integrated layers:

| Layer | Responsibility | Key Components |
|---|---|---|
| **Execution** | Runtime environment | Docker sandbox, secrets vault, PoC validator |
| **Knowledge** | Structured playbooks | Skill library, CVE/KEV feed, staging pipeline |
| **Agent** | Specialist roster | 41 agent cards (YAML), communication bus |
| **Toolbelt** | Kill-chain-mapped tools | 39-tool registry with risk/sandbox metadata |
| **Orchestration** | Control plane | Model router, scope gate, sanity checks, scheduler, message bus |
| **Governance** | Safety & compliance | ROE templates, CRITICAL-RULES R1–R10, audit trail, compliance mapping (SOC2/PCI-DSS/ISO 27001/NIST) |

---

## Agents

**41 specialised agents** across six stages. Each is defined by an ECC agent card (`agents/<name>/agent.md`) plus a `master-prompt.md` and deep-aggressive `skill-playbook.md`.

### Reconnaissance

| Agent | Role |
|---|---|
| osint-agent | Passive footprinting, subdomain/email enumeration, credential-leak search, certificate transparency |
| recon-agent | Host discovery, port scanning |
| dns-agent | DNS enumeration, zone transfers, subdomain discovery |
| web-discover-agent | Content discovery, endpoint mapping, tech fingerprinting |
| vuln-scan-agent | CVE matching, misconfiguration detection |

### Exploitation

| Agent | Role |
|---|---|
| exploit-agent | Metasploit module selection, payload delivery |
| web-exploit-agent | SQLi, XSS, SSRF, RCE, LFI/RFI |
| creed-creds-agent | Credential harvesting, password spraying |
| pivot-agent | Lateral movement, tunnels (chisel, sshuttle) |
| ai-security-agent | LLM prompt injection, RAG poisoning, MCP/tool abuse |
| container-escape-agent | Container/K8s escape, kubelet/kube-api, RBAC abuse |
| supply-chain-agent | CI/CD attacks, OIDC abuse, dependency confusion |

### Analysis / Support / Infrastructure

- **Analysis** — analyzer, state, risk, report agents
- **Support** — scope, audit, scheduler, validator agents
- **Infrastructure** — sandbox, vault, config, comm agents
- **Specialist** — api-testing, cloud-expert, mobile-app, web-expert, server-side, client-side, active-testing, exploit-poc, password-credential, wireless, threat-modeling, compliance-audit, sca-sbom, secrets-scanning, verification-correlation, cleanup-teardown agents

---

## Skill Library

65 playbooks organised by domain. Every playbook follows a standard structure: **Detection → Confirmation → Exploitation → Tool-Specific Guidance → PoC Generation → Verification (Sandbox) → MITRE Mapping → References**.

### Web Exploitation
- SQL Injection, XSS, SSRF, Command Injection, File Inclusion (LFI/RFI), SSTI, XXE, Insecure Deserialization, NoSQL Injection, IDOR, CSRF, Open Redirect, File Upload, CORS Misconfiguration, Request Smuggling
- **Web Attack Coverage** — full OWASP A01–A10 checklist

### API & GraphQL
- JWT Testing, BOLA/BFLA, Mass Assignment, OAuth/SSO, API Key Leaks, GraphQL Testing

### Network & Services
- Port Scanning, Service Enumeration, Host Discovery, Protocol Exploitation
- **OSI 7-Layer Weakness Model** — L1–L7 with layer-to-toolchain mapping

### Cloud
- AWS IAM (incl. privesc chains, S3), Azure AD / Entra ID, **Cloud Detection & Findings**, **Cloud Identity Privilege Escalation** (AWS/Azure/GCP)

### Modern Attack Surfaces (2026)
- **AI/LLM Security** — prompt injection, RAG poisoning, garak/PyRIT
- **CI/CD & Supply Chain** — runner takeover, OIDC abuse, dependency confusion
- **Container & Kubernetes** — escape vectors, kubelet/kube-api, RBAC
- **ICS/OT & IoT** — Modbus/DNP3/BACnet, PLC/HMI, firmware extraction
- **Web3** — smart contracts, wallets, bridges, Slither/Mythril/Foundry

### Detection & Credentials
- **Server-Based Detection & Findings**, **Version Fingerprinting → CVE Pipeline**, **Hash & Password Cracking** (rate-limit aware, auto-terminate)

### Mobile / Malware / DFIR / Threat Intel
- Mobile (Android/iOS), Android Insecure Storage, Static/Dynamic/Memory Malware Analysis, DFIR Incident Triage, Threat Intelligence, YARA Hunting, CVE Analysis

---

## Installation

**Requirements:** Python 3.10+, Docker (for sandbox execution), and one LLM backend (Ollama / NVIDIA NIM / OpenAI / Anthropic).

### Option A — Python package

```bash
# Clone
git clone https://github.com/m524security/HIVEBREACH.git
cd HIVEBREACH

# Install in development mode
pip install -e .

# Configure environment
cp .env.example .env   # then edit with your LLM keys
```

### Option B — Bootstrap scripts

```bash
# Linux / macOS
chmod +x install.sh
./install.sh

# Windows (PowerShell)
.\install.ps1
```

### LLM backends

| Backend | Use case | Cost |
|---|---|---|
| Ollama (local) | Fully offline / air-gapped | Free |
| NVIDIA NIM | Production-quality hosted, no GPU needed | Free tier |
| OpenAI / Anthropic | Frontier reasoning for hard/critical tasks | Paid |

Backends auto-fall back in order if the primary is unreachable or rate-limited.

---

## Usage

### Python API

```python
import asyncio
from orchestration.orchestrator import HiveOrchestrator

async def main():
    orchestrator = HiveOrchestrator(
        roe_path="governance/rules-of-engagement-template/roe-template.md",
        llm_config="orchestration/llm-router/config.yaml",
    )

    session = await orchestrator.run_engagement(
        targets=["api.acme.com", "app.acme.com"],
        sandbox_mode=True,
    )

    orchestrator.save_session("sessions/latest.pkl")
    findings = orchestrator.export_findings()
    print(f"Findings: {findings['summary']['total_findings']}")

asyncio.run(main())
```

### CLI

```bash
# Full engagement
python -m hivebreach scan --targets api.acme.com,app.acme.com --roe scope_rules.yaml

# Recon-only (CI-friendly)
python -m hivebreach scan --targets api.acme.com --mode recon --ci

# Deep scan (full kill chain)
python -m hivebreach scan --targets acme.com --mode deep

# Resume a persisted session
python -m hivebreach resume --session sessions/latest.pkl

# Validate a single PoC by correlation ID
python -m hivebreach validate --poc-id abc-123-def
```

### OpenCode integration

HiveBreach is wired into **OpenCode** as the primary harness:

- Orchestrator agent: `~/.config/opencode/agent/hacker.md`
- Skill router: `~/.config/opencode/skills/hivebreach/SKILL.md`
- The orchestrator loads the relevant playbook for the target, dispatches specialist subagents, and enforces R1–R10.

---

## Configuration

`.env` (copy from `.env.example`):

```bash
LLM_BACKEND=ollama
OLLAMA_HOST=http://localhost:11434
NVIDIA_NIM_API_KEY=nvapi-...
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...
SCOPE_FILE=governance/rules-of-engagement-template/roe-template.md
SANDBOX_ENABLED=true
MAX_CONCURRENT_AGENTS=5
AUDIT_LOG_DIR=sessions/
SECRETS_RETENTION_HOURS=24
ECC_HOOK_PROFILE=standard
```

**Hook profiles** (`ECC_HOOK_PROFILE`):

- `minimal` — scope-gate pre-scan only (CI environments)
- `standard` — adds session save/load persistence hooks
- `strict` — blocks on critical findings pending human approval

**Model routing** — `orchestration/llm-router/config.yaml`:
- Difficulty map (trivial → critical) selects model tier
- Per-agent overrides and fallback chains
- OpenAI + Anthropic enabled for frontier tasks (hard/critical)

---

## Governance

### CRITICAL-RULES (R1–R10)

Non-negotiable enforcement policy (`governance/CRITICAL-RULES.md`) that overrides all agent flexibility:

- **R1** — Authorization gate: never touch out-of-scope assets; stop-and-ask on ambiguity
- **R2** — Evidence-first: no deterministic PoC, no finding
- **R3** — No damage/destruction: no destructive SQL, DoS, or persistence on production
- **R4** — Proof, not theft: minimal data extraction, redacted reporting
- **R5** — Sandbox verification first
- **R6** — Leave no trace: full teardown after every engagement
- **R7** — Audit everything: HMAC-chained, immutable
- **R8** — No secrets in output or commits
- **R9** — Stay within approved tooling
- **R10** — Human-in-the-loop for high-impact actions

### Scope gate

- Deterministic Python code, **no LLM involvement**
- Parses ROE → builds an authorization trie (allow/deny per target + action)
- Intercepts every agent action; hard-deny with logged context on violation

### Compliance mapping

- **SOC2** (18 controls), **PCI-DSS** (15 requirements), **ISO 27001** (27 controls), **NIST 800-53** (40 controls)

---

## Tools

| Tool | Purpose | Usage |
|---|---|---|
| `tools/gap-report.py` | MITRE ATT&CK coverage tracking | `python3 tools/gap-report.py` / `--json` |
| `tools/self-learn.py` | Findings → lessons library | `python3 tools/self-learn.py --findings f.json --engagement ENG-001 --apply` |

---

## Testing

**326 tests** across 16 suites (pytest, no external test dependencies).

```bash
pytest tests/ -v
pytest tests/test_orchestrator.py -v
pytest tests/test_scope_gate.py -v
pytest tests/test_sandbox.py -v
pytest tests/ --cov=. -v
```

Coverage includes: orchestration, scope gate, sandbox manager, PoC validator, session manager, vault manager, audit logger, message bus, hooks, sanity checks, agent shield, commands, and pattern extraction.

---

## Extensibility

- **New agents** — copy `agents/agent-template/`, write the agent card, master prompt, and skill playbook, then register in the harness descriptor
- **New skills** — add a playbook under `skills/<category>/` following the standard 9-section structure
- **New hooks** — add a module in `hooks/` and register it in `hooks/registry.py`
- **New tools** — add an entry to `toolbelt/registry.json` with risk/sandbox/kill-chain metadata

---

## Roadmap

**Tier 2 (in progress)**
- Human-in-the-loop approval gate (Slack/email/webhook notifications)
- CI-mode vs deep-mode split
- Cost and rate-limit governor dashboard
- Compliance report overlay
- Fill remaining 289 MITRE ATT&CK coverage gaps (post-exploitation, evasion, DFIR)

**Tier 3 (planned)**
- Attack-path chain visualiser (BloodHound-style, generalised to web/cloud/network)
- Community plugin architecture
- Web-based management dashboard

---

## Legal

HiveBreach is designed **exclusively for authorised security testing** against systems you own or have written permission to test under a signed Rules of Engagement.

- The scope/authorisation gate is deterministic and **non-removable**.
- Using HiveBreach without authorization, or removing the scope gate, is outside intended and supported use.
- Reports carry a fixed disclaimer: *"This is a suggested remediation for developer review — it has not been applied or validated as a patch."*
- Credential findings reference existence and location but never embed live values (routed to the encrypted vault with automatic expiry).
- Responsible disclosure applies to all findings affecting third-party software or infrastructure.

Operators are responsible for compliance with all applicable laws (CFAA, Computer Misuse Act, NIS Directive, GDPR/CCPA/LGPD, etc.) and should consult legal counsel before cross-jurisdictional testing.

---

*HiveBreach is provided as a tool for professional security researchers, authorised penetration testers, and defensive security teams operating under a properly scoped Rules of Engagement.*
