# HiveBreach — Claude Workspace Configuration

## On Start
Load ECC agent harness skill: `skill ecc-agent-harness`
Follow Fable 5 patterns: high effort, lead with outcome, checkpoint discipline, ground claims in tool results.

## Agent Manifest
See `AGENTS.md` — 20 specialised agents across 5 stages (recon, exploitation, analysis, support, infrastructure). Each agent has an ECC-format YAML frontmatter card with role, stage, tools, verification method, and communication peers.

## File Path Conventions
- `hivebreach/` — Python package source
- `sessions/` — Audit logs and session data (gitignored)
- `vault/` — Encrypted key material (gitignored)
- `sandbox/` — Container image definitions
- `skills/` — MITRE/OWASP-mapped attack playbooks

## Commands
- `pip install -e .` — Install package in dev mode
- `python -m hivebreach` — Run framework
- `install.ps1` / `install.sh` — Bootstrap environment
- Activate venv before working: `.venv\Scripts\Activate.ps1` (Windows) or `source .venv/bin/activate` (Unix)

## ECC Integration
- Agents use ECC agent card YAML frontmatter format
- Skills follow ECC skill playbook format with MITRE/OWASP mappings
- Hooks/rules govern orchestration lifecycle
- `ECC_HOOK_PROFILE` in `.env` selects gate profile (minimal/standard/strict)
