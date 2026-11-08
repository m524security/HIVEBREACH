# Skill Playbook: config-agent — DEEP AGGRESSIVE MODE

> **Purpose:** Authoritative deep-aggressive-mode operating procedures for configuration assembly, schema validation, secret injection, versioning, and hot-reload distribution across the framework. Every phase embeds the skill-path and tool-path references of the target agents (network-security, penetration-testing, dfir, threat-intel, malware-analysis). Configs that fail schema validation are quarantined, never released.

## Phase 1 — Template Registry and Schema Contracts

1. **Maintain Templates** — One Jinja2 template per agent with placeholders for env vars and vault secret references.
2. **Version Everything** — Track template_id, template_version, schema_version, last_modified. Updates are atomic.
3. **Define Schema** — JSON Schema per agent contract: required fields (agent_id, harness, scope, skill_paths, tool_paths, timeouts, rate_limits), type constraints, enums (mode: reconnaissance|active|aggressive|deep-aggressive; status: enabled|paused|disabled).
4. **Validate Schema Contract** — Every skill_path must resolve to an existing skill playbook under `skills/`; every tool_path must resolve to an installed tool. Deprecated references block the template update.

## Phase 2 — Config Assembly

1. **Receive Request** — agent_id + desired version (explicit or "latest").
2. **Load Template and Schema** — Fetch current template and its contract.
3. **Resolve Env** — Replace env placeholders from the env mapping with defaults applied.
4. **Resolve Secrets** — Request vault-backed secrets from vault-agent over the secure channel; inject into placeholders.
   ```bash
   vault get sec-<id> --consumer config-agent
   ```
5. **Render**:
   ```bash
   jinja2 templates/exploit-agent.j2 -D scope=192.0.2.0/24 -D mode=deep-aggressive > /tmp/config.json
   ```
6. **Prepare Canonical Form** — Serialize to canonical JSON for stable hashing.

## Phase 3 — Validation, Hashing, Versioning

1. **Schema Validate** — Fail fast:
   ```bash
   python3 -c "
   import json, jsonschema
   schema = json.load(open('schemas/exploit-agent.schema.json'))
   config = json.load(open('/tmp/config.json'))
   jsonschema.validate(config, schema)
   "
   ```
2. **Pydantic Coerce** — Enforce runtime types and constraints (max timeout, rate-limit ceiling).
3. **Compute Hash** — `sha256sum /tmp/config.json` → config_hash.
4. **Assign Version** — version = previous + 1 for the same agent.
5. **Quarantine Violations** — Rejected configs are stored with a structured report: config_id, path, expected, actual. Never released.

## Phase 4 — Distribution and Receipts

1. **Push to Inbox** — Deliver the validated config to the target agent's inbox queue:
   ```bash
   messaging send --to agent:<agent_id>:inbox --type config --payload /tmp/config.json
   ```
2. **Request Ack** — Target agent must acknowledge config_id/version.
3. **Retry on Miss** — Unacknowledged → retry with exponential backoff (1s, 2s, 4s; max 3 retries) → escalate to scheduler-agent.
4. **Receipt Logging** — Record distribution receipts; report acknowledged config_id/version to audit-agent.
5. **Divergence Check** — If an agent's acknowledged version lags the latest release, re-push and notify audit-agent.

## Phase 5 — Hot-Reload

1. **Watch Triggers** — scope changes, rate-limit updates, skill-path additions, mode transitions from scheduler-agent.
2. **Assemble New Version** — Re-run the assembly pipeline with the updated parameters.
3. **Diff Summary** — Compute added/removed/changed fields; secret fields render as `[REDACTED]`.
4. **Distribute** — Push new config_id/version to the inbox with the diff summary attached.
5. **Confirm Ack** — Await acknowledgment; on failure apply the backoff/escalation path.
6. **Align Framework** — On engagement-wide mode changes, hot-reload all affected agents so the whole framework moves together.

## Quality Gates

- **Gate 1:** Zero config releases without schema validation, version, and hash.
- **Gate 2:** Zero plaintext secrets in rendered configs, diffs, logs, or audit events; secret fields render as `[REDACTED]`.
- **Gate 3:** Every skill_path and tool_path resolves to an existing skill playbook / installed tool.
- **Gate 4:** Every distribution is acknowledged; persistent failures escalate to scheduler-agent with backoff.
- **Gate 5:** Every hot-reload carries a diff summary and is acknowledged by the target.
- **Gate 6:** Schema violations are quarantined with a path-exact report, never partially released.

## References
- skills/penetration-testing/skill-playbook.md (scope and mode guidance for pentest agents)
- skills/network-security/host-discovery.md, skills/network-security/port-scanning.md, skills/network-security/service-enumeration.md, skills/network-security/protocol-exploitation.md (tool-path validation)
- skills/dfir/skill-playbook.md, skills/threat-intel/skill-playbook.md, skills/malware-analysis/dynamic-analysis.md (agent skill-path resolution)
- Jinja2 Templates: https://jinja.palletsprojects.com/
- JSON Schema: https://json-schema.org/
- Pydantic: https://docs.pydantic.dev/
