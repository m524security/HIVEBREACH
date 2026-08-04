# Skill Playbook: [Agent Name] — DEEP AGGRESSIVE MODE

> **Purpose:** Authoritative deep-aggressive-mode operating procedures for [domain]. Every phase embeds the technique chains from `skills/<domain>/<playbook>.md` and the supporting skill library. [Specific domain operating principle: e.g., sandbox-only default, scope-gated execution, evidence-first validation].

## Phase 1 — Reconnaissance and Baseline

1. **Resolve Scope** — Extract the scope_token and target list from the task directive; verify every target against the ROE whitelist before any action.
2. **Enumerate Surface** — Run host discovery and port scanning per the applicable playbook:
   ```bash
   # example command for the agent's domain
   tool -T target -p <ports> -o /evidence/scan.json
   ```
3. **Fingerprint** — Identify technology stack and service versions; map to known CVEs and attack vectors.
4. **Baseline State** — Capture pre-engagement state (processes, files, configs) for post-teardown verification.
5. **Emit Recon Results** — Record findings to the knowledge graph with correlation_id, scope_token, and evidence paths.

## Phase 2 — Attack and Technique Expansion

1. **Map Vectors** — Map enumerated services to attack chains per the domain playbook; order by depth (shallow → deep).
2. **Execute Deepest Viable Chain** — Attempt the deepest attack path within scope; each step carries scope_token verification and is logged.
3. **Escalate on Confirmation** — On each confirmed step, attempt the next tier; never exceed the scope_token boundary.
4. **Chain Findings** — Combine low-severity findings into higher-impact chains (e.g., misconfig → cred → lateral) and record the chain.
5. **Rate-Limit Discipline** — Honor framework rate-limit ceilings; back off on WAF/IDS detection; log every throttle event.

## Phase 3 — Verification and Evidence

1. **Deterministic Proof** — Every finding carries raw tool output, response diff, callback, or state assertion as evidence.
2. **Independent Reproduction** — Hand confirmed findings to validator-agent for sandboxed PoC reproduction; retain pre/post snapshots.
3. **Confidence Tiers** — confirmed (deterministic proof), likely (strong but not decisive evidence), tentative (correlation only). Never inflate.
4. **False-Positive Logging** — Document disconfirming evidence for each rejected candidate; report to audit-agent.
5. **Evidence Packaging** — Package evidence with hashes and chain-of-custody metadata; deliver to audit-agent and report-agent.

## Phase 4 — Handoff and Teardown

1. **Handoff Results** — Deliver findings, evidence, and knowledge-graph records to downstream agents with correlation_id propagated.
2. **Notify Scheduler** — Emit phase-completion status with findings summary and resource metrics.
3. **Request Cleanup** — On engagement close, hand the artifact list to cleanup-teardown-agent for verified teardown.
4. **Verify Baseline** — Confirm post-teardown state matches the pre-engagement baseline.

## Quality Gates

- **Gate 1:** Every target verified against scope_token before any action; zero out-of-scope touches.
- **Gate 2:** Every finding carries deterministic evidence; no finding promoted without it.
- **Gate 3:** Every confirmed finding is independently reproduced by validator-agent before reporting.
- **Gate 4:** False positives are documented with disconfirming evidence, never silently dropped.
- **Gate 5:** Rate-limit ceilings and framework policies honored; every throttle/detection event logged.
- **Gate 6:** Post-teardown baseline verification confirms zero residual artifacts.

## References
- skills/<domain>/<playbook>.md
- skills/<domain>/<playbook>.md
- skills/penetration-testing/skill-playbook.md
- [Authority reference URLs relevant to the agent's domain]
