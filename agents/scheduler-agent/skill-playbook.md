# Skill Playbook: scheduler-agent — DEEP AGGRESSIVE MODE

> **Purpose:** Authoritative deep-aggressive-mode operating procedures for pipeline orchestration, dependency resolution, and parallel execution. Every wave embeds skill-library phase relationships from `skills/network-security/*`, `skills/penetration-testing/*`, `skills/dfir/skill-playbook.md`, and `skills/threat-intel/skill-playbook.md`. DAG-validated by construction; no agent runs before its dependencies resolve.

## Phase 1 — Pipeline Definition and DAG Validation

1. **Load Dependency Graph** — Pull the pipeline YAML from config-agent. Nodes are agents, edges are data dependencies:
   ```yaml
   pipeline:
     agents:
       recon-agent: {dependencies: [], timeout: 3600, critical: true}
       dns-agent: {dependencies: [recon-agent], timeout: 1800, critical: false}
       web-discover-agent: {dependencies: [dns-agent, recon-agent], timeout: 2400, critical: true}
       vuln-scan-agent: {dependencies: [web-discover-agent], timeout: 3600, critical: false}
       web-exploit-agent: {dependencies: [vuln-scan-agent], timeout: 7200, critical: true}
       exploit-agent: {dependencies: [vuln-scan-agent, web-discover-agent], timeout: 7200, critical: true}
       validator-agent: {dependencies: [exploit-agent, web-exploit-agent], timeout: 3600, critical: false}
       cleanup-teardown-agent: {dependencies: [], timeout: 1800, critical: true}
   ```
2. **Validate DAG** — Reject any graph with cycles. Use Kahn's algorithm:
   ```python
   from networkx import DiGraph, is_directed_acyclic_graph, topological_sort
   g = DiGraph()
   g.add_nodes_from(agents); g.add_edges_from(edges)
   assert is_directed_acyclic_graph(g), "cycle detected"
   order = list(topological_sort(g))
   ```
3. **Verify Roster** — Every referenced agent must exist in the agent roster with a registered inbox queue on comm-agent.
4. **Partition into Layers** — Layer 0 = zero-dependency agents; layer N = agents whose dependencies all resolve in layers 0..N-1.
5. **Check Criticality** — Mark critical agents; a critical failure halts the pipeline.
6. **Log Validation** — Emit the validated DAG, layer partition, and topo order to audit-agent before any execution.

## Phase 2 — Recon and Discovery Wave Scheduling

1. **Schedule Recon Lanes** — Run host-discovery, port-scanning, and service-enumeration lanes in parallel per `skills/network-security/host-discovery.md`, `skills/network-security/port-scanning.md`, and `skills/network-security/service-enumeration.md`. These are layer 0/1 tasks.
2. **Fan Out DNS and Web Discovery** — dns-agent and web-discover-agent depend on recon-agent's live-host list. Schedule after recon lane completion.
3. **Scope Gate** — Before the first targeting message of any wave, confirm scope-agent has published an authorization policy. No wave starts without it.
4. **Rate Ceiling Propagation** — Propagate ROE rate ceilings (pkts/sec, req/sec, concurrency) into each scheduled agent's task context so scan lanes self-throttle.
5. **Parallel Batch Invocation** — Spawn all agents in a layer concurrently:
   ```python
   import asyncio
   async def run_layer(layer):
       await asyncio.gather(*(spawn_agent(a) for a in layer))
   ```

## Phase 3 — Validation and Exploitation Wave Scheduling

1. **Validation Gate** — vuln-scan and api-testing lanes must complete and their findings pass confirmation before exploitation lanes are scheduled (per `skills/penetration-testing/*` confirmation gates).
2. **Exploitation Waves** — Schedule network-protocol exploitation per `skills/network-security/protocol-exploitation.md` and web exploitation per `skills/penetration-testing/sql-injection.md`, `skills/penetration-testing/ssrf.md`, `skills/penetration-testing/xss.md`, `skills/penetration-testing/xxe.md`, `skills/penetration-testing/ssti.md`. Each exploit task carries the confirmed-finding IDs it is permitted to target.
3. **Sandbox Verification Tasks** — Pair every Critical/High exploitation task with a sandbox verification task on validator-agent. Verification is scheduled to run against sandbox snapshots, not production.
4. **Credential Pipeline** — When exploitation yields credentials, schedule creed-creds/vault tasks to store them securely before any further exploitation depends on them.
5. **Chain Awareness** — If the skill library defines an attack chain (e.g., SSRF-to-cloud-credential, SQLi-to-file-write), schedule the chained agents in dependency order and pass the intermediate artifacts between them.

## Phase 4 — Retry, Backoff, and Timeout Management

1. **Apply Retry Policy** — On task failure, apply the configured policy:
   ```python
   import random, time
   def backoff(attempt, strategy, initial, jitter=0):
       delays = {"fixed": initial,
                 "linear": initial * (attempt + 1),
                 "exponential": initial * (2 ** attempt)}
       d = delays[strategy]
       return d + random.uniform(0, jitter)
   ```
2. **Cap Retries** — After max_retries exhausted, mark the agent `failed_unrecoverable`.
3. **Timeout Enforcement** — Start a timeout timer per task. On expiry, send a kill signal via comm-agent, mark `timed_out`, and evaluate downstream impact.
4. **Jitter Injection** — Add uniform jitter to backoff delays to prevent synchronized retry storms when multiple agents fail simultaneously.
5. **Transient vs Permanent** — Classify failures: transient (network blip, queue backlog, provider 5xx) → retry; permanent (bad config, missing dependency, out-of-scope target) → fail fast without retry.

## Phase 5 — Deadlock Prevention and Task State Management

1. **Acyclic Routing** — Every task message routes by `to_agent`; self-routing is rejected. Verify comm-agent's routing table is acyclic before the pipeline starts.
2. **No Shared Mutable State** — Each task owns its inputs/outputs. Cross-agent data flows only via comm-agent messages with correlation IDs.
3. **Watchdog** — Monitor layer progress. If a layer stalls beyond the grace period with no agent heartbeat, kill stalled agents and retry per policy.
4. **State Transitions** — Track per-agent state: `pending → scheduled → running → retrying → succeeded | failed | timed_out | skipped`. Every transition is logged to audit-agent.
5. **Criticality Escalation** — If a critical agent fails unrecoverably, transition the pipeline to FAILED, halt scheduling, and emit an operator alert.

## Phase 6 — Analysis, DFIR, and Intel Waves

1. **Parallel Analysis Lanes** — After exploitation, schedule DFIR reconstruction (`skills/dfir/skill-playbook.md`) and threat-intel enrichment (`skills/threat-intel/skill-playbook.md`) in parallel. These are non-critical, so their failure degrades rather than halts.
2. **Evidence Correlation** — Schedule report-agent after analysis lanes so findings can be correlated with audit-agent's chain and evidence hashes.
3. **Intel-Driven Prioritization** — Feed threat-intel IOC and CVE context (`skills/threat-intel/skill-playbook.md`) into the vuln-scan lane so high-relevance findings are scheduled before general scanning completes.

## Phase 7 — Cleanup and Closure Wave

1. **Unconditional Cleanup** — Schedule cleanup-teardown-agent as the final wave regardless of pipeline outcome. It runs after success, failure, or abort.
2. **Certification Gate** — Do not close the pipeline until cleanup-teardown-agent certifies environments clean and state matches pre-scan baselines.
3. **Final Report** — On certification, send the pipeline execution report to report-agent and the finalized state to audit-agent.
4. **Resource Release** — Release Celery/Redis task resources, close worker pools, and log the closure to audit-agent.

## Quality Gates

- **Gate 1:** DAG validated (acyclic, roster complete, dependencies resolvable) before any agent starts.
- **Gate 2:** No wave begins before scope-agent publishes authorization and the previous wave's critical outputs verify.
- **Gate 3:** Every retry respects the configured policy with jitter; every timeout terminates within the grace period.
- **Gate 4:** Message routing is acyclic; no deadlock can form by construction.
- **Gate 5:** Cleanup-teardown runs unconditionally and pipeline closes only after environment certification.

## References
- skills/network-security/host-discovery.md
- skills/network-security/port-scanning.md
- skills/network-security/service-enumeration.md
- skills/network-security/protocol-exploitation.md
- skills/penetration-testing/sql-injection.md
- skills/penetration-testing/ssrf.md
- skills/penetration-testing/xss.md
- skills/penetration-testing/xxe.md
- skills/penetration-testing/ssti.md
- skills/dfir/skill-playbook.md
- skills/threat-intel/skill-playbook.md
- Kahn's Algorithm for Topological Sorting
- Celery Task Queue: https://docs.celeryq.dev/
- AWS Step Functions state machine patterns
