# Skill Playbook: comm-agent — DEEP AGGRESSIVE MODE

> **Purpose:** Authoritative deep-aggressive-mode operating procedures for inter-agent messaging: inbox routing, schema validation, ack/nack, exponential-backoff retry, dead-letter quarantine, correlation-ID lineage, and LLM service abstraction. No message is dropped; no failure is silent. Skill-path guidance routes message payloads to the correct target-agent playbooks.

## Phase 1 — Message Intake and Schema Validation

1. **Validate Schema** — Every inbound message must match its per-type schema: message_id, correlation_id, from_agent, to_agent, message_type, priority, payload, ttl. Reject with reason if malformed.
2. **Assign Correlation** — New operations get a fresh correlation_id (UUID); child messages inherit the parent's.
3. **Resolve Target** — `to_agent` → `agent:<to_agent>:inbox`. Unknown/disabled target → dead-letter with routing reason.
4. **Enforce Priority** — high-priority messages consume before normal in the same inbox.
5. **Reject Secret-Bearing LLM Payloads** — Any llm_request carrying secret references is refused and reported to audit-agent.

## Phase 2 — Reliable Delivery and Acknowledgment

1. **Push to Inbox**:
   ```bash
   python3 -m messaging.route --from exploit-agent --to validator-agent \
     --type task --corr corr-<id> --payload task.json
   ```
2. **At-Least-Once Semantics** — Pop the message only after the consumer acks.
3. **Ack Window** — Await ack; on timeout begin the retry ladder.
4. **Retry with Backoff** — Exponential: 1s, 2s, 4s, 8s (5 attempts normal, 8 high):
   ```bash
   python3 -m messaging.retry --message msg-<id> --policy exponential --base 1 --mult 2
   ```
5. **Nack Handling** — Consumer-reported processing failure (e.g. payload schema error) → dead-letter with the failure reason.
6. **Dead-Letter Quarantine** — Exhausted retries → move to dead-letter queue with full metadata: attempt timestamps, failure reasons, original payload. Never dropped silently.

## Phase 3 — Correlation Lineage

1. **Propagate Correlation** — Every downstream message (result, evidence, notify, LLM round-trip) born from a task carries the task's correlation_id.
2. **Lineage Reconstruction** — Support audit queries by correlation_id to rebuild the full operation graph:
   ```bash
   python3 -m messaging.lineage --corr corr-<id>
   ```
3. **LLM Correlation** — llm_request and llm_response pairs share the correlation_id for replay and prompt-hygiene review.
4. **Report Lineage** — On audit-agent request, emit the complete lineage: originating task, all child messages, timestamps, outcomes.

## Phase 4 — LLM Service Abstraction

1. **Template Prompt** — Render the structured prompt from the llm_request against the configured model endpoint:
   ```bash
   python3 -m llm.template --request llm_request.json --model gpt-4o \
     --temperature 0.2 --max_tokens 4096
   ```
2. **Authenticate** — Attach model auth from the secure channel; never embed secrets in prompts.
3. **Send and Correlate** — Dispatch to the LLM service; capture the response and bind it to correlation_id.
4. **Route Response** — Deliver llm_response back to the requesting agent's inbox.
5. **Report Usage** — Tokens, model, latency → scheduler-agent for quota management.
6. **Refuse Secrets** — Secret-bearing prompts rejected and reported to audit-agent.

## Phase 5 — Health, Failure Escalation, Teardown

1. **Queue Health** — Monitor depth, lag, and dead-letter count per inbox; report to scheduler-agent on a schedule or on threshold breach.
2. **Broker Failure** — Inboxes unreachable → bounded in-memory buffer (with TTL), retry persistence; escalate to scheduler-agent after 60s downtime.
3. **LLM Outage** — Endpoints down → fail llm_request messages with a clear error, schedule retry, report outage to scheduler-agent.
4. **Policy Updates** — config-agent retry/dead-letter policy changes apply immediately to new messages.
5. **Engagement Close** — On cleanup-teardown-agent directive: drain inboxes, flush dead-letter records to audit-agent, shut down routing cleanly.

## Quality Gates

- **Gate 1:** Zero silent drops — every failure path logs, retries, dead-letters, or escalates.
- **Gate 2:** Every message passes per-type schema validation before routing.
- **Gate 3:** Every delivered message is acknowledged or retried with exponential backoff; exhausted retries dead-letter with full metadata.
- **Gate 4:** Every operation lineage is reconstructible from a single correlation_id.
- **Gate 5:** Zero secret-bearing payloads reach the LLM service.
- **Gate 6:** Delivery telemetry (attempts, latency, outcome) reaches audit-agent for every message.

## References
- skills/penetration-testing/skill-playbook.md, skills/network-security/host-discovery.md, skills/network-security/port-scanning.md, skills/network-security/service-enumeration.md, skills/network-security/protocol-exploitation.md, skills/dfir/skill-playbook.md, skills/threat-intel/skill-playbook.md, skills/malware-analysis/dynamic-analysis.md (target-agent payload handling)
- RabbitMQ Reliability Docs: https://www.rabbitmq.com/docs/reliability
- Redis Streams: https://redis.io/docs/data-types/streams/
- WebSocket Protocol RFC 6455
