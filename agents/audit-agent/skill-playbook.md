# Skill Playbook: audit-agent — DEEP AGGRESSIVE MODE

> **Purpose:** Authoritative deep-aggressive-mode operating procedures for full telemetry capture, chain-of-custody logging, and immutable audit trails. Every phase embeds the DFIR evidence lifecycle from `skills/dfir/skill-playbook.md` and the triage discipline from `skills/dfir/incident-triage.md`. Passive-immutability default: no entry is ever modified, corrected entries are appended, and the chain is the single source of forensic truth.

## Phase 1 — Chain Initialization and Key Management

1. **Generate Chain Key** — Produce a 256-bit random signing key:
   ```bash
   openssl rand -hex 32 > /hivebreach/audit/chain.key
   chmod 400 /hivebreach/audit/chain.key
   ```
2. **Key Security** — Store read-only for the audit process only. Never share with report-agent, validator-agent, or any other consumer. Version-tag the key file for rotation readiness.
3. **Create Genesis Block** — Initialize the chain:
   ```json
   {
     "index": 0,
     "timestamp": "2026-07-08T10:00:00.000000Z",
     "event_type": "chain_init",
     "agent_id": "audit-agent",
     "action": "audit_chain_initialize",
     "target": "hivebreach-framework",
     "result": "success",
     "payload_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
     "prev_hmac": "0000000000000000000000000000000000000000000000000000000000000000",
     "hmac": "<computed>"
   }
   ```
4. **Verify Genesis** — Recompute the genesis HMAC independently before accepting the chain.
5. **Register Baseline** — Log the chain key fingerprint (SHA-256 of the key, not the key itself) and genesis index to scheduler-agent.

## Phase 2 — Event Ingestion and Normalization

1. **Subscribe to All Channels** — Listen on every agent channel plus the broadcast channel. Full telemetry means no agent is excluded.
2. **Validate Schema** — Check each event against the audit schema: `event_type`, `agent_id`, `action`, `target`, `result`, `payload`, `correlation_id`, `timestamp`, `scope_token`.
3. **Flag Malformed Events** — Record malformed events with `event_type: malformed` rather than dropping them. Preserve raw bytes for reconstruction.
4. **Compute Payload Hash** — `sha256sum` the exact payload bytes received; store the digest, not the raw payload interpretation.
5. **Normalize Timestamp** — Stamp with UTC microseconds from the audit process's own clock. Never trust agent-supplied timestamps for ordering; use them as metadata only.
6. **Add Custody Metadata** — Attach the full chain-of-custody tuple to every entry: `actor`, `timestamp`, `target`, `action`, `payload_hash`, `correlation_id`, `scope_token`.
7. **Acknowledge Receipt** — Send ack to the emitting agent so the framework knows the event is durably recorded.

## Phase 3 — HMAC Chain Construction

1. **Compute Entry HMAC** — Build the canonical entry JSON (index through payload_hash), then:
   ```bash
   echo -n "$ENTRY_JSON" | openssl dgst -sha256 -mac HMAC -macopt hexkey:$(cat chain.key)
   ```
2. **Link prev_hmac** — The new entry's `prev_hmac` equals the previous entry's computed HMAC. This creates the cryptographic linkage.
3. **Append Atomically** — Write the entry to the append-only log with `O_APPEND`. Never rewrite earlier segments.
4. **Maintain Monotonic Index** — Increment the index with every append. Any gap or duplicate index is a tamper indicator.
5. **Batch Heartbeats** — Every 100 entries, emit an integrity heartbeat: `{index, chain_verified, last_entry_timestamp}` to scheduler-agent.

## Phase 4 — Full Chain Integrity Verification

1. **Walk Genesis to Head** — Recompute every entry's HMAC with the chain key and verify the stored HMAC matches.
2. **Verify Linkage** — Confirm each entry's `prev_hmac` equals the previous entry's computed HMAC.
3. **Locate Divergence** — If any check fails, find the first index where recomputed != stored or linkage breaks. This is the tamper point.
4. **Record Violation** — Append an `integrity_violation` entry with the divergence index, expected HMAC, and observed HMAC.
5. **Halt Ingestion** — Stop accepting new events. Notify scheduler-agent immediately. The violation entry becomes the final valid entry.
6. **Independent Cross-Check** — Spot-verify sampled entries with `openssl dgst` against the stored HMACs to confirm the verification path itself is sound.
7. **Random Spot-Check** — Select a random index and recompute its HMAC independently. Log the result.

## Phase 5 — Filtered Views and Query Serving

1. **By Agent** — Extract all entries from a specific `agent_id`.
2. **By Action** — Extract entries matching action categories (scan, exploit, config, secret, cleanup).
3. **By Time Range** — Extract entries within a UTC window.
4. **By Target** — Extract entries referencing a canonical target identifier.
5. **By Correlation ID** — Extract the full multi-agent workflow for a correlation ID — the backbone of incident reconstruction.
6. **By Result** — Extract success, failure, blocked, or partial events.
7. **Attach Chain Metadata** — Every view ships with `start_index`, `end_index`, `total_entries`, `chain_verified`.

## Phase 6 — DFIR Evidence Integration

1. **Evidence Hashing** — When audit-agent archives evidence artifacts (screenshots, tool output, pcap excerpts), compute and store SHA-256 hashes per `skills/dfir/skill-playbook.md` section 2.1.
2. **Custody Handoffs** — Record every custody transfer of an evidence artifact: who acquired it, when, from where, to where, with hashes at each step.
3. **Volatility Ordering** — If memory or volatile artifacts are captured, log the capture order so downstream DFIR review can respect volatility semantics.
4. **Correlation with Findings** — Link each audit entry to the finding ID it generated, so report-agent can trace any finding back to its originating events.
5. **Timeline Reconstruction** — On request, produce a chronological event timeline from the chain, clustered by correlation_id and target, mirroring DFIR timeline-analysis methodology.

## Phase 7 — Engagement Closure and Finalization

1. **Finalize Chain** — Compute the final chain HMAC over the complete sequence.
2. **Sign Closeout** — Sign the finalized chain with the engagement closeout key.
3. **Export Complete Trail** — Export the full audit trail to report-agent and the evidence archive with the signature block.
4. **Independent Verification Handoff** — Deliver the export to validator-agent for independent chain verification.
5. **Retention** — Archive per the retention policy (PCI DSS 10.x, NIST SP 800-92). Never truncate or rotate during the active engagement.
6. **Cleanup of Live Key** — After closeout, zeroize the chain key in memory and schedule secure deletion of the key file per retention policy.

## Quality Gates

- **Gate 1:** Every entry carries the full custody tuple: actor, timestamp, target, action, payload hash, correlation ID.
- **Gate 2:** Every entry links prev_hmac to the prior entry; the chain is append-only with monotonic indices.
- **Gate 3:** Full chain verification passes from genesis to head before any filtered view or heartbeat claims chain_verified: true.
- **Gate 4:** Integrity violations halt ingestion and are themselves recorded as the final valid entry.
- **Gate 5:** Evidence artifacts are hashed at acquisition and their custody handoffs are logged per DFIR doctrine.

## References
- skills/dfir/skill-playbook.md
- skills/dfir/incident-triage.md
- NIST SP 800-92 Guide to Computer Security Log Management
- RFC 2104 HMAC: https://datatracker.ietf.org/doc/html/rfc2104
- PCI DSS v4.0 Requirement 10: Logging and Monitoring
- NIST SP 800-38D (GCM) context for AEAD custody hashing
