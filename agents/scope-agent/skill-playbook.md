# Skill Playbook: scope-agent — DEEP AGGRESSIVE MODE

> **Purpose:** Authoritative deep-aggressive-mode operating procedures for ROE enforcement, target validation, and boundary compliance. Every phase embeds the technique chains from `skills/network-security/*`, `skills/penetration-testing/*`, and `skills/threat-intel/skill-playbook.md` so that authorization decisions are grounded in the exact scanning, enumeration, and exploitation behaviors they gate. Enforcement-first default; no action is ever taken without explicit authorization.

## Phase 1 — ROE Ingestion and Normalization

1. **Collect ROE Document** — Request the ROE from config-agent or scheduler-agent. Accept plain text, PDF, DOCX, YAML, or JSON. Normalize every format to a canonical YAML document with a schema:
   ```yaml
   roe:
     id: ROE-2026-042
     authorized: {domains: [], cidrs: [], ips: [], asns: [], url_patterns: []}
     excluded: {domains: [], cidrs: [], ips: [], url_patterns: []}
     greyzone: {domains: [], cidrs: [], ips: []}
     rate_limits: {pkt_per_sec: 500, req_per_sec: 20, concurrent_connections: 10}
     time_windows: {days: [mon-fri], hours: "22:00-06:00 UTC", blackout_dates: []}
     prohibited: [dos, social-engineering, physical]
     jurisdictions: {origin_allowed: [US], techniques_blocked: []}
     data_handling: {pii_blocked: true, storage_allowed: ["hivebreach-vault"]}
     notifications: {before_test: [], critical_finding: [], after_test: []}
     third_party: [{provider: aws, authorized: true, approval_ref: "SP-2026-100"}]
   ```
2. **Parse Every Field** — Extract all ten ROE field groups (targets, exclusions, greyzone, rate limits, time windows, prohibited techniques, jurisdiction, data handling, notifications, third-party authorization). Treat the text extraction as suspect until cross-verified against the original clause text.
3. **Normalize Targets** — Convert domains to lowercase FQDN, expand URL patterns to host+path tuples, convert IP ranges like `192.0.2.1-192.0.2.254` to CIDR, and keep ASNs symbolic until ASN-to-CIDR resolution.
4. **Checksum the Policy** — Compute SHA-256 of the normalized policy document. Log the hash to audit-agent as the policy provenance baseline.
5. **Detect Conflicts** — Flag overlapping entries (a target in both whitelist and blacklist). Resolve by explicit exclusion precedence and document the decision with the ROE clause that justifies it.

## Phase 2 — Scope Policy Construction

1. **Build Whitelist** — Insert every authorized target into a prefix-trie of CIDR ranges. Normalize `example.com` to its resolved CIDR set.
2. **Build Blacklist** — Insert every excluded target into the same trie with an exclusion flag.
3. **Compute Effective Scope** — For each whitelisted range, subtract all blacklisted ranges contained within it using CIDR difference arithmetic:
   ```bash
   # cidr-calc difference example
   cidr-calc difference 192.0.2.0/24 192.0.2.128/25
   # -> 192.0.2.0/25
   cidr-calc difference 192.0.2.0/24 192.0.2.64/26
   # -> 192.0.2.0/26, 192.0.2.128/25
   ```
4. **Resolve ASNs** — Query RIPE/ARIN/APNIC data and the threat-intel feed (`skills/threat-intel/skill-playbook.md`) to expand each ASN to its announced CIDR prefixes. Add to whitelist; flag any ASN whose prefixes include excluded IPs.
5. **Expand Wildcard Domains** — For `*.app.example.com`, resolve the base domain plus a representative sample of known subdomains from CT-log data (crt.sh) and passive DNS. Add only verified in-scope IPs. Never add the entire authoritative zone blindly.
6. **Ownership Verification** — Run WHOIS and ASN lookups for every resolved IP range. Verify the registrant org matches the target org. Flag mismatches as ownership anomalies with evidence.
7. **Build Lookup Engine** — Compile the effective scope into the O(1) authorization structure. Load into `custom-scope-engine` for high-throughput querying.
8. **Generate Scope Statement** — Produce a human-readable summary: what is in scope, what is carved out, what is greyzone, special conditions. Send to report-agent for the engagement preamble.

## Phase 3 — Authorization Enforcement

1. **Serve Requests** — For every targeting request on the message bus, extract: `agent_id`, `target`, `action_type`, `context`. Require a valid `scope_token` on every message; reject malformed requests.
2. **Normalize the Target** — Resolve domains to IPs (dual-resolve for stability), expand ranges to CIDR, canonicalize URL patterns. Normalization failure means deny-by-default.
3. **Evaluate** — Check target against the trie:
   - In whitelist, not in blacklist: authorize.
   - In blacklist: deny with "excluded target".
   - Not in whitelist: deny with "out of scope".
   - In greyzone: escalate.
4. **Return Structured Decision** — Authorized: `{authorized: true, authorization_id, valid_until, conditions}`. Denied: `{authorized: false, reason, roe_reference, suggested_corrective_action}`.
5. **Apply Conditions** — Attach ROE conditions to every grant: rate ceiling for the agent's action class, time window validity, technique whitelist. The grant is only valid while all conditions hold.
6. **Enforce Rate Limits** — Maintain per-action-class counters. Decrement on each grant; when a ceiling is reached, deny until the window resets. Critical escalations bypass non-critical counters only.
7. **Enforce Time Windows** — If the current time is outside the authorized window, hold or deny non-critical requests. Deliver a clear message with the window reopening time.
8. **Gate Prohibited Techniques** — If the requested action maps to a prohibited technique (e.g., `dos`), deny with the exact ROE clause. Never soft-pass a prohibited action even in deep aggressive mode.

## Phase 4 — DNS Revalidation and Drift Response

1. **Schedule Revalidation** — Re-resolve every authorized domain every 10 minutes (or per ROE). Compare against the previous mapping.
2. **Detect Drift** — If a domain's resolved IP moves into a blacklisted range or outside effective scope, flag it as a scope-drift incident.
3. **Issue Scope-Block** — Immediately notify affected agents that the domain is scope-blocked pending re-authorization. Log the drift to audit-agent.
4. **Re-Authorize** — If the new IP is in effective scope, issue a fresh authorization with the new IP and log the update.
5. **Escalate Persistent Drift** — If a domain bounces between IPs, escalate to scheduler-agent for a manual decision rather than burning authorization churn.

## Phase 5 — Blast Radius Limiting

1. **Cap Per-Target Passes** — Track the number of authorized scan passes per host. After N passes, require manual re-authorization.
2. **Enforce Concurrency Ceilings** — For masscan, ffuf, and hydra requests, verify the concurrent-connection ceiling from the ROE is respected before granting.
3. **Protect Fragile Services** — Query `skills/network-security/service-enumeration.md` for known-fragile service markers (legacy stacks, embedded devices). Enforce the conservative probe-rate tier for those targets.
4. **Limit Exfiltration** — Authorize only the minimum OOB/exfiltration footprint needed to prove impact per `skills/penetration-testing/sql-injection.md` and `skills/penetration-testing/ssrf.md`. Deny full-dump authorizations unless the ROE explicitly permits.
5. **Bound the Exploitation Surface** — When exploiting agents chain targets (e.g., pivot paths from `skills/network-security/protocol-exploitation.md`), validate every hop in the chain against scope before granting the chain token.

## Phase 6 — Verification and Boundary Testing

1. **Positive/Negative Suite** — After every policy build, run a test suite of known in-scope and out-of-scope targets. Assert correct allow/deny.
2. **CIDR Edge Cases** — Test adjacent subnets, overlapping ranges, supernet/subnet containment, and IPv4-mapped IPv6 forms:
   ```bash
   cidr-calc contains 192.0.2.0/24 192.0.2.200
   cidr-calc contains 192.0.2.0/24 192.0.3.1
   cidr-calc overlap 10.0.0.0/8 10.1.2.0/24
   ```
3. **Wildcard Leak Test** — Resolve `*.app.example.com` against a large subdomain wordlist; assert every discovered IP is either in effective scope or denied.
4. **Rate Limit Test** — Submit rapid requests; assert denial after the ceiling is reached and re-authorization after reset.
5. **Integrity Check** — Recompute the policy checksum after every update; compare against the logged baseline.
6. **Deny-by-Default Test** — Inject targets with unresolvable DNS and unverifiable ownership; assert all return deny.

## Phase 7 — Audit and Reporting

1. **Log Every Decision** — Emit to audit-agent: `request_id`, `agent_id`, `target`, `action_type`, `decision`, `reason`, `roe_reference`, `timestamp`, `authorization_id`, `valid_until`, `conditions`.
2. **Greyzone Escalations** — Forward greyzone targets to scheduler-agent with ownership evidence and a recommendation.
3. **Policy Change Broadcast** — On ROE updates, broadcast the change to all agents and invalidate outstanding authorizations.
4. **Compliance Summary** — Produce a scope-compliance summary for report-agent: total authorizations, denials by reason, drift incidents, greyzone outcomes, rate-limit encounters.
5. **Provenance Record** — Keep the normalized ROE, policy checksums, and ownership evidence for the engagement archive.

## Quality Gates

- **Gate 1:** No targeting request is granted without a normalized, trie-validated target and a valid scope_token.
- **Gate 2:** Every denial carries an ROE clause reference; every grant carries conditions and a validity window.
- **Gate 3:** Boundary edge cases (adjacent subnets, wildcard expansion, exclusion carving) pass the verification suite before the policy is accepted.
- **Gate 4:** Rate ceilings, time windows, and prohibited-technique gates are enforced on every request, never soft-passed.
- **Gate 5:** Every decision, drift event, and policy change is written to audit-agent with full chain-of-custody metadata.

## References
- skills/network-security/host-discovery.md
- skills/network-security/port-scanning.md
- skills/network-security/service-enumeration.md
- skills/network-security/protocol-exploitation.md
- skills/penetration-testing/sql-injection.md
- skills/penetration-testing/ssrf.md
- skills/threat-intel/skill-playbook.md
- PTES Pre-engagement: http://www.pentest-standard.org/index.php/Pre-engagement
- OWASP WSTG: https://owasp.org/www-project-web-security-testing-guide/
