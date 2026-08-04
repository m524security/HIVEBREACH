---
skill: active-testing-chaining-deep-aggressive
mitre_attack_id: T1078
owasp_mapping: [A01, A03, A04, A06, A08]
difficulty: advanced
mode: deep-aggressive
tags: [vulnerability-chaining, request-smuggling, cache-poisoning, race-conditions, second-order-injection, privilege-escalation, lateral-movement, interception, replay]
---

# Deep Aggressive Mode Playbook: active-testing-agent

> Purpose: This playbook is the deep-aggressive operational doctrine for live interception, multi-step attack chains, and vulnerability chaining toward maximum business impact. Every chain is executed through the proxy, verified end-to-end three times, and delivered with full evidence. Reference the class playbooks under skills/penetration-testing/ for attack patterns per step.

## Phase 1 — Chain Graph Construction

1. Collect all confirmed findings from web-exploit-agent, server-side-agent, and client-side-agent with their preconditions: auth level, user interaction required, host/port, data exposure.
2. Build the chaining graph: an edge exists between finding A and finding B when A's output satisfies B's precondition.
3. Rank chains by impact-to-effort: unauthenticated admin access > RCE > account takeover > data exfiltration > privilege escalation > informational.
4. Select the highest-impact chains and request explicit authorization for any step outside RoE.

## Phase 2 — Classic High-Value Chains

1. SQLi -> credential dump -> admin login -> command injection -> shell:
   - Step 1: skills/penetration-testing/sql-injection.md — extract admin hash via UNION/time oracle
   - Step 2: crack or reuse hash, log in to admin panel
   - Step 3: skills/penetration-testing/command-injection.md — inject through an admin file-operation/import feature
   - Step 4: hand the shell to exploit-agent for session handling
2. XSS -> CSRF -> account takeover:
   - Step 1: skills/penetration-testing/xss.md — confirm stored XSS in attacker-controlled surface
   - Step 2: skills/penetration-testing/csrf.md — confirm state-changing endpoints lack CSRF protection
   - Step 3: chain payload: XSS auto-submits the CSRF request as the victim
   - Step 4: validate in a sandboxed browser session (client-side-agent)
3. SSRF -> cloud metadata -> cloud credential -> lateral movement:
   - Step 1: skills/penetration-testing/ssrf.md — confirm metadata access
   - Step 2: extract IAM/instance credentials
   - Step 3: use credentials against cloud APIs; hand to pivot-agent
4. Open redirect -> OAuth token theft -> account takeover:
   - Step 1: skills/penetration-testing/open-redirect.md — confirm redirect_uri path-open
   - Step 2: build the steal chain and validate with client-side-agent
5. Network foothold -> pass-the-hash -> domain admin:
   - Step 1: skills/network-security/protocol-exploitation.md — confirm SMB/NTLM exposure
   - Step 2: capture hash via responder or extract from compromised host
   - Step 3: pass-the-hash to spread; hand credentials to credential-agent

## Phase 3 — Request Smuggling

1. Detect CL.TE: send `Content-Length` larger than body, terminate with `0` chunk; observe subsequent-request poisoning with timing oracle.
2. Detect TE.CL: chunked body with an internal `Content-Length`; observe desync with a follow-up request.
3. Detect TE.TE: obfuscated Transfer-Encoding headers (`Transfer-Encoding : chunked`, `Transfer-Encoding: xchunked`).
4. Confirmation: poison the next legitimate request to a safe endpoint; observe the desynced prefix in a victim request. Safe probes only — no cache pollution of production caches.
5. Impact chains: bypass front-end WAF/auth for the smuggled request; redirect victim request to attacker-controlled content; CL.0 request tunneling.

## Phase 4 — Cache Poisoning and Deception

1. Identify cache behavior: `X-Cache`, `Age`, `CF-Cache-Status` headers on responses.
2. Test unkeyed headers: `X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Original-URL`, `X-Rewrite-URL`, arbitrary `Host`.
3. Poison a cached page with attacker content or a stored XSS payload in a cacheable asset.
4. Web cache deception: request `/profile/notfound.png` where the app serves the profile page and the cache stores it; steal authenticated pages via the cache key.
5. Validate impact in sandbox; only demonstrate with controlled payloads.

## Phase 5 — Race Conditions

1. Identify state-changing endpoints with server-side checks: coupon redemption, balance transfer, token validation, account creation.
2. Use Turbo Intruder with a parallel request group: `gate.race` across N synchronized connections.
3. Single-packet attack for extremely fast endpoints; HTTP/2 and request-pipelining variants for CL.TE-tolerant targets.
4. Token/nonce bypass: race identical requests where the server validates a one-time token — confirm which request wins.
5. Non-destructive payloads only; document timing precision and reproducibility.

## Phase 6 — Second-Order Injection

1. Find a sink that consumes attacker-controlled data stored earlier: admin dashboard rendering comments, log viewers rendering filenames, CSV export injecting formulas, notification templates echoing names.
2. Store the payload through the normal user surface (profile, filename, comment) then trigger through the consuming surface.
3. Examples: stored XSS in a username rendered in admin panel; SQL injection via stored order-note in a report query; CSV injection via exported user data; template injection via stored email template field.
4. Validate the second-order trigger executes in the sandboxed context.

## Phase 7 — Chain Execution and Validation

1. Execute every chain end-to-end three times through the intercepting proxy.
2. Test each individual link independently before combining (false-positive elimination).
3. Capture per-step evidence: request, response, application state before/after, error messages.
4. Verify application stability after each chain (health endpoint or known-good page).
5. Classify confidence: confirmed (executed 3/3), tentative (executed but flaky), unconfirmed.

## Phase 8 — Handoff

1. Send confirmed chains with evidence to verification-correlation-agent for independent replay.
2. Send pivot points and credentials to pivot-agent and credential-agent respectively.
3. Send chain-path narratives to report-agent for the executive report.
4. Log every request/response pair with chain_id to audit-agent.

## Verification

1. Every reported chain executed end-to-end three times; each link independently confirmed.
2. Critical/High chains have deterministic output proof (command output, stolen session, cloud credential).
3. All actions proxied; no direct target connections; conservative thread counts.
4. No destructive payloads, no real-user impact, no production data modification.
5. Scope violations halt immediately.

## Skill Library References
- skills/penetration-testing/sql-injection.md
- skills/penetration-testing/ssrf.md
- skills/penetration-testing/xss.md
- skills/penetration-testing/csrf.md
- skills/penetration-testing/command-injection.md
- skills/penetration-testing/file-inclusion.md
- skills/penetration-testing/ssti.md
- skills/penetration-testing/xxe.md
- skills/penetration-testing/insecure-deserialization.md
- skills/penetration-testing/nosql-injection.md
- skills/penetration-testing/open-redirect.md
- skills/penetration-testing/cors-misconfiguration.md
- skills/network-security/protocol-exploitation.md
