# Agent Communication Protocol — ECC Common Rule

## Scope

This rule defines the standard message format and routing protocol for all inter-agent communication within the HiveBreach framework.

## Message Format

All agent-to-agent messages MUST be structured JSON with the following fields:

### Required Fields

```json
{
  "from_agent": "string",
  "to_agent": "string",
  "correlation_id": "uuid-string",
  "timestamp": "ISO-8601-datetime",
  "action": "string",
  "payload": {},
  "scope_token": "hmac-string"
}
```

| Field | Description |
|-------|-------------|
| `from_agent` | Sender agent name (from AGENTS.md) |
| `to_agent` | Recipient agent name or `*` for broadcast |
| `correlation_id` | UUID v4 for end-to-end traceability |
| `timestamp` | ISO 8601 UTC timestamp |
| `action` | Action verb (request, response, notify, error) |
| `payload` | Action-specific data payload |
| `scope_token` | HMAC-SHA256 token for ROE compliance |

### Optional Fields

| Field | Description |
|-------|-------------|
| `ttl` | Time-to-live in seconds |
| `retry_count` | Current retry attempt number |
| `priority` | Message priority (low, normal, high, critical) |

## Routing

- Messages are routed through the scheduler-agent's message bus
- Broadcast messages (`to_agent: "*"`) are delivered to all registered agents
- Replies MUST reference the original `correlation_id`

## Retry Logic

| Attempt | Delay | Backoff |
|---------|-------|---------|
| 1 | 1s | — |
| 2 | 2s | linear |
| 3 | 4s | exponential |
| 4 | 8s | exponential |
| 5+ | 16s | cap at 16s |

Max 10 retries before the message is dead-lettered to the audit-agent.

## Delivery Guarantees

- At-least-once delivery for action type `request`
- At-most-once delivery for action type `notify`
- Exactly-once delivery is NOT guaranteed; handlers must be idempotent

## Verification

All messages are logged by the audit-agent. The `scope_token` is verified by the scope-agent before any action is taken.
