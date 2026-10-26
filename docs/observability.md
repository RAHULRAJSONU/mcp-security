# Observability

What the service emits, what it deliberately does not, and how to alert on it.
Alert rules are in [`ops/prometheus-alerts.yml`](../ops/prometheus-alerts.yml).

## The rule that shapes everything

Telemetry goes to shared systems, so it never carries patient data, free text or the
caller's justification. Metric labels are small fixed sets: no user, client, tenant or
patient ids. Identifiers appear only in the audit log lines and the `access_events`
table, which are access-controlled.

## Metrics (management port 8081, `/actuator/prometheus`)

| Metric | Labels | Meaning |
| --- | --- | --- |
| `clinical_patient_access_total` | `outcome`, `purpose`, `category` | Every access decision. `ALLOWED`, `DENIED`, `ERROR`. `purpose=EMERGENCY` is break-glass. |
| `mcp_tool_calls_total` | `tool`, `outcome` | Every tool call. `outcome` is `ok` or the error code the model received: `access_denied`, `unauthenticated`, `rate_limited`, `server_busy`, `request_failed`. |
| `mcp_tool_duration_seconds` | `tool`, `outcome` | Latency histogram per tool. |
| `mcp_agent_denied_total` | `reason` | Why an agent was refused: `no_client`, `unknown`, `not_approved`, `expired`. The caller never sees the reason; only operators do. |
| `mcp_agent_quota_rejected_total` | none | Calls refused by the per-identity quota. |
| `mcp_bulkhead_rejected_total` | none | Calls refused with `server_busy` because too many were already in flight. See [scaling](scaling.md). |
| `mcp_bulkhead_in_flight` | none | Calls running or waiting for a connection right now. Compare with `MAX_IN_FLIGHT_CALLS`. |
| `mcp_ratelimit_rejected_total` | `layer` | HTTP-level rate limit (`ip`, `token`). |
| `cache_gets_total` | `cache`, `result` | Caffeine hits and misses for `agent_registry`, `agent_quota`, `ratelimit_ip`, `ratelimit_token`. A low `agent_registry` hit rate means the 5 s cache time is not helping. |
| `cache_size`, `cache_evictions_total` | `cache` | How many identities each cache holds, and how many were pushed out. Evictions on `agent_quota` or `ratelimit_*` mean `max-tracked-keys` is too small, and a tracked identity's limit was forgotten. |
| Boot defaults | | JVM, `http_server_requests`, Hikari pool, `application_*`. |

## Logs

In prod, logs are ECS JSON on stdout (`logging.structured.format.console: ecs`).

| Logger | Content |
| --- | --- |
| `AUDIT.patient-access` | One line per access decision: outcome, subject, tenant, patient, **client**, **actor** (RFC 8693 `act` chain, `-` if none), purpose, category, break-glass, justification *length*. `WARN` for break-glass, `INFO` otherwise. |
| `AUDIT.agent-access` | `agent_denied reason=… tenant=… subject=… client=…` at `WARN`. |
| `…McpToolErrorConfig` | `mcp_tool_fingerprint name=… sha256=…` at startup. |
| `…SecuredPatientQueryService` | `request_failed category=…` with the full exception, server side only. |
| `…AccessAuditor` | `audit_write_failed …` when an event could not be stored. |

Route the two `AUDIT.*` loggers to tamper-evident storage separately from application logs.

Every line produced while handling a request carries `request_id` (from the MDC). The same
id is returned in the `X-Request-ID` response header. A caller-supplied `X-Request-ID` is
kept only if it is 8 to 64 characters of `[A-Za-z0-9._-]`; anything else is replaced, so it
cannot forge log lines. To investigate a report, ask for the `X-Request-ID` and search for it.

## Reading an incident

1. **A user says "it said access denied".** Every denial looks identical to the caller, by
   design. Take the `request_id`, then read `AUDIT.agent-access` (why the agent was refused)
   and `AUDIT.patient-access` (which check refused the read). The `access_events` row also
   names the client.
2. **Spike in `request_failed`.** Search the log for `request_failed` and `audit_write_failed`
   with that `request_id`. The exception is there; the model was only told "Request could not
   be completed".
3. **A tool changed.** Compare `mcp_tool_fingerprint` lines between releases. A new hash
   means the model is being told something different about that tool.

## Not covered yet

- No distributed tracing (no OpenTelemetry or Micrometer Tracing dependency). `request_id`
  correlates within this service only.
- No dashboard is shipped. Useful starting queries:
  - `sum by (tool, outcome) (rate(mcp_tool_calls_total[5m]))`
  - `histogram_quantile(0.95, sum by (tool, le) (rate(mcp_tool_duration_seconds_bucket[5m])))`
  - `sum by (reason) (increase(mcp_agent_denied_total[1h]))`
- Alert rules have not been run through `promtool check rules`.
