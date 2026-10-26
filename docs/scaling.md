# Concurrency and scaling

What limits throughput, what was done about it, and what still has to be solved before
running several replicas.

## What a call costs

One tool call is one database transaction on one pooled connection: the agent check (cached),
the policy and the read, and the ALLOWED audit row, committed together. The database pool
(`DB_POOL_SIZE`, default 10) is the real capacity limit. Threads are not.

## What was done

| Change | Effect |
| --- | --- |
| Virtual threads (`spring.threads.virtual.enabled`) | A request waiting on the database costs a few KB, not a platform thread. Accepting thousands of concurrent requests is cheap. |
| Stateless MCP (`MCP_PROTOCOL=STATELESS`, the default) | No session to pin a client to one instance. Any replica answers any call, so no sticky sessions. Switch to `STREAMABLE` only if a tool needs server-to-client messages (sampling, elicitation). |
| One transaction per call | The audit row is written in the same transaction as the read: half the connection checkouts and commits, and "no audit, no data" is atomic. A denied or failed call still gets its own best-effort transaction. |
| Load shedding (`CallBulkhead`) | At most `MAX_IN_FLIGHT_CALLS` (default 20) calls run or wait for a connection. A call that cannot get a place within `MAX_IN_FLIGHT_WAIT` (default 0.5 s) gets `server_busy`, retryable, before it takes a connection. A burst degrades into fast refusals instead of a queue that times out. |
| Caffeine for the hot paths | Agent-registry lookups (5 s, single-flight: 400 simultaneous callers cause one query), quota buckets and HTTP rate-limit buckets. All hit/miss/size metrics are exported. |

### Sizing

- `MAX_IN_FLIGHT_CALLS` is about **twice** `DB_POOL_SIZE`. A few more places than connections is
  fine: the extra calls wait briefly. **Far** more is the trap: calls pile up inside the pool,
  hit Hikari's 3 s connection timeout and fail as `request_failed` before the limit refuses
  them. `ConcurrencySanityCheck` logs `concurrency_misconfigured` at startup when the limit is
  more than three times the pool.
- `MAX_IN_FLIGHT_WAIT` must stay well under the 3 s connection timeout.
- Raise `DB_POOL_SIZE` only as far as PostgreSQL can serve (`max_connections` across all
  replicas, minus headroom). Then raise `MAX_IN_FLIGHT_CALLS` with it.

### What the tests prove

- 900 overlapping requests across two tenants on ten pooled connections: every roster and
  read matches its own tenant, and every cross-tenant read is refused (`ConcurrencyIT`).
- 300 parallel allowed reads leave exactly 300 audit rows, none lost or doubled.
- 1,500 simultaneous calls into a pool of 10 complete without errors.
- A saturated server refuses at once with `server_busy`, writes no audit row, then recovers
  (`LoadSheddingIT`).
- Quotas and rate limits admit exactly their capacity under 400-way contention
  (`ConcurrencySafetyTest`).

## Before running more than one replica

These are **per instance** today. They are correct for one replica and weaker with N:

| State | With N replicas | What to do |
| --- | --- | --- |
| Agent quota (`calls-per-minute`, `calls-per-day`) | Each replica counts separately: the effective limit is up to N times higher. | Divide the configured limits by N, or move the counters to shared storage (Redis with Bucket4j, or a database counter). |
| HTTP rate limit (per IP, per token) | Same. | Same. It is a flood guard, so dividing by N is usually enough. |
| Agent-registry cache (5 s) | Fine: a suspension reaches every replica within the cache time. | Nothing. |
| Load shedding | Per replica, which is what you want: it protects that replica's own pool. | Nothing. |

Not in place, and the likely next ceiling:

- **The audit write is synchronous and per call.** That is deliberate ("no audit, no data"),
  and PostgreSQL's group commit already batches commits across concurrent transactions. If
  the audit insert becomes the bottleneck, the next step is to batch events from concurrent
  calls into one insert per tenant, with every caller still waiting for the batch to commit.
  Do not make it asynchronous: that gives up the guarantee.
- **One database.** Read replicas do not help the audit write, and the reads are cheap
  indexed lookups. Pooling in front of PostgreSQL (PgBouncer in transaction mode) helps
  once replicas multiply connections. It is compatible with the `set_config(..., true)`
  transaction-local tenant setting.

## Overload behaviour a client should expect

`server_busy` and `rate_limited` are both retryable. Clients should back off with jitter.
`server_busy` is not logged as a denial or an error and writes no audit row: nothing was
decided. Watch `mcp_bulkhead_rejected_total` and `mcp_bulkhead_in_flight` (see
[observability](observability.md)).
