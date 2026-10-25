# Agent registry

An AI agent is an OAuth client acting for one user. A call is allowed only when the
token's `azp` (client id) is registered, approved and unexpired **for the token's
subject, in the token's tenant**. The check runs on every tool call, inside the
tenant-scoped transaction, in `AgentAccessPolicy`.

| Column | Meaning |
| --- | --- |
| `tenant_id`, `client_id`, `owner_subject` | One row per user a client may act for. An approval for doctor-101 does not cover doctor-202. |
| `state` | `PENDING`, `APPROVED`, `SUSPENDED`, `RETIRED`. Only `APPROVED` is let through. |
| `expires_at` | Approval ends at this instant. Judged against the clock on every call. |

Every refusal (unknown client, wrong user, wrong state, expired, no `azp`) returns the
same `access_denied` result, so a caller cannot tell which check failed. The refusal
is audited with the client id.

## Who changes the registry

The application role (`healthcare_app`) can only `SELECT` from `agents`. It cannot
approve itself. Registration is an operator action, run as the migration owner:

```sql
-- Approve a client for a user for 90 days
INSERT INTO agents (tenant_id, client_id, owner_subject, state, expires_at)
VALUES ('hospital-A', 'healthcare-mcp-client', 'doctor-101', 'APPROVED', now() + interval '90 days');

-- Suspend (takes effect within app.security.agent.registry-cache-ttl, 5 s by default)
UPDATE agents SET state = 'SUSPENDED'
 WHERE tenant_id = 'hospital-A' AND client_id = 'healthcare-mcp-client' AND owner_subject = 'doctor-101';

-- Retire for good
UPDATE agents SET state = 'RETIRED' WHERE tenant_id = 'hospital-A' AND client_id = 'old-client';
```

Run these through your change process: each one changes who can reach patient data.
Row-level security does not apply to the owner role, so name the tenant in every
statement.

## Related controls

- **Quota** (`AgentQuota`): per (tenant, user, client), `app.security.agent.calls-per-minute`
  and `calls-per-day`. Keyed on who is acting, so a refreshed token does not reset it.
- **Break-glass step-up**: `purpose=EMERGENCY` is chosen by the caller, which may be a
  model. In prod the token must also carry `acr` equal to `app.security.break-glass.required-acr`
  (`BREAK_GLASS_ACR`, default `urn:healthcare:acr:step-up`). Configure the identity
  provider to issue that `acr` only after a fresh human step-up such as MFA. If it never
  does, break-glass is simply unavailable.
- **Untrusted notes**: `getClinicalNotes` marks its result as untrusted data written by
  other people, ahead of the content.
- **Tool fingerprints**: at startup each tool logs `mcp_tool_fingerprint name=… sha256=…`.
  Record these per release; a changed hash means the model is being told something new
  about a tool.
