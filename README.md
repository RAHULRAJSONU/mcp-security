# mcp-security

A Spring Boot [Model Context Protocol](https://modelcontextprotocol.io) server that lets an AI agent read patient
summaries, built to show the security mechanisms a healthcare system should have before an agent gets near
patient data.

> **Status: reference implementation (proof of concept).** It demonstrates the controls below and most are backed
> by automated tests; the gaps are marked. It is not a production system or a compliance certification, and it
> deliberately leaves out the items in [What this PoC leaves out](#what-this-poc-leaves-out). All patient data
> is synthetic. HIPAA compliance belongs to an organisation, not a codebase: see
> [PHI and PII handling](docs/phi-handling.md) for what this code does and what you must still provide.

**Stack:** Java 27, Spring Boot 4, Spring AI MCP server (Streamable HTTP), Spring Security (OAuth 2.0 resource
server with DPoP support and optional mutual TLS with certificate-bound tokens), PostgreSQL with row-level security, Flyway, Testcontainers.

## Safety assumptions

Returning PHI to an AI agent is **not safe by default**. It means sending PHI to a second party (the model) and to
an agent host that records it. The controls in this repository limit and record what an agent can ask for. They
do not control where the data goes next. Treat the following as preconditions; if one is false, do not connect
this service to real patient data.

| # | Assumption | Owner | Enforced here? |
|---|---|---|---|
| 1 | The model provider operates under a **business associate agreement**, with confirmed retention, no training on your data, and a known processing location. | Organisation | No |
| 2 | The **agent host** is itself a covered system. Transcripts, traces and tool logs are access-controlled, retained appropriately (or not kept at all), and protected as PHI at rest. | Organisation | No |
| 3 | The agent acts **only with the end user's own short-lived token**, never a shared service credential, so a compromised session cannot see more than that clinician could. | Agent host and IdP | Partly: audience and tenant checks, and tokens older than `JWT_MAX_LIFETIME` are refused |
| 4 | **Only approved agent hosts** can connect. | Platform | Only when the `mtls` profile is on |
| 5 | The identity provider issues correct claims (`tenant_id`, least-privilege scopes), enforces **multi-factor authentication**, and can revoke access. | IdP owner | No: the service trusts the IdP |
| 6 | The ingress terminates TLS, rate-limits, sets `X-Forwarded-Proto` **itself** (never passed through from clients), and does not publish the management port. | Platform | Partly: the `prod` profile refuses plain HTTP |
| 7 | The database has **encryption at rest**, protected backups, a provisioned `healthcare_app` role, and a guarded owner credential. | Platform | No |
| 8 | **Application logs are restricted.** They can incidentally hold data, such as a database error. The audit trail is retained (HIPAA expects six years) and reviewed. | Organisation | No retention policy |
| 9 | **Alerts exist and someone responds**: break-glass use, denial spikes, audit-write failures. | Organisation | Metrics and logs exist; no alert rules ship |
| 10 | A formal **risk analysis**, workforce training and a breach procedure are in place. All data in this repository is synthetic. | Organisation | No |

### What this does not protect against

- **Prompt injection that moves data the user may legitimately see.** Authorisation comes from the user's token, so
  an injected instruction cannot reach a patient the user cannot see. It can still persuade the agent to send
  permitted data somewhere it should not go.
- **A compromised identity provider**, which can mint any tenant and scope.
- **A malicious database owner or operator**, who can still change history.
- **A compromised agent host**, which already holds the user's token and the transcripts.

### Suggested posture

Start with the low-risk tools (`listMyPatients`, `getPatientSummary`) and enable medications and notes only after
assumptions 1 to 3 have been verified. There is no per-tool on/off switch yet, so today this is a deployment
decision: omit the scopes from tokens until you are ready.

## Architecture

![Architecture and trust boundaries](docs/architecture.png)

![Request security flow](docs/security-flow.png)

Sources are the editable SVGs in `docs/`.

## Security mechanisms

Each row is one mechanism, the threat it addresses, and the test that proves it.

| Mechanism | Threat it addresses | Implemented in | Proved by |
|---|---|---|---|
| Issuer and **audience** validation | Token minted for another service is accepted | `JwtSecurityConfig` | `JwtSecurityConfigTest` (audience validator) |
| DPoP sender-constrained tokens | Stolen token replayed from a log or proxy | `SecurityConfig` | **Not enforced.** A live test with a real Keycloak token showed plain bearer tokens are accepted, so DPoP is supported but optional |
| Mutual TLS on the public listener + certificate-bound tokens (RFC 8705), profile `mtls` | Impersonated client; stolen token replayed from another machine | `CertificateBoundTokenFilter`, `application-mtls.yaml` | `MutualTlsIT`, `CertificateBoundTokenFilterTest` |
| Deny-by-default routing, hardened headers | Unintended exposure | `SecurityConfig` | `SecurityEndpointsIT` |
| Scope + purpose + active-assignment policy | Over-broad access | `PatientAccessPolicy` | `PatientAccessPolicyTest`, `PatientAccessEndToEndIT` |
| Break-glass: own scope, justification, WARN audit, own metric | Emergency access via shared logins; insider abuse | `PatientAccessPolicy`, `AccessAuditLogger` | `PatientAccessPolicyTest`, `AccessAuditLoggerTest`, `PatientAccessEndToEndIT` |
| One indistinguishable refusal | Enumerating which patient IDs exist | `PatientAccessPolicy`, service layer | `PatientAccessEndToEndIT` |
| Forced row-level security with a per-transaction tenant | Cross-tenant leak; a forgotten `WHERE` clause | `V4` migration, `TenantScopedExecutor` | `TenantScopedExecutorIT`, `PatientAccessEndToEndIT` |
| Least-privilege app role, separate migration owner | SQL injection writing data; RLS bypass by an owner | `V3` migration, datasource config | Every `*IT` connects as that role |
| Audit trail: durable **append-only** `access_events` table, written before data is returned (fail-closed); log lines hold identifiers only | Repudiation, history tampering, unrecorded reads, PHI in logs, log forging | `AccessAuditor`, `AccessAuditLogger`, `V6` grants and policies | `AppendOnlyAuditIT`, `AuditFailClosedIT`, `AccessAuditLoggerTest` |
| One scope per data type; break-glass refused for clinical notes | Over-broad tokens; emergency access used to read sensitive data | `DataCategory`, `PatientAccessPolicy` | `PatientAccessPolicyTest`, `ClinicalToolsEndToEndIT` |
| Separate audit-reader duty (`audit.read`), tenant-isolated, reads are audited | Clinicians reviewing or hiding their own trail | `PatientAccessPolicy.requireAuditAccess` | `ClinicalToolsEndToEndIT` |
| Roster limited to active assignments | Enumerating patients; stale access after revocation | `JdbcRosterRepositoryAdapter` | `ClinicalToolsEndToEndIT` |
| PHI kept out of logs, errors, metrics and caches: redacted `toString`, Hibernate pinned, fixed error text, `no-store` | PHI leaking through side channels, including to the AI model | `domain` records, `SecuredPatientQueryService`, `application.yaml` | `PhiLogLeakIT`, `PhiRedactionTest`, `SecuredPatientQueryServiceTest`, `SecurityEndpointsIT` |
| Short-lived tokens; HTTPS-only in `prod` | A leaked token staying useful; PHI served in the clear | `JwtSecurityConfig`, `RequireHttpsFilter` | `TokenLifetimeValidatorTest`, `HttpsEnforcementIT` |
| Metrics and health on a separate port | Operational endpoints exposed publicly | `SecurityConfig` | `SecurityEndpointsIT` |
| No secret has a default | Credential leakage through source or builds | `application.yaml` | Convention; no test |


## The tools

Each tool exercises a different part of the policy. Every call is tenant-scoped and audited, and every refusal
looks identical whatever the cause (missing scope, no assignment, other tenant, unknown patient).

| Tool | Scopes needed | What it demonstrates |
|---|---|---|
| `getPatientSummary(patientId, purpose?, justification?)` | `patient.read` | Active assignment required; break-glass allowed |
| `listMyPatients()` | `patient.read` | Results limited to the caller's active assignments; revoked and expired ones disappear; no emergency form |
| `getPatientMedications(patientId, purpose?, justification?)` | `patient.read`, `medication.read` | A separate scope per data type; break-glass allowed |
| `getClinicalNotes(patientId, purpose?, justification?)` | `patient.read`, `notes.read` | A separate scope; break-glass is **refused** even when the caller holds the scope |
| `getAccessHistory(patientId, limit?)` | `audit.read` | An audit-officer duty clinicians don't hold; tenant-isolated; reading it is itself audited |
| `listBreakGlassEvents(limit?)` | `audit.read` | Review of emergency access, including the stated justification |

### Purposes

| Purpose | Requires | Behaviour |
|---|---|---|
| `TREATMENT` (default) | the tool's scopes and an **active assignment** to the patient | Routine read. |
| `EMERGENCY` (break-glass) | the tool's scopes **and** `patient.break_glass`, plus a 15–500 character `justification` | Skips the assignment check, never crosses tenants, logs at WARN, counted separately, and the justification is stored for audit readers. Not available for clinical notes. |
| anything else | n/a | Denied. |

### What happens when (all asserted in `ClinicalToolsEndToEndIT`)

| Caller | Scopes | Call | Result |
|---|---|---|---|
| doctor-101, hospital-A | `patient.read` | summary, `patient-400` | Allowed |
| doctor-101 | `patient.read` | summary, `patient-500` | Denied: assignment was revoked |
| doctor-101 | `patient.read` | medications, `patient-400` | Denied: no `medication.read` |
| doctor-101 | + `medication.read` | medications, `patient-400` | Allowed |
| doctor-101 | + `medication.read`, `patient.break_glass` | medications, `patient-500`, `EMERGENCY` + justification | Allowed, WARN, appears in the break-glass review |
| doctor-101 | + `notes.read`, `patient.break_glass` | notes, `patient-500`, `EMERGENCY` | Denied: break-glass never opens notes |
| doctor-101 | + `medication.read`, `patient.break_glass` | medications, `patient-600`, `EMERGENCY` | Denied: other tenant |
| doctor-101 / doctor-202 | `patient.read` | `listMyPatients` | `patient-400` only / `patient-400` and `patient-500` |
| doctor-101 | anything but `audit.read` | `getAccessHistory` | Denied |
| compliance-1, hospital-A | `audit.read` | `listBreakGlassEvents` | Shows who, which patient, and why |
| compliance-B, hospital-B | `audit.read` | `getAccessHistory`, `patient-400` | Empty: another tenant's history is invisible |

## Access token requirements

The server validates access tokens from the configured issuer, including DPoP-bound tokens, and certificate-bound tokens when the `mtls` profile is on. A token must carry:

| Claim | Requirement |
|---|---|
| `iss` | Equals `OIDC_ISSUER` |
| `aud` | Contains `JWT_AUDIENCE` (default `healthcare-mcp-server`) |
| `sub` | The clinician's identifier. Used for assignment checks and audit |
| `tenant_id` | The caller's tenant (hospital). Drives row-level security |
| `scope` | Space-separated. `patient.read` for patient data; `medication.read`, `notes.read` for those data types; `patient.break_glass` for emergency access; `audit.read` for the audit tools |
| `cnf` | Only with the `mtls` profile: `x5t#S256`, the base64url SHA-256 thumbprint of the client certificate. DPoP-bound tokens carry `jkt` instead |

Your identity provider must be configured to emit `tenant_id` and the audience. Discovery metadata
(RFC 9728) is served at `/.well-known/oauth-protected-resource`.

## Demo data (profile `local` and tests only)

Patients: `patient-400` and `patient-500` in `hospital-A`; `patient-600` in `hospital-B`. Each has a medication list
and a progress note.

| Clinician | Tenant | Assignments |
|---|---|---|
| `doctor-101` | `hospital-A` | `patient-400` active; `patient-500` **revoked** |
| `doctor-202` | `hospital-A` | `patient-400` and `patient-500`, both active |
| `doctor-303` | `hospital-B` | `patient-600` active |

Break-glass on `patient-500` works for `doctor-101` (own tenant); the same on `patient-600` never does.

## Run locally

Requirements: JDK 27, a PostgreSQL (tested on 17 and 18), and an OIDC provider you can reach. Docker is optional.

```
# one-time database setup (the app role's password is provisioned outside the migrations)
psql -U postgres -c "CREATE DATABASE patient_db"
psql -U postgres -c "CREATE ROLE healthcare_app LOGIN PASSWORD 'postgres'"

SPRING_PROFILES_ACTIVE=local OIDC_ISSUER=https://your-idp/realms/your-realm ./mvnw spring-boot:run
```

The `local` profile supplies developer defaults for the database and public URL. The service listens on `8080`,
with health and metrics on `8081`.

To practise against a real identity provider and Claude Desktop, follow the [hands-on guide](docs/cloud-iam-guide.md): a free Cloud-IAM realm, real tokens, sixteen policy scenarios with expected results, and a Desktop setup over HTTP.

## Configuration

All configuration is environment-driven; nothing secret has a default outside the `local` profile.

| Variable | Required | Purpose |
|---|---|---|
| `OIDC_ISSUER` | yes | Issuer of access tokens. Resolved at startup; the app refuses to boot if unreachable. |
| `APP_PUBLIC_URL` | yes* | Externally visible base URL, advertised as the protected resource identifier. |
| `POSTGRES_HOST` | yes* | Database host. |
| `DATABASE_PASSWORD` | yes* | Password for the restricted `healthcare_app` role. |
| `FLYWAY_USER` / `FLYWAY_PASSWORD` | yes* | Privileged owner used only for migrations. |
| `POSTGRES_PORT`, `POSTGRES_DB`, `POSTGRES_SSLMODE` | no | Defaults `5432`, `patient_db`, `verify-full`. |
| `DATABASE_USERNAME` | no | Default `healthcare_app`. |
| `JWT_AUDIENCE` | no | Default `healthcare-mcp-server`. |
| `JWT_MAX_LIFETIME` | no | Longest accepted access-token lifetime (`exp` minus `iat`), ISO-8601. Default `PT15M`. |
| `FLYWAY_ENABLED` | no | Set `false` to run migrations as a separate job. |
| `PORT`, `MANAGEMENT_PORT` | no | Defaults `8080` and `8081`. Never expose the management port through an ingress. |
| `DB_POOL_SIZE` | no | Default `10`. |

\* The `local` profile supplies defaults for these.

The `healthcare_app` role must be provisioned by the platform with its credential; migration `V3` only ensures it
exists and grants least-privilege `SELECT`.

## Profiles

- `prod`: structured (ECS JSON) logs, and refuses plain HTTP (the proxy must set `X-Forwarded-Proto` itself and never pass it through from clients). The Docker image sets this by default.
- `local`: developer defaults (local Postgres, seed data, debug security logs). Never deploy.
- `mtls`: mutual TLS on the public listener, with certificate-bound tokens.
- `oauth-demo`: a browser login helper under `/oauth/**`, using `OAUTH_CLIENT_ID` and optionally `OAUTH_CLIENT_SECRET`. Never deploy.

## Mutual TLS (optional)

Activate with `SPRING_PROFILES_ACTIVE=...,mtls`. The public listener then requires a client certificate that your
truststore accepts, and every access token must be bound to that certificate.

| Variable | Purpose |
|---|---|
| `MTLS_KEYSTORE`, `MTLS_KEYSTORE_PASSWORD` | Server certificate and key, for example `file:/etc/tls/server.p12` |
| `MTLS_TRUSTSTORE`, `MTLS_TRUSTSTORE_PASSWORD` | Client certificates (or the CA) the server accepts |
| `MTLS_KEYSTORE_TYPE`, `MTLS_TRUSTSTORE_TYPE` | Default `PKCS12` |
| `MTLS_REQUIRE_BOUND_TOKENS` | Default `true`. `false` also accepts unbound tokens (migration aid only) |

Your identity provider must issue tokens with a `cnf` claim containing `x5t#S256`, the base64url SHA-256 thumbprint
of the client certificate. Tokens without it, or bound to a different certificate, get `401`. The management port
stays plain HTTP and must remain on an internal network. This has been tested with real TLS handshakes and unit
tests, **not** end to end against a real identity provider. Revocation checking (CRL or OCSP) is not configured.

## Build and test

```
./mvnw verify      # unit tests + integration tests against a real PostgreSQL
docker build -t mcp-security .
```

Integration tests use Testcontainers by default. Without Docker, point them at an existing **empty** database:

```
IT_DB_URL=jdbc:postgresql://localhost:5432/scratch_db \
IT_DB_OWNER=postgres IT_DB_OWNER_PASSWORD=... IT_DB_APP_PASSWORD=... ./mvnw verify
```

With neither available, the database-backed tests are skipped, not failed. The container image has not been built
in this repository's verification runs.

## Operations (what a real deployment would add)

These notes illustrate the operational side. The PoC includes the hooks, not a deployment.

- Probes and metrics are served only on the management port: `/actuator/health/liveness`, `/actuator/health/readiness`, `/actuator/prometheus`. The public port returns 401 for them.
- Patient access is audited on logger `AUDIT.patient-access` (identifiers only, no clinical data) and counted as `clinical_patient_access_total{outcome,purpose}`. Route the log to retained, tamper-evident storage.
- Rate limiting, TLS termination and WAF belong at the gateway or ingress.

## Upgrading an existing dev database

`V3__create_database_role.sql` no longer contains a password, and the synthetic seed (`V2`) moved to `db/seed`,
loaded only by the `local` profile. An already-migrated dev DB will fail checksum validation once; run
`./mvnw flyway:repair` (or recreate the DB). Never edit an applied migration after the first real deployment.

## What this PoC leaves out

- Tamper evidence for the audit trail beyond database privileges. The application cannot edit or delete history, but the database owner still can, and there is no hash chain or write-once storage. Auditors can review break-glass use, but there is no approval workflow.
- Shipped alert rules, dashboards and a measured load test, which is illustrative).
- Automated tests for DPoP and injection attempts, and making DPoP mandatory. A live test against a real Keycloak realm confirmed plain bearer tokens are currently accepted.
- Role- or purpose-based field filtering. The summary returns an id, name and date of birth (no MRN), and the notes tool returns full note bodies, for any caller holding the scope.
- Rate limiting, TLS termination and WAF, which are assumed to sit at the platform or a gateway. Mutual TLS is implemented only for the public listener; gateway-to-service and service-to-database mTLS, revocation checking, and an end-to-end run with a real identity provider are not.
- A formal risk analysis and compliance review is an engineering aid, not a certification).
