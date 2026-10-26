# Application Security for AI Tools & MCP: An Incremental Reference Implementation & Curriculum

[![Java 27](https://img.shields.io/badge/Java-27-orange.svg)](https://openjdk.org/projects/jdk/27/)
[![Spring Boot 4](https://img.shields.io/badge/Spring%20Boot-4.1.1-green.svg)](https://spring.io/projects/spring-boot)
[![Model Context Protocol](https://img.shields.io/badge/MCP-Stateless%20HTTP-blue.svg)](https://modelcontextprotocol.io)
[![PostgreSQL RLS](https://img.shields.io/badge/PostgreSQL-Row--Level%20Security-336791.svg)](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)

A Spring Boot [Model Context Protocol](https://modelcontextprotocol.io) (MCP) server that lets an AI agent read patient records, engineered to demonstrate the **defense-in-depth security controls** required before an autonomous AI tool is permitted near sensitive enterprise data (such as Protected Health Information / PHI under HIPAA).

> **Educational Reference Implementation:** This repository is structured as both a working, production-grade reference implementation and an **incremental multi-page educational curriculum** to teach Application Security for AI Tools, AI Agents, and Tool Calling. All patient data is synthetic.

---

## 🎓 The Multi-Page Learning Curriculum

This repository includes a step-by-step, incremental course designed to teach security engineers, AI developers, and cloud architects how to secure Model Context Protocol (MCP) servers and AI agent tool integrations:

👉 **[Start the Curriculum: Master Index & Syllabus](curriculum/README.md)**

```
┌────────────────────────────────────────────────────────────────────────┐
│ THE INCREMENTAL LEARNING CURRICULUM                                    │
├────────────────────────────────────────────────────────────────────────┤
│ 🚀 Module 00: Start Here (new to MCP or security? begin here)          │
│    - Guided code tour, run a test, break a control on purpose          │
│    🔗 [Read Module 00](curriculum/00-start-here.md)                                      │
├────────────────────────────────────────────────────────────────────────┤
│ 📖 Module 01: Threat Modeling & MCP Trust Boundaries                   │
│    - The AI agent dilemma, OWASP Top 10 for LLMs, and trust boundaries │
│    🔗 [Read Module 01](curriculum/01-threat-modeling-and-trust-boundaries.md)            │
├────────────────────────────────────────────────────────────────────────┤
│ 📖 Module 02: Transport Layer Security & Ingress Hardening             │
│    - Fail-hard HTTPS, port segregation (8080 vs 8081), and zero-cache  │
│    🔗 [Read Module 02](curriculum/02-transport-and-edge-security.md)                     │
├────────────────────────────────────────────────────────────────────────┤
│ 📖 Module 03: Token Binding & Cryptographic Authentication             │
│    - User delegation, audience locking, and RFC 8705 mTLS token binding │
│    🔗 [Read Module 03](curriculum/03-authentication-and-token-binding.md)              │
├────────────────────────────────────────────────────────────────────────┤
│ 📖 Module 04: Contextual Authorization, Scopes & Break-Glass           │
│    - Fine-grained scopes, ReBAC assignments, and emergency overrides   │
│    🔗 [Read Module 04](curriculum/04-contextual-authorization-and-breakglass.md)        │
├────────────────────────────────────────────────────────────────────────┤
│ 📖 Module 05: Data-Tier Multi-Tenancy & PostgreSQL Row-Level Security   │
│    - Kernel RLS, transaction-scoped tenants, and least-privilege roles  │
│    🔗 [Read Module 05](curriculum/05-data-tier-isolation-and-row-level-security.md)    │
├────────────────────────────────────────────────────────────────────────┤
│ 📖 Module 06: Non-Repudiation, Fail-Closed Auditing & Immutable Logs   │
│    - "No audit, no data" paradigm, append-only DB tables, duty checks  │
│    🔗 [Read Module 06](curriculum/06-fail-closed-auditing-and-non-repudiation.md)      │
├────────────────────────────────────────────────────────────────────────┤
│ 📖 Module 07: Privacy by Design, Data Minimization & Side Channels     │
│    - Domain toString() redaction, CWE-117 log forging, error masking   │
│    🔗 [Read Module 07](curriculum/07-privacy-data-minimization-and-side-channels.md)    │
├────────────────────────────────────────────────────────────────────────┤
│ 📖 Module 08: Automated Security Testing & Verification Harness        │
│    - Testcontainers harness, testing DB RLS, and log leak assertions   │
│    🔗 [Read Module 08](curriculum/08-automated-security-verification.md)               │
├────────────────────────────────────────────────────────────────────────┤
│ 📖 Module 09: Production Hardening, Monitoring & Threat Playbook       │
│    - Zero-secret config, Prometheus anomaly alerts, incident triage    │
│    🔗 [Read Module 09](curriculum/09-production-hardening-and-threat-playbook.md)      │
├────────────────────────────────────────────────────────────────────────┤
│ 📖 Module 10: Agent Controls, Safe Errors & Resilience                 │
│    - Agent registry, step-up break-glass, quotas, load shedding        │
│    🔗 [Read Module 10](curriculum/10-agent-controls-and-resilience.md)                    │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 🛡️ Core Safety Assumptions

Returning PHI to an AI agent is **not safe by default**. Tool responses are transmitted to third-party LLM providers and recorded in host transcripts. Treat the following as non-negotiable preconditions before connecting this service to real patient data:

| # | Assumption | Owner | Enforced here? |
|---|---|---|---|
| 1 | The model provider operates under a **business associate agreement (BAA)** with confirmed zero data retention. | Organisation | No (External legal policy) |
| 2 | The **agent host** is itself a covered system with encrypted local transcripts and traces. | Organisation | No (Client-side workstation governance) |
| 3 | The agent acts **only with the end user's own short-lived token**, never a shared service credential. | Agent host & IdP | **Yes:** Validates subject, tenant, audience, and rejects tokens older than 15 minutes (`JWT_MAX_LIFETIME`). |
| 4 | **Only approved agent hosts** can connect. | Platform | **Yes:** When the `mtls` profile is on, requires client certificates. |
| 5 | The identity provider enforces **multi-factor authentication** and mints valid `tenant_id` claims. | IdP Owner | Assumed: Service trusts signed JWTs from `OIDC_ISSUER`. |
| 6 | The ingress terminates TLS, rate-limits, and isolates the management port. | Platform | **Yes:** `RequireHttpsFilter` rejects plain HTTP; port 8081 is separated from public 8080. |
| 7 | The database enforces **encryption at rest** and runs with a restricted runtime role. | Platform | **Yes:** Migrations provision least-privilege `healthcare_app` runtime user distinct from migration owner. |
| 8 | **Application logs are strictly restricted** from holding clinical data or free-text justifications. | Development | **Yes:** Verified by `PhiLogLeakIT` and record `toString()` redactions. |
| 9 | **Real-time alerting exists** for break-glass use and denial spikes. | Operations | **Yes:** Emits Prometheus metric counters (`clinical_patient_access_total`). |
| 10 | A formal **risk analysis**, workforce training, and breach procedure are established. | Organisation | Administrative policy. |

---

## 🏛️ Architecture & Verification Gates

Every tool call processed by this server must pass **six distinct verification gates** across a single database transaction. Around those gates sit the agent-registry check, the per-agent quota and the load-shedding limit (see [Agent Controls, Resilience & Operations](#-agent-controls-resilience--operations)). The diagrams predate those additions.

![Architecture and trust boundaries](docs/architecture.png)

![One tool call: six checks, one transaction, one audit trail](docs/security-flow.png)

*(Editable SVG sources are available in `docs/architecture.svg` and `docs/security-flow.svg`)*

---

## 🔒 Security Mechanisms & Test Proofs

| Mechanism | Threat Addressed | Implementation | Verification Test |
|---|---|---|---|
| **Audience Validation** | Token minted for another microservice is replayed | [`JwtSecurityConfig.java`](src/main/java/io/github/rahulrajsonu/mcpsecurity/filter/JwtSecurityConfig.java) | [`JwtSecurityConfigTest.java`](src/test/java/io/github/rahulrajsonu/mcpsecurity/filter/JwtSecurityConfigTest.java) |
| **Short-Lived Tokens** | Stolen token remains usable indefinitely | [`JwtSecurityConfig.java`](src/main/java/io/github/rahulrajsonu/mcpsecurity/filter/JwtSecurityConfig.java) | [`TokenLifetimeValidatorTest.java`](src/test/java/io/github/rahulrajsonu/mcpsecurity/filter/TokenLifetimeValidatorTest.java) |
| **Mutual TLS & Certificate-Bound Tokens (RFC 8705)** | Stolen token replayed from another machine or proxy | [`CertificateBoundTokenFilter.java`](src/main/java/io/github/rahulrajsonu/mcpsecurity/security/CertificateBoundTokenFilter.java) | [`MutualTlsIT.java`](src/test/java/io/github/rahulrajsonu/mcpsecurity/MutualTlsIT.java) |
| **Deny-by-Default Ingress & Port Separation** | Accidental exposure of operational endpoints (SSRF/RCE) | [`SecurityConfig.java`](src/main/java/io/github/rahulrajsonu/mcpsecurity/config/SecurityConfig.java) | [`SecurityEndpointsIT.java`](src/test/java/io/github/rahulrajsonu/mcpsecurity/SecurityEndpointsIT.java) |
| **Fail-Hard HTTPS Enforcement** | Cleartext sniffing of bearer tokens and patient queries | [`RequireHttpsFilter.java`](src/main/java/io/github/rahulrajsonu/mcpsecurity/security/RequireHttpsFilter.java) | [`HttpsEnforcementIT.java`](src/test/java/io/github/rahulrajsonu/mcpsecurity/HttpsEnforcementIT.java) |
| **Contextual Authorization & ReBAC** | Over-broad access; accessing unassigned patients | [`PatientAccessPolicy.java`](src/main/java/io/github/rahulrajsonu/mcpsecurity/security/PatientAccessPolicy.java) | [`PatientAccessPolicyTest.java`](src/test/java/io/github/rahulrajsonu/mcpsecurity/security/PatientAccessPolicyTest.java) |
| **Break-Glass Emergency Governance** | Insider abuse; unrecorded emergency access | [`PatientAccessPolicy.java`](src/main/java/io/github/rahulrajsonu/mcpsecurity/security/PatientAccessPolicy.java), [`AccessAuditLogger.java`](src/main/java/io/github/rahulrajsonu/mcpsecurity/security/AccessAuditLogger.java) | [`ClinicalToolsEndToEndIT.java`](src/test/java/io/github/rahulrajsonu/mcpsecurity/ClinicalToolsEndToEndIT.java) |
| **Indistinguishable Refusals** | Patient enumeration across tenants | [`SecuredPatientQueryService.java`](src/main/java/io/github/rahulrajsonu/mcpsecurity/service/SecuredPatientQueryService.java) | [`PatientAccessEndToEndIT.java`](src/test/java/io/github/rahulrajsonu/mcpsecurity/PatientAccessEndToEndIT.java) |
| **PostgreSQL Row-Level Security (RLS)** | Cross-tenant data leaks; forgotten SQL `WHERE` clauses | [`TenantScopedExecutor.java`](src/main/java/io/github/rahulrajsonu/mcpsecurity/security/TenantScopedExecutor.java), [`V4`](src/main/resources/db/migration/V4__enable_tenant_rls.sql), [`V6`](src/main/resources/db/migration/V6__secure_clinical_data.sql) | [`TenantScopedExecutorIT.java`](src/test/java/io/github/rahulrajsonu/mcpsecurity/security/TenantScopedExecutorIT.java) |
| **Least-Privilege Database Role** | SQL injection deleting data or modifying history | [`V3`](src/main/resources/db/migration/V3__create_database_role.sql), [`V6`](src/main/resources/db/migration/V6__secure_clinical_data.sql) | [`AppendOnlyAuditIT.java`](src/test/java/io/github/rahulrajsonu/mcpsecurity/AppendOnlyAuditIT.java) |
| **Fail-Closed Append-Only Audit Trail** | "No audit, no data"; repudiation; audit tampering | [`AccessAuditor.java`](src/main/java/io/github/rahulrajsonu/mcpsecurity/service/AccessAuditor.java), [`SecuredPatientQueryService.java`](src/main/java/io/github/rahulrajsonu/mcpsecurity/service/SecuredPatientQueryService.java) | [`AuditFailClosedIT.java`](src/test/java/io/github/rahulrajsonu/mcpsecurity/AuditFailClosedIT.java), [`AppendOnlyAuditIT.java`](src/test/java/io/github/rahulrajsonu/mcpsecurity/AppendOnlyAuditIT.java) |
| **Audit Duty Segregation** | Clinicians reviewing or tampering with audit logs | [`PatientAccessPolicy.java`](src/main/java/io/github/rahulrajsonu/mcpsecurity/security/PatientAccessPolicy.java) | [`ClinicalToolsEndToEndIT.java`](src/test/java/io/github/rahulrajsonu/mcpsecurity/ClinicalToolsEndToEndIT.java) |
| **Side-Channel Log & Error Redaction** | PHI leaking into logging infrastructure or AI prompts | [`domain records`](src/main/java/io/github/rahulrajsonu/mcpsecurity/mcp/domain/), [`AccessAuditLogger.java`](src/main/java/io/github/rahulrajsonu/mcpsecurity/security/AccessAuditLogger.java) | [`PhiLogLeakIT.java`](src/test/java/io/github/rahulrajsonu/mcpsecurity/PhiLogLeakIT.java), [`PhiRedactionTest.java`](src/test/java/io/github/rahulrajsonu/mcpsecurity/mcp/domain/PhiRedactionTest.java) |

---

## 🧰 The Model Context Protocol (MCP) Tools

Tools are exposed over HTTP under `/mcp` using Spring AI MCP Server. The protocol is **stateless** by default (`MCP_PROTOCOL=STATELESS`), so any replica can answer any call. Set `MCP_PROTOCOL=STREAMABLE` only if a tool needs server-to-client messages. Every tool returns an `McpSchema.CallToolResult`.

| Tool Name | Scopes Required | Capabilities & Policy Constraints |
|---|---|---|
| `getPatientSummary(patientId, purpose?, justification?)` | `patient.read` | Requires active clinician assignment. Allows break-glass emergency read. Excludes MRN (data minimization). |
| `listMyPatients()` | `patient.read` | Returns active roster entries for caller. Expired or revoked assignments disappear. No emergency form. |
| `getPatientMedications(patientId, purpose?, justification?)` | `patient.read`, `medication.read` | Category-specific scope. Allows break-glass emergency read. |
| `getClinicalNotes(patientId, purpose?, justification?)` | `patient.read`, `notes.read` | Category-specific scope. **Break-glass is strictly refused** even if held by caller. |
| `getAccessHistory(patientId, limit?)` | `audit.read` | Compliance officer tool. Isolated by tenant. Reading the audit log is itself audited. |
| `listBreakGlassEvents(limit?)` | `audit.read` | Compliance officer tool. Lists emergency reads with stated clinical justifications. |

### Error contract

Failures come back as `CallToolResult` with `isError=true` and a sanitized JSON body `{error, message, retryable}`. No stack traces or internals are returned.

| `error` | Meaning | `retryable` |
|---|---|---|
| `access_denied` | Policy, tenant, agent-registry or step-up refusal. Cross-tenant refusals are indistinguishable from "not found". | no |
| `unauthenticated` | Missing or invalid identity. | no |
| `rate_limited` | Per-agent quota exceeded. | yes |
| `server_busy` | Load shedding. Nothing was decided, read or audited. | yes |
| `request_failed` | Unexpected failure, including an unavailable audit store (fail-closed). | yes |

Clinical notes are wrapped with an "UNTRUSTED CONTENT" notice, because free text can carry prompt injection.

---

## 🤖 Agent Controls, Resilience & Operations

Beyond user authorization, the server controls **which agent** may act for a user, how much it may do, and how it behaves under load.

| Capability | What it does | Details |
|---|---|---|
| **Agent registry** | An OAuth client (`azp`) may act for a user only if registered for that (tenant, client, user) as `APPROVED` and unexpired. Denials: `no_client`, `unknown`, `not_approved`, `expired`. Lookups are cached for 5 s, so a suspension takes effect within seconds. | [docs/agent-registry.md](docs/agent-registry.md) |
| **Break-glass step-up** | Purpose and justification are model-supplied arguments, so the token must also carry an `acr` equal to `BREAK_GLASS_ACR` (prod default `urn:healthcare:acr:step-up`; blank disables it). | [docs/agent-registry.md](docs/agent-registry.md) |
| **Agent quota** | Per (tenant, subject, client) calls per minute and per day (Bucket4j + Caffeine) → `rate_limited`. | `app.security.agent.*` |
| **Load shedding** | At most `MAX_IN_FLIGHT_CALLS` (default 20) calls run or wait for a connection. Excess calls get `server_busy` within `MAX_IN_FLIGHT_WAIT` (default 0.5 s). Keep the limit at about 2× `DB_POOL_SIZE`. | [docs/scaling.md](docs/scaling.md) |
| **Single-transaction audit** | The agent check, the read and the ALLOWED audit row commit together, so "no audit, no data" is atomic. Denied and failed calls get a best-effort audit row. | [docs/scaling.md](docs/scaling.md) |
| **Actor chain** | The RFC 8693 `act` chain (for example `agent-a>agent-b`) is recorded, up to 5 hops, in `access_events.actor`. It is recorded only and grants nothing. | [docs/agent-registry.md](docs/agent-registry.md) |
| **Virtual threads** | `spring.threads.virtual.enabled=true`: waiting on the database is cheap. The database pool is the real capacity limit. | [docs/scaling.md](docs/scaling.md) |
| **Observability** | Prometheus metrics on the management port (tool calls and latency, agent denials, quota, rate limit, bulkhead, Caffeine caches), `X-Request-ID` correlation, ECS JSON logs in `prod`, tool fingerprints logged at startup, and 13 alert rules. | [docs/observability.md](docs/observability.md), [ops/prometheus-alerts.yml](ops/prometheus-alerts.yml) |

Quotas and rate limits are **per instance**. With N replicas, divide the limits by N or move the counters to shared storage.

### Key configuration

| Variable | Default | Purpose |
|---|---|---|
| `MCP_PROTOCOL` | `STATELESS` | `STATELESS` or `STREAMABLE` |
| `BREAK_GLASS_ACR` | blank (prod: `urn:healthcare:acr:step-up`) | Required `acr` for emergency access |
| `MAX_IN_FLIGHT_CALLS` | `20` | Load-shedding limit |
| `MAX_IN_FLIGHT_WAIT` | `PT0.5S` | How long a call waits for a place before `server_busy` |
| `DB_POOL_SIZE` | `10` | Database pool; sizes the limit above |
| `JWT_MAX_LIFETIME` | 15 minutes | Maximum accepted token lifetime |

---

## 🚀 Quickstart & Local Execution

### Prerequisites
- JDK 27
- PostgreSQL 17 or 18 (with `psql` client)
- Node.js 18+ (for OAuth device flow helper)

### 1. One-Time Database Setup
```bash
psql -U postgres -c "CREATE DATABASE patient_db"
psql -U postgres -c "CREATE ROLE healthcare_app LOGIN PASSWORD 'postgres'"
```

### 2. Boot Application (Local Profile)
```bash
SPRING_PROFILES_ACTIVE=local \
OIDC_ISSUER=https://your-idp/realms/your-realm \
./mvnw spring-boot:run
```
The server listens on **8080** (public MCP listener) and **8081** (internal actuator metrics).

### 3. Hands-On Verification with Claude Desktop
Follow the hands-on tutorial to connect Claude Desktop to a real Keycloak instance on Cloud-IAM and test live tool interactions:  
👉 **[Read the Hands-On Cloud-IAM & Claude Desktop Guide](docs/cloud-iam-guide.md)**

---

## 🧪 Automated Testing & Verification

Integration tests leverage Testcontainers to spin up isolated PostgreSQL instances and assert database-level security policies. They also cover the agent registry, quotas, load shedding, the stateless HTTP transport and concurrency: 900 overlapping cross-tenant requests on 10 pooled connections, and exactly one audit row per allowed call.

```bash
# Run all unit tests
./mvnw test -Dtest=*Test

# Run all unit and integration tests (requires Docker)
./mvnw verify
```

To run integration tests against a pre-existing local database without Docker:
```bash
IT_DB_URL=jdbc:postgresql://localhost:5432/scratch_db \
IT_DB_OWNER=postgres \
IT_DB_OWNER_PASSWORD=secret \
IT_DB_APP_PASSWORD=secret \
./mvnw verify
```

---

## 📖 Additional Documentation & Resources

- [Multi-Page Learning Curriculum](curriculum/README.md)
- [PHI & PII Handling Guide](docs/phi-handling.md)
- [Agent Registry](docs/agent-registry.md)
- [Observability: metrics, logs, request IDs](docs/observability.md)
- [Concurrency & Scaling](docs/scaling.md)
- [Prometheus alert rules](ops/prometheus-alerts.yml)
- [Cloud-IAM & Claude Desktop Integration Guide](docs/cloud-iam-guide.md)
- [Architecture Diagram Source](docs/architecture.svg)
- [Security Flow Diagram Source](docs/security-flow.svg)
