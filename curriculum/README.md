# Application Security for AI Tools & MCP: A Comprehensive Engineering Curriculum

Welcome to the **Application Security for AI Tools & Model Context Protocol (MCP)** curriculum. This curriculum converts this repository from a reference codebase into an incremental, multi-page educational masterclass.

Modern AI agents and Large Language Models (LLMs) are no longer isolated text completion engines. Through protocols like **Model Context Protocol (MCP)**, agents execute tools, interact with APIs, query databases, and read highly sensitive enterprise data (such as Protected Health Information / PHI under HIPAA). 

**Connecting an autonomous agent to enterprise systems is not safe by default.** This course teaches you how to construct, audit, and verify hardened application security controls for AI tooling, grounded in real code and automated integration tests.

---

## 🗺️ Incremental Learning Path

The curriculum is structured as a **Start Here module plus 10 progressive modules**, moving from a guided code tour and threat modeling to cryptographic identity, fine-grained access control, data-tier row-level isolation, tamper-evident auditing, automated verification, and finally agent-specific controls and resilience.

> **New to security or MCP? Begin with [Module 00: Start Here](00-start-here.md).** It takes about an hour, assumes only Java and basic Spring, and walks one request through the real classes before you run and deliberately break your first test.

```
┌────────────────────────────────────────────────────────────────────────┐
│ START HERE                                                             │
│ [00. Start Here: The Whole Idea in One Hour]                           │
│  - Guided code tour, vocabulary, run a test, break a control on purpose│
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│ LEVEL 1: FOUNDATIONS & THREAT MODELING                                 │
│ [01. Threat Modeling & MCP Trust Boundaries]                           │
│  - The AI Agent Security Dilemma, Trust Boundaries & Attack Surfaces   │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│ LEVEL 2: NETWORK & PERIMETER DEFENSE                                   │
│ [02. Transport Layer Security & Ingress Hardening]                     │
│  - Fail-Hard HTTPS, Port Segregation & Hardened HTTP Headers           │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│ LEVEL 3: IDENTITY & CRYPTOGRAPHIC PROOF                                │
│ [03. Authentication, OIDC & Token Binding (mTLS/DPoP)]                 │
│  - User-Delegated Identity, Audience Locking & Proof-of-Possession     │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│ LEVEL 4: FINE-GRAINED ACCESS GOVERNANCE                                │
│ [04. Contextual Authorization, Purpose & Break-Glass]                  │
│  - Scope Partitioning, Active Assignments & Emergency Overrides        │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│ LEVEL 5: DATA TIER & MULTI-TENANT ISOLATION                            │
│ [05. PostgreSQL Row-Level Security & Role Separation]                  │
│  - RLS Policies, Transaction Tenants & Anti-Enumeration Refusals       │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│ LEVEL 6: AUDITABILITY & NON-REPUDIATION                                │
│ [06. Fail-Closed Auditing & Immutable Event Logs]                      │
│  - "No Audit, No Data", Append-Only DB Grants & Duty Segregation       │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│ LEVEL 7: DATA MINIMIZATION & PRIVACY                                   │
│ [07. Privacy by Design, Side Channels & Redaction]                     │
│  - PHI Masking, Safe toString(), CWE-117 Log Forging & Error Guarding  │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│ LEVEL 8: CONTINUOUS SECURITY VERIFICATION                              │
│ [08. Automated Security Testing & Verification Harness]                │
│  - Testcontainers, Asserting DB RLS, Fail-Closed & Leak Tests          │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│ LEVEL 9: PRODUCTION OPERATIONS & PLAYBOOKS                             │
│ [09. Production Hardening & Operational Security Playbook]             │
│  - Zero-Secret Config, Prometheus Anomaly Detection & Incident Triage  │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│ LEVEL 10: AGENT CONTROLS & RESILIENCE                                  │
│ [10. Agent Registry, Safe Errors, Quotas & Load Shedding]              │
│  - Which software may act, bounded volume, safe errors, overload       │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 📚 Curriculum Modules & Code Reference Map

| Module | Core Security Concept | Attack Vectors Addressed | Primary Code References | Verification Tests |
|---|---|---|---|---|
| **[00. Start Here](00-start-here.md)** | The whole request path, vocabulary, running and breaking a test | Not knowing where to begin | [`SecuredPatientQueryService.java`](../src/main/java/io/github/rahulrajsonu/mcpsecurity/service/SecuredPatientQueryService.java), [`PatientMcpTools.java`](../src/main/java/io/github/rahulrajsonu/mcpsecurity/mcp/tool/PatientMcpTools.java) | [`AgentRegistryIT.java`](../src/test/java/io/github/rahulrajsonu/mcpsecurity/AgentRegistryIT.java) |
| **[01. Threat Modeling & Trust Boundaries](01-threat-modeling-and-trust-boundaries.md)** | AI Agent Trust Boundaries, MCP Protocol Attack Surface | Prompt injection data exfiltration, Confused deputy, Excessive agency | [`McpSecurityApplication.java`](../src/main/java/io/github/rahulrajsonu/mcpsecurity/McpSecurityApplication.java), [docs/architecture.svg](../docs/architecture.svg) | Architectural review |
| **[02. Transport & Edge Security](02-transport-and-edge-security.md)** | Network Ingress Hardening, Fail-Hard HTTPS, Port Separation | Cleartext credential sniffing, Management endpoint exposure (SSRF/RCE), Caching of PHI | [`RequireHttpsFilter.java`](../src/main/java/io/github/rahulrajsonu/mcpsecurity/security/RequireHttpsFilter.java), [`SecurityConfig.java`](../src/main/java/io/github/rahulrajsonu/mcpsecurity/config/SecurityConfig.java) | [`HttpsEnforcementIT.java`](../src/test/java/io/github/rahulrajsonu/mcpsecurity/HttpsEnforcementIT.java), [`SecurityEndpointsIT.java`](../src/test/java/io/github/rahulrajsonu/mcpsecurity/SecurityEndpointsIT.java) |
| **[03. Token Binding & Authentication](03-authentication-and-token-binding.md)** | OAuth 2.0 / OIDC Delegation, Audience Validation, RFC 8705 Certificate-Bound Tokens | Bearer token theft and replay, Cross-service token confusion, Stale token reuse | [`JwtSecurityConfig.java`](../src/main/java/io/github/rahulrajsonu/mcpsecurity/filter/JwtSecurityConfig.java), [`CertificateBoundTokenFilter.java`](../src/main/java/io/github/rahulrajsonu/mcpsecurity/security/CertificateBoundTokenFilter.java) | [`JwtSecurityConfigTest.java`](../src/test/java/io/github/rahulrajsonu/mcpsecurity/filter/JwtSecurityConfigTest.java), [`MutualTlsIT.java`](../src/test/java/io/github/rahulrajsonu/mcpsecurity/MutualTlsIT.java) |
| **[04. Contextual Authorization & Break-Glass](04-contextual-authorization-and-breakglass.md)** | Granular Scopes, Purpose-Based Access Control (PBAC), Emergency Overrides | Over-broad tool permissions, Snooping on unassigned patients, Break-glass abuse | [`PatientAccessPolicy.java`](../src/main/java/io/github/rahulrajsonu/mcpsecurity/security/PatientAccessPolicy.java), [`PatientMcpTools.java`](../src/main/java/io/github/rahulrajsonu/mcpsecurity/mcp/tool/PatientMcpTools.java) | [`PatientAccessPolicyTest.java`](../src/test/java/io/github/rahulrajsonu/mcpsecurity/security/PatientAccessPolicyTest.java), [`ClinicalToolsEndToEndIT.java`](../src/test/java/io/github/rahulrajsonu/mcpsecurity/ClinicalToolsEndToEndIT.java) |
| **[05. Data-Tier Isolation & PostgreSQL RLS](05-data-tier-isolation-and-row-level-security.md)** | Multi-Tenancy, PostgreSQL Row-Level Security, Least-Privilege DB Roles | Cross-tenant data leaks, Missing application WHERE clauses, SQL Injection data theft | [`TenantScopedExecutor.java`](../src/main/java/io/github/rahulrajsonu/mcpsecurity/security/TenantScopedExecutor.java), [`V4__enable_tenant_rls.sql`](../src/main/resources/db/migration/V4__enable_tenant_rls.sql), [`V6__secure_clinical_data.sql`](../src/main/resources/db/migration/V6__secure_clinical_data.sql) | [`TenantScopedExecutorIT.java`](../src/test/java/io/github/rahulrajsonu/mcpsecurity/security/TenantScopedExecutorIT.java), [`PatientAccessEndToEndIT.java`](../src/test/java/io/github/rahulrajsonu/mcpsecurity/PatientAccessEndToEndIT.java) |
| **[06. Fail-Closed Auditing & Non-Repudiation](06-fail-closed-auditing-and-non-repudiation.md)** | "No Audit, No Data" Paradigm, Database Append-Only Enforcement, Audit Duty Separation | Repudiation, Tampering with audit logs, Silent unrecorded data exfiltration | [`AccessAuditor.java`](../src/main/java/io/github/rahulrajsonu/mcpsecurity/service/AccessAuditor.java), [`SecuredPatientQueryService.java`](../src/main/java/io/github/rahulrajsonu/mcpsecurity/service/SecuredPatientQueryService.java) | [`AuditFailClosedIT.java`](../src/test/java/io/github/rahulrajsonu/mcpsecurity/AuditFailClosedIT.java), [`AppendOnlyAuditIT.java`](../src/test/java/io/github/rahulrajsonu/mcpsecurity/AppendOnlyAuditIT.java) |
| **[07. Privacy by Design & Side-Channel Leaks](07-privacy-data-minimization-and-side-channels.md)** | Data Minimization, Object `toString()` Redaction, CWE-117 Log Injection, Error Masking | PHI leaking into log ingestion pipelines, Model hallucinating on internal DB errors, Patient enumeration | [`PatientSummary.java`](../src/main/java/io/github/rahulrajsonu/mcpsecurity/mcp/domain/PatientSummary.java), [`AccessAuditLogger.java`](../src/main/java/io/github/rahulrajsonu/mcpsecurity/security/AccessAuditLogger.java) | [`PhiLogLeakIT.java`](../src/test/java/io/github/rahulrajsonu/mcpsecurity/PhiLogLeakIT.java), [`PhiRedactionTest.java`](../src/test/java/io/github/rahulrajsonu/mcpsecurity/mcp/domain/PhiRedactionTest.java) |
| **[08. Automated Security Testing Harness](08-automated-security-verification.md)** | Security Test Harnesses, Testcontainers Isolation, Database-Level Assertion | Regression in security policies, Silent permission drift, Untested edge cases | [`AbstractPostgresIT.java`](../src/test/java/io/github/rahulrajsonu/mcpsecurity/AbstractPostgresIT.java), [`ClinicalToolsEndToEndIT.java`](../src/test/java/io/github/rahulrajsonu/mcpsecurity/ClinicalToolsEndToEndIT.java) | `./mvnw verify` |
| **[09. Production Hardening & Playbooks](09-production-hardening-and-threat-playbook.md)** | Zero-Secret Config, Prometheus Anomaly Metrics, Incident Response Playbook | Credential leaks in git, Undetected brute-force enumeration or prompt injection loops | [`application-prod.yaml`](../src/main/resources/application-prod.yaml), [`application-mtls.yaml`](../src/main/resources/application-mtls.yaml) | Deployment runbooks & alerts |
| **[10. Agent Controls & Resilience](10-agent-controls-and-resilience.md)** | Agent Registry, Break-Glass Step-Up, Per-Agent Quotas, Safe Error Contract, Load Shedding, Client/Actor Attribution | Unapproved or retired agents, prompt-injected emergency access, runaway loops and bulk reads, error-text leakage, overload outages | [`AgentAccessPolicy.java`](../src/main/java/io/github/rahulrajsonu/mcpsecurity/security/AgentAccessPolicy.java), [`AgentQuota.java`](../src/main/java/io/github/rahulrajsonu/mcpsecurity/security/AgentQuota.java), [`CallBulkhead.java`](../src/main/java/io/github/rahulrajsonu/mcpsecurity/security/CallBulkhead.java), [`ToolCallResponse.java`](../src/main/java/io/github/rahulrajsonu/mcpsecurity/mcp/tool/ToolCallResponse.java) | [`TutorialLabIT.java`](../src/test/java/io/github/rahulrajsonu/mcpsecurity/TutorialLabIT.java), [`AgentRegistryIT.java`](../src/test/java/io/github/rahulrajsonu/mcpsecurity/AgentRegistryIT.java), [`LoadSheddingIT.java`](../src/test/java/io/github/rahulrajsonu/mcpsecurity/LoadSheddingIT.java), [`ConcurrencyIT.java`](../src/test/java/io/github/rahulrajsonu/mcpsecurity/ConcurrencyIT.java) |

---

## 🛠️ How to Study This Curriculum

1. **Read Incrementally**: Each module is self-contained yet builds sequentially on earlier principles. Start with Module 00 (or Module 1 if you already know the basics) and progress through Module 10.
2. **Follow Code Anchors**: Every chapter includes exact code walkthroughs with links to source lines in `src/main/` and `src/test/`.
3. **Execute the Verification Tests**: Run unit tests and integration tests locally to watch how security assertions pass or fail when controls are toggled:
   ```bash
   # Run all unit tests
   ./mvnw test -Dtest=*Test

   # Run integration tests (with Docker running)
   ./mvnw verify
   ```
4. **Complete the Hands-On Labs**: Each chapter contains concrete engineering labs and "Attack & Defend" exercises designed to test your understanding.

---

[➡️ Begin with Module 00: Start Here](00-start-here.md)
