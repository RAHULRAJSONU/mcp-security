# Module 09: Production Hardening, Monitoring & Threat Playbook

> **Level:** DevOps, SRE & Incident Response | **Estimated Reading Time:** 25 mins  
> **Prerequisites:** Modules 01–08, familiarity with Docker, Kubernetes, Prometheus, and Incident Response.  
> **Navigation:** [⬅️ Module 08: Automated Security Testing Harness](08-automated-security-verification.md) | [📚 Return to Curriculum Overview](README.md)

---

## 1. The Production Security Mandate

Transitioning an AI Tool / MCP server from development to production requires elevating security controls from code-level checks to infrastructure and operational enforcement.

In production:
- Secrets must never exist in configuration files or container images.
- Operational metrics must feed automated security alerting pipelines.
- Security and compliance teams must possess concrete incident response playbooks for AI-specific attacks.

---

## 2. Zero-Secret Configuration Architecture

A common vulnerability in enterprise software is committing default passwords or fallback API tokens into source control (CWE-798).

### The Configuration Rule in `mcp-security`
In [`application.yaml`](file:///c:/ws/health-mcp-client/src/main/resources/application.yaml), **no secret has a default value**:

```yaml
spring:
  datasource:
    url: jdbc:postgresql://${POSTGRES_HOST}:${POSTGRES_PORT:5432}/${POSTGRES_DB:patient_db}?sslmode=${POSTGRES_SSLMODE:verify-full}
    username: ${DATABASE_USERNAME:healthcare_app}
    password: ${DATABASE_PASSWORD}  # NO DEFAULT: Boot fails if omitted!
  flyway:
    user: ${FLYWAY_USER}            # NO DEFAULT: Privileged migration user
    password: ${FLYWAY_PASSWORD}    # NO DEFAULT

app:
  public-url: ${APP_PUBLIC_URL}     # NO DEFAULT: Advertised resource ID
  security:
    jwt:
      audience: ${JWT_AUDIENCE:healthcare-mcp-server}
      max-lifetime: ${JWT_MAX_LIFETIME:PT15M}
```

If an operator forgets to inject `DATABASE_PASSWORD` or `OIDC_ISSUER`, Spring Boot fails fast during application startup.

### Environment Profiles
The application provides distinct Spring profiles for safe operations:
- `prod`: Enables structured JSON logs (ECS format), forces HTTPS (`app.security.require-https=true`), disables developer web endpoints, and omits seed data.
- `mtls`: Activates mutual TLS on the public listener (port 8080) and enforces RFC 8705 certificate-bound token validation.
- `local`: Developer defaults for local Docker Postgres and Keycloak. **Must never be activated in production.**

---

## 3. Real-Time Security Monitoring & Alerting

When an AI agent interacts with the server, every access decision updates Prometheus metrics via Micrometer in [`AccessAuditLogger.java`](file:///c:/ws/health-mcp-client/src/main/java/io/github/rahulrajsonu/mcpsecurity/security/AccessAuditLogger.java#L45-L49):

```java
meters.counter("clinical.patient.access",
        "outcome", outcome.name(),
        "purpose", context.purpose().name(),
        "category", category.name()).increment();
```

These counters are exposed strictly on the internal management port (`:8081/actuator/prometheus`) and ingested by Prometheus.

### Recommended PromQL Alert Rules

#### Alert 1: Denial Spike (Possible Prompt Injection Loop or Enumeration)
A sudden spike in access denials indicates an AI agent caught in a prompt injection loop, attempting to brute-force patient IDs, or using an expired token.
```promql
alert: HighAccessDenialRate
expr: sum(rate(clinical_patient_access_total{outcome="DENIED"}[5m])) > 10
for: 2m
labels:
  severity: warning
annotations:
  summary: "Elevated access denials detected on MCP Server"
  description: "More than 10 tool call denials per second observed over 5m. Possible agent prompt injection loop or credential misconfiguration."
```

#### Alert 2: Break-Glass Emergency Access Invocation
Emergency access bypasses clinician-patient assignment checks. Every occurrence must be immediately reviewed by compliance officers.
```promql
alert: BreakGlassAccessTriggered
expr: increase(clinical_patient_access_total{purpose="EMERGENCY",outcome="ALLOWED"}[1m]) > 0
for: 0m
labels:
  severity: high
annotations:
  summary: "Emergency Break-Glass access utilized"
  description: "A clinician invoked break-glass emergency read. Justification review required."
```

#### Alert 3: Fail-Closed Audit Store Error
If the audit database is unresponsive, all authorized reads are blocked (fail-closed).
```promql
alert: AuditWriteFailureSpike
expr: sum(rate(clinical_patient_access_total{outcome="ERROR"}[5m])) > 0
for: 1m
labels:
  severity: critical
annotations:
  summary: "Audit store unavailable; all patient data reads blocked"
  description: "The audit repository cannot write access events. System is failing closed."
```

---

## 4. Incident Response Playbook for AI Tools

### Scenario A: Investigating a Break-Glass Emergency Read
**Trigger:** SIEM receives a `BreakGlassAccessTriggered` alert or a `WARN` audit log line:
```text
WARN AUDIT.patient-access -- patient_access outcome=ALLOWED subject=dr-ada tenant=hospital-A patient=patient-500 purpose=EMERGENCY category=PATIENT_SUMMARY break_glass=true justification_chars=48
```

**Step-by-step Triage:**
1. **Assume Compliance Role:** Authenticate an incident responder with a token carrying the `audit.read` scope.
2. **Retrieve Full Justification:** Invoke `listBreakGlassEvents(limit=10)` via MCP or query the database:
   ```sql
   SELECT occurred_at, subject, patient_id, category, justification
   FROM access_events
   WHERE break_glass = true AND occurred_at >= NOW() - INTERVAL '1 hour';
   ```
3. **Verify Clinical Context:** Confirm with Emergency Department logs whether the target patient was physically admitted under emergency care at the timestamp of the read.
4. **Determine Intent:**
   - If legitimate: Document emergency review and sign off.
   - If unauthorized: Escalate as an insider threat or compromised token, revoke the clinician's Keycloak session, and initiate HIPAA breach notification procedures.

---

### Scenario B: Prompt Injection Data Exfiltration Attempt
**Trigger:** High denial alert accompanied by anomalous LLM agent logs.

**Step-by-step Triage:**
1. **Identify Session & Subject:** Check Prometheus labels or audit logs for the user `sub` generating denials.
2. **Review Target Patient IDs:** Inspect denied events:
   ```sql
   SELECT patient_id, count(*)
   FROM access_events
   WHERE outcome = 'DENIED' AND subject = 'doctor-101'
   GROUP BY patient_id;
   ```
   If IDs belong to other hospitals (`patient-600`) or follow an algorithmic sequence (`patient-100`, `patient-101`), the agent has been compromised by prompt injection or automated scraping.
3. **Terminate Session:**
   - Immediately revoke the user's active session in Keycloak / IdP.
   - Block the user's refresh token.
4. **Assess Blast Radius:** Query `access_events` for any `outcome = 'ALLOWED'` rows associated with that `subject` during the incident window. The immutable audit trail proves conclusively what records were disclosed and what remained protected.

---

## 5. Enterprise Deployment Pre-Flight Checklist

Before connecting this MCP server to a live enterprise database, ensure all 10 items are verified:

- [ ] **1. Business Associate Agreement (BAA):** Confirmed active BAA with the cloud LLM provider (OpenAI, Anthropic, Google) with zero data retention for training.
- [ ] **2. Agent Host Security:** Claude Desktop, IDE extensions, or agent runners are managed on enterprise-enrolled, encrypted endpoints.
- [ ] **3. User-Delegated Identity:** Tokens are minted per clinician via OIDC (PKCE or Device Code grant); no shared service account exists.
- [ ] **4. Short-Lived Tokens:** `JWT_MAX_LIFETIME` enforced to $\le 15$ minutes; IdP session lifetimes tuned accordingly.
- [ ] **5. Ingress TLS Hardening:** Ingress controller terminates TLS, strips and overwrites `X-Forwarded-Proto`, and enforces WAF rate limits.
- [ ] **6. Port Segregation:** Ingress routes only port `8080`; internal management port `8081` is firewalled from external traffic.
- [ ] **7. Database Least Privilege:** PostgreSQL running with separate migration owner and `healthcare_app` runtime user granted only `SELECT` and `INSERT`.
- [ ] **8. Row-Level Security Enforced:** Migrations `V4` and `V6` applied with `FORCE ROW LEVEL SECURITY`.
- [ ] **9. Append-Only Audit Trail:** `access_events` table verified to reject `UPDATE` and `DELETE` queries from application role.
- [ ] **10. SIEM Alerting Active:** Alerts configured for denial spikes, break-glass usage, and audit store connectivity failures.

---

## 6. Hands-On Lab: Cloud-IAM Live Verification

To connect this repository to a real, live Keycloak Identity Provider in the cloud and interact with it from **Claude Desktop**, follow the step-by-step hands-on guide:

👉 **[Follow the Hands-On Cloud-IAM & Claude Desktop Guide](../docs/cloud-iam-guide.md)**

This guide walks you through:
1. Creating a free Keycloak realm on Cloud-IAM.
2. Configuring the 5 custom scopes and token claims (`tenant_id`, `aud`).
3. Running `scripts/device-login.js` to sign in through a real browser.
4. Testing 16 real-world authorization scenarios through Claude Desktop.

---

[⬅️ Back to Curriculum Overview](README.md)
