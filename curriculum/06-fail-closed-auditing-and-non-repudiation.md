# Module 06: Non-Repudiation, Fail-Closed Auditing & Immutable Logs

> **Level:** Enterprise Compliance & Auditability | **Estimated Reading Time:** 25 mins  
> **Prerequisites:** Module 01, Module 05, understanding of database transactions and logging architectures.  
> **Navigation:** [⬅️ Module 05: Data-Tier Isolation & PostgreSQL RLS](05-data-tier-isolation-and-row-level-security.md) | [➡️ Module 07: Privacy by Design & Side Channels](07-privacy-data-minimization-and-side-channels.md)

---

## 1. The Audit Accountability Crisis in AI Agents

When human doctors interact with Electronic Health Record (EHR) systems, they click buttons in a predictable sequence. Every screen view is logged with their session ID.

When an **AI agent** operates on a user's behalf:
- The agent may issue dozens of tool invocations per second across multiple data stores.
- The user may not even be aware of the specific internal tool calls the agent made to answer a prompt like: *"Give me a summary of my morning patients."*
- If an agent's access to sensitive records is not immutably recorded, compliance with HIPAA (§ 164.312(b) Audit Controls) is impossible.
- If an audit failure occurs silently, unauthorized reads can occur without any evidence left behind.

---

## 2. The "No Audit, No Data" Paradigm: Fail-Closed Auditing

Many cloud architectures implement audit logging as a **fail-open asynchronous pattern**:
```
❌ FAIL-OPEN ANTI-PATTERN (VULNERABLE)
[Tool Call] ──► [Query Database] ──► [Return PHI to Agent]
                       │
                       └─► [Async Fire-and-Forget / Kafka Queue]
                           (If Kafka is down or queue is full, PHI is ALREADY in the
                            agent's hands, but no audit record will ever exist!)
```

In healthcare and high-assurance security, this is unacceptable. Once PHI reaches the AI agent and the model provider, **it cannot be recalled**.

### The Hardened Fail-Closed Pattern
In this repository, auditing is **fail-closed**:
```
✅ FAIL-CLOSED PATTERN: "NO AUDIT, NO DATA"
[Tool Call] ──► [Read Patient from DB] ──► [Append Durable Audit Record to DB]
                                                          │
                       ┌──────────────────────────────────┴──────────────────────────────────┐
                       ▼ SUCCESS                                                             ▼ FAILURE (Disk/Network error)
             [Return PHI to Agent]                                                 [Throw AuditUnavailableException]
                                                                                   [ZERO Patient Data Returned]
```

### The Code Implementation
Inspect [`SecuredPatientQueryService.java`](file:///c:/ws/health-mcp-client/src/main/java/io/github/rahulrajsonu/mcpsecurity/service/SecuredPatientQueryService.java#L78-L95):

```java
private <T> T guarded(
        ClinicalAccessContext context,
        String patientId,
        DataCategory category,
        Supplier<T> read) {

    try {
        // 1. Fetch data inside tenant-isolated transaction
        T result = tenantExecutor.execute(context.principal(), read);

        // 2. MUST succeed BEFORE data leaves. Failure here FAILS the entire request!
        auditor.allowed(context, patientId, category);

        // 3. Only return data once audit record is durably stored
        return result;

    } catch (PatientAccessDeniedException | ClinicalAccessDeniedException ex) {
        // Denials are best-effort: caller receives nothing anyway
        auditor.denied(context, patientId, category);
        throw ex;
    } catch (AuditUnavailableException ex) {
        auditor.failed(context, patientId, category);
        throw ex;
    }
}
```

And in [`AccessAuditor.java`](file:///c:/ws/health-mcp-client/src/main/java/io/github/rahulrajsonu/mcpsecurity/service/AccessAuditor.java#L41-L50):

```java
public void allowed(ClinicalAccessContext context, String patientId, DataCategory category) {
    try {
        store(context, patientId, category, Outcome.ALLOWED);
    } catch (RuntimeException ex) {
        LOG.error("audit_write_failed outcome=ALLOWED; access refused", ex);
        // Rethrowing ensures zero clinical data is returned
        throw new AuditUnavailableException(ex);
    }
    logger.record(context, patientId, category, Outcome.ALLOWED);
}
```

---

## 3. The Immutable, Append-Only Database Table

Audit logs cannot be trusted if an attacker, application bug, or malicious insider can edit or delete historical rows.

### The `access_events` Schema
Inspect migration [`V5__create_clinical_data.sql`](file:///c:/ws/health-mcp-client/src/main/resources/db/migration/V5__create_clinical_data.sql#L37-L51):

```sql
CREATE TABLE access_events (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    subject VARCHAR(128) NOT NULL,
    patient_id VARCHAR(128) NOT NULL,
    purpose VARCHAR(40) NOT NULL,
    category VARCHAR(40) NOT NULL,
    outcome VARCHAR(10) NOT NULL,
    break_glass BOOLEAN NOT NULL,
    justification VARCHAR(500),

    CONSTRAINT chk_access_event_outcome
        CHECK (outcome IN ('ALLOWED', 'DENIED', 'ERROR'))
);
```

> [!IMPORTANT]
> **Why is there no FOREIGN KEY on `patient_id`?**  
> If an attacker queries a non-existent ID (`patient-999`) or attempts to access a cross-tenant patient (`patient-600`), a foreign key constraint would fail and prevent recording the intrusion! The audit table must record all access attempts, even against bogus or forbidden targets.

### Enforcing Append-Only at the Database Privilege Level
In [`V6__secure_clinical_data.sql`](file:///c:/ws/health-mcp-client/src/main/resources/db/migration/V6__secure_clinical_data.sql#L28-L37):

```sql
-- Append-only policy: application may insert events for its tenant
CREATE POLICY access_event_append
ON access_events
FOR INSERT
TO healthcare_app
WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

-- Privilege grant: ONLY SELECT and INSERT. NO UPDATE. NO DELETE.
GRANT SELECT, INSERT ON access_events TO healthcare_app;
```

Even if an attacker gains arbitrary SQL execution through the Spring Boot application, **PostgreSQL physically rejects any `UPDATE` or `DELETE` statement on `access_events`**.

---

## 4. Segregation of Duties for Audit Inspection

In a secure enterprise, clinicians should not review the audit logs of their colleagues, nor should they be able to monitor whether compliance officers are investigating their own access patterns.

### Dedicated Scope: `audit.read`
Access to audit tools is gated by a separate scope held only by compliance and privacy officers:
- `getAccessHistory(patientId, limit)`
- `listBreakGlassEvents(limit)`

Inspect [`AuditMcpTools.java`](file:///c:/ws/health-mcp-client/src/main/java/io/github/rahulrajsonu/mcpsecurity/mcp/tool/AuditMcpTools.java):
1. **Scope Check:** Verified by `PatientAccessPolicy.requireAuditAccess(principal)`. Standard clinicians holding `patient.read` get `403 Access Denied`.
2. **Auditing the Auditors:** Reading the audit trail is **itself an audited event**:
   ```java
   public List<AccessEvent> getAccessHistory(ClinicalAccessContext context, String patientId, Integer limit) {
       return guarded(context, patientId, DataCategory.ACCESS_AUDIT,
               () -> auditQueryService.historyFor(context, patientId, limit));
   }
   ```
3. **Tenant-Isolation for Auditors:** PostgreSQL RLS ensures an audit officer at `hospital-A` cannot query or observe audit logs belonging to `hospital-B`.

---

## 5. Proving It: Integration Tests

### 1. Proving Database-Enforced Append-Only: `AppendOnlyAuditIT.java`
Inspect [`AppendOnlyAuditIT.java`](file:///c:/ws/health-mcp-client/src/test/java/io/github/rahulrajsonu/mcpsecurity/AppendOnlyAuditIT.java#L41-L69):

```java
@Test
void theApplicationRoleCannotRewriteHistory() {
    // Attempting an UPDATE query throws DataAccessException
    assertThatThrownBy(() -> executor.execute(HOSPITAL_A,
            () -> jdbc.sql("UPDATE access_events SET outcome = 'ALLOWED'").update()))
            .isInstanceOf(DataAccessException.class);

    // Attempting a DELETE query throws DataAccessException
    assertThatThrownBy(() -> executor.execute(HOSPITAL_A,
            () -> jdbc.sql("DELETE FROM access_events").update()))
            .isInstanceOf(DataAccessException.class);
}

@Test
void theApplicationRoleCannotWriteEventsForAnotherTenant() {
    // Attempting to insert an event for hospital-B while scoped to hospital-A fails RLS
    assertThatThrownBy(() -> executor.execute(HOSPITAL_A, () -> insert("hospital-B")))
            .isInstanceOf(DataAccessException.class);
}
```

### 2. Proving Fail-Closed Behavior: `AuditFailClosedIT.java`
Inspect [`AuditFailClosedIT.java`](file:///c:/ws/health-mcp-client/src/test/java/io/github/rahulrajsonu/mcpsecurity/AuditFailClosedIT.java#L36-L51):

```java
@Test
void anAllowedReadIsRefusedWhenTheAuditWriteFails() {
    // Simulate audit database failure
    doThrow(new IllegalStateException("audit store down")).when(events).append(any(), any());

    loginAsDoctor();

    // Invoking the tool throws AuditUnavailableException and returns ZERO patient data
    assertThatThrownBy(() -> patientTools.getPatientSummary("patient-400", null, null))
            .isInstanceOf(AuditUnavailableException.class)
            // Asserts error message does NOT leak patient data
            .hasMessageNotContaining("patient-400")
            .hasMessageNotContaining("Alice");
}
```

---

## 6. Hands-On Lab: Test Fail-Closed Auditing

Run the fail-closed and append-only integration tests:
```bash
./mvnw test -Dtest=AppendOnlyAuditIT,AuditFailClosedIT
```

Review how the assertions verify:
1. `healthcare_app` cannot rewrite history.
2. An exception during audit logging completely halts data delivery to the caller.

---

[➡️ Proceed to Module 07: Privacy by Design & Side Channels](07-privacy-data-minimization-and-side-channels.md)
