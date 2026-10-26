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
✅ FAIL-CLOSED PATTERN: "NO AUDIT, NO DATA"   (one database transaction)
[Tool Call] ──► [Agent check] ──► [Read Patient] ──► [Append Audit Row] ──► COMMIT
                                                          │
                       ┌──────────────────────────────────┴──────────────────────────────────┐
                       ▼ COMMIT SUCCEEDS                                                     ▼ ANY STEP FAILS (Disk/Network error)
             [Return PHI to Agent]                                                 [Transaction rolls back]
                                                                                   [ZERO Patient Data Returned]
```

The read and its audit row are written **in the same transaction**. They commit together or not at all, so there is no window in which data was read but no record exists, and no record of a read that was never delivered. It also halves the connection checkouts and commits per call, which matters under load (see [Module 10](10-agent-controls-and-resilience.md)).

### The Code Implementation
Inspect [`SecuredPatientQueryService.java`](file:///c:/ws/health-mcp-client/src/main/java/io/github/rahulrajsonu/mcpsecurity/service/SecuredPatientQueryService.java), method `guarded`:

```java
requireWellFormed(patientId);              // reject malformed ids before any I/O
quota.acquire(context.principal());        // per-agent quota (Module 10)

T result = bulkhead.run(() ->              // load shedding (Module 10)
    tenantExecutor.execute(context.principal(), () -> {   // one tenant-scoped transaction
        agentPolicy.requireActive(context.principal());   // is this agent approved?
        T value = read.get();                             // policy + the read
        auditor.appendAllowed(context, patientId, category);  // MUST succeed, same tx
        return value;
    }));

auditor.logAllowed(context, patientId, category);   // log line and metric, after commit
return result;
```

The failure handling around it:

```java
} catch (PatientAccessDeniedException | ClinicalAccessDeniedException | RateLimitExceededException ex) {
    auditor.denied(context, patientId, category);   // best effort, own transaction
    throw ex;
} catch (ServerBusyException ex) {
    throw ex;                                        // nothing was decided: no audit row
} catch (AuditUnavailableException ex) {
    auditor.failed(context, patientId, category);
    throw ex;
} catch (RuntimeException ex) {
    auditor.failed(context, patientId, category);
    throw new RequestFailedException(ex);            // generic error to the model
}
```

And in [`AccessAuditor.java`](file:///c:/ws/health-mcp-client/src/main/java/io/github/rahulrajsonu/mcpsecurity/service/AccessAuditor.java):

```java
// Runs inside the caller's transaction. A failure aborts the whole call.
public void appendAllowed(ClinicalAccessContext context, String patientId, DataCategory category) {
    try {
        events.append(context.principal().tenantId(), event(context, patientId, category, Outcome.ALLOWED));
    } catch (RuntimeException ex) {
        LOG.error("audit_write_failed outcome=ALLOWED; access refused", ex);
        throw new AuditUnavailableException(ex);   // zero clinical data is returned
    }
}

// After the commit: the log line and the metric. Never the source of truth.
public void logAllowed(ClinicalAccessContext context, String patientId, DataCategory category) {
    logger.record(context, patientId, category, Outcome.ALLOWED);
}
```

> [!NOTE]
> Denied and failed attempts are written in their **own** transaction, best effort: the caller receives nothing either way, and a denial must still be recorded even though the main transaction rolled back. A call refused by load shedding (`server_busy`) writes no row, because no decision was made.

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
    client_id VARCHAR(128),   -- added in V10: which OAuth client (agent) made the call
    actor VARCHAR(256),       -- added in V11: delegation chain from the token's `act` claim

    CONSTRAINT chk_access_event_outcome
        CHECK (outcome IN ('ALLOWED', 'DENIED', 'ERROR'))
);
```

`client_id` and `actor` answer the question the subject alone cannot: *which software* acted for this user, and through whom. `actor` holds the RFC 8693 `act` chain (for example `agent-a>agent-b`), outermost first, capped at five hops. It is **recorded, never trusted**: it grants nothing and is there for investigation. The same two values appear in the audit log line (`client=`, `actor=`).

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

    CallToolResult result = patientTools.getPatientSummary("patient-400", null, null);

    // The tool returns an error result with a generic code and ZERO patient data
    assertFailed(result, "request_failed");
    assertThat(text(result))
            .doesNotContain("patient-400")
            .doesNotContain("Alice")
            .doesNotContain("audit store down");   // no internals either
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
