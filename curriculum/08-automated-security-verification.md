# Module 08: Automated Security Testing & Verification Harness

> **Level:** Advanced Testing & Verification | **Estimated Reading Time:** 25 mins  
> **Prerequisites:** Modules 01–07, familiarity with JUnit 5, Mockito, and Testcontainers.  
> **Navigation:** [⬅️ Module 07: Privacy by Design & Side Channels](07-privacy-data-minimization-and-side-channels.md) | [➡️ Module 09: Production Hardening & Playbooks](09-production-hardening-and-threat-playbook.md)

---

## 1. Why Unit Tests Are Not Enough for AI Security

In conventional software development, unit tests mock out external dependencies:
```java
when(patientRepository.findById("patient-400")).thenReturn(Optional.of(patient));
```
While unit tests are valuable for verifying isolated Java branching logic, **they are completely incapable of verifying defense-in-depth security controls**:
- A unit test cannot prove that PostgreSQL Row-Level Security (RLS) drops cross-tenant rows.
- A unit test cannot prove that the `healthcare_app` database user is denied `UPDATE` and `DELETE` privileges.
- A unit test cannot prove that a real TLS handshake rejects a client presenting an untrusted certificate.
- A unit test cannot prove that third-party database drivers (Postgres JDBC, Hibernate) don't log SQL bind parameters containing PHI.

To provide genuine security guarantees, we must construct an **Automated Security Verification Harness** that executes against real database engines, real network sockets, and real logging pipelines.

---

## 2. The Four Tiers of Security Testing

This repository organizes automated verification into **four distinct testing tiers**:

```
┌────────────────────────────────────────────────────────────────────────┐
│ TIER 4: END-TO-END RESILIENCE & PRIVACY LEAK TESTS                     │
│  - PhiLogLeakIT: Captures root DEBUG logs; asserts 0 PHI leaks         │
│  - ClinicalToolsEndToEndIT: Full matrix of scopes, assignments & tools │
├────────────────────────────────────────────────────────────────────────┤
│ TIER 3: DATABASE KERNEL & ACCESS-CONTROL TESTS                         │
│  - AppendOnlyAuditIT: Asserts DB rejects UPDATE/DELETE on audit table  │
│  - TenantScopedExecutorIT: Asserts RLS drops cross-tenant rows in SQL  │
├────────────────────────────────────────────────────────────────────────┤
│ TIER 2: PROTOCOL & WIRE TRANSPORT TESTS                                │
│  - MutualTlsIT: Real TLS handshakes with keytool-generated certs       │
│  - HttpsEnforcementIT: Asserts 403 Forbidden on plain HTTP requests    │
│  - SecurityEndpointsIT: Asserts port separation and hardened headers   │
├────────────────────────────────────────────────────────────────────────┤
│ TIER 1: UNIT LOGIC & POLICY SPECIFICATION TESTS                        │
│  - PatientAccessPolicyTest: Asserts justification lengths, scopes, PBAC│
│  - JwtSecurityConfigTest: Asserts audience and expiration validations  │
│  - PhiRedactionTest: Asserts domain record toString() redactions       │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 3. The Testcontainers PostgreSQL Harness: `AbstractPostgresIT`

To test database permissions and RLS reliably without requiring developers to manually configure local databases, integration tests inherit from [`AbstractPostgresIT.java`](file:///c:/ws/health-mcp-client/src/test/java/io/github/rahulrajsonu/mcpsecurity/AbstractPostgresIT.java).

### How the Harness Works:
1. **Container Initialization:** If Docker is running, Testcontainers starts an ephemeral, pristine PostgreSQL container.
2. **Role Setup:** Executes `test-init-role.sql` to initialize the `healthcare_app` role.
3. **Dynamic Property Injection:**
   ```java
   @DynamicPropertySource
   static void configureDatabase(DynamicPropertyRegistry registry) {
       registry.add("spring.datasource.url", container::getJdbcUrl);
       registry.add("spring.datasource.username", () -> "healthcare_app");
       registry.add("spring.datasource.password", () -> "postgres");
       // Flyway runs as privileged owner
       registry.add("spring.flyway.user", container::getUsername);
       registry.add("spring.flyway.password", container::getPassword);
   }
   ```
4. **Flyway Execution:** Flyway runs migrations `V1` through `V7`, applying RLS policies, table structures, and synthetic seed data.
5. **Least-Privilege Execution:** The Spring application datasource connects **strictly as `healthcare_app`**, ensuring all application queries run under least-privilege database constraints.

---

## 4. Writing Attack Simulations in JUnit

### Attack Simulation 1: Database Privilege Escalation & Log Tampering
Can the application role delete records from `access_events` or alter its own history?

Inspect [`AppendOnlyAuditIT.java`](file:///c:/ws/health-mcp-client/src/test/java/io/github/rahulrajsonu/mcpsecurity/AppendOnlyAuditIT.java#L53-L69):
```java
@Test
void theApplicationRoleCannotRewriteHistory() {
    // Attempt raw SQL UPDATE as healthcare_app
    assertThatThrownBy(() -> executor.execute(HOSPITAL_A,
            () -> jdbc.sql("UPDATE access_events SET outcome = 'ALLOWED'").update()))
            .isInstanceOf(DataAccessException.class);

    // Attempt raw SQL DELETE as healthcare_app
    assertThatThrownBy(() -> executor.execute(HOSPITAL_A,
            () -> jdbc.sql("DELETE FROM access_events").update()))
            .isInstanceOf(DataAccessException.class);
}

@Test
void theApplicationRoleCannotWriteClinicalData() {
    // Attempt raw SQL DELETE on clinical notes
    assertThatThrownBy(() -> executor.execute(HOSPITAL_A,
            () -> jdbc.sql("DELETE FROM clinical_notes").update()))
            .isInstanceOf(DataAccessException.class);
}
```
*Result: The test proves that PostgreSQL throws a `permission denied` exception directly in the database engine.*

---

### Attack Simulation 2: Side-Channel Log Sniffing
Can an attacker inspect server debug logs to extract patient data or justification notes?

Inspect [`PhiLogLeakIT.java`](file:///c:/ws/health-mcp-client/src/test/java/io/github/rahulrajsonu/mcpsecurity/PhiLogLeakIT.java#L52-L107):
```java
@BeforeEach
void capture() {
    root = (Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
    root.setLevel(Level.DEBUG); // Turn logging up to maximum
    captured.start();
    root.addAppender(captured);
}

@Test
void noPhiOrJustificationTextReachesAnyLogLine() {
    loginAs("doctor-101", "patient.read medication.read notes.read patient.break_glass");

    // Exercise all tool endpoints: summaries, notes, medications, break-glass
    patientTools.getPatientSummary("patient-400", null, null);
    patientTools.getPatientMedications("patient-500", "EMERGENCY", JUSTIFICATION);
    // ...

    // Verify NOT ONE forbidden string appears in the captured log lines
    for (ILoggingEvent event : captured.list) {
        String message = render(event);
        for (String secret : PHI) {
            assertThat(message)
                    .as("Log line contained PHI [%s]: %s", secret, message)
                    .doesNotContain(secret);
        }
    }
}
```

---

### Attack Simulation 3: Audit Outage Resilience (Fail-Closed)
What happens if the audit store crashes while processing a valid tool call?

Inspect [`AuditFailClosedIT.java`](file:///c:/ws/health-mcp-client/src/test/java/io/github/rahulrajsonu/mcpsecurity/AuditFailClosedIT.java#L36-L51):
```java
@Test
void anAllowedReadIsRefusedWhenTheAuditWriteFails() {
    // Force audit store to simulate crash / disk failure
    doThrow(new IllegalStateException("audit store down")).when(events).append(any(), any());

    // Call tool with valid authorization
    assertThatThrownBy(() -> patientTools.getPatientSummary("patient-400", null, null))
            .isInstanceOf(AuditUnavailableException.class)
            .hasMessageNotContaining("patient-400")
            .hasMessageNotContaining("Alice");
}
```
*Result: Proves conclusively that patient data is never returned if the audit write fails.*

---

## 5. Continuous Integration (CI/CD) Pipeline Integration

In an automated CI/CD pipeline (GitHub Actions, GitLab CI, Jenkins), security verification tests must run on every commit and pull request:

```yaml
# Example GitHub Actions Workflow snippet
name: Security Verification
on: [push, pull_request]

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up JDK 27
        uses: actions/setup-java@v4
        with:
          java-version: '27'
          distribution: 'temurin'
      - name: Run Full Security Test Suite
        run: ./mvnw verify
```

If a developer accidentally alters an RLS policy, adds an unredacted log line, or changes an error response to echo patient data, the pipeline fails immediately.

---

## 6. Hands-On Lab: Run the Security Verification Suite

Run all unit tests in the suite:
```bash
./mvnw test -Dtest=*Test
```

If Docker is running on your machine, run the complete integration test suite:
```bash
./mvnw verify
```

Observe how:
1. `AbstractPostgresIT` launches PostgreSQL via Testcontainers.
2. Flyway applies the RLS migrations.
3. Every test simulates a specific attack vector (log injection, cross-tenant leak, audit tampering) and asserts that the defense-in-depth gate successfully neutralizes it.

---

[➡️ Proceed to Module 09: Production Hardening & Playbooks](09-production-hardening-and-threat-playbook.md)
