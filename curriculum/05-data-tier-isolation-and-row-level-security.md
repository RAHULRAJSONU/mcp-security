# Module 05: Data-Tier Multi-Tenancy & PostgreSQL Row-Level Security

> **Level:** Database Security & Architecture | **Estimated Reading Time:** 30 mins  
> **Prerequisites:** Module 01, Module 04, intermediate knowledge of SQL and database transactions.  
> **Navigation:** [⬅️ Module 04: Contextual Authorization & Break-Glass](04-contextual-authorization-and-breakglass.md) | [➡️ Module 06: Fail-Closed Auditing & Non-Repudiation](06-fail-closed-auditing-and-non-repudiation.md)

---

## 1. The Multi-Tenant Threat in AI Tool Calling

Multi-tenant SaaS architectures store data for multiple organizations (e.g., Hospital A, Hospital B, Clinic C) within the same database schema.

In traditional software, developers prevent cross-tenant data leaks by appending `WHERE tenant_id = :currentTenant` to every SQL query.

### Why Application-Level Tenant Filtering Fails for AI Tools
1. **Developer Fallibility:** In a complex enterprise schema with dozens of tables, subqueries, and JPA entity graphs, a developer eventually forgets a `WHERE tenant_id` clause.
2. **LLM Hallucination & Prompt Injection:** An AI agent might generate or pass an identifier it observed in another conversation (`patient-600` belonging to Hospital B).
3. **ORM Bypass & Native Queries:** Complex reporting or analytics queries often bypass standard ORM filters.
4. **SQL Injection:** If user input reaches dynamic SQL, `WHERE tenant_id = 'A' OR '1'='1'` obliterates the application filter.

### The Solution: Database Kernel Enforcement
To achieve true defense-in-depth, tenant isolation must be enforced by the **PostgreSQL database kernel itself** using **Row-Level Security (RLS)**. Even if an application bug executes `SELECT * FROM patients`, the database engine physically prevents the query from seeing rows outside the caller's tenant.

---

## 2. PostgreSQL Row-Level Security (RLS) Architecture

Let's inspect how RLS is configured in migration [`V4__enable_tenant_rls.sql`](file:///c:/ws/health-mcp-client/src/main/resources/db/migration/V4__enable_tenant_rls.sql):

```sql
-- 1. Enable RLS on the table
ALTER TABLE patients ENABLE ROW LEVEL SECURITY;

-- 2. FORCE RLS even for table owners and superusers
ALTER TABLE patients FORCE ROW LEVEL SECURITY;

-- 3. Define the tenant isolation policy for the application role
CREATE POLICY patient_tenant_isolation
ON patients
FOR ALL
TO healthcare_app
USING (
    tenant_id = current_setting('app.tenant_id', true)
)
WITH CHECK (
    tenant_id = current_setting('app.tenant_id', true)
);
```

### Critical RLS Mechanics
- `ENABLE ROW LEVEL SECURITY`: Activates policy checks for queries executed by normal roles.
- `FORCE ROW LEVEL SECURITY`: **Crucial security setting.** By default, PostgreSQL exempts table owners from RLS. `FORCE` guarantees that even if the connection runs as the table owner, RLS policies are strictly applied.
- `USING (...)`: Evaluated on `SELECT`, `UPDATE`, and `DELETE`. Rows where this condition evaluates to `false` or `NULL` simply do not exist from the query's perspective.
- `WITH CHECK (...)`: Evaluated on `INSERT` and `UPDATE`. Prevents the application from inserting or mutating a row to belong to another tenant.
- `current_setting('app.tenant_id', true)`: Reads a custom session setting. The second parameter (`true`) means **missing_ok**: if the variable has not been set, PostgreSQL returns `NULL` rather than throwing an error. Because `tenant_id = NULL` evaluates to false, an uninitialized session sees **zero rows**.

---

## 3. The Transactional Bridge: `TenantScopedExecutor`

How does the Java application tell PostgreSQL which tenant is executing the current query without contaminating other requests?

### The HikariCP Connection Pool Hazard
In a Spring Boot application, database connections are pooled (via HikariCP). If an HTTP request sets a session variable on a database connection and returns it to the pool, the next request might reuse that connection and inherit the previous tenant's identity!

### The Defense: Transaction-Local Settings
Inspect [`TenantScopedExecutor.java`](file:///c:/ws/health-mcp-client/src/main/java/io/github/rahulrajsonu/mcpsecurity/security/TenantScopedExecutor.java#L18-L45):

```java
@Component
@RequiredArgsConstructor
public class TenantScopedExecutor {

    private final EntityManager entityManager;

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public <T> T execute(
            ClinicalPrincipal principal,
            Supplier<T> operation) {

        Objects.requireNonNull(principal);
        Objects.requireNonNull(operation);

        String tenantId = principal.tenantId();
        if (tenantId == null || tenantId.isBlank()) {
            throw new SecurityException("Missing or blank tenant context");
        }

        // Set the PostgreSQL transaction variable
        entityManager.createNativeQuery("""
            SELECT set_config(
                'app.tenant_id',
                :tenantId,
                true
            )
            """)
            .setParameter("tenantId", tenantId)
            .getSingleResult();

        return operation.get();
    }
}
```

### Why This Design is Secure:
1. `set_config('app.tenant_id', :tenantId, true)`: The third parameter (`is_local = true`) instructs PostgreSQL that this setting is **strictly local to the current transaction**. The instant the transaction commits or rolls back, PostgreSQL automatically wipes `app.tenant_id`.
2. `Propagation.REQUIRES_NEW`: Suspends any existing transaction and opens a clean, isolated database transaction. This prevents transaction state leakage across service methods.

---

## 4. Principle of Least Privilege in Database Roles

Many applications connect to the database using the database owner or superuser (`postgres`). If an attacker executes arbitrary SQL, they have full control over the database.

In this repository, we enforce strict role separation:

```
┌──────────────────────────────────────┐     ┌──────────────────────────────────────┐
│ Flyway Migration Owner               │     │ Application Runtime Role             │
│ Role: postgres                       │     │ Role: healthcare_app                 │
├──────────────────────────────────────┤     ├──────────────────────────────────────┤
│ - Creates and alters tables          │     │ - Has NO schema alteration rights    │
│ - Enables and forces RLS             │     │ - Has NO table owner privileges      │
│ - Defines RLS security policies      │     │ - Granted ONLY SELECT on data tables │
│ - Provisions database roles          │     │ - Granted SELECT, INSERT on audit    │
│ - Run ONLY during CI/CD migrations   │     │ - Has ZERO UPDATE or DELETE rights   │
└──────────────────────────────────────┘     └──────────────────────────────────────┘
```

Look at [`V6__secure_clinical_data.sql`](file:///c:/ws/health-mcp-client/src/main/resources/db/migration/V6__secure_clinical_data.sql#L36-L37):

```sql
-- Least-privilege grant for runtime application
GRANT SELECT ON medications, clinical_notes TO healthcare_app;
GRANT SELECT, INSERT ON access_events TO healthcare_app;
```

> [!NOTE]
> Notice that `healthcare_app` is **never granted `UPDATE` or `DELETE` on anything**. Even if an attacker achieves SQL injection or breaks into the Spring Boot container, they cannot modify medical history or delete audit records.

---

## 5. Anti-Enumeration & Indistinguishable Refusals

If an attacker (or compromised agent) is trying to discover which patient IDs exist in the system, they will send queries with probe IDs: `patient-100`, `patient-101`, etc.

### The Enumeration Vulnerability
If the application returns different responses:
- `patient-400`: `200 OK` (User's patient)
- `patient-500`: `403 Forbidden: You are not assigned to this patient` (Proves `patient-500` exists in Hospital A!)
- `patient-600`: `403 Forbidden: Cross-tenant access prohibited` (Proves `patient-600` exists in Hospital B!)
- `patient-999`: `404 Not Found: Patient does not exist` (Proves `patient-999` is invalid!)

The attacker can map out the entire patient registry across all hospitals!

### The Hardened Defense: Indistinguishable Denial
In [`SecuredPatientQueryService.java`](file:///c:/ws/health-mcp-client/src/main/java/io/github/rahulrajsonu/mcpsecurity/service/SecuredPatientQueryService.java#L89-L91) and [`PatientAccessPolicy.java`](file:///c:/ws/health-mcp-client/src/main/java/io/github/rahulrajsonu/mcpsecurity/security/PatientAccessPolicy.java#L9-L11):

All refusals return the exact same exception and error message:
```java
throw new PatientAccessDeniedException("Patient access denied");
```

Whether:
1. The patient ID does not exist in the database,
2. The patient belongs to another tenant (and was hidden by RLS),
3. The clinician has no active assignment to the patient, or
4. The caller is missing the required scope,

**The response is identical in HTTP status, payload, and timing.** The caller learns zero information about the database contents.

---

## 6. Proving It: Integration Tests

Inspect [`PatientAccessEndToEndIT.java`](file:///c:/ws/health-mcp-client/src/test/java/io/github/rahulrajsonu/mcpsecurity/PatientAccessEndToEndIT.java#L65-L76):

```java
@Test
void unassignedAndCrossTenantAndUnknownAreIndistinguishable() {
    ClinicalPrincipal p = doctor("hospital-A", "patient.read");

    // 1. Unassigned patient in own hospital
    String unassigned = messageOf(() -> read(p, AccessPurpose.TREATMENT, null, "patient-500"));

    // 2. Patient in another hospital (Hospital B)
    String crossTenant = messageOf(() -> read(p, AccessPurpose.TREATMENT, null, "patient-600"));

    // 3. Fictitious patient that doesn't exist anywhere
    String unknown = messageOf(() -> read(p, AccessPurpose.TREATMENT, null, "patient-does-not-exist"));

    // All three error messages MUST BE 100% IDENTICAL
    assertThat(crossTenant).isEqualTo(unassigned);
    assertThat(unknown).isEqualTo(unassigned);
    assertThat(audit.list).allSatisfy(e -> 
        assertThat(e.getFormattedMessage()).contains("outcome=DENIED"));
}
```

Inspect [`TenantScopedExecutorIT.java`](file:///c:/ws/health-mcp-client/src/test/java/io/github/rahulrajsonu/mcpsecurity/security/TenantScopedExecutorIT.java):
- Proves that querying without setting `app.tenant_id` returns 0 rows.
- Proves that a query scoped to `hospital-A` returns 0 rows for `patient-600` (even with raw `SELECT * FROM patients WHERE id = 'patient-600'`).

---

## 7. Hands-On Lab: Database RLS Exploration

If you have PostgreSQL running locally:
1. Connect using `psql` as the restricted user:
   ```bash
   psql -U healthcare_app -d patient_db
   ```
2. Run a plain query without setting the tenant:
   ```sql
   SELECT * FROM patients;
   ```
   *(Notice: Returns 0 rows! RLS hides everything).*
3. Set the transaction-local tenant to `hospital-A`:
   ```sql
   BEGIN;
   SELECT set_config('app.tenant_id', 'hospital-A', true);
   SELECT id, first_name, tenant_id FROM patients;
   COMMIT;
   ```
   *(Notice: Returns only patients 400 and 500. Patient 600 from hospital-B is invisible).*
4. Try to delete a row:
   ```sql
   DELETE FROM patients WHERE id = 'patient-400';
   ```
   *(Notice: Fails immediately with `ERROR: permission denied for table patients`).*

---

[➡️ Proceed to Module 06: Fail-Closed Auditing & Non-Repudiation](06-fail-closed-auditing-and-non-repudiation.md)
