# Module 04: Contextual Authorization, Scopes & Break-Glass Workflows

> **Level:** Application Security & Policy Enforcement | **Estimated Reading Time:** 30 mins  
> **Prerequisites:** Module 01, Module 03, understanding of RBAC, ABAC, and ReBAC concepts.  
> **Navigation:** [⬅️ Module 03: Token Binding & Authentication](03-authentication-and-token-binding.md) | [➡️ Module 05: Data-Tier Isolation & PostgreSQL RLS](05-data-tier-isolation-and-row-level-security.md)

---

## 1. The Vulnerability of Monolithic Scopes in AI Tooling

In traditional web applications, developers frequently bundle permissions into coarse scopes like `user:read`, `api:access`, or `admin`.

When an autonomous AI agent is given a token with broad scopes:
- **Excessive Agency ([OWASP LLM06](https://owasp.org/www-project-top-10-for-large-language-model-applications/)):** An agent instructed to "check the patient's room assignment" might autonomously query psychiatric progress notes, active medication dosages, or audit trails if all are gated by a single `read` scope.
- **Prompt Injection Amplification:** An attacker who exploits prompt injection in a routine summary tool gains immediate lateral access to the most sensitive data domains in the system.

To secure AI tools, we implement **Granular Scope Partitioning**, **Relationship-Based Access Control (ReBAC)**, and **Purpose-Based Access Control (PBAC)**.

---

## 2. Granular Scope Partitioning

In this repository, access is divided across **five distinct, orthogonal scopes**:

```
                              ┌──────────────────────┐
                              │ Clinician OAuth JWT  │
                              └──────────┬───────────┘
                                         │
       ┌──────────────────┬──────────────┴─────┬──────────────────┐
       ▼                  ▼                    ▼                  ▼
[patient.read]   [medication.read]       [notes.read]   [patient.break_glass]
       │                  │                    │                  │
       │                  ▼                    │                  │
       │         getPatientMedications         │                  │
       │         (Requires BOTH scopes)        ▼                  │
       ▼                                getClinicalNotes          ▼
getPatientSummary                      (Requires BOTH scopes)  Bypasses Assignment
listMyPatients                                                 (Needs 15-500 char reason)
```

| Scope | Protected Data Domain | Tool Requiring Scope | Why It Is Separated |
|---|---|---|---|
| `patient.read` | Patient demographics, roster | `getPatientSummary`, `listMyPatients` | Base read permission; exposes non-sensitive summary info. |
| `medication.read` | Prescription history, dosage | `getPatientMedications` | Protects medical history from agents that only need demographics. |
| `notes.read` | Clinical progress notes, observations | `getClinicalNotes` | Highly confidential clinician text notes. Highly sensitive. |
| `patient.break_glass` | Emergency unassigned read | Used with `purpose=EMERGENCY` | Bypasses assignment check during critical life-safety emergencies. |
| `audit.read` | Tamper-evident audit logs | `getAccessHistory`, `listBreakGlassEvents` | Segregation of duties: clinicians cannot review or tamper with logs. |

---

## 3. The Relationship-Based Check (ReBAC): Active Assignments

Holding `patient.read` does **not** grant access to all patients in a hospital. Under HIPAA Minimum Necessary rules (§ 164.502(b)), a clinician must have a legitimate, active treatment relationship with that specific patient.

### Assignment Lifecycle
Assignments are tracked in the `patient_assignments` table (defined in [`V1__create_clinical_tables.sql`](file:///c:/ws/health-mcp-client/src/main/resources/db/migration/V1__create_clinical_tables.sql#L16-L39)):
- **Status:** Must be `ACTIVE`. If `SUSPENDED`, `REVOKED`, or `EXPIRED`, access is rejected.
- **Time Window:** Current timestamp must fall between `valid_from` and `valid_until`.

In [`PatientAccessPolicy.java`](file:///c:/ws/health-mcp-client/src/main/java/io/github/rahulrajsonu/mcpsecurity/security/PatientAccessPolicy.java#L77-L90):

```java
private void requireActiveAssignment(
        ClinicalPrincipal principal,
        String patientId) {

    boolean assigned = assignments.hasActiveAssignment(
            principal.tenantId(),
            principal.subject(),
            patientId
    );

    if (!assigned) {
        // Deny access without revealing patient status
        throw new PatientAccessDeniedException();
    }
}
```

---

## 4. Break-Glass: Emergency Access Engineering

In emergency medicine, strict assignment checks can be lethal. If an unconscious patient arrives in the Emergency Department, the attending trauma physician is not yet assigned in the EHR.

**Break-Glass** allows emergency access while preserving auditability and compliance.

### The Six Break-Glass Constraints
Under [`PatientAccessPolicy.java`](file:///c:/ws/health-mcp-client/src/main/java/io/github/rahulrajsonu/mcpsecurity/security/PatientAccessPolicy.java#L51-L56) and [`requireBreakGlass`](file:///c:/ws/health-mcp-client/src/main/java/io/github/rahulrajsonu/mcpsecurity/security/PatientAccessPolicy.java#L97-L114):

1. **Explicit Scope Required:** The token must carry the dedicated `patient.break_glass` scope.
2. **Explicit Purpose:** The tool call must declare `purpose = "EMERGENCY"`.
3. **Mandatory Clinical Justification:** The caller must supply a free-text `justification` between **15 and 500 characters** (e.g., *"Unconscious patient in ED, no prior assignment"*). Blank or short reasons (`"emergency"`, `"asdf"`) are rejected.
4. **Data Category Restrictions:** Break-glass is permitted for `PATIENT_SUMMARY` and `MEDICATIONS`. It is **strictly refused** for `CLINICAL_NOTES`:
   ```java
   // In DataCategory.java
   CLINICAL_NOTES("notes.read", false) // breakGlassAllowed = false
   ```
   *Why? Progress notes contain subjective narratives and psychiatric notes that are rarely required for acute resuscitation.*
5. **Elevated Logging:** Emitted at `WARN` level to a dedicated audit log and incremented on Prometheus metric counters.
6. **Zero Tenant Crossing:** Break-glass **never** bypasses tenant isolation. A doctor at Hospital A can break glass on unassigned patients in Hospital A, but never on patients in Hospital B.

---

## 5. Walkthrough: The Complete Authorization Flow

Inspect [`PatientAccessPolicy.java`](file:///c:/ws/health-mcp-client/src/main/java/io/github/rahulrajsonu/mcpsecurity/security/PatientAccessPolicy.java#L37-L60):

```java
public void requireReadAccess(
        ClinicalAccessContext context,
        String patientId,
        DataCategory category) {

    ClinicalPrincipal principal = context.principal();

    // 1. Verify base read scope AND category scope
    if (!principal.hasScope(READ_SCOPE)
            || !principal.hasScope(category.requiredScope())) {
        throw new PatientAccessDeniedException();
    }

    // 2. Evaluate purpose-based branch
    switch (context.purpose()) {
        case TREATMENT -> requireActiveAssignment(principal, patientId);
        case EMERGENCY -> {
            if (!category.breakGlassAllowed()) {
                throw new PatientAccessDeniedException();
            }
            requireBreakGlass(context);
        }
        default -> throw new PatientAccessDeniedException();
    }
}
```

Notice the strict default-deny: any purpose other than `TREATMENT` or `EMERGENCY` throws `PatientAccessDeniedException`.

---

## 6. Proving It: The Security Decision Matrix

The integration test [`ClinicalToolsEndToEndIT.java`](file:///c:/ws/health-mcp-client/src/test/java/io/github/rahulrajsonu/mcpsecurity/ClinicalToolsEndToEndIT.java) verifies every row of the authorization matrix against a real PostgreSQL database:

| Caller | Held Scopes | Tool Called | Target Patient | Purpose | Expected Outcome | Why? |
|---|---|---|---|---|---|---|
| `doctor-101` | `patient.read` | `getPatientSummary` | `patient-400` | `TREATMENT` | **ALLOWED** | Active assignment exists in Hospital A. |
| `doctor-101` | `patient.read` | `getPatientSummary` | `patient-500` | `TREATMENT` | **DENIED** | Assignment was `REVOKED`. |
| `doctor-101` | `patient.read` | `getPatientMedications` | `patient-400` | `TREATMENT` | **DENIED** | Missing `medication.read` scope. |
| `doctor-101` | `+ medication.read` | `getPatientMedications` | `patient-400` | `TREATMENT` | **ALLOWED** | Has both scopes and active assignment. |
| `doctor-101` | `+ medication.read, patient.break_glass` | `getPatientMedications` | `patient-500` | `EMERGENCY` + Justification | **ALLOWED** | Break-glass succeeds on own tenant. Audited as `WARN`. |
| `doctor-101` | `+ notes.read, patient.break_glass` | `getClinicalNotes` | `patient-500` | `EMERGENCY` + Justification | **DENIED** | **Policy rule:** Break-glass never unlocks clinical notes. |
| `doctor-101` | `+ medication.read, patient.break_glass` | `getPatientMedications` | `patient-600` | `EMERGENCY` + Justification | **DENIED** | Belongs to `hospital-B` (RLS blocks cross-tenant access). |
| `doctor-101` | `patient.read` | `getAccessHistory` | `patient-400` | `TREATMENT` | **DENIED** | Clinicians do not hold `audit.read`. |
| `compliance-1`| `audit.read` | `listBreakGlassEvents`| `*` | `TREATMENT` | **ALLOWED** | Audit officer can review justifications and emergency reads. |

---

## 7. Hands-On Lab: Test the Policy Rules

Execute the authorization policy unit tests:
```bash
./mvnw test -Dtest=PatientAccessPolicyTest
```

Look at the test assertions:
- Verify that a 14-character justification fails (`MIN_JUSTIFICATION_CHARS = 15`).
- Verify that a 501-character justification fails (`MAX_JUSTIFICATION_CHARS = 500`).
- Verify that emergency access for `CLINICAL_NOTES` always throws `PatientAccessDeniedException`.

---

[➡️ Proceed to Module 05: Data-Tier Isolation & PostgreSQL RLS](05-data-tier-isolation-and-row-level-security.md)
