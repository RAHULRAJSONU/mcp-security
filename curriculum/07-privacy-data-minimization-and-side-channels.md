# Module 07: Privacy by Design, Data Minimization & Side-Channel Leaks

> **Level:** Privacy Engineering & Application Hardening | **Estimated Reading Time:** 25 mins  
> **Prerequisites:** Module 01, Module 06, understanding of logging frameworks, CWE vulnerabilities, and HIPAA Privacy rules.  
> **Navigation:** [⬅️ Module 06: Fail-Closed Auditing & Non-Repudiation](06-fail-closed-auditing-and-non-repudiation.md) | [➡️ Module 08: Automated Security Testing Harness](08-automated-security-verification.md)

---

## 1. The Proliferation of AI Side Channels

When securing traditional APIs, engineers focus primarily on the HTTP response payload.

In an **AI Tool / MCP environment**, data flows across multiple side channels that are routinely ingested by third parties:

```
┌────────────────────────────────────────────────────────────────────────┐
│ The MCP Server Runtime                                                 │
│                                                                        │
│  [Primary Channel]                                                     │
│   Tool JSON-RPC Output ────────► AI Agent Context ────► LLM Provider   │
│                                                                        │
│  [Side Channel 1: Application Logs]                                    │
│   SLF4J / Logback stdout ──────► CloudWatch / Datadog / Splunk         │
│                                                                        │
│  [Side Channel 2: Error Responses]                                     │
│   Unhandled SQL / DB Errors ───► AI Prompt Context (Model reads error) │
│                                                                        │
│  [Side Channel 3: Metrics & Telemetry]                                 │
│   Prometheus Counter Labels ───► Public / Internal Grafana Dashboards  │
│                                                                        │
│  [Side Channel 4: Local Disk Caches]                                   │
│   HTTP Response Caches ────────► Developer / Host Temp Directories     │
└────────────────────────────────────────────────────────────────────────┘
```

If Protected Health Information (PHI) or Personally Identifiable Information (PII) enters **any** of these side channels, an unauthorized disclosure has occurred.

---

## 2. Principle of Data Minimization (HIPAA § 164.502(b))

Under data minimization rules, an application must expose only the minimum necessary information required for the agent to accomplish its task.

### Example: `Patient` vs `PatientSummary`
Consider the database entity [`Patient.java`](file:///c:/ws/health-mcp-client/src/main/java/io/github/rahulrajsonu/mcpsecurity/mcp/domain/Patient.java):
```java
public record Patient(
        String id,
        String tenantId,
        String medicalRecordNumber,  // High-value identifier
        String firstName,
        String lastName,
        LocalDate dateOfBirth
) { ... }
```

When an agent calls `getPatientSummary`, what should it receive? Does the LLM need the patient's Medical Record Number (MRN) to answer clinical questions? **No.**

Now look at [`PatientSummary.java`](file:///c:/ws/health-mcp-client/src/main/java/io/github/rahulrajsonu/mcpsecurity/mcp/domain/PatientSummary.java#L10-L21):
```java
/**
 * The minimum needed to confirm which patient this is: an internal id, a name
 * and a date of birth (two identifiers). The medical record number is not
 * returned, because nothing the agent does needs it.
 */
public record PatientSummary(
        String patientId,
        String displayName,
        LocalDate dateOfBirth
) {
    public static PatientSummary from(Patient patient) {
        return new PatientSummary(
                patient.id(),
                patient.firstName() + " " + patient.lastName(),
                patient.dateOfBirth()
        );
    }
}
```
By dropping `medicalRecordNumber` at the domain boundary, we ensure the agent cannot leak or exfiltrate it.

---

## 3. Defending Object Serialization: Redacted `toString()`

In modern Java, `record` types automatically generate a `toString()` method that prints every record component:
```text
Patient[id=patient-400, tenantId=hospital-A, medicalRecordNumber=MRN-A-400, firstName=Alice, lastName=Smith, dateOfBirth=1985-04-12]
```

### The Accidental Disclosure Trap
A developer debugging an issue writes:
```java
LOG.debug("Successfully fetched patient: {}", patient);
```
Or a Spring framework filter logs request/response payloads in debug mode. Immediately, unencrypted patient names, dates of birth, and MRNs are streamed into centralized log aggregators.

### The Defense: Explicit Redaction
Every domain record in this repository explicitly overrides `toString()`:

In [`Patient.java`](file:///c:/ws/health-mcp-client/src/main/java/io/github/rahulrajsonu/mcpsecurity/mcp/domain/Patient.java#L23-L27):
```java
/** Records print every field; this one holds direct identifiers, so it must never reach a log. */
@Override
public String toString() {
    return "Patient[id=" + id + ", identifiers redacted]";
}
```

In [`ClinicalNote.java`](file:///c:/ws/health-mcp-client/src/main/java/io/github/rahulrajsonu/mcpsecurity/mcp/domain/ClinicalNote.java#L12-L15):
```java
@Override
public String toString() {
    return "ClinicalNote[noteId=" + noteId + ", body redacted]";
}
```

In [`PatientSummary.java`](file:///c:/ws/health-mcp-client/src/main/java/io/github/rahulrajsonu/mcpsecurity/mcp/domain/PatientSummary.java#L23-L26):
```java
@Override
public String toString() {
    return "PatientSummary[patientId=" + patientId + ", identifiers redacted]";
}
```

Even if root logging is set to `TRACE`, logs will only ever record `[identifiers redacted]`.

---

## 4. Free-Text Justification Sanitization & Length-Only Logging

When invoking break-glass emergency access, clinicians provide a free-text justification:
> *"Patient John Doe in room 402 collapsed with suspected acute myocardial infarction."*

This justification text **is itself PHI**. If written to application logs, it leaks patient health data.

### The Dual Storage Strategy
1. **The Database:** The full justification text is stored in the access-controlled, tenant-isolated `access_events` table (for compliance officers with `audit.read`).
2. **The Application Log:** The logger records **only the character count**, never the raw text!

Look at [`AccessAuditLogger.java`](file:///c:/ws/health-mcp-client/src/main/java/io/github/rahulrajsonu/mcpsecurity/security/AccessAuditLogger.java#L50-L69):

```java
String line = "patient_access outcome={} subject={} tenant={} patient={} purpose={} category={} break_glass={} justification_chars={}";
Object[] fields = {
        outcome,
        sanitize(principal.subject()),
        sanitize(principal.tenantId()),
        sanitize(patientId),
        context.purpose(),
        category,
        breakGlass,
        // Log ONLY character length! Never the string content!
        breakGlass && context.justification() != null
                ? context.justification().strip().length()
                : 0
};

if (breakGlass) {
    AUDIT.warn(line, fields);
} else {
    AUDIT.info(line, fields);
}
```

---

## 5. CWE-117: Log Injection / Log Forging Prevention

If user-controlled values (such as `subject`, `tenant_id`, or `patientId`) contain carriage return (`\r`) or newline (`\n`) characters, an attacker can inject fake log entries:
```text
patient-400\n2026-10-25 00:00:00 INFO AUDIT.patient-access -- patient_access outcome=ALLOWED subject=admin ...
```

In [`AccessAuditLogger.java`](file:///c:/ws/health-mcp-client/src/main/java/io/github/rahulrajsonu/mcpsecurity/security/AccessAuditLogger.java#L72-L79), all logged parameters are sanitized:

```java
// Values can be caller-controlled; strip anything that could forge log lines.
static String sanitize(String value) {
    if (value == null) {
        return "-";
    }
    // Replace non-printable and whitespace/newline characters with '?'
    String cleaned = value.replaceAll("[^\\p{Print}]", "?");
    return cleaned.length() > 128 ? cleaned.substring(0, 128) : cleaned;
}
```

---

## 6. Error Masking & Preventing Database Reflection to LLMs

When database errors occur (e.g., constraint violations, type conversion errors, disk failures), database engines often echo the problematic SQL or values in the error message:
```text
org.postgresql.util.PSQLException: ERROR: value too long for type character varying(20): "Patient Alice Smith Diagnosis..."
```

If this raw exception is returned in the tool failure response, the **AI agent reads the error and ingests the raw database contents into its context window**, which it may then disclose to the end user.

In [`SecuredPatientQueryService.java`](file:///c:/ws/health-mcp-client/src/main/java/io/github/rahulrajsonu/mcpsecurity/service/SecuredPatientQueryService.java#L95-L101):

```java
} catch (RuntimeException ex) {
    auditor.failed(context, patientId, category);
    // Detail stays securely in the internal server log.
    LOG.error("request_failed category={}", category, ex);
    // What reaches the caller and the AI model is a fixed, non-leaking message:
    throw new RequestFailedException();
}
```

The caller receives a generic `RequestFailedException` with fixed message `"Request failed"`, preventing any database error reflection.

---

## 7. Proving It: Integration Tests

The integration test [`PhiLogLeakIT.java`](file:///c:/ws/health-mcp-client/src/test/java/io/github/rahulrajsonu/mcpsecurity/PhiLogLeakIT.java) is one of the most comprehensive privacy tests in modern software engineering.

### How `PhiLogLeakIT` Works:
1. Configures the root logger to `DEBUG` level and attaches a Logback `ListAppender` capturing every log event from Spring, Hibernate, HikariCP, and application code.
2. Defines a blacklist of all synthetic PHI seeded in the database:
   ```java
   private static final List<String> PHI = List.of(
           "Alice", "Bob", "Carol",
           "1985-04-12", "1990-07-21", "1978-11-03",
           "MRN-A-400", "MRN-A-500", "MRN-B-600",
           "Lisinopril", "Atorvastatin", "Metformin", "Levothyroxine",
           "blood pressure controlled", "glucose within target",
           JUSTIFICATION);
   ```
3. Exercises every kind of access: allowed read, unassigned denial, emergency break-glass, clinical notes read, and audit query.
4. Asserts that **none** of the blacklisted PHI values appear in **any** captured log line:
   ```java
   for (ILoggingEvent event : captured.list) {
       String message = render(event);
       for (String secret : PHI) {
           assertThat(message)
                   .as("Log line contained PHI [%s]: %s", secret, message)
                   .doesNotContain(secret);
       }
   }
   ```

---

## 8. Hands-On Lab: Verify Domain Redaction

Run the domain redaction tests:
```bash
./mvnw test -Dtest=PhiRedactionTest
```

Review how `PhiRedactionTest` asserts that calling `toString()` on `Patient`, `PatientSummary`, and `ClinicalNote` returns redacted placeholders and contains zero sensitive field values.

---

[➡️ Proceed to Module 08: Automated Security Testing Harness](08-automated-security-verification.md)
