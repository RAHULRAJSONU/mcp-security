# PHI and PII Handling Guide

> This document outlines how Protected Health Information (PHI) under HIPAA (§ 164.502) and Personally Identifiable Information (PII) are guarded throughout this MCP server implementation.
>
> For the comprehensive engineering course chapter on this topic, see:  
> 👉 **[Curriculum Module 07: Privacy by Design, Data Minimization & Side Channels](../curriculum/07-privacy-data-minimization-and-side-channels.md)**

---

## 1. What This Codebase Does

1. **Synthetic Data Only:** All patient identities, MRNs, notes, and medications in seed files and test suites are 100% synthetic. No real patient data ever touches this repository.
2. **Data Minimization at the Boundary:**
   - [`PatientSummary`](../src/main/java/io/github/rahulrajsonu/mcpsecurity/mcp/domain/PatientSummary.java) returns only internal ID, display name, and date of birth.
   - Medical Record Numbers (MRN) and address/contact details are stripped before reaching the AI model context.
3. **Safe Object Serialization:**
   - Custom `toString()` implementations on [`Patient`](../src/main/java/io/github/rahulrajsonu/mcpsecurity/mcp/domain/Patient.java), [`PatientSummary`](../src/main/java/io/github/rahulrajsonu/mcpsecurity/mcp/domain/PatientSummary.java), and [`ClinicalNote`](../src/main/java/io/github/rahulrajsonu/mcpsecurity/mcp/domain/ClinicalNote.java) return redacted placeholders (`identifiers redacted`), preventing accidental logging during framework debug output or uncaught exceptions.
4. **Log Leak Prevention:**
   - Free-text emergency justifications (which may contain PHI entered by clinicians) are stored strictly in the database `access_events` table.
   - The application log records only the character length: `justification_chars=48` ([`AccessAuditLogger.java`](../src/main/java/io/github/rahulrajsonu/mcpsecurity/security/AccessAuditLogger.java)).
   - Sanitization prevents log injection attacks (CWE-117).
5. **Masked Error Responses:**
   - Database errors that might reflect SQL values or schema internals are caught and masked as generic `RequestFailedException` before returning to the AI agent ([`SecuredPatientQueryService.java`](../src/main/java/io/github/rahulrajsonu/mcpsecurity/service/SecuredPatientQueryService.java)).
6. **No HTTP Caching:**
   - `Cache-Control: no-store` is applied to all responses to prevent edge proxies and browsers from persisting PHI.

---

## 2. What Your Organization Must Provide

Code-level controls are only one component of HIPAA compliance. An organization deploying this server must provide:

1. **Business Associate Agreement (BAA):** A legally binding BAA with the cloud LLM vendor ensuring zero retention of prompts and tool outputs for training.
2. **Endpoint Governance:** Hardened workstations running Claude Desktop or agent hosts with disk encryption (BitLocker/FileVault) and access-controlled transcripts.
3. **Audit Log Retention:** HIPAA requires audit trails to be retained for a minimum of **six years**. The database `access_events` table must be backed up to write-once, tamper-evident archival storage (e.g., AWS S3 Object Lock in Compliance Mode).
4. **Active Security Monitoring:** Incident response teams monitoring Prometheus metrics for denial spikes and break-glass events.
5. **Formal Risk Assessment:** Periodic security reviews, penetration tests, and threat modeling workshops.
