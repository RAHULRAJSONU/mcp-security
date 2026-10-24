package io.github.rahulrajsonu.mcpsecurity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.rahulrajsonu.mcpsecurity.mcp.domain.AccessEvent;
import io.github.rahulrajsonu.mcpsecurity.mcp.tool.AuditMcpTools;
import io.github.rahulrajsonu.mcpsecurity.mcp.tool.PatientMcpTools;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

/**
 * The MCP tools exactly as an agent calls them: identity comes from a JWT's
 * claims, and the policy, tenant isolation and audit all run for real against
 * the seeded database.
 *
 * Seed: doctor-101 (hospital-A) is active on patient-400 and REVOKED on
 * patient-500; doctor-202 is active on both; doctor-303 is hospital-B only.
 */
class ClinicalToolsEndToEndIT extends AbstractPostgresIT {

    private static final String WHY = "Unconscious patient in ED, no prior assignment: ";

    @Autowired
    PatientMcpTools patientTools;

    @Autowired
    AuditMcpTools auditTools;

    @AfterEach
    void logout() {
        SecurityContextHolder.clearContext();
    }

    private static void loginAs(String subject, String tenant, String scopes) {
        Jwt jwt = Jwt.withTokenValue("test")
                .header("alg", "none")
                .subject(subject)
                .claim("tenant_id", tenant)
                .claim("scope", scopes)
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60))
                .build();
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt, List.of()));
    }

    private static String uniqueReason() {
        return WHY + UUID.randomUUID();
    }

    // ---- roster: scoped by assignment ----

    @Test
    void rosterListsOnlyActiveAssignmentsInTheCallersTenant() {
        loginAs("doctor-101", "hospital-A", "patient.read");
        assertThat(patientTools.listMyPatients()).extracting("patientId").containsExactly("patient-400");

        loginAs("doctor-202", "hospital-A", "patient.read");
        assertThat(patientTools.listMyPatients()).extracting("patientId").containsExactly("patient-400", "patient-500");

        loginAs("doctor-303", "hospital-B", "patient.read");
        assertThat(patientTools.listMyPatients()).extracting("patientId").containsExactly("patient-600");
    }

    @Test
    void rosterNeedsTheReadScope() {
        loginAs("doctor-101", "hospital-A", "medication.read");

        assertThatThrownBy(() -> patientTools.listMyPatients()).isInstanceOf(AccessDeniedException.class);
    }

    // ---- medications: own scope, break-glass allowed ----

    @Test
    void medicationsNeedTheirOwnScopeAndAnAssignment() {
        loginAs("doctor-101", "hospital-A", "patient.read medication.read");
        assertThat(patientTools.getPatientMedications("patient-400", null, null))
                .extracting("name").containsExactly("Atorvastatin", "Lisinopril");

        // Revoked assignment on patient-500.
        assertThatThrownBy(() -> patientTools.getPatientMedications("patient-500", null, null))
                .isInstanceOf(AccessDeniedException.class);

        // patient.read alone does not open medications.
        loginAs("doctor-101", "hospital-A", "patient.read");
        assertThatThrownBy(() -> patientTools.getPatientMedications("patient-400", null, null))
                .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void breakGlassOpensMedicationsWithinTheTenantOnly() {
        loginAs("doctor-101", "hospital-A", "patient.read medication.read patient.break_glass");

        assertThat(patientTools.getPatientMedications("patient-500", "EMERGENCY", uniqueReason()))
                .extracting("name").containsExactly("Metformin");

        assertThatThrownBy(() -> patientTools.getPatientMedications("patient-600", "EMERGENCY", uniqueReason()))
                .isInstanceOf(AccessDeniedException.class);
    }

    // ---- notes: own scope, break-glass refused ----

    @Test
    void notesAreReadableForTreatmentButNeverThroughBreakGlass() {
        loginAs("doctor-101", "hospital-A", "patient.read notes.read patient.break_glass");

        assertThat(patientTools.getClinicalNotes("patient-400", null, null)).hasSize(1);

        // Same caller, same scopes: break-glass works for medications elsewhere, but not here.
        assertThatThrownBy(() -> patientTools.getClinicalNotes("patient-500", "EMERGENCY", uniqueReason()))
                .isInstanceOf(AccessDeniedException.class);
    }

    // ---- audit: separate duty, durable, tenant-isolated ----

    @Test
    void auditOfficerSeesBreakGlassWithJustificationButClinicianCannot() {
        String reason = uniqueReason();

        loginAs("doctor-101", "hospital-A", "patient.read medication.read patient.break_glass");
        patientTools.getPatientMedications("patient-500", "EMERGENCY", reason);

        // The clinician who did it cannot read the audit trail.
        assertThatThrownBy(() -> auditTools.listBreakGlassEvents(50)).isInstanceOf(AccessDeniedException.class);

        loginAs("compliance-1", "hospital-A", "audit.read");
        List<AccessEvent> events = auditTools.listBreakGlassEvents(200);

        assertThat(events).anySatisfy(event -> {
            assertThat(event.subject()).isEqualTo("doctor-101");
            assertThat(event.patientId()).isEqualTo("patient-500");
            assertThat(event.outcome()).isEqualTo("ALLOWED");
            assertThat(event.category()).isEqualTo("MEDICATIONS");
            assertThat(event.justification()).isEqualTo(reason);
        });
    }

    @Test
    void deniedAttemptsAreRecordedToo() {
        loginAs("doctor-101", "hospital-A", "patient.read");
        assertThatThrownBy(() -> patientTools.getPatientSummary("patient-500", null, null))
                .isInstanceOf(AccessDeniedException.class);

        loginAs("compliance-1", "hospital-A", "audit.read");
        assertThat(auditTools.getAccessHistory("patient-500", 200)).anySatisfy(event -> {
            assertThat(event.subject()).isEqualTo("doctor-101");
            assertThat(event.outcome()).isEqualTo("DENIED");
        });
    }

    @Test
    void auditTrailIsTenantIsolated() {
        loginAs("doctor-101", "hospital-A", "patient.read");
        patientTools.getPatientSummary("patient-400", null, null);

        loginAs("compliance-B", "hospital-B", "audit.read");

        // Another hospital's auditor sees none of hospital-A's history, even by patient id.
        assertThat(auditTools.getAccessHistory("patient-400", 200)).isEmpty();
    }

    @Test
    void readingTheAuditTrailIsItselfAudited() {
        loginAs("compliance-1", "hospital-A", "audit.read");
        auditTools.getAccessHistory("patient-400", 10);

        assertThat(auditTools.getAccessHistory("patient-400", 200)).anySatisfy(event -> {
            assertThat(event.subject()).isEqualTo("compliance-1");
            assertThat(event.category()).isEqualTo("ACCESS_AUDIT");
        });
    }
}
