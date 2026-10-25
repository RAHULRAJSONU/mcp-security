package io.github.rahulrajsonu.mcpsecurity;

import static org.assertj.core.api.Assertions.assertThat;
import static io.github.rahulrajsonu.mcpsecurity.mcp.tool.ToolResultAssert.assertDenied;
import static io.github.rahulrajsonu.mcpsecurity.mcp.tool.ToolResultAssert.items;

import io.github.rahulrajsonu.mcpsecurity.mcp.domain.AccessEvent;
import io.github.rahulrajsonu.mcpsecurity.mcp.tool.AuditMcpTools;
import io.github.rahulrajsonu.mcpsecurity.mcp.tool.PatientMcpTools;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
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
                .claim("azp", "healthcare-mcp-client")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60))
                .build();
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt, List.of()));
    }

    @SuppressWarnings("unchecked")
    private static List<AccessEvent> events(CallToolResult result) {
        return (List<AccessEvent>) items(result);
    }

    private static String uniqueReason() {
        return WHY + UUID.randomUUID();
    }

    // ---- roster: scoped by assignment ----

    @Test
    void rosterListsOnlyActiveAssignmentsInTheCallersTenant() {
        loginAs("doctor-101", "hospital-A", "patient.read");
        assertThat(items(patientTools.listMyPatients())).extracting("patientId").containsExactly("patient-400");

        loginAs("doctor-202", "hospital-A", "patient.read");
        assertThat(items(patientTools.listMyPatients())).extracting("patientId").containsExactly("patient-400", "patient-500");

        loginAs("doctor-303", "hospital-B", "patient.read");
        assertThat(items(patientTools.listMyPatients())).extracting("patientId").containsExactly("patient-600");
    }

    @Test
    void rosterNeedsTheReadScope() {
        loginAs("doctor-101", "hospital-A", "medication.read");

        assertDenied(patientTools.listMyPatients());
    }

    // ---- medications: own scope, break-glass allowed ----

    @Test
    void medicationsNeedTheirOwnScopeAndAnAssignment() {
        loginAs("doctor-101", "hospital-A", "patient.read medication.read");
        assertThat(items(patientTools.getPatientMedications("patient-400", null, null)))
                .extracting("name").containsExactly("Atorvastatin", "Lisinopril");

        // Revoked assignment on patient-500.
        assertDenied(patientTools.getPatientMedications("patient-500", null, null));

        // patient.read alone does not open medications.
        loginAs("doctor-101", "hospital-A", "patient.read");
        assertDenied(patientTools.getPatientMedications("patient-400", null, null));
    }

    @Test
    void breakGlassOpensMedicationsWithinTheTenantOnly() {
        loginAs("doctor-101", "hospital-A", "patient.read medication.read patient.break_glass");

        assertThat(items(patientTools.getPatientMedications("patient-500", "EMERGENCY", uniqueReason())))
                .extracting("name").containsExactly("Metformin");

        assertDenied(patientTools.getPatientMedications("patient-600", "EMERGENCY", uniqueReason()));
    }

    // ---- notes: own scope, break-glass refused ----

    @Test
    void notesAreReadableForTreatmentButNeverThroughBreakGlass() {
        loginAs("doctor-101", "hospital-A", "patient.read notes.read patient.break_glass");

        assertThat(items(patientTools.getClinicalNotes("patient-400", null, null))).hasSize(1);

        // Same caller, same scopes: break-glass works for medications elsewhere, but not here.
        assertDenied(patientTools.getClinicalNotes("patient-500", "EMERGENCY", uniqueReason()));
    }

    // ---- audit: separate duty, durable, tenant-isolated ----

    @Test
    void auditOfficerSeesBreakGlassWithJustificationButClinicianCannot() {
        String reason = uniqueReason();

        loginAs("doctor-101", "hospital-A", "patient.read medication.read patient.break_glass");
        patientTools.getPatientMedications("patient-500", "EMERGENCY", reason);

        // The clinician who did it cannot read the audit trail.
        assertDenied(auditTools.listBreakGlassEvents(50));

        loginAs("compliance-1", "hospital-A", "audit.read");
        List<AccessEvent> events = events(auditTools.listBreakGlassEvents(200));

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
        assertDenied(patientTools.getPatientSummary("patient-500", null, null));

        loginAs("compliance-1", "hospital-A", "audit.read");
        assertThat(events(auditTools.getAccessHistory("patient-500", 200))).anySatisfy(event -> {
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
        assertThat(items(auditTools.getAccessHistory("patient-400", 200))).isEmpty();
    }

    @Test
    void readingTheAuditTrailIsItselfAudited() {
        loginAs("compliance-1", "hospital-A", "audit.read");
        auditTools.getAccessHistory("patient-400", 10);

        assertThat(events(auditTools.getAccessHistory("patient-400", 200))).anySatisfy(event -> {
            assertThat(event.subject()).isEqualTo("compliance-1");
            assertThat(event.category()).isEqualTo("ACCESS_AUDIT");
        });
    }
}
