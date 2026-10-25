package io.github.rahulrajsonu.mcpsecurity;

import static io.github.rahulrajsonu.mcpsecurity.mcp.tool.ToolResultAssert.assertDenied;
import static io.github.rahulrajsonu.mcpsecurity.mcp.tool.ToolResultAssert.items;
import static io.github.rahulrajsonu.mcpsecurity.mcp.tool.ToolResultAssert.text;
import static org.assertj.core.api.Assertions.assertThat;

import io.github.rahulrajsonu.mcpsecurity.mcp.domain.AccessEvent;
import io.github.rahulrajsonu.mcpsecurity.mcp.tool.AuditMcpTools;
import io.github.rahulrajsonu.mcpsecurity.mcp.tool.PatientMcpTools;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import io.github.rahulrajsonu.mcpsecurity.persistence.repository.AccessEventRepository;
import io.github.rahulrajsonu.mcpsecurity.security.ClinicalPrincipal;
import io.github.rahulrajsonu.mcpsecurity.security.TenantScopedExecutor;
import java.time.Instant;
import java.util.Set;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.test.context.TestPropertySource;

/**
 * The controls that sit around a read: id validation, the break-glass step-up,
 * the untrusted-content marking and tenant isolation, through the tools as an
 * agent calls them.
 */
@TestPropertySource(properties = "app.security.break-glass.required-acr=urn:test:step-up")
class ToolGuardrailsIT extends AbstractPostgresIT {

    private static final String STEP_UP = "urn:test:step-up";
    private static final String CLIENT = "healthcare-mcp-client";

    @Autowired
    PatientMcpTools patientTools;

    @Autowired
    AuditMcpTools auditTools;

    @Autowired
    AccessEventRepository accessEvents;

    @Autowired
    TenantScopedExecutor tenantExecutor;

    @AfterEach
    void logout() {
        SecurityContextHolder.clearContext();
    }

    private static void loginAs(String subject, String tenant, String scopes, String acr) {
        Jwt.Builder jwt = Jwt.withTokenValue("test")
                .header("alg", "none")
                .subject(subject)
                .claim("tenant_id", tenant)
                .claim("scope", scopes)
                .claim("azp", CLIENT)
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60));
        if (acr != null) {
            jwt.claim("acr", acr);
        }
        SecurityContextHolder.getContext()
                .setAuthentication(new JwtAuthenticationToken(jwt.build(), List.of()));
    }

    private static String reason() {
        return "Unconscious patient in ED, no prior assignment: " + UUID.randomUUID();
    }

    @SuppressWarnings("unchecked")
    private List<AccessEvent> history(String patientId) {
        loginAs("compliance-1", "hospital-A", "audit.read", null);
        return (List<AccessEvent>) items(auditTools.getAccessHistory(patientId, 200));
    }

    // ---- patient id validation ----

    @Test
    void malformedPatientIdsAreRefusedAndNeverReachTheDatabase() {
        loginAs("doctor-101", "hospital-A", "patient.read medication.read notes.read", null);

        for (String bad : new String[] {"../../etc/passwd", "p'; DROP TABLE patients;--", "x".repeat(65), "a b", ""}) {
            assertDenied(patientTools.getPatientSummary(bad, null, null));
            assertDenied(patientTools.getPatientMedications(bad, null, null));
            assertDenied(patientTools.getClinicalNotes(bad, null, null));
        }
    }

    @Test
    void aRefusedMalformedIdIsStillAudited() {
        loginAs("doctor-101", "hospital-A", "patient.read", null);
        assertDenied(patientTools.getPatientSummary("bad id!", null, null));

        // Read the row directly: the audit tool itself refuses a malformed id.
        List<AccessEvent> events = tenantExecutor.execute(
                new ClinicalPrincipal("compliance-1", "hospital-A", Set.of("audit.read")),
                () -> accessEvents.findByPatient("hospital-A", "bad id!", 10));
        assertThat(events).anySatisfy(event -> {
            assertThat(event.subject()).isEqualTo("doctor-101");
            assertThat(event.clientId()).isEqualTo(CLIENT);
            assertThat(event.outcome()).isEqualTo("DENIED");
        });
    }

    // ---- break-glass step-up ----

    @Test
    void emergencyAccessIsRefusedWithoutTheStepUpClaim() {
        loginAs("doctor-101", "hospital-A", "patient.read medication.read patient.break_glass", null);

        assertDenied(patientTools.getPatientMedications("patient-500", "EMERGENCY", reason()));
    }

    @Test
    void emergencyAccessIsRefusedWithTheWrongStepUpClaim() {
        loginAs("doctor-101", "hospital-A", "patient.read medication.read patient.break_glass", "urn:other");

        assertDenied(patientTools.getPatientMedications("patient-500", "EMERGENCY", reason()));
    }

    @Test
    void emergencyAccessWorksWithTheStepUpClaim() {
        loginAs("doctor-101", "hospital-A", "patient.read medication.read patient.break_glass", STEP_UP);

        assertThat(items(patientTools.getPatientMedications("patient-500", "EMERGENCY", reason())))
                .extracting("name").containsExactly("Metformin");
    }

    @Test
    void theStepUpClaimAloneGrantsNothing() {
        // Without the break-glass scope the claim does not help.
        loginAs("doctor-101", "hospital-A", "patient.read medication.read", STEP_UP);

        assertDenied(patientTools.getPatientMedications("patient-500", "EMERGENCY", reason()));
    }

    @Test
    void treatmentDoesNotNeedTheStepUp() {
        loginAs("doctor-101", "hospital-A", "patient.read medication.read", null);

        assertThat(items(patientTools.getPatientMedications("patient-400", null, null))).isNotEmpty();
    }

    @Test
    void aRefusedEmergencyAttemptIsRecordedAsBreakGlassDenied() {
        String why = reason();
        loginAs("doctor-101", "hospital-A", "patient.read medication.read patient.break_glass", null);
        assertDenied(patientTools.getPatientMedications("patient-500", "EMERGENCY", why));

        assertThat(history("patient-500")).anySatisfy(event -> {
            assertThat(event.breakGlass()).isTrue();
            assertThat(event.outcome()).isEqualTo("DENIED");
            assertThat(event.justification()).isEqualTo(why);
        });
    }

    // ---- untrusted content ----

    @Test
    @SuppressWarnings("unchecked")
    void clinicalNotesAreMarkedUntrustedBeforeTheirContent() {
        loginAs("doctor-101", "hospital-A", "patient.read notes.read", null);

        CallToolResult result = patientTools.getClinicalNotes("patient-400", null, null);

        assertThat(result.isError()).isNotEqualTo(true);
        assertThat(result.content()).hasSize(2);
        assertThat(text(result)).startsWith("UNTRUSTED CONTENT");
        assertThat(((TextContent) result.content().get(1)).text()).doesNotStartWith("UNTRUSTED");
        assertThat(((Map<String, Object>) result.structuredContent())).containsKey("notice");
        assertThat(items(result)).hasSize(1);
    }

    @Test
    void otherToolsAreNotMarkedUntrusted() {
        loginAs("doctor-101", "hospital-A", "patient.read medication.read", null);

        CallToolResult result = patientTools.getPatientMedications("patient-400", null, null);

        assertThat(text(result)).doesNotContain("UNTRUSTED");
    }

    // ---- tenant isolation through the tools ----

    @Test
    void aClinicianCannotReadAnotherHospitalsPatient() {
        loginAs("doctor-303", "hospital-B", "patient.read medication.read patient.break_glass", STEP_UP);

        // patient-400 is hospital-A's. Not assigned, and even break-glass stays inside the tenant.
        assertDenied(patientTools.getPatientSummary("patient-400", null, null));
        assertDenied(patientTools.getPatientMedications("patient-400", "EMERGENCY", reason()));
    }

    @Test
    void anUnknownPatientLooksLikeAnotherTenantsPatient() {
        loginAs("doctor-101", "hospital-A", "patient.read medication.read patient.break_glass", STEP_UP);

        CallToolResult unknown = patientTools.getPatientMedications("patient-does-not-exist", "EMERGENCY", reason());
        CallToolResult otherTenant = patientTools.getPatientMedications("patient-600", "EMERGENCY", reason());

        assertDenied(unknown);
        assertDenied(otherTenant);
        // Identical bodies: an id cannot be probed for existence.
        assertThat(text(unknown)).isEqualTo(text(otherTenant));
    }

    // ---- errors never carry data ----

    @Test
    void refusalsNeverContainPatientDataOrIdentifiers() {
        loginAs("doctor-101", "hospital-A", "patient.read", null);

        CallToolResult result = patientTools.getPatientSummary("patient-500", null, null);

        assertDenied(result);
        assertThat(text(result)).doesNotContain("patient-500").doesNotContain("Alice").doesNotContain("hospital");
    }
}
