package io.github.rahulrajsonu.mcpsecurity;

import static io.github.rahulrajsonu.mcpsecurity.mcp.tool.ToolResultAssert.assertDenied;
import static io.github.rahulrajsonu.mcpsecurity.mcp.tool.ToolResultAssert.assertFailed;
import static io.github.rahulrajsonu.mcpsecurity.mcp.tool.ToolResultAssert.items;
import static io.github.rahulrajsonu.mcpsecurity.mcp.tool.ToolResultAssert.text;
import static org.assertj.core.api.Assertions.assertThat;

import io.github.rahulrajsonu.mcpsecurity.mcp.domain.AccessEvent;
import io.github.rahulrajsonu.mcpsecurity.mcp.tool.AuditMcpTools;
import io.github.rahulrajsonu.mcpsecurity.mcp.tool.PatientMcpTools;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.test.context.TestPropertySource;

/**
 * The runnable labs of curriculum Module 10. Each test is one lab: read it, run it,
 * then change one line and watch it fail. Kept in the build so the tutorial cannot
 * drift away from the code.
 *
 * Seed data (hospital-A): doctor-101 is assigned patient-400 and had patient-500 revoked.
 * healthcare-mcp-client is APPROVED for doctor-101, doctor-202 and compliance-1;
 * suspended-client is SUSPENDED for doctor-101.
 */
@TestPropertySource(properties = {
        // Lab 3: emergency access needs this acr in the token.
        "app.security.break-glass.required-acr=urn:test:step-up",
        // Lab 4: a small quota so the limit is easy to hit. The quota is per (tenant, user, client)
        // and lives as long as the application context, so Lab 4 uses a user no other lab uses.
        "app.security.agent.calls-per-minute=5",
        "app.security.agent.calls-per-day=1000"})
class TutorialLabIT extends AbstractPostgresIT {

    @Autowired
    PatientMcpTools patientTools;

    @Autowired
    AuditMcpTools auditTools;

    @AfterEach
    void logout() {
        SecurityContextHolder.clearContext();
    }

    /** Pretends the identity provider issued this token. {@code acr} may be null. */
    private static void loginAs(String subject, String scopes, String client, String acr) {
        Jwt.Builder jwt = Jwt.withTokenValue("test")
                .header("alg", "none")
                .subject(subject)
                .claim("tenant_id", "hospital-A")
                .claim("scope", scopes)
                .claim("azp", client)
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60));
        if (acr != null) {
            jwt.claim("acr", acr);
        }
        SecurityContextHolder.getContext()
                .setAuthentication(new JwtAuthenticationToken(jwt.build(), List.of()));
    }

    // Lab 1: the same user, two different agents.
    @Test
    void lab1_theUserIsAllowedButOnlyThroughAnApprovedAgent() {
        loginAs("doctor-101", "patient.read", "healthcare-mcp-client", null);
        assertThat(items(patientTools.listMyPatients())).isNotEmpty();

        loginAs("doctor-101", "patient.read", "suspended-client", null);
        assertDenied(patientTools.listMyPatients());
    }

    // Lab 2: a refusal is audited, and the audit row names the agent.
    @Test
    void lab2_aRefusedAgentLeavesATrail() {
        loginAs("doctor-101", "patient.read", "suspended-client", null);
        assertDenied(patientTools.getPatientSummary("patient-400", null, null));

        loginAs("compliance-1", "audit.read", "healthcare-mcp-client", null);
        @SuppressWarnings("unchecked")
        List<AccessEvent> events = (List<AccessEvent>) items(auditTools.getAccessHistory("patient-400", 200));

        assertThat(events).anySatisfy(event -> {
            assertThat(event.clientId()).isEqualTo("suspended-client");
            assertThat(event.outcome()).isEqualTo("DENIED");
        });
    }

    // Lab 3: the model can type EMERGENCY, but it cannot mint an acr claim.
    @Test
    void lab3_breakGlassNeedsTheStepUpClaimInTheToken() {
        String scopes = "patient.read medication.read patient.break_glass";
        String why = "Unconscious patient in ED, no prior assignment";

        loginAs("doctor-101", scopes, "healthcare-mcp-client", null);
        assertDenied(patientTools.getPatientMedications("patient-500", "EMERGENCY", why));

        loginAs("doctor-101", scopes, "healthcare-mcp-client", "urn:test:step-up");
        CallToolResult withStepUp = patientTools.getPatientMedications("patient-500", "EMERGENCY", why);
        assertThat(withStepUp.isError()).isNotEqualTo(true);
    }

    // Lab 4: a quota turns a runaway loop into a retryable error, not an outage.
    @Test
    void lab4_theSixthCallInAMinuteIsRateLimited() {
        loginAs("doctor-202", "patient.read", "healthcare-mcp-client", null);
        for (int i = 0; i < 5; i++) {
            assertThat(patientTools.listMyPatients().isError()).isNotEqualTo(true);
        }

        CallToolResult sixth = patientTools.listMyPatients();

        assertFailed(sixth, "rate_limited");
        assertThat(text(sixth)).contains("\"retryable\":true");
    }
}
