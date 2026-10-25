package io.github.rahulrajsonu.mcpsecurity;

import static io.github.rahulrajsonu.mcpsecurity.mcp.tool.ToolResultAssert.assertDenied;
import static io.github.rahulrajsonu.mcpsecurity.mcp.tool.ToolResultAssert.items;
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

/**
 * The agent registry against the seeded database (V9): which OAuth client may
 * act for which user, and what the audit trail records about it.
 *
 * Seed, hospital-A: healthcare-mcp-client is APPROVED for doctor-101, doctor-202
 * and compliance-1; suspended-client is SUSPENDED and expired-client is past its
 * expiry, both for doctor-101. hospital-B approves it for doctor-101, doctor-303
 * and compliance-B.
 */
class AgentRegistryIT extends AbstractPostgresIT {

    @Autowired
    PatientMcpTools patientTools;

    @Autowired
    AuditMcpTools auditTools;

    @AfterEach
    void logout() {
        SecurityContextHolder.clearContext();
    }

    private static void loginAs(String subject, String tenant, String scopes, String clientId) {
        Jwt.Builder jwt = Jwt.withTokenValue("test")
                .header("alg", "none")
                .subject(subject)
                .claim("tenant_id", tenant)
                .claim("scope", scopes)
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60));
        if (clientId != null) {
            jwt.claim("azp", clientId);
        }
        SecurityContextHolder.getContext()
                .setAuthentication(new JwtAuthenticationToken(jwt.build(), List.of()));
    }

    @Test
    void approvedAgentForTheUserCanRead() {
        loginAs("doctor-101", "hospital-A", "patient.read", "healthcare-mcp-client");

        assertThat(items(patientTools.listMyPatients())).isNotEmpty();
    }

    @Test
    void suspendedAgentIsRefused() {
        loginAs("doctor-101", "hospital-A", "patient.read", "suspended-client");

        assertDenied(patientTools.listMyPatients());
    }

    @Test
    void expiredAgentIsRefused() {
        loginAs("doctor-101", "hospital-A", "patient.read", "expired-client");

        assertDenied(patientTools.listMyPatients());
    }

    @Test
    void unregisteredAgentIsRefused() {
        loginAs("doctor-101", "hospital-A", "patient.read", "never-registered");

        assertDenied(patientTools.listMyPatients());
    }

    @Test
    void tokenWithoutAClientIdIsRefused() {
        loginAs("doctor-101", "hospital-A", "patient.read", null);

        assertDenied(patientTools.listMyPatients());
    }

    @Test
    void anApprovalIsBoundToItsUser() {
        // suspended-client is registered for doctor-101 only; doctor-202 has no row for it.
        loginAs("doctor-202", "hospital-A", "patient.read", "suspended-client");

        assertDenied(patientTools.listMyPatients());
    }

    @Test
    void anApprovalInOneTenantDoesNotCrossToAnother() {
        // doctor-202 is approved in hospital-A only.
        loginAs("doctor-202", "hospital-B", "patient.read", "healthcare-mcp-client");

        assertDenied(patientTools.listMyPatients());
    }

    @Test
    void auditTrailNamesTheAgentThatActed() {
        loginAs("doctor-101", "hospital-A", "patient.read", "healthcare-mcp-client");
        patientTools.getPatientSummary("patient-400", null, null);

        loginAs("compliance-1", "hospital-A", "audit.read", "healthcare-mcp-client");
        CallToolResult history = auditTools.getAccessHistory("patient-400", 200);

        @SuppressWarnings("unchecked")
        List<AccessEvent> events = (List<AccessEvent>) items(history);
        assertThat(events).anySatisfy(event -> {
            assertThat(event.subject()).isEqualTo("doctor-101");
            assertThat(event.clientId()).isEqualTo("healthcare-mcp-client");
        });
    }

    @Test
    void aRefusedAgentIsStillRecordedWithItsClient() {
        loginAs("doctor-101", "hospital-A", "patient.read", "suspended-client");
        assertDenied(patientTools.getPatientSummary("patient-400", null, null));

        loginAs("compliance-1", "hospital-A", "audit.read", "healthcare-mcp-client");
        @SuppressWarnings("unchecked")
        List<AccessEvent> events = (List<AccessEvent>) items(auditTools.getAccessHistory("patient-400", 200));

        assertThat(events).anySatisfy(event -> {
            assertThat(event.clientId()).isEqualTo("suspended-client");
            assertThat(event.outcome()).isEqualTo("DENIED");
        });
    }
}
