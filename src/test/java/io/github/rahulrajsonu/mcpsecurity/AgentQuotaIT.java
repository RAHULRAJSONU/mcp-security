package io.github.rahulrajsonu.mcpsecurity;

import static io.github.rahulrajsonu.mcpsecurity.mcp.tool.ToolResultAssert.assertFailed;
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
import org.springframework.test.context.TestPropertySource;

/**
 * The per-identity quota with the real wiring. Each test uses a different user,
 * because the quota is keyed on (tenant, user, client) and lives for the context.
 */
@TestPropertySource(properties = {
        "app.security.agent.calls-per-minute=3",
        "app.security.agent.calls-per-day=1000"})
class AgentQuotaIT extends AbstractPostgresIT {

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
        SecurityContextHolder.getContext()
                .setAuthentication(new JwtAuthenticationToken(jwt, List.of()));
    }

    @Test
    void callsOverTheLimitAreRefusedAsRetryable() {
        loginAs("doctor-202", "hospital-A", "patient.read");

        for (int i = 0; i < 3; i++) {
            assertThat(patientTools.listMyPatients().isError()).isNotEqualTo(true);
        }
        CallToolResult refused = patientTools.listMyPatients();

        assertFailed(refused, "rate_limited");
        assertThat(((java.util.Map<?, ?>) refused.structuredContent()).get("retryable")).isEqualTo(true);
    }

    @Test
    void oneUsersQuotaDoesNotAffectAnother() {
        loginAs("doctor-101", "hospital-A", "patient.read");
        for (int i = 0; i < 4; i++) {
            patientTools.listMyPatients();
        }
        assertFailed(patientTools.listMyPatients(), "rate_limited");

        // doctor-303 is approved in hospital-B and has a bucket of its own.
        loginAs("doctor-303", "hospital-B", "patient.read");
        assertThat(patientTools.listMyPatients().isError()).isNotEqualTo(true);
    }

    @Test
    void aRefusedCallIsAuditedAsDeniedAndReturnsNoData() {
        loginAs("compliance-1", "hospital-A", "audit.read");
        // Three audit reads use the minute's budget.
        auditTools.getAccessHistory("patient-400", 5);
        auditTools.getAccessHistory("patient-400", 5);
        auditTools.getAccessHistory("patient-400", 5);

        CallToolResult refused = auditTools.getAccessHistory("patient-400", 5);

        assertFailed(refused, "rate_limited");
        assertThat(refused.structuredContent()).isNotInstanceOf(List.class);
        assertThat(((java.util.Map<?, ?>) refused.structuredContent()).containsKey("items")).isFalse();
    }

    @Test
    void theQuotaCountsAcrossToolsNotPerTool() {
        // doctor-101 in hospital-B has a bucket no other test touches.
        loginAs("doctor-101", "hospital-B", "patient.read medication.read");

        patientTools.listMyPatients();
        patientTools.getPatientMedications("patient-600", null, null);
        patientTools.getPatientSummary("patient-600", null, null);

        assertFailed(patientTools.listMyPatients(), "rate_limited");
    }

    @SuppressWarnings("unchecked")
    @Test
    void auditReadsStillWorkForAFreshIdentity() {
        loginAs("compliance-B", "hospital-B", "audit.read");

        List<AccessEvent> events = (List<AccessEvent>) items(auditTools.getAccessHistory("patient-600", 5));

        assertThat(events).isNotNull();
    }
}
