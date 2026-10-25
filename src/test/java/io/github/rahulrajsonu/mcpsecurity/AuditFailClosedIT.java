package io.github.rahulrajsonu.mcpsecurity;

import static org.assertj.core.api.Assertions.assertThat;
import static io.github.rahulrajsonu.mcpsecurity.mcp.tool.ToolResultAssert.assertFailed;
import static io.github.rahulrajsonu.mcpsecurity.mcp.tool.ToolResultAssert.text;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;

import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.github.rahulrajsonu.mcpsecurity.mcp.tool.PatientMcpTools;
import io.github.rahulrajsonu.mcpsecurity.persistence.repository.AccessEventRepository;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

/** "No audit, no data": if the access cannot be recorded, nothing is returned. */
class AuditFailClosedIT extends AbstractPostgresIT {

    @MockitoBean
    AccessEventRepository events;

    @Autowired
    PatientMcpTools patientTools;

    @AfterEach
    void logout() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void anAllowedReadIsRefusedWhenTheAuditWriteFails() {
        doThrow(new IllegalStateException("audit store down")).when(events).append(any(), any());

        Jwt jwt = Jwt.withTokenValue("test").header("alg", "none").subject("doctor-101")
                .claim("tenant_id", "hospital-A").claim("scope", "patient.read").claim("azp", "healthcare-mcp-client")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60)).build();
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt, List.of()));

        CallToolResult result = patientTools.getPatientSummary("patient-400", null, null);

        // Refused, and the message is generic: no data from the read, no audit-store detail.
        assertFailed(result, "request_failed");
        assertThat(text(result))
                .doesNotContain("patient-400")
                .doesNotContain("Alice")
                .doesNotContain("audit store down");

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
    }
}
