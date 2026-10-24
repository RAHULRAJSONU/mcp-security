package io.github.rahulrajsonu.mcpsecurity.mcp.tool;

import io.github.rahulrajsonu.mcpsecurity.mcp.domain.AccessEvent;
import io.github.rahulrajsonu.mcpsecurity.security.AccessPurpose;
import io.github.rahulrajsonu.mcpsecurity.security.ClinicalAccessContext;
import io.github.rahulrajsonu.mcpsecurity.security.ClinicalPrincipalResolver;
import io.github.rahulrajsonu.mcpsecurity.service.SecuredPatientQueryService;
import lombok.RequiredArgsConstructor;

import org.springframework.ai.mcp.annotation.McpTool;
import org.springframework.ai.mcp.annotation.McpToolParam;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * For the privacy or compliance officer, a separate duty from treating
 * patients. Needs scope audit.read, which clinicians do not hold.
 */
@Component
@RequiredArgsConstructor
public class AuditMcpTools {

    private final ClinicalPrincipalResolver principalResolver;
    private final SecuredPatientQueryService patientQueryService;

    @McpTool(description = "List recorded access attempts for one patient in the caller's tenant, newest first. "
            + "Needs scope audit.read. Reading the history is itself recorded.")
    public List<AccessEvent> getAccessHistory(
            @McpToolParam(description = "Patient identifier")
            String patientId,

            @McpToolParam(description = "Maximum events to return (default 50, max 200)", required = false)
            Integer limit) {

        return patientQueryService.getAccessHistory(context(), patientId, limit);
    }

    @McpTool(description = "List emergency (break-glass) access attempts across the caller's tenant, "
            + "including the stated justification, newest first. Needs scope audit.read.")
    public List<AccessEvent> listBreakGlassEvents(
            @McpToolParam(description = "Maximum events to return (default 50, max 200)", required = false)
            Integer limit) {

        return patientQueryService.getBreakGlassEvents(context(), limit);
    }

    private ClinicalAccessContext context() {
        Authentication authentication =
                SecurityContextHolder.getContext()
                        .getAuthentication();

        if (authentication == null) {
            throw new AccessDeniedException(
                    "Authentication required"
            );
        }

        // Auditing is a healthcare-operations activity, not treatment.
        return new ClinicalAccessContext(
                principalResolver.resolve(authentication),
                AccessPurpose.HEALTHCARE_OPERATIONS
        );
    }
}
