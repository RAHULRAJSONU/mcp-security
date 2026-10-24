package io.github.rahulrajsonu.mcpsecurity.mcp.tool;

import io.github.rahulrajsonu.mcpsecurity.mcp.domain.ClinicalNote;
import io.github.rahulrajsonu.mcpsecurity.mcp.domain.Medication;
import io.github.rahulrajsonu.mcpsecurity.mcp.domain.PatientSummary;
import io.github.rahulrajsonu.mcpsecurity.mcp.domain.RosterEntry;
import io.github.rahulrajsonu.mcpsecurity.security.AccessPurpose;
import io.github.rahulrajsonu.mcpsecurity.security.ClinicalAccessContext;
import io.github.rahulrajsonu.mcpsecurity.security.ClinicalPrincipal;
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

@Component
@RequiredArgsConstructor
public class PatientMcpTools {

    private final ClinicalPrincipalResolver principalResolver;
    private final SecuredPatientQueryService patientQueryService;

    @McpTool(description = "Retrieve an authorized patient's summary. "
            + "Defaults to purpose TREATMENT, which requires an active assignment. "
            + "EMERGENCY (break-glass) requires a justification and is audited.")
    public PatientSummary getPatientSummary(
            @McpToolParam(description = "Patient identifier")
            String patientId,

            @McpToolParam(
                    description = "Purpose of access: TREATMENT (default) or EMERGENCY",
                    required = false)
            String purpose,

            @McpToolParam(
                    description = "Why emergency access is needed. Required for EMERGENCY",
                    required = false)
            String justification) {

        return patientQueryService.getSummary(
                context(purpose, justification),
                patientId
        );
    }

    @McpTool(description = "List the patients the caller is currently assigned to. "
            + "Revoked, suspended and expired assignments are not included. "
            + "Needs scope patient.read; there is no emergency form of this tool.")
    public List<RosterEntry> listMyPatients() {
        return patientQueryService.getRoster(
                context(AccessPurpose.TREATMENT.name(), null));
    }

    @McpTool(description = "Retrieve a patient's active medications. "
            + "Needs scopes patient.read and medication.read. "
            + "Emergency (break-glass) access is permitted.")
    public List<Medication> getPatientMedications(
            @McpToolParam(description = "Patient identifier")
            String patientId,

            @McpToolParam(
                    description = "Purpose of access: TREATMENT (default) or EMERGENCY",
                    required = false)
            String purpose,

            @McpToolParam(
                    description = "Why emergency access is needed. Required for EMERGENCY",
                    required = false)
            String justification) {

        return patientQueryService.getMedications(
                context(purpose, justification),
                patientId
        );
    }

    @McpTool(description = "Retrieve a patient's clinical notes. "
            + "Needs scopes patient.read and notes.read. "
            + "Emergency (break-glass) access is NOT permitted for notes.")
    public List<ClinicalNote> getClinicalNotes(
            @McpToolParam(description = "Patient identifier")
            String patientId,

            @McpToolParam(
                    description = "Purpose of access: TREATMENT (default). EMERGENCY is refused for notes",
                    required = false)
            String purpose,

            @McpToolParam(
                    description = "Accepted for symmetry with other tools; does not unlock notes",
                    required = false)
            String justification) {

        return patientQueryService.getNotes(
                context(purpose, justification),
                patientId
        );
    }

    private ClinicalAccessContext context(String purpose, String justification) {
        Authentication authentication =
                SecurityContextHolder.getContext()
                        .getAuthentication();

        if (authentication == null) {
            throw new AccessDeniedException(
                    "Authentication required"
            );
        }

        ClinicalPrincipal principal =
                principalResolver.resolve(authentication);

        return new ClinicalAccessContext(
                principal,
                parsePurpose(purpose),
                justification
        );
    }

    static AccessPurpose parsePurpose(String purpose) {
        if (purpose == null || purpose.isBlank()) {
            return AccessPurpose.TREATMENT;
        }

        try {
            return AccessPurpose.valueOf(
                    purpose.strip().toUpperCase(java.util.Locale.ROOT));
        } catch (IllegalArgumentException ex) {
            // Same answer as any other refusal; do not echo the input.
            throw new AccessDeniedException("Patient access denied");
        }
    }
}
