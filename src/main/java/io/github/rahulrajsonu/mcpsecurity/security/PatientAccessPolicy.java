package io.github.rahulrajsonu.mcpsecurity.security;

import io.github.rahulrajsonu.mcpsecurity.exception.PatientAccessDeniedException;
import io.github.rahulrajsonu.mcpsecurity.persistence.repository.PatientAssignmentRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * Deny by default. Every denial raises the same exception so callers cannot
 * tell "no such patient" from "not yours" from "missing scope".
 */
@Service
@RequiredArgsConstructor
public class PatientAccessPolicy {

    public static final String READ_SCOPE = "patient.read";
    public static final String BREAK_GLASS_SCOPE = "patient.break_glass";
    public static final String AUDIT_SCOPE = "audit.read";

    static final int MIN_JUSTIFICATION_CHARS = 15;
    static final int MAX_JUSTIFICATION_CHARS = 500;

    private final PatientAssignmentRepository assignments;

    public void requireReadAccess(
            ClinicalAccessContext context,
            String patientId
    ) {
        requireReadAccess(context, patientId, DataCategory.PATIENT_SUMMARY);
    }

    /**
     * Patient-bound reads: the base read scope plus the category's own scope,
     * then either an active assignment (treatment) or break-glass, where the
     * category permits it.
     */
    public void requireReadAccess(
            ClinicalAccessContext context,
            String patientId,
            DataCategory category
    ) {
        ClinicalPrincipal principal = context.principal();

        if (!principal.hasScope(READ_SCOPE)
                || !principal.hasScope(category.requiredScope())) {
            throw new PatientAccessDeniedException();
        }

        switch (context.purpose()) {
            case TREATMENT -> requireActiveAssignment(principal, patientId);
            case EMERGENCY -> {
                if (!category.breakGlassAllowed()) {
                    throw new PatientAccessDeniedException();
                }
                requireBreakGlass(context);
            }
            // PAYMENT and HEALTHCARE_OPERATIONS have no defined rules for patient data yet.
            default -> throw new PatientAccessDeniedException();
        }
    }

    /** Listing assigned patients is a treatment activity; there is no emergency form of it. */
    public void requireRosterAccess(ClinicalAccessContext context) {
        if (!context.principal().hasScope(READ_SCOPE)
                || context.purpose() != AccessPurpose.TREATMENT) {
            throw new PatientAccessDeniedException();
        }
    }

    /** Reading the access history is a separate duty from reading patients. */
    public void requireAuditAccess(ClinicalPrincipal principal) {
        if (!principal.hasScope(AUDIT_SCOPE)) {
            throw new PatientAccessDeniedException();
        }
    }

    private void requireActiveAssignment(
            ClinicalPrincipal principal,
            String patientId) {

        boolean assigned = assignments.hasActiveAssignment(
                principal.tenantId(),
                principal.subject(),
                patientId
        );

        if (!assigned) {
            throw new PatientAccessDeniedException();
        }
    }

    /**
     * Emergency access skips the assignment check, so it is gated by a
     * separate, explicitly granted scope and a mandatory justification. It
     * never crosses tenants: row-level security still applies.
     */
    private void requireBreakGlass(ClinicalAccessContext context) {
        if (!context.principal().hasScope(BREAK_GLASS_SCOPE)) {
            throw new PatientAccessDeniedException();
        }

        String justification = context.justification();

        if (justification == null) {
            throw new PatientAccessDeniedException();
        }

        int length = justification.strip().length();

        if (length < MIN_JUSTIFICATION_CHARS
                || length > MAX_JUSTIFICATION_CHARS) {
            throw new PatientAccessDeniedException();
        }
    }
}
