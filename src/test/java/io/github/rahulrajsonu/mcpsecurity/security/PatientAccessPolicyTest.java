package io.github.rahulrajsonu.mcpsecurity.security;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import io.github.rahulrajsonu.mcpsecurity.config.BreakGlassProperties;
import io.github.rahulrajsonu.mcpsecurity.exception.PatientAccessDeniedException;
import io.github.rahulrajsonu.mcpsecurity.persistence.repository.PatientAssignmentRepository;
import java.util.Set;
import org.junit.jupiter.api.Test;

class PatientAccessPolicyTest {

    private static final String JUSTIFICATION = "Unconscious patient in ED, no prior assignment";

    private final PatientAssignmentRepository assignments = mock(PatientAssignmentRepository.class);
    private final PatientAccessPolicy policy = new PatientAccessPolicy(assignments);

    private static ClinicalPrincipal principal(String... scopes) {
        return new ClinicalPrincipal("doctor-101", "hospital-A", Set.of(scopes));
    }

    private static ClinicalAccessContext ctx(ClinicalPrincipal p, AccessPurpose purpose, String why) {
        return new ClinicalAccessContext(p, purpose, why);
    }

    @Test
    void treatmentRequiresActiveAssignment() {
        when(assignments.hasActiveAssignment("hospital-A", "doctor-101", "patient-400")).thenReturn(true);

        assertThatCode(() -> policy.requireReadAccess(
                ctx(principal("patient.read"), AccessPurpose.TREATMENT, null), "patient-400"))
                .doesNotThrowAnyException();
    }

    @Test
    void treatmentWithoutAssignmentIsDenied() {
        when(assignments.hasActiveAssignment(any(), any(), any())).thenReturn(false);

        assertThatThrownBy(() -> policy.requireReadAccess(
                ctx(principal("patient.read"), AccessPurpose.TREATMENT, null), "patient-500"))
                .isInstanceOf(PatientAccessDeniedException.class);
    }

    @Test
    void readScopeIsAlwaysRequired() {
        assertThatThrownBy(() -> policy.requireReadAccess(
                ctx(principal("patient.break_glass"), AccessPurpose.EMERGENCY, JUSTIFICATION), "patient-500"))
                .isInstanceOf(PatientAccessDeniedException.class);
        verifyNoInteractions(assignments);
    }

    @Test
    void emergencyWithScopeAndJustificationSkipsAssignmentCheck() {
        assertThatCode(() -> policy.requireReadAccess(
                ctx(principal("patient.read", "patient.break_glass"), AccessPurpose.EMERGENCY, JUSTIFICATION),
                "patient-500"))
                .doesNotThrowAnyException();
        verifyNoInteractions(assignments);
    }

    @Test
    void emergencyWithoutBreakGlassScopeIsDenied() {
        assertThatThrownBy(() -> policy.requireReadAccess(
                ctx(principal("patient.read"), AccessPurpose.EMERGENCY, JUSTIFICATION), "patient-500"))
                .isInstanceOf(PatientAccessDeniedException.class);
    }

    @Test
    void emergencyRejectsMissingShortOrOversizedJustification() {
        ClinicalPrincipal p = principal("patient.read", "patient.break_glass");

        for (String why : new String[] {null, "", "   ", "urgent", "x".repeat(501)}) {
            assertThatThrownBy(() -> policy.requireReadAccess(ctx(p, AccessPurpose.EMERGENCY, why), "patient-500"))
                    .as("justification=%s", why == null ? "null" : "len " + why.length())
                    .isInstanceOf(PatientAccessDeniedException.class);
        }
    }

    @Test
    void eachDataCategoryNeedsItsOwnScope() {
        when(assignments.hasActiveAssignment(any(), any(), any())).thenReturn(true);

        // patient.read alone is not enough for medications or notes.
        for (DataCategory category : new DataCategory[] {DataCategory.MEDICATIONS, DataCategory.CLINICAL_NOTES}) {
            assertThatThrownBy(() -> policy.requireReadAccess(
                    ctx(principal("patient.read"), AccessPurpose.TREATMENT, null), "patient-400", category))
                    .as(category.name())
                    .isInstanceOf(PatientAccessDeniedException.class);
        }

        assertThatCode(() -> policy.requireReadAccess(
                ctx(principal("patient.read", "medication.read"), AccessPurpose.TREATMENT, null),
                "patient-400", DataCategory.MEDICATIONS)).doesNotThrowAnyException();
        assertThatCode(() -> policy.requireReadAccess(
                ctx(principal("patient.read", "notes.read"), AccessPurpose.TREATMENT, null),
                "patient-400", DataCategory.CLINICAL_NOTES)).doesNotThrowAnyException();
    }

    @Test
    void breakGlassReachesMedicationsButNeverNotes() {
        ClinicalPrincipal p = principal("patient.read", "medication.read", "notes.read", "patient.break_glass");

        assertThatCode(() -> policy.requireReadAccess(
                ctx(p, AccessPurpose.EMERGENCY, JUSTIFICATION), "patient-500", DataCategory.MEDICATIONS))
                .doesNotThrowAnyException();

        assertThatThrownBy(() -> policy.requireReadAccess(
                ctx(p, AccessPurpose.EMERGENCY, JUSTIFICATION), "patient-500", DataCategory.CLINICAL_NOTES))
                .isInstanceOf(PatientAccessDeniedException.class);
    }

    @Test
    void rosterNeedsReadScopeAndTreatmentPurpose() {
        assertThatCode(() -> policy.requireRosterAccess(
                ctx(principal("patient.read"), AccessPurpose.TREATMENT, null))).doesNotThrowAnyException();

        assertThatThrownBy(() -> policy.requireRosterAccess(
                ctx(principal("medication.read"), AccessPurpose.TREATMENT, null)))
                .isInstanceOf(PatientAccessDeniedException.class);
        assertThatThrownBy(() -> policy.requireRosterAccess(
                ctx(principal("patient.read", "patient.break_glass"), AccessPurpose.EMERGENCY, JUSTIFICATION)))
                .isInstanceOf(PatientAccessDeniedException.class);
    }

    @Test
    void auditAccessIsASeparateDutyFromPatientAccess() {
        assertThatCode(() -> policy.requireAuditAccess(principal("audit.read"))).doesNotThrowAnyException();

        assertThatThrownBy(() -> policy.requireAuditAccess(
                principal("patient.read", "medication.read", "notes.read", "patient.break_glass")))
                .isInstanceOf(PatientAccessDeniedException.class);
    }

    @Test
    void purposesWithoutDefinedRulesAreDenied() {
        ClinicalPrincipal p = principal("patient.read", "patient.break_glass");

        for (AccessPurpose purpose : new AccessPurpose[] {AccessPurpose.PAYMENT, AccessPurpose.HEALTHCARE_OPERATIONS}) {
            assertThatThrownBy(() -> policy.requireReadAccess(ctx(p, purpose, JUSTIFICATION), "patient-400"))
                    .as(purpose.name())
                    .isInstanceOf(PatientAccessDeniedException.class);
        }
    }

    // ---- break-glass step-up ----

    private static final String STEP_UP = "urn:healthcare:acr:step-up";

    private PatientAccessPolicy withStepUp() {
        return new PatientAccessPolicy(assignments, new BreakGlassProperties(STEP_UP));
    }

    private static ClinicalPrincipal emergencyPrincipal(String acr) {
        return new ClinicalPrincipal("doctor-101", "hospital-A",
                Set.of("patient.read", "patient.break_glass"), "healthcare-mcp-client", acr);
    }

    @Test
    void emergencyNeedsTheStepUpClaimWhenRequired() {
        assertThatCode(() -> withStepUp().requireReadAccess(
                ctx(emergencyPrincipal(STEP_UP), AccessPurpose.EMERGENCY, JUSTIFICATION), "patient-500"))
                .doesNotThrowAnyException();

        assertThatThrownBy(() -> withStepUp().requireReadAccess(
                ctx(emergencyPrincipal(null), AccessPurpose.EMERGENCY, JUSTIFICATION), "patient-500"))
                .isInstanceOf(PatientAccessDeniedException.class);

        assertThatThrownBy(() -> withStepUp().requireReadAccess(
                ctx(emergencyPrincipal("urn:something:else"), AccessPurpose.EMERGENCY, JUSTIFICATION), "patient-500"))
                .isInstanceOf(PatientAccessDeniedException.class);
    }

    @Test
    void stepUpDoesNotAffectTreatment() {
        when(assignments.hasActiveAssignment("hospital-A", "doctor-101", "patient-400")).thenReturn(true);

        assertThatCode(() -> withStepUp().requireReadAccess(
                ctx(emergencyPrincipal(null), AccessPurpose.TREATMENT, null), "patient-400"))
                .doesNotThrowAnyException();
    }
}
