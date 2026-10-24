package io.github.rahulrajsonu.mcpsecurity.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.github.rahulrajsonu.mcpsecurity.exception.PatientAccessDeniedException;
import io.github.rahulrajsonu.mcpsecurity.exception.RequestFailedException;
import io.github.rahulrajsonu.mcpsecurity.security.AccessPurpose;
import io.github.rahulrajsonu.mcpsecurity.security.ClinicalAccessContext;
import io.github.rahulrajsonu.mcpsecurity.security.ClinicalPrincipal;
import io.github.rahulrajsonu.mcpsecurity.security.DataCategory;
import io.github.rahulrajsonu.mcpsecurity.security.TenantScopedExecutor;
import java.util.Set;
import java.util.function.Supplier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class SecuredPatientQueryServiceTest {

    private final TenantScopedExecutor executor = mock(TenantScopedExecutor.class);
    private final PatientSummaryService summaries = mock(PatientSummaryService.class);
    private final PatientDataService data = mock(PatientDataService.class);
    private final AuditQueryService audit = mock(AuditQueryService.class);
    private final AccessAuditor auditor = mock(AccessAuditor.class);

    private final SecuredPatientQueryService service =
            new SecuredPatientQueryService(executor, summaries, data, audit, auditor);

    private final ClinicalAccessContext context = new ClinicalAccessContext(
            new ClinicalPrincipal("doctor-101", "hospital-A", Set.of("patient.read", "medication.read")),
            AccessPurpose.TREATMENT);

    @BeforeEach
    @SuppressWarnings("unchecked")
    void runOperationsInline() {
        when(executor.execute(any(), any())).thenAnswer(call -> ((Supplier<Object>) call.getArgument(1)).get());
    }

    @Test
    void unexpectedFailuresReachTheCallerAsAFixedMessage() {
        // A driver error can echo data or SQL. The caller, and the model, must not see it.
        when(data.getMedications(any(), any())).thenThrow(new IllegalStateException(
                "could not extract ResultSet for patient Alice Test born 1985-04-12 (SELECT ... FROM medications)"));

        assertThatThrownBy(() -> service.getMedications(context, "patient-400"))
                .isInstanceOf(RequestFailedException.class)
                .hasMessage("Request could not be completed")
                .hasNoCause();

        verify(auditor).failed(context, "patient-400", DataCategory.MEDICATIONS);
    }

    @Test
    void denialsKeepTheirOwnTypeAndAreAuditedAsDenied() {
        when(data.getMedications(any(), any())).thenThrow(new PatientAccessDeniedException());

        assertThatThrownBy(() -> service.getMedications(context, "patient-500"))
                .isInstanceOf(PatientAccessDeniedException.class);

        verify(auditor).denied(context, "patient-500", DataCategory.MEDICATIONS);
    }

    @Test
    void anAllowedReadIsAuditedBeforeItIsReturned() {
        when(data.getMedications(any(), any())).thenReturn(java.util.List.of());

        assertThat(service.getMedications(context, "patient-400")).isEmpty();

        verify(auditor).allowed(context, "patient-400", DataCategory.MEDICATIONS);
    }
}
