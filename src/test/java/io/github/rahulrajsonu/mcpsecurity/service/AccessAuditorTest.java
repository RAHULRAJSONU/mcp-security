package io.github.rahulrajsonu.mcpsecurity.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.github.rahulrajsonu.mcpsecurity.exception.AuditUnavailableException;
import io.github.rahulrajsonu.mcpsecurity.mcp.domain.AccessEvent;
import io.github.rahulrajsonu.mcpsecurity.persistence.repository.AccessEventRepository;
import io.github.rahulrajsonu.mcpsecurity.security.AccessAuditLogger;
import io.github.rahulrajsonu.mcpsecurity.security.AccessPurpose;
import io.github.rahulrajsonu.mcpsecurity.security.ClinicalAccessContext;
import io.github.rahulrajsonu.mcpsecurity.security.ClinicalPrincipal;
import io.github.rahulrajsonu.mcpsecurity.security.DataCategory;
import io.github.rahulrajsonu.mcpsecurity.security.TenantScopedExecutor;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Set;
import java.util.function.Supplier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

class AccessAuditorTest {

    private static final Instant NOW = Instant.parse("2026-03-01T10:00:00Z");

    private final AccessEventRepository events = mock(AccessEventRepository.class);
    private final TenantScopedExecutor executor = mock(TenantScopedExecutor.class);
    private final AccessAuditor auditor = new AccessAuditor(
            new AccessAuditLogger(new SimpleMeterRegistry()),
            events,
            executor,
            Clock.fixed(NOW, ZoneOffset.UTC));

    @BeforeEach
    @SuppressWarnings("unchecked")
    void runInline() {
        when(executor.execute(any(), any())).thenAnswer(call -> ((Supplier<Object>) call.getArgument(1)).get());
    }

    private static ClinicalAccessContext context(String clientId, AccessPurpose purpose, String why) {
        return new ClinicalAccessContext(
                new ClinicalPrincipal("doctor-101", "hospital-A", Set.of("patient.read"), clientId), purpose, why);
    }

    private AccessEvent stored() {
        ArgumentCaptor<AccessEvent> captor = ArgumentCaptor.forClass(AccessEvent.class);
        verify(events).append(eq("hospital-A"), captor.capture());
        return captor.getValue();
    }

    @Test
    void allowedAccessStoresWhoActedAndWhichAgentDidIt() {
        auditor.allowed(context("healthcare-mcp-client", AccessPurpose.TREATMENT, null),
                "patient-400", DataCategory.MEDICATIONS);

        AccessEvent event = stored();
        assertThat(event.occurredAt()).isEqualTo(NOW);
        assertThat(event.subject()).isEqualTo("doctor-101");
        assertThat(event.clientId()).isEqualTo("healthcare-mcp-client");
        assertThat(event.patientId()).isEqualTo("patient-400");
        assertThat(event.category()).isEqualTo("MEDICATIONS");
        assertThat(event.outcome()).isEqualTo("ALLOWED");
        assertThat(event.breakGlass()).isFalse();
        assertThat(event.justification()).isNull();
    }

    @Test
    void aTokenWithoutAClientIsStoredWithoutOne() {
        auditor.denied(context(null, AccessPurpose.TREATMENT, null), "patient-400", DataCategory.PATIENT_SUMMARY);

        assertThat(stored().clientId()).isNull();
    }

    @Test
    void emergencyAccessKeepsTheTrimmedJustification() {
        auditor.allowed(context("c", AccessPurpose.EMERGENCY, "  Unconscious patient in ED  "),
                "patient-500", DataCategory.MEDICATIONS);

        AccessEvent event = stored();
        assertThat(event.breakGlass()).isTrue();
        assertThat(event.justification()).isEqualTo("Unconscious patient in ED");
    }

    @Test
    void justificationIsNeverStoredForRoutineAccess() {
        auditor.allowed(context("c", AccessPurpose.TREATMENT, "should not be kept"),
                "patient-400", DataCategory.PATIENT_SUMMARY);

        assertThat(stored().justification()).isNull();
    }

    @Test
    void longValuesAreTruncatedSoTheyFitTheColumns() {
        auditor.allowed(context("c".repeat(300), AccessPurpose.EMERGENCY, "j".repeat(900)),
                "p".repeat(300), DataCategory.MEDICATIONS);

        AccessEvent event = stored();
        assertThat(event.patientId()).hasSize(128);
        assertThat(event.clientId()).hasSize(128);
        assertThat(event.justification()).hasSize(500);
    }

    @Test
    void anAllowedAccessFailsWhenTheEventCannotBeStored() {
        doThrow(new IllegalStateException("audit store down")).when(events).append(any(), any());

        assertThatThrownBy(() -> auditor.allowed(context("c", AccessPurpose.TREATMENT, null),
                "patient-400", DataCategory.PATIENT_SUMMARY))
                .isInstanceOf(AuditUnavailableException.class)
                .hasMessage("Request could not be completed");
    }

    @Test
    void deniedAndFailedRecordsAreBestEffort() {
        doThrow(new IllegalStateException("audit store down")).when(events).append(any(), any());
        ClinicalAccessContext context = context("c", AccessPurpose.TREATMENT, null);

        assertThatCode(() -> auditor.denied(context, "patient-400", DataCategory.PATIENT_SUMMARY))
                .doesNotThrowAnyException();
        assertThatCode(() -> auditor.failed(context, "patient-400", DataCategory.PATIENT_SUMMARY))
                .doesNotThrowAnyException();
    }
}
