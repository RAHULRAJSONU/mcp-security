package io.github.rahulrajsonu.mcpsecurity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.github.rahulrajsonu.mcpsecurity.mcp.domain.PatientSummary;
import io.github.rahulrajsonu.mcpsecurity.security.AccessPurpose;
import io.github.rahulrajsonu.mcpsecurity.security.ClinicalAccessContext;
import io.github.rahulrajsonu.mcpsecurity.security.ClinicalPrincipal;
import io.github.rahulrajsonu.mcpsecurity.service.SecuredPatientQueryService;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;

/**
 * The whole path (policy, tenant scoping, row-level security, audit) against a
 * real database seeded with: doctor-101 assigned to patient-400 in hospital-A;
 * patient-500 in hospital-A (unassigned); patient-600 in hospital-B.
 */
class PatientAccessEndToEndIT extends AbstractPostgresIT {

    private static final String WHY = "Unconscious patient in ED, no prior assignment";

    @Autowired
    SecuredPatientQueryService service;

    private final ListAppender<ILoggingEvent> audit = new ListAppender<>();
    private Logger auditLogger;

    @BeforeEach
    void attach() {
        auditLogger = (Logger) LoggerFactory.getLogger("AUDIT.patient-access");
        audit.start();
        auditLogger.addAppender(audit);
    }

    @AfterEach
    void detach() {
        auditLogger.detachAppender(audit);
    }

    private static ClinicalPrincipal doctor(String tenant, String... scopes) {
        return new ClinicalPrincipal("doctor-101", tenant, Set.of(scopes));
    }

    private PatientSummary read(ClinicalPrincipal p, AccessPurpose purpose, String why, String patient) {
        return service.getSummary(new ClinicalAccessContext(p, purpose, why), patient);
    }

    @Test
    void assignedClinicianCanReadForTreatment() {
        PatientSummary summary = read(doctor("hospital-A", "patient.read"), AccessPurpose.TREATMENT, null, "patient-400");

        assertThat(summary.patientId()).isEqualTo("patient-400");
        assertThat(audit.list.getLast().getFormattedMessage()).contains("outcome=ALLOWED");
    }

    @Test
    void unassignedAndCrossTenantAndUnknownAreIndistinguishable() {
        ClinicalPrincipal p = doctor("hospital-A", "patient.read");

        String unassigned = messageOf(() -> read(p, AccessPurpose.TREATMENT, null, "patient-500"));
        String crossTenant = messageOf(() -> read(p, AccessPurpose.TREATMENT, null, "patient-600"));
        String unknown = messageOf(() -> read(p, AccessPurpose.TREATMENT, null, "patient-does-not-exist"));

        assertThat(crossTenant).isEqualTo(unassigned);
        assertThat(unknown).isEqualTo(unassigned);
        assertThat(audit.list).allSatisfy(e -> assertThat(e.getFormattedMessage()).contains("outcome=DENIED"));
    }

    @Test
    void breakGlassReadsUnassignedPatientInOwnTenantAndIsAuditedAsWarning() {
        PatientSummary summary = read(
                doctor("hospital-A", "patient.read", "patient.break_glass"), AccessPurpose.EMERGENCY, WHY, "patient-500");

        assertThat(summary.patientId()).isEqualTo("patient-500");
        ILoggingEvent event = audit.list.getLast();
        assertThat(event.getLevel().toString()).isEqualTo("WARN");
        assertThat(event.getFormattedMessage()).contains("break_glass=true", "outcome=ALLOWED").doesNotContain("Unconscious");
    }

    @Test
    void breakGlassCannotCrossTenants() {
        ClinicalPrincipal p = doctor("hospital-A", "patient.read", "patient.break_glass");

        assertThatThrownBy(() -> read(p, AccessPurpose.EMERGENCY, WHY, "patient-600"))
                .isInstanceOf(AccessDeniedException.class);
        assertThat(audit.list.getLast().getFormattedMessage()).contains("outcome=DENIED", "break_glass=true");
    }

    private static String messageOf(Runnable call) {
        try {
            call.run();
            throw new AssertionError("expected a denial");
        } catch (AccessDeniedException ex) {
            return ex.getMessage();
        }
    }
}
