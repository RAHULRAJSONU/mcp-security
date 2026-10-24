package io.github.rahulrajsonu.mcpsecurity.security;

import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

class AccessAuditLoggerTest {

    private final SimpleMeterRegistry meters = new SimpleMeterRegistry();
    private final AccessAuditLogger audit = new AccessAuditLogger(meters);
    private final ListAppender<ILoggingEvent> appender = new ListAppender<>();
    private Logger logger;

    @BeforeEach
    void attach() {
        logger = (Logger) LoggerFactory.getLogger("AUDIT.patient-access");
        appender.start();
        logger.addAppender(appender);
    }

    @AfterEach
    void detach() {
        logger.detachAppender(appender);
    }

    private static ClinicalAccessContext ctx(AccessPurpose purpose, String why) {
        return new ClinicalAccessContext(
                new ClinicalPrincipal("doctor-101", "hospital-A", Set.of("patient.read")), purpose, why);
    }

    @Test
    void routineAccessIsLoggedAtInfoAndCounted() {
        audit.record(ctx(AccessPurpose.TREATMENT, null), "patient-400", AccessAuditLogger.Outcome.ALLOWED);

        ILoggingEvent event = appender.list.getFirst();
        assertThat(event.getLevel()).isEqualTo(Level.INFO);
        assertThat(event.getFormattedMessage())
                .contains("outcome=ALLOWED", "subject=doctor-101", "tenant=hospital-A",
                        "patient=patient-400", "purpose=TREATMENT", "break_glass=false");
        assertThat(meters.get(AccessAuditLogger.METRIC)
                .tag("outcome", "ALLOWED").tag("purpose", "TREATMENT").counter().count()).isEqualTo(1.0);
    }

    @Test
    void metricLabelsNeverCarryPatientOrUserIdentifiers() {
        audit.record(ctx(AccessPurpose.TREATMENT, null), "patient-400", DataCategory.MEDICATIONS, AccessAuditLogger.Outcome.DENIED);

        // Labels must stay low-cardinality and free of identifiers: they go to a metrics system.
        meters.getMeters().forEach(meter -> assertThat(meter.getId().getTags())
                .extracting(tag -> tag.getKey())
                .isSubsetOf("outcome", "purpose", "category"));
        meters.getMeters().forEach(meter -> assertThat(meter.getId().getTags())
                .extracting(tag -> tag.getValue())
                .doesNotContain("patient-400", "doctor-101", "hospital-A"));
    }

    @Test
    void breakGlassIsLoggedAtWarnWithoutTheJustificationText() {
        String secret = "Patient Jane Roe, SSN 000-00-0000, collapsed";
        audit.record(ctx(AccessPurpose.EMERGENCY, secret), "patient-500", AccessAuditLogger.Outcome.ALLOWED);

        ILoggingEvent event = appender.list.getFirst();
        assertThat(event.getLevel()).isEqualTo(Level.WARN);
        assertThat(event.getFormattedMessage())
                .contains("break_glass=true", "justification_chars=" + secret.length())
                .doesNotContain("Jane").doesNotContain("SSN");
    }

    @Test
    void stripsLineBreaksSoCallersCannotForgeAuditEntries() {
        String forged = "patient-1\nAUDIT outcome=ALLOWED subject=admin";

        assertThat(AccessAuditLogger.sanitize(forged))
                .doesNotContain("\n")
                .doesNotContain("\r");
    }

    @Test
    void truncatesOversizedValues() {
        assertThat(AccessAuditLogger.sanitize("x".repeat(500))).hasSize(128);
    }

    @Test
    void marksMissingValues() {
        assertThat(AccessAuditLogger.sanitize(null)).isEqualTo("-");
    }
}
