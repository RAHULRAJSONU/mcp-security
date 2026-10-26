package io.github.rahulrajsonu.mcpsecurity.security;

import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

/** The audit log line names the agent that acted, and the client id is caller-controlled input. */
class AccessAuditLoggerClientTest {

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

    private static ClinicalAccessContext ctx(String clientId) {
        return new ClinicalAccessContext(
                new ClinicalPrincipal("doctor-101", "hospital-A", Set.of("patient.read"), clientId),
                AccessPurpose.TREATMENT);
    }

    @Test
    void theLineNamesTheClient() {
        audit.record(ctx("healthcare-mcp-client"), "patient-400", AccessAuditLogger.Outcome.ALLOWED);

        assertThat(appender.list.getFirst().getFormattedMessage())
                .contains("client=healthcare-mcp-client");
    }

    @Test
    void aMissingClientIsShownAsADash() {
        audit.record(ctx(null), "patient-400", AccessAuditLogger.Outcome.DENIED);

        assertThat(appender.list.getFirst().getFormattedMessage()).contains("client=-");
    }

    @Test
    void aForgedClientIdCannotInjectLogLines() {
        audit.record(ctx("agent\nINFO patient_access outcome=ALLOWED subject=attacker"),
                "patient-400", AccessAuditLogger.Outcome.DENIED);

        assertThat(appender.list).hasSize(1);
        assertThat(appender.list.getFirst().getFormattedMessage()).doesNotContain("\n").doesNotContain("\r");
    }

    @Test
    void theClientIsNotAMetricLabelBecauseItWouldBlowUpCardinality() {
        audit.record(ctx("healthcare-mcp-client"), "patient-400", AccessAuditLogger.Outcome.ALLOWED);

        meters.getMeters().forEach(meter -> assertThat(meter.getId().getTags())
                .extracting(tag -> tag.getKey())
                .doesNotContain("client", "client_id", "clientId"));
    }

    @Test
    void theLineNamesTheActorChainAndSanitizesIt() {
        ClinicalAccessContext context = new ClinicalAccessContext(
                new ClinicalPrincipal("doctor-101", "hospital-A", Set.of("patient.read"), "c", null,
                        "agent-a>evil\nINFO forged"),
                AccessPurpose.TREATMENT);

        audit.record(context, "patient-400", AccessAuditLogger.Outcome.ALLOWED);

        assertThat(appender.list).hasSize(1);
        assertThat(appender.list.getFirst().getFormattedMessage()).contains("actor=agent-a>evil").doesNotContain("\n");
    }

    @Test
    void noActorIsShownAsADash() {
        audit.record(ctx("c"), "patient-400", AccessAuditLogger.Outcome.ALLOWED);

        assertThat(appender.list.getFirst().getFormattedMessage()).contains("actor=-");
    }
}
