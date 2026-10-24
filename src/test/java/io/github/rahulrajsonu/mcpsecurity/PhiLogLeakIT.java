package io.github.rahulrajsonu.mcpsecurity;

import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.IThrowableProxy;
import ch.qos.logback.core.read.ListAppender;
import io.github.rahulrajsonu.mcpsecurity.mcp.tool.AuditMcpTools;
import io.github.rahulrajsonu.mcpsecurity.mcp.tool.PatientMcpTools;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

/**
 * Runs every kind of access (allowed, denied, emergency, audit) with the root
 * logger turned up to DEBUG, captures every line from every library, and fails
 * if any seeded PHI or the caller's free-text justification appears.
 */
class PhiLogLeakIT extends AbstractPostgresIT {

    private static final String JUSTIFICATION = "Collapsed at the entrance, unknown history " + UUID.randomUUID();

    /** Seeded values that must never be logged. */
    private static final List<String> PHI = List.of(
            "Alice", "Bob", "Carol",
            "1985-04-12", "1990-07-21", "1978-11-03",
            "MRN-A-400", "MRN-A-500", "MRN-B-600",
            "Lisinopril", "Atorvastatin", "Metformin", "Levothyroxine",
            "blood pressure controlled", "glucose within target",
            JUSTIFICATION);

    @Autowired
    PatientMcpTools patientTools;

    @Autowired
    AuditMcpTools auditTools;

    private final ListAppender<ILoggingEvent> captured = new ListAppender<>();
    private Logger root;
    private Level originalLevel;

    @BeforeEach
    void capture() {
        root = (Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
        originalLevel = root.getLevel();
        root.setLevel(Level.DEBUG);
        captured.start();
        root.addAppender(captured);
    }

    @AfterEach
    void release() {
        root.detachAppender(captured);
        root.setLevel(originalLevel);
        SecurityContextHolder.clearContext();
    }

    private static void loginAs(String subject, String scopes) {
        Jwt jwt = Jwt.withTokenValue("test").header("alg", "none").subject(subject)
                .claim("tenant_id", "hospital-A").claim("scope", scopes)
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60)).build();
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt, List.of()));
    }

    private static String render(ILoggingEvent event) {
        StringBuilder text = new StringBuilder(event.getFormattedMessage());
        for (IThrowableProxy t = event.getThrowableProxy(); t != null; t = t.getCause()) {
            text.append(' ').append(t.getMessage());
        }
        return text.toString();
    }

    @Test
    void noPhiOrJustificationTextReachesAnyLogLine() {
        loginAs("doctor-101", "patient.read medication.read notes.read patient.break_glass");

        patientTools.getPatientSummary("patient-400", null, null);
        patientTools.getPatientMedications("patient-400", null, null);
        patientTools.getClinicalNotes("patient-400", null, null);
        patientTools.listMyPatients();
        patientTools.getPatientMedications("patient-500", "EMERGENCY", JUSTIFICATION);
        try {
            patientTools.getPatientSummary("patient-500", null, null);   // denied
        } catch (RuntimeException expected) {
            // refusals are the point
        }

        loginAs("compliance-1", "audit.read");
        auditTools.getAccessHistory("patient-500", 50);
        auditTools.listBreakGlassEvents(50);

        assertThat(captured.list).as("the run produced log output to inspect").isNotEmpty();

        for (ILoggingEvent event : captured.list) {
            assertThat(render(event))
                    .as("[%s] %s", event.getLoggerName(), event.getFormattedMessage())
                    .doesNotContain(PHI);
        }
    }
}
