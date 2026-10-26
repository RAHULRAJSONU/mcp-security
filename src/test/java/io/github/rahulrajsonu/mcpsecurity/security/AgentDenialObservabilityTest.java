package io.github.rahulrajsonu.mcpsecurity.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.github.rahulrajsonu.mcpsecurity.exception.ClinicalAccessDeniedException;
import io.github.rahulrajsonu.mcpsecurity.mcp.domain.Agent;
import io.github.rahulrajsonu.mcpsecurity.mcp.domain.AgentState;
import io.github.rahulrajsonu.mcpsecurity.persistence.repository.AgentRepository;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

/** The caller gets one refusal; the operator gets the reason. */
class AgentDenialObservabilityTest {

    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

    private final AgentRepository agents = mock(AgentRepository.class);
    private final SimpleMeterRegistry meters = new SimpleMeterRegistry();
    private final AgentAccessPolicy policy =
            new AgentAccessPolicy(agents, Clock.fixed(NOW, ZoneOffset.UTC), Duration.ZERO, meters);
    private final ListAppender<ILoggingEvent> appender = new ListAppender<>();
    private Logger logger;

    @BeforeEach
    void attach() {
        logger = (Logger) LoggerFactory.getLogger("AUDIT.agent-access");
        appender.start();
        logger.addAppender(appender);
    }

    @AfterEach
    void detach() {
        logger.detachAppender(appender);
    }

    private static ClinicalPrincipal principal(String client) {
        return new ClinicalPrincipal("doctor-101", "hospital-A", Set.of("patient.read"), client);
    }

    private double denied(String reason) {
        var counter = meters.find("mcp.agent.denied").tag("reason", reason).counter();
        return counter == null ? 0 : counter.count();
    }

    private void refused(String client) {
        assertThatThrownBy(() -> policy.requireActive(principal(client)))
                .isInstanceOf(ClinicalAccessDeniedException.class)
                .hasMessage("Clinical resource access denied");
    }

    @Test
    void eachReasonIsCountedSeparatelyButLooksTheSameToTheCaller() {
        refused(null);

        when(agents.find("hospital-A", "ghost", "doctor-101")).thenReturn(Optional.empty());
        refused("ghost");

        when(agents.find("hospital-A", "paused", "doctor-101"))
                .thenReturn(Optional.of(new Agent("paused", AgentState.SUSPENDED, NOW.plusSeconds(60))));
        refused("paused");

        when(agents.find("hospital-A", "stale", "doctor-101"))
                .thenReturn(Optional.of(new Agent("stale", AgentState.APPROVED, NOW.minusSeconds(1))));
        refused("stale");

        assertThat(denied("no_client")).isEqualTo(1.0);
        assertThat(denied("unknown")).isEqualTo(1.0);
        assertThat(denied("not_approved")).isEqualTo(1.0);
        assertThat(denied("expired")).isEqualTo(1.0);
    }

    @Test
    void anApprovedAgentCountsNothing() {
        when(agents.find("hospital-A", "ok", "doctor-101"))
                .thenReturn(Optional.of(new Agent("ok", AgentState.APPROVED, NOW.plusSeconds(60))));

        policy.requireActive(principal("ok"));

        assertThat(meters.find("mcp.agent.denied").counters()).isEmpty();
        assertThat(appender.list).isEmpty();
    }

    @Test
    void theLogLineNamesTheReasonAndTheAgentAtWarn() {
        when(agents.find("hospital-A", "paused", "doctor-101"))
                .thenReturn(Optional.of(new Agent("paused", AgentState.SUSPENDED, NOW.plusSeconds(60))));
        refused("paused");

        ILoggingEvent event = appender.list.getFirst();
        assertThat(event.getLevel()).isEqualTo(Level.WARN);
        assertThat(event.getFormattedMessage())
                .contains("reason=not_approved", "tenant=hospital-A", "subject=doctor-101", "client=paused");
    }

    @Test
    void aForgedClientIdCannotInjectLogLinesAndTheReasonStaysLowCardinality() {
        String forged = "evil\nWARN agent_denied reason=expired";
        when(agents.find("hospital-A", forged, "doctor-101")).thenReturn(Optional.empty());
        refused(forged);

        assertThat(appender.list).hasSize(1);
        assertThat(appender.list.getFirst().getFormattedMessage()).doesNotContain("\n");
        // The client id is never a metric label: it is attacker-controlled.
        meters.getMeters().stream()
                .filter(meter -> meter.getId().getName().equals("mcp.agent.denied"))
                .forEach(meter -> assertThat(meter.getId().getTags())
                        .extracting(tag -> tag.getKey()).containsOnly("reason"));
    }
}
