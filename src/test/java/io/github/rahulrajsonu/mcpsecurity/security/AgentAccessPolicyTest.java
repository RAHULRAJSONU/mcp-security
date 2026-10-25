package io.github.rahulrajsonu.mcpsecurity.security;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.github.rahulrajsonu.mcpsecurity.exception.ClinicalAccessDeniedException;
import io.github.rahulrajsonu.mcpsecurity.mcp.domain.Agent;
import io.github.rahulrajsonu.mcpsecurity.mcp.domain.AgentState;
import io.github.rahulrajsonu.mcpsecurity.persistence.repository.AgentRepository;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;

class AgentAccessPolicyTest {

    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

    private final AgentRepository agents = mock(AgentRepository.class);
    private final Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);

    /** No lookup reuse, so each case sees the registry as the test just set it. */
    private final AgentAccessPolicy policy = new AgentAccessPolicy(agents, clock, Duration.ZERO);

    private static ClinicalPrincipal principal(String subject, String clientId) {
        return new ClinicalPrincipal(subject, "hospital-A", Set.of("patient.read"), clientId);
    }

    private static ClinicalPrincipal principal(String clientId) {
        return principal("doctor-101", clientId);
    }

    private void registered(AgentState state, Instant expiresAt) {
        when(agents.find("hospital-A", "agent-1", "doctor-101"))
                .thenReturn(Optional.of(new Agent("agent-1", state, expiresAt)));
    }

    @Test
    void approvedUnexpiredAgentIsAllowed() {
        registered(AgentState.APPROVED, NOW.plusSeconds(60));

        assertThatCode(() -> policy.requireActive(principal("agent-1"))).doesNotThrowAnyException();
    }

    @Test
    void agentThatIsNotApprovedIsDenied() {
        for (AgentState state : AgentState.values()) {
            if (state == AgentState.APPROVED) {
                continue;
            }
            registered(state, NOW.plusSeconds(60));

            assertThatThrownBy(() -> policy.requireActive(principal("agent-1")))
                    .isInstanceOf(ClinicalAccessDeniedException.class);
        }
    }

    @Test
    void expiredAgentIsDenied() {
        registered(AgentState.APPROVED, NOW.minusSeconds(1));

        assertThatThrownBy(() -> policy.requireActive(principal("agent-1")))
                .isInstanceOf(ClinicalAccessDeniedException.class);
    }

    @Test
    void agentExpiringExactlyNowIsDenied() {
        registered(AgentState.APPROVED, NOW);

        assertThatThrownBy(() -> policy.requireActive(principal("agent-1")))
                .isInstanceOf(ClinicalAccessDeniedException.class);
    }

    @Test
    void unknownAgentIsDenied() {
        when(agents.find("hospital-A", "agent-1", "doctor-101")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> policy.requireActive(principal("agent-1")))
                .isInstanceOf(ClinicalAccessDeniedException.class);
    }

    @Test
    void approvalForOneUserDoesNotCoverAnother() {
        registered(AgentState.APPROVED, NOW.plusSeconds(60));
        when(agents.find("hospital-A", "agent-1", "doctor-202")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> policy.requireActive(principal("doctor-202", "agent-1")))
                .isInstanceOf(ClinicalAccessDeniedException.class);
    }

    @Test
    void tokenWithoutClientIdIsDenied() {
        assertThatThrownBy(() -> policy.requireActive(principal(null)))
                .isInstanceOf(ClinicalAccessDeniedException.class);
        assertThatThrownBy(() -> policy.requireActive(principal(" ")))
                .isInstanceOf(ClinicalAccessDeniedException.class);
    }

    @Test
    void lookupsAreReusedWithinTheCacheTime() {
        AgentAccessPolicy cached = new AgentAccessPolicy(agents, clock, Duration.ofMinutes(1));
        registered(AgentState.APPROVED, NOW.plusSeconds(60));

        cached.requireActive(principal("agent-1"));
        cached.requireActive(principal("agent-1"));

        verify(agents, times(1)).find("hospital-A", "agent-1", "doctor-101");
    }

    @Test
    void expiryIsStillJudgedAgainstTheClockWhenTheLookupIsReused() {
        java.util.concurrent.atomic.AtomicReference<Instant> now = new java.util.concurrent.atomic.AtomicReference<>(NOW);
        Clock moving = new Clock() {
            @Override
            public java.time.ZoneId getZone() {
                return ZoneOffset.UTC;
            }

            @Override
            public Clock withZone(java.time.ZoneId zone) {
                return this;
            }

            @Override
            public Instant instant() {
                return now.get();
            }
        };
        AgentAccessPolicy cached = new AgentAccessPolicy(agents, moving, Duration.ofHours(1));
        registered(AgentState.APPROVED, NOW.plusSeconds(1));
        cached.requireActive(principal("agent-1"));

        now.set(NOW.plusSeconds(5));

        assertThatThrownBy(() -> cached.requireActive(principal("agent-1")))
                .isInstanceOf(ClinicalAccessDeniedException.class);
        verify(agents, times(1)).find("hospital-A", "agent-1", "doctor-101");
    }
}
