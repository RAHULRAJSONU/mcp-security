package io.github.rahulrajsonu.mcpsecurity.security;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.github.rahulrajsonu.mcpsecurity.config.AgentControlProperties;
import io.github.rahulrajsonu.mcpsecurity.exception.ClinicalAccessDeniedException;
import io.github.rahulrajsonu.mcpsecurity.mcp.domain.Agent;
import io.github.rahulrajsonu.mcpsecurity.mcp.domain.AgentState;
import io.github.rahulrajsonu.mcpsecurity.persistence.repository.AgentRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

/**
 * Only a registered, approved, unexpired agent may act, and only for the user
 * it was registered for. Fails closed: a token with no client id, an unknown
 * client or user, or any other state is denied with the same message, so the
 * caller cannot tell which check failed.
 *
 * Must run inside {@link TenantScopedExecutor}, because the agents table is
 * under row-level security. Lookups are reused for a few seconds to spare the
 * database on every call; expiry is still judged against the clock each time,
 * and a suspension takes effect within the cache time.
 */
@Component
public class AgentAccessPolicy {

    private final AgentRepository agents;
    private final Clock clock;
    private final Cache<String, Optional<Agent>> lookups;

    @Autowired
    public AgentAccessPolicy(AgentRepository agents, Clock clock, AgentControlProperties props) {
        this(agents, clock, props.registryCacheTtl());
    }

    AgentAccessPolicy(AgentRepository agents, Clock clock, Duration cacheTtl) {
        this.agents = agents;
        this.clock = clock;
        this.lookups = Caffeine.newBuilder()
                .maximumSize(10_000)
                .expireAfterWrite(cacheTtl)
                .build();
    }

    public void requireActive(ClinicalPrincipal principal) {
        String clientId = principal.clientId();
        if (clientId == null || clientId.isBlank()) {
            throw new ClinicalAccessDeniedException();
        }

        String key = principal.tenantId() + '|' + clientId + '|' + principal.subject();
        Agent agent = lookups
                .get(key, k -> agents.find(principal.tenantId(), clientId, principal.subject()))
                .orElseThrow(ClinicalAccessDeniedException::new);

        if (agent.state() != AgentState.APPROVED
                || !agent.expiresAt().isAfter(Instant.now(clock))) {
            throw new ClinicalAccessDeniedException();
        }
    }
}
