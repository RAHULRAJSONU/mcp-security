package io.github.rahulrajsonu.mcpsecurity.security;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.github.rahulrajsonu.mcpsecurity.config.AgentControlProperties;
import io.github.rahulrajsonu.mcpsecurity.exception.ClinicalAccessDeniedException;
import io.github.rahulrajsonu.mcpsecurity.mcp.domain.Agent;
import io.github.rahulrajsonu.mcpsecurity.mcp.domain.AgentState;
import io.github.rahulrajsonu.mcpsecurity.persistence.repository.AgentRepository;
import io.micrometer.core.instrument.binder.cache.CaffeineCacheMetrics;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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

    private static final Logger AUDIT = LoggerFactory.getLogger("AUDIT.agent-access");

    private final AgentRepository agents;
    private final Clock clock;
    private final Cache<String, Optional<Agent>> lookups;
    private final MeterRegistry meters;

    @Autowired
    public AgentAccessPolicy(AgentRepository agents, Clock clock, AgentControlProperties props, MeterRegistry meters) {
        this(agents, clock, props.registryCacheTtl(), meters);
    }

    AgentAccessPolicy(AgentRepository agents, Clock clock, Duration cacheTtl) {
        this(agents, clock, cacheTtl, new SimpleMeterRegistry());
    }

    AgentAccessPolicy(AgentRepository agents, Clock clock, Duration cacheTtl, MeterRegistry meters) {
        this.agents = agents;
        this.clock = clock;
        this.meters = meters;
        this.lookups = Caffeine.newBuilder()
                .maximumSize(10_000)
                .expireAfterWrite(cacheTtl)
                .recordStats()
                .build();
        // Hit rate shows whether the cache time is doing anything; evictions show it is too small.
        CaffeineCacheMetrics.monitor(meters, this.lookups, "agent_registry");
    }

    public void requireActive(ClinicalPrincipal principal) {
        String clientId = principal.clientId();
        if (clientId == null || clientId.isBlank()) {
            throw denied(principal, "no_client");
        }

        String key = principal.tenantId() + '|' + clientId + '|' + principal.subject();
        Optional<Agent> found = lookups
                .get(key, k -> agents.find(principal.tenantId(), clientId, principal.subject()));
        if (found.isEmpty()) {
            throw denied(principal, "unknown");
        }

        Agent agent = found.get();
        if (agent.state() != AgentState.APPROVED) {
            throw denied(principal, "not_approved");
        }
        if (!agent.expiresAt().isAfter(Instant.now(clock))) {
            throw denied(principal, "expired");
        }
    }

    /**
     * The caller always gets the same refusal. The reason goes only to the
     * operator, as a metric (a small fixed set of values) and a log line.
     */
    private ClinicalAccessDeniedException denied(ClinicalPrincipal principal, String reason) {
        meters.counter("mcp.agent.denied", "reason", reason).increment();
        AUDIT.warn("agent_denied reason={} tenant={} subject={} client={}",
                reason,
                AccessAuditLogger.sanitize(principal.tenantId()),
                AccessAuditLogger.sanitize(principal.subject()),
                AccessAuditLogger.sanitize(principal.clientId()));
        return new ClinicalAccessDeniedException();
    }
}
