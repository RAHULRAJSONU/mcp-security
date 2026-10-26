package io.github.rahulrajsonu.mcpsecurity.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.github.benmanes.caffeine.cache.Ticker;
import io.github.bucket4j.TimeMeter;
import io.github.rahulrajsonu.mcpsecurity.config.AgentControlProperties;
import io.github.rahulrajsonu.mcpsecurity.config.RateLimitProperties;
import io.github.rahulrajsonu.mcpsecurity.mcp.domain.Agent;
import io.github.rahulrajsonu.mcpsecurity.mcp.domain.AgentState;
import io.github.rahulrajsonu.mcpsecurity.persistence.repository.AgentRepository;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** The Caffeine caches report hits, misses and size, so cache time and capacity can be tuned. */
class CaffeineMetricsTest {

    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

    private final MeterRegistry meters = new SimpleMeterRegistry();

    private double gets(String cache, String result) {
        var counter = meters.find("cache.gets").tag("cache", cache).tag("result", result).functionCounter();
        return counter == null ? -1 : counter.count();
    }

    private static ClinicalPrincipal principal() {
        return new ClinicalPrincipal("doctor-101", "hospital-A", Set.of("patient.read"), "agent-1");
    }

    @Test
    void theRegistryCacheReportsItsHitRate() {
        AgentRepository agents = mock(AgentRepository.class);
        when(agents.find("hospital-A", "agent-1", "doctor-101"))
                .thenReturn(Optional.of(new Agent("agent-1", AgentState.APPROVED, NOW.plusSeconds(60))));
        AgentAccessPolicy policy = new AgentAccessPolicy(
                agents, Clock.fixed(NOW, ZoneOffset.UTC), Duration.ofMinutes(1), meters);

        policy.requireActive(principal());
        policy.requireActive(principal());
        policy.requireActive(principal());

        assertThat(gets("agent_registry", "miss")).isEqualTo(1.0);
        assertThat(gets("agent_registry", "hit")).isEqualTo(2.0);
    }

    @Test
    void theQuotaCacheReportsHowManyIdentitiesItTracks() {
        AgentQuota quota = new AgentQuota(
                new AgentControlProperties(10, 100, 100, Duration.ofSeconds(5)), meters,
                Ticker.systemTicker(), TimeMeter.SYSTEM_NANOTIME);

        quota.acquire(principal());
        quota.acquire(new ClinicalPrincipal("doctor-202", "hospital-A", Set.of("patient.read"), "agent-1"));

        assertThat(meters.find("cache.size").tag("cache", "agent_quota").gauge().value()).isEqualTo(2.0);
    }

    @Test
    void theHttpRateLimitCachesAreReportedToo() {
        RateLimiter limiter = new RateLimiter(
                new RateLimitProperties(100, 100, 100, Duration.ofMinutes(5)), meters,
                Ticker.systemTicker(), TimeMeter.SYSTEM_NANOTIME);

        limiter.check("10.0.0.1", "token-hash");
        limiter.check("10.0.0.1", "token-hash");

        assertThat(gets("ratelimit_ip", "miss")).isEqualTo(1.0);
        assertThat(gets("ratelimit_ip", "hit")).isEqualTo(1.0);
        assertThat(gets("ratelimit_token", "miss")).isEqualTo(1.0);
    }

    @Test
    void onlyTheCacheNameIsALabelSoNoIdentifierReachesTheMetrics() {
        AgentRepository agents = mock(AgentRepository.class);
        when(agents.find("hospital-A", "agent-1", "doctor-101")).thenReturn(Optional.empty());
        new AgentAccessPolicy(agents, Clock.fixed(NOW, ZoneOffset.UTC), Duration.ofMinutes(1), meters);

        meters.getMeters().stream()
                .filter(meter -> meter.getId().getName().startsWith("cache."))
                .forEach(meter -> assertThat(meter.getId().getTags())
                        .extracting(tag -> tag.getKey())
                        .isSubsetOf("cache", "result", "cause", "name"));
    }
}
