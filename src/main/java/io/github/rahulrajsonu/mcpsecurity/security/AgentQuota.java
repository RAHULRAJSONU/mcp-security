package io.github.rahulrajsonu.mcpsecurity.security;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Ticker;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.TimeMeter;
import io.github.rahulrajsonu.mcpsecurity.config.AgentControlProperties;
import io.github.rahulrajsonu.mcpsecurity.exception.RateLimitExceededException;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.binder.cache.CaffeineCacheMetrics;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.time.Duration;

/**
 * Per-identity quota on tool calls, checked after authentication. The token
 * limit in the HTTP filter is keyed on the raw token, so a refreshed token
 * starts a new bucket; this one is keyed on who is acting (tenant, user,
 * client), so it cannot be reset that way. The daily bucket bounds how much a
 * single agent session can read in bulk.
 */
@Component
public class AgentQuota {

    private final Cache<String, Bucket> buckets;
    private final AgentControlProperties props;
    private final TimeMeter timeMeter;
    private final Counter rejected;

    @Autowired
    public AgentQuota(AgentControlProperties props, MeterRegistry meters) {
        this(props, meters, Ticker.systemTicker(), TimeMeter.SYSTEM_NANOTIME);
    }

    AgentQuota(AgentControlProperties props, MeterRegistry meters, Ticker ticker, TimeMeter timeMeter) {
        this.props = props;
        this.timeMeter = timeMeter;
        this.buckets = Caffeine.newBuilder()
                .maximumSize(props.maxTrackedKeys())
                .expireAfterAccess(Duration.ofHours(25))
                .ticker(ticker)
                .recordStats()
                .build();
        CaffeineCacheMetrics.monitor(meters, this.buckets, "agent_quota");
        this.rejected = Counter.builder("mcp.agent.quota.rejected").register(meters);
    }

    public void acquire(ClinicalPrincipal principal) {
        String key = principal.tenantId() + '|' + principal.subject() + '|' + principal.clientId();

        Bucket bucket = buckets.get(key, k -> Bucket.builder()
                .addLimit(l -> l.capacity(props.callsPerMinute())
                        .refillGreedy(props.callsPerMinute(), Duration.ofMinutes(1)))
                .addLimit(l -> l.capacity(props.callsPerDay())
                        .refillGreedy(props.callsPerDay(), Duration.ofDays(1)))
                .withCustomTimePrecision(timeMeter)
                .build());

        if (!bucket.tryConsume(1)) {
            rejected.increment();
            throw new RateLimitExceededException();
        }
    }
}
