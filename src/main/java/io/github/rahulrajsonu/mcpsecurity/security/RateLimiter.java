package io.github.rahulrajsonu.mcpsecurity.security;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Ticker;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.ConsumptionProbe;
import io.github.bucket4j.TimeMeter;
import io.github.rahulrajsonu.mcpsecurity.config.RateLimitProperties;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

public class RateLimiter {
    public record Decision(boolean allowed, long retryAfterSeconds){}

    private final Cache<String, Bucket> byIp;
    private final Cache<String, Bucket> byToken;
    private final RateLimitProperties props;
    private final TimeMeter timeMeter;
    private final Counter ipRejected, tokenRejected;

    public RateLimiter(RateLimitProperties props, MeterRegistry meters, Ticker ticker, TimeMeter timeMeter){
        this.props=props;
        this.timeMeter=timeMeter;
        this.byIp= newCache(props, ticker);
        this.byToken = newCache(props, ticker);
        this.ipRejected = Counter.builder("mcp.ratelimit.rejected").tag("layer","ip").register(meters);
        this.tokenRejected = Counter.builder("mcp.ratelimit.rejected").tag("layer", "token").register(meters);
    }

    private static Cache<String, Bucket> newCache(RateLimitProperties p, Ticker ticker){
        return Caffeine.newBuilder()
                .maximumSize(p.maxTrackedKeys())
                .expireAfterAccess(p.idleEviction())
                .ticker(ticker)
                .build();
    }
    private Bucket newBucket(int perMinute) {
        return Bucket.builder()
                .addLimit(l -> l.capacity(perMinute).refillGreedy(perMinute, Duration.ofMinutes(1)))
                .withCustomTimePrecision(timeMeter)
                .build();
    }

    public Decision check(String ip, String tokenKey) {
        ConsumptionProbe ipProbe = byIp.get(ip, k -> newBucket(props.ipPerMinute())).tryConsumeAndReturnRemaining(1);
        if (!ipProbe.isConsumed()) { ipRejected.increment(); return deny(ipProbe); }
        if (tokenKey == null) return new Decision(true, 0);

        ConsumptionProbe tp = byToken.get(tokenKey, k -> newBucket(props.tokenPerMinute())).tryConsumeAndReturnRemaining(1);
        if (!tp.isConsumed()) { tokenRejected.increment(); return deny(tp); }
        return new Decision(true, 0);
    }

    /** For tests: how many token buckets are still held after pending evictions run. */
    long trackedTokens() {
        byToken.cleanUp();
        return byToken.estimatedSize();
    }

    private static Decision deny(ConsumptionProbe p) {
        return new Decision(false, Math.max(1, TimeUnit.NANOSECONDS.toSeconds(p.getNanosToWaitForRefill()) + 1));
    }

}
