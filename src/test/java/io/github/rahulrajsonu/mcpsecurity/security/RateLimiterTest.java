package io.github.rahulrajsonu.mcpsecurity.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.github.benmanes.caffeine.cache.Ticker;
import io.github.bucket4j.TimeMeter;
import io.github.rahulrajsonu.mcpsecurity.config.RateLimitProperties;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

import java.time.Duration;

import org.junit.jupiter.api.Test;

class RateLimiterTest {

    /** One clock for both Bucket4j refill and Caffeine expiry, so a test moves them together. */
    static final class ManualTime implements TimeMeter, Ticker {
        private long nanos = 1_000_000_000L;

        void advance(Duration d) {
            nanos += d.toNanos();
        }

        @Override public long currentTimeNanos() { return nanos; }
        @Override public boolean isWallClockBased() { return false; }
        @Override public long read() { return nanos; }
    }

    private final ManualTime time = new ManualTime();
    private final SimpleMeterRegistry meters = new SimpleMeterRegistry();

    private RateLimiter limiter(int ipPerMinute, int tokenPerMinute) {
        return limiter(ipPerMinute, tokenPerMinute, 10_000, Duration.ofMinutes(5));
    }

    private RateLimiter limiter(int ip, int token, long maxKeys, Duration idle) {
        return new RateLimiter(new RateLimitProperties(ip, token, maxKeys, idle), meters, time, time);
    }

    private double rejected(String layer) {
        return meters.counter("mcp.ratelimit.rejected", "layer", layer).count();
    }

    @Test
    void a_token_is_refused_once_its_bucket_is_empty() {
        var limiter = limiter(1000, 3);

        assertThat(limiter.check("1.1.1.1", "t").allowed()).isTrue();
        assertThat(limiter.check("1.1.1.1", "t").allowed()).isTrue();
        assertThat(limiter.check("1.1.1.1", "t").allowed()).isTrue();
        assertThat(limiter.check("1.1.1.1", "t").allowed()).isFalse();
        assertThat(rejected("token")).isEqualTo(1);
        assertThat(rejected("ip")).isZero();
    }

    @Test
    void the_bucket_refills_with_time() {
        var limiter = limiter(1000, 60);

        for (int i = 0; i < 60; i++) {
            limiter.check("1.1.1.1", "t");
        }
        assertThat(limiter.check("1.1.1.1", "t").allowed()).isFalse();

        time.advance(Duration.ofSeconds(1)); // 60 per minute is one per second
        assertThat(limiter.check("1.1.1.1", "t").allowed()).isTrue();
    }

    @Test
    void a_new_made_up_token_on_every_request_does_not_dodge_the_limits() {
        var limiter = limiter(100, 10);

        int allowed = 0;
        for (int i = 0; i < 1000; i++) {
            if (limiter.check("6.6.6.6", "invented-token-" + i).allowed()) {
                allowed++;
            }
        }

        assertThat(allowed).isEqualTo(100);      // stopped by the address, not the token
        assertThat(rejected("ip")).isEqualTo(900);
        assertThat(rejected("token")).isZero();  // no invented token ever got as far as its own bucket limit
    }

    @Test
    void one_noisy_address_does_not_starve_another() {
        var limiter = limiter(2, 1000);

        limiter.check("6.6.6.6", null);
        limiter.check("6.6.6.6", null);

        assertThat(limiter.check("6.6.6.6", null).allowed()).isFalse();
        assertThat(limiter.check("7.7.7.7", null).allowed()).isTrue();
    }

    @Test
    void a_request_with_no_token_is_still_limited_by_address() {
        var limiter = limiter(2, 1000);

        assertThat(limiter.check("1.1.1.1", null).allowed()).isTrue();
        assertThat(limiter.check("1.1.1.1", null).allowed()).isTrue();
        assertThat(limiter.check("1.1.1.1", null).allowed()).isFalse();
        assertThat(limiter.trackedTokens()).isZero(); // no token bucket was created
    }

    @Test
    void a_refusal_tells_the_caller_when_to_retry() {
        var limiter = limiter(1000, 60);
        for (int i = 0; i < 60; i++) {
            limiter.check("1.1.1.1", "t");
        }

        var refused = limiter.check("1.1.1.1", "t");

        assertThat(refused.allowed()).isFalse();
        assertThat(refused.retryAfterSeconds()).isBetween(1L, 60L);
    }

    @Test
    void a_refused_request_does_not_spend_the_token_bucket() {
        // The address check runs first. A request it turns away must not also burn the token's allowance.
        var limiter = limiter(1, 2);

        assertThat(limiter.check("1.1.1.1", "t").allowed()).isTrue();   // spends 1 of 2 token allowance
        assertThat(limiter.check("1.1.1.1", "t").allowed()).isFalse();  // refused by address
        assertThat(limiter.check("1.1.1.1", "t").allowed()).isFalse();  // refused by address

        // A different address, same token: the token should still have 1 left, not 0.
        assertThat(limiter.check("2.2.2.2", "t").allowed()).isTrue();
        assertThat(limiter.check("3.3.3.3", "t").allowed()).isFalse();  // now the token is spent
    }

    @Test
    void invented_keys_cannot_grow_memory_without_bound() {
        var limiter = limiter(1_000_000, 10, 100, Duration.ofMinutes(5));

        for (int i = 0; i < 1000; i++) {
            limiter.check("1.1.1.1", "k" + i);
        }

        assertThat(limiter.trackedTokens()).isLessThanOrEqualTo(100);
    }

    @Test
    void idle_buckets_are_forgotten() {
        var limiter = limiter(1_000_000, 10, 10_000, Duration.ofMinutes(5));
        limiter.check("1.1.1.1", "t");
        assertThat(limiter.trackedTokens()).isEqualTo(1);

        time.advance(Duration.ofMinutes(6));

        assertThat(limiter.trackedTokens()).isZero();
    }

    @Test
    void a_drained_bucket_is_not_forgotten_before_it_has_refilled() {
        // If the cache evicted a drained bucket early, its owner would get a full one back.
        var limiter = limiter(1_000_000, 2, 10_000, Duration.ofMinutes(5));
        limiter.check("1.1.1.1", "t");
        limiter.check("1.1.1.1", "t");
        assertThat(limiter.check("1.1.1.1", "t").allowed()).isFalse();

        time.advance(Duration.ofSeconds(20)); // well under the one-minute refill window

        // 2 per minute refills 1 per 30 s, so after 20 s there is still nothing to spend.
        assertThat(limiter.check("1.1.1.1", "t").allowed()).isFalse();
    }

    @Test
    void idle_eviction_shorter_than_the_refill_window_is_rejected() {
        assertThatThrownBy(() -> new RateLimitProperties(10, 10, 100, Duration.ofSeconds(30)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("at least one minute");
    }

    @Test
    void metric_tags_never_carry_an_address_or_token() {
        var limiter = limiter(1, 1);
        limiter.check("9.9.9.9", "secret-token");
        limiter.check("9.9.9.9", "secret-token");

        meters.getMeters().forEach(m -> m.getId().getTags().forEach(tag -> {
            assertThat(tag.getValue()).doesNotContain("9.9.9.9").doesNotContain("secret-token");
        }));
    }
}
