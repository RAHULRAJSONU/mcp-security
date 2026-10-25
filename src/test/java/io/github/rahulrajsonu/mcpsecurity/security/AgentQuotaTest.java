package io.github.rahulrajsonu.mcpsecurity.security;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.github.benmanes.caffeine.cache.Ticker;
import io.github.bucket4j.TimeMeter;
import io.github.rahulrajsonu.mcpsecurity.config.AgentControlProperties;
import io.github.rahulrajsonu.mcpsecurity.exception.RateLimitExceededException;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.time.Duration;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;

class AgentQuotaTest {

    private final AtomicLong nanos = new AtomicLong();

    private AgentQuota quota(int perMinute, int perDay) {
        AgentControlProperties props = new AgentControlProperties(perMinute, perDay, 100, Duration.ofSeconds(5));
        TimeMeter clock = new TimeMeter() {
            @Override
            public long currentTimeNanos() {
                return nanos.get();
            }

            @Override
            public boolean isWallClockBased() {
                return false;
            }
        };
        Ticker ticker = nanos::get;
        return new AgentQuota(props, new SimpleMeterRegistry(), ticker, clock);
    }

    private static ClinicalPrincipal who(String subject, String client) {
        return new ClinicalPrincipal(subject, "hospital-A", Set.of("patient.read"), client);
    }

    @Test
    void callsOverTheMinuteLimitAreRefused() {
        AgentQuota quota = quota(2, 100);
        ClinicalPrincipal doctor = who("doctor-101", "agent-1");

        quota.acquire(doctor);
        quota.acquire(doctor);

        assertThatThrownBy(() -> quota.acquire(doctor)).isInstanceOf(RateLimitExceededException.class);
    }

    @Test
    void theMinuteBucketRefills() {
        AgentQuota quota = quota(1, 100);
        ClinicalPrincipal doctor = who("doctor-101", "agent-1");
        quota.acquire(doctor);
        assertThatThrownBy(() -> quota.acquire(doctor)).isInstanceOf(RateLimitExceededException.class);

        nanos.addAndGet(Duration.ofMinutes(1).toNanos());

        assertThatCode(() -> quota.acquire(doctor)).doesNotThrowAnyException();
    }

    @Test
    void theDailyCapHoldsEvenWhenTheMinuteBucketRefills() {
        AgentQuota quota = quota(100, 3);
        ClinicalPrincipal doctor = who("doctor-101", "agent-1");

        for (int i = 0; i < 3; i++) {
            quota.acquire(doctor);
            nanos.addAndGet(Duration.ofMinutes(2).toNanos());
        }

        assertThatThrownBy(() -> quota.acquire(doctor)).isInstanceOf(RateLimitExceededException.class);
    }

    @Test
    void eachUserAndClientHasItsOwnBucket() {
        AgentQuota quota = quota(1, 100);
        quota.acquire(who("doctor-101", "agent-1"));

        assertThatCode(() -> quota.acquire(who("doctor-202", "agent-1"))).doesNotThrowAnyException();
        assertThatCode(() -> quota.acquire(who("doctor-101", "agent-2"))).doesNotThrowAnyException();
        assertThatThrownBy(() -> quota.acquire(who("doctor-101", "agent-1")))
                .isInstanceOf(RateLimitExceededException.class);
    }

    @Test
    void aFreshTokenForTheSameIdentityDoesNotResetTheQuota() {
        // The quota is keyed on who is acting, not on the token string.
        AgentQuota quota = quota(1, 100);
        quota.acquire(who("doctor-101", "agent-1"));

        assertThatThrownBy(() -> quota.acquire(who("doctor-101", "agent-1")))
                .isInstanceOf(RateLimitExceededException.class);
    }
}
