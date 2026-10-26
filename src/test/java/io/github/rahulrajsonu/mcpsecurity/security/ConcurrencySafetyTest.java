package io.github.rahulrajsonu.mcpsecurity.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.github.benmanes.caffeine.cache.Ticker;
import io.github.bucket4j.TimeMeter;
import io.github.rahulrajsonu.mcpsecurity.config.AgentControlProperties;
import io.github.rahulrajsonu.mcpsecurity.config.RateLimitProperties;
import io.github.rahulrajsonu.mcpsecurity.exception.RateLimitExceededException;
import io.github.rahulrajsonu.mcpsecurity.mcp.domain.Agent;
import io.github.rahulrajsonu.mcpsecurity.mcp.domain.AgentState;
import io.github.rahulrajsonu.mcpsecurity.persistence.repository.AgentRepository;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.IntPredicate;
import org.junit.jupiter.api.Test;

/**
 * The limits and caches are shared by every request thread. These tests release many
 * threads at once and check the outcome is exact, not merely plausible.
 */
class ConcurrencySafetyTest {

    private static final int THREADS = 400;

    /** Runs {@code task} on THREADS virtual threads released together; returns how many returned true. */
    private static int stampede(IntPredicate task) throws Exception {
        CountDownLatch go = new CountDownLatch(1);
        AtomicInteger yes = new AtomicInteger();
        try (ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Future<?>> futures = new ArrayList<>();
            for (int i = 0; i < THREADS; i++) {
                int n = i;
                futures.add(pool.submit(() -> {
                    go.await();
                    if (task.test(n)) {
                        yes.incrementAndGet();
                    }
                    return null;
                }));
            }
            go.countDown();
            for (Future<?> future : futures) {
                future.get(30, TimeUnit.SECONDS);
            }
        }
        return yes.get();
    }

    private static ClinicalPrincipal who(String subject) {
        return new ClinicalPrincipal(subject, "hospital-A", Set.of("patient.read"), "agent-1");
    }

    @Test
    void theQuotaAdmitsExactlyItsCapacityNoMatterHowManyRaceForIt() throws Exception {
        // Frozen clock, so nothing refills mid-test: exactly 50 of 400 may pass.
        TimeMeter frozen = new TimeMeter() {
            @Override
            public long currentTimeNanos() {
                return 1_000_000_000L;
            }

            @Override
            public boolean isWallClockBased() {
                return false;
            }
        };
        AgentQuota quota = new AgentQuota(
                new AgentControlProperties(50, 1000, 100, Duration.ofSeconds(5)),
                new SimpleMeterRegistry(), () -> 1_000_000_000L, frozen);
        ClinicalPrincipal doctor = who("doctor-101");

        int admitted = stampede(n -> {
            try {
                quota.acquire(doctor);
                return true;
            } catch (RateLimitExceededException ex) {
                return false;
            }
        });

        assertThat(admitted).isEqualTo(50);
    }

    @Test
    void identitiesDoNotShareABucketUnderContention() throws Exception {
        TimeMeter frozen = new TimeMeter() {
            @Override
            public long currentTimeNanos() {
                return 1_000_000_000L;
            }

            @Override
            public boolean isWallClockBased() {
                return false;
            }
        };
        AgentQuota quota = new AgentQuota(
                new AgentControlProperties(5, 1000, 1000, Duration.ofSeconds(5)),
                new SimpleMeterRegistry(), () -> 1_000_000_000L, frozen);

        // 400 callers spread over 80 identities, each allowed 5: all 400 fit exactly.
        int admitted = stampede(n -> {
            try {
                quota.acquire(who("user-" + (n % 80)));
                return true;
            } catch (RateLimitExceededException ex) {
                return false;
            }
        });

        assertThat(admitted).isEqualTo(400);
    }

    @Test
    void theHttpRateLimitAdmitsExactlyItsCapacityPerAddress() throws Exception {
        TimeMeter frozen = new TimeMeter() {
            @Override
            public long currentTimeNanos() {
                return 1_000_000_000L;
            }

            @Override
            public boolean isWallClockBased() {
                return false;
            }
        };
        RateLimiter limiter = new RateLimiter(
                new RateLimitProperties(100, 100_000, 1000, Duration.ofMinutes(5)),
                new SimpleMeterRegistry(), () -> 1_000_000_000L, frozen);

        int admitted = stampede(n -> limiter.check("203.0.113.9", "token-" + n).allowed());

        assertThat(admitted).isEqualTo(100);
    }

    @Test
    void aStampedeOnOneAgentLoadsItFromTheDatabaseOnce() throws Exception {
        AgentRepository agents = mock(AgentRepository.class);
        when(agents.find("hospital-A", "agent-1", "doctor-101")).thenAnswer(call -> {
            Thread.sleep(50);   // a slow lookup, so many callers arrive while it is loading
            return Optional.of(new Agent("agent-1", AgentState.APPROVED, Instant.parse("2027-01-01T00:00:00Z")));
        });
        AgentAccessPolicy policy = new AgentAccessPolicy(
                agents, Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC),
                Duration.ofMinutes(1), new SimpleMeterRegistry());
        ClinicalPrincipal doctor = who("doctor-101");

        int allowed = stampede(n -> {
            policy.requireActive(doctor);
            return true;
        });

        assertThat(allowed).isEqualTo(THREADS);
        // No thundering herd: 400 simultaneous callers, one query.
        verify(agents, times(1)).find("hospital-A", "agent-1", "doctor-101");
    }
}
