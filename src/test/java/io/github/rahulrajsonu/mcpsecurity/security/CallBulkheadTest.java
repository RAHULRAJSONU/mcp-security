package io.github.rahulrajsonu.mcpsecurity.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.rahulrajsonu.mcpsecurity.config.ConcurrencyProperties;
import io.github.rahulrajsonu.mcpsecurity.exception.ServerBusyException;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class CallBulkheadTest {

    private final MeterRegistry meters = new SimpleMeterRegistry();

    private CallBulkhead bulkhead(int places, Duration wait) {
        return new CallBulkhead(new ConcurrencyProperties(places, wait), meters);
    }

    private double rejected() {
        return meters.get("mcp.bulkhead.rejected").counter().count();
    }

    /** Occupies {@code count} places until the returned latch is released. */
    private List<Future<Object>> hold(CallBulkhead bulkhead, ExecutorService pool, int count, CountDownLatch release)
            throws InterruptedException {
        CountDownLatch started = new CountDownLatch(count);
        List<Future<Object>> held = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            held.add(pool.submit(() -> bulkhead.run(() -> {
                started.countDown();
                try {
                    release.await();
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                }
                return null;
            })));
        }
        assertThat(started.await(5, TimeUnit.SECONDS)).isTrue();
        return held;
    }

    @Test
    void runsTheWorkAndReturnsItsResult() {
        assertThat(bulkhead(2, Duration.ofMillis(50)).run(() -> "done")).isEqualTo("done");
    }

    @Test
    void refusesFastWhenEveryPlaceIsTaken() throws Exception {
        CallBulkhead bulkhead = bulkhead(2, Duration.ofMillis(50));
        CountDownLatch release = new CountDownLatch(1);
        try (ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor()) {
            hold(bulkhead, pool, 2, release);

            long start = System.nanoTime();
            assertThatThrownBy(() -> bulkhead.run(() -> "never")).isInstanceOf(ServerBusyException.class);
            long waitedMillis = Duration.ofNanos(System.nanoTime() - start).toMillis();

            assertThat(waitedMillis).as("refused after about max-wait, not after the work finished").isLessThan(1000);
            assertThat(rejected()).isEqualTo(1.0);
            release.countDown();
        }
    }

    @Test
    void theWorkNeverRunsWhenRefused() throws Exception {
        CallBulkhead bulkhead = bulkhead(1, Duration.ZERO);
        CountDownLatch release = new CountDownLatch(1);
        AtomicInteger ran = new AtomicInteger();
        try (ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor()) {
            hold(bulkhead, pool, 1, release);

            assertThatThrownBy(() -> bulkhead.run(ran::incrementAndGet)).isInstanceOf(ServerBusyException.class);

            assertThat(ran).hasValue(0);
            release.countDown();
        }
    }

    @Test
    void aPlaceIsFreedWhenTheWorkFails() {
        CallBulkhead bulkhead = bulkhead(1, Duration.ZERO);

        for (int i = 0; i < 5; i++) {
            assertThatThrownBy(() -> bulkhead.run(() -> {
                throw new IllegalStateException("boom");
            })).isInstanceOf(IllegalStateException.class);
        }

        // If a failure leaked its place, this would now be refused.
        assertThat(bulkhead.run(() -> "still works")).isEqualTo("still works");
        assertThat(bulkhead.inFlight()).isZero();
    }

    @Test
    void placesComeBackOnceHeldWorkFinishes() throws Exception {
        CallBulkhead bulkhead = bulkhead(2, Duration.ofMillis(20));
        CountDownLatch release = new CountDownLatch(1);
        try (ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Future<Object>> held = hold(bulkhead, pool, 2, release);
            assertThatThrownBy(() -> bulkhead.run(() -> "x")).isInstanceOf(ServerBusyException.class);

            release.countDown();
            for (Future<Object> future : held) {
                future.get(5, TimeUnit.SECONDS);
            }

            assertThat(bulkhead.run(() -> "recovered")).isEqualTo("recovered");
        }
    }

    @Test
    void theInFlightGaugeTracksHeldPlaces() throws Exception {
        CallBulkhead bulkhead = bulkhead(3, Duration.ofMillis(20));
        CountDownLatch release = new CountDownLatch(1);
        try (ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor()) {
            hold(bulkhead, pool, 2, release);

            assertThat(meters.get("mcp.bulkhead.in.flight").gauge().value()).isEqualTo(2.0);
            release.countDown();
        }
    }

    @Test
    void neverMoreThanTheLimitRunAtOnceUnderHeavyContention() throws Exception {
        int places = 8;
        CallBulkhead bulkhead = bulkhead(places, Duration.ofSeconds(10));
        AtomicInteger running = new AtomicInteger();
        AtomicInteger highWater = new AtomicInteger();
        AtomicInteger completed = new AtomicInteger();

        try (ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Future<?>> futures = new ArrayList<>();
            for (int i = 0; i < 500; i++) {
                futures.add(pool.submit(() -> bulkhead.run(() -> {
                    int now = running.incrementAndGet();
                    highWater.accumulateAndGet(now, Math::max);
                    Thread.onSpinWait();
                    running.decrementAndGet();
                    completed.incrementAndGet();
                    return null;
                })));
            }
            for (Future<?> future : futures) {
                future.get(30, TimeUnit.SECONDS);
            }
        }

        assertThat(completed).hasValue(500);
        assertThat(highWater.get()).isLessThanOrEqualTo(places);
        assertThat(bulkhead.inFlight()).isZero();
    }
}
