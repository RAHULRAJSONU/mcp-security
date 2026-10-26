package io.github.rahulrajsonu.mcpsecurity.security;

import io.github.rahulrajsonu.mcpsecurity.config.ConcurrencyProperties;
import io.github.rahulrajsonu.mcpsecurity.exception.ServerBusyException;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.stereotype.Component;

import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

/**
 * Load shedding for the database-bound part of a call. A call that cannot get a place
 * within {@code maxWait} is refused at once with {@link ServerBusyException}, before it
 * holds a connection, so a burst degrades into quick retryable refusals and the calls
 * already running keep their latency. Cheap to block on: callers are virtual threads.
 */
@Component
public class CallBulkhead {

    private final Semaphore places;
    private final int max;
    private final long maxWaitNanos;
    private final Counter rejected;

    public CallBulkhead(ConcurrencyProperties props, MeterRegistry meters) {
        this.max = props.maxInFlightCalls();
        this.places = new Semaphore(max);
        this.maxWaitNanos = props.maxWait().toNanos();
        this.rejected = Counter.builder("mcp.bulkhead.rejected")
                .description("Calls refused because too many were already in flight")
                .register(meters);
        Gauge.builder("mcp.bulkhead.in.flight", this, CallBulkhead::inFlight)
                .description("Calls currently running or waiting for a connection")
                .register(meters);
    }

    public <T> T run(Supplier<T> work) {
        boolean acquired;
        try {
            acquired = places.tryAcquire(maxWaitNanos, TimeUnit.NANOSECONDS);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            rejected.increment();
            throw new ServerBusyException();
        }
        if (!acquired) {
            rejected.increment();
            throw new ServerBusyException();
        }
        try {
            return work.get();
        } finally {
            places.release();
        }
    }

    int inFlight() {
        return max - places.availablePermits();
    }
}
