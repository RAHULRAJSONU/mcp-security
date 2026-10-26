package io.github.rahulrajsonu.mcpsecurity.config;

import jakarta.validation.constraints.Min;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.time.Duration;

/**
 * Virtual threads make it cheap to accept far more requests than the database can
 * serve. This bounds the database-bound work so overload turns into a fast, retryable
 * refusal instead of a queue that times out.
 *
 * @param maxInFlightCalls tool calls allowed to run (or wait for a connection) at once.
 *                         Start at about twice the database pool size (DB_POOL_SIZE).
 * @param maxWait          how long a call may wait for a place before it is refused. Keep it
 *                         well under the pool's connection timeout (3 s).
 */
@ConfigurationProperties("app.concurrency")
public record ConcurrencyProperties(
        @DefaultValue("20") @Min(1) int maxInFlightCalls,
        @DefaultValue("PT0.5S") Duration maxWait) {

    public ConcurrencyProperties {
        if (maxWait == null || maxWait.isNegative()) {
            throw new IllegalArgumentException("max-wait must not be negative");
        }
    }
}
