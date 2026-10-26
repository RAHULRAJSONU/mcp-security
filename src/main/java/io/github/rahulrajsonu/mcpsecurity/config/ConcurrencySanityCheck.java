package io.github.rahulrajsonu.mcpsecurity.config;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Load shedding only works if the in-flight limit is close to what the database pool can
 * serve. Far above it, calls pile up inside the pool, hit its connection timeout and fail as
 * {@code request_failed} before the limit ever refuses them. Say so at startup instead of
 * letting it show up as errors under the first real burst.
 */
@Component
public class ConcurrencySanityCheck {

    private static final Logger LOG = LoggerFactory.getLogger(ConcurrencySanityCheck.class);

    /** A few more than the pool is fine: they queue briefly. Much more is the trap. */
    static final int MAX_RATIO = 3;

    private final int maxInFlight;
    private final int poolSize;

    public ConcurrencySanityCheck(
            ConcurrencyProperties props,
            @Value("${spring.datasource.hikari.maximum-pool-size:10}") int poolSize) {
        this.maxInFlight = props.maxInFlightCalls();
        this.poolSize = poolSize;
    }

    @PostConstruct
    void check() {
        if (isOversized(maxInFlight, poolSize)) {
            LOG.warn("concurrency_misconfigured max_in_flight_calls={} db_pool_size={}: calls beyond the pool "
                    + "will time out waiting for a connection instead of being refused fast. "
                    + "Keep MAX_IN_FLIGHT_CALLS at about twice DB_POOL_SIZE.", maxInFlight, poolSize);
        }
    }

    static boolean isOversized(int maxInFlight, int poolSize) {
        return maxInFlight > (long) MAX_RATIO * poolSize;
    }
}
