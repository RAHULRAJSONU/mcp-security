package io.github.rahulrajsonu.mcpsecurity.config;

import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import java.time.Duration;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

class ConcurrencySanityCheckTest {

    private final ListAppender<ILoggingEvent> appender = new ListAppender<>();
    private Logger logger;

    @BeforeEach
    void attach() {
        logger = (Logger) LoggerFactory.getLogger(ConcurrencySanityCheck.class);
        appender.start();
        logger.addAppender(appender);
    }

    @AfterEach
    void detach() {
        logger.detachAppender(appender);
    }

    private void check(int inFlight, int pool) {
        new ConcurrencySanityCheck(new ConcurrencyProperties(inFlight, Duration.ofMillis(500)), pool).check();
    }

    @Test
    void theDefaultsAreAccepted() {
        check(20, 10);

        assertThat(appender.list).isEmpty();
    }

    @Test
    void upToThreeTimesThePoolIsAccepted() {
        check(30, 10);

        assertThat(appender.list).isEmpty();
    }

    @Test
    void aLimitFarAboveThePoolIsWarnedAbout() {
        check(500, 10);

        assertThat(appender.list).hasSize(1);
        assertThat(appender.list.getFirst().getLevel()).isEqualTo(Level.WARN);
        assertThat(appender.list.getFirst().getFormattedMessage())
                .contains("max_in_flight_calls=500", "db_pool_size=10", "MAX_IN_FLIGHT_CALLS");
    }

    @Test
    void theBoundaryIsExact() {
        assertThat(ConcurrencySanityCheck.isOversized(30, 10)).isFalse();
        assertThat(ConcurrencySanityCheck.isOversized(31, 10)).isTrue();
        assertThat(ConcurrencySanityCheck.isOversized(Integer.MAX_VALUE, Integer.MAX_VALUE)).isFalse();
    }
}
