package io.github.rahulrajsonu.mcpsecurity.config;

import com.github.benmanes.caffeine.cache.Ticker;
import io.github.bucket4j.TimeMeter;
import io.github.rahulrajsonu.mcpsecurity.security.RateLimiter;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(RateLimitProperties.class)
public class RateLimitConfig {

    @Bean
    RateLimiter rateLimiter(RateLimitProperties props, MeterRegistry meters){
        return new RateLimiter(props, meters, Ticker.systemTicker(), TimeMeter.SYSTEM_NANOTIME);
    }
}
