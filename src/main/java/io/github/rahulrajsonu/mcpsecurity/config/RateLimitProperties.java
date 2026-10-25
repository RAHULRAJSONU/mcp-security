package io.github.rahulrajsonu.mcpsecurity.config;

import jakarta.validation.constraints.Min;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.time.Duration;

@ConfigurationProperties("app.security.rate-limit")
public record RateLimitProperties(
        @DefaultValue("3000") @Min(1) int ipPerMinute,
        @DefaultValue("600") @Min(1) int tokenPerMinute,
        @DefaultValue("10000") @Min(1) long maxTrackedKeys,
        @DefaultValue("PT5M") Duration idleEviction) {
    public RateLimitProperties{
        if(idleEviction.compareTo(Duration.ofMinutes(1)) < 0){
            throw new IllegalArgumentException("idle-eviction must be at least one minute");
        }
    }
}
