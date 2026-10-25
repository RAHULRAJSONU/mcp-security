package io.github.rahulrajsonu.mcpsecurity.config;

import jakarta.validation.constraints.Min;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.time.Duration;

/**
 * Limits on what one agent acting for one user may do.
 *
 * @param callsPerMinute   tool calls per minute for one (tenant, user, client)
 * @param callsPerDay      tool calls per day for one (tenant, user, client); bounds bulk reading
 * @param maxTrackedKeys   how many identities are tracked at once
 * @param registryCacheTtl how long a registry lookup is reused; suspending an agent takes effect within this time
 */
@ConfigurationProperties("app.security.agent")
public record AgentControlProperties(
        @DefaultValue("120") @Min(1) int callsPerMinute,
        @DefaultValue("5000") @Min(1) int callsPerDay,
        @DefaultValue("10000") @Min(1) long maxTrackedKeys,
        @DefaultValue("PT5S") Duration registryCacheTtl) {

    public AgentControlProperties {
        if (registryCacheTtl == null || registryCacheTtl.isNegative()) {
            throw new IllegalArgumentException("registry-cache-ttl must not be negative");
        }
    }
}
