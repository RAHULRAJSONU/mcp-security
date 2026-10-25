package io.github.rahulrajsonu.mcpsecurity.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * Emergency access is chosen by the caller, which may be an AI model, so the
 * token must also prove a recent human step-up: the {@code acr} claim must
 * equal this value, which only the identity provider can issue. Blank turns
 * the check off (local development only).
 */
@ConfigurationProperties("app.security.break-glass")
public record BreakGlassProperties(@DefaultValue("") String requiredAcr) {

    public boolean stepUpRequired() {
        return requiredAcr != null && !requiredAcr.isBlank();
    }
}
