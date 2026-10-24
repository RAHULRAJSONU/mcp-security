package io.github.rahulrajsonu.mcpsecurity.filter;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import java.time.Duration;

@Configuration
public class JwtSecurityConfig {

    @Bean
    JwtDecoder jwtDecoder(
            @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
            String issuer,
            @Value("${app.security.jwt.audience}")
            String expectedAudience,
            @Value("${app.security.jwt.max-lifetime:PT15M}")
            Duration maxLifetime) {

        // Resolve Keycloak's OIDC metadata and configure JWT decoding.
        NimbusJwtDecoder decoder =
                NimbusJwtDecoder.withIssuerLocation(issuer).build();

        OAuth2TokenValidator<Jwt> issuerValidator =
                JwtValidators.createDefaultWithIssuer(issuer);

        decoder.setJwtValidator(
                new DelegatingOAuth2TokenValidator<>(
                        issuerValidator,
                        audienceValidator(expectedAudience),
                        maxLifetimeValidator(maxLifetime)
                )
        );

        return decoder;
    }

    /**
     * Automatic logoff for a stateless API is the token's lifetime. Rejecting
     * long-lived tokens here means a leaked token expires quickly even if the
     * identity provider is configured generously.
     */
    static OAuth2TokenValidator<Jwt> maxLifetimeValidator(Duration maxLifetime) {

        if (maxLifetime == null || maxLifetime.isNegative() || maxLifetime.isZero()) {
            throw new IllegalArgumentException(
                    "Maximum token lifetime must be positive");
        }

        return jwt -> {
            if (jwt.getIssuedAt() != null
                    && jwt.getExpiresAt() != null
                    && Duration.between(jwt.getIssuedAt(), jwt.getExpiresAt())
                            .compareTo(maxLifetime) <= 0) {
                return OAuth2TokenValidatorResult.success();
            }

            return OAuth2TokenValidatorResult.failure(
                    new OAuth2Error(
                            "invalid_token",
                            "Token lifetime is missing or too long",
                            null
                    )
            );
        };
    }

    static OAuth2TokenValidator<Jwt> audienceValidator(
            String expectedAudience) {

        if (expectedAudience == null || expectedAudience.isBlank()) {
            throw new IllegalArgumentException(
                    "Expected JWT audience must not be blank");
        }

        return jwt -> {
            if (jwt.getAudience() != null
                    && jwt.getAudience().contains(expectedAudience)) {
                return OAuth2TokenValidatorResult.success();
            }

            return OAuth2TokenValidatorResult.failure(
                    new OAuth2Error(
                            "invalid_token",
                            "Token audience is not accepted",
                            null
                    )
            );
        };
    }
}
