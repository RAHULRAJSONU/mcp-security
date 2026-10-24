package io.github.rahulrajsonu.mcpsecurity.filter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;

class TokenLifetimeValidatorTest {

    private final OAuth2TokenValidator<Jwt> validator =
            JwtSecurityConfig.maxLifetimeValidator(Duration.ofMinutes(15));

    private static Jwt token(Instant issuedAt, Instant expiresAt) {
        Jwt.Builder jwt = Jwt.withTokenValue("t").header("alg", "none").subject("doctor-101");
        if (issuedAt != null) {
            jwt.issuedAt(issuedAt);
        }
        if (expiresAt != null) {
            jwt.expiresAt(expiresAt);
        }
        return jwt.claim("sub", "doctor-101").build();
    }

    @Test
    void acceptsAShortLivedToken() {
        Instant now = Instant.now();

        assertThat(validator.validate(token(now, now.plus(Duration.ofMinutes(5)))).hasErrors()).isFalse();
    }

    @Test
    void acceptsATokenExactlyAtTheLimit() {
        Instant now = Instant.now();

        assertThat(validator.validate(token(now, now.plus(Duration.ofMinutes(15)))).hasErrors()).isFalse();
    }

    @Test
    void rejectsATokenLivingLongerThanTheLimit() {
        Instant now = Instant.now();

        assertThat(validator.validate(token(now, now.plus(Duration.ofHours(8)))).hasErrors()).isTrue();
    }

    @Test
    void rejectsATokenWithoutIssuedAtOrExpiry() {
        Instant now = Instant.now();

        assertThat(validator.validate(token(null, now.plusSeconds(60))).hasErrors()).isTrue();
        assertThat(validator.validate(token(now, null)).hasErrors()).isTrue();
    }

    @Test
    void refusesANonsensicalLimit() {
        assertThatThrownBy(() -> JwtSecurityConfig.maxLifetimeValidator(Duration.ZERO))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> JwtSecurityConfig.maxLifetimeValidator(null))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
