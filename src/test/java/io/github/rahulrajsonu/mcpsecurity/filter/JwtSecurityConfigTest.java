package io.github.rahulrajsonu.mcpsecurity.filter;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class JwtSecurityConfigTest {

    private static final String EXPECTED_AUDIENCE =
            "healthcare-mcp-api";

    private static final String ISSUER =
            "https://lemur-1.cloud-iam.com/auth/realms/rajrahul9939";

    private Jwt createJwt(List<String> audiences) {
        Instant now = Instant.now();

        return Jwt.withTokenValue("test-token")
                .header("alg", "RS256")
                .subject("clinician-123")
                .issuer(ISSUER)
                .audience(audiences)
                .issuedAt(now)
                .expiresAt(now.plusSeconds(300))
                .build();
    }

    @Test
    void acceptsExpectedAudience() {
        OAuth2TokenValidator<Jwt> validator =
                JwtSecurityConfig.audienceValidator(
                        EXPECTED_AUDIENCE);

        var result = validator.validate(
                createJwt(List.of(EXPECTED_AUDIENCE)));

        assertFalse(result.hasErrors());
    }

    @Test
    void rejectsWrongAudience() {
        OAuth2TokenValidator<Jwt> validator =
                JwtSecurityConfig.audienceValidator(
                        EXPECTED_AUDIENCE);

        var result = validator.validate(
                createJwt(List.of("billing-api")));

        assertTrue(result.hasErrors());
        assertEquals(
                "invalid_token",
                result.getErrors().stream().toList().getFirst().getErrorCode());
    }

    @Test
    void rejectsMissingAudience() {
        OAuth2TokenValidator<Jwt> validator =
                JwtSecurityConfig.audienceValidator(
                        EXPECTED_AUDIENCE);

        var result = validator.validate(createJwt(List.of()));

        assertTrue(result.hasErrors());
    }

    @Test
    void rejectsBlankExpectedAudience() {
        assertThrows(
                IllegalArgumentException.class,
                () -> JwtSecurityConfig.audienceValidator(" "));
    }
}
