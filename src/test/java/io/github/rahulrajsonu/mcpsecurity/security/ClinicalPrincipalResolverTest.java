package io.github.rahulrajsonu.mcpsecurity.security;

import org.junit.jupiter.api.Test;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ClinicalPrincipalResolverTest {

    private final ClinicalPrincipalResolver resolver =
            new ClinicalPrincipalResolver();

    @Test
    void shouldRejectJwtWithoutTenantClaim() {

        Jwt jwt = new Jwt(
                "synthetic-test-token",
                Instant.now(),
                Instant.now().plusSeconds(300),
                Map.of("alg", "RS256"),
                Map.of(
                        "sub", "doctor-101",
                        "scope", "patient.read"
                )
        );

        JwtAuthenticationToken authentication =
                new JwtAuthenticationToken(
                        jwt,
                        List.of(
                                new SimpleGrantedAuthority("SCOPE_patient.read")
                        ),
                        jwt.getSubject()
                );
        assertTrue(authentication.isAuthenticated());
        assertThrows(
                AccessDeniedException.class,
                () -> resolver.resolve(authentication)
        );
    }

    @Test
    void shouldExtractTrustedClaims() {

        Jwt jwt = new Jwt(
                "synthetic-test-token",
                Instant.now(),
                Instant.now().plusSeconds(300),
                Map.of("alg", "RS256"),
                Map.of(
                        "sub", "doctor-101",
                        "tenant_id", "hospital-A",
                        "scope", "patient.read"
                )
        );

        JwtAuthenticationToken authentication =
                new JwtAuthenticationToken(
                        jwt,
                        List.of(
                                new SimpleGrantedAuthority("SCOPE_patient.read")
                        ),
                        jwt.getSubject()
                );

        assertTrue(authentication.isAuthenticated());
        ClinicalPrincipal principal =
                resolver.resolve(authentication);

        assertEquals("doctor-101", principal.subject());
        assertEquals("hospital-A", principal.tenantId());
        assertTrue(principal.hasScope("patient.read"));
    }

    @Test
    void shouldRejectUnauthenticatedJwt() {

        Jwt jwt = new Jwt(
                "synthetic-test-token",
                Instant.now(),
                Instant.now().plusSeconds(300),
                Map.of("alg", "RS256"),
                Map.of(
                        "sub", "doctor-101",
                        "tenant_id", "hospital-A",
                        "scope", "patient.read"
                )
        );

        JwtAuthenticationToken authentication =
                new JwtAuthenticationToken(jwt);

        assertFalse(authentication.isAuthenticated());

        assertThrows(
                AccessDeniedException.class,
                () -> resolver.resolve(authentication)
        );
    }
}