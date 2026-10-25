package io.github.rahulrajsonu.mcpsecurity.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

/** The claims the agent registry and the break-glass step-up depend on. */
class ClinicalPrincipalClaimsTest {

    private final ClinicalPrincipalResolver resolver = new ClinicalPrincipalResolver();

    private static JwtAuthenticationToken token(Map<String, Object> extra) {
        Map<String, Object> claims = new HashMap<>(Map.of(
                "sub", "doctor-101", "tenant_id", "hospital-A", "scope", "patient.read"));
        claims.putAll(extra);
        Jwt jwt = new Jwt("synthetic-test-token", Instant.now(), Instant.now().plusSeconds(300),
                Map.of("alg", "RS256"), claims);
        return new JwtAuthenticationToken(jwt, List.of());
    }

    @Test
    void clientIdComesFromTheAuthorizedPartyClaim() {
        ClinicalPrincipal principal = resolver.resolve(token(Map.of("azp", "healthcare-mcp-client")));

        assertThat(principal.clientId()).isEqualTo("healthcare-mcp-client");
    }

    @Test
    void stepUpComesFromTheAuthenticationContextClaim() {
        ClinicalPrincipal principal = resolver.resolve(token(Map.of("acr", "urn:healthcare:acr:step-up")));

        assertThat(principal.authContext()).isEqualTo("urn:healthcare:acr:step-up");
    }

    @Test
    void missingClaimsResolveToNullSoThePoliciesDeny() {
        ClinicalPrincipal principal = resolver.resolve(token(Map.of()));

        assertThat(principal.clientId()).isNull();
        assertThat(principal.authContext()).isNull();
    }

    @Test
    void aTokenWithoutASubjectIsRefused() {
        Jwt jwt = new Jwt("t", Instant.now(), Instant.now().plusSeconds(60), Map.of("alg", "RS256"),
                Map.of("tenant_id", "hospital-A", "scope", "patient.read"));

        assertThatThrownBy(() -> resolver.resolve(new JwtAuthenticationToken(jwt, List.of())))
                .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void principalRejectsBlankIdentityAndScopes() {
        assertThatThrownBy(() -> new ClinicalPrincipal(" ", "hospital-A", Set.of()))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new ClinicalPrincipal("doctor-101", " ", Set.of()))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new ClinicalPrincipal("doctor-101", "hospital-A", Set.of(" ")))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void shorterConstructorsLeaveTheOptionalFieldsEmpty() {
        ClinicalPrincipal three = new ClinicalPrincipal("doctor-101", "hospital-A", Set.of("patient.read"));
        ClinicalPrincipal four = new ClinicalPrincipal("doctor-101", "hospital-A", Set.of("patient.read"), "c");

        assertThat(three.clientId()).isNull();
        assertThat(three.authContext()).isNull();
        assertThat(four.clientId()).isEqualTo("c");
        assertThat(four.authContext()).isNull();
    }

    @Test
    void scopeChecksIgnoreBlankAndMissingValues() {
        ClinicalPrincipal principal = new ClinicalPrincipal("doctor-101", "hospital-A", Set.of("patient.read"));

        assertThat(principal.hasScope("patient.read")).isTrue();
        assertThat(principal.hasScope("patient.write")).isFalse();
        assertThat(principal.hasScope(null)).isFalse();
        assertThat(principal.hasScope(" ")).isFalse();
    }
}
