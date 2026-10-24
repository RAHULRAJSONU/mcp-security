package io.github.rahulrajsonu.mcpsecurity.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

class CertificateBoundTokenFilterTest {

    private static final byte[] DER = {1, 2, 3, 4, 5};

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    private static X509Certificate certificate(byte[] der) throws Exception {
        X509Certificate cert = mock(X509Certificate.class);
        when(cert.getEncoded()).thenReturn(der);
        return cert;
    }

    private static String thumbprintOf(byte[] der) throws Exception {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(MessageDigest.getInstance("SHA-256").digest(der));
    }

    private static void authenticate(Map<String, Object> cnf) {
        Jwt.Builder jwt = Jwt.withTokenValue("t")
                .header("alg", "none")
                .subject("doctor-101")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60));
        if (cnf != null) {
            jwt.claim("cnf", cnf);
        }
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt.build(), java.util.List.of()));
    }

    private static MockHttpServletRequest requestWith(X509Certificate... chain) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        if (chain.length > 0) {
            request.setAttribute(CertificateBoundTokenFilter.CERTIFICATE_ATTRIBUTE, chain);
        }
        return request;
    }

    private static MockHttpServletResponse run(boolean requireBound, MockHttpServletRequest request) throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        new CertificateBoundTokenFilter(requireBound).doFilter(request, response, new MockFilterChain());
        return response;
    }

    @Test
    void acceptsTokenBoundToThePresentedCertificate() throws Exception {
        authenticate(Map.of("x5t#S256", thumbprintOf(DER)));

        MockHttpServletResponse response = run(true, requestWith(certificate(DER)));

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
    }

    @Test
    void rejectsTokenBoundToADifferentCertificate() throws Exception {
        authenticate(Map.of("x5t#S256", thumbprintOf(DER)));

        MockHttpServletResponse response = run(true, requestWith(certificate(new byte[] {9, 9, 9})));

        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getHeader("WWW-Authenticate")).contains("invalid_token");
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    void rejectsBoundTokenWhenNoClientCertificateWasPresented() throws Exception {
        authenticate(Map.of("x5t#S256", thumbprintOf(DER)));

        assertThat(run(true, requestWith()).getStatus()).isEqualTo(401);
    }

    @Test
    void rejectsUnboundTokenWhenBindingIsRequired() throws Exception {
        authenticate(null);

        assertThat(run(true, requestWith(certificate(DER))).getStatus()).isEqualTo(401);
    }

    @Test
    void allowsUnboundTokenWhenBindingIsNotRequired() throws Exception {
        authenticate(null);

        assertThat(run(false, requestWith(certificate(DER))).getStatus()).isEqualTo(200);
    }

    @Test
    void ignoresRequestsThatAreNotJwtAuthenticated() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("u", "p", java.util.List.of()));

        assertThat(run(true, requestWith()).getStatus()).isEqualTo(200);
    }

    @Test
    void errorResponseNeverRevealsWhichCheckFailed() throws Exception {
        authenticate(Map.of("x5t#S256", "some-other-thumbprint"));

        String header = run(true, requestWith(certificate(DER))).getHeader("WWW-Authenticate");

        assertThat(header).doesNotContain("some-other-thumbprint").doesNotContain(thumbprintOf(DER));
    }
}
