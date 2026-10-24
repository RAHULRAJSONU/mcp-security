package io.github.rahulrajsonu.mcpsecurity.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Map;

/**
 * RFC 8705 certificate-bound access tokens: the token's {@code cnf.x5t#S256}
 * thumbprint must equal the thumbprint of the client certificate presented on
 * this TLS connection. A token stolen from a log or proxy is then useless to
 * anyone who does not hold the matching private key.
 *
 * Runs after bearer authentication, so it only inspects an authenticated JWT.
 * It is only registered when mutual TLS is enabled.
 */
public class CertificateBoundTokenFilter extends OncePerRequestFilter {

    static final String CERTIFICATE_ATTRIBUTE = "jakarta.servlet.request.X509Certificate";
    static final String CONFIRMATION_CLAIM = "cnf";
    static final String THUMBPRINT_MEMBER = "x5t#S256";

    private final boolean requireBoundTokens;

    public CertificateBoundTokenFilter(boolean requireBoundTokens) {
        this.requireBoundTokens = requireBoundTokens;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain) throws ServletException, IOException {

        Authentication authentication =
                SecurityContextHolder.getContext().getAuthentication();

        if (authentication instanceof JwtAuthenticationToken jwtAuth
                && jwtAuth.isAuthenticated()
                && !isAcceptable(jwtAuth.getToken(), request)) {

            SecurityContextHolder.clearContext();
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            // Fixed text: never echo which check failed or any token content.
            response.setHeader("WWW-Authenticate",
                    "Bearer error=\"invalid_token\", "
                            + "error_description=\"Token is not bound to the presented client certificate\"");
            return;
        }

        chain.doFilter(request, response);
    }

    private boolean isAcceptable(Jwt token, HttpServletRequest request) {
        String boundThumbprint = boundThumbprint(token);

        if (boundThumbprint == null) {
            return !requireBoundTokens;
        }

        Object attribute = request.getAttribute(CERTIFICATE_ATTRIBUTE);

        if (!(attribute instanceof X509Certificate[] chain) || chain.length == 0) {
            return false;
        }

        String presented = thumbprint(chain[0]);

        return presented != null && MessageDigest.isEqual(
                boundThumbprint.getBytes(StandardCharsets.US_ASCII),
                presented.getBytes(StandardCharsets.US_ASCII));
    }

    private static String boundThumbprint(Jwt token) {
        Object cnf = token.getClaim(CONFIRMATION_CLAIM);

        if (cnf instanceof Map<?, ?> map && map.get(THUMBPRINT_MEMBER) instanceof String value
                && !value.isBlank()) {
            return value;
        }

        return null;
    }

    /** base64url (no padding) of the SHA-256 of the DER-encoded certificate. */
    static String thumbprint(X509Certificate certificate) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(certificate.getEncoded());
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException | CertificateEncodingException ex) {
            return null;
        }
    }
}
