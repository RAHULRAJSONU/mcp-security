package io.github.rahulrajsonu.mcpsecurity.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;

/**
 * Runs before the bearer-token filter, so a flood of bad tokens is refused before any
 * signature work. Only the MCP endpoint and the API are limited; health checks and
 * discovery documents stay open.
 */
public class RateLimitFilter extends OncePerRequestFilter {

    private final RateLimiter limiter;

    public RateLimitFilter(RateLimiter limiter) {
        this.limiter = limiter;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return !(path.equals("/mcp") || path.startsWith("/mcp/") || path.startsWith("/api/"));
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain) throws ServletException, IOException {

        // getRemoteAddr() is the real client address only because forward-headers-strategy
        // is on and the proxy overwrites X-Forwarded-For. Without that, anyone can spoof it.
        String ip = request.getRemoteAddr();

        RateLimiter.Decision decision = limiter.check(ip, tokenKey(request.getHeader("Authorization")));
        if (!decision.allowed()) {
            response.setStatus(429);
            response.setHeader("Retry-After", String.valueOf(decision.retryAfterSeconds()));
            return;
        }
        chain.doFilter(request, response);
    }

    /** A hash, so the raw token never sits in memory as a map key. */
    private static String tokenKey(String authorization) {
        if (authorization == null || authorization.isBlank()) {
            return null;
        }
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(authorization.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
