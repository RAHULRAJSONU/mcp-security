package io.github.rahulrajsonu.mcpsecurity.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Refuses to answer over plain HTTP, so a misconfigured ingress cannot serve
 * PHI in the clear. Behind a TLS-terminating proxy the scheme comes from
 * X-Forwarded-Proto, which the proxy must set itself and never pass through
 * from the client. Requests matching {@code exempt} (the internal management
 * port) are left alone.
 *
 * It fails hard instead of redirecting: by the time a plain-HTTP request
 * arrives its contents have already crossed the network unprotected, so the
 * useful response is a refusal that surfaces the misconfiguration.
 */
public class RequireHttpsFilter extends OncePerRequestFilter {

    private final RequestMatcher exempt;

    public RequireHttpsFilter(RequestMatcher exempt) {
        this.exempt = exempt;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain) throws ServletException, IOException {

        if (request.isSecure() || exempt.matches(request)) {
            chain.doFilter(request, response);
            return;
        }

        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
    }
}
