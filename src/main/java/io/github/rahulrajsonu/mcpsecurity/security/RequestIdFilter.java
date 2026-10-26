package io.github.rahulrajsonu.mcpsecurity.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.MDC;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Gives every request an id that appears on every log line it produces (the
 * ECS formatter prints the MDC) and on the response, so a failed call reported
 * by a user or a client can be found in the logs. A caller-supplied
 * {@code X-Request-ID} is kept only if it is short and plain; anything else
 * could forge log content, so it is replaced.
 */
public class RequestIdFilter extends OncePerRequestFilter {

    public static final String HEADER = "X-Request-ID";
    public static final String MDC_KEY = "request_id";

    private static final Pattern SAFE = Pattern.compile("[A-Za-z0-9._-]{8,64}");

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain) throws ServletException, IOException {

        String supplied = request.getHeader(HEADER);
        String id = supplied != null && SAFE.matcher(supplied).matches()
                ? supplied
                : UUID.randomUUID().toString();

        MDC.put(MDC_KEY, id);
        response.setHeader(HEADER, id);
        try {
            chain.doFilter(request, response);
        } finally {
            MDC.remove(MDC_KEY);
        }
    }
}
