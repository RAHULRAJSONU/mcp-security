package io.github.rahulrajsonu.mcpsecurity.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import com.github.benmanes.caffeine.cache.Ticker;
import io.github.bucket4j.TimeMeter;
import io.github.rahulrajsonu.mcpsecurity.config.RateLimitProperties;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;

import java.time.Duration;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class RateLimitFilterTest {

    private final FilterChain chain = mock(FilterChain.class);

    private RateLimitFilter filter(int ipPerMinute, int tokenPerMinute) {
        var props = new RateLimitProperties(ipPerMinute, tokenPerMinute, 1000, Duration.ofMinutes(5));
        var limiter = new RateLimiter(props, new SimpleMeterRegistry(), Ticker.systemTicker(), TimeMeter.SYSTEM_NANOTIME);
        return new RateLimitFilter(limiter);
    }

    private static MockHttpServletRequest request(String uri, String ip, String authorization) {
        var req = new MockHttpServletRequest("POST", uri);
        req.setRequestURI(uri);
        req.setRemoteAddr(ip);
        if (authorization != null) {
            req.addHeader("Authorization", authorization);
        }
        return req;
    }

    private MockHttpServletResponse send(RateLimitFilter filter, MockHttpServletRequest req) throws Exception {
        var res = new MockHttpServletResponse();
        filter.doFilter(req, res, chain);
        return res;
    }

    @Test
    void a_request_within_the_limit_reaches_the_next_filter() throws Exception {
        var res = send(filter(10, 10), request("/mcp", "1.1.1.1", "Bearer a"));

        assertThat(res.getStatus()).isEqualTo(200);
        verify(chain).doFilter(any(ServletRequest.class), any(ServletResponse.class));
    }

    @Test
    void an_over_limit_request_gets_429_with_a_numeric_retry_after_and_goes_no_further() throws Exception {
        var filter = filter(10, 1);
        send(filter, request("/mcp", "1.1.1.1", "Bearer a"));

        var res = send(filter, request("/mcp", "1.1.1.1", "Bearer a"));

        assertThat(res.getStatus()).isEqualTo(429);
        assertThat(res.getHeader("Retry-After")).matches("\\d+");
        verify(chain, times(1)).doFilter(any(ServletRequest.class), any(ServletResponse.class)); // only the first
    }

    @Test
    void a_new_made_up_token_each_time_is_still_stopped_by_the_address() throws Exception {
        var filter = filter(3, 1000);

        int refused = 0;
        for (int i = 0; i < 20; i++) {
            if (send(filter, request("/mcp", "6.6.6.6", "Bearer invented-" + i)).getStatus() == 429) {
                refused++;
            }
        }

        assertThat(refused).isEqualTo(17);
        verify(chain, times(3)).doFilter(any(ServletRequest.class), any(ServletResponse.class));
    }

    @Test
    void health_checks_and_discovery_are_never_limited() throws Exception {
        var filter = filter(1, 1);

        for (int i = 0; i < 5; i++) {
            assertThat(send(filter, request("/actuator/health/liveness", "1.1.1.1", null)).getStatus()).isEqualTo(200);
            assertThat(send(filter, request("/.well-known/oauth-protected-resource", "1.1.1.1", null)).getStatus())
                    .isEqualTo(200);
        }
        verify(chain, times(10)).doFilter(any(ServletRequest.class), any(ServletResponse.class));
    }

    @Test
    void the_api_is_limited_as_well_as_the_mcp_endpoint() throws Exception {
        var filter = filter(1, 1000);
        send(filter, request("/api/security/probe", "1.1.1.1", "Bearer a"));

        assertThat(send(filter, request("/api/security/probe", "1.1.1.1", "Bearer a")).getStatus()).isEqualTo(429);
    }

    @Test
    void the_limit_is_shared_between_the_mcp_endpoint_and_the_api_for_one_address() throws Exception {
        var filter = filter(1, 1000);
        send(filter, request("/mcp", "1.1.1.1", "Bearer a"));

        assertThat(send(filter, request("/api/security/probe", "1.1.1.1", "Bearer a")).getStatus()).isEqualTo(429);
    }

    @Test
    void a_refused_request_never_reaches_authentication() throws Exception {
        var filter = filter(1, 1000);
        send(filter, request("/mcp", "1.1.1.1", null));
        var refusedChain = mock(FilterChain.class);

        filter.doFilter(request("/mcp", "1.1.1.1", "Bearer junk"), new MockHttpServletResponse(), refusedChain);

        verify(refusedChain, never()).doFilter(any(ServletRequest.class), any(ServletResponse.class));
    }
}
