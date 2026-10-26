package io.github.rahulrajsonu.mcpsecurity.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import jakarta.servlet.ServletException;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class RequestIdFilterTest {

    private final RequestIdFilter filter = new RequestIdFilter();

    private record Outcome(String idInLogs, String idOnResponse) {
    }

    private Outcome run(String supplied) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/mcp");
        if (supplied != null) {
            request.addHeader(RequestIdFilter.HEADER, supplied);
        }
        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicReference<String> seen = new AtomicReference<>();

        filter.doFilter(request, response, new MockFilterChain() {
            @Override
            public void doFilter(jakarta.servlet.ServletRequest req, jakarta.servlet.ServletResponse res) {
                seen.set(MDC.get(RequestIdFilter.MDC_KEY));
            }
        });
        return new Outcome(seen.get(), response.getHeader(RequestIdFilter.HEADER));
    }

    @Test
    void aGeneratedIdIsOnTheLogsAndTheResponse() throws Exception {
        Outcome outcome = run(null);

        assertThat(outcome.idInLogs()).isNotBlank().isEqualTo(outcome.idOnResponse());
    }

    @Test
    void aPlainSuppliedIdIsKept() throws Exception {
        Outcome outcome = run("client-req-12345");

        assertThat(outcome.idInLogs()).isEqualTo("client-req-12345");
        assertThat(outcome.idOnResponse()).isEqualTo("client-req-12345");
    }

    @Test
    void anUnsafeSuppliedIdIsReplacedSoItCannotForgeLogLines() throws Exception {
        for (String hostile : new String[] {
                "abc\nINFO patient_access outcome=ALLOWED", "short", "x".repeat(65), "has space in it", "<script>alert(1)</script>"}) {
            Outcome outcome = run(hostile);

            assertThat(outcome.idInLogs()).isNotEqualTo(hostile).matches("[0-9a-f-]{36}");
            assertThat(outcome.idOnResponse()).isEqualTo(outcome.idInLogs());
        }
    }

    @Test
    void eachRequestGetsItsOwnIdWhenNoneIsSupplied() throws Exception {
        assertThat(run(null).idInLogs()).isNotEqualTo(run(null).idInLogs());
    }

    @Test
    void theIdIsRemovedFromTheLoggingContextAfterwards() throws Exception {
        run("client-req-12345");

        assertThat(MDC.get(RequestIdFilter.MDC_KEY)).isNull();
    }

    @Test
    void theIdIsRemovedEvenWhenTheRequestFails() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        assertThatThrownBy(() -> filter.doFilter(request, response, new MockFilterChain() {
            @Override
            public void doFilter(jakarta.servlet.ServletRequest req, jakarta.servlet.ServletResponse res)
                    throws ServletException {
                throw new ServletException("boom");
            }
        })).isInstanceOf(ServletException.class);

        assertThat(MDC.get(RequestIdFilter.MDC_KEY)).isNull();
    }
}
