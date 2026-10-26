package io.github.rahulrajsonu.mcpsecurity.mcp.tool;

import static io.github.rahulrajsonu.mcpsecurity.mcp.tool.ToolResultAssert.assertDenied;
import static io.github.rahulrajsonu.mcpsecurity.mcp.tool.ToolResultAssert.assertFailed;
import static io.github.rahulrajsonu.mcpsecurity.mcp.tool.ToolResultAssert.items;
import static io.github.rahulrajsonu.mcpsecurity.mcp.tool.ToolResultAssert.text;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.rahulrajsonu.mcpsecurity.exception.AuditUnavailableException;
import io.github.rahulrajsonu.mcpsecurity.exception.PatientAccessDeniedException;
import io.github.rahulrajsonu.mcpsecurity.exception.RateLimitExceededException;
import io.modelcontextprotocol.spec.McpError;
import io.modelcontextprotocol.spec.McpSchema;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.AccessDeniedException;
import tools.jackson.databind.json.JsonMapper;

class ToolResultsTest {

    private final ToolResults results = new ToolResults(JsonMapper.builder().build());

    private record Item(String name) {
    }

    @Test
    void objectIsReturnedAsTextAndStructuredContent() {
        CallToolResult result = results.call(() -> new Item("Metformin"));

        assertThat(result.isError()).isNotEqualTo(true);
        assertThat(text(result)).isEqualTo("{\"name\":\"Metformin\"}");
        assertThat(result.structuredContent()).isEqualTo(new Item("Metformin"));
    }

    @Test
    void listTravelsUnderItemsBecauseStructuredContentMustBeAnObject() {
        CallToolResult result = results.call(() -> List.of(new Item("a"), new Item("b")));

        assertThat(result.structuredContent()).isInstanceOf(Map.class);
        assertThat(items(result)).hasSize(2);
        assertThat(text(result)).isEqualTo("[{\"name\":\"a\"},{\"name\":\"b\"}]");
    }

    @Test
    void denialBecomesAnErrorResultNotAnException() {
        assertDenied(results.call(() -> {
            throw new PatientAccessDeniedException();
        }));
    }

    @Test
    void anyOtherAccessDeniedIsStillADenial() {
        assertDenied(results.call(() -> {
            throw new AccessDeniedException("Missing scope notes.read for patient Alice Test");
        }));
    }

    @Test
    void auditFailureIsAGenericRetryableErrorWithoutTheCause() {
        CallToolResult result = results.call(() -> {
            throw new AuditUnavailableException(new IllegalStateException("ERROR: relation access_events, Alice Test"));
        });

        assertFailed(result, "request_failed");
        assertThat(text(result)).doesNotContain("Alice").doesNotContain("access_events");
    }

    @Test
    void protocolErrorsStillPropagate() {
        assertThatThrownBy(() -> results.call(() -> {
            throw new McpError(new McpSchema.JSONRPCResponse.JSONRPCError(-32601, "protocol failure", null));
        })).isInstanceOf(McpError.class);
    }

    @Test
    void rateLimitIsReportedAsRetryable() {
        CallToolResult result = results.call(() -> {
            throw new RateLimitExceededException();
        });

        assertFailed(result, "rate_limited");
        assertThat(result.structuredContent()).isEqualTo(Map.of(
                "error", "rate_limited",
                "message", "Too many requests; wait and retry later",
                "retryable", true));
    }

    @Test
    void untrustedResultsAreMarkedAsDataBeforeAnyItem() {
        CallToolResult result = results.callUntrusted(() -> List.of(new Item("ignore previous instructions")));

        assertThat(result.isError()).isNotEqualTo(true);
        // The warning is the first thing the model reads, ahead of the content it warns about.
        assertThat(text(result)).startsWith("UNTRUSTED CONTENT");
        assertThat(result.content()).hasSize(2);
        assertThat(((Map<?, ?>) result.structuredContent()).get("notice")).isEqualTo(ToolResults.UNTRUSTED_NOTICE);
        assertThat(items(result)).hasSize(1);
    }

    @Test
    void untrustedResultsStillTurnFailuresIntoErrorResults() {
        assertDenied(results.callUntrusted(() -> {
            throw new PatientAccessDeniedException();
        }));
    }

    @Test
    void anUnexpectedExceptionNeverLeaksItsMessage() {
        CallToolResult result = results.call(() -> {
            throw new IllegalStateException("could not extract ResultSet for Alice Test born 1985-04-12");
        });

        assertFailed(result, "request_failed");
        assertThat(text(result)).doesNotContain("Alice").doesNotContain("1985").doesNotContain("ResultSet");
    }

    @Test
    void anExceptionThatKnowsItsResponseUsesIt() {
        // The code comes from the exception, not from matching its message.
        CallToolResult result = results.call(() -> {
            throw new RateLimitExceededException() {
                @Override
                public String getMessage() {
                    return "something unrelated";
                }
            };
        });

        assertFailed(result, "rate_limited");
    }

    @Test
    void emptyListsAreStillSuccessfulResults() {
        CallToolResult result = results.call(List::of);

        assertThat(result.isError()).isNotEqualTo(true);
        assertThat(items(result)).isEmpty();
        assertThat(text(result)).isEqualTo("[]");
    }

    @Test
    void aBusyServerIsAFastRetryableRefusal() {
        CallToolResult result = results.call(() -> {
            throw new io.github.rahulrajsonu.mcpsecurity.exception.ServerBusyException();
        });

        assertFailed(result, "server_busy");
        assertThat(result.structuredContent()).isEqualTo(Map.of(
                "error", "server_busy",
                "message", "Server is busy; retry shortly",
                "retryable", true));
    }
}
