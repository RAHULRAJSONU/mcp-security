package io.github.rahulrajsonu.mcpsecurity.mcp.tool;

import static org.assertj.core.api.Assertions.assertThat;

import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import org.junit.jupiter.api.Test;

class ToolCallResponseTest {

    @Test
    void ourOwnMessagesKeepTheirCode() {
        assertThat(ToolCallResponse.classify("Patient access denied")).isEqualTo(ToolCallResponse.ACCESS_DENIED);
        assertThat(ToolCallResponse.classify("Clinical resource access denied")).isEqualTo(ToolCallResponse.ACCESS_DENIED);
        assertThat(ToolCallResponse.classify("Authentication required")).isEqualTo(ToolCallResponse.UNAUTHENTICATED);
        assertThat(ToolCallResponse.classify("Too many requests")).isEqualTo(ToolCallResponse.RATE_LIMITED);
        assertThat(ToolCallResponse.classify("Request could not be completed")).isEqualTo(ToolCallResponse.REQUEST_FAILED);
    }

    @Test
    void onlyTheFirstLineDecidesTheCode() {
        // The framework appends the root cause on the next line; it must never pick the code.
        assertThat(ToolCallResponse.classify("Request could not be completed\nPatient access denied"))
                .isEqualTo(ToolCallResponse.REQUEST_FAILED);
        assertThat(ToolCallResponse.classify("Something else\nPatient access denied"))
                .isEqualTo(ToolCallResponse.REQUEST_FAILED);
    }

    @Test
    void nullBlankAndUnknownTextAllFailClosed() {
        assertThat(ToolCallResponse.classify(null)).isEqualTo(ToolCallResponse.REQUEST_FAILED);
        assertThat(ToolCallResponse.classify("")).isEqualTo(ToolCallResponse.REQUEST_FAILED);
        assertThat(ToolCallResponse.classify("  ")).isEqualTo(ToolCallResponse.REQUEST_FAILED);
        assertThat(ToolCallResponse.classify("patient access denied")).isEqualTo(ToolCallResponse.REQUEST_FAILED);
    }

    @Test
    void onlyTransientFailuresAreRetryable() {
        assertThat(ToolCallResponse.ACCESS_DENIED.retryable()).isFalse();
        assertThat(ToolCallResponse.UNAUTHENTICATED.retryable()).isFalse();
        assertThat(ToolCallResponse.RATE_LIMITED.retryable()).isTrue();
        assertThat(ToolCallResponse.REQUEST_FAILED.retryable()).isTrue();
    }

    @Test
    void jsonBodyHasTheDocumentedShape() {
        assertThat(ToolCallResponse.RATE_LIMITED.toJson()).isEqualTo(
                "{\"error\":\"rate_limited\",\"message\":\"Too many requests; wait and retry later\",\"retryable\":true}");
    }

    @Test
    void resultIsAnErrorWithTextAndStructuredContent() {
        CallToolResult result = ToolCallResponse.ACCESS_DENIED.toResult();

        assertThat(result.isError()).isTrue();
        assertThat(result.content()).hasSize(1);
        assertThat(ToolCallResponse.firstText(result)).isEqualTo(ToolCallResponse.ACCESS_DENIED.toJson());
        assertThat(ToolCallResponse.isSanitized(result)).isTrue();
    }

    @Test
    void ordinaryResultsAreNotMistakenForSanitizedOnes() {
        assertThat(ToolCallResponse.isSanitized(CallToolResult.builder().addTextContent("[]").build())).isFalse();
        assertThat(ToolCallResponse.isSanitized(CallToolResult.builder().build())).isFalse();
    }
}
