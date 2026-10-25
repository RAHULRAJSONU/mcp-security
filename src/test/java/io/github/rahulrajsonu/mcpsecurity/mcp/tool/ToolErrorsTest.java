package io.github.rahulrajsonu.mcpsecurity.mcp.tool;

import static org.assertj.core.api.Assertions.assertThat;

import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import org.junit.jupiter.api.Test;

class ToolErrorsTest {

    private static CallToolResult failure(String text) {
        return CallToolResult.builder().isError(true).addTextContent(text).build();
    }

    private static String text(CallToolResult result) {
        return ToolCallResponse.firstText(result);
    }

    @Test
    void successIsUntouched() {
        CallToolResult ok = CallToolResult.builder().addTextContent("[]").build();

        assertThat(ToolErrors.sanitize(ok)).isSameAs(ok);
    }

    @Test
    void knownDenialKeepsItsCodeAndDropsTheRootCause() {
        CallToolResult result = ToolErrors.sanitize(failure(
                "Patient access denied" + System.lineSeparator() + "Patient access denied"));

        assertThat(result.isError()).isTrue();
        assertThat(text(result)).isEqualTo("{\"error\":\"access_denied\",\"message\":\"Access denied\",\"retryable\":false}");
    }

    @Test
    void databaseTextInTheRootCauseNeverReachesTheModel() {
        CallToolResult result = ToolErrors.sanitize(failure(
                "Request could not be completed" + System.lineSeparator()
                        + "ERROR: duplicate key (patient_id)=(patient-400) Alice Test 1985-04-12"));

        assertThat(text(result)).isEqualTo(ToolCallResponse.REQUEST_FAILED.toJson());
        assertThat(text(result)).doesNotContain("Alice").doesNotContain("patient-400");
    }

    @Test
    void unknownMessagesBecomeAGenericFailure() {
        CallToolResult result = ToolErrors.sanitize(failure(
                "Error invoking method: could not extract ResultSet for Alice Test"));

        assertThat(text(result)).isEqualTo(ToolCallResponse.REQUEST_FAILED.toJson());
    }

    @Test
    void missingAuthenticationIsReportedAsSuch() {
        assertThat(text(ToolErrors.sanitize(failure("Authentication required"))))
                .contains("\"error\":\"unauthenticated\"");
    }

    @Test
    void errorCarriesStructuredContentForClients() {
        CallToolResult result = ToolErrors.sanitize(failure("Request could not be completed"));

        assertThat(result.structuredContent()).isEqualTo(java.util.Map.of(
                "error", "request_failed",
                "message", "Request could not be completed",
                "retryable", true));
    }

    @Test
    void sanitizingTwiceDoesNotReclassify() {
        CallToolResult once = ToolErrors.sanitize(failure("Patient access denied"));

        assertThat(ToolErrors.sanitize(once)).isSameAs(once);
    }
}
