package io.github.rahulrajsonu.mcpsecurity.mcp.tool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import io.modelcontextprotocol.server.McpServerFeatures.SyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import java.util.Map;
import org.junit.jupiter.api.Test;

class ToolMetricsTest {

    private final MeterRegistry registry = new SimpleMeterRegistry();
    private final ToolMetrics metrics = new ToolMetrics(() -> registry);

    private double calls(String tool, String outcome) {
        var counter = registry.find(ToolMetrics.CALLS).tag("tool", tool).tag("outcome", outcome).counter();
        return counter == null ? 0 : counter.count();
    }

    @Test
    void aSuccessfulCallIsCountedAndTimedAsOk() {
        CallToolResult result = metrics.observe("listMyPatients", () -> CallToolResult.builder().addTextContent("[]").build());

        assertThat(result.isError()).isNotEqualTo(true);
        assertThat(calls("listMyPatients", "ok")).isEqualTo(1.0);
        assertThat(registry.find(ToolMetrics.DURATION).tag("tool", "listMyPatients").tag("outcome", "ok").timer().count())
                .isEqualTo(1L);
    }

    @Test
    void aFailureIsCountedUnderTheCodeTheModelWasGiven() {
        metrics.observe("getPatientSummary", ToolCallResponse.ACCESS_DENIED::toResult);
        metrics.observe("getPatientSummary", ToolCallResponse.RATE_LIMITED::toResult);
        metrics.observe("getPatientSummary", ToolCallResponse.RATE_LIMITED::toResult);

        assertThat(calls("getPatientSummary", "access_denied")).isEqualTo(1.0);
        assertThat(calls("getPatientSummary", "rate_limited")).isEqualTo(2.0);
        assertThat(calls("getPatientSummary", "ok")).isZero();
    }

    @Test
    void anErrorWithoutACodeIsStillCounted() {
        metrics.observe("t", () -> CallToolResult.builder().isError(true).addTextContent("x").build());

        assertThat(calls("t", "error")).isEqualTo(1.0);
    }

    @Test
    void anExceptionIsCountedAndStillPropagates() {
        assertThatThrownBy(() -> metrics.observe("t", () -> {
            throw new IllegalStateException("protocol failure");
        })).isInstanceOf(IllegalStateException.class);

        assertThat(calls("t", "exception")).isEqualTo(1.0);
    }

    @Test
    void labelsAreOnlyToolAndOutcomeSoNoIdentifierCanLeakIntoMetrics() {
        metrics.observe("getPatientSummary", ToolCallResponse.ACCESS_DENIED::toResult);

        registry.getMeters().forEach(meter -> assertThat(meter.getId().getTags())
                .extracting(tag -> tag.getKey())
                .containsOnly("tool", "outcome"));
    }

    @Test
    void withoutARegistryTheCallStillRuns() {
        ToolMetrics none = new ToolMetrics(() -> null);

        CallToolResult result = none.observe("t", () -> CallToolResult.builder().addTextContent("ok").build());

        assertThat(result.isError()).isNotEqualTo(true);
    }

    @Test
    void theWrapperObservesTheFinalSanitizedOutcomeNotTheRawFrameworkText() {
        Tool tool = Tool.builder().name("getPatientMedications").description("d").inputSchema(Map.of("type", "object")).build();
        SyncToolSpecification raw = new SyncToolSpecification(tool, (exchange, request) ->
                CallToolResult.builder().isError(true)
                        .addTextContent("Patient access denied\nERROR: relation x, Alice Test").build());

        ToolErrors.sanitized(raw, metrics).callHandler().apply(null, null);

        // Counted under the sanitized code, which is what the model saw.
        assertThat(calls("getPatientMedications", "access_denied")).isEqualTo(1.0);
        assertThat(calls("getPatientMedications", "error")).isZero();
    }
}
