package io.github.rahulrajsonu.mcpsecurity.mcp.tool;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;

import java.util.Map;
import java.util.function.Supplier;

/**
 * Count and time every tool call by tool and outcome. Both labels are small
 * fixed sets (a handful of tools; ok or an error code), so they are safe for a
 * metrics system. Nothing about the caller or the patient is a label.
 */
public class ToolMetrics {

    static final String CALLS = "mcp.tool.calls";
    static final String DURATION = "mcp.tool.duration";

    private final Supplier<MeterRegistry> registry;

    public ToolMetrics(Supplier<MeterRegistry> registry) {
        this.registry = registry;
    }

    public CallToolResult observe(String tool, Supplier<CallToolResult> call) {
        MeterRegistry meters = registry.get();
        if (meters == null) {
            return call.get();
        }

        Timer.Sample sample = Timer.start(meters);
        String outcome = "exception";
        try {
            CallToolResult result = call.get();
            outcome = outcomeOf(result);
            return result;
        } finally {
            sample.stop(Timer.builder(DURATION)
                    .description("Time to run a tool call")
                    .tag("tool", tool)
                    .tag("outcome", outcome)
                    .publishPercentileHistogram()
                    .register(meters));
            meters.counter(CALLS, "tool", tool, "outcome", outcome).increment();
        }
    }

    /** "ok", or the error code the model was given (access_denied, rate_limited, ...). */
    static String outcomeOf(CallToolResult result) {
        if (result == null || !Boolean.TRUE.equals(result.isError())) {
            return "ok";
        }
        if (result.structuredContent() instanceof Map<?, ?> body && body.get("error") instanceof String code) {
            return code;
        }
        return "error";
    }
}
