package io.github.rahulrajsonu.mcpsecurity.mcp.tool;

import io.modelcontextprotocol.server.McpServerFeatures.SyncToolSpecification;
import io.modelcontextprotocol.server.McpStatelessServerFeatures;
import io.modelcontextprotocol.spec.McpSchema;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;

public final class ToolErrors {

    private ToolErrors() {
    }

    public static SyncToolSpecification sanitized(SyncToolSpecification spec) {
        return sanitized(spec, null);
    }

    /** As above, and each call is counted and timed by tool and final outcome. */
    public static SyncToolSpecification sanitized(SyncToolSpecification spec, ToolMetrics metrics) {
        return new SyncToolSpecification(spec.tool(), (exchange, request) -> {
            java.util.function.Supplier<CallToolResult> call =
                    () -> sanitize(spec.callHandler().apply(exchange, request));
            return metrics == null ? call.get() : metrics.observe(spec.tool().name(), call);
        });
    }

    /**
     * A hash of what the model is told about a tool: its name, description and
     * input schema. Logged at startup so a deployment can pin it and notice when
     * a release changes a tool the clients had already trusted.
     */
    public static String fingerprint(SyncToolSpecification spec) {
        return fingerprint(spec.tool());
    }

    public static String fingerprint(McpSchema.Tool tool) {
        String definition = tool.name() + '\n' + tool.description() + '\n' + tool.inputSchema();
        try {
            return java.util.HexFormat.of().formatHex(
                    java.security.MessageDigest.getInstance("SHA-256")
                            .digest(definition.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        } catch (java.security.NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }

    /** The same wrapper for the stateless transport, where a call has no session or exchange. */
    public static McpStatelessServerFeatures.SyncToolSpecification sanitized(
            McpStatelessServerFeatures.SyncToolSpecification spec, ToolMetrics metrics) {
        return new McpStatelessServerFeatures.SyncToolSpecification(spec.tool(), (context, request) -> {
            java.util.function.Supplier<CallToolResult> call =
                    () -> sanitize(spec.callHandler().apply(context, request));
            return metrics == null ? call.get() : metrics.observe(spec.tool().name(), call);
        });
    }

    static CallToolResult sanitize(CallToolResult result) {
        if (result == null || !Boolean.TRUE.equals(result.isError()) || ToolCallResponse.isSanitized(result)) {
            return result;
        }
        return ToolCallResponse.classify(ToolCallResponse.firstText(result)).toResult();
    }
}
