package io.github.rahulrajsonu.mcpsecurity.mcp.tool;

import io.modelcontextprotocol.server.McpServerFeatures.SyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;

public final class ToolErrors {

    private ToolErrors() {
    }

    public static SyncToolSpecification sanitized(SyncToolSpecification spec) {
        return new SyncToolSpecification(spec.tool(), (exchange, request) ->
                sanitize(spec.callHandler().apply(exchange, request)));
    }

    /**
     * A hash of what the model is told about a tool: its name, description and
     * input schema. Logged at startup so a deployment can pin it and notice when
     * a release changes a tool the clients had already trusted.
     */
    public static String fingerprint(SyncToolSpecification spec) {
        String definition = spec.tool().name() + '\n' + spec.tool().description() + '\n' + spec.tool().inputSchema();
        try {
            return java.util.HexFormat.of().formatHex(
                    java.security.MessageDigest.getInstance("SHA-256")
                            .digest(definition.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        } catch (java.security.NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }

    static CallToolResult sanitize(CallToolResult result) {
        if (result == null || !Boolean.TRUE.equals(result.isError()) || ToolCallResponse.isSanitized(result)) {
            return result;
        }
        return ToolCallResponse.classify(ToolCallResponse.firstText(result)).toResult();
    }
}
