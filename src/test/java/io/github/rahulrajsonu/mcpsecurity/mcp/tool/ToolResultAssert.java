package io.github.rahulrajsonu.mcpsecurity.mcp.tool;

import static org.assertj.core.api.Assertions.assertThat;

import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import java.util.List;
import java.util.Map;

/** Reads a {@link CallToolResult} the way a client would. */
public final class ToolResultAssert {

    private ToolResultAssert() {
    }

    /** The list a successful list-returning tool put in structured content. */
    public static List<?> items(CallToolResult result) {
        assertThat(result.isError()).isNotEqualTo(true);
        return (List<?>) ((Map<?, ?>) result.structuredContent()).get(ToolResults.ITEMS);
    }

    public static String text(CallToolResult result) {
        return ((TextContent) result.content().get(0)).text();
    }

    public static void assertFailed(CallToolResult result, String errorCode) {
        assertThat(result.isError()).isTrue();
        assertThat(text(result)).contains("\"error\":\"" + errorCode + "\"");
    }

    public static void assertDenied(CallToolResult result) {
        assertFailed(result, "access_denied");
    }
}
