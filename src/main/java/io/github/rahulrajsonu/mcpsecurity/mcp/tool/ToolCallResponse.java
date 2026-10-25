package io.github.rahulrajsonu.mcpsecurity.mcp.tool;

import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Content;
import io.modelcontextprotocol.spec.McpSchema.TextContent;

import java.util.Map;

/**
 * What the model reads when a tool fails: a normal result with {@code isError}
 * set and a small JSON body {@code {"error": code, "message": text, "retryable": bool}},
 * repeated as structured content. Only {@link #REQUEST_FAILED} is worth retrying.
 *
 * The framework builds its own error text from the exception message plus the
 * root cause's message, and a root cause can be a database error that echoes
 * SQL or data. So nothing from it is forwarded unless it is one of our own
 * fixed messages below; everything else becomes {@link #REQUEST_FAILED}.
 */
public record ToolCallResponse(String error, String message, boolean retryable) {

    public static final ToolCallResponse ACCESS_DENIED =
            new ToolCallResponse("access_denied", "Access denied", false);
    public static final ToolCallResponse UNAUTHENTICATED =
            new ToolCallResponse("unauthenticated", "Authentication required", false);
    public static final ToolCallResponse RATE_LIMITED =
            new ToolCallResponse("rate_limited", "Too many requests; wait and retry later", true);
    public static final ToolCallResponse REQUEST_FAILED =
            new ToolCallResponse("request_failed", "Request could not be completed", true);

    /**
     * Fallback for failures the framework raises before a tool body runs, where
     * only text is left. Our own exceptions implement {@code ToolError} instead.
     * Matched on the first line only.
     */
    private static final Map<String, ToolCallResponse> KNOWN = Map.of(
            "Patient access denied", ACCESS_DENIED,
            "Clinical resource access denied", ACCESS_DENIED,
            "Authentication required", UNAUTHENTICATED,
            "Authenticated JWT required", UNAUTHENTICATED,
            "Missing required subject claim", UNAUTHENTICATED,
            "Missing required tenant claim", UNAUTHENTICATED,
            "Too many requests", RATE_LIMITED,
            "Request could not be completed", REQUEST_FAILED);

    /** The sanitized response for the text the framework produced for a failed call. */
    public static ToolCallResponse classify(String frameworkText) {
        if (frameworkText == null) {
            return REQUEST_FAILED;
        }
        String firstLine = frameworkText.lines().findFirst().orElse("").strip();
        return KNOWN.getOrDefault(firstLine, REQUEST_FAILED);
    }

    /** All fields are fixed constants, so no JSON escaping is needed. */
    public String toJson() {
        return "{\"error\":\"" + error + "\",\"message\":\"" + message
                + "\",\"retryable\":" + retryable + "}";
    }

    /** Text for the model, plus the same facts as structured content for clients. */
    public CallToolResult toResult() {
        return CallToolResult.builder()
                .isError(true)
                .addTextContent(toJson())
                .structuredContent(Map.of(
                        "error", error,
                        "message", message,
                        "retryable", retryable))
                .build();
    }

    /** Already one of ours, so wrapping a second time must not reclassify it. */
    static boolean isSanitized(CallToolResult result) {
        return result.content() != null
                && result.content().size() == 1
                && result.content().get(0) instanceof TextContent text
                && text.text() != null
                && text.text().startsWith("{\"error\":\"");
    }

    static String firstText(CallToolResult result) {
        if (result.content() == null) {
            return null;
        }
        for (Content content : result.content()) {
            if (content instanceof TextContent text) {
                return text.text();
            }
        }
        return null;
    }
}
