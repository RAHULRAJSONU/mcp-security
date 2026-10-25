package io.github.rahulrajsonu.mcpsecurity.exception;

import io.github.rahulrajsonu.mcpsecurity.mcp.tool.ToolCallResponse;
/**
 * What the caller (and so the AI model) sees when something unexpected fails.
 * Internal messages, SQL and data never travel with it; the original exception
 * is logged server-side only.
 */
public class RequestFailedException extends RuntimeException implements ToolError {

    public RequestFailedException() {
        super("Request could not be completed");
    }

    @Override
    public ToolCallResponse toolResponse() {
        return ToolCallResponse.REQUEST_FAILED;
    }
}
