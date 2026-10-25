package io.github.rahulrajsonu.mcpsecurity.exception;

import io.github.rahulrajsonu.mcpsecurity.mcp.tool.ToolCallResponse;

public class RateLimitExceededException extends RuntimeException implements ToolError {

    public RateLimitExceededException() {
        super("Too many requests");
    }

    @Override
    public ToolCallResponse toolResponse() {
        return ToolCallResponse.RATE_LIMITED;
    }
}
