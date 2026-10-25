package io.github.rahulrajsonu.mcpsecurity.exception;

import io.github.rahulrajsonu.mcpsecurity.mcp.tool.ToolCallResponse;
/**
 * The access could not be recorded, so it is not allowed. The message is
 * deliberately generic; the cause is logged server-side.
 */
public class AuditUnavailableException extends RuntimeException implements ToolError {

    public AuditUnavailableException(Throwable cause) {
        super("Request could not be completed", cause);
    }

    @Override
    public ToolCallResponse toolResponse() {
        return ToolCallResponse.REQUEST_FAILED;
    }
}
