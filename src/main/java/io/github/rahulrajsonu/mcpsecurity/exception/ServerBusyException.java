package io.github.rahulrajsonu.mcpsecurity.exception;

import io.github.rahulrajsonu.mcpsecurity.mcp.tool.ToolCallResponse;

/** Too much work is in flight. Nothing was read or written; the caller may retry shortly. */
public class ServerBusyException extends RuntimeException implements ToolError {

    public ServerBusyException() {
        super("Server busy");
    }

    @Override
    public ToolCallResponse toolResponse() {
        return ToolCallResponse.SERVER_BUSY;
    }
}
