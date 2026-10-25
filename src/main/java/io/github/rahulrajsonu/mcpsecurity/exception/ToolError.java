package io.github.rahulrajsonu.mcpsecurity.exception;

import io.github.rahulrajsonu.mcpsecurity.mcp.tool.ToolCallResponse;

/** An exception that knows what the model should be told, so nothing matches on message text. */
public interface ToolError {

    ToolCallResponse toolResponse();
}
