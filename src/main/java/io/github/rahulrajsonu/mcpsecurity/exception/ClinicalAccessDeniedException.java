package io.github.rahulrajsonu.mcpsecurity.exception;

import io.github.rahulrajsonu.mcpsecurity.mcp.tool.ToolCallResponse;
import org.springframework.security.access.AccessDeniedException;

public class ClinicalAccessDeniedException
        extends AccessDeniedException implements ToolError {

    public ClinicalAccessDeniedException() {
        super("Clinical resource access denied");
    }

    @Override
    public ToolCallResponse toolResponse() {
        return ToolCallResponse.ACCESS_DENIED;
    }
}
