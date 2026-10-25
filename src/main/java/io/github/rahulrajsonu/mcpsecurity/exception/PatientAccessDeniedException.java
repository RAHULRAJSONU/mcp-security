package io.github.rahulrajsonu.mcpsecurity.exception;

import io.github.rahulrajsonu.mcpsecurity.mcp.tool.ToolCallResponse;
import org.springframework.security.access.AccessDeniedException;

public class PatientAccessDeniedException
        extends AccessDeniedException implements ToolError {

    public PatientAccessDeniedException() {
        super("Patient access denied");
    }

    @Override
    public ToolCallResponse toolResponse() {
        return ToolCallResponse.ACCESS_DENIED;
    }
}
