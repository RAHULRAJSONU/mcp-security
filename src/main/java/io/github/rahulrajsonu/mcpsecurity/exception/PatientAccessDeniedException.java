package io.github.rahulrajsonu.mcpsecurity.exception;

import org.springframework.security.access.AccessDeniedException;

public class PatientAccessDeniedException
        extends AccessDeniedException {

    public PatientAccessDeniedException() {
        super("Patient access denied");
    }
}