package io.github.rahulrajsonu.mcpsecurity.exception;

import org.springframework.security.access.AccessDeniedException;

public class ClinicalAccessDeniedException
        extends AccessDeniedException {

    public ClinicalAccessDeniedException() {
        super("Clinical resource access denied");
    }
}