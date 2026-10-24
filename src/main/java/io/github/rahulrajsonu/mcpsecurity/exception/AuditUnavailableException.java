package io.github.rahulrajsonu.mcpsecurity.exception;

/**
 * The access could not be recorded, so it is not allowed. The message is
 * deliberately generic; the cause is logged server-side.
 */
public class AuditUnavailableException extends RuntimeException {

    public AuditUnavailableException(Throwable cause) {
        super("Request could not be completed", cause);
    }
}
