package io.github.rahulrajsonu.mcpsecurity.exception;

/**
 * What the caller (and so the AI model) sees when something unexpected fails.
 * Internal messages, SQL and data never travel with it; the original exception
 * is logged server-side only.
 */
public class RequestFailedException extends RuntimeException {

    public RequestFailedException() {
        super("Request could not be completed");
    }
}
