package io.github.rahulrajsonu.mcpsecurity.security;

import java.util.Objects;

/**
 * Who is asking, and why. {@code justification} is free text supplied by the
 * caller (required for {@link AccessPurpose#EMERGENCY}); it can contain PHI and
 * must never be logged verbatim.
 */
public record ClinicalAccessContext(
        ClinicalPrincipal principal,
        AccessPurpose purpose,
        String justification
) {
    public ClinicalAccessContext {
        Objects.requireNonNull(principal);
        Objects.requireNonNull(purpose);
    }

    public ClinicalAccessContext(
            ClinicalPrincipal principal,
            AccessPurpose purpose) {
        this(principal, purpose, null);
    }
}
