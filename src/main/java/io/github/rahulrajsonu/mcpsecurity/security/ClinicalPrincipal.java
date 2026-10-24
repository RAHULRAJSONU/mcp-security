package io.github.rahulrajsonu.mcpsecurity.security;

import java.util.Objects;
import java.util.Set;

public record ClinicalPrincipal(
        String subject,
        String tenantId,
        Set<String> scopes
) {
    public ClinicalPrincipal {
        Objects.requireNonNull(subject, "subject");
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(scopes, "scopes");

        if (subject.isBlank() || tenantId.isBlank()) {
            throw new IllegalArgumentException(
                    "Invalid clinical principal"
            );
        }

        scopes = Set.copyOf(scopes);

        if (scopes.stream().anyMatch(
                scope -> scope == null || scope.isBlank())) {
            throw new IllegalArgumentException(
                    "Invalid scope value"
            );
        }
    }

    public boolean hasScope(String scope) {
        return scope != null
                && !scope.isBlank()
                && scopes.contains(scope);
    }
}
