package io.github.rahulrajsonu.mcpsecurity.security;

import java.util.Objects;
import java.util.Set;

public record ClinicalPrincipal(
        String subject,
        String tenantId,
        Set<String> scopes,
        String clientId,
        String authContext,
        String actor
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

    public ClinicalPrincipal(String subject, String tenantId, Set<String> scopes) {
        this(subject, tenantId, scopes, null, null, null);
    }

    public ClinicalPrincipal(String subject, String tenantId, Set<String> scopes, String clientId) {
        this(subject, tenantId, scopes, clientId, null, null);
    }

    public ClinicalPrincipal(String subject, String tenantId, Set<String> scopes, String clientId, String authContext) {
        this(subject, tenantId, scopes, clientId, authContext, null);
    }

    public boolean hasScope(String scope) {
        return scope != null
                && !scope.isBlank()
                && scopes.contains(scope);
    }
}
