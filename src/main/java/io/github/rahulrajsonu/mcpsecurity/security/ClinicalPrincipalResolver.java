package io.github.rahulrajsonu.mcpsecurity.security;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

import java.util.Set;
import java.util.Arrays;
import java.util.stream.Collectors;

@Component
public class ClinicalPrincipalResolver {

    public ClinicalPrincipal resolve(Authentication authentication) {

        if (!(authentication instanceof JwtAuthenticationToken jwtAuth)
                || !jwtAuth.isAuthenticated()) {
            throw new AccessDeniedException(
                    "Authenticated JWT required"
            );
        }

        var jwt = jwtAuth.getToken();

        String subject = jwt.getSubject();
        String tenantId = jwt.getClaimAsString("tenant_id");
        String scopeClaim = jwt.getClaimAsString("scope");

        if (subject == null || subject.isBlank()) {
            throw new AccessDeniedException(
                    "Missing required subject claim"
            );
        }

        if (tenantId == null || tenantId.isBlank()) {
            throw new AccessDeniedException(
                    "Missing required tenant claim"
            );
        }

        Set<String> scopes = scopeClaim == null
                ? Set.of()
                : Arrays.stream(scopeClaim.split("\\s+"))
                    .filter(s -> !s.isBlank())
                    .collect(Collectors.toUnmodifiableSet());

        return new ClinicalPrincipal(
                subject,
                tenantId,
                scopes
        );
    }
}