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
        String clientId = jwt.getClaimAsString("azp");
        // Authentication context class: set by the identity provider after a human step-up.
        String authContext = jwt.getClaimAsString("acr");
        String actor = actorChain(jwt.getClaim("act"));

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
                scopes,
                clientId,
                authContext,
                actor
        );
    }

    private static final int MAX_ACTOR_DEPTH = 5;

    /**
     * RFC 8693 delegation: {@code act} names the party acting for the subject, and a nested
     * {@code act} the one before it. Returned outermost first ("agent-a>agent-b"), or null
     * when there is none. Recorded for the audit trail only; it grants nothing.
     */
    static String actorChain(Object act) {
        StringBuilder chain = new StringBuilder();
        Object current = act;
        for (int depth = 0; depth < MAX_ACTOR_DEPTH && current instanceof java.util.Map<?, ?> claim; depth++) {
            if (claim.get("sub") instanceof String sub && !sub.isBlank()) {
                if (!chain.isEmpty()) {
                    chain.append('>');
                }
                chain.append(sub.strip());
            }
            current = claim.get("act");
        }
        return chain.isEmpty() ? null : chain.toString();
    }
}
