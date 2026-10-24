package io.github.rahulrajsonu.mcpsecurity.security;

import jakarta.persistence.EntityManager;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.Objects;
import java.util.function.Supplier;

@Component
@RequiredArgsConstructor
public class TenantScopedExecutor {

    private final EntityManager entityManager;

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public <T> T execute(
            ClinicalPrincipal principal,
            Supplier<T> operation) {

        Objects.requireNonNull(principal);
        Objects.requireNonNull(operation);

        String tenantId = principal.tenantId();

        if (tenantId == null || tenantId.isBlank()) {
            throw new SecurityException(
                    "Missing or blank tenant context"
            );
        }

        entityManager.createNativeQuery("""
            SELECT set_config(
                'app.tenant_id',
                :tenantId,
                true
            )
            """)
            .setParameter("tenantId", tenantId)
            .getSingleResult();

        return operation.get();
    }
}