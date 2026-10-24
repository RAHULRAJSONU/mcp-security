package io.github.rahulrajsonu.mcpsecurity.security;

import static org.junit.jupiter.api.Assertions.*;

import io.github.rahulrajsonu.mcpsecurity.AbstractPostgresIT;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class TenantScopedExecutorIT extends AbstractPostgresIT {

    @Autowired
    TenantScopedExecutor tenantExecutor;

    @Autowired
    EntityManager entityManager;

    private ClinicalPrincipal principal(String tenantId) {
        return new ClinicalPrincipal(
                "doctor-101",
                tenantId,
                Set.of("patient.read")
        );
    }

    private List<String> patientIds(String tenantId) {
        return tenantExecutor.execute(
                principal(tenantId),
                () -> entityManager.createNativeQuery(
                        "SELECT id FROM patients ORDER BY id",
                        String.class
                ).getResultList()
        );
    }

    @Test
    void shouldIsolateTenantsAcrossTransactions() {

        List<String> hospitalA = patientIds("hospital-A");
        List<String> hospitalB = patientIds("hospital-B");
        List<String> hospitalAAgain = patientIds("hospital-A");

        assertThat(hospitalA)
                .containsExactly("patient-400", "patient-500");

        assertThat(hospitalB)
                .containsExactly("patient-600");

        assertThat(hospitalAAgain)
                .containsExactly("patient-400", "patient-500");
    }

    @Test
    void shouldPreventCrossTenantPatientAccess() {

        List<String> result = tenantExecutor.execute(
                principal("hospital-A"),
                () -> entityManager.createNativeQuery(
                        """
                        SELECT id
                        FROM patients
                        WHERE id = 'patient-600'
                        """,
                        String.class
                ).getResultList()
        );

        assertThat(result).isEmpty();
    }

    @Test
    void shouldIsolateTenantsUnderConcurrentLoad()
            throws Exception {

        int requests = 100;

        try (ExecutorService executor =
                     Executors.newFixedThreadPool(10)) {

            List<Callable<Void>> tasks =
                    IntStream.range(0, requests)
                            .<Callable<Void>>mapToObj(i -> () -> {

                                String tenant = i % 2 == 0
                                        ? "hospital-A"
                                        : "hospital-B";

                                List<String> ids = patientIds(tenant);

                                if ("hospital-A".equals(tenant)) {
                                    assertThat(ids).containsExactly(
                                            "patient-400",
                                            "patient-500"
                                    );
                                } else {
                                    assertThat(ids).containsExactly(
                                            "patient-600"
                                    );
                                }

                                return null;
                            })
                            .toList();

            List<Future<Void>> results =
                    executor.invokeAll(tasks);

            for (Future<Void> result : results) {
                result.get();
            }
        }
    }

    @Test
    void rejectsMissingTenantBeforeExecutingOperation() {
        ClinicalPrincipal principal = mock(ClinicalPrincipal.class);
        when(principal.tenantId()).thenReturn(null);

        AtomicBoolean executed = new AtomicBoolean(false);

        assertThrows(
                SecurityException.class,
                () -> tenantExecutor.execute(principal, () -> {
                    executed.set(true);
                    return "should not execute";
                })
        );

        assertFalse(executed.get());
    }
}