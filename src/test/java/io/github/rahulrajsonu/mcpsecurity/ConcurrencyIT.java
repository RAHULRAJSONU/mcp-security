package io.github.rahulrajsonu.mcpsecurity;

import static io.github.rahulrajsonu.mcpsecurity.mcp.tool.ToolResultAssert.text;
import static org.assertj.core.api.Assertions.assertThat;

import io.github.rahulrajsonu.mcpsecurity.mcp.domain.RosterEntry;
import io.github.rahulrajsonu.mcpsecurity.mcp.tool.PatientMcpTools;
import io.github.rahulrajsonu.mcpsecurity.mcp.tool.ToolResultAssert;
import io.github.rahulrajsonu.mcpsecurity.security.ClinicalPrincipal;
import io.github.rahulrajsonu.mcpsecurity.security.TenantScopedExecutor;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.test.context.TestPropertySource;

/**
 * Many requests at once against the real database, which has a pool of only 10
 * connections. Row-level security depends on a per-transaction setting on a pooled
 * connection, so the question is whether anything leaks from one request into the next.
 * Quotas are raised so the test measures correctness, not throttling.
 */
@TestPropertySource(properties = {
        "app.security.agent.calls-per-minute=10000000",
        "app.security.agent.calls-per-day=100000000",
        // The production relationship: a few more places than connections, and excess callers
        // wait at the limit (cheap, holding no connection) rather than inside the pool, where
        // Hikari's 3 s timeout would fail them. A very long wait so nothing is shed here.
        "app.concurrency.max-in-flight-calls=20",
        "app.concurrency.max-wait=PT120S"})
class ConcurrencyIT extends AbstractPostgresIT {

    @Autowired
    PatientMcpTools patientTools;

    @Autowired
    TenantScopedExecutor tenantExecutor;

    @Autowired
    JdbcClient jdbc;

    /** Runs the task as a given caller on its own thread, then clears that thread's identity. */
    private static <T> T as(String subject, String tenant, String scopes, Callable<T> task) throws Exception {
        Jwt jwt = Jwt.withTokenValue("test")
                .header("alg", "none")
                .subject(subject)
                .claim("tenant_id", tenant)
                .claim("scope", scopes)
                .claim("azp", "healthcare-mcp-client")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(120))
                .build();
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt, List.of()));
        try {
            return task.call();
        } finally {
            SecurityContextHolder.clearContext();
        }
    }

    /** Releases all tasks together so they really overlap, and fails the test on any exception. */
    private static void stampede(List<Callable<Void>> tasks) throws Exception {
        CountDownLatch go = new CountDownLatch(1);
        try (ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Future<Void>> futures = new ArrayList<>();
            for (Callable<Void> task : tasks) {
                futures.add(pool.submit(() -> {
                    go.await();
                    return task.call();
                }));
            }
            go.countDown();
            for (Future<Void> future : futures) {
                future.get(120, TimeUnit.SECONDS);
            }
        }
    }

    private static List<String> ids(CallToolResult result) {
        return ToolResultAssert.items(result).stream().map(o -> ((RosterEntry) o).patientId()).toList();
    }

    private long allowedRows(String subject, String category, String patientId) {
        ClinicalPrincipal reader = new ClinicalPrincipal("compliance-1", "hospital-A", Set.of("audit.read"));
        return tenantExecutor.execute(reader, () -> jdbc.sql("""
                        SELECT count(*) FROM access_events
                        WHERE subject = :subject AND category = :category
                          AND patient_id = :patientId AND outcome = 'ALLOWED'
                        """)
                .param("subject", subject)
                .param("category", category)
                .param("patientId", patientId)
                .query(Long.class)
                .single());
    }

    @Test
    void tenantsNeverMixWhenManyRequestsShareTenPooledConnections() throws Exception {
        Queue<String> problems = new ConcurrentLinkedQueue<>();
        List<Callable<Void>> tasks = new ArrayList<>();

        for (int i = 0; i < 150; i++) {
            // hospital-A: sees only its own patient, can read it
            tasks.add(() -> {
                List<String> mine = as("doctor-101", "hospital-A", "patient.read", () -> ids(patientTools.listMyPatients()));
                if (!mine.equals(List.of("patient-400"))) {
                    problems.add("hospital-A roster: " + mine);
                }
                return null;
            });
            // hospital-B: sees only its own patient
            tasks.add(() -> {
                List<String> mine = as("doctor-303", "hospital-B", "patient.read", () -> ids(patientTools.listMyPatients()));
                if (!mine.equals(List.of("patient-600"))) {
                    problems.add("hospital-B roster: " + mine);
                }
                return null;
            });
            // each reads its own patient
            tasks.add(() -> {
                CallToolResult own = as("doctor-101", "hospital-A", "patient.read",
                        () -> patientTools.getPatientSummary("patient-400", null, null));
                if (Boolean.TRUE.equals(own.isError())) {
                    problems.add("hospital-A own read failed: " + text(own));
                }
                return null;
            });
            tasks.add(() -> {
                CallToolResult own = as("doctor-303", "hospital-B", "patient.read",
                        () -> patientTools.getPatientSummary("patient-600", null, null));
                if (Boolean.TRUE.equals(own.isError())) {
                    problems.add("hospital-B own read failed: " + text(own));
                }
                return null;
            });
            // and each is refused the other's patient, every single time
            tasks.add(() -> {
                CallToolResult other = as("doctor-303", "hospital-B", "patient.read",
                        () -> patientTools.getPatientSummary("patient-400", null, null));
                if (!Boolean.TRUE.equals(other.isError()) || !text(other).contains("access_denied")) {
                    problems.add("hospital-B READ hospital-A's patient: " + text(other));
                }
                return null;
            });
            tasks.add(() -> {
                CallToolResult other = as("doctor-101", "hospital-A", "patient.read",
                        () -> patientTools.getPatientSummary("patient-600", null, null));
                if (!Boolean.TRUE.equals(other.isError()) || !text(other).contains("access_denied")) {
                    problems.add("hospital-A READ hospital-B's patient: " + text(other));
                }
                return null;
            });
        }

        stampede(tasks);

        assertThat(problems).as("900 overlapping requests, two tenants, ten connections").isEmpty();
    }

    @Test
    void everyAllowedCallLeavesExactlyOneAuditRow() throws Exception {
        long before = allowedRows("doctor-202", "MEDICATIONS", "patient-400");
        Queue<String> problems = new ConcurrentLinkedQueue<>();
        List<Callable<Void>> tasks = new ArrayList<>();

        int calls = 300;
        for (int i = 0; i < calls; i++) {
            tasks.add(() -> {
                CallToolResult result = as("doctor-202", "hospital-A", "patient.read medication.read",
                        () -> patientTools.getPatientMedications("patient-400", null, null));
                if (Boolean.TRUE.equals(result.isError())) {
                    problems.add(text(result));
                }
                return null;
            });
        }
        stampede(tasks);

        assertThat(problems).isEmpty();
        // The read and its audit row commit together, so none are lost and none are doubled.
        assertThat(allowedRows("doctor-202", "MEDICATIONS", "patient-400") - before).isEqualTo(calls);
    }

    @Test
    void aBurstFarBeyondThePoolCompletesWithoutErrors() throws Exception {
        Queue<String> problems = new ConcurrentLinkedQueue<>();
        List<Callable<Void>> tasks = new ArrayList<>();

        for (int i = 0; i < 1500; i++) {
            tasks.add(() -> {
                CallToolResult result = as("doctor-101", "hospital-A", "patient.read",
                        () -> patientTools.listMyPatients());
                if (Boolean.TRUE.equals(result.isError())) {
                    problems.add(text(result));
                }
                return null;
            });
        }

        long start = System.nanoTime();
        stampede(tasks);
        long seconds = TimeUnit.NANOSECONDS.toSeconds(System.nanoTime() - start);

        assertThat(problems).as("1500 simultaneous calls into a pool of 10").isEmpty();
        assertThat(seconds).as("finished in a sane time, not by timing out").isLessThan(60);
    }
}
