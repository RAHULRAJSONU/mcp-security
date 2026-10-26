package io.github.rahulrajsonu.mcpsecurity;

import static io.github.rahulrajsonu.mcpsecurity.mcp.tool.ToolResultAssert.assertFailed;
import static io.github.rahulrajsonu.mcpsecurity.mcp.tool.ToolResultAssert.items;
import static io.github.rahulrajsonu.mcpsecurity.mcp.tool.ToolResultAssert.text;
import static org.assertj.core.api.Assertions.assertThat;

import io.github.rahulrajsonu.mcpsecurity.mcp.tool.PatientMcpTools;
import io.github.rahulrajsonu.mcpsecurity.security.CallBulkhead;
import io.github.rahulrajsonu.mcpsecurity.security.ClinicalPrincipal;
import io.github.rahulrajsonu.mcpsecurity.security.TenantScopedExecutor;
import io.micrometer.core.instrument.MeterRegistry;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.test.context.TestPropertySource;

/**
 * When the server is saturated it must say so quickly and keep working afterwards.
 * Two places are held open on purpose, so the refusal is deterministic: no timing,
 * no reliance on the database being slow.
 */
@TestPropertySource(properties = {
        "app.concurrency.max-in-flight-calls=2",
        "app.concurrency.max-wait=PT0.05S",
        "app.security.agent.calls-per-minute=10000000",
        "app.security.agent.calls-per-day=100000000"})
class LoadSheddingIT extends AbstractPostgresIT {

    @Autowired
    PatientMcpTools patientTools;

    @Autowired
    CallBulkhead bulkhead;

    @Autowired
    MeterRegistry meters;

    @Autowired
    TenantScopedExecutor tenantExecutor;

    @Autowired
    JdbcClient jdbc;

    private ExecutorService holders;
    private CountDownLatch release;

    @BeforeEach
    void occupyEveryPlace() throws Exception {
        holders = Executors.newVirtualThreadPerTaskExecutor();
        release = new CountDownLatch(1);
        CountDownLatch started = new CountDownLatch(2);
        for (int i = 0; i < 2; i++) {
            holders.submit(() -> bulkhead.run(() -> {
                started.countDown();
                try {
                    release.await();
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                }
                return null;
            }));
        }
        assertThat(started.await(10, TimeUnit.SECONDS)).isTrue();
    }

    @AfterEach
    void letGo() {
        release.countDown();
        holders.close();
        SecurityContextHolder.clearContext();
    }

    private static void loginAs(String subject, String tenant, String scopes) {
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
    }

    private long auditRows(String subject) {
        ClinicalPrincipal reader = new ClinicalPrincipal("compliance-1", "hospital-A", Set.of("audit.read"));
        return tenantExecutor.execute(reader, () -> jdbc.sql(
                        "SELECT count(*) FROM access_events WHERE subject = :s")
                .param("s", subject).query(Long.class).single());
    }

    @Test
    void aSaturatedServerRefusesQuicklyAndRetryably() {
        loginAs("doctor-101", "hospital-A", "patient.read");

        long start = System.nanoTime();
        CallToolResult result = patientTools.listMyPatients();
        Duration took = Duration.ofNanos(System.nanoTime() - start);

        assertFailed(result, "server_busy");
        assertThat(((Map<?, ?>) result.structuredContent()).get("retryable")).isEqualTo(true);
        assertThat(took).as("refused at once, not after queueing for a connection").isLessThan(Duration.ofSeconds(2));
    }

    @Test
    void aRefusedCallTouchesNeitherTheDataNorTheAuditTrail() {
        long before = auditRows("doctor-101");
        loginAs("doctor-101", "hospital-A", "patient.read medication.read");

        CallToolResult result = patientTools.getPatientMedications("patient-400", null, null);

        assertFailed(result, "server_busy");
        assertThat(text(result)).doesNotContain("Atorvastatin").doesNotContain("patient-400");
        // Shed before any decision was made: not logged as a denial or an error either.
        assertThat(auditRows("doctor-101")).isEqualTo(before);
    }

    @Test
    void aWholeBurstIsShedAsBusyNeverAsAFailure() throws Exception {
        List<Callable<String>> calls = new ArrayList<>();
        for (int i = 0; i < 40; i++) {
            calls.add(() -> {
                loginAs("doctor-101", "hospital-A", "patient.read");
                try {
                    return text(patientTools.listMyPatients());
                } finally {
                    SecurityContextHolder.clearContext();
                }
            });
        }

        List<String> bodies = new ArrayList<>();
        try (ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Future<String>> futures = new ArrayList<>();
            for (Callable<String> call : calls) {
                futures.add(pool.submit(call));
            }
            for (Future<String> future : futures) {
                bodies.add(future.get(30, TimeUnit.SECONDS));
            }
        }

        assertThat(bodies).hasSize(40).allSatisfy(body -> assertThat(body).contains("\"error\":\"server_busy\""));
    }

    @Test
    void theCountersAndGaugeShowTheOverload() {
        double before = meters.get("mcp.bulkhead.rejected").counter().count();
        loginAs("doctor-101", "hospital-A", "patient.read");

        patientTools.listMyPatients();
        patientTools.listMyPatients();

        assertThat(meters.get("mcp.bulkhead.rejected").counter().count()).isEqualTo(before + 2);
        assertThat(meters.get("mcp.bulkhead.in.flight").gauge().value()).isEqualTo(2.0);
    }

    @Test
    void onceThePressureEndsTheServerServesAgain() throws Exception {
        loginAs("doctor-101", "hospital-A", "patient.read");
        assertFailed(patientTools.listMyPatients(), "server_busy");

        release.countDown();
        // Places are returned as the held work finishes.
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        CallToolResult result;
        do {
            result = patientTools.listMyPatients();
        } while (Boolean.TRUE.equals(result.isError()) && System.nanoTime() < deadline);

        assertThat(result.isError()).isNotEqualTo(true);
        assertThat(items(result)).isNotEmpty();
    }
}
