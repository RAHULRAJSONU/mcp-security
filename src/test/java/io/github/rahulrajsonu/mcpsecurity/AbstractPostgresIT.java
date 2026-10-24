package io.github.rahulrajsonu.mcpsecurity;

import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.api.extension.ExecutionCondition;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.postgresql.PostgreSQLContainer;

/**
 * Real PostgreSQL with the production migrations applied, so row-level
 * security is exercised exactly as deployed. The app connects as the
 * restricted {@code healthcare_app} role; Flyway as the database owner.
 *
 * Default: a Testcontainers PostgreSQL (CI). To use an existing, EMPTY
 * database instead (no Docker), set {@code IT_DB_URL} and optionally
 * {@code IT_DB_OWNER}, {@code IT_DB_OWNER_PASSWORD}, {@code IT_DB_APP_PASSWORD}.
 * Tests are skipped, never failed, when neither is available.
 */
@SpringBootTest
@ActiveProfiles("test")
@ExtendWith(AbstractPostgresIT.DatabaseAvailable.class)
public abstract class AbstractPostgresIT {

    private static final String APP_PASSWORD_DEFAULT = "test-only";

    // The real decoder resolves the IdP's metadata at startup; tests have no IdP.
    @MockitoBean
    JwtDecoder jwtDecoder;

    private static PostgreSQLContainer container;

    private static String env(String name, String fallback) {
        String value = System.getenv(name);
        return value == null || value.isBlank() ? fallback : value;
    }

    private static boolean external() {
        return System.getenv("IT_DB_URL") != null;
    }

    private static synchronized PostgreSQLContainer container() {
        if (container == null) {
            container = new PostgreSQLContainer("postgres:17-alpine")
                    .withDatabaseName("patient_db")
                    .withInitScript("test-init-role.sql");
            container.start();
        }
        return container;
    }

    @DynamicPropertySource
    static void datasource(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.username", () -> "healthcare_app");

        if (external()) {
            registry.add("spring.datasource.url", () -> System.getenv("IT_DB_URL"));
            registry.add("spring.datasource.password",
                    () -> env("IT_DB_APP_PASSWORD", APP_PASSWORD_DEFAULT));
            registry.add("spring.flyway.user", () -> env("IT_DB_OWNER", "postgres"));
            registry.add("spring.flyway.password", () -> env("IT_DB_OWNER_PASSWORD", ""));
        } else {
            registry.add("spring.datasource.url", () -> container().getJdbcUrl());
            registry.add("spring.datasource.password", () -> APP_PASSWORD_DEFAULT);
            registry.add("spring.flyway.user", () -> container().getUsername());
            registry.add("spring.flyway.password", () -> container().getPassword());
        }
    }

    static class DatabaseAvailable implements ExecutionCondition {
        @Override
        public ConditionEvaluationResult evaluateExecutionCondition(ExtensionContext context) {
            if (external() || DockerClientFactory.instance().isDockerAvailable()) {
                return ConditionEvaluationResult.enabled("database available");
            }
            return ConditionEvaluationResult.disabled(
                    "No Docker and no IT_DB_URL: skipping database-backed tests");
        }
    }
}
