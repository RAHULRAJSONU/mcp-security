package io.github.rahulrajsonu.mcpsecurity;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.rahulrajsonu.mcpsecurity.security.ClinicalPrincipal;
import io.github.rahulrajsonu.mcpsecurity.security.TenantScopedExecutor;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.simple.JdbcClient;

/**
 * The database, not the application, makes the audit trail append-only and
 * tenant-scoped. These run raw SQL as the application's own restricted role.
 */
class AppendOnlyAuditIT extends AbstractPostgresIT {

    @Autowired
    TenantScopedExecutor executor;

    @Autowired
    JdbcClient jdbc;

    private static final ClinicalPrincipal HOSPITAL_A =
            new ClinicalPrincipal("attacker", "hospital-A", Set.of("audit.read"));

    private int insert(String tenant) {
        return jdbc.sql("""
                        INSERT INTO access_events (id, tenant_id, occurred_at, subject, patient_id,
                                                   purpose, category, outcome, break_glass)
                        VALUES (:id, :tenant, now(), 's', 'p', 'TREATMENT', 'PATIENT_SUMMARY', 'ALLOWED', false)
                        """)
                .param("id", UUID.randomUUID().toString())
                .param("tenant", tenant)
                .update();
    }

    @Test
    void theApplicationRoleCanAppendEventsForItsOwnTenant() {
        assertThatCode(() -> executor.execute(HOSPITAL_A, () -> insert("hospital-A")))
                .doesNotThrowAnyException();
    }

    @Test
    void theApplicationRoleCannotWriteEventsForAnotherTenant() {
        assertThatThrownBy(() -> executor.execute(HOSPITAL_A, () -> insert("hospital-B")))
                .isInstanceOf(DataAccessException.class);
    }

    @Test
    void theApplicationRoleCannotRewriteHistory() {
        assertThatThrownBy(() -> executor.execute(HOSPITAL_A,
                () -> jdbc.sql("UPDATE access_events SET outcome = 'ALLOWED'").update()))
                .isInstanceOf(DataAccessException.class);

        assertThatThrownBy(() -> executor.execute(HOSPITAL_A,
                () -> jdbc.sql("DELETE FROM access_events").update()))
                .isInstanceOf(DataAccessException.class);
    }

    @Test
    void theApplicationRoleCannotWriteClinicalData() {
        assertThatThrownBy(() -> executor.execute(HOSPITAL_A,
                () -> jdbc.sql("DELETE FROM clinical_notes").update()))
                .isInstanceOf(DataAccessException.class);
    }
}
