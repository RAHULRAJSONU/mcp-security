package io.github.rahulrajsonu.mcpsecurity.persistence.adapter;

import io.github.rahulrajsonu.mcpsecurity.mcp.domain.AccessEvent;
import io.github.rahulrajsonu.mcpsecurity.persistence.repository.AccessEventRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;

@Repository
@RequiredArgsConstructor
public class JdbcAccessEventRepositoryAdapter
        implements AccessEventRepository {

    private static final RowMapper<AccessEvent> MAPPER = (rs, row) -> new AccessEvent(
            rs.getObject("occurred_at", OffsetDateTime.class).toInstant(),
            rs.getString("subject"),
            rs.getString("patient_id"),
            rs.getString("purpose"),
            rs.getString("category"),
            rs.getString("outcome"),
            rs.getBoolean("break_glass"),
            rs.getString("justification"),
            rs.getString("client_id"));

    private static final String COLUMNS = """
            occurred_at, subject, patient_id, purpose, category,
            outcome, break_glass, justification, client_id
            """;

    private final JdbcClient jdbc;

    @Override
    public void append(String tenantId, AccessEvent event) {
        jdbc.sql("""
                        INSERT INTO access_events (
                            id, tenant_id, occurred_at, subject, patient_id, purpose,
                            category, outcome, break_glass, justification, client_id)
                        VALUES (
                            :id, :tenantId, :occurredAt, :subject, :patientId, :purpose,
                            :category, :outcome, :breakGlass, :justification, :clientId)
                        """)
                .param("id", UUID.randomUUID().toString())
                .param("tenantId", tenantId)
                .param("occurredAt", OffsetDateTime.ofInstant(event.occurredAt(), ZoneOffset.UTC))
                .param("subject", event.subject())
                .param("patientId", event.patientId())
                .param("purpose", event.purpose())
                .param("category", event.category())
                .param("outcome", event.outcome())
                .param("breakGlass", event.breakGlass())
                .param("justification", event.justification())
                .param("clientId", event.clientId())
                .update();
    }

    @Override
    public List<AccessEvent> findByPatient(String tenantId, String patientId, int limit) {
        return jdbc.sql("SELECT " + COLUMNS + """
                        FROM access_events
                        WHERE tenant_id = :tenantId AND patient_id = :patientId
                        ORDER BY occurred_at DESC
                        LIMIT :limit
                        """)
                .param("tenantId", tenantId)
                .param("patientId", patientId)
                .param("limit", limit)
                .query(MAPPER)
                .list();
    }

    @Override
    public List<AccessEvent> findBreakGlass(String tenantId, int limit) {
        return jdbc.sql("SELECT " + COLUMNS + """
                        FROM access_events
                        WHERE tenant_id = :tenantId AND break_glass
                        ORDER BY occurred_at DESC
                        LIMIT :limit
                        """)
                .param("tenantId", tenantId)
                .param("limit", limit)
                .query(MAPPER)
                .list();
    }
}
