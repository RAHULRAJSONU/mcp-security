package io.github.rahulrajsonu.mcpsecurity.persistence.adapter;

import io.github.rahulrajsonu.mcpsecurity.mcp.domain.RosterEntry;
import io.github.rahulrajsonu.mcpsecurity.persistence.repository.RosterRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;

@Repository
@RequiredArgsConstructor
public class JdbcRosterRepositoryAdapter
        implements RosterRepository {

    private final JdbcClient jdbc;

    @Override
    public List<RosterEntry> findActive(
            String tenantId,
            String clinicianId,
            Instant now) {

        return jdbc.sql("""
                        SELECT p.id, p.first_name, p.last_name
                        FROM patient_assignments a
                        JOIN patients p
                          ON p.tenant_id = a.tenant_id AND p.id = a.patient_id
                        WHERE a.tenant_id = :tenantId
                          AND a.clinician_id = :clinicianId
                          AND a.status = 'ACTIVE'
                          AND a.valid_from <= :now
                          AND (a.valid_until IS NULL OR a.valid_until > :now)
                        ORDER BY p.id
                        """)
                .param("tenantId", tenantId)
                .param("clinicianId", clinicianId)
                .param("now", OffsetDateTime.ofInstant(now, ZoneOffset.UTC))
                .query((rs, row) -> new RosterEntry(
                        rs.getString("id"),
                        rs.getString("first_name") + " " + rs.getString("last_name")))
                .list();
    }
}
