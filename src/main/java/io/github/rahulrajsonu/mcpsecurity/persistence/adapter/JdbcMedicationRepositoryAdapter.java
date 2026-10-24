package io.github.rahulrajsonu.mcpsecurity.persistence.adapter;

import io.github.rahulrajsonu.mcpsecurity.mcp.domain.Medication;
import io.github.rahulrajsonu.mcpsecurity.persistence.repository.MedicationRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
@RequiredArgsConstructor
public class JdbcMedicationRepositoryAdapter
        implements MedicationRepository {

    private final JdbcClient jdbc;

    @Override
    public List<Medication> findActive(String tenantId, String patientId) {
        return jdbc.sql("""
                        SELECT name, dose, frequency
                        FROM medications
                        WHERE tenant_id = :tenantId
                          AND patient_id = :patientId
                          AND active
                        ORDER BY name
                        """)
                .param("tenantId", tenantId)
                .param("patientId", patientId)
                .query((rs, row) -> new Medication(
                        rs.getString("name"),
                        rs.getString("dose"),
                        rs.getString("frequency")))
                .list();
    }
}
