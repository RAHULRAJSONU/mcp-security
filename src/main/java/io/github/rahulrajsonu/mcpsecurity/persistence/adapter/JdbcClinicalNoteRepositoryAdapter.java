package io.github.rahulrajsonu.mcpsecurity.persistence.adapter;

import io.github.rahulrajsonu.mcpsecurity.mcp.domain.ClinicalNote;
import io.github.rahulrajsonu.mcpsecurity.persistence.repository.ClinicalNoteRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.time.OffsetDateTime;
import java.util.List;

@Repository
@RequiredArgsConstructor
public class JdbcClinicalNoteRepositoryAdapter
        implements ClinicalNoteRepository {

    private final JdbcClient jdbc;

    @Override
    public List<ClinicalNote> findByPatient(String tenantId, String patientId) {
        return jdbc.sql("""
                        SELECT id, author_id, note_type, body, created_at
                        FROM clinical_notes
                        WHERE tenant_id = :tenantId
                          AND patient_id = :patientId
                        ORDER BY created_at DESC
                        """)
                .param("tenantId", tenantId)
                .param("patientId", patientId)
                .query((rs, row) -> new ClinicalNote(
                        rs.getString("id"),
                        rs.getString("author_id"),
                        rs.getString("note_type"),
                        rs.getString("body"),
                        rs.getObject("created_at", OffsetDateTime.class).toInstant()))
                .list();
    }
}
