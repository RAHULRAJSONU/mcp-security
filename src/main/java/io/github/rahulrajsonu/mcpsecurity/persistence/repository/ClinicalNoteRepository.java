package io.github.rahulrajsonu.mcpsecurity.persistence.repository;

import io.github.rahulrajsonu.mcpsecurity.mcp.domain.ClinicalNote;

import java.util.List;

public interface ClinicalNoteRepository {

    List<ClinicalNote> findByPatient(String tenantId, String patientId);
}
