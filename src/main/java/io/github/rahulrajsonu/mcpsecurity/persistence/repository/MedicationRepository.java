package io.github.rahulrajsonu.mcpsecurity.persistence.repository;

import io.github.rahulrajsonu.mcpsecurity.mcp.domain.Medication;

import java.util.List;

public interface MedicationRepository {

    List<Medication> findActive(String tenantId, String patientId);
}
