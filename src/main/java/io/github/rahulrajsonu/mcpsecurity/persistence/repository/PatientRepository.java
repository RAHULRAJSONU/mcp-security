package io.github.rahulrajsonu.mcpsecurity.persistence.repository;

import io.github.rahulrajsonu.mcpsecurity.mcp.domain.Patient;

import java.util.Optional;

public interface PatientRepository {

    Optional<Patient> findByTenantIdAndId(
            String tenantId,
            String patientId
    );
}