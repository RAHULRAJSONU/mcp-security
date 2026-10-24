package io.github.rahulrajsonu.mcpsecurity.persistence.repository;

import io.github.rahulrajsonu.mcpsecurity.mcp.domain.PatientAssignment;

import java.time.Instant;
import java.util.Optional;

public interface PatientAssignmentRepository {

    boolean hasActiveAssignment(
            String tenantId,
            String clinicianId,
            String patientId
    );
}