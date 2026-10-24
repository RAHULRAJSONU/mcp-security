package io.github.rahulrajsonu.mcpsecurity.persistence.adapter;

import io.github.rahulrajsonu.mcpsecurity.mcp.domain.AssignmentStatus;
import io.github.rahulrajsonu.mcpsecurity.persistence.repository.PatientAssignmentRepository;
import io.github.rahulrajsonu.mcpsecurity.persistence.repository.SpringDataPatientAssignmentRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import java.time.Clock;
import java.time.Instant;

@Repository
@RequiredArgsConstructor
public class JpaPatientAssignmentRepositoryAdapter
        implements PatientAssignmentRepository {

    private final SpringDataPatientAssignmentRepository repository;
    private final Clock clock;

    @Override
    public boolean hasActiveAssignment(
            String tenantId,
            String clinicianId,
            String patientId) {

        return repository.hasActiveAssignment(
                tenantId,
                clinicianId,
                patientId,
                AssignmentStatus.ACTIVE,
                Instant.now(clock)
        );
    }
}