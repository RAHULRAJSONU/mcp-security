package io.github.rahulrajsonu.mcpsecurity.persistence.adapter;

import io.github.rahulrajsonu.mcpsecurity.mcp.domain.Patient;
import io.github.rahulrajsonu.mcpsecurity.persistence.repository.PatientRepository;
import io.github.rahulrajsonu.mcpsecurity.persistence.repository.SpringDataPatientRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
@RequiredArgsConstructor
public class JpaPatientRepositoryAdapter
        implements PatientRepository {

    private final SpringDataPatientRepository repository;

    @Override
    public Optional<Patient> findByTenantIdAndId(
            String tenantId,
            String patientId) {

        return repository.findByTenantIdAndId(
                tenantId, patientId
        ).map(entity -> new Patient(
                entity.getId(),
                entity.getTenantId(),
                entity.getMedicalRecordNumber(),
                entity.getFirstName(),
                entity.getLastName(),
                entity.getDateOfBirth()
        ));
    }
}