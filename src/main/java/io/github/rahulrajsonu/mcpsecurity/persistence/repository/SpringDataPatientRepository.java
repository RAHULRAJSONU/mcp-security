package io.github.rahulrajsonu.mcpsecurity.persistence.repository;

import io.github.rahulrajsonu.mcpsecurity.persistence.entity.PatientEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface SpringDataPatientRepository
        extends JpaRepository<PatientEntity, String> {

    Optional<PatientEntity> findByTenantIdAndId(
            String tenantId,
            String id
    );
}