package io.github.rahulrajsonu.mcpsecurity.persistence.repository;

import io.github.rahulrajsonu.mcpsecurity.mcp.domain.AssignmentStatus;
import io.github.rahulrajsonu.mcpsecurity.persistence.entity.PatientAssignmentEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;

public interface SpringDataPatientAssignmentRepository
        extends JpaRepository<PatientAssignmentEntity, String> {

    @Query("""
        SELECT CASE WHEN COUNT(a) > 0
            THEN true ELSE false END
        FROM PatientAssignmentEntity a
        WHERE a.tenantId = :tenantId
          AND a.clinicianId = :clinicianId
          AND a.patientId = :patientId
          AND a.status = :status
          AND a.validFrom <= :now
          AND (a.validUntil IS NULL OR a.validUntil > :now)
        """)
    boolean hasActiveAssignment(
            @Param("tenantId") String tenantId,
            @Param("clinicianId") String clinicianId,
            @Param("patientId") String patientId,
            @Param("status") AssignmentStatus status,
            @Param("now") Instant now
    );
}