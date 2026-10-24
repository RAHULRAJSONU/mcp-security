package io.github.rahulrajsonu.mcpsecurity.persistence.entity;

import io.github.rahulrajsonu.mcpsecurity.mcp.domain.AssignmentStatus;
import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(
    name = "patient_assignments",
    indexes = @Index(
        name = "idx_assignment_lookup",
        columnList = "tenant_id,clinician_id,patient_id,status"
    )
)
public class PatientAssignmentEntity {

    @Id
    private String id;

    @Column(name = "tenant_id", nullable = false)
    private String tenantId;

    @Column(name = "clinician_id", nullable = false)
    private String clinicianId;

    @Column(name = "patient_id", nullable = false)
    private String patientId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private AssignmentStatus status;

    @Column(name = "valid_from", nullable = false)
    private Instant validFrom;

    @Column(name = "valid_until")
    private Instant validUntil;

    protected PatientAssignmentEntity() {}

    public PatientAssignmentEntity(
            String id,
            String tenantId,
            String clinicianId,
            String patientId,
            AssignmentStatus status,
            Instant validFrom,
            Instant validUntil) {
        this.id = id;
        this.tenantId = tenantId;
        this.clinicianId = clinicianId;
        this.patientId = patientId;
        this.status = status;
        this.validFrom = validFrom;
        this.validUntil = validUntil;
    }
}