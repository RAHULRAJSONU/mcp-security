package io.github.rahulrajsonu.mcpsecurity.persistence.entity;

import jakarta.persistence.*;
import java.time.LocalDate;

@Entity
@Table(
    name = "patients",
    uniqueConstraints = @UniqueConstraint(
        name = "uk_patient_tenant_id",
        columnNames = {"tenant_id", "id"}
    )
)
public class PatientEntity {

    @Id
    @Column(nullable = false)
    private String id;

    @Column(name = "tenant_id", nullable = false)
    private String tenantId;

    @Column(name = "medical_record_number", nullable = false)
    private String medicalRecordNumber;

    @Column(name = "first_name", nullable = false)
    private String firstName;

    @Column(name = "last_name", nullable = false)
    private String lastName;

    @Column(name = "date_of_birth", nullable = false)
    private LocalDate dateOfBirth;

    protected PatientEntity() {}

    public PatientEntity(
            String id,
            String tenantId,
            String medicalRecordNumber,
            String firstName,
            String lastName,
            LocalDate dateOfBirth) {
        this.id = id;
        this.tenantId = tenantId;
        this.medicalRecordNumber = medicalRecordNumber;
        this.firstName = firstName;
        this.lastName = lastName;
        this.dateOfBirth = dateOfBirth;
    }

    public String getId() { return id; }
    public String getTenantId() { return tenantId; }
    public String getMedicalRecordNumber() { return medicalRecordNumber; }
    public String getFirstName() { return firstName; }
    public String getLastName() { return lastName; }
    public LocalDate getDateOfBirth() { return dateOfBirth; }
}