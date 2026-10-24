package io.github.rahulrajsonu.mcpsecurity.mcp.domain;

import java.time.Instant;
import java.util.Objects;

import java.time.Instant;
import java.util.Objects;

public record PatientAssignment(
        String id,
        String tenantId,
        String clinicianId,
        String patientId,
        AssignmentStatus status,
        Instant validFrom,
        Instant validUntil
) {
    public PatientAssignment {
        Objects.requireNonNull(id);
        Objects.requireNonNull(tenantId);
        Objects.requireNonNull(clinicianId);
        Objects.requireNonNull(patientId);
        Objects.requireNonNull(status);
        Objects.requireNonNull(validFrom);
    }

    public boolean isActiveAt(Instant now) {
        return status == AssignmentStatus.ACTIVE
                && !now.isBefore(validFrom)
                && (validUntil == null || now.isBefore(validUntil));
    }
}