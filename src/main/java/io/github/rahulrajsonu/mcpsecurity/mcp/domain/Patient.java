package io.github.rahulrajsonu.mcpsecurity.mcp.domain;

import java.time.LocalDate;
import java.util.Objects;

public record Patient(
        String id,
        String tenantId,
        String medicalRecordNumber,
        String firstName,
        String lastName,
        LocalDate dateOfBirth
) {
    public Patient {
        Objects.requireNonNull(id);
        Objects.requireNonNull(tenantId);
        Objects.requireNonNull(medicalRecordNumber);
        Objects.requireNonNull(firstName);
        Objects.requireNonNull(lastName);
        Objects.requireNonNull(dateOfBirth);
    }

    /** Records print every field; this one holds direct identifiers, so it must never reach a log. */
    @Override
    public String toString() {
        return "Patient[id=" + id + ", identifiers redacted]";
    }
}
