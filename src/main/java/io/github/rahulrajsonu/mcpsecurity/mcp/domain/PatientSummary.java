package io.github.rahulrajsonu.mcpsecurity.mcp.domain;

import java.time.LocalDate;

/**
 * The minimum needed to confirm which patient this is: an internal id, a name
 * and a date of birth (two identifiers). The medical record number is not
 * returned, because nothing the agent does needs it.
 */
public record PatientSummary(
        String patientId,
        String displayName,
        LocalDate dateOfBirth
) {
    public static PatientSummary from(Patient patient) {
        return new PatientSummary(
                patient.id(),
                patient.firstName() + " " + patient.lastName(),
                patient.dateOfBirth()
        );
    }

    @Override
    public String toString() {
        return "PatientSummary[patientId=" + patientId + ", identifiers redacted]";
    }
}
