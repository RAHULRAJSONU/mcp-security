package io.github.rahulrajsonu.mcpsecurity.mcp.domain;

/** Minimum needed to pick a patient: an identifier and a display name. */
public record RosterEntry(
        String patientId,
        String displayName
) {
    @Override
    public String toString() {
        return "RosterEntry[patientId=" + patientId + ", name redacted]";
    }
}
