package io.github.rahulrajsonu.mcpsecurity.mcp.domain;

import java.time.Instant;

/**
 * One recorded access decision. {@code justification} is only present for
 * emergency (break-glass) attempts, is free text that may contain PHI, and is
 * visible solely to audit readers.
 */
public record AccessEvent(
        Instant occurredAt,
        String subject,
        String patientId,
        String purpose,
        String category,
        String outcome,
        boolean breakGlass,
        String justification,
        String clientId
) {
    @Override
    public String toString() {
        return "AccessEvent[subject=" + subject + ", patientId=" + patientId
                + ", clientId=" + clientId + ", category=" + category + ", outcome=" + outcome
                + ", justification " + (justification == null ? "absent" : "redacted") + "]";
    }
}
