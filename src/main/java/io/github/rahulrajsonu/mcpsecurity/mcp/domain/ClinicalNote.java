package io.github.rahulrajsonu.mcpsecurity.mcp.domain;

import java.time.Instant;

public record ClinicalNote(
        String noteId,
        String authorId,
        String noteType,
        String body,
        Instant createdAt
) {
    @Override
    public String toString() {
        return "ClinicalNote[noteId=" + noteId + ", body redacted]";
    }
}
