package io.github.rahulrajsonu.mcpsecurity.mcp.domain;

public record Medication(
        String name,
        String dose,
        String frequency
) {
    @Override
    public String toString() {
        return "Medication[redacted]";
    }
}
