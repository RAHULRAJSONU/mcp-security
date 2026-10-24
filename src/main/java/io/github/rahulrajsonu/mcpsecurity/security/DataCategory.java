package io.github.rahulrajsonu.mcpsecurity.security;

/**
 * What kind of data a tool touches. Each category has its own scope, so a
 * token granted one kind of access does not silently get the others, and it
 * decides whether emergency (break-glass) access may reach it at all.
 */
public enum DataCategory {

    PATIENT_SUMMARY("patient.read", true),
    MEDICATIONS("medication.read", true),
    /** Deliberately out of reach for break-glass: an emergency does not need free-text notes. */
    CLINICAL_NOTES("notes.read", false),
    PATIENT_ROSTER("patient.read", false),
    ACCESS_AUDIT("audit.read", false);

    private final String requiredScope;
    private final boolean breakGlassAllowed;

    DataCategory(String requiredScope, boolean breakGlassAllowed) {
        this.requiredScope = requiredScope;
        this.breakGlassAllowed = breakGlassAllowed;
    }

    public String requiredScope() {
        return requiredScope;
    }

    public boolean breakGlassAllowed() {
        return breakGlassAllowed;
    }
}
