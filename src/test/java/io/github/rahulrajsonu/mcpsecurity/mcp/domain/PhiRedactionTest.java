package io.github.rahulrajsonu.mcpsecurity.mcp.domain;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.time.LocalDate;
import org.junit.jupiter.api.Test;

/**
 * Records print every field by default, so anything that logs one (a debug
 * statement, an exception message, a framework) would leak PHI. These types
 * override toString, and this test fails if that is ever removed.
 */
class PhiRedactionTest {

    private static final String NAME = "Zelda Quill";
    private static final String MRN = "MRN-SECRET-1";
    private static final String DOB = "1971-02-03";
    private static final String NOTE = "Patient reports a sensitive condition";
    private static final String DRUG = "Zorbacillin";
    private static final String WHY = "Collapsed in the waiting room, history unknown";

    private static void assertNoPhi(Object value) {
        assertThat(value.toString())
                .doesNotContain("Zelda", "Quill", MRN, DOB, "sensitive", DRUG, "Collapsed");
    }

    @Test
    void patientDoesNotPrintIdentifiers() {
        assertNoPhi(new Patient("p1", "t1", MRN, "Zelda", "Quill", LocalDate.parse(DOB)));
    }

    @Test
    void summaryDoesNotPrintIdentifiers() {
        assertNoPhi(new PatientSummary("p1", NAME, LocalDate.parse(DOB)));
    }

    @Test
    void rosterDoesNotPrintTheName() {
        assertNoPhi(new RosterEntry("p1", NAME));
    }

    @Test
    void medicationDoesNotPrintTheDrug() {
        assertNoPhi(new Medication(DRUG, "10 mg", "daily"));
    }

    @Test
    void noteDoesNotPrintTheBody() {
        assertNoPhi(new ClinicalNote("n1", "doctor-101", "PROGRESS", NOTE, Instant.now()));
    }

    @Test
    void accessEventDoesNotPrintTheJustification() {
        assertNoPhi(new AccessEvent(Instant.now(), "doctor-101", "p1", "EMERGENCY",
                "MEDICATIONS", "ALLOWED", true, WHY, "healthcare-mcp-client"));
    }

    @Test
    void redactedFormsStillIdentifyTheRecordForDebugging() {
        assertThat(new Patient("p1", "t1", MRN, "Zelda", "Quill", LocalDate.parse(DOB)).toString()).contains("p1");
        assertThat(new ClinicalNote("n1", "d", "PROGRESS", NOTE, Instant.now()).toString()).contains("n1");
    }
}
