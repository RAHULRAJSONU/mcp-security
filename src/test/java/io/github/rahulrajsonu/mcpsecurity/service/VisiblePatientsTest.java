package io.github.rahulrajsonu.mcpsecurity.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.github.rahulrajsonu.mcpsecurity.exception.ClinicalAccessDeniedException;
import io.github.rahulrajsonu.mcpsecurity.mcp.domain.Patient;
import io.github.rahulrajsonu.mcpsecurity.persistence.repository.PatientRepository;
import io.github.rahulrajsonu.mcpsecurity.security.AccessPurpose;
import io.github.rahulrajsonu.mcpsecurity.security.ClinicalAccessContext;
import io.github.rahulrajsonu.mcpsecurity.security.ClinicalPrincipal;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;

class VisiblePatientsTest {

    private final PatientRepository patients = mock(PatientRepository.class);
    private final VisiblePatients visible = new VisiblePatients(patients);

    private static ClinicalAccessContext context(String tenant) {
        return new ClinicalAccessContext(
                new ClinicalPrincipal("doctor-101", tenant, Set.of("patient.read")), AccessPurpose.TREATMENT);
    }

    @Test
    void returnsThePatientInTheCallersTenant() {
        Patient patient = mock(Patient.class);
        when(patients.findByTenantIdAndId("hospital-A", "patient-400")).thenReturn(Optional.of(patient));

        assertThat(visible.require(context("hospital-A"), "patient-400")).isSameAs(patient);
    }

    @Test
    void unknownAndOtherTenantPatientsLookIdentical() {
        when(patients.findByTenantIdAndId("hospital-A", "patient-600")).thenReturn(Optional.empty());
        when(patients.findByTenantIdAndId("hospital-A", "no-such-patient")).thenReturn(Optional.empty());

        // Same exception and message either way, so ids cannot be probed.
        assertThatThrownBy(() -> visible.require(context("hospital-A"), "patient-600"))
                .isInstanceOf(ClinicalAccessDeniedException.class)
                .hasMessage("Clinical resource access denied");
        assertThatThrownBy(() -> visible.require(context("hospital-A"), "no-such-patient"))
                .isInstanceOf(ClinicalAccessDeniedException.class)
                .hasMessage("Clinical resource access denied");
    }
}
