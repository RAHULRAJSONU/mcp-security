package io.github.rahulrajsonu.mcpsecurity.service;

import io.github.rahulrajsonu.mcpsecurity.exception.PatientAccessDeniedException;
import io.github.rahulrajsonu.mcpsecurity.persistence.repository.PatientAssignmentRepository;
import io.github.rahulrajsonu.mcpsecurity.persistence.repository.PatientRepository;
import io.github.rahulrajsonu.mcpsecurity.security.AccessPurpose;
import io.github.rahulrajsonu.mcpsecurity.security.ClinicalAccessContext;
import io.github.rahulrajsonu.mcpsecurity.security.ClinicalPrincipal;
import io.github.rahulrajsonu.mcpsecurity.security.PatientAccessPolicy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PatientSummaryServiceTest {

    @Mock
    PatientRepository patients;

    @Mock
    PatientAssignmentRepository assignments;

    PatientSummaryService service;

    @BeforeEach
    void setUp() {
        PatientAccessPolicy policy =
                new PatientAccessPolicy(assignments);

        service = new PatientSummaryService(
                policy,
                new VisiblePatients(patients)
        );
    }

    @Test
    void shouldDenyUnassignedPatientWithoutLoadingPHI() {

        ClinicalPrincipal principal = new ClinicalPrincipal(
                "doctor-101",
                "hospital-A",
                Set.of("patient.read")
        );

        ClinicalAccessContext context =
                new ClinicalAccessContext(
                        principal,
                        AccessPurpose.TREATMENT
                );

        when(assignments.hasActiveAssignment(
                "hospital-A",
                "doctor-101",
                "patient-500"
        )).thenReturn(false);

        assertThrows(
                PatientAccessDeniedException.class,
                () -> service.getSummary(
                        context,
                        "patient-500"
                )
        );

        verifyNoInteractions(patients);
    }
}