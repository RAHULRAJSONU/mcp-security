package io.github.rahulrajsonu.mcpsecurity.service;

import io.github.rahulrajsonu.mcpsecurity.exception.ClinicalAccessDeniedException;
import io.github.rahulrajsonu.mcpsecurity.mcp.domain.Patient;
import io.github.rahulrajsonu.mcpsecurity.persistence.repository.PatientRepository;
import io.github.rahulrajsonu.mcpsecurity.security.ClinicalAccessContext;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * An unknown or other-tenant patient must not look like "a patient with no
 * data", or a read could be used to probe which ids exist.
 */
@Component
@RequiredArgsConstructor
public class VisiblePatients {

    private final PatientRepository patients;

    public Patient require(ClinicalAccessContext context, String patientId) {
        return patients.findByTenantIdAndId(context.principal().tenantId(), patientId)
                .orElseThrow(ClinicalAccessDeniedException::new);
    }
}
