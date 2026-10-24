package io.github.rahulrajsonu.mcpsecurity.service;

import io.github.rahulrajsonu.mcpsecurity.mcp.domain.Patient;
import io.github.rahulrajsonu.mcpsecurity.mcp.domain.PatientSummary;
import io.github.rahulrajsonu.mcpsecurity.persistence.repository.PatientRepository;
import io.github.rahulrajsonu.mcpsecurity.security.ClinicalAccessContext;
import io.github.rahulrajsonu.mcpsecurity.exception.ClinicalAccessDeniedException;
import io.github.rahulrajsonu.mcpsecurity.security.PatientAccessPolicy;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class PatientSummaryService {

    private final PatientAccessPolicy accessPolicy;
    private final PatientRepository patients;

    public PatientSummaryService(
            PatientAccessPolicy accessPolicy,
            PatientRepository patients) {

        this.accessPolicy = accessPolicy;
        this.patients = patients;
    }

    @Transactional(readOnly = true)
    public PatientSummary getSummary(
            ClinicalAccessContext context,
            String patientId) {

        accessPolicy.requireReadAccess(context, patientId);

        Patient patient = patients
                .findByTenantIdAndId(
                        context.principal().tenantId(),
                        patientId
                )
                .orElseThrow(
                        ClinicalAccessDeniedException::new
                );

        return PatientSummary.from(patient);
    }
}