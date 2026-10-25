package io.github.rahulrajsonu.mcpsecurity.service;

import io.github.rahulrajsonu.mcpsecurity.mcp.domain.PatientSummary;
import io.github.rahulrajsonu.mcpsecurity.security.ClinicalAccessContext;
import io.github.rahulrajsonu.mcpsecurity.security.PatientAccessPolicy;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class PatientSummaryService {

    private final PatientAccessPolicy accessPolicy;
    private final VisiblePatients visiblePatients;

    public PatientSummaryService(
            PatientAccessPolicy accessPolicy,
            VisiblePatients visiblePatients) {

        this.accessPolicy = accessPolicy;
        this.visiblePatients = visiblePatients;
    }

    @Transactional(readOnly = true)
    public PatientSummary getSummary(
            ClinicalAccessContext context,
            String patientId) {

        accessPolicy.requireReadAccess(context, patientId);

        return PatientSummary.from(visiblePatients.require(context, patientId));
    }
}
