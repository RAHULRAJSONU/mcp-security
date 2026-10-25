package io.github.rahulrajsonu.mcpsecurity.service;

import io.github.rahulrajsonu.mcpsecurity.mcp.domain.ClinicalNote;
import io.github.rahulrajsonu.mcpsecurity.mcp.domain.Medication;
import io.github.rahulrajsonu.mcpsecurity.mcp.domain.RosterEntry;
import io.github.rahulrajsonu.mcpsecurity.persistence.repository.ClinicalNoteRepository;
import io.github.rahulrajsonu.mcpsecurity.persistence.repository.MedicationRepository;
import io.github.rahulrajsonu.mcpsecurity.persistence.repository.RosterRepository;
import io.github.rahulrajsonu.mcpsecurity.security.ClinicalAccessContext;
import io.github.rahulrajsonu.mcpsecurity.security.DataCategory;
import io.github.rahulrajsonu.mcpsecurity.security.PatientAccessPolicy;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.List;

/**
 * Policy first, data second. Callers reach this through
 * {@link SecuredPatientQueryService}, which supplies the tenant scope and audit.
 */
@Service
@RequiredArgsConstructor
public class PatientDataService {

    private final PatientAccessPolicy accessPolicy;
    private final VisiblePatients visiblePatients;
    private final MedicationRepository medications;
    private final ClinicalNoteRepository notes;
    private final RosterRepository roster;
    private final Clock clock;

    @Transactional(readOnly = true)
    public List<Medication> getMedications(ClinicalAccessContext context, String patientId) {
        accessPolicy.requireReadAccess(context, patientId, DataCategory.MEDICATIONS);
        visiblePatients.require(context, patientId);

        return medications.findActive(context.principal().tenantId(), patientId);
    }

    @Transactional(readOnly = true)
    public List<ClinicalNote> getNotes(ClinicalAccessContext context, String patientId) {
        accessPolicy.requireReadAccess(context, patientId, DataCategory.CLINICAL_NOTES);
        visiblePatients.require(context, patientId);

        return notes.findByPatient(context.principal().tenantId(), patientId);
    }

    @Transactional(readOnly = true)
    public List<RosterEntry> getRoster(ClinicalAccessContext context) {
        accessPolicy.requireRosterAccess(context);

        return roster.findActive(
                context.principal().tenantId(),
                context.principal().subject(),
                Instant.now(clock));
    }
}
