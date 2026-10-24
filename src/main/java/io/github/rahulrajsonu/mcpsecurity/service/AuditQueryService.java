package io.github.rahulrajsonu.mcpsecurity.service;

import io.github.rahulrajsonu.mcpsecurity.mcp.domain.AccessEvent;
import io.github.rahulrajsonu.mcpsecurity.persistence.repository.AccessEventRepository;
import io.github.rahulrajsonu.mcpsecurity.security.ClinicalAccessContext;
import io.github.rahulrajsonu.mcpsecurity.security.PatientAccessPolicy;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
public class AuditQueryService {

    static final int DEFAULT_LIMIT = 50;
    static final int MAX_LIMIT = 200;

    private final PatientAccessPolicy accessPolicy;
    private final AccessEventRepository events;

    @Transactional(readOnly = true)
    public List<AccessEvent> historyFor(ClinicalAccessContext context, String patientId, Integer limit) {
        accessPolicy.requireAuditAccess(context.principal());

        return events.findByPatient(context.principal().tenantId(), patientId, clamp(limit));
    }

    @Transactional(readOnly = true)
    public List<AccessEvent> breakGlassEvents(ClinicalAccessContext context, Integer limit) {
        accessPolicy.requireAuditAccess(context.principal());

        return events.findBreakGlass(context.principal().tenantId(), clamp(limit));
    }

    static int clamp(Integer requested) {
        if (requested == null || requested < 1) {
            return DEFAULT_LIMIT;
        }
        return Math.min(requested, MAX_LIMIT);
    }
}
