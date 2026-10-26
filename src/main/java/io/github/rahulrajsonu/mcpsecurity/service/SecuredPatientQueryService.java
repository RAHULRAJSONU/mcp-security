package io.github.rahulrajsonu.mcpsecurity.service;

import io.github.rahulrajsonu.mcpsecurity.exception.AuditUnavailableException;
import io.github.rahulrajsonu.mcpsecurity.exception.ClinicalAccessDeniedException;
import io.github.rahulrajsonu.mcpsecurity.exception.PatientAccessDeniedException;
import io.github.rahulrajsonu.mcpsecurity.exception.RateLimitExceededException;
import io.github.rahulrajsonu.mcpsecurity.exception.ServerBusyException;
import io.github.rahulrajsonu.mcpsecurity.exception.RequestFailedException;
import io.github.rahulrajsonu.mcpsecurity.mcp.domain.AccessEvent;
import io.github.rahulrajsonu.mcpsecurity.mcp.domain.ClinicalNote;
import io.github.rahulrajsonu.mcpsecurity.mcp.domain.Medication;
import io.github.rahulrajsonu.mcpsecurity.mcp.domain.PatientSummary;
import io.github.rahulrajsonu.mcpsecurity.mcp.domain.RosterEntry;
import io.github.rahulrajsonu.mcpsecurity.security.AgentAccessPolicy;
import io.github.rahulrajsonu.mcpsecurity.security.AgentQuota;
import io.github.rahulrajsonu.mcpsecurity.security.CallBulkhead;
import io.github.rahulrajsonu.mcpsecurity.security.ClinicalAccessContext;
import io.github.rahulrajsonu.mcpsecurity.security.DataCategory;
import io.github.rahulrajsonu.mcpsecurity.security.TenantScopedExecutor;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.function.Supplier;

/**
 * The single door every tool goes through: tenant-scoped transaction, then the
 * policy and read, then a durable audit record before anything is returned.
 */
@Service
@RequiredArgsConstructor
public class SecuredPatientQueryService {

    private static final Logger LOG = LoggerFactory.getLogger(SecuredPatientQueryService.class);

    /** Audit target for operations that are not about one patient. */
    static final String NO_PATIENT = "*";

    /** Ids are short and plain. Anything else is refused before it reaches a query or the audit row. */
    private static final java.util.regex.Pattern PATIENT_ID = java.util.regex.Pattern.compile("[A-Za-z0-9._:-]{1,64}");

    private final TenantScopedExecutor tenantExecutor;
    private final PatientSummaryService patientSummaryService;
    private final PatientDataService patientDataService;
    private final AuditQueryService auditQueryService;
    private final AccessAuditor auditor;
    private final AgentAccessPolicy agentPolicy;
    private final AgentQuota quota;
    private final CallBulkhead bulkhead;

    public PatientSummary getSummary(
            ClinicalAccessContext context,
            String patientId) {

        return guarded(context, patientId, DataCategory.PATIENT_SUMMARY,
                () -> patientSummaryService.getSummary(context, patientId));
    }

    public List<Medication> getMedications(ClinicalAccessContext context, String patientId) {
        return guarded(context, patientId, DataCategory.MEDICATIONS,
                () -> patientDataService.getMedications(context, patientId));
    }

    public List<ClinicalNote> getNotes(ClinicalAccessContext context, String patientId) {
        return guarded(context, patientId, DataCategory.CLINICAL_NOTES,
                () -> patientDataService.getNotes(context, patientId));
    }

    public List<RosterEntry> getRoster(ClinicalAccessContext context) {
        return guarded(context, NO_PATIENT, DataCategory.PATIENT_ROSTER,
                () -> patientDataService.getRoster(context));
    }

    /** Reading the audit trail is itself audited. */
    public List<AccessEvent> getAccessHistory(
            ClinicalAccessContext context, String patientId, Integer limit) {

        return guarded(context, patientId, DataCategory.ACCESS_AUDIT,
                () -> auditQueryService.historyFor(context, patientId, limit));
    }

    public List<AccessEvent> getBreakGlassEvents(ClinicalAccessContext context, Integer limit) {
        return guarded(context, NO_PATIENT, DataCategory.ACCESS_AUDIT,
                () -> auditQueryService.breakGlassEvents(context, limit));
    }

    private <T> T guarded(
            ClinicalAccessContext context,
            String patientId,
            DataCategory category,
            Supplier<T> read) {

        try {
            requireWellFormed(patientId);
            quota.acquire(context.principal());
            // One transaction: the agent check, the read and the ALLOWED audit row. If the
            // audit row cannot be written the transaction rolls back and no data leaves.
            T result = bulkhead.run(() -> tenantExecutor.execute(context.principal(), () -> {
                agentPolicy.requireActive(context.principal());
                T value = read.get();
                auditor.appendAllowed(context, patientId, category);
                return value;
            }));
            auditor.logAllowed(context, patientId, category);
            return result;
        } catch (PatientAccessDeniedException | ClinicalAccessDeniedException | RateLimitExceededException ex) {
            auditor.denied(context, patientId, category);
            throw ex;
        } catch (ServerBusyException ex) {
            // Nothing ran and no decision was made, so there is nothing to audit. Writing
            // an audit row would also need a connection, which is what is in short supply.
            throw ex;
        } catch (AuditUnavailableException ex) {
            auditor.failed(context, patientId, category);
            throw ex;
        } catch (RuntimeException ex) {
            auditor.failed(context, patientId, category);
            // Detail stays in the server log. What reaches the caller, and so the
            // AI model, is a fixed message: database errors can echo data.
            LOG.error("request_failed category={}", category, ex);
            throw new RequestFailedException();
        }
    }

    private static void requireWellFormed(String patientId) {
        if (NO_PATIENT.equals(patientId)) {
            return;
        }
        if (patientId == null || !PATIENT_ID.matcher(patientId).matches()) {
            throw new PatientAccessDeniedException();
        }
    }
}
