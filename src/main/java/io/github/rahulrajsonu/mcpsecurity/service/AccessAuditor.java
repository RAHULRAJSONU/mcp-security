package io.github.rahulrajsonu.mcpsecurity.service;

import io.github.rahulrajsonu.mcpsecurity.exception.AuditUnavailableException;
import io.github.rahulrajsonu.mcpsecurity.mcp.domain.AccessEvent;
import io.github.rahulrajsonu.mcpsecurity.persistence.repository.AccessEventRepository;
import io.github.rahulrajsonu.mcpsecurity.security.AccessAuditLogger;
import io.github.rahulrajsonu.mcpsecurity.security.AccessAuditLogger.Outcome;
import io.github.rahulrajsonu.mcpsecurity.security.AccessPurpose;
import io.github.rahulrajsonu.mcpsecurity.security.ClinicalAccessContext;
import io.github.rahulrajsonu.mcpsecurity.security.DataCategory;
import io.github.rahulrajsonu.mcpsecurity.security.TenantScopedExecutor;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Instant;

/**
 * Writes the durable audit record and the log line for each access decision.
 *
 * "No audit, no data": when an access was allowed, the event must be stored
 * before the result is returned, and failure to store it fails the request.
 * For denials and errors the record is best-effort, because the caller gets
 * nothing either way.
 */
@Component
@RequiredArgsConstructor
public class AccessAuditor {

    private static final Logger LOG = LoggerFactory.getLogger(AccessAuditor.class);
    private static final int MAX_JUSTIFICATION = 500;
    private static final int MAX_ID = 128;

    private final AccessAuditLogger logger;
    private final AccessEventRepository events;
    private final TenantScopedExecutor tenantExecutor;
    private final Clock clock;

    public void allowed(ClinicalAccessContext context, String patientId, DataCategory category) {
        try {
            store(context, patientId, category, Outcome.ALLOWED);
        } catch (RuntimeException ex) {
            LOG.error("audit_write_failed outcome=ALLOWED; access refused", ex);
            throw new AuditUnavailableException(ex);
        }
        logger.record(context, patientId, category, Outcome.ALLOWED);
    }

    public void denied(ClinicalAccessContext context, String patientId, DataCategory category) {
        bestEffort(context, patientId, category, Outcome.DENIED);
    }

    public void failed(ClinicalAccessContext context, String patientId, DataCategory category) {
        bestEffort(context, patientId, category, Outcome.ERROR);
    }

    private void bestEffort(
            ClinicalAccessContext context,
            String patientId,
            DataCategory category,
            Outcome outcome) {

        try {
            store(context, patientId, category, outcome);
        } catch (RuntimeException ex) {
            LOG.error("audit_write_failed outcome={}", outcome, ex);
        }
        logger.record(context, patientId, category, outcome);
    }

    private void store(
            ClinicalAccessContext context,
            String patientId,
            DataCategory category,
            Outcome outcome) {

        boolean breakGlass = context.purpose() == AccessPurpose.EMERGENCY;

        AccessEvent event = new AccessEvent(
                Instant.now(clock),
                truncate(context.principal().subject(), MAX_ID),
                truncate(patientId, MAX_ID),
                context.purpose().name(),
                category.name(),
                outcome.name(),
                breakGlass,
                breakGlass ? justification(context) : null);

        // Own transaction scoped to the caller's tenant, so a denied or failed
        // request is still recorded and the row satisfies the tenant policy.
        tenantExecutor.execute(context.principal(), () -> {
            events.append(context.principal().tenantId(), event);
            return null;
        });
    }

    private static String justification(ClinicalAccessContext context) {
        String text = context.justification();
        return text == null ? null : truncate(text.strip(), MAX_JUSTIFICATION);
    }

    private static String truncate(String value, int max) {
        if (value == null) {
            return "-";
        }
        return value.length() > max ? value.substring(0, max) : value;
    }
}
