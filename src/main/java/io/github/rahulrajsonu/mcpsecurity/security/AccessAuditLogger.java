package io.github.rahulrajsonu.mcpsecurity.security;

import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Log line and metric for every access decision. Emitted on a dedicated
 * logger so it can be routed to tamper-evident storage independently of
 * application logs. Contains identifiers only, never clinical data and never
 * the caller's free-text justification (it can contain PHI); the justification
 * is kept only in the access-controlled {@code access_events} table.
 *
 * Also counts outcomes so denial spikes and break-glass use are alertable.
 */
@Component
public class AccessAuditLogger {

    public enum Outcome { ALLOWED, DENIED, ERROR }

    static final String METRIC = "clinical.patient.access";

    private static final Logger AUDIT = LoggerFactory.getLogger("AUDIT.patient-access");

    private final MeterRegistry meters;

    public AccessAuditLogger(MeterRegistry meters) {
        this.meters = meters;
    }

    public void record(ClinicalAccessContext context, String patientId, Outcome outcome) {
        record(context, patientId, DataCategory.PATIENT_SUMMARY, outcome);
    }

    public void record(
            ClinicalAccessContext context,
            String patientId,
            DataCategory category,
            Outcome outcome) {

        ClinicalPrincipal principal = context.principal();
        boolean breakGlass = context.purpose() == AccessPurpose.EMERGENCY;

        meters.counter(METRIC,
                "outcome", outcome.name(),
                "purpose", context.purpose().name(),
                "category", category.name()).increment();

        String line = "patient_access outcome={} subject={} tenant={} patient={} client={} purpose={} category={} break_glass={} justification_chars={}";
        Object[] fields = {
                outcome,
                sanitize(principal.subject()),
                sanitize(principal.tenantId()),
                sanitize(patientId),
                sanitize(principal.clientId()),
                context.purpose(),
                category,
                breakGlass,
                breakGlass && context.justification() != null
                        ? context.justification().strip().length()
                        : 0
        };

        // Emergency access is always surfaced above routine reads.
        if (breakGlass) {
            AUDIT.warn(line, fields);
        } else {
            AUDIT.info(line, fields);
        }
    }

    // Values can be caller-controlled; strip anything that could forge log lines.
    static String sanitize(String value) {
        if (value == null) {
            return "-";
        }
        String cleaned = value.replaceAll("[^\\p{Print}]", "?");
        return cleaned.length() > 128 ? cleaned.substring(0, 128) : cleaned;
    }
}
