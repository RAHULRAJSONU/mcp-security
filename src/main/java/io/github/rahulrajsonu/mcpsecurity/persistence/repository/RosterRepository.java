package io.github.rahulrajsonu.mcpsecurity.persistence.repository;

import io.github.rahulrajsonu.mcpsecurity.mcp.domain.RosterEntry;

import java.time.Instant;
import java.util.List;

public interface RosterRepository {

    /** Patients the clinician has an ACTIVE, in-window assignment to. */
    List<RosterEntry> findActive(String tenantId, String clinicianId, Instant now);
}
