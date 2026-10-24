package io.github.rahulrajsonu.mcpsecurity.persistence.repository;

import io.github.rahulrajsonu.mcpsecurity.mcp.domain.AccessEvent;

import java.util.List;

/** Append and read only. There is deliberately no update or delete. */
public interface AccessEventRepository {

    void append(String tenantId, AccessEvent event);

    List<AccessEvent> findByPatient(String tenantId, String patientId, int limit);

    List<AccessEvent> findBreakGlass(String tenantId, int limit);
}
