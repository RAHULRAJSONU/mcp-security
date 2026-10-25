package io.github.rahulrajsonu.mcpsecurity.persistence.repository;

import io.github.rahulrajsonu.mcpsecurity.mcp.domain.Agent;

import java.util.Optional;

public interface AgentRepository {
    /** The registration letting {@code clientId} act for {@code ownerSubject} in this tenant. */
    Optional<Agent> find(String tenantId, String clientId, String ownerSubject);
}
