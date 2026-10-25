package io.github.rahulrajsonu.mcpsecurity.persistence.adapter;

import io.github.rahulrajsonu.mcpsecurity.mcp.domain.Agent;
import io.github.rahulrajsonu.mcpsecurity.mcp.domain.AgentState;
import io.github.rahulrajsonu.mcpsecurity.persistence.repository.AgentRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.time.OffsetDateTime;
import java.util.Optional;

@Repository
@RequiredArgsConstructor
public class JdbcAgentRepositoryAdapter
        implements AgentRepository {

    private final JdbcClient jdbc;

    @Override
    public Optional<Agent> find(String tenantId, String clientId, String ownerSubject) {

        return jdbc.sql("""
                        SELECT client_id, state, expires_at
                        FROM agents
                        WHERE tenant_id = :tenantId
                          AND client_id = :clientId
                          AND owner_subject = :ownerSubject
                        """)
                .param("tenantId", tenantId)
                .param("clientId", clientId)
                .param("ownerSubject", ownerSubject)
                .query((rs, row) -> new Agent(
                        rs.getString("client_id"),
                        AgentState.valueOf(rs.getString("state")),
                        rs.getObject("expires_at", OffsetDateTime.class).toInstant()))
                .optional();
    }
}
