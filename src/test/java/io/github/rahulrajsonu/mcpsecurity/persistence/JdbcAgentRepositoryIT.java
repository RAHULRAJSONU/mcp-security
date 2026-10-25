package io.github.rahulrajsonu.mcpsecurity.persistence;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.rahulrajsonu.mcpsecurity.AbstractPostgresIT;
import io.github.rahulrajsonu.mcpsecurity.mcp.domain.Agent;
import io.github.rahulrajsonu.mcpsecurity.mcp.domain.AgentState;
import io.github.rahulrajsonu.mcpsecurity.persistence.repository.AgentRepository;
import io.github.rahulrajsonu.mcpsecurity.security.ClinicalPrincipal;
import io.github.rahulrajsonu.mcpsecurity.security.TenantScopedExecutor;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.simple.JdbcClient;

/** The agents table as the restricted application role sees it, against the V9 seed. */
class JdbcAgentRepositoryIT extends AbstractPostgresIT {

    @Autowired
    AgentRepository agents;

    @Autowired
    TenantScopedExecutor tenantExecutor;

    @Autowired
    JdbcClient jdbc;

    private static ClinicalPrincipal in(String tenant) {
        return new ClinicalPrincipal("doctor-101", tenant, Set.of("patient.read"));
    }

    private Optional<Agent> find(String tenant, String client, String owner) {
        return tenantExecutor.execute(in(tenant), () -> agents.find(tenant, client, owner));
    }

    @Test
    void findsAnApprovedRegistration() {
        Agent agent = find("hospital-A", "healthcare-mcp-client", "doctor-101").orElseThrow();

        assertThat(agent.clientId()).isEqualTo("healthcare-mcp-client");
        assertThat(agent.state()).isEqualTo(AgentState.APPROVED);
        assertThat(agent.expiresAt()).isAfter(Instant.now());
    }

    @Test
    void readsSuspendedAndExpiredRowsWithoutJudgingThem() {
        // The repository reports facts; AgentAccessPolicy decides.
        assertThat(find("hospital-A", "suspended-client", "doctor-101").orElseThrow().state())
                .isEqualTo(AgentState.SUSPENDED);
        assertThat(find("hospital-A", "expired-client", "doctor-101").orElseThrow().expiresAt())
                .isBefore(Instant.now());
    }

    @Test
    void aRegistrationIsPerUser() {
        assertThat(find("hospital-A", "healthcare-mcp-client", "doctor-202")).isPresent();
        assertThat(find("hospital-A", "healthcare-mcp-client", "doctor-303")).isEmpty();
        assertThat(find("hospital-A", "suspended-client", "doctor-202")).isEmpty();
    }

    @Test
    void unknownClientsAreEmpty() {
        assertThat(find("hospital-A", "never-registered", "doctor-101")).isEmpty();
    }

    @Test
    void rowLevelSecurityHidesAnotherTenantsRegistrations() {
        // Asking for hospital-A's row while scoped to hospital-B finds nothing.
        Optional<Agent> crossTenant = tenantExecutor.execute(in("hospital-B"),
                () -> agents.find("hospital-A", "healthcare-mcp-client", "doctor-101"));

        assertThat(crossTenant).isEmpty();
    }

    @Test
    void withoutATenantScopeNothingIsVisible() {
        // No set_config, so current_setting is NULL and the policy matches no row.
        assertThat(agents.find("hospital-A", "healthcare-mcp-client", "doctor-101")).isEmpty();
    }

    @Test
    void theApplicationRoleCannotRegisterOrChangeAnAgent() {
        // Approval is an operator action. A compromised app must not be able to approve itself.
        org.junit.jupiter.api.Assertions.assertThrows(DataAccessException.class, () ->
                tenantExecutor.execute(in("hospital-A"), () -> jdbc.sql("""
                        INSERT INTO agents (tenant_id, client_id, owner_subject, state, expires_at)
                        VALUES ('hospital-A', 'self-approved', 'doctor-101', 'APPROVED', now() + interval '1 day')
                        """).update()));

        org.junit.jupiter.api.Assertions.assertThrows(DataAccessException.class, () ->
                tenantExecutor.execute(in("hospital-A"), () -> jdbc.sql("""
                        UPDATE agents SET state = 'APPROVED' WHERE client_id = 'suspended-client'
                        """).update()));
    }
}
