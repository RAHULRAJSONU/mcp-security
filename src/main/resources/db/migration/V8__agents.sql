CREATE TABLE agents(
    tenant_id VARCHAR(64) NOT NULL,
    client_id VARCHAR(128) NOT NULL,
    owner_subject VARCHAR(64) NOT NULL,
    state VARCHAR(20) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,

    -- One row per user a client may act for, so an approval is never shared between users.
    PRIMARY KEY (tenant_id, client_id, owner_subject),
    CONSTRAINT chk_agent_state CHECK (state IN ('PENDING', 'APPROVED', 'SUSPENDED', 'RETIRED'))
);

ALTER TABLE agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE agents FORCE ROW LEVEL SECURITY;

CREATE POLICY agent_tenant_read
       ON agents
       FOR SELECT
       TO healthcare_app
           USING (tenant_id = current_setting('app.tenant_id', true));

GRANT SELECT ON agents TO healthcare_app;