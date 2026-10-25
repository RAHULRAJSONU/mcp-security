-- Synthetic. Local profile and tests only.
-- One row per (client, user): the client may act only for the listed owner.
INSERT INTO agents (tenant_id, client_id, owner_subject, state, expires_at)
VALUES
    ('hospital-A', 'healthcare-mcp-client', 'doctor-101',   'APPROVED',  CURRENT_TIMESTAMP + INTERVAL '90 days'),
    ('hospital-A', 'healthcare-mcp-client', 'doctor-202',   'APPROVED',  CURRENT_TIMESTAMP + INTERVAL '90 days'),
    ('hospital-A', 'healthcare-mcp-client', 'compliance-1', 'APPROVED',  CURRENT_TIMESTAMP + INTERVAL '90 days'),
    ('hospital-A', 'suspended-client',      'doctor-101',   'SUSPENDED', CURRENT_TIMESTAMP + INTERVAL '90 days'),
    ('hospital-A', 'expired-client',        'doctor-101',   'APPROVED',  CURRENT_TIMESTAMP - INTERVAL '1 day'),
    ('hospital-B', 'healthcare-mcp-client', 'doctor-101',   'APPROVED',  CURRENT_TIMESTAMP + INTERVAL '90 days'),
    ('hospital-B', 'healthcare-mcp-client', 'doctor-303',   'APPROVED',  CURRENT_TIMESTAMP + INTERVAL '90 days'),
    ('hospital-B', 'healthcare-mcp-client', 'compliance-B', 'APPROVED',  CURRENT_TIMESTAMP + INTERVAL '90 days');
