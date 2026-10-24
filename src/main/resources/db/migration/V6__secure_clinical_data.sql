ALTER TABLE medications ENABLE ROW LEVEL SECURITY;
ALTER TABLE medications FORCE ROW LEVEL SECURITY;

CREATE POLICY medication_tenant_isolation
ON medications
FOR SELECT
TO healthcare_app
USING (tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE clinical_notes ENABLE ROW LEVEL SECURITY;
ALTER TABLE clinical_notes FORCE ROW LEVEL SECURITY;

CREATE POLICY note_tenant_isolation
ON clinical_notes
FOR SELECT
TO healthcare_app
USING (tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE access_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE access_events FORCE ROW LEVEL SECURITY;

CREATE POLICY access_event_read
ON access_events
FOR SELECT
TO healthcare_app
USING (tenant_id = current_setting('app.tenant_id', true));

-- Append-only for the application: it may add events for its own tenant and
-- read them back, but has no UPDATE or DELETE privilege or policy.
CREATE POLICY access_event_append
ON access_events
FOR INSERT
TO healthcare_app
WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

GRANT SELECT ON medications, clinical_notes TO healthcare_app;
GRANT SELECT, INSERT ON access_events TO healthcare_app;
