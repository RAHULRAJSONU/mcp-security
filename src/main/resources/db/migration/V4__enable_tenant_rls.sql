ALTER TABLE patients
    ENABLE ROW LEVEL SECURITY;

ALTER TABLE patients
    FORCE ROW LEVEL SECURITY;

CREATE POLICY patient_tenant_isolation
ON patients
FOR ALL
TO healthcare_app
USING (
    tenant_id = current_setting(
        'app.tenant_id', true
    )
)
WITH CHECK (
    tenant_id = current_setting(
        'app.tenant_id', true
    )
);

ALTER TABLE patient_assignments
    ENABLE ROW LEVEL SECURITY;

ALTER TABLE patient_assignments
    FORCE ROW LEVEL SECURITY;

CREATE POLICY assignment_tenant_isolation
ON patient_assignments
FOR ALL
TO healthcare_app
USING (
    tenant_id = current_setting(
        'app.tenant_id', true
    )
)
WITH CHECK (
    tenant_id = current_setting(
        'app.tenant_id', true
    )
);