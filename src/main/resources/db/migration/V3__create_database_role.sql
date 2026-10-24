-- The application role is provisioned out-of-band (its credential is injected
-- by the platform). This only guarantees the role exists and is least-privilege.
DO
$$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'healthcare_app') THEN
        CREATE ROLE healthcare_app LOGIN;
    END IF;

    EXECUTE format('GRANT CONNECT ON DATABASE %I TO healthcare_app', current_database());
END
$$;

GRANT USAGE ON SCHEMA public
    TO healthcare_app;

GRANT SELECT ON patients, patient_assignments
    TO healthcare_app;
