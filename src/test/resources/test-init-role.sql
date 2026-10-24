-- Mirrors the platform provisioning step: the app role exists before Flyway runs.
CREATE ROLE healthcare_app LOGIN PASSWORD 'test-only';
