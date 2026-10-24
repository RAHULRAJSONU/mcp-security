CREATE TABLE medications (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    patient_id VARCHAR(64) NOT NULL,
    name VARCHAR(200) NOT NULL,
    dose VARCHAR(100) NOT NULL,
    frequency VARCHAR(100) NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,

    CONSTRAINT fk_medication_patient
        FOREIGN KEY (tenant_id, patient_id)
            REFERENCES patients (tenant_id, id)
);

CREATE INDEX idx_medication_patient
    ON medications (tenant_id, patient_id);

CREATE TABLE clinical_notes (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    patient_id VARCHAR(64) NOT NULL,
    author_id VARCHAR(64) NOT NULL,
    note_type VARCHAR(40) NOT NULL,
    body TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,

    CONSTRAINT fk_note_patient
        FOREIGN KEY (tenant_id, patient_id)
            REFERENCES patients (tenant_id, id)
);

CREATE INDEX idx_note_patient
    ON clinical_notes (tenant_id, patient_id, created_at DESC);

-- Durable record of every access decision. No foreign key to patients on purpose:
-- attempts on unknown or other-tenant patient ids must be recorded too.
CREATE TABLE access_events (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    subject VARCHAR(128) NOT NULL,
    patient_id VARCHAR(128) NOT NULL,
    purpose VARCHAR(40) NOT NULL,
    category VARCHAR(40) NOT NULL,
    outcome VARCHAR(10) NOT NULL,
    break_glass BOOLEAN NOT NULL,
    justification VARCHAR(500),

    CONSTRAINT chk_access_event_outcome
        CHECK (outcome IN ('ALLOWED', 'DENIED', 'ERROR'))
);

CREATE INDEX idx_access_event_patient
    ON access_events (tenant_id, patient_id, occurred_at DESC);

CREATE INDEX idx_access_event_break_glass
    ON access_events (tenant_id, occurred_at DESC)
    WHERE break_glass;
