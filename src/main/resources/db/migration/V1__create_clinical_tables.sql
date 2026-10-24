CREATE TABLE patients (
      id VARCHAR(64) PRIMARY KEY,
      tenant_id VARCHAR(64) NOT NULL,
      medical_record_number VARCHAR(64) NOT NULL,
      first_name VARCHAR(100) NOT NULL,
      last_name VARCHAR(100) NOT NULL,
      date_of_birth DATE NOT NULL,

      CONSTRAINT uk_patient_tenant_id
          UNIQUE (tenant_id, id),

      CONSTRAINT uk_patient_tenant_mrn
          UNIQUE (tenant_id, medical_record_number)
);

CREATE TABLE patient_assignments (
     id VARCHAR(64) PRIMARY KEY,
     tenant_id VARCHAR(64) NOT NULL,
     clinician_id VARCHAR(64) NOT NULL,
     patient_id VARCHAR(64) NOT NULL,
     status VARCHAR(20) NOT NULL,
     valid_from TIMESTAMPTZ NOT NULL,
     valid_until TIMESTAMPTZ,

     CONSTRAINT fk_assignment_patient
         FOREIGN KEY (tenant_id, patient_id)
             REFERENCES patients (tenant_id, id),

     CONSTRAINT chk_assignment_status
         CHECK (status IN (
                           'ACTIVE', 'SUSPENDED', 'REVOKED', 'EXPIRED'
             )),

     CONSTRAINT chk_assignment_window
         CHECK (
             valid_until IS NULL
                 OR valid_until > valid_from
             )
);

CREATE INDEX idx_assignment_lookup
    ON patient_assignments (
            tenant_id,
            clinician_id,
            patient_id,
            status
        );