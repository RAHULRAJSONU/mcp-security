INSERT INTO patients (
    id, tenant_id, medical_record_number,
    first_name, last_name, date_of_birth
)
VALUES
    (
        'patient-400', 'hospital-A', 'MRN-A-400',
        'Alice', 'Test', '1985-04-12'
    ),
    (
        'patient-500', 'hospital-A', 'MRN-A-500',
        'Bob', 'Test', '1990-07-21'
    ),
    (
        'patient-600', 'hospital-B', 'MRN-B-600',
        'Carol', 'Test', '1978-11-03'
    );

INSERT INTO patient_assignments (
    id, tenant_id, clinician_id, patient_id,
    status, valid_from, valid_until
)
VALUES (
           'assignment-001',
           'hospital-A',
           'doctor-101',
           'patient-400',
           'ACTIVE',
           CURRENT_TIMESTAMP - INTERVAL '1 day',
           CURRENT_TIMESTAMP + INTERVAL '30 days'
       );