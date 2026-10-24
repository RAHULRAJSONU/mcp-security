-- Synthetic data only. Loaded by the local profile and the tests, never in a real environment.

-- doctor-101: one active assignment (patient-400, from V2) and one REVOKED (patient-500).
-- doctor-202: active on both hospital-A patients, so a roster has more than one entry.
-- doctor-303: hospital-B only.
INSERT INTO patient_assignments (
    id, tenant_id, clinician_id, patient_id,
    status, valid_from, valid_until
)
VALUES
    ('assignment-002', 'hospital-A', 'doctor-101', 'patient-500',
     'REVOKED', CURRENT_TIMESTAMP - INTERVAL '10 days', NULL),
    ('assignment-003', 'hospital-A', 'doctor-202', 'patient-400',
     'ACTIVE', CURRENT_TIMESTAMP - INTERVAL '1 day', CURRENT_TIMESTAMP + INTERVAL '30 days'),
    ('assignment-004', 'hospital-A', 'doctor-202', 'patient-500',
     'ACTIVE', CURRENT_TIMESTAMP - INTERVAL '1 day', CURRENT_TIMESTAMP + INTERVAL '30 days'),
    ('assignment-005', 'hospital-B', 'doctor-303', 'patient-600',
     'ACTIVE', CURRENT_TIMESTAMP - INTERVAL '1 day', CURRENT_TIMESTAMP + INTERVAL '30 days');

INSERT INTO medications (id, tenant_id, patient_id, name, dose, frequency, active)
VALUES
    ('med-001', 'hospital-A', 'patient-400', 'Lisinopril', '10 mg', 'once daily', TRUE),
    ('med-002', 'hospital-A', 'patient-400', 'Atorvastatin', '20 mg', 'nightly', TRUE),
    ('med-003', 'hospital-A', 'patient-500', 'Metformin', '500 mg', 'twice daily', TRUE),
    ('med-004', 'hospital-B', 'patient-600', 'Levothyroxine', '75 mcg', 'once daily', TRUE);

INSERT INTO clinical_notes (id, tenant_id, patient_id, author_id, note_type, body, created_at)
VALUES
    ('note-001', 'hospital-A', 'patient-400', 'doctor-101', 'PROGRESS',
     'Synthetic note: blood pressure controlled on current regimen. Review in three months.',
     CURRENT_TIMESTAMP - INTERVAL '3 days'),
    ('note-002', 'hospital-A', 'patient-500', 'doctor-202', 'PROGRESS',
     'Synthetic note: glucose within target range. Continue current plan.',
     CURRENT_TIMESTAMP - INTERVAL '2 days'),
    ('note-003', 'hospital-B', 'patient-600', 'doctor-303', 'PROGRESS',
     'Synthetic note: thyroid levels stable.',
     CURRENT_TIMESTAMP - INTERVAL '1 day');
