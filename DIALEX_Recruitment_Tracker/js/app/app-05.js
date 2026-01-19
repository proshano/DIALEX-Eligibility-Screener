
function updatePatientName(index, value) {
    const patient = patientsData[index];
    if (!patient) return;
    if (!ensureEditablePatient(patient)) return;
    const trimmed = (value || '').trim();
    patient.patient_name = trimmed;
    persistPatient(patient, false);
    refreshPatientRow(patient);
    showRecordWarning('');
}

function updatePatientBirthDate(index, value) {
    const patient = patientsData[index];
    if (!patient) return;
    if (!ensureEditablePatient(patient)) return;
    const raw = (value || '').trim();
    if (!raw) {
        if (!patient.birth_date) {
            showRecordWarning('');
            return;
        }
        patient.birth_date = '';
        patient.age = null;
        patient.incl_age = 0;
        persistPatient(patient, false);
        refreshPatientRow(patient);
        showRecordWarning('');
        return;
    }
    const normalized = normalizeISODateString(raw);
    if (!normalized) {
        showRecordWarning('Enter birth date as DD/MM/YYYY.', 'error');
        renderPatientTable();
        return;
    }
    if (normalized === patient.birth_date) {
        showRecordWarning('');
        return;
    }
    const birth = parseISODate(normalized);
    if (!birth) {
        showRecordWarning('Enter a valid birth date.', 'error');
        renderPatientTable();
        return;
    }
    if (isDateInFuture(birth)) {
        showRecordWarning('Birth date cannot be in the future.', 'error');
        renderPatientTable();
        return;
    }
    if (patient.dialysis_start_date) {
        const start = parseISODate(patient.dialysis_start_date);
        if (start && start.getTime() <= birth.getTime()) {
            showRecordWarning('Dialysis start date must be after birth date.', 'error');
            renderPatientTable();
            return;
        }
    }
    const age = calculateAgeFromDate(birth);
    if (!Number.isFinite(age) || age < 0 || age > 130) {
        showRecordWarning('Birth date yields an age outside 0-130 years.', 'error');
        renderPatientTable();
        return;
    }
    patient.birth_date = normalized;
    patient.age = age;
    const meetsAgeCriteria = age >= 60 || (age >= 45 && age < 60 && patient.diabetes_known === 1);
    patient.incl_age = meetsAgeCriteria ? 1 : 0;
    persistPatient(patient, false);
    refreshPatientRow(patient);
    if (isDateOlderThanYears(birth, DOB_WARNING_YEARS)) {
        showRecordWarning(`Check birth date: more than ${DOB_WARNING_YEARS} years ago.`, 'status');
    } else {
        showRecordWarning('');
    }
}

function updatePatientAge(index, value) {
    const patient = patientsData[index];
    if (!patient) return;
    if (!ensureEditablePatient(patient)) return;
    const raw = (value || '').trim();
    const hasStoredAge = Number.isFinite(patient.age);
    if (!raw) {
        if (!hasStoredAge && !patient.birth_date) {
            showRecordWarning('');
            return;
        }
        patient.age = null;
        patient.birth_date = '';
        patient.incl_age = 0;
        persistPatient(patient, false);
        refreshPatientRow(patient);
        showRecordWarning('');
        return;
    }
    const cleaned = raw.replace(/\s+/g, '');
    if (!/^\d{1,3}$/.test(cleaned)) {
        showRecordWarning('Enter age as a whole number between 0 and 130.', 'error');
        renderPatientTable();
        return;
    }
    const age = Number(cleaned);
    if (!Number.isFinite(age) || age < 0 || age > 130) {
        showRecordWarning('Enter age as a whole number between 0 and 130.', 'error');
        renderPatientTable();
        return;
    }
    const derivedBirth = buildBirthDateFromAge(age);
    if (!derivedBirth) {
        showRecordWarning('Unable to set age. Please try again.', 'error');
        renderPatientTable();
        return;
    }
    const derivedIso = formatISODate(derivedBirth);
    const currentAge = Number.isFinite(patient.age) ? patient.age : null;
    if (currentAge === age && derivedIso === (patient.birth_date || '')) {
        showRecordWarning('');
        return;
    }
    if (patient.dialysis_start_date) {
        const start = parseISODate(patient.dialysis_start_date);
        if (start && start.getTime() <= derivedBirth.getTime()) {
            showRecordWarning("Dialysis start date must be after the patient's birth year.", 'error');
            renderPatientTable();
            return;
        }
    }
    patient.age = age;
    patient.birth_date = derivedIso;
    const meetsAgeCriteria = age >= 60 || (age >= 45 && age < 60 && patient.diabetes_known === 1);
    patient.incl_age = meetsAgeCriteria ? 1 : 0;
    persistPatient(patient, false);
    refreshPatientRow(patient);
    if (age > DOB_WARNING_YEARS) {
        showRecordWarning(`Check age: ${age} years.`, 'status');
    } else {
        showRecordWarning('');
    }
}

function updatePatientMrn(index, value) {
    const patient = patientsData[index];
    if (!patient) return;
    if (!ensureEditablePatient(patient)) return;
    const trimmed = (value || '').trim();
    const previous = patient.mrn || '';
    if (!trimmed) {
        if (isTemporaryMrn(previous)) {
            showRecordWarning('');
            return;
        }
        const tempMrn = generateTemporaryMrn();
        if (db) {
            const updateStmt = db.prepare('UPDATE patient_assessments SET mrn = ? WHERE mrn = ?');
            updateStmt.run([tempMrn, previous]);
            updateStmt.free();
        }
        patient.mrn = tempMrn;
        persistPatient(patient, false);
        refreshPatientRow(patient);
        showRecordWarning('');
        return;
    }
    if (trimmed === previous) {
        showRecordWarning('');
        return;
    }
    if (db) {
        const check = db.prepare('SELECT COUNT(*) AS count FROM patient_assessments WHERE mrn = ?');
        check.bind([trimmed]);
        let conflict = false;
        if (check.step()) {
            const row = check.getAsObject();
            conflict = Number(row.count) > 0;
        }
        check.free();
        if (conflict) {
            showRecordWarning('Another patient already uses this MRN.', 'error');
            renderPatientTable();
            return;
        }
        const updateStmt = db.prepare('UPDATE patient_assessments SET mrn = ? WHERE mrn = ?');
        updateStmt.run([trimmed, previous]);
        updateStmt.free();
    }
    patient.mrn = trimmed;
    persistPatient(patient, false);
    refreshPatientRow(patient);
    showRecordWarning('');
}

function updatePatientHcn(index, value) {
    const patient = patientsData[index];
    if (!patient) return;
    if (!ensureEditablePatient(patient)) return;
    const trimmed = (value || '').trim();
    const normalized = normalizeHealthCardValue(trimmed);
    const provinceCode = patient.health_card_province || '';
    if (db && normalized) {
        const check = db.prepare('SELECT mrn, health_card FROM patient_assessments WHERE mrn != ?');
        check.bind([patient.mrn || '']);
        let conflictMrn = '';
        try {
            while (check.step()) {
                const row = check.getAsObject();
                const existing = normalizeHealthCardValue(row.health_card || '');
                if (existing && existing === normalized) {
                    conflictMrn = row.mrn || '';
                    break;
                }
            }
        } finally {
            check.free();
        }
        if (conflictMrn) {
            showRecordWarning('Another patient already uses this health card number.', 'error');
            renderPatientTable();
            return;
        }
    }
    patient.health_card = normalized || '';
    const inferredProvince = provinceCode || inferProvinceFromHealthCard(normalized || '');
    if (inferredProvince) {
        patient.health_card_province = inferredProvince;
    }
    patient.hasHealthCard = patient.health_card.length > 0;
    const formatError = validateHealthCardFormat(patient.health_card, patient.health_card_province || '');
    patient.incl_health_card = patient.hasHealthCard && !formatError ? 1 : 0;
    persistPatient(patient, false);
    refreshPatientRow(patient);
    if (formatError) {
        showRecordWarning(formatError, 'error');
    } else {
        showRecordWarning('');
    }
}

function updateHealthCardProvince(index, value) {
    const patient = patientsData[index];
    if (!patient) return;
    if (!ensureEditablePatient(patient)) return;
    const code = (value || '').trim().toUpperCase();
    if (code && !PROVINCE_LABELS[code]) {
        showRecordWarning('Select a valid province/territory code.', 'error');
        renderPatientTable();
        return;
    }
    patient.health_card_province = code;
    if (patient.health_card) {
        const formatError = validateHealthCardFormat(patient.health_card, code);
        if (formatError) {
            patient.incl_health_card = 0;
            showRecordWarning(formatError, 'error');
            persistPatient(patient, false);
            refreshPatientRow(patient);
            return;
        }
    }
    patient.incl_health_card = patient.health_card && !validateHealthCardFormat(patient.health_card, code) ? 1 : 0;
    persistPatient(patient, false);
    refreshPatientRow(patient);
    showRecordWarning('');
}

function updateInlineNotes(index, value) {
    const patient = patientsData[index];
    if (!patient) return;
    patient.notes = value;
    persistPatient(patient, false);
    refreshPatientRow(patient);
}

function updateRandomizedStatus(index, value) {
    const patient = patientsData[index];
    if (!patient) return;
    if (!ensureEditablePatient(patient)) return;
    const shouldMark = String(value) === '1';
    if (!shouldMark) {
        releaseStudyId(patient.study_id);
        patient.randomized = 0;
        patient.enrollment_status = (patient.noExclusions && patient.inclusionMet && patient.no_exclusions_confirmed && patient.hasHealthCard) ? 'eligible' : 'pending';
        patient.therapy_prescribed = 0;
        patient.allocation = '';
        patient.study_id = '';
        showRecordWarning('');
        persistPatient(patient, false);
        refreshPatientRow(patient);
        return;
    }
    if (!patient.notification_date) {
        showRecordWarning('Set notification date before marking randomized.', 'error');
        renderPatientTable();
        return;
    }
    if (patient.opt_out_status !== OPT_OUT_STATUS.DID_NOT) {
        showRecordWarning('Select "Did not opt out" before marking randomized.', 'error');
        renderPatientTable();
        return;
    }
    if (!patient.inclusionMet) {
        showRecordWarning('Complete inclusion checklist before marking randomized.', 'error');
        renderPatientTable();
        return;
    }
    if (!patient.noExclusions) {
        showRecordWarning('Resolve exclusions before marking randomized.', 'error');
        renderPatientTable();
        return;
    }
    if (!patient.no_exclusions_confirmed) {
        showRecordWarning('Confirm "No exclusions" before marking randomized.', 'error');
        renderPatientTable();
        return;
    }
    if (!patient.study_id) {
        showRecordWarning('Assign a Study ID before marking randomized.', 'error');
        renderPatientTable();
        return;
    }
    const firstEligible = computeFirstEligibleDate(patient);
    if (!firstEligible) {
        showRecordWarning('Set notification and eligibility inputs before marking randomized.', 'error');
        renderPatientTable();
        return;
    }
    if (firstEligible.getTime() > getTorontoNowTimestamp()) {
        showRecordWarning(`Eligible on ${formatISODate(firstEligible)}.`, 'error');
        renderPatientTable();
        return;
    }
    patient.randomized = 1;
    patient.enrollment_status = 'enrolled';
    if (!normalizeLocationValue(patient.location_at_randomization)) {
        patient.location_at_randomization = getCanonicalLocationValue(patient.location);
    }
    showRecordWarning('');
    persistPatient(patient, false);
    refreshPatientRow(patient);
}

function updateDialysisStartDate(index, value) {
    const patient = patientsData[index];
    if (!patient) return;
    if (!ensureEditablePatient(patient)) return;
    const raw = (value || '').trim();
    if (!raw) {
        if (!patient.dialysis_start_date) {
            showRecordWarning('');
            return;
        }
        patient.dialysis_start_date = '';
        patient.dialysis_duration_confirmed = 0;
    } else {
        const normalized = normalizeISODateString(raw);
        if (!normalized) {
            showRecordWarning('Enter dialysis start date as DD/MM/YYYY.', 'error');
            renderPatientTable();
            return;
        }
        if (normalized === patient.dialysis_start_date) {
            showRecordWarning('');
            return;
        }
        if (patient.birth_date) {
            const birth = parseISODate(patient.birth_date);
            const start = parseISODate(normalized);
            if (birth && start && start.getTime() <= birth.getTime()) {
                showRecordWarning("Dialysis start date must be after the patient's birth year.", 'error');
                renderPatientTable();
                return;
            }
        }
        patient.dialysis_start_date = normalized;
        patient.dialysis_duration_confirmed = 0;
    }
    recalcDialysisInclusion(patient);
    persistPatient(patient, false);
    refreshPatientRow(patient);
    if (patient.dialysis_start_date) {
        const start = parseISODate(patient.dialysis_start_date);
        if (start && isDateOlderThanYears(start, DIALYSIS_WARNING_YEARS)) {
            showRecordWarning(`Check dialysis start date: more than ${DIALYSIS_WARNING_YEARS} years ago.`, 'status');
            return;
        }
    }
    showRecordWarning('');
}

function setDialysisDurationConfirmed(index, flag) {
    const patient = patientsData[index];
    if (!patient) return;
    if (!ensureEditablePatient(patient)) return;
    if (patient.dialysis_start_date) return;
    patient.dialysis_duration_confirmed = flag ? 1 : 0;
    recalcDialysisInclusion(patient);
    persistPatient(patient, false);
    refreshPatientRow(patient);
}

function toggleTherapyPrescribed(index, checkbox) {
    const patient = patientsData[index];
    if (!patient || !checkbox) return;
    if (!ensureEditablePatient(patient)) {
        checkbox.checked = !!patient.therapy_prescribed;
        return;
    }
    if (checkbox.checked && !patient.randomized) {
        checkbox.checked = false;
        showRecordWarning('Mark randomized before marking as prescribed.', 'error');
        return;
    }
    if (checkbox.checked && !patient.study_id) {
        checkbox.checked = false;
        showRecordWarning('Enter the study ID before marking as prescribed.', 'error');
        return;
    }
    if (checkbox.checked && !patient.allocation) {
        checkbox.checked = false;
        showRecordWarning('Select an allocation before marking as prescribed.', 'error');
        return;
    }
    patient.therapy_prescribed = checkbox.checked ? 1 : 0;
    persistPatient(patient, false);
    refreshPatientRow(patient);
}

function updateAllocation(index, value) {
    const patient = patientsData[index];
    if (!patient) return;
    if (!ensureEditablePatient(patient)) return;
    if (!patient.randomized) {
        showRecordWarning('Mark randomized before selecting allocation.', 'error');
        renderPatientTable();
        return;
    }
    if (!patient.study_id) {
        showRecordWarning('Assign a Study ID before selecting allocation.', 'error');
        renderPatientTable();
        return;
    }
    patient.allocation = (value || '').trim();
    if (!patient.allocation) {
        patient.therapy_prescribed = 0;
    }
    persistPatient(patient, false);
    refreshPatientRow(patient);
}

function updateStudyId(index, value) {
    const patient = patientsData[index];
    if (!patient) return;
    if (!ensureEditablePatient(patient)) return;
    const firstEligible = computeFirstEligibleDate(patient);
    const randomizationAllowed = patient.opt_out_status === OPT_OUT_STATUS.DID_NOT
        && Boolean(firstEligible)
        && patient.inclusionMet
        && patient.noExclusions
        && patient.no_exclusions_confirmed;
    if (!patient.randomized && !randomizationAllowed) {
        showRecordWarning('Complete eligibility and opt-out steps before assigning a Study ID.', 'error');
        renderPatientTable();
        return;
    }
    const raw = formatStudyIdInput(value || '');
    if (!raw) {
        releaseStudyId(patient.study_id);
        patient.study_id = '';
        patient.allocation = '';
        patient.therapy_prescribed = 0;
        showRecordWarning('');
        persistPatient(patient, false);
        refreshPatientRow(patient);
        return;
    }
    const normalized = normalizeStudyIdValue(raw);
    if (!normalized) {
        showRecordWarning('Study ID must match ####-AAA-### (e.g., 1835-WKC-003).', 'error');
        renderPatientTable();
        return;
    }
    const studySite = extractStudySite(normalized);
    const locationCode = getPatientRandomizationCode(patient);
    if (!locationCode) {
        showRecordWarning('Select a dialysis unit at randomization before assigning a Study ID.', 'error');
        renderPatientTable();
        return;
    }
    if (studySite !== locationCode) {
        const siteName = getLocationNameFromCode(studySite) || `site ${studySite}`;
        showRecordWarning(`Study ID site code ${studySite} corresponds to ${siteName}. Check the Study ID or update the dialysis unit at randomization.`, 'error');
        renderPatientTable();
        return;
    }
    showRecordWarning('');
    patient.study_id = normalized;
    persistPatient(patient, false);
    refreshPatientRow(patient);
}

function assignStudyId(index) {
    const patient = patientsData[index];
    if (!patient) return;
    if (!db) {
        showStatus('Create or load a database first.', 'error');
        return;
    }
    if (!ensureEditablePatient(patient)) return;
    if (patient.study_id) {
        showRecordWarning('Study ID already assigned.', 'error');
        return;
    }
    if (!patient.notification_date) {
        showRecordWarning('Set notification date before assigning a Study ID.', 'error');
        renderPatientTable();
        return;
    }
    if (patient.opt_out_status !== OPT_OUT_STATUS.DID_NOT) {
        showRecordWarning('Select "Did not opt out" before assigning a Study ID.', 'error');
        renderPatientTable();
        return;
    }
    if (!patient.inclusionMet) {
        showRecordWarning('Complete inclusion checklist before assigning a Study ID.', 'error');
        renderPatientTable();
        return;
    }
    if (!patient.noExclusions) {
        showRecordWarning('Resolve exclusions before assigning a Study ID.', 'error');
        renderPatientTable();
        return;
    }
    if (!patient.no_exclusions_confirmed) {
        showRecordWarning('Confirm "No exclusions" before assigning a Study ID.', 'error');
        renderPatientTable();
        return;
    }
    const firstEligible = computeFirstEligibleDate(patient);
    if (!firstEligible) {
        showRecordWarning('Set notification and eligibility inputs before assigning a Study ID.', 'error');
        renderPatientTable();
        return;
    }
    if (firstEligible.getTime() > getTorontoNowTimestamp()) {
        showRecordWarning(`Eligible on ${formatISODate(firstEligible)}.`, 'error');
        renderPatientTable();
        return;
    }
    const siteCode = getPatientRandomizationCode(patient);
    if (!siteCode) {
        showRecordWarning('Select a dialysis unit at randomization before assigning a Study ID.', 'error');
        renderPatientTable();
        return;
    }
    const available = getAvailableStudyId(siteCode);
    if (!available) {
        showRecordWarning(`No available Study IDs for site ${siteCode}.`, 'error');
        renderPatientTable();
        return;
    }
    try {
        db.run('BEGIN');
        const stmt = db.prepare('DELETE FROM study_ids WHERE study_id = ?');
        stmt.run([available]);
        stmt.free();
        db.run('COMMIT');
    } catch (error) {
        db.run('ROLLBACK');
        console.warn('Unable to claim Study ID', error);
        showRecordWarning('Unable to assign Study ID. Try again.', 'error');
        renderPatientTable();
        return;
    }
    patient.study_id = available;
    if (!normalizeLocationValue(patient.location_at_randomization)) {
        patient.location_at_randomization = getCanonicalLocationValue(patient.location);
    }
    showRecordWarning('');
    persistPatient(patient, false);
    refreshPatientRow(patient);
}

function getAvailableStudyId(siteCode) {
    if (!db) return '';
    const code = (siteCode || '').trim().toUpperCase();
    let stmt;
    try {
        if (code) {
            stmt = db.prepare('SELECT study_id FROM study_ids WHERE study_id LIKE ? ORDER BY study_id LIMIT 1');
            stmt.bind([`%-${code}-%`]);
        } else {
            stmt = db.prepare('SELECT study_id FROM study_ids ORDER BY study_id LIMIT 1');
        }
        if (stmt.step()) {
            const row = stmt.getAsObject();
            return (row.study_id || '').trim();
        }
    } catch (error) {
        console.warn('Unable to read study IDs', error);
    } finally {
        if (stmt) stmt.free();
    }
    return '';
}

function releaseStudyId(studyId) {
    if (!db) return;
    const normalized = (studyId || '').trim();
    if (!normalized) return;
    try {
        const stmt = db.prepare('INSERT OR IGNORE INTO study_ids (study_id, created_at) VALUES (?, ?)');
        stmt.run([normalized, getSqlTimestamp()]);
        stmt.free();
    } catch (error) {
        console.warn('Unable to release Study ID', error);
    }
}

function toggleDialysisDurationConfirmed() {}

function toggleRecordLocked(index, checked) {
    const patient = patientsData[index];
    if (!patient) return;
    if (checked) {
        patient.locked_at = getTorontoNow().toISOString();
        showStatus('Record locked. Only notes remain editable.', 'success');
    } else {
        patient.locked_at = '';
        showStatus('Record unlocked.', 'status');
    }
    persistPatient(patient, false);
    refreshPatientRow(patient);
}

function copyPatientField(index, field) {
    const patient = patientsData[index];
    if (!patient) return;
    const rawValue = field === 'mrn' ? getDisplayMrnValue(patient.mrn) : patient[field];
    const dateFields = new Set(['notification_date', 'opt_out_date', 'dialysis_start_date', 'birth_date']);
    const value = dateFields.has(field) ? formatEntryDate(rawValue) : rawValue;
    const labels = {
        mrn: 'MRN',
        health_card: 'Health card number',
        notification_date: 'Date notified',
        opt_out_date: 'Date opted out',
        study_id: 'Study ID',
        dialysis_start_date: 'Dialysis start date'
    };
    const label = labels[field] || 'Value';
    copyTextToClipboard(value, label);
}

function getSqlTimestamp() {
    const now = getTorontoNow();
    const y = now.getFullYear();
    const m = String(now.getMonth() + 1).padStart(2, '0');
    const d = String(now.getDate()).padStart(2, '0');
    const hh = String(now.getHours()).padStart(2, '0');
    const mm = String(now.getMinutes()).padStart(2, '0');
    const ss = String(now.getSeconds()).padStart(2, '0');
    return `${y}-${m}-${d} ${hh}:${mm}:${ss}`;
}

function logAuditEvent(action, details = null, options = {}) {
    if (!db || !action) return;
    try {
        const actorUsername = (options.actorUsername !== undefined ? options.actorUsername : getCurrentUsername()) || 'system';
        const actorRole = (options.actorRole !== undefined ? options.actorRole : (currentUser ? currentUser.role : '')) || '';
        const targetType = options.targetType || '';
        const targetId = options.targetId || '';
        let detailText = '';
        if (details && typeof details === 'object') {
            if (Object.keys(details).length) {
                detailText = JSON.stringify(details);
            }
        } else if (typeof details === 'string' && details.trim()) {
            detailText = details.trim();
        }
        const stmt = db.prepare(`
            INSERT INTO audit_log (
                event_time, actor_username, actor_role, action, target_type, target_id, details
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?
            )
        `);
        stmt.run([getSqlTimestamp(), actorUsername, actorRole, action, targetType, targetId, detailText]);
        stmt.free();
        markDatabaseChanged();
    } catch (error) {
        console.warn('Unable to write audit log entry', error);
    }
}

function persistPatient(patient, refresh = true) {
    if (!db) return;
    try {
        const criteriaPlaceholders = Array(INCLUSION_KEYS.length + EXCLUSION_KEYS.length).fill('?').join(', ');
        const currentUsername = getCurrentUsername();
        const createdByExisting = patient.created_by ? patient.created_by : null;
        const createdByFallback = currentUsername || null;
        const updatedByValue = currentUsername || patient.updated_by || '';
        const createdAtValue = patient.created_at ? patient.created_at : null;
        const entrySourceValue = patient.entry_source || (isTemporaryMrn(patient.mrn) ? ENTRY_SOURCE_MANUAL : '');
        let recordExists = false;
        if (patient && patient.mrn) {
            const checkStmt = db.prepare('SELECT 1 FROM patient_assessments WHERE mrn = ?');
            checkStmt.bind([patient.mrn]);
            recordExists = checkStmt.step();
            checkStmt.free();
        }
        if (!patient.created_by && createdByFallback) {
            patient.created_by = createdByFallback;
        }
        if (!patient.created_at) {
            patient.created_at = getSqlTimestamp();
        }
        const createdAtForSql = patient.created_at || getSqlTimestamp();
        const updatedAtForSql = getSqlTimestamp();
        patient.updated_by = updatedByValue;
        patient.entry_source = entrySourceValue;
        const stmt = db.prepare(`
            INSERT OR REPLACE INTO patient_assessments (
                mrn, patient_name, age, location, location_at_notification, location_at_randomization,
                health_card, health_card_province, birth_date,
                dialysis_start_date, notification_date, opt_out_status, opt_out_date, randomization_date, randomized, allocation,
                notes, enrollment_status, therapy_prescribed,
                did_not_opt_out, dialysis_duration_confirmed, study_id, locked_at, diabetes_known, no_exclusions_confirmed,
                entry_source, created_by, updated_by,
                ${INCLUSION_KEYS.concat(EXCLUSION_KEYS).join(', ')},
                created_at, updated_at
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                COALESCE(?, ?), ?,
                ${criteriaPlaceholders},
                ?, ?
            )
        `);
        const values = [
            patient.mrn,
            patient.patient_name || '',
            patient.age ?? null,
            patient.location || '',
            patient.location_at_notification || '',
            patient.location_at_randomization || '',
            patient.health_card || '',
            patient.health_card_province || '',
            patient.birth_date || '',
            patient.dialysis_start_date || '',
            patient.notification_date || '',
            patient.opt_out_status || OPT_OUT_STATUS.PENDING,
            patient.opt_out_date || '',
            patient.randomization_date || '',
            patient.randomized || 0,
            patient.allocation || '',
            patient.notes || '',
            patient.enrollment_status || 'pending',
            patient.therapy_prescribed || 0,
            patient.did_not_opt_out || 0,
            patient.dialysis_duration_confirmed || 0,
            patient.study_id || '',
            patient.locked_at || '',
            patient.diabetes_known || 0,
            patient.no_exclusions_confirmed || 0,
            entrySourceValue,
            createdByExisting,
            createdByFallback,
            updatedByValue,
            ...INCLUSION_KEYS.map(key => patient[key] || 0),
            ...EXCLUSION_KEYS.map(key => patient[key] || 0),
            createdAtForSql,
            updatedAtForSql
        ];
        stmt.run(values);
        stmt.free();
        markDatabaseChanged();
        logAuditEvent(recordExists ? 'patient_updated' : 'patient_created', null, {
            targetType: 'patient',
            targetId: patient.mrn || ''
        });
        if (refresh) {
            refreshPatientData();
        }
    } catch (error) {
        console.error(error);
        showStatus('Error saving patient', 'error');
    }
}

function isTemporaryMrn(value) {
    return typeof value === 'string' && value.startsWith(TEMP_MRN_PREFIX);
}

function isManualPatientRecord(patient) {
    if (!patient) return false;
    if (patient.entry_source === ENTRY_SOURCE_MANUAL) return true;
    return isTemporaryMrn(patient.mrn);
}

function getDisplayMrnValue(mrn) {
    const trimmed = (mrn || '').toString().trim();
    if (!trimmed || isTemporaryMrn(trimmed)) return '';
    return trimmed;
}

function generateTemporaryMrn() {
    const existing = new Set((patientsData || []).map(entry => entry && entry.mrn).filter(Boolean));
    let attempts = 0;
    let candidate = '';
    do {
        candidate = `${TEMP_MRN_PREFIX}${getTorontoNowTimestamp()}-${attempts++}`;
    } while (existing.has(candidate));
    return candidate;
}

function createBlankPatientRecord(mrn) {
    const currentUsername = getCurrentUsername();
    const patient = {
        mrn,
        patient_name: 'New patient',
        age: null,
        location: '',
        location_at_notification: '',
        location_at_randomization: '',
        health_card: '',
        health_card_province: '',
        birth_date: '',
        dialysis_start_date: '',
        notification_date: '',
        randomization_date: '',
        randomized: 0,
        notes: '',
        enrollment_status: 'pending',
        therapy_prescribed: 0,
        opt_out_status: OPT_OUT_STATUS.PENDING,
        opt_out_date: '',
        allocation: '',
        study_id: '',
        did_not_opt_out: 0,
        dialysis_duration_confirmed: 0,
        locked_at: '',
        diabetes_known: 0,
        no_exclusions_confirmed: 0,
        entry_source: ENTRY_SOURCE_MANUAL,
        created_by: currentUsername,
        updated_by: currentUsername,
        created_at: getSqlTimestamp()
    };
    INCLUSION_KEYS.concat(EXCLUSION_KEYS).forEach(key => {
        patient[key] = 0;
    });
    return patient;
}

function focusPatientRow(mrn) {
    if (!mrn) return;
    requestAnimationFrame(() => {
        const rows = Array.from(document.querySelectorAll('#patient-table-body tr'));
        if (!rows.length) return;
        rows.forEach(row => row.classList.remove('row-highlight'));
        let target = null;
        for (const row of rows) {
            if (row.dataset && row.dataset.mrn === mrn) {
                target = row;
                break;
            }
        }
        if (target) {
            target.classList.add('row-highlight');
            target.scrollIntoView({ behavior: 'smooth', block: 'center' });
            setTimeout(() => target.classList.remove('row-highlight'), 2000);
        }
    });
}

function deleteManualPatient(index) {
    const patient = patientsData[index];
    if (!patient) return;
    if (!db) {
        showStatus('Create or load a database first.', 'error');
        return;
    }
    if (!ensureEditablePatient(patient)) return;
    if (!isManualPatientRecord(patient)) {
        showRecordWarning('Only manually added records can be deleted.', 'error');
        return;
    }
    if (!patient.mrn) {
        showStatus('Unable to delete record without an MRN.', 'error');
        return;
    }
    const displayMrn = getDisplayMrnValue(patient.mrn);
    const name = (patient.patient_name || '').trim();
    const labelParts = [];
    if (name) labelParts.push(name);
    if (displayMrn) labelParts.push(`MRN ${displayMrn}`);
    const label = labelParts.length ? labelParts.join(' - ') : 'this manual record';
    if (!window.confirm(`Delete ${label}? This cannot be undone.`)) return;
    try {
        const stmt = db.prepare('DELETE FROM patient_assessments WHERE mrn = ?');
        stmt.run([patient.mrn]);
        stmt.free();
        expandedPatientIndex = null;
        markDatabaseChanged();
        logAuditEvent('patient_deleted', {
            entry_source: patient.entry_source || '',
            patient_name: patient.patient_name || ''
        }, {
            targetType: 'patient',
            targetId: patient.mrn || ''
        });
        refreshPatientData();
        showRecordWarning('');
        showStatus('Manual patient record deleted.', 'success');
    } catch (error) {
        console.error(error);
        showStatus('Error deleting patient record.', 'error');
    }
}

function promptNewPatient() {
    if (!db) {
        showStatus('Create or load a database first.', 'error');
        return;
    }
    const tempMrn = generateTemporaryMrn();
    const patient = createBlankPatientRecord(tempMrn);
    persistPatient(patient);
    showRecordWarning('Blank patient row added (listed under "Missing Data" until required fields are completed). Enter the patient details directly in the table.', 'status');
    showStatus('Blank patient row added', 'success');
    focusPatientRow(tempMrn);
}

async function importRegistrationExtract(event) {
    const file = event.target.files[0];
    event.target.value = '';
    if (!file) return;
    if (!db) {
        showStatus('Create or load a database first.', 'error');
        return;
    }
    if (!isAutosaveReady()) {
        showStatus('Autosave must be ready before importing. Select a save folder and confirm encryption.', 'error');
        return;
    }
    const readText = (inputFile) => new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(reader.result || '');
        reader.onerror = () => reject(new Error('Error reading file.'));
        reader.readAsText(inputFile);
    });
    let csvText = '';
    try {
        showStatus('Reading file...', 'status');
        csvText = await readText(file);
    } catch (error) {
        console.error(error);
        showStatus('Error reading file.', 'error');
        return;
    }
    let rows;
    let prescreenSummary;
    try {
        rows = parseLegacyRegistrationCSV(csvText || '');
        prescreenSummary = analyzePreScreeningRows(rows);
    } catch (error) {
        console.error(error);
        showStatus('Error parsing CSV: ' + error.message, 'error');
        return;
    }
    const backupLabel = await promptImportBackupModal();
    if (!backupLabel) {
        showStatus('Import canceled. A backup is required before importing.', 'status');
        return;
    }
    const backupFilename = await createImportBackup(backupLabel);
    if (!backupFilename) {
        showStatus('Import canceled. Backup could not be saved.', 'error');
        return;
    }
    updatePrescreenUI(prescreenSummary);
    ingestRegistrationRows(rows);
}

function ingestRegistrationRows(rows) {
    if (!Array.isArray(rows) || rows.length === 0) {
        showStatus('CSV did not contain any usable patient rows.', 'error');
        return;
    }
    if (!db) return;
    const existingMrns = new Set();
    const existingHcns = new Set();
    try {
        const existingStmt = db.prepare('SELECT mrn, health_card FROM patient_assessments');
        while (existingStmt.step()) {
            const row = existingStmt.getAsObject();
            if (row.mrn) existingMrns.add(String(row.mrn).trim());
            if (row.health_card) {
                const normalizedHcn = normalizeHealthCardValue(row.health_card);
                if (normalizedHcn) existingHcns.add(normalizedHcn);
            }
        }
        existingStmt.free();
    } catch (error) {
        console.warn('Unable to read existing patients for duplicate check', error);
    }
    const seenMrns = new Set(existingMrns);
    const seenHcns = new Set(existingHcns);
    const duplicates = [];
const stmt = db.prepare(`
        INSERT OR REPLACE INTO patient_assessments (
            mrn, patient_name, age, location, location_at_notification, location_at_randomization,
            health_card, health_card_province, birth_date,
            dialysis_start_date, notification_date, opt_out_status, opt_out_date, randomization_date, randomized, allocation,
            study_id, notes, enrollment_status, therapy_prescribed, did_not_opt_out, dialysis_duration_confirmed, locked_at, diabetes_known, no_exclusions_confirmed,
            entry_source, created_by, updated_by,
            ${INCLUSION_KEYS.concat(EXCLUSION_KEYS).join(', ')},
            created_at, updated_at
        ) VALUES (
        ${Array(26).fill('?').join(', ')},
            ?, ?,
            ${Array(INCLUSION_KEYS.length + EXCLUSION_KEYS.length).fill('?').join(', ')},
            ?, ?
        )
    `);
    const importUsername = getCurrentUsername();
    const importTimestamp = getSqlTimestamp();
    let imported = 0;
    rows.forEach(original => {
        if (!original) return;
        const mrn = (original[MRN_HEADER] || '').toString().trim();
        if (!mrn) return;
        const patientName = getPatientNameFromRow(original);
        const locationCode = getField(original, [LOCATION_HEADER]) || '';
        const locationName = LOCATION_CODES[locationCode] || locationCode || '';
        const locationDisplay = locationCode && locationName ? `${locationCode}: ${locationName}` : locationName || locationCode;
        const healthCard = getField(original, [LAST_HCN_HEADER, 'Latest Known HCN', HCN_HEADER]) || '';
        const healthCardProvince = getField(original, [HCN_PROVINCE_HEADER]) || '';
        const normalizedHealthCard = normalizeHealthCardValue(healthCard);
        let duplicateReason = '';
        if (seenMrns.has(mrn)) {
            duplicateReason = 'MRN';
        } else if (normalizedHealthCard && seenHcns.has(normalizedHealthCard)) {
            duplicateReason = 'Health card';
        }
        if (duplicateReason) {
            duplicates.push({ mrn, healthCard, reason: duplicateReason });
            return;
        }
        const province = healthCardProvince;
        let modalityCode = getField(original, [MODALITY_HEADER, 'Current Modality', 'Latest Modality']) || '';
        if (!VALID_MODALITY_CODES.includes(modalityCode) && DISPLAY_TO_PREFERRED_CODE[modalityCode]) {
            modalityCode = DISPLAY_TO_PREFERRED_CODE[modalityCode];
        }
        const hasValidModality = VALID_MODALITY_CODES.includes(modalityCode);
        const birthDate = parseLegacyDate(getField(original, [BIRTH_DATE_HEADER]));
        const age = birthDate ? calculateAgeFromDate(birthDate) : null;
        const dialysisStartIso = normalizeLegacyDate(getField(original, [START_DATE_HEADER]));
        let startIsoValid = dialysisStartIso;
        if (birthDate && dialysisStartIso) {
            const startDate = parseISODate(dialysisStartIso);
            if (startDate && startDate.getTime() <= birthDate.getTime()) {
                startIsoValid = '';
            }
        }
        const diabetesType1 = getField(original, [DIAB_TYPE1_HEADER]);
        const diabetesType2 = getField(original, [DIAB_TYPE2_HEADER]);
        const hasDiabetesData = Boolean(diabetesType1 || diabetesType2);
        const hasDiabetes = parseBoolean(diabetesType1) || parseBoolean(diabetesType2);
        const diabetesKnown = hasDiabetesData ? 1 : 0;
        const inclusionValues = [
            computeInclusionAge(age, hasDiabetes),
            startIsoValid ? meetsDialysisDays(startIsoValid) : 0,
            hasValidModality ? 1 : 0,
            healthCard ? 1 : 0
        ];
        const exclusionValues = EXCLUSION_KEYS.map(() => 0);
        const values = [
            mrn,                               // mrn
            patientName,                       // patient_name
            age,                               // age
            locationDisplay,                   // location
            '',                                // location_at_notification
            '',                                // location_at_randomization
            healthCard,                        // health_card
            province,                          // health_card_province
            birthDate ? formatISODate(birthDate) : '', // birth_date
            startIsoValid || '',               // dialysis_start_date
            '',                                // notification_date
            OPT_OUT_STATUS.PENDING,            // opt_out_status
            '',                                // opt_out_date
            '',                                // randomization_date
            0,                                 // randomized
            '',                                // allocation
            '',                                // study_id
            '',                                // notes
            'pending',                         // enrollment_status
            0,                                 // therapy_prescribed
            0,                                 // did_not_opt_out
            0,                                 // dialysis_duration_confirmed
            '',                                // locked_at
            diabetesKnown,                     // diabetes_known
            0,                                 // no_exclusions_confirmed
            ENTRY_SOURCE_IMPORT,               // entry_source
            importUsername,                    // created_by
            importUsername                     // updated_by
        ].concat(inclusionValues, exclusionValues, [importTimestamp, importTimestamp]);
        try {
            stmt.run(values);
            imported++;
            seenMrns.add(mrn);
            if (normalizedHealthCard) {
                seenHcns.add(normalizedHealthCard);
            }
        } catch (error) {
            console.error('Failed to import row', error);
        }
    });
    stmt.free();
    refreshPatientData();
    markDatabaseChanged();
    let statusMessage;
    if (imported) {
        statusMessage = `Imported ${imported} patient${imported === 1 ? '' : 's'} from CSV.`;
    } else {
        statusMessage = 'No new patients imported.';
    }
    if (duplicates.length) {
        statusMessage += ` Skipped ${duplicates.length} duplicate${duplicates.length === 1 ? '' : 's'}.`;
        const sample = duplicates.slice(0, 5).map(entry => {
            if (entry.reason === 'MRN') {
                return `MRN ${entry.mrn}`;
            }
            return entry.healthCard ? `HCN ${entry.healthCard}` : `MRN ${entry.mrn}`;
        });
        const more = duplicates.length > sample.length ? '…' : '';
        showRecordWarning(`Skipped duplicate imports (${duplicates.length}): ${sample.join(', ')}${more}`, 'error');
    } else {
        showRecordWarning('');
    }
    logAuditEvent('patients_imported', {
        imported,
        duplicates: duplicates.length
    }, {
        targetType: 'patient',
        targetId: ''
    });
    showStatus(statusMessage, imported ? 'success' : 'status');
}
